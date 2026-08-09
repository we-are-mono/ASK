"""IPv4 control-plane edge case 1d: bad checksum + invalid version.

Injects packets with corrupted IP checksum, version=5 (illegal), and
version=15 (also illegal) from LAN. Two oracles run together:

  1. splat_window asserts no kernel KASAN/UBSAN/BUG/lockdep splat —
     the high-value assertion. Malformed input parsing is exactly
     where memory bugs hide.
  2. RX-path golden tripwire records what *did* happen (hardware
     handled vs punted to the kernel, read off the ingress netdev's
     kernel RX counter). Either outcome is pinned, regression
     catches a future change.

This test is in the KASAN-eligible nightly subset per the Phase 2
plan: malformed-packet parsers are precisely what KASAN catches.
"""

from __future__ import annotations

import asyncio
import os
import textwrap

import pytest

from _topology import (
    TARGET_LAN_IF,
    assert_counter_signature,
    classify_rx_path,
    golden_for,
    kernel_rx_packets,
    lan_run_python,
)


WAN_IPERF_IP = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")


_VARIANTS: list[tuple[str, str, int]] = [
    # (label, mutation expression in scapy script, packet count)
    # The mutation is applied to the bytes() of the packet to bypass
    # scapy's own checksum recomputation on send(). Counts must
    # dominate background chatter on the LAN segment — see
    # classify_rx_path().
    ("bad_checksum",
     # Build a normal packet, then flip checksum bytes in the wire form.
     "raw = bytes(IP(dst=DST, chksum=0xdead) "
     "  / UDP(sport=47104, dport=47134) / Raw(b'C' * 32))",
     20),
    ("version_5",
     # Override version field (top nibble of byte 0); recompute nothing.
     "raw = bytes(IP(dst=DST, version=5) "
     "  / UDP(sport=47105, dport=47135) / Raw(b'D' * 32))",
     20),
    ("version_15",
     "raw = bytes(IP(dst=DST, version=15) "
     "  / UDP(sport=47106, dport=47136) / Raw(b'E' * 32))",
     20),
]


def _injection_script(mutation: str, n: int) -> str:
    return textwrap.dedent(f"""
        from scapy.all import IP, UDP, Raw, sendp, Ether, conf
        DST = "{WAN_IPERF_IP}"
        {mutation}
        # send raw IP via L2: scapy's send() recomputes ip.chksum, which
        # we don't want. sendp() with Ether wrapping leaves the IP layer
        # bytes intact.
        iface = conf.route.route(DST)[0]
        sendp(Ether() / raw, iface=iface, count={n}, verbose=0, inter=0.05)
        print("INJECTED", {n})
    """).strip()


@pytest.mark.parametrize(
    "label,mutation,n",
    _VARIANTS,
    ids=[v[0] for v in _VARIANTS],
)
async def test_ipv4_edge_malformed_tripwire(
    aiohttp_session, target_agent, lan, splat_window,
    label, mutation, n,
):
    await asyncio.sleep(0.5)
    before = await kernel_rx_packets(
        target_agent, aiohttp_session, TARGET_LAN_IF)

    script = _injection_script(mutation, n)
    r = await lan_run_python(
        lan, script, label=f"ipv4_malformed_{label}", timeout=30.0,
    )
    assert r.rc == 0, f"injection failed: rc={r.rc}, out={r.stdout!r}"
    assert f"INJECTED {n}" in r.stdout, r.stdout

    await asyncio.sleep(1.0)
    after = await kernel_rx_packets(
        target_agent, aiohttp_session, TARGET_LAN_IF)

    sig = {"rx_path": classify_rx_path(after - before, n)}
    assert_counter_signature(
        sig,
        golden_path=golden_for("ipv4_edge_malformed.json"),
        label=label,
    )

"""IPv6 control-plane edge case 2d: extension-header chain.

LAN sends IPv6 packets with a chained sequence of extension headers
(HopByHop, optionally Routing, then DestOpt) ahead of UDP. Pins the
hardware-vs-kernel RX-path classification in a golden file; subsequent
runs assert equality. Tripwire shape — discriminates between HW
handling and slow-path punt without pre-supposing either.
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
    ipv6_topology,  # noqa: F401  (fixture)
    kernel_rx_packets,
    lan_run_python,
)


WAN_IPV6 = os.environ.get("ASK_WAN_IPV6", "fc00:beef::99")


_VARIANTS: list[tuple[str, str, int]] = [
    # (label, scapy chain expression, packet count)
    # Counts must dominate background chatter on the LAN segment —
    # see classify_rx_path().
    ("hbh_only",
     "IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\\x00' * 4)])",
     20),
    ("hbh_dest",
     "IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\\x00' * 4)]) "
     "/ IPv6ExtHdrDestOpt(options=[PadN(optdata=b'\\x00' * 4)])",
     20),
    ("hbh_routing_dest",
     "IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\\x00' * 4)]) "
     "/ IPv6ExtHdrRouting(addresses=['2001:db8::beef']) "
     "/ IPv6ExtHdrDestOpt(options=[PadN(optdata=b'\\x00' * 4)])",
     20),
]


def _injection_script(chain_expr: str, n: int) -> str:
    return textwrap.dedent(f"""
        from scapy.all import (
            IPv6, UDP, Raw, send,
            IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
            IPv6ExtHdrDestOpt, PadN,
        )
        pkt = (IPv6(dst="{WAN_IPV6}")
               / {chain_expr}
               / UDP(sport=47110, dport=47140)
               / Raw(b"X" * 32))
        send(pkt, count={n}, verbose=0, inter=0.05)
        print("INJECTED", {n})
    """).strip()


@pytest.mark.parametrize(
    "label,chain_expr,n",
    _VARIANTS,
    ids=[v[0] for v in _VARIANTS],
)
async def test_ipv6_edge_eh_chain_tripwire(
    aiohttp_session, target_agent, lan, splat_window, ipv6_topology,
    label, chain_expr, n,
):
    await asyncio.sleep(0.5)
    before = await kernel_rx_packets(
        target_agent, aiohttp_session, TARGET_LAN_IF)

    script = _injection_script(chain_expr, n)
    r = await lan_run_python(
        lan, script, label=f"ipv6_eh_{label}", timeout=30.0,
    )
    assert r.rc == 0, f"injection failed: rc={r.rc}, out={r.stdout!r}"
    assert f"INJECTED {n}" in r.stdout, r.stdout

    await asyncio.sleep(1.0)
    after = await kernel_rx_packets(
        target_agent, aiohttp_session, TARGET_LAN_IF)

    sig = {"rx_path": classify_rx_path(after - before, n)}
    assert_counter_signature(
        sig,
        golden_path=golden_for("ipv6_edge_eh_chain.json"),
        label=label,
    )

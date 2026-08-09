"""IPv6 control-plane edge case 2a: hop-by-hop options.

Same tripwire shape as test_ipv4_edge_options.py: scapy on LAN sends
packets carrying an IPv6 HopByHop extension header; the hardware-vs-
kernel RX-path classification is pinned in a golden file. We don't
pre-suppose whether HW drops, slow-paths, or fast-paths these —
whatever it does gets pinned and a future change fails the test loudly.

Assumes IPv6 forwarding is wired up on the DUT and the LAN VM has a
route toward ASK_WAN_IPV6 via the DUT. If the routing isn't there,
scapy will source-pick the wrong interface and counter deltas won't
reflect DUT processing.
"""

from __future__ import annotations

import asyncio
import os
import textwrap

from _topology import (
    TARGET_LAN_IF,
    assert_counter_signature,
    classify_rx_path,
    golden_for,
    ipv6_topology,  # noqa: F401  (fixture)
    kernel_rx_packets,
    lan_run_python,
)


WAN_IPV6   = os.environ.get("ASK_WAN_IPV6", "fc00:beef::99")
TEST_DPORT = 47137
TEST_SPORT = 47107
# Must dominate background chatter on the LAN segment — see
# classify_rx_path().
N_PACKETS  = 20


_INJECT_TEMPLATE = textwrap.dedent("""
    from scapy.all import IPv6, IPv6ExtHdrHopByHop, UDP, Raw, send, PadN
    pkt = (IPv6(dst="{wan}")
           / IPv6ExtHdrHopByHop(options=[PadN(optdata=b"\\x00" * 4)])
           / UDP(sport={sport}, dport={dport})
           / Raw(b"H" * 32))
    send(pkt, count={n}, verbose=0, inter=0.05)
    print("INJECTED", {n})
""").strip()


async def test_ipv6_edge_hbh_options_tripwire(
    aiohttp_session, target_agent, lan, splat_window, ipv6_topology,
):
    await asyncio.sleep(0.5)
    before = await kernel_rx_packets(
        target_agent, aiohttp_session, TARGET_LAN_IF)

    script = _INJECT_TEMPLATE.format(
        wan=WAN_IPV6, sport=TEST_SPORT, dport=TEST_DPORT, n=N_PACKETS,
    )
    r = await lan_run_python(lan, script, label="ipv6_hbh", timeout=30.0)
    assert r.rc == 0, f"injection failed: rc={r.rc}, out={r.stdout!r}"
    assert f"INJECTED {N_PACKETS}" in r.stdout, r.stdout

    await asyncio.sleep(1.0)
    after = await kernel_rx_packets(
        target_agent, aiohttp_session, TARGET_LAN_IF)

    sig = {"rx_path": classify_rx_path(after - before, N_PACKETS)}
    assert_counter_signature(
        sig,
        golden_path=golden_for("ipv6_edge_hbh.json"),
        label="hop_by_hop_padn",
    )

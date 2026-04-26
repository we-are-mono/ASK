"""IPv6 control-plane edge case 2a: hop-by-hop options.

Same tripwire shape as test_ipv4_edge_options.py: scapy on LAN sends
packets carrying an IPv6 HopByHop extension header; counters before
and after are recorded into a golden file. We don't pre-suppose
whether HW drops, slow-paths, or fast-paths these — whatever it does
gets pinned and a future change fails the test loudly.

Assumes IPv6 forwarding is wired up on the DUT and the LAN VM has a
route toward ASK_WAN_IPV6 via the DUT. If the routing isn't there,
scapy will source-pick the wrong interface and counter deltas won't
reflect DUT processing.
"""

from __future__ import annotations

import asyncio
import base64
import os
import textwrap

from _topology import (
    assert_counter_signature,
    counter_signature,
    golden_for,
    ipv6_topology,  # noqa: F401  (fixture)
)


WAN_IPV6   = os.environ.get("ASK_WAN_IPV6", "fc00:beef::99")
TEST_DPORT = 47137
TEST_SPORT = 47107


_INJECT_TEMPLATE = textwrap.dedent("""
    from scapy.all import IPv6, IPv6ExtHdrHopByHop, UDP, Raw, send, PadN
    pkt = (IPv6(dst="{wan}")
           / IPv6ExtHdrHopByHop(options=[PadN(optdata=b"\\x00" * 4)])
           / UDP(sport={sport}, dport={dport})
           / Raw(b"H" * 32))
    send(pkt, count=3, verbose=0, inter=0.05)
    print("INJECTED 3")
""").strip()


async def test_ipv6_edge_hbh_options_tripwire(
    aiohttp_session, target_agent, lan, splat_window, ipv6_topology,
):
    await asyncio.sleep(0.5)
    before = await target_agent.counters(
        aiohttp_session, ifaces=["eth3", "eth4"],
    )

    script = _INJECT_TEMPLATE.format(
        wan=WAN_IPV6, sport=TEST_SPORT, dport=TEST_DPORT,
    )
    b64 = base64.b64encode(script.encode()).decode()
    path = "/tmp/ask_ipv6_hbh.py"
    r = lan.run(f"echo {b64} | base64 -d > {path} && echo OK", timeout=10)
    assert "OK" in r.stdout, f"stage failed: rc={r.rc}, {r.stdout!r}"

    r = await asyncio.to_thread(lan.run, f"python3 {path}", 30.0)
    assert r.rc == 0, f"injection failed: rc={r.rc}, out={r.stdout!r}"
    assert "INJECTED 3" in r.stdout, r.stdout

    await asyncio.sleep(1.0)
    after = await target_agent.counters(
        aiohttp_session, ifaces=["eth3", "eth4"],
    )

    sig = counter_signature(
        before, after, key_regex=r"^fqid_stats/.*frame_count$",
    )
    assert_counter_signature(
        sig,
        golden_path=golden_for("ipv6_edge_hbh.json"),
        label="hop_by_hop_padn",
    )

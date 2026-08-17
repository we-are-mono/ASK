"""IPv4 control-plane edge case 1c: TTL=1 → ICMP time-exceeded.

LAN sends a packet with TTL=1 destined for the WAN. The DUT must
decrement TTL, hit zero, drop the packet, and emit ICMP type=11
(time-exceeded) back to the source. Asserted by tcpdump on the
LAN-facing interface, bounded by the agent's exec timeout.
"""

from __future__ import annotations

import asyncio
import os
import textwrap

from _topology import (
    ICMP4_TIME_EXCEEDED,
    TARGET_LAN_IF,
    expect_icmp_egress,
    lan_run_python,
)


WAN_IPERF_IP  = os.environ.get("ASK_WAN_IPERF_IP",   "10.0.0.141")


_INJECT_TEMPLATE = textwrap.dedent("""
    from scapy.all import IP, UDP, Raw, send
    pkt = (IP(dst="{wan}", ttl=1)
           / UDP(sport=47103, dport=47133)
           / Raw(b"B" * 32))
    send(pkt, count=1, verbose=0)
    print("INJECTED")
""").strip()


async def test_ipv4_edge_ttl1_emits_time_exceeded(
    aiohttp_session, target_agent, lan, splat_window,
):
    script = _INJECT_TEMPLATE.format(wan=WAN_IPERF_IP)

    async def _inject():
        # 200 ms buffer so tcpdump on the DUT is listening before the
        # ICMP frame would arrive.
        await asyncio.sleep(0.2)
        r = await lan_run_python(lan, script, label="ipv4_ttl1", timeout=15.0)
        assert r.rc == 0, f"injection failed: {r.stdout!r}"

    summary, _ = await asyncio.gather(
        expect_icmp_egress(
            target_agent, aiohttp_session,
            iface=TARGET_LAN_IF,
            icmp_type=11,                       # time-exceeded
            expect_substr=ICMP4_TIME_EXCEEDED,
            ip_ver=4,
            timeout_s=3.0,
        ),
        _inject(),
    )
    assert summary, "expect_icmp_egress returned empty summary"

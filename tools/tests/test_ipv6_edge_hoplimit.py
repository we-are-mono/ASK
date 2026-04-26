"""IPv6 control-plane edge case 2b: hop-limit=1 → ICMPv6 time-exceeded.

LAN sends an IPv6 packet with hlim=1 destined for ASK_WAN_IPV6. The
DUT decrements hop-limit to 0, drops the packet, and emits ICMPv6
type=3 (time-exceeded) back to the source. Asserted by tcpdump on
the LAN-facing interface.
"""

from __future__ import annotations

import asyncio
import os
import textwrap

from _topology import (
    ICMP6_TIME_EXCEEDED,
    expect_icmp_egress,
    ipv6_topology,  # noqa: F401  (fixture)
    lan_run_python,
)


WAN_IPV6      = os.environ.get("ASK_WAN_IPV6",      "fc00:beef::99")
TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth4")


_INJECT = textwrap.dedent("""
    from scapy.all import IPv6, UDP, Raw, send
    pkt = (IPv6(dst="{wan}", hlim=1)
           / UDP(sport=47108, dport=47138)
           / Raw(b"L" * 32))
    send(pkt, count=1, verbose=0)
    print("INJECTED")
""").strip()


async def test_ipv6_edge_hoplimit_emits_time_exceeded(
    aiohttp_session, target_agent, lan, splat_window, ipv6_topology,
):
    script = _INJECT.format(wan=WAN_IPV6)

    async def _inject():
        await asyncio.sleep(0.2)
        r = await lan_run_python(lan, script, label="ipv6_hlim1", timeout=15.0)
        assert r.rc == 0, f"injection failed: {r.stdout!r}"

    summary, _ = await asyncio.gather(
        expect_icmp_egress(
            target_agent, aiohttp_session,
            iface=TARGET_LAN_IF,
            icmp_type=3,                        # ICMPv6 time-exceeded
            expect_substr=ICMP6_TIME_EXCEEDED,
            ip_ver=6,
            timeout_s=3.0,
        ),
        _inject(),
    )
    assert summary

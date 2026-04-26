"""IPv6 control-plane edge case 2c: PMTU + Packet-Too-Big.

LAN sends an oversized IPv6 packet to ASK_WAN_IPV6 while the DUT's
egress interface MTU is lowered to 1300. The kernel must emit ICMPv6
type=2 (Packet-Too-Big) back to the source. Asserted by tcpdump on
the LAN-facing interface.
"""

from __future__ import annotations

import asyncio
import os
import textwrap

from _topology import (
    ICMP6_PACKET_TOO_BIG,
    dut_egress_mtu,  # noqa: F401  (fixture)
    expect_icmp_egress,
    ipv6_topology,  # noqa: F401  (fixture)
    lan_run_python,
)


WAN_IPV6      = os.environ.get("ASK_WAN_IPV6",      "fc00:beef::99")
TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth4")
TARGET_WAN_IF = os.environ.get("ASK_TARGET_WAN_IF", "eth3")
LOWERED_MTU   = 1300


_INJECT = textwrap.dedent("""
    from scapy.all import IPv6, UDP, Raw, send
    # Payload sized so the total packet (40 IPv6 + 8 UDP + payload =
    # 1448 B) is below the LAN VM's 1500 MTU (so scapy can put it on
    # the wire) but above the DUT's lowered 1300 MTU (so the DUT's
    # forwarding emits Packet-Too-Big back to source).
    pkt = (IPv6(dst="{wan}")
           / UDP(sport=47109, dport=47139)
           / Raw(b"P" * 1400))
    send(pkt, count=1, verbose=0)
    print("INJECTED")
""").strip()


async def test_ipv6_edge_pmtu_emits_packet_too_big(
    aiohttp_session, target_agent, lan, splat_window,
    dut_egress_mtu, ipv6_topology,
):
    await dut_egress_mtu(TARGET_WAN_IF, LOWERED_MTU)

    script = _INJECT.format(wan=WAN_IPV6)

    async def _inject():
        await asyncio.sleep(0.2)
        r = await lan_run_python(lan, script, label="ipv6_pmtu", timeout=15.0)
        assert r.rc == 0, f"injection failed: {r.stdout!r}"

    summary, _ = await asyncio.gather(
        expect_icmp_egress(
            target_agent, aiohttp_session,
            iface=TARGET_LAN_IF,
            icmp_type=2,                        # ICMPv6 packet-too-big
            expect_substr=ICMP6_PACKET_TOO_BIG,
            ip_ver=6,
            timeout_s=3.0,
        ),
        _inject(),
    )
    assert str(LOWERED_MTU) in summary, (
        f"PTB captured but MTU {LOWERED_MTU} absent from summary: {summary!r}"
    )

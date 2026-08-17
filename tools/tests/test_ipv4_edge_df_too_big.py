"""IPv4 control-plane edge case 1b: DF + needs-fragmentation.

Injects a DF=1 packet from LAN that exceeds the DUT's egress MTU; the
kernel must emit ICMP fragmentation-needed (type=3, code=4) back to
the source. Asserted by tcpdump on the LAN-facing interface (eth3 by
default), bounded by the agent-side exec timeout.
"""

from __future__ import annotations

import asyncio
import os
import textwrap

from _topology import (
    ICMP4_FRAG_NEEDED,
    TARGET_LAN_IF,
    TARGET_WAN_IF,
    dut_egress_mtu,  # noqa: F401  (fixture)
    expect_icmp_egress,
    lan_run_python,
)


WAN_IPERF_IP    = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
LOWERED_MTU     = 1300


_INJECT_TEMPLATE = textwrap.dedent("""
    from scapy.all import IP, UDP, Raw, send
    pkt = (IP(dst="{wan}", flags="DF")
           / UDP(sport=47102, dport=47132)
           / Raw(b"A" * 1500))
    send(pkt, count=1, verbose=0)
    print("INJECTED")
""").strip()


async def test_ipv4_edge_df_too_big_emits_frag_needed(
    aiohttp_session, target_agent, lan, splat_window, dut_egress_mtu,
):
    # Lower the WAN-facing egress MTU; restored on fixture teardown.
    await dut_egress_mtu(TARGET_WAN_IF, LOWERED_MTU)

    script = _INJECT_TEMPLATE.format(wan=WAN_IPERF_IP)

    # Start the egress watcher BEFORE injection so we don't race the
    # ICMP response. expect_icmp_egress waits up to timeout_s for one
    # matching frame; gather() lets injection and observation overlap.
    async def _inject():
        await asyncio.sleep(0.2)
        r = await lan_run_python(lan, script, label="ipv4_df", timeout=15.0)
        assert r.rc == 0, f"injection failed: {r.stdout!r}"

    summary, _ = await asyncio.gather(
        expect_icmp_egress(
            target_agent, aiohttp_session,
            iface=TARGET_LAN_IF,
            icmp_type=3, icmp_code=4,           # frag-needed
            expect_substr=ICMP4_FRAG_NEEDED,
            ip_ver=4,
            timeout_s=3.0,
        ),
        _inject(),
    )

    # Sanity: the captured frame should mention the lowered MTU.
    assert str(LOWERED_MTU) in summary, (
        f"ICMP frag-needed captured but MTU not present in summary "
        f"(expected {LOWERED_MTU}): {summary!r}"
    )

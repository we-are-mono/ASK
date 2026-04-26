"""IPv4 control-plane edge case 1b: DF + needs-fragmentation.

Injects a DF=1 packet from LAN that exceeds the DUT's egress MTU; the
kernel must emit ICMP fragmentation-needed (type=3, code=4) back to
the source. Asserted by tcpdump on the LAN-facing interface (eth4 by
default), bounded by the agent-side exec timeout.
"""

from __future__ import annotations

import asyncio
import base64
import os
import textwrap

from _topology import (
    ICMP4_FRAG_NEEDED,
    dut_egress_mtu,  # noqa: F401  (fixture)
    expect_icmp_egress,
)


WAN_IPERF_IP    = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
TARGET_LAN_IF   = os.environ.get("ASK_TARGET_LAN_IF", "eth4")
TARGET_WAN_IF   = os.environ.get("ASK_TARGET_WAN_IF", "eth3")
LOWERED_MTU     = 1300


_INJECT_TEMPLATE = textwrap.dedent("""
    from scapy.all import IP, UDP, Raw, send
    pkt = (IP(dst="{wan}", flags="DF")
           / UDP(sport=47102, dport=47132)
           / Raw(b"A" * 1500))
    send(pkt, count=1, verbose=0)
    print("INJECTED")
""").strip()


def _push_and_run(lan, script: str, path: str) -> None:
    b64 = base64.b64encode(script.encode()).decode()
    r = lan.run(f"echo {b64} | base64 -d > {path} && echo OK", timeout=10)
    assert "OK" in r.stdout, f"stage failed: rc={r.rc}, {r.stdout!r}"


async def test_ipv4_edge_df_too_big_emits_frag_needed(
    aiohttp_session, target_agent, lan, splat_window, dut_egress_mtu,
):
    # Lower the WAN-facing egress MTU; restored on fixture teardown.
    await dut_egress_mtu(TARGET_WAN_IF, LOWERED_MTU)

    # Stage the scapy script on LAN.
    script = _INJECT_TEMPLATE.format(wan=WAN_IPERF_IP)
    path = "/tmp/ask_ipv4_df_too_big.py"
    _push_and_run(lan, script, path)

    # Start the egress watcher BEFORE injection so we don't race the
    # ICMP response. expect_icmp_egress waits up to timeout_s for one
    # matching frame; gather() lets injection and observation overlap.
    async def _inject():
        # 200 ms buffer so tcpdump on the DUT is listening before the
        # ICMP frame would arrive.
        await asyncio.sleep(0.2)
        r = await asyncio.to_thread(lan.run, f"python3 {path}", 15.0)
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

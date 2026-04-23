"""End-to-end offload test: LAN → target → WAN iperf3 + CMM query oracle.

Asserts FMAN actually offloads the forwarded flow (not SW fastpath), by
comparing the CMM conntrack table pre- and during-traffic AND checking
that sustained throughput exceeds a threshold only offload can reach.
"""

from __future__ import annotations

import asyncio
import os
import re


WAN_IPERF_IP     = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
IPERF_DURATION_S = int(os.environ.get("ASK_IPERF_DURATION", "5"))

# SW forwarding on a Cortex-A72 can't sustain more than ~500 Mbps at
# 1500 B MTU; FMAN offload runs near 10G line rate.
OFFLOAD_MIN_GBPS = 1.0


_IPERF_RX_RE = re.compile(
    r"^\[\s*\d+\]\s+[\d.]+-[\d.]+\s+sec\s+[\d.]+\s[KMGT]?Bytes\s+([\d.]+)\s+([KMG]?)bits/sec",
    re.M,
)
_CT_TOTAL_RE = re.compile(r"Total Connection Entries:\s*(\d+)")


def _flow_count(cmm_response: dict) -> int:
    m = _CT_TOTAL_RE.search(cmm_response.get("stdout", ""))
    return int(m.group(1)) if m else 0


def _iperf_receiver_gbps(log: str) -> float | None:
    matches = _IPERF_RX_RE.findall(log)
    if not matches:
        return None
    value, unit = matches[-1]
    scale = {"": 1e-9, "K": 1e-6, "M": 1e-3, "G": 1.0}.get(unit, 0.0)
    return float(value) * scale


async def test_iperf_ipv4_tcp_offload(
    aiohttp_session, target_agent, lan, splat_window
):
    baseline = await target_agent.cmm_query(aiohttp_session, "connections")
    baseline_count = _flow_count(baseline)

    # Console.run is blocking — shove it onto a thread so we don't stall
    # the event loop during the ~0.5s UART round-trip.
    await asyncio.to_thread(
        lan.run,
        f"nohup iperf3 -c {WAN_IPERF_IP} -t {IPERF_DURATION_S} "
        f"> /tmp/iperf.log 2>&1 & echo started",
    )

    # Give cmm + the FCI offload path a moment to install the flow.
    await asyncio.sleep(2.0)
    during = await target_agent.cmm_query(aiohttp_session, "connections")
    during_count = _flow_count(during)
    assert during_count > baseline_count, (
        f"CMM saw no new flows: baseline={baseline_count}, during={during_count}; "
        f"stderr={during.get('stderr','').strip()!r}"
    )

    # Wait for iperf to finish, then fetch the result.
    await asyncio.sleep(IPERF_DURATION_S + 1)
    log_result = await asyncio.to_thread(lan.run, "cat /tmp/iperf.log")
    gbps = _iperf_receiver_gbps(log_result.stdout)
    assert gbps is not None, f"iperf summary missing; log:\n{log_result.stdout}"
    assert gbps >= OFFLOAD_MIN_GBPS, (
        f"throughput {gbps:.2f} Gbps below {OFFLOAD_MIN_GBPS} Gbps — "
        f"probably SW fallback"
    )

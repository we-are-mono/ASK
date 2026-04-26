"""IPv4 control-plane edge case 1a: IP options.

Injects packets carrying record-route and source-route options via scapy
on the LAN VM. Records the per-FQ frame-count delta on the DUT into a
golden file (regen with ASK_REGEN_GOLDEN=1); subsequent runs
assert byte-equality.

Tripwire shape: we don't pre-suppose whether FMAN drops options-bearing
packets, punts them to the kernel slow path, or fast-paths them.
Whatever it does today gets pinned. A future change to FMAN microcode
or the PCD config that alters this behaviour fails the test loudly,
flagging it for human review.
"""

from __future__ import annotations

import asyncio
import os
import textwrap

import pytest

from _topology import (
    assert_counter_signature,
    counter_signature,
    golden_for,
    lan_run_python,
)


WAN_IPERF_IP = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")

# Unique 5-tuple bits so cross-talk on shared subnets doesn't pollute
# the FQ delta. Chosen well outside iperf3 (5201) and other common
# services.
TEST_DPORT  = 47131
TEST_SPORT  = 47101


_OPTION_VARIANTS: list[tuple[str, str, int]] = [
    # (label, scapy IPOption ctor expression, packet count)
    ("record_route",  "IPOption_RR(length=39)",                            3),
    ("loose_source",  "IPOption_LSRR(routers=['10.0.0.50','10.0.0.60'])",  3),
    ("strict_source", "IPOption_SSRR(routers=['10.0.0.50','10.0.0.60'])",  3),
]


def _injection_script(variant_expr: str, n: int) -> str:
    return textwrap.dedent(f"""
        from scapy.all import (
            IP, UDP, Raw, send,
            IPOption_RR, IPOption_LSRR, IPOption_SSRR,
        )
        opt = {variant_expr}
        pkt = (IP(dst="{WAN_IPERF_IP}", options=[opt])
               / UDP(sport={TEST_SPORT}, dport={TEST_DPORT})
               / Raw(b"X" * 32))
        send(pkt, count={n}, verbose=0, inter=0.05)
        print("INJECTED", {n})
    """).strip()


@pytest.mark.parametrize(
    "label,variant_expr,n",
    _OPTION_VARIANTS,
    ids=[v[0] for v in _OPTION_VARIANTS],
)
async def test_ipv4_edge_options_tripwire(
    aiohttp_session, target_agent, lan, splat_window,
    label, variant_expr, n,
):
    # Drain any in-flight traffic before the pre-snapshot.
    await asyncio.sleep(0.5)
    before = await target_agent.counters(
        aiohttp_session, ifaces=["eth3", "eth4"],
    )

    script = _injection_script(variant_expr, n)
    r = await lan_run_python(
        lan, script, label=f"ipv4_opt_{label}", timeout=30.0,
    )
    assert r.rc == 0, f"injection failed: rc={r.rc}, out={r.stdout!r}"
    assert f"INJECTED {n}" in r.stdout, (
        f"injection script did not finish: {r.stdout!r}"
    )

    # Let the DUT's classifier and FQ counters settle.
    await asyncio.sleep(1.0)
    after = await target_agent.counters(
        aiohttp_session, ifaces=["eth3", "eth4"],
    )

    # Per-FQ frame counts only — ethtool counters get noise from BMC
    # and link-state ticks during the test window, which would make
    # the golden non-deterministic.
    sig = counter_signature(
        before, after, key_regex=r"^fqid_stats/.*frame_count$",
    )
    assert_counter_signature(
        sig,
        golden_path=golden_for("ipv4_edge_options.json"),
        label=label,
    )

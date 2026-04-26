"""IPv6 control-plane edge case 2d: extension-header chain.

LAN sends IPv6 packets with a chained sequence of extension headers
(HopByHop → Routing → Fragment → DestOpt → UDP). Records the per-FQ
frame-count delta into a golden file; subsequent runs assert
byte-equality. Tripwire shape — same as 1a/2a — discriminates between
HW drop, slow-path punt, and fast-path handling without pre-supposing
any of them.
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
    ipv6_topology,  # noqa: F401  (fixture)
    lan_run_python,
)


WAN_IPV6 = os.environ.get("ASK_WAN_IPV6", "fc00:beef::99")


_VARIANTS: list[tuple[str, str, int]] = [
    # (label, scapy chain expression, packet count)
    ("hbh_only",
     "IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\\x00' * 4)])",
     3),
    ("hbh_dest",
     "IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\\x00' * 4)]) "
     "/ IPv6ExtHdrDestOpt(options=[PadN(optdata=b'\\x00' * 4)])",
     3),
    ("hbh_routing_dest",
     "IPv6ExtHdrHopByHop(options=[PadN(optdata=b'\\x00' * 4)]) "
     "/ IPv6ExtHdrRouting(addresses=['2001:db8::beef']) "
     "/ IPv6ExtHdrDestOpt(options=[PadN(optdata=b'\\x00' * 4)])",
     3),
]


def _injection_script(chain_expr: str, n: int) -> str:
    return textwrap.dedent(f"""
        from scapy.all import (
            IPv6, UDP, Raw, send,
            IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
            IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, PadN,
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
    before = await target_agent.counters(
        aiohttp_session, ifaces=["eth3", "eth4"],
    )

    script = _injection_script(chain_expr, n)
    r = await lan_run_python(
        lan, script, label=f"ipv6_eh_{label}", timeout=30.0,
    )
    assert r.rc == 0, f"injection failed: rc={r.rc}, out={r.stdout!r}"
    assert f"INJECTED {n}" in r.stdout, r.stdout

    await asyncio.sleep(1.0)
    after = await target_agent.counters(
        aiohttp_session, ifaces=["eth3", "eth4"],
    )

    sig = counter_signature(
        before, after, key_regex=r"^fqid_stats/.*frame_count$",
    )
    assert_counter_signature(
        sig,
        golden_path=golden_for("ipv6_edge_eh_chain.json"),
        label=label,
    )

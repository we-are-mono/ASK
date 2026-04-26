"""H9 regression — IPv4 conntrack cursor under parallel readers + mutators."""

from __future__ import annotations

import struct

from _query_vs_mutator import CMM_TABLES_BROAD, CursorSpec, run_query_vs_mutator


CMD_IPV4_CONNTRACK = 0x0314
ACTION_DEREGISTER  = 1
ACTION_QUERY       = 6


def _ct_cmd(
    action: int,
    saddr: int = 0, daddr: int = 0, sport: int = 0, dport: int = 0,
    saddr_reply: int = 0, daddr_reply: int = 0,
    sport_reply: int = 0, dport_reply: int = 0,
    protocol: int = 0, flags: int = 0,
) -> bytes:
    # struct CtCommand (packed, see cdx/fe.h:_tCtCommand).
    return struct.pack(
        "<HHIIHHIIHHHHQII",
        action, 0,
        saddr, daddr, sport, dport,
        saddr_reply, daddr_reply, sport_reply, dport_reply,
        protocol, flags,
        0, 0, 0,
    )


async def test_concurrent_query_vs_mutator_ipv4_ct(
    aiohttp_session, target_agent, splat_window,
):
    spec = CursorSpec(
        name="ipv4_ct",
        fci_calls=[
            (CMD_IPV4_CONNTRACK, _ct_cmd(ACTION_QUERY)),
            # Bogus 5-tuple → walks the CT table, returns not-found.
            (CMD_IPV4_CONNTRACK, _ct_cmd(
                ACTION_DEREGISTER,
                saddr=0xDEADBEEF, daddr=0xCAFEBABE,
                sport=0xBEE5, dport=0xBADF,
                protocol=17,
            )),
        ],
        cmm_tables=CMM_TABLES_BROAD,
    )
    await run_query_vs_mutator(aiohttp_session, target_agent, spec)

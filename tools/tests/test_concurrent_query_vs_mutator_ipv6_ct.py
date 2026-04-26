"""H9 regression — IPv6 conntrack cursor under parallel readers + mutators."""

from __future__ import annotations

import struct

from _query_vs_mutator import CMM_TABLES_BROAD, CursorSpec, run_query_vs_mutator


CMD_IPV6_CONNTRACK = 0x0414
ACTION_DEREGISTER  = 1
ACTION_QUERY       = 6


def _ct6_cmd(
    action: int,
    saddr: bytes = b"\x00" * 16,
    daddr: bytes = b"\x00" * 16,
    sport: int = 0, dport: int = 0,
    saddr_reply: bytes = b"\x00" * 16,
    daddr_reply: bytes = b"\x00" * 16,
    sport_reply: int = 0, dport_reply: int = 0,
    protocol: int = 0, flags: int = 0,
) -> bytes:
    # struct CtCommandIPv6 (packed, see cdx/fe.h:_tCtCommandIPv6).
    return (
        struct.pack("<HH", action, 0)
        + saddr.ljust(16, b"\x00")[:16]
        + daddr.ljust(16, b"\x00")[:16]
        + struct.pack("<HH", sport, dport)
        + saddr_reply.ljust(16, b"\x00")[:16]
        + daddr_reply.ljust(16, b"\x00")[:16]
        + struct.pack("<HHHHQII",
                      sport_reply, dport_reply, protocol, flags,
                      0, 0, 0)
    )


async def test_concurrent_query_vs_mutator_ipv6_ct(
    aiohttp_session, target_agent, splat_window,
):
    spec = CursorSpec(
        name="ipv6_ct",
        fci_calls=[
            (CMD_IPV6_CONNTRACK, _ct6_cmd(ACTION_QUERY)),
            (CMD_IPV6_CONNTRACK, _ct6_cmd(
                ACTION_DEREGISTER,
                saddr=b"\xde\xad\xbe\xef" * 4,
                daddr=b"\xca\xfe\xba\xbe" * 4,
                sport=0xBEE5, dport=0xBADF,
                protocol=17,
            )),
        ],
        cmm_tables=CMM_TABLES_BROAD,
    )
    await run_query_vs_mutator(aiohttp_session, target_agent, spec)

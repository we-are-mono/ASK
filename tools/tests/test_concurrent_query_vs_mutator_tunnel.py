"""H9 regression — tunnel cursor under parallel readers + mutators.

Tunnel is the odd one out: query vs mutator are *separate command codes*
(CMD_TNL_QUERY / CMD_TNL_DELETE) rather than an action field on a single
opcode. The runner doesn't care — it just round-robins through fci_calls.
"""

from __future__ import annotations

import struct

from _query_vs_mutator import CMM_TABLES_BROAD, CursorSpec, run_query_vs_mutator


CMD_TNL_DELETE      = 0x0B02
CMD_TNL_QUERY       = 0x0B05
CMD_TNL_QUERY_CONT  = 0x0B06


def _tnl_query_payload() -> bytes:
    # struct TNLCommand_query — 72 B, send a zero-filled stub. Walks the
    # tunnel snapshot cursor regardless of payload contents.
    return b"\x00" * 72


def _tnl_delete_cmd(name: bytes) -> bytes:
    # struct TNLCommand_delete = U8 name[16].
    return name.ljust(16, b"\x00")[:16]


async def test_concurrent_query_vs_mutator_tunnel(
    aiohttp_session, target_agent, splat_window,
):
    spec = CursorSpec(
        name="tunnel",
        fci_calls=[
            (CMD_TNL_QUERY,      _tnl_query_payload()),
            (CMD_TNL_QUERY_CONT, _tnl_query_payload()),
            (CMD_TNL_DELETE,     _tnl_delete_cmd(b"definitely.not")),
        ],
        cmm_tables=CMM_TABLES_BROAD,
    )
    await run_query_vs_mutator(aiohttp_session, target_agent, spec)

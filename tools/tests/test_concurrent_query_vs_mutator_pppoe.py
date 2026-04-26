"""H9 regression — PPPoE cursor under parallel readers + mutators."""

from __future__ import annotations

import struct

from _query_vs_mutator import CMM_TABLES_BROAD, CursorSpec, run_query_vs_mutator


CMD_PPPOE_ENTRY    = 0x0601
ACTION_DEREGISTER  = 1
ACTION_QUERY       = 6
IF_NAME_SIZE       = 16


def _pppoe_cmd(
    action: int,
    session_id: int = 0,
    mac: bytes = b"\x00" * 6,
    phy_intf: bytes = b"",
    log_intf: bytes = b"",
    mode: int = 0,
) -> bytes:
    # struct PPPoECommand (cdx/fe.h:_tPPPoECommand). Not __packed; the
    # trailing fields land on natural boundaries — explicit padding kept.
    return (
        struct.pack("<HH", action, session_id)
        + mac.ljust(6, b"\x00")[:6]
        + phy_intf.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
        + log_intf.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
        + struct.pack("<H", mode)
    )


async def test_concurrent_query_vs_mutator_pppoe(
    aiohttp_session, target_agent, splat_window,
):
    spec = CursorSpec(
        name="pppoe",
        fci_calls=[
            (CMD_PPPOE_ENTRY, _pppoe_cmd(ACTION_QUERY)),
            (CMD_PPPOE_ENTRY, _pppoe_cmd(
                ACTION_DEREGISTER,
                session_id=0xBEEF,
                mac=b"\xde\xad\xbe\xef\xca\xfe",
                phy_intf=b"definitely.not.here",
            )),
        ],
        cmm_tables=CMM_TABLES_BROAD,
    )
    await run_query_vs_mutator(aiohttp_session, target_agent, spec)

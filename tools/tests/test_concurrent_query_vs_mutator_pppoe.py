"""H9 regression — PPPoE cursor under parallel readers + mutators."""

from __future__ import annotations

from _pppoe_helpers import (
    ACTION_DEREGISTER,
    ACTION_QUERY,
    CMD_PPPOE_ENTRY,
    pppoe_cmd as _pppoe_cmd,
)
from _query_vs_mutator import CMM_TABLES_BROAD, CursorSpec, run_query_vs_mutator


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

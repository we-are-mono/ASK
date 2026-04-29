"""H9 regression — IPsec SA cursor under parallel readers + mutators.

Fills the per-cursor coverage gap left by the original H9 fix
(613efa3 + 75dfbba): vlan, ipv4_ct, ipv6_ct, pppoe, tunnel were
all wired up to the runner; the IPsec SA cursor in
cdx/query_ipsec.c was not. Without this test, a regression of
ipsec_query_mutex (the per-cursor lock around pSASnapshot,
sa_hash_index, sa_snapshot_entries, sa_snapshot_index,
sa_snapshot_buf_entries) would not be caught by the existing per-
cursor concurrent-stress matrix.

The mutator-shape opcode is CMD_IPSEC_SA_DELETE on a sagd that
shouldn't exist (within the test-reserved SAGD_BASE range) — exercises
the cache-walk path under cursor read without changing global state.
"""

from __future__ import annotations

from _ipsec_helpers import (
    ACTION_QUERY,
    CMD_IPSEC_SA_ACTION_QUERY,
    CMD_IPSEC_SA_DELETE,
    SAGD_BASE,
    delete_sa,
    query_sa,
)
from _query_vs_mutator import CMM_TABLES_BROAD, CursorSpec, run_query_vs_mutator


async def test_concurrent_query_vs_mutator_ipsec(
    aiohttp_session, target_agent, splat_window,
):
    spec = CursorSpec(
        name="ipsec",
        fci_calls=[
            (CMD_IPSEC_SA_ACTION_QUERY, query_sa(ACTION_QUERY)),
            # Mutator-shape: DELETE on a sagd in the test-reserved range
            # that no slice-1 test creates. Exercises the cache-walk
            # path concurrent with the cursor read.
            (CMD_IPSEC_SA_DELETE, delete_sa(SAGD_BASE + 0x0DEE)),
        ],
        cmm_tables=CMM_TABLES_BROAD,
    )
    await run_query_vs_mutator(aiohttp_session, target_agent, spec)

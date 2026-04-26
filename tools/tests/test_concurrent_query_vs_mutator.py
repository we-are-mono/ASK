"""H1/H9 concurrency regression — VLAN cursor under parallel readers + mutators.

ISSUES.md H1 (cdx_ioc_set_dpa_params globals) and H9 (per-subsystem
query-snapshot static state) were closed by per-subsystem locking
fixes. This test runs the kind of workload that *would have* tripped
those bugs pre-fix — multiple readers walking snapshot state while
mutators churn through the VLAN cursor — and asserts no kernel splat.

Sibling files exercise the same shape against IPv4/IPv6 CT, PPPoE, and
tunnel cursors. The runner lives in _query_vs_mutator.py.
"""

from __future__ import annotations

import struct

from _query_vs_mutator import CMM_TABLES_BROAD, CursorSpec, run_query_vs_mutator


CMD_VLAN_ENTRY    = 0x0901
ACTION_DEREGISTER = 1
ACTION_QUERY      = 6
IF_NAME_SIZE      = 16


def _vlan_cmd(action: int, vlan_id: int = 0,
              vlan_if: bytes = b"", phy_if: bytes = b"",
              mac: bytes = b"\x00" * 6) -> bytes:
    vlan_if_padded = vlan_if.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    phy_if_padded  = phy_if.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    mac_padded     = mac.ljust(6, b"\x00")[:6]
    return (
        struct.pack("<HH", action, vlan_id)
        + vlan_if_padded
        + phy_if_padded
        + mac_padded
        + b"\x00\x00"
    )


async def test_concurrent_query_vs_mutator(
    aiohttp_session, target_agent, splat_window,
):
    spec = CursorSpec(
        name="vlan",
        fci_calls=[
            (CMD_VLAN_ENTRY, _vlan_cmd(ACTION_QUERY)),
            (CMD_VLAN_ENTRY, _vlan_cmd(
                ACTION_DEREGISTER, vlan_id=0xBEEF,
                vlan_if=b"definitely.not.here",
            )),
        ],
        cmm_tables=CMM_TABLES_BROAD,
    )
    await run_query_vs_mutator(aiohttp_session, target_agent, spec)

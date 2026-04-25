"""H1/H9 concurrency regression — parallel CMM queries + FCI mutators.

ISSUES.md H1 (cdx_ioc_set_dpa_params globals) and H9 (per-subsystem
query-snapshot static state) were closed by per-subsystem locking
fixes. This test runs the kind of workload that *would have* tripped
those bugs pre-fix — multiple readers walking snapshot state while
mutators churn through the same subsystems — and asserts no kernel
splat / no agent failure.

Oracle: splat_window catches KASAN / lockdep / WARN / BUG. Per-task
accounting tracks errors that aren't kernel-side (e.g. CMM crashes,
agent 5xx). kmemleak isn't part of the oracle here — the workload's
broad backtrace surface overlaps the DPAA bpool refill baseline
(ISSUES.md X3) too much for a clean filter, and splat_window already
catches the failure mode this test cares about.
"""

from __future__ import annotations

import asyncio
import struct


# FCI opcodes + actions used by this test.
CMD_VLAN_ENTRY    = 0x0901
ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1
ACTION_QUERY      = 6
IF_NAME_SIZE      = 16


def _vlan_cmd(action: int, vlan_id: int = 0,
              vlan_if: bytes = b"", phy_if: bytes = b"",
              mac: bytes = b"\x00" * 6) -> bytes:
    """Pack a VlanCommand — duplicate of test_vlan_control.py's helper.
    Kept inline so this file stays standalone."""
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


# Workload knobs. Total ops ≈ (N_QUERY + N_MUTATOR) × ITERS = 120,
# spread across the tasks asyncio.gather()s together.
N_QUERY_TASKS   = 3
N_MUTATOR_TASKS = 3
ITERS_PER_TASK  = 20

QUERY_TABLES = ["connections", "vlan", "mcast", "bridge", "pppoe"]


async def test_concurrent_query_vs_mutator(
    aiohttp_session, target_agent, splat_window,
):
    """Hammer the kernel control-plane with concurrent readers and
    mutators. Asserts no splat fires (per splat_window) and every
    task completes its iterations without agent-side errors."""
    failures: list[tuple[str, str, dict]] = []

    async def run_query(task_id: int) -> None:
        for k in range(ITERS_PER_TASK):
            table = QUERY_TABLES[(task_id + k) % len(QUERY_TABLES)]
            r = await target_agent.cmm_query(aiohttp_session, table=table)
            # Some tables may legitimately return non-zero rc when the
            # corresponding feature isn't currently active (empty
            # bridge table etc.); the test only cares that the agent
            # returned a valid JSON response — i.e. CMM didn't crash.
            if "error" in r:
                failures.append((f"q{task_id}", f"cmm query {table}", r))

    async def run_mutator(task_id: int) -> None:
        # Two FCI command shapes; alternate so the kernel sees both
        # snapshot reads (ACTION_QUERY) and mutation attempts
        # (ACTION_DEREGISTER) interleaved with the cmm queries.
        query_cmd  = _vlan_cmd(action=ACTION_QUERY)
        dereg_cmd  = _vlan_cmd(
            action=ACTION_DEREGISTER, vlan_id=0xBEEF,
            vlan_if=b"definitely.not.here",
        )

        for k in range(ITERS_PER_TASK):
            cmd = query_cmd if (k & 1) else dereg_cmd
            r = await target_agent.fci_send(
                aiohttp_session, fcode=CMD_VLAN_ENTRY,
                length=len(cmd), payload=cmd, timeout_ms=2000,
            )
            if "error" in r:
                failures.append((f"m{task_id}", "fci vlan", r))

    tasks: list = []
    tasks.extend(run_query(i)   for i in range(N_QUERY_TASKS))
    tasks.extend(run_mutator(i) for i in range(N_MUTATOR_TASKS))
    await asyncio.gather(*tasks)

    assert not failures, (
        f"agent-side failures during concurrent stress "
        f"({len(failures)} of {(N_QUERY_TASKS + N_MUTATOR_TASKS) * ITERS_PER_TASK} ops): "
        f"{failures[:5]}"
    )

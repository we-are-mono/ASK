"""Shared runner for concurrent-query-vs-mutator tests (H9 regression net).

Each per-cursor sibling file declares a CursorSpec — which FCI calls the
mutator tasks alternate, and which CMM tables the reader tasks walk —
then awaits run_query_vs_mutator(). The runner stresses the cursor under
test from both directions in parallel so a regression of H9's per-cursor
mutex (snapshot races) shows up as a kernel splat.

Capability probe: before driving the workload, the runner sends one
fci_send with the spec's first mutator opcode. If the dispatcher returns
ERR_UNKNOWN_COMMAND the subsystem is gated out of the build (CDX_TODO_*);
the test is skipped instead of running silently against a no-op surface.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest


# cdx/fe.h:60 — what the dispatcher stamps when no entry matches the cmd code.
ERR_UNKNOWN_COMMAND = 1


@dataclass
class CursorSpec:
    name: str
    # Bytes the mutator tasks send via fci_send. Each call is a (fcode, payload)
    # pair; tasks round-robin through the list. Use both query- and mutator-
    # shaped calls so the cursor is exercised from both reader and writer paths.
    fci_calls: list[tuple[int, bytes]]
    # CMM tables the reader tasks query through cmm_query (round-robined).
    cmm_tables: list[str]


N_QUERY_TASKS   = 3
N_MUTATOR_TASKS = 3
ITERS_PER_TASK  = 20


async def run_query_vs_mutator(
    aiohttp_session,
    target_agent,
    spec: CursorSpec,
    *,
    n_query_tasks: int = N_QUERY_TASKS,
    n_mutator_tasks: int = N_MUTATOR_TASKS,
    iters_per_task: int = ITERS_PER_TASK,
    fci_timeout_ms: int = 2000,
) -> None:
    """Drive concurrent readers + mutators against the cursor in `spec`.

    Asserts no agent-side errors. Splat oracle is the caller's
    splat_window fixture — this runner is intentionally agnostic.
    """
    # Capability probe: bail with skip if the cursor's primary opcode
    # isn't even compiled in. Without this, a build that disables the
    # subsystem (e.g. CDX_TODO_PPPOE) would let the test pass silently
    # — every mutator iteration returns ERR_UNKNOWN_COMMAND in
    # reply_rc, which the failure check below ("error" in r) doesn't
    # see, and the workload is a no-op.
    probe_fcode, probe_payload = spec.fci_calls[0]
    probe = await target_agent.fci_send(
        aiohttp_session,
        fcode=probe_fcode, length=len(probe_payload), payload=probe_payload,
        timeout_ms=fci_timeout_ms,
    )
    if probe.get("reply_rc") == ERR_UNKNOWN_COMMAND:
        pytest.skip(
            f"{spec.name}: cmd 0x{probe_fcode:04x} is not registered "
            f"in this build (gated by CDX_TODO_*); no-op test."
        )

    failures: list[tuple[str, str, dict]] = []

    async def run_query(task_id: int) -> None:
        for k in range(iters_per_task):
            table = spec.cmm_tables[(task_id + k) % len(spec.cmm_tables)]
            r = await target_agent.cmm_query(aiohttp_session, table=table)
            # CMM may return non-zero rc for empty tables; we only care
            # that the agent itself didn't 5xx.
            if "error" in r:
                failures.append((spec.name, f"q{task_id} cmm {table}", r))

    async def run_mutator(task_id: int) -> None:
        for k in range(iters_per_task):
            fcode, payload = spec.fci_calls[(task_id + k) % len(spec.fci_calls)]
            r = await target_agent.fci_send(
                aiohttp_session,
                fcode=fcode,
                length=len(payload),
                payload=payload,
                timeout_ms=fci_timeout_ms,
            )
            if "error" in r:
                failures.append((spec.name, f"m{task_id} fci 0x{fcode:04x}", r))

    tasks: list = []
    tasks.extend(run_query(i)   for i in range(n_query_tasks))
    tasks.extend(run_mutator(i) for i in range(n_mutator_tasks))
    await asyncio.gather(*tasks)

    total_ops = (n_query_tasks + n_mutator_tasks) * iters_per_task
    assert not failures, (
        f"agent-side failures during {spec.name} stress "
        f"({len(failures)} of {total_ops} ops): {failures[:5]}"
    )


# ---- Standard CMM table set ---------------------------------------------

# Query *across* tables, regardless of which cursor the mutator targets:
# the H9 fix is about per-cursor isolation, so reading every cursor while
# the mutator hammers one of them is the right exercise.
CMM_TABLES_BROAD = [
    "connections", "v6-connections", "vlan",
    "mcast", "bridge", "pppoe", "tunnels",
]

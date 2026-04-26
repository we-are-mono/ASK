"""Failslab sweep over CMD_IPV4_CONNTRACK ACTION_REGISTER.

Drives ct_alloc() (cdx/control_ipv4.c:59) into NULL via fork-isolated
failslab; asserts the unwind in IPv4_HandleIP_CONNTRACK leaves no
leaked CT_PAIR allocations behind. No real connection is offloaded —
the 5-tuple is bogus; the kernel just walks the hash, finds nothing,
allocates, and returns.

Pre-iter DEREGISTER lets the same 5-tuple be reused: a successful
REGISTER inserts the entry into the CT slist, so the next iteration
would bounce on ERR_CT_ENTRY_ALREADY_REGISTERED instead of reaching
ct_alloc.
"""

from __future__ import annotations

import asyncio
import os
import struct

CMD_IPV4_CONNTRACK    = 0x0314
ACTION_REGISTER       = 0
ACTION_DEREGISTER     = 1
NO_ERR                = 0
ERR_NOT_ENOUGH_MEMORY = 6  # cdx/fe.h — ct_alloc() == NULL → this code

IPV4_CT_LEAK_FILTER = [
    "ct_alloc",
    "IPv4_HandleIP_CONNTRACK",
    "ipv4_conntrack_handle",
]


def _ct_cmd(
    action: int,
    saddr: int = 0xC0A80101, daddr: int = 0xC0A80201,
    sport: int = 0xBEE5, dport: int = 0xBADF,
    saddr_reply: int = 0xC0A80201, daddr_reply: int = 0xC0A80101,
    sport_reply: int = 0xBADF, dport_reply: int = 0xBEE5,
    protocol: int = 17, flags: int = 0,
) -> bytes:
    # struct CtCommand (cdx/fe.h, __packed). 48 B total.
    return struct.pack(
        "<HHIIHHIIHHHHQII",
        action, 0,
        saddr, daddr, sport, dport,
        saddr_reply, daddr_reply, sport_reply, dport_reply,
        protocol, flags,
        0, 0, 0,
    )


# Sweep walks N from 1..NSWEEP, faulting exactly the Nth kmalloc by the
# agent's child task. ct_alloc sits past the netlink+fci scaffold, so the
# sweep needs enough headroom to reach it.
NSWEEP = int(os.environ.get("ASK_IPV4_CT_FAILSLAB_SWEEP", "100"))
KMEMLEAK_AGE_GRACE_S = 7.0


async def test_ipv4_ct_register_failslab_sweep(
    aiohttp_session, target_agent, splat_window,
):
    register_cmd  = _ct_cmd(ACTION_REGISTER)
    dereg_cmd     = _ct_cmd(ACTION_DEREGISTER)

    async def _dereg() -> None:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IPV4_CONNTRACK,
            length=len(dereg_cmd), payload=dereg_cmd, timeout_ms=2000,
        )

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []

    for n in range(1, NSWEEP + 1):
        await _dereg()  # clear any leftover from prior iteration

        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IPV4_CONNTRACK,
            length=len(register_cmd), payload=register_cmd,
            timeout_ms=3000, failslab_times=n,
        )
        reply_rc = r.get("reply_rc")
        send_err = r.get("send_error")
        outcomes.append((n, reply_rc, send_err))

        if reply_rc == NO_ERR and send_err is None:
            await _dereg()

    await _dereg()

    faulted = [n for n, rc, e in outcomes if rc == ERR_NOT_ENOUGH_MEMORY]
    assert faulted, (
        f"failslab sweep never drove ct_alloc to NULL across "
        f"times=1..{NSWEEP}; outcomes={outcomes}."
    )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=IPV4_CT_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab REGISTER sweep (1..{NSWEEP}) leaked {leak_count} "
            f"ipv4-ct-path object(s); {len(faulted)} iteration(s) hit "
            f"ERR_NOT_ENOUGH_MEMORY.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

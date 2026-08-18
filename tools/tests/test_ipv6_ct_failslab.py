"""Failslab sweep over CMD_IPV6_CONNTRACK ACTION_REGISTER.

Mirror of test_ipv4_ct_failslab.py against the IPv6 conntrack handler
(cdx/control_ipv6.c). ct_alloc() is the same allocator function as the
IPv4 path; the leak filter is intentionally narrow to the v6 caller so
this test's signal can't cross-fire on IPv4 leftovers.
"""

from __future__ import annotations

import asyncio
import os
import struct

CMD_IPV6_CONNTRACK    = 0x0414
ACTION_REGISTER       = 0
ACTION_DEREGISTER     = 1
NO_ERR                = 0
ERR_NOT_ENOUGH_MEMORY = 6

IPV6_CT_LEAK_FILTER = [
    "ipv6_conntrack_handle",
    "control_ipv6",
]


def _ct6_cmd(
    action: int,
    saddr: bytes = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01",
    daddr: bytes = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02",
    sport: int = 0xBEE5, dport: int = 0xBADF,
    saddr_reply: bytes | None = None,
    daddr_reply: bytes | None = None,
    sport_reply: int = 0xBADF, dport_reply: int = 0xBEE5,
    protocol: int = 17, flags: int = 0,
) -> bytes:
    if saddr_reply is None:
        saddr_reply = daddr
    if daddr_reply is None:
        daddr_reply = saddr
    # struct CtCommandIPv6 (cdx/fe.h, __packed). 96 B total.
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


# See test_ipv4_ct_failslab.py for the rationale on the sweep range.
NSWEEP = int(os.environ.get("ASK_IPV6_CT_FAILSLAB_SWEEP", "100"))
KMEMLEAK_AGE_GRACE_S = 7.0


async def test_ipv6_ct_register_failslab_sweep(
    aiohttp_session, target_agent, splat_window,
):
    register_cmd = _ct6_cmd(ACTION_REGISTER)
    dereg_cmd    = _ct6_cmd(ACTION_DEREGISTER)

    async def _dereg() -> None:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IPV6_CONNTRACK,
            length=len(dereg_cmd), payload=dereg_cmd, timeout_ms=2000,
        )

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []

    for n in range(1, NSWEEP + 1):
        await _dereg()

        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IPV6_CONNTRACK,
            length=len(register_cmd), payload=register_cmd,
            timeout_ms=3000, failslab_times=n,
        )
        reply_rc = r.get("reply_rc")
        send_err = r.get("send_error")
        # 4th field: /proc/self/fail-nth after the syscall — == n means the
        # path made zero fault-eligible allocations (injection tested
        # nothing), 0 means the fault fired; see ISSUES.md A70.
        outcomes.append((n, reply_rc, send_err, r.get("fail_nth_residue")))

        if reply_rc == NO_ERR and send_err is None:
            await _dereg()

    await _dereg()

    faulted = [n for n, rc, e, *_ in outcomes if rc == ERR_NOT_ENOUGH_MEMORY]
    assert faulted, (
        f"failslab sweep never drove ct_alloc to NULL across "
        f"times=1..{NSWEEP}; outcomes={outcomes}."
    )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=IPV6_CT_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e, *_ in outcomes
        )
        raise AssertionError(
            f"failslab REGISTER sweep (1..{NSWEEP}) leaked {leak_count} "
            f"ipv6-ct-path object(s); {len(faulted)} iteration(s) hit "
            f"ERR_NOT_ENOUGH_MEMORY.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

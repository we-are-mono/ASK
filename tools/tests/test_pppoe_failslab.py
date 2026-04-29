"""Failslab sweep over CMD_PPPOE_ENTRY ACTION_REGISTER.

Drives pppoe_alloc() (cdx/control_pppoe.c:358) into NULL via fork-isolated
failslab; asserts the unwind in PPPoE_Handle_Entry leaves no leaked
PPPoE_Info allocations behind. The wire payload uses a synthetic session
whose log_intf name doesn't collide with any onif registered at boot;
the kernel just walks the hash, validates the phy_intf, allocates, sets
up the iface chain, and either succeeds or unwinds.

Pre-iter DEREGISTER lets the same session_id+mac+log_intf be reused: a
successful REGISTER inserts the session into pppoe_cache and registers
an onif with the log_intf name, so the next iteration would bounce on
ERR_PPPOE_ENTRY_ALREADY_REGISTERED at cdx/control_pppoe.c:344-355
instead of reaching pppoe_alloc.

Note: REGISTER also requires phy_intf to be a known onif
(cdx/control_pppoe.c:348-350 returns ERR_UNKNOWN_INTERFACE otherwise).
We pass eth3 because that's the WAN-side iface registered by dpa_app at
boot. If REGISTER consistently returns ERR_UNKNOWN_INTERFACE, the test
will skip with a clear diagnosis rather than leak the unobservable
unwind state into a flaky failslab signal.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from _pppoe_helpers import (
    ACTION_DEREGISTER,
    ACTION_REGISTER,
    CMD_PPPOE_ENTRY,
    PPPOE_LEAK_FILTER,
    pppoe_cmd,
)


NO_ERR                              = 0
ERR_UNKNOWN_INTERFACE               = 5
ERR_NOT_ENOUGH_MEMORY               = 6   # cdx/fe.h:67 — pppoe_alloc()==NULL
ERR_PPPOE_ENTRY_ALREADY_REGISTERED  = 800  # cdx/fe.h:116


# Synthetic session — must not collide with any cmm-driven session
# that might exist on the box, AND must not collide with the offload
# or name_bounds tests' (sid, mac) buckets so a leftover from one
# doesn't ALREADY_REGISTER-block another.
SESSION_ID  = 0xFA01
MAC         = b"\x02\xfa\x11\x5b\xab\x01"
PHY_INTF    = b"eth3"
LOG_INTF    = b"flsppp"
MODE        = 0


# Sweep walks N from 1..NSWEEP. pppoe_alloc sits past the netlink+fci
# scaffold and after the get_onif_by_name() lookup chain; NSWEEP=100
# matches the headroom test_tunnel_failslab uses for tunnel_alloc.
NSWEEP = int(os.environ.get("ASK_PPPOE_FAILSLAB_SWEEP", "100"))
KMEMLEAK_AGE_GRACE_S = 7.0


def _register() -> bytes:
    return pppoe_cmd(
        action=ACTION_REGISTER, session_id=SESSION_ID, mac=MAC,
        phy_intf=PHY_INTF, log_intf=LOG_INTF, mode=MODE,
    )


def _deregister() -> bytes:
    return pppoe_cmd(
        action=ACTION_DEREGISTER, session_id=SESSION_ID, mac=MAC,
        phy_intf=PHY_INTF, log_intf=LOG_INTF, mode=MODE,
    )


async def test_pppoe_register_failslab_sweep(
    aiohttp_session, target_agent, splat_window,
):
    register_cmd = _register()
    deregister_cmd = _deregister()

    async def _dereg() -> None:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_PPPOE_ENTRY,
            length=len(deregister_cmd), payload=deregister_cmd,
            timeout_ms=2000,
        )

    # Probe once unencumbered — if eth3 isn't a known onif, every REGISTER
    # will return ERR_UNKNOWN_INTERFACE and the sweep can't reach
    # pppoe_alloc. Skip with a clear diagnosis rather than emit an
    # uninterpretable empty-faulted-list assertion at the end.
    await _dereg()  # ensure clean slate
    probe = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_PPPOE_ENTRY,
        length=len(register_cmd), payload=register_cmd, timeout_ms=2000,
    )
    if probe.get("reply_rc") == ERR_UNKNOWN_INTERFACE:
        pytest.skip(
            f"phy_intf={PHY_INTF.decode()} not registered as an onif at boot "
            "— REGISTER can't reach pppoe_alloc; failslab sweep would be "
            "an empty oracle. Likely cmm/dpa_app didn't run, or eth3 was "
            "renamed. Investigate before re-enabling."
        )
    # Probe registered the entry; clear it before the sweep starts.
    await _dereg()

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []

    for n in range(1, NSWEEP + 1):
        await _dereg()  # clear any leftover from prior iteration

        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_PPPOE_ENTRY,
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
        f"failslab sweep never drove pppoe_alloc to NULL across "
        f"times=1..{NSWEEP}; outcomes={outcomes}."
    )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=PPPOE_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab REGISTER sweep (1..{NSWEEP}) leaked {leak_count} "
            f"pppoe-path object(s); {len(faulted)} iteration(s) hit "
            f"ERR_NOT_ENOUGH_MEMORY.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

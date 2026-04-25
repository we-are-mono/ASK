"""Fault-injection sweep over cdx_create_mcast_group / _delete_mcast_group_member.

A3-equivalent runtime coverage. ISSUES.md A3a-A3e fixed err_ret cascades
in several init functions; A3's concern — "an allocation failure anywhere
in the cascade must not leak earlier acquisitions" — applies equally to
the mcast ADD/REMOVE paths, which run at runtime via FCI (so we can
actually exercise them in a pytest loop, unlike module-init paths).

Mechanism:
  * Agent's /fci/send accepts `failslab_times=N`. Under the hood it forks
    a child, arms `/sys/kernel/debug/failslab/probability=100` + `times=N`
    + `/proc/<child>/make-it-fail=1` AFTER opening the netlink socket
    (syscall-path kmallocs spent; failslab counter is aimed at the FCI
    handler + cdx dispatcher + mcast handler kmallocs).
  * We sweep N from 1..NSWEEP. At each step: clear kmemleak cursor, send
    ADD with failslab armed, disarm implicitly when child exits, scan
    kmemleak filtered to ASK code. Leak count must stay at 0 whether
    ADD succeeded (allocation passed the faulting window) or failed
    (err_ret walked the cleanup cascade).

The single-listener variant keeps the allocation footprint small — a
full-fat 8-listener scenario would spend `times` counters on
create_exthash_entry4mcast_member iterations that aren't the interesting
targets. Coverage expansion (UPDATE, REMOVE, 9-overflow) can add their
own loops later.
"""

from __future__ import annotations

import asyncio
import os
import struct

import pytest_asyncio


# Narrower than ASK_KMEMLEAK_FILTER (which matches module-tag frames and
# triggers on boot-time `modprobe pid N` allocations in dpaa_vwd_init /
# abm_build_l2flow that happen to carry [cdx]/[auto_bridge] annotations).
# A leak caused by this test's sweep will always have one of these
# mcast-path function names somewhere in its backtrace; baseline DPAA
# noise won't.
MCAST_LEAK_FILTER = [
    "cdx_create_mcast_group",
    "cdx_update_mcast_group",
    "cdx_delete_mcast_group_member",
    "cdx_add_mcast_table_entry",
    "cdx_free_exthash_mcast_members",
    "create_exthash_entry4mcast_member",
]


# Wire constants — mirror of test_mcast_pagination.py. Self-contained
# deliberately; keeping the two files independent avoids the
# tools.tests.* import gymnastics pytest's rootdir-flat-layout forces.
CMD_MC4_MULTICAST      = 0x0701
CDX_MC_ACTION_ADD      = 0
CDX_MC_ACTION_REMOVE   = 1
CDX_MC_ACTION_UPDATE   = 2
ACTION_QUERY           = 6
ACTION_QUERY_CONT      = 7
NO_ERR                 = 0
ERR_MC_ENTRY_NOT_FOUND = 700  # cdx/fe.h — QUERY when no group exists
ERR_MC_CONFIG          = 707  # cdx/fe.h — stamped when cdx_create_mcast_group returns -1
IF_NAME_SIZE           = 16
MC4_MIN_COMMAND_SIZE   = 44


def _ip_be_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _pack_mc4_output(iface: str) -> bytes:
    """48-byte MC4Output: timer(4) + output_device_str(16) + shaper_mask(1)
    + bitfield(1) + uc_mac(6) + queue(1) + new_output_device_str(16)
    + bitfield(1) + padding(2)."""
    name = iface.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    return (
        b"\x00\x00\x00\x00"   # timer
        + name                # output_device_str[16]
        + b"\x00"             # shaper_mask
        + b"\x00"             # bitfield (uc_bit/q_bit/rsvd)
        + b"\x00" * 6         # uc_mac
        + b"\x00"             # queue
        + b"\x00" * 16        # new_output_device_str
        + b"\x00"             # bitfield (if_bit/unused)
        + b"\x00\x00"         # padding[2]
    )


def _pack_mc4_command(action: int, listeners: list[str],
                     dst: str = "239.1.1.7", src: str = "10.0.0.141",
                     ingress: str = "eth3") -> bytes:
    n = len(listeners)
    header = (
        struct.pack("<HBB", action, 0, 0)
        + _ip_be_bytes(src)
        + _ip_be_bytes(dst)
        + struct.pack("<I", n)
    )
    ingress_field = ingress.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    outputs = b"".join(_pack_mc4_output(i) for i in listeners)
    wire = header + ingress_field + outputs
    if len(wire) < MC4_MIN_COMMAND_SIZE:
        wire += b"\x00" * (MC4_MIN_COMMAND_SIZE - len(wire))
    return wire


TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth4")
VID           = int(os.environ.get("ASK_MCAST_FAILSLAB_VID", "231"))
LISTENER_IF   = f"{TARGET_LAN_IF}.{VID}"

# How deep to sweep. The mcast ADD path allocates for: pMcastGrpInfo
# (1x kzalloc), RtEntry and InsEntryInfo (on-stack), then per-listener
# create_exthash_entry4mcast_member runs ExternalHashTableAllocEntry (~1
# kmalloc per listener) plus the CT entry insert which allocates a
# pCtEntry chain inside cdx_add_mcast_table_entry. 30 covers all these
# plus the send/recv syscall path's own kmallocs and a margin.
NSWEEP = int(os.environ.get("ASK_MCAST_FAILSLAB_SWEEP", "30"))

# Kmemleak's default jiffies_min_age is 5s — a freshly-allocated object
# isn't classified as unreferenced until it's aged past that. Wait a
# little longer than that after the sweep finishes so the final scan
# sees every leak the sweep caused.
KMEMLEAK_AGE_GRACE_S = 7.0


@pytest_asyncio.fixture
async def two_vlan_listeners(aiohttp_session, target_agent):
    """Two VLAN subifs (`eth4.{VID}` and `eth4.{VID+1}`) for the UPDATE
    sweep — the group is seeded with the first listener via a clean
    ADD, then each iteration tries to UPDATE in the second listener
    under failslab. CMM picks both up via netlink so get_onif_by_name
    succeeds for both names."""
    listener_a = f"{TARGET_LAN_IF}.{VID}"
    listener_b = f"{TARGET_LAN_IF}.{VID + 1}"
    for n in (listener_a, listener_b):
        await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", n])
    try:
        for vid_off, name in ((0, listener_a), (1, listener_b)):
            r = await target_agent.exec_cmd(aiohttp_session, [
                "ip", "link", "add", "link", TARGET_LAN_IF,
                "name", name, "type", "vlan", "id", str(VID + vid_off),
            ])
            assert r["rc"] == 0, f"vlan add {name} failed: {r}"
            r = await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "set", name, "up"],
            )
            assert r["rc"] == 0, f"vlan up {name} failed: {r}"
        await asyncio.sleep(1.0)
        yield listener_a, listener_b
    finally:
        for n in (listener_a, listener_b):
            await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", n])


@pytest_asyncio.fixture
async def one_vlan_listener(aiohttp_session, target_agent):
    """One VLAN subif on the LAN-facing port. CMM registers it into the
    FMAN onif table so get_onif_by_name(LISTENER_IF) succeeds — a
    prerequisite for mcast ADD to ever reach the allocation-heavy
    path (otherwise it fails in create_exthash_entry4mcast_member on
    the onif lookup, before any interesting kmalloc runs)."""
    # Nuke stale state.
    await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", LISTENER_IF])
    try:
        r = await target_agent.exec_cmd(aiohttp_session, [
            "ip", "link", "add", "link", TARGET_LAN_IF,
            "name", LISTENER_IF, "type", "vlan", "id", str(VID),
        ])
        assert r["rc"] == 0, f"vlan add failed: {r}"
        r = await target_agent.exec_cmd(
            aiohttp_session, ["ip", "link", "set", LISTENER_IF, "up"],
        )
        assert r["rc"] == 0, f"vlan up failed: {r}"
        await asyncio.sleep(1.0)  # let CMM pick up NEWLINK
        yield LISTENER_IF
    finally:
        await target_agent.exec_cmd(
            aiohttp_session, ["ip", "link", "del", LISTENER_IF],
        )


async def _remove_if_present(target_agent, session, listeners: list[str]) -> None:
    """Idempotent REMOVE. Reply is discarded; ERR_MC_CONFIG (group
    doesn't exist) is the expected outcome when the previous iteration's
    ADD failed under failslab and there's nothing to clean up."""
    payload = _pack_mc4_command(CDX_MC_ACTION_REMOVE, listeners)
    await target_agent.fci_send(
        session, fcode=CMD_MC4_MULTICAST,
        length=len(payload), payload=payload, timeout_ms=2000,
    )


async def test_mcast_add_failslab_sweep(
    aiohttp_session, target_agent, splat_window, one_vlan_listener,
):
    """Sweep failslab `times` over the mcast ADD path; assert no kmemleak
    grows regardless of whether ADD succeeded or the err_ret cascade ran.

    Design note: kmemleak's jiffies_min_age (5s) means freshly-allocated
    objects aren't classified as unreferenced until they age past the
    threshold. A per-iteration scan-after-fault pattern would miss every
    leak a sweep step causes, because it'd race the grace period. So we
    batch: one cursor at the start, run the whole sweep, age-grace wait,
    single scan at the end. Trade-off: we lose the per-iteration
    attribution — a failing assert reports the aggregate, and bisecting
    (narrow NSWEEP or split the range) is on the investigator."""
    payload = _pack_mc4_command(CDX_MC_ACTION_ADD, [one_vlan_listener])

    # One cursor for the whole sweep. Any ASK-code allocation made
    # between this call and the final scan that's still unreferenced
    # is a sweep-induced leak.
    await target_agent.kmemleak_clear(aiohttp_session)

    # Track sweep outcomes so the failure message can say what happened.
    outcomes: list[tuple[int, int | None, str | None]] = []  # (n, reply_rc, send_err)

    for n in range(1, NSWEEP + 1):
        # Best-effort REMOVE: clean up whatever the previous iteration left.
        await _remove_if_present(target_agent, aiohttp_session, [one_vlan_listener])

        r = await target_agent.fci_send(
            aiohttp_session,
            fcode=CMD_MC4_MULTICAST,
            length=len(payload),
            payload=payload,
            timeout_ms=3000,
            failslab_times=n,
        )
        reply_rc = r.get("reply_rc")
        send_err = r.get("send_error")
        outcomes.append((n, reply_rc, send_err))

        if reply_rc == NO_ERR and send_err is None:
            # ADD succeeded (fault didn't catch the critical path). Clean
            # up so the next iteration doesn't trip on "group exists".
            await _remove_if_present(
                target_agent, aiohttp_session, [one_vlan_listener],
            )

    # Final REMOVE in case the last iteration left a group behind.
    await _remove_if_present(target_agent, aiohttp_session, [one_vlan_listener])

    # Oracle #1: failslab must actually have driven cdx into err_ret
    # for this sweep to mean anything. ERR_MC_CONFIG (707) is what
    # MC4_Command_Handler stamps when cdx_create_mcast_group returns
    # -1 (the listener loop hit create_exthash_entry4mcast_member
    # returning NULL, which is the failslab-induced failure we want).
    # If every iteration came back NO_ERR, either failslab is not
    # arming (fork-isolated make-it-fail broke), the `times` values
    # are being consumed entirely in the socket/netlink syscall path
    # before reaching cdx, or the handler is silently swallowing
    # errors — any of which invalidates the leak oracle below.
    faulted = [n for n, rc, e in outcomes if rc == ERR_MC_CONFIG]
    assert faulted, (
        f"failslab sweep never drove cdx into ERR_MC_CONFIG across "
        f"times=1..{NSWEEP}; outcomes={outcomes}. Either failslab "
        f"isn't firing in the cdx path, or cdx is swallowing errors."
    )

    # Oracle #2: kmemleak must show no ASK-code leaks. Wait for
    # kmemleak's jiffies_min_age grace to elapse so any
    # still-unreferenced allocation from the sweep is classifiable
    # by the scan below.
    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=MCAST_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab sweep (1..{NSWEEP}) leaked {leak_count} mcast-path "
            f"object(s); {len(faulted)} iteration(s) hit ERR_MC_CONFIG.\n"
            f"Per-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )


async def test_mcast_update_failslab_sweep(
    aiohttp_session, target_agent, splat_window, two_vlan_listeners,
):
    """Sweep failslab over the mcast UPDATE path. Companion to the ADD
    sweep, with the same oracle: some iterations must drive cdx to
    ERR_MC_CONFIG, none may leave mcast-path kmemleak objects behind.

    Setup: ADD listener_a once cleanly so a group exists. Each iteration
    then attempts to UPDATE in listener_b under failslab. Successful
    UPDATEs are immediately followed by a REMOVE of listener_b so the
    next iteration sees the group with only listener_a (avoiding the
    duplicate-member rejection at cdx_update_mcast_group line 757)."""
    listener_a, listener_b = two_vlan_listeners

    # Seed group with listener_a (no failslab, must succeed cleanly).
    seed = _pack_mc4_command(CDX_MC_ACTION_ADD, [listener_a])
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(seed), payload=seed, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, f"seed ADD failed: {r}"

    update_payload = _pack_mc4_command(CDX_MC_ACTION_UPDATE, [listener_b])
    remove_b      = _pack_mc4_command(CDX_MC_ACTION_REMOVE, [listener_b])

    # Cursor for the sweep window only — seed-ADD's allocations are
    # legitimate group state and shouldn't count against us.
    await target_agent.kmemleak_clear(aiohttp_session)

    # Track listener_b's presence so the per-iter cleanup hits the
    # right cdx_delete branch. Caveat: ISSUES.md M12 — REMOVE's
    # full-group-delete fast path triggers whenever request count
    # equals current group count, IGNORING listener names. So a naive
    # `REMOVE [b]` against `{ a }` (counts both 1) destroys the group
    # we want to keep seeding from. Skipping the cleanup in that case.
    b_in_group = False
    outcomes: list[tuple[int, int | None, str | None]] = []
    for n in range(1, NSWEEP + 1):
        if b_in_group:
            # Group is { a, b } (count 2). REMOVE [b] (count 1) takes
            # the per-listener path: removes b, keeps a. Group ends
            # at { a } again.
            await target_agent.fci_send(
                aiohttp_session, fcode=CMD_MC4_MULTICAST,
                length=len(remove_b), payload=remove_b, timeout_ms=2000,
            )
            b_in_group = False

        r = await target_agent.fci_send(
            aiohttp_session,
            fcode=CMD_MC4_MULTICAST,
            length=len(update_payload),
            payload=update_payload,
            timeout_ms=3000,
            failslab_times=n,
        )
        outcomes.append((n, r.get("reply_rc"), r.get("send_error")))
        if r.get("reply_rc") == NO_ERR and r.get("send_error") is None:
            b_in_group = True

    # Final teardown: pass exactly the group's current listener set so
    # the count-match fast path triggers a full-group delete cleanly.
    final_listeners = [listener_a, listener_b] if b_in_group else [listener_a]
    full_remove = _pack_mc4_command(CDX_MC_ACTION_REMOVE, final_listeners)
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(full_remove), payload=full_remove, timeout_ms=2000,
    )

    faulted = [n for n, rc, e in outcomes if rc == ERR_MC_CONFIG]
    assert faulted, (
        f"failslab UPDATE sweep never drove cdx into ERR_MC_CONFIG "
        f"across times=1..{NSWEEP}; outcomes={outcomes}. The UPDATE "
        f"path's create_exthash_entry4mcast_member allocation didn't "
        f"trip — either failslab plumbing broke or cdx swallowed the "
        f"error."
    )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=MCAST_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab UPDATE sweep (1..{NSWEEP}) leaked {leak_count} "
            f"mcast-path object(s); {len(faulted)} iteration(s) hit "
            f"ERR_MC_CONFIG.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )


async def test_mcast_remove_with_nonmember_listener_rejects(
    aiohttp_session, target_agent, splat_window, one_vlan_listener,
):
    """ISSUES.md M12 regression: REMOVE with a listener name that is
    not a member of the group must NOT destroy the group, even when
    the request count happens to match the group's current member
    count (which used to trip an unconditional full-group-delete
    fast path)."""
    listener_a = one_vlan_listener
    bogus = f"{TARGET_LAN_IF}.999"   # never registered as an onif

    # Seed { listener_a }, count 1.
    seed = _pack_mc4_command(CDX_MC_ACTION_ADD, [listener_a])
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(seed), payload=seed, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, f"seed ADD failed: {r}"

    # REMOVE [bogus] — count 1, group count 1. Pre-fix: count-match
    # fast path destroys the group. Post-fix: pre-validation catches
    # the unknown name and returns ERR_MC_CONFIG without mutation.
    bad_remove = _pack_mc4_command(CDX_MC_ACTION_REMOVE, [bogus])
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(bad_remove), payload=bad_remove, timeout_ms=2000,
    )
    assert r.get("reply_rc") == ERR_MC_CONFIG, (
        f"REMOVE with bogus listener should return ERR_MC_CONFIG "
        f"(707), got {r}"
    )

    # Group must still exist with listener_a — verify via QUERY.
    query = _pack_mc4_command(ACTION_QUERY, [])
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(query), payload=query, timeout_ms=2000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"QUERY should find the group; got {r}. The bogus REMOVE "
        f"likely destroyed it (M12 regression)."
    )

    # Cleanup: legitimate REMOVE [listener_a] hits the count-match
    # fast path validly (validation passes since listener_a is a
    # real member, count matches, group cleanly deleted).
    teardown = _pack_mc4_command(CDX_MC_ACTION_REMOVE, [listener_a])
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(teardown), payload=teardown, timeout_ms=2000,
    )
    assert r.get("reply_rc") == NO_ERR, f"teardown REMOVE failed: {r}"


async def test_mcast_remove_failslab_sweep(
    aiohttp_session, target_agent, splat_window, one_vlan_listener,
):
    """Stress test of cdx_delete_mcast_group_member's locking + err-path
    discipline under failslab pressure. Companion to ADD/UPDATE sweeps,
    BUT with a different oracle.

    REMOVE has effectively no kmalloc sites in its critical path: the
    full-delete path is `list_del` + a chain of `kfree`s, the
    per-listener path's only allocation is buried in
    ExternalHashTableFmPcdHcSync's HC frame send which uses a
    pre-allocated pool. So failslab rarely (or never) fires inside
    cdx during REMOVE — empirically, 30/30 iterations under
    failslab_times=1..30 return NO_ERR.

    The sweep still has value:

      1. **Mutex release discipline.** mc_mutators_mutex (M10/M11) is
         taken at the top of MC{4,6}_Command_Handler for every
         ADD/REMOVE/UPDATE. A missed unlock on any return path would
         deadlock the next iteration's seed-ADD. 30 successful
         iterations is the oracle that all return paths unlock.
      2. **No leaks across the ADD-REMOVE cycle.** Single kmemleak
         cursor at start, scan after the sweep, asserts the
         mcast-path filter is clean.

    For real fault-induced err_ret coverage on REMOVE, see the M12
    regression test (which exercises the validation rejection path
    via a bogus listener name, not failslab)."""
    listener = one_vlan_listener
    seed_payload   = _pack_mc4_command(CDX_MC_ACTION_ADD, [listener])
    remove_payload = _pack_mc4_command(CDX_MC_ACTION_REMOVE, [listener])

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []

    for n in range(1, NSWEEP + 1):
        # Best-effort: clear any leftover from the previous iteration
        # (might be a stuck group with uiListenerCnt=0 if a prior
        # REMOVE faulted between members[] mutation and HW sync). The
        # subsequent ADD takes the duplicate-group path inside
        # cdx_create_mcast_group, which routes to cdx_update_mcast_group
        # and re-installs the listener into the empty slot.
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_MC4_MULTICAST,
            length=len(remove_payload), payload=remove_payload,
            timeout_ms=2000,
        )

        # Seed a fresh single-listener group. No failslab here — the
        # ADD path is exercised by test_mcast_add_failslab_sweep.
        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_MC4_MULTICAST,
            length=len(seed_payload), payload=seed_payload, timeout_ms=2000,
        )
        if r.get("reply_rc") != NO_ERR:
            # Couldn't seed (maybe the group is stuck). Skip this
            # iteration's REMOVE attempt; track it so the oracle
            # doesn't credit failslab for it.
            outcomes.append((n, None, "seed_failed"))
            continue

        r = await target_agent.fci_send(
            aiohttp_session,
            fcode=CMD_MC4_MULTICAST,
            length=len(remove_payload),
            payload=remove_payload,
            timeout_ms=3000,
            failslab_times=n,
        )
        outcomes.append((n, r.get("reply_rc"), r.get("send_error")))

    # Final cleanup attempt; ignore the outcome.
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(remove_payload), payload=remove_payload, timeout_ms=2000,
    )

    # Implicit oracle: getting here means all NSWEEP iterations
    # completed — no missed mutex unlock deadlocked us. seed_failed
    # outcomes are still acceptable (a partial-state group from a
    # prior REMOVE can briefly block a fresh ADD's duplicate-group
    # path), as long as enough iterations succeeded to exercise the
    # ADD-REMOVE cycle.
    successful_cycles = [
        n for n, rc, e in outcomes
        if e is None and rc == NO_ERR
    ]
    assert len(successful_cycles) >= NSWEEP // 2, (
        f"too few successful ADD-REMOVE cycles "
        f"({len(successful_cycles)}/{NSWEEP}); outcomes={outcomes}"
    )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=MCAST_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab REMOVE sweep (1..{NSWEEP}) leaked {leak_count} "
            f"mcast-path object(s).\n"
            f"Per-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

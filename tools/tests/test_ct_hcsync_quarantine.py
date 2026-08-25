"""A95 — a failed HC sync inside DeleteKey must quarantine a conntrack's
classifier entry, not free it and not lose it.

ExternalHashTableDeleteKey() is tri-state (fm_ehash.h): 0 means the key
was unlinked *and* a host-command sync proved no ucode walker can still
reach the entry, EN_EHASH_DELETE_UNSYNCED (-2) means the unlink happened
but the barrier failed, and -1 means the key was never provably unlinked
at all. Every cdx caller now routes the delete through
cdx_ehash_delete_entry() (cdx/cdx_ehash.c), which owns the table entry on
all three arms: free on 0, park on -2, leak deliberately on -1.

Asserted here, all from user space and with no traffic:

  * the -2 arm reached through delete_entry_from_classif_table() parks
    exactly one entry per failed delete instead of freeing it (which the
    hardware would turn into a use-after-free) or dropping it (a leak),
  * -2 does *not* set CONNTRACK_DEL_FAILED, so the flow is still allowed
    back into hardware — the key is provably out of the table, only the
    barrier is missing. The oracle is that a second armed teardown
    consumes a second fail credit: it can only do that if the re-offload
    actually reinstalled the key,
  * a later successful delete anywhere on the PCD retires the whole
    backlog, because one sync is a barrier for every entry unlinked
    before it.

The flows are synthetic: a route plus a conntrack pushed straight down
the FCI command bus, which is what CMM would do for a real forwarded
flow. That keeps the whole sequence deterministic — no traffic, no
aging, and exactly one classifier delete per step, which matters because
a single successful delete would drain the backlog being measured.

Sync failures come from the kernel-side fault knob at
/proc/fm_ehash_hcsync_fail (test image only): write N to make the next N
HC barriers issued inside ExternalHashTableDeleteKey() report failure,
read it back for the remaining armed count. The quarantine depth is
cdx-wide and is reported as `pending=` by the mcast knob at
/proc/cdx_mc_hcsync_fail. The test skips when either file is absent, so
it degrades gracefully on a production kernel build.

Known exposure: `pending` counts the whole cdx backlog, and *any*
successful DeleteKey anywhere retires all of it — including one issued
by the CT aging kthread (cdx_timer.c -> ct_aging_handler -> ct_remove).
That kthread takes ctrl.mutex, which orders it against the FCI commands
below but not against the /proc reads, so a background conntrack timing
out inside the sub-second window between a command's reply and the next
knob read can zero the backlog and fail an assertion here. Nothing in
the harness can quiesce aging, and no assertion shape survives a drain,
so the exposure is documented rather than worked around: a failure whose
message says the backlog was *empty* when it should have held entries is
worth re-running once before being believed. The inverse signature also
exists while the kernel knob is armed: an aging DeleteKey in the window
consumes the fail credit AND parks its own entry, so `armed` still reads
0 while `pending` comes back one higher than asserted — same remedy.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from _topology import TARGET_LAN_IF, TARGET_WAN_IF


# Fails the next N HC barriers issued inside ExternalHashTableDeleteKey().
DELETE_KNOB_PATH = "/proc/fm_ehash_hcsync_fail"
# Same cdx-wide quarantine, reported as `pending=` alongside the mcast
# knob's own `armed=`.
PENDING_KNOB_PATH = "/proc/cdx_mc_hcsync_fail"

# FCI opcodes (cdx/cdx_cmdhandler.h)
CMD_IP_ROUTE       = 0x0313
CMD_IPV4_CONNTRACK = 0x0314

# cdx/fe.h:37-44. The values are NOT contiguous — 2, 5 and 8 are unused
# and ACTION_REMOVED (3) sits between DEREGISTER and UPDATE — so these
# must be copied, never inferred. An action the handler doesn't know
# falls through IPv4_HandleIP_CONNTRACK's switch to ERR_UNKNOWN_ACTION.
ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1
ACTION_UPDATE     = 4

NO_ERR             = 0
ERR_UNKNOWN_ACTION = 4

# cdx/fe.h
CTCMD_FLAGS_ORIG_DISABLED = 1 << 0

IF_NAME_SIZE = 16

# Route id claim: 0x0095_xxxx, distinct from the ids the other route
# tests register (0x0053_/0x0057_/0x0069_/0x0604_).
ROUTE_ID = 0x0095_A100

# Three 5-tuples, all in TEST-NET-2 so nothing on the bench can own them.
# Distinct ports keep them in different CT hash buckets and make a stray
# leftover from a crashed run identifiable.
FLOW_BASELINE = (0xC6336401, 0xC6336465, 0x9501, 0x9601)
FLOW_PARKED   = (0xC6336402, 0xC6336466, 0x9502, 0x9602)
FLOW_DRAIN    = (0xC6336403, 0xC6336467, 0x9503, 0x9603)

PROTO_UDP = 17

# kmemleak's jiffies_min_age is 5s — a just-freed-or-not allocation isn't
# classifiable as unreferenced until it ages past that.
KMEMLEAK_AGE_GRACE_S = 7.0

# Narrower than ASK_KMEMLEAK_FILTER, which trips on unrelated boot-time
# [cdx]-annotated allocations. Everything this test can leak — the
# classifier table entry, its hw_ct wrapper, the quarantine node, the
# CT_PAIR, the route — is allocated through one of these frames.
CT_LEAK_FILTER = [
    "insert_entry_in_classif_table",
    "delete_entry_from_classif_table",
    "cdx_ehash_quarantine_entry",
    "ct_alloc",
    "IPv4_HandleIP_CONNTRACK",
    "L2_route_add",
]


# --- Wire helpers -------------------------------------------------------
#
# Self-contained on purpose, as the other FCI-driven tests are: pytest's
# flat rootdir layout makes a shared tools.tests.* import awkward, and
# keeping the packers next to the assertions is what makes a layout drift
# fail loudly here instead of silently mispacking.

def _pack_rt(action: int, route_id: int) -> bytes:
    """RtCommand (cdx/fe.h), 88 B with VLAN_FILTER:
      0   action(2) mtu(2) macAddr(6) egress_vid(2) underlying_vid(2)
      14  pad(2) outputDevice(16) inputDevice(16) UnderlyingInputDevice(16)
      64  id(4) flags(4) daddr[4](16)

    inputDevice is what gives the route an underlying_input_itf, and
    without one insert_entry_in_classif_table() refuses the offload —
    the flow would stay software-only and never call DeleteKey at all.
    """
    out_dev = TARGET_LAN_IF.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    in_dev  = TARGET_WAN_IF.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    wire = (
        struct.pack("<HH", action, 1500)
        + b"\x02\x00\x00\x0a\x95\x01"                # macAddr
        + struct.pack("<HH", 0, 0)                   # egress_vid, underlying_vid
        + struct.pack("<H", 0)                       # pad
        + out_dev + in_dev + b"\x00" * IF_NAME_SIZE  # UnderlyingInputDevice unset
        + struct.pack("<II", route_id, 0)            # id, flags
        + b"\x00" * 16                               # daddr[4]
    )
    assert len(wire) == 88, len(wire)
    return wire


def _pack_ct(action: int, flow: tuple[int, int, int, int],
             flags: int = 0) -> bytes:
    """CtCommand (cdx/fe.h), 48 B packed. The reply tuple is the plain
    mirror of the originator one, so the handler's NAT pre-computation
    stays out of the way."""
    saddr, daddr, sport, dport = flow
    wire = struct.pack(
        "<HHIIHHIIHHHHQII",
        action, 0,                       # action, format (no SA, no tunnel)
        saddr, daddr, sport, dport,
        daddr, saddr, dport, sport,      # reply tuple
        PROTO_UDP, flags,
        0,                               # qosconnmark
        ROUTE_ID, ROUTE_ID,
    )
    assert len(wire) == 48, len(wire)
    return wire


async def _send(agent, sess, fcode: int, payload: bytes, tmo: int = 3000):
    r = await agent.fci_send(sess, fcode=fcode, length=len(payload),
                             payload=payload, timeout_ms=tmo)
    return r


# --- Knob helpers -------------------------------------------------------

async def _read_knob(target_agent, session, path: str) -> dict[str, int]:
    """Parse `key=<n>` pairs out of a probe file."""
    r = await target_agent.fs_read(session, path)
    assert r.get("errno", 0) == 0, f"{path} read failed: {r!r}"
    text = bytes.fromhex(r["content_hex"]).decode("ascii", errors="replace")
    return {k: int(v) for k, v in (p.split("=", 1) for p in text.split())}


async def _armed(target_agent, session) -> int:
    return (await _read_knob(target_agent, session, DELETE_KNOB_PATH))["armed"]


async def _pending(target_agent, session) -> int:
    return (await _read_knob(target_agent, session, PENDING_KNOB_PATH))["pending"]


async def _arm(target_agent, session, n: int) -> None:
    r = await target_agent.fs_write(session, DELETE_KNOB_PATH, f"{n}\n")
    assert r.get("errno", 0) == 0 and r.get("rc", -1) > 0, (
        f"arming {DELETE_KNOB_PATH} to {n} failed: {r!r}"
    )


# --- Test ---------------------------------------------------------------

async def test_ct_delete_hcsync_failure_quarantines_classifier_entry(
    aiohttp_session, target_agent, splat_window,
):
    for path in (DELETE_KNOB_PATH, PENDING_KNOB_PATH):
        probe = await target_agent.fs_read(aiohttp_session, path)
        if probe.get("errno", 0) != 0:
            pytest.skip(
                f"HC-sync fault-injection knob absent at {path} "
                f"(errno={probe.get('errno')!r}); kernel build does not "
                f"define the fault-injection probes."
            )

    ag, sess = target_agent, aiohttp_session

    async def ct(action, flow, flags=0, tmo=3000):
        return (await _send(ag, sess, CMD_IPV4_CONNTRACK,
                            _pack_ct(action, flow, flags), tmo)).get("reply_rc")

    async def rt(action):
        return (await _send(ag, sess, CMD_IP_ROUTE,
                            _pack_rt(action, ROUTE_ID))).get("reply_rc")

    # Nuke whatever a crashed prior run left behind; replies are
    # irrelevant (ERR_CT_ENTRY_NOT_FOUND / ERR_RT_ENTRY_NOT_FOUND when
    # there is nothing there).
    await _arm(ag, sess, 0)
    for flow in (FLOW_BASELINE, FLOW_PARKED, FLOW_DRAIN):
        await ct(ACTION_DEREGISTER, flow)
    await rt(ACTION_DEREGISTER)

    rc = await rt(ACTION_REGISTER)
    assert rc == NO_ERR, f"route register failed: rc={rc}"

    try:
        # A backlog inherited from an earlier test would make every
        # absolute pending assertion below meaningless. One successful
        # delete is a barrier for the whole PCD, so a register/deregister
        # cycle with the knob disarmed is the cheapest way to establish
        # pending == 0.
        rc = await ct(ACTION_REGISTER, FLOW_BASELINE)
        assert rc == NO_ERR, (
            f"baseline CT register failed: rc={rc}. ct_add() propagates a "
            f"failed insert_entry_in_classif_table(), so this also means "
            f"the synthetic flow did not reach hardware."
        )
        rc = await ct(ACTION_DEREGISTER, FLOW_BASELINE)
        assert rc == NO_ERR, f"baseline CT deregister failed: rc={rc}"
        assert await _pending(ag, sess) == 0, (
            "a successful delete must retire the whole quarantine backlog"
        )

        await ag.kmemleak_clear(sess)

        # --- the parked flow -------------------------------------------
        #
        # REGISTER installs both directions; ct_add() fails the command if
        # either insert fails, so NO_ERR here means the classifier entries
        # exist in hardware.
        rc = await ct(ACTION_REGISTER, FLOW_PARKED)
        assert rc == NO_ERR, f"CT register failed: rc={rc}"

        # An UPDATE that disables the originator direction takes
        # ct_update_one()'s incomplete arm, which deletes exactly that
        # one direction — the replier stays complete and only has its
        # enqueue params refreshed. One delete, one fail credit, and the
        # backlog depth is unambiguous.
        await _arm(ag, sess, 1)
        rc = await ct(ACTION_UPDATE, FLOW_PARKED,
                      flags=CTCMD_FLAGS_ORIG_DISABLED)
        assert rc != ERR_UNKNOWN_ACTION, (
            f"ACTION_UPDATE={ACTION_UPDATE} was rejected as an unknown "
            f"action; the cdx/fe.h action values drifted and this file's "
            f"copy is stale"
        )
        assert rc == NO_ERR, f"CT update (disable orig) failed: rc={rc}"

        assert await _armed(ag, sess) == 0, (
            "the fail credit was never spent, so no HC barrier ran inside "
            "DeleteKey — the originator direction was not in hardware "
            "(check that the route resolved an input interface) or the "
            "delete bailed out before its sync"
        )
        assert await _pending(ag, sess) == 1, (
            "the unlinked entry must be quarantined: freeing it without a "
            "barrier is a use-after-free the hardware commits, and "
            "dropping it is a leak"
        )

        # EN_EHASH_DELETE_UNSYNCED means the key really is out of the
        # table, so re-offload stays allowed — only the -1 arm sets
        # CONNTRACK_DEL_FAILED and bars it. Re-enable, then tear the
        # direction down again with a fresh fail credit: the second
        # credit can only be spent if the re-offload reinstalled the key.
        rc = await ct(ACTION_UPDATE, FLOW_PARKED)
        assert rc == NO_ERR, f"CT update (re-enable orig) failed: rc={rc}"
        assert await _pending(ag, sess) == 1, (
            "a re-insert must not disturb the backlog — it issues no "
            "barrier that could prove the parked entry walker-free"
        )

        await _arm(ag, sess, 1)
        rc = await ct(ACTION_UPDATE, FLOW_PARKED,
                      flags=CTCMD_FLAGS_ORIG_DISABLED)
        assert rc == NO_ERR, f"CT update (re-disable orig) failed: rc={rc}"
        assert await _armed(ag, sess) == 0, (
            "no delete ran on the second teardown, so the flow was never "
            "put back into hardware: an unsynced delete must not set "
            "CONNTRACK_DEL_FAILED"
        )
        assert await _pending(ag, sess) == 2, (
            "the second unlinked entry must be quarantined alongside the "
            "first"
        )

        # --- the draining flow -----------------------------------------
        #
        # A separate flow, deleted with the knob disarmed. Its successful
        # DeleteKey syncs the one LS1046A PCD, which is a valid barrier
        # for every entry unlinked before it, so the backlog goes with it.
        rc = await ct(ACTION_REGISTER, FLOW_DRAIN)
        assert rc == NO_ERR, f"drain CT register failed: rc={rc}"
        assert await _pending(ag, sess) == 2, (
            "an unrelated insert must not disturb the backlog"
        )
        rc = await ct(ACTION_DEREGISTER, FLOW_DRAIN)
        assert rc == NO_ERR, f"drain CT deregister failed: rc={rc}"
        assert await _pending(ag, sess) == 0, (
            "a successful sync proves every earlier unlinked entry is "
            "walker-free, so the backlog must be empty"
        )
    finally:
        await _arm(ag, sess, 0)
        for flow in (FLOW_BASELINE, FLOW_PARKED, FLOW_DRAIN):
            await ct(ACTION_DEREGISTER, flow)
        await rt(ACTION_DEREGISTER)

    # Both parked entries were released by the drain, everything else by
    # its own teardown. Anything still unreferenced is a real leak.
    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)
    report = await ag.kmemleak(sess, filter_substrs=CT_LEAK_FILTER)
    leak_count = report.get("leak_count", 0)
    assert not leak_count, (
        f"CT HC-sync failure/recovery cycle leaked {leak_count} "
        f"classifier-path object(s)\n\n" + report.get("report", "")[:4000]
    )

"""A80 — a failed HC sync during per-listener REMOVE must quarantine, not leak.

The per-listener REMOVE path in cdx/dpa_control_mc.c splices a member's
en_exthash_tbl_entry out of the live FMAN replication chain *before* it
issues the ExternalHashTableFmPcdHcSync barrier that proves no ucode
walker is still inside that chain. When the barrier fails the entry can
be neither freed (no proof the hardware is done with it) nor unlinked a
second time (the surgery already advanced the pointers it would need),
so it goes onto a pending-free quarantine and is reclaimed the next time
any sync on the same PCD succeeds.

Three properties are asserted here, all from user space:

  * a failed sync leaves exactly one entry quarantined and reports the
    REMOVE as failed (the abort-the-batch contract — a sync failure is a
    property of the HC channel, not of the listener, so the rest of the
    batch would fail identically),
  * the next successful REMOVE drains the backlog to zero,
  * re-REMOVEing the listener whose sync failed is rejected cleanly
    rather than re-entering the first-listener surgery on already-
    advanced pointers. That path used to NULL-deref, oops the FCI
    handler and orphan ctrl.mutex, wedging every later FCI command; the
    splat_window fixture is the oracle for its absence.

Sync failures are forced through the CDX_DEBUG_MC_HCSYNC_FAIL knob at
/proc/cdx_mc_hcsync_fail (test image only): write N to make the next N
barriers issued by dpa_control_mc.c report failure, read it back for the
remaining armed count and the current quarantine depth. The test skips
when the knob is absent, so it degrades gracefully on a production
kernel build.
"""

from __future__ import annotations

import asyncio
import os
import struct

import pytest
import pytest_asyncio

from _topology import TARGET_LAN_IF, TARGET_WAN_IF


KNOB_PATH = "/proc/cdx_mc_hcsync_fail"

# FCI opcode (cdx/cdx_cmdhandler.h)
CMD_MC4_MULTICAST = 0x0701

# Actions (cdx/dpa_control_mc.h + cdx/fe.h)
CDX_MC_ACTION_ADD    = 0
CDX_MC_ACTION_REMOVE = 1

# Return codes (cdx/fe.h). MC4_Command_Handler maps every -1 from the
# mcast mutators onto ERR_MC_CONFIG, so both "sync failed" and "that
# listener isn't a member" surface as 707.
NO_ERR        = 0
ERR_MC_CONFIG = 707

IF_NAME_SIZE         = 16
MC4_MIN_COMMAND_SIZE = 44

# VLAN claim: 261..264, registered in _topology.py's ID table.
BASE_VID  = int(os.environ.get("ASK_MCAST_HCSYNC_BASE_VID", "261"))
N_LISTENERS = 4
LISTENER_IFACES = [f"{TARGET_LAN_IF}.{BASE_VID + i}" for i in range(N_LISTENERS)]

MCAST_DST     = os.environ.get("ASK_MCAST_HCSYNC_DST", "239.1.1.11")
MCAST_SRC     = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
INGRESS_IFACE = os.environ.get("ASK_MCAST_INGRESS", TARGET_WAN_IF)

# kmemleak's jiffies_min_age is 5s — a just-freed-or-not allocation isn't
# classifiable as unreferenced until it ages past that.
KMEMLEAK_AGE_GRACE_S = 7.0

# Narrower than ASK_KMEMLEAK_FILTER, which trips on unrelated boot-time
# [cdx]-annotated allocations. Anything this test leaks passes through
# one of these frames: the listener entry's allocator, the quarantine
# node's allocator, or the REMOVE path itself.
MCAST_LEAK_FILTER = [
    "cdx_create_mcast_group",
    "cdx_delete_mcast_group_member",
    "cdx_add_mcast_table_entry",
    "cdx_free_exthash_mcast_members",
    "create_exthash_entry4mcast_member",
    "mc_quarantine_entry",
]


# --- Wire helpers -------------------------------------------------------
#
# Self-contained on purpose, exactly as test_mcast_failslab.py is: keeping
# the mcast test files independent avoids the tools.tests.* import
# gymnastics pytest's flat rootdir layout forces.

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
                      dst: str = MCAST_DST, src: str = MCAST_SRC,
                      ingress: str = INGRESS_IFACE) -> bytes:
    n = len(listeners)
    header = (
        struct.pack("<HBB", action, 0, 0)   # action, src_addr_mask, bitfield
        + _ip_be_bytes(src)
        + _ip_be_bytes(dst)
        + struct.pack("<I", n)              # num_output
    )
    ingress_field = ingress.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    outputs = b"".join(_pack_mc4_output(i) for i in listeners)
    wire = header + ingress_field + outputs
    if len(wire) < MC4_MIN_COMMAND_SIZE:
        wire += b"\x00" * (MC4_MIN_COMMAND_SIZE - len(wire))
    return wire


async def _mc4(target_agent, session, action: int, listeners: list[str],
               timeout_ms: int = 3000) -> dict:
    payload = _pack_mc4_command(action, listeners)
    return await target_agent.fci_send(
        session, fcode=CMD_MC4_MULTICAST,
        length=len(payload), payload=payload, timeout_ms=timeout_ms,
    )


# --- Knob helpers -------------------------------------------------------

async def _read_knob(target_agent, session) -> dict[str, int]:
    """Parse `armed=<n> pending=<n>` out of the probe file."""
    r = await target_agent.fs_read(session, KNOB_PATH)
    assert r.get("errno", 0) == 0, f"knob read failed: {r!r}"
    text = bytes.fromhex(r["content_hex"]).decode("ascii", errors="replace")
    return {k: int(v) for k, v in (p.split("=", 1) for p in text.split())}


async def _arm(target_agent, session, n: int) -> None:
    r = await target_agent.fs_write(session, KNOB_PATH, f"{n}\n")
    assert r.get("errno", 0) == 0 and r.get("rc", -1) > 0, (
        f"arming knob to {n} failed: {r!r}"
    )


# --- Fixtures -----------------------------------------------------------

@pytest_asyncio.fixture
async def four_vlan_listeners(aiohttp_session, target_agent):
    """Four VLAN subifs on the DUT's LAN-facing port. CMM registers each
    NEWLINK into the FMAN onif table, which is what makes mcast ADD's
    get_onif_by_name(listener) resolve. Four is the smallest count that
    lets the test spend one listener on establishing a zero-pending
    baseline, one on the forced failure, one on the recovery, and still
    leave a single member for the count-match full-group delete."""
    async def _del_all():
        for name in LISTENER_IFACES:
            await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", name])

    await _del_all()   # nuke stale state from a crashed prior run
    try:
        for i, name in enumerate(LISTENER_IFACES):
            r = await target_agent.exec_cmd(aiohttp_session, [
                "ip", "link", "add", "link", TARGET_LAN_IF,
                "name", name, "type", "vlan", "id", str(BASE_VID + i),
            ])
            assert r["rc"] == 0, f"vlan add {name} failed: {r}"
            r = await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "set", name, "up"],
            )
            assert r["rc"] == 0, f"vlan up {name} failed: {r}"
        await asyncio.sleep(1.0)   # let CMM pick up the NEWLINKs
        yield LISTENER_IFACES
    finally:
        await _del_all()


# --- Test ---------------------------------------------------------------

async def test_mcast_hcsync_failure_quarantines_listener_entry(
    aiohttp_session, target_agent, splat_window, four_vlan_listeners,
):
    probe = await target_agent.fs_read(aiohttp_session, KNOB_PATH)
    if probe.get("errno", 0) != 0:
        pytest.skip(
            f"HC-sync fault-injection knob absent at {KNOB_PATH} "
            f"(errno={probe.get('errno')!r}); kernel build does not "
            f"define CDX_DEBUG_MC_HCSYNC_FAIL."
        )

    listeners = four_vlan_listeners

    # Start disarmed whatever a previous run left behind.
    await _arm(target_agent, aiohttp_session, 0)

    # Best-effort teardown of a group left over by a crashed prior run;
    # the reply is irrelevant (ERR_MC_CONFIG when there's nothing there).
    await _mc4(target_agent, aiohttp_session, CDX_MC_ACTION_REMOVE, listeners)

    await target_agent.kmemleak_clear(aiohttp_session)

    r = await _mc4(target_agent, aiohttp_session, CDX_MC_ACTION_ADD, listeners)
    assert r.get("reply_rc") == NO_ERR, f"seed ADD failed: {r!r}"

    # Baseline. A backlog carried in from an earlier test would let the
    # armed REMOVE below spend its fail credit on the recovery drain
    # instead of on the surgery's own barrier, so establish pending=0
    # with a REMOVE that is allowed to succeed. Group: 4 -> 3 members.
    r = await _mc4(target_agent, aiohttp_session,
                   CDX_MC_ACTION_REMOVE, [listeners[0]])
    assert r.get("reply_rc") == NO_ERR, f"baseline REMOVE failed: {r!r}"
    knob = await _read_knob(target_agent, aiohttp_session)
    assert knob == {"armed": 0, "pending": 0}, (
        f"expected a disarmed knob and an empty quarantine before the "
        f"injection; got {knob!r}"
    )

    # Force the barrier after the splice to fail. Group: 3 -> 2 members,
    # and listeners[1]'s table entry lands in the quarantine.
    await _arm(target_agent, aiohttp_session, 1)
    r = await _mc4(target_agent, aiohttp_session,
                   CDX_MC_ACTION_REMOVE, [listeners[1]])
    assert r.get("reply_rc") == ERR_MC_CONFIG, (
        f"REMOVE with a forced HC-sync failure must report failure so the "
        f"caller knows the batch was abandoned; got {r!r}"
    )
    knob = await _read_knob(target_agent, aiohttp_session)
    assert knob == {"armed": 0, "pending": 1}, (
        f"the unlinked entry must be quarantined (freeing it without a "
        f"barrier is a use-after-free; dropping it is a leak); got {knob!r}"
    )

    # Explicit disarm — the single credit is already spent, but leaving
    # the knob's state implicit would make a later edit to the arm count
    # silently change what the next step tests.
    await _arm(target_agent, aiohttp_session, 0)

    # The next mutator retries the barrier for the backlog before doing
    # its own work. Group: 2 -> 1 member.
    r = await _mc4(target_agent, aiohttp_session,
                   CDX_MC_ACTION_REMOVE, [listeners[2]])
    assert r.get("reply_rc") == NO_ERR, f"recovery REMOVE failed: {r!r}"
    knob = await _read_knob(target_agent, aiohttp_session)
    assert knob == {"armed": 0, "pending": 0}, (
        f"a successful sync proves every earlier unlinked entry is "
        f"walker-free, so the backlog must be empty; got {knob!r}"
    )

    # Re-REMOVE of the listener whose sync failed. Its member slot was
    # cleared during the failed attempt, so this must be rejected as a
    # non-member — not replayed through the splice a second time. An
    # oops here orphans ctrl.mutex and wedges every later FCI command;
    # splat_window is what catches it.
    r = await _mc4(target_agent, aiohttp_session,
                   CDX_MC_ACTION_REMOVE, [listeners[1]])
    assert r.get("reply_rc") == ERR_MC_CONFIG, (
        f"re-REMOVE of an already-unlinked listener must be rejected as "
        f"a non-member; got {r!r}"
    )
    knob = await _read_knob(target_agent, aiohttp_session)
    assert knob["pending"] == 0, f"re-REMOVE disturbed the quarantine: {knob!r}"

    # One member left, so the request count matches and this takes the
    # full-group delete path. It must still succeed after the group has
    # been through a failed barrier.
    r = await _mc4(target_agent, aiohttp_session,
                   CDX_MC_ACTION_REMOVE, [listeners[3]])
    assert r.get("reply_rc") == NO_ERR, f"full-group DELETE failed: {r!r}"
    knob = await _read_knob(target_agent, aiohttp_session)
    assert knob == {"armed": 0, "pending": 0}, (
        f"quarantine must be empty after teardown; got {knob!r}"
    )

    # Everything the sequence allocated has been released by now: the
    # quarantined entry through the recovery drain, the rest through the
    # group destroy. Anything still unreferenced is a real leak.
    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)
    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=MCAST_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    assert not leak_count, (
        f"HC-sync failure/recovery cycle leaked {leak_count} mcast-path "
        f"object(s)\n\n" + report.get("report", "")[:4000]
    )

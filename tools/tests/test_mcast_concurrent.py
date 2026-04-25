"""Concurrency stress test for mc_mutators_mutex (ISSUES.md M10/M11).

The mutex serialises ADD/REMOVE/UPDATE of any mcast group at the
MC{4,6}_Command_Handler dispatcher level. Without it, two parallel
mutators on the same group would race in the lookup-then-mutate
windows inside cdx_create_mcast_group / cdx_update_mcast_group /
cdx_delete_mcast_group_member — `Cdx_GetMcastMemberFreeIndex` drops
the per-bucket spinlock between lookup and the caller's mutation, so
two ADDs concurrently grabbing the "free slot k" would both believe
they own it and the last writer would silently overwrite the first.

This test forces that exact pattern: N parallel asyncio tasks each
register a unique listener into the *same* mcast group, then remove
it, looping K times. Without the mutex, races would surface as:

  * REMOVE failures (listener not found because a concurrent ADD
    overwrote its slot)
  * Listener count drift (uiListenerCnt incremented twice for the
    same slot)
  * KASAN/lockdep splats during list_for_each races (caught by
    splat_window)
  * Mcast-path kmemleak objects from listeners whose tbl_entry was
    leaked when their slot was clobbered

With the mutex, all N*K operations serialise cleanly.
"""

from __future__ import annotations

import asyncio
import os
import struct

import pytest_asyncio


CMD_MC4_MULTICAST    = 0x0701
CDX_MC_ACTION_ADD    = 0
CDX_MC_ACTION_REMOVE = 1
NO_ERR               = 0
IF_NAME_SIZE         = 16
MC4_MIN_COMMAND_SIZE = 44

TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth4")
VID_BASE      = int(os.environ.get("ASK_MCAST_CONCURRENT_VID", "241"))
INGRESS_IFACE = os.environ.get("ASK_MCAST_INGRESS", "eth3")

# Per-task knobs. 4 parallel tasks × 20 iterations = 80 mutator
# operations, all serialised through mc_mutators_mutex.
N_TASKS         = 4
ITERS_PER_TASK  = 20

# Single shared mcast group identity. All tasks ADD/REMOVE listeners
# on this group, so they all hit MC4_Command_Handler concurrently and
# the mutex is what keeps members[] consistent.
SHARED_DST = "239.7.1.1"
SHARED_SRC = "10.0.0.141"

# Function-name needles in kmemleak backtraces that are unique to the
# mcast mutation paths (no DPAA softirq baseline overlap).
MCAST_LEAK_FILTER = [
    "cdx_create_mcast_group",
    "cdx_update_mcast_group",
    "cdx_delete_mcast_group_member",
    "cdx_add_mcast_table_entry",
    "cdx_free_exthash_mcast_members",
    "create_exthash_entry4mcast_member",
]


def _ip_be_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _pack_mc4_output(iface: str) -> bytes:
    name = iface.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    return (
        b"\x00\x00\x00\x00"   # timer
        + name                # output_device_str[16]
        + b"\x00"             # shaper_mask
        + b"\x00"             # bitfield
        + b"\x00" * 6         # uc_mac
        + b"\x00"             # queue
        + b"\x00" * 16        # new_output_device_str
        + b"\x00"             # bitfield
        + b"\x00\x00"         # padding[2]
    )


def _pack_mc4_command(action: int, listeners: list[str],
                     dst: str = SHARED_DST, src: str = SHARED_SRC,
                     ingress: str = INGRESS_IFACE) -> bytes:
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


# --- fixtures ---------------------------------------------------------

@pytest_asyncio.fixture
async def n_vlan_listeners(aiohttp_session, target_agent):
    """N_TASKS VLAN subifs, each carrying a unique VLAN ID. CMM picks
    them up via netlink so each listener resolves through
    get_onif_by_name during mcast ADD."""
    names = [f"{TARGET_LAN_IF}.{VID_BASE + i}" for i in range(N_TASKS)]

    for n in names:
        await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", n])
    try:
        for i, n in enumerate(names):
            r = await target_agent.exec_cmd(aiohttp_session, [
                "ip", "link", "add", "link", TARGET_LAN_IF,
                "name", n, "type", "vlan", "id", str(VID_BASE + i),
            ])
            assert r["rc"] == 0, f"vlan add {n} failed: {r}"
            r = await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "set", n, "up"],
            )
            assert r["rc"] == 0, f"vlan up {n} failed: {r}"
        await asyncio.sleep(1.0)
        yield names
    finally:
        for n in names:
            await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "del", n],
            )


# --- test --------------------------------------------------------------

async def test_mcast_concurrent_mutator_stress(
    aiohttp_session, target_agent, splat_window, n_vlan_listeners,
):
    """N_TASKS parallel asyncio tasks each cycle ADD+REMOVE of their
    own listener on the shared mcast group, looping ITERS_PER_TASK times.
    Implicit oracles:

      * splat_window — any KASAN/lockdep/WARN/BUG produced by a race
        in members[] mutation or the per-bucket list traversal fails
        the test immediately.
      * Per-task accounting — every ADD must succeed; every REMOVE
        must succeed (since each listener name is unique to its task,
        the only way REMOVE finds nothing is if the slot was
        clobbered by another task's racing ADD).
      * Final kmemleak (mcast filter) — any tbl_entry whose slot got
        overwritten without being freed surfaces here.
    """
    listeners = n_vlan_listeners

    await target_agent.kmemleak_clear(aiohttp_session)

    # Each task tracks its own counts so the assertion message can
    # pinpoint which task saw a problem.
    task_results: dict[int, dict[str, int]] = {
        i: {"add_fail": 0, "rem_fail": 0, "add_ok": 0, "rem_ok": 0}
        for i in range(N_TASKS)
    }

    async def run_task(task_id: int, listener: str) -> None:
        add  = _pack_mc4_command(CDX_MC_ACTION_ADD,    [listener])
        rem  = _pack_mc4_command(CDX_MC_ACTION_REMOVE, [listener])
        bucket = task_results[task_id]
        for _ in range(ITERS_PER_TASK):
            r = await target_agent.fci_send(
                aiohttp_session, fcode=CMD_MC4_MULTICAST,
                length=len(add), payload=add, timeout_ms=5000,
            )
            if r.get("reply_rc") == NO_ERR:
                bucket["add_ok"] += 1
            else:
                bucket["add_fail"] += 1
            r = await target_agent.fci_send(
                aiohttp_session, fcode=CMD_MC4_MULTICAST,
                length=len(rem), payload=rem, timeout_ms=5000,
            )
            if r.get("reply_rc") == NO_ERR:
                bucket["rem_ok"] += 1
            else:
                bucket["rem_fail"] += 1

    await asyncio.gather(*[
        run_task(i, listeners[i]) for i in range(N_TASKS)
    ])

    # Every ADD must have succeeded. A failure here either means the
    # mutex isn't actually serialising (listener slot conflict) or
    # the group hit MC_MAX_LISTENERS_PER_GROUP because cleanup
    # REMOVEs from peer tasks didn't run between this task's ADDs.
    # With sequential serialisation each task's ADD runs against a
    # group that has at most N_TASKS-1 other listeners, well under 8.
    add_failures = [(i, b["add_fail"]) for i, b in task_results.items() if b["add_fail"]]
    rem_failures = [(i, b["rem_fail"]) for i, b in task_results.items() if b["rem_fail"]]
    assert not add_failures, (
        f"task ADDs failed (mutex not serialising? slot collisions?): "
        f"{add_failures}; full results={task_results}"
    )
    assert not rem_failures, (
        f"task REMOVEs failed (own-listener slot was clobbered by a "
        f"racing peer): {rem_failures}; full results={task_results}"
    )

    # Final cleanup: best-effort REMOVE per listener in case the
    # group still holds anything (each task's ADD/REMOVE pair should
    # be balanced, but the assertions above cover that case
    # explicitly so this is just hygiene).
    for listener in listeners:
        rem = _pack_mc4_command(CDX_MC_ACTION_REMOVE, [listener])
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_MC4_MULTICAST,
            length=len(rem), payload=rem, timeout_ms=2000,
        )

    # kmemleak grace + scan
    await asyncio.sleep(7.0)
    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=MCAST_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    assert leak_count == 0, (
        f"concurrent mutator stress leaked {leak_count} mcast-path "
        f"object(s); per-task results={task_results}\n\n"
        + report.get("report", "")[:4000]
    )

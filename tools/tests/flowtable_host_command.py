"""The FMan host-command channel through a busy or stalled CPU portal (A401).

Every barrier a hardware delete owes is a host-command sync, whose
confirmation QMan delivers on the first CPU's portal. Two loads on that portal,
from CDX's test knobs, each with a barrier of its own issued from another CPU
once the load is in place, while the case's flowtable is unbound and its flow
retired under it:

- a backlog: a queue on the portal's channel that never empties, at the work
  queue CDX gives the exception queue it pins to that CPU, or at WQ0, the top
  of the channel. QMan serves a channel's WQ0 and WQ1 strictly ahead of the
  rest, so a confirmation queued below the backlog waits for as long as the
  backlog lasts. The confirmation must arrive through it: every barrier
  completes, in time, and nothing times out.
- a stall: the CPU itself held with bottom halves off past the sync's
  deadline, so a confirmation can only come late. The knob's sync times out,
  and the channel must open again when it is confirmed: the retirement
  completes by itself, and the next flow goes to hardware. No reboot.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from _flowtable_rig import command, hardware_proof, read

BACKLOG = "/sys/module/cdx/parameters/portal_backlog"
STALL = "/sys/module/cdx/parameters/portal_stall"
# Longer than the host command's one-second deadline several times over.
BACKLOG_MS = 3000
# Past the deadline, but short of anything that watches for stalled CPUs.
STALL_MS = 1500
DEADLINE_MS = 1000
TIMED_OUT = "HC confirmation timed out"
LATE = "after its timeout"
RESUMED = "after its timeout; commands resume"


async def kernel_log(r):
    return (await command(r.target, r.session, "dmesg"))["stdout"]


def count(log, text):
    return sum(text in line for line in log.splitlines())


async def knob(r, path):
    """A knob's read-back as a dict of its `key value` pairs."""
    words = (await read(r.target, r.session, path)).split()
    return dict(zip(words[::2], words[1::2]))


async def knob_done(r, path, timeout):
    """The knob's load over and its barrier returned."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = await knob(r, path)
        if state["active"] == "0" and state["barrier_done"] == "1":
            return state
        await asyncio.sleep(0.1)
    pytest.fail(f"{path} still busy after {timeout} s: {state}")


async def settled(r, timeout=15):
    """Unbound with nothing left unproven: no entry, nothing parked for a
    barrier, no latch."""
    return await r.wait(lambda s: not s["bindings"] and not s["entries"] and not s["quarantine"]
                        and not s["owed"] and not s["fatal"], timeout=timeout)


async def offloads_again(r):
    await r.table()
    await r.admit()
    await hardware_proof(r)


@pytest.mark.parametrize("wq", [None, 0], ids=["exception-queue", "wq0"])
async def test_host_command_answers_through_a_portal_backlog(rig, wq):
    r = rig
    await r.table()
    await r.admit()
    before = await r.state()
    log = await kernel_log(r)
    value = f"{BACKLOG_MS}" if wq is None else f"{BACKLOG_MS} {wq}"
    result = await r.target.fs_write(r.session, BACKLOG, value)
    assert result["errno"] == 0, result
    # The flow retired under the backlog: its unbind's barriers meet it too.
    await r.delete_table()
    backlog = await knob_done(r, BACKLOG, BACKLOG_MS / 1000 + 15)
    state = await settled(r)
    after = await kernel_log(r)
    r.record("backlog", {"wq": wq, "knob": backlog, "state": state})
    # The backlog held the portal and lost nothing, and the knob's barrier
    # was issued and answered while it did, well inside the deadline.
    assert int(backlog["dequeues"]) > 100000 and backlog["lost"] == "0", backlog
    if wq is not None:
        assert backlog["wq"] == str(wq), backlog
    assert backlog["barrier_overlapped"] == "1", backlog
    assert backlog["barrier_rc"] == "0" and int(backlog["barrier_ms"]) < DEADLINE_MS / 2, backlog
    # No barrier anywhere timed out or failed.
    assert count(after, TIMED_OUT) == count(log, TIMED_OUT), backlog
    assert count(after, LATE) == count(log, LATE), backlog
    assert state["errors"] == before["errors"], (before, state)
    await offloads_again(r)


async def test_late_sync_reopens_the_host_command_channel(rig):
    r = rig
    await r.table()
    await r.admit()
    log = await kernel_log(r)
    result = await r.target.fs_write(r.session, STALL, str(STALL_MS))
    assert result["errno"] == 0, result
    await r.delete_table()
    stall = await knob_done(r, STALL, STALL_MS / 1000 + 15)
    r.record("stall", {"knob": stall})
    # The knob's sync met the stall and timed out: the case this test is for.
    assert stall["barrier_overlapped"] == "1" and stall["barrier_rc"] != "0", stall
    assert int(stall["barrier_ms"]) >= DEADLINE_MS, stall
    # Its answer came once the stall ended, and with nothing else left
    # unanswered the channel opened again.
    after = await kernel_log(r)
    assert count(after, TIMED_OUT) > count(log, TIMED_OUT), stall
    assert count(after, RESUMED) > count(log, RESUMED), stall
    # The timeout said where its frame was: never on the port's queue, the
    # port having taken it, and the answer counted where it waited.
    timeout = [line for line in after.splitlines() if TIMED_OUT in line][-1]
    r.record("stall-timeout", {"line": timeout})
    assert "frames queued: command 0," in timeout and "its portal holds" in timeout, timeout
    # So the barriers the retirement still owes complete by themselves, and
    # the next flow goes to hardware.
    state = await settled(r)
    r.record("stall-settled", {"state": state})
    await offloads_again(r)

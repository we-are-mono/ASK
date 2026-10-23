"""A classifier delete CDX cannot prove takes the classifier out of the
datapath, which forwards in software meanwhile, and CDX restarts it.

A delete that fails before its unlink leaves a key the FMan may still walk to.
CDX latches the failure and stops every classifier port only for as long as it
takes to see them idle, then sends them past the classifier -- each keeps its
PCD -- so the ports run again and every frame goes to Linux. With nothing
walking the tables CDX settles the key, deleting it again or finding it in no
bucket, and gives the classifier back, all in the same boot. Whatever it waits
for -- a barrier, a key, the restart budget -- it waits for in software, never
for a reboot. The unicast, multicast and IPsec cases each fail one delete of
their own kind (the test image's knobs) and hand the bypassed window to these
helpers, which prove it and then the restart.

The test image's flowtable_restart_hold keeps the classifier bypassed, with
every key recorded, until it is cleared: that is the window a case inspects.
Inside it everything still goes over the DUT's UART, as it did when the window
stopped the ports; the agent is used again once the classifier is back.

CDX allows three restarts in ten minutes; past that a latch waits in software
for the window to allow another. The cases between them restart more often
than that, and a rerun in the same boot more again, so each runs inside
restart_budget(), which raises the limit for the case and puts it back after.
"""
from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
import json
import re
import shlex
import time
import pytest
from _flowtable_rig import (CONSOLE_NOISE, RX_PORTS_CODE, RX_PORTS_SCRIPT, console_command, console_json, console_python, proc_paths, status_text)

HOLD = "/sys/module/cdx/parameters/flowtable_restart_hold"
LIMIT = "/sys/module/cdx/parameters/flowtable_restart_limit"
REASON = "/sys/module/cdx/parameters/flowtable_degraded_reason"
UNICAST_FAULT = "/sys/module/cdx/parameters/flowtable_fail_unlink"
ROOT_FAULT = "/sys/module/cdx/parameters/ehash_fail_unlink"
RESTARTED = "datapath restarted after unproven deletion"
BYPASSED = "classifier bypassed after unproven deletion"
# What no episode may ever say any more.
TERMINAL = "reboot required"
UNSTARTED = "did not start again"
KASAN = "BUG: KASAN"
# How long a restart with nothing holding it may take, from the failed delete
# to the receive ports classifying again, and how long of that they may forward
# nothing at all: the stop, until they are seen idle and bypassed.
RESTART_BOUND = 2.0
STOP_BOUND = 0.5
RUNNING = {"6": 1, "7": 1}
STOPPED = {"6": 0, "7": 0}
# The budget a case restarts under: more than any case or rerun spends in one
# window. Never 0, which keeps every latch in software until it is raised.
CASE_RESTART_LIMIT = 1000

# The two 10G receive ports' next engine after the BMI, which is the PCD's
# while they classify and the queue manager's while they bypass it.
RX_ENGINES_SCRIPT = RX_PORTS_CODE + '''
import json
def rx_ports_next_engine(paths, ports=('6', '7')):
    states = {}
    for port in ports:
        match = re.search(r'0x([0-9a-fA-F]{8})\\s+fmbm_rfne$', open(paths[port]).read(), re.M)
        states[port] = int(match[1], 16) & 0x00ffffff
    return states
print(json.dumps(rx_ports_next_engine(rx_port_dumps())))
'''


async def require_knobs(agent, session, *paths):
    """The fault-injection image's knobs, read over the agent while it still
    reaches the DUT. A production image has none, and these cases are then
    misconfigured rather than skipped."""
    for path in (HOLD, *paths):
        present = await agent.fs_read(session, path)
        if present["errno"]:
            pytest.fail(f"{path} is missing: this is not the fault-injection test image")


async def proc(console) -> dict:
    """The adapter's status and stats over the UART, less any line another
    writer -- the managed service, the kernel -- dropped into them."""
    text = (await console_command(console, "cat", *proc_paths("status", "stats")))["stdout"]
    return status_text(CONSOLE_NOISE.sub("", text).strip())


async def ports(console) -> dict:
    return console_json((await console_python(console, RX_PORTS_SCRIPT))["stdout"])


async def engines(console) -> dict:
    """Where each 10G receive port hands a frame after the BMI."""
    return console_json((await console_python(console, RX_ENGINES_SCRIPT))["stdout"])


async def write(console, path, value):
    await console_command(console, "sh", "-c", f"echo {shlex.quote(str(value))} > {shlex.quote(path)}")


async def knob(console, path) -> str:
    return (await console_command(console, "cat", path))["stdout"].strip()


async def dmesg_count(console, text) -> int:
    """How many kernel log lines carry `text`, counted on the DUT: the whole
    log of a KASAN image is slow at 115200 baud."""
    out = (await console_command(console, "sh", "-c",
                                 f"dmesg | grep -c -F -- {shlex.quote(text)} || true"))["stdout"]
    counts = [line for line in out.splitlines() if re.fullmatch(r"\d+", line.strip())]
    assert counts, out
    return int(counts[-1])


async def log_marks(console) -> dict:
    """What the kernel log says so far, to compare a case's own lines with."""
    return {text: await dmesg_count(console, text)
            for text in (RESTARTED, BYPASSED, TERMINAL, UNSTARTED, KASAN)}


async def assert_healthy(console) -> dict:
    """The platform's own probe passes: a datapath forwarding in software is
    a healthy one, however long its restart waits."""
    health = await console_command(console, "ask-flowtable", "health", check=False)
    assert health["rc"] == 0, health
    return health


async def wait_bypassed(console, before: dict, classifying: dict, timeout: float = 15) -> tuple[dict, dict]:
    """The latch holds and the classifier is bypassed: the receive ports run
    -- enabled, never left stopped -- with their frames going to the queue
    manager rather than to the PCD they had while classifying (`classifying`,
    their next engine then), and no restart yet."""
    deadline = time.monotonic() + timeout
    while True:
        state = await proc(console)
        rx = await ports(console)
        if state["fatal"] == 1 and state["bypassed"] == 1 and rx == RUNNING:
            break
        assert time.monotonic() < deadline, (state, rx)
        await asyncio.sleep(0.2)
    now = await engines(console)
    assert all(now[port] != classifying[port] for port in classifying), (classifying, now)
    assert state["restarts"] == before["restarts"], (before, state)
    return state, rx


async def latch_cleared(console, timeout: float = 10) -> bool:
    """Whether CDX has no restart pending, waiting up to `timeout` for one to
    finish: the latch clear in the adapter's status. A case that failed with
    the adapter unloaded gets it loaded again, which the latch refuses until
    it clears."""
    deadline = time.monotonic() + timeout
    while True:
        present = await console_command(console, "test", "-e", *proc_paths("status"), check=False)
        if present["rc"]:
            await console_command(console, "modprobe", "ask_flowtable", check=False, timeout=30)
        else:
            state = await proc(console)
            if not state["fatal"]:
                return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(0.25)


@asynccontextmanager
async def quiet_console(console):
    """Keep the kernel's warnings off the console for a case: the bypass and
    the restart are reported from a worker, and a line landing inside a
    console read corrupts it. dmesg keeps every line for the assertions; the
    levels are put back after."""
    printk = (await console_command(console, "cat", "/proc/sys/kernel/printk"))["stdout"].split()
    await console_command(console, "sysctl", "-w", "kernel.printk=1 4 1 7")
    try:
        yield
    finally:
        await console_command(console, "sysctl", "-w", "kernel.printk=" + " ".join(printk[:4]))


@asynccontextmanager
async def restart_budget(console, owner=None, faults: tuple[str, ...] = ()):
    """Restart under a budget no case spends, and put the boot's own back
    after, whatever happened.

    On the way out the hold and every fault knob named are cleared first --
    a case that failed inside its window must not leave the classifier
    bypassed or a delete armed to fail. The boot's limit comes back only once
    the latch has cleared: CDX checks the limit before it gives the classifier
    back, and a restart still pending would find a budget the suite has long
    spent and wait in software for the window. One that has not cleared
    leaves the limit raised and says so. Everything goes over the console. The
    limit to put back is left on `owner` until it is, for a fixture that
    restores what this could not."""
    saved = await knob(console, LIMIT)
    assert re.fullmatch(r"\d+", saved), saved
    if owner is not None:
        owner.restart_limit = saved
    await write(console, LIMIT, CASE_RESTART_LIMIT)
    failed = False
    try:
        yield saved
    except BaseException:
        failed = True
        raise
    finally:
        for path in (HOLD, *faults):
            await write(console, path, 0)
        # A case may have lowered the limit to make a latch wait; the case's
        # own budget comes back first, so that it ends.
        await write(console, LIMIT, CASE_RESTART_LIMIT)
        if await latch_cleared(console):
            await write(console, LIMIT, saved)
            if owner is not None:
                owner.restart_limit = None
        elif not failed:
            pytest.fail("the datapath has not restarted; CDX's restart limit is left raised")


async def assert_ports_reopen(console, devs):
    """A port taken down and up while the classifier is bypassed opens as
    usual -- it forwards in software like the rest -- and runs: no open is
    refused once the ports have gone past the classifier. The routes and
    neighbours taking it down discards are the case's to put back."""
    reopened = []
    for dev in devs:
        await console_command(console, "ip", "link", "set", "dev", dev, "down")
        start = await console_command(console, "ip", "link", "set", "dev", dev, "up", check=False)
        assert start["rc"] == 0, start
        link = json.loads((await console_command(console, "ip", "-j", "link", "show", "dev", dev))["stdout"])[0]
        assert "UP" in link["flags"], link
        reopened.append({"dev": dev, "start": start})
    deadline = time.monotonic() + 5
    while (rx := await ports(console)) != RUNNING:
        assert time.monotonic() < deadline, rx
        await asyncio.sleep(0.2)
    return reopened


async def wait_restarted(console, before: dict, *, adapter: bool = True, timeout: float = 10) -> dict:
    """Clear the hold and wait for CDX to restart: the latch gone, one more
    restart counted, the classifier no longer bypassed, and every port it
    stopped started again. Without the adapter there is no /proc to ask, so
    the adapter's own load is the probe: refused while the latch holds."""
    await write(console, HOLD, 0)
    deadline = time.monotonic() + timeout
    while True:
        if not adapter:
            loaded = await console_command(console, "modprobe", "ask_flowtable", check=False, timeout=30)
            if loaded["rc"] == 0:
                adapter = True
                continue
            assert "Operation not supported" in loaded["stdout"], loaded
        else:
            state = await proc(console)
            if not state["fatal"]:
                break
        assert time.monotonic() < deadline, "the datapath did not restart"
        await asyncio.sleep(0.2)
    assert state["restarts"] == before["restarts"] + 1 and not state["bypassed"], (before, state)
    assert state["resume_failures"] == before["resume_failures"], (before, state)
    return state


async def wait_running(console, classifying: dict | None = None, timeout: float = 5) -> dict:
    """The receive ports running -- and, given what their next engine was
    while they classified, classifying again."""
    deadline = time.monotonic() + timeout
    while True:
        rx = await ports(console)
        if rx == RUNNING and (classifying is None or await engines(console) == classifying):
            return rx
        assert time.monotonic() < deadline, rx
        await asyncio.sleep(0.2)


async def assert_restarted_cleanly(console, marks: dict, restarts: int = 1) -> str:
    """One bypass line and one restart line per restart, nothing that says
    reboot, no port left unstarted, no KASAN report, and the restart line
    itself for what it settled."""
    now = await log_marks(console)
    assert now[RESTARTED] == marks[RESTARTED] + restarts, (marks, now)
    assert now[BYPASSED] == marks[BYPASSED] + restarts, (marks, now)
    assert now[TERMINAL] == marks[TERMINAL], (marks, now)
    assert now[UNSTARTED] == marks[UNSTARTED], (marks, now)
    assert now[KASAN] == marks[KASAN], (marks, now)
    line = (await console_command(console, "sh", "-c",
                                  f"dmesg | grep -F -- {shlex.quote(RESTARTED)} | tail -n 1"))["stdout"]
    restart_counts(line)
    return line


def restart_counts(line: str) -> tuple[int, int, int, int]:
    """Keys resolved, FQID ranges released, and the milliseconds the ports
    were stopped and then bypassed, from a restart line."""
    match = re.search(r"\((\d+) keys resolved, (\d+) FQID ranges released, "
                      r"stopped (\d+) ms, bypassed (\d+) ms\)", line)
    assert match, line
    return int(match[1]), int(match[2]), int(match[3]), int(match[4])


# Fails one unicast delete and times the restart on the DUT itself, so the UART
# is no part of the measurement: from the delete's own command to the latch
# gone, one more restart counted and both receive ports running again -- and
# how long, of that, the receive ports were not running at all.
TIMED_RESTART = '''
import json, subprocess, time
def proc():
    fields = {{}}
    for line in open('/proc/ask_flowtable/status'):
        key, _, value = line.partition(':')
        if value.strip().isdigit():
            fields[key.strip()] = int(value)
    return fields
dumps = rx_port_dumps()
first = proc()
before = first['restarts']
open({fault!r}, 'w').write('1')
start = time.monotonic()
subprocess.run({trigger!r}, check=True)
latched = False
stopped_since, stopped = None, 0.0
while time.monotonic() - start < 10:
    state, rx = proc(), rx_ports_enabled(dumps)
    now = time.monotonic()
    latched |= bool(state['fatal'])
    if rx != {{'6': 1, '7': 1}}:
        stopped_since = stopped_since or now
    elif stopped_since:
        stopped = max(stopped, now - stopped_since)
        stopped_since = None
    if not state['fatal'] and state['restarts'] == before + 1 and rx == {{'6': 1, '7': 1}}:
        break
    time.sleep(0.002)
print(json.dumps({{'seconds': time.monotonic() - start, 'before': before, 'restarts': state['restarts'],
                  'fatal': state['fatal'], 'ports': rx, 'latched': latched, 'stopped': stopped,
                  'resume_failures': state['resume_failures'] - first['resume_failures']}}))
'''


async def timed_restart(console, trigger: list[str], fault: str = UNICAST_FAULT) -> dict:
    """A restart nothing holds: within RESTART_BOUND of the failed delete, the
    receive ports never stopped for longer than STOP_BOUND of it."""
    result = console_json((await console_python(console, RX_PORTS_CODE + TIMED_RESTART.format(
        fault=fault, trigger=trigger), timeout=30))["stdout"])
    assert result["restarts"] == result["before"] + 1 and not result["fatal"], result
    assert result["ports"] == RUNNING and result["resume_failures"] == 0, result
    assert result["seconds"] <= RESTART_BOUND, result
    assert result["stopped"] <= STOP_BOUND, result
    return result

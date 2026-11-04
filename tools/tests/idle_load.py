"""An idle DUT reports an idle load average."""

import json

from ask_orch.commands import console_python
from ask_orch.uart import Console

# Linux counts every task in TASK_UNINTERRUPTIBLE ("D") toward the load
# average, whether or not it waits for anything. A thread that parks there
# between work items reads as one runnable task forever, so an idle router
# reports a load of 1.0 to every monitoring tool. An idle wait belongs in
# TASK_IDLE, which /proc reports as "I" and the load average leaves out.
#
# A window is ten samples of every thread, half a second apart. A thread in D
# in all ten is a constant load; one blocked on real work (a flowtable
# transaction holding cdx's mutex on this debug image) leaves D by a later
# window, so a dirty window is retried before it counts.
IDLE_STATES = r"""
import glob, json, time

def sample():
    tasks = {}
    for path in glob.glob('/proc/[0-9]*/task/[0-9]*/stat'):
        try:
            with open(path, 'rb') as stat:
                line = stat.read().decode(errors='replace')
        except OSError:
            continue
        end = line.rindex(')')
        tasks[path[:-len('/stat')]] = (line[line.index('(') + 1:end], line[end + 2])
    return tasks

def wchan(task):
    try:
        with open(task + '/wchan') as f:
            return f.read()
    except OSError:
        return '?'

windows = []
for _ in range(3):
    samples = []
    for _ in range(10):
        samples.append(sample())
        time.sleep(0.5)
    blocked = set.intersection(*({(task, comm) for task, (comm, state) in s.items() if state == 'D'}
                                 for s in samples))
    timer = sorted({state for s in samples for comm, state in s.values() if comm == 'cdx_ctrl_timer'})
    windows.append({'always_blocked': sorted([task, comm, wchan(task)] for task, comm in blocked),
                    'cdx_ctrl_timer': timer})
    if not blocked and 'I' in timer:
        break
    time.sleep(5)
print(json.dumps(windows))
"""


async def test_idle_threads_add_no_load(splat_window):
    result = await console_python(Console.target(), IDLE_STATES, timeout=60)
    windows = json.loads(result["stdout"])
    last = windows[-1]
    # cdx's timer wheel thread ticks for the module's life. Catching it idle
    # proves the window covered it, and an uninterruptible sleep never shows I.
    assert "I" in last["cdx_ctrl_timer"], ("cdx_ctrl_timer never seen idle", windows)
    assert not last["always_blocked"], (
        "tasks held in uninterruptible sleep at idle add one each to the load average", windows)

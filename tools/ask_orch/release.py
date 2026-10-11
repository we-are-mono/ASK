"""The release matrix: every run a release needs, and the ledger of how each
one went against a checkout and a DUT image.

One invocation cannot hold the whole qualification. Soaks take an hour,
some cases run in a mode chosen for the run, and some end the boot they run
on. Each of those is an entry here with the settings that select it; the
plugin refuses a release run that narrows or changes its entry, and appends
its outcome to the ledger. `python -m ask_orch.release status` then says,
for the current checkout, which entries passed on one image and which are
still missing.
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from ask_orch.artifacts import runs_root
from ask_orch.provenance import checkout

TOOLS = Path(__file__).resolve().parents[1]
SUITES = {"all": ("host_tests", "tests"), "dut": ("tests",), "startup": ("startup_tests",)}


@dataclass(frozen=True)
class Run:
    suite: str
    # Node paths under tools/; none means the whole suite.
    paths: tuple = ()
    env: dict = field(default_factory=dict)
    # What the boot this run starts on has to be, for the operator.
    boot: str = "the staged test image"


ENDS = "the staged test image, which it ends"
MATRIX = {
    "suite": Run("all"),
    "churn": Run("dut", ("tests/flowtable_churn.py",), {"ASK_FLOWTABLE_CHURN": "1"}),
    "invalidation-barrier": Run("dut", ("tests/flowtable_offload.py::test_invalidation",),
                                {"ASK_FLOWTABLE_INVALIDATION": "barrier"}),
    "terminal-unload": Run("dut", ("tests/flowtable_offload.py::test_terminal",),
                           {"ASK_FLOWTABLE_TERMINAL": "unload"}, ENDS),
    "terminal-budget": Run("dut", ("tests/flowtable_offload.py::test_terminal",),
                           {"ASK_FLOWTABLE_TERMINAL": "budget"}, ENDS),
    "unregister": Run("dut", ("tests/flowtable_unregister.py",), {"ASK_FLOWTABLE_UNREGISTER": "1"}, ENDS),
    "startup": Run("startup", boot="the staged test image with rdinit=/bin/sh, which it ends"),
}

# Explicit cases no entry runs, and why that loses no coverage.
WAIVED = {
    "tests/flowtable_offload.py::test_long_exchange":
        "a diagnostic that localises loss the suite's own exchanges already fail on",
}

# Settings that would weaken what a release run proves: its rate floors,
# sweep widths, soak lengths and offered loads, and the snapshot rewrite. A
# release proves the defaults, so each must be unset.
GATES = {
    "ASK_DRAIN_SOAK_PASSES", "ASK_FLOWTABLE_CHURN_SECONDS", "ASK_FLOWTABLE_QOS_CAP_MBIT",
    "ASK_FLOWTABLE_QOS_UNSHAPED_GBPS", "ASK_FLOWTABLE_QOS_WRED_MBIT", "ASK_IPERF_DURATION",
    "ASK_IPSEC_DMA_SWEEP", "ASK_IPSEC_FAILSLAB_SWEEP", "ASK_IPSEC_IPERF_BPS",
    "ASK_PROFILE_HOME_POLICE_BURST", "ASK_PROFILE_HOME_POLICE_MBIT", "ASK_REGEN_ABI_SNAPSHOT",
}
FLOOR = re.compile(r"^ASK_\w*_MIN_GBPS\d?$")


def variables():
    return sorted({name for run in MATRIX.values() for name in run.env})


def overrides(environ):
    return sorted(name for name in environ if name in GATES or FLOOR.match(name))


def environment(name, environ):
    """The environment that runs entry `name`: every matrix variable unset
    but the entry's own."""
    env = {key: value for key, value in environ.items() if key not in variables()}
    env.update(MATRIX[name].env)
    return env


def paths(name):
    run = MATRIX[name]
    return list(run.paths or SUITES[run.suite])


def contains(path, nodeid):
    if "::" in path:
        return nodeid == path or nodeid.startswith(path + "[")
    return nodeid.startswith(path + ("::" if path.endswith(".py") else "/"))


def covers(name, nodeid, variable, values):
    """Whether entry `name` runs an explicit case: it sets the case's
    variable to a value that selects it, over a path that contains it."""
    return (MATRIX[name].env.get(variable) in values
            and any(contains(path, nodeid) for path in paths(name)))


def uncovered(run, cases):
    """The explicit cases entry `run` leaves out that no other entry runs
    and no waiver accounts for."""
    return [case["nodeid"] for case in cases
            if case["nodeid"] not in WAIVED and not any(
                covers(other, case["nodeid"], case["variable"], case["values"])
                for other in MATRIX if other != run)]


def ledger_path(root=None):
    return Path(os.environ.get("ASK_RELEASE_LEDGER") or Path(root or runs_root()) / "release-ledger.jsonl")


def append(path, entry):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    with os.fdopen(fd, "a") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def read(path):
    try:
        lines = Path(path).read_text().splitlines()
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in lines if line.strip()]


def status(entries, source):
    """One row per matrix entry for checkout `source`: its latest run there,
    and whether it passed on the same DUT image as the others."""
    latest = {}
    for entry in entries:
        if entry.get("checkout") == source["sha256"] and entry.get("run") in MATRIX:
            if entry["run"] not in latest or entry["finished"] >= latest[entry["run"]]["finished"]:
                latest[entry["run"]] = entry
    passed = [entry for entry in latest.values() if entry["exitstatus"] == 0]
    reference = (latest["suite"]["image"] if "suite" in latest and latest["suite"]["exitstatus"] == 0
                 else max(passed, key=lambda entry: entry["finished"])["image"] if passed else None)
    rows = []
    for name in MATRIX:
        entry = latest.get(name)
        if entry is None:
            state = "missing"
        elif entry["exitstatus"] != 0:
            state = "failed"
        elif not entry.get("image"):
            state = "no image identity"
        elif entry["image"] != reference:
            state = "other image"
        else:
            state = "passed"
        rows.append({"run": name, "state": state, "entry": entry})
    return rows


def _when(seconds):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(seconds))


def report(rows, source, ledger, out=sys.stdout):
    print(f"release matrix for {source['revision'][:12]} (checkout {source['sha256'][:12]}); "
          f"ledger {ledger}", file=out)
    width = max(len(name) for name in MATRIX)
    for row in rows:
        name, state, entry = row["run"], row["state"], row["entry"]
        if entry is None:
            detail = f"make test-release RUN={name}  (on {MATRIX[name].boot})"
        else:
            detail = f"{_when(entry['finished'])}  boot {str(entry.get('boot_id'))[:8]}  {entry['run_dir']}"
            if state == "failed":
                failed = entry.get("failed") or [f"exit status {entry['exitstatus']}"]
                detail += f"\n{'':{width + 13}}{len(failed)} failed: {', '.join(failed[:3])}"
        print(f"  {name:{width}}  {state:9}  {detail}", file=out)
    for nodeid, reason in WAIVED.items():
        print(f"  waived: {nodeid}: {reason}", file=out)
    done = sum(row["state"] == "passed" for row in rows)
    print(f"release {'qualified' if done == len(rows) else 'incomplete'}: {done} of {len(rows)} runs passed",
          file=out)
    return done == len(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("status",))
    parser.parse_args(argv)
    source = checkout(TOOLS.parent)
    ledger = ledger_path()
    return 0 if report(status(read(ledger), source), source, ledger) else 1


if __name__ == "__main__":
    sys.exit(main())

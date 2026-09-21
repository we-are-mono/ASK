#!/usr/bin/python3
"""DUT failslab lease: one real slab failure in a named allocation path.

The stack filter follows asynchronous work, unlike a sender's fail-nth.
This independent process restores every knob on consumption, cancellation or
expiry, even if the orchestrator disconnects. It never repairs flowtables.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

TARGETS = {
    "binding": ("ft_block_setup", "ask_flowtable", "flow_block_cb_alloc"),
    "callback": ("flow_block_cb_alloc", None, None),
    "entry": ("ft_replace", "ask_flowtable", None),
    "hardware": ("cdx_ft_hw_add", "cdx", None),
    "work": ("nf_flow_offload_add", "nf_flow_table", None),
    "rule": ("nf_flow_offload_rule_alloc", "nf_flow_table", None),
    "actions": ("flow_rule_alloc", None, None),
}
KNOBS = ("probability", "times", "interval", "space", "verbose", "task-filter",
         "ignore-gfp-wait", "cache-filter", "stacktrace-depth", "require-start",
         "require-end", "reject-start", "reject-end", "verbose_ratelimit_interval_ms",
         "verbose_ratelimit_burst")


def symbol_range(text, name, module):
    symbols = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) not in (3, 4) or parts[1] not in ("t", "T"):
            continue
        owner = parts[3].strip("[]") if len(parts) == 4 else None
        if owner == module:
            symbols.append((int(parts[0], 16), parts[2]))
    matches = [(address, symbol) for address, symbol in symbols
               if symbol == name or re.fullmatch(re.escape(name) + r"\.(?:constprop|isra)\.\d+", symbol)]
    assert len(matches) == 1, (name, module, matches)
    address, symbol = matches[0]
    assert address, "kernel symbol addresses are hidden"
    end = min(a for a, _ in symbols if a > address)
    return {"name": symbol, "module": module, "start": address, "end": end}


def save(root, name, data):
    tmp = root / (name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(root / name)


def drain_kmsg(fd):
    result = []
    while True:
        try:
            record = os.read(fd, 65536)
            if not record:
                return result
            result.append(record.decode(errors="replace"))
        except BlockingIOError:
            return result


def run(root, target, *, lease=20, debugfs=Path("/sys/kernel/debug/failslab"),
        kallsyms=Path("/proc/kallsyms"), backend=Path("/proc/cdx_flowtable"),
        lock_path=Path("/run/lock/ask-flowtable-failslab.lock"), kmsg=Path("/dev/kmsg")):
    assert 0 < lease <= 30
    root.mkdir(exist_ok=True)
    snapshot, result, records = {}, {"target": target, "consumed": False}, []
    fd = None
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            for name in KNOBS:
                snapshot[name] = (debugfs / name).read_text().strip()
            assert int(snapshot["probability"]) == 0, "another failslab user is active"
            name, module, reject = TARGETS[target]
            symbols = kallsyms.read_text()
            selected = symbol_range(symbols, name, module)
            excluded = symbol_range(symbols, reject, None) if reject else None
            result.update(selected=selected, excluded=excluded, original=snapshot)
            save(root, "original.json", snapshot)
            fd = os.open(kmsg, os.O_RDONLY | os.O_NONBLOCK)
            os.lseek(fd, 0, os.SEEK_END)
            settings = {"times": "1", "interval": "1", "space": "0", "verbose": "2",
                        "task-filter": "N", "ignore-gfp-wait": "N", "cache-filter": "N",
                        "stacktrace-depth": "32", "require-start": hex(selected["start"]),
                        "require-end": hex(selected["end"]),
                        "reject-start": hex(excluded["start"]) if excluded else "0",
                        "reject-end": hex(excluded["end"]) if excluded else "0",
                        "verbose_ratelimit_interval_ms": "0", "verbose_ratelimit_burst": "100"}
            for name, value in settings.items():
                (debugfs / name).write_text(value)
            started = time.monotonic()
            (debugfs / "probability").write_text("100")
            save(root, "armed.json", {**result, "armed_at": started, "pid": os.getpid(), "lease": lease})
            while time.monotonic() - started < lease and not (root / "cancel").exists():
                records.extend(drain_kmsg(fd))
                remaining = int((debugfs / "times").read_text().strip())
                if remaining == 0:
                    result.update(consumed=True, consumed_at=time.monotonic(), remaining=remaining)
                    break
                time.sleep(0.01)
        except BaseException as error:
            result["error"] = repr(error)
        finally:
            # Do not touch a pre-existing active injector. Once we own the
            # inactive configuration, restore it even after a partial setup.
            failures = []
            if snapshot and snapshot.get("probability") == "0":
                try:
                    (debugfs / "probability").write_text("0")
                except OSError as error:
                    failures.append(repr(error))
                for name, value in snapshot.items():
                    if name == "probability":
                        continue
                    try:
                        (debugfs / name).write_text(value)
                    except OSError as error:
                        failures.append(repr(error))
                result["restored"] = {name: (debugfs / name).read_text().strip() for name in snapshot}
            if fd is not None:
                records.extend(drain_kmsg(fd))
                os.close(fd)
            result["restore_errors"] = failures
            result["finished_at"] = time.monotonic()
            result["kernel_records"] = records
            result["backend"] = backend.read_text()
            save(root, "result.json", result)


if __name__ == "__main__":
    root = Path(sys.argv[1])
    # TERM requests the same bounded cleanup as a normal cancellation.
    signal.signal(signal.SIGTERM, lambda *_: (root / "cancel").touch())
    run(root, sys.argv[2])

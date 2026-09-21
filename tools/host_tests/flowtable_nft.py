#!/usr/bin/env python3
"""A stateful nft process boundary for the real C controller's host tests."""
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

root = Path(os.environ["FT_TEST_ROOT"])
args = sys.argv[1:]
script = sys.stdin.read() if "-f" in args else ""
with (root / "calls").open("a") as log:
    log.write(json.dumps({"args": args, "time": time.monotonic()}) + "\n")


def backend(**changes):
    path = root / "backend"
    fields = dict(line.split() for line in path.read_text().splitlines())
    fields.update({k: str(v) for k, v in changes.items()})
    tmp = path.with_suffix(".tmp")
    tmp.write_text("".join(f"{k} {v}\n" for k, v in fields.items()))
    tmp.replace(path)


def crash(point):
    armed = root / "crash-at"
    if not armed.exists() or armed.read_text() != point:
        return
    armed.unlink()
    controller = int((root / "daemon.pid").read_text())
    (root / "crash-hit.tmp").write_text(json.dumps({"point": point, "controller": controller,
                                                   "worker": os.getpid(), "guardian": os.getppid()}))
    (root / "crash-hit.tmp").replace(root / "crash-hit")
    os.kill(controller, signal.SIGKILL)
    time.sleep(2)  # guardian must kill us; this old writer must not resume
    (root / "late-writer").touch()


table = root / "table"
if (root / "inspect-error").exists() and args[0] == "list":
    sys.exit("injected netlink inspection failure")
if args == ["list", "tables"]:
    if table.exists():
        print("table inet ask_flowtable")
elif args == ["list", "table", "inet", "ask_flowtable"]:
    if not table.exists():
        sys.exit("Error: No such file or directory")
    print(table.read_text())
elif args == ["delete", "table", "inet", "ask_flowtable"]:
    table.unlink(missing_ok=True)
    backend(bindings=0, entries=0, handle_refs=0, neighbour_refs=0, quarantine=0)
    crash("drain")
elif "-f" in args:
    fail = root / "fail-install"
    if "--check" not in args:
        crash("install")
        if (root / "hang-install").exists():
            (root / "hang-install").unlink()
            (root / "fault-consumed").touch()
            time.sleep(2)
        if fail.exists():
            fail.unlink()
            (root / "fault-consumed").touch()
            sys.exit("injected transaction failure")
        if (root / "block-install").exists():
            (root / "install-blocked").touch()
            deadline = time.monotonic() + 10
            while (root / "block-install").exists():
                if time.monotonic() > deadline:
                    sys.exit("test did not release blocked install")
                time.sleep(0.01)
        table.write_text(script)
        devices = re.search(r"devices\s*=\s*\{([^}]+)\}", script)[1]
        backend(bindings=len(re.findall(r'"[^"]+"', devices)), invalidated=0)
        crash("commit")
        if (root / "commit-hang").exists():
            (root / "commit-hang").unlink()
            (root / "fault-consumed").touch()
            time.sleep(2)
else:
    sys.exit(f"unexpected nft command: {args}")

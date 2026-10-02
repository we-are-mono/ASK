"""Shared support for flowtable recovery."""

import json
import os
import re
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from ask_orch.process import run_process

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "flowtable/src"
POLICY = "enabled yes\ndevices eth3 eth4\nscope any\n"
AUTO = "enabled yes\ndevices auto\nscope any\n"


@pytest.fixture
def controller(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    replacements = {
        "/run/ask-flowtable": str(tmp_path),
        "/proc/cdx_flowtable": str(tmp_path / "backend"),
        "/proc/sys/kernel/random/boot_id": str(tmp_path / "boot_id"),
        "/sys/module/cdx": str(tmp_path / "cdx"),
        "/sys/module/ask_flowtable/parameters/multicast": str(tmp_path / "multicast"),
        "/run/ask-flowtable/policy.lock": str(tmp_path / "lock"),
        "/run/ask-flowtable/paused": str(tmp_path / "paused"),
        "/etc/ask/offload.conf": str(tmp_path / "policy"),
        "/run/ask-flowtable/daemon.lock": str(tmp_path / "daemon.lock"),
        "/run/ask-flowtable/service.lock": str(tmp_path / "service.lock"),
        "/run/ask-flowtable/control.lock": str(tmp_path / "control.lock"),
        "/run/ask-flowtable/service.sock": str(tmp_path / "service.sock"),
        "/run/ask-flowtable/worker.pid": str(tmp_path / "daemon.pid"),
        "/run/ask-flowtable/supervisor.pid": str(tmp_path / "supervisor.pid"),
        "/dev/log": str(tmp_path / "log.sock"),
        "/dev/console": str(tmp_path / "console"),
    }
    for path in ENGINE.iterdir():
        if path.suffix not in {".h", ".c"}:
            continue
        text = path.read_text()
        for before, after in replacements.items():
            text = text.replace('"' + before + '"', '"' + after + '"')
        (src / path.name).write_text(text)
    # No real host networking mutations or events. A pipe permits intentional
    # event storms as well as a provably quiet network.
    (src / "netlink.c").write_text('''
#include "runtime.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int ft_nl_open(void) { return open(getenv("FT_TEST_EVENTS"), O_RDWR | O_NONBLOCK); }
int ft_nl_drain(int fd) { char b[4096]; return read(fd, b, sizeof(b)) > 0; }
''')
    # The up ports are whatever a test last published, eth3 and eth4 until then.
    (src / "enumerate.c").write_text('''
#include "runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int ft_enumerate(struct ft_policy *p) {
    char path[4096], name[FT_IFNAME_MAX + 1];
    FILE *f;
    snprintf(path, sizeof(path), "%s/ports", getenv("FT_TEST_ROOT"));
    p->ndevices = 0;
    if (!(f = fopen(path, "r"))) {
        strcpy(p->devices[0], "eth3"); strcpy(p->devices[1], "eth4");
        return p->ndevices = 2;
    }
    while (p->ndevices < FT_MAX_DEVICES && fscanf(f, "%15s", name) == 1)
        strcpy(p->devices[p->ndevices++], name);
    fclose(f);
    return p->ndevices;
}
''')
    binary = tmp_path / "ask-flowtable"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-O1", "-g",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-DFT_HEALTH_MS=100", "-DFT_RETRY_MIN_MS=50",
        "-DFT_RETRY_MAX_MS=400", "-DFT_DEBOUNCE_MS=20",
        "-DFT_NFT_TIMEOUT_MS=500", "-DFT_NFT_CLEANUP_MS=500",
        "-DFT_SUPERVISOR_MIN_MS=60", "-DFT_SUPERVISOR_MAX_MS=240",
        "-DFT_SUPERVISOR_STABLE_MS=600", "-DFT_SUPERVISOR_STOP_MS=100",
        "-DFT_SERVICE_WAIT_MS=1500",
        "-DFT_HEALTH_TIMEOUT_MS=500",
        *map(str, sorted(src.glob("*.c"))), "-o", str(binary),
    ], check=True)
    shutil.copyfile(Path(__file__).with_name("flowtable_nft.py"), tmp_path / "nft")
    (tmp_path / "nft").chmod(0o755)
    (tmp_path / "cdx").mkdir()
    (tmp_path / "policy").write_text(POLICY)
    (tmp_path / "backend").write_text(
        "bindings 0\nentries 0\nhandle_refs 0\nneighbour_refs 0\n"
        "quarantine 0\nfatal 0\nobserve 0\ninvalidated 0\n"
        "installs 0\ndeletes 0\nrearms 0\nerrors 0\nqos_mark_mask 0\n"
        "mcast_enabled 1\nmcast_installed 0\nmroute_installed 0\n")
    os.mkfifo(tmp_path / "events")
    return Controller(tmp_path, binary)


class Controller:
    def __init__(self, root, binary):
        self.root, self.binary = root, binary
        self.env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                    "FT_TEST_ROOT": str(root), "FT_TEST_EVENTS": str(root / "events"),
                    "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1"}

    def run(self, *args, check=True):
        result = run_process([str(self.binary), *args], env=self.env,
                                capture_output=True, text=True, timeout=5)
        if check:
            assert result.returncode == 0, result.stderr
        return result

    def status(self):
        return json.loads(self.run("status").stdout)

    def ready(self):
        return self.status()["admission_ready"]

    def wait(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        pytest.fail("controller did not converge; " + (self.root / "daemon.log").read_text())

    def calls(self, verb=None):
        path = self.root / "calls"
        calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [c for c in calls if verb is None or c["args"][0] == verb]

    def backend(self, **changes):
        path = self.root / "backend"
        fields = dict(line.split() for line in path.read_text().splitlines())
        fields.update({k: str(v) for k, v in changes.items()})
        tmp = path.with_suffix(".update")
        tmp.write_text("".join(f"{k} {v}\n" for k, v in fields.items()))
        tmp.replace(path)

    def ports(self, *names):
        """Publish the ports `devices auto` finds up."""
        tmp = self.root / "ports.update"
        tmp.write_text(" ".join(names) + "\n")
        tmp.replace(self.root / "ports")

    def log(self):
        return (self.root / "daemon.log").read_text()

    @contextmanager
    def daemon(self):
        with (self.root / "daemon.log").open("a") as log:
            process = subprocess.Popen([str(self.binary), "daemon"], env=self.env,
                                       stdout=log, stderr=log)
            try:
                yield process
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                text = (self.root / "daemon.log").read_text()
                assert "AddressSanitizer" not in text and "runtime error:" not in text, text


def statements(call):
    """(verb, devices) for each statement of a device membership update."""
    return [(verb, re.findall(r'"([^"]+)"', names)) for verb, names in
            re.findall(r"^(add|delete) flowtable inet ask_flowtable fast \{.*?devices = \{([^}]*)\}",
                       call["script"], re.M)]


def following(c, ports):
    status = c.status()
    return (sorted(status["devices"] or []) == sorted(ports) and status["admission_ready"]
            and status["backend"]["bindings"] == len(ports))


def relist(c, name, listed):
    """Make nft list a device under another name than the one installed."""
    table = c.root / "table"
    table.write_text(table.read_text().replace(f'"{name}"', f'"{listed}"'))

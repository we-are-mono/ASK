"""Exercise the real controller, locks and daemon with a fake nft/kernel boundary."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "flowtable/src"
POLICY = "enabled yes\ndevices eth3 eth4\nscope any\n"


@pytest.fixture
def controller(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    replacements = {
        "/proc/cdx_flowtable": str(tmp_path / "backend"),
        "/sys/module/cdx": str(tmp_path / "cdx"),
        "/run/lock/ask-flowtable.lock": str(tmp_path / "lock"),
        "/run/lock/ask-flowtable.paused": str(tmp_path / "paused"),
        "/etc/ask/offload.conf": str(tmp_path / "policy"),
        "/run/lock/ask-flowtable-daemon.lock": str(tmp_path / "daemon.lock"),
        "/run/lock/ask-flowtable-service.lock": str(tmp_path / "service.lock"),
        "/run/lock/ask-flowtable-control.lock": str(tmp_path / "control.lock"),
        "/run/ask-flowtable.sock": str(tmp_path / "service.sock"),
        "/var/run/ask-flowtable.pid": str(tmp_path / "daemon.pid"),
        "/var/run/ask-flowtable-supervisor.pid": str(tmp_path / "supervisor.pid"),
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
    (src / "enumerate.c").write_text('''
#include "runtime.h"
#include <string.h>
int ft_enumerate(struct ft_policy *p) {
    strcpy(p->devices[0], "eth3"); strcpy(p->devices[1], "eth4");
    return p->ndevices = 2;
}
''')
    binary = tmp_path / "ask-flowtable"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-O1", "-g",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-DFT_HEALTH_MS=100", "-DFT_RETRY_MIN_MS=50",
        "-DFT_RETRY_MAX_MS=400", "-DFT_DEBOUNCE_MS=20",
        "-DFT_NFT_TIMEOUT_MS=500", "-DFT_NFT_CLEANUP_MS=500",
        "-DFT_SUPERVISOR_MIN_MS=60", "-DFT_SUPERVISOR_MAX_MS=240",
        "-DFT_SUPERVISOR_STABLE_MS=600", "-DFT_SUPERVISOR_STOP_MS=100",
        "-DFT_SERVICE_WAIT_MS=1500",
        *map(str, sorted(src.glob("*.c"))), "-o", str(binary),
    ], check=True)
    shutil.copyfile(Path(__file__).with_name("flowtable_nft.py"), tmp_path / "nft")
    (tmp_path / "nft").chmod(0o755)
    (tmp_path / "cdx").mkdir()
    (tmp_path / "policy").write_text(POLICY)
    (tmp_path / "backend").write_text(
        "bindings 0\nentries 0\nhandle_refs 0\nneighbour_refs 0\n"
        "quarantine 0\nfatal 0\nobserve 0\ninvalidated 0\n"
        "installs 0\ndeletes 0\nrearms 0\nerrors 0\nqos_mark_mask 0\n")
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
        result = subprocess.run([str(self.binary), *args], env=self.env,
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


def test_quiet_network_retries_failed_apply(controller):
    c = controller
    (c.root / "fail-install").touch()
    with c.daemon():
        c.wait(lambda: (c.root / "fault-consumed").exists())
        c.wait(c.ready)
        assert len(c.calls("-f")) == 2


def test_hung_install_cannot_commit_after_timeout(controller):
    c = controller
    (c.root / "hang-install").touch()
    started = time.monotonic()
    result = c.run("apply", check=False)
    elapsed = time.monotonic() - started
    assert (c.root / "fault-consumed").exists()
    assert result.returncode != 0, result.stdout
    assert "deadline" in result.stderr
    assert elapsed < 1.8, elapsed
    # A new owner can commit safely; the timed-out writer cannot wake later
    # and restore its older generation after this stop released the lease.
    c.run("stop")
    time.sleep(2)
    assert not (c.root / "table").exists()


@pytest.mark.parametrize("fault,commits", [("hang-install", 2), ("commit-hang", 1)])
def test_daemon_recovers_hung_transaction_from_observed_state(controller, fault, commits):
    c = controller
    (c.root / fault).touch()
    with c.daemon() as daemon:
        c.wait(lambda: (c.root / "fault-consumed").exists())
        c.wait(c.ready)
        time.sleep(0.5)
        assert daemon.poll() is None
        assert len(c.calls("-f")) == commits
        assert not c.calls("delete")  # a lost reply cannot force a healthy rebind
        assert "deadline" in (c.root / "daemon.log").read_text()


def test_manual_lost_reply_reports_uncertainty_and_keeps_pause(controller):
    c = controller
    (c.root / "commit-hang").touch()
    result = c.run("apply", check=False)
    assert result.returncode != 0 and "outcome requires inspection" in result.stderr
    assert c.ready() and c.status()["reconciliation_paused"]
    assert len(c.calls("-f")) == 1


def test_quiet_network_restores_missing_table(controller):
    c = controller
    with c.daemon():
        c.wait(c.ready)
        original = c.status()["policy_hash"]
        subprocess.run([str(c.root / "nft"), "delete", "table", "inet", "ask_flowtable"],
                       env=c.env, check=True)
        c.wait(c.ready)
        assert c.status()["policy_hash"] == original
        assert len(c.calls("-f")) == 2


def test_quiet_network_repairs_invalidated_backend(controller):
    c = controller
    with c.daemon():
        c.wait(c.ready)
        original = c.status()["policy_hash"]
        c.backend(invalidated=1)
        c.wait(c.ready)
        assert c.status()["policy_hash"] == original
        assert len(c.calls("delete")) == 1
        assert len(c.calls("-f")) == 2


def test_healthy_checks_do_not_rebuild(controller):
    c = controller
    with c.daemon():
        c.wait(c.ready)
        time.sleep(0.6)
        assert len(c.calls("list")) >= 4
        assert len(c.calls("-f")) == 1
        assert not c.calls("delete")


def test_stop_survives_daemon_restart_until_resume(controller):
    c = controller
    with c.daemon():
        c.wait(c.ready)
        c.run("stop")
        time.sleep(0.4)
        assert not c.ready()
        assert c.status()["reconciliation_paused"]
    with c.daemon():
        time.sleep(0.4)
        assert not c.ready()
        assert len(c.calls("-f")) == 1
        c.run("resume")
        c.wait(c.ready)
        assert not c.status()["reconciliation_paused"]


def test_manual_temporary_policy_retains_authority(controller):
    c = controller
    custom = c.root / "temporary.conf"
    custom.write_text(POLICY + "exclude tcp 443\n")
    with c.daemon():
        c.wait(c.ready)
        original = c.status()["policy_hash"]
        c.run("apply", "--config", str(custom))
        manual = c.status()["policy_hash"]
        assert manual != original
        custom.unlink()
        time.sleep(0.5)
        assert c.status()["policy_hash"] == manual
        assert c.status()["reconciliation_paused"]
        c.run("resume")
        c.wait(lambda: c.status()["policy_hash"] == original)


def test_failed_manual_apply_does_not_restore_obsolete_policy(controller):
    c = controller
    with c.daemon():
        c.wait(c.ready)
        (c.root / "fail-install").touch()
        result = c.run("apply", check=False)
        assert result.returncode != 0 and "injected" in result.stderr
        time.sleep(0.5)
        assert not c.ready()
        assert c.status()["reconciliation_paused"]
        assert len(c.calls("-f")) == 2


def test_disabled_configuration_stays_disabled_and_can_be_enabled(controller):
    c = controller
    with c.daemon():
        c.wait(c.ready)
        (c.root / "policy").write_text("enabled no\n")
        c.wait(lambda: not c.ready())
        time.sleep(0.4)
        assert len(c.calls("-f")) == 1
        assert len(c.calls("delete")) == 1
        assert not c.status()["reconciliation_paused"]
        (c.root / "policy").write_text(POLICY)
        c.wait(c.ready)


def test_malformed_configuration_preserves_policy_and_does_not_block_stop(controller):
    c = controller
    with c.daemon():
        c.wait(c.ready)
        before = c.status()["policy_hash"]
        (c.root / "policy").write_text("enabled maybe\n")
        time.sleep(0.4)
        assert c.status()["policy_hash"] == before
        assert len(c.calls("-f")) == 1
        c.run("stop")
        c.run("resume")
        time.sleep(0.3)
        assert not c.ready()
        (c.root / "policy").write_text(POLICY)
        c.wait(c.ready)


@pytest.mark.parametrize("bindings", [0, 2])
def test_foreign_table_is_never_modified(controller, bindings):
    c = controller
    foreign = 'table inet ask_flowtable { comment "foreign"; }\n'
    (c.root / "table").write_text(foreign)
    c.backend(bindings=bindings)
    with c.daemon():
        time.sleep(0.5)
        result = c.run("apply", check=False)
        assert result.returncode != 0 and "ownership marker" in result.stderr
        assert (c.root / "table").read_text() == foreign
        assert not c.calls("delete") and not c.calls("-f") and not c.calls("--check")


def test_foreign_backend_bindings_are_never_replaced(controller):
    c = controller
    c.backend(bindings=2)
    with c.daemon():
        time.sleep(0.5)
        assert not c.calls("delete") and not c.calls("-f") and not c.calls("--check")
        c.backend(bindings=0)
        c.wait(c.ready)


@pytest.mark.parametrize("field,value", [("fatal", 1), ("observe", 1)])
def test_inactive_or_fatal_backend_is_not_rearmed(controller, field, value):
    c = controller
    c.backend(**{field: value})
    with c.daemon():
        time.sleep(0.5)
        assert not c.calls("delete") and not c.calls("-f") and not c.calls("--check")
        if field != "fatal":
            c.backend(**{field: 0})
            c.wait(c.ready)


def test_absent_adapter_is_retried_until_it_returns(controller):
    """CDX without the adapter (e.g. across an ask_flowtable reload) keeps
    the controller running: it installs nothing, then recovers by itself."""
    c = controller
    backend = c.root / "backend"
    header = backend.read_text()
    backend.unlink()
    with c.daemon():
        time.sleep(0.5)
        assert not c.calls("-f") and not c.calls("--check")
        backend.write_text(header)
        c.wait(c.ready)


def test_inspection_error_does_not_authorize_install(controller):
    c = controller
    (c.root / "inspect-error").touch()
    with c.daemon():
        time.sleep(0.5)
        assert not c.calls("-f") and not c.calls("--check")
        (c.root / "inspect-error").unlink()
        c.wait(c.ready)


def test_pause_write_failure_prevents_stop_mutation(controller):
    c = controller
    c.run("apply")
    (c.root / "paused").unlink()
    (c.root / "paused").mkdir()
    result = c.run("stop", check=False)
    assert result.returncode != 0 and "cannot set reconciliation pause" in result.stderr
    assert c.ready()
    assert not c.calls("delete")


def test_stop_waiting_for_install_cannot_be_undone_by_daemon(controller):
    c = controller
    (c.root / "block-install").touch()
    with c.daemon():
        c.wait(lambda: (c.root / "install-blocked").exists())
        stop = subprocess.Popen([str(c.binary), "stop"], env=c.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(0.1)
            assert stop.poll() is None
            (c.root / "block-install").unlink()
            _, err = stop.communicate(timeout=3)
            assert stop.returncode == 0, err
            time.sleep(0.4)
            assert not c.ready() and c.status()["reconciliation_paused"]
            assert len(c.calls("-f")) == 1
        finally:
            (c.root / "block-install").unlink(missing_ok=True)
            if stop.poll() is None:
                stop.kill()
                stop.wait()


def test_event_storm_cannot_starve_recovery_or_defeat_backoff(controller):
    c = controller
    (c.root / "inspect-error").touch()
    done = threading.Event()
    events = os.open(c.root / "events", os.O_RDWR | os.O_NONBLOCK)

    def storm():
        while not done.wait(0.001):
            try:
                os.write(events, b"event")
            except BlockingIOError:
                pass

    thread = threading.Thread(target=storm)
    thread.start()
    try:
        with c.daemon():
            time.sleep(0.8)
            attempts = [r["time"] for r in c.calls("list") if r["args"][1] == "table"]
            assert 2 <= len(attempts) <= 5, attempts
            assert all(b - a >= 0.04 for a, b in zip(attempts, attempts[1:])), attempts
            (c.root / "inspect-error").unlink()
            c.wait(c.ready)
    finally:
        done.set()
        thread.join(timeout=2)
        os.close(events)


def test_missing_explicit_config_does_not_fall_back_to_default(controller):
    c = controller
    result = c.run("apply", "--config", str(c.root / "missing"), check=False)
    assert result.returncode != 0 and "cannot open" in result.stderr
    assert not c.calls()


def test_resume_rejects_candidate_configuration(controller):
    c = controller
    c.run("stop")
    result = c.run("resume", "--config", str(c.root / "policy"), check=False)
    assert result.returncode == 2
    assert c.status()["reconciliation_paused"]

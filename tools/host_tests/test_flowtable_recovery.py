"""Exercise the real controller, locks and daemon with a fake nft/kernel boundary."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "flowtable/src"
POLICY = "enabled yes\ndevices eth3 eth4\nscope any\n"
AUTO = "enabled yes\ndevices auto\nscope any\n"


@pytest.fixture
def controller(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    replacements = {
        "/proc/cdx_flowtable": str(tmp_path / "backend"),
        "/sys/module/cdx": str(tmp_path / "cdx"),
        "/sys/module/ask_flowtable/parameters/multicast": str(tmp_path / "multicast"),
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


def test_stop_and_disabled_policy_withdraw_multicast(controller):
    """Multicast follows no flowtable: an enabled policy switches the adapter's
    multicast acceleration on after its table, and a stop or a disabled policy
    switches it off first. A stop returns only once both learners' groups have
    left hardware, and a disabled policy rewrites the switch on every check,
    which is how an adapter reloaded with it on again is caught."""
    c = controller
    switch = c.root / "multicast"

    def multicast():
        """The parameter as last written, None before the first write."""
        return switch.read_text() if switch.exists() else None

    with c.daemon():
        c.wait(lambda: c.ready() and multicast() == "Y\n")
        c.backend(mcast_installed=2, mroute_installed=1)
        stop = subprocess.Popen([str(c.binary), "stop"], env=c.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            c.wait(lambda: multicast() == "N\n")
            c.backend(mcast_installed=0)
            time.sleep(0.3)
            assert stop.poll() is None  # a routed group is still in hardware
            c.backend(mroute_installed=0)
            out, err = stop.communicate(timeout=3)
            assert stop.returncode == 0, err
            drained = json.loads(out)["drained"]
            assert drained["mcast_installed"] == drained["mroute_installed"] == 0, drained
        finally:
            if stop.poll() is None:
                stop.kill()
                stop.wait()
        time.sleep(0.3)
        assert multicast() == "N\n" and not c.ready()
        c.run("resume")
        c.wait(lambda: c.ready() and multicast() == "Y\n")
        (c.root / "policy").write_text("enabled no\n")
        c.wait(lambda: not c.ready() and multicast() == "N\n")
        switch.write_text("Y\n")
        c.wait(lambda: multicast() == "N\n")


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


def test_foreign_table_bound_beside_ours_is_left_alone(controller):
    """The adapter binds a second flowtable beside this one: a consumer's own,
    or its offload probe mid-transaction. The backend then counts more
    bindings than this table has devices. Replacing this table would delete it
    and wait on a drain the other table holds up, so the daemon keeps it, says
    why once, and refuses an explicit apply until the other table is gone."""
    c = controller
    with c.daemon():
        c.wait(c.ready)
        installs = len(c.calls("-f"))
        c.backend(bindings=4)
        time.sleep(0.6)
        assert not c.calls("delete") and len(c.calls("-f")) == installs
        assert c.log().count("bound beside") == 1, c.log()
        result = c.run("apply", check=False)
        assert result.returncode != 0 and "bound beside" in result.stderr, result.stderr
        assert not c.calls("delete") and len(c.calls("-f")) == installs
        c.backend(bindings=2)
        time.sleep(0.4)
        assert c.ready() and not c.calls("delete") and len(c.calls("-f")) == installs


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


def test_restarting_datapath_is_waited_for_not_backed_off(controller):
    """CDX restarts the datapath after a deletion it could not prove, which
    takes a second or two: the controller leaves its table alone meanwhile,
    asks again at the shortest interval rather than backing off, says so once,
    and is ready as soon as the latch clears. A latch that is terminal is a
    reboot's, as before."""
    c = controller
    with c.daemon():
        c.wait(c.ready)
        installs = len(c.calls("-f"))
        c.backend(fatal=1, fatal_terminal=0)
        c.wait(lambda: not c.ready())
        time.sleep(0.2)
        checks = len(c.calls("list"))
        time.sleep(1.2)
        # Backing off from 50 ms would allow five checks in this window; the
        # shortest interval allows two dozen, and a loaded host still well
        # over the bound.
        assert len(c.calls("list")) - checks >= 10
        assert not c.calls("delete") and len(c.calls("-f")) == installs
        assert c.log().count("datapath restarting after an unproven deletion") == 1
        status = c.status()["backend"]
        assert status["fatal"] == 1 and status["fatal_terminal"] == 0
        c.backend(fatal=0, restarts=1, resume_failures=1)
        c.wait(c.ready)
        # A port that would not start again is reported, and holds nothing up:
        # the tables are settled, and the netdev is the operator's to restart.
        status = c.status()["backend"]
        assert status["restarts"] == 1 and status["resume_failures"] == 1
        assert not c.calls("delete") and len(c.calls("-f")) == installs
        c.backend(fatal=1, fatal_terminal=1)
        time.sleep(0.4)
        assert "fresh boot required" in c.log()
        assert not c.calls("delete") and len(c.calls("-f")) == installs


def test_drain_waits_out_a_restart(controller):
    """A stop while CDX restarts the datapath waits for the restart like any
    other drain rather than failing, as it fails on a terminal latch."""
    c = controller
    c.run("apply")
    c.backend(fatal=1, fatal_terminal=0)

    def restarted():
        time.sleep(0.3)
        c.backend(fatal=0, restarts=1)

    worker = threading.Thread(target=restarted)
    started = time.monotonic()
    worker.start()
    c.run("stop")
    worker.join()
    assert time.monotonic() - started >= 0.3
    c.run("apply")
    c.backend(fatal=1, fatal_terminal=1)
    result = c.run("stop", check=False)
    assert result.returncode != 0 and "fresh boot required" in result.stderr


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


def statements(call):
    """(verb, devices) for each statement of a device membership update."""
    return [(verb, re.findall(r'"([^"]+)"', names)) for verb, names in
            re.findall(r"^(add|delete) flowtable inet ask_flowtable fast \{.*?devices = \{([^}]*)\}",
                       call["script"], re.M)]


def following(c, ports):
    status = c.status()
    return (sorted(status["devices"] or []) == sorted(ports) and status["admission_ready"]
            and status["backend"]["bindings"] == len(ports))


def test_auto_ports_are_followed_in_place(controller):
    """Under `devices auto` a port joining or leaving is added to or deleted
    from the live flowtable. The table is not deleted, nothing drains, the
    ports that stay are not rebound, and the policy hash, which `check`
    computes without resolving any port, does not move. A swap is one
    transaction."""
    c = controller
    (c.root / "policy").write_text(AUTO)
    with c.daemon():
        c.wait(lambda: following(c, ["eth3", "eth4"]))
        configured = json.loads(c.run("check").stdout)["policy_hash"]
        assert c.status()["policy_hash"] == configured
        # Hardware flows on the ports that stay: a drain would have to empty them.
        c.backend(entries=6, handle_refs=6, neighbour_refs=6)
        for ports, update in ((["eth3", "eth4", "eth5"], [("add", ["eth5"])]),
                              (["eth3", "eth4"], [("delete", ["eth5"])]),
                              (["eth3", "eth5"], [("add", ["eth5"]), ("delete", ["eth4"])])):
            before = len(c.calls("-f"))
            c.ports(*ports)
            c.wait(lambda: following(c, ports))
            calls = c.calls("-f")[before:]
            assert [statements(call) for call in calls] == [update], calls
            status = c.status()
            assert status["policy_hash"] == configured, status
            assert status["backend"]["entries"] == 6, status
        # Only the first install checked, installed a table and drained.
        assert not c.calls("delete") and len(c.calls("--check")) == 1
        assert len(c.calls("-f")) == 4


def test_explicit_device_list_change_replaces_the_table(controller):
    """An explicit device list is configuration: changing it is a new policy,
    installed by the full delete, drain, check and install transaction."""
    c = controller
    with c.daemon():
        c.wait(c.ready)
        original = c.status()["policy_hash"]
        c.backend(entries=6, handle_refs=6, neighbour_refs=6)
        (c.root / "policy").write_text("enabled yes\ndevices eth3 eth4 eth5\nscope any\n")
        c.wait(lambda: following(c, ["eth3", "eth4", "eth5"]))
        status = c.status()
        assert status["policy_hash"] != original
        assert status["backend"]["entries"] == 0, status
        assert len(c.calls("delete")) == 1 and len(c.calls("--check")) == 2
        assert all(call["script"].startswith("table inet ask_flowtable") for call in c.calls("-f"))


def test_auto_below_two_ports_keeps_the_installed_table(controller):
    """With no table, fewer than two up ports install nothing and retry. Once
    a table stands, dropping below two keeps it as it is, with one notice and
    no retries; a different second port is then followed from that table. An
    unhealthy table is still never replaced by one that cannot forward."""
    c = controller
    (c.root / "policy").write_text(AUTO)
    c.ports("eth3")
    with c.daemon():
        c.wait(lambda: "deferred: fewer than two offload-capable ports are up" in c.log())
        assert not c.calls("-f") and not c.ready()
        c.ports("eth3", "eth4")
        c.wait(lambda: following(c, ["eth3", "eth4"]))
        c.backend(entries=6, handle_refs=6, neighbour_refs=6)
        deferred = c.log().count("deferred")
        c.ports("eth3")
        c.wait(lambda: "keeping the installed devices" in c.log())
        time.sleep(0.5)  # several more checks
        assert following(c, ["eth3", "eth4"]) and c.status()["backend"]["entries"] == 6
        assert c.log().count("keeping the installed devices") == 1, c.log()
        assert c.log().count("deferred") == deferred, c.log()
        assert len(c.calls("-f")) == 1 and not c.calls("delete")
        c.ports("eth3", "eth5")
        c.wait(lambda: following(c, ["eth3", "eth5"]))
        assert statements(c.calls("-f")[-1]) == [("add", ["eth5"]), ("delete", ["eth4"])]
        assert not c.calls("delete") and c.status()["backend"]["entries"] == 6
        c.ports("eth3")
        c.backend(invalidated=1)
        c.wait(lambda: c.log().count("deferred: fewer than two") > 1)
        assert not c.calls("delete") and sorted(c.status()["devices"]) == ["eth3", "eth5"]
        c.ports("eth3", "eth5")
        c.wait(lambda: following(c, ["eth3", "eth5"]))
        assert len(c.calls("delete")) == 1


def relist(c, name, listed):
    """Make nft list a device under another name than the one installed."""
    table = c.root / "table"
    table.write_text(table.read_text().replace(f'"{name}"', f'"{listed}"'))


def test_explicit_device_listed_under_its_primary_name_is_kept(controller):
    """nft accepts a device's alternative name and lists its primary one. An
    explicit list is identified by its hash, not by comparing names with the
    listing, which would replace such a table on every check."""
    c = controller
    with c.daemon():
        c.wait(c.ready)
        relist(c, "eth4", "wan0")
        time.sleep(0.5)  # several checks
        assert sorted(c.status()["devices"]) == ["eth3", "wan0"] and c.ready()
        assert len(c.calls("-f")) == 1 and not c.calls("delete")


def test_auto_listing_it_cannot_read_is_judged_by_bindings(controller):
    """A listing whose devices do not read back degrades to the binding count
    with one warning, never to a replacement on every check. A change in
    count is then all it can see, and the full transaction handles it."""
    c = controller
    (c.root / "policy").write_text(AUTO)
    with c.daemon():
        c.wait(lambda: following(c, ["eth3", "eth4"]))
        relist(c, "eth4", "e;h4")
        c.wait(lambda: "cannot read the installed flowtable's devices" in c.log())
        time.sleep(0.5)  # several checks
        assert c.status()["devices"] is None and c.ready()
        assert c.log().count("cannot read the installed flowtable's devices") == 1, c.log()
        assert len(c.calls("-f")) == 1 and not c.calls("delete")
        c.ports("eth3", "eth4", "eth5")
        c.wait(lambda: following(c, ["eth3", "eth4", "eth5"]))
        assert len(c.calls("delete")) == 1


@pytest.mark.parametrize("fault", ["fail-update", "short-bind"])
def test_failed_device_update_falls_back_to_replacement(controller, fault):
    """A device update that fails, or commits without the bindings it should
    have acquired, falls back to the full transaction in the same check. The
    replacement converges where retrying the update alone could not."""
    c = controller
    (c.root / "policy").write_text(AUTO)
    with c.daemon():
        c.wait(lambda: following(c, ["eth3", "eth4"]))
        original = c.status()["policy_hash"]
        (c.root / fault).touch()
        c.ports("eth3", "eth4", "eth5")
        c.wait(lambda: following(c, ["eth3", "eth4", "eth5"]))
        assert (c.root / "fault-consumed").exists()
        assert c.status()["policy_hash"] == original
        installs = c.calls("-f")
        assert [statements(call) for call in installs] == [[], [("add", ["eth5"])], []], installs
        assert installs[2]["script"].startswith("table inet ask_flowtable")
        assert len(c.calls("delete")) == 1
        assert "device update failed" in c.log()

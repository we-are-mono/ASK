"""Exercise the real controller, locks and daemon with a fake nft/kernel boundary."""

from ask_orch.process import run_process

from _host_flowtable_recovery import (AUTO, POLICY, following, relist, statements)
import json
import os
import subprocess
import threading
import time

import pytest


def test_quiet_network_retries_failed_apply(controller):
    c = controller
    (c.root / "fail-install").touch()
    with c.daemon():
        c.wait(lambda: (c.root / "fault-consumed").exists())
        c.wait(c.ready)
        assert len(c.calls("-f")) == 2


def test_platform_health_and_reboot_budget(controller):
    """The OS owns resets; ASK spends a persistent attempt once per boot."""
    c = controller
    c.run("health")
    c.backend(fatal=1, fatal_terminal=0)
    c.run("health")  # an in-place restart does not require a reboot
    c.backend(fatal_terminal=1)
    reason = c.root / "cdx/parameters/flowtable_terminal_reason"
    reason.parent.mkdir()
    reason.write_text("restart budget exhausted\n")
    # A terminal latch answers 2, which the monitor resets on at once.
    failed = c.run("health", check=False)
    assert failed.returncode == 2 and "restart budget exhausted" in failed.stderr
    (c.root / "backend").unlink()
    assert c.run("health", check=False).returncode == 2  # CDX still owns the latch
    reason.write_text("")
    c.run("health")  # deliberately unloaded ASK, ordinary Linux networking
    (c.root / "backend").write_text("fatal_terminal 0\n")
    assert c.run("health", check=False).returncode == 1
    (c.root / "backend").unlink()
    os.mkfifo(c.root / "backend")
    started = time.monotonic()
    failed = c.run("health", check=False)
    assert failed.returncode == 1 and "deadline" in failed.stderr
    assert time.monotonic() - started < 2
    reason.write_text("restart budget exhausted\n")

    # Both utilities share one stand-in environment. Script input must contain
    # only the ASK key; the firmware's rollback state must survive every update.
    for name in ("fw_printenv", "fw_setenv"):
        tool = c.root / name
        tool.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["FT_TEST_ROOT"])
if (root / "env-error").exists(): sys.exit(1)
path = root / "environment"
env = json.loads(path.read_text())
if pathlib.Path(sys.argv[0]).name == "fw_printenv":
    for key, value in env.items(): print(f"{key}={value}")
else:
    assert sys.argv[1] == "ask_recovery" and len(sys.argv) == 3
    env["ask_recovery"] = sys.argv[2]
    path.write_text(json.dumps(env))
    with (root / "env-writes").open("a") as out: out.write("write\\n")
''')
        tool.chmod(0o755)
    platform = {"bootcount": "2", "bootlimit": "3", "upgrade_available": "1", "slot": "b"}
    envfile = c.root / "environment"
    envfile.write_text(json.dumps(platform))
    for boot in range(1, 5):
        (c.root / "boot_id").write_text(f"00000000-0000-0000-0000-{boot:012d}\n")
        result = c.run("recovery-arm", check=False)
        assert result.returncode == (2 if boot == 4 else 0), result.stderr
        if boot < 4:
            writes = (c.root / "env-writes").read_text()
            c.run("recovery-arm")
            assert (c.root / "env-writes").read_text() == writes
            c.run("recovery-failed")
        record = json.loads(envfile.read_text())
        assert record["ask_recovery"].split(" ", 2)[0] == str(min(boot, 3))
        assert record["ask_recovery"].split(" ", 2)[2] == "restart budget exhausted"
        assert {key: record[key] for key in platform} == platform
    c.run("recovery-clear")
    writes = (c.root / "env-writes").read_text()
    c.run("recovery-clear")
    c.run("recovery-arm")
    assert (c.root / "env-writes").read_text() == writes
    record = json.loads(envfile.read_text())
    assert record["ask_recovery"].split(" ", 2)[0] == "0"
    for bad in ("-1", "4", "junk", ""):
        record["ask_recovery"] = bad + " " + record["ask_recovery"].split(" ", 1)[1]
        envfile.write_text(json.dumps(record))
        assert c.run("recovery-arm", check=False).returncode == 1
    (c.root / "env-error").touch()
    assert c.run("recovery-arm", check=False).returncode == 1


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
        run_process([str(c.root / "nft"), "delete", "table", "inet", "ask_flowtable"],
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
    (c.root / "paused").rmdir()
    assert c.ready()
    assert not c.calls("delete")


@pytest.mark.parametrize("name", ["lock", "paused", "daemon.lock", "control.lock", "service.lock"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "shared"])
def test_runtime_files_refuse_untrusted_objects(controller, name, kind):
    c = controller
    path = c.root / name
    victim = c.root / "victim"
    victim.write_text("untouched")
    victim.chmod(0o600)
    if kind == "symlink":
        path.symlink_to(victim)
    elif kind == "hardlink":
        os.link(victim, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "directory":
        path.mkdir()
    else:
        path.touch(mode=0o666)
        path.chmod(0o666)
    verbs = {"lock": ("status",), "paused": ("status", "stop", "resume"),
             "daemon.lock": ("daemon",), "control.lock": ("service-start",),
             "service.lock": ("supervise",)}
    for verb in verbs[name]:
        result = c.run(verb, check=False)
        assert result.returncode != 0, (verb, result)
    assert victim.read_text() == "untouched"
    assert not c.calls()


def test_runtime_directory_permissions_are_not_repaired(controller):
    c = controller
    c.root.chmod(0o777)
    try:
        result = c.run("status", check=False)
        assert result.returncode != 0 and "unsafe runtime directory" in result.stderr
        assert c.root.stat().st_mode & 0o777 == 0o777
        assert not c.calls()
    finally:
        c.root.chmod(0o700)


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

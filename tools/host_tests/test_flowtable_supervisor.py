"""Exercise the shipping supervisor and service controls with real processes."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

import pytest

from test_flowtable_recovery import controller  # noqa: F401


def service(c):
    return json.loads(c.run("service-status").stdout)


def worker(c):
    return service(c).get("worker_pid", 0)


@pytest.fixture
def running(controller):
    c = controller
    (c.root / "daemon.log").touch()
    c.env["ASAN_OPTIONS"] += ":log_path=" + str(c.root / "asan")
    c.env["UBSAN_OPTIONS"] += ":log_path=" + str(c.root / "ubsan")
    c.run("service-start")
    try:
        c.wait(c.ready)
        yield c
    finally:
        # Stop the lifecycle even if the test intentionally corrupted the
        # backend. A failed drain must not leave respawning test processes.
        c.run("service-stop", check=False)
        assert not service(c)["running"]
        assert not list(c.root.glob("asan.*"))
        assert not list(c.root.glob("ubsan.*"))


@pytest.mark.parametrize("point,installs", [("drain", 2), ("install", 3), ("commit", 2)])
def test_supervisor_recovers_transaction_crashes(running, point, installs):
    c = running
    before = service(c)
    original = c.status()["policy_hash"]
    (c.root / "crash-at").write_text(point)
    c.backend(invalidated=1)
    c.wait(lambda: (c.root / "crash-hit").exists())
    hit = json.loads((c.root / "crash-hit").read_text())
    assert hit["controller"] == before["worker_pid"] and hit["point"] == point
    c.wait(lambda: worker(c) not in (0, before["worker_pid"]))
    c.wait(c.ready)
    time.sleep(0.3)
    after = service(c)
    assert after["supervisor_pid"] == before["supervisor_pid"]
    assert after["restarts"] == 1
    assert c.status()["policy_hash"] == original
    assert len(c.calls("-f")) == installs
    assert len(c.calls("delete")) == 1
    assert all(not Path(f"/proc/{hit[k]}").exists() for k in ("controller", "worker", "guardian"))
    assert not (c.root / "late-writer").exists()


@pytest.mark.parametrize("sig", [signal.SIGKILL, signal.SIGTERM])
def test_worker_exit_including_zero_is_restarted(running, sig):
    c = running
    before = worker(c)
    os.kill(before, sig)
    c.wait(lambda: worker(c) not in (0, before))
    c.wait(c.ready)
    assert len(c.calls("-f")) == 1


def test_manual_pause_survives_worker_crash(running):
    c = running
    c.run("stop")
    before = worker(c)
    os.kill(before, signal.SIGKILL)
    c.wait(lambda: worker(c) not in (0, before))
    time.sleep(0.4)
    assert c.status()["reconciliation_paused"] and not c.ready()
    c.run("resume")
    c.wait(c.ready)


def test_service_stop_during_backoff_never_respawns(running):
    c = running
    before = service(c)
    os.kill(before["worker_pid"], signal.SIGKILL)
    c.wait(lambda: worker(c) == 0)
    c.run("service-stop")
    time.sleep(0.5)
    assert not service(c)["running"]
    assert not (c.root / "daemon.pid").exists()
    assert not (c.root / "supervisor.pid").exists()
    assert c.status()["reconciliation_paused"] and not c.ready()
    c.run("service-start")
    assert c.status()["reconciliation_paused"] and not c.ready()
    c.run("resume")
    c.wait(c.ready)


def test_duplicate_and_concurrent_starts_keep_one_worker(running):
    c = running
    before = service(c)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: c.run("service-start"), range(4)))
    assert all(r.returncode == 0 for r in results)
    after = service(c)
    assert before["worker_pid"] == after["worker_pid"]
    assert before["supervisor_pid"] == after["supervisor_pid"]
    assert len(c.calls("-f")) == 1


def test_concurrent_restart_preserves_newest_generation(running):
    c = running
    before = service(c)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: c.run("service-restart"), range(2)))
    c.wait(c.ready)
    after = service(c)
    assert after["supervisor_pid"] != before["supervisor_pid"]
    assert after["worker_pid"] != before["worker_pid"]
    assert int((c.root / "daemon.pid").read_text()) == after["worker_pid"]
    assert int((c.root / "supervisor.pid").read_text()) == after["supervisor_pid"]
    assert not c.status()["reconciliation_paused"]
    assert len(c.calls("-f")) == 1


def test_concurrent_stop_and_start_keep_maintenance_authority(running):
    c = running
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(c.run, ("service-start", "service-stop")))
    time.sleep(0.4)
    assert c.status()["reconciliation_paused"] and not c.ready()


def test_stale_pid_files_never_signal_unrelated_process(running):
    c = running
    with subprocess.Popen(["sleep", "10"]) as unrelated:
        try:
            for name in ("daemon.pid", "supervisor.pid"):
                (c.root / name).write_text(str(unrelated.pid))
            c.run("service-stop")
            assert unrelated.poll() is None
            c.run("service-start")
            c.run("resume")
            c.wait(c.ready)
            assert unrelated.poll() is None
        finally:
            unrelated.terminate()


def test_inactive_owner_suppresses_respawn_but_allows_stop(running):
    c = running
    (c.root / "owner").write_text("cmm\n")
    os.kill(worker(c), signal.SIGKILL)
    c.wait(lambda: worker(c) == 0)
    time.sleep(0.5)
    assert worker(c) == 0
    c.run("service-stop")
    assert not service(c)["running"]
    c.run("service-start")
    assert not service(c)["running"]


def test_crash_backoff_is_capped_and_resets_after_stable_run(running):
    c = running
    delays = []
    for _ in range(5):
        before = worker(c)
        started = time.monotonic()
        os.kill(before, signal.SIGKILL)
        c.wait(lambda: worker(c) not in (0, before))
        delays.append(time.monotonic() - started)
    assert delays[0] >= 0.05 and delays[1] >= 0.10
    assert all(0.21 <= value < 0.6 for value in delays[2:]), delays
    time.sleep(0.7)
    before = worker(c)
    started = time.monotonic()
    os.kill(before, signal.SIGKILL)
    c.wait(lambda: worker(c) not in (0, before))
    assert time.monotonic() - started < 0.22


def test_failed_stop_still_disables_supervision(running):
    c = running
    (c.root / "backend").write_text("incomplete\n")
    result = c.run("service-stop", check=False)
    assert result.returncode != 0 and "incomplete backend" in result.stderr
    assert not service(c)["running"]
    time.sleep(0.4)
    assert not service(c)["running"] and (c.root / "paused").exists()


def test_supervisor_death_cannot_orphan_worker(running):
    c = running
    before = service(c)
    os.kill(before["supervisor_pid"], signal.SIGKILL)
    c.wait(lambda: not Path(f"/proc/{before['worker_pid']}").exists())
    assert not service(c)["running"]
    c.run("service-start")
    c.wait(c.ready)
    assert worker(c) != before["worker_pid"]
    assert len(c.calls("-f")) == 1


def test_stalled_logger_cannot_block_restart(running):
    c = running
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as logger:
        logger.bind(str(c.root / "log.sock"))
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.setblocking(False)
            for _ in range(10000):
                try:
                    sender.sendto(b"fill", str(c.root / "log.sock"))
                except BlockingIOError:
                    break
            else:
                pytest.fail("failed to fill logger queue")
        before = worker(c)
        os.kill(before, signal.SIGKILL)
        c.wait(lambda: worker(c) not in (0, before))
        c.wait(c.ready)

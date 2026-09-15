"""Configuration validation and the hardware-drain transaction boundary."""
import copy
import json
import os
from pathlib import Path
import re
import signal
import shlex
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

import ask_flowtable as policy

BASE = {"version": 1, "enabled": True, "devices": ["eth3", "eth4"],
        "scope": [{"source": "192.0.2.0/24", "destination": "198.51.100.2"}],
        "exclude": [{"protocol": "tcp", "port": 21}]}


@pytest.mark.parametrize("change", [
    {"version": True}, {"version": 2}, {"enabled": 1}, {"devices": ["eth3", "eth3"]},
    {"devices": ["eth3; flush ruleset", "eth4"]}, {"scope": []}, {"extra": 1},
    {"exclude": [{}]}, {"scope": [{"source": "192.0.2.1/24"}]},
    {"scope": [{"source": "2001:db8::/32"}]}, {"exclude": [{"protocol": "icmp"}]},
    {"exclude": [{"port": True}]}, {"exclude": [{"port": 0}]},
    {"exclude": [{"port": {"min": 100, "max": 1}}]},
    {"exclude": [{"mark": {"value": 16, "mask": 15}}]},
    {"exclude": [{"name": "an accidental wildcard"}]},
])
def test_policy_rejects_invalid_configuration(change):
    with pytest.raises(policy.PolicyError):
        policy.validate({**copy.deepcopy(BASE), **change})


def test_policy_json_and_tuple_semantics(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"version": 1, "version": 2}')
    with pytest.raises(policy.PolicyError, match="duplicate JSON key"):
        policy.load_policy(path)
    path.write_bytes(b" " * 65537)
    with pytest.raises(policy.PolicyError, match="64 KiB"):
        policy.load_policy(path)
    candidate = copy.deepcopy(BASE)
    candidate["exclude"].append({"reply_destination": "203.0.113.4", "source_port": {"min": 1000, "max": 2000},
                                 "mark": {"value": 2, "mask": 3}})
    original = copy.deepcopy(candidate)
    rules = policy.render(candidate)
    for expression in ("ct original proto-src 21", "ct original proto-dst 21",
                       "ct reply proto-src 21", "ct reply proto-dst 21"):
        assert "meta l4proto tcp " + expression + " return" in rules
    assert "ct reply ip daddr 203.0.113.4/32 ct original proto-src 1000-2000 ct mark & 0x3 == 0x2 return" in rules
    assert "ct original ip saddr 192.0.2.0/24 ct original ip daddr 198.51.100.2/32 flow add @fast" in rules
    assert "ct status snat meta l4proto != udp return" in rules
    assert "ct status dnat return" in rules
    assert "counter" not in rules and "flush" not in rules
    assert policy.MARKER + policy.policy_hash(candidate) in rules
    assert candidate == original, "render mutated the candidate"


def resources(**values):
    return {"owner": "flowtable", "fatal": 0, "observe": 0, "invalidated": 0,
            **dict.fromkeys(policy.DRAIN_FIELDS, 0), **values}


class Backend(policy.Runtime):
    """Simulate asynchronous provider completion, never the policy algorithm."""
    def __init__(self):
        self.current = {"hash": "0" * 64}
        self.resources = resources(bindings=2, entries=2, handle_refs=2, neighbour_refs=2)
        self.pending = []
        self.calls = []
        self.failure = None

    def table(self):
        return self.current

    def state(self):
        if self.pending:
            self.resources = self.pending.pop(0)
        return copy.deepcopy(self.resources)

    def require_device(self, name):
        assert name in ("eth3", "eth4")

    def nft(self, *args, script=None):
        self.calls.append(args)
        if args[0] == "delete":
            self.current = None
            self.pending = [resources(entries=2, handle_refs=2, neighbour_refs=2, quarantine=1), resources()]
        else:
            assert all(self.resources[k] == 0 for k in policy.DRAIN_FIELDS), "publication preceded hardware drain"
            if args[0] == "--check":
                if self.failure == "check":
                    raise policy.PolicyError("kernel rejected candidate")
                self.pending = [resources(bindings=2), resources()]
            else:
                assert args == ("-f", "-")
                self.current = {"hash": re.search(policy.MARKER + r"([0-9a-f]{64})", script)[1]}
                self.resources = resources(bindings=2, invalidated=int(self.failure == "verify"))
                if self.failure == "install":
                    raise policy.PolicyError("transaction completion failed")
        return ""


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "LOCK", tmp_path / "policy.lock")
    monkeypatch.setattr(policy, "time", SimpleNamespace(monotonic=time.monotonic, sleep=lambda delay: None))
    return Backend()


def test_policy_apply_waits_for_both_drains(runtime):
    result = runtime.apply(BASE)
    assert result["enabled"] and result["policy_hash"] == policy.policy_hash(BASE)
    assert all(result["drained"][k] == 0 for k in policy.DRAIN_FIELDS)
    assert runtime.calls == [("delete", "table", "inet", policy.TABLE), ("--check", "-f", "-"), ("-f", "-")]
    assert runtime.lock_fd is None
    stopped = runtime.apply({**BASE, "enabled": False})
    assert not stopped["enabled"] and runtime.current is None
    assert all(stopped["drained"][k] == 0 for k in policy.DRAIN_FIELDS)


@pytest.mark.parametrize("failure", ["check", "install", "verify"])
def test_policy_failed_apply_leaves_hardware_drained(runtime, failure):
    runtime.failure = failure
    with pytest.raises(policy.PolicyError, match="acceleration disabled"):
        runtime.apply(BASE)
    assert runtime.current is None and not runtime.pending
    assert all(runtime.resources[k] == 0 for k in policy.DRAIN_FIELDS)
    assert runtime.lock_fd is None


def test_policy_refuses_foreign_owner_and_fatal_state(runtime):
    runtime.resources["fatal"] = 1
    with pytest.raises(policy.PolicyError, match="fresh boot"):
        runtime.apply(BASE)
    assert runtime.current and not runtime.calls
    runtime.resources["fatal"] = 0
    runtime.current = None
    with pytest.raises(policy.PolicyError, match="another flowtable"):
        runtime.apply(BASE)
    with pytest.raises(policy.PolicyError, match="another flowtable"):
        runtime.stop()
    assert not runtime.calls


def test_policy_does_not_delete_table_without_marker(monkeypatch):
    runtime = policy.Runtime()
    table = {"table": {"family": "inet", "name": policy.TABLE}}
    calls = []

    def nft(*args, **kwargs):
        calls.append(args)
        return json.dumps({"nftables": [table]})

    monkeypatch.setattr(runtime, "nft", nft)
    with pytest.raises(policy.PolicyError, match="ownership marker"):
        runtime.table()
    assert all(args[0] == "-j" for args in calls)


def test_policy_failed_retirement_never_publishes(runtime, monkeypatch):
    runtime.remove = lambda: runtime.drain(timeout=0)
    with pytest.raises(policy.PolicyError, match="have not drained"):
        runtime.apply(BASE)
    assert not runtime.calls and runtime.current
    runtime.resources["fatal"] = 1
    with pytest.raises(policy.PolicyError, match="retirement failed"):
        runtime.drain()


@pytest.mark.parametrize("owner,action,expected,rc", [
    ("cmm", "start", [], 0), ("", "start", [], 0),
    ("flowtable", "reload", ["apply"], 7),
    ("flowtable", "stop", ["stop"], 7),
    ("flowtable", "status", ["status"], 7),
])
def test_policy_boot_ownership_and_failure(tmp_path, owner, action, expected, rc):
    selection, calls, executable = (tmp_path / n for n in ("owner", "calls", "control"))
    selection.write_text(owner)
    calls.touch()
    executable.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> ' + shlex.quote(str(calls)) + '\nexit 7\n')
    executable.chmod(0o755)
    root = Path(__file__).resolve().parents[2]
    source = (root / "meta-ask/recipes-ask/config/files/S50ask-flowtable").read_text()
    script = tmp_path / "init"
    script.write_text(source.replace("/sys/module/cdx/parameters/offload_owner", shlex.quote(str(selection)))
                     .replace("/usr/sbin/ask-flowtable", shlex.quote(str(executable))))
    result = subprocess.run(["sh", str(script), action], capture_output=True, text=True, timeout=5)
    assert result.returncode == rc, result
    assert calls.read_text().splitlines() == expected


def test_policy_child_preserves_lease_after_controller_death(tmp_path, monkeypatch):
    lock, pidfile = tmp_path / "policy.lock", tmp_path / "child.pid"
    monkeypatch.setattr(policy, "LOCK", lock)
    fake = tmp_path / "nft"
    fake.write_text("#!/usr/bin/python3\nimport os,time,pathlib\n"
                    "target=pathlib.Path(os.environ['TEST_CHILD_PID']); temporary=target.with_suffix('.tmp')\n"
                    "temporary.write_text(str(os.getpid())); temporary.replace(target)\n"
                    "time.sleep(10)\n")
    fake.chmod(0o755)
    source = "import os,pathlib,ask_flowtable as p\np.LOCK=pathlib.Path(os.environ['TEST_LOCK'])\n"
    source += "r=p.Runtime()\nwith r.locked(): r.nft('--hold')\n"
    child = None
    controller = subprocess.Popen([sys.executable, "-c", source], env={
        **os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "PYTHONPATH": str(Path(policy.__file__).parent), "TEST_LOCK": str(lock), "TEST_CHILD_PID": str(pidfile),
    }, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 3
        while not pidfile.exists() or not pidfile.read_text():
            assert controller.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        child = os.pidfd_open(int(pidfile.read_text()))
        controller.kill()
        controller.wait(timeout=3)
        with pytest.raises(policy.PolicyError, match="holds the lock"):
            with policy.policy_lock(timeout=0.05):
                pytest.fail("orphaned nft transaction lost its lease")
        signal.pidfd_send_signal(child, signal.SIGTERM)
        os.close(child)
        child = None
        with policy.policy_lock(timeout=3):
            pass
    finally:
        if controller.poll() is None:
            controller.kill()
        controller.wait(timeout=3)
        if child is not None:
            try:
                signal.pidfd_send_signal(child, signal.SIGTERM)
            except ProcessLookupError:
                pass
            os.close(child)

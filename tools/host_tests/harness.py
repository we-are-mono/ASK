"""Failures in the harness must leave cleanup and reporting trustworthy."""

import asyncio
import base64
import errno
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest
from ask_orch.capture import verify_capture
from ask_orch.lifecycle import CleanupStack, bench_lock
from run_tests import command

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "harness_dmesg",
    ROOT / "tools/askd_agent/dmesg.py",
)
dmesg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dmesg)


async def test_ipv6_default_restoration_uses_seekable_snapshot(monkeypatch):
    import _topology as topology
    import subprocess

    saved = b"route snapshot"
    restored = []

    async def run(lan, cmd, timeout=10):
        assert cmd.startswith(("ip -6 route replace ", "ip -6 route del "))
        return SimpleNamespace(rc=0, stdout="")

    def restore(argv, *, stdin, **kwargs):
        assert argv == ["ip", "-6", "route", "restore"]
        assert stdin.seekable()
        assert stdin.tell() == 0
        restored.append(stdin.read())

    async def python(lan, script, *, label):
        if label == "save_ipv6_default":
            return SimpleNamespace(rc=0, stdout=base64.b64encode(saved).decode())
        exec(script, {})
        return SimpleNamespace(rc=0, stdout="")

    monkeypatch.setattr(topology, "lan_run", run)
    monkeypatch.setattr(topology, "lan_run_python", python)
    monkeypatch.setattr(subprocess, "run", restore)
    stack = CleanupStack()
    await topology.lan_ipv6_default(stack, object(), "fc00::1", "eth0")
    await stack.teardown()
    assert restored == [saved]


@pytest.mark.parametrize("prior_state", [None, "REACHABLE", "PERMANENT"])
@pytest.mark.parametrize("lost_reply", [False, True])
async def test_bridge_restores_lan_neighbour_after_cleanup_failure(monkeypatch, tmp_path, prior_state, lost_reply):
    import _flowtable_service_bridge as bridge

    gateway, old_mac, dut_mac = "192.0.2.1", "02:00:00:00:00:01", "02:00:00:00:00:02"
    old = [{"lladdr": old_mac, "state": [prior_state]}] if prior_state else []
    calls = []

    def execute(argv, **kwargs):
        calls.append(argv)
        if lost_reply and len(calls) == 2:
            raise RuntimeError("QGA outcome unknown")
        return SimpleNamespace(rc=0, stdout=json.dumps(old) if "show" in argv else "")

    async def command(agent, session, *argv, **kwargs):
        result = []
        if argv[:4] == ("ip", "-j", "link", "show"):
            result = [{"ifname": bridge.TARGET_LAN_IF}]
        elif argv[:5] == ("ip", "-j", "-4", "addr", "show"):
            result = [{"addr_info": [{"family": "inet", "local": gateway, "prefixlen": 24}]}]
        return {"rc": 0, "stdout": json.dumps(result)}

    async def state():
        return {"vlan_records": 0, "vlan_slots": 0, "errors": 0}

    def unavailable(**kwargs):
        raise RuntimeError("UART unavailable during cleanup")

    monkeypatch.setattr(bridge, "command", command)
    monkeypatch.setattr(bridge, "artifact_dir", lambda: tmp_path)
    monkeypatch.setattr(bridge.Console, "target", unavailable)
    rig = SimpleNamespace(target=object(), session=None, lan=SimpleNamespace(execute=execute),
                          lan_ip="192.0.2.2", lan_gateway=gateway, lan_mac=old_mac,
                          dut_lan_mac=dut_mac, state=state, record=lambda *args: None)
    with pytest.raises(RuntimeError, match="unknown|unavailable"):
        async with bridge.bridge_topology(rig, guest=False):
            assert calls[-1] == ["ip", "neigh", "replace", gateway, "lladdr", dut_mac,
                                 "nud", "permanent", "dev", bridge.LAN_NIC]
    expected = ["ip", "neigh", "del", gateway, "dev", bridge.LAN_NIC]
    if prior_state:
        expected = ["ip", "neigh", "replace", gateway, "lladdr", old_mac, "nud",
                    "permanent" if prior_state == "PERMANENT" else "stale", "dev", bridge.LAN_NIC]
    assert calls[-1] == expected


@pytest.mark.parametrize("inner", [False, True])
async def test_tagged_segment_owns_one_route(monkeypatch, inner):
    import _flowtable_vlan as vlan

    route_table = {}
    owned = []

    async def dut(stack, agent, session, *, parent, vid, **kwargs):
        return f"{parent}.{vid}"

    async def lan(stack, console, *, parent, vid, name=None, routes=(), **kwargs):
        iface = name or f"vlan{vid}"
        for spec in routes:
            prefix = spec.split()[0]
            owned.append(iface)
            route_table[prefix] = iface

            async def remove(prefix=prefix):
                del route_table[prefix]
            stack.push(remove)
        return iface

    async def link(*args, **kwargs):
        return SimpleNamespace(stdout='[{"address":"02:00:00:00:00:01"}]')

    async def read(*args):
        return "02:00:00:00:00:02"

    monkeypatch.setattr(vlan, "dut_vlan_subif", dut)
    monkeypatch.setattr(vlan, "lan_vlan_subif", lan)
    monkeypatch.setattr(vlan, "lan_run", link)
    monkeypatch.setattr(vlan, "read", read)
    r = SimpleNamespace(target=object(), session=object(), lan=object())
    stack = CleanupStack()
    await vlan._tagged_segment(r, stack, inner)
    assert owned == [r.lan_vlan_if]
    await stack.teardown()
    assert not route_table


@pytest.mark.parametrize("remaining", [errno.ENOENT, 0, errno.EACCES])
async def test_vlan_cleanup_only_accepts_a_confirmed_absent_device(remaining):
    from _topology import dut_vlan_subif

    class Target:
        async def exec_cmd(self, session, argv):
            return {"rc": 1 if argv[:3] == ["ip", "link", "del"] else 0,
                    "stderr": "delete failed"}

        async def fs_read(self, session, path):
            assert path == "/sys/class/net/eth3.244/ifindex"
            return {"errno": remaining}

    stack = CleanupStack()
    await dut_vlan_subif(stack, Target(), None, parent="eth3", vid=244)
    if remaining == errno.ENOENT:
        await stack.teardown()
    else:
        with pytest.raises(ExceptionGroup, match="restoration failed"):
            await stack.teardown()


async def test_profile_listener_releases_captured_command_pipes(monkeypatch, tmp_path):
    import socket
    import subprocess
    import sys
    import time
    import profile_homelab as profile

    async def local_python(ctx, client, source, **kwargs):
        result = await asyncio.to_thread(
            subprocess.run, [sys.executable, "-c", source],
            capture_output=True, text=True, timeout=2, check=True)
        return SimpleNamespace(rc=result.returncode, stdout=result.stdout)

    monkeypatch.setattr(profile, "_client_python", local_python)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    label = tmp_path.name
    path = Path(f"/tmp/ask_profile_home_echo_{label}_{port}.py")
    try:
        stop = await profile._udp_listener(None, {"ip": "127.0.0.1"}, port, label)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.05)
            deadline = time.monotonic() + 2
            while True:
                client.sendto(b"listener survived launcher", ("127.0.0.1", port))
                try:
                    data, peer = client.recvfrom(1024)
                    break
                except TimeoutError:
                    assert time.monotonic() < deadline, path.with_suffix(".py.log").read_text()
            assert (data, peer) == (b"listener survived launcher", ("127.0.0.1", port))
        await stop()
    finally:
        subprocess.run(["pkill", "-f", f"^python3 {path}$"], check=False)
        path.unlink(missing_ok=True)
        Path(str(path) + ".log").unlink(missing_ok=True)


def test_checkout_fingerprint_covers_uncommitted_inputs_and_excludes_ignored_files(tmp_path):
    import subprocess
    from ask_orch.provenance import checkout

    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, check=True)

    git("init", "-q")
    tracked = tmp_path / "source.py"
    tracked.write_text("original")
    (tmp_path / ".gitignore").write_text("private-token\n")
    git("add", "source.py", ".gitignore")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "fixture")
    first = checkout(tmp_path)
    (tmp_path / "private-token").write_text("ignored test fixture")
    assert checkout(tmp_path) == first
    hashes = [first["sha256"]]
    tracked.write_text("changed")
    hashes.append(checkout(tmp_path)["sha256"])
    added = tmp_path / "renamed.py"
    added.write_text("new source")
    hashes.append(checkout(tmp_path)["sha256"])
    added.write_text("changed new source")
    hashes.append(checkout(tmp_path)["sha256"])
    added.chmod(0o755)
    hashes.append(checkout(tmp_path)["sha256"])
    tracked.unlink()
    hashes.append(checkout(tmp_path)["sha256"])
    tracked.symlink_to("renamed.py")
    hashes.append(checkout(tmp_path)["sha256"])
    assert len(set(hashes)) == len(hashes)
    assert checkout(tmp_path)["revision"] == first["revision"]


def test_firmware_probe_reports_installed_sources_and_missing_tools():
    import os
    import subprocess
    import sys
    from ask_orch.provenance import agent_sources, firmware_script

    missing = "ask_test_nonexistent_binary_29fd"
    result = subprocess.run([sys.executable, "-c", firmware_script({"python3", missing})],
                            capture_output=True, text=True, check=True,
                            env={**os.environ, "PYTHONPATH": str(ROOT / "tools")})
    report = json.loads(result.stdout)
    assert report["agent_sources"] == agent_sources(ROOT / "tools/askd_agent")
    assert report["missing_binaries"] == [missing]
    assert len(report["binaries"]["python3"]["sha256"]) == 64
    assert report["kernel"]


@pytest.mark.parametrize("lost_reply", [False, True])
async def test_native_process_cleanup_owns_an_unacknowledged_launch(tmp_path, lost_reply):
    import subprocess
    import sys
    import time
    from _native_process import dut_process

    class Console:
        def python(self, source, timeout=20):
            result = subprocess.run([sys.executable, "-c", source],
                                    capture_output=True, text=True, timeout=timeout)
            if lost_reply and "print('launched')" in source:
                raise EOFError("launch response lost")
            return {"rc": result.returncode, "stdout": result.stdout + result.stderr}

    pidfile = tmp_path / "child.pid"
    source = ("import os,pathlib,time\n"
              f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
              "time.sleep(60)\n")
    stack = CleanupStack()
    try:
        launch = dut_process(stack, Console(), [sys.executable, "-c", source],
                             base=str(tmp_path / "owned"))
        if lost_reply:
            with pytest.raises(EOFError, match="launch response lost"):
                await launch
        else:
            await launch
        deadline = time.monotonic() + 2
        while not pidfile.exists():
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)
        pid = pidfile.read_text()
    finally:
        await stack.teardown()
    stat = Path(f"/proc/{pid}/stat")
    assert not stat.exists() or stat.read_text().split()[2] == "Z"


async def test_partial_setup_and_failed_undo_still_release_other_resources():
    stack = CleanupStack()
    released = []

    async def release(name, rc=0):
        released.append(name)
        return {"rc": rc}

    with pytest.raises(ExceptionGroup, match="restoration failed"):
        try:
            stack.push(lambda: release("first"))
            stack.push(lambda: release("second", 1))
            stack.push(lambda: release("third"))
            raise RuntimeError("setup failed before yield")
        finally:
            await stack.teardown()
    assert released == ["third", "second", "first"]
    await stack.teardown()
    assert released == ["third", "second", "first"]


async def test_cleanup_timeout_does_not_spend_the_next_cleanup_budget():
    stack = CleanupStack(timeout=0.01)
    finished = []

    async def release():
        finished.append(True)

    stack.push(release)
    stack.push(lambda: asyncio.sleep(10))
    with pytest.raises(ExceptionGroup):
        await stack.teardown()
    assert finished == [True]


async def test_pytest_failure_in_cleanup_does_not_skip_other_resources():
    stack = CleanupStack()
    released = []

    async def release():
        released.append(True)

    async def failure():
        pytest.fail("cleanup state did not converge")

    stack.push(release)
    stack.push(failure)
    with pytest.raises(ExceptionGroup):
        await stack.teardown()
    assert released == [True]


def test_overlapping_bench_reservations_are_refused_and_released(tmp_path):
    with bench_lock(["dut-a", "lan-shared"], tmp_path):
        with pytest.raises(RuntimeError, match="already in use"):
            with bench_lock(["dut-b", "lan-shared"], tmp_path):
                pytest.fail("overlapping run acquired the shared LAN")
    with bench_lock(["dut-a", "dut-b", "lan-shared"], tmp_path):
        pass


def test_old_run_artifacts_are_pruned(tmp_path, monkeypatch):
    from ask_orch import artifacts

    day = 86400
    now = 1_800_000_000
    runs = {}
    for age in (9, 8, 7, 6, 5, 4, 1, 0):
        run = tmp_path / f"2026100{9 - age}-120000-{age:02d}"
        (run / "case").mkdir(parents=True)
        os.utime(run, (now - age * day, now - age * day))
        runs[age] = run
    other = tmp_path / "notes"
    other.mkdir()
    os.utime(other, (now - 30 * day, now - 30 * day))
    monkeypatch.setattr(artifacts.time, "time", lambda: now)
    free = {"bytes": 1 << 40}
    monkeypatch.setattr(artifacts.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=free["bytes"]))

    # By age: older than three days goes, but the newest runs always stay.
    artifacts.prune_runs(tmp_path, keep_days=3, keep_runs=3, min_free=1 << 30)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [runs[4].name, runs[1].name, runs[0].name, "notes"])

    # By space: oldest first until enough is free, never the newest runs and
    # never a directory that is not a run.
    removed = []
    real_rmtree = artifacts.shutil.rmtree

    def rmtree(path, **kwargs):
        removed.append(Path(path).name)
        free["bytes"] = 1 << 40
        real_rmtree(path, **kwargs)

    free["bytes"] = 0
    monkeypatch.setattr(artifacts.shutil, "rmtree", rmtree)
    artifacts.prune_runs(tmp_path, keep_days=30, keep_runs=1, min_free=1 << 30)
    assert removed == [runs[4].name]
    free["bytes"] = 0
    artifacts.prune_runs(tmp_path, keep_days=30, keep_runs=2, min_free=1 << 30)
    assert removed == [runs[4].name]
    assert other.exists()


def test_failed_capture_seek_closes_descriptor(monkeypatch):
    closed = []
    monkeypatch.setattr(dmesg.os, "open", lambda *args: 42)

    def fail(*args):
        raise OSError(errno.EIO, "seek failed")

    monkeypatch.setattr(dmesg.os, "lseek", fail)
    monkeypatch.setattr(dmesg.os, "close", closed.append)
    with pytest.raises(OSError):
        dmesg.open_at_tail()
    assert closed == [42]


@pytest.mark.parametrize("failure", ["unavailable", "overrun", "gap", "lost-boot"])
def test_missing_kernel_evidence_cannot_pass(monkeypatch, failure):
    records = iter(
        [b"6,0,100,-;first\n", b"6,2,200,-;third\n"]
        if failure == "gap"
        else [b"6,9,100,-;old boot messages are gone\n"]
    )

    def read(*args):
        if failure == "overrun":
            raise OSError(errno.EPIPE, "ring wrapped")
        try:
            return next(records)
        except StopIteration:
            raise BlockingIOError

    monkeypatch.setattr(dmesg.os, "read", read)
    result = dmesg.drain(
        None if failure == "unavailable" else 42, boot=failure == "lost-boot"
    )
    result["splats"] = dmesg.has_splat(result["lines"])
    with pytest.raises(AssertionError, match="incomplete"):
        verify_capture(result, "example", [])


def test_boot_history_is_checked_for_splats(monkeypatch):
    records = iter([b"6,0,100,-;boot\n", b"3,1,200,-;BUG: KASAN: boot failure\n"])

    def read(*args):
        try:
            return next(records)
        except StopIteration:
            raise BlockingIOError

    monkeypatch.setattr(dmesg.os, "read", read)
    result = dmesg.drain(42, boot=True)
    result["splats"] = dmesg.has_splat(result["lines"])
    assert result["complete"]
    with pytest.raises(AssertionError, match="KASAN"):
        verify_capture(result, "boot", [])


def test_make_arguments_survive_sudo_as_literal_arguments(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    expression = "ipsec or (mcast and not slow)"
    argv, env = command(
        "dut",
        {
            "DUT_IP": "192.0.2.1",
            "WAN_IP": "192.0.2.2",
            "WAN_AGENT_IP": "127.0.0.1",
            "K": expression,
            "ASK_LAN_PASSWORD": "a password with 'quotes'",
            "ARGS": '--junitxml="/tmp/a report.xml"',
        },
        "/venv/python",
    )
    assert argv[:2] == ["sudo", "env"]
    assert "ASK_LAN_PASSWORD=a password with 'quotes'" in argv
    assert argv[argv.index("-k") + 1] == expression
    assert argv[-1] == "--junitxml=/tmp/a report.xml"
    assert env["ASK_TARGET_IP"] == "192.0.2.1"
    assert env["ASK_WAN_IPERF_IP"] == "192.0.2.2"
    assert env["ASK_WAN_IP"] == "127.0.0.1"
    # A full run collects every failure; stopping at the first is opt-in.
    assert "-x" not in argv
    host, _ = command("host", {}, "/venv/python")
    assert host[0] == "/venv/python" and "-x" not in host
    scoped, _ = command("dut", {"ARGS": "-x"}, "/venv/python")
    assert scoped[-1] == "-x"


def test_teardown_failure_quarantines_bench_and_keeps_junit(pytester, monkeypatch):
    artifacts = pytester.path / "artifacts"
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(artifacts))
    pytester.makeconftest("""
import pytest
pytest_plugins = ["ask_orch.pytest_plugin"]
@pytest.fixture(scope="session", autouse=True)
def hardware_bench():
    yield
@pytest.fixture
def broken_cleanup():
    yield
    raise RuntimeError("restoration failed")
""")
    cases = pytester.path / "tests"
    cases.mkdir()
    (cases / "test_example.py").write_text("""
def test_first(broken_cleanup):
    pass
def test_second():
    raise AssertionError("must not run on a dirty bench")
""")
    result = pytester.runpytest_subprocess("-v")
    result.assert_outcomes(passed=1, errors=1, skipped=1)
    (run,) = artifacts.iterdir()
    xml = ElementTree.parse(run / "junit.xml")
    assert xml.findall(".//error")
    reports = [json.loads(p.read_text()) for p in run.glob("*/teardown.json")]
    assert any(
        r["outcome"] == "failed" and "restoration failed" in r["failure"]
        for r in reports
    )
    result.stdout.fnmatch_lines(["*Artifacts:*"])


def test_group_selection_precedes_bench_validation_and_workers_share_artifacts(
    pytester, monkeypatch
):
    artifacts = pytester.path / "artifacts"
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(artifacts))
    for key in ("ASK_TARGET_IP", "ASK_TARGET_DEV", "ASK_LAN_VM", "ASK_LAN_NIC"):
        monkeypatch.delenv(key, raising=False)
    pytester.makeconftest('pytest_plugins = ["ask_orch.pytest_plugin"]')
    host = pytester.path / "host_tests"
    hardware = pytester.path / "tests"
    host.mkdir()
    hardware.mkdir()
    (host / "test_host.py").write_text("def test_one(): pass\ndef test_two(): pass\n")
    (hardware / "test_hardware.py").write_text(
        'def test_board(): raise AssertionError("must be deselected")\n'
    )
    result = pytester.runpytest_subprocess("-m", "host", "-n", "2")
    result.assert_outcomes(passed=2)
    (run,) = artifacts.iterdir()
    xml = ElementTree.parse(run / "junit.xml")
    assert len(xml.findall(".//testcase")) == 2
    assert len(list(run.glob("*/call.json"))) == 2


def test_unconfigured_bench_fails_before_test_body(pytester, monkeypatch):
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(pytester.path / "artifacts"))
    for key in ("ASK_TARGET_IP", "ASK_TARGET_DEV", "ASK_LAN_VM", "ASK_LAN_NIC"):
        monkeypatch.delenv(key, raising=False)
    pytester.makeconftest('pytest_plugins = ["ask_orch.pytest_plugin"]')
    tests = pytester.path / "tests"
    tests.mkdir()
    (tests / "test_board.py").write_text(
        'def test_board(): raise AssertionError("must not reach hardware")\n'
    )
    result = pytester.runpytest_subprocess("--tb=short")
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*missing bench settings:*ASK_LAN_VM*"])


@pytest.mark.parametrize("skipif", [False, True])
def test_release_rejects_selected_skips(pytester, monkeypatch, skipif):
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(pytester.path / "artifacts"))
    pytester.makeconftest("""
import pytest
pytest_plugins = ["ask_orch.pytest_plugin"]
@pytest.fixture(scope="session", autouse=True)
def hardware_bench():
    yield
""")
    pytester.makepyfile(f"""
import pytest
@pytest.mark.skipif({skipif!r}, reason="opt-in required")
def test_missing_capability():
    pytest.skip("firmware tool unavailable")
""")
    result = pytester.runpytest_subprocess("--release")
    result.assert_outcomes(failed=int(not skipif), errors=int(skipif))
    result.stdout.fnmatch_lines(["*release run cannot skip required coverage:*"])


def test_progress_column_shows_duration_and_count(pytester, monkeypatch):
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(pytester.path / "artifacts"))
    pytester.makeini("[pytest]\nconsole_output_style = count\n")
    pytester.makeconftest("""
import pytest
pytest_plugins = ["ask_orch.pytest_plugin"]
@pytest.fixture(scope="session", autouse=True)
def hardware_bench():
    yield
""")
    pytester.makepyfile("""
import time
def test_slow(): time.sleep(0.3)
def test_fast(): pass
""")
    result = pytester.runpytest_subprocess("-v")
    result.assert_outcomes(passed=2)
    result.stdout.re_match_lines([r".*::test_slow PASSED +0\.[3-9]s \[1/2\]$",
                                  r".*::test_fast PASSED +0\.0s \[2/2\]$"])


def test_module_order_is_reproducible_and_keeps_cases_together(pytester, monkeypatch):
    artifacts = pytester.path / "artifacts"
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(artifacts))
    pytester.makeconftest('pytest_plugins = ["ask_orch.pytest_plugin"]')
    for name in ("alpha", "beta", "gamma", "delta"):
        pytester.makepyfile(**{f"test_{name}": """
import pytest
@pytest.mark.parametrize('value', [2, 1])
def test_first(value): pass
def test_second(): pass
"""})

    def collect(seed):
        before = set(artifacts.glob("*/session-*/selection.json"))
        result = pytester.runpytest_subprocess("--collect-only", "-q",
                                              f"--module-order-seed={seed}")
        assert result.ret == 0
        created, = set(artifacts.glob("*/session-*/selection.json")) - before
        selection = json.loads(created.read_text())
        assert selection["module_order_seed"] == seed
        nodes = selection["nodeids"]
        assert len(nodes) == 12
        for offset in range(0, 12, 3):
            group = [node.split("::") for node in nodes[offset:offset + 3]]
            assert len({module for module, case in group}) == 1
            assert [case for module, case in group] == ["test_first[2]", "test_first[1]", "test_second"]
        return nodes

    assert collect(1) == collect(1)
    assert collect(1) != collect(2)


def test_bench_runs_draw_a_module_order_and_report_it(pytester, monkeypatch):
    artifacts = pytester.path / "artifacts"
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(artifacts))
    pytester.makeconftest('pytest_plugins = ["ask_orch.pytest_plugin"]')
    names = [f"test_m{n:02d}" for n in range(12)]
    for name in names:
        pytester.makepyfile(**{name: "def test_case(): pass\n"})
    host = pytester.mkdir("host_tests")
    for name in names:
        (host / f"{name}.py").write_text("def test_case(): pass\n")

    def collect(*args):
        before = set(artifacts.glob("*/session-*/selection.json"))
        result = pytester.runpytest_subprocess("--collect-only", "-q", *args)
        assert result.ret == 0
        created, = set(artifacts.glob("*/session-*/selection.json")) - before
        selection = json.loads(created.read_text())
        return result, selection["module_order_seed"], [n.split("::")[0][:-3] for n in selection["nodeids"]]

    # Outside host_tests a case is a bench case, and a bench run draws an order.
    result, seed, order = collect(*(f"{name}.py" for name in names))
    assert isinstance(seed, int) and sorted(order) == names
    result.stdout.fnmatch_lines([f"module order: seed {seed} (repeat with --module-order-seed={seed})"])
    assert collect(f"--module-order-seed={seed}", *(f"{name}.py" for name in names))[2] == order
    assert collect("--fixed-order", *(f"{name}.py" for name in names))[1:] == (None, names)
    # Host cases keep theirs: xdist workers must all collect the same one.
    assert collect("host_tests")[1:] == (None, [f"host_tests/{name}" for name in names])


@pytest.mark.parametrize("reported_failure", [False, True])
async def test_capture_collects_evidence_for_a_reported_test_failure(monkeypatch, tmp_path, reported_failure):
    # pytest reports a failed test before resuming yield fixtures; it does not
    # throw that assertion back through their context managers.
    from ask_orch.capture import capture_window
    collected = []
    released = []

    class Agent:
        async def capture_start(self, session):
            return "window"

        async def capture_stop(self, session, ident):
            return {"complete": True, "splats": [], "artifact": {"id": "evidence"}}

        async def artifact(self, session, ident):
            collected.append(ident)
            return b'{"lines":["diagnostic"]}'

        async def request(self, session, operation, body):
            released.append((operation, body["id"]))

    monkeypatch.setattr("ask_orch.capture.artifact_dir", lambda nodeid: tmp_path)
    monkeypatch.setattr("ask_orch.capture.record", lambda *args, **kwargs: None)
    async with capture_window(Agent(), None, "test", [], failed_check=lambda: reported_failure):
        pass
    assert bool(collected) is reported_failure
    assert (tmp_path / "kernel-log.json").exists() is reported_failure
    assert released == [("artifact/release", "evidence")]


async def test_kernel_window_drains_while_the_host_is_idle(monkeypatch):
    import threading
    observed = threading.Event()
    samples = iter([
        {"complete": True, "error": None, "cursor": 1, "lines": ["early"]},
        {"complete": False, "error": "sequence gap", "cursor": 3, "lines": ["later"]},
    ])

    def drain(fd, *, cursor):
        result = next(samples, {"complete": True, "error": None, "cursor": cursor, "lines": []})
        if result["cursor"] == 3:
            observed.set()
        return result

    monkeypatch.setattr(dmesg, "drain", drain)
    window = dmesg.Window(None)
    try:
        assert await asyncio.to_thread(observed.wait, 2)
    finally:
        result = await window.finish()
    assert result["lines"] == ["early", "later"]
    assert result["complete"] is False and result["error"] == "sequence gap"

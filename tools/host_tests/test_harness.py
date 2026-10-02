"""Failures in the harness must leave cleanup and reporting trustworthy."""

import asyncio
import errno
import importlib.util
import json
from pathlib import Path
from xml.etree import ElementTree

import pytest
from ask_orch.capture import verify_capture
from ask_orch.lifecycle import CleanupStack, bench_lock
from run_tests import command

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "harness_dmesg",
    ROOT / "meta-ask/recipes-support/ask-test-agent/files/askd_agent/dmesg.py",
)
dmesg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dmesg)


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
    host, _ = command("host", {}, "/venv/python")
    assert host[0] == "/venv/python" and "-x" not in host


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


def test_release_rejects_runtime_skip_despite_inactive_skipif(pytester, monkeypatch):
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(pytester.path / "artifacts"))
    pytester.makeconftest("""
import pytest
pytest_plugins = ["ask_orch.pytest_plugin"]
@pytest.fixture(scope="session", autouse=True)
def hardware_bench():
    yield
""")
    pytester.makepyfile("""
import pytest
@pytest.mark.skipif(False, reason="opt-in enabled")
def test_missing_capability():
    pytest.skip("firmware tool unavailable")
""")
    result = pytester.runpytest_subprocess("--release")
    result.assert_outcomes(failed=1)

"""A release is the matrix of runs it declares, each run exactly as declared,
on one checkout and one DUT image."""

import io
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ask_orch import release
from run_tests import command

FAKE = {
    "plain": release.Run("all", ("suite",)),
    "soak": release.Run("all", ("suite/test_soak.py",), {"ASK_SOAK": "1"}),
}
CONFTEST = '''
from pathlib import Path
import pytest
from ask_orch import release
from ask_orch.artifacts import record
release.TOOLS = Path(__file__).parent
release.MATRIX.clear()
release.MATRIX.update({
    "plain": release.Run("all", ("suite",)),
    "soak": release.Run("all", ("suite/test_soak.py",), {"ASK_SOAK": "1"}),
})
pytest_plugins = ["ask_orch.pytest_plugin"]

@pytest.fixture(scope="session", autouse=True)
def hardware_bench():
    record("dut", {"boot_id": "boot-1"}, nodeid="session")
    record("firmware", {"image": {"kernel_notes_sha256": "k", "modules_sha256": "m"}}, nodeid="session")
    yield
'''


@pytest.fixture
def bench(pytester, monkeypatch):
    for name in ("ASK_SOAK", "ASK_SOAK_FAILS", "ASK_FLOWTABLE_MIN_GBPS", "ASK_RELEASE_LEDGER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASK_TEST_ARTIFACTS", str(pytester.path / "artifacts"))
    pytester.makeconftest(CONFTEST)
    suite = pytester.mkdir("suite")
    (suite / "test_plain.py").write_text("def test_plain(): pass\n")
    (suite / "test_soak.py").write_text(
        "import os, pytest\n"
        "@pytest.mark.explicit('ASK_SOAK', '1', reason='soak')\n"
        "def test_soak(): assert os.environ.get('ASK_SOAK_FAILS') != '1'\n")
    return pytester


def ledger(pytester):
    return release.read(pytester.path / "artifacts" / "release-ledger.jsonl")


def test_each_run_lands_in_the_ledger_with_its_boot_and_image(bench, monkeypatch):
    bench.runpytest_subprocess("suite", "--release-run", "plain").assert_outcomes(passed=1, deselected=1)
    monkeypatch.setenv("ASK_SOAK", "1")
    monkeypatch.setenv("ASK_SOAK_FAILS", "1")
    bench.runpytest_subprocess("suite/test_soak.py", "--release-run", "soak").assert_outcomes(failed=1)
    bench.runpytest_subprocess("suite/test_soak.py", "--release-run", "soak", "--collect-only")
    plain, soak = ledger(bench)
    assert (plain["run"], plain["exitstatus"], plain["failed"], plain["selected"]) == ("plain", 0, [], 1)
    assert plain["boot_id"] == "boot-1"
    assert plain["image"] == {"kernel_notes_sha256": "k", "modules_sha256": "m"}
    assert (soak["run"], soak["exitstatus"], soak["failed"]) == ("soak", 1, ["suite/test_soak.py::test_soak"])
    assert plain["started"] <= plain["finished"] <= soak["started"]
    assert Path(plain["run_dir"]).is_dir()


@pytest.mark.parametrize("args, environ, refusal", [
    (["-k", "plain"], {}, "narrows the selection with keyword"),
    (["--deselect", "suite/test_plain.py::test_plain"], {}, "narrows the selection with deselect"),
    (["suite/test_plain.py"], {}, "selects ['suite', 'suite/test_plain.py']"),
    ([], {"ASK_SOAK": "1"}, "needs ASK_SOAK=(unset)"),
    ([], {"ASK_FLOWTABLE_MIN_GBPS": "1"}, "ASK_FLOWTABLE_MIN_GBPS unset"),
])
def test_a_run_other_than_declared_is_refused_and_not_recorded(bench, monkeypatch, args, environ, refusal):
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    result = bench.runpytest_subprocess("suite", "--release-run", "plain", *args)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    assert refusal in result.stderr.str()
    assert ledger(bench) == []


def test_an_explicit_case_no_entry_runs_refuses_the_run(bench):
    (bench.path / "suite" / "test_orphan.py").write_text(
        "import pytest\n"
        "@pytest.mark.explicit('ASK_ORPHAN', '1', reason='orphan')\n"
        "def test_orphan(): pass\n")
    result = bench.runpytest_subprocess("suite", "--release-run", "plain")
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*leaves out suite/test_orphan.py::test_orphan, which no other entry runs*"])


def test_nothing_in_a_session_uses_the_boot_a_destructive_case_ended(bench):
    (bench.path / "suite" / "test_plain.py").write_text(
        "import pytest\n"
        "@pytest.mark.destructive\n"
        "def test_ends(): pass\n"
        "def test_after(): pass\n")
    result = bench.runpytest_subprocess("suite/test_plain.py", "-rs")
    result.assert_outcomes(passed=1, skipped=1)
    result.stdout.fnmatch_lines(["*bench requires recovery: suite/test_plain.py::test_ends*"])


def _entry(run, exitstatus=0, image="a", finished=1.0):
    return {"run": run, "checkout": "c", "exitstatus": exitstatus, "finished": finished,
            "image": {"kernel_notes_sha256": image, "modules_sha256": image},
            "boot_id": "b", "run_dir": "/r", "failed": [] if exitstatus == 0 else ["x::y"]}


def test_status_needs_every_entry_passed_on_one_image(monkeypatch):
    monkeypatch.setattr(release, "MATRIX", dict(FAKE))
    source = {"sha256": "c", "revision": "r" * 40}
    states = lambda entries: {row["run"]: row["state"] for row in release.status(entries, source)}
    assert states([]) == {"plain": "missing", "soak": "missing"}
    assert states([_entry("plain"), _entry("soak", 1)]) == {"plain": "passed", "soak": "failed"}
    # The latest run of an entry is the one that counts.
    assert states([_entry("plain"), _entry("soak", 1), _entry("soak", finished=2.0)])["soak"] == "passed"
    assert states([_entry("plain"), _entry("soak", image="b")])["soak"] == "other image"
    other = dict(_entry("soak"), checkout="d")
    assert states([_entry("plain"), other])["soak"] == "missing"
    out = io.StringIO()
    assert release.report(release.status([_entry("plain"), _entry("soak")], source), source, "ledger", out)
    assert out.getvalue().endswith("release qualified: 2 of 2 runs passed\n")
    out = io.StringIO()
    assert not release.report(release.status([_entry("plain")], source), source, "ledger", out)
    assert "  soak   missing    make test-release RUN=soak  (on the staged test image)\n" in out.getvalue()


def test_uncovered_explicit_cases_and_gate_overrides(monkeypatch):
    monkeypatch.setattr(release, "MATRIX", dict(FAKE))
    monkeypatch.setattr(release, "WAIVED", {"suite/test_diag.py::test_diag": "diagnostic"})
    case = lambda nodeid, variable="ASK_SOAK", values=("1",): {
        "nodeid": nodeid, "variable": variable, "values": list(values)}
    assert release.uncovered("plain", [case("suite/test_soak.py::test_soak"),
                                       case("suite/test_soak.py::test_soak[x]"),
                                       case("suite/test_diag.py::test_diag", "ASK_DIAG")]) == []
    assert release.uncovered("plain", [case("suite/test_other.py::test_soak"),
                                       case("suite/test_soak.py::test_soak", values=("2",))]) == [
        "suite/test_other.py::test_soak", "suite/test_soak.py::test_soak"]
    assert release.overrides({"ASK_FLOWTABLE_MIN_GBPS": "1", "ASK_PROFILE_ISP_MIN_GBPS6": "1",
                              "ASK_REGEN_ABI_SNAPSHOT": "1", "ASK_WAN_IP": "x"}) == [
        "ASK_FLOWTABLE_MIN_GBPS", "ASK_PROFILE_ISP_MIN_GBPS6", "ASK_REGEN_ABI_SNAPSHOT"]


def test_make_runs_one_entry_with_only_its_settings(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    argv, env = command("release", {"RUN": "terminal-budget", "ASK_FLOWTABLE_CHURN": "1",
                                    "ASK_FLOWTABLE_TERMINAL": "unload", "ARGS": "-x"}, "/venv/python")
    assert argv[argv.index("--release-run") + 1] == "terminal-budget"
    assert [arg for arg in argv if "::" in arg] == [
        str(release.TOOLS / "tests/flowtable_offload.py::test_terminal")]
    assert env["ASK_FLOWTABLE_TERMINAL"] == "budget" and "ASK_FLOWTABLE_CHURN" not in env
    assert argv[-1] == "-x"
    with pytest.raises(SystemExit, match="drop K"):
        command("release", {"RUN": "suite", "K": "ipsec"})
    with pytest.raises(SystemExit, match="RUN names one release run"):
        command("release", {})


@pytest.mark.parametrize("run", sorted(release.MATRIX))
def test_every_entry_selects_cases_in_this_tree(run, tmp_path, monkeypatch):
    """Each declared run collects, passes its own release checks, and selects
    cases: a renamed test or a new explicit case without an entry fails here
    rather than on the bench."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    environ = {key: value for key, value in os.environ.items()
               if not key.startswith("ASK_") and key not in {"K", "ARGS", "RUN"}}
    environ.update(RUN=run, ASK_TEST_ARTIFACTS=str(tmp_path))
    argv, env = command("release", environ, sys.executable)
    result = subprocess.run(argv + ["--collect-only", "-q", "-p", "no:cacheprovider"],
                            env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    selected = int(re.search(r"(\d+)(?:/\d+)? tests? collected", result.stdout).group(1))
    assert selected > 0
    assert not (tmp_path / "release-ledger.jsonl").exists()

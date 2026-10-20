"""Compile the devlink policer registration against the profiles it reports.

Run without the board fixtures:
    pytest tools/host_tests/devlink_policer.py
"""

from ask_orch.process import run_process

import os
import shutil
from pathlib import Path

import pytest

from _host_policer import ROOT, function, policer_layer


def body(source: str, name: str) -> str:
    """The text of one function's body, for asserting the order of its calls."""
    lifted = function(source, name)
    return lifted[lifted.index("{"):]


# Registration and the verbs, then a set whose write does not land on each
# policer, then the drop counts across failed reads and rewrites; each in a
# process of its own.
CASES = ["verbs", "sec_deferred", "punt_deferred", "counters"]


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    tmp_path = tmp_path_factory.mktemp("devlink_policer")
    policer_layer(tmp_path)
    devlink = (ROOT / "cdx/cdx_devlink.c").read_text()
    (tmp_path / "devlink_policer_production.inc").write_text(
        devlink[devlink.index("/* The punt policer."):])
    binary = tmp_path / "devlink_policer"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-Wno-unused-function", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-Werror=implicit-function-declaration",
        "-I", str(tmp_path), "-I", str(ROOT / "cdx"), "-I", str(Path(__file__).parent),
        str(Path(__file__).with_name("devlink_policer.c")), "-o", str(binary),
    ], check=True)
    return binary


@pytest.mark.parametrize("case", CASES)
def test_devlink_policer(binary, case):
    result = run_process([str(binary), case], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"devlink policers {case}: passed" in result.stdout


def test_lifetime_follows_the_profiles():
    """The instance is registered once the profiles it reports exist, and goes
    before they are released. cdx_startup.c drives the same order through
    every fault point; this pins where the calls sit, so an attach moved back
    ahead of the profiles fails here by name."""
    cfg = (ROOT / "cdx/dpa_cfg.c").read_text()
    setup = body(cfg, "dpa_cfg_install")
    attach = setup.index("cdx_devlink_attach(")
    assert setup.index("cdxdrv_create_missaction_policer_profiles(") < attach
    assert setup.index("cdxdrv_create_ingress_qos_policer_profiles(") < attach
    rollback = body(cfg, "dpa_rollback_resources")
    detach = rollback.index("cdx_devlink_detach();")
    assert detach < rollback.index("dpa_release_pcd_fqs();")
    assert detach < rollback.index("cdxdrv_release_shared_policers(")
    # Nothing registers it from an interface coming up any more: that ran
    # before either profile existed.
    control = (ROOT / "cdx/control_qm.c").read_text()
    assert "cdx_devlink_attach(" not in body(control, "cdx_enable_ceetm_on_iface")

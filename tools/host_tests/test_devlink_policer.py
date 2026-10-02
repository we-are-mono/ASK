"""Compile the devlink policer registration against the profiles it reports.

Run without the board fixtures:
    pytest tools/host_tests/test_devlink_policer.py
"""

from ask_orch.process import run_process

import os
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def function(source: str, name: str) -> str:
    """Lift one function definition out of a production source file."""
    # The line has to begin with a return type, not with the ` * ' of a comment
    # continuation: a comment naming `foo()' above the definition of foo would
    # otherwise be lifted instead.
    match = re.search(rf"^(?:static\s+)?\w[\w \*]*\b{name}\(", source, re.M)
    assert match, name
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def body(source: str, name: str) -> str:
    """The text of one function's body, for asserting the order of its calls."""
    lifted = function(source, name)
    return lifted[lifted.index("{"):]


def test_devlink_policer(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    qos = (ROOT / "cdx/cdx_qos.c").read_text()
    cfg = (ROOT / "cdx/dpa_cfg.c").read_text()
    module_qm = (ROOT / "cdx/module_qm.h").read_text()
    devlink = (ROOT / "cdx/cdx_devlink.c").read_text()
    (tmp_path / "devlink_policer_profiles.inc").write_text(
        cfg[cfg.index("#define CDX_EXPT_ETH_DEFA_LIMIT"):
            cfg.index("static void dpa_cfg_set_expt_defaults")]
        + function(cfg, "dpa_cfg_set_expt_defaults")
        # The profiles cdx creates and modifies from them, with the defaults
        # the SEC profile is created with.
        + "\n".join(re.findall(r"^#define DEFAULT_INGRESS_BYTE_MODE_[CP]BS\s.*$",
                               module_qm, re.M)) + "\n"
        + qos[qos.index("#define DEFAULT_INGRESS_CIR_VALUE"):
              qos.index("uint32_t port_ff_lim_mode")]
        + "".join(function(qos, name) for name in [
            "cdxdrv_modify_missaction_policer_profile",
            "cdxdrv_create_missaction_policer_profiles",
            "cdxdrv_create_ingress_qos_policer_profiles",
            "cdxdrv_modify_ingress_qos_policer_profile",
            "cdxdrv_set_default_qos_policer_profile",
            "cdxdrv_enable_or_disable_ingress_policer"])
        # And the accessors the registration reads them back through.
        + "".join(function(cfg, name) for name in [
            "cdx_expt_rate_is_packet_mode", "cdx_expt_rate_config",
            "cdx_set_expt_rate", "cdx_ingress_enable_or_disable_qos",
            "cdx_ingress_policer_modify_config", "cdx_ingress_policer_peak"]))
    (tmp_path / "devlink_policer_production.inc").write_text(
        devlink[devlink.index("/* The punt policer."):])
    binary = tmp_path / "devlink_policer"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-Wno-unused-function", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-Werror=implicit-function-declaration",
        "-I", str(tmp_path), "-I", str(ROOT / "cdx"),
        str(Path(__file__).with_name("devlink_policer.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "devlink policers" in result.stdout


def test_devlink_policer_lifetime_follows_the_profiles():
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

"""Exercise boot ownership selection using the installed module-loader script."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("cmdline,fail,expected,rc", [
    ("", "", ["cdx offload_owner=cmm flowtable_observe=0", "fci", "auto_bridge"], 0),
    ("ask.offload=flowtable", "", ["cdx offload_owner=flowtable flowtable_observe=0", "ask_flowtable"], 0),
    ("ask.offload=flowtable ask.flowtable_observe=1", "", ["cdx offload_owner=flowtable flowtable_observe=1", "ask_flowtable"], 0),
    ("ask.offload=flowtable", "ask_flowtable", ["cdx offload_owner=flowtable flowtable_observe=0", "ask_flowtable"], 1),
    ("ask.offload=flowtable", "cdx", ["cdx offload_owner=flowtable flowtable_observe=0"], 1),
    ("ask.offload=invalid", "", [], 1),
])
def test_flowtable_boot_modules(tmp_path, cmdline, fail, expected, rc):
    conf, boot, log = (tmp_path / name for name in ("modules", "cmdline", "calls"))
    conf.write_text("# dependencies first\n\ncdx\nfci\nauto_bridge\n")
    boot.write_text(cmdline + "\n")
    log.touch()
    probe = tmp_path / "modprobe"
    probe.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n[ "$1" != "$FAIL" ]\n')
    probe.chmod(0o755)
    source = (ROOT / "meta-ask/recipes-ask/config/files/S05ask-modules").read_text()
    script = tmp_path / "loader"
    script.write_text(source.replace("CONF=/etc/modules-load.d/ask.conf", "CONF=" + shlex.quote(str(conf)))
                      .replace("cat /proc/cmdline", "cat " + shlex.quote(str(boot))))
    result = subprocess.run(["sh", str(script), "start"], capture_output=True, text=True,
                            env={**os.environ, "PATH": str(tmp_path) + ":" + os.environ["PATH"],
                                 "CALLS": str(log), "FAIL": fail}, timeout=5)
    assert result.returncode == rc, result
    assert log.read_text().splitlines() == expected

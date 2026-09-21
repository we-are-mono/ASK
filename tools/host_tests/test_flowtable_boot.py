"""Exercise boot ownership selection using the installed module-loader script."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("cmdline,fail,expected,rc", [
    ("", "", ["cdx offload_owner=cmm flowtable_observe=0 ask_debug=1", "fci", "auto_bridge"], 0),
    ("ask.offload=flowtable", "", ["cdx offload_owner=flowtable flowtable_observe=0 ask_debug=1", "ask_flowtable"], 0),
    ("ask.offload=flowtable ask.flowtable_observe=1", "", ["cdx offload_owner=flowtable flowtable_observe=1 ask_debug=1", "ask_flowtable"], 0),
    ("ask.offload=flowtable ask.debug=0", "", ["cdx offload_owner=flowtable flowtable_observe=0 ask_debug=0", "ask_flowtable"], 0),
    ("ask.offload=flowtable", "ask_flowtable", ["cdx offload_owner=flowtable flowtable_observe=0 ask_debug=1", "ask_flowtable"], 1),
    ("ask.offload=flowtable", "cdx", ["cdx offload_owner=flowtable flowtable_observe=0 ask_debug=1"], 1),
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


@pytest.mark.parametrize("verb,stop_rc,expected,rc", [
    ("stop", 42, ["service-stop"], 42),
    ("stop", 0, ["service-stop"], 0),
    ("restart", 0, ["service-restart"], 0),
    ("reload", 0, ["resume", "service-start"], 0),
])
def test_flowtable_service_preserves_authority_and_stop_errors(tmp_path, verb, stop_rc, expected, rc):
    log, owner = tmp_path / "calls", tmp_path / "owner"
    owner.write_text("flowtable\n")
    daemon = tmp_path / "daemon"
    daemon.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$CALLS"\n'
                      'if [ "$1" = service-stop ]; then exit "$STOP_RC"; fi\n')
    daemon.chmod(0o755)
    service = tmp_path / "service"
    text = (ROOT / "meta-ask/recipes-ask/config/files/S50ask-flowtable").read_text()
    text = text.replace("/sys/module/cdx/parameters/offload_owner", str(owner))
    text = text.replace("DAEMON=/usr/sbin/ask-flowtable", "DAEMON=" + shlex.quote(str(daemon)))
    text = text.replace("PIDFILE=/var/run/ask-flowtable.pid", "PIDFILE=" + shlex.quote(str(tmp_path / "pid")))
    service.write_text(text)
    service.chmod(0o755)
    starter = tmp_path / "start-stop-daemon"
    starter.write_text("#!/bin/sh\nexit 0\n")
    starter.chmod(0o755)
    result = subprocess.run([str(service), verb], capture_output=True, text=True,
                            env={**os.environ, "PATH": str(tmp_path) + ":" + os.environ["PATH"],
                                 "CALLS": str(log), "STOP_RC": str(stop_rc)}, timeout=5)
    assert result.returncode == rc, result
    assert (log.read_text().splitlines() if log.exists() else []) == expected

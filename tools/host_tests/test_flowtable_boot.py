"""Exercise the installed module-loader and flowtable service scripts."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


LOADED = ["cdx flowtable_observe=0 ask_debug=1", "ask_flowtable", "nf_conntrack"]


@pytest.mark.parametrize("cmdline,fail,expected,rc", [
    ("", "", LOADED, 0),
    # The retired owner switch may linger in a boot environment; it selects nothing.
    ("ask.offload=cmm", "", LOADED, 0),
    ("ask.flowtable_observe=1", "", ["cdx flowtable_observe=1 ask_debug=1", *LOADED[1:]], 0),
    ("ask.debug=0", "", ["cdx flowtable_observe=0 ask_debug=0", *LOADED[1:]], 0),
    ("", "ask_flowtable", LOADED[:2], 1),
    ("", "cdx", LOADED[:1], 1),
    ("ask.flowtable_observe=2", "", [], 1),
])
def test_flowtable_boot_modules(tmp_path, cmdline, fail, expected, rc):
    conf, boot, log = (tmp_path / name for name in ("modules", "cmdline", "calls"))
    conf.write_text("# dependencies first\n\ncdx\nnf_conntrack\n")
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
    log = tmp_path / "calls"
    daemon = tmp_path / "daemon"
    daemon.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$CALLS"\n'
                      'if [ "$1" = service-stop ]; then exit "$STOP_RC"; fi\n')
    daemon.chmod(0o755)
    service = tmp_path / "service"
    text = (ROOT / "meta-ask/recipes-ask/config/files/S50ask-flowtable").read_text()
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

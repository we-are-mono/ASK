"""Exercise the shipped platform hooks without changing a host watchdog."""

from ask_orch.process import run_process
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_platform_recovery_hooks(tmp_path):
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "TEST_ROOT": str(tmp_path)}
    log = tmp_path / "calls"
    uptime = tmp_path / "uptime"
    scripts = {
        "ask-flowtable": '''#!/bin/sh
echo "ask $*" >> "$TEST_ROOT/calls"
case "$1" in
 health)
  # One status per probe from HEALTH_SEQ, the last repeated; the first
  # probe moves the clock past the hour the budget clear waits for.
  n=$(($(cat "$TEST_ROOT/probed" 2>/dev/null || echo 0) + 1))
  echo "$n" > "$TEST_ROOT/probed"
  echo '3601.0 0.0' > "$TEST_ROOT/uptime"
  set -- ${HEALTH_SEQ:-0 1}
  [ "$n" -le "$#" ] && i=$n || i=$#
  eval "exit \\${$i}" ;;
 recovery-arm) exit "${ARM_STATUS:-0}" ;;
 recovery-clean) exit "${CLEAN_STATUS:-0}" ;;
esac
''',
        "systemd-notify": '#!/bin/sh\necho "notify $*" >> "$TEST_ROOT/calls"\n',
        "ubus": '''#!/bin/sh
echo "ubus $*" >> "$TEST_ROOT/calls"
case "$*" in *'"stop":false'*) echo "${WDT_START_STATUS:-offline}"; exit 0 ;; esac
echo "${WDT_STATUS:-running}"
''',
        "jsonfilter": '#!/bin/sh\ncat\n',
        "logger": '#!/bin/sh\necho "log $*" >> "$TEST_ROOT/calls"\n',
        "sleep": '#!/bin/sh\n[ "$1" = 5 ]\n',
        "reboot": '#!/bin/sh\necho unexpected-reboot >> "$TEST_ROOT/calls"\nexit 1\n',
    }
    for name, body in scripts.items():
        path = tmp_path / name
        path.write_text(body)
        path.chmod(0o755)
    monitor = tmp_path / "monitor"
    monitor.write_text((ROOT / "integration/ask-recovery-monitor").read_text().replace(
        "/proc/uptime", str(uptime)))
    def monitor_run(platform, sequence):
        uptime.write_text("0.0 0.0\n")
        (tmp_path / "probed").unlink(missing_ok=True)
        log.write_text("")
        result = run_process(["sh", str(monitor), platform], env={**env, "HEALTH_SEQ": sequence},
                             capture_output=True, timeout=5)
        return result, log.read_text()

    for platform in ("systemd", "openwrt"):
        # A failing datapath resets on its third consecutive miss, having
        # fed the watchdog through the first two.
        result, calls = monitor_run(platform, "0 1")
        assert result.returncode == 1, result.stderr
        assert calls.count("ask health") == 4 and calls.count("ask recovery-clear") == 1, calls
        assert calls.count("health check failed") == 2 and "unexpected-reboot" not in calls
        # A terminal latch resets on the probe that reports it.
        result, terminal = monitor_run(platform, "0 2")
        assert result.returncode == 1 and terminal.count("ask health") == 2, terminal
        assert "health check failed" not in terminal
        # Misses that a successful probe interrupts are forgiven, and the
        # budget is cleared only on a successful probe.
        result, recovered = monitor_run(platform, "1 1 0 1 1 2")
        assert result.returncode == 1 and recovered.count("ask health") == 6, recovered
        assert recovered.count("health check failed") == 4
        assert recovered.count("ask recovery-clear") == 1
        lines = recovered.splitlines()
        cleared = lines.index("ask recovery-clear")
        assert sum(line == "ask health" for line in lines[:cleared]) == 3, recovered
        if platform == "systemd":
            assert "notify --ready WATCHDOG=1" in calls
            assert "ask recovery-failed" not in calls  # native OnFailure unit owns it
        else:
            assert '"magicclose":false,"stop":true' in calls
            assert "ask recovery-failed" in calls

    # Model rc.common's discarded start_service status: service_started must
    # still reject unavailable watchdogs and an exhausted recovery budget.
    init = ROOT / "integration/openwrt/ask-recovery"
    wrapper = f'''
. '{init}'
procd_open_instance() {{ echo "instance opened $1" >> "$TEST_ROOT/calls"; }}
procd_set_param() {{ echo "param $*" >> "$TEST_ROOT/calls"; }}
procd_close_instance() {{ :; }}
service_running() {{ return 0; }}
start_service
true
service_started
'''
    for status, arm, start, allowed in [("running", "0", "offline", True), ("running", "2", "offline", False),
                                       ("offline", "0", "offline", False), ("offline", "0", "running", True)]:
        log.write_text("")
        state = tmp_path / "state"
        result = run_process(["sh", "-c", wrapper],
                                env={**env, "WDT_STATUS": status, "ARM_STATUS": arm, "WDT_START_STATUS": start,
                                     "ASK_RECOVERY_STATE": str(state)},
                                capture_output=True, timeout=5)
        assert (result.returncode == 0) == allowed, result.stderr
        assert ("instance opened monitor" in log.read_text()) == allowed
        # A spent budget schedules its one retry, a day out, and says so;
        # nothing else does.
        exhausted = status == "running" and arm == "2"
        assert ("instance opened retry" in log.read_text()) == exhausted
        if exhausted:
            assert "sleep 86400 && { ask-flowtable recovery-retry ||" in log.read_text()
        expected = "armed" if allowed else "exhausted" if exhausted else "unavailable"
        assert state.read_text().strip() == expected
        if status == "running":
            assert '"stop":false' not in log.read_text()
    # "armed" waits for the monitor procd runs: none running, none claimed.
    log.write_text("")
    state = tmp_path / "state"
    result = run_process(["sh", "-c", wrapper.replace("service_running() {{ return 0; }}".replace("{{", "{").replace("}}", "}"),
                                                      "service_running() { return 1; }")],
                         env={**env, "ASK_RECOVERY_STATE": str(state)}, capture_output=True, timeout=5)
    assert result.returncode != 0 and state.read_text().strip() == "unavailable", state.read_text()

    # Only a shutdown refunds, and only of a datapath that still passes its
    # health check; a plain stop or restart writes nothing. A refund that
    # fails is logged.
    for action, health, refunded in [("shutdown", "0", True), ("shutdown", "1", False),
                                     ("stop", "0", False), ("restart", "0", False)]:
        log.write_text("")
        state = tmp_path / "state"
        result = run_process(["sh", "-c", f". '{init}'\naction={action}\nstop_service"],
                             env={**env, "HEALTH_SEQ": health, "ASK_RECOVERY_STATE": str(state)},
                             capture_output=True, timeout=5)
        assert result.returncode == 0, result.stderr
        assert ("ask recovery-clean" in log.read_text()) == refunded, (action, health, log.read_text())
        assert state.read_text().strip() == "stopped"
    log.write_text("")
    (tmp_path / "probed").unlink(missing_ok=True)
    result = run_process(["sh", "-c", f". '{init}'\naction=shutdown\nstop_service"],
                         env={**env, "HEALTH_SEQ": "0", "CLEAN_STATUS": "1",
                              "ASK_RECOVERY_STATE": str(tmp_path / "state")},
                         capture_output=True, timeout=5)
    assert result.returncode == 0 and "could not refund" in log.read_text(), log.read_text()


def test_systemd_units_parse(tmp_path):
    """systemd accepts every shipped unit: syntax, specifiers and the `$$`
    escapes in the shutdown refund. The binaries they name are not on this
    host, which is the one complaint allowed."""
    import shutil
    import pytest
    if not shutil.which("systemd-analyze"):
        pytest.skip("systemd-analyze is not installed")
    units = sorted((ROOT / "integration/systemd").glob("*.service")) + \
        sorted((ROOT / "integration/systemd").glob("*.timer"))
    for unit in units:
        shutil.copy(unit, tmp_path / unit.name)
    result = run_process(["systemd-analyze", "verify", "--man=no",
                          *[str(tmp_path / unit.name) for unit in units]],
                         capture_output=True, text=True, timeout=30)
    complaints = [line for line in (result.stdout + result.stderr).splitlines()
                  if line.strip() and "is not executable" not in line]
    assert not complaints, complaints


def test_systemd_refund_gate(tmp_path):
    """The budget unit's ExecStop, run as systemd runs it once `$$` is
    unescaped: a refund only while the system is stopping and the datapath
    passes its health check."""
    import re
    unit = (ROOT / "integration/systemd/ask-recovery-budget.service").read_text()
    command = re.search(r"^ExecStop=-/bin/sh -c '(.*)'$", unit, re.M).group(1).replace("$$", "$")
    calls = tmp_path / "calls"
    for name, body in {
        "systemctl": '#!/bin/sh\n[ "$1" = is-system-running ] && echo "$SYSTEM_STATE"\n',
        "ask-flowtable": '#!/bin/sh\necho "ask $*" >> "$TEST_ROOT/calls"\n'
                         '[ "$1" = health ] && exit "$HEALTH"\nexit 0\n',
    }.items():
        (tmp_path / name).write_text(body)
        (tmp_path / name).chmod(0o755)
    command = command.replace("/usr/sbin/ask-flowtable", str(tmp_path / "ask-flowtable"))
    for state, health, refunded in [("stopping", "0", True), ("stopping", "1", False),
                                    ("running", "0", False), ("degraded", "0", False)]:
        calls.write_text("")
        run_process(["sh", "-c", command],
                    env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}",
                         "TEST_ROOT": str(tmp_path), "SYSTEM_STATE": state, "HEALTH": health},
                    capture_output=True, timeout=5)
        assert ("ask recovery-clean" in calls.read_text()) == refunded, (state, health, calls.read_text())

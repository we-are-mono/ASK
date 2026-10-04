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
procd_open_instance() {{ echo 'instance opened' >> "$TEST_ROOT/calls"; }}
procd_set_param() {{ :; }}
procd_close_instance() {{ :; }}
service_running() {{ return 0; }}
start_service
true
service_started
'''
    for status, arm, start, allowed in [("running", "0", "offline", True), ("running", "2", "offline", False),
                                       ("offline", "0", "offline", False), ("offline", "0", "running", True)]:
        log.write_text("")
        result = run_process(["sh", "-c", wrapper],
                                env={**env, "WDT_STATUS": status, "ARM_STATUS": arm, "WDT_START_STATUS": start},
                                capture_output=True, timeout=5)
        assert (result.returncode == 0) == allowed, result.stderr
        assert ("instance opened" in log.read_text()) == allowed
        if status == "running":
            assert '"stop":false' not in log.read_text()

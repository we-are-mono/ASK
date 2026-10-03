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
  [ ! -e "$TEST_ROOT/probed" ] || exit 1
  touch "$TEST_ROOT/probed"
  echo '3601.0 0.0' > "$TEST_ROOT/uptime" ;;
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
        "logger": '#!/bin/sh\nexit 0\n',
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
    for platform in ("systemd", "openwrt"):
        uptime.write_text("0.0 0.0\n")
        (tmp_path / "probed").unlink(missing_ok=True)
        log.write_text("")
        result = run_process(["sh", str(monitor), platform], env=env, capture_output=True, timeout=5)
        assert result.returncode == 1, result.stderr
        calls = log.read_text()
        assert calls.count("ask health") == 2 and calls.count("ask recovery-clear") == 1, calls
        assert "unexpected-reboot" not in calls
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

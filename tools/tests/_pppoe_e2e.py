"""PPPoE end-to-end fixtures.

Vision-side `pppoe_real_server`: spawns pppoe-server via direct subprocess
on the orchestrator host. No agent involvement — pppoe-server is too
privileged a surface to add to the askd-agent allowlist.

DUT-side `pppoe_dut_session`: drives pppd via Console.target() UART. Same
"don't expose pppd through the agent" rationale. pppd output captured to
/tmp/pppd.log on the DUT so failures (auth, MTU, IPCP) produce a useful
assertion message instead of "ppp iface didn't come UP within 20s".

Both fixtures pre-probe their requirements (pppoe-server on vision,
pppd on DUT) and skip with clear messages if missing — so a fresh dev
machine or an image without the IMAGE_INSTALL change gets a
graceful skip rather than a confused failure.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess

import pathlib
import pytest
import pytest_asyncio

from ask_orch.uart import Console


def _stage_file(target, path: str, content: str, *, mode: str = "644") -> None:
    """Write `content` to `path` on the DUT via UART.

    Heredoc with `true` no-op after EOF: Console.run()'s rc-capture
    wrapper appends `; echo MARKER=$?` to the last line, which would
    break a heredoc terminator if EOF were the last line. Putting
    `true` on the line after EOF lets EOF terminate cleanly and the
    rc-marker attaches to `true; echo MARKER=$?` instead.

    Busybox's default config doesn't include `base64`, so the
    obvious base64-staging pattern (used in lan_run_python for the
    LAN VM) doesn't work for the DUT."""
    # `'EOF'` (quoted) prevents shell expansion inside the heredoc body
    # — peer-options text is taken literally regardless of $ or \\ chars.
    target.run(
        f"cat > {path} <<'EOF'\n{content}EOF\nchmod {mode} {path}",
        timeout=10,
    )


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@pytest_asyncio.fixture
async def pppoe_real_server():
    """Bring up pppoe-server on the orchestrator (vision) bound to br0
    by default. Pre-probes the DUT for pppd so we don't spin up the
    server uselessly when the test image is missing the ppp package.

    Yields a config dict; tears down pppoe-server + staged config on
    exit. Defaults are overridable via env."""

    if shutil.which("pppoe-server") is None:
        pytest.skip("pppoe-server not installed on orchestrator")

    # Pre-probe the DUT for pppd via UART. If absent, skip BEFORE
    # spawning pppoe-server — saves a spin-up + teardown cycle.
    target = Console.target()
    try:
        target.login("root")
        r = target.run("which pppd 2>&1; modinfo pppoe 2>&1 | head -1",
                       timeout=5)
        out = r.stdout
        if "pppd" not in out or "/pppd" not in out:
            pytest.skip(
                "pppd not in DUT image. Add `ppp` to IMAGE_INSTALL in "
                "meta-ask/recipes-core/images/ask-image.bb, rebuild via "
                "`kas build`, run `make stage-image`, and reboot."
            )
        # modinfo prints "filename: ..." on success or "modinfo: ..." on miss.
        if "filename:" not in out and "modinfo: ERROR" in out:
            pytest.skip(
                "kernel pppoe module missing on DUT. Plan assumes the "
                "in-kernel pppoe plugin path; if absent, plan fallback "
                "is to use userspace rp-pppoe (extra fixture step)."
            )
    finally:
        target.close()

    bind_if      = _env("ASK_PPPOE_BIND_IF",      "br0")
    # 10.98.0.x deliberately avoided the 10.99.0.x range — Vision's
    # IPsec test setup puts 10.99.0.2/32 on lo, so a PPP peer of
    # 10.99.0.2 would loop replies back via loopback instead of ppp0.
    inner_local  = _env("ASK_PPPOE_INNER_LOCAL",  "10.98.0.1")
    inner_remote = _env("ASK_PPPOE_INNER_REMOTE", "10.98.0.2")
    user         = "ask-test"
    secret       = "ask-test-secret"

    pap_path = "/tmp/ask-pppoe-pap-secrets"
    opt_path = "/tmp/ask-pppoe-server.opt"

    pathlib.Path(pap_path).write_text(f'"{user}"   *   "{secret}"   *\n')
    os.chmod(pap_path, 0o600)
    pathlib.Path(opt_path).write_text(
        # require-pap → demand DUT auth us via PAP using the staged
        # pap-secrets. lcp-echo keeps the link probed; mtu/mru match DUT.
        "require-pap\n"
        f"chap-secrets {pap_path}\n"
        f"pap-secrets {pap_path}\n"
        "mtu 1492\n"
        "mru 1492\n"
        "lcp-echo-interval 5\n"
        "lcp-echo-failure 3\n"
        "noipdefault\n"
    )

    proc = subprocess.Popen(
        [
            "pppoe-server",
            "-I", bind_if,
            "-L", inner_local,
            "-R", inner_remote,
            "-O", opt_path,
            "-S", "ask-test",
            "-F",                # foreground — we manage lifetime
            "-T", "30",          # PADT timeout
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Give it ~0.5s to bind. If it bounced (bad iface, port-in-use,
    # etc.) it exits fast — catch that explicitly so the test gets a
    # useful failure message rather than a timeout 15s later.
    await asyncio.sleep(0.5)
    if proc.poll() is not None:
        _, err = proc.communicate(timeout=2)
        pytest.fail(
            f"pppoe-server exited rc={proc.returncode}; "
            f"stderr={err.decode('utf-8', 'replace')[:1000]!r}"
        )

    try:
        yield {
            "bind_if":      bind_if,
            "inner_local":  inner_local,
            "inner_remote": inner_remote,
            "user":         user,
            "secret":       secret,
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for p in (pap_path, opt_path):
            try: os.unlink(p)
            except FileNotFoundError: pass


@pytest_asyncio.fixture
async def pppoe_dut_session(pppoe_real_server):
    """Dial the session from the DUT via pppd (UART). Yields ppp_ifname.

    Failure modes are common during PPPoE bring-up (auth, MTU, IPCP);
    we capture pppd's stderr+stdout to /tmp/pppd.log on the DUT and
    dump it into the assertion message so flakes are actionable
    without re-running with extra logging."""
    cfg = pppoe_real_server
    target = Console.target()
    target.login("root")

    # Load PPP kernel modules. pppd accesses /dev/ppp which is created
    # by ppp_generic on insmod; pppoe.ko depends on ppp_generic and the
    # modprobe brings both in. Idempotent — already-loaded modules
    # return rc=0 silently.
    target.run("modprobe pppoe", timeout=5)

    # Stage CHAP/PAP secret + peer file in /tmp (don't touch /etc).
    secrets = f'"{cfg["user"]}"   *   "{cfg["secret"]}"   *\n'
    _stage_file(target, "/tmp/chap-secrets-dut", secrets, mode="600")

    peer_opts = (
        # plugin loads in-kernel pppoe support. The Yocto `ppp-oe`
        # package ships /usr/lib/pppd/<ver>/pppoe.so (named pppoe.so
        # in upstream ppp 2.5.2; older "rp-pppoe.so" is the historical
        # name from rp-pppoe v3 — current ppp tree consolidated it).
        # eth3 = WAN-facing iface (DUT's L2 path to vision).
        "plugin pppoe.so\n"
        "eth3\n"
        f"name {cfg['user']}\n"
        "noauth\n"               # don't demand server auth us back
        "nodefaultroute\n"       # don't replace DUT's default route
        # NOT persist: under `persist`, pppd auto-redials after the link
        # drops, but the fixture also relies on pppd exiting on SIGTERM.
        # With persist + default-detach, the pppd we kill is a parent
        # that has already daemonized (echo $! tracks the wrapper PID
        # which has exited; pppd child survives) — we accumulate zombies.
        # `nodetach` keeps pppd in the foreground so /tmp/pppd.pid is
        # the actual pppd PID, and skipping `persist` means a single
        # connection lifetime — matches the per-test fixture model.
        "nodetach\n"
        "maxfail 3\n"
        "holdoff 2\n"
        "mtu 1492\n"             # PPPoE overhead
        "mru 1492\n"
        "lcp-echo-interval 5\n"
        "lcp-echo-failure 3\n"
        "linkname asktest\n"
        "chap-secrets /tmp/chap-secrets-dut\n"
        "pap-secrets /tmp/chap-secrets-dut\n"
    )
    target.run("mkdir -p /tmp/peers", timeout=3)
    _stage_file(target, "/tmp/peers/ask-test", peer_opts, mode="644")

    # Dial via `pppd file <path>` — `pppd call <name>` looks in
    # /etc/ppp/peers/<name>, but we want a self-contained /tmp config.
    # Capture pid + log so failures are diagnosable and cleanup is
    # PID-targeted (not a broad `pkill pppd`).
    target.run(
        "rm -f /tmp/pppd.log /tmp/pppd.pid; "
        "nohup pppd file /tmp/peers/ask-test "
        "</dev/null >/tmp/pppd.log 2>&1 & "
        "echo $! > /tmp/pppd.pid",
        timeout=5,
    )

    # Wait up to 25s for ppp iface to appear and be UP. PPPoE bring-up
    # is PADI/PADO/PADR/PADS + LCP + CHAP/PAP + IPCP — typically 3–8s.
    # Single long-timeout shell loop instead of Python-side polling so
    # we issue ONE Console.run() — robust against mid-stream kernel
    # log noise (e.g., the upstream ppp_generic lockdep WARNING that
    # fires on first PPPIOCNEWUNIT and would corrupt a tight polling
    # loop's marker read; see ISSUES.md A13).
    # Top-level `exit 0` from this script would log the shell out — use
    # `break` and emit the result line after the loop.
    poll_script = (
        "found=; "
        "for i in $(seq 1 50); do "
        "  iface=$(ip -br link show | awk '/^ppp[0-9]/ {print $1; exit}'); "
        "  if [ -n \"$iface\" ]; then "
        "    state=$(cat /sys/class/net/$iface/operstate 2>/dev/null); "
        "    if [ \"$state\" = \"unknown\" ] || [ \"$state\" = \"up\" ]; then "
        "      found=$iface; break; "
        "    fi; "
        "  fi; "
        "  sleep 0.5; "
        "done; "
        "if [ -n \"$found\" ]; then echo PPPIFACE=$found; "
        "else echo PPPIFACE_TIMEOUT; fi"
    )
    r = target.run(poll_script, timeout=30.0)
    ppp_iface: str | None = None
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("PPPIFACE=") and "TIMEOUT" not in line:
            ppp_iface = line.split("=", 1)[1].strip()
            break

    if not ppp_iface:
        log = target.run("cat /tmp/pppd.log 2>/dev/null | tail -50",
                         timeout=3).stdout
        target.run(
            "[ -f /tmp/pppd.pid ] && kill -TERM $(cat /tmp/pppd.pid) "
            "2>/dev/null; sleep 1; "
            "[ -f /tmp/pppd.pid ] && kill -KILL $(cat /tmp/pppd.pid) "
            "2>/dev/null; rm -f /tmp/pppd.pid",
            timeout=5,
        )
        target.close()
        pytest.fail(
            "ppp iface didn't come UP within 20s. pppd log tail:\n"
            + (log[:3000] if log.strip()
               else "<empty — pppd never started? check /tmp/pppd.log>")
        )

    try:
        yield ppp_iface
    finally:
        # PID-targeted SIGTERM, then poll for iface disappearance,
        # then SIGKILL fallback. Don't broad-pkill — defensive against
        # other pppd processes the user might be running.
        target.run(
            f"[ -f /tmp/pppd.pid ] && kill -TERM $(cat /tmp/pppd.pid) "
            f"2>/dev/null; "
            f"for i in 1 2 3 4 5 6 7 8 9 10; do "
            f"  ip link show {ppp_iface} 2>/dev/null || break; "
            f"  sleep 0.5; "
            f"done; "
            f"[ -f /tmp/pppd.pid ] && kill -KILL $(cat /tmp/pppd.pid) "
            f"2>/dev/null; "
            f"rm -f /tmp/pppd.pid",
            timeout=15,
        )
        target.run(
            "rm -f /tmp/chap-secrets-dut /tmp/peers/ask-test "
            "/tmp/pppd.log; "
            "rmdir /tmp/peers 2>/dev/null; true",
            timeout=3,
        )
        target.close()

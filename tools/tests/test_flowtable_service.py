"""Recovery through the shipping daemon, without harness-issued repairs.

The base rig supplies endpoints and routing. This fixture then starts the real
boot service against its actual configuration file. Only setup/teardown and the
explicit maintenance test issue control commands; fault recovery must come from
the running daemon. The nft wrapper injects failed or hung operations and
otherwise execs the real nft with the inherited transaction lease intact.
"""
from __future__ import annotations

import asyncio
import json
import os
import time

import pytest
import pytest_asyncio

from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_connections import peer
from test_flowtable_offload import (ARTIFACTS, DPORT, SPORT, WAN_IP, command,
                                    console_command, console_python, read, rig)  # noqa: F401
from test_flowtable_selective_neighbour import hardware, warm

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires a flowtable boot and staged recovery controller")
DAEMON = "/usr/sbin/ask-flowtable"
INIT = "/etc/init.d/ask-flowtable"
CONF = "/etc/ask/offload.conf"
FAULT_DIR = "/tmp/ask-flowtable-service-fault"
FIRST = SPORT + 512
FLOWS = [{"id": i, "proto": proto, "sport": FIRST + offset}
         for i, (proto, offset) in enumerate((("udp", 0), ("tcp", 0), ("tcp", 1), ("udp", 2)))]


async def service_status(r):
    result = await console_command(r.service_console, DAEMON, "status")
    return json.loads(result["stdout"])


async def wait_service(r, ready=True, timeout=12):
    deadline = time.monotonic() + timeout
    samples = []
    while time.monotonic() < deadline:
        status = await service_status(r)
        samples.append({"time": time.monotonic(), "status": status})
        if status["admission_ready"] == ready:
            return samples
        await asyncio.sleep(0.2)
    r.record("service-recovery-timeout", samples)
    pytest.fail(f"service failed to converge in {timeout}s: {samples}")


@pytest_asyncio.fixture
async def service(rig):
    r = rig
    old = await read(r.target, r.session, CONF)
    cleanup = []
    initial_errors = (await r.state())["errors"]
    with Console.target(log_path=str(ARTIFACTS / "service-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        r.service_console = con
        try:
            for proto in ("tcp", "udp"):
                nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", proto,
                       "--sport", f"{FIRST}:{FIRST + 2}", "--dport", str(DPORT), "-j", "ACCEPT"]
                await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
                cleanup.append(["iptables", "-t", "nat", "-D", *nat])
                await command(r.target, r.session, "conntrack", "-D", "-p", proto,
                              "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                              "--dport", str(DPORT), check=False)
            deny = ["FORWARD", "-s", r.lan_ip, "-d", WAN_IP, "-p", "udp",
                    "--sport", str(FIRST + 2), "--dport", str(DPORT), "-j", "DROP"]
            await command(r.target, r.session, "iptables", "-I", *deny)
            cleanup.append(["iptables", "-D", *deny])
            policy = (f"enabled yes\ndevices {TARGET_LAN_IF} {TARGET_WAN_IF}\n"
                      f"scope saddr {r.lan_ip} daddr {WAN_IP} sport {FIRST}-{FIRST + 2} dport {DPORT}\n")
            result = await r.target.fs_write(r.session, CONF, policy)
            assert result["errno"] == 0, result
            # Resolve the real executable before adding the fault wrapper to
            # PATH. The wrapper is confined to this daemon's environment.
            await console_python(con, f'''
from pathlib import Path
import shutil
root = Path({FAULT_DIR!r})
assert not root.exists(), root
root.mkdir()
real = shutil.which('nft')
assert real
script = """#!/usr/bin/python3
import json, os, signal, sys, time
from pathlib import Path
root = Path({FAULT_DIR!r})
if sys.argv[1:] == ['-f', '-']:
    with (root / 'attempts').open('a') as f:
        print(time.monotonic(), file=f)
    try:
        (root / 'armed').rename(root / 'consumed')
    except FileNotFoundError:
        pass
    else:
        fault = (root / 'consumed').read_text().strip()
        if fault == 'once':
            sys.exit('injected one-shot nft transaction failure')
        child = os.fork()
        if child == 0:
            if fault == 'hung-apply':
                os.setsid()
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                time.sleep(30)
            os.execv(REAL_NFT, [REAL_NFT, *sys.argv[1:]])
        (root / 'pids.tmp').write_text(json.dumps(dict(worker=os.getpid(), guardian=os.getppid(), child=child)))
        (root / 'pids.tmp').replace(root / 'pids')
        if fault == 'lost-reply':
            _, status = os.waitpid(child, 0)
            assert status == 0, status
            (root / 'committed').touch()
        time.sleep(60)
        sys.exit('test timeout did not terminate nft')
os.execv(REAL_NFT, [REAL_NFT, *sys.argv[1:]])
""".replace('REAL_NFT', repr(real))
compile(script, str(root / 'nft'), 'exec')
(root / 'nft').write_text(script)
(root / 'nft').chmod(0o755)
''')
            await console_command(con, DAEMON, "resume")
            await console_command(con, "sh", "-c", f'PATH={FAULT_DIR}:"$PATH" {INIT} start')
            await wait_service(r)
            r.service_boot = (await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")).strip()
            r.service_pid = (await read(r.target, r.session, "/var/run/ask-flowtable.pid")).strip()
            r.service_hash = (await service_status(r))["policy_hash"]
            yield r
        finally:
            # Teardown occurs only after the recovery assertions (or failure
            # capture). It must never turn a failed observation into a pass.
            failures = []

            async def attempt(operation):
                try:
                    return await operation
                except Exception as error:
                    failures.append(repr(error))

            status = await attempt(service_status(r))
            r.record("service-final-status", status)
            await attempt(console_command(con, INIT, "stop", timeout=45))
            drained = await attempt(r.state())
            r.record("service-drained", drained)
            if drained and (any(drained[k] for k in ("bindings", "entries", "handle_refs", "neighbour_refs", "quarantine", "fatal"))
                            or drained["installs"] != drained["deletes"] or drained["errors"] != initial_errors):
                failures.append({"unbalanced": drained})
            # UART restoration stays available even if the management agent
            # is one of the things a failed recovery left unreachable.
            await attempt(console_python(con, f"from pathlib import Path\nPath({CONF!r}).write_text({old!r})\n"))
            for argv in reversed(cleanup):
                await attempt(console_command(con, *argv))
            for proto in ("tcp", "udp"):
                await attempt(console_command(con, "conntrack", "-D", "-p", proto,
                                              "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                                              "--dport", str(DPORT), check=False))
            await attempt(console_command(con, "rm", "-rf", FAULT_DIR))
            assert not failures, ("service fixture restoration failed", failures)


async def blocked_probe(r, p):
    received = r.echo.packets
    await p.rpc("start", [3], count=4, interval=0.01, allow_loss=True, udp_timeout=0.1)
    result = await p.rpc("wait", [3])
    assert result["3"]["received"] == 0 and result["3"]["lost"] == 4, result
    assert r.echo.packets == received, "forbidden UDP reached WAN"
    return result


@pytest.mark.parametrize("fault", ["missing-table", "invalidated-backend", "failed-apply",
                                 "hung-apply", "lost-reply"])
async def test_flowtable_service_automatic_recovery(service, fault):
    r = service
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS]
    async with peer(r, flows, initial_ids=[0, 1, 3]) as p:
        await warm(r, p, [0, 1], f"service-{fault}-warm", flows[:2])
        initial = await hardware(r, p, f"service-{fault}-before", flows[:2])
        await blocked_probe(r, p)
        started = time.monotonic()
        if fault == "invalidated-backend":
            # Rule events invalidate the backend but do not alter policy or
            # produce the LINK/ADDR notifications subscribed by the daemon.
            priority = "32007"
            rules = json.loads((await command(r.target, r.session, "ip", "-j", "rule", "show"))["stdout"])
            assert not any(rule.get("priority") == int(priority) for rule in rules), rules
            await command(r.target, r.session, "ip", "rule", "add", "pref", priority,
                          "from", "198.18.254.0/24", "table", "main")
            try:
                invalid = await r.wait(lambda s: s["invalidated"] == 1 or s["rearms"] > initial["rearms"], timeout=3)
                assert not invalid["fatal"], invalid
                r.record("service-rule-invalidation", invalid)
            finally:
                await command(r.target, r.session, "ip", "rule", "del", "pref", priority)
        else:
            if fault in ("failed-apply", "hung-apply", "lost-reply"):
                mode = "once" if fault == "failed-apply" else fault
                result = await r.target.fs_write(r.session, FAULT_DIR + "/armed", mode + "\n")
                assert result["errno"] == 0, result
            await console_command(r.service_console, "nft", "delete", "table", "inet", "ask_flowtable")
        # These are still the original sockets. The test issues no apply,
        # resume, restart, table recreation or reboot after fault injection.
        software = await p.batch([0, 1], count=32, interval=0.01)
        await blocked_probe(r, p)
        recovery_limit = 20 if fault in ("hung-apply", "lost-reply") else 12
        samples = await wait_service(r, timeout=recovery_limit)
        elapsed = time.monotonic() - started
        assert elapsed < recovery_limit, (elapsed, samples)
        if fault in ("failed-apply", "hung-apply", "lost-reply"):
            mode = "once" if fault == "failed-apply" else fault
            assert (await read(r.target, r.session, FAULT_DIR + "/consumed")).strip() == mode
            attempts = (await read(r.target, r.session, FAULT_DIR + "/attempts")).splitlines()
            # A committed transaction with a lost reply needs inspection,
            # while an uncommitted failure needs another install.
            assert len(attempts) == (2 if fault == "lost-reply" else 3), attempts
        if fault in ("hung-apply", "lost-reply"):
            pids = json.loads(await read(r.target, r.session, FAULT_DIR + "/pids"))
            await console_python(r.service_console, f"""
from pathlib import Path
for pid in {list(pids.values())!r}:
    assert not Path('/proc/' + str(pid)).exists(), pid
""")
            r.record(f"service-{fault}-reaped", pids)
        if fault == "lost-reply":
            await console_command(r.service_console, "test", "-f", FAULT_DIR + "/committed")
        await warm(r, p, [0, 1], f"service-{fault}-readmitted", flows[:2])
        recovered = await hardware(r, p, f"service-{fault}-after", flows[:2])
        hardware_seconds = time.monotonic() - started
        assert hardware_seconds < 35, hardware_seconds
        if fault == "invalidated-backend":
            assert recovered["rearms"] > initial["rearms"], (initial, recovered)
        assert recovered["errors"] == initial["errors"], (initial, recovered)
        await p.rpc("open", [2])
        await warm(r, p, [0, 1, 2], f"service-{fault}-new-flow", flows[:3])
        await hardware(r, p, f"service-{fault}-new-hardware", flows[:3])
        await blocked_probe(r, p)
        assert (await service_status(r))["policy_hash"] == r.service_hash
        assert (await read(r.target, r.session, "/var/run/ask-flowtable.pid")).strip() == r.service_pid
        assert (await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")).strip() == r.service_boot
        r.record(f"service-{fault}-recovery", {"controller_seconds": elapsed,
                 "hardware_proof_seconds": hardware_seconds, "samples": samples,
                 "transition_transfers": software, "pid": r.service_pid, "boot": r.service_boot})


async def test_flowtable_service_maintenance_stop(service):
    r = service
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS]
    async with peer(r, flows, initial_ids=[0, 1, 3]) as p:
        await warm(r, p, [0, 1], "service-stop-warm", flows[:2])
        await console_command(r.service_console, DAEMON, "stop", timeout=45)
        # Longer than a health interval, then a real service process restart.
        await asyncio.sleep(6)
        assert not (await service_status(r))["admission_ready"]
        await console_command(r.service_console, INIT, "restart", timeout=45)
        await asyncio.sleep(6)
        restarted_pid = (await read(r.target, r.session, "/var/run/ask-flowtable.pid")).strip()
        assert restarted_pid != r.service_pid, (r.service_pid, restarted_pid)
        status = await service_status(r)
        assert status["reconciliation_paused"] and not status["policy_installed"], status
        await p.batch([0, 1], count=64, interval=0.01)
        await blocked_probe(r, p)
        await console_command(r.service_console, DAEMON, "resume")
        await wait_service(r)
        await warm(r, p, [0, 1], "service-stop-readmitted", flows[:2])
        await hardware(r, p, "service-stop-hardware", flows[:2])
        assert not (await service_status(r))["reconciliation_paused"]
        r.record("service-maintenance-restart", {"before_pid": r.service_pid,
                 "after_pid": restarted_pid, "paused_status": status})

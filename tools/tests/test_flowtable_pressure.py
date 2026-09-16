"""Concurrent policy and route changes while traffic is active."""
from __future__ import annotations

import asyncio
import copy
import json
import os

import pytest

from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from ask_flowtable import policy_hash
from test_flowtable_connections import FLOWS, SPORT, connections, peer  # noqa: F401
from test_flowtable_offload import ARTIFACTS, DPORT, TABLE, WAN_IP, command, console_command, console_python, rig  # noqa: F401
from test_flowtable_policy import apply, candidate, installed, stop
from test_flowtable_selective_neighbour import hardware, keys, warm
from test_flowtable_tcp import software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")


async def test_flowtable_concurrent_policy_and_routes(connections):
    r = connections
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS[:2]]
    policy = candidate(r)
    excluded = copy.deepcopy(policy)
    excluded["exclude"] = [{"protocol": "udp", "port": SPORT}]
    await r.delete_table()
    with Console.target(log_path=str(ARTIFACTS / "pressure-policy-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        try:
            await apply(con, policy, r=r)
            async with peer(r, flows) as p:
                initial = await warm(r, p, [0, 1], "pressure-policy-initial", flows)
                await p.rpc("start", [0, 1], count=0, interval=0.01)
                running = True
                try:
                    script = f'''
import concurrent.futures, json, pathlib, subprocess, time
policies = { [policy, excluded]!r}
paths = [pathlib.Path('/tmp/ask-flowtable-race-%d.json' % i) for i in range(2)]
def run(argv):
    start = time.monotonic()
    r = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    return dict(argv=argv, rc=r.returncode, stdout=r.stdout, stderr=r.stderr, start=start, end=time.monotonic())
def reload(worker):
    return [run(['/usr/sbin/ask-flowtable', 'apply', '--config', str(paths[(worker + i) % 2])]) for i in range(3)]
def change():
    result = []
    for i in range(12):
        result.append(run(['ip', 'route', 'replace', {WAN_IP + '/32'!r}, 'dev', {TARGET_WAN_IF!r}, 'mtu', '1200',
                           'advmss', str(1100 if i % 2 == 0 else 1120)]))
        result.append(run(['ip', 'link', 'set', 'dev', {TARGET_LAN_IF!r}, 'mtu', str(1400 if i % 2 == 0 else 1500)]))
        time.sleep(0.05)
    return result
try:
    for path, policy in zip(paths, policies): path.write_text(json.dumps(policy))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(reload, i) for i in range(3)] + [pool.submit(change)]
        result = [j.result() for j in jobs]
    print(json.dumps(result))
finally:
    for path in paths: path.unlink(missing_ok=True)
    subprocess.run(['ip', 'link', 'set', 'dev', {TARGET_LAN_IF!r}, 'mtu', '1500'], check=True)
    subprocess.run(['ip', 'route', 'replace', {WAN_IP + '/32'!r}, 'dev', {TARGET_WAN_IF!r}, 'mtu', '1200'], check=True)
'''
                    job = asyncio.create_task(console_python(con, script, timeout=60))
                    try:
                        while not job.done():
                            done, _ = await asyncio.wait({job}, timeout=6)
                            if not done:
                                # Preserve the control lease while the UART
                                # stages and executes the bounded stress job.
                                await p.rpc("open", [])
                        result = await job
                    finally:
                        await job
                    operations = json.loads(result["stdout"])
                    assert all(item["rc"] == 0 for group in operations for item in group), operations
                    reports = await p.rpc("stop", [0, 1])
                    running = False
                    assert all(v["count"] >= 128 for v in reports.values()), reports
                    changed = await r.state()
                    r.record("pressure-concurrent-operations", {"operations": operations, "continuous_transfers": reports,
                                                                "before": initial, "after": changed})
                    assert changed["route_invalidations"] > initial["route_invalidations"], changed
                    # A route notification may already invalidate a shared
                    # generation before its paired MTU event arrives. Only
                    # the first cause increments a retirement counter.
                    for group in operations[:3]:
                        for item in group:
                            applied = json.loads(item["stdout"])
                            assert applied["enabled"] and applied["policy_hash"] in (policy_hash(policy), policy_hash(excluded))
                            assert all(applied["drained"][k] == 0 for k in ("bindings", "entries", "handle_refs", "neighbour_refs", "quarantine"))
                finally:
                    if running:
                        await p.rpc("stop", [0, 1])
                # Resolve the last-lock-winner ordering with an explicit final
                # desired policy, then prove stable hardware on both sockets.
                await apply(con, policy, r=r)
                status = await installed(con)
                assert status["admission_ready"] and status["policy_hash"] == policy_hash(policy), status
                await warm(r, p, [0, 1], "pressure-policy-recovered", flows)
                await hardware(r, p, "pressure-policy-final-hardware", flows)
        finally:
            await stop(con)
            await console_command(con, "ip", "link", "set", "dev", TARGET_LAN_IF, "mtu", "1500")
            await console_command(con, "rm", "-f", "/tmp/ask-flowtable-test.json")

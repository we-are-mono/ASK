"""Actual capacity overflow, resource reuse and concurrent policy changes."""
from __future__ import annotations

import asyncio
import copy
import json
import os

import pytest

from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from ask_flowtable import policy_hash
from test_flowtable_connections import (ALL, FLOWS, SPORT, by_key, connections, delete_connection,
                                        hardware_batch, healthy, peer, unchanged)  # noqa: F401
from test_flowtable_offload import ARTIFACTS, DPORT, TABLE, WAN_IP, command, console_command, console_python, rig  # noqa: F401
from test_flowtable_policy import apply, candidate, installed, stop
from test_flowtable_selective_neighbour import hardware, keys, warm
from test_flowtable_tcp import software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")


async def test_flowtable_capacity_overflow_and_reuse(connections):
    r = connections
    extra = [{"id": 32 + i, "proto": proto, "sport": SPORT + 16, "lan": r.lan_ip}
             for i, proto in enumerate(("udp", "tcp"))]
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS] + extra
    cleanup = []
    try:
        for spec in extra:
            nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", spec["proto"],
                   "--sport", str(spec["sport"]), "--dport", str(DPORT), "-j", "ACCEPT"]
            await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
            cleanup.append(["iptables", "-t", "nat", "-D", *nat])
            ct = ["conntrack", "-D", "-p", spec["proto"], "--orig-src", r.lan_ip,
                  "--orig-dst", WAN_IP, "--sport", str(spec["sport"]), "--dport", str(DPORT)]
            await command(r.target, r.session, *ct, check=False)
            cleanup.append(ct)
            await r.nft(f"add rule inet {TABLE} forward ip saddr {r.lan_ip} ip daddr {WAN_IP} "
                        f"{spec['proto']} sport {spec['sport']} {spec['proto']} dport {DPORT} flow add @fast")
        async with peer(r, flows, initial_ids=ALL) as p:
            await p.batch(ALL, 128, 0.01)
            await r.wait(lambda s: s["entries"] == 64)
            full = await hardware_batch(r, p, ALL, "pressure-full-hardware")
            await p.rpc("start", ALL, count=0, interval=0.03125)
            try:
                await p.rpc("open", [32, 33])
                before_tx = await software_tx(r)
                reports = await p.batch([32, 33], 256, 0.03125)
                after_tx, overflow = await software_tx(r), await r.state()
                unchanged(r, full, overflow, ALL)
                assert overflow["entries"] == 64 and overflow["installs"] == full["installs"]
                assert overflow["deletes"] == full["deletes"] and overflow["rejects"] > full["rejects"]
                assert not (keys([32, 33], flows) & by_key(overflow).keys()), overflow
                tx = {d: after_tx[d] - before_tx[d] for d in before_tx}
                assert all(n >= 256 for n in tx.values()), tx
                r.record("pressure-overflow-software", {"state": overflow, "transfers": reports, "software_tx": tx})

                await p.rpc("stop", [0, 1])
                await delete_connection(r, 0)
                await p.rpc("close", [1])
                freed = await r.wait(lambda s: s["entries"] == 60)
                unchanged(r, full, freed, ALL[2:])
                assert freed["deletes"] == full["deletes"] + 4
                # Native software flow refresh retries hardware admission.
                # Neither overflow socket nor its conntrack is replaced.
                for _ in range(8):
                    await p.batch([32, 33], 128, 0.01)
                    reused = await r.state()
                    if reused["entries"] == 64:
                        break
                healthy(reused)
                unchanged(r, full, reused, ALL[2:])
                assert by_key(reused).keys() == keys(list(range(2, 34)), flows), reused
                assert reused["installs"] == full["installs"] + 4 and reused["deletes"] == freed["deletes"]
                before_tx = await software_tx(r)
                reports = await p.batch([32, 33], 256, 0.03125)
                after_tx, hardware_state = await software_tx(r), await r.state()
                tx = {d: after_tx[d] - before_tx[d] for d in before_tx}
                assert tx[TARGET_LAN_IF] <= 64 and tx[TARGET_WAN_IF] <= 512, tx
                for key in keys([32, 33], flows):
                    old, new = by_key(reused)[key], by_key(hardware_state)[key]
                    assert old["cookie"] == new["cookie"]
                    packets = int(new["packets"]) - int(old["packets"])
                    assert packets == 256 if key[1] == "17" else packets >= reports[33]["bytes"] // 1500
                r.record("pressure-overflow-reused-hardware", {"before": reused, "after": hardware_state,
                                                             "transfers": reports, "software_tx": tx})
            finally:
                await p.rpc("stop", ALL[2:])
    finally:
        await r.delete_table()
        failures = []
        for argv in reversed(cleanup):
            result = await command(r.target, r.session, *argv, check=False)
            if result["rc"] and argv[0] != "conntrack":
                failures.append(result)
        assert not failures, failures


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
            await apply(con, policy)
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
                await apply(con, policy)
                status = await installed(con)
                assert status["admission_ready"] and status["policy_hash"] == policy_hash(policy), status
                await warm(r, p, [0, 1], "pressure-policy-recovered", flows)
                await hardware(r, p, "pressure-policy-final-hardware", flows)
        finally:
            await stop(con)
            await console_command(con, "ip", "link", "set", "dev", TARGET_LAN_IF, "mtu", "1500")
            await console_command(con, "rm", "-f", "/tmp/ask-flowtable-test.json")

"""Opt-in full-rate Loki-to-Vision TCP NAT benchmark with hardware-path evidence."""
import asyncio
import json
import os

import pytest
import pytest_asyncio

from ask_orch.client import Agent

from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import by_key, healthy
from test_flowtable_offload import (ARTIFACTS, DPORT, WAN_IP, command,
                                   console_command, rig)  # noqa: F401
from test_flowtable_policy import CONFIG, apply, candidate, stop
from test_flowtable_tcp import cpu, cpu_delta, software_tx

pytestmark = pytest.mark.skipif(
    os.environ.get("ASK_FLOWTABLE_TESTS") != "1" or os.environ.get("ASK_FLOWTABLE_THROUGHPUT") != "1",
    reason="requires explicit experimental boot and full-rate benchmark opt-in")
PORT, STREAMS = DPORT + 3000, 4


@pytest_asyncio.fixture
async def rate_path(rig):
    r = rig
    addresses = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show",
                                         "dev", TARGET_WAN_IF))["stdout"])
    external = next(a["local"] for a in addresses[0]["addr_info"] if a["family"] == "inet")
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    existing = json.loads((await command(wan, r.session, "ip", "-j", "route", "show", "exact", external + "/32"))["stdout"])
    assert not existing, ("benchmark requires an unused endpoint host route", existing)
    # Prior MTU-exception proofs can leave endpoint PMTU caches at 1200.
    # A temporary explicit route provides fresh 1500-byte path metrics.
    await command(wan, r.session, "ip", "route", "add", external + "/32", "dev", r.wan_if, "mtu", "1500")
    try:
        yield r
    finally:
        await command(wan, r.session, "ip", "route", "del", external + "/32", "dev", r.wan_if)


async def test_flowtable_nat_throughput(rate_path):
    r = rate_path
    for address, dev in ((r.lan_ip, TARGET_LAN_IF), (WAN_IP, TARGET_WAN_IF)):
        await command(r.target, r.session, "ip", "route", "replace", address + "/32", "dev", dev, "mtu", "1500")
    addresses = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show",
                                         "dev", TARGET_WAN_IF))["stdout"])
    external = next(a["local"] for a in addresses[0]["addr_info"] if a["family"] == "inet")
    policy = candidate(r)
    policy["scope"] = [{"source": r.lan_ip, "destination": WAN_IP, "protocol": "tcp", "destination_port": PORT}]
    nat_table = "ask_nat_rate_test"
    nat = (f"table ip {nat_table} {{ chain postrouting {{ type nat hook postrouting priority 90; "
           f"ip saddr {r.lan_ip} ip daddr {WAN_IP} tcp dport {PORT} masquerade; }}; }}")
    server = lan_task = None
    with Console.target(log_path=str(ARTIFACTS / "nat-rate-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        assert (await console_command(con, "nft", "list", "table", "ip", nat_table, check=False))["rc"] != 0
        await console_command(con, "nft", nat)
        try:
            await apply(con, policy, r=r)
            server = await asyncio.create_subprocess_exec("iperf3", "-s", "-1", "-B", WAN_IP, "-p", str(PORT), "-J",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.sleep(0.2)
            assert server.returncode is None, "dedicated iperf server failed to start"
            script = f'''
import json, subprocess
link = subprocess.check_output(['ethtool', {LAN_NIC!r}], text=True)
assert 'Speed: 10000Mb/s' in link and 'Duplex: Full' in link and 'Link detected: yes' in link, link
argv = ['iperf3', '-c', {WAN_IP!r}, '-B', {r.lan_ip!r}, '-p', {str(PORT)!r},
        '-P', {str(STREAMS)!r}, '-t', '20', '-O', '3', '-Z', '-J']
existing = json.loads(subprocess.check_output(['ip', '-j', 'route', 'show', 'exact', {WAN_IP + '/32'!r}], text=True))
assert not existing, existing
subprocess.run(['ip', 'route', 'add', {WAN_IP + '/32'!r}, 'via', {r.lan_gateway!r}, 'dev', {LAN_NIC!r}, 'mtu', '1500'], check=True)
try:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=40)
finally:
    subprocess.run(['ip', 'route', 'del', {WAN_IP + '/32'!r}, 'dev', {LAN_NIC!r}], check=True)
print(json.dumps({{'link': link, 'argv': argv, 'rc': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr}}), flush=True)
assert result.returncode == 0
'''
            lan_task = asyncio.create_task(lan_run_python(r.lan, script, label="flowtable_nat_rate", timeout=55))
            # Select the four bulk sockets by measured payload activity. The
            # iperf control socket is in scope but must not substitute for one.
            deadline = asyncio.get_running_loop().time() + 8
            while True:
                before = await r.state()
                bulk = [f for f in before["flows"] if f["in"] == TARGET_LAN_IF and f["proto"] == "6"
                        and f["dst"] == f"{WAN_IP}:{PORT}" and int(f["bytes"]) > 1_000_000]
                if len(bulk) == STREAMS:
                    break
                assert not lan_task.done(), "iperf ended before hardware admission"
                assert asyncio.get_running_loop().time() < deadline, before
                await asyncio.sleep(0.25)
            healthy(before)
            keys = set()
            for row in bulk:
                assert row["new_src"].rsplit(":", 1)[0] == external and row["new_dst"] == row["dst"], row
                assert row["src"].rsplit(":", 1)[0] == r.lan_ip and row["mtu"] == "1500", row
                keys.add((TARGET_LAN_IF, "6", row["src"], row["dst"]))
                keys.add((TARGET_WAN_IF, "6", row["new_dst"], row["new_src"]))
            old = by_key(before)
            assert keys <= old.keys(), before
            for row in bulk:
                reply = old[(TARGET_WAN_IF, "6", row["new_dst"], row["new_src"])]
                assert (reply["new_src"], reply["new_dst"]) == (row["dst"], row["src"]), reply
            tx_before, cpu_before = await software_tx(r), await cpu(r)
            await asyncio.sleep(10)
            cpu_after, tx_after = await cpu(r), await software_tx(r)
            after = await r.state()
            healthy(after)
            new = by_key(after)
            deltas = []
            for key in keys:
                assert new[key]["cookie"] == old[key]["cookie"], (before, after)
                packets = int(new[key]["packets"]) - int(old[key]["packets"])
                size = int(new[key]["bytes"]) - int(old[key]["bytes"])
                assert packets > 1000, (key, packets)
                deltas.append({"key": key, "packets": packets, "bytes": size})
            tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
            measurement = {"before": before, "after": after, "hardware": deltas, "software_tx": tx,
                           "cpu": cpu_delta(cpu_before, cpu_after)}
            r.record("nat-rate-hardware", measurement)
            assert all(0 <= count <= 512 for count in tx.values()), tx
            result = await lan_task
            r.record("nat-rate-client-console", {"rc": result.rc, "stdout": result.stdout})
            assert result.rc == 0, result.stdout
            client = json.loads(result.stdout.strip())
            client_json = json.loads(client["stdout"])
            stdout, stderr = await asyncio.wait_for(server.communicate(), 10)
            server_json = json.loads(stdout)
            r.record("nat-rate-iperf", {"client": client_json, "server": server_json,
                                        "stderr": stderr.decode(), "lan_link": client["link"]})
            assert client["rc"] == server.returncode == 0 and "error" not in client_json and "error" not in server_json
            received = server_json["end"]["sum_received"]
            assert received["bytes"] > 0 and received["seconds"] >= 19, received
            assert received["bits_per_second"] >= float(os.environ.get("ASK_FLOWTABLE_MIN_GBPS", "9")) * 1e9, received
        finally:
            try:
                if lan_task:
                    result = await lan_task
                    r.record("nat-rate-client-console", {"rc": result.rc, "stdout": result.stdout})
            finally:
                try:
                    if server and server.returncode is None:
                        server.terminate()
                        await asyncio.wait_for(server.communicate(), 5)
                finally:
                    try:
                        await stop(con)
                    finally:
                        await console_command(con, "nft", "delete", "table", "ip", nat_table)
                        await console_command(con, "rm", "-f", CONFIG)
                        await console_command(con, "conntrack", "-D", "-p", "tcp", "--orig-src", r.lan_ip,
                            "--orig-dst", WAN_IP, "--dport", str(PORT), check=False)
            final = await r.state()
            assert final["installs"] == final["deletes"] and final["errors"] == final["fatal"] == final["quarantine"] == 0, final
            r.record("nat-rate-cleanup", final)

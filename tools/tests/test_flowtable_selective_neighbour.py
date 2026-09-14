"""Retire one peer's TCP/UDP flows while another peer stays in hardware."""
from __future__ import annotations

import json
import os

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import by_key, healthy, peer
from test_flowtable_offload import DPORT, SPORT, TABLE, WAN_IP, command, read, rig  # noqa: F401
from test_flowtable_tcp import cpu, cpu_delta, software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
GATEWAY = "198.18.29.1"
PEERS = [dict(netns="ask-ft-neigh-a", iface="askftna", lan="198.18.29.2", mac="02:9d:99:b2:33:a1"),
         dict(netns="ask-ft-neigh-b", iface="askftnb", lan="198.18.29.3", mac="02:9d:99:b2:33:b1")]
FLOWS = [{**spec, "id": 2 * i + j, "proto": proto, "sport": SPORT + 96}
         for i, spec in enumerate(PEERS) for j, proto in enumerate(("udp", "tcp"))]
A, B, ALL = [0, 1], [2, 3], [0, 1, 2, 3]
CHANGED_MAC = "02:9d:99:b2:33:a2"


def keys(ids):
    result = set()
    for ident in ids:
        spec = FLOWS[ident]
        proto = "6" if spec["proto"] == "tcp" else "17"
        src, dst = f"{spec['lan']}:{spec['sport']}", f"{WAN_IP}:{DPORT}"
        result.update(((TARGET_LAN_IF, proto, src, dst), (TARGET_WAN_IF, proto, dst, src)))
    return result


def unchanged(before, after, ids):
    healthy(after)
    assert after["handle_refs"] == after["entries"], after
    old, new = by_key(before), by_key(after)
    for key in keys(ids):
        assert new[key]["cookie"] == old[key]["cookie"], (key, before, after)
        for field in ("packets", "bytes"):
            assert int(new[key][field]) >= int(old[key][field]), (key, before, after)


@pytest_asyncio.fixture
async def selective(rig):
    r = rig
    r.selective_errors = (await r.state())["errors"]
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    cleanup = []
    setup = f'''
import pathlib, subprocess
peers = {PEERS!r}
def run(*args): subprocess.run(args, check=True, capture_output=True, text=True)
for p in peers:
    assert not pathlib.Path('/var/run/netns/' + p['netns']).exists()
    assert not pathlib.Path('/sys/class/net/' + p['iface']).exists()
created = []
try:
    for p in peers:
        run('ip', 'netns', 'add', p['netns']); created.append(p)
        run('ip', 'link', 'add', 'link', {LAN_NIC!r}, 'name', p['iface'],
            'netns', p['netns'], 'type', 'macvlan', 'mode', 'bridge')
        run('ip', '-n', p['netns'], 'link', 'set', 'lo', 'up')
        run('ip', '-n', p['netns'], 'link', 'set', p['iface'], 'address', p['mac'], 'up')
        run('ip', '-n', p['netns'], 'addr', 'add', p['lan'] + '/24', 'dev', p['iface'])
        run('ip', '-n', p['netns'], 'route', 'add', 'default', 'via', {GATEWAY!r})
except BaseException:
    for p in reversed(created): run('ip', 'netns', 'del', p['netns'])
    raise
'''
    result = await lan_run_python(r.lan, setup, label="flowtable_selective_setup", timeout=20)
    assert result.rc == 0, result.stdout
    try:
        async def change(agent, args, undo):
            await command(agent, r.session, *args)
            cleanup.append((agent, undo))

        dut_ip = next(a["local"] for i in json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_WAN_IF))["stdout"])
                      for a in i["addr_info"] if a["family"] == "inet")
        await change(r.target, ["ip", "addr", "add", GATEWAY + "/24", "dev", TARGET_LAN_IF],
                     ["ip", "addr", "del", GATEWAY + "/24", "dev", TARGET_LAN_IF])
        for spec in PEERS:
            address = spec["lan"] + "/32"
            await change(r.target, ["ip", "route", "add", address, "dev", TARGET_LAN_IF, "mtu", "1200"],
                         ["ip", "route", "del", address, "dev", TARGET_LAN_IF])
            await change(wan, ["ip", "route", "add", address, "via", dut_ip, "dev", r.wan_if],
                         ["ip", "route", "del", address, "via", dut_ip, "dev", r.wan_if])
        for spec in FLOWS:
            nat = ["POSTROUTING", "-s", spec["lan"], "-d", WAN_IP, "-p", spec["proto"],
                   "--sport", str(spec["sport"]), "--dport", str(DPORT), "-j", "ACCEPT"]
            await change(r.target, ["iptables", "-t", "nat", "-I", *nat],
                         ["iptables", "-t", "nat", "-D", *nat])
        for name, value in [("base_reachable_time_ms", 1000), ("delay_first_probe_time", 1),
                            ("retrans_time_ms", 200), ("ucast_solicit", 3),
                            ("mcast_solicit", 3), ("app_solicit", 0)]:
            key = f"net.ipv4.neigh.{TARGET_LAN_IF}.{name}"
            old = (await read(r.target, r.session, "/proc/sys/" + key.replace(".", "/"))).strip()
            await change(r.target, ["sysctl", "-w", f"{key}={value}"], ["sysctl", "-w", f"{key}={old}"])
        await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {{ {PEERS[0]['lan']}, {PEERS[1]['lan']} }} ip daddr {WAN_IP} udp sport {SPORT + 96} udp dport {DPORT} flow add @fast
 ip saddr {{ {PEERS[0]['lan']}, {PEERS[1]['lan']} }} ip daddr {WAN_IP} tcp sport {SPORT + 96} tcp dport {DPORT} flow add @fast
 }}
}}''')
        await r.wait(lambda s: s["bindings"] == 2)
        yield r
    finally:
        failures = []

        async def attempt(operation):
            try:
                return await operation
            except Exception as error:
                failures.append(str(error))

        final = await attempt(r.delete_table())
        if final:
            r.record("selective-cleanup", final)
            if not (final["entries"] == final["handle_refs"] == final["neighbour_refs"] == final["quarantine"] == 0
                    and final["installs"] == final["deletes"] and final["errors"] == r.selective_errors):
                failures.append(final)
        for spec in FLOWS:
            await attempt(command(r.target, r.session, "conntrack", "-D", "-p", spec["proto"],
                                  "--orig-src", spec["lan"], "--orig-dst", WAN_IP,
                                  "--sport", str(spec["sport"]), "--dport", str(DPORT), check=False))
        for agent, args in reversed(cleanup):
            await attempt(command(agent, r.session, *args))
        for spec in PEERS:
            await attempt(command(r.target, r.session, "ip", "neigh", "del", spec["lan"], "dev", TARGET_LAN_IF, check=False))
        teardown = f'''
import subprocess
errors = []
for p in {PEERS!r}:
    result = subprocess.run(['ip', 'netns', 'del', p['netns']], capture_output=True, text=True)
    if result.returncode: errors.append(result.stderr)
assert not errors, errors
'''
        result = await attempt(lan_run_python(r.lan, teardown, label="flowtable_selective_cleanup", timeout=15))
        if result and result.rc:
            failures.append(result.stdout)
        assert not failures, failures


async def warm(r, p, ids, label):
    samples = []
    for _ in range(8):
        await p.batch(ids, count=128, interval=0.01)
        state = await r.state()
        samples.append(state)
        if state["entries"] == 8:
            healthy(state)
            assert state["handle_refs"] == 8 and by_key(state).keys() == keys(ALL), state
            r.record(label, samples)
            return state
    pytest.fail(f"automatic hardware admission failed: {samples}")


async def hardware(r, p, label):
    before = await r.state()
    tx_before, cpu_before = await software_tx(r), await cpu(r)
    reports = await p.batch(ALL, count=256, interval=0.03125)
    after, tx_after, cpu_after = await r.state(), await software_tx(r), await cpu(r)
    unchanged(before, after, ALL)
    assert before["installs"] == after["installs"] and before["deletes"] == after["deletes"], (before, after)
    old, new = by_key(before), by_key(after)
    for ident in ALL:
        for key in keys([ident]):
            packets = int(new[key]["packets"]) - int(old[key]["packets"])
            if FLOWS[ident]["proto"] == "udp":
                assert packets == 256, (key, packets)
                assert int(new[key]["bytes"]) - int(old[key]["bytes"]) == 256 * (256 + 42), (key, old, new)
            else:
                assert packets >= reports[ident]["bytes"] // 1500, (key, packets)
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    assert 0 <= tx[TARGET_LAN_IF] <= 64 and 0 <= tx[TARGET_WAN_IF] <= 512, tx
    r.record(label, {"before": before, "after": after, "transfers": reports,
                     "software_tx": tx, "cpu": cpu_delta(cpu_before, cpu_after)})
    return after


async def retired(r, before, label):
    state = await r.wait(lambda s: s["entries"] == 4)
    unchanged(before, state, B)
    assert by_key(state).keys() == keys(B), state
    assert state["neighbour_invalidations"] == before["neighbour_invalidations"] + 2, (before, state)
    assert state["installs"] == before["installs"] and state["deletes"] == before["deletes"] + 4, (before, state)
    assert state["rearms"] == before["rearms"] and not state["invalidation_done"], state
    r.record(label, {"before": before, "after": state})
    return state


async def test_flowtable_selective_neighbour(selective):
    r = selective
    async with peer(r, FLOWS) as p:
        await warm(r, p, ALL, "selective-initial-admission")
        initial = await hardware(r, p, "selective-initial-hardware")
        await p.rpc("start", B, count=0, interval=0.01)
        # A is idle; B keeps sending on its original sockets throughout all
        # faults. All four flows share WAN resolution, but only A changes.
        await p.rpc("neighbour", ident=0, changes={"mac": CHANGED_MAC})
        await retired(r, initial, "selective-mac-retired")
        before = await warm(r, p, A, "selective-mac-readmitted")
        unchanged(initial, before, B)

        await p.rpc("start", [1], count=0, interval=0.01)
        failure = await p.rpc("neighbour", ident=0, changes={"arp_ignore": 8, "restore_after": 8})
        await command(r.target, r.session, "ip", "neigh", "change", PEERS[0]["lan"],
                      "dev", TARGET_LAN_IF, "nud", "stale")
        await retired(r, before, "selective-unreachable-retired")
        ns = await command(r.target, r.session, "ip", "-j", "neigh", "show", "to", PEERS[0]["lan"])
        # The same TCP socket can already be retrying ARP after FAILED, so the
        # next observable state may be INCOMPLETE. Neither has a usable MAC.
        assert set(json.loads(ns["stdout"])[0]["state"]) & {"FAILED", "INCOMPLETE"}, ns
        restored = await p.rpc("neighbour", ident=0, changes={"arp_ignore": 0})
        report = await p.rpc("stop", [1])
        r.record("selective-tcp-fault", {"failure": failure, "restored": restored,
                                        "neighbour": ns, "transfer": report})
        before = await warm(r, p, A, "selective-unreachable-readmitted")
        unchanged(initial, before, B)

        await command(r.target, r.session, "ip", "neigh", "del", PEERS[0]["lan"], "dev", TARGET_LAN_IF)
        await retired(r, before, "selective-object-retired")
        after = await warm(r, p, A, "selective-object-readmitted")
        unchanged(initial, after, B)
        reports = await p.rpc("stop", B)
        for report in reports.values():
            assert report["count"] > 128, reports
        r.record("selective-unaffected-transfers", reports)
        final = await hardware(r, p, "selective-final-hardware")
        unchanged(initial, final, B)
        assert final["rearms"] == initial["rearms"], (initial, final)
        assert final["neighbour_invalidations"] == initial["neighbour_invalidations"] + 6, (initial, final)


async def test_flowtable_selective_neighbour_barrier(selective):
    """An unproven retirement barrier closes admission for every connection."""
    r = selective
    knob = "/proc/fm_ehash_hcsync_fail"
    try:
        async with peer(r, FLOWS) as p:
            before = await warm(r, p, ALL, "selective-barrier-admission")
            r.selective_errors += 2
            result = await r.target.fs_write(r.session, knob, "2")
            assert result["errno"] == 0, result
            await command(r.target, r.session, "ip", "neigh", "del", PEERS[0]["lan"], "dev", TARGET_LAN_IF)
            state = await r.wait(lambda s: s["invalidation_done"] == 1 and s["entries"] == 0)
            assert state["invalidated"] == 1 and state["bindings"] == 2, state
            assert state["handle_refs"] == state["neighbour_refs"] == state["fatal"] == state["quarantine"] == 0, state
            assert state["errors"] == r.selective_errors, state
            assert state["deletes"] == before["deletes"] + 8 and state["installs"] == before["installs"], (before, state)
            assert (await read(r.target, r.session, knob)).strip() == "armed=0"
            reports = await p.batch(ALL)
            after = await r.state()
            assert after["entries"] == 0 and after["installs"] == before["installs"], after
            r.record("selective-barrier", {"before": before, "retired": state,
                                           "software": after, "transfers": reports})
    finally:
        result = await r.target.fs_write(r.session, knob, "0")
        assert result["errno"] == 0, result
        await r.delete_table()
        # Global recovery still requires a fresh table. Leave this boot usable
        # after the deliberately injected errors; the detailed proof is in rearm.
        state = await r.state()
        if state["invalidated"] and not state["fatal"]:
            await r.wait(lambda s: s["rearm_ready"] == 1)
            await r.table()
            await r.delete_table()

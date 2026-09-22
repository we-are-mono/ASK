"""Revoke and restore guest bridge membership without repairing admission."""
from __future__ import annotations

import asyncio
import json
import os
import time

import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from flowtable_connections_peer import payload
from test_flowtable_connections import peer
from test_flowtable_offload import ARTIFACTS, command, console_command, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, unchanged, warm
from test_flowtable_service import FIRST, managed_service, service_status, supervision_status, wait_service
from test_flowtable_service_vlan import attempts, balanced, denied, received

BRIDGE = "br-ftsvc"
TRUST_VID, GUEST_VID = 285, 286
TRUST_IF, GUEST_IF = f"{BRIDGE}.{TRUST_VID}", f"{BRIDGE}.{GUEST_VID}"
NETNS, LAN_IF = "ask-ft-service-guest", "askftguest"
GATEWAY, ADDRESS = "172.29.86.1", "172.29.86.2"


@pytest_asyncio.fixture
async def bridge_service(rig):
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    baseline = await r.state()
    links = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show"))["stdout"])
    assert not {BRIDGE, TRUST_IF, GUEST_IF} & {link["ifname"] for link in links}, links
    assert "master" not in next(link for link in links if link["ifname"] == TARGET_LAN_IF), links
    addresses = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_LAN_IF))["stdout"])
    original = [f"{a['local']}/{a['prefixlen']}" for a in addresses[0]["addr_info"] if a["family"] == "inet"]
    assert original, addresses
    routes = json.loads((await command(wan, r.session, "ip", "-j", "route", "show", "exact", ADDRESS + "/32"))["stdout"])
    assert not routes, routes
    dut_wan = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_WAN_IF))["stdout"])
    dut_ip = next(a["local"] for a in dut_wan[0]["addr_info"] if a["family"] == "inet")
    bridge_created = lan_created = wan_route = False

    async def dut(*args):
        return await command(r.target, r.session, *args)

    try:
        await dut("ip", "link", "add", "name", BRIDGE, "type", "bridge")
        bridge_created = True
        await dut("ip", "link", "set", BRIDGE, "address", r.dut_lan_mac)
        await dut("ip", "link", "set", BRIDGE, "type", "bridge", "vlan_filtering", "1", "vlan_default_pvid", "0")
        for address in original:
            await dut("ip", "addr", "del", address, "dev", TARGET_LAN_IF)
        await dut("ip", "link", "set", TARGET_LAN_IF, "master", BRIDGE)
        await dut("ip", "link", "set", BRIDGE, "up")
        await dut("bridge", "vlan", "add", "dev", TARGET_LAN_IF, "vid", str(TRUST_VID), "pvid", "untagged")
        await dut("bridge", "vlan", "add", "dev", TARGET_LAN_IF, "vid", str(GUEST_VID))
        for vid, dev, cidrs in [(TRUST_VID, TRUST_IF, original), (GUEST_VID, GUEST_IF, [GATEWAY + "/24"])]:
            await dut("bridge", "vlan", "add", "dev", BRIDGE, "vid", str(vid), "self")
            await dut("ip", "link", "add", "link", BRIDGE, "name", dev, "type", "vlan", "id", str(vid))
            for address in cidrs:
                await dut("ip", "addr", "add", address, "dev", dev)
            await dut("ip", "link", "set", dev, "up")
        for address, dev in [(r.lan_ip, TRUST_IF), (ADDRESS, GUEST_IF)]:
            await dut("ip", "route", "replace", address + "/32", "dev", dev, "mtu", "1200")
            await dut("ip", "neigh", "replace", address, "lladdr", r.lan_mac, "nud", "permanent", "dev", dev)
        setup = f'''
from pathlib import Path
import subprocess
def run(*args): subprocess.run(args, check=True, capture_output=True, text=True)
assert not Path('/var/run/netns/' + {NETNS!r}).exists()
assert not Path('/sys/class/net/' + {LAN_IF!r}).exists()
run('ip', 'netns', 'add', {NETNS!r})
try:
    run('ip', 'link', 'add', 'link', {LAN_NIC!r}, 'name', {LAN_IF!r},
        'netns', {NETNS!r}, 'type', 'vlan', 'id', {str(GUEST_VID)!r})
    run('ip', '-n', {NETNS!r}, 'link', 'set', 'lo', 'up')
    run('ip', '-n', {NETNS!r}, 'addr', 'add', {ADDRESS + '/24'!r}, 'dev', {LAN_IF!r})
    run('ip', '-n', {NETNS!r}, 'link', 'set', {LAN_IF!r}, 'up')
    run('ip', '-n', {NETNS!r}, 'route', 'add', 'default', 'via', {GATEWAY!r})
    run('ip', '-n', {NETNS!r}, 'neigh', 'replace', {GATEWAY!r}, 'lladdr',
        {r.dut_lan_mac!r}, 'nud', 'permanent', 'dev', {LAN_IF!r})
except BaseException:
    run('ip', 'netns', 'del', {NETNS!r})
    raise
'''
        result = await lan_run_python(r.lan, setup, label="service_bridge_setup", timeout=20)
        assert result.rc == 0, result.stdout
        lan_created = True
        await command(wan, r.session, "ip", "route", "add", ADDRESS + "/32", "via", dut_ip, "dev", r.wan_if)
        wan_route = True
        async with managed_service(r, addresses=(r.lan_ip, ADDRESS)):
            yield r
    finally:
        failures = []

        async def attempt(operation):
            try:
                return await operation
            except Exception as error:
                failures.append(repr(error))

        if wan_route:
            await attempt(command(wan, r.session, "ip", "route", "del", ADDRESS + "/32", "via", dut_ip, "dev", r.wan_if))
        if bridge_created:
            # Restore the base rig's L3 path before its own teardown. The
            # independent console remains usable if bridge setup was partial.
            with Console.target(log_path=str(ARTIFACTS / "service-bridge-cleanup-uart.log")) as con:
                await asyncio.to_thread(con.login, "root", None)
                await attempt(console_command(con, "ip", "link", "set", TARGET_LAN_IF, "nomaster"))
                await attempt(console_command(con, "ip", "link", "del", BRIDGE))
                for address in original:
                    await attempt(console_command(con, "ip", "addr", "replace", address, "dev", TARGET_LAN_IF))
                await attempt(console_command(con, "ip", "route", "replace", r.lan_ip + "/32", "dev", TARGET_LAN_IF, "mtu", "1200"))
                await attempt(console_command(con, "ip", "neigh", "replace", r.lan_ip, "lladdr", r.lan_mac,
                                              "nud", "permanent", "dev", TARGET_LAN_IF))
        if lan_created:
            result = await attempt(lan_run_python(r.lan,
                f"import subprocess\nsubprocess.run(['ip', 'netns', 'del', {NETNS!r}], check=True)\n",
                label="service_bridge_cleanup", timeout=15))
            if result and result.rc:
                failures.append(result.stdout)
        final = await attempt(r.state())
        r.record("service-bridge-cleanup", final)
        if final and any(final[k] != baseline[k] for k in ("vlan_records", "vlan_slots", "errors")):
            failures.append({"baseline": baseline, "final": final})
        assert not failures, failures


async def membership(r):
    rows = json.loads((await console_command(r.service_console, "bridge", "-j", "vlan", "show", "dev", TARGET_LAN_IF))["stdout"])
    entries = [v for row in rows if row["ifname"] == TARGET_LAN_IF for v in row["vlans"]]
    return {vid: v.get("flags", []) for v in entries
            for vid in range(v["vlan"], v.get("vlanEnd", v["vlan"]) + 1)}


async def topology(r):
    result = {}
    for dev in (TRUST_IF, GUEST_IF):
        link = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", dev))["stdout"])[0]
        routes = json.loads((await command(r.target, r.session, "ip", "-j", "route", "show", "dev", dev))["stdout"])
        neighbours = json.loads((await command(r.target, r.session, "ip", "-j", "neigh", "show", "dev", dev))["stdout"])
        result[dev] = {"ifindex": link["ifindex"], "addresses": link["addr_info"], "routes": routes,
                       "pinned_neighbours": [n for n in neighbours if "PERMANENT" in n["state"]]}
    return result


def guest_rows(state):
    return [f for f in state["flows"] if f["src"].startswith(ADDRESS + ":") or f["dst"].startswith(ADDRESS + ":")]


def bridge_paths(state, r):
    for flow in state["flows"]:
        guest = flow in guest_rows(state)
        endpoint = ADDRESS if guest else r.lan_ip
        forward = flow["src"].startswith(endpoint + ":")
        logical = GUEST_IF if guest else TRUST_IF
        tag = str(GUEST_VID) if guest else "-"
        assert (flow["in_br"], flow["out_br"]) == ((logical, "-") if forward else ("-", logical)), flow
        assert (flow["in_vlan"], flow["out_vlan"]) == ((tag, "-") if forward else ("-", tag)), flow


async def test_flowtable_service_bridge_membership(bridge_service):
    r = bridge_service
    guest = {"lan": ADDRESS, "netns": NETNS}
    flows = [
        {"id": 0, "proto": "udp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 1, "proto": "tcp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 2, "proto": "udp", "sport": FIRST, **guest},
        {"id": 3, "proto": "tcp", "sport": FIRST, **guest},
        {"id": 4, "proto": "tcp", "sport": FIRST + 1, **guest},
        {"id": 5, "proto": "udp", "sport": FIRST + 2, "lan": r.lan_ip},
        {"id": 6, "proto": "udp", "sport": FIRST + 2, **guest},
    ]
    identity, service = await topology(r), await supervision_status(r)
    original_membership = await membership(r)
    assert TRUST_VID in original_membership and GUEST_VID in original_membership, original_membership
    # A reply on the existing guest UDP tuple must never reach its open
    # socket while membership is absent. The impossible serial fails the
    # receiver's payload checks if even one reverse-direction probe leaks.
    probe = payload(2, (1 << 63) - 1, 256)
    async with peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=300) as p:
        await warm(r, p, [0, 1, 2, 3], "service-bridge-baseline", flows[:4])
        initial = await hardware(r, p, "service-bridge-baseline-hardware", flows[:4])
        bridge_paths(initial, r)
        for ident in (5, 6):
            await denied(r, p, ident)
        for cycle in range(3):
            label = f"service-bridge-cycle-{cycle}"
            before, before_attempts = await r.state(), await attempts(r)
            await p.rpc("start", [2], count=0, interval=0.05, allow_loss=True)
            await p.rpc("start", [3], count=0, interval=0.05)
            samples, probes = [], 0
            try:
                await console_command(r.service_console, "bridge", "vlan", "del", "dev", TARGET_LAN_IF, "vid", str(GUEST_VID))
                removed_at = time.monotonic()
                await asyncio.sleep(0.2)  # in-flight traffic may finish
                absent_received = received(r, 2)
                retired = await r.wait(lambda s: not guest_rows(s), timeout=5)
                r.record(label + "-retired", retired)
                balanced(retired, initial["errors"])
                assert received(r, 2) == absent_received, "guest uplink survived membership removal"
                while time.monotonic() - removed_at < 6:
                    r.echo.transport.sendto(probe, (ADDRESS, FIRST))
                    probes += 1
                    await p.batch([0, 1], count=32, interval=0.01)
                    peer_state = await p.rpc("status")
                    assert not peer_state["errors"], ("guest downlink escaped membership filtering", peer_state)
                    state = await r.state()
                    samples.append({"seconds": time.monotonic() - removed_at, "state": state})
                    balanced(state, initial["errors"])
                    assert not guest_rows(state) and received(r, 2) == absent_received, state
                assert probes > 0
                held_membership = await membership(r)
                assert held_membership == {k: v for k, v in original_membership.items() if k != GUEST_VID}, held_membership
                assert await topology(r) == identity
                await denied(r, p, 5)
                r.record(label + "-absent", {"samples": samples, "membership": held_membership,
                    "reverse_probes": probes, "status": await service_status(r)})
            finally:
                # Inspect first so a lost deletion acknowledgement cannot
                # bypass restoration. Restore membership only, never policy.
                if GUEST_VID not in await membership(r):
                    await console_command(r.service_console, "bridge", "vlan", "add", "dev", TARGET_LAN_IF, "vid", str(GUEST_VID))
            restored_at = time.monotonic()
            reports = await p.rpc("stop", [2, 3])
            r.record(label + "-transfers", reports)
            assert reports["2"]["lost"] > 0 and reports["3"]["lost"] == 0, reports
            assert reports["3"]["count"] > 0, reports
            status = await wait_service(r, timeout=20, policy_hash=r.service_hash)
            await warm(r, p, [0, 1, 2, 3], label + "-readmitted", flows[:4])
            ready_seconds = time.monotonic() - restored_at
            assert ready_seconds < 20, (ready_seconds, status)
            after = await hardware(r, p, label + "-hardware", flows[:4])
            hardware_seconds = time.monotonic() - restored_at
            assert hardware_seconds < 40, hardware_seconds
            balanced(after, initial["errors"])
            bridge_paths(after, r)
            assert after["rearms"] > before["rearms"], (before, after)
            assert all(after[k] == initial[k] for k in ("vlan_records", "vlan_slots")), (initial, after)
            after_attempts = await attempts(r)
            assert 1 <= after_attempts - before_attempts <= 4, (before_attempts, after_attempts)
            await p.batch([0, 1, 2, 3], count=128, interval=0.045)
            quiet = await r.state()
            unchanged(after, quiet, [0, 1, 2, 3], flows)
            assert quiet["installs"] == after["installs"] and quiet["deletes"] == after["deletes"], (after, quiet)
            assert await attempts(r) == after_attempts
            for ident in (5, 6):
                await denied(r, p, ident)
            assert await membership(r) == original_membership
            assert await topology(r) == identity
            assert await supervision_status(r) == service
            assert (await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")).strip() == r.service_boot
            r.record(label + "-recovery", {"before": before, "after": after, "quiet": quiet,
                "ready_seconds": ready_seconds, "hardware_seconds": hardware_seconds,
                "install_attempts": after_attempts - before_attempts, "transfers": reports})
        await p.rpc("open", [4])
        await warm(r, p, [0, 1, 2, 3, 4], "service-bridge-new-connection", flows[:5])
        final = await hardware(r, p, "service-bridge-new-hardware", flows[:5])
        bridge_paths(final, r)
        for ident in (5, 6):
            await denied(r, p, ident)

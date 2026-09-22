"""Recover persistent connections when a routed VLAN disappears and returns."""
from __future__ import annotations

import asyncio
import json
import os
import struct
import time

import pytest_asyncio

from ask_orch.client import Agent
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import peer
from test_flowtable_offload import DPORT, WAN_IP, command, console_command, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, unchanged, warm
from test_flowtable_service import (FAULT_DIR, FIRST, managed_service, service_status,
                                    supervision_status, wait_service)

VID = 284
DUT_IF = f"{TARGET_LAN_IF}.{VID}"
LAN_IF = "askftvlan"
NETNS = "ask-ft-service-vlan"
GATEWAY, ADDRESS = "172.29.84.1", "172.29.84.2"


async def create_vlan(r, *, console=False):
    async def run(*args):
        if console:
            return await console_command(r.service_console, *args)
        return await command(r.target, r.session, *args)

    await run("ip", "link", "add", "link", TARGET_LAN_IF, "name", DUT_IF,
              "type", "vlan", "id", str(VID))
    r.service_vlan_created = True
    await run("ip", "addr", "add", GATEWAY + "/24", "dev", DUT_IF)
    await run("ip", "link", "set", "dev", DUT_IF, "up")
    await run("ip", "route", "add", ADDRESS + "/32", "dev", DUT_IF, "mtu", "1200")
    await run("ip", "neigh", "replace", ADDRESS, "lladdr", r.lan_mac,
              "nud", "permanent", "dev", DUT_IF)


@pytest_asyncio.fixture
async def vlan_service(rig):
    r = rig
    r.service_vlan_created = False
    r.service_vlan_records_before = (await r.state())["vlan_records"]
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    lan_created = wan_route = False
    links = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show"))["stdout"])
    assert DUT_IF not in {link["ifname"] for link in links}, links
    routes = json.loads((await command(wan, r.session, "ip", "-j", "route", "show", "exact", ADDRESS + "/32"))["stdout"])
    assert not routes, routes
    dut_wan = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_WAN_IF))["stdout"])
    dut_ip = next(a["local"] for a in dut_wan[0]["addr_info"] if a["family"] == "inet")
    try:
        await create_vlan(r)
        # The peer namespace routes its sockets over the VLAN while the
        # control connection and unaffected sockets keep the normal LAN path.
        setup = f'''
from pathlib import Path
import subprocess
def run(*args): subprocess.run(args, check=True, capture_output=True, text=True)
assert not Path('/var/run/netns/' + {NETNS!r}).exists()
assert not Path('/sys/class/net/' + {LAN_IF!r}).exists()
run('ip', 'netns', 'add', {NETNS!r})
try:
    run('ip', 'link', 'add', 'link', {LAN_NIC!r}, 'name', {LAN_IF!r},
        'netns', {NETNS!r}, 'type', 'vlan', 'id', {str(VID)!r})
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
        result = await lan_run_python(r.lan, setup, label="service_vlan_setup", timeout=20)
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
        if r.service_vlan_created:
            await attempt(command(r.target, r.session, "ip", "link", "del", DUT_IF))
        if lan_created:
            result = await attempt(lan_run_python(r.lan,
                f"import subprocess\nsubprocess.run(['ip', 'netns', 'del', {NETNS!r}], check=True)\n",
                label="service_vlan_cleanup", timeout=15))
            if result and result.rc:
                failures.append(result.stdout)
        final = await attempt(r.state())
        r.record("service-vlan-cleanup", final)
        if final and final["vlan_records"] != r.service_vlan_records_before:
            failures.append({"vlan_records": final})
        assert not failures, failures


def received(r, ident):
    return sum(count for data, count in r.echo.received.items()
               if len(data) >= 4 and struct.unpack("!I", data[:4])[0] == ident)


async def denied(r, p, ident):
    before = received(r, ident)
    await p.rpc("start", [ident], count=4, interval=0.01, allow_loss=True, udp_timeout=0.1)
    result = (await p.rpc("wait", [ident]))[str(ident)]
    assert result["received"] == 0 and result["lost"] == 4, result
    assert received(r, ident) == before, "forbidden UDP reached WAN"
    return result


async def attempts(r):
    return len((await read(r.target, r.session, FAULT_DIR + "/attempts")).splitlines())


def tagged(state):
    return [f for f in state["flows"]
            if f["src"].startswith(ADDRESS + ":") or f["dst"].startswith(ADDRESS + ":")]


def balanced(state, errors):
    assert state["errors"] == errors and state["fatal"] == state["quarantine"] == 0, state
    assert state["installs"] - state["deletes"] == state["entries"], state
    assert state["entries"] == state["handle_refs"] == state["neighbour_refs"] == len(state["flows"]), state


async def test_flowtable_service_vlan_recreation(vlan_service):
    r = vlan_service
    vlan = {"lan": ADDRESS, "netns": NETNS}
    flows = [
        {"id": 0, "proto": "udp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 1, "proto": "tcp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 2, "proto": "udp", "sport": FIRST, **vlan},
        {"id": 3, "proto": "tcp", "sport": FIRST, **vlan},
        {"id": 4, "proto": "tcp", "sport": FIRST + 1, **vlan},
        {"id": 5, "proto": "udp", "sport": FIRST + 2, "lan": r.lan_ip},
        {"id": 6, "proto": "udp", "sport": FIRST + 2, **vlan},
    ]
    service = await supervision_status(r)
    async with peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=300) as p:
        await warm(r, p, [0, 1, 2, 3], "service-vlan-baseline", flows[:4])
        initial = await hardware(r, p, "service-vlan-baseline-hardware", flows[:4])
        for ident in (5, 6):
            await denied(r, p, ident)
        for cycle in range(3):
            label = f"service-vlan-cycle-{cycle}"
            before = await r.state()
            old_index = (await read(r.target, r.session, f"/sys/class/net/{DUT_IF}/ifindex")).strip()
            before_attempts = await attempts(r)
            await p.rpc("start", [2], count=0, interval=0.05, allow_loss=True)
            await p.rpc("start", [3], count=0, interval=0.05)
            samples = []
            try:
                await console_command(r.service_console, "ip", "link", "del", DUT_IF)
                r.service_vlan_created = False
                removed_at = time.monotonic()
                retired = await r.wait(lambda s: not tagged(s) and s["vlan_records"] == r.service_vlan_records_before,
                                       timeout=5)
                r.record(label + "-retired", retired)
                balanced(retired, initial["errors"])
                # Allow in-flight packets to drain, then require zero VLAN
                # delivery while untagged control traffic continues to work.
                await asyncio.sleep(0.2)
                absent_received = received(r, 2)
                while time.monotonic() - removed_at < 6:
                    await p.batch([0, 1], count=32, interval=0.01)
                    state = await r.state()
                    samples.append({"seconds": time.monotonic() - removed_at, "state": state})
                    balanced(state, initial["errors"])
                    assert not tagged(state) and received(r, 2) == absent_received, state
                missing = await r.target.fs_read(r.session, f"/sys/class/net/{DUT_IF}/ifindex")
                assert missing["errno"] == 2, "controller recreated the missing VLAN"
                await denied(r, p, 5)
                r.record(label + "-absent", {"samples": samples, "status": await service_status(r)})
            finally:
                # Restore only the network prerequisite, through independent
                # UART. All admission repair belongs to the running service.
                # Inspect actual state even if deletion lost its acknowledgement.
                links = json.loads((await console_command(r.service_console, "ip", "-j", "link", "show"))["stdout"])
                r.service_vlan_created = DUT_IF in {link["ifname"] for link in links}
                if not r.service_vlan_created:
                    await create_vlan(r, console=True)
            restored_at = time.monotonic()
            reports = await p.rpc("stop", [2, 3])
            r.record(label + "-transfers", reports)
            assert reports["2"]["lost"] > 0 and reports["3"]["lost"] == 0, reports
            assert reports["3"]["count"] > 0, reports
            new_index = (await read(r.target, r.session, f"/sys/class/net/{DUT_IF}/ifindex")).strip()
            assert new_index != old_index, (old_index, new_index)
            status = await wait_service(r, timeout=20, policy_hash=r.service_hash)
            ready = await warm(r, p, [0, 1, 2, 3], label + "-readmitted", flows[:4])
            ready_seconds = time.monotonic() - restored_at
            assert ready_seconds < 20, (ready_seconds, status, ready)
            after = await hardware(r, p, label + "-hardware", flows[:4])
            hardware_seconds = time.monotonic() - restored_at
            assert hardware_seconds < 40, hardware_seconds
            balanced(after, initial["errors"])
            assert after["vlan_records"] == initial["vlan_records"], (initial, after)
            for flow in tagged(after):
                tags = (flow["in_vlan"], flow["out_vlan"])
                assert tags == ((str(VID), "-") if flow["in"] == TARGET_LAN_IF else ("-", str(VID))), flow
            after_attempts = await attempts(r)
            assert 0 <= after_attempts - before_attempts <= 4, (before_attempts, after_attempts)
            # Cover a complete health-check period after convergence: the
            # controller must stop reinstalling a healthy, unchanged policy.
            await p.batch([0, 1, 2, 3], count=128, interval=0.045)
            quiet = await r.state()
            unchanged(after, quiet, [0, 1, 2, 3], flows)
            assert quiet["installs"] == after["installs"] and quiet["deletes"] == after["deletes"], (after, quiet)
            assert await attempts(r) == after_attempts
            for ident in (5, 6):
                await denied(r, p, ident)
            assert await supervision_status(r) == service
            assert (await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")).strip() == r.service_boot
            r.record(label + "-recovery", {"before": before, "after": after, "quiet": quiet,
                "old_ifindex": old_index, "new_ifindex": new_index, "ready_seconds": ready_seconds,
                "hardware_seconds": hardware_seconds, "install_attempts": after_attempts - before_attempts,
                "status": status, "transfers": reports})
        await p.rpc("open", [4])
        await warm(r, p, [0, 1, 2, 3, 4], "service-vlan-new-connection", flows[:5])
        await hardware(r, p, "service-vlan-new-hardware", flows[:5])
        for ident in (5, 6):
            await denied(r, p, ident)

"""Take a bridge port, or one VLAN of it, out of forwarding and back without
repairing admission: revoked membership, a blocked port and a blocked VLAN."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import errno
import json
import os
import struct
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from flowtable_connections_peer import payload
from test_flowtable_connections import peer
from test_flowtable_offload import (ARTIFACTS, DPORT, SPORT, TABLE, WAN_IP, command, console_command,
                                    read, rig)  # noqa: F401
from test_flowtable_selective_neighbour import hardware, unchanged, warm
from test_flowtable_service import FIRST, managed_service, service_status, supervision_status, wait_service
from test_flowtable_service_vlan import attempts, balanced, denied, received

BRIDGE = "br-ftsvc"
TRUST_VID, GUEST_VID = 285, 286
TRUST_IF, GUEST_IF = f"{BRIDGE}.{TRUST_VID}", f"{BRIDGE}.{GUEST_VID}"
NETNS, LAN_IF = "ask-ft-service-guest", "askftguest"
GATEWAY, ADDRESS = "172.29.86.1", "172.29.86.2"
# The user-space STP entry point the kernel runs when STP is switched on, and
# a second bridge port that keeps the bridge's carrier while the LAN port is
# blocked.
STP_HELPER, STP_STUB = "/sbin/bridge-stp", "#!/bin/sh\nexit 0\n"
CARRIER_PORT = "askftstp"
# The tail of every reply-tuple probe. The LAN wire probe counts it whichever
# socket, if any, a leaked probe reaches.
MARKER = (b"ASK-BLOCKED-PORT-PROBE-" * 11)[:244]


@asynccontextmanager
async def bridge_topology(r, *, guest=True):
    """br-ftsvc over the LAN port, VLAN-filtering, with the trusted VLAN
    untagged on the port and routed on br-ftsvc.285. `guest` adds the tagged
    guest VLAN routed on br-ftsvc.286 and its station in a LAN-VM namespace."""
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
    vlans = [(TRUST_VID, TRUST_IF, original)] + ([(GUEST_VID, GUEST_IF, [GATEWAY + "/24"])] if guest else [])
    hosts = [(r.lan_ip, TRUST_IF)] + ([(ADDRESS, GUEST_IF)] if guest else [])

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
        if guest:
            await dut("bridge", "vlan", "add", "dev", TARGET_LAN_IF, "vid", str(GUEST_VID))
        for vid, dev, cidrs in vlans:
            await dut("bridge", "vlan", "add", "dev", BRIDGE, "vid", str(vid), "self")
            await dut("ip", "link", "add", "link", BRIDGE, "name", dev, "type", "vlan", "id", str(vid))
            for address in cidrs:
                await dut("ip", "addr", "add", address, "dev", dev)
            await dut("ip", "link", "set", dev, "up")
        for address, dev in hosts:
            await dut("ip", "route", "replace", address + "/32", "dev", dev, "mtu", "1200")
            await dut("ip", "neigh", "replace", address, "lladdr", r.lan_mac, "nud", "permanent", "dev", dev)
        if not guest:
            yield
            return
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
        yield
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


@pytest_asyncio.fixture
async def bridge_service(rig):
    r = rig
    async with bridge_topology(r):
        async with managed_service(r, addresses=(r.lan_ip, ADDRESS)):
            yield r


@pytest_asyncio.fixture
async def bridge_software(rig):
    """The bridge with no service and no guest: the rig's own flowtable, which
    a test builds without hardware offload."""
    r = rig
    async with bridge_topology(r, guest=False):
        yield r


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


async def port_state(r, port=TARGET_LAN_IF):
    rows = json.loads((await command(r.target, r.session, "bridge", "-j", "link", "show", "dev", port))["stdout"])
    return rows[0]["state"]


async def vlan_states(r):
    """Each VLAN's own STP state on the LAN port, as `bridge -d vlan` has it."""
    rows = json.loads((await command(r.target, r.session, "bridge", "-j", "-d", "vlan", "show",
                                     "dev", TARGET_LAN_IF))["stdout"])
    entries = [v for row in rows if row["ifname"] == TARGET_LAN_IF for v in row["vlans"]]
    return {vid: v.get("state") for v in entries
            for vid in range(v["vlan"], v.get("vlanEnd", v["vlan"]) + 1)}


async def offloaded(r, lan, sport):
    """Whether conntrack holds the UDP connection in a flowtable, in software
    ([OFFLOAD]) or in hardware ([HW_OFFLOAD])."""
    listing = await command(r.target, r.session, "conntrack", "-L", "-p", "udp", "--orig-src", lan,
                            "--orig-dst", WAN_IP, "--sport", str(sport), "--dport", str(DPORT), check=False)
    return "OFFLOAD]" in listing["stdout"]


async def settle(r, streams, sport, timeout=5):
    """Wait for the connections a block retired to leave the flowtable. Both
    the hardware retirement and the software sweep run after the state
    change, not in it."""
    deadline = time.monotonic() + timeout
    while True:
        cached = {ident: await offloaded(r, lan, sport) for ident, lan in streams.items()}
        if not any(cached.values()):
            return
        assert time.monotonic() < deadline, ("a flow through the stopped port stayed cached", cached)
        await asyncio.sleep(0.1)


def reply_probe(ident):
    """A datagram on a connection's reply tuple that its socket can never
    accept: the serial lies outside every range the connection sends, so a
    leaked one fails the stream reading it, and the tail is the marker the LAN
    wire probe counts."""
    return struct.pack("!IQ", ident, (1 << 63) - 1) + MARKER


@asynccontextmanager
async def pinned(r, vids):
    """Pin the LAN station's address to the LAN port in each VLAN. A port or
    VLAN that stops forwarding stops learning too, and an entry that aged out
    meanwhile would make the forward-path walk miss rather than refuse."""
    done = []
    try:
        for vid in vids:
            await command(r.target, r.session, "bridge", "fdb", "replace", r.lan_mac, "dev", TARGET_LAN_IF,
                          "master", "static", "vlan", str(vid))
            done.append(vid)
        yield
    finally:
        failures = []
        for vid in done:
            result = await command(r.target, r.session, "bridge", "fdb", "del", r.lan_mac, "dev", TARGET_LAN_IF,
                                   "master", "vlan", str(vid), check=False)
            if result["rc"]:
                failures.append(result)
        assert not failures, failures


@asynccontextmanager
async def blockable(r, con):
    """Make the LAN port's STP state the test's to set, and to keep.

    With STP off, br_set_port_state() goes on to br_port_state_selection(),
    which finds every port designated and puts it straight back to
    FORWARDING: `bridge link set ... state 4` never outlives the command.
    User-space STP leaves port states to user space, and the kernel starts it
    only once /sbin/bridge-stp answers "start" with success -- so a stub that
    always succeeds stands in for the daemon. A dummy port, enslaved while STP
    is still off so that it forwards, keeps the bridge's carrier: a bridge with
    no forwarding port drops it, and the link retirement that follows would
    race the one under test."""
    existing = await r.target.fs_read(r.session, STP_HELPER, max_bytes=4096)
    assert existing["errno"] == errno.ENOENT or (
        existing["errno"] == 0 and bytes.fromhex(existing["content_hex"]).decode() == STP_STUB), existing
    links = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show"))["stdout"])
    assert CARRIER_PORT not in {link["ifname"] for link in links}, links
    undo = []
    try:
        await command(r.target, r.session, "modprobe", "dummy", "numdummies=0")
        await command(r.target, r.session, "ip", "link", "add", CARRIER_PORT, "type", "dummy")
        undo.append(("ip", "link", "del", CARRIER_PORT))
        await command(r.target, r.session, "ip", "link", "set", CARRIER_PORT, "master", BRIDGE)
        await command(r.target, r.session, "ip", "link", "set", CARRIER_PORT, "up")
        # The port is enabled once link watch reports it operational, which
        # trails the command; with user-space STP on, it would stay blocked.
        deadline = time.monotonic() + 5
        while (state := await port_state(r, CARRIER_PORT)) != "forwarding":
            assert time.monotonic() < deadline, state
            await asyncio.sleep(0.1)
        undo.append(("rm", "-f", STP_HELPER))
        written = await r.target.fs_write(r.session, STP_HELPER, STP_STUB)
        assert written["errno"] == 0, written
        await console_command(con, "chmod", "755", STP_HELPER)
        undo.append(("ip", "link", "set", BRIDGE, "type", "bridge", "stp_state", "0"))
        await command(r.target, r.session, "ip", "link", "set", BRIDGE, "type", "bridge", "stp_state", "1")
        # 2 is user-space STP. 1 would be the kernel's own, which refuses a
        # port state set from outside.
        mode = (await read(r.target, r.session, f"/sys/class/net/{BRIDGE}/bridge/stp_state")).strip()
        assert mode == "2", mode
        assert await port_state(r) == "forwarding"
        yield
    finally:
        failures = []
        # Forwarding again before STP stops, because stopping user-space STP
        # leaves a blocked port blocked; the helper goes only after the stop,
        # which runs it.
        for argv in [("bridge", "link", "set", "dev", TARGET_LAN_IF, "state", "3")] + undo[::-1]:
            try:
                result = await console_command(con, *argv, check=False)
                if result["rc"]:
                    failures.append(result)
            except Exception as error:
                failures.append(repr(error))
        assert not failures, failures


async def blocked_window(r, streams, sport, label, seconds=6, check=None):
    """Hold a block for `seconds` while both directions of every stream keep
    trying: the LAN side sends throughout, and the WAN side answers on each
    reply tuple. Neither may cross, nor may any of the connections be cached
    in a flowtable. No RPC to the peer here -- its control connection may
    cross the stopped port too."""
    await settle(r, streams, sport)
    before = {ident: received(r, ident) for ident in streams}
    started, samples = time.monotonic(), []
    while time.monotonic() - started < seconds:
        for ident, lan in streams.items():
            r.echo.transport.sendto(reply_probe(ident), (lan, sport))
        await asyncio.sleep(0.2)
        state = await r.state()
        cached = {ident: await offloaded(r, lan, sport) for ident, lan in streams.items()}
        samples.append({"seconds": time.monotonic() - started, "state": state, "cached": cached})
        assert not any(cached.values()), ("a flow through the stopped port was cached", samples[-1])
        assert {ident: received(r, ident) for ident in streams} == before, (
            "a LAN datagram crossed the stopped port", before)
        if check:
            check(state)
    r.record(label, samples)


async def crossed_nothing(r, p, streams, label):
    """After the block: nothing the WAN sent reached the LAN wire, no stream
    met a reply it did not send, and every stream lost what it sent while
    blocked."""
    wire = await p.rpc("wire_probe", changes={"action": "status"})
    await p.rpc("wire_probe", changes={"action": "stop"})
    peer_state = await p.rpc("status")
    r.record(label, {"wire": wire, "peer": peer_state})
    assert wire["received"] == 0, ("a reply crossed the stopped port", wire)
    # Before stopping: a stream that met a stray reply has failed, and
    # stopping it would take the peer down with the error.
    assert not peer_state["errors"], ("a reply reached a stream", peer_state)
    reports = await p.rpc("stop", list(streams))
    r.record(label + "-streams", reports)
    assert all(report["lost"] > 0 for report in reports.values()), reports


async def test_flowtable_service_bridge_stp(bridge_service):
    """A port that stops forwarding takes every flow bridged through it out of
    hardware at once, since the classifier has no idea of a port state and
    would go on bridging through a blocked port. Nothing is cached while it
    stays blocked, in either direction, and traffic alone readmits every
    connection once it forwards again."""
    r = bridge_service
    guest = {"lan": ADDRESS, "netns": NETNS}
    flows = [
        {"id": 0, "proto": "udp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 1, "proto": "tcp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 2, "proto": "udp", "sport": FIRST, **guest},
        {"id": 3, "proto": "tcp", "sport": FIRST, **guest},
    ]
    streams = {0: r.lan_ip, 2: ADDRESS}
    service = await supervision_status(r)
    async with pinned(r, (TRUST_VID, GUEST_VID)), blockable(r, r.service_console), \
            peer(r, flows, initial_ids=[0, 1, 2, 3], lease=300) as p:
        await warm(r, p, [0, 1, 2, 3], "service-bridge-stp-baseline", flows)
        initial = await hardware(r, p, "service-bridge-stp-baseline-hardware", flows)
        bridge_paths(initial, r)
        await p.rpc("wire_probe", changes={"action": "start", "iface": LAN_NIC, "marker": MARKER[:32].hex()})
        await p.rpc("start", list(streams), count=0, interval=0.05, allow_loss=True)
        try:
            await command(r.target, r.session, "bridge", "link", "set", "dev", TARGET_LAN_IF, "state", "4")
            # It has to hold: with STP off the kernel would already have put
            # the port back to forwarding.
            assert await port_state(r) == "blocking"
            retired = await r.wait(lambda s: not s["flows"], timeout=5)
            r.record("service-bridge-stp-retired", retired)
            balanced(retired, initial["errors"])
            # One retirement per connection: both directions share a handle.
            assert retired["stp_invalidations"] - initial["stp_invalidations"] == len(flows), (initial, retired)

            def nothing_admitted(state):
                balanced(state, initial["errors"])
                assert not state["flows"], state
            await blocked_window(r, streams, FIRST, "service-bridge-stp-blocked", check=nothing_admitted)
            assert await port_state(r) == "blocking"
        finally:
            if await port_state(r) != "forwarding":
                await command(r.target, r.session, "bridge", "link", "set", "dev", TARGET_LAN_IF, "state", "3")
        restored_at = time.monotonic()
        await crossed_nothing(r, p, streams, "service-bridge-stp-crossed")
        await warm(r, p, [0, 1, 2, 3], "service-bridge-stp-readmitted", flows)
        assert time.monotonic() - restored_at < 20
        after = await hardware(r, p, "service-bridge-stp-hardware", flows)
        balanced(after, initial["errors"])
        bridge_paths(after, r)
        assert after["stp_invalidations"] == retired["stp_invalidations"], (retired, after)
        assert all(after[k] == initial[k] for k in ("vlan_records", "vlan_slots")), (initial, after)
        assert await supervision_status(r) == service
        r.record("service-bridge-stp-recovery", {"initial": initial, "retired": retired, "after": after})


async def test_flowtable_service_bridge_vlan_state(bridge_service):
    """One VLAN of a port can stop forwarding while the port and its other
    VLAN go on: a per-VLAN STP state, which the kernel accepts with spanning
    tree off and keeps, unlike a port state. It reaches hardware as an event of
    its own, which nothing raised before. The blocked VLAN's connections leave
    hardware and are cached nowhere, in either direction; the other VLAN keeps
    forwarding through the same port and returns to hardware; and traffic alone
    readmits the blocked VLAN's connections once it forwards again."""
    r = bridge_service
    guest = {"lan": ADDRESS, "netns": NETNS}
    flows = [
        {"id": 0, "proto": "udp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 1, "proto": "tcp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 2, "proto": "udp", "sport": FIRST, **guest},
        {"id": 3, "proto": "tcp", "sport": FIRST, **guest},
    ]
    streams = {2: ADDRESS}
    service = await supervision_status(r)
    assert (await vlan_states(r))[GUEST_VID] == "forwarding"
    async with pinned(r, (TRUST_VID, GUEST_VID)), peer(r, flows, initial_ids=[0, 1, 2, 3], lease=300) as p:
        await warm(r, p, [0, 1, 2, 3], "service-bridge-vlan-state-baseline", flows)
        initial = await hardware(r, p, "service-bridge-vlan-state-baseline-hardware", flows)
        await p.rpc("wire_probe", changes={"action": "start", "iface": LAN_NIC, "marker": MARKER[:32].hex()})
        await p.rpc("start", list(streams), count=0, interval=0.05, allow_loss=True)
        try:
            await command(r.target, r.session, "bridge", "vlan", "set", "dev", TARGET_LAN_IF,
                          "vid", str(GUEST_VID), "state", "blocking")
            states = await vlan_states(r)
            assert states[GUEST_VID] == "blocking" and states[TRUST_VID] == "forwarding", states
            assert await port_state(r) == "forwarding"
            retired = await r.wait(lambda s: not guest_rows(s), timeout=5)
            r.record("service-bridge-vlan-state-retired", retired)
            balanced(retired, initial["errors"])
            # The whole port's connections: rules are not mapped onto VLANs.
            assert retired["stp_invalidations"] - initial["stp_invalidations"] == len(flows), (initial, retired)

            def guest_absent(state):
                balanced(state, initial["errors"])
                assert not guest_rows(state), state
            await blocked_window(r, streams, FIRST, "service-bridge-vlan-state-blocked", check=guest_absent)
            # The trusted VLAN forwards through the same port all along -- the
            # peer's control connection runs on it -- and returns to hardware
            # while the guest VLAN is still blocked.
            await p.batch([0, 1], count=64, interval=0.01)
            trusted = await r.wait(lambda s: len(s["flows"]) == 4 and not guest_rows(s), timeout=10)
            r.record("service-bridge-vlan-state-trusted", trusted)
            assert (await vlan_states(r))[GUEST_VID] == "blocking"
        finally:
            if (await vlan_states(r)).get(GUEST_VID) != "forwarding":
                await command(r.target, r.session, "bridge", "vlan", "set", "dev", TARGET_LAN_IF,
                              "vid", str(GUEST_VID), "state", "forwarding")
        restored_at = time.monotonic()
        await crossed_nothing(r, p, streams, "service-bridge-vlan-state-crossed")
        await warm(r, p, [0, 1, 2, 3], "service-bridge-vlan-state-readmitted", flows)
        assert time.monotonic() - restored_at < 20
        after = await hardware(r, p, "service-bridge-vlan-state-hardware", flows)
        balanced(after, initial["errors"])
        bridge_paths(after, r)
        assert all(after[k] == initial[k] for k in ("vlan_records", "vlan_slots")), (initial, after)
        assert await supervision_status(r) == service
        r.record("service-bridge-vlan-state-recovery", {"initial": initial, "retired": retired, "after": after})


@pytest.mark.parametrize("offload", [False, True], ids=["software", "hardware"])
async def test_flowtable_bridge_stp_fastpath(bridge_software, offload):
    """The same block against a flowtable that offers a flow on any
    established packet, in either direction, as fw4's does. That is what lets
    a reply from the WAN cache a flow through the blocked port, and the
    flowtable's hook on the port runs before br_handle_frame(), so such a flow
    would carry the port's received frames past the block. Without hardware
    offload the bridge hop is also a DIRECT transmit, which goes out of the
    port past br_forward(); and nothing but the adapter's sweep takes away a
    software flow cached before the block. With it, the flow is in hardware
    and the adapter's own retirement takes it."""
    r = bridge_software
    flows = [{"id": 0, "proto": "udp", "sport": SPORT, "lan": r.lan_ip}]
    streams = {0: r.lan_ip}
    label = "bridge-stp-" + ("hardware" if offload else "software")
    await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; {"flags offload;" if offload else ""} }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 meta l4proto udp ct original ip saddr {r.lan_ip} ct original ip daddr {WAN_IP} ct original proto-src {SPORT} ct original proto-dst {DPORT} ct state established flow add @fast
 }}
}}''')
    bound = await r.wait(lambda s: s["bindings"] == (2 if offload else 0))
    with Console.target(log_path=str(ARTIFACTS / "bridge-stp-fastpath-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        async with pinned(r, (TRUST_VID,)), blockable(r, con), peer(r, flows, lease=180) as p:
            await p.batch([0], count=64, interval=0.01)
            assert await offloaded(r, r.lan_ip, SPORT), "the flowtable never took the connection"
            if offload:
                admitted = await r.wait(lambda s: s["entries"] == 2)
                assert admitted["installs"] > bound["installs"], (bound, admitted)
            await p.rpc("wire_probe", changes={"action": "start", "iface": LAN_NIC, "marker": MARKER[:32].hex()})
            await p.rpc("start", list(streams), count=0, interval=0.05, allow_loss=True)
            try:
                await command(r.target, r.session, "bridge", "link", "set", "dev", TARGET_LAN_IF, "state", "4")
                assert await port_state(r) == "blocking"

                def nothing_admitted(state):
                    assert not state["flows"], state
                await blocked_window(r, streams, SPORT, label + "-blocked", check=nothing_admitted)
                assert await port_state(r) == "blocking"
            finally:
                if await port_state(r) != "forwarding":
                    await command(r.target, r.session, "bridge", "link", "set", "dev", TARGET_LAN_IF, "state", "3")
            await crossed_nothing(r, p, streams, label + "-crossed")
            # Traffic alone caches it again.
            await p.batch([0], count=64, interval=0.01)
            assert await offloaded(r, r.lan_ip, SPORT), "the connection was not cached again"
            if offload:
                await r.wait(lambda s: s["entries"] == 2)

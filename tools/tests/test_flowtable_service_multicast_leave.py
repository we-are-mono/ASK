"""A listener leaves: the hardware follows the bridge's membership down.

Every way a membership ends is covered -- an IGMPv2 leave, IGMPv3's TO_IN({})
for an any-source membership and BLOCK for a source-specific one or a refused
source, an MLDv1 done, and a host that simply stops answering the querier --
and each has to end the same way:

  - while another listener remains, it keeps receiving every frame, in
    hardware, with the group untouched;
  - once nothing on a port wants the stream, the hardware stops sending it
    there, and a group with no listener left is removed;
  - nothing is leaked: the adapter's group and installed counts come back to
    where they started, and nothing is parked.

Two shapes, because the rig decides what "another listener" can be. The board
has two ports with carrier and one of them is always the ingress, so a bridged
group has exactly one listener port. There the second listener is a second
host behind that same port, and the port's own leave is the group's removal.
A routed group expanding through a snooping bridge sees each VLAN on that port
as a listener of its own, so there one listener's leave is a chain swap under
a live stream and the other keeps its copies.

The bridge timers the leave and the expiry run on are shortened on the test
bridges only, and put back.
"""
from __future__ import annotations

import asyncio
from collections import namedtuple
from contextlib import AsyncExitStack, asynccontextmanager
import json

import pytest
import pytest_asyncio

from _mcast_windows import (COUNT, bridge_settings, delivered, host, in_hardware, in_software,
                            learn, mcast_rows, mdb, mdb_ports, members, moved, mroute_row,
                            multicast_rig, packets, same, silenced, stream, streamed,  # noqa: F401
                            summary, trickle)
from _topology import (LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, TopologyStack, dut_vlan_subif,
                       lan_vlan_subif)
from test_flowtable_offload import command
from test_mcast_e2e import dut_mac, mcast_bridge, wan_source_address  # noqa: F401
from test_mroute_capacity import _daemon, _python

# How a membership ends, and what the host does to end it. `mode` is the
# filter mode it joined in; `end` is the socket call, or `silence` for a host
# that stops reporting without leaving.
MECHANISMS = {
    "igmpv2-leave": dict(family=4, version=2, mode="asm", end="leave"),
    "igmpv3-to-in": dict(family=4, version=3, mode="asm", end="leave"),
    "mldv1-done": dict(family=6, version=1, mode="asm", end="leave"),
    "expiry": dict(family=4, version=2, mode="asm", end="silence"),
    "igmpv3-block": dict(family=4, version=3, mode="asm", end="block"),
    "igmpv3-ssm-block": dict(family=4, version=3, mode="ssm", end="leave"),
}
BRIDGED_GROUP = {4: "239.9.8.1", 6: "ff1e::9:8:1"}
ROUTED_GROUP = {4: "239.9.8.2", 6: "ff1e::9:8:2"}
FILTER_GROUP = {4: "239.9.8.3", 6: "ff1e::9:8:3"}
BLOCK_GROUP = {4: "239.9.8.4", 6: "ff1e::9:8:4"}
# A second sender of a bridged group. The bridge validates no source, so any
# address the WAN segment could carry will do.
OTHER_SOURCE = {4: "198.18.166.2", 6: "fd00:166::2"}
# The source-filtering reports: IGMPv3 and MLDv2, with the querier speaking
# them. A blocked source is blocked once its group-and-source query goes
# unanswered, two queries a second apart.
FILTER_TIMERS = dict(igmp_version=3, mld_version=2, last_member_count=2, last_member_interval=100)
FILTER_VERSION = {4: 3, 6: 2}
SECOND_HOST = "askmcb"
LISTENER_BRIDGE = "br-askmcl"
VID_LEFT, VID_KEPT = 321, 322
# Source-specific handling needs the querier speaking IGMPv3. The last-member
# queries a leave provokes are pinned at two, a second apart, so the waits
# below do not depend on what the bridge was created with.
LEAVE_TIMERS = dict(igmp_version=3, last_member_count=2, last_member_interval=100)

ListenerBridge = namedtuple("ListenerBridge", "name left kept lan_left lan_kept")


async def end(stack, member, spec, iface):
    if spec["end"] == "silence":
        await stack.enter_async_context(silenced(member.lan, iface))
    else:
        await member.do(spec["end"])


@asynccontextmanager
async def second_host(lan):
    """A second receiver behind the same LAN port, with its own MAC.

    A macvlan answers the querier from its own address, so the bridge sees
    two hosts' reports arriving on one port -- which is all a second set-top
    box behind a dumb switch is."""
    await _python(lan, f"""
import pathlib, subprocess, time
def run(*args): subprocess.run(args, check=True, capture_output=True, text=True)
assert not pathlib.Path('/sys/class/net/{SECOND_HOST}').exists()
run('ip', 'link', 'add', 'link', {LAN_NIC!r}, 'name', {SECOND_HOST!r}, 'type', 'macvlan', 'mode', 'bridge')
# MLD reports need a usable link-local address the moment the host joins.
pathlib.Path('/proc/sys/net/ipv6/conf/{SECOND_HOST}/accept_dad').write_text('0')
run('ip', 'link', 'set', {SECOND_HOST!r}, 'up')
for _ in range(50):
    if 'scope link' in subprocess.check_output(['ip', '-6', 'addr', 'show', 'dev', {SECOND_HOST!r}], text=True):
        break
    time.sleep(0.1)
else:
    raise AssertionError('no link-local address on {SECOND_HOST}')
""")
    try:
        yield SECOND_HOST
    finally:
        await _python(lan, f"import subprocess\nsubprocess.run(['ip', 'link', 'del', {SECOND_HOST!r}], check=True)\n")


@pytest_asyncio.fixture
async def listener_bridge(multicast_rig):
    """The LAN port in a VLAN-aware snooping bridge, two VLANs routed onto it.

    Each VLAN device is an oif of its own, and a routed group expands each
    through the bridge's membership for that VLAN: two tag stacks on the one
    port, which the hardware carries as two listeners. That is the only way a
    replica set larger than one exists on this rig. The port's addresses move
    to the bridge and back so the LAN VM keeps its gateway."""
    r = multicast_rig
    topology = TopologyStack()
    interfaces = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show",
                                           "dev", TARGET_LAN_IF))["stdout"])
    addresses = [f"{a['local']}/{a['prefixlen']}" for a in interfaces[0]["addr_info"]
                 if a["family"] == "inet"]
    links = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show"))["stdout"])
    assert LISTENER_BRIDGE not in {link["ifname"] for link in links}, links

    async def run(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    try:
        await run("ip", "link", "add", "name", LISTENER_BRIDGE, "type", "bridge", "vlan_filtering", "1",
                  "mcast_snooping", "1", "mcast_querier", "1")

        async def restore():
            await run("ip", "link", "set", TARGET_LAN_IF, "nomaster", check=False)
            await run("ip", "link", "del", LISTENER_BRIDGE, check=False)
            for address in addresses:
                await run("ip", "addr", "replace", address, "dev", TARGET_LAN_IF, check=False)
            await run("ip", "link", "set", TARGET_LAN_IF, "up", check=False)
        topology.push(restore)
        for address in addresses:
            await run("ip", "addr", "del", address, "dev", TARGET_LAN_IF)
        await run("ip", "link", "set", TARGET_LAN_IF, "master", LISTENER_BRIDGE)
        for vid in (VID_LEFT, VID_KEPT):
            await run("bridge", "vlan", "add", "dev", TARGET_LAN_IF, "vid", str(vid))
            await run("bridge", "vlan", "add", "dev", LISTENER_BRIDGE, "vid", str(vid), "self")
        await run("ip", "link", "set", LISTENER_BRIDGE, "up")
        for address in addresses:
            await run("ip", "addr", "add", address, "dev", LISTENER_BRIDGE)
        left, kept = [await dut_vlan_subif(topology, r.target, r.session, parent=LISTENER_BRIDGE, vid=vid,
                                           ipv4=f"198.18.{vid - 160}.1/24", ipv6=f"fd00:{vid:x}::1/64")
                      for vid in (VID_LEFT, VID_KEPT)]
        lan_left, lan_kept = [await lan_vlan_subif(topology, r.lan, parent=LAN_NIC, vid=vid)
                              for vid in (VID_LEFT, VID_KEPT)]
        # The querier's startup queries, and the VLAN devices' link-local
        # addresses, before anything joins.
        await asyncio.sleep(3)
        yield ListenerBridge(LISTENER_BRIDGE, left, kept, lan_left, lan_kept)
    finally:
        await topology.teardown("listener bridge")


@pytest.mark.parametrize("mechanism", MECHANISMS)
async def test_flowtable_service_multicast_routed_bridge_leave(multicast_rig, listener_bridge, mechanism):
    """One VLAN's listener leaves; the routed group swaps to the other's.

    The kept VLAN's membership is static, as an operator configures one, so
    it outlives every timer the leaving one runs on; removing it last is what
    empties the group."""
    r = multicast_rig
    spec = MECHANISMS[mechanism]
    family = spec["family"]
    group, source = ROUTED_GROUP[family], wan_source_address(family)
    bridge = listener_bridge
    left, kept = f"{TARGET_LAN_IF}/{VID_LEFT}", f"{TARGET_LAN_IF}/{VID_KEPT}"
    # Each copy leaves with the address of the VLAN device ipmr sends it
    # through, which it took from the bridge -- not the port's own, though a
    # one-port bridge happens to carry that.
    observers = [(r.lan, {bridge.lan_left: await dut_mac(r.target, r.session, bridge.left),
                          bridge.lan_kept: await dut_mac(r.target, r.session, bridge.kept)})]

    def row(state):
        return mroute_row(state, group, source)

    def carrying(state, listeners):
        current = row(state)
        return bool(current) and current["state"] == "installed" and members(current, "listeners") == listeners

    def window(label):
        return r.window([stream(family, group, hops=63)], observers, ingress=TARGET_WAN_IF,
                        label=f"leave-routed-{mechanism}-{label}")

    timers = dict(LEAVE_TIMERS)
    if spec["end"] == "silence":
        # Nothing refreshes a VLAN listener here -- the querier's queries go
        # out untagged -- so the membership lapses on its own timer. Long
        # enough for the first window to finish inside it.
        timers.update(membership_interval=1500)

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(bridge_settings(r, bridge.name, **timers))
        ctl = await stack.enter_async_context(
            _daemon(r.target, r.session, [TARGET_WAN_IF, bridge.left, bridge.kept]))
        await mdb(r, bridge.name, group, add=True, vid=VID_KEPT)
        leaving = await stack.enter_async_context(host(
            r.lan, family=family, group=group, iface=bridge.lan_left, mode=spec["mode"],
            version=spec["version"]))
        if spec["end"] == "silence":
            await end(stack, leaving, spec, bridge.lan_left)
        await ctl("add", TARGET_WAN_IF, source, group, bridge.left, bridge.kept)
        # Carried once Linux has been seen forwarding it to both oifs.
        both = await learn(r, [stream(family, group, hops=63)],
                           lambda s: carrying(s, {left, kept}), f"{mechanism}: two listeners")
        first = await window("two-listeners")
        assert delivered(first, streamed(first, group), bridge.lan_left)
        assert delivered(first, streamed(first, group), bridge.lan_kept)
        in_hardware(first)
        # Counted from what the tail of the confirming burst left on it.
        base = packets(row(first["before"]))
        assert packets(row(first["after"])) == base + COUNT, summary(first["after"])

        if spec["end"] != "silence":
            await end(stack, leaving, spec, bridge.lan_left)
        swapped = await r.settle(lambda s: carrying(s, {kept}), f"{mechanism}: the leaving listener dropped",
                                 timeout=40 if spec["end"] == "silence" else 12)
        assert swapped["mroute_installed"] == both["mroute_installed"], summary(swapped)
        second = await window("one-listener")
        assert not delivered(second, streamed(second, group), bridge.lan_left)
        assert delivered(second, streamed(second, group), bridge.lan_kept)
        in_hardware(second)
        # One root counted both windows: the chain was swapped under it
        # rather than the group torn down and built again.
        assert packets(row(second["after"])) == base + 2 * COUNT, summary(second["after"])

        # The last listener goes and the group leaves hardware with it.
        await mdb(r, bridge.name, group, add=False, vid=VID_KEPT)
        empty = await r.settle(lambda s: bool(row(s)) and row(s)["state"] == "refused-listener" and
                               row(s)["listeners"] == "-" and
                               s["mroute_installed"] == r.initial["mroute_installed"],
                               f"{mechanism}: no listener left")
        third = await window("no-listener")
        assert not delivered(third, streamed(third, group), bridge.lan_left)
        assert not delivered(third, streamed(third, group), bridge.lan_kept)
        in_software(third)
        await ctl("remove", TARGET_WAN_IF, source, group)
        # This group's record, not the total: the WAN segment is a live LAN
        # whose own multicast (SSDP, mDNS, MLD) comes and goes meanwhile.
        final = await r.settle(lambda s: row(s) is None, f"{mechanism}: the route's record gone")
    assert empty["quarantine"] == final["quarantine"] == 0, summary(final)
    assert final["mroute_installed"] == r.initial["mroute_installed"], summary(final)
    assert final["mroute_install_errors"] == r.initial["mroute_install_errors"], summary(final)


@pytest.mark.parametrize("mechanism", MECHANISMS)
async def test_flowtable_service_multicast_bridged_leave(multicast_rig, mcast_bridge, mechanism):
    """Two hosts behind the LAN port of the WAN-LAN bridge; one goes, then the other."""
    r = multicast_rig
    spec = MECHANISMS[mechanism]
    family = spec["family"]
    group, source = BRIDGED_GROUP[family], wan_source_address(family)
    port = f"{TARGET_LAN_IF}/0"
    # Hop count and payload say bridged and exact; the source MAC is the
    # bridged-MAC work's to assert.
    observers = [(r.lan, {LAN_NIC: None})]

    def carrying(state):
        """Installed rows that replicate this stream to the LAN port."""
        return [row for row in mcast_rows(state, group) if row["state"] == "installed"
                and same(row["src"], source) and port in members(row, "ports")]

    def carried(state):
        rows = carrying(state)
        assert len(rows) <= 1, rows
        return rows[0] if rows else None

    def window(label):
        return r.window([stream(family, group, hops=64)], observers, ingress=TARGET_WAN_IF,
                        label=f"leave-bridged-{mechanism}-{label}")

    timers = dict(LEAVE_TIMERS)
    if spec["end"] == "silence":
        # A querier every second from the first -- the startup queries too,
        # which otherwise come a quarter of the old interval apart -- and a
        # membership that lapses after four, so a silent host is forgotten
        # quickly and a live one is never missed.
        timers.update(query_interval=100, startup_query_interval=100, query_response_interval=50,
                      membership_interval=400)
    # Past what the bridge takes to drop a member nobody refreshes.
    forgotten = 6 if spec["end"] == "silence" else 3.5

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(bridge_settings(r, mcast_bridge, **timers))
        other = await stack.enter_async_context(second_host(r.lan))
        hosts = [await stack.enter_async_context(host(
            r.lan, family=family, group=group, iface=iface, mode=spec["mode"], version=spec["version"]))
            for iface in (LAN_NIC, other)]
        joined = await learn(r, [stream(family, group, hops=64)], lambda s: carried(s) is not None,
                             f"{mechanism}: two hosts joined")
        both = await window("two-hosts")
        assert delivered(both, streamed(both, group), LAN_NIC)
        assert moved(both, carried) == COUNT, summary(both["after"])
        in_hardware(both)

        # One host goes. The other still wants the stream on the same port,
        # and says so when the bridge asks, so nothing may change. The stream
        # keeps flowing meanwhile, as it would: with expiry's four-second
        # membership interval an entry that counts nothing for ten ages out,
        # and the wait and the window's own setup can take that long, so a
        # silent stream would be learned afresh inside the window below
        # rather than carried across it.
        await end(stack, hosts[0], spec, LAN_NIC)
        await trickle(r, [stream(family, group, hops=64)], forgotten)
        assert TARGET_LAN_IF in await mdb_ports(r, mcast_bridge, group)
        one = await window("one-host")
        assert delivered(one, streamed(one, group), LAN_NIC)
        assert moved(one, carried) == COUNT, summary(one["after"])
        in_hardware(one)
        assert one["after"]["mcast_installed"] == joined["mcast_installed"], summary(one["after"])

        # The last host goes: no listener is left on the port, so nothing
        # may be replicated there any more.
        await end(stack, hosts[1], spec, other)
        gone = await r.settle(lambda s: not carrying(s) and
                              s["mcast_installed"] == r.initial["mcast_installed"],
                              f"{mechanism}: the port's last listener gone",
                              timeout=forgotten + 10)
        if spec["end"] != "block":
            # Refusing one source leaves the membership standing for others.
            assert not mcast_rows(gone, group), summary(gone)
            assert TARGET_LAN_IF not in await mdb_ports(r, mcast_bridge, group)
        none = await window("no-host")
        assert not delivered(none, streamed(none, group), LAN_NIC)
        in_software(none)
    # Leaving the hosts' scope ended whatever membership was left.
    # This group's records, not the total: the WAN segment's own multicast
    # listeners come and go meanwhile.
    final = await r.settle(lambda s: not mcast_rows(s, group),
                           f"{mechanism}: no group record left", timeout=15)
    assert final["mcast_installed"] == r.initial["mcast_installed"], summary(final)
    assert final["quarantine"] == 0, summary(final)
    assert final["mcast_install_errors"] == r.initial["mcast_install_errors"], summary(final)


def flow_row(state, group, source):
    """The bridged learner's row for one source of a group: one per flow."""
    rows = [row for row in mcast_rows(state, group) if same(row["src"], source)]
    assert len(rows) <= 1, rows
    return rows[0] if rows else None


def carried_to(state, group, source, port=f"{TARGET_LAN_IF}/0"):
    row = flow_row(state, group, source)
    return bool(row) and row["state"] == "installed" and members(row, "ports") == {port}


def withheld(state, group, source):
    """Learned, and the bridge forwards it nowhere: left to the bridge."""
    row = flow_row(state, group, source)
    return bool(row) and row["state"] == "refused-listener" and row["ports"] == "-"


@pytest.mark.parametrize("family", [4, 6])
async def test_flowtable_service_multicast_bridged_ssm_beside_asm(multicast_rig, mcast_bridge, family):
    """A source-specific listener and an any-source one behind the LAN port.

    The SSM host's INCLUDE{S1} makes the bridge hold a (*,G) INCLUDE port
    group, which it never forwards, and an (S1,G) one; the ASM host's
    EXCLUDE{} makes the port want every source. Two sources are two flows,
    each carried to the port. When the ASM host leaves, the port wants S1
    alone: S2's flow leaves hardware and S2 stops reaching the port, while S1
    stays in hardware on its entry. Before flows, both memberships contested
    one key and neither was carried; installed from the (*,G) set, S2 would
    have kept arriving at a port nothing on it wants."""
    r = multicast_rig
    group, first, second = FILTER_GROUP[family], wan_source_address(family), OTHER_SOURCE[family]
    observers = [(r.lan, {LAN_NIC: None})]
    version = FILTER_VERSION[family]

    def window(label):
        return r.window([stream(family, group, hops=64, source=s) for s in (first, second)],
                        observers, ingress=TARGET_WAN_IF, label=f"ssm-asm-v{family}-{label}")

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(bridge_settings(r, mcast_bridge, **FILTER_TIMERS))
        other = await stack.enter_async_context(second_host(r.lan))
        await stack.enter_async_context(host(
            r.lan, family=family, group=group, iface=LAN_NIC, mode="ssm", version=version,
            source=first))
        asm = await stack.enter_async_context(host(
            r.lan, family=family, group=group, iface=other, mode="asm", version=version))
        both = await learn(r, [stream(family, group, hops=64, source=s) for s in (first, second)],
                           lambda s: carried_to(s, group, first) and carried_to(s, group, second),
                           f"v{family}: both sources carried")
        assert both["mcast_installed"] == r.initial["mcast_installed"] + 2, summary(both)
        together = await window("both-hosts")
        for source in (first, second):
            assert delivered(together, streamed(together, group, source), LAN_NIC), source
            assert moved(together, lambda s, source=source: flow_row(s, group, source)) == COUNT, \
                (source, summary(together["after"]))
        in_hardware(together, streams=2)

        # The any-source host goes. What stays on the port is INCLUDE{S1}.
        await asm.do("leave")
        alone = await r.settle(lambda s: carried_to(s, group, first) and withheld(s, group, second),
                               f"v{family}: the second source withdrawn", timeout=15)
        assert alone["mcast_installed"] == r.initial["mcast_installed"] + 1, summary(alone)
        after = await window("ssm-host")
        assert delivered(after, streamed(after, group, first), LAN_NIC)
        assert not delivered(after, streamed(after, group, second), LAN_NIC)
        assert moved(after, lambda s: flow_row(s, group, first)) == COUNT, summary(after["after"])
        assert moved(after, lambda s: flow_row(s, group, second)) == 0, summary(after["after"])
        # The second source reached the CPU, and the bridge dropped it there.
        assert after["stream_cpu"] < COUNT * 1.1, (after["stream_cpu"], after["cpu"], after["idle"])
    final = await r.settle(lambda s: not mcast_rows(s, group) and
                           s["mcast_groups"] == r.initial["mcast_groups"],
                           f"v{family}: no record left", timeout=15)
    assert final["mcast_installed"] == r.initial["mcast_installed"], summary(final)
    assert final["mcast_install_errors"] == r.initial["mcast_install_errors"], summary(final)


@pytest.mark.parametrize("family", [4, 6])
async def test_flowtable_service_multicast_bridged_block_before_the_stream(multicast_rig, mcast_bridge,
                                                                         family):
    """A host joins any-source and blocks one source before anything is sent.

    The bridge answers the block with a group-and-source query nobody
    answers, and holds the source blocked from then on. From the first frame,
    the blocked source never reaches the port -- not in software while the
    learner learns it, and not in hardware once the other source is carried --
    and its own flow stays out of hardware."""
    r = multicast_rig
    group, blocked, allowed = BLOCK_GROUP[family], wan_source_address(family), OTHER_SOURCE[family]
    observers = [(r.lan, {LAN_NIC: None})]

    def window(label):
        return r.window([stream(family, group, hops=64, source=s) for s in (blocked, allowed)],
                        observers, ingress=TARGET_WAN_IF, label=f"block-first-v{family}-{label}")

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(bridge_settings(r, mcast_bridge, **FILTER_TIMERS))
        member = await stack.enter_async_context(host(
            r.lan, family=family, group=group, iface=LAN_NIC, mode="asm",
            version=FILTER_VERSION[family], source=blocked))
        await member.do("block")
        # Two unanswered queries a second apart, and then some.
        await asyncio.sleep(3.5)

        first = await window("learning")
        assert not delivered(first, streamed(first, group, blocked), LAN_NIC)
        assert delivered(first, streamed(first, group, allowed), LAN_NIC)
        settled = await r.settle(lambda s: carried_to(s, group, allowed) and withheld(s, group, blocked),
                                 f"v{family}: the allowed source carried, the blocked one not")
        assert settled["mcast_installed"] == r.initial["mcast_installed"] + 1, summary(settled)
        second = await window("carried")
        assert not delivered(second, streamed(second, group, blocked), LAN_NIC)
        assert delivered(second, streamed(second, group, allowed), LAN_NIC)
        assert moved(second, lambda s: flow_row(s, group, allowed)) == COUNT, summary(second["after"])
        assert moved(second, lambda s: flow_row(s, group, blocked)) == 0, summary(second["after"])
        assert second["stream_cpu"] < COUNT * 1.1, (second["stream_cpu"], second["cpu"], second["idle"])
    final = await r.settle(lambda s: not mcast_rows(s, group) and
                           s["mcast_groups"] == r.initial["mcast_groups"],
                           f"v{family}: no record left", timeout=15)
    assert final["mcast_installed"] == r.initial["mcast_installed"], summary(final)
    assert final["mcast_install_errors"] == r.initial["mcast_install_errors"], summary(final)

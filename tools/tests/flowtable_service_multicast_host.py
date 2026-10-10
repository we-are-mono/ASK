"""A socket on the DUT itself joins a group the hardware is carrying.

A hardware entry replicates to ports and the frame never reaches the CPU, so a
local listener would be starved silently. Both learners therefore refuse a
group the host has joined (`refused-host`): the routed learner when the
membership is on the route's parent VIF or on an oif, which it finds at its
next derivation, the five-second refresh at the latest
(docs/flowtable/multicast-routed.md, "The host"); the bridged learner when the
bridge device itself joined, which the bridge reports as a host MDB object
(docs/flowtable/multicast.md, "The host").

Each case starts with the group in hardware, then a listener on the DUT joins
through an ordinary socket, which is what makes the kernel's own membership
list and reports carry it. The group must leave hardware, and one numbered
stream must reach both the DUT's socket and the LAN VM exactly, every
sequence once, through the CPU. When the socket closes the group must come
back into hardware by itself and the LAN VM keep receiving every frame.
"""
from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
import asyncio
import json
import uuid

import pytest

from _flowtable_service_multicast_leave import LEAVE_TIMERS
from _mcast_windows import (COUNT, PORT, bridge_settings, delivered, host, in_hardware, in_software,
                            kernel_mroute, learn, mcast_rows, mdb_ports, members, moved, mroute_row, same,
                            stream, streamed, summary)
from _mroute_capacity import _daemon
from _mroute_capture import MAGIC
from _mcast_e2e import wan_source_address
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF
from ask_orch.commands import console_python
from ask_orch.uart import Console

ROUTED_GROUP = {4: "239.9.13.1", 6: "ff1e::9:13:1"}
BRIDGED_GROUP = {4: "239.9.13.2", 6: "ff1e::9:13:2"}
LISTENER = f"{TARGET_LAN_IF}/0"
EVIDENCE = "ASK-MCAST-HOST-EVIDENCE"

# The DUT's listener: an ordinary socket joined on one interface, counting
# every sequence of every stream it is handed, by token, until SIGTERM.
MEMBER = r'''
import json, pathlib, signal, socket, struct, sys
config = json.loads(sys.argv[1])
magic = bytes.fromhex(config["magic"])
family = socket.AF_INET6 if config["family"] == 6 else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
sock.bind((config["group"], config["port"]))
index = socket.if_nametoindex(config["iface"])
if family == socket.AF_INET6:
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                    socket.inet_pton(family, config["group"]) + struct.pack("@I", index))
else:
    # ip_mreqn, by index: ip_mreq names the interface by address, and its
    # 0.0.0.0 lands on the default route's device.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(config["group"]) + b"\0" * 4 + struct.pack("@i", index))
state = pathlib.Path(config["state"])
seen, duplicates, foreign = {}, {}, 0
def publish():
    staged = state.with_name(state.name + ".new")
    staged.write_text(json.dumps({"seen": {k: sorted(v) for k, v in seen.items()},
                                  "duplicates": duplicates, "foreign": foreign}))
    staged.replace(state)
stopping = []
signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
publish()
sock.settimeout(0.1)
dirty = False
while not stopping:
    try:
        data = sock.recv(2048)
    except socket.timeout:
        if dirty:
            publish()
            dirty = False
        continue
    dirty = True
    if data[:len(magic)] != magic:
        foreign += 1
        continue
    token = data[len(magic):len(magic) + 16].hex()
    sequence = struct.unpack("!I", data[len(magic) + 16:len(magic) + 20])[0]
    got = seen.setdefault(token, set())
    if sequence in got:
        duplicates[token] = duplicates.get(token, 0) + 1
    got.add(sequence)
publish()
'''


class Member:
    """The DUT's listener, read back from the state file it publishes."""

    def __init__(self, r, path):
        self.r, self.path = r, path

    async def report(self) -> dict:
        result = await self.r.target.fs_read(self.r.session, self.path + ".json")
        assert result["errno"] == 0, result
        return json.loads(bytes.fromhex(result["content_hex"]))

    async def evidence(self) -> dict:
        """What the DUT says of the membership and of what it received."""
        script = f"""
import json, pathlib, subprocess
def text(path):
    try:
        return pathlib.Path(path).read_text()
    except OSError as error:
        return repr(error)
print({EVIDENCE!r})
print(json.dumps({{
    "log": text({self.path + '.log'!r}),
    "igmp": text('/proc/net/igmp') + text('/proc/net/igmp6'),
    "snmp6": [l for l in text('/proc/net/snmp6').splitlines() if l.startswith(('Udp6', 'Ip6InMcast', 'Ip6OutMcast'))],
    "mroute": subprocess.run(['ip', '-s', 'mroute'], capture_output=True, text=True).stdout +
              subprocess.run(['ip', '-6', '-s', 'mroute'], capture_output=True, text=True).stdout,
}}))
"""
        with Console.target() as console:
            out = await console_python(console, script)
        # The console merges stderr into stdout: read the line after the marker.
        lines = out["stdout"].splitlines()
        return json.loads(lines[lines.index(EVIDENCE) + 1])

    async def sequences(self, config: dict, label: str) -> list[int]:
        """What the socket received of one stream; no sequence twice, or the
        case fails. Waits out the listener's idle publication, and records
        the DUT's membership and UDP counters when anything is missing."""
        for _ in range(30):
            report = await self.report()
            got = report["seen"].get(config["token"], [])
            if len(got) == config["count"]:
                break
            await asyncio.sleep(0.1)
        else:
            self.r.record(f"{label}-member", {"report": report, **await self.evidence()})
        assert not report["duplicates"].get(config["token"]), ("duplicated", report["duplicates"])
        return got


@asynccontextmanager
async def dut_member(r, *, family: int, group: str, iface: str):
    """A socket on the DUT joined to `group` on `iface` for the duration."""
    path = f"/tmp/ask-mcast-host-{uuid.uuid4().hex}"
    config = {"family": family, "group": group, "port": PORT, "iface": iface,
              "magic": MAGIC.hex(), "state": path + ".json"}
    with Console.target() as console:
        try:
            out = await console_python(console, f"""
import json, pathlib, subprocess, sys, time
pathlib.Path({path + '.py'!r}).write_text({MEMBER!r})
with open({path + '.log'!r}, 'w') as log:
    child = subprocess.Popen([sys.executable, {path + '.py'!r}, {json.dumps(config)!r}],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             start_new_session=True)
pathlib.Path({path + '.pid'!r}).write_text(str(child.pid))
for _ in range(50):
    if pathlib.Path({config['state']!r}).exists() or child.poll() is not None:
        break
    time.sleep(0.1)
print('JOINED' if pathlib.Path({config['state']!r}).exists() else 'FAILED ' + open({path + '.log'!r}).read())
""")
            assert "JOINED" in out["stdout"].splitlines(), out
            yield Member(r, path)
        finally:
            # Only this listener's process, identified by its script, never a
            # recycled PID. Its exit drops the membership.
            await console_python(console, f"""
import os, pathlib, signal, time
pidfile = pathlib.Path({path + '.pid'!r})
try:
    if pidfile.exists():
        pid = int(pidfile.read_text())
        try:
            if {path.encode() + b'.py'!r} in pathlib.Path('/proc/%d/cmdline' % pid).read_bytes().split(b'\\0'):
                os.kill(pid, signal.SIGTERM)
                for _ in range(50):
                    if not pathlib.Path('/proc/%d' % pid).exists():
                        break
                    time.sleep(0.1)
                else:
                    os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, FileNotFoundError):
            pass
finally:
    for suffix in ('.py', '.pid', '.log', '.json', '.json.new'):
        pathlib.Path({path!r} + suffix).unlink(missing_ok=True)
""", timeout=20)


async def checksummed(source: str, group: str) -> dict:
    """How many conntrack entries the DUT holds for the stream, and whether
    conntrack verifies checksums. Together they give a CHECKSUM_NONE IPv6
    frame the software CHECKSUM_COMPLETE value the forward's hop-limit
    rewrite must keep valid; without them the looped copy arrives with no
    value to go stale, and the case proves nothing about patch 170."""
    script = f"""
import ipaddress, json, pathlib
want = (ipaddress.ip_address({source!r}), ipaddress.ip_address({group!r}), {str(PORT)!r})
entries = 0
for line in pathlib.Path('/proc/net/nf_conntrack').read_text().splitlines():
    fields = line.split()
    if 'udp' not in fields:
        continue
    tags = {{}}
    for field in fields:
        key, eq, value = field.partition('=')
        if eq and key not in tags:
            tags[key] = value
    try:
        tuple_ = (ipaddress.ip_address(tags['src']), ipaddress.ip_address(tags['dst']), tags['dport'])
    except (KeyError, ValueError):
        continue
    entries += tuple_ == want
print({EVIDENCE!r})
print(json.dumps({{"entries": entries, "checksum": int(pathlib.Path(
    '/proc/sys/net/netfilter/nf_conntrack_checksum').read_text())}}))
"""
    with Console.target() as console:
        out = await console_python(console, script)
    lines = out["stdout"].splitlines()
    return json.loads(lines[lines.index(EVIDENCE) + 1])


@pytest.mark.parametrize("side", ["parent", "oif"])
@pytest.mark.parametrize("family", [4, 6])
async def test_routed_yields_to_the_host(multicast_rig, family, side):
    """The routed learner, with the DUT's socket joined on the route's parent
    VIF (the WAN port the stream arrives on) or on its oif (the LAN port it
    is replicated to). ipmr delivers locally from the one and loops each
    forwarded copy back from the other. The stream's datagrams are longer
    than CHECKSUM_BREAK (76 bytes): UDP recomputes a shorter one's checksum
    on receive, so only these show whether the looped copy's checksum state
    survived the forward's hop-limit rewrite (patch 170). For IPv6 that state
    exists only while conntrack checksums the stream, which the oif case
    therefore requires."""
    r = multicast_rig
    group, source = ROUTED_GROUP[family], wan_source_address(family)
    observers = [(r.lan, {LAN_NIC: r.dut_lan_mac})]

    def row(state):
        return mroute_row(state, group, source)

    def installed(state):
        found = row(state)
        return bool(found) and found["state"] == "installed" and members(found, "listeners") == {LISTENER}

    def window(label):
        return r.window([stream(family, group, hops=63)], observers, ingress=TARGET_WAN_IF,
                        label=f"host-routed-v{family}-{side}-{label}")

    async with _daemon(r.target, r.session, [TARGET_WAN_IF, TARGET_LAN_IF]) as ctl:
        await ctl("add", TARGET_WAN_IF, source, group, TARGET_LAN_IF)
        await learn(r, [stream(family, group, hops=63)], installed, "the route in hardware")
        carried = await window("carried")
        assert delivered(carried, streamed(carried, group), LAN_NIC)
        assert moved(carried, row) == COUNT, summary(carried["after"])
        in_hardware(carried)

        async with dut_member(r, family=family, group=group,
                              iface=TARGET_WAN_IF if side == "parent" else TARGET_LAN_IF) as member:
            refused = await r.settle(lambda s: row(s) and row(s)["state"] == "refused-host",
                                     "the host's membership refused the route", timeout=15)
            assert refused["mroute_installed"] == r.initial["mroute_installed"], summary(refused)
            line, _, _ = await kernel_mroute(r, family, source, group, offloaded=False)
            assert line and "offload" not in line, line
            shared = await window("host-joined")
            config = streamed(shared, group)
            local = await member.sequences(config, f"host-routed-v{family}-{side}")
            assert delivered(shared, config, LAN_NIC)
            assert local == list(range(COUNT)), (await member.report())
            in_software(shared)
            # Refused for the whole window, not re-admitted part way through.
            assert row(shared["after"])["state"] == "refused-host", summary(shared["after"])
            if family == 6 and side == "oif":
                view = await checksummed(source, group)
                assert view["entries"] >= 1 and view["checksum"] == 1, view

        # The socket is gone, and with it the membership; the next derivation
        # finds none, and the route is confirmed by its own traffic again.
        await learn(r, [stream(family, group, hops=63)], installed, "the route back in hardware")
        line, _, _ = await kernel_mroute(r, family, source, group, offloaded=True)
        assert line and "offload" in line, line
        again = await window("host-left")
        assert delivered(again, streamed(again, group), LAN_NIC)
        assert moved(again, row) == COUNT, summary(again["after"])
        in_hardware(again)

        await ctl("remove", TARGET_WAN_IF, source, group)
        final = await r.settle(lambda s: row(s) is None and
                               s["mroute_installed"] == r.initial["mroute_installed"],
                               "the route removed")
    assert final["quarantine"] == 0, summary(final)
    assert final["mroute_install_errors"] == r.initial["mroute_install_errors"], summary(final)


@pytest.mark.parametrize("family", [4, 6])
async def test_bridged_yields_to_the_host(multicast_rig, mcast_bridge, family):
    """The bridged learner, with the DUT's socket joined on the bridge device
    the LAN VM's membership is learned on: the bridge hands the group up to
    the host as well as to the port."""
    r = multicast_rig
    group, source = BRIDGED_GROUP[family], wan_source_address(family)
    port = f"{TARGET_LAN_IF}/0"
    observers = [(r.lan, {LAN_NIC: None})]

    def flow(state):
        rows = [row for row in mcast_rows(state, group) if same(row["src"], source)]
        assert len(rows) <= 1, rows
        return rows[0] if rows else None

    def carried(state):
        found = flow(state)
        return bool(found) and found["state"] == "installed" and port in members(found, "ports")

    def window(label):
        return r.window([stream(family, group, hops=64)], observers, ingress=TARGET_WAN_IF,
                        label=f"host-bridged-v{family}-{label}")

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(bridge_settings(r, mcast_bridge, **LEAVE_TIMERS))
        await stack.enter_async_context(host(r.lan, family=family, group=group, iface=LAN_NIC,
                                             mode="asm", version=3 if family == 4 else 2))
        await learn(r, [stream(family, group, hops=64)], carried, "the LAN membership in hardware")
        first = await window("carried")
        assert delivered(first, streamed(first, group), LAN_NIC)
        assert moved(first, flow) == COUNT, summary(first["after"])
        in_hardware(first)

        async with dut_member(r, family=family, group=group, iface=mcast_bridge) as member:
            # This flow's own state: the global installed count also moves
            # with the WAN segment's own multicast.
            await r.settle(lambda s: flow(s) and flow(s)["state"] == "refused-host",
                           "the host's membership refused the flow", timeout=15)
            # The flow was carried, so no flood, router port or promiscuous
            # bridge handed it up; what changed is the bridge device's own
            # entry, the host MDB object the learner refuses on.
            assert mcast_bridge in await mdb_ports(r, mcast_bridge, group)
            shared = await window("host-joined")
            config = streamed(shared, group)
            assert delivered(shared, config, LAN_NIC)
            local = await member.sequences(config, f"host-bridged-v{family}")
            assert local == list(range(COUNT)), (await member.report())
            in_software(shared)
            assert flow(shared["after"])["state"] == "refused-host", summary(shared["after"])

        # The bridge forgets the host's membership after its last-member
        # queries, and the flow is offered again by its next frames.
        for _ in range(100):
            if mcast_bridge not in await mdb_ports(r, mcast_bridge, group):
                break
            await asyncio.sleep(0.1)
        else:
            pytest.fail("the bridge kept the host's membership after the socket closed")
        await learn(r, [stream(family, group, hops=64)], carried, "the flow back in hardware")
        again = await window("host-left")
        assert delivered(again, streamed(again, group), LAN_NIC)
        assert moved(again, flow) == COUNT, summary(again["after"])
        in_hardware(again)
    final = await r.settle(lambda s: not mcast_rows(s, group), "no group record left", timeout=30)
    assert final["quarantine"] == 0, summary(final)
    assert final["mcast_install_errors"] == r.initial["mcast_install_errors"], summary(final)

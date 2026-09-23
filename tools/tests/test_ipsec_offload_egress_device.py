"""A packet-offloaded SA's plaintext leaves by the SA's own port or not at all.

xfrm_output() hands a packet for such an SA on still in plaintext, and only
the port the SA was installed on gives it to SEC. The bundle's child route is
looked up afresh for every forwarded packet, so when the route to the peer
moves to another device -- a failover, a more specific route, a routing rule
-- the child names that device, and a frame sent there would leave in the
clear: the upstream wrong-device drop in validate_xmit_xfrm() keys on
xfrm_offload(), which answers NULL for these frames because the state is
carried with len and no olen.

The flow here is forwarded LAN -> WAN host, IPv4 in IPv4, with no flowtable, so
every packet takes the software path. Three phases on one SA pair:

  - the route to the peer leaves by the WAN port: every datagram is echoed and
    the port hands exactly that many frames to SEC (`tx toenc`);
  - the route is moved to a dummy device: every datagram is refused and
    counted as XfrmOutBundleCheckError, the dummy transmits nothing, and SEC
    sees nothing either;
  - the route is moved back: the same SA carries traffic again, so nothing
    about the refusal outlived its cause.

The leak oracle is the dummy's own transmit counter. A postrouting counter on
the dummy would not do: the bundle's POSTROUTING runs before xfrm_output() and
names the child's device as its output, so it counts the refused packets too.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import struct

from ask_orch.client import Agent
from _topology import LAN_IPV6, TARGET_WAN_IF, lan_run_python
from test_flowtable_ipv6 import PayloadEcho, _udp_exchange, ipv6_rig  # noqa: F401
from test_flowtable_ipv6_sa import REMOTE_V6
from test_flowtable_offload import WAN_IP, Echo, command, read, rig  # noqa: F401
from test_flowtable_service_ipsec_replay import xfrm_mib
from test_ipsec_inbound_flow_offload import crypto, sec_counter

# The tunnelled flow's far end and the WAN host's tunnel endpoint, both on its
# loopback, so moving the route to the endpoint never touches the address the
# DUT's agent is reached through.
INNER = "198.18.106.2"
PEER = "198.18.106.1"
# The device the route to the peer is moved to, and the gateway it names.
DETOUR = "askdetour0"
DETOUR_LOCAL, DETOUR_GATEWAY = "198.18.107.1", "198.18.107.2"
SPORT, DPORT = 48980, 48981
V6_SPORT, V6_DPORT = 48982, 48983
REQIDS = {"out": "49511", "in": "49512"}
COUNT = 32


def payload(n):
    return struct.pack("!Q", n) + b"ASK-sa-egress-device".ljust(48, b".")


async def send(r, first, count, wait):
    """`count` datagrams from the LAN VM to INNER. With `wait`, each must be
    echoed with its own payload; without, the sender does not listen."""
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({r.lan_ip!r}, {SPORT}))
s.settimeout(2)
echoed = 0
for n in range({first}, {first + count}):
    data = struct.pack('!Q', n) + b'ASK-sa-egress-device'.ljust(48, b'.')
    s.sendto(data, ({INNER!r}, {DPORT}))
    if {wait!r}:
        try:
            reply, addr = s.recvfrom(2048)
        except TimeoutError:
            continue
        assert reply == data and addr == ({INNER!r}, {DPORT}), (n, reply, addr)
        echoed += 1
    time.sleep(0.01)
s.close()
print(json.dumps({{'echoed': echoed}}))
'''
    result = await lan_run_python(r.lan, script, timeout=count * 2.1 + 20, label="ipsec_egress_device")
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])["echoed"]


async def counters(r):
    return {
        "refused": xfrm_mib(await read(r.target, r.session, "/proc/net/xfrm_stat"))[
            "XfrmOutBundleCheckError"],
        "detour_tx": int(await read(r.target, r.session,
                                    f"/sys/class/net/{DETOUR}/statistics/tx_packets")),
        "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc"),
    }


def moved(before, after):
    return {name: after[name] - before[name] for name in before}


async def wan_outer(r):
    """The DUT's IPv4 address on its WAN port: the local tunnel endpoint."""
    return next(a["local"] for i in json.loads((await command(
        r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_WAN_IF))["stdout"])
        for a in i["addr_info"] if a["family"] == "inet")


async def install_tunnel(r, wan, outer, sources, step, inner=INNER):
    """`inner` and the tunnel endpoint PEER on the WAN host's loopback, and a
    packet-offloaded SA pair on the DUT's WAN port selecting each of
    `sources` <-> `inner`. An IPv6 `inner` makes it IPv6 inside the IPv4
    tunnel, routed to the WAN port with no gateway. The WAN host's half is
    ordinary software. `step` runs a command and records how to undo it."""
    v6 = ":" in inner
    host = "/128" if v6 else "/32"
    family = ["-6"] if v6 else []
    await step(wan, ["ip", *family, "addr", "add", inner + host, "dev", "lo"],
               ["ip", *family, "addr", "del", inner + host, "dev", "lo"])
    await step(wan, ["ip", "addr", "add", PEER + "/32", "dev", "lo"],
               ["ip", "addr", "del", PEER + "/32", "dev", "lo"])
    # The DUT masquerades what leaves by the WAN port; the inner source has to
    # reach the policy and the peer's selector unchanged. IPv4 only: nothing
    # translates IPv6 here.
    for source in sources if not v6 else []:
        exempt = ["POSTROUTING", "-s", source, "-d", inner, "-j", "ACCEPT"]
        await step(r.target, ["iptables", "-t", "nat", "-I", *exempt],
                   ["iptables", "-t", "nat", "-D", *exempt])
    await step(r.target, ["ip", "route", "add", PEER + "/32", "via", WAN_IP, "dev", TARGET_WAN_IF],
               ["ip", "route", "del", PEER + "/32"])
    if v6:
        await step(r.target, ["ip", "-6", "route", "add", inner + host, "dev", TARGET_WAN_IF],
                   ["ip", "-6", "route", "del", inner + host, "dev", TARGET_WAN_IF])
    else:
        await step(r.target, ["ip", "route", "add", inner + host, "via", WAN_IP, "dev",
                              TARGET_WAN_IF],
                   ["ip", "route", "del", inner + host])
    # A state's selector takes the outer family unless told otherwise, and
    # xfrm hands a flow only a state whose selector is the flow's family.
    selector_family = ["sel", "src", "::/0", "dst", "::/0"] if v6 else []
    for direction in ("out", "in"):
        spi = hex(0xA7000000 | secrets.randbits(24))
        outer_src, outer_dst = (outer, PEER) if direction == "out" else (PEER, outer)
        state = ["src", outer_src, "dst", outer_dst, "proto", "esp", "spi", spi]
        window = ["replay-window", "32"] if direction == "in" else []
        await step(wan, ["ip", "xfrm", "state", "add", *state, *crypto(REQIDS[direction]),
                         *selector_family, "replay-window", "32"],
                   ["ip", "xfrm", "state", "delete", *state])
        await step(r.target, ["ip", "xfrm", "state", "add", *state, *crypto(REQIDS[direction]),
                              *selector_family, *window, "offload", "packet", "dev",
                              TARGET_WAN_IF, "dir", direction],
                   ["ip", "xfrm", "state", "delete", *state])
        template = ["tmpl", "src", outer_src, "dst", outer_dst, "proto", "esp", "mode", "tunnel",
                    "reqid", REQIDS[direction], "level", "required"]
        peer_dir = "in" if direction == "out" else "out"
        for source in sources:
            src, dst = (source, inner) if direction == "out" else (inner, source)
            selector = ["src", src + host, "dst", dst + host]
            await step(wan, ["ip", "xfrm", "policy", "add", *selector, "dir", peer_dir, *template],
                       ["ip", "xfrm", "policy", "delete", *selector, "dir", peer_dir])
            await step(r.target, ["ip", "xfrm", "policy", "add", *selector, "dir", direction,
                                  *template, "offload", "packet", "dev", TARGET_WAN_IF],
                       ["ip", "xfrm", "policy", "delete", *selector, "dir", direction])
            if direction == "in":
                await step(r.target, ["ip", "xfrm", "policy", "add", *selector, "dir", "fwd",
                                      *template],
                           ["ip", "xfrm", "policy", "delete", *selector, "dir", "fwd"])


async def add_detour(r, step):
    """The dummy device the route to the peer is moved to."""
    await command(r.target, r.session, "modprobe", "dummy", "numdummies=0")
    await step(r.target, ["ip", "link", "add", DETOUR, "type", "dummy"],
               ["ip", "link", "del", DETOUR])
    # No IPv6 on it, so router solicitations and MLD reports cannot move its
    # transmit counter.
    await command(r.target, r.session, "sysctl", "-w", f"net.ipv6.conf.{DETOUR}.disable_ipv6=1")
    await command(r.target, r.session, "ip", "addr", "add", DETOUR_LOCAL + "/30", "dev", DETOUR)
    await command(r.target, r.session, "ip", "link", "set", DETOUR, "up")


async def test_offloaded_sa_plaintext_stays_on_its_port(rig):
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer = await wan_outer(r)
    echo = Echo()
    transport = None
    cleanup = []

    async def step(agent, argv, undo):
        await command(agent, r.session, *argv)
        cleanup.append((agent, undo))

    try:
        route = json.loads(r.lan.run(f"ip -j route get {INNER}", timeout=10).stdout.strip())[0]
        assert route.get("gateway") == r.lan_gateway, ("the LAN VM must reach INNER through the DUT",
                                                        route)
        await install_tunnel(r, wan, outer, [r.lan_ip], step)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(INNER, DPORT))
        await add_detour(r, step)

        phases = {}
        before = await counters(r)
        echoed = await send(r, 0, COUNT, wait=True)
        phases["wan"] = {"echoed": echoed, **moved(before, await counters(r))}
        assert phases["wan"] == {"echoed": COUNT, "refused": 0, "detour_tx": 0, "toenc": COUNT}, phases
        assert all(echo.received[payload(n)] == 1 for n in range(COUNT)), echo.received

        await command(r.target, r.session, "ip", "route", "replace", PEER + "/32", "via",
                      DETOUR_GATEWAY, "dev", DETOUR)
        before = await counters(r)
        await send(r, COUNT, COUNT, wait=False)
        await asyncio.sleep(0.5)
        phases["detour"] = {"delivered": sum(echo.received[payload(n)]
                                             for n in range(COUNT, 2 * COUNT)),
                            **moved(before, await counters(r))}
        assert phases["detour"] == {"delivered": 0, "refused": COUNT, "detour_tx": 0, "toenc": 0}, \
            phases

        await command(r.target, r.session, "ip", "route", "replace", PEER + "/32", "via", WAN_IP,
                      "dev", TARGET_WAN_IF)
        before = await counters(r)
        echoed = await send(r, 2 * COUNT, COUNT, wait=True)
        phases["restored"] = {"echoed": echoed, **moved(before, await counters(r))}
        assert phases["restored"] == {"echoed": COUNT, "refused": 0, "detour_tx": 0,
                                      "toenc": COUNT}, phases
        r.record("ipsec-egress-device", phases)
    finally:
        if transport:
            transport.close()
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


async def send6(r, count):
    """`count` IPv6 datagrams from the LAN VM to REMOTE_V6, not waiting for
    any answer."""
    script = f'''
import socket, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(({LAN_IPV6!r}, {V6_SPORT}))
for n in range({count}):
    s.sendto(b'ASK-sa-egress-device-v6'.ljust(48, b'.'), ({REMOTE_V6!r}, {V6_DPORT}))
    time.sleep(0.01)
s.close()
'''
    result = await lan_run_python(r.lan, script, timeout=count * 0.1 + 20, label="ipsec_egress_device_v6")
    assert result.rc == 0, result.stdout


async def test_offloaded_cross_family_sa_stays_on_its_port(ipv6_rig):
    """The same three phases for IPv6 inside the IPv4 tunnel. The bundle's
    route is then the flow's own, which does not move; what moves is the IPv4
    route to the peer, which the kernel asks per packet in the SA's own
    family and refuses the packet for once it leaves by another device."""
    r = ipv6_rig
    outer = await wan_outer(r)
    echo = PayloadEcho()
    transport = None
    cleanup = []

    async def step(agent, argv, undo):
        await command(agent, r.session, *argv)
        cleanup.append((agent, undo))

    async def exchange():
        return await _udp_exchange(r, V6_SPORT, REMOTE_V6, V6_DPORT, COUNT, (REMOTE_V6, V6_DPORT),
                                   "ipsec_egress_device_v6")

    try:
        await install_tunnel(r, r.wan, outer, [LAN_IPV6], step, inner=REMOTE_V6)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(REMOTE_V6, V6_DPORT), family=socket.AF_INET6)
        await add_detour(r, step)

        phases = {}
        before = await counters(r)
        report = await exchange()
        phases["wan"] = {**report, **moved(before, await counters(r))}
        assert phases["wan"] == {"echoed": COUNT, "lost": 0, "refused": 0, "detour_tx": 0,
                                 "toenc": COUNT}, phases

        await command(r.target, r.session, "ip", "route", "replace", PEER + "/32", "via",
                      DETOUR_GATEWAY, "dev", DETOUR)
        before, delivered = await counters(r), echo.packets
        await send6(r, COUNT)
        await asyncio.sleep(0.5)
        phases["detour"] = {"delivered": echo.packets - delivered, **moved(before, await counters(r))}
        assert phases["detour"] == {"delivered": 0, "refused": COUNT, "detour_tx": 0, "toenc": 0}, \
            phases

        await command(r.target, r.session, "ip", "route", "replace", PEER + "/32", "via", WAN_IP,
                      "dev", TARGET_WAN_IF)
        before = await counters(r)
        report = await exchange()
        phases["restored"] = {**report, **moved(before, await counters(r))}
        assert phases["restored"] == {"echoed": COUNT, "lost": 0, "refused": 0, "detour_tx": 0,
                                      "toenc": COUNT}, phases
        r.record("ipsec-egress-device-v6", phases)
    finally:
        if transport:
            transport.close()
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)

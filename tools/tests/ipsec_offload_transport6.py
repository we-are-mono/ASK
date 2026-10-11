"""A packet-offloaded IPv6 transport-mode SA, which its peer decrypts.

Transport mode keeps the packet's own headers ahead of ESP. In IPv6 those are
the fixed header and the extension headers ESP has to follow: hop-by-hop
options, and destination options with no routing header after them, as
ip6_find_1stfragopt() places ESP. The DPAA driver hands SEC their length and
the offset of the next-header byte it swaps for ESP, per frame, in DPOVRD. Too
short a header encrypts one the peer has to read before ESP; too long leaves
the start of the payload in the clear; the wrong byte names the wrong
protocol in the trailer. Nothing the peer receives then decodes.

The DUT sends UDP from its WAN-segment address to an address on the WAN host's
loopback through an offloaded transport SA; the WAN host's half is ordinary
software. A quarter of the datagrams carry no extension header, a quarter
hop-by-hop options, a quarter destination options, and a quarter both. Every
datagram must arrive once and intact, the DUT's port must have handed SEC
exactly that many frames, each frame on the wire must carry its extension
headers in the clear ahead of ESP, the peer's SA must have decrypted as many,
and the peer must have refused nothing.

A second case selects every protocol between the two hosts, what strongSwan
installs for a host-to-host SA, and sends datagrams as large as the SA
carries. Each must leave SEC whole, as one frame 42 bytes longer than the
datagram, with nothing fragmented on the way.

The rest cover the same headers the other way, through an inbound SA (A364);
the longest header SEC is given, either way (A366); and a hop limit of 1
(A365).
"""
from __future__ import annotations

import asyncio
from collections import Counter
import json
import os
from pathlib import Path
import secrets
import struct
import threading

import pytest

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import DUT_IPV6_WAN, TARGET_WAN_IF, WAN_IPV6, has_address
from _flowtable_ipv6_sa import (fragments_sent)
from _flowtable_rig import (artifact_dir, Echo, command, console_python)
from _flowtable_service_ipsec import (wire_interface)
from _flowtable_service_ipsec_replay import (PEER_ERRORS, xfrm_mib)
from _ipsec_inbound_flow_offload import (sec_counter)
from _ipsec_packet_offload_traffic import (decrypted_packets)
from _ipsec_transport import (dut_counters, moved, numbered, options_header, received_on_dut, send,
                              sender as numbered_sender, transport_sa)

PEER6 = "fc00:a8::1"
PORT = 48994
FULL_PORT = 48995
IN_PORT = 49484
BOUND_OUT_PORT, BOUND_IN_PORT = 49485, 49486
HOP_PORT = 49487
COUNT = 16
# The longest IPv6 header SEC may keep ahead of a transport SA's ESP, 88
# bytes of extension headers: SEC's output then carries ESP at byte 146,
# behind 14 bytes of Ethernet and the SA's 4-byte tag, its SPI and sequence
# number ending at 154. FMan's parser discards most frames whose transport
# header ends past byte 158; eight bytes more end ESP's at 162.
LONGEST = 128
IPPROTO_IPV6, IPV6_UNICAST_HOPS = 41, 16
# IPV6_HOPOPTS and IPV6_DSTOPTS (linux/in6.h), each set to a header of one
# PadN option filling its eight bytes. Without a routing header the kernel
# sends destination options after hop-by-hop options, and both ahead of ESP.
HOPOPTS, DSTOPTS = 54, 59
PAD = bytes([0, 0, 1, 4, 0, 0, 0, 0])
LAYOUTS = [((), "ESP"),
           ((HOPOPTS,), "IPv6ExtHdrHopByHop ESP"),
           ((DSTOPTS,), "IPv6ExtHdrDestOpt ESP"),
           ((HOPOPTS, DSTOPTS), "IPv6ExtHdrHopByHop IPv6ExtHdrDestOpt ESP")]


def payload(n):
    return struct.pack("!Q", n) + b"ASK-transport6".ljust(48, b".")


def full_payload(n, size):
    """Datagram `n` of an IPv6 packet `size` bytes long, headers included."""
    return struct.pack("!Q", n) + b"ASK-transport6-full".ljust(size - 56, b".")


def sender(source):
    return f'''
import socket, struct, time
for index, options in enumerate({[options for options, _ in LAYOUTS]!r}):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    for option in options:
        s.setsockopt(socket.IPPROTO_IPV6, option, {PAD!r})
    s.bind(({source!r}, 0))
    for n in range(index * {COUNT}, (index + 1) * {COUNT}):
        s.sendto(struct.pack('!Q', n) + b'ASK-transport6'.ljust(48, b'.'), ({PEER6!r}, {PORT}))
        time.sleep(0.01)
    s.close()
print('sent')
'''


def full_sender(source, size):
    return f'''
import socket, struct, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(({source!r}, 0))
for n in range({2 * COUNT}):
    s.sendto(struct.pack('!Q', n) + b'ASK-transport6-full'.ljust({size} - 56, b'.'), ({PEER6!r}, {FULL_PORT}))
    time.sleep(0.01)
s.close()
print('sent')
'''


async def peer_on_loopback(r, wan, step):
    """PEER6 on the WAN host's loopback, routed from the DUT through the WAN
    host's WAN-segment address. Neighbour discovery stays between the two
    segment addresses, outside any selector naming PEER6."""
    if not await has_address(r.target, r.session, TARGET_WAN_IF, DUT_IPV6_WAN):
        await step(r.target, ["ip", "-6", "addr", "add", f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF,
                              "nodad"],
                   ["ip", "-6", "addr", "del", f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF])
    if not await has_address(wan, r.session, r.wan_if, WAN_IPV6):
        await step(wan, ["ip", "-6", "addr", "add", f"{WAN_IPV6}/64", "dev", r.wan_if, "nodad"],
                   ["ip", "-6", "addr", "del", f"{WAN_IPV6}/64", "dev", r.wan_if])
    await step(wan, ["ip", "-6", "addr", "add", PEER6 + "/128", "dev", "lo"],
               ["ip", "-6", "addr", "del", PEER6 + "/128", "dev", "lo"])
    await step(r.target, ["ip", "-6", "route", "add", PEER6 + "/128", "via", WAN_IPV6, "dev",
                          TARGET_WAN_IF],
               ["ip", "-6", "route", "del", PEER6 + "/128"])


class Steps(list):
    def __init__(self, r):
        super().__init__()
        self.r = r

    async def __call__(self, agent, argv, undo):
        await command(agent, self.r.session, *argv)
        self.append((agent, undo))

    async def undo(self):
        for agent, argv in reversed(self):
            await command(agent, self.r.session, *argv, check=False)


async def capture(r, ready_timeout=5, src=DUT_IPV6_WAN, dst=PEER6):
    from scapy.all import AsyncSniffer
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=wire_interface(r), store=True, started_callback=ready.set,
                           filter=f"ip6 and src host {src} and dst host {dst}")
    sniffer.start()
    assert await asyncio.to_thread(ready.wait, ready_timeout), "wire capture did not start"
    return sniffer


def chain(packet):
    """The headers after the fixed IPv6 header, as the wire carries them."""
    from scapy.all import IPv6
    layers = packet.layers()
    return " ".join(layer.__name__ for layer in layers[layers.index(IPv6) + 1:])


async def test_offloaded_transport_sa_is_decrypted(rig):
    from scapy.all import ESP
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    spi = 0xA9000000 | secrets.randbits(24)
    echo = Echo()
    echo.reply = False
    transport = sniffer = None
    step = Steps(r)
    try:
        await peer_on_loopback(r, wan, step)
        # Only this test's datagrams: the selector names the port. UDP by
        # number: the image carries no /etc/protocols for ip to resolve names.
        selector = ["src", DUT_IPV6_WAN + "/128", "dst", PEER6 + "/128", "proto", "17",
                    "dport", str(PORT)]
        await transport_sa(r, wan, step, DUT_IPV6_WAN, PEER6, spi, selector)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(PEER6, PORT))

        refused = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        toenc = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
        sniffer = await capture(r)
        with Console.target(log_path=str(artifact_dir() / "ipsec-offload-transport6-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(console, sender(DUT_IPV6_WAN), timeout=30)
        assert "sent" in result["stdout"], result
        await asyncio.sleep(0.5)
        captured = await asyncio.to_thread(sniffer.stop)
        sniffer = None

        now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        peer = (await command(wan, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        esp = [p for p in captured if ESP in p]
        observed = {
            "delivered": sum(echo.received[payload(n)] for n in range(len(LAYOUTS) * COUNT)),
            "duplicates": sum(c - 1 for c in echo.received.values() if c > 1),
            "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - toenc,
            "layouts": dict(Counter(chain(p) for p in captured)),
            "spis": sorted({p[ESP].spi for p in esp}),
            "peer_decrypted": decrypted_packets(peer, spi),
            "peer_refused": {name: now[name] - refused[name] for name in PEER_ERRORS
                             if now[name] != refused[name]},
        }
        r.record("ipsec-offload-transport6", observed)
        assert observed == {"delivered": len(LAYOUTS) * COUNT, "duplicates": 0,
                            "toenc": len(LAYOUTS) * COUNT,
                            "layouts": {layout: COUNT for _, layout in LAYOUTS},
                            "spis": [spi], "peer_decrypted": len(LAYOUTS) * COUNT,
                            "peer_refused": {}}, observed
        assert all(echo.received[payload(n)] == 1 for n in range(len(LAYOUTS) * COUNT)), echo.received
    finally:
        if sniffer:
            sniffer.stop()
        if transport:
            transport.close()
        await step.undo()


@pytest.mark.parametrize("policy_first", [False, True], ids=["state-first", "policy-first"])
async def test_offloaded_transport_sa_carries_full_size_frames(rig, policy_first):
    """Datagrams as large as a host-to-host IPv6 transport SA carries leave
    SEC as single frames, whichever of the SA and its any-protocol policy
    came first."""
    from scapy.all import ESP, IPv6, IPv6ExtHdrFragment
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    link = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show", "dev",
                                     TARGET_WAN_IF))["stdout"])
    port_mtu = int(link[0]["mtu"])
    # xfrm_state_mtu() for AES-CBC with HMAC-SHA256-128 in IPv6 transport
    # mode: the 24 bytes of ESP header and IV, the 16-byte ICV and the IPv6
    # header come off, the rest is aligned to the block and two trailer bytes
    # come off that. Such a packet pads to nothing and leaves SEC exactly 42
    # bytes longer; unlike IPv4's, that falls short of a 1500-byte MTU, since
    # the 40-byte header leaves a remainder the block alignment drops.
    size = ((port_mtu - 80) & ~15) + 38
    frame = size + 42
    assert frame <= port_mtu < frame + 16, (port_mtu, size, frame)
    spi = 0xA9000000 | secrets.randbits(24)
    echo = Echo()
    echo.reply = False
    transport = sniffer = None
    step = Steps(r)
    try:
        await peer_on_loopback(r, wan, step)
        # Every protocol between the two hosts: it covers the SA's own ESP
        # from the DUT to the peer, which is what exposes the lookup.
        selector = ["src", DUT_IPV6_WAN + "/128", "dst", PEER6 + "/128"]
        await transport_sa(r, wan, step, DUT_IPV6_WAN, PEER6, spi, selector, policy_first)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(PEER6, FULL_PORT))
        # Two accounting passes, each of which asks every SA's path again:
        # an SA installed before its policy met the policy there.
        await asyncio.sleep(2.5)

        refused = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        toenc = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
        fragments = await fragments_sent(r)
        sniffer = await capture(r)
        with Console.target(log_path=str(artifact_dir() / "ipsec-offload-transport6-full-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(console, full_sender(DUT_IPV6_WAN, size), timeout=30)
        assert "sent" in result["stdout"], result
        await asyncio.sleep(0.5)
        captured = await asyncio.to_thread(sniffer.stop)
        sniffer = None

        now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        peer = (await command(wan, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        esp = [p for p in captured if ESP in p]
        observed = {
            "delivered": sum(echo.received[full_payload(n, size)] for n in range(2 * COUNT)),
            "duplicates": sum(c - 1 for c in echo.received.values() if c > 1),
            "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - toenc,
            "fragmented": {k: v - fragments[k] for k, v in (await fragments_sent(r)).items()},
            "frames": len(esp),
            "sizes": sorted({p[IPv6].plen + 40 for p in esp}),
            "split": sum(1 for p in captured if IPv6ExtHdrFragment in p),
            "peer_decrypted": decrypted_packets(peer, spi),
            "peer_refused": {name: now[name] - refused[name] for name in PEER_ERRORS
                             if now[name] != refused[name]},
        }
        r.record("ipsec-offload-transport6-full", {"size": size, "frame": frame, **observed})
        assert observed == {"delivered": 2 * COUNT, "duplicates": 0, "toenc": 2 * COUNT,
                            "fragmented": {4: 0, 6: 0}, "frames": 2 * COUNT, "sizes": [frame],
                            "split": 0, "peer_decrypted": 2 * COUNT,
                            "peer_refused": {}}, observed
    finally:
        if sniffer:
            sniffer.stop()
        if transport:
            transport.close()
        await step.undo()


def hop_by_hop(total):
    return (IPPROTO_IPV6, HOPOPTS, options_header(total))


def destination(total):
    return (IPPROTO_IPV6, DSTOPTS, options_header(total))


def wan_agent():
    return Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")


async def test_inbound_transport_sa_is_decrypted(rig):
    """The WAN host sends the DUT UDP through an inbound transport SA, the
    DUT's half packet-offloaded: ESP behind no extension header, hop-by-hop
    options, destination options, both, and the longest header SEC may be
    given. The port's ESP entry keys on the fixed header's next header, so
    only the first reach SEC from the port; the rest reach it through the
    stack, which tells SEC where ESP starts and which byte names it. Told
    nothing, SEC read the first extension header as ESP and refused every
    one of them (A364). Every datagram must arrive once and intact, the SA
    must have decrypted each, the stack must have given SEC exactly those
    behind extension headers, and nothing may be refused."""
    from scapy.all import ESP
    r = rig
    wan = wan_agent()
    spi = 0xA9100000 | secrets.randbits(20)
    step = Steps(r)
    sniffer = None
    groups = [((), 0, COUNT),
              ((hop_by_hop(8),), COUNT, COUNT),
              ((destination(8),), 2 * COUNT, COUNT),
              ((hop_by_hop(8), destination(16)), 3 * COUNT, COUNT),
              ((hop_by_hop(LONGEST - 40),), 4 * COUNT, COUNT),
              # A hop limit of 1, which a decrypted packet keeps on the
              # offline port, where the soft parser sends it to the CPU.
              (((IPPROTO_IPV6, IPV6_UNICAST_HOPS, 1),), 5 * COUNT, COUNT)]
    total = len(groups) * COUNT
    try:
        await peer_on_loopback(r, wan, step)
        selector = ["src", PEER6 + "/128", "dst", DUT_IPV6_WAN + "/128", "proto", "17",
                    "dport", str(IN_PORT)]
        await transport_sa(r, wan, step, DUT_IPV6_WAN, PEER6, spi, selector, direction="in")
        before = await dut_counters(r)
        sniffer = await capture(r, src=PEER6, dst=DUT_IPV6_WAN)
        with Console.target(log_path=str(artifact_dir() / "ipsec-transport6-inbound-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            async with received_on_dut(console, "AF_INET6", DUT_IPV6_WAN, IN_PORT, PEER6) as got:
                await asyncio.to_thread(send, "AF_INET6", PEER6, DUT_IPV6_WAN, IN_PORT, groups)
        captured = await asyncio.to_thread(sniffer.stop)
        sniffer = None
        # The adapter publishes SEC's per-SA counts once a second.
        await asyncio.sleep(1.5)
        dut = (await command(r.target, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        observed = {
            "delivered": [sum(got["got"].get(n, 0) for n in range(first, first + count))
                          for _, first, count in groups],
            "duplicates": sum(c - 1 for c in got["got"].values() if c > 1),
            "other": got["other"],
            "layouts": dict(Counter(chain(p) for p in captured if ESP in p)),
            "dut": moved(before, await dut_counters(r)),
            "decrypted": decrypted_packets(dut, spi),
        }
        r.record("ipsec-transport6-inbound", observed)
        assert observed == {
            "delivered": [COUNT] * len(groups), "duplicates": 0, "other": 0,
            "layouts": {"ESP": 2 * COUNT, "IPv6ExtHdrHopByHop ESP": 2 * COUNT,
                        "IPv6ExtHdrDestOpt ESP": COUNT,
                        "IPv6ExtHdrHopByHop IPv6ExtHdrDestOpt ESP": COUNT},
            "dut": {"todec": total - COUNT, "toenc": 0, "tx_dropped": 0, "mismatch": 0,
                    "refused": 0},
            "decrypted": total}, observed
    finally:
        if sniffer:
            sniffer.stop()
        await step.undo()


@pytest.mark.parametrize("direction", ["out", "in"])
async def test_transport_header_bound(rig, direction):
    """SEC may keep a header of LONGEST bytes ahead of a transport SA's ESP,
    and is given none longer (A366). The IPsec offline port parses SEC's
    output next, and FMan discarded most frames eight bytes longer, after
    SEC had numbered or decrypted them, counting them only as the port's
    filtered frames. Out, the longer frame is now the port's transmit drop
    and SEC never sees it; in, the stack gives it back unsubmitted and drops
    it as a state mismatch. Frames of LONGEST cross either way."""
    from scapy.all import ESP, IPv6
    r = rig
    wan = wan_agent()
    spi = 0xA9200000 | secrets.randbits(20)
    step = Steps(r)
    echo = Echo()
    echo.reply = False
    transport = sniffer = None
    groups = [((hop_by_hop(LONGEST - 40),), 0, COUNT),
              ((hop_by_hop(LONGEST - 32),), COUNT, COUNT)]
    port = BOUND_OUT_PORT if direction == "out" else BOUND_IN_PORT
    src, dst = (DUT_IPV6_WAN, PEER6) if direction == "out" else (PEER6, DUT_IPV6_WAN)
    try:
        await peer_on_loopback(r, wan, step)
        selector = ["src", src + "/128", "dst", dst + "/128", "proto", "17", "dport", str(port)]
        await transport_sa(r, wan, step, DUT_IPV6_WAN, PEER6, spi, selector, direction=direction)
        before = await dut_counters(r)
        sniffer = await capture(r, src=src, dst=dst)
        with Console.target(log_path=str(artifact_dir() / f"ipsec-transport6-bound-{direction}-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            if direction == "out":
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: echo, local_addr=(PEER6, port))
                result = await console_python(
                    console, numbered_sender("AF_INET6", DUT_IPV6_WAN, PEER6, port, groups), timeout=30)
                assert "sent" in result["stdout"], result
                await asyncio.sleep(0.5)
                got = {"got": {n: echo.received[numbered(n)] for n in range(2 * COUNT)
                               if echo.received[numbered(n)]}, "other": 0}
            else:
                async with received_on_dut(console, "AF_INET6", DUT_IPV6_WAN, port, PEER6) as got:
                    await asyncio.to_thread(send, "AF_INET6", PEER6, DUT_IPV6_WAN, port, groups)
        captured = await asyncio.to_thread(sniffer.stop)
        sniffer = None
        await asyncio.sleep(1.5)
        esp = [p for p in captured if ESP in p]
        observed = {
            "delivered": sorted(got["got"]),
            "duplicates": sum(c - 1 for c in got["got"].values() if c > 1),
            "wire": dict(Counter(p[IPv6].plen + 40 - len(p[ESP]) for p in esp)),
            "dut": moved(before, await dut_counters(r)),
        }
        r.record(f"ipsec-transport6-bound-{direction}", observed)
        # On the wire: the frames the sender let go, their headers as long as
        # the group asked. Out, the refused group never left the DUT.
        wire = {LONGEST: COUNT} if direction == "out" else {LONGEST: COUNT, LONGEST + 8: COUNT}
        dut = ({"todec": 0, "toenc": COUNT, "tx_dropped": COUNT, "mismatch": 0, "refused": 0}
               if direction == "out" else
               {"todec": COUNT, "toenc": 0, "tx_dropped": 0, "mismatch": COUNT, "refused": 0})
        assert observed == {"delivered": list(range(COUNT)), "duplicates": 0, "wire": wire,
                            "dut": dut}, observed
    finally:
        if sniffer:
            sniffer.stop()
        if transport:
            transport.close()
        await step.undo()


async def test_transport_sa_sends_hop_limit_one(rig):
    """A transport SA's packet keeps its own hop limit through SEC, and 1 is
    a proper one: a first traceroute probe, a protocol that stays on the
    link. The IPsec offline port sends a frame with a hop limit of 1 or 0 to
    the CPU, as a decrypted packet its forwarding entry would pass on
    expired, and an outbound SA's output was freed there (A365). It now
    passes ESP its fixed header names. It cannot see ESP behind extension
    headers, so the driver refuses such a frame before SEC numbers it: the
    port's transmit drop. With a hop limit of 2 the same header crosses."""
    from scapy.all import ESP, IPv6
    r = rig
    wan = wan_agent()
    spi = 0xA9300000 | secrets.randbits(20)
    step = Steps(r)
    echo = Echo()
    echo.reply = False
    transport = sniffer = None
    hops = lambda n: (IPPROTO_IPV6, IPV6_UNICAST_HOPS, n)
    groups = [((hops(1),), 0, COUNT),
              ((hops(1), hop_by_hop(8)), COUNT, COUNT),
              ((hops(2), hop_by_hop(8)), 2 * COUNT, COUNT)]
    try:
        await peer_on_loopback(r, wan, step)
        selector = ["src", DUT_IPV6_WAN + "/128", "dst", PEER6 + "/128", "proto", "17",
                    "dport", str(HOP_PORT)]
        await transport_sa(r, wan, step, DUT_IPV6_WAN, PEER6, spi, selector)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(PEER6, HOP_PORT))
        before = await dut_counters(r)
        refused = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        sniffer = await capture(r)
        with Console.target(log_path=str(artifact_dir() / "ipsec-transport6-hop-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(
                console, numbered_sender("AF_INET6", DUT_IPV6_WAN, PEER6, HOP_PORT, groups), timeout=30)
        assert "sent" in result["stdout"], result
        await asyncio.sleep(0.5)
        captured = await asyncio.to_thread(sniffer.stop)
        sniffer = None
        now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        peer = (await command(wan, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        observed = {
            "delivered": sorted(n for n in range(3 * COUNT) if echo.received[numbered(n)]),
            "duplicates": sum(c - 1 for c in echo.received.values() if c > 1),
            "wire": dict(Counter(f"hop limit {p[IPv6].hlim}: {chain(p)}" for p in captured if ESP in p)),
            "dut": moved(before, await dut_counters(r)),
            "peer_decrypted": decrypted_packets(peer, spi),
            "peer_refused": {name: now[name] - refused[name] for name in PEER_ERRORS
                             if now[name] != refused[name]},
        }
        r.record("ipsec-transport6-hop", observed)
        assert observed == {
            "delivered": [*range(COUNT), *range(2 * COUNT, 3 * COUNT)], "duplicates": 0,
            "wire": {"hop limit 1: ESP": COUNT, "hop limit 2: IPv6ExtHdrHopByHop ESP": COUNT},
            "dut": {"todec": 0, "toenc": 2 * COUNT, "tx_dropped": COUNT, "mismatch": 0, "refused": 0},
            "peer_decrypted": 2 * COUNT, "peer_refused": {}}, observed
    finally:
        if sniffer:
            sniffer.stop()
        if transport:
            transport.close()
        await step.undo()

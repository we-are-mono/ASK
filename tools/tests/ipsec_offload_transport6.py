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
from _ipsec_transport import (transport_sa)

PEER6 = "fc00:a8::1"
PORT = 48994
FULL_PORT = 48995
COUNT = 16
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


async def capture(r, ready_timeout=5):
    from scapy.all import AsyncSniffer
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=wire_interface(r), store=True, started_callback=ready.set,
                           filter=f"ip6 and src host {DUT_IPV6_WAN} and dst host {PEER6}")
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

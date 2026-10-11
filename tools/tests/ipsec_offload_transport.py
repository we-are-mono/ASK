"""A packet-offloaded transport-mode SA, which its peer decrypts.

Transport mode keeps the packet's own IP header, so SEC has to be told how
long that header is and where its next-header byte sits: it moves that byte
into the ESP trailer, writes ESP in its place and encrypts what follows. The
DPAA driver hands SEC those values per frame in DPOVRD, which overrides the
SA's PDB. A tunnel's value there -- the inner protocol, with header length and
offset zero -- makes SEC encrypt the IP header itself and name IPIP in the
trailer, and nothing the peer receives decodes.

The DUT sends UDP from its WAN address to an address on the WAN host's
loopback through an offloaded transport SA; the WAN host's half is ordinary
software. Two thirds of the datagrams carry IPv4 options, four bytes or the
most a header holds, whose longer header the SA's PDB alone would get wrong.
Every datagram must arrive once and intact, the DUT's port must have handed
SEC exactly that many frames, the peer's SA must have decrypted as many, and
the peer must have refused nothing.

The same holds the other way: the WAN host sends the DUT datagrams through an
inbound transport SA, with and without options. SEC decrypts them against the
plain header its PDB states, so the port sends ESP behind options to the CPU,
which tells SEC the header's length (A364). And a packet with a TTL of 1
leaves through an outbound SA as it does without one (A365).

A second case selects every protocol between the two hosts, which is what
strongSwan installs for a host-to-host SA and so what a transport SA usually
runs under, and sends datagrams as large as the SA carries: each leaves SEC as
a frame exactly the port's MTU. A selector that wide also covers the SA's own
ESP, and the adapter once asked for the route to the peer through xfrm, which
answered with the SA's own bundle and its inner MTU. The SA's entry then
bounded every frame leaving SEC by that, and excepted or fragmented the
full-size ones (A231). Every frame must cross whole: the peer sees each as one
ESP frame of the full size, the microcode fragments nothing, and every
datagram arrives, with DF and without.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import secrets
import struct
import threading

import pytest

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import TARGET_WAN_IF
from _flowtable_ipv6_sa import (fragments_sent)
from _flowtable_rig import (artifact_dir, WAN_IP, Echo, command, console_python)
from _flowtable_service_ipsec import (wire_interface)
from _flowtable_service_ipsec_replay import (PEER_ERRORS, xfrm_mib)
from _ipsec_inbound_flow_offload import (sec_counter)
from _ipsec_offload_egress_device import (PEER, wan_outer)
from _ipsec_packet_offload_traffic import (decrypted_packets)
from _ipsec_transport import (dut_counters, moved, numbered, received_on_dut, send, sender as
                              numbered_sender, transport_sa)

PORT = 48992
FULL_PORT = 48993
COUNT = 32
# Four option bytes: three no-ops and the end of the list, so the header is
# 24 bytes rather than 20; and the most a header holds, 40, for 60 bytes.
OPTIONS = b"\x01\x01\x01\x00"
LONG_OPTIONS = b"\x01" * 39 + b"\x00"
# Record Route, 39 bytes for nine addresses with the first slot free, and
# the end of the list.
RECORD_ROUTE = bytes([7, 39, 4]) + bytes(36) + b"\x00"
IN_PORT, TTL_PORT = 49480, 49481
IPPROTO_IP, IP_OPTIONS, IP_TTL = 0, 4, 2


def payload(n):
    return struct.pack("!Q", n) + b"ASK-transport-sa".ljust(48, b".")


def full_payload(n, size):
    """Datagram `n` of an IPv4 packet `size` bytes long, headers included."""
    return struct.pack("!Q", n) + b"ASK-transport-full".ljust(size - 36, b".")


def sender(source):
    return f'''
import socket, struct, time
for options, first in ((b'', 0), ({OPTIONS!r}, {COUNT}), ({LONG_OPTIONS!r}, {2 * COUNT})):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if options:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, options)
    s.bind(({source!r}, 0))
    for n in range(first, first + {COUNT}):
        s.sendto(struct.pack('!Q', n) + b'ASK-transport-sa'.ljust(48, b'.'), ({PEER!r}, {PORT}))
        time.sleep(0.01)
    s.close()
print('sent')
'''


def full_sender(source, size):
    """COUNT datagrams of `size` bytes with DF and COUNT without."""
    return f'''
import socket, struct, time
# IP_MTU_DISCOVER and its IP_PMTUDISC_DO and _DONT (linux/in.h).
for pmtu, first in ((2, 0), (0, {COUNT})):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, 10, pmtu)
    s.bind(({source!r}, 0))
    for n in range(first, first + {COUNT}):
        s.sendto(struct.pack('!Q', n) + b'ASK-transport-full'.ljust({size} - 36, b'.'), ({PEER!r}, {FULL_PORT}))
        time.sleep(0.01)
    s.close()
print('sent')
'''


async def peer_on_loopback(r, wan, step):
    await step(wan, ["ip", "addr", "add", PEER + "/32", "dev", "lo"],
               ["ip", "addr", "del", PEER + "/32", "dev", "lo"])
    await step(r.target, ["ip", "route", "add", PEER + "/32", "via", WAN_IP, "dev",
                          TARGET_WAN_IF],
               ["ip", "route", "del", PEER + "/32"])


async def test_offloaded_transport_sa_is_decrypted(rig):
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer = await wan_outer(r)
    spi = 0xA8000000 | secrets.randbits(24)
    echo = Echo()
    echo.reply = False
    transport = None
    cleanup = []

    async def step(agent, argv, undo):
        await command(agent, r.session, *argv)
        cleanup.append((agent, undo))

    try:
        await peer_on_loopback(r, wan, step)
        # Only this test's datagrams: the selector names the port. UDP by
        # number: the image carries no /etc/protocols for ip to resolve names.
        selector = ["src", outer + "/32", "dst", PEER + "/32", "proto", "17", "dport", str(PORT)]
        await transport_sa(r, wan, step, outer, PEER, spi, selector)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(PEER, PORT))

        refused = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        toenc = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
        with Console.target(log_path=str(artifact_dir() / "ipsec-offload-transport-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(console, sender(outer), timeout=30)
        assert "sent" in result["stdout"], result
        await asyncio.sleep(0.5)

        now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        peer = (await command(wan, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        observed = {
            "delivered": sum(echo.received[payload(n)] for n in range(3 * COUNT)),
            "duplicates": sum(c - 1 for c in echo.received.values() if c > 1),
            "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - toenc,
            "peer_decrypted": decrypted_packets(peer, spi),
            "peer_refused": {name: now[name] - refused[name] for name in PEER_ERRORS
                             if now[name] != refused[name]},
        }
        r.record("ipsec-offload-transport", observed)
        assert observed == {"delivered": 3 * COUNT, "duplicates": 0, "toenc": 3 * COUNT,
                            "peer_decrypted": 3 * COUNT, "peer_refused": {}}, observed
        assert all(echo.received[payload(n)] == 1 for n in range(3 * COUNT)), echo.received
    finally:
        if transport:
            transport.close()
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


@pytest.mark.parametrize("policy_first", [False, True], ids=["state-first", "policy-first"])
async def test_offloaded_transport_sa_carries_full_size_frames(rig, policy_first):
    """Datagrams as large as a host-to-host transport SA carries, with DF and
    without, leave SEC as single frames of the port's full MTU, whichever of
    the SA and its any-protocol policy came first."""
    from scapy.all import IP, AsyncSniffer
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer = await wan_outer(r)
    link = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show", "dev",
                                     TARGET_WAN_IF))["stdout"])
    port_mtu = int(link[0]["mtu"])
    # xfrm_state_mtu() for AES-CBC with HMAC-SHA256-128 in transport mode:
    # the 8-byte ESP header, the 16-byte IV and ICV and the IPv4 header come
    # off, the rest is aligned to the block and two trailer bytes come off
    # that. Such a datagram pads to nothing, so it leaves SEC exactly 42
    # bytes longer: at most the port's MTU, and exactly it on 1500 bytes.
    size = ((port_mtu - 60) & ~15) + 18
    frame = size + 42
    assert frame <= port_mtu and (port_mtu != 1500 or frame == 1500), (port_mtu, size, frame)
    spi = 0xA8000000 | secrets.randbits(24)
    echo = Echo()
    echo.reply = False
    transport = sniffer = None
    cleanup = []

    async def step(agent, argv, undo):
        await command(agent, r.session, *argv)
        cleanup.append((agent, undo))

    try:
        await peer_on_loopback(r, wan, step)
        # Every protocol between the two hosts: it covers the SA's own ESP
        # from the DUT to the peer, which is what exposes the lookup.
        selector = ["src", outer + "/32", "dst", PEER + "/32"]
        await transport_sa(r, wan, step, outer, PEER, spi, selector, policy_first)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(PEER, FULL_PORT))
        # Two accounting passes, each of which asks every SA's path again:
        # an SA installed before its policy met the policy there.
        await asyncio.sleep(2.5)

        refused = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        toenc = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
        fragments = await fragments_sent(r)
        # Everything the DUT sends the peer, as the wire carries it.
        ready = threading.Event()
        sniffer = AsyncSniffer(iface=wire_interface(r), store=True, started_callback=ready.set,
                               filter=f"ip and src host {outer} and dst host {PEER}")
        sniffer.start()
        assert await asyncio.to_thread(ready.wait, 5), "wire capture did not start"
        with Console.target(log_path=str(artifact_dir() / "ipsec-offload-transport-full-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(console, full_sender(outer, size), timeout=30)
        assert "sent" in result["stdout"], result
        await asyncio.sleep(0.5)
        captured = await asyncio.to_thread(sniffer.stop)
        sniffer = None

        now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        peer = (await command(wan, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        esp = [p[IP] for p in captured if IP in p and p[IP].proto == 50]
        observed = {
            "delivered": sum(echo.received[full_payload(n, size)] for n in range(2 * COUNT)),
            "duplicates": sum(c - 1 for c in echo.received.values() if c > 1),
            "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - toenc,
            "fragmented": {k: v - fragments[k] for k, v in (await fragments_sent(r)).items()},
            "frames": len(esp),
            "sizes": sorted({p.len for p in esp}),
            "split": sum(1 for p in esp if p.flags.MF or p.frag),
            "df": sum(1 for p in esp if p.flags.DF),
            "peer_decrypted": decrypted_packets(peer, spi),
            "peer_refused": {name: now[name] - refused[name] for name in PEER_ERRORS
                             if now[name] != refused[name]},
        }
        r.record("ipsec-offload-transport-full", {"size": size, "frame": frame, **observed})
        # Every datagram crossed SEC once, left it whole at the full size --
        # the DF half with DF, which transport mode copies from the packet's
        # own header -- and reached the far end: none was excepted after
        # SEC, which would have lost it, nor fragmented, which the microcode
        # would have counted.
        assert observed == {"delivered": 2 * COUNT, "duplicates": 0, "toenc": 2 * COUNT,
                            "fragmented": {4: 0, 6: 0}, "frames": 2 * COUNT, "sizes": [frame],
                            "split": 0, "df": COUNT, "peer_decrypted": 2 * COUNT,
                            "peer_refused": {}}, observed
    finally:
        if sniffer:
            sniffer.stop()
        if transport:
            transport.close()
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


async def test_inbound_transport_sa_is_decrypted(rig):
    """The WAN host sends the DUT UDP through an inbound transport SA, the
    DUT's half packet-offloaded: without options, with four bytes of them
    and with forty. SEC decrypts an SA's frames against the 20-byte header
    its PDB states and read the options as ESP, refusing every such frame;
    the port now sends them to the CPU, which tells SEC the header's length
    (A364). Every datagram must arrive once and intact, the SA must have
    decrypted each, the stack must have given SEC exactly those with
    options, and nothing may be refused."""
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer = await wan_outer(r)
    spi = 0xA8100000 | secrets.randbits(20)
    cleanup = []

    async def step(agent, argv, undo):
        await command(agent, r.session, *argv)
        cleanup.append((agent, undo))

    groups = [((), 0, COUNT),
              (((IPPROTO_IP, IP_OPTIONS, OPTIONS),), COUNT, COUNT),
              (((IPPROTO_IP, IP_OPTIONS, LONG_OPTIONS),), 2 * COUNT, COUNT),
              # Record Route with free slots: the DUT's stack writes its
              # own address into the header it delivers.
              (((IPPROTO_IP, IP_OPTIONS, RECORD_ROUTE),), 3 * COUNT, COUNT),
              # A TTL of 1, which a decrypted packet keeps on the offline
              # port, where the soft parser sends it to the CPU.
              (((IPPROTO_IP, IP_TTL, 1),), 4 * COUNT, COUNT)]
    total = len(groups) * COUNT
    try:
        await peer_on_loopback(r, wan, step)
        selector = ["src", PEER + "/32", "dst", outer + "/32", "proto", "17", "dport", str(IN_PORT)]
        await transport_sa(r, wan, step, outer, PEER, spi, selector, direction="in")
        before = await dut_counters(r)
        with Console.target(log_path=str(artifact_dir() / "ipsec-transport-inbound-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            async with received_on_dut(console, "AF_INET", outer, IN_PORT, PEER) as got:
                await asyncio.to_thread(send, "AF_INET", PEER, outer, IN_PORT, groups)
        # The adapter publishes SEC's per-SA counts once a second.
        await asyncio.sleep(1.5)
        dut = (await command(r.target, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        observed = {
            "delivered": [sum(got["got"].get(n, 0) for n in range(first, first + count))
                          for _, first, count in groups],
            "duplicates": sum(c - 1 for c in got["got"].values() if c > 1),
            "other": got["other"],
            "dut": moved(before, await dut_counters(r)),
            "decrypted": decrypted_packets(dut, spi),
        }
        r.record("ipsec-transport-inbound", observed)
        assert observed == {
            "delivered": [COUNT] * len(groups), "duplicates": 0, "other": 0,
            "dut": {"todec": total - COUNT, "toenc": 0, "tx_dropped": 0, "mismatch": 0, "refused": 0},
            "decrypted": total}, observed
    finally:
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


async def test_transport_sa_sends_ttl_one(rig):
    """A transport SA's packet keeps its own TTL through SEC, and 1 is a
    proper one: a first traceroute probe, a protocol that stays on the
    link. The IPsec offline port sends a frame with a TTL of 1 or 0 to the
    CPU, as a decrypted packet its forwarding entry would pass on expired,
    and an outbound SA's output was freed there (A365). ESP is now SEC's
    output and passes, and every datagram must arrive."""
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer = await wan_outer(r)
    spi = 0xA8200000 | secrets.randbits(20)
    echo = Echo()
    echo.reply = False
    transport = None
    cleanup = []

    async def step(agent, argv, undo):
        await command(agent, r.session, *argv)
        cleanup.append((agent, undo))

    try:
        await peer_on_loopback(r, wan, step)
        selector = ["src", outer + "/32", "dst", PEER + "/32", "proto", "17", "dport", str(TTL_PORT)]
        await transport_sa(r, wan, step, outer, PEER, spi, selector)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(PEER, TTL_PORT))
        before = await dut_counters(r)
        refused = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        with Console.target(log_path=str(artifact_dir() / "ipsec-transport-ttl-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(console, numbered_sender(
                "AF_INET", outer, PEER, TTL_PORT, [(((IPPROTO_IP, IP_TTL, 1),), 0, COUNT)]), timeout=30)
        assert "sent" in result["stdout"], result
        await asyncio.sleep(0.5)
        now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        peer = (await command(wan, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        observed = {
            "delivered": sum(echo.received[numbered(n)] for n in range(COUNT)),
            "duplicates": sum(c - 1 for c in echo.received.values() if c > 1),
            "dut": moved(before, await dut_counters(r)),
            "peer_decrypted": decrypted_packets(peer, spi),
            "peer_refused": {name: now[name] - refused[name] for name in PEER_ERRORS
                             if now[name] != refused[name]},
        }
        r.record("ipsec-transport-ttl", observed)
        assert observed == {
            "delivered": COUNT, "duplicates": 0,
            "dut": {"todec": 0, "toenc": COUNT, "tx_dropped": 0, "mismatch": 0, "refused": 0},
            "peer_decrypted": COUNT, "peer_refused": {}}, observed
    finally:
        if transport:
            transport.close()
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)

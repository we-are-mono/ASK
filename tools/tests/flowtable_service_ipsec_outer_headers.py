"""Inbound tunnel ESP whose outer header is not the plain one its SA's PDB
states.

A tunnel SA's decap PDB states a 20- or 40-byte outer header, and a UDP header
behind it for ESP-in-UDP. A frame that carries IPv4 options or IPv6 extension
headers ahead of ESP reaches the stack instead of SEC: the port's IPv6 ESP
table keys on the fixed header's next header, and the soft parser sends IPv4
ESP or UDP behind options to the CPU. xfrm_input() hands it to the driver's
submit, which has to tell SEC the frame's own outer header; given the PDB as it
stands, SEC read the options as ESP and refused every such frame (A368).

Each case sends frames of one outer shape, built on this host with the SA's
keys, and checks the LAN end receives every one: a plain frame through the
classifier, with no submit, and every other through the submit, `tx todec`.
A header whose ESP ends past byte 160 is beyond FMan's parser (A367): the
port drops some such frames, how many varies, and counts every one it drops
in its `rx_dropped`; the rest reach the submit and are delivered.
"""
from __future__ import annotations

import asyncio
import contextlib
import secrets
import socket

import pytest

from ask_orch.uart import Console
from _flowtable_rig import (WAN_IP, artifact_dir, console_python, read)
from _flowtable_service_ipsec import (Transform)
from _flowtable_service_ipsec_natt import (NATT, PORTS)
from _flowtable_service_ipsec_replay import (Inbound, arrivals, delivered, dut_counters, lan_listener)
from _ipsec_transport import (Ready, options_header)
from _topology import TARGET_WAN_IF

OUTER6 = Transform(outer6=True)
NEXTHDR_HOP, NEXTHDR_DEST = 0, 60
COUNT = 8
# FMan's parser reads no further than this byte of a frame (A367).
PARSE_REACH = 160

NOP4 = (b"\x01" * 4,)
# Record Route with all nine slots free, and the end of the list: 40 bytes,
# the longest IPv4 header. The DUT's stack writes its own address into it.
RECORD_ROUTE = (bytes([7, 39, 4]) + bytes(36), b"\x00")


def chain(headers, last):
    """An IPv6 extension-header chain of (type, length) entries, the last
    naming `last`: the fixed header's next header and the chain's bytes."""
    out = b""
    for i, (_, total) in enumerate(headers):
        header = bytearray(options_header(total))
        header[0] = headers[i + 1][0] if i + 1 < len(headers) else last
        out += bytes(header)
    return (headers[0][0] if headers else last), out


# Each shape: what to call it, the IPv4 options or IPv6 extension headers the
# outer header carries, and whether its ESP still ends within the parser's
# reach. A plain header reaches SEC through the classifier; anything else
# through the stack's submit.
SHAPES = {
    "outer4": [("plain", ()), ("nop", NOP4), ("record-route", RECORD_ROUTE)],
    "natt": [("plain", ()), ("nop", NOP4), ("record-route", RECORD_ROUTE)],
    "outer6": [("plain", ()), ("hop-by-hop", ((NEXTHDR_HOP, 8),)),
               ("destination", ((NEXTHDR_DEST, 8),)),
               ("both", ((NEXTHDR_HOP, 8), (NEXTHDR_DEST, 16))),
               # ESP's SPI and sequence number end at byte 158.
               ("longest", ((NEXTHDR_HOP, 88), (NEXTHDR_DEST, 8))),
               # They end at byte 166, past the parser's reach.
               ("past-reach", ((NEXTHDR_HOP, 104),))],
}


def outer(r, shape, sealed):
    """The frame carrying `sealed` ESP under the outer header `shape` names,
    and the byte its ESP header ends at."""
    from scapy.all import Ether, IP, IPOption, IPv6, Raw, UDP
    eth = Ether(src=r.wan_mac, dst=r.dut_wan_mac)
    if r.ipsec.transform.outer6:
        first, headers = chain(shape, 50)
        frame = eth / IPv6(src=r.ipsec.peer, dst=r.ipsec.outer, hlim=64, nh=first) / Raw(headers + sealed)
        return frame, 14 + 40 + len(headers) + 8
    options = [IPOption(option) for option in shape]
    if r.ipsec.transform.encap:
        dut, peer = PORTS
        frame = (eth / IP(src=r.ipsec.peer, dst=r.ipsec.outer, ttl=64, options=options)
                 / UDP(sport=peer, dport=dut, chksum=0) / Raw(sealed))
        udp = 8
    else:
        frame = eth / IP(src=r.ipsec.peer, dst=r.ipsec.outer, ttl=64, proto=50, options=options) / Raw(sealed)
        udp = 0
    wire = bytes(frame)
    header = (wire[14] & 0xF) * 4
    assert header == 20 + sum(len(option) for option in shape), (shape, header)
    return frame, 14 + header + udp + 8


def holder(outer, port, control, peer, ready, seconds):
    """An ESP-in-UDP socket on the DUT's NAT-T port, as an IKE daemon keeps
    one, for as long as the test sends: without it the stack has nowhere to
    take a punted ESP-in-UDP frame. It says it is ready with a datagram to
    `peer`:`ready` and closes on a word to `control`, or after `seconds`."""
    return f'''
import select, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({outer!r}, {port}))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)
stop = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
stop.bind(({outer!r}, {control}))
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"ready", ({peer!r}, {ready}))
select.select([stop], [], [], {seconds})
print("held")
'''


@contextlib.asynccontextmanager
async def natt_socket(r, seconds=120):
    if not r.ipsec.transform.encap:
        yield
        return
    ready_port, control = 49610, 49611
    loop = asyncio.get_running_loop()
    transport, ready = await loop.create_datagram_endpoint(Ready, local_addr=(WAN_IP, ready_port))
    with Console.target(log_path=str(artifact_dir() / "ipsec-outer-natt-uart.log")) as console:
        await asyncio.to_thread(console.login, "root", None)
        task = asyncio.create_task(console_python(
            console, holder(r.ipsec.outer, PORTS[0], control, WAN_IP, ready_port, seconds),
            timeout=seconds + 30))
        try:
            done, _ = await asyncio.wait({task, ready.ready}, timeout=30,
                                         return_when=asyncio.FIRST_COMPLETED)
            assert ready.ready in done, ("the DUT's NAT-T socket never said it was ready",
                                         task.result() if task in done else None)
            yield
        finally:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as word:
                word.sendto(b"done", (r.ipsec.outer, control))
            transport.close()
            await task


async def rx_dropped(r):
    return int((await read(r.target, r.session, f"/sys/class/net/{TARGET_WAN_IF}/statistics/rx_dropped")).strip())


@pytest.mark.parametrize("ipsec_service", [Transform(), NATT, OUTER6], ids=list(SHAPES), indirect=True)
async def test_outer_header_reaches_sec(ipsec_service, request):
    from scapy.all import sendp

    r = ipsec_service
    case = request.node.callspec.id
    marker = secrets.token_bytes(16)
    sa = Inbound(r, marker, r.ipsec.transform.algorithms, 32)
    await sa.install()
    records, seq = [], 1
    async with lan_listener(r, marker), natt_socket(r):
        for name, shape in SHAPES[case]:
            seqs = list(range(seq, seq + COUNT))
            seq += COUNT
            frames, ends = zip(*(outer(r, shape, sa.sealed(n)) for n in seqs))
            before, seen, dropped = await dut_counters(r), await delivered(r), await rx_dropped(r)
            await asyncio.to_thread(sendp, list(frames), iface=r.wan_if, inter=0.01, verbose=False)
            got = await arrivals(r, sa.spi, seen, COUNT if ends[0] <= PARSE_REACH else 0)
            after = await dut_counters(r)
            record = {"case": case, "shape": name, "esp_ends": ends[0],
                      "delivered": sorted(got.elements()), "rx_dropped": await rx_dropped(r) - dropped,
                      "counters": {key: after[key] - before[key] for key in after}}
            records.append(record)
            r.record("ipsec-outer-headers", records)
            plain = not shape
            if ends[0] <= PARSE_REACH:
                # Every frame reaches the LAN end once, SEC refusing none:
                # a plain one by the classifier, anything else by the submit.
                assert sorted(got.elements()) == seqs, record
                assert record["counters"]["todec"] == (0 if plain else COUNT), record
                assert record["counters"]["ipsec_sec_refused"] == 0, record
            else:
                # Past the parser's reach the port drops what it cannot
                # classify, and counts every frame it drops.
                lost = COUNT - sum(got.values())
                assert set(got) <= set(seqs) and max(got.values(), default=1) == 1, record
                assert record["rx_dropped"] >= lost, record
                assert record["counters"]["ipsec_sec_refused"] == 0, record

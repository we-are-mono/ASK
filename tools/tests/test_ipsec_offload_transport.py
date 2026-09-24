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
software. Half the datagrams carry IPv4 options, whose longer header the SA's
PDB alone would get wrong. Every datagram must arrive once and intact, the
DUT's port must have handed SEC exactly that many frames, the peer's SA must
have decrypted as many, and the peer must have refused nothing.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import secrets
import struct

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import TARGET_WAN_IF
from test_flowtable_offload import (ARTIFACTS, WAN_IP, Echo, command, console_python,  # noqa: F401
                                   rig)
from test_flowtable_service_ipsec_replay import PEER_ERRORS, xfrm_mib
from test_ipsec_inbound_flow_offload import AUTH, CIPHER, sec_counter
from test_ipsec_offload_egress_device import PEER, wan_outer
from test_ipsec_packet_offload_traffic import decrypted_packets

PORT = 48992
REQID = "49521"
COUNT = 32
# Four option bytes: three no-ops and the end of the list, so the header is
# 24 bytes rather than 20.
OPTIONS = b"\x01\x01\x01\x00"


def payload(n):
    return struct.pack("!Q", n) + b"ASK-transport-sa".ljust(48, b".")


def sender(source):
    return f'''
import socket, struct, time
for options, first in ((b'', 0), ({OPTIONS!r}, {COUNT})):
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
        await step(wan, ["ip", "addr", "add", PEER + "/32", "dev", "lo"],
                   ["ip", "addr", "del", PEER + "/32", "dev", "lo"])
        await step(r.target, ["ip", "route", "add", PEER + "/32", "via", WAN_IP, "dev",
                              TARGET_WAN_IF],
                   ["ip", "route", "del", PEER + "/32"])
        state = ["src", outer, "dst", PEER, "proto", "esp", "spi", hex(spi)]
        algorithms = ["mode", "transport", "reqid", REQID, "enc", "cbc(aes)", CIPHER,
                      "auth-trunc", "hmac(sha256)", AUTH, "128"]
        await step(wan, ["ip", "xfrm", "state", "add", *state, *algorithms, "replay-window", "32"],
                   ["ip", "xfrm", "state", "delete", *state])
        await step(r.target, ["ip", "xfrm", "state", "add", *state, *algorithms,
                              "offload", "packet", "dev", TARGET_WAN_IF, "dir", "out"],
                   ["ip", "xfrm", "state", "delete", *state])
        # Only this test's datagrams: the selector names the port. UDP by
        # number: the image carries no /etc/protocols for ip to resolve names.
        selector = ["src", outer + "/32", "dst", PEER + "/32", "proto", "17", "dport", str(PORT)]
        template = ["tmpl", "src", outer, "dst", PEER, "proto", "esp", "mode", "transport",
                    "reqid", REQID, "level", "required"]
        await step(wan, ["ip", "xfrm", "policy", "add", *selector, "dir", "in", *template],
                   ["ip", "xfrm", "policy", "delete", *selector, "dir", "in"])
        await step(r.target, ["ip", "xfrm", "policy", "add", *selector, "dir", "out", *template,
                              "offload", "packet", "dev", TARGET_WAN_IF],
                   ["ip", "xfrm", "policy", "delete", *selector, "dir", "out"])
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(PEER, PORT))

        refused = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        toenc = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
        with Console.target(log_path=str(ARTIFACTS / "ipsec-offload-transport-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(console, sender(outer), timeout=30)
        assert "sent" in result["stdout"], result
        await asyncio.sleep(0.5)

        now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        peer = (await command(wan, r.session, "ip", "-s", "xfrm", "state"))["stdout"]
        observed = {
            "delivered": sum(echo.received[payload(n)] for n in range(2 * COUNT)),
            "duplicates": sum(c - 1 for c in echo.received.values() if c > 1),
            "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - toenc,
            "peer_decrypted": decrypted_packets(peer, spi),
            "peer_refused": {name: now[name] - refused[name] for name in PEER_ERRORS
                             if now[name] != refused[name]},
        }
        r.record("ipsec-offload-transport", observed)
        assert observed == {"delivered": 2 * COUNT, "duplicates": 0, "toenc": 2 * COUNT,
                            "peer_decrypted": 2 * COUNT, "peer_refused": {}}, observed
        assert all(echo.received[payload(n)] == 1 for n in range(2 * COUNT)), echo.received
    finally:
        if transport:
            transport.close()
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)

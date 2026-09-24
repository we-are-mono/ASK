"""IPv6 inside an IPsec tunnel with an IPv4 outer header, in hardware.

The adapter accepts IPv4 tunnel endpoints only, so an IPv6 flow reaches an SA
as IPv6-in-IPv4: a dual-stack LAN's IPv6 carried over an IPv4 site-to-site
tunnel. What such a direction does with a packet too big for the SA's bundle
is the question here. Software checks a packet against the bundle's MTU, the
outer device's less the ESP expansion, and answers an oversized one with
Packet Too Big (xfrm6_tunnel_check_size). The entry is programmed with the
port's MTU and the expansion on top, so the hardware takes the packet, and
what it does next is what these cases pin: it encrypts the inner packet whole
and fragments the outer IPv4 packet, whose DF it leaves clear because the
inner family has none to copy. The inner packet is never fragmented, which is
what bounding an IPv6 direction exists to prevent (a router must not fragment
IPv6), and it arrives exactly once. Outer fragmentation is what Linux itself
does for an IPv4 inner packet without DF.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket

import pytest

from _topology import LAN_IPV6, LAN_NIC, TARGET_WAN_IF, WAN_IPV6, lan_run_python
from test_flowtable_ipv6 import (PayloadEcho, _drive, _drop_tables, _offload_table, _udp_exchange,
                                 ipv6_rig)  # noqa: F401
from test_flowtable_offload import command, read
from test_ipsec_inbound_flow_offload import crypto

SPORT, DPORT = 48960, 48961
REQIDS = {"out": "49411", "in": "49412"}
# The bundle's MTU for AES-CBC and a 128-bit HMAC-SHA256 tag over an IPv4
# outer header: ((1500 - 20 - 8 - 16 - 16) & ~15) - 2.
BUNDLE_MTU = 1438
FITS = BUNDLE_MTU - 40 - 8


async def fragments_sent(r):
    text = await read(r.target, r.session, "/proc/ucode_frag/stats")
    return {family: int(text.split(f"Number of IPv{family} fragments sent :")[1].split()[0])
            for family in (4, 6)}


async def sa_pair(r, cleanup):
    """A tunnel-mode SA pair between the DUT's WAN address and the WAN host,
    selecting the IPv6 flow between the LAN VM and the WAN host's IPv6 address.
    The DUT's half is packet-offloaded; the WAN host's is ordinary software."""
    outer = next(a["local"] for i in json.loads((await command(
        r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_WAN_IF))["stdout"])
        for a in i["addr_info"] if a["family"] == "inet")
    peer = os.environ.get("ASK_WAN_IP", "127.0.0.1")

    async def add(agent, kind, identity, *options):
        await command(agent, r.session, "ip", "xfrm", kind, "add", *identity, *options)
        cleanup.append((agent, ["ip", "xfrm", kind, "delete", *identity]))

    for direction in ("out", "in"):
        spi = hex(0xA6000000 | secrets.randbits(24))
        outer_src, outer_dst = (outer, peer) if direction == "out" else (peer, outer)
        src, dst = (LAN_IPV6, WAN_IPV6) if direction == "out" else (WAN_IPV6, LAN_IPV6)
        state = ["src", outer_src, "dst", outer_dst, "proto", "esp", "spi", spi]
        # A state's selector takes the outer family unless told otherwise, and
        # xfrm hands a flow only a state whose selector is the flow's family.
        inner = ["sel", "src", "::/0", "dst", "::/0"]
        await add(r.wan, "state", state, *crypto(REQIDS[direction]), *inner, "replay-window", "32")
        window = ["replay-window", "32"] if direction == "in" else []
        await add(r.target, "state", state, *crypto(REQIDS[direction]), *inner, *window,
                  "offload", "packet", "dev", TARGET_WAN_IF, "dir", direction)
        selector = ["src", src + "/128", "dst", dst + "/128"]
        template = ["tmpl", "src", outer_src, "dst", outer_dst, "proto", "esp", "mode", "tunnel",
                    "reqid", REQIDS[direction], "level", "required"]
        await add(r.wan, "policy", [*selector, "dir", "in" if direction == "out" else "out"], *template)
        await add(r.target, "policy", [*selector, "dir", direction], *template,
                  "offload", "packet", "dev", TARGET_WAN_IF)
        if direction == "in":
            await add(r.target, "policy", [*selector, "dir", "fwd"], *template)


async def test_flowtable_ipv6_sa_oversized(ipv6_rig):
    r = ipv6_rig
    echo = PayloadEcho()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, DPORT), family=socket.AF_INET6)
    cleanup = []

    async def send(count=8):
        return await _udp_exchange(r, SPORT, WAN_IPV6, DPORT, count, (WAN_IPV6, DPORT),
                                   "flowtable_v6_sa")

    try:
        # A dual-stack WAN carries an IPv6 default route. With packet offload
        # the kernel looks the child route up in the policy's family
        # (xfrm_bundle_create), which only a default route can answer for an
        # IPv4 outer address.
        await command(r.target, r.session, "ip", "-6", "route", "add", "default", "via", WAN_IPV6,
                      "dev", TARGET_WAN_IF)
        cleanup.append((r.target, ["ip", "-6", "route", "del", "default", "via", WAN_IPV6,
                                   "dev", TARGET_WAN_IF]))
        await sa_pair(r, cleanup)
        await _offload_table(r, f"ip6 saddr {LAN_IPV6} udp sport {SPORT} udp dport {DPORT}")
        admitted = await _drive(r, send, lambda s: s["entries"] == 2,
                                "both directions of the protected IPv6 flow should be in hardware")
        forward = next(f for f in admitted["flows"] if f["sa"] != "0")
        assert forward["in_sa"] == "0" and forward["family"] == "6", admitted
        assert sum(f["in_sa"] != "0" for f in admitted["flows"]) == 1, admitted
        r.record("ipv6-sa-admitted", admitted)
        results = {}
        for size in (FITS, FITS + 1, 1452):
            payload = bytes([size % 251]) * size
            before, frags = await r.state(), await fragments_sent(r)
            counts = {f["cookie"]: int(f["packets"]) for f in before["flows"]}
            script = f'''
import json
from scapy.all import Ether, IPv6, UDP, Raw, ICMPv6PacketTooBig, sendp, sniff
packet = IPv6(src={LAN_IPV6!r}, dst={WAN_IPV6!r})/UDP(sport={SPORT}, dport={DPORT})/Raw({payload!r})
answers = sniff(iface={LAN_NIC!r}, timeout=2, lfilter=lambda p: ICMPv6PacketTooBig in p,
                started_callback=lambda: sendp(Ether(dst={r.dut_lan_mac!r})/packet,
                                               iface={LAN_NIC!r}, verbose=False))
print(json.dumps({{"too_big": [a[ICMPv6PacketTooBig].mtu for a in answers]}}))
'''
            result = await lan_run_python(r.lan, script, timeout=20, label="flowtable_v6_sa_oversized")
            assert result.rc == 0, result.stdout
            await asyncio.sleep(0.5)
            after = await r.state()
            moved = {f["cookie"]: int(f["packets"]) - counts[f["cookie"]] for f in after["flows"]}
            sent = await fragments_sent(r)
            results[size] = {"lan": json.loads(result.stdout.strip().splitlines()[-1]),
                             "delivered": echo.received[payload], "hardware": moved,
                             "fragments": {k: sent[k] - frags[k] for k in sent}}
            observed = results[size]
            assert observed["delivered"] == 1 and observed["lan"]["too_big"] == [], (size, observed)
            assert moved[forward["cookie"]] == 1, (size, observed)
            assert set(moved) == set(counts), (size, before, after)
            # Two outer fragments exactly when the inner packet exceeds the
            # bundle; never an inner one.
            assert observed["fragments"] == {4: 0 if size == FITS else 2, 6: 0}, (size, observed)
        final = await r.state()
        assert final["errors"] == r.errors and final["entries"] == 2, final
        r.record("ipv6-sa-oversized", {"results": results, "final": final})
    finally:
        transport.close()
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)

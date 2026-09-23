"""UDP-encapsulated ESP (NAT-T) through the offload.

xfrm hands the adapter an SA's encapsulation ports in network byte order, and
the SA cache keeps them in host order: cdx_ipsec_set_natt() converts them.
The outbound PDB writes them into the UDP header SEC puts in front of ESP, and
the inbound SA's classifier entry is keyed on them. A symmetric pair such as
4500/4500 cannot tell a byte swap, or the two ports swapped with each other,
from the right answer. So the DUT's end here is 4500 and the peer's 31000, as
behind a NAT, and the wire is checked per direction.

Transport mode is refused: SEC builds the UDP header, and the decapsulation
offset past it, only on its tunnel arms, so a transport SA would leave as bare
ESP. Packet offload has no software fallback (xfrm_dev_state_add() returns
the driver's error for it), so the add fails with the adapter's reason. And an
in-place update may not move an offloaded SA's ports, which the hardware SA
carries and no update reaches.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from pathlib import Path
import re
import secrets
import struct

import pytest

from _ipsec_helpers import endpoints_down, endpoints_up
from _topology import TARGET_WAN_IF
from test_flowtable_connections import peer
from test_flowtable_offload import ARTIFACTS, WAN_IP, command, rig  # noqa: F401
from test_flowtable_selective_neighbour import warm
from test_flowtable_service_ipsec import (INNER, Transform, flows_for, hardware, ipsec_service,  # noqa: F401
                                          negative, plaintext_probe)
from test_flowtable_service_ipsec_replay import sa_state
from test_flowtable_tunnel import Capture

# (DUT port, peer port). Neither is the other byte-swapped (0x1194 against
# 0x7918), so a swap of either kind lands on a port nothing listens on.
PORTS = (4500, 31000)
NATT = Transform(encap=PORTS)


class Encapsulated(Capture):
    """ESP between the DUT and the peer in both directions, bare or in UDP,
    taken below the WAN host's bridge."""
    snaplen = 64

    def __init__(self, r, label):
        self.path = ARTIFACTS / (label + ".pcap")
        self.interface = r.ipsec_wire_if
        outer = r.ipsec.outer
        self.filter = (f"(udp or ip proto 50) and ((src host {outer} and dst host {WAN_IP}) or "
                       f"(src host {WAN_IP} and dst host {outer}))")


def encapsulations(path, spis):
    """How each SA's frames were carried: a count per (SPI, source MAC,
    encapsulation), where encapsulation is the UDP port pair or "esp" for a
    bare ESP frame. UDP whose payload does not start with one of `spis` is
    something else between the two hosts and is ignored."""
    seen, data, offset = Counter(), Path(path).read_bytes(), 24
    while offset + 16 <= len(data):
        length = struct.unpack_from("<I", data, offset + 8)[0]
        frame = data[offset + 16:offset + 16 + length]
        offset += 16 + length
        l3 = 18 if frame[12:14] == b"\x81\x00" else 14
        if len(frame) < l3 + 20:
            continue
        l4 = l3 + (frame[l3] & 0xF) * 4
        source = frame[6:12].hex(":")
        if frame[l3 + 9] == 50 and len(frame) >= l4 + 4:
            spi, how = struct.unpack_from("!I", frame, l4)[0], "esp"
        elif frame[l3 + 9] == 17 and len(frame) >= l4 + 12:
            spi, how = struct.unpack_from("!I", frame, l4 + 8)[0], struct.unpack_from("!HH", frame, l4)
        else:
            continue
        if spi in spis:
            seen[(spi, source, how)] += 1
    return seen


@pytest.mark.parametrize("ipsec_service", [NATT], ids=["dut4500-peer31000"], indirect=True)
async def test_flowtable_service_ipsec_natt(ipsec_service):
    """An ESP-in-UDP SA pair with asymmetric ports is offloaded and carries the
    tunnel in hardware both ways, with each direction's outer ports exactly as
    configured on the wire and SEC's own counters moving."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    dut, peer_port = PORTS
    sas = {"out": r.ipsec.active["out"], "in": r.ipsec.active["in"]}
    # The kernel's view first, so a port mix-up in the configuration is not
    # blamed on the hardware.
    for direction, spi in sas.items():
        shown = (await command(r.target, r.session, "ip", "xfrm", "state", "get",
                               *r.ipsec.state(direction, spi)))["stdout"]
        sport, dport = PORTS if direction == "out" else PORTS[::-1]
        assert f"encap type espinudp sport {sport} dport {dport}" in shown, shown
        assert re.search(rf"crypto offload parameters: dev {TARGET_WAN_IF} dir {direction} mode packet", shown), shown
    before = {direction: await sa_state(r, spi, direction) for direction, spi in sas.items()}
    capture = Encapsulated(r, "ipsec-natt-wire")
    async with capture, peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400, listen_addresses=[INNER]) as p:
        await warm(r, p, [0, 1, 2, 3], "natt-baseline", flows[:4])
        # Flow counters per direction, SA handles on both, and neither SEC
        # submit counter tracking the transfer: the inbound frames were
        # matched by the SA's UDP-keyed entry, not handed up by the CPU.
        await hardware(r, p, "natt-hardware", flows[:4])
        await plaintext_probe(r, p, "natt-plaintext")
        await negative(r, p)
    carried = encapsulations(capture.path, set(sas.values()))
    # The accounting pass publishes SEC's per-SA counters once a second.
    await asyncio.sleep(1.5)
    after = {direction: await sa_state(r, spi, direction) for direction, spi in sas.items()}
    r.record("ipsec-natt", {"wire": {f"{spi:#x} {source} {how}": count for (spi, source, how), count in carried.items()},
                            "before": before, "after": after})
    expected = {(sas["out"], r.dut_wan_mac, (dut, peer_port)), (sas["in"], r.wan_mac, (peer_port, dut))}
    assert set(carried) == expected, (
        "each direction's frames must carry exactly the configured ports: the DUT's from "
        f"{dut} to {peer_port}, the peer's back", carried)
    assert all(count >= 256 for count in carried.values()), carried
    # SEC's per-SA counters, as the accounting pass publishes them.
    for direction in sas:
        assert after[direction]["packets"] - before[direction]["packets"] >= 256, (direction, before, after)


# A documentation-range pair of its own. Nothing is sent: the peer does not
# exist, and its neighbour entry is invented.
LOCAL, PEER = "198.18.104.1", "198.18.104.2"
REQID = "49306"


async def test_ipsec_natt_transport_refused(aiohttp_session, target_agent, splat_window):
    """Transport-mode ESP-in-UDP is refused with the adapter's reason, in both
    directions, and leaves no state. The same SA in tunnel mode installs,
    offloaded, with its ports as configured."""
    await endpoints_up(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=LOCAL, peer=PEER,
                       lladdr="02:00:00:00:04:02")
    identities, results = [], []
    try:
        for direction in ("out", "in"):
            src, dst = (LOCAL, PEER) if direction == "out" else (PEER, LOCAL)
            sport, dport = PORTS if direction == "out" else PORTS[::-1]
            for mode in ("transport", "tunnel"):
                identity = ["src", src, "dst", dst, "proto", "esp", "spi", hex(0x4E000000 | secrets.randbits(24))]
                identities.append(identity)
                added = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "add", *identity,
                                      "mode", mode, "reqid", REQID, *Transform().algorithms,
                                      "encap", "espinudp", str(sport), str(dport), "0.0.0.0",
                                      "offload", "packet", "dev", TARGET_WAN_IF, "dir", direction, check=False)
                shown = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "get", *identity,
                                      check=False)
                results.append({"direction": direction, "mode": mode, "add": added, "get": shown})
                if mode == "transport":
                    assert added["rc"] != 0, results[-1]
                    assert "cdx: UDP encapsulation needs tunnel mode" in added["stderr"], results[-1]
                    assert shown["rc"] != 0, ("a refused packet-offload SA was installed anyway", results[-1])
                else:
                    assert added["rc"] == 0, results[-1]
                    assert f"encap type espinudp sport {sport} dport {dport}" in shown["stdout"], results[-1]
                    assert re.search(rf"crypto offload parameters: dev {TARGET_WAN_IF} dir {direction} mode packet",
                                     shown["stdout"]), results[-1]
    finally:
        for identity in identities:
            await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "delete", *identity, check=False)
        await endpoints_down(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=LOCAL, peer=PEER)


def natt(sport, dport):
    return ["encap", "espinudp", str(sport), str(dport), "0.0.0.0"]


async def test_ipsec_natt_update_keeps_hardware_ports(aiohttp_session, target_agent, splat_window):
    """An in-place update of an offloaded NAT-T SA may not move its ports.

    The ports are in the hardware SA: SEC writes them in front of every frame
    it encrypts, and the classifier keys the SA's inbound frames on them. An
    update reaches no driver, so changing them in place would leave the
    hardware on the old ports while `ip xfrm state` showed the new ones. The
    update is refused and the state keeps its ports and its offload. An update
    that keeps the ports still applies: here, a new hard lifetime."""
    await endpoints_up(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=LOCAL, peer=PEER,
                       lladdr="02:00:00:00:04:02")
    identities, results = [], []
    try:
        for direction in ("out", "in"):
            src, dst = (LOCAL, PEER) if direction == "out" else (PEER, LOCAL)
            ports = PORTS if direction == "out" else PORTS[::-1]
            identity = ["src", src, "dst", dst, "proto", "esp", "spi", hex(0x4F000000 | secrets.randbits(24))]
            state = [*identity, "mode", "tunnel", "reqid", REQID, *Transform().algorithms]
            await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "add", *state, *natt(*ports),
                          "offload", "packet", "dev", TARGET_WAN_IF, "dir", direction)
            identities.append(identity)
            # The DUT's own port, whichever side of the pair it is on.
            moved = (ports[0] + 1, ports[1]) if direction == "out" else (ports[0], ports[1] + 1)
            refused = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "update", *state,
                                    *natt(*moved), check=False)
            kept = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "update", *state,
                                 *natt(*ports), "limit", "time-hard", "86400", check=False)
            shown = (await command(target_agent, aiohttp_session, "ip", "-s", "xfrm", "state", "get",
                                   *identity))["stdout"]
            results.append({"direction": direction, "refused": refused, "kept": kept, "shown": shown})
            assert refused["rc"] != 0 and "Invalid argument" in refused["stderr"], results[-1]
            assert kept["rc"] == 0, results[-1]
            assert f"encap type espinudp sport {ports[0]} dport {ports[1]}" in shown, results[-1]
            assert "hard 86400(sec)" in shown, results[-1]
            assert re.search(rf"crypto offload parameters: dev {TARGET_WAN_IF} dir {direction} mode packet",
                             shown), results[-1]
    finally:
        for identity in identities:
            await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "delete", *identity, check=False)
        await endpoints_down(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=LOCAL, peer=PEER)

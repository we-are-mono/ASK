"""VLAN flowtable offload: the LAN sits behind an 802.1Q tag, the WAN does not.

The asymmetry is the point. One direction arrives tagged and leaves untagged,
the other the reverse, so a single connection exercises both the ingress strip
and the egress insert and neither can be mistaken for the other. Every case
asserts the tags the adapter recorded, then sends a second burst and requires
the classifier's own packet counters to account for all of it, which is the
only evidence the encapsulation reached the wire rather than just the rule.
"""
from __future__ import annotations

import asyncio
import secrets
import threading
from collections import Counter

from _flowtable_vlan import (NAT_TABLE, SNAT_ADDR, VLAN_ID, VLAN_INNER, _direction, _established,
                             _flows, _send_vlan_frames, _vlan_ingress_visible)

import pytest

from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from _flowtable_rig import (DPORT, SPORT, TABLE, WAN_IP, artifact_dir, assert_undisturbed,
                            command, ct_listing)
from _flowtable_udp_wire import udp_wire_payload
from _gated_tcp import GatedTcp
from ask_orch.counters import kernel_tx_packets


async def test_routed(vlan_rig):
    """A tagged LAN and an untagged WAN, routed, with no translation."""
    r = vlan_rig
    flows, delta = await _established(r)
    forward = _direction(flows, r.lan_ip, WAN_IP)
    reverse = _direction(flows, WAN_IP, r.lan_ip)
    # The tag is described where the frame actually carries it and nowhere
    # else: stripped on the way in, inserted on the way back.
    assert forward["in_vlan"] == str(VLAN_ID) and forward["out_vlan"] == "-", forward
    assert reverse["in_vlan"] == "-" and reverse["out_vlan"] == str(VLAN_ID), reverse
    # Both directions name the physical ports; a tag never becomes one.
    assert forward["in"] == TARGET_LAN_IF and forward["out"] == TARGET_WAN_IF, forward
    assert reverse["in"] == TARGET_WAN_IF and reverse["out"] == TARGET_LAN_IF, reverse
    assert all(d == 64 for d in delta.values()), delta
    r.record("vlan-routed", {"flows": flows, "delta": delta})


async def test_snat(vlan_rig):
    """Source NAT across the tag boundary, proved at the far endpoint.

    The WAN host observing the translated source is what separates a rewrite
    that reached the wire from one that only reached the rule.
    """
    r = vlan_rig
    # nft rather than an iptables SNAT target, which this image has no module
    # for, and at priority 90 so it runs ahead of the fixture's own
    # priority-100 exemption rather than behind it.
    nat = (f"table ip {NAT_TABLE} {{ chain postrouting {{ "
           f"type nat hook postrouting priority 90; "
           f"ip saddr {r.lan_ip} ip daddr {WAN_IP} udp sport {SPORT} udp dport {DPORT} "
           f"snat to {SNAT_ADDR}; }}; }}")
    await command(r.target, r.session, "nft", nat)
    await command(r.wan, r.session, "ip", "route", "replace", f"{SNAT_ADDR}/32",
                  "via", r.dut_wan_ip, "dev", r.wan_if)
    try:
        flows, delta = await _established(r)
        forward = _direction(flows, r.lan_ip, WAN_IP)
        assert forward["new_src"].startswith(SNAT_ADDR + ":"), forward
        assert forward["in_vlan"] == str(VLAN_ID) and forward["out_vlan"] == "-", forward
        reverse = _direction(flows, WAN_IP, SNAT_ADDR)
        assert reverse["new_dst"].startswith(r.lan_ip + ":"), reverse
        assert reverse["in_vlan"] == "-" and reverse["out_vlan"] == str(VLAN_ID), reverse
        assert all(d == 64 for d in delta.values()), delta
        # What the wire carried, not what the rule said it would.
        assert r.echo.sources == {(SNAT_ADDR, SPORT)}, r.echo.sources
        r.record("vlan-snat", {"flows": flows, "delta": delta,
                               "observed": sorted(r.echo.sources)})
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)
        await command(r.wan, r.session, "ip", "route", "del", f"{SNAT_ADDR}/32", check=False)


@pytest.mark.parametrize("vlan_rig", ["qinq"], indirect=True)
async def test_qinq(vlan_rig):
    """Two tags, and the order they are carried in.

    The rule records them outermost first. Recording them the other way round
    still forwards on a single-tag path, which is why the pair has to be
    asserted by position rather than as a set.
    """
    r = vlan_rig
    flows, delta = await _established(r)
    expected = f"{VLAN_ID}.{VLAN_INNER}"
    forward = _direction(flows, r.lan_ip, WAN_IP)
    reverse = _direction(flows, WAN_IP, r.lan_ip)
    assert forward["in_vlan"] == expected and forward["out_vlan"] == "-", forward
    assert reverse["out_vlan"] == expected and reverse["in_vlan"] == "-", reverse
    assert all(d == 64 for d in delta.values()), delta
    r.record("vlan-qinq", {"flows": flows, "delta": delta})


@pytest.mark.parametrize("vlan_rig", ["udp", "qinq"], indirect=True)
@pytest.mark.parametrize("hardware", [False, True], ids=["software", "hardware"])
async def test_installed_tuple_isolation(vlan_rig, hardware):
    """An installed physical-port/5-tuple must not bypass VLAN isolation."""
    from scapy.all import AsyncSniffer, Dot1Q, Ether, IP, Raw, UDP, wrpcap

    r = vlan_rig
    tags = r.vlan_tags
    wrong = VLAN_ID % 4094 + 1
    while wrong in tags:
        wrong = wrong % 4094 + 1
    negatives = {"wrong-vid": [wrong, *tags[1:]], "missing-tags": []}
    if len(tags) == 2:
        negatives.update({"missing-outer": tags[1:], "missing-inner": tags[:1],
                          "wrong-inner": [VLAN_ID, wrong],
                          "reversed-tags": list(reversed(tags))})
    prefix = f"ASK-vlan-{secrets.token_hex(4)}-".encode()

    def probes(name, stack, count):
        payloads, frames = [], []
        for n in range(count):
            payload = prefix + f"{name}-{n}".encode()
            payload = payload.ljust(128, b".")
            packet = Ether(src=r.lan_mac, dst=r.dut_lan_mac)
            for vid in stack:
                packet /= Dot1Q(vlan=vid)
            packet /= IP(src=r.lan_ip, dst=WAN_IP, ttl=64) / UDP(sport=SPORT, dport=DPORT) / Raw(payload)
            payloads.append(payload)
            frames.append(bytes(packet))
        return payloads, frames

    bad = {name: probes(name, stack, 4) for name, stack in negatives.items()}
    # The physical LAN remains routable. Make the intended isolation explicit:
    # an untagged packet with the same source is otherwise valid slow-path traffic.
    await r.nft(f'''table inet {TABLE} {{
 chain isolation {{ type filter hook forward priority -10; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} udp sport {SPORT} udp dport {DPORT} \
iifname != "{r.dut_vlan_if}" counter drop
 }}
}}''')
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=r.wan_if, store=True, started_callback=ready.set,
                          filter=f"ether src {r.dut_wan_mac} or ether src {r.lan_mac}")
    reports, expected = {}, []
    sniffer.start()
    try:
        assert await asyncio.to_thread(ready.wait, 5), "WAN VLAN capture did not start"
        await _vlan_ingress_visible(r, [frame for _, frames in bad.values() for frame in frames])
        await r.clear_ct()
        await r.table(hardware=hardware)
        if hardware:
            installed = await r.admit()
            assert _direction(installed["flows"], r.lan_ip, WAN_IP)["in_vlan"] == ".".join(map(str, tags))
        else:
            for _ in range(10):
                await r.exchange(4)
                if "[OFFLOAD]" in await ct_listing(r):
                    break
            assert "[OFFLOAD]" in await ct_listing(r)
            installed = await r.state()
            assert installed["entries"] == installed["bindings"] == 0, installed
        # Raw injection owns no UDP socket on the LAN. Suppress replies so a
        # port-unreachable cannot retire the connection under measurement.
        r.echo.reply = False
        cases = [("valid-before", probes("valid-before", tags, 32)), *bad.items(),
                 ("valid-after", probes("valid-after", tags, 32))]
        for name, (payloads, frames) in cases:
            positive = name.startswith("valid-")
            before = await r.state()
            tx_before = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF)
            sent = await _send_vlan_frames(r, frames, "vlan_tuple_isolation")
            await asyncio.sleep(0.2)
            after = await r.state()
            software_tx = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF) - tx_before
            reports[name] = {**sent, "before": before, "after": after, "software_tx": software_tx}
            r.record("vlan-isolation", reports)
            if not hardware:
                assert "[OFFLOAD]" in await ct_listing(r), (name, reports[name])
            assert_undisturbed(r, installed, after,
                               {f["cookie"] for f in installed["flows"]} ==
                               {f["cookie"] for f in after["flows"]} and
                               (installed["installs"], installed["deletes"]) ==
                               (after["installs"], after["deletes"]))
            if positive:
                expected.extend(payloads)
                assert all(r.echo.received[payload] == 1 for payload in payloads), (name, r.echo.received)
                if hardware:
                    old = _direction(before["flows"], r.lan_ip, WAN_IP)
                    new = _direction(after["flows"], r.lan_ip, WAN_IP)
                    assert int(new["packets"]) - int(old["packets"]) == len(frames), reports[name]
                    assert 0 <= software_tx <= 8, reports[name]
                else:
                    assert software_tx >= len(frames), reports[name]
            # A rejected frame can hit the classifier before the tag check,
            # so negative hardware-counter deltas are deliberately unconstrained.
        await asyncio.sleep(0.5)
    finally:
        r.echo.reply = True
        packets = list(sniffer.stop() or [])
        wrpcap(str(artifact_dir() / "vlan-isolation-wan.pcap"), packets)

    forbidden = [payload for payloads, _ in bad.values() for payload in payloads]
    leaked = [bytes(packet).hex() for packet in packets
              if any(payload in bytes(packet) for payload in forbidden)]
    assert not leaked, ("wrong-tag frames escaped on the WAN", leaked)
    assert not any(r.echo.received[payload] for payload in forbidden), r.echo.received
    received = []
    for packet in packets:
        if prefix not in bytes(packet):
            continue
        payload = udp_wire_payload(bytes(packet), source_ip=r.lan_ip, destination_ip=WAN_IP,
                                   source_port=SPORT, destination_port=DPORT,
                                   source_mac=r.dut_wan_mac, destination_mac=r.wan_mac)
        assert payload is not None, packet.summary()
        received.append(payload)
    assert Counter(received) == Counter(expected), (received, expected)


async def test_device_mtu_retires(vlan_rig):
    """The VLAN device carries its own MTU, and a flow through it depends on it.

    Each direction carries the MTU of the interface it leaves by, so lowering
    the tagged LAN device touches only the reverse direction. Both directions
    share one invalidation handle, so retiring the connection is a single
    increment rather than two.

    Lowered below a full frame, the tagged device is a path the reverse's
    datagrams -- arriving on the WAN port, which can deliver 1500 bytes
    whatever its MTU -- no longer fit, and the microcode would have to
    fragment them. So the flow comes back with the forward direction alone
    in hardware, still at the WAN port's MTU, and the reverse refused to
    Linux, which fragments correctly.
    """
    r = vlan_rig
    await r.table()

    async def settled(expected, since=None):
        """`expected` maps the egress port of each direction hardware should
        hold to the MTU it should describe; `since`, a state the directions
        must have been installed after. Readmission needs traffic, so each
        attempt sends before it looks; nothing re-offers a retired flow on its
        own."""
        for _ in range(10):
            await r.exchange(count=4)
            state = await r.state()
            if (sorted(f["out"] for f in state["flows"]) == sorted(expected)
                    and all(int(f["mtu"]) == expected[f["out"]] for f in state["flows"])
                    and (since is None or state["installs"] > since["installs"])):
                return state
        pytest.fail(f"flow did not settle at {expected}: {state}")

    before = await settled({TARGET_LAN_IF: 1500, TARGET_WAN_IF: 1500})
    await command(r.target, r.session, "ip", "link", "set", r.dut_vlan_if, "mtu", "1400")
    try:
        invalidated = await r.wait(
            lambda s: s["mtu_invalidations"] >= before["mtu_invalidations"] + 1)
        # The flow comes back rather than staying retired: the direction
        # leaving by the WAN port as it was, the one into the tagged device
        # refused. Installed since, so a state caught mid-retirement cannot
        # pass for the readmitted one.
        reduced = await settled({TARGET_WAN_IF: 1500}, since=before)
        assert reduced["errors"] == before["errors"], reduced
        assert reduced["rejects"] > invalidated["rejects"], (invalidated, reduced)
        r.record("vlan-mtu", {"before": before, "invalidated": invalidated,
                              "reduced": reduced})
    finally:
        await command(r.target, r.session, "ip", "link", "set", r.dut_vlan_if,
                      "mtu", "1500", check=False)


async def test_full_mtu_datagram(vlan_rig):
    """A datagram filling the path MTU still crosses the tag.

    The tagged frame is four bytes longer than the untagged one it becomes. If
    the hardware's own size check counted those four bytes, this is the payload
    that would be dropped or punted while a shorter one was forwarded, so the
    counters have to account for it exactly as for any other burst.
    """
    r = vlan_rig
    await r.table()
    await r.exchange(count=4)
    before = {f["cookie"]: int(f["packets"]) for f in await _flows(r)}
    # 1500 less the IPv4 and UDP headers: the largest datagram the path takes
    # without fragmenting, and the one the tag makes an oversized frame of.
    await r.exchange(count=16, payload_size=1472)
    after = {f["cookie"]: int(f["packets"]) for f in await _flows(r)}
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == 16 for d in delta.values()), delta
    r.record("vlan-full-mtu", {"delta": delta})


@pytest.mark.parametrize("vlan_rig", ["tcp"], indirect=True)
async def test_tcp(vlan_rig):
    """An established TCP connection over the tagged segment.

    The classifier punts SYN, FIN and RST before its own lookup, so what the
    hardware actually carries is the bulk transfer in the middle. The cookies
    staying put is what proves the connection was never readmitted underneath
    it.
    """
    r = vlan_rig
    await r.table()
    async with GatedTcp(r.run_peer, source=r.lan_ip, sport=SPORT, peer=WAN_IP,
                        dport=DPORT, label="flowtable_vlan_tcp") as transfer:
        await transfer.warmed()
        before = await r.wait(lambda s: len(s["flows"]) == 2)
        await transfer.measure()
        after = await r.state()
    r.record("vlan-tcp", {"before": before, "after": after, "report": transfer.report})
    forward = _direction(before["flows"], r.lan_ip, WAN_IP)
    reverse = _direction(before["flows"], WAN_IP, r.lan_ip)
    assert forward["in_vlan"] == str(VLAN_ID) and forward["out_vlan"] == "-", forward
    assert reverse["in_vlan"] == "-" and reverse["out_vlan"] == str(VLAN_ID), reverse
    old = {f["cookie"]: int(f["packets"]) for f in before["flows"]}
    new = {f["cookie"]: int(f["packets"]) for f in after["flows"]}
    assert_undisturbed(r, before, after, old.keys() == new.keys()
                       and (before["installs"], before["deletes"]) == (after["installs"], after["deletes"]))
    assert all(new[cookie] - count > 100 for cookie, count in old.items()), (old, new)

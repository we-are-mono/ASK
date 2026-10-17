"""PPPoE flowtable offload: the WAN sits behind a session, the LAN does not.

The asymmetry is the point, as it is for a tag. One direction arrives inside a
session and leaves bare, the other the reverse, so a single connection
exercises both the ingress strip and the egress insert and neither can be
mistaken for the other.

Two things make a session unlike a tag, and both are what these cases are for.
Netfilter describes an ingress session with *nothing* -- there is no pop action
and no dissector key, so the reverse direction's rule is byte-for-byte the rule
an unencapsulated flow produces, and only the devices say otherwise. And a ppp
device resolves no Ethernet destination at all: it is NOARP with no address, so
the four Ethernet mangles Netfilter writes are zeros and the real destination
is the concentrator the session named. Every case therefore asserts the session
the adapter recorded against `/proc/net/pppoe`, which is where the kernel's own
view of the negotiated session can be read back independently, and then sends a
second burst and requires the classifier's own packet counters to account for
all of it.

The session runs over a tag, because the bench's access concentrator lives on a
standing VLAN. That is not incidental: `ppp0` over `eth4.3900` over `eth4` puts
a session and a tag on one path, which is both encapsulation slots a direction
has, and it is the shape every case here runs in.

The bench side that pre-exists is used, never built: the orchestrator's
`wan3900` device and the LAN VM's route to the inner address are standing
state, so this file creates neither and removes neither.

An IPv4 UDP upload into the session takes the offline-port detour (A385). It
arrives on the LAN port, which can deliver a full 1500-byte frame whatever MTU
the port is given, and the session carries 1492: the microcode has to fragment
it, and the fragments it builds from a frame an Ethernet port received carry no
payload, where those of a frame an offline port took are whole. So the LAN
port's entry hands each frame to the offline port, whose entry for the flow
does the upload's work -- the insert, the translation in front of it, the LAN
tag it pops, the fragmenting -- and the UDP cases prove both directions in
hardware, the upload's counted as it arrived. An IPv6 UDP upload stays in
Linux, as no router fragments IPv6. TCP, which sets DF and is never the
microcode's to fragment, is carried as it is.
"""
from __future__ import annotations

from _flowtable_pppoe import QOS_COUNT, QOS_RATE_MBIT, QOS_VOICE_CQ, QOS_VOICE_PRIO

from _flowtable_pppoe import (INNER_LOCAL, INNER_LOCAL6, INNER_REMOTE, INNER_REMOTE6, LAN_VID, LCP_ECHO_INTERVAL, NAT_TABLE, SERVER_IF, PORT_QOS_BULK, PORT_QOS_VOICE, PPP_RX_OVERHEAD, PPP_TX_OVERHEAD, QOS_TABLE, SESSION_MTU, SNAT_ADDR, SPORT6, SourceEcho, UNTAGGED_COUNT, UNTAGGED_DPORT, UNTAGGED_SPORT, WAN_ENDPOINT, WAN_VID, _assert_carried, _assert_session, _assert_undisturbed, _both_directions, _dial, _direction, _established, _exchange6, _hangup, _offload_table6, _ppp_link, _qos_bulk, _qos_bulk_stop, _session_halves, _session_identity, _session_row, _session_text, _snat_table, _tcp_carried, _untagged_directions, _udp_directions, _untagged_path, _untagged_window, _wait_reachable)

import asyncio
import json
import math
import socket
import struct
import subprocess
import time

import pytest

from _flowtable_pppoe import CLONED_WAN_MAC, DPORT6, _concentrator_if
from _gated_tcp import GatedTcp
from _topology import LAN_IPV6, TARGET_LAN_IF, TARGET_WAN_IF, lan_run
import _flowtable_rig as ft
from _flowtable_rig import Echo, SPORT, command, console_command, read


@pytest.mark.rfc("2516")
@pytest.mark.rfc("1661")
@pytest.mark.rfc("1332")
@pytest.mark.rfc("1334")
@pytest.mark.rfc("1994")
@pytest.mark.parametrize("pppoe_rig", ["udp", "chap"], indirect=True)
async def test_routed(pppoe_rig):
    """A session on the WAN side and a bare LAN, routed, with no translation.

    The session id and the concentrator the adapter recorded have to be the
    ones the kernel negotiated, on the direction that strips the header and on
    the one that inserts it, and on neither of the LAN-side halves. The upload
    takes the offline-port detour, its path the session's.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    # Nothing on the LAN side is encapsulated, which is what makes the session
    # assertions above about the session rather than about the path.
    assert reverse["out_vlan"] == "-" and reverse["out_br"] == "-", reverse
    assert forward["in_vlan"] == "-" and forward["in_br"] == "-", forward
    # The download leaves by the LAN port, whose full MTU it carries; the
    # upload by the session, whose MTU it describes, through the detour.
    assert int(reverse["mtu"]) == 1500 and reverse["detour"] == "0", reverse
    assert int(forward["mtu"]) == SESSION_MTU and forward["detour"] == "1", forward
    assert all(d == 64 for d in delta.values()), delta
    r.record("pppoe-routed", {"flows": flows, "delta": delta,
                              "session": _session_text(r.session_identity)})


@pytest.mark.parametrize("pppoe_rig", ["ipv6"], indirect=True)
async def test_ipv6_routed(pppoe_rig):
    """IPv6 across the session, which was the one thing a session excluded.

    The exclusion was about the firmware rather than the adapter.
    `en_ehash_insert_pppoe_hdr` carries a version, a type, a code and a session
    id, and no PPP protocol id at all, so the microcode chooses between 0x0021
    and 0x0057 itself and nothing had shown which it picks for an IPv6 frame. A
    wrong choice is a header the concentrator discards, which is silent loss
    rather than a refusal, so it stayed out until measured.

    This is the download's half of the measurement: a complete v6 exchange
    across the session, every reply stripped by the hardware. The UDP upload
    is Linux's: the LAN port delivers a full frame and the session carries
    1492, and the microcode would fragment the excess where Linux answers it
    with Packet Too Big -- the offline-port detour that carries IPv4's takes
    no IPv6. The insert, where the protocol id is chosen, is proved by
    test_ipv6_tcp.

    One routed case per protocol is the whole of it, deliberately. Nothing
    about the family reaches the session decode -- the walk, the concentrator
    and the id are identical either way -- so what the other shapes would
    re-prove is the adapter's handling of a session, which the IPv4 cases
    already cover, and what is new here belongs to the firmware.
    """
    r = pppoe_rig
    # Errors accumulate for the life of the module, and the fault-injection
    # cases in flowtable_offload.py raise some on purpose, so what this
    # case can claim is that it added none of its own.
    initial = await r.state()
    baseline = initial["errors"]
    await _offload_table6(r)
    # Nothing re-offers a flow on its own, so each attempt sends before it
    # looks; admission needs traffic and the reverse direction needs a reply.
    for _ in range(10):
        await _exchange6(r, 4)
        if (await r.state())["entries"] == 1:
            break
    state = await r.state()
    flows = state["flows"]
    assert len(flows) == 1 and state["rejects"] > initial["rejects"], (initial, state)
    reverse = _direction(flows, f"[{INNER_LOCAL6}]", f"[{LAN_IPV6}]")
    assert reverse["family"] == "6", flows
    # The session, asserted exactly as the v4 routed case asserts it: the id
    # and the concentrator the kernel negotiated on the direction that strips
    # the header, and nothing on its LAN half.
    _assert_session(r, None, reverse)
    assert reverse["out_vlan"] == "-" and reverse["out_br"] == "-", reverse

    before = {f["cookie"]: int(f["packets"]) for f in flows}
    report = await _exchange6(r, 64)
    assert report == {"echoed": 64, "lost": 0}, report
    state = await r.state()
    after = {f["cookie"]: int(f["packets"]) for f in state["flows"]}
    assert set(before) == set(after), (before, state)
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == 64 for d in delta.values()), (delta, state)
    assert state["errors"] == baseline, (baseline, state)
    # And what the far end observed, which is where the protocol id was really
    # decided: the concentrator's stack had to parse the PPP frame before this
    # datagram could reach a socket at all.
    assert r.echo6.sources == {(LAN_IPV6, SPORT6)}, r.echo6.sources
    r.record("pppoe-ipv6-routed", {"flows": flows, "delta": delta,
                                   "session": _session_text(r.session_identity),
                                   "observed": sorted(r.echo6.sources)})


@pytest.mark.parametrize("pppoe_rig", ["ipv6"], indirect=True)
async def test_ipv6_tcp(pppoe_rig):
    """The v6 insert across the session, over TCP, which the uplink's MSS
    clamp keeps within the session's MTU.

    `en_ehash_insert_pppoe_hdr` carries no PPP protocol id, so the microcode
    chooses between 0x0021 and 0x0057 itself, and a wrong choice is a header
    the concentrator discards: silent loss rather than a refusal. A transfer
    the concentrator's stack completed is the evidence that it parsed every
    frame the hardware inserted a header onto, and the upload's own counter
    says the hardware did the inserting.
    """
    r = pppoe_rig
    baseline = (await r.state())["errors"]
    await _offload_table6(r, "tcp")
    async with GatedTcp(r.run_peer, source=LAN_IPV6, sport=SPORT6, peer=INNER_LOCAL6,
                        dport=DPORT6, label="flowtable_pppoe_v6_tcp") as transfer:
        await transfer.warmed()
        before = await r.wait(lambda s: len(s["flows"]) == 2)
        flows = await _both_directions(r, before)
        await transfer.measure()
        after = await r.state()
    forward = _direction(flows, f"[{LAN_IPV6}]", f"[{INNER_LOCAL6}]")
    reverse = _direction(flows, f"[{INNER_LOCAL6}]", f"[{LAN_IPV6}]")
    assert forward["family"] == reverse["family"] == "6", flows
    _assert_session(r, forward, reverse)
    assert forward["in_vlan"] == "-" and reverse["out_vlan"] == "-", (forward, reverse)
    assert forward["in_br"] == reverse["out_br"] == "-", (forward, reverse)
    # The upload leaves by the session, so it carries the session's MTU --
    # above the IPv6 minimum link MTU, the one extra thing v6 requires of a path.
    assert int(forward["mtu"]) == SESSION_MTU, forward
    new = {f["cookie"]: int(f["packets"]) for f in after["flows"]}
    assert new.keys() == {forward["cookie"], reverse["cookie"]}, after
    assert (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]), (before, after)
    upload = new[forward["cookie"]] - int(forward["packets"])
    download = new[reverse["cookie"]] - int(reverse["packets"])
    assert upload > 100 and download > 100, (upload, download)
    assert after["errors"] == baseline, (baseline, after)
    r.record("pppoe-ipv6-tcp", {"flows": flows, "after": after, "report": transfer.report,
                                "session": _session_text(r.session_identity)})


async def test_session_counters(pppoe_rig):
    """The session's own byte counters, which the firmware keeps for it, and
    where an operator reads them: on the ppp device.

    One record per ppp device, not per flow and not per direction: every
    direction of a connection that crosses the device in hardware holds a
    reference, and counts into the half of the record it uses. Sending a
    measured burst and requiring the record to have moved by it is what
    separates counters the firmware is really maintaining from an index that
    was merely written into an opcode; requiring `ip -s link` on the device to
    have moved by the same burst, restated into the payload the device itself
    counts, is what makes the record an operator's number rather than a
    diagnostic.

    Both directions hold the record: the download moves its receive half,
    and the upload, through the offline-port detour, its transmit half -- the
    offline port's entry does the insert and counts it there, so a detoured
    direction's session is counted as any other's.
    """
    r = pppoe_rig
    await r.table()
    for _ in range(10):
        await r.exchange(count=4)
        if len((await r.state())["flows"]) == 2:
            break
    await _udp_directions(r)
    state = await r.state()
    row = _session_row(state, r.session_identity)
    # Held by both directions, and holding a record: the pool is empty only
    # after four sessions, and this bench has one. The record is the device's,
    # and says which device.
    assert row["refs"] == "2", row
    assert row["slot"] == "yes", row
    assert row["dev"] == r.ppp_if, row
    assert state["session_records"] == 1 and state["session_slots"] == 1, state
    before = {k: int(row[k]) for k in
              ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes")}
    link_before = await _ppp_link(r)

    payload = 256
    ip_len = 20 + 8 + payload
    await r.exchange(count=64, payload_size=payload)
    burst = await r.state()
    _assert_undisturbed(r, state, burst, [f["cookie"] for f in burst["flows"]]
                        == [f["cookie"] for f in state["flows"]])
    row = _session_row(burst, r.session_identity)
    link_after = await _ppp_link(r)
    after = {k: int(row[k]) for k in before}
    delta = {k: after[k] - before[k] for k in before}
    link = {k: link_after[k] - link_before[k] for k in before}
    # Received frames are the ones the download stripped the header from;
    # transmitted ones those the upload's offline entry inserted it into.
    assert delta["rx_packets"] == delta["tx_packets"] == 64, (before, after)
    # The firmware's session record, measured on this bench and pinned here:
    # the strip counts the frame as it arrived less the session header alone,
    # so the WAN tag the session runs over is still in; the insert counts the
    # frame with the Ethernet and session headers on and no tag yet.
    assert delta["rx_bytes"] == 64 * (ip_len + PPP_RX_OVERHEAD), delta
    assert delta["tx_bytes"] == 64 * (ip_len + PPP_TX_OVERHEAD), delta
    # The device counts the payload alone, both ways, folded in from the
    # record, and its counters now include the burst restated to exactly that,
    # plus the few frames the session itself exchanges meanwhile (LCP echoes),
    # each at most one frame.
    for half in ("rx", "tx"):
        stray = link[f"{half}_packets"] - 64
        assert 0 <= stray <= 8, (half, link)
        assert 64 * ip_len <= link[f"{half}_bytes"] <= 64 * ip_len + stray * 1518, (half, link)
    r.record("pppoe-session-counters", {"before": before, "after": after, "delta": delta,
                                        "row": row, "link": link})
    # The record belongs to the device rather than to the flows: retiring the
    # connection returns the references and keeps the record and its totals,
    # so the device's counters survive the connection going idle.
    await r.delete_table()
    state = await r.state()
    row = _session_row(state, r.session_identity)
    assert row["refs"] == "0" and row["slot"] == "yes", row
    assert state["session_records"] == 1 and state["session_slots"] == 1, state
    assert {k: int(row[k]) for k in after} == after, (row, after)


async def test_session_record_ignores_untagged_flows(pppoe_rig):
    """A session's hardware record ignores untagged flows that do not cross it.

    An entry whose ingress names no tag and no session still carries the strip
    that validates it arrived untagged, and that strip's statistics word is a
    count of zero at a pointer to the base of the statistics carve
    (insert_remove_vlan_hm()). The carve opens with the session pool, so the
    pointer is the receive half of the first session record -- the very
    address the download of a session holding that record counts into. Only
    the count tells the two apart. A microcode that followed the pointer
    whatever the count would put every untagged frame into that session's
    record, and through the fold into its ppp device's `ip -s link`; with the
    record free, into the free list's link, which occupies the same bytes.

    So a plain routed flow runs both ways between the bare ports while the
    session holds a record, and the record must not move at all. That is sharp
    while the session holds the first record, and here it does by
    construction: the pool is a stack laid down in carve order, taken from and
    returned to its head, so it hands out the first record every time until
    two sessions hold records at once -- and no case on this bench ever holds
    two, since each dials the only session (_session_identity). What of that
    can be read back is checked: no record held before the admission, exactly
    one after.

    The control is the session's own flow: 64 frames each way through it
    still move the same record by exactly 64 each way, the upload's through
    the offline-port detour. A record that counted nothing at all would pass
    everything else here too.
    """
    r = pppoe_rig
    initial = await r.state()
    assert initial["session_records"] == 0, (
        "a session record outlived its device, so the one this case takes would "
        "not come off the head of the pool", initial["sessions"])
    cleanup = []
    transport = None
    try:
        wan_if, dut_wan_ip = await _untagged_path(r, cleanup)
        await r.table()
        await r.nft(f"add rule inet {ft.TABLE} forward ip saddr {r.lan_ip} "
                    f"ip daddr {WAN_ENDPOINT} udp sport {UNTAGGED_SPORT} "
                    f"udp dport {UNTAGGED_DPORT} flow add @fast")
        for _ in range(10):
            await r.exchange(count=4)
            if len((await r.state())["flows"]) == 2:
                break
        await _udp_directions(r)
        held = await r.state()
        row = _session_row(held, r.session_identity)
        assert row["slot"] == "yes" and row["dev"] == r.ppp_if, row
        assert held["session_records"] == held["session_slots"] == 1, held
        transport, echo = await asyncio.get_running_loop().create_datagram_endpoint(
            Echo, local_addr=(WAN_ENDPOINT, UNTAGGED_DPORT))
        echo.record_payloads = False
        # The concentrator reaches the LAN VM through the session, so the WAN
        # host's echoes would come back inside it. For the window its route to
        # the LAN VM goes by the DUT's WAN address instead, which leaves both
        # halves of the flow bare; the session's route is back before the
        # control, which needs it.
        await command(r.wan, r.session, "ip", "route", "replace", r.reachable,
                      "via", dut_wan_ip, "dev", wan_if)
        try:
            measured = await _untagged_window(r, echo)
        finally:
            await command(r.wan, r.session, "ip", "route", "replace", r.reachable,
                          "dev", await _concentrator_if(r), check=False)
        r.record("pppoe-untagged-beside-session",
                 {**measured, "session": _session_text(r.session_identity)})

        before, after = measured["before"], measured["after"]
        old = _untagged_directions(r, before["flows"])
        new = _untagged_directions(r, after["flows"])
        _assert_undisturbed(r, before, after, new is not None and
                            [f["cookie"] for f in new] == [f["cookie"] for f in old])
        # Bare both ways: nothing described on either side of either
        # direction, so each entry's strip is the one that names no record.
        for flow, ingress, egress in ((old[0], TARGET_LAN_IF, TARGET_WAN_IF),
                                      (old[1], TARGET_WAN_IF, TARGET_LAN_IF)):
            assert (flow["in"], flow["out"]) == (ingress, egress), flow
            assert all(flow[k] == "-" for k in ("in_vlan", "out_vlan", "in_br", "out_br",
                                                "in_ppp", "out_ppp", "in_tnl", "out_tnl")), flow
        # Every round trip crossed in hardware, both ways.
        assert measured["report"] == {"echoed": UNTAGGED_COUNT, "lost": 0}, measured["report"]
        assert measured["answered"] == UNTAGGED_COUNT, measured["answered"]
        moved = [int(n["packets"]) - int(o["packets"]) for o, n in zip(old, new)]
        assert moved == [UNTAGGED_COUNT, UNTAGGED_COUNT], (moved, old, new)
        # Nothing crossed the session's directions in hardware meanwhile,
        # where they are still installed -- they can go idle and expire in the
        # window, which retires the entries and keeps the record. So any
        # movement below is the pointer's and not traffic's.
        download = {f["cookie"]: int(f["packets"]) for f in before["flows"]
                    if f["in_ppp"] != "-" or f["out_ppp"] != "-"}
        crossed = {f["cookie"]: int(f["packets"]) - download[f["cookie"]]
                   for f in after["flows"] if f["cookie"] in download}
        assert not any(crossed.values()), (crossed, before["flows"], after["flows"])
        record = {k: measured["record_after"][k] - measured["record"][k]
                  for k in measured["record"]}
        assert record == dict.fromkeys(record, 0), (
            f"{2 * UNTAGGED_COUNT} untagged frames moved the session's record",
            measured["record"], measured["record_after"])
        # What the session exchanges on its own meanwhile: each end sends an
        # LCP echo request every LCP_ECHO_INTERVAL seconds and answers the
        # other's, so the DUT receives at most two frames per interval, and a
        # window of w seconds overlaps at most ceil(w / interval) + 1 of them;
        # each is at most a full frame. A record counting the untagged flows
        # would fold thousands in here.
        allowance = 2 * (math.ceil(measured["window"] / LCP_ECHO_INTERVAL) + 1)
        link = {k: measured["link_after"][k] - measured["link"][k] for k in measured["link"]}
        assert 0 <= link["rx_packets"] <= allowance, (
            allowance, measured["window"], measured["link"], measured["link_after"])
        assert link["rx_bytes"] <= link["rx_packets"] * 1518, (
            measured["link"], measured["link_after"])
        assert after["errors"] == initial["errors"], (initial["errors"], after)
        row = _session_row(after, r.session_identity)
        assert row["slot"] == "yes", row
        assert after["session_records"] == after["session_slots"] == 1, after

        # The control. The session's directions may have expired over the
        # window, so they are offered until hardware holds both again, then
        # measured as test_session_counters measures them.
        for _ in range(10):
            await r.exchange(count=4)
            state = await r.state()
            if sum(f["in_ppp"] != "-" or f["out_ppp"] != "-" for f in state["flows"]) == 2:
                break
        else:
            pytest.fail(f"the session's directions were not readmitted: {state}")
        download = _direction(state["flows"], INNER_LOCAL, r.lan_ip)
        halves = _session_halves(state, r.session_identity)
        payload = 256
        await r.exchange(count=64, payload_size=payload)
        burst = await r.state()
        counted = _direction(burst["flows"], INNER_LOCAL, r.lan_ip)
        _assert_undisturbed(r, state, burst, counted["cookie"] == download["cookie"])
        control = {k: v - halves[k] for k, v in _session_halves(burst, r.session_identity).items()}
        r.record("pppoe-untagged-control", {"before": halves, "delta": control,
                                            "download": [download, counted]})
        assert int(counted["packets"]) - int(download["packets"]) == 64, (download, counted)
        assert control == {"rx_packets": 64,
                           "rx_bytes": 64 * (20 + 8 + payload + PPP_RX_OVERHEAD),
                           "tx_packets": 64,
                           "tx_bytes": 64 * (20 + 8 + payload + PPP_TX_OVERHEAD)}, (halves, control)
    finally:
        if transport:
            transport.close()
        # The table first, so its entries retire by unbinding rather than by
        # the routes below going out from under them.
        await command(r.target, r.session, "nft", "delete", "table", "inet", ft.TABLE,
                      check=False)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


@pytest.mark.parametrize("target", ["dev-stats", "hardware"])
async def test_admission_failslab(pppoe_rig, target):
    """A session direction's admission takes a reference on the ppp device's
    statistics record before its hardware entry exists. A hardware failure
    after that has to hand the reference back, and the connection recovers by
    traffic alone. A failure creating the record itself is not an admission
    failure: that direction forwards in hardware and counts nowhere, which the
    record's references and counters both show.

    Both directions of the UDP flow cross the session, the upload through the
    offline-port detour, and the fault meets whichever asks first. A failed
    hardware add, of either -- for the detour, its record of the direction
    first -- leaves nothing held, and both come back holding the record. A
    failed record leaves the direction that asked for it uncounted, and the
    other creates the record and counts alone."""
    from _flowtable_failslab import (slab_fault)
    from _flowtable_service import (FAULT_DIR)

    r = pppoe_rig
    # The guard is staged and cancelled over the DUT console; no service
    # fixture runs here to own the directory it lives in.
    r.service_console = r.console
    await console_command(r.console, "rm", "-rf", FAULT_DIR)
    await console_command(r.console, "mkdir", FAULT_DIR)
    try:
        initial = await r.state()
        await r.table()
        async with slab_fault(r, target, "pppoe-" + target) as fault:
            await r.exchange(count=4)
            hit = await fault.hit()
        deadline = time.monotonic() + 20
        while True:
            await r.exchange(count=4)
            state = await r.state()
            if len(state["flows"]) == 2:
                break
            assert time.monotonic() < deadline, state
    finally:
        await console_command(r.console, "rm", "-rf", FAULT_DIR, check=False)
    flows = await _udp_directions(r)
    _assert_session(r, _direction(flows, r.lan_ip, INNER_LOCAL), _direction(flows, INNER_LOCAL, r.lan_ip))
    state = await r.state()
    assert state["errors"] == initial["errors"] and state["fatal"] == state["quarantine"] == 0, state
    assert state["installs"] - state["deletes"] == state["entries"] == 2, state
    assert state["detour_flows"] == initial["detour_flows"] + 1, (initial, state)
    assert state["session_records"] == initial["session_records"] + 1, (initial, state)
    counted = _session_row(state, r.session_identity)
    assert counted["slot"] == "yes", counted
    assert counted["refs"] == ("1" if target == "dev-stats" else "2"), counted
    before = {f["cookie"]: int(f["packets"]) for f in flows}
    installed = state
    await r.exchange(count=64)
    state = await r.state()
    _assert_undisturbed(r, installed, state, {f["cookie"] for f in state["flows"]} == set(before))
    assert {f["cookie"]: int(f["packets"]) - before[f["cookie"]]
            for f in state["flows"]} == {c: 64 for c in before}, (before, state["flows"])
    # The download strips the session header and the upload inserts it, and
    # the burst moved each by 64: into the record's receive and transmit
    # halves, but for the one direction whose record failed, which counts
    # nowhere.
    row = _session_row(state, r.session_identity)
    moved = {half: int(row[half + "_packets"]) - int(counted[half + "_packets"])
             for half in ("rx", "tx")}
    if target == "dev-stats":
        assert sorted(moved.values()) == [0, 64], (counted, row)
    else:
        assert moved == {"rx": 64, "tx": 64}, (counted, row)
    r.record("pppoe-" + target + "-recovery", {"initial": initial, "state": state,
                                               "hit": hit, "row": row})
    # Retiring the connection returns exactly the references it took.
    await r.delete_table()
    row = _session_row(await r.state(), r.session_identity)
    assert row["refs"] == "0", row


async def test_snat(pppoe_rig):
    """Source NAT across the session, proved at the far endpoint.

    The concentrator observing the translated source is what separates a
    rewrite that reached the wire from one that only reached the rule. Both
    halves are the hardware's: the translation on the way out, in front of the
    insert, on the offline port's entry of the detoured upload, and the
    reverse translation, after the strip, on the download's.
    """
    r = pppoe_rig
    await command(r.target, r.session, "nft", _snat_table(r))
    try:
        flows, delta = await _established(r)
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        assert forward["new_src"].startswith(SNAT_ADDR + ":") and forward["detour"] == "1", forward
        reverse = _direction(flows, INNER_LOCAL, SNAT_ADDR)
        assert reverse["new_dst"].startswith(r.lan_ip + ":"), reverse
        _assert_session(r, forward, reverse)
        assert all(d == 64 for d in delta.values()), delta
        # What the wire carried, not what the rule said it would.
        assert r.echo.sources == {(SNAT_ADDR, SPORT)}, r.echo.sources
        r.record("pppoe-snat", {"flows": flows, "delta": delta,
                                "observed": sorted(r.echo.sources)})
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)


@pytest.mark.parametrize("pppoe_rig", ["tcp"], indirect=True)
async def test_snat_tcp(pppoe_rig):
    """Source NAT in front of the insert, in hardware.

    The concentrator seeing the translated source connect, while the upload
    that carried the connection was in hardware, says the translation and the
    encapsulation were applied to the same frame in the right order: the
    rewrite before the session header went on, and the reverse translation
    after it came off.
    """
    r = pppoe_rig
    await command(r.target, r.session, "nft", _snat_table(r))
    try:
        await r.table()
        measured = await _tcp_carried(r, "flowtable_pppoe_snat_tcp")
        flows = measured["flows"]
        r.record("pppoe-snat-tcp", measured)
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        assert forward["new_src"].startswith(SNAT_ADDR + ":"), forward
        reverse = _direction(flows, INNER_LOCAL, SNAT_ADDR)
        assert reverse["new_dst"].startswith(r.lan_ip + ":"), reverse
        _assert_session(r, forward, reverse)
        _assert_carried(r, measured)
        assert measured["peer"] == (SNAT_ADDR, SPORT), measured["peer"]
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)


@pytest.mark.parametrize("pppoe_rig", ["tagged", "tagged-tcp"], indirect=True)
async def test_tagged_lan(pppoe_rig):
    """A tag on the LAN and a session on the WAN, so every slot is spent.

    The WAN path already costs a tag and a session, which is both
    encapsulation slots that direction has. Adding a tag on the LAN gives each
    direction something to describe on each side at once: the forward rule pops
    the LAN tag, pushes the WAN tag and pushes the session, and the reverse one
    is the mirror. A derivation that counted the session against the wrong
    direction's budget, or emitted its push in the wrong place, produces an
    action list of the right length for the wrong reason -- so the tags are
    asserted per direction, not as a set.

    Both directions are proved over either protocol, the UDP upload through
    the offline-port detour, whose receive entry hands the frame on with the
    LAN tag still on for the offline port's entry to pop.
    """
    r = pppoe_rig
    if r.proto == "tcp":
        await r.table()
        delta = await _tcp_carried(r, "flowtable_pppoe_tagged_tcp")
        flows = delta["flows"]
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        _assert_carried(r, delta)
    else:
        flows, delta = await _established(r)
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        assert forward["detour"] == "1", forward
        assert all(d == 64 for d in delta.values()), delta
    assert forward["in_vlan"] == str(LAN_VID), forward
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    assert reverse["out_vlan"] == str(LAN_VID), reverse
    r.record("pppoe-tagged-lan-" + r.proto, {"flows": flows, "delta": delta,
                                             "lan_vid": LAN_VID, "wan_vid": WAN_VID})


async def _send_datagrams(r, count, size, label, echo=False):
    """`count` datagrams of `size` bytes from the LAN VM to the session's far
    end with DF clear, one at a time; with `echo`, each echo awaited and
    compared, and how many came back whole."""
    from _topology import lan_run_python
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, 10, 4)  # IP_MTU_DISCOVER: IP_PMTUDISC_INTERFACE, DF clear
s.settimeout(2)
s.bind(({r.lan_ip!r}, {SPORT}))
whole = 0
for n in range({count}):
    payload = struct.pack('!Q', n) + bytes(range(1, 256)) * ({size} // 255 + 1)
    payload = payload[:{size}]
    s.sendto(payload, ({INNER_LOCAL!r}, {ft.DPORT}))
    if {echo!r}:
        try:
            data, _ = s.recvfrom(4096)
            whole += data == payload
        except TimeoutError:
            pass
    else:
        time.sleep(0.01)
s.close()
print(json.dumps({{"sent": {count}, "whole": whole}}))
'''
    result = await lan_run_python(r.lan, script, timeout=30, label=label)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


async def test_upload_fragments_whole(pppoe_rig):
    """A UDP upload larger than the session leaves in fragments that are whole,
    each with a session header of its own.

    The upload takes the offline-port detour (see the module docstring), whose
    entry inserts the session header and fragments what exceeds the session:
    a 1500-byte datagram from the 1500-byte LAN becomes two, each a PPPoE frame
    whose length is its own, on the session the kernel negotiated. Captured as
    the wire carries them, on the concentrator's side of the tag, and checked
    there byte for byte; the concentrator's ppp device reassembles every one.
    Linux sends none of them: the fragmenter counts each."""
    from scapy.all import IP, PPPoE, AsyncSniffer, wrpcap
    from _flowtable_mtu import detour_counters, fragmenter
    import threading
    r = pppoe_rig
    flows, _ = await _established(r)
    session_id, _ = r.session_identity
    count, size = 32, SESSION_MTU - 20
    before, counters_before = await r.state(), await fragmenter(r)
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=SERVER_IF, filter=f"pppoes and ip src {r.lan_ip}",
                           store=True, started_callback=ready.set)
    sniffer.start()
    r.echo.reply = False
    try:
        assert await asyncio.to_thread(ready.wait, 5), "wire capture did not start"
        await _send_datagrams(r, count, size, "flowtable_pppoe_upload_fragments")
        payloads = [struct.pack("!Q", n) + (bytes(range(1, 256)) * (size // 255 + 1)) for n in range(count)]
        payloads = [p[:size] for p in payloads]
        deadline = time.monotonic() + 5
        while sum(r.echo.received[p] for p in payloads) < count and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
    finally:
        r.echo.reply = True
        frames = sniffer.stop()
        ft.artifact_dir().mkdir(parents=True, exist_ok=True)
        wrpcap(str(ft.artifact_dir() / "pppoe-upload-fragments.pcap"), frames)
    await asyncio.sleep(1.5)
    after, counters_after = await r.state(), await fragmenter(r)
    moved = {k: counters_after[k] - counters_before[k] for k in counters_before}
    r.record("pppoe-upload-fragments", {"before": before, "after": after, "fragmenter": moved,
                                        "frames": len(frames)})
    assert [r.echo.received[p] for p in payloads] == [1] * count, [r.echo.received[p] for p in payloads]
    assert moved["IPv4 frames received"] == count, moved
    assert moved["Number of IPv4 fragments sent"] == 2 * count, moved
    assert moved["Failures in allocating buffers"] == 0, moved
    assert detour_counters(after) == detour_counters(before), (before, after)
    groups = {}
    for frame in frames:
        if IP in frame:
            groups.setdefault(frame[IP].id, []).append(frame)
    assert len(groups) == count, sorted(groups)
    for ident, fragments in groups.items():
        assert len(fragments) == 2, (ident, [f.summary() for f in fragments])
        for fragment in fragments:
            # The session's, and a length that is this fragment's: its PPP
            # protocol field and its IP packet.
            assert fragment[PPPoE].sessionid == session_id, fragment.summary()
            assert fragment[PPPoE].len == fragment[IP].len + 2, fragment.summary()
            assert fragment[IP].len <= SESSION_MTU, fragment.summary()
        first, last = sorted(fragments, key=lambda f: f[IP].frag)
        datagram = b"".join(bytes(f[IP])[4 * f[IP].ihl:f[IP].len] for f in (first, last))
        serial = struct.unpack("!Q", datagram[8:16])[0]
        assert datagram[8:] == payloads[serial], (ident, datagram[8:40].hex())


async def test_download_into_smaller_lan_path(pppoe_rig):
    """A download out of the session into a LAN path lowered below the
    session's MTU stays in software; the upload still takes the detour.

    The offline port does not classify a session frame to its entry -- every
    frame of a download through the detour came back from the port when one
    was tried (A393) -- so it is left to Linux, which fragments it, as
    before. 1400-byte datagrams go up whole through
    the detour and come back fragmented by Linux, which the LAN host
    reassembles byte for byte."""
    from _flowtable_mtu import detour_counters, fragmenter
    r = pppoe_rig
    route = [f"{r.lan_ip}/32", "dev", r.dut_lan_if]
    echo_socket = r.echo.transport.get_extra_info("socket")
    pmtu = echo_socket.getsockopt(socket.SOL_IP, 10)
    await command(r.target, r.session, "ip", "route", "replace", *route, "mtu", "1200")
    # The far end's replies leave with DF clear, as the LAN's requests do, so
    # what is too big for the LAN path is fragmented rather than refused.
    echo_socket.setsockopt(socket.SOL_IP, 10, 0)  # IP_MTU_DISCOVER: IP_PMTUDISC_DONT
    try:
        initial = await r.state()
        await r.table()
        for _ in range(10):
            await r.exchange(count=4)
            state = await r.state()
            if state["flows"] and state["rejects"] > initial["rejects"]:
                break
        upload, = state["flows"]
        assert (upload["in"], int(upload["mtu"]), upload["detour"]) == (
            TARGET_LAN_IF, SESSION_MTU, "1"), state
        before, counters_before = await r.state(), await fragmenter(r)
        report = await _send_datagrams(r, 32, 1400, "flowtable_pppoe_download_smaller", echo=True)
        await asyncio.sleep(1.5)
        after, counters_after = await r.state(), await fragmenter(r)
        moved = {k: counters_after[k] - counters_before[k] for k in counters_before}
        r.record("pppoe-download-smaller", {"report": report, "fragmenter": moved,
                                            "before": before, "after": after})
        assert report == {"sent": 32, "whole": 32}, report
        # Nothing fragmented in hardware -- the upload fits the session -- and
        # nothing handed back.
        assert moved["IPv4 frames received"] == 0, moved
        assert detour_counters(after) == detour_counters(before), (before, after)
        assert int(after["flows"][0]["packets"]) - int(before["flows"][0]["packets"]) == 32, (before, after)
    finally:
        echo_socket.setsockopt(socket.SOL_IP, 10, pmtu)
        await r.delete_table()
        await command(r.target, r.session, "ip", "route", "del", *route, check=False)


async def _in_hdr_errors(r):
    """The DUT's IPv4 header-error count, which ip_forward() raises for every
    packet it would forward with a TTL of 0 or 1, rate limit or not."""
    rows = [line.split() for line in (await read(r.target, r.session, "/proc/net/snmp")).splitlines()
            if line.startswith("Ip:")]
    return int(dict(zip(rows[0][1:], rows[1][1:]))["InHdrErrors"])


def _time_exceeded(icmp, source, destination, dport, seconds):
    """Time Exceeded messages arriving on a raw ICMP socket within `seconds`
    that quote a UDP datagram from `source` to `destination`:`dport`."""
    found, deadline = 0, time.monotonic() + seconds
    while (left := deadline - time.monotonic()) > 0:
        icmp.settimeout(left)
        try:
            packet = icmp.recv(2048)
        except TimeoutError:
            break
        header = 4 * (packet[0] & 0x0F)
        message, quoted = packet[header:header + 8], packet[header + 8:]
        if message[:2] != b"\x0b\x00" or len(quoted) < 28:
            continue
        inner = 4 * (quoted[0] & 0x0F)
        if (quoted[9] == socket.IPPROTO_UDP
                and socket.inet_ntoa(quoted[12:16]) == source
                and socket.inet_ntoa(quoted[16:20]) == destination
                and struct.unpack("!H", quoted[inner + 2:inner + 4])[0] == dport):
            found += 1
    return found


async def test_download_ttl_one_reaches_linux(pppoe_rig):
    """A download packet with a TTL of 1 on the offloaded tuple reaches Linux,
    which answers Time Exceeded, and is not carried; the direction still is.

    It arrives inside the session. The soft parser's TTL check ends the parse
    without confirming its IPv4 header, and used to enqueue it to the CPU from
    the parser itself, past the punt meter (A370). It is now classified by its
    session header alone, as an LCP frame is, and must still find Linux rather
    than the direction's entry. Every such packet raises
    ip_forward()'s header-error count; Time Exceeded is rate limited, so one is
    enough of those."""
    r = pppoe_rig
    count = 4
    flows, _ = await _established(r)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    echo_socket = r.echo.transport.get_extra_info("socket")
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ttl = echo_socket.getsockopt(socket.SOL_IP, socket.IP_TTL)
    try:
        before, errors = await r.state(), await _in_hdr_errors(r)
        echo_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
        try:
            for n in range(count):
                r.echo.transport.sendto(b"ASK-pppoe-ttl-one" + struct.pack("!Q", n),
                                        (r.lan_ip, SPORT))
        finally:
            echo_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        exceeded = await asyncio.to_thread(_time_exceeded, icmp, INNER_LOCAL, r.lan_ip, SPORT, 2)
        after, errors = await r.state(), await _in_hdr_errors(r) - errors
    finally:
        icmp.close()
    carried = {f["cookie"]: int(f["packets"]) for f in after["flows"]}
    r.record("pppoe-ttl-one", {"before": before, "after": after, "in_hdr_errors": errors,
                               "time_exceeded": exceeded})
    assert errors >= count and exceeded >= 1, (errors, exceeded)
    assert carried[reverse["cookie"]] == int(_direction(before["flows"], INNER_LOCAL,
                                                        r.lan_ip)["packets"]), (before, after)
    _assert_undisturbed(r, before, after, {f["cookie"] for f in before["flows"]} == set(carried))
    await r.exchange(count=16)
    final = await r.state()
    moved = int(_direction(final["flows"], INNER_LOCAL, r.lan_ip)["packets"]) - carried[reverse["cookie"]]
    assert moved == 16, (after, final)


@pytest.mark.parametrize("pppoe_rig", ["tagged"], indirect=True)
async def test_handback_tagged(pppoe_rig):
    """What the offline port hands back of a tagged upload reaches Linux on
    the LAN port, tag and all, and Linux forwards it into the session.

    The upload's receive entry is installed alone (the `detour_strand` test
    knob), so every frame of it comes back from the offline port with nothing
    to say where it arrived; the detour's record, found through the LAN tag,
    says, and Linux takes the frame through the tagged device as it would have
    from the port."""
    from _flowtable_mtu import STRAND, detour_counters
    r = pppoe_rig
    assert (await r.target.fs_write(r.session, STRAND, "1"))["errno"] == 0
    r.detour_strand = True
    try:
        await _established(r)
    finally:
        r.detour_strand = False
        assert (await r.target.fs_write(r.session, STRAND, "0"))["errno"] == 0
    before = await r.state()
    report = await _send_datagrams(r, 16, 1400, "flowtable_pppoe_handback", echo=True)
    await asyncio.sleep(1)
    after = await r.state()
    r.record("pppoe-handback", {"report": report, "before": before, "after": after})
    assert report == {"sent": 16, "whole": 16}, report
    delta = {k: after[k] - before[k] for k in detour_counters(before)}
    assert delta == {"detour_flows": 0, "detour_delivered": 16, "detour_unknown": 0,
                     "detour_failed": 0, "detour_errors": 0}, delta


async def test_full_mtu_datagram(pppoe_rig):
    """A datagram filling the session MTU still crosses it.

    The frame the session carries is twelve bytes longer than the datagram
    inside it: eight for the PPPoE and PPP headers and four for the tag the
    session stands on. If the hardware's own size check counted any of them,
    this is the payload that would be dropped or punted while a shorter one was
    forwarded, so the counters have to account for it exactly as for any other
    burst. 1492 is the path MTU rather than a number chosen here, which is what
    makes the reply the same size as the request.

    Both datagrams are the hardware's: the request, into the session through
    the offline-port detour, whose receive entry carries the session MTU for
    its DF check and whose offline entry adds all twelve and fragments nothing
    of a datagram that fits; and the reply, stripped of all twelve.
    """
    r = pppoe_rig
    await r.table()
    for _ in range(10):
        await r.exchange(count=4)
        if len((await r.state())["flows"]) == 2:
            break
    before = {f["cookie"]: int(f["packets"]) for f in await _udp_directions(r)}
    installed = await r.state()
    # The session MTU less the IPv4 and UDP headers: the largest datagram the
    # path takes without fragmenting, and exactly the one the eight bytes of
    # PPPoE would push over if they were counted twice.
    await r.exchange(count=16, payload_size=SESSION_MTU - 28)
    state = await r.state()
    after = {f["cookie"]: int(f["packets"]) for f in state["flows"]}
    _assert_undisturbed(r, installed, state, set(before) == set(after))
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == 16 for d in delta.values()), delta
    r.record("pppoe-full-mtu", {"delta": delta, "payload": SESSION_MTU - 28})


async def test_qos_upload_keeps_its_class(pppoe_rig):
    """A marked upload through the session lands on its class, and unmarked
    bulk through the same session cannot starve it.

    Every frame the CPU sends into a PPPoE session loses its conntrack and its
    ingress index before it reaches the port: ppp_start_xmit() scrubs both. The
    port's queue selection used to take such a frame for the gateway's own,
    which put every upload over the session -- marked or not -- on class queue
    7, above every class in the tree. The marked flow lost its class, and an
    unmarked one could take the whole channel from every leaf. Now the port
    reads the frame through the tag and the session header and finds the
    connection again by the translated packet's tuple.

    The tree is on the WAN port: one channel at QOS_RATE_MBIT and one prio 1
    leaf. The marked flow is translated, as a subscriber's is, and echoed one
    datagram at a time while the unmarked one offers three times the channel.
    Nothing is offloaded -- no flowtable is bound -- so this is the software
    path alone. The oracles are the port's CEETM counters: every marked frame
    on the leaf, the unmarked flow holding the unclassified queue full, and
    the control queue carrying only control traffic.
    """
    from _flowtable_qos import (OAL, egress, leaf_delta, timing_slack)

    r = pppoe_rig
    mask = int((await read(r.target, r.session,
                           "/sys/module/ask_flowtable/parameters/qos_mark_mask")).strip())
    if not mask:
        pytest.skip("classification is off in this boot; the QoS case needs "
                    "ask_flowtable.qos_mark_mask=0xf0, which the test image ships")
    mark = QOS_VOICE_CQ << ((mask & -mask).bit_length() - 1)
    dev = TARGET_WAN_IF
    rate = f"{QOS_RATE_MBIT}mbit"

    async def tc(*argv, check=True):
        """`tc` is not in the agent's argv allowlist, so the tree is built on
        the console the fixture holds."""
        return await console_command(r.console, "tc", *argv, check=check, timeout=30)

    async def clear_ct():
        for port in (PORT_QOS_VOICE, PORT_QOS_BULK):
            await command(r.target, r.session, "conntrack", "-D", "-p", "udp",
                          "--orig-src", r.lan_ip, "--dport", str(port), check=False)

    # A port nothing reads: the far end queues what arrives until its buffer
    # is full and drops the rest, rather than answering every datagram with an
    # ICMP error back down the session.
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind((INNER_LOCAL, PORT_QOS_BULK))
    transport, echo = await asyncio.get_running_loop().create_datagram_endpoint(
        SourceEcho, local_addr=(INNER_LOCAL, PORT_QOS_VOICE))
    bulk = False
    try:
        await clear_ct()
        # A run killed before its teardown leaves its tree behind.
        await tc("qdisc", "del", "dev", dev, "root", check=False)
        await tc("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "offload")
        await tc("class", "add", "dev", dev, "parent", "1:", "classid", "1:1",
                 "htb", "rate", rate, "ceil", rate)
        await tc("class", "add", "dev", dev, "parent", "1:1", "classid", "1:10",
                 "htb", "rate", rate, "ceil", rate, "prio", str(QOS_VOICE_PRIO))
        # The mark at forward/mangle, and the translation at the priority the
        # SNAT case uses, ahead of the image's own masquerade.
        await command(r.target, r.session, "nft", f"""table ip {QOS_TABLE} {{
 chain forward {{ type filter hook forward priority -150; policy accept;
 ip saddr {r.lan_ip} udp dport {PORT_QOS_VOICE} ct mark set {mark:#x}; }}
 chain postrouting {{ type nat hook postrouting priority 90; policy accept;
 ip saddr {r.lan_ip} ip daddr {INNER_LOCAL} udp dport {PORT_QOS_VOICE} snat to {SNAT_ADDR}; }}
}}""")
        await _qos_bulk(r, seconds=30)
        bulk = True
        await asyncio.sleep(3)
        first = await egress(r, dev)
        voice = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({r.lan_ip!r}, {PORT_QOS_VOICE}))
s.settimeout(1)
echoed = lost = 0
for n in range({QOS_COUNT}):
    payload = struct.pack('!Q', n) + b'ASK-pppoe-qos'.ljust(120, b'.')
    s.sendto(payload, ({INNER_LOCAL!r}, {PORT_QOS_VOICE}))
    try:
        while s.recv(2048) != payload:
            pass
        echoed += 1
    except TimeoutError:
        lost += 1
    time.sleep(0.02)
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
'''
        result = await r.run_peer(voice, label="pppoe_qos_voice", timeout=QOS_COUNT * 1.1 + 30)
        assert result.rc == 0, result.stdout
        report = json.loads(result.stdout.strip().splitlines()[-1])
        second = await egress(r, dev)
        conntrack = await command(r.target, r.session, "conntrack", "-L", "-p", "udp",
                                  "--dport", str(PORT_QOS_VOICE), "-o", "extended", check=False)
    finally:
        if bulk:
            await _qos_bulk_stop(r)
        transport.close()
        sink.close()
        await tc("qdisc", "del", "dev", dev, "root", check=False)
        await command(r.target, r.session, "nft", "delete", "table", "ip", QOS_TABLE,
                      check=False)
        await clear_ct()
    voice_leaf = leaf_delta(first, second, 0)
    unclassified = leaf_delta(first, second, "default")
    control = leaf_delta(first, second, "control")
    window = second["at"] - first["at"]
    shaped = sum((q["bytes"] + OAL * q["frames"]) * 8
                 for q in (voice_leaf, unclassified, control)) / window
    r.record("pppoe-qos", {"report": report, "voice_leaf": voice_leaf,
                           "unclassified": unclassified, "control": control,
                           "shaped_bps": shaped, "window": window,
                           "sources": sorted(echo.sources),
                           "conntrack": conntrack["stdout"]})

    # Translated on the way, so the connection was found by the inverse of a
    # tuple the table does not hold.
    assert echo.sources == {(SNAT_ADDR, PORT_QOS_VOICE)}, echo.sources
    # Every marked frame on the leaf its mark names, and it lost nothing to
    # the unmarked flow beside it: the leaf is above the queue that flow is on.
    assert report["echoed"] + report["lost"] == QOS_COUNT, report
    assert report["lost"] <= QOS_COUNT // 100, report
    assert QOS_COUNT - report["lost"] <= voice_leaf["frames"] <= QOS_COUNT, (voice_leaf, report)
    assert voice_leaf["rejected"] == 0, voice_leaf
    # The unmarked flow held the unclassified queue full -- the queue refused
    # what the channel could not carry -- and the channel carried what it was
    # shaped to.
    assert unclassified["rejected"] > 0 and unclassified["frames"] > 0, unclassified
    slack = timing_slack(first, second)
    assert shaped >= (0.85 - slack) * QOS_RATE_MBIT * 1e6, (shaped, slack)
    # None of it rode the control queue, which now carries only control
    # traffic: the session's LCP, the gateway's own sessions.
    assert control["frames"] * 20 < unclassified["frames"], (control, unclassified)


@pytest.mark.parametrize("pppoe_rig", ["tcp"], indirect=True)
async def test_tcp(pppoe_rig):
    """An established TCP connection across the session.

    The classifier punts SYN, FIN and RST before its own lookup, so what the
    hardware actually carries is the bulk transfer in the middle. The cookies
    staying put is what proves the connection was never readmitted underneath
    it -- and with a session that matters more than elsewhere, because a
    readmission against a changed session would still forward, just to a
    header the concentrator no longer answers.

    It is also the upload in hardware, which UDP cannot be: the insert, the
    session MTU it carries, its large segments crossing whole, and the
    record's transmit half counting them into the ppp device's own counters.
    """
    r = pppoe_rig
    await r.table()
    measured = await _tcp_carried(r, "flowtable_pppoe_tcp")
    flows = measured["flows"]
    r.record("pppoe-tcp", {**measured, "session": _session_text(r.session_identity)})
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    # The forward direction leaves by the session, so it carries the session's
    # MTU; nothing in this test set it, and the eight bytes are already in it.
    assert int(forward["mtu"]) == SESSION_MTU, forward
    _assert_carried(r, measured)


@pytest.mark.parametrize("pppoe_rig", ["openwrt"], indirect=True)
async def test_openwrt_lan(pppoe_rig):
    """OpenWrt's own LAN behind the session: the station sits on a br-lan port
    whose address is not the bridge's, as it does on every port but one.

    The download is held in hardware and leaves by the station's port through
    the bridge, and the exchange checks that every frame towards the station
    carries the bridge's address as its source, as the software path's do. The
    upload enters by that port and takes the offline-port detour (see the
    module docstring); test_openwrt_lan_tcp carries TCP both ways.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    assert reverse["out_br"] == r.dut_lan_if and reverse["out_vlan"] == "-", reverse
    assert int(reverse["mtu"]) == 1500, reverse
    assert forward["in_br"] == r.dut_lan_if and forward["detour"] == "1", forward
    assert int(forward["mtu"]) == SESSION_MTU, forward
    assert all(d == 64 for d in delta.values()), delta
    r.record("pppoe-openwrt", {"flows": flows, "delta": delta,
                               "session": _session_text(r.session_identity)})


@pytest.mark.parametrize("pppoe_rig", ["openwrt-tcp"], indirect=True)
async def test_openwrt_lan_tcp(pppoe_rig):
    """Both directions between OpenWrt's br-lan and a session, in hardware: the
    upload enters by the station's bridge port and inserts the session, the
    download strips it and leaves by that port, and the session's record counts
    both halves into the ppp device."""
    r = pppoe_rig
    await r.table()
    measured = await _tcp_carried(r, "flowtable_pppoe_openwrt_tcp")
    flows = measured["flows"]
    r.record("pppoe-openwrt-tcp", {**measured, "session": _session_text(r.session_identity)})
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    assert forward["in_br"] == r.dut_lan_if and reverse["out_br"] == r.dut_lan_if, (forward,
                                                                                   reverse)
    assert int(forward["mtu"]) == SESSION_MTU, forward
    _assert_carried(r, measured)


@pytest.mark.parametrize("pppoe_rig", ["cloned-tcp"], indirect=True)
async def test_cloned_wan_mac(pppoe_rig):
    """A session over a device carrying a cloned MAC, as an ISP that binds the
    line to one requires (OpenWrt's `macaddr` on the WAN).

    The concentrator finds a session's frames by their source address as well
    as by the session id (pppoe_rcv()), so the upload reaching it from hardware
    at all is the wire's proof that the insert writes the clone rather than
    the port's own address -- which would be dropped there, unanswered.
    """
    r = pppoe_rig
    lower = (await read(r.target, r.session, f"/sys/class/net/{r.ppp_lower}/address")).strip()
    port = (await read(r.target, r.session, f"/sys/class/net/{TARGET_WAN_IF}/address")).strip()
    assert lower == CLONED_WAN_MAC != port, (lower, port)
    await r.table()
    measured = await _tcp_carried(r, "flowtable_pppoe_cloned_tcp")
    flows = measured["flows"]
    r.record("pppoe-cloned-tcp", {**measured, "session": _session_text(r.session_identity)})
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    _assert_carried(r, measured)


@pytest.mark.parametrize("pppoe_rig", ["bridged-wan-tcp"], indirect=True)
async def test_bridged_wan(pppoe_rig):
    """A session over a VLAN device on a bridged WAN: br-wan, whose address is
    its own rather than its port's, and br-wan.3900 over it.

    The session's frames carry br-wan.3900's address, which is the bridge's,
    and the concentrator answers a session only from the source it was
    negotiated with (pppoe_rcv()), so the upload reaching it from hardware is
    the wire's proof of the source the insert writes.
    """
    r = pppoe_rig
    lower = (await read(r.target, r.session, f"/sys/class/net/{r.ppp_lower}/address")).strip()
    port = (await read(r.target, r.session, f"/sys/class/net/{TARGET_WAN_IF}/address")).strip()
    assert lower == r.wan_bridge_mac != port, (lower, port)
    await r.table()
    measured = await _tcp_carried(r, "flowtable_pppoe_bridged_wan_tcp")
    flows = measured["flows"]
    r.record("pppoe-bridged-wan-tcp", {**measured, "session": _session_text(r.session_identity)})
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    assert forward["out_br"] != "-" and reverse["in_br"] != "-", (forward, reverse)
    _assert_carried(r, measured)


async def test_mtu_retires(pppoe_rig):
    """The ppp device carries its own MTU, and a flow through it depends on it.

    Each direction carries the MTU of the interface it leaves by: the
    download, which arrives by the session, the LAN port's; the upload, through
    the offline-port detour at any session MTU below a full frame, the
    session's. Lowering the session retires the connection -- one increment,
    for the one invalidation handle both directions share -- and both come
    back, the download as it was and the upload describing the new MTU.
    """
    r = pppoe_rig
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

    before = await settled({TARGET_LAN_IF: 1500, TARGET_WAN_IF: SESSION_MTU})
    await command(r.target, r.session, "ip", "link", "set", r.ppp_if, "mtu", "1400")
    try:
        invalidated = await r.wait(
            lambda s: s["mtu_invalidations"] >= before["mtu_invalidations"] + 1)
        # Installed since, which is what tells the readmitted directions from
        # the retired ones.
        reduced = await settled({TARGET_LAN_IF: 1500, TARGET_WAN_IF: 1400}, since=before)
        assert reduced["errors"] == before["errors"], reduced
        assert {f["out"]: f["detour"] for f in reduced["flows"]} == {
            TARGET_LAN_IF: "0", TARGET_WAN_IF: "1"}, reduced
        # The session survived the MTU change, so the flow came back describing
        # the same session rather than a different one.
        assert await _session_identity(r) == r.session_identity
        r.record("pppoe-mtu", {"before": before, "invalidated": invalidated,
                               "reduced": reduced})
    finally:
        await command(r.target, r.session, "ip", "link", "set", r.ppp_if,
                      "mtu", str(SESSION_MTU), check=False)


@pytest.mark.rfc("2516", section="5")
@pytest.mark.rfc("1661", section="5.8")
async def test_session_retires_and_redials(pppoe_rig):
    """The session going away retires the flow, and a redial readmits it.

    This is the dependency proof. The session is what the hardware inserts and
    strips, and nothing about it reaches the rule that could be revalidated
    later: the id is in an action the flow was built from once, and the
    concentrator's address is in no action at all. So hanging the session up
    has to retire the flow -- otherwise the hardware keeps inserting a session
    header the concentrator has already forgotten, and the frames vanish with
    every counter looking healthy.

    What notices is the route. pppd's peer route dies with the device, and the
    flow borrowed that destination, so the route watch retires its directions,
    normally before the device is even unregistered. Should the unregistration
    arrive while the entries are still being taken out, it retires them too
    rather than stopping admission: a ppp device is neither bound nor a port.
    That makes a session drop *selective*: the retirement costs
    the directions it should and nothing else, the bindings stay up, and
    admission is never disabled. A drop is therefore self-healing -- the table
    is not touched, nothing re-arms, and the next packet re-offers the flow
    against whatever session exists then, which is the assertion that matters
    and the one a stale entry would fail. Both directions are in hardware on
    either side of the redial, the upload through the offline-port detour, and
    the session they name is the one the download strips and the upload
    inserts.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    _assert_session(r, _direction(flows, r.lan_ip, INNER_LOCAL),
                    _direction(flows, INNER_LOCAL, r.lan_ip))
    assert all(d == 64 for d in delta.values()), delta
    before = await r.state()
    first = r.session_identity

    await _hangup(r.console)
    # The route is what goes first, so that is what the convergence waits on.
    retired = await r.wait(
        lambda s: not s["entries"] and
        s["route_invalidations"] >= before["route_invalidations"] + 1, timeout=30)
    # Selective, and that is the result: the table is untouched, so admission
    # was never disabled and nothing has to be rebuilt to get it back.
    assert retired["bindings"] == 2, retired
    assert retired["invalidated"] == 0 and retired["invalidation_done"] == 0, retired
    assert retired["rearms"] == before["rearms"], retired
    assert retired["handle_refs"] == retired["neighbour_refs"] == 0, retired
    assert retired["detour_flows"] == 0, retired
    assert retired["fatal"] == retired["quarantine"] == 0, retired
    assert retired["errors"] == before["errors"], retired
    # The device is gone, so /proc/net/pppoe has nothing left to describe.
    assert not (await read(r.target, r.session, "/proc/net/pppoe")).splitlines()[1:]

    # The redial's discovery and the session's keepalive, as the concentrator
    # sees them on the wire.
    pcap = ft.artifact_dir() / "pppoe-redial.pcap"
    ft.artifact_dir().mkdir(parents=True, exist_ok=True)
    dump = subprocess.Popen(["tcpdump", "-i", SERVER_IF, "-U", "-s", "96", "-w", str(pcap),
                             "pppoed or pppoes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    await asyncio.sleep(1.5)
    r.ppp_if, r.ppp_pid = await _dial(r.console, r.ppp_lower, ipv6=r.session_ipv6)
    await asyncio.sleep(2 * LCP_ECHO_INTERVAL + 1)
    dump.terminate()
    dump.wait(5)
    from scapy.all import PPPoED, PPP_LCP_Echo, rdpcap
    frames = rdpcap(str(pcap))
    # PADI, PADO, PADR, PADS in order (RFC 2516 §5), then an echo request
    # answered by a reply on the session (RFC 1661 §5.8).
    discovery = [p[PPPoED].code for p in frames if PPPoED in p]
    assert discovery[:4] == [0x09, 0x07, 0x19, 0x65], discovery
    echoes = {p[PPP_LCP_Echo].code for p in frames if PPP_LCP_Echo in p}
    assert echoes >= {9, 10}, echoes
    # The device went and took its routes with it; the concentrator still has
    # no other way back to the LAN.
    server_ppp_if = await _concentrator_if(r)
    for prefix in (r.reachable, f"{SNAT_ADDR}/32"):
        await command(r.wan, r.session, "ip", "route", "replace", prefix,
                      "dev", server_ppp_if)
    second = await _session_identity(r)
    r.session_identity = second
    # The path went down and came back, so let the bring-up settle before any
    # measurement rather than charging a lost first datagram to the adapter.
    await _wait_reachable(r)

    # Nothing re-offers a retired flow on its own, so each attempt sends before
    # it looks. What it does not need is the table: the retirement was
    # selective, so the bindings that were there before are the ones admitting
    # this flow again.
    for _ in range(10):
        await r.exchange(count=4)
        state = await r.state()
        if state["entries"] == 2:
            break
    else:
        pytest.fail(f"the flow was not readmitted after the redial: {state}")
    readmitted = await _udp_directions(r)
    # Against the session that exists now. A flow that had survived the hangup,
    # or been readmitted from anything cached, would name the old one -- which
    # is exactly the failure that forwards happily and delivers nothing.
    _assert_session(r, _direction(readmitted, r.lan_ip, INNER_LOCAL),
                    _direction(readmitted, INNER_LOCAL, r.lan_ip), session=second)
    after = await r.state()
    # Readmitted through the bindings that were never disturbed: no global
    # invalidation to clear, and nothing to re-arm.
    assert after["bindings"] == 2 and after["rearms"] == before["rearms"], after
    assert after["invalidated"] == after["invalidation_done"] == 0, after
    assert after["errors"] == before["errors"], after
    # And the readmitted flow forwards, measured the same way as any other.
    counts = {f["cookie"]: int(f["packets"]) for f in readmitted}
    await r.exchange(count=32)
    measured = await r.state()
    final = {f["cookie"]: int(f["packets"]) for f in measured["flows"]}
    _assert_undisturbed(r, after, measured, set(final) == set(counts))
    assert all(final[c] - counts[c] == 32 for c in counts), (counts, final)
    r.record("pppoe-redial", {"first": _session_text(first),
                              "second": _session_text(second),
                              "before": before, "retired": retired, "after": after})


@pytest.mark.parametrize("mode", ["6o4", "4o6"])
@pytest.mark.parametrize("pppoe_rig", ["ipv6"], indirect=True)
async def test_tunnel(pppoe_rig, mode):
    """A tunnel whose outer packets leave by the session: 6rd or a tunnel
    broker on a PPPoE WAN for 6o4, DS-Lite on one for 4o6.

    One direction is both encapsulations at once -- the tunnel's outer header,
    then the session's, then the tag the session runs over -- and the other
    arrives inside all three. The outer header is addressed to the far end of
    the tunnel, which is not the neighbour the frame is for: the concentrator
    is, and the only place its Ethernet address is recorded is the session.
    Frames that reach the concentrator's ppp device, where the capture sits,
    are ones its PPPoE stack took for this session, which is the proof that
    the frame was addressed to it.

    A UDP upload is Linux's -- an Ethernet LAN can deliver a full frame and
    the tunnel's path is smaller, and the offline-port detour takes no
    tunnel -- so over UDP the direction proved is the one
    that arrives inside all three, and the records are held by it alone. The
    upload that leaves inside all three is proved over TCP, which the uplink's
    MSS clamp keeps within the tunnel.
    """
    import _flowtable_tunnel as tunnel

    r = pppoe_rig
    shape = tunnel.Shape(mode, 48960, 48961)
    if mode == "6o4":
        shape.outer, shape.mtu = (INNER_REMOTE, INNER_LOCAL), SESSION_MTU - 20
    else:
        shape.outer, shape.mtu = (INNER_REMOTE6, INNER_LOCAL6), SESSION_MTU - 60
    r.shape = shape
    # The concentrator's ppp device is where the outer packets are plain IP.
    r.wan_if = r.server_ppp_if
    cleanup, lan_cleanup = [], []
    transport = None
    try:
        await tunnel._lan_side(r, cleanup, lan_cleanup)
        if shape.family == 4:
            for proto in ("udp", "tcp"):
                accept = ["POSTROUTING", "-s", r.lan_address, "-d", shape.inner_orch, "-p", proto,
                          "--sport", str(shape.sport), "--dport", str(shape.dport), "-j", "ACCEPT"]
                await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept)
                cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *accept]))
        await tunnel._dut_tunnel(r, cleanup)
        await tunnel._orchestrator_tunnel(r, cleanup)
        await tunnel._wait_reachable(r)
        await tunnel._clear_ct(r)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            tunnel.EchoServer, local_addr=(shape.inner_orch, shape.dport),
            family=socket.AF_INET6 if shape.family == 6 else socket.AF_INET)
        before = await r.state()
        flows, delta = await tunnel._established(r, name=f"pppoe-{mode}")
        forward, reverse = tunnel._directions(r, flows)
        tunnel._assert_tunnel(r, forward, reverse)
        _assert_session(r, forward, reverse)
        assert all(d == 64 for d in delta.values()), delta
        state = await r.state()
        # One tunnel record and the one session record, each held by every
        # direction of the one connection that is in hardware.
        row = _session_row(state, r.session_identity)
        assert row["refs"] == str(len(flows)), (row, flows)
        tunnels = [t for t in state["tunnels"] if t["dev"] == shape.device]
        assert len(tunnels) == 1 and tunnels[0]["refs"] == str(len(flows)), state["tunnels"]
        assert state["errors"] == before["errors"], (before, state)
        r.record(f"pppoe-tunnel-{mode}", {"flows": flows, "delta": delta, "session": row,
                                          "tunnel": tunnels[0]})

        # The upload inside all three, over TCP.
        await tunnel._offload_table(r, "tcp")

        def tcp(s):
            return [f for f in s["flows"] if f["proto"] == "6"]

        async with GatedTcp(r.run_peer, source=r.lan_address, sport=shape.sport,
                            peer=shape.inner_orch, dport=shape.dport,
                            label=f"flowtable_pppoe_{mode}_tcp") as transfer:
            await transfer.warmed()
            started = await r.wait(lambda s: len(tcp(s)) == 2)
            await transfer.measure()
            ended = await r.state()
        forward, reverse = tunnel._directions(r, tcp(started))
        assert forward is not None, tcp(started)
        tunnel._assert_tunnel(r, forward, reverse)
        _assert_session(r, forward, reverse)
        moved = {f["cookie"]: int(f["packets"]) for f in tcp(ended)}
        assert moved.keys() == {forward["cookie"], reverse["cookie"]}, ended
        upload = moved[forward["cookie"]] - int(forward["packets"])
        assert upload > 100, (upload, transfer.report)
        assert ended["errors"] == before["errors"], (before, ended)
        r.record(f"pppoe-tunnel-{mode}-tcp", {"flows": tcp(started), "ended": ended,
                                              "report": transfer.report})
    finally:
        if transport:
            transport.close()
        failures = []
        await command(r.target, r.session, "nft", "delete", "table", "inet", tunnel.TABLE,
                      check=False)
        if hasattr(r, "lan_address"):
            await tunnel._clear_ct(r)
        for agent, argv in reversed(cleanup):
            result = await command(agent, r.session, *argv, check=False)
            if result["rc"] and "Cannot find device" not in (result.get("stderr") or ""):
                failures.append(result)
        for cmd in reversed(lan_cleanup):
            await lan_run(r.lan, cmd)
        assert not failures, failures

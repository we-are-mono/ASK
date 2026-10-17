"""6o4 and 4o6 tunnel offload on the Linux flowtable: the outer IP header is
inserted and stripped in hardware.

A tunnel is an encapsulation the same shape as a PPPoE session, one layer up:
one direction of a connection leaves the DUT by the tunnel device and the
hardware has to prepend the outer header the kernel would, and the other
direction arrives inside that header on the physical WAN port and the
hardware has to strip it before it can match the inner tuple. Both halves are
asserted separately, because the ingress half is the one Netfilter describes
with nothing at all -- no pop action, no dissector key -- and is therefore the
half most likely to be silently refused.

Two things make a tunnel unlike a session. The kernel resolves the outer
route and its next hop when it walks the forwarding path, so the adapter
records what the kernel walked rather than deriving it, and every case here
asserts the adapter's record against the tunnel device's own configuration.
And the outer header is a real IP header with a TTL and a checksum, so the
routed cases capture the frames the hardware put on the wire and read those
fields back, which the counters alone cannot show. The outer header carries no
don't-fragment bit: the insert opcode fills the fragment field itself and
ignores the template's, exactly as the legacy owner met and hardcoded around,
so the tunnel's pmtudisc reaches the wire only for CPU-forwarded frames.

Shapes: `6o4` is IPv6 inside IPv4 (`sit`, proto 41), the tunnel-broker and
6rd shape; `4o6` is IPv4 inside IPv6 (`ipip6`, next header 4), the DS-Lite
shape. The outer endpoints are the DUT's WAN address and the orchestrator's;
the inner ones a /64 or a /24 that belongs to neither segment, so a routing
mistake cannot look like a working path.

A 4o6 UDP upload stays in Linux. It arrives on the LAN port, which can deliver
a full 1500-byte frame whatever MTU it is given, and the tunnel's path is
smaller: the microcode would have to fragment it, and the fragments it builds
from a frame an Ethernet port received carry no payload. So the 4o6 UDP cases
assert that refusal and the download half, and the 4o6 upload -- the insert
opcode -- is carried by TCP, which sets DF and is never the microcode's to
fragment.
"""
from __future__ import annotations

from _flowtable_tunnel import CHANGED_TTL

from _flowtable_tunnel import (MOVED_DEV, MOVED_GATEWAY, MOVED_MAC, Capture, _admit, _announce, _assert_marked, _assert_outer, _assert_tunnel, _both_directions, _carried, _change, _congested, _directions, _ecn_capable, _established, _expected, _insert_phases, _ip_checksum, _marking, _moved_host, _offload_table, _outer_neighbour, _retired, _stripped, _tunnel_counters, _tunnel_record, _tunnel_text, _udp_exchange, _undo)


import asyncio
import os
import subprocess

import pytest

from ask_orch.counters import kernel_tx_packets
from _flowtable_qos import (AF11_TOS, COUNT, EF_TOS, FLOW_LABEL, REMARK_CLASS, assert_remarked, remark_fields, remarking)
from _gated_tcp import GatedTcp
from _throughput import tcp_floor
from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from _flowtable_rig import assert_undisturbed, command

# Both modes ran at the path's ceiling on four streams: 6o4 9.15 Gb/s
# inserting and 9.14 stripping, 4o6 9.14 and 9.08 (docs/flowtable/tunnels.md).
MIN_RATE = float(os.environ.get("ASK_FLOWTABLE_TUNNEL_MIN_GBPS", "8.8")) * 1e9


# ---- cases ---------------------------------------------------------------

@pytest.mark.rfc("4213")
@pytest.mark.rfc("2473", section="4.1.1")
@pytest.mark.parametrize("tunnel_rig", ["6o4", "4o6"], indirect=True)
async def test_routed(tunnel_rig):
    """A routed UDP flow through the tunnel.

    The forward direction inserts the outer header and the reverse strips it;
    the adapter names the tunnel on exactly those two and on neither LAN half.
    The frames the DUT put on the wire carry the header the kernel would have
    built, and the tunnel device's counters moved by the burst although no
    packet of its hardware directions reached the CPU. A 4o6 upload is
    Linux's (see the module docstring), so there the strip is what is proved
    and the insert is test_tcp's.
    """
    r = tunnel_rig
    flows, delta = await _established(r)
    forward, reverse = _directions(r, flows)
    _assert_tunnel(r, forward, reverse)
    if r.shape.mode == "4o6":
        # The far end's ip6tnl sends a Tunnel Encapsulation Limit option
        # (RFC 2473 §4.1.1), so the strip counted below matched past it.
        detail = subprocess.run(["ip", "-d", "link", "show", r.shape.device],
                                capture_output=True, text=True, check=True).stdout
        assert "encaplimit 4" in detail, detail
    assert reverse["out_vlan"] == reverse["out_ppp"] == "-", reverse
    if forward:
        assert forward["in_vlan"] == forward["in_ppp"] == "-", forward
    assert all(d == 64 for d in delta.values()), delta


@pytest.mark.rfc("4213", section="3.2")
@pytest.mark.rfc("2473", section="7.1")
@pytest.mark.parametrize("tunnel_rig", ["6o4/mtu", "4o6/mtu"], indirect=True)
async def test_full_mtu(tunnel_rig):
    """A datagram that fills the tunnel's MTU is still carried in hardware.

    The microcode compares what it transmits against the programmed MTU, and
    what it transmits is the outer packet; a direction programmed with the
    tunnel-reduced inner MTU excepts every full-size frame to the CPU while
    every counter says the flow is offloaded. The payload here is exactly the
    inner MTU less its own headers. Only the strip carries it in hardware: a
    UDP insert into a tunnel smaller than a full frame is Linux's, which is
    what answers the oversized probe below. The full-size insert is proved by
    test_tcp, whose segments fill the tunnel.
    """
    r = tunnel_rig
    shape = r.shape
    payload = shape.mtu - (40 if shape.family == 6 else 20) - 8
    flows, delta = await _established(r, count=32, payload_size=payload, name="mtu")
    forward, reverse = _directions(r, flows)
    _assert_tunnel(r, forward, reverse)
    assert all(d == 32 for d in delta.values()), delta
    # One byte over, DF set: the entry point reports the tunnel's MTU back to
    # the sender rather than fragmenting or dropping it (RFC 4213 §3.2,
    # RFC 2473 §7.1), whatever MTU the LAN advertises.
    if shape.family == 6:
        probe = (f"IPv6(src={r.lan_address!r}, dst={shape.inner_orch!r})"
                 f"/UDP(sport={shape.sport}, dport={shape.dport})/Raw(b'x' * {payload + 1})")
        check = f"ICMPv6PacketTooBig in a and a[ICMPv6PacketTooBig].mtu == {shape.mtu}"
    else:
        probe = (f"IP(src={r.lan_address!r}, dst={shape.inner_orch!r}, flags='DF')"
                 f"/UDP(sport={shape.sport}, dport={shape.dport})/Raw(b'x' * {payload + 1})")
        check = f"ICMP in a and (a[ICMP].type, a[ICMP].code, a[ICMP].nexthopmtu) == (3, 4, {shape.mtu})"
    result = await lan_run_python(r.lan, f'''
from scapy.all import IP, IPv6, UDP, ICMP, ICMPv6PacketTooBig, Raw, sr1
a = sr1({probe}, timeout=3, verbose=False)
assert a is not None and {check}, a and a.show(dump=True)
''', label="flowtable_tunnel_ptb", timeout=30)
    assert result.rc == 0, result.stdout


@pytest.mark.parametrize("tunnel_rig", ["6o4/tcp", "4o6/tcp"], indirect=True)
async def test_tcp(tunnel_rig):
    """An established TCP connection through the tunnel.

    TCP is a classifier table of its own, so a UDP proof says nothing about
    it; and the classifier punts SYN, FIN and RST before its own lookup, so
    what the hardware carries is the bulk transfer in the middle. The cookies
    staying put proves the connection was never readmitted underneath it.

    It is also the large-segment insert. The far end advertises the MSS its
    tunnel allows, so every full data segment of the upload comes within its
    TCP options of the tunnel's MTU; a size check that counted the outer
    header against that MTU would except each one to Linux, which would then
    send it out of the WAN port itself. For 4o6 this is the only hardware
    insert there is, the UDP upload being Linux's.
    """
    r = tunnel_rig
    shape = r.shape
    await _offload_table(r, "tcp")

    async def run(script, **kwargs):
        return await lan_run_python(r.lan, script, **kwargs)

    # Read while the connection is open and idle (see _gated_tcp): a FIN
    # retires the entries within about a second of the peer closing.
    async with GatedTcp(run, source=r.lan_address, sport=shape.sport, peer=shape.inner_orch,
                        dport=shape.dport, label="flowtable_tunnel_tcp") as transfer:
        await transfer.warmed()
        # Admission is asynchronous, and an offer that lost rtnl_trylock comes
        # back only on a later packet; the warm phase runs long enough for that
        # (_gated_tcp.WARM_SECONDS). Wait admission in before reading the
        # baseline the record and the direction check share.
        before = await r.wait(lambda s: len(s["flows"]) == _expected(r, "tcp"))
        flows = await _both_directions(r, "tcp", before)
        record = _tunnel_record(r, before)
        link = await _tunnel_counters(r)
        sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF)
        # The outer headers of the hardware's own inserts, for 4o6 the only
        # ones there are (RFC 2473 §3).
        capture = Capture(r, "tcp")
        capture.snaplen = 128
        async with capture:
            await transfer.measure()
        sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF) - sent
        after = await r.state()
        record = {k: v - record[k] for k, v in _tunnel_record(r, after).items()}
        link = {k: v - link[k] for k, v in (await _tunnel_counters(r)).items()}
    forward, reverse = _directions(r, flows)
    r.record("tunnel-tcp", {"flows": flows, "after": after, "record": record, "link": link,
                            "software_wan_tx": sent, "report": transfer.report})
    _assert_tunnel(r, forward, reverse)
    _assert_outer(r, capture.packets(), 100)
    assert forward["proto"] == reverse["proto"] == "6", flows
    new = {f["cookie"]: f for f in after["flows"]}
    assert_undisturbed(r, before, after, new.keys() == {forward["cookie"], reverse["cookie"]}
                       and (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]),
                       label="tunnel-readmitted")
    upload = int(new[forward["cookie"]]["packets"]) - int(forward["packets"])
    download = int(new[reverse["cookie"]]["packets"]) - int(reverse["packets"])
    assert upload > 100 and download > 100, (upload, download)
    # The tunnel device's record counts the same frames the two entries did:
    # the insert's the upload's, the strip's the download's.
    assert (record["tx_packets"], record["rx_packets"]) == (upload, download), (record, upload, download)
    # And `ip -s link` on the device moved by the record restated into the
    # inner packets it counts itself -- the Ethernet and outer headers off what
    # the insert counted, the Ethernet header off what the strip did -- which
    # is the transmit fold of inserted frames that a UDP upload in Linux cannot
    # show, plus at most a few frames the device sent or took itself.
    for half, overhead in (("tx", 14 + shape.header), ("rx", 14)):
        stray = link[half] - record[half + "_packets"]
        assert 0 <= stray <= 8, (half, record, link)
        inner = record[half + "_bytes"] - overhead * record[half + "_packets"]
        assert inner <= link[half + "_bytes"] <= inner + stray * 1518, (half, record, link)
    # Only the handful of frames the reads above cost left the WAN port in
    # software while the measured phase crossed it.
    assert 0 <= sent < upload // 4, (sent, upload)


@pytest.mark.rfc("3168", section="5")
@pytest.mark.rfc("6437", section="2")
@pytest.mark.parametrize("tunnel_rig", ["6o4/remark", "4o6/remark"], indirect=True)
async def test_remark_rewrites_the_carried_header(qos, tunnel_rig):
    """A class that remarks to EF, on a connection through the tunnel,
    rewrites the header the tunnel carries -- the connection's own -- and
    nothing else in it, on either half of the path the hardware runs.

    The strip: this host answers each of the LAN VM's datagrams at AF11, the
    ECN field walking its four encodings and, inside IPv6, under a flow label
    of its own. The replies reach the LAN VM at EF and otherwise as they were
    sent, one hop fewer, while the classifier counted every one and Linux saw
    next to none of their outer packets: the hardware rewrote the header the
    strip had just exposed.

    The insert: a UDP upload into a tunnel smaller than a full frame is
    Linux's (_upload_refused()), so the requests of that exchange show the
    software path rewriting the carried header behind the outer one. The
    hardware's insert is TCP's. ECN is negotiated for the connection, so the
    LAN VM's data segments carry ECT(0) and its bare acknowledgements none;
    each has to leave inside the outer header the hardware built, at EF and
    with its own ECN codepoint.

    The remark bits lie outside the image's mask, so the adapter is reloaded
    with a wider one for the case (remarking()).
    """
    from scapy.all import TCP, UDP

    r, t = qos, tunnel_rig
    shape = t.shape
    v6 = shape.family == 6
    ip = "ip6" if v6 else "ip"
    label = FLOW_LABEL if v6 else None
    async with remarking(r) as mark:
        try:
            await _offload_table(t, match=f"{ip} saddr {t.lan_address} {ip} daddr {shape.inner_orch} "
                                          f"meta l4proto {{ tcp, udp }} ct mark set {mark:#x}")
            await _admit(t)
            strip, replies, requests, _ = await _stripped(t, AF11_TOS, f"remark-{shape.mode}")
            (phase,) = await _insert_phases(t, f"remark-{shape.mode}-tcp")
        finally:
            await t.delete_table()

    # The strip: every reply carried by the hardware, rewritten and nothing else.
    assert int(strip["qos"], 16) == REMARK_CLASS, strip
    assert_remarked("strip", replies, COUNT, label=label)
    # The software insert: each request's carried header rewritten likewise.
    carried = [_carried(t, p) for p in requests]
    assert_remarked("insert", [remark_fields(c) for c in carried if UDP in c], COUNT, label=label)
    # The hardware insert: the connection's class on both directions, and the
    # LAN VM's segments carried by its insert -- at EF, with their own ECN.
    assert {int(f["qos"], 16) for f in phase["rows"]} == {REMARK_CLASS}, phase["rows"]
    sent = [c for c in (_carried(t, p) for p in phase["packets"])
            if TCP in c and c[TCP].sport == shape.sport]
    sequences, data = set(), 0
    for c in sent:
        tos = c.tc if v6 else c.tos
        assert tos >> 2 == EF_TOS >> 2 and c[TCP].dport == shape.dport, c.summary()
        assert v6 or _ip_checksum(bytes(c)[:c.ihl * 4]) == 0, c.summary()
        if not len(c[TCP].payload):
            assert tos & 3 == 0, ("a bare acknowledgement carries no ECN", c.summary())
            continue
        # A retransmission is sent without ECT; the original carried it.
        if c[TCP].seq not in sequences:
            assert tos & 3 == 2, ("a data segment lost its ECT(0)", c.summary())
            data += 1
        sequences.add(c[TCP].seq)
    # Short of the rows' count: this host may coalesce the segments it
    # receives before the capture sees them.
    assert data, [c.summary() for c in sent[:8]]


# The fixed markings a case configures and then moves to under a live
# connection: AF11 then AF41 in the TOS byte, and for 4o6 a flow label each.
# The second is configured with an ECN bit set, which Linux's encapsulation
# replaces with the carried packet's ECN field, so the insert has to as well.
MARKINGS = {"6o4": ((0x28, None), (0x8a, None)), "4o6": ((0x28, 0x12345), (0x8a, 0x54321))}
AF21_TOS = 18 << 2


def _marking_options(mode, tos, label):
    if mode == "6o4":
        return ["tos", f"{tos:#x}"]
    return ["tclass", f"{tos:#x}", "flowlabel", f"{label:#x}"]


@pytest.mark.rfc("2983", section="3")
@pytest.mark.rfc("6040", section="4.1")
@pytest.mark.rfc("6437", section="2")
@pytest.mark.parametrize("tunnel_rig", ["6o4/marking", "4o6/marking"], indirect=True)
async def test_fixed_marking(tunnel_rig):
    """The outer header the hardware inserts carries the marking the tunnel
    is configured with -- a sit tunnel's `tos`, an ip6_tnl tunnel's `tclass`
    and `flowlabel` -- and a change to it under a live connection reaches the
    wire.

    Beside the configured codepoint the outer ECN field is the carried
    packet's, as Linux's encapsulation copies it (RFC 6040 §4.1, CE leaving
    as ECT(0)), whatever ECN bits the configured marking itself sets. Linux's own outer headers are the reference: a UDP upload
    into the tunnel is Linux's (_upload_refused()), and the requests of an
    exchange walking all four ECN encodings show the configured marking and
    the copy. The hardware's insert is TCP's: the LAN VM's connection
    negotiates ECN, so its data segments carry ECT(0) and its bare
    acknowledgements none, and every outer header the insert builds has to
    carry the marking with the matching ECN field.

    `ip tunnel change` then moves the marking under the connection. The
    adapter retires every flow through the device, the connection is
    readmitted, and its next phase leaves with the new marking.
    """
    r = tunnel_rig
    shape = r.shape
    ip = "ip6" if shape.family == 6 else "ip"
    first, second = MARKINGS[shape.mode]
    await _change(r.target, r, *_marking_options(shape.mode, *first))
    await _offload_table(r, match=f"{ip} saddr {r.lan_address} {ip} daddr {shape.inner_orch} "
                                  f"meta l4proto {{ tcp, udp }}")
    await _admit(r)
    _, _, requests, _ = await _stripped(r, AF11_TOS, f"marking-{shape.mode}")
    phases = await _insert_phases(
        r, f"marking-{shape.mode}-tcp",
        (None, lambda: _change(r.target, r, *_marking_options(shape.mode, *second))))
    # Linux's insert: the configured marking and every ECN encoding copied,
    # CE as ECT(0).
    assert _assert_marked(r, requests, first[0] >> 2, first[1], "udp").keys() == {0, 1, 2}
    # The hardware's, before and after the change.
    for phase, (tos, label) in zip(phases, (first, second)):
        assert _assert_marked(r, phase["packets"], tos >> 2, label, "tcp").keys() == {0, 2}


@pytest.mark.rfc("2983", section="3")
@pytest.mark.parametrize("tunnel_rig", ["6o4/inherit", "4o6/inherit"], indirect=True)
async def test_inherited_traffic_class(tunnel_rig):
    """A tunnel told to inherit the carried packet's codepoint.

    An ip6_tnl tunnel's `tclass inherit` has a microcode flag of its own, and
    the hardware's insert follows it: the LAN VM's connection leaves at AF21,
    and every outer header the insert builds carries AF21 beside the carried
    ECN field. A sit tunnel's `tos inherit` has none, so its flows are
    declined, and Linux carries the connection and inherits the codepoint
    itself.
    """
    r = tunnel_rig
    shape = r.shape
    await _change(r.target, r, "tclass" if shape.mode == "4o6" else "tos", "inherit")
    await _offload_table(r, "tcp")
    if shape.mode == "4o6":
        (phase,) = await _insert_phases(r, "inherit-4o6", tos=AF21_TOS)
        assert {_marking(r, p)["inner_dscp"] for p in phase["packets"]} == {AF21_TOS >> 2}
        assert _assert_marked(r, phase["packets"], None, None, "tcp").keys() == {0, 2}
        return

    async def run(script, **kwargs):
        return await lan_run_python(r.lan, script, **kwargs)

    async with _ecn_capable(r.lan), GatedTcp(
            run, source=r.lan_address, sport=shape.sport, peer=shape.inner_orch,
            dport=shape.dport, label="flowtable_tunnel_inherit", tos=AF21_TOS) as transfer:
        await transfer.warmed()
        capture = Capture(r, "inherit-6o4")
        capture.snaplen = 128
        async with capture:
            await transfer.measure()
        state = await r.state()
    r.record("tunnel-inherit-6o4", state)
    assert not [f for f in state["flows"] if f["proto"] == "6"], state
    packets = capture.packets()
    assert {_marking(r, p)["inner_dscp"] for p in packets} == {AF21_TOS >> 2}
    assert _assert_marked(r, packets, None, None, "tcp").keys() == {0, 2}


@pytest.mark.rfc("2983", section="3")
@pytest.mark.parametrize("tunnel_rig", ["6o4/copy", "4o6/copy"], indirect=True)
async def test_outer_codepoint_on_receive(tunnel_rig):
    """The far end marks every outer header AF21 while the replies inside it
    leave at zero, each with an ECN encoding of its own. The hardware's strip
    removes the outer codepoint with the outer header: the replies reach the
    LAN VM at zero with their own ECN field.

    An ip6_tnl tunnel can be told otherwise: `dscp inherit` copies the outer
    codepoint into the carried header and nothing more, so a CE reply, whose
    outer header the far end sent at ECT(0), still arrives CE (RFC 6040
    §4.2). The strip's own copy adds the whole outer traffic class instead,
    ECN bits and all, so the adapter leaves that strip to Linux: turned on
    under the live flow, the setting retires it, every offer afterwards is
    declined, and the replies arrive copied as Linux copies them.
    """
    r = tunnel_rig
    shape = r.shape
    label = FLOW_LABEL if shape.family == 6 else None

    def sent_as_described(frames):
        # The far end's outer headers: AF21, beside each reply's own ECN
        # field as Linux encapsulates it, a CE reply's at ECT(0).
        markings = [_marking(r, p) for p in frames]
        assert len(markings) == COUNT, len(markings)
        for m in markings:
            assert (m["dscp"], m["ecn"]) == (AF21_TOS >> 2, 2 if m["inner_ecn"] == 3
                                             else m["inner_ecn"]), m
        assert {m["inner_ecn"] for m in markings} == {0, 1, 2, 3}, markings[:4]

    await _change(r.wan, r, "tclass" if shape.mode == "4o6" else "tos", f"{AF21_TOS:#x}")
    await _offload_table(r)
    await _admit(r)
    _, replies, _, sent = await _stripped(r, 0, f"copy-{shape.mode}")
    sent_as_described(sent)
    assert_remarked("strip", replies, COUNT, tos=0, label=label)
    if shape.mode == "6o4":
        return
    await _retired(r, await r.state(), lambda: _change(r.target, r, "dscp", "inherit"))
    _, replies, _, sent = await _stripped(r, 0, "copy-4o6-inherit", hardware=False)
    sent_as_described(sent)
    assert_remarked("strip, copied", replies, COUNT, tos=AF21_TOS, label=label)


@pytest.mark.rfc("6040", section="4.2")
@pytest.mark.parametrize("tunnel_rig", ["6o4/ce", "4o6/ce"], indirect=True)
async def test_outer_ce_on_receive(tunnel_rig):
    """Replies whose outer header arrives CE, as a congested router inside the
    tunnel marks it, are Linux's to receive: an ECT carried packet leaves CE
    and a Not-ECT one is dropped (RFC 6040 §4.2), which the hardware's strip
    cannot do -- it removed the outer header, mark and all (A372).

    The soft parser hands such a frame to the CPU before the strip entry is
    searched. So the replies sent ECT(0), ECT(1) or CE reach the LAN VM CE, each
    Not-ECT one is a frame error on the DUT's tunnel and never arrives, Linux
    sees every outer packet, and the strip counts none of them. With the mark
    gone, the same strip carries the next replies again."""
    r = tunnel_rig
    shape = r.shape
    count = 64
    await _offload_table(r)
    await _admit(r)
    answered, sent, moved = await _congested(r, count, f"ce-{shape.mode}")
    markings = [_marking(r, p) for p in sent]
    assert len(markings) == count and {m["ecn"] for m in markings} == {3}, markings[:4]
    assert {m["inner_ecn"] for m in markings} == {0, 1, 2, 3}, markings[:4]
    received = {f["n"]: f["tos"] & 3 for f in answered["fields"]}
    assert sorted(received) == [n for n in range(count) if n % 4], received
    assert set(received.values()) == {3}, received
    assert answered["lost"] == count // 4 and not any(answered["errors"].values()), answered
    assert moved["frame_errors"] == count // 4, moved
    assert moved["strip"] == 0 and moved["record"]["rx_packets"] == 0, moved
    assert moved["outer_seen"] >= count, moved
    _, replies, _, _ = await _stripped(r, 0, f"ce-after-{shape.mode}")
    assert {f["tos"] & 3 for f in replies} == {0, 1, 2, 3}, replies[:4]


@pytest.mark.parametrize("tunnel_rig", ["4o6/inherit"], indirect=True)
async def test_inherited_traffic_class_after_remark(qos, tunnel_rig):
    """A remark class on a connection through a `tclass inherit` tunnel: the
    hardware rewrites the carried header first and builds the outer header
    from it, so both leave at EF."""
    r, t = qos, tunnel_rig
    shape = t.shape
    await _change(t.target, t, "tclass", "inherit")
    async with remarking(r) as mark:
        try:
            await _offload_table(t, match=f"{shape.match(t.lan_address, 'tcp')} "
                                          f"ct mark set {mark:#x}")
            (phase,) = await _insert_phases(t, "inherit-remark-4o6", tos=AF21_TOS)
        finally:
            await t.delete_table()
    assert {_marking(t, p)["inner_dscp"] for p in phase["packets"]} == {EF_TOS >> 2}
    assert _assert_marked(t, phase["packets"], None, None, "tcp").keys() == {0, 2}


@pytest.mark.parametrize("upload", [True, False], ids=["insert", "strip"])
@pytest.mark.parametrize("tunnel_rig", ["6o4/rate", "4o6/rate"], indirect=True)
async def test_rate(tunnel_rig, upload):
    """TCP through the tunnel at the path's ceiling, inserting the outer
    header on the upload and stripping it on the download, every stream and
    its acknowledgements on a hardware entry while the rate is measured
    (_throughput)."""
    r = tunnel_rig
    shape = r.shape
    ip = "ip6" if shape.family == 6 else "ip"
    # The fixture exempts only its fixed port pair from the image's
    # masquerade; iperf3's streams take their own source ports.
    accept = ["POSTROUTING", "-s", r.lan_address, "-d", shape.inner_orch, "-p", "tcp",
              "--dport", str(shape.dport), "-j", "ACCEPT"]
    if shape.family == 4:
        await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept)
    hop = _tunnel_text(shape)

    def through_tunnel(data, acks):
        # Inserted on the way out of the LAN port, stripped on the way in
        # from the WAN port, for the data and its acknowledgements alike.
        for row in data + acks:
            side = row["out_tnl"] if row["in"] == TARGET_LAN_IF else row["in_tnl"]
            assert side == hop, (hop, row)

    try:
        await _offload_table(r, match=f"{ip} saddr {r.lan_address} tcp dport {shape.dport}")
        await tcp_floor(r, server=shape.inner_orch, client=r.lan_address, port=shape.dport,
                        upload=upload, floor=MIN_RATE, family=shape.family, check=through_tunnel,
                        label=f"tunnel-rate-{shape.mode}-{'insert' if upload else 'strip'}")
    finally:
        await r.delete_table()
        await command(r.target, r.session, "conntrack", "-D", "-p", "tcp",
                      "--orig-src", r.lan_address, "--orig-dst", shape.inner_orch,
                      "--dport", str(shape.dport), check=False)
        if shape.family == 4:
            await command(r.target, r.session, "iptables", "-t", "nat", "-D", *accept)


async def _follows(r, label, move, back, counter):
    """One TCP connection through the tunnel, measured in hardware three
    times: on the WAN host's own MAC, after `move()` points the outer path at
    MOVED_MAC, and after `back()` returns it. Each move must retire the
    generation it found -- its cookies gone, `counter` up -- and the next must
    come back by itself on the same connection, its inserted outer frames
    leaving for the new MAC.

    The outer path is a dependency of the inserting direction alone, in the
    outer header's family rather than the flow's: nothing the flow borrows
    watches it. The stripping direction goes with it, sharing the flow's
    handle."""
    from scapy.all import Ether
    shape = r.shape
    await _offload_table(r, "tcp")

    async def run(script, **kwargs):
        return await lan_run_python(r.lan, script, **kwargs)

    def cookies(state):
        return {f["cookie"] for f in state["flows"]}

    # A retired flow is re-added by its next packet only once Netfilter's
    # garbage collection, a second or so later, has finished tearing the old
    # one down, and an admission that loses RTNL is offered again a second
    # after that. The phase that readmits runs for several seconds of both.
    readmit = 1024
    records = {}
    async with GatedTcp(run, source=r.lan_address, sport=shape.sport, peer=shape.inner_orch,
                        dport=shape.dport, label=f"flowtable_tunnel_{label}",
                        more=(readmit, 128, readmit, 128)) as transfer:
        await transfer.warmed()
        state = await r.wait(lambda s: len(s["flows"]) == _expected(r, "tcp"))
        for name, change, mac in (("own", None, r.wan_mac), ("moved", move, MOVED_MAC),
                                  ("back", back, r.wan_mac)):
            if change:
                old, counted = cookies(state), state[counter]
                await change()
                retired = await r.wait(lambda s: not old & cookies(s) and s[counter] > counted)
                assert retired["invalidated"] == 0 and retired["bindings"] == 2, retired
                # The next phase is what offers the connection again.
                await transfer.measure()
                state = await r.wait(lambda s: len(s["flows"]) == _expected(r, "tcp")
                                     and not old & cookies(s))
            before = await r.state()
            flows = await _both_directions(r, "tcp", before)
            forward, reverse = _directions(r, flows)
            _assert_tunnel(r, forward, reverse)
            sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF)
            capture = Capture(r, f"{label}-{name}")
            capture.snaplen = 128
            async with capture:
                await transfer.measure()
            sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF) - sent
            state = after = await r.state()
            new = {f["cookie"]: f for f in after["flows"]}
            kept = {forward["cookie"], reverse["cookie"]} <= new.keys()
            upload = int(new[forward["cookie"]]["packets"]) - int(forward["packets"]) if kept else 0
            download = int(new[reverse["cookie"]]["packets"]) - int(reverse["packets"]) if kept else 0
            packets = capture.packets()
            destinations = {p[Ether].dst for p in packets}
            records[name] = {"before": before, "after": after, "upload": upload, "download": download,
                             "software_wan_tx": sent, "outer_destinations": sorted(destinations),
                             "outer_neighbour": await _outer_neighbour(r)}
            r.record(f"tunnel-{label}", records)
            assert kept, ("readmitted mid-phase", name)
            assert upload > 100 and download > 100, records[name]
            assert 0 <= sent < upload // 4, records[name]
            _assert_outer(r, packets, 100)
            assert destinations == {mac}, (name, mac, destinations)
    # One connection throughout: the far end accepted no other, and the peer's
    # one socket would have failed on a reset.
    assert transfer.connections == 1, transfer.connections
    return records


@pytest.mark.parametrize("tunnel_rig", ["6o4/neighbour", "4o6/neighbour"], indirect=True)
async def test_outer_neighbour_moves(tunnel_rig):
    """The WAN host's outer endpoint moves to another MAC and says so -- a
    gratuitous ARP for 6o4's IPv4 outer header, an overriding Neighbor
    Advertisement for 4o6's IPv6 one -- and later moves back. The DUT's
    learned outer neighbour follows each time, the tunnel's established TCP
    connection is retired from hardware and readmitted on the same
    connection, and its inserted outer frames go to the MAC announced."""
    r = tunnel_rig
    shape = r.shape
    family = ["-6"] if shape.outer_family == 6 else []
    pinned = ["ip", *family, "neigh", "replace", shape.outer[1], "lladdr", r.wan_mac,
              "nud", "permanent", "dev", TARGET_WAN_IF]
    cleanup = []
    try:
        await _moved_host(r, cleanup)
        if shape.outer_family == 4:
            # This host would otherwise refresh its own entry for the DUT
            # with an ARP request from its usual MAC, and an ARP request
            # teaches its receiver the sender's MAC: the DUT would learn the
            # old one back. 4o6's entry is pinned by the fixture.
            await command(r.wan, r.session, "ip", "neigh", "replace", shape.outer[0], "lladdr",
                          r.dut_wan_mac, "nud", "permanent", "dev", r.wan_if)
            cleanup.append((r.wan, ["ip", "neigh", "replace", shape.outer[0], "lladdr", r.dut_wan_mac,
                                    "nud", "stale", "dev", r.wan_if]))
        # Learned rather than pinned: only a learned entry follows an
        # announcement.
        await command(r.target, r.session, "ip", *family, "neigh", "replace", shape.outer[1],
                      "lladdr", r.wan_mac, "nud", "reachable", "dev", TARGET_WAN_IF)
        cleanup.append((r.target, pinned))

        def announcing(mac, device):
            async def change():
                _announce(r, mac, device)
                for _ in range(20):
                    if (await _outer_neighbour(r)).get("lladdr") == mac:
                        return
                    await asyncio.sleep(0.25)
                pytest.fail(f"the DUT's outer neighbour never took {mac}: {await _outer_neighbour(r)}")
            return change

        await _follows(r, "outer-neighbour", announcing(MOVED_MAC, MOVED_DEV),
                       announcing(r.wan_mac, r.wan_if), "neighbour_invalidations")
    finally:
        await _undo(r, cleanup)


@pytest.mark.parametrize("tunnel_rig", ["6o4/route", "4o6/route"], indirect=True)
async def test_outer_route_moves(tunnel_rig):
    """The DUT's route to the WAN host's outer endpoint is replaced by one
    through a gateway at another MAC, and later removed, which returns the
    endpoint to its on-link route. The route watch matches the outer
    destination in the outer header's family, the tunnel's established TCP
    connection is retired and readmitted on the same connection, and its
    inserted outer frames go to whichever next hop the route names."""
    r = tunnel_rig
    shape = r.shape
    family = ["-6"] if shape.outer_family == 6 else []
    gateway = MOVED_GATEWAY[shape.mode]
    host = f"{shape.outer[1]}/{128 if shape.outer_family == 6 else 32}"
    cleanup = []
    unroute = (r.target, ["ip", *family, "route", "del", host, "dev", TARGET_WAN_IF])
    try:
        await _moved_host(r, cleanup)
        await command(r.target, r.session, "ip", *family, "neigh", "replace", gateway, "lladdr",
                      MOVED_MAC, "nud", "permanent", "dev", TARGET_WAN_IF)
        cleanup.append((r.target, ["ip", *family, "neigh", "del", gateway, "dev", TARGET_WAN_IF]))

        async def through_gateway():
            cleanup.append(unroute)
            await command(r.target, r.session, "ip", *family, "route", "replace", host, "via", gateway,
                          "dev", TARGET_WAN_IF, *([] if family else ["onlink"]))

        async def on_link():
            await command(r.target, r.session, *unroute[1])
            cleanup.remove(unroute)

        await _follows(r, "outer-route", through_gateway, on_link, "route_invalidations")
    finally:
        await _undo(r, cleanup)


@pytest.mark.parametrize("tunnel_rig", ["6o4/change"], indirect=True)
async def test_change_retires(tunnel_rig):
    """Reconfiguring the tunnel under a live flow retires it, and the flow
    readmitted afterwards carries the new outer header.

    `ip tunnel change` rewrites the device's parameters in place and raises
    only NETDEV_CHANGE, on a device that is always running with carrier. A
    flow admitted against the old parameters would otherwise keep sending the
    old header from hardware while software sent the new one. The TTL is what
    changes here because it is visible on the wire.
    """
    r = tunnel_rig
    flows, _ = await _established(r)
    before = await r.state()
    await command(r.target, r.session, "ip", "tunnel", "change", r.shape.device,
                  "ttl", str(CHANGED_TTL))
    retired = await r.wait(lambda s: s["entries"] == 0)
    assert retired["bindings"] == 2, retired
    assert retired["link_invalidations"] > before["link_invalidations"], (before, retired)
    # Readmitted against the new configuration, and the wire says so.
    flows = await _admit(r)
    forward, reverse = _directions(r, flows)
    _assert_tunnel(r, forward, reverse)
    async with Capture(r, "change") as capture:
        report = await _udp_exchange(r, 32)
    assert report == {"echoed": 32, "lost": 0}, report
    _assert_outer(r, capture.packets(), 32, ttl=CHANGED_TTL)
    r.record("tunnel-change", {"before": before, "retired": retired, "flows": flows})


@pytest.mark.parametrize("tunnel_rig", ["6o4/delete"], indirect=True)
async def test_delete_retires(tunnel_rig):
    """Deleting the tunnel device retires both directions and leaves the
    bindings up: the ports are untouched, admission stays open, and the next
    flow is judged against whatever tunnel exists then."""
    r = tunnel_rig
    flows, _ = await _established(r)
    assert len(flows) == _expected(r), flows
    before = await r.state()
    await command(r.target, r.session, "ip", "link", "del", r.shape.device)
    retired = await r.wait(lambda s: s["entries"] == 0)
    assert retired["bindings"] == 2 and retired["invalidated"] == 0, retired
    assert retired["rearms"] == before["rearms"], (before, retired)
    r.record("tunnel-delete", {"before": before, "retired": retired})

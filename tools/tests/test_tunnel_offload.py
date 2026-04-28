"""Tunnel data-plane: 6o4 (IPv6-in-IPv4) decap from WAN to LAN.

The full ASK tunnel-offload workflow is a three-FCI-command sequence
per active tunnel:

  1. CMD_TNL_CREATE        — register the tunnel iface (mode, local,
                             remote, output_device).
  2. CMD_IP_ROUTE          — add a forward route (egress=eth4, dst MAC
                             = LAN VM MAC) AND a tunnel route
                             (output_device=tunnel iface,
                             flags=RTCMD_FLAGS_6o4, daddr=remote).
  3. CMD_IPV4_CONNTRACK    — add CtExCommand entry keyed on the OUTER
                             5-tuple (src=peer, dst=DUT_WAN, proto=41)
                             with format=CT_ORIG_TUNNEL and
                             tunnel_route_id pointing at the tunnel
                             route. THIS step installs the per-tunnel
                             ehash entry in cdx_6o4_cc whose action
                             chain calls create_tunnel_remove_hm()
                             (cdx/cdx_ehash.c:2345) — the FMAN ucode
                             v210.10.1 REMOVE_FIRST_IP_HDR opcode that
                             actually decaps.

Steps 1 and 3 alone don't engage the data plane: the PCD distribution
classifies the outer frame into cdx_6o4_cc, but with no entry there
FMAN misses → kg-direct-scheme miss action → kernel exception path.
The CT-add is what populates the table.

Inner-frame routing reuses the ipv6_topology fixture (DUT eth4 =
fc00:dead::1/64, LAN VM enp4s0 = fc00:dead::2/64). After REMOVE_FIRST_
IP_HDR, FMAN re-classifies the now-naked IPv6 frame; v6 forwarding on
the DUT then sends it out eth4 to the LAN VM.

Two oracles, both required:

  (i) Inner-frame arrival: tcpdump on the LAN VM captures the post-
      decap IPv6/UDP frame within a 2s window. count==1 discriminates
      between drop (0 — decap broken or routing missing), correct
      handling (1), and unexpected duplication (>=2).

  (ii) Offload engagement: counter-signature tripwire over per-FQ
      frame counters (Agent.counters() → fqid_stats/*/frame_count).
      Records which FQs tick — most importantly the cdx_6o4_dist FQ
      base (0x10f0). On first run with ASK_REGEN_GOLDEN=1 the
      observed deltas seed golden/tunnel_6o4_offload.json; subsequent
      runs assert byte-equality.

Reverse direction (LAN→WAN encap) is out of scope for this commit.

Orchestrator prerequisites:
  - br0 (or ASK_WAN_INJECT_IF) sits on the WAN /24 — the orchestrator
    has 10.0.0.141/24 on br0 by default; scapy L3 send() ARPs the
    DUT's eth3 unicast MAC.
"""

from __future__ import annotations

import asyncio
import os
import struct

import pytest
import pytest_asyncio

from _topology import (
    counter_signature,
    assert_counter_signature,
    golden_for,
    ipv6_topology,  # noqa: F401  (fixture, imported for resolution)
)


CMD_TNL_CREATE       = 0x0B01
CMD_TNL_DELETE       = 0x0B02
CMD_IP_ROUTE         = 0x0313
CMD_IPV4_CONNTRACK   = 0x0314

# Action codes (cdx/fe.h:38-43)
ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1

# CtExCommand format flags (cdx/fe.h:499-500)
CT_ORIG_TUNNEL = 1 << 1
CT_REPL_TUNNEL = 1 << 2

# CtCommand flags (cdx/fe.h:301-302)
CTCMD_FLAGS_ORIG_DISABLED = 1 << 0
CTCMD_FLAGS_REP_DISABLED  = 1 << 1

# RtCommand flags (cdx/fe.h:354-355)
RTCMD_FLAGS_6o4 = 1 << 0
RTCMD_FLAGS_4o6 = 1 << 1

NO_ERR              = 0
TNL_MODE_6O4        = 1
PROTOCOL_IPV6_IN_IP = 41   # IPPROTO_IPV6 — outer-IPv4 carries IPv6

TNL_NAME      = b"otunoffl"  # 8 chars, fits in 16-byte name field
TNL_OUTPUT_IF = os.environ.get("ASK_TARGET_WAN_IF", "eth3").encode()

DUT_WAN_IPV4 = os.environ.get("ASK_TARGET_IP",     "10.0.0.62")
WAN_PEER_IP  = os.environ.get("ASK_WAN_IPERF_IP",  "10.0.0.141")
WAN_INJECT_IF = os.environ.get("ASK_WAN_INJECT_IF", "br0")
LAN_NIC       = os.environ.get("ASK_LAN_NIC",       "enp4s0")

# DUT-side iface MACs and the LAN VM's NIC MAC. Used to populate the
# RtCommand.macAddr field on the forward route. Defaults match the
# primary dev site (loki LAN VM behind 10.0.0.62 DUT); override per
# deployment.
DUT_ETH3_MAC = os.environ.get("ASK_TARGET_WAN_MAC", "e8:f6:d7:00:01:13")
DUT_ETH4_MAC = os.environ.get("ASK_TARGET_LAN_MAC", "e8:f6:d7:00:01:14")
LAN_NIC_MAC  = os.environ.get("ASK_LAN_NIC_MAC",    "64:9d:99:b2:33:02")

# Route IDs. RouteEntry.id is U16 in the kernel ([cdx/layer2.h:56]) —
# values >0xFFFF are silently truncated on store but compared as U32 in
# lookup, so they can be added but never found. Stay below 0x10000.
# 0x6041/0x6042 echo the "6o4" mode visually without colliding with the
# small-int ids CMM tends to allocate from the bottom of the U16 range.
TUNNEL_FORWARD_ROUTE_ID = 0x6041
TUNNEL_DECAP_ROUTE_ID   = 0x6042

# Tunnel-injected inner UDP carries this port so the LAN-side BPF
# filter is tight against background v6 chatter.
TUNNEL_INNER_PORT = int(os.environ.get("ASK_TUNNEL_INNER_PORT", "47210"))

# Inner-frame source: any v6 address routable from the test peer.
# fc00:beef::99 is the Phase 2 ASK_WAN_IPV6 default — already documented
# as living in the WAN /64; reusing it keeps the conventions aligned.
TUNNEL_INNER_SRC = os.environ.get("ASK_WAN_IPV6", "fc00:beef::99")


def _ip_be_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def _pack_rt_command(
    *,
    action: int,
    output_device: bytes,
    input_device: bytes = b"",
    underlying_input_device: bytes = b"",
    route_id: int,
    flags: int = 0,
    mac: bytes = b"\x00" * 6,
    daddr_v4: str | None = None,
    daddr_v6_bytes: bytes | None = None,
    mtu: int = 1500,
    egress_vid: int = 0,
    underlying_vid: int = 0,
) -> bytes:
    """Pack RtCommand (cdx/fe.h:364-380) — 88 bytes when VLAN_FILTER is
    defined (which it is for ASK cdx — see cdx/Kbuild:7).

    Layout:
      0   action(2) mtu(2) macAddr(6) egress_vid(2) underlying_vid(2)
      14  pad(2) outputDevice(16) inputDevice(16) UnderlyingInputDevice(16)
      66  id(4) flags(4) daddr[4](16)
    """
    if daddr_v4 is not None:
        daddr_field = _ip_be_bytes(daddr_v4) + b"\x00" * 12
    elif daddr_v6_bytes is not None:
        assert len(daddr_v6_bytes) == 16
        daddr_field = daddr_v6_bytes
    else:
        daddr_field = b"\x00" * 16

    out_dev = output_device.ljust(16, b"\x00")[:16]
    in_dev  = input_device.ljust(16, b"\x00")[:16]
    uin_dev = underlying_input_device.ljust(16, b"\x00")[:16]

    wire = (
        struct.pack("<HH", action, mtu)               # 4
        + mac.ljust(6, b"\x00")[:6]                   # +6 = 10
        + struct.pack("<HH", egress_vid, underlying_vid)  # +4 = 14
        + struct.pack("<H", 0)                        # +2 pad = 16
        + out_dev                                     # +16 = 32
        + in_dev                                      # +16 = 48
        + uin_dev                                     # +16 = 64
        + struct.pack("<II", route_id, flags)         # +8 = 72
        + daddr_field                                 # +16 = 88
    )
    assert len(wire) == 88, f"RtCommand wire size {len(wire)} != 88"
    return wire


def _pack_ctex_command_v4(
    *,
    action: int,
    saddr: str, daddr: str, sport: int, dport: int,
    saddr_reply: str, daddr_reply: str, sport_reply: int, dport_reply: int,
    protocol: int,
    flags: int,
    format_field: int,
    qosconnmark: int = 0,
    route_id: int = 0,
    route_id_reply: int = 0,
    sa_dir: int = 0, sa_nr: int = 0, sa_handle: tuple = (0, 0, 0, 0),
    sa_dir_reply: int = 0, sa_nr_reply: int = 0,
    sa_handle_reply: tuple = (0, 0, 0, 0),
    tunnel_route_id: int = 0,
    tunnel_route_id_reply: int = 0,
) -> bytes:
    """Pack CtExCommand (cdx/fe.h:325-352) — 80 bytes total.

    IPv4 fields are passed as dotted strings; on-disk bytes match the
    on-wire NBO IPv4 layout (4 raw bytes, no host-endian U32 swap).
    The kernel side handles these as opaque U32s — what matters is
    that FMAN's classifier extracts the same byte sequence from the
    incoming frame.

    Field order with offsets:
      0   action(2) format(2) saddr(4) daddr(4)
      12  sport(2) dport(2) saddrR(4) daddrR(4)
      24  sportR(2) dportR(2) protocol(2) flags(2)
      32  qosconnmark(8) route_id(4) route_idR(4)
      48  SA_dir(1) SA_nr(1) SA_handle[4](8) SAReply_dir(1) SAReply_nr(1)
          SAReply_handle[4](8)
      72  tunnel_route_id(4) tunnel_route_idR(4)
    """
    head = (
        struct.pack("<HH", action, format_field)
        + _ip_be_bytes(saddr) + _ip_be_bytes(daddr)
        + struct.pack("<HH", sport, dport)
        + _ip_be_bytes(saddr_reply) + _ip_be_bytes(daddr_reply)
        + struct.pack(
            "<HHHHQII",
            sport_reply, dport_reply,
            protocol, flags,
            qosconnmark,
            route_id, route_id_reply,
        )
    )
    sa_block = struct.pack(
        "<BB4HBB4HII",
        sa_dir, sa_nr, *sa_handle,
        sa_dir_reply, sa_nr_reply, *sa_handle_reply,
        tunnel_route_id, tunnel_route_id_reply,
    )
    wire = head + sa_block
    # CtExCommand: 48 (header) + 28 (SA block: 1+1+8+1+1+8+4+4) = 76 B.
    assert len(wire) == 76, f"CtExCommand wire size {len(wire)} != 76"
    return wire


def _tnl_create_payload_6o4() -> bytes:
    """6o4 tunnel CREATE pinned to (DUT_WAN_IPV4, WAN_PEER_IP) on eth3."""
    name_field   = TNL_NAME.ljust(16, b"\x00")[:16]
    output_field = TNL_OUTPUT_IF.ljust(16, b"\x00")[:16]
    local_field  = _ip_be_bytes(DUT_WAN_IPV4) + b"\x00" * 12
    remote_field = _ip_be_bytes(WAN_PEER_IP)  + b"\x00" * 12
    tail = struct.pack(
        "<BBBBIHHIHBB",
        TNL_MODE_6O4,  # mode
        0,             # secure (must be 0 for 6o4 — handler rejects 1)
        0,             # elim
        64,            # hlim
        0,             # fl
        0,             # frag_off
        1,             # enabled
        0,             # route_id (no inner-prefix binding for ingress test)
        1480,          # mtu
        0,             # flags
        0,             # pad
    )
    wire = name_field + local_field + remote_field + output_field + tail
    assert len(wire) == 84
    return wire


def _tnl_delete_payload() -> bytes:
    return TNL_NAME.ljust(16, b"\x00")[:16]


# ---- tunnel lifecycle fixture --------------------------------------------

@pytest_asyncio.fixture
async def tunnel_6o4(aiohttp_session, target_agent, ipv6_topology):
    """CREATE a 6o4 tunnel, yield, DELETE on teardown.

    Depends on ipv6_topology so the inner-side IPv6 routing
    (DUT eth4 = fc00:dead::1/64, LAN = fc00:dead::2/64) is in place
    before the FMAN microcode tries to forward the decapped frame.
    """
    create = _tnl_create_payload_6o4()
    delete = _tnl_delete_payload()

    # Best-effort cleanup of any leftover entry from a previous run.
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_TNL_DELETE,
        length=len(delete), payload=delete, timeout_ms=2000,
    )

    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_TNL_CREATE,
        length=len(create), payload=create, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"6o4 tunnel CREATE failed: reply_rc={r.get('reply_rc')}, "
        f"send_error={r.get('send_error')!r}"
    )

    try:
        yield ipv6_topology
    finally:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_TNL_DELETE,
            length=len(delete), payload=delete, timeout_ms=2000,
        )


@pytest_asyncio.fixture
async def tunnel_route_and_ct_6o4(aiohttp_session, target_agent, tunnel_6o4):
    """Compose the full 6o4 decap workflow on top of `tunnel_6o4`.

    Step 1 (tunnel CREATE) is done by the parent fixture. This adds:
      - Forward route: outputDevice=eth4, inputDevice=eth3, dst MAC =
        LAN VM MAC. Used by the conntrack entry's pRtEntry — gives
        non-NULL input_itf so create_tunnel_remove_hm can read RX
        stats; gives the egress iface for the post-decap inner frame.
      - Tunnel route: outputDevice=tunnel iface, inputDevice=eth3,
        flags=RTCMD_FLAGS_6o4, daddr=WAN_PEER_IP. Bound to the
        conntrack entry's tnl_route, drives the
        l3_info.tnl_header_present=1 setting that triggers
        REMOVE_FIRST_IP_HDR.
      - Conntrack ADD (CtExCommand, 80 B) with format=CT_ORIG_TUNNEL,
        protocol=41, outer 5-tuple = (WAN_PEER, DUT_WAN, 0, 0, 41),
        route_id=forward, tunnel_route_id=tunnel,
        flags=CTCMD_FLAGS_REP_DISABLED (don't bother wiring the reply
        direction — this commit only tests WAN→LAN decap).

    Teardown reverses: CT remove, both routes remove, then the parent
    fixture deletes the tunnel.
    """
    topo = tunnel_6o4
    target_lan_if = os.environ.get("ASK_TARGET_LAN_IF", "eth4").encode()

    # ---- Forward route: post-decap inner egress on eth4 to LAN VM ----
    fwd_add = _pack_rt_command(
        action=ACTION_REGISTER,
        output_device=target_lan_if,
        input_device=TNL_OUTPUT_IF,
        underlying_input_device=TNL_OUTPUT_IF,
        route_id=TUNNEL_FORWARD_ROUTE_ID,
        flags=0,
        mac=_mac_bytes(LAN_NIC_MAC),
        mtu=1500,
    )
    fwd_del = _pack_rt_command(
        action=ACTION_DEREGISTER,
        output_device=target_lan_if,
        route_id=TUNNEL_FORWARD_ROUTE_ID,
    )

    # Best-effort cleanup of any leftover route from a prior run.
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IP_ROUTE,
        length=len(fwd_del), payload=fwd_del, timeout_ms=2000,
    )

    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IP_ROUTE,
        length=len(fwd_add), payload=fwd_add, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"forward route ADD failed: reply_rc={r.get('reply_rc')}, "
        f"send_error={r.get('send_error')!r}"
    )

    # ---- Tunnel route: outputDevice = tunnel iface ----
    tnl_add = _pack_rt_command(
        action=ACTION_REGISTER,
        output_device=TNL_NAME,
        input_device=TNL_OUTPUT_IF,
        underlying_input_device=TNL_OUTPUT_IF,
        route_id=TUNNEL_DECAP_ROUTE_ID,
        flags=RTCMD_FLAGS_6o4,
        mac=_mac_bytes(DUT_ETH3_MAC),
        mtu=1480,
        daddr_v4=WAN_PEER_IP,
    )
    tnl_del = _pack_rt_command(
        action=ACTION_DEREGISTER,
        output_device=TNL_NAME,
        route_id=TUNNEL_DECAP_ROUTE_ID,
    )

    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IP_ROUTE,
        length=len(tnl_del), payload=tnl_del, timeout_ms=2000,
    )

    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IP_ROUTE,
        length=len(tnl_add), payload=tnl_add, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"tunnel route ADD failed: reply_rc={r.get('reply_rc')}, "
        f"send_error={r.get('send_error')!r}"
    )

    # ---- Conntrack: outer 5-tuple keyed on (peer→DUT, proto=41) ----
    ct_add = _pack_ctex_command_v4(
        action=ACTION_REGISTER,
        saddr=WAN_PEER_IP, daddr=DUT_WAN_IPV4,
        sport=0, dport=0,
        saddr_reply=DUT_WAN_IPV4, daddr_reply=WAN_PEER_IP,
        sport_reply=0, dport_reply=0,
        protocol=PROTOCOL_IPV6_IN_IP,
        flags=CTCMD_FLAGS_REP_DISABLED,
        format_field=CT_ORIG_TUNNEL,
        route_id=TUNNEL_FORWARD_ROUTE_ID,
        route_id_reply=TUNNEL_FORWARD_ROUTE_ID,
        tunnel_route_id=TUNNEL_DECAP_ROUTE_ID,
        tunnel_route_id_reply=0,
    )
    ct_del = _pack_ctex_command_v4(
        action=ACTION_DEREGISTER,
        saddr=WAN_PEER_IP, daddr=DUT_WAN_IPV4,
        sport=0, dport=0,
        saddr_reply=DUT_WAN_IPV4, daddr_reply=WAN_PEER_IP,
        sport_reply=0, dport_reply=0,
        protocol=PROTOCOL_IPV6_IN_IP,
        flags=0,
        format_field=0,
    )

    # Best-effort cleanup.
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IPV4_CONNTRACK,
        length=len(ct_del), payload=ct_del, timeout_ms=2000,
    )

    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IPV4_CONNTRACK,
        length=len(ct_add), payload=ct_add, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"6o4 conntrack ADD with CT_ORIG_TUNNEL failed: "
        f"reply_rc={r.get('reply_rc')}, send_error={r.get('send_error')!r}"
    )

    try:
        yield topo
    finally:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IPV4_CONNTRACK,
            length=len(ct_del), payload=ct_del, timeout_ms=2000,
        )
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IP_ROUTE,
            length=len(tnl_del), payload=tnl_del, timeout_ms=2000,
        )
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IP_ROUTE,
            length=len(fwd_del), payload=fwd_del, timeout_ms=2000,
        )


# ---- LAN-side capture (clones test_mcast_replication shape) --------------

_TCPDUMP_PIDFILE = f"/tmp/ask_tunnel_offload_tcpdump_{LAN_NIC}.pid"


def _spawn_inner_tcpdump(lan, capfile: str) -> None:
    """Backgrounded tcpdump on the LAN NIC, BPF-tight to the inner UDP
    port so background v6 chatter doesn't pollute the count.
    """
    bpf = f"ip6 and udp port {TUNNEL_INNER_PORT}"
    chain = (
        f"nohup tcpdump -i {LAN_NIC} -Q in -w {capfile} '{bpf}' "
        f"</dev/null >/dev/null 2>&1 & "
        f"echo $! > {_TCPDUMP_PIDFILE}; "
        "echo SPAWNED"
    )
    r = lan.run(chain, timeout=10)
    assert "SPAWNED" in r.stdout, (
        f"failed to spawn tcpdump: rc={r.rc}, out={r.stdout!r}"
    )


def _kill_inner_tcpdump(lan) -> None:
    chain = (
        f"[ -f {_TCPDUMP_PIDFILE} ] && kill -TERM $(cat {_TCPDUMP_PIDFILE}) "
        f"2>/dev/null; rm -f {_TCPDUMP_PIDFILE}; echo KILLED"
    )
    r = lan.run(chain, timeout=10)
    assert "KILLED" in r.stdout, (
        f"failed to kill tcpdump: rc={r.rc}, out={r.stdout!r}"
    )


def _read_pcap_count(lan, capfile: str) -> int:
    r = lan.run(f"tcpdump -r {capfile} -nn 2>&1", timeout=10)
    if r.rc != 0:
        raise AssertionError(
            f"tcpdump -r {capfile} failed: rc={r.rc}, out={r.stdout!r}"
        )
    return sum(
        1 for ln in r.stdout.splitlines()
        if " IP6 " in ln and "UDP" in ln
    )


def _send_6o4_outer_from_orchestrator(
    *, dst_v4: str, src_v4: str, inner_dst_v6: str,
    inner_src_v6: str, inner_port: int, payload: bytes,
) -> None:
    """Build IP(proto=41)/IPv6/UDP and inject toward the DUT.

    L3 send() so the kernel ARPs the DUT's eth3 unicast MAC via the
    orchestrator's br0 (which sits on the WAN /24). sendp() with a
    default Ether() would broadcast at L2, and FMAN's PCD filters on
    the local-MAC dst — broadcasts wouldn't be classified into the
    tunnel-decap path.
    """
    from scapy.all import IP, IPv6, UDP, Raw, send  # type: ignore[import]

    pkt = (IP(src=src_v4, dst=dst_v4, proto=41)  # 41 = IPv6 over IPv4
           / IPv6(src=inner_src_v6, dst=inner_dst_v6, hlim=64)
           / UDP(sport=47211, dport=inner_port)
           / Raw(payload))
    send(pkt, count=1, verbose=0)


# ---- the test ------------------------------------------------------------

async def test_tunnel_6o4_decap_to_lan(
    aiohttp_session, target_agent, lan, splat_window, tunnel_route_and_ct_6o4,
):
    """Single 6o4 frame from WAN → DUT decaps → inner IPv6 reaches LAN.

    Two oracles:
      (i) tcpdump on LAN counts exactly 1 inner frame
     (ii) per-FQ counter signature matches the golden (records which
          fqid_stats lines tick during decap; on first run with
          ASK_REGEN_GOLDEN=1 the test records observed deltas).
    """
    topo = tunnel_route_and_ct_6o4
    inner_dst = topo["lan_v6"]   # fc00:dead::2

    capfile_drain = "/tmp/ask_tunnel_offload_drain.pcap"
    capfile       = "/tmp/ask_tunnel_offload.pcap"

    try:
        # ---- Pre-test drain: assert no stray inner frames on the wire.
        _spawn_inner_tcpdump(lan, capfile_drain)
        try:
            await asyncio.sleep(0.4)  # listener-up grace
            await asyncio.sleep(2.0)  # drain window
        finally:
            _kill_inner_tcpdump(lan)
        await asyncio.sleep(0.2)
        drain_count = _read_pcap_count(lan, capfile_drain)
        assert drain_count == 0, (
            f"pre-test drain saw {drain_count} stray inner-port frames; "
            f"port {TUNNEL_INNER_PORT} on the LAN side is contaminated"
        )

        # ---- Counter baseline + capture window ----
        before = await target_agent.counters(aiohttp_session)

        _spawn_inner_tcpdump(lan, capfile)
        try:
            await asyncio.sleep(0.4)
            await asyncio.to_thread(
                _send_6o4_outer_from_orchestrator,
                dst_v4=DUT_WAN_IPV4,
                src_v4=WAN_PEER_IP,
                inner_dst_v6=inner_dst,
                inner_src_v6=TUNNEL_INNER_SRC,
                inner_port=TUNNEL_INNER_PORT,
                payload=b"tunnel_6o4_offload",
            )
            await asyncio.sleep(2.0)  # give FMAN + counters time to settle
        finally:
            _kill_inner_tcpdump(lan)
        await asyncio.sleep(0.2)

        after = await target_agent.counters(aiohttp_session)

        # ---- Oracle (i): inner-frame arrival ----
        count = _read_pcap_count(lan, capfile)
        assert count == 1, (
            f"6o4 decap arrival mismatch: expected exactly 1 inner frame "
            f"on {LAN_NIC}, got {count}. drop=0 means decap is broken "
            f"or inner-routing is missing; >=2 means duplication."
        )

        # ---- Oracle (ii): per-FQ offload-engagement signature ----
        # Filter to fqid_stats only — ethtool counters tick whether
        # FMAN offloads or the kernel does softirq forwarding, so they
        # don't distinguish the two paths.
        sig = counter_signature(
            before, after, key_regex=r"^fqid_stats/.*/frame_count$",
        )
        assert_counter_signature(
            sig,
            golden_path=golden_for("tunnel_6o4_offload.json"),
            label="6o4_one_frame_decap",
        )
    finally:
        try:
            lan.run(
                f"rm -f {capfile_drain} {capfile}", timeout=5,
            )
        except Exception:
            pass

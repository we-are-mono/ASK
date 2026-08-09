"""FCI wire-format helpers for the tunnel/route command surface.

Historically this module carried a synthetic-FCI 6o4 decap test that
installed an outer-keyed proto-41 conntrack. That approach was retired:
cdx rightly rejects outer-keyed decap entries — the design keys decap
on the INNER tuple (PCD dists parse to the innermost L3 header), and
the real-path decap offload is covered by test_tunnel_decap_offload.py.
See ISSUES.md A9 for the full evidence chain.

What remains here is the RtCommand wire packing shared with
test_route_id_width.py, plus the command-code constants.
"""

from __future__ import annotations

import os
import struct


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

# Route IDs. 0x6041/0x6042 echo the "6o4" mode visually without
# colliding with the small-int ids CMM tends to allocate from the
# bottom of the range. (RouteEntry.id was U16 until the A10 fix
# widened it to match the U32 wire field; these ids predate that and
# work either way.)
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



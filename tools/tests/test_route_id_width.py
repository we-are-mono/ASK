"""A10 regression — route ids above 0xFFFF survive the add/remove round-trip.

RouteEntry.id was U16 while the RtCommand wire field is U32: ADD with
id >= 0x10000 returned NO_ERR but stored a truncated id, so the entry
hashed under the wrong bucket and every later lookup by the original
id missed. The user-visible failure was "route silently doesn't
exist" — CT commands referencing the route failed, DEREGISTER
returned ERR_RT_ENTRY_NOT_FOUND, and the leaked entry stayed behind.

DEREGISTER goes through L2_route_find(id) with the full U32, so an
ADD/REMOVE round-trip on a wide id is a complete oracle for the
truncation: pre-fix the REMOVE fails, post-fix both calls return
NO_ERR.
"""

from __future__ import annotations

import struct

from _topology import TARGET_LAN_IF


CMD_IP_ROUTE = 0x0313

# Action codes (cdx/fe.h:38-43)
ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1

NO_ERR = 0


def _ip_be_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


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

# High word non-zero (the class of id that surfaced A10: tunnel-fixture
# ids in the 0x0604xxxx range); low word distinct from ids other tests
# use, so a truncating kernel can't collide with their entries either.
WIDE_ROUTE_ID = 0x0604_7A31

ERR_RT_ENTRY_NOT_FOUND = 209  # cdx/fe.h errno for missing route


async def test_route_id_above_u16_add_remove(
    aiohttp_session, target_agent, splat_window,
):
    out_dev = TARGET_LAN_IF.encode()

    add = _pack_rt_command(
        action=ACTION_REGISTER,
        output_device=out_dev,
        route_id=WIDE_ROUTE_ID,
        mac=b"\x02\x00\x00\x0a\x10\x31",
        mtu=1500,
    )
    remove = _pack_rt_command(
        action=ACTION_DEREGISTER,
        output_device=out_dev,
        route_id=WIDE_ROUTE_ID,
    )

    # Best-effort cleanup of a leftover entry from a prior run.
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IP_ROUTE,
        length=len(remove), payload=remove, timeout_ms=2000,
    )

    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IP_ROUTE,
        length=len(add), payload=add, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"route ADD with id=0x{WIDE_ROUTE_ID:08x} failed: "
        f"reply_rc={r.get('reply_rc')}, send_error={r.get('send_error')!r}"
    )

    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IP_ROUTE,
        length=len(remove), payload=remove, timeout_ms=3000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"route REMOVE by id=0x{WIDE_ROUTE_ID:08x} failed with "
        f"reply_rc={r.get('reply_rc')} after a successful ADD. "
        f"A reply_rc of {ERR_RT_ENTRY_NOT_FOUND} (ERR_RT_ENTRY_NOT_FOUND) "
        f"means the stored id was truncated on ADD — the A10 "
        f"RouteEntry.id width regression (cdx/layer2.h). The truncated "
        f"entry is now leaked kernel-side until reboot."
    )

"""A53 regression — dangling RouteEntry->itf on interface teardown.

The struct _itf a RouteEntry points at is embedded in its owner
(VlanEntry here). Deregistering the VLAN frees the owner, but a route
that a socket still pins cannot be removed, so pre-fix it kept a
pointer into freed memory and the next route QUERY read it (a slab
UAF that KASAN catches, no traffic needed).

Post-fix remove_onif_by_index quarantines the pinned route (clears
itf), the QUERY reports a blank output device instead of dereferencing
the freed itf, a fresh pin on the quarantined route is refused, and the
route becomes removable once the socket releases it.

Control-plane only — every step is an FCI command; run under KASAN
(KASAN=1 kas build) for the splat_window oracle to have teeth.
"""

from __future__ import annotations

import struct

import pytest

from _topology import TARGET_LAN_IF


CMD_IP_ROUTE       = 0x0313
CMD_IPV4_SOCK_OPEN  = 0x0330
CMD_IPV4_SOCK_CLOSE = 0x0331
CMD_VLAN_ENTRY      = 0x0901

ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1
ACTION_QUERY      = 6
ACTION_QUERY_CONT = 7

NO_ERR              = 0
ERR_RT_ENTRY_LINKED = 202

VID      = 0x53
VLAN_IF  = f"{TARGET_LAN_IF}.{VID}"
ROUTE_ID = 0x0053_A100
SOCK_ID  = 0x7B01


def _pack_vlan(action: int, vid: int, vlanif: str, phyif: str) -> bytes:
    return (
        struct.pack("<HH", action, vid)
        + vlanif.encode().ljust(16, b"\x00")[:16]
        + phyif.encode().ljust(16, b"\x00")[:16]
        + b"\x02\x00\x00\x0a\x22\x00" + b"\x00\x00"
    )


def _pack_rt(action: int, route_id: int, outdev: str) -> bytes:
    out = outdev.encode().ljust(16, b"\x00")[:16]
    z16 = b"\x00" * 16
    return (
        struct.pack("<HH", action, 1500) + b"\x02\x00\x00\x0a\x11\x00"
        + struct.pack("<HH", 0, 0) + struct.pack("<H", 0)
        + out + z16 + z16 + struct.pack("<II", route_id, 0) + b"\x00" * 16
    )


def _pack_sock_open(sock_id: int, route_id: int) -> bytes:
    w = (
        struct.pack("<H", sock_id) + bytes([0, 0])
        + struct.pack("<II", 0x0A0B0C0E, 0x01020305)
        + struct.pack("<HH", 5001, 6001)
        + bytes([17, 0]) + struct.pack("<H", 0)
        + struct.pack("<I", route_id)
        + struct.pack("<HHH", 0, 0, 0)
        + struct.pack("<H", 0) + b"\x00" * 8
        + struct.pack("<H", 0) + b"\x00" * 8
        + struct.pack("<H", 0)
    )
    assert len(w) == 52, len(w)
    return w


async def _send(agent, sess, code, payload, tmo=4000):
    r = await agent.fci_send(sess, fcode=code, length=len(payload),
                             payload=payload, timeout_ms=tmo)
    return r.get("reply_rc"), r


async def _query_route(agent, sess, route_id):
    """Walk the route QUERY pagination; return (found, outputDevice)."""
    rc, rep = await _send(agent, sess, CMD_IP_ROUTE, _pack_rt(ACTION_QUERY, 0, ""))
    seen = 0
    while rc == NO_ERR and seen < 128:
        raw = bytes.fromhex(rep.get("payload_hex") or "")
        if len(raw) >= 72:
            rid = struct.unpack_from("<I", raw, 64)[0]
            if rid == route_id:
                outdev = raw[16:32].split(b"\x00")[0].decode(errors="replace")
                return True, outdev
        seen += 1
        rc, rep = await _send(agent, sess, CMD_IP_ROUTE,
                              _pack_rt(ACTION_QUERY_CONT, 0, ""))
    return False, None


async def test_pinned_route_quarantined_on_vlan_deregister(
    aiohttp_session, target_agent, splat_window,
):
    ag, sess = target_agent, aiohttp_session

    # kernel netdev backing the FCI vlan entry
    await ag.exec_cmd(sess, ["ip", "link", "add", "link", TARGET_LAN_IF,
                             "name", VLAN_IF, "type", "vlan", "id", str(VID)])
    await ag.exec_cmd(sess, ["ip", "link", "set", VLAN_IF, "up"])

    # best-effort cleanup from a prior run
    await _send(ag, sess, CMD_IPV4_SOCK_CLOSE, struct.pack("<HH", SOCK_ID, 0))
    await _send(ag, sess, CMD_IP_ROUTE, _pack_rt(ACTION_DEREGISTER, ROUTE_ID, VLAN_IF))
    await _send(ag, sess, CMD_VLAN_ENTRY, _pack_vlan(ACTION_DEREGISTER, VID, VLAN_IF, TARGET_LAN_IF))

    try:
        rc, _ = await _send(ag, sess, CMD_VLAN_ENTRY,
                            _pack_vlan(ACTION_REGISTER, VID, VLAN_IF, TARGET_LAN_IF))
        assert rc == NO_ERR, f"vlan REGISTER rc={rc}"

        rc, _ = await _send(ag, sess, CMD_IP_ROUTE,
                            _pack_rt(ACTION_REGISTER, ROUTE_ID, VLAN_IF))
        assert rc == NO_ERR, f"route REGISTER rc={rc}"

        rc, _ = await _send(ag, sess, CMD_IPV4_SOCK_OPEN,
                            _pack_sock_open(SOCK_ID, ROUTE_ID))
        assert rc == NO_ERR, f"sock OPEN rc={rc}"

        # route is pinned by the socket
        rc, _ = await _send(ag, sess, CMD_IP_ROUTE,
                            _pack_rt(ACTION_DEREGISTER, ROUTE_ID, VLAN_IF))
        assert rc == ERR_RT_ENTRY_LINKED, f"dereg-while-pinned rc={rc}"

        # frees the VlanEntry that owns the itf the route points at
        rc, _ = await _send(ag, sess, CMD_VLAN_ENTRY,
                            _pack_vlan(ACTION_DEREGISTER, VID, VLAN_IF, TARGET_LAN_IF))
        assert rc == NO_ERR, f"vlan DEREGISTER rc={rc}"

        # pre-fix UAF read: QUERY dereferences the freed itf. Post-fix the
        # route is quarantined and reports a blank output device.
        found, outdev = await _query_route(ag, sess, ROUTE_ID)
        assert found, "quarantined route vanished from QUERY"
        assert outdev == "", f"expected blank outputDevice, got {outdev!r}"

        # a fresh pin on a quarantined route must be refused (itf==NULL gate)
        rc, _ = await _send(ag, sess, CMD_IPV4_SOCK_OPEN,
                            _pack_sock_open(SOCK_ID + 1, ROUTE_ID))
        assert rc != NO_ERR, "sock OPEN on quarantined route should fail"

        # releasing the pin makes the route removable again
        rc, _ = await _send(ag, sess, CMD_IPV4_SOCK_CLOSE,
                            struct.pack("<HH", SOCK_ID, 0))
        assert rc == NO_ERR, f"sock CLOSE rc={rc}"
        rc, _ = await _send(ag, sess, CMD_IP_ROUTE,
                            _pack_rt(ACTION_DEREGISTER, ROUTE_ID, VLAN_IF))
        assert rc == NO_ERR, f"dereg-after-release rc={rc}"
    finally:
        await _send(ag, sess, CMD_IPV4_SOCK_CLOSE, struct.pack("<HH", SOCK_ID, 0))
        await _send(ag, sess, CMD_IPV4_SOCK_CLOSE, struct.pack("<HH", SOCK_ID + 1, 0))
        await _send(ag, sess, CMD_IP_ROUTE, _pack_rt(ACTION_DEREGISTER, ROUTE_ID, VLAN_IF))
        await _send(ag, sess, CMD_VLAN_ENTRY, _pack_vlan(ACTION_DEREGISTER, VID, VLAN_IF, TARGET_LAN_IF))
        await ag.exec_cmd(sess, ["ip", "link", "del", VLAN_IF])

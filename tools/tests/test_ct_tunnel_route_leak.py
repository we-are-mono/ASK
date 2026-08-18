"""A69 regression — CT register must not leak main-route refs when the
tunnel route fails to resolve.

The IPv4/IPv6 conntrack REGISTER handlers resolve the main routes with
IP_Check_Route() (an L2_route_get, taking an nbref) before resolving the
tunnel route. Pre-fix, a tunnel route that failed to resolve took the
error path through a plain ct_free() — which only kfree()s the pair and
never released those main-route references, so the routes stayed pinned
against removal forever (L2_route_remove → ERR_RT_ENTRY_LINKED). Post-fix
the error path runs ct_free_unresolved(), mirroring ct_add()'s err0
unwind, so the references are released.

Oracle (no traffic): register a route R, then CT-register a tunnel flow
that references R on both directions but names an *unregistered* tunnel
route id. The register fails with ERR_RT_LINK_NOT_POSSIBLE; then
DEREGISTER of R must return NO_ERR (nbref back to 0). Pre-fix it returns
ERR_RT_ENTRY_LINKED because the CT leaked two refs on R.
"""

from __future__ import annotations

import struct

from _topology import TARGET_LAN_IF


CMD_IP_ROUTE       = 0x0313
CMD_IPV4_CONNTRACK = 0x0314

ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1

NO_ERR                   = 0
ERR_RT_ENTRY_LINKED      = 202
ERR_RT_LINK_NOT_POSSIBLE = 203

CT_ORIG_TUNNEL = 1 << 1  # cdx/fe.h

ROUTE_ID        = 0x0069_A100
# A tunnel route id that is never registered, so L2_route_get() returns NULL.
BAD_TNL_ROUTE_ID = 0x0069_DEAD


def _pack_rt(action: int, route_id: int) -> bytes:
    """RtCommand, 88 B with VLAN_FILTER (cf. test_route_id_width)."""
    out = TARGET_LAN_IF.encode().ljust(16, b"\x00")[:16]
    z16 = b"\x00" * 16
    wire = (
        struct.pack("<HH", action, 1500)
        + b"\x02\x00\x00\x0a\x69\x01"            # macAddr
        + struct.pack("<HH", 0, 0)               # egress_vid, underlying_vid
        + struct.pack("<H", 0)                   # pad
        + out + z16 + z16                        # output / input / underlying dev
        + struct.pack("<II", route_id, 0)        # id, flags
        + b"\x00" * 16                           # daddr[4]
    )
    assert len(wire) == 88, len(wire)
    return wire


def _pack_ct_ex_tunnel(action: int, route_id: int, tunnel_route_id: int) -> bytes:
    """CtExCommand (cdx/fe.h), 76 B packed, format = CT_ORIG_TUNNEL."""
    wire = (
        struct.pack(
            "<HHIIHHIIHHHHQII",
            action, CT_ORIG_TUNNEL,
            0x0A0B0C69, 0x01020369,              # Saddr, Daddr
            0x1069, 0x2069,                      # Sport, Dport
            0x01020369, 0x0A0B0C69,              # SaddrReply, DaddrReply
            0x2069, 0x1069,                      # SportReply, DportReply
            17, 0,                               # protocol (UDP), flags
            0,                                   # qosconnmark
            route_id, route_id,                  # route_id, route_id_reply
        )
        + struct.pack("<BB", 0, 0)               # SA_dir, SA_nr
        + struct.pack("<4H", 0, 0, 0, 0)         # SA_handle[4]
        + struct.pack("<BB", 0, 0)               # SAReply_dir, SAReply_nr
        + struct.pack("<4H", 0, 0, 0, 0)         # SAReply_handle[4]
        + struct.pack("<II", tunnel_route_id, 0) # tunnel_route_id, _reply
    )
    assert len(wire) == 76, len(wire)
    return wire


async def _send(agent, sess, code, payload, tmo=3000):
    r = await agent.fci_send(sess, fcode=code, length=len(payload),
                             payload=payload, timeout_ms=tmo)
    return r.get("reply_rc")


async def test_ct_register_tunnel_route_fail_releases_main_route(
    aiohttp_session, target_agent, splat_window,
):
    ag, sess = target_agent, aiohttp_session

    # best-effort cleanup from a prior run
    await _send(ag, sess, CMD_IP_ROUTE, _pack_rt(ACTION_DEREGISTER, ROUTE_ID))

    rc = await _send(ag, sess, CMD_IP_ROUTE, _pack_rt(ACTION_REGISTER, ROUTE_ID))
    assert rc == NO_ERR, f"route REGISTER rc={rc}"

    try:
        # CT register naming R on both directions + an unresolvable tunnel
        # route: IP_Check_Route takes two refs on R, then the tunnel get
        # fails and the handler must unwind them.
        rc = await _send(ag, sess, CMD_IPV4_CONNTRACK,
                         _pack_ct_ex_tunnel(ACTION_REGISTER, ROUTE_ID, BAD_TNL_ROUTE_ID))
        assert rc == ERR_RT_LINK_NOT_POSSIBLE, (
            f"CT register with unresolvable tunnel route rc={rc}, "
            f"expected {ERR_RT_LINK_NOT_POSSIBLE}"
        )

        # The route must be removable — pre-fix the leaked refs pinned it.
        rc = await _send(ag, sess, CMD_IP_ROUTE, _pack_rt(ACTION_DEREGISTER, ROUTE_ID))
        assert rc == NO_ERR, (
            f"route DEREGISTER rc={rc}; ERR_RT_ENTRY_LINKED (202) means the "
            f"failed CT register leaked its main-route references"
        )
    finally:
        await _send(ag, sess, CMD_IP_ROUTE, _pack_rt(ACTION_DEREGISTER, ROUTE_ID))

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

import os

from test_tunnel_offload import (
    ACTION_DEREGISTER,
    ACTION_REGISTER,
    CMD_IP_ROUTE,
    NO_ERR,
    _pack_rt_command,
)

# High word non-zero (the class of id that surfaced A10: tunnel-fixture
# ids in the 0x0604xxxx range); low word distinct from ids other tests
# use, so a truncating kernel can't collide with their entries either.
WIDE_ROUTE_ID = 0x0604_7A31

ERR_RT_ENTRY_NOT_FOUND = 209  # cdx/fe.h errno for missing route


async def test_route_id_above_u16_add_remove(
    aiohttp_session, target_agent, splat_window,
):
    out_dev = os.environ.get("ASK_TARGET_LAN_IF", "eth4").encode()

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

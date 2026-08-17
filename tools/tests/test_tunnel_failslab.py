"""Failslab sweep over CMD_TNL_CREATE.

Drives tunnel_alloc() (cdx/control_tunnel.c:76) into NULL via fork-
isolated failslab; asserts the unwind in TNL_handle_CREATE leaves no
leaked TnlEntry allocations behind. The wire payload uses a 6o4-mode
tunnel whose remote address is unrouteable from the test environment;
the kernel just walks the hash, allocates, classifies the mode, and
returns — no real tunnel comes up.

Pre-iter DELETE lets the same tunnel name be reused: a successful
CREATE registers an onif with that name, so the next iteration would
bounce on ERR_TNL_ALREADY_CREATED at get_onif_by_name() instead of
reaching tunnel_alloc.
"""

from __future__ import annotations

import asyncio
import os
import struct

from _topology import TARGET_WAN_IF


CMD_TNL_CREATE = 0x0B01
CMD_TNL_DELETE = 0x0B02

NO_ERR                = 0
ERR_NOT_ENOUGH_MEMORY = 6   # cdx/fe.h — tunnel_alloc() == NULL → this code

# TNL_MODE_6O4 (control_tunnel.h): IPv6-in-IPv4 outer. Pick the mode
# with the smallest extra work in the success path so the failslab
# sweep has the cleanest unwind set to exercise.
TNL_MODE_6O4 = 1

TNL_NAME = b"flsltun"  # 7 chars + NULs to 16 — short, recognisable, no collisions

TUNNEL_LEAK_FILTER = [
    "tunnel_alloc",
    "tunnel_free",
    "tnl_create_handle",
    "TNL_handle_CREATE",
    "M_tnl_add",
]


def _ip_be_bytes(addr: str) -> bytes:
    """IPv4 as 4 NBO bytes — matches the codebase's wire convention
    (cf. test_mcast_replication._ip_be_bytes); local/remote are stamped
    straight into the outer IP header without htonl()."""
    return bytes(int(o) for o in addr.split("."))


def _tnl_create_payload(
    name: bytes = TNL_NAME,
    local_ip: str = "10.0.0.62",
    remote_ip: str = "10.0.0.141",
    output_device: bytes = TARGET_WAN_IF.encode(),
    mode: int = TNL_MODE_6O4,
    secure: int = 0,
    elim: int = 0,
    hlim: int = 64,
    fl: int = 0,
    frag_off: int = 0,
    enabled: int = 0,
    route_id: int = 0,
    mtu: int = 1480,
    flags: int = 0,
) -> bytes:
    # struct TNLCommand_create (cdx/control_tunnel.h:64) — 84 B total.
    # local/remote are U32[4] (16 B each); IPv4 puts the address in the
    # first 4 bytes (NBO) and zero-fills the rest.
    name_field = name.ljust(16, b"\x00")[:16]
    output_field = output_device.ljust(16, b"\x00")[:16]
    local_field  = _ip_be_bytes(local_ip)  + b"\x00" * 12
    remote_field = _ip_be_bytes(remote_ip) + b"\x00" * 12
    tail = struct.pack(
        "<BBBBIHHIHBB",
        mode, secure, elim, hlim,
        fl, frag_off, enabled,
        route_id, mtu, flags,
        0,  # pad
    )
    wire = name_field + local_field + remote_field + output_field + tail
    assert len(wire) == 84, f"TNLCommand_create wire size {len(wire)} != 84"
    return wire


def _tnl_delete_payload(name: bytes = TNL_NAME) -> bytes:
    return name.ljust(16, b"\x00")[:16]


# Sweep walks N from 1..NSWEEP. tunnel_alloc sits past the netlink+fci
# scaffold and after get_onif_by_name; NSWEEP=100 reaches it consistently
# (same headroom test_ipv4_ct_failslab uses for ct_alloc).
NSWEEP = int(os.environ.get("ASK_TUNNEL_FAILSLAB_SWEEP", "100"))
KMEMLEAK_AGE_GRACE_S = 7.0


async def test_tunnel_create_failslab_sweep(
    aiohttp_session, target_agent, splat_window,
):
    create_cmd = _tnl_create_payload()
    delete_cmd = _tnl_delete_payload()

    async def _delete() -> None:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_TNL_DELETE,
            length=len(delete_cmd), payload=delete_cmd, timeout_ms=2000,
        )

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []

    for n in range(1, NSWEEP + 1):
        await _delete()  # clear any leftover from prior iteration

        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_TNL_CREATE,
            length=len(create_cmd), payload=create_cmd,
            timeout_ms=3000, failslab_times=n,
        )
        reply_rc = r.get("reply_rc")
        send_err = r.get("send_error")
        outcomes.append((n, reply_rc, send_err))

        if reply_rc == NO_ERR and send_err is None:
            await _delete()

    await _delete()

    faulted = [n for n, rc, e in outcomes if rc == ERR_NOT_ENOUGH_MEMORY]
    assert faulted, (
        f"failslab sweep never drove tunnel_alloc to NULL across "
        f"times=1..{NSWEEP}; outcomes={outcomes}."
    )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=TUNNEL_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab CREATE sweep (1..{NSWEEP}) leaked {leak_count} "
            f"tunnel-path object(s); {len(faulted)} iteration(s) hit "
            f"ERR_NOT_ENOUGH_MEMORY.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

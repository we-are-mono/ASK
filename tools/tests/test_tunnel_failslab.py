"""Failslab sweep over CMD_TNL_CREATE.

Drives the tunnel create path into NULL via fork-isolated failslab and
checks three properties on every faulted iteration:

  - no leaked TnlEntry allocations after the unwind (kmemleak), the
    original leak regression;
  - A57 structure: a create that did not return NO_ERR leaves no tunnel
    reachable by name (DELETE returns ERR_TNL_ENTRY_NOT_FOUND). Pre-fix
    M_tnl_add hash-linked the entry before the fallible dpa_add_tunnel_if
    and discarded its result, so a faulted add could leave a half-linked
    entry (and, had the rc been propagated, freed it while still linked);
  - A57 route discipline: the parent route this create references is
    never left pinned by a faulted round (DEREGISTER is 0/201, never 202)
    — the create's err1 arm must L2_route_put the reference it took.

Unlike the route_id=0 variant this used to be, the create here carries a
real parent route, so the sweep also exercises the L2_route_get/put pair
on the exact path A57 reordered.

Pre-iter DELETE lets the same tunnel name be reused: a successful CREATE
registers an onif with that name, so the next iteration would otherwise
bounce on ERR_TNL_ALREADY_CREATED at get_onif_by_name().
"""

from __future__ import annotations

import asyncio
import os
import struct

from _topology import TARGET_LAN_IF, TARGET_WAN_IF


CMD_IP_ROUTE   = 0x0313
CMD_TNL_CREATE = 0x0B01
CMD_TNL_DELETE = 0x0B02

ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1

NO_ERR                  = 0
ERR_NOT_ENOUGH_MEMORY   = 6     # cdx/fe.h — tunnel_alloc() == NULL → this code
ERR_RT_ENTRY_LINKED     = 202   # route still pinned
ERR_TNL_ENTRY_NOT_FOUND = 1001  # DELETE of an absent tunnel

TNL_ROUTE_ID = 0x0057_F500

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
    route_id: int = TNL_ROUTE_ID,
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


def _rt_payload(action: int, route_id: int = TNL_ROUTE_ID) -> bytes:
    out = TARGET_LAN_IF.encode().ljust(16, b"\x00")[:16]
    z16 = b"\x00" * 16
    return (struct.pack("<HH", action, 1500) + b"\x02\x00\x00\x0a\x11\x00"
            + struct.pack("<HH", 0, 0) + struct.pack("<H", 0)
            + out + z16 + z16 + struct.pack("<II", route_id, 0) + b"\x00" * 16)


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

    async def _fci(code, payload, tmo=2000, failslab=None):
        kw = dict(fcode=code, length=len(payload), payload=payload, timeout_ms=tmo)
        if failslab is not None:
            kw["failslab_times"] = failslab
        return await target_agent.fci_send(aiohttp_session, **kw)

    async def _delete() -> int | None:
        r = await _fci(CMD_TNL_DELETE, delete_cmd)
        return r.get("reply_rc")

    # Calibrate the not-found rc for this build against a clean miss, so the
    # half-linked assertion below can't be defeated by an enum drift.
    await _delete()
    miss_rc = await _delete()
    assert miss_rc == ERR_TNL_ENTRY_NOT_FOUND, (
        f"DELETE of an absent tunnel returned {miss_rc}, expected "
        f"{ERR_TNL_ENTRY_NOT_FOUND}"
    )

    # Parent route the create references — lets the sweep exercise the
    # L2_route_get/put pair and the route-pin invariant.
    rc = (await _fci(CMD_IP_ROUTE, _rt_payload(ACTION_REGISTER))).get("reply_rc")
    assert rc == NO_ERR, f"parent route REGISTER rc={rc}"

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []

    try:
        for n in range(1, NSWEEP + 1):
            await _delete()  # clear any leftover from prior iteration

            r = await _fci(CMD_TNL_CREATE, create_cmd, tmo=3000, failslab=n)
            reply_rc = r.get("reply_rc")
            send_err = r.get("send_error")
            # 4th field: /proc/self/fail-nth after the syscall — == n means
            # the path made zero fault-eligible allocations (injection
            # tested nothing), 0 means the fault fired; see ISSUES.md A70.
            outcomes.append((n, reply_rc, send_err, r.get("fail_nth_residue")))

            faulted_iter = (send_err is not None) or (reply_rc not in (NO_ERR,))
            del_rc = await _delete()

            if faulted_iter:
                # A57: a faulted create must not leave a name-reachable entry.
                assert del_rc == ERR_TNL_ENTRY_NOT_FOUND, (
                    f"n={n}: create faulted (rc={reply_rc}, err={send_err}) but "
                    f"the tunnel is reachable by name (DELETE rc={del_rc}) — "
                    f"half-linked entry"
                )
            else:
                assert del_rc == NO_ERR, f"n={n}: create OK but DELETE rc={del_rc}"

            # A57: a faulted round must never leave the parent route pinned.
            rrc = (await _fci(CMD_IP_ROUTE, _rt_payload(ACTION_DEREGISTER))).get("reply_rc")
            assert rrc != ERR_RT_ENTRY_LINKED, (
                f"n={n}: parent route left pinned after a faulted create"
            )
            if rrc == NO_ERR:  # re-register for the next iteration
                rc = (await _fci(CMD_IP_ROUTE, _rt_payload(ACTION_REGISTER))).get("reply_rc")
                assert rc == NO_ERR, f"n={n}: parent route re-register rc={rc}"

        await _delete()
    finally:
        await _fci(CMD_IP_ROUTE, _rt_payload(ACTION_DEREGISTER))

    faulted = [n for n, rc, e, *_ in outcomes if rc == ERR_NOT_ENOUGH_MEMORY]
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
            for n, rc, e, *_ in outcomes
        )
        raise AssertionError(
            f"failslab CREATE sweep (1..{NSWEEP}) leaked {leak_count} "
            f"tunnel-path object(s); {len(faulted)} iteration(s) hit "
            f"ERR_NOT_ENOUGH_MEMORY.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

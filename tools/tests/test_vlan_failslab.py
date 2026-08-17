"""Failslab sweep over CMD_VLAN_ENTRY ACTION_REGISTER.

Same shape as test_mcast_failslab.py: under failslab pressure aimed at the
cdx FCI handler, every iteration of vlan_alloc()'s failure path must
unwind cleanly. Oracle is kmemleak filtered to vlan-handler frames after
the sweep + the agent's splat_window.

Reaching vlan_alloc requires onif and vlan_cache both NOT to hold an
entry for the target interface — CMM's NEWLINK auto-registration leaves
both populated, so each iteration explicitly DEREGISTERs first.
"""

from __future__ import annotations

import asyncio
import os
import struct

import pytest_asyncio

from _topology import TARGET_LAN_IF


CMD_VLAN_ENTRY        = 0x0901
ACTION_REGISTER       = 0
ACTION_DEREGISTER     = 1
NO_ERR                = 0
ERR_NOT_ENOUGH_MEMORY = 6  # cdx/fe.h — vlan_alloc() == NULL → this code
IF_NAME_SIZE          = 16

VLAN_LEAK_FILTER = [
    "vlan_alloc",
    "vlan_entry_handle",
    "control_vlan",
]


def _vlan_cmd(action: int, vlan_id: int = 0,
              vlan_if: bytes = b"", phy_if: bytes = b"",
              mac: bytes = b"\x00" * 6) -> bytes:
    vlan_if_padded = vlan_if.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    phy_if_padded  = phy_if.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    mac_padded     = mac.ljust(6, b"\x00")[:6]
    return (
        struct.pack("<HH", action, vlan_id)
        + vlan_if_padded
        + phy_if_padded
        + mac_padded
        + b"\x00\x00"
    )


VID           = int(os.environ.get("ASK_VLAN_FAILSLAB_VID", "251"))
LISTENER_IF   = f"{TARGET_LAN_IF}.{VID}"

# NSWEEP walks N from 1..NSWEEP and faults exactly the Nth kmalloc the
# agent's child makes. Many kmallocs happen in the netlink/fci scaffold
# before the cdx vlan handler runs, so the sweep needs to extend past
# that count to land on vlan_alloc.
NSWEEP = int(os.environ.get("ASK_VLAN_FAILSLAB_SWEEP", "100"))
KMEMLEAK_AGE_GRACE_S = 7.0


@pytest_asyncio.fixture
async def one_vlan_subif(aiohttp_session, target_agent):
    """Create a VLAN sub-interface; CMM auto-registers it via NEWLINK.
    The test's first DEREGISTER (in the sweep loop) clears that state so
    the subsequent REGISTER reaches vlan_alloc()."""
    await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", LISTENER_IF])
    try:
        r = await target_agent.exec_cmd(aiohttp_session, [
            "ip", "link", "add", "link", TARGET_LAN_IF,
            "name", LISTENER_IF, "type", "vlan", "id", str(VID),
        ])
        assert r["rc"] == 0, f"vlan add failed: {r}"
        r = await target_agent.exec_cmd(
            aiohttp_session, ["ip", "link", "set", LISTENER_IF, "up"],
        )
        assert r["rc"] == 0, f"vlan up failed: {r}"
        await asyncio.sleep(1.0)  # let CMM pick up NEWLINK
        yield LISTENER_IF
    finally:
        await target_agent.exec_cmd(
            aiohttp_session, ["ip", "link", "del", LISTENER_IF],
        )


async def test_vlan_register_failslab_sweep(
    aiohttp_session, target_agent, splat_window, one_vlan_subif,
):
    register_cmd = _vlan_cmd(
        action=ACTION_REGISTER, vlan_id=VID,
        vlan_if=LISTENER_IF.encode(), phy_if=TARGET_LAN_IF.encode(),
    )
    deregister_cmd = _vlan_cmd(
        action=ACTION_DEREGISTER, vlan_id=VID,
        vlan_if=LISTENER_IF.encode(),
    )

    async def _dereg() -> None:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_VLAN_ENTRY,
            length=len(deregister_cmd), payload=deregister_cmd, timeout_ms=2000,
        )

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []

    for n in range(1, NSWEEP + 1):
        # Clear cdx vlan_cache + onif so the next REGISTER reaches
        # vlan_alloc rather than bouncing on ALREADY_REGISTERED.
        await _dereg()

        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_VLAN_ENTRY,
            length=len(register_cmd), payload=register_cmd,
            timeout_ms=3000, failslab_times=n,
        )
        reply_rc = r.get("reply_rc")
        send_err = r.get("send_error")
        outcomes.append((n, reply_rc, send_err))

        # If REGISTER succeeded, drop it so the next pre-iter dereg has
        # something to clear (otherwise pre-iter clears nothing, fine).
        if reply_rc == NO_ERR and send_err is None:
            await _dereg()

    await _dereg()  # final cleanup

    faulted = [n for n, rc, e in outcomes if rc == ERR_NOT_ENOUGH_MEMORY]
    assert faulted, (
        f"failslab sweep never drove vlan_alloc to NULL across "
        f"times=1..{NSWEEP}; outcomes={outcomes}. Either failslab isn't "
        f"firing in the cdx vlan path, or the handler is masking the alloc failure."
    )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=VLAN_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab REGISTER sweep (1..{NSWEEP}) leaked {leak_count} "
            f"vlan-path object(s); {len(faulted)} iteration(s) hit "
            f"ERR_NOT_ENOUGH_MEMORY.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

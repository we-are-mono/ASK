"""VLAN control-plane tests via CMD_VLAN_ENTRY (FCI code 0x0901).

Complements the fuzzer: where test_fci_fuzz proves "malformed input is
rejected at the dispatcher", this file proves "well-formed input reaches
the handler, gets the semantic treatment it should, and returns the
right domain error". No target-side VLAN netdev setup required — all
cases probe the error branches of `vlan_entry_handle` which are
reachable with a valid-sized struct but nonexistent interface names.

Covered ISSUES.md items:
  * A1b — the validator-table migration of control_vlan.c. Positive
    asserts that the dispatcher routes CMD_VLAN_ENTRY to the handler
    (not ERR_UNKNOWN_COMMAND), and the handler returns its own error
    codes (not ERR_WRONG_COMMAND_SIZE).
  * The validator-level semantic check (vlan_entry_validate): actions
    outside {REGISTER, DEREGISTER, QUERY, QUERY_CONT} return
    ERR_UNKNOWN_ACTION.

Not covered here (would need a real VLAN setup on the target):
  * Successful ACTION_REGISTER path
  * End-to-end offload of VLAN-tagged traffic
"""

from __future__ import annotations

import struct

import pytest


CMD_VLAN_ENTRY    = 0x0901
CMD_VLAN_ENTRY_RESET = 0x0902

# From cdx/fe.h
NO_ERR                  = 0
ERR_UNKNOWN_COMMAND     = 1
ERR_WRONG_COMMAND_SIZE  = 2
ERR_UNKNOWN_ACTION      = 4
FAILURE                 = 0xFFFF  # `-1` in cdx/misc.h, u16-cast on the wire
ERR_VLAN_ENTRY_NOT_FOUND = 601

# From cdx/fe.h
ACTION_REGISTER    = 0
ACTION_DEREGISTER  = 1
ACTION_QUERY       = 6
ACTION_QUERY_CONT  = 7

IF_NAME_SIZE = 16
# VlanCommand layout (cdx/control_vlan.h):
#   U16 action, U16 vlanID, U8 vlanifname[16], U8 phyifname[16],
#   U8 macaddr[6], U8 unused[2]  = 44 bytes
SIZEOF_VLAN_COMMAND = 44


def _vlan_cmd(action: int, vlan_id: int = 0,
              vlan_if: bytes = b"", phy_if: bytes = b"",
              mac: bytes = b"\x00" * 6) -> bytes:
    """Pack a VlanCommand. Short if-name / mac args are zero-padded."""
    vlan_if_padded = vlan_if.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    phy_if_padded  = phy_if.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    mac_padded     = mac.ljust(6, b"\x00")[:6]
    # Little-endian per-field pack, matches how the handler reads them.
    return (
        struct.pack("<HH", action, vlan_id)
        + vlan_if_padded
        + phy_if_padded
        + mac_padded
        + b"\x00\x00"                  # unused[2]
    )


async def _send_vlan(target_agent, session, cmd_bytes: bytes) -> dict:
    r = await target_agent.fci_send(
        session,
        fcode=CMD_VLAN_ENTRY,
        length=len(cmd_bytes),
        payload=cmd_bytes,
    )
    return r


# ------------------------------------------------------------------

async def test_vlan_unknown_action_rejected(
    aiohttp_session, target_agent, splat_window,
):
    """Action value outside {0,1,2,3} → validator returns ERR_UNKNOWN_ACTION,
    handler never runs. Proves the validator callback is wired up."""
    cmd = _vlan_cmd(action=99, vlan_id=100, vlan_if=b"eth4.100")
    r = await _send_vlan(target_agent, aiohttp_session, cmd)
    assert r.get("reply_rc") == ERR_UNKNOWN_ACTION, (
        f"expected ERR_UNKNOWN_ACTION ({ERR_UNKNOWN_ACTION}), got {r}"
    )


async def test_vlan_deregister_nonexistent_entry(
    aiohttp_session, target_agent, splat_window,
):
    """ACTION_DEREGISTER with a vlanifname that isn't in the hash cache
    → ERR_VLAN_ENTRY_NOT_FOUND. Reaches the handler, exercises the
    hash lookup branch."""
    cmd = _vlan_cmd(
        action=ACTION_DEREGISTER,
        vlan_id=0xBEEF,
        vlan_if=b"definitely.not.here",
    )
    r = await _send_vlan(target_agent, aiohttp_session, cmd)
    assert r.get("reply_rc") == ERR_VLAN_ENTRY_NOT_FOUND, (
        f"expected ERR_VLAN_ENTRY_NOT_FOUND ({ERR_VLAN_ENTRY_NOT_FOUND}), got {r}"
    )


async def test_vlan_register_missing_netdev(
    aiohttp_session, target_agent, splat_window,
):
    """ACTION_REGISTER with bogus vlanifname + phyifname →
    `dev_get_by_name` misses twice, handler returns FAILURE. Doesn't
    actually register anything."""
    cmd = _vlan_cmd(
        action=ACTION_REGISTER,
        vlan_id=42,
        vlan_if=b"no.such.vlan",
        phy_if=b"no.such.phy",
    )
    r = await _send_vlan(target_agent, aiohttp_session, cmd)
    assert r.get("reply_rc") == FAILURE, (
        f"expected FAILURE ({FAILURE}) for missing netdevs, got {r}"
    )


async def test_vlan_query_completes(
    aiohttp_session, target_agent, splat_window,
):
    """ACTION_QUERY walks the hash table; empty cache → returns success
    with no entry. Exercises the query path alongside the REGISTER/
    DEREGISTER paths tested above."""
    cmd = _vlan_cmd(action=ACTION_QUERY)
    r = await _send_vlan(target_agent, aiohttp_session, cmd)
    # Query path returns NO_ERR with the entry (or a sentinel if empty).
    # We don't assert on specific contents; just that the handler ran
    # without rejecting at the dispatcher/validator layer.
    assert r.get("reply_rc") not in (
        ERR_UNKNOWN_COMMAND, ERR_WRONG_COMMAND_SIZE, ERR_UNKNOWN_ACTION,
    ), f"query path shouldn't be rejected pre-handler, got {r}"


async def test_vlan_entry_reset_accepts_empty_payload(
    aiohttp_session, target_agent, splat_window,
):
    """CMD_VLAN_ENTRY_RESET (0x0902) uses CDX_CMD_VAR(0, U16_MAX) per
    ISSUES.md A1b item 6 — accepts any length including 0. Should
    succeed (NO_ERR) on an empty payload."""
    r = await target_agent.fci_send(
        aiohttp_session,
        fcode=CMD_VLAN_ENTRY_RESET,
        length=0,
        payload=b"",
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"CMD_VLAN_ENTRY_RESET empty payload should return NO_ERR, got {r}"
    )

"""Validator-table fuzzer for the FCI command bus (A1 surface).

Sends crafted FCI commands straight to the kernel (bypassing libfci) via
the agent's /fci/send endpoint. Every case asserts:

  1. The dispatcher returns a specific error code (ERR_UNKNOWN_COMMAND
     for unknown cmd codes, ERR_WRONG_COMMAND_SIZE for well-known codes
     with the wrong payload size).
  2. No kernel splat fires during the test window (via splat_window
     fixture — UBSAN / KASAN / lockdep / WARN / BUG / PROVE_LOCKING).

The command list is source-driven via _cmd_catalog: it parses every
CDX_CMD / CDX_CMD_V / CDX_CMD_NOARG / CDX_CMD_VAR registration in the
cdx/ tree and cross-references numeric codes from cdx_cmdhandler.h.
Strict-spec commands (exact-length or bounded-range) get fuzz cases;
permissive CDX_CMD_VAR(0, U16_MAX) commands are skipped here (ISSUES.md
A1b item 6 tracks tightening those).

Error codes (from cdx/fe.h):
    NO_ERR                 = 0
    ERR_UNKNOWN_COMMAND    = 1
    ERR_WRONG_COMMAND_SIZE = 2
"""

from __future__ import annotations

import pytest

from _cmd_catalog import build_catalogs


NO_ERR                 = 0
ERR_UNKNOWN_COMMAND    = 1
ERR_WRONG_COMMAND_SIZE = 2

EXACT_CMDS, BOUNDED_CMDS, PERMISSIVE_CMDS = build_catalogs()


# ------------------------------------------------------------------
# Mutation class 1: unknown command code.
# ------------------------------------------------------------------

# Picks span sparse parts of the 16-bit space away from real codes.
# If any of these turn out to actually be registered somewhere, the
# auto-catalog lets us spot it (they'd be in EXACT/BOUNDED/PERMISSIVE).
_KNOWN_CODES = {c for _, c in EXACT_CMDS} | {c for _, c in BOUNDED_CMDS} | {c for _, c in PERMISSIVE_CMDS}
UNKNOWN_CMD_CODES = [
    c for c in (
        0x0000, 0x00FF, 0x01FF, 0x02FF,       # just below subsystem blocks
        0x0200, 0x0300, 0x0400, 0x0500,
        0x0800, 0x0A00, 0x7777, 0xABCD, 0xFFFE, 0xFFFF,
    )
    if c not in _KNOWN_CODES
]


@pytest.mark.parametrize(
    "cmd_code",
    UNKNOWN_CMD_CODES,
    ids=[f"0x{c:04x}" for c in UNKNOWN_CMD_CODES],
)
async def test_fci_unknown_cmd_code(
    aiohttp_session, target_agent, splat_window, cmd_code
):
    """Unknown cmd_code → ERR_UNKNOWN_COMMAND, no splat."""
    reply = await target_agent.fci_send(
        aiohttp_session, fcode=cmd_code, length=0, payload=b"",
    )
    rc = reply.get("reply_rc")
    assert rc == ERR_UNKNOWN_COMMAND, (
        f"cmd_code=0x{cmd_code:04x}: expected rc=ERR_UNKNOWN_COMMAND ({ERR_UNKNOWN_COMMAND}), "
        f"got {rc}; full reply={reply}"
    )


# ------------------------------------------------------------------
# Mutation class 2: exact-spec command + wrong length.
#
# CDX_CMD / CDX_CMD_V / CDX_CMD_NOARG all enforce `length == arg_size`.
# We test length=1 and length=509 — both odd, both small enough to
# stay under FCI_MSG_MAX_PAYLOAD (512) so the fci.c length-validation
# layer doesn't reject first.
# ------------------------------------------------------------------

_EXACT_CASES = [
    (name, code, bad_len)
    for (name, code) in EXACT_CMDS
    for bad_len in (1, 509)
]


@pytest.mark.parametrize(
    "cmd_name,cmd_code,bad_len",
    _EXACT_CASES,
    ids=[f"{n}/len={bl}" for (n, _, bl) in _EXACT_CASES],
)
async def test_fci_exact_spec_wrong_length(
    aiohttp_session, target_agent, splat_window,
    cmd_name, cmd_code, bad_len,
):
    """Exact-spec cmd + length ≠ arg_size → ERR_WRONG_COMMAND_SIZE."""
    reply = await target_agent.fci_send(
        aiohttp_session,
        fcode=cmd_code,
        length=bad_len,
        payload=b"\x00" * bad_len,
    )
    rc = reply.get("reply_rc")
    assert rc == ERR_WRONG_COMMAND_SIZE, (
        f"{cmd_name} (0x{cmd_code:04x}) len={bad_len}: expected rc="
        f"ERR_WRONG_COMMAND_SIZE ({ERR_WRONG_COMMAND_SIZE}), got {rc}; "
        f"full reply={reply}"
    )


# ------------------------------------------------------------------
# Mutation class 3: bounded CDX_CMD_VAR + length below the floor.
#
# For bounded-range specs, length=0 is below any positive min (all
# known bounded commands have min > 0), so it should always be
# rejected. Upper-bound probing would need min-max values — future
# refinement.
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "cmd_name,cmd_code",
    BOUNDED_CMDS,
    ids=[n for n, _ in BOUNDED_CMDS],
)
async def test_fci_bounded_spec_zero_length(
    aiohttp_session, target_agent, splat_window,
    cmd_name, cmd_code,
):
    """Bounded CDX_CMD_VAR + length=0 (below min) → ERR_WRONG_COMMAND_SIZE."""
    reply = await target_agent.fci_send(
        aiohttp_session, fcode=cmd_code, length=0, payload=b"",
    )
    rc = reply.get("reply_rc")
    assert rc == ERR_WRONG_COMMAND_SIZE, (
        f"{cmd_name} (0x{cmd_code:04x}) len=0: expected rc="
        f"ERR_WRONG_COMMAND_SIZE ({ERR_WRONG_COMMAND_SIZE}), got {rc}; "
        f"full reply={reply}"
    )

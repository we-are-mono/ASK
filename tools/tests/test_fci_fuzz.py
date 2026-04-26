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

from _cmd_catalog import build_catalogs, exact_payload_types
from _payload_structs import sizes_for_commands


NO_ERR                 = 0
ERR_UNKNOWN_COMMAND    = 1
ERR_WRONG_COMMAND_SIZE = 2

EXACT_CMDS, BOUNDED_CMDS, PERMISSIVE_CMDS = build_catalogs()
_EXACT_TYPES = exact_payload_types()
EXACT_SIZES  = sizes_for_commands(_EXACT_TYPES)


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


# ------------------------------------------------------------------
# Mutation class 4: payload-body mutations at the correct length.
#
# The dispatcher accepts the length so the handler runs. We don't
# care about the handler's reply rc — handlers may legitimately
# accept or reject mutated payloads. The oracle is the splat_window
# fixture: under KASAN (and UBSAN/lockdep/etc.) the kernel must not
# OOPS / WARN / report OOB on these inputs. Bug class targeted:
#
#   - integer-overflow         : all 0xFF in numeric fields
#   - enum out-of-range        : leading 16-bit field set high
#                                (most cdx commands lead with an
#                                action/mode enum)
#   - string overflow          : trailing fixed-length char arrays
#                                with no NUL terminator
#
# Sizes are derived from sizeof(TYPE) parsed from cdx headers via
# _payload_structs. Commands whose TYPE has fields we can't size
# (function pointers, deeply nested structs) are silently skipped.
#
# Note this test only covers payload bytes — a tighter version would
# generate per-field semantic mutations once a ctypes wrapper exists.
# ------------------------------------------------------------------


def _payload_all_ff(size: int) -> bytes:
    return b"\xff" * size


def _payload_high_enum(size: int) -> bytes:
    # First 2 bytes = 0xFFFF (likely a bogus action/mode), rest 0x00.
    return b"\xff\xff" + b"\x00" * (size - 2) if size >= 2 else b"\xff" * size


def _payload_no_nul_strings(size: int) -> bytes:
    # First 2 bytes = 0x0001 (typical "valid" action), rest 0xFF — fills
    # any trailing char arrays with non-NUL bytes so handlers walking
    # them as C strings run off the end.
    return b"\x01\x00" + b"\xff" * (size - 2) if size >= 2 else b"\xff" * size


_PAYLOAD_MUTATORS = {
    "all_ff":      _payload_all_ff,
    "high_enum":   _payload_high_enum,
    "no_nul_str":  _payload_no_nul_strings,
}


_PAYLOAD_CASES = [
    (name, code, EXACT_SIZES[name], mut_label, mut_fn)
    for (name, code) in EXACT_CMDS
    if name in EXACT_SIZES
    for mut_label, mut_fn in _PAYLOAD_MUTATORS.items()
]


@pytest.mark.parametrize(
    "cmd_name,cmd_code,arg_size,mut_label,mut_fn",
    _PAYLOAD_CASES,
    ids=[f"{n}/{lbl}" for (n, _, _, lbl, _) in _PAYLOAD_CASES],
)
async def test_fci_payload_mutation(
    aiohttp_session, target_agent, splat_window,
    cmd_name, cmd_code, arg_size, mut_label, mut_fn,
):
    """Correct-length / mutated-body must not splat the kernel.

    No assertion on reply_rc — handlers may accept or reject. The
    splat_window fixture catches KASAN/UBSAN/WARN/BUG.
    """
    payload = mut_fn(arg_size)
    assert len(payload) == arg_size  # mutator self-check
    await target_agent.fci_send(
        aiohttp_session,
        fcode=cmd_code,
        length=arg_size,
        payload=payload,
    )

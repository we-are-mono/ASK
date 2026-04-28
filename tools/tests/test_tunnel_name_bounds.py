"""Regression for ISSUES.md A6 (commit 9f9b69d).

Drive CMD_TNL_CREATE / CMD_TNL_DELETE / CMD_TNL_UPDATE with malformed
16-byte tunnel-name fields and assert no kernel splat. Pre-fix, the
CDX tunnel handlers walked cmd.name as a NUL-terminated C string —
HASH_TUNNEL_NAME's `while (*tnlname)` and a follow-up strcmp() ran
past the end of a 16-byte payload that had no NUL, KASAN-flagging a
stack-OOB read in tnl_delete_handle. The fix bounded both walks to
sizeof(name)=16; this test wires the malformed inputs directly so the
A6 path stays gated against re-introduction.

Oracle: splat_window. The handlers may accept or reject however they
like (ERR_TNL_ENTRY_NOT_FOUND / ERR_TNL_NOT_SUPPORTED / NO_ERR are
all fine); the contract under test is only that the kernel survives
without OOB read, UAF, or UBSAN type confusion. The auto-fuzzer
(test_fci_fuzz.py / no_nul_str mutator) covers the high-byte all-FF
shape on first run under KASAN; this file pins the regression
explicitly and adds the embedded-NUL and over-length-claim shapes
the generic fuzzer doesn't generate.
"""

from __future__ import annotations

import struct

import pytest


CMD_TNL_CREATE = 0x0B01
CMD_TNL_DELETE = 0x0B02
CMD_TNL_UPDATE = 0x0B03

TNL_MODE_6O4 = 1


def _ip_be_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _tnl_create_payload(name_field: bytes) -> bytes:
    """TNLCommand_create with a caller-supplied 16-byte name field."""
    assert len(name_field) == 16
    local_field  = _ip_be_bytes("10.0.0.62")  + b"\x00" * 12
    remote_field = _ip_be_bytes("10.0.0.141") + b"\x00" * 12
    output_field = b"eth3".ljust(16, b"\x00")
    tail = struct.pack(
        "<BBBBIHHIHBB",
        TNL_MODE_6O4, 0, 0, 64,  # mode, secure, elim, hlim
        0, 0, 0,                 # fl, frag_off, enabled
        0, 1480, 0,              # route_id, mtu, flags
        0,                       # pad
    )
    wire = name_field + local_field + remote_field + output_field + tail
    assert len(wire) == 84
    return wire


def _tnl_delete_payload(name_field: bytes) -> bytes:
    assert len(name_field) == 16
    return name_field


# Each case: (label, 16-byte name field). Names exercise the four shapes
# the post-9f9b69d HASH_TUNNEL_NAME / strncmp pair must tolerate without
# walking off the end of the field.
_NAME_CASES = [
    # All 0xFF — no NUL anywhere. Pre-fix this is what KASAN caught:
    # the hash loop walked past byte 16 into adjacent stack.
    ("no_nul_all_ff",      b"\xff" * 16),

    # NUL at offset 0 — degenerate empty-name. Hash returns 0;
    # strncmp(_, _, 16) compares zero bytes; equality on the first
    # entry would be a false positive — the lookup must reject.
    ("nul_at_offset_0",    b"\x00" * 16),

    # All-NUL except a single high byte at offset 15 — looks empty
    # to a strlen() but the bounded walk should still hash byte 15.
    ("nul_then_trailing",  b"\x00" * 15 + b"\xff"),

    # ASCII with no NUL — looks like a valid name to a careless
    # strcmp() but blows past the field end without bounding.
    ("ascii_no_nul",       b"ABCDEFGHIJKLMNOP"),

    # Mixed printable + binary, NUL embedded mid-field — the bounded
    # walk should stop at the NUL; the strncmp tail beyond it must
    # not be reached.
    ("nul_at_offset_3",    b"abc\x00\xff" + b"\xde\xad\xbe\xef" * 2 + b"\xff\xff\xff"),
]


@pytest.mark.parametrize(
    "label,name_field",
    _NAME_CASES,
    ids=[lbl for lbl, _ in _NAME_CASES],
)
async def test_tunnel_create_malformed_name(
    aiohttp_session, target_agent, splat_window,
    label, name_field,
):
    """CREATE with malformed name — kernel must not splat. Reply rc is
    handler's prerogative; we only gate on the splat oracle."""
    payload = _tnl_create_payload(name_field)
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_TNL_CREATE,
        length=len(payload), payload=payload, timeout_ms=2000,
    )
    # Best-effort cleanup: if CREATE somehow succeeded with this name,
    # leave the entry behind for a subsequent DELETE-with-same-name run
    # to clean up. The splat oracle is the only test contract here.


@pytest.mark.parametrize(
    "label,name_field",
    _NAME_CASES,
    ids=[lbl for lbl, _ in _NAME_CASES],
)
async def test_tunnel_delete_malformed_name(
    aiohttp_session, target_agent, splat_window,
    label, name_field,
):
    """DELETE was the original A6 site — KASAN caught the OOB read in
    HASH_TUNNEL_NAME() called from M_tnl_get_by_name() out of
    tnl_delete_handle()."""
    payload = _tnl_delete_payload(name_field)
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_TNL_DELETE,
        length=len(payload), payload=payload, timeout_ms=2000,
    )


@pytest.mark.parametrize(
    "label,name_field",
    _NAME_CASES,
    ids=[lbl for lbl, _ in _NAME_CASES],
)
async def test_tunnel_update_malformed_name(
    aiohttp_session, target_agent, splat_window,
    label, name_field,
):
    """UPDATE shares the M_tnl_get_by_name() lookup with DELETE — same
    fix, same regression coverage."""
    payload = _tnl_create_payload(name_field)
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_TNL_UPDATE,
        length=len(payload), payload=payload, timeout_ms=2000,
    )

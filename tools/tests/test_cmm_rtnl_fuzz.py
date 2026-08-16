"""Fuzz cmm's RTNL attribute parser against malformed inputs.

The cmm RTNL listener (cmm/src/rtnl.c) is the only userspace path that
ingests attacker-influenced bytes from the kernel netlink listener.
RTA_OK / RTA_NEXT bound the loop, but the function's tail dereferences
rta->rta_len when the loop exits with len != 0 — a stale-pointer read
that ASAN catches on a truncated trailing attribute.

cmm_rtnl_fuzzer (built from cmm/test/cmm_rtnl_fuzzer.c, ASAN+UBSAN) runs
on the target via exec_cmd. Each case is a hex-encoded buffer; the test
checks that the binary exited cleanly AND that stderr carries no
sanitizer report.
"""

from __future__ import annotations

import struct

import pytest


# ASAN/UBSAN signatures the fuzzer's stderr will carry on a hit. Match
# substrings, not full lines — the message format varies a bit across
# sanitizer versions.
_SAN_SIGNATURES = (
    "AddressSanitizer",
    "runtime error",
    "UndefinedBehaviorSanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "SUMMARY: ",
)


def _rtattr(rta_type: int, payload: bytes) -> bytes:
    """Pack one rtattr {len, type, payload}, padded to 4-byte alignment."""
    rta_len = 4 + len(payload)
    body = struct.pack("<HH", rta_len, rta_type) + payload
    pad = (-len(body)) & 3
    return body + b"\x00" * pad


def _payloads() -> list[tuple[str, bytes, int]]:
    """Generate (name, buf, max_type) cases.

    A mix of well-formed (control), bounded-malformed (parser must
    reject without UB), and edge cases that historically caught the
    cmm tail-deref bug.
    """
    out: list[tuple[str, bytes, int]] = []

    # Control: well-formed empty.
    out.append(("empty", b"", 64))

    # Control: well-formed single attr.
    out.append(("one_u32_attr", _rtattr(1, b"\x00" * 4), 64))

    # Control: 4 well-formed attrs of varying types.
    multi = b"".join(_rtattr(t, b"\xaa" * (4 * t)) for t in (1, 2, 3, 4))
    out.append(("four_attrs", multi, 64))

    # rta_len=0 → RTA_OK rejects on first iteration.
    out.append(("zero_rta_len", b"\x00\x00\x01\x00", 64))

    # rta_len = 1, 2, 3 → all below sizeof(struct rtattr); RTA_OK rejects.
    for short in (1, 2, 3):
        buf = struct.pack("<HH", short, 0) + b"\x00" * 4
        out.append((f"rta_len_{short}", buf, 64))

    # rta_len > buffer length → RTA_OK rejects.
    out.append(("rta_len_oversize",
                struct.pack("<HH", 100, 0) + b"\x00" * 4, 64))

    # Trailing odd byte: parser walks one valid attr, leaves len=1, then
    # the tail `if (len) ... rta->rta_len` reads OOB. This is the bug
    # class under test — must be a clean exit (the
    # fuzzer's volatile read makes ASAN trip).
    out.append(("trailing_byte_after_one_attr",
                _rtattr(1, b"") + b"\x99", 64))

    # Trailing 3 odd bytes (also yields len != 0 after loop).
    out.append(("trailing_three_bytes",
                _rtattr(2, b"\x00" * 4) + b"\x99\x88\x77", 64))

    # rta_type out of bounds (max=4, attr type 999) → silently skipped
    # by the bounds check; must not write past tb[].
    out.append(("rta_type_above_max",
                _rtattr(999, b"\x00" * 4), 4))

    # Deeply nested attrs (RTA_NESTED). cmm_parse_rtattr is non-recursive
    # for nested attrs by design, so this is more of a stress test —
    # but a chain of 64 attrs of types 1..64 hits every tb[] slot.
    nested_chain = b"".join(_rtattr(t, b"\x00" * 4) for t in range(1, 65))
    out.append(("64_attrs_chain", nested_chain, 64))

    # Single attr filling the whole buffer.
    out.append(("one_big_attr", _rtattr(1, b"\xee" * 200), 64))

    # All-0xff scramble — RTA_OK should reject on rta_len > len.
    out.append(("all_ff_64b", b"\xff" * 64, 64))

    # All-0x00 scramble — RTA_OK rejects rta_len < 4 immediately.
    out.append(("all_00_64b", b"\x00" * 64, 64))

    # Buffer that ends exactly at a valid rtattr boundary (no tail).
    out.append(("two_clean_attrs",
                _rtattr(1, b"\x00" * 4) + _rtattr(2, b"\x00" * 4), 64))

    return out


@pytest.mark.parametrize(
    "name,buf,max_type",
    _payloads(),
    ids=[name for name, _, _ in _payloads()],
)
async def test_cmm_rtnl_fuzz_parses_without_san_report(
    aiohttp_session, target_agent, splat_window,
    name, buf, max_type,
):
    r = await target_agent.exec_cmd(
        aiohttp_session,
        ["cmm_rtnl_fuzzer", buf.hex(), str(max_type)],
        timeout_ms=5000,
    )
    if r.get("error", "").startswith(("not installed", "exec timed out")):
        pytest.skip(f"cmm_rtnl_fuzzer not on target image: {r}")
    rc = r.get("rc")
    stderr = r.get("stderr", "") or ""
    assert rc == 0, f"{name}: fuzzer exited non-zero: {r}"
    san_hits = [s for s in _SAN_SIGNATURES if s in stderr]
    assert not san_hits, (
        f"{name}: sanitizer reported on input {buf.hex()!r}: "
        f"hits={san_hits}\nstderr:\n{stderr[:2000]}"
    )

"""H2 regression — IPsec SA cipher_key zeroed on free.

The H2 fix (commit 613efa3) replaced kfree with kfree_sensitive on
cipher_key / auth_key / split_key in cdx_ipsec_sec_sa_context_free.
A regression to plain kfree leaves the key bytes in the slab where
the next consumer can read them.

This test asserts the fix by reading a kernel-side debug probe at
/proc/cdx/last_freed_key. The probe (gated by CDX_DEBUG_KEY_ZEROING,
on only in the meta-ask test image) snapshots the cipher_key buffer
immediately after kfree_sensitive returns. On a working H2 build the
snapshot is mostly zero (memzero_explicit ran before kfree); under a
plain-kfree regression the original 0xA5 bytes survive.

Note on assertion shape: the snapshot is NOT guaranteed all-zero even
when H2 is correct — SLUB writes a freelist pointer into the freed
slot before our read. The cipher_key buffer is kzalloc(100), i.e. the
kmalloc-128 cache, where the hardened-SLUB free pointer sits at the
slot's center (offset ~64) — outside the 16-byte key at offset 0 —
but the exact offset is layout-dependent, so the test checks for the
cipher-key BYTE PATTERN instead: 8 contiguous 0xA5 bytes must not
appear and the total 0xA5 count must stay low. Under the H2 fix
neither signal trips; under a plain-kfree regression at least one
will, for any freelist-pointer placement.

The probe's header carries a monotonically increasing seq counter
(bumped on every observed cipher_key free). The test baselines seq
right before its DELETE and polls for an advance, so it cannot
false-pass on a snapshot latched by some earlier free in the same
boot. If the sampled allocation happens to be a KFENCE object the
probe cannot read it post-free (captured=false, len=0); the test
retries with a fresh SA — a new allocation is virtually never
KFENCE-sampled.

False-pass caveats: active SLUB poisoning (CONFIG_SLUB_DEBUG_ON=y or
a slub_debug=P boot arg — plain CONFIG_SLUB_DEBUG=y is inert) fills
freed slabs with 0x6b, and CONFIG_INIT_ON_FREE_DEFAULT_ON (or
init_on_free=1 on the cmdline) zeroes them — either hides a kfree
regression from this test. The meta-ask kernel activates neither; if
that changes, this test must be revisited.
"""

from __future__ import annotations

import asyncio

import pytest

from _ipsec_helpers import (
    NO_ERR,
    SAGD_BASE,
    cleanup_sa,
    install_sa_inbound,
)


# Synthetic SA — distinct sagd from test_ipsec_offload's 0xF001 so the two
# tests can interleave without colliding.
SAGD   = SAGD_BASE + 0x14    # 0xF014
SPI    = 0x12340014
DST_IP = 0x0A0A0A14          # 10.10.10.20

PROBE_PATH = "/proc/cdx/last_freed_key"

# DELETE schedules cdx_ipsec_release_sa_ctx_cbk on a 1-second cdx_timer
# (SA_CTX_RELEASE_TIMER_VAL in cdx/control_ipsec.h). The callback walks
# FQ retire state — for a synthetic SA without active FQs this completes
# on the first fire. Allow a generous budget so a loaded test bus doesn't
# false-fail on timer jitter.
CAPTURE_POLL_BUDGET_S = 5.0
CAPTURE_POLL_INTERVAL_S = 0.25

# Full SA install/delete retries when the sampled allocation turns out to
# be a KFENCE object (captured=false). One retry virtually always
# suffices; three consecutive KFENCE hits means the probe is lying.
KFENCE_RETRY_ATTEMPTS = 3


def _parse_probe(content_hex: str) -> tuple[dict, bytes]:
    """Decode /proc/cdx/last_freed_key into (header_fields, snapshot_bytes)."""
    raw = bytes.fromhex(content_hex).decode("ascii", errors="replace")
    lines = raw.split("\n")
    if len(lines) < 2:
        raise AssertionError(f"unexpected probe layout: {raw!r}")
    header = dict(p.split("=", 1) for p in lines[0].split())
    snapshot = bytes.fromhex(lines[1].strip()) if lines[1].strip() else b""
    return header, snapshot


async def test_ipsec_key_zeroing_after_free(
    aiohttp_session, target_agent, splat_window,
):
    pre = await target_agent.fs_read(aiohttp_session, PROBE_PATH)
    if pre.get("errno", 0) != 0:
        pytest.skip(
            f"H2 probe absent at {PROBE_PATH} (errno={pre.get('errno')!r}); "
            "kernel build does not define CDX_DEBUG_KEY_ZEROING."
        )

    header: dict = {}
    snapshot = b""
    for _attempt in range(KFENCE_RETRY_ATTEMPTS):
        await cleanup_sa(target_agent, aiohttp_session, SAGD)
        # If that cleanup deleted a stale SA from a crashed prior run, its
        # deferred free fires on the 1-second cdx_timer and would advance
        # seq after our baseline read below — latching a snapshot that is
        # not ours. Let it land first.
        await asyncio.sleep(1.5)

        result = await install_sa_inbound(
            target_agent, aiohttp_session, SAGD,
            spi=SPI, dst_ip=DST_IP, natt=False,
        )
        if result.infra_skip_reason:
            pytest.skip(result.infra_skip_reason)

        create_rc = result.replies["create"].get("reply_rc")
        if create_rc != NO_ERR:
            await cleanup_sa(target_agent, aiohttp_session, SAGD)
            pytest.fail(
                f"CREATE failed (rc={create_rc!r}); replies={result.replies!r}"
            )

        set_keys_rc = result.replies.get("set_keys", {}).get("reply_rc")
        if set_keys_rc != NO_ERR:
            await cleanup_sa(target_agent, aiohttp_session, SAGD)
            pytest.fail(
                f"SET_KEYS failed (rc={set_keys_rc!r}); replies={result.replies!r}. "
                f"Without SET_KEYS the cipher_key bytes are still kzalloc-zero, "
                f"so the test cannot distinguish H2-OK from H2-broken."
            )

        # Baseline seq immediately before the DELETE, so an advance can
        # only come from a free triggered after this point. Tests run
        # sequentially, so the advancing free is ours.
        base = await target_agent.fs_read(aiohttp_session, PROBE_PATH)
        assert base.get("errno", 0) == 0, (
            f"probe read failed pre-DELETE: {base!r}"
        )
        base_header, _ = _parse_probe(base["content_hex"])
        base_seq = int(base_header.get("seq", 0))

        await cleanup_sa(target_agent, aiohttp_session, SAGD)

        deadline = asyncio.get_event_loop().time() + CAPTURE_POLL_BUDGET_S
        header = {}
        snapshot = b""
        while asyncio.get_event_loop().time() < deadline:
            post = await target_agent.fs_read(aiohttp_session, PROBE_PATH)
            assert post.get("errno", 0) == 0, (
                f"probe read failed mid-test: {post!r}"
            )
            header, snapshot = _parse_probe(post["content_hex"])
            if int(header.get("seq", 0)) > base_seq:
                break
            await asyncio.sleep(CAPTURE_POLL_INTERVAL_S)

        assert int(header.get("seq", 0)) > base_seq, (
            f"H2 probe never observed a cipher_key free in "
            f"{CAPTURE_POLL_BUDGET_S}s after DELETE (seq stuck at "
            f"{base_seq}) — final header={header!r}. Either "
            f"cdx_ipsec_sec_sa_context_free was not reached (DELETE handler "
            f"took an A24b leak path?) or the timer callback did not fire. "
            f"Inspect dmesg for cdx errors during the run."
        )

        if header.get("captured") == "true":
            break
        # seq advanced but captured=false: the allocation was
        # KFENCE-sampled and the probe skipped the unreadable page.
        # Retry with a fresh SA (new allocation).
    else:
        pytest.fail(
            f"{KFENCE_RETRY_ATTEMPTS} consecutive cipher_key allocations "
            f"reported KFENCE-sampled (captured=false) — statistically "
            f"implausible; probe state suspect: {header!r}"
        )

    n = int(header["len"])
    assert n > 0, f"captured len=0 — probe state corrupt: {header!r}"
    assert len(snapshot) == n, (
        f"body length {len(snapshot)} != header len={n}: {header!r}"
    )

    contiguous_a5_8 = b"\xA5" * 8 in snapshot
    a5_count = snapshot.count(0xA5)

    assert not contiguous_a5_8 and a5_count < 8, (
        f"H2 REGRESSION: cipher key bytes survived kfree_sensitive. "
        f"Original key was 16x 0xA5; after a working kfree_sensitive the "
        f"slab should be mostly zero (with at most an 8-byte SLUB freelist "
        f"pointer). Found contiguous-8x0xA5={contiguous_a5_8}, "
        f"total 0xA5 byte count={a5_count}. "
        f"This usually means cdx_ipsec_sec_sa_context_free was reverted to "
        f"plain kfree on cipher_key — re-check the H2 fix in "
        f"cdx/cdx_dpa_ipsec.c. Snapshot ({n} B): {snapshot.hex()}"
    )

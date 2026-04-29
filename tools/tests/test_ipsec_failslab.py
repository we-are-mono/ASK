"""Failslab sweep over CMD_IPSEC_SA_CREATE — M7-class regression net.

Drives cdx_ipsec_sec_sa_context_alloc (cdx/cdx_dpa_ipsec.c) into NULL via
fork-isolated failslab. The five kzalloc(GFP_KERNEL) sites are reached
during CREATE — invoked from M_ipsec_sa_cache_create immediately after
sa_alloc(). On NULL the allocator's unwind unmaps prior DMA maps and
frees prior key buffers; the caller then sa_free()s the SA struct.

Oracles:
  - splat_window — no oops/lockdep/UBSAN/KASAN reports during the sweep.
  - kmemleak (filtered to IPSEC_LEAK_FILTER) — zero leaks across the
    faulted-iteration unwind paths.

Per-iteration unique sagd avoids same-sagd state conflicts in case any
allocator path leaves internal proc/sysfs entries half-built.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from _ipsec_helpers import (
    CMD_IPSEC_SA_CREATE,
    CMD_IPSEC_SA_DELETE,
    ERR_CREATION_FAILED,
    ERR_NOT_ENOUGH_MEMORY,
    IPSEC_LEAK_FILTER,
    NO_ERR,
    SAGD_BASE,
    create_sa,
    delete_sa,
)


# IPsec_handle_CREATE_SA returns ERR_CREATION_FAILED when M_ipsec_sa_cache_create
# returns NULL — the path the cdx_ipsec_sec_sa_context_alloc fault takes us
# down. ERR_NOT_ENOUGH_MEMORY shows up if a different (earlier) kmalloc faults
# while reply assembly. None / send_error is the faulted-too-early case
# where the reply itself didn't make it back.
def _is_faulted(rc, send_error) -> bool:
    if send_error is not None:
        return True
    if rc is None:
        return True
    return rc in (ERR_CREATION_FAILED, ERR_NOT_ENOUGH_MEMORY)


# Synthetic SA range — sweep iter `n` uses sagd = SAGD_BASE_SWEEP + n. Sit
# above the offload test's 0xF001 so a leftover from one doesn't block the
# other; below the bounds test's range to keep ranges non-overlapping.
SAGD_BASE_SWEEP = SAGD_BASE + 0x100  # 0xF100..0xF1FF for NSWEEP up to 256
SPI_BASE        = 0xFA1AB000
DST_IP          = 0x0A0A0A11    # 10.10.10.17

NSWEEP = int(os.environ.get("ASK_IPSEC_FAILSLAB_SWEEP", "100"))
# IPsec SA cleanup is deferred via cdx_ipsec_release_sa_resources →
# 1s timer → cdx_ipsec_release_sa_ctx_cbk → reschedule for another 1s
# if any FQ isn't yet in retired state. Under rapid sweep pressure that
# can take 5-15 reschedules per SA. 30s gives plenty of headroom for
# the steady-state cleanup to drain before kmemleak reports.
KMEMLEAK_AGE_GRACE_S = float(os.environ.get("ASK_IPSEC_KMEMLEAK_GRACE_S", "30.0"))


async def test_ipsec_create_failslab_sweep(
    aiohttp_session, target_agent, splat_window,
):
    async def _delete(sagd: int) -> None:
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IPSEC_SA_DELETE,
            length=4, payload=delete_sa(sagd), timeout_ms=2000,
        )

    async def _create(sagd: int, spi: int, *, failslab: int | None = None) -> dict:
        kwargs = {}
        if failslab is not None:
            kwargs["failslab_times"] = failslab
        payload = create_sa(sagd, spi, DST_IP)
        return await target_agent.fci_send(
            aiohttp_session, fcode=CMD_IPSEC_SA_CREATE,
            length=len(payload), payload=payload, timeout_ms=3000, **kwargs,
        )

    # Pre-probe: one unencumbered CREATE → DELETE roundtrip on a probe
    # sagd. Skip if CREATE returns infra-class error; sweep can't reach
    # cdx_ipsec_sec_sa_context_alloc otherwise.
    probe_sagd = SAGD_BASE_SWEEP - 1
    await _delete(probe_sagd)
    probe = await _create(probe_sagd, SPI_BASE - 1)
    if probe.get("reply_rc") != NO_ERR:
        await _delete(probe_sagd)
        pytest.skip(
            f"unencumbered CREATE returned reply_rc={probe.get('reply_rc')!r}"
            f" — CAAM/DPAA infra likely not ready, sweep can't reach "
            f"cdx_ipsec_sec_sa_context_alloc. send_error="
            f"{probe.get('send_error')!r}"
        )
    await _delete(probe_sagd)

    await target_agent.kmemleak_clear(aiohttp_session)
    outcomes: list[tuple[int, int | None, str | None]] = []
    attempted_sagds: list[int] = []

    try:
        for n in range(1, NSWEEP + 1):
            sagd = SAGD_BASE_SWEEP + n
            spi  = SPI_BASE + n
            attempted_sagds.append(sagd)
            r = await _create(sagd, spi, failslab=n)
            outcomes.append((n, r.get("reply_rc"), r.get("send_error")))
    finally:
        # DELETE every attempted sagd — even iters where the user-side
        # reply was lost (rc=None / ENOBUFS) might have created the SA in
        # the kernel before the reply path faulted. Best-effort sweep so
        # any surviving kmemleak signal is from genuinely-unwound paths,
        # not from undeleted SAs we forgot to clean up.
        for sagd in attempted_sagds:
            await _delete(sagd)

    faulted = [n for n, rc, e in outcomes if _is_faulted(rc, e)]
    if not faulted:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"NSWEEP={NSWEEP} did not produce any faulted iteration "
            f"(rc \u2208 {{ERR_NOT_ENOUGH_MEMORY=6, ERR_CREATION_FAILED=7, "
            f"None}} or send_error). Either the allocator moved to a deeper "
            f"slot in the call chain (regression worth investigating in "
            f"control_ipsec.c \u2192 cdx_dpa_ipsec.c handler depth) or raise "
            f"NSWEEP via ASK_IPSEC_FAILSLAB_SWEEP=200 and confirm. "
            f"Per-step outcomes: {outcome_summary}."
        )

    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=IPSEC_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    if leak_count:
        outcome_summary = ", ".join(
            f"{n}={'OK' if rc == NO_ERR and e is None else (f'rc={rc}' if e is None else e)}"
            for n, rc, e in outcomes
        )
        raise AssertionError(
            f"failslab CREATE sweep (1..{NSWEEP}) leaked {leak_count} "
            f"ipsec-path object(s); {len(faulted)} iteration(s) hit a "
            f"fault.\nPer-step outcomes: {outcome_summary}\n\n"
            + report.get("report", "")[:4000]
        )

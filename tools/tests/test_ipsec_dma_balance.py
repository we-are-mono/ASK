"""H3 regression — the SET_STATE fast-path push unwinds cleanly under failslab.

Mechanism (this corrects the earlier "needs a real-peer fixture" note — the
block was never the peer). A synthetic SA's *fabricated* dst_ip never matched
a DUT interface, so dpa_get_iface_info_by_ipaddress (devman.c:830,
`if_info->ifa_local == *daddr`) failed and the push short-circuited before any
fast-path allocation ran. Setting the SA's daddr to a DUT-local WAN address
clears that lookup, and CMD_IPSEC_SA_SET_STATE then drives
ipsec_push_sa_to_fast_path → cdx_ipsec_add_classification_table_entry — the
function the H3 fix (613efa3) hardened:

  - the info / sa->ct kzalloc unwind (cdx_dpa_ipsec.c:2377 / :2387 → err_ret
    at :2603, which frees both and rolls back SA_SH_DESC_BUILT at :2608), and
  - cdx_ipsec_create_shareddescriptor (call site :2506) with its
    err_unmap_crypto / err_unmap_auth DMA-map unwind.

All pure FCI: no xfrm_state, no strongSwan, no ESP traffic. A synthetic SA's
SET_STATE still returns ERR_CREATION_FAILED — ipsec_push_sa_to_fast_path's
xfrm_state lookup (control_ipsec.c:766, xfrm_state_lookup_byhandle by the
sagd) finds no kernel state for a handle we never registered, so it tears the
entry back down — but that failure is *after* the guarded allocations run, so
the unwind under failslab is exercised regardless. ERR_CREATION_FAILED here is
the expected clean-failure outcome, not an infra skip.

The test sweeps failslab `times` over the SET_STATE step (CREATE + SET_KEYS run
unencumbered) so successive kmallocs on the push path are driven to NULL, then
asserts — via the DMA-extended kmemleak filter and the splat window — that
nothing on the unwound path leaks a DMA map / key buffer / hw_ct or trips a
sanitizer.

Target site + reachability — CONFIRM ON A LIVE RUN:
  - Target is the :2506 (lone non-NAT-T inbound SA) call site, NOT the :2306
    NAT-T-second-SA site: :2306 sits inside the `natt_sa && natt_sa->ct`
    branch, and a synthetic NAT-T twin can never keep a populated ct (its push
    fails the same xfrm_state lookup and cdx_ipsec_delete_fp_entry nulls the
    ct), so that branch is unreachable without a real xfrm_state. The lone-SA
    :2506 path has no such dependency.
  - The info / sa->ct kzallocs (:2377 / :2387) precede every runtime gate, so
    failslab always exercises that unwind once the push is entered — this is
    the part guaranteed to have signal.
  - cdx_ipsec_create_shareddescriptor (:2506) is reached only when the WAN
    port carries the ESP-IPv4 classification table (dpa_get_tdinfo, :2430) and
    the PCD is loaded (dpa_get_pcdhandle, :2397). On the ASK test image both
    hold; if not, SET_STATE fails earlier at the td lookup and the deeper site
    isn't reached (the info/ct unwind still is).
  - create_shareddescriptor takes only dma_map_single (no slab alloc in its
    tree — cdx_ipsec_build_shared_descriptor / _build_in_sa_pdb operate on
    pre-allocated buffers), so failslab cannot fault *inside* it, and its
    err_unmap labels guard a descriptor-overflow path that supported ciphers
    (AES-CBC + HMAC-SHA256) never take. The DMA leak filter is therefore a
    tripwire on those maps, not a path this sweep drives directly.

Best run under KASAN (KASAN=1 kas build) so a use-after-unmap on the DMA maps
or a slab overflow on the unwound key buffers is caught too.
"""

from __future__ import annotations

import asyncio
import os
import warnings

import pytest

from _ipsec_helpers import (
    IPSEC_DMA_LEAK_FILTER,
    NO_ERR,
    SAGD_BASE,
    cleanup_sa,
    install_sa_inbound,
    resolve_dut_local_ipv4,
)
from _topology import TARGET_WAN_IF


# Sweep sagd range sits above the failslab sweep's 0xF100..0xF1FF and the
# bounds test's reserved 0xF200..0xF2FF so a leftover from one test can't
# collide with another. 0xF300..0xF3FF covers NSWEEP up to 255.
SAGD_BASE_SWEEP = SAGD_BASE + 0x300   # 0xF300
SPI_BASE        = 0xD3A00000          # distinct from the CREATE-sweep's SPI base

NSWEEP = int(os.environ.get("ASK_IPSEC_DMA_SWEEP", "100"))
# IPsec SA cleanup is deferred (cdx_ipsec_release_sa_resources → 1s timer,
# rescheduled while any FQ isn't retired). Under sweep pressure that can take
# several reschedules per SA; 30s lets steady-state cleanup drain before the
# kmemleak scan so a still-in-flight free isn't misread as a leak.
KMEMLEAK_AGE_GRACE_S = float(os.environ.get("ASK_IPSEC_KMEMLEAK_GRACE_S", "30.0"))


async def test_ipsec_set_state_dma_balance(
    aiohttp_session, target_agent, splat_window,
):
    """Sweep failslab over SET_STATE for a DUT-local-daddr inbound SA; assert
    the push-path unwind leaks no DMA map / key / hw_ct and trips no sanitizer."""
    # A DUT-local WAN address makes dpa_get_iface_info_by_ipaddress resolve, so
    # the push proceeds into cdx_ipsec_add_classification_table_entry instead of
    # bailing at the daddr match. ASK_IPSEC_LOCAL_IP overrides the live query.
    try:
        local_ip, dst_ip = await resolve_dut_local_ipv4(
            target_agent, aiohttp_session, TARGET_WAN_IF)
    except RuntimeError as e:
        pytest.skip(str(e))

    # Pre-probe: one unencumbered install on a probe sagd. Skip only if CREATE
    # is infra-blocked (CAAM/DPAA not up) — a synthetic SA's SET_STATE returning
    # ERR_CREATION_FAILED is EXPECTED (no kernel xfrm_state) and is not a skip.
    probe_sagd = SAGD_BASE_SWEEP - 1
    await cleanup_sa(target_agent, aiohttp_session, probe_sagd)
    probe = await install_sa_inbound(
        target_agent, aiohttp_session, probe_sagd,
        spi=SPI_BASE - 1, dst_ip=dst_ip, natt=False,
    )
    await cleanup_sa(target_agent, aiohttp_session, probe_sagd)
    if probe.infra_skip_reason:
        pytest.skip(probe.infra_skip_reason)
    probe_create_rc = probe.replies.get("create", {}).get("reply_rc")
    if probe_create_rc != NO_ERR:
        pytest.skip(
            f"unencumbered CREATE returned reply_rc={probe_create_rc!r} on "
            f"daddr={local_ip} — CAAM/DPAA infra likely not ready; the sweep "
            f"can't reach the SET_STATE push path"
        )
    # SET_STATE must actually have run on the probe (CREATE + SET_KEYS ok), else
    # the sweep would exercise nothing.
    if "set_state" not in probe.replies:
        pytest.skip(
            f"unencumbered install never reached SET_STATE on daddr={local_ip}; "
            f"replies={probe.replies!r} — a wire-layout or infra issue, not a "
            f"failslab result"
        )

    await target_agent.kmemleak_clear(aiohttp_session)

    # (n, set_state reply_rc, set_state send_error, create reply_rc)
    outcomes: list[tuple[int, int | None, str | None, int | None]] = []
    attempted: list[int] = []
    try:
        for n in range(1, NSWEEP + 1):
            sagd = SAGD_BASE_SWEEP + n
            attempted.append(sagd)
            res = await install_sa_inbound(
                target_agent, aiohttp_session, sagd,
                spi=SPI_BASE + n, dst_ip=dst_ip, natt=False,
                failslab_step="set_state", failslab_times=n,
            )
            ss = res.replies.get("set_state", {})
            outcomes.append((
                n, ss.get("reply_rc"), ss.get("send_error"),
                res.replies.get("create", {}).get("reply_rc"),
            ))
            # CREATE runs unencumbered here, so each iteration leaves a real SA
            # (SEC context + DPAA FQs) in the cache; delete it now rather than
            # holding NSWEEP of them concurrently. The SET_STATE failure never
            # removes the SA itself, so this DELETE is what frees it.
            await cleanup_sa(target_agent, aiohttp_session, sagd)
    finally:
        # Safety net for an interrupted loop: idempotent DELETE over the whole
        # attempted range so any surviving kmemleak signal is a genuine unwind
        # leak, not an SA we simply forgot to remove.
        for sagd in attempted:
            await cleanup_sa(target_agent, aiohttp_session, sagd)

    # Non-vacuity gate: SET_STATE was actually driven on at least one iteration
    # (CREATE + SET_KEYS succeeded so the failslab-armed SET_STATE could reach
    # the push). Without this the sweep would exercise nothing.
    reached = [o for o in outcomes if o[1] is not None or o[2] is not None]
    assert reached, (
        f"no sweep iteration reached SET_STATE (create rc across sweep: "
        f"{sorted({o[3] for o in outcomes})}) — sweep exercised nothing"
    )

    # Clean-failure invariant: a synthetic SA can never push to the fast path
    # cleanly (its xfrm_state lookup at control_ipsec.c:766 is always NULL), so
    # no iteration that reached SET_STATE may report NO_ERR — every one must be
    # a reported failure (ERR_CREATION_FAILED baseline, or a lost/short reply
    # under fault), never a hang and never a spurious success. A NO_ERR here
    # would mean a real xfrm_state exists for a test-reserved sagd, or the push
    # invariant changed — surface it rather than swallow it.
    clean_success = [(n, rc) for (n, rc, se, _cr) in outcomes if rc == NO_ERR]
    assert not clean_success, (
        f"SET_STATE returned NO_ERR on synthetic SA(s) {clean_success!r} — a "
        f"synthetic install can't complete the fast-path push (no kernel "
        f"xfrm_state for the sagd). Stale xfrm state on the DUT, or a change to "
        f"the push invariant? outcomes={outcomes}"
    )

    # Failslab-fired signal (best-effort, NOT a hard gate): a lost/short reply
    # (send_error, or rc None) unambiguously means the injected NULL hit an
    # allocation early on the send path — positive proof failslab is arming.
    # Its ABSENCE is inconclusive, not a failure: failslab only faults
    # GFP_KERNEL allocations, so a sweep whose faults all land on the handler's
    # kzallocs surfaces as ERR_CREATION_FAILED (indistinguishable from the
    # synthetic baseline) yet still exercised the unwind. Warn so a silently
    # broken failslab is visible without turning a clean run red.
    fired = [(n, se) for (n, rc, se, _cr) in outcomes if se is not None or rc is None]
    if not fired:
        warnings.warn(
            f"failslab times=1..{NSWEEP} produced no lost/short reply — could "
            f"not positively confirm the fault reached the send path (all "
            f"replies were handler-level rc). kmemleak + splat oracles still "
            f"ran. If this persists, verify failslab arms on the SET_STATE "
            f"send and that the WAN ESP table / PCD is present on {TARGET_WAN_IF}."
        )

    # Oracle: no leaked DMA maps / key buffers / hw_ct from the unwound push.
    await asyncio.sleep(KMEMLEAK_AGE_GRACE_S)
    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=IPSEC_DMA_LEAK_FILTER,
    )
    leak_count = report.get("leak_count", 0)
    assert not leak_count, (
        f"SET_STATE failslab sweep (1..{NSWEEP}) leaked {leak_count} "
        f"ipsec/DMA object(s) on the push-path unwind; "
        f"{len(fired)} iteration(s) showed a lost/short reply.\n"
        + report.get("report", "")[:4000]
    )
    # splat_window (fixture) independently asserts no KASAN/BUG/UBSAN/lockdep
    # report fired during the sweep — the use-after-unmap / OOB oracle.

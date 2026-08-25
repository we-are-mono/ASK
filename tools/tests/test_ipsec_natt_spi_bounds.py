"""H5 regression — NAT-T per-flow SPI array bound is `>=` not `>`.

The H5 fix (613efa3) flipped the bounds check in
cdx_ipsec_process_udp_classification_table_entry (cdx/cdx_dpa_ipsec.c:2322)
from `> MAX_SPI_PER_FLOW` to `>= MAX_SPI_PER_FLOW`, so arr_index ==
MAX_SPI_PER_FLOW (16, fm_ehash.h:187 — one past the spi_param[16] end,
fm_ehash.h:200) is rejected instead of writing spi_param[16] out of bounds
at :2332. The rejection propagates as ERR_CREATION_FAILED
(ipsec_push_sa_to_fast_path, control_ipsec.c), so set_state's reply_rc is the
oracle for the boundary once the site is reached.

REACHABILITY — via the CDX_DEBUG_IPSEC_TEST_XFRM test hook.
The bound lives inside `if (natt_sa && natt_sa->ct)` (cdx_dpa_ipsec.c:2290),
entered only when a *prior* same-flow NAT-T SA still holds a populated ct.
Production resolves an SA's xfrm_state by handle==sagd
(cdx_get_xfrm_state_of_sa → xfrm_state_lookup_byhandle); a synthetic FCI SA
has no such kernel state, so its push fails the control_ipsec.c:766 gate and
cdx_ipsec_delete_fp_entry nulls its ct — no same-flow SA keeps a ct and the
array never accumulates. The test image is built with
CDX_DEBUG_IPSEC_TEST_XFRM, which adds a *by-SPI* fallback at that gate
(cdx_test_xfrm_lookup_by_sa): a test pre-creates a matching `ip xfrm state`
(same daddr + spi, proto ESP) per SA, the fallback resolves it to a genuine,
ref-held xfrm_state, the gate passes and the SA keeps its ct. The bounds
check and all NAT-T bookkeeping remain the real production code; only the
state *source* is swapped for the gate. No strongSwan, no ESP traffic.

FILL SEMANTICS (traced from cdx_dpa_ipsec.c:2280-2356, one SPI per SA):
  - SA #0 finds no twin → else-branch (:2344) →
    cdx_ipsec_add_classification_table_entry builds the ct and takes slot 0.
  - Each later same-flow SA finds the populated ct → if-branch (:2290),
    get_free_natt_arr_index returns the lowest free slot.
  - When the array is full, get_free_natt_arr_index returns MAX and
    `arr_index >= MAX_SPI_PER_FLOW` (:2322) rejects → ERR_CREATION_FAILED,
    with no spi_param[MAX] write.
So MAX distinct same-flow SPIs are accepted; the next is rejected.

DYNAMIC, None-TOLERANT FILL (why not a fixed count of 16).
On the rig a SET_STATE install intermittently returns a lost/short FCI reply
(reply_rc None) — a transport-level dropped reply, not a cdx failure (no
SEC/HC/ERN/BUG in dmesg at that point). Confirmed live: such a None install
takes NO array slot (the over-max SA otherwise landed in the freed slot and
returned NO_ERR instead of overflowing). Worse, SET_STATE does not delete the
SA on a push failure (control_ipsec.c:981), so a None SA lingers in the cache
as a null-ct VALID twin that could steer a later M_ipsec_get_matched_natt_tunnel
into the wrong branch. So the fill installs with a FRESH sagd+spi (and a fresh
matching xfrm state) every attempt, counts only NO_ERR as a filled slot,
DELETES a None install and retries without counting, and stops on the first
ERR_CREATION_FAILED. Total attempts are capped so a run of lost replies can't
loop forever.

DRAIN TOLERANCE (why the shared infra probe retries). IPsec SA teardown is
deferred (cdx_ipsec_release_sa_resources → 1s timer, rescheduled while FQs
retire), so when these two tests run back-to-back the first's 16 SAs are still
draining as the second starts and a plain CREATE transiently returns rc=7 —
cumulative drain, not infra-down. The fixture's readiness probe retries that
rc=7 for a few seconds before concluding infra-not-ready, so the suite ordering
(at_max then over_max) doesn't spuriously skip; a genuine infra-down stays rc=7
across the retries and still skips.

Run under KASAN (KASAN=1 kas build): a regressed `>` would let arr_index ==
MAX through and OOB-write spi_param[MAX] at :2332 — invisible to reply_rc
alone but caught by splat_window (and, because that SA's xfrm state is also
pre-created, it would additionally clear the :766 gate and return NO_ERR, so
the reply_rc oracle catches the regression too).

Both tests skip cleanly on an image without the hook: no same-flow SA ever
reaches NO_ERR, so the fill counts zero (see the fixture's skip-guard).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest
import pytest_asyncio

from _ipsec_helpers import (
    ERR_CREATION_FAILED,
    MAX_SPI_PER_FLOW,
    NO_ERR,
    SAGD_BASE,
    add_xfrm_state_natt,
    cleanup_sa,
    flush_xfrm,
    install_sa_inbound,
    resolve_dut_local_ipv4,
)
from _topology import TARGET_WAN_IF


# Reserved sagd window for this test (0xF200..0xF2FF; see the SAGD_BASE note
# in _ipsec_helpers and the dma-balance sweep's range comment). Attempts
# advance one sagd each, capped well inside the window.
SAGD_BASE_BOUNDS = SAGD_BASE + 0x200          # 0xF200
# One SPI per attempt (fresh every attempt, retries included), one matching
# xfrm state per SPI. Distinct from the create-sweep and dma-balance SPI
# bases so a stale SA from another test can't alias ours; all non-zero.
SPI_BASE_BOUNDS  = 0x0B000000
# Throwaway SPI for the "is `ip xfrm` usable" pre-probe — clear of the
# incrementing attempt range (which starts at +0 and never reaches +0x100).
PROBE_SPI        = SPI_BASE_BOUNDS + 0x100

# A single fixed NAT-T 5-tuple: every SA shares sport/dport/family/saddr/daddr
# and differs only in SPI — exactly M_ipsec_get_matched_natt_tunnel's
# "same flow" predicate (control_ipsec.c:169-180) — so each SA finds the
# flow's populated ct and takes the if-branch that reaches the :2322 bound.
# (All synthetic SAs share saddr 0 from create_sa's default, satisfying the
# saddr arm of that predicate.)
NATT_SPORT = 4500
NATT_DPORT = 4500
# `src` for the pre-created xfrm states is arbitrary: xfrm_state_lookup keys
# on daddr+spi+proto+family+mark and ignores src. 198.51.100.1 is TEST-NET-2.
XFRM_SRC_IP = "198.51.100.1"

# SET_STATE drives the fast-path push; give its FCI reply generous headroom in
# case the None is a transient timeout under rapid back-to-back pushes, and
# settle briefly between installs. Both are harmless if the None is a genuine
# lost reply rather than a slow one.
INSTALL_TIMEOUT_MS = 8000
SETTLE_S           = 0.15

# Attempt caps. FILL_CAP allows a run of lost replies while still reaching MAX
# counted; OVERFLOW_CAP bounds the retries for a definitive over-max verdict.
FILL_CAP     = MAX_SPI_PER_FLOW + 8
OVERFLOW_CAP = 8

# Drain-tolerant infra gate. IPsec SA teardown is deferred
# (cdx_ipsec_release_sa_resources → 1s timer, rescheduled while FQs retire), so
# a heavy predecessor test (at_max's 16 SAs) can leave the SA/SEC/FQ pool
# transiently drained and a plain CREATE returns rc=7 (ERR_CREATION_FAILED) for
# a second or two. Probe with retries so back-to-back runs don't spuriously
# skip; a genuine infra-down stays rc=7 across all retries and still skips.
INFRA_PROBE_SAGD    = SAGD_BASE_BOUNDS + 0xF0   # 0xF2F0, top of the reserved window
INFRA_PROBE_SPI     = SPI_BASE_BOUNDS + 0x200   # clear of PROBE_SPI (+0x100) and the fill range
INFRA_PROBE_TRIES   = 10                         # with the delay below, ~15s total
INFRA_PROBE_DELAY_S = 1.5
# Brief teardown settle so the deferred teardown gets a head start before the
# next test's probe — belt-and-braces; the probe retry is the real fix.
TEARDOWN_SETTLE_S   = 1.0


def set_state_rc(res) -> int | None:
    """SET_STATE reply_rc — the push oracle for a NAT-T SA install."""
    return res.replies.get("set_state", {}).get("reply_rc")


def _fmt_attempts(attempts) -> str:
    return "[" + ", ".join(
        f"(#{idx} sagd={sagd:#06x} spi={spi:#010x} rc={rc!r})"
        for (idx, sagd, spi, rc) in attempts
    ) + "]"


@dataclass
class FillResult:
    counted: int                        # NO_ERR installs (== filled slots)
    attempts: list                      # (idx, sagd, spi, rc) in order
    early_reject: tuple | None = None   # (idx, rc) if ERR_CREATION_FAILED before MAX


@dataclass
class NattFlow:
    """One same-flow NAT-T install driver over a fixed 5-tuple.

    Every attempt consumes a fresh (sagd, spi) and lays down a matching
    inbound xfrm state so the CDX_DEBUG_IPSEC_TEST_XFRM by-SPI fallback can
    resolve it. Every touched sagd is tracked for teardown.
    """

    agent: object
    session: object
    dst_ip: str
    dst_int: int
    max: int = MAX_SPI_PER_FLOW
    _next: int = 0
    _attempted: set = field(default_factory=set)
    fill: FillResult | None = None

    def _sagd(self, idx: int) -> int:
        return SAGD_BASE_BOUNDS + idx

    def _spi(self, idx: int) -> int:
        return SPI_BASE_BOUNDS + idx

    async def attempt_install(self):
        """Install one same-flow NAT-T SA with a fresh sagd+spi and its
        matching xfrm state. Returns (idx, sagd, spi, rc, res):

          rc  — SET_STATE reply_rc, or None if the reply was lost/short or the
                xfrm-state prep failed. Either None case means no slot was
                taken (confirmed live), so the caller drops and retries.
          res — the InstallResult (None if the xfrm prep failed).
        """
        idx = self._next
        self._next += 1
        sagd, spi = self._sagd(idx), self._spi(idx)

        add = await add_xfrm_state_natt(
            self.agent, self.session,
            spi=spi, daddr_ip=self.dst_ip, src_ip=XFRM_SRC_IP,
            sport=NATT_SPORT, dport=NATT_DPORT,
        )
        if add.get("rc") != 0:
            # Couldn't lay the lookup target; no SA installed, no slot.
            await asyncio.sleep(SETTLE_S)
            return idx, sagd, spi, None, None

        # Track for cleanup before installing: a lost SET_STATE reply still
        # leaves the CREATE'd SA in the cache, so it must be deletable.
        self._attempted.add(sagd)
        await cleanup_sa(self.agent, self.session, sagd)  # idempotent pre-clean
        res = await install_sa_inbound(
            self.agent, self.session, sagd,
            spi=spi, dst_ip=self.dst_int, natt=True,
            natt_sport=NATT_SPORT, natt_dport=NATT_DPORT,
            timeout_ms=INSTALL_TIMEOUT_MS,
        )
        await asyncio.sleep(SETTLE_S)
        return idx, sagd, spi, set_state_rc(res), res

    async def drop(self, sagd: int) -> None:
        """Delete a same-flow SA that took no slot (None install). Removing it
        keeps it from lingering as a null-ct twin (SET_STATE doesn't delete on
        push failure, control_ipsec.c:981)."""
        await cleanup_sa(self.agent, self.session, sagd)

    async def fill_to_max(self) -> FillResult:
        counted = 0
        attempts: list = []
        while counted < self.max and len(attempts) < FILL_CAP:
            idx, sagd, spi, rc, _res = await self.attempt_install()
            attempts.append((idx, sagd, spi, rc))
            if rc == NO_ERR:
                counted += 1
            elif rc == ERR_CREATION_FAILED:
                # Array rejected before MAX (or, at counted 0, a hookless image
                # whose push never cleared the :766 gate). Terminal either way.
                return FillResult(counted, attempts, early_reject=(idx, rc))
            else:
                # None: lost/short reply, xfrm-prep failure, OR a residual
                # post-teardown CREATE drain (rc surfaces as None because
                # SET_STATE never ran) — no slot taken. Drop the lingering SA
                # and retry with a fresh sagd+spi. The fixture's drain-tolerant
                # infra probe has already cleared genuine infra-not-ready.
                await self.drop(sagd)
        return FillResult(counted, attempts)

    async def cleanup(self) -> None:
        for sagd in sorted(self._attempted):
            await cleanup_sa(self.agent, self.session, sagd)
        await flush_xfrm(self.agent, self.session)
        # Brief settle so the deferred IPsec SA teardown (1s timer) gets a head
        # start before the next test's infra probe — belt-and-braces; the
        # probe's own retry is the load-bearing drain tolerance.
        await asyncio.sleep(TEARDOWN_SETTLE_S)


async def _infra_probe(flow: NattFlow) -> str | None:
    """Drain-tolerant CAAM/DPAA readiness gate. Install + delete a throwaway
    lone (non-NAT-T) SA to check the SA/SEC/FQ pool accepts a CREATE, retrying
    a transient rc=7 left by a predecessor test's still-draining pool. Returns
    None once a CREATE goes through (infra ready), or the last infra_skip_reason
    after the retries are exhausted (genuine infra-down → caller skips).

    natt=False keeps the probe out of the NAT-T flow entirely (IS_NATT_SA is
    false, so it is never a twin); no xfrm state is created for it, so its
    SET_STATE push fails — but only CREATE's rc (via infra_skip_reason) is the
    signal here, exactly the condition the coordinator observed.
    """
    flow._attempted.add(INFRA_PROBE_SAGD)
    reason = None
    for i in range(INFRA_PROBE_TRIES):
        await cleanup_sa(flow.agent, flow.session, INFRA_PROBE_SAGD)  # pre-clean
        res = await install_sa_inbound(
            flow.agent, flow.session, INFRA_PROBE_SAGD,
            spi=INFRA_PROBE_SPI, dst_ip=flow.dst_int, natt=False,
            timeout_ms=INSTALL_TIMEOUT_MS,
        )
        await cleanup_sa(flow.agent, flow.session, INFRA_PROBE_SAGD)  # free the probe SA
        if not res.infra_skip_reason:
            return None                      # CREATE went through — infra ready
        reason = res.infra_skip_reason
        if i < INFRA_PROBE_TRIES - 1:
            await asyncio.sleep(INFRA_PROBE_DELAY_S)
    return reason


@pytest_asyncio.fixture
async def natt_flow(aiohttp_session, target_agent):
    """Fill a same-flow NAT-T SPI array to MAX_SPI_PER_FLOW and yield the
    driver (with `.fill` set). None (lost-reply) installs are dropped and
    retried; only NO_ERR counts as a slot.

    Skips (never false-fails) when the DUT can't host the test: no DUT-local
    WAN IPv4, `ip xfrm` unavailable, CAAM/DPAA not up, or — the common case —
    an image without the hook (no install ever reaches NO_ERR).
    """
    try:
        dst_ip, dst_int = await resolve_dut_local_ipv4(
            target_agent, aiohttp_session, TARGET_WAN_IF)
    except RuntimeError as e:
        pytest.skip(str(e))

    flow = NattFlow(target_agent, aiohttp_session, dst_ip=dst_ip, dst_int=dst_int)
    try:
        # Clean slate so a leftover state can't satisfy the hook for a wrong SA.
        await flush_xfrm(target_agent, aiohttp_session)

        # Pre-probe: is `ip xfrm` usable at all? Lay a throwaway state on a
        # dedicated SPI (cleared by the teardown flush).
        probe = await add_xfrm_state_natt(
            target_agent, aiohttp_session, spi=PROBE_SPI, daddr_ip=dst_ip,
            src_ip=XFRM_SRC_IP, sport=NATT_SPORT, dport=NATT_DPORT)
        if probe.get("rc") != 0:
            pytest.skip(
                f"`ip xfrm state add` failed on DUT (rc={probe.get('rc')!r}, "
                f"stderr={probe.get('stderr', '')!r}) — the agent exec allowlist "
                f"may lack `ip xfrm`, or the kernel lacks XFRM/espinudp support"
            )

        # Drain-tolerant CAAM/DPAA readiness gate (retries a transient rc=7 from
        # a predecessor test's still-draining SA pool before concluding
        # infra-not-ready). Both tests share this one probe.
        infra_reason = await _infra_probe(flow)
        if infra_reason:
            pytest.skip(infra_reason)

        fill = await flow.fill_to_max()
        # Hookless-image guard: with the fallback absent, no same-flow SA ever
        # clears the :766 gate, so not one install reaches NO_ERR.
        if fill.counted == 0:
            pytest.skip(
                "CDX_DEBUG_IPSEC_TEST_XFRM not in image / xfrm fallback not "
                f"active: no same-flow NAT-T SA reached NO_ERR "
                f"(attempts={_fmt_attempts(fill.attempts)}). Build the meta-ask "
                f"cdx recipe with the hook define to run this test."
            )
        flow.fill = fill
        yield flow
    finally:
        await flow.cleanup()


async def test_ipsec_natt_spi_at_max(natt_flow):
    """The array must accept exactly MAX_SPI_PER_FLOW same-flow SPIs cleanly:
    MAX NO_ERR installs with no rejection before MAX. None (lost-reply)
    attempts took no slot and were retried, so they don't count."""
    fill = natt_flow.fill

    # No ERR_CREATION_FAILED before the array was full — a rejection at slot
    # k < MAX would mean the bound is too tight (or an unrelated push failure).
    assert fill.early_reject is None, (
        f"a same-flow NAT-T SA was rejected before MAX ({natt_flow.max}) slots "
        f"filled: {fill.early_reject!r}; attempts={_fmt_attempts(fill.attempts)}"
    )
    # Exactly MAX slots accepted. Falls short only if lost replies exhausted
    # the attempt cap — surfaced with the full attempt log, not silently.
    assert fill.counted == natt_flow.max, (
        f"fill reached {fill.counted} NO_ERR installs, expected exactly "
        f"{natt_flow.max}; attempts={_fmt_attempts(fill.attempts)}"
    )
    # Non-vacuity (the fallback ran) is implied by counted == MAX >= 1; the
    # fixture already skipped a hookless image (counted == 0).


async def test_ipsec_natt_spi_over_max(natt_flow, splat_window):
    """With the flow full (MAX slots), the next same-flow NAT-T SA hits
    arr_index == MAX at cdx_dpa_ipsec.c:2322 and must be rejected with
    ERR_CREATION_FAILED — and must NOT OOB-write spi_param[MAX]. splat_window
    (fixture) is the KASAN/UBSAN OOB oracle; the fixture filled slots
    0..MAX-1, and the over-max install below runs inside the window."""
    fill = natt_flow.fill
    if fill.counted != natt_flow.max:
        pytest.skip(
            f"flow did not fill to MAX ({fill.counted}/{natt_flow.max}); the "
            f"overflow boundary can't be reached — see test_ipsec_natt_spi_at_max"
        )

    # The array is full. The next same-flow SA must overflow. Retry ONLY on a
    # None (lost reply, no slot taken); a NO_ERR here would mean a slot was
    # free — the bound regressed.
    rc = None
    over_attempts: list = []
    for _ in range(OVERFLOW_CAP):
        idx, sagd, spi, rc, _res = await natt_flow.attempt_install()
        over_attempts.append((idx, sagd, spi, rc))
        if rc in (NO_ERR, ERR_CREATION_FAILED):
            break
        await natt_flow.drop(sagd)  # None: took no slot, retry fresh

    assert rc == ERR_CREATION_FAILED, (
        f"over-max NAT-T SA returned rc={rc!r}, expected ERR_CREATION_FAILED — "
        f"the `arr_index >= MAX_SPI_PER_FLOW` rejection at cdx_dpa_ipsec.c:2322. "
        f"A NO_ERR means a {natt_flow.max + 1}th SPI found a slot: the H5 OOB "
        f"has regressed (`>` instead of `>=`). A None every attempt means no "
        f"definitive reply in {OVERFLOW_CAP} tries. overflow attempts="
        f"{_fmt_attempts(over_attempts)}"
    )
    # splat_window independently asserts no KASAN/UBSAN/BUG report fired during
    # this window — i.e. spi_param[MAX] was not written out of bounds.

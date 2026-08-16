"""IPsec control-plane smoke test (synthetic FCI install + query + delete).

  test_ipsec_install_query_roundtrip
      Drives a 3-step transport-mode SA install (CREATE → SET_KEYS →
      SET_STATE) via direct FCI, runs one ACTION_QUERY against the SA
      cursor, then DELETE on fixture teardown. Asserts wire layouts in
      _ipsec_helpers.py match the kernel for command codes 0x0A01, 0x0A04,
      0x0A07, 0x0A02 and 0x0A0A.

      SET_STATE will return ERR_CREATION_FAILED on synthetic SAs because
      cdx_ipsec_add_classification_table_entry can't populate sa->ct
      without a real route/iface — that's expected and accepted; the SA
      stays in sa_cache_by_h for QUERY to find. The test is **not**
      driven via NAT-T because the NAT-T fast-path push needs a real
      iface/route to populate sa->ct; the else-branch that once NULL-
      derefed sa->ct->natt_in_refcnt without a real SA (A18) is fixed.

  test_ipsec_query_empty_payload
      Sanity-check that an all-zeros 252-byte SAQueryCommand with only
      the action field set is accepted by the kernel cursor — pins the
      assumption query_sa() relies on. If a future change starts
      validating other fields, this trips before any other test.

Real-peer + iperf3 E2E coverage is deferred. Tests that need to drive
SET_STATE deeper than the current synthetic-SA reach (the H3/H5
regressions) require real iface/route setup and are deferred too.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from _ipsec_helpers import (
    CMD_IPSEC_SA_ACTION_QUERY,
    NO_ERR,
    SAGD_BASE,
    cleanup_sa,
    install_sa_inbound,
    query_sa,
)


# Synthetic SA — locally-administered (RFC1918) destination, sagd in the
# test-reserved high range (cmm only stores user-supplied sagds, see
# cmm/src/module_ipsec.c:103 — collision risk is zero).
SAGD     = SAGD_BASE + 0x01    # 0xF001
SPI      = 0x12340001
DST_IP   = 0x0A0A0A02          # 10.10.10.2

# SET_STATE for a synthetic SA fails to push to fast-path (no real iface
# bound to DST_IP, so cdx_ipsec_add_classification_table_entry can't
# resolve a netdev). Acceptable here — the SA remains in
# sa_cache_by_h, QUERY finds it, DELETE removes it. Strict-NO_ERR would
# require the real-peer fixture.
ACCEPTABLE_SET_STATE_RCS = {0, 7}  # NO_ERR, ERR_CREATION_FAILED


@pytest_asyncio.fixture
async def ipsec_sa(aiohttp_session, target_agent):
    """Install a synthetic transport-mode inbound SA, delete on teardown."""
    await cleanup_sa(target_agent, aiohttp_session, SAGD)  # pre-clean

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
            f"CREATE failed unexpectedly: reply_rc={create_rc!r}; "
            f"send_error={result.replies['create'].get('send_error')!r}. "
            "If this isn't infra-class, the wire layout in "
            "_ipsec_helpers.create_sa() needs fixing."
        )

    for step in ("set_keys",):
        rc = result.replies.get(step, {}).get("reply_rc")
        if rc != NO_ERR:
            await cleanup_sa(target_agent, aiohttp_session, SAGD)
            pytest.fail(
                f"{step} failed: reply_rc={rc!r}; full replies={result.replies!r}. "
                f"Check _ipsec_helpers wire layouts."
            )

    set_state_rc = result.replies.get("set_state", {}).get("reply_rc")
    if set_state_rc not in ACCEPTABLE_SET_STATE_RCS:
        await cleanup_sa(target_agent, aiohttp_session, SAGD)
        pytest.fail(
            f"SET_STATE returned unexpected rc={set_state_rc!r}; "
            f"full replies={result.replies!r}. NO_ERR or ERR_CREATION_FAILED "
            f"are acceptable on a synthetic SA."
        )

    try:
        yield {"sagd": SAGD, "spi": SPI, "dst_ip": DST_IP}
    finally:
        await cleanup_sa(target_agent, aiohttp_session, SAGD)


async def test_ipsec_install_query_roundtrip(
    aiohttp_session, target_agent, splat_window, ipsec_sa,
):
    """Full 4-step install (via fixture) + one ACTION_QUERY + implicit DELETE."""
    payload = query_sa()
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IPSEC_SA_ACTION_QUERY,
        length=len(payload), payload=payload, timeout_ms=2000,
    )
    rc = r.get("reply_rc")
    assert rc == NO_ERR, (
        f"ACTION_QUERY against a populated SA cache returned rc={rc!r} "
        f"(expected NO_ERR=0); send_error={r.get('send_error')!r}"
    )


async def test_ipsec_query_empty_payload(
    aiohttp_session, target_agent, splat_window,
):
    """An all-zeros 252-byte SAQueryCommand with only `action` set is
    accepted by the kernel cursor. Pins query_sa()'s wire-layout assumption:
    NO_ERR (cache had entries) and ERR_SA_ENTRY_NOT_FOUND (cursor walked
    past every empty hash slot) both indicate the layout was accepted;
    ERR_WRONG_COMMAND_SIZE would indicate a layout regression."""
    ERR_SA_ENTRY_NOT_FOUND = 909
    payload = query_sa()
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IPSEC_SA_ACTION_QUERY,
        length=len(payload), payload=payload, timeout_ms=2000,
    )
    rc = r.get("reply_rc")
    assert rc in (NO_ERR, ERR_SA_ENTRY_NOT_FOUND), (
        f"ACTION_QUERY with empty payload returned rc={rc!r} (expected "
        f"NO_ERR=0 or ERR_SA_ENTRY_NOT_FOUND=909). Other rc likely means "
        f"the kernel rejected the wire layout — verify sizeof(SAQueryCommand) "
        f"hasn't changed since 252 B."
    )

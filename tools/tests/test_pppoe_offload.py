"""PPPoE control-plane smoke test (synthetic FCI register/query/dereg).

  test_pppoe_register_query_roundtrip
      REGISTER a synthetic PPPoE session via direct FCI, QUERY it, then
      DEREGISTER on fixture teardown. Asserts the FCI surface is
      end-to-end alive: payload framing matches PPPoECommand layout,
      the kernel pppoe_cache walks correctly, DEREGISTER unwinds without
      splatting. Fast (~3s), no pppd dependency — useful as a smoke
      test when slice-2's full pppoe_dut_session fixture is unavailable.

For real-pppd end-to-end + offload coverage see
[test_pppoe_e2e.py](tools/tests/test_pppoe_e2e.py): Tier A (session
lifecycle + cmm push), Tier B (DUT-local link liveness), Tier C
(LAN-through-DUT iperf3 with cmm-CT positive control).
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

from _pppoe_helpers import (
    ACTION_DEREGISTER,
    ACTION_QUERY,
    ACTION_REGISTER,
    CMD_PPPOE_ENTRY,
    pppoe_cmd,
)


NO_ERR                = 0
ERR_UNKNOWN_INTERFACE = 5  # cdx/fe.h:66

# Synthetic session — recognisable, locally-administered MAC, and a
# log_intf name no real pppd would pick. Picked to be in a different
# (sid, mac) hash bucket from the failslab and bounds tests so any
# leftover state from those doesn't block the offload fixture's REGISTER.
SESSION_ID = 0xCA01
PEER_MAC   = b"\x02\xca\xfe\xba\xbe\x01"
PHY_INTF   = b"eth3"
LOG_INTF   = b"oflppp"


@pytest_asyncio.fixture
async def pppoe_session(aiohttp_session, target_agent):
    """Register a synthetic PPPoE session for the test, deregister on
    teardown. Skips the test if eth3 isn't a known onif (REGISTER will
    return ERR_UNKNOWN_INTERFACE — test would be uninterpretable)."""

    register = pppoe_cmd(
        action=ACTION_REGISTER, session_id=SESSION_ID, mac=PEER_MAC,
        phy_intf=PHY_INTF, log_intf=LOG_INTF,
    )
    deregister = pppoe_cmd(
        action=ACTION_DEREGISTER, session_id=SESSION_ID, mac=PEER_MAC,
        phy_intf=PHY_INTF, log_intf=LOG_INTF,
    )

    async def _dereg_quiet():
        await target_agent.fci_send(
            aiohttp_session, fcode=CMD_PPPOE_ENTRY,
            length=len(deregister), payload=deregister, timeout_ms=2000,
        )

    await _dereg_quiet()  # pre-clean

    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_PPPOE_ENTRY,
        length=len(register), payload=register, timeout_ms=3000,
    )
    if r.get("reply_rc") == ERR_UNKNOWN_INTERFACE:
        pytest.skip(
            f"phy_intf={PHY_INTF.decode()} not registered as an onif "
            "— REGISTER returned ERR_UNKNOWN_INTERFACE. Likely the dpa_app "
            "boot-time onif install didn't complete; investigate before "
            "re-enabling."
        )
    if r.get("reply_rc") != NO_ERR:
        await _dereg_quiet()
        pytest.fail(
            f"PPPoE REGISTER failed unexpectedly: reply_rc={r.get('reply_rc')!r} "
            f"send_error={r.get('send_error')!r}"
        )

    try:
        yield {
            "session_id": SESSION_ID,
            "peer_mac":   PEER_MAC,
            "phy_intf":   PHY_INTF.decode(),
            "log_intf":   LOG_INTF.decode(),
        }
    finally:
        await _dereg_quiet()


async def test_pppoe_register_query_roundtrip(
    aiohttp_session, target_agent, splat_window, pppoe_session,
):
    """REGISTER / QUERY / (implicit DEREGISTER on fixture teardown)."""
    sess = pppoe_session
    query_payload = pppoe_cmd(
        action=ACTION_QUERY, session_id=sess["session_id"], mac=sess["peer_mac"],
        phy_intf=sess["phy_intf"].encode(), log_intf=sess["log_intf"].encode(),
    )
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_PPPOE_ENTRY,
        length=len(query_payload), payload=query_payload, timeout_ms=2000,
    )
    rc = r.get("reply_rc")
    assert rc == NO_ERR, (
        f"QUERY on a registered session returned rc={rc!r} "
        f"(expected NO_ERR=0); send_error={r.get('send_error')!r}"
    )

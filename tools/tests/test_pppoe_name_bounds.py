"""Malformed-input regression for CMD_PPPOE_ENTRY.

Drive REGISTER / DEREGISTER / QUERY with malformed phy_intf, log_intf,
mac, and session_id fields and assert no kernel splat. The shape of
the worry is the same one that motivated A6 for tunnels: handlers that
treat 16-byte name fields as NUL-terminated C strings will walk past the
field end if the input never NUL-terminates, KASAN-flagging a stack-OOB
read inside add_onif / get_onif_by_name / dpa_add_pppoe_if.

Oracle: splat_window. The handlers may accept or reject however they
like (NO_ERR / ERR_PPPOE_ENTRY_NOT_FOUND / ERR_UNKNOWN_INTERFACE are
all fine); the contract under test is only that the kernel survives
without OOB read, UAF, or UBSAN type confusion.

The 5-case _NAME_CASES matrix is shared with test_tunnel_name_bounds.py
because both subsystems use the same 16-byte IF_NAME_SIZE and have the
same "C string vs raw 16-byte field" failure mode. The two extra cases
(_MAC_CASES, _SESSION_CASES) exercise the non-name fields the tunnel
test doesn't have.

Each REGISTER test uses a unique session_id derived from the case label
(via the case index) so successful registrations don't block sibling
cases via ERR_PPPOE_ENTRY_ALREADY_REGISTERED — the cache key is
(session_id, mac), so identical session_ids+macs collide regardless of
log_intf differences. The teardown-on-finally DEREGISTERs each
registration so cross-test pollution doesn't leak into the offload
suite that follows.
"""

from __future__ import annotations

import pytest

from _pppoe_helpers import (
    ACTION_DEREGISTER,
    ACTION_QUERY,
    ACTION_REGISTER,
    CMD_PPPOE_ENTRY,
    pppoe_cmd,
)
from _topology import TARGET_WAN_IF


# The WAN-facing physical port — registered as an onif by dpa_app at
# boot, so REGISTER gets past the ERR_UNKNOWN_INTERFACE gate and
# actually reaches the name-handling code these cases target.
_PHY_INTF = TARGET_WAN_IF.encode()

# Per-case unique session_ids start here. Picked above the typical
# 0..0xFF range CMM allocates from on a real ppp dial-up to avoid
# collisions with anything cmm might have registered concurrently.
_SESSION_BASE = 0xC100

# Common test-only mac. Locally-administered (0x02 first byte).
_TEST_MAC = b"\x02\xde\xad\xbe\xef\x02"

# Common log_intf used when the test isn't varying it.
_TEST_LOG = b"bndsppp"


# Same shapes as test_tunnel_name_bounds.py:_NAME_CASES — the 16-byte
# field has identical failure modes whether it's tunnel.name or
# pppoe.{phy,log}_intf.
_NAME_CASES = [
    ("no_nul_all_ff",     b"\xff" * 16),
    ("nul_at_offset_0",   b"\x00" * 16),
    ("nul_then_trailing", b"\x00" * 15 + b"\xff"),
    ("ascii_no_nul",      b"ABCDEFGHIJKLMNOP"),
    ("nul_at_offset_3",   b"abc\x00\xff" + b"\xde\xad\xbe\xef" * 2 + b"\xff\xff\xff"),
]

# 6-byte mac field — narrower failure surface than the name fields, but
# COPY_MACADDR / TESTEQ_MACADDR call sites are macros that could be
# careless about alignment or read-past-end if the field were ever
# treated as a string.
_MAC_CASES = [
    ("mac_all_ff",   b"\xff" * 6),
    ("mac_all_zero", b"\x00" * 6),
    ("mac_high_bit", b"\x80\x00\x00\x00\x00\x00"),
]

_SESSION_CASES = [
    ("session_zero",    0x0000),
    ("session_max",     0xFFFF),
    ("session_typical", 0xBEEF),
]


async def _send(target_agent, aiohttp_session, payload: bytes) -> dict:
    return await target_agent.fci_send(
        aiohttp_session, fcode=CMD_PPPOE_ENTRY,
        length=len(payload), payload=payload, timeout_ms=2000,
    )


async def _dereg_quiet(target_agent, aiohttp_session, *,
                       session_id: int, mac: bytes,
                       phy_intf: bytes, log_intf: bytes) -> None:
    """Best-effort DEREGISTER for fixture cleanup. The cache walk at
    cdx/control_pppoe.c:93-100 needs all of (session_id, mac, log_intf)
    to match — calling sites must pass exactly what they REGISTERed."""
    payload = pppoe_cmd(
        action=ACTION_DEREGISTER, session_id=session_id, mac=mac,
        phy_intf=phy_intf, log_intf=log_intf,
    )
    await _send(target_agent, aiohttp_session, payload)


@pytest.mark.parametrize(
    "phy_label,phy",  _NAME_CASES,
    ids=[f"phy={lbl}" for lbl, _ in _NAME_CASES],
)
async def test_pppoe_register_malformed_phy_intf(
    aiohttp_session, target_agent, splat_window, phy_label, phy,
):
    """Malformed phy_intf can't reach add_onif (the get_onif_by_name
    lookup at cdx/control_pppoe.c:120 returns NULL → ERR_UNKNOWN_INTERFACE)
    so REGISTER never installs an entry. No cleanup needed."""
    payload = pppoe_cmd(
        action=ACTION_REGISTER, session_id=_SESSION_BASE + 0x10,
        mac=_TEST_MAC, phy_intf=phy, log_intf=_TEST_LOG,
    )
    await _send(target_agent, aiohttp_session, payload)


@pytest.mark.parametrize(
    "idx,name_case",  list(enumerate(_NAME_CASES)),
    ids=[f"log={lbl}" for lbl, _ in _NAME_CASES],
)
async def test_pppoe_register_malformed_log_intf(
    aiohttp_session, target_agent, splat_window, idx, name_case,
):
    """phy_intf=_PHY_INTF is valid → REGISTER may successfully install an
    entry with a malformed log_intf. Each parametrized case uses a
    unique session_id so cache-key collisions don't make subsequent
    cases trip on ERR_PPPOE_ENTRY_ALREADY_REGISTERED, and try/finally
    DEREGISTERs the entry so it doesn't leak into following tests."""
    log_label, log = name_case
    sid = _SESSION_BASE + 0x20 + idx
    payload = pppoe_cmd(
        action=ACTION_REGISTER, session_id=sid,
        mac=_TEST_MAC, phy_intf=_PHY_INTF, log_intf=log,
    )
    try:
        await _send(target_agent, aiohttp_session, payload)
    finally:
        await _dereg_quiet(
            target_agent, aiohttp_session,
            session_id=sid, mac=_TEST_MAC,
            phy_intf=_PHY_INTF, log_intf=log,
        )


@pytest.mark.parametrize(
    "log_label,log",  _NAME_CASES,
    ids=[f"log={lbl}" for lbl, _ in _NAME_CASES],
)
async def test_pppoe_deregister_malformed_log_intf(
    aiohttp_session, target_agent, splat_window, log_label, log,
):
    """DEREGISTER's slist walk at cdx/control_pppoe.c:96-100 calls
    strcmp(_, get_onif_name(...), cmd->log_intf); a non-NUL log_intf
    runs past the 16-byte field if the strcmp() isn't bounded.
    No registration happens here (no matching entry) so no cleanup
    is needed."""
    payload = pppoe_cmd(
        action=ACTION_DEREGISTER, session_id=_SESSION_BASE + 0x30,
        mac=_TEST_MAC, phy_intf=_PHY_INTF, log_intf=log,
    )
    await _send(target_agent, aiohttp_session, payload)


@pytest.mark.parametrize(
    "idx,mac_case",  list(enumerate(_MAC_CASES)),
    ids=[lbl for lbl, _ in _MAC_CASES],
)
async def test_pppoe_register_malformed_mac(
    aiohttp_session, target_agent, splat_window, idx, mac_case,
):
    """Malformed MAC may successfully register; clean up after."""
    mac_label, mac = mac_case
    sid = _SESSION_BASE + 0x40 + idx
    log = b"bndmac" + str(idx).encode()
    payload = pppoe_cmd(
        action=ACTION_REGISTER, session_id=sid, mac=mac,
        phy_intf=_PHY_INTF, log_intf=log,
    )
    try:
        await _send(target_agent, aiohttp_session, payload)
    finally:
        await _dereg_quiet(
            target_agent, aiohttp_session,
            session_id=sid, mac=mac,
            phy_intf=_PHY_INTF, log_intf=log,
        )


@pytest.mark.parametrize(
    "idx,sess_case",  list(enumerate(_SESSION_CASES)),
    ids=[lbl for lbl, _ in _SESSION_CASES],
)
async def test_pppoe_register_malformed_session_id(
    aiohttp_session, target_agent, splat_window, idx, sess_case,
):
    """session_id values include the parametrized value itself; the
    test exercises the kernel's handling of edge values without
    needing per-case derivation. Cleanup uses the same value."""
    sess_label, sess = sess_case
    log = b"bndsid" + str(idx).encode()
    payload = pppoe_cmd(
        action=ACTION_REGISTER, session_id=sess,
        mac=_TEST_MAC, phy_intf=_PHY_INTF, log_intf=log,
    )
    try:
        await _send(target_agent, aiohttp_session, payload)
    finally:
        await _dereg_quiet(
            target_agent, aiohttp_session,
            session_id=sess, mac=_TEST_MAC,
            phy_intf=_PHY_INTF, log_intf=log,
        )


async def test_pppoe_query_malformed_no_setup(
    aiohttp_session, target_agent, splat_window,
):
    """QUERY walks the cursor independent of the input fields' sanity —
    any field could be junk and the response is generated from kernel
    state, not user input. Only the splat oracle matters."""
    payload = pppoe_cmd(
        action=ACTION_QUERY,
        session_id=0xFFFF,
        mac=b"\xff" * 6,
        phy_intf=b"\xff" * 16,
        log_intf=b"\xff" * 16,
    )
    await _send(target_agent, aiohttp_session, payload)

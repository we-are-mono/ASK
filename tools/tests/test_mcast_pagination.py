"""M1 — multicast listener pagination on real 8-listener group.

ISSUES.md M1 flagged an OOB: `cdx_mc_query.c` used to walk
MC_MAX_LISTENERS_PER_GROUP (8) slots while writing into a reply struct
sized at MC_MAX_LISTENERS_IN_QUERY (5). Groups with 6-8 listeners
clobbered past output_list[4]. Fixed by splitting the reply across two
commands: first page holds 5, second page holds the remainder.

This test exercises the full state machine end-to-end against the real
kernel: set up 8 real VLAN subinterfaces (so get_onif_by_name succeeds
on each), register via ADD(5)+UPDATE(3), attempt one more UPDATE (9 →
rejected), then QUERY+QUERY_CONT and verify all 8 listener names come
back across two pages with the expected num_output per page.
"""

from __future__ import annotations

import asyncio
import os
import struct

import pytest
import pytest_asyncio

from ask_orch.client import ASK_KMEMLEAK_FILTER


# FCI opcode (cdx/cdx_cmdhandler.h)
CMD_MC4_MULTICAST = 0x0701

# Actions (cdx/dpa_control_mc.h + cdx/fe.h)
CDX_MC_ACTION_ADD    = 0
CDX_MC_ACTION_REMOVE = 1
CDX_MC_ACTION_UPDATE = 2
ACTION_QUERY         = 6
ACTION_QUERY_CONT    = 7

# Return codes (cdx/fe.h)
NO_ERR                         = 0
ERR_WRONG_COMMAND_SIZE         = 2
ERR_MC_ENTRY_NOT_FOUND         = 700
ERR_MC_MAX_LISTENERS           = 701
ERR_MC_MAX_LISTENERS_PER_GROUP = 706
ERR_MC_CONFIG                  = 707  # "mcast group does not exist" on REMOVE

# Wire layout (cdx/dpa_control_mc.h, __packed__)
IF_NAME_SIZE               = 16
MC_MAX_LISTENERS_PER_GROUP = 8
MC4_MAX_LISTENERS_IN_QUERY = 5
MC4_OUTPUT_SIZE = 48   # 4+16+1+1+6+1+16+1+2
MC4_CMD_FIXED   = 32   # 2+1+1+4+4+4+16  (pre-output_list bytes)
MC4_CMD_SIZE    = MC4_CMD_FIXED + MC4_OUTPUT_SIZE * MC4_MAX_LISTENERS_IN_QUERY  # 272


# --- Test topology ------------------------------------------------------

TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth4")
BASE_VID      = int(os.environ.get("ASK_MCAST_BASE_VID", "201"))  # .201 .. .208
INGRESS_IFACE = os.environ.get("ASK_MCAST_INGRESS", "eth3")       # WAN side
MCAST_DST     = "239.1.1.7"
MCAST_SRC     = "10.0.0.141"

LISTENER_IFACES = [f"{TARGET_LAN_IF}.{BASE_VID + i}" for i in range(MC_MAX_LISTENERS_PER_GROUP)]


# --- Pack/unpack helpers -----------------------------------------------

def _ip_be_bytes(addr: str) -> bytes:
    """Network-order bytes for an IPv4 dotted-quad."""
    return bytes(int(o) for o in addr.split("."))


def _pack_mc4_output(iface: str) -> bytes:
    """One packed MC4Output. Only output_device_str matters for the state
    we're validating — the rest of the struct is zero-filled."""
    name = iface.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    return (
        b"\x00\x00\x00\x00"   # timer
        + name                # output_device_str[16]
        + b"\x00"             # shaper_mask
        + b"\x00"             # bitfield (uc_bit/q_bit/rsvd)
        + b"\x00" * 6         # uc_mac
        + b"\x00"             # queue
        + b"\x00" * 16        # new_output_device_str
        + b"\x00"             # bitfield (if_bit/unused)
        + b"\x00\x00"         # padding[2]
    )


MC4_MIN_COMMAND_SIZE = 44   # 32+12 per cdx/dpa_control_mc.h — validator floor


def _pack_mc4_command(
    action: int,
    listeners: list[str],
    dst: str = MCAST_DST,
    src: str = MCAST_SRC,
    ingress: str = INGRESS_IFACE,
) -> bytes:
    """Pack an MC4Command with N listeners (N <= 5). Wire size is the
    fixed prefix plus N * sizeof(MC4Output), padded up to
    MC4_MIN_COMMAND_SIZE (44) which the validator table enforces as the
    lower bound — QUERY/QUERY_CONT still need to clear that floor even
    though they carry no listeners in the request."""
    n = len(listeners)
    assert n <= MC4_MAX_LISTENERS_IN_QUERY, "at most 5 listeners fit one wire command"
    header = (
        struct.pack("<HBB", action, 0, 0)   # action, src_addr_mask, bitfield
        + _ip_be_bytes(src)                  # src_addr (network order)
        + _ip_be_bytes(dst)                  # dst_addr (network order)
        + struct.pack("<I", n)               # num_output
    )
    ingress_field = ingress.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    outputs = b"".join(_pack_mc4_output(i) for i in listeners)
    wire = header + ingress_field + outputs
    if len(wire) < MC4_MIN_COMMAND_SIZE:
        wire += b"\x00" * (MC4_MIN_COMMAND_SIZE - len(wire))
    return wire


def _unpack_mc4_query_page(payload: bytes) -> tuple[int, int, list[str]]:
    """Parse an MC4Command wire reply. Returns (reply_rc, num_output,
    listener_names). On error, reply_rc is the error code and the rest
    of the buffer is undefined."""
    assert len(payload) >= MC4_CMD_SIZE, f"short reply: {len(payload)} < {MC4_CMD_SIZE}"
    reply_rc, = struct.unpack("<H", payload[0:2])
    num_output, = struct.unpack("<I", payload[12:16])
    names: list[str] = []
    for i in range(num_output):
        base = MC4_CMD_FIXED + i * MC4_OUTPUT_SIZE
        # output_device_str sits at offset 4 within MC4Output
        name_bytes = payload[base + 4 : base + 4 + IF_NAME_SIZE]
        names.append(name_bytes.split(b"\x00", 1)[0].decode(errors="replace"))
    return reply_rc, num_output, names


async def _send_mc4(target_agent, session, action: int,
                    listeners: list[str], *, timeout_ms: int = 2000) -> dict:
    """Send one CMD_MC4_MULTICAST and return the fci_send reply dict."""
    payload = _pack_mc4_command(action, listeners)
    return await target_agent.fci_send(
        session,
        fcode=CMD_MC4_MULTICAST,
        length=len(payload),
        payload=payload,
        timeout_ms=timeout_ms,
    )


# --- Fixture: 8 VLAN subifs on the target, auto-registered via CMM -----

@pytest_asyncio.fixture
async def eight_vlan_listeners(aiohttp_session, target_agent):
    """Create 8 VLAN subinterfaces on TARGET_LAN_IF. CMM's netlink watcher
    emits CMD_VLAN_ENTRY REGISTER for each, adding them to the FMAN onif
    table — a prerequisite for create_exthash_entry4mcast_member to
    resolve get_onif_by_name(listener_name) during mcast ADD.

    Tear them down unconditionally so a failing test can't leak 8
    sticky netdevs onto the DUT.
    """
    # Nuke any stale state from a previous aborted run.
    for iface in LISTENER_IFACES:
        await target_agent.exec_cmd(
            aiohttp_session, ["ip", "link", "del", iface],
        )

    try:
        for i, iface in enumerate(LISTENER_IFACES):
            r = await target_agent.exec_cmd(aiohttp_session, [
                "ip", "link", "add", "link", TARGET_LAN_IF,
                "name", iface, "type", "vlan", "id", str(BASE_VID + i),
            ])
            assert r["rc"] == 0, f"vlan add failed for {iface}: {r}"
            r = await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "set", iface, "up"],
            )
            assert r["rc"] == 0, f"vlan up failed for {iface}: {r}"
        # Let CMM pick up the NEWLINK events and push CMD_VLAN_ENTRY.
        await asyncio.sleep(1.0)
        yield LISTENER_IFACES
    finally:
        for iface in LISTENER_IFACES:
            await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "del", iface],
            )


@pytest_asyncio.fixture
async def clean_mcast_group(aiohttp_session, target_agent, eight_vlan_listeners):
    """Teardown of the mcast group after the test. REMOVE with count ==
    current group size hits the full-group-delete branch at
    cdx_delete_mcast_group_member line 883; partial removes hit the
    per-listener loop starting line 900. Combined with the fix in
    cdx_free_exthash_mcast_members (walk members[] by bIsValidEntry,
    not by uiListenerCnt), this sequence leaves no dangling
    ExternalHashTableAllocEntry allocations behind."""
    yield
    r1 = await _send_mc4(target_agent, aiohttp_session,
                         CDX_MC_ACTION_REMOVE, LISTENER_IFACES[:5])
    r2 = await _send_mc4(target_agent, aiohttp_session,
                         CDX_MC_ACTION_REMOVE, LISTENER_IFACES[5:])
    # Surface teardown failure after the cleanup has run. ERR_MC_CONFIG
    # (707) means "group doesn't exist" — expected when the test body
    # already performed its own REMOVE (e.g. before an in-test kmemleak
    # scan) and this fixture runs as a belt-and-braces second pass.
    # Anything else suggests a real teardown issue worth surfacing.
    for label, r in (("REMOVE[0:5]", r1), ("REMOVE[5:8]", r2)):
        rc = r.get("reply_rc")
        if rc not in (NO_ERR, ERR_MC_CONFIG, None):
            import warnings
            warnings.warn(f"mcast teardown {label} returned reply_rc={rc}: {r}")


# --- The test ----------------------------------------------------------

async def test_mcast_8_listener_pagination_roundtrip(
    aiohttp_session, target_agent, splat_window,
    eight_vlan_listeners, clean_mcast_group,
):
    """Register 8 listeners (ADD 5 + UPDATE 3), verify a 9th UPDATE is
    rejected, then QUERY + QUERY_CONT and assert the 8 listener names
    round-trip across two pages (5 + 3) with no OOB."""
    listeners = eight_vlan_listeners

    # Establish a kmemleak cursor before we exercise the mcast state
    # machine. Combined with the post-teardown scan below, this gives
    # us a true in-test delta — independent of whatever boot-time DPAA
    # baseline noise kmemleak is still settling.
    await target_agent.kmemleak_clear(aiohttp_session)

    # -- ADD 5 listeners into a new group --
    r = await _send_mc4(target_agent, aiohttp_session,
                        CDX_MC_ACTION_ADD, listeners[:5])
    assert r.get("reply_rc") == NO_ERR, f"ADD(5) failed: {r}"

    # -- UPDATE with 3 more → total 8 --
    r = await _send_mc4(target_agent, aiohttp_session,
                        CDX_MC_ACTION_UPDATE, listeners[5:8])
    assert r.get("reply_rc") == NO_ERR, f"UPDATE(+3) failed: {r}"

    # -- UPDATE with 1 more → 9th rejected by the per-group cap --
    # dpa_control_mc.c line 705:
    #   if ((uiNoOfListeners + pMcastGrpInfo->uiListenerCnt)
    #        > MC_MAX_LISTENERS_PER_GROUP)
    #           iRet = ERR_MC_MAX_LISTENERS_PER_GROUP;
    # Use an unused iface name; we don't want the resolve to fail first.
    overflow_iface = f"{TARGET_LAN_IF}.{BASE_VID + 99}"
    await target_agent.exec_cmd(aiohttp_session, [
        "ip", "link", "add", "link", TARGET_LAN_IF,
        "name", overflow_iface, "type", "vlan", "id", str(BASE_VID + 99),
    ])
    try:
        await asyncio.sleep(0.5)  # let CMM register the extra subif
        r = await _send_mc4(target_agent, aiohttp_session,
                            CDX_MC_ACTION_UPDATE, [overflow_iface])
        assert r.get("reply_rc") == ERR_MC_MAX_LISTENERS_PER_GROUP, (
            f"9th listener UPDATE should be rejected with "
            f"ERR_MC_MAX_LISTENERS_PER_GROUP ({ERR_MC_MAX_LISTENERS_PER_GROUP}), "
            f"got {r}"
        )
    finally:
        await target_agent.exec_cmd(aiohttp_session,
                                    ["ip", "link", "del", overflow_iface])

    # -- QUERY page 1: 5 listeners (MC4_MAX_LISTENERS_IN_QUERY) --
    r = await _send_mc4(target_agent, aiohttp_session, ACTION_QUERY, [])
    assert r.get("reply_rc") == NO_ERR, f"QUERY page 1 failed: {r}"
    page1 = bytes.fromhex(r["payload_hex"])
    rc1, n1, names1 = _unpack_mc4_query_page(page1)
    assert rc1 == NO_ERR
    assert n1 == MC4_MAX_LISTENERS_IN_QUERY, (
        f"page 1 should have exactly {MC4_MAX_LISTENERS_IN_QUERY} listeners, got {n1}"
    )

    # -- QUERY_CONT page 2: remaining 3 listeners --
    r = await _send_mc4(target_agent, aiohttp_session, ACTION_QUERY_CONT, [])
    assert r.get("reply_rc") == NO_ERR, f"QUERY_CONT page 2 failed: {r}"
    page2 = bytes.fromhex(r["payload_hex"])
    rc2, n2, names2 = _unpack_mc4_query_page(page2)
    assert rc2 == NO_ERR
    assert n2 == MC_MAX_LISTENERS_PER_GROUP - MC4_MAX_LISTENERS_IN_QUERY, (
        f"page 2 should have 3 listeners, got {n2}"
    )

    # -- All 8 registered listener names must round-trip --
    got = set(names1) | set(names2)
    expected = set(listeners)
    assert got == expected, (
        f"listener names did not round-trip across pagination:\n"
        f"  expected: {sorted(expected)}\n"
        f"  got:      {sorted(got)}\n"
        f"  page1: {names1}\n  page2: {names2}"
    )

    # -- No mcast-originated leaks during the full state-machine run --
    # Let REMOVE teardown run first (it's a later-scoped fixture, so it
    # tears down before we get here — actually no, pytest runs body
    # first then fixture cleanup). So we issue REMOVE inline here and
    # scan; the separate teardown fixture then re-runs REMOVE idempotently.
    await _send_mc4(target_agent, aiohttp_session,
                    CDX_MC_ACTION_REMOVE, listeners[:5])
    await _send_mc4(target_agent, aiohttp_session,
                    CDX_MC_ACTION_REMOVE, listeners[5:8])
    await asyncio.sleep(1.5)  # let kmemleak's scanner see the frees
    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=ASK_KMEMLEAK_FILTER,
    )
    assert report.get("leak_count", 0) == 0, (
        f"mcast ADD+UPDATE+REMOVE cycle leaked "
        f"{report['leak_count']} ASK-code object(s):\n"
        + report.get("report", "")[:4000]
    )

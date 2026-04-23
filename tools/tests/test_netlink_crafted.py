"""Crafted-netlink tests for C1 (auto_bridge nla length) + C2 (fci length validation).

C1 context (ISSUES.md): pre-fix `auto_bridge.c` memcpy'd an attacker-
controlled `nla_len(tb[L2FLOWA_IP_SRC])` bytes into a 16-byte stack
union. The fix added `abm_l2flow_policy[]` restricting the attribute
to NLA_BINARY with .len = 16. We assert the oversized attribute gets
rejected before the memcpy runs — in practice that means a garbled
message returns no reply and produces no splat.

C2 context: pre-fix `fci.c` trusted `nlh->nlmsg_len` and `fci_msg->length`
blindly, leading to OOB reads. The fix uses `skb->len` as authoritative.
We assert crafted bad-length messages return no reply + no splat.

Both tests use the splat_window fixture — a real defence failure would
surface as a KASAN / UBSAN / BUG dmesg line within the capture window.
"""

from __future__ import annotations

import struct

import pytest


# -------- C1: auto_bridge oversized attr ------------------------------

NETLINK_L2FLOW    = 33
L2FLOW_MSG_ENTRY  = 17   # from enum l2flow_msg_types
L2FLOWA_SVLAN_TAG = 1
L2FLOWA_IP_SRC    = 6
L2FLOWA_IP_PROTO  = 8
NLM_F_REQUEST     = 1


def _l2flow_msg_body() -> bytes:
    """Minimal valid `struct l2flow_msg` (action u8 + flags u32 + saddr[6]
    + daddr[6] + ethertype u16) with natural alignment padding to 24 B."""
    return struct.pack(
        "<B 3x I 6B 6B H 2x",
        0,                          # action = L2FLOW_ENTRY_NEW
        0,                          # flags
        0, 0, 0, 0, 0, 0,           # saddr
        0, 0, 0, 0, 0, 0,           # daddr
        0,                          # ethertype
    )


def _rtattr(type_: int, payload: bytes) -> bytes:
    """Build rtattr = u16 len, u16 type, payload, padded to 4 bytes."""
    hdr_len = 4 + len(payload)
    pad = (4 - (hdr_len & 3)) & 3
    return struct.pack("<HH", hdr_len, type_) + payload + b"\x00" * pad


# ASK_OVERSIZE picks a size that's BIGGER than the 16-byte union the
# memcpy target holds. Pre-fix this overflows the stack object; post-fix
# the nla_policy rejects the message outright.
C1_CASES = [
    ("ip_src_oversize",  L2FLOWA_IP_SRC,   b"\x41" * 32),
    ("ip_src_wildly_oversize", L2FLOWA_IP_SRC,  b"\x42" * 64),
    # IP_PROTO is strict-typed as NLA_U8 post-fix; pre-fix it was bare.
    ("ip_proto_as_u32",  L2FLOWA_IP_PROTO, b"\x00\x00\x00\x00"),
]


@pytest.mark.parametrize(
    "label,attr_type,attr_payload", C1_CASES,
    ids=[x[0] for x in C1_CASES],
)
async def test_c1_auto_bridge_malformed_attr(
    aiohttp_session, target_agent, splat_window,
    label, attr_type, attr_payload,
):
    """Oversized / wrong-type L2FLOWA attrs must be rejected before
    the memcpy path runs. Pass = clean dmesg + socket didn't fault."""
    body = _l2flow_msg_body() + _rtattr(attr_type, attr_payload)
    r = await target_agent.netlink_send(
        aiohttp_session,
        protocol=NETLINK_L2FLOW,
        msg=body,
        nlmsg_type=L2FLOW_MSG_ENTRY,
        nlmsg_flags=NLM_F_REQUEST,
        timeout_ms=300,
    )
    # The auto_bridge rcv handler has no reply path for L2FLOW_MSG_ENTRY,
    # so we don't assert on reply contents — splat_window teardown is
    # the real check. `sent_bytes` proves the agent did send it.
    assert r.get("sent_bytes", 0) > 0, f"{label}: send failed: {r}"


# -------- C2: fci length validation ----------------------------------

NETLINK_FF          = 30
FCI_MSG_HDR_SIZE    = 4      # u16 fcode + u16 length
FCI_MSG_MAX_PAYLOAD = 512


C2_CASES = [
    # (label, fci_length_field, actual_payload_len, nlmsg_len_override)
    #
    # length > (skb->len - FCI_MSG_HDR_SIZE): the post-fix check rejects.
    ("length_field_overshoots",       999,  0,    None),
    ("length_field_past_max_payload", 0xFFFF, 0,  None),
    # nlmsg_len overrides: lie about how much data we're sending.
    # Pre-C2 code trusted nlmsg_len for skb bounds.
    ("nlmsg_len_way_oversize",        0,    0,    60000),
    ("nlmsg_len_below_hdr",           0,    0,    10),   # < NLMSG_LENGTH(4)
]


@pytest.mark.parametrize(
    "label,fci_len,pad_bytes,nlmsg_override", C2_CASES,
    ids=[x[0] for x in C2_CASES],
)
async def test_c2_fci_bad_length_field(
    aiohttp_session, target_agent, splat_window,
    label, fci_len, pad_bytes, nlmsg_override,
):
    """Malformed FCI length fields must be rejected without OOB reads.
    Pass = splat_window clean."""
    # Use fcode=0 so the dispatcher would rc=ERR_UNKNOWN_COMMAND if
    # we ever reach it — but the C2 check runs earlier and should drop.
    r = await target_agent.fci_send(
        aiohttp_session,
        fcode=0x0000,
        length=fci_len,
        payload=b"\x00" * pad_bytes,
        nlmsg_len_override=nlmsg_override,
        timeout_ms=300,
    )
    assert r.get("sent_bytes", 0) > 0, f"{label}: send failed: {r}"

"""N1: CAP_NET_ADMIN gate on the FCI and auto_bridge netlink command buses.

G1 gated the /dev/cdx_ctrl ioctl, but the sibling entry points were open:
any process could create a NETLINK_FF (fci) or NETLINK_L2FLOW (abm)
socket — socket creation and unicast-to-kernel need no capability — and
drive the datapath-reconfiguration command bus directly. The fix adds a
per-message `netlink_capable(skb, CAP_NET_ADMIN)` check at the top of
both input handlers:

  * fci __fci_fe_inbound_data answers an uncapable sender with
    netlink_ack(-EPERM) before any payload parsing;
  * abm abm_nl_rcv_msg returns -EPERM (netlink_rcv_skb turns that into
    an NLMSG_ERROR ack) before the message-type switch.

The agent's /fci/send and /netlink/send take `uid`/`userns` to fork a
child that drops privilege before opening the socket — netlink_capable
checks the socket *opener's* credentials, so the drop must precede
socket creation.

Oracles: privileged senders must reach the parsers (an FCI-format reply
for fci; the parser's own -EAGAIN for an out-of-range abm message type),
unprivileged senders must get NLMSG_ERROR/-EPERM for the *same* bytes.
That errno flip also proves the gate sits before the parser.
"""

from __future__ import annotations

import errno
import struct


NETLINK_L2FLOW  = 33
NETLINK_KEY     = 32   # patched MAX_LINKS=64 admits this proto; the
                       # af_key ipsec-offload command bus lives here
NLMSG_ERROR     = 2
NLM_F_REQUEST   = 1    # netlink_rcv_skb only dispatches requests
L2FLOW_MSG_MAX  = 19   # auto_bridge.h enum: BASE=16, ENTRY, RESET, MAX

NON_ROOT_UID    = 1000

# nlkey_msg fcodes (patch 040). SA_NOTIFY expires an SA; FLOW_REMOVE is
# the case whose memcpy reads sizeof(struct flowi)+4 out of the payload.
NLKEY_SA_NOTIFY   = 0x0A09
NLKEY_FLOW_REMOVE = 0x0A12

# An nlmsg_len far larger than the on-wire bytes: the value a caller sets
# to make a length-blind handler copy/echo past the request skb.
INFLATED_NLMSG_LEN = 0x8000

# Deliberately unknown fcode: as root this still crosses the gate and
# comes back as a normal FCI reply (rc=ERR_UNKNOWN_COMMAND); the exact
# rc doesn't matter here, only FCI-reply vs NLMSG_ERROR.
FCODE_PROBE     = 0xFFFF


def _nl_header_and_err(result: dict) -> tuple[int, int | None]:
    """Parse (nlmsg_type, error) out of a raw agent reply.

    `error` is the NLMSG_ERROR payload's error field (negative errno)
    when nlmsg_type == NLMSG_ERROR, else None.
    """
    raw = bytes.fromhex(result.get("reply_hex", ""))
    assert len(raw) >= 16, f"no netlink reply at all: {result}"
    _len, nl_type, _flags, _seq, _pid = struct.unpack_from("=IHHII", raw, 0)
    if nl_type != NLMSG_ERROR:
        return nl_type, None
    assert len(raw) >= 20, f"truncated NLMSG_ERROR: {result}"
    return nl_type, struct.unpack_from("=i", raw, 16)[0]


def _nlkey_body(fcode: int, payload: bytes = b"") -> bytes:
    """A struct nlkey_msg: u16 fcode, u16 length, then payload. The
    agent prepends the nlmsghdr, so this is what the handler sees at
    NLMSG_DATA."""
    return struct.pack("=HH", fcode & 0xFFFF, len(payload) & 0xFFFF) + payload


async def test_fci_unprivileged_uid_gets_eperm(
    aiohttp_session, target_agent, splat_window,
):
    """A uid-1000 sender on NETLINK_FF is answered with -EPERM."""
    r = await target_agent.fci_send(
        aiohttp_session, fcode=FCODE_PROBE, length=0, uid=NON_ROOT_UID,
    )
    nl_type, err = _nl_header_and_err(r)
    assert nl_type == NLMSG_ERROR and err == -errno.EPERM, (
        f"unprivileged FCI send must be refused with EPERM, got {r}"
    )


async def test_fci_userns_root_gets_eperm(
    aiohttp_session, target_agent, splat_window,
):
    """Capabilities held only in an unmapped user namespace don't count:
    the gate checks CAP_NET_ADMIN against the init userns."""
    r = await target_agent.fci_send(
        aiohttp_session, fcode=FCODE_PROBE, length=0, userns=True,
    )
    nl_type, err = _nl_header_and_err(r)
    assert nl_type == NLMSG_ERROR and err == -errno.EPERM, (
        f"userns-root FCI send must be refused with EPERM, got {r}"
    )


async def test_fci_root_passes_gate(
    aiohttp_session, target_agent, splat_window,
):
    """Sanity: as real root the same bytes cross the gate and come back
    as an FCI-format reply (the dispatcher's answer, not NLMSG_ERROR)."""
    r = await target_agent.fci_send(
        aiohttp_session, fcode=FCODE_PROBE, length=0,
    )
    nl_type, err = _nl_header_and_err(r)
    assert not (nl_type == NLMSG_ERROR and err == -errno.EPERM), (
        f"root hit the capability gate (regression!): {r}"
    )
    assert r.get("reply_rc") is not None, (
        f"root should get a normal FCI reply, got {r}"
    )


async def test_abm_unprivileged_uid_gets_eperm(
    aiohttp_session, target_agent, splat_window,
):
    """A uid-1000 sender on NETLINK_L2FLOW is refused with -EPERM before
    the parser runs — the same message as root would draw the parser's
    -EAGAIN (see the root sanity test below)."""
    r = await target_agent.netlink_send(
        aiohttp_session, protocol=NETLINK_L2FLOW, msg=b"",
        nlmsg_type=L2FLOW_MSG_MAX, nlmsg_flags=NLM_F_REQUEST,
        uid=NON_ROOT_UID,
    )
    nl_type, err = _nl_header_and_err(r)
    assert nl_type == NLMSG_ERROR and err == -errno.EPERM, (
        f"unprivileged l2flow send must be refused with EPERM, got {r}"
    )


async def test_abm_root_passes_gate(
    aiohttp_session, target_agent, splat_window,
):
    """Sanity: root crosses the gate and reaches the message-type
    check, whose out-of-range answer for L2FLOW_MSG_MAX is -EAGAIN."""
    r = await target_agent.netlink_send(
        aiohttp_session, protocol=NETLINK_L2FLOW, msg=b"",
        nlmsg_type=L2FLOW_MSG_MAX, nlmsg_flags=NLM_F_REQUEST,
    )
    nl_type, err = _nl_header_and_err(r)
    assert nl_type == NLMSG_ERROR and err == -errno.EAGAIN, (
        f"root l2flow probe should reach the parser (-EAGAIN), got {r}"
    )


async def test_fci_unprivileged_inflated_nlmsg_len_no_oob(
    aiohttp_session, target_agent, splat_window,
):
    """Unprivileged sender + an nlmsg_len far larger than the 20-byte skb.

    The raw FCI .input handler gets no core length validation, and the
    -EPERM netlink_ack it would otherwise send echoes nlmsg_len bytes
    straight out of the request skb — a ~32 KB heap over-read (KASAN oops,
    or a plain infoleak in the error body). The handler bounds nlmsg_len
    against NLMSG_ALIGN(skb->len) before the capability check, so an
    over-long message is dropped as malformed. Invariants: no splat (the
    splat_window fixture) and no reply large enough to carry echoed heap.
    """
    r = await target_agent.fci_send(
        aiohttp_session, fcode=FCODE_PROBE, length=0,
        uid=NON_ROOT_UID, nlmsg_len_override=INFLATED_NLMSG_LEN,
    )
    raw = bytes.fromhex(r.get("reply_hex", ""))
    assert len(raw) < 256, (
        f"reply ballooned to {len(raw)} bytes — nlmsg_len-sized heap echo: {r}"
    )


async def test_fci_root_inflated_nlmsg_len_no_oob(
    aiohttp_session, target_agent, splat_window,
):
    """The same malformed nlmsg_len as root. The bound sits ahead of the
    capability check, so privilege doesn't change the outcome: the error
    path never echoes out-of-bounds bytes. No splat, no ballooned reply.
    """
    r = await target_agent.fci_send(
        aiohttp_session, fcode=FCODE_PROBE, length=0,
        nlmsg_len_override=INFLATED_NLMSG_LEN,
    )
    raw = bytes.fromhex(r.get("reply_hex", ""))
    assert len(raw) < 256, (
        f"reply ballooned to {len(raw)} bytes — nlmsg_len-sized heap echo: {r}"
    )


async def test_nlkey_unprivileged_no_splat(
    aiohttp_session, target_agent, splat_window,
):
    """NETLINK_KEY (proto 32) reconfigures host IPsec offload — expiring
    SAs, forging counters, toggling offload. An unprivileged sender must
    be stopped at the CAP_NET_ADMIN gate before the handler dereferences
    anything. The short NLKEY_FLOW_REMOVE is the worst case: ungated it
    memcpy'd sizeof(struct flowi)+4 bytes out of a header-only skb. The
    handler replies to neither; the assertion is a clean splat window.
    """
    sa_notify = struct.pack("=HHI", 0xFFFF, 0, 0)   # bogus handle, soft action
    for fcode, payload in (
        (NLKEY_SA_NOTIFY, sa_notify),
        (NLKEY_FLOW_REMOVE, b""),                   # too short for the memcpy
    ):
        await target_agent.netlink_send(
            aiohttp_session, protocol=NETLINK_KEY,
            msg=_nlkey_body(fcode, payload),
            nlmsg_flags=NLM_F_REQUEST, uid=NON_ROOT_UID,
        )


async def test_nlkey_root_reaches_handler_no_splat(
    aiohttp_session, target_agent, splat_window,
):
    """As root the same messages cross the gate and reach the handler.
    The per-command length guards reject the short NLKEY_FLOW_REMOVE
    before its memcpy, and NLKEY_SA_NOTIFY against an unknown handle is a
    no-op (xfrm_state_lookup_byhandle returns NULL). No splat either way.
    Effect-level verification (an SA surviving an unprivileged expire)
    needs an offloaded SA to exist and is out of scope here.
    """
    sa_notify = struct.pack("=HHI", 0xFFFF, 0, 0)
    for fcode, payload in (
        (NLKEY_SA_NOTIFY, sa_notify),
        (NLKEY_FLOW_REMOVE, b""),
    ):
        await target_agent.netlink_send(
            aiohttp_session, protocol=NETLINK_KEY,
            msg=_nlkey_body(fcode, payload),
            nlmsg_flags=NLM_F_REQUEST,
        )

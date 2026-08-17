"""abm L2-flow netlink notifier — observe ebt-hook → broadcast.

When a unicast IP frame is bridged through abm_ebt_hook
(NF_BR_FORWARD followed by NF_BR_POST_ROUTING), the hook creates
a new l2flowTable entry, transitions it SEEN→CONFIRMED, and
synchronously calls abm_nl_send_l2flow_msg(L2FLOW_ENTRY_NEW),
which netlink_broadcasts on NETLINK_L2FLOW (proto 33), multicast
group L2FLOW_NL_GRP=1 — provided netlink_has_listeners() is true.

The test subscribes a listener via the askd-agent
/netlink-listen-{start,stop} pair, drives a unicast IP frame
across the configured bridge from the LAN VM (scapy with explicit
src/dst MAC + Dot1Q tag), and asserts at least one well-formed
L2FLOW_MSG_ENTRY frame arrives with `action` ∈ {NEW, UPDATE, DEL}.

Bridge fast-path gate (br_input.c): abm_ebt_hook only runs on
skbs with skb->abm_ff==1, which the bridge sets only when a
unicast frame's destination MAC resolves in the FDB (br_forward
path, not br_flood). The trigger therefore primes the FDB with
a seed broadcast from the destination MAC on the second VLAN
port before injecting the unicast trigger.
"""

from __future__ import annotations

import asyncio
import struct
import textwrap

from _topology import (
    LAN_NIC,
    VLAN_IDS_BRIDGE,
    bridge_with_n_ports,  # noqa: F401  (fixture)
    lan_run,
    lan_run_python,
)


# auto_bridge.h:28-39 — uapi constants. Duplicated here (not imported
# from a kernel header) so the test stays self-contained.
NETLINK_L2FLOW   = 33
L2FLOW_NL_GRP    = 1
L2FLOW_MSG_BASE  = 16
L2FLOW_MSG_ENTRY = 17
L2FLOW_ACTIONS   = {0, 1, 2}   # NEW / UPDATE / DEL

# struct nlmsghdr — u32 len, u16 type, u16 flags, u32 seq, u32 pid.
_NLMSGHDR_SIZE = 16

PRIMARY_VID, SECONDARY_VID = VLAN_IDS_BRIDGE   # 231, 232

# Locally-administered unicast MACs — distinct from anything the LAN
# VM's NIC actually owns, so the trigger frame stays foreign-sourced
# and Linux delivers it via the wire path (not via local hairpin).
SRC_MAC = "02:00:ab:11:22:01"
DST_MAC = "02:00:ab:11:22:02"


def _parse_nl_frames(messages_hex: list[str]) -> list[dict]:
    """Decode a list of hex-serialised netlink datagrams into
    [{nlmsg_type, nlmsg_flags, body}, ...].

    A single recv() may carry multiple stacked nlmsghdr's (common when
    several broadcasts queue up between reads); walk by nlmsg_len with
    NLMSG_ALIGN(4) so we don't lose the second message in such a frame.
    """
    out: list[dict] = []
    for hexstr in messages_hex:
        buf = bytes.fromhex(hexstr)
        off = 0
        while off + _NLMSGHDR_SIZE <= len(buf):
            nlmsg_len, nlmsg_type, nlmsg_flags = struct.unpack_from(
                "=IHH", buf, off,
            )
            if nlmsg_len < _NLMSGHDR_SIZE or off + nlmsg_len > len(buf):
                break
            body = buf[off + _NLMSGHDR_SIZE : off + nlmsg_len]
            out.append({
                "nlmsg_type":  nlmsg_type,
                "nlmsg_flags": nlmsg_flags,
                "body":        body,
            })
            # NLMSG_ALIGN(len) — round up to 4.
            off += (nlmsg_len + 3) & ~3
    return out


_INJECT_SCRIPT = textwrap.dedent(f"""
    from scapy.all import Ether, Dot1Q, IP, UDP, Raw, sendp

    LAN_NIC = {LAN_NIC!r}

    # Seed frame: src=DST_MAC tagged on SECONDARY_VID. The DUT's bridge
    # learns DST_MAC -> eth3.{SECONDARY_VID} so the subsequent trigger
    # resolves in the FDB and takes the br_forward fast path (abm_ff=1).
    seed = (Ether(src={DST_MAC!r}, dst="ff:ff:ff:ff:ff:ff")
            / Dot1Q(vlan={SECONDARY_VID})
            / IP(src="10.99.{SECONDARY_VID}.2", dst="10.99.{SECONDARY_VID}.255")
            / UDP(sport=4242, dport=4243)
            / Raw(b"abm-seed"))
    sendp(seed, iface=LAN_NIC, verbose=0)

    # Trigger frames: unicast src=SRC_MAC -> dst=DST_MAC tagged on
    # PRIMARY_VID. Bridge ingresses on eth3.{PRIMARY_VID}, FDB hits
    # DST_MAC on eth3.{SECONDARY_VID}, fast-path forward sets abm_ff=1.
    # Multiple shots so a lost first one (FDB still settling) doesn't
    # turn the test vacuous.
    pkt = (Ether(src={SRC_MAC!r}, dst={DST_MAC!r})
           / Dot1Q(vlan={PRIMARY_VID})
           / IP(src="10.99.{PRIMARY_VID}.2", dst="10.99.{PRIMARY_VID}.3")
           / UDP(sport=5555, dport=6666)
           / Raw(b"abm-trigger"))
    sendp(pkt, iface=LAN_NIC, count=5, inter=0.05, verbose=0)
    print("INJECTED")
""").strip()


async def test_abm_netfilter_hook_l2flow_broadcast(
    aiohttp_session, target_agent, lan, splat_window, bridge_with_n_ports,
):
    """Subscribe NETLINK_L2FLOW, drive a bridged unicast frame across
    the abm-instrumented bridge, assert ≥1 L2FLOW_MSG_ENTRY arrives.
    """
    # bridge fixture yields (bridge_name, [port, ...]) — we don't need
    # either name directly; the trigger keys off VLAN tags.
    _ = bridge_with_n_ports

    listener_id = await target_agent.netlink_listen_start(
        aiohttp_session, protocol=NETLINK_L2FLOW, group=L2FLOW_NL_GRP,
    )
    try:
        # Tiny pause so the kernel's NETLINK_ADD_MEMBERSHIP take effect
        # before the seed broadcast — without it, an unlucky race could
        # have the trigger fire before netlink_has_listeners() flips true.
        await asyncio.sleep(0.2)

        r = await lan_run_python(
            lan, _INJECT_SCRIPT, label="abm_nl_trigger", timeout=15.0,
        )
        assert "INJECTED" in r.stdout, (
            f"scapy injection didn't complete: rc={r.rc}, stdout={r.stdout!r}"
        )

        # abm_ebt_hook broadcasts synchronously, but the listener thread
        # on the agent side reads frames off a kernel-buffered socket;
        # give the buffer a moment to drain into the per-id list before
        # we stop+collect.
        await asyncio.sleep(1.5)
    finally:
        result = await target_agent.netlink_listen_stop(
            aiohttp_session, listener_id,
        )

    parsed = _parse_nl_frames(result.get("messages", []))
    entry_msgs = [
        m for m in parsed
        if m["nlmsg_type"] == L2FLOW_MSG_ENTRY
        and len(m["body"]) >= 1
        and m["body"][0] in L2FLOW_ACTIONS
    ]
    assert entry_msgs, (
        f"expected ≥1 L2FLOW_MSG_ENTRY broadcast (action in NEW/UPDATE/DEL); "
        f"got {len(parsed)} netlink message(s) total: "
        f"{[(m['nlmsg_type'], m['body'][:1].hex()) for m in parsed[:5]]!r}"
    )

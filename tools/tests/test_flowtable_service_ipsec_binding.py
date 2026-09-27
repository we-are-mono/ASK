"""A decrypted flow's hardware entry is bound to the SA that decrypted it.

The classifier reclassifies SEC's decrypted output on one offline port,
whichever SA produced it, and the flowtable admits a decrypted direction for
the inbound SA whose selector covers it. The entry it installs used to key on
the offline port id and the inner 5-tuple alone, so a second offloaded inbound
SA -- any peer the box has a tunnel with -- could encrypt an inner packet
carrying that 5-tuple, and SEC would authenticate it under the second SA and
the offline-port lookup would hit the first SA's entry and forward it. The
frame was never sent through the first tunnel; the second peer forged it.

Each of the port's keys now carries the SA a frame left SEC by -- the FQID its
FROM_SEC queue names in Context B, its TO_CP queue -- so an entry admitted for
one SA matches nothing another decrypted. A forged frame misses, lands in the
second SA's exception queue with a secpath naming that SA, and Linux's forward
policy -- which requires the first SA's reqid for that inner tuple -- drops it.

The exploit installs a second offloaded inbound SA B on the DUT and forges,
straight to the DUT's outer address, an ESP frame under B that carries A's
decrypted inner tuple. Forging the ESP here rather than routing an inner packet
through a second WAN-host tunnel is deliberate: it needs no outbound SA or
policy on the WAN host (so nothing contends with A's policy for the shared
selector), binds none of the peer's sockets, and touches neither the LAN
console the traffic peer holds. B is null-cipher with an HMAC-SHA256
authenticator, so the ICV is a plain keyed hash and no cipher library is
needed; SEC still authenticates and decapsulates it. The test asserts the DUT
decrypted the forgeries under B (its SA counter moves, XfrmInNoStates does
not), that A's decrypted-direction entry did not count them, that Linux
dropped them as a template mismatch, and that A's genuine traffic stays in
hardware (the `hardware()` oracle, which is also the regression that the
decrypted direction is still carried).

The rekey test rebinds a flow to a fresh SA over the same selectors, and the
selector case installs a newer inbound SA whose selector does not cover the
flow and shows the flow stays bound to the covering one -- the case that
separates A288 from choosing by address. The exhaustive selector/newest-first
logic is host-tested in test_ipsec_adapter.py::test_paired_inbound.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import socket
import struct
import time
from hashlib import sha256

import pytest

from _topology import TARGET_WAN_IF
from test_flowtable_connections import by_key, peer
from test_flowtable_offload import DPORT, WAN_IP, command, console_command, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import warm
from test_flowtable_service import FIRST
from test_flowtable_service_ipsec import (  # noqa: F401
    INNER, LAN_INNER, REQIDS, flows_for, hardware, ipsec_service,
)
from test_flowtable_service_ipsec_replay import PEER_ERRORS, xfrm_mib

pytestmark = [pytest.mark.asyncio(loop_scope="module")]

# Peer B: a second offloaded inbound SA on the DUT, distinct SPI and reqid from
# the fixture's A pair, null cipher + HMAC-SHA256-128 so its ESP can be forged
# with only hashlib. It has no forwarding policy on the DUT: a frame it
# decrypts is one no policy for A's inner tuple accepts.
SPI_B = 0xB2000001
REQID_B = "50701"
B_AUTH_KEY = bytes(range(32))            # the DUT's B SA and the forger share it
FORGED = 64
# A newer inbound SA whose selector does not cover the flow: same outer
# endpoints as A, so choosing by address would pick it, but its selector
# excludes the flow's inner tuple, so choosing by selector does not.
SPI_A2 = 0xA2000001
REQID_A2 = "50801"
DECOY_SRC, DECOY_DST = "198.18.199.9", "198.18.199.10"
ALGO_NULL = ("mode", "tunnel", "reqid", REQID_B,
             "enc", "ecb(cipher_null)", "0x",
             "auth-trunc", "hmac(sha256)", "0x" + B_AUTH_KEY.hex(), "128")
# A's decrypted direction: arriving on the WAN port, forwarded to the LAN,
# carrying INNER -> LAN_INNER (the reply half of the fixture's flow 2). It is
# the entry a forged frame would hit; its in_sa names the SA it is bound to.
DECRYPTED_KEY = (TARGET_WAN_IF, "17", f"{INNER}:{DPORT}", f"{LAN_INNER}:{FIRST}")


async def dut_xfrm(r):
    return xfrm_mib(await read(r.target, r.session, "/proc/net/xfrm_stat"))


async def decrypted_row(r):
    rows = by_key(await r.state())
    assert DECRYPTED_KEY in rows, (DECRYPTED_KEY, sorted(rows))
    return rows[DECRYPTED_KEY]


async def sa_packets(r, spi):
    """SEC's per-SA decrypt count for the DUT's B, published by the accounting
    pass; None once the SA is gone."""
    result = await command(r.target, r.session, "ip", "-s", "xfrm", "state", "get",
                           "src", WAN_IP, "dst", r.ipsec.outer, "proto", "esp",
                           "spi", hex(spi), check=False)
    if result["rc"]:
        return None
    import re
    m = re.search(r"lifetime current:\s*\d+\(bytes\), (\d+)\(packets\)", result["stdout"])
    return int(m.group(1)) if m else 0


def _ip_csum(header):
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _inner(payload):
    """An IPv4/UDP datagram INNER:DPORT -> LAN_INNER:FIRST -- A's decrypted
    inner tuple, the one A's offline-port entry is keyed on."""
    udp = struct.pack("!HHHH", DPORT, FIRST, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    src = socket.inet_aton(INNER)
    dst = socket.inet_aton(LAN_INNER)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0, 64, socket.IPPROTO_UDP, 0) + src + dst
    hdr = hdr[:10] + struct.pack("!H", _ip_csum(hdr)) + hdr[12:]
    return hdr + udp


def _esp(spi, seq, inner):
    """A tunnel-mode ESP packet under B: null cipher (payload verbatim), next
    header IPv4, HMAC-SHA256-128 ICV over the whole ESP header and payload."""
    padlen = (-(len(inner) + 2)) % 4
    pad = bytes(range(1, padlen + 1))
    body = struct.pack("!II", spi, seq) + inner + pad + bytes([padlen, socket.IPPROTO_IPIP])
    icv = hmac.new(B_AUTH_KEY, body, sha256).digest()[:16]
    return body + icv


def forge(outer):
    """Send FORGED ESP frames under B straight to the DUT's outer address. A
    raw ESP socket, so the WAN host's own xfrm output is never consulted."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
    try:
        s.bind((WAN_IP, 0))
        for seq in range(1, FORGED + 1):
            s.sendto(_esp(SPI_B, seq, _inner(b"ASK-FORGED-" + struct.pack("!I", seq))), (outer, 0))
            time.sleep(0.01)
    finally:
        s.close()


async def test_forged_inner_packet_under_a_second_sa_is_not_delivered(ipsec_service):
    r = ipsec_service
    flows = flows_for(r)
    outer = r.ipsec.outer

    async with peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400,
                    listen_addresses=[INNER]) as p:
        await warm(r, p, [0, 1, 2, 3], "binding-baseline", flows[:4])
        await hardware(r, p, "binding-baseline-hardware", flows[:4])
        before_row = await decrypted_row(r)
        assert before_row["in_sa"] != "0", before_row

        try:
            # B's inbound half on the DUT, offloaded on the WAN port, selected
            # by SPI; no forwarding policy for it.
            await command(r.target, r.session, "ip", "xfrm", "state", "add",
                          "src", WAN_IP, "dst", outer, "proto", "esp", "spi", hex(SPI_B),
                          *ALGO_NULL, "replay-window", "32",
                          "offload", "packet", "dev", TARGET_WAN_IF, "dir", "in")
            b_before = await sa_packets(r, SPI_B)
            dut_before = await dut_xfrm(r)
            await asyncio.to_thread(forge, outer)
            await asyncio.sleep(3)   # let SEC's per-SA counters be published
            after_row = await decrypted_row(r)
            dut_after = await dut_xfrm(r)
            b_after = await sa_packets(r, SPI_B)

            # The DUT decrypted the forgeries under B -- so the miss is a
            # binding decision, not SEC turning them away: XfrmInNoStates,
            # which a frame with no SA at all would raise, did not move.
            assert dut_after.get("XfrmInNoStates", 0) == dut_before.get("XfrmInNoStates", 0), (
                "the DUT had no SA for the forged frames", dut_before, dut_after)
            assert b_after is not None and b_after - (b_before or 0) >= FORGED - 4, (
                "B did not decrypt the forgeries", b_before, b_after)
            # A's decrypted-direction entry did not count them: they carried
            # A's inner tuple but B's SA, and its key names A's.
            assert after_row["in_sa"] == before_row["in_sa"], (before_row, after_row)
            assert int(after_row["packets"]) - int(before_row["packets"]) <= 2, (
                before_row, after_row)
            # Linux dropped them: B's secpath does not satisfy the forward
            # policy for A's inner tuple, which requires A's reqid.
            drops = {name: dut_after.get(name, 0) - dut_before.get(name, 0) for name in PEER_ERRORS}
            r.record("binding-forge", {"drops": drops, "b_decrypts": (b_before, b_after),
                                       "before": before_row, "after": after_row})
            assert drops.get("XfrmInTmplMismatch", 0) >= FORGED - 4, drops

            # A's genuine traffic is still carried in hardware.
            await hardware(r, p, "binding-after-forge-hardware", flows[:4])
        finally:
            await command(r.target, r.session, "ip", "xfrm", "state", "delete",
                          "src", WAN_IP, "dst", outer, "proto", "esp",
                          "spi", hex(SPI_B), check=False)


async def test_flow_rebinds_to_the_new_sa_after_a_rekey(ipsec_service):
    r = ipsec_service
    flows = flows_for(r)

    async with peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400,
                    listen_addresses=[INNER]) as p:
        await warm(r, p, [0, 1, 2, 3], "rekey-baseline", flows[:4])
        await hardware(r, p, "rekey-baseline-hardware", flows[:4])
        old_in_sa = (await decrypted_row(r))["in_sa"]

        # A CHILD_SA rekey: the new inbound SA over the same selectors goes in,
        # then the old one is withdrawn. install() makes the new SPI active, so
        # the old one is deleted by its saved SPI rather than through remove(),
        # which would now delete the new one. No conntrack flush: the old SA's
        # deletion retires the flow, and the next packet re-admits it bound to
        # the new SA -- which is the path a rekey actually takes.
        old_spi = r.ipsec.active["in"]
        new_spi = await r.ipsec.prepare_peer("in")
        await r.ipsec.install("in", new_spi)
        await console_command(r.service_console, "ip", "xfrm", "state", "delete",
                              *r.ipsec.state("in", old_spi))
        await command(r.ipsec.wan, r.session, "ip", "xfrm", "state", "delete",
                      *r.ipsec.state("in", old_spi), check=False)

        deadline = time.monotonic() + 25
        while True:
            await p.batch([2, 3], count=32, interval=0.02)
            row = by_key(await r.state()).get(DECRYPTED_KEY)
            if row and row["in_sa"] not in ("0", old_in_sa):
                break
            assert time.monotonic() < deadline, (old_in_sa, row)
        await hardware(r, p, "rekey-rebound-hardware", flows[:4])


async def test_flow_keeps_the_sa_whose_selector_covers_it(ipsec_service):
    r = ipsec_service
    flows = flows_for(r)
    outer = r.ipsec.outer

    async with peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400,
                    listen_addresses=[INNER]) as p:
        await warm(r, p, [0, 1, 2, 3], "selector-baseline", flows[:4])
        await hardware(r, p, "selector-baseline-hardware", flows[:4])

        try:
            # A newer inbound SA between the same outer endpoints as A, but with
            # a selector that does not cover the flow. Choosing the flow's
            # inbound SA by address (the old code) would pick this one, the most
            # recent for the pair, and key the entry on its FQID -- so the
            # genuine frames A decrypts, carrying A's FQID, would miss and the
            # decrypted direction would stall. Choosing by selector keeps A.
            await command(r.target, r.session, "ip", "xfrm", "state", "add",
                          "src", WAN_IP, "dst", outer, "proto", "esp", "spi", hex(SPI_A2),
                          "mode", "tunnel", "reqid", REQID_A2, *r.ipsec.transform.algorithms,
                          "sel", "src", DECOY_SRC + "/32", "dst", DECOY_DST + "/32",
                          "replay-window", "32",
                          "offload", "packet", "dev", TARGET_WAN_IF, "dir", "in")
            # Re-admit flow 2 so the decoy is in the SA table when its inbound
            # direction is resolved. A targeted conntrack delete, not a flush.
            await command(r.target, r.session, "conntrack", "-D", "-f", "ipv4", "-p", "udp",
                          "--orig-src", LAN_INNER, "--orig-dst", INNER,
                          "--sport", str(FIRST), "--dport", str(DPORT), check=False)
            await p.rpc("close", [2])
            await p.rpc("open", [2])
            await warm(r, p, [0, 1, 2, 3], "selector-readmitted", flows[:4])
            # The flow still carries in hardware: its entry is bound to A, whose
            # frames match it, not to the decoy whose frames never arrive.
            after = await hardware(r, p, "selector-covering-hardware", flows[:4])
            r.record("selector-covering", {"row": by_key(after).get(DECRYPTED_KEY)})
        finally:
            await command(r.target, r.session, "ip", "xfrm", "state", "delete",
                          "src", WAN_IP, "dst", outer, "proto", "esp",
                          "spi", hex(SPI_A2), check=False)

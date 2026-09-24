"""An offloaded tunnel SA answers an oversized IPv4 datagram with DF as Linux does.

Linux bounds a direction into an SA by the bundle's MTU, the smaller of the
SA's MTU and the inner route's, and answers an oversized IPv4 datagram with DF
by Fragmentation Needed carrying that bound. The SA's MTU is what xfrm computes
for the transform: for AES-CBC with HMAC-SHA256-128 over IPv4 on a 1500-byte
port, ((1500 - 20 - 8 - 16 - 16) & ~15) - 2 = 1438.

The classifier entry is given that bound with SEC's expansion on top, and the
microcode adds the expansion to a packet bound for SEC before the size check
that hands an oversized IPv4 packet with DF to Linux. Two things kept the two
bounds apart. The expansion was the headers alone, because the SA was
programmed while xfrm still held the state as not yet valid, so a DF datagram
between the SA's MTU and the port's less the headers (1439-1456 bytes for that
transform) went to SEC and left it larger than the port (A227). And the entry
took the port's MTU in place of the flow's, so an inner route with an MTU of its
own was not the bound at all: DF datagrams between it and the SA's MTU crossed
in hardware where Linux answers them (A230).

Each case runs once with the inner route carrying no MTU, where the SA's is the
bound, and once with the fixture's own inner route MTU, below the SA's. Every
DF size over the bound draws Linux's answer; one at exactly the bound crosses
the tunnel in hardware as one frame; and, below the SA's MTU, one without DF
over the inner route's crosses too, whole, as Linux itself sends it.
"""
from __future__ import annotations

import asyncio
import json
import secrets

import pytest

from _topology import LAN_NIC, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import by_key, peer
from test_flowtable_ipv6_sa import fragments_sent
from test_flowtable_offload import DPORT, WAN_IP, command, rig  # noqa: F401
from test_flowtable_selective_neighbour import keys, unchanged, warm
from test_flowtable_service_ipsec import (INNER, LAN_INNER, Transform, flows_for, ipsec_service,  # noqa: F401
                                          sec_counter)
from test_flowtable_service_ipsec_replay import AEAD

# What esp4 puts around a transform's payload: the cipher's block, which it
# aligns to 4 bytes, and the IV it sends; GCM is a stream cipher with a block
# of one.
GEOMETRY = {"cbc(aes)": (16, 16), "cbc(des3_ede)": (8, 8), "rfc3686(ctr(aes))": (1, 8),
            "rfc4106(gcm(aes))": (1, 8)}
# The fixture routes the far inner address with an MTU of its own, below any
# SA's here; put back when a case is done.
FIXTURE_ROUTE_MTU = 1400


def esp_geometry(transform):
    """The transform's outer header length and its SA's inner MTU on a port of
    `port_mtu`, as xfrm_state_mtu() computes them for a tunnel-mode ESP state
    over IPv4."""
    algorithms = transform.algorithms
    if algorithms[0] == "aead":
        _, cipher, _, icv_bits = algorithms
    else:
        _, cipher, _, kind, _, _, icv_bits = algorithms
        assert kind == "auth-trunc", algorithms
    block, iv = GEOMETRY[cipher]
    header = 20 + 8 + iv + (8 if transform.encap else 0)
    align = -(-block // 4) * 4

    def inner_mtu(port_mtu):
        return (port_mtu - header - int(icv_bits) // 8) // align * align - 2
    return header, inner_mtu


def probe_script(r, sport, payload, df):
    """Send one IPv4 datagram, with DF or without, on the probe flow's own
    tuple from the LAN end, and collect every Fragmentation Needed quoting it."""
    return f'''
import json
from scapy.all import Ether, IP, IPerror, UDP, ICMP, Raw, sendp, sniff
packet = IP(src={LAN_INNER!r}, dst={INNER!r}, flags={"DF" if df else 0!r})/UDP(sport={sport}, dport={DPORT})/Raw({payload!r})
def frag_needed(p):
    return (ICMP in p and p[ICMP].type == 3 and p[ICMP].code == 4 and IPerror in p
            and p[IPerror].src == {LAN_INNER!r} and p[IPerror].dst == {INNER!r})
answers = sniff(iface={LAN_NIC!r}, timeout=2, lfilter=frag_needed,
                started_callback=lambda: sendp(Ether(dst={r.dut_lan_mac!r})/packet,
                                               iface={LAN_NIC!r}, verbose=False))
print(json.dumps({{"length": len(packet),
                  "frag_needed": [{{"mtu": a[ICMP].nexthopmtu, "length": a[IPerror].len}}
                                  for a in answers]}}))
'''


async def probe(r, flow, size, df=True):
    """One datagram of `size` bytes, all headers included, and what it did:
    whether the LAN end heard Fragmentation Needed, whether the far end got
    it intact, and what the hardware direction, the software SEC submit and
    the microcode's fragmenter counted meanwhile."""
    payload = (b"ASK-ipsec-mtu-" + secrets.token_bytes(8)).ljust(size - 28, b".")
    forward = next(key for key in keys([0], [flow]) if key[0] != TARGET_WAN_IF)
    before, fragments = await r.state(), await fragments_sent(r)
    submitted = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
    result = await lan_run_python(r.lan, probe_script(r, flow["sport"], payload, df), timeout=20,
                                  label="flowtable_ipsec_mtu")
    assert result.rc == 0, result.stdout
    await asyncio.sleep(0.5)
    after = await r.state()
    lan = json.loads(result.stdout.strip().splitlines()[-1])
    assert lan["length"] == size, lan
    return {"size": size, "df": df, "lan": lan, "delivered": r.echo.received[payload],
            "hardware": int(by_key(after)[forward]["packets"]) - int(by_key(before)[forward]["packets"]),
            "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - submitted,
            "fragments": {k: v - fragments[k] for k, v in (await fragments_sent(r)).items()},
            "before": before, "after": after}


@pytest.mark.parametrize("route_mtu", [None, FIXTURE_ROUTE_MTU], ids=["sa-bound", "route-bound"])
@pytest.mark.parametrize("ipsec_service", [Transform(), AEAD["rfc4106-icv16"]],
                         ids=["cbc-sha256", "rfc4106-icv16"], indirect=True)
async def test_flowtable_service_ipsec_df_mtu(ipsec_service, route_mtu):
    """A DF datagram over the direction's bound -- the SA's inner MTU, or the
    inner route's where that is smaller -- up to the port's less the headers,
    draws Fragmentation Needed with that bound; one at exactly the bound
    crosses the tunnel in hardware as one frame."""
    r = ipsec_service
    flows = flows_for(r, "udp")
    flow = flows[4]
    link = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show", "dev",
                                     TARGET_WAN_IF))["stdout"])
    port_mtu = int(link[0]["mtu"])
    header, inner_mtu = esp_geometry(r.ipsec.transform)
    sa_mtu = inner_mtu(port_mtu)
    bound = sa_mtu if route_mtu is None else min(route_mtu, sa_mtu)
    assert route_mtu is None or route_mtu < sa_mtu, (route_mtu, sa_mtu)
    # Just over the bound, a little further, the SA's own MTU where the
    # route's is below it, and the largest the headers alone would have let
    # through.
    oversized = sorted({bound + 1, bound + 12, sa_mtu, port_mtu - header} - {bound})
    assert bound < oversized[0] and oversized[-1] <= port_mtu, (bound, oversized)
    label = "ipsec-mtu-" + ("sa-bound" if route_mtu is None else "route-bound")
    route = ["ip", "route", "replace", INNER + "/32", "via", WAN_IP, "dev", TARGET_WAN_IF]
    # Set explicitly either way rather than trusted from the fixture, since
    # the answer depends on it.
    await command(r.target, r.session, *route, *(["mtu", str(route_mtu)] if route_mtu else []))
    results = {}
    try:
        async with peer(r, flows, initial_ids=[4], lease=400, listen_addresses=[INNER]) as p:
            await warm(r, p, [4], label + "-admitted", [flow])
            for size in oversized:
                result = results[f"df-{size}"] = await probe(r, flow, size)
                r.record(label, {"sa_mtu": sa_mtu, "bound": bound, "results": results})
                # Linux's answer, once, with the bound, and the datagram
                # dropped: never handed to SEC by the CPU or the hardware, so
                # nothing reached the far end and nothing was fragmented.
                assert result["lan"]["frag_needed"] == [{"mtu": bound, "length": size}], result
                assert result["delivered"] == 0 and result["toenc"] == 0, result
                assert result["fragments"] == {4: 0, 6: 0}, result
                unchanged(result["before"], result["after"], [0], [flow])
            result = results[f"df-{bound}"] = await probe(r, flow, bound)
            r.record(label, {"sa_mtu": sa_mtu, "bound": bound, "results": results})
            # The largest the bound admits: SEC encrypts it in hardware and it
            # leaves as one frame, exactly the port's MTU when the SA's MTU is
            # the bound.
            assert result["lan"]["frag_needed"] == [], result
            assert result["delivered"] == 1 and result["hardware"] == 1, result
            assert result["toenc"] == 0 and result["fragments"] == {4: 0, 6: 0}, result
            unchanged(result["before"], result["after"], [0], [flow])
            if route_mtu is not None:
                # Without DF, a datagram over the inner route's MTU and within
                # the SA's is Linux's to encrypt whole: the bundle carries it
                # in one frame. The hardware does the same -- the size check
                # hands Linux only DF packets, and the enqueue to SEC
                # fragments nothing -- so it reaches the far end intact, as
                # one frame, without an answer, and encrypted in hardware.
                size = (bound + sa_mtu) // 2
                result = results[f"no-df-{size}"] = await probe(r, flow, size, df=False)
                r.record(label, {"sa_mtu": sa_mtu, "bound": bound, "results": results})
                assert result["lan"]["frag_needed"] == [] and result["delivered"] == 1, result
                assert result["hardware"] == 1 and result["toenc"] == 0, result
                assert result["fragments"] == {4: 0, 6: 0}, result
                unchanged(result["before"], result["after"], [0], [flow])
    finally:
        await command(r.target, r.session, *route, "mtu", str(FIXTURE_ROUTE_MTU))

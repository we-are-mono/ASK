"""Re-admit current MTUs through an unchanged table and established TCP socket,
and leave to Linux every IPv4 direction the microcode would have to fragment."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import threading
import time

import pytest

from ask_orch.client import Agent
from _topology import FULL_FRAME, LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import FLOWS, by_key, connections, healthy, peer  # noqa: F401
from test_flowtable_offload import (ARTIFACTS, DPORT, SPORT, TABLE, WAN_IP, command, ct_listing,  # noqa: F401
                                    read, rig)
from test_flowtable_selective_neighbour import hardware, keys, warm
from test_flowtable_tcp import connection, hardware_transfer, installed, software_tx, tcp_table

# A path below a full frame on either port, built by the cases that need one.
SMALL_PATH = 1200


def udp_ingresses(mtus):
    """The ports whose arriving UDP direction hardware carries at these MTUs.

    `mtus` maps each port to its MTU, which is also the path MTU of a
    direction leaving by it. The microcode fragments a non-DF IPv4 packet
    larger than its entry's MTU, and fragments it builds from a frame an
    Ethernet port received have zero-filled payloads, so the adapter installs
    a non-TCP direction only where its path carries the largest packet its
    ingress port can deliver. Every other one stays in Linux, which fragments
    correctly or answers DF with Fragmentation Needed."""
    return {dev for dev, out in ((TARGET_LAN_IF, TARGET_WAN_IF), (TARGET_WAN_IF, TARGET_LAN_IF))
            if mtus[out] >= max(mtus[dev], FULL_FRAME)}


def carried(flows, mtus):
    """`flows` with each UDP spec naming the directions Linux keeps at `mtus`."""
    kept = tuple(sorted({TARGET_LAN_IF, TARGET_WAN_IF} - udp_ingresses(mtus)))
    return [{**f, "software": kept} if f["proto"] == "udp" else f for f in flows]


async def table_identity(r):
    result = await command(r.target, r.session, "nft", "-a", "-j", "list", "table", "inet", TABLE)
    tables = [item["flowtable"] for item in json.loads(result["stdout"])["nftables"] if "flowtable" in item]
    assert len(tables) == 1 and "handle" in tables[0], result
    return tables[0]


def current_mtus(state, mtus):
    healthy(state)
    assert state["handle_refs"] == state["entries"], state
    assert all(int(f["mtu"]) == mtus[f["out"]] for f in state["flows"]), (mtus, state)


async def udp_warm(r, sport, mtus):
    """Exchange until the UDP tuple holds exactly the directions `mtus` admits."""
    wanted = udp_ingresses(mtus)
    for _ in range(8):
        await r.exchange(64, sport=sport, promiscuous=False)
        state = await r.state()
        if (sorted(f["in"] for f in state["flows"]) == sorted(wanted)
                and all(f["proto"] == "17" for f in state["flows"])):
            current_mtus(state, mtus)
            return state
    pytest.fail(f"UDP was not re-admitted on {sorted(wanted)}: {state}")


async def udp_size(r, sport, size, label, mtus=None):
    """256 datagrams of `size` bytes each way. The directions `mtus` admits
    (both, when it is not given) are counted by the classifier; one Linux
    keeps crosses in software and is counted by the port it leaves."""
    wanted = udp_ingresses(mtus) if mtus else {TARGET_LAN_IF, TARGET_WAN_IF}
    before, tx_before = await r.state(), await software_tx(r)
    # PROBE bypasses a PMTU learned by this endpoint during earlier changes;
    # the packet must reach the DUT to test its current MTU.
    reports = await r.exchange(256, payload_size=size, sport=sport,
                               ignore_pmtu=True, promiscuous=False)
    after, tx_after = await r.state(), await software_tx(r)
    healthy(after)
    if len(wanted) < 2:
        # The direction Linux keeps re-offers the flow about once a second.
        # Its refusal is decided before RTNL and the installed direction's
        # offer is answered without it, so nothing here should take RTNL at
        # all; busy moving would name an offer that did, before anything
        # below could only report what it cost.
        assert after["busy"] == before["busy"], ("an offer took RTNL mid-burst", before, after)
    assert before["installs"] == after["installs"] and before["deletes"] == after["deletes"], (before, after)
    old, new = by_key(before), by_key(after)
    assert old.keys() == new.keys() and sorted(key[0] for key in new) == sorted(wanted), (before, after)
    for key in old:
        assert old[key]["cookie"] == new[key]["cookie"], (key, before, after)
        assert int(new[key]["packets"]) - int(old[key]["packets"]) == 256
        assert int(new[key]["bytes"]) - int(old[key]["bytes"]) == 256 * (size + 42)
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    # A direction Linux keeps leaves by the port it did not arrive on.
    software = {dev: 0 for dev in tx}
    for ingress in {TARGET_LAN_IF, TARGET_WAN_IF} - wanted:
        software[TARGET_WAN_IF if ingress == TARGET_LAN_IF else TARGET_LAN_IF] += 256
    assert software[TARGET_LAN_IF] <= tx[TARGET_LAN_IF] <= 64 + software[TARGET_LAN_IF], tx
    assert software[TARGET_WAN_IF] <= tx[TARGET_WAN_IF] <= 128 + software[TARGET_WAN_IF], tx
    r.record(label, {"before": before, "after": after, "software_tx": tx, "transfers": reports})


async def test_flowtable_mtu_recovery(connections):
    r = connections
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS[:2]]
    ids, sport = [0, 1], flows[0]["sport"]
    original = {dev: int((await read(r.target, r.session, f"/sys/class/net/{dev}/mtu")).strip())
                for dev in (TARGET_LAN_IF, TARGET_WAN_IF)}
    assert all(mtu == 1500 for mtu in original.values()), original
    mtus = dict(original)
    identity = await table_identity(r)
    boot_id = await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")
    echo_socket = r.echo.transport.get_extra_info("socket")
    pmtu_option = getattr(socket, "IP_MTU_DISCOVER", 10)
    echo_pmtu = echo_socket.getsockopt(socket.SOL_IP, pmtu_option)
    try:
        async with peer(r, flows) as p:
            await warm(r, p, ids, "mtu-initial-admission", flows)
            initial = await hardware(r, p, "mtu-initial-hardware", flows)
            current_mtus(initial, mtus)
            # Exercise decrease and increase on each side. No conntrack flush,
            # flowtable recreation, adapter reload or socket reopen is allowed.
            # While a port is below a full frame, the UDP direction leaving by
            # it stays in Linux -- the other port can still deliver 1500 bytes
            # -- and the other three directions come back at the new MTUs.
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                for mtu in (1400, original[dev]):
                    before, tx_before = await r.state(), await software_tx(r)
                    await p.rpc("start", ids, count=0, interval=0.01)
                    await command(r.target, r.session, "ip", "link", "set", "dev", dev, "mtu", str(mtu))
                    mtus[dev] = mtu
                    expected = keys(ids, carried(flows, mtus))
                    after = await r.wait(lambda s: by_key(s).keys() == expected
                                         and s["deletes"] >= before["deletes"] + before["entries"]
                                         and all(int(f["mtu"]) == mtus[f["out"]] for f in s["flows"]))
                    reports = await p.rpc("stop", ids)
                    tx_after = await software_tx(r)
                    current_mtus(after, mtus)
                    # This case changes an MTU under RTNL while traffic is
                    # flowing, so an admission can lose rtnl_trylock and
                    # decline with -EAGAIN. With no IPsec policy configured
                    # that retires nothing -- the software path offers the
                    # flow again about a second later -- so whatever busy
                    # reads, the installs and deletes are exactly the
                    # directions this is counting.
                    assert after["installs"] == before["installs"] + len(expected), (before, after)
                    assert after["deletes"] == before["deletes"] + before["entries"], (before, after)
                    assert after["mtu_invalidations"] == before["mtu_invalidations"] + 2, (before, after)
                    assert after["rearms"] == initial["rearms"] and not after["invalidation_done"], after
                    assert all(report["count"] > 0 for report in reports.values()), reports
                    assert await table_identity(r) == identity
                    label = f"mtu-{dev}-{mtu}"
                    r.record(label, {"before": before, "after": after, "transfers": reports,
                                     "software_tx": {d: tx_after[d] - tx_before[d] for d in tx_before},
                                     "table": identity})
                    await hardware(r, p, label + "-hardware", carried(flows, mtus))

        # The TCP peer has closed cleanly and released the sole LAN console.
        # Keep the same table and UDP tuple for the MTU boundary itself. The
        # WAN endpoint can retain PMTU from the earlier TCP transitions; make
        # its UDP replies probe the path too, rather than fragment there.
        wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
        endpoint_route = await command(wan, r.session, "ip", "-j", "route", "get", r.lan_ip)
        r.record("mtu-endpoint-pmtu", {"route": json.loads(endpoint_route["stdout"]),
                                      "echo_pmtu_discover": echo_pmtu})
        echo_socket.setsockopt(socket.SOL_IP, pmtu_option, 3)  # IP_PMTUDISC_PROBE
        # Below a full frame on the WAN port, the upload's path no longer
        # carries what the LAN port can deliver, so Linux keeps that direction:
        # a datagram exactly at the new MTU crosses it in software, one byte
        # more with DF gets Linux's own Fragmentation Needed, and the download
        # stays in hardware throughout.
        lowered = await r.state()
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF, "mtu", "1400")
        mtus[TARGET_WAN_IF] = 1400
        refused = await udp_warm(r, sport, mtus)
        assert refused["rejects"] > lowered["rejects"], (lowered, refused)
        await udp_size(r, sport, 1372, "mtu-exact-boundary", mtus)
        probe = b"ASK-mtu-boundary".ljust(1373, b".")
        script = f'''
import json
from scapy.all import Ether, IP, UDP, ICMP, Raw, srp1
packet = Ether(dst={r.dut_lan_mac!r})/IP(src={r.lan_ip!r}, dst={WAN_IP!r}, flags='DF')/UDP(sport={sport}, dport={DPORT})/Raw({probe!r})
answer = srp1(packet, iface={LAN_NIC!r}, timeout=3, verbose=False)
assert answer is not None and ICMP in answer, answer
assert (answer[ICMP].type, answer[ICMP].code, answer[ICMP].nexthopmtu) == (3, 4, 1400), answer.show(dump=True)
print(json.dumps({{'type': answer[ICMP].type, 'code': answer[ICMP].code, 'mtu': answer[ICMP].nexthopmtu}}))
'''
        result = await lan_run_python(r.lan, script, timeout=15, label="flowtable_mtu_boundary")
        assert result.rc == 0, result.stdout
        assert not r.echo.received[probe], "oversized DF packet bypassed the new MTU"
        r.record("mtu-oversized-df", json.loads(result.stdout.strip()))
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF, "mtu", "1500")
        mtus[TARGET_WAN_IF] = 1500
        await udp_warm(r, sport, mtus)
        await udp_size(r, sport, 1432, "mtu-raised-boundary-hardware", mtus)
        assert await table_identity(r) == identity
        assert await read(r.target, r.session, "/proc/sys/kernel/random/boot_id") == boot_id
        r.record("mtu-complete", {"state": await r.state(), "table": identity, "boot_id": boot_id})
    finally:
        echo_socket.setsockopt(socket.SOL_IP, pmtu_option, echo_pmtu)
        try:
            await r.delete_table()
        finally:
            failures = []
            for dev, mtu in original.items():
                result = await command(r.target, r.session, "ip", "link", "set", "dev", dev,
                                       "mtu", str(mtu), check=False)
                if result["rc"]:
                    failures.append(result)
            assert not failures, failures


async def fragmenter(r):
    """The microcode fragmenter's cumulative counters, by their proc labels."""
    text = await read(r.target, r.session, "/proc/ucode_frag/stats")
    return {label.strip(): int(value) for label, value in
            (line.rsplit(":", 1) for line in text.splitlines() if ":" in line)}


async def test_flowtable_mtu_fragments_non_df_ipv4(rig):
    """An IPv4 datagram with DF clear that is larger than its path is
    fragmented by Linux, because the direction that would need the microcode
    to fragment it is never installed.

    The microcode fragments a non-DF IPv4 packet that exceeds its entry's MTU,
    and for a frame an Ethernet port received every payload byte of every
    fragment it builds is zero. So a UDP direction whose path is smaller than
    the largest frame its ingress port can deliver stays in Linux. Here the
    host route to the WAN endpoint is lowered to 1200 for the test: the
    LAN-to-WAN direction is refused, while the reverse -- arriving on the WAN
    port and leaving by the LAN port at its full MTU -- is still installed.

    The LAN sends 1250-byte payloads at its interface MTU with DF clear --
    whatever path MTU it learned from earlier tests -- and the WAN endpoint
    receives without answering. Every packet must leave the WAN port as exactly
    two fragments within 1200 bytes that carry the datagram's own bytes, the
    endpoint must reassemble each exactly once, and the microcode's fragmenter
    must count nothing. TCP into the same path stays in hardware, which
    test_flowtable_mtu_tcp_into_smaller_path proves."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("the refusal is a hardware admission decision")
    route = [WAN_IP + "/32", "dev", TARGET_WAN_IF]
    await command(r.target, r.session, "ip", "route", "replace", *route, "mtu", str(SMALL_PATH))
    try:
        await linux_fragments(r)
    finally:
        # Back to the fixture's route, which carries no MTU of its own. Never
        # checked here: a failure above is the one worth reporting, and the
        # fixture removes the route either way.
        await command(r.target, r.session, "ip", "route", "replace", *route, check=False)


async def linux_fragments(r):
    from scapy.all import AsyncSniffer, Ether, IP, wrpcap
    initial = await r.state()
    await r.table()
    await r.exchange()
    # Both directions are offered together: the upload is refused and the
    # download, whose path carries a full frame, is installed.
    admitted = await r.wait(lambda s: s["entries"] == 1 and s["rejects"] > initial["rejects"])
    reverse, = admitted["flows"]
    assert (reverse["in"], reverse["out"]) == (TARGET_WAN_IF, TARGET_LAN_IF), admitted
    assert int(reverse["mtu"]) == r.port_mtu, admitted
    count, size = 64, 1250
    payloads = [struct.pack("!Q", n) + b"ASK-fragment".ljust(size - 8, b".") for n in range(count)]
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, 10, 4)  # IP_MTU_DISCOVER: IP_PMTUDISC_INTERFACE, DF clear
s.bind(({r.lan_ip!r}, {SPORT}))
for n in range({count}):
    s.sendto(struct.pack('!Q', n) + b'ASK-fragment'.ljust({size - 8}, b'.'), ({WAN_IP!r}, {DPORT}))
    time.sleep(0.01)
s.close()
print(json.dumps({{'sent': {count}}}))
'''
    before, counters_before = await r.state(), await fragmenter(r)
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=r.wan_if, filter=f"ip src {r.lan_ip} and ip dst {WAN_IP}",
                           store=True, started_callback=ready.set)
    sniffer.start()
    r.echo.reply = False
    try:
        assert await asyncio.to_thread(ready.wait, 5), "endpoint capture did not start"
        # Management traffic also leaves by the WAN port, so nothing but the
        # counter reads themselves sits between these two.
        tx_before = await software_tx(r)
        result = await lan_run_python(r.lan, script, timeout=20, label="flowtable_fragment")
        assert result.rc == 0, result.stdout
        deadline = time.monotonic() + 5
        while sum(r.echo.received[p] for p in payloads) < count and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
        tx_after = await software_tx(r)
    finally:
        r.echo.reply = True
        frames = sniffer.stop()
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        wrpcap(str(ARTIFACTS / "fragments-non-df.pcap"), frames)
    after, counters_after = await r.state(), await fragmenter(r)
    listing = await ct_listing(r)
    moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
    r.record("fragments-non-df", {"before": before, "after": after, "fragmenter": moved,
                                  "software_tx": {d: tx_after[d] - tx_before[d] for d in tx_before},
                                  "conntrack": listing, "frames": len(frames)})
    # The endpoint reassembled each packet, once.
    assert [r.echo.received[p] for p in payloads] == [1] * count, [r.echo.received[p] for p in payloads]
    # The microcode fragmented nothing: no entry could have asked it to.
    assert moved == {label: 0 for label in counters_before}, moved
    # The download's entry is untouched: the same generation, and no traffic
    # of its own, since the endpoint did not answer.
    assert (after["installs"], after["deletes"], after["entries"]) == (
        before["installs"], before["deletes"], 1), (before, after)
    old, new = before["flows"][0], after["flows"][0]
    assert (new["in"], new["cookie"], new["packets"]) == (old["in"], old["cookie"], old["packets"]), (old, new)
    # Linux sent every fragment itself.
    assert tx_after[TARGET_WAN_IF] - tx_before[TARGET_WAN_IF] >= 2 * count, (tx_before, tx_after)
    # The wire: two fragments per packet, each within the path MTU, DF clear,
    # offsets contiguous, forwarded once with the DUT's own addressing -- and
    # between them the datagram's own header and payload, byte for byte,
    # which is exactly what the microcode's fragments of such a frame lack.
    groups = {}
    for frame in frames:
        if IP in frame:
            groups.setdefault(frame[IP].id, []).append(frame)
    assert len(groups) == count, sorted(groups)
    serials = set()
    for ident, fragments in groups.items():
        assert len(fragments) == 2, (ident, [f.summary() for f in fragments])
        first, last = sorted(fragments, key=lambda f: f[IP].frag)
        assert (first[IP].frag, int(first[IP].flags), int(last[IP].flags)) == (0, 1, 0), (first, last)
        assert last[IP].frag * 8 == first[IP].len - 4 * first[IP].ihl, (first, last)
        assert sum(f[IP].len - 4 * f[IP].ihl for f in fragments) == 8 + size, (first, last)
        for fragment in fragments:
            assert fragment[IP].len <= SMALL_PATH and fragment[IP].ttl == 63, fragment.summary()
            assert (fragment[Ether].src, fragment[Ether].dst) == (r.dut_wan_mac, r.wan_mac), fragment.summary()
            header = fragment[IP].copy()
            del header.chksum
            assert IP(bytes(header)).chksum == fragment[IP].chksum, fragment.summary()
        datagram = b"".join(bytes(f[IP])[4 * f[IP].ihl:f[IP].len] for f in (first, last))
        assert struct.unpack("!HHH", datagram[:6]) == (SPORT, DPORT, 8 + size), (ident, datagram[:8].hex())
        serial = struct.unpack("!Q", datagram[8:16])[0]
        assert serial < count and datagram[8:] == payloads[serial], (ident, datagram[8:40].hex())
        serials.add(serial)
    assert serials == set(range(count)), sorted(set(range(count)) - serials)


@pytest.mark.parametrize("rig", ["tcp"], indirect=True)
async def test_flowtable_mtu_tcp_into_smaller_path(rig):
    """TCP into a path smaller than a full frame stays in hardware, and an
    oversized segment on its entry is still Linux's to answer.

    TCP sets DF, so nothing on such an entry is ever the microcode's to
    fragment: a segment larger than the entry's MTU is excepted to Linux,
    which answers Fragmentation Needed with the path's MTU, and the sender's
    next segments fit. Both host routes are lowered to 1200 here -- the path
    the non-DF UDP case keeps in Linux -- and both directions of one connection
    are installed with it and carry an upload in hardware.

    Then the WAN host sends one segment on the installed tuple, one byte over
    the entry's MTU and with DF set. It is the DF check in hardware, which is
    the same for every protocol: Linux must answer it with 1200, the
    microcode's fragmenter must not count it, and the entry must still be the
    one that was installed. The connection is idle while the probe crosses, so
    the entry's own hit counter -- which counts a frame before it is excepted
    -- moving by exactly one is what shows the probe met the entry in
    hardware rather than reaching Linux some other way."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("the DF exception requires installed hardware")
    from scapy.all import Ether, ICMP, IP, TCP, Raw, srp1
    routes = [(r.lan_ip, TARGET_LAN_IF), (WAN_IP, TARGET_WAN_IF)]
    try:
        for address, dev in routes:
            await command(r.target, r.session, "ip", "route", "replace", address + "/32",
                          "dev", dev, "mtu", str(SMALL_PATH))
        await tcp_table(r)
        async with connection(r) as conn:
            admitted = await installed(r, conn)
            assert all(int(f["mtu"]) == SMALL_PATH for f in admitted["flows"]), admitted
            await hardware_transfer(r, conn, "upload", label="mtu-tcp-small-path-hardware")
            # The peer waits for its next command from here on; let the last
            # ACK of the transfer cross before the entries are read.
            await asyncio.sleep(0.5)
            before, counters_before = await r.state(), await fragmenter(r)
            # 20 bytes of IPv4 and 20 of TCP header, then one byte too many.
            probe = (Ether(src=r.wan_mac, dst=r.dut_wan_mac)
                     / IP(src=WAN_IP, dst=r.lan_ip, flags="DF")
                     / TCP(sport=DPORT, dport=SPORT, flags="A")
                     / Raw(b"M" * (SMALL_PATH - 39)))
            answer = await asyncio.to_thread(srp1, probe, iface=r.wan_if, timeout=3, verbose=False)
            after, counters_after = await r.state(), await fragmenter(r)
            moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
            r.record("mtu-tcp-oversized-df", {"answer": answer.summary() if answer else None,
                                              "before": before, "after": after, "fragmenter": moved})
            assert answer is not None and ICMP in answer, "oversized DF segment was not answered"
            assert (answer[ICMP].type, answer[ICMP].code, answer[ICMP].nexthopmtu) == (3, 4, SMALL_PATH), \
                answer.show(dump=True)
            assert moved == {label: 0 for label in counters_before}, moved
            assert (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]), (before, after)
            old, new = {f["in"]: f for f in before["flows"]}, {f["in"]: f for f in after["flows"]}
            assert {d: f["cookie"] for d, f in new.items()} == {d: f["cookie"] for d, f in old.items()}, \
                (before, after)
            hits = {d: int(new[d]["packets"]) - int(old[d]["packets"]) for d in old}
            assert hits == {TARGET_WAN_IF: 1, TARGET_LAN_IF: 0}, (hits, before, after)
            await conn.close("fin")
    finally:
        # Back to the fixture's routes, which carry no MTU of their own.
        for address, dev in routes:
            await command(r.target, r.session, "ip", "route", "replace", address + "/32", "dev", dev,
                          check=False)

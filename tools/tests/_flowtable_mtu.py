"""Shared support for flowtable mtu."""

from __future__ import annotations

import asyncio
import json
import struct
import threading
import time

import pytest
from _flowtable_connections import by_key, healthy
from _flowtable_rig import (
    DPORT,
    SPORT,
    TABLE,
    WAN_IP,
    artifact_dir,
    command,
    ct_listing,
    read,
)
from _flowtable_tcp import software_tx
from _topology import FULL_FRAME, LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python

# A path below a full frame on either port, built by the cases that need one.
SMALL_PATH = 1200


def udp_ingresses(mtus):
    """The ports whose arriving UDP direction hardware carries at these MTUs.

    `mtus` maps each port to its MTU, which is also the path MTU of a
    direction leaving by it. The microcode fragments a non-DF IPv4 packet
    larger than its entry's MTU, and fragments it builds from a frame an
    Ethernet port received have zero-filled payloads; of a frame an offline
    port took they are whole. So an IPv4 UDP direction whose path does not
    carry the largest packet its ingress port can deliver is carried through
    the offline-port detour (A385) -- the rig's device tree has the port --
    whose receive entry hands a DF packet that does not fit to Linux for its
    Fragmentation Needed: from a port that delivers no more than a standard
    frame, the detour taking no jumbo port (A394). Every other one stays in
    Linux, which fragments correctly or answers DF with Fragmentation
    Needed."""
    return {dev for dev, out in ((TARGET_LAN_IF, TARGET_WAN_IF), (TARGET_WAN_IF, TARGET_LAN_IF))
            if mtus[out] >= max(mtus[dev], FULL_FRAME) or mtus[dev] <= FULL_FRAME}


def detoured(flow, mtus):
    """Whether a direction is carried through the offline-port detour at
    these MTUs: an IPv4 UDP one from a standard port whose path is smaller
    than what that port delivers."""
    return (flow["proto"] == "17" and flow["family"] == "4"
            and mtus[flow["in"]] <= FULL_FRAME and mtus[flow["out"]] < FULL_FRAME)


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
    assert all(f["detour"] == str(int(detoured(f, mtus))) for f in state["flows"]), (mtus, state)


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


async def fragmenter(r):
    """The microcode fragmenter's cumulative counters, by their proc labels."""
    text = await read(r.target, r.session, "/proc/ucode_frag/stats")
    return {label.strip(): int(value) for label, value in
            (line.rsplit(":", 1) for line in text.splitlines() if ":" in line)}


DETOUR_COUNTERS = ("detour_flows", "detour_delivered", "detour_unknown", "detour_failed",
                   "detour_errors")


def detour_counters(state):
    """The offline-port detour's /proc/cdx_flowtable counters."""
    return {k: state[k] for k in DETOUR_COUNTERS}


async def detour_admitted(r):
    """The rig's UDP flow admitted with its upload into SMALL_PATH: both
    directions installed, the download, whose path carries a full frame, as
    it is, and the upload through the detour, its path being smaller than
    what its port delivers."""
    initial = await r.state()
    assert initial["detour"] == 1, ("the image's device tree has no detour port", initial)
    await r.table()
    await r.exchange()
    admitted = await r.wait(lambda s: s["entries"] == 2)
    upload = next(f for f in admitted["flows"] if f["in"] == TARGET_LAN_IF)
    reverse = next(f for f in admitted["flows"] if f["in"] == TARGET_WAN_IF)
    assert (upload["out"], upload["detour"], int(upload["mtu"])) == (
        TARGET_WAN_IF, "1", SMALL_PATH), admitted
    assert (reverse["out"], reverse["detour"], int(reverse["mtu"])) == (
        TARGET_LAN_IF, "0", r.port_mtu), admitted
    assert admitted["detour_flows"] == initial["detour_flows"] + 1, (initial, admitted)
    return admitted


async def lan_probes(r, script_body, label):
    """Run scapy on the LAN VM against the DUT and return its JSON line."""
    result = await lan_run_python(r.lan, script_body, timeout=30, label=label)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


async def detour_df(r):
    """A DF datagram the detoured path cannot carry is Linux's: the receive
    entry, carrying the path's MTU, hands it over as it arrived, and Linux
    answers Fragmentation Needed with that MTU. One that fits is carried
    whole, DF and all, through the offline port."""
    from scapy.all import IP, AsyncSniffer, wrpcap
    await detour_admitted(r)
    count = 16
    big = [b"ASK-df-big-%02d" % n for n in range(count)]
    fits = [b"ASK-df-fits-%02d" % n for n in range(count)]
    script = f'''
import json
from scapy.all import Ether, IP, UDP, ICMP, Raw, srp1, sendp
answers = []
for tag in {big!r}:
    packet = Ether(dst={r.dut_lan_mac!r})/IP(src={r.lan_ip!r}, dst={WAN_IP!r}, flags='DF')/UDP(sport={SPORT}, dport={DPORT})/Raw(tag.ljust(1250, b'.'))
    answer = srp1(packet, iface={LAN_NIC!r}, timeout=2, verbose=False)
    answers.append(None if answer is None or ICMP not in answer else
                   [answer[ICMP].type, answer[ICMP].code, answer[ICMP].nexthopmtu])
for tag in {fits!r}:
    sendp(Ether(dst={r.dut_lan_mac!r})/IP(src={r.lan_ip!r}, dst={WAN_IP!r}, flags='DF')/UDP(sport={SPORT}, dport={DPORT})/Raw(tag.ljust({SMALL_PATH - 28}, b'.')), iface={LAN_NIC!r}, verbose=False)
print(json.dumps({{"answers": answers}}))
'''
    before, counters_before = await r.state(), await fragmenter(r)
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=r.wan_if, filter=f"ip src {r.lan_ip} and ip dst {WAN_IP}",
                           store=True, started_callback=ready.set)
    sniffer.start()
    r.echo.reply = False
    try:
        assert await asyncio.to_thread(ready.wait, 5), "endpoint capture did not start"
        report = await lan_probes(r, script, "flowtable_detour_df")
        await asyncio.sleep(1.5)
    finally:
        r.echo.reply = True
        frames = sniffer.stop()
        artifact_dir().mkdir(parents=True, exist_ok=True)
        wrpcap(str(artifact_dir() / "detour-df.pcap"), frames)
    after, counters_after = await r.state(), await fragmenter(r)
    moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
    r.record("detour-df", {"report": report, "before": before, "after": after, "fragmenter": moved,
                           "frames": len(frames)})
    assert report["answers"] == [[3, 4, SMALL_PATH]] * count, report
    assert not any(r.echo.received[tag.ljust(1250, b".")] for tag in big), "a DF datagram went through"
    assert all(r.echo.received[tag.ljust(SMALL_PATH - 28, b".")] == 1 for tag in fits), "a fitting one was lost"
    # The fitting ones whole and unfragmented, DF kept, by the hardware: the
    # fragmenter saw none of them, and the offline port handed nothing back.
    whole = [f for f in frames if IP in f and int(f[IP].flags) == 2 and f[IP].len == SMALL_PATH]
    assert len(whole) == count, [f.summary() for f in frames]
    assert moved["IPv4 frames received"] == 0, moved
    assert detour_counters(after) == detour_counters(before), (before, after)
    assert (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]), (before, after)


async def detour_ttl(r):
    """A datagram whose TTL runs out on the DUT is Linux's, which answers Time
    Exceeded, on a detoured direction as on any: none goes through. Six, the
    burst Linux's per-peer limit on that answer allows."""
    await detour_admitted(r)
    count = 6
    tags = [b"ASK-ttl-%02d" % n for n in range(count)]
    script = f'''
import json
from scapy.all import Ether, IP, UDP, ICMP, Raw, srp1
answers = []
for n, tag in enumerate({tags!r}):
    size = 1250 if n % 2 else 200
    packet = Ether(dst={r.dut_lan_mac!r})/IP(src={r.lan_ip!r}, dst={WAN_IP!r}, ttl=1)/UDP(sport={SPORT}, dport={DPORT})/Raw(tag.ljust(size, b'.'))
    answer = srp1(packet, iface={LAN_NIC!r}, timeout=2, verbose=False)
    answers.append(None if answer is None or ICMP not in answer else
                   [answer[ICMP].type, answer[ICMP].code])
print(json.dumps({{"answers": answers}}))
'''
    before = await r.state()
    r.echo.reply = False
    try:
        report = await lan_probes(r, script, "flowtable_detour_ttl")
        await asyncio.sleep(1.5)
    finally:
        r.echo.reply = True
    after = await r.state()
    r.record("detour-ttl", {"report": report, "before": before, "after": after})
    assert report["answers"] == [[11, 0]] * count, report
    assert not any(r.echo.received[tag.ljust(1250 if n % 2 else 200, b".")]
                   for n, tag in enumerate(tags)), "a spent datagram went through"
    assert (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]), (before, after)


STRAND = "/sys/module/cdx/parameters/detour_strand"


async def detour_handback(r):
    """What the offline port hands back reaches Linux on the port it came in
    by, which forwards it. The receive entry is installed alone (`detour_strand`,
    a test knob), so every frame of the direction misses on the offline port,
    as one does whose entry went between the two lookups, and comes back by
    the port's PCD queues with nothing to say where it arrived: the detour's
    record of the direction says. Every datagram reaches the endpoint once --
    a large one fragmented by Linux, a small one as it was -- and each is
    counted as given to Linux, none as unknown."""
    assert (await r.target.fs_write(r.session, STRAND, "1"))["errno"] == 0
    try:
        await detour_admitted(r)
    finally:
        assert (await r.target.fs_write(r.session, STRAND, "0"))["errno"] == 0
    count = 32
    payloads = [struct.pack("!Q", n) + b"ASK-handback".ljust((1250 if n % 2 else 200) - 8, b".")
                for n in range(count)]
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, 10, 4)  # IP_MTU_DISCOVER: IP_PMTUDISC_INTERFACE, DF clear
s.bind(({r.lan_ip!r}, {SPORT}))
for n in range({count}):
    s.sendto(struct.pack('!Q', n) + b'ASK-handback'.ljust((1250 if n % 2 else 200) - 8, b'.'), ({WAN_IP!r}, {DPORT}))
    time.sleep(0.01)
s.close()
print(json.dumps({{'sent': {count}}}))
'''
    before, counters_before = await r.state(), await fragmenter(r)
    r.echo.reply = False
    try:
        await lan_probes(r, script, "flowtable_detour_handback")
        deadline = time.monotonic() + 5
        while sum(r.echo.received[p] for p in payloads) < count and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
    finally:
        r.echo.reply = True
    after, counters_after = await r.state(), await fragmenter(r)
    moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
    r.record("detour-handback", {"before": before, "after": after, "fragmenter": moved})
    assert [r.echo.received[p] for p in payloads] == [1] * count, [r.echo.received[p] for p in payloads]
    delta = {k: after[k] - before[k] for k in DETOUR_COUNTERS}
    assert delta == {"detour_flows": 0, "detour_delivered": count, "detour_unknown": 0,
                     "detour_failed": 0, "detour_errors": 0}, delta
    # Nothing reached the offline port's fragmenter: no entry there to ask.
    assert moved["IPv4 frames received"] == 0, moved
    assert (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]), (before, after)


async def detour_fragments(r):
    from scapy.all import IP, AsyncSniffer, Ether, wrpcap
    await detour_admitted(r)
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
        artifact_dir().mkdir(parents=True, exist_ok=True)
        wrpcap(str(artifact_dir() / "fragments-non-df.pcap"), frames)
    # The hardware's counters reach the adapter on its statistics pass.
    await asyncio.sleep(1.5)
    after, counters_after = await r.state(), await fragmenter(r)
    listing = await ct_listing(r)
    moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
    r.record("fragments-non-df", {"before": before, "after": after, "fragmenter": moved,
                                  "software_tx": {d: tx_after[d] - tx_before[d] for d in tx_before},
                                  "conntrack": listing, "frames": len(frames)})
    # The endpoint reassembled each packet, once.
    assert [r.echo.received[p] for p in payloads] == [1] * count, [r.echo.received[p] for p in payloads]
    # The offline port's microcode fragmented each, into two, with buffers to
    # spare.
    assert moved["IPv4 frames received"] == count, moved
    assert moved["Number of IPv4 fragments sent"] == 2 * count, moved
    assert moved["Failures in allocating buffers"] == 0, moved
    # The entries are untouched -- the same generation -- and the upload's
    # counted every packet as it arrived; nothing was handed back.
    assert (after["installs"], after["deletes"], after["entries"]) == (
        before["installs"], before["deletes"], 2), (before, after)
    old = {f["in"]: f for f in before["flows"]}
    new = {f["in"]: f for f in after["flows"]}
    assert all(new[d]["cookie"] == old[d]["cookie"] for d in old), (old, new)
    assert int(new[TARGET_LAN_IF]["packets"]) - int(old[TARGET_LAN_IF]["packets"]) == count, (old, new)
    assert new[TARGET_WAN_IF]["packets"] == old[TARGET_WAN_IF]["packets"], (old, new)
    assert detour_counters(after) == detour_counters(before), (before, after)
    # Linux sent none of them.
    assert tx_after[TARGET_WAN_IF] - tx_before[TARGET_WAN_IF] < count, (tx_before, tx_after)
    # The wire: two fragments per packet, each within the path MTU, DF clear,
    # offsets contiguous, forwarded once with the DUT's own addressing -- and
    # between them the datagram's own header and payload, byte for byte,
    # which is exactly what the microcode's fragments of a frame an Ethernet
    # port received lack.
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


# The fragmented datagrams a second the detour forwards at the least: measured
# at some 530k on the DK, the offline port its bound.
DETOUR_FLOOR_PPS = 400_000


def _host_rx(name):
    """The WAN host NIC's MAC-level receive count, and what it dropped."""
    import subprocess
    out = subprocess.run(["ethtool", "-S", name], capture_output=True, text=True,
                         timeout=5, check=True).stdout
    stats = {k.strip(): int(v) for k, v in (line.split(":", 1) for line in out.splitlines()[1:])
             if v.strip().isdigit()}
    return {k: stats[k] for k in ("rx_packets_phy", "rx_dropped") if k in stats}


async def detour_overload(r, seconds=5, frame=1514):
    """A detoured direction offered more than the offline port forwards --
    the LAN VM's pktgen at the 10G line rate, every datagram to be fragmented
    -- loses what it cannot carry at the queue into the port, whose tail drop
    hands the buffers back: afterwards every pool holds what it held, give or
    take what the CPUs refill. What it does carry arrives whole, two
    fragments a datagram, at no less than DETOUR_FLOOR_PPS, and the FMan's
    host-command channel stays healthy: nothing installed or deleted fails."""
    from _flowtable_service_ipsec import wire_interface
    from _flowtable_service_multicast_leave import pool_contents
    await detour_admitted(r)
    wire = wire_interface(r)
    commands = ["count 0", "clone_skb 1000", f"pkt_size {frame - 4}", "burst 32",
                f"dst_mac {r.dut_lan_mac}", f"src_min {r.lan_ip}", f"src_max {r.lan_ip}",
                f"dst_min {WAN_IP}", f"dst_max {WAN_IP}", f"udp_src_min {SPORT}", f"udp_src_max {SPORT}",
                f"udp_dst_min {DPORT}", f"udp_dst_max {DPORT}", "flag UDPCSUM"]
    script = f'''
import json, subprocess, threading, time
from pathlib import Path
root = Path("/proc/net/pktgen")
subprocess.run(["modprobe", "pktgen"], check=True)
def pg(path, cmd):
    (root / path).write_text(cmd + "\\n")
def nic():
    out = subprocess.check_output(["ethtool", "-S", {LAN_NIC!r}], text=True)
    st = {{k.strip(): int(v) for k, v in (l.split(":", 1) for l in out.splitlines()[1:]) if v.strip().isdigit()}}
    return st.get("tx_pkts_nic", st.get("tx_packets"))
dev = "{LAN_NIC}@0"
pg("kpktgend_0", "rem_device_all")
pg("kpktgend_0", f"add_device {{dev}}")
try:
    for cmd in {commands!r} + ["queue_map_min 0", "queue_map_max 0"]:
        pg(dev, cmd)
    before = nic()
    t = threading.Thread(target=pg, args=("pgctrl", "start"))
    t.start()
    time.sleep({seconds})
    pg("pgctrl", "stop")
    t.join()
    after = nic()
finally:
    pg("kpktgend_0", "rem_device_all")
print(json.dumps({{"sent": after - before}}))
'''
    before, counters_before = await r.state(), await fragmenter(r)
    pools = await pool_contents(r)
    host_before = _host_rx(wire)
    r.echo.reply = False
    try:
        sender = await lan_probes(r, script, "flowtable_detour_overload")
        await asyncio.sleep(2)
    finally:
        r.echo.reply = True
    host_after = _host_rx(wire)
    after, counters_after = await r.state(), await fragmenter(r)
    drained = await pool_contents(r)
    moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
    host = {k: host_after[k] - host_before[k] for k in host_before}
    record = {"sender": sender, "fragmenter": moved, "host": host, "pools": pools,
              "drained": drained, "before": before, "after": after,
              "detoured_pps": moved["IPv4 frames received"] / seconds}
    r.record("detour-overload", record)
    # More was offered than carried: the case is about the overload.
    assert sender["sent"] > moved["IPv4 frames received"] * 1.1, record
    assert moved["IPv4 frames received"] / seconds >= DETOUR_FLOOR_PPS, record
    assert moved["Number of IPv4 fragments sent"] == 2 * moved["IPv4 frames received"], record
    assert moved["Failures in allocating buffers"] == 0, record
    # Every fragment the port sent reached the WAN host, which kept up.
    assert host.get("rx_dropped", 0) == 0, record
    assert host["rx_packets_phy"] >= moved["Number of IPv4 fragments sent"], record
    # Nothing was handed back, and the entries stood throughout.
    assert detour_counters(after) == detour_counters(before), record
    assert (after["installs"], after["deletes"], after["entries"]) == (
        before["installs"], before["deletes"], 2), record
    # No buffer was kept by a rejected enqueue.
    assert pools.keys() == drained.keys(), record
    for bpid, count in pools.items():
        assert abs(drained[bpid] - count) < 512, (bpid, record)
    # And the host-command channel came through it: the entries go, each
    # deletion's barrier completing, with nothing failed or left unproven.
    await r.delete_table()
    gone = await r.wait(lambda s: s["entries"] == 0)
    assert (gone["errors"], gone["quarantine"], gone["invalidated"]) == (
        before["errors"], before["quarantine"], before["invalidated"]), (before, gone)


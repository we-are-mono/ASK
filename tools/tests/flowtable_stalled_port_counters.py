"""What a port that stops sending reads in the standard counters.

An offloaded frame is enqueued by the port it arrived on, straight to the queue
of the port it leaves by. When that port stops sending -- its link partner
pauses it, as a congested switch or host does -- its queue fills, and FMan
drops the rest with nothing told, refused at the enqueue once the queue's group
is full. The port must not then read as having sent them (A338), and the port
they arrived on must count them as drops (A339). Each frame the queue holds
takes a buffer from the pool every DPAA port receives into, so the group's
bound must leave that pool enough to receive into whatever the frames' size
(A341).
"""
from __future__ import annotations

import asyncio
import json
import socket
import time

import pytest

from _flowtable_rig import DPORT, SPORT, WAN_IP, console_python, pings_answered
from _lan_pause import while_lan_port_paused
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from ask_orch.uart import Console

FMAN = "/sys/devices/platform/soc/1a00000.fman"
# Frames the kernel itself sends on the paused port while the test runs --
# neighbour and router traffic -- are counted by both sides alike; allow some.
KERNEL_SLACK = 1000
# Pings to the DUT's WAN address while the LAN port is paused, which the
# blast outlasts.
PINGS = 20


async def _counters(r):
    """The ports' standard counters, their MACs' transmit registers, and every
    FMan port's statistics, in one read."""
    script = f'''
import glob, json, os
links = {{}}
for dev in ({TARGET_LAN_IF!r}, {TARGET_WAN_IF!r}):
    stats = {{}}
    for name in ("tx_packets", "tx_bytes", "rx_packets", "rx_dropped", "rx_missed_errors", "tx_dropped"):
        stats[name] = int(open(f"/sys/class/net/{{dev}}/statistics/{{name}}").read())
    mac = {{}}
    for line in open(f"/sys/class/net/{{dev}}/mac_tx_stats"):
        parts = line.split()
        if len(parts) >= 3 and parts[0].endswith(":"):
            mac[parts[-1]] = int(parts[1], 16)
    stats["mac"] = mac
    links[dev] = stats
ports = {{}}
for path in glob.glob("{FMAN}/*.port/statistics/*"):
    try:
        ports[path[len("{FMAN}/"):]] = int(open(path).read().split()[-1])
    except (OSError, ValueError, IndexError):
        pass
print(json.dumps({{"links": links, "ports": ports}}))
'''
    result = await console_python(Console.target(), script, timeout=30)
    return json.loads(result["stdout"].strip().splitlines()[-1])


def _mac_frames(mac):
    """Frames the MAC sent, from its 64-bit registers: its unicast, multicast
    and broadcast frames, which leave out the PAUSE frames it sends itself."""
    def counter(name):
        return mac.get(f"{name}_l", 0) | mac.get(f"{name}_u", 0) << 32
    return counter("tuca") + counter("tmca") + counter("tbca")


def _blast(sock, lan_ip, seconds, size):
    """Datagrams of `size` bytes down the offloaded flow, from the WAN end of
    it."""
    payload, sent = bytes(size), 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for _ in range(64):
            try:
                sock.sendto(payload, (lan_ip, SPORT))
                sent += 1
            except OSError:
                pass
    return sent


async def _paused_blast(r, size, label):
    """Three seconds of `size`-byte datagrams down the offloaded flow, from the
    WAN end of it, with the LAN port paused throughout, and the WAN host
    pinging the DUT's WAN address meanwhile. Returns what was sent and what
    the counters made of it."""
    await r.table()
    await r.admit()
    flows = (await r.state())["flows"]
    down = next(f for f in flows if f["in"] == TARGET_WAN_IF)
    # The WAN end's address and port, which the flow is keyed on: the rig's
    # echo gives them up to a blocking socket of the case's own. Replies are
    # irrelevant, as the LAN end is about to stop answering.
    r.echo.transport.close()
    # The transport closes its socket on the loop's next turn.
    await asyncio.sleep(0.1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((WAN_IP, DPORT))
    try:
        before = await _counters(r)
        flow_before = int(down["packets"])
        # The pings start once the paused port's queue is full: a fraction
        # of a second of the blast fills it.
        (sent, answered), pauses = await while_lan_port_paused(
            r, lambda: asyncio.gather(asyncio.to_thread(_blast, sock, r.lan_ip, 3, size),
                                      pings_answered(r.dut_wan_ip, PINGS, 0.5)), 3)
        # What the port's queue held goes out once the pause lifts.
        await asyncio.sleep(2)
        after = await _counters(r)
        state = await r.state()
    finally:
        sock.close()
    flow = next(f for f in state["flows"] if f["cookie"] == down["cookie"])
    hits = int(flow["packets"]) - flow_before
    delta = {dev: {k: after["links"][dev][k] - before["links"][dev][k]
                   for k in before["links"][dev] if k != "mac"}
             for dev in after["links"]}
    wire = _mac_frames(after["links"][TARGET_LAN_IF]["mac"]) - _mac_frames(before["links"][TARGET_LAN_IF]["mac"])
    ports = {k: after["ports"][k] - before["ports"].get(k, 0)
             for k in after["ports"] if after["ports"][k] != before["ports"].get(k, 0)}
    record = {"sent": sent, "pauses": pauses, "hits": hits, "wire": wire, "answered": answered,
              "delta": delta, "ports": ports,
              "mac_before": before["links"][TARGET_LAN_IF]["mac"],
              "mac_after": after["links"][TARGET_LAN_IF]["mac"]}
    r.record(label, record)
    assert sent > 100_000 and hits > 100_000, record
    return record


async def test_paused_port_leaves_the_pool(rig):
    """A341: the frames a paused port's queue holds take buffers from the pool
    every DPAA port receives into, and small frames offloaded towards it must
    not take them all. The WAN port keeps receiving -- the DUT answers pings
    to its address throughout -- and what the paused port's queue cannot take
    is refused at the enqueue, a drop, never lost for want of a buffer."""
    record = await _paused_blast(rig, 64, "stalled-port-pool")
    wan = record["delta"][TARGET_WAN_IF]
    assert record["answered"] == PINGS, record
    assert wan["rx_missed_errors"] == 0, record
    assert wan["rx_dropped"] >= record["hits"] - record["wire"] - KERNEL_SLACK, record


# The DUT made to send PAUSE frames of its own on its WAN port: for two seconds
# its receive port draws buffers from a pool that has none and asks for PAUSE
# as soon as its FIFO holds anything, while the WAN host floods the port with
# datagrams nothing answers. Both registers are put back. Reads the MAC's
# transmit registers and the port's standard counters around it, each pair of
# reads taken again until the MAC sent nothing between them.
SEND_PAUSE = f'''
import ctypes, glob, json, mmap, os, subprocess, time
DEV = {TARGET_WAN_IF!r}
nodes = {{}}
for p in glob.glob("/proc/device-tree/soc/**/phandle", recursive=True):
    nodes[int.from_bytes(open(p, "rb").read(), "big")] = os.path.dirname(p)
def ref(node, prop):
    return nodes[int.from_bytes(open(os.path.join(node, prop), "rb").read()[:4], "big")]
mac_node = ref(os.path.realpath(f"/sys/class/net/{{DEV}}/device/of_node"), "fsl,fman-mac")
rx_port = ref(mac_node, "fsl,fman-ports")
bmi = 0x1a00000 + int.from_bytes(open(os.path.join(rx_port, "reg"), "rb").read()[:4], "big")
fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
regs = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=bmi)
bman = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0x1890000)
def reg(m, off):
    return ctypes.c_uint32.from_buffer(m, off)
def word(m, off):
    return int.from_bytes(reg(m, off).value.to_bytes(4, "little"), "big")
def put(off, value):
    reg(regs, off).value = int.from_bytes(value.to_bytes(4, "big"), "little")
def free(bpid):
    return word(bman, 0x600 + 4 * bpid) & 0x7fffff
# A pool no receive port draws from and that holds nothing: the starved port's
# frames then find no buffer at all, rather than one some other port owns.
used = set()
for node in glob.glob("/proc/device-tree/soc/fman@1a00000/port@*"):
    compat = open(os.path.join(node, "compatible"), "rb").read()
    if b"port-rx" not in compat:
        continue
    page = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                     offset=0x1a00000 + int.from_bytes(open(os.path.join(node, "reg"), "rb").read()[:4], "big"))
    for i in range(8):
        info = word(page, 0x100 + 4 * i)
        if info & 0x80000000:
            used.add(info >> 16 & 0x3f)
empty = next(b for b in range(63, 0, -1) if b not in used and free(b) == 0)
def mac():
    out = {{}}
    for line in open(f"/sys/class/net/{{DEV}}/mac_tx_stats"):
        parts = line.split()
        if len(parts) >= 3 and parts[0].endswith(":"):
            out[parts[-1]] = int(parts[1], 16)
    return {{n: out[n + "_l"] | out[n + "_u"] << 32 for n in ("txpf", "tfrm", "tuca", "tmca", "tbca", "toct")}}
def snapshot():
    for _ in range(100):
        first = mac()
        stats = {{n: int(open(f"/sys/class/net/{{DEV}}/statistics/{{n}}").read())
                 for n in ("tx_packets", "tx_bytes")}}
        if mac() == first:
            return {{**first, **stats}}
    raise RuntimeError("the MAC never stood still for a reading")
rule = ["INPUT", "-i", DEV, "-p", "udp", "--dport", "9", "-j", "DROP"]
subprocess.run(["iptables", "-I", *rule], check=True)
rfp, ebmpi = word(regs, 0x00c), word(regs, 0x100)
try:
    before = snapshot()
    time.sleep(1)
    put(0x00c, rfp & ~0x3ff)
    put(0x100, (ebmpi & ~0x003f0000) | empty << 16)
    time.sleep(2)
finally:
    put(0x100, ebmpi)
    put(0x00c, rfp)
    subprocess.run(["iptables", "-D", *rule])
time.sleep(1)
after = snapshot()
print(json.dumps({{"bpid": empty, "delta": {{k: after[k] - before[k] for k in before}}}}))
'''


def _discard_flood(address, seconds):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload, end = bytes(1400), time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            try:
                sock.sendto(payload, (address, 9))
            except OSError:
                pass
    finally:
        sock.close()


async def test_sent_pause_is_no_frame(rig):
    """The PAUSE frames a port sends itself are among its MAC's good frames
    and octets (TFRM, TOCT), and not among its unicast, multicast or broadcast
    frames, so a port's transmit counts take their frames from the latter and
    their octets less the PAUSE frames' -- which no one sent (A338, A349). The
    DUT made to send some, its counts are the MAC's data frames exactly."""
    r = rig
    flood = asyncio.create_task(asyncio.to_thread(_discard_flood, r.dut_wan_ip, 8))
    try:
        result = await console_python(Console.target(), SEND_PAUSE, timeout=60)
    finally:
        await flood
    record = json.loads(result["stdout"].strip().splitlines()[-1])
    # The port receives again once its registers are back.
    record["answered"] = await pings_answered(r.dut_wan_ip, 5, 0.2)
    r.record("sent-pause", record)
    assert record["answered"] == 5, record
    d = record["delta"]
    frames = d["tuca"] + d["tmca"] + d["tbca"]
    assert d["txpf"] > 0, record
    assert d["tfrm"] == frames + d["txpf"], record
    assert d["tx_packets"] == frames, record
    assert d["tx_bytes"] == d["toct"] - 64 * d["txpf"] - 4 * frames, record


@pytest.mark.parametrize("size", [64, 1400], ids=["small", "full"])
async def test_paused_port_counts(rig, size):
    """The LAN VM pauses the DUT's LAN port with 802.3x PAUSE frames, as a
    congested switch or host does. The WAN host meanwhile sends down an
    offloaded flow to it far more than the port's queue holds. The LAN port's
    transmit count is what its MAC sent, not what was queued for it, and the
    WAN port counts the rest as received and dropped."""
    r = rig
    record = await _paused_blast(r, size, "stalled-port-counters")
    hits, wire, delta = record["hits"], record["wire"], record["delta"]
    # The pause held: far fewer frames left than arrived for the port.
    dropped = hits - wire
    assert dropped > hits // 2, record
    # A338: what the port says it sent is what its MAC sent.
    assert abs(delta[TARGET_LAN_IF]["tx_packets"] - wire) <= KERNEL_SLACK, record
    # A339: the port the frames came in by counts the rest, refused at the
    # enqueue, as drops.
    wan = delta[TARGET_WAN_IF]
    assert abs(wan["rx_dropped"] - dropped) <= KERNEL_SLACK, record

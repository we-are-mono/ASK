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
import re
import socket
import time

import pytest

from _flowtable_rig import DPORT, SPORT, WAN_IP, console_python
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
    """Frames the MAC sent, from its 64-bit registers: its good frames, less
    the PAUSE frames it sent itself."""
    def counter(name):
        return mac.get(f"{name}_l", 0) | mac.get(f"{name}_u", 0) << 32
    return counter("tfrm") - counter("txpf")


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


async def _ping(address, count, delay):
    """How many of `count` pings to `address`, from the WAN host, a tenth of a
    second apart and starting `delay` seconds from now, were answered."""
    await asyncio.sleep(delay)
    proc = await asyncio.create_subprocess_exec(
        "ping", "-n", "-q", "-c", str(count), "-i", "0.1", "-W", "1", address,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    received = re.search(r"(\d+) (?:packets )?received", out.decode())
    assert received, out.decode()
    return int(received.group(1))


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
                                      _ping(r.dut_wan_ip, PINGS, 0.5)), 3)
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

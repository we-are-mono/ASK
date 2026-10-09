"""A flood the CPU cannot keep up with must not take the Ethernet buffer pool.

Every DPAA port receives into one pool, and a frame for the CPU holds its
buffer from the port's receive until the CPU has taken it; only then is a buffer
put back for it. Traffic for the gateway itself, or for a flow not yet in
hardware, offered faster than the CPU handles it, queues on the port's queues
to the CPU, and those were bounded at 256 MB: the queue took the whole pool,
and every port missed whatever it received, offloaded forwarding included
(A347).
"""
from __future__ import annotations

import asyncio
import multiprocessing
import socket
import time

from _flowtable_rig import pool_lowest, port_drops
from _topology import TARGET_LAN_IF, TARGET_WAN_IF

# The discard service: nothing on the gateway listens there, so every datagram
# is the CPU's to receive and throw away.
DISCARD = 9


def _blast(address, seconds):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload, sent, end = bytes(64), 0, time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            for _ in range(64):
                try:
                    sock.sendto(payload, (address, DISCARD))
                    sent += 1
                except OSError:
                    pass
    finally:
        sock.close()
    return sent


def _flood(address, seconds, senders=4):
    """Small datagrams to the gateway's own address from several processes at
    once, as fast as each goes: several times what its CPU receives."""
    with multiprocessing.get_context("fork").Pool(senders) as pool:
        return sum(pool.starmap(_blast, [(address, seconds)] * senders))


async def test_cpu_flood_leaves_the_pool(rig):
    """The WAN host floods the gateway's own WAN address, which only the CPU
    can take. The port's queues to the CPU hold no more of the pool than their
    share; what they cannot take is refused at the enqueue, a drop, and
    neither port loses anything for want of a buffer."""
    r = rig
    bpid, idle = await pool_lowest(0)
    before = await port_drops()
    sent, (_, lowest) = await asyncio.gather(
        asyncio.to_thread(_flood, r.dut_wan_ip, 4),
        pool_lowest(6, bpid))
    after = await port_drops()
    drops = {dev: {k: after[dev][k] - before[dev][k] for k in before[dev]} for dev in before}
    record = {"sent": sent, "drops": drops, "pool": {"bpid": bpid, "idle": idle, "lowest": lowest}}
    r.record("cpu-flood-pool", record)
    wan = drops[TARGET_WAN_IF]
    # What the WAN host's own queues let through is a fraction of what it
    # counts as sent; what reached the gateway was still more than its CPU
    # takes, and the rest was refused at the queue.
    assert sent > 1_000_000, record
    assert wan["rx_dropped"] > 100_000, record
    assert wan["rx_missed_errors"] == 0 and drops[TARGET_LAN_IF]["rx_missed_errors"] == 0, record
    # The pool kept at least half of itself to receive into.
    assert lowest >= idle // 2, record

"""A port that stops sending must not take SEC's output pool with it.

Every frame SEC writes sits in a buffer of one pool all SAs share until the
port it leaves by has sent it. A port its link partner pauses -- 802.3x flow
control from a congested switch or host -- sends nothing, and keeps what is
queued for it. The decrypted frames among them hold the pool's buffers, and a
queue bounded in bytes for its latency (A313) held many more of them than the
pool has: SEC refused every SA's jobs for want of an output buffer, until the
port sent again (A335). They now wait on queues of their own, bounded by count.
"""
from __future__ import annotations

import asyncio
import re
import socket
import time

from _flowtable_ipv6 import PayloadEcho, _drive, _drop_tables, _udp_exchange
from _flowtable_ipv6_sa import STALL_DPORT, STALL_SPORT, tunnel
from _flowtable_qos import egress, leaf_delta
from _flowtable_rig import command, console_command, console_python
from _flowtable_service_ipsec import SEC_EGRESS_FRAMES, SEC_POOL
from _lan_pause import while_lan_port_paused
from _topology import LAN_IPV6, TARGET_WAN_IF, WAN_IPV6
from ask_orch.uart import Console

# The lowest free count SEC's output pool reaches over a stretch, read from
# BMan's big-endian content register for the pool cdx publishes.
POOL_LOWEST = '''
import ctypes, mmap, os, time
bpid = int(open('/sys/module/cdx/parameters/ipsec_bpid').read())
fd = os.open('/dev/mem', os.O_RDWR | os.O_SYNC)
regs = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0x1890000)
word = ctypes.c_uint32.from_buffer(regs, 0x600 + 4 * bpid)
lowest, end = 1 << 30, time.monotonic() + {seconds}
while True:
    lowest = min(lowest, int.from_bytes(word.value.to_bytes(4, 'little'), 'big') & 0x7fffff)
    if time.monotonic() >= end:
        break
print('lowest', lowest)
del word
regs.close()
'''


def _blast(seconds):
    """Small datagrams from the WAN host down the tunnel to the LAN VM's end
    of the flow, as fast as one socket goes."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((WAN_IPV6, STALL_DPORT))
    payload, sent = bytes(64), 0
    end = time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            for _ in range(64):
                try:
                    s.sendto(payload, (LAN_IPV6, STALL_SPORT))
                    sent += 1
                except OSError:
                    pass
    finally:
        s.close()
    return sent


async def test_paused_lan_port_leaves_sec_its_buffers(ipv6_rig):
    """The LAN VM pauses the DUT's LAN port with 802.3x PAUSE frames, as a
    congested switch or host does. The WAN host meanwhile sends small
    datagrams through the tunnel to it, on a flow in hardware, and SEC refuses
    none of them for want of a buffer."""
    r = ipv6_rig
    cleanup = []
    echo = PayloadEcho()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, STALL_DPORT), family=socket.AF_INET6)
    try:
        await tunnel(r, cleanup, f"udp sport {STALL_SPORT} udp dport {STALL_DPORT}")

        async def send(count=8):
            return await _udp_exchange(r, STALL_SPORT, WAN_IPV6, STALL_DPORT, count,
                                       (WAN_IPV6, STALL_DPORT), "flowtable_ipsec_stalled_port")

        await _drive(r, send, lambda s: s["entries"] == 2,
                     "both directions of the flow should be in hardware")
        transport.close()
        start = await r.state()
        (lowest, sent), pauses = await while_lan_port_paused(r, lambda: asyncio.gather(
            console_python(Console.target(), POOL_LOWEST.format(seconds=4), timeout=30),
            asyncio.to_thread(_blast, 3)), 4)
        await asyncio.sleep(1.5)
        end = await r.state()
    finally:
        transport.close()
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)
    refused = {key: end[key] - start[key] for key in end
               if key.startswith(("ipsec_sec_refused", "ipsec_offline_port_rejected"))}
    record = {"sent": sent, "pauses": pauses, "refused": refused, "flows": end["flows"],
              "pool_lowest": int(re.search(r"lowest (\d+)", lowest["stdout"]).group(1))}
    r.record("ipsec-paused-port", record)
    assert sent > 10_000, record
    assert refused["ipsec_sec_refused_buffer_depletion"] == 0, record
    # The port did stop, its queues held SEC's frames up to the port's share
    # of the pool and no further -- the rest is what SEC has in flight -- and
    # what it could not take was refused at the offline port.
    lowest = record["pool_lowest"]
    assert SEC_POOL - SEC_EGRESS_FRAMES - 64 <= lowest <= SEC_POOL - SEC_EGRESS_FRAMES // 2, record
    assert refused["ipsec_offline_port_rejected"] > 0, record


# What a port's class queues may hold of the pool every port receives into,
# altogether: half of what the port seeds it with, 640 for each of four CPUs.
# With SEC's share of its own pool larger than that, the tighter of the two.
TREE_SHARE = 4 * 640 // 2
# The LAN tree's one class, the default: a RED qdisc on it asks for more than
# the tree may hold, with the curve's band at the top of the limit, so the
# queue takes nearly all of what it is given before RED drops anything.
DEEP_RED = {"limit": 4_000_000, "min": 3_600_000, "max": 3_900_000}
# The WAN tree beside it, an ISP's upload: one channel, two leaves, and the
# top channel's class queue 0, three queues asking 128 frames each.
WAN_LEAVES = (("2:100", "0"), ("2:101", "1"))
# Frames past a class queue's depth that SEC can have in flight towards it.
IN_FLIGHT = 64


async def test_paused_lan_tree_leaves_sec_its_buffers(ipv6_rig):
    """A hardware qdisc on the LAN port, a WAN tree beside it, and the port
    paused: the decrypted frames wait on the LAN tree's class queues in SEC's
    output buffers, as many as the queues may hold. The trees share SEC's
    share of the pool by what each asks (A421): the WAN tree's three queues
    take their 128 each, and the LAN tree's one deep class all of the port's
    Ethernet share but the frame its unclassified queue keeps -- where the even
    split gave it 512 less those. Filled through the tunnel while the port
    sends nothing, it holds most of that in SEC's buffers, and SEC still
    refuses no job for want of one."""
    r = ipv6_rig
    cleanup = []
    console = Console.target()
    lan, wan = r.dut_lan_if, TARGET_WAN_IF
    echo = PayloadEcho()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, STALL_DPORT), family=socket.AF_INET6)

    async def tc(*argv, check=True):
        return await console_command(console, "tc", *argv, check=check, timeout=30)

    try:
        await tunnel(r, cleanup, f"udp sport {STALL_SPORT} udp dport {STALL_DPORT}")
        # Built before the flow is offered, so its entries resolve to the
        # trees' class queues from the start.
        await tc("qdisc", "add", "dev", lan, "root", "handle", "1:", "htb", "offload",
                 "default", "10")
        await tc("class", "add", "dev", lan, "parent", "1:", "classid", "1:10",
                 "htb", "rate", "1gbit", "ceil", "1gbit", "prio", "0")
        burst = (2 * DEEP_RED["min"] + DEEP_RED["max"]) // (3 * 1500) + 1
        await tc("qdisc", "add", "dev", lan, "parent", "1:10", "handle", "10:", "red",
                 *(str(v) for item in DEEP_RED.items() for v in item), "avpkt", "1500",
                 "burst", str(burst), "probability", "0.02", "bandwidth", "1gbit")
        await tc("qdisc", "add", "dev", wan, "root", "handle", "2:", "htb", "offload")
        await tc("class", "add", "dev", wan, "parent", "2:", "classid", "2:10",
                 "htb", "rate", "5gbit", "ceil", "5gbit")
        for classid, prio in WAN_LEAVES:
            await tc("class", "add", "dev", wan, "parent", "2:10", "classid", classid,
                     "htb", "rate", "2gbit", "ceil", "5gbit", "prio", prio)

        async def send(count=8):
            return await _udp_exchange(r, STALL_SPORT, WAN_IPV6, STALL_DPORT, count,
                                       (WAN_IPV6, STALL_DPORT), "flowtable_ipsec_stalled_port")

        await _drive(r, send, lambda s: s["entries"] == 2,
                     "both directions of the flow should be in hardware")
        transport.close()
        start = await r.state()
        leaf_before = await egress(r, lan)
        (lowest, sent), pauses = await while_lan_port_paused(r, lambda: asyncio.gather(
            console_python(console, POOL_LOWEST.format(seconds=4), timeout=30),
            asyncio.to_thread(_blast, 3)), 4)
        leaf_after = await egress(r, lan)
        await asyncio.sleep(1.5)
        end = await r.state()
    finally:
        transport.close()
        for dev in (lan, wan):
            await tc("qdisc", "del", "dev", dev, "root", check=False)
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)
    depth = {(row["dev"], row["classid"]): int(row["depth"]) for row in start["qos_classes"]
             if row["kind"] == "leaf"}
    refused = {key: end[key] - start[key] for key in end
               if key.startswith(("ipsec_sec_refused", "ipsec_offline_port_rejected"))}
    record = {"sent": sent, "pauses": pauses, "refused": refused, "flows": end["flows"],
              "depth": {f"{dev} {classid}": d for (dev, classid), d in depth.items()},
              "leaf": leaf_delta(leaf_before, leaf_after, 0),
              "pool_lowest": int(re.search(r"lowest (\d+)", lowest["stdout"]).group(1))}
    r.record("ipsec-paused-tree", record)
    # The cap gave the deep class the port's share but its unclassified
    # queue's frame, and the WAN tree's leaves their asking.
    assert depth[(lan, "1:10")] == TREE_SHARE - 1, record
    assert all(depth[(wan, classid)] == 128 for classid, _ in WAN_LEAVES), record
    assert sent > 10_000, record
    assert refused["ipsec_sec_refused_buffer_depletion"] == 0, record
    # The class's queue filled and refused the rest: the frames reached it
    # in hardware, decrypted, while the port sent nothing.
    assert record["leaf"]["rejected"] > 0, record
    # It held more of SEC's buffers than a lone tree's whole share once was,
    # and no more than its depth and what SEC had in flight.
    held = SEC_POOL - record["pool_lowest"]
    assert 1024 < held <= TREE_SHARE + IN_FLIGHT, record

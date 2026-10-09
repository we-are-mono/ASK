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
import os
import re
import socket
import subprocess
import time

from _flowtable_ipv6 import PayloadEcho, _drive, _drop_tables, _udp_exchange
from _flowtable_ipv6_sa import STALL_DPORT, STALL_SPORT, tunnel
from _flowtable_rig import command, console_python
from _flowtable_service_ipsec import SEC_EGRESS_FRAMES, SEC_POOL
from _topology import LAN_IPV6, LAN_NIC, WAN_IPV6, lan_run
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
    """The LAN VM's NIC pauses the DUT's LAN port, flow control on and its
    ring no longer drained: the VM is suspended. The WAN host meanwhile sends
    small datagrams through the tunnel to it, on a flow in hardware, and SEC
    refuses none of them for want of a buffer."""
    r = ipv6_rig
    cleanup = []
    vm = os.environ.get("ASK_LAN_VM", "loki")
    echo = PayloadEcho()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, STALL_DPORT), family=socket.AF_INET6)
    suspended = False
    try:
        await tunnel(r, cleanup, f"udp sport {STALL_SPORT} udp dport {STALL_DPORT}")

        async def send(count=8):
            return await _udp_exchange(r, STALL_SPORT, WAN_IPV6, STALL_DPORT, count,
                                       (WAN_IPV6, STALL_DPORT), "flowtable_ipsec_stalled_port")

        await _drive(r, send, lambda s: s["entries"] == 2,
                     "both directions of the flow should be in hardware")
        transport.close()
        # A 10G link negotiates no pause: set it outright.
        result = await lan_run(r.lan, f"ethtool -A {LAN_NIC} autoneg off rx on tx on")
        assert result.rc == 0, result.stdout
        start = await r.state()
        subprocess.run(["virsh", "suspend", vm], check=True, capture_output=True)
        suspended = True
        lowest, sent = await asyncio.gather(
            console_python(Console.target(), POOL_LOWEST.format(seconds=4), timeout=30),
            asyncio.to_thread(_blast, 3))
        await asyncio.sleep(1.5)
        end = await r.state()
    finally:
        transport.close()
        if suspended:
            subprocess.run(["virsh", "resume", vm], check=False, capture_output=True)
            await asyncio.sleep(2)
        await lan_run(r.lan, f"ethtool -A {LAN_NIC} autoneg on rx off tx off")
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)
    refused = {key: end[key] - start[key] for key in end
               if key.startswith(("ipsec_sec_refused", "ipsec_offline_port_rejected"))}
    record = {"sent": sent, "refused": refused, "flows": end["flows"],
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

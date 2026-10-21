"""Every flow's last hardware delta reaches conntrack when many leave at once."""
from __future__ import annotations

import asyncio
import json
import re
import struct

from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from _flowtable_rig import (DPORT, TABLE, WAN_IP, command)

FLOWS = 200
RATE = 20         # datagrams per second, per flow
SECONDS = 20
PAYLOAD = 256
PORT = DPORT + 11


class FlowEcho(asyncio.DatagramProtocol):
    """The WAN end of every flow, counting what it answers by the flow the
    payload names rather than by source port, which NAT may remap."""

    def __init__(self):
        self.echoed = [0] * FLOWS

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        flow, _ = struct.unpack_from("!HI", data)
        if flow < len(self.echoed):
            self.echoed[flow] += 1
        self.transport.sendto(data, addr)


def stream(lan_ip, base, flows, rate):
    """`flows` UDP flows from consecutive source ports at `rate` each for
    SECONDS, then what each sent and got back."""
    return f'''
import json, selectors, socket, struct, time
FLOWS, RATE, SECONDS = {flows}, {rate}, {SECONDS}
sel = selectors.DefaultSelector()
socks = []
for i in range(FLOWS):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    s.bind(({lan_ip!r}, {base} + i))
    s.connect(({WAN_IP!r}, {PORT}))
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, i)
    socks.append(s)
sent, received = [0] * FLOWS, [0] * FLOWS
pad = b"x" * ({PAYLOAD} - 6)
def drain(timeout):
    for key, _ in sel.select(timeout=timeout):
        try:
            while True:
                key.fileobj.recv(2048)
                received[key.data] += 1
        except BlockingIOError:
            pass
def send(i):
    try:
        socks[i].send(struct.pack("!HI", i, sent[i]) + pad)
        sent[i] += 1
    except BlockingIOError:
        pass
# Each flow's first datagram answered before its second is sent, a hundred at
# a time: the second is what offloads the flow, and a conntrack whose replies
# only ever cross in hardware is never marked replied and dies at teardown
# with its counts (A408).
cold = set(range(FLOWS))
for attempt in range(3):
    batch = sorted(cold)
    for n in range(0, len(batch), 100):
        for i in batch[n:n + 100]:
            send(i)
        drain(0.02)
    end = time.monotonic() + 1
    while time.monotonic() < end and any(received[i] == 0 for i in cold):
        drain(0.05)
    cold = {{i for i in cold if received[i] == 0}}
    if not cold:
        break
start, tick = time.monotonic(), 0
while time.monotonic() - start < SECONDS:
    for i in range(FLOWS):
        send(i)
    tick += 1
    while True:
        wait = start + tick / RATE - time.monotonic()
        drain(max(wait, 0))
        if wait <= 0:
            break
end = time.monotonic() + 2
while time.monotonic() < end:
    drain(0.2)
print(json.dumps({{"sent": sent, "received": received, "cold": sorted(cold)}}))
'''


async def conntrack(r, base, flows):
    """Each flow's (original, reply) packets, by its index."""
    listing = await command(r.target, r.session, "conntrack", "-L", "-p", "udp",
                            "--orig-src", r.lan_ip, "--orig-dst", WAN_IP, "--dport", str(PORT))
    counts = {}
    for sport, orig, reply in re.findall(
            rf"sport=(\d+) dport={PORT} packets=(\d+) bytes=\d+ .*?packets=(\d+) bytes=",
            listing["stdout"]):
        if base <= int(sport) < base + flows:
            counts[int(sport) - base] = (int(orig), int(reply))
    return counts


async def unreplied(r, base, flows):
    """The flows whose conntrack has seen no reply, by index."""
    listing = await command(r.target, r.session, "conntrack", "-L", "-p", "udp",
                            "--orig-src", r.lan_ip, "--orig-dst", WAN_IP, "--dport", str(PORT))
    return sorted(int(sport) - base for sport in re.findall(
        rf"sport=(\d+) dport={PORT} packets=\d+ bytes=\d+ \[UNREPLIED\]", listing["stdout"])
        if base <= int(sport) < base + flows)


async def settled(r, base, flows, quiet=4.5):
    """The counts once no stats pass adds to them any more."""
    last, still = await conntrack(r, base, flows), 0.0
    while still < quiet:
        await asyncio.sleep(0.5)
        now = await conntrack(r, base, flows)
        still = still + 0.5 if now == last else 0.0
        last = now
    return last


async def forget(r):
    await command(r.target, r.session, "conntrack", "-D", "-p", "udp", "--orig-src", r.lan_ip,
                  "--orig-dst", WAN_IP, "--dport", str(PORT), check=False)


def table(r, base, flows):
    return f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; counter; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} udp sport {base}-{base + flows - 1} udp dport {PORT} flow add @fast
 }}
}}'''


async def burst(r, echo, base, label, retire, flows=FLOWS, rate=RATE):
    """Stream every flow through the hardware, call `retire` mid-stream, and
    check each flow's conntrack against what crossed it. A reply was counted
    no fewer times than the LAN end got one and no more than the WAN end sent
    one; an original no fewer times than the WAN end answered one and no more
    than the LAN end sent one. A last delta lost at teardown leaves a count
    short; one reported twice leaves it over."""
    await forget(r)
    echo.echoed = [0] * flows
    await r.nft(table(r, base, flows))
    before = await r.wait(lambda s: s["bindings"] == 2)
    peer = asyncio.create_task(lan_run_python(r.lan, stream(r.lan_ip, base, flows, rate),
                                              label=label, timeout=SECONDS + 30))
    try:
        admitted = await r.wait(lambda s: s["entries"] == 2 * flows, timeout=SECONDS / 2)
        await asyncio.sleep(2)  # hardware counting, a stats pass or so behind
        # No conntrack the teardown would expire with its counts (A408).
        cold = await unreplied(r, base, flows)
        assert not cold, ("offloaded before any reply reached conntrack", cold)
        await retire()
    finally:
        result = await peer
    assert result.rc == 0, result.stdout
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert not report["cold"], ("first datagram never answered", report["cold"])
    counts = await settled(r, base, flows)
    after = await r.state()
    wrong = {i: {"ct": counts.get(i), "sent": report["sent"][i], "echoed": echo.echoed[i],
                 "received": report["received"][i]}
             for i in range(flows)
             if i not in counts or
             not echo.echoed[i] <= counts[i][0] <= report["sent"][i] or
             not report["received"][i] <= counts[i][1] <= echo.echoed[i]}
    r.record(label, {"before": before, "admitted": admitted, "after": after, "report": report,
                     "echoed": echo.echoed, "conntrack": counts, "wrong": wrong})
    assert after["errors"] == before["errors"], (before, after)
    assert not wrong, (len(wrong), dict(list(wrong.items())[:8]))
    return counts


async def test_burst_teardown_accounting(rig):
    """Two hundred flows leave the hardware together, twice: their table is
    deleted, and a route change retires every one of them, twice, while the
    stream readmits them. Each flow's conntrack accounts every datagram that
    crossed it, both ways, wherever each crossed -- the hardware counts of
    every direction reach it, however many directions leave at once."""
    r = rig
    loop = asyncio.get_running_loop()
    transport, echo = await loop.create_datagram_endpoint(FlowEcho, local_addr=(WAN_IP, PORT))
    nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", "udp", "--dport", str(PORT), "-j", "ACCEPT"]
    route = ["ip", "route", "replace", f"{WAN_IP}/32", "dev", TARGET_WAN_IF]
    await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
    try:
        async def delete():
            await r.delete_table(timeout=30)

        await burst(r, echo, 43100, "burst-delete", delete)

        async def reroute():
            for extra in (["mtu", "1500"], []):
                await command(r.target, r.session, *route, *extra)
                await asyncio.sleep(4)  # readmitted, and counting in hardware again

        try:
            await burst(r, echo, 43400, "burst-route", reroute)
        finally:
            await command(r.target, r.session, *route)
            await r.delete_table(timeout=30)
    finally:
        transport.close()
        await command(r.target, r.session, "iptables", "-t", "nat", "-D", *nat, check=False)
        await forget(r)


async def test_port_stop_accounting(rig):
    """The LAN port stops with a thousand flows in the hardware, and comes
    back. Its stop marks the port's transmit side down for the classifier,
    which then hands Linux what an entry still sending to the port matches
    instead of sending it, after counting it: a reply would be counted by the
    entry and again by conntrack on its way to the stopped port. Each flow's
    conntrack accounts every datagram that crossed it, both ways, once. A
    thousand at four a second each: two thousand directions take a debug
    kernel some 300 ms to retire, a window two hundred would close in one of
    their ticks."""
    r = rig
    loop = asyncio.get_running_loop()
    transport, echo = await loop.create_datagram_endpoint(FlowEcho, local_addr=(WAN_IP, PORT))
    nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", "udp", "--dport", str(PORT), "-j", "ACCEPT"]
    await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
    try:
        async def stop():
            await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_LAN_IF, "down")
            try:
                await asyncio.sleep(1)
            finally:
                # Going down takes the fixture's host route and neighbour.
                await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_LAN_IF, "up")
                await command(r.target, r.session, "ip", "route", "replace", f"{r.lan_ip}/32",
                              "dev", TARGET_LAN_IF)
                await command(r.target, r.session, "ip", "neigh", "replace", r.lan_ip, "lladdr",
                              r.lan_mac, "nud", "permanent", "dev", TARGET_LAN_IF)

        try:
            # Below the LAN end's ephemeral ports, which a thousand might meet.
            await burst(r, echo, 21000, "burst-port-stop", stop, flows=1000, rate=4)
        finally:
            await r.delete_table(timeout=30)
    finally:
        transport.close()
        await command(r.target, r.session, "iptables", "-t", "nat", "-D", *nat, check=False)
        await forget(r)

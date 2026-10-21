"""Every flow's last hardware delta reaches conntrack when many leave at once."""
from __future__ import annotations

import asyncio
import json
import re
import struct
from collections import defaultdict

from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from _flowtable_rig import (DPORT, TABLE, WAN_IP, command)

FLOWS = 200
RATE = 20         # datagrams per second, per flow
SECONDS = 20
PAYLOAD = 256
PORT = DPORT + 11


class FlowEcho(asyncio.DatagramProtocol):
    """The WAN end of every flow, counting what it answers by the flow the
    payload names rather than by source port, which NAT may remap, and noting
    the ports each flow arrived from. A flow in `silent` is not answered until
    its datagram of that sequence number."""

    def __init__(self):
        self.echoed = [0] * FLOWS
        self.silent = {}
        self.ports = defaultdict(set)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        flow, seq = struct.unpack_from("!HI", data)
        if flow < len(self.echoed):
            self.ports[flow].add(addr[1])
            if seq < self.silent.get(flow, 0):
                return
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
print(json.dumps({{"sent": sent, "received": received}}))
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


async def connections(r, base, flows):
    """Each flow's conntrack by index: its id, whether it has seen a reply,
    its flags, and the port its replies are addressed to."""
    listing = await command(r.target, r.session, "conntrack", "-L", "-p", "udp", "-o", "id",
                            "--orig-src", r.lan_ip, "--orig-dst", WAN_IP, "--dport", str(PORT))
    found = {}
    for line in listing["stdout"].splitlines():
        match = re.search(rf"sport=(\d+) dport={PORT} packets=\d+ bytes=\d+ (\[UNREPLIED\] )?"
                          rf"src=\S+ dst=\S+ sport={PORT} dport=(\d+) .*?id=(\d+)", line)
        if match and base <= int(match[1]) < base + flows:
            found[int(match[1]) - base] = {
                "id": int(match[4]), "replied": not match[2], "port": int(match[3]),
                "flags": re.findall(r"\[(\w+)\]", line)}
    return found


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


async def burst(r, echo, base, label, retire, flows=FLOWS, rate=RATE, offered=None):
    """Stream every flow through the hardware, call `retire` mid-stream, and
    check each flow's conntrack against what crossed it. A reply was counted
    no fewer times than the LAN end got one and no more than the WAN end sent
    one; an original no fewer times than the WAN end answered one and no more
    than the LAN end sent one. A last delta lost at teardown leaves a count
    short; one reported twice leaves it over. `offered`, if given, runs as
    the stream starts."""
    await forget(r)
    echo.echoed = [0] * flows
    echo.ports.clear()
    await r.nft(table(r, base, flows))
    before = await r.wait(lambda s: s["bindings"] == 2)
    peer = asyncio.create_task(lan_run_python(r.lan, stream(r.lan_ip, base, flows, rate),
                                              label=label, timeout=SECONDS + 30))
    try:
        if offered:
            await offered()
        admitted = await r.wait(lambda s: s["entries"] == 2 * flows, timeout=SECONDS / 2)
        await asyncio.sleep(2)  # hardware counting, a stats pass or so behind
        await retire()
    finally:
        result = await peer
    assert result.rc == 0, result.stdout
    report = json.loads(result.stdout.strip().splitlines()[-1])
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


async def port_stop(r):
    """The LAN port down for a second, and up again."""
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
        try:
            # Below the LAN end's ephemeral ports, which a thousand might meet.
            await burst(r, echo, 21000, "burst-port-stop", lambda: port_stop(r), flows=1000, rate=4)
        finally:
            await r.delete_table(timeout=30)
    finally:
        transport.close()
        await command(r.target, r.session, "iptables", "-t", "nat", "-D", *nat, check=False)
        await forget(r)


async def test_unanswered_flows_keep_their_conntrack(rig):
    """Half the flows go unanswered for their first three seconds, so the
    flowtable, which takes a UDP flow at its second datagram, has each of
    them before any reply has reached its conntrack, and carries every reply
    that follows itself. Conntrack still learns of those replies and marks
    each connection replied, as it would have from the stack; so a teardown
    that hands the conntracks straight back -- the table deleted, the LAN
    port stopped -- hands each back alive, translated as it was and with
    every datagram counted, and each flow goes on in the connection it
    started in. Two more are never answered: a teardown hands theirs back
    unreplied, and alive for as long as conntrack keeps an unanswered one --
    the flowtable's own timeout comes off only a flow that expired idle."""
    r = rig
    flows, mute = 22, (20, 21)
    loop = asyncio.get_running_loop()
    transport, echo = await loop.create_datagram_endpoint(FlowEcho, local_addr=(WAN_IP, PORT))
    nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", "udp", "--dport", str(PORT),
           "-j", "MASQUERADE"]
    await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
    try:
        async def delete():
            await r.delete_table(timeout=30)

        for base, label, teardown in ((22100, "unanswered-delete", delete),
                                      (22200, "unanswered-port-stop", lambda: port_stop(r))):
            echo.silent = {i: 3 * RATE for i in range(0, 20, 2)}
            echo.silent.update({i: SECONDS * RATE * 2 for i in mute})
            seen = {}

            async def offered():
                # Every silent flow in the flowtable while still unanswered.
                deadline = loop.time() + SECONDS / 2
                while loop.time() < deadline:
                    seen["offered"] = await connections(r, base, flows)
                    if all({"OFFLOAD", "HW_OFFLOAD"} & set(seen["offered"].get(i, {}).get("flags", ()))
                           for i in echo.silent):
                        break
                    await asyncio.sleep(0.05)
                assert not [i for i in echo.silent if seen["offered"].get(i, {}).get("replied", True)], \
                    ("a silent flow was not offered unanswered", seen["offered"])

            async def retire():
                # Every flow answered for a second, through the flowtable
                # alone, and every conntrack marked replied once a stats pass
                # or two has brought the hardware's counts in.
                deadline = loop.time() + SECONDS / 2
                while loop.time() < deadline:
                    seen["answered"] = await connections(r, base, flows)
                    if min(echo.echoed[i] for i in echo.silent if i not in mute) >= RATE and \
                            all(c["replied"] for i, c in seen["answered"].items() if i not in mute):
                        break
                    await asyncio.sleep(0.2)
                await teardown()

            try:
                await burst(r, echo, base, label, retire, flows=flows, offered=offered)
                seen["after"] = await connections(r, base, flows)
            finally:
                r.record(f"{label}-connections",
                         {**seen, "ports": {i: sorted(p) for i, p in echo.ports.items()}})
                await r.delete_table(timeout=30)
            unreplied = [i for i in range(flows) if i not in mute and
                         not seen["answered"].get(i, {}).get("replied")]
            assert not unreplied, ("answered, yet never marked replied", label, unreplied)
            replied = [i for i in mute if seen["after"].get(i, {}).get("replied", True)]
            assert not replied, ("never answered, yet marked replied", label, replied)
            moved = {(i, k): (seen["answered"].get(i, {}).get(k), seen["after"].get(i, {}).get(k))
                     for i in range(flows) for k in ("id", "port")
                     if seen["answered"].get(i, {}).get(k) != seen["after"].get(i, {}).get(k)}
            assert not moved, ("a teardown replaced a flow's conntrack", label, moved)
            assert all(len(echo.ports[i]) == 1 for i in range(flows)), (label, dict(echo.ports))
    finally:
        transport.close()
        await command(r.target, r.session, "iptables", "-t", "nat", "-D", *nat, check=False)
        await forget(r)

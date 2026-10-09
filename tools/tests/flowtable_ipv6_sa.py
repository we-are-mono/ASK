"""IPv6 inside an IPsec tunnel with an IPv4 outer header, in hardware.

The adapter accepts IPv4 tunnel endpoints only, so an IPv6 flow reaches an SA
as IPv6-in-IPv4: a dual-stack LAN's IPv6 carried over an IPv4 site-to-site
tunnel. What such a direction does with a packet too big for the SA's bundle
is the question here. Software checks a packet against the bundle's MTU, the
outer device's less the ESP expansion, and answers an oversized one with
Packet Too Big (xfrm6_tunnel_check_size). The entry is programmed with the
port's MTU and the expansion on top, so the hardware takes the packet, and
what it does next is what these cases pin: it encrypts the inner packet whole
and fragments the outer IPv4 packet, whose DF it leaves clear because the
inner family has none to copy. The inner packet is never fragmented, which is
what bounding an IPv6 direction exists to prevent (a router must not fragment
IPv6), and it arrives exactly once. Outer fragmentation is what Linux itself
does for an IPv4 inner packet without DF.

The same tunnel is also what carries IPv6 across a WAN that has no IPv6 at
all, and that case gets its own test. There the remote IPv6 prefix is routed
to the WAN port with no gateway and nothing else: no IPv6 default route and no
IPv6 neighbour on the link. A packet-offloaded bundle has to take its child
route from the flow, since the SA's IPv4 endpoints mean nothing to IPv6
routing, and the software path has to hand the plaintext to SEC without
resolving a neighbour of the inner destination, which nothing on the link
would answer.
"""
from __future__ import annotations

from _flowtable_ipv6_sa import BULK_PORT, DPORT, SPORT, V4_WAN_DPORT, V4_WAN_SPORT

from _flowtable_ipv6_sa import FITS, REMOTE_PREFIX, REMOTE_V6, fragments_sent, sa_pair, tunnel, xfrm_counters

import asyncio
import json
import os
from pathlib import Path
import re
import socket


from _topology import LAN_IPV6, LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, WAN_IPV6, lan_run_python
from _flowtable_ipv6 import (PayloadEcho, _drive, _drop_tables, _hardware_delta, _offload_table, _udp_exchange)
from _flowtable_ipv6_sa import STALL_DPORT, STALL_SPORT
from _flowtable_rig import command, console_python
from ask_orch.uart import Console
from _flowtable_service_ipsec import (offline_port_discards, offline_port_rejections)
from _flowtable_service_ipsec_replay import (xfrm_mib)

# What SEC's input queues may hold of the pool every port receives into
# (IPSEC_TO_SEC_FRAMES): half of what one port seeds it with, 640 for each of
# the DUT's four CPUs.
SEC_INPUT_FRAMES = 4 * 640 // 2


async def test_oversized(ipv6_rig):
    r = ipv6_rig
    echo = PayloadEcho()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, DPORT), family=socket.AF_INET6)
    cleanup = []

    async def send(count=8):
        return await _udp_exchange(r, SPORT, WAN_IPV6, DPORT, count, (WAN_IPV6, DPORT),
                                   "flowtable_v6_sa")

    try:
        # A dual-stack WAN carries an IPv6 default route. The bundle does not
        # need it: the flow's own route leaves by the offload port and is the
        # child. It is here because a dual-stack WAN is this case's setting.
        await command(r.target, r.session, "ip", "-6", "route", "add", "default", "via", WAN_IPV6,
                      "dev", TARGET_WAN_IF)
        cleanup.append((r.target, ["ip", "-6", "route", "del", "default", "via", WAN_IPV6,
                                   "dev", TARGET_WAN_IF]))
        await sa_pair(r, cleanup)
        await _offload_table(r, f"ip6 saddr {LAN_IPV6} udp sport {SPORT} udp dport {DPORT}")
        admitted = await _drive(r, send, lambda s: s["entries"] == 2,
                                "both directions of the protected IPv6 flow should be in hardware")
        forward = next(f for f in admitted["flows"] if f["sa"] != "0")
        assert forward["in_sa"] == "0" and forward["family"] == "6", admitted
        assert sum(f["in_sa"] != "0" for f in admitted["flows"]) == 1, admitted
        r.record("ipv6-sa-admitted", admitted)
        results = {}
        for size in (FITS, FITS + 1, 1452):
            payload = bytes([size % 251]) * size
            before, frags = await r.state(), await fragments_sent(r)
            peer_before = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
            counts = {f["cookie"]: int(f["packets"]) for f in before["flows"]}
            script = f'''
import json
from scapy.all import Ether, IPv6, UDP, Raw, ICMPv6PacketTooBig, sendp, sniff
packet = IPv6(src={LAN_IPV6!r}, dst={WAN_IPV6!r})/UDP(sport={SPORT}, dport={DPORT})/Raw({payload!r})
answers = sniff(iface={LAN_NIC!r}, timeout=2, lfilter=lambda p: ICMPv6PacketTooBig in p,
                started_callback=lambda: sendp(Ether(dst={r.dut_lan_mac!r})/packet,
                                               iface={LAN_NIC!r}, verbose=False))
print(json.dumps({{"too_big": [a[ICMPv6PacketTooBig].mtu for a in answers]}}))
'''
            result = await lan_run_python(r.lan, script, timeout=20, label="flowtable_v6_sa_oversized")
            assert result.rc == 0, result.stdout
            await asyncio.sleep(0.5)
            after = await r.state()
            moved = {f["cookie"]: int(f["packets"]) - counts[f["cookie"]] for f in after["flows"]}
            sent = await fragments_sent(r)
            results[size] = {"lan": json.loads(result.stdout.strip().splitlines()[-1]),
                             "delivered": echo.received[payload], "hardware": moved,
                             "fragments": {k: sent[k] - frags[k] for k in sent}}
            peer_after = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
            results[size]["peer_xfrm_delta"] = {
                key: value - peer_before[key] for key, value in peer_after.items()
                if value != peer_before[key]
            }
            # Keep the failing size and peer refusal counters even when the
            # assertion below prevents the final aggregate from being written.
            r.record(f"ipv6-sa-oversized-{size}", results[size])
            observed = results[size]
            assert observed["delivered"] == 1 and observed["lan"]["too_big"] == [], (size, observed)
            assert moved[forward["cookie"]] == 1, (size, observed)
            assert set(moved) == set(counts), (size, before, after)
            # Two outer fragments exactly when the inner packet exceeds the
            # bundle; never an inner one.
            assert observed["fragments"] == {4: 0 if size == FITS else 2, 6: 0}, (size, observed)
        final = await r.state()
        assert final["errors"] == r.errors and final["entries"] == 2, final
        r.record("ipv6-sa-oversized", {"results": results, "final": final})
    finally:
        transport.close()
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


async def test_ipv4_only_wan(ipv6_rig):
    """IPv6-in-IPv4 across a WAN with no IPv6: the remote prefix is routed to
    the WAN port without a gateway, the DUT has no IPv6 default route, and the
    far end's address is on no link, so no IPv6 neighbour exists for it.

    Every bundle must still build (XfrmOutBundleGenError does not move), the
    first packets must cross in software for the flow to be established at
    all, and once admitted the classifier carries both directions exactly."""
    r = ipv6_rig
    echo = PayloadEcho()
    transport = None
    cleanup = []

    async def send(count=8):
        return await _udp_exchange(r, V4_WAN_SPORT, REMOTE_V6, V4_WAN_DPORT, count,
                                   (REMOTE_V6, V4_WAN_DPORT), "flowtable_v6_sa_ipv4_wan")

    try:
        defaults = (await command(r.target, r.session, "ip", "-6", "route", "show",
                                  "default"))["stdout"].strip()
        assert not defaults, ("this case needs a DUT without an IPv6 default route", defaults)
        await command(r.wan, r.session, "ip", "-6", "addr", "add", REMOTE_V6 + "/128", "dev", "lo",
                      "nodad")
        cleanup.append((r.wan, ["ip", "-6", "addr", "del", REMOTE_V6 + "/128", "dev", "lo"]))
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=(REMOTE_V6, V4_WAN_DPORT), family=socket.AF_INET6)
        await command(r.target, r.session, "ip", "-6", "route", "add", REMOTE_PREFIX, "dev",
                      TARGET_WAN_IF)
        cleanup.append((r.target, ["ip", "-6", "route", "del", REMOTE_PREFIX, "dev",
                                   TARGET_WAN_IF]))
        await sa_pair(r, cleanup, remote=REMOTE_V6)
        await _offload_table(r, f"ip6 saddr {LAN_IPV6} udp sport {V4_WAN_SPORT} "
                                f"udp dport {V4_WAN_DPORT}")
        mib = await xfrm_counters(r)
        # Admission needs an established connection, so it also proves the
        # first packets crossed the software path in both directions.
        admitted = await _drive(r, send, lambda s: s["entries"] == 2,
                                "the protected IPv6 flow should be in hardware on an IPv4-only WAN")
        rows = {f["in"]: f for f in admitted["flows"]}
        assert set(rows) == {TARGET_LAN_IF, TARGET_WAN_IF}, admitted
        assert rows[TARGET_LAN_IF]["sa"] != "0" and rows[TARGET_WAN_IF]["in_sa"] != "0", admitted
        assert all(f["family"] == "6" for f in rows.values()), admitted
        # The encrypted direction's next hop is the one IPv4 routing gives
        # the tunnel's endpoint, resolved in that family: the IPv6 route
        # under the bundle has no neighbour for it.
        peer = os.environ["ASK_WAN_IPERF_IP"]
        route = json.loads((await command(r.target, r.session, "ip", "-j", "route", "get",
                                          peer))["stdout"])[0]
        assert rows[TARGET_LAN_IF]["nexthop"] == route.get("gateway", peer), (route, admitted)
        report = await send(64)
        assert report == {"echoed": 64, "lost": 0}, report
        after = await r.state()
        moved = {f["in"]: f for f in after["flows"]}
        delta = _hardware_delta(rows, moved)
        assert delta == {TARGET_LAN_IF: 64, TARGET_WAN_IF: 64}, (delta, admitted, after)
        assert (admitted["installs"], admitted["deletes"]) == (after["installs"], after["deletes"]), \
            (admitted, after)
        assert after["errors"] == r.errors, after
        for direction in rows:
            assert moved[direction]["cookie"] == rows[direction]["cookie"], (rows, moved)
        now = await xfrm_counters(r)
        refused = {name: now[name] - mib[name]
                   for name in ("XfrmOutBundleGenError", "XfrmOutBundleCheckError",
                                "XfrmOutNoStates", "XfrmOutError")}
        assert not any(refused.values()), refused
        r.record("ipv6-sa-ipv4-only-wan", {"admitted": admitted, "after": after,
                                           "hardware_delta": delta, "xfrm": refused})
    finally:
        if transport:
            transport.close()
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


async def _iperf(r, port, options, label, seconds=10):
    """One iperf3 test from the LAN VM to the WAN host's IPv6 address, through
    the tunnel; the end summary iperf3 reports."""
    server = await asyncio.create_subprocess_exec(
        "iperf3", "-s", "-1", "-B", WAN_IPV6, "-p", str(port), "-J",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        await asyncio.sleep(0.2)
        argv = ["iperf3", "-6", "-c", WAN_IPV6, "-B", LAN_IPV6, "-p", str(port),
                "-t", str(seconds), "-Z", "-J", *options]
        script = f"""
import subprocess
result = subprocess.run({argv!r}, capture_output=True, text=True, timeout={seconds + 20})
print(result.stdout, flush=True)
assert result.returncode == 0, result.stderr
"""
        result = await lan_run_python(r.lan, script, timeout=seconds + 30, label=label)
        assert result.rc == 0, result.stdout
        await asyncio.wait_for(server.communicate(), 10)
        return json.loads(result.stdout.strip())["end"]
    finally:
        if server.returncode is None:
            server.kill()
            await server.wait()


async def test_decrypted_frames_intact_under_load(ipv6_rig):
    """Bulk IPv6 TCP each way through the IPv4 tunnel: SEC writes every
    decrypted IPv6 frame whole, its ACKs while the LAN sends and its full
    segments while the WAN host does. SEC's own refusals are the only discards
    the IPsec offline port may make (offline_port_discards()).

    Refusals do occur. The WAN host's software ESP sends its ACKs up to a few
    hundred sequence numbers out of order under this load, and SEC drops each
    one that falls behind the SA's 32-packet replay window, as RFC 4303 asks.
    None is for want of an output buffer: the flows' heads and tails reach
    the CPU, and they may no longer take SEC's pool with them (A333)."""
    r = ipv6_rig
    cleanup = []
    received = {}
    try:
        await tunnel(r, cleanup)
        async with offline_port_discards(r, "ipv6-sa-bulk-discards") as discards:
            for direction, options in (("lan-to-wan", []), ("wan-to-lan", ["-R"])):
                end = await _iperf(r, BULK_PORT, ["-P", "4", *options], "flowtable_v6_sa_bulk")
                received[direction] = end["sum_received"]["bytes"]
    finally:
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)
    r.record("ipv6-sa-bulk", {"received": received, "discards": discards})
    assert all(received.values()), received
    assert discards["depletion"] == 0, discards


async def test_exception_backlog_leaves_sec_its_buffers(ipv6_rig):
    """A flow the offload did not take still has its frames decrypted in
    hardware; they reach the CPU through the SA's exception queue, each in a
    buffer of the pool SEC writes into. A stream faster than the CPU drains
    that queue must not take the whole pool, or SEC refuses every job it is
    given, of every SA and every offloaded flow, for want of an output buffer.

    Here an unoffloaded UDP stream from the WAN host runs at several times
    what the CPU can deliver, beside offloaded TCP the other way. SEC may
    refuse frames for its own reasons (the peer's reordering against the
    replay window), but never for want of a buffer. What the CPU had no time
    for is dropped at the offline port instead, and /proc/cdx_flowtable
    counts it, as the port's own register does (A336)."""
    r = ipv6_rig
    cleanup = []
    try:
        await tunnel(r, cleanup)
        start, rejections = await r.state(), await offline_port_rejections(r)
        # Either can fail when SEC starves, the offloaded TCP by stalling; the
        # refusals say why, so they are read and checked first.
        tcp, udp = await asyncio.gather(
            _iperf(r, BULK_PORT, ["-P", "4"], "flowtable_v6_sa_bulk"),
            _iperf(r, BULK_PORT + 1, ["-u", "-R", "-b", "500M", "-l", "1200"],
                   "flowtable_v6_sa_exception"),
            return_exceptions=True)
        await asyncio.sleep(1.5)
        end = await r.state()
        refused = {key: end[key] - start[key] for key in end if key.startswith("ipsec_sec_refused")}
        rejected = {"counted": end["ipsec_offline_port_rejected"] - start["ipsec_offline_port_rejected"],
                    "port": (await offline_port_rejections(r) - rejections) % 2**32}
        r.record("ipv6-sa-exception-backlog", {"tcp": repr(tcp), "udp": repr(udp),
                                               "refused": refused, "rejected": rejected, "state": end})
        assert refused["ipsec_sec_refused_buffer_depletion"] == 0, (refused, tcp, udp)
        assert rejected["counted"] == rejected["port"] > 0, rejected
        for result in (tcp, udp):
            if isinstance(result, BaseException):
                raise result
        assert tcp["sum_received"]["bytes"] and udp["sum"]["packets"], (tcp, udp)
    finally:
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


PORT_DROPS = f'''
import json
print(json.dumps({{dev: {{n: int(open(f"/sys/class/net/{{dev}}/statistics/{{n}}").read())
                        for n in ("rx_dropped", "rx_missed_errors")}}
                  for dev in ({TARGET_LAN_IF!r}, {TARGET_WAN_IF!r})}}))
'''

# The lowest free count of a BMan pool over a stretch, read from BMan's
# big-endian content registers -- with no pool named, of the pool every DPAA
# port receives into, which idle is the largest there is, many times SEC's own.
POOL_LOWEST = '''
import ctypes, mmap, os, time
fd = os.open('/dev/mem', os.O_RDWR | os.O_SYNC)
regs = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0x1890000)
words = [ctypes.c_uint32.from_buffer(regs, 0x600 + 4 * bpid) for bpid in range(64)]
def free(word):
    return int.from_bytes(word.value.to_bytes(4, 'little'), 'big') & 0x7fffff
counts = [free(word) for word in words]
bpid = {bpid}
if bpid < 0:
    bpid = counts.index(max(counts))
lowest, end = counts[bpid], time.monotonic() + {seconds}
while time.monotonic() < end:
    lowest = min(lowest, free(words[bpid]))
print('pool', bpid, lowest)
del words
regs.close()
'''

# Datagrams as large as the tunnel carries whole, from the LAN VM on one
# tuple, from several processes at once, as fast as each goes: line rate,
# several times what SEC encrypts.
FLOOD = '''
import multiprocessing, socket, time
def blast(seconds):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(({lan!r}, {sport}))
    payload, sent, end = bytes({size}), 0, time.monotonic() + seconds
    while time.monotonic() < end:
        for _ in range(64):
            try:
                s.sendto(payload, ({wan!r}, {dport}))
                sent += 1
            except OSError:
                pass
    return sent
with multiprocessing.Pool(4) as pool:
    print('sent', sum(pool.map(blast, [{seconds}] * 4)))
'''


async def _port_drops():
    result = await console_python(Console.target(), PORT_DROPS, timeout=30)
    return json.loads(result["stdout"].strip().splitlines()[-1])


async def test_sec_slower_than_its_input_leaves_the_pool(ipv6_rig):
    """Frames waiting for SEC hold buffers of the pool every DPAA port receives
    into, as frames waiting on a port do (A341). Offered more than it can
    encrypt -- the LAN VM at line rate on a flow in hardware -- its input
    queues hold no more of that pool than their share, and what SEC has no
    room for is refused at the LAN port's enqueue, a drop, never lost for want
    of a buffer (A344). The flow is in hardware before the flood starts: until
    it is, the datagrams go to the CPU, whose own queues are another matter
    (A347)."""
    r = ipv6_rig
    cleanup = []
    echo = PayloadEcho()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, STALL_DPORT), family=socket.AF_INET6)
    try:
        await tunnel(r, cleanup, f"udp sport {STALL_SPORT} udp dport {STALL_DPORT}")

        async def send(count=8):
            return await _udp_exchange(r, STALL_SPORT, WAN_IPV6, STALL_DPORT, count,
                                       (WAN_IPV6, STALL_DPORT), "flowtable_v6_sa_flood")

        await _drive(r, send, lambda s: s["entries"] == 2,
                     "both directions of the flow should be in hardware")
        transport.close()
        start, before = await r.state(), await _port_drops()
        idle = await console_python(Console.target(), POOL_LOWEST.format(bpid=-1, seconds=0),
                                    timeout=60)
        bpid, idle = (int(v) for v in re.search(r"pool (\d+) (\d+)", idle["stdout"]).groups())
        pool, flood = await asyncio.gather(
            console_python(Console.target(), POOL_LOWEST.format(bpid=bpid, seconds=6), timeout=60),
            lan_run_python(r.lan, FLOOD.format(lan=LAN_IPV6, sport=STALL_SPORT, wan=WAN_IPV6,
                                               dport=STALL_DPORT, size=FITS, seconds=4),
                           timeout=60, label="flowtable_v6_sa_flood"))
        await asyncio.sleep(1)
        end, after = await r.state(), await _port_drops()
    finally:
        transport.close()
        await _drop_tables(r)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)
    assert flood.rc == 0, flood.stdout
    lowest = int(re.search(r"pool \d+ (\d+)", pool["stdout"]).group(1))
    hits = {f["cookie"]: int(f["packets"]) for f in end["flows"]}
    record = {"sent": int(flood.stdout.split()[-1]),
              "hits": sum(hits[f["cookie"]] - int(f["packets"]) for f in start["flows"]
                          if f["in"] == TARGET_LAN_IF and f["cookie"] in hits),
              "drops": {dev: {k: after[dev][k] - before[dev][k] for k in before[dev]}
                        for dev in before},
              "pool": {"bpid": bpid, "idle": idle, "lowest": lowest},
              "depletion": end["ipsec_sec_refused_buffer_depletion"]
                           - start["ipsec_sec_refused_buffer_depletion"]}
    r.record("ipv6-sa-sec-input", record)
    lan, wan = record["drops"][TARGET_LAN_IF], record["drops"][TARGET_WAN_IF]
    # SEC was offered, in hardware, more than it encrypts.
    assert record["hits"] > 1_000_000, record
    # What it had no room for was refused at the enqueue, and nothing either
    # port received was lost for want of a buffer.
    assert lan["rx_dropped"] > record["hits"] // 4, record
    assert lan["rx_missed_errors"] == 0 and wan["rx_missed_errors"] == 0, record
    # SEC's input held its share of the pool while the flood ran -- which also
    # proves the reading overlapped the flood -- and no more than that and
    # what is in flight.
    assert SEC_INPUT_FRAMES // 2 <= idle - lowest <= 2 * SEC_INPUT_FRAMES, record
    assert record["depletion"] == 0, record

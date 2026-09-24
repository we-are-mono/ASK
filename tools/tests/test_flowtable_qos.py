"""Hardware QoS on offloaded flows, proved at rates only the hardware reaches.

Software forwarding on this rig tops out near 130 Mbit/s and the ports run at
10 Gbit/s, so every rate case here shapes or polices around 2 Gbit/s and offers
three times that. Delivery near the cap then says two things at once: the
hardware enforced the rate, and the flow was in hardware, because nothing else
could have carried it that fast. A low-rate result proves neither. Beside the
rate, two independent oracles:

  - **the adapter's row.** It names the class the hardware entry was given, and
    its packet counter moves only for frames the classifier matched.
  - **the leaf counters `ethtool -S` reports.** One set per leaf slot: what that
    class queue dequeued and what its congestion group rejected. An offloaded
    flow never reaches a leaf's software qdisc, so `tc -s class show` cannot see
    it; these can.

Most traffic runs from the orchestrator to the LAN VM, so the trees are built on
the LAN port. The orchestrator is the side that can offer several times the cap,
and the WAN port carries the agent every oracle is read through. The one case
about changing the WAN port's own egress runs the other way.

Enabling CEETM on a port moves its sub-portal's dequeues onto the LNI scheduler,
and removing a tree once left that switched, with the port reporting healthy
while it transmitted nothing. The fixture's last act is therefore to forward
traffic through both ports after every tree is gone: a case that leaves a port
unable to transmit fails there, not in whichever test happens to run next.

Needs `ask_flowtable.qos_mark_mask` nonzero -- the test image ships 0xf0 -- and
iperf3 on the LAN VM and on the orchestrator.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import statistics
import struct
import threading
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_offload import (ARTIFACTS, DPORT, TABLE, WAN_IP, command,
                                    console_command, read, rig)  # noqa: F401

# One port per flow, so a conntrack left behind by one case never feeds another.
# Above the gateway profiles' ranges (49100 and 49200). The devlink file takes
# PORT + 16 onwards; the NAT exemption covers the whole block.
PORT = int(os.environ.get("ASK_FLOWTABLE_QOS_PORT", "49300"))
PORT_SHAPED = PORT
PORT_HIGH, PORT_LOW = PORT + 1, PORT + 2
PORT_BULK, PORT_PROBE = PORT + 3, PORT + 4
PORT_EF, PORT_BE, PORT_EF_SOFTWARE = PORT + 5, PORT + 6, PORT + 7
PORT_POLICED = PORT + 8
PORT_EGRESS = PORT + 9
PORTS_LAST = PORT + 19

# The shaped or policed rate. Below the roughly 9 Gbit/s the rig forwards
# unshaped and far above what the CPU can: see the module docstring.
CAP_MBIT = int(os.environ.get("ASK_FLOWTABLE_QOS_CAP_MBIT", "2000"))
OFFERED_MBIT = 3 * CAP_MBIT
DATAGRAM = 1400
UDP_HEADERS = 14 + 20 + 8
# Bytes a CEETM shaper charges each frame beyond the frame itself -- preamble,
# delimiter, FCS and inter-frame gap -- as the port's LNI is configured
# (CEETM_DEFA_OAL). A shaper held at the cap passes fewer payload bits than the
# cap by exactly this and the headers.
OAL = 24

# cdx_htb_cq_get() numbers the strict-priority class queues from the top, so a
# leaf of `prio N` holds class queue 7 - N, and a conntrack mark names that
# index. prio 0 is the queue that wins.
HIGH_PRIO, HIGH_CQ = 0, 7
LOW_PRIO, LOW_CQ = 1, 6

IPERF_SECONDS = 8
# Admission, and the burst a token bucket starts with, both happen in the first
# second or two of a transfer; rates are sampled after them.
SETTLE = 2.5
WINDOW = 4.0

# The WRED case reads queue occupancy as the extra round trip a probe waits
# behind it, so it shapes lower than the rest: at 500 Mbit/s a full 128-frame
# queue is 3 ms and a band a few tens of kilobytes wide a fraction of one, which
# a probe resolves cleanly. That is still several times what the CPU forwards,
# so the bulk flow's rate remains proof it was in hardware.
WRED_MBIT = int(os.environ.get("ASK_FLOWTABLE_QOS_WRED_MBIT", "500"))
# (min, max) in bytes: a narrow band, and a wider one wholly above it.
WRED_BANDS = {"narrow": (8000, 24000), "wide": (40000, 100000)}
# The tail-drop threshold under RED, far above either band: a curve that did
# not drop until its tail would show as a queue this deep.
WRED_LIMIT = 400000
WRED_PROBABILITY = "0.1"
# A leaf's class queue with no RED qdisc on it tail-drops at this many frames
# (CDX_HTB_CQ_DEPTH).
TAIL_FRAMES = 128
TCP_FRAME, TCP_PAYLOAD = 1514, 1448
# Scheduling noise in a round trip between two Python processes.
PROBE_SLACK = 0.15e-3

# Expedited forwarding, DSCP 46, as it sits in the tos byte.
EF_DSCP = 46
EF_TOS = EF_DSCP << 2
COUNT = 256
# A class that carries a remark: the flag at bit 12, the codepoint in the six
# bits above it. The image's 0xf0 mask stops at the class queue, so the adapter
# is reloaded with the field widened from the same base -- a mark of 0x70 still
# names class queue 7 under it.
REMARK_MASK = 0x7ffff0
REMARK_CLASS = 1 << 12 | EF_DSCP << 13

# A UDP flow does not back off, so the policer's burst only shapes the first
# instant of the transfer; a megabyte keeps that instant short.
POLICE_BURST = "1m"

# Goodput a hardware TCP transfer has to hold with no tree in its way. The rig
# forwards about 9.4 Gbit/s; the CPU a small fraction of that.
UNSHAPED_GBPS = float(os.environ.get("ASK_FLOWTABLE_QOS_UNSHAPED_GBPS", "7"))

LAN_BASE = "/tmp/ask_flowtable_qos"
ECHO = f"{LAN_BASE}_echo.py"
ECHO_SOURCE = '''
import select, socket, sys
host, ports = sys.argv[1], [int(port) for port in sys.argv[2:]]
socks = []
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
    s.bind((host, port))
    socks.append(s)
while True:
    for s in select.select(socks, [], [])[0]:
        data, peer = s.recvfrom(4096)
        s.sendto(data, peer)
'''


# ---- the LAN VM's side, detached ------------------------------------------

async def lan_start(r, *, iperf=(), echo=(), host=None, lifetime=240):
    """Start iperf3 servers and a UDP echo on the LAN VM, detached.

    Detached because the LAN console is a single channel and the traffic that
    follows is driven from this host while the servers run. Each process is its
    own session under `timeout`, so a run that dies without its teardown leaves
    nothing listening for longer than `lifetime`, and `lan_stop` kills each
    whole group. The servers speak JSON so a client asking for
    `--get-server-output` gets the receiver's intervals back.
    """
    host = host or r.lan_ip
    plan = [["iperf3", "-s", "-J", "-B", host, "-p", str(port)] for port in iperf]
    if echo:
        plan.append(["python3", ECHO, host, *map(str, echo)])
    script = f'''
import pathlib, subprocess, time
pathlib.Path({ECHO!r}).write_text({ECHO_SOURCE!r})
plan = {plan!r}
procs = []
with open({LAN_BASE + '.pids'!r}, 'a') as pids:
    for index, argv in enumerate(plan):
        log = open({LAN_BASE!r} + '_%d.err' % index, 'wb')
        proc = subprocess.Popen(['timeout', {str(lifetime)!r}] + argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
        pids.write('%d\\n' % proc.pid)
        procs.append(proc)
time.sleep(0.7)
for index, (argv, proc) in enumerate(zip(plan, procs)):
    assert proc.poll() is None, (argv, pathlib.Path({LAN_BASE!r} + '_%d.err' % index).read_text())
print('LAN-UP')
'''
    result = await lan_run_python(r.lan, script, label="flowtable_qos_start", timeout=30)
    assert result.rc == 0 and "LAN-UP" in result.stdout, result.stdout


async def lan_stop(r):
    script = f'''
import os, pathlib, signal
pids = pathlib.Path({LAN_BASE + '.pids'!r})
if pids.exists():
    for pid in pids.read_text().split():
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    pids.unlink()
print('LAN-DOWN')
'''
    result = await lan_run_python(r.lan, script, label="flowtable_qos_stop", timeout=30)
    assert result.rc == 0 and "LAN-DOWN" in result.stdout, result.stdout


# ---- the orchestrator's side ----------------------------------------------

async def iperf(r, port, *, seconds=IPERF_SECONDS, udp_mbit=None, streams=1):
    """One iperf3 run from here to the LAN VM, and its report.

    The receiver's intervals come back in `server_output_json`, which is where a
    steady-state rate is read: the sender's own figure for UDP is what it
    offered, not what arrived.
    """
    argv = ["iperf3", "-c", r.lan_ip, "-B", WAN_IP, "-p", str(port), "-t", str(seconds),
            "-J", "--get-server-output"]
    if udp_mbit:
        argv += ["-u", "-b", f"{udp_mbit}M", "-l", str(DATAGRAM)]
    if streams > 1:
        argv += ["-P", str(streams)]
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), seconds + 30)
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
    report = json.loads(stdout) if stdout.strip() else {}
    assert proc.returncode == 0 and "error" not in report, (
        proc.returncode, report.get("error"), stderr.decode(errors="replace")[-400:])
    return report


def received_bps(report, after=SETTLE):
    """What the receiver counted per second once the transfer had settled."""
    intervals = [i["sum"] for i in report["server_output_json"]["intervals"]
                 if i["sum"]["start"] >= after - 0.01]
    assert intervals, report["server_output_json"]
    return sum(i["bytes"] for i in intervals) * 8 / sum(i["seconds"] for i in intervals)


def received_loss(report, after=SETTLE):
    """The fraction of a UDP transfer the receiver never saw, once settled."""
    intervals = [i["sum"] for i in report["server_output_json"]["intervals"]
                 if i["sum"]["start"] >= after - 0.01]
    packets = sum(i["packets"] for i in intervals)
    assert packets, report["server_output_json"]
    return sum(i["lost_packets"] for i in intervals) / packets


def lockstep(destination, port, count, *, tos=0, payload_size=256, timeout=1.0):
    """Echo `count` datagrams one at a time from this host, and count the replies.

    The source port is the destination port, so every call is the same flow and
    a flow admitted by one call is measured by the next.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
    sock.bind((WAN_IP, port))
    sock.settimeout(timeout)
    echoed = 0
    try:
        for n in range(count):
            payload = struct.pack("!Q", n) + b"ASK-qos".ljust(payload_size - 8, b".")
            sock.sendto(payload, (destination, port))
            try:
                while sock.recv(4096) != payload:
                    pass
                echoed += 1
            except TimeoutError:
                pass
    finally:
        sock.close()
    return echoed


def probe(destination, seconds, *, interval=0.01, timeout=0.25):
    """Round trips of a small datagram to the LAN VM's echo, one at a time.

    The probe's flow is marked into the same class as the traffic under test,
    so its request waits behind whatever that class queue holds, and the round
    trip it adds over an idle one is the queue's depth in time. A probe the
    queue dropped is counted, not waited for.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((WAN_IP, PORT_PROBE))
    rtts, lost, sent = [], 0, 0
    end = time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            payload = struct.pack("!Q", sent) + b"ASK-qos-probe"
            sent += 1
            started = time.perf_counter()
            sock.sendto(payload, (destination, PORT_PROBE))
            while True:
                left = started + timeout - time.perf_counter()
                if left <= 0:
                    lost += 1
                    break
                sock.settimeout(left)
                try:
                    data = sock.recv(2048)
                except TimeoutError:
                    lost += 1
                    break
                if data == payload:
                    rtts.append(time.perf_counter() - started)
                    break
            pause = started + interval - time.perf_counter()
            if pause > 0:
                time.sleep(pause)
    finally:
        sock.close()
    return {"rtts": rtts, "lost": lost, "sent": sent}


# ---- reading the DUT ------------------------------------------------------

LEAF_COUNTER = re.compile(
    r"^\s*ceetm (dequeued frames|dequeued bytes|rejected frames) \[leaf (\d+)\]:\s*(\d+)\s*$", re.M)
SOFTWARE_TX = re.compile(r"^\s*tx packets \[TOTAL\]:\s*(\d+)\s*$", re.M)
LEAF_FIELDS = {"dequeued frames": "frames", "dequeued bytes": "bytes",
               "rejected frames": "rejected"}


async def egress(r, dev):
    """One `ethtool -S` read of a port: each leaf slot's dequeued frames and
    bytes and rejected frames, the port's software transmit count, and when.

    The leaf counters are hardware totals read without clearing, so a delta
    between two reads is exact. The time is the middle of the call, which is
    what a rate over a window of a few seconds is taken against, and the call's
    length is kept: the counters were read somewhere inside it.
    """
    started = time.monotonic()
    text = (await command(r.target, r.session, "ethtool", "-S", dev))["stdout"]
    ended = time.monotonic()
    leaves = {}
    for name, slot, value in LEAF_COUNTER.findall(text):
        leaves.setdefault(int(slot), {})[LEAF_FIELDS[name]] = int(value)
    software = SOFTWARE_TX.findall(text)
    assert leaves and len(software) == 1, text
    return {"at": (started + ended) / 2, "span": ended - started, "leaves": leaves,
            "software_tx": int(software[0])}


def leaf_delta(before, after, slot):
    return {key: after["leaves"][slot][key] - before["leaves"][slot][key]
            for key in ("frames", "bytes", "rejected")}


def timing_slack(before, after):
    """How far a rate taken between two reads can be off only because neither
    read's instant is known better than its call's length. Small while the
    agent's own path is idle; it grows when that path shares a shaped queue."""
    return (before["span"] + after["span"]) / 2 / (after["at"] - before["at"])


def shaped_bps(before, after, *slots):
    """What the shaper let through the given leaves, in the bits it charges."""
    charged = 0
    for slot in slots:
        moved = leaf_delta(before, after, slot)
        charged += (moved["bytes"] + OAL * moved["frames"]) * 8
    return charged / (after["at"] - before["at"])


def police_counters(text):
    """What a hardware police action reports through `tc -s filter show`: the
    frames its meter saw and how many it dropped.

    The profile counts frames per colour and no bytes, so tc is handed frames
    and drops; a filter and its action each print a stats block, and the larger
    reading is the one carrying the driver's numbers.
    """
    metered = [int(n) for n in re.findall(r"Sent hardware \d+ bytes (\d+) pkt", text)]
    dropped = [int(n) for n in re.findall(r"\(dropped (\d+)", text)]
    return max(metered, default=0), max(dropped, default=0)


def directions(state, *, ingress, proto, src=None, dst=None):
    """The installed directions arriving on `ingress`, by the endpoints of their
    match. Either endpoint may be left open."""
    return [f for f in state["flows"] if f["in"] == ingress and f["proto"] == str(proto)
            and (src is None or f["src"] == src) and (dst is None or f["dst"] == dst)]


async def offload(r, *rules):
    """The flowtable, with the forward-chain rules that offer flows to it.

    Named as the rig's own table, so the rig's teardown is what drains it.
    """
    body = "\n ".join(rules)
    await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 {body}
 }}
}}''')
    await r.wait(lambda s: s["bindings"] == 2)


def inbound(r, proto, port, mark=None):
    """A rule offering the orchestrator's flow to one LAN port, marked for a
    class. The mark is set on every packet of the flow and the offer comes after
    it in the same rule, so admission always sees it."""
    marking = f"ct mark set {mark:#x} " if mark else ""
    return f"ip saddr {WAN_IP} ip daddr {r.lan_ip} {proto} dport {port} {marking}flow add @fast"


async def tree(r, dev, rate_mbit, leaves):
    """The three levels CEETM has: the port as the root qdisc, one channel under
    it shaped at `rate_mbit`, and one class queue per leaf.

    rate and ceil are equal, so the channel has nothing to borrow and its
    committed rate is its ceiling. Leaves take Tx queue slots in the order they
    are created -- the first inherits the channel's own slot when
    TC_HTB_LEAF_TO_INNER turns the channel into an inner class -- so the slot
    `ethtool -S` reports a leaf under is its position in `leaves`.
    """
    rate = f"{rate_mbit}mbit"
    await r.tc("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "offload")
    await r.tc("class", "add", "dev", dev, "parent", "1:", "classid", "1:1",
               "htb", "rate", rate, "ceil", rate)
    for classid, prio in leaves:
        await r.tc("class", "add", "dev", dev, "parent", "1:1", "classid", classid,
                   "htb", "rate", rate, "ceil", rate, "prio", str(prio))
    shown = (await r.tc("class", "show", "dev", dev))["stdout"]
    for classid in ("1:1", *(leaf for leaf, _ in leaves)):
        assert f"class htb {classid} " in shown, (classid, shown)


async def conntrack_clear(r):
    """Every connection between the two hosts, whichever side opened it.

    A mark is sampled once, at admission, so a connection left over from an
    earlier run would carry its old class into this one. Nothing between these
    two hosts outlives the test that opened it, the rig's own echo included."""
    for proto in ("tcp", "udp"):
        for src, dst in ((WAN_IP, r.lan_ip), (r.lan_ip, WAN_IP)):
            await command(r.target, r.session, "conntrack", "-D", "-p", proto,
                          "--orig-src", src, "--orig-dst", dst, check=False)


async def admit(r, port, *, tos=0, destination=None, timeout=20):
    """Echo short bursts to a LAN-side UDP port until both directions of the flow
    are installed, and return the two rows.

    A deadline rather than a round count: an admission that loses the adapter's
    RTNL trylock is declined and offered again only after flowtable GC ticks, so
    every attempt sends before it looks.
    """
    destination = destination or r.lan_ip
    target = f"{destination}:{port}"
    deadline = time.monotonic() + timeout
    while True:
        await asyncio.to_thread(lockstep, destination, port, 8, tos=tos)
        state = await r.state()
        forward = directions(state, ingress=TARGET_WAN_IF, proto=17, dst=target)
        reverse = directions(state, ingress=TARGET_LAN_IF, proto=17, src=target)
        if forward and reverse:
            assert len(forward) == len(reverse) == 1, (forward, reverse)
            return forward[0], reverse[0]
        if time.monotonic() > deadline:
            pytest.fail(f"{target} was not admitted in both directions: {state}")
        await asyncio.sleep(0.5)


async def captured(r, send):
    """The rig's requests as they arrive on this host's WAN interface, captured
    while the coroutine `send()` makes runs."""
    from scapy.all import IP, UDP, AsyncSniffer

    ready = threading.Event()
    sniffer = AsyncSniffer(iface=r.wan_if, store=True, started_callback=ready.set,
                           filter=f"udp and src host {r.lan_ip} and dst port {DPORT}")
    sniffer.start()
    try:
        assert await asyncio.to_thread(ready.wait, 5), "the WAN capture did not start"
        await send()
    finally:
        packets = sniffer.stop()
    return [p for p in packets if IP in p and UDP in p]


async def reload_adapter(r, *parameters, idle=True):
    """Unload the flowtable adapter and load it again with `parameters`.

    The class decode is boot-immutable -- its parameters are 0444 -- so a case
    that needs a different mask reloads the module, and puts the image's own
    options back the same way. The adapter refuses to leave while anything is
    bound, so a caller that expects a clean reload checks that first.
    """
    if idle:
        state = await r.state()
        assert state["bindings"] == state["entries"] == 0, state
    await console_command(r.console, "rmmod", "ask_flowtable", check=idle, timeout=30)
    await console_command(r.console, "modprobe", "ask_flowtable", *parameters, timeout=30)


@pytest_asyncio.fixture
async def qos(rig):
    """The rig, readied for multi-gigabit transfers and hardware queues.

    A transfer measured at line rate needs full-size frames. The rig's host
    routes carry the ports' own MTU already, but an earlier case that lowered
    a path can leave a smaller MTU cached against the LAN VM at the
    orchestrator, so that route is widened here explicitly. Flows in this
    file's port block are routed rather than masqueraded, so a row's endpoints
    are the hosts'.

    Teardown takes down every tree and clsact qdisc on both ports, then forwards
    an exchange through both: that is the proof each port still transmits once
    CEETM has been switched off again.
    """
    r = rig
    mask = int((await read(r.target, r.session,
                           "/sys/module/ask_flowtable/parameters/qos_mark_mask")).strip())
    if not mask:
        pytest.skip("classification is off in this boot; the QoS cases need "
                    "ask_flowtable.qos_mark_mask=0xf0, which the test image ships")
    shift = (mask & -mask).bit_length() - 1
    r.mark = lambda cq: cq << shift
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    console = Console.target(log_path=str(ARTIFACTS / "qos-uart.log"))
    await asyncio.to_thread(console.login, "root", None)
    r.console = console

    async def tc(*argv, check=True):
        """`tc` is not in the agent's argv allowlist, so trees and filters are
        built on the console."""
        return await console_command(console, "tc", *argv, check=check, timeout=30)
    r.tc = tc
    cleanup = []
    printk = None
    try:
        # Every console command is framed by a marker, and a printk landing
        # in the middle of one breaks the framing. Restored last in teardown,
        # after the console's last use.
        printk = " ".join((await read(r.target, r.session, "/proc/sys/kernel/printk")).split()[:4])
        await command(r.target, r.session, "sysctl", "-w", "kernel.printk=1 4 1 7")
        route = json.loads((await command(wan, r.session, "ip", "-j", "route", "show",
                                          "exact", f"{r.lan_ip}/32"))["stdout"])[0]
        await command(wan, r.session, "ip", "route", "replace", f"{r.lan_ip}/32",
                      "via", route["gateway"], "dev", route["dev"], "mtu", "1500")
        cleanup.append((wan, ["ip", "route", "replace", f"{r.lan_ip}/32",
                              "via", route["gateway"], "dev", route["dev"]]))
        for proto in ("tcp", "udp"):
            nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", proto,
                   "--dport", f"{PORT}:{PORTS_LAST}", "-j", "ACCEPT"]
            await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
            cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *nat]))
        await conntrack_clear(r)
        yield r
    finally:
        failures = []

        async def attempt(step, label):
            try:
                await step
            except Exception as error:
                failures.append(f"{label}: {error!r}")

        await attempt(lan_stop(r), "LAN servers")
        for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
            await attempt(tc("qdisc", "del", "dev", dev, "clsact", check=False), f"{dev} clsact")
            await attempt(tc("qdisc", "del", "dev", dev, "root", check=False), f"{dev} root")
        for agent, argv in reversed(cleanup):
            await attempt(command(agent, r.session, *argv, check=False), " ".join(argv))
        await attempt(conntrack_clear(r), "conntrack")
        try:
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                shown = (await tc("qdisc", "show", "dev", dev))["stdout"]
                assert "htb" not in shown and "clsact" not in shown, (dev, shown)
            # Both ports' egress, after CEETM: the request leaves by the WAN
            # port and the echo by the LAN port.
            await r.exchange(32)
        except (Exception, pytest.fail.Exception) as error:
            failures.append(f"egress after teardown: {error!r}")
        console.close()
        if printk:
            await attempt(command(r.target, r.session, "sysctl", "-w", f"kernel.printk={printk}",
                                  check=False), "printk")
        assert not failures, ("QoS fixture restoration failed", failures)


# ---- the scheduler ---------------------------------------------------------

async def test_flowtable_qos_htb_shapes_at_the_cap(qos):
    """One class at the cap, one offloaded flow offered three times it.

    The shaper's own output is measured from the leaf's dequeued bytes over a
    window inside the transfer, which is the hardware's figure rather than the
    receiver's: it has to sit on the cap. The receiver's steady-state goodput is
    held to the same cap less the headers and the shaper's per-frame charge.

    Every frame the classifier matched for the flow is accounted for at the
    leaf -- dequeued or rejected -- and the only frames the leaf may carry beyond
    those are ones the CPU sent before the flow was admitted, which the port's
    software transmit counter bounds. The rejections are the other half of the
    proof: the shaper held the rate by refusing the excess, rather than the
    sender failing to offer it.
    """
    r = qos
    await tree(r, TARGET_LAN_IF, CAP_MBIT, [("1:10", HIGH_PRIO)])
    await offload(r, inbound(r, "udp", PORT_SHAPED, r.mark(HIGH_CQ)))
    await lan_start(r, iperf=[PORT_SHAPED])
    target = f"{r.lan_ip}:{PORT_SHAPED}"
    before = await egress(r, TARGET_LAN_IF)
    client = asyncio.create_task(iperf(r, PORT_SHAPED, udp_mbit=OFFERED_MBIT))
    try:
        await asyncio.sleep(SETTLE)
        first = await egress(r, TARGET_LAN_IF)
        installed = await r.state()
        await asyncio.sleep(WINDOW)
        second = await egress(r, TARGET_LAN_IF)
        report = await client
    finally:
        if not client.done():
            client.cancel()
            await asyncio.gather(client, return_exceptions=True)
    # The class queue drains at the shaped rate; give it time to empty before
    # the totals are compared.
    await asyncio.sleep(0.5)
    after = await egress(r, TARGET_LAN_IF)
    state = await r.state()
    forward = directions(state, ingress=TARGET_WAN_IF, proto=17, dst=target)
    early = directions(installed, ingress=TARGET_WAN_IF, proto=17, dst=target)
    cap = CAP_MBIT * 1e6
    window = leaf_delta(first, second, 0)
    whole = leaf_delta(before, after, 0)
    shaped = shaped_bps(first, second, 0)
    goodput = received_bps(report)
    offered = report["end"]["sum_sent"]["bits_per_second"]
    r.record("qos-htb-shaped", {"installed": installed, "state": state, "window": window,
                                "whole": whole, "shaped_bps": shaped, "goodput_bps": goodput,
                                "offered_bps": offered, "before": before, "first": first,
                                "second": second, "after": after, "report": report})

    assert len(forward) == 1 and len(early) == 1, (early, forward)
    row = forward[0]
    assert row["out"] == TARGET_LAN_IF and int(row["qos"], 16) == HIGH_CQ, row
    # One admission for the whole transfer: the row read mid-window is the row
    # whose packets are accounted below.
    assert early[0]["cookie"] == row["cookie"], (early, row)
    assert offered >= 2 * cap, ("the orchestrator did not offer enough to test a cap", offered)
    slack = timing_slack(first, second)
    assert (0.95 - slack) * cap <= shaped <= (1.03 + slack) * cap, (shaped, cap, slack, window)
    assert window["rejected"] >= window["frames"], window
    software = second["software_tx"] - first["software_tx"]
    assert software <= window["frames"] // 100, (software, window)
    expected = cap * DATAGRAM / (DATAGRAM + UDP_HEADERS + OAL)
    assert 0.9 * expected <= goodput <= 1.02 * expected, (goodput, expected)
    extra = whole["frames"] + whole["rejected"] - int(row["packets"])
    assert 0 <= extra <= after["software_tx"] - before["software_tx"], (
        whole, row["packets"], after["software_tx"] - before["software_tx"])


async def test_flowtable_qos_strict_priority_keeps_its_rate(qos):
    """Two classes on one channel at the cap: the high-priority one offered half
    of it, the low-priority one three times all of it.

    Strict priority serves the high class whenever it holds a frame, so
    saturating its neighbour must cost it nothing: its leaf dequeues what it
    offered and rejects next to nothing, and its receiver loses next to nothing.
    The low class gets what is left -- the two leaves together sit on the cap --
    and its leaf is where the excess is refused.
    """
    r = qos
    await tree(r, TARGET_LAN_IF, CAP_MBIT, [("1:10", HIGH_PRIO), ("1:11", LOW_PRIO)])
    await offload(r, inbound(r, "udp", PORT_HIGH, r.mark(HIGH_CQ)),
                  inbound(r, "udp", PORT_LOW, r.mark(LOW_CQ)))
    await lan_start(r, iperf=[PORT_HIGH, PORT_LOW])
    high_mbit = CAP_MBIT // 2
    clients = [asyncio.create_task(iperf(r, PORT_HIGH, udp_mbit=high_mbit)),
               asyncio.create_task(iperf(r, PORT_LOW, udp_mbit=OFFERED_MBIT))]
    try:
        await asyncio.sleep(SETTLE)
        first = await egress(r, TARGET_LAN_IF)
        state = await r.state()
        await asyncio.sleep(WINDOW)
        second = await egress(r, TARGET_LAN_IF)
        high, low = await asyncio.gather(*clients)
    finally:
        for client in clients:
            if not client.done():
                client.cancel()
        await asyncio.gather(*clients, return_exceptions=True)
    cap = CAP_MBIT * 1e6
    # Shaper bits per payload bit, for datagrams of DATAGRAM bytes.
    charge = (DATAGRAM + UDP_HEADERS + OAL) / DATAGRAM
    held, starved = leaf_delta(first, second, 0), leaf_delta(first, second, 1)
    high_shaped = shaped_bps(first, second, 0)
    total = shaped_bps(first, second, 0, 1)
    rows = {port: directions(state, ingress=TARGET_WAN_IF, proto=17, dst=f"{r.lan_ip}:{port}")
            for port in (PORT_HIGH, PORT_LOW)}
    r.record("qos-strict-priority", {"state": state, "first": first, "second": second,
                                     "high_leaf": held, "low_leaf": starved,
                                     "high_shaped_bps": high_shaped, "total_bps": total,
                                     "high": high, "low": low})

    for port, cq in ((PORT_HIGH, HIGH_CQ), (PORT_LOW, LOW_CQ)):
        assert len(rows[port]) == 1 and int(rows[port][0]["qos"], 16) == cq, rows
    assert low["end"]["sum_sent"]["bits_per_second"] >= 2 * cap, low["end"]["sum_sent"]
    slack = timing_slack(first, second)
    assert (0.95 - slack) * cap <= total <= (1.03 + slack) * cap, (total, cap, slack, held,
                                                                   starved)
    expected_high = high_mbit * 1e6 * charge
    assert (0.95 - slack) * expected_high <= high_shaped <= (1.05 + slack) * expected_high, (
        "the high class did not keep the rate it offered", high_shaped, expected_high, slack)
    assert held["rejected"] <= held["frames"] // 200, held
    assert received_loss(high) <= 0.01, high["server_output_json"]["intervals"]
    assert starved["rejected"] >= starved["frames"], starved
    expected_low = (cap - high_shaped) / charge
    assert 0.85 * expected_low <= received_bps(low) <= 1.05 * expected_low, (
        received_bps(low), expected_low)


async def test_flowtable_qos_wred_drops_before_the_tail(qos):
    """A RED qdisc on a leaf is that class queue's WRED curve, and the curve is
    what drops -- not the tail.

    An offloaded bulk TCP transfer saturates the class; a probe flow marked into
    the same class queue measures how deep the queue sits, as the round trip it
    adds over an idle one. Three phases on one class:

      - a narrow band: the queue holds within it, far below the tail threshold
        the same qdisc sets, so drops began at the curve;
      - a wider band wholly above the first: the queue rises with it, so where
        drops begin follows the configured threshold rather than a fixed one;
      - no RED at all: the queue fills to the tail-drop depth, which is the
        proof the probe can see this queue in the first place. Without it the
        first two would pass for a probe that bypassed the class entirely.

    Each phase's leaf rejections have to move: they are the drops the curve
    made, and the only counter that sees them for an offloaded flow.
    """
    r = qos
    rate = WRED_MBIT * 1e6
    mark = r.mark(HIGH_CQ)
    await tree(r, TARGET_LAN_IF, WRED_MBIT, [("1:10", HIGH_PRIO)])
    await offload(r, inbound(r, "tcp", PORT_BULK, mark), inbound(r, "udp", PORT_PROBE, mark))
    await lan_start(r, iperf=[PORT_BULK], echo=[PORT_PROBE])
    probe_target = f"{r.lan_ip}:{PORT_PROBE}"
    deadline = time.monotonic() + 20
    while True:
        await asyncio.to_thread(probe, r.lan_ip, 0.5)
        rows = directions(await r.state(), ingress=TARGET_WAN_IF, proto=17, dst=probe_target)
        if rows:
            break
        assert time.monotonic() < deadline, "the probe flow was never admitted"
    assert int(rows[0]["qos"], 16) == HIGH_CQ, rows
    idle = await asyncio.to_thread(probe, r.lan_ip, 1.5)
    base = statistics.median(idle["rtts"])

    async def loaded():
        before = await egress(r, TARGET_LAN_IF)
        bulk = asyncio.create_task(iperf(r, PORT_BULK, seconds=6, streams=4))
        try:
            await asyncio.sleep(2.0)
            sample = await asyncio.to_thread(probe, r.lan_ip, 3.0)
            state = await r.state()
            report = await bulk
        finally:
            if not bulk.done():
                bulk.cancel()
                await asyncio.gather(bulk, return_exceptions=True)
        after = await egress(r, TARGET_LAN_IF)
        return {"added": statistics.median(sample["rtts"]) - base,
                "received": len(sample["rtts"]), "lost": sample["lost"],
                "leaf": leaf_delta(before, after, 0),
                "goodput": report["end"]["sum_received"]["bits_per_second"],
                "rows": directions(state, ingress=TARGET_WAN_IF, proto=6,
                                   dst=f"{r.lan_ip}:{PORT_BULK}")}

    phases = {}
    for name, (low, high) in WRED_BANDS.items():
        # tc wants the averaging burst at least min/avpkt; the hardware curve
        # works on the instantaneous count and ignores it.
        burst = (2 * low + high) // (3 * 1500) + 1
        await r.tc("qdisc", "add", "dev", TARGET_LAN_IF, "parent", "1:10", "handle", "10:",
                   "red", "limit", str(WRED_LIMIT), "min", str(low), "max", str(high),
                   "avpkt", "1500", "burst", str(burst), "probability", WRED_PROBABILITY,
                   "bandwidth", f"{WRED_MBIT}mbit")
        phases[name] = await loaded()
        await r.tc("qdisc", "del", "dev", TARGET_LAN_IF, "parent", "1:10", "handle", "10:")
    phases["tail"] = await loaded()
    r.record("qos-wred", {"base": base, "idle": idle, "phases": phases})

    def delay(size):
        return size * 8 / rate

    for name, phase in phases.items():
        assert phase["leaf"]["rejected"] > 0, (name, phase["leaf"])
        assert phase["received"] >= 100, (name, phase["received"], phase["lost"])
        assert phase["goodput"] >= 0.8 * rate * TCP_PAYLOAD / (TCP_FRAME + OAL), (
            name, phase["goodput"])
        assert len(phase["rows"]) >= 4, (name, phase["rows"])
        assert all(int(f["qos"], 16) == HIGH_CQ for f in phase["rows"]), (name, phase["rows"])
    narrow, wide, tail = phases["narrow"], phases["wide"], phases["tail"]
    assert tail["added"] >= 0.4 * delay(TAIL_FRAMES * (TCP_FRAME + OAL)), (
        "the probe does not wait behind the class queue, so nothing below says "
        "anything about it", tail)
    assert narrow["added"] <= 1.3 * delay(WRED_BANDS["narrow"][1]) + PROBE_SLACK, narrow
    assert wide["added"] <= 1.3 * delay(WRED_BANDS["wide"][1]) + PROBE_SLACK, wide
    assert wide["added"] >= 0.5 * delay(WRED_BANDS["wide"][0]), wide
    assert narrow["added"] < wide["added"] < tail["added"], phases


# ---- DSCP -----------------------------------------------------------------

async def test_flowtable_qos_dscp_map_classifies_unmarked_frames(qos):
    """A frame whose mark names no class is queued by its DSCP, through the
    egress map, in hardware and in software alike.

    The map is the per-port table a `flower ip_tos ... skbedit priority` filter
    programs, and it answers only for frames that named no class of their own.
    Both paths once failed to reach it. The hardware enable tested the entry's
    whole mark word, which is never zero because every offloaded flow carries a
    valid ingress-policer field, so no offloaded flow could use the map; and the
    software path asked a function that answers a default queue for every
    unmarked frame. Either regression sends EF to the default class queue, and
    the leaf counts below read zero.

    The counts are exact because the queue is one nothing else reaches: EF goes
    to the prio 1 leaf, since the DUT's own unmarked frames leave on class queue
    7, which the prio 0 leaf holds. A best-effort flow on the same port is the
    control, and moves neither leaf.
    """
    r = qos
    dev = TARGET_LAN_IF
    await tree(r, dev, CAP_MBIT, [("1:10", HIGH_PRIO), ("1:11", LOW_PRIO)])
    await r.tc("qdisc", "add", "dev", dev, "clsact")
    await r.tc("filter", "add", "dev", dev, "egress", "protocol", "ip", "pref", "1",
               "flower", "skip_sw", "ip_tos", f"{EF_TOS:#x}/0xfc",
               "action", "skbedit", "priority", "1:11")
    shown = (await r.tc("filter", "show", "dev", dev, "egress"))["stdout"]
    assert "in_hw" in shown and "skip_sw" in shown, shown
    # EF_SOFTWARE is deliberately not offered: it is the software half.
    await offload(r, f"ip saddr {WAN_IP} ip daddr {r.lan_ip} "
                     f"udp dport {{ {PORT_EF}, {PORT_BE} }} flow add @fast")
    await lan_start(r, echo=[PORT_EF, PORT_BE, PORT_EF_SOFTWARE])
    for port, tos in ((PORT_EF, EF_TOS), (PORT_BE, 0)):
        forward, reverse = await admit(r, port, tos=tos)
        assert int(forward["qos"], 16) == int(reverse["qos"], 16) == 0, (forward, reverse)

    async def burst(port, tos):
        target = f"{r.lan_ip}:{port}"
        state = await r.state()
        before = await egress(r, dev)
        echoed = await asyncio.to_thread(lockstep, r.lan_ip, port, COUNT, tos=tos)
        after = await egress(r, dev)
        final = await r.state()
        return {"echoed": echoed,
                "rows": (directions(state, ingress=TARGET_WAN_IF, proto=17, dst=target),
                         directions(final, ingress=TARGET_WAN_IF, proto=17, dst=target)),
                "mapped": leaf_delta(before, after, 1), "other": leaf_delta(before, after, 0),
                "software_tx": after["software_tx"] - before["software_tx"]}

    ef = await burst(PORT_EF, EF_TOS)
    best_effort = await burst(PORT_BE, 0)
    software = await burst(PORT_EF_SOFTWARE, EF_TOS)
    r.record("qos-dscp-map", {"filter": shown, "ef": ef, "best_effort": best_effort,
                              "software": software})

    frame = 256 + UDP_HEADERS
    for name, result in (("ef", ef), ("best_effort", best_effort)):
        assert result["echoed"] == COUNT, (name, result)
        assert [len(rows) for rows in result["rows"]] == [1, 1], (name, result["rows"])
        (old,), (new,) = result["rows"]
        assert old["cookie"] == new["cookie"], (name, old, new)
        assert int(new["packets"]) - int(old["packets"]) == COUNT, (name, old, new)
        assert result["software_tx"] <= COUNT // 4, (name, result)
    # Offloaded and unmarked, and every frame on the class the codepoint names.
    assert ef["mapped"] == {"frames": COUNT, "bytes": COUNT * frame, "rejected": 0}, ef
    assert best_effort["mapped"]["frames"] == 0, best_effort
    assert best_effort["other"]["frames"] < COUNT // 4, best_effort
    # The same codepoint through the CPU lands on the same class.
    assert software["echoed"] == COUNT, software
    assert software["rows"] == ([], []), software
    assert software["software_tx"] >= COUNT, software
    assert software["mapped"] == {"frames": COUNT, "bytes": COUNT * frame, "rejected": 0}, software


async def test_flowtable_qos_dscp_remark_rewrites_the_wire(qos):
    """A mark that carries a remark makes the hardware rewrite the DSCP on the
    wire, and nothing else rewrites it.

    The WAN host captures what arrives. First, before any class exists, the
    rig's own sender through plain software forwarding: every request at DSCP
    0, which is what the sender puts there itself. Then the same sender with
    the flow in hardware under a mark naming EF: every request at EF, with an
    IP checksum that still verifies, one TTL lower, and each one counted by the
    classifier while the CPU transmitted next to nothing.

    The remark lives in bits the image's mask does not cover, so the adapter
    is reloaded with a wider one for the case and with the image's own options
    afterwards; the two boot-immutable parameters have to read back as they
    did before.
    """
    from scapy.all import IP

    r = qos
    parameters = "/sys/module/ask_flowtable/parameters/"
    original = {name: (await read(r.target, r.session, parameters + name)).strip()
                for name in ("qos_mark_mask", "qos_default_class")}
    plain = await captured(r, lambda: r.exchange(16))
    assert len(plain) == 16 and {p[IP].tos for p in plain} == {0}, [p.summary() for p in plain]
    await r.clear_ct()
    await reload_adapter(r, f"qos_mark_mask={REMARK_MASK:#x}")
    try:
        assert int((await read(r.target, r.session, parameters + "qos_mark_mask")).strip()) \
            == REMARK_MASK
        shift = (REMARK_MASK & -REMARK_MASK).bit_length() - 1
        await r.table(mark=REMARK_CLASS << shift)
        await r.exchange(64)
        installed = await r.wait(lambda s: s["entries"] == 2)
        before = await egress(r, TARGET_WAN_IF)
        packets = await captured(r, lambda: r.exchange(COUNT))
        after = await egress(r, TARGET_WAN_IF)
        final = await r.state()
        r.record("qos-dscp-remark", {"installed": installed, "final": final,
                                     "tos": [p[IP].tos for p in packets],
                                     "software_tx": after["software_tx"] - before["software_tx"]})

        assert all(int(f["qos"], 16) == REMARK_CLASS for f in installed["flows"]), installed
        counted = {f["cookie"]: int(f["packets"]) for f in final["flows"]}
        assert set(counted) == {f["cookie"] for f in installed["flows"]}, (installed, final)
        for flow in installed["flows"]:
            assert counted[flow["cookie"]] - int(flow["packets"]) == COUNT, (flow, final)
        assert after["software_tx"] - before["software_tx"] <= 32, (before, after)
        assert len(packets) == COUNT, len(packets)
        for p in packets:
            assert p[IP].tos == EF_TOS and p[IP].ttl == 63, p.summary()
            saved = p[IP].chksum
            copy = p[IP].copy()
            del copy.chksum
            assert IP(bytes(copy)).chksum == saved, p.summary()
    finally:
        try:
            await r.delete_table()
            await r.clear_ct()
        finally:
            await reload_adapter(r, idle=False)
    restored = {name: (await read(r.target, r.session, parameters + name)).strip()
                for name in original}
    assert restored == original, (original, restored)


# ---- ingress policing ------------------------------------------------------

async def test_flowtable_qos_flower_police_caps_the_flow(qos):
    """A `flower` police filter on the WAN port's ingress, offloaded, holds one
    offloaded flow offered three times its rate.

    The filter is bound to the flow at admission: the adapter matches the
    finished tuple against it and writes the profile it allocated into the
    entry, so the forward row names a policer and the reverse row, which
    arrives on the other port, names none. The filter reports zero the moment it
    exists -- its baseline is seeded from the profile, which an earlier filter
    may have used -- and afterwards the frames it metered are the frames the
    classifier matched for the flow. Which exact reading that is depends on
    whether the microcode counts an entry hit before or after the meter's
    verdict, which its headers do not say, so both exact readings are
    accepted and nothing between them.
    """
    r = qos
    dev = TARGET_WAN_IF
    target = f"{r.lan_ip}:{PORT_POLICED}"
    await r.tc("qdisc", "add", "dev", dev, "clsact")
    await r.tc("filter", "add", "dev", dev, "ingress", "protocol", "ip", "pref", "1",
               "flower", "skip_sw", "ip_proto", "udp", "dst_ip", r.lan_ip,
               "dst_port", str(PORT_POLICED),
               "action", "police", "rate", f"{CAP_MBIT}mbit", "burst", POLICE_BURST,
               "conform-exceed", "drop")
    installed = (await r.tc("-s", "filter", "show", "dev", dev, "ingress"))["stdout"]
    assert "in_hw" in installed and "skip_sw" in installed, installed
    assert police_counters(installed) == (0, 0), installed
    # The filter exists before the flow does, because the binding is made at
    # admission and a flow admitted earlier would never meet it.
    await offload(r, inbound(r, "udp", PORT_POLICED))
    await lan_start(r, iperf=[PORT_POLICED])
    report = await iperf(r, PORT_POLICED, udp_mbit=OFFERED_MBIT)
    state = await r.state()
    shown = (await r.tc("-s", "filter", "show", "dev", dev, "ingress"))["stdout"]
    metered, dropped = police_counters(shown)
    forward = directions(state, ingress=dev, proto=17, dst=target)
    reverse = directions(state, ingress=TARGET_LAN_IF, proto=17, src=target)
    goodput = received_bps(report)
    offered = report["end"]["sum_sent"]["bits_per_second"]
    r.record("qos-flower-police", {"filter": shown, "state": state, "metered": metered,
                                   "dropped": dropped, "goodput_bps": goodput,
                                   "offered_bps": offered, "report": report})

    cap = CAP_MBIT * 1e6
    assert len(forward) == len(reverse) == 1, (forward, reverse)
    profile = int(forward[0]["qos"], 16) >> 8 & 0xf
    assert 1 <= profile <= 7, forward
    assert int(reverse[0]["qos"], 16) >> 8 & 0xf == 0, reverse
    assert offered >= 2 * cap, ("the orchestrator did not offer enough to test a meter", offered)
    hits = int(forward[0]["packets"])
    assert hits in (metered, metered - dropped), (hits, metered, dropped)
    # Three times the rate offered: about two frames in three are red.
    assert dropped >= metered // 2, (metered, dropped)
    # The profile meters the frame the port received, headers and all.
    expected = cap * DATAGRAM / (DATAGRAM + UDP_HEADERS)
    assert 0.9 * expected <= goodput <= 1.03 * expected, (goodput, expected)


# ---- the egress a flow was installed with ----------------------------------

async def read_intervals(stream, into):
    """Every interval a `--json-stream` iperf3 reports, with when it arrived
    here. An interval is reported as it ends, so it covers the second before."""
    while line := await stream.readline():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("event") == "interval":
            into.append((time.monotonic(), event["data"]["sum"]["bits_per_second"]))


async def conntrack_ids(r, port):
    """The ids of the LAN VM's TCP connections to one port on this host."""
    listing = await command(r.target, r.session, "conntrack", "-L", "-p", "tcp",
                            "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                            "--dport", str(port), "-o", "id")
    return set(re.findall(r"\bid=(\d+)", listing["stdout"]))


async def test_flowtable_qos_egress_change_readmits_under_the_tree(qos):
    """A tree built or removed under live offloaded flows retires and readmits
    every one of them, with nothing but the next packet doing it.

    A hardware entry carries the egress frame queue it was installed with, so
    when HTB offload switches a port into or out of CEETM, each entry leaving
    by that port names a queue the port no longer schedules. cdx tells the
    adapter after every HTB command, and the adapter retires every entry using
    the port, counting each as a QoS invalidation. Linux readmits the flow on
    its next packet, against whatever the port has by then.

    One four-stream TCP transfer from the LAN VM runs through all of it, and
    its connections are the same conntrack entries at the end as at the start:
    no flush, no reconnect. Unshaped, it runs at hardware line rate; once the
    tree is up every stream is back on a fresh entry, carries the class its
    mark names, and is held at the cap by the leaf that class holds; once the
    tree is gone every stream is back on a fresh entry again, at line rate.
    """
    r = qos
    dev = TARGET_WAN_IF
    target = f"{WAN_IP}:{PORT_EGRESS}"
    await offload(r, f"ip saddr {r.lan_ip} ip daddr {WAN_IP} tcp dport {PORT_EGRESS} "
                     f"ct mark set {r.mark(HIGH_CQ):#x} flow add @fast")
    route = f"{WAN_IP}/32"
    client = f'''
import json, subprocess
route = {route!r}
existing = json.loads(subprocess.check_output(['ip', '-j', 'route', 'show', 'exact', route], text=True))
assert not existing, existing
subprocess.run(['ip', 'route', 'add', route, 'via', {r.lan_gateway!r}, 'dev', {LAN_NIC!r},
                'mtu', '1500'], check=True)
try:
    result = subprocess.run(['iperf3', '-c', {WAN_IP!r}, '-B', {r.lan_ip!r},
                             '-p', {str(PORT_EGRESS)!r}, '-P', '4', '-t', '60'],
                            capture_output=True, text=True, timeout=90)
finally:
    subprocess.run(['ip', 'route', 'del', route, 'dev', {LAN_NIC!r}])
print(json.dumps({{'rc': result.returncode, 'stderr': result.stderr[-400:]}}))
'''
    # The receiving end streams its intervals, so a rate can be read for each
    # phase of the one transfer. It is stopped once the last phase has been
    # sampled, which ends the sender too.
    server = await asyncio.create_subprocess_exec(
        "iperf3", "-s", "-1", "-B", WAN_IP, "-p", str(PORT_EGRESS), "--json-stream",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    intervals = []
    reader = asyncio.create_task(read_intervals(server.stdout, intervals))
    transfer = None
    try:
        await asyncio.sleep(0.3)
        assert server.returncode is None, "the endpoint iperf3 did not start"
        transfer = asyncio.create_task(lan_run_python(r.lan, client, label="flowtable_qos_egress",
                                                      timeout=120))
        deadline = time.monotonic() + 10
        while True:
            state = await r.state()
            bulk = [f for f in directions(state, ingress=TARGET_LAN_IF, proto=6, dst=target)
                    if int(f["bytes"]) > 1_000_000]
            if len(bulk) == 4:
                break
            assert not transfer.done() and time.monotonic() < deadline, state
            await asyncio.sleep(0.25)
        streams = {f["src"] for f in bulk}
        admitted = time.monotonic()
        connections = await conntrack_ids(r, PORT_EGRESS)
        await asyncio.sleep(3.0)

        async def change(step):
            """Change the WAN port's tree, then wait until every stream is back
            on an entry installed after the change, and the port's QoS
            invalidations account for every entry that was using it."""
            before = await r.state()
            using = sum(1 for f in before["flows"] if dev in (f["in"], f["out"]))
            old = {f["cookie"] for f in before["flows"]}
            started = time.monotonic()
            await step()
            # A change is several HTB commands, and a flow readmitted between
            # two of them is retired again by the next. The retirement itself
            # is queued work, so give it a moment: an entry still listed for
            # that instant must not pass for the readmission this waits for.
            await asyncio.sleep(0.5)

            # A retired connection is readmitted as the same Netfilter flow,
            # so its cookie is kept; what shows the readmission is an install
            # for each of its directions. Invalidations count connections,
            # whose two directions share one handle. Only the bulk streams
            # are waited for: iperf3's idle control connection is retired
            # too, and sends nothing that would readmit it.
            def readmitted(state):
                present = {f["src"] for f in directions(state, ingress=TARGET_LAN_IF, proto=6,
                                                        dst=target)}
                return (streams <= present and
                        state["installs"] - before["installs"] >= 2 * len(streams) and
                        state["qos_invalidations"] >= before["qos_invalidations"] + len(streams))
            after = await r.wait(readmitted, timeout=20)
            return {"started": started, "readmitted": time.monotonic(), "before": before,
                    "after": after, "using": using, "old": sorted(old)}

        shaping = await change(lambda: tree(r, dev, CAP_MBIT, [("1:10", HIGH_PRIO)]))
        await asyncio.sleep(1.0)
        first = await egress(r, dev)
        await asyncio.sleep(WINDOW)
        second = await egress(r, dev)
        unshaping = await change(lambda: r.tc("qdisc", "del", "dev", dev, "root"))
        await asyncio.sleep(4.5)
        ended = time.monotonic()
        survived = await conntrack_ids(r, PORT_EGRESS)
    finally:
        if server.returncode is None:
            server.terminate()
        await asyncio.wait_for(server.wait(), 10)
        await asyncio.gather(reader, return_exceptions=True)
        # The LAN console is a single channel, and the fixture's teardown needs
        # it back: the sender has to have finished before anything else runs.
        sender = await transfer if transfer else None
    r.record("qos-egress-change", {"intervals": intervals, "admitted": admitted,
                                   "shaping": shaping, "unshaping": unshaping, "ended": ended,
                                   "first": first, "second": second,
                                   "connections": sorted(connections),
                                   "survived": sorted(survived),
                                   "sender": sender.stdout if sender else None})

    def median_between(start, end):
        rates = [bps for arrived, bps in intervals if arrived - 1.0 >= start and arrived <= end]
        assert len(rates) >= 2, (start, end, intervals)
        return statistics.median(rates)

    cap = CAP_MBIT * 1e6
    assert len(connections) >= 4 and survived == connections, (connections, survived)
    for phase in (shaping, unshaping):
        after = phase["after"]
        assert phase["using"] >= 2 * len(streams), phase["before"]
        # Every connection using the port was retired, and each stream's
        # directions installed again.
        assert after["qos_invalidations"] - phase["before"]["qos_invalidations"] >= phase["using"] // 2, (
            "an entry using the port outlived the change to its egress", phase)
        assert after["installs"] - phase["before"]["installs"] >= 2 * len(streams), phase
        assert after["invalidated"] == after["fatal"] == 0 and after["bindings"] == 2, after
    shaped_rows = directions(shaping["after"], ingress=TARGET_LAN_IF, proto=6, dst=target)
    assert all(int(f["qos"], 16) == HIGH_CQ for f in shaped_rows), shaped_rows
    assert median_between(admitted, shaping["started"]) >= UNSHAPED_GBPS * 1e9, intervals
    expected = cap * TCP_PAYLOAD / (TCP_FRAME + OAL)
    shaped = median_between(shaping["readmitted"] + 1.0, unshaping["started"])
    assert 0.88 * expected <= shaped <= 1.01 * expected, (shaped, expected)
    # The agent's own frames leave by this port through the same class queue as
    # the transfer while the tree stands, so its reads are slower here than
    # anywhere else in the file, and the window's edges less certain.
    held = shaped_bps(first, second, 0)
    slack = timing_slack(first, second)
    assert (0.95 - slack) * cap <= held <= (1.03 + slack) * cap, (
        held, cap, slack, leaf_delta(first, second, 0))
    assert median_between(unshaping["readmitted"] + 1.0, ended) >= UNSHAPED_GBPS * 1e9, intervals

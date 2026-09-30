"""6o4 and 4o6 tunnel offload on the Linux flowtable: the outer IP header is
inserted and stripped in hardware.

A tunnel is an encapsulation the same shape as a PPPoE session, one layer up:
one direction of a connection leaves the DUT by the tunnel device and the
hardware has to prepend the outer header the kernel would, and the other
direction arrives inside that header on the physical WAN port and the
hardware has to strip it before it can match the inner tuple. Both halves are
asserted separately, because the ingress half is the one Netfilter describes
with nothing at all -- no pop action, no dissector key -- and is therefore the
half most likely to be silently refused.

Two things make a tunnel unlike a session. The kernel resolves the outer
route and its next hop when it walks the forwarding path, so the adapter
records what the kernel walked rather than deriving it, and every case here
asserts the adapter's record against the tunnel device's own configuration.
And the outer header is a real IP header with a TTL and a checksum, so the
routed cases capture the frames the hardware put on the wire and read those
fields back, which the counters alone cannot show. The outer header carries no
don't-fragment bit: the insert opcode fills the fragment field itself and
ignores the template's, exactly as the legacy owner met and hardcoded around,
so the tunnel's pmtudisc reaches the wire only for CPU-forwarded frames.

Shapes: `6o4` is IPv6 inside IPv4 (`sit`, proto 41), the tunnel-broker and
6rd shape; `4o6` is IPv4 inside IPv6 (`ipip6`, next header 4), the DS-Lite
shape. The outer endpoints are the DUT's WAN address and the orchestrator's;
the inner ones a /64 or a /24 that belongs to neither segment, so a routing
mistake cannot look like a working path.

A 4o6 UDP upload stays in Linux. It arrives on the LAN port, which can deliver
a full 1500-byte frame whatever MTU it is given, and the tunnel's path is
smaller: the microcode would have to fragment it, and the fragments it builds
from a frame an Ethernet port received carry no payload. So the 4o6 UDP cases
assert that refusal and the download half, and the 4o6 upload -- the insert
opcode -- is carried by TCP, which sets DF and is never the microcode's to
fragment.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.counters import kernel_tx_packets
from _gated_tcp import GatedTcp
from _topology import (DUT_IPV6_LAN, DUT_IPV6_WAN, FULL_FRAME, LAN_IPV6, LAN_NIC, TARGET_LAN_IF,
                       TARGET_WAN_IF, lan_run, lan_run_python)
import test_flowtable_offload as ft
from test_flowtable_offload import ARTIFACTS, Rig, assert_undisturbed, command, read

TABLE = "ask_tunnel"
DUT_WAN_IPV4 = os.environ.get("ASK_TARGET_IP", "10.0.0.62")
# The orchestrator's own WAN address, which is also where its agent listens.
ORCH_IPV4 = os.environ.get("ASK_WAN_IP", "127.0.0.1")

# 6o4: the inner /64 is the point-to-point link between the two sit devices.
TUN_6O4 = "ft6o4"
DUT_INNER_V6, ORCH_INNER_V6 = "fc00:cafe::2", "fc00:cafe::1"
MTU_6O4 = 1480          # 1500 less the 20-byte IPv4 outer header

# 4o6: the outer endpoints share the WAN segment's ULA /64 with the IPv6
# tests; the inner /24 is the tunnel's own.
TUN_4O6 = "ft4o6"
ORCH_OUTER_V6 = os.environ.get("ASK_TUNNEL_ORCH_OUTER_V6", "fc00:beef::2")
DUT_INNER_V4, ORCH_INNER_V4 = "10.77.0.2", "10.77.0.1"
MTU_4O6 = 1440          # 1500 less the 40-byte IPv6 outer header and a 20-byte margin

# One port pair per case so a conntrack left by one never feeds another.
PORTS = {"routed": (48910, 48911), "mtu": (48920, 48921), "tcp": (48930, 48931),
         "change": (48940, 48941), "delete": (48950, 48951)}

# What the outer header's TTL is asked to be, and what it is changed to by the
# case that reconfigures the tunnel under a live flow.
TTL, CHANGED_TTL = 64, 33


def _upload_refused(shape, proto="udp"):
    """Whether the adapter leaves the LAN-to-tunnel direction to Linux.

    A non-TCP IPv4 direction is installed only where its path carries the
    largest packet its ingress port can deliver; into a tunnel smaller than a
    full frame, the microcode would fragment it, and its fragments of a frame
    an Ethernet port received are zero-filled. TCP sets DF and is exempt, and
    an IPv6 direction is bounded by the LAN's advertised MTU instead."""
    return shape.family == 4 and proto != "tcp" and shape.mtu < FULL_FRAME


class TunnelRig(Rig):
    """Only the family-independent parts of Rig are reused: state, wait,
    record, nft. Its table, conntrack and exchange helpers are IPv4-shaped and
    bound to the WAN host's ordinary address, which a tunnel never uses."""

    async def delete_table(self):
        await command(self.target, self.session, "nft", "delete", "table", "inet", TABLE,
                      check=False)
        return await self.wait(lambda s: not s["bindings"] and not s["entries"])


def _tunnel_text(shape):
    """How the adapter prints a tunnel hop on a flow row: the device, the
    mode, and the outer endpoints as the tunnel device configures them, local
    first. An IPv6 address is bracketed, as the row's other addresses are."""
    local, remote = shape.outer
    fmt = (lambda a: f"[{a}]") if ":" in local else (lambda a: a)
    return f"{shape.device}/{shape.mode}:{fmt(local)}>{fmt(remote)}"


class Shape:
    """One tunnel mode: the devices, the addresses at each end and the family
    of the flow inside it."""

    def __init__(self, mode, sport, dport):
        self.mode = mode
        self.sport, self.dport = sport, dport
        if mode == "6o4":
            self.device = TUN_6O4
            self.outer = (DUT_WAN_IPV4, ORCH_IPV4)
            self.inner_dut, self.inner_orch = DUT_INNER_V6, ORCH_INNER_V6
            self.family, self.mtu, self.header = 6, MTU_6O4, 20
        else:
            self.device = TUN_4O6
            self.outer = (DUT_IPV6_WAN, ORCH_OUTER_V6)
            self.inner_dut, self.inner_orch = DUT_INNER_V4, ORCH_INNER_V4
            self.family, self.mtu, self.header = 4, MTU_4O6, 40

    @property
    def outer_family(self):
        return 4 if self.mode == "6o4" else 6

    def match(self, lan_address, proto="udp"):
        ip = "ip6" if self.family == 6 else "ip"
        return (f"{ip} saddr {lan_address} {proto} sport {self.sport} "
                f"{proto} dport {self.dport}")

    def capture_filter(self):
        """The outer packets the DUT sends, and only those. A 4o6 packet Linux
        built carries ip6tnl's tunnel encapsulation limit in a destination
        options header before the inner one, which `ip6 proto` would not look
        past, so the next header is read at both places it can be."""
        local, remote = self.outer
        if self.mode == "6o4":
            return f"ip proto 41 and src host {local} and dst host {remote}"
        return (f"ip6 and src host {local} and dst host {remote} "
                f"and (ip6[6] == 4 or (ip6[6] == 60 and ip6[40] == 4))")


# ---- traffic -------------------------------------------------------------

async def _udp_exchange(r, count, payload_size=64):
    """Echo `count` datagrams from the LAN VM to the orchestrator's inner
    address. A wrong payload or a reply from the wrong endpoint is fatal; a
    timeout is only counted, so a caller can tolerate loss while the flow is
    being admitted and forbid it once it is installed."""
    shape = r.shape
    family = "socket.AF_INET6" if shape.family == 6 else "socket.AF_INET"
    script = f'''
import json, socket, struct, time
s = socket.socket({family}, socket.SOCK_DGRAM)
s.settimeout(2)
s.bind(({r.lan_address!r}, {shape.sport}))
if {shape.family} == 4:
    s.setsockopt(socket.SOL_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 2)  # IP_PMTUDISC_DO
else:
    s.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_MTU_DISCOVER", 23), 2)
echoed = lost = 0
for n in range({count}):
    payload = struct.pack('!Q', n) + b'ASK-flowtable-tunnel'.ljust({payload_size} - 8, b'.')[:{payload_size} - 8]
    s.sendto(payload, ({shape.inner_orch!r}, {shape.dport}))
    try:
        data, addr = s.recvfrom(4096)
    except TimeoutError:
        lost += 1
        continue
    assert data == payload, (n, len(data), len(payload))
    assert (addr[0], addr[1]) == ({shape.inner_orch!r}, {shape.dport}), (n, addr)
    echoed += 1
    time.sleep(0.005)
s.close()
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
'''
    result = await lan_run_python(r.lan, script, timeout=count * 0.3 + 40,
                                  label="flowtable_tunnel")
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


def _expected(r, proto="udp"):
    """How many directions of the connection hardware should hold."""
    return 1 if _upload_refused(r.shape, proto) else 2


async def _both_directions(r, proto="udp", state=None):
    """Admission is directional: one direction refused leaves the other
    accelerated, and a throughput number hides the difference. The ingress
    half of a tunnel is the likelier refusal, because its rule is
    byte-for-byte the rule an unencapsulated flow produces. Where the upload
    is Linux's by design, the download alone is what is expected. Reads the
    state unless handed one."""
    state = state or await r.state()
    expected = _expected(r, proto)
    if len(state["flows"]) != expected:
        conntrack = await command(r.target, r.session, "conntrack", "-L", "-o", "extended",
                                  check=False)
        r.record("tunnel-partial-admission", {"state": state, "conntrack": conntrack})
        pytest.fail(f"{len(state['flows'])} of {expected} directions admitted: "
                    f"validated={state['validated']} rejects={state['rejects']} "
                    f"busy={state['busy']} errors={state['errors']}\n"
                    f"flows={state['flows']}\nconntrack={conntrack['stdout']}")
    return state["flows"]


async def _offload_table(r, proto="udp"):
    await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }};
 flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 {r.shape.match(r.lan_address, proto)} flow add @fast
 }}
}}''')
    await r.wait(lambda s: s["bindings"] == 2)


async def _admit(r, timeout=15):
    """Exchange short bursts until the expected directions are installed. A
    deadline rather than a round count: an admission that loses rtnl_trylock
    is declined, and the software path offers the flow again only about a
    second later, while traffic keeps it there."""
    deadline = time.monotonic() + timeout
    while True:
        await _udp_exchange(r, 4)
        state = await r.state()
        if len(state["flows"]) == _expected(r):
            return state["flows"]
        if time.monotonic() > deadline:
            return await _both_directions(r)
        await asyncio.sleep(0.5)


def _direction(flows, source, destination):
    matching = [f for f in flows if f["src"].startswith(source + ":")
                and f["dst"].startswith(destination + ":")]
    assert len(matching) == 1, (source, destination, flows)
    return matching[0]


def _bracketed(address):
    return f"[{address}]" if ":" in address else address


def _directions(r, flows):
    """(forward, reverse). The forward is None where the upload is Linux's by
    design, and then it must be absent rather than merely unasked for."""
    lan, orch = _bracketed(r.lan_address), _bracketed(r.shape.inner_orch)
    reverse = _direction(flows, orch, lan)
    if _upload_refused(r.shape, "tcp" if reverse["proto"] == "6" else "udp"):
        assert not [f for f in flows if f["src"].startswith(lan + ":")], flows
        return None, reverse
    return _direction(flows, lan, orch), reverse


def _assert_tunnel(r, forward, reverse):
    """The tunnel is named on the direction that inserts its header and on the
    one that strips it, and on neither LAN half. Both directions still name
    the physical ports: a tunnel device never becomes one. `forward` is None
    where the upload stays in Linux."""
    expected = _tunnel_text(r.shape)
    assert reverse["in_tnl"] == expected and reverse["out_tnl"] == "-", reverse
    assert reverse["in"] == TARGET_WAN_IF and reverse["out"] == TARGET_LAN_IF, reverse
    assert reverse["family"] == str(r.shape.family), reverse
    if forward is None:
        return
    assert forward["out_tnl"] == expected and forward["in_tnl"] == "-", forward
    assert forward["in"] == TARGET_LAN_IF and forward["out"] == TARGET_WAN_IF, forward
    assert forward["family"] == str(r.shape.family), forward
    # The forward direction leaves by the tunnel, so it carries the tunnel's
    # MTU; the reverse carries the LAN port's.
    assert int(forward["mtu"]) == r.shape.mtu, forward


async def _tunnel_counters(r):
    """The tunnel device's own counters, which include what the hardware
    carried through it once the adapter has folded its record in."""
    result = await command(r.target, r.session, "ip", "-s", "-j", "link", "show", r.shape.device)
    stats = json.loads(result["stdout"])[0]["stats64"]
    return {"rx": stats["rx"]["packets"], "tx": stats["tx"]["packets"],
            "rx_bytes": stats["rx"]["bytes"], "tx_bytes": stats["tx"]["bytes"]}


def _tunnel_record(r, state):
    """The adapter's record for the tunnel device: the strip counts into its
    receive half and the insert into its transmit half."""
    rows = [t for t in state["tunnels"] if t["dev"] == r.shape.device]
    assert len(rows) == 1, (r.shape.device, state["tunnels"])
    return {k: int(rows[0][k]) for k in ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes")}


class Capture:
    """The outer packets the DUT sends, taken off the orchestrator's WAN NIC
    while a burst runs. The orchestrator is this machine, so tcpdump is a
    plain subprocess."""

    # Bytes kept per frame; 0 keeps whole frames. Headers-only checks set it
    # so a line-rate burst does not fill /tmp.
    snaplen = 0

    def __init__(self, r, name):
        self.path = ARTIFACTS / f"tunnel-{name}.pcap"
        self.filter = r.shape.capture_filter()
        self.interface = r.wan_if

    async def __aenter__(self):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.path.unlink(missing_ok=True)
        self.log = open(self.path.with_suffix(".log"), "wb")
        # -Z root: tcpdump otherwise drops to its own user before opening the
        # savefile, and the artifact directory is root's. --immediate-mode:
        # -U only flushes what tcpdump has read, and without it tcpdump reads
        # the kernel's ring a buffer timeout at a time, so a burst that ends
        # less than that before the stop below was received and never saved.
        self.proc = subprocess.Popen(
            ["tcpdump", "-i", self.interface, "--immediate-mode", "-U", "-Z", "root", "-s", str(self.snaplen),
             "-w", str(self.path), "-n", self.filter],
            stdout=subprocess.DEVNULL, stderr=self.log)
        # tcpdump takes a moment to attach; a burst that starts first is
        # partly missed, which would read as loss on the wire.
        await asyncio.sleep(1.5)
        assert self.proc.poll() is None, self.stderr()
        return self

    async def __aexit__(self, *exc):
        await asyncio.sleep(0.5)
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.log.close()

    def stderr(self):
        return self.path.with_suffix(".log").read_text(errors="replace")

    def packets(self):
        from scapy.all import rdpcap
        packets = rdpcap(str(self.path))
        assert packets, (f"tcpdump on {self.interface} with '{self.filter}' captured nothing: "
                         f"{self.stderr()!r}")
        return packets


def _assert_outer(r, packets, count, ttl=TTL):
    """Every captured outer header is the one the tunnel device would have
    built: the endpoints, the protocol, the TTL, and for IPv4 a correct
    checksum. The inner packet's hop count is one less than the LAN VM sent,
    which is the routing the hardware did on the way through. The outer IPv4
    header carries no DF: the insert opcode fills the fragment field itself,
    a limitation the legacy owner also had, so requiring its absence is what
    catches a future microcode that starts honouring the template.

    A 4o6 UDP upload is Linux's by design, so its outer packets are the
    kernel's own: ip6tnl adds a tunnel encapsulation limit option the insert
    opcode never builds, and for those the endpoints, the hop limit and the
    routed inner packet are what the two have in common."""
    from scapy.all import IP, IPv6, UDP, TCP
    shape = r.shape
    outer = [p for p in packets if (IP in p if shape.outer_family == 4 else IPv6 in p)]
    assert len(outer) >= count, (len(outer), count)
    for p in outer:
        if shape.outer_family == 4:
            o = p[IP]
            assert (o.src, o.dst, o.proto) == (shape.outer[0], shape.outer[1], 41), p.summary()
            assert o.ttl == ttl, (o.ttl, ttl)
            assert not o.flags.DF and o.frag == 0, p.summary()
            assert o.ihl == 5 and o.version == 4, p.summary()
            raw = bytes(o)[:20]
            assert IP(raw).chksum == o.chksum and _ip_checksum(raw) == 0, "outer checksum"
            inner = o.payload
            assert IPv6 in inner, p.summary()
            assert inner[IPv6].hlim == 63, inner[IPv6].hlim
        else:
            o = p[IPv6]
            inner = o.payload
            assert IP in inner, p.summary()
            linux = _upload_refused(shape, "tcp" if TCP in inner else "udp")
            assert (o.src, o.dst) == (shape.outer[0], shape.outer[1]), p.summary()
            assert linux or o.nh == 4, p.summary()
            assert o.hlim == ttl, (o.hlim, ttl)
            assert inner[IP].ttl == 63, inner[IP].ttl
        assert UDP in inner or TCP in inner, p.summary()


def _ip_checksum(header):
    total = sum(int.from_bytes(header[i:i + 2], "big") for i in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


OUTER_TABLE = "ask_tunnel_outer"


async def _outer_counter_add(r):
    """Count the tunnel's received outer packets where Linux would first see
    them: a netdev ingress chain on the WAN port, which a frame the hardware
    strips and forwards never reaches. The port's software receive total would
    also count the control channel and whatever else shares the segment."""
    dut, orch = r.shape.outer
    if r.shape.mode == "6o4":
        match = f"ip saddr {orch} ip daddr {dut} ip protocol 41"
    else:
        # l4proto looks past the destination options ip6tnl adds.
        match = f"ip6 saddr {orch} ip6 daddr {dut} meta l4proto 4"
    await command(r.target, r.session, "nft", "delete", "table", "netdev", OUTER_TABLE,
                  check=False)
    await command(r.target, r.session, "nft", f"""table netdev {OUTER_TABLE} {{
 chain ingress {{ type filter hook ingress device {TARGET_WAN_IF} priority 10; policy accept;
 {match} counter;
 }}
}}""")


async def _outer_counter(r):
    listing = json.loads((await command(r.target, r.session, "nft", "-j", "list", "table",
                                        "netdev", OUTER_TABLE))["stdout"])
    return sum(expr["counter"]["packets"] for item in listing["nftables"] if "rule" in item
               for expr in item["rule"]["expr"] if "counter" in expr)


async def _established(r, count=64, payload_size=64, name="routed"):
    """Install the flow, then measure a second burst against the hardware,
    the software receive counter of the WAN port, the tunnel device's own
    counters and the frames on the wire."""
    await _offload_table(r)
    flows = await _admit(r)
    installed = await r.state()
    before = {f["cookie"]: int(f["packets"]) for f in flows}
    record0 = _tunnel_record(r, installed)
    tun0 = await _tunnel_counters(r)
    await _outer_counter_add(r)
    try:
        sw0 = await _outer_counter(r)
        async with Capture(r, name) as capture:
            report = await _udp_exchange(r, count, payload_size)
        sw1 = await _outer_counter(r)
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "netdev", OUTER_TABLE,
                      check=False)
    tun1 = await _tunnel_counters(r)
    state = await r.state()
    after = {f["cookie"]: int(f["packets"]) for f in state["flows"]}
    assert_undisturbed(r, installed, state, set(before) == set(after), label="tunnel-readmitted")
    assert report == {"echoed": count, "lost": 0}, report
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == count for d in delta.values()), delta
    # The burst's outer packets Linux saw: the hardware stripped the rest
    # before any hook ran. A quarter of the burst is the allowance.
    software = sw1 - sw0
    assert software < count // 4, (software, count)
    tunnel = {k: tun1[k] - tun0[k] for k in tun0}
    record = {k: v - record0[k] for k, v in _tunnel_record(r, state).items()}
    r.record(f"tunnel-{name}", {"flows": flows, "delta": delta, "software_rx": software,
                                "tunnel": tunnel, "record": record, "report": report,
                                "tunnel_text": _tunnel_text(r.shape)})
    assert tunnel["rx"] >= count and tunnel["tx"] >= count, tunnel
    # The record counts what the hardware did: every download it stripped,
    # and every upload it inserted -- none, where the upload is Linux's, whose
    # sends the device counted itself above. The fold of inserted frames into
    # the device is test_flowtable_tunnel_tcp's to prove.
    inserted = 0 if _upload_refused(r.shape) else count
    assert (record["rx_packets"], record["tx_packets"]) == (count, inserted), record
    _assert_outer(r, capture.packets(), count)
    return flows, delta


# ---- topology ------------------------------------------------------------

async def _dut_tunnel(r, cleanup, ttl=TTL):
    shape = r.shape
    target = r.target
    local, remote = shape.outer
    if shape.mode == "6o4":
        await command(target, r.session, "modprobe", "sit")
        add = ["ip", "tunnel", "add", shape.device, "mode", "sit", "local", local,
               "remote", remote, "ttl", str(ttl)]
    else:
        await command(target, r.session, "modprobe", "ip6_tunnel")
        add = ["ip", "-6", "tunnel", "add", shape.device, "mode", "ipip6", "local", local,
               "remote", remote, "hoplimit", str(ttl)]
    await command(target, r.session, "ip", "link", "del", shape.device, check=False)
    await command(target, r.session, *add)
    cleanup.append((target, ["ip", "link", "del", shape.device]))
    await command(target, r.session, "ip", "link", "set", shape.device, "up", "mtu",
                  str(shape.mtu))
    prefix = "64" if shape.family == 6 else "24"
    await command(target, r.session, "ip", "addr", "add", f"{shape.inner_dut}/{prefix}",
                  "dev", shape.device, *(["nodad"] if shape.family == 6 else []))


async def _orchestrator_tunnel(r, cleanup):
    shape = r.shape
    wan = r.wan
    local, remote = shape.outer[1], shape.outer[0]
    if shape.mode == "6o4":
        await command(wan, r.session, "modprobe", "sit")
        add = ["ip", "tunnel", "add", shape.device, "mode", "sit", "local", local,
               "remote", remote, "ttl", str(TTL)]
    else:
        await command(wan, r.session, "modprobe", "ip6_tunnel")
        add = ["ip", "-6", "tunnel", "add", shape.device, "mode", "ipip6", "local", local,
               "remote", remote, "hoplimit", str(TTL)]
    await command(wan, r.session, "ip", "link", "del", shape.device, check=False)
    await command(wan, r.session, *add)
    cleanup.append((wan, ["ip", "link", "del", shape.device]))
    await command(wan, r.session, "ip", "link", "set", shape.device, "up", "mtu",
                  str(shape.mtu))
    prefix = "64" if shape.family == 6 else "24"
    await command(wan, r.session, "ip", "addr", "add", f"{shape.inner_orch}/{prefix}",
                  "dev", shape.device, *(["nodad"] if shape.family == 6 else []))
    # The way back to the LAN is through the tunnel and nothing else.
    host = f"{r.lan_address}/{128 if shape.family == 6 else 32}"
    await command(wan, r.session, "ip", "route", "replace", host, "dev", shape.device)
    cleanup.append((wan, ["ip", "route", "del", host, "dev", shape.device]))


async def _lan_side(r, cleanup, lan_cleanup):
    """The LAN VM's address and its route to the inner peer, and the DUT's
    LAN-facing address for the family the flow uses. Both neighbours are
    pinned so admission never races ARP or ND."""
    shape = r.shape
    target = r.target
    if shape.family == 6:
        await command(target, r.session, "ip", "-6", "addr", "del", f"{DUT_IPV6_LAN}/64",
                      "dev", TARGET_LAN_IF, check=False)
        await command(target, r.session, "ip", "-6", "addr", "add", f"{DUT_IPV6_LAN}/64",
                      "dev", TARGET_LAN_IF, "nodad")
        cleanup.append((target, ["ip", "-6", "addr", "del", f"{DUT_IPV6_LAN}/64",
                                 "dev", TARGET_LAN_IF]))
        await lan_run(r.lan, f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null; true")
        result = await lan_run(r.lan, f"ip -6 addr add {LAN_IPV6}/64 dev {LAN_NIC} nodad")
        assert result.rc == 0, result.stdout
        lan_cleanup.append(f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null; true")
        await lan_run(r.lan, f"ip -6 route replace {shape.inner_orch}/128 via {DUT_IPV6_LAN} "
                             f"dev {LAN_NIC}")
        lan_cleanup.append(f"ip -6 route del {shape.inner_orch}/128 dev {LAN_NIC} "
                           f"2>/dev/null; true")
        await lan_run(r.lan, f"ip -6 neigh replace {DUT_IPV6_LAN} lladdr {r.dut_lan_mac} "
                             f"nud permanent dev {LAN_NIC}")
        lan_cleanup.append(f"ip -6 neigh del {DUT_IPV6_LAN} dev {LAN_NIC} 2>/dev/null; true")
        r.lan_address = LAN_IPV6
        await command(target, r.session, "ip", "-6", "neigh", "replace", LAN_IPV6, "lladdr",
                      r.lan_mac, "nud", "permanent", "dev", TARGET_LAN_IF)
        cleanup.append((target, ["ip", "-6", "neigh", "del", LAN_IPV6, "dev", TARGET_LAN_IF]))
    else:
        addr = json.loads((await lan_run(r.lan, f"ip -j -4 addr show dev {LAN_NIC}")).stdout)
        r.lan_address = next(a["local"] for a in addr[0]["addr_info"] if a["family"] == "inet")
        await command(target, r.session, "ip", "neigh", "replace", r.lan_address, "lladdr",
                      r.lan_mac, "nud", "permanent", "dev", TARGET_LAN_IF)
        cleanup.append((target, ["ip", "neigh", "del", r.lan_address, "dev", TARGET_LAN_IF]))
        # The LAN VM reaches the inner peer through its default route, which
        # is the DUT; the DUT reaches it through the tunnel's own /24.


async def _outer_segment(r, cleanup):
    """The outer endpoints on the WAN segment, with their neighbours pinned
    on both sides. For 6o4 they are the addresses the segment already
    carries; for 4o6 they are two ULAs put there for the purpose."""
    shape = r.shape
    target, wan = r.target, r.wan
    dut_outer, orch_outer = shape.outer
    if shape.mode == "4o6":
        await command(target, r.session, "ip", "-6", "addr", "del", f"{dut_outer}/64",
                      "dev", TARGET_WAN_IF, check=False)
        await command(target, r.session, "ip", "-6", "addr", "add", f"{dut_outer}/64",
                      "dev", TARGET_WAN_IF, "nodad")
        cleanup.append((target, ["ip", "-6", "addr", "del", f"{dut_outer}/64",
                                 "dev", TARGET_WAN_IF]))
        await command(wan, r.session, "ip", "-6", "addr", "del", f"{orch_outer}/64",
                      "dev", r.wan_if, check=False)
        await command(wan, r.session, "ip", "-6", "addr", "add", f"{orch_outer}/64",
                      "dev", r.wan_if, "nodad")
        cleanup.append((wan, ["ip", "-6", "addr", "del", f"{orch_outer}/64", "dev", r.wan_if]))
        await command(wan, r.session, "ip", "-6", "neigh", "replace", dut_outer, "lladdr",
                      r.dut_wan_mac, "nud", "permanent", "dev", r.wan_if)
        cleanup.append((wan, ["ip", "-6", "neigh", "del", dut_outer, "dev", r.wan_if]))
        family = ["-6"]
    else:
        family = []
    old = json.loads((await command(target, r.session, "ip", "-j", *family, "neigh", "show",
                                    "to", orch_outer, "dev", TARGET_WAN_IF))["stdout"])
    restore = ["ip", *family, "neigh", "del", orch_outer, "dev", TARGET_WAN_IF]
    if old and old[0].get("lladdr"):
        state = "permanent" if "PERMANENT" in old[0]["state"] else "stale"
        restore = ["ip", *family, "neigh", "replace", orch_outer, "lladdr", old[0]["lladdr"],
                   "nud", state, "dev", TARGET_WAN_IF]
    await command(target, r.session, "ip", *family, "neigh", "replace", orch_outer, "lladdr",
                  r.wan_mac, "nud", "permanent", "dev", TARGET_WAN_IF)
    cleanup.append((target, restore))


async def _wait_reachable(r, attempts=25):
    """Prove the path across the tunnel before measuring anything on it."""
    shape = r.shape
    ping = "ping -6" if shape.family == 6 else "ping"
    for _ in range(attempts):
        probe = await lan_run(r.lan, f"{ping} -c 3 -W 2 -I {r.lan_address} {shape.inner_orch} "
                                     f">/dev/null 2>&1; echo rc=$?", 20.0)
        if "rc=0" in probe.stdout:
            return
        await asyncio.sleep(1.0)
    dut = await command(r.target, r.session, "ip", "-d", "addr", "show", shape.device,
                        check=False)
    route = await command(r.target, r.session, "ip", "route", "get", shape.inner_orch,
                          check=False)
    orch = await command(r.wan, r.session, "ip", "-d", "addr", "show", shape.device,
                         check=False)
    lan_route = await lan_run(r.lan, f"ip route get {shape.inner_orch} 2>&1", 10.0)
    pytest.fail(f"the LAN VM could not reach {shape.inner_orch} across the tunnel after "
                f"{attempts} attempts: {probe.stdout!r}\n"
                f"  DUT {shape.device}:  {dut.get('stdout', dut)!r}\n"
                f"  DUT route:      {route.get('stdout', route)!r}\n"
                f"  orch {shape.device}: {orch.get('stdout', orch)!r}\n"
                f"  LAN route:      {lan_route.stdout!r}")


async def _clear_ct(r, proto="udp"):
    shape = r.shape
    await command(r.target, r.session, "conntrack", "-D", "-p", proto,
                  "--orig-src", r.lan_address, "--orig-dst", shape.inner_orch,
                  "--sport", str(shape.sport), "--dport", str(shape.dport), check=False)


class EchoServer(asyncio.DatagramProtocol):
    def __init__(self):
        self.packets = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.packets += 1
        self.transport.sendto(data, addr)


@pytest_asyncio.fixture
async def tunnel_rig(target_agent, aiohttp_session, lan, splat_window, request):
    """LAN VM -> DUT -> tunnel -> orchestrator, in the mode the parameter
    names: "6o4" or "4o6", optionally suffixed with the case's port pair
    ("6o4/mtu"). Teardown reverses only what came up."""
    param = getattr(request, "param", "6o4")
    mode, _, case = param.partition("/")
    assert mode in {"6o4", "4o6"}, param
    sport, dport = PORTS[case or "routed"]
    r = TunnelRig()
    r.shape = Shape(mode, sport, dport)
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    await ft.stop_boot_daemon()
    initial = await r.state()
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    ft.HEALTH_BASELINE["errors"] = initial["errors"]
    r.wan = Agent("wan", f"http://{ORCH_IPV4}:9110")
    cleanup, lan_cleanup = [], []
    transport = None
    try:
        await command(r.target, r.session, "modprobe", "xt_tcpudp")
        link = json.loads((await lan_run(lan, f"ip -j link show dev {LAN_NIC}")).stdout)[0]
        r.lan_mac = link["address"]
        r.dut_lan_mac = (await read(r.target, r.session,
                                    f"/sys/class/net/{TARGET_LAN_IF}/address")).strip()
        r.dut_wan_mac = (await read(r.target, r.session,
                                    f"/sys/class/net/{TARGET_WAN_IF}/address")).strip()
        addresses = json.loads((await command(r.wan, r.session, "ip", "-j", "-4", "addr"))["stdout"])
        r.wan_if = next(i["ifname"] for i in addresses
                        if any(a.get("local") == ORCH_IPV4 for a in i["addr_info"]))
        r.wan_mac = json.loads((await command(r.wan, r.session, "ip", "-j", "link", "show",
                                              "dev", r.wan_if))["stdout"])[0]["address"]
        for key in ("net.ipv6.conf.all.forwarding", "net.ipv4.ip_forward"):
            previous = (await command(r.target, r.session, "sysctl", "-n", key))["stdout"].strip()
            cleanup.append((r.target, ["sysctl", "-w", f"{key}={previous}"]))
            await command(r.target, r.session, "sysctl", "-w", f"{key}=1")
        if r.shape.family == 6:
            # An IPv6 direction into a smaller path is only offloaded while
            # the LAN tells its hosts that path's MTU: the microcode would
            # fragment anything larger instead of letting Linux send its
            # Packet Too Big. This is the configuration a 6in4 LAN needs.
            key = f"net.ipv6.conf.{TARGET_LAN_IF}.mtu"
            previous = (await command(r.target, r.session, "sysctl", "-n", key))["stdout"].strip()
            cleanup.append((r.target, ["sysctl", "-w", f"{key}={previous}"]))
            await command(r.target, r.session, "sysctl", "-w", f"{key}={r.shape.mtu}")
        await _lan_side(r, cleanup, lan_cleanup)
        await _outer_segment(r, cleanup)
        await _dut_tunnel(r, cleanup)
        await _orchestrator_tunnel(r, cleanup)
        # Without this the image's own masquerade rule would translate the
        # routed case and it would silently stop being a routed case.
        if r.shape.family == 4:
            accept = ["POSTROUTING", "-s", r.lan_address, "-d", r.shape.inner_orch,
                      "-p", "udp", "--sport", str(sport), "--dport", str(dport), "-j", "ACCEPT"]
            await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept)
            cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *accept]))
            accept_tcp = accept[:]
            accept_tcp[accept.index("udp")] = "tcp"
            await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept_tcp)
            cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *accept_tcp]))
        old_acct = (await read(r.target, r.session,
                               "/proc/sys/net/netfilter/nf_conntrack_acct")).strip()
        await command(r.target, r.session, "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
        cleanup.append((r.target, ["sysctl", "-w",
                                   f"net.netfilter.nf_conntrack_acct={old_acct}"]))
        await _wait_reachable(r)
        await _clear_ct(r)
        transport, r.echo = await asyncio.get_running_loop().create_datagram_endpoint(
            EchoServer, local_addr=(r.shape.inner_orch, dport),
            family=socket.AF_INET6 if r.shape.family == 6 else socket.AF_INET)
        r.record("tunnel-fixture", {"mode": mode, "case": case, "lan": r.lan_address,
                                    "inner": r.shape.inner_orch, "outer": r.shape.outer,
                                    "device": r.shape.device, "initial": initial,
                                    "expected_row": _tunnel_text(r.shape)})
        yield r
    finally:
        if transport:
            transport.close()
        failures = []
        for step in (r.delete_table, lambda: _clear_ct(r), lambda: _clear_ct(r, "tcp")):
            try:
                await step()
            except Exception as error:
                failures.append(str(error))
        for agent, argv in reversed(cleanup):
            result = await command(agent, r.session, *argv, check=False)
            if result["rc"] and "Cannot find device" not in (result.get("stderr") or ""):
                failures.append(result)
        for cmd in reversed(lan_cleanup):
            await lan_run(r.lan, cmd)
        assert not failures, failures


# ---- cases ---------------------------------------------------------------

@pytest.mark.parametrize("tunnel_rig", ["6o4", "4o6"], indirect=True)
async def test_flowtable_tunnel_routed(tunnel_rig):
    """A routed UDP flow through the tunnel.

    The forward direction inserts the outer header and the reverse strips it;
    the adapter names the tunnel on exactly those two and on neither LAN half.
    The frames the DUT put on the wire carry the header the kernel would have
    built, and the tunnel device's counters moved by the burst although no
    packet of its hardware directions reached the CPU. A 4o6 upload is
    Linux's (see the module docstring), so there the strip is what is proved
    and the insert is test_flowtable_tunnel_tcp's.
    """
    r = tunnel_rig
    flows, delta = await _established(r)
    forward, reverse = _directions(r, flows)
    _assert_tunnel(r, forward, reverse)
    assert reverse["out_vlan"] == reverse["out_ppp"] == "-", reverse
    if forward:
        assert forward["in_vlan"] == forward["in_ppp"] == "-", forward
    assert all(d == 64 for d in delta.values()), delta


@pytest.mark.parametrize("tunnel_rig", ["6o4/mtu", "4o6/mtu"], indirect=True)
async def test_flowtable_tunnel_full_mtu(tunnel_rig):
    """A datagram that fills the tunnel's MTU is still carried in hardware.

    The microcode compares what it transmits against the programmed MTU, and
    what it transmits is the outer packet; a direction programmed with the
    tunnel-reduced inner MTU excepts every full-size frame to the CPU while
    every counter says the flow is offloaded. The payload here is exactly the
    inner MTU less its own headers. For 4o6 only the strip carries it in
    hardware; the full-size insert is proved by test_flowtable_tunnel_tcp,
    whose segments fill the tunnel.
    """
    r = tunnel_rig
    payload = r.shape.mtu - (40 if r.shape.family == 6 else 20) - 8
    flows, delta = await _established(r, count=32, payload_size=payload, name="mtu")
    forward, reverse = _directions(r, flows)
    _assert_tunnel(r, forward, reverse)
    assert all(d == 32 for d in delta.values()), delta


@pytest.mark.parametrize("tunnel_rig", ["6o4/tcp", "4o6/tcp"], indirect=True)
async def test_flowtable_tunnel_tcp(tunnel_rig):
    """An established TCP connection through the tunnel.

    TCP is a classifier table of its own, so a UDP proof says nothing about
    it; and the classifier punts SYN, FIN and RST before its own lookup, so
    what the hardware carries is the bulk transfer in the middle. The cookies
    staying put proves the connection was never readmitted underneath it.

    It is also the large-segment insert. The far end advertises the MSS its
    tunnel allows, so every full data segment of the upload comes within its
    TCP options of the tunnel's MTU; a size check that counted the outer
    header against that MTU would except each one to Linux, which would then
    send it out of the WAN port itself. For 4o6 this is the only hardware
    insert there is, the UDP upload being Linux's.
    """
    r = tunnel_rig
    shape = r.shape
    await _offload_table(r, "tcp")

    async def run(script, **kwargs):
        return await lan_run_python(r.lan, script, **kwargs)

    # Read while the connection is open and idle (see _gated_tcp): a FIN
    # retires the entries within about a second of the peer closing.
    async with GatedTcp(run, source=r.lan_address, sport=shape.sport, peer=shape.inner_orch,
                        dport=shape.dport, label="flowtable_tunnel_tcp") as transfer:
        await transfer.warmed()
        # Admission is asynchronous (rtnl_trylock, deferred a second or two
        # under RTNL contention), so warmed()'s brief settle can miss a late
        # direction; wait admission in before reading the baseline the record
        # and the direction check share.
        before = await r.wait(lambda s: len(s["flows"]) == _expected(r, "tcp"))
        flows = await _both_directions(r, "tcp", before)
        record = _tunnel_record(r, before)
        link = await _tunnel_counters(r)
        sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF)
        await transfer.measure()
        sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF) - sent
        after = await r.state()
        record = {k: v - record[k] for k, v in _tunnel_record(r, after).items()}
        link = {k: v - link[k] for k, v in (await _tunnel_counters(r)).items()}
    forward, reverse = _directions(r, flows)
    r.record("tunnel-tcp", {"flows": flows, "after": after, "record": record, "link": link,
                            "software_wan_tx": sent, "report": transfer.report})
    _assert_tunnel(r, forward, reverse)
    assert forward["proto"] == reverse["proto"] == "6", flows
    new = {f["cookie"]: f for f in after["flows"]}
    assert_undisturbed(r, before, after, new.keys() == {forward["cookie"], reverse["cookie"]}
                       and (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]),
                       label="tunnel-readmitted")
    upload = int(new[forward["cookie"]]["packets"]) - int(forward["packets"])
    download = int(new[reverse["cookie"]]["packets"]) - int(reverse["packets"])
    assert upload > 100 and download > 100, (upload, download)
    # The tunnel device's record counts the same frames the two entries did:
    # the insert's the upload's, the strip's the download's.
    assert (record["tx_packets"], record["rx_packets"]) == (upload, download), (record, upload, download)
    # And `ip -s link` on the device moved by the record restated into the
    # inner packets it counts itself -- the Ethernet and outer headers off what
    # the insert counted, the Ethernet header off what the strip did -- which
    # is the transmit fold of inserted frames that a UDP upload in Linux cannot
    # show, plus at most a few frames the device sent or took itself.
    for half, overhead in (("tx", 14 + shape.header), ("rx", 14)):
        stray = link[half] - record[half + "_packets"]
        assert 0 <= stray <= 8, (half, record, link)
        inner = record[half + "_bytes"] - overhead * record[half + "_packets"]
        assert inner <= link[half + "_bytes"] <= inner + stray * 1518, (half, record, link)
    # Only the handful of frames the reads above cost left the WAN port in
    # software while the measured phase crossed it.
    assert 0 <= sent < upload // 4, (sent, upload)


@pytest.mark.parametrize("tunnel_rig", ["6o4/change"], indirect=True)
async def test_flowtable_tunnel_change_retires(tunnel_rig):
    """Reconfiguring the tunnel under a live flow retires it, and the flow
    readmitted afterwards carries the new outer header.

    `ip tunnel change` rewrites the device's parameters in place and raises
    only NETDEV_CHANGE, on a device that is always running with carrier. A
    flow admitted against the old parameters would otherwise keep sending the
    old header from hardware while software sent the new one. The TTL is what
    changes here because it is visible on the wire.
    """
    r = tunnel_rig
    flows, _ = await _established(r)
    before = await r.state()
    await command(r.target, r.session, "ip", "tunnel", "change", r.shape.device,
                  "ttl", str(CHANGED_TTL))
    retired = await r.wait(lambda s: s["entries"] == 0)
    assert retired["bindings"] == 2, retired
    assert retired["link_invalidations"] > before["link_invalidations"], (before, retired)
    # Readmitted against the new configuration, and the wire says so.
    flows = await _admit(r)
    forward, reverse = _directions(r, flows)
    _assert_tunnel(r, forward, reverse)
    async with Capture(r, "change") as capture:
        report = await _udp_exchange(r, 32)
    assert report == {"echoed": 32, "lost": 0}, report
    _assert_outer(r, capture.packets(), 32, ttl=CHANGED_TTL)
    r.record("tunnel-change", {"before": before, "retired": retired, "flows": flows})


@pytest.mark.parametrize("tunnel_rig", ["6o4/delete"], indirect=True)
async def test_flowtable_tunnel_delete_retires(tunnel_rig):
    """Deleting the tunnel device retires both directions and leaves the
    bindings up: the ports are untouched, admission stays open, and the next
    flow is judged against whatever tunnel exists then."""
    r = tunnel_rig
    flows, _ = await _established(r)
    assert len(flows) == 2
    before = await r.state()
    await command(r.target, r.session, "ip", "link", "del", r.shape.device)
    retired = await r.wait(lambda s: s["entries"] == 0)
    assert retired["bindings"] == 2 and retired["invalidated"] == 0, retired
    assert retired["rearms"] == before["rearms"], (before, retired)
    r.record("tunnel-delete", {"before": before, "retired": retired})

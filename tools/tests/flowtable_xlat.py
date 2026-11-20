"""NAT64 sessions offered to the adapter by a translation client.

ask_xlat_test.ko stands in for a translator (docs/flowtable/nat64.md, "Test
client"): it offers sessions described by hand through ask_xlat.h, and the
adapter finds their routes, neighbours, ports and MTU itself. Only the meta-ask
image builds it; elsewhere every case skips.

The sessions are TCP. With both ports at 1500 bytes a UDP session is refused by
design: an IPv4 port's full-size packet is 1520 bytes as IPv6.

Two shapes, both through the DUT's own WAN address as the pool, so the WAN host
reaches the IPv4 side of a session without a route of its own:

- the hairpin: the WAN host is both ends. Its IPv6 address talks to its IPv4
  one mapped into 64:ff9b::/96, and both directions leave and arrive on the WAN
  port;
- LAN to WAN: the LAN VM's IPv6 address talks to the WAN host's IPv4 one, the
  upload from the LAN port into the WAN port and the download back.

Probes are TCP segments built by hand, never a connection: the hardware
translates whatever matches the session's tuple. The WAN host drops the probes
it receives before its own TCP stack answers them, so nothing but a case's own
frames hits an entry. Every frame is checked from its raw bytes.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
import struct
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass

import pytest
import pytest_asyncio

from _flowtable_rig import WAN_IP, command, read
from _topology import (DUT_IPV6_LAN, LAN_IPV6, LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, WAN_IPV6,
                       lan_run, lan_run_python)
from ask_orch.artifacts import artifact_dir
from ask_orch.counters import kernel_rx_packets
from ask_orch.lifecycle import CleanupStack, checked

MODULE = "ask_xlat_test"
SESSION = f"/sys/module/{MODULE}/parameters/session"
ASK_DEBUG = "/sys/module/cdx/parameters/ask_debug"
STATS_MS = "/sys/module/ask_flowtable/parameters/stats_ms"
# The refusal bit of cdx's ask_debug mask (cdx_flowtable_backend.h).
ASK_DBG_REFUSE = 0x1
# What the counter pass runs at for translated sessions when stats_ms is 0
# (FT_STATS_XLAT_MS).
XLAT_STATS_MS = 1000
NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
# A table on the WAN host dropping, before its TCP stack, every probe that
# reaches it: an unsolicited segment would otherwise draw a reset, which the
# session's other direction would carry.
PROBE_TABLE = "ask_xlat_probe"
LAN_ROUTE = f"{NAT64_PREFIX} via {DUT_IPV6_LAN} dev {LAN_NIC}"
# Set by the LAN VM's capture once it is receiving; named for what it is.
LAN_CAPTURE_READY = "/tmp/ask_xlat_lan_capture_ready"
# The TOS or traffic class each wire probe carries: none, EF, and EF with ECN
# CE, which the translation has to keep.
TOS = (0x00, 0xb8, 0xbb)
# The load through the LAN-to-WAN upload: a few hundred thousand frames over
# about two seconds.
LOAD_FRAMES = 300_000
LOAD_RATE = 150_000


@dataclass(frozen=True)
class Session:
    """One translated session as the client's `session` line describes it: the
    IPv6 client, the IPv4 server, and the pool address and port the client is
    translated to. Its first direction is the client's upload, arriving on
    `ingress`; the second its inverse."""
    cookie: int
    ingress: str
    client: str
    client_port: int
    server: str
    server_port: int
    pool: str
    pool_port: int

    @property
    def mapped(self) -> str:
        """The server's IPv4 address in the NAT64 prefix (RFC 6052)."""
        return str(ipaddress.IPv6Address(int(NAT64_PREFIX.network_address)
                                         | int(ipaddress.IPv4Address(self.server))))

    def line(self) -> str:
        return (f"in={self.ingress} proto=tcp src={self.client} dst={self.mapped} "
                f"sport={self.client_port} dport={self.server_port} nsrc={self.pool} "
                f"ndst={self.server} nsport={self.pool_port} ndport={self.server_port} "
                f"tos=copy cookie={self.cookie}")


def _fold(data: bytes) -> int:
    """The one's-complement sum of `data` as 16-bit words."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total


@dataclass
class Segment:
    """A TCP segment as it was on the wire, read from the frame's own bytes."""
    eth_src: str
    eth_dst: str
    family: int
    src: str
    dst: str
    hops: int
    tos: int
    df: bool
    header_ok: bool
    sport: int
    dport: int
    l4_ok: bool
    payload: bytes


def parse(frame: bytes) -> Segment | None:
    """An untagged IPv4 or IPv6 TCP segment, or None. Lengths come from the IP
    header, so the bytes a translated frame carries past it are no part of the
    segment."""
    ethertype = struct.unpack("!H", frame[12:14])[0]
    ip = frame[14:]
    if ethertype == 0x0800 and len(ip) >= 20 and ip[9] == 6:
        ihl = (ip[0] & 0x0f) * 4
        segment = ip[ihl:struct.unpack("!H", ip[2:4])[0]]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(segment))
        family, src, dst = 4, ipaddress.IPv4Address(ip[12:16]), ipaddress.IPv4Address(ip[16:20])
        hops, tos = ip[8], ip[1]
        df = bool(struct.unpack("!H", ip[6:8])[0] & 0x4000)
        header_ok = _fold(ip[:ihl]) == 0xffff
    elif ethertype == 0x86dd and len(ip) >= 40 and ip[6] == 6:
        segment = ip[40:40 + struct.unpack("!H", ip[4:6])[0]]
        pseudo = ip[8:40] + struct.pack("!I3xB", len(segment), 6)
        family, src, dst = 6, ipaddress.IPv6Address(ip[8:24]), ipaddress.IPv6Address(ip[24:40])
        hops, tos = ip[7], ((ip[0] & 0x0f) << 4) | (ip[1] >> 4)
        df, header_ok = False, True
    else:
        return None
    if len(segment) < 20:
        return None
    sport, dport = struct.unpack("!HH", segment[:4])
    return Segment(eth_src=frame[6:12].hex(":"), eth_dst=frame[0:6].hex(":"), family=family,
                   src=str(src), dst=str(dst), hops=hops, tos=tos, df=df, header_ok=header_ok,
                   sport=sport, dport=dport, l4_ok=_fold(pseudo + segment) == 0xffff,
                   payload=segment[(segment[12] >> 4) * 4:])


def endpoint(text: str):
    host, _, port = text.rpartition(":")
    return ipaddress.ip_address(host.strip("[]")), int(port)


class Xlat:
    """The client and the adapter's view of what it offered."""

    def __init__(self, r):
        self.r = r
        self.payloads = 0

    async def target(self, *argv, check=True):
        return await command(self.r.target, self.r.session, *argv, check=check)

    async def write(self, line: str) -> int:
        """Hand the client a line; the errno it answered with."""
        return (await self.r.target.fs_write(self.r.session, SESSION, line))["errno"]

    async def offer(self, session: Session):
        errno = await self.write(session.line())
        assert errno == 0, ("the client's offer was refused at the door", errno, session)

    async def client(self) -> dict:
        """The client's listing: each session still owed an answer, by cookie,
        and the totals."""
        listing = {"sessions": {}}
        for line in (await read(self.r.target, self.r.session, SESSION)).splitlines():
            kind, _, rest = line.partition(" ")
            fields = {k: int(v) for k, v in (item.split("=", 1) for item in rest.split())}
            if kind == "session":
                listing["sessions"][fields["cookie"]] = fields
            elif kind == "total":
                listing.update(fields)
        return listing

    async def state(self):
        return await self.r.state()

    @staticmethod
    def rows(state, session: Session) -> dict:
        """The session's flows rows by the family each direction arrives in;
        `cookie=` is the client's cookie, in hex."""
        rows = [f for f in state["flows"] if f.get("cookie") == f"{session.cookie:x}"]
        return {int(f["family"]): f for f in rows}

    async def installed(self, session: Session, timeout=10):
        """Offer the session and wait for both its directions."""
        await self.offer(session)
        return await self.r.wait(lambda s: len(self.rows(s, session)) == 2, timeout=timeout)

    async def expired(self, base: int, timeout=10) -> dict:
        """Wait for exactly one `expired` beyond `base`, and see no second
        follow within a counter pass."""
        deadline = time.monotonic() + timeout
        while (listing := await self.client())["expired"] <= base:
            assert time.monotonic() < deadline, ("no expired said", base, listing)
            await asyncio.sleep(0.1)
        await asyncio.sleep(XLAT_STATS_MS / 1000)
        listing = await self.client()
        assert listing["expired"] == base + 1, ("expired said other than once", base, listing)
        return listing

    async def gone(self, session: Session, timeout=10):
        return await self.r.wait(lambda s: not self.rows(s, session) and not s["xlat_entries"],
                                 timeout=timeout)

    def payload(self, label: str) -> bytes:
        """A payload naming the probe it is, unlike any other this run sends."""
        self.payloads += 1
        return f"ASK-xlat-{label}-{self.payloads:04d}-{secrets.token_hex(6)}".encode()

    def hairpin(self) -> Session:
        return Session(cookie=_cookie(), ingress=TARGET_WAN_IF, client=WAN_IPV6, client_port=46611,
                       server=WAN_IP, server_port=46612, pool=self.pool, pool_port=46613)

    def lan(self) -> Session:
        return Session(cookie=_cookie(), ingress=TARGET_LAN_IF, client=LAN_IPV6, client_port=46621,
                       server=WAN_IP, server_port=46622, pool=self.pool, pool_port=46623)

    def upload(self, session: Session, tos: int, payload: bytes, *, eth_src, eth_dst):
        """The client's IPv6 segment to the mapped server."""
        from scapy.all import IPv6, TCP, Ether, Raw
        return (Ether(src=eth_src, dst=eth_dst)
                / IPv6(src=session.client, dst=session.mapped, hlim=64, tc=tos)
                / TCP(sport=session.client_port, dport=session.server_port, flags="PA",
                      seq=1000, ack=1) / Raw(payload))

    def download(self, session: Session, tos: int, payload: bytes):
        """The server's IPv4 segment to the pool, from the WAN host."""
        from scapy.all import IP, TCP, Ether, Raw
        r = self.r
        return (Ether(src=r.wan_mac, dst=r.dut_wan_mac)
                / IP(src=session.server, dst=session.pool, ttl=64, tos=tos, flags="DF")
                / TCP(sport=session.server_port, dport=session.pool_port, flags="PA",
                      seq=1000, ack=1) / Raw(payload))

    async def send(self, frames):
        from scapy.all import sendp
        await asyncio.to_thread(sendp, frames, iface=self.r.wan_if, verbose=False, inter=0.02)

    @asynccontextmanager
    async def capture(self, label: str):
        """Every TCP frame the DUT sends the WAN host meanwhile, as bytes,
        once the block ends; also kept as a pcap artifact."""
        from scapy.all import AsyncSniffer, wrpcap
        ready = threading.Event()
        sniffer = AsyncSniffer(iface=self.r.wan_if, store=True, started_callback=ready.set,
                               filter=f"ether src {self.r.dut_wan_mac} and tcp")
        sniffer.start()
        frames: list[bytes] = []
        try:
            assert await asyncio.to_thread(ready.wait, 5), "the WAN host's capture did not start"
            yield frames
            # What is still on its way when the last probe has gone.
            await asyncio.sleep(0.5)
        finally:
            packets = sniffer.stop() or []
            artifact_dir().mkdir(parents=True, exist_ok=True)
            wrpcap(str(artifact_dir() / f"{label}.pcap"), packets)
            frames.extend(bytes(p) for p in packets)


def _cookie() -> int:
    """A session cookie no earlier case or boot used, so a trace line or a
    callback can only be this case's."""
    return secrets.randbelow(10 ** 12) + 1


def translated(frames, payload: bytes) -> list[Segment]:
    return [s for s in map(parse, frames) if s is not None and s.payload == payload]


def assert_upload(segment: Segment, session: Session, tos: int, r, label: str):
    """The client's IPv6 segment as the server receives it: IPv4 from the pool,
    one hop less, DF set, the TOS copied whole, both checksums right."""
    expected = {"family": 4, "src": session.pool, "dst": session.server,
                "sport": session.pool_port, "dport": session.server_port,
                "hops": 63, "tos": tos, "df": True, "header_ok": True, "l4_ok": True,
                "eth_src": r.dut_wan_mac, "eth_dst": r.wan_mac}
    found = {k: getattr(segment, k) for k in expected}
    assert found == expected, (label, found, expected)


def assert_download(segment: Segment, session: Session, tos: int, label: str, *,
                    eth_src: str, eth_dst: str):
    """The server's IPv4 segment as the client receives it: IPv6 from the
    mapped server, one hop less, the traffic class copied whole, the checksum
    right."""
    expected = {"family": 6, "src": session.mapped, "dst": session.client,
                "sport": session.server_port, "dport": session.client_port,
                "hops": 63, "tos": tos, "l4_ok": True, "eth_src": eth_src, "eth_dst": eth_dst}
    found = {k: getattr(segment, k) for k in expected}
    assert found == expected, (label, found, expected)


@pytest_asyncio.fixture
async def xlat_client(target_agent, aiohttp_session):
    """Skip unless this image built the client: only meta-ask does."""
    release = (await read(target_agent, aiohttp_session, "/proc/sys/kernel/osrelease")).strip()
    modules = await target_agent.fs_read(aiohttp_session, f"/lib/modules/{release}/modules.dep")
    if modules["errno"] or not any(
            line.split(":", 1)[0].endswith(f"/{MODULE}.ko")
            for line in bytes.fromhex(modules["content_hex"]).decode().splitlines()):
        pytest.skip(f"{MODULE}.ko is built only for the meta-ask test image")


@pytest_asyncio.fixture
async def xlat(xlat_client, ipv6_rig):
    """The client loaded over ipv6_rig's addresses, with what both shapes need:
    the WAN host's IPv4 address as a neighbour on the WAN port, a host route to
    its IPv6 one a case can take away, the LAN VM's route to the NAT64 prefix,
    and the WAN host's probe drop. Every one goes again, the client last
    withdrawing what it still offers and unloading, which drains the adapter."""
    r = ipv6_rig
    x = Xlat(r)
    cleanup = CleanupStack()
    try:
        assert WAN_IP, "the hairpin needs the WAN host's IPv4 address (ASK_WAN_IPERF_IP)"
        dut = json.loads((await x.target("ip", "-j", "-4", "addr", "show", "dev",
                                         TARGET_WAN_IF))["stdout"])[0]
        x.pool = next(a["local"] for a in dut["addr_info"] if a["family"] == "inet")

        old = json.loads((await x.target("ip", "-j", "neigh", "show", "to", WAN_IP, "dev",
                                         TARGET_WAN_IF))["stdout"])

        async def restore_neighbour(old=old):
            # A case may have deleted it, and the kernel learned it again or
            # not: only the state the case found is put back.
            if old and old[0].get("lladdr"):
                state = "permanent" if "PERMANENT" in old[0]["state"] else "stale"
                return await x.target("ip", "neigh", "replace", WAN_IP, "lladdr",
                                      old[0]["lladdr"], "nud", state, "dev", TARGET_WAN_IF)
            await x.target("ip", "neigh", "del", WAN_IP, "dev", TARGET_WAN_IF, check=False)
        cleanup.push(restore_neighbour)
        await x.target("ip", "neigh", "replace", WAN_IP, "lladdr", r.wan_mac, "nud", "permanent",
                       "dev", TARGET_WAN_IF)

        # Host routes to both of the WAN host's addresses, so each direction's
        # next hop is the WAN host itself whatever subnet the port is on.
        for family, host in (("-4", f"{WAN_IP}/32"), ("-6", f"{WAN_IPV6}/128")):
            routes = json.loads((await x.target("ip", "-j", family, "route", "show", "exact",
                                                host))["stdout"])
            assert not routes, ("the fixture owns the WAN host's host routes", routes)
            cleanup.push(lambda f=family, h=host: x.target("ip", f, "route", "del", h, "dev",
                                                           TARGET_WAN_IF, check=False))
            await x.target("ip", family, "route", "add", host, "dev", TARGET_WAN_IF)

        cleanup.push(lambda: lan_run(r.lan, f"ip -6 route del {LAN_ROUTE}", 5))
        checked(await lan_run(r.lan, f"ip -6 route replace {LAN_ROUTE}", 5))

        await command(r.wan, r.session, "nft", "delete", "table", "inet", PROBE_TABLE, check=False)
        cleanup.push(lambda: command(r.wan, r.session, "nft", "delete", "table", "inet",
                                     PROBE_TABLE))
        ports = ", ".join(str(p) for p in sorted({x.hairpin().client_port,
                                                  x.hairpin().server_port,
                                                  x.lan().server_port}))
        await command(r.wan, r.session, "nft", f"""table inet {PROBE_TABLE} {{
 chain prerouting {{ type filter hook prerouting priority -300; policy accept;
  meta l4proto tcp th dport {{ {ports} }} drop
 }}
}}""")

        # A client a killed run left loaded goes first, with what it offered.
        if not (await r.target.fs_read(r.session, f"/sys/module/{MODULE}/refcnt"))["errno"]:
            await x.target("rmmod", MODULE)
        x.baseline = await x.state()
        assert not x.baseline["xlat_entries"] and not x.baseline["xlat_registered"], x.baseline

        async def unload():
            if (await r.target.fs_read(r.session, f"/sys/module/{MODULE}/refcnt"))["errno"]:
                return None
            listing = await x.client()
            assert not listing["unknown"], ("callbacks named cookies never offered", listing)
            await x.write("flush")
            await x.target("rmmod", MODULE)
            state = await r.wait(lambda s: not s["xlat_registered"] and not s["xlat_entries"])
            assert state["entries"] == x.baseline["entries"], (x.baseline, state)
            assert state["fatal"] == x.baseline["fatal"], (x.baseline, state)
            return None
        cleanup.push(unload)
        await x.target("modprobe", MODULE)
        assert (await x.state())["xlat_registered"] == 1
        x.stats_ms = int((await read(r.target, r.session, STATS_MS)).strip()) or XLAT_STATS_MS
        r.record("xlat-fixture", {"pool": x.pool, "wan4": WAN_IP, "wan6": WAN_IPV6,
                                  "lan6": LAN_IPV6, "stats_ms": x.stats_ms,
                                  "baseline": {k: x.baseline[k] for k in
                                               ("entries", "fatal", "xlat_entries")}})
        yield x
    finally:
        await cleanup.teardown("xlat fixture")


async def test_refused_without_a_neighbour(xlat):
    """An offer whose upload has no neighbour to send to is refused with one
    `expired`, nothing installed, and the reason in the refusal trace."""
    x, r = xlat, xlat.r
    session = x.hairpin()
    debug = int((await read(r.target, r.session, ASK_DEBUG)).strip(), 0)
    try:
        assert not (await r.target.fs_write(r.session, ASK_DEBUG,
                                            str(debug | ASK_DBG_REFUSE)))["errno"]
        await x.target("ip", "neigh", "del", WAN_IP, "dev", TARGET_WAN_IF)
        before, stats = await x.client(), await x.state()
        await x.offer(session)
        listing = await x.expired(before["expired"])
        state = await x.state()
        assert not x.rows(state, session) and not state["xlat_entries"], state
        assert state["xlat_refused"] == stats["xlat_refused"] + 1, (stats, state)
        assert state["xlat_installs"] == stats["xlat_installs"], (stats, state)
        assert session.cookie not in listing["sessions"], listing
        log = (await x.target("dmesg"))["stdout"]
        reason = (f"ASK-DEBUG: xlat cookie={session.cookie} dir=0 neigh {WAN_IP} "
                  f"on {TARGET_WAN_IF} unresolved")
        assert reason in log, ("no refusal reason traced", reason,
                               [line for line in log.splitlines() if "xlat" in line][-10:])
    finally:
        assert not (await r.target.fs_write(r.session, ASK_DEBUG, str(debug)))["errno"]


async def test_installed_rows(xlat):
    """Both directions installed, each row carrying the client's cookie (in
    hex), its translated family and `tos=copy`."""
    x = xlat
    session = x.hairpin()
    before, answered = await x.state(), (await x.client())["expired"]
    state = await x.installed(session)
    rows = x.rows(state, session)
    assert set(rows) == {4, 6}, rows
    up, down = rows[6], rows[4]
    for row in (up, down):
        assert row["cookie"] == f"{session.cookie:x}" and row["tos"] == "copy", row
        assert row["in"] == row["out"] == TARGET_WAN_IF and row["proto"] == "6", row
    assert up["xlat"] == "4" and down["xlat"] == "6", rows
    client, mapped = ipaddress.ip_address(session.client), ipaddress.ip_address(session.mapped)
    server, pool = ipaddress.ip_address(session.server), ipaddress.ip_address(session.pool)
    assert endpoint(up["src"]) == (client, session.client_port), up
    assert endpoint(up["dst"]) == (mapped, session.server_port), up
    assert endpoint(up["new_src"]) == (pool, session.pool_port), up
    assert endpoint(up["new_dst"]) == (server, session.server_port), up
    assert ipaddress.ip_address(up["nexthop"]) == server, up
    assert endpoint(down["src"]) == (server, session.server_port), down
    assert endpoint(down["dst"]) == (pool, session.pool_port), down
    assert endpoint(down["new_src"]) == (mapped, session.server_port), down
    assert endpoint(down["new_dst"]) == (client, session.client_port), down
    assert ipaddress.ip_address(down["nexthop"]) == client, down
    assert state["xlat_sessions"] == 1 and state["xlat_entries"] == 2, state
    assert state["xlat_installs"] == before["xlat_installs"] + 1, (before, state)
    listing = await x.client()
    assert session.cookie in listing["sessions"] and listing["expired"] == answered, listing


async def test_hairpin_wire(xlat):
    """Through the WAN port both ways: each segment translated to the other
    family with its header and TCP checksums right from the raw bytes, one hop
    less, DF set on IPv4, the TOS or traffic class copied with its ECN bits,
    the data intact; and each direction's entry counted exactly the probes."""
    x, r = xlat, xlat.r
    session = x.hairpin()
    installed = x.rows(await x.installed(session), session)
    probes = [(tos, x.payload("up"), x.payload("down")) for tos in TOS]
    async with x.capture("xlat-hairpin-wire") as frames:
        for tos, up, down in probes:
            await x.send([x.upload(session, tos, up, eth_src=r.wan_mac, eth_dst=r.dut_wan_mac),
                          x.download(session, tos, down)])
    for tos, up, down in probes:
        uploads, downloads = translated(frames, up), translated(frames, down)
        assert len(uploads) == 1 and len(downloads) == 1, (tos, uploads, downloads)
        assert_upload(uploads[0], session, tos, r, f"upload tos {tos:#04x}")
        assert_download(downloads[0], session, tos, f"download tos {tos:#04x}",
                        eth_src=r.dut_wan_mac, eth_dst=r.wan_mac)
    after = x.rows(await x.state(), session)
    for family in (4, 6):
        delta = int(after[family]["packets"]) - int(installed[family]["packets"])
        assert delta == len(TOS), (family, installed[family], after[family])
    r.record("xlat-hairpin-wire", {"installed": installed, "after": after})


async def test_keepalive(xlat):
    """`used` is said only for counter passes that saw the session's packets:
    not while it idles, and again after traffic."""
    x, r = xlat, xlat.r
    session = x.hairpin()
    await x.installed(session)
    period = x.stats_ms / 1000

    async def used():
        return (await x.client())["sessions"][session.cookie]["used"]

    idle = await used()
    await asyncio.sleep(3 * period)
    assert await used() == idle, "used said for passes with no packets"
    await x.send([x.upload(session, 0, x.payload("keepalive"), eth_src=r.wan_mac,
                           eth_dst=r.dut_wan_mac) for _ in range(3)])
    deadline = time.monotonic() + 4 * period
    while (moved := await used()) == idle:
        assert time.monotonic() < deadline, "no used said after traffic"
        await asyncio.sleep(0.1)
    await asyncio.sleep(3 * period)
    assert await used() == moved, "used said again with no packets since"


async def test_withdraw(xlat):
    """A withdrawal takes both entries out and says nothing, and the next
    probe in either direction is not translated."""
    x, r = xlat, xlat.r
    session = x.hairpin()
    await x.installed(session)
    before = await x.client()
    assert await x.write(f"withdraw cookie={session.cookie}") == 0
    await x.gone(session)
    await asyncio.sleep(x.stats_ms / 1000)
    listing = await x.client()
    assert listing["expired"] == before["expired"], (before, listing)
    assert listing["withdrawals"] == before["withdrawals"] + 1 and not listing["late"], listing
    assert session.cookie not in listing["sessions"], listing
    up, down = x.payload("withdrawn-up"), x.payload("withdrawn-down")
    async with x.capture("xlat-withdrawn") as frames:
        await x.send([x.upload(session, 0, up, eth_src=r.wan_mac, eth_dst=r.dut_wan_mac),
                      x.download(session, 0, down)])
    leaked = [s for s in translated(frames, up) if s.family == 4] + \
             [s for s in translated(frames, down) if s.family == 6]
    assert not leaked, ("translated after the withdrawal", leaked)


async def test_retired_by_neighbour_change(xlat):
    """The upload's neighbour moving to another MAC retires the session, said
    `expired` once."""
    x = xlat
    session = x.hairpin()
    await x.installed(session)
    before = await x.client()
    try:
        await x.target("ip", "neigh", "replace", WAN_IP, "lladdr", "02:a5:4b:00:64:01",
                       "nud", "permanent", "dev", TARGET_WAN_IF)
        await x.gone(session)
        await x.expired(before["expired"])
    finally:
        await x.target("ip", "neigh", "replace", WAN_IP, "lladdr", x.r.wan_mac,
                       "nud", "permanent", "dev", TARGET_WAN_IF)


async def test_retired_by_route_removal(xlat):
    """The download's route going retires the session, said `expired` once."""
    x = xlat
    session = x.hairpin()
    await x.installed(session)
    before = await x.client()
    try:
        await x.target("ip", "-6", "route", "del", f"{WAN_IPV6}/128", "dev", TARGET_WAN_IF)
        await x.gone(session)
        await x.expired(before["expired"])
    finally:
        await x.target("ip", "-6", "route", "replace", f"{WAN_IPV6}/128", "dev", TARGET_WAN_IF)


async def test_unload_drains(xlat):
    """Unloading the client with a session installed takes the adapter's
    entries back to where they were, latching nothing; loaded again, it
    installs as before."""
    x, r = xlat, xlat.r
    session = x.hairpin()
    await x.installed(session)
    await x.target("rmmod", MODULE)
    state = await r.wait(lambda s: not s["xlat_registered"] and not s["xlat_entries"])
    assert not x.rows(state, session) and state["entries"] == x.baseline["entries"], state
    assert state["fatal"] == x.baseline["fatal"], (x.baseline, state)
    await x.target("modprobe", MODULE)
    assert (await x.state())["xlat_registered"] == 1
    await x.installed(x.hairpin())


async def _lan_capture(x, session: Session, count: int, timeout: float):
    """Start the LAN VM receiving the session's download frames, and return
    the task that ends with them once `count` arrived or `timeout` passed."""
    r = x.r
    script = f"""
import json, os, select, socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(({LAN_NIC!r}, 0))
open({LAN_CAPTURE_READY!r}, "w").close()
frames, deadline = [], time.monotonic() + {timeout}
try:
    while len(frames) < {count} and time.monotonic() < deadline:
        if not select.select([s], [], [], 0.2)[0]:
            continue
        data, address = s.recvfrom(65535)
        if address[2] == socket.PACKET_OUTGOING or data[12:14] != b"\\x86\\xdd" or data[20] != 6:
            continue
        if struct.unpack("!HH", data[54:58]) == ({session.server_port}, {session.client_port}):
            frames.append(data.hex())
finally:
    os.unlink({LAN_CAPTURE_READY!r})
print(json.dumps({{"frames": frames}}))
"""
    await lan_run(r.lan, f"rm -f {LAN_CAPTURE_READY}", 5)
    task = asyncio.create_task(lan_run_python(r.lan, script, label="xlat_download_capture",
                                              timeout=timeout + 20))
    deadline = time.monotonic() + 15
    while (await lan_run(r.lan, f"test -e {LAN_CAPTURE_READY}", 5)).rc:
        if task.done() or time.monotonic() > deadline:
            task.cancel()
            pytest.fail(f"the LAN VM's capture did not start: {task}")
        await asyncio.sleep(0.2)
    return task


async def test_lan_to_wan_wire(xlat):
    """LAN VM to WAN host and back through the two ports: each direction's
    segments translated as on the hairpin."""
    x, r = xlat, xlat.r
    session = x.lan()
    await x.installed(session)
    uploads = [(tos, x.payload("lan-up")) for tos in TOS]
    frames = [bytes(x.upload(session, tos, payload, eth_src=r.lan_mac,
                             eth_dst=r.dut_lan_mac)).hex() for tos, payload in uploads]
    async with x.capture("xlat-lan-upload") as captured:
        sent = await lan_run_python(r.lan, f"""
import socket, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(({LAN_NIC!r}, 0))
for frame in {frames!r}:
    s.send(bytes.fromhex(frame))
    time.sleep(0.02)
print("sent")
""", label="xlat_upload_probes", timeout=30)
        assert sent.rc == 0 and "sent" in sent.stdout, sent
    for tos, payload in uploads:
        found = translated(captured, payload)
        assert len(found) == 1, (tos, found)
        assert_upload(found[0], session, tos, r, f"LAN upload tos {tos:#04x}")
    downloads = [(tos, x.payload("lan-down")) for tos in TOS]
    task = await _lan_capture(x, session, len(downloads), 10)
    await x.send([x.download(session, tos, payload) for tos, payload in downloads])
    result = await task
    assert result.rc == 0, result.stdout
    received = [bytes.fromhex(f) for f in json.loads(result.stdout.strip().splitlines()[-1])["frames"]]
    for tos, payload in downloads:
        found = translated(received, payload)
        assert len(found) == 1, (tos, found, received)
        assert_download(found[0], session, tos, f"LAN download tos {tos:#04x}",
                        eth_src=r.dut_lan_mac, eth_dst=r.lan_mac)


async def test_lan_upload_load(xlat):
    """A few hundred thousand frames from the LAN VM through the upload's
    entry: it counts every one, and the DUT's CPU receives next to none of
    them."""
    x, r = xlat, xlat.r
    session = x.lan()
    before = x.rows(await x.installed(session), session)[6]
    frame = bytes(x.upload(session, 0, b"ASK-xlat-load".ljust(64, b"."), eth_src=r.lan_mac,
                           eth_dst=r.dut_lan_mac)).hex()
    cpu_before = await kernel_rx_packets(r.target, r.session, TARGET_LAN_IF)
    result = await lan_run_python(r.lan, f"""
import errno, json, socket, time
iface, frame = {LAN_NIC!r}, bytes.fromhex({frame!r})
def counters():
    return {{name: int(open(f"/sys/class/net/{{iface}}/statistics/{{name}}").read())
            for name in ("tx_packets", "tx_dropped", "tx_errors")}}
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
# Straight to the driver, so a frame it cannot take is refused here and sent
# again rather than dropped by a queue on the way.
s.setsockopt(263, 20, 1)  # SOL_PACKET, PACKET_QDISC_BYPASS
s.bind((iface, 0))
first, sent, refused = counters(), 0, 0
start = time.monotonic()
while sent < {LOAD_FRAMES}:
    due = min({LOAD_FRAMES}, int((time.monotonic() - start) * {LOAD_RATE}) + 64)
    while sent < due:
        try:
            s.send(frame)
        except OSError as error:
            if error.errno not in (errno.ENOBUFS, errno.EAGAIN):
                raise
            refused += 1
            break
        sent += 1
    else:
        time.sleep(0.0005)
elapsed = time.monotonic() - start
time.sleep(0.5)
print(json.dumps({{"sent": sent, "refused": refused, "elapsed": elapsed,
                  "before": first, "after": counters()}}))
""", label="xlat_upload_load", timeout=120)
    assert result.rc == 0, result.stdout
    load = json.loads(result.stdout.strip().splitlines()[-1])
    cpu = await kernel_rx_packets(r.target, r.session, TARGET_LAN_IF) - cpu_before
    after = x.rows(await x.state(), session)[6]
    r.record("xlat-lan-load", {"load": load, "before": before, "after": after, "cpu_rx": cpu})
    # A frame the LAN NIC took and then lost never reached the DUT; the count
    # sent would overstate what the entry could see.
    lost = {k: load["after"][k] - load["before"][k] for k in ("tx_dropped", "tx_errors")}
    assert not any(lost.values()), ("the LAN NIC lost frames it took", lost, load)
    assert int(after["packets"]) - int(before["packets"]) == load["sent"], (before, after, load)
    # In software every frame would reach the CPU; offloaded, only what else
    # crosses the LAN port meanwhile does -- neighbour discovery and the like,
    # a handful a second whatever the load. A hundredth of the frames sent
    # tells the two apart by two orders of magnitude either way.
    assert cpu * 100 <= load["sent"], ("the DUT's CPU received the load", cpu, load)

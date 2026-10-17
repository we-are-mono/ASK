"""The two device-wide meters, set, read back and flooded through devlink.

Neither belongs to a netdev a `tc` filter could sit on, so cdx registers both
on the FMAN's own devlink instance as trap policers. Policer 1 meters what the
classifier punts to the CPU: every frame that misses every entry, the frames
the soft parser ends the parse early for among them -- a TTL or hop limit of 0
or 1, IPv4 ESP or UDP behind options, an IKE packet on the NAT-T port, a TCP
SYN, FIN or RST, a PPPoE LCP frame -- unless a flow's entry or a bridged pair
takes them. Policer 2
meters what the classifier hands to the SEC engine, which a flow bound for an
offloaded SA meets instead of the profile its own class names. Each is a rate
and a burst in packets, and a drop count.

The floods offer about a thousand packets a second above a thousand-packet
rate. A profile programmed with equal committed and peak rates passes the
burst it starts with and then its rate, and colours everything else red, which
it drops and counts. So what gets through is the rate over the flood's
duration plus the burst, and the drop counter reports the rest. The tolerance
is the profile's rate resolution and whatever background traffic shares the
meter for those few seconds -- not an allowance for the arithmetic.

Every value a case sets is put back as devlink reported it before the case, by
the fixture, whatever the case did. devlink reports what each meter was created
with until something sets it, so what the fixture puts back is what the
hardware ran at boot, not a placeholder that would switch a meter off.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
import re
import secrets
import shlex
import socket
import struct
import subprocess
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run, lan_run_python
from _flowtable_rig import (artifact_dir, WAN_IP, command, console_command, console_json)
from _flowtable_qos import (PORT, admit, lan_start, lan_stop, offload)

POLICER_PUNT, POLICER_SEC = 1, 2
# The ranges cdx_devlink.c declares. devlink refuses anything outside them
# itself, before the driver is asked.
LIMITS = {POLICER_PUNT: {"rate": (1000, 5000000), "burst": (1, 2048)},
          POLICER_SEC: {"rate": (1, 14880952), "burst": (1, 2048)}}
# What each meter's profile is created with, and so what devlink reports until
# something sets it: dpa_app's punt defaults, and the SEC profile's peak pair --
# it passes green and yellow alike, so the peak rate and burst are all it
# enforces.
BOOT = {POLICER_PUNT: (195312, 64), POLICER_SEC: (1060000, 64)}

FLOOD_RATE = 1000          # packets per second the meter is set to
FLOOD_OFFERED = 2000       # and what the flood offers it
FLOOD_BURST = 64
FLOOD_SECONDS = 4.0

PORT_PUNT, PORT_SEC = PORT + 16, PORT + 17
# The inner address of the SEC case's tunnel, on the LAN VM's loopback. Distinct
# from the other IPsec tests' inner prefixes.
SEC_INNER = os.environ.get("ASK_FLOWTABLE_QOS_SEC_INNER", "198.18.89.2")
SEC_REQID = 49317
CIPHER = b"\xa5" * 16
AUTH = b"\x5a" * 32


async def policers(con):
    """The FMAN's devlink handle, and its policers by id with their drop counts."""
    result = await console_command(con, "devlink", "-j", "-s", "trap", "policer", "show")
    shown = console_json(result["stdout"])["trap_policer"]
    assert len(shown) == 1, shown
    handle, rows = next(iter(shown.items()))
    return handle, {row["policer"]: row for row in rows}


async def set_policer(con, handle, policer, rate, burst, *, check=True):
    return await console_command(con, "devlink", "trap", "policer", "set", handle,
                                 "policer", str(policer), "rate", str(rate),
                                 "burst", str(burst), check=check)


def dropped(row):
    return row["stats"]["rx"]["dropped"]


@asynccontextmanager
async def devlink_console():
    """A DUT console, the devlink handle and both policers as found; on the way
    out, both put back and read back.

    On the console rather than through the agent: devlink is not in its argv
    allowlist, and a meter set to a thousand packets a second also meters the
    agent's own traffic.
    """
    con = Console.target(log_path=str(artifact_dir() / "qos-devlink-uart.log"))
    await asyncio.to_thread(con.login, "root", None)
    handle, original = None, {}
    try:
        handle, original = await policers(con)
        assert set(original) == set(LIMITS), original
        yield con, handle, original
    finally:
        try:
            failures = []
            for policer, row in original.items():
                result = await set_policer(con, handle, policer, row["rate"], row["burst"],
                                           check=False)
                if result["rc"]:
                    failures.append(result)
            if handle:
                _, restored = await policers(con)
                failures += [(policer, row, restored[policer]) for policer, row in original.items()
                             if (restored[policer]["rate"], restored[policer]["burst"])
                             != (row["rate"], row["burst"])]
        finally:
            con.close()
        assert not failures, ("devlink policers not restored", failures)


@pytest_asyncio.fixture
async def devlink(splat_window):
    async with devlink_console() as held:
        yield held


@pytest_asyncio.fixture
async def metered(rig):
    """The rig, with the devlink console alongside it."""
    async with devlink_console() as (con, handle, original):
        rig.console, rig.devlink = con, handle
        yield rig, original


async def test_policers_round_trip(devlink):
    """Each policer takes a rate and burst inside its declared range and reads
    them back; refuses each edge just outside it, with devlink's own message,
    leaving the value it held; and takes its original value back."""
    con, handle, original = devlink

    async def current(policer):
        _, rows = await policers(con)
        return rows[policer]["rate"], rows[policer]["burst"]

    for policer, limits in LIMITS.items():
        start = original[policer]["rate"], original[policer]["burst"]
        (low_rate, high_rate), (low_burst, high_burst) = limits["rate"], limits["burst"]
        wanted = (low_rate + 12345, 257)
        if wanted == start:
            wanted = (low_rate + 23456, 129)
        await set_policer(con, handle, policer, *wanted)
        assert await current(policer) == wanted, (policer, wanted)
        for rate, burst, message in (
                (low_rate - 1, wanted[1], "Policer rate lower than limit"),
                (high_rate + 1, wanted[1], "Policer rate higher than limit"),
                (wanted[0], low_burst - 1, "Policer burst size lower than limit"),
                (wanted[0], high_burst + 1, "Policer burst size higher than limit")):
            refused = await set_policer(con, handle, policer, rate, burst, check=False)
            assert refused["rc"] != 0 and message in refused["stdout"], (policer, rate, burst,
                                                                         refused)
            assert await current(policer) == wanted, (policer, rate, burst)
        await set_policer(con, handle, policer, *start)
        assert await current(policer) == start, (policer, start)


async def test_policers_report_what_the_hardware_runs(devlink):
    """Each policer reports the rate and burst its meter was created with, and a
    set that names only a rate keeps the burst the meter runs.

    devlink reports a policer's registered values until a set succeeds, and
    keeps the registered burst for a set that leaves it out. Every case in this
    file puts back what it found, so the values found here are the boot values
    on any run of the same boot; a case that failed to restore fails here.
    """
    con, handle, original = devlink
    found = {policer: (row["rate"], row["burst"]) for policer, row in original.items()}
    assert found == BOOT, found
    rate = 100000
    await console_command(con, "devlink", "trap", "policer", "set", handle,
                          "policer", str(POLICER_PUNT), "rate", str(rate))
    _, rows = await policers(con)
    assert (rows[POLICER_PUNT]["rate"], rows[POLICER_PUNT]["burst"]) == (
        rate, BOOT[POLICER_PUNT][1]), rows[POLICER_PUNT]
    assert (rows[POLICER_SEC]["rate"], rows[POLICER_SEC]["burst"]) == BOOT[POLICER_SEC], rows


class Sink(asyncio.DatagramProtocol):
    def __init__(self, tag):
        self.tag, self.count = tag, 0

    def datagram_received(self, data, addr):
        if data.startswith(self.tag):
            self.count += 1


def assert_metered(label, sent, passed, drops, seconds):
    """The flood arithmetic every case here shares: the sender held its pace,
    what got through is the rate plus the burst, and the drop counter accounts
    for the rest."""
    assert sent >= 0.95 * FLOOD_OFFERED * FLOOD_SECONDS, (label, "the sender fell behind", sent)
    expected = FLOOD_RATE * seconds + FLOOD_BURST
    assert abs(passed - expected) <= 0.05 * FLOOD_RATE * seconds + 32, (
        label, passed, expected)
    assert abs(drops - (sent - passed)) <= max(32, sent // 100), (label, sent, passed, drops)


async def test_punt_policer_meters_the_punt_path(metered):
    """A flow no entry matches is punted to the CPU through policer 1, and held
    to its rate.

    No flowtable is bound, so every frame of the LAN VM's flood misses and is
    punted; what the meter passes, the CPU forwards to this host, which counts
    it. Everything the meter saw and did not pass is on its drop counter.
    Setting a rate reprograms the profile, which restarts its counters, so the
    baseline is read after the set. The agent is not used between the set and
    the restore: its own traffic is punted through the same meter.
    """
    r, original = metered
    tag = b"ASK-punt"
    flood = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({r.lan_ip!r}, {PORT_PUNT}))
filler = b'.' * 48
rate, seconds = {FLOOD_OFFERED}, {FLOOD_SECONDS}
sent = 0
start = time.perf_counter()
while True:
    now = time.perf_counter()
    if now - start >= seconds:
        break
    due = start + sent / rate
    if now < due:
        time.sleep(min(due - now, 0.0005))
        continue
    s.sendto({tag!r} + struct.pack('!Q', sent) + filler, ({WAN_IP!r}, {PORT_PUNT}))
    sent += 1
print(json.dumps({{'sent': sent, 'seconds': time.perf_counter() - start}}))
'''
    transport, sink = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: Sink(tag), local_addr=(WAN_IP, PORT_PUNT))
    try:
        await set_policer(r.console, r.devlink, POLICER_PUNT, FLOOD_RATE, FLOOD_BURST)
        _, rows = await policers(r.console)
        base = dropped(rows[POLICER_PUNT])
        result = await lan_run_python(r.lan, flood, label="flowtable_qos_punt",
                                      timeout=FLOOD_SECONDS + 30)
        await asyncio.sleep(0.5)
        _, rows = await policers(r.console)
    finally:
        transport.close()
        row = original[POLICER_PUNT]
        await set_policer(r.console, r.devlink, POLICER_PUNT, row["rate"], row["burst"])
    assert result.rc == 0, result.stdout
    report = json.loads(result.stdout.strip().splitlines()[-1])
    drops = dropped(rows[POLICER_PUNT]) - base
    r.record("qos-devlink-punt", {"flood": report, "passed": sink.count, "dropped": drops,
                                  "policers": rows})
    await command(r.target, r.session, "conntrack", "-D", "-p", "udp", "--orig-src", r.lan_ip,
                  "--orig-dst", WAN_IP, "--dport", str(PORT_PUNT), check=False)
    assert_metered("punt", report["sent"], sink.count, drops, report["seconds"])


# What the soft parser ends the parse early for and hands to the CPU, each
# kind addressed to the DUT itself. The first five were enqueued from the
# parser, past every lookup and the meter (A370); a SYN and an LCP frame
# always met it.
PARSER_PUNTS = ("ttl_one", "hop_limit_one", "ipv4_options", "nat_t_ike", "pppoe_ttl_one",
                "tcp_syn", "pppoe_lcp")
PORT_PARSER = PORT + 18
PPPOE_SESSION = 0x1234
# Every scheme a lookup keyed on an IP header is reached through.
IP_SCHEMES = frozenset(f"cdx_{name}_dist" for name in (
    "esp4", "esp6", "udp4", "tcp4", "udp6", "tcp6", "ipv4multicast", "ipv6multicast",
    "bridged_mcast4", "bridged_mcast6", "tup3udp4", "tup3udp6"))
# The scheme that must classify a kind's flood, if one is known, and those
# that must classify none of it. The parser ends the first five without
# confirming the header it stops at, so no table keyed on that header, an
# entry of which would carry the frame on, is searched: a routed group's root
# decrements a TTL of 1 to 0, and the UDP table holds ESP-in-UDP SAs.
CLASSIFIED = {
    "ttl_one": ("cdx_ethernet_dist", IP_SCHEMES),
    "hop_limit_one": ("cdx_ethernet_dist", IP_SCHEMES),
    "ipv4_options": ("cdx_ethernet_dist", IP_SCHEMES),
    "nat_t_ike": (None, frozenset({"cdx_udp4_dist", "cdx_esp4_dist", "cdx_tup3udp4_dist"})),
    "pppoe_ttl_one": ("cdx_pppoe_dist", IP_SCHEMES),
    "tcp_syn": ("cdx_tcp4_dist", frozenset()),
    "pppoe_lcp": ("cdx_pppoe_dist", IP_SCHEMES),
}


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def pppoe_session(dut_mac, host_mac, protocol, payload):
    """An Ethernet frame of PPPoE session PPPOE_SESSION carrying `payload` as
    PPP `protocol`, padded to the Ethernet minimum."""
    ppp = struct.pack("!H", protocol) + payload
    frame = (dut_mac + host_mac
             + struct.pack("!HBBHH", 0x8864, 0x11, 0, PPPOE_SESSION, len(ppp)) + ppp)
    return frame.ljust(60, b"\0")


def parser_punt(kind, dut):
    """A socket and the function that sends one frame of `kind` through it,
    from this host to the DUT's own WAN address: UDP to a closed port, a SYN
    to one, or a PPPoE session frame for a session the DUT does not have."""
    if kind == "hop_limit_one":
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 1)
        target = (dut["ipv6"], PORT_PARSER, 0, socket.if_nametoindex(dut["host_if"]))
        return sock, lambda n: sock.sendto(b"ASK-parser" + struct.pack("!Q", n), target)
    if kind in ("ttl_one", "ipv4_options", "nat_t_ike"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((WAN_IP, PORT_PARSER))
        port, prefix = PORT_PARSER, b"ASK-parser"
        if kind == "ttl_one":
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        elif kind == "ipv4_options":
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b"\x01\x01\x01\x00")
        else:
            # A zero where ESP-in-UDP has its SPI: IKE's non-ESP marker.
            port, prefix = 4500, b"\0\0\0\0ASK-parser"
        return sock, lambda n: sock.sendto(prefix + struct.pack("!Q", n), (dut["ipv4"], port))
    if kind == "tcp_syn":
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.bind((WAN_IP, 0))
        pseudo = socket.inet_aton(WAN_IP) + socket.inet_aton(dut["ipv4"]) + struct.pack(
            "!BBH", 0, socket.IPPROTO_TCP, 20)

        def syn(n):
            header = struct.pack("!HHIIBBHHH", PORT_PARSER, PORT_PARSER, n, 0, 5 << 4, 0x02,
                                 512, 0, 0)
            header = header[:16] + struct.pack("!H", checksum(pseudo + header)) + header[18:]
            sock.sendto(header, (dut["ipv4"], 0))
        return sock, syn
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((dut["host_if"], 0))
    host_mac = sock.getsockname()[4]
    if kind == "pppoe_lcp":
        frame = pppoe_session(dut["mac"], host_mac, 0xC021, struct.pack("!BBHI", 9, 1, 8, 0))
    else:
        udp = struct.pack("!HHHH", PORT_PARSER, PORT_PARSER, 18, 0) + b"ASK-parser"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 1, socket.IPPROTO_UDP,
                         0, socket.inet_aton(WAN_IP), socket.inet_aton(dut["ipv4"]))
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        frame = pppoe_session(dut["mac"], host_mac, 0x0021, ip + udp)
    return sock, lambda n: sock.send(frame)


def parser_flood(kind, dut):
    """FLOOD_OFFERED frames of `kind` a second for FLOOD_SECONDS."""
    sock, send = parser_punt(kind, dut)
    sent = 0
    try:
        start = time.perf_counter()
        while True:
            now = time.perf_counter()
            if now - start >= FLOOD_SECONDS:
                break
            due = start + sent / FLOOD_OFFERED
            if now < due:
                time.sleep(min(due - now, 0.0005))
                continue
            send(sent)
            sent += 1
        return {"sent": sent, "seconds": time.perf_counter() - start}
    finally:
        sock.close()


async def dut_wan(con):
    """The DUT's WAN port as this host reaches it: its MAC, IPv4 and IPv6
    link-local addresses, and the host device on the same segment."""
    shown = console_json((await console_command(con, "ip", "-j", "addr", "show", "dev",
                                                TARGET_WAN_IF))["stdout"])[0]
    addresses = [a for a in shown["addr_info"] if "local" in a]
    host = json.loads(subprocess.run(["ip", "-j", "-4", "addr", "show"], check=True,
                                     capture_output=True, text=True).stdout)
    return {"mac": bytes.fromhex(shown["address"].replace(":", "")),
            "ipv4": next(a["local"] for a in addresses if a["family"] == "inet"),
            "ipv6": next(a["local"] for a in addresses
                         if a["family"] == "inet6" and a["scope"] == "link"),
            "host_if": next(i["ifname"] for i in host
                            if any(a.get("local") == WAN_IP for a in i["addr_info"]))}


async def scheme_frames(con):
    """The frames each KeyGen scheme has classified, by name; a scheme shared
    by several ports is listed under each with one handle, and counted once."""
    shown = (await console_command(con, "cat", "/proc/cdx_pcd_schemes"))["stdout"]
    handles = {m.group(2): (m.group(1), int(m.group(3))) for m in
               re.finditer(r"^fm\d+ \S+ (\S+) handle (\S+) frames (\d+)\s*$", shown, re.M)}
    assert handles, shown
    totals = {}
    for name, frames in handles.values():
        totals[name] = totals.get(name, 0) + frames
    return totals


async def wan_rx_packets(con):
    result = await console_command(con, "cat",
                                   f"/sys/class/net/{TARGET_WAN_IF}/statistics/rx_packets")
    return int(result["stdout"].split()[-1])


@pytest.mark.parametrize("kind", PARSER_PUNTS)
async def test_punt_policer_meters_parser_punts(devlink, kind):
    """A frame the soft parser hands to the CPU meets policer 1 like any other
    punt, is held to its rate, and is classified where no entry can carry it.

    A TTL or hop limit of 1, UDP behind IPv4 options, IKE's non-ESP marker on
    the NAT-T port and a TTL of 1 inside a PPPoE session each end the parse
    early. The parser used to enqueue them itself, which no meter sees, so a
    flood of them reached the CPU whatever devlink said (A370); they now take
    the punt path every other exception takes. A TCP SYN and a PPPoE LCP frame
    always did, and are the controls. Each flood is addressed to the DUT itself,
    so every frame the meter passes is one the WAN port hands the CPU, and the
    port's receive count is what got through. The KeyGen schemes' own counters
    say which classified the flood (CLASSIFIED). The agent is not used between
    the set and the restore: its own traffic shares the meter.
    """
    con, handle, original = devlink
    dut = await dut_wan(con)
    try:
        await set_policer(con, handle, POLICER_PUNT, FLOOD_RATE, FLOOD_BURST)
        _, rows = await policers(con)
        base, rx = dropped(rows[POLICER_PUNT]), await wan_rx_packets(con)
        schemes = await scheme_frames(con)
        report = await asyncio.to_thread(parser_flood, kind, dut)
        await asyncio.sleep(0.5)
        _, rows = await policers(con)
        passed = await wan_rx_packets(con) - rx
        schemes = {name: (frames - schemes.get(name, 0)) & 0xFFFFFFFF
                   for name, frames in (await scheme_frames(con)).items()}
    finally:
        row = original[POLICER_PUNT]
        await set_policer(con, handle, POLICER_PUNT, row["rate"], row["burst"])
    drops = dropped(rows[POLICER_PUNT]) - base
    path = artifact_dir() / f"qos-devlink-parser-{kind}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"flood": report, "passed": passed, "dropped": drops,
                                "schemes": {k: v for k, v in schemes.items() if v}}, indent=1))
    assert_metered(kind, report["sent"], passed, drops, report["seconds"])
    # A scheme shared by several ports counts what all of them classify, and
    # what else crosses them in four seconds is a few frames, not a flood's
    # worth.
    expected, excluded = CLASSIFIED[kind]
    if expected:
        assert schemes[expected] >= report["sent"] - max(32, report["sent"] // 100), (
            kind, expected, schemes)
    taken = {name: schemes.get(name, 0) for name in excluded}
    assert all(frames <= report["sent"] // 20 for frames in taken.values()), (kind, taken)


def paced(destination, port, rate, seconds, *, tag=b"ASK-sec", payload_size=512):
    """Send at `rate` datagrams a second for `seconds` from this host, counting
    the echoes as they come back and for half a second after."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((WAN_IP, port))
    sock.setblocking(False)
    filler = b"." * (payload_size - len(tag) - 8)
    sent = echoed = 0

    def drain():
        nonlocal echoed
        while True:
            try:
                data = sock.recv(4096)
            except BlockingIOError:
                return
            if data.startswith(tag):
                echoed += 1

    try:
        start = time.perf_counter()
        while True:
            now = time.perf_counter()
            if now - start >= seconds:
                break
            due = start + sent / rate
            if now < due:
                drain()
                time.sleep(min(due - now, 0.0005))
                continue
            sock.sendto(tag + struct.pack("!Q", sent) + filler, (destination, port))
            sent += 1
        elapsed = time.perf_counter() - start
        settle = time.perf_counter() + 0.5
        while time.perf_counter() < settle:
            drain()
            time.sleep(0.01)
    finally:
        sock.close()
    return {"sent": sent, "echoed": echoed, "seconds": elapsed}


async def test_sec_policer_meters_the_crypto_path(metered):
    """An offloaded flow bound for an SA meets policer 2 on its way to SEC,
    and is held to its rate.

    The tunnel runs between the DUT's LAN port and the LAN VM, and the flow is
    forwarded: this host sends to an address behind the tunnel, the classifier
    entry names the SA, and the entry hands each frame to SEC with policer 2 in
    place of the profile its class would name. The LAN VM decrypts and echoes
    in the clear, on a return direction that names no SA and meets no such
    meter, so every echo is a frame the meter passed. The row's own counter
    sees every frame the flood offered it, passed or not.
    """
    r, original = metered
    spi = 0x0A890000 | (secrets.randbelow(0xFFFF) + 1)

    async def dut(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    async def lan(*argv, check=True):
        result = await lan_run(r.lan, shlex.join(argv), 25)
        if check:
            assert result.rc == 0, (argv, result.stdout)
        return result

    def address(dev):
        return dut("ip", "-j", "-4", "addr", "show", "dev", dev)

    dut_lan = next(a["local"] for a in json.loads((await address(TARGET_LAN_IF))["stdout"])[0][
        "addr_info"] if a["family"] == "inet")
    dut_wan = next(a["local"] for a in json.loads((await address(TARGET_WAN_IF))["stdout"])[0][
        "addr_info"] if a["family"] == "inet")
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    state =("src", dut_lan, "dst", r.lan_ip, "proto", "esp", "spi", hex(spi))
    crypto = ("mode", "tunnel", "reqid", str(SEC_REQID),
              "enc", "cbc(aes)", "0x" + CIPHER.hex(),
              "auth-trunc", "hmac(sha256)", "0x" + AUTH.hex(), "128")
    selector = ("src", WAN_IP + "/32", "dst", SEC_INNER + "/32")
    tmpl = ("tmpl", "src", dut_lan, "dst", r.lan_ip, "proto", "esp", "mode", "tunnel",
            "reqid", str(SEC_REQID), "level", "required")
    cleanup = []
    try:
        # The LAN VM: the tunnel's far end, and the echo behind it.
        await lan("ip", "address", "add", f"{SEC_INNER}/32", "dev", "lo")
        cleanup.append(lambda: lan("ip", "address", "del", f"{SEC_INNER}/32", "dev", "lo",
                                   check=False))
        await lan("ip", "xfrm", "state", "add", *state, *crypto, "replay-window", "32")
        cleanup.append(lambda: lan("ip", "xfrm", "state", "delete", *state, check=False))
        await lan("ip", "xfrm", "policy", "add", *selector, "dir", "in", *tmpl)
        cleanup.append(lambda: lan("ip", "xfrm", "policy", "delete", *selector, "dir", "in",
                                   check=False))
        await lan_start(r, echo=[PORT_SEC], host=SEC_INNER)
        cleanup.append(lambda: lan_stop(r))
        # The DUT: the flowtable, then the SA and its policy, offloaded.
        await offload(r, f"ip saddr {WAN_IP} ip daddr {SEC_INNER} udp dport {PORT_SEC} "
                         f"flow add @fast")
        await dut("ip", "route", "replace", f"{SEC_INNER}/32", "via", r.lan_ip)
        cleanup.append(lambda: dut("ip", "route", "del", f"{SEC_INNER}/32", check=False))
        await dut("ip", "xfrm", "state", "add", *state, *crypto,
                  "offload", "packet", "dev", TARGET_LAN_IF, "dir", "out")
        cleanup.append(lambda: dut("ip", "xfrm", "state", "delete", *state, check=False))
        await dut("ip", "xfrm", "policy", "add", *selector, "dir", "out", *tmpl,
                  "offload", "packet", "dev", TARGET_LAN_IF)
        cleanup.append(lambda: dut("ip", "xfrm", "policy", "delete", *selector, "dir", "out",
                                   check=False))
        cleanup.append(lambda: dut("conntrack", "-D", "-p", "udp", "--orig-src", WAN_IP,
                                   "--orig-dst", SEC_INNER, check=False))
        # This host's way to the inner address is through the DUT.
        await command(wan, r.session, "ip", "route", "replace", f"{SEC_INNER}/32",
                      "via", dut_wan, "dev", r.wan_if)
        cleanup.append(lambda: command(wan, r.session, "ip", "route", "del", f"{SEC_INNER}/32",
                                       "via", dut_wan, "dev", r.wan_if, check=False))

        forward, reverse = await admit(r, PORT_SEC, destination=SEC_INNER)
        assert forward["out"] == TARGET_LAN_IF and forward["sa"] != "0", forward
        assert reverse["sa"] == "0", reverse
        await set_policer(r.console, r.devlink, POLICER_SEC, FLOOD_RATE, FLOOD_BURST)
        _, rows = await policers(r.console)
        base = dropped(rows[POLICER_SEC])
        before = await r.state()
        flood = await asyncio.to_thread(paced, SEC_INNER, PORT_SEC, FLOOD_OFFERED, FLOOD_SECONDS)
        _, rows = await policers(r.console)
        after = await r.state()
    finally:
        try:
            row = original[POLICER_SEC]
            await set_policer(r.console, r.devlink, POLICER_SEC, row["rate"], row["burst"])
        finally:
            for undo in reversed(cleanup):
                try:
                    await undo()
                except Exception:
                    pass
    drops = dropped(rows[POLICER_SEC]) - base
    target = f"{SEC_INNER}:{PORT_SEC}"
    old = [f for f in before["flows"] if f["cookie"] == forward["cookie"]]
    new = [f for f in after["flows"] if f["cookie"] == forward["cookie"]]
    r.record("qos-devlink-sec", {"flood": flood, "dropped": drops, "forward": forward,
                                 "before": old, "after": new, "policers": rows})
    assert len(old) == len(new) == 1, (target, old, new)
    moved = int(new[0]["packets"]) - int(old[0]["packets"])
    assert flood["echoed"] <= moved <= flood["sent"], (moved, flood)
    assert_metered("sec", flood["sent"], flood["echoed"], drops, flood["seconds"])

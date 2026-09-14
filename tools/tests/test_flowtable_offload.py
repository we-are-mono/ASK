"""Opt-in, CMM-independent IPv4/UDP flowtable acceptance on the real DUT.

Boot ask.offload=flowtable, then ASK_FLOWTABLE_TESTS=1 make ask-test
ASK_TEST_ARGS='-k flowtable_offload'. Normal legacy runs skip these tests.
The invalidation test is last because invalidation intentionally lasts to reboot.
"""
from __future__ import annotations

import asyncio
import base64
from collections import Counter
import errno
import json
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import threading
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, kernel_rx_packets, lan_run_python

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
WAN_IP = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
SPORT = int(os.environ.get("ASK_FLOWTABLE_SPORT", "48270"))
DPORT = int(os.environ.get("ASK_FLOWTABLE_DPORT", "48271"))
TABLE = "ask_poc"
ARTIFACTS = Path(os.environ.get("ASK_FLOWTABLE_ARTIFACTS", "/tmp/ask-flowtable"))


async def read(agent, session, path):
    result = await agent.fs_read(session, path)
    assert result["errno"] == 0, (path, result)
    return bytes.fromhex(result["content_hex"]).decode()


async def command(agent, session, *argv, check=True):
    result = await agent.exec_cmd(session, list(argv), timeout_ms=15000)
    if check:
        assert result["rc"] == 0, result
    return result


async def console_command(console, *argv, check=True, timeout=20):
    # BusyBox line editing can wrap and redraw the echoed command. Frame
    # actual output rather than relying on the console's echo stripping.
    assert all("\n" not in arg for arg in argv), "use console_python for scripts"
    marker = f"__ASK_OUTPUT_{time.monotonic_ns()}__"
    cmd = f"printf '\\n%s\\n' {shlex.quote(marker)}; {shlex.join(argv)}"
    result = await asyncio.to_thread(console.run, cmd, timeout)
    match = re.search(r"(?:^|\n)" + marker + r"\r?\n", result.stdout)
    assert match, ("missing console output boundary", result.stdout)
    stdout = result.stdout[match.end():]
    if check:
        assert result.rc == 0, stdout
    return {"rc": result.rc, "stdout": stdout}


async def console_python(console, script):
    encoded = base64.b64encode(script.encode()).decode()
    return await console_command(console, "python3", "-c",
                                 f"import base64; exec(base64.b64decode({encoded!r}))")


def status_text(text):
    state = {"flows": []}
    for line in text.splitlines():
        if line.startswith("flow "):
            state["flows"].append(dict(item.split("=", 1) for item in line.split()[1:]))
        else:
            key, value = line.split()
            state[key] = int(value) if value.isdecimal() else value
    return state


class Echo(asyncio.DatagramProtocol):
    def __init__(self):
        self.received = Counter()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received[data] += 1
        self.transport.sendto(data, addr)


class Rig:
    async def state(self):
        return status_text(await read(self.target, self.session, "/proc/cdx_flowtable"))

    async def wait(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = await self.state()
            if predicate(state):
                return state
            await asyncio.sleep(0.1)
        pytest.fail(f"flowtable state did not converge: {state}")

    async def nft(self, text):
        return await command(self.target, self.session, "nft", text)

    async def table(self, hardware=True, counter=False):
        await self.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }};
 {"flags offload;" if hardware else ""} {"counter;" if counter else ""} }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {self.lan_ip} ip daddr {WAN_IP} udp sport {SPORT} udp dport {DPORT} flow add @fast
 }}
}}''')
        if hardware:
            await self.wait(lambda s: s["bindings"] == 2)

    async def delete_table(self):
        await command(self.target, self.session, "nft", "delete", "table", "inet", TABLE, check=False)
        return await self.wait(lambda s: not s["bindings"] and not s["entries"])

    async def clear_ct(self):
        await command(self.target, self.session, "conntrack", "-D", "-p", "udp",
                      "--orig-src", self.lan_ip, "--orig-dst", WAN_IP,
                      "--sport", str(SPORT), "--dport", str(DPORT), check=False)

    async def exchange(self, count=64, interval=0.003, payload_size=256, promiscuous=True):
        assert payload_size >= 8
        first = self.sequence
        self.sequence += count
        script = f'''
import json, socket, struct, subprocess, time
def link_stats():
    text = subprocess.check_output(['ethtool', '-S', {LAN_NIC!r}], text=True)
    return {{k.strip(): int(v.strip()) for line in text.splitlines() if ':' in line
            for k, v in [line.split(':', 1)] if v.strip().isdigit() and
            any(word in k for word in ('error', 'dropped', 'no_buffer', 'no_dma', 'timeout'))}}
link_before = link_stats()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
s.setsockopt(socket.SOL_IP, getattr(socket, "IP_RECVTTL", 12), 1)
s.settimeout(2)
s.bind(({self.lan_ip!r}, {SPORT}))
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(({LAN_NIC!r}, 0)); raw.settimeout(2)
if {promiscuous!r}:
    raw.setsockopt(263, 1, struct.pack('IHH8s', socket.if_nametoindex({LAN_NIC!r}), 1, 0, b''))
received = []
for n in range({first}, {first + count}):
    payload = struct.pack('!Q', n) + b'ASK-flowtable'.ljust({payload_size - 8}, b'.')[:{payload_size - 8}]
    s.sendto(payload, ({WAN_IP!r}, {DPORT}))
    try:
        data, ancillary, flags, addr = s.recvmsg(2048, 128)
    except TimeoutError as error:
        raw.settimeout(0.05)
        frames = []
        try:
            while len(frames) < 32:
                frame = raw.recv(65535)
                frames.append(frame.hex())
        except TimeoutError:
            pass
        print(json.dumps({{'timeout_sequence': n, 'frames': frames,
                          'link_before': link_before, 'link_after': link_stats()}}), flush=True)
        raise AssertionError(('echo timeout', n)) from error
    assert data == payload and addr == ({WAN_IP!r}, {DPORT}), (n, data, addr)
    ttl = [struct.unpack('i', v)[0] for level, kind, v in ancillary if level == socket.SOL_IP and kind == socket.IP_TTL]
    assert ttl == [63], (n, ttl)
    while True:
        frame = raw.recv(65535)
        if len(frame) < 42 or frame[23] != socket.IPPROTO_UDP or frame[26:30] != socket.inet_aton({WAN_IP!r}):
            continue
        ihl = (frame[14] & 15) * 4
        start = 14 + ihl
        if struct.unpack('!HH', frame[start:start+4]) != ({DPORT}, {SPORT}):
            continue
        assert frame[start+8:start+8+len(payload)] == payload, (n, 'duplicate or unexpected frame')
        assert frame[:6] == bytes.fromhex({self.lan_mac.replace(':', '')!r})
        assert frame[6:12] == bytes.fromhex({self.dut_lan_mac.replace(':', '')!r})
        assert ihl == 20 and frame[22] == 63
        break
    received.append(n)
    time.sleep({interval})
s.close()
raw.close()
print(json.dumps({{'first': received[0], 'last': received[-1], 'count': len(received)}}))
'''
        result = await lan_run_python(self.lan, script, timeout=max(15, count * interval + 10), label="flowtable_echo")
        if result.rc:
            state = await self.state()
            received = [struct.unpack("!Q", p[:8])[0] for p in self.echo.received if len(p) >= 8]
            ct = await command(self.target, self.session, "conntrack", "-L", "-p", "udp", "-o", "extended")
            self.record("failed-exchange", {"state": state, "first": first, "count": count,
                                           "received": received, "stdout": result.stdout, "conntrack": ct})
            pytest.fail(f"{result.stdout}\nstate={state}\nlast received={received[-8:]}")
        report = json.loads(result.stdout.strip())
        assert report == {"first": first, "last": first + count - 1, "count": count}
        for n in range(first, first + count):
            data = struct.pack("!Q", n) + b"ASK-flowtable".ljust(payload_size - 8, b".")[:payload_size - 8]
            assert self.echo.received[data] == 1, (n, self.echo.received[data])
        return report

    def record(self, name, data):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        (ARTIFACTS / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")


@pytest_asyncio.fixture
async def rig(target_agent, aiohttp_session, lan, splat_window):
    r = Rig()
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    initial = await r.state()
    assert initial["owner"] == "flowtable", "boot ask.offload=flowtable first"
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    assert "auto_bridge " not in await read(r.target, r.session, "/proc/modules")
    # The daemon pidfile is absent on a clean experimental boot; also inspect
    # the command line of any stale pidfile rather than treating it as proof.
    pid = await r.target.fs_read(r.session, "/var/run/cmm.pid")
    assert pid["errno"] != 0, "CMM must never have started in this boot"
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    cleanup = []
    transport = None
    try:
        await command(r.target, r.session, "modprobe", "xt_tcpudp")
        def lan_json(cmd):
            result = lan.run(cmd, timeout=10)
            assert result.rc == 0, result.stdout
            return json.loads(result.stdout.strip())
        r.lan_ip = next(a["local"] for a in lan_json(f"ip -j -4 addr show dev {shlex.quote(LAN_NIC)}")[0]["addr_info"]
                        if a["family"] == "inet")
        lan_mac = lan_json(f"ip -j link show dev {shlex.quote(LAN_NIC)}")[0]["address"]
        r.lan_mac = lan_mac
        r.dut_lan_mac = (await read(r.target, r.session, f"/sys/class/net/{TARGET_LAN_IF}/address")).strip()
        r.dut_wan_mac = (await read(r.target, r.session, f"/sys/class/net/{TARGET_WAN_IF}/address")).strip()
        r.lan_gateway = lan_json(f"ip -j route get {shlex.quote(WAN_IP)}")[0]["gateway"]
        # Select the interface owning the endpoint address (route get would
        # report lo for an address belonging to the local WAN host).
        addresses = json.loads((await command(wan, r.session, "ip", "-j", "-4", "addr"))["stdout"])
        r.wan_if = next(i["ifname"] for i in addresses if any(a.get("local") == WAN_IP for a in i["addr_info"]))
        wan_mac = json.loads((await command(wan, r.session, "ip", "-j", "link", "show", "dev", r.wan_if))["stdout"])[0]["address"]
        r.wan_mac = wan_mac
        dut = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_WAN_IF))["stdout"])[0]
        dut_ip = next(a["local"] for a in dut["addr_info"] if a["family"] == "inet")
        existing = json.loads((await command(wan, r.session, "ip", "-j", "route", "show", "exact", f"{r.lan_ip}/32"))["stdout"])
        if existing:
            assert existing[0].get("gateway") == dut_ip and existing[0]["dev"] == r.wan_if, existing
        else:
            await command(wan, r.session, "ip", "route", "add", f"{r.lan_ip}/32", "via", dut_ip, "dev", r.wan_if)
            cleanup.append((wan, ["ip", "route", "del", f"{r.lan_ip}/32", "via", dut_ip, "dev", r.wan_if]))
        for ip, mac, dev in [(r.lan_ip, lan_mac, TARGET_LAN_IF), (WAN_IP, wan_mac, TARGET_WAN_IF)]:
            old = json.loads((await command(r.target, r.session, "ip", "-j", "neigh", "show", "to", ip, "dev", dev))["stdout"])
            restore = ["ip", "neigh", "del", ip, "dev", dev]
            if old and old[0].get("lladdr"):
                state = "permanent" if "PERMANENT" in old[0]["state"] else "stale"
                restore = ["ip", "neigh", "replace", ip, "lladdr", old[0]["lladdr"], "nud", state, "dev", dev]
            await command(r.target, r.session, "ip", "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", dev)
            cleanup.append((r.target, restore))
            # A route MTU below both port MTUs lets exception tests send a
            # valid ingress Ethernet frame which is oversized at egress.
            routes = json.loads((await command(r.target, r.session, "ip", "-j", "route", "show", "exact", f"{ip}/32"))["stdout"])
            assert not routes, ("fixture requires unused host routes", routes)
            await command(r.target, r.session, "ip", "route", "add", f"{ip}/32", "dev", dev, "mtu", "1200")
            cleanup.append((r.target, ["ip", "route", "del", f"{ip}/32", "dev", dev]))
        nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", "udp", "--sport", str(SPORT), "--dport", str(DPORT), "-j", "ACCEPT"]
        await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
        cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *nat]))
        await r.clear_ct()
        old_acct = (await read(r.target, r.session, "/proc/sys/net/netfilter/nf_conntrack_acct")).strip()
        await command(r.target, r.session, "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
        cleanup.append((r.target, ["sysctl", "-w", f"net.netfilter.nf_conntrack_acct={old_acct}"]))
        transport, r.echo = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=(WAN_IP, DPORT))
        r.record("fixture", {"lan": r.lan_ip, "wan": WAN_IP, "sport": SPORT, "dport": DPORT,
                             "lan_mac": lan_mac, "wan_mac": wan_mac, "initial": initial,
                             "boot_id": await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")})
        yield r
    finally:
        if transport:
            transport.close()
        failures = []
        try:
            if r.recovery_console:
                await console_command(r.recovery_console, "nft", "delete", "table", "inet", TABLE, check=False)
            else:
                await r.delete_table()
        except Exception as error:
            failures.append(str(error))
        if hasattr(r, "lan_ip"):
            try:
                if r.recovery_console:
                    await console_command(r.recovery_console, "conntrack", "-D", "-p", "udp",
                                          "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                                          "--sport", str(SPORT), "--dport", str(DPORT), check=False)
                else:
                    await r.clear_ct()
            except Exception as error:
                failures.append(str(error))
        try:
            if r.recovery_console:
                # Terminal cases remove CDX and may stop management traffic.
                # Restoration must not depend on its procfs or HTTP.
                await console_python(r.recovery_console, """
from pathlib import Path
for name in ('flowtable_fail_stage', 'flowtable_fail_unlink'):
    path = Path('/sys/module/cdx/parameters') / name
    if path.exists():
        path.write_text('0')
""")
            else:
                result = await r.target.fs_write(r.session, "/sys/module/cdx/parameters/flowtable_fail_stage", "0")
                if result["errno"]:
                    failures.append(result)
        except Exception as error:
            failures.append(str(error))
        for agent, argv in reversed(cleanup):
            try:
                if r.recovery_console and agent is r.target:
                    result = await console_command(r.recovery_console, *argv, check=False)
                else:
                    result = await command(agent, r.session, *argv, check=False)
                if result["rc"]:
                    failures.append(result)
            except Exception as error:
                failures.append(str(error))
        if r.recovery_console:
            r.recovery_console.close()
        assert not failures, ("fixture restoration failed", failures)


@pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_BASELINE") not in {"software", "flowtable", "hardware"},
                    reason="explicit forwarding-path loss diagnosis")
async def test_flowtable_offload_long_exchange(rig):
    assert (await rig.state())["entries"] == 0
    hardware = os.environ["ASK_FLOWTABLE_BASELINE"] == "hardware"
    if hardware:
        assert not (await rig.state())["observe"]
        await rig.table()
    elif os.environ["ASK_FLOWTABLE_BASELINE"] == "flowtable":
        await rig.table(hardware=False)
    await rig.exchange(4096, promiscuous=False)
    assert (await rig.state())["entries"] == (2 if hardware else 0)


async def test_flowtable_offload_reference_and_lifecycle(rig):
    r = rig
    from _ioctl import CDX_CTRL_DPA_SET_PARAMS, SIZEOF_CDX_CTRL_SET_DPA_PARAMS
    from test_fci_netlink_caps import _nl_header_and_err
    for fcode in [0xFFFF, 0x0316]:  # unknown command and IPv4 reset
        reply = await r.target.fci_send(r.session, fcode=fcode, length=0)
        assert _nl_header_and_err(reply) == (2, -errno.EOPNOTSUPP), reply
    reply = await r.target.ioctl_send(r.session, "/dev/cdx_ctrl", CDX_CTRL_DPA_SET_PARAMS,
                                     bytes(SIZEOF_CDX_CTRL_SET_DPA_PARAMS))
    assert reply["errno"] == errno.EOPNOTSUPP, reply
    await r.exchange()  # ordinary routing, no flowtable
    assert (await r.state())["entries"] == 0
    await r.table(hardware=False, counter=True)
    await r.exchange()
    assert (await r.state())["entries"] == 0
    await r.delete_table()
    await r.clear_ct()
    await r.table(counter=True)
    before = await r.state()
    await r.exchange()
    rejected = await r.wait(lambda s: s["rejects"] > before["rejects"])
    assert rejected["entries"] == 0 and rejected["installs"] == before["installs"], rejected
    r.record("counter-declined", rejected)
    await r.delete_table()
    await r.clear_ct()
    await r.table()
    await r.exchange()
    if (await r.state())["observe"]:
        state = await r.wait(lambda s: s["validated"] >= 2)
        assert state["entries"] == state["installs"] == 0
        r.record("observe", state)
        return
    installed = await r.wait(lambda s: s["entries"] == 2)
    assert all(flow["mtu"] == "1200" for flow in installed["flows"]), installed
    before = {dev: await kernel_rx_packets(r.target, r.session, dev) for dev in [TARGET_LAN_IF, TARGET_WAN_IF]}
    baseline = {flow["in"]: int(flow["packets"]) for flow in installed["flows"]}
    from scapy.all import AsyncSniffer, Ether, IP, UDP, wrpcap
    capture_ready = threading.Event()
    sniffer = AsyncSniffer(iface=r.wan_if, filter=f"udp port {DPORT}", store=True,
                          started_callback=capture_ready.set)
    sniffer.start()
    try:
        assert await asyncio.to_thread(capture_ready.wait, 5), "endpoint capture did not start"
        report = await r.exchange(512)
    finally:
        packets = sniffer.stop()
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        wrpcap(str(ARTIFACTS / "hardware-udp.pcap"), packets)
    final = await r.state()
    after = {dev: await kernel_rx_packets(r.target, r.session, dev) for dev in before}
    for flow in final["flows"]:
        assert int(flow["packets"]) - baseline[flow["in"]] == 512, (installed, final)
    for dev in before:
        assert 0 <= after[dev] - before[dev] <= 64, (dev, before, after)
    requests = [p for p in packets if IP in p and UDP in p and p[IP].src == r.lan_ip and p[UDP].dport == DPORT]
    assert len(requests) == 512
    for p in requests:
        assert p[IP].ttl == 63 and p[IP].ihl == 5
        assert p[Ether].src == r.dut_wan_mac and p[Ether].dst == r.wan_mac
        saved = p[IP].chksum
        copy = p[IP].copy(); del copy.chksum
        assert IP(bytes(copy)).chksum == saved
        udp = p[IP].copy(); saved_udp = udp[UDP].chksum; del udp[UDP].chksum
        assert IP(bytes(udp))[UDP].chksum == saved_udp
    r.record("hardware", {"installed": installed, "final": final, "software_rx_before": before,
                          "software_rx_after": after, "exchange": report})
    await r.exchange(32, payload_size=8)
    short_packets = await r.state()
    for old, new in zip(final["flows"], short_packets["flows"], strict=True):
        assert old["cookie"] == new["cookie"]
        assert int(new["packets"]) - int(old["packets"]) == 32
        assert int(new["bytes"]) - int(old["bytes"]) == 32 * 60  # includes Ethernet padding
    r.record("short-packets", {"before": final, "after": short_packets})
    # Three repeated cycles exercise unbind/rebind and resource return under traffic.
    for _ in range(3):
        received = len(r.echo.received)
        traffic = asyncio.create_task(r.exchange(256))
        deadline = time.monotonic() + 10
        while len(r.echo.received) < received + 16 and not traffic.done():
            assert time.monotonic() < deadline, "teardown traffic did not start"
            await asyncio.sleep(0.01)
        try:
            removed = await r.delete_table()
        finally:
            await traffic
        assert removed["quarantine"] == removed["errors"] == 0, removed
        await r.exchange()
        assert (await r.state())["entries"] == 0
        await r.clear_ct()
        await r.table()
        await r.exchange()
        await r.wait(lambda s: s["entries"] == 2)
    # Active traffic spans two default 30-second UDP flowtable timeouts.
    end = time.monotonic() + 65
    while time.monotonic() < end:
        await r.exchange(16)
        assert (await r.state())["entries"] == 2
        await asyncio.sleep(2)
    expired = await r.wait(lambda s: s["entries"] == 0, timeout=40)
    assert expired["quarantine"] == expired["errors"] == 0
    r.record("idle-expiry", expired)


async def test_flowtable_offload_same_tuple_exceptions(rig):
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("exception handling requires installed hardware")
    await r.table()
    await r.exchange()
    await r.wait(lambda s: s["entries"] == 2)
    before = await r.state()
    await r.exchange(32, payload_size=8)
    r.record("exception-short-packets", {"before": before, "after": await r.state()})
    script = f'''
import json, socket, struct
from scapy.all import Ether, IP, UDP, ICMP, Raw, IPOption, fragment, sendp, srp1, getmacbyip
iface = {LAN_NIC!r}
src, dst = {r.lan_ip!r}, {WAN_IP!r}
sport, dport = {SPORT}, {DPORT}
gateway = getmacbyip({r.lan_gateway!r})
assert gateway
eth = Ether(dst=gateway)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, sport)); s.settimeout(3)
s.setsockopt(socket.SOL_IP, getattr(socket, "IP_RECVTTL", 12), 1)
base = IP(src=src, dst=dst, ttl=64)/UDP(sport=sport, dport=dport)
results = {{}}
for name, pkt, icmp_type, icmp_code in [
    ('ttl', IP(src=src,dst=dst,ttl=1)/UDP(sport=sport,dport=dport)/Raw(b'ASK-expired'), 11, 0),
    ('mtu', IP(src=src,dst=dst,ttl=64,flags='DF')/UDP(sport=sport,dport=dport)/Raw(b'M'*1250), 3, 4),
]:
    answer = srp1(eth/pkt, iface=iface, timeout=3, verbose=False)
    assert answer is not None and ICMP in answer, (name, answer)
    assert (answer[ICMP].type, answer[ICMP].code) == (icmp_type, icmp_code), answer.summary()
    if name == 'mtu': assert answer[ICMP].nexthopmtu == 1200, answer.show(dump=True)
    results[name] = answer.summary()
for name, packets, payload in [
    ('options', [IP(src=src,dst=dst,ttl=64,options=[IPOption(b'\\x01'*4)])/UDP(sport=sport,dport=dport)/Raw(b'ASK-options')], b'ASK-options'),
    ('fragments', fragment(base/Raw(b'ASK-fragments'.ljust(1024,b'.')), fragsize=512), b'ASK-fragments'.ljust(1024,b'.')),
]:
    sendp([eth/p for p in packets], iface=iface, verbose=False)
    data, anc, flags, addr = s.recvmsg(4096, 128)
    assert data == payload and addr == (dst, dport), (name, data, addr)
    ttl = [struct.unpack('i', v)[0] for level, kind, v in anc if level == socket.SOL_IP and kind == socket.IP_TTL]
    assert ttl == [63], (name, ttl)
    results[name] = len(data)
s.close()
print(json.dumps(results))
'''
    result = await lan_run_python(r.lan, script, timeout=25, label="flowtable_exceptions")
    assert result.rc == 0, result.stdout
    assert r.echo.received[b"ASK-options"] == 1
    assert r.echo.received[b"ASK-fragments".ljust(1024, b".")] == 1
    assert not r.echo.received[b"ASK-expired"] and not r.echo.received[b"M" * 1250]
    await r.exchange()
    r.record("exceptions", {"results": json.loads(result.stdout.strip()), "state": await r.state()})


async def test_flowtable_offload_add_failures(rig):
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("installation faults require hardware mode")
    for stage in [1, 2, 3]:
        result = await r.target.fs_write(r.session, "/sys/module/cdx/parameters/flowtable_fail_stage", str(stage))
        assert result["errno"] == 0, result
        for attempt in range(3):
            before = await r.state()
            await r.table()
            await r.exchange()
            remaining = (await read(r.target, r.session, "/sys/module/cdx/parameters/flowtable_fail_stage")).strip()
            if remaining == "0":
                break
            # RTNL contention deliberately declines admission before fault
            # injection. Native flowtable does not retry that installation;
            # a fresh connection is needed to exercise the requested stage.
            state = await r.state()
            assert state["busy"] > before["busy"] and state["invalidated"] == 0, state
            await r.delete_table()
            await r.clear_ct()
        assert remaining == "0", (stage, await r.state())
        # Native Netfilter may install the other direction: each accepted
        # direction is independent. The rejected request leaves no owned object.
        await r.wait(lambda s: s["rejects"] > before["rejects"])
        assert (await read(r.target, r.session, "/sys/module/cdx/parameters/flowtable_fail_stage")).strip() == "0"
        state = await r.delete_table()
        assert state["errors"] == state["quarantine"] == 0 and state["installs"] == state["deletes"], state
        await r.clear_ct()
        r.record(f"add-failure-{stage}", state)


@pytest.mark.parametrize("trigger", [os.environ.get("ASK_FLOWTABLE_INVALIDATION", "neighbour")])
async def test_flowtable_offload_invalidation(rig, trigger):
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("invalidation requires installed hardware")
    await r.table()
    await r.exchange()
    before = await r.wait(lambda s: s["entries"] == 2)
    assert trigger in {"neighbour", "barrier", "counter"}
    if trigger == "barrier":
        knob = "/proc/fm_ehash_hcsync_fail"
        result = await r.target.fs_write(r.session, knob, "2")
        assert result["errno"] == 0, result
        try:
            await r.delete_table()
            assert (await read(r.target, r.session, knob)).strip() == "armed=0"
        finally:
            result = await r.target.fs_write(r.session, knob, "0")
            assert result["errno"] == 0, result
    elif trigger == "counter":
        await r.nft(f"add flowtable inet {TABLE} fast {{ hook ingress priority 0; "
                    f"devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; counter; }}")
    else:
        await command(r.target, r.session, "ip", "neigh", "del", WAN_IP, "dev", TARGET_WAN_IF)
    state = await r.wait(lambda s: s["invalidation_done"] == 1 and s["entries"] == 0)
    assert state["invalidated"] == 1 and state["fatal"] == state["quarantine"] == 0
    assert state["errors"] - before["errors"] == (2 if trigger == "barrier" else 0)
    await r.exchange()
    assert (await r.state())["entries"] == 0
    r.record(f"invalidation-{trigger}", state)


async def terminal_stream(r, duration=12):
    """Keep sending across an intentional datapath stop; validate every echo.

    A terminal operation may interrupt delivery. Normal exchange() retains its
    zero-loss requirement and separately checks forwarding after healthy unload.
    """
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({r.lan_ip!r}, {SPORT})); s.settimeout(0.02)
first = 1 << 63
sent = first
received = set()
start = time.monotonic()
while time.monotonic() - start < {duration}:
    payload = struct.pack('!Q', sent) + b'ASK-terminal'.ljust(248, b'.')
    s.sendto(payload, ({WAN_IP!r}, {DPORT}))
    sent += 1
    try:
        data, addr = s.recvfrom(2048)
    except TimeoutError:
        pass
    else:
        assert addr == ({WAN_IP!r}, {DPORT}) and len(data) == 256
        sequence = struct.unpack('!Q', data[:8])[0]
        assert first <= sequence < sent and sequence not in received
        assert data[8:] == b'ASK-terminal'.ljust(248, b'.')
        received.add(sequence)
    time.sleep(0.005)
s.close()
print(json.dumps({{'sent': sent-first, 'received': len(received),
                  'duration': time.monotonic()-start}}))
'''
    result = await lan_run_python(r.lan, script, timeout=duration + 10, label="flowtable_terminal")
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip())


@pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TERMINAL") not in {"unload", "unlink"},
                    reason="explicit terminal lifecycle test; fresh boot required")
async def test_flowtable_offload_terminal(rig):
    r = rig
    kind = os.environ["ASK_FLOWTABLE_TERMINAL"]
    assert not (await r.state())["observe"]
    r.recovery_console = Console.target(log_path=str(ARTIFACTS / "terminal-uart.log"))
    con = r.recovery_console
    await asyncio.to_thread(con.login, "root", None)
    # FCI depends on CDX, but has no active controller in this boot. Remove
    # that dependency before the measured CDX unload; never force removal.
    await console_command(con, "rmmod", "fci")
    await r.table()
    await r.exchange(128)
    initial = await r.wait(lambda s: s["entries"] == 2)
    assert all(int(f["packets"]) > 0 for f in initial["flows"]), initial
    baseline = len(r.echo.received)
    traffic = asyncio.create_task(terminal_stream(r))
    unloaded = False
    try:
        deadline = time.monotonic() + 5
        while len(r.echo.received) < baseline + 32:
            assert not traffic.done(), "traffic stopped before terminal operation"
            assert time.monotonic() < deadline, "terminal stream did not reach WAN"
            await asyncio.sleep(0.05)
        live = await r.state()
        assert live["entries"] == 2 and all(
            int(after["packets"]) > int(before["packets"])
            for before, after in zip(initial["flows"], live["flows"])
        ), live
        r.record(f"{kind}-live", live)
        if kind == "unlink":
            # Read physical receive-port enable state, not netdev carrier:
            # fixed links can retain carrier while classification is stopped.
            from _ioctl import _IOR
            port_script = f'''
import fcntl, json, os
states = {{}}
for port in (6, 7):
    fd = os.open('/dev/fm0-port-rx%d' % port, os.O_RDWR)
    try:
        value = bytearray(1)
        fcntl.ioctl(fd, {_IOR(0xe1, 70 + 44, 1)}, value)
        states[str(port)] = value[0]
    finally:
        os.close(fd)
print(json.dumps(states))
'''
            before_ports = await console_python(con, port_script)
            assert json.loads(before_ports["stdout"]) == {"6": 1, "7": 1}
            await console_python(con, "from pathlib import Path; Path('/sys/module/cdx/parameters/flowtable_fail_unlink').write_text('1')")
            await console_command(con, "nft", "delete", "table", "inet", TABLE)
            deadline = time.monotonic() + 10
            while True:
                result = await console_command(con, "cat", "/proc/cdx_flowtable")
                stopped = status_text(result["stdout"].strip())
                if stopped["invalidation_done"]:
                    break
                assert time.monotonic() < deadline, stopped
                await asyncio.sleep(0.1)
            assert stopped["fatal"] == stopped["invalidated"] == 1, stopped
            assert stopped["errors"] - live["errors"] == 1, stopped
            assert stopped["entries"] == stopped["bindings"] == stopped["quarantine"] == 0, stopped
            ports = await console_python(con, port_script)
            assert json.loads(ports["stdout"]) == {"6": 0, "7": 0}, ports
            knob = await console_command(con, "cat", "/sys/module/cdx/parameters/flowtable_fail_unlink")
            assert knob["stdout"].strip() == "N", knob
            log = (await console_command(con, "dmesg"))["stdout"]
            assert log.count("retaining possibly linked key") == 1, log
            assert "hardware stopped after unproven deletion; reboot required" in log
            r.record("unlink-stopped", {"state": stopped, "ports": json.loads(ports["stdout"]), "dmesg": log})
            # Allow already queued datagrams to arrive, then prove ingress
            # remains stopped while the LAN sender is still running.
            await asyncio.sleep(0.2)
            received = len(r.echo.received)
            assert not traffic.done(), "traffic ended before stopped-port observation"
            await asyncio.sleep(1)
            assert len(r.echo.received) == received, "traffic passed stopped classifier ports"
        else:
            await console_command(con, "rmmod", "cdx", timeout=25)
            unloaded = True
        r.record(f"{kind}-traffic", await traffic)
    finally:
        # Await the finite LAN script before fixture cleanup uses its UART.
        try:
            await traffic
        finally:
            if kind == "unlink" and not unloaded:
                await console_command(con, "rmmod", "cdx", timeout=25)
                unloaded = True
    absent = await console_command(con, "test", "-e", "/sys/module/cdx", check=False)
    assert absent["rc"] == 1, absent
    assert (await console_command(con, "test", "-e", "/proc/cdx_flowtable", check=False))["rc"] == 1
    await console_command(con, "nft", "delete", "table", "inet", TABLE, check=False)
    await r.clear_ct()
    await r.exchange(64)
    r.record(f"{kind}-complete", {"module_absent": True, "post_unload_echoes": 64,
                                "boot_id": await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")})

"""IPv4/UDP flowtable acceptance on the real DUT.

Run with make ask-test ASK_TEST_ARGS='-k flowtable_offload'.
Healthy invalidation can recover after complete flowtable detachment. Terminal
failure tests still require a fresh boot before using ASK again.
"""
from __future__ import annotations

import asyncio
import base64
from collections import Counter
import errno
import hashlib
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
from ask_orch.counters import kernel_tx_packets
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, kernel_rx_packets, lan_run_python

WAN_IP = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
SPORT = int(os.environ.get("ASK_FLOWTABLE_SPORT", "48270"))
DPORT = int(os.environ.get("ASK_FLOWTABLE_DPORT", "48271"))
TABLE = "ask_poc"
ARTIFACTS = Path(os.environ.get("ASK_FLOWTABLE_ARTIFACTS", "/tmp/ask-flowtable"))
# Per-boot floor for the cumulative counters health checks compare against;
# the rig fixture refreshes it for every test.
HEALTH_BASELINE = {"errors": 0}


async def read(agent, session, path):
    limit = 16 << 20 if path == "/proc/cdx_flowtable" else 1 << 20
    result = await agent.fs_read(session, path, max_bytes=limit)
    assert result.get("size", 0) < limit, (path, "truncated diagnostics")
    assert result["errno"] == 0, (path, result)
    return bytes.fromhex(result["content_hex"]).decode()


async def command(agent, session, *argv, check=True, timeout_ms=15000):
    result = await agent.exec_cmd(session, list(argv), timeout_ms=timeout_ms)
    if check:
        assert result["rc"] == 0, result
    return result


async def ct_bytes(r):
    """Bytes conntrack has accounted to the original direction of the flow.

    The first bytes= in an extended listing is the original direction; the
    second is the reply. Both the software fast path and a hardware delta land
    here, which is what makes the two agreeing on units observable at all."""
    listing = await command(r.target, r.session, "conntrack", "-L", "-p", r.proto,
                            "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                            "--sport", str(SPORT), "--dport", str(DPORT), "-o", "extended")
    counts = re.findall(r"bytes=(\d+)", listing["stdout"])
    assert counts, listing
    return int(counts[0])


async def upper_roundtrip(r, dev):
    """Exercise unsupported upper-device topology, restoring it through UART."""
    temporary = "askftupper"
    with Console.target(log_path=str(ARTIFACTS / "upper-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        links = json.loads((await console_command(con, "ip", "-j", "link", "show"))["stdout"])
        assert temporary not in {i["ifname"] for i in links}, links
        assert "master" not in next(i for i in links if i["ifname"] == dev), links
        await console_command(con, "ip", "link", "add", "name", temporary, "type", "bridge")
        try:
            return await console_command(con, "ip", "link", "set", "dev", dev, "master", temporary)
        finally:
            try:
                await console_command(con, "ip", "link", "set", "dev", dev, "nomaster")
            finally:
                await console_command(con, "ip", "link", "del", "dev", temporary)


async def console_command(console, *argv, check=True, timeout=20, resync=False):
    # BusyBox line editing can wrap and redraw the echoed command. Frame
    # actual output rather than relying on the console's echo stripping.
    #
    # `resync` is for a caller whose command is idempotent and who would rather
    # be told the framing was lost than have the test fail on line noise. The
    # UART has no flow control and the DUT logs `ttyS0: input overrun(s)` under
    # a fast writer: characters vanish mid-word and the marker comes back
    # misspelled, which is indistinguishable from the command never running.
    # Such a caller gets rc None, resynchronises the prompt and decides for
    # itself; everyone else still fails loudly, because for a mutating command
    # "it is unknown whether this ran" is not a result worth continuing on.
    assert all("\n" not in arg for arg in argv), "use console_python for scripts"
    marker = f"__ASK_OUTPUT_{time.monotonic_ns()}__"
    cmd = f"printf '\\n%s\\n' {shlex.quote(marker)}; {shlex.join(argv)}"
    try:
        result = await asyncio.to_thread(console.run, cmd, timeout)
    except TimeoutError as error:
        if not resync:
            raise
        await asyncio.to_thread(console.sync_prompt)
        return {"rc": None, "stdout": str(error)}
    match = re.search(r"(?:^|\n)" + marker + r"\r?\n", result.stdout)
    if not match and resync:
        await asyncio.to_thread(console.sync_prompt)
        return {"rc": None, "stdout": result.stdout}
    assert match, ("missing console output boundary", result.stdout)
    stdout = result.stdout[match.end():]
    if check:
        assert result.rc == 0, stdout
    return {"rc": result.rc, "stdout": stdout}


# Other writers share the UART with our command: the managed service's
# console-fallback log lines, and kernel messages at console level (failslab
# stack dumps, the Wi-Fi driver logging a client associating with the test
# AP, and printk's own "messages dropped" notice when it falls behind). Each is
# a whole line, but it can start anywhere, including in the middle of the
# controller's JSON, so it is removed wherever it lands. None of these shapes
# can occur inside that JSON.
CONSOLE_NOISE = re.compile(
    r"(?:(?:ask-flowtable\[\d+\]: |\[\s*\d+\.\d+\] )[^\n]*|\*\* \d+ printk messages dropped \*\*)\r?\n?")


def console_json(text):
    """Decode controller JSON from UART output, minus interleaved console lines.

    The raw UART transcript still records those lines for diagnosis.
    """
    return json.loads(CONSOLE_NOISE.sub("", text))


async def flowtable_json(console, *args):
    """Run the controller over the UART and decode its JSON."""
    result = await console_command(console, "/usr/sbin/ask-flowtable", *args)
    return console_json(result["stdout"])


async def console_python(console, script, *, timeout=20, attempts=3):
    # The physical UART can lose characters in long input lines, so stage short
    # chunks and verify the exact script before executing any test operation.
    # A dropped character corrupts the staged text, not the console, so retry
    # the staging rather than failing the test on the line noise: decoding each
    # chunk as it arrived turned one lost character into "base64: invalid
    # input" and lost the whole test. Accumulate the encoded text, decode once,
    # and let the digest decide whether it survived.
    encoded = base64.b64encode(script.encode()).decode()
    wanted = hashlib.sha256(script.encode()).hexdigest()
    path = f"/tmp/ask_ft_{time.monotonic_ns()}.py"
    staged = f"{path}.b64"
    last_failure = None
    try:
        for attempt in range(attempts):
            # Tolerant, and it has to be: this is the first command of each
            # attempt, so a boundary lost to an overrun here used to raise
            # before the retry loop it sits inside could do anything. `rm -f`
            # is idempotent, and a delete that silently did not happen leaves
            # stale text the digest below catches on this same pass.
            try:
                await console_command(console, "rm", "-f", path, staged, resync=True)
                for offset in range(0, len(encoded), 144):
                    await console_command(console, "sh", "-c",
                                          f"printf %s {shlex.quote(encoded[offset:offset + 144])} "
                                          f">> {shlex.quote(staged)}")
                decoded = await console_command(console, "sh", "-c",
                                                f"base64 -d {shlex.quote(staged)} > {shlex.quote(path)}",
                                                check=False)
                digest = await console_command(console, "sha256sum", path, check=False)
                if decoded["rc"] == digest["rc"] == 0 and digest["stdout"].split()[:1] == [wanted]:
                    break
                last_failure = (decoded, digest)
            except (AssertionError, TimeoutError) as error:
                # Kernel messages can split either output marker. Only the
                # private staging files have changed: discard and restage.
                # Execution stays outside this retry boundary because an
                # unacknowledged test operation may already have happened.
                last_failure = repr(error)
                await asyncio.to_thread(console.sync_prompt)
        else:
            pytest.fail(f"UART staging failed {attempts} times: {last_failure}")
        return await console_command(console, "python3", path, timeout=timeout)
    finally:
        # Tolerant for the same reason, and with less at stake: this runs on
        # the way out, the rootfs is an initramfs that forgets /tmp at the next
        # boot, and a cleanup that lost its framing must not turn a passing
        # test into an error.
        await console_command(console, "rm", "-f", path, staged, resync=True)


# Row kinds the proc file emits, by their leading word. Everything else is a
# single "key value" counter. A row kind always yields a list, present and
# empty when nothing of that kind exists, so a caller never has to guess
# whether an absent key means none or means an older adapter.
STATUS_ROWS = {"flow": "flows", "session": "sessions", "vlan": "vlans",
               "tunnel": "tunnels", "mcast": "mcast", "mroute": "mroute"}


def status_text(text):
    state = {name: [] for name in STATUS_ROWS.values()}
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind in STATUS_ROWS:
            state[STATUS_ROWS[kind]].append(
                dict(item.split("=", 1) for item in rest.split()))
        else:
            parts = line.split()
            assert len(parts) == 2, f"unexpected /proc/cdx_flowtable line: {line!r}"
            key, value = parts
            state[key] = int(value) if value.isdecimal() else value
    return state


class Echo(asyncio.DatagramProtocol):
    def __init__(self):
        self.received = Counter()
        self.record_payloads = True
        self.packets = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.packets += 1
        if self.record_payloads:
            self.received[data] += 1
        self.transport.sendto(data, addr)


class Rig:
    proto = "udp"

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

    def ruleset(self, hardware=True, counter=False, mark=None):
        # A mark is set in the same rule that offers the flow, so admission
        # sees it: it is how a test asks for a hardware decline that owes
        # nothing to fault injection.
        marking = f"ct mark set {mark:#x}" if mark else ""
        return f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }};
 {"flags offload;" if hardware else ""} {"counter;" if counter else ""} }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {self.lan_ip} ip daddr {WAN_IP} {self.proto} sport {SPORT} {self.proto} dport {DPORT} {marking} flow add @fast
 }}
}}'''

    async def table(self, hardware=True, counter=False, mark=None):
        await self.nft(self.ruleset(hardware, counter, mark))
        if hardware:
            await self.wait(lambda s: s["bindings"] == 2)

    async def delete_table(self, timeout=10):
        # Unbinding retires every hardware entry one delete at a time before
        # nft returns, so a caller holding a full table passes a longer bound.
        await command(self.target, self.session, "nft", "delete", "table", "inet", TABLE,
                      check=False, timeout_ms=max(15000, timeout * 1000))
        return await self.wait(lambda s: not s["bindings"] and not s["entries"], timeout=timeout)

    async def clear_ct(self):
        await command(self.target, self.session, "conntrack", "-D", "-p", self.proto,
                      "--orig-src", self.lan_ip, "--orig-dst", WAN_IP,
                      "--sport", str(SPORT), "--dport", str(DPORT), check=False)

    async def run_peer(self, script, **kwargs):
        netns = getattr(self, "peer_netns", None)
        if netns:
            script = ("import os\n" +
                      f"with open('/var/run/netns/' + {netns!r}, 'rb') as ns:\n" +
                      "    os.setns(ns.fileno(), os.CLONE_NEWNET)\n" + script)
        return await lan_run_python(self.lan, script, **kwargs)

    async def exchange(self, count=64, interval=0.003, payload_size=256, promiscuous=True,
                       sport=SPORT, ignore_pmtu=False):
        assert payload_size >= 8
        peer_if = getattr(self, "peer_if", LAN_NIC)
        # Driver-level counters belong to the physical NIC. A VLAN device has
        # no ethtool statistics at all, so a tagged peer has to name the port
        # underneath it for the link health check while still capturing frames
        # on the device that terminates the tag.
        link_if = getattr(self, "peer_link", peer_if)
        peer_mac = getattr(self, "peer_mac", self.lan_mac)
        gateway_mac = getattr(self, "peer_gateway_mac", self.dut_lan_mac)
        ttl = 64 - getattr(self, "forward_hops", 1)
        first = self.sequence
        self.sequence += count
        script = f'''
import json, socket, struct, subprocess, time
def link_stats():
    text = subprocess.check_output(['ethtool', '-S', {link_if!r}], text=True)
    return {{k.strip(): int(v.strip()) for line in text.splitlines() if ':' in line
            for k, v in [line.split(':', 1)] if v.strip().isdigit() and
            any(word in k for word in ('error', 'dropped', 'no_buffer', 'no_dma', 'timeout'))}}
link_before = link_stats()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
s.setsockopt(socket.SOL_IP, getattr(socket, "IP_RECVTTL", 12), 1)
if {ignore_pmtu!r}:
    s.setsockopt(socket.SOL_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 3)  # IP_PMTUDISC_PROBE
s.settimeout(2)
s.bind(({self.lan_ip!r}, {sport}))
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(({peer_if!r}, 0)); raw.settimeout(2)
if {promiscuous!r}:
    raw.setsockopt(263, 1, struct.pack('IHH8s', socket.if_nametoindex({peer_if!r}), 1, 0, b''))
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
    assert ttl == [{ttl}], (n, ttl)
    while True:
        frame = raw.recv(65535)
        if len(frame) < 42 or frame[23] != socket.IPPROTO_UDP or frame[26:30] != socket.inet_aton({WAN_IP!r}):
            continue
        ihl = (frame[14] & 15) * 4
        start = 14 + ihl
        if struct.unpack('!HH', frame[start:start+4]) != ({DPORT}, {sport}):
            continue
        assert frame[start+8:start+8+len(payload)] == payload, (n, 'duplicate or unexpected frame', frame.hex())
        assert frame[:6] == bytes.fromhex({peer_mac.replace(':', '')!r})
        assert frame[6:12] == bytes.fromhex({gateway_mac.replace(':', '')!r})
        assert ihl == 20 and frame[22] == {ttl}
        break
    received.append(n)
    time.sleep({interval})
s.close()
raw.close()
print(json.dumps({{'first': received[0], 'last': received[-1], 'count': len(received)}}))
'''
        result = await self.run_peer(script, timeout=max(15, count * interval + 10), label="flowtable_echo")
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


async def stop_boot_daemon():
    """The offload service is default-on: a normal boot has already installed
    the catch-all policy, so the backend starts bound. Controlled tests own the
    policy themselves, so they stop the boot daemon first -- the init script
    kills it and removes its table, draining the hardware to an unbound state.
    Every rig does this itself rather than rely on an earlier test having done
    it, so a test run on its own after a boot sees the same start."""
    with Console.target(log_path=str(ARTIFACTS / "boot-daemon-stop.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        await console_command(con, "/etc/init.d/ask-flowtable", "stop", check=False, timeout=45)


@pytest_asyncio.fixture
async def rig(target_agent, aiohttp_session, lan, splat_window, request):
    r = Rig()
    r.proto = getattr(request, "param", "udp")
    assert r.proto in {"udp", "tcp"}
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    await stop_boot_daemon()
    initial = await r.state()
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    # The adapter's error count is cumulative for the boot and deliberately
    # never reset, so whatever earlier tests already accounted for is this
    # test's floor. Only errors raised from here are its own.
    HEALTH_BASELINE["errors"] = initial["errors"]
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
        nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", r.proto, "--sport", str(SPORT), "--dport", str(DPORT), "-j", "ACCEPT"]
        await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
        cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *nat]))
        await r.clear_ct()
        old_acct = (await read(r.target, r.session, "/proc/sys/net/netfilter/nf_conntrack_acct")).strip()
        await command(r.target, r.session, "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
        cleanup.append((r.target, ["sysctl", "-w", f"net.netfilter.nf_conntrack_acct={old_acct}"]))
        if r.proto == "udp":
            transport, r.echo = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=(WAN_IP, DPORT))
        r.record("fixture", {"lan": r.lan_ip, "wan": WAN_IP, "sport": SPORT, "dport": DPORT,
                             "lan_mac": lan_mac, "wan_mac": wan_mac, "initial": initial,
                             "protocol": r.proto,
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
        except (Exception, pytest.fail.Exception) as error:
            failures.append(str(error))
        if hasattr(r, "lan_ip"):
            try:
                if r.recovery_console:
                    await console_command(r.recovery_console, "conntrack", "-D", "-p", r.proto,
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
for module, name in [('ask_flowtable', 'flowtable_fail_stage'), ('cdx', 'flowtable_fail_unlink')]:
    path = Path('/sys/module') / module / 'parameters' / name
    if path.exists():
        path.write_text('0')
""")
            else:
                result = await r.target.fs_write(r.session, "/sys/module/ask_flowtable/parameters/flowtable_fail_stage", "0")
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
    # A counter-enabled hardware table is admitted, and what reaches conntrack
    # accounting is the frame Netfilter counts rather than the frame the
    # classifier saw. A 256-byte payload is 298 bytes on the wire and 284 once
    # the Ethernet header the software path never sees is taken off, so both
    # paths agree and the total is the same whichever forwarded it.
    await r.table(counter=True)
    await r.clear_ct()
    payload, count = 256, 64
    expected = count * (payload + 8 + 20)
    # The whole flow, not a delta around a baseline. The first packets cross in
    # software and the rest in hardware, and the total is the same either way --
    # which is the point: the two now agree on what a frame is worth, so no part
    # of this has to know where the boundary fell.
    await r.exchange(count, payload_size=payload)
    counted = await r.wait(lambda s: s["entries"] == 2)
    total, deadline = None, time.monotonic() + 30
    while time.monotonic() < deadline:
        total = await ct_bytes(r)
        if total >= expected:
            break
        await asyncio.sleep(0.5)
    assert total == expected, (total, expected, counted, await r.state())
    r.record("counter-accounted", {"bytes": total, "expected": expected, "state": await r.state()})
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
import json, socket, struct, time
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
# Headers Linux would discard must not be forwarded by the entry for their tuple.
for name, pkt in [
    ('bad_checksum', IP(src=src,dst=dst,ttl=64,chksum=0x1234)/UDP(sport=sport,dport=dport)/Raw(b'ASK-badsum')),
    ('version', IP(src=src,dst=dst,ttl=64,version=5)/UDP(sport=sport,dport=dport)/Raw(b'ASK-version')),
    ('version15', IP(src=src,dst=dst,ttl=64,version=15)/UDP(sport=sport,dport=dport)/Raw(b'ASK-version15')),
]:
    sendp(eth/pkt, iface=iface, verbose=False)
    results[name] = 'sent'
time.sleep(0.5)
s.close()
print(json.dumps(results))
'''
    result = await lan_run_python(r.lan, script, timeout=25, label="flowtable_exceptions")
    assert result.rc == 0, result.stdout
    assert r.echo.received[b"ASK-options"] == 1
    assert r.echo.received[b"ASK-fragments".ljust(1024, b".")] == 1
    assert not r.echo.received[b"ASK-expired"] and not r.echo.received[b"M" * 1250]
    assert not any(r.echo.received[p] for p in (b"ASK-badsum", b"ASK-version", b"ASK-version15"))
    await r.exchange()
    r.record("exceptions", {"results": json.loads(result.stdout.strip()), "state": await r.state()})


async def ct_listing(r):
    """The test flow's conntrack line as `conntrack -L -o id` prints it.

    The third column is the remaining timeout in seconds, the id names this
    conntrack rather than its tuple, and a flow hardware holds prints as
    [HW_OFFLOAD], which conntrack(8) shows in place of [OFFLOAD]."""
    result = await command(r.target, r.session, "conntrack", "-L", "-p", r.proto,
                           "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                           "--sport", str(SPORT), "--dport", str(DPORT), "-o", "id")
    lines = [line for line in result["stdout"].splitlines() if line.startswith(r.proto + " ")]
    assert len(lines) == 1, result
    return lines[0]


async def test_flowtable_offload_conntrack_timeout_extension(rig):
    """A packet that still reaches conntrack after admission cuts the offloaded
    conntrack's timeout back to its protocol's. The flowtable GC must lift it
    again on its next pass, or the conntrack expires under a flow hardware is
    still carrying and its retirement takes the hardware flow with it.

    The stream timeout is shortened to ten seconds so the window fits in a
    test, and one same-tuple frame software has to handle -- TTL 1, which
    Linux answers with Time Exceeded only after conntrack has seen it -- resets
    the conntrack to it. Thirty seconds of hardware-only traffic follow, three
    of those timeouts, with a table dump every round: a dump evicts any
    expired conntrack it walks past, so one left to lapse dies inside the
    window instead of waiting for conntrack's own GC to find it."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("timeout extension requires installed hardware")
    await r.table()
    opened = time.monotonic()
    await r.exchange()
    installed = await r.wait(lambda s: s["entries"] == 2)
    admitted = await ct_listing(r)
    assert "[HW_OFFLOAD]" in admitted, admitted
    identity = re.search(r"\bid=(\d+)", admitted)[1]
    knob = "net.netfilter.nf_conntrack_udp_timeout_stream"
    old = (await read(r.target, r.session, "/proc/sys/" + knob.replace(".", "/"))).strip()
    await command(r.target, r.session, "sysctl", "-w", f"{knob}=10")
    try:
        # udp_packet() applies the stream timeout only to a connection older
        # than two seconds; a younger one would get the unreplied timeout.
        await asyncio.sleep(max(0.0, 2.5 - (time.monotonic() - opened)))
        script = f'''
import json
from scapy.all import Ether, IP, UDP, ICMP, Raw, srp1
packet = IP(src={r.lan_ip!r}, dst={WAN_IP!r}, ttl=1)/UDP(sport={SPORT}, dport={DPORT})/Raw(b'ASK-ct-refresh')
answer = srp1(Ether(dst={r.dut_lan_mac!r})/packet, iface={LAN_NIC!r}, timeout=3, verbose=False)
assert answer is not None and ICMP in answer, answer
assert (answer[ICMP].type, answer[ICMP].code) == (11, 0), answer.summary()
print(json.dumps(answer.summary()))
'''
        result = await lan_run_python(r.lan, script, timeout=15, label="flowtable_ct_refresh")
        assert result.rc == 0, result.stdout
        assert not r.echo.received[b"ASK-ct-refresh"]
        before = await r.state()
        assert {f["cookie"] for f in before["flows"]} == {f["cookie"] for f in installed["flows"]}, before
        tx_before = await kernel_tx_packets(r.target, r.session, TARGET_LAN_IF)
        sent, rounds = 0, []
        window = time.monotonic() + 30
        while time.monotonic() < window:
            await r.exchange(16, promiscuous=False)
            sent += 16
            listing = await ct_listing(r)
            rounds.append({"seconds": round(time.monotonic() - window + 30, 1), "conntrack": listing})
            assert "[HW_OFFLOAD]" in listing and f"id={identity}" in listing.split(), rounds
            await asyncio.sleep(1)
        after = await r.state()
        tx_after = await kernel_tx_packets(r.target, r.session, TARGET_LAN_IF)
        r.record("ct-timeout-extension", {"refresh": result.stdout.strip(), "before": before,
                                          "after": after, "rounds": rounds, "sent": sent,
                                          "software_lan_tx": tx_after - tx_before})
        assert after["installs"] == before["installs"] and after["deletes"] == before["deletes"], (before, after)
        old_rows, new_rows = {f["in"]: f for f in before["flows"]}, {f["in"]: f for f in after["flows"]}
        assert after["entries"] == 2 and new_rows.keys() == old_rows.keys(), after
        for ingress, flow in new_rows.items():
            assert flow["cookie"] == old_rows[ingress]["cookie"], (before, after)
            assert int(flow["packets"]) - int(old_rows[ingress]["packets"]) == sent, (ingress, before, after)
        # Every reply crossed the LAN port; hardware carried all of them.
        assert 0 <= tx_after - tx_before <= 64 < sent, (tx_before, tx_after, sent)
        # The timeout itself is not observable: neither /proc/net/nf_conntrack
        # nor ctnetlink reports one for an offloaded conntrack. Surviving three
        # stream timeouts of dumps that evict an expired entry is the proof.
    finally:
        await command(r.target, r.session, "sysctl", "-w", f"{knob}={old}")


async def test_flowtable_offload_add_failures(rig):
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("installation faults require hardware mode")
    for stage in [1, 2, 3]:
        result = await r.target.fs_write(r.session, "/sys/module/ask_flowtable/parameters/flowtable_fail_stage", str(stage))
        assert result["errno"] == 0, result
        for attempt in range(3):
            before = await r.state()
            await r.table()
            await r.exchange()
            remaining = (await read(r.target, r.session, "/sys/module/ask_flowtable/parameters/flowtable_fail_stage")).strip()
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
        assert (await read(r.target, r.session, "/sys/module/ask_flowtable/parameters/flowtable_fail_stage")).strip() == "0"
        state = await r.delete_table()
        assert state["errors"] == state["quarantine"] == 0 and state["installs"] == state["deletes"], state
        await r.clear_ct()
        r.record(f"add-failure-{stage}", state)


async def test_flowtable_offload_rearm(rig):
    """Recover after upper-device and routing-policy changes and a retried delete barrier."""
    r = rig
    initial = await r.state()
    if initial["observe"]:
        pytest.skip("rearm proof requires installed hardware")
    original_mtu = (await read(r.target, r.session, f"/sys/class/net/{TARGET_LAN_IF}/mtu")).strip()
    rule_priority = "32001"
    rules = json.loads((await command(r.target, r.session, "ip", "-j", "rule", "show"))["stdout"])
    assert not any(rule.get("priority") == int(rule_priority) for rule in rules), rules
    rule_added = False
    boot_id = await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")
    await r.table()
    await r.exchange(128, promiscuous=False)
    await r.wait(lambda s: s["entries"] == 2)
    try:
        for cycle, trigger in enumerate(("device", "rule", "barrier"), 1):
            before = await r.state()
            traffic = None
            knob = "/proc/fm_ehash_hcsync_fail"
            try:
                if trigger == "device":
                    received = len(r.echo.received)
                    traffic = asyncio.create_task(terminal_stream(r, duration=6))
                    deadline = time.monotonic() + 5
                    while len(r.echo.received) < received + 16:
                        assert not traffic.done() and time.monotonic() < deadline
                        await asyncio.sleep(0.02)
                    await upper_roundtrip(r, TARGET_LAN_IF)
                elif trigger == "rule":
                    await command(r.target, r.session, "ip", "rule", "add", "pref", rule_priority,
                                  "from", "198.18.254.0/24", "table", "main")
                    rule_added = True
                else:
                    result = await r.target.fs_write(r.session, knob, "2")
                    assert result["errno"] == 0, result
                    await r.delete_table()
                    assert (await read(r.target, r.session, knob)).strip() == "armed=0"
                invalid = await r.wait(lambda s: s["invalidation_done"] == 1 and s["entries"] == 0)
                assert invalid["invalidated"] == 1 and invalid["fatal"] == invalid["quarantine"] == 0
                assert invalid["installs"] == before["installs"]
                assert invalid["rearms"] == before["rearms"]
                assert invalid["errors"] - before["errors"] == (2 if trigger == "barrier" else 0)
                assert invalid["bindings"] == (0 if trigger == "barrier" else 2)
                assert invalid["rearm_ready"] == (1 if trigger == "barrier" else 0)
            finally:
                if traffic:
                    r.record("rearm-transition", await traffic)
                if trigger == "barrier":
                    result = await r.target.fs_write(r.session, knob, "0")
                    assert result["errno"] == 0, result
            # An MTU event must not turn an unrelated global invalidation into
            # automatic recovery, including after all directions have drained.
            try:
                await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_LAN_IF, "mtu", "1400")
            finally:
                await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_LAN_IF, "mtu", original_mtu)
            held = await r.state()
            assert held["invalidated"] == held["invalidation_done"] == 1, held
            assert held["installs"] == before["installs"] and held["rearms"] == before["rearms"], held
            software_before = await kernel_tx_packets(r.target, r.session, TARGET_LAN_IF)
            await r.exchange(64, promiscuous=False)
            software_after = await kernel_tx_packets(r.target, r.session, TARGET_LAN_IF)
            blocked = await r.state()
            assert software_after - software_before >= 64
            assert blocked["entries"] == 0 and blocked["installs"] == before["installs"]
            assert blocked["invalidated"] == 1 and blocked["rearms"] == before["rearms"]
            if trigger == "device":
                # Hook removal alone leaves cached Linux flows. Such a table
                # must not reopen hardware admission, even with zero bindings.
                await r.nft(f"delete flowtable inet {TABLE} fast {{ "
                            f"devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; }}")
                await r.wait(lambda s: s["bindings"] == 0 and s["rearm_ready"] == 1)
                refused = await command(r.target, r.session, "nft",
                                        f"add flowtable inet {TABLE} fast {{ hook ingress priority 0; "
                                        f"devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}",
                                        check=False)
                assert refused["rc"] != 0 and "Operation not supported" in refused["stderr"], refused
                same_table = await r.state()
                assert same_table["bindings"] == same_table["entries"] == 0
                assert same_table["invalidated"] == 1 and same_table["rearms"] == before["rearms"]
                r.record("rearm-populated-refused", {"state": same_table, "nft": refused})
            await r.delete_table()
            detached = await r.wait(lambda s: s["rearm_ready"] == 1)
            assert detached["bindings"] == detached["entries"] == detached["quarantine"] == 0
            await r.clear_ct()
            await r.table()
            rearmed = await r.state()
            assert rearmed["rearms"] == initial["rearms"] + cycle
            assert rearmed["invalidated"] == rearmed["invalidation_done"] == rearmed["rearm_ready"] == 0
            assert rearmed["errors"] == invalid["errors"] and rearmed["fatal"] == 0
            await r.exchange(128, promiscuous=False)
            installed = await r.wait(lambda s: s["entries"] == 2)
            for flow in installed["flows"]:
                expected_mtu = 1200
                assert int(flow["mtu"]) == expected_mtu, installed
            tx_before = {d: await kernel_tx_packets(r.target, r.session, d)
                         for d in (TARGET_LAN_IF, TARGET_WAN_IF)}
            report = await r.exchange(512, promiscuous=False)
            final = await r.state()
            tx_after = {d: await kernel_tx_packets(r.target, r.session, d) for d in tx_before}
            packets = {f["in"]: int(f["packets"]) for f in installed["flows"]}
            assert final["entries"] == 2 and final["installs"] == installed["installs"]
            for flow in final["flows"]:
                assert int(flow["packets"]) - packets[flow["in"]] == 512, (installed, final)
            for dev in tx_before:
                assert 0 <= tx_after[dev] - tx_before[dev] <= 64, (dev, tx_before, tx_after)
            assert final["errors"] == invalid["errors"]
            assert final["invalidated"] == final["fatal"] == final["quarantine"] == 0
            assert await read(r.target, r.session, "/proc/sys/kernel/random/boot_id") == boot_id
            r.record(f"rearm-{trigger}", {"before": before, "invalid": invalid, "blocked": blocked,
                     "software_tx_delta": software_after - software_before, "detached": detached,
                     "rearmed": rearmed, "installed": installed, "final": final,
                     "software_tx_before": tx_before, "software_tx_after": tx_after,
                     "exchange": report, "boot_id": boot_id})
    finally:
        try:
            await r.delete_table()
        finally:
            if rule_added:
                await command(r.target, r.session, "ip", "rule", "del", "pref", rule_priority,
                              "from", "198.18.254.0/24", "table", "main")


@pytest.mark.parametrize("trigger", [os.environ.get("ASK_FLOWTABLE_INVALIDATION", "neighbour")])
async def test_flowtable_offload_invalidation(rig, trigger):
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("invalidation requires installed hardware")
    await r.table()
    await r.exchange()
    before = await r.wait(lambda s: s["entries"] == 2)
    assert trigger in {"neighbour", "barrier"}
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
    else:
        await command(r.target, r.session, "ip", "neigh", "del", WAN_IP, "dev", TARGET_WAN_IF)
    state = await r.wait(lambda s: s["entries"] == 0 and (
        s["neighbour_invalidations"] > before["neighbour_invalidations"] if trigger == "neighbour"
        else s["invalidation_done"] == 1))
    assert state["invalidated"] == int(trigger != "neighbour") and state["fatal"] == state["quarantine"] == 0
    assert state["handle_refs"] == state["neighbour_refs"] == 0, state
    assert state["errors"] - before["errors"] == (2 if trigger == "barrier" else 0)
    await r.exchange()
    if trigger != "neighbour":
        assert (await r.state())["entries"] == 0
    r.record(f"invalidation-{trigger}", state)


async def test_flowtable_offload_table_reload(rig):
    """A consumer reloads its ruleset by deleting its table and creating it
    again in one transaction, which is how `nft -f` with a flush and fw4 both
    apply a change. Netfilter binds the new flowtable while preparing and
    releases the old one only at commit, so for that instant two tables hold
    every port: the reload has to go through with hardware rather than fall
    back to software, and so does fw4's check-mode probe of a second offload
    table. A third table at once is still refused, and nothing is left behind
    by any of it."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("the reload proof requires installed hardware")
    await r.table()
    await r.exchange(count=4)
    before = await r.wait(lambda s: s["entries"] == 2)
    ports = f"devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload;"
    probe = f"table inet {TABLE}_probe {{ flowtable probe {{ hook ingress priority 0; {ports} }}; }}"
    third = f"table inet {TABLE}_third {{ flowtable third {{ hook ingress priority 0; {ports} }}; }}"
    checked = await command(r.target, r.session, "nft", "-c", probe, check=False)
    assert checked["rc"] == 0, checked
    crowded = await command(r.target, r.session, "nft", "-c", probe + "\n" + third, check=False)
    assert crowded["rc"] != 0 and "busy" in crowded["stderr"].lower(), crowded
    probed = await r.state()
    assert probed["bindings"] == 2 and probed["entries"] == 2, probed
    assert {f["cookie"] for f in probed["flows"]} == {f["cookie"] for f in before["flows"]}, (before, probed)
    reloaded = await command(r.target, r.session, "nft", f"delete table inet {TABLE}\n" + r.ruleset(),
                             check=False)
    assert reloaded["rc"] == 0, reloaded
    # The old flowtable took its flows with it; conntrack still holds the
    # connection, so the next packets offer it to the new one.
    await r.wait(lambda s: s["bindings"] == 2 and not s["entries"])
    await r.exchange(count=4)
    admitted = await r.wait(lambda s: s["entries"] == 2)
    baseline = {f["cookie"]: int(f["packets"]) for f in admitted["flows"]}
    await r.exchange(count=64)
    after = await r.state()
    assert {f["cookie"]: int(f["packets"]) - baseline[f["cookie"]] for f in after["flows"]} == \
        {c: 64 for c in baseline}, (admitted, after)
    for key in ("errors", "fatal", "quarantine", "invalidated"):
        assert after[key] == before[key], (key, before, after)
    assert after["installs"] - after["deletes"] == after["entries"] == 2, after
    assert after["handle_refs"] == after["neighbour_refs"] == 2, after
    r.record("table-reload", {"before": before, "probed": probed, "after": after,
                              "crowded": crowded["stderr"]})


async def ct_counts(r):
    """(packets, bytes) conntrack has accounted to each direction of the flow,
    original first."""
    listing = await command(r.target, r.session, "conntrack", "-L", "-p", r.proto,
                            "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                            "--sport", str(SPORT), "--dport", str(DPORT), "-o", "extended")
    counts = [(int(p), int(b)) for p, b in re.findall(r"packets=(\d+) bytes=(\d+)", listing["stdout"])]
    assert len(counts) == 2, listing
    return counts


async def test_flowtable_offload_counter_enabled_live(rig):
    """Enabling `counter` on a table whose flows are already in hardware keeps
    them there and starts accounting their hardware traffic in conntrack.

    Netfilter applies the flag to the live flowtable without unbinding it, so
    the adapter sees no event: entries, cookies and bindings stay as they were
    and nothing is invalidated. From the next statistics pass the flowtable
    core adds each hardware delta to conntrack, restated in Netfilter's units,
    so a 256-byte payload counts 284 bytes in either direction.

    Until then hardware traffic reaches the flowtable core but not conntrack.
    A statistics pass runs within about four seconds of the last packet at the
    default 30-second timeout, so the pause before the change lets one consume
    everything earlier, and the delta measured after it is this test's own."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("live counter enablement requires installed hardware")
    await r.table()
    await r.exchange()
    installed = await r.wait(lambda s: s["entries"] == 2)
    await r.exchange(32)
    await asyncio.sleep(8)
    await r.nft(f"add flowtable inet {TABLE} fast {{ hook ingress priority 0; "
                f"devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; counter; }}")
    listed = await command(r.target, r.session, "nft", "list", "flowtable", "inet", TABLE, "fast")
    assert "counter" in listed["stdout"], listed
    enabled = await r.state()
    counted = await ct_counts(r)
    tx_before = await kernel_tx_packets(r.target, r.session, TARGET_LAN_IF)
    count, payload = 64, 256
    await r.exchange(count, payload_size=payload)
    tx_after = await kernel_tx_packets(r.target, r.session, TARGET_LAN_IF)
    after = await r.state()
    expected = [(packets + count, octets + count * (payload + 8 + 20)) for packets, octets in counted]
    accounted, deadline = counted, time.monotonic() + 15
    while time.monotonic() < deadline:
        accounted = await ct_counts(r)
        if all(now[0] >= wanted[0] for now, wanted in zip(accounted, expected)):
            break
        await asyncio.sleep(0.5)
    r.record("counter-enabled-live", {"installed": installed, "enabled": enabled, "after": after,
                                      "conntrack_before": counted, "conntrack_after": accounted,
                                      "expected": expected, "software_lan_tx": tx_after - tx_before})
    for state in (enabled, after):
        assert state["entries"] == state["bindings"] == 2, state
        assert state["invalidated"] == state["invalidation_done"] == state["fatal"] == 0, state
        assert (state["installs"], state["deletes"], state["rearms"], state["errors"]) == (
            installed["installs"], installed["deletes"], installed["rearms"], installed["errors"]), (installed, state)
    old, new = {f["in"]: f for f in enabled["flows"]}, {f["in"]: f for f in after["flows"]}
    assert {f["in"]: f["cookie"] for f in installed["flows"]} == {i: f["cookie"] for i, f in new.items()}
    for ingress, flow in new.items():
        assert int(flow["packets"]) - int(old[ingress]["packets"]) == count, (enabled, after)
    assert 0 <= tx_after - tx_before < count // 2, (tx_before, tx_after)
    assert accounted == expected, (counted, accounted, expected)


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
send_timeouts = 0
start = time.monotonic()
while time.monotonic() - start < {duration}:
    payload = struct.pack('!Q', sent) + b'ASK-terminal'.ljust(248, b'.')
    try:
        s.sendto(payload, ({WAN_IP!r}, {DPORT}))
    except TimeoutError:
        # Stopped classifier ports can apply backpressure to the peer.
        # Keep attempting sends until the observation window ends.
        send_timeouts += 1
        time.sleep(0.005)
        continue
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
                  'send_timeouts': send_timeouts,
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
    await r.table()
    await r.exchange(128)
    initial = await r.wait(lambda s: s["entries"] == 2)
    assert all(int(f["packets"]) > 0 for f in initial["flows"]), initial
    baseline = len(r.echo.received)
    traffic = asyncio.create_task(terminal_stream(r, duration=24 if kind == "unlink" else 12))
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
            assert stopped["rearm_ready"] == 0, stopped
            await console_command(con, "nft", "add", "table", "inet", TABLE)
            attempted = await console_command(con, "nft", f"add flowtable inet {TABLE} fast {{ "
                                  f"hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; "
                                  "flags offload; }", check=False)
            assert attempted["rc"] != 0 and "Operation not supported" in attempted["stdout"], attempted
            refused = status_text((await console_command(con, "cat", "/proc/cdx_flowtable"))["stdout"].strip())
            assert refused["fatal"] == refused["invalidated"] == refused["invalidation_done"] == 1
            assert refused["bindings"] == refused["entries"] == refused["rearm_ready"] == 0
            assert refused["rearms"] == live["rearms"] and refused["errors"] == stopped["errors"]
            r.record("unlink-rearm-refused", {"state": refused, "nft": attempted})
            await console_command(con, "nft", "delete", "table", "inet", TABLE)
            ports = await console_python(con, port_script)
            assert json.loads(ports["stdout"]) == {"6": 0, "7": 0}, ports
            knob = await console_command(con, "cat", "/sys/module/cdx/parameters/flowtable_fail_unlink")
            assert knob["stdout"].strip() == "N", knob
            log = (await console_command(con, "dmesg"))["stdout"]
            assert log.count("retaining possibly linked key") == 1, log
            assert "hardware stopped after unproven deletion; reboot required" in log
            r.record("unlink-stopped", {"state": stopped, "ports": json.loads(ports["stdout"]), "dmesg": log})
            mtu_checks = []
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                original_mtu = (await console_command(con, "cat", f"/sys/class/net/{dev}/mtu"))["stdout"].strip()
                try:
                    await console_command(con, "ip", "link", "set", "dev", dev, "mtu", "1400")
                finally:
                    await console_command(con, "ip", "link", "set", "dev", dev, "mtu", original_mtu)
                held = status_text((await console_command(con, "cat", "/proc/cdx_flowtable"))["stdout"].strip())
                for field in ("fatal", "invalidated", "invalidation_done", "rearm_ready", "entries", "bindings",
                              "installs", "deletes", "rearms", "errors", "quarantine"):
                    assert held[field] == stopped[field], (field, held, stopped)
                ports = json.loads((await console_python(con, port_script))["stdout"])
                assert ports == {"6": 0, "7": 0}, ports
                mtu_checks.append({"dev": dev, "state": held, "ports": ports})
            r.record("unlink-mtu-refused", mtu_checks)
            restart_checks = []
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                await console_command(con, "ip", "link", "set", "dev", dev, "down")
                restart = await console_command(con, "ip", "link", "set", "dev", dev, "up", check=False)
                assert restart["rc"] != 0 and "Input/output error" in restart["stdout"], restart
                link = json.loads((await console_command(con, "ip", "-j", "link", "show", "dev", dev))["stdout"])[0]
                assert "UP" not in link["flags"], link
                ports = json.loads((await console_python(con, port_script))["stdout"])
                assert ports == {"6": 0, "7": 0}, ports
                restart_checks.append({"dev": dev, "restart": restart, "ports": ports})
            r.record("unlink-port-restart-refused", restart_checks)
            # Allow already queued datagrams to arrive, then prove ingress
            # remains stopped while the LAN sender is still running.
            await asyncio.sleep(0.2)
            received = len(r.echo.received)
            assert not traffic.done(), "traffic ended before stopped-port observation"
            await asyncio.sleep(1)
            assert len(r.echo.received) == received, "traffic passed stopped classifier ports"
        else:
            await console_command(con, "rmmod", "ask_flowtable", timeout=25)
            await console_command(con, "rmmod", "cdx", timeout=25)
            unloaded = True
        r.record(f"{kind}-traffic", await traffic)
    finally:
        # Await the finite LAN script before fixture cleanup uses its UART.
        try:
            await traffic
        finally:
            if kind == "unlink" and not unloaded:
                await console_command(con, "rmmod", "ask_flowtable", timeout=25)
                # The fatal latch belongs to the still-loaded provider. A
                # fresh consumer must not turn an unproven deletion healthy.
                refused = await console_command(con, "modprobe", "ask_flowtable", check=False)
                assert refused["rc"] != 0 and "Operation not supported" in refused["stdout"], refused
                await console_command(con, "test", "-e", "/sys/module/cdx")
                for path in ("/sys/module/ask_flowtable", "/proc/cdx_flowtable",
                             "/sys/module/cdx/holders/ask_flowtable"):
                    assert (await console_command(con, "test", "-e", path, check=False))["rc"] == 1, path
                r.record("unlink-module-reload-refused", refused)
                for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                    restart = await console_command(con, "ip", "link", "set", "dev", dev, "up", check=False)
                    assert restart["rc"] != 0 and "Input/output error" in restart["stdout"], restart
                ports = json.loads((await console_python(con, port_script))["stdout"])
                assert ports == {"6": 0, "7": 0}, ports
                r.record("unlink-provider-guard-retained", {"ports": ports, "adapter_absent": True})
                await console_command(con, "rmmod", "cdx", timeout=25)
                unloaded = True
    for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
        await console_command(con, "ip", "link", "set", "dev", dev, "up")
    # DOWN can discard the fixture's /32 routes and permanent neighbours.
    # Restore these before its normal undo actions and software proof.
    for address, mac, dev in ((r.lan_ip, r.lan_mac, TARGET_LAN_IF),
                              (WAN_IP, r.wan_mac, TARGET_WAN_IF)):
        await console_command(con, "ip", "route", "replace", address + "/32", "dev", dev, "mtu", "1200")
        await console_command(con, "ip", "neigh", "replace", address, "lladdr", mac,
                              "nud", "permanent", "dev", dev)
    absent = await console_command(con, "test", "-e", "/sys/module/cdx", check=False)
    assert absent["rc"] == 1, absent
    assert (await console_command(con, "test", "-e", "/proc/cdx_flowtable", check=False))["rc"] == 1
    await console_command(con, "nft", "delete", "table", "inet", TABLE, check=False)
    await r.clear_ct()
    await r.exchange(64)
    r.record(f"{kind}-complete", {"module_absent": True, "post_unload_echoes": 64,
                                "boot_id": await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")})

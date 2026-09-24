"""IPsec prerequisite and allocation recovery through the shipping service.

XFRM owns SAs; restoring a withdrawn SA models the configuration/IKE owner.
The flowtable service must recover existing sockets without any flow repair.
All policies remain required while an SA is absent, including on the peer.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import socket
import struct
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import by_key, peer
from test_flowtable_failslab import same_service, slab_fault
from test_flowtable_offload import ARTIFACTS, DPORT, Echo, WAN_IP, command, console_command, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import keys, unchanged, warm
from test_flowtable_service import FIRST, managed_service, supervision_status
from test_flowtable_service_vlan import attempts, balanced, denied, received
from test_flowtable_tcp import software_tx
from test_flowtable_tunnel import Capture
from test_ipsec_inbound_flow_offload import AUTH, CIPHER, sec_counter

INNER = "198.18.102.2"
LAN_INNER = "198.18.102.3"
REQIDS = {"out": "49301", "in": "49302"}
# Linux's UDP_ENCAP socket option and its ESP-in-UDP mode (linux/udp.h).
UDP_ENCAP, UDP_ENCAP_ESPINUDP = 100, 2


@dataclass(frozen=True)
class Transform:
    """The fixture's SA pair: the `ip xfrm state` algorithm arguments, and UDP
    encapsulation as (DUT port, peer port), or None for bare ESP.

    A test asks for another one by parametrizing `ipsec_service` indirectly."""
    algorithms: tuple = ("enc", "cbc(aes)", CIPHER, "auth-trunc", "hmac(sha256)", AUTH, "128")
    encap: tuple | None = None


async def xfrm(r, agent, kind):
    # This image's iproute2 does not produce JSON for XFRM (even with -j).
    # Split its normal records at the unindented source/destination header.
    text = (await command(agent, r.session, "ip", "xfrm", kind, "list"))["stdout"]
    return [record.strip() for record in re.split(r"(?m)(?=^src )", text) if record.strip()]


def owned_state(state):
    return any(re.search(r"\breqid " + reqid + r"\b", state) for reqid in REQIDS.values())


class SecurityAssociations:
    def __init__(self, r, wan, outer, transform=Transform()):
        self.r, self.wan, self.outer = r, wan, outer
        self.transform = transform
        self.active, self.cleanup = {}, []

    def state(self, direction, spi):
        src, dst = (self.outer, WAN_IP) if direction == "out" else (WAN_IP, self.outer)
        return ["src", src, "dst", dst, "proto", "esp", "spi", hex(spi)]

    def crypto(self, direction):
        encap = []
        if self.transform.encap:
            # The source port is the sending end's: the DUT's going out.
            sport, dport = self.transform.encap if direction == "out" else self.transform.encap[::-1]
            encap = ["encap", "espinudp", str(sport), str(dport), "0.0.0.0"]
        return ["mode", "tunnel", "reqid", REQIDS[direction], *self.transform.algorithms, *encap]

    async def add(self, agent, kind, identity, *options, check=True):
        result = await command(agent, self.r.session, "ip", "xfrm", kind, "add", *identity, *options, check=check)
        if result["rc"] == 0:
            self.cleanup.append((agent, ["ip", "xfrm", kind, "delete", *identity]))
        return result

    async def prepare_peer(self, direction, *options):
        spi = 0xA9000000 | secrets.randbits(24)
        await self.add(self.wan, "state", self.state(direction, spi), *self.crypto(direction),
                       "replay-window", "32", *options)
        return spi

    async def install(self, direction, spi, *options, check=True):
        # An inbound SA checks replays only with a window, and 0 turns the
        # hardware's check off as it does software's. 32 is what strongSwan
        # installs, so every case here runs with anti-replay on unless it
        # names its own window.
        if direction == "in" and "replay-window" not in options:
            options = (*options, "replay-window", "32")
        result = await self.add(self.r.target, "state", self.state(direction, spi),
                               *self.crypto(direction), *options, "offload", "packet", "dev", TARGET_WAN_IF,
                               "dir", direction, check=check)
        if result["rc"] == 0:
            self.active[direction] = spi
        return result

    async def remove(self, direction):
        spi = self.active.pop(direction)
        await console_command(self.r.service_console, "ip", "xfrm", "state", "delete", *self.state(direction, spi))
        return spi

    async def states(self):
        return [s for s in await xfrm(self.r, self.r.target, "state") if owned_state(s)]

    async def policies(self):
        return [p for p in await xfrm(self.r, self.r.target, "policy") if INNER + "/32" in p.splitlines()[0]]


def wire_interface(r):
    """The WAN host's DUT-facing physical port, where ESP is captured as the
    wire carries it. XFRM reinjects decrypted packets on the host's L3
    interface, so capturing below a bridge keeps those copies from
    masquerading as plaintext on the wire."""
    members = Path('/sys/class/net', r.wan_if, 'brif')
    physical = [p.name for p in members.iterdir()
                if Path('/sys/class/net', p.name, 'device').exists()] if members.exists() else [r.wan_if]
    wire = os.environ.get('ASK_WAN_WIRE_IF')
    if not wire:
        assert len(physical) == 1, ('set ASK_WAN_WIRE_IF to the DUT-facing physical port', physical)
        wire = physical[0]
    return wire


@pytest_asyncio.fixture
async def ipsec_service(rig, request):
    r = rig
    transform = getattr(request, "param", Transform())
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer = next(a["local"] for i in json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_WAN_IF))["stdout"])
                 for a in i["addr_info"] if a["family"] == "inet")
    r.ipsec = sa = SecurityAssociations(r, wan, outer, transform)
    r.ipsec_wire_if = wire_interface(r)
    transport, lan_created, encap = None, False, None
    cleanup = []
    for agent in (r.target, wan):
        assert not json.loads((await command(agent, r.session, "ip", "-j", "route", "show", "table", "all", "exact", INNER + "/32"))["stdout"])
        states = [s for s in await xfrm(r, agent, "state") if owned_state(s)]
        assert not states, "test-owned SA identifiers already exist"
        policies = [p for p in await xfrm(r, agent, "policy") if INNER + "/32" in p.splitlines()[0]]
        assert not policies, policies
    try:
        setup = f'''
import json, subprocess
addresses=json.loads(subprocess.check_output(['ip','-j','-4','addr'],text=True))
assert not any(a.get('local') in {({LAN_INNER, INNER})!r} for i in addresses for a in i['addr_info']), addresses
subprocess.run(['ip','addr','add',{LAN_INNER + '/32'!r},'dev','lo'],check=True)
'''
        result = await lan_run_python(r.lan, setup, label='ipsec_recovery_inner', timeout=15)
        assert result.rc == 0, result.stdout
        lan_created = True
        for agent, args, undo in [
            (wan, ["ip", "addr", "add", INNER + "/32", "dev", "lo"], ["ip", "addr", "del", INNER + "/32", "dev", "lo"]),
            (r.target, ["ip", "route", "add", INNER + "/32", "via", WAN_IP, "dev", TARGET_WAN_IF, "mtu", "1400"],
             ["ip", "route", "del", INNER + "/32", "via", WAN_IP, "dev", TARGET_WAN_IF]),
            (r.target, ["ip", "route", "add", LAN_INNER + "/32", "via", r.lan_ip, "dev", TARGET_LAN_IF, "mtu", "1200"],
             ["ip", "route", "del", LAN_INNER + "/32", "via", r.lan_ip, "dev", TARGET_LAN_IF]),
            (wan, ["ip", "route", "add", LAN_INNER + "/32", "via", outer, "dev", r.wan_if],
             ["ip", "route", "del", LAN_INNER + "/32", "via", outer, "dev", r.wan_if]),
        ]:
            await command(agent, r.session, *args)
            cleanup.append((agent, undo))
        if transform.encap:
            # The peer's end of ESP-in-UDP: without an encapsulating socket on
            # its port, this host treats the DUT's frames as plain UDP.
            encap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            encap.bind((WAN_IP, transform.encap[1]))
            encap.setsockopt(socket.IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)
        for direction in ("out", "in"):
            spi = await sa.prepare_peer(direction)
            await sa.install(direction, spi)
            src, dst = (LAN_INNER, INNER) if direction == "out" else (INNER, LAN_INNER)
            outer_src, outer_dst = (outer, WAN_IP) if direction == "out" else (WAN_IP, outer)
            selector = ["src", src + "/32", "dst", dst + "/32"]
            template = ["tmpl", "src", outer_src, "dst", outer_dst, "proto", "esp", "mode", "tunnel",
                        "reqid", REQIDS[direction], "level", "required"]
            await sa.add(wan, "policy", [*selector, "dir", "in" if direction == "out" else "out"], *template)
            await sa.add(r.target, "policy", [*selector, "dir", direction], *template,
                         "offload", "packet", "dev", TARGET_WAN_IF)
            if direction == "in":
                await sa.add(r.target, "policy", [*selector, "dev", TARGET_LAN_IF, "dir", "fwd"], *template)
        echo = Echo()
        echo.received = r.echo.received
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: echo, local_addr=(INNER, DPORT))
        async with managed_service(r, extra_paths=[(LAN_INNER, INNER)]):
            yield r
    finally:
        if transport:
            transport.close()
        if encap:
            encap.close()
        failures = []
        with Console.target(log_path=str(ARTIFACTS / "service-ipsec-cleanup-uart.log")) as con:
            await asyncio.to_thread(con.login, "root", None)
            for agent, argv in reversed(cleanup + sa.cleanup):
                try:
                    # Withdrawn/rekeyed states already disappeared. Exact identities
                    # prevent teardown from touching somebody else's XFRM state.
                    check = "state" not in argv
                    if agent is r.target:
                        await console_command(con, *argv, check=check)
                    else:
                        await command(agent, r.session, *argv, check=check)
                except Exception as error:
                    failures.append(repr(error))
        for agent in (r.target, wan):
            states = [s for s in await xfrm(r, agent, "state") if owned_state(s)]
            policies = [p for p in await xfrm(r, agent, "policy") if INNER + "/32" in p.splitlines()[0]]
            if states or policies:
                failures.append({"agent": str(agent), "states": states, "policies": policies})
        if lan_created:
            result = await lan_run_python(r.lan,
                f"import subprocess\nsubprocess.run(['ip','addr','del',{LAN_INNER + '/32'!r},'dev','lo'],check=True)\n",
                label='ipsec_recovery_inner_cleanup', timeout=15)
            if result.rc:
                failures.append(result.stdout)
        assert not failures, failures


def flows_for(r, protocol="tcp"):
    return [
        {"id": 0, "proto": "udp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 1, "proto": "tcp", "sport": FIRST, "lan": r.lan_ip},
        {"id": 2, "proto": "udp", "sport": FIRST, "lan": LAN_INNER, "connect_ip": INNER},
        {"id": 3, "proto": "tcp", "sport": FIRST, "lan": LAN_INNER, "connect_ip": INNER, "tcp_timeout": 60},
        {"id": 4, "proto": protocol, "sport": FIRST + 1, "lan": LAN_INNER, "connect_ip": INNER},
        {"id": 5, "proto": "udp", "sport": FIRST + 2, "lan": r.lan_ip},
        {"id": 6, "proto": "udp", "sport": FIRST + 2, "lan": LAN_INNER, "connect_ip": INNER},
    ]


class Wire(Capture):
    def __init__(self, r, label):
        self.path = ARTIFACTS / (label + ".pcap")
        self.interface = r.ipsec_wire_if
        esp = "ip proto 50"
        if r.ipsec.transform.encap:
            esp = f"(ip proto 50 or udp port {r.ipsec.transform.encap[0]})"
        self.filter = f"ether src {r.dut_wan_mac} and ({esp} or (src host {LAN_INNER} and dst host {INNER}))"

    def check(self, *, encrypted=False, spi=None):
        from scapy.all import IP, ESP, rdpcap
        packets = rdpcap(str(self.path))
        assert not any(IP in p and p[IP].dst == INNER for p in packets), "required IPsec policy leaked plaintext on the WAN"
        esp = [p for p in packets if ESP in p]
        if encrypted:
            assert len(esp) >= 256, (len(esp), self.stderr())
            assert all(p[ESP].spi == spi for p in esp), {p[ESP].spi for p in esp}
        return {"esp": len(esp), "plaintext": 0}


async def hardware(r, p, label, flows):
    before = await r.state()
    forwarded = await r.software_forwarded()
    enc = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
    dec = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx todec")
    tx = await software_tx(r)
    async with Wire(r, label) as wire:
        reports = await p.batch(list(range(len(flows))), count=256, interval=0.03125)
    after = await r.state()
    unchanged(before, after, list(range(len(flows))), flows)
    assert (before["installs"], before["deletes"]) == (after["installs"], after["deletes"]), (before, after)
    old, new = by_key(before), by_key(after)
    for ident in range(len(flows)):
        for key in keys([ident], flows):
            packets = int(new[key]["packets"]) - int(old[key]["packets"])
            assert packets >= (256 if flows[ident]["proto"] == "udp" else reports[ident]["bytes"] // 1500), (key, packets)
            if ident >= 2:
                field = "sa" if key[0] == TARGET_LAN_IF else "in_sa"
                assert new[key][field] != "0", new[key]
    enc = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - enc
    dec = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx todec") - dec
    assert 0 <= enc <= 5 and dec == 0, (enc, dec)
    tx_after = await software_tx(r)
    delta = {dev: tx_after[dev] - tx[dev] for dev in tx}
    slow_path = await r.software_forwarded() - forwarded
    assert 0 <= slow_path <= 64, slow_path
    r.record(label, {"before": before, "after": after, "reports": reports, "software_tx": delta,
                     "toenc": enc, "todec": dec, "software_forwarded": slow_path,
                     "wire": wire.check(encrypted=True, spi=r.ipsec.active["out"])})
    return after


async def negative(r, p):
    for ident in (5, 6):
        await denied(r, p, ident)


async def plaintext_probe(r, p, label):
    from scapy.all import Ether, IP, UDP, Raw, sendp
    marker = b'ASK-IPSEC-CLEAR-' + secrets.token_bytes(16)
    await p.rpc('wire_probe', changes={'action': 'start', 'iface': LAN_NIC, 'marker': marker.hex()})
    try:
        frame = (Ether(src=r.wan_mac, dst=r.dut_wan_mac) / IP(src=INNER, dst=LAN_INNER) /
                 UDP(sport=DPORT, dport=FIRST) / Raw(marker))
        # L2 injection bypasses the peer's required outbound XFRM policy.
        await asyncio.to_thread(sendp, frame, iface=r.wan_if, count=64, inter=0.01, verbose=False)
        await asyncio.sleep(0.2)
        result = await p.rpc('wire_probe', changes={'action': 'status'})
        r.record(label, result)
        assert result['received'] == 0, 'plaintext reached LAN despite required receiving policy'
    finally:
        await p.rpc('wire_probe', changes={'action': 'stop'})


@pytest.mark.parametrize("direction", ["out", "in"])
@pytest.mark.parametrize("allocation_failure", [False, True], ids=["withdrawal", "failslab"])
async def test_flowtable_service_ipsec_sa_recovery(ipsec_service, direction, allocation_failure):
    r, flows = ipsec_service, flows_for(ipsec_service)
    service, policies = await supervision_status(r), await r.ipsec.policies()
    capture = Wire(r, "ipsec-sa-wire")
    capture.filter = "ip proto 50"
    # Observe before opening sockets so capture setup cannot hide an
    # admission race by delaying their first exchanges.
    async with capture, peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400,
                             listen_addresses=[INNER]) as p:
        try:
            await warm(r, p, [0, 1, 2, 3], "ipsec-baseline", flows[:4])
        except BaseException:
            r.record("ipsec-baseline-failure", {
                "backend": await r.state(), "states": await r.ipsec.states(),
                "policies": await r.ipsec.policies(),
                "xfrm_stats": await read(r.target, r.session, "/proc/net/xfrm_stat"),
                "sec_stats": (await command(r.target, r.session, "ethtool", "-S", TARGET_WAN_IF))["stdout"],
            })
            raise
        initial = await hardware(r, p, "ipsec-baseline-hardware", flows[:4])
        await plaintext_probe(r, p, 'ipsec-baseline-plaintext')
        initial_attempts = await attempts(r)
        for cycle in range(1 if allocation_failure else 3):
            label = f"ipsec-{direction}-{'slab' if allocation_failure else 'withdraw'}-{cycle}"
            await negative(r, p)
            before = await r.state()
            # New SPI avoids resetting the anti-replay sequence on a reused SA.
            spi = await r.ipsec.prepare_peer(direction)
            await p.rpc("start", [2], count=0, interval=0.05, allow_loss=True)
            await p.rpc("start", [3], count=0, interval=0.05)
            started = time.monotonic()
            old_spi = await r.ipsec.remove(direction)
            try:
                retired = await r.wait(lambda s: by_key(s).keys() == keys([0, 1], flows), timeout=5)
                retire_seconds = time.monotonic() - started
                assert retire_seconds < 5
                unchanged(initial, retired, [0, 1], flows)
                assert retired["ipsec_invalidations"] == before["ipsec_invalidations"] + 2, (before, retired)
                await asyncio.sleep(0.2)
                stopped, wan_before = await p.rpc("status"), received(r, 2)
                await plaintext_probe(r, p, label + '-plaintext')
                async with Wire(r, label + "-unavailable") as wire:
                    held = time.monotonic()
                    while time.monotonic() - held < 6:
                        await p.batch([0, 1], count=32, interval=0.01)
                        progress = await p.rpc("status")
                        assert not progress["errors"], progress
                        assert all(progress["received"][str(i)] == stopped["received"][str(i)] for i in (2, 3)), progress
                        state = await r.state()
                        r.record(label + '-held', {'state': state, 'progress': progress})
                        unchanged(initial, state, [0, 1], flows)
                        assert by_key(state).keys() == keys([0, 1], flows), state
                assert await r.ipsec.policies() == policies
                assert len(await r.ipsec.states()) == 1
                assert await attempts(r) == initial_attempts
                if direction == "out":
                    assert received(r, 2) == wan_before, "required outbound policy failed open"
                r.record(label + "-absent", {"state": retired, "seconds": retire_seconds, "wire": wire.check()})
                if allocation_failure:
                    async with slab_fault(r, "ipsec-context", label) as fault:
                        refused = await r.ipsec.install(direction, spi, check=False)
                        assert refused["rc"] != 0, refused
                        hit = await fault.hit()
                        assert len(await r.ipsec.states()) == 1
                        await p.batch([0, 1], count=32, interval=0.01)
                        r.record(label + "-refused", {"result": refused, "hit": hit})
            finally:
                await r.ipsec.install(direction, spi)
                await command(r.ipsec.wan, r.session, "ip", "xfrm", "state", "delete", *r.ipsec.state(direction, old_spi))
            restored = time.monotonic()
            while True:
                await p.batch([0, 1], count=32, interval=0.01)
                progress = await p.rpc("status")
                assert not progress["errors"], progress
                if progress["received"]["2"] >= stopped["received"]["2"] + 16 and progress["received"]["3"] > stopped["received"]["3"]:
                    break
                assert time.monotonic() - restored < 25, progress
            transfers = await p.rpc("stop", [2, 3])
            assert transfers["2"]["lost"] > 0 and transfers["3"]["lost"] == 0, transfers
            await warm(r, p, [0, 1, 2, 3], label + "-readmitted", flows[:4])
            ready_seconds = time.monotonic() - restored
            assert ready_seconds < 25
            after = await hardware(r, p, label + "-hardware", flows[:4])
            hardware_seconds = time.monotonic() - restored
            assert hardware_seconds < 45
            balanced(after, initial["errors"])
            unchanged(initial, after, [0, 1], flows)
            assert after["rearms"] == initial["rearms"]
            assert (after["installs"], after["deletes"]) == (before["installs"] + 4, before["deletes"] + 4)
            await p.batch([0, 1, 2, 3], count=128, interval=0.045)
            quiet = await r.state()
            unchanged(after, quiet, [0, 1, 2, 3], flows)
            assert (quiet["installs"], quiet["deletes"]) == (after["installs"], after["deletes"])
            assert await attempts(r) == initial_attempts
            await same_service(r, service)
            r.record(label + "-recovery", {"ready_seconds": ready_seconds, "hardware_seconds": hardware_seconds,
                "before": before, "after": after, "transfers": transfers})
        await p.rpc("open", [4])
        await warm(r, p, [0, 1, 2, 3, 4], "ipsec-new-connection", flows[:5])
        await hardware(r, p, "ipsec-new-hardware", flows[:5])
        await negative(r, p)


async def test_flowtable_service_ipsec_admission_churn(ipsec_service):
    """Repeatedly cross software/SEC and hardware admission with exact delivery."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    service, initial_attempts = await supervision_status(r), await attempts(r)
    capture = Wire(r, "ipsec-admission-churn")
    capture.filter = "ip proto 50"
    # Start capture before opening sockets so observation adds no settling
    # delay between the first connections and their initial exchanges.
    async with capture, peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400,
                             listen_addresses=[INNER]) as p:
        try:
            await warm(r, p, [0, 1, 2, 3], "admission-churn-baseline", flows[:4])
            initial = await hardware(r, p, "admission-churn-baseline-hardware", flows[:4])
            for cycle in range(24):
                before = await r.state()
                await p.rpc("close", [2])
                await command(r.target, r.session, "conntrack", "-D", "-f", "ipv4", "-p", "udp",
                              "--orig-src", LAN_INNER, "--orig-dst", INNER,
                              "--sport", str(FIRST), "--dport", str(DPORT))
                retired = await r.wait(lambda s: not (by_key(s).keys() & keys([2], flows)), timeout=5)
                unchanged(initial, retired, [0, 1, 3], flows)
                await p.rpc("open", [2])
                await warm(r, p, [0, 1, 2, 3], f"admission-churn-{cycle}", flows[:4])
                admitted = await r.state()
                reports = await p.batch([0, 1, 2, 3], count=32, interval=0.01)
                after = await r.state()
                unchanged(admitted, after, [0, 1, 2, 3], flows)
                unchanged(initial, after, [0, 1, 3], flows)
                old, new = by_key(admitted), by_key(after)
                for key in keys([2], flows):
                    assert int(new[key]["packets"]) - int(old[key]["packets"]) >= 32, (key, old[key], new[key])
                assert (after["installs"], after["deletes"]) == (before["installs"] + 2, before["deletes"] + 2)
                balanced(after, initial["errors"])
                assert after["rearms"] == initial["rearms"]
                r.record(f"admission-churn-{cycle}-verified", {"before": before, "after": after,
                                                             "reports": reports})
            await hardware(r, p, "admission-churn-final-hardware", flows[:4])
            await plaintext_probe(r, p, "admission-churn-plaintext")
            await negative(r, p)
            assert await attempts(r) == initial_attempts
            await same_service(r, service)
        except BaseException:
            r.record("admission-churn-failure", {
                "backend": await r.state(), "states": await r.ipsec.states(),
                "policies": await r.ipsec.policies(), "wan_udp_received": received(r, 2),
                "xfrm_stats": await read(r.target, r.session, "/proc/net/xfrm_stat"),
                "sec_stats": (await command(r.target, r.session, "ethtool", "-S", TARGET_WAN_IF))["stdout"],
            })
            raise


BLASTER = "/tmp/ask-ipsec-sequence-blast.py"
SEQUENCE_SECONDS = 4


def blast_script(seconds):
    """Flow 2's tuple from one socket, as fast as it goes, echoes discarded."""
    return f"""
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(({LAN_INNER!r}, {FIRST}))
s.setblocking(False)
payload, end = b"x" * 1000, time.time() + {seconds}
while time.time() < end:
    try:
        s.sendto(payload, ({INNER!r}, {DPORT}))
    except BlockingIOError:
        time.sleep(0.0001)
    try:
        while True:
            s.recv(2048)
    except BlockingIOError:
        pass
"""


def reused_sequences(path):
    """ESP frames in a pcap, and how many (SPI, sequence) pairs went out twice.
    A plain walk: scapy takes minutes on a line-rate burst."""
    seen = Counter()
    data = Path(path).read_bytes()
    off = 24
    while off + 16 <= len(data):
        length = struct.unpack_from("<I", data, off + 8)[0]
        frame = data[off + 16:off + 16 + length]
        off += 16 + length
        l3 = 18 if frame[12:14] == b"\x81\x00" else 14
        if len(frame) >= l3 + 28 and frame[l3 + 9] == 50:
            ihl = (frame[l3] & 0xF) * 4
            seen[frame[l3 + ihl:l3 + ihl + 8]] += 1
    return sum(seen.values()), sum(1 for n in seen.values() if n > 1)


def replay_drops():
    """Anti-replay rejections on this host, the SA's receiving peer."""
    for line in Path("/proc/net/xfrm_stat").read_text().splitlines():
        if line.startswith("XfrmInStateSeqError"):
            return int(line.split()[1])


async def test_flowtable_service_ipsec_shared_sequence(ipsec_service):
    """Both SEC feeders of one outbound SA draw from one sequence counter.

    The classifier enqueues the offloaded flow's frames to the SA's SEC queue
    while the CPU enqueues what the flowtable never offloads, ICMP here. SEC
    shares a descriptor, and with it the stored ESP sequence number, only
    between jobs that fetch it under the same ICID. If FMan and the QMan
    software portals stamp frames differently, both feeders encrypt from the
    same stored number and the peer drops the later copy as a replay."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    # Only the reserved test ports are exempt from the WAN masquerade, and a
    # masqueraded source no longer matches the IPsec policy.
    exempt = ["POSTROUTING", "-s", LAN_INNER, "-d", INNER, "-p", "icmp", "-j", "ACCEPT"]
    await command(r.target, r.session, "iptables", "-t", "nat", "-I", *exempt)
    capture = Wire(r, "ipsec-shared-sequence")
    capture.snaplen = 64
    try:
        script = base64.b64encode(blast_script(SEQUENCE_SECONDS).encode()).decode()
        await asyncio.to_thread(r.lan.run, f"echo {script} | base64 -d > {BLASTER}", timeout=15)
        # A first burst gets the flow admitted, so the measured one runs in
        # hardware from its first frame.
        await asyncio.to_thread(r.lan.run, f"python3 {BLASTER}", timeout=SEQUENCE_SECONDS + 15)
        admitted = by_key(await r.state())
        for key in keys([2], flows):
            assert key in admitted, (key, sorted(admitted))
            assert admitted[key]["sa" if key[0] == TARGET_LAN_IF else "in_sa"] != "0", admitted[key]
        drops = replay_drops()
        cpu = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
        async with capture:
            await asyncio.to_thread(
                r.lan.run, f"timeout {SEQUENCE_SECONDS} ping -q -f -l 64 -s 64 -I {LAN_INNER} {INNER} "
                f">/dev/null 2>&1 & python3 {BLASTER}", timeout=SEQUENCE_SECONDS + 15)
        cpu = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - cpu
        esp, reused = reused_sequences(capture.path)
        drops = replay_drops() - drops
        r.record("ipsec-shared-sequence", {"esp": esp, "cpu_fed": cpu, "reused": reused,
                                           "replay_drops": drops})
        # Without both feeders busy at once the check below proves nothing.
        # Unfixed, nearly every CPU-fed frame collides (219 of 238 measured).
        assert cpu >= 100 and esp - cpu >= 100_000, (cpu, esp)
        assert (reused, drops) == (0, 0), {"reused": reused, "replay_drops": drops, "cpu_fed": cpu, "esp": esp}
    finally:
        await command(r.target, r.session, "iptables", "-t", "nat", "-D", *exempt)
        await asyncio.to_thread(r.lan.run, f"rm -f {BLASTER}", timeout=15)

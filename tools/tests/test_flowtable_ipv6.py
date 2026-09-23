"""IPv6 flowtable offload: routed, SNAT, DNAT and TCP, each proved in hardware.

Every case establishes the flow, asserts the adapter's view of both directions,
then sends a second burst and requires the classifier's own packet counters to
account for all of it. A translated case additionally asserts what the far
endpoint observed, which is the only evidence that the 16-byte address rewrite
reached the wire rather than just the rule.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import socket
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from _topology import (DUT_IPV6_LAN, DUT_IPV6_WAN, LAN_IPV6, LAN_NIC, TARGET_LAN_IF,
                       TARGET_WAN_IF, VIRT_IPV6, WAN_IPV6, lan_run, lan_run_python)
from test_flowtable_offload import Rig, command, read, stop_boot_daemon

TABLE = "ask_poc6"
NAT_TABLE = "ask_nat6"
# Distinct per case so a leftover conntrack from one never feeds another.
PORTS = {"routed": (48810, 48811), "snat": (48820, 48821),
         "dnat": (48830, 48831), "tcp": (48840, 48841),
         "masquerade": (48850, 48851), "mtu": (48860, 48861),
         "exceptions": (48870, 48871), "bound": (48880, 48881),
         "budget": (48900, 48990)}
SNAT_PORT = 49820


class IPv6Rig(Rig):
    """Only the family-independent parts of Rig are reused: state, wait, record.
    Its table, conntrack and exchange helpers are IPv4-shaped by construction."""


def _endpoint(address, port):
    return f"[{address}]:{port}"


async def _nft(r, text):
    return await command(r.target, r.session, "nft", text)


async def _drop_tables(r):
    for family, name in (("inet", TABLE), ("ip6", NAT_TABLE)):
        await command(r.target, r.session, "nft", "delete", "table", family, name,
                      check=False)


async def _offload_table(r, match):
    await _nft(r, f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }};
 flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 {match} flow add @fast
 }}
}}''')
    await r.wait(lambda s: s["bindings"] == 2)


class Echo(asyncio.DatagramProtocol):
    """Records the source each datagram arrived from: under SNAT that is the
    translated endpoint, which is what proves the rewrite reached the wire."""

    def __init__(self):
        self.packets = 0
        self.sources = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.packets += 1
        self.sources.add((addr[0], addr[1]))
        self.transport.sendto(data, addr)


class PayloadEcho(Echo):
    """Also counts each payload: what an exception case must or must not have
    delivered across the DUT."""

    def __init__(self):
        super().__init__()
        self.received = Counter()

    def datagram_received(self, data, addr):
        self.received[data] += 1
        super().datagram_received(data, addr)


BLOCK = bytes(range(256)) * 16


class Connection:
    """Controller side of flowtable_ipv6_tcp_peer, speaking over the tested
    connection itself."""

    def __init__(self, reader, writer, peer):
        self.reader, self.writer, self.peer = reader, writer, peer

    async def transfer(self, op, blocks):
        self.writer.write(json.dumps({"op": op, "blocks": blocks}).encode() + b"\n")
        await self.writer.drain()
        if op == "download":
            for _ in range(blocks):
                self.writer.write(BLOCK)
            await self.writer.drain()
        else:
            remaining = blocks * len(BLOCK)
            while remaining:
                chunk = await self.reader.read(min(remaining, 65536))
                assert chunk, ("peer stopped mid-upload", remaining)
                remaining -= len(chunk)
        report = json.loads(await self.reader.readline())
        assert report == {"op": op, "bytes": blocks * len(BLOCK)}, report
        return report

    async def close(self):
        self.writer.write(b'{"op": "close"}\n')
        await self.writer.drain()


@asynccontextmanager
async def _tcp_connection(r, sport, dport):
    accepted = asyncio.Queue()
    server = await asyncio.start_server(
        lambda rd, wr: accepted.put_nowait((rd, wr)), WAN_IPV6, dport, family=socket.AF_INET6)
    script = (f"LAN_IPV6={LAN_IPV6!r}; WAN_IPV6={WAN_IPV6!r}; SPORT={sport}; DPORT={dport}\n" +
              Path(__file__).with_name("flowtable_ipv6_tcp_peer.py").read_text())
    peer = asyncio.create_task(lan_run_python(r.lan, script, timeout=180,
                                              label="flowtable_v6_tcp"))
    writer = None
    try:
        reader, writer = await asyncio.wait_for(accepted.get(), 20)
        assert writer.get_extra_info("peername")[:2] == (LAN_IPV6, sport)
        assert json.loads(await asyncio.wait_for(reader.readline(), 10)) == {"ready": True}
        yield Connection(reader, writer, peer)
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
        server.close()
        await server.wait_closed()
        # The LAN UART is single-channel: this operation must finish before
        # fixture cleanup can use it again, including after a failed assertion.
        result = await peer
        r.record("ipv6-tcp-peer-last", {"rc": result.rc, "stdout": result.stdout})


@pytest_asyncio.fixture
async def ipv6_rig(target_agent, aiohttp_session, lan, splat_window):
    """LAN VM <-> DUT <-> WAN host over two ULA /64s, with both endpoints
    pinned as permanent neighbours so admission never races ND. Teardown
    reverses only what actually came up."""
    r = IPv6Rig()
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    await stop_boot_daemon()
    initial = await r.state()
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    # The adapter's error count is cumulative for the boot and never reset;
    # tests that inject failures may already have run. Only errors raised
    # from here are this file's own.
    r.errors = initial["errors"]
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    r.wan = wan
    cleanup = []

    async def target(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    try:
        lan_link = json.loads((await lan_run(lan, f"ip -j link show dev {LAN_NIC}"))
                              .stdout.strip())[0]
        r.lan_mac = lan_link["address"]
        r.dut_lan_mac = (await read(r.target, r.session,
                                    f"/sys/class/net/{TARGET_LAN_IF}/address")).strip()
        r.dut_wan_mac = (await read(r.target, r.session,
                                    f"/sys/class/net/{TARGET_WAN_IF}/address")).strip()
        # The IPv6 endpoint shares the interface that already carries the IPv4
        # WAN address, so the two topologies describe the same physical path.
        wan_v4 = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
        addresses = json.loads((await command(wan, r.session, "ip", "-j", "-4", "addr"))["stdout"])
        r.wan_if = next(i["ifname"] for i in addresses
                        if any(a.get("local") == wan_v4 for a in i["addr_info"]))
        r.wan_mac = json.loads((await command(wan, r.session, "ip", "-j", "link", "show",
                                              "dev", r.wan_if))["stdout"])[0]["address"]

        previous = (await target("sysctl", "-n", "net.ipv6.conf.all.forwarding"))["stdout"].strip()
        cleanup.append(lambda v=previous: target("sysctl", "-w",
                                                 f"net.ipv6.conf.all.forwarding={v}"))
        await target("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")

        # nodad on every static address: DAD would leave it tentative for
        # ~1.5s and the first flow of the session would silently not come up.
        for address, interface in ((DUT_IPV6_LAN, TARGET_LAN_IF), (DUT_IPV6_WAN, TARGET_WAN_IF)):
            await target("ip", "-6", "addr", "del", f"{address}/64", "dev", interface,
                         check=False)
            await target("ip", "-6", "addr", "add", f"{address}/64", "dev", interface, "nodad")
            cleanup.append(lambda a=address, i=interface: target(
                "ip", "-6", "addr", "del", f"{a}/64", "dev", i, check=False))

        await lan_run(lan, f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null; true")
        result = await lan_run(lan, f"ip -6 addr add {LAN_IPV6}/64 dev {LAN_NIC} nodad")
        assert result.rc == 0, result.stdout

        async def _lan_address():
            await lan_run(lan, f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null; true")
        cleanup.append(_lan_address)

        # replace, not add: loki may already hold a default route learned from
        # the DUT's router advertisements via a link-local next hop.
        await lan_run(lan, f"ip -6 route replace default via {DUT_IPV6_LAN} dev {LAN_NIC}")
        await lan_run(lan, f"ip -6 neigh replace {DUT_IPV6_LAN} lladdr {r.dut_lan_mac} "
                           f"nud permanent dev {LAN_NIC}")

        async def _lan_route():
            await lan_run(lan, f"ip -6 route del default via {DUT_IPV6_LAN} 2>/dev/null; true")
            await lan_run(lan, f"ip -6 neigh del {DUT_IPV6_LAN} dev {LAN_NIC} 2>/dev/null; true")
        cleanup.append(_lan_route)

        await command(wan, r.session, "ip", "-6", "addr", "del", f"{WAN_IPV6}/64",
                      "dev", r.wan_if, check=False)
        await command(wan, r.session, "ip", "-6", "addr", "add", f"{WAN_IPV6}/64",
                      "dev", r.wan_if, "nodad")
        cleanup.append(lambda: command(wan, r.session, "ip", "-6", "addr", "del",
                                       f"{WAN_IPV6}/64", "dev", r.wan_if, check=False))
        await command(wan, r.session, "ip", "-6", "route", "replace", f"{LAN_IPV6}/128",
                      "via", DUT_IPV6_WAN, "dev", r.wan_if)
        cleanup.append(lambda: command(wan, r.session, "ip", "-6", "route", "del",
                                       f"{LAN_IPV6}/128", "dev", r.wan_if, check=False))
        await command(wan, r.session, "ip", "-6", "neigh", "replace", DUT_IPV6_WAN,
                      "lladdr", r.dut_wan_mac, "nud", "permanent", "dev", r.wan_if)
        cleanup.append(lambda: command(wan, r.session, "ip", "-6", "neigh", "del",
                                       DUT_IPV6_WAN, "dev", r.wan_if, check=False))

        for address, mac, interface in ((LAN_IPV6, r.lan_mac, TARGET_LAN_IF),
                                        (WAN_IPV6, r.wan_mac, TARGET_WAN_IF),
                                        (VIRT_IPV6, r.wan_mac, TARGET_WAN_IF)):
            await target("ip", "-6", "neigh", "replace", address, "lladdr", mac,
                         "nud", "permanent", "dev", interface)
            cleanup.append(lambda a=address, i=interface: target(
                "ip", "-6", "neigh", "del", a, "dev", i, check=False))

        accounting = (await read(r.target, r.session,
                                 "/proc/sys/net/netfilter/nf_conntrack_acct")).strip()
        await target("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
        cleanup.append(lambda v=accounting: target(
            "sysctl", "-w", f"net.netfilter.nf_conntrack_acct={v}"))

        await _drop_tables(r)
        r.record("ipv6-fixture", {"lan": LAN_IPV6, "wan": WAN_IPV6, "virtual": VIRT_IPV6,
                                  "lan_mac": r.lan_mac, "wan_mac": r.wan_mac,
                                  "dut_lan_mac": r.dut_lan_mac, "dut_wan_mac": r.dut_wan_mac,
                                  "wan_if": r.wan_if, "initial": initial})
        yield r
    finally:
        failures = []
        try:
            await _drop_tables(r)
            await r.wait(lambda s: not s["bindings"] and not s["entries"])
        except Exception as error:
            failures.append(str(error))
        for step in reversed(cleanup):
            try:
                await step()
            except Exception as error:
                failures.append(str(error))
        assert not failures, ("IPv6 fixture restoration failed", failures)


async def _udp_exchange(r, sport, destination, dport, count, expect_from, label):
    """Echo `count` datagrams from the LAN VM. A wrong payload or a reply from
    the wrong endpoint is always fatal — under DNAT `expect_from` is the
    pre-translation destination, which only matches if the reverse rewrite was
    applied. A timeout is merely counted, so the caller can tolerate loss while
    the flow is still being admitted and forbid it once it is installed."""
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(2)
s.bind(({LAN_IPV6!r}, {sport}))
echoed = lost = 0
for n in range({count}):
    payload = struct.pack('!Q', n) + b'ASK-flowtable-v6'.ljust(48, b'.')
    s.sendto(payload, ({destination!r}, {dport}))
    try:
        data, addr = s.recvfrom(2048)
    except TimeoutError:
        lost += 1
        continue
    assert data == payload, (n, data)
    assert (addr[0], addr[1]) == ({expect_from[0]!r}, {expect_from[1]}), (n, addr)
    echoed += 1
    time.sleep(0.01)
s.close()
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
'''
    result = await lan_run_python(r.lan, script, timeout=count * 0.3 + 40, label=label)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


def _assert_pair(state, proto, forward, reverse):
    """Both directions installed, family-tagged, and carrying the expected
    translation. `forward`/`reverse` are (src, dst, new_src, new_dst, nexthop)."""
    assert state["entries"] == 2, state
    rows = {f["in"]: f for f in state["flows"]}
    assert set(rows) == {TARGET_LAN_IF, TARGET_WAN_IF}, state
    for interface, expected in ((TARGET_LAN_IF, forward), (TARGET_WAN_IF, reverse)):
        flow = rows[interface]
        assert flow["family"] == "6", state
        assert flow["proto"] == str(proto), state
        assert tuple(flow[k] for k in ("src", "dst", "new_src", "new_dst", "nexthop")) \
            == expected, state
    return rows


def _hardware_delta(before, after):
    """Per-direction classifier packet counts, keyed by ingress interface."""
    return {i: int(after[i]["packets"]) - int(before[i]["packets"]) for i in before}


async def _drive(r, send, settled, failure, timeout=10):
    """Exchange traffic until `settled(state)` holds, failing with `failure`
    once `timeout` seconds have passed. A deadline, not a round count: an
    admission can lose rtnl_trylock in the backend, which declines it and
    retires the generation, and Linux re-offers the flow only after two
    flowtable GC ticks. A round is one short LAN exchange plus a state read,
    well under a second, so the default covers that retry several times."""
    deadline = time.monotonic() + timeout
    while True:
        await send()
        state = await r.state()
        if settled(state):
            return state
        if time.monotonic() >= deadline:
            pytest.fail(f"{failure}: {state}")


async def _settle(r, proto, forward, reverse, send, label):
    """Drive traffic until both directions are installed, then record them."""
    state = await _drive(r, send, lambda s: s["entries"] == 2, "IPv6 flow did not install")
    rows = _assert_pair(state, proto, forward, reverse)
    r.record(label, state)
    return state, rows


@pytest.mark.parametrize("case", ["routed", "snat", "dnat"])
async def test_flowtable_ipv6_udp(ipv6_rig, case):
    r = ipv6_rig
    sport, dport = PORTS[case]
    loop = asyncio.get_running_loop()
    echo = Echo()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, dport), family=socket.AF_INET6)
    # Where the LAN sends, what the WAN endpoint should see as the source, and
    # what the LAN should see replies coming back from.
    destination = VIRT_IPV6 if case == "dnat" else WAN_IPV6
    seen_source = (DUT_IPV6_WAN, SNAT_PORT) if case == "snat" else (LAN_IPV6, sport)
    reply_from = (destination, dport)
    if case == "snat":
        forward = (_endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport),
                   _endpoint(DUT_IPV6_WAN, SNAT_PORT), _endpoint(WAN_IPV6, dport), WAN_IPV6)
        reverse = (_endpoint(WAN_IPV6, dport), _endpoint(DUT_IPV6_WAN, SNAT_PORT),
                   _endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport), LAN_IPV6)
    elif case == "dnat":
        forward = (_endpoint(LAN_IPV6, sport), _endpoint(VIRT_IPV6, dport),
                   _endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport), WAN_IPV6)
        reverse = (_endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport),
                   _endpoint(VIRT_IPV6, dport), _endpoint(LAN_IPV6, sport), LAN_IPV6)
    else:
        forward = (_endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport),
                   _endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport), WAN_IPV6)
        reverse = (_endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport),
                   _endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport), LAN_IPV6)
    try:
        if case == "snat":
            await _nft(r, f'table ip6 {NAT_TABLE} {{ chain postrouting {{ '
                          f'type nat hook postrouting priority 90; '
                          f'ip6 saddr {LAN_IPV6} ip6 daddr {WAN_IPV6} udp sport {sport} '
                          f'udp dport {dport} snat to [{DUT_IPV6_WAN}]:{SNAT_PORT}; }}; }}')
        elif case == "dnat":
            await _nft(r, f'table ip6 {NAT_TABLE} {{ chain prerouting {{ '
                          f'type nat hook prerouting priority -100; '
                          f'ip6 saddr {LAN_IPV6} ip6 daddr {VIRT_IPV6} udp sport {sport} '
                          f'udp dport {dport} dnat to [{WAN_IPV6}]:{dport}; }}; }}')
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} udp sport {sport} udp dport {dport}')

        async def send(count=8):
            return await _udp_exchange(r, sport, destination, dport, count, reply_from,
                                       f"flowtable_v6_{case}")

        before_state, before = await _settle(r, socket.IPPROTO_UDP, forward, reverse,
                                             send, f"ipv6-{case}-admission")
        assert echo.sources == {seen_source}, echo.sources

        # Everything from here must be forwarded by the classifier itself,
        # with nothing falling back to software.
        report = await send(64)
        assert report == {"echoed": 64, "lost": 0}, report
        after_state = await r.state()
        after = _assert_pair(after_state, socket.IPPROTO_UDP, forward, reverse)
        delta = _hardware_delta(before, after)
        assert delta == {TARGET_LAN_IF: 64, TARGET_WAN_IF: 64}, (delta, before_state, after_state)
        assert before_state["installs"] == after_state["installs"], (before_state, after_state)
        assert before_state["deletes"] == after_state["deletes"], (before_state, after_state)
        assert after_state["errors"] == r.errors, after_state
        assert echo.sources == {seen_source}, echo.sources
        for direction in before:
            assert after[direction]["cookie"] == before[direction]["cookie"], (before, after)
        r.record(f"ipv6-{case}-hardware", {"before": before_state, "after": after_state,
                                           "hardware_delta": delta,
                                           "observed_sources": sorted(echo.sources)})
    finally:
        transport.close()
        await _drop_tables(r)


async def test_flowtable_ipv6_tcp(ipv6_rig):
    r = ipv6_rig
    sport, dport = PORTS["tcp"]
    forward = (_endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport),
               _endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport), WAN_IPV6)
    reverse = (_endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport),
               _endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport), LAN_IPV6)
    try:
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} tcp sport {sport} tcp dport {dport}')
        # One connection carries the whole test. The handshake is punted by the
        # soft parser and admission waits for ESTABLISHED, so the flow installs
        # part-way through it and the later transfers are the hardware
        # measurement -- which is why the peer is driven over this connection
        # rather than by a second console operation.
        async with _tcp_connection(r, sport, dport) as conn:
            state, before = await _settle(
                r, socket.IPPROTO_TCP, forward, reverse,
                lambda: conn.transfer("upload", 4), "ipv6-tcp-admission")
            await conn.transfer("upload", 64)
            await conn.transfer("download", 64)
            after_state = await r.state()
            after = _assert_pair(after_state, socket.IPPROTO_TCP, forward, reverse)
            delta = _hardware_delta(before, after)
            # Segments are not payload units: TCP coalesces and acknowledges on
            # its own schedule, and the peer's window is its own business. Half
            # a megabyte each way cannot cross in fewer than a hundred frames,
            # so require that much rather than an exact count.
            assert delta[TARGET_LAN_IF] >= 100 and delta[TARGET_WAN_IF] >= 100, \
                (delta, after_state)
            assert after_state["errors"] == r.errors, after_state
            assert state["installs"] == after_state["installs"], (state, after_state)
            for direction in before:
                assert after[direction]["cookie"] == before[direction]["cookie"], (before, after)
            r.record("ipv6-tcp-hardware", {"before": state, "after": after_state,
                                           "hardware_delta": delta})
            await conn.close()
    finally:
        await _drop_tables(r)


def _split_endpoint(text):
    """Parse a proc row's `[addr]:port` into its parts."""
    address, _, port = text.rpartition(":")
    return address.strip("[]"), int(port)


async def test_flowtable_ipv6_masquerade(ipv6_rig):
    """MASQUERADE picks both the source address and the port, so pin the
    address to the egress interface's own and let the kernel own the port —
    then require the far endpoint to have seen exactly what it chose."""
    r = ipv6_rig
    sport, dport = PORTS["masquerade"]
    loop = asyncio.get_running_loop()
    echo = Echo()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, dport), family=socket.AF_INET6)
    try:
        await _nft(r, f'table ip6 {NAT_TABLE} {{ chain postrouting {{ '
                      f'type nat hook postrouting priority 90; '
                      f'ip6 saddr {LAN_IPV6} ip6 daddr {WAN_IPV6} udp sport {sport} '
                      f'udp dport {dport} masquerade; }}; }}')
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} udp sport {sport} udp dport {dport}')

        async def send(count=8):
            return await _udp_exchange(r, sport, WAN_IPV6, dport, count, (WAN_IPV6, dport),
                                       "flowtable_v6_masquerade")

        state = await _drive(r, send, lambda s: s["entries"] == 2,
                             "IPv6 masquerade did not install")
        rows = {f["in"]: f for f in state["flows"]}
        assert set(rows) == {TARGET_LAN_IF, TARGET_WAN_IF}, state
        forward, reverse = rows[TARGET_LAN_IF], rows[TARGET_WAN_IF]
        assert forward["family"] == reverse["family"] == "6", state
        translated, port = _split_endpoint(forward["new_src"])
        assert translated == DUT_IPV6_WAN, (forward, DUT_IPV6_WAN)
        assert forward["src"] == _endpoint(LAN_IPV6, sport), state
        assert forward["new_dst"] == _endpoint(WAN_IPV6, dport), state
        # The reverse direction must carry the inverse of whatever was chosen.
        assert reverse["dst"] == _endpoint(DUT_IPV6_WAN, port), state
        assert reverse["new_dst"] == _endpoint(LAN_IPV6, sport), state
        assert echo.sources == {(DUT_IPV6_WAN, port)}, (echo.sources, port)
        r.record("ipv6-masquerade-admission", state)

        before = rows
        report = await send(64)
        assert report == {"echoed": 64, "lost": 0}, report
        after_state = await r.state()
        after = {f["in"]: f for f in after_state["flows"]}
        delta = _hardware_delta(before, after)
        assert delta == {TARGET_LAN_IF: 64, TARGET_WAN_IF: 64}, (delta, after_state)
        assert after_state["errors"] == r.errors, after_state
        assert echo.sources == {(DUT_IPV6_WAN, port)}, echo.sources
        r.record("ipv6-masquerade-hardware", {"after": after_state, "hardware_delta": delta,
                                              "translated_port": port})
    finally:
        transport.close()
        await _drop_tables(r)


async def test_flowtable_ipv6_mtu_recovery(ipv6_rig):
    """A device MTU change must retire both IPv6 directions and let them come
    back describing the new MTU, exactly as the IPv4 path does.

    The LAN's IPv6 MTU is lowered with the WAN, as an operator would for any
    smaller upstream: a LAN-to-WAN direction may only be in hardware while no
    LAN host is told it can send more than the path carries (see
    test_flowtable_ipv6_mtu_bound). It also lowers the LAN route, so both
    directions come back at 1400."""
    r = ipv6_rig
    sport, dport = PORTS["mtu"]
    loop = asyncio.get_running_loop()
    echo = Echo()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, dport), family=socket.AF_INET6)
    original = int((await read(r.target, r.session, f"/sys/class/net/{TARGET_WAN_IF}/mtu")).strip())
    assert original == 1500, original
    lan_mtu = f"net.ipv6.conf.{TARGET_LAN_IF}.mtu"
    try:
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} udp sport {sport} udp dport {dport}')

        async def send(count=8):
            return await _udp_exchange(r, sport, WAN_IPV6, dport, count, (WAN_IPV6, dport),
                                       "flowtable_v6_mtu")

        async def settled(expected):
            """`expected` maps egress device to MTU: a direction describes the
            path it leaves by, so only the one egressing the changed device
            moves."""
            # The reduce step below retires the flow twice over (the MTU change,
            # then the injected lost RTNL), four GC ticks in the worst case.
            return await _drive(r, send, lambda s: s["entries"] == 2 and all(
                int(f["mtu"]) == expected[f["out"]] for f in s["flows"]),
                f"IPv6 flow did not settle at MTU {expected}", timeout=20)

        initial = await settled({TARGET_LAN_IF: original, TARGET_WAN_IF: original})
        r.record("ipv6-mtu-initial", initial)
        # 1400 is below the port MTU and above the IPv6 minimum, so the flow
        # stays admissible and simply has to be re-described.
        #
        # The readmission is made to lose RTNL on its second direction. The
        # backend never waits for RTNL under its transaction: it declines with
        # -EAGAIN, retires the generation, and Linux re-offers the flow after
        # two flowtable GC ticks. Any RTNL holder can cause that in production,
        # so the re-description has to survive it every run, not by chance.
        #
        # The LAN's IPv6 MTU goes first: lowering it leaves both installed
        # directions bounded, so nothing retires until the device change.
        await command(r.target, r.session, "sysctl", "-w", f"{lan_mtu}=1400")
        knob = "/sys/module/ask_flowtable/parameters/flowtable_fail_stage"
        assert (await r.target.fs_write(r.session, knob, "4"))["errno"] == 0
        try:
            await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF,
                          "mtu", "1400")
            # Both directions of a connection share one invalidation handle and
            # the counter moves on the transition, so a single connection
            # retiring is one increment -- not one per direction.
            retired = await r.wait(lambda s: s["mtu_invalidations"] >= initial["mtu_invalidations"] + 1)
            reduced = await settled({TARGET_LAN_IF: 1400, TARGET_WAN_IF: 1400})
            assert (await read(r.target, r.session, knob)).strip() == "0", "fault not consumed"
        finally:
            assert (await r.target.fs_write(r.session, knob, "0"))["errno"] == 0
        assert reduced["errors"] == r.errors, reduced
        assert reduced["busy"] >= initial["busy"] + 1, (initial, reduced)
        assert reduced["admission_invalidations"] >= initial["admission_invalidations"] + 1, \
            (initial, reduced)
        r.record("ipv6-mtu-reduced", {"retired": retired, "reduced": reduced})
        # The LAN first again, so the WAN-to-LAN direction is never left
        # unbounded behind a 1400-byte WAN: raising it retires the bounded
        # LAN-to-WAN one, and the device change then retires whatever came
        # back in between.
        await command(r.target, r.session, "sysctl", "-w", f"{lan_mtu}={original}")
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF,
                      "mtu", str(original))
        restored = await settled({TARGET_LAN_IF: original, TARGET_WAN_IF: original})
        assert restored["errors"] == r.errors, restored
        r.record("ipv6-mtu-restored", restored)
    finally:
        transport.close()
        await command(r.target, r.session, "sysctl", "-w", f"{lan_mtu}={original}", check=False)
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF,
                      "mtu", str(original), check=False)
        await _drop_tables(r)


async def test_flowtable_ipv6_same_tuple_exceptions(ipv6_rig):
    """Packets on an offloaded IPv6 tuple that Linux must handle still reach it.

    The IPv6 counterpart of test_flowtable_offload_same_tuple_exceptions. With
    both directions in hardware, the same 5-tuple carries a hop limit of 1,
    which must come back as an ICMPv6 error from Linux rather than leave the
    WAN port, and hop-by-hop options, destination options, a chain of both and
    fragments, which Linux forwards intact. The entries must still be carrying
    the flow afterwards. An oversized packet is not among them: a path smaller
    than the LAN's IPv6 MTU never has that direction in hardware at all, which
    test_flowtable_ipv6_mtu_bound covers.
    """
    r = ipv6_rig
    sport, dport = PORTS["exceptions"]
    loop = asyncio.get_running_loop()
    echo = PayloadEcho()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, dport), family=socket.AF_INET6)
    forward = (_endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport),
               _endpoint(LAN_IPV6, sport), _endpoint(WAN_IPV6, dport), WAN_IPV6)
    reverse = (_endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport),
               _endpoint(WAN_IPV6, dport), _endpoint(LAN_IPV6, sport), LAN_IPV6)
    try:
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} udp sport {sport} udp dport {dport}')

        async def send(count=8):
            return await _udp_exchange(r, sport, WAN_IPV6, dport, count, (WAN_IPV6, dport),
                                       "flowtable_v6_exceptions")

        admitted, admitted_rows = await _settle(r, socket.IPPROTO_UDP, forward, reverse, send,
                                                "ipv6-exceptions-admission")
        script = f'''
import json, socket, struct, time
from scapy.all import (Ether, IPv6, UDP, Raw, ICMPv6TimeExceeded,
                       IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
                       fragment6, sendp, srp1)
iface = {LAN_NIC!r}
src, dst = {LAN_IPV6!r}, {WAN_IPV6!r}
sport, dport = {sport}, {dport}
eth = Ether(dst={r.dut_lan_mac!r})
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind((src, sport)); s.settimeout(3)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
def udp(payload, *headers, hlim=64):
    packet = IPv6(src=src, dst=dst, hlim=hlim)
    for header in headers:
        packet = packet/header
    return packet/UDP(sport=sport, dport=dport)/Raw(payload)
results = {{}}
answer = srp1(eth/udp(b'ASK6-expired', hlim=1), iface=iface, timeout=3, verbose=False)
assert answer is not None and ICMPv6TimeExceeded in answer, answer
results['hoplimit'] = answer.summary()
fragments = b'ASK6-fragments'.ljust(1024, b'.')
for name, packets, payload in [
    ('hop_by_hop', [udp(b'ASK6-hbh', IPv6ExtHdrHopByHop())], b'ASK6-hbh'),
    ('destination', [udp(b'ASK6-dest', IPv6ExtHdrDestOpt())], b'ASK6-dest'),
    ('chain', [udp(b'ASK6-chain', IPv6ExtHdrHopByHop(), IPv6ExtHdrDestOpt())], b'ASK6-chain'),
    ('fragments', fragment6(udp(fragments, IPv6ExtHdrFragment()), 600), fragments),
]:
    sendp([eth/p for p in packets], iface=iface, verbose=False)
    data, anc, flags, addr = s.recvmsg(4096, 128)
    assert data == payload and addr[:2] == (dst, dport), (name, data, addr)
    hops = [struct.unpack('i', v)[0] for level, kind, v in anc
            if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_HOPLIMIT]
    assert hops == [63], (name, hops)
    results[name] = len(data)
time.sleep(0.5)
s.close()
print(json.dumps(results))
'''
        result = await lan_run_python(r.lan, script, timeout=40, label="flowtable_v6_exceptions")
        assert result.rc == 0, result.stdout
        for payload in (b"ASK6-hbh", b"ASK6-dest", b"ASK6-chain", b"ASK6-fragments".ljust(1024, b".")):
            assert echo.received[payload] == 1, (payload, echo.received)
        assert not echo.received[b"ASK6-expired"], echo.received

        # The exceptions went to Linux; the entries kept the flow.
        before_state = await r.state()
        before = _assert_pair(before_state, socket.IPPROTO_UDP, forward, reverse)
        report = await send(16)
        assert report == {"echoed": 16, "lost": 0}, report
        after_state = await r.state()
        after = _assert_pair(after_state, socket.IPPROTO_UDP, forward, reverse)
        delta = _hardware_delta(before, after)
        assert delta == {TARGET_LAN_IF: 16, TARGET_WAN_IF: 16}, (delta, before_state, after_state)
        for direction in before:
            assert after[direction]["cookie"] == admitted_rows[direction]["cookie"], (admitted, after_state)
        assert after_state["errors"] == r.errors, after_state
        r.record("ipv6-exceptions", {"results": json.loads(result.stdout.strip().splitlines()[-1]),
                                     "admitted": admitted, "after": after_state,
                                     "hardware_delta": delta})
    finally:
        transport.close()
        await _drop_tables(r)


async def test_flowtable_ipv6_mtu_bound(ipv6_rig):
    """The microcode fragments an IPv6 packet over its entry's MTU instead of
    handing it to Linux, so a direction whose path is smaller than its ingress
    interface's IPv6 MTU must stay in software, where Linux answers with
    Packet Too Big. The route to the WAN host is locked to 1280, the minimum.

    While the LAN's IPv6 MTU is 1280 as well, the LAN-to-WAN direction is
    bounded and goes to hardware; the WAN-to-LAN one is not, because the LAN
    route now carries 1280 against a 1500-byte WAN. Raising the LAN back to
    1500 is a sysctl no device event reports, so the next stats pass has to
    retire the flow, and it comes back the other way round. Then an oversized
    packet gets its Packet Too Big and the microcode fragments nothing.
    """
    r = ipv6_rig
    sport, dport = PORTS["bound"]
    loop = asyncio.get_running_loop()
    echo = PayloadEcho()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, dport), family=socket.AF_INET6)
    lan_mtu = f"net.ipv6.conf.{TARGET_LAN_IF}.mtu"
    original = (await command(r.target, r.session, "sysctl", "-n", lan_mtu))["stdout"].strip()
    assert original == "1500", original
    # IPv6 forwarding ignores an unlocked route MTU (ip6_dst_mtu_maybe_forward),
    # in software and so in the flow too.
    route = ["ip", "-6", "route", "replace", f"{WAN_IPV6}/128", "dev", TARGET_WAN_IF,
             "mtu", "lock", "1280"]

    def one_direction(ingress, mtu):
        def settled(s):
            return (s["entries"] == 1 and s["flows"][0]["in"] == ingress
                    and int(s["flows"][0]["mtu"]) == mtu)
        return settled

    async def send(count=8):
        return await _udp_exchange(r, sport, WAN_IPV6, dport, count, (WAN_IPV6, dport),
                                   "flowtable_v6_bound")

    async def fragments_sent():
        text = await read(r.target, r.session, "/proc/ucode_frag/stats")
        return int(text.split("Number of IPv6 fragments sent :")[1].split()[0])

    try:
        await command(r.target, r.session, "sysctl", "-w", f"{lan_mtu}=1280")
        await command(r.target, r.session, *route)
        initial = await r.state()
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} udp sport {sport} udp dport {dport}')
        bounded = await _drive(r, send, one_direction(TARGET_LAN_IF, 1280),
                               "only the LAN-to-WAN direction should be in hardware")
        assert bounded["rejects"] > initial["rejects"], (initial, bounded)
        r.record("ipv6-bound-lan", bounded)

        await command(r.target, r.session, "sysctl", "-w", f"{lan_mtu}={original}")
        retired = await r.wait(lambda s: s["mtu_invalidations"] > bounded["mtu_invalidations"])
        unbounded = await _drive(r, send, one_direction(TARGET_WAN_IF, 1500),
                                 "only the WAN-to-LAN direction should be in hardware")
        r.record("ipv6-bound-wan", {"retired": retired, "unbounded": unbounded})

        before = await fragments_sent()
        script = f'''
import json
from scapy.all import Ether, IPv6, UDP, Raw, ICMPv6PacketTooBig, srp1
packet = IPv6(src={LAN_IPV6!r}, dst={WAN_IPV6!r})/UDP(sport={sport}, dport={dport})/Raw(b'M' * 1400)
answer = srp1(Ether(dst={r.dut_lan_mac!r})/packet, iface={LAN_NIC!r}, timeout=3, verbose=False)
assert answer is not None and ICMPv6PacketTooBig in answer, answer
assert answer[ICMPv6PacketTooBig].mtu == 1280, answer.show(dump=True)
print(json.dumps(answer.summary()))
'''
        result = await lan_run_python(r.lan, script, timeout=20, label="flowtable_v6_bound")
        assert result.rc == 0, result.stdout
        await asyncio.sleep(0.5)
        assert not echo.received[b"M" * 1400], echo.received
        assert await fragments_sent() == before

        # Small packets still cross, the bounded direction in software.
        report = await send(16)
        assert report == {"echoed": 16, "lost": 0}, report
        final = await r.state()
        assert one_direction(TARGET_WAN_IF, 1500)(final), final
        assert final["errors"] == r.errors, final
        r.record("ipv6-bound", {"too_big": result.stdout.strip().splitlines()[-1], "final": final})
    finally:
        transport.close()
        await _drop_tables(r)
        await command(r.target, r.session, "ip", "-6", "route", "del", f"{WAN_IPV6}/128",
                      "dev", TARGET_WAN_IF, check=False)
        await command(r.target, r.session, "sysctl", "-w", f"{lan_mtu}={original}", check=False)


async def test_flowtable_ipv6_shares_the_admission_budget(ipv6_rig):
    """Both families draw on one budget and one pair of software indexes, so
    many concurrent IPv6 flows must each consume two directions and nothing
    else. This is accounting at a readable scale, not a capacity fill."""
    r = ipv6_rig
    base, dport = PORTS["budget"]
    count = 24
    loop = asyncio.get_running_loop()
    echo = Echo()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, dport), family=socket.AF_INET6)
    try:
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} udp dport {dport}')
        script = f'''
import json, socket, struct, time
sockets = []
for n in range({count}):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.bind(({LAN_IPV6!r}, {base} + n))
    sockets.append(s)
echoed = lost = 0
for _round in range(6):
    for n, s in enumerate(sockets):
        payload = struct.pack('!Q', n) + b'ASK-v6-budget'.ljust(48, b'.')
        s.sendto(payload, ({WAN_IPV6!r}, {dport}))
        try:
            data, addr = s.recvfrom(2048)
        except TimeoutError:
            lost += 1
            continue
        assert data == payload, (n, data)
        echoed += 1
    time.sleep(0.05)
for s in sockets:
    s.close()
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
'''
        async def send():
            result = await lan_run_python(r.lan, script, timeout=120, label="flowtable_v6_budget")
            assert result.rc == 0, result.stdout

        # Each round drives every connection, so a round is long; the budget
        # still has to hold a lost-RTNL retry on any one of them.
        state = await _drive(r, send, lambda s: s["entries"] == 2 * count,
                             "IPv6 budget did not fill", timeout=60)
        # One budget, one index pair: every IPv6 direction is counted like an
        # IPv4 one, holds its own references, and none is double-counted.
        assert state["handle_refs"] == state["neighbour_refs"] == 2 * count, state
        assert state["max_entries"] == 32768, state
        assert state["errors"] == r.errors, state
        assert state["fatal"] == state["quarantine"] == 0, state
        assert all(f["family"] == "6" for f in state["flows"]), state
        # Every reverse direction legitimately shares one source endpoint --
        # the echo server -- so identity is the pair, not the source alone.
        assert len({(f["src"], f["dst"]) for f in state["flows"]}) == 2 * count, state
        assert len({f["src"] for f in state["flows"] if f["in"] == TARGET_LAN_IF}) == count, state
        r.record("ipv6-budget", state)
    finally:
        transport.close()
        await _drop_tables(r)


# Client and server both behind the LAN port, so a translated flow has to
# leave by the interface it arrived on. Distinct MACs and no on-link route to
# each other's address: reaching the server means going through the gateway.
HAIRPIN_GATEWAY = DUT_IPV6_LAN
HAIRPIN = {"client": {"netns": "ask-ft6-client", "iface": "askft6c",
                      "lan": "fc00:dead::12", "mac": "02:9d:99:b2:d6:12"},
           "server": {"netns": "ask-ft6-server", "iface": "askft6s",
                      "lan": "fc00:dead::13", "mac": "02:9d:99:b2:d6:13"}}
HAIRPIN_PUBLIC, HAIRPIN_MAPPED = 48870, 49870
HAIRPIN_SPORT, HAIRPIN_DPORT = 48871, 48872


def _hairpin_script(body):
    return (f"CLIENT={HAIRPIN['client']!r}\nSERVER={HAIRPIN['server']!r}\n"
            f"GATEWAY={HAIRPIN_GATEWAY!r}\nLAN_NIC={LAN_NIC!r}\n" + body)


@pytest_asyncio.fixture
async def hairpin6(ipv6_rig):
    r = ipv6_rig
    setup = _hairpin_script('''
import json, subprocess
def run(*args):
    subprocess.run(args, check=True, capture_output=True, text=True)
created = []
for peer in (CLIENT, SERVER):
    subprocess.run(['ip', 'netns', 'del', peer['netns']], capture_output=True, text=True)
for peer in (CLIENT, SERVER):
    run('ip', 'netns', 'add', peer['netns'])
    created.append(peer)
    run('ip', 'link', 'add', peer['iface'], 'link', LAN_NIC, 'netns', peer['netns'],
        'type', 'macvlan', 'mode', 'bridge')
    run('ip', '-n', peer['netns'], 'link', 'set', 'lo', 'up')
    run('ip', '-n', peer['netns'], 'link', 'set', peer['iface'], 'address', peer['mac'], 'up')
    run('ip', '-n', peer['netns'], 'addr', 'add', peer['lan'] + '/64',
        'dev', peer['iface'], 'nodad')
    run('ip', '-n', peer['netns'], 'route', 'add', 'default', 'via', GATEWAY,
        'dev', peer['iface'])
print(json.dumps({'created': [p['netns'] for p in created]}))
''')
    result = await lan_run_python(r.lan, setup, label="flowtable_v6_hairpin_setup", timeout=40)
    assert result.rc == 0, result.stdout
    cleanup = []
    for peer in HAIRPIN.values():
        await command(r.target, r.session, "ip", "-6", "neigh", "replace", peer["lan"],
                      "lladdr", peer["mac"], "nud", "permanent", "dev", TARGET_LAN_IF)
        cleanup.append(peer["lan"])
    try:
        yield r
    finally:
        for address in cleanup:
            await command(r.target, r.session, "ip", "-6", "neigh", "del", address,
                          "dev", TARGET_LAN_IF, check=False)
        teardown = _hairpin_script('''
import json, subprocess
left = []
for peer in (CLIENT, SERVER):
    result = subprocess.run(['ip', 'netns', 'del', peer['netns']], capture_output=True, text=True)
    if result.returncode:
        left.append(peer['netns'])
print(json.dumps({'left': left}))
''')
        await lan_run_python(r.lan, teardown, label="flowtable_v6_hairpin_cleanup", timeout=30)


async def _hairpin_exchange(r, external, count):
    """Both endpoints live on the LAN VM in separate namespaces, so one script
    owns the echo server and the client: the UART cannot carry two."""
    script = _hairpin_script(f'''
import json, os, socket, struct, time
def enter(netns):
    with open('/var/run/netns/' + netns, 'rb') as handle:
        os.setns(handle.fileno(), os.CLONE_NEWNET)
child = os.fork()
if child == 0:
    try:
        enter(SERVER['netns'])
        server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        server.bind((SERVER['lan'], {HAIRPIN_DPORT}))
        while True:
            data, peer = server.recvfrom(2048)
            server.sendto(data, peer)
    finally:
        os._exit(0)
time.sleep(1.0)
enter(CLIENT['netns'])
client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
client.settimeout(2)
client.bind((CLIENT['lan'], {HAIRPIN_SPORT}))
echoed = lost = 0
try:
    for n in range({count}):
        payload = struct.pack('!Q', n) + b'ASK-v6-hairpin'.ljust(48, b'.')
        client.sendto(payload, ({external!r}, {HAIRPIN_PUBLIC}))
        try:
            data, addr = client.recvfrom(2048)
        except TimeoutError:
            lost += 1
            continue
        assert data == payload, (n, data)
        # The reply must appear to come from the public endpoint the client
        # addressed, never from the server's own address.
        assert (addr[0], addr[1]) == ({external!r}, {HAIRPIN_PUBLIC}), (n, addr)
        echoed += 1
        time.sleep(0.01)
finally:
    os.kill(child, 9)
    os.waitpid(child, 0)
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
''')
    result = await lan_run_python(r.lan, script, timeout=count * 0.3 + 60,
                                  label="flowtable_v6_hairpin")
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


async def test_flowtable_ipv6_hairpin(hairpin6):
    """Source and destination translation together, with both directions
    leaving by the port they arrived on."""
    r = hairpin6
    external = DUT_IPV6_WAN
    client, server = HAIRPIN["client"]["lan"], HAIRPIN["server"]["lan"]
    public = _endpoint(external, HAIRPIN_PUBLIC)
    mapped = _endpoint(HAIRPIN_GATEWAY, HAIRPIN_MAPPED)
    origin = _endpoint(client, HAIRPIN_SPORT)
    target = _endpoint(server, HAIRPIN_DPORT)
    destination = (f'ip6 saddr {client} ip6 daddr {external} udp sport {HAIRPIN_SPORT} '
                   f'udp dport {HAIRPIN_PUBLIC} dnat to [{server}]:{HAIRPIN_DPORT};')
    source = (f'ip6 saddr {client} ip6 daddr {server} udp sport {HAIRPIN_SPORT} '
              f'udp dport {HAIRPIN_DPORT} snat to [{HAIRPIN_GATEWAY}]:{HAIRPIN_MAPPED};')
    try:
        await _nft(r, f'table ip6 {NAT_TABLE} {{ '
                      f'chain prerouting {{ type nat hook prerouting priority -110; {destination} }}; '
                      f'chain postrouting {{ type nat hook postrouting priority 90; {source} }}; }}')
        # The forward hook runs after prerouting, so the destination here is
        # already the translated one: matching the public port never fires.
        await _offload_table(r, f'ip6 saddr {client} ip6 daddr {server} '
                                f'udp sport {HAIRPIN_SPORT} udp dport {HAIRPIN_DPORT}')
        state = await _drive(r, lambda: _hairpin_exchange(r, external, 8),
                             lambda s: s["entries"] == 2, "IPv6 hairpin did not install")
        rows = {(f["src"], f["dst"]): f for f in state["flows"]}
        # Client to server carries both translations at once; the reply carries
        # both inverses. Every direction enters and leaves by the LAN port.
        assert rows.keys() == {(origin, public), (target, mapped)}, state
        assert all(f["in"] == f["out"] == TARGET_LAN_IF for f in state["flows"]), state
        assert all(f["family"] == "6" for f in state["flows"]), state
        forward, reverse = rows[(origin, public)], rows[(target, mapped)]
        assert (forward["new_src"], forward["new_dst"]) == (mapped, target), state
        assert (reverse["new_src"], reverse["new_dst"]) == (public, origin), state
        r.record("ipv6-hairpin-admission", state)

        before = {(f["src"], f["dst"]): f for f in state["flows"]}
        report = await _hairpin_exchange(r, external, 64)
        assert report == {"echoed": 64, "lost": 0}, report
        after_state = await r.state()
        after = {(f["src"], f["dst"]): f for f in after_state["flows"]}
        delta = {key: int(after[key]["packets"]) - int(before[key]["packets"]) for key in before}
        assert delta == {(origin, public): 64, (target, mapped): 64}, (delta, after_state)
        assert after_state["errors"] == r.errors, after_state
        r.record("ipv6-hairpin-hardware", {"after": after_state,
                                           "hardware_delta": {str(k): v for k, v in delta.items()}})
    finally:
        await _drop_tables(r)

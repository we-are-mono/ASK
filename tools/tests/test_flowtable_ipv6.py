"""IPv6 flowtable offload: routed, SNAT, DNAT and TCP, each proved in hardware.

Every case establishes the flow, asserts the adapter's view of both directions,
then sends a second burst and requires the classifier's own packet counters to
account for all of it. A translated case additionally asserts what the far
endpoint observed, which is the only evidence that the 16-byte address rewrite
reached the wire rather than just the rule.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import socket

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from _topology import (DUT_IPV6_LAN, DUT_IPV6_WAN, LAN_IPV6, LAN_NIC, TARGET_LAN_IF,
                       TARGET_WAN_IF, VIRT_IPV6, WAN_IPV6, lan_run, lan_run_python)
from test_flowtable_offload import Rig, command, read

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
TABLE = "ask_poc6"
NAT_TABLE = "ask_nat6"
# Distinct per case so a leftover conntrack from one never feeds another.
PORTS = {"routed": (48810, 48811), "snat": (48820, 48821),
         "dnat": (48830, 48831), "tcp": (48840, 48841)}
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
    initial = await r.state()
    assert initial["owner"] == "flowtable", "boot ask.offload=flowtable first"
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
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


async def _settle(r, proto, forward, reverse, send, label):
    """Drive traffic until both directions are installed, then record them."""
    for _ in range(10):
        await send()
        state = await r.state()
        if state["entries"] == 2:
            rows = _assert_pair(state, proto, forward, reverse)
            r.record(label, state)
            return state, rows
    pytest.fail(f"IPv6 flow did not install: {state}")


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
        assert after_state["errors"] == 0, after_state
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
            assert after_state["errors"] == 0, after_state
            assert state["installs"] == after_state["installs"], (state, after_state)
            for direction in before:
                assert after[direction]["cookie"] == before[direction]["cookie"], (before, after)
            r.record("ipv6-tcp-hardware", {"before": state, "after": after_state,
                                           "hardware_delta": delta})
            await conn.close()
    finally:
        await _drop_tables(r)

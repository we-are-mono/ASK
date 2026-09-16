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
         "dnat": (48830, 48831), "tcp": (48840, 48841),
         "masquerade": (48850, 48851), "mtu": (48860, 48861),
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

        for _ in range(10):
            await send()
            state = await r.state()
            if state["entries"] == 2:
                break
        else:
            pytest.fail(f"IPv6 masquerade did not install: {state}")
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
        assert after_state["errors"] == 0, after_state
        assert echo.sources == {(DUT_IPV6_WAN, port)}, echo.sources
        r.record("ipv6-masquerade-hardware", {"after": after_state, "hardware_delta": delta,
                                              "translated_port": port})
    finally:
        transport.close()
        await _drop_tables(r)


async def test_flowtable_ipv6_mtu_recovery(ipv6_rig):
    """A device MTU change must retire both IPv6 directions and let them come
    back describing the new MTU, exactly as the IPv4 path does."""
    r = ipv6_rig
    sport, dport = PORTS["mtu"]
    loop = asyncio.get_running_loop()
    echo = Echo()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: echo, local_addr=(WAN_IPV6, dport), family=socket.AF_INET6)
    original = int((await read(r.target, r.session, f"/sys/class/net/{TARGET_WAN_IF}/mtu")).strip())
    assert original == 1500, original
    try:
        await _offload_table(r, f'ip6 saddr {LAN_IPV6} udp sport {sport} udp dport {dport}')

        async def send(count=8):
            return await _udp_exchange(r, sport, WAN_IPV6, dport, count, (WAN_IPV6, dport),
                                       "flowtable_v6_mtu")

        async def settled(expected):
            """`expected` maps egress device to MTU: a direction describes the
            path it leaves by, so only the one egressing the changed device
            moves."""
            for _ in range(10):
                await send()
                state = await r.state()
                if state["entries"] == 2 and all(
                        int(f["mtu"]) == expected[f["out"]] for f in state["flows"]):
                    return state
            pytest.fail(f"IPv6 flow did not settle at MTU {expected}: {state}")

        initial = await settled({TARGET_LAN_IF: original, TARGET_WAN_IF: original})
        r.record("ipv6-mtu-initial", initial)
        # 1400 is below the port MTU and above the IPv6 minimum, so the flow
        # stays admissible and simply has to be re-described.
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF,
                      "mtu", "1400")
        # Both directions of a connection share one invalidation handle and
        # the counter moves on the transition, so a single connection retiring
        # is one increment -- not one per direction.
        retired = await r.wait(lambda s: s["mtu_invalidations"] >= initial["mtu_invalidations"] + 1)
        reduced = await settled({TARGET_LAN_IF: original, TARGET_WAN_IF: 1400})
        assert reduced["errors"] == 0, reduced
        r.record("ipv6-mtu-reduced", {"retired": retired, "reduced": reduced})
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF,
                      "mtu", str(original))
        restored = await settled({TARGET_LAN_IF: original, TARGET_WAN_IF: original})
        assert restored["errors"] == 0, restored
        r.record("ipv6-mtu-restored", restored)
    finally:
        transport.close()
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF,
                      "mtu", str(original), check=False)
        await _drop_tables(r)


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
        state = None
        for _ in range(6):
            result = await lan_run_python(r.lan, script, timeout=120, label="flowtable_v6_budget")
            assert result.rc == 0, result.stdout
            state = await r.state()
            if state["entries"] == 2 * count:
                break
        assert state["entries"] == 2 * count, state
        # One budget, one index pair: every IPv6 direction is counted like an
        # IPv4 one, holds its own references, and none is double-counted.
        assert state["handle_refs"] == state["neighbour_refs"] == 2 * count, state
        assert state["max_entries"] == 32768, state
        assert state["errors"] == state["fatal"] == state["quarantine"] == 0, state
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
        for _ in range(10):
            await _hairpin_exchange(r, external, 8)
            state = await r.state()
            if state["entries"] == 2:
                break
        else:
            pytest.fail(f"IPv6 hairpin did not install: {state}")
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
        assert after_state["errors"] == 0, after_state
        r.record("ipv6-hairpin-hardware", {"after": after_state,
                                           "hardware_delta": {str(k): v for k, v in delta.items()}})
    finally:
        await _drop_tables(r)

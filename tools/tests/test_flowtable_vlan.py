"""VLAN flowtable offload: the LAN sits behind an 802.1Q tag, the WAN does not.

The asymmetry is the point. One direction arrives tagged and leaves untagged,
the other the reverse, so a single connection exercises both the ingress strip
and the egress insert and neither can be mistaken for the other. Every case
asserts the tags the adapter recorded, then sends a second burst and requires
the classifier's own packet counters to account for all of it, which is the
only evidence the encapsulation reached the wire rather than just the rule.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from _topology import (LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, TopologyStack,
                       dut_vlan_subif, lan_run, lan_vlan_subif)
from test_flowtable_offload import (DPORT, Echo, SPORT, WAN_IP, Rig, command, read)

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                                reason="requires an explicit experimental boot")

# Claimed in _topology.py's VLAN ID conventions block. 271 carries the tagged
# LAN; 272 is the inner tag of the QinQ case, stacked on top of 271 so the wire
# carries 271 outside and 272 inside.
VLAN_ID = int(os.environ.get("ASK_FLOWTABLE_VLAN_ID", "271"))
VLAN_INNER = VLAN_ID + 1
# Deliberately not derived from the VID: a VLAN id can exceed an octet, and a
# subnet built out of one silently aliases as soon as it does.
LAN_SUBNET, DUT_VLAN_ADDR, LAN_VLAN_ADDR = "172.29.71.0/24", "172.29.71.1", "172.29.71.2"
QINQ_SUBNET, DUT_QINQ_ADDR, LAN_QINQ_ADDR = "172.29.72.0/24", "172.29.72.1", "172.29.72.2"
SNAT_ADDR = "172.29.71.9"
NAT_TABLE = "ask_vlan_nat"


class SourceEcho(Echo):
    """Echo that also records where each datagram came from. Under SNAT that is
    the translated endpoint, which is the wire-level proof of the rewrite."""

    def __init__(self):
        super().__init__()
        self.sources = set()

    def datagram_received(self, data, addr):
        self.sources.add((addr[0], addr[1]))
        super().datagram_received(data, addr)


async def _flows(r):
    return (await r.state())["flows"]


def _direction(flows, source, destination):
    """One installed direction, named by the endpoints of its match."""
    matching = [f for f in flows if f["src"].startswith(source + ":")
                and f["dst"].startswith(destination + ":")]
    assert len(matching) == 1, (source, destination, flows)
    return matching[0]


async def _tagged_segment(r, stack, inner):
    """The tagged LAN, on both sides of the wire.

    Only the LAN is tagged. The WAN keeps the untagged address the rest of the
    suite uses, so the two directions of one connection differ in exactly the
    encapsulation and nothing else.
    """
    dut_if = await dut_vlan_subif(stack, r.target, r.session, parent=TARGET_LAN_IF,
                                  vid=VLAN_ID, ipv4=f"{DUT_VLAN_ADDR}/24")
    lan_if = await lan_vlan_subif(stack, r.lan, parent=LAN_NIC, vid=VLAN_ID,
                                  ipv4=f"{LAN_VLAN_ADDR}/24",
                                  routes=[f"{WAN_IP}/32 via {DUT_VLAN_ADDR} dev vlan{VLAN_ID}"])
    r.lan_ip, subnet = LAN_VLAN_ADDR, LAN_SUBNET
    if inner:
        dut_if = await dut_vlan_subif(stack, r.target, r.session, parent=dut_if,
                                      vid=VLAN_INNER, ipv4=f"{DUT_QINQ_ADDR}/24")
        lan_if = await lan_vlan_subif(stack, r.lan, parent=lan_if, vid=VLAN_INNER,
                                      name=f"vlan{VLAN_ID}.{VLAN_INNER}",
                                      ipv4=f"{LAN_QINQ_ADDR}/24",
                                      routes=[f"{WAN_IP}/32 via {DUT_QINQ_ADDR} "
                                              f"dev vlan{VLAN_ID}.{VLAN_INNER}"])
        r.lan_ip, subnet = LAN_QINQ_ADDR, QINQ_SUBNET
    r.peer_if, r.dut_vlan_if, r.lan_vlan_if = lan_if, dut_if, lan_if
    r.peer_link = LAN_NIC
    # The frame assertions compare against the devices that terminate the
    # tagged segment, not the ports under them. A VLAN device normally
    # inherits its parent's address, which is exactly why naming the wrong one
    # would pass by accident.
    link = json.loads((await lan_run(r.lan, f"ip -j link show dev {lan_if}")).stdout)[0]
    r.peer_mac = r.lan_mac = link["address"]
    r.peer_gateway_mac = r.dut_lan_mac = (
        await read(r.target, r.session, f"/sys/class/net/{dut_if}/address")).strip()
    return subnet


@pytest_asyncio.fixture
async def vlan_rig(target_agent, aiohttp_session, lan, splat_window, request):
    """LAN VM -> tagged segment -> DUT -> untagged WAN host.

    The parameter selects the shape: "udp" (default), "tcp", or "qinq" for a
    second tag inside the first. Teardown reverses only what came up, so a
    partial setup leaves nothing for the next case to inherit.
    """
    shape = getattr(request, "param", "udp")
    assert shape in {"udp", "tcp", "qinq"}
    r = Rig()
    r.proto = "tcp" if shape == "tcp" else "udp"
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    initial = await r.state()
    assert initial["owner"] == "flowtable", "boot ask.offload=flowtable first"
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    r.wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    stack = TopologyStack()
    cleanup = []
    transport = None
    try:
        await command(r.target, r.session, "modprobe", "xt_tcpudp")
        subnet = await _tagged_segment(r, stack, shape == "qinq")
        r.dut_wan_mac = (await read(r.target, r.session,
                                    f"/sys/class/net/{TARGET_WAN_IF}/address")).strip()
        addresses = json.loads((await command(r.wan, r.session, "ip", "-j", "-4", "addr"))["stdout"])
        r.wan_if = next(i["ifname"] for i in addresses
                        if any(a.get("local") == WAN_IP for a in i["addr_info"]))
        r.wan_mac = json.loads((await command(r.wan, r.session, "ip", "-j", "link", "show",
                                              "dev", r.wan_if))["stdout"])[0]["address"]
        dut = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr",
                                        "show", "dev", TARGET_WAN_IF))["stdout"])[0]
        r.dut_wan_ip = next(a["local"] for a in dut["addr_info"] if a["family"] == "inet")
        await command(r.wan, r.session, "ip", "route", "replace", subnet, "via", r.dut_wan_ip,
                      "dev", r.wan_if)
        cleanup.append((r.wan, ["ip", "route", "del", subnet, "via", r.dut_wan_ip,
                                "dev", r.wan_if]))
        # Pin both neighbours so admission never races ARP. The LAN one belongs
        # to the VLAN device; the same address on the port underneath would be
        # a different neighbour and would not be found.
        for ip, mac, dev in ((r.lan_ip, r.lan_mac, r.dut_vlan_if),
                             (WAN_IP, r.wan_mac, TARGET_WAN_IF)):
            await command(r.target, r.session, "ip", "neigh", "replace", ip, "lladdr", mac,
                          "nud", "permanent", "dev", dev)
            cleanup.append((r.target, ["ip", "neigh", "del", ip, "dev", dev]))
        # Without this the image's own masquerade rule would translate the
        # routed case and it would silently stop being a routed case.
        accept = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", r.proto,
                  "--sport", str(SPORT), "--dport", str(DPORT), "-j", "ACCEPT"]
        await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept)
        cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *accept]))
        old_acct = (await read(r.target, r.session,
                               "/proc/sys/net/netfilter/nf_conntrack_acct")).strip()
        await command(r.target, r.session, "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
        cleanup.append((r.target, ["sysctl", "-w",
                                   f"net.netfilter.nf_conntrack_acct={old_acct}"]))
        await r.clear_ct()
        if r.proto == "udp":
            transport, r.echo = await asyncio.get_running_loop().create_datagram_endpoint(
                SourceEcho, local_addr=(WAN_IP, DPORT))
        r.record("vlan-fixture", {"lan": r.lan_ip, "wan": WAN_IP, "vid": VLAN_ID,
                                  "shape": shape, "dut_if": r.dut_vlan_if,
                                  "lan_if": r.lan_vlan_if, "lan_mac": r.lan_mac,
                                  "dut_lan_mac": r.dut_lan_mac, "initial": initial})
        yield r
    finally:
        if transport:
            transport.close()
        failures = []
        # clear_ct needs an address the setup may never have reached; a
        # teardown that raises there would mask the real failure.
        steps = [r.delete_table] + ([r.clear_ct] if hasattr(r, "lan_ip") else [])
        for step in steps:
            try:
                await step()
            except Exception as error:
                failures.append(str(error))
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)
        await stack.teardown("flowtable-vlan")
        assert not failures, failures


async def _both_directions(r):
    """Admission is directional, so one direction refused leaves the other
    accelerated and the difference is invisible in a throughput number. When
    the count is wrong, say what Linux and the adapter each thought."""
    state = await r.state()
    if len(state["flows"]) != 2:
        conntrack = await command(r.target, r.session, "conntrack", "-L", "-o", "extended",
                                  check=False)
        r.record("vlan-partial-admission", {"state": state, "conntrack": conntrack})
        pytest.fail(f"{len(state['flows'])} of 2 directions admitted: "
                    f"validated={state['validated']} rejects={state['rejects']} "
                    f"busy={state['busy']} errors={state['errors']}\n"
                    f"flows={state['flows']}\nconntrack={conntrack['stdout']}")
    return state["flows"]


async def _established(r, count=64):
    """Install the flow, then measure a second burst against the hardware."""
    await r.table()
    await r.exchange(count=4)
    flows = await _both_directions(r)
    before = {f["cookie"]: int(f["packets"]) for f in flows}
    await r.exchange(count=count)
    after = {f["cookie"]: int(f["packets"]) for f in await _flows(r)}
    assert set(before) == set(after), ("a direction was readmitted mid-measurement",
                                       before, after)
    return flows, {c: after[c] - before[c] for c in before}


async def test_flowtable_vlan_routed(vlan_rig):
    """A tagged LAN and an untagged WAN, routed, with no translation."""
    r = vlan_rig
    flows, delta = await _established(r)
    forward = _direction(flows, r.lan_ip, WAN_IP)
    reverse = _direction(flows, WAN_IP, r.lan_ip)
    # The tag is described where the frame actually carries it and nowhere
    # else: stripped on the way in, inserted on the way back.
    assert forward["in_vlan"] == str(VLAN_ID) and forward["out_vlan"] == "-", forward
    assert reverse["in_vlan"] == "-" and reverse["out_vlan"] == str(VLAN_ID), reverse
    # Both directions name the physical ports; a tag never becomes one.
    assert forward["in"] == TARGET_LAN_IF and forward["out"] == TARGET_WAN_IF, forward
    assert reverse["in"] == TARGET_WAN_IF and reverse["out"] == TARGET_LAN_IF, reverse
    assert all(d == 64 for d in delta.values()), delta
    r.record("vlan-routed", {"flows": flows, "delta": delta})


async def test_flowtable_vlan_snat(vlan_rig):
    """Source NAT across the tag boundary, proved at the far endpoint.

    The WAN host observing the translated source is what separates a rewrite
    that reached the wire from one that only reached the rule.
    """
    r = vlan_rig
    # nft rather than an iptables SNAT target, which this image has no module
    # for, and at priority 90 so it runs ahead of the fixture's own
    # priority-100 exemption rather than behind it.
    nat = (f"table ip {NAT_TABLE} {{ chain postrouting {{ "
           f"type nat hook postrouting priority 90; "
           f"ip saddr {r.lan_ip} ip daddr {WAN_IP} udp sport {SPORT} udp dport {DPORT} "
           f"snat to {SNAT_ADDR}; }}; }}")
    await command(r.target, r.session, "nft", nat)
    await command(r.wan, r.session, "ip", "route", "replace", f"{SNAT_ADDR}/32",
                  "via", r.dut_wan_ip, "dev", r.wan_if)
    try:
        flows, delta = await _established(r)
        forward = _direction(flows, r.lan_ip, WAN_IP)
        assert forward["new_src"].startswith(SNAT_ADDR + ":"), forward
        assert forward["in_vlan"] == str(VLAN_ID) and forward["out_vlan"] == "-", forward
        reverse = _direction(flows, WAN_IP, SNAT_ADDR)
        assert reverse["new_dst"].startswith(r.lan_ip + ":"), reverse
        assert reverse["in_vlan"] == "-" and reverse["out_vlan"] == str(VLAN_ID), reverse
        assert all(d == 64 for d in delta.values()), delta
        # What the wire carried, not what the rule said it would.
        assert r.echo.sources == {(SNAT_ADDR, SPORT)}, r.echo.sources
        r.record("vlan-snat", {"flows": flows, "delta": delta,
                               "observed": sorted(r.echo.sources)})
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)
        await command(r.wan, r.session, "ip", "route", "del", f"{SNAT_ADDR}/32", check=False)


@pytest.mark.parametrize("vlan_rig", ["qinq"], indirect=True)
async def test_flowtable_vlan_qinq(vlan_rig):
    """Two tags, and the order they are carried in.

    The rule records them outermost first. Recording them the other way round
    still forwards on a single-tag path, which is why the pair has to be
    asserted by position rather than as a set.
    """
    r = vlan_rig
    flows, delta = await _established(r)
    expected = f"{VLAN_ID}.{VLAN_INNER}"
    forward = _direction(flows, r.lan_ip, WAN_IP)
    reverse = _direction(flows, WAN_IP, r.lan_ip)
    assert forward["in_vlan"] == expected and forward["out_vlan"] == "-", forward
    assert reverse["out_vlan"] == expected and reverse["in_vlan"] == "-", reverse
    assert all(d == 64 for d in delta.values()), delta
    r.record("vlan-qinq", {"flows": flows, "delta": delta})


async def test_flowtable_vlan_device_mtu_retires(vlan_rig):
    """The VLAN device carries its own MTU, and a flow through it depends on it.

    Each direction carries the MTU of the interface it leaves by, so lowering
    the tagged LAN device moves only the reverse direction. Both directions
    share one invalidation handle, so retiring the connection is a single
    increment rather than two.
    """
    r = vlan_rig
    await r.table()

    async def settled(expected):
        """`expected` maps egress port to the MTU the direction leaving by it
        should describe. Readmission needs traffic, so each attempt sends
        before it looks; nothing re-offers a retired flow on its own."""
        for _ in range(10):
            await r.exchange(count=4)
            state = await r.state()
            if state["entries"] == 2 and all(
                    int(f["mtu"]) == expected[f["out"]] for f in state["flows"]):
                return state
        pytest.fail(f"flow did not settle at {expected}: {state}")

    before = await settled({TARGET_LAN_IF: 1500, TARGET_WAN_IF: 1500})
    await command(r.target, r.session, "ip", "link", "set", r.dut_vlan_if, "mtu", "1400")
    try:
        invalidated = await r.wait(
            lambda s: s["mtu_invalidations"] >= before["mtu_invalidations"] + 1)
        # Only the direction leaving by the tagged device moves; the flow comes
        # back describing the new path rather than staying retired.
        reduced = await settled({TARGET_LAN_IF: 1400, TARGET_WAN_IF: 1500})
        assert reduced["errors"] == before["errors"], reduced
        r.record("vlan-mtu", {"before": before, "invalidated": invalidated,
                              "reduced": reduced})
    finally:
        await command(r.target, r.session, "ip", "link", "set", r.dut_vlan_if,
                      "mtu", "1500", check=False)


async def test_flowtable_vlan_full_mtu_datagram(vlan_rig):
    """A datagram filling the path MTU still crosses the tag.

    The tagged frame is four bytes longer than the untagged one it becomes. If
    the hardware's own size check counted those four bytes, this is the payload
    that would be dropped or punted while a shorter one was forwarded, so the
    counters have to account for it exactly as for any other burst.
    """
    r = vlan_rig
    await r.table()
    await r.exchange(count=4)
    before = {f["cookie"]: int(f["packets"]) for f in await _flows(r)}
    # 1500 less the IPv4 and UDP headers: the largest datagram the path takes
    # without fragmenting, and the one the tag makes an oversized frame of.
    await r.exchange(count=16, payload_size=1472)
    after = {f["cookie"]: int(f["packets"]) for f in await _flows(r)}
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == 16 for d in delta.values()), delta
    r.record("vlan-full-mtu", {"delta": delta})


@pytest.mark.parametrize("vlan_rig", ["tcp"], indirect=True)
async def test_flowtable_vlan_tcp(vlan_rig):
    """An established TCP connection over the tagged segment.

    The classifier punts SYN, FIN and RST before its own lookup, so what the
    hardware actually carries is the bulk transfer in the middle. The cookies
    staying put is what proves the connection was never readmitted underneath
    it.
    """
    r = vlan_rig
    await r.table()
    peer = f'''
import json, socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(({r.lan_ip!r}, {SPORT}))
s.settimeout(20)
s.connect(({WAN_IP!r}, {DPORT}))
block = bytes(range(256)) * 16
sent = 0
for _ in range(128):
    s.sendall(block)
    sent += len(block)
    remaining = len(block)
    while remaining:
        chunk = s.recv(remaining)
        assert chunk, 'peer closed mid-transfer'
        remaining -= len(chunk)
    time.sleep(0.002)
s.close()
print(json.dumps({{'sent': sent}}))
'''
    server = await asyncio.start_server(_echo_stream, WAN_IP, DPORT)
    try:
        async with server:
            # The echo server is an endpoint in this process; the peer has to
            # run off the event loop or every reply misses its deadline.
            result = await r.run_peer(peer, timeout=90, label="flowtable_vlan_tcp")
        assert result.rc == 0, result.stdout
        report = json.loads(result.stdout.strip())
        flows = await _both_directions(r)
        forward = _direction(flows, r.lan_ip, WAN_IP)
        reverse = _direction(flows, WAN_IP, r.lan_ip)
        assert forward["in_vlan"] == str(VLAN_ID) and forward["out_vlan"] == "-", forward
        assert reverse["out_vlan"] == str(VLAN_ID), reverse
        assert int(forward["packets"]) > 100 and int(reverse["packets"]) > 100, flows
        r.record("vlan-tcp", {"flows": flows, "report": report})
    finally:
        server.close()
        await server.wait_closed()


async def _echo_stream(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()

"""Shared support for flowtable vlan."""

from __future__ import annotations

import asyncio
import json
import os
import time

import pytest
import pytest_asyncio
from _flowtable_rig import (DPORT, SPORT, WAN_IP, Echo, Rig, command, read, release_latch,
                            stop_boot_daemon)
from _topology import (
    LAN_NIC,
    TARGET_LAN_IF,
    TARGET_WAN_IF,
    TopologyStack,
    dut_vlan_subif,
    lan_run,
    lan_vlan_subif,
)
from ask_orch.client import Agent
from ask_orch.commands import console_json, console_python
from ask_orch.uart import Console
from ask_orch.artifacts import artifact_dir

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


async def _send_vlan_frames(r, frames, label):
    """Send serialized frames on the physical peer, without its VLAN devices."""
    result = await r.run_peer(f'''
import json, socket, time
frames = [bytes.fromhex(frame) for frame in {[frame.hex() for frame in frames]!r}]
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as wire:
    wire.bind(({r.peer_link!r}, 0))
    for frame in frames:
        assert wire.send(frame) == len(frame)
        time.sleep(0.003)
print(json.dumps({{"sent": len(frames), "bytes": sum(map(len, frames))}}))
''', timeout=10, label=label)
    assert result.rc == 0, result.stdout
    report = json.loads(result.stdout.strip())
    assert report == {"sent": len(frames), "bytes": sum(map(len, frames))}, report
    return report


async def _vlan_ingress_visible(r, frames):
    """Prove every negative tag stack reaches the DUT before installing a flow.

    A hardware rejection need not punt to Linux. Calibrate the same frames
    with no flowtable, so a switch dropping an unfamiliar VID cannot pass the
    later isolation test. The offset alternatives cover zero, one and two tags
    without libpcap's stateful `vlan` filter changing subsequent offsets.
    """
    from scapy.all import rdpcap

    assert (await r.state())["entries"] == 0
    ready = f"/tmp/ask-vlan-capture-{time.monotonic_ns()}"
    bpf = (f"ether src {r.lan_mac} and ether dst {r.dut_lan_mac} and (" +
           " or ".join(f"ether[{offset}:4] = 0x41534b2d" for offset in (42, 46, 50)) + ")")
    script = f'''
import json, pathlib, subprocess, tempfile, time
ready = pathlib.Path({ready!r})
with tempfile.TemporaryDirectory(prefix='ask-vlan-capture-') as directory:
    pcap = pathlib.Path(directory) / 'ingress.pcap'
    log = pathlib.Path(directory) / 'tcpdump.log'
    with log.open('wb') as stderr:
        proc = subprocess.Popen(['tcpdump', '-p', '-n', '-U', '-Z', 'root', '--immediate-mode',
                                 '-i', {TARGET_LAN_IF!r}, '-c', {str(len(frames))!r},
                                 '-w', str(pcap), {bpf!r}],
                                stdout=subprocess.DEVNULL, stderr=stderr)
        complete = False
        try:
            deadline = time.monotonic() + 5
            while 'listening on' not in log.read_text():
                assert proc.poll() is None and time.monotonic() < deadline, log.read_text()
                time.sleep(0.02)
            ready.write_text('ready')
            try:
                complete = proc.wait(timeout=10) == 0
            except subprocess.TimeoutExpired:
                pass
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            ready.unlink(missing_ok=True)
    print(json.dumps({{'complete': complete, 'pcap': pcap.read_bytes().hex(),
                      'stderr': log.read_text()}}))
'''
    with Console.target() as con:
        task = asyncio.create_task(console_python(con, script, timeout=20))
        try:
            deadline = time.monotonic() + 10
            while True:
                if task.done():
                    await task
                    pytest.fail("DUT VLAN capture ended before becoming ready")
                status = await r.target.fs_read(r.session, ready)
                if status["errno"] == 0:
                    assert bytes.fromhex(status["content_hex"]) == b"ready", status
                    break
                assert status["errno"] == 2, status
                assert time.monotonic() < deadline, "DUT VLAN capture did not start"
                await asyncio.sleep(0.05)
            sent = await _send_vlan_frames(r, frames, "vlan_ingress_calibration")
        finally:
            # Let the bounded process finish its own cleanup even if sending fails.
            await asyncio.gather(task, return_exceptions=True)
        report = console_json(task.result()["stdout"])
    path = artifact_dir() / "vlan-isolation-ingress.pcap"
    path.write_bytes(bytes.fromhex(report.pop("pcap")))
    captured = [bytes(packet) for packet in rdpcap(str(path))]
    r.record("vlan-isolation-ingress", {**report, **sent,
                                       "frames": [frame.hex() for frame in captured]})
    assert report["complete"], report
    assert captured == frames, ("negative probes did not arrive intact at the DUT", captured, frames)


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
                                  routes=[] if inner else [f"{WAN_IP}/32 via {DUT_VLAN_ADDR} dev vlan{VLAN_ID}"])
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
    r.vlan_tags = [VLAN_ID, VLAN_INNER] if shape == "qinq" else [VLAN_ID]
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    await stop_boot_daemon()
    initial = await release_latch(r)
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
    # Admission is asynchronous and takes rtnl_trylock, so a direction can be
    # deferred a second or two when the bench's own ip commands hold RTNL; give
    # the deferred readmission that window before treating a missing direction
    # as a refusal. A genuine refusal still fails, just after the wait.
    state = await r.state()
    for _ in range(100):
        if len(state["flows"]) == 2:
            break
        await asyncio.sleep(0.1)
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

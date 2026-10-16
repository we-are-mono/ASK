"""Bridged unicast offload: LAN-to-LAN switching in hardware.

1.0.7 switched unicast traffic between two bridge ports at line rate, CMM's
auto_bridge installing an entry per station pair; 1.1 does it with the bridged
unicast learner (cdx/ask_flowtable_l2.c). These cases put a station on each
of two physical bridge ports and require the classifier, not the bridge, to
carry what they send each other.

The rig has one LAN-side station, the LAN VM behind eth3. The second sits
behind eth4: a private namespace on the WAN host, on a macvlan child of the
standing `wan3900` device, which reaches eth4 tagged 3900. br-l2 joins the two
in VLAN 3900 -- untagged on eth3, tagged on eth4 -- so each pair needs one of
the two tag rewrites: the station's frames gain the tag on their way out of
eth4, the peer's lose it on their way out of eth3. That is OpenWrt's DSA-style
LAN (vlan_filtering on, a PVID per access port) with a trunk on one side. The
WAN keeps working in VLAN 1 of the same bridge, untagged on eth4, the bridge
holding eth4's address and the WAN address; the DUT's LAN address moves to
br-l2.3900. Neither station shares a subnet with the DUT, so nothing between
them is ever routed.

The "trunk" shape tags the LAN VM's side too, so both pairs are tagged on
both ports and stripped and tagged again.

Every case proves the classifier forwards the pairs: both listed with the tag
rewrite each needs, and their own hardware counters accounting for the
traffic while the DUT's kernel transmits none of it. What an entry must not
forward is proven at the far end instead, by counting what arrives: an
entry's counters count its key's matches, which include the frames its tag
check hands to Linux.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time

import pytest
import pytest_asyncio

from ask_orch.counters import kernel_rx_packets
from _flowtable_rig import Rig, command, release_latch, stop_boot_daemon
from _flowtable_tcp import cpu, cpu_delta, software_tx
from _throughput import MOVED, RAMP, SOFTWARE_TX, STAGING, STREAMS, WINDOW, settled
from _topology import (LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, VLAN_ID_PPPOE_WAN,
                       TopologyStack, lan_run, lan_run_python, lan_vlan_subif)

BRIDGE = "br-l2"
# The bench VLAN wan3900 already carries between the WAN host and eth4: only
# the namespaced macvlan child below is this test's (_topology.py claims).
VID = VLAN_ID_PPPOE_WAN
NAMESPACE = "ask-l2"
PEER_IF = "ask-l2-peer"
# Fixed, so the bridge's FDB and the hardware key name the same station on
# every run.
PEER_MAC = "02:00:00:00:12:02"
# Claimed in _topology.py. Neither end is the DUT's.
PEER_ADDR, STATION_ADDR = "172.29.77.1", "172.29.77.2"
PREFIX = 24
IPERF_PORT = 5212
TABLE = "ask_l2"
FILTER_TABLE = "ask_l2_filter"
# Bridged in hardware, the pairs run at the ports' line rate, as every routed
# path on this rig does; in software the DUT bridges a fraction of it.
MIN_RATE = float(os.environ.get("ASK_FLOWTABLE_L2_MIN_GBPS", "9")) * 1e9
# Centiseconds. Long enough for setup and learning, short enough that a
# measured run outlives it: the run proves the learner keeps the FDB entries
# of a pair it carries alive (br_fdb_refresh()).
AGEING_CS = 1000


async def _local(*argv, check=True):
    result = await asyncio.to_thread(subprocess.run, argv, capture_output=True, text=True,
                                     timeout=20)
    if check:
        assert result.returncode == 0, (argv, result.stdout, result.stderr)
    return {"rc": result.returncode, "stdout": result.stdout}


def _pairs(r, state):
    """The two pairs between the stations, by ingress port."""
    stations = {r.station_mac, PEER_MAC}
    return {row["in"]: row for row in state["l2flows"] if {row["dst"], row["src"]} == stations}


async def _exchange(r, count=10, interval=0.05):
    """Pings from the station to the peer: a unicast request and a unicast
    reply per round, one frame each way between the two."""
    result = await lan_run(r.lan, f"ping -n -q -c {count} -i {interval} -W 1 {PEER_ADDR}",
                           count * interval + 10)
    return result.stdout


async def _carried(r, timeout=10):
    """Both pairs installed. Exchanges while waiting: the learner hears of a
    pair from its frames, and a pass that lost RTNL retries on its own, but a
    pair retired since is heard of again only from new frames."""
    deadline = time.monotonic() + timeout
    while True:
        state = await r.state()
        if len(_pairs(r, state)) == 2:
            return state
        if time.monotonic() >= deadline:
            r.record("l2-not-carried", state)
            pytest.fail(f"bridged pairs not in hardware: l2_entries={state.get('l2_entries')} "
                        f"refused={state.get('l2_refused')} installs={state.get('l2_installs')} "
                        f"rows={state['l2flows']}")
        await _exchange(r, count=4)


async def _segment(r, stack, shape):
    """br-l2 over eth3 and eth4, as the module docstring describes. The
    "trunk" shape has the LAN VM tagged 3900 on eth3 as well, which has no
    PVID then: both pairs are tagged on the way in and on the way out."""
    async def dut(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    def addresses(output):
        return [f"{a['local']}/{a['prefixlen']}" for link in json.loads(output or "[]")
                for a in link["addr_info"] if "local" in a]

    held = {}
    for port in (TARGET_LAN_IF, TARGET_WAN_IF):
        v4 = (await dut("ip", "-j", "-4", "addr", "show", "dev", port))["stdout"]
        v6 = (await dut("ip", "-j", "-6", "addr", "show", "dev", port, "scope", "global"))["stdout"]
        held[port] = (addresses(v4), addresses(v6))
    defaults = json.loads((await dut("ip", "-j", "-4", "route", "show", "default",
                                     "dev", TARGET_WAN_IF))["stdout"])
    gateways = [d["gateway"] for d in defaults if "gateway" in d]
    r.bridge_mac = json.loads((await dut("ip", "-j", "link", "show", "dev",
                                         TARGET_WAN_IF))["stdout"])[0]["address"]

    async def restore():
        await dut("ip", "link", "del", BRIDGE, check=False)
        for port, (v4, v6) in held.items():
            await dut("ip", "link", "set", port, "up", check=False)
            for address in v4:
                await dut("ip", "addr", "replace", address, "dev", port, check=False)
            for address in v6:
                await dut("ip", "-6", "addr", "replace", address, "dev", port, "nodad", check=False)
        for gateway in gateways:
            await dut("ip", "route", "replace", "default", "via", gateway,
                      "dev", TARGET_WAN_IF, check=False)
        return {"rc": 0}
    stack.push(restore)

    await dut("ip", "link", "del", BRIDGE, check=False)
    # vlan_default_pvid 0: no port is given a PVID this shape did not ask
    # for. The bridge keeps eth4's address, so the WAN's neighbours of the
    # DUT stay right.
    await dut("ip", "link", "add", "name", BRIDGE, "type", "bridge",
              "vlan_filtering", "1", "vlan_default_pvid", "0")
    await dut("ip", "link", "set", BRIDGE, "address", r.bridge_mac)
    for port, (v4, v6) in held.items():
        for address in v4:
            await dut("ip", "addr", "del", address, "dev", port)
        for address in v6:
            await dut("ip", "-6", "addr", "del", address, "dev", port)
        await dut("ip", "link", "set", port, "master", BRIDGE)
    await dut("bridge", "vlan", "add", "dev", TARGET_WAN_IF, "vid", "1", "pvid", "untagged")
    await dut("bridge", "vlan", "add", "dev", TARGET_WAN_IF, "vid", str(VID))
    await dut("bridge", "vlan", "add", "dev", TARGET_LAN_IF, "vid", str(VID),
              *(["pvid", "untagged"] if shape == "access" else []))
    await dut("bridge", "vlan", "add", "dev", BRIDGE, "vid", "1", "pvid", "untagged", "self")
    await dut("bridge", "vlan", "add", "dev", BRIDGE, "vid", str(VID), "self")
    await dut("ip", "link", "set", BRIDGE, "up")
    lan_l3 = f"{BRIDGE}.{VID}"
    await dut("ip", "link", "add", "link", BRIDGE, "name", lan_l3, "type", "vlan", "id", str(VID))
    await dut("ip", "link", "set", lan_l3, "up")
    for port, l3 in ((TARGET_WAN_IF, BRIDGE), (TARGET_LAN_IF, lan_l3)):
        v4, v6 = held[port]
        for address in v4:
            await dut("ip", "addr", "add", address, "dev", l3)
        for address in v6:
            await dut("ip", "-6", "addr", "add", address, "dev", l3, "nodad")
    for gateway in gateways:
        await dut("ip", "route", "replace", "default", "via", gateway, "dev", BRIDGE)

    # The peer: a namespace of this test's own on the bench VLAN.
    await _local("ip", "netns", "del", NAMESPACE, check=False)
    await _local("ip", "netns", "add", NAMESPACE)
    stack.push(lambda: _local("ip", "netns", "del", NAMESPACE))
    await _local("ip", "link", "add", "link", "wan3900", "name", PEER_IF, "address", PEER_MAC,
                 "netns", NAMESPACE, "type", "macvlan", "mode", "bridge")
    for dev in ("lo", PEER_IF):
        await _local("ip", "-n", NAMESPACE, "link", "set", dev, "up")
    await _local("ip", "-n", NAMESPACE, "addr", "add", f"{PEER_ADDR}/{PREFIX}", "dev", PEER_IF)

    # The station: a second address on the LAN VM's port, or on a VLAN
    # device over it.
    if shape == "trunk":
        await lan_vlan_subif(stack, r.lan, parent=LAN_NIC, vid=VID, ipv4=f"{STATION_ADDR}/{PREFIX}")
    else:
        await lan_run(r.lan, f"ip addr del {STATION_ADDR}/{PREFIX} dev {LAN_NIC} 2>/dev/null; true", 10)
        checked = await lan_run(r.lan, f"ip addr add {STATION_ADDR}/{PREFIX} dev {LAN_NIC}", 10)
        assert checked.rc == 0, checked.stdout

        async def drop_station():
            result = await lan_run(r.lan, f"ip addr del {STATION_ADDR}/{PREFIX} dev {LAN_NIC}", 10)
            return {"rc": result.rc, "stdout": result.stdout}
        stack.push(drop_station)
    link = json.loads((await lan_run(r.lan, f"ip -j link show dev {LAN_NIC}", 10)).stdout)
    r.station_mac = link[0]["address"]

    # Both ports bound: the learner carries a pair only between two ports an
    # offload flowtable holds.
    await dut("nft", "delete", "table", "inet", TABLE, check=False)
    await dut("nft", f"add table inet {TABLE}")
    stack.push(lambda: dut("nft", "delete", "table", "inet", TABLE, check=False))
    await dut("nft", f"add flowtable inet {TABLE} fast {{ hook ingress priority 0 ; "
                     f"devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }} ; flags offload ; }}")
    await r.wait(lambda s: s["bindings"] == 2)


@pytest_asyncio.fixture
async def l2_rig(target_agent, aiohttp_session, lan, splat_window, request):
    """The parameter selects the shape: "access" (default) or "trunk"."""
    shape = getattr(request, "param", "access")
    assert shape in {"access", "trunk"}
    r = Rig()
    r.shape = shape
    r.target, r.session, r.lan = target_agent, aiohttp_session, lan
    await stop_boot_daemon()
    initial = await release_latch(r)
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    assert initial["l2_enabled"] in (0, 1) and initial["l2_entries"] == 0, initial
    stack = TopologyStack()
    try:
        await _segment(r, stack, shape)
        state = await r.state()
        assert state["l2_enabled"] == 1, state
        r.record("l2-fixture", {"station": r.station_mac, "peer": PEER_MAC,
                                "bridge_mac": r.bridge_mac, "initial": initial})
        yield r
    finally:
        await stack.teardown("flowtable-l2")
        # The DUT's own addresses are what later fixtures cannot recover
        # alone; prove they came back.
        for port in (TARGET_LAN_IF, TARGET_WAN_IF):
            restored = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr",
                                                 "show", "dev", port))["stdout"])
            assert restored and restored[0]["addr_info"], f"{port} left without an address"
        final = await r.state()
        assert final["l2_entries"] == 0, final


@pytest.mark.parametrize("l2_rig", ["access", "trunk"], indirect=True)
async def test_l2_pairs_in_hardware(l2_rig):
    """Both directions installed with the rewrite each needs, and the
    classifier carries every frame of a burst while the DUT's kernel sends
    none of them."""
    r = l2_rig
    trunk = r.shape == "trunk"
    await _exchange(r, count=4)
    state = await _carried(r)
    pairs = _pairs(r, state)
    r.record("l2-pairs", pairs)
    out = pairs[TARGET_LAN_IF]
    assert (out["out"], out["br"], out["dst"], out["src"]) == \
        (TARGET_WAN_IF, BRIDGE, PEER_MAC, r.station_mac), out
    # Untagged in, the port's PVID, and tagged on the way out -- or, from a
    # trunk, tagged in, validated and stripped, and tagged again.
    assert (out["type"], out["vid"], out["tagged"], out["in_vlan"], out["out_vlan"]) == \
        ("0x0800", str(VID), "1" if trunk else "0", "strip" if trunk else "-", str(VID)), out
    back = pairs[TARGET_WAN_IF]
    assert (back["out"], back["dst"], back["src"]) == (TARGET_LAN_IF, r.station_mac, PEER_MAC), back
    # Tagged in, validated and stripped, untagged on the way out to an
    # access port and tagged again to a trunk.
    assert (back["type"], back["vid"], back["tagged"], back["in_vlan"], back["out_vlan"]) == \
        ("0x0800", str(VID), "1", "strip", str(VID) if trunk else "0"), back
    # The router's own frames are routed, never a pair.
    assert not [row for row in state["l2flows"] if row["dst"] == r.bridge_mac], state["l2flows"]

    burst = 200
    tx_before = await software_tx(r)
    await _exchange(r, count=burst, interval=0.01)
    # The worker reads the counters once a pass.
    await asyncio.sleep(2.5)
    tx_after = await software_tx(r)
    after = _pairs(r, await r.state())
    moved = {port: int(after[port]["packets"]) - int(pairs[port]["packets"]) for port in pairs}
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    r.record("l2-burst", {"moved": moved, "software_tx": tx})
    assert all(count >= burst for count in moved.values()), moved
    assert all(count < burst // 4 for count in tx.values()), tx


async def _rate(r, *, upload, seconds):
    """One iperf3 run between the stations, measured as _throughput.py
    measures a routed path: the pairs' counters moving and the DUT's kernel
    transmitting next to nothing inside a window of the settled run."""
    record = {}
    server = await asyncio.create_subprocess_exec(
        "ip", "netns", "exec", NAMESPACE, "iperf3", "-s", "-1", "-B", PEER_ADDR,
        "-p", str(IPERF_PORT), "-J", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    task = None
    try:
        await asyncio.sleep(0.5)
        assert server.returncode is None, "the peer's iperf3 did not start"
        argv = ["iperf3", "-c", PEER_ADDR, "-B", STATION_ADDR, "-p", str(IPERF_PORT),
                "-P", str(STREAMS), "-t", str(seconds), "-Z", "-J", *([] if upload else ["-R"])]
        script = f'''
import json, subprocess
result = subprocess.run({argv!r}, capture_output=True, text=True, timeout={seconds + 20})
print(json.dumps({{'rc': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}}))
'''
        loop = asyncio.get_running_loop()
        launched = loop.time()
        task = asyncio.create_task(lan_run_python(r.lan, script, label="l2_iperf",
                                                  timeout=seconds + 40))
        await asyncio.sleep(max(0, launched + STAGING + RAMP - loop.time()))
        record["before"] = before = await r.state()
        tx_before, cpu_before = await software_tx(r), await cpu(r)
        await asyncio.sleep(WINDOW)
        cpu_after, tx_after = await cpu(r), await software_tx(r)
        record["after"] = after = await r.state()
        assert not task.done(), "the run ended inside the window"
        record["cpu"] = cpu_delta(cpu_before, cpu_after)
        record["software_tx"] = tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
        old, new = _pairs(r, before), _pairs(r, after)
        assert len(old) == len(new) == 2, (before["l2flows"], after["l2flows"])
        record["moved"] = moved = {port: int(new[port]["packets"]) - int(old[port]["packets"])
                                   for port in new}
        assert all(count > MOVED for count in moved.values()), moved
        for name in ("l2_installs", "l2_retired"):
            assert after[name] == before[name], (name, before[name], after[name])
        assert all(0 <= count <= SOFTWARE_TX for count in tx.values()), \
            "the DUT's kernel forwarded the streams"
        result = await task
        task = None
        assert result.rc == 0, result.stdout
        report = json.loads(result.stdout.strip().splitlines()[-1])
        assert report["rc"] == 0, report["stderr"]
        record["client"] = client = json.loads(report["stdout"])
        stdout, stderr = await asyncio.wait_for(server.communicate(), 15)
        record["server"] = peer = json.loads(stdout) if stdout.strip() else {}
        assert server.returncode == 0, stderr.decode()
        record["settled"] = settled(peer if upload else client)
        return record
    finally:
        r.record(f"l2-rate-{r.shape}-{'up' if upload else 'down'}", record)
        if task:
            task.cancel()
        if server.returncode is None:
            server.terminate()
            await asyncio.wait_for(server.communicate(), 10)


@pytest.mark.parametrize("l2_rig", ["access", "trunk"], indirect=True)
@pytest.mark.parametrize("upload", [True, False], ids=["station-to-peer", "peer-to-station"])
async def test_l2_line_rate(l2_rig, upload):
    """Line rate between the stations, carried by the two pairs throughout,
    and for longer than the bridge's ageing time: hardware-forwarded frames
    never reach the bridge, so the pairs stay only because the learner keeps
    their FDB entries fresh."""
    r = l2_rig
    await command(r.target, r.session, "ip", "link", "set", BRIDGE, "type", "bridge",
                  "ageing_time", str(AGEING_CS))
    await _exchange(r, count=4)
    start = await _carried(r)
    seconds = max(15, AGEING_CS // 100 + 5)
    samples = []
    for _ in range(3):
        record = await _rate(r, upload=upload, seconds=seconds)
        samples.append(record["settled"]["bits_per_second"])
        if samples[-1] >= MIN_RATE:
            break
    end = await r.state()
    r.record(f"l2-rate-{r.shape}-{'up' if upload else 'down'}-samples",
             {"samples": samples, "floor": MIN_RATE})
    assert end["l2_retired"] == start["l2_retired"], \
        "a carried pair was retired: its FDB entries aged out under it"
    assert len(_pairs(r, end)) == 2, end["l2flows"]
    assert max(samples) >= MIN_RATE, (samples, MIN_RATE)


async def test_l2_fdb_delete_retires(l2_rig):
    """A station's FDB entry going takes both pairs naming it out of
    hardware -- the bridge would flood the next frame, the entry would not --
    and the next frames learn them again."""
    r = l2_rig
    await _exchange(r, count=4)
    before = await _carried(r)
    await command(r.target, r.session, "bridge", "fdb", "del", r.station_mac,
                  "dev", TARGET_LAN_IF, "vlan", str(VID), "master")
    after = await r.wait(lambda s: not _pairs(r, s), timeout=5)
    assert after["l2_retired"] >= before["l2_retired"] + 2, (before, after)
    await _carried(r)


async def test_l2_bridge_filter_keeps_software(l2_rig):
    """A bridge-family chain can drop or mark what the bridge forwards, and
    an entry would forward where it never runs: while one exists, no pair is
    carried, and once it goes they are again."""
    r = l2_rig
    await _exchange(r, count=4)
    await _carried(r)
    await command(r.target, r.session, "nft", f"add table bridge {FILTER_TABLE}")
    try:
        await command(r.target, r.session, "nft",
                      f"add chain bridge {FILTER_TABLE} forward {{ type filter hook forward "
                      f"priority 0 ; policy accept ; }}")
        await r.wait(lambda s: not _pairs(r, s), timeout=5)
        await _exchange(r, count=20)
        await asyncio.sleep(2.5)
        state = await r.state()
        assert not _pairs(r, state), state["l2flows"]
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "bridge", FILTER_TABLE,
                      check=False)
    await _carried(r)


async def test_l2_idle_ages_out(l2_rig):
    """A pair no frame has hit for the idle time leaves the hardware, and the
    next frames learn it again. Shortened here; 30 s by default."""
    r = l2_rig
    param = "/sys/module/ask_flowtable/parameters/l2_idle_ms"
    saved = (await r.target.fs_read(r.session, param))
    saved = bytes.fromhex(saved["content_hex"]).decode().strip()
    assert (await r.target.fs_write(r.session, param, "2000"))["errno"] == 0
    try:
        await _exchange(r, count=4)
        before = await _carried(r)
        after = await r.wait(lambda s: not _pairs(r, s), timeout=8)
        assert after["l2_retired"] >= before["l2_retired"] + 2, (before, after)
        await _carried(r)
    finally:
        await r.target.fs_write(r.session, param, saved)


def _frame(dst, src, vid, marker):
    """A UDP datagram between the stations' addresses, as raw Ethernet: tagged
    with `vid`, or untagged when it is None, its payload `marker`."""
    import socket
    import struct
    payload = marker * 4
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0, 64, 17, 0,
                         socket.inet_aton(PEER_ADDR), socket.inet_aton(STATION_ADDR))
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    header = header[:10] + struct.pack("!H", ~total & 0xffff) + header[12:]
    udp = struct.pack("!HHHH", 50998, 50999, 8 + len(payload), 0)
    tag = struct.pack("!HH", 0x8100, vid) if vid is not None else b""
    return (bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) + tag +
            b"\x08\x00" + header + udp + payload)


def _capture_script(device, marker, seconds):
    """Count the frames carrying `marker` that `device` receives."""
    return f"""
import socket, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
# SO_RCVBUFFORCE: a burst must not outrun the default receive buffer.
s.setsockopt(socket.SOL_SOCKET, 33, 8 << 20)
s.bind(({device!r}, 0))
s.settimeout(0.2)
seen, end = 0, time.monotonic() + {seconds}
while time.monotonic() < end:
    try:
        data = s.recv(4096)
    except TimeoutError:
        continue
    seen += {marker!r} in data
print('seen', seen)
"""


def _inject_script(device, frame, count):
    # Paced, so neither end's queues decide what arrives.
    return f"""
import socket, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(({device!r}, 0))
for _ in range({count}):
    s.send(bytes.fromhex({frame.hex()!r}))
    time.sleep(0.001)
print('sent')
"""


async def _python_here(script, timeout):
    process = await asyncio.create_subprocess_exec(
        "python3", "-c", script, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    assert process.returncode == 0, stderr.decode()
    return stdout.decode()


@pytest.mark.parametrize("l2_rig", ["access", "trunk"], indirect=True)
async def test_l2_ingress_tag_validated(l2_rig):
    """The key holds neither the VLAN nor whether the frame is tagged, so
    the tag check an entry's strip carries is all that keeps the pair's
    addresses arriving in another form from riding it. Frames with a pair's
    addresses are injected at either end -- in the pair's own form (the
    control, which the far end receives), and in a form the bridge would not
    forward to that end -- and the far end counts what arrives."""
    r = l2_rig
    await _exchange(r, count=4)
    await _carried(r)
    parent = json.loads((await _local("ip", "-j", "-d", "link", "show", "wan3900"))["stdout"])[0]["link"]
    count, seconds = 300, 7
    delivered = {}
    # The WAN host's segment passes 3900 and untagged frames only, so a
    # tagged entry is shown another VLAN from the LAN VM, in the trunk shape.
    cases = [
        # WAN host -> eth4 -> eth3 -> LAN VM, against the tagged entry.
        ("tagged-control", "wan", VID),
        ("tagged-entry-untagged-frame", "wan", None),
    ] + ([
        # LAN VM -> eth3 -> eth4 -> WAN host, against the tagged entry.
        ("trunk-control", "lan", VID),
        ("trunk-entry-other-vlan", "lan", VID + 1),
        ("trunk-entry-untagged-frame", "lan", None),
    ] if r.shape == "trunk" else [
        # LAN VM -> eth3 -> eth4 -> WAN host, against the untagged entry.
        ("untagged-control", "lan", None),
        ("untagged-entry-tagged-frame", "lan", VID + 1),
    ])
    try:
        for label, side, vid in cases:
            marker = f"askl2-{label}".encode()
            port = TARGET_WAN_IF if side == "wan" else TARGET_LAN_IF
            punted = await kernel_rx_packets(r.target, r.session, port)
            if side == "wan":
                frame = _frame(r.station_mac, PEER_MAC, vid, marker)
                capture = asyncio.create_task(lan_run_python(
                    r.lan, _capture_script(LAN_NIC, marker, seconds), label="l2_capture",
                    timeout=seconds + 20))
                await asyncio.sleep(3)
                await _python_here(_inject_script(parent, frame, count), 30)
                result = await capture
                assert result.rc == 0, result.stdout
                out = result.stdout
            else:
                frame = _frame(PEER_MAC, r.station_mac, vid, marker)
                capture = asyncio.create_task(_python_here(
                    _capture_script(parent, marker, seconds), seconds + 20))
                await asyncio.sleep(1)
                injected = await lan_run_python(r.lan, _inject_script(LAN_NIC, frame, count),
                                                label="l2_inject", timeout=30)
                assert injected.rc == 0 and "sent" in injected.stdout, injected.stdout
                out = await capture
            delivered[label] = int(out.split("seen", 1)[1].split()[0])
            # What reached the DUT's kernel on the ingress instead: a frame the
            # entry's check handed up, or one no entry matched.
            delivered[label + "-punted"] = (await kernel_rx_packets(r.target, r.session, port)
                                            - punted)
    finally:
        r.record(f"l2-ingress-tag-{r.shape}", delivered)
    for label, _, _ in cases:
        if label.endswith("control"):
            assert delivered[label] >= count * 9 // 10, (label, delivered)
        else:
            # Handed to the bridge, which drops it or keeps it in its own
            # VLAN: never at the far end.
            assert delivered[label] == 0, (label, delivered)

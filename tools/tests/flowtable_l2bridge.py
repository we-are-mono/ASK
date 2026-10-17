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
import contextlib
import json
import os
import re
import subprocess
import time

import pytest
import pytest_asyncio

from ask_orch.artifacts import artifact_dir
from ask_orch.counters import kernel_rx_packets
from ask_orch.uart import Console
from _flowtable_rig import (HEALTH_BASELINE, Rig, command, console_command, read, release_latch,
                            stop_boot_daemon)
from _flowtable_tcp import cpu, cpu_delta, software_tx
from _throughput import MOVED, RAMP, SOFTWARE_TX, STAGING, STREAMS, WINDOW, settled
from _topology import (LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, VLAN_ID_PPPOE_WAN,
                       TopologyStack, dut_vlan_subif, lan_run, lan_run_python, lan_vlan_subif)

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
# The "vlanport" shape's VLAN on the LAN segment: eth3's VLAN device for it
# is the bridge's port. Claimed in _topology.py.
PORT_VID = int(os.environ.get("ASK_FLOWTABLE_L2_PORT_VID", "334"))
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
BRNF_SYSCTLS = ("net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables")
BRNF_VLAN = "net.bridge.bridge-nf-filter-vlan-tagged"
# FT_BRIDGE_HOOK_*, as /proc/cdx_flowtable reports l2_hook_kinds.
HOOK_NFT, HOOK_BRNF, HOOK_OTHER = 1, 2, 4
# The station's frames to the peer, as a bridge or an IP rule names them.
DROP = f"ip saddr {STATION_ADDR} ip daddr {PEER_ADDR} drop"


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


def _received(ping):
    match = re.search(r"(\d+) (?:packets )?received", ping)
    assert match, ping
    return int(match.group(1))


async def _carried(r, timeout=10, since=None):
    """Both pairs installed -- since `since`, a state they must have been
    installed after, if given. Exchanges while waiting: the learner hears of a
    pair from its frames, and a pass that lost RTNL retries on its own, but a
    pair retired since is heard of again only from new frames."""
    deadline = time.monotonic() + timeout
    while True:
        state = await r.state()
        if len(_pairs(r, state)) == 2 and \
                (since is None or state["l2_installs"] >= since["l2_installs"] + 2):
            return state
        if time.monotonic() >= deadline:
            r.record("l2-not-carried", state)
            pytest.fail(f"bridged pairs not in hardware: l2_entries={state.get('l2_entries')} "
                        f"refused={state.get('l2_refused')} installs={state.get('l2_installs')} "
                        f"rows={state['l2flows']}")
        await _exchange(r, count=4)


TWO_TAGS = "vlanport-trunk"
# The LAN VM's NIC MTU outside this file, which a run that died with it
# raised does not get to change.
LAN_BASE_MTU = 1500


def _lan_nic_mtu(lan, mtu):
    """The LAN VM's NIC at `mtu`, its link up again for five seconds running.
    An ixgbe MTU change resets the port and retrains the link, which on this
    bench's 10GBASE-T link has taken from seconds to over three minutes."""
    result = lan.run(f"ip link set dev {LAN_NIC} mtu {mtu}")
    assert result.rc == 0, result.stdout
    started, stable = time.monotonic(), 0
    while time.monotonic() < started + 300:
        up = lan.run(f"cat /sys/class/net/{LAN_NIC}/operstate").stdout.strip() == "up"
        stable = stable + 1 if up else 0
        if stable >= 5:
            return
        time.sleep(1)
    raise AssertionError(f"{LAN_NIC} stayed down after its MTU went to {mtu}")


@pytest.fixture(scope="module", autouse=True)
def lan_two_tags(lan, request):
    """A full-size frame with two tags is a tag longer than the LAN VM's port
    receives at its MTU, so the port is raised by four bytes for the file when
    a "vlanport-trunk" case runs, and lowered once after it, as
    flowtable_jumbo.py raises it: every change retrains the link, and
    retraining it per case lost the link to the cases after it. Every shape
    keeps the station's own packets at 1500 (_segment())."""
    wanted = any(item.module is request.module and TWO_TAGS in item.nodeid
                 for item in request.session.items)
    if not wanted:
        yield
        return
    try:
        _lan_nic_mtu(lan, LAN_BASE_MTU + 4)
        yield
    finally:
        _lan_nic_mtu(lan, LAN_BASE_MTU)


async def _segment(r, stack, shape):
    """br-l2 over eth3 and eth4, as the module docstring describes. The
    "trunk" shape has the LAN VM tagged 3900 on eth3 as well, which has no
    PVID then: both pairs are tagged on the way in and on the way out. The
    "vlanport" shape bridges eth3's VLAN device for PORT_VID instead of eth3,
    the way OpenWrt bridges a VLAN without bridge-vlan sections: the station's
    tag is that device's, and eth3 keeps its own address."""
    async def dut(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    r.lan_port = TARGET_LAN_IF
    if shape.startswith("vlanport"):
        r.lan_port = await dut_vlan_subif(stack, r.target, r.session, parent=TARGET_LAN_IF,
                                          vid=PORT_VID)

    def addresses(output):
        return [f"{a['local']}/{a['prefixlen']}" for link in json.loads(output or "[]")
                for a in link["addr_info"] if "local" in a]

    held = {}
    for port in (r.lan_port, TARGET_WAN_IF):
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
    await dut("bridge", "vlan", "add", "dev", r.lan_port, "vid", str(VID),
              *([] if shape.endswith("trunk") else ["pvid", "untagged"]))
    await dut("bridge", "vlan", "add", "dev", BRIDGE, "vid", "1", "pvid", "untagged", "self")
    await dut("bridge", "vlan", "add", "dev", BRIDGE, "vid", str(VID), "self")
    await dut("ip", "link", "set", BRIDGE, "up")
    lan_l3 = f"{BRIDGE}.{VID}"
    await dut("ip", "link", "add", "link", BRIDGE, "name", lan_l3, "type", "vlan", "id", str(VID))
    await dut("ip", "link", "set", lan_l3, "up")
    for port, l3 in ((TARGET_WAN_IF, BRIDGE), (r.lan_port, lan_l3)):
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
    await _local("ip", "-n", NAMESPACE, "link", "set", "lo", "up")
    # A namespace deleted a moment ago is torn down asynchronously, and its
    # macvlan holds PEER_MAC on wan3900 until it is: wait that out.
    for _ in range(50):
        if not (await _local("ip", "-n", NAMESPACE, "link", "set", PEER_IF, "up",
                             check=False))["rc"]:
            break
        await asyncio.sleep(0.2)
    else:
        await _local("ip", "-n", NAMESPACE, "link", "set", PEER_IF, "up")
    await _local("ip", "-n", NAMESPACE, "addr", "add", f"{PEER_ADDR}/{PREFIX}", "dev", PEER_IF)

    # The station: a second address on the LAN VM's port, or on a VLAN
    # device over it.
    # The station's packets are 1500 bytes at most in every shape, whatever
    # the NIC under them is raised to (lan_two_tags()): a VLAN device takes
    # its parent's MTU when it is made.
    if shape == "vlanport-trunk":
        # Two tags: the port's VLAN device's outside, the bridge's inside.
        outer = await lan_vlan_subif(stack, r.lan, parent=LAN_NIC, vid=PORT_VID)
        inner = await lan_vlan_subif(stack, r.lan, parent=outer, vid=VID,
                                     ipv4=f"{STATION_ADDR}/{PREFIX}")
        for dev in (inner, outer):
            pinned = await lan_run(r.lan, f"ip link set {dev} mtu 1500", 10)
            assert pinned.rc == 0, pinned.stdout
    elif shape != "access":
        dev = await lan_vlan_subif(stack, r.lan, parent=LAN_NIC,
                                   vid=VID if shape == "trunk" else PORT_VID,
                                   ipv4=f"{STATION_ADDR}/{PREFIX}")
        pinned = await lan_run(r.lan, f"ip link set {dev} mtu 1500", 10)
        assert pinned.rc == 0, pinned.stdout
    else:
        await lan_run(r.lan, f"ip addr del {STATION_ADDR}/{PREFIX} dev {LAN_NIC} 2>/dev/null; true", 10)
        checked = await lan_run(r.lan, f"ip addr add {STATION_ADDR}/{PREFIX} dev {LAN_NIC}", 10)
        assert checked.rc == 0, checked.stdout

        async def drop_station():
            result = await lan_run(r.lan, f"ip addr del {STATION_ADDR}/{PREFIX} dev {LAN_NIC}", 10)
            return {"rc": result.rc, "stdout": result.stdout}
        stack.push(drop_station)
        pinned = await lan_run(r.lan, f"ip route replace {PEER_ADDR.rsplit('.', 1)[0]}.0/{PREFIX} "
                                      f"dev {LAN_NIC} proto kernel scope link src {STATION_ADDR} "
                                      f"mtu 1500", 10)
        assert pinned.rc == 0, pinned.stdout
    link = json.loads((await lan_run(r.lan, f"ip -j link show dev {LAN_NIC}", 10)).stdout)
    r.station_mac = link[0]["address"]

    stack.push(lambda: dut("nft", "delete", "table", "inet", TABLE, check=False))
    await _bind(r)


async def _bind(r):
    """Both ports bound: the learner carries a pair only between two ports an
    offload flowtable holds."""
    async def dut(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    await dut("nft", "delete", "table", "inet", TABLE, check=False)
    await dut("nft", f"add table inet {TABLE}")
    await dut("nft", f"add flowtable inet {TABLE} fast {{ hook ingress priority 0 ; "
                     f"devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }} ; flags offload ; }}")
    await r.wait(lambda s: s["bindings"] == 2)


@pytest_asyncio.fixture
async def l2_rig(target_agent, aiohttp_session, lan, splat_window, request):
    """The parameter selects the shape: "access" (default), "trunk",
    "vlanport", or "vlanport-trunk" -- the VLAN-device port tagged for the
    bridge's VLAN too, so the station's frames carry two tags."""
    shape = getattr(request, "param", "access")
    assert shape in {"access", "trunk", "vlanport", "vlanport-trunk"}
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


# What each shape's pairs strip on the way in and push on the way out, by
# ingress: the station's (eth3 or its VLAN device) and the peer's (eth4).
TAGS = {
    "access": {"station": ("0", "-", str(VID)), "peer": ("1", str(VID), "-")},
    "trunk": {"station": ("1", str(VID), str(VID)), "peer": ("1", str(VID), str(VID))},
    "vlanport": {"station": ("0", str(PORT_VID), str(VID)),
                 "peer": ("1", str(VID), str(PORT_VID))},
    "vlanport-trunk": {"station": ("1", f"{PORT_VID}.{VID}", str(VID)),
                       "peer": ("1", str(VID), f"{PORT_VID}.{VID}")},
}


@pytest.mark.parametrize("l2_rig", ["access", "trunk", "vlanport", "vlanport-trunk"], indirect=True)
async def test_l2_pairs_in_hardware(l2_rig):
    """Both directions installed with the rewrite each needs, and the
    classifier carries every frame of a burst while the DUT's kernel sends
    none of them."""
    r = l2_rig
    await _exchange(r, count=4)
    state = await _carried(r)
    pairs = _pairs(r, state)
    r.record("l2-pairs", pairs)
    out = pairs[r.lan_port]
    assert (out["out"], out["port_in"], out["port_out"], out["br"], out["dst"], out["src"]) == \
        (TARGET_WAN_IF, TARGET_LAN_IF, TARGET_WAN_IF, BRIDGE, PEER_MAC, r.station_mac), out
    # Whatever arrives tagged is validated and stripped, all of it, and the
    # egress tags are pushed afresh: the port's own VLAN device's outermost,
    # the bridge's inside it.
    assert (out["type"], out["vid"], out["tagged"], out["in_vlan"], out["out_vlan"]) == \
        ("0x0800", str(VID), *TAGS[r.shape]["station"]), out
    back = pairs[TARGET_WAN_IF]
    assert (back["out"], back["port_in"], back["port_out"], back["dst"], back["src"]) == \
        (r.lan_port, TARGET_WAN_IF, TARGET_LAN_IF, r.station_mac, PEER_MAC), back
    assert (back["type"], back["vid"], back["tagged"], back["in_vlan"], back["out_vlan"]) == \
        ("0x0800", str(VID), *TAGS[r.shape]["peer"]), back
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


@pytest.mark.parametrize("l2_rig", ["access", "trunk", "vlanport", "vlanport-trunk"], indirect=True)
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


@pytest.mark.parametrize("l2_rig", ["access", "vlanport"], indirect=True)
async def test_l2_port_leaves(l2_rig):
    """A port leaving the bridge -- eth3, or the VLAN device on it that is
    the bridge's port -- takes both pairs through it out of hardware."""
    r = l2_rig
    await _exchange(r, count=4)
    before = await _carried(r)
    await command(r.target, r.session, "ip", "link", "set", r.lan_port, "nomaster")
    after = await r.wait(lambda s: not _pairs(r, s), timeout=5)
    assert after["l2_retired"] >= before["l2_retired"] + 2, (before, after)


@pytest.mark.parametrize("l2_rig", ["vlanport"], indirect=True)
async def test_l2_mtu(l2_rig):
    """What arrives is what the physical port's MAC accepts, whatever the
    VLAN device on it says: with eth3 raised to 9000 bytes under a 1500-byte
    eth3.N, the station's frames can be larger than eth4 carries, which the
    bridge drops and the hardware would fragment -- so that pair leaves the
    hardware and stays out, while the other way still fits."""
    r = l2_rig
    phys_mtu = int((await read(r.target, r.session,
                               f"/sys/class/net/{TARGET_LAN_IF}/mtu")).strip())
    await _exchange(r, count=4)
    before = await _carried(r)
    try:
        await command(r.target, r.session, "ip", "link", "set", TARGET_LAN_IF, "mtu", "9000")
        await r.wait(lambda s: r.lan_port not in _pairs(r, s), timeout=5)
        for _ in range(4):
            await _exchange(r, count=4)
            await asyncio.sleep(1)
        state = await r.state()
        pairs = _pairs(r, state)
        assert r.lan_port not in pairs and TARGET_WAN_IF in pairs, state["l2flows"]
        assert state["l2_refused"] > before["l2_refused"], (before, state)
    finally:
        await command(r.target, r.session, "ip", "link", "set", TARGET_LAN_IF, "mtu",
                      str(phys_mtu), check=False)


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


async def test_l2_bridge_chain_rules(l2_rig):
    """A bridge-family chain can drop or mark what the bridge forwards, and an
    entry forwards where it never runs (A387). Once one exists the pairs made
    without it go, and come back once a frame of theirs is seen leaving after
    it; a rule dropping their frames, added under them, takes them out again
    and keeps them out -- its frames never reach the peer -- and once the
    chain goes they are carried as before."""
    r = l2_rig
    await _exchange(r, count=4)
    before = await _carried(r)
    await command(r.target, r.session, "nft", f"add table bridge {FILTER_TABLE}")
    try:
        await command(r.target, r.session, "nft",
                      f"add chain bridge {FILTER_TABLE} forward {{ type filter hook forward "
                      f"priority 0 ; policy accept ; }}")
        confirmed = await _carried(r, timeout=15, since=before)
        assert confirmed["l2_hook_kinds"] == HOOK_NFT, confirmed
        await command(r.target, r.session, "nft",
                      f"add rule bridge {FILTER_TABLE} forward {DROP}")
        gone = await r.wait(lambda s: not _pairs(r, s), timeout=5)
        assert _received(await _exchange(r, count=20)) == 0
        await asyncio.sleep(2.5)
        held = await r.state()
        r.record("l2-bridge-chain", {"confirmed": confirmed, "gone": gone, "held": held})
        assert not _pairs(r, held), held["l2flows"]
        assert held["l2_unconfirmed"] > gone["l2_unconfirmed"], (gone, held)
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


async def test_l2_many_pairs(l2_rig):
    """More pairs than one batch of any walk takes (A382): 400 stations behind
    eth3, each talking to the peer, are all installed, all listed -- one
    /proc record each, across many reads -- and all retired again by the idle
    sweep, a batch per hold of the transaction, leaving nothing behind."""
    r = l2_rig
    count = 400
    param = "/sys/module/ask_flowtable/parameters/l2_idle_ms"
    await _exchange(r, count=4)
    await _carried(r)
    stations = [f"02:a5:{i >> 8:02x}:{i & 0xff:02x}:00:01" for i in range(count)]
    frames = [_frame(PEER_MAC, mac, None, b"askl2-many").hex() for mac in stations]
    script = f"""
import socket, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(({LAN_NIC!r}, 0))
frames = [bytes.fromhex(f) for f in {frames!r}]
for _ in range(6):
    for frame in frames:
        s.send(frame)
        time.sleep(0.0005)
    time.sleep(1)
print('sent')
"""
    saved = bytes.fromhex((await r.target.fs_read(r.session, param))["content_hex"]).decode().strip()
    try:
        injected = asyncio.create_task(lan_run_python(r.lan, script, label="l2_many", timeout=90))
        deadline = time.monotonic() + 60
        while True:
            state = await r.state()
            rows = [row for row in state["l2flows"] if row["dst"] == PEER_MAC]
            if len(rows) >= count or time.monotonic() > deadline:
                break
            await asyncio.sleep(1)
        result = await injected
        assert result.rc == 0 and "sent" in result.stdout, result.stdout
        r.record("l2-many", {"entries": state["l2_entries"], "rows": len(rows),
                             "refused": state["l2_refused"], "dropped": state["l2_dropped"]})
        assert len(rows) >= count, (len(rows), state["l2_entries"], state["l2_refused"])
        # The header's count and the rows span several reads, between which
        # a pair can come or go; they agree once nothing does.
        await r.wait(lambda s: s["l2_entries"] == len(s["l2flows"]), timeout=10)
        assert (await r.target.fs_write(r.session, param, "2000"))["errno"] == 0
        after = await r.wait(lambda s: not s["l2_entries"] and not s["l2flows"], timeout=30)
        assert after["l2_retired"] >= state["l2_retired"] + count, (state["l2_retired"], after["l2_retired"])
    finally:
        await r.target.fs_write(r.session, param, saved)


async def test_l2_refusal_held(l2_rig):
    """A pair the bridge would not forward -- here, between two isolated
    ports -- is refused once and then left to software for up to ten seconds,
    as auto_bridge left a pair CMM denied, rather than asked again every
    second it carries traffic (A383); and a change to a port it rests on asks
    again at once. Isolation is lifted while the refusal is fresh, so an
    admission well inside the hold is the port's event clearing it, not the
    hold running out."""
    r = l2_rig
    await _exchange(r, count=4)
    await _carried(r)
    frame = _frame(PEER_MAC, r.station_mac, None, b"askl2-held").hex()
    script = f"""
import socket, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(({LAN_NIC!r}, 0))
frame = bytes.fromhex({frame!r})
end = time.monotonic() + 14
while time.monotonic() < end:
    s.send(frame)
    time.sleep(0.02)
print('sent')
"""
    for port in (TARGET_LAN_IF, TARGET_WAN_IF):
        await command(r.target, r.session, "bridge", "link", "set", "dev", port, "isolated", "on")
    await r.wait(lambda s: not _pairs(r, s), timeout=5)
    before = await r.state()
    run = asyncio.create_task(lan_run_python(r.lan, script, label="l2_held", timeout=40))
    try:
        refused = await r.wait(lambda s: s["l2_refused"] > before["l2_refused"], timeout=5)
        refused_at = time.monotonic()
        await asyncio.sleep(2.5)
        held = await r.state()
        r.record("l2-held", {"refused": held["l2_refused"] - before["l2_refused"],
                             "held": held["l2_held"] - refused["l2_held"]})
        assert not _pairs(r, held), held["l2flows"]
        # One refusal, and the observations since held rather than asked.
        assert held["l2_refused"] - before["l2_refused"] <= 2, (before, held)
        assert held["l2_held"] > refused["l2_held"], (refused, held)
        # One port no longer isolated: the bridge forwards the pair again,
        # and the port's event clears the refusal.
        await command(r.target, r.session, "bridge", "link", "set", "dev", TARGET_LAN_IF,
                      "isolated", "off")
        await r.wait(lambda s: r.lan_port in _pairs(r, s), timeout=4)
        assert time.monotonic() - refused_at < 8.5, time.monotonic() - refused_at
    finally:
        result = await run
    assert result.rc == 0 and "sent" in result.stdout, result.stdout


@contextlib.asynccontextmanager
async def _br_netfilter(r, call, vlan_tagged=True):
    """br_netfilter loaded, as Docker loads it, handing the IP frames the
    bridge forwards to the IP hooks with `call` 1 -- Docker's setting -- or
    not with 0, OpenWrt's own at boot; and an inet forward chain accepting
    all, as Docker's FORWARD and fw4's forward are. Unloaded after.

    Every pair on this rig leaves one port tagged, and br_netfilter hands a
    frame the bridge tags on its way out to the IP forward and postrouting
    hooks only with bridge-nf-filter-vlan-tagged on, which `vlan_tagged`
    sets: a case whose rules must see every frame needs it. Without it such
    a frame meets only prerouting, as on an OpenWrt LAN with a tagged trunk
    to an access point."""
    async def dut(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    await dut("modprobe", "br_netfilter")
    try:
        await dut("sysctl", "-w", f"{BRNF_VLAN}={int(vlan_tagged)}")
        for name in BRNF_SYSCTLS:
            await dut("sysctl", "-w", f"{name}={call}")
        await dut("nft", f"add table inet {FILTER_TABLE}")
        await dut("nft", f"add chain inet {FILTER_TABLE} forward {{ type filter hook forward "
                         f"priority 0 ; policy accept ; }}")
        yield dut
    finally:
        await dut("nft", "delete", "table", "inet", FILTER_TABLE, check=False)
        for name in (*BRNF_SYSCTLS, BRNF_VLAN):
            await dut("sysctl", "-w", f"{name}=0", check=False)
        await dut("rmmod", "br_netfilter", check=False)



@pytest.mark.parametrize("l2_rig", ["access", "vlanport"], indirect=True)
@pytest.mark.parametrize("vlan_tagged", [True, False], ids=["filter-tagged", "prerouting-only"])
async def test_l2_br_netfilter_carried(l2_rig, vlan_tagged):
    """With br_netfilter handing bridged frames to the IP hooks, as on a box
    running Docker, a pair is carried once a frame of it is seen leaving after
    every one of them (A387) -- and at line rate, as auto_bridge carried it in
    1.0.7. The pairs made before br_netfilter came were judged by no IP rule:
    they go, and come back confirmed. "prerouting-only" leaves
    bridge-nf-filter-vlan-tagged off: the station's frames, tagged on their
    way out, meet only prerouting, and their connection is never confirmed in
    conntrack, which must not keep them in software."""
    r = l2_rig
    await _exchange(r, count=4)
    before = await _carried(r)
    async with _br_netfilter(r, call=1, vlan_tagged=vlan_tagged):
        state = await _carried(r, timeout=15, since=before)
        r.record("l2-brnf-carried", state)
        assert state["l2_hook_kinds"] == HOOK_BRNF and state["l2_confirming"] == 1, state
        record = await _rate(r, upload=True, seconds=15)
        assert record["settled"]["bits_per_second"] >= MIN_RATE, \
            (record["settled"], MIN_RATE)


async def test_l2_br_netfilter_rules(l2_rig):
    """Under br_netfilter the IP rules decide a pair as they decide its frames
    in software (A387): a rule added under a carried pair takes it back within
    a pass, so the rule applies -- the frames it drops never reach the peer --
    and the pair is not carried again while the rule stands; once the rule
    goes, it is."""
    r = l2_rig
    async with _br_netfilter(r, call=1) as dut:
        await _exchange(r, count=4)
        carried = await _carried(r, timeout=15)
        await dut("nft", f"add rule inet {FILTER_TABLE} forward {DROP}")
        gone = await r.wait(lambda s: not _pairs(r, s), timeout=5)
        assert gone["l2_ruleset_changes"] > carried["l2_ruleset_changes"], (carried, gone)
        assert _received(await _exchange(r, count=20)) == 0
        await asyncio.sleep(2.5)
        held = await r.state()
        r.record("l2-brnf-rules", {"carried": carried, "gone": gone, "held": held})
        assert not _pairs(r, held), held["l2flows"]
        assert held["l2_unconfirmed"] > gone["l2_unconfirmed"], (gone, held)
        await dut("nft", "flush", "chain", "inet", FILTER_TABLE, "forward")
        await _carried(r, timeout=15)


async def test_l2_br_netfilter_turned_on(l2_rig):
    """OpenWrt boots with bridge-nf-call-iptables at 0, and Docker sets it to
    1. A pair carried while its frames met no IP rule is taken back once they
    do (patch 172 counts the change, which nothing else reports), so a rule
    that applies to them from then on -- here, one dropping them -- applies
    to the pair too."""
    r = l2_rig
    async with _br_netfilter(r, call=0) as dut:
        await dut("nft", f"add rule inet {FILTER_TABLE} forward {DROP}")
        await _exchange(r, count=4)
        carried = await _carried(r, timeout=15)
        assert carried["l2_hook_kinds"] == HOOK_BRNF, carried
        await dut("sysctl", "-w", f"{BRNF_SYSCTLS[0]}=1")
        gone = await r.wait(lambda s: not _pairs(r, s), timeout=5)
        r.record("l2-brnf-turned-on", {"carried": carried, "gone": gone})
        assert gone["l2_ruleset_changes"] > carried["l2_ruleset_changes"], (carried, gone)
        assert _received(await _exchange(r, count=20)) == 0
        assert not _pairs(r, await r.state())


async def _reload_adapter(r):
    """The adapter unloaded and loaded again, which registers its hooks after
    every one registered now, and the ports bound again: Linux replays no
    flowtable binding to a module that registers later."""
    con = Console.target(log_path=str(artifact_dir() / "l2-reload-uart.log"))
    try:
        await asyncio.to_thread(con.login, "root", None)
        await console_command(con, "rmmod", "ask_flowtable", timeout=25)
        await console_command(con, "modprobe", "ask_flowtable")
    finally:
        con.close()
    # A fresh adapter counts errors from zero.
    HEALTH_BASELINE["errors"] = (await r.state())["errors"]
    await _bind(r)


async def test_l2_br_netfilter_loaded_first(l2_rig):
    """br_netfilter loaded before the adapter, as a box that loads every
    module at boot may order them: its POST_ROUTING hook then runs after the
    bridge confirmation hook, which leaves it the frames it takes to the IP
    hooks, and the IP confirmation hooks confirm them there. A drop at IP
    postrouting, which such a frame meets only after the bridge hook, proves
    the bridge hook left them: the pairs go and stay out."""
    r = l2_rig
    async with _br_netfilter(r, call=1) as dut:
        await _reload_adapter(r)
        await _exchange(r, count=4)
        state = await _carried(r, timeout=15)
        assert state["l2_hook_kinds"] == HOOK_BRNF and state["l2_confirming"] == 1, state
        await dut("nft", f"add chain inet {FILTER_TABLE} post {{ type filter hook postrouting "
                         f"priority 0 ; policy accept ; }}")
        await dut("nft", f"add rule inet {FILTER_TABLE} post {DROP}")
        gone = await r.wait(lambda s: not _pairs(r, s), timeout=5)
        assert _received(await _exchange(r, count=20)) == 0
        await asyncio.sleep(2.5)
        held = await r.state()
        r.record("l2-brnf-first", {"carried": state, "gone": gone, "held": held})
        assert not _pairs(r, held), held["l2flows"]


async def test_l2_hook_after_confirmation(l2_rig):
    """A bridge chain that runs after the confirmation hook -- registered
    before the adapter at the last priority, which netfilter then runs after
    it -- could drop or mark a frame already confirmed: while it exists, no
    pair is carried; once it goes, they are."""
    r = l2_rig
    await command(r.target, r.session, "nft", f"add table bridge {FILTER_TABLE}")
    try:
        await command(r.target, r.session, "nft",
                      f"add chain bridge {FILTER_TABLE} post {{ type filter hook postrouting "
                      f"priority 2147483647 ; policy accept ; }}")
        await _reload_adapter(r)
        await _exchange(r, count=20)
        await asyncio.sleep(2.5)
        await _exchange(r, count=20)
        state = await r.state()
        r.record("l2-hook-after", state)
        assert state["l2_hook_kinds"] == HOOK_NFT | HOOK_OTHER, state
        assert not _pairs(r, state), state["l2flows"]
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "bridge", FILTER_TABLE,
                      check=False)
    await _carried(r)


async def _tcp(r, seconds=3):
    """A TCP stream from the station to the peer, at a rate the CPU forwards."""
    server = await asyncio.create_subprocess_exec(
        "ip", "netns", "exec", NAMESPACE, "iperf3", "-s", "-1", "-B", PEER_ADDR,
        "-p", str(IPERF_PORT), stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL)
    try:
        await asyncio.sleep(0.5)
        result = await lan_run(r.lan, f"iperf3 -c {PEER_ADDR} -B {STATION_ADDR} -p {IPERF_PORT} "
                                      f"-t {seconds} -b 20M >/dev/null && echo streamed",
                               seconds + 20)
        assert result.rc == 0 and "streamed" in result.stdout, result.stdout
    finally:
        if server.returncode is None:
            server.terminate()
        await server.wait()


async def test_l2_br_netfilter_flow_add(l2_rig):
    """fw4's forward chain offers every TCP and UDP connection it sees to its
    flowtable (`flow add`), and under br_netfilter it sees the bridged ones
    too. Their route is br_netfilter's placeholder, which nothing forwards
    by: patch 173 keeps them from the flowtable, whose flow would never be
    matched but would mark the conntrack offloaded and turn its TCP window
    checks off (A388). A promiscuous bridge keeps the pairs in software, so
    the CPU forwards every frame and the chain sees each one."""
    r = l2_rig
    subnet = f"{PEER_ADDR.rsplit('.', 1)[0]}.0/{PREFIX}"
    async with _br_netfilter(r, call=1) as dut:
        await dut("nft", f"add chain inet {TABLE} fw4 {{ type filter hook forward priority 0 ; "
                         f"policy accept ; }}")
        await dut("nft", f"add rule inet {TABLE} fw4 meta l4proto {{ tcp, udp }} counter "
                         f"flow add @fast")
        # A route back to the stations through the bridge, as a router's LAN
        # has: without one the flow could not be built at all, and the case
        # would pass on a kernel without the patch.
        await dut("ip", "route", "replace", subnet, "dev", BRIDGE)
        await dut("ip", "link", "set", BRIDGE, "promisc", "on")
        try:
            await _tcp(r)
            conntrack = await dut("conntrack", "-L", "-o", "extended", check=False)
            bridged = [line for line in conntrack["stdout"].splitlines() if PEER_ADDR in line]
            chain = json.loads((await dut("nft", "-j", "list", "chain", "inet", TABLE,
                                          "fw4"))["stdout"])
            offered = sum(e["counter"]["packets"] for item in chain["nftables"]
                          for e in item.get("rule", {}).get("expr", []) if "counter" in e)
            r.record("l2-brnf-flow-add", {"conntrack": bridged, "offered": offered,
                                          "state": await r.state()})
            # The rule saw the stream: `flow add` was asked of it.
            assert offered > 0, chain
            assert bridged, conntrack["stdout"]
            assert not any("OFFLOAD" in line for line in bridged), bridged
        finally:
            await dut("ip", "link", "set", BRIDGE, "promisc", "off", check=False)
            await dut("ip", "route", "del", subnet, "dev", BRIDGE, check=False)
            await dut("nft", "delete", "chain", "inet", TABLE, "fw4", check=False)

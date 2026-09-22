"""A158: the flowtable listener ceiling and replication across physical ports.

Run on an idle DUT. No global daemon kills.
Captures identify every sequence independently on every receiving VLAN.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

import pytest

from ask_orch.counters import kernel_rx_packets
from _topology import (
    LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, TopologyStack,
    VLAN_IDS_MROUTE_LIMIT, VLAN_ID_PPPOE_WAN,
    dut_vlan_subif, lan_run_python, lan_vlan_subif,
)
from mroute_capture import multicast_mac, payload, assert_results
from test_mcast_e2e import (
    _exec, dut_mac, flowtable_proc, mroute_line, mroute_proc_row, wan_source_address,
)
from test_flowtable_offload import ARTIFACTS

pytestmark = pytest.mark.asyncio
COUNT, PPS, PORT = 256, 200, 47358
CAPTURE_SOURCE = Path(__file__).with_name("mroute_capture.py").read_text()


async def _python(lan, script):
    if lan is not None:
        r = await lan_run_python(lan, script, label="a158", timeout=15)
        assert r.rc == 0, r.stdout
        return r.stdout
    proc = await asyncio.create_subprocess_exec(
        "sudo", "-n", sys.executable, "-c", script,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), 15)
    assert proc.returncode == 0, err.decode()
    return out.decode()


@asynccontextmanager
async def _capture(lan, config):
    path = f"/tmp/ask-a158-{uuid.uuid4().hex}"
    config = {**config, "ready": path + ".ready", "result": path + ".json"}
    script = path + ".py"
    try:
        await _python(lan, f"""
import pathlib, subprocess, sys
pathlib.Path({script!r}).write_text({CAPTURE_SOURCE!r})
with open({path + '.log'!r}, 'w') as log:
    child = subprocess.Popen([sys.executable, {script!r}, {json.dumps(config)!r}],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             start_new_session=True)
pathlib.Path({path + '.pid'!r}).write_text(str(child.pid))
""")
        for _ in range(30):
            out = await _python(lan, f"""
import pathlib
ready = pathlib.Path({config['ready']!r})
print('READY' if ready.exists() else 'WAIT')
""")
            if "READY" in out.splitlines():
                break
            await asyncio.sleep(0.1)
        else:
            log = await _python(lan, f"print(open({path + '.log'!r}).read())")
            raise AssertionError(f"A158 capture did not become ready: {log}")
        yield (lan, config, path)
    finally:
        # Verify process identity before signalling; a capture may have hit its
        # own deadline. Never signal a recycled PID or another test's capture.
        await _python(lan, f"""
import os, pathlib, signal, time
pidfile = pathlib.Path({path + '.pid'!r})
if pidfile.exists():
    pid = int(pidfile.read_text())
    try:
        args = pathlib.Path('/proc/%d/cmdline' % pid).read_bytes().split(b'\\0')
        if {script.encode()!r} in args:
            os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, FileNotFoundError):
        pass
for _ in range(50):
    if pathlib.Path({config['result']!r}).exists():
        break
    time.sleep(0.1)
""")


async def _finish(capture):
    lan, config, path = capture
    result = json.loads((await _python(lan, f"print(open({config['result']!r}).read())")).strip())
    await _python(lan, f"""
import pathlib
for suffix in ('.pid', '.ready', '.json', '.log', '.py'):
    pathlib.Path({path!r} + suffix).unlink(missing_ok=True)
""")
    return result


@asynccontextmanager
async def _daemon(target, session, interfaces):
    name = "ask-a158-" + uuid.uuid4().hex[:8]
    config = f"/tmp/{name}.conf"
    text = "".join(f"phyint {dev} enable\n" for dev in interfaces)
    r = await target.fs_write(session, config, text)
    assert r.get("errno", 0) == 0, r

    async def command(*args, check=True):
        return await _exec(target, session, "smcroutectl", "-i", name, *args, check=check)

    try:
        # A different daemon owning the default MRT table makes startup fail;
        # it is not stopped or replaced by this test.
        await _exec(target, session, "smcrouted", "-N", "-i", name,
                    "-f", config, "-l", "notice")
        for _ in range(30):
            if (await command("show", "routes", check=False))["rc"] == 0:
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("A158 smcrouted failed to own the default routing table")
        yield command
    finally:
        await command("kill", check=False)
        await target.fs_write(session, config, "")


async def _state(target, session, group, state, listeners=()):
    last = ""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        last = await mroute_proc_row(target, session, group)
        names = re.search(r"listeners=(\S+)", last)
        actual = set(names[1].split(",")) if names and names[1] != "-" else set()
        if f"state={state} " in last and actual == set(listeners):
            return last
        await asyncio.sleep(0.1)
    raise AssertionError(f"{group}: expected {state}, {list(listeners)}, got {last!r}")


async def _absent(target, session, group):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if not await mroute_proc_row(target, session, group):
            return
        await asyncio.sleep(0.1)
    raise AssertionError(f"{group}: multicast row survived route removal")


def _send(config):
    from scapy.all import Ether, IP, IPv6, UDP, Raw, sendp
    layer = (IP(src=config["source"], dst=config["group"], ttl=64)
             if config["family"] == 4 else
             IPv6(src=config["source"], dst=config["group"], hlim=64))
    frames = [Ether(dst=multicast_mac(config["group"])) / layer /
              UDP(sport=PORT, dport=PORT) / Raw(payload(config["token"], i))
              for i in range(COUNT)]
    sendp(frames, iface=os.environ.get("ASK_WAN_INJECT_IF", "br0"),
          inter=1 / PPS, verbose=False)


async def _window(target, session, *, family, group, observers,
                  expected, hardware, label):
    """observers is [(peer, {interface: expected source MAC}), ...]."""
    from contextlib import AsyncExitStack
    config = {"family": family, "source": wan_source_address(family), "group": group,
              "port": PORT, "count": COUNT, "token": uuid.uuid4().hex}
    captures = []
    idle_start = await kernel_rx_packets(target, session, TARGET_WAN_IF)
    await asyncio.sleep(COUNT / PPS)
    idle = await kernel_rx_packets(target, session, TARGET_WAN_IF) - idle_start
    async with AsyncExitStack() as stack:
        for peer, interfaces in observers:
            captures.append(await stack.enter_async_context(
                _capture(peer, {**config, "interfaces": interfaces})))
        before_row = await mroute_proc_row(target, session, group)
        before = await kernel_rx_packets(target, session, TARGET_WAN_IF)
        await asyncio.to_thread(_send, config)
        after = await kernel_rx_packets(target, session, TARGET_WAN_IF)
        await asyncio.sleep(0.4)  # drain receiver queues before requesting output
    results = {}
    for capture in captures:
        results.update(await _finish(capture))
    row = await mroute_proc_row(target, session, group)  # also folds MFC counters
    route, _ = await mroute_line(target, session, family, config["source"], group)
    artifact = {"config": config, "results": results, "before": before_row,
                "after": row, "mroute": route, "cpu_rx": after - before, "idle": idle}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / f"a158-{label}-v{family}.json").write_text(json.dumps(artifact, indent=2))
    assert_results(results, expected, COUNT)
    assert ("offload" in route) == hardware, route
    cpu = after - before
    if hardware:
        assert "state=installed" in row, row
        assert cpu - idle < COUNT * 0.1, artifact
        packets = lambda text: int(re.search(r"packets=(\d+)", text)[1])
        assert packets(row) - packets(before_row) >= COUNT * 0.95, artifact
    else:
        assert "state=refused-listener" in row and "listeners=- " in row, row
        assert cpu >= COUNT, artifact


async def _preflight(target, session):
    assert "mroute_groups 0\n" in await flowtable_proc(target, session), \
        "existing multicast routes belong to another workload"


@pytest.mark.parametrize("family", [4, 6])
async def test_routed_listener_ceiling(aiohttp_session, target_agent, lan,
                                       splat_window, family):
    """Eight exact copies; nine all in software; remove ninth and recover eight."""
    await _preflight(target_agent, aiohttp_session)
    topology = TopologyStack()
    group = "239.8.158.1" if family == 4 else "ff1e::8:158:1"
    dut, peers = [], []
    try:
        for i, vid in enumerate(VLAN_IDS_MROUTE_LIMIT):
            dut.append(await dut_vlan_subif(
                topology, target_agent, aiohttp_session, parent=TARGET_LAN_IF, vid=vid,
                ipv4=f"198.18.158.{4 * i + 1}/30",
                ipv6=f"fd00:158:{vid:x}::1/64"))
            peers.append(await lan_vlan_subif(topology, lan, parent=LAN_NIC, vid=vid))
        mac = await dut_mac(target_agent, aiohttp_session, TARGET_LAN_IF)
        async with _daemon(target_agent, aiohttp_session, [TARGET_WAN_IF, *dut]) as ctl:
            await ctl("add", TARGET_WAN_IF, wan_source_address(family), group, *dut[:8])
            for size in (8, 9, 8):
                if size == 9:
                    await ctl("add", TARGET_WAN_IF, wan_source_address(family), group, *dut)
                state = "installed" if size == 8 else "refused-listener"
                listeners = [f"{TARGET_LAN_IF}/{v}" for v in VLAN_IDS_MROUTE_LIMIT[:size]]
                await _state(target_agent, aiohttp_session, group, state,
                             listeners if size == 8 else ())
                await _window(target_agent, aiohttp_session, family=family, group=group,
                              observers=[(lan, dict.fromkeys(peers, mac))],
                              expected=peers[:size], hardware=size == 8,
                              label=f"limit-{size}-{'recovered' if len(dut) == 8 else 'initial'}")
                if size == 9:
                    # smcroute ADD only grows a route. Removing the ninth VIF
                    # exercises the actual netdevice/FIB withdrawal path.
                    await _exec(target_agent, aiohttp_session, "ip", "link", "del", dut.pop())
            await ctl("remove", TARGET_WAN_IF, wan_source_address(family), group)
            await _absent(target_agent, aiohttp_session, group)
    finally:
        await topology.teardown("A158 listener ceiling")


@pytest.mark.parametrize("family", [4, 6])
async def test_routed_replication_across_physical_ports(aiohttp_session, target_agent,
                                                       lan, splat_window, family):
    """One copy leaves LAN, another leaves WAN tagged; ingress is WAN untagged."""
    await _preflight(target_agent, aiohttp_session)
    assert TARGET_LAN_IF != TARGET_WAN_IF, "two distinct physical ports required"
    topology = TopologyStack()
    group = "239.8.158.2" if family == 4 else "ff1e::8:158:2"
    vid = VLAN_IDS_MROUTE_LIMIT[0]
    wan_vid = int(os.environ.get("ASK_MROUTE_WAN_VID", str(VLAN_ID_PPPOE_WAN)))
    wan_peer = os.environ.get("ASK_MROUTE_WAN_IF", "wan3900")
    # The WAN switch carries this standing bench VLAN; arbitrary new VLANs
    # (including the originally proposed 320) do not reach the orchestrator.
    # Read its configuration, then borrow only a socket membership. Never
    # create, reconfigure or delete the existing interface/PPPoE service.
    peer = json.loads(await _python(None, f"""
import subprocess
print(subprocess.check_output(['ip', '-j', '-d', 'link', 'show', 'dev', {wan_peer!r}], text=True))
"""))[0]
    assert "UP" in peer["flags"], peer
    assert peer["linkinfo"]["info_kind"] == "vlan", peer
    assert peer["linkinfo"]["info_data"]["id"] == wan_vid, peer
    try:
        lan_oif = await dut_vlan_subif(
            topology, target_agent, aiohttp_session, parent=TARGET_LAN_IF, vid=vid,
            ipv4="198.18.158.1/30", ipv6=f"fd00:158:{vid:x}::1/64")
        lan_peer = await lan_vlan_subif(topology, lan, parent=LAN_NIC, vid=vid)
        wan_oif = await dut_vlan_subif(
            topology, target_agent, aiohttp_session, parent=TARGET_WAN_IF, vid=wan_vid,
            ipv4="198.18.158.253/30", ipv6=f"fd00:158:{wan_vid:x}::1/64")
        # AF_PACKET sees the replica even though its source is this host's
        # own sender address, without changing its addresses or routes.
        lan_mac = await dut_mac(target_agent, aiohttp_session, TARGET_LAN_IF)
        wan_mac = await dut_mac(target_agent, aiohttp_session, TARGET_WAN_IF)
        async with _daemon(target_agent, aiohttp_session,
                           [TARGET_WAN_IF, lan_oif, wan_oif]) as ctl:
            await ctl("add", TARGET_WAN_IF, wan_source_address(family), group, lan_oif, wan_oif)
            await _state(target_agent, aiohttp_session, group, "installed",
                         [f"{TARGET_LAN_IF}/{vid}", f"{TARGET_WAN_IF}/{wan_vid}"])
            await _window(target_agent, aiohttp_session, family=family, group=group,
                          observers=[(lan, {lan_peer: lan_mac}), (None, {wan_peer: wan_mac})],
                          expected=[lan_peer, wan_peer], hardware=True, label="physical-ports")
            await ctl("remove", TARGET_WAN_IF, wan_source_address(family), group)
            await _absent(target_agent, aiohttp_session, group)
    finally:
        await topology.teardown("A158 physical ports")

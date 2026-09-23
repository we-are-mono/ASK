"""Bridge multicast recovery with an isolated, tagged LAN listener."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
import pytest_asyncio

from ask_orch.counters import kernel_rx_packets
from ask_orch.uart import Console
from _mcast_wire import capture, frames, new_config, send
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from mcast_wire_capture import multicast_mac
from test_flowtable_offload import ARTIFACTS, WAN_IP, command, console_command, rig  # noqa: F401
from test_flowtable_service import managed_service
from test_flowtable_service_multicast import recover

BRIDGE = 'br-ftmcast'
LAN_VID, WAN_VID, IPTV_VID = 287, 288, 289
IPTV_TAGGED = os.environ.get('ASK_MCAST_RECOVERY_TAGGED') == '1'
WAN_PVID = WAN_VID if IPTV_TAGGED else IPTV_VID
LAN_L3, WAN_L3, LISTENER = BRIDGE + '.287', f'{BRIDGE}.{WAN_PVID}', 'askftmc'
REPORT_TABLE = 'ask_ft_mc_reports'


@pytest_asyncio.fixture(params=[4, 6])
async def multicast_bridge_service(rig, request):
    r = rig
    r.multicast_family, r.multicast_kind = request.param, 'mcast'
    r.multicast_groups = ['239.9.5.1', '239.9.5.2'] if request.param == 4 else ['ff1e::9:5:1', 'ff1e::9:5:2']
    r.multicast_source = '198.18.103.2' if request.param == 4 else 'fd42:6173:8:2::2'
    r.multicast_vlan, r.multicast_window, r.multicast_listener = IPTV_VID, 0, LISTENER
    r.multicast_wire_vlan = IPTV_VID if IPTV_TAGGED else None
    r.multicast_bridge = BRIDGE
    members = Path('/sys/class/net', r.wan_if, 'brif')
    physical = [p.name for p in members.iterdir()
                if Path('/sys/class/net', p.name, 'device').exists()] if members.exists() else [r.wan_if]
    r.multicast_send_if = os.environ.get('ASK_WAN_WIRE_IF')
    if not r.multicast_send_if:
        assert len(physical) == 1, ('set ASK_WAN_WIRE_IF to the DUT-facing physical port', physical)
        r.multicast_send_if = physical[0]
    links = json.loads((await command(r.target, r.session, 'ip', '-j', 'link', 'show'))['stdout'])
    assert not {BRIDGE, LAN_L3, WAN_L3} & {i['ifname'] for i in links}, links
    assert all('master' not in i for i in links if i['ifname'] in (TARGET_LAN_IF, TARGET_WAN_IF)), links
    original = {}
    for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
        interfaces = json.loads((await command(r.target, r.session, 'ip', '-j', '-4', 'addr', 'show', 'dev', dev))['stdout'])
        original[dev] = [f"{a['local']}/{a['prefixlen']}" for a in interfaces[0]['addr_info'] if a['family'] == 'inet']
        assert original[dev]
    defaults = json.loads((await command(r.target, r.session, 'ip', '-j', 'route', 'show', 'default'))['stdout'])
    default = next((rt for rt in defaults if rt.get('dev') == TARGET_WAN_IF), None)
    before = await r.state()
    lan_created = bridge_created = False
    try:
        # The upstream bench switch does not trunk IPTV by default. Its
        # untagged stream and WAN management share the WAN PVID, as in the ISP
        # profile. The LAN listener is tagged; ordinary LAN traffic retains
        # a separate PVID. A trunk can opt into tagged WAN injection.
        # UART carries the address move so management is never needed midway.
        with Console.target(log_path=str(ARTIFACTS / 'multicast-bridge-setup-uart.log')) as con:
            await asyncio.to_thread(con.login, 'root', None)
            await console_command(con, 'ip', 'link', 'add', 'name', BRIDGE, 'type', 'bridge',
                                  'vlan_filtering', '1', 'vlan_default_pvid', '0',
                                  'mcast_snooping', '1', 'mcast_querier', '1')
            bridge_created = True
            await console_command(con, 'ip', 'link', 'set', BRIDGE, 'address', r.dut_wan_mac, 'up')
            for dev, logical, vid, mac in [(TARGET_LAN_IF, LAN_L3, LAN_VID, r.dut_lan_mac),
                                           (TARGET_WAN_IF, WAN_L3, WAN_PVID, r.dut_wan_mac)]:
                for address in original[dev]:
                    await console_command(con, 'ip', 'addr', 'del', address, 'dev', dev)
                await console_command(con, 'ip', 'link', 'set', dev, 'master', BRIDGE)
                await console_command(con, 'bridge', 'vlan', 'add', 'dev', dev, 'vid', str(vid), 'pvid', 'untagged')
                if vid != IPTV_VID:
                    await console_command(con, 'bridge', 'vlan', 'add', 'dev', dev, 'vid', str(IPTV_VID))
                await console_command(con, 'bridge', 'link', 'set', 'dev', dev, 'mcast_flood', 'off', 'mcast_router', '0')
                await console_command(con, 'bridge', 'vlan', 'add', 'dev', BRIDGE, 'vid', str(vid), 'self')
                await console_command(con, 'ip', 'link', 'add', 'link', BRIDGE, 'name', logical, 'type', 'vlan', 'id', str(vid))
                await console_command(con, 'ip', 'link', 'set', logical, 'address', mac, 'up')
                for address in original[dev]:
                    await console_command(con, 'ip', 'addr', 'add', address, 'dev', logical)
            for address, logical, mac in [(r.lan_ip, LAN_L3, r.lan_mac), (WAN_IP, WAN_L3, r.wan_mac)]:
                await console_command(con, 'ip', 'route', 'replace', address + '/32', 'dev', logical)
                await console_command(con, 'ip', 'neigh', 'replace', address, 'lladdr', mac, 'nud', 'permanent', 'dev', logical)
            if default:
                await console_command(con, 'ip', 'route', 'replace', 'default', 'via', default['gateway'], 'dev', WAN_L3)
        # Static MDB configuration owns these recovery transitions. Suppress
        # the listener's automatic reports so a querier cannot undo a
        # deliberate withdrawal while its receiving socket stays open.
        rules = f'''table inet {REPORT_TABLE} {{
 chain output {{ type filter hook output priority -300; policy accept;
  oifname "{LISTENER}" ip protocol igmp drop
  oifname "{LISTENER}" meta l4proto ipv6-icmp icmpv6 type {{ 130, 131, 132, 143 }} drop
 }}
}}'''
        setup = f'''
from pathlib import Path
import json, subprocess
def run(*argv): subprocess.run(argv,check=True,capture_output=True,text=True)
assert not Path('/sys/class/net/' + {LISTENER!r}).exists()
tables=json.loads(subprocess.check_output(['nft','-j','list','tables'],text=True))
assert not any(t.get('table',{{}}).get('name') == {REPORT_TABLE!r} for t in tables['nftables'])
addresses=json.loads(subprocess.check_output(['ip','-j','addr'],text=True))
assert not any(a['local'].startswith(('198.18.103.','fd42:6173:8:2:')) for i in addresses for a in i['addr_info'])
run('ip','link','add','link',{LAN_NIC!r},'name',{LISTENER!r},'type','vlan','id',{str(IPTV_VID)!r})
filtered=False
try:
 subprocess.run(['nft','-f','-'],input={rules!r},text=True,check=True,capture_output=True)
 filtered=True
 run('ip','link','set',{LISTENER!r},'up')
 # A numbered IPTV segment also satisfies the listener's source validation.
 # With no IPv4 address, even loose rp_filter rejects this ingress device.
 run('ip','addr','add','198.18.103.3/24','dev',{LISTENER!r})
 run('ip','-6','addr','add','fd42:6173:8:2::3/64','dev',{LISTENER!r},'nodad')
 Path('/proc/sys/net/ipv4/conf/' + {LISTENER!r} + '/force_igmp_version').write_text('2')
 Path('/proc/sys/net/ipv6/conf/' + {LISTENER!r} + '/force_mld_version').write_text('1')
except BaseException:
 run('ip','link','del',{LISTENER!r})
 if filtered: run('nft','delete','table','inet',{REPORT_TABLE!r})
 raise
'''
        result = await lan_run_python(r.lan, setup, label='multicast_bridge_listener', timeout=15)
        assert result.rc == 0, result.stdout
        lan_created = True
        await asyncio.sleep(3)
        async with managed_service(r):
            yield r
    finally:
        failures = []
        if bridge_created:
            with Console.target(log_path=str(ARTIFACTS / 'multicast-bridge-cleanup-uart.log')) as con:
                await asyncio.to_thread(con.login, 'root', None)
                async def undo(*argv):
                    try:
                        await console_command(con, *argv)
                    except Exception as error:
                        failures.append(repr(error))
                for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                    await undo('ip', 'link', 'set', dev, 'nomaster')
                await undo('ip', 'link', 'del', BRIDGE)
                for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                    for address in original[dev]:
                        await undo('ip', 'addr', 'replace', address, 'dev', dev)
                for address, dev, mac in [(r.lan_ip, TARGET_LAN_IF, r.lan_mac), (WAN_IP, TARGET_WAN_IF, r.wan_mac)]:
                    await undo('ip', 'route', 'replace', address + '/32', 'dev', dev)
                    await undo('ip', 'neigh', 'replace', address, 'lladdr', mac, 'nud', 'permanent', 'dev', dev)
                if default:
                    await undo('ip', 'route', 'replace', 'default', 'via', default['gateway'], 'dev', TARGET_WAN_IF)
        if lan_created:
            result = await lan_run_python(r.lan, f"import subprocess\nsubprocess.run(['ip','link','del',{LISTENER!r}],check=True)\nsubprocess.run(['nft','delete','table','inet',{REPORT_TABLE!r}],check=True)\n",
                                          label='multicast_bridge_listener_cleanup', timeout=15)
            if result.rc:
                failures.append(result.stdout)
        final = await r.wait(lambda s: s['mcast_groups'] == before['mcast_groups']
                             and s['mcast_installed'] == before['mcast_installed'], timeout=8)
        r.record('multicast-bridge-drained', final)
        assert not failures, failures


@pytest.mark.parametrize('fault', ['withdrawal', 'claim-failslab'])
async def test_flowtable_service_multicast_bridge_recovery(multicast_bridge_service, fault):
    await recover(multicast_bridge_service, fault)


# ---- what a bridged replica looks like on the wire --------------------------
#
# A bridge forwards a frame with the Ethernet addresses and hop count it arrived
# with. The listeners' old literal header wrote the egress port's address over
# the sender's, and the IP-level oracles above cannot see that: they read the
# datagram, not the frame. These read the frame.

FRAMING_PORT = 47395
FRAMING_COUNT = 128
# How the WAN wire carries IPTV: untagged on the port's PVID by default, tagged
# where the bench trunks it (ASK_MCAST_RECOVERY_TAGGED=1).
WAN_WIRE_VID = IPTV_VID if IPTV_TAGGED else 0
# A LAN-side sender on the IPTV segment, the listener's own address.
LAN_SOURCE = {4: '198.18.103.3', 6: 'fd42:6173:8:2::3'}


def _group(r):
    return '239.9.5.3' if r.multicast_family == 4 else 'ff1e::9:5:3'


async def _bridged_row(r, group, ready):
    def found(state):
        rows = [g for g in state['mcast'] if g['group'] == group]
        return rows and ready(rows[0])
    state = await r.wait(found, timeout=15)
    return next(g for g in state['mcast'] if g['group'] == group)


async def _mdb(r, port, group, add=True):
    return await command(r.target, r.session, 'bridge', 'mdb', 'replace' if add else 'del',
                         'dev', BRIDGE, 'port', port, 'grp', group, 'vid', str(IPTV_VID),
                         *(['permanent'] if add else []))


def _packets(state, group):
    return int(next(g for g in state['mcast'] if g['group'] == group)['packets'])


async def _window(r, group, source, capture_on, ifaces, inject, ingress, label):
    """Inject a fresh run and read it off the listener's wire, with the
    classifier's own count and the ingress CPU's beside it."""
    config = new_config(r.multicast_family, source, group, FRAMING_PORT, ifaces)
    before = await r.state()
    cpu = await kernel_rx_packets(r.target, r.session, ingress)
    async with capture(capture_on, config) as handle:
        await inject(config, FRAMING_COUNT)
        await asyncio.sleep(0.5)
    cpu = await kernel_rx_packets(r.target, r.session, ingress) - cpu
    after = await r.state()
    r.record(label, {'result': handle['result'], 'before': before, 'after': after,
                     'cpu_rx': cpu})
    return handle['result'], before, after, cpu


async def _from_wan(r, config, count, source_mac):
    """Frames from the orchestrator onto the WAN wire, as the IPTV head end's
    router would send them: tagged where the bench trunks the IPTV VLAN."""
    await asyncio.to_thread(send, frames(config, {1: 512}, count, source_mac=source_mac,
                                         vlan=IPTV_VID if IPTV_TAGGED else None),
                            r.multicast_send_if)


async def _from_lan(r, config, count):
    """Frames from the LAN VM's own IPTV VLAN device. The kernel there puts the
    tag on, so the DUT's LAN port receives exactly the tagged frames a sender
    behind a trunk would send."""
    overhead = (20 if config['family'] == 4 else 40) + 8
    layer = (f"IP(src={config['source']!r}, dst={config['group']!r}, ttl=64, flags='DF')"
             if config['family'] == 4 else
             f"IPv6(src={config['source']!r}, dst={config['group']!r}, hlim=64)")
    script = f'''
import struct, time
from scapy.all import Ether, IP, IPv6, UDP, Raw, conf
token = bytes.fromhex({config['token']!r})
sock = conf.L2socket(iface={LISTENER!r})
try:
    for sequence in range({count}):
        data = b'ASKMCW1' + token + struct.pack('!BI', 1, sequence)
        data += b'.' * ({512 - overhead} - len(data))
        sock.send(Ether(dst={multicast_mac(config['group']).hex(':')!r}) / {layer}
                  / UDP(sport={FRAMING_PORT}, dport={FRAMING_PORT}) / Raw(data))
        time.sleep(0.005)
finally:
    sock.close()
'''
    result = await lan_run_python(r.lan, script, label='multicast_bridge_lan_source',
                                  timeout=30)
    assert result.rc == 0, result.stdout


def _assert_bridged_copy(result, source_mac, group):
    assert not result['errors'], result
    assert result['seen'].get('1') == list(range(FRAMING_COUNT)), result
    assert result['duplicates'] == 0 and result['fragments'] == 0, result
    # A bridge changes neither the sender's address nor the hop count.
    assert result['sources'] == [source_mac.lower()], result
    assert result['destinations'] == [multicast_mac(group).hex(':')], result
    assert result['hops'] == [64], result


async def test_flowtable_service_multicast_bridge_keeps_the_sender(multicast_bridge_service):
    """IPTV in on the WAN port, out to the set-top box tagged. The replica
    carries the sender's MAC, the group's MAC and the sender's hop count, and
    the classifier -- not the CPU -- made it. A second sender of the same
    (S,G) misses the key, which names the first one's address, and once the
    first has gone idle the learner moves the key to the second."""
    r = multicast_bridge_service
    group = _group(r)
    source = r.multicast_source
    await _mdb(r, TARGET_LAN_IF, group)
    try:
        # The first frames teach the learner the stream; then it is hardware.
        await _from_wan(r, new_config(r.multicast_family, source, group, FRAMING_PORT, []),
                        16, r.wan_mac)
        row = await _bridged_row(r, group, lambda g: g['state'] == 'installed')
        assert row['smac'] == r.wan_mac.lower(), row
        assert row['dmac'] == multicast_mac(group).hex(':'), row
        assert row['in'] == TARGET_WAN_IF and row['in_vid'] == str(WAN_WIRE_VID), row
        assert row['ports'] == f'{TARGET_LAN_IF}/{IPTV_VID}', row
        result, before, after, cpu = await _window(
            r, group, source, r.lan, [LISTENER],
            lambda c, n: _from_wan(r, c, n, r.wan_mac), TARGET_WAN_IF,
            'multicast-bridge-sender')
        _assert_bridged_copy(result[LISTENER], r.wan_mac, group)
        assert _packets(after, group) - _packets(before, group) >= FRAMING_COUNT * 0.95, \
            (before, after)
        assert cpu < FRAMING_COUNT * 0.1, cpu

        other = '02:a5:19:10:00:02'
        deadline = asyncio.get_running_loop().time() + 30
        while True:
            await _from_wan(r, new_config(r.multicast_family, source, group,
                                          FRAMING_PORT, []), 16, other)
            row = await _bridged_row(r, group, lambda g: True)
            if row['smac'] == other and row['state'] == 'installed':
                break
            assert asyncio.get_running_loop().time() < deadline, row
            await asyncio.sleep(1)
        result, before, after, cpu = await _window(
            r, group, source, r.lan, [LISTENER],
            lambda c, n: _from_wan(r, c, n, other), TARGET_WAN_IF,
            'multicast-bridge-new-sender')
        _assert_bridged_copy(result[LISTENER], other, group)
        assert _packets(after, group) - _packets(before, group) >= FRAMING_COUNT * 0.95, \
            (before, after)
        assert cpu < FRAMING_COUNT * 0.1, cpu
    finally:
        await _mdb(r, TARGET_LAN_IF, group, add=False)
        await r.wait(lambda s: not any(g['group'] == group for g in s['mcast']), timeout=12)


async def test_flowtable_service_multicast_bridge_tagged_ingress(multicast_bridge_service):
    """IPTV in tagged on the LAN port, out of the WAN port as the WAN wire
    carries it. Before a group could say what it arrives with, its root
    expected an untagged frame and every tagged one fell back to the CPU; now
    the root strips the tag it was told about, and the copy leaves with the
    LAN sender's own address and hop count."""
    r = multicast_bridge_service
    group = _group(r)
    source = LAN_SOURCE[r.multicast_family]
    capture_if = r.multicast_send_if
    await _mdb(r, TARGET_WAN_IF, group)
    try:
        await _from_lan(r, new_config(r.multicast_family, source, group, FRAMING_PORT, []), 16)
        row = await _bridged_row(r, group, lambda g: g['state'] == 'installed')
        assert row['smac'] == r.lan_mac.lower(), row
        assert row['in'] == TARGET_LAN_IF and row['in_vid'] == str(IPTV_VID), row
        assert row['ports'] == f'{TARGET_WAN_IF}/{WAN_WIRE_VID}', row
        # The orchestrator's own wire port is the listener: it receives the
        # copy exactly as the WAN segment carries it.
        result, before, after, cpu = await _window(
            r, group, source, None, [capture_if],
            lambda c, n: _from_lan(r, c, n), TARGET_LAN_IF,
            'multicast-bridge-tagged-ingress')
        _assert_bridged_copy(result[capture_if], r.lan_mac, group)
        assert _packets(after, group) - _packets(before, group) >= FRAMING_COUNT * 0.95, \
            (before, after)
        assert cpu < FRAMING_COUNT * 0.1, cpu
    finally:
        await _mdb(r, TARGET_WAN_IF, group, add=False)
        await r.wait(lambda s: not any(g['group'] == group for g in s['mcast']), timeout=12)

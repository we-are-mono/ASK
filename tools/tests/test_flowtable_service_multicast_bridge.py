"""Bridge multicast recovery with an isolated, tagged LAN listener."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
import pytest_asyncio

from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_offload import ARTIFACTS, WAN_IP, command, console_command, rig  # noqa: F401
from test_flowtable_service import managed_service
from test_flowtable_service_multicast import recover, pytestmark

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
                await console_command(con, 'ip', 'route', 'replace', address + '/32', 'dev', logical, 'mtu', '1200')
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
                    await undo('ip', 'route', 'replace', address + '/32', 'dev', dev, 'mtu', '1200')
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

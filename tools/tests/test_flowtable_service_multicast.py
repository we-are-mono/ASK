"""Native multicast recovery with live unicast and multicast controls."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import time

import pytest
import pytest_asyncio

from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_connections import peer
from test_flowtable_failslab import same_service, slab_fault
from test_flowtable_offload import command, console_command, console_python, read, rig, WAN_IP  # noqa: F401
from test_flowtable_selective_neighbour import hardware, unchanged, warm
from test_flowtable_service import FAULT_DIR, FIRST, FLOWS, managed_service, supervision_status
from test_flowtable_service_vlan import attempts, balanced, denied

pytestmark = pytest.mark.skipif(os.environ.get('ASK_FLOWTABLE_TESTS') != '1',
                               reason='requires the flowtable service on the DUT')
IDENTITY = 'ask-recovery-mcast'
PORT = 49401
GROUPS = {4: ['239.9.4.1', '239.9.4.2'], 6: ['ff1e::9:4:1', 'ff1e::9:4:2']}
SOURCE6, DUT6 = 'fd42:6173:8:2::2', 'fd42:6173:8:2::1'


@pytest_asyncio.fixture(params=[4, 6])
async def multicast_service(rig, request):
    r = rig
    r.multicast_family = request.param
    r.multicast_kind, r.multicast_listener = 'mroute', LAN_NIC
    r.multicast_groups = GROUPS[request.param]
    r.multicast_source = SOURCE6 if request.param == 6 else WAN_IP
    r.multicast_window = 0
    cleanup = []
    before = await r.state()
    r.multicast_initial = before
    assert before['mroute_groups'] == before['mroute_installed'] == 0, before
    try:
        if request.param == 6:
            old = (await read(r.target, r.session, '/proc/sys/net/ipv6/conf/all/forwarding')).strip()
            await command(r.target, r.session, 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=1')
            cleanup.append(['sysctl', '-w', 'net.ipv6.conf.all.forwarding=' + old])
            await command(r.target, r.session, 'ip', '-6', 'addr', 'add', DUT6 + '/64', 'dev', TARGET_WAN_IF, 'nodad')
            cleanup.append(['ip', '-6', 'addr', 'del', DUT6 + '/64', 'dev', TARGET_WAN_IF])
        async with managed_service(r):
            started = False
            try:
                # A separate instance and exact PID ownership. MRT_INIT itself
                # refuses a competing owner; never kill another routing daemon.
                conf = FAULT_DIR + '/smcroute.conf'
                result = await r.target.fs_write(r.session, conf,
                    f'phyint {TARGET_WAN_IF} enable\nphyint {TARGET_LAN_IF} enable\n')
                assert result['errno'] == 0, result
                await console_python(r.service_console, f'''
from pathlib import Path
import subprocess
root=Path({FAULT_DIR!r})
assert not Path('/var/run/' + {IDENTITY!r} + '.pid').exists()
assert not Path('/var/run/' + {IDENTITY!r} + '.sock').exists()
with (root/'smcroute.log').open('w') as log:
 p=subprocess.Popen(['smcrouted','-n','-N','-i',{IDENTITY!r},'-f',{conf!r},'-l','notice'],
                    stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
(root/'smcroute.pid').write_text(str(p.pid))
''')
                started = True
                await asyncio.sleep(2)
                result = await command(r.target, r.session, 'smcroutectl', '-i', IDENTITY, 'show', 'interfaces')
                r.record('multicast-interfaces', result)
                yield r
            finally:
                if started:
                    await console_command(r.service_console, 'smcroutectl', '-i', IDENTITY, 'kill', check=False)
                    await asyncio.sleep(1)
                    state = await r.wait(lambda s: s['mroute_groups'] == s['mroute_installed'] == 0, timeout=8)
                    r.record('multicast-drained', state)
                for argv in reversed(cleanup):
                    await console_command(r.service_console, *argv)
                cleanup.clear()
    finally:
        # An early configuration error can happen before managed_service owns
        # UART; these changes remain reachable over the unmodified IPv4 path.
        for argv in reversed(cleanup):
            await command(r.target, r.session, *argv)


async def route(r, group, add=True):
    if r.multicast_kind == 'mcast':
        result = await command(r.target, r.session, 'bridge', 'mdb', 'replace' if add else 'del',
                               'dev', r.multicast_bridge, 'port', TARGET_LAN_IF, 'grp', group,
                               'vid', str(r.multicast_vlan), *(['permanent'] if add else []))
        if add:
            # Membership grants permission; real traffic supplies its source
            # and physical ingress. A static MDB contains neither of those.
            window = r.multicast_window
            r.multicast_window += 1
            await asyncio.to_thread(send, r, [group], window, 16)
        return result
    return await command(r.target, r.session, 'smcroutectl', '-i', IDENTITY,
                         'add' if add else 'remove', TARGET_WAN_IF, r.multicast_source, group,
                         *([TARGET_LAN_IF] if add else []))


def row(state, group, kind='mroute'):
    rows = [g for g in state[kind] if g['group'] == group]
    assert len(rows) <= 1, rows
    return rows[0] if rows else None


async def wait_group(r, group, installed):
    def ready(state):
        current = row(state, group, r.multicast_kind)
        return (current and current['state'] == 'installed') if installed else (current is None or current['state'] != 'installed')
    return await r.wait(ready, timeout=12)


def send(r, groups, window, count):
    from scapy.all import Ether, Dot1Q, IP, IPv6, UDP, Raw, conf
    frames = []
    for group in groups:
        if ':' in group:
            raw = socket.inet_pton(socket.AF_INET6, group)
            mac = '33:33:' + ':'.join(f'{b:02x}' for b in raw[-4:])
            network = IPv6(src=r.multicast_source, dst=group, hlim=64)
        else:
            octets = [int(v) for v in group.split('.')]
            mac = '01:00:5e:%02x:%02x:%02x' % (octets[1] & 127, octets[2], octets[3])
            network = IP(src=r.multicast_source, dst=group, ttl=64)
        ethernet = Ether(src=r.wan_mac, dst=mac)
        if getattr(r, 'multicast_wire_vlan', None):
            ethernet /= Dot1Q(vlan=r.multicast_wire_vlan)
        frames.append(ethernet / network / UDP(sport=PORT, dport=PORT))
    # Bridge multicast tests inject Ethernet directly on the wire;
    # the orchestrator's own bridge snooping must not decide its delivery.
    sock = conf.L2socket(iface=getattr(r, 'multicast_send_if', r.wan_if))
    try:
        for sequence in range(count):
            payload = b'ASKMCv1:' + struct.pack('!II', window, sequence) + b'x' * 496
            for frame in frames:
                sock.send(frame / Raw(payload))
            time.sleep(0.005)
    finally:
        sock.close()


async def transfer(r, p, label, target=True, probe_target=True):
    groups = r.multicast_groups
    before = await r.state()
    window = r.multicast_window
    r.multicast_window += 1
    await asyncio.gather(asyncio.to_thread(send, r, groups if probe_target else groups[1:], window, 256),
                         p.batch([0, 1], count=128, interval=0.01))
    await asyncio.sleep(0.2)
    after = await r.state()
    results = {}
    for i, group in enumerate(groups):
        result = await p.rpc('multicast', changes={'action': 'status', 'group': group})
        assert not result['errors'], result
        sample = result['windows'].get(str(window), {'received': 0})
        results[group] = sample
        r.record(label, {'before': before, 'after': after, 'received': results})
        if i == 1 or target:
            assert sample['received'] == 256 and sample['duplicates'] == 0, sample
            assert sample['hops'] == [64 if r.multicast_kind == 'mcast' else 63] and sample['sources'] == [r.multicast_source], sample
            current, previous = row(after, group, r.multicast_kind), row(before, group, r.multicast_kind)
            assert current and previous and current['state'] == previous['state'] == 'installed'
            assert int(current['packets']) - int(previous['packets']) == 256, (previous, current)
            # Reading proc above folds hardware statistics into Linux's MFC.
            argv = (['bridge', 'mdb', 'show', 'dev', r.multicast_bridge] if r.multicast_kind == 'mcast' else
                    ['ip', '-6' if r.multicast_family == 6 else '-4', '-s', 'mroute', 'show'])
            table = (await command(r.target, r.session, *argv))['stdout']
            assert any(group in line and 'offload' in line for line in table.splitlines()), table
        else:
            assert sample['received'] == 0, sample
            current = row(after, group, r.multicast_kind)
            # smcrouted may install a negative MFC after traffic requests a
            # withdrawn route. It has no listeners and must stay in software.
            assert current is None or (current['state'] == 'refused-listener' and current['listeners'] == '-'), after
    r.record(label, {'before': before, 'after': after, 'received': results})
    return after


async def recover(r, fault):
    flows = [{**f, 'lan': r.lan_ip} for f in FLOWS]
    service = await supervision_status(r)
    async with peer(r, flows, initial_ids=[0, 1, 3], lease=300) as p:
        await warm(r, p, [0, 1], 'multicast-control-warm', flows[:2])
        initial = await hardware(r, p, 'multicast-controls', flows[:2])
        initial_attempts = await attempts(r)
        for group in r.multicast_groups:
            await p.rpc('multicast', changes={'action': 'join', 'group': group, 'iface': r.multicast_listener, 'port': PORT})
            await route(r, group)
            await wait_group(r, group, True)
        await transfer(r, p, 'multicast-baseline')
        target, control = r.multicast_groups
        for cycle in range(3 if fault == 'withdrawal' else 1):
            label = f'{r.multicast_kind}-{r.multicast_family}-{fault}-{cycle}'
            before = await r.state()
            started = time.monotonic()
            if fault == 'delete-event-failslab':
                async with slab_fault(r, 'mroute-event', label) as injection:
                    await route(r, target, False)
                    hit = await injection.hit()
                    retired = await wait_group(r, target, False)
                    assert retired['mroute_lost'] == before['mroute_lost'] + 1, (before, retired)
                    r.record(label + '-injection', hit)
            else:
                await route(r, target, False)
                retired = await wait_group(r, target, False)
            retirement = time.monotonic() - started
            assert retirement < 12
            unchanged(initial, retired, [0, 1], flows)
            held = time.monotonic()
            while time.monotonic() - held < 6:
                # Traffic can make smcrouted create a negative MFC. Keep the
                # target quiet in ADD-allocation cases so restoration really
                # adds a missing group rather than replacing a known MFC.
                await transfer(r, p, label + '-unavailable', target=False,
                               probe_target=fault not in ('add-event-failslab', 'group-failslab'))
            # Restoration touches only the MFC owner. No apply, rearm, daemon
            # restart, traffic socket replacement, or module reload occurs.
            started = time.monotonic()
            if fault in ('claim-failslab', 'add-event-failslab', 'group-failslab'):
                selected = {'claim-failslab': 'multicast-claim', 'add-event-failslab': 'mroute-event',
                            'group-failslab': 'mroute-group'}[fault]
                async with slab_fault(r, selected, label) as injection:
                    await route(r, target)
                    hit = await injection.hit()
                    admitted = await wait_group(r, target, True)
                    if fault == 'claim-failslab':
                        worker = 'ft_mc_work_fn' if r.multicast_kind == 'mcast' else 'ft_mr_work_fn'
                        assert worker in ''.join(hit['kernel_records']), hit
                        counter = r.multicast_kind + '_install_errors'
                        assert admitted[counter] == before[counter] + 1, (before, admitted)
                    else:
                        assert admitted['mroute_lost'] == before['mroute_lost'] + 1, (before, admitted)
                    r.record(label + '-injection', hit)
            else:
                await route(r, target)
                admitted = await wait_group(r, target, True)
            readmission = time.monotonic() - started
            assert readmission < 15
            after = await transfer(r, p, label + '-recovered')
            assert time.monotonic() - started < 25
            unchanged(initial, after, [0, 1], flows)
            balanced(after, initial['errors'])
            assert int(row(after, control, r.multicast_kind)['packets']) > int(row(before, control, r.multicast_kind)['packets'])
            assert after[r.multicast_kind + '_installed'] >= 2
            assert {g['group'] for g in after[r.multicast_kind] if g['group'] in r.multicast_groups} == set(r.multicast_groups)
            assert after['rearms'] == initial['rearms'] and await attempts(r) == initial_attempts
            await denied(r, p, 3)
            await same_service(r, service)
            r.record(label + '-recovery', {'retirement_seconds': retirement, 'ready_seconds': readmission,
                                          'before': before, 'retired': retired, 'admitted': admitted, 'after': after})
        await p.rpc('open', [2])
        await warm(r, p, [0, 1, 2], 'multicast-new-control', flows[:3])
        await hardware(r, p, 'multicast-final-controls', flows[:3])
        for group in r.multicast_groups:
            await route(r, group, False)
            await wait_group(r, group, False)
            await p.rpc('multicast', changes={'action': 'leave', 'group': group})


@pytest.mark.parametrize('fault', ['withdrawal', 'claim-failslab', 'add-event-failslab', 'delete-event-failslab', 'group-failslab'])
async def test_flowtable_service_multicast_recovery(multicast_service, fault):
    await recover(multicast_service, fault)

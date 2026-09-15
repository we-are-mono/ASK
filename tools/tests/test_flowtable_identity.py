"""Physical MAC and name changes preserve Linux ownership and current rewrites."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct

import pytest

from ask_orch.counters import kernel_tx_packets
from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_connections import FLOWS, connections, healthy, peer  # noqa: F401
from test_flowtable_mtu import table_identity, udp_size, udp_warm
from test_flowtable_offload import (ARTIFACTS, DPORT, TABLE, WAN_IP, command,  # noqa: F401
                                    console_command, console_python, read, rig)
from test_flowtable_selective_neighbour import hardware, warm

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")


async def set_mac(con, dev, address, mac):
    # Announce the new receive address through ordinary ARP. Endpoints retain
    # their existing sockets and learn the gateway's new address normally.
    script = rf'''
import socket, struct, subprocess
subprocess.run(['ip', 'link', 'set', 'dev', {dev!r}, 'address', {mac!r}], check=True)
mac = bytes.fromhex({mac.replace(':', '')!r})
ip = socket.inet_aton({address!r})
frame = b'\xff'*6 + mac + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x800, 6, 4, 1) + mac + ip + b'\x00'*6 + ip
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x806)) as s:
    s.bind(({dev!r}, 0))
    s.send(frame); s.send(frame)
'''
    await console_python(con, script)


async def wan_wire(r, sport, source_mac, operation):
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
    raw.bind((r.wan_if, 0))
    raw.setblocking(False)
    loop = asyncio.get_running_loop()

    async def capture():
        count = 0
        async with asyncio.timeout(15):
            while count < 256:
                frame = await loop.sock_recv(raw, 65536)
                if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
                    continue
                if frame[26:30] != socket.inet_aton(r.lan_ip) or frame[30:34] != socket.inet_aton(WAN_IP):
                    continue
                ihl = (frame[14] & 15) * 4
                if struct.unpack('!HH', frame[14 + ihl:18 + ihl]) != (sport, DPORT):
                    continue
                assert frame[6:12] == bytes.fromhex(source_mac.replace(':', '')), frame.hex()
                assert frame[:6] == bytes.fromhex(r.wan_mac.replace(':', '')), frame.hex()
                count += 1
        return {"frames": count, "source_mac": source_mac}

    task = asyncio.create_task(capture())
    try:
        result = await operation
        return result, await task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raw.close()


async def test_flowtable_mac_recovery(connections):
    r = connections
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS[:2]]
    original = {TARGET_LAN_IF: r.dut_lan_mac, TARGET_WAN_IF: r.dut_wan_mac}
    current = dict(original)
    addresses = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr"))["stdout"])
    ips = {d: next(a["local"] for i in addresses if i["ifname"] == d for a in i["addr_info"])
           for d in original}
    identity = await table_identity(r)
    with Console.target(log_path=str(ARTIFACTS / "mac-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)

        async def change(dev, mac):
            current[dev] = mac  # Finally must restore even if announcement fails.
            await set_mac(con, dev, ips[dev], mac)

        try:
            async with peer(r, flows) as p:
                try:
                    await warm(r, p, [0, 1], "mac-initial-admission", flows)
                    initial = await hardware(r, p, "mac-initial-hardware", flows)
                    for dev in original:
                        changed = "02:f6:d7:00:01:33" if dev == TARGET_LAN_IF else "02:f6:d7:00:01:44"
                        for mac in (changed, original[dev]):
                            before = await r.state()
                            await p.rpc("start", [0], count=0, interval=0.01, allow_loss=True)
                            await p.rpc("start", [1], count=0, interval=0.01)
                            await change(dev, mac)
                            transfers = await p.rpc("stop", [0, 1])
                            assert transfers["1"]["count"] > 0 and transfers["1"]["lost"] == 0
                            after = await warm(r, p, [0, 1], f"mac-{dev}-{mac}-admission", flows)
                            # IPv4 can invalidate neighbours before the MAC
                            # notifier sees the same shared handle. The first
                            # invalidator owns its diagnostic count.
                            counters = ("mac_invalidations", "neighbour_invalidations")
                            assert sum(after[k] - before[k] for k in counters) >= 2
                            assert after["deletes"] >= before["deletes"] + 4
                            assert after["installs"] - before["installs"] == after["deletes"] - before["deletes"]
                            assert after["rearms"] == initial["rearms"] and not after["invalidation_done"]
                            assert await table_identity(r) == identity
                            _, wire = await wan_wire(r, flows[0]["sport"], current[TARGET_WAN_IF],
                                                     hardware(r, p, f"mac-{dev}-{mac}-hardware", flows))
                            r.record(f"mac-{dev}-{mac}", {"before": before, "after": after,
                                                         "transfers": transfers, "wan_wire": wire})
                finally:
                    for dev, mac in original.items():
                        if current[dev] != mac:
                            await change(dev, mac)
            # The sole LAN console is free again. Verify the LAN Ethernet
            # source with a raw receive socket as well as hardware counters.
            await change(TARGET_LAN_IF, "02:f6:d7:00:01:33")
            r.dut_lan_mac = current[TARGET_LAN_IF]
            await udp_warm(r, flows[0]["sport"], {d: 1200 for d in original})
            await udp_size(r, flows[0]["sport"], 256, "mac-lan-wire")
            assert await table_identity(r) == identity
        finally:
            for dev, mac in original.items():
                if current[dev] != mac:
                    await change(dev, mac)
            r.dut_lan_mac, r.dut_wan_mac = original[TARGET_LAN_IF], original[TARGET_WAN_IF]
            # CHANGEADDR evicts even permanent neighbours. Re-establish the
            # fixture's records so its original restore/delete actions apply.
            for address, dev, mac in ((r.lan_ip, TARGET_LAN_IF, r.lan_mac),
                                      (WAN_IP, TARGET_WAN_IF, r.wan_mac)):
                await console_command(con, "ip", "neigh", "replace", address,
                                      "dev", dev, "lladdr", mac, "nud", "permanent")


async def test_flowtable_rename_identity(connections):
    r = connections
    flows = [{**f, "sport": f["sport"] + 1, "lan": r.lan_ip} for f in FLOWS[:2]]
    names = {d: d for d in (TARGET_LAN_IF, TARGET_WAN_IF)}
    temporary = "askftrename"
    with Console.target(log_path=str(ARTIFACTS / "rename-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        links = json.loads((await command(r.target, r.session, "ip", "-j", "link"))["stdout"])
        assert temporary not in {i["ifname"] for i in links}, links
        async with peer(r, flows) as p:
            await warm(r, p, [0, 1], "rename-initial-admission", flows)

            async def window(label):
                before = await r.state()
                healthy(before)
                tx_before = {d: await kernel_tx_packets(r.target, r.session, n) for d, n in names.items()}
                transfers = await p.batch([0, 1], 256, 0.03125)
                after = await r.state()
                healthy(after)
                assert before["installs"] == after["installs"] and before["deletes"] == after["deletes"]
                old, new = ({f["cookie"]: f for f in s["flows"]} for s in (before, after))
                assert old.keys() == new.keys() and len(new) == 4
                for cookie, flow in new.items():
                    assert flow["in"] in names.values() and flow["out"] in names.values()
                    packets = int(flow["packets"]) - int(old[cookie]["packets"])
                    if flow["proto"] == "17":
                        assert packets == 256
                        assert int(flow["bytes"]) - int(old[cookie]["bytes"]) == 256 * 298
                    else:
                        assert packets >= transfers[1]["bytes"] // 1500
                tx = {d: await kernel_tx_packets(r.target, r.session, n) - tx_before[d] for d, n in names.items()}
                assert 0 <= tx[TARGET_LAN_IF] <= 64 and 0 <= tx[TARGET_WAN_IF] <= 512, tx
                r.record(label, {"before": before, "after": after, "transfers": transfers, "software_tx": tx})

            for dev in names:
                before = await r.state()
                identity = await table_identity(r)
                try:
                    await console_command(con, "ip", "link", "set", "dev", dev, "name", temporary)
                    names[dev] = temporary
                    after = await r.state()
                    assert after["installs"] == before["installs"] and after["deletes"] == before["deletes"]
                    assert (await table_identity(r))["handle"] == identity["handle"]
                    await window(f"rename-{dev}-retained")
                    # A fresh binding must find the same hardware port by
                    # object identity while its OS name differs from startup.
                    await r.delete_table()
                    await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {', '.join(names.values())} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} meta l4proto {{ tcp, udp }} th sport {flows[0]['sport']} th dport {DPORT} flow add @fast
 }}
}}''')
                    for _ in range(8):
                        await p.batch([0, 1], 128, 0.01)
                        if (await r.state())["entries"] == 4:
                            break
                    else:
                        pytest.fail("renamed port did not admit fresh flows")
                    await window(f"rename-{dev}-rebound")
                finally:
                    if names[dev] != dev:
                        await console_command(con, "ip", "link", "set", "dev", names[dev], "name", dev)
                        names[dev] = dev

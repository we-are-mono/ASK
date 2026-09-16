"""Native MASQUERADE translation and Linux-owned WAN mapping retirement."""
import asyncio
import json
import os
import re

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_connections import FLOWS, connections, healthy, peer  # noqa: F401
from test_flowtable_offload import (ARTIFACTS, DPORT, WAN_IP, command, console_command,
                                   read, rig, status_text)  # noqa: F401
from test_flowtable_policy import CONFIG, apply, candidate, stop
from test_flowtable_snat import test_flowtable_udp_snat as _udp
from test_flowtable_tcp import (cpu, cpu_delta, software_tx,
                               test_flowtable_tcp_retransmit_withdraw_rst as _tcp)
from test_flowtable_tcp_snat import tcp_snat  # noqa: F401

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
ADDRESS, REPLACEMENT, ENDPOINT = "198.18.40.1", "198.18.40.3", "198.18.40.2"


@pytest_asyncio.fixture(autouse=True)
async def masquerade_network(request, target_agent, aiohttp_session):
    if request.node.originalname != "test_flowtable_masquerade_wan_lifecycle":
        yield
        return
    # Autouse ordering provisions the extra subnet before the common rig finds
    # its endpoint interface and installs its ordinary routes/neighbours.
    assert WAN_IP == ENDPOINT, f"run this test with ASK_WAN_IPERF_IP={ENDPOINT}"
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    cleanup = []
    try:
        for agent, dev, address in [(wan, "br0", ENDPOINT), (target_agent, TARGET_WAN_IF, ADDRESS)]:
            await command(agent, aiohttp_session, "ip", "addr", "add", address + "/24", "dev", dev)
            cleanup.append((agent, dev, address))
        yield cleanup
    finally:
        for agent, dev, address in reversed(cleanup):
            await command(agent, aiohttp_session, "ip", "addr", "del", address + "/24", "dev", dev, check=False)


async def test_flowtable_udp_masquerade(connections):
    await _udp(connections, False, nat_kind="masquerade")


@pytest.mark.parametrize("rig", ["tcp"], indirect=True)
@pytest.mark.parametrize("tcp_snat", ["masquerade"], indirect=True)
async def test_flowtable_tcp_masquerade(tcp_snat):
    await _tcp(tcp_snat)


def mapping_rows(r, state, ids, external):
    healthy(state)
    assert state["entries"] == 2 * len(ids), state
    rows = {}
    for ident in ids:
        spec = FLOWS[ident]
        proto = "6" if spec["proto"] == "tcp" else "17"
        local, remote = f"{r.lan_ip}:{spec['sport']}", f"{WAN_IP}:{DPORT}"
        mapped = f"{external}:{spec['sport'] + 1024}"
        for dev, expected in ((TARGET_LAN_IF, (local, remote, mapped, remote, WAN_IP)),
                              (TARGET_WAN_IF, (remote, mapped, remote, local, r.lan_ip))):
            row, = [f for f in state["flows"] if f["in"] == dev and f["proto"] == proto]
            assert tuple(row[k] for k in ("src", "dst", "new_src", "new_dst", "nexthop")) == expected, state
            assert row["mtu"] == "1200", row
            rows[(dev, proto)] = row
    return rows


async def warm_mapping(r, p, ids, external):
    for _ in range(10):
        await p.batch(ids, 64, 0.01)
        state = await r.state()
        if state["entries"] == len(ids) * 2:
            mapping_rows(r, state, ids, external)
            return state
    pytest.fail(f"MASQUERADE did not install: {state}")


async def hardware_mapping(r, p, ids, external, label):
    before = await r.state()
    old = mapping_rows(r, before, ids, external)
    tx_before, cpu_before = await software_tx(r), await cpu(r)
    reports = await p.batch(ids, 256, 0.03125)
    cpu_after, tx_after = await cpu(r), await software_tx(r)
    after = await r.state()
    new = mapping_rows(r, after, ids, external)
    assert (after["installs"], after["deletes"]) == (before["installs"], before["deletes"])
    for key, row in new.items():
        previous = old[key]
        assert row["cookie"] == previous["cookie"]
        packets = int(row["packets"]) - int(previous["packets"])
        if key[1] == "17":
            assert packets == 256
            assert int(row["bytes"]) - int(previous["bytes"]) == 76288
        else:
            assert packets >= (256 * 16384) // 1500
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    assert tx[TARGET_LAN_IF] <= 64 and tx[TARGET_WAN_IF] <= 512, tx
    r.record(label, {"before": before, "after": after, "transfers": reports,
                     "software_tx": tx, "cpu": cpu_delta(cpu_before, cpu_after)})
    return after


async def test_flowtable_masquerade_wan_lifecycle(connections, masquerade_network):
    r = connections
    nat_table = "ask_masq_test"
    flows = []
    for spec in FLOWS[:6]:
        external = ADDRESS if spec["id"] < 2 else REPLACEMENT
        flow = {**spec, "remote": [external, spec["sport"] + 1024], "abort": True}
        if spec["proto"] == "udp":
            flow.update(iface=LAN_NIC, wire={"source_ip": WAN_IP, "destination_ip": r.lan_ip,
                "source_port": DPORT, "destination_port": spec["sport"],
                "source_mac": r.dut_lan_mac, "destination_mac": r.lan_mac})
        flows.append(flow)
    rules = " ".join(f"ip saddr {r.lan_ip} ip daddr {WAN_IP} {f['proto']} sport {f['sport']} "
                     f"{f['proto']} dport {DPORT} masquerade to :{f['sport'] + 1024};" for f in flows)
    nat = f"table ip {nat_table} {{ chain postrouting {{ type nat hook postrouting priority 90; {rules} }}; }}"
    await r.delete_table()
    control = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", "tcp", "--dport", str(DPORT + 1), "-j", "ACCEPT"]
    with Console.target(log_path=str(ARTIFACTS / "masquerade-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        async def ct(ids):
            result = {}
            for ident in ids:
                f = FLOWS[ident]
                reply = await console_command(con, "conntrack", "-L", "-p", f["proto"],
                    "--orig-src", r.lan_ip, "--orig-dst", WAN_IP, "--sport", str(f["sport"]),
                    "--dport", str(DPORT), "-o", "id")
                # UART merges stdout/stderr; conntrack prints its entry-count
                # summary even when no mapping remains. Retain only ID rows.
                result[str(ident)] = "\n".join(line for line in reply["stdout"].splitlines()
                                                if re.search(r"\bid=\d+", line))
            return result

        async def retired(ids, before):
            deadline = asyncio.get_running_loop().time() + 8
            while asyncio.get_running_loop().time() < deadline:
                state = status_text((await console_command(con, "cat", "/proc/cdx_flowtable"))["stdout"])
                conntracks = await ct(ids)
                if not state["entries"] and not any(v.strip() for v in conntracks.values()):
                    break
                await asyncio.sleep(0.1)
            healthy(state)
            assert state["entries"] == state["handle_refs"] == state["neighbour_refs"] == 0, state
            assert state["deletes"] == before["deletes"] + 4 and state["installs"] == before["installs"], (before, state)
            assert not any(v.strip() for v in conntracks.values()), conntracks
            return {"state": state, "conntracks": conntracks}

        async def restore_port():
            await console_command(con, "ip", "link", "set", "dev", TARGET_WAN_IF, "up")
            for _ in range(60):
                carrier = await console_command(con, "cat", f"/sys/class/net/{TARGET_WAN_IF}/carrier", check=False)
                if carrier["stdout"].strip() == "1":
                    break
                await asyncio.sleep(0.1)
            assert carrier["stdout"].strip() == "1", carrier
            await console_command(con, "ip", "route", "replace", WAN_IP + "/32", "dev", TARGET_WAN_IF, "mtu", "1200")
            await console_command(con, "ip", "neigh", "replace", WAN_IP, "lladdr", r.wan_mac, "nud", "permanent", "dev", TARGET_WAN_IF)

        existing = await console_command(con, "nft", "list", "table", "ip", nat_table, check=False)
        assert existing["rc"] != 0
        await console_command(con, "nft", nat)
        try:
            await console_command(con, "iptables", "-t", "nat", "-I", *control)
            await apply(con, candidate(r), r=r)
            async with peer(r, flows, initial_ids=[0, 1]) as p:
                await warm_mapping(r, p, [0, 1], ADDRESS)
                before = await hardware_mapping(r, p, [0, 1], ADDRESS, "masq-initial")
                old = await ct([0, 1])
                assert all(re.search(r"\bid=\d+", text) for text in old.values()), old
                await console_command(con, "ip", "addr", "del", ADDRESS + "/24", "dev", TARGET_WAN_IF)
                removed = await retired([0, 1], before)
                r.record("masq-address-retired", {"old": old, **removed})
                await p.rpc("close", [0, 1])
                await console_command(con, "ip", "addr", "add", REPLACEMENT + "/24", "dev", TARGET_WAN_IF)
                masquerade_network.append((r.target, TARGET_WAN_IF, REPLACEMENT))
                await restore_port()
                await p.rpc("open", [2, 3])
                await warm_mapping(r, p, [2, 3], REPLACEMENT)
                before = await hardware_mapping(r, p, [2, 3], REPLACEMENT, "masq-new-address")
                current = await ct([2, 3])
                assert set(re.findall(r"\bid=\d+", str(current))).isdisjoint(re.findall(r"\bid=\d+", str(old)))
                try:
                    await console_command(con, "ip", "link", "set", "dev", TARGET_WAN_IF, "down")
                    removed = await retired([2, 3], before)
                    r.record("masq-link-retired", {"old": current, **removed})
                finally:
                    await restore_port()
                await p.rpc("close", [2, 3])
                await p.rpc("open", [4, 5])
                await warm_mapping(r, p, [4, 5], REPLACEMENT)
                await hardware_mapping(r, p, [4, 5], REPLACEMENT, "masq-link-restored")
        finally:
            await restore_port()
            try:
                await stop(con)
            finally:
                await console_command(con, "iptables", "-t", "nat", "-D", *control, check=False)
                await console_command(con, "nft", "delete", "table", "ip", nat_table)
                await console_command(con, "rm", "-f", CONFIG)

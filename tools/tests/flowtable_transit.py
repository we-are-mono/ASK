"""Transit tunnels in hardware (A386): ESP between two IPsec peers, and GRE,
IPv4 in IPv4 and IPv6 in IPv4 between two tunnel endpoints, routed through the
DUT from the LAN VM to the WAN host.

Conntrack tracks each by its address pair and protocol, the flowtable carries
them so (kernel patch 174), and the adapter installs each direction in the
routed tables' three-tuple key -- ESP reached there by its own table's miss,
the tunnels by the TCP and UDP tables' (cdxdrv_set_miss_action()), whose
schemes key the stream a tunnel carries rather than the tunnel. The endpoints
are real: Linux tunnel devices at both ends, and for ESP a pair of manual
transport-mode SAs over one TCP port, so what crosses the DUT is what a LAN
host's VPN or tunnel broker would send.

Each case proves the hardware carries the tunnel: both directions installed,
their counters moving by the stream inside it, and the DUT's kernel sending
next to nothing meanwhile.
"""
from __future__ import annotations

import asyncio
import json
import os
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from _flowtable_ipv6 import _offload_table, ipv6_rig  # noqa: F401
from _flowtable_rig import TABLE, WAN_IP, command, rig  # noqa: F401
from _flowtable_tcp import software_tx
from _throughput import SOFTWARE_TX
from _topology import LAN_IPV6, TARGET_LAN_IF, TARGET_WAN_IF, WAN_IPV6, lan_run

TUNNEL = "ftt0"
IPERF_PORT = 5277
# Inside the tunnels: the WAN host's end first. Claimed here alone.
INNER4 = ("10.77.0.1", "10.77.0.2")
INNER6 = ("fd77:7700::1", "fd77:7700::2")
# Manual SAs for the ESP case, one per direction: an AES-GCM key of 16 bytes
# and its 4-byte salt.
ESP_KEY = "0x" + "11" * 20
ESP_SPI = (0x77001, 0x77002)
KINDS = {
    "gre": {"proto": 47, "mode": "gre"},
    "ipip": {"proto": 4, "mode": "ipip"},
    "6in4": {"proto": 41, "mode": "sit"},
    "esp": {"proto": 50, "mode": None},
}
# The stream's frames the hardware must account for, per direction, inside
# the window it is measured over.
MOVED = 5000


def _wan():
    return Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")


async def _lan(r, cmd, timeout=15):
    result = await lan_run(r.lan, cmd, timeout)
    assert result.rc == 0, (cmd, result.stdout)
    return result.stdout


@pytest_asyncio.fixture(params=list(KINDS))
async def transit(rig, request):  # noqa: F811
    r = rig
    r.kind = request.param
    kind = KINDS[r.kind]
    wan = _wan()
    undo = []

    async def dut(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    async def host(*argv, check=True):
        return await command(wan, r.session, *argv, check=check)

    proto = str(kind["proto"])
    try:
        # Not translated: the image masquerades what leaves by the WAN,
        # and a translated tunnel is not offered (patch 174).
        nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", proto, "-j", "ACCEPT"]
        await dut("iptables", "-t", "nat", "-I", *nat)
        undo.append(lambda: dut("iptables", "-t", "nat", "-D", *nat, check=False))
        await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
  ip saddr {r.lan_ip} ip daddr {WAN_IP} meta l4proto {proto} flow add @fast
  ip saddr {WAN_IP} ip daddr {r.lan_ip} meta l4proto {proto} flow add @fast
 }}
}}''')
        await r.wait(lambda s: s["bindings"] == 2)
        if kind["mode"]:
            for side, local, remote, inner in (("lan", r.lan_ip, WAN_IP, 1), ("host", WAN_IP, r.lan_ip, 0)):
                argv = ["ip", "tunnel", "add", TUNNEL, "mode", kind["mode"], "local", local,
                        "remote", remote, "ttl", "64"]
                addr = (f"{INNER6[inner]}/64" if r.kind == "6in4" else f"{INNER4[inner]}/30")
                family = "-6" if r.kind == "6in4" else "-4"
                if side == "lan":
                    await lan_run(r.lan, f"ip link del {TUNNEL} 2>/dev/null; true", 10)
                    await _lan(r, " ".join(argv))
                    undo.append(lambda: lan_run(r.lan, f"ip link del {TUNNEL}", 10))
                    await _lan(r, f"ip {family} addr add {addr} dev {TUNNEL} nodad"
                                  if family == "-6" else f"ip addr add {addr} dev {TUNNEL}")
                    await _lan(r, f"ip link set {TUNNEL} up")
                else:
                    await host("ip", "link", "del", TUNNEL, check=False)
                    await host(*argv)
                    undo.append(lambda: host("ip", "link", "del", TUNNEL, check=False))
                    await host("ip", family, "addr", "add", addr, "dev", TUNNEL,
                               *(["nodad"] if family == "-6" else []))
                    await host("ip", "link", "set", TUNNEL, "up")
            r.server_addr = INNER6[0] if r.kind == "6in4" else INNER4[0]
            r.client_addr = INNER6[1] if r.kind == "6in4" else INNER4[1]
        else:
            await _esp(r, host, r.lan_ip, WAN_IP, undo)
            r.server_addr, r.client_addr = WAN_IP, r.lan_ip
        r.proto_num = kind["proto"]
        yield r
    finally:
        for step in reversed(undo):
            try:
                await step()
            except Exception:  # noqa: BLE001 -- teardown keeps going
                pass
        await command(r.target, r.session, "conntrack", "-D", "-p", proto, "-s", r.lan_ip,
                      "-d", WAN_IP, check=False)
        await command(r.target, r.session, "conntrack", "-D", "-p", proto, "-s", WAN_IP,
                      "-d", r.lan_ip, check=False)


async def _esp(r, host, lan, wan, undo):
    """Manual transport-mode SAs over the one TCP port the stream uses, so
    nothing else between the two is touched; their undoing goes on `undo`."""
    sas = [(lan, wan, ESP_SPI[0]), (wan, lan, ESP_SPI[1])]
    policies = {
        "lan": [(lan, wan, "out", "dport"), (wan, lan, "in", "sport")],
        "host": [(wan, lan, "out", "sport"), (lan, wan, "in", "dport")],
    }
    for side in ("lan", "host"):
        cmds = [["ip", "xfrm", "state", "add", "src", src, "dst", dst, "proto", "esp",
                 "spi", hex(spi), "reqid", "77", "mode", "transport",
                 "aead", "rfc4106(gcm(aes))", ESP_KEY, "128"] for src, dst, spi in sas]
        cmds += [["ip", "xfrm", "policy", "add", "src", src, "dst", dst, "proto", "tcp",
                  port, str(IPERF_PORT), "dir", direction, "tmpl", "src", src, "dst", dst,
                  "proto", "esp", "reqid", "77", "mode", "transport"]
                 for src, dst, direction, port in policies[side]]
        flush = [["ip", "xfrm", "state", "deleteall", "proto", "esp", "reqid", "77"]] + \
                [["ip", "xfrm", "policy", "delete", "src", src, "dst", dst, "proto", "tcp",
                  port, str(IPERF_PORT), "dir", direction]
                 for src, dst, direction, port in policies[side]]
        for argv in cmds:
            if side == "lan":
                await _lan(r, " ".join(f"'{a}'" if "(" in a else a for a in argv))
            else:
                await host(*argv)
        for argv in flush:
            if side == "lan":
                undo.append(lambda a=argv: lan_run(r.lan, " ".join(a), 10))
            else:
                undo.append(lambda a=argv: host(*a, check=False))


def _rows(r, state):
    return [f for f in state["flows"] if int(f["proto"]) == r.proto_num]


async def _iperf(r, seconds):
    """A TCP stream from the LAN VM to the WAN host inside the tunnel; returns
    the client's JSON report."""
    server = await asyncio.create_subprocess_exec(
        "iperf3", "-s", "-1", "-B", r.server_addr, "-p", str(IPERF_PORT),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    try:
        await asyncio.sleep(0.5)
        return asyncio.create_task(lan_run(
            r.lan, f"iperf3 -c {r.server_addr} -B {r.client_addr} -p {IPERF_PORT} "
                   f"-t {seconds} -P 4 -J", seconds + 30)), server
    except BaseException:
        server.terminate()
        raise


async def test_transit_in_hardware(transit):
    await _carried(transit)


async def test_transit_esp6_in_hardware(ipv6_rig):  # noqa: F811
    """ESP between two IPv6 peers, which the classifier sends to the IPv6
    routed tables as it sends IPv4 ESP to the IPv4 ones."""
    r = ipv6_rig
    r.kind, r.proto_num = "esp6", 50
    wan = _wan()
    undo = []

    async def host(*argv, check=True):
        return await command(wan, r.session, *argv, check=check)

    try:
        await _offload_table(r, "meta l4proto 50")
        await _esp(r, host, LAN_IPV6, WAN_IPV6, undo)
        r.server_addr, r.client_addr = WAN_IPV6, LAN_IPV6
        await _carried(r)
    finally:
        for step in reversed(undo):
            try:
                await step()
            except Exception:  # noqa: BLE001 -- teardown keeps going
                pass
        await command(r.target, r.session, "conntrack", "-D", "-f", "ipv6", "-p", "50",
                      check=False)


async def _carried(r):
    """The tunnel's stream inside it, carried by its two directions in
    hardware with the DUT's kernel sending next to nothing."""
    # Both directions of the tunnel seen, so its conntrack is confirmed and
    # both directions are offered.
    ping = (f"ping -6 -c 4 -i 0.2 -W 2 {r.server_addr}" if ":" in r.server_addr
            else f"ping -c 4 -i 0.2 -W 2 {r.server_addr}")
    if r.kind.startswith("esp"):
        # No SA covers ICMP: the stream itself sets the tunnel up.
        ping = "true"
    await lan_run(r.lan, ping, 15)
    task, server = await _iperf(r, 12)
    try:
        deadline = time.monotonic() + 8
        state = await r.state()
        while len(_rows(r, state)) < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.5)
            state = await r.state()
        r.record(f"transit-{r.kind}-admitted", state)
        rows = _rows(r, state)
        assert len(rows) == 2, (r.kind, state["flows"], state.get("rejects"))
        before = {row["cookie"]: int(row["packets"]) for row in rows}
        tx_before = await software_tx(r)
        await asyncio.sleep(3)
        tx_after = await software_tx(r)
        after = {row["cookie"]: int(row["packets"]) for row in _rows(r, await r.state())}
        result = await task
        task = None
    finally:
        if task:
            task.cancel()
        if server.returncode is None:
            server.terminate()
        await server.wait()
    report = json.loads(result.stdout[result.stdout.index("{"):])
    rate = report["end"]["sum_received"]["bits_per_second"]
    moved = {c: after.get(c, 0) - before[c] for c in before}
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    r.record(f"transit-{r.kind}", {"moved": moved, "software_tx": tx, "rate": rate})
    assert all(m >= MOVED for m in moved.values()), moved
    assert all(0 <= t <= SOFTWARE_TX for t in tx.values()), tx

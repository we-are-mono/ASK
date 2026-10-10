"""Bulk and simultaneous TCP NAT, and a NAT'd UDP direction at minimum and
small frame sizes, with hardware evidence."""
import asyncio
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.commands import console_python
from ask_orch.counters import kernel_rx_packets

from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from _flowtable_connections import (by_key, healthy)
from _flowtable_rig import (artifact_dir, DPORT, HEALTH_BASELINE, SPORT, WAN_IP, command, console_command, read)
from _flowtable_policy import (CONFIG, apply, candidate, stop)
from _flowtable_service_ipsec import wire_interface
from _flowtable_tcp import (cpu, cpu_delta, software_tx)

PORT, STREAMS = DPORT + 3000, 4
# Short enough for every suite run. The proof is structural -- every bulk
# stream on its hardware entry, software TX flat, cookies stable -- and the
# rate only needs a steady-state sample: iperf discards the ramp (-O), and the
# hardware window sits inside the measured interval.
IPERF_SECONDS, IPERF_OMIT, WINDOW_SECONDS = 5, 2, 3

# The packet-rate flows' own tuples, one source port per generator thread,
# apart from the bulk cases'. One flow per thread spreads the WAN host's
# receive work over as many queues.
PACKET_SPORT, PACKET_PORT = SPORT + 3002, DPORT + 3002
# Wire sizes, FCS included: the minimum Ethernet frame, and a small one.
PACKET_FRAMES = (64, 128)
# The LAN VM's four pktgen threads, one per transmit queue of its 10 Gbit/s
# NIC, put 9.04 Mpps of minimum frames on the wire, into a MAC nobody owns,
# and 8 Mpps of 128-byte ones. That overloads the DUT. A paced rate needs a
# single thread: the LAN VM is a guest, and a paced pktgen thread the host
# descheduled catches up at full speed, so four of them catching up together
# offer well past the DUT's ceiling for a moment, where one alone cannot.
PACKET_THREADS = 4
PACKET_SECONDS = 3
PACKET_SENDER = {64: 9e6, 128: 8e6}


def _mpps(name, frame, default):
    return float(os.environ.get(f"ASK_PACKET_RATE_{name}_{frame}", default)) * 1e6


# One LAN port's FMan receive path forwarded 3.17-3.30 Mpps at both sizes,
# overloaded; past that its MAC FIFO overflows and drops whole frames.
PACKET_CAPACITY = {frame: _mpps("CAPACITY", frame, "3") for frame in PACKET_FRAMES}
# Paced, one thread delivered 1.91 Mpps of minimum frames and 1.97 of small
# ones for 2 asked, with nothing dropped anywhere; pktgen's pacing runs a few
# per cent slow, so the generator must reach nine tenths of what it is asked.
PACKET_LOSSLESS = {frame: _mpps("LOSSLESS", frame, "2") for frame in PACKET_FRAMES}
PACKET_PACED = 0.9
FMAN = "/sys/devices/platform/soc/1a00000.fman"
# The LAN port's receive half, by its BMI register block.
LAN_RX_PORT = "1a90000"
PORT_STATISTICS = ("port_frame", "port_enq_total", "port_discard_frame", "port_rx_bad_frame",
                   "port_rx_filter_frame", "port_rx_out_of_buffers_discard")
# The share of the offered frames any hop may come up short by.
PACKET_LOSS = 1e-4
# The LAN VM's own frames (ARP, neighbour discovery) landing between two
# counter reads of one snapshot.
PACKET_NOISE = 64


def _udp_counters():
    rows = [line.split()[1:] for line in Path("/proc/net/snmp").read_text().splitlines()
            if line.startswith("Udp:")]
    return dict(zip(rows[0], map(int, rows[1])))


def _nic_counters(name):
    # A bridge has no driver statistics; retain its physical members too.
    names = [name, *sorted(path.name for path in (Path("/sys/class/net") / name / "brif").glob("*"))]
    reports = {}
    for interface in names:
        result = subprocess.run(["ethtool", "-S", interface], capture_output=True, text=True, timeout=5)
        reports[interface] = {"rc": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    return reports


async def _port_counters(con):
    # Offloaded receive drops bypass the netdev's ethtool counters.
    result = await console_python(con, f'''
import json
from pathlib import Path
print(json.dumps({{dev: {{name: (Path('/sys/class/net') / dev / name).read_text()
                         for name in ('mac_rx_stats', 'mac_tx_stats')}}
                  for dev in {(TARGET_LAN_IF, TARGET_WAN_IF)!r}}}))
''')
    return json.loads(result["stdout"])


@pytest_asyncio.fixture
async def rate_path(rig):
    r = rig
    addresses = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show",
                                         "dev", TARGET_WAN_IF))["stdout"])
    external = next(a["local"] for a in addresses[0]["addr_info"] if a["family"] == "inet")
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    existing = json.loads((await command(wan, r.session, "ip", "-j", "route", "show", "exact", external + "/32"))["stdout"])
    assert not existing, ("benchmark requires an unused endpoint host route", existing)
    # Prior MTU-exception proofs can leave endpoint PMTU caches at 1200.
    # A temporary explicit route provides fresh 1500-byte path metrics.
    await command(wan, r.session, "ip", "route", "add", external + "/32", "dev", r.wan_if, "mtu", "1500")
    try:
        yield r
    finally:
        await command(wan, r.session, "ip", "route", "del", external + "/32", "dev", r.wan_if)


@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reverse"])
async def test_flowtable_nat_throughput(rate_path, reverse):
    await _throughput(rate_path, reverse=reverse)


@pytest.mark.parametrize("overload", [False, True], ids=["lossless", "overload"])
@pytest.mark.parametrize("frame", PACKET_FRAMES, ids=["minimum", "small"])
async def test_packet_rate(rate_path, frame, overload):
    """NAT'd UDP directions in hardware at packet rates no CPU path comes
    near, every frame accounted for on the wire at each hop.

    The flows are established both ways first, then their echo stops and
    the LAN VM's kernel packet generator floods the same tuples one way. The
    sender's capacity is the case's own premise, so it is checked rather than
    assumed: the generator's NIC must report the offered rate actually leaving
    it. The receiver's capacity is the WAN host's MAC, which counts what
    arrives on the wire whatever its CPU makes of it, and its driver must
    keep up. Between the two, the DUT's receiving MAC, the flows' hardware
    entries and its transmitting MAC each account for the frames, and its
    kernel sees none of them.

    Lossless, the offered rate sits under the hardware path's ceiling and
    nothing is lost anywhere. Overloaded, the generator offers several times
    the ceiling: the path still forwards at its capacity, and every frame
    past it is refused, and counted, at the receiving MAC."""
    await _packet_rate(rate_path, frame, overload)


async def test_simultaneous_tcp_directions(rate_path):
    """Both directions at once, unpaced. Each saturates its egress port, whose
    offloaded queue is bounded in time and shared out per flow, so neither
    direction's ACKs wait behind the other's data (A313): unbounded, the
    reverse direction got 1.3-2.2 Gbit/s behind a 9 ms queue."""
    await _throughput(rate_path, bidirectional=True)


async def _throughput(rate_path, *, bidirectional=False, reverse=False):
    r = rate_path
    protocol, number = "tcp", "6"
    seconds = 10 if bidirectional else IPERF_SECONDS
    streams = STREAMS
    for address, dev in ((r.lan_ip, TARGET_LAN_IF), (WAN_IP, TARGET_WAN_IF)):
        await command(r.target, r.session, "ip", "route", "replace", address + "/32", "dev", dev, "mtu", "1500")
    addresses = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show",
                                         "dev", TARGET_WAN_IF))["stdout"])
    external = next(a["local"] for a in addresses[0]["addr_info"] if a["family"] == "inet")
    policy = candidate(r)
    policy["scope"] = [{"source": r.lan_ip, "destination": WAN_IP, "protocol": protocol, "destination_port": PORT}]
    nat_table = "ask_nat_rate_test"
    nat = (f"table ip {nat_table} {{ chain postrouting {{ type nat hook postrouting priority 90; "
           f"ip saddr {r.lan_ip} ip daddr {WAN_IP} {protocol} dport {PORT} masquerade; }}; }}")
    server = lan_task = None
    with Console.target(log_path=str(artifact_dir() / "nat-rate-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        assert (await command(r.target, r.session, "nft", "list", "table", "ip", nat_table, check=False))["rc"] != 0
        await command(r.target, r.session, "nft", nat)
        try:
            await apply(con, policy, r=r)
            server = await asyncio.create_subprocess_exec("iperf3", "-s", "-1", "-B", WAN_IP, "-p", str(PORT), "-J",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.sleep(0.2)
            assert server.returncode is None, "dedicated iperf server failed to start"
            script = f'''
import json, subprocess
link = subprocess.check_output(['ethtool', {LAN_NIC!r}], text=True)
stats_before = subprocess.check_output(['ethtool', '-S', {LAN_NIC!r}], text=True)
assert 'Speed: 10000Mb/s' in link and 'Duplex: Full' in link and 'Link detected: yes' in link, link
argv = ['iperf3', '-c', {WAN_IP!r}, '-B', {r.lan_ip!r}, '-p', {str(PORT)!r},
        '-P', {str(streams)!r}, '-t', {str(seconds)!r}, '-O', {str(IPERF_OMIT)!r}, '-J']
argv += {['-Z', '--bidir'] if bidirectional else ['-Z', '-R'] if reverse else ['-Z']!r}
existing = json.loads(subprocess.check_output(['ip', '-j', 'route', 'show', 'exact', {WAN_IP + '/32'!r}], text=True))
assert not existing, existing
subprocess.run(['ip', 'route', 'add', {WAN_IP + '/32'!r}, 'via', {r.lan_gateway!r}, 'dev', {LAN_NIC!r}, 'mtu', '1500'], check=True)
try:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=40)
finally:
    subprocess.run(['ip', 'route', 'del', {WAN_IP + '/32'!r}, 'dev', {LAN_NIC!r}], check=True)
print(json.dumps({{'link': link, 'argv': argv, 'rc': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr,
                  'nic_before': stats_before,
                  'nic_after': subprocess.check_output(['ethtool', '-S', {LAN_NIC!r}], text=True)}}), flush=True)
assert result.returncode == 0
'''
            snmp_before = _udp_counters()
            nic = os.environ.get("ASK_WAN_INJECT_IF", r.wan_if)
            host_nic_before = _nic_counters(nic)
            r.record("nat-rate-dut-ports-before", await _port_counters(con))
            lan_task = asyncio.create_task(lan_run_python(r.lan, script, label="flowtable_nat_rate", timeout=55))
            # Measure each stream's data direction.
            deadline = asyncio.get_running_loop().time() + 8
            while True:
                before = await r.state()
                bulk = [f for f in before["flows"] if f["proto"] == number
                        and f"{WAN_IP}:{PORT}" in (f["src"], f["dst"])
                        and (bidirectional or f["in"] == (TARGET_WAN_IF if reverse else TARGET_LAN_IF))
                        and int(f["bytes"]) > max(1_000_000, 512 * int(f["packets"]))]
                if len(bulk) == streams * (2 if bidirectional else 1):
                    break
                assert not lan_task.done(), "iperf ended before hardware admission"
                assert asyncio.get_running_loop().time() < deadline, before
                await asyncio.sleep(0.25)
            healthy(before)
            keys = set()
            for row in bulk:
                assert row["mtu"] == "1500", row
                if row["in"] == TARGET_LAN_IF:
                    assert row["new_src"].rsplit(":", 1)[0] == external and row["new_dst"] == row["dst"], row
                    assert row["src"].rsplit(":", 1)[0] == r.lan_ip, row
                else:
                    assert (bidirectional or reverse) and row["in"] == TARGET_WAN_IF, row
                    assert row["new_dst"].rsplit(":", 1)[0] == r.lan_ip and row["new_src"] == row["src"], row
                    assert row["dst"].rsplit(":", 1)[0] == external, row
                keys.add((row["in"], number, row["src"], row["dst"]))
                opposite = TARGET_WAN_IF if row["in"] == TARGET_LAN_IF else TARGET_LAN_IF
                keys.add((opposite, number, row["new_dst"], row["new_src"]))
            old = by_key(before)
            assert keys <= old.keys(), before
            for row in bulk:
                opposite = TARGET_WAN_IF if row["in"] == TARGET_LAN_IF else TARGET_LAN_IF
                reply = old[(opposite, number, row["new_dst"], row["new_src"])]
                assert (reply["new_src"], reply["new_dst"]) == (row["dst"], row["src"]), reply
            tx_before, cpu_before = await software_tx(r), await cpu(r)
            await asyncio.sleep(WINDOW_SECONDS)
            cpu_after, tx_after = await cpu(r), await software_tx(r)
            after = await r.state()
            healthy(after)
            new = by_key(after)
            deltas = []
            for key in keys:
                assert new[key]["cookie"] == old[key]["cookie"], (before, after)
                packets = int(new[key]["packets"]) - int(old[key]["packets"])
                size = int(new[key]["bytes"]) - int(old[key]["bytes"])
                assert packets > 1000, (key, packets)
                deltas.append({"key": key, "packets": packets, "bytes": size})
            tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
            measurement = {"before": before, "after": after, "hardware": deltas, "software_tx": tx,
                           "cpu": cpu_delta(cpu_before, cpu_after)}
            r.record("nat-rate-hardware", measurement)
            assert all(0 <= count <= 512 for count in tx.values()), tx
            result = await lan_task
            r.record("nat-rate-client-console", {"rc": result.rc, "stdout": result.stdout})
            assert result.rc == 0, result.stdout
            client = json.loads(result.stdout.strip())
            client_json = json.loads(client["stdout"])
            stdout, stderr = await asyncio.wait_for(server.communicate(), 10)
            server_json = json.loads(stdout)
            r.record("nat-rate-iperf", {"client": client_json, "server": server_json,
                                        "stderr": stderr.decode(), "lan_link": client["link"],
                                        "lan_nic": {key: client[key] for key in ("nic_before", "nic_after")},
                                        "host_nic": {"before": host_nic_before, "after": _nic_counters(nic)},
                                        "host_udp_delta": {key: value - snmp_before[key]
                                                           for key, value in _udp_counters().items()}})
            assert client["rc"] == server.returncode == 0 and "error" not in client_json and "error" not in server_json
            received = (client_json if reverse else server_json)["end"]["sum_received"]
            assert received["bytes"] > 0 and received["seconds"] >= seconds - 0.1, received
            minimum = 8e9 if bidirectional else float(os.environ.get("ASK_FLOWTABLE_MIN_GBPS", "9")) * 1e9
            assert received["bits_per_second"] >= minimum, received
            if bidirectional:
                # The forward data and the reverse ACKs share the WAN
                # port, and both directions' tail drops land somewhere.
                # Eleven runs measured 5.5-7.9 Gbit/s (mean 6.9), the
                # low end with the hosts' senders, not the DUT, short
                # of work; the unbounded queue this guards against
                # (A313) gave 1.3-2.2.
                reverse_result = client_json["end"]["sum_received_bidir_reverse"]
                assert reverse_result["bits_per_second"] >= 5e9, reverse_result
        finally:
            try:
                if lan_task:
                    result = await lan_task
                    r.record("nat-rate-client-console", {"rc": result.rc, "stdout": result.stdout})
            finally:
                try:
                    if server and server.returncode is None:
                        server.terminate()
                        await asyncio.wait_for(server.communicate(), 5)
                finally:
                    try:
                        try:
                            r.record("nat-rate-dut-ports-after", await _port_counters(con))
                        finally:
                            await stop(con)
                    finally:
                        await command(r.target, r.session, "nft", "delete", "table", "ip", nat_table)
                        await console_command(con, "rm", "-f", CONFIG)
                        await command(r.target, r.session, "conntrack", "-D", "-p", protocol, "--orig-src", r.lan_ip,
                            "--orig-dst", WAN_IP, "--dport", str(PORT), check=False)
            final = await r.state()
            assert final["installs"] == final["deletes"] and final["fatal"] == final["quarantine"] == 0, final
            assert final["errors"] == HEALTH_BASELINE["errors"], (final, HEALTH_BASELINE)
            r.record("nat-rate-cleanup", final)


class _Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


def _mac_stats(text):
    """An mEMAC statistics dump by register name, each 64-bit value read
    from its _l/_u halves."""
    halves = {}
    for value, name, half in re.findall(r"0x([0-9a-fA-F]{8})\s+(\w+?)_([lu])\s*$", text, re.M):
        halves.setdefault(name, {})[half] = int(value, 16)
    return {name: (h.get("u", 0) << 32) | h.get("l", 0) for name, h in halves.items()}


async def _dut_hops(r):
    """What the DUT's LAN MAC received and dropped, what the FMan port behind
    it took and discarded, what its WAN MAC sent, and what its kernel
    received on the LAN port and sent on both."""
    lan = _mac_stats(await read(r.target, r.session, f"/sys/class/net/{TARGET_LAN_IF}/mac_rx_stats"))
    wan = _mac_stats(await read(r.target, r.session, f"/sys/class/net/{TARGET_WAN_IF}/mac_tx_stats"))
    port = {name: int((await read(r.target, r.session,
                                  f"{FMAN}/{LAN_RX_PORT}.port/statistics/{name}")).split()[-1])
            for name in PORT_STATISTICS}
    return {"lan_rx": {k: lan[k] for k in ("rpkt", "rfrm", "rdrp", "rerr", "rovr", "rfcs")},
            "lan_port": port,
            "wan_tx": {k: wan[k] for k in ("tpkt", "tfrm", "terr")},
            "kernel_rx": await kernel_rx_packets(r.target, r.session, TARGET_LAN_IF),
            "kernel_tx": await software_tx(r)}


def _host_nic(name):
    """The WAN host NIC's MAC-level receive counters: what arrived on the
    wire, whatever this host's CPU then made of it."""
    out = subprocess.run(["ethtool", "-S", name], capture_output=True, text=True, timeout=5, check=True).stdout
    stats = {k.strip(): int(v) for k, v in (line.split(":", 1) for line in out.splitlines()[1:])
             if v.strip().isdigit()}
    return {k: stats[k] for k in ("rx_packets_phy", "rx_packets", "rx_dropped") if k in stats}


def _pktgen(r, frame, threads, count, ratep):
    """The LAN VM's script: `threads` pktgen threads, one per transmit queue,
    each sending `count` frames of its own flow, at `ratep` frames a second
    or as fast as it can, and what its NIC says left it."""
    # pktgen paces a burst, not a frame, so a paced thread sends one at a time.
    commands = [f"count {count}", "clone_skb 1000", f"pkt_size {frame - 4}",
                *([f"ratep {ratep}", "burst 1"] if ratep else ["burst 32"]), f"dst_mac {r.dut_lan_mac}",
                f"src_min {r.lan_ip}", f"src_max {r.lan_ip}", f"dst_min {WAN_IP}", f"dst_max {WAN_IP}",
                f"udp_dst_min {PACKET_PORT}", f"udp_dst_max {PACKET_PORT}", "flag UDPCSUM"]
    return f'''
import json, subprocess, time
from pathlib import Path
root = Path("/proc/net/pktgen")
subprocess.run(["modprobe", "pktgen"], check=True)
def pg(path, cmd):
    (root / path).write_text(cmd + "\\n")
def nic():
    out = subprocess.check_output(["ethtool", "-S", {LAN_NIC!r}], text=True)
    stats = {{k.strip(): int(v) for k, v in (l.split(":", 1) for l in out.splitlines()[1:]) if v.strip().isdigit()}}
    return {{k: stats[k] for k in ("tx_pkts_nic", "tx_packets", "tx_dropped")}}
threads = {threads}
devices = [f"{LAN_NIC}@{{t}}" for t in range(threads)]
try:
    for t, dev in enumerate(devices):
        pg(f"kpktgend_{{t}}", "rem_device_all")
        pg(f"kpktgend_{{t}}", f"add_device {{dev}}")
        for cmd in {commands!r} + [f"queue_map_min {{t}}", f"queue_map_max {{t}}",
                                   f"udp_src_min {{{PACKET_SPORT} + t}}", f"udp_src_max {{{PACKET_SPORT} + t}}"]:
            pg(dev, cmd)
    before = nic()
    start = time.monotonic()
    pg("pgctrl", "start")
    elapsed = time.monotonic() - start
    after = nic()
    results = {{dev: (root / dev).read_text().split("Result:")[1].strip().splitlines()[0] for dev in devices}}
finally:
    for t in range(threads):
        pg(f"kpktgend_{{t}}", "rem_device_all")
print(json.dumps({{"elapsed": elapsed, "results": results,
                  "nic": {{k: after[k] - before[k] for k in before}}}}))
'''


async def _packet_rate(r, frame, overload):
    threads = PACKET_THREADS if overload else 1
    offered = None if overload else PACKET_LOSSLESS[frame]
    ratep = int(offered / threads) if offered else None
    # Overloaded, the generator runs as fast as it can; long enough either
    # way that the DUT's queues filling and draining is a rounding error.
    count = int((ratep or PACKET_SENDER[frame] / threads) * PACKET_SECONDS)
    sports = [PACKET_SPORT + t for t in range(threads)]
    wire = wire_interface(r)
    for address, dev in ((r.lan_ip, TARGET_LAN_IF), (WAN_IP, TARGET_WAN_IF)):
        await command(r.target, r.session, "ip", "route", "replace", address + "/32", "dev", dev, "mtu", "1500")
    policy = candidate(r)
    policy["scope"] = [{"source": r.lan_ip, "destination": WAN_IP, "protocol": "udp",
                        "destination_port": PACKET_PORT}]
    nat_table = "ask_nat_packet_rate"
    nat = (f"table ip {nat_table} {{ chain postrouting {{ type nat hook postrouting priority 90; "
           f"ip saddr {r.lan_ip} ip daddr {WAN_IP} udp dport {PACKET_PORT} masquerade; }}; }}")
    # The flood stops at this host's port, before its stack, which has no
    # use for it.
    sink = "ask_packet_rate_sink"
    sink_rules = (f'table netdev {sink} {{ chain ingress {{ type filter hook ingress device "{wire}" '
                  f'priority -500; policy accept; ip daddr {WAN_IP} udp dport {PACKET_PORT} counter drop; }}; }}')
    route = ["ip", "route", "add", WAN_IP + "/32", "via", r.lan_gateway, "dev", LAN_NIC, "mtu", "1500"]
    unroute = ["ip", "route", "del", WAN_IP + "/32", "dev", LAN_NIC]
    warm = f'''
import socket
echoed = {{}}
for sport in {sports!r}:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(({r.lan_ip!r}, sport))
    s.settimeout(0.3)
    echoed[sport] = 0
    for _ in range(4):
        s.sendto(b"warm", ({WAN_IP!r}, {PACKET_PORT}))
        try:
            s.recvfrom(64)
            echoed[sport] += 1
        except socket.timeout:
            pass
    s.close()
print(echoed)
'''
    record = {"frame": frame, "overload": overload, "offered_target": offered,
              "count_per_thread": count, "wire": wire}
    transport = None
    sinking = routed = False
    with Console.target(log_path=str(artifact_dir() / "packet-rate-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        assert (await command(r.target, r.session, "nft", "list", "table", "ip", nat_table, check=False))["rc"] != 0
        await command(r.target, r.session, "nft", nat)
        try:
            await apply(con, policy, r=r)
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                _Echo, local_addr=(WAN_IP, PACKET_PORT))
            result = await lan_run_python(r.lan, f"import subprocess\nsubprocess.run({route!r}, check=True)\n",
                                          label="packet_rate_route", timeout=15)
            assert result.rc == 0, result.stdout
            routed = True

            def directions(state):
                """Each flow's two entries, by (ingress, LAN source port)."""
                rows = {}
                for f in state["flows"]:
                    if f["proto"] != "17":
                        continue
                    for sport in sports:
                        lan = f"{r.lan_ip}:{sport}"
                        if ((f["in"] == TARGET_LAN_IF and f["src"] == lan
                             and f["dst"] == f"{WAN_IP}:{PACKET_PORT}")
                                or (f["in"] == TARGET_WAN_IF and f["src"] == f"{WAN_IP}:{PACKET_PORT}"
                                    and f["new_dst"] == lan)):
                            rows[(f["in"], sport)] = f
                return rows

            loop = asyncio.get_running_loop()
            deadline = loop.time() + 15
            while True:
                result = await lan_run_python(r.lan, warm, label="packet_rate_warm", timeout=15)
                assert result.rc == 0, result.stdout
                before = await r.state()
                if len(directions(before)) == 2 * len(sports):
                    break
                assert loop.time() < deadline, ("the flows did not enter hardware", result.stdout, before)
                await asyncio.sleep(0.5)
            # One way from here: an echo would answer every flooded frame.
            transport.close()
            transport = None
            healthy(before)
            entries = {sport: directions(before)[(TARGET_LAN_IF, sport)] for sport in sports}
            record["entries"] = entries
            subprocess.run(["nft", sink_rules], check=True, timeout=10)
            sinking = True

            hops_before, host_before, cpu_before = await _dut_hops(r), _host_nic(wire), await cpu(r)
            result = await lan_run_python(r.lan, _pktgen(r, frame, threads, count, ratep),
                                          label="packet_rate_pktgen", timeout=PACKET_SECONDS * 4 + 30)
            assert result.rc == 0, result.stdout
            sender = json.loads(result.stdout.strip().splitlines()[-1])
            # The hardware's counters reach the adapter on its statistics
            # pass, once a second.
            await asyncio.sleep(2)
            after = await r.state()
            hops_after, host_after, cpu_after = await _dut_hops(r), _host_nic(wire), await cpu(r)
            sunk = subprocess.run(["nft", "-j", "list", "table", "netdev", sink],
                                  capture_output=True, text=True, timeout=10, check=True).stdout
            moved = directions(after)
            record.update({
                "sender": sender, "before": before, "after": after,
                "hops": {side: {k: v for k, v in hops.items()} for side, hops in
                         (("before", hops_before), ("after", hops_after))},
                "host": {k: host_after[k] - host_before[k] for k in host_before},
                "sink": [rule["rule"]["expr"] for rule in json.loads(sunk)["nftables"] if "rule" in rule],
                "cpu": cpu_delta(cpu_before, cpu_after)})

            sent = sender["nic"]["tx_pkts_nic"]
            rate = sent / sender["elapsed"]
            assert all((TARGET_LAN_IF, sport) in moved and moved[(TARGET_LAN_IF, sport)]["cookie"]
                       == entries[sport]["cookie"] for sport in sports), ("an entry was replaced", entries, moved)
            matched = sum(int(moved[(TARGET_LAN_IF, sport)]["packets"]) - int(entries[sport]["packets"])
                          for sport in sports)
            change = {side: {k: hops_after[side][k] - hops_before[side][k] for k in hops_before[side]}
                      for side in ("lan_rx", "lan_port", "wan_tx", "kernel_tx")}
            record["account"] = account = {
                "sent": sent, "offered_pps": rate, "forwarded_pps": matched / sender["elapsed"],
                **change, "matched": matched, "kernel_rx": hops_after["kernel_rx"] - hops_before["kernel_rx"],
                "host": record["host"]}
            lan_rx, port, wan_tx = change["lan_rx"], change["lan_port"], change["wan_tx"]
            # The sender's capacity is the premise: a generator that fell
            # short offered less than the case is about. Overloaded, it has
            # to offer well past what the DUT forwards.
            assert sent >= threads * count, ("the LAN VM did not send every frame", sender)
            if overload:
                assert rate >= 2 * PACKET_CAPACITY[frame], ("the LAN VM did not overload the port", account)
            else:
                assert rate >= offered * PACKET_PACED, ("the LAN VM did not offer the rate", account)
            # Every frame the FMan port enqueued was matched, and every one
            # matched left the WAN MAC; the WAN host's MAC received them all
            # and its driver kept up, so its capacity is not what was
            # measured.
            assert lan_rx["rpkt"] >= sent * (1 - PACKET_LOSS), ("the LAN MAC missed frames", account)
            assert matched >= port["port_enq_total"] * (1 - PACKET_LOSS), \
                ("enqueued frames went unmatched", account)
            assert wan_tx["tpkt"] >= matched * (1 - PACKET_LOSS) and wan_tx["terr"] == 0, \
                ("matched frames did not leave the WAN MAC", account)
            assert record["host"]["rx_packets_phy"] >= wan_tx["tpkt"] * (1 - PACKET_LOSS), \
                ("the WAN host's MAC did not receive every frame", account)
            assert record["host"].get("rx_dropped", 0) == 0, ("the WAN host's driver fell behind", account)
            assert all(0 <= v <= 512 for v in change["kernel_tx"].values()), \
                ("the DUT's kernel forwarded the flood", account)
            if overload:
                # What the hardware path sustains, and every frame past it
                # counted where it was refused: whole at the MAC (RDRP less
                # the cut-short RERR ones it passes on), or by the FMan
                # port's frame filter, which takes those cut short and
                # anything else that arrives in error.
                assert matched / sender["elapsed"] >= PACKET_CAPACITY[frame], ("below capacity", account)
                assert abs(lan_rx["rpkt"] - lan_rx["rfrm"] - lan_rx["rdrp"]) <= PACKET_NOISE, \
                    ("uncounted MAC drops", account)
                assert abs(port["port_frame"] - lan_rx["rfrm"] - lan_rx["rerr"]) <= PACKET_NOISE, \
                    ("the port lost frames", account)
                assert abs(port["port_frame"] - port["port_enq_total"] - port["port_rx_filter_frame"]
                           - port["port_discard_frame"]) <= PACKET_NOISE, ("uncounted port drops", account)
            else:
                assert lan_rx["rdrp"] == lan_rx["rerr"] == lan_rx["rovr"] == 0, ("the LAN MAC dropped", account)
                assert port["port_discard_frame"] == port["port_rx_bad_frame"] == 0, ("the port discarded", account)
                assert matched >= sent * (1 - PACKET_LOSS), ("frames were lost", account)
            assert after["invalidated"] == after["fatal"] == after["quarantine"] == 0, after
            assert after["errors"] == before["errors"], (before, after)
        finally:
            r.record(f"packet-rate-{frame}-{'overload' if overload else 'lossless'}", record)
            try:
                if transport:
                    transport.close()
                if sinking:
                    subprocess.run(["nft", "delete", "table", "netdev", sink], check=False, timeout=10)
                if routed:
                    await lan_run_python(r.lan, f"import subprocess\nsubprocess.run({unroute!r}, check=True)\n",
                                         label="packet_rate_unroute", timeout=15)
            finally:
                try:
                    await stop(con)
                finally:
                    await command(r.target, r.session, "nft", "delete", "table", "ip", nat_table)
                    await console_command(con, "rm", "-f", CONFIG)
                    await command(r.target, r.session, "conntrack", "-D", "-p", "udp", "--orig-src", r.lan_ip,
                                  "--orig-dst", WAN_IP, "--dport", str(PACKET_PORT), check=False)
        final = await r.wait(lambda s: not s["entries"])
        assert final["installs"] == final["deletes"] and final["fatal"] == final["quarantine"] == 0, final
        assert final["errors"] == HEALTH_BASELINE["errors"], (final, HEALTH_BASELINE)

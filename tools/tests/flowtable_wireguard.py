"""TCP through WireGuard tunnels the offload carries: LAN VM -> DUT -> tunnel
-> WAN host, over one, two and four tunnels, each way and both at once.

WireGuard's crypto runs on the DUT's CPUs, so these rates are CPU-bound; cdx
takes away the rest of the CPU's work. A tunnel's uploads are sealed where
they lie and sent from the WAN port, its downloads opened where they lie and
forwarded to the LAN port, neither through the kernel's stack or its
transmit path (cdx/cdx_wg.c). /proc/cdx_wireguard counts both per device:
the proof here is that they account for every frame of each tunnel, both
ways, as its end on this host counts them, but each connection's first few
hundred: those its flow was not yet admitted for, the only ones the
kernel transmits.

On the KASAN image (2026-11-10, either cpufreq governor, outer UDP tracked
or not) every shape moved 678-1859 Mbit/s: one tunnel ~0.7 Gbit/s each way,
more tunnels either that or about twice it, as their receiving CPUs coincide
or not. The same image's software path moved 39-77 Mbit/s through one
tunnel. FLOOR sits a quarter below the lowest sample and six times above the
software path, and is met by the best of up to SAMPLES runs; the proof must
hold in every run.

A run saturates the DUT's CPUs, and its console answered only once a run had
ended, so every DUT counter is read at idle, before and after a run.
"""
import asyncio
import ipaddress
import json
import os
import subprocess
import tempfile

import pytest
import pytest_asyncio

from _flowtable_rig import TABLE, WAN_IP, Rig, command, console_command, read, release_latch, \
    stop_boot_daemon
from _flowtable_tcp import software_tx
from _throughput import SOFTWARE_TX
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run, lan_run_python
from ask_orch.artifacts import artifact_dir
from ask_orch.uart import Console

# Tunnel i: WireGuard on port LISTEN + i at both ends, iperf3 on PORT + i.
LISTEN, PORT = 51840, 49060
TUNNELS = 4
DUT_KEY = "/tmp/ask_wg.key"
FLOOR = float(os.environ.get("ASK_WIREGUARD_MIN_GBPS", "0.5")) * 1e9
# A tunnel's share of a sample each way it is driven: it moved, rather than
# stalled behind the others (30 Mbit/s the least measured). A direction this
# slow carries more frames than PREADMISSION lets escape cdx, so it cannot
# have stayed in software.
TUNNEL_FLOOR = 20e6
SECONDS, RAMP = 10, 3
SAMPLES = 3
# Frames per connection that may escape cdx: its first ones, before its flow
# is admitted, which go through the kernel (480 the most measured, two
# tunnels' upload). Every other frame the WAN host's end of a tunnel received
# was sealed, and every one it sent forwarded, data and acknowledgements
# alike, whichever way the data goes.
PREADMISSION = 1000


def inner(i, host):
    """Tunnel i's inner /24: the DUT at .1, the WAN host at .2. PPPoE's
    session already claims 10.98.0.0/24 (_flowtable_pppoe.py)."""
    return f"10.97.{i}.{host}"


def host(*argv, check=True):
    """A command on this host, the WAN host, as root: the WAN agent does not
    run `wg`."""
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert not check or result.returncode == 0, (argv, result.stdout, result.stderr)
    return result


async def on_console(*argv, check=True):
    """A shell command on the DUT the agent does not run (`wg`), over its
    console; at idle, so the console answers."""
    with Console.target(log_path=str(artifact_dir() / "wireguard-console.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        return await console_command(con, *argv, check=check, timeout=45)


async def wg_counters(r):
    """/proc/cdx_wireguard by device: `name id N [gone] key value ...`."""
    rows = {}
    for line in (await read(r.target, r.session, "/proc/cdx_wireguard")).splitlines():
        name, *words = line.split()
        words = [word for word in words if word != "gone"]
        rows[name] = {key: int(value) for key, value in zip(words[::2], words[1::2])}
    return rows


def wan_frames(r):
    """The frames each tunnel's end on this host received and sent."""
    def count(dev, name):
        with open(f"/sys/class/net/{dev}/statistics/{name}_packets") as stream:
            return int(stream.read())
    return {f"wgt{i}": {name: count(f"wgt{i}", name) for name in ("rx", "tx")} for i in range(r.tunnels)}


async def released(r):
    """What is left of any WireGuard device once the adapter, and then cdx,
    have given back every one they hold (cdx_wg_netdev_event()). The adapter
    holds every running one, whether or not a flowtable lists it."""
    await r.wait(lambda s: s["wg_devs"] == 0)
    for _ in range(50):
        if not (left := await wg_counters(r)):
            return left
        await asyncio.sleep(0.2)
    return left


async def edge(r):
    return {"wg": await wg_counters(r), "wan": wan_frames(r), "tx": await software_tx(r),
            "state": await r.state()}


def received(report):
    """What the end that wrote `report` received: bits per second over its
    intervals from RAMP on, and bytes over the whole run. A bidirectional
    run's report carries one received sum per interval as well."""
    sums = [s for interval in report["intervals"]
            for s in (interval.get("sum"), interval.get("sum_bidir_reverse")) if s and not s["sender"]]
    settled = [s for s in sums if s["start"] >= RAMP - 0.01]
    seconds = sum(s["seconds"] for s in settled)
    return {"bits_per_second": sum(s["bytes"] for s in settled) * 8 / seconds if seconds else 0.0,
            "bytes": sum(s["bytes"] for s in sums)}


@pytest_asyncio.fixture
async def wg_rig(target_agent, aiohttp_session, lan, splat_window, request):
    """`request.param` tunnels between the DUT and this host, each offered to
    the offload. Teardown reverses only what came up, then proves the adapter
    and cdx gave every device back."""
    r = Rig()
    r.target, r.session, r.lan, r.tunnels = target_agent, aiohttp_session, lan, request.param
    await stop_boot_daemon()
    # Whatever a killed run left goes first, of any tunnel count: on the DUT
    # before the clean slate is read, since the adapter holds a leftover
    # device that is up.
    for i in range(TUNNELS):
        await command(r.target, r.session, "ip", "link", "del", f"wgt{i}", check=False)
    left = await released(r)
    assert not left, ("cdx kept WireGuard devices", left)
    initial = await release_latch(r)
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    assert initial["wg_devs"] == 0, initial
    dut, wan, lan_undo = [], [], []
    try:
        dut_lan = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev",
                                            TARGET_LAN_IF))["stdout"])[0]["addr_info"][0]
        dut_lan = ipaddress.ip_interface(f"{dut_lan['local']}/{dut_lan['prefixlen']}")
        dut_wan = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev",
                                            TARGET_WAN_IF))["stdout"])[0]["addr_info"][0]["local"]
        link = json.loads((await lan_run(lan, f"ip -j link show dev {LAN_NIC}")).stdout)[0]
        # Each tunnel's own LAN VM address: the WAN host routes it back
        # through that tunnel and no other, and the LAN VM's own address
        # keeps the route other fixtures give it.
        r.sources = [str(dut_lan.network[20 + i]) for i in range(r.tunnels)]
        # The WAN host and the LAN VM outlive DUT boots. An orphaned server
        # would hold its port once the address it bound comes back.
        host("pkill", "-f", r"^iperf3 -s -1 -B 10\.97\.", check=False)
        for i in range(TUNNELS):
            host("ip", "link", "del", f"wgt{i}", check=False)
            await lan_run(lan, f"ip addr del {dut_lan.network[20 + i]}/32 dev {LAN_NIC} 2>/dev/null; true")
        await lan_run(lan, f"ip route del 10.97.0.0/16 dev {LAN_NIC} 2>/dev/null; true")
        # The seal writes the WAN host's MAC from the DUT's neighbour entry
        # and declines without a valid one: pinned for the run, as the rig
        # fixture pins it, and put back after.
        wan_if = next(i["ifname"] for i in json.loads(host("ip", "-j", "-4", "addr").stdout)
                      if any(a.get("local") == WAN_IP for a in i["addr_info"]))
        with open(f"/sys/class/net/{wan_if}/address") as stream:
            wan_mac = stream.read().strip()
        old = json.loads((await command(r.target, r.session, "ip", "-j", "neigh", "show", "to", WAN_IP,
                                        "dev", TARGET_WAN_IF))["stdout"])
        restore = ["ip", "neigh", "del", WAN_IP, "dev", TARGET_WAN_IF]
        if old and old[0].get("lladdr"):
            restore = ["ip", "neigh", "replace", WAN_IP, "lladdr", old[0]["lladdr"], "nud",
                       "permanent" if "PERMANENT" in old[0]["state"] else "stale", "dev", TARGET_WAN_IF]
        await command(r.target, r.session, "ip", "neigh", "replace", WAN_IP, "lladdr", wan_mac,
                      "nud", "permanent", "dev", TARGET_WAN_IF)
        dut.append(restore)
        dut_key, wan_key = (host("wg", "genkey").stdout.strip() for _ in range(2))
        dut_pub, wan_pub = (subprocess.run(["wg", "pubkey"], input=key, capture_output=True, text=True,
                                           check=True).stdout.strip() for key in (dut_key, wan_key))
        with tempfile.NamedTemporaryFile("w", suffix=".key") as keyfile:
            keyfile.write(wan_key + "\n")
            keyfile.flush()
            for i, source in enumerate(r.sources):
                dev = f"wgt{i}"
                await command(r.target, r.session, "ip", "link", "add", dev, "type", "wireguard")
                dut.append(["ip", "link", "del", dev])
                await command(r.target, r.session, "ip", "addr", "add", f"{inner(i, 1)}/24", "dev", dev)
                await command(r.target, r.session, "ip", "link", "set", dev, "up")
                # Pinned, so no admission waits on ARP.
                await command(r.target, r.session, "ip", "neigh", "replace", source, "lladdr",
                              link["address"], "nud", "permanent", "dev", TARGET_LAN_IF)
                dut.append(["ip", "neigh", "del", source, "dev", TARGET_LAN_IF])
                host("ip", "link", "add", dev, "type", "wireguard")
                wan.append(["ip", "link", "del", dev])
                host("wg", "set", dev, "listen-port", str(LISTEN + i), "private-key", keyfile.name,
                     "peer", dut_pub, "endpoint", f"{dut_wan}:{LISTEN + i}",
                     "allowed-ips", f"{inner(i, 1)}/32,{source}/32")
                host("ip", "addr", "add", f"{inner(i, 2)}/24", "dev", dev)
                host("ip", "link", "set", dev, "up")
                host("ip", "route", "replace", f"{source}/32", "dev", dev)
                result = await lan_run(lan, f"ip addr add {source}/32 dev {LAN_NIC}")
                assert result.rc == 0, result.stdout
                lan_undo.append(f"ip addr del {source}/32 dev {LAN_NIC}")
        assert (await r.target.fs_write(r.session, DUT_KEY, dut_key + "\n"))["errno"] == 0
        configure = " && ".join(
            f"wg set wgt{i} listen-port {LISTEN + i} private-key {DUT_KEY} peer {wan_pub} "
            f"endpoint {WAN_IP}:{LISTEN + i} allowed-ips {inner(i, 2)}/32" for i in range(r.tunnels))
        # The key goes whether or not every device took it.
        await on_console("sh", "-c", f"{configure}; rc=$?; rm -f {DUT_KEY}; exit $rc")
        route = f"10.97.0.0/16 via {dut_lan.ip} dev {LAN_NIC}"
        result = await lan_run(lan, f"ip route replace {route}")
        assert result.rc == 0, result.stdout
        lan_undo.append(f"ip route del {route}")
        devices = ", ".join([TARGET_LAN_IF, TARGET_WAN_IF, *(f"wgt{i}" for i in range(r.tunnels))])
        await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {devices} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.sources[0]}-{r.sources[-1]} ip daddr 10.97.0.0/16 meta l4proto tcp flow add @fast
 }}
}}''')
        await r.wait(lambda s: s["bindings"] == 2 and s["wg_devs"] == r.tunnels)
        # The first packet of each tunnel starts its handshake.
        pings = " && ".join(f"ping -c 2 -W 2 -I {source} {inner(i, 2)} >/dev/null"
                            for i, source in enumerate(r.sources))
        for _ in range(15):
            if "rc=0" in (await lan_run(lan, f"{pings}; echo rc=$?", 30)).stdout:
                break
            await asyncio.sleep(1)
        else:
            pytest.fail(f"a tunnel did not pass the LAN VM's pings: {host('wg', 'show').stdout}")
        r.record("wireguard-fixture", {"tunnels": r.tunnels, "sources": r.sources, "initial": initial,
                                       "counters": await wg_counters(r)})
        yield r
    finally:
        failures = []

        async def undo(step, failed):
            # Every step is tried whatever the one before did: a DUT that
            # went away mid-run must not keep the hosts' state.
            try:
                result = step()
                if asyncio.iscoroutine(result):
                    result = await result
                if failed(result):
                    failures.append(result)
            except (Exception, pytest.fail.Exception) as error:
                failures.append(repr(error))

        await undo(r.delete_table, lambda result: False)
        for argv in reversed(dut):
            await undo(lambda: command(r.target, r.session, *argv, check=False), lambda res: res["rc"])
        for argv in reversed(wan):
            await undo(lambda: host(*argv, check=False), lambda res: res.returncode)
        for cmd in reversed(lan_undo):
            await undo(lambda: lan_run(lan, cmd), lambda res: res.rc)
        # Nothing of any tunnel stays registered.
        await undo(lambda: released(r), lambda left: left)
        assert not failures, ("fixture restoration failed", failures)


async def _sample(r, direction, record):
    """One run of every tunnel at once into `record`, which keeps what it
    collected when it fails. Returns the rate over every tunnel and direction."""
    streams = max(2, 4 // r.tunnels)
    flag = {"upload": [], "download": ["-R"], "bidir": ["--bidir"]}[direction]
    servers = []
    try:
        for i in range(r.tunnels):
            servers.append(await asyncio.create_subprocess_exec(
                "iperf3", "-s", "-1", "-B", inner(i, 2), "-p", str(PORT + i), "-J",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE))
        await asyncio.sleep(0.3)
        assert all(server.returncode is None for server in servers), "an endpoint iperf3 did not start"
        record["before"] = before = await edge(r)
        record["argv"] = argvs = [
            ["iperf3", "-c", inner(i, 2), "-B", source, "-p", str(PORT + i), "-P", str(streams),
             "-t", str(SECONDS), "-Z", "-J", *flag] for i, source in enumerate(r.sources)]
        script = f'''
import json, subprocess, tempfile
runs = []
for argv in {argvs!r}:
    out, err = tempfile.TemporaryFile("w+"), tempfile.TemporaryFile("w+")
    runs.append((subprocess.Popen(argv, stdout=out, stderr=err, text=True), out, err))
reports = []
for run, out, err in runs:
    rc = run.wait(timeout={SECONDS + 30})
    out.seek(0)
    err.seek(0)
    reports.append({{"rc": rc, "stdout": out.read(), "stderr": err.read()}})
print(json.dumps(reports))
'''
        result = await lan_run_python(r.lan, script, label="wireguard", timeout=SECONDS + 60)
        assert result.rc == 0, result.stdout
        record["clients"] = [{**client, "report": json.loads(client["stdout"]) if client["stdout"].strip()
                              else {}} for client in json.loads(result.stdout.strip().splitlines()[-1])]
        record["servers"] = []
        for server in servers:
            try:
                stdout, stderr = await asyncio.wait_for(server.communicate(), 15)
            except TimeoutError:
                # Its client never connected, or never finished.
                record["servers"].append({"rc": None, "stderr": "no report 15 s after the clients", "report": {}})
                continue
            record["servers"].append({"rc": server.returncode, "stderr": stderr.decode(),
                                      "report": json.loads(stdout) if stdout.strip() else {}})
        record["after"] = after = await edge(r)
    finally:
        for server in servers:
            if server.returncode is None:
                server.kill()
                await server.wait()
    for end in record["clients"] + record["servers"]:
        assert end["rc"] == 0 and end["report"] and "error" not in end["report"], end
    total = 0.0
    # Each stream, each way iperf3 opens them, and its control connection.
    allowance = PREADMISSION * (streams * (2 if direction == "bidir" else 1) + 1)
    record["tunnels"] = []
    for i in range(r.tunnels):
        dev = f"wgt{i}"
        up, down = received(record["servers"][i]["report"]), received(record["clients"][i]["report"])
        delta = {key: after["wg"][dev][key] - before["wg"][dev][key]
                 for key in ("sealed", "slow", "tx_fail", "delivered", "forwarded", "opened", "to_stack",
                             "dropped")}
        wan = {name: after["wan"][dev][name] - before["wan"][dev][name] for name in ("rx", "tx")}
        record["tunnels"].append({"device": dev, "upload": up, "download": down, "counters": delta,
                                  "wan_frames": wan})
        for flow, wanted in ((up, direction != "download"), (down, direction != "upload")):
            if wanted:
                assert flow["bits_per_second"] >= TUNNEL_FLOOR, (dev, flow)
        assert wan["rx"] - delta["sealed"] <= allowance, \
            (f"{dev}'s frames out were not sealed by cdx", allowance, wan, delta)
        assert wan["tx"] - delta["forwarded"] <= allowance, \
            (f"{dev}'s frames in were not forwarded by cdx", allowance, wan, delta)
        assert delta["slow"] <= SOFTWARE_TX and delta["to_stack"] <= SOFTWARE_TX, (dev, delta)
        assert delta["tx_fail"] == delta["dropped"] == 0, (dev, delta)
        total += up["bits_per_second"] + down["bits_per_second"]
    # What the kernel transmits is those same first frames, and the tunnels'
    # handshakes.
    record["software_tx"] = tx = {dev: after["tx"][dev] - before["tx"][dev] for dev in before["tx"]}
    assert all(0 <= count <= SOFTWARE_TX + allowance * r.tunnels for count in tx.values()), \
        ("the DUT's kernel transmitted the tunnels' traffic", tx, allowance)
    for state in (before["state"], after["state"]):
        assert state["invalidated"] == state["fatal"] == state["quarantine"] == 0, state
        assert state["wg_devs"] == r.tunnels, state
    assert after["state"]["errors"] == before["state"]["errors"], "the adapter counted an error"
    return total


@pytest.mark.parametrize("direction", ["upload", "download", "bidir"])
@pytest.mark.parametrize("wg_rig", [1, 2, 4], ids=["1T", "2T", "4T"], indirect=True)
async def test_rate(wg_rig, direction):
    r = wg_rig
    samples = []
    for attempt in range(SAMPLES):
        record = {}
        try:
            samples.append(await _sample(r, direction, record))
        finally:
            r.record(f"wireguard-{r.tunnels}T-{direction}-{attempt}", record)
        if samples[-1] >= FLOOR:
            break
    r.record(f"wireguard-{r.tunnels}T-{direction}", {"floor": FLOOR, "samples": samples})
    assert max(samples) >= FLOOR, (samples, FLOOR)

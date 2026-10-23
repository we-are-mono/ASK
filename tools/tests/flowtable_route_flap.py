"""Change a route thousands of offloaded flows depend on, again and again, while
they carry traffic, and run the platform's health probe throughout (A402, A411).

On the OpenWrt image, ~6,000 offloaded flows behind a /32 route changed every
5 s, eight TCP streams filling the WAN among them, kept `ask-flowtable
health`'s read of the adapter's /proc past its 5 s deadline, and three misses
in a row rebooted the board. Each change retires every flow behind the route,
the bulk streams forward in software until readmitted, and the flows' next
packets offer them again: the read waits its turn behind hundreds of Linux's
offers and counter reads for CDX's transaction, each holder on a CPU the
streams' softirq fills running at a few percent of it. A busy transaction is
not a dead one, and the probe passes while it changes hands. This puts
CONNECTIONS connections and BULK_STREAMS iperf3 streams behind WAN_IP/32,
replaces the route every FLAP_SECONDS for FLAPS changes with traffic on every
connection, and runs the probe every PROBE_INTERVAL.
"""
from __future__ import annotations

import asyncio
import json
import os
import resource
import socket
import time

from ask_orch.uart import Console
from _flowtable_capacity import BASE, batch, socket_drops, start, wait_entries
from _flowtable_connections import peer
from _flowtable_qos import iperf, lan_start, lan_stop
from _flowtable_rig import DPORT, TABLE, WAN_IP, command, console_command
from _topology import TARGET_LAN_IF, TARGET_WAN_IF

CONNECTIONS = 6144
FLAPS = 12
FLAP_SECONDS = 5
PROBE_INTERVAL = 1
SEND_INTERVAL = float(os.environ.get("ASK_FLAP_SEND_INTERVAL", "2"))
BULK_PORT = 5310
BULK_STREAMS = int(os.environ.get("ASK_FLAP_BULK_STREAMS", "8"))


async def test_route_flap_keeps_the_probe_healthy(rig):
    r = rig
    con = Console.target()
    receiver = r.echo.transport.get_extra_info("socket")
    receiver.setsockopt(socket.SOL_SOCKET, 33, 4 << 20)  # Linux SO_RCVBUFFORCE
    address = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr",
                                       "show", "dev", TARGET_WAN_IF))["stdout"])[0]
    public = next(a["local"] for a in address["addr_info"] if a["family"] == "inet")
    specs = [{"id": i, "proto": "tcp" if i & 1 else "udp", "sport": BASE + i // 2,
              "remote": [public, BASE + i // 2]} for i in range(CONNECTIONS)]
    ids = list(range(CONNECTIONS))
    r.bulk = True
    await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} meta l4proto {{ tcp, udp }} th sport {BASE}-{BASE + CONNECTIONS // 2 - 1} th dport {DPORT} flow add @fast
 ip saddr {WAN_IP} ip daddr {r.lan_ip} tcp dport {BULK_PORT} flow add @fast
 }}
}}''')
    # The fixture's own host route, as it made it.
    cleanup = [["ip", "route", "replace", f"{WAN_IP}/32", "dev", TARGET_WAN_IF]]
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(limits[0], 2 * len(specs) + 512), limits[1]))
    probes = []
    try:
        for proto in ("udp", "tcp"):
            await command(r.target, r.session, "conntrack", "-D", "-p", proto, "--orig-src", r.lan_ip,
                          "--orig-dst", WAN_IP, "--dport", str(DPORT), check=False, quiet=True)
        async with peer(r, specs, initial_ids=[], lease=900, tcp_size=1024) as p:
            for offset in range(0, len(ids), 256):
                group = ids[offset:offset + 256]
                await p.rpc("open", group)
                await batch(p, group, count=4, interval=0.025)
                await start(p, group, interval=SEND_INTERVAL)
            full = await wait_entries(r, 2 * CONNECTIONS, p, timeout=150)
            stop = asyncio.Event()

            async def prober():
                while not stop.is_set():
                    began = time.monotonic()
                    health = await console_command(con, "ask-flowtable", "health", check=False)
                    probes.append({"at": round(began - started, 2),
                                   "seconds": round(time.monotonic() - began, 3), **health})
                    await asyncio.sleep(PROBE_INTERVAL)

            bulk = None
            if BULK_STREAMS:
                await lan_start(r, iperf=(BULK_PORT,), lifetime=FLAPS * FLAP_SECONDS + 120)
                bulk = asyncio.create_task(iperf(r, BULK_PORT, seconds=FLAPS * FLAP_SECONDS + 5,
                                                 streams=BULK_STREAMS))
                # In hardware before the first change, as a running transfer is.
                await asyncio.sleep(3)
            started = time.monotonic()
            probing = asyncio.create_task(prober())
            changes = []
            try:
                for n in range(FLAPS):
                    began = time.monotonic()
                    await command(r.target, r.session, "ip", "route", "replace", f"{WAN_IP}/32",
                                  "dev", TARGET_WAN_IF, "advmss", str(1300 + n % 2))
                    changes.append(round(time.monotonic() - began, 3))
                    await asyncio.sleep(max(0, began + FLAP_SECONDS - time.monotonic()))
            finally:
                stop.set()
                await asyncio.gather(probing, return_exceptions=True)
                if bulk:
                    report = (await asyncio.gather(bulk, return_exceptions=True))[0]
                    await lan_stop(r)
            if bulk:
                assert not isinstance(report, BaseException), report
                r.record("route-flap-bulk", {"received_bps": report["end"]["sum_received"]["bits_per_second"]})
            after = (await r.target.observe(r.session, "summary"))
            r.record("route-flap", {"full_entries": full["entries"], "probes": probes, "changes": changes,
                                    "route_invalidations": after["route_invalidations"] -
                                                          full["route_invalidations"],
                                    "installs": after["installs"] - full["installs"],
                                    "deletes": after["deletes"] - full["deletes"],
                                    "busy": after.get("busy", 0) - full.get("busy", 0),
                                    "longest_probe_seconds": max(probe["seconds"] for probe in probes)})
            # Every change retired the table's flows and their traffic offered
            # them again: what this measures happened.
            assert after["route_invalidations"] - full["route_invalidations"] >= CONNECTIONS, after
            assert after["installs"] - full["installs"] >= CONNECTIONS, after
            assert len(probes) >= FLAPS * FLAP_SECONDS // (4 * PROBE_INTERVAL), probes
            assert all(probe["rc"] == 0 for probe in probes), [probe for probe in probes if probe["rc"]]
            await p.rpc("stop", ids)
        assert socket_drops(receiver) == 0, "generator UDP receive queue overflow"
    finally:
        try:
            await r.delete_table(timeout=60)
        finally:
            for argv in reversed(cleanup):
                await command(r.target, r.session, *argv, check=False)
            resource.setrlimit(resource.RLIMIT_NOFILE, limits)

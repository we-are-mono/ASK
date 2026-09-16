"""Prove independent connection lifetimes within the admission budget."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import secrets

import pytest
import pytest_asyncio

from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from flowtable_connections_peer import TCP_SIZE, UDP_SIZE, payload
from test_flowtable_offload import (DPORT, HEALTH_BASELINE, SPORT as BASE_SPORT, TABLE, WAN_IP,
                                    command, read, rig)  # noqa: F401
from test_flowtable_tcp import cpu, cpu_delta, software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
# Keep this set separate from the single-connection regressions' TCP TIME_WAIT.
SPORT = BASE_SPORT + 32
FLOWS = [{"id": i, "proto": "tcp" if i & 1 else "udp", "sport": SPORT + i // 2}
         for i in range(32)]
ALL = list(range(len(FLOWS)))


def by_key(state):
    return {(f["in"], f["proto"], f["src"], f["dst"]): f for f in state["flows"]}


def keys(r, ids):
    result = set()
    for ident in ids:
        spec = FLOWS[ident]
        proto = "6" if spec["proto"] == "tcp" else "17"
        src, dst = f"{r.lan_ip}:{spec['sport']}", f"{WAN_IP}:{DPORT}"
        result.update(((TARGET_LAN_IF, proto, src, dst), (TARGET_WAN_IF, proto, dst, src)))
    return result


# The adapter's error count is cumulative for the boot and deliberately never
# reset, and the rearm test asserts that its barrier adds exactly two. Health
# therefore means "no new errors", not "none ever": against an absolute zero
# every test collected after that one fails on its predecessor's bookkeeping.
# The other three are current state rather than counters and stay absolute.
def healthy(state):
    assert state["bindings"] == 2 and state["max_entries"] == 32768, state
    assert state["entries"] == state["neighbour_refs"] == state["handle_refs"] == len(state["flows"]), state
    assert state["invalidated"] == state["fatal"] == state["quarantine"] == 0, state
    assert state["errors"] == HEALTH_BASELINE["errors"], (state, HEALTH_BASELINE)


def unchanged(r, before, after, ids):
    healthy(after)
    old, new = by_key(before), by_key(after)
    for key in keys(r, ids):
        assert new[key]["cookie"] == old[key]["cookie"], (key, before, after)
        assert int(new[key]["packets"]) >= int(old[key]["packets"]), (key, before, after)
        assert int(new[key]["bytes"]) >= int(old[key]["bytes"]), (key, before, after)


async def delete_connection(r, ident):
    spec = FLOWS[ident]
    return await command(r.target, r.session, "conntrack", "-D", "-p", spec["proto"],
                         "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                         "--sport", str(spec["sport"]), "--dport", str(DPORT), check=False)


class Peer:
    def __init__(self, reader, writer, flows, tcp_size=TCP_SIZE):
        self.reader, self.writer = reader, writer
        self.tcp_size = tcp_size
        self.flows = {f["id"]: f for f in flows}

    async def rpc(self, op, ids=None, **kwargs):
        async with asyncio.timeout(25):
            self.writer.write(json.dumps({"op": op, "ids": ids or [], **kwargs}).encode() + b"\n")
            await self.writer.drain()
            line = await self.reader.readline()
            assert line, f"LAN peer disconnected during {op}; see connections-peer.json"
            response = json.loads(line)
            assert response["op"] == op, response
            return response["result"]

    async def batch(self, ids, count=32, interval=0.005):
        await self.rpc("start", ids, count=count, interval=interval)
        result = {int(k): v for k, v in (await self.rpc("wait", ids)).items()}
        assert set(result) == set(ids), result
        for ident, report in result.items():
            assert report["count"] == count, report
            size = self.tcp_size if self.flows[ident]["proto"] == "tcp" else UDP_SIZE
            assert report["bytes"] == count * size, report
        return result


@asynccontextmanager
async def peer(r, flows=FLOWS, *, initial_ids=None, servers=(), lease=180, tcp_size=TCP_SIZE,
               reconnect=False):
    specs = {f["id"]: f for f in flows}
    accepted = asyncio.Queue()
    tasks, writers, errors, tcp_counts = set(), set(), [], {}
    active_ids = set()
    control_server = await asyncio.start_server(lambda rd, wr: accepted.put_nowait((rd, wr)), WAN_IP, DPORT + 1, limit=8 << 20)
    server = task = controller = None

    async def echo(reader, writer):
        writers.add(writer)
        ident = None
        owns_id = False
        try:
            hello = json.loads(await asyncio.wait_for(reader.readline(), 10))
            ident = hello["id"]
            assert ident in specs and specs[ident]["proto"] == "tcp"
            assert writer.get_extra_info("peername") == tuple(specs[ident].get("remote", (specs[ident].get("lan", r.lan_ip), specs[ident]["sport"])))
            assert ident not in active_ids, (ident, "overlapping TCP generations")
            assert reconnect or ident not in tcp_counts
            assert hello["serial"] == tcp_counts.get(ident, 0), (ident, hello, tcp_counts.get(ident))
            tcp_counts.setdefault(ident, 0)
            active_ids.add(ident)
            owns_id = True
            while True:
                try:
                    data = await reader.readexactly(tcp_size)
                except asyncio.IncompleteReadError as error:
                    assert not error.partial, (ident, "partial TCP record", len(error.partial))
                    break
                assert data == payload(ident, tcp_counts[ident], tcp_size), (ident, tcp_counts[ident])
                tcp_counts[ident] += 1
                writer.write(data)
                await writer.drain()
        except ConnectionError as error:
            if ident not in specs or not specs[ident].get("abort"):
                errors.append((ident, repr(error)))
        except Exception as error:
            errors.append((ident, repr(error)))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                if ident not in specs or not specs[ident].get("abort"):
                    errors.append((ident, "unexpected reset on close"))
            writers.discard(writer)
            if owns_id:
                active_ids.remove(ident)

    def accept(reader, writer):
        job = asyncio.create_task(echo(reader, writer))
        tasks.add(job)
        job.add_done_callback(tasks.discard)

    try:
        server = await asyncio.start_server(accept, WAN_IP, DPORT)
        config = {"lan": r.lan_ip, "wan": WAN_IP, "dport": DPORT,
                  "control_port": DPORT + 1, "servers": list(servers), "token": secrets.token_hex(16),
                  "lease": lease, "tcp_size": tcp_size}
        script = (f"CONFIG={config!r}\n" + Path(__file__).with_name("flowtable_neighbour_peer.py").read_text()
                  + "\n" + Path(__file__).with_name("flowtable_udp_wire.py").read_text()
                  + "\n" + Path(__file__).with_name("flowtable_echo_peer.py").read_text()
                  + "\n" + Path(__file__).with_name("flowtable_connections_peer.py").read_text())
        task = asyncio.create_task(lan_run_python(r.lan, script, timeout=lease + 20, label="flowtable_connections"))
        reader, writer = await asyncio.wait_for(accepted.get(), 15)
        controller = Peer(reader, writer, flows, tcp_size)
        ready = json.loads(await asyncio.wait_for(reader.readline(), 5))
        assert ready == {"ready": config["token"]}, ready
        # Transfer the potentially large workload over the control connection,
        # keeping the console staging command independent of connection count.
        writer.write(json.dumps({"flows": flows}).encode() + b"\n")
        await writer.drain()
        await controller.rpc("open", list(specs) if initial_ids is None else initial_ids)
        yield controller
    finally:
        shutdown_error = None
        try:
            if controller:
                await controller.rpc("shutdown")
        except Exception as error:
            shutdown_error = error
        finally:
            if controller:
                controller.writer.close()
                try:
                    waiter = asyncio.create_task(controller.writer.wait_closed())
                    try:
                        await asyncio.wait_for(asyncio.shield(waiter), 5)
                    except TimeoutError:
                        controller.writer.transport.abort()
                        await asyncio.wait_for(waiter, 5)
                except (ConnectionError, OSError) as error:
                    shutdown_error = shutdown_error or error
            if server:
                server.close()
            control_server.close()
            for writer in list(writers):
                # NAT lifecycle tests can destroy a mapping before its peer
                # closes. Cleanup must not wait for an unreachable TCP tuple.
                writer.transport.abort()
            await asyncio.gather(*list(tasks), return_exceptions=True)
            # Python 3.13 Server.wait_closed also waits for accepted clients.
            # Close their transports before waiting for the listening servers.
            if server:
                await server.wait_closed()
            await control_server.wait_closed()
            # Always finish the sole LAN console operation before fixture cleanup.
            if task:
                result = await task
                r.record("connections-peer", {"rc": result.rc, "stdout": result.stdout,
                                                "server_errors": errors, "tcp_records": tcp_counts})
                assert result.rc == 0 and not errors, (result.stdout, errors)
        if shutdown_error:
            raise shutdown_error


@pytest_asyncio.fixture
async def connections(rig):
    r = rig
    cleanup = []
    try:
        initial = await r.state()
        assert not initial["observe"] and initial["max_entries"] == 32768, initial
        for proto in ("udp", "tcp"):
            nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", proto,
                   "--sport", f"{SPORT}:{SPORT + 15}", "--dport", str(DPORT), "-j", "ACCEPT"]
            await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
            cleanup.append(["iptables", "-t", "nat", "-D", *nat])
            name = f"net.netfilter.nf_flowtable_{proto}_timeout"
            value = (await read(r.target, r.session, "/proc/sys/" + name.replace(".", "/"))).strip()
            await command(r.target, r.session, "sysctl", "-w", f"{name}=5")
            cleanup.append(["sysctl", "-w", f"{name}={value}"])
        for ident in ALL:
            await delete_connection(r, ident)
        await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} udp sport {SPORT}-{SPORT + 15} udp dport {DPORT} flow add @fast
 ip saddr {r.lan_ip} ip daddr {WAN_IP} tcp sport {SPORT}-{SPORT + 15} tcp dport {DPORT} flow add @fast
 }}
}}''')
        await r.wait(lambda s: s["bindings"] == 2)
        yield r
    finally:
        failures = []
        try:
            final = await r.delete_table()
            assert final["entries"] == final["neighbour_refs"] == final["quarantine"] == 0, final
            assert final["installs"] == final["deletes"], final
            assert final["errors"] == HEALTH_BASELINE["errors"], (final, HEALTH_BASELINE)
            r.record("connections-cleanup", final)
        except Exception as error:
            failures.append(str(error))
        for ident in ALL:
            try:
                await delete_connection(r, ident)
            except Exception as error:
                failures.append(str(error))
        for argv in reversed(cleanup):
            try:
                await command(r.target, r.session, *argv)
            except Exception as error:
                failures.append(str(error))
        assert not failures, failures


async def hardware_batch(r, p, ids, label):
    before = await r.state()
    healthy(before)
    tx_before, cpu_before = await software_tx(r), await cpu(r)
    reports = await p.batch(ids, count=256, interval=0.03125)
    cpu_after, tx_after = await cpu(r), await software_tx(r)
    after = await r.state()
    unchanged(r, before, after, ids)
    assert by_key(after).keys() == keys(r, ids), after
    assert after["installs"] == before["installs"] and after["deletes"] == before["deletes"], (before, after)
    old, new = by_key(before), by_key(after)
    deltas = []
    for ident in ids:
        for key in keys(r, [ident]):
            packets = int(new[key]["packets"]) - int(old[key]["packets"])
            byte_count = int(new[key]["bytes"]) - int(old[key]["bytes"])
            if FLOWS[ident]["proto"] == "udp":
                assert packets == 256 and byte_count == 256 * (UDP_SIZE + 42), (key, packets, byte_count)
            else:
                assert packets >= reports[ident]["bytes"] // 1500, (key, packets)
            deltas.append({"key": key, "packets": packets, "bytes": byte_count})
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    assert 0 <= tx[TARGET_LAN_IF] <= 64 and 0 <= tx[TARGET_WAN_IF] <= 512, tx
    r.record(label, {"before": before, "after": after, "transfers": reports,
                     "hardware": deltas, "software_tx": tx, "cpu": cpu_delta(cpu_before, cpu_after),
                     "cpu_ticks_before": cpu_before, "cpu_ticks_after": cpu_after})
    return after


async def test_flowtable_connections_independent_lifetimes(connections):
    r = connections
    assert (await r.state())["entries"] == 0
    cpu_before = await cpu(r)
    await asyncio.sleep(4)
    cpu_after = await cpu(r)
    assert (await r.state())["entries"] == 0
    r.record("connections-idle", {"cpu": cpu_delta(cpu_before, cpu_after),
                                  "cpu_ticks_before": cpu_before, "cpu_ticks_after": cpu_after})
    async with peer(r) as p:
        await p.batch(ALL)
        installed = await r.wait(lambda s: s["entries"] == 64)
        healthy(installed)
        assert by_key(installed).keys() == keys(r, ALL), installed
        baseline = await hardware_batch(r, p, ALL, "connections-full")

        # Keep every other connection active while deleting exactly one UDP CT.
        live = ALL[1:]
        await p.rpc("start", live, count=0, interval=0.01)
        deleted = await delete_connection(r, 0)
        assert deleted["rc"] == 0, deleted
        removed = await r.wait(lambda s: s["entries"] == 62)
        assert by_key(removed).keys() == keys(r, live), removed
        unchanged(r, baseline, removed, live)
        assert removed["installs"] == baseline["installs"] and removed["deletes"] == baseline["deletes"] + 2
        r.record("connections-delete", {"before": baseline, "after": removed, "conntrack": deleted})

        # A normal TCP close must retire just its two directions too.
        await p.rpc("stop", [1])
        await p.rpc("close", [1])
        live.remove(1)
        closed = await r.wait(lambda s: s["entries"] == 60)
        assert by_key(closed).keys() == keys(r, live), closed
        unchanged(r, baseline, closed, live)
        assert closed["installs"] == baseline["installs"] and closed["deletes"] == baseline["deletes"] + 4
        r.record("connections-fin", closed)

        # Shared-neighbour activity must not refresh an idle connection.
        await p.rpc("stop", [2])
        live.remove(2)
        idle = await r.wait(lambda s: s["entries"] == 58, timeout=15)
        assert by_key(idle).keys() == keys(r, live), idle
        unchanged(r, baseline, idle, live)
        assert idle["installs"] == baseline["installs"] and idle["deletes"] == baseline["deletes"] + 6
        for key in keys(r, live):
            assert int(by_key(idle)[key]["packets"]) > int(by_key(removed)[key]["packets"]), (key, removed, idle)
        r.record("connections-expiry", idle)

        # Reuse the deleted UDP tuple and refresh the still-open idle one while
        # all surviving connections keep their original hardware ownership.
        await p.batch([0, 2])
        restored = await r.wait(lambda s: s["entries"] == 62)
        unchanged(r, baseline, restored, live)
        assert by_key(restored).keys() == keys(r, [0, 2] + live), restored
        assert restored["installs"] == baseline["installs"] + 4 and restored["deletes"] == idle["deletes"], restored
        for key in keys(r, [0, 2]):
            assert int(by_key(restored)[key]["packets"]) <= 32, (key, restored)
        r.record("connections-reuse", restored)
        background = await p.rpc("stop", live)
        assert all(report["count"] > 0 for report in background.values()), background
        r.record("connections-background", background)
        await hardware_batch(r, p, [0, 2] + live, "connections-survivors")

        # Every UDP record is unique across warmup, steady traffic and reuse.
        assert r.echo.received and all(n == 1 for n in r.echo.received.values())
        r.record("connections-udp", {"unique_records": len(r.echo.received),
                                      "duplicates": sum(n - 1 for n in r.echo.received.values())})

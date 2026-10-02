"""Shared flowtable connections fixtures and scenarios."""

from __future__ import annotations

import asyncio
import json
import secrets
import socket
import struct
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import pytest_asyncio
from _flowtable_rig import DPORT, HEALTH_BASELINE, TABLE, WAN_IP, command, read
from _flowtable_rig import SPORT as BASE_SPORT
from _flowtable_tcp import cpu, cpu_delta, software_tx
from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from flowtable_connections_peer import TCP_SIZE, UDP_SIZE, payload

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
# A second offload table bound beside the rig's own adds its devices to
# `bindings`; a caller that holds one passes the total it expects.
def healthy(state, bindings=2):
    assert state["bindings"] == bindings and state["max_entries"] == 32768, state
    assert consistent(state), state
    assert state["invalidated"] == state["fatal"] == state["quarantine"] == 0, state
    assert state["errors"] == HEALTH_BASELINE["errors"], (state, HEALTH_BASELINE)




# /proc/cdx_flowtable is read a page at a time, and each page is a fresh
# look: the counters at its head and the rows after them can straddle a
# delete. A wait for rows to go also waits for the counters to agree.
def consistent(state):
    return state["entries"] == state["neighbour_refs"] == state["handle_refs"] == len(state["flows"])


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
               reconnect=False, listen_addresses=()):
    specs = {f["id"]: f for f in flows}
    accepted = asyncio.Queue()
    tasks, writers, errors, tcp_counts = set(), set(), [], {}
    active_ids = set()
    control_server = await asyncio.start_server(lambda rd, wr: accepted.put_nowait((rd, wr)), WAN_IP, DPORT + 1, limit=8 << 20)
    listeners = []
    task = controller = None

    async def echo(reader, writer):
        writers.add(writer)
        ident = None
        owns_id = False
        try:
            hello = json.loads(await asyncio.wait_for(reader.readline(), 10))
            ident = hello["id"]
            assert ident in specs and specs[ident]["proto"] == "tcp"
            assert writer.get_extra_info("peername")[:2] == tuple(specs[ident].get("remote", (specs[ident].get("lan", r.lan_ip), specs[ident]["sport"])))
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
                await asyncio.wait_for(writer.wait_closed(), 5)
            except (ConnectionError, TimeoutError):
                writer.transport.abort()
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
        for address in dict.fromkeys((WAN_IP, *listen_addresses)):
            listeners.append(await asyncio.start_server(accept, address, DPORT))
        config = {"lan": r.lan_ip, "wan": WAN_IP, "dport": DPORT,
                  "control_port": DPORT + 1, "servers": list(servers), "token": secrets.token_hex(16),
                  "lease": lease, "tcp_size": tcp_size}
        script = (f"CONFIG={config!r}\n" + Path(__file__).with_name("flowtable_neighbour_peer.py").read_text()
                  + "\n" + Path(__file__).with_name("flowtable_multicast_peer.py").read_text()
                  + "\n" + Path(__file__).with_name("flowtable_udp_wire.py").read_text()
                  + "\n" + Path(__file__).with_name("flowtable_echo_peer.py").read_text()
                  + "\n" + Path(__file__).with_name("flowtable_connections_peer.py").read_text())
        task = asyncio.create_task(lan_run_python(r.lan, script, timeout=lease + 20, label="flowtable_connections"))
        reader, writer = await asyncio.wait_for(accepted.get(), 15)
        controller = Peer(reader, writer, flows, tcp_size)
        def tcp_info():
            snapshots = []
            for stream in writers:
                sock = stream.get_extra_info("socket")
                if sock is not None:
                    snapshots.append({"peer": stream.get_extra_info("peername"),
                        "tcp_info_hex": sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104).hex()})
            return snapshots
        controller.wan_tcp_info = tcp_info
        ready = json.loads(await asyncio.wait_for(reader.readline(), 5))
        assert ready == {"ready": config["token"]}, ready
        # Transfer the potentially large workload over the control connection,
        # keeping the console staging command independent of connection count.
        writer.write(json.dumps({"flows": flows}).encode() + b"\n")
        await asyncio.wait_for(writer.drain(), 15)
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
            for listener in listeners:
                listener.close()
            control_server.close()
            for writer in list(writers):
                # NAT lifecycle tests can destroy a mapping before its peer
                # closes. Cleanup must not wait for an unreachable TCP tuple.
                writer.transport.abort()
            try:
                await asyncio.wait_for(asyncio.gather(*list(tasks), return_exceptions=True), 10)
                # Python 3.13 also waits for accepted clients, aborted above.
                for listener in listeners:
                    await asyncio.wait_for(listener.wait_closed(), 10)
                await asyncio.wait_for(control_server.wait_closed(), 10)
            except (Exception, pytest.fail.Exception) as error:
                shutdown_error = shutdown_error or error
            # Always finish the sole LAN console operation before fixture cleanup.
            if task:
                result = await task
                r.record("connections-peer", {"rc": result.rc, "stdout": result.stdout,
                                                "server_errors": errors, "tcp_records": tcp_counts})
                if result.rc != 0 or errors:
                    # Which way a lost datagram died: the WAN echo's own record
                    # of what reached it, the newest serials of each flow. A
                    # serial the LAN never got back but the WAN saw was lost on
                    # the way back.
                    seen = {}
                    for data in getattr(getattr(r, "echo", None), "received", {}):
                        if len(data) >= 12:
                            ident, serial = struct.unpack("!IQ", data[:12])
                            seen.setdefault(ident, []).append(serial)
                    dut = {}
                    for path in ("/proc/net/xfrm_stat", "/proc/cdx_flowtable"):
                        try:
                            dut[path] = await read(r.target, r.session, path)
                        except Exception as error:
                            dut[path] = repr(error)
                    r.record("connections-wan-received",
                             {"wan": {ident: sorted(serials)[-32:] for ident, serials in seen.items()},
                              "dut": dut})
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

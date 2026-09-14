"""Focused IPv4 TCP acceptance using the opt-in two-port flowtable rig."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import threading
import time

import pytest

from ask_orch.client import Agent
from ask_orch.counters import kernel_tx_packets
from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_offload import ARTIFACTS, DPORT, SPORT, TABLE, WAN_IP, command, read, rig  # noqa: F401

pytestmark = [
    pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                       reason="requires an explicit experimental boot"),
    pytest.mark.parametrize("rig", ["tcp"], indirect=True),
]
BLOCK = bytes(range(256)) * 256
MIB = 1 << 20


class Connection:
    def __init__(self, reader, writer, peer):
        self.reader, self.writer, self.peer = reader, writer, peer

    async def send(self, op, **kwargs):
        self.writer.write(json.dumps({"op": op, **kwargs}).encode() + b"\n")
        await self.writer.drain()

    async def transfer(self, op, size=MIB, rate=8 * MIB):
        async with asyncio.timeout(45):
            await self.send(op, size=size, rate=rate)
            start = time.monotonic()
            digest = hashlib.sha256()
            for offset in range(0, size, len(BLOCK)):
                if op == "upload":
                    data = await self.reader.readexactly(len(BLOCK))
                    assert data == BLOCK, ("upload corruption", offset)
                    digest.update(data)
                else:
                    self.writer.write(BLOCK)
                    await self.writer.drain()
                    delay = (offset + len(BLOCK)) / rate - (time.monotonic() - start)
                    if delay > 0:
                        await asyncio.sleep(delay)
                    digest.update(BLOCK)
            report = json.loads(await self.reader.readline())
            assert report["bytes"] == size and report["op"] == op, report
            if op == "download":
                assert report["sha256"] == digest.hexdigest(), report
            report.update(sha256=digest.hexdigest(), seconds=time.monotonic() - start)
            return report

    async def close(self, how):
        await self.send(how)
        async with asyncio.timeout(10):
            if how == "fin":
                assert await self.reader.read() == b""
            else:
                with pytest.raises(ConnectionResetError):
                    await self.reader.read()
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except ConnectionResetError:
                assert how == "rst"
            result = await self.peer
            assert result.rc == 0, result.stdout
            assert json.loads(result.stdout.strip()) == {"closed": how}, result.stdout


@asynccontextmanager
async def connection(r):
    accepted = asyncio.Queue()
    server = await asyncio.start_server(lambda rd, wr: accepted.put_nowait((rd, wr)), WAN_IP, DPORT)
    script = (f"LAN_IP={r.lan_ip!r}; WAN_IP={WAN_IP!r}; SPORT={SPORT}; DPORT={DPORT}\n" +
              Path(__file__).with_name("flowtable_tcp_peer.py").read_text())
    peer = asyncio.create_task(lan_run_python(r.lan, script, timeout=180, label="flowtable_tcp"))
    writer = None
    try:
        reader, writer = await asyncio.wait_for(accepted.get(), 15)
        assert json.loads(await asyncio.wait_for(reader.readline(), 5)) == {"ready": True}
        yield Connection(reader, writer, peer)
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
        server.close()
        await server.wait_closed()
        # LAN UART is single-channel. Always finish this operation before
        # fixture cleanup can use it again, including on a failed assertion.
        result = await peer
        r.record("tcp-peer-last", {"rc": result.rc, "stdout": result.stdout})


async def tcp_table(r):
    await r.table()
    # These counters are on the ordinary forward hook, independent of the
    # flowtable counter feature (which this backend deliberately declines).
    for flag in ("syn", "fin", "rst"):
        await r.nft(f"add counter inet {TABLE} tcp_{flag}")
        for src, dst, sport, dport in [(r.lan_ip, WAN_IP, SPORT, DPORT),
                                      (WAN_IP, r.lan_ip, DPORT, SPORT)]:
            await r.nft(f"insert rule inet {TABLE} forward ip saddr {src} ip daddr {dst} "
                        f"tcp sport {sport} tcp dport {dport} tcp flags & {flag} == {flag} "
                        f"counter name tcp_{flag}")


async def control_counters(r):
    result = await command(r.target, r.session, "nft", "-j", "list", "counters", "table", "inet", TABLE)
    return {obj["counter"]["name"]: obj["counter"]["packets"]
            for obj in json.loads(result["stdout"])["nftables"] if "counter" in obj}


async def installed(r, conn):
    # Several application exchanges let the asynchronous hardware worker
    # install both rules without assuming a particular scheduling delay.
    for _ in range(10):
        await conn.transfer("upload", size=len(BLOCK))
        state = await r.state()
        if state["entries"] == 2:
            assert all(f["proto"] == "6" for f in state["flows"]), state
            assert not state["fatal"] and not state["quarantine"], state
            return state
        await asyncio.sleep(0.1)
    pytest.fail(f"TCP did not install: {state}")


async def cpu(r):
    return {parts[0]: [int(x) for x in parts[1:9]]
            for line in (await read(r.target, r.session, "/proc/stat")).splitlines()
            if (parts := line.split()) and parts[0].startswith("cpu")}


def cpu_delta(before, after):
    result = {}
    for name in before:
        ticks = [b - a for a, b in zip(before[name], after[name], strict=True)]
        total = sum(ticks)
        assert total > 0, ticks
        result[name] = {"busy_percent": round(100 * (total - ticks[3] - ticks[4]) / total, 2),
                        "softirq_percent": round(100 * ticks[6] / total, 2)}
    return result


async def software_tx(r):
    return {dev: await kernel_tx_packets(r.target, r.session, dev)
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF)}


async def conntrack(r):
    return await command(r.target, r.session, "conntrack", "-L", "-p", "tcp",
                         "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                         "--sport", str(SPORT), "--dport", str(DPORT))


@asynccontextmanager
async def tcp_timeouts(r):
    saved = []
    try:
        for name, value in [("nf_flowtable_tcp_timeout", 4),
                            ("nf_conntrack_tcp_timeout_last_ack", 10),
                            ("nf_conntrack_tcp_timeout_time_wait", 10)]:
            old = (await read(r.target, r.session, f"/proc/sys/net/netfilter/{name}")).strip()
            await command(r.target, r.session, "sysctl", "-w", f"net.netfilter.{name}={value}")
            saved.append((name, old))
        yield
    finally:
        for name, value in reversed(saved):
            await command(r.target, r.session, "sysctl", "-w", f"net.netfilter.{name}={value}")


async def capture_fin(r, conn):
    from scapy.all import AsyncSniffer, IP, TCP, wrpcap
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=r.wan_if, store=True, started_callback=ready.set,
                          filter=f"tcp and host {r.lan_ip} and port {SPORT} and port {DPORT}")
    sniffer.start()
    try:
        assert await asyncio.to_thread(ready.wait, 5), "TCP close capture did not start"
        await conn.close("fin")
        await asyncio.sleep(0.1)
    finally:
        packets = sniffer.stop()
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        wrpcap(str(ARTIFACTS / "tcp-fin.pcap"), packets)
    fins = [p for p in packets if TCP in p and int(p[TCP].flags) & 1]
    assert {p[IP].src for p in fins} == {r.lan_ip, WAN_IP}, fins
    wan_fin = next(p for p in fins if p[IP].src == WAN_IP)
    assert any(p[IP].src == r.lan_ip and int(p[TCP].flags) == 16 and
               p[TCP].ack == (wan_fin[TCP].seq + 1) % (1 << 32)
               for p in packets if TCP in p), "endpoint's final ACK missing"


async def hardware_transfer(r, conn, op, label=None):
    before = await r.state()
    tx_before, cpu_before = await software_tx(r), await cpu(r)
    report = await conn.transfer(op, size=64 * MIB)
    cpu_after, tx_after = await cpu(r), await software_tx(r)
    after = await r.state()
    assert after["entries"] == 2 and after["installs"] == before["installs"], (before, after)
    old = {f["in"]: f for f in before["flows"]}
    deltas = {f["in"]: int(f["packets"]) - int(old[f["in"]]["packets"]) for f in after["flows"]}
    ingress = TARGET_LAN_IF if op == "upload" else TARGET_WAN_IF
    assert deltas[ingress] >= report["bytes"] // 1500, deltas
    assert deltas[TARGET_WAN_IF if op == "upload" else TARGET_LAN_IF] > 100, deltas
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    # Management HTTP uses WAN software TX too. Bound it far below the tens
    # of thousands of data frames, while allowing control-plane traffic.
    assert 0 <= tx[TARGET_LAN_IF] <= 32 and 0 <= tx[TARGET_WAN_IF] <= 512, tx
    report.update(hardware_packets=deltas, software_tx=tx, cpu=cpu_delta(cpu_before, cpu_after),
                  before=before, after=after)
    r.record(label or f"tcp-hardware-{op}", report)
    return report


async def test_flowtable_tcp_transfer_expiry_fin(rig):
    r = rig
    async with tcp_timeouts(r):
        idle_before = await cpu(r)
        await asyncio.sleep(2)
        r.record("tcp-idle-cpu", cpu_delta(idle_before, await cpu(r)))
        await tcp_table(r)
        async with connection(r) as conn:
            await installed(r, conn)
            counters = await control_counters(r)
            assert counters["tcp_syn"] >= 2 and counters["tcp_fin"] == counters["tcp_rst"] == 0, counters
            await hardware_transfer(r, conn, "upload")
            await hardware_transfer(r, conn, "download")
            expired = await r.wait(lambda s: s["entries"] == 0, timeout=12)
            r.record("tcp-idle-expired", expired)
            resumed = await installed(r, conn)
            assert resumed["installs"] == expired["installs"] + 2, (expired, resumed)
            await capture_fin(r, conn)
            removed = await r.wait(lambda s: s["entries"] == 0, timeout=3)
            counters = await control_counters(r)
            assert counters["tcp_fin"] >= 2 and counters["tcp_rst"] == 0, counters
            ct = await conntrack(r)
            # FIN punts mark NF_FLOW_TEARDOWN immediately, but NF queues
            # hardware removal from its periodic GC. The final pure ACK can
            # cross hardware in that interval, leaving CT in LAST_ACK. Both
            # endpoints must still close, both FINs must reach Linux, hardware
            # must disappear promptly, and CT must expire without OFFLOAD.
            assert any(state in ct["stdout"] for state in ("TIME_WAIT", "LAST_ACK")), ct
            assert "OFFLOAD" not in ct["stdout"], ct
            r.record("tcp-fin", {"state": removed, "counters": counters, "conntrack": ct})
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                final_ct = await conntrack(r)
                if not final_ct["stdout"].strip():
                    break
                await asyncio.sleep(0.1)
            assert not final_ct["stdout"].strip(), final_ct
            r.record("tcp-fin-expired", final_ct)


async def test_flowtable_tcp_retransmit_withdraw_rst(rig):
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    await tcp_table(r)
    async with connection(r) as conn:
        await installed(r, conn)
        # Drop only this connection's inbound data at its WAN endpoint. ACKs
        # and management traffic remain usable. The sender must retransmit.
        drop = ["INPUT", "-s", r.lan_ip, "-d", WAN_IP, "-p", "tcp", "--sport", str(SPORT),
                "--dport", str(DPORT), "-m", "length", "--length", "200:65535",
                "-m", "comment", "--comment", "ask-flowtable-tcp-retransmit", "-j", "DROP"]
        await command(wan, r.session, "iptables", "-I", *drop)
        traffic = asyncio.create_task(conn.transfer("upload", size=8 * MIB))
        try:
            await asyncio.sleep(0.5)
            dropped = await command(wan, r.session, "iptables", "-nvx", "-L", "INPUT")
        finally:
            await command(wan, r.session, "iptables", "-D", *drop)
            report = await traffic
        rows = [line.split() for line in dropped["stdout"].splitlines() if "ask-flowtable-tcp-retransmit" in line]
        assert len(rows) == 1 and int(rows[0][0]) > 0, dropped
        assert report["retransmits"] > 0, report
        r.record("tcp-retransmit", {"transfer": report, "dropped_packets": int(rows[0][0]), "state": await r.state()})
        tx_before = await software_tx(r)
        traffic = asyncio.create_task(conn.transfer("download", size=16 * MIB))
        try:
            await asyncio.sleep(0.25)
            removed = await r.delete_table()
        finally:
            report = await traffic
        tx_after = await software_tx(r)
        assert tx_after[TARGET_LAN_IF] - tx_before[TARGET_LAN_IF] > 100, (tx_before, tx_after)
        assert removed["entries"] == removed["bindings"] == removed["quarantine"] == 0, removed
        r.record("tcp-withdraw", {"transfer": report, "state": removed, "software_tx_before": tx_before, "software_tx_after": tx_after})
        await tcp_table(r)
        await installed(r, conn)
        await hardware_transfer(r, conn, "upload", label="tcp-hardware-after-withdraw")
        await conn.close("rst")
        removed = await r.wait(lambda s: s["entries"] == 0, timeout=3)
        counters = await control_counters(r)
        assert counters["tcp_rst"] >= 1, counters
        ct = await conntrack(r)
        # nf_conntrack_proto_tcp intentionally retains ESTABLISHED when the
        # RST sequence differs from its last observed ACK, allowing a possible
        # RFC5961 challenge ACK. Offloaded data makes that observation stale.
        # Its RST path still applies the short CLOSE timeout. Require reset at
        # the endpoint, Linux visibility, prompt removal and bounded CT expiry.
        assert any(state in ct["stdout"] for state in ("CLOSE ", "ESTABLISHED")), ct
        close_timeout = int((await read(r.target, r.session,
                                       "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close")).strip())
        assert "OFFLOAD" not in ct["stdout"] and int(ct["stdout"].split()[2]) <= close_timeout, ct
        r.record("tcp-rst", {"state": removed, "counters": counters, "conntrack": ct})
        deadline = time.monotonic() + close_timeout + 2
        while time.monotonic() < deadline:
            final_ct = await conntrack(r)
            if not final_ct["stdout"].strip():
                break
            await asyncio.sleep(0.1)
        assert not final_ct["stdout"].strip(), final_ct
        r.record("tcp-rst-expired", final_ct)

"""Lifetimes and sequence numbers of offloaded SAs, as xfrm keeps them.

Packet offload bypasses xfrm_output_one() and xfrm_input(), where the stack
counts an SA's traffic and judges its limits. The adapter carries SEC's per-SA
counters into the state's current lifetime once a second and lets
xfrm_state_check_expire() decide, so byte and packet limits fire through
xfrm's own soft and hard expiry, up to one accounting pass late.

An outbound SA's sequence number crosses the same boundary both ways: the
number the state was installed with seeds SEC, and SEC's position is published
back into the state. A non-ESN SA near the end of its 32-bit space is asked to
rekey with a soft expiry, since SEC will not wrap it.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
import json
from pathlib import Path
import re
import secrets
import struct
import time

import pytest

from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from _flowtable_connections import (by_key)
from _flowtable_rig import (DPORT, command, console_command, console_python, drive, read)
from _flowtable_selective_neighbour import (keys)
from _flowtable_service import (FIRST)
from _flowtable_service_ipsec import (INNER, LAN_INNER, Wire, flows_for, sec_counter)
from _flowtable_service_ipsec_replay import (offloaded, peer_errors, sa_state, xfrm_mib)
from _ipsec_helpers import sa_replay_state

# The accounting pass runs once a second, so a limit fires on the first pass
# after it is crossed. This allows for that period and the jitter of a
# delayed work item and of the monitor's own timestamps.
PASS_SLACK_SECONDS = 1.5


# One message of `ip -stats -tshort xfrm monitor`, from its timestamp to the next.
MESSAGE = re.compile(r"^\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6})\] ", re.M)


def monitor_events(text):
    starts = list(MESSAGE.finditer(text))
    events = []
    for index, start in enumerate(starts):
        body = text[start.end():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
        spi = re.search(r"\bspi (0x[0-9a-f]+)", body)
        hard = re.search(r"^\s*hard (\d+)", body, re.M)
        current = re.search(r"lifetime current:\s*(\d+)\(bytes\), (\d+)\(packets\)", body)
        events.append({"time": datetime.strptime(start.group(1), "%Y-%m-%dT%H:%M:%S.%f"),
                       "kind": body.split(None, 1)[0] if body.strip() else "",
                       "spi": int(spi.group(1), 16) if spi else None,
                       "hard": int(hard.group(1)) if hard else None,
                       "bytes": int(current.group(1)) if current else None,
                       "packets": int(current.group(2)) if current else None})
    return events


class XfrmMonitor:
    """`ip xfrm monitor` on the DUT, started before whatever it watches.

    The service console starts it, because the agent runs commands to
    completion; its log is read through the agent."""

    def __init__(self, r, label):
        self.r, self.label = r, label
        self.path = f"/tmp/ask-ipsec-xfrm-monitor-{time.monotonic_ns()}.log"
        self.pid = None

    async def __aenter__(self):
        started = await console_python(self.r.service_console, f"""
import json, subprocess, time
log = open({self.path!r}, "wb")
proc = subprocess.Popen(["ip", "-stats", "-tshort", "xfrm", "monitor"], stdin=subprocess.DEVNULL,
                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
time.sleep(0.5)
assert proc.poll() is None, open({self.path!r}).read()
print(json.dumps({{"pid": proc.pid}}))
""")
        reported = [line for line in started["stdout"].splitlines() if line.startswith("{")]
        assert reported, started["stdout"]
        self.pid = json.loads(reported[-1])["pid"]
        return self

    async def text(self):
        return await read(self.r.target, self.r.session, self.path)

    async def expiries(self, spi):
        return [event for event in monitor_events(await self.text())
                if event["kind"] == "Expired" and event["spi"] == spi]

    async def __aexit__(self, *exc):
        try:
            self.r.record(self.label + "-xfrm-monitor", {"log": await self.text()})
        finally:
            await command(self.r.target, self.r.session, "kill", str(self.pid), check=False)
            await console_command(self.r.service_console, "rm", "-f", self.path, check=False)


async def replace_outbound(r, *options, peer=()):
    """Swap the fixture's outbound SA for one installed with `options` on the
    DUT and `peer` on the WAN host. The peer's copy goes in first, so it
    accepts the new SA's first frame."""
    spi = await r.ipsec.prepare_peer("out", *peer)
    await r.ipsec.remove("out")
    await r.ipsec.install("out", spi, *options)
    return spi


async def restore_sa(r, expired, direction="out"):
    """Put an SA back once a hard expiry has deleted the fixture's.

    An outbound state also removes the larval one an acquire left behind, if it
    has not expired first (the fixture keeps net.core.xfrm_acq_expires
    short): the policy is still required, and traffic after the expiry asked
    the key manager, which the monitor is, for a state that never came."""
    if await sa_state(r, expired, direction) is not None:
        return None
    spi = await r.ipsec.prepare_peer(direction)
    await r.ipsec.install(direction, spi)
    return spi


def blast_script(count, rate, seconds):
    """Flow 2's tuple at a steady rate, echoes drained and discarded."""
    return f"""
import json, socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(({LAN_INNER!r}, {FIRST}))
s.setblocking(False)
payload, sent, start = b"x" * 1000, 0, time.monotonic()
while sent < {count} and time.monotonic() - start < {seconds}:
    due = min({count}, int((time.monotonic() - start) * {rate}) + 1)
    while sent < due:
        try:
            s.sendto(payload, ({INNER!r}, {DPORT}))
        except BlockingIOError:
            break
        sent += 1
    try:
        while True:
            s.recv(2048)
    except BlockingIOError:
        pass
    time.sleep(0.0005)
print(json.dumps({{"sent": sent, "seconds": round(time.monotonic() - start, 2)}}))
"""


async def blast(r, count, rate, seconds=30):
    result = await lan_run_python(r.lan, blast_script(count, rate, seconds), label="ipsec_lifetime_blast",
                                  timeout=seconds + 20)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


def echo_script(count):
    return f"""
import json, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(({LAN_INNER!r}, {FIRST}))
s.settimeout(1)
echoed = 0
for n in range({count}):
    payload = b"ASK-ipsec-sequence-%08d" % n
    s.sendto(payload, ({INNER!r}, {DPORT}))
    try:
        while s.recv(2048) != payload:
            pass
        echoed += 1
    except socket.timeout:
        pass
print(json.dumps({{"echoed": echoed}}))
"""


async def echoes(r, count):
    """Datagrams of flow 2 that made the round trip through both SAs."""
    result = await lan_run_python(r.lan, echo_script(count), label="ipsec_sequence_echo", timeout=count + 20)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])["echoed"]


# Enough to cross the hard limit of either unit with room to spare, at a rate
# that leaves at least two accounting passes between the soft and the hard
# limit: at a rate crossing both inside one pass, xfrm would raise only the
# hard expiry and the soft one would never be seen.
BLAST_COUNT = 125_000
BLAST_RATE = 20_000
LIMITS = {"packet": (50_000, 100_000), "byte": (50_000_000, 100_000_000)}


@pytest.mark.parametrize("direction", ["out", "in"])
@pytest.mark.parametrize("unit", ["packet", "byte"])
async def test_expiry(ipsec_service, unit, direction):
    """A packet or byte limit on an offloaded SA fires through xfrm:
    one soft expiry within a pass of the soft limit, then the hard expiry and
    the state's deletion. Until then the counts rise in `ip -s xfrm state`
    and the flow stays in hardware; the hard expiry retires it."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    soft, hard = LIMITS[unit]
    field = unit + "s"
    ingress = TARGET_LAN_IF if direction == "out" else TARGET_WAN_IF
    flow_key = next(key for key in keys([2], flows) if key[0] == ingress)
    sa_field = "sa" if direction == "out" else "in_sa"
    feeder = "tx toenc" if direction == "out" else "tx todec"
    label = f"ipsec-lifetime-{unit}-{direction}"
    restored = None
    async with XfrmMonitor(r, label) as monitor:
        replace = replace_outbound if direction == "out" else replace_inbound
        spi = await replace(r, "limit", f"{unit}-soft", str(soft), "limit", f"{unit}-hard", str(hard))
        task, samples = None, []
        try:
            if direction == "in":
                # The fixture's replaced SA may still be releasing its FQs.
                # Drain it before admission, so this wait cannot age the flow.
                await r.wait(lambda s: s["ipsec_sa_cache"] == s["ipsec_sas"], timeout=45)
            # A first burst gets flow 2 admitted, so the counted one runs in
            # hardware from its first frame.
            admitted = await drive(r, lambda: blast(r, 500, 2_000), lambda state: flow_key in by_key(state))
            flow = by_key(admitted)[flow_key]
            assert flow[sa_field] != "0", flow
            if direction == "in":
                sa_dir = f"/proc/fqid_stats/sa/{int(flow['in_sa']):#x}"
                await console_command(r.service_console, "test", "-d", sa_dir)
            at_admission = await sa_state(r, spi, direction)
            cpu = await sec_counter(r.session, r.target, TARGET_WAN_IF, feeder)
            task = asyncio.create_task(blast(r, BLAST_COUNT, BLAST_RATE))
            while not task.done():
                # The flow first: an SA still short of its hard limit when read
                # after it proves the flow was read before any hard expiry.
                state = await r.state()
                samples.append({"flow": by_key(state).get(flow_key), "sa": await sa_state(r, spi, direction),
                                "cpu_fed": await sec_counter(r.session, r.target, TARGET_WAN_IF, feeder),
                                "ipsec_invalidations": state["ipsec_invalidations"]})
                await asyncio.sleep(0.3)
            report = await task
            await asyncio.sleep(1.5)
            final = await r.state()
            expiries = await monitor.expiries(spi)
            r.record(label, {"admitted": flow, "samples": samples, "blast": report, "final": final,
                             "expiries": [{**event, "time": event["time"].isoformat()} for event in expiries]})
            softs = [event for event in expiries if event["hard"] == 0]
            hards = [event for event in expiries if event["hard"] == 1]
            assert len(softs) == 1 and len(hards) == 1 and softs[0]["time"] < hards[0]["time"], expiries
            rate = (hards[0][field] - softs[0][field]) / (hards[0]["time"] - softs[0]["time"]).total_seconds()
            assert soft <= softs[0][field] <= soft + PASS_SLACK_SECONDS * rate, (softs, rate)
            assert hard <= hards[0][field] <= hard + PASS_SLACK_SECONDS * rate, (hards, rate)
            # A hard expiry deletes the state; a soft one leaves it alone.
            assert await sa_state(r, spi, direction) is None, "the hard expiry did not delete the state"
            live = [sample for sample in samples if sample["sa"] and sample["sa"][field] < hard]
            counts = [sample["sa"][field] for sample in live]
            assert len(set(counts)) >= 3 and counts == sorted(counts), counts
            assert all(sample["sa"]["use"] != "-" for sample in live if sample["sa"]["packets"]), live
            assert any(sample["sa"][field] >= soft for sample in live), "no sample between the two expiries"
            for sample in live:
                assert sample["flow"] and (sample["flow"]["cookie"], sample["flow"][sa_field]) == (flow["cookie"], flow[sa_field]), (
                    "the flow left hardware before the hard expiry", sample)
            # The SA's figures trail SEC by up to a pass, the flow's do not.
            carried = live[-1]["sa"]["packets"] - at_admission["packets"]
            matched = int(live[-1]["flow"]["packets"]) - int(flow["packets"])
            assert matched >= carried - PASS_SLACK_SECONDS * BLAST_RATE, (matched, carried)
            assert 0 <= live[-1]["cpu_fed"] - cpu <= 64, ("the CPU carried the traffic", live[-1]["cpu_fed"] - cpu)
            assert flow_key not in by_key(final), final
            assert final["ipsec_invalidations"] == admitted["ipsec_invalidations"] + 1, (admitted, final)
            if direction == "in":
                retired = await r.wait(lambda s:
                    s["ipsec_sas"] == admitted["ipsec_sas"] - 1 and
                    s["ipsec_sa_cache"] == admitted["ipsec_sa_cache"] - 1 and
                    all(f["in_sa"] != flow["in_sa"] and f["cookie"] != flow["cookie"] for f in s["flows"]),
                    timeout=45)
                deadline = time.monotonic() + 45
                while (exists := await console_command(r.service_console, "test", "-d", sa_dir, check=False))["rc"] == 0:
                    assert time.monotonic() < deadline, ("expired SA queues remain", sa_dir)
                    await asyncio.sleep(0.5)
                assert exists["rc"] == 1, exists
                # Requests must still reach and authenticate at the peer, and
                # its replies must actually carry the expired SPI on the wire.
                # No echo alone could also mean the outbound path was broken.
                capture = Wire(r, label + "-expired")
                capture.filter = f"ip proto 50 and src host {r.ipsec.peer} and dst host {r.ipsec.outer}"
                capture.snaplen = 64
                received = r.inner_echo.packets
                async with capture:
                    echoed = await echoes(r, 16)
                seqs = [seq for owner, seq in esp_sequences(capture.path) if owner == spi]
                withdrawn = {"retired": retired, "sa_dir": sa_dir, "echoed": echoed,
                             "peer_received": r.inner_echo.packets - received, "wire": seqs}
                r.record(label + "-withdrawal", withdrawn)
                assert withdrawn["peer_received"] == 16 and len(seqs) == len(set(seqs)) == 16, withdrawn
                assert echoed == 0, withdrawn
        finally:
            if task:
                await asyncio.gather(task, return_exceptions=True)
            restored = await restore_sa(r, spi, direction)
    assert restored, "the hard expiry left the fixture's SA in place"
    if direction == "in":
        assert restored != spi and await sa_state(r, restored, "in") is not None, restored
        await offloaded(r)
        recovered = await drive(r, lambda: echoes(r, 4), lambda s:
            flow_key in by_key(s) and s["ipsec_sas"] == admitted["ipsec_sas"] and
            s["ipsec_sa_cache"] == admitted["ipsec_sa_cache"])
        new = by_key(recovered)[flow_key]
        assert new["in_sa"] != "0", new
        cpu = await sec_counter(r.session, r.target, TARGET_WAN_IF, feeder)
    assert await echoes(r, 16) == 16, "the restored SA does not carry the tunnel"
    if direction == "in":
        after = await r.state()
        carried = by_key(after)[flow_key]
        submitted = await sec_counter(r.session, r.target, TARGET_WAN_IF, feeder) - cpu
        r.record(label + "-recovered", {"spi": restored, "before": recovered, "after": after, "cpu_fed": submitted})
        assert (carried["cookie"], carried["in_sa"]) == (new["cookie"], new["in_sa"]), (new, carried)
        assert int(carried["packets"]) - int(new["packets"]) == 16 and submitted == 0, (new, carried, submitted)


@pytest.mark.rfc("4301", section="4.4.2.1")
async def test_time_expiry(ipsec_service):
    """A time limit on an offloaded outbound SA fires through xfrm's own timer:
    soft, then hard, which deletes the state and retires its flow."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    outbound = next(key for key in keys([2], flows) if key[0] == TARGET_LAN_IF)
    async with XfrmMonitor(r, "ipsec-lifetime-time") as monitor:
        spi = await replace_outbound(r, "limit", "time-soft", "3", "limit", "time-hard", "6")
        try:
            await drive(r, lambda: blast(r, 500, 2_000), lambda state: outbound in by_key(state))
            await r.wait(lambda state: outbound not in by_key(state), timeout=10)
            expiries = await monitor.expiries(spi)
            assert [event["hard"] for event in expiries] == [0, 1], expiries
            assert await sa_state(r, spi) is None, "the hard expiry did not delete the state"
        finally:
            restored = await restore_sa(r, spi)
    assert restored and await echoes(r, 16) == 16


@pytest.mark.rfc("4303", section="3.3.3")
async def test_sequence_exhaustion(ipsec_service):
    """A non-ESN SA sends all seven supported tail sequences, ending at
    0xFFFFFFFE. SEC refuses 0xFFFFFFFF itself; no number wraps or is reused."""
    r = ipsec_service
    start = 0xFFFFFFFF - 8
    expected = list(range(start + 1, 0xFFFFFFFF))
    spi = await replace_outbound(r, "replay-oseq", hex(start))
    capture = Wire(r, "ipsec-sequence-exhaustion")
    capture.snaplen = 64
    async with capture:
        echoed = await echoes(r, 32)
    seqs = [seq for owner, seq in esp_sequences(capture.path) if owner == spi]
    r.record("ipsec-sequence-exhaustion", {"spi": spi, "echoed": echoed, "wire": seqs,
                                          "expected": expected})
    assert echoed == len(expected) and seqs == expected, (echoed, seqs, expected)
    await replace_outbound(r)
    assert await echoes(r, 16) == 16, "a fresh SA does not carry the tunnel"


def esp_sequences(path):
    """(SPI, sequence) of every bare ESP frame in a capture, in capture order.
    A plain walk, like reused_sequences()."""
    data, frames, offset = Path(path).read_bytes(), [], 24
    while offset + 16 <= len(data):
        length = struct.unpack_from("<I", data, offset + 8)[0]
        frame = data[offset + 16:offset + 16 + length]
        offset += 16 + length
        l3 = 18 if frame[12:14] == b"\x81\x00" else 14
        if len(frame) >= l3 + 28 and frame[l3 + 9] == 50:
            frames.append(struct.unpack_from("!II", frame, l3 + (frame[l3] & 0xF) * 4))
    return frames


SEQUENCE_COUNT = 16
# 2^32 - 2^28: the first outbound sequence number the accounting pass treats
# as close enough to the end of a non-ESN SA's space to ask for a rekey.
EXHAUSTING = 0xF0000000
# Named by no policy, so this SA never carries the fixture's traffic.
EXHAUSTING_REQID = "49303"


@pytest.mark.parametrize("feeder", ["cpu", "classifier"])
async def test_outbound_esn_rollover(ipsec_service, feeder):
    """Both SEC feeders cross the low-word boundary with one 64-bit counter.

    The software peer authenticates the implicit high word. The classifier
    case is admitted before the wrap, so cold-flow CPU traffic cannot stand
    in for the hardware feeder at the boundary."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    label = f"ipsec-outbound-esn-{feeder}"
    target = (1 << 32) | 0xFFFFFFF7
    start = target if feeder == "cpu" else (1 << 32) | 0xFFFFFE00
    spi = await replace_outbound(
        r, "flag", "esn", "replay-oseq-hi", "1", "replay-oseq", hex(start & 0xFFFFFFFF),
        peer=("flag", "esn", "replay-seq-hi", "1", "replay-seq", hex(start & 0xFFFFFFFF)))
    await offloaded(r)
    outbound = next(key for key in keys([2], flows) if key[0] == TARGET_LAN_IF)
    record = {"spi": spi, "start": start, "publication": []}
    exempt = ["POSTROUTING", "-s", LAN_INNER, "-d", INNER, "-p", "icmp", "-j", "ACCEPT"]
    exempted = False

    async def position(expected):
        # GETAE and GETSA both publish the live PDB. Each completed round trip
        # has already left SEC, so these quiet boundaries have exact values.
        replay = await sa_replay_state(r.target, r.session, dst=r.ipsec.peer, spi=spi)
        state = await sa_state(r, spi)
        samples = record["publication"]
        samples.append({"expected": expected, "getae": replay["oseq"], "state": state})
        assert state and replay["oseq"] == state["oseq"] == expected, record
        assert len(samples) == 1 or samples[-2]["getae"] <= replay["oseq"], record

    async def send(count):
        if feeder == "classifier":
            assert await echoes(r, count) == count, (label, count)
        else:
            result = await asyncio.to_thread(
                r.lan.run, f"ping -n -q -c {count} -i 0.02 -W 1 -I {LAN_INNER} {INNER}", timeout=count + 5)
            received = re.search(r"(\d+) packets transmitted, (\d+) received", result.stdout)
            assert result.rc == 0 and received and tuple(map(int, received.groups())) == (count, count), result.stdout

    try:
        if feeder == "cpu":
            await command(r.target, r.session, "iptables", "-t", "nat", "-I", *exempt)
            exempted = True
        else:
            warmed = 0

            async def warm():
                nonlocal warmed
                warmed += 4
                assert warmed <= 256, "the classifier did not admit the flow before the rollover headroom ran out"
                await send(4)

            await drive(r, warm, lambda s: outbound in by_key(s) and by_key(s)[outbound]["sa"] != "0")
            await position(start + warmed)
            # Align only after admission. Replacing a warmed SA here would
            # retire its flow, leaving the rollover to the CPU again.
            await send(target - start - warmed)
        await position(target)
        before = await r.state()
        cpu = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc")
        peer = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        capture = Wire(r, label)
        capture.snaplen = 64
        sent = 0
        async with capture:
            for count in (4, 8, 4):
                await send(count)
                sent += count
                await position(target + sent)
        after = await r.state()
        submitted = await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc") - cpu
        seqs = [seq for owner, seq in esp_sequences(capture.path) if owner == spi]
        expected = [(target + n) & 0xFFFFFFFF for n in range(1, 17)]
        record.update(before=before, after=after, cpu_fed=submitted, wire=seqs,
                      expected=expected, peer_refused=peer_errors(peer))
        assert seqs == expected and not record["peer_refused"], record
        assert submitted == (16 if feeder == "cpu" else 0), record
        if feeder == "classifier":
            old, new = by_key(before)[outbound], by_key(after)[outbound]
            assert old["sa"] != "0" and (old["cookie"], old["sa"]) == (new["cookie"], new["sa"]), record
            assert int(new["packets"]) - int(old["packets"]) == 16, record
            assert (before["installs"], before["deletes"]) == (after["installs"], after["deletes"]), record
    finally:
        r.record(label, record)
        if exempted:
            await command(r.target, r.session, "iptables", "-t", "nat", "-D", *exempt)


async def test_starting_sequence(ipsec_service):
    """An outbound SA sends from the sequence number it was installed with,
    and SEC's position comes back into the state.

    Without ESN, `replay-oseq 0x1000` puts 0x1001 on the wire first. With ESN,
    oseq-hi 1 and oseq 5 put 6 on the wire and the high word into the ICV, so
    only a peer expecting that high word accepts the frames. And an SA
    installed within 2^28 of the end of its 32-bit space soft-expires with no
    traffic at all."""
    r = ipsec_service
    cases = [
        ("oseq", 0x1000, ("replay-oseq", "0x1000"), ()),
        ("esn", 1 << 32 | 5, ("flag", "esn", "replay-oseq-hi", "1", "replay-oseq", "5"),
         ("flag", "esn", "replay-seq-hi", "1", "replay-seq", "5")),
    ]
    async with XfrmMonitor(r, "ipsec-starting-sequence") as monitor:
        spis, records = [], []
        for name, start, options, peer in cases:
            spi = await replace_outbound(r, *options, peer=peer)
            spis.append(spi)
            before = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
            capture = Wire(r, f"ipsec-starting-sequence-{name}")
            capture.snaplen = 64
            async with capture:
                echoed = await echoes(r, SEQUENCE_COUNT)
            seqs = [seq for owner, seq in esp_sequences(capture.path) if owner == spi]
            refused = peer_errors(before)
            first = (start + 1) & 0xFFFFFFFF
            record = {"case": name, "spi": spi, "echoed": echoed, "wire": seqs, "peer_refused": refused}
            records.append(record)
            r.record("ipsec-starting-sequence", records)
            assert echoed == SEQUENCE_COUNT and not refused, record
            assert seqs and seqs[0] == first, record
            assert sorted(seqs) == list(range(first, first + SEQUENCE_COUNT)), record
            # SEC numbers the frames, and its position comes back into the
            # state as SEC has it, within about a pass: the last number sent.
            # A re-add of the SA is what goes past it, never the state.
            deadline = time.monotonic() + 3
            while not (start + SEQUENCE_COUNT <= (figures := await sa_state(r, spi))["oseq"]
                       <= start + 3 * SEQUENCE_COUNT):
                assert time.monotonic() < deadline, (record, figures)
                await asyncio.sleep(0.25)
            record["oseq"] = figures["oseq"]
        spi = 0xAB000000 | secrets.randbits(24)
        await r.ipsec.add(r.target, "state", r.ipsec.state("out", spi), "mode", "tunnel",
                          "reqid", EXHAUSTING_REQID, *r.ipsec.transform.algorithms,
                          "replay-oseq", hex(EXHAUSTING), "offload", "packet", "dev", TARGET_WAN_IF, "dir", "out")
        added = time.monotonic()
        while not await monitor.expiries(spi):
            assert time.monotonic() - added < 4, "a nearly exhausted SA was not asked to rekey"
            await asyncio.sleep(0.2)
        elapsed = time.monotonic() - added
        # Another pass must not raise it again, and the state stays.
        await asyncio.sleep(1.5)
        expiries = await monitor.expiries(spi)
        figures = await sa_state(r, spi)
        records.append({"case": "exhausting", "spi": spi, "seconds": elapsed, "state": figures,
                        "expiries": [{**event, "time": event["time"].isoformat()} for event in expiries]})
        r.record("ipsec-starting-sequence", records)
        assert [event["hard"] for event in expiries] == [0], expiries
        assert elapsed <= 2.5, elapsed
        assert figures and (figures["packets"], figures["oseq"]) == (0, EXHAUSTING), figures
        # Neither SA above came near the end of its space.
        for spi in spis:
            assert not await monitor.expiries(spi), spi


async def replace_inbound(r, *options, peer=()):
    """Swap the fixture's inbound SA for one installed with `options` on the
    DUT and `peer` on the WAN host, which sends on it."""
    spi = await r.ipsec.prepare_peer("in", *peer)
    await r.ipsec.remove("in")
    await r.ipsec.install("in", spi, *options)
    return spi


# Where an inbound ESN SA starts, as (high word, low word), and how many echoes
# cross it. The first sits in the window-width after a rollover, where SEC holds
# its stored high word back (RFC 4303 App. A; ipsec.md); the second is the
# control outside it; the third crosses the rollover itself, 32 frames before
# it and 48 after.
ESN_WINDOW = 64
ESN_CASES = {
    "after-rollover": ((1, 5), 20),
    "control": ((1, 200), 20),
    "across-rollover": ((0, 0xFFFFFFE0), 80),
}


@pytest.mark.parametrize("case", list(ESN_CASES))
async def test_inbound_esn(ipsec_service, case):
    """An inbound ESN SA authenticates with the right high word wherever its
    window starts and across the low word wrapping (RFC 4303 2.2.1), and the
    replay state published back into xfrm carries the high word over."""
    r = ipsec_service
    (hi, lo), count = ESN_CASES[case]
    spi = await replace_inbound(
        r, "flag", "esn", "replay-window", str(ESN_WINDOW),
        "replay-seq-hi", str(hi), "replay-seq", hex(lo),
        peer=("flag", "esn", "replay-oseq-hi", str(hi), "replay-oseq", hex(lo)))
    before = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
    echoed = await echoes(r, count)
    last = (hi << 32 | lo) + count
    deadline = time.monotonic() + 3
    while True:
        state = await sa_replay_state(r.target, r.session, dst=r.ipsec.outer, spi=spi)
        if state["seq"] == last or time.monotonic() > deadline:
            break
        await asyncio.sleep(0.25)
    figures = await sa_state(r, spi, "in")
    record = {"case": case, "spi": spi, "echoed": echoed, "replay": state, "sa": figures,
              "peer_refused": peer_errors(before), "start": [hi, lo], "last": last}
    r.record(f"ipsec-inbound-esn-{case}", record)
    assert echoed == count, record
    assert figures["replay"][1:] == [0, 0], record
    assert state["seq"] == last, record

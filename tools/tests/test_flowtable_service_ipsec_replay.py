"""Sequence numbers and anti-replay on offloaded SAs, across ciphers and feeders.

An SA's SEC queue has two feeders in each direction. Outbound, the classifier
enqueues offloaded flows and the CPU everything else. Inbound, the classifier
steers whole ESP frames to SEC by SPI, while an outer IP fragment cannot match
that entry: the CPU reassembles it, and xfrm_input() hands it to the same queue
(the software SEC submit, `tx todec`). Whichever feeder a frame takes, one
shared descriptor holds the SA's sequence state, so a sequence number seen
through one feeder must be refused through the other.

AEAD SAs take a different sharing policy from CBC+HMAC (SERIAL without
SAVECTX, cdx_ipsec_sh_desc_hdr_flags()), and each ICV length is its own
descriptor, so the traffic and shared-sequence proofs are repeated for them.

The replayed ESP is built on this host with the fixture's keys. The suite's
scapy has no cryptography backend, so the cipher runs in this host's kernel
through AF_ALG: the same implementation the peer's own SAs use.
"""
from __future__ import annotations

import asyncio
import base64
from collections import Counter
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import socket
import struct

import pytest

from _ipsec_helpers import endpoints_down, endpoints_up
from _topology import TARGET_WAN_IF, lan_run
from test_flowtable_connections import peer
from test_flowtable_offload import DPORT, WAN_IP, command, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import warm
from test_flowtable_service import FIRST
from test_flowtable_service_ipsec import (INNER, LAN_INNER, REQIDS, Transform, flows_for, hardware,
                                          ipsec_service, negative, plaintext_probe, sec_counter)  # noqa: F401
from test_flowtable_service_ipsec import test_flowtable_service_ipsec_shared_sequence as shared_sequence

# An AES-128 key followed by the four-byte salt RFC 4106 and 4543 take with it.
GCM_KEY = "0x" + "c3" * 20
# The AEAD transforms SEC carries. GMAC (rfc4543) is not one of them: see
# test_ipsec_gmac_refused.
AEAD = {
    "rfc4106-icv16": Transform(("aead", "rfc4106(gcm(aes))", GCM_KEY, "128")),
    "rfc4106-icv8": Transform(("aead", "rfc4106(gcm(aes))", GCM_KEY, "64")),
}
GMAC = ("aead", "rfc4543(gcm(aes))", GCM_KEY, "128")
# Counters on this host that move when it refuses a frame the DUT produced.
PEER_ERRORS = ("XfrmInError", "XfrmInHdrError", "XfrmInNoStates", "XfrmInStateProtoError",
               "XfrmInStateSeqError", "XfrmInStateMismatch", "XfrmInStateInvalid", "XfrmInTmplMismatch")


def xfrm_mib(text):
    return {name: int(value) for name, value in (line.split() for line in text.splitlines() if line.strip())}


def peer_errors(before):
    """What this host, the peer that decrypts the DUT's frames, refused since
    `before`."""
    now = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
    return {name: now[name] - before[name] for name in PEER_ERRORS if now[name] != before[name]}


async def sa_state(r, spi, direction="out"):
    """`ip -s xfrm state` figures for one of the DUT's SAs, or None once it is
    gone. Packet offload leaves them to the adapter's accounting pass, which
    publishes SEC's per-SA counters once a second."""
    result = await command(r.target, r.session, "ip", "-s", "xfrm", "state", "get",
                           *r.ipsec.state(direction, spi), check=False)
    if result["rc"]:
        return None
    text = result["stdout"]
    current = re.search(r"lifetime current:\s*(\d+)\(bytes\), (\d+)\(packets\)\s*add (\S+ \S+) use (-|\S+ \S+)", text)
    assert current, text
    legacy = re.search(r"anti-replay context: seq 0x([0-9a-f]+), oseq 0x([0-9a-f]+)", text)
    esn = re.search(r"oseq-hi 0x([0-9a-f]+), oseq 0x([0-9a-f]+)", text)
    oseq = (int(legacy.group(2), 16) if legacy else
            int(esn.group(1), 16) << 32 | int(esn.group(2), 16) if esn else None)
    stats = re.search(r"stats:\s*replay-window (\d+) replay (\d+) failed (\d+)", text)
    return {"bytes": int(current.group(1)), "packets": int(current.group(2)), "use": current.group(4),
            "oseq": oseq, "replay": [int(value) for value in stats.groups()] if stats else None}


async def offloaded(r):
    """Both of the fixture's SAs are in hardware and carry its transform."""
    states = await r.ipsec.states()
    assert len(states) == 2, states
    for state in states:
        assert r.ipsec.transform.algorithms[1] in state, state
        assert re.search(rf"crypto offload parameters: dev {TARGET_WAN_IF} dir (in|out) mode packet", state), state


def aead_label(r):
    algorithms = r.ipsec.transform.algorithms
    return f"ipsec-aead-{algorithms[1].split('(')[0]}-{algorithms[-1]}"


@pytest.mark.parametrize("ipsec_service", list(AEAD.values()), ids=list(AEAD), indirect=True)
async def test_flowtable_service_ipsec_aead_traffic(ipsec_service):
    """AEAD SAs carry the tunnel in hardware both ways, as CBC+HMAC does, and
    the peer authenticates every frame SEC produced."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    label = aead_label(r)
    await offloaded(r)
    before = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
    async with peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400, listen_addresses=[INNER]) as p:
        await warm(r, p, [0, 1, 2, 3], label, flows[:4])
        await hardware(r, p, label + "-hardware", flows[:4])
        await plaintext_probe(r, p, label + "-plaintext")
        await negative(r, p)
        # A connection opened while the tunnel is already in hardware.
        await p.rpc("open", [4])
        await warm(r, p, [0, 1, 2, 3, 4], label + "-new", flows[:5])
        await hardware(r, p, label + "-new-hardware", flows[:5])
    refused = peer_errors(before)
    r.record(label + "-peer-errors", refused)
    assert not refused, f"the peer refused frames SEC encrypted: {refused}"


@pytest.mark.parametrize("ipsec_service", [AEAD["rfc4106-icv16"]], ids=["rfc4106-icv16"], indirect=True)
async def test_flowtable_service_ipsec_aead_shared_sequence(ipsec_service):
    """Both SEC feeders of one GCM SA draw from one sequence counter.

    GCM runs its shared descriptor SERIAL without SAVECTX, unlike CBC+HMAC,
    and it is where the reuse this guards against was first measured, as
    replay-window rejections at the peer."""
    await offloaded(ipsec_service)
    await shared_sequence(ipsec_service)


def _afalg(kind, name, key, iv, data, *, assoclen=0, authsize=0):
    with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as alg:
        alg.bind((kind, name))
        alg.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
        if authsize:
            alg.setsockopt(socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, authsize)
        operation, _ = alg.accept()
        with operation:
            operation.sendmsg_afalg([data], op=socket.ALG_OP_ENCRYPT, iv=iv, assoclen=assoclen)
            return operation.recv(len(data) + authsize)


def esp(algorithms, spi, seq, inner):
    """Tunnel-mode ESP for `inner`, from the header to the ICV (RFC 4303).

    `algorithms` are the `ip xfrm state` arguments the SA was installed with:
    AES-CBC with HMAC-SHA256, or RFC 4106 GCM, whose output already carries
    the header and IV it was given as associated data."""
    head = struct.pack("!II", spi, seq)
    if algorithms[0] == "aead":
        _, name, key, icv = algorithms
        assert name == "rfc4106(gcm(aes))", algorithms
        pad = -(len(inner) + 2) % 4
        plain = inner + bytes(range(1, pad + 1)) + bytes([pad, socket.IPPROTO_IPIP])
        iv = os.urandom(8)
        # The kernel's rfc4106 authenticates the associated data less its
        # trailing eight bytes, which is where ESP puts the IV.
        return _afalg("aead", name, bytes.fromhex(key[2:]), iv, head + iv + plain,
                      assoclen=len(head + iv), authsize=int(icv) // 8)
    _, cipher, cipher_key, _, auth, auth_key, bits = algorithms
    assert (cipher, auth) == ("cbc(aes)", "hmac(sha256)"), algorithms
    pad = -(len(inner) + 2) % 16
    plain = inner + bytes(range(1, pad + 1)) + bytes([pad, socket.IPPROTO_IPIP])
    iv = os.urandom(16)
    body = head + iv + _afalg("skcipher", cipher, bytes.fromhex(cipher_key[2:]), iv, plain)
    return body + hmac.new(bytes.fromhex(auth_key[2:]), body, hashlib.sha256).digest()[:int(bits) // 8]


# The injected datagrams leave the tunnel toward this LAN port, outside the
# service's offload scope: a flow whose every packet carries a sec_path is
# never offered to the flowtable anyway.
RPORT = FIRST + 8
LISTENER = "/tmp/ask-ipsec-replay-listener.py"
DELIVERED = "/tmp/ask-ipsec-replay-delivered"
LISTENER_PID = "/tmp/ask-ipsec-replay-listener.pid"
LISTENER_SECONDS = 240


def listener_script(marker):
    """Record every marked datagram reaching the LAN end as SPI and sequence."""
    return f"""
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({LAN_INNER!r}, {RPORT}))
s.settimeout(0.5)
marker = bytes.fromhex({marker.hex()!r})
end = time.monotonic() + {LISTENER_SECONDS}
with open({DELIVERED!r}, "w") as out:
    out.write("READY\\n")
    out.flush()
    while time.monotonic() < end:
        try:
            data = s.recv(4096)
        except socket.timeout:
            continue
        if data.startswith(marker):
            out.write(data[len(marker):len(marker) + 8].hex() + "\\n")
            out.flush()
"""


async def delivered(r):
    result = await lan_run(r.lan, f"cat {DELIVERED}", 10)
    assert result.rc == 0 and "READY" in result.stdout, result.stdout
    return Counter((int(line[:8], 16), int(line[8:], 16))
                   for line in re.findall(r"^([0-9a-f]{16})\r?$", result.stdout, re.M))


async def arrivals(r, spi, seen, expected):
    """The sequence numbers of `spi` that reached the LAN end since `seen`.

    Waits for the expected count, then a little longer: a duplicate travels
    no slower than its original, so anything extra is in by then."""
    def since(now):
        return Counter({seq: count for (owner, seq), count in (now - seen).items() if owner == spi})
    got = Counter()
    for _ in range(15 if expected else 0):
        await asyncio.sleep(0.2)
        got = since(await delivered(r))
        if sum(got.values()) >= expected:
            break
    await asyncio.sleep(0.5 if expected else 1.0)
    return since(await delivered(r))


# The /proc/net/xfrm_stat counters the adapter folds SEC's protocol refusals
# into. Which of them a refusal lands in follows the class the FMan microcode
# counted it in, and that is not reliable -- replays have been measured in
# its catch-all, other_errs, which folds to XfrmInError -- so only their sum
# is held to account. It leaves out SEC's faults, which a replay burst does
# not cause; the exact count of every refusal is ipsec_sec_refused in
# /proc/cdx_flowtable.
SEC_REFUSAL_MIBS = ("XfrmInStateSeqError", "XfrmInStateProtoError", "XfrmInError", "XfrmOutStateSeqError")


async def dut_counters(r):
    snmp = [line.split()[1:] for line in (await read(r.target, r.session, "/proc/net/snmp")).splitlines()
            if line.startswith("Ip:")]
    mib = xfrm_mib(await read(r.target, r.session, "/proc/net/xfrm_stat"))
    state = await r.state()
    return {"todec": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx todec"),
            "reasm": int(dict(zip(*snmp))["ReasmOKs"]),
            "refusals": sum(mib[name] for name in SEC_REFUSAL_MIBS),
            **{name: mib[name] for name in SEC_REFUSAL_MIBS},
            # Every class the microcode counted, and their exact total.
            **{key: value for key, value in state.items() if key.startswith("ipsec_sec_refused")}}


class Inbound:
    """One inbound SA on the DUT and the peer frames this host sends it."""

    def __init__(self, r, marker, algorithms, window):
        self.r, self.marker, self.algorithms, self.window = r, marker, algorithms, window
        self.spi = 0xAA000000 | secrets.randbits(24)
        self.frames = {}
        self.ident = secrets.randbits(16)

    async def install(self):
        # The fixture's receiving policy names this reqid, so what SEC
        # decrypts for this SA is forwarded as the fixture's own SA would be.
        # Windows above 32 reach the kernel as an ESN-format replay state.
        await self.r.ipsec.add(self.r.target, "state", self.r.ipsec.state("in", self.spi),
                               "mode", "tunnel", "reqid", REQIDS["in"], *self.algorithms,
                               "replay-window", str(self.window),
                               "offload", "packet", "dev", TARGET_WAN_IF, "dir", "in")

    def packet(self, seq):
        """The frame for `seq`, built once: every replay is byte-identical."""
        from scapy.all import IP, UDP, Raw
        if seq not in self.frames:
            payload = self.marker + struct.pack("!II", self.spi, seq)
            inner = IP(src=INNER, dst=LAN_INNER, ttl=64) / UDP(sport=DPORT, dport=RPORT) / Raw(payload.ljust(64, b"."))
            self.ident = (self.ident + 1) & 0xFFFF
            self.frames[seq] = IP(src=WAN_IP, dst=self.r.ipsec.outer, ttl=64, id=self.ident, proto=50) / Raw(
                esp(self.algorithms, self.spi, seq, bytes(inner)))
        return self.frames[seq]

    async def send(self, frames):
        from scapy.all import Ether, fragment, sendp
        wire = []
        for seq, form in frames:
            packet = self.packet(seq)
            if form == "fragments":
                # A fresh outer ID, so no reassembly queue can mix it with
                # another datagram. The outer header is not authenticated.
                self.ident = (self.ident + 1) & 0xFFFF
                packet = packet.copy()
                packet.id = self.ident
                parts = fragment(packet, fragsize=48)
                assert len(parts) >= 2, parts
            else:
                parts = [packet]
            wire += [Ether(src=self.r.wan_mac, dst=self.r.dut_wan_mac) / part for part in parts]
        await asyncio.to_thread(sendp, wire, iface=self.r.wan_if, inter=0.005, verbose=False)


def phase(name, frames, delivered_seqs, *, rejected=0):
    """What one burst must do: which sequence numbers reach the LAN end, how
    many frames SEC must refuse, and how many reach it through the CPU."""
    cpu = sum(1 for _, form in frames if form == "fragments")
    return {"name": name, "frames": frames, "delivered": Counter(delivered_seqs),
            "rejected": rejected, "cpu": cpu}


def whole(*seqs):
    return [(seq, "whole") for seq in seqs]


def fragments(*seqs):
    return [(seq, "fragments") for seq in seqs]


def both_feeders(base):
    """A 32-wide window across both feeders: each replay is refused by the
    feeder that did not see the original, in both orders, and the window's
    edge is where the configuration put it."""
    a, d, f = range(base, base + 8), range(base + 8, base + 16), range(base + 16, base + 24)
    edge = base + 100
    return [
        phase("fresh-whole", whole(*a), a),
        phase("replay-whole", whole(*a), [], rejected=8),
        phase("replay-fragments", fragments(*a), [], rejected=8),
        phase("fresh-fragments", fragments(*d), d),
        phase("replay-whole-after-fragments", whole(*d), [], rejected=8),
        phase("fresh-whole-after-replays", whole(*f), f),
        phase("edge", whole(edge + 40), [edge + 40]),
        # 35 behind the highest is past a 32-wide window, 20 behind is not.
        phase("too-old", whole(edge + 5), [], rejected=1),
        phase("late-inside", whole(edge + 20), [edge + 20]),
    ]


def rounded_up(base):
    """A 48-wide window rides SEC's 64-entry one: 50 behind the highest is
    still accepted, 70 behind is not."""
    return [
        phase("fresh", whole(base, base + 80), [base, base + 80]),
        phase("late-inside-64", whole(base + 30), [base + 30]),
        phase("too-old-for-64", whole(base + 10), [], rejected=1),
        phase("replay", whole(base + 80), [], rejected=1),
    ]


def disabled(base):
    """A zero window turns anti-replay off: replays and late frames pass."""
    return [
        phase("fresh", whole(base), [base]),
        phase("replay-whole", whole(base), [base]),
        phase("replay-fragments", fragments(base), [base]),
        phase("ahead", whole(base + 100), [base + 100]),
        phase("far-behind", whole(base - 50), [base - 50]),
    ]


CBC = Transform().algorithms
REPLAY_CASES = [
    ("cbc-32", CBC, 32, both_feeders(1000)),
    ("rfc4106-32", AEAD["rfc4106-icv16"].algorithms, 32, both_feeders(1000)),
    ("cbc-48", CBC, 48, rounded_up(2000)),
    ("cbc-0", CBC, 0, disabled(3000)),
]


async def test_flowtable_service_ipsec_replay_window(ipsec_service):
    """Inbound anti-replay in hardware, as the SA's window configures it.

    Whole frames reach SEC through the classifier and fragments through the
    CPU, and the two share one window. Every datagram is delivered to the LAN
    end exactly as often as its window allows, and every frame the window
    refuses is counted: once in the FMan microcode's refusal total, which
    /proc/cdx_flowtable carries, and once across the /proc/net/xfrm_stat
    counters the adapter folds the microcode's non-fault classes into, which
    is where the microcode files replays and late frames. Per SA it is counted
    nowhere; SEC keeps no such count."""
    r = ipsec_service
    marker = secrets.token_bytes(16)
    script = base64.b64encode(listener_script(marker).encode()).decode()
    records, sas = [], []
    # A background process with a pidfile: the LAN console is one channel,
    # and the listener has to outlive this command.
    started = await lan_run(r.lan, f"echo {script} | base64 -d > {LISTENER} && rm -f {DELIVERED} && "
                                   f"(nohup python3 {LISTENER} >/dev/null 2>&1 & echo $! > {LISTENER_PID}) && "
                                   f"for i in $(seq 1 25); do grep -q READY {DELIVERED} 2>/dev/null && break; "
                                   f"sleep 0.2; done; cat {DELIVERED}", 20)
    try:
        assert started.rc == 0 and "READY" in started.stdout, started.stdout
        initial = await dut_counters(r)
        rejected, accepted = 0, Counter()
        for name, algorithms, window, phases in REPLAY_CASES:
            sa = Inbound(r, marker, algorithms, window)
            await sa.install()
            sas.append(sa)
            accepted[sa.spi] = 0
            for step in phases:
                before, seen = await dut_counters(r), await delivered(r)
                await sa.send(step["frames"])
                got = await arrivals(r, sa.spi, seen, sum(step["delivered"].values()))
                after = await dut_counters(r)
                record = {"case": name, "phase": step["name"], "delivered": sorted(got.elements()),
                          "expected": sorted(step["delivered"].elements()),
                          "counters": {key: after[key] - before[key] for key in after}}
                records.append(record)
                r.record("ipsec-replay-window", records)
                assert got == step["delivered"], record
                assert (record["counters"]["todec"], record["counters"]["reasm"]) == (step["cpu"], step["cpu"]), (
                    "whole frames must reach SEC through the classifier and fragments through the CPU", record)
                rejected += step["rejected"]
                accepted[sa.spi] += sum(got.values())
        # The accounting pass publishes SEC's figures, and reads the
        # microcode's refusal count, once a second.
        await asyncio.sleep(1.5)
        figures = {sa.spi: await sa_state(r, sa.spi, "in") for sa in sas}
        for _ in range(8):
            final = await dut_counters(r)
            counted = {key: final[key] - initial[key] for key in ("refusals", "ipsec_sec_refused")}
            if min(counted.values()) >= rejected:
                break
            await asyncio.sleep(0.5)
        errors = [line for line in (await command(r.target, r.session, "dmesg"))["stdout"].splitlines()
                  if "IPsec SEC error" in line or "SEC could not process" in line][-64:]
        r.record("ipsec-replay-window-accounting", {
            "refused": rejected, "counted": counted, "sec_errors": errors,
            "classes": {key: final[key] - initial[key] for key in final
                        if key.startswith("ipsec_sec_refused_") or key.startswith("Xfrm")},
            "sas": {f"{spi:#x}": {"accepted": accepted[spi], **figures[spi]} for spi in accepted}})
        # SEC counts the frames it decrypted, whichever feeder brought them,
        # and not the ones its window refused: a replay must not age an SA.
        assert {spi: figures[spi]["packets"] for spi in accepted} == dict(accepted), (figures, accepted)
        # Every frame SEC refused, through either feeder, is counted once:
        # by the microcode, whose total /proc/cdx_flowtable carries, and
        # across the xfrm_stat counters, since the microcode files replays
        # and late frames in a class that is folded there (measured: its
        # catch-all, other_errs, never a fault class).
        assert counted["ipsec_sec_refused"] == rejected, (
            f"SEC refused {rejected} replayed or late frames and the microcode's count moved by "
            f"{counted['ipsec_sec_refused']}")
        assert counted["refusals"] == rejected, (
            f"SEC refused {rejected} replayed or late frames and {'+'.join(SEC_REFUSAL_MIBS)} moved by "
            f"{counted['refusals']}; a hardware refusal must be counted where Linux counts its own")
    finally:
        await lan_run(r.lan, f"kill $(cat {LISTENER_PID}) 2>/dev/null; rm -f {LISTENER} {DELIVERED} {LISTENER_PID}", 10)
        await command(r.target, r.session, "conntrack", "-D", "-p", "udp", "--orig-src", INNER,
                      "--orig-dst", LAN_INNER, "--dport", str(RPORT), check=False)


# A documentation-range pair of its own, so no other IPsec test's endpoints
# are disturbed. Nothing is sent: the peer does not exist.
LIMIT_LOCAL, LIMIT_PEER = "198.18.105.1", "198.18.105.2"


async def test_ipsec_replay_window_limit(aiohttp_session, target_agent, splat_window):
    """SEC keeps at most a 128-entry window. A wider one is refused with the
    reason rather than silently narrowed, which would drop late frames the
    configuration accepts; 128 itself installs."""
    await endpoints_up(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=LIMIT_LOCAL,
                       peer=LIMIT_PEER, lladdr="02:00:00:00:05:02")
    results = {}
    try:
        for window, spi in ((128, 0x4D6F0080), (200, 0x4D6F00C8)):
            identity = ["src", LIMIT_PEER, "dst", LIMIT_LOCAL, "proto", "esp", "spi", hex(spi)]
            added = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "add", *identity,
                                  "mode", "tunnel", "reqid", "49305", *CBC, "replay-window", str(window),
                                  "offload", "packet", "dev", TARGET_WAN_IF, "dir", "in", check=False)
            shown = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "get", *identity,
                                  check=False)
            results[window] = {"add": added, "get": shown}
            if added["rc"] == 0:
                await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "delete", *identity)
        assert results[128]["add"]["rc"] == 0, results[128]
        assert "replay_window 128" in results[128]["get"]["stdout"], results[128]
        assert re.search(rf"crypto offload parameters: dev {TARGET_WAN_IF} dir in mode packet",
                         results[128]["get"]["stdout"]), results[128]
        refused = results[200]["add"]
        assert refused["rc"] != 0, results[200]
        assert "cdx: SEC's anti-replay window is at most 128 packets" in refused["stderr"], refused
        # Packet offload has no software fallback: nothing was installed.
        assert results[200]["get"]["rc"] != 0, results[200]
    finally:
        for spi in (0x4D6F0080, 0x4D6F00C8):
            await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "delete", "src", LIMIT_PEER,
                          "dst", LIMIT_LOCAL, "proto", "esp", "spi", hex(spi), check=False)
        await endpoints_down(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=LIMIT_LOCAL,
                             peer=LIMIT_PEER)


# Again a pair, SPIs and a reqid of its own, and again nothing is sent.
GMAC_LOCAL, GMAC_PEER = "198.18.108.1", "198.18.108.2"
GMAC_REQID = "49307"
GMAC_STATES = {
    "out": ["src", GMAC_LOCAL, "dst", GMAC_PEER, "proto", "esp", "spi", hex(0x474D0001)],
    "in": ["src", GMAC_PEER, "dst", GMAC_LOCAL, "proto", "esp", "spi", hex(0x474D0002)],
}


async def test_ipsec_gmac_refused(aiohttp_session, target_agent, splat_window):
    """AES-GMAC is refused for packet offload in both directions, with the
    reason, and the same state installs in software.

    SEC runs GMAC as GCM with the payload left unencrypted, so its ICV covers
    the ESP header and payload but not the IV, which RFC 4543 and every
    software peer authenticate. Offloaded, every frame the SA sent failed the
    peer's check and every compliant frame it received was dropped."""
    await endpoints_up(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=GMAC_LOCAL,
                       peer=GMAC_PEER, lladdr="02:00:00:00:08:02")
    try:
        for direction, identity in GMAC_STATES.items():
            added = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "add", *identity,
                                  "mode", "tunnel", "reqid", GMAC_REQID, *GMAC,
                                  "offload", "packet", "dev", TARGET_WAN_IF, "dir", direction, check=False)
            shown = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "get", *identity,
                                  check=False)
            result = {"direction": direction, "add": added, "get": shown}
            assert added["rc"] != 0, result
            assert "cdx: SEC's AES-GMAC leaves the IV out of the ICV" in added["stderr"], result
            # Packet offload has no software fallback: nothing was installed.
            assert shown["rc"] != 0, result
        # Asked for without offload, it is software's, which follows the RFC.
        identity = GMAC_STATES["out"]
        added = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "add", *identity,
                              "mode", "tunnel", "reqid", GMAC_REQID, *GMAC, check=False)
        shown = await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "get", *identity,
                              check=False)
        result = {"add": added, "get": shown}
        assert added["rc"] == 0 and shown["rc"] == 0, result
        assert GMAC[1] in shown["stdout"], result
        assert "crypto offload parameters" not in shown["stdout"], result
    finally:
        for identity in GMAC_STATES.values():
            await command(target_agent, aiohttp_session, "ip", "xfrm", "state", "delete", *identity,
                          check=False)
        await endpoints_down(target_agent, aiohttp_session, iface=TARGET_WAN_IF, local=GMAC_LOCAL,
                             peer=GMAC_PEER)

"""A packet-offloaded transport-mode SA between the DUT and a software peer on
the WAN host, either family and either way."""
from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import struct
import time

from _flowtable_rig import (read)
from _flowtable_service_ipsec_replay import (SEC_REFUSAL_MIBS, xfrm_mib)
from _ipsec_inbound_flow_offload import (AUTH, CIPHER, sec_counter)
from _topology import TARGET_WAN_IF
from ask_orch.commands import console_python

REQID = "49521"
ALGORITHMS = ["mode", "transport", "reqid", REQID, "enc", "cbc(aes)", CIPHER,
              "auth-trunc", "hmac(sha256)", AUTH, "128"]


async def transport_sa(r, wan, step, outer, peer, spi, selector, policy_first=False,
                       direction="out"):
    """The SA between the DUT's `outer` address and `peer` on the WAN host,
    `direction` as the DUT sees it, with the policy selecting `selector` on
    both ends: the DUT's half packet-offloaded, the WAN host's ordinary
    software. The receiving end keeps a 32-packet replay window.
    `policy_first` installs the policies before the states, the order a trap
    policy has them in. `step` runs a command and records how to undo it."""
    src, dst = (outer, peer) if direction == "out" else (peer, outer)
    state = ["src", src, "dst", dst, "proto", "esp", "spi", hex(spi)]
    template = ["tmpl", "src", src, "dst", dst, "proto", "esp", "mode", "transport",
                "reqid", REQID, "level", "required"]
    window = ["replay-window", "32"]
    peer_dir = "in" if direction == "out" else "out"
    states = [
        (wan, ["ip", "xfrm", "state", "add", *state, *ALGORITHMS,
               *(window if direction == "out" else [])],
         ["ip", "xfrm", "state", "delete", *state]),
        (r.target, ["ip", "xfrm", "state", "add", *state, *ALGORITHMS,
                    *(window if direction == "in" else []),
                    "offload", "packet", "dev", TARGET_WAN_IF, "dir", direction],
         ["ip", "xfrm", "state", "delete", *state]),
    ]
    policies = [
        (wan, ["ip", "xfrm", "policy", "add", *selector, "dir", peer_dir, *template],
         ["ip", "xfrm", "policy", "delete", *selector, "dir", peer_dir]),
        (r.target, ["ip", "xfrm", "policy", "add", *selector, "dir", direction, *template,
                    "offload", "packet", "dev", TARGET_WAN_IF],
         ["ip", "xfrm", "policy", "delete", *selector, "dir", direction]),
    ]
    for group in ((policies, states) if policy_first else (states, policies)):
        for agent, argv, undo in group:
            await step(agent, argv, undo)


def options_header(total):
    """A hop-by-hop or destination options header `total` bytes long, as
    IPV6_HOPOPTS and IPV6_DSTOPTS take one: the kernel fills in the next
    header. Eight bytes are one PadN option; anything longer is one of RFC
    4727's experimental type 0x1e, which a receiver skips -- Linux refuses
    PadN longer than seven bytes."""
    assert total % 8 == 0 and 8 <= total <= 2048, total
    if total == 8:
        return bytes([0, 0, 1, 4, 0, 0, 0, 0])
    assert total - 4 <= 255, total
    return bytes([0, total // 8 - 1, 0x1e, total - 4]) + bytes(total - 4)


# A datagram's body after its eight-byte number.
BODY = b"ASK-transport-in".ljust(40, b".")


def numbered(n):
    return struct.pack("!Q", n) + BODY


def receiver(family, address, port, control, peer, ready, seconds):
    """A listener on the DUT: datagrams to `address`:`port` whose bytes are
    numbered(n), counted by n, and any other. It says it is ready with a
    datagram to `peer`:`ready`, and stops 1.5 s after the sender's own,
    unencrypted, word on `control`, or after `seconds`."""
    return f'''
import json, select, socket, struct, time
family = socket.{family}
data = socket.socket(family, socket.SOCK_DGRAM)
data.bind(({address!r}, {port}))
stop = socket.socket(family, socket.SOCK_DGRAM)
stop.bind(({address!r}, {control}))
socket.socket(family, socket.SOCK_DGRAM).sendto(b"ready", ({peer!r}, {ready}))
got, other, end = {{}}, 0, time.monotonic() + {seconds}
while time.monotonic() < end:
    readable, _, _ = select.select([data, stop], [], [], 0.2)
    if stop in readable:
        stop.recv(64)
        end = min(end, time.monotonic() + 1.5)
    if data in readable:
        payload = data.recv(65535)
        n = struct.unpack("!Q", payload[:8])[0] if len(payload) >= 8 else -1
        if payload[8:] == {BODY!r}:
            got[n] = got.get(n, 0) + 1
        else:
            other += 1
print(json.dumps({{"got": got, "other": other}}))
'''


class Ready(asyncio.DatagramProtocol):
    def __init__(self):
        self.ready = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if data == b"ready" and not self.ready.done():
            self.ready.set_result(addr)


@contextlib.asynccontextmanager
async def received_on_dut(console, family, address, port, peer, *, seconds=40):
    """Run receiver() on the DUT for the block, which sends once it is
    ready; afterwards `result["got"]` maps each intact datagram's number to
    how often it arrived and `result["other"]` counts anything else."""
    ready_port, control = port + 100, port + 101
    loop = asyncio.get_running_loop()
    transport, ready = await loop.create_datagram_endpoint(Ready, local_addr=(peer, ready_port))
    task = asyncio.create_task(console_python(
        console, receiver(family, address, port, control, peer, ready_port, seconds),
        timeout=seconds + 30))
    result = {}

    def stop():
        with socket.socket(getattr(socket, family), socket.SOCK_DGRAM) as word:
            word.bind((peer, 0))
            word.sendto(b"done", (address, control))

    try:
        done, _ = await asyncio.wait({task, ready.ready}, timeout=seconds,
                                     return_when=asyncio.FIRST_COMPLETED)
        assert ready.ready in done, ("the DUT's receiver never said it was ready",
                                     task.result() if task in done else None)
        try:
            yield result
        finally:
            # However the block ends, so the receiver lets its ports go.
            stop()
        output = await task
        parsed = json.loads(output["stdout"].strip().splitlines()[-1])
        result["got"] = {int(n): count for n, count in parsed["got"].items()}
        result["other"] = parsed["other"]
    finally:
        transport.close()
        if not task.done():
            task.cancel()
            with contextlib.suppress(BaseException):
                await task


def send(family, source, address, port, groups):
    """Send each group's numbered() datagrams from `source` to
    `address`:`port`, a group being (socket options, first number, count),
    each option (level, name, value)."""
    for options, first, count in groups:
        with socket.socket(getattr(socket, family), socket.SOCK_DGRAM) as s:
            for level, name, value in options:
                s.setsockopt(level, name, value)
            s.bind((source, 0))
            for n in range(first, first + count):
                s.sendto(numbered(n), (address, port))
                time.sleep(0.01)


def sender(family, source, address, port, groups):
    """send() as a script for the DUT's console."""
    return f'''
import socket, struct, time
family = socket.{family}
for options, first, count in {groups!r}:
    s = socket.socket(family, socket.SOCK_DGRAM)
    for level, name, value in options:
        s.setsockopt(level, name, value)
    s.bind(({source!r}, 0))
    for n in range(first, first + count):
        s.sendto(struct.pack("!Q", n) + {BODY!r}, ({address!r}, {port}))
        time.sleep(0.01)
    s.close()
print("sent")
'''


async def dut_counters(r):
    """What the DUT counts of frames its WAN port hands SEC or refuses: frames
    the stack gave SEC either way, its transmit drops, and the stack's
    receive refusals, SEC's folded in."""
    mib = xfrm_mib(await read(r.target, r.session, "/proc/net/xfrm_stat"))
    return {
        "todec": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx todec"),
        "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc"),
        "tx_dropped": int((await read(r.target, r.session,
                                      f"/sys/class/net/{TARGET_WAN_IF}/statistics/tx_dropped")).strip()),
        "mismatch": mib["XfrmInStateMismatch"],
        "refused": sum(mib[name] for name in SEC_REFUSAL_MIBS),
    }


def moved(before, after):
    return {key: after[key] - before[key] for key in before}

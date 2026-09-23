"""Bulk TCP through a packet-offloaded tunnel, on the software path.

TCP hands the stack GSO packets. A local socket builds them from its send
queue, because a bundle whose SA is offloaded on the route's own port keeps
the socket's segmentation offload (xfrm_dst_offload_ok()); the LAN port's GRO
merges forwarded segments into them. With no flowtable every one reaches
xfrm_output() for the offloaded SA. SEC encrypts one packet per ESP and needs
the inner checksums finished, so each GSO packet has to be segmented in
software before SEC sees it; finishing a GSO packet's checksum in place is
refused with a warning and the packet dropped.

Two transfers of a known size over one SA pair, to a TCP sink on the WAN
host: one from the LAN VM, forwarded by the DUT, and one from the DUT itself,
from an address on its loopback. Each must arrive whole and in order, and the
sink's count must come back through the tunnel; XfrmOutError must not move;
and SEC must have been handed at least one frame per full-size segment. The
splat window fails the test on the warning.
"""
from __future__ import annotations

import asyncio
import json
import os

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_offload import (ARTIFACTS, command, console_json, console_python, read,  # noqa: F401
                                   rig)
from test_flowtable_service_ipsec_replay import xfrm_mib
from test_ipsec_inbound_flow_offload import sec_counter
from test_ipsec_offload_egress_device import INNER, install_tunnel, wan_outer

# The DUT's own inner address, on its loopback.
DUT_INNER = "198.18.106.3"
PORT = 48990
TOTAL = 8 << 20
# Offsets into a repeating 0..255 pattern, so the sink can check order and
# content of whatever chunk sizes TCP delivers without holding the stream.
PATTERN = bytes(range(256)) * 258


def sender(source):
    return f'''
import json, socket
pattern = bytes(range(256)) * 258
s = socket.create_connection(({INNER!r}, {PORT}), timeout=30, source_address=({source!r}, 0))
sent = 0
while sent < {TOTAL}:
    n = min(65536, {TOTAL} - sent)
    s.sendall(pattern[sent % 256:sent % 256 + n])
    sent += n
s.shutdown(socket.SHUT_WR)
reply = b''
while not reply.endswith(b'\\n'):
    chunk = s.recv(64)
    if not chunk:
        break
    reply += chunk
s.close()
print(json.dumps({{'sent': sent, 'reply': reply.decode().strip()}}))
'''


class Sink:
    """Counts each connection's bytes, checks them against the pattern, and
    answers with the count once the sender has finished."""

    def __init__(self):
        self.received = {}

    async def __call__(self, reader, writer):
        peer = writer.get_extra_info("peername")[0]
        count, intact = 0, True
        while chunk := await reader.read(65536):
            offset = count % 256
            intact = intact and chunk == PATTERN[offset:offset + len(chunk)]
            count += len(chunk)
        self.received[peer] = {"bytes": count, "intact": intact}
        writer.write(f"{count}\n".encode())
        await writer.drain()
        writer.close()


async def counters(r):
    return {
        "out_error": xfrm_mib(await read(r.target, r.session, "/proc/net/xfrm_stat"))["XfrmOutError"],
        "toenc": await sec_counter(r.session, r.target, TARGET_WAN_IF, "tx toenc"),
    }


async def offloads(r, iface):
    result = await command(r.target, r.session, "ethtool", "-k", iface)
    return {line.split(":")[0].strip(): line.split(":")[1].split()[0]
            for line in result["stdout"].splitlines() if ":" in line and line.split(":")[1].split()}


async def test_offloaded_tunnel_carries_bulk_tcp(rig):
    r = rig
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer = await wan_outer(r)
    sink = Sink()
    server = None
    cleanup = []

    async def step(agent, argv, undo):
        await command(agent, r.session, *argv)
        cleanup.append((agent, undo))

    try:
        # Both kinds of GSO packet have to exist for this to test anything:
        # merged on the LAN port, and built for a socket whose route leaves
        # by the WAN port.
        assert (await offloads(r, TARGET_LAN_IF))["generic-receive-offload"] == "on"
        assert (await offloads(r, TARGET_WAN_IF))["generic-segmentation-offload"] == "on"
        route = json.loads(r.lan.run(f"ip -j route get {INNER}", timeout=10).stdout.strip())[0]
        assert route.get("gateway") == r.lan_gateway, ("the LAN VM must reach INNER through the DUT",
                                                        route)
        await step(r.target, ["ip", "addr", "add", DUT_INNER + "/32", "dev", "lo"],
                   ["ip", "addr", "del", DUT_INNER + "/32", "dev", "lo"])
        await step(wan, ["ip", "route", "add", DUT_INNER + "/32", "via", outer, "dev", r.wan_if],
                   ["ip", "route", "del", DUT_INNER + "/32", "via", outer, "dev", r.wan_if])
        await install_tunnel(r, wan, outer, [r.lan_ip, DUT_INNER], step)
        server = await asyncio.start_server(sink, INNER, PORT)

        transfers = {}
        before = await counters(r)
        result = await lan_run_python(r.lan, sender(r.lan_ip), timeout=90, label="ipsec_offload_tcp")
        assert result.rc == 0, result.stdout
        transfers["forwarded"] = json.loads(result.stdout.strip().splitlines()[-1])
        with Console.target(log_path=str(ARTIFACTS / "ipsec-offload-tcp-uart.log")) as console:
            await asyncio.to_thread(console.login, "root", None)
            result = await console_python(console, sender(DUT_INNER), timeout=90)
        transfers["local"] = console_json(result["stdout"].strip())
        moved = {name: value - before[name] for name, value in (await counters(r)).items()}
        record = {"transfers": transfers, "received": sink.received, "moved": moved}
        r.record("ipsec-offload-tcp", record)

        for name, source in (("forwarded", r.lan_ip), ("local", DUT_INNER)):
            assert transfers[name] == {"sent": TOTAL, "reply": str(TOTAL)}, record
            assert sink.received.get(source) == {"bytes": TOTAL, "intact": True}, record
        assert moved["out_error"] == 0, record
        # Every byte left in a frame SEC encrypted, one ESP per segment: at
        # least a frame per full-size segment of both transfers.
        assert moved["toenc"] >= 2 * TOTAL // 1500, record
    finally:
        if server:
            server.close()
            await server.wait_closed()
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)

"""How many frames the WAN wire loses on its way to the DUT, measured once a
session before any case.

A frame lost between this host and the DUT's WAN MAC fails every zero-loss
oracle downstream of it exactly as a forwarding loss would, and it leaves no
trace on the DUT. Frames longer than the port accepts measure that leg: the
mEMAC counts each one it receives as oversized (`rovr`) and drops it, and
nothing else on the segment sends them. They are addressed to the DUT's own
MAC, so the switch delivers them to its port alone. This host's send count
against that count is what the wire lost, before the DUT handled anything.
"""
from __future__ import annotations

import asyncio
import re
import socket
import time

# Above any standard port's maximum frame, below this host's jumbo MTU.
FRAME = 1600
FRAMES = 100_000
PPS = 50_000
STATS = "/sys/class/net/{}/mac_rx_stats"


def mac_stats(text: str) -> dict[str, int]:
    """An mEMAC statistics dump by register name, each 64-bit value read
    from its _l/_u halves."""
    halves = {}
    for value, name, half in re.findall(r"0x([0-9a-fA-F]{8})\s+(\w+?)_([lu])\s*$", text, re.M):
        halves.setdefault(name, {})[half] = int(value, 16)
    return {name: (h.get("u", 0) << 32) | h.get("l", 0) for name, h in halves.items()}


def send(iface: str, dst_mac: str, frames: int = FRAMES, pps: int = PPS) -> int:
    """Send `frames` oversized frames to `dst_mac` on `iface`, paced; the
    number the socket accepted. EtherType 0x88B5, the IEEE's local
    experimental one: nothing on the segment parses them."""
    src = open(f"/sys/class/net/{iface}/address").read().strip()
    frame = (bytes.fromhex(dst_mac.replace(":", "") + src.replace(":", "")) + b"\x88\xb5").ljust(FRAME, b"\0")
    sent = 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((iface, 0))
        start = time.monotonic()
        for n in range(frames):
            sock.send(frame)
            sent += 1
            delay = start + (n + 1) / pps - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    return sent


async def measure(target, session, wire: str, dev: str) -> dict:
    """Send the frames on `wire` at the DUT port `dev` and count what its MAC
    received of them. `oversized` 0 means the port accepts frames this long,
    so nothing was measured."""
    async def read(path):
        result = await target.fs_read(session, path)
        assert result["errno"] == 0, (path, result)
        return bytes.fromhex(result["content_hex"]).decode()

    mac = (await read(f"/sys/class/net/{dev}/address")).strip()
    before = mac_stats(await read(STATS.format(dev)))
    sent = await asyncio.to_thread(send, wire, mac)
    await asyncio.sleep(0.1)  # the last frames still on the wire
    after = mac_stats(await read(STATS.format(dev)))
    moved = {name: after[name] - before[name] for name in ("rovr", "rfcs", "rerr", "rdrp", "rjbr", "rfrg")}
    return {"wire": wire, "dev": dev, "frame": FRAME, "sent": sent, "oversized": moved["rovr"],
            "lost": sent - moved["rovr"] if moved["rovr"] else None, "moved": moved}

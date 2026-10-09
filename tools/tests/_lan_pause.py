"""The DUT's LAN port paused by its link partner, as a congested switch or host
pauses it."""

from __future__ import annotations

import asyncio

from _topology import LAN_NIC, lan_run_python

# 802.3x PAUSE frames for the longest pause there is, 0xffff quanta (3.4 ms at
# 10 Gbit/s), several within each, for as long as asked.
_PAUSE = '''
import socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(({nic!r}, 0))
source = bytes.fromhex(open("/sys/class/net/{nic}/address").read().strip().replace(":", ""))
frame = bytes.fromhex("0180c2000001") + source + struct.pack("!HHH", 0x8808, 0x0001, 0xffff) + bytes(42)
end, sent = time.monotonic() + {seconds}, 0
while time.monotonic() < end:
    s.send(frame)
    sent += 1
    time.sleep(0.0005)
print("pause frames", sent)
'''


async def _pause(r, seconds):
    result = await lan_run_python(r.lan, _PAUSE.format(nic=LAN_NIC, seconds=seconds),
                                  timeout=seconds + 30, label="lan_pause")
    assert result.rc == 0, result.stdout
    return int(result.stdout.split()[-1])


async def while_lan_port_paused(r, body, seconds):
    """Run `body()` -- what it returns is awaited, and takes about `seconds` --
    with the DUT's LAN port paused throughout: the LAN VM sends it PAUSE frames
    from half a second before it starts until half a second after. Returns the
    body's result and how many PAUSE frames went out. The link and the NIC's
    own flow control settings are left alone: changing them resets the NIC,
    and the rig's LAN copper link has latched dead across such resets."""
    pause = asyncio.create_task(_pause(r, seconds + 1))
    try:
        await asyncio.sleep(0.5)
        result = await body()
    finally:
        sent = await pause
    return result, sent

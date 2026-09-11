"""Wi-Fi reset semantics and the VWD character-device lifetime."""

import shlex
import struct

from ask_orch.uart import Console


async def test_vwd_open_close(splat_window):
    script = 'import os\nfor _ in range(256): os.close(os.open("/dev/vwd0", os.O_RDWR))'
    with Console.target() as con:
        con.login("root", None)
        result = con.run("python3 -c " + shlex.quote(script), timeout=20)
        assert result.rc == 0, result.stdout


async def test_wifi_reset_body_ignored(aiohttp_session, target_agent, splat_window):
    name, vap = "ask-wifi-test", 31
    mac = bytes.fromhex("020000200531")

    async def entry(action):
        payload = struct.pack("<HH16s6sH", action, vap, name.encode(), mac, 0)
        reply = await target_agent.fci_send(aiohttp_session, 0x2001, len(payload), payload)
        return reply.get("reply_rc")

    result = await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "add", name, "type", "bridge"])
    assert result["rc"] == 0, result
    try:
        result = await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "set", name, "up"])
        assert result["rc"] == 0, result
        for length in (0, 1, 512):
            assert await entry(0) == 0
            reply = await target_agent.fci_send(aiohttp_session, 0x2005, length, b"\xa5" * length)
            assert reply.get("reply_rc") == 0, reply
            # Reset released the VAP: removing it now reports the existing
            # duplicate-operation error, and the next ADD must succeed.
            assert await entry(1) == 2001
    finally:
        await entry(1)
        result = await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", name])
        assert result["rc"] == 0, result

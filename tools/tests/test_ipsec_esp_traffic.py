"""Send live tunnel ESP and check the SEC shared-descriptor counters.

The WAN host's kernel is the software peer. Kernel XFRM events drive
CMM's normal SA installation; no direct FCI install or test hook is used.
Only the test's addresses, policy and SA are removed during teardown.
"""

import asyncio
from contextlib import AsyncExitStack
import json
import os
import secrets
import shlex
import socket
import struct
import textwrap
import uuid

import pytest

from ask_orch.client import Agent
from ask_orch.uart import Console

PEER = "198.18.85.1"
LOCAL = "198.18.85.2"
REQID = 48501
PORT = 48501
COUNT = 32
CIPHER = b"\xa5" * 16
AUTH = b"\x5a" * 32


@pytest.mark.parametrize("direction", ("inbound", "outbound"))
async def test_ipsec_esp_traffic(aiohttp_session, target_agent, splat_window,
                                direction, record_property):
    session = aiohttp_session
    wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    outer_wan = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
    outer_dut = os.environ.get("ASK_TARGET_IP", "10.0.0.62")
    spi = 0x0A850000 | (secrets.randbelow(65535) + 1)
    inbound = direction == "inbound"
    source, destination = (PEER, LOCAL) if inbound else (LOCAL, PEER)
    outer_peer, outer_local = (outer_wan, outer_dut) if inbound else (outer_dut, outer_wan)

    async def command(agent, *args):
        result = await agent.exec_cmd(session, ["ip", *args])
        assert result["rc"] == 0, result
        return result

    async def fci(code, payload):
        result = await target_agent.fci_send(session, code, len(payload), payload,
                                             timeout_ms=5000)
        assert result.get("reply_rc") == 0, (hex(code), result)
        return bytes.fromhex(result["payload_hex"])

    async def nat_rule(action):
        result = await target_agent.exec_cmd(session, [
            "iptables", "-t", "nat", action, "POSTROUTING",
            "-s", LOCAL + "/32", "-d", PEER + "/32", "-j", "ACCEPT",
        ])
        assert result["rc"] == 0, result

    async def counters():
        await fci(0x0E09, struct.pack("<HHi", 2, 0, 0))
        found = None
        for _ in range(256):
            data = await fci(0x0E0A, bytes(44))
            if struct.unpack_from("<H", data, 2)[0]:
                break
            if (struct.unpack_from("<I", data, 8)[0] == spi
                    and data[12:16] == socket.inet_aton(outer_local)):
                packets, low, high = struct.unpack_from("<III", data, 28)
                found = (packets, (high << 32) | low)
        else:
            raise AssertionError("SA statistics query did not terminate")
        assert found is not None, "test SA missing from hardware statistics"
        return found

    async def enabled():
        code, found = 0x0A0A, None
        for _ in range(256):
            result = await target_agent.fci_send(session, code, 252, bytes(252), timeout_ms=3000)
            if result.get("reply_rc") == 909:
                return found
            assert result.get("reply_rc") == 0, result
            data = bytes.fromhex(result["payload_hex"])
            if (struct.unpack_from("!I", data, 8)[0] == spi
                    and data[16:20] == socket.inet_aton(outer_local)):
                found = (data[49], struct.unpack_from("<H", data, 50)[0])
            code = 0x0A0B
        raise AssertionError("SA query did not terminate")

    async with AsyncExitStack() as cleanup:
        # Keep the narrow inner selector intact through the bench's WAN NAT.
        await nat_rule("-I")
        cleanup.push_async_callback(nat_rule, "-D")
        for agent, address in ((wan, PEER), (target_agent, LOCAL)):
            await command(agent, "address", "add", address + "/32", "dev", "lo")
            cleanup.push_async_callback(command, agent, "address", "del",
                                        address + "/32", "dev", "lo")
        for agent, route_destination, via in (
            (wan, LOCAL, outer_dut), (target_agent, PEER, outer_wan),
        ):
            await command(agent, "route", "add", route_destination + "/32", "via", via)
            cleanup.push_async_callback(command, agent, "route", "del", route_destination + "/32")

        state = ("src", outer_peer, "dst", outer_local, "proto", "esp", "spi", hex(spi))
        for agent in (wan, target_agent):
            await command(agent, "xfrm", "state", "add", *state, "mode", "tunnel",
                          "reqid", str(REQID), "replay-window", "32",
                          "enc", "cbc(aes)", "0x" + CIPHER.hex(),
                          "auth-trunc", "hmac(sha256)", "0x" + AUTH.hex(), "128")
            cleanup.push_async_callback(command, agent, "xfrm", "state", "delete", *state)
        for agent, policy_dir in (
            (wan, "out" if inbound else "in"),
            (target_agent, "in" if inbound else "out"),
        ):
            selector = ("src", source + "/32", "dst", destination + "/32", "dir", policy_dir)
            await command(agent, "xfrm", "policy", "add", *selector,
                          "tmpl", "src", outer_peer, "dst", outer_local, "proto", "esp",
                          "mode", "tunnel", "reqid", str(REQID), "level", "required")
            cleanup.push_async_callback(command, agent, "xfrm", "policy", "delete", *selector)

        # CMM consumes the XFRM event asynchronously.
        for _ in range(30):
            status = await enabled()
            if status and status[0] == 2 and status[1] & 0x10:
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError(f"CMM did not enable test SA: {status}")
        before = await counters()

        payloads = [struct.pack("!I", index) + bytes(range(256)) for index in range(COUNT)]
        if not inbound:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
                listener.bind((PEER, PORT))
                listener.setblocking(False)
                sender = textwrap.dedent(f'''
                    import socket, struct, time
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.bind(({LOCAL!r}, 0))
                        for index in range({COUNT}):
                            sock.sendto(struct.pack('!I', index) + bytes(range(256)),
                                        ({PEER!r}, {PORT}))
                            time.sleep(0.01)
                ''')
                with Console.target() as con:
                    con.login("root", None)
                    result = con.run("python3 -c " + shlex.quote(sender), timeout=10)
                    assert result.rc == 0, result.stdout
                loop = asyncio.get_running_loop()
                received = [await asyncio.wait_for(loop.sock_recv(listener, 2048), 5)
                            for _ in range(COUNT)]
            after = await counters()
            assert received == payloads
            assert after[0] - before[0] == COUNT, (before, after)
            assert after[1] > before[1], (before, after)
            record_property("sec_packets", after[0] - before[0])
            record_property("sec_bytes", after[1] - before[1])
            return

        path = "/tmp/ask_esp_" + uuid.uuid4().hex
        receiver = textwrap.dedent(f'''
            import json, socket
            from pathlib import Path
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(({LOCAL!r}, {PORT}))
            sock.settimeout(5)
            Path({path + '.ready'!r}).touch()
            received = []
            try:
                for _ in range({COUNT}):
                    received.append(sock.recv(2048).hex())
            except TimeoutError:
                pass
            finally:
                sock.close()
                Path({path + '.json'!r}).write_text(json.dumps(received))
        ''')
        with Console.target() as con:
            con.login("root", None)
            result = con.run("python3 -c " + shlex.quote(receiver)
                             + " > " + path + ".log 2>&1 & echo $!")
            assert result.rc == 0, result.stdout
            pid = next(line for line in result.stdout.splitlines() if line.strip().isdigit())
            try:
                for _ in range(30):
                    ready = await target_agent.fs_read(session, path + ".ready")
                    if ready.get("errno", 0) == 0:
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError("ESP receiver did not bind")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.bind((PEER, 0))
                    for payload in payloads:
                        sender.sendto(payload, (LOCAL, PORT))
                        await asyncio.sleep(0.01)
                for _ in range(60):
                    result = await target_agent.fs_read(session, path + ".json")
                    if result.get("errno", 0) == 0:
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError("ESP receiver did not finish")
                received = json.loads(bytes.fromhex(result["content_hex"]))
                after = await counters()
                assert received == [payload.hex() for payload in payloads], (
                    len(received), before, after)
                assert after[0] - before[0] == COUNT, (before, after)
                assert after[1] > before[1], (before, after)
                record_property("sec_packets", after[0] - before[0])
                record_property("sec_bytes", after[1] - before[1])
            finally:
                con.run("kill " + pid + " 2>/dev/null; rm -f " + path + ".ready "
                        + path + ".json " + path + ".log")

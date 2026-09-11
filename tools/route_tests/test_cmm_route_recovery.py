"""Dedicated hardware regression: temporarily restart CMM with send failures.

Run separately from tools/tests; the fixture restores the normal daemon.
"""
import asyncio
import base64
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess

import aiohttp
import pytest
import pytest_asyncio

from ask_orch.client import TARGET
from ask_orch.uart import Console

HERE = Path(__file__).resolve().parent
WAN = os.environ.get("ASK_TARGET_WAN_IF", "eth4")
REMOTE = "198.18.66.10"
GATEWAYS = ("198.18.66.1", "198.18.66.2")
MACS = (bytes.fromhex("020000006601"), bytes.fromhex("020000006602"))
SOCKET_ID = 26666
SPI = "0x0a660001"


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def rig(tmp_path_factory):
    artifacts = tmp_path_factory.mktemp("cmm-route-retry")
    library = artifacts / "cmm_route_fault.so"
    subprocess.run([os.environ.get("ASK_AARCH64_CC", "aarch64-linux-gnu-gcc"),
                    "-shared", "-fPIC", "-O2", "-Wall", "-Werror",
                    str(HERE / "cmm_route_fault.c"), "-ldl", "-o", str(library)], check=True)
    async with aiohttp.ClientSession() as session:
        async def write(path, data):
            result = await TARGET.fs_write(session, path, data)
            assert result.get("errno", 0) == 0, result

        async def read(path):
            result = await TARGET.fs_read(session, path)
            assert result.get("errno", 0) == 0, result
            return bytes.fromhex(result["content_hex"]).decode()

        with Console.target(log_path=str(artifacts / "uart.log")) as con:
            con.login("root", None)

            def run(command, timeout=20):
                result = con.run(command, timeout=timeout)
                assert result.rc == 0, (command, result.stdout)
                return result.stdout

            await write("/tmp/ask-route-fault.b64", base64.b64encode(library.read_bytes()).decode())
            await write("/tmp/ask-route-ipc.py", (HERE / "cmm_ipc.py").read_text())
            run("base64 -d /tmp/ask-route-fault.b64 > /tmp/ask-route-fault.so")
            await write("/tmp/ask-route-fault", "0")
            await write("/tmp/ask-route-fault.log", "")
            run("/etc/init.d/cmm stop")
            try:
                run("stty cols 240 -echo")
                run("LD_PRELOAD=/tmp/ask-route-fault.so /etc/init.d/cmm start > /tmp/ask-route-cmm.log 2>&1")
                await asyncio.sleep(2)
                pid = (await read("/var/run/cmm.pid")).strip()
                assert "ask-route-fault.so" in await read(f"/proc/{pid}/maps")
                response = await TARGET.exec_cmd(session, ["ip", "-j", "address", "show", "dev", WAN])
                assert response["rc"] == 0, response
                local = next(a["local"] for a in json.loads(response["stdout"])[0]["addr_info"]
                             if a["family"] == "inet")
                yield session, run, read, write, local, artifacts
            finally:
                await write("/tmp/ask-route-fault", "0")
                (artifacts / "commands.log").write_text(await read("/tmp/ask-route-fault.log"))
                (artifacts / "cmm.log").write_text(await read("/tmp/ask-route-cmm.log"))
                run("/etc/init.d/cmm stop")
                run("/etc/init.d/cmm start > /tmp/ask-route-cmm-restored.log 2>&1")
                run("stty echo")
                run("rm -f /tmp/ask-route-fault /tmp/ask-route-fault.b64 /tmp/ask-route-fault.so /tmp/ask-route-ipc.py")


@pytest.mark.asyncio(loop_scope="module")
@pytest.mark.parametrize("kind", ["socket", "sa", "tunnel"])
@pytest.mark.parametrize("change", ["gateway", "mtu"])
async def test_cmm_route_recovery(rig, kind, change):
    session, run, read, write, local, artifacts = rig
    code = {"socket": 0x0332, "sa": 0x0a15, "tunnel": 0x0b03}[kind]
    capture = await TARGET.capture_start(session, ifaces=[WAN])
    route_events = 0

    async def ip(*args):
        result = await TARGET.exec_cmd(session, ["ip", *args])
        assert result["rc"] == 0, result

    async def route(gateway, mtu):
        nonlocal route_events
        route_events += 1
        # Linux can suppress an identical replace. Change only the protocol
        # label to guarantee a notification with identical forwarding data.
        await ip("route", "replace", REMOTE + "/32", "via", gateway,
                 "dev", WAN, "onlink", "mtu", str(mtu),
                 "proto", "static" if route_events % 2 else "boot")

    async def fci(action, route_id=0):
        payload = bytearray(88)
        struct.pack_into("<H", payload, 0, action)
        struct.pack_into("<I", payload, 64, route_id)
        return await TARGET.fci_send(session, 0x0313, len(payload), payload, timeout_ms=3000)

    async def routes():
        result, found = await fci(6), []
        for _ in range(256):
            if result.get("reply_rc") != 0:
                return found
            data = bytes.fromhex(result["payload_hex"])
            if data[4:10] in MACS:
                found.append((struct.unpack_from("<I", data, 64)[0],
                              data[4:10].hex(), struct.unpack_from("<H", data, 2)[0]))
            result = await fci(7)
        raise AssertionError("route query did not terminate")

    async def wait_routes(mac, mtu):
        for _ in range(30):
            found = await routes()
            if len(found) == 1 and found[0][1:] == (mac.hex(), mtu):
                return found[0][0]
            await asyncio.sleep(0.1)
        raise AssertionError((kind, change, "unexpected hardware routes", found))

    async def ipc(command, payload):
        run(f"python3 /tmp/ask-route-ipc.py {command} {shlex.quote(payload.hex())}")

    async def remove_sa(state):
        # A107: CMM deletes its route before the hardware SA on normal
        # XFRM deletion. Detach this test SA first so its route can be freed.
        await write("/tmp/ask-route-fault", "0")
        try:
            result = await TARGET.fci_send(session, 0x0a0a, 252, bytes(252))
            for _ in range(256):
                if result.get("reply_rc") != 0:
                    raise AssertionError("test SA disappeared before cleanup")
                data = bytes.fromhex(result["payload_hex"])
                if struct.unpack_from("!I", data, 8)[0] == int(SPI, 0):
                    handle = struct.unpack_from("<H", data, 2)[0]
                    reply = await TARGET.fci_send(session, 0x0a15, 4, struct.pack("<HH", handle, 0))
                    assert reply.get("reply_rc") == 0, reply
                    return
                result = await TARGET.fci_send(session, 0x0a0b, 252, bytes(252))
            raise AssertionError("SA query did not terminate")
        finally:
            await ip("xfrm", "state", "delete", *state)

    try:
        async with AsyncExitStack() as cleanup:
            for gateway, mac in zip(GATEWAYS, MACS):
                await ip("neigh", "add", gateway, "lladdr", mac.hex(":"), "nud", "permanent", "dev", WAN)
                cleanup.push_async_callback(ip, "neigh", "del", gateway, "dev", WAN)
            await route(GATEWAYS[0], 1500)
            cleanup.push_async_callback(ip, "route", "del", REMOTE + "/32")
            if kind == "socket":
                payload = struct.pack("<HBBI", SOCKET_ID, 0, 0, socket.AF_INET)
                payload += socket.inet_aton(REMOTE) + bytes(12) + socket.inet_aton(local) + bytes(12)
                payload += struct.pack("!HH", 26666, 27666) + struct.pack("<BBHIH", 17, 0, 0, 0, 0)
                await ipc(0x1301, payload)
                cleanup.push_async_callback(ipc, 0x1302, struct.pack("<HH", SOCKET_ID, 0))
            elif kind == "sa":
                state = ("src", local, "dst", REMOTE, "proto", "esp", "spi", SPI)
                await ip("xfrm", "state", "add", *state, "mode", "tunnel", "reqid", "16666",
                         "enc", "cbc(aes)", "0x" + "a5" * 16,
                         "auth-trunc", "hmac(sha256)", "0x" + "5a" * 32, "128")
                cleanup.push_async_callback(remove_sa, state)
            else:
                await ip("tunnel", "add", "ask-a66", "mode", "sit", "local", "0.0.0.0", "remote", REMOTE, "ttl", "64")
                cleanup.push_async_callback(ip, "link", "del", "ask-a66")
                await ip("link", "set", "ask-a66", "up")
            old = await wait_routes(MACS[0], 1500)
            assert (await fci(1, old)).get("reply_rc") == 202, "holder must pin its old route"
            await write("/tmp/ask-route-fault", str(code))
            gateway, mac, mtu = (GATEWAYS[1], MACS[1], 1500) if change == "gateway" else (GATEWAYS[0], MACS[0], 1400)
            before = await read("/tmp/ask-route-fault.log")
            await route(gateway, mtu)
            for _ in range(30):
                log = (await read("/tmp/ask-route-fault.log"))[len(before):]
                if f"reject {code:04x}" in log:
                    break
                await asyncio.sleep(0.1)
            else:
                raise AssertionError("route change did not reach the injected failure")
            await asyncio.sleep(0.3)
            assert await wait_routes(MACS[0], 1500) == old
            assert (await fci(1, old)).get("reply_rc") == 202
            await route(gateway, mtu)
            await asyncio.sleep(0.3)
            assert await wait_routes(MACS[0], 1500) == old
            await write("/tmp/ask-route-fault", "0")
            # Replay exactly the same route, with both permanent neighbors
            # already valid. No neighbor churn can conceal a stale retry.
            await route(gateway, mtu)
            new = await wait_routes(mac, mtu)
            assert new != old
            assert (await fci(1, new)).get("reply_rc") == 202, "holder must pin its replacement route"
            await route(gateway, mtu)
            await asyncio.sleep(0.2)
            assert await wait_routes(mac, mtu) == new
            (artifacts / f"{kind}-{change}.json").write_text(json.dumps({
                "old_route": old, "new_route": new, "mac": mac.hex(), "mtu": mtu,
                "repeated_failure": True, "unchanged_route_retry": True}, indent=2))
        for _ in range(30):
            if not await routes():
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("test routes leaked after holder removal")
    finally:
        await write("/tmp/ask-route-fault", "0")
        result = await TARGET.capture_stop(session, capture)
        assert not result.get("splats"), result.get("splats")

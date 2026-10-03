"""LAN control keeps working while the measured traffic receives no replies."""

import asyncio
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace

from _flowtable_rig import Echo
import _flowtable_connections as connections


class LocalGuest:
    def python(self, source, timeout=30):
        result = subprocess.run([sys.executable, "-c", source],
                                capture_output=True, text=True, timeout=timeout)
        return SimpleNamespace(rc=result.returncode, stdout=result.stdout + result.stderr)


async def test_peer_control_is_independent_of_data_delivery(monkeypatch):
    # A real local shell stands in for the LAN console; the production staging,
    # Unix socket, peer process and traffic protocol run unchanged.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    monkeypatch.setattr(connections, "WAN_IP", "127.0.0.1")
    monkeypatch.setattr(connections, "DPORT", port)
    echo = Echo()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=("127.0.0.1", port))
    records = {}
    rig = SimpleNamespace(lan=LocalGuest(), lan_ip="127.0.0.1", echo=echo,
                          record=lambda name, value: records.update({name: value}))
    flows = [{"id": 0, "proto": "udp", "sport": 0}]
    try:
        async with connections.peer(rig, flows, lease=60) as peer:
            report = await peer.batch([0], count=4)
            assert report[0]["received"] == 4
            echo.reply = False
            await peer.rpc("start", [0], count=0, interval=0.01, allow_loss=True, udp_timeout=0.05)
            await asyncio.sleep(0.15)
            status = await peer.rpc("status", compact=True)
            assert status["running"] == 1 and not status["errors"]
            stopped = await peer.rpc("stop", [0])
            assert stopped["0"]["lost"] > 0
            # A quiet DUT measurement may exceed the peer's 35-second idle
            # lease. Only the production heartbeat keeps this peer alive.
            await asyncio.sleep(36)
            assert (await peer.rpc("status", compact=True))["running"] == 0
        assert json.loads(records["connections-peer"]["stdout"])["closed"]
    finally:
        transport.close()


async def test_peer_stops_traffic_when_its_controller_disappears():
    echo = Echo()
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=("127.0.0.1", 0))
    flows = [{"id": 0, "proto": "udp", "sport": 0}]
    try:
        with tempfile.TemporaryDirectory(prefix="ask-peer-") as directory:
            path = Path(directory) / "control.sock"
            config = {"lan": "127.0.0.1", "wan": "127.0.0.1",
                      "dport": transport.get_extra_info("sockname")[1],
                      "control_path": str(path), "flows": flows,
                      "tcp_size": connections.TCP_SIZE, "lease": 120}
            process = await asyncio.create_subprocess_exec(sys.executable, "-c",
                connections.peer_script(config), stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            try:
                async with asyncio.timeout(3):
                    while not path.exists():
                        assert process.returncode is None
                        await asyncio.sleep(0.01)
                peer = connections.Peer(LocalGuest(), str(path), flows)
                await peer.rpc("open", [0])
                await peer.rpc("start", [0], count=0, interval=0.01)
                # No heartbeat or further command. The production 35-second
                # idle deadline must stop an otherwise unbounded transfer.
                stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
                assert process.returncode != 0 and b"TimeoutError" in stderr, (stdout, stderr)
                assert not path.exists()
                received = len(echo.received)
                assert received > 100
                await asyncio.sleep(0.2)
                assert len(echo.received) == received
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.communicate()
    finally:
        transport.close()


async def test_peer_failure_closes_the_control_connection(tmp_path):
    path = tmp_path / 'control.sock'
    config = {'lan': '127.0.0.1', 'wan': '127.0.0.1', 'dport': 9,
              'control_path': str(path), 'flows': [],
              'tcp_size': connections.TCP_SIZE, 'lease': 60}
    process = await asyncio.create_subprocess_exec(sys.executable, '-c',
        connections.peer_script(config), stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    writer = None
    try:
        async with asyncio.timeout(3):
            while not path.exists():
                assert process.returncode is None
                await asyncio.sleep(0.01)
        reader, writer = await asyncio.open_unix_connection(str(path))
        writer.write(b'{"op":"unsupported"}\n')
        await writer.drain()
        stdout, stderr = await asyncio.wait_for(process.communicate(), 3)
        assert process.returncode != 0 and b'AssertionError' in stderr and b'unsupported' in stderr, (stdout, stderr)
        assert await reader.read() == b''
        assert not path.exists()
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        if process.returncode is None:
            process.kill()
            await process.communicate()

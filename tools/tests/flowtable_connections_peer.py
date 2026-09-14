"""Concurrent TCP/UDP peer; staged once over the LAN console.

CONFIG is prepended by the controller. A separate, unoffloaded TCP connection
controls the workload while the single console operation remains in flight.
Every exchange carries its connection ID and a monotonically increasing serial.
"""
import asyncio
from contextlib import contextmanager
import json
import os
import socket
import struct
import time

TCP_SIZE = 16384
UDP_SIZE = 256


def payload(ident, serial, size):
    return struct.pack("!IQ", ident, serial) + bytes([ident % 251]) * (size - 12)


@contextmanager
def namespace(spec):
    # No await is permitted in this context: other tasks share this thread.
    # Sockets retain their creation namespace after the thread returns.
    if "netns" not in spec:
        yield
        return
    with open('/proc/self/ns/net', 'rb') as original, open('/var/run/netns/' + spec["netns"], 'rb') as peer:
        os.setns(peer.fileno(), os.CLONE_NEWNET)
        try:
            yield
        finally:
            os.setns(original.fileno(), os.CLONE_NEWNET)


class Flow:
    def __init__(self, spec):
        self.spec = spec
        self.serial = 0
        self.reader = self.writer = self.sock = None
        self.stop = asyncio.Event()

    async def open(self, config):
        local = (self.spec.get("lan", config["lan"]), self.spec["sport"])
        remote = (config["wan"], config["dport"])
        if self.spec["proto"] == "tcp":
            with namespace(self.spec):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setblocking(False)
                sock.bind(local)
                await asyncio.get_running_loop().sock_connect(sock, remote)
                self.reader, self.writer = await asyncio.open_connection(sock=sock)
            except BaseException:
                sock.close()
                raise
            self.writer.write(json.dumps({"id": self.spec["id"]}).encode() + b"\n")
            await self.writer.drain()
        else:
            with namespace(self.spec):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setblocking(False)
            self.sock.bind(local)
            self.sock.connect(remote)

    async def run(self, count, interval):
        first = self.serial
        size = TCP_SIZE if self.writer else UDP_SIZE
        loop = asyncio.get_running_loop()
        # Spread the streams within each pacing interval.
        await asyncio.sleep(self.spec["id"] * interval / 32)
        started = time.monotonic()
        while not self.stop.is_set() and (not count or self.serial - first < count):
            data = payload(self.spec["id"], self.serial, size)
            async with asyncio.timeout(20 if self.writer else 5):
                if self.writer:
                    self.writer.write(data)
                    await self.writer.drain()
                    reply = await self.reader.readexactly(size)
                else:
                    await loop.sock_sendall(self.sock, data)
                    reply = await loop.sock_recv(self.sock, size + 1)
            assert reply == data, (self.spec, self.serial, "corrupt, duplicate or misdirected echo")
            self.serial += 1
            delay = (self.serial - first) * interval - (time.monotonic() - started)
            if delay > 0:
                await asyncio.sleep(delay)
        return {"first": first, "count": self.serial - first,
                "bytes": (self.serial - first) * size,
                "seconds": time.monotonic() - started}

    async def close(self):
        if self.writer:
            self.writer.write_eof()
            assert await asyncio.wait_for(self.reader.read(), 5) == b""
            self.writer.close()
            await self.writer.wait_closed()
            self.writer = None
        if self.sock:
            self.sock.close()
            self.sock = None


async def main(config):
    flows = {spec["id"]: Flow(spec) for spec in config["flows"]}
    running = {}
    control = None
    reports = []

    async def finish(ids, stop=False):
        if stop:
            for ident in ids:
                flows[ident].stop.set()
        result = {}
        for ident in ids:
            result[ident] = await running.pop(ident)
        reports.append(result)
        return result

    try:
        # A local lease also ends traffic if the controller disappears.
        async with asyncio.timeout(180):
            reader, control = await asyncio.open_connection(config["wan"], config["control_port"])
            control.write(json.dumps({"ready": config["token"]}).encode() + b"\n")
            await control.drain()
            while line := await asyncio.wait_for(reader.readline(), 35):
                command = json.loads(line)
                op, ids = command["op"], command.get("ids", [])
                result = {}
                if op == "open":
                    async with asyncio.TaskGroup() as group:
                        for ident in ids:
                            group.create_task(flows[ident].open(config))
                elif op == "neighbour":
                    flow = flows[command["ident"]]
                    with namespace(flow.spec):
                        result = configure_neighbour(flow.spec["iface"], flow.spec["lan"], **command["changes"])
                elif op == "start":
                    for ident in ids:
                        assert ident not in running
                        flow = flows[ident]
                        flow.stop.clear()
                        running[ident] = asyncio.create_task(flow.run(command["count"], command["interval"]))
                elif op in {"wait", "stop"}:
                    result = await finish(ids, stop=op == "stop")
                elif op == "close":
                    assert all(i not in running for i in ids)
                    await asyncio.gather(*(flows[i].close() for i in ids))
                elif op == "shutdown":
                    result = await finish(list(running), stop=True)
                    await asyncio.gather(*(flow.close() for flow in flows.values()))
                else:
                    raise AssertionError(command)
                control.write(json.dumps({"op": op, "result": result}).encode() + b"\n")
                await control.drain()
                if op == "shutdown":
                    print(json.dumps({"reports": reports, "closed": True}), flush=True)
                    return
            raise AssertionError("controller disconnected without shutdown")
    finally:
        tasks = list(running.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for flow in flows.values():
            if flow.writer:
                flow.writer.close()
            if flow.sock:
                flow.sock.close()
        if control:
            control.close()
            await control.wait_closed()


if __name__ == "__main__":
    asyncio.run(main(CONFIG))

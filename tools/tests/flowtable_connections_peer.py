"""Concurrent TCP/UDP peer; staged once over the LAN console.

CONFIG is prepended by the controller. A separate, unoffloaded TCP connection
controls the workload while the single console operation remains in flight.
Every exchange carries its connection ID and a monotonically increasing serial.
"""
import asyncio
from contextlib import contextmanager
import errno
import json
import os
import resource
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
    def __init__(self, spec, validate_udp=None, capture_udp=None):
        self.spec = spec
        self.validate_udp = validate_udp
        self.capture_udp = capture_udp
        self.serial = 0
        self.reader = self.writer = self.sock = None
        self.wire = None
        self.stop = asyncio.Event()

    async def open(self, config):
        local = (self.spec.get("lan", config["lan"]), self.spec["sport"])
        remote = (self.spec.get("connect_ip", config["wan"]),
                  self.spec.get("connect_port", config["dport"]))
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
            if "wire" in self.spec:
                with namespace(self.spec):
                    self.wire = self.capture_udp(self.spec["sport"])
                self.wire.bind((self.spec["iface"], 0))
                self.wire.setblocking(False)
                if self.spec["wire"].get("zero_checksum"):
                    self.sock.setsockopt(socket.SOL_SOCKET, 11, 1)  # Linux SO_NO_CHECK

    async def run(self, count, interval, allow_loss=False, udp_timeout=None):
        # Loss-tolerant UDP windows validate every received payload. Their
        # controller supplies the loss budget; TCP always requires delivery.
        assert not (allow_loss and self.writer)
        deadline = 20 if self.writer else (udp_timeout if udp_timeout is not None
                                           else 0.1 if allow_loss else 5)
        assert deadline > 0
        first = self.serial
        received = lost = late = 0
        size = TCP_SIZE if self.writer else UDP_SIZE
        loop = asyncio.get_running_loop()
        # Spread the streams within each pacing interval.
        await asyncio.sleep((self.spec["id"] % 256) * interval / 256)
        started = time.monotonic()
        while not self.stop.is_set() and (not count or self.serial - first < count):
            data = payload(self.spec["id"], self.serial, size)
            try:
                async with asyncio.timeout(deadline):
                    if self.writer:
                        self.writer.write(data)
                        await self.writer.drain()
                        reply = await self.reader.readexactly(size)
                    else:
                        await loop.sock_sendall(self.sock, data)
                        while True:
                            reply = await loop.sock_recv(self.sock, size + 1)
                            if not allow_loss or reply == data:
                                break
                            assert len(reply) == size, (self.spec, reply)
                            ident, serial = struct.unpack('!IQ', reply[:12])
                            assert ident == self.spec['id'] and first <= serial < self.serial
                            assert reply == payload(ident, serial, size)
                            late += 1
                        if self.wire:
                            while True:
                                frame = await loop.sock_recv(self.wire, 65536)
                                wire_payload = self.validate_udp(frame, **self.spec["wire"])
                                if wire_payload is not None:
                                    assert wire_payload == data, (self.spec, self.serial, frame.hex())
                                    break
                assert reply == data, (self.spec, self.serial, "corrupt, duplicate or misdirected echo")
                received += 1
            except (TimeoutError, OSError) as error:
                if not allow_loss or (isinstance(error, OSError) and not isinstance(error, TimeoutError)
                                      and error.errno not in {errno.EHOSTUNREACH, errno.ENETUNREACH,
                                                              errno.ECONNREFUSED}):
                    error.add_note(f"flow={self.spec} serial={self.serial} first={first}")
                    if self.wire:
                        packets, drops = struct.unpack("II", self.wire.getsockopt(263, 6, 8))
                        error.add_note(f"receive capture: {packets} packets, {drops} socket drops; serial={self.serial}")
                    raise
                lost += 1
            self.serial += 1
            delay = (self.serial - first) * interval - (time.monotonic() - started)
            if delay > 0:
                await asyncio.sleep(delay)
        return {"first": first, "count": self.serial - first,
                "bytes": received * size, "received": received, "lost": lost, "late": late,
                "seconds": time.monotonic() - started}

    async def close(self):
        if self.writer:
            if self.spec.get("abort"):
                self.writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                                               struct.pack("ii", 1, 0))
                self.writer.transport.abort()
            else:
                self.writer.write_eof()
                assert await asyncio.wait_for(self.reader.read(), 5) == b""
            self.writer.close()
            await self.writer.wait_closed()
            self.writer = None
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.wire:
            self.wire.close()
            self.wire = None


async def main(config):
    global TCP_SIZE
    TCP_SIZE = config["tcp_size"]
    flows = {}
    running = {}
    control = None
    reports = []
    servers = None

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
        async with asyncio.timeout(config["lease"]):
            reader, control = await asyncio.open_connection(config["wan"], config["control_port"], limit=8 << 20)
            control.write(json.dumps({"ready": config["token"]}).encode() + b"\n")
            await control.drain()
            workload = json.loads(await asyncio.wait_for(reader.readline(), 15))
            specs = workload["flows"]
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            needed = len(specs) * 2 + 256
            assert needed <= hard, (needed, hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, needed), hard))
            flows = {spec["id"]: Flow(spec, udp_wire_payload, udp_capture_socket) for spec in specs}
            servers = EchoServers(config.get("servers", []), specs, namespace, payload,
                                  udp_wire_payload, udp_capture_socket)
            await servers.start()
            opening = asyncio.Semaphore(32)

            async def open_one(ident):
                async with opening:
                    await flows[ident].open(config)

            while line := await asyncio.wait_for(reader.readline(), 35):
                command = json.loads(line)
                op, ids = command["op"], command.get("ids", [])
                result = {}
                if op == "open":
                    async with asyncio.TaskGroup() as group:
                        for ident in ids:
                            group.create_task(open_one(ident))
                elif op == "status":
                    result = {"running": len(running), "errors": {
                        ident: repr(task.exception()) for ident, task in running.items()
                        if task.done() and not task.cancelled() and task.exception()}}
                elif op == "neighbour":
                    flow = flows[command["ident"]]
                    with namespace(flow.spec):
                        result = configure_neighbour(flow.spec["iface"], flow.spec["lan"], **command["changes"])
                elif op == "servers":
                    result = servers.status()
                elif op == "start":
                    for ident in ids:
                        assert ident not in running
                        flow = flows[ident]
                        flow.stop.clear()
                        running[ident] = asyncio.create_task(flow.run(command["count"], command["interval"],
                                                                     command.get("allow_loss", False),
                                                                     command.get("udp_timeout")))
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
                    assert not servers.errors, servers.errors
                    print(json.dumps({"reports": reports if len(flows) <= 64 else None,
                                      "report_groups": len(reports), "flows": len(flows),
                                      "closed": True, "servers": servers.status()}), flush=True)
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
            if flow.wire:
                flow.wire.close()
        if servers:
            await servers.close()
        if control:
            control.close()
            await control.wait_closed()


if __name__ == "__main__":
    asyncio.run(main(CONFIG))

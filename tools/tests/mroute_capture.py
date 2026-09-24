"""A158 packet oracle, staged unchanged on a listener host (stdlib only)."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import sys
import time

MAGIC = b"ASK-A158"


def multicast_mac(group: str) -> bytes:
    address = ipaddress.ip_address(group)
    if address.version == 6:
        return b"\x33\x33" + address.packed[-4:]
    return b"\x01\x00\x5e" + (int(address) & 0x7fffff).to_bytes(3, "big")


def payload(token: str, sequence: int) -> bytes:
    return MAGIC + bytes.fromhex(token) + struct.pack("!I", sequence) + b"." * 128


def decode(frame: bytes, config: dict, source_mac: str) -> int | None:
    """Return this run's sequence; unrelated traffic is ignored, bad copies fail.

    Sockets bind to individual VLAN devices, so VLAN demultiplexing itself is
    the framing oracle. L2/L3 headers here are the frame after that demultiplex.
    """
    family = config["family"]
    ip_start, udp_start = 14, 34 if family == 4 else 54
    if len(frame) < udp_start + 8:
        return None
    if frame[12:14] != (b"\x08\x00" if family == 4 else b"\x86\xdd"):
        return None
    if family == 4:
        if frame[23] != 17:
            return None
        udp_start = ip_start + (frame[ip_start] & 15) * 4
        source, group, ttl = frame[26:30], frame[30:34], frame[22]
    else:
        if frame[20] != 17:
            return None
        source, group, ttl = frame[22:38], frame[38:54], frame[21]
    if (source, group) != (ipaddress.ip_address(config["source"]).packed,
                           ipaddress.ip_address(config["group"]).packed):
        return None
    if len(frame) < udp_start + 8:
        return None
    sport, dport, length, _ = struct.unpack_from("!HHHH", frame, udp_start)
    if (sport, dport) != (config["port"], config["port"]):
        return None
    body = frame[udp_start + 8:udp_start + length]
    prefix = MAGIC + bytes.fromhex(config["token"])
    if not body.startswith(prefix):
        return None
    assert len(body) == len(prefix) + 4 + 128, "truncated/oversized replica"
    sequence = struct.unpack_from("!I", body, len(prefix))[0]
    assert 0 <= sequence < config["count"], f"unexpected sequence {sequence}"
    assert body == payload(config["token"], sequence), "corrupt payload"
    # One routing hop by default. A bridged replica keeps the sender's 64.
    hops = config.get("hops", 63)
    assert ttl == hops, f"expected TTL/hop-limit {hops}, got {ttl}"
    assert frame[:6] == multicast_mac(config["group"]), "wrong multicast MAC"
    # None leaves the source MAC to a case that asserts it on its own.
    if source_mac is not None:
        assert frame[6:12] == bytes.fromhex(source_mac.replace(":", "")), "wrong source MAC"
    return sequence


def record(result: dict, sequence: int) -> None:
    if sequence in result["seen"]:
        result["duplicates"] += 1
    result["seen"].add(sequence)


def summary(results: dict) -> dict:
    return {iface: {**r, "seen": sorted(r["seen"])} for iface, r in results.items()}


def assert_results(results: dict, expected: list[str], count: int) -> None:
    assert set(expected) <= results.keys(), (expected, results.keys())
    for iface, result in results.items():
        want = list(range(count)) if iface in expected else []
        assert result["seen"] == want, f"{iface}: missing or unexpected replicas: {result}"
        assert result["duplicates"] == 0, f"{iface}: duplicate replicas: {result}"
        assert not result["errors"], f"{iface}: malformed replicas: {result}"


def capture(config: dict) -> None:
    results = {iface: {"seen": set(), "duplicates": 0, "errors": []}
               for iface in config["interfaces"]}
    sockets = []
    running = True

    def stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    protocol = 0x0800 if config["family"] == 4 else 0x86dd
    try:
        with selectors.DefaultSelector() as poll:
            for iface, mac in config["interfaces"].items():
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(protocol))
                sockets.append(sock)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                sock.bind((iface, protocol))
                # Join only this Ethernet multicast address on this socket.
                # Closing the socket drops its membership; no persistent
                # promiscuity, sysctl or IP membership is changed.
                request = struct.pack("IHH8s", socket.if_nametoindex(iface), 0, 6,
                                      multicast_mac(config["group"]))
                sock.setsockopt(263, 1, request)  # SOL_PACKET/PACKET_ADD_MEMBERSHIP
                # And promiscuity, held by this socket alone: a VLAN device on
                # a snooping bridge (the orchestrator's WAN peer is one) only
                # sees a group the bridge knows its host joined, and a routed
                # replica's group is one nothing here joins at the IP layer.
                # A promiscuous upper makes the bridge deliver it anyway.
                request = struct.pack("IHH8s", socket.if_nametoindex(iface), 1, 0, b"")
                sock.setsockopt(263, 1, request)  # PACKET_MR_PROMISC
                sock.setblocking(False)
                poll.register(sock, selectors.EVENT_READ, (iface, mac))
            Path(config["ready"]).write_text(str(os.getpid()))
            deadline = time.monotonic() + config.get("seconds", 30)
            while running and time.monotonic() < deadline:
                for key, _ in poll.select(0.1):
                    iface, mac = key.data
                    for _ in range(64):
                        try:
                            frame, address = key.fileobj.recvfrom(65536)
                        except BlockingIOError:
                            break
                        if address[2] == socket.PACKET_OUTGOING:
                            continue
                        # A socket on a VLAN's parent also receives that
                        # VLAN's frames, untagged, naming the VLAN device;
                        # they are the child's copies to count, not ours.
                        if address[0] != iface:
                            continue
                        try:
                            sequence = decode(frame, config, mac)
                            if sequence is not None:
                                record(results[iface], sequence)
                        except AssertionError as exc:
                            results[iface]["errors"].append(str(exc))
    finally:
        for sock in sockets:
            sock.close()
        destination = Path(config["result"])
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(summary(results)))
        temporary.replace(destination)


if __name__ == "__main__":
    capture(json.loads(sys.argv[1]))

"""The raw replay-carrying SA installer uses the Linux XFRM wire layout."""
from __future__ import annotations

import socket
import struct

from _ipsec_helpers import newsa, sa_add


ENDPOINTS = dict(src="198.51.100.9", dst="203.0.113.17", spi=0x12345678,
                 reqid=42, ifindex=9)
REPLAY = (17, 113, 0xB)
AEAD = ("rfc4106(gcm(aes))", bytes(range(20)), 128)


def attributes(body):
    """Decode independently of the builder, including its fixed SA header."""
    assert body[:56] == bytes(56)
    assert body[56:72] == socket.inet_aton(ENDPOINTS["dst"]) + bytes(12)
    assert body[72:80] == struct.pack(">I", ENDPOINTS["spi"]) + bytes([50, 0, 0, 0])
    assert body[80:96] == socket.inet_aton(ENDPOINTS["src"]) + bytes(12)
    assert body[96:128] == b"\xff" * 32
    assert body[128:204] == bytes(76)
    assert struct.unpack_from("<IIHBBB", body, 204) == (0, 42, 2, 1, 32, 0)
    assert body[217:224] == bytes(7)
    decoded = {}
    offset = 224
    while offset < len(body):
        length, kind = struct.unpack_from("<HH", body, offset)
        assert 4 <= length <= len(body) - offset and kind not in decoded
        decoded[kind] = body[offset + 4:offset + length]
        aligned = (length + 3) & ~3
        assert body[offset + length:offset + aligned] == bytes(aligned - length)
        offset += aligned
    assert offset == len(body)
    assert decoded[10] == struct.pack("<III", *REPLAY)
    return decoded


def test_newsa_aead_preserves_endpoints_and_replay():
    body = newsa(**ENDPOINTS, aead=AEAD, inbound=True, replay_window=32,
                 replay=REPLAY, natt=(4500, 4501))
    attrs = attributes(body)
    assert set(attrs) == {18, 10, 4, 28}
    name, key, icv_bits = AEAD
    assert attrs[18] == name.encode().ljust(64, b"\0") + struct.pack("<II", 160, icv_bits) + key
    assert attrs[4] == struct.pack("<H", 2) + struct.pack(">HH", 4500, 4501) + bytes(18)
    assert attrs[28] == struct.pack("<IBBH", 9, 6, 0, 0)


def test_newsa_keeps_default_cbc_and_authentication_attributes():
    attrs = attributes(newsa(**ENDPOINTS, replay_window=32, replay=REPLAY))
    assert set(attrs) == {2, 20, 10, 28}
    assert attrs[2] == b"cbc(aes)".ljust(64, b"\0") + struct.pack("<I", 128) + b"\xa5" * 16
    assert attrs[20] == b"hmac(sha256)".ljust(64, b"\0") + struct.pack("<II", 256, 128) + b"\x5a" * 32
    assert attrs[28] == struct.pack("<IBBH", 9, 4, 0, 0)


async def test_sa_add_sends_aead_and_replay_without_crypto_offload_attribute():
    calls = []

    class Target:
        async def netlink_send(self, *args, **kwargs):
            calls.append((args, kwargs))
            return {"body_hex": "00000000", "reply_hex": struct.pack("<IHHII", 16, 2, 0, 1, 0).hex()}

    session = object()
    reply = await sa_add(Target(), session, **ENDPOINTS, aead=AEAD, offload=False,
                         replay_window=32, replay=REPLAY, timeout_ms=700, failslab_times=3)
    assert reply.ok and not reply.lost
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[:2] == (session, 6)
    attrs = attributes(args[2])
    assert set(attrs) == {18, 10}
    assert attrs[18] == AEAD[0].encode().ljust(64, b"\0") + struct.pack("<II", 160, 128) + AEAD[1]
    assert kwargs == dict(nlmsg_type=16, nlmsg_flags=5, timeout_ms=700, failslab_times=3)

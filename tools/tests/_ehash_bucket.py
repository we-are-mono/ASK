"""Which classifier bucket a flow's key lands in, so a test can crowd one.

The SDK picks an external hash table's bucket from a reflected CRC-64/ECMA
of the key (get_indexed_hash_bucket(), crc64.h): seeded with all ones, no
final xor, the top 16 bits shifted by the table's hashshift and masked. The
CRC is affine, so whether two keys of one length share a bucket depends on
their difference alone: the ports chosen here collide whatever the port id
and addresses around them.

CDX's native IPv4 TCP/UDP key (insert_entry_in_classif_table_encap(),
cdx_ehash.c) is 56 bytes: the logical port id, addresses, ports, protocol,
34 zero bytes for outer tunnel checks and eight for the PPPoE identity.
The protocol tables have 32768 buckets and hashshift 0.
"""
from __future__ import annotations

import ipaddress

POLY = 0xC96C5795D7870F42
TABLE = []
for _byte in range(256):
    _crc = _byte
    for _ in range(8):
        _crc = (_crc >> 1) ^ POLY if _crc & 1 else _crc >> 1
    TABLE.append(_crc)

IPV4_MASK = 0x7FFF
MCAST_MASK = 0xFF
# Destination-port XOR offsets admitting 33 colliding keys while source ports
# stay below 32768. Consecutive destinations need not have such an inverse.
CROWDED_DPORT_XORS = (0, 1, 6, 7, 8, 9, 14, 15, 18, 19, 20, 21, 26, 27, 28, 29,
                     32, 33, 38, 39, 40, 41, 46, 47, 50, 51, 52, 53, 58, 59, 60, 61, 66)


def crc64(data: bytes) -> int:
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc = TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc


def bucket(key: bytes, mask: int = IPV4_MASK, shift: int = 0) -> int:
    return (crc64(key) >> ((6 - shift) * 8)) & mask


def ipv4_key(portid: int, source: bytes, destination: bytes, proto: int, sport: int, dport: int) -> bytes:
    return (bytes([portid]) + source + destination
            + sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + bytes([proto]) + bytes(42))


def _ports_bucket(sport: int, dport: int) -> int:
    return bucket(ipv4_key(0, bytes(4), bytes(4), 17, sport, dport))


def mcast_ipv4_key(portid: int, source_mac: bytes, source: bytes, group: bytes) -> bytes:
    """Bridged UDP multicast's 22-byte key, including its mapped Ethernet DA."""
    destination_mac = bytes([1, 0, 0x5E, group[1] & 0x7F, group[2], group[3]])
    return bytes([portid]) + destination_mac + source_mac + source + group + bytes([17])


def crowded_mcast_ipv4(count: int = 33, prefix: str = "239.79.0.0/16") -> list[str]:
    """Distinct groups colliding for any common source MAC, IP and port id."""
    buckets = {}
    for group in ipaddress.IPv4Network(prefix).hosts():
        index = bucket(mcast_ipv4_key(0, bytes(6), bytes(4), group.packed), MCAST_MASK)
        groups = buckets.setdefault(index, [])
        groups.append(str(group))
        if len(groups) == count:
            return groups
    raise AssertionError(("not enough colliding multicast groups", count, prefix))


def crowded_ipv4(dports: list[int], low: int = 1024, high: int = 32768) -> list[tuple[int, int]]:
    """One source port per destination port, all of the IPv4 keys sharing a
    bucket in one direction's table, every source port in [low, high): below
    the usual ephemeral range, so binding them collides with nothing."""
    zero = _ports_bucket(0, 0)
    image = {}
    for offset in range(1 << 16):
        image.setdefault(_ports_bucket(offset, 0) ^ zero, []).append(offset)
    # The source port offsets that cancel each destination port's change.
    offsets = [image[_ports_bucket(0, d) ^ _ports_bucket(0, dports[0])] for d in dports]
    for first in range(low, high):
        sports = []
        for options in offsets:
            # These inverse images of a linear CRC map are disjoint or
            # identical cosets. Choosing an unused member cannot consume a
            # different set's only candidate, so no combination search is
            # needed when one port's candidates are outside the range.
            available = [first ^ offset for offset in options
                         if low <= (first ^ offset) < high and (first ^ offset) not in sports]
            if not available:
                break
            sports.append(available[0])
        else:
            pairs = list(zip(sports, dports))
            assert len({_ports_bucket(s, d) for s, d in pairs}) == 1, pairs
            return pairs
    raise AssertionError(("no crowded source ports in range", dports, low, high))

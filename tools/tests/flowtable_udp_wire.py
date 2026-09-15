"""Independent Ethernet/IPv4/UDP receive validation, also staged on the LAN VM."""
import socket
import struct


def wire_checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def udp_wire_payload(frame, *, source_ip, destination_ip, source_port, destination_port,
                     source_mac, destination_mac, zero_checksum=False):
    if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
        return None
    ihl = (frame[14] & 15) * 4
    start = 14 + ihl
    if len(frame) < start + 8:
        return None
    if (frame[26:30], frame[30:34], struct.unpack('!HH', frame[start:start + 4])) != (
            socket.inet_aton(source_ip), socket.inet_aton(destination_ip), (source_port, destination_port)):
        return None
    assert frame[:6] == bytes.fromhex(destination_mac.replace(':', '')), frame.hex()
    assert frame[6:12] == bytes.fromhex(source_mac.replace(':', '')), frame.hex()
    assert frame[14] == 0x45 and frame[22] == 63, frame.hex()
    assert not (struct.unpack('!H', frame[20:22])[0] & 0x3fff), frame.hex()
    size = struct.unpack('!H', frame[16:18])[0]
    assert 28 <= size <= len(frame) - 14, frame.hex()
    ip = frame[14:14 + size]
    udp = ip[20:]
    assert wire_checksum(ip[:20]) == 0, frame.hex()
    assert struct.unpack('!H', udp[4:6])[0] == len(udp), frame.hex()
    checksum = struct.unpack('!H', udp[6:8])[0]
    assert (checksum == 0) == zero_checksum, frame.hex()
    if checksum:
        pseudo = ip[12:20] + struct.pack('!BBH', 0, 17, len(udp))
        assert wire_checksum(pseudo + udp) == 0, frame.hex()
    return udp[8:]

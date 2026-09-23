"""Exercise the multicast wire oracle without a network, UART or DUT fixtures."""
import importlib.util
import ipaddress
from pathlib import Path
import struct

import pytest

PATH = Path(__file__).resolve().parents[1] / "tests/mcast_wire_capture.py"
spec = importlib.util.spec_from_file_location("mcast_wire_capture", PATH)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
TOKEN = "0123456789abcdef0123456789abcdef"
SENDER = bytes.fromhex("020000000105")


def config(family):
    return {"family": family, "source": "10.0.0.232" if family == 4 else "fc00:beef::99",
            "group": "239.8.196.1" if family == 4 else "ff1e::8:196:1",
            "port": 47396, "token": TOKEN}


def frame(family, size_class=1, sequence=7, length=200, hops=64, flags=0x4000,
          nexthdr=17, source_mac=SENDER):
    """Independent construction: nothing here comes from the oracle's own
    payload or MAC builders."""
    c = config(family)
    data = (b"ASKMCW1" + bytes.fromhex(TOKEN) + struct.pack("!BI", size_class, sequence)
            + b"." * (length - 28))
    udp = struct.pack("!HHHH", c["port"], c["port"], 8 + len(data), 0x1234) + data
    if family == 4:
        mac = bytes.fromhex("01005e08c401")
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, flags, hops, 17, 0,
                         ipaddress.ip_address(c["source"]).packed,
                         ipaddress.ip_address(c["group"]).packed)
        ethertype = 0x0800
    else:
        mac = bytes.fromhex("333301960001")
        ip = struct.pack("!IHBB16s16s", 6 << 28, len(udp), nexthdr, hops,
                         ipaddress.ip_address(c["source"]).packed,
                         ipaddress.ip_address(c["group"]).packed)
        ethertype = 0x86dd
    return mac + source_mac + struct.pack("!H", ethertype) + ip + udp


@pytest.mark.parametrize("family", [4, 6])
def test_a_whole_datagram_is_recorded_with_its_framing(family):
    kind, info = capture.decode(frame(family, length=1400, hops=63), config(family))
    assert kind == "whole"
    assert info["class"] == 1 and info["sequence"] == 7 and info["hops"] == 63
    assert info["source"] == "02:00:00:00:01:05"
    assert info["destination"] == capture.multicast_mac(config(family)["group"]).hex(":")
    assert info["ip_length"] == (20 if family == 4 else 40) + 8 + 1400
    result = capture.empty()
    capture.record(result, (kind, info))
    capture.record(result, (kind, info))
    out = capture.summary({"eth0": result})["eth0"]
    assert out["seen"] == {"1": [7]} and out["duplicates"] == 1
    assert out["hops"] == [63] and out["sources"] == ["02:00:00:00:01:05"]
    assert out["fragments"] == 0


@pytest.mark.parametrize("flags", [0x2000, 0x0010, 0x2001])
def test_an_ipv4_fragment_is_counted_not_decoded(flags):
    assert capture.decode(frame(4, flags=flags), config(4)) == ("fragment", None)


def test_an_ipv6_fragment_is_counted_not_decoded():
    assert capture.decode(frame(6, nexthdr=44), config(6)) == ("fragment", None)


@pytest.mark.parametrize("family", [4, 6])
def test_another_stream_is_ignored(family):
    other = dict(config(family), source="10.0.0.9" if family == 4 else "fc00::9")
    assert capture.decode(frame(family), other) is None
    wrong_token = dict(config(family), token="f" * 32)
    assert capture.decode(frame(family), wrong_token) is None


@pytest.mark.parametrize("family", [4, 6])
def test_a_corrupt_copy_of_this_run_fails(family):
    wire = bytearray(frame(family))
    wire[-1] ^= 0xff
    with pytest.raises(AssertionError):
        capture.decode(bytes(wire), config(family))


def test_payload_round_trips():
    data = capture.payload(TOKEN, 3, 9, 1000)
    assert len(data) == 1000 and data.startswith(b"ASKMCW1")
    assert struct.unpack_from("!BI", data, 7 + 16) == (3, 9)

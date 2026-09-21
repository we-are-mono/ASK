"""Exercise the A158 wire oracle without a network, UART or DUT fixtures."""
import importlib.util
import ipaddress
from pathlib import Path
import struct

import pytest

PATH = Path(__file__).resolve().parents[1] / "tests/mroute_capture.py"
spec = importlib.util.spec_from_file_location("mroute_capture", PATH)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
MAC = "02:00:00:00:01:03"
TOKEN = "0123456789abcdef0123456789abcdef"


def frame(family, sequence=2):
    # Independent packet construction; do not use the oracle's payload or MAC
    # builder to generate its own expected input.
    config = {"family": family, "source": "10.0.0.232" if family == 4 else "fc00:beef::99",
              "group": "239.8.158.1" if family == 4 else "ff1e::8:158:1",
              "port": 47358, "count": 256, "token": TOKEN}
    data = b"ASK-A158" + bytes.fromhex(TOKEN) + struct.pack("!I", sequence) + b"." * 128
    udp = struct.pack("!HHHH", 47358, 47358, 8 + len(data), 0x1234) + data
    if family == 4:
        mac = bytes.fromhex("01005e089e01")
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 63, 17, 0,
                         ipaddress.ip_address(config["source"]).packed,
                         ipaddress.ip_address(config["group"]).packed)
        ethertype = 0x0800
    else:
        mac = bytes.fromhex("333301580001")
        ip = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 63,
                         ipaddress.ip_address(config["source"]).packed,
                         ipaddress.ip_address(config["group"]).packed)
        ethertype = 0x86dd
    wire = mac + bytes.fromhex(MAC.replace(":", "")) + struct.pack("!H", ethertype) + ip + udp
    return config, wire


@pytest.mark.parametrize("family", [4, 6])
def test_exact_replica(family):
    config, wire = frame(family)
    assert capture.decode(wire, config, MAC) == 2
    assert capture.multicast_mac(config["group"]) == wire[:6]
    assert capture.payload(TOKEN, 2) == wire[-156:]
    result = {"seen": set(), "duplicates": 0, "errors": []}
    capture.record(result, 2)
    capture.record(result, 2)
    assert capture.summary({"vlan311": result}) == {
        "vlan311": {"seen": [2], "duplicates": 1, "errors": []}}


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("fault", ["ttl", "source_mac", "group_mac", "payload", "sequence", "truncated"])
def test_bad_replica_rejected(family, fault):
    config, wire = frame(family, 256 if fault == "sequence" else 2)
    wire = bytearray(wire)
    if fault == "ttl":
        wire[22 if family == 4 else 21] = 64
    elif fault == "source_mac":
        wire[6] ^= 1
    elif fault == "group_mac":
        wire[0] ^= 1
    elif fault == "payload":
        wire[-1] ^= 1
    elif fault == "truncated":
        del wire[-1]
    with pytest.raises(AssertionError):
        capture.decode(bytes(wire), config, MAC)


@pytest.mark.parametrize("family", [4, 6])
def test_other_run_and_source_ignored(family):
    config, wire = frame(family)
    assert capture.decode(wire, {**config, "token": "ff" * 16}, MAC) is None
    assert capture.decode(wire, {**config, "source": "10.0.0.233" if family == 4 else "fc00:beef::9a"}, MAC) is None
    assert capture.decode(wire, {**config, "port": 47359}, MAC) is None
    assert capture.decode(wire[:10], config, MAC) is None


def test_ninth_listener_cannot_hide_behind_eight_good_copies():
    results = {f"vlan{vid}": {"seen": list(range(4)), "duplicates": 0, "errors": []}
               for vid in range(311, 319)}
    results["vlan319"] = {"seen": [], "duplicates": 0, "errors": []}
    capture.assert_results(results, list(results)[:8], 4)
    with pytest.raises(AssertionError):
        capture.assert_results(results, list(results), 4)
    results["vlan319"]["seen"] = list(range(4))
    capture.assert_results(results, list(results), 4)
    with pytest.raises(AssertionError):  # a withdrawn oif must stop receiving
        capture.assert_results(results, list(results)[:8], 4)
    results["vlan319"]["duplicates"] = 1
    with pytest.raises(AssertionError):
        capture.assert_results(results, list(results), 4)

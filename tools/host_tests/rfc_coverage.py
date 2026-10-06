"""Every RFC the gateway claims has a rig test that proves it.

The catalogue below is the claim; `@pytest.mark.rfc("NNNN", section=...)` on a
rig test is the proof. Run this file directly for the RFC -> tests table:

    python tools/host_tests/rfc_coverage.py
"""

import ast
from collections import defaultdict
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1] / "tests"

# number -> (status, note). "supported" and "declined" (refused on purpose, with
# software carrying the traffic) each need a test; the others are recorded so
# a marker naming them is still a known RFC.
CATALOGUE = {
    # Forwarding, fragmentation, ICMP, ARP
    "791": ("supported", "IPv4 forwarding, TTL, fragmentation"),
    "8200": ("supported", "IPv6 forwarding, hop limit, fragmentation"),
    "792": ("supported", "ICMP errors through NAT, Time Exceeded"),
    "4443": ("supported", "ICMPv6 Packet Too Big, Time Exceeded"),
    "826": ("supported", "ARP neighbour changes retire flows"),
    "4861": ("supported", "Neighbor Discovery changes retire flows"),
    "4862": ("supported", "SLAAC"),
    "5722": ("supported", "overlapping IPv6 fragments dropped"),
    "1812": ("supported", "router requirements: TTL, multicast scope"),
    "793": ("supported", "TCP flows"),
    "768": ("supported", "UDP flows"),
    # Translation
    "3022": ("supported", "NAPT"),
    "4787": ("supported", "UDP NAT behaviour unchanged by offload"),
    "6296": ("supported", "NPTv6"),
    "2766": ("unsupported", "NAT-PT, Historic"),
    # Multicast
    "1112": ("supported", "IPv4 multicast"),
    "2236": ("supported", "IGMPv2"),
    "3376": ("supported", "IGMPv3"),
    "2710": ("supported", "MLDv1"),
    "3810": ("supported", "MLDv2"),
    "4291": ("supported", "IPv6 multicast addressing"),
    "3307": ("supported", "IPv6 multicast allocation"),
    "4541": ("supported", "IGMP/MLD snooping"),
    # Access
    "2131": ("supported", "DHCP client lease renewal"),
    "2516": ("supported", "PPPoE"),
    "1661": ("supported", "PPP, LCP echo"),
    "1332": ("supported", "IPCP"),
    "1334": ("supported", "PAP"),
    "1994": ("supported", "CHAP"),
    "3817": ("unsupported", "PPPoE relay"),
    # Tunnels
    "2473": ("supported", "4o6 tunnel"),
    "4213": ("supported", "6o4 (sit) tunnel"),
    "5969": ("unsupported", "6rd, TODO after 1.1.0"),
    "7597": ("unsupported", "MAP-E, TODO after 1.1.0"),
    # IPsec
    "4301": ("supported", "tunnel-mode SAs, lifetimes"),
    "4303": ("supported", "ESP, sequence numbers"),
    "3948": ("supported", "NAT-T"),
    "7296": ("supported", "IKEv2"),
    "2409": ("supported", "IKEv1"),
    "2402": ("declined", "AH stays in software"),
    "3173": ("declined", "IPComp stays in software"),
    # Linux/OpenWrt userspace, not the offload
    "1035": ("out-of-scope", "DNS"),
    "2616": ("out-of-scope", "HTTP"),
    "959": ("out-of-scope", "FTP"),
}


def markers():
    """RFC -> ["file::test[ section]"], from the decorators of every rig test."""
    found = defaultdict(list)
    for path in sorted(TESTS.glob("[!_]*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr == "rfc"):
                    number = decorator.args[0].value
                    section = next((k.value.value for k in decorator.keywords if k.arg == "section"),
                                   None)
                    found[number].append(f"{path.name}::{node.name}"
                                         + (f" §{section}" if section else ""))
    return found


def test_rfc_coverage():
    found = markers()
    unknown = sorted(set(found) - set(CATALOGUE))
    assert not unknown, f"markers name RFCs missing from the catalogue: {unknown}"
    untested = sorted(n for n, (status, _) in CATALOGUE.items()
                      if status in ("supported", "declined") and n not in found)
    assert not untested, f"claimed RFCs with no rig test: {untested}"


if __name__ == "__main__":
    found = markers()
    for number, (status, note) in sorted(CATALOGUE.items(), key=lambda i: int(i[0])):
        tests = found.get(number, [])
        print(f"RFC {number:>5}  {status:<12} {note}")
        for test in tests:
            print(f"           {test}")
        if status in ("supported", "declined") and not tests:
            print("           (no test)")

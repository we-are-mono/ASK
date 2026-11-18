# NAT64 feasibility — 2026-11-18/19

What the NAT-PT flow-entry opcodes put on the wire, measured on the DK before
any translator was wired to them. The mechanism and the design are in the
[NAT64 guide](../nat64.md).

## Setup

* **Build:** ASK branch `nat64-offload` (base `mono-1.4.0`, `d94a73e9`); the
  6.18 KASAN test image, TFTP-booted; microcode 210.10.1.
* **Topology:** loki's passthrough NIC had been detached from the VM, so
  every probe ran on the WAN link alone. The DUT had hairpin entries,
  `in=eth4 out=eth4`, installed through the `cdx.xlat_test` hook. The WAN
  host (vision, `br0`) crafted frames to the DUT's MAC with scapy and
  captured what came back.
* **Entries:** IPv6 `fd25:…:274e.40001 → 64:ff9b::a00:e8.5000` translated to
  IPv4 `10.0.0.62.40001 → 10.0.0.232.5000`, and the reverse.
* **Verification:** from raw bytes: frame length against the IP length, the
  IPv4 header checksum, the L4 checksum over the new pseudo-header, and every
  header field.

## Results

| Probe | Result |
| --- | --- |
| UDP and TCP, both directions, 64 and 1400-byte payloads | Translated; L4 checksum correct; data intact; TTL/hop limit decremented by one |
| IPv4 header checksum, template naming the protocol | Wrong by exactly the protocol value: 0x11 for UDP, 0x06 for TCP |
| IPv4 header checksum, template protocol 0 | Correct, for UDP and TCP. The microcode writes the protocol from the IPv6 next header |
| Template checksum field set to the protocol | Wrong by twice the protocol: the field is summed in |
| TOS 0xb8 sent, copy flag (bit 25) set, template TOS 0 | 0x00 out, both directions |
| Template TOS 0x28 | 0x28 out, both directions |
| Word bits 26-31 one at a time | No TOS copy; bit 26 makes the IPv4 ID the template's (0) |
| IPv4 identification | 1, 2, 3, … per flow |
| Trailing bytes | 2 past the IP packet in every translated frame, both directions, with the Ethernet header rebuilt or not. A plain NAT entry with a rebuilt header has none |
| Without the Ethernet rebuild | EtherType left as garbage: 0x36ff and 0xbfb5, leftovers of the old header and the headroom |
| Template length 18, 22 or 24 instead of 20 | Nothing came back |
| IPv4 UDP checksum 0, into IPv6 | Emitted with checksum 0x0000 (invalid in IPv6) |
| TTL 2 / 1 / 0 | Out with 1 / to the CPU untranslated (Linux's port-unreachable quotes TTL 1) / to the CPU |
| TCP SYN from a host socket | Never counted by the entry; the classifier gives SYNs to the CPU |

## MTU and DF

**Entry MTU 1500, no expansion, IPv4 to IPv6:**

| IPv4 packet | Result |
| --- | --- |
| up to 1478 bytes | Arrived whole |
| 1480 bytes (IPv6 1500 + 2) | Fragmented into IPv6 fragments, DF ignored |

**Entry MTU 1600:** frames carrying up to 1522 bytes after the Ethernet
header arrived. The DUT's MAC and the WAN host both accept the extra 2 bytes.

**Entry MTU egress + 2 = 1502, expansion 22** (the encoder's values now):

| IPv4 packet | DF clear | DF set |
| --- | --- | --- |
| 1480 bytes | IPv6 payload 1460, whole | Same, whole |
| 1481 bytes | IPv6 fragments 0\|1448, 1448\|13 | To the CPU: Linux's port unreachable |
| 1500 bytes | IPv6 fragments 0\|1448, 1448\|32 | To the CPU |

**IPv6 to IPv4:** a 1500-byte IPv6 packet became a 1480-byte IPv4 packet,
correct.

## Load

**Method:** a Python IPv6 UDP sender with 1400-byte payloads ran on the WAN
host for 5 s, through the 6to4 entry, to an IPv4 receiver on the same host.
For this run only, the host had the route `64:ff9b::/96 via fe80::eaf6:d7ff:fe00:114`.

**Results:**
* sent 2,551,040 packets (510 kpps, 5.71 Gbit/s of payload; the Python sender
  set this rate);
* the entry counted 2,551,041 (every one, plus a probe);
* the DUT CPU's eth4 receive counter rose by 12, all background;
* 98.5% arrived, with no bad payload or peer. The missing 1.5% is the same
  host's single-threaded receiver.

## Not measured

* Line rate with a real LAN client (loki's NIC was detached).
* Whether the microcode honours a DF bit in the 6to4 template.
* FIN/RST handling.
* A translated direction combined with VLAN or PPPoE.
* The source of the 2 trailing bytes.

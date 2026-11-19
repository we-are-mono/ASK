# NAT64 feasibility — 2026-11-18/19

What the NAT-PT flow-entry opcodes put on the wire, measured on the DK before
any translator was wired to them, and what their handlers in the microcode
do. The mechanism and the design are in the [NAT64 guide](../nat64.md).

**Correction (2026-11-19):** the first round concluded that TOS/traffic class
could only be fixed per flow. The handlers have a copy path behind a template
sentinel of 0xff, which the first round never tried. It works; see the
results table and the handlers below.

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
| Template TOS/TC 0xff (the handlers' sentinel, below), bit 25 set on 6to4 | Arriving 0xb8, 0xbb (CE), 0x01, 0x00 each copied, UDP and TCP, both directions; IPv4 header checksum correct |
| Template DF (6to4) | `frag 0x4000` out, checksum correct |
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

## The handlers

Decoded statically from the stock blob (210.10.1, SHA-256 `5f3ed8d3…`). The
microcode decompilation project's tools and notes were the starting point; its
comparison wrongly lists NAT64 as impossible in hardware. Some instruction
classes are inferred, but the readings reproduce every measurement above.

* **Dispatch.** w8682 loads the opcode byte and w8688 is a jump table on its
  high nibble. Nibble 5 (w8699) jumps to w10408, where bit 0 selects 4to6
  (w10409-w10548) and bit 1 selects 6to4 (w10550-w10730). Both exit at
  w10732 having consumed 4 + template length bytes of parameter.
* **Template.** The length (bits 16-23) is read at w10414 and w10551; the
  template is copied over the old header at w10462 and w10606. The old
  header's length is the parser's L4 offset minus the current L3 offset, so
  IPv4 options go and IPv6 extension headers go too. But the IPv4 protocol
  is written from the first next header (w10563, w10626).
* **TTL** (bit 24): w10468 and w10613 write TTL−1 / hop−1.
* **IPv4 ID:** w10642-w10658 write the counter, add it to the checksum,
  increment it and store it back into the entry, unless bit 26 is set.
* **IPv4 checksum:** the template's sum (protocol, length, ID, TTL and
  checksum fields counted as whatever they hold) plus TTL, protocol, length
  and ID. It is folded and stored at w10659-w10673. The template must
  therefore hold 0 in each of those fields.
* **TOS/TC sentinel.**
  - 4to6: w10480-w10487 insert the saved IPv4 TOS when the template's traffic
    class reads 0xff; no flag is involved.
  - 6to4: w10631 tests bit 25, then w10633-w10640 insert the saved traffic
    class when the template TOS reads 0xff. The 0xff is subtracted from the
    checksum and the real value added (w10637, w10640).
* **The 2 bytes.** IC+0xc0 is the frame-length delta: zeroed at w8668,
  reduced by 14 by the Ethernet strip, and added to the FD length at
  enqueue. NAT-PT adds the header difference plus a literal 2 (w10438 on
  4to6, w10596 on 6to4; w10452, w10459, w10582 and w10603 on paths the
  supported headers never take).

## Patched microcode: the 2 bytes removed

**The patch:** two words, `f0415302 → f0415300` (w10438) and
`f4414302 → f4414300` (w10596), built with `qef-patch.py` (SHA-256
`0f10775f…`).

**Boot:** RAM-only through U-Boot's `fman_ucode`. The DUT's device-tree copy
of the firmware hashed to the patched value.

**Results:** every probe above came back with no trailing bytes and correct
checksums.

**Side effect, as expected:** with the encoder still adding the 2 bytes of
slack, a 1481-byte IPv4 packet without DF went through whole, as 1501 bytes
of IPv6. With this microcode the slack is 0 and the 4to6 expansion is 20.

**Back to stock:** a plain reboot loads the flash copy.

## Fragment payloads (2026-11-19)

**The question.** The adapter keeps non-TCP directions out of paths smaller
than their ingress, on A202's finding (2026-09-24, repeated in A316 and A385)
that the microcode's fragments of a frame received on a port carry an
all-zero payload.

**Method.** Each case sent one patterned UDP datagram with DF clear through
an entry installed by the test hook (stock 210.10.1, this branch's 6.18
image), then reassembled what came back and compared it byte for byte.

**Results:**

| Entry | Datagram | Fragments | Payload |
| --- | --- | --- | --- |
| Hairpin eth4, plain IPv4 NAT, MTU 1000 | 1400 B | 2 | identical |
| Hairpin eth4, NAT-PT 4to6, MTU 1500 | 1472 B (IPv6 1520) | 2 IPv6 | identical |
| Hairpin eth4, IPv6 into a 6o4 tunnel, MTU 1480 | 1452 B | 2 outer IPv4 | identical |
| Hairpin eth4, IPv4 into a PPPoE session, MTU 1492 | 1472 B | 2 | identical |
| eth3 → eth4 (loki), SNAT, MTU 1000 | 1400 B | 2 | identical |
| eth3 → eth4, into a PPPoE session, MTU 1492 (A202's shape) | 1472 B | 2 | identical |
| eth3 → eth4, into a 4o6 tunnel, MTU 1460 (A202's shape) | 1472 B | 2 outer IPv6 | identical |
| eth3 at MTU 9000 → eth4, MTU 1500 (A316's jumbo shape) | 3000 B | 3 | identical |

An unfragmented control alongside each case was intact too.

**Conclusion.** A202's zero payload does not reproduce on this build in any
recorded shape. What changed since is not known.

## Not measured

* Line rate with a real LAN client (loki's NIC was detached).
* FIN/RST handling.
* A translated direction combined with VLAN or PPPoE.
* How the classifier treats IPv6 extension headers on an offloaded flow.

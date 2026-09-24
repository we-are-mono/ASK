# Linux flowtable IPv6

IPv6 offload in the ASK flowtable adapter: what makes a flow eligible, the two
places where the family is not a cosmetic difference, and the hardware proof.

The accepted boundary is the
[supported scope](README.md#supported-scope). This document
explains the mechanism behind it; the
[NAT guide](nat.md) covers translation, which IPv6 shares.

## What the family changes

The hardware and Linux were both ready before any of this work. The classifier
has had `FFTYPE_IPV6`, `HASH_CT6` and a 38-byte IPv6 TCP/UDP key since the NXP
sources, the PCD gives every port `cdx_udp6_dist` and `cdx_tcp6_dist`, the soft
parser's SYN/FIN/RST punt and hop-limit check are family-agnostic, and
`nf_flow_table_ip.c` has complete IPv6 hooks. What was IPv4-only was the
adapter's own key.

`struct cdx_ft_rule` is that key. Its four addresses are now
`union nf_inet_addr` — the same UAPI value type conntrack uses, so a tuple and a
rule compare without transcription — with a `family` field selecting the arm.
The unused bytes of every address are always zero, which keeps whole-rule
`memcmp` and the `jhash2` key hash correct for both families at once.

Because that struct is the key, the change reaches `ft_parse`, `ft_translation`,
`ft_nat_edit`, `ft_key_hash`, `ft_same_key`, `ft_find`, `ft_replace`,
`cdx_ft_hw_add` and the proc output together. Threaded halfway it still
compiles and silently mis-keys flows, which is why it landed as one increment.

## Two differences that are not cosmetic

**A destination is only valid for one FIB generation.** `ipv4_dst_check()`
ignores its cookie argument; `ip6_dst_check()` compares it against the fib6
node's `fn_sernum` and returns NULL on any mismatch. Validating a borrowed IPv6
route with `dst_check(dst, 0)` therefore rejects *every* route, and no IPv6 flow
could ever be admitted. Patch 140 now carries each direction's
`nf_dst_cookie` alongside its `nf_dst`, taken from the tuple the route was
selected under (`FLOW_CLS_HAS_NF_CONTEXT` 6).

**`twin_Sport` and `twin_Dport` overlay `Daddr_v6`.** In `CtEntry` the
hardware-visible area is a union: IPv4 spends it on its addresses and a twin
mirror, IPv6 spends all 32 bytes on two 128-bit addresses. `twin_Saddr`,
`twin_Daddr`, `twin_Sport` and `twin_Dport` sit at offsets 16 through 27, which
is the second half of `Daddr_v6`. An IPv6 entry must leave every one of them
alone; writing a twin port corrupts its own destination address. The reply
tuple reaches the encoder through the twin `CtEntry` object instead, which is
where `fill_actions()` reads it from for IPv6 anyway — and where it reads the
ports from in *both* families.

## Eligibility

Beyond the IPv4 rules, which all still apply:

- The dissector must describe `FLOW_DISSECTOR_KEY_IPV6_ADDRS` with exact masks
  in all four words, `ETH_P_IPV6`, and an `addr_type` that agrees; the
  conntrack's `l3num` must agree with both.
- Endpoints must be globally routable unicast. Link-local, loopback,
  unspecified, multicast, v4-mapped and v4-compatible addresses are declined,
  because a link-local endpoint is scoped to one link and cannot be forwarded
  between the two ports.
- The **next hop** is deliberately tested more weakly: link-local is normal and
  expected for an IPv6 gateway, so only loopback and non-unicast are declined.
- Neighbours resolve through `nd_tbl` rather than `arp_tbl`; both tables key on
  the leading bytes of the address union, so one pointer serves either.
- The route must not be `RTF_REJECT`, `RTF_LOCAL` or `RTF_ANYCAST`, and its
  `dst->error` must be clear.
- The MTU floor is `IPV6_MIN_MTU` (1280), not 68.
- A direction's MTU may not be below its ingress interface's IPv6 MTU; see
  the next section.

## Packets larger than the path

The microcode fragments any forwarded packet larger than its entry's MTU, and
for IPv6 nothing makes it hand the packet to Linux instead. A router must never
fragment IPv6 (RFC 8200): it drops the packet and returns ICMPv6 Packet Too Big
with the link MTU (RFC 4443), which is how the sender learns the path MTU.
Linux does exactly that; the hardware, left to itself, does not. Measured on
a route locked to 1280: a 1448-byte datagram left the WAN port as two fragments
carrying the microcode's own sequential identification, and no Packet Too Big
came back. Both controls the encoder has were tried on the board and act on
IPv4 alone: the `PREEMPT_DFBIT_HONOR` preemptive check, which excepts an
oversized IPv4 packet with DF set, and the fragmenter's DF action in the MURAM
parameter block, set live to don't-fragment.

So an IPv6 direction is admitted only while nothing larger than its MTU is
expected to arrive: while the IPv6 MTU of the interface it arrives on
(`net.ipv6.conf.<if>.mtu`, the value its hosts learn from router
advertisements) is no larger than the direction's own. A direction refused for
this stays on the software flowtable path, where the oversized packet reaches
`ip6_forward()` and gets its Packet Too Big; the reverse direction is admitted
on its own. The IPv6 MTU is a sysctl that no device event reports, so every
stats pass, and every time Linux offers an installed direction again, rechecks
the bound and retires an installed direction that no longer satisfies it
(counted as `mtu_invalidations`). The re-offer is what reaches the installed
half of a partially offloaded flow within a second, since Linux offers such a
flow again every second its other half forwards in software; the stats pass
reaches it too, on the statistics period.

Equal MTUs everywhere, the ordinary case, are unaffected. A smaller upstream
is where it shows: IPv6 leaving a 1500-byte LAN by PPPoE (1492) or a 6in4
tunnel (1480) runs in software in that direction unless the LAN is told the
smaller MTU, by setting its IPv6 MTU and advertising it. That is the
configuration such a network wants anyway, since it is also what spares its
hosts a Packet Too Big round trip on every new path. An SA does not narrow
the bound: through a transform a flow's MTU is its outer device's, because
`ip6_dst_mtu_maybe_forward()` ignores the bundle's unlocked `RTAX_MTU`, so an
IPv6 direction into an SA is admitted as before. Its entry carries the port's
MTU plus the ESP expansion, so a packet that fits the port but not the bundle
(1438 for AES-CBC and a 128-bit HMAC-SHA256 tag over IPv4) is taken by the
hardware: SEC encrypts the inner packet whole and the microcode fragments the
outer IPv4 packet, whose DF stays clear because an IPv6 inner packet has none
to copy. Measured on the DK (`test_flowtable_ipv6_sa.py`): the peer reassembles
and decrypts every such packet exactly once, the microcode counts two IPv4
fragments and no IPv6 ones, and no Packet Too Big is sent. The inner packet is
never fragmented, which is what bounding exists to prevent -- a router must not
fragment IPv6 -- and post-encryption fragmentation is what Linux itself does
for an IPv4 inner packet without DF, so the direction stays in hardware; the
microcode's fragments of the SEC output are correct. IPv4 has a bound of its
own for a different reason: the microcode's fragments of a frame received on
an Ethernet port carry an all-zero payload, so an IPv4 direction that is
neither TCP nor to or from an SA is never admitted into a path smaller than
what its ingress receives
([architecture.md](architecture.md#native-context-and-admission)).

## The consumer contract

One obligation, and only on a network whose upstream path is narrower than
its LAN. When the WAN is a PPPoE session (1492) or a 6in4/6rd tunnel (1480),
the integration that owns the LAN interface sets its IPv6 MTU to the upstream
path's and advertises that value in its router advertisements:

- `net.ipv6.conf.<lan>.mtu` set to the uplink's IPv6 MTU, which is what the
  admission bound above compares against;
- the RA MTU option carrying the same value (odhcpd `ra_mtu`, radvd
  `AdvLinkMTU`, systemd-networkd `[IPv6SendRA] ... LinkMTU` equivalents), so
  hosts send packets that fit and never need the Packet Too Big round trip.

Without it nothing breaks: the LAN-to-WAN IPv6 direction stays on the software
flowtable path and every oversized packet still gets its Packet Too Big from
`ip6_forward()`. Only that direction's acceleration is lost. Deriving the value
from the uplink belongs to the integration that configures the uplink, since
only it knows when a PPPoE session or tunnel comes up and at what MTU. ASK
itself configures neither interface.

## Translation

`nf_flow_rule_route_ipv6()` lays a translation out differently from IPv4: one
mangle action per 32-bit quarter of the address, five actions per edit rather
than two, and **no** trailing `FLOW_ACTION_CSUM` — IPv6 has no header checksum,
and the L4 checksum correction is the encoder's job. An admitted IPv6
translation therefore has `5 + 5 × edits` actions where IPv4 has `6 + 2 × edits`,
and `ft_nat_edit` validates each address word against the resolved conntrack
mapping in address order before accepting the port edit that follows them.

On the hardware side the IPv6 encoder rewrites each address whenever its status
bit is set and never compares the two, and it gates the port rewrite on either
bit. `cdx_ft_hw_add` therefore marks a direction translated when its address
*or* its port moved, which is exactly what the legacy IPv6 control path does.

## Route invalidation

IPv4 route changes reach the adapter through `NETEVENT_IPV4_ROUTE_UPDATE`,
published by patch 140 from `fib_trie.c` under RTNL. IPv6 gets the same
treatment from `ip6_fib.c` as `NETEVENT_IPV6_ROUTE_UPDATE`, with one contract
difference that matters: it is emitted under the table's `tb6_lock` and **not
always under RTNL**, because router advertisements install and withdraw routes
from softirq. Consumers must be atomic-safe, and RTNL does not exclude a
concurrent change.

That leaves a window RTNL closes for IPv4 but not for IPv6: a route committed
between admission's validation and the moment the new entry becomes visible to
the notifier would reach neither. `ft_replace` therefore revalidates both
borrowed destinations once more *after* publishing the entry; a change caught
there invalidates the handle and the entry retires through the same path as one
observed during hardware insertion.

## Verification

Host-side, `tools/host_tests/flowtable.c::test_ipv6` compiles the production
decoder against a simulated kernel and covers admission, the cookie contract,
link-local endpoint refusal against link-local gateway acceptance, the exact-mask
and family-agreement rules, the MTU floor, the five-action translation layout
against an IPv4-shaped one, and `ft_route6_event` selectivity.
`flowtable_hw.c` reproduces the `CtEntry` union byte for byte, so its IPv6
variants fail if any `twin_*` field is written over the destination address.

On hardware, `tools/tests/test_flowtable_ipv6.py` runs LAN VM → DUT → WAN host
over two ULA /64s and requires the classifier's own counters to account for
every packet of the measurement burst:

| Case | Hardware packets, each direction | Evidence beyond the counters |
| --- | --- | --- |
| Routed UDP | 64 | 64 echoed, zero lost |
| Source NAT | 64 | the WAN endpoint observed the translated source address and port |
| Destination NAT | 64 | replies arrived from the pre-translation destination |
| MASQUERADE | 64 | the address is pinned to the egress interface's own and the port is read back from the rule, then required of the wire |
| Hairpin double NAT | 64 | both translations at once, both directions entering and leaving by the LAN port |
| TCP | ≥100 segments | half a megabyte each way on one connection, cookies unchanged |

Further cases assert behaviour rather than a packet count. A device MTU
change retires the connection and lets it come back describing the new path:
each direction carries the MTU of the interface *it* leaves by, and one
connection is one retirement because both directions share an invalidation
handle. The WAN port is reduced to 1400 together with the LAN's IPv6 MTU, as
an operator would, so both directions come back at 1400 in hardware.
`test_flowtable_ipv6_mtu_bound` proves the bound itself: with the WAN route
locked to 1280 and the LAN's IPv6 MTU at 1280, only the LAN-to-WAN direction
is admitted; raising the LAN to 1500 retires it on the next stats pass or
re-offer and the
flow comes back with only the WAN-to-LAN direction in hardware; a 1448-byte
datagram then gets Packet Too Big with MTU 1280 and the microcode's IPv6
fragment counter does not move. `test_flowtable_ipv6_same_tuple_exceptions`
sends a hop limit of 1, hop-by-hop options, destination options, a chain of
both and fragments down a tuple with both directions in hardware: the first is
answered with Time Exceeded, the rest arrive intact, and the entries keep the
flow. Twenty-four
concurrent IPv6 connections then consume forty-eight directions with matching
handle and neighbour references, which is what makes the shared 32,768 budget
observable — accounting at a readable scale rather than a capacity fill.

Throughput was measured with `iperf3` over the routed IPv6 path on the KASAN
image: 9.173 Gb/s forward and 9.260 Gb/s reverse, against 97.9 Mb/s for the
same flow forwarded in software. The ratio is inflated by KASAN
instrumentation, which slows the software path far more than the hardware one;
the offloaded figure is the meaningful one.

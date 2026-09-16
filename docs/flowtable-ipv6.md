# Linux flowtable IPv6

IPv6 offload in the ASK flowtable adapter: what makes a flow eligible, the two
places where the family is not a cosmetic difference, and the hardware proof.

The accepted boundary is the
[supported scope](linux-flowtable-offload.md#supported-scope). This document
explains the mechanism behind it; the
[NAT guide](flowtable-nat.md) covers translation, which IPv6 shares.

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

Two further cases assert behaviour rather than a packet count. A device MTU
change retires the connection and lets it come back describing the new path:
each direction carries the MTU of the interface *it* leaves by, so reducing
the WAN port moves only the forward direction, and one connection is one
retirement because both directions share an invalidation handle. Twenty-four
concurrent IPv6 connections then consume forty-eight directions with matching
handle and neighbour references, which is what makes the shared 32,768 budget
observable — accounting at a readable scale rather than a capacity fill.

Throughput was measured with `iperf3` over the routed IPv6 path on the KASAN
image: 9.173 Gb/s forward and 9.260 Gb/s reverse, against 97.9 Mb/s for the
same flow forwarded in software. The ratio is inflated by KASAN
instrumentation, which slows the software path far more than the hardware one;
the offloaded figure is the meaningful one.

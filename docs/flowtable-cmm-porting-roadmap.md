# CMM retirement roadmap

What the Linux flowtable path still has to absorb before CMM can be retired,
and what it already replaces. Derived from `cmm/src/` (22 modules, ~21k lines),
the `cdx/control_*.c` handlers those modules drive, and the FCI command
families declared across `cdx/`.

Effort is relative, not an estimate. The column that decides sequencing is
whether Linux already provides the mechanism: where it does, the work is FMAN
key encoding plus an eligibility contract, which is the shape of the IPv4
NAT increments already delivered. Where it does not, the feature needs a
contract of its own and must not be forced through a unicast flowtable tuple.

Keep this file current as increments land. The accepted boundary at any moment
is the [supported scope](linux-flowtable-offload.md#supported-scope); this
roadmap is what sits outside it.

## Already replaced

The bounded IPv4 TCP/UDP NAT foundation supersedes roughly half of CMM by
volume. None of this needs porting; it needs deleting once CMM is retired.

| CMM subsystem | Lines | Replaced by |
| --- | ---: | --- |
| `conntrack.c` | 3,661 | Linux conntrack and `nft_flow_offload` admission |
| `route_cache.c` | 1,660 | Linux FIB with selective route invalidation |
| `forward_engine.c` | 1,530 | `nf_flow_table_ip` and the CDX backend |
| `neighbor_resolution.c` | 1,063 | Linux neighbour table with selective invalidation |
| `keytrack.c` | 1,021 | adapter cookie and key hash indexes |
| `module_route.c` | 597 | Linux routing and nexthop retirement |
| `module_rx.c`, `module_tx.c` | 907 | flowtable ingress and egress hooks |
| unicast half of `control_ipv6.c` | ~400 | the same adapter, with the address family threaded through its key |

## Remaining work

| # | Subsystem | Lines | FCI cmds | Linux mechanism | Effort | Notes |
| ---: | --- | ---: | ---: | --- | --- | --- |
| 3 | PPPoE (`pppoe.c`, `control_pppoe`) | 303 | 2 | Yes — `DEV_PATH_PPPOE` | Low-Med | The relay offset is already confirmed on hardware. |
| 5 | QoS and CEETM (`module_qm`) | 1,907 | 23 | Partial — conntrack mark only | High | Largest command surface and the most likely blocker: `USE_QOSCONNMARK`, `ENABLE_INGRESS_QOS` and `ENABLE_EGRESS_QOS` are all in the shipping build. Shaping has no flowtable concept. |
| 6 | IPsec (`module_ipsec`, `dpa_ipsec`) | 618 | 14 | Partial — `FLOW_OFFLOAD_XMIT_XFRM` | High | The xmit type exists, but SA handling, rekey and ESN live entirely in CDX. |
| 7 | Multicast (`module_mcast`, `mc4`, `mc6`) | 1,785 | 4 | No | High | The flowtable is unicast-conntrack by construction. Needs a parallel replication path rather than a flowtable feature. |
| 8 | Tunnels (`module_tunnel`) | 1,223 | 7 | Partial | High | Encapsulation does not fit the tuple contract. |
| 9 | Statistics (`module_stat`) | 985 | 12 | Partial — flow stats callbacks | Medium | Per-flow counters exist. Treat carefully: the stats path is where A140 lived. Now also owes the per-VLAN-interface counters, see below. |
| 10 | RTP/RTCP relay (`module_rtp`) | 849 | 9 | No | High | No Linux analogue. Scope decision before any porting. |
| 11 | Wi-Fi (`module_wifi`, `dpa_wifi`) | 345 | 3 | No | High | Needs driver-side `dev_fill_forward_path` support that does not exist. |
| 12 | Sockets (`module_socket`) | 1,641 | — | Not applicable | Medium | Local termination. Decide whether it needs porting at all. |
| 13 | MACVLAN (`module_macvlan`) | 202 | 2 | Partial — path type exists | Low | Did not fall out of the VLAN and bridge work: the device walk declines it as its own path type. Needs an arm of its own. |

## IPv6, delivered

Scoped and landed 2026-09-16, NAT included. It cost one increment because the
adapter's key is one struct: widening it reached the decoder, both indexes, the
hardware encoder and the proc output at once. The mechanism, the two places
where the family is not cosmetic, and the hardware proof are in the
[IPv6 guide](flowtable-ipv6.md).

Two findings were not visible from reading alone, and are worth carrying into
the remaining increments. An IPv6 destination is valid only for the FIB
generation it was selected in, so a borrowed route has to arrive with its
cookie or `dst_check()` rejects all of them. And the `CtEntry` union means an
IPv6 entry's destination address occupies the bytes IPv4 uses for its twin
mirror, so the legacy twin fields must be left untouched. Both are the kind of
defect that admits flows and then misroutes them, rather than failing loudly.

## VLAN, delivered

Scoped and landed 2026-09-16, QinQ included. The mechanism, the three places
where an encapsulated flow is not an ordinary one with an extra header, and
the hardware proof are in the [VLAN guide](flowtable-vlan.md).

The finding worth carrying into the remaining increments is that a tagged flow
is the first one where the device Linux routes through and the device the
hardware transmits on are different objects. Neighbours, the borrowed
destination, the payload bound and the retirement dependencies all belong to
the logical device; only the classifier key and the egress queue belong to the
port. Every later encapsulation — PPPoE, bridges, tunnels — inherits that
split, and so does the device walk that derives it, which the bridge increment
widened rather than replaced.

One capability does not come across: **per-VLAN-interface byte counters**. CMM
maintains them in the microcode's logical statistics area and returns them
through an FCI query. This ownership mode loads no FCI, and the microcode
needs an interface index to allocate the counters against, which only a
registered VLAN interface has. Both halves belong to item 9, which has to
cover physical ports, VLANs and per-flow read-back in one design rather than
grow a VLAN-shaped allocator here. Until it lands, the flowtable path reports
per-flow counters and the physical ports' own MAC counters, and nothing
per-VLAN.

## Bridge, delivered

Scoped and landed 2026-09-16, and with it the configuration the product
actually runs: `br-lan.N` on a vlan-aware bridge over an untagged port. The
mechanism, the transmit type it had to change, and the hardware proof are in
the [bridge guide](flowtable-bridge.md). `auto_bridge` and `ffbridge.c` are
replaced rather than shared with: this mode loads neither.

Two findings are worth carrying. The first is that a bridge hop forced
`FLOW_OFFLOAD_XMIT_DIRECT` in `nft_dev_path_info()` before any table's request
was consulted, so every bridged flow arrived with cached Ethernet addresses
and no destination at all — and with it no `dst_check()`, no FIB-generation
cookie and no route invalidation. Patch 140 honours `use_neigh` there too. Any later increment that adds a path type with its own transmit handling
should expect the same collision.

The second is the FDB. `br_fill_forward_path()` pins a flow's egress port to
whatever the FDB named at admission, and **Linux retires nothing of its own
when that changes** — nothing under `net/bridge/` references a flowtable, so
an upstream bridged flow misforwards in software for exactly as long. The
adapter watches it on the switchdev notifier chain, which a plain bridge
reports on too. That is the fifth dependency class, alongside route,
neighbour, netdev and nexthop, and the first one where upstream's own
behaviour was the thing being corrected rather than followed.

Item 13 (MACVLAN) did **not** fall out of this work as expected. A MACVLAN is
neither an 802.1Q VLAN nor a bridge master, so the widened walk still declines
it; it needs its own arm and its own eligibility rules.

## Parity measurements

Retirement requires parity, not just capability, so every feature ported needs
a like-for-like comparison against the owner it replaces. The two owners are
exclusive per boot, so each row is a paired boot: same image, same NAT rule,
same traffic, same CPU accounting, only the owner differs.

**IPv4 TCP masquerade, 4 streams, 30 s, non-KASAN image — 2026-09-16**

| Direction | Flowtable | CMM |
| --- | --- | --- |
| LAN to WAN | 9.41 Gb/s, 1.33% DUT CPU | 9.41 Gb/s, 1.42% DUT CPU |
| WAN to LAN | 9.40 Gb/s, 14.29% DUT CPU | 9.40 Gb/s, 14.56% DUT CPU |

Both owners were confirmed to have actually offloaded rather than reaching the
rate in software: the flowtable adapter held ten directional entries, and the
CMM connection table held the five connections with the masqueraded reply
tuple. Software forwarding on this SoC does not exceed roughly 0.5 Gb/s, so
the rate alone also excludes a fallback.

The rates are identical and the CPU difference is within run-to-run noise in
both directions. The reverse direction costs an order of magnitude more CPU
than the forward one under *both* owners, so that asymmetry belongs to the
path rather than to either owner; it is unexplained and worth its own look,
but it is not a flowtable regression.

**IPv4 TCP masquerade over an 802.1Q LAN, 4 streams, 30 s — 2026-09-16**

| Direction | Flowtable | CMM |
| --- | --- | --- |
| LAN to WAN | 9.39 Gb/s, 2.15% and 2.16% DUT CPU | 9.39 Gb/s, 3.34% and 3.42% DUT CPU |
| WAN to LAN | 9.39 Gb/s, 2.93% and 2.90% DUT CPU | 9.39 Gb/s, 2.05% and 2.07% DUT CPU |

Two settled runs per cell. Both owners were sampled while the transfer was
still in flight rather than after it: the flowtable adapter held ten
directional entries carrying the expected `271`/`-` tag pair, and the CMM
connection table held the five connections. Reading either table after the
transfer catches whatever survived teardown, which is not what was carrying
it.

The rates are identical. The CPU difference is about a point either way and
changes sign between directions, while repeats within one owner agree to
0.03 points, so it is a real but small and non-directional difference rather
than a regression. The order-of-magnitude reverse-direction asymmetry recorded
for the untagged IPv4 measurement above does not appear here under either
owner.

**IPv4 TCP masquerade over a vlan-aware bridge, 4 streams, 30 s — 2026-09-16**

The shipping shape: the DUT's LAN address on `br-ft.273` over a port that is
an untagged member of 273, so the station stays untagged and the tag the
bridge resolves its FDB on has no netdev describing it.

| Direction | Flowtable | CMM |
| --- | --- | --- |
| LAN to WAN | 9.41 Gb/s, 1.87% and 2.00% DUT CPU | 9.40 and 9.41 Gb/s, 2.87% and 2.53% DUT CPU |
| WAN to LAN | 9.40 Gb/s, 2.62% and 2.42% DUT CPU | 9.40 Gb/s, 1.25% and 1.66% DUT CPU |

Two settled runs per cell, both owners sampled mid-transfer rather than after
it. The flowtable adapter held ten directional entries, every one of them
naming `br-ft.273` as the bridge it crossed; the CMM connection table held the
five connections. Both owners therefore forwarded in hardware rather than
reaching the rate in software, which the rate alone also excludes.

The rates are identical. The CPU difference is about a point either way and
changes sign between directions — flowtable is cheaper on the forward path and
CMM on the reverse — which is the same non-directional difference the tagged
measurement above shows, not a regression. This boot's discarded first CMM run
recorded 23.98% on the reverse direction against 1.25% and 1.66% once settled,
which is the artefact below and the reason each cell is two runs.

**The first measurement after a boot is contaminated under both owners** —
23.47% and 25.48% on the reverse direction against roughly 2% once settled.
Discard a boot's first run rather than reporting it; a single pair of runs
cannot tell that artefact from a real difference between owners, which is why
every cell above is two settled runs.

These cover three features. The remaining subsystems each need their own paired
measurement before the retirement claim can be made for them.

## Sequencing

**Items 3 and 13 are the natural next increments.** Linux supplies the
mechanism for both, so each is an encoder arm and an eligibility contract with
its own focused proof, exactly like the NAT, IPv6, VLAN and bridge increments
already delivered. Both extend the same device walk; neither needs new
architecture in the encoder. Item 13 is no longer expected to fall out of
another increment — a MACVLAN is its own path type and the walk declines it.

**Items 5 to 8 need feature-specific contracts.** Each expresses behaviour a
unicast flowtable tuple cannot carry, and each needs its own hardware
eligibility rules before any code.

**Items 10, 11 and 12 need a scoping decision first.** RTP relay and Wi-Fi
offload have no Linux counterpart at all, so the question is whether the
product still needs them, not how to port them.

**QoS is the critical path.** It has the largest command surface of anything
remaining, and all three of its build features ship today, so CMM cannot be
retired while it is outstanding regardless of how the other items progress.

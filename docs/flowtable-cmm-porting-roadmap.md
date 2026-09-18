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
| 5 | QoS and CEETM (`module_qm`) | 1,907 | 23 | Partial — conntrack mark only | Medium | Scoped: see the [QoS design](flowtable-qos.md). Three separable planes; only classification is new, and it is one field on `cdx_ft_rule`. QoS is dormant in the shipping build, so this is a capability to add, not behaviour to preserve. |
| 6 | IPsec (`module_ipsec`, `dpa_ipsec`) | 618 | 14 | Yes — `xfrmdev_ops` packet offload | Medium | **Delivered**, both directions: see the [IPsec design](flowtable-ipsec.md). Control plane is mainline `xfrmdev_ops` in packet mode, with no ASK userspace. The estimate that the shared encoder already carried the SEC action held; what it did not anticipate is that `FLOW_OFFLOAD_XMIT_XFRM` had to be *admitted* rather than excluded — three generic helpers refuse that transmit type outright, which silently kept every real tunnel in software until step 6 measured it. |
| 7 | Multicast (`module_mcast`, `mc4`, `mc6`) | 1,785 | 4 | Partial — bridge MDB | High | **Scoped: see the [multicast design](flowtable-multicast.md).** Wanted, and next — but not a merge blocker: `query mc4` on a production gateway carrying IPTV answers "table empty", so this adds a capability rather than preserving behaviour. Control plane is the bridge's own IGMP snooping, read off the switchdev chain the adapter is already on, with no ASK userspace. The decisive fact is that the classifier key is an exact `(S,G)` while an IGMPv2 join is `(*,G)`, so membership alone cannot compose a key; the source and the ingress port are learned from the stream. Needs a parallel replication path, not a flowtable feature. |
| 8 | Tunnels (`module_tunnel`) | 1,223 | 7 | Partial | High | Encapsulation does not fit the tuple contract. |
| 9 | Statistics (`module_stat`) | 985 | 12 | Partial — flow stats callbacks | Medium | Per-flow and per-session counters exist. What is left is per-VLAN and per-port read-back, on the allocator that already serves the session ones; see below. Treat carefully: the stats path is where A140 lived. |
| 10 | RTP/RTCP relay (`module_rtp`) | 849 | 9 | No | High | No Linux analogue. Scope decision before any porting. |
| 11 | Wi-Fi (`module_wifi`, `dpa_wifi`) | 345 | 3 | No | High | Needs driver-side `dev_fill_forward_path` support that does not exist. |
| 12 | Sockets (`module_socket`) | 1,641 | — | Not applicable | Medium | Local termination. Decide whether it needs porting at all. |

## Out of scope

**MACVLAN (`module_macvlan`, 202 lines) is not a retirement blocker, because
CMM never offloaded it.** `FC_MACVLAN`, `CMD_MACVLAN_ENTRY` and
`CMD_MACVLAN_ENTRY_RESET` are declared in `cdx/cdx_cmdhandler.h` and dispatched
from nowhere in `cdx/`, so the `FPP_CMD_MACVLAN_ENTRY` that
`cmm/src/module_macvlan.c` sends returns `ERR_UNKNOWN_COMMAND`. The 202 lines
are sender-side code for a command the hardware layer does not implement, and
there is no capability here to replace.

`ISSUES.md` A38 deferred it on 2026-09-11 and the reasoning stands unchanged;
the product owner has since confirmed there is no MACVLAN use case. A38 remains
open as the record of that deferral.

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
through an FCI query. This ownership mode loads no FCI, and the microcode needs
an interface index to allocate the counters against, which only a registered
VLAN interface has. Deferring it to item 9 was the right call rather than
growing a VLAN-shaped allocator here: the PPPoE increment then needed the same
mechanism and built a general one, so what remains for a VLAN is asking it for
a record and reading it back. Until that lands the flowtable path reports
per-flow counters, the physical ports' own MAC counters and a PPPoE session's
own records, and nothing per-VLAN.

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

A MACVLAN did **not** fall out of this work, and that is correct rather than a
gap. It is neither an 802.1Q VLAN nor a bridge master, so the widened walk
declines it as its own path type — which is the right answer for a device
CMM never offloaded either; see the out-of-scope entry above.

## PPPoE, delivered

Item 3, scoped and landed 2026-09-16, both halves: a session is inserted on
egress and stripped on ingress, and the bench proves each direction separately
because the ingress half is the one nothing in a rule describes. The mechanism,
what stands in for the neighbour and the Ethernet destination a ppp device does
not have, and the hardware proof are in the
[PPPoE guide](flowtable-pppoe.md). `pppoe.c` and `control_pppoe` are replaced
rather than shared with; the PPPoE *relay* they once also carried was deleted
as dead code before this work and is not reintroduced by it.

**The first finding is a warning about a source we had been reading as an
oracle.** The FMC-emitted soft parser in `cdx_sp.xml` ends the parse at the
PPPoE header — `nextproto="end_parse"` on both arms of `pppoeschema`, which
compiles to a real `END_PARSE`, with the frame redirected to the PPPoE relay
table at `$ccbase + 0x30`. Read literally, that says an encapsulated frame
never reaches the IPv4 or IPv6 5-tuple tables and only the egress half of a
PPPoE flow could ever be offloaded. It was read that way, carefully, and it is
**wrong**: measured on the rig under CMM before any of this was written, both
directions offload at roughly 9 Gb/s with the ppp device's own byte counters
confirming the tunnel carried it. The v210.10.1 microcode does not do what the
FMC-emitted parser says. So `cdx_sp.xml` describes the compiled soft parser and
not the classifier's reachable behaviour, and any future increment that reasons
from it about what the hardware can match must measure before it believes —
the cost of not measuring here would have been an increment scoped to half its
real capability. (`ISSUES.md` A12 closed this question in the other direction
and the measurement vindicates it.)

**The second is that a session drop retires selectively, through the route.**
The expectation was full invalidation: the ppp device unregisters, and
unregistration of a device a flow depends on is the one netdev event the
adapter escalates. It never fires. pppd's peer route dies with the device
first, the flow borrowed that destination, and the route watch retires both
directions before the unregistration arrives — by which time nothing references
the device and it was never a binding. The bindings stay up, admission is never
disabled, nothing re-arms, and a redial readmits on the next packet with the
table untouched. Worth carrying into any later increment whose path type has a
route of its own: the route watch gets there first, and the coarser netdev
escalation is a backstop rather than the mechanism.

**The third finding is that the interface-statistics allocator is now general,
which changes what item 9 is.** Per-session byte counters were the capability
VLAN left behind and PPPoE was going to leave behind too. They came across
instead, because what was missing turned out to be ownership rather than a
mechanism: the microcode's records exist, they are indexed rather than named by
an interface, and only the allocator's interface was interface-shaped. It now
names the shape of the record — `CDX_FT_STATS_TIMESTAMPED` for the timestamped
records a session's opcodes read, `CDX_FT_STATS_PLAIN` for the ones a VLAN's
would — so **a VLAN asks for a slot with the same call a session does**. What
item 9 still owes for interface statistics is therefore per-VLAN and per-port
*read-back*, not an allocator: something to ask for a slot on a tagged flow's
behalf and somewhere to report it, both of which a session already demonstrates
in `/proc/cdx_flowtable`.

Two caveats belong with it. The pool is four timestamped records deep and
shared with the legacy owner, so exhaustion is an ordinary outcome rather than
a fault — a fifth session forwards without counters and says so — and widening
it means moving a MURAM carve both owners allocate from. And the plain pool has
more records than the eight-bit index fields can name, so its usable depth is
122 of 124; the allocator refuses the rest rather than truncating, which the
legacy path does silently.

The residual gap that is PPPoE's own is a session renegotiated under a `pppN`
device that never disappears; the failure mode is loss rather than
misdelivery, and no exported interface reports it.

**And IPv6 through a session is carried, which an earlier revision of this
document said was excluded.** The insert opcode names no PPP protocol id, so
the microcode chooses one, and the exclusion stood on nobody having shown which
it chooses for a v6 frame. Measured: CMM offloads IPv6 through a PPPoE session
on this bench at 8.95 Gb/s forward and 9.20 Gb/s reverse at roughly 2% DUT CPU,
with its `v6connections` table holding all five connections mid-transfer and
its `pppoe` table registering the session, and iperf3 completing cleanly — so
the peer parsed every frame. CMM reaches the opcode through the same
`create_pppoe_ins_hm()` and the same `INSERT_PPPoE_HDR`. The general lesson is
the first finding's again: a capability was scoped out on a reading rather than
a measurement, and the measurement disagreed.

## Parity measurements

Retirement requires parity, not just capability, so every feature ported needs
a like-for-like comparison against the owner it replaces. The two owners are
exclusive per boot, so each row is a paired boot: same image, same NAT rule,
same traffic, same CPU accounting, only the owner differs.

**IPsec tunnel, forwarded TCP, 4 streams, 20 s, non-KASAN image — 2026-09-18**

| Direction | Flowtable | CMM |
| --- | --- | --- |
| WAN to LAN, encrypting | 2.55 and 2.55 Gb/s | 2.55 and 2.55 Gb/s |
| LAN to WAN, decrypting | 2.65 and 2.65 Gb/s | 2.72 and 2.71 Gb/s |

Two settled runs per cell. The tunnel's outer endpoints are the DUT's LAN port
and the LAN VM, and the traffic inside it is forwarded between the WAN-side
orchestrator and an inner address on the VM. Only the DUT's SAs are in
hardware, so the VM's software crypto sets the absolute ceiling — identically
on both sides, which is what leaves the DUT's own cost as the variable.

Both owners were confirmed to be carrying it in hardware by the same oracle:
`tx toenc`, which counts frames the *software* path handed to SEC, stayed
between 20 and 54 across transfers of roughly two hundred thousand packets.
Each run was also gated on the LAN segment not having lost carrier during it,
after a flapping cable produced a full set of plausible-looking numbers.

The encrypting direction is identical. The decrypting direction is 2.4 per cent
slower under the flowtable, consistently; it is the direction that crosses the
offline port twice, and the difference is recorded rather than explained. CPU
followed the same per-run trend under both owners and so cancels.

This row cost a real defect to produce: the adapter was programming the
classifier with Netfilter's tunnel-*reduced* flow MTU, and the microcode
compares post-tunnelling size against it, so every full-size frame was matched,
excepted to the CPU and encrypted in software — 0.07 Gb/s while every
functional test passed. See the [IPsec design](flowtable-ipsec.md).

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

**IPv4 TCP masquerade through a PPPoE session, 4 streams, 30 s — 2026-09-16**

The session rides VLAN 3900 on the WAN side, so every frame spends both
encapsulation slots — a tag and a session on one path.

| Direction | Flowtable | CMM |
| --- | --- | --- |
| LAN to WAN | 8.948 and 8.936 Gb/s, 2.92% and 2.00% DUT CPU | 8.984 and 8.931 Gb/s, 2.74% and 3.21% DUT CPU |
| WAN to LAN | 9.309 and 9.314 Gb/s, 2.09% and 3.09% DUT CPU | 9.278 and 9.323 Gb/s, 3.23% and 2.20% DUT CPU |

Two settled runs per cell, both owners sampled mid-transfer. The flowtable
adapter held ten directional entries, each naming the session id and
concentrator the kernel had negotiated; the CMM connection table held the five
connections. The rates agree to within a percent and the CPU difference
changes sign between runs of the same owner, so it is run-to-run noise rather
than a difference between owners.

Both directions are offloaded, which is the result that decided the increment's
scope: the reverse direction is PPPoE *ingress*, and the compiled soft parser
had suggested it could not be classified at all.

**The first measurement after a boot is contaminated under both owners** —
23.47% and 25.48% on the reverse direction against roughly 2% once settled.
Discard a boot's first run rather than reporting it; a single pair of runs
cannot tell that artefact from a real difference between owners, which is why
every cell above is two settled runs.

These cover four features. The remaining subsystems each need their own paired
measurement before the retirement claim can be made for them.

## Sequencing

**The device-walk family of increments is complete.** NAT, IPv6, VLAN, bridge
and PPPoE were all the same shape — Linux supplies the mechanism, so each was
an arm of the device walk plus an eligibility contract with its own focused
proof — and nothing remaining has that shape. MACVLAN was the last candidate
and it is out of scope, above, so the next increment is a change of kind rather
than another one of these.

**Items 5 to 8 need feature-specific contracts.** Each expresses behaviour a
unicast flowtable tuple cannot carry, and each needs its own hardware
eligibility rules before any code.

**Item 9 needs read-back rather than a mechanism.** The allocator that hands
out firmware statistics records is general and a session already uses it; what
is left is asking for a record on a VLAN's and a port's behalf and reporting
what it holds.

**Items 10, 11 and 12 need a scoping decision first.** RTP relay and Wi-Fi
offload have no Linux counterpart at all, so the question is whether the
product still needs them, not how to port them.

**The order is IPsec, then multicast.** Both are decided rather than open, and
the reasoning for each is worth keeping so neither is re-litigated.

IPsec goes first because it is the larger body of live functionality: eight
test files exercise it, the hardware questions were answered by A24a and A15,
and the QoS work has already registered `devlink trap policer 2` — the SEC
meter — which meters nothing until IPsec lands and is deliberately ungated so
nothing has to be remembered when it does. It is scoped in the
[IPsec design](flowtable-ipsec.md), which also records why the control plane
converges on mainline `xfrmdev_ops` rather than extending patch 040: that
patch's largest file is a netlink bus whose only consumer is CMM, so it is the
half of the design being retired rather than an alternative to retiring it.

Multicast follows, and it is wanted: IPTV runs in production on a Gateway
Development Kit, bridged on the ISP's VLAN. Earlier revisions of this file left
its scope open pending an answer about IPTV, and the answer is yes.

**It is not, however, a merge blocker, and the distinction was nearly missed.**
`cmm -c "query mc4"` on that same production gateway answers *"FPP Multicast
IPV4 table empty"*. Nothing in CMM learns multicast — no netlink, no IGMP
snooping, no MFC in `module_mcast.c` or `module_mc4.c`, only an explicit
`CMD_MC4_MULTICAST` from outside that nothing on the box sends — and
`auto_bridge` tracks the unicast FDB alone. So the streams have been forwarded
in software by the Linux bridge the whole time, and the flowtable gives up
nothing by not replicating them. Porting this adds a capability rather than
restoring one, which is why it can follow IPsec instead of gating the merge.

That the box is **bridged** rather than routed also decides the mechanism:
`ipmr`'s MFC is empty and irrelevant here, and the source of truth is the
bridge's MDB, offered to any driver willing to listen — `br_switchdev_mdb_notify()`
calls `switchdev_port_obj_add()` for every port group with no check that the
port belongs to a switch ASIC, so the events are available without ASK becoming
a switchdev driver or growing a port parent id.

What that mechanism does **not** supply is the rest of a classifier key, and
scoping it found this to be the item's real problem rather than the
eight-listener constant an earlier pass concentrated on. `fill_key_info()`
composes a multicast key as `{portid, saddr, daddr, protocol}` in an external
*hash* table, so the source address is exact and unmaskable — `src_addr_mask`
is a wire field NXP never wired to anything — while an IGMPv2 join produces a
`(*,G)` MDB entry with no source and no ingress port at all. Both missing
facts are properties of the traffic rather than of the membership, so both are
learned from the stream's first frames, which the bridge is forwarding in
software anyway. The [multicast design](flowtable-multicast.md) records the
three options and what the chosen one costs.

Two corrections to earlier revisions of this file belong with it. The encoder
is **not** unproven CMM-era code: `tools/tests/` carries five `test_mcast_*`
files and `cb8fc27` fixed the hardware path that makes them pass, with
replication asserted at exactly one frame per listener. And the encoder is
unreachable in a flowtable boot for a reason that is not an init gate —
`CMD_INIT(mc4)` and `CMD_INIT(mc6)` already run unconditionally, but
`comcerto_fpp_send_command()` refuses every FCI command in this ownership
mode, so the learner calls the encoder in kernel and the listener-ceiling
measurement has to run in a CMM boot.

**QoS is no longer the critical path.** Its three build features are compiled
in, but `/etc/config/cmmqos` ships with `enabled '0'` and nothing sends
`CMD_QM_QOSENABLE`, so the plane is dormant end to end and CEETM is bypassed on
every port. The scoping work found that only one of its three planes —
per-flow classification — needs a new mechanism, and that mechanism is a `u32`
on `cdx_ft_rule` fed from the standard `ct->mark`. The scheduler and policer
planes are a control-transport swap over hardware that is already built
unconditionally at module load. See the [QoS design](flowtable-qos.md) for the
mechanism, the three control-plane options and the sequencing.

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
| 2 | VLAN (`module_vlan`) | 556 | 2 | Yes — `DEV_PATH_VLAN`, `encap[]` | Low-Med | The kernel already fills the encap stack; needs FMAN VLAN key encoding. |
| 3 | PPPoE (`pppoe.c`, `control_pppoe`) | 303 | 2 | Yes — `DEV_PATH_PPPOE` | Low-Med | The relay offset is already confirmed on hardware. |
| 4 | Bridge / auto_bridge (`ffbridge.c`) | 276 | — | Yes — `DEV_PATH_BRIDGE` | Medium | CDX already falls back to the physical ingress port for `br-lan.N`. |
| 5 | QoS and CEETM (`module_qm`) | 1,907 | 23 | Partial — conntrack mark only | High | Largest command surface and the most likely blocker: `USE_QOSCONNMARK`, `ENABLE_INGRESS_QOS` and `ENABLE_EGRESS_QOS` are all in the shipping build. Shaping has no flowtable concept. |
| 6 | IPsec (`module_ipsec`, `dpa_ipsec`) | 618 | 14 | Partial — `FLOW_OFFLOAD_XMIT_XFRM` | High | The xmit type exists, but SA handling, rekey and ESN live entirely in CDX. |
| 7 | Multicast (`module_mcast`, `mc4`, `mc6`) | 1,785 | 4 | No | High | The flowtable is unicast-conntrack by construction. Needs a parallel replication path rather than a flowtable feature. |
| 8 | Tunnels (`module_tunnel`) | 1,223 | 7 | Partial | High | Encapsulation does not fit the tuple contract. |
| 9 | Statistics (`module_stat`) | 985 | 12 | Partial — flow stats callbacks | Medium | Per-flow counters exist. Treat carefully: the stats path is where A140 lived. |
| 10 | RTP/RTCP relay (`module_rtp`) | 849 | 9 | No | High | No Linux analogue. Scope decision before any porting. |
| 11 | Wi-Fi (`module_wifi`, `dpa_wifi`) | 345 | 3 | No | High | Needs driver-side `dev_fill_forward_path` support that does not exist. |
| 12 | Sockets (`module_socket`) | 1,641 | — | Not applicable | Medium | Local termination. Decide whether it needs porting at all. |
| 13 | MACVLAN (`module_macvlan`) | 202 | 2 | Partial — path type exists | Low | Likely falls out of the VLAN and bridge work. |

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

This covers one feature. The remaining subsystems each need their own paired
measurement before the retirement claim can be made for them.

## Sequencing

**Items 2 to 4 are the natural next increments.** Linux supplies the mechanism,
so each is an encoder and an eligibility contract with its own focused proof,
exactly like the NAT and IPv6 increments already delivered. VLAN is the best
next target: the kernel already fills the encap stack, so the work is FMAN key
encoding rather than new architecture.

**Items 5 to 8 need feature-specific contracts.** Each expresses behaviour a
unicast flowtable tuple cannot carry, and each needs its own hardware
eligibility rules before any code.

**Items 10, 11 and 12 need a scoping decision first.** RTP relay and Wi-Fi
offload have no Linux counterpart at all, so the question is whether the
product still needs them, not how to port them.

**QoS is the critical path.** It has the largest command surface of anything
remaining, and all three of its build features ship today, so CMM cannot be
retired while it is outstanding regardless of how the other items progress.

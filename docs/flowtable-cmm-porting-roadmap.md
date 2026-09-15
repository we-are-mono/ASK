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

## Remaining work

| # | Subsystem | Lines | FCI cmds | Linux mechanism | Effort | Notes |
| ---: | --- | ---: | ---: | --- | --- | --- |
| 1 | IPv6 (`module_mc6`, `control_ipv6`) | 641 | 7 | Yes — full v6 hooks in `nf_flow_table_ip.c` | Low | The adapter is IPv4-only by choice; `ft_parse` declines v6. Encoder and eligibility work, not new architecture. |
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

## IPv6 implementation plan

Scoped 2026-09-16 by reading the adapter and the classifier rather than
estimating. The hardware is ready and Linux is ready; the adapter is IPv4 by
construction rather than by a flag, so the work is threading an address family
through its key.

Already available, needing no work:

- `CtEntry` carries both families in a union, `Saddr_v4` and `Saddr_v6[4]`
  (`cdx/control_ipv4.h`), and `insert_entry_in_classif_table` is shared.
- `FFTYPE_IPV6` and `HASH_CT6` exist and are exercised by `control_ipv6.c`.
- The Linux flowtable has complete IPv6 hooks in `nf_flow_table_ip.c`.

What has to change:

| Site | Change |
| --- | --- |
| `struct cdx_ft_rule` (`cdx/cdx_flowtable_backend.h`) | Widen the four addresses to a family union. This struct is the adapter's key, so the change reaches `ft_parse`, `ft_key_hash`, `ft_same_key`, `ft_find`, `ft_replace`, `cdx_ft_hw_add` and the proc output together. |
| `ft_parse` (`cdx/ask_flowtable.c`) | Accept `FLOW_DISSECTOR_KEY_IPV6_ADDRS` and `ETH_P_IPV6` beside the v4 keys, and carry the family into the rule. |
| `ft_key_hash` | Hash a v6 address rather than a `u32`. |
| `cdx_ft_hw_add` (`cdx/cdx_flowtable_hw.c`) | Set `FFTYPE_IPV6`, use `HASH_CT6`, fill `Saddr_v6`/`Daddr_v6`. |
| Route and neighbour validation | `ft_routes_valid` and the neighbour path use IPv4 helpers throughout and need v6 equivalents. |
| `/proc/cdx_flowtable` | Family-aware address formatting instead of `%pI4`. |
| Tests | A v6 counterpart to the NAT tests, v6 support in the connection peer, and v6 addressing on the loki and vision topology. |

Decide before starting: **whether v6 NAT is in scope.** Declining it keeps the
twin and inverse-translation encoding out of the first increment and matches
how IPv6 is normally deployed, but it must be an explicit boundary in the
supported scope rather than an unstated omission. Recommend excluding it from
the first increment and admitting v6 routed traffic only.

Do this as one increment with its own proof, not as filler work: a partially
threaded address family compiles and silently mis-keys flows.

## Sequencing

**Items 1 to 4 are the natural next increments.** Linux supplies the mechanism,
so each is an encoder and an eligibility contract with its own focused proof,
exactly like the NAT increments. IPv6 is the best first target: the widest
capability gain for the least new architecture.

**Items 5 to 8 need feature-specific contracts.** Each expresses behaviour a
unicast flowtable tuple cannot carry, and each needs its own hardware
eligibility rules before any code.

**Items 10, 11 and 12 need a scoping decision first.** RTP relay and Wi-Fi
offload have no Linux counterpart at all, so the question is whether the
product still needs them, not how to port them.

**QoS is the critical path.** It has the largest command surface of anything
remaining, and all three of its build features ship today, so CMM cannot be
retired while it is outstanding regardless of how the other items progress.

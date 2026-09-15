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

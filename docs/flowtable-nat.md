# Linux flowtable NAT

IPv4 TCP/UDP static source NAT, MASQUERADE, destination NAT and combined
source/destination translation are supported on the foundation's physical ports.
Combined NAT also permits routing back out the ingress port for hairpin traffic.
Linux conntrack and nftables own the mapping. The adapter
validates Linux's native actions and CDX encodes the resolved translation using
the existing proprietary firmware interface. No CMM or per-flow FCI call is
involved, and the shared legacy encoder is unchanged.

IPv6 and other protocols remain outside hardware eligibility. They need separate
increments and lifecycle proofs.
The [foundation](flowtable-foundation.md) still supplies the capacity, device,
route, neighbour, retirement and policy contracts. NAT does not lift those limits.

## Mapping and dependencies

For a client `A:a` reaching server `B:b` through source translation `C:c`:

| Direction | Hardware match | Packet after translation | Routed destination |
| --- | --- | --- | --- |
| Original | `A:a → B:b` | `C:c → B:b` | `B` |
| Reply | `B:b → C:c` | `B:b → A:a` | `A` |

For a WAN client `A:a` reaching public endpoint `P:p`, forwarded to `B:b`:

| Direction | Hardware match | Packet after translation | Routed destination |
| --- | --- | --- | --- |
| Original | `A:a → P:p` | `A:a → B:b` | `B` |
| Reply | `B:b → A:a` | `P:p → A:a` | `A` |

For combined NAT, `A:a → P:p` becomes `G:g → B:b`; replies match
`B:b → G:g` and become `P:p → A:a`. Linux allocates both mappings. The same
contract supports two physical ports or hairpin routing on one physical port.
Same-port admission currently requires both SNAT and DNAT; it does not admit
arbitrary same-port routing or make a bridge eligible. Physical identity, live
routes, per-direction next hops, neighbour MACs and MTU checks still apply.

The adapter requires completed NAT, a TCP/UDP match identical to one of the
conntrack tuples, and consistent opposite tuple endpoints. It accepts exactly
four Ethernet edits, one IPv4/transport edit pair per resolved NAT type, the
matching native IPv4/TCP or IPv4/UDP checksum action and a redirect. Combined NAT
requires both completion flags and both edit pairs in native SNAT-then-DNAT order.
Masks, offsets and values must agree with the resolved mapping. Identity address or port edits are permitted; arbitrary flower
rewrites and additional actions are refused. The translated tuple is always the
inverse of the opposite conntrack tuple.

The private backend rule carries complete match and translated tuples. The
classifier key uses the match; the existing encoder's synthetic twin describes
the inverse translated tuple. Neither this twin nor the route joins legacy CMM
tables, timers or notification paths. `/proc/cdx_flowtable` exposes `src`, `dst`,
`new_src` and `new_dst`, including their ports.

Neighbour lookup uses the translated destination. Route-prefix retirement
watches that destination and the original match source, which is the opposite
direction's routed destination. This preserves both dependencies even when only
one hardware direction has installed. NAT lifetime follows the native conntrack
and flowtable generation; the adapter owns no independent mapping allocator.

## Configuration

Configure NAT through ordinary Linux nftables or iptables support. The
`ask-flowtable` JSON controls acceleration scope and exclusions; it does not
allocate NAT mappings or duplicate NAT rules. Original and reply selectors keep
their conntrack meanings: under SNAT, `reply_destination` and
`reply_destination_port` select the translated source endpoint. Under DNAT,
`reply_source` and `reply_source_port` select the internal server endpoint. An
original destination selector still names the public endpoint before DNAT.

The test image packages `nft_nat`, `nft_chain_nat` and `nft_masq` so native nftables static
NAT works after a clean boot. The kernel configuration already enables them.
The default policy remains disabled and existing gateway setup is unchanged.

Policy stop/apply drains accelerated directions while preserving the conntrack
mapping and socket. As with ordinary Linux NAT, editing a NAT rule affects new
connections; it does not retroactively replace mappings of existing conntracks.
To revoke forwarding immediately, use the documented
[firewall revocation sequence](flowtable-policy.md#firewall-ordering-and-revocation).

## MASQUERADE lifetime

MASQUERADE uses the same validated source translation actions as static SNAT.
Linux chooses the current output address and source port; the adapter does not
allocate mappings or mirror interface address state. Native Linux masquerade
notifiers remove affected conntracks when their address is removed or the
interface is taken down. Native flowtable cleanup and the existing route/device
retirement mechanisms remove the associated hardware directions.

This differs from policy stop/apply: WAN address removal intentionally destroys
the old mapping. Established sockets cannot be promised to survive an address
change. Fresh connections acquire the new address and can be accelerated again.
Removal follows Linux's asynchronous cleanup, not an instantaneous firewall
revocation guarantee. Use the policy drain sequence when a configuration change
requires forwarding to stop before mutation.

## Focused verification

`test_flowtable_udp_snat` forces both the source address and source port to
change. It uses a persistent UDP socket, an independent WAN echo endpoint and
raw receive captures at both endpoints. Every steady window checks the exact
payload sequence, Ethernet addresses, IPv4 addresses, UDP ports, TTL, IPv4
checksum and UDP checksum. A second case sends zero UDP checksums in both
directions and requires them to remain zero.

The same mapping crosses a one-shot post-insert rollback, dependent route
replacement, policy removal during traffic, software forwarding, and policy
reapplication. Hardware windows require exact per-direction packet and byte
deltas and low software TX counts. The software window requires at least one
software TX per datagram in each direction. Conntrack IDs must survive policy
removal, and cleanup requires balanced installs/deletes and zero references.

After building with `KASAN=1 make ask-image`, staging with `make stage-image`
and booting `ask.offload=flowtable`, select only the relevant tests:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=55000 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_udp_snat'
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=55100 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_startup_without_cmm_or_fci'
```

The TCP SNAT tests reuse the established TCP lifetime proofs with forced source
address and port translation. They check both decoded directions, 64 MiB bulk
transfers, low software TX, idle expiration and reinstallation, SYN/FIN/RST
visibility in Linux, retransmission after deliberate loss, and native close
expiry. The production policy tool stops and reapplies acceleration during an
active transfer; the socket and conntrack ID must survive.

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=55200 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_tcp_snat'
```

The [TCP SNAT validation record](flowtable/history/tcp-snat.md) records the measured
TCP results. The [UDP SNAT validation record](flowtable/history/udp-snat.md) contains measured
results and image identities. This increment does not establish arbitrary NAT
feature combinations, sustained scale, every exception path, or production-image
parity.

`test_flowtable_udp_masquerade` and `test_flowtable_tcp_masquerade` repeat the
translation/lifetime proofs with native masquerade rules. The separate
`test_flowtable_masquerade_wan_lifecycle` uses a temporary WAN subnet to remove
an active address, replace it, and take the WAN interface down/up. Both live TCP
and UDP conntracks and hardware directions must disappear at each destructive
transition. Fresh connections must use the replacement address and offload
without recreating the policy table. Its setup requires this endpoint address:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=198.18.40.2 ASK_FLOWTABLE_SPORT=55400 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_masquerade_wan_lifecycle'
```

See the [MASQUERADE validation record](flowtable/history/masquerade.md).

`test_flowtable_dnat` initiates TCP and UDP on the WAN host and runs the echo
servers on Loki. It forces both destination address and port changes, checks
both translated hardware directions, and independently validates UDP receive
frames at both endpoints with ordinary and zero checksums. Exact TCP records
exercise Linux endpoint checksum handling. The same sockets cross insertion
rollback, dependent route replacement and policy stop/apply; software forwarding
must preserve both conntrack IDs. Native TCP FIN processing removes both TCP
hardware directions while the UDP mapping remains active.

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=55500 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_dnat'
```

See the [DNAT validation record](flowtable/history/dnat.md).

`test_flowtable_double_nat` repeats the WAN-initiated proof with simultaneous
source and destination address/port rewrites. `test_flowtable_hairpin` places two
separate MAC/IP endpoints in Loki network namespaces. Both TCP/UDP directions
enter and leave the DUT's LAN port, with both NAT mappings preventing a direct
LAN reply. Every received UDP frame must have the DUT's source MAC and one TTL
decrement. Both tests cover ordinary and zero UDP checksums, insertion rollback,
route retirement, live policy withdrawal, software forwarding, readmission and
native TCP FIN processing. Temporary namespaces, addresses, routes and rules
are removed automatically.

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=55600 \
  make ask-test ASK_TEST_ARGS='-q -k "test_flowtable_double_nat or test_flowtable_hairpin"'
```

See the [double NAT and hairpin validation record](flowtable/history/double-nat.md).

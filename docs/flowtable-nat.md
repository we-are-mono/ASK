# Linux flowtable NAT

The first NAT increment supports static IPv4 UDP source NAT on the foundation's
two physical ports. Linux conntrack and nftables own the mapping. The adapter
validates Linux's native actions and CDX encodes the resolved translation using
the existing proprietary firmware interface. No CMM or per-flow FCI call is
involved, and the shared legacy encoder is unchanged.

TCP NAT, MASQUERADE, destination NAT, hairpin/double NAT and IPv6 remain outside
hardware eligibility. Those need separate increments and lifecycle proofs.
The [foundation](flowtable-foundation.md) still supplies the capacity, device,
route, neighbour, retirement and policy contracts. NAT does not lift those limits.

## Mapping and dependencies

For a client `A:a` reaching server `B:b` through source translation `C:c`:

| Direction | Hardware match | Packet after translation | Routed destination |
| --- | --- | --- | --- |
| Original | `A:a → B:b` | `C:c → B:b` | `B` |
| Reply | `B:b → C:c` | `B:b → A:a` | `A` |

The adapter requires completed source NAT, a UDP match identical to one of the
conntrack tuples, and consistent opposite tuple endpoints. It accepts exactly
four Ethernet edits, one IPv4 edit, one UDP port edit, the native IPv4/UDP
checksum action and a redirect. Masks, offsets and values must agree with the
resolved mapping. Identity address or port edits are permitted; arbitrary flower
rewrites, additional actions, DNAT and masquerade mappings are refused.

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
`reply_destination_port` select the translated source endpoint.

The test image packages `nft_nat` and `nft_chain_nat` so native nftables static
NAT works after a clean boot. The kernel configuration already enables them.
The default policy remains disabled and existing gateway setup is unchanged.

Policy stop/apply drains accelerated directions while preserving the conntrack
mapping and socket. As with ordinary Linux NAT, editing a NAT rule affects new
connections; it does not retroactively replace mappings of existing conntracks.
To revoke forwarding immediately, use the documented
[firewall revocation sequence](flowtable-policy.md#firewall-ordering-and-revocation).

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

The [UDP SNAT validation record](flowtable/history/udp-snat.md) contains measured
results and image identities. This increment does not establish arbitrary NAT
feature combinations, sustained scale, every exception path, or production-image
parity.

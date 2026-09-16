# Linux flowtable VLAN

802.1Q offload in the ASK flowtable adapter: where the tags come from, the
three places where an encapsulated flow is not an ordinary one with an extra
header, and the hardware proof.

The accepted boundary is the
[supported scope](linux-flowtable-offload.md#supported-scope). This document
explains the mechanism behind it; the [NAT guide](flowtable-nat.md) covers
translation, which a tagged flow shares unchanged.

## Where the tags come from

A tagged flow reaches the adapter as two different descriptions of one path.
`FLOW_ACTION_REDIRECT` names the **physical port**, because patch 140 sets
`use_neigh` on the table and a neighbour-output flow redirects to the
interface the reverse direction arrives on. The destination Netfilter selected
names the **VLAN subinterface**, because that is the netdev Linux would route
through. Everything this increment does follows from those two being different
objects for the first time.

The tags themselves are derived from the devices, not decoded from the action
list. `ft_vlan_stack()` walks `cls->nf_dst->dev` down to the redirect port and
`cls->nf_dst_reverse->dev` down to the binding's port, one VLAN layer at a
time, and the `FLOW_ACTION_VLAN_POP` and `FLOW_ACTION_VLAN_PUSH` actions are
then required to agree with what the walk found. That is the same shape the
adapter already uses for translation, where the mapping comes from the
conntrack and the mangle actions have to match it. It also means every path
that is not a chain of 802.1Q devices — a bridge, a PPPoE session, a bond, a
MACVLAN — is declined by the walk itself rather than by an action count that
happens not to add up.

CDX takes the stack from the rule. It has no VLAN interface to walk: the
adapter registers none, and in this ownership mode `control_vlan.c` never
runs. `insert_entry_in_classif_table_encap()` applies the rule's tags to the
L2 description that `dpa_get_tx_info_by_itf()` derived from the physical
ports, and sets `vlan_filtering` so `create_vlan_ins_hm()` emits no
per-interface statistics pointer — the same mechanism the bridge path already
uses for tags that come from bridge VLAN filtering rather than from a netdev.
Without it the unallocated offset zero would aim the microcode's counter
update at another interface's statistics slot. `fill_actions()` is unchanged,
and every legacy caller passes no encapsulation at all.

Registering VLAN interfaces from the adapter instead was rejected. It would
not have avoided the logical/physical split, which the borrowed destination
forces either way; it cannot express a tag that comes from a vlan-aware bridge
with no netdev behind it, which is the next increment; and `remove_onif_by_index()`
sweeps the legacy conntrack table and the route cache, which this mode seals.

## Three differences that are not cosmetic

**The logical device owns everything except the hardware.** The borrowed
destination, the neighbour, the payload bound and the retirement dependencies
all belong to the VLAN subinterface; only the classifier key and the egress
queue belong to the port. `ft_next_hop()` validates the destination against
the logical device, `ft_neigh_check()` and `ft_neigh_attach()` resolve there —
a neighbour on the port underneath is a different neighbour and is not found —
and `ft_device_used()`/`ft_device_retire()` watch it, so a VLAN device's own
MTU, link state or removal retires the flows that depend on it.

**`vlan_dev_real_dev()` returns the bottom device, not the parent.** Its own
loop descends through every stacked VLAN in one call. A walk built on it
collapses a QinQ pair into its inner tag alone, admits the flow, and forwards
it with one tag where the wire carries two. `ft_vlan_lower()` takes the
immediate lower neighbour from the device's adjacency list instead, which
admission's RTNL already permits. The compensating property is that
`vlan_dev_real_dev()` descends *only* through VLAN devices, so its result
reaching the port would still prove the chain contains nothing else.

**The ingress tags are recorded but never advertised.**
`nf_flow_rule_match()` registers the `FLOW_DISSECTOR_KEY_VLAN` and
`KEY_CVLAN` offsets and fills their values, and never sets either bit in
`used_keys`. A tagged rule therefore describes exactly the same key set as an
untagged one. A contract that expected the selector to appear declines every
tagged flow — while the untagged reverse direction of the same connection is
admitted, which is what makes it look like an encoder fault rather than a
decoder one. `ft_vlan_match()` reads the values through those offsets, bounded
by the tag count the device walk found, and requires each to name the tag that
walk derived under Netfilter's own exact masks.

## Order

The rule stores its tags **outermost first**, which is the order the wire
carries them, the order `flow_offload_fill_dir()` reverses the path walk into,
and the order `nf_flow_rule_route_common()` emits `VLAN_PUSH` in.
`dpa_l2hdr_info` stores them **innermost first**, because it is normally built
by walking a VLAN interface up towards its parent. `ft_encap()` in
`cdx_flowtable_hw.c` is the single place the two conventions meet. Getting
that reversal wrong swaps a QinQ pair on the wire and nothing else notices.

## Eligibility

Beyond the rules a routed flow already satisfies:

- Each logical device must reach its physical port through 802.1Q VLAN devices
  alone, at most `NF_FLOW_TABLE_ENCAP_MAX` of them. 802.1ad is declined: the
  kernel describes no selector for it and emits no push action, so a tag that
  is not 802.1Q is one the hardware would be asked to reproduce blind.
- An egress VLAN device may not override its parent's MAC address. The
  Ethernet source of a neighbour-output flow is the port's, and the encoder
  caches one address per port, so an override would have software and hardware
  disagree about the source MAC of the same flow.
- The POP actions must be one per ingress tag and the PUSH actions must name
  the egress tags in order, imposing neither priority nor DEI, neither of
  which the hardware reproduces.
- Re-entering the port a frame arrived on still requires full NAT unless the
  two tag stacks differ, which is ordinary routing between VLANs on one trunk.

The classifier key is the physical port plus the 5-tuple; no tag reaches it.
Two flows that share a 5-tuple on one port and differ only by VLAN therefore
collide, and the second is refused as a duplicate key rather than admitted
alongside the first. The ingress stack is validated by the header
manipulation, not by the lookup.

## Verification

Host-side, `tools/host_tests/flowtable.c::test_vlan` compiles the production
decoder against a simulated kernel and covers a single tag on each side, QinQ,
the asymmetric shape, the declined paths, the exact-mask rules, the MAC
inheritance requirement and the action arithmetic against both families.
Its `vlan_dev_real_dev()` shim reproduces the bottom-device behaviour, so a
decoder that used it fails the QinQ case rather than passing and shipping.
`flowtable_hw.c` asserts the innermost-first reversal tag by tag.

On hardware, `tools/tests/test_flowtable_vlan.py` runs LAN VM → DUT → WAN host
with the LAN behind a tag and the WAN untagged, so one connection exercises
the ingress strip and the egress insert at once:

| Case | Hardware packets, each direction | Evidence beyond the counters |
| --- | --- | --- |
| Routed UDP | 64 | tags recorded on the direction that carries them and not the other; both directions name the physical ports |
| Source NAT | 64 | the WAN endpoint observed the translated source address and port |
| QinQ | 64 | both tags, asserted by position rather than as a set |
| Full-MTU datagram | 16 | a 1472-byte payload crosses the tag, so the microcode's size check does not count the four tag bytes |
| TCP | ≥500 segments | half a megabyte each way on one connection, cookies unchanged |

A device MTU change asserts behaviour rather than a count: lowering the tagged
LAN device moves only the direction leaving by it, the other keeps the port's
MTU, and one connection retiring is a single invalidation because both
directions share a handle.

## What this does not carry

Per-VLAN-interface byte counters. CMM maintains them in the microcode's
logical statistics area and returns them through an FCI query; this ownership
mode loads no FCI, and the counters would need an interface index to be
allocated against. Deferring that to item 9 rather than growing a VLAN-shaped
allocator here is what made it cheap when PPPoE needed the same thing: the
allocator built for a session names the shape of the record rather than the
feature, so a VLAN asks for one with the same call. What is still missing for
a tagged flow is asking and reading back. Recorded against item 9 in the
[retirement roadmap](flowtable-cmm-porting-roadmap.md).

# Linux flowtable PPPoE

Session offload in the ASK flowtable adapter: why a session cannot be derived
the way a tag can, what stands in for the neighbour and the Ethernet
destination a ppp device does not have, what a session costs in the
encapsulation budget, and the hardware proof.

The accepted boundary is the
[supported scope](linux-flowtable-offload.md#supported-scope). This document
explains the mechanism behind it; the [VLAN guide](flowtable-vlan.md) covers
the device walk and the logical/physical split, which a session extends rather
than replaces.

## Where the session comes from

A tag is derived. A session is handed over, and it has to be.

`ft_path_stack()` derives a tag stack by descending from the logical device to
the physical port, one lower neighbour at a time. That walk stops dead at a ppp
device: `ppp_generic` registers no netdev adjacency, so there is nothing below
it to descend to. The session id and the concentrator's address are not in a
netdev at all — they live in a `pppox_sock` this module has no view of, and no
exported interface offers them.

So the hop arrives from the one walk that can resolve it.
`pppoe_fill_forward_path()` records `{session id, concentrator MAC}` and moves
the context down to the device the session runs over; patch 140 carries that
record — the device included — through `nf_flow_route` and the tuple to
`cls->nf_session` and `cls->nf_session_reverse`, paired with the two
destinations exactly as `nf_dst`/`nf_dst_reverse` are. The adapter's own walk
then splices it in: the session hop is taken *before* the loop, and everything
below it is derived as usual, so a session over a VLAN device or a bridge is
still walked rather than assumed.

Taking a second `dev_fill_forward_path()` in the adapter was rejected. Two
walks can disagree, and the one that would then describe the hardware is not
the one the rule was built from. One walk, one truth — which also means the
only cross-check available is the one thing the rule does carry, the
`FLOW_ACTION_PPPOE_PUSH` sid, and that is checked against the record.

## What Linux describes, and what it does not

Three gaps, and the contract is mostly about them.

**There is no pop, and no selector.** `nf_flow_rule_route_common()` emits
`FLOW_ACTION_VLAN_POP` for an 802.1Q ingress tag and nothing at all for an
ingress session — Linux has no PPPoE pop action to emit. `nf_flow_rule_match()`
fills the VLAN and CVLAN dissector values for a tag and nothing for a session.
So the rule for a direction whose frames *arrive* inside a session is
byte-for-byte the rule an unencapsulated flow produces: same key set, same four
Ethernet mangles, same action count. Only `cls->nf_dst_reverse->dev` being a
ppp device says otherwise. That is why the hardware proof counts both
directions separately and why `_both_directions()` exists: an ingress session
is the half most likely to be silently refused and the hardest to notice.

**There is no Ethernet destination.** A ppp device is `IFF_NOARP` with
`addr_len` zero, so `arp_constructor()` rewrites the key of every neighbour on
it to `INADDR_ANY` and leaves the hardware address zero.
`flow_offload_eth_dst()` reads that neighbour and writes **zeros** into the
four Ethernet mangle words. The real destination is the concentrator, which the
session names and nothing else does. The adapter therefore requires those words
to be exactly zero for a session egress and takes `dst_mac` from the session —
requiring the zero rather than ignoring the words is what stops a future kernel
that starts resolving something there from being silently overridden.

**There is no neighbour to watch.** `ft_neigh_matches()` excludes `NUD_NOARP`
deliberately, and a neighbour keyed on `INADDR_ANY` would not be found by a
lookup on the next hop anyway. A session egress is therefore published on the
watch list holding no neighbour at all, which is the first time watch-list
membership and neighbour ownership came apart: `ft_neigh_detach()` now unlinks
by the list's own emptiness, because an entry can be on it with nothing to
release, and an entry missing from it is retired by nothing.

Everything else about the routed contract is unchanged. The borrowed
destination, its FIB-generation cookie, `dst_check()` and the route
invalidation all still come from `nf_dst`; the Ethernet *source* is still the
physical port's, because `flow_offload_eth_src()` reads it from
`other_tuple->iifidx` under NEIGH, which is the port. No patch-140 change to
the transmit type was needed: unlike a bridge hop, a PPPoE hop does not force
`FLOW_OFFLOAD_XMIT_DIRECT`.

## The budget

`NF_FLOW_TABLE_ENCAP_MAX` is two, and a session spends one of the two. So a
direction can carry a session and one tag, and PPPoE over QinQ is refused —
by Netfilter first, which declines the path outright, and by the adapter's own
budget check, which states the bound rather than inheriting it from somebody
else's loop.

That ceiling is not theoretical here. The bench's access concentrator lives on
a standing VLAN, so the session runs over `eth4.3900`: **every case in the
proof below already spends both slots on the WAN side**, and the tagged-LAN
case adds a tag on the other side so each direction describes something on each
side at once.

Two orderings follow from the session being the innermost header. The push
actions are emitted outermost first, so the session push comes after every tag
push; and the encoder's opcodes insert PPPoE before VLAN before Ethernet, so
the session ends up inside the tag on the wire. Neither needs a reversal of its
own — `ft_encap()` reverses tags because two conventions meet there, and a
session has only one place it can be.

## What the encoder already had, and what it did not

The header manipulations existed. `INSERT_PPPoE_HDR` and `STRIP_PPPoE_HDR` are
in the shipped microcode, `fill_actions()` already emitted both, and
`dpa_l2hdr_info` already carried `pppoe_present`, `add_pppoe_hdr`,
`ac_mac_addr` and `pppoe_sess_id`. What was missing was a way to describe a
session that comes from a flow rather than from a registered PPPoE interface:
`struct cdx_l2_encap` carried only tags, and `apply_l2_encap()` refused any
description that named a session at all.

One thing had to be added rather than plumbed. Both opcodes index the logical
statistics area by an offset a registered interface owns. A flow-described
session owns none, so the insert would have aimed the microcode's counter
update at the unallocated offset zero — another interface's slot — and the
strip would have failed outright, since its lookup resolves an interface of
type `IF_TYPE_PPPOE` and is handed a physical port. `pppoe_no_ifstats` makes
both emit a null statistics pointer instead.

**That suppression rests on weaker evidence than the VLAN one.** The VLAN
insert's field is documented in the SDK header as "base of stats area or stats
pointer, null no stats". The two PPPoE structures carry no such comment; the
only evidence that null means "no statistics" for them is that NXP's own
`INCLUDE_PPPoE_IFSTATS`-disabled arms write zero. Host tests pin the emission —
`tools/host_tests/pppoe_hm.c` compiles both production manipulations against
the shipped header and requires the null pointer, and requires the strip not to
attempt the interface lookup at all — but what the microcode does with a null
pointer is not provable off hardware. The hardware runs below show no counter
corruption and no errors, which is evidence and not proof.

## Eligibility

Beyond the rules a routed, tagged flow already satisfies:

- At most one session per direction, and it must be the outermost hop. This is
  structural rather than guarded: the hop is taken before the walk loop, so a
  second ppp device, or one beneath a tag, is declined by the loop as any other
  unsupported upper device is.
- The session must have completed discovery: a session id of zero is reserved
  for discovery itself, and a concentrator address that is not a valid unicast
  Ethernet address describes nothing the hardware could reach.
- The device the session runs over must resolve, and must share its port's MAC
  address. This is the rule the VLAN increment imposes on a logical device,
  applied to the one device a session hides — a ppp device has no address of
  its own, so that is where the rule has to be stated.
- A session the kernel's walk crossed but the adapter's did not reach is
  refused rather than dropped from the description, which would forward with no
  session header at all.
- A session and its tags together may not exceed `NF_FLOW_TABLE_ENCAP_MAX`.
- The four Ethernet mangle words must be zero on a session egress, and the
  `FLOW_ACTION_PPPOE_PUSH` sid must equal the one the walk resolved.
- IPv6 over a session is declined. `en_ehash_insert_pppoe_hdr` carries a
  version, a type, a code and a session id, and no PPP protocol id at all, so
  the firmware chooses between `0x0021` and `0x0057` on its own and nothing has
  shown that it picks the IPv6 one for an IPv6 flow. A wrong protocol id is a
  header the peer discards — a silent loss rather than a loud refusal — so it
  is excluded until proven.

The classifier key is unchanged — the physical port plus the 5-tuple — so a
session reaches the hardware only as the header it inserts or strips.

## Retirement

A session drop is **self-healing, and selective**, which was not the
expectation. The route is what notices first: pppd's peer route dies with the
device, the flow borrowed that destination, and the route watch retires both
directions before the device is unregistered. By the time it is, nothing
references it and it was never a binding, so `ft_device_used()` is already
false and the netdev watch's escalation to full invalidation never fires. The
bindings stay up, admission is never disabled, nothing re-arms, and the next
packet re-offers the flow against whatever session exists then.

What the adapter depends on otherwise is the ppp device itself: its MTU — which
arrives at 1492 without anyone setting it, the eight bytes of overhead already
in it — its link state and its removal, all through `ft_entry_uses()` on
`out_logical`/`in_logical`.

## Verification

Host-side, `tools/host_tests/flowtable.c::test_pppoe` compiles the production
decoder against a simulated kernel and covers a session on each side, both at
once, a session over a VLAN device and over a bridge, the hairpin whose two
directions differ only by a session, the lifecycle of an entry holding no
neighbour, and twenty-two declined paths. `tools/host_tests/pppoe_hm.c` covers
the two header manipulations and `apply_l2_encap()` against the shipped SDK
header, including the session-id byte order — which the legacy control path
reaches by applying `htons()` twice, so it is worth stating — and the
statistics suppression on both opcodes. Thirty mutations of the guards
described here were reintroduced one at a time; twenty-eight were caught. The
two that were not were redundant guards subsumed by others, one of which was
also the only thing bounding the walk; both were removed and the bound made
structural instead.

On hardware, `tools/tests/test_flowtable_pppoe.py` runs LAN VM → DUT → session
→ orchestrator, with a real `pppoe-server` on the far end and `pppd` on the
DUT over `eth4.3900`. Every case asserts the session id and concentrator the
adapter recorded against `/proc/net/pppoe`, which is the kernel's own
independent view of what was negotiated:

| Case | Hardware packets, each direction | Evidence beyond the counters |
| --- | --- | --- |
| Routed UDP | 64 | session recorded on the direction that inserts it and the one that strips it, and on neither LAN half; both directions name the physical ports; the forward MTU is 1492 with nothing having set it |
| Source NAT | 64 | the concentrator observed the translated source, so the rewrite and the encapsulation reached the same frame in the right order |
| Tagged LAN | 64 | a tag on the LAN and a tag plus a session on the WAN: each direction pops one and pushes two, asserted per direction rather than as a set |
| Full-MTU datagram | 16 | a 1464-byte payload fills the 1492 path MTU, so the microcode's size check counts neither the eight session bytes nor the four tag bytes |
| TCP | ≥100 segments | half a megabyte each way on one connection, cookies unchanged |

Two cases assert behaviour rather than a count. Lowering the ppp device's MTU
moves only the direction leaving by it, the other keeping the LAN port's, with
one connection retiring as a single invalidation because both directions share
a handle — and the session identity is unchanged across it. And hanging the
session up retires both directions through the route watch with the bindings
untouched, no invalidation and no re-arm, after which a redial and ordinary
traffic readmit the flow against the **new** session id and concentrator, which
is what a stale entry would fail while forwarding happily into nothing.

All of it on the KASAN image, with the adapter's error, fatal and quarantine
counters at zero afterwards.

## What this does not carry

**A session renegotiated under a surviving `pppN` device.** The dependency is
the ppp device, and every change to the device the session runs over destroys
the session outright — `pppoe_device_event()` flushes on `CHANGEADDR`,
`CHANGEMTU`, `GOING_DOWN` and `DOWN` — which pppd then turns into the device
going away. What is not covered is a reconnection that keeps the unit, as
`persist` with a reconnect script can: the id and the concentrator would change
under a device that never disappeared, and nothing would notice. The failure
mode is loss rather than misdelivery — the concentrator drops frames for a
session it no longer knows, and the DUT's own source address does not match any
other subscriber's — and no exported interface reports a session change, so
closing it would need a notifier that does not exist. Stated rather than
silently assumed away.

**IPv6 over a session**, for the reason in the eligibility list: the firmware's
choice of PPP protocol id is unverified.

**Per-session byte counters.** CMM maintains them in the microcode's logical
statistics area against a registered PPPoE interface and returns them through
an FCI query; this ownership mode loads no FCI and registers no such interface,
which is the same reason a tagged flow carries no per-VLAN-interface counters
and the same item — 9 in the [retirement
roadmap](flowtable-cmm-porting-roadmap.md) — that owes both.

**PPPoE relay**, which is a different feature: session-to-session forwarding
through `REPLACE_PPPOE_HDR` and the relay classifier table, deleted from CMM
and CDX as dead code before this increment and not reintroduced by it.

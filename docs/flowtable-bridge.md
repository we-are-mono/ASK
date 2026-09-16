# Linux flowtable bridge

Bridge offload in the ASK flowtable adapter: why a bridged flow has to keep
its destination, where its tags come from when no netdev describes them, the
dependency no earlier increment had to watch, and the hardware proof.

The accepted boundary is the
[supported scope](linux-flowtable-offload.md#supported-scope). This document
explains the mechanism behind it; the [VLAN guide](flowtable-vlan.md) covers
the logical/physical device split and the device walk, which this increment
widens rather than replaces.

## Why the transmit type had to change

`nft_dev_path_info()` forces `FLOW_OFFLOAD_XMIT_DIRECT` inside its
`DEV_PATH_BRIDGE` case, before it consults anything a table asked for. A
DIRECT tuple caches `h_source`, `h_dest` and an `ifidx` in the union where the
destination would otherwise live, so `nf_flow_offload_dst()` returns NULL for
it and the adapter declines it at the `!cls->nf_dst || !cls->nf_dst_reverse`
gate. Every bridged flow reached the adapter that way.

The adapter's whole contract is built on that destination: the borrowed route,
its FIB-generation cookie, `dst_check()`, the neighbour validated and attached
against the logical device, and the route-invalidation hook all come from
`nf_dst`/`nf_dst_reverse`. (The MTU does not: `flow_offload_fill_route()`
computes it from the destination before releasing it, so a DIRECT tuple keeps
it.) Patch 140 therefore honours `use_neigh` in the bridge case too, and a
bridged flow keeps its destination.

Nothing about the egress port is lost by doing so. A NEIGH redirect names
`other_tuple->iifidx`, which `nft_dev_forward_path()` set to `info.indev` —
and `info.indev` is the physical port, because `DEV_PATH_BRIDGE` never assigns
it: `br_fill_forward_path()` sets `ctx->dev` to the port the FDB resolved, and
the walk terminates on it with a `DEV_PATH_ETHERNET` entry. The Ethernet
source follows the same path: `flow_offload_eth_src()` reads it from that
interface under NEIGH, which is the physical port's address and exactly what
the encoder caches and `cdx_ft_add()` requires.

Teaching the adapter a second, DIRECT-transmit contract was rejected. It has
no destination, so it would need its own substitutes for `dst_check()`, the
generation cookie and route invalidation, and its Ethernet addresses
would come from the tuple rather than from a validated neighbour — duplicating
the validation surface four increments went into getting right. The only thing
DIRECT buys is skipping the bridge in *software*, and this mode's traffic is
in hardware. Software fallback is unaffected either way: the bridge is an L3
device, `dst_neigh_lookup()` resolves on it, and output traverses the bridge
and its FDB as ordinary routing does.

## Where the tags come from when no device carries them

A vlan-aware bridge transforms the tag stack through its own VLAN groups
rather than through a netdev. `br_vlan_fill_forward_path_pvid()` decides which
VLAN the frame is in — the outermost tag already present if it is in the
bridge's protocol, otherwise the bridge's PVID — and
`br_vlan_fill_forward_path_mode()` then reads the egress port's membership:
tagged leaves the stack alone, untagged either removes the tag or cancels the
PVID insertion. Four outcomes, and only one of them agrees with the devices:

| Shape | Bridge decision | Tags on the wire |
| --- | --- | --- |
| VLAN filtering off | `BR_VLAN_KEEP` | whatever the VLAN devices describe |
| `br-lan.N`, port tagged for N | `BR_VLAN_KEEP` | the VLAN device's tag |
| `br-lan.N`, port untagged for N | `BR_VLAN_UNTAG` | none, though a VLAN device is in the path |
| `br-lan`, port tagged for the PVID | `BR_VLAN_TAG` | a tag no netdev describes |

The third row is the configuration that ships. Deriving tags from the devices
alone would push one onto a frame the station cannot parse; declining it would
leave the increment unable to reach the product's topology at all. So
`ft_bridge_vlan()` mirrors both kernel functions through the same bridge state
they read — `br_vlan_enabled()`, `br_vlan_get_proto()`, `br_vlan_get_pvid()`
and `br_vlan_get_info()` — and the rule's POP/PUSH actions are still checked
against the result. The direction of authority is unchanged: the devices and
the bridge configuration decide, and the actions have to agree.

`DEV_PATH_BR_VLAN_UNTAG_HW` is the fifth outcome and is excluded rather than
derived. It means the tag is on the wire while the rule describes neither a
selector nor a POP for it, and it is indistinguishable from an ordinary
untagged port through the exported bridge queries. The bridge only chooses it
for a VLAN a switchdev driver accepted, so `cdx_ft_port_supported()` now
refuses any port reporting a switch parent — which a DPAA MAC never does. The
exclusion is a property the gate proves, not one the hardware is assumed to
have.

## The bridge hop is terminal

`ft_path_stack()` accepts one bridge master and stops there. It does not
descend through `netdev_for_each_lower_dev()`, as it does for a VLAN device: a
bridge has many lower devices and the first is whichever was enslaved first,
never the one the FDB chose. The port this flow leaves by is already known —
it is what the redirect and the binding name — so the walk requires
`netdev_master_upper_dev_get(physical)` to be that bridge and terminates.

The same requirement declines a bridge port that is itself a stacked device: a
VLAN device enslaved to the bridge hides whatever tag lies between it and the
physical port, and the walk would derive a stack shorter than the wire carries.

## The fifth dependency

Four dependency classes were already watched: route, neighbour, netdev and
nexthop. A bridged flow adds a fifth. `br_fill_forward_path()` chose the
egress port with `br_fdb_find_rcu(br, destination MAC, VID)`, so the hardware
entry is pinned to whatever that entry named at admission. A station that
roams to another port, or an entry that ages out and is relearned elsewhere,
otherwise keeps being forwarded to the old port until something unrelated
retires the flow.

**Linux does not retire its own flows on an FDB change.** Nothing under
`net/bridge/` references a flowtable. An upstream bridged flow is DIRECT and
caches the same port in `out.ifidx`, so it misforwards in software for exactly
as long. The staleness is inherited, not introduced, and it has to be watched.

`ft_fdb_event()` subscribes to the switchdev notifier chain, which
`fdb_notify()` reaches for a plain, non-switchdev bridge too: a roam emits a
delete against the old port and an add against the new one, ageing and
explicit deletion emit a delete, and a port leaving the bridge deletes
everything it learned. The handler follows the shape of the four existing
notifiers — latch under `ft_watch_lock`, never touch the backend — because the
chain is atomic; `br_fdb_update()` learns from softirq. It matches on the
destination MAC and the VID the bridge resolved, and an add naming the port
the flow already leaves by re-states the pinning rather than changing it.
Matching no more narrowly than that is deliberate: a same-address event on an
unrelated bridge costs one retirement and readmission, where missing a real
move costs silent misforwarding.

The bridge configuration `ft_bridge_vlan()` reads is watched the same way, on
the blocking switchdev chain: per-port membership arrives as
`SWITCHDEV_OBJ_ID_PORT_VLAN` objects against the port, and the two bridge-wide
settings — whether it filters by VLAN at all, and in which protocol — as
`SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING` and `_PROTOCOL` attributes against
the bridge. None of the three emits a netdev event and the ports stay up
across all of them, so nothing else here would notice; each is administrative
and rare, so each takes the coarse route a nexthop-object change takes.

Two properties of that handler are load-bearing. It never sets `handled`,
because the bridge treats a handled port-VLAN object as installed in hardware
and then skips `vlan_vid_add()`, which would filter the VLAN out of the port
entirely. And it invalidates only for a device the adapter depends on: every
bridge installs its default PVID on a port the moment that port is enslaved,
whatever its VLAN filtering setting, so a handler without that scope test
retires every flow on the hardware whenever any device anywhere is enslaved to
anything.

One FDB change is not reported and so is not watched: an entry added from
userspace as dynamic — `bridge fdb add <mac> dev <port> master dynamic` —
takes `br_switchdev_fdb_notify()`'s early return for a user-added entry that
is neither static nor externally learned, so it emits nothing on any chain. It
re-points forwarding with no event to act on. Every learned, aged, roamed,
flushed and ordinary-deleted entry does notify.

Ageing deserves one note. Hardware forwarding never reaches the bridge, so
nothing refreshes the entry from the flow's own traffic. What keeps it warm in
practice is the neighbour watch: `ft_stats()` calls `ft_neigh_used()` with the
hardware's own activity, which lets Linux advance the neighbour through
STALE/DELAY/PROBE and solicit ARP, and the reply crosses the bridge. A
*permanent* neighbour has no such cycle, and its FDB entry does age out under
a live flow — which is the case the proof below drives, because it is the one
that would misforward if the delete were not watched.

## Eligibility

Beyond the rules a routed, tagged flow already satisfies:

- Each logical device must reach its physical port through 802.1Q VLAN devices
  and at most one bridge master, and that bridge must be the port's own
  master. A bridge port that is itself a stacked device is declined.
- The effective tag stack, after the bridge's own transformation, is still
  bounded by `NF_FLOW_TABLE_ENCAP_MAX`.
- The egress port must be a member of the VLAN the bridge resolved. It would
  otherwise have failed `br_fill_forward_path()` outright, so Netfilter would
  never have described the flow.
- A port reporting a switchdev parent is refused, which is what makes
  `DEV_PATH_BR_VLAN_UNTAG_HW` unreachable.
- The bridge (or the VLAN device above it) must share the egress port's MAC
  address, under the rule the VLAN increment already imposes: the Ethernet
  source of a neighbour-output flow is the port's, and the encoder caches one
  address per port. A bridge takes its lowest port's address, so this holds for
  that port and decides which ports of a multi-port bridge are eligible.
- `CONFIG_NET_SWITCHDEV` is required to build the adapter at all. It is the
  only chain a plain bridge reports FDB and VLAN-membership changes on, and
  building without it would offload bridged flows and never retire a stale
  one.

The classifier key is unchanged — the physical port plus the 5-tuple — so a
bridge reaches the hardware only as the tag stack it produces and the egress
queue it selects.

## Verification

Host-side, `tools/host_tests/flowtable.c::test_bridge` and `::test_bridge_fdb`
compile the production decoder against a simulated kernel carrying bridge VLAN
groups, and cover all four VLAN shapes on both the ingress and egress side,
the declined paths, the QinQ ordering the bridge resolves on, the device
references each shape pins, and every branch of the FDB and port-VLAN
notifiers. The simulated bridge's first lower device is deliberately not the
port a flow leaves by, so a walk that descended it by adjacency fails rather
than passing and shipping. Twenty-one mutations of the guards described here
were reintroduced one at a time; each was caught.

On hardware, `tools/tests/test_flowtable_bridge.py` runs LAN VM → DUT → WAN
host with the LAN behind `br-ft` and the WAN unbridged, in three shapes:

| Case | Hardware packets, each direction | Evidence beyond the counters |
| --- | --- | --- |
| Routed UDP, plain bridge | 64 | the bridge named on the direction that crosses it and not the other; both directions name the physical ports; the station still learned on the port the entry was pinned to |
| Source NAT, plain bridge | 64 | the WAN endpoint observed the translated source address and port |
| Vlan-aware bridge, untagged port | 64 | `br-ft.273` recorded with the VID its FDB lookup used, and no tag on either wire |
| Vlan-aware bridge, tagged port | 64 | the same devices and a different membership: the tag reaches the wire on the direction that carries it |
| TCP, vlan-aware bridge | ≥500 segments | half a megabyte each way on one connection, cookies unchanged |

Three cases assert behaviour rather than a count. A station made to reappear
on a second bridge port — by sending from its own address through a VLAN
pseudo-port on the same wire, so the bridge relearns rather than being told to
— moves the FDB entry, increments the FDB invalidation counter once, retires
the flow, and is readmitted against the first port when ordinary traffic
teaches the bridge it is back. An entry left to age out under a live flow does
the same, which is the case that would misforward silently if the delete were
not watched. And lowering the bridge's MTU moves only the direction leaving by
it, the other keeping the port's, with one connection retiring as a single
invalidation because both directions share a handle.

All of it on the KASAN image, with the adapter's error, fatal and quarantine
counters at zero afterwards and no suppressed diagnostics.

## What this does not carry

A bridge whose address differs from the egress port's, which is every port of
a multi-port bridge except the one the address was taken from. Lifting it
needs a per-flow Ethernet source in the encoder rather than one cached address
per port, which is the same allocator question interface statistics raise, and
belongs with item 9 rather than here.

MACVLAN, which item 13 records, is a separate upper device and is still
declined by the walk: it is neither an 802.1Q VLAN nor a bridge master.

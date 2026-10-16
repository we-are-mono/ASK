# Linux flowtable bridge

Bridge offload in the ASK flowtable adapter: why a bridged flow has to keep
its destination, where its tags come from when no netdev describes them, the
dependency no earlier increment had to watch, and the hardware proof.

The accepted boundary is the
[supported scope](README.md#supported-scope). This document
explains the mechanism behind it; the [VLAN guide](vlan.md) covers
the logical/physical device split and the device walk, which this increment
widens rather than replaces.

## Bridge output filters

A routed unicast entry that leaves through a bridge is refused while any
bridge-family `LOCAL_OUT` or `POST_ROUTING` hook is registered. Hardware sends
directly to the port queue and cannot execute those hooks. The software
flowtable's neighbour output traverses the bridge and applies them.

The adapter rechecks these hooks on each installed offer and statistics poll.
If a hook appears after admission, it retires the flow generation, including
its other hardware direction. This follows the flowtable polling cadence;
retirement is asynchronous. Once the hook is removed, traffic can be admitted
again. `test_unicast_bridge_egress_filter` covers both hooks before admission
and after a flow is already installed, with packet delivery and drop counters.

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

## The bridge hop

`ft_path_stack()` accepts one bridge master. It does not descend from it
through `netdev_for_each_lower_dev()`, as it does from a VLAN device: a bridge
has many lower devices and the first is whichever was enslaved first, never
the one the FDB chose. The port this flow leaves by is already known — it is
what the redirect and the binding name — so the walk finds the bridge's port
from below instead (`ft_bridge_port()`): the physical port itself, or an
802.1Q VLAN device on it that the bridge enslaves, which is how OpenWrt
bridges a VLAN without `bridge-vlan` sections (`br-lan` over `eth0.10`). From
that port the walk descends as anywhere else, so the port's own tag lands
outside any the bridge adds, and the VLAN device is recorded with the tags --
its counters, and the dependency that retires the flow when its state, its
membership or its MTU changes, and whose MTU bounds the direction: the bridge
checks a frame against its port (`is_skb_forwardable()`), which a VLAN device
may set below the physical port's (`ft_port_mtu()`). A bridge that enslaves
two VLAN devices of one physical port is ambiguous from below and declined, as
is a second bridge on the way down. Where the physical port and a VLAN device
on it are both the bridge's ports, the physical port is taken; a flow the FDB
sent through the VLAN device then fails the exact action count and the
pushes' VIDs, unless the bridge's own tag on the physical port is that same
VID -- the same wire, with the port's STP and FDB dependencies attached in
place of the device's. 1.0.7 carried the same shape (a bridged VLAN interface, sending
with the bridge's address); 1.1.0 declined it until this walk.

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

The bridge's forwarding state is the last input. A port that STP, MST or a
per-VLAN state takes out of FORWARDING carries nothing through the bridge, but
the flowtable does not ask the bridge per frame: its hook on the port runs
before `br_handle_frame()`, and a DIRECT tuple transmits past `br_forward()`.
Three pieces close that. `162-bridge-forward-path-forwarding-state.patch`
makes `br_fill_forward_path()` refuse such a port with `-EAGAIN`, which
`nft_flow_route()` turns into no flow at all -- a flow cached on the logical
device instead would never be offered to the port once it forwarded again --
and exports the same test as `br_port_forwarding(port, vid)`, which admission
asks because a refresh re-offers a flow described while the port still
forwarded. The same patch reports a per-VLAN state set directly as
`SWITCHDEV_ATTR_ID_PORT_VLAN_STATE`; before, only MST states had an event.
And on any of those events leaving FORWARDING the adapter retires its hardware
entries through the port and queues `nf_flow_table_cleanup()` for it, which
reaches the software flows no handle names: the ones admission refused and the
ones another table owns. Two MST events are raised on the bridge alone and
stop every port of it: `SWITCHDEV_ATTR_ID_VLAN_MSTI`, since a VLAN moved to
another MSTI takes up that MSTI's state on each port (DISABLED where it has
none) with no port event, and `SWITCHDEV_ATTR_ID_BRIDGE_MST` switching MST
off, since each port's own STP state then applies again. Admission keeps an
MST bridge out of hardware, so those two reach software flows. The sweep is
queued because an MSTI's state arrives inside an RCU read-side section and
native cleanup sleeps. It takes RTNL, then waits out a grace period: several
of these events are raised before the change they report, inside the RTNL
section that makes it, so only then is the new state certain to be in place
and every flow whose walk read the old one already in the table to be found.
With spanning tree off, `bridge link set ... state 4` never
sticks -- `br_port_state_selection()` puts a designated port straight back to
FORWARDING -- so the rig blocks a port under user-space STP.

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
  and at most one bridge master, whose port is the physical port or one 802.1Q
  VLAN device stack on it.
- The effective tag stack, after the bridge's own transformation, is still
  bounded by `NF_FLOW_TABLE_ENCAP_MAX`.
- The egress port must be a member of the VLAN the bridge resolved. It would
  otherwise have failed `br_fill_forward_path()` outright, so Netfilter would
  never have described the flow.
- A port reporting a switchdev parent is refused, which is what makes
  `DEV_PATH_BR_VLAN_UNTAG_HW` unreachable.
- The bridge (or the VLAN device above it) need not share the egress port's
  MAC address: the direction carries the address Linux sends with (see
  [the Ethernet source](#the-ethernet-source)). A Wi-Fi VAP behind the bridge is
  the exception for now and still has to carry the bridge's address itself.
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

On hardware, `tools/tests/flowtable_bridge.py` runs LAN VM → DUT → WAN
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
not watched. And lowering the bridge's MTU retires the connection as a single
invalidation, because both directions share a handle; the UDP direction
leaving by the bridge then stays in software, the path now smaller than what a
port receives ([architecture.md](architecture.md#native-context-and-admission)),
while the other is readmitted at the port's. Raising the bridge's MTU above its
port's -- 9000 over a 1500-byte port, which `br_change_mtu()` allows -- does
not raise the direction leaving by it: Linux drops at the port what the port's
MTU forbids (`is_skb_forwardable()`), so that direction is readmitted at the
port's 1500 rather than the bridge's 9000 (A340). Nor does the bridge receive
more than its port does, whose MAC takes frames by its own MTU, so the
direction arriving on it is readmitted too, into the WAN's 1500 (A346).

All of it on the KASAN image, with the adapter's error, fatal and quarantine
counters at zero afterwards and no suppressed diagnostics.

## The Ethernet source

A routed frame Linux sends through a bridge carries the bridge's address, on
whichever port the FDB chose. On a multi-port bridge that is every port's
frames but those of the port the address was taken from -- OpenWrt's br-lan
over eth0 to eth3, its address eth0's, is the common case. Each direction
therefore carries its own source: the address of the device the walk found
Linux transmitting from (`ft_path_stack()`), which the encoder writes in place
of the port's (`RouteEntry.srcmac`). The same rule covers a VLAN device with an
address of its own and the device under a PPPoE session. A change of that
address retires the entries naming the device, as a port's does.

`flowtable_bridge.py` runs its routed, SNAT and TCP cases over that shape too
("openwrt", `_topology.openwrt_lan()`), and the exchange checks the bridge's
address on every frame the station receives; `flowtable_pppoe.py` does the
same behind a session (`test_openwrt_lan`, `test_openwrt_lan_tcp`).

## Switching between two ports

Everything above is routed: a flow crosses a bridge on its way to or from a
route. Two stations on two ports of one bridge talk with no route at all, so
no flowtable ever sees them, and 1.1.0 forwarded them in software. 1.0.7
switched them at line rate: `auto_bridge`, fed by a kernel bridge hook (patch
020, gone with CMM), handed CMM each pair to install. The bridged unicast
learner (`ask_flowtable_l2.c`) does the same job inside the adapter.

The hardware side needed nothing new. Every IP table's miss already falls
through to the ingress port's Ethernet table (`cdxdrv_set_miss_action()`),
keyed on the port and the frame's destination, source and EtherType, and that
table sat empty. `insert_l2_entry_in_classif_table()` fills it: one entry per
direction of a pair, the non-routed actions (no TTL, no NAT), the frame's own
addresses written back unchanged (`RouteEntry.srcmac` again), and a pop or a
push where the two ports tag the pair's VLAN differently. The key's EtherType
is the frame's own inside the tag, not the TPID; the rig's tagged direction
proves it. A tagged frame is always stripped and tagged again, even when both
ports carry the VLAN tagged: the strip is what checks the VID, which the key
does not hold, and without it the same pair in another VLAN of the port would
leave in its own. Measured, the check is exact: a frame tagged with another
VID than the entry strips, an untagged frame against an entry that strips a
tag, and a tagged one against an entry that strips none all match the key and
are handed to Linux, never forwarded. The tag inserted carries the VID alone, so a frame bridged
from one trunk to another leaves with priority 0 where the bridge keeps its
PCP -- as 1.0.7's entries did. Since neither the VLAN nor the tag is in the
key, a pair in two VLANs, or tagged and untagged, on one port would need one
key twice; the second stays in software.

The learner is the bridged multicast learner's shape: a bridge
`PRE_ROUTING` hook -- before the bridge gives an untagged frame its PVID, the
only place the wire form, which is the key, is still known -- that records a
unicast IPv4 or IPv6 pair at most once a second per CPU and never diverts a
frame; a worker that asks the bridge, under a trylocked RTNL, everything it
would decide about the pair; and events that mark pairs dead from wherever
they arrive. Admission requires both ports bound to an offload flowtable and
supported, both forwarding in the VLAN (`br_port_bridging()`, patch 163: the
port's state and its VLAN's, not the bridge's own entry, which a bridged frame
never crosses), the VLAN the one the bridge puts the frame in now -- an
untagged observation's VID still the ingress PVID, none at all without
filtering -- the destination learned on another port and the source on the
ingress, 802.1Q filtering or none, no MST, no isolation between the two, no
locked, MAB or VLAN-tunnel port, nothing tc or a netdev chain runs on either
port, an egress MTU no smaller than the ingress's, and a bridge that is not
promiscuous: one that is hands every frame it forwards up as well, to a
capture or to an upper device with an address of its own (a VRRP virtual
MAC), and an entry would take that copy away. Frames for the bridge's own
address are the router's and are never recorded, and `br_fdb_forward_port()`
(patch 163) answers only for learned entries, so a port's own address is not
a destination either. Priority-tagged and 802.1ad-tagged frames stay in
software. Either port may be an 802.1Q VLAN device on a physical port, as in
the routed walk: the key is then the physical port's, the device's tag is
checked and stripped on the way in and pushed outermost on the way out, the
bridge's own inside it, and the physical ports are what must be bound. What
can arrive is what the physical port's MAC accepts, so the egress port's MTU
is held to that, not to a VLAN device's on the way in. Two VLAN devices of one
physical port share its key, so the same pair through a second one stays in
software. The rig runs pairs through a VLAN-device port alone ("vlanport") and
tagged for the bridge's VLAN as well ("vlanport-trunk", two tags each way). While any bridge-family hook other than the learners' own
is registered -- an nftables or ebtables chain, br_netfilter -- no pair is
carried, exactly as for a bridged routed flow.

The learner publishes a pair where events can mark it before it asks the
bridge the last time and builds the entry, so nothing the bridge does in
between goes unseen. A pair retires when an FDB entry of either station
moves, ages out or is deleted (matched through a per-station index, not a
walk); when a port or the bridge changes state, VLAN membership, filtering,
MTU, address or link, leaves the bridge or unregisters; when the port is
unbound; on global invalidation; and after `l2_idle_ms` (30 s) with no frame.
An egress change -- an HTB tree, a class, the DSCP map -- takes the port's
pairs out synchronously before CDX hands its queues on (`ft_egress_drain()`),
and a pair built across one is taken out again. Some changes raise no event
-- a tc filter or a netdev chain, the bridge turning promiscuous, the VLAN
tunnel flag, an FDB entry added by hand as dynamic or locked -- so every
installed pair is asked of the bridge again every five seconds. Frames the
hardware forwards never reach the bridge to refresh its FDB, so a pair whose
counters moved refreshes its source station's entry, while it still names the
ingress port (`br_fdb_refresh()`, patch 163), as a received frame would; the
destination's is its reverse pair's to keep, so a station that went silent
ages out and is flooded for as it would be in software.

A pair the learner refuses is left to software for at most ten seconds
(`FT_L2_REFUSE_HOLD`) before its frames are offered again, unless something it
may rest on changes first: an FDB event for either station (the destination not
yet learned is the commonest refusal), any port's or the bridge's change, a
binding coming, going or being rearmed, the datapath restarting, or the pair it
collided with -- the same stations in another form, or through another VLAN
device of the port -- being retired. A refusal decided while such an event came
in is not held at all. auto_bridge parked a pair CMM denied until ten seconds
without a frame or a change, so a denied pair carrying traffic stayed denied;
this one is asked again within ten seconds whatever. What raises no event -- a
tc filter or netdev chain going, the bridge leaving promiscuous mode, the VLAN
tunnel flag, room freed in a full hardware table -- waits out the hold.
`l2_held` counts the observations a refusal kept from the worker.

`/proc/cdx_flowtable` lists each pair as an `l2flow` row with its ports,
addresses, VLAN, tag rewrite and counters, after the flow rows and under
`l2_*` totals in the header. Like the flow rows, each is a record of its own,
so a read holds the transaction for one buffer of them; and every walk over
the pairs -- the once-a-second sweep that reads counters and ages pairs out,
the recheck, a global invalidation, an egress drain, unload -- goes a batch at
a time, at most `FT_L2_VISIT_BATCH` (256) pairs visited and `FT_RETIRE_BATCH`
(64) retired per hold, as routed retirement does (A327, A382).
`ask_flowtable.l2_bridge=0` turns the learner off.

`flowtable_l2bridge.py` proves it on the rig: the LAN VM on eth3 and a
namespace on the WAN host, reaching eth4 tagged 3900, bridged in one VLAN --
untagged on eth3 ("access") or tagged there too ("trunk"), tagged on eth4 --
with the WAN in VLAN 1 of the same bridge. Both pairs are listed with the tag
rewrite each needs; a ping burst moves both pairs' counters by every frame
while the DUT transmits none; four TCP streams run at 9.37-9.39 Gbit/s each
way in both shapes with the DUT ~5% busy, for longer than a shortened FDB
ageing time with nothing retired; an FDB delete, an idle pair and a bridge
chain each take the pairs out, and they come back. Frames injected with a
pair's addresses in every form the bridge would not forward to the far end --
untagged, tagged where the entry expects none, tagged in another VLAN -- are
counted at the far end: none arrives, every one reaches Linux on the ingress.
The entry's counters are no evidence there: they count a key's matches,
including the frames its check then hands up.

## What this does not carry

Between two ports, the learner carries IPv4 and IPv6 unicast only: ARP,
other EtherTypes, a tagged frame on a bridge that does not filter VLANs
(forwarded with its tag as payload), 802.1ad, a Wi-Fi VAP as either end and a
pair whose TTL or hop limit is 1 stay in software.

MACVLAN is a separate upper device and is still declined by the walk: it is
neither an 802.1Q VLAN nor a bridge master. That is the accepted answer rather
than a pending increment — see the out-of-scope entry in the
[retirement roadmap](cmm-porting-roadmap.md).

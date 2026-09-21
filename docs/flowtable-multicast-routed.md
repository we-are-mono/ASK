# Routed multicast without CMM

Roadmap item 7, second half, and the last item on the CMM-retirement list. The
[bridged learner](flowtable-multicast.md) reads the bridge's MDB; this one
reads the kernel's multicast routing tables. They are two learners against one
encoder, and the difference between them is not a feature — it is that one of
them has to guess and the other does not.

## The shape of the problem, and why it is a second learner

The bridged increment turned on one observation: the hardware matches an exact
`(S,G)` on an exact ingress port, and an MDB membership names neither. A
`(*,G)` join is a permission, not a key, so that learner has a netfilter hook
in the bridge's receive path whose only job is to watch the first frames of a
stream and read the source and the ingress port off them.

**ipmr states both.** `struct mfc_cache` is `mfc_origin`, `mfc_mcastgrp`,
`mfc_parent` and `ttls[MAXVIFS]`: a specific source, a group, the VIF the
stream arrives on, and — because `ip_mr_forward()` forwards out VIF `i` exactly
when `ttl > ttls[i]` and 255 means "not an oif" — a replication list. That is
the whole of a classifier key and the whole of a listener set, written down by
the control plane before a single frame has arrived.

So the two halves of the bridged learner collapse into one here. There is no
traffic hook, nothing is ever `pending-source`, and a group is installed or
refused the moment the routing daemon writes its entry.

That is why it is a sibling rather than a modification. The state is different
(an MFC entry, not a `(bridge, br_ip)` membership), the lifecycle is different
(a kernel object with a refcount, not a switchdev object), the chain is
different (the FIB notifier, not switchdev), and the eligibility questions are
different (a VIF's flags, a threshold, a policy rule). What is shared is the
encoder underneath and the hardware key namespace above — and the second of
those turns out to need a register of its own; see below.

**The encoder needed no change at all, and that is worth stating precisely
because it looks like it should have.** A multicast root entry is built by
`fill_actions()` in `cdx/cdx_ehash.c`, which sets `TTL_HM_VALID`
unconditionally, so the microcode decrements the TTL or hop limit on every
matched frame — and the FMC soft parser ends the parse before classification
for any frame arriving with 0 or 1, which is the kernel's own `ttl > 1` rule
expressed one layer down. Each listener entry
(`create_exthash_entry4mcast_member`, `fill_mcast_member_actions`) rebuilds the
Ethernet header with the egress port's own address and the group's mapped
multicast destination. Decrement the hop count, rewrite the L2 header, replicate:
that *is* a router. The bridged learner has been driving a router and asking it
to bridge. This one asks it to do what it does.

## What the kernel offers

`net/ipv4/ipmr.c` and `net/ipv6/ip6mr.c` announce everything on the FIB
notifier chain, under two families of their own — `RTNL_FAMILY_IPMR` and
`RTNL_FAMILY_IP6MR` — and **the adapter has been registered on that chain since
the foundation increment**. `ft_fib_event()` dropped those events at its
`AF_INET`/`AF_INET6` filter; opening that filter is the whole of the plumbing.

Four kinds of event arrive:

- `FIB_EVENT_VIF_ADD` / `FIB_EVENT_VIF_DEL`, carrying
  `struct vif_entry_notifier_info`: a VIF index, a table id, the device and the
  VIF's flags. This is the only way to resolve an index, because `mr_table` is
  private to ipmr and the MFC notification carries indexes alone.
- `FIB_EVENT_ENTRY_ADD` for a new MFC entry, `FIB_EVENT_ENTRY_REPLACE` for a
  changed one (`ipmr_mfc_add()` updates in place and emits REPLACE against the
  same pointer), and `FIB_EVENT_ENTRY_DEL`, each carrying
  `struct mfc_entry_notifier_info` — the `struct mr_mfc *` itself and a table
  id.
- `FIB_EVENT_RULE_ADD` / `FIB_EVENT_RULE_DEL` for the multicast policy rules,
  with `ipmr_rule_default()` and `ip6mr_rule_default()` exported to tell the
  one the kernel installs itself from one an operator added.

Registration replays all of it. `mr_dump()` (in `net/ipv4/ipmr_base.c`) walks
the rules, then every VIF, then every MFC entry, so the learner's view is
complete from load rather than from the first change — and the VIFs arrive
before the entries that index them, which is what makes a single ordered queue
enough.

The chain is **atomic** (`atomic_notifier_call_chain`) and every `mr_*` caller
asserts RTNL. So the handler runs in process context, holding RTNL, and may
not sleep. That decides the whole locking design; see below.

`mlxsw` is the upstream precedent for consuming this, in
`drivers/net/ethernet/mellanox/mlxsw/spectrum_router.c` and `spectrum_mr.c`,
and the pattern here is its pattern: hold the mfc with `mr_cache_hold()` and
the device with `netdev_hold()` in the notifier, defer to a work item, set
`MFC_OFFLOAD` on success, and fold hardware counters into the entry
periodically. The code is not copied; the shape is.

## The eligibility contract

What the hardware may be asked to replicate. Everything outside this is
forwarded by `ip_mr_forward()` in software, exactly as it is today, and
`/proc/cdx_flowtable` names the clause that turned it down.

**The table.** The default multicast routing table only, which is the one
`ipmr_rules_init()` and `ip6mr_rules_init()` create and install the kernel's own
rule for. **The two families do not use the same id, and the names invite the
opposite conclusion**: IPv4's is `RT_TABLE_DEFAULT`, 253, while IPv6's
`RT6_TABLE_DFLT` is `#define`d to `RT6_TABLE_MAIN`, which is `RT_TABLE_MAIN`,
**254** (`include/net/ip6_fib.h`, `include/uapi/linux/rtnetlink.h`). So a `table=`
of 253 in an IPv4 row and 254 in an IPv6 one are both the default. An entry in
any other table is `refused-table`.

**Policy rules.** A multicast policy rule that is not the kernel's own default
can send a stream to a table this learner does not read. A hardware entry
matches at the classifier and is never offered to the rule that would have
redirected it, so one such rule anywhere in a family keeps **every** routed
group of that family in software: `refused-policy`. The count is per family and
the registration dump makes it right from load.

**The group.** A specific source and a specific group. `INADDR_ANY` /
`in6addr_any` as the origin — and the `(*,*)` form ipmr also carries — is
`refused-wildcard`, because the classifier composes an external *hash* over the
source and a masked field cannot match: a wildcard changes the hash rather than
widening it. A group outside `224.0.0.0/4`, or `224.0.0.0/24`, or an IPv6 scope
at or below link-local, is `refused-scope`. The backend refuses those too; the
test is mirrored here so `/proc` says `refused-scope` rather than
`refused-failed` four retries later.

**The ingress.** The parent VIF must be a plain interface — no `VIFF_TUNNEL`,
no `VIFF_REGISTER`, no `MIFF_REGISTER`, because a PIM register VIF is a
software tunnel to the rendezvous point and an IPIP VIF encapsulates on egress,
and neither is a port. Its device must resolve to exactly one physical CDX
port, directly or through at most two stacked 802.1Q VLAN devices. A bridge
cannot be an ingress: it is many ports and the key is one. A bridge *port*
cannot either, and for the opposite reason — its frames go to the bridge's
receive handler and never reach a VIF above it, so a VIF naming one describes
traffic that does not exist. A ppp device likewise. All of these are
`refused-ingress`.

The classifier key includes the port but not its VLAN tag, and the
per-listener rebuild strips whatever L2 the frame arrived with, so a VLAN
device above a port keys on the port. The tag count is kept anyway, because the
counter fold has to subtract the framing it represents.

**The thresholds.** Every oif must be at threshold 1. `ip_mr_forward()`
forwards out VIF `i` when `ttl > ttls[i]`; the hardware forwards when the TTL
is at least 2, because the parser refuses 0 and 1. Those two agree for
threshold 1 and for nothing else, so a scoped threshold is a decision the
classifier cannot express and the group stays in software:
`refused-threshold`. A `ttls[i]` of 255 is not an oif and is skipped.

**The listeners.** Each oif device is resolved as follows.

- A physical CDX port is itself, with the tags accumulated above it.
- An 802.1Q VLAN device is the port beneath it plus its tag, up to the two a
  rule can describe; a QinQ pair is two tags, outermost first as the wire
  carries them. 802.1ad is declined for the reason `ft_bridge_vlan()` gives:
  the kernel describes no selector for that tag and the hardware would be asked
  to reproduce it blind.
- A bridge, plain or vlan-aware, is its ports. Which ports is what
  `br_dev_xmit()` decides: a group with an MDB entry goes to
  `br_multicast_flood()` and therefore to exactly that entry's port group, and
  everything else to `br_flood()` and therefore to every port carrying
  `BR_MCAST_FLOOD`. The first of those is read from the bridged learner, which
  mirrors the MDB already; the second is read from the ports directly. Each
  port's egress tag comes from `ft_bridge_vlan()` applied to the stack
  accumulated above the bridge, which is the shipping `br-lan.N` shape: the
  bridge forwards within the VLAN the frame already carries and the port's own
  membership decides tagged or untagged.
- Anything else — a bond, a MACVLAN, a ppp device, a tunnel — is refused.

**A listener is its whole framing, not its port.** One port carries as many
copies of a group as it has distinct tag stacks — two oifs that resolve to the
same port with different tags are two listeners and both are programmed —
and the same stack twice is one copy and collapses. Nothing under
`cdx_mc_group_add()` identifies a member by its device: each listener gets its
own external-hash entry built from its own encapsulation, `members[]` is
indexed by position, and the name copied into `if_info` is for the query dump.
The two name lookups that exist, `Cdx_GetMcastMemberId()` and
`mcast_member_by_name()`, are on the FCI mutators and are never reached from
this path.

The same rule decides what "back the way it came" means, and it is the rule
the unicast path has used since the IPv6 increment. `ft_parse()` refuses a
flow that re-enters its ingress port only when the two tag stacks match,
because differing stacks are ordinary routing between VLANs carried on one
link; and the hardware demonstrably enqueues back to the port a frame arrived
on — the hairpin double-NAT case is measured at full rate in both directions
on one port ([IPv6 guide](flowtable-ipv6.md)). So a group whose iif is
`eth3.10` and whose oif is `eth3.20` is carried, and one whose oif is `eth3.10`
is not. Unicast additionally lets full NAT make an identical-stack hairpin a
distinct path; a group has no NAT, so identical is refused outright.

**The residual that carries, stated rather than discovered.** The classifier
key names a port and no VLAN, so an entry whose iif is `eth3.10` also matches
the same `(S,G)` arriving on `eth3` untagged or on `eth3.20` — and replicates
it as though it had arrived on `eth3.10`, where `ip_mr_forward()` would have
counted `wrong_if` and dropped it. This is inherent to keying on the port and
predates the rule above: it exists for any VLAN-device iif. What the rule adds
is one more reachable shape of it — a stream injected on a VLAN that is also
an oif is replicated back onto that VLAN, once. It cannot amplify: a replica
is transmitted, not re-classified, so one frame in is always N frames out.
Nothing in the adapter can narrow it, because the decision is made by a key
the parser composes before any table is consulted.

Two further rules, both `refused-listener`:

- **A bridge with any port the hardware cannot carry is refused whole.** A
  matched frame never reaches the bridge, so a port left out of the hardware
  set does not fall back to software — it stops receiving. This is the
  backend's all-or-nothing rule applied one level up. The bridged learner keeps
  the same rule from its own side, so its port set is safe to read: it records
  a member it cannot carry rather than dropping it, and `ft_mc_bridge_ports()`
  refuses such a membership outright rather than handing back the carried
  subset — which would look, from here, exactly like a complete one.
- **A listener whose port and tags both equal the ingress's is refused**, as is
  a parent VIF named as its own oif.

At most `CDX_MC_MAX_LISTENERS` listeners in total, which is eight — counted in
copies rather than in ports, since one port can be several of them. An oif
whose VIF has been removed is dropped rather than refused, because what is left
is a shorter replication list; an empty one is `refused-listener`.

**The host.** `ip_mr_input()` delivers locally as well as forwarding when the
ingress interface has joined the group — `ip_route_input_mc()` asks
`ip_check_mc_rcu()` on the input device, and IPv6 asks the idev's own list — and
a hardware entry replicates to ports without the frame ever reaching the CPU.
Such a group is `refused-host` rather than carried with a starved local
listener, which is the bridged learner's answer to the same question. Neither
check is exported, so the learner walks `__in_dev_get_rcu(dev)->mc_list` and
`__in6_dev_get(dev)->mc_list` under RCU.

**The key.** One address pair, one owner; see the next section.
`refused-contested`.

**Retries.** Four, then `refused-failed`. A failure is not permanent — a port
that lost carrier gets it back — but retrying forever against a group that
cannot be carried would spin the worker. Anything that could change the answer
resets the count.

## The shared key namespace

The classifier keeps one group id and one root entry per address pair:
`GetMcastGrpId()` matches `(saddr, daddr)` and refuses a second. The ingress is
reported back rather than compared, so even two ingresses for one `(S,G)` are
one entry.

Two learners now compose keys into that one space, and they can collide in
three ways: a bridged group and a routed group for the same `(S,G)`; two
bridged groups on different bridges; and two MFC entries with the same `(S,G)`
on different iifs, which `rhltable` permits because `ipmr_cache_find_parent()`
filters by parent after the hash.

The answer is a register — `ft_mc_claim_take()` / `ft_mc_claim_give()` — that
each learner consults before it installs and releases when it stops carrying a
key. It is a leaf: a spinlock taken while no other lock of this module is held,
so it orders against nothing. That is what makes it shareable. The alternative,
each learner reading the other's list, would need `ft_mc_lock` and `ft_mr_lock`
nested in some order, and the routed worker already takes `ft_mc_lock` while
holding neither.

Whoever gets there first wins; the other reports `refused-contested` and waits.
Handing a key back wakes both learners, because the refusal it caused is now
stale and nothing else would ever look again.

**The bridged learner's traffic hook is unaffected by any of this, and that is
worth saying because it looks as though it should not be.** That hook stays
registered while some bridged membership is still waiting for a source, and a
routed group installed for the same group address does not end that wait — but
it also cannot starve it, because the two never see the same frames. A routed
group's ingress is a physical port that is not a bridge port (a bridge port is
`refused-ingress`, since its frames go to the bridge's receive handler and
never reach a VIF), and a bridged group's traffic arrives on a bridge port. The
hook's cost is bounded by the bridged learner's own state and nothing here
changes it.

**The two listener sets are not merged, and that remains open.** A group that
is both bridged and routed on one box is a real configuration — an IPTV VLAN
bridged to some ports and routed to others — and what it deserves is one
hardware group with the union of the two listener sets. What it gets is one of
them carried and the other in software, which is correct but not optimal. It is
recorded in `ISSUES.md` rather than guessed at here, because merging means
deciding which learner owns the retirement of a listener the other contributed,
and neither of them has the state for that today.

## Locking

Three rules, and `tools/host_tests/test_mroute_learner.py` greps the source for
each of them.

**The handler only queues.** The FIB chain is atomic and every `mr_*` caller
asserts RTNL, so `ft_mr_fib_event()` runs in process context under RTNL and may
not sleep. It takes a reference on what the worker will need — `mr_cache_hold()`
for an entry, `dev_hold()` for a VIF's device, because by the time the worker
runs the entry may be deleted and the device unregistered — allocates its queue
node with `GFP_ATOMIC`, appends under a spinlock and schedules the worker. A
failed allocation is counted in `mroute_lost` and provokes a full re-derivation,
which recovers a lost VIF, rule or replace; a lost delete is not recoverable
that way and is stated as a bounded failure mode rather than papered over. It
is never a use-after-free: the group's own `mr_cache_hold()` keeps the entry
alive, so the worst case is a stale hardware group, retired when a port it
names goes away or when the adapter unloads.

**The worker holds nothing across the transaction.** `/proc` takes
`cdx_ft_begin()` and then `ft_mr_lock`, so the reverse order would close a cycle
with it; and `cdx_ctrl_lock_with_rtnl()` states the other half outright — never
wait for RTNL or the control mutex while holding the other. So one pass is:
take `ft_mr_lock`, choose a dirty group, release it; take RTNL, derive the whole
decision into a plan with a device reference of its own for every device in it,
release RTNL; take the transaction, call the backend, release it; take
`ft_mr_lock` again and record what happened. The delayed counter fold takes the
transaction *and then* `ft_mr_lock`, which is `/proc`'s order and therefore the
only one either may use.

**The two learners never nest their locks.** `ft_mr_lock` is never taken while
`ft_mc_lock` is held and `ft_mc_lock` is never taken while `ft_mr_lock` is held.
The routed worker takes `ft_mc_lock` briefly, under RTNL and with its own lock
released, to copy a bridge's port set; the bridged side never reaches into this
learner at all — the MDB handler only calls `ft_mr_kick()`, which sets a flag
and schedules.

**Dependencies and retirement.** The same classes the bridged learner has, one
family over:

| What changed | How it arrives | What happens |
| --- | --- | --- |
| The MFC entry deleted | `FIB_EVENT_ENTRY_DEL` | retired, `MFC_OFFLOAD` cleared, the mfc put |
| Its parent or thresholds | `FIB_EVENT_ENTRY_REPLACE` | re-derived; a changed ingress is a delete and an add, because the port is part of the key and `cdx_mc_group_replace()` refuses a changed one |
| A VIF added or removed | `FIB_EVENT_VIF_*` | every group of that family re-derived: an index only means anything against the table it indexes |
| A policy rule | `FIB_EVENT_RULE_*` | the family's count moves and every group re-derived |
| A port down or unregistering | the netdev chain, beside `ft_mc_device_gone()` | references released synchronously — one still held when `netdev_wait_allrefs()` starts spinning is a device that never finishes unregistering — and the group re-derived |
| A port coming back up | the netdev chain | re-derived; nothing else would ever reconsider a refused group, because the MFC entry does not change and no frame re-offers it |
| A bridged membership on a bridge some group expands through | the switchdev chain | the routed worker is kicked; the second set-top box joining on a second port is the case, and the group grows from one listener to two through `cdx_mc_group_replace()` |
| The bridge's VLAN configuration or filtering | the switchdev chain | kicked and re-derived |
| A hardware key handed back | the shared register | both learners kicked |

## Standard-tool surfaces

The house rule is that state and statistics surface through the tools an
operator already has, and that `/proc/cdx_flowtable` is the diagnostic beside
them rather than the only door.

**`MFC_OFFLOAD`.** Set on `mfc->mfc_flags` after a successful install and
cleared on retire, which `mr_fill_mroute()` turns into `RTNH_F_OFFLOAD` and
`ip mroute show` prints as `offload`. ipmr writes `mfc_flags` under RTNL, from
`ipmr_mfc_add()`, so the learner takes RTNL for that one store rather than
racing a read-modify-write with it — which is why it is written outside the
derivation, where RTNL is already held. It is cleared *before* the
`mr_cache_put()` that may free the entry through RCU.

**The counters.** `mfc_un.res.pkt`, `.bytes` and `.lastuse`, set to the
hardware's absolute values the way mlxsw does. There is no double counting: the
software counters stay at zero for an entry the CPU never sees. The bytes are
restated into the kernel's units first — `ip_mr_forward()` counts `skb->len`,
which is the L3 packet, and the classifier counts the L2 frame it matched, so
the ingress framing comes off per packet exactly as `ft_l2_overhead()` takes it
off a flow's. The fold runs on a delayed work of its own every five seconds and
again on every `/proc` read, so the two surfaces never disagree and a daemon
polling `SIOCGETSGCNT` sees activity within one interval without anybody
reading `/proc` at all.

The effect is that `ip mroute show` prints `offload`, `ip -s mroute` shows
traffic the CPU never handled, and `igmpproxy` or `pimd` see their entries
staying alive through the ioctl they already use — which matters, because a
daemon that prunes on inactivity would otherwise tear down exactly the groups
the offload is carrying.

**`/proc/cdx_flowtable`.** A summary —

```
mroute_groups 2
mroute_installed 1
mroute_refused 1
mroute_install_errors 0
mroute_policy_rules 0
mroute_lost 0
```

— and one row per group:

```
mroute family=4 table=253 group=239.8.1.5 src=10.0.0.52 in=eth4 oifs=eth3 \
    listeners=eth3/0 state=installed packets=1500 bytes=795000
```

`oifs` names the VIF devices the kernel listed; `listeners` names the physical
ports and tags the hardware was actually given, which is where a bridge oif
becomes several. The states are `installed`, `pending`, and the ten refusals
above, each distinct so an operator can tell them apart. `mroute_policy_rules`
is the one most likely to be needed: a single non-default ipmr rule keeps a
whole family in software and nothing else on the box would say so.

## Deliberately excluded

- **Multicast router ports.** `br_multicast_flood()` copies to a bridge's
  router ports as well as to the port group, and this listener walk does not.
  A bridge with a downstream multicast router would under-replicate. There is
  no exported way to ask a bridge for its router ports; the switchdev chain
  emits `SWITCHDEV_ATTR_ID_PORT_MROUTER` and tracking that is a separate piece
  of work. `ISSUES.md` carries it, because under-replication is silent and that
  makes it a gap rather than a scoping decision.
- **Other multicast routing tables, and policy routing.** Refused rather than
  followed, and refused for the whole family, because a hardware entry matches
  before any rule could redirect it.
- **`(*,G)` and `(*,*)` entries.** The classifier's key has no wildcard to
  offer. An `igmpproxy` or `smcroute` deployment installs `(S,G)` entries on
  the NOCACHE upcall, so this is not the shape they produce in practice — but
  a `(*,G)` rule that never resolves to a specific source is carried in
  software for its whole life.
- **Tunnel and register VIFs.** PIM-SM's register VIF is a software tunnel and
  an IPIP VIF encapsulates on egress; neither is a port.
- **A bridged ingress.** The key names one port.
- **Merging with a bridged group for the same `(S,G)`.** Open; see above.
- **The Wi-Fi path.** A VAP is not a CDX physical port and a routed group's
  listener must be one. Wire-to-Wi-Fi multicast replication would go through
  the VWD path, which is a different encoder.

## The consumer contract

There is none, again, and for a different reason than the bridged learner's.
There the control plane was the bridge itself; here it is a routing daemon, and
the deployment has to have one — but whichever one it has needs nothing from
ASK.

`igmpproxy`, `omcproxy`, `smcroute` and `pimd` all do the same two things: hold
an `MRT_INIT` socket, and write `(S,G)` entries at threshold 1 into the default
table. `igmpproxy` and `smcroute` write theirs in response to the NOCACHE
upcall, `smcroute` also for a static rule, and `pimd` after a join has
propagated. Every one of those is inside the contract above. Nothing has to be
configured, patched or packaged on the ASK side, and nothing in the adapter
names any of them.

**Which one a product ships is a packaging decision outside this repository.**
The OpenWrt build already enables `KERNEL_IP_MROUTE`; it selects none of
`igmpproxy`, `omcproxy` or `smcroute` today, so a routed-multicast deployment
would start by adding one to the image. That belongs with the consumer, the
same way the flowtable's own `flow_offloading_hw` does — the kernel side is
here and the choice is there. The meta-ask test image carries `smcroute`
because the tests need a real consumer writing real MFC entries, not because
the product does.

## Tests

**Host** — `tools/host_tests/test_mroute_learner.py` and `mroute_learner.c`,
in the shape of the bridged pair. It compiles the decision functions out of
`cdx/ask_flowtable.c` against stubs and drives every clause of the contract:
each refusal, a VLAN-device iif resolving to its port, an oif expanded through
a VLAN device, through a plain bridge on the flood set and through a
vlan-aware bridge on an MDB port set, the listener ceiling, a listener equal to
the ingress, a local membership, and what the chain's events do to the group
list — an add that creates, a replace against the same pointer that re-derives
rather than duplicating, a delete that marks for retirement, VIF adds and
deletes, and a rule count that does not wrap when a delete arrives without its
add.

The rest of that file is grep over the source, because the three ordering rules
cannot be observed from a passing test: that the FIB handler allocates
`GFP_ATOMIC` and takes no mutex, that neither `ft_mr_lock` nor RTNL is ever held
across `cdx_ft_begin()`, that the two learners' mutexes are never nested, that
every reference has exactly one release path, and that `MFC_OFFLOAD` is cleared
before the reference that keeps the entry alive goes.

**Rig** — `tools/tests/test_mcast_e2e.py`, which grew a routed section beside
its bridged one. The DUT routes rather than bridges, which is its shipping
configuration, and `smcroute` writes the MFC entries. Five cases: IPv4 and IPv6
to the LAN port, IPv4 to a VLAN sub-interface on it, IPv4 to a bridge over it
with snooping off, and **two oifs on the one LAN port — untagged and tagged**.

That last one is the measurement `ISSUES.md` A158 has been waiting for. The
board has five ports and two with carrier, one of which is every group's
ingress, so a second listener has to be a second tag stack on the one port
left; identifying a listener by its framing rather than by its device is what
makes that expressible. It counts the two copies separately, which is what
discriminates replication from one copy seen twice — the socket joined on the
parent NIC receives the untagged copy and only that one, because the tagged
copy is demuxed to the sub-interface where nothing has joined — and then drops
one oif and requires the other to survive, which is the chain swap.

Six oracles each, and the last two are ones a bridged case cannot produce:

1. `ip mroute show` reports `offload` against the entry.
2. `/proc/cdx_flowtable` has an `mroute … state=installed` row.
3. The DUT's CPU does not see the stream — the SDK driver's own software RX
   counter on the ingress port, which excludes the hardware's.
4. The LAN VM receives at least 95%.
5. **The replicas carry the DUT's egress MAC as their Ethernet source and a
   TTL one below the sender's.** A bridge would have forwarded the frame with
   the sender's MAC and the TTL untouched, so this is what tells *routed* from
   *bridged* — and it is the one assertion that proves `TTL_HM_VALID` and the
   listener's header rebuild are doing what this document claims.
6. `ip -s mroute` shows the traffic, which is the counter fold: the software
   counter is zero for an offloaded entry, so a number there is the
   classifier's.

Teardown is an assertion too — removing the route has to take the hardware
group, the `/proc` row and the kernel's flag with it.

## Proved on hardware

Flowtable boot, KASAN image, 2026-09-21. The DUT routes between its WAN and
LAN ports — its shipping configuration, no bridge — and `smcrouted` writes the
MFC. Streams are 1500 frames of 512 bytes at 500 pps from the orchestrator,
TTL 64. The five cases of `test_routed_to_*` in `tools/tests/test_mcast_e2e.py`
all pass; the numbers below are from those runs and from a stepwise run of the
same path with every counter read by hand.

| What | Result |
| --- | --- |
| IPv4 `(S,G)` to the LAN port | `installed`; the classifier's own entry counted **1500 of 1500** |
| Frames reaching the DUT's CPU, group installed | **none of the stream.** The ingress port's software receive counter moved by 38 across the window, which is the segment's background chatter; eth3 transmitted 1500 with a software transmit delta of **0** |
| Replica source MAC and TTL at the listener | source `e8:f6:d7:00:01:13`, which is the DUT's LAN port, and **`ttl 63`** from a sent 64. The two together are what say the FMAN routed the frame rather than bridging it |
| `ip mroute show` reports `offload` | yes — `Iif: eth4  Oifs: eth3  State: resolved offload` |
| `ip -s mroute` packet count against the stream | **1500 packets, 810000 bytes** against the classifier's 831000: the ingress framing restated at 14 bytes a packet, exactly |
| IPv6 `(S,G)`, the mc6 encoder | passes, with `hlim 63` in place of the TTL |
| Oif a VLAN sub-interface — tag on the wire | `listeners=eth3/244`; **1488 of 1500** captured on the LAN VM's own sub-interface, so the tag the entry inserts is the one the peer demultiplexes on |
| Oif a bridge, snooping off — flood set | passes; the bridge's one flood-enabled port becomes the one listener |
| Two oifs on one port, untagged and tagged — both copies counted (A158) | passes; the row names **two** listeners, `eth3/0,eth3/244`, and the two copies are counted separately |
| One of those two dropped — the chain swap (A158) | passes; deleting the VLAN device withdraws its VIF and the group is re-derived onto the remaining listener without leaving hardware |
| A non-default ipmr rule present | measured: the group goes to **`refused-policy`** and out of hardware the moment `ip -4 mrule add iif eth4 lookup 199` lands, and is readmitted when the rule is withdrawn |
| The route removed | group retired, `/proc` row gone, `offload` gone |
| KASAN, lockdep, kmemleak across every run above | **no reports** |

Two clauses of the contract are not reachable from this rig and are covered by
the host harness alone. A **threshold above 1** needs a daemon that writes one,
and every daemon in the contract writes 1. **`refused-host`** needs the box to
have joined the group on its own ingress interface, which nothing here does.
`refused-contested` is likewise host-only: it needs the bridged learner to hold
the same address pair, and the bridged rig cases cannot run (see `ISSUES.md`).

One number is worth carrying forward because it is the design working rather
than a shortfall. `ip -s mroute` lags the hardware by up to the fold's
five-second interval, so a reader who wants it exact reads
`/proc/cdx_flowtable` first — that read folds. A test that asked the kernel
first saw 88% of a three-second stream and looked like a broken fold.

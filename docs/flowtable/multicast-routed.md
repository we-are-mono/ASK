# Routed multicast without CMM

Roadmap item 7, second half, and the last item on the CMM-retirement list. The
[bridged learner](multicast.md) reads the bridge's MDB; this one
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
- A bridge, plain or VLAN-aware, is its complete multicast data egress set.
  Kernel patch 161 exports `br_multicast_list_ports()`: under RTNL and the
  bridge's multicast lock it reads the current VLAN context, querier, MDB and
  protocol-specific router list. With snooping and a querier, copies go to the
  applicable MDB port group **and multicast router ports**; without an MDB
  entry they go to router ports alone. Without active snooping/querier they
  follow `BR_MCAST_FLOOD`. A port present in both sets receives one copy.
  Source filters, forwarding state and VLAN egress membership apply before
  returning the set. Each selected port's tag stack still comes from
  `ft_bridge_vlan()`, including the `br-lan.N` shape.
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
on one port ([IPv6 guide](ipv6.md)). So a group whose iif is
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

- **A bridge with any selected destination the hardware cannot carry is
  refused whole.** A matched frame never reaches the bridge, so omitting a
  selected Wi-Fi or other unsupported router/listener would stop its delivery.
  Ports outside the copy set do not prevent offload. The kernel snapshot
  refuses an overflowing set instead of returning a truncated one, and refuses
  MST and multicast-to-unicast copies, which this port-only API cannot describe.
- **A listener whose port and tags both equal the ingress's is refused**, as is
  a parent VIF named as its own oif.

At most `CDX_MC_MAX_LISTENERS` listeners in total, which is eight — counted in
copies rather than in ports, since one port can be several of them. An oif
whose VIF has been removed is dropped rather than refused, because what is left
is a shorter replication list; an empty one is `refused-listener`.

**The MTU.** No copy may leave by a path narrower than the parent VIF. Each
listener's entry ends in `ENQUEUE_PKT`, which fragments a replica larger than
its MTU, and nothing in front of it hands such a packet to Linux. Linux would
not fragment it: `ip6mr` answers an oversized IPv6 replica with Packet Too Big,
and `ipmr_queue_xmit()` drops an IPv4 one with DF set. So a group is carried
only while nothing the parent VIF can deliver is larger than the smallest MTU a
copy leaves by. That MTU is taken over the whole path: the oif, each VLAN
device below it, the port, and for a bridge oif the bridge and each chosen
port. A copy that collapses into another oif's keeps the narrower of the two
paths. IPv6 is compared in IPv6 MTUs, the value a link is told and the one a
Packet Too Big quotes, which is the bound the unicast IPv6 path uses
([IPv6 guide](ipv6.md#packets-larger-than-the-path)). Otherwise the group is
`refused-mtu`. Neither an MTU change nor the IPv6 MTU sysctl raises an MFC
event, so the device change kicks the worker and the five-second refresh
catches the sysctl. See [the bridged contract](multicast.md#the-eligibility-contract)
for why this is an admission bound rather than a check in hardware.

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
nested in some order. The shared register avoids that dependency.

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
The routed worker reads the kernel's bridge snapshot under RTNL, with its own
lock released. The bridged side's MDB handler only calls `ft_mr_kick()`, which
sets a flag and schedules.

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
| A device MTU | `NETDEV_CHANGEMTU` | every group re-derived, installed ones included; a copy narrower than its parent VIF takes the group out as `refused-mtu` |
| The IPv6 MTU sysctl | nothing reports it | the five-second refresh re-derives every group, which finds it |
| A bridged membership on a bridge some group expands through | the switchdev chain | the routed worker is kicked; the second set-top box joining on a second port is the case, and the group grows from one listener to two through `cdx_mc_group_replace()` |
| The bridge's VLAN configuration or filtering | the switchdev chain | kicked and re-derived |
| A multicast router port, snooping, flood flag or forwarding state | switchdev attributes | kicked and re-derived from the live snapshot; patch 161 emits router refreshes on either protocol's transition, even while the other remains a router |
| Querier timers or per-VLAN snooping state without a notification | the existing five-second worker | re-derived, including refused groups; unchanged forwarding plans leave their hardware chains intact |
| A hardware key handed back | the shared register | both learners kicked |

A replacement that fails is withdrawn completely: retaining the old chain
could omit a new router port indefinitely. Software carries the whole stream
while the bounded admission retries run. Periodic refresh preserves the retry
ceiling; control-plane changes reset it. Teardown drains the refresh, worker,
and any refresh rearmed by an in-flight worker before freeing groups.

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

**The counters.** `mfc_un.res.pkt`, `.bytes` and `.lastuse`, with the
hardware's count *added* to them. They are the CPU's counters too:
`ip_mr_forward()` counts the packets that resolve an entry, every one before
the worker installs it, and all of them while a refusal keeps the group in
software. A hardware group counts from zero each time one is added, so writing
its total over the entry's — mlxsw's way, which works there because its counter
belongs to the route from creation and counts trapped packets too — erased the
first kind and sent the count backwards on every reinstall. The fold adds what
the classifier matched since the last fold instead, and the entry reads the
CPU's count plus the hardware's, never less than it did. The bytes are restated
into the kernel's units first — `ip_mr_forward()` counts `skb->len`, which is
the L3 packet, and the classifier counts the L2 frame it matched, so the ingress
framing comes off per packet exactly as `ft_l2_overhead()` takes it off a
flow's. The fold runs on a delayed work of its own every five seconds and again
on every `/proc` read, so a daemon polling `SIOCGETSGCNT` sees activity within
one interval without anybody reading `/proc` at all. What the hardware matched
after the last fold is not carried over when a group leaves hardware: at most
one interval, and the count still never goes back. `/proc`'s own row reports the
present hardware group's raw L2 count, which starts again with each group.

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
becomes several. The states are `installed`, `pending`, and the refusals above,
each distinct so an operator can tell them apart. `mroute_policy_rules`
is the one most likely to be needed: a single non-default ipmr rule keeps a
whole family in software and nothing else on the box would say so.

## Deliberately excluded

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

That last case supplied A158's first replication measurement. The board has
two ports with carrier; that run used WAN ingress and two differently framed
LAN listeners. The later A158 completion below also sends a tagged replica
back through the physical WAN port, proving both transmit paths. Identifying
a listener by its framing rather than just its device makes these topologies
expressible. The first case counts the two copies separately, which is what
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
6. `ip -s mroute` shows the traffic, which is the counter fold: the CPU never
   forwards an offloaded stream, so what the entry's count gains across it is
   the classifier's.

Teardown is an assertion too — removing the route has to take the hardware
group, the `/proc` row and the kernel's flag with it.

`tools/tests/test_mcast_member_mtu.py` proves the MTU clause on the wire, for
both families. The listener is a 1400-byte VLAN device behind a 1500-byte
ingress. The group reads `refused-mtu`. Small datagrams arrive through
software. 1448-byte ones, with DF for IPv4, arrive neither whole nor as
fragments, and the microcode's fragment counters do not move. Raising the
listener to 1500 re-derives the group into hardware through the MTU change
alone. Full 1500-byte datagrams then arrive whole with hop count 63, the
classifier counts them, and the fragment counters still do not move. Lowering
it again takes the installed group back out. For IPv6, the IPv6 MTU sysctl
alone does the same within the refresh interval.

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

## A189 follow-up — 2026-09-21

Router ports are included by kernel patch 161 and the routed bridge expansion.
The snapshot reads existing state directly, so a module load needs no router
notification replay and keeps no additional device references or event cache.
IPv4 and IPv6 router sets and per-VLAN contexts remain distinct. It also fixes
router-only delivery with no MDB, and the flood decision when no querier exists.

Host regressions execute the snapshot with IPv6 enabled and disabled and run
the routed worker through unchanged refreshes, listener changes, replacement
failure, retry exhaustion/recovery and teardown with a timer rearm. The full
host suite and KASAN image build are recorded in `ISSUES.md`.

DUT validation of the bridge/router semantics remains pending. The image was
rebuilt, staged and booted for A158 below, but those plain VLAN-oif cases do not
exercise this change. The earlier hardware results above predate A189. A future
rig check should turn snooping and a querier on, disable multicast flooding on the LAN
bridge port, and toggle that port's multicast-router role while routing a group
with no MDB membership. Capture delivery and hardware counters, verify removal
and re-addition, then repeat with an overlapping MDB membership and IPv6.

## A158 hardware completion — 2026-09-21

`tools/tests/test_mroute_capacity.py` passed all four rig cases in **48.13 s**,
with no failures or skips, on the rebuilt KASAN flowtable image. Each shape
passed for both IPv4 and IPv6:

- **8 → 9 → 8 listeners.** Nine VLAN subinterfaces are available on the LAN
  port. Eight must install and each receive every sequence exactly once. Adding
  the ninth must withdraw the entire hardware group while all nine receive in
  software. Deleting the ninth DUT VLAN withdraws its VIF; eight must return to
  hardware and the ninth receiving VLAN must become silent.
- **Two physical egress ports.** The source enters WAN untagged. One tagged
  copy leaves LAN and a differently tagged copy leaves WAN. The WAN receiver is
  an AF_PACKET socket on the existing orchestrator `wan3900` interface, so
  local-source IP rejection cannot hide a correctly received replica. Both
  `eth3/311` and `eth4/3900` received every sequence independently. This proves
  two physical transmit paths using the existing cables.

The initial run passed both listener-ceiling cases but received no WAN copy
on the proposed VLAN 320. A software-transmit probe then received **16/16**
untagged packets and **16/16** on VLAN 3900, but **0/16** on VLAN 320, locating
the limitation in the bench path. The final run uses the standing VLAN 3900;
its interface, addresses, routes and PPPoE service are not reconfigured.

The tests reserve LAN VLANs 311–319 and `198.18.158.0/24` for DUT oif
addresses. Each capture joins only its Ethernet multicast destination and
closes that socket membership at exit. Each test owns a separate smcrouted
identity and stops only that instance. An existing multicast workload prevents
admission rather than being removed. No CMM or FCI is used.

Each window sends 256 unique sequences at 200 packets/s, checks exact delivery
per receiving VLAN and no duplicates, verifies hop limit/TTL 63 and the DUT's
physical egress MAC, and compares `/proc`, MFC offload flags and software RX
counters. JSON artifacts record the packet results, route rows and counters.
All expected receivers got **256/256** unique sequences, with zero duplicate
or malformed copies. The ninth receiver got zero while the group had eight
listeners, including after recovery. The 17 packet-oracle host tests also pass.

| Family | Window | Classifier packet delta | Software ingress RX | 1.28 s idle RX |
| --- | --- | ---: | ---: | ---: |
| IPv4 | Eight, initial | 256 | 3 | 3 |
| IPv4 | Nine, software | 0 | 261 | 4 |
| IPv4 | Eight, recovered | 256 | 4 | 3 |
| IPv4 | Two physical ports | 256 | 4 | 7 |
| IPv6 | Eight, initial | 256 | 5 | 4 |
| IPv6 | Nine, software | 0 | 260 | 3 |
| IPv6 | Eight, recovered | 256 | 4 | 5 |
| IPv6 | Two physical ports | 256 | 5 | 3 |

The nine-listener windows had `state=refused-listener`, an empty hardware
listener list and no MFC offload flag. Every other window had `state=installed`
and the offload flag. Route removal erased each group's row. Final inspection
found no A158 routes, VLAN devices or running test processes; the existing
`wan3900` remained present, both physical links were up and the agent was healthy.
No KASAN, UBSAN, BUG, WARN or lockdep reports appeared; taint remained the
out-of-tree-module baseline of 4096. This run did not perform a kmemleak scan.

Reproduction: build with `KASAN=1 make ask-image`, stage with `make stage-image`,
and TFTP boot with `ask.offload=flowtable` (that switch has since been removed;
every boot is a flowtable boot). The compressed image exceeded the
old 128 MiB U-Boot input bound; this boot used the temporary setting
`kernel_comp_size=0x10000000`, with no flash or saved-environment writes.
Set `ASK_WAN_IPERF_IP` to the orchestrator's current address and `ASK_WAN_IPV6`
if the source differs from `fc00:beef::99`. `ASK_MROUTE_WAN_IF` and
`ASK_MROUTE_WAN_VID` may select a different existing, transported WAN VLAN.

```sh
sudo env PYTHONPATH=tools ASK_WAN_IPERF_IP=10.0.0.232 \
  ASK_FLOWTABLE_ARTIFACTS=/tmp/ask-a158-hardware-20260921/run2 \
  /opt/askd-agent/venv/bin/pytest -c tools/pyproject.toml \
  tools/tests/test_mroute_capacity.py
```

Artifacts on `vision`: `/tmp/ask-a158-hardware-20260921/` contains build/stage
and boot logs, verified kernel/module build IDs, the initial failed run and WAN
path probe, final `run2` JSON/JUnit results, and post-test cleanup evidence.
The staged image and DTB hashes matched the build; loaded kernel, CDX and
ask_flowtable build IDs matched their ELF artifacts. Image SHA-256:
`d34bdd5b6a4e82e24a5c013be0f383113b55c43bc02a3585e2afd64e836f4f2c`.
The build passed with five existing forced-task/build-path warnings. A158 is
closed, and the DUT remains in flowtable mode on this tested image.

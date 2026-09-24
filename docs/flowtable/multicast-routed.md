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

So the two halves of the bridged learner collapse into one here. Nothing is
ever `pending-source`: the key and the listeners come from the entry, and a
group is refused the moment the routing daemon writes it. Traffic decides one
thing only, whether the firewall lets the stream go, so an accepted group is
carried once Linux has been seen forwarding its first copies; see
[what Linux forwarded](#what-linux-forwarded).

That is why it is a sibling rather than a modification. The state is different
(an MFC entry, not a `(bridge, br_ip)` membership), the lifecycle is different
(a kernel object with a refcount, not a switchdev object), the chain is
different (the FIB notifier, not switchdev), and the eligibility questions are
different (a VIF's flags, a threshold, a policy rule). What is shared is the
encoder underneath and, for a stream that is both bridged and routed, the
hardware group that carries it; see below.

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
port, directly or through at most two stacked 802.1Q VLAN devices — or be a
bridge, or one 802.1Q device above a VLAN-filtering bridge, which is the case
[the next section](#one-stream-both-learners) describes: the stream arrives on
a bridge port, and the entry rides the bridged group for it instead of
installing a root of its own. A bridge *port* cannot be an ingress — its
frames go to the bridge's receive handler and never reach a VIF above it, so a
VIF naming one describes traffic that does not exist. A ppp device likewise,
and QinQ above a bridge. All of these are `refused-ingress`.

The classifier key includes the port but not its VLAN tag, and the
per-listener rebuild strips whatever L2 the frame arrived with, so a VLAN
device above a port keys on the port. The tags themselves go into the group
description (`in_vlan`), and the root's `STRIP_ALL_VLAN_HDRS` validates and
strips exactly those, the way a flow's root does. Before that, the root
expected an untagged frame. A VLAN-device parent matched its key and then
fell back to Linux on every frame, and no rig case had a tagged ingress to
show it. The tag count is also what the counter fold subtracts per frame.

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

**The residual, and how the ingress tag closes it.** The classifier key names
a port and no VLAN. An entry whose iif is `eth3.10` used to match the same
`(S,G)` arriving on `eth3` untagged or on `eth3.20` too, and to replicate it
as though it had arrived on `eth3.10`, where `ip_mr_forward()` would have
counted `wrong_if` and dropped it. The root now validates the parent's own
tags. The same key untagged or on another VLAN matches, fails the strip, and
is excepted to Linux, which counts it `wrong_if`. One entry per key remains:
two parents on different VLANs of one port with the same `(S,G)` share a key
the classifier cannot tell apart, and the second is refused. The rule above
is unaffected: a copy is transmitted, not re-classified, so one frame in is
always N frames out.

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
`ip_check_mc_rcu()` on the input device, and IPv6 asks the idev's own list. The
same holds on the way out. `ip_mc_output()` loops each forwarded copy back to
the host when its output route is `RTCF_LOCAL`, which is when the host has
joined the group on the oif. `ip6_finish_output2()` does the same when
`ipv6_chk_mcast_addr()` finds the group on the output device. A hardware entry
replicates to ports without the frame ever reaching the CPU, so a group with a
host membership on its parent VIF or on any oif is `refused-host` rather than
carried with a starved local listener, which is the bridged learner's answer to
the same question. Any membership counts, whatever its source filter. Refusing
one the filter would not deliver costs only the offload. Neither check is
exported, so the learner walks `__in_dev_get_rcu(dev)->mc_list` and
`__in6_dev_get(dev)->mc_list` under RCU.

**The key.** A routed root is keyed on its port and address pair, and the key
names no VLAN. Two MFC entries for one `(S,G)` whose parents are two VLANs of
one port — `eth4` and `eth4.10` — are one classifier entry whose root can
validate only one of the two tag stacks. The first installed keeps it; the
other is `refused-contested`, and takes the key in the same worker pass the
first gives it up. See the next section for why this is the only collision
left.

**Retries.** Four, one per five-second refresh, then `refused-failed`. A
failure is not permanent — a port that lost carrier gets it back — but tried
again at once, in the same pass, nothing could have changed, and retrying
forever against a group that cannot be carried would spin the worker.
Anything that could change the answer resets the count.

**Linux forwards it.** A group the contract accepts is carried only once Linux
has been seen forwarding it to every oif, under the ruleset in force. Until
then it is `pending-confirm` and stays in software. See the next section.

## What Linux forwarded

The MFC says where ipmr and ip6mr would send a stream. It does not say whether
the firewall lets the stream go. A forward chain that drops the group toward an
oif is as much a part of the routing decision as the MFC entry, and fw4's
default from WAN to LAN is exactly that. A hardware entry replicates at the
classifier, where no netfilter hook runs again, so carrying the MFC as it stands
would forward what Linux drops.

**A copy has to be seen leaving.** The learner registers an observer at
`NF_INET_POST_ROUTING` for each family, at `NF_IP_PRI_LAST` and
`NF_IP6_PRI_LAST`, while any group of that family is watched. A forwarded
multicast copy reaches it only after passing `PRE_ROUTING`, `FORWARD` and every
earlier `POST_ROUTING` chain, filter and NAT alike. `ipmr_queue_xmit()` and
`ip6mr_forward2()` mark each copy `IPSKB_FORWARDED` / `IP6SKB_FORWARDED` and
send it through `NF_INET_FORWARD` to `dst_output()`. `ip_mc_output()` and
`ip6_output()` then run `POST_ROUTING` with the VIF as the output device. The
observer records the `(S,G)` and that device's ifindex against the group's
oifs, for a copy whose `skb_iif` is the parent VIF's. `skb_iif` is the device
ipmr saw the stream arrive on, a VLAN device or a bridge included. What every
packet pays there is one test of whether its destination is multicast. A
forwarded copy of a group then costs one hash lookup, and only its first
sighting per oif writes anything.

**Where it came from.** fw4's zone rules, like most forward rules, are keyed on
the input interface as much as the output one. So a confirmation holds for the
parent VIF it was made from. An MFC entry replaced with another parent and the
same oifs, such as a route added again from another inbound interface or an RPF
change under a PIM daemon, starts from nothing, and copies still in flight from
the old parent confirm nothing for the new one.

**What runs after it.** At an equal priority netfilter puts a hook registered
later ahead of the ones already there. So an nftables chain at priority
2147483647 created after the observer runs before it and is covered. One that
already existed when the observer registered runs after it. The observer
registers afresh whenever a family's first group appears. Such a chain can
still drop, queue or steal a confirmed copy. While one follows the observer on
that family's `POST_ROUTING`, its groups are `refused-filter`. Conntrack's
confirmation also sits at that priority. It is the kernel's own, registered
with no hook type, and drops a copy only when it cannot insert its entry, so it
does not count. No BPF program can be there at all: a netfilter BPF link
refuses the last priority, which it leaves to conntrack.

**All or nothing.** A root consumes every frame it matches, and no listener the
encoder expresses delivers to the CPU; the bridged learner's `refused-host` is
the same gap. An entry carrying only the confirmed oifs would therefore starve
an unconfirmed one that Linux still forwards to. So the group waits in software
until every MFC oif has been seen, and an oif the firewall drops toward keeps
the whole group there. An oif added to a carried group takes the group back
to software until it too is seen. Its other oifs keep their confirmations. A
group refused for another reason, such as a policy rule, a host membership or
its MTU, is watched all the same while Linux forwards it. It is carried as
soon as that reason goes.

**Which oif.** The VIF is what is confirmed, not the port: a bridge, or a VLAN
device above one, is seen as itself. A copy routed into a bridge then passes
the bridge's own `output` and `postrouting` hooks after the confirmation, so a
group with such an oif is `refused-filter` while any bridge hook is registered
there. CDX's own VWD hooks are not counted. A group routed *through* a bridge,
with its parent VIF on one, is confirmed the same way, from what ipmr forwards
once the bridge has handed the stream up, before its copies are published to
the bridged flow that carries them. That covers a bridge `input` chain on the
way up too.

**The ruleset.** Confirmations are good for the ruleset they were made under:
nftables' commit counter `init_net.nft.base_seq`, and the cursor
`init_net.nft.gencursor` the packet path reads rules through, which the commit
moves just after the counter. When either changes, every confirmation is taken
back and every group returns to software, so a drop rule added under a carried
group stops the stream rather than being bypassed. Nothing reports a commit,
so the pair is read every second while any group exists, as well as at every
worker pass and by the observer itself, which wakes the worker when it sees
the pair move. That second is how long a rule added under a carried group can
go unenforced. `mroute_ruleset_changes` counts the commits that took
confirmations back.

**Settling.** A commit goes on applying some of itself after it has moved the
pair: a new base chain's policy, element timeouts, and a concatenated (pipapo)
set's new contents, which become visible only after the transaction loop.
nf_tables' own commit mutex and busy mark are private to its pernet state, and
nfnetlink releases its subsystem lock before the batch runs. So kernel patch
148 adds a mark beside the pair in `struct net`. `net->nft.commit_applying` is
set just before the new `base_seq` is published, which orders it by that
release store. It is cleared with a release store once the set backends'
updates are in. `nft_commit_in_progress()` reads it with an acquire. It fits in
the padding after `gencursor`, so `struct net` does not grow, and the learner
reads it inline without depending on the nf_tables module. Read after the pair,
a clear mark means the commit that produced the pair is applied whole.

Re-arming first waits out the copies the observer has in hand, clears every
confirmation, and reads the pair. Confirmations start again once three things
hold: the pair has stood still for a second (`FT_MR_RULESET_SETTLE`), the
commit behind it is no longer applying, and a grace period has passed for
every copy judged before that. It then reads the pair once more. A commit
that takes longer than the second to apply is waited out. The learner looks
again every 100 ms until it is done. The second itself is hysteresis. It
bounds how often a run of commits moves a group in and out of hardware.
`mroute_ruleset_settled` says whether confirmations are being accepted.

**What a commit costs.** Every commit counts, including a set element added by
a daemon. For each routed group it costs one episode in software, and the
stream keeps flowing through the CPU meanwhile. The episode starts when the
commit is noticed, at most a second after it lands. It lasts the second of
settling, then until the next copy of the group per oif and one worker pass:
a little over one second of software forwarding. A further commit during the
episode starts the settling again. The settling also bounds the churn: however
fast commits arrive, a group goes in and out of hardware at most about once a
second, with two classifier operations and a few RTNL holds each time. This
is deliberately stricter than unicast. Linux never revokes a unicast
flowtable flow on a commit, only when the flowtable itself goes. A routed
multicast stream lives for hours, no conntrack timeout bounds it, and a
blocklist entry added for its source has to stop it.

**What it does not cover.** A confirmation proves that the ruleset forwards the
stream to that oif, not what it does to each packet:

- A rate limit, a quota, a counter, or a match that differs from one packet to
  the next stops applying once the group is carried, as it does for a
  flowtable flow.
- Verdicts that change without a commit are not followed:
  - ipset membership (`iptables-nft -m set`) and stateful xt matches;
  - set elements added by the datapath (`add @s`, `update @s`) or expiring
    by timeout;
  - `fib`-based rules after a route change;
  - an interface renamed, or moved between groups, under an `iifname`,
    `oifname`, `iifgroup` or `oifgroup` rule -- the parent VIF's name counts
    as much as an oif's, since a confirmation holds for its parent;
  - a table owned by a netlink socket (`flags owner`, not `persist`), which
    nf_tables releases when that socket closes, and every table, which it
    releases when its module is unloaded. Neither is a commit. Both only take
    hooks away, which loosens a verdict rather than tightening it, except
    across tables: a mark set in the table that went and tested by a drop in
    another. A carried group then keeps bypassing that drop until something
    else takes it back to software.
- A copy queued to userspace (NFQUEUE) before a commit and reinjected after
  the re-arm is observed under the new pair.
- Anything after `POST_ROUTING` is not seen at all: an nftables `netdev`
  egress chain, and a tc egress filter or action. Creating such a chain is a
  commit. The next copy is seen at `POST_ROUTING` all the same, and is dropped
  only in software after that.
- iptables-legacy tables are replaced with no generation a module can read, so
  a legacy rule change is followed only once something else takes the group
  back: an MFC change, a device change, or an nftables commit. iptables-nft is
  nftables and is followed.

## One stream, both learners

**The two learners do not share a key.** A routed root is keyed on its port and
address pair in the routed multicast tables, and its port is never a bridge
port. A bridged root is keyed on its port, its frames' Ethernet pair and the
address pair in [tables of its own](multicast-hardware.md#production-integration),
and its port always is one. No frame is a candidate for both, and the backend
keys a group on its whole classifier key rather than on the address pair, so
neither learner can take a key from the other. The address-pair register that
used to arbitrate between them (`ft_mc_claim_take()`) is gone. Each learner
refuses only its own collisions: two MFC entries on one port with different
tags (above), and two bridged flows that are one key on two VLANs
([bridged contract](multicast.md#the-eligibility-contract)).

**What they share is a stream.** An IPTV VLAN bridged to a set-top box and
routed to the rest of the house arrives on a bridge port. The bridge forwards it
to the box and, as a multicast router, hands it to the host on `br0.289`, where
ipmr routes it out of another port. That is one classifier key — the bridged
one — so it is one hardware group, carrying the union of the two sets: the
box's copy with the sender's Ethernet pair and hop count, ipmr's with the egress
port's address, the group's mapped destination and one hop fewer.

**Who owns what.** The bridged learner owns the group, as one of its flows,
because only its traffic hook knows the port, the Ethernet pair and the tag the
stream arrives with. An MFC entry whose parent VIF is a bridge, or one 802.1Q
device above a filtering bridge, installs nothing: the routed learner derives
it as usual, publishes its copies to the bridged learner as an `ft_mc_route`,
and reads back whether a bridged flow is carrying them (`installed`) or not yet
(`pending-bridged`, with the reason in the bridged row). Each learner keeps its
own copies — the bridge's come and go with its answer for the flow, a route's
with the MFC — and the group is replaced in place when either set changes. It
is retired only when neither learner names the flow: a set-top box leaving a
stream the house still routes leaves the routed copies in hardware, and a
route with no bridged listener at all names its stream's flow by itself, so
the flow is learned from the stream's first frame with no membership.

**Where the VIF sits decides what it receives.** `br_pass_frame_up()` hands the
host a frame only in a VLAN the bridge itself is a member of, untagged when that
membership is untagged and tagged otherwise. So `br0.289` receives VLAN 289 when
the bridge carries it tagged, and `br0` receives every VLAN it carries untagged.
A route counts only for the VLANs its VIF really receives, and only while the
bridge is a multicast router for the flow's family (`mcast_router 2`, or a
query heard from the host) — which the bridge's own answer for the flow says,
as `BR_MCAST_TO_HOST_ROUTER`: a bridge that is not one hands the host only what
the host itself joined, and a host membership keeps a flow in software
regardless. A route through a bridge that is not a router therefore forwards
nothing in Linux either, and carrying it would forward what Linux does not.

**The host's own copy.** Once the bridge hands a stream to a VIF, the hardware
has to account for the host's copy, not only the ports'. A bridged group whose
bridge VLAN a VIF receives is carried only together with the route that
forwards its stream. Without one — no MFC entry yet, which is how `igmpproxy` or
`smcroute` learn a source from the NOCACHE upcall, or one this learner refuses
— it is `refused-routed` and stays in software, where ipmr sees it. So the
routed learner also publishes where its VIFs sit on bridges (`ft_mc_tap`); a
mirror a lost notification invalidated says instead that they may be anywhere,
which keeps every such group in software until a resync completes. Before this,
the bridged learner ignored a bridge that was a multicast router, installed the
box's copy alone and starved ipmr: the routed half was silently lost.

**What does not merge**, each with its reason:

- A routed copy framed exactly like a bridged one — one port, one tag stack —
  would be two identical-looking entries the backend takes for a duplicate:
  `refused-listener`.
- The union has to fit `CDX_MC_MAX_LISTENERS`: `refused-listener`.
- Every routed copy has to fit the port the stream arrives on, which the bridge
  hands up whatever the bridge device's MTU: `refused-mtu` on the bridged row.
- A host membership on the parent VIF, or on an oif, is a local listener:
  `refused-host` on both rows.
- The same port, sender and source of a group on two VLANs of one bridge is
  one classifier key, and both flows stay `refused-contested`. `(*,G)` and
  `(S,G)` memberships of one group no longer contest anything: they are both
  reasons to ask the bridge about the same flow, and its answer combines them
  as it does per frame.

**The routed copy's hop.** A bridged root preserves the hop count, so a routed
copy in a bridged group decrements it in its own listener entry — `UPDATE_TTL`
or `UPDATE_HOPLIMIT` ahead of its header inserts, with a zero DSCP word — and
rebuilds Ethernet from the egress port. Per-copy L3 edits under `REPLICATE_PKT`
have not been measured on hardware; see
[the hardware notes](multicast-hardware.md#routed-copies-in-a-bridged-group).

**Locking.** The routed learner reaches the bridged one only through functions
that take `ft_mc_lock` themselves, called with `ft_mr_lock` released; what the
bridged learner reports back — carried or not, what it counted, the ingress
framing that count includes — sits under a leaf spinlock the routed learner
reads holding its own lock. The bridged worker never takes `ft_mr_lock`; it
kicks the routed worker when a route's answer changes. A route is freed by its
owner only after it is off the bridged learner's list, which clears every
pointer to it there.

**Counters.** A merged group's frames never reach ipmr, so what the bridged
group carrying the route matched is added to the MFC's counters, as a routed
group's own entry's is: the bridged refresh adds each interval's growth to the
route's count, which only grows while the route is published, and the routed
fold adds the route's growth to the MFC in ipmr's units, less the ingress tag
the bridged group reports. A daemon that ages routes by `SIOCGETSGCNT` sees the
stream flow, and the count never goes backwards when an entry is replaced or
two streams carry one route.

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
release RTNL; take the transaction, call the backend with the transaction
alone, take `ft_mr_lock` inside it to record what happened (`ft_mr_record()`),
and release both. The group keeps its hardware and its installed set until
then, so nothing else that takes the transaction ever meets it half-built,
and nothing that takes only `ft_mr_lock` under RTNL — the netdev events, the
egress mark — waits behind a hardware call. The delayed counter fold takes the
transaction *and then* `ft_mr_lock`, which is `/proc`'s order and therefore
the only one either may use. The bridged worker does the same with
`ft_mc_lock`: the MDB handler takes it under RTNL and never waits behind a
build either.

One caller does take the transaction under RTNL: the egress drain a DSCP
filter runs, under the RTNL `tc` took for it — RTNL then the transaction, the
order the flowtable's bind path already takes. It closes no cycle because the
only path that waits for RTNL while holding the transaction is the legacy FCI
command plane, sealed once the flowtable owns the hardware, and the worker,
which does wait for RTNL, never holds the transaction then. The drain never
waits for the worker either: a worker that has picked a group may well be
waiting for that same RTNL. So the drain rebuilds the group in place from the
spec its entry was built from, recorded whole beside it — ingress tags
included — with nothing to decide. The bridged learner's drain does the same
for its flows; see [bridged multicast](multicast.md).

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
| A port down or unregistering | the netdev chain, beside `ft_mc_device_gone()` | the group's references released synchronously and the group re-derived; an installed entry keeps its own hold on its ingress until the worker deletes it, because the backend deletes through that device, so unregistration waits only for the worker it scheduled |
| A port coming back up | the netdev chain | re-derived; nothing else would ever reconsider a refused group, because the MFC entry does not change and no frame re-offers it |
| A device MTU | `NETDEV_CHANGEMTU` | every group re-derived, installed ones included; a copy narrower than its parent VIF takes the group out as `refused-mtu` |
| The IPv6 MTU sysctl | nothing reports it | the five-second refresh re-derives every group, which finds it |
| A bridged membership on a bridge some group expands through | the switchdev chain | the routed worker is kicked; the second set-top box joining on a second port is the case, and the group grows from one listener to two through `cdx_mc_group_replace()` |
| The bridge's VLAN configuration or filtering | the switchdev chain | kicked and re-derived |
| A multicast router port, snooping, flood flag or forwarding state | switchdev attributes | kicked and re-derived from the live snapshot. `PORT_MROUTER` is one boolean for both families, sent only when the union changes — drivers count references by it — so one family's router arriving or expiring while the other stands is found by the five-second refresh instead |
| Querier timers or per-VLAN snooping state without a notification | the existing five-second worker | re-derived, including refused groups; unchanged forwarding plans leave their hardware chains intact |
| An nftables commit (iptables-nft included) | nothing reports it: read every second while any group exists, at every worker pass, and by the observer | every confirmation taken back, every group to software until the ruleset has stood still for a second and a copy is then seen leaving each oif again |
| The ruleset having stood still for a second | the ruleset poll, moved to that moment | confirmations accepted again |
| A copy seen leaving an oif at `POST_ROUTING`, having arrived by the parent VIF | the observer, which wakes the worker when a group's last oif is seen | re-derived and carried |
| The MFC entry's parent replaced | the FIB chain | a new watch with nothing confirmed; to software until copies from the new parent are seen |
| A bridge hook registered at `output` or `postrouting` | nothing reports it: asked at every derivation | a group with an oif through a bridge is `refused-filter` |
| An nftables chain after the observer at `POST_ROUTING` | nothing reports it: asked at every derivation, and creating a chain is a commit | the family's groups are `refused-filter` |
| The host joining the group on the parent VIF or an oif | nothing reports it | `refused-host` at the next derivation; the five-second refresh finds it |
| A root this learner gives up | its own worker | a group refused its key is asked again in the same pass |
| The bridged group carrying a route installs or retires | the bridged worker kicks this one | re-derived; the route's state follows, and `MFC_OFFLOAD` with it |
| A bridge becoming or ceasing to be a multicast router | `SWITCHDEV_ATTR_ID_BRIDGE_MROUTER` | the bridged worker asks the bridge about every flow on it again, and re-matches each against the routes and VIFs; the dedup slots are forgotten, so a stream only a route names is learned from its next frame |
| A bridge turning promiscuous, or back | nothing reports it | each publication of a route through the bridge compares, one per refresh, and forgets the dedup slots when it changed |
| A port's egress queues: an HTB tree switching it to or from CEETM, a class moving or going, the DSCP map changing | `ft_mc_egress_changed()`, from the adapter's egress hook | every installed group of either learner with a copy on the port is marked and rebuilt in place, because each listener entry names the queue and the DSCP-map bit its port had when it was built; a group routed through a bridge is rebuilt with the bridged flow its copies ride; the DSCP map's drain rebuilds what the workers have not yet, from each entry's recorded spec; `mcast_egress_rebuilds` counts the marks |

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
after the last fold is read before a group's entry is deleted and folded then,
so nothing is lost when a group leaves hardware. `/proc`'s own row reports the
present hardware group's raw L2 count, which starts again with each group.

One entry's counters only grow, so a sample below what was already folded
means a misread: the classifier's 64-bit fields are separate loads, and nothing
documents their update as atomic against the CPU's, so a read across a carry
can be off by 2^32 either way. A low sample folds nothing, and a sane one after
it folds from the baseline that stood. A second low sample in a row says the
baseline came from a high misread, already folded and past taking back, and the
baseline is taken up from there. Otherwise the count and `lastuse` would stand
still until the true count passed the bad baseline -- 4 GiB of an IPTV stream,
about an hour -- which a daemon ageing routes by either reads as a stream that
stopped. The bridged learner feeds a route's count by the same rule.

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
mroute_ruleset_changes 3
mroute_ruleset_settled 1
mroute_confirm_errors 0
```

— and one row per group:

```
mroute family=4 table=253 group=239.8.1.5 src=10.0.0.52 in=eth4 oifs=eth3 \
    listeners=eth3/0 state=installed unconfirmed=- packets=1500 bytes=795000
```

`oifs` names the VIF devices the kernel listed; `listeners` names the physical
ports and tags the hardware was actually given, which is where a bridge oif
becomes several. `unconfirmed` names the oifs Linux has not yet been seen
forwarding the group to, which is what keeps a `pending-confirm` group in
software. The states are `installed`, `pending`, `pending-bridged`,
`pending-confirm`, and the refusals above plus `refused-filter`, each distinct
so an operator can tell them apart. While a routed group exists,
`mroute_ruleset_settled` is 0 for the second after a commit, and for as long
as the commit is still being applied. Meanwhile no copy confirms anything, and
every group reads `pending-confirm` with all its oifs unconfirmed. With no
group the ruleset is not followed: it is read only when something else wakes
the learner, so the value can still read 1 across a commit until the first
group appears and the next pass reads the pair. Read it beside a group's
state, never alone. `mroute_confirm_errors`
counts failures to register the observer or to allocate a group's watch, each
of which keeps groups in software. A group
routed through a bridge names the bridge as `in`: the port its stream arrives
on is the bridged group's to know, and that row — `mcast … routed=eth3/287` —
names it, with its own copies beside the routed ones. `mroute_policy_rules`
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
- **A bridge whose per-VLAN multicast snooping is on.** Whether a bridge is a
  multicast router is read from `br_multicast_router()`, which answers for the
  bridge's global context; with `mcast_vlan_snooping` each VLAN has its own,
  and no exported call reads it. A per-VLAN router state that differs from the
  global one is not seen.
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

The shared stream is covered from both ends. `mroute_learner.c` derives a
parent on a bridge and on a VLAN device above one into a published plan with
no ingress port, and refuses the shapes a bridge does not hand up.
`mroute_refresh.c` runs the real worker: a group routed through a bridge never
reaches `cdx_mc_group_add()`, its state and `MFC_OFFLOAD` follow what the
bridged learner reports, its counters are the bridged group's less the ingress
tag, and a parent moving back to a port withdraws the route. It runs the
admission with the real table as well. A group is `pending-confirm` until
its oif is seen, and a copy to another device, of another group, from another
parent or of the other family confirms nothing. A commit, by the counter or by
the cursor alone, withdraws the group. Copies confirm nothing until the
ruleset has stood still for its second. A further commit, or one landing in
the grace period before opening, starts that again. A commit still being
applied when the second is up holds it closed, looked at again every 100 ms
until the mark clears. The next copy after
it re-confirms the group. A copy seen after a commit the worker has not
caught up with confirms nothing and wakes it. So does a commit between the
pass's sync and its admission. An oif Linux never forwards to keeps the group
in software through any number of refreshes, and is carried once seen. An oif
removed leaves the rest confirmed. A new parent starts from nothing. A bridge
output hook, or a hook after the observer, refuses the group. A watch that
cannot be allocated admits nothing and is counted. The same happens for IPv6
in a table of its own. It also runs two MFC entries on one port's two VLANs,
the second `refused-contested` until the first retires.
`mroute_confirm_order.c` runs the real walk of the `POST_ROUTING` list, where
only an nftables chain after the observer counts.
`mcast_learner.c` runs the bridged half: the union and its
ceiling, a duplicate framing, the MTU bound, retention while either learner
names a group, the group a route creates for itself and the join that fills
it, which VLANs a VIF on a bridge receives, a bridge that is not a multicast
router, a VIF with no route (`refused-routed`), and a departing device.
`mcast_hm.c` checks a routed copy's entry: the hop decrement first, a zero DSCP
word, the header from the egress port.

**Rig** — `test_flowtable_service_multicast_bridge.py::`
`test_flowtable_service_multicast_bridge_and_route`, both families. IPTV in
untagged on the WAN port, bridged to the set-top box on VLAN 289 and routed by
`smcroute` from `br-ftmcast.289` into VLAN 290 on the same LAN port, with the
bridge a multicast router. It asserts the one `mcast` row carries both
(`ports=eth3/289 routed=eth3/290`), the `mroute` row is `installed` through
the bridge and `ip mroute` says `offload`; then, on the wire, the bridged copy
has the sender's MAC and hop count 64 and the routed copy the port's MAC, the
group's and 63, each whole and once, with the classifier counting at least 95%
and the ingress CPU under 10% beyond what the port receives idle over as long
again, and `ip -s mroute` counting the stream. The box
leaving keeps the routed copy in hardware alone; the route going retires the
group.

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

`test_flowtable_service_multicast_routed_firewall`, in
`tools/tests/test_flowtable_service_multicast_edges.py`, proves the
confirmation for both families. The group has two oifs, the LAN port and a VLAN
device on it, and an `inet` forward chain drops the group toward the VLAN
device, as fw4's zone policy would. The group reads `pending-confirm` with the
VLAN device `unconfirmed`. The port receives the stream through software, and
the VLAN peer receives nothing. With the table deleted, the group is carried to
both, and the classifier counts the whole window. Adding the chain back is a
commit: `mroute_ruleset_changes` moves and the group leaves hardware. Once
`mroute_ruleset_settled` is back, the port is confirmed again from the stream,
and the VLAN peer receives nothing.

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
have joined the group on its own ingress interface or on an oif, which nothing
here does.
`refused-contested` is likewise host-only: it needs two parents on two VLANs of
one port for one `(S,G)`, which no daemon in the contract writes on its own.

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

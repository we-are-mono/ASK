# Multicast without CMM

Roadmap item 7. What the hardware already replicates, what the bridge already
knows, and the one thing neither of them has — which decides the shape of the
whole increment.

This document is the decision and the contract. It is written before any code,
because the roadmap asks items 5 to 8 each to settle a feature-specific
hardware eligibility contract first, and because this is the first remaining
item where the control plane Linux offers and the key the hardware matches on
do not describe the same object.

## The shape of the problem

Every increment before this one had the same shape: Linux decided what to
forward and the adapter transcribed that decision into a classifier key. NAT,
IPv6, VLAN, bridge, PPPoE and IPsec are all that. Multicast is not, and the
reason is worth stating precisely before any option is weighed.

**The hardware matches an exact (S,G) pair.** `fill_key_info()` in
`cdx/cdx_ehash.c` builds one key for every table it serves, and for a
multicast entry `cdx_add_mcast_table_entry()` hands it a `CtEntry` with
`proto = IPPROTOCOL_UDP` and both ports zero. The key that comes out is
`{portid, saddr, daddr, protocol}` — the zeroed ports shorten it by four
bytes, which is the only masking the composer does. The source address is
always present, and this is an external *hash* table: a masked field cannot
match, because the mask would change the hash.

`MC4Command.src_addr_mask` and `MC6Command.src_mask_len` exist in
`cdx/dpa_control_mc.h` and are read nowhere in the tree. They are not an
unexercised capability; they are a field NXP declared on the wire and never
wired to anything, and could not have been. `ISSUES.md` should not carry them
as a gap — there is no hardware behind them to reach.

The bench already proved this the expensive way. Commit `73144ff` records a
replication test failing with **0 frames at every listener** purely because
scapy chose a source address the group had not been keyed on. A wrong source
is not a degraded match; it is a miss.

**The bridge's MDB is keyed `(*,G)` for the joins that matter.**
`struct br_ip` carries a `src`, and the bridge does populate it — but only for
IGMPv3 INCLUDE-mode reports, which create their own source-specific port
groups (`br_multicast.c:622`). An IGMPv2 join, and an IGMPv3 EXCLUDE{} report,
which is what an IGMPv2 join becomes on a v3 querier, produce an entry whose
`src` is zero. The bridge floods such a group to every port that joined it,
whatever the source, and has no opinion about where the traffic comes from
because it does not need one.

So the control plane's most common entry describes a set the hardware cannot
express. That gap — not the eight-listener constant the previous scoping pass
concentrated on — is this increment's actual problem.

**And the MDB does not name an ingress port either.** A CDX multicast entry is
keyed on the ingress port as well as the addresses: `portid` is the first field
of the key and `cdx_add_mcast_table_entry()` takes it from a single
`input_device_str`. The MDB says which ports want a copy. It says nothing about
which port the stream arrives on, because for the bridge that is whichever port
the frame showed up on and there is nothing to record.

Two unknowns, then, and the useful observation is that they are the same
unknown: both are properties of the *traffic*, not of the *membership*. Nothing
in any control plane can supply them, because until a frame arrives there is no
fact to supply.

## What is already true, and what it means

**The encoder works, and this is a correction to the scoping that preceded
this document.** An earlier handoff recorded that there is no `test_mcast*`
anywhere in `tools/tests/` and that the encoder in `cdx/dpa_control_mc.c`
should be treated as unproven CMM-era code. Both are wrong. The tree carries
five files and 1,986 lines of it —
`test_mcast_replication.py`, `test_mcast_pagination.py`,
`test_mcast_concurrent.py`, `test_mcast_failslab.py` and
`test_mcast_hcsync_quarantine.py` — and `cb8fc27` ("cdx,fman: fix IPv4
multicast offload", `ISSUES.md` M15) fixed the hardware path that makes them
pass. `test_mcast_replication.py` asserts *exactly one* replicated frame at
each of three listeners for a single injected frame, which discriminates
between drop, correct replication and double replication.

So hardware replication is a measured behaviour rather than a hope, and the
`ISSUES.md` M-series entries are its scar tissue. What is missing is only a
learner.

**But the encoder is unreachable in this ownership mode, and not for the reason
IPsec's was.** IPsec had two init gates to open. Multicast has none —
`CMD_INIT(mc4)` and `CMD_INIT(mc6)` run unconditionally at
`cdx/cdx_cmdhandler.c:177`. What they build, though, is not hardware:
`mc4_init()` allocates the group-id array and the bucket spinlocks and calls
`set_cmd_handler(EVENT_MC4, ...)`, and that is all. The hardware side is the
FMAN table descriptor, which the PCD provides in both modes.

The door that is shut is further up and shuts on everything:
`comcerto_fpp_send_command()` answers `-EOPNOTSUPP` to **every** FCI command
when `cdx_flowtable_enabled()` (`cdx/cdx_cmdhandler.c:213`). So a flowtable
boot cannot reach `MC4_Command_Handler` at all, by design, and nothing in this
increment should change that. The learner calls the encoder in-kernel, the way
the flowtable adapter calls `cdx_ft_add()` and the IPsec adapter calls
`cdx_ipsec_sa_add()`. One consequence is practical and immediate: **the
listener-ceiling experiment has to run in a CMM boot**, because that is the
only boot in which raw FCI is answered.

**CMM never learned a group either.** `cmm -c "query mc4"` on the production
gateway that carries IPTV answers *"FPP Multicast IPV4 table empty"*. There is
no netlink, no IGMP snooping and no MFC anywhere in `cmm/src/module_mcast.c`
or `module_mc4.c` — only an explicit `CMD_MC4_MULTICAST` from outside that
nothing on the box sends. `auto_bridge` tracks the unicast FDB alone. So this
adds a capability rather than restoring one, it does not gate the merge, and
CMM's control API is one caller's idea rather than a specification to
reproduce. The only part worth keeping is the group structure it fills.

**No VLAN interface has an onif in this mode, and the listener encoder assumes
one.** `create_exthash_entry4mcast_member()` resolves each listener with
`get_onif_by_name(pListener->output_device_str)` and then derives that
listener's egress framing — including its VLAN tags — from the onif, through
`dpa_get_tx_info_by_itf()`. A VLAN onif is created in exactly one place,
`control_vlan.c:209`, from an FCI `CMD_VLAN_ENTRY` that only CMM sends. So
every existing multicast test reaches its tagged listeners through a
CMM-created onif, and in a flowtable boot only the physical ports have one.

This is a solved problem rather than a new one. The flowtable's own encoder
hit it first and answered it with `struct cdx_l2_encap`
(`cdx/control_ipv4.h:170`) and `apply_l2_encap()` (`cdx/cdx_ehash.c:1049`): the
caller names the tag stack and the encoder applies it, with no interface
registration anywhere. And `fill_mcast_member_actions()` already emits
`create_vlan_ins_hm()` whenever `l2_info.num_egress_vlan_hdrs` is non-zero, so
the opcode side needs nothing new. What the per-listener builder is missing is
the parameter.

## The control-plane decision

Linux offers the bridge MDB two ways, and they carry different information.

**Option A — switchdev objects.** `br_switchdev_mdb_notify()` calls
`switchdev_port_obj_add()` for every port group with **no check that the port
belongs to a switch ASIC** (`net/bridge/br_switchdev.c:655`), and
`br_mdb_notify()` calls it unconditionally for a plain bridge
(`net/bridge/br_mdb.c:529`). The adapter is already registered on that exact
chain — `register_switchdev_blocking_notifier(&ft_swdev_nb)` at
`ask_flowtable.c:3193`, which today filters for `SWITCHDEV_OBJ_ID_PORT_VLAN` —
so consuming `SWITCHDEV_OBJ_ID_PORT_MDB` costs one more case in a switch
statement that exists.

Two properties make this the right *transport* regardless of which option
wins. The object is delivered with `SWITCHDEV_F_DEFER`, so it arrives from
`switchdev_deferred_process_work()` — process context, under RTNL, which is
where a CDX transaction can be taken. And answering it has a defined meaning:
setting `obj_info.handled` and returning zero makes
`switchdev_port_obj_add_deferred()` call `br_switchdev_mdb_complete()`, which
sets `MDB_PG_FLAGS_OFFLOAD` and makes `bridge mdb show` print `offload`
against that port group. The kernel already has the vocabulary for "this is in
hardware" and displays it in the standard tool.

The catch is `br_switchdev_mdb_populate()`. It converts the group to a
multicast MAC with `ip_eth_mc_map()` and hands the driver only
`struct switchdev_obj_port_mdb { struct switchdev_obj obj; unsigned char
addr[ETH_ALEN]; u16 vid; }`. **The L3 group is discarded.** That mapping folds
28 bits of group address into 23 bits of MAC, so 32 IPv4 groups share one
Ethernet address, and a driver matching on the MAC delivers the union of those
groups' port sets. For CDX the objection is sharper than aliasing: the key
being composed is an IPv4 or IPv6 address, not a MAC, so a MAC is not a lossy
version of what is needed — it is the wrong field entirely.

**Option B — the bridge's netlink MDB.** `RTM_NEWMDB`/`RTM_DELMDB` carry
`struct br_mdb_entry`, which keeps the real group: a union of `ip4`, `ip6` or
`mac_addr`, plus `vid`, `ifindex`, `state` and `MDB_FLAGS_OFFLOAD`. Exact L3
semantics, matching the key the classifier composes. The cost is that
netlink's natural consumer is userspace, and an ASK userspace component between
kernel and hardware is the thing being retired. An in-kernel netlink listener
is possible and is worse than either neighbour: it re-parses a message the
kernel built from state it already holds, and it arrives outside RTNL, which
is the lock the port walk needs.

**Option C — patch the bridge to carry the group into the switchdev object.**
The kernel *has* `mp->addr` at the point it throws it away. Adding the
`struct br_ip` to `switchdev_obj_port_mdb` and populating it in
`br_switchdev_mdb_populate()` keeps Option A's shape and Option B's accuracy,
and costs a handful of lines in two files.

### The decision

**Option C, and the reasoning is the IPsec increment's.** ASK carries 28 kernel
patches and patching is normal house practice, so "the mainline API is missing
a field" is a reason to add the field, not a reason to build a consumer that
does not need it. The patch is small, it is additive, it changes no existing
behaviour for any driver that ignores the new field, and the alternative —
matching on a multicast MAC — is not a degraded version of the right answer
but a different and wrong one.

Two details make it cheaper than it looks. `struct br_ip` lives in
`include/linux/if_bridge.h`, a public header, so `include/net/switchdev.h` can
name it without reaching into `br_private.h`. And `switchdev_obj_size()`
already returns `sizeof(struct switchdev_obj_port_mdb)` for both MDB object
ids, so the deferred copy widens with the struct and no size bookkeeping has
to be found and changed.

**ASK must not become a switchdev driver to use any of this, and the
distinction is load-bearing.** `cdx_ft_switch_port()`
(`cdx/cdx_flowtable_backend.c`) *refuses* any port that answers
`dev_get_port_parent_id()`, because a switch-ASIC port lets the bridge mark a
VLAN as already hardware-stripped. Growing a port parent id would make the
flowtable reject its own ports. Listening on the notifier chain is fine and is
what the adapter already does for the FDB and for port VLANs; registering as a
switchdev is not.

## The second decision: where the source and the ingress port come from

Option C settles what the membership looks like. It does not settle the two
facts the membership cannot contain — and this is the decision the increment
actually turns on.

For a `(*,G)` entry the adapter has a group, a VLAN and a set of egress ports,
and it needs a source address and an ingress port before it can compose a key.
Three ways to get them were considered.

**Refuse `(*,G)` and offload only source-specific joins.** Honest, and it is
what a naive reading of the contract would produce. It is also close to
useless: IGMPv2 and IGMPv3 EXCLUDE{} are what an ordinary set-top box emits,
and refusing them means the production IPTV case — the one that motivated the
item — is exactly the case not carried.

**Take the ingress port from the bridge's multicast router port.**
`SWITCHDEV_ATTR_ID_PORT_MROUTER` is emitted on the same blocking chain
(`net/bridge/br_multicast.c:3269`) whenever a port starts or stops being a
router port, which for IPTV is the ISP-facing port and is therefore usually
right. It is available and it is free, but it answers only half the question —
it says nothing about the source — and it is a heuristic dressed as a fact: a
port is a router port because a querier was heard on it, which is correlated
with, but not the same as, being where a given stream arrives.

**Learn both from the first frames of the stream. Chosen.**

Until a hardware entry exists the bridge forwards the group in software,
exactly as it does today and has done throughout the product's life. Those
frames carry both missing facts: `skb->dev` is the ingress port and the IP
header holds the source. A netfilter hook on `NFPROTO_BRIDGE` /
`NF_BR_PRE_ROUTING` sees each of them once, before the forwarding decision,
and needs to see only the first.

The shape this produces is the architecture's own, which is the strongest
argument for it. A unicast flow is not offloaded when a route appears; it is
offloaded when `nft_flow_offload` sees a packet on an established conntrack.
The control plane describes what is *permitted* and the data plane decides what
is *present*. A `(*,G)` MDB entry is a permission, and it becomes an
installable `(S,G)` the moment traffic proves which source and which port it
is about.

It is also self-quieting in a way a polling design would not be. Once the
entry is installed, the hardware classifier matches the stream at ingress and
replicates it without the frame ever reaching the CPU — so the hook stops
seeing that group. The cost of the mechanism falls to zero exactly where the
offload starts paying.

Three consequences follow and belong in the contract below: a source that
changes produces a second entry rather than a modified one; a source that goes
away is aged out rather than withdrawn; and a group with many simultaneous
sources multiplies entries. All three are stated there rather than discovered.

## What this choice costs, stated honestly

**A netfilter hook is a packet-path cost the other increments did not have.**
Every previous increment put its cost in control paths only. This one registers
`NF_BR_PRE_ROUTING` and so appears in the bridge's receive path for every
frame. Three things bound it. The hook is registered only while at least one
group is pending, so a box with no unresolved `(*,G)` membership pays the
static-key check and nothing else — `nf_hook_bridge_pre()` tests
`static_key_false(&nf_hooks_needed[NFPROTO_BRIDGE][NF_BR_PRE_ROUTING])` before
anything else happens. The hook's own first test is on the destination MAC's
multicast bit. And it never mutates or consumes an skb: it records and returns
`NF_ACCEPT`, always.

It is still a hook in a datapath, and that is a real difference in kind from
everything above it in the roadmap. It is accepted because the alternative is
refusing the deployment the item exists for.

**The first frames of every stream are forwarded in software.** This is a
latency and CPU cost at channel change, not a correctness one, and it is
exactly what happens today for the whole stream's life. The window is one
forwarding decision long. It is worth measuring rather than assuming, because
an IPTV zap time is a number operators care about, and it belongs in the
parity row.

**A group whose source moves leaves a stale entry behind.** The hardware entry
is keyed on a source that is no longer sending. It matches nothing, it costs
one exthash entry and one group id of 512, and it is removed when its MDB
membership goes or when its idle timer expires. It never misdelivers, because
a key that matches nothing forwards nothing — but it does occupy capacity, so
the ageing is part of the design rather than a refinement.

**The eight-listener constant is inherited unproven, deliberately.** It is
`MC_MAX_LISTENERS_PER_GROUP` in `cdx/dpa_control_mc.h`, it sizes
`mcast_group_info.members[]`, and `cdx_create_mcast_group()` refuses anything
larger. Nothing ties it to hardware: the programming path is a loop, one
iteration per listener, each building its own external-hash entry and threading
`tbl_entry` into the next call, and there is no eight-wide hardware object
anywhere. It has the same shape as `ft_bound >= 2`, the flowtable binding cap
that survived three years as a proof-of-concept constant before being lifted to
`MAX_PHY_PORTS`.

But a gateway has five physical ports, and a bridged group's listeners are
physical ports in this ownership mode, so eight is not a limit this deployment
can reach. The measurement is worth making because the number should be a
measured bound rather than a copied one — it is step 1 below — and its result
changes nothing about the increment either way. Note the neighbouring constant
that is easy to conflate: `MC_MAX_LISTENERS_IN_QUERY` is 5, it sizes
`MC4Command.output_list[]`, and it is how many listener records fit in one FCI
*message* rather than a forwarding limit. It is irrelevant to an in-kernel
caller, which is one more argument for not synthesising FCI.

**Scoping this turned up a second, quieter bound that had to be removed before
the measurement could mean anything.** `struct ins_entry_info` is the write
cursor into one entry's fixed 16-slot opcode area, and both multicast callers
declared one, zeroed it once, and passed the same pointer to every listener in
the group. Three quarters of the cursor — `opcptr`, `paramptr`, `param_size` —
were re-based per entry; `opc_count` was not, and nothing in the tree ever
assigns it zero. A group's listeners therefore shared one entry's opcode
budget: two opcodes per tagged listener against `MAX_OPCODES` of 16.

It never tripped, and the reason is the `MC_MAX_LISTENERS_IN_QUERY` gate above.
`MC4_Command_Handler` refuses any mutating command naming more than five
listeners, and a group larger than that is assembled by several commands, each
with a fresh struct — `test_mcast_pagination.py` builds its eight as ADD 5 plus
UPDATE 3. So the worst reachable case was ten opcodes against sixteen. Latent,
with six opcodes of headroom, and the headroom would have evaporated the moment
someone raised the per-command limit toward the per-group one in order to run
step 1.

The fix is to stop sharing the struct: the builder allocates its own, which is
what every other entry builder in `cdx_ehash.c` already does. That also removes
three things the sharing made possible but that nothing has yet hit —
`tnl_hdr_size` accumulating with `+=`, `flags` only ever being OR-ed, and
`preempt_params` being left pointing into the previous listener's entry for any
future path that emits a preemptive check. Riding along in the same commit is a
use-before-init the audit found next door: `create_exthash_entry4mcast_member()`
passed `dpa_get_fm_port_index()` a *local* `fm_idx` and copied it into the
struct ten lines after `dpa_get_tdinfo()` had already read the struct's copy, so
every listener selected its table descriptor with the previous listener's FMAN
index — or with zero, on the first. Invisible on a single-FMAN part and wrong
on any other.

**Replication does not take an offline port, and that is a decision rather
than an inheritance.** Three FMAN offline ports are unclaimed on this board —
the DTS declares six, `0x2` is the PCD host-command port and CDX takes `0x3`
and `0x4` for IPsec and Wi-Fi, so `0x5` through `0x7` are free and claiming one
is a cell-index override alongside the existing two. An offline port buys a
second classification pass, which is what IPsec needs because a decrypted
frame's real 5-tuple was encrypted on the way in, and what Wi-Fi needs because
its frames never arrived on a MAC at all.

Multicast needs neither, and the reason is that fan-out is already expressible
in the ingress port's own tables. The root entry's `REPLICATE` opcode names a
chain of per-listener entries, each carrying its own opcode list — its own
`INSERT_VLAN_HDR`, its own `INSERT_L2_HDR`, its own enqueue — so a per-listener
header transform is a property of that listener's entry rather than something
a frame has to be re-classified to acquire. The bridged case is exactly this:
one group's copies leave tagged on one port and untagged on another, and both
are one pass.

Nor is the chain a bound to route around. The microcode walks `next_entry` to
a null terminator rather than a count — `first_member_flow_addr`'s neighbouring
`rsvd` field is the vendor's own commented-out `num_mcast_members`, and their
dumper walks `while(1)` — so nothing in the structure limits its length. The
eight was `MC_MAX_LISTENERS_PER_GROUP` sizing a software array, plus the shared
opcode cursor described above, and neither survives contact.

The positive reason not to spend one is that multicast is the worst possible
workload to put a second pipeline traversal in front of. It is the one case
where the frame count is *multiplied*: N listeners already cost N transmits,
and a re-injection pass would make it N transmits plus a re-classify. An
offline port is a scarce resource being spent to make the expensive case more
expensive.

**Host delivery is not solved by this increment.**
`SWITCHDEV_OBJ_ID_HOST_MDB` exists for traffic the bridge itself must receive,
and a hardware entry that replicates to ports only would starve a local
listener. The contract refuses such a group rather than carrying it partially;
see below.

## The eligibility contract

What the hardware may be asked to replicate. Everything outside this is
forwarded by the Linux bridge, in software, exactly as it is today.

**The group.** IPv4 and IPv6, learned from the bridge MDB. A key is always
`(S,G)`: `daddr` is the group and `saddr` is a specific sender. A `(*,G)`
membership is a permission to install one `(S,G)` entry per source observed
carrying that group, and is never itself installed. An IPv4 group must satisfy
`224.0.0.0/4`, which `MC4_Command_Handler` already enforces and the in-kernel
path must enforce equally.

**Link-local scope is refused.** `224.0.0.0/24` and IPv6 scopes 1 and 2 carry
control-plane traffic — IGMP and MLD reports themselves, and the querier the
bridge's own snooping depends on. Replicating those in hardware would take the
membership protocol away from the bridge that is the source of truth for this
whole design. The bridge floods them and must keep flooding them.

**The ingress.** A single physical CDX port, learned from the frame that
resolved the source, and a member of the bridge the MDB entry belongs to. The
entry is keyed on it, so a stream arriving elsewhere misses and is forwarded in
software — which is correct rather than a failure, and is how a second ingress
gets its own entry.

**The listeners.** Each MDB port group names a bridge port. That port must
satisfy `cdx_ft_port_supported()` — a registered physical CDX Ethernet onif,
not an L3 slave, not a switch-ASIC port, up and with carrier. A port that does
not is not a reason to refuse the group: it is dropped from the hardware
replication list, and the group is then refused outright, because a partially
replicated group is a silently broken one. There is no mode in which some
listeners are served by hardware and the rest by software, since the matched
frame never reaches the bridge to be flooded to the remainder.

**The tag stack.** A bridged group carries the MDB entry's `vid`. Each
listener's egress framing is resolved from that vid and the port's own
membership: untagged in the vid means no tag, tagged means one 802.1Q tag with
the bridge's protocol. This is `ft_bridge_vlan()`'s existing question asked
from the other end, and it is delivered to the encoder as `struct cdx_l2_encap`
rather than through a registered VLAN interface. 802.1ad bridges are refused
for the reason `ft_bridge_vlan()` already gives: the kernel describes no
selector for that tag and the hardware would be asked to reproduce it blind.

**The host.** A group carrying a `SWITCHDEV_OBJ_ID_HOST_MDB` object, or whose
bridge device has itself joined it, is refused. The classifier entry replicates
to ports and the frame does not reach the CPU, so a local listener would be
starved silently. This is a refusal rather than a gap to fill later only
because filling it means a listener whose egress is the host's own receive
queue, which nothing in the encoder expresses today.

**A group must be resolved to be installed, and installation is not
retroactive.** An MDB entry with no observed source is a pending permission and
occupies no hardware. This is the one place the contract admits a state the
other increments have no analogue for, and it is why `/proc` has to show it:
an operator looking at a group that is not being replicated must be able to
tell "refused" from "not yet seen".

**Capacity.** 512 group ids per family (`MAX_MC4_ENTRIES`), and one id per
`(S,G,ingress)` triple rather than per membership. Exhaustion is an ordinary
outcome: the group stays in software and says so, exactly as an exhausted
statistics pool does for a PPPoE session.

**Dependencies.** A multicast group is the sixth dependency class. Its
memberships come from the MDB and are retired by it; its listener ports and
ingress port are netdev dependencies retired the way a flow's are; its tag
stack depends on the bridge's VLAN configuration, which the adapter already
watches on the switchdev chain. What is new is the source: an installed `(S,G)`
entry whose stream stops has nothing to retire it, so it carries an idle timer
of its own.

## Implementation plan

Ordered so that each step is provable before the next depends on it.

### 1. Measure the listener ceiling

In a **CMM boot**, because that is the only boot in which FCI is answered.
Raise `MC_MAX_LISTENERS_PER_GROUP` — it also sizes `members[]`, so that is the
whole change — build through kas, and program a group with twelve to twenty
outputs. The board has five ports and few with carrier, so the outputs are VLAN
sub-interfaces, which also answers whether the encoder accepts them as
listeners at all.

Then inject one stream and **count what leaves each listener**: `ethtool -S`
per physical port, capture on the peers for per-VLAN truth. A return code of
zero only re-tests the check that was just raised. Watch `dmesg` for
`create_exthash_entry4mcast_member` failures as N climbs.

A malformed FCI command that oopses a handler orphans `ctrl.mutex`, after which
every FCI call hangs and only a reboot recovers. Build the command from the
existing `test_mcast_pagination.py` layout rather than by hand.

The result is recorded either way. It does not gate the steps below: five
physical ports cannot reach eight.

### 2. Per-listener encapsulation in the encoder

Give `create_exthash_entry4mcast_member()` a `const struct cdx_l2_encap *`,
applied with the existing `apply_l2_encap()`, so a listener's tags come from
the caller rather than from a VLAN onif. `fill_mcast_member_actions()` already
emits `create_vlan_ins_hm()` from `l2_info.num_egress_vlan_hdrs`, so the opcode
side is unchanged. FCI callers pass NULL and keep today's behaviour exactly,
which is what the existing five test files then prove.

Provable on its own: a CMM-boot run of `test_mcast_replication.py` must stay
green, byte-for-byte.

### 3. The typed backend interface

`cdx/cdx_mcast_backend.h`, in the shape of `cdx_ipsec_backend.h`: a group
described once, in kernel types, with no interface-name strings and no
`MC4Command` anywhere. A `struct net_device *` for the ingress, a
`union nf_inet_addr` pair for `(S,G)`, a family, and an array of listeners each
carrying its own `struct net_device *` and `struct cdx_ft_vlan` stack. Add,
replace the listener set, delete, and read counters.

It runs inside the flowtable backend's transaction, taken with `cdx_ft_begin()`
and asserted with `cdx_ft_assert_held()`, for the reason the IPsec header
gives: a group and a flow reach the same classifier through the same control
mutex, and a second lock would have to be ordered against the first for no
gain.

The implementation translates to the existing `cdx_create_mcast_group()` path
rather than duplicating it — the group list, the id allocator, the ingress MAC
subscription and the teardown are all there and all covered by the existing
tests.

### 4. Patch the bridge

`patches/kernel/`, a new number because this is a distinct concern: carry the
`struct br_ip` into `struct switchdev_obj_port_mdb` and populate it in
`br_switchdev_mdb_populate()`. Two files, additive, no behaviour change for a
driver that ignores the field.

Provable with a printk learner before anything else exists: enable snooping,
join a group from the LAN VM, and read the exact group and vid out of the
notifier.

### 5. The membership half of the learner

`SWITCHDEV_OBJ_ID_PORT_MDB` and `SWITCHDEV_OBJ_ID_HOST_MDB` on the existing
blocking chain. Accumulate per-`(bridge, group, vid)` port sets, resolve each
port's tag stack, and hold the result as a pending group. Answer `handled` and
zero only for a group actually installed, so `bridge mdb show` says `offload`
when and only when the hardware is carrying it — and leave `-EOPNOTSUPP` to be
the chain's answer otherwise, which is the discipline `ft_swdev_event()`
already documents for port VLANs.

Nothing is installed at this step. `/proc/cdx_flowtable` grows a multicast
section showing pending groups, which is both the proof and the operator
surface the contract promised.

### 6. The traffic half of the learner

The `NF_BR_PRE_ROUTING` hook, registered while and only while a pending group
exists. It matches a multicast destination against the pending set, reads the
source and `skb->dev`, and hands the completed triple to the backend. The
entry appears, the frames stop arriving at the hook, and the group's MDB port
groups are marked offloaded.

This is the first step that makes an observable promise, so this is where the
failing test comes first.

### 7. Retirement

The dependency watches: MDB delete, listener or ingress port down or
unregistered, bridge VLAN configuration change, and the idle timer for a source
that stopped. Each retires the group and returns it to pending or to nothing.
A group that loses one listener is reinstalled with the remainder rather than
being torn down, which is what the backend's replace operation is for.

### 8. Parity

A paired boot against CMM on an IPTV-shaped stream, in the roadmap's format.
CMM cannot learn a group, so the comparison is against CMM *with a group
programmed by hand over FCI* — which measures the encoder against itself and
isolates the learner's cost — plus a software-bridge baseline, which is what
the product ships today and is the number that actually improves.

Channel-change latency belongs in this row, because step 6 deliberately spends
a forwarding decision in software.

## Tests

The five existing files all drive FCI and all keep working, because step 2
leaves the FCI path byte-identical and step 3 reaches the same encoder. They
are the regression net for the encoder, and they remain CMM-boot tests; none
of them moves.

New coverage follows the house rule — the failing test first, proved to fail
without the fix — and splits in two.

**Host tests** for the decision logic: which memberships are eligible, how a
port's tag stack is derived from a vid and a membership, link-local refusal,
host-MDB refusal, and the pending-to-installed transition. Every new production
function must be added to the `names` list in the matching
`tools/host_tests/*.py`, or the harness stubs it silently and it is never
compiled — which is how the IPsec increment ended up with no host coverage of
its decision logic at all.

**A rig test** that is the increment's real proof: join a group from the LAN
VM, inject the stream from the WAN side, and assert that `bridge mdb show`
reports `offload`, that the hardware group is present, and that each listener
receives exactly one copy. The tripwire shape of `test_mcast_replication.py` —
count equals one, discriminating loudly between drop, correct replication and
double replication — transfers directly and is the right assertion here too.

Both halves run in a **flowtable boot**, which the existing five cannot.

## The consumer contract

There is none, and that is the result.

The bridge's own IGMP snooping is the entire control plane. It is on by default
(`multicast_snooping` is 1), it needs a querier on the segment or in the bridge
(`multicast_querier`), and it needs nothing installed, configured or packaged
by ASK. An operator who bridges an ISP's IPTV VLAN today already has the MDB
populated; what changes is that the groups in it are replicated by the FMAN
instead of by the CPU.

`igmpproxy` and `smcroute` remain a consumer's business and are unaffected:
they program `ipmr`'s MFC, which is the *routed* multicast path, and this
increment does not read it. That is a second learner against the same encoder
and is scoped as a follow-up — see below.

## Open questions

- **Routed multicast is a second learner, not a second feature.** `ipmr`'s
  `mfc_cache` carries `mfc_origin`, `mfc_mcastgrp`, `mfc_parent` and
  `ttls[MAXVIFS]`, where a non-zero `ttls[i]` means "forward out vif i" —
  which is already a replication list, and already an `(S,G)` key, so it needs
  none of the traffic-learning above. The kernel announces changes through
  `call_ipmr_mfc_entry_notifiers()` on family `RTNL_FAMILY_IPMR`, and **the
  adapter is already on that chain**: `ft_fib_event()` receives those events
  today and drops them at its `AF_INET`/`AF_INET6` filter. Deliberately not
  built here. If it is built, three things need deciding: who owns a group that
  is both bridged and routed, whether the two learners' output lists merge, and
  that they share one listener budget.

- **The idle timer's period is unmeasured.** A source that stops sending leaves
  an entry matching nothing. Too short and a bursty stream is retired between
  bursts; too long and capacity is held by ghosts. The hardware entry has flow
  statistics, so the timer can read the frame count rather than guess, but what
  a sensible period is has not been measured against a real stream.

- **Whether a group with many simultaneous sources is a real shape.** The
  design produces one entry per source and the contract says so, but an IPTV
  channel has exactly one source and the multi-source case may be purely
  theoretical. If it is not, the entry count wants a bound of its own.

- **`MC_MAX_LISTENERS_PER_GROUP` remains a copied constant until step 1
  reports.** Recorded here so that the number is not treated as a hardware fact
  by whoever reads this next, which is the mistake this document's predecessor
  made about the encoder's health and about the test surface.

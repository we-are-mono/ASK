# Multicast without CMM

Validation update: the original design below did not account for the ASK
listener encoder replacing a bridged packet's source MAC. A bridged group is
now keyed on its frames' own Ethernet pair in tables of its own, every copy is
rebuilt with that pair, and the group names the ingress tag its root
validates. See [the hardware investigation](multicast-hardware.md) for the
defect, the proof and the
[production integration](multicast-hardware.md#production-integration).

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
only boot in which raw FCI is answered. (The image no longer builds CMM, and
`comcerto_fpp_send_command()` now refuses every command unconditionally, so
that boot no longer exists.)

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
frame. Three things bound it. The hook is registered only while a membership
with a port, or a route through a bridge, could name a flow, so a box with
neither pays the static-key check and nothing else — `nf_hook_bridge_pre()`
tests `static_key_false(&nf_hooks_needed[NFPROTO_BRIDGE][NF_BR_PRE_ROUTING])`
before anything else happens. It stays registered while such a membership
stands even when every flow is installed, because a group can gain a second
source at any time and only a frame says so; an installed flow's frames never
reach it. The hook's own first test is on the destination MAC's multicast bit,
and a restatement of any of the last eight things it recorded is dropped under
one spinlock. And it never mutates or consumes an skb: it records and returns
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

**A stream with TTL 1 is never offloaded, and for a bridged group that is a
real limitation rather than a formality.** The FMC soft parser ends the parse
before classification for any IPv4 frame whose TTL is 0 or 1
(`cdx_sp.xml`, the `ipv4schema` protocol's `<before>` block, which assigns a
new next-instruction address and exits), and the same for an IPv6 hop limit.
Such a frame reaches the CPU and the bridge floods it in software, exactly as
it does today.

For *routed* multicast that is correct and unremarkable: TTL 1 means do not
forward beyond this link, so a router must not replicate it. For a **bridge**
it is a genuine gap, because bridging is not forwarding in the IP sense and
the Linux bridge will happily replicate a TTL-1 group. Anything that scopes
itself to the local link by TTL — and a good deal of service discovery does —
is therefore carried in software on this hardware whatever the MDB says.

Nothing in the adapter can change that: the decision is made in the parser
before any table is consulted. What the adapter does is not learn from such a
frame. An entry for the stream would count nothing, age out after the
membership interval, and be learned again from the next frame, for as long as
the stream runs. So the membership stays `pending-source` in `/proc` and the
MDB claims `offload` for a port that is only ever served in software. It is
recorded here because it is invisible from every surface an operator has, and
because it is a very effective way to convince yourself the offload is broken
when it is working. Measure with a TTL above 1, and have a test that sets it
explicitly rather than inheriting a default: a plain UDP multicast socket sends
TTL 1.

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

**The frame.** The key also carries the frame's own destination and source
MACs. A bridge forwards a frame with the addresses it arrived with, and a
listener can only write back addresses its root matched. So a second sender of
the same `(S,G)` misses and is bridged in software, still with its own address.
The ingress shape is learned as well: the group's VLAN as one 802.1Q tag, or
untagged on the port's PVID. The root validates and strips exactly that shape.
A frame with two tags, a tag in another protocol, or a tag on a bridge that
does not filter is not learned from, because no root can validate it. The
`/proc` row shows `smac`, `dmac` and `in_vid`, which is 0 for untagged.

**One flow per source and ingress.** What is installed is a *flow*: one
source's frames of a group as they arrive on one bridge port, keyed exactly as
the classifier matches. A membership installs nothing; it is a reason to learn
the flows of its group, and a change to it is a reason to ask about them again.
Two sources of a group are two flows with their own port sets, and so is one
source arriving on two ports. A group has at most eight flows per bridge VLAN
(`FT_MC_MAX_FLOWS`), which keeps a group every host sends to — SSDP's
`239.255.255.250` is the common one — from taking entries the table is short
of. A ninth source takes a place only when something asked for it by name —
an `(S,G)` membership, which an SSM listener's report produces, or a route —
and only from a flow that nothing names that way and nothing carries. So a
source an SSM listener asked for is not refused because the group's other
senders got there first, and none of those can take a place back: a group
every host sends to keeps the first eight it saw, and later senders cost a
lookup, not a flow made, asked of the bridge under RTNL and retired again on
each of their frames. No place is given up while the bridge refuses the whole
group — the host joined it, or it floods — because the new source would be
refused the same way. `mcast_refused` counts a place given up, and a source
turned away once until the group's flows change.

**A shape is replaced only when idle.** An installed flow keeps its key while
it carries traffic, so two live senders of one source do not trade one entry.
A five-second refresh reads each entry's counter. When an entry counted nothing
for a whole interval, a shape seen meanwhile takes over the key: a sender whose
MAC changed, a port that now carries the tag.

**The listeners are the bridge's answer.** Where a flow's frames go is not read
off the memberships. The bridge decides it per frame, and a switchdev object
carries none of what it decides by: an `(S,G)` entry is looked up before the
`(*,G)` one under IGMPv3 and MLDv2, a `(*,G)` INCLUDE port group is skipped, a
port that blocks the source is skipped, multicast router ports receive
everything, the ingress never receives its own frame, and an isolated port
does not forward to another. So the worker asks the bridge, under RTNL,
through `br_multicast_list_ports()` with the flow's ingress (patch 161), and
installs exactly the ports it names. A hairpin ingress, a port converting to
unicast, per-VLAN STP, or more ports than a group holds come back as an error
and refuse the flow. This is what keeps an IGMPv3 source filter in force: a
`BLOCK` or `TO_EX{S}` that makes the bridge stop forwarding `S` to a port asks
every flow of the group again, and the hardware stops with it.

Each port the bridge names must satisfy `cdx_mc_port_identity()` — a physical
CDX Ethernet port — and have egress framing a rule can describe. A port that
does not **refuses the whole flow**, because a partially replicated flow is a
silently broken one: the matched frame never reaches the bridge, so a listener
left out of the hardware set does not fall back to software, it stops
receiving. The shipping shape is a Wi-Fi VAP on `br-lan`: a phone joining the
stream a set-top box is already watching puts an uncarriable port in the
answer, and the flow goes back to the bridge in its entirety. A flow the bridge
forwards nowhere — every listener behind its ingress, or blocking its source —
has nothing to replicate and stays with the bridge too. `/proc` says
`refused-listener` for all of these.

**The tag stack.** A bridged group carries the MDB entry's `vid`. Each
listener's egress framing is resolved from that vid and the port's own
membership: untagged in the vid means no tag, tagged means one 802.1Q tag with
the bridge's protocol. This is `ft_bridge_vlan()`'s existing question asked
from the other end, and it is delivered to the encoder as `struct cdx_l2_encap`
rather than through a registered VLAN interface. 802.1ad bridges are refused
for the reason `ft_bridge_vlan()` already gives: the kernel describes no
selector for that tag and the hardware would be asked to reproduce it blind.

**The MTU.** No listener port may have a smaller MTU than the ingress port. A
listener's entry ends in `ENQUEUE_PKT`, and the microcode fragments any replica
larger than the MTU that opcode carries. A bridge never fragments:
`br_dev_queue_push_xmit()` drops a frame that does not fit the egress port,
whatever its family or DF bit. The two agree only while no such frame can
arrive, so a narrower listener keeps the whole group in software, where the
bridge decides per frame. `/proc` says `refused-mtu`. The comparison is in
device MTUs because a bridge decides in them, and an MTU change re-derives
installed groups as well as refused ones. The routed contract has the same
clause in IP units; see [the routed design](multicast-routed.md#the-eligibility-contract).

Why an admission bound rather than a check in hardware. A member entry has no
preemptive check: `fill_mcast_member_actions()` starts from a fresh
`ins_entry_info`, so `seal_preemptive_checks_hm()` has nothing to seal. And
excepting a single replica would duplicate the packet, because Linux would
re-replicate it to every member. The only place a check could stop the whole
packet is the root, before `REPLICATE_PKT`. The root already emits
`PREEMPTIVE_CHECKS_ON_PKT`, unsealed. What that opcode can express does not
cover the case. `PREEMPT_DFBIT_HONOR` excepts oversized IPv4 with DF set and
nothing else: A198 measured that neither it nor the fragmenter's DF action
stops IPv6. And a bridge must not fragment IPv4 without DF either. The check
also locates its MTU through `mtu_offset`, relative to an enqueue parameter
block that a root does not have, so it would have to read a synthetic MTU word
no hardware run has shown a replicating entry reading. An admission bound
covers every case with no unproven microcode behaviour. Its cost is that a
group whose listener MTU is below its ingress MTU stays in software even for
packets that would fit. That shape is rare on a gateway: it needs a jumbo
ingress or a deliberately narrowed listener.

**The host.** A flow the bridge also hands to the host because the bridge
device itself joined the group — a `SWITCHDEV_OBJ_ID_HOST_MDB` object — is
refused, and so is one it hands up because nothing is snooping it: snooping
off, or no querier on the segment, where the bridge floods every group to
every port and to the host alike. The classifier entry replicates to ports and
the frame does not reach the CPU, so a local listener would be starved
silently. This is a refusal rather than a gap to fill later only because
filling it means a listener whose egress is the host's own receive queue,
which nothing in the encoder expresses today. `/proc` says `refused-host`.

**Bridge filtering.** A carried flow is replicated at the classifier, before
any bridge netfilter hook runs. An nftables `bridge` chain, an ebtables table,
or `br_netfilter` handing bridged traffic to iptables would stop seeing the
stream the moment it went into hardware: a drop rule would stop dropping it,
and a counter would stop counting it. So while any bridge hook is registered
in the initial namespace at `prerouting`, `forward` or `postrouting`, no
bridged flow is carried, and installed ones come out. CDX's own hooks do not
count: the learner's, which only observes, and VWD's, which hands frames bound
for a Wi-Fi VAP to its fast path and is registered whenever an access point is
up. Hooks are per namespace, not per bridge, so this applies to every bridge.
Nothing announces a registered hook, so the worker checks the hook lists at
every pass, and the refresh runs a pass every five seconds while any flow
exists. `/proc` says `refused-filter`, and the kernel log says so once each
time the state changes. The rig case
`test_flowtable_service_multicast_bridge_yields_to_a_bridge_filter` drops the
group in a bridge `forward` chain while it is carried: the flow comes out, the
set-top box receives nothing, and the flow goes back in when the chain goes.

A bridge `input` chain sees what the host receives. A plain bridged flow's
frames never go there. A flow carrying a route's copies is different: the
bridge hands its frames up for ipmr to route, and those copies are carried
only once ipmr has been seen forwarding them past the inet hooks. A bridge
`input` chain that drops them prevents that. Its changes are followed with the
rest of the nftables ruleset; see
[what Linux forwarded](multicast-routed.md#what-linux-forwarded). A bridge
`output` chain sees what the host sends. The routed learner checks for one
before carrying a copy routed into a bridge.

Some hooks never go away once they appear, and keep bridged multicast in
software for the rest of the boot: `br_netfilter` once loaded (Docker and
libvirt load it), an ebtables table once anything has listed or used it, and
an nftables bridge base chain even when it is empty with an accept policy.
`br_netfilter` counts whether or not `bridge-nf-call-iptables` is set. Its
per-namespace sysctls live in its own private state and the per-bridge option
in the bridge's, neither of which a module can read, and its hooks cannot be
told from an nftables chain at the same priority; the setting also defaults to
on. A host that wants bridged multicast offloaded unloads it. Hooks the check
does not see at all: an nftables `netdev` ingress chain and a tc ingress
filter on a bridge port run before the bridge and are bypassed by a carried
flow like any other software step.

**The host as a router.** A bridge that is a multicast router for the flow's
family — `mcast_router 2`, or a query heard from the host itself — hands every
group to the host as well, and so does a promiscuous one: a bridge has no
unicast filter, so an upper device with an address of its own makes it
promiscuous. Where a VIF receives that bridge VLAN, ipmr routes what it is
handed. Such a flow is carried only together with the route that forwards
its stream, as one group with both output lists; without one it is
`refused-routed` and stays in software, where ipmr sees it and a routing daemon
learns its source. See
[one stream, both learners](multicast-routed.md#one-stream-both-learners). A
route names its stream's flow directly: the flow is learned from traffic with
no membership at all, and kept with no member port left. It does so only while
the bridge hands the host its streams, so a bridge becoming a router
(`BRIDGE_MROUTER`) or turning promiscuous lets a stream seen before be
recorded again. Promiscuity raises no event, so the routed learner's publication
of the route, one per five-second refresh, is where that change is found. The
`/proc` row lists the route's copies as `routed=`, beside the bridge's own
`ports=`.

**A flow must be learned to be installed, and installation is not
retroactive.** A membership with no observed source occupies no hardware. This
is the one place the contract admits a state the other increments have no
analogue for, and it is why `/proc` has to show it: an operator looking at a
group that is not being replicated must be able to tell "refused" from "not yet
seen". `/proc` prints one `mcast` row per flow, with `member_src` the source of
the most specific membership naming it, and one per membership that names no
flow yet, as `pending-source`. `mcast_groups` counts memberships and
`mcast_flows` flows; `mcast_installed` counts flows in hardware.

**Capacity.** 512 group ids per family (`MAX_MC4_ENTRIES`), and one id per
flow — per `(S,G,ingress)` triple — rather than per membership. Exhaustion is
an ordinary outcome: the flow stays in software and says so, exactly as an
exhausted statistics pool does for a PPPoE session. A failed install is tried
again at each of the next refreshes, five seconds apart, up to four times, and
then reads `refused-failed` until the bridge's answer for the flow changes.

**Dependencies.** A multicast flow is the sixth dependency class. Its
memberships come from the MDB and are retired by it, and a flow nothing names
any more goes with them; its copies and its ingress port are netdev
dependencies, retired when the device goes away or its ingress leaves the
bridge. A port leaving a bridge takes its memberships there with it at once:
the bridge flushes them with deletes it defers, and a port moved straight to
another bridge is that bridge's by the time they arrive, where they would
find nothing to delete. A link merely going down retires nothing: the bridge keeps a
permanent membership across it and never announces it again, so the flows
naming the port are asked again instead, and the bridge's answer leaves a
port that is not forwarding out. Everything the bridge decides its ports
by — the MDB, the bridge's and its ports' VLANs, STP state, port flags,
multicast router ports and state, snooping itself — is watched on the
switchdev chain and asks the bridge's flows again. Some of it changes with no
notification at all: a querier appearing or timing out turns snooping, and so
every answer, on or off. So the refresh asks every flow again every five
seconds as well, which costs RTNL for the asking and nothing in hardware
unless the answer changed. What is new is the source: an installed `(S,G)`
entry whose stream stops matches nothing. The refresh already reads each
entry's count, and an entry that has counted nothing for the bridge's group
membership interval -- `multicast_membership_interval`, 260 seconds unless
configured, read for the flow's VLAN at each derivation -- goes, flow and all.
That is the clock the bridge forgets an unrefreshed membership by, so a
stopped source is aged as the bridge would age a silent listener. An interval
shorter than two refreshes is taken as two, and a count read below the last
one ages nothing, because neither can tell a running stream from a stopped
one. A source
that resumes reaches the CPU again and is learned from its next frames like
any new one; a flow never in hardware has no count to age by, and is bounded
by the group's eight instead.

**A reload.** Registering on the switchdev chain replays nothing, and a
membership that stands is never announced again — a refreshing report finds
its port group and only restarts a timer. So at load the adapter asks every
bridge port for what it holds, through the bridge's own
`switchdev_bridge_port_replay()`, and a stream already flowing is learned
again from its next frame. Patch 160 makes the replay say what the
notification says: a blocked port group replays blocked, and a replay is not
dropped as a duplicate of a queued event for another group sharing its MAC.

A listener's entry also names the frame queue its port had when it was built,
and whether the port's DSCP map was on. When CDX changes a port's egress
queues — an HTB offload tree switching it to or from CEETM, a class moving or
going, the DSCP map changing — the adapter's egress hook counts the change and
`ft_mc_egress_changed()` marks every installed group with a copy on that port,
either learner's, and the workers rebuild each chain with
`cdx_mc_group_replace()`, which asks the port again and swaps the chain in
under the same key. The mark needs no RTNL and takes each learner's mutex in
turn. What a flow's copies are is read from the chain its entry was built
from, recorded whole beside the entry in the same transaction: the bridge's
copies and the routed copies riding it, so a route's port changing its queues
rebuilds the bridged flow that carries it. A flow whose chain was being built
while the change landed was not yet there to mark; the worker compares the
count of egress changes — the same count an SA install compares — across the
build and marks the flow itself. `/proc` counts the marks as
`mcast_egress_rebuilds`.

A DSCP map leaving a port cannot wait for the workers: its `drain()` runs
under the RTNL `tc` holds, and the bridged worker takes RTNL to ask the bridge.
So the drain rebuilds every flow still marked itself, in place, by replacing
its entry with the chain recorded for it, whole — the sender and the ingress
tag the root is keyed on, and the routed copies, included — with nothing to
decide: only the port's queues changed, not where the stream goes. That holds
while the worker has the flow in hand, because the worker keeps the flow's
entry and its recorded chain until it is inside its own transaction, and
records what it built before leaving it. A flow the drain cannot vouch for —
its recorded chain lost a device, or the replace failed and left the old chain
in place — is handed to the worker and reported, and the map stays claimed
until the next port asking for it finds the drain done. The worker's own
failed replace withdraws the flow to software in the same pass, so that wait
never runs to the retries the refresh paces.

A VLAN change on the bridge, whether a port's membership, the bridge's own,
its filtering or its protocol, marks every flow on that bridge. The worker
asks the bridge again under RTNL, not in the notifier, because a port VLAN
object is notified before the bridge applies it. Each copy's tag is
re-resolved, and a port that left the VLAN is no longer in the answer. A flow
whose ingress shape no longer resolves to its VLAN is over and is learned
again from its next frame: a moved PVID, or a tagged ingress port that left
the VLAN.

## Implementation plan

Ordered so that each step is provable before the next depends on it.

### 1. Measure the listener ceiling

In a **CMM boot**, because that is the only boot in which FCI is answered; the
image no longer has one, so this step cannot run as written.
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
port's tag stack, and hold the result as a pending group.

Nothing is installed at this step. `/proc/cdx_flowtable` grows a multicast
section showing pending groups, which is both the proof and the operator
surface the contract promised.

#### The handler cannot install, and that decides what `offload` means

A switchdev object with `SWITCHDEV_F_DEFER` is delivered from
`switchdev_port_obj_add_deferred()`, which opens with `ASSERT_RTNL()`. So this
handler runs **holding RTNL**, and the transaction every backend operation
requires is `cdx_info->ctrl.mutex`.

Those two cannot be nested in that order here, and the tree already says so.
`cdx_ctrl_lock_with_rtnl()` in `cdx_main.c` is a trylock-and-back-off loop
carrying the rule outright: *"RTNL holders may flush flowtable callbacks which
need ctrl.mutex; legacy FCI can take RTNL with ctrl.mutex held. Never wait for
either lock while holding the other."* Both orders exist in the tree —
`control_vlan.c` takes RTNL from inside an FCI command, which runs under
ctrl.mutex — and `cdx_ft_admission_begin()` is an `rtnl_trylock()` for exactly
this reason. A blocking `cdx_ft_begin()` from this handler would be the
inversion those two are avoiding.

It is also the wrong place to install regardless of locking: building a group
means allocating entries and syncing the PCD, and doing that under RTNL stalls
every other network configuration on the box for the duration.

So the handler **decides** and a work item **installs**. Everything the
decision needs — which ports are supported, what tag each carries, whether the
bridge itself has joined — is bridge and netdev state, which RTNL is precisely
the right lock for. Nothing in it touches hardware.

That settles what `handled` may claim. The adapter answers `handled` for a
group it has accepted responsibility for, not for one already in hardware,
because at that instant no group can be. `bridge mdb show` therefore reads
*"the adapter took this on"* rather than *"the hardware is carrying this"*, and
the two differ for as long as the work item takes to run — and permanently if
the install ultimately fails.

That is a stretch of the flag's upstream meaning, where a switch driver's
accept is synchronous with its hardware, and it is taken deliberately over the
alternatives. Leaving `-EOPNOTSUPP` as the answer, as the port-VLAN observer
does, would keep the flag honest but give an operator no standard-tool signal
at all. Setting it from the work item is not available: the deferred operation
has already called `obj->complete()` and returned by then, and MDB has no late
notification of the kind `SWITCHDEV_FDB_OFFLOADED` gives the FDB.

What makes the stretch tolerable is that it is not the surface anything
important reads. `/proc/cdx_flowtable` says what is actually installed, and it
is where a disagreement shows up. The two are worth reading together, and the
end-to-end tests assert both for that reason.

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
The image no longer builds CMM; the roadmap's flowtable-only line-rate check
now stands in for this pairing.
CMM cannot learn a group, so the comparison is against CMM *with a group
programmed by hand over FCI* — which measures the encoder against itself and
isolates the learner's cost — plus a software-bridge baseline, which is what
the product ships today and is the number that actually improves.

Channel-change latency belongs in this row, because step 6 deliberately spends
a forwarding decision in software.

## Proved on hardware, 2026-09-18

Flowtable boot, KASAN image, a plain bridge over the DUT's WAN and LAN ports
with snooping on. Memberships added with `bridge mdb add`; streams injected
from the orchestrator. Every case reads three independent things: the group's
row in `/proc/cdx_flowtable`, the classifier entry's own match counter, and
whether the frames reached the CPU at all.

| What | Result |
| --- | --- |
| IPv4 `(*,G)`, source learned from traffic | `installed`, 1000 of 1000 frames matched |
| Frames reaching the DUT's CPU, group installed | **0** — capture on the bridge saw none of the 1000 |
| Replication out the listener port | +1000 on eth3's transmit counter |
| Sustained rate | 50,000 frames at 385k pps, **+50000** matched, no loss |
| IPv6 `(*,G)` via MLD, the mc6 encoder | `installed`, 962 of 1000 matched |
| IPv4 `(S,G)`, source from the membership | `installed`, 768 of 800 matched |
| `(S,G)` with a foreign source | stays `pending-source` — 300 frames, correctly ignored |
| Membership withdrawn | group retired, `mcast_installed` decremented, entry gone |
| Teardown of the bridge | every group retired, every device released, no splat |
| Tagged listener on a vlan-aware bridge | tag resolved — `ports=eth3/3999` |

The first few frames of each stream are forwarded in software while the source
is being learned — 15 of 1000, 38 of 1000, 32 of 800 across the runs above.
That is the design working: a `(*,G)` membership has no key until traffic
supplies one, and the window is however long the worker takes to run.

Three things this rig could not exercise, and they are coverage gaps rather
than results. The board has five ports and only two have carrier, one of which
is the ingress, so **every group here has exactly one listener**: multi-listener
replication, the chain swap a join or leave performs against an installed
group, and the listener ceiling all need a second live listener port. And the
managed switch upstream does not trunk VLAN 3999, so while the tag is derived
correctly and reaches the encoder, a tagged frame has not been carried end to
end. The encapsulation itself is covered by `tools/host_tests/test_mcast_hm.py`.

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

`igmpproxy` and `smcroute` remain a consumer's business and are unaffected by
*this* half: they program `ipmr`'s MFC, which is the *routed* multicast path,
and this increment does not read it. That is a second learner against the same
encoder, and it has since been built — see the
[routed design](multicast-routed.md). It has no consumer contract of
its own either: whichever daemon a product ships writes `(S,G)` entries at
threshold 1 into the default table and needs nothing from ASK.

## Open questions

- **Routed multicast is a second learner, not a second feature. Built — see
  the [routed design](multicast-routed.md).** `ipmr`'s `mfc_cache`
  carries `mfc_origin`, `mfc_mcastgrp`, `mfc_parent` and `ttls[MAXVIFS]`, where
  `ttls[i]` below 255 means "forward out vif i" — which is already a
  replication list, and already an `(S,G)` key, so it needs none of the
  traffic-learning above. The kernel announces changes through
  `call_ipmr_mfc_entry_notifiers()` on family `RTNL_FAMILY_IPMR`, and the
  adapter was already on that chain; `ft_fib_event()` used to drop those events
  at its `AF_INET`/`AF_INET6` filter and now hands them to `ft_mr_fib_event()`.
  All three things this bullet said needed deciding are settled. The two
  learners do not share a key: a routed root's port is never a bridge port and
  a bridged root's always is, in tables of their own. A group that is both
  bridged and routed is one hardware group carrying both output lists, owned
  by this learner, each learner keeping its own listeners within the one
  eight-listener budget — see
  [one stream, both learners](multicast-routed.md#one-stream-both-learners).

- **Whether eight flows per group is the right bound.** An IPTV channel has
  exactly one source and an SSM subscriber names its own; the bound exists for
  groups every host sends to. It is a guess at where such a group stops being
  worth hardware, not a measurement.

- **`MC_MAX_LISTENERS_PER_GROUP` remains a copied constant until step 1
  reports.** Recorded here so that the number is not treated as a hardware fact
  by whoever reads this next, which is the mistake this document's predecessor
  made about the encoder's health and about the test surface.

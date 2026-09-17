# QoS and CEETM without CMM

How CMM programs egress QoS today, why none of it reaches a flowtable-offloaded
flow, and what has to exist before CMM can be retired from the QoS path.

This is a design document, not a delivered contract. The accepted boundary is
still the [supported scope](linux-flowtable-offload.md#supported-scope), which
admits only flows with a **zero conntrack mark**. That exclusion is the subject
of this document: it is the seam where QoS attaches.

## Three planes, not one subsystem

"QoS" in ASK is three independent mechanisms that share a command family and
nothing else. They retire separately and have different difficulty.

| Plane | What it does | Hardware | Driven by |
| --- | --- | --- | --- |
| Scheduler | Builds the CEETM tree: LNI, channels, class queues, shapers, WBFS weights, tail-drop | QMan CEETM | 12 `CMD_QM_*` commands |
| Classification | Decides which class queue a flow's frames enter, and which ingress policer they pass | FMAN action FQID and `pp_no` / `skb` TX path | conntrack mark; DSCP map |
| Policing | Rate-limits ingress flows, the fast-forward path, the punt path and the SEC path | FMAN PCD RFC-2698 policer profiles | 11 `CMD_QM_*` commands |

The scheduler plane is per-port configuration that an offloaded flow inherits
for free once it is enqueued to the right FQ. The policing plane is per-port
*except* for the eight ingress profiles, whose **selection is per-flow**: the
mark's `iqid` reaches `create_preemptive_checks_hm()` and becomes the ucode's
`pp_no` (`cdx/cdx_ehash.c:917`, `:2390`). So the classification plane carries
both egress class and ingress policer, and it is the only one the flowtable
must learn to speak.

## What CMM actually does

Less than the command count suggests.

The product's control plane is `/etc/config/cmmqos`, an OpenWrt UCI file shipped
by `package/mono/cmmqos` with `option enabled '0'`. Its init script renders the
sections into `set qm …` lines and feeds them to `cmm -c`, which relays them
over a SysV message queue to the CMM daemon, which sends FCI commands to
`cdx/control_qm.c`, which calls `qman_ceetm_*` and the FMAN PCD policer API.

CMM holds **no shadow QoS state**. Every programmed value lives in the kernel,
in `gQMCtx[]` (`cdx/control_qm.c:25`) and `qm_chnl_info[]`
(`cdx/cdx_ceetm_app.c:25`), and is read back over `CMD_QM_QUERY`. Deleting CMM
loses no configuration. What it loses is:

- the `ifname → port_id` alias table (`cmm/src/itf.c:35`), which also defines
  which ports constitute the QoS domain for a config flush;
- the `qm-config` apply protocol — a dry-run pass, then a `CMD_QM_RESET` flush
  of every enabled port, then apply. The kernel has no transaction concept;
- grammar-level range and consistency validation performed before any write;
- **which channel an interface gets.** `ceetm_assign_chnl()` refuses a channel
  that is already bound (`cdx/cdx_ceetm_app.c:1327`) but nothing in the kernel
  picks a free one. Channel allocation policy is CMM's alone.

Nor is much of the hardware CMM's doing. `qm_init()` builds the entire CEETM
tree at module load, before any interface exists and before any command
arrives: 8 channels, and per channel 16 CCGs, 16 class queues and 16 LFQs —
128 of each — plus 128 egress FMAN policer profiles allocated at DPA init
(`ceetm_init_cq_plcr`, `cdx/cdx_ceetm_app.c:854`). Per-interface, netdev
registration claims the sub-portal and LNI. What the FCI commands actually do
is bind a channel to an LNI, flip the sub-portal into CEETM mode, and push
rates, weights and thresholds into objects that already exist.

`CMD_INIT(qm)` runs **unconditionally**, unlike `CMD_INIT(ipsec)` which is
skipped when `cdx_flowtable_enabled()` (`cdx/cdx_cmdhandler.c:163`, `:167`). In
flowtable mode the board therefore pays for 128 LFQs and 128 policer profiles
that nothing can reach.

And CMM **never decided a queue**. `forward_engine.c` copied `ct->qosconnmark`
verbatim into the FCI conntrack command, and that was the entire contribution of
the daemon to the classification plane. Increment 7 removed the copy along with
the field, so CMM mode now has no classifier at all — the scheduler commands are
untouched and every flow lands on the default class.

## The field everything reduces to

`union ctentry_qosmark` (`cdx/control_ipv4.h:23`) is 32 bits carried per
direction inside the hardware conntrack entry:

| Bits | Field | Consumed by |
| --- | --- | --- |
| 0-3 | `queue` | `ceetm_get_egressfq()` → CEETM class queue 0-15 |
| 5-7 | `vlan_pbits` | *nothing* — declared, never read |
| 8 | `dscp_mark_flag` | `create_update_dscp_hm()` (`cdx/cdx_ehash.c:2122`) |
| 9-14 | `dscp_mark_value` | same |
| 15 | `vlan_pbits_valid` | *nothing* |
| 16-19 | `iqid` | `fill_actions()` ingress policer select (`cdx/cdx_ehash.c:917`) |
| 23 | `iqid_valid` | same |
| 24-27 | `chnl_id` | `ceetm_get_egressfq()` → CEETM channel 0-7 |
| 31 | `ds_info_valid` | direction split |

Two readers consume it. On the **software** TX path, `dpa_tx()` resolves a
class — from the Tx queue the qdisc chose, else from `pfe_eth_get_queuenum()`,
else from the DSCP map — and `cpe_fp_tx()` turns it into a CEETM FQ. On the
**hardware** path, `insert_entry_in_classif_table()` passes `&entry->qosmark` to
`dpa_get_tx_info_by_itf()` (`cdx/cdx_ehash.c:1100`), which reaches
`cdx_get_txfq()` and bakes the resulting CEETM LFQID into the classifier entry's
action. From then on the FMAN enqueues straight to a CEETM class queue and the
hardware scheduler shapes the flow with no software involvement at all.

This union is the *hardware* mark format and it stays. What fed it used to be
`ct->qosconnmark`, a 64-bit ASK-added field on `struct nf_conn` set by an
`iptables -j QOSCONNMARK` target — low 32 bits the original direction, high 32
the reply, gated by bit 63. Increment 7 removed it; the key is now `ct->mark`,
decoded by `ft_qos_class()` in the flowtable adapter. Grep results conflate the
two names, so read each site: `union ctentry_qosmark` is not the ASK mark.

## Why a flowtable flow has no QoS today

Three reasons, all deliberate, all in the current tree.

1. `ask_flowtable.c:562` refuses admission outright when
   `READ_ONCE(cls->nf_ct->mark)` is nonzero. Marked flows fall back to software.
2. `cdx_ft_hw_add()` (`cdx/cdx_flowtable_hw.c:39`) `kzalloc`s its `CtEntry` and
   never writes `entry.qosmark`. Every admitted flow therefore encodes
   `chnl_id = 0, queue = 0`.
3. `priv->ceetm_en` only becomes true on `CMD_QM_QOSENABLE`
   (`cdx/cdx_ceetm_app.c:1130`), which nothing sends, because `cmmqos` ships
   disabled. With it false, `cdx_get_txfq()` returns `fwd_tx_fqinfo[0]` and
   CEETM is bypassed entirely.

So QoS is dormant end to end. Retiring it today costs no shipped behaviour — it
costs a capability. That is what makes staging possible.

It also hides a trap. Enable QoS and `qosmark == 0` sends **every** unmarked
flow to `fls(chnl_map) - 1` — the channel `ceetm_get_egressfq()` calls "least
prio" — class queue 0, which `GET_CEETM_PRIORITY` maps to CEETM queue 7, the
*lowest* priority strict queue. This is a property of the mark encoding rather
than of the flowtable: the software path reaches the same queue for a
conntracked unmarked flow. Only bare control traffic escapes it, because
`pfe_eth_get_queuenum()` returns `QOS_DEFAULT_QUEUE = 7` when there is no
conntrack at all, which inverts to CEETM queue 0, the highest. Any design must
name an explicit default class rather than let zero mean "wherever zero lands".

## Design

### Classification: the only genuinely new mechanism

Everything else is a control-channel swap. This is the one place where the
flowtable needs a concept it does not have.

Upstream gives us nothing to build on. `nf_flow_table_offload.c` emits exactly
seven action types — mangle, checksum, redirect, VLAN push/pop, PPPoE push,
tunnel encap/decap — and none of them expresses priority or queue. There is no
`FLOW_ACTION_PRIORITY` in a flowtable rule and no queue field on
`struct flow_offload`. The only channel available is the conntrack entry, and
the adapter already holds it: `cls->nf_ct` at `ask_flowtable.c:453`.

**Use the standard `ct->mark`, not `ct->qosconnmark`.**

A direction needs 3 bits of channel and 4 bits of class queue. Two directions
need 14. `ct->mark` is `u32` and already manipulated by nftables (`ct mark set`)
and by every OpenWrt QoS package in existence. The 64-bit ASK field exists only
because the original design wanted room it never used — `vlan_pbits` is dead.

Scope the first increment to **egress class only**. Adding `iqid` costs another
4 bits per direction and `dscp_mark` another 7, which together would claim 22 of
32 bits and leave too little for the firewall and `mwan3` to share. Ingress
policing and DSCP remarking are separate increments with their own bit budget
argument; neither is configured in the shipping product today.

Concretely:

- `struct cdx_ft_rule` gains a `u32 qos` field. It is part of the key, so a mark
  change produces a different rule and `ft_replace`'s `memcmp` reinstalls it,
  exactly as the IPv6 widening reached every index at once.
- `ft_parse` replaces the zero-mark refusal with a decode under a configured
  mask, so the mark can be shared with `mwan3` and firewall policy routing the
  way `fwmark` masks are shared everywhere else in OpenWrt. The policy tool
  already reserves a `mark: {value, mask}` selector
  ([policy](flowtable-policy.md)), so the schema does not move.
- Direction comes from `ft_tuple_matches(out, orig)`, which `ft_translation`
  already computes for the NAT case and which is cheap to compute for all flows.
- `cdx_ft_hw_add` writes `ct->qosmark.chnl_id` and `.queue`. Nothing else in the
  hardware path changes: the existing encoder already resolves them to an LFQID.

**The contract to state explicitly:** the mark is sampled once, at admission.
Once `IPS_OFFLOAD` is set, `nft_flow_offload` stops seeing the flow's packets, so
a later mark change cannot move an offloaded flow. This is correct for the normal
case — marking happens in mangle/PREROUTING on the first packets, before the
flowtable admits anything — but it must be documented, and a controller that
wants mid-flow reclassification has to call `flow_offload_teardown()`. Hooking
`IPCT_MARK` is not a good answer: the conntrack event notifier is a single
per-net slot already held by `ctnetlink`.

The payoff beyond QoS: this retires `patches/kernel/060`, the four files in
`iptables-extensions/`, and `CONFIG_NETFILTER_XT_QOSMARK`/`_QOSCONNMARK`.

The DSCP→FQ map is **not** a viable alternative. Its fast-path table is a single
global (`dscp_fq_map_ff_g`, `cdx/cdx_ehash.c:168`) keyed on one `port_id`, so it
can classify egress on exactly one port at a time. A gateway shapes both
directions.

### Scheduler configuration: swap the transport, keep the hardware layer

Three options, in increasing order of how much they change.

**A — hand the tree to the SDK's `tc ceetm` qdisc.**
`sdk_dpaa/dpaa_eth_ceetm.c` is a complete classful qdisc (`type root|prio|wbfs`)
that builds the same objects through the same `qman_ceetm_*` API, and
`CONFIG_FSL_DPAA_CEETM` is currently `not set`. Enabling it gives a standard
control plane and `tc -s class show` statistics for free.

It is the wrong trade, for four reasons that compound.

*It cannot coexist with cdx on the same interface.* Both derive an index from
the netdev's TX channel and call `qman_ceetm_sp_claim` and
`qman_ceetm_lni_claim` against the same global lists, so the second claimant
fails. Worse, cdx bypasses `qman_ceetm_channel_claim` entirely — it calls the
raw `qman_alloc_ceetm0_channel()` (`cdx/cdx_ceetm_app.c:770`), hand-rolls the
`qm_ceetm_channel`, issues its own `CEETM_COMMAND_CHANNEL_MAPPING` and does its
own `list_add_tail(&channel->node, &lni->channels)`. Both sides would push
structurally different, separately allocated nodes onto the same list, each
invisible to the other's teardown. And `priv->ceetm_en` is one bool with no
ownership: either side disabling it reverts the interface to the non-CEETM TX
path while the other's queues stay claimed.

*Its TX path is unreachable.* `dpa_tx()` under `CONFIG_CPE_FAST_PATH` returns
`cpe_fp_tx()` before the `ceetm_tx()` branch (`dpaa_eth_sg.c:2026`). Enabled
today, the qdisc would accept `tc qdisc add … ceetm`, claim real hardware,
report statistics, and shape nothing.

*It solves none of the classification problem.* Its classifier is
`tcf_classify()` on an skb, which an offloaded flow never produces.

*It is narrower than what it replaces.* cdx puts all eight WBFQ queues in group
A and never claims group B; the qdisc's own model is 4-8 per group. Neither has
the per-class-queue FMAN policer that ASK calls "cqshaper", and the qdisc has no
DSCP map.

Against that, adopting it means retiring roughly 2,000 lines of hardened code —
A21, A109, A122 and A133 all live in `cdx_ceetm_app.c` — in favour of 55k of
SDK code that is compiled out of every current build.

**B — keep `cdx_ceetm_app.c`, replace FCI with `ndo_setup_tc` HTB offload.**
`TC_SETUP_QDISC_HTB` is the mainline-blessed verb for this shape and is what
mlx5 uses for hardware queue trees. The parameter mapping is clean: `rate` and
`ceil` are shaper rates, `prio` picks a strict-priority class queue and
`quantum` a weighted one. Which level of the tree owns which is settled in
[increment 3](#3-htb-offload-commands), where it was built.
Tail-drop depth has no HTB field and stays a per-port default. The callback has
everything it needs already: `priv->qm_ctx` is stashed at netdev registration
(`cdx/control_qm.c:518`), and every cdx setter — `ceetm_configure_shaper`,
`ceetm_configure_wbfq`, `ceetm_configure_cq`, `ceetm_assign_chnl`,
`ceetm_enable_or_disable_qos` — is already a thin function over a plain
`(channel, classque)` index pair. The FCI handlers do nothing but resolve an
ifname and call them.

Two real constraints.

**HTB offload binds a leaf class to a netdev TX queue, and this driver has no
per-queue plumbing at all.** `TC_HTB_LEAF_ALLOC_QUEUE` returns a `qid` that
`sch_htb` turns straight into `netdev_get_tx_queue(dev, qid)` and grafts a
pfifo onto (`net/sched/sch_htb.c:1909`); there is no bounds check on that path,
so a bad qid is out-of-bounds memory rather than an error. The driver must
therefore own a dense, exclusively-allocated range below
`real_num_tx_queues` and resize it on every leaf add and delete. Today
`sdk_dpaa` has none of the machinery that implies: no `ndo_setup_tc`, no
`NETIF_F_HW_TC`, no `ndo_select_queue` (the one in `dpaa_eth.c:696` is
`#ifdef CONFIG_FMAN_PFC`, which is off in every build), no
`netif_set_real_num_tx_queues` call, no per-queue stop/wake, no BQL and no XPS
maps. `real_num_tx_queues` is fixed at probe to `DPAA_ETH_TX_QUEUES`, which is
literally `NR_CPUS` — 64 under OpenWrt, 16 under meta-ask. A leaf budget that
varies with a distribution's kernel config is not a contract, so that has to be
decoupled from `NR_CPUS` regardless of which control plane wins.

**Only eight weighted classes are available**, because cdx claims WBFS group A
only and never group B (`qman_ceetm_cq_claim_A`, `cdx/cdx_ceetm_app.c:548`). A
tree wider than eight weighted leaves per channel needs group B claimed first.

Every hardened path survives; only the transport changes. The control plane
becomes `tc class add dev eth3 parent 1: classid 1:10 htb rate 100mbit ceil
900mbit prio 2`, and the `cmmqos` UCI schema can be kept verbatim with its
renderer retargeted from `cmm -c` to `tc` — no product-surface change at all.

**C — a small userspace tool speaking the existing FCI commands.**
A tool of a few hundred lines writing the same `CMD_QM_*` structures removes CMM
from the QoS path with no kernel change to the hardware layer.

This option was originally written up as needing no kernel change at all, on the
claim that the QM family is not sealed in flowtable mode. **That was wrong**, and
[increment 8](#the-gap-nothing-can-set-the-rates) records how it was found:
`comcerto_fpp_send_command()` refuses every family when
`cdx_flowtable_enabled()`, and `/dev/cdx_ctrl` carries three ioctls, none of them
a QM command. C in flowtable mode needs the seal opened first.

**Recommendation: B, with the mark kept as the single classification key.**

C looks attractive because it needs no kernel change, but that advantage does
not survive contact with how the product is built. ASK is a dependency of its
distributions, not a peer of them: each consumes whatever ASK exposes, and each
has to be adapted to the flowtable regardless. Landing C would buy no earlier
product capability and would cost every consumer two adaptations — one to C's
bespoke tool, one to `tc` — for the same feature. C keeps its value only as a
bench fixture for exercising CEETM before the `ndo_setup_tc` work lands, which
is exactly how the increment-1 proof below uses it.

A is not worth its risk at any point.

### Why HTB offload does not classify

The obvious reading of B is wrong, and it is worth stating so nobody
re-discovers it. HTB offload's own model is "a leaf class *is* a netdev TX
queue": a `tc` filter sets the queue mapping, the packet lands on that queue's
pfifo, and the driver reads `skb_get_queue_mapping()`. Adopting that model
wholesale would classify the *software* path by tc filter while the hardware
path continues to classify by the conntrack mark — two sources of truth for one
flow's class, silently disagreeing whenever an operator updates one and not the
other, and switching over at the moment a flow gets offloaded.

The mark is the only key the two paths can share, because an offloaded flow
produces no skb, reaches no qdisc and touches no TX queue. So the mark stays
the classifier and HTB offload supplies only the *tree*: rates, priorities,
weights, and a stable classid per leaf.

Concretely, `ndo_select_queue` resolves the conntrack mark to the leaf's TX
queue — the same decode `pfe_eth_get_queuenum()` already performs, moved
earlier and expressed as a queue index. `cpe_fp_tx()` then reads
`skb_get_queue_mapping()` and looks up the CEETM FQ through the same
`txq → (channel, class queue)` map that leaf allocation built. The hardware path
resolves the identical pair from the identical mark. One source of truth, two
consumers.

This is also why NXP's own `ceetm` qdisc ignores the TX queue for egress
selection and classifies in `ceetm_tx()` instead. The difference is that a
bespoke qdisc needs `TCA_CEETM_*` attributes that no upstream iproute2 knows,
which fails the portability requirement above. HTB offload's vocabulary ships
everywhere.

### What HTB offload cannot tell you

It has no statistics command. `struct tc_htb_qopt_offload` carries no stats
member and `enum tc_htb_command` has no stats verb; per-class counters come
from the software pfifo sitting on the leaf's TX queue
(`htb_dump_class_stats`, `net/sched/sch_htb.c:1341`). Hardware-offloaded flows
never enqueue there, so `tc -s class show` would read approximately zero for
precisely the traffic being accelerated.

Expose the real counters through `ethtool -S` instead. cdx already reads them
(`qman_ceetm_cq_get_dequeue_statistics` and
`qman_ceetm_ccg_get_reject_statistics`, `cdx/cdx_ceetm_app.c:1732` and `:1741`),
the netdev already implements `get_strings`/`get_sset_count`/
`get_ethtool_stats` (`sdk_dpaa/dpaa_ethtool.c:564`), and `ethtool` is as
portable as `tc`. `tc -s class show` then honestly reports the software share
and `ethtool -S` reports what the hardware actually dequeued and rejected.

### Policing

The eight ingress profiles, the per-port fast-forward rate, the exception rate
and the SEC rate are FMAN PCD RFC-2698 profiles attached to keygen results, not
CEETM objects, and they have no qdisc analogue. The nearest Linux verb —
`tc filter … action police` on a `clsact` ingress qdisc — does not map onto a
profile bound to a PCD classification result.

These follow the same C-then-B path as the scheduler. The per-port fast-forward
rate can eventually become a `TC_SETUP_BLOCK` matchall-police; the exception and
SEC rates police the punt and crypto paths, which have no netdev, so they stay a
private knob under whatever control channel plane 1 ends up using.

Which profile a flow's ingress frames meet is a different question from what
that profile's rate is, and the two have been settled separately.
[Increment 8](#8-ingress-policing) delivered the selection as a third nibble of
the class the mark carries. The rates have no surface in flowtable mode at all,
because the QM command family is sealed there; that is an open decision, with
the options and a recommendation recorded with the increment.

One thing not to copy forward, now fixed: CMM validated ingress `cir`/`pir`
against `1..20971250`, a packets-per-second range, while `cdx_qos.c` programs
those profiles in `e_FM_PCD_PLCR_BYTE_MODE`, where the unit is Kbit/s.

## Implementation plan

Eight increments, each with its own proof. Everything is ASK-side; consumers
are adapted once, after increment 5, rather than tracking intermediate control
planes. Estimates assume rig access and are for the increment's own work, not
for review or for a release sweep.

### 1. Classification — the mark reaches hardware

The only increment that is fully traced today, and the only one that delivers
observable behaviour on its own.

`struct cdx_ft_rule` gains `u32 qos`. Two properties fall out of the existing
code with no extra work: `ft_same_key()` (`cdx/ask_flowtable.c:655`) is an
explicit field list, so `qos` stays out of flow identity and two marks cannot
collide as duplicate keys; and `ft_replace()` compares whole rules with
`memcmp`, so a mark change reinstalls the flow. `ft_parse()` already
`memset`s the struct (`:582`), so the added field is padding-safe.

- `cdx/cdx_flowtable_backend.h` — add the field, document it as the decoded
  `(channel, class queue)` pair rather than the raw mark.
- `cdx/ask_flowtable.c` — narrow the refusal from "any mark" to "any bit
  outside the mask", decode under the mask after `ft_translation()` succeeds,
  and report the class in the proc row.

  No direction split is needed. Each direction is admitted as its own rule, so
  the value is already per-direction; both directions simply read one mark. A
  channel nibble of zero resolves to whichever channel the egress port owns, so
  a single class index means "this priority, on whatever port this direction
  leaves by" — which is what a per-port tree wants. Asymmetric classes would
  need a second field and are not in this increment.
- `cdx/cdx_flowtable_hw.c` — write `ct->qosmark.chnl_id` and `.queue` in
  `cdx_ft_hw_add()`.
- `tools/ask_flowtable.py` — render the guard from the mask the running
  adapter reports rather than restating a constant, which moves the render
  inside the lock because only a live backend knows the mask. Policy `mark`
  selectors keep their existing "representable for migration" status; making a
  dead selector an error would regress that.

Two decisions belong to this increment. The **mask** is a `0444` module param,
matching `offload_owner`'s boot-immutable shape, and zero means classification
is off and every marked flow is refused — the historical contract, byte for
byte. The **default class** is explicit: an unmarked flow resolves to CEETM
queue 7, the lowest strict priority. That is the right answer for best-effort
traffic, but only once it is chosen rather than inherited from `kzalloc`.
Both are validated at load, because a boot-immutable parameter has exactly one
moment to be rejected out loud.

*Proved on hardware, 2026-09-17.* Booted `ask.offload=flowtable` with
`ask_flowtable.qos_mark_mask=0xf0` on the KASAN image, and marked every
forwarded flow `ct mark 0x30` from an nftables chain at forward/mangle. Four
flows installed, every one reporting `qos=03` — the class that mask and mark
decode to — and a TCP transfer through them ran 27.4 GB at 9.41 Gb/s. Under
the previous code each of those flows was refused outright for carrying a
nonzero mark, so admission, decode and the write into the hardware entry are
all exercised by that one result. The scoped UDP SNAT offload tests pass with
the same mask and marks live.

What this does *not* show is shaping: `priv->ceetm_en` is false without
`CMD_QM_QOSENABLE`, so the class selects among unshaped forwarding FQs rather
than CEETM class queues. That is increment 3's job.

*Remaining proof.* `tools/tests/test_qos_control.py` already
queries all 128 class queues over `CMD_QM_QUERY_QUEUE` and reads back their
fqids; the same reply carries `deque_pkts` and `frm_count`. The test enables
CEETM over FCI — the bench use of option C — assigns a channel, drives two
differently-marked flows, and asserts the dequeue counters split. Add a
negative case: a mark outside the mask must not change the class.

*Effort: 2–3 days including rig time.*

### 2a. TX queue foundation

Nothing in `sdk_dpaa` supports a per-queue model yet, and the gaps are
structural rather than incidental. Delivered as
`patches/kernel/150-sdk_dpaa-tx-queue-headroom.patch`.

- `DPAA_ETH_TX_QUEUES` was literally `NR_CPUS` (`dpaa_eth.h:201`) — 64 queues
  under OpenWrt, 16 under meta-ask. Pinned at sixteen, which is what the more
  constrained of the two already ran, so the test image's Tx path is unchanged
  and the other moves down to a count already in service. Still a power of
  two, because the Tx paths index `conf_fqs[]` with `& (N - 1)`.

  These are only the queues the CPU sends through; an offloaded flow reaches
  none of them, so the count says nothing about offload capacity. It is not
  derived from the core count either: with no XPS maps in this driver,
  `netdev_core_pick_tx()` falls through to `skb_tx_hash()`, so a queue is
  chosen by flow hash rather than by CPU. The count trades qdisc contention
  between concurrent software senders against the frame queues each one costs.
- `DPAA_ETH_CEETM_LEAF_QUEUES` reserves sixteen more, allocated up front by
  `alloc_etherdev_mq()`, because `sch_htb` turns a returned qid straight into
  `netdev_get_tx_queue()` with no bounds check.
- `netif_set_real_num_tx_queues()` narrows the usable set to the direct
  queues, which the driver never called at all. Ordinary traffic therefore
  cannot hash into the reserved range, and a qdisc sees an honest count of
  the queues that already existed.
- `cdx/control_qm.c` asserted the CEETM class-queue count against
  `DPAA_ETH_TX_QUEUES`, which held only because both were sized from
  `NR_CPUS`. It now asserts against the leaf headroom, which is the invariant
  that actually matters.

*Proved on hardware, 2026-09-17.* `eth3` reports sixteen Tx queues, and the
count no longer differs between the two kernel configurations. The test image's
count is unchanged by design, so what the rig exercises is what it ran before;
OpenWrt's reduction from sixty-four is still unverified.

### 2b. `ndo_setup_tc`, and why it is not in 2a

`NETIF_F_HW_TC` and an `ndo_setup_tc` that dispatches to cdx look like part of
the same increment, and they are not, because adding the ndo silently moves
the *flowtable* onto a path cdx does not implement.

`nf_flow_table_offload_setup()` chooses its binding by presence, not by
capability:

```c
if (dev->netdev_ops->ndo_setup_tc)
        err = nf_flow_table_offload_cmd(...);      /* direct */
else
        err = nf_flow_table_indr_offload_cmd(...); /* indirect */
```

The adapter registers with `flow_indr_dev_register(ft_bind, NULL)`, so the
moment the DPAA netdev grows an `ndo_setup_tc` — for HTB, for anything — every
flowtable bind takes the direct branch and `ft_bind` is never called again.
Acceleration would stop, with no error anywhere.

Migrating is not a redirect, but it needs no kernel change to carry the
context, which a first reading of this got wrong. `ft_bind` takes the
`struct nf_flowtable *` as its own argument and needs it for binding identity
and the `use_neigh`/`use_hw_handles` writes. The direct path passes only a
`flow_block_offload` — but `nf_flow_table_block_offload_init()` sets
`bo->block = &flowtable->flow_block`, so the owner is recoverable with
`container_of`. Patch 140 is not involved.

What the two routes genuinely disagree about is smaller and sharper, and
neither half is visible to a compiler:

- **Locking.** The indirect route calls the driver *before* `block_setup`
  takes `flow_block_lock`, so `ft_bind` takes it itself on UNBIND. The direct
  route already holds it across the whole of `ndo_setup_tc`, for both
  commands (`nf_flow_table_offload_cmd`), so taking it there deadlocks on a
  non-recursive rwsem at the first unbind.
- **Callback helpers.** `flow_block_cb_alloc`/`_remove` rather than the
  `flow_indr_` pair.

So `ft_bind`'s body became `ft_block_setup`, shared by both routes and
differing only in those two places, with `ft_bind` and `cdx_ft_setup_tc` as
the entry points. Both registrations are kept: which route Netfilter uses is
the driver's choice, and a kernel without the ndo has only the indirect one.

One consequence worth stating. Because Netfilter selects on the ndo's mere
presence, from the moment this driver offers one, a hardware flowtable bind
with no handler registered is *refused*, where before it was served. The
adapter registers at init and the window is a boot-time one, but a kernel
carrying this patch without the adapter loaded is a configuration that now
declines `flags offload` flowtables on these ports.

*Proved on hardware, 2026-09-17.* `ethtool -k eth3` reports `hw-tc-offload:
on`, and with the ndo present a policy still binds — `bindings: 2`, so
Netfilter took the direct route and the adapter served it — and `ask-flowtable
stop` returns 0 with bindings back to zero, so the unbind does not deadlock on
the rwsem its caller already holds. Those were the two failures a build cannot
show, and neither occurred. A KASAN boot reported nothing beyond its own init
banner.

*Effort: 1 week for 2a and 2b together.*

### 3. HTB offload commands

The command set, in `cdx/cdx_htb.c`, over `cdx_ceetm_app.c`'s existing setters.
Nothing new is claimed: `ceetm_init_channels()` builds every channel, class
queue and logical FQ at module load, so a tc class only ever decides which
`(channel, class queue)` pair it means.

**The tree maps onto the hardware's own three levels.**

| HTB | CEETM | parameters |
| --- | --- | --- |
| qdisc root | the port, that is its LNI | `default` is recorded, and advisory until increment 4 |
| class under the root | a channel bound to that port | `rate` → committed shaper, `ceil` → ceiling |
| class under one of those | a class queue on that channel | `prio` → one of eight strict-priority queues, `quantum` → the weighted group instead |

A class under the root that has no children is both: it holds a channel and
occupies one class queue on it, because `sch_htb` gives every leaf a netdev Tx
queue and expects frames to reach it. `TC_HTB_LEAF_TO_INNER` is where it stops
being a queue and becomes only a channel, handing the child both its Tx queue
and its place on the channel. A third level is refused — there is no fourth
level in CEETM to put it on.

Two mappings are worth stating because they are not the obvious reading.

**`ceil` is a ceiling, and the hardware's two token buckets are additive.** A
class queue eligible for both transmits against the committed rate and then
again against the excess one, so the channel's output approaches their sum;
the excess rate to program is `ceil - rate`, not `ceil`. Measured before the
correction: a class given `rate 200mbit ceil 200mbit` ran at 376 Mbit/s.
The channel shaper is also coupled, so committed tokens a class does not use
top up its excess ones, which is what makes borrowing up to `ceil` behave the
way HTB describes it. The SDK's own CEETM qdisc couples the same shaper.

**`quantum` is a weight, not a byte count.** CEETM's weighted scheduler takes a
weight of 1 to 255; there is no byte-deficit round robin to give a quantum to.
A leaf that names one asks to share bandwidth at its priority level rather than
to pre-empt, which is the weighted group; a leaf that does not gets a
strict-priority queue of its own, and asking for a priority another class holds
is an error rather than a silent demotion. A leaf's own `rate` and `ceil` have
no hardware behind them — CEETM shapes channels, not queues — so what a leaf
can change is where it sits among its siblings.

**Registration moved into `cdx.ko`.** A driver takes one `ndo_setup_tc`
handler, and CEETM belongs to cdx, which is loaded in both ownership modes
while the flowtable adapter is loaded in one. So cdx claims the ndo and
dispatches: `TC_SETUP_QDISC_HTB` to this file, `TC_SETUP_FT` on to the adapter
through a registration of its own, `TC_SETUP_ROOT_QDISC` acknowledged because
it is a notification and refusing it makes every successful `tc qdisc add`
report a failed graft. The window increment 2b described is unchanged: a bind
arriving with no adapter registered is still refused.

Some things the contract makes sharp:

- `LEAF_DEL` writes back a different classid to report that the driver moved a
  qid, which is how the range stays dense in its sixteen slots per port.
- `TC_HTB_DESTROY` and `LEAF_DEL_LAST_FORCE` have their return values
  **discarded**, so teardown reports trouble and keeps going rather than
  stopping at the first failure.
- `real_num_tx_queues` deliberately stays at the direct queues. Growing it
  would let ordinary traffic hash onto a leaf's queue, and nothing in the
  software Tx path reads that index yet — with CEETM on, `cpe_fp_tx()` resolves
  its frame queue from the mark. Increment 4 owns that, and grows the count
  when it is true.
- A channel a class gave up stays bound to the port and is handed to the next
  class under the root, rather than detached and rebound: detaching a live
  channel means draining it while frames are still being classified onto it.
  Channels return to the global pool at `TC_HTB_DESTROY`.
- Leaf class queues get a tail-drop depth of 128 frames rather than the
  hardware layer's default of eight, which is far too shallow for a queue that
  is deliberately being shaped. Increment 6 replaces tail drop with WRED.

Limits, all of them the hardware's: eight channels for the whole SoC shared by
every port, eight weighted leaves per channel until WBFS group B is claimed
(`qman_ceetm_cq_claim_A`), eight strict priorities, sixteen leaves per port,
and two levels. `tc qdisc replace` on a port that already has one is refused,
because `sch_htb` creates the new qdisc before destroying the old; delete and
add instead. mlx5 refuses the same sequence.

Two defects in the hardware layer had to be fixed for any of this to work
twice, both filed as A143 and A144 and both reachable from CMM as well:
enabling QoS drove an already-shaped channel's excess rate to zero, starving
every class queue on it, and disabling QoS left the LNI shaper enabled, so a
port could only ever be enabled once. `tools/host_tests/test_ceetm_qos_enable.py`
cycles the pair and fails on either.

*Proved on hardware, 2026-09-17.* Both ownership modes, on the KASAN image.

Under `ask.offload=cmm`, with no flowtable adapter loaded at all,
`tc qdisc add dev eth3 root handle 1: htb offload` and four classes built a
tree that `CMD_QM_QUERY_QUEUE` and `CMD_QM_QUERY` read back as exactly what was
asked for: the port QoS-enabled, channel 0 shaped at 1000000 Kbps, class queues
7 and 6 — CEETM priorities 0 and 1, which is the inversion
`GET_CEETM_PRIORITY` applies — at depth 128, and class queue 8, the first of the
weighted group, carrying the weight 4 that `quantum 4` asked for. The other 125
stayed at their defaults. Deleting a class in the middle and then the qdisc
returned the port to `mq` with sixteen `pfifo_fast`, and the same queries
reported `qos_enabled=0`, no channel claimed, and every class queue back at
depth 8 and weight 1.

Under `ask.offload=flowtable` with `qos_mark_mask=0xf0`, a policy bound through
the moved registration (`bindings 2`), and every offloaded flow carried the
class its mark named. A qdisc built, torn down and built again on the same port
succeeded both times, which is the A144 case. Shaping followed `tc`:

| tc | measured |
| --- | --- |
| unshaped | 9.41 Gbit/s |
| `rate 200mbit ceil 200mbit` | 188 Mbit/s |
| `rate 600mbit ceil 600mbit` | 565 Mbit/s |
| `rate 200mbit ceil 800mbit` | 753 Mbit/s |

Each is the ceiling less TCP's header share, and the last two came from
`TC_HTB_NODE_MODIFY` on a live tree. With two classes on one 200 Mbit channel
and two marks, `/proc/cdx_flowtable` showed six flows at `qos=06` and six at
`qos=07` — the two classes the two marks name — and the strict priority between
them is unambiguous: the `prio 0` flow took 188 Mbit/s and the `prio 1` flow
0.00 bit/s. **That is the first point at which QoS genuinely shapes.** No
KASAN, BUG, WARNING or lockdep output in either boot.

*Effort: 1.5–2 weeks.*

### 4. The software path agrees with hardware

The driver grows a second pair of callbacks, `struct dpa_qdisc_ops`, registered
by the same module that hands out leaf classes and published as one pointer so
a frame never sees one without the other.

- `ndo_select_queue` asks which leaf a frame belongs to and puts it on that
  leaf's Tx queue.
- `cpe_fp_tx()` reads the class back out of the queue index instead of
  resolving the frame's mark a second time.

**The decode is one function, not two that agree.** The plan above said this
reused what `pfe_eth_get_queuenum()` does, and that was wrong in a way worth
recording: that function reads `ct->qosconnmark`, the ASK mark, while the
flowtable classifies on `ct->mark` under `qos_mark_mask`. Two fields, two
encodings. So the adapter registers `ft_qos_class()` itself with cdx, and the
software path calls the very function that gave the flow's hardware rule its
class. Deriving the same answer twice would still be two things to keep in
step.

That registration is also the switch. With no classifier registered — every
CMM port, because the adapter is not loaded there — queue selection expresses
no opinion and `cpe_fp_tx()` resolves its frame queue exactly as it did before
any of this existed. Enabling a qdisc under CMM therefore builds a tree without
changing how a frame reaches it.

`real_num_tx_queues` now grows as leaf classes come into service, because
`netdev_cap_txqueue()` rewrites anything at or above it to queue zero. What
keeps ordinary traffic off the range is not the count but the driver: a frame
that named no class keeps the stack's own choice — socket affinity and XPS
included — folded back below the leaf base. A leaf queue is reachable only by
naming its class.

The maps the Tx path reads are plain byte arrays rebuilt under RTNL after every
change to the tree, rather than a walk of the class list, because that list is
mutated under RTNL while frames are reading it. A reader racing a rebuild sees
an old byte or a new one, never a freed node.

**The `conf_fq` index is fixed here too**, as the plan intended. `cpe_fp_tx()`
indexed `conf_fqs[]` with `queuenum`, which in the CEETM branch is a class-queue
id and not a Tx queue at all: a DSCP-classified frame, whose `queuenum` is
always zero, confirmed on `conf_fqs[0]` whichever core sent it, and a marked one
confirmed on whichever conf queue its class happened to number. Filed as A145.
It is a pre-existing defect rather than a consequence of this work, but the
correct index — the queue the frame actually left by — is the one this increment
makes meaningful.

*Proved on hardware, 2026-09-17.* One flow, forced through software and then
offloaded, on the KASAN image with a `rate 400mbit` class and a mark naming it.

Software first, with the policy unbound so nothing is accelerated:
`tc -s class show dev eth4` counted **93,465,296 bytes in 61,760 packets on
class 1:10** — the class the mark names. Before this increment that counter read
zero, because the frame went to a direct queue and never reached the leaf's
qdisc. Then the same flow offloaded: throughput went to 376 Mbit/s, every entry
reported `qos=07` — the same class — and the qdisc counter moved by 486 bytes in
7 packets, which is the handshake that still goes through software. Hardware
bypasses the qdisc entirely and lands on the class the software path chose.

The shaper holds at rates only the hardware path can reach, which is what makes
a capped measurement proof of both at once — software forwarding on this rig
tops out near 130 Mbit/s:

| tc | measured |
| --- | --- |
| unshaped | 9.41 Gbit/s |
| `rate 2gbit ceil 2gbit` | 1.88 Gbit/s |
| `rate 5gbit ceil 5gbit` | 4.71 Gbit/s |
| `rate 8gbit ceil 8gbit` | 7.53 Gbit/s |

Each is within about 1.5% of the ceiling less TCP's header share, and the last
two came from `TC_HTB_NODE_MODIFY` on a live tree. `eth4` reported seventeen Tx
queues with one leaf class and sixteen again after teardown. Under
`ask.offload=cmm`, with no adapter loaded, the port still forwarded at
9.38 Gbit/s and stayed at sixteen queues — the path this increment leaves
alone. No KASAN, BUG, WARNING or lockdep output in either boot.

*Effort: 3–4 days.*

### 5. Hardware statistics through ethtool

The existing `get_strings`/`get_sset_count`/`get_ethtool_stats` gain dequeued
frames, dequeued bytes and rejected frames per leaf class, read through a third
callback on the `struct dpa_qdisc_ops` increment 4 introduced.

Two things decide the shape.

**The count has to be a constant.** ethtool fetches the names and the values in
separate ioctls, so a count that moved with `tc class add` would leave userspace
lining one up against the other. There is therefore one set of counters per leaf
*slot* — sixteen, always — rather than per class in the tree, and a slot no class
holds reads zero. The driver answers even with no module registered, so the
number does not change when cdx loads either. The name carries the slot, and
leaf *N* is Tx queue `DPAA_ETH_TX_QUEUES + N`, which is what
`TC_HTB_LEAF_QUERY_QUEUE` answers for a classid.

**The counters are read without `QMAN_CEETM_FLAG_CLEAR_STATISTICS_COUNTER`**, so
repeated reads report totals rather than deltas. They have one owner in
hardware and `CMD_QM_QUERY_QUEUE` can clear them, which moves the baseline
underneath anyone else reading; a statistics call that cleared them would make
every other reader wrong.

*Proved on hardware, 2026-09-17.* A `rate 3gbit` class on `eth4`, a marked flow
through it, on the KASAN image. `ethtool -S` counted **1,951,317 frames,
2,954,241,583 bytes and 17,727 rejected** on leaf 0 where `tc -s class show`
counted **766 bytes in 11 packets** — the handshake, and nothing else, because
an offloaded flow never enqueues on the leaf's software qdisc.

The two account for the same traffic. iperf3 received 2.63 GBytes of TCP
payload; the frame bytes ethtool reports are 4.6% more, which is 1514/1448 —
the Ethernet, IP and TCP headers that payload does not count. The frames divide
into the bytes at exactly 1514, so every one was full-size. And the rejected
count is the shaper doing its job: 17,727 frames tail-dropped holding the flow
to its 3 Gbit ceiling, which no `tc` counter can see at all.

Read twice with no traffic in between, the values were identical — totals, not
deltas. `eth4` reported 48 CEETM counters before the tree existed, with it live
and after `tc qdisc del`, and leaf 0 read zero once no class held it. No KASAN,
BUG, WARNING or lockdep output.

*Effort: 2–3 days.*

**Consumers can be adapted from here.** Everything after this point improves
the offering rather than enabling it.

### 6. WRED

The CCG carries `wr_en_g/y/r` and `wr_parm_g/y/r` and always has. Nothing ever
wrote them: cdx touched those fields zero times, and the CQ configuration
command CMM can send carries four flags — shaper eligibility, weight, tail-drop
threshold, policer rate — with no WRED among them. So this is not a CMM feature
being ported. It is capability the hardware shipped with that no control plane
ever reached, which also means there is no parity bar to clear: nothing can
regress, because nothing used it.

**The control surface is `tc ... red` on a leaf class**, offloaded through
`TC_SETUP_QDISC_RED`. It is the only vocabulary in tc for what the congestion
group does, it ships everywhere, and sch_red hands the driver the class the
qdisc was grafted under — which is exactly the class queue whose congestion
group it configures. A RED qdisc anywhere else is refused rather than quietly
kept in software, because an offloaded flow would never reach it.

ECN is refused too. This hardware drops; it cannot mark. Accepting `ecn` would
answer a request to mark by dropping instead.

**Converting the curve is the whole of the work.** RED says "start dropping at
min, reach probability P at max". The CCG says "reach P at MaxTH, getting there
at Slope", so the minimum is implied rather than stored, and all three fields
are separately encoded mantissa-and-exponent. Two things that look like details
are not:

- the probability has to be taken back *out* of `Pn` before the slope is drawn
  from it, because `Pn` steps in quarters of a 256th and a slope drawn to the
  asked-for top puts the implied minimum somewhere else entirely;
- the slope has to be drawn to the `MaxTH` the field actually holds, not the one
  requested, because `MaxTH` rounds down to an eight-bit mantissa and on a band
  that is narrow beside its own depth that rounding is most of the band.

Both were caught by `tools/host_tests/test_ceetm_wred.py`, which asserts the
invariant that matters — the curve's *implied minimum* lands back on the
minimum that was asked for — across seven shapes rather than checking that each
field round-trips.

Tail drop moves to counting bytes along with the curve, because RED names its
thresholds in bytes and the offload carries no average frame size to convert
them with, and because one mode covers both so they cannot disagree about the
unit. RED's `limit` becomes the tail-drop threshold. Without a RED qdisc a leaf
keeps the frame-counted default from increment 3.

**Congestion-state notification stays off**, which settles the question this
increment was asked to decide. Nothing consumes a notification: there is no CSCN
handler and `cscn_targ` is never set, so enabling it would deliver events to a
portal with no consumer. The visibility gap it was meant to close is closed
instead by increment 5 — the rejected-frame counter is the observable, and a
counter costs nothing where an interrupt would.

*Proved on hardware, 2026-09-17.* A `rate 500mbit` class on `eth4`, an offloaded
bulk flow saturating it, and a ping through the same class as the sparse flow —
software-forwarded, because ICMP is not offloadable, so the two paths increments
3 and 4 built share one class queue.

| leaf class queue | ping avg | ping max | sparse-flow loss | frames rejected |
| --- | --- | --- | --- | --- |
| tail drop only | 3.359 ms | 3.658 ms | 6.7% | 3,194 |
| `min 60000 max 150000 probability 0.02` | 2.448 ms | 3.161 ms | 0% | 4,245 |
| `min 20000 max 60000 probability 0.02` | 1.646 ms | 1.930 ms | 0% | 8,112 |
| `min 20000 max 60000 probability 0.20` | 1.428 ms | 1.870 ms | 0% | 3,512 |
| `min 5000 max 20000 probability 0.02` | 1.298 ms | 4.108 ms | 6.7% | 18,302 |

The baseline is bufferbloat, and measurably so: 128 frames of 1514 bytes drained
at 500 Mbit is 3.1 ms, and the queue sat full at 3.36. WRED halves that and
takes the sparse flow's loss to zero — tail drop was hitting the ping, and early
random drops hit the bulk flow instead, which is the entire point.

Latency falls monotonically as the band tightens and rejections rise with it,
across a twelvefold range of thresholds, which is what says the byte thresholds
land where they were asked to. Raising the probability shortens the queue
*and* drops less, which is the equilibrium moving down a steeper curve rather
than an anomaly. Too tight a band — five thousand bytes is about three frames —
starts dropping the sparse flow again, and is the far edge of useful
configuration rather than a better setting.

What that does **not** establish is the one number the SDK headers give no units
for. `MaxP = 4 * (Pn + 1)` is a fraction of something they never state; 256ths
is the reading under which the field spans exactly 1/64 to 1 across its six
bits, and every measurement above is consistent with it, but consistency across
one probability decade is not the reference manual. It is recorded as
`CEETM_WRED_MAXP_UNITS` with its reasoning attached, and a test fails if either
goes missing.

No KASAN, BUG, WARNING or lockdep output. Removing the RED qdisc returned the
class to its frame-counted tail drop, and tearing the tree down left sixteen Tx
queues and no bindings.

*Effort: 1 week.*

### 7. Retire the ASK mark

`ct->mark` is the classification key; `ct->qosconnmark` is gone, and with it
`skb->qosmark`, the two xtables modules, and the four `iptables-extensions/`
plugins. Increment 1 established the replacement and increment 4 moved the
software path onto it, so this increment is deletion — but it was not the
deletion the plan described, in two ways worth recording.

**The field was never in patch 060.** `nf_conn.qosconnmark`, `IPCT_QOSCONNMARK`,
`CTA_QOSCONNMARK`/`_PAD` and the ctnetlink dump and set paths were all in
**050**, the conntrack-offload patch, whose other contents ASK still needs;
`skb->qosmark` and its `__copy_skb_header` line were in **010**. So three
patches were regenerated surgically rather than one being dropped. What 060
actually carried besides the xtables modules is
`net/netfilter/comcerto_fp_netfilter.c` — the hooks that stamp a conntrack's
`comcerto_fp_info` for cmm, nothing to do with QoS. 060 keeps only those and is
renamed `060-ask-netfilter-fastpath-hooks.patch`.

Removing `IPCT_QOSCONNMARK` also puts `IPCT_SYNPROXY` back on its mainline
value. It had been inserted mid-enum, shifting everything after it.

**The mark was writable after all**, by two paths the survey missed, and both
are now gone:

- `cmmCtChange()` served `CMMD_ACTION_UPDATE` on the IPv4 and IPv6 conntrack
  commands. It wrote the value into conntrack over ctnetlink and re-registered
  the flow, and that write was its only effect, so the action now falls through
  to `CMMD_ERR_UNKNOWN_ACTION`.
- `ffcontrol`'s `ipv4 update` / `ipv6 update` CLI verbs existed to reach it. The
  verbs, their `cmmCtChangeProcess4/6` senders and their dispatch are removed.

So the honest statement is not that nothing could write the mark — it is that
nothing in any shipped configuration did, which the maintainer confirmed.

**cmm keeps compiling and keeps its FCI layout.** `cmmQosmarkGet/Set` are gone
and `cmd.qosconnmark` is simply not filled; the structures `memset` to zero, so
every conntrack command now carries the zero that every shipped build already
carried. The `qosconnmark` field itself stays in `fpp.h` and `cdx/fe.h`, marked
reserved: it is a public header, and renaming it would break source
compatibility for out-of-tree FCI clients for no gain. cdx's side — the
`get_ctentry_qosmark_from_qosconnmark()` decode, `IP_get_qosconnmark()` and
their eight call sites — is removed, because a decode that can only ever
produce zero is worse than no decode. `union ctentry_qosmark` stays: it is the
*hardware* mark format that `cdx_get_txfq()` and `ceetm_get_egressfq()` use, not
the conntrack one.

`pfe_eth_get_queuenum()` loses its conntrack branch and falls through to
`skb->mark & EMAC_QUEUENUM_MASK`, then to `QOS_DEFAULT_QUEUE` — the standard
fallback that was already written beneath it.

**What this costs is one capability: asymmetric per-direction class.** The
64-bit field packed two classes into one word, bit 63 marking the reply half
valid. `ct->mark` is 32 bits and carries one. Recovering it needs no kernel
patch — a second field in `ct->mark` selected by direction, about eight mask
bits and a decode change.

**It also ends per-flow classification in CMM mode**, which is the part to be
deliberate about now that cmm stays in the tree. CMM mode keeps its CEETM
scheduler — the `CMD_QM_*` commands are untouched — but has no classifier, so
every flow lands on the default class. That is what every shipped
configuration already did: `cmmqos` ships disabled, `CMD_QM_QOSENABLE` is never
sent, and with `priv->ceetm_en` false `cdx_get_txfq()` returns
`fwd_tx_fqinfo[0]` and bypasses CEETM entirely. Per-flow QoS lives in flowtable
mode, where `tc` builds the tree and `ct mark` selects the class.

The deliberate non-change is `ATTR_QOSCONNMARK` in the libnetfilter-conntrack
ASK patch, which is now a dead declaration mirroring a kernel attribute that no
longer exists. Removing it means regenerating two patches against upstream
tarballs; filed as **A146**.

*Proved on hardware, 2026-09-17.* See the increment 4 re-run below.

*Effort: 3–4 days.*

### 8. Ingress policing

The class the mark carries now has a third nibble, and it selects one of the
eight FMAN RFC-2698 ingress profiles.

**The selection half is delivered. The rate half has no control surface in
flowtable mode, and that is a decision this increment could not make for
itself** — see below.

`cdx_ft_rule.qos` widens from 8 bits to 12: class queue, channel, ingress
policer, one nibble each.

**The policer nibble is the profile number directly, 0–7, and deliberately
unlike the channel nibble beside it.** The symmetry is tempting and it is
wrong. The channel nibble needs a sentinel because "the port's least-priority
channel" is a real, distinct answer from "channel 1". The policer nibble needs
none, because **there is no "no meter" state to express**: the hardware encoder
starts from profile 0 and only an `iqid`-carrying mark moves it, so profile 0
is what every flow that says nothing has always metered against. It is the
default profile — the one CMM spells `set qm ingress queue default`, which is
literally `queue_no = 0`.

A nibble reserved to mean "none" would therefore select profile 0 anyway and
collide with the nibble naming it. `cdx_ft_hw_add()` copies the nibble into
`iqid` and always raises `iqid_valid`; the bit is not a "policer wanted" flag,
since leaving it clear selects profile 0 just the same.

That makes **profile 0 special for whoever ends up configuring rates**: it is
the one that meters everything which does not say otherwise, so it needs a
defined default rather than being one slot of eight.

*Bit budget.* Twelve bits of a 32-bit `ct->mark` are spoken for, leaving twenty
to the operator's own policy routing or VPN marks. `qos_mark_mask` still places
the field anywhere in the word, and a mask narrower than twelve bits is not an
error: the nibbles it does not cover read zero, which every position spells
"unspecified".

*One hazard, and it is the reason to say this out loud.* The software Tx path
indexes `class_txq[256]` with the decoded class. Widening the decode without
masking would have read up to 3839 bytes past that array on any frame whose
mark named a policer. `cdx_htb_select_queue()` masks with
`CDX_FT_QOS_EGRESS_MASK` before indexing — the policer names an ingress meter
and says nothing about which queue a frame leaves by — and a static assertion
ties the table's size to that mask.

**No tc verb, and no invention.** There is no mainline tc verb for a policer
bound to a PCD classification result: `tc filter … action police` on a `clsact`
ingress qdisc polices a filter's own match, not a profile the keygen result
selects. So this stays a mark field.

#### The gap: nothing can set the rates

This is the part the plan did not anticipate, and it is worth recording
precisely because the doc above got it wrong.

The claim in [option C](#scheduler-configuration-swap-the-transport-keep-the-hardware-layer)
that "the QM command family is *not* sealed in flowtable mode" **is false.**
`comcerto_fpp_send_command()` refuses *every* family when
`cdx_flowtable_enabled()` (`cdx/cdx_cmdhandler.c:208`), `FC_QM` included. And
`/dev/cdx_ctrl` is not a route to the QM commands at all — its table carries
three ioctls, `CDX_CTRL_DPA_SET_PARAMS`, `CDX_CTRL_DPA_INIT_CHECK` and a debug
MURAM read (`cdx/cdx_dev.c`). The FCI commands travel over netlink, which is
the sealed path.

So in flowtable mode the eight profiles cannot be configured, and the two
halves of a proof cannot meet in one boot:

- **flowtable mode** has the classifier but no way to set a rate;
- **CMM mode** can set a rate — `set qm ingress queue <1-7> cir … pir …` — but
  after increment 7 has no classifier, so no flow can select a profile.

Naming an unconfigured profile is harmless rather than a silent drop:
`cdx_get_policer_profile_id()` answers zero unless that profile is enabled, and
the encoder leaves `PREEMPT_POLICE_PKT` clear when it does. The selection is
therefore safe to ship ahead of the surface that configures it.

Three surfaces were weighed and **all three were rejected**, which is worth
recording because two of them look reasonable until a fact kills them.

1. **A module parameter on `ask_flowtable`.** Not a new surface — `qos_mark_mask`
   and the writable `flowtable_fail_stage` are already there. But a private knob
   with a private schema is not a kernel interface, and a consumer still has to
   learn something ASK-shaped.
2. **The policy JSON and `ask-flowtable`.** Same objection: `ask-flowtable` is
   already packaged everywhere, so it costs no packaging, but it is still an
   ASK-private vocabulary.
3. **Unseal the `FC_QM` ingress-policer subcommands.** This one looked strongest
   — one change restores per-port, aggregate and per-flow together, reusing
   handlers, validation and `CMD_QM_QUERY` read-back that already exist and are
   tested. **It does not work.** `fci` is not loaded in flowtable mode at all
   (`rmmod fci` on the DUT answers "not currently loaded"), and the only FCI
   client in the product is cmm, which does not run there either. Unsealing the
   commands would expose a surface nothing can speak; making it speakable means
   loading `fci` and writing and packaging a new FCI client for Armbian,
   OpenWrt and meta-ask. That is a per-consumer porting cost, which is the
   objection that retired option C for the scheduler.

**Decision: offload `FLOW_ACTION_POLICE`.** The scheduler already set the
pattern and it is the one to follow — `tc` for the tree, `ethtool -S` for the
counters, `ct mark` for classification, and no ASK-specific API anywhere. The
ingress meter should arrive the same way:

```sh
tc qdisc add dev eth4 clsact
tc filter add dev eth4 ingress matchall \
    action police rate 500mbit burst 64k conform-exceed drop
tc filter add dev eth4 ingress flower ip_proto udp dst_port 5004 \
    action police rate 20mbit peakrate 25mbit burst 32k conform-exceed drop
```

### Ingress policing through `tc`, in outline

**The mapping is close to one-to-one**, which is what makes this worth doing
rather than tolerating. `flow_action_entry.police` carries `rate_bytes_ps`,
`peakrate_bytes_ps`, `burst`, `burst_pkt`, `rate_pkt_ps`, `mtu` and an
`exceed`/`notexceed` pair of action ids. The hardware profile is
`e_FM_PCD_PLCR_RFC_2698`: CIR, PIR, CBS, PBS, and an action per colour. So
`rate_bytes_ps` is the CIR, `peakrate_bytes_ps` the PIR, `burst` the CBS, and
`exceed.act_id == FLOW_ACTION_DROP` is what `cdx_qos.c` already programs as
`e_FM_PCD_PLCR_DROP_FRAME` on red. Even the mode survives: `rate_pkt_ps` is
packet mode, which these profiles also support.

Only the unit differs. The kernel gives bytes per second; the FMD's byte mode
takes Kbit/s (`GetInfoRateReg()` does `tmp *= 1000`), so the conversion is
`rate_bytes_ps * 8 / 1000` — the same unit confusion that made CMM validate a
packets-per-second range against a byte-mode profile.

**Eight meters is the budget, and finite meters are ordinary.** Profile 0 stays
the default for everything unclassified, leaving seven for distinct police
actions; the SEC profile is numbered separately and is not in this pool. An
eighth distinct action returns `-EOPNOTSUPP` and tc leaves the filter in
software, which is exactly how a driver with finite meters is expected to
behave.

**`TC_SETUP_BLOCK` is not handled today** — `cdx_setup_tc()` answers HTB, RED,
`TC_SETUP_ROOT_QDISC` and `TC_SETUP_FT`, and everything else falls to
`-EOPNOTSUPP`. That is the entry point this work adds.

**The one hard part is binding a filter to a flow.** `action police` attaches to
a *tc filter*; the FMAN selects a profile per *flowtable entry*, through the
`iqid` in that entry's own action. The two are created by different subsystems,
so something has to decide that a given admitted flow falls under a given
filter. Two stages, and the first needs none of it:

- **Stage 1 — `matchall`.** A port-wide meter needs no correlation at all: every
  flow on the port uses it. This restores the per-port fast-forward rate as a
  kernel verb, and is the whole of what most deployments want. **Delivered.**
- **Stage 2 — `flower`.** Offloading a 5-tuple match means recording the filter
  and consulting it when a flow is admitted, so `cdx_ft_hw_add()` can set
  `iqid` to the profile that filter allocated. The class nibble from
  increment 8 is the mechanism underneath; it stops being an operator-facing
  surface and becomes how the adapter tells the hardware what tc already
  decided. **Delivered.**

Revocation is the same constraint as classification: an offloaded flow never
re-enters the ingress path, so a filter added after admission does not reach
flows already in hardware. The existing stop → change → apply sequence is the
answer, as it is for the mark.

What this retires: the per-port fast-forward rate, the eight profiles and the
aggregate default all become `tc` verbs, and nothing in the QoS plane needs FCI
or CMM. That is the last QoS reason to keep either.

#### Stage 1, proved on hardware 2026-09-17

`cdx_setup_tc()` now answers `TC_SETUP_BLOCK` for a clsact ingress block, and
`cdx_police.c` turns a `matchall` filter's police action into the port's
profile. `CONFIG_NET_CLS_MATCHALL` had to be enabled — the classifier was
simply absent from both defconfigs, so `tc` answered "TC classifier not found"
before any of this was reachable.

The filter is genuinely offloaded, not accepted and ignored. `skip_sw` means
hardware or nothing, and `tc filter show` agrees:

```
filter protocol all pref 49152 matchall chain 0 handle 0x1
  skip_sw
  in_hw
	action order 1: police 0x1 rate 500Mbit burst 65500b mtu 2Kb action drop
```

And it meters. loki sending through the DUT's LAN port, policed on that port's
ingress:

| configured | measured |
| --- | --- |
| no filter | 109 Mbit/s |
| `rate 20mbit` | 17.6 Mbit/s |
| `rate 50mbit` | 41.1 Mbit/s |
| filter removed | 111 Mbit/s |

Goodput lands a little under each cap, which is what a token-bucket policer in
front of TCP should do: it drops rather than queues, the sender backs off, and
the profile meters the full frame while iperf3 reports payload. Removing the
filter returns the port to the rate it booted with rather than leaving the last
policed value in place.

Refusals reach the operator as themselves rather than a bare `EOPNOTSUPP`:

```
Error: cdx: police: rate rounds to zero at this profile's resolution.
Error: cdx: police: exceed action must be drop.
```

No BUG, WARNING or call trace across the run. Statistics were refused at this
stage and are delivered below.

#### Stage 2, proved on hardware 2026-09-17

A `flower` filter allocates one of the seven per-flow profiles, records what it
matched, and `cdx_ft_hw_add()` consults that when a flow is admitted — setting
`iqid` to the profile whose filter claims the flow. A tc filter outranks the
conntrack mark, because it is the more specific statement of the same intent;
with no filter matching, the mark's nibble stands.

The binding is made **at admission**, so a filter has to exist before the flow
does. `conntrack -F` is what forces re-admission in testing, and the stop →
change → apply sequence is what does it in service. This is the same contract
the mark already had, arriving from the other direction.

loki sending through the DUT's LAN port, with the flowtable bound.

**Measure above the software path's ceiling, or the number proves nothing about
where the policing happened.** Software forwarding tops out near 130 Mbit on
this rig, so a 30 Mbit result shows only that *something* enforced the rate —
the kernel could have. A multi-gigabit cap can be reached by an offloaded flow
and nothing else, so one number proves the flow is in hardware *and* that the
hardware meter is holding it:

| `flower src_ip <loki> action police …` | goodput |
| --- | --- |
| no filter | 9414 Mbit/s |
| `rate 5gbit burst 32m` | 4787 Mbit/s |
| `rate 2gbit burst 32m` | 1930 Mbit/s |
| filter removed | 9414 Mbit/s |

Both caps land within 4% of what was asked for, at rates the CPU could not
forward at all.

Selectivity, at a rate where it is easy to read:

| | goodput |
| --- | --- |
| `rate 30mbit burst 1m`, filter naming loki | 29.0 Mbit/s |
| same filter naming a different host | 9409 Mbit/s |

The meter reaches the flow the filter names and only that flow.

**The burst matters more than it looks, and the rig proved it twice.** The first
attempt measured 0.00 Mbit/s — `cdxdrv_modify_ingress_qos_policer_profile()`
was discarding the caller's burst and forcing its 2000-byte default, about one
and a third frames, which drops enough of every TCP window that the connection
collapses rather than settling. That is fixed; the FCI path passes the default
explicitly and is unaffected. Even then a burst has to be big enough for the
flow's burstiness, because a policer drops where a shaper would queue:

| burst, at `rate 30mbit` | goodput |
| --- | --- |
| 32k | 10.9 Mbit/s |
| 128k | 9.70 Mbit/s |
| 1m | 29.0 Mbit/s |
| 4m | 32.1 Mbit/s |

So an operator policing TCP should size the burst against the flow rather than
leave it small, and a rate under about a megabyte of burst will read low. That
is a property of policing, not of this hardware.

**The rule is the single truth, which is why the filter is resolved in the
adapter rather than in the backend.** The first cut looked it up in
`cdx_ft_hw_add()`, which worked but left `/proc/cdx_flowtable` reporting
`qos=000` for a flow that was being metered: the row printed the rule's nibble,
the one derived from the mark, while the hardware had been told something else.
`ft_parse()` now resolves it last, once the tuple is finished, so what the
hardware is given and what the row says are the same value:

```
 2 qos=000      # reply direction, arriving on the other port
 2 qos=100      # policed direction: policer nibble 1, profile 1
```

and with the filter naming a different host, all four rows read `qos=000`.

Last, rather than anywhere convenient, because a filter matches on the
finished tuple: the ports, the protocol and the ingress device all have to be
decided first. The harness pins that by refusing a lookup on a half-built rule.

#### Stage 3, the counters

`TC_CLSMATCHALL_STATS` and `FLOW_CLS_STATS` were refused through stages 1 and 2
because claiming them without wiring the counters would report every filter as
passing everything. They are answered now, and the whole of the work is the
arithmetic between what the hardware keeps and what tc expects.

**The profile counts frames per colour and nothing else.** There is no byte
counter anywhere in it: `e_FmPcdPlcrProfileCounters` offers green, yellow and
red packet totals and the two recoloured ones, and that is the complete list.
Green and yellow are enqueued and red is dropped, because the profile programs
`e_FM_PCD_PLCR_DROP_FRAME` on red, so the frames the meter saw are the sum of
the three totals and the ones it discarded are the red ones.

So `tc` is told frames and drops, and **zero bytes**. The two alternatives are
worse: multiplying frames by an assumed size would put an invented number in a
counter an operator sizes a policer from, and refusing statistics outright
loses the drop count — which is the one number no software counter can supply
for a flow that never reaches the CPU, and the reason to have this at all.

**Totals in, deltas out.** `flow_stats_update()` adds what a driver reports to
what the action already holds, and the hardware counters are free-running, so
every filter keeps the values it last read and reports the difference.

A counter that has gone *backwards* is the case worth stating. It was cleared
by another reader — the FCI query commands still clear these on request — and
not wrapped, so what it holds now is the whole of the delta. The other reading
is a 32-bit wrap, and at 10G with full-size frames the counters do wrap, in
about ninety minutes of saturation. Both readings are wrong some of the time
and the asymmetry decides it: treating a clear as a wrap credits a filter with
almost four billion frames it never saw, while treating a wrap as a clear loses
one wrap's counting from a filter nobody had polled in an hour and a half. An
invented four billion is the worse answer.

**A filter's baseline starts where the hardware is, not at zero.** The port's
limiter has been counting since the port came up, and a per-flow profile handed
back by one filter still holds the frames that filter metered — the pool is
seven profiles and they are reused. Without seeding, a new filter's first
report would credit it with everything anyone ever metered through that
profile. So `matchall` reads the port counters and `flower` reads the profile's
as the filter is created.

The records this needs are also what makes an unknown cookie answerable:
`matchall` had no per-filter state at all before, and both commands now return
`-ENOENT` for a filter the driver never recorded rather than handing back the
port's numbers under somebody else's name. The same records absorb tc's replay
of a filter onto a block callback that binds after it — the second arrival
reprograms the hardware and keeps the baseline, because the counters did not
restart.

The counter read itself happens **outside** `cdx_police_lock`.
`FM_PCD_PlcrProfileGetCounter()` takes the FMD's host-command path when one is
in use and busy-waits there, and that lock is taken from the flowtable's
admission path. The filter is therefore looked up twice: once to decide which
profile to read, and again afterwards to find the baseline, because it can be
destroyed in between.

`tools/host_tests/test_police.py` pins the arithmetic — the colour mapping, the
delta, the cleared counter, the seeded baseline, per-filter independence and
the unknown cookie. Two of those assertions were confirmed to fail without the
code that satisfies them.

With this, `CMD_QM_INGRESS_POLICER_QUERY_STATS` has a kernel-verb equivalent
and nothing in the ingress-policing plane needs FCI.

##### Proved on hardware, 2026-09-17

`ask.offload=flowtable` with `qos_mark_mask=0xf0` on the KASAN image, policy
applied (`bindings 2`), loki sending through the DUT's LAN port.

A `matchall action police rate 2gbit burst 32m` reported **`Sent 0 bytes 0 pkt`
the moment it was installed**, although the port's limiter had been metering
since link-up — which is the seeded baseline, and the one number that says the
filter reports its own traffic rather than the port's history. `tc` also showed
`in_hw` and `used_hw_stats immediate`.

Ten seconds of four-stream iperf3 then ran at **1.93 Gbit/s** — under the cap,
and an order of magnitude above the ~130 Mbit this rig forwards in software, so
the flow was in hardware and the hardware meter was holding it. The filter
reported **1,823,099 frames, 155,954 dropped**. iperf3's own sender counted
**156,001 retransmits**: the profile's red counter and the sender's losses agree
to 0.03%, which is what says red is the drops rather than something adjacent.

Read three times in a row with no traffic between, the filter reported
`1823099 pkt (dropped 155954)` **each time**. Under a driver handing back
totals the second read would have doubled it. That is the whole of the delta
contract in one observation.

Two `flower` filters then took profiles 1 and 2 on the same port, one naming
TCP port 5201 at `rate 1gbit`, the other 5202 at `rate 400mbit`; both installed
`in_hw` at `0 pkt`.

| | goodput | frames | dropped |
| --- | --- | --- | --- |
| 5201, `rate 1gbit` | 978 Mbit/s | 957,738 | 112,571 |
| 5202, `rate 400mbit` | 405 Mbit/s | 415,970 | — |

The independence is the point. After the first flow, filter 2 read exactly
zero. After the second, filter 1 read **exactly 957,738** again — unchanged to
the frame — so each filter's baseline is its own and each profile counts only
the flows the filter claims. `tc` reported the whole of it as
`Sent hardware … pkt` with `Sent software 0 bytes 0 pkt`, which is honest: an
offloaded flow never reaches the action in software.

Deleting the filters and the qdisc returned the port to an empty ingress block.
No BUG, WARNING, call trace or KASAN output across the run beyond KASAN's own
init banner.

#### The unit error, fixed

CMM validated ingress `cir`/`pir` against `1..20971250`, a packets-per-second
range, while `cdx_qos.c` programs those profiles in `e_FM_PCD_PLCR_BYTE_MODE`.
The FMD settles the unit beyond argument: in byte mode `GetInfoRateReg()` does
`tmp *= 1000; /* kb --> b */`, so the field is **Kbit/s**. The range is now
`1..10000000`, the fastest port's line rate.

Only that pair was wrong. The fast-forward rate really is packets per second —
`port_ff_lim_mode` is `e_FM_PCD_PLCR_PACKET_MODE` — and so is the SEC rate,
whose ceiling of 14880952 is the 64-byte frame rate of a 10G port and is
correct as it stands.

*Effort: 1 week.*

### Order and total

Increments 1 and 2a are independent, and both are written. 2b depends on 2a
and gates 3; 4 depends on 3; 5 on 3. 6, 7 and 8 each depend only on 1.
Roughly **six to eight weeks** of focused work to the end of increment 5,
where the feature becomes consumable, plus three weeks for 6 to 8.

Two risks stand out, and both are failures that a build cannot catch. 2b moves
the flowtable's binding path, where a mistake stops acceleration silently
rather than loudly. And increment 3's teardown paths run under a `sch_htb`
that discards the return value of both destroy commands, in a file whose
history — A21, A109, A122, A133 — is that exact failure mode.

## The consumer contract

ASK is a dependency of several distributions — Armbian in production, OpenWrt
on the gateway, meta-ask on the bench — so what it exposes has to be a
*generic Linux* contract. Anything shaped like one consumer's configuration
system is wrong by construction, and a bespoke control binary is worse: it has
no ecosystem tooling and has to be packaged three times.

The flowtable controller already sets the precedent and should be matched
rather than improved on. `tools/ask_flowtable.py` is stdlib-only Python over
`/etc/ask/flowtable.json`, `/proc/cdx_flowtable`, `/sys/class/net` and the
`nft` binary. No UCI, no procd, no systemd, no distribution assumption
anywhere. QoS should look the same.

| Concern | Generic interface | What a consumer does with it |
| --- | --- | --- |
| Scheduler tree | `tc` HTB offload via `ndo_setup_tc` | Armbian: `tc` directly. OpenWrt: render UCI to `tc`. Bench: script it. |
| Classification | `ct mark`, set by nftables or iptables | Whatever firewall the distribution already runs |
| Policy and state | `/etc/ask/*.json` plus a stdlib-only tool | Package the file; no code |

This is the decisive argument against a userspace FCI writer. `tc` is in
iproute2 on every distribution, is already the vocabulary for hardware queue
trees, and gives `tc -s class show` for free. A private binary over
`/dev/cdx_ctrl` would give one consumer a fast path and every other consumer a
porting task.

Three things must be decided on the ASK side, because no consumer can paper
over them.

- **Who owns the flowtable, and how a conflict is reported.** There are two
  conflicts and only one of them is already handled. ASK registers an *indirect*
  block callback (`flow_indr_dev_register`, `cdx/ask_flowtable.c:1417`), so a
  foreign flowtable declaring `flags offload` on a supported port can seize the
  CDX backend; the adapter then refuses the second table with `-EBUSY`
  (`:949`) and the controller reports "another flowtable owns the backend
  bindings". That one is loud. The other is not: a foreign flowtable whose
  forward chain runs at a **lower priority number** than ASK's 10 wins
  `test_and_set_bit(IPS_OFFLOAD_BIT)` in `nft_flow_offload_eval()` and takes
  every flow. There is no packet state in which the earlier chain declines and
  ASK's accepts, so ASK receives nothing at all, silently, with no error
  anywhere. The generic fix is not to special-case a firewall manager: the
  controller should enumerate flowtables on its devices, and refuse to claim
  ownership while another one exists whose chain runs earlier.
- **Which mark bits, and prefer the high ones.** The mask must be
  configuration, not a constant; the policy schema already carries
  `mark: {value, mask}` and the decode should read its mask from there. Bias
  the default allocation towards the **top** of the word. The realistic
  contender for `ct mark` across distributions is strongSwan's `connmark`
  plugin, which is built and loaded by default in more than one of ours; when
  an operator configures `mark_in`/`mark_out` as `%unique`, strongSwan
  allocates small ascending integers from 1, i.e. squarely in the low bits.
- **Which hook the mark must arrive from.** The requirement is not simply
  "before priority 10" — it is *before the flow is admitted*, on a hook that
  sees the packet earlier in the same traversal. Prerouting and forward-mangle
  hooks qualify. Postrouting does not: a mark written there is visible only
  from the following packet, so the first established forward packet is
  evaluated against the old value. ASK should state that requirement and leave
  the mechanism entirely to the consumer, because there is no portable one —
  nftables can express `ct mark set` directly, but a given distribution's
  firewall front-end may have no vocabulary for it and may need a raw-ruleset
  include instead.

Once a flow is cached in hardware its packets bypass the forward hooks
entirely, so a mark written by a later rule change never reaches it. That is
the same constraint as the sampled-at-admission contract above, arriving from
the other direction, and the existing stop → change → apply revocation
sequence is the only way to re-evaluate.

Nothing here needs the flowtable to reach parity first: QoS is dormant in the
shipping build, so the increments add a capability rather than restore one.
What they do need is a decision, before step 1, on whether the product intends
to ship CEETM QoS at all. If it does not, the honest retirement is to delete
the plane rather than port it, and steps 1 and 5 collapse into removing the
`ct->mark` refusal at `ask_flowtable.c:562`.

## Defects found while mapping this

None is on the flowtable path; all are in code a QoS increment would touch.
The first two are filed as **A141**, the last as **A142**.

- `ceetm_get_egressfq()` (`cdx/cdx_ceetm_app.c:54`) mutates the shared
  `qman_fq.fqid` in place, OR-ing the policer-profile number into the top byte
  when the class-queue policer is on and `ff == 1`. The clearing branch is an
  `else if` requiring `cq_shaper_enable == DISABLE_POLICER`, so a subsequent
  `ff = 0` call hits neither branch. `ceetm_dscp_fq_map()` calls it with
  `ff = 0` and then `ff = 1` on the same FQ, storing the *pointer* from the
  first call and the *value* from the second, so with the class-queue policer
  enabled the slow-path DSCP table ends up pointing at an FQ whose `fqid`
  carries the fast-path policer byte.
- `ceetm_release_iface()` calls `disable_dscp_fqid_map(qm_ctx - gQMCtx)`
  (`cdx/cdx_ceetm_app.c:1902`) — array-index arithmetic — where every other
  caller passes `qm_ctx->port_info->portid`. They agree only because
  `QM_GET_CONTEXT(portid)` is `&gQMCtx[portid]`.
- `union ctentry_qosmark.vlan_pbits` and `.vlan_pbits_valid` are declared,
  carried through the whole command path, and read by nothing.
- In flowtable mode, `CMD_INIT(qm)` still builds 8 channels, 128 class queues,
  128 LFQs and 128 FMAN policer profiles that no command can reach, because
  unlike the IPsec family it is not gated on `cdx_flowtable_enabled()`.

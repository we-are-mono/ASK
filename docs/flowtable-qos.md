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

And CMM **never decides a queue**. `forward_engine.c:461` and `:659` copy
`ct->qosconnmark` verbatim into the FCI conntrack command. That is the entire
contribution of the daemon to the classification plane.

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

Two readers consume it. On the **software** TX path, `pfe_eth_get_queuenum()`
(`sdk_dpaa/dpaa_eth_sg.c:1454`) pulls `ct->qosconnmark` off the skb's conntrack
and `cpe_fp_tx()` resolves it to a CEETM FQ. On the **hardware** path,
`insert_entry_in_classif_table()` passes `&entry->qosmark` to
`dpa_get_tx_info_by_itf()` (`cdx/cdx_ehash.c:1100`), which reaches
`cdx_get_txfq()` and bakes the resulting CEETM LFQID into the classifier entry's
action. From then on the FMAN enqueues straight to a CEETM class queue and the
hardware scheduler shapes the flow with no software involvement at all.

`ct->qosconnmark` is a 64-bit ASK-added field on `struct nf_conn`
(`patches/kernel/060-ask-netfilter-qosmark.patch`), set by an
`iptables -j QOSCONNMARK` target. Low 32 bits are the original direction, high
32 the reply, gated by bit 63 (`cdx/cdx.h:67`).

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
mlx5 uses for hardware queue trees. The parameter mapping is clean: root
`rate`/`ceil` → LNI commit/excess shaper; leaf `rate`/`ceil` → channel shaper;
leaf `prio` → strict-priority class queue; leaf `quantum` → WBFS weight.
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
The QM command family is *not* sealed in flowtable mode; only
`CDX_CTRL_DPA_SET_PARAMS` is (`cdx/cdx_dev.c:140`). A tool of a few hundred lines
writing the same `CMD_QM_*` structures to `/dev/cdx_ctrl` removes CMM from the
QoS path with no kernel change whatsoever.

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

One thing not to copy forward: CMM validates ingress `cir`/`pir` against
`1..20971250`, a packets-per-second range, while `cdx_qos.c` programs the profile
in `e_FM_PCD_PLCR_BYTE_MODE`, where the unit is Kbit/s. The replacement should
fix the range rather than reproduce it.

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

Implement the command set over `cdx_ceetm_app.c`'s existing setters, all of
which are already thin functions over a `(channel, class queue)` pair.

- `TC_HTB_CREATE` latches the qdisc handle major and default class.
- `TC_HTB_LEAF_ALLOC_QUEUE` claims a channel and class queue, returns a dense
  qid, and records the `txq → (channel, class queue)` map.
- `TC_HTB_LEAF_TO_INNER`, `LEAF_DEL`, `LEAF_DEL_LAST`, `NODE_MODIFY`,
  `LEAF_QUERY_QUEUE`.
- Map `rate`/`ceil` to the LNI and channel shapers, `prio` to the strict
  priority queue, `quantum` to the WBFS weight.

Three sharp edges from the `sch_htb` contract. `LEAF_DEL` may write back a
different classid to report that the driver moved a qid, which is how the
range stays dense; skipping it means fragmenting the budget. `TC_HTB_DESTROY`
and `LEAF_DEL_LAST_FORCE` have their return values **discarded**, so teardown
must always succeed — the same class of problem A21, A109, A122 and A133 were
about, in the same file, so budget for it. And every leaf add or delete wraps
a full `dev_deactivate()`/`dev_activate()` cycle, so building a wide tree
quiesces the netdev once per class.

Only eight weighted leaves per channel are available until WBFS group B is
claimed (`qman_ceetm_cq_claim_A`, `cdx/cdx_ceetm_app.c:548`).

*Proof.* Build a tree with `tc`, read it back with `tc class show`, and
confirm against `CMD_QM_QUERY_QUEUE` that the hardware matches what was asked
for. Tear it down and confirm every claim is released.

*Effort: 1.5–2 weeks.*

### 4. The software path agrees with hardware

- `ndo_select_queue` resolves the conntrack mark to the leaf's TX queue,
  reusing the decode `pfe_eth_get_queuenum()` performs today.
- `cpe_fp_tx()` selects its CEETM FQ from `skb_get_queue_mapping()` through
  the increment-3 map instead of resolving the mark itself.
- Fix the `conf_fq` index while here. `dpaa_eth_sg.c:1999` indexes
  `conf_fqs[]` with a class-queue id in the CEETM branch, so every
  DSCP-classified frame confirms on `conf_fqs[0]`. That is a live bug, not a
  consequence of this work.

*Proof.* One flow, forced through software and then offloaded, lands in the
same class queue both times.

*Effort: 3–4 days.*

### 5. Hardware statistics through ethtool

Extend the existing `get_strings`/`get_sset_count`/`get_ethtool_stats`
(`sdk_dpaa/dpaa_ethtool.c:564`) with per-class dequeued frames, dequeued bytes
and rejected frames, read from the counters cdx already calls
(`cdx/cdx_ceetm_app.c:1732`, `:1741`).

*Proof.* `ethtool -S` accounts for offloaded traffic that `tc -s class show`
cannot see, and the two together account for the whole link.

*Effort: 2–3 days.*

**Consumers can be adapted from here.** Everything after this point improves
the offering rather than enabling it.

### 6. WRED

The CCG already carries `wr_en_g/y/r` and `wr_parm_g/y/r`
(`include/linux/fsl_qman.h:3748`); cdx configures none of it, so today's
offering is strict priority and shapers over a tail-drop of eight frames.
Expose the parameters and pick defaults that behave under load.

Note that cdx also disables congestion-state notification entirely
(`cscn_en = 0`, `cdx/cdx_ceetm_app.c:436`), so overload is invisible to
software. Decide in this increment whether that stays true.

*Proof.* A saturating flow and a sparse one share a class; latency for the
sparse flow stays bounded where tail-drop alone would not keep it so.

*Effort: 1 week.*

### 7. Retire the ASK mark

Drop `patches/kernel/060`, the four files in `iptables-extensions/`, and
`CONFIG_NETFILTER_XT_QOSMARK`/`_QOSCONNMARK`, once nothing reads
`ct->qosconnmark`. Increment 4 already moved the software path, so this is
mostly deletion. Worth doing early rather than late: the extension is not
packaged for OpenWrt at all, so `ct->qosconnmark` is permanently zero there
and the path is already dead in production.

*Effort: 3–4 days.*

### 8. Ingress policing

Extend the decode with `iqid`, argue the bit budget against the mask, and
prove a policed flow drops at its configured rate. Fix the unit error while
here: CMM validates `cir`/`pir` against a packets-per-second range while
`cdx_qos.c` programs the profile in byte mode, where the unit is Kbit/s.

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

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

It also hides a trap. If QoS were enabled with the flowtable owning the
datapath, `qosmark == 0` would send **every** offloaded flow to
`fls(chnl_map) - 1` — the channel `ceetm_get_egressfq()` calls "least prio" —
class queue 0, which `GET_CEETM_PRIORITY` maps to CEETM queue 7, the *lowest*
priority strict queue. Any design must name an explicit default class rather
than let zero mean "wherever zero lands".

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
`TC_SETUP_QDISC_HTB` is the mainline-blessed verb for exactly this shape and is
what mlx5 uses for hardware queue trees. The mapping is direct: root
`rate`/`ceil` → LNI commit/excess shaper; `TC_HTB_LEAF_ALLOC_QUEUE` → claim a
channel and class queue and hand back the binding; leaf `rate`/`ceil` → channel
shaper; leaf `prio` → strict-priority class queue; leaf `quantum` → WBFS weight.
Tail-drop depth has no HTB field and stays a per-port default. The callback has
everything it needs already: `priv->qm_ctx` is stashed at netdev registration
(`cdx/control_qm.c:518`), and every cdx setter — `ceetm_configure_shaper`,
`ceetm_configure_wbfq`, `ceetm_configure_cq`, `ceetm_assign_chnl`,
`ceetm_enable_or_disable_qos` — is already a thin function over a plain
`(channel, classque)` index pair. The FCI handlers do nothing but resolve an
ifname and call them.

One real constraint: only eight weighted classes are available, because cdx
claims WBFS group A only and never group B (`qman_ceetm_cq_claim_A`,
`cdx/cdx_ceetm_app.c:548`). An HTB tree wider than eight weighted leaves per
channel needs group B claimed first.

Every hardened path survives; only the transport changes. The control plane
becomes `tc class add dev eth3 parent 1: classid 1:10 htb rate 100mbit ceil
900mbit prio 2`, and the `cmmqos` UCI schema can be kept verbatim with its
renderer retargeted from `cmm -c` to `tc` — no product-surface change at all.

**C — a small userspace tool speaking the existing FCI commands.**
The QM command family is *not* sealed in flowtable mode; only
`CDX_CTRL_DPA_SET_PARAMS` is (`cdx/cdx_dev.c:140`). A tool of a few hundred lines
writing the same `CMD_QM_*` structures to `/dev/cdx_ctrl` removes CMM from the
QoS path with no kernel change whatsoever.

**Recommendation: C to unblock, B as the destination.** C lets CMM be retired
from QoS on the same day the classification work lands, because it changes
nothing in the kernel and nothing in the UCI schema. B then replaces C's
transport with `tc` without touching the hardware layer again. A is not worth
its risk.

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

## Sequencing

1. **Classification.** `cdx_ft_rule.qos`, the mark decode with a mask, the
   direction split, the default-class contract, and a hardware proof that two
   flows with different marks land in different class queues under load. Cannot
   start before a default class is chosen, or admitted flows silently land on
   the lowest-priority queue.
2. **Control channel C.** Replace `cmmqos.init`'s `cmm -c` backend with a direct
   FCI writer. Purely a userspace change; the UCI schema does not move.
3. **Retire the ASK mark.** Drop patch 060, the iptables extensions and their
   two Kconfig symbols once nothing reads `ct->qosconnmark`. Note that
   `pfe_eth_get_queuenum()` reads it on the software TX path, so this step also
   has to convert `cpe_fp_tx()` to `ct->mark`.
4. **Control channel B.** `ndo_setup_tc` HTB offload over the existing
   `cdx_ceetm_app.c`, retargeting the UCI renderer to `tc`. Deletes
   `cmm/src/module_qm.c`, most of `cdx/control_qm.c` and 23 command codes.
5. **Ingress policing, if wanted.** Extend the mark decode with `iqid`, argue
   the bit budget, and prove a policed flow drops at its configured rate.
   Independent of everything above and unconfigured in the product today.

Steps 1 and 2 are independent and can land in either order. Step 3 depends on 1.
Step 4 depends on 2. Step 5 depends on 1.

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

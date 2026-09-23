# IPsec without CMM

Roadmap item 6. What the hardware already does, what patch 040 actually is,
and the control plane that replaces the one it was built for.

This document is the decision and the contract. It is written before any code,
because the roadmap asks items 5 to 8 each to settle a feature-specific
hardware eligibility contract first, and because the two available
architectures here differ in what the tree carries forever rather than in how
long they take to write.

## The shape of the problem

IPsec is the first remaining item where the mechanism Linux supplies and the
mechanism the hardware supplies are *both* present and do not meet. Linux has
had a device-offload API for IPsec since 4.13 and a packet-offload mode since
6.2. CDX has had a SEC datapath since NXP wrote it. Neither knows about the
other, and the thing that used to join them is the daemon being retired.

Concretely, in a flowtable boot today:

- **Two** ownership gates skip IPsec, not one, and they are easy to mistake for
  each other. `cdx/cdx_cmdhandler.c:165` skips `CMD_INIT(ipsec)`, so the SA
  caches are not initialised, the CAAM job ring is not claimed and the datapath
  frame-queue hook is not registered. Separately, `cdx/cdx_main.c:395` jumps
  over `cdx_dpa_ipsec_init()` and the scatter-gather and skb-return buffer
  pools, so the SEC **offline port, buffer pool and PCD frame queues** are
  never built at all. The second one is the one that matters most and the
  easier to miss: its absence surfaces as a shared descriptor that cannot be
  created, several layers from the cause, with no log line naming a pool.
- `to_sec_fqid` is written only from the CMM path, so no frame selects SEC.
- `devlink trap policer 2` — the SEC meter registered by the QoS increment —
  meters nothing, which `cdx/cdx_devlink.c:99` already says is temporary.

## Patch 040 is the kernel half of a userspace design

This has to be said plainly because the opposite reading is easy and it changes
what the work is. `patches/kernel/040-ask-xfrm-ipsec-offload.patch` is 2,319
lines and its header describes a fast path wiring `xfrm_state` into SEC. It
does not do that. It wires `xfrm_state` into a **netlink bus whose only
consumer is CMM**.

896 of those lines — more than a third of the patch, and by far its largest
file — are added to `net/key/af_key.c`. They define a private message family:

```
NLKEY_SA_CREATE  NLKEY_SA_SET_KEYS  NLKEY_SA_SET_TUNNEL  NLKEY_SA_SET_NATT
NLKEY_SA_SET_LIFETIME  NLKEY_SA_SET_STATE  NLKEY_SA_DELETE  NLKEY_SA_FLUSH
NLKEY_SA_NOTIFY  NLKEY_SA_INFO_UPDATE  NLKEY_SA_SET_OFFLOAD
NLKEY_FLOW_ADD  NLKEY_FLOW_REMOVE  NLKEY_FLOW_NOTIFY
```

`ipsec_xfrm2nlkey()` serialises an `xfrm_state` into that sequence and
broadcasts it on `NETLINK_KEY`. The receiver is `cmm/src/module_ipsec.c`,
which subscribes through libfci's `FCILIB_KEY_TYPE` (`fci/lib/src/libfci.c:66`)
and re-encodes every message as an FCI `FC_IPSEC` command back into CDX. The
full path an SA takes today is:

```
strongSwan → XFRM netlink → xfrm_state → af_key nlkey broadcast
           → CMM module_ipsec → FCI → cdx control_ipsec → SEC
```

The daemon the no-userspace constraint forbids is not an alternative to patch
040. It is the half of patch 040 that reaches the hardware.

Two further corrections to the brief this work started from:

**`net/xfrm/ipsec_flow.c` is dead.** All 231 lines of it. `ipsec_flow_init()`
is called only under `#ifdef IPSEC_FLOW_CACHE`, which is defined nowhere in
the tree, so `ft->hash_table` is always NULL. A comment already in the patch
records this, added when `NLKEY_FLOW_REMOVE` was hardened against oopsing on
the NULL table it walks.

**`FLOW_OFFLOAD_XMIT_XFRM` in patch 140 is upstream context, not ASK code.**
The line is inside `nf_flow_dst_check()`, which upstream wrote. ASK's own
addition a few hunks below states the opposite of what its presence suggests:
`nf_flow_offload_dst()` returns NULL for any transmit type other than
`FLOW_OFFLOAD_XMIT_NEIGH`, with the comment "XFRM destinations are
deliberately excluded from the routed-neighbour adapter contract". The adapter
refuses these flows today; it does not half-handle them.

## What the hardware side already provides

The datapath is in better shape than the control plane, and one discovery
decides the size of this increment.

**The shared encoder already has the IPsec hook, and the flowtable backend
already calls it.** `cdx_ft_hw_add()` ends at
`insert_entry_in_classif_table_encap()` (`cdx/cdx_flowtable_hw.c:214`), and
that function contains, at `cdx/cdx_ehash.c:1190`:

```c
if (entry->status & CONNTRACK_SEC) {
        if (cdx_ipsec_fill_sec_info(entry, info))
                goto err_ret;
}
```

`cdx_ipsec_fill_sec_info()` (`cdx/cdx_dpa_ipsec.c:490`) walks the entry's
`hSAEntry[SA_MAX_OP]` handles and, per direction:

- **outbound** — sets `info->to_sec_fqid` from the SA's SEC context, plus
  `info->sa_family` and `info->tnl_hdr_size` (derived as `dev_mtu - mtu`, the
  tunnel header expansion). The classifier action then enqueues matching
  frames to the SEC frame queue instead of the egress port.
- **inbound** — sets `info->l3_info.ipsec_inbound_flow` and replaces the table
  descriptor with the offline port's via `dpa_ipsec_ofport_td()`, so the
  post-decryption frame is classified on the OH port.

So the flowtable's hardware path does not need a new encoder, a new opcode
family or a new table. It needs two fields on `struct cdx_ft_rule` — the SA
handles — and `ct->status |= CONNTRACK_SEC`. Everything downstream of that is
code CMM has been exercising for years.

**`ipsec_init()` is nearly mode-agnostic.** `cdx/control_ipsec.c:1340` does
four things: initialise the three SA hash lists, call `cdx_ipsec_init()`
(CAAM job ring allocation and SEC era detection), start the SA lifetime timer,
and register the datapath FQ hook `cdx_get_to_sec_fq_handler`. Exactly one
line in it belongs to FCI:

```c
set_cmd_handler(EVENT_IPS_IN, M_ipsec_cmdproc);
```

This is the same shape QoS turned out to have — the hardware plane is built
unconditionally and only a consumer was missing — rather than the shape the
gating suggested.

## The decision: converge on `xfrmdev_ops`

Two coherent architectures existed. The tree takes the second.

**Option A, extend 040.** Keep `x->offloaded`, `x->handle`, the `state_byh`
hash, `skb->ipsec_offload` and the private direction enum; replace only the
netlink hop with an in-kernel notifier calling a new `cdx_ipsec_backend.h`
that mirrors `cdx_flowtable_backend.h`. Nothing upstream-shaped is adopted.

**Option B, converge on `xfrmdev_ops`.** Register `struct xfrmdev_ops` on the
SDK DPAA netdevs. `xdo_dev_state_add()` programs CDX directly from the
`xfrm_state`. Chosen.

### Why

**Mainline already has the semantics 040 hand-rolled.** The central trick in
040's output path is: when an SA is offloaded, do not encapsulate in software
— set a flag, skip `xfrm4_prepare_output()`/`xfrm6_prepare_output()`, skip
`x->type->output()`, and let the hardware add ESP. That behaviour is
`XFRM_DEV_OFFLOAD_PACKET` in this kernel, unpatched:

- `net/xfrm/xfrm_output.c:527` — `if (err <= 0 || x->xso.type ==
  XFRM_DEV_OFFLOAD_PACKET) goto resume;` skips the transform walk entirely.
- `net/xfrm/xfrm_output.c:854` — packet-offload tunnel mode goes to
  `xfrm_dev_direct_output()`, which pops the xfrm dst, sets
  `skb->dev = x->xso.dev` and transmits the *inner* packet, leaving the ESP
  and outer header to hardware.

040's `skb->ipsec_offload` and the four `if (skb->ipsec_offload) return 0;`
guards it needs in the encap helpers are a private reimplementation of a
kernel feature that landed after NXP wrote them.

**`offload_handle` is already the field CDX wants.**
`struct xfrm_dev_offload` carries `unsigned long offload_handle`, `dev`,
`real_dev`, `dir` and `type`. Linux already stores a driver cookie per state,
so `xfrm_state.handle` has nothing left to do.

The index beside it is a subtler question, and reading the datapath changed the
answer. `netns_xfrm.state_byh` is not bookkeeping: `dpa_ipsec.c:391` walks it
**per packet**, on the SEC decrypt-completion path, because a decrypted frame
arrives carrying nothing but its SA's handle in the trailer and the stack drops
it unless a `sec_path` naming the state is attached first. Deleting the hash
without replacing the lookup would break inbound IPsec entirely.

It is still deleted, because the lookup belongs on the other side of the
interface. The backend allocates the handle — it must, since the handle indexes
`sa_cache_by_h` and no caller can know which values are free — and it is handed
the `xfrm_state` by `xdo_dev_state_add()`, so it can answer `handle → state`
from the cache it already keeps. The legacy design needed an index in kernel
core only because CMM chose the handle and cdx had nothing but the number. Here
the same code that allocates the handle holds the state, and
`get_netdev_of_SA_by_fqid()` has already found that entry one line earlier on
the very path that wants it, so the second lookup collapses into the first.

**The consumer already speaks it.** `strongswan-6.0.3` is in the OpenWrt build
tree for this target and supports `hw_offload = packet` per child SA
(`src/libcharon/plugins/vici/vici_config.c:1951`), which its netlink backend
turns into `XFRM_OFFLOAD_PACKET` on the state
(`src/libcharon/plugins/kernel_netlink/kernel_netlink_ipsec.c:1666`). Enabling
hardware IPsec becomes one line in a swanctl connection, with no ASK package,
no ASK UAPI and no ASK daemon. Under Option A the same capability needs
something to originate the in-kernel programming, and the only honest
candidates are a private UAPI or reading policy out of strongSwan ourselves.

**It shrinks the carried patch rather than growing it.** Option B deletes
`net/key/af_key.c` (−896), `net/xfrm/ipsec_flow.c` and `.h` (−262),
`include/uapi/linux/pfkeyv2.h` (−1), the `xfrm_state`/`netns_xfrm` handle
fields and the `ipsec_flow_*` declarations in `include/net/xfrm.h`. Patch 040
goes from 2,319 lines to roughly half that, and what remains is hook points
rather than a protocol.

### What Option B costs, stated honestly

**The outbound slow path loses its SA pointer.** `cpe_fp_tx()`
(`patches/kernel/010-…:1699`) reaches SEC through
`dpaa_submit_outb_pkt_to_SEC()`, which reads `skb_sec_path(skb)->xvec[0]` and
looks the frame queue up by `x->handle`. `xfrm_dev_direct_output()` sets no
sec_path. The fix is a small hunk in `xfrm_output()` that attaches a
one-entry sec_path for packet-offload tunnel mode before the direct output —
about ten lines replacing the hundred 040 currently spends there — and the
lookup key becomes `x->xso.offload_handle`. This must not be papered over by
recovering the state from `skb_dst()`: the dst is popped before transmit.

**Packet offload is per-netdev; CDX's SEC is SoC-wide.** `xfrm_dev_state_add()`
binds a state to one `net_device`, either named by `xuo->ifindex` or derived by
routing the tunnel endpoints. Binding every SA to the WAN port is a modelling
choice, not a fact about the hardware, and the eligibility contract below has
to say so rather than let it be assumed.

**Mainline has no `parent_sa_handle`.** 040 carries one so CMM can migrate
live flows onto a rekeyed SA (`cmm/src/module_ipsec.c:545`,
`cmmUpdateFlowsWithNewSAInfo`). This is not a gap under the flowtable: an SA
change is a dependency change, and the adapter already has selective
retirement for exactly that shape — retire the generations that depend on the
old SA, let fresh traffic readmit against the new one. ISSUES A15 settled that
no resync is needed and that blackout-window losses are recovered by an xfrm
flush. So the field is dropped rather than reimplemented.

**`type_offload` must exist for ESP, and getting it took two config changes
rather than one.** `xfrm_dev_state_add()` refuses a state whose
`x->type_offload` is NULL before it ever reaches the driver, and that type is
registered by the ESP offload module. The test image had
`CONFIG_INET_ESP_OFFLOAD=m` against `CONFIG_INET6_ESP_OFFLOAD=y`, and the
initramfs does not even package `esp4_offload.ko`, so the v4 type was never
registered at all.

Setting `CONFIG_INET_ESP_OFFLOAD=y` alone does nothing, silently: it depends on
`INET_ESP`, which was `=m`, so Kconfig downgrades it straight back to `=m` and
`olddefconfig` reports nothing. Both symbols move to `=y`, matching the IPv6
side, which was already built in.

The failure this produces is worth recognising, because it looks like the
driver refusing the SA and is not: `ip xfrm state add … offload packet` fails
with *"Error: Type doesn't support offload"*, which is the `type_offload` gate
and happens before any `xdo_dev_state_add` runs.

`CONFIG_INET_IPSEC_OFFLOAD=y`, `CONFIG_INET6_IPSEC_OFFLOAD=y` and
`CONFIG_CPE_FAST_PATH=y` are all already set, so patch 040's code is compiled
into the test image today and its removals are live changes rather than edits
to dead config.

## The eligibility contract

What the hardware may be asked to carry. Everything outside this goes to
Linux, in software, exactly as it does today.

**The SA.** ESP only — `x->id.proto == IPPROTO_ESP`; AH is refused, as 040's
own check already does. Tunnel mode and transport mode, IPv4 and IPv6 outer.
Ciphers as the CDX shared-descriptor builder supports them: CBC and CTR with
an HMAC, and AEAD — GCM at ICV 8/12/16 and GMAC (`rfc4543`). GCM is admitted
without reservation: A24a fixed the shared-descriptor sharing policy that made
it unsafe (DNCPE-2358, `43f29a0`) and GCM now outperforms CBC+HMAC on TCP.
NAT-T is carried through `x->encap->encap_sport/dport`. TFC padding is refused
by `xfrm_dev_state_add()` before the driver sees it. ESN is admitted; the
state is programmed with the ESN flag and SEC keeps the whole 64-bit sequence
number in its PDB, advancing the high word itself. There is no
`xdo_dev_state_advance_esn`: `xfrm_dev_state_add()` requires it only of crypto
offload, where the stack builds the ESP header.

**The device.** The state's `xso.dev` must be a registered physical CDX port.
A state bound to any other device is refused rather than accepted and ignored,
because packet offload has no silent software fallback and an accepted-but-dead
SA would black-hole the tunnel. This is an *identity* test and deliberately not
the liveness one a flow's ports face: an SA may legitimately be installed
before the link it will ride has carrier, and refusing then would fail the
tunnel outright instead of delaying it.

**And there must be an engine behind the port.** The IPsec offline port, its
buffer pool and PCD frame queues, and the CAAM job ring are all claimed at
module init, and a board whose device tree describes none of them still
loads `cdx.ko` — as a gateway without IPsec offload, not one without offload
(A167). `cdx_ipsec_ready()` says whether that claim succeeded, and
`cdx_ipsec_port_supported()` folds it in, which is what makes the absence a
refusal at every entry rather than a fault several layers in: the adapter
never attaches the xfrmdev ops to such a port, so it never advertises
`esp-hw-offload` and strongSwan is never offered it; a state or policy that
reaches admission anyway is refused with `-EOPNOTSUPP`; the legacy owner's
`CREATE_SA` fails; and the encoder's table lookup fails cleanly. The test image
can boot into this state with `cdx.dpa_init_fail_site=cdx_dpa_ipsec_init
cdx.dpa_init_fail_step=1` on the kernel command line.

**The local endpoint must be an address on that port.** Not a contract this
work chose — it is how CDX resolves an SA to an interface at all.
`cdx_ipsec_add_classification_table_entry()` looks the SA up by address:
`sa->id.saddr` for an outbound SA, `sa->id.daddr` for an inbound one. A
tunnel whose local endpoint lives somewhere else is refused with
`dpa_get_iface_info_by_ipaddress returned error` in the log. Real deployments
satisfy this without trying, because strongSwan's local endpoint is the WAN
address; a bench that invents endpoints has to put one on the port.

The inner LAN may still be a bridge or VLAN. For an opted-in flowtable,
Netfilter resolves that direction's physical path even when the opposite
destination uses XFRM. Requiring both directions to use neighbour output
skipped the LAN walk and left hardware admission pointing at the logical
bridge. The transformed direction keeps its destination and transmit type;
the ordinary device walk must not resolve its inner address as the outer peer.

**An outbound SA needs a resolved next hop at install time**, and this is the
requirement that most changes the shape of the work. What leaves SEC is a
finished frame: the hardware writes the outer header and both Ethernet
addresses, so it must be told the destination before the first packet. The
legacy owner never resolved anything — CMM had already filled CDX's route
table over FCI and named a route id — and **this ownership mode keeps that
table empty by design**, the same way the flowtable gives each direction a
private route rather than joining the legacy hash. So the adapter resolves the
peer through the ordinary FIB and neighbour table and the SA carries its own
embedded route, holding the single reference a table-held one would have had.

A missing route is a refusal. An unresolved *neighbour* is not: the adapter
asks for it the ordinary way and waits briefly, because a cold ARP cache is a
normal state for a freshly booted gateway and refusing then would fail the
tunnel outright rather than delay it — packet offload has no software fallback
to degrade into. The wait runs on the netlink path before any CDX lock or RTNL
is taken, so it blocks only the caller that asked for the SA, and its bound is
short next to the exchange that preceded it. This was found on the rig: an SA
installed moments after a reboot was refused with "no resolved neighbour"
purely because nothing had spoken to the peer yet.

The *later* case — the peer moving once the SA is installed — is step 8 below.
CMM was told about it over `CMD_IPSEC_SA_SET_TNL_ROUTE`; this ownership mode
notices it itself, from the same neighbour and route events that retire a
flow.

**The flow.** A flow is eligible for the SEC action when its egress
destination carries exactly one `xfrm_state`, that state is offloaded to a
port the flow already satisfies the routed contract for, and the flow is
otherwise admissible under the existing contract — routed unicast TCP or UDP,
assured established conntrack for TCP, supported NAT, supported encapsulation.
Bundles deeper than one SA are refused: `hSAEntry[SA_MAX_OP]` can hold more,
but nothing proves the opcode order for a nested bundle and the roadmap's rule
is that each combination needs its own proof.

**The direction pair is not symmetric, and this is the contract's sharp
edge.** The outbound direction is an ordinary flowtable entry with
`to_sec_fqid` set. The inbound direction is not: the arriving frame is ESP,
its 5-tuple is the tunnel's and not the flow's, and the decrypted frame
re-enters classification on the offline port with a different table
descriptor. Capacity or unsupported-direction refusal leaving one direction
accelerated is already permitted by the architecture; here it is the expected
steady state until the inbound half is proved on hardware.

**Dependencies.** An offloaded SA is a fifth-and-a-half dependency class
alongside route, neighbour, netdev, nexthop and bridge FDB. SA deletion,
expiry (soft or hard), rekey and `xfrm` flush each retire the generations that
depend on that SA. The existing selective-retirement machinery does the work;
what is new is the watch.

## Implementation plan

Ordered so that each step is provable on the rig before the next depends on it.

### 1. Ungate the hardware

Both gates. Run `CMD_INIT(ipsec)` in both ownership modes and move the FCI
dispatch registration behind the ownership check instead of the whole init, and
stop jumping over `cdx_dpa_ipsec_init()` in `cdx_module_init()`. After this the
SA caches exist, the CAAM job ring is claimed, the SEC era is detected,
`cdx_get_to_sec_fq_handler` is registered, and — the part the first pass missed
— the SEC offline port, buffer pool and PCD frame queues are built.

Proof: a flowtable boot logs the SEC era and the job-ring device, and
`devlink trap policer 2` is present with zero counts — unchanged behaviour,
since nothing steers to SEC yet.

#### Proved on hardware, 2026-09-17

KASAN image, booted with `ask.offload=flowtable`:

```
# cat /sys/module/cdx/parameters/offload_owner
flowtable
# dmesg | grep -iE 'cdx_ipsec_init|SEC era|job ring'
[   13.513736] caam 1700000.crypto: job rings = 3, qi = 1
[   15.516041] cdx_ipsec_init
[   15.519502] cdx_ipsec_init SEC era= 8
[   15.523521] cdx_ipsec_init job ring device= 00000000173dc891
# devlink trap policer show
platform/1a00000.fman:
  policer 1 rate 5000000 burst 2048
  policer 2 rate 14880952 burst 2048
```

Before this change none of the `cdx_ipsec_init` lines appeared in a flowtable
boot at all. The only `dmesg` hit for `call trace|kasan|BUG:` is KASAN's own
initialisation banner, so the CAAM job-ring claim brings no splat with it.

### 2. The backend interface

`cdx/cdx_ipsec_backend.h`, alongside `cdx_flowtable_backend.h` and under the
same `ASK_CDX_FLOWTABLE` GPL-only export namespace: typed SA add, delete,
stats read-back and an opaque owner. Keys are named in the PF_KEY numbering
the SEC descriptor builder already consumes, for the same reason
`cdx_ft_rule` holds a `union nf_inet_addr` — a UAPI value type crosses without
being transcribed, and no private enum has to be kept in step with two other
tables.

Three things are decided here rather than inherited.

**One call, not five.** FCI spells an SA as CREATE, SET_KEYS, SET_TUNNEL or
SET_NATT, SET_LIFETIME and SET_STATE in sequence, because PF_KEY delivers a
state to userspace in installments. `xdo_dev_state_add()` is handed a complete
`xfrm_state`, so the SA is described once and installed once — and there is no
window in which a half-built SA is reachable by handle.

**The backend allocates the handle.** CMM chose the sagd and cdx trusted it,
which works only while there is exactly one client. The handle indexes the SA
cache and is what SEC stamps into a decrypted frame, so it belongs to whoever
owns that cache. Allocation rotates rather than restarting from one, so a
frame still in flight when its SA was deleted resolves to nothing rather than
to whichever SA was created next.

**The state is bound before the classifier entry, not after.** The FCI path
installs the entry and then looks the state up, which is the only order
available to it. Here the order matters: frames can arrive from SEC the moment
the entry exists, and one arriving before the state is reachable is dropped.

The SA machinery itself is not duplicated. `M_ipsec_sa_cache_create()`, the two
key setters, `M_ipsec_sa_cache_delete()` and the classifier install are the
functions the legacy owner already drives, now declared in `control_ipsec.h`;
`ipsec_push_sa_to_fast_path()` was split so its FCI-only state lookup stays
with FCI. Only the door is new.

### 3. `xfrmdev_ops` on the DPAA netdev

`xdo_dev_state_add` / `_delete` / `_free` / `_offload_ok` and
`xdo_dev_policy_add` / `_delete` / `_free`, registered by the adapter on the
bound physical ports rather than by the SDK driver, so CDX keeps no flowtable
dependency. There is no `_state_advance_esn` and no `_state_update_stats`; the
accounting subsection below says why. `xdo_dev_state_add` maps the `xfrm_state` straight onto the
backend call; the field mapping is exactly what `ipsec_xfrm2nlkey()` already
computes, minus the serialisation:

| CDX needs | Read from |
| --- | --- |
| SA identity, direction | `x->id.proto`, `x->id.spi`, `x->props.family`, `x->props.saddr`, `x->id.daddr`, `x->xso.dir` |
| Authentication key | `x->aalg->alg_key`/`alg_key_len`, `x->props.aalgo` |
| Cipher key | `x->ealg->alg_key`/`alg_key_len`, `x->props.ealgo` |
| AEAD key and ICV | `x->aead->alg_key`/`alg_key_len`/`alg_icv_len`, `alg_name` for the GCM/CCM/GMAC split |
| Outer header | `x->props.mode == XFRM_MODE_TUNNEL`, built from `props.saddr`/`id.daddr` |
| NAT-T ports | `x->encap->encap_sport`/`encap_dport` |
| Lifetimes | not passed: xfrm judges `x->lft` against the `x->curlft` the accounting pass publishes |
| ESN | `x->props.flags & XFRM_STATE_ESN` |
| Starting sequence number | `x->replay.oseq`/`seq`, or `x->replay_esn->oseq`/`seq` with `_hi` under ESN |
| Inbound replay history | `x->replay.bitmap`, or the `x->replay_esn->bmp` ring |
| Anti-replay window | `x->props.replay_window`, or `x->replay_esn->replay_window` |
| Hardware cookie | written back to `x->xso.offload_handle` |

The port's `NETIF_F_HW_ESP` feature bit is set here too, without which
strongSwan never offers the state — see the consumer contract above. It goes
into `wanted_features` as well as `hw_features` and `features`, because
`netdev_get_wanted_features()` is `(features & ~hw_features) | wanted_features`:
once the bit is advertised in `hw_features` the first term stops carrying it,
so anything that later recomputes features would clear it and the only symptom
would be strongSwan quietly declining to offload from then on.

#### The callback contract, which decides where the teardown goes

Three facts about when these run, none of them obvious from the ops struct,
and together they fix the design:

- **`xdo_dev_state_delete()` is atomic.** `xfrm_state_delete()` takes `x->lock`
  with `spin_lock_bh()` around `__xfrm_state_delete()`, which is what reaches
  the callback. Every backend operation needs the control mutex, so no hardware
  teardown can happen there directly.
- **`xdo_dev_state_free()` may sleep**, reached from `___xfrm_state_destroy()`
  on the garbage collector's workqueue or after a `synchronize_rcu()`.
- **The backend must not hold a reference to the state.** Free is reached only
  once the last reference is gone, so a reference held by the SA would be
  waiting for the teardown that is waiting for it. The pointer is borrowed and
  dropped in the teardown.

**And the teardown must not wait for free either**, which is the part this
increment got wrong first and had to be shown on hardware. A frame handed to
SEC holds a reference to the state: it travels on the skb's sec_path so the
transmit path can find its frame queue. That skb is freed *lazily* — the DPAA
submit path stashes it in the scatter-gather table's trailing slot and the
buffer's next user frees it — so on an idle tunnel the next user never arrives,
the references sit there, free never runs, and the SA stays in the classifier
for ever. The next SA with the same key is then refused by the hash table with
`Resource Already Exists`.

The references and the lazy free are both older than this work; patch 040 takes
the same hold on the CMM path. What was new was the coupling: CMM retired an SA
over FCI on its own schedule, so nothing depended on the state's refcount, while
here the teardown *was* the state's destruction. So the hardware is retired from
a workqueue queued by delete — promptly, and independently of any skb — and the
state's lifetime is left to the kernel. The window the earlier revision of this
document accepted, between deletion and the last reference going away, is gone
with it.

**Policy offload is mandatory, which an earlier revision of this document got
exactly backwards.** It first said that declining `xdo_dev_policy_add` was a
deliberate simplification that kept the callbacks out of atomic context. It is
not optional at all: `xfrm_state_find()` skips a packet-offloaded state
whenever the policy that reached it is not offloaded too --

```c
} else if (x->xso.type == XFRM_DEV_OFFLOAD_PACKET)
        /* Skip HW policy for SW lookups */
        continue;
```

-- so an SA paired with a software policy is never selected. On the rig that
looked like success: the SA installed, reported itself installed, and carried
nothing, with `0 packets` on the state and no error anywhere. CDX needs nothing
from a policy, so the ops exist only to make that pairing hold.

Implementing them does make `xfrm_state_find()`'s acquire path reachable, where
`xdo_dev_state_add()` runs under `xfrm_state_lock` with `netdev_hold(GFP_ATOMIC)`
beside it and the failure branch calls `xdo_dev_state_free()` under the same
lock. That is handled rather than avoided: an acquire placeholder carries
`XFRM_DEV_OFFLOAD_FLAG_ACQ`, has no keys and no SPI, and is accepted without
being programmed, so the atomic path never does real work and free finds
nothing to release. Accepting rather than refusing matters -- a refusal there
fails the on-demand tunnel being negotiated.

Proof: `ip xfrm state add … offload packet dev ethN` succeeds, the SA appears
in CDX's cache, `ethtool -k ethN` reports `esp-hw-offload: on`, and deleting
the state releases the SEC context.

#### Proved on hardware, 2026-09-18

`tools/tests/test_ipsec_xfrm_offload.py`, both cases, on a KASAN flowtable
boot. Each was watched failing first: `esp-hw-offload: off [fixed]` before the
ops were attached, and the SA refused before each gate below was cleared.

```
[   15.456749] cdx_ipsec_init SEC era= 8
[   27.688329] ipsec_init_ohport:: ipsec of port id = 9
[   27.695407]  add_ipsec_bpool::bp->size :1792, bpid 34
# ethtool -k eth3 | grep esp-hw   ->  esp-hw-offload: on
# ethtool -k eth4 | grep esp-hw   ->  esp-hw-offload: on
```

**Four refusals stood between the ops being registered and an SA installing,
and each one was a layer the design had not accounted for.** In order:
`Type doesn't support offload` (the ESP offload type, two config symbols);
`dpa_get_iface_info_by_ipaddress returned error` (the local endpoint must be
an address on the port); `dpa_get_out_tx_info_by_itf_id::NULL Route` (an
outbound SA needs egress framing, and this mode keeps no route table); and
`unable to create shared desc` (the SEC buffer pool, skipped by the second
ownership gate). None was visible from reading; each surfaced several layers
from its cause.

#### Counters and lifetimes

xfrm expires an SA on bytes or packets only in `xfrm_state_check_expire()`,
which compares `x->curlft` against `x->lft` and which the stack calls per
packet from `xfrm_output_one()` and `xfrm_input()`. Packet offload reaches
neither: an outbound frame skips `xfrm_output_one()` entirely, and an inbound
one comes back from SEC already decrypted and stamps only `use_time`. So
`curlft` stayed at zero, `ip -s xfrm state` showed an idle SA, and a byte or
packet limit never fired. The legacy SA timer still walked these SAs, but it
compared their limits against the classifier's counters and sent its expiry
notice over FCI, to a daemon that is not there in this mode; the send failed
and was retried every 30 seconds.

The adapter now runs an accounting pass once a second while it owns an SA.
Inside the control transaction, which keeps each SA installed while it is
read, the pass reads SEC's per-SA counters from the shared descriptor. SEC
keeps the packet count in 32 bits and lets it wrap, so the backend builds a
64-bit total from successive readings. A read that races SEC's store can tear
the 64-bit byte count, which is not always 8-byte aligned in the descriptor.
The backend rereads until two readings agree. That is not enough on its own,
because the store spans cache lines and two reads can land between the same
two line updates. So it also refuses a byte count that went down, or rose by
2^32 or more since the last one it believed: a torn value is out by a whole
2^32. A jump that large is believed once the next reading confirms it, so a
pass held off for seconds at line rate does not wedge the count. Under
`x->lock`, and only for a `VALID` state, the pass adds to `curlft` whatever
the totals moved forward since its last publication, and calls
`xfrm_state_check_expire()`. Soft and hard expiry are then xfrm's own, down to
`km_state_expired()` and the state timer. The legacy timer skips SAs marked
`SA_XFRM_OWNED`, and the spec no longer carries lifetimes.

A hard expiry does not stop SEC at once. The state timer deletes the state,
and the SA's classifier entries keep forwarding until the retirement that
follows removes them. An SA can therefore run past its hard limit by up to
one accounting period, plus the retirement's latency.

An outbound SA on the extended encapsulation descriptor, which it gets only
when its features overflow the normal one, keeps no counters at all: that
builder never enables them. Such an SA reports none, and only its time limits
apply. Every other SA has counters, whatever its outer family, despite old
comments in the builder that said IPv4 only. `cdx_ipsec_pdb_len()` places them
past the outer header the encapsulation PDB carries: 20 or 40 bytes, plus 8
for NAT-T. The decapsulation PDB carries no header, so its layout is the same
for both families, and so is the replay state read back from it.
`tools/host_tests/ipsec_backend.c` checks the placement and the read for every
header size.

There is no `xdo_dev_state_update_stats()`. Most of its callers hold `x->lock`
or `xfrm_state_lock`: the state timer, `xfrm_state_check_expire()`, and state
dumps. So it cannot sleep for the control mutex, under which the backend
builds its 64-bit packet total; a second reader outside the mutex would race
the pass. `XFRM_MSG_GETSA` reaches it holding only `xfrm_cfg_mutex`, and there
nothing keeps the SA from being retired underneath it. What the op could
publish, `curlft` already holds, at most a second old. mlx5 is no fresher: its
flow counters are cached on a one-second period (`MLX5_FC_STATS_PERIOD`), and
a one-second work judges its software limits (`mlx5e_ipsec_handle_sw_limits()`).

The pass also raises a soft expiry for a non-ESN outbound SA within 2^28 of the
end of its sequence space. SEC does not wrap the sequence number: past the
last one every frame fails in SEC. At 1.4 Mpps the space lasts 51 minutes,
less than strongSwan's default hour between rekeys. The legacy owner reported
the approach to CMM; here it is the same soft expiry a lifetime raises, once
per state. 2^28 is over three minutes at that rate, enough for an IKE
exchange and its retransmissions.

The pass takes a reference on each state while `ft_ipsec_retired_lock` shows
the state's entry still owned: xfrm drops the reference that keeps a state
alive only after `xdo_dev_state_delete()` returns, and that callback takes the
entry off the owned list first. The pass takes `x->lock` only after it drops
that lock, because deletion takes the two in the other order. Module exit
cancels the pass after draining retirements; by then no SA is owned, since
every offloaded state pins the module through its ops.

#### The starting sequence number and the replay window

The SA cache started every SA at sequence zero and gave every inbound SA a
64-entry window, because FCI carried neither value. An outbound state installed
with a non-zero `oseq` therefore sent numbers its peer had already seen, and
the peer dropped every frame until the count passed them. That happens when a
state is migrated, or re-added by a keying daemon that moves it to a new
address. The inbound window ignored the configuration, including a window of
zero, which turns anti-replay off.

The spec now carries both values in xfrm's units. `seq` is the last number sent
for an outbound SA, which the PDB builder seeds SEC one past, and the highest
number received for an inbound one, where SEC anchors its window. The high word
counts only under ESN. `replay_window` is the width in packets. The backend
refuses a non-ESN number above 32 bits, and an outbound number with nothing left
to send. SEC refuses to send the all-ones number (SEC RM table 9-2), so the
last outbound number is `FFFFFFFE`, or `FFFFFFFF:FFFFFFFE` with ESN. A state
whose `oseq` is one below that or higher is refused.

The ESP decapsulation PDB offers three windows in its ARS bits: 32, 64 and 128
entries. SEC's stand-alone anti-replay command takes any width up to 128, but
the ESP protocol does not expose it. A width between two sizes is carried on the
next larger one. That loses nothing: anti-replay refuses every sequence number
it has already seen at any width, and the width only bounds how late an unseen
frame may arrive and still be accepted. A narrower window would drop late
frames the configuration accepts, so an inbound window wider than 128 is
refused with an extack message rather than narrowed, as mlx5 refuses any width
its hardware does not keep (`mlx5e_xfrm_validate_state()`). An outbound SA
checks nothing, and its window is ignored. Zero clears the window: the backend
passes it to the cache create as `SA_ALLOW_SEQ_ROLL`, and the PDB gets
`ARSNONE`. SAs created over FCI keep their 64 entries.

SEC numbers and checks the frames, so xfrm's own replay state never moves
unless the accounting pass moves it. Anything that carries a state on reads
that copy: `XFRM_MSG_GETAE`, which a keying daemon reads to carry the state over
when it re-adds an SA at a new address (strongSwan's MOBIKE update does: GETAE,
delete, add), and the clone `xfrm_state_migrate()` makes. So the pass publishes
both directions back, forward only:

- **Outbound**: SEC's last sequence number, plus twice what the SA sent in the
  last period. SEC keeps numbering until the SA is deleted, up to a period
  after the reading plus however long the daemon takes between GETAE and the
  delete. A re-add that started behind that would reuse numbers, while skipping
  ahead looks like loss to the peer and costs nothing. Twice covers a rate that
  rises into the next period. A burst out of idle in the last period before a
  re-add can still exceed it. A non-ESN SA stops at the end of its space.
- **Inbound**: the decapsulation PDB's sequence number and scorecard, written
  into `x->replay.seq` and its bitmap, or into `replay_esn->seq`, `seq_hi` and
  the `bmp` ring. SEC keeps the newest number in the least significant bit of
  its first scorecard word, and each bit to the left one older (SEC RM, IPsec
  anti-replay). xfrm's ring keeps the newest at `(seq - 1) % window` and each
  older one position before it. Without this, a re-add was anchored at zero,
  and every number the old SA had ever accepted could be replayed once.

In the other direction, a state added with inbound history seeds the PDB with
it. The sequence number anchors SEC's window, and the bitmap becomes its
scorecard, so a re-add carries on from where the old SA left off. Positions
past the state's own window are history xfrm does not keep, while SEC's window
may be wider. They are marked as seen, so SEC refuses as a replay what xfrm
would have refused as too old.

One case is open. With ESN, the PDB is seeded with the window top's high word.
The SEC RM says SEC holds its own stored ESN back after a rollover until the
whole window is past it ("Optional use of ESN in ESP decapsulation"). In the
first window-width of numbers after a rollover, the stored ESN is therefore
one below the top's. The RM does not say which value SEC expects of a window
seeded inside that stretch, or how it tells that stretch from the start of a
fresh SA, whose window also reaches below number zero. A wrong choice fails
every frame's ICV. The rig settles it:

1. Add an inbound ESN SA on the DUT with `replay-window 64 flag esn
   replay-seq-hi 1 replay-seq 5 offload packet`. Give the peer's matching
   outbound ESN SA `replay-oseq-hi 1 replay-oseq 5`, so that its next frames
   are (1, 6), (1, 7), and so on. Send 20 frames through the tunnel.
2. Do the same with `replay-seq 200` and `replay-oseq 200`, which is outside
   the stretch. Both readings agree there, so this is the control.
3. Add an inbound ESN SA seeded at (0, 0xffffffe0), which is outside the
   stretch, with the peer starting at `replay-oseq-hi 0 replay-oseq
   0xffffffe0`. Send frames across the rollover. After 10 post-rollover
   frames, and again after 70, read the SA's replay state with
   `ip xfrm state`. The pass publishes the PDB's numbers, so a top at
   `seq_hi 1` after 10 frames means SEC stores the top's high word. A top still
   at `seq_hi 0` until the window has passed means SEC stores the window
   bottom's.

In each step, count what the LAN side receives, and the SA's `failed` count in
`ip -s xfrm state` with `XfrmInStateProtoError`. With the top's convention,
every step delivers all its frames. With the bottom's, step 1 refuses all 20
as ICV failures while step 2 delivers, and `cdx_ipsec_build_in_replay()` then
has to seed `hi - 1` inside the stretch.

### 4. The slow path

Replace `x->offloaded` with `x->xso.type == XFRM_DEV_OFFLOAD_PACKET` at the
datapath sites, publish the backend's handle as `x->handle` so the SEC
completion path can still resolve a decrypted frame, and give packet-offload
tunnel output the sec_path and the finished Ethernet header SEC expects.

Four things in that hunk are not obvious, and each one was a failure first:

**Tunnel mode goes to the device directly, but not by
`xfrm_dev_direct_output()`.** That path pushes `hard_header_len` of
uninitialised space, because it is written for hardware that writes the L2
header itself, and SEC is handed the frame with its Ethernet header. The first
version therefore sent every packet through the ordinary neighbour output,
which tied a tunnel's plaintext to a neighbour of its *inner* destination:
wrong for any tunnel, and impossible for one whose outer family differs — an
IPv4-only WAN has no IPv6 neighbours, so IPv6-in-IPv4 carried nothing.
`xfrm_dev_sec_output()` transmits to `x->xso.dev` with a header that names the
inner protocol and leaves both addresses zero. `cpe_fp_tx()` reads that
ethertype to find the inner packet, SEC copies the fourteen bytes ahead of the
tunnel header it builds, and the IPsec offline port rewrites the addresses and
the ethertype from the SA's own next hop and outer family
(`fill_ipsec_actions()` → `create_ethernet_hm(info, 1)`). It does not run the
child route's `local_out`: with `ipsec_offload` set, 030's `__ip_local_out()`
and `__ip6_local_out()` skip `LOCAL_OUT` and transmit through the child's
neighbour themselves, which is the path this replaces, and the inner header
was already finished by its protocol's output on the bundle or by forwarding.
The SA's next hop is still used per packet, as neighbour output used it: that
keeps Linux's entry from ageing out and resolves it again after a flush or a
carrier flap, and that entry is what refreshes the SA's programmed address and
lets its flows back into hardware. The frame does not wait for it. Transport
mode is addressed to the peer itself and keeps the ordinary path.

**It only ever leaves by the SA's device.** The frame is still plaintext and
only that port hands it to SEC; any other device would send it in the clear,
and the upstream wrong-device drop in `validate_xmit_xfrm()` never sees it,
because it keys on `xfrm_offload()` and this frame carries no `olen` (below).
So `xfrm_output()` drops a bundle whose route leaves by another device — the
route to the peer moved by a failover, a more specific route or a rule — and
`validate_xmit_xfrm()` drops a frame moved off the device afterwards, by a
hook, a qdisc action or a stacked device. Both count `XfrmOutBundleCheckError`,
a counter nothing else in this kernel increments. The adapter's own check that
the route to the peer leaves by the SA's port, at install and when the peer
moves, asks the FIB unbound: bound to the port, the lookup answered through it
whatever the table held, so that refusal could never fire and a peer routed
elsewhere was followed to a next hop on the old port. Patch 146 is the other half
for a tunnel whose outer family differs: the child route is the flow's own
when that leaves by the SA's device, instead of the SA's endpoints looked up
in the wrong family. That route then cannot name the tunnel's next hop, so
the flowtable's Ethernet destination, the adapter's next hop and the direct
output's per-packet neighbour use come from `xfrm_dev_peer_route()`, which
routes the endpoint in the SA's family with the SA's output mark and its
port's VRF, and the adapter checks and watches that neighbour in that family
(`cdx_ft_rule.next_hop_family`). Before, both read the IPv4 endpoint as an
IPv6 address on the route under the bundle, which answered only through a
default route's gateway. The same per-packet lookup is where such an SA's
endpoint moving off its port shows, so the packet is refused as
`XfrmOutBundleCheckError` there, as a same-family SA's is by its own route;
and the lookup names its next hop itself, so an on-link endpoint takes the
FIB's cached route rather than the per-lookup clone the tunnel lookups ask
for. The adapter's own peer lookup carries the same mark and VRF.

**It must set `sp->len` and not `sp->olen`.** `xfrm_offload(skb)` answers
non-NULL exactly when `olen` is non-zero and equal to `len`, and a non-NULL
answer draws the frame into `validate_xmit_xfrm()` on the way out — which, on
a device advertising `NETIF_F_HW_ESP`, encrypts it in software and hands the
driver a finished packet. The tunnel then works perfectly with the hardware
counter at zero, which is exactly how this was found. The crypto-offload
branch below does increment `olen`, because that path wants the fixup.

**It must complete the checksum.** `skb_checksum_help()` sits after the
packet-offload branch, so a locally generated frame still carrying
`CHECKSUM_PARTIAL` reaches SEC unfinished. ESP authenticates the ciphertext,
not the payload inside it, so such a packet encrypts, traverses and decrypts
perfectly and is then dropped at the far end for a bad inner checksum: the
peer's SA counters advance and nothing is delivered. Upstream skips that help
only for a device advertising `NETIF_F_HW_ESP_TX_CSUM`, which this does not
claim.

A GSO packet cannot be finished that way: `skb_checksum_help()` refuses one
with a warning and the packet was dropped, which is every TCP packet a local
socket builds over the tunnel and every forwarded one the LAN port's GRO
merged. So `xfrm_dev_sec_gso()` segments it first, in software and with no
features, as `xfrm_output_gso()` does for a software transform, and each
segment goes on as a packet of its own: SEC encrypts one packet per ESP, and
the port's own segmentation would leave the checksum to a transmit offload
that frames bound for SEC never reach.

**A transport frame names its own header to SEC.** The driver gives SEC a
DPOVRD word with every frame, and a set word overrides the SA's PDB. A
tunnel's word names the inner protocol for the ESP trailer. Transport mode was
given the same word, which also states a header length and a next-header
offset of zero: SEC then encrypted the IP header with the payload and named
IPIP in the trailer, and the peer decoded nothing. `dpa_ipsec_dpovrd()` now
gives a transport frame its own IP header length, options included, and for
IPv6 the hop-by-hop, routing and leading destination-options headers that
precede ESP; and the offset of the next-header byte SEC swaps for ESP: 1 for
IPv4's protocol byte or the IPv6 fixed header's, otherwise the extension
header, in eight-byte units, whose first byte it is. A header the word cannot
describe — not in the linear area, or longer than the field's 255 bytes —
fails the frame rather than send it encrypted wrong.
`tools/host_tests/test_ipsec_dpovrd.py` compiles that function out of the
patched tree; `test_ipsec_offload_transport.py` has a software peer decrypt
the DUT's transport traffic, half of it carrying IPv4 options.

Proof: a tunnel carries traffic with no flowtable entry at all, with the SEC
counter advancing and an independent peer decrypting what it produced.

#### Proved on hardware, 2026-09-18

`tools/tests/test_ipsec_packet_offload_traffic.py`, on a KASAN flowtable boot.
The tunnel runs between the DUT and the LAN VM; only the DUT is offloaded, so
the peer's decryption is an independent check on what SEC emitted.

```
endpoints      = 192.168.1.1 <-> 192.168.1.122
sec_frames     = 32     frames the DUT's port handed to SEC
peer_decrypted = 32     frames the LAN VM authenticated and decrypted
delivered      = 32     payloads intact
```

On the wire, captured at the peer: 32 × `ESP(spi=0x0a878e3e,seq=0x1..0x20)`.

**Putting the far end on the orchestrator instead was a mistake that cost
hours.** There the decrypted datagrams reached the IP layer and were dropped by
that host's own input path, so the peer's SA counters advanced while nothing
arrived — evidence that looked exactly like a malformed-packet bug in the
offload and was nothing of the sort. A bench whose far end is an ordinary host
on the segment, with the test machine outside the path, is worth insisting on.

### 5. The outbound fast path

`struct cdx_ft_rule` gains the SA handle; `cdx_ft_hw_add()` sets
`CONNTRACK_SEC` and `hSAEntry[]`; the adapter resolves the SA, applies the
eligibility contract and publishes an SA watch. Patch 140 also stops hiding
transformed destinations from the driver: `nf_flow_offload_dst()` returned NULL
for anything but `XMIT_NEIGH`, although `flow_offload_fill_route()` fills NEIGH
and XFRM from the same branch and both genuinely hold one.

#### Ask the policy, not the destination

The obvious implementation is to read `dst_xfrm()` off the destination the
callback already borrows. It is wrong, and wrong in the direction that matters.

A transformed destination only reaches the flowtable for **locally generated**
traffic. A *forwarded* flow is routed by `nf_route()` with a plain FIB lookup
and is transformed afterwards, in `xfrm_route_forward()` at POSTROUTING, so its
cached destination never carries the transform that will be applied to it.
`dst_xfrm()` therefore answers "no transform" for exactly the flows a gateway
encrypts — and the flow is then installed as an ordinary plain one, so the
classifier forwards in hardware what the policy says to encrypt. **Measured on
the bench before this was fixed: fifty-nine packets forwarded past a `level
required` policy, in the clear.**

That blind spot is this branch's own. The `dst_xfrm(dst)` refusal came in with
`444af05`, which created the adapter; NXP has no flowtable adapter at all. It
had never been reachable because IPsec did not work in this ownership mode
until the first increment above made it work, which is why it surfaced here
rather than earlier.

So admission repeats the lookup forwarding itself does — `xfrm_lookup()` with
the flow's own translated tuple, ports included, since a selector can name them
— and believes the answer. Three outcomes: no policy, and the flow is plain; a
policy resolving to an offloadable SA, and its handle goes on the rule; a
policy that matches but resolves to nothing usable, and the flow is **refused**
so the software path can do whatever the policy asks, including an acquire.

One subtlety, found by KASAN rather than by reading: on success
`xfrm_bundle_create()` links the destination into the bundle and takes over the
caller's reference to it. `XFRM_LOOKUP_KEEP_DST_REF` does not prevent that; it
only suppresses the extra release on the paths that fail. Passing a borrowed
destination therefore hands over a reference that was never ours, and releasing
the bundle frees a destination the flowtable still uses —
`slab-use-after-free in rcuref_put()`, which panicked the DUT. The lookup takes
its own reference first and gives it back on the paths that consume nothing.

#### The SA is a dependency, like a route or a neighbour

A direction names its SA by handle, and handles are reused once their SA is
deleted, so the flows have to be retired before the hardware is. They are, from
the same callback that queues the retirement, and `ipsec_invalidations` in
`/proc/cdx_flowtable` counts them alongside the other causes. Retiring rather
than rewriting matches every other dependency here: Linux stops using its
cached lookup at once and the flow is readmitted from scratch on the next
packet.

Proof: the tunnelled direction offloaded with its SA named, the return
direction plain because no policy covers it, and — the oracle that separates
this increment from the one before it — `tx toenc` advancing by **one** rather
than by the packet count. That counter counts frames the *software* path handed
to SEC, so on the slow path it tracks the transfer; here it moves once, for the
packet that travelled before the entry existed, and then stops while the rest
goes through. Throughput cannot tell the two apart.

`devlink trap policer 2` is not part of that proof, and the earlier revision of
this document overstated it. The policer reports drops, not passes, so a drop
count of zero is consistent with metering traffic and dropping none of it —
but it does not by itself demonstrate that frames traverse the meter. Showing
that would mean exceeding 14.88 Mpps, which is line rate for minimum-size
frames on this port.

### 6. The inbound fast path

The offline-port half, scoped after step 5 measured rather than before.
Measuring first was right: two of the three things this step turned out to
need were invisible from the source, and one of them was that **step 5 had
never been exercised by a tunnel at all**.

#### What the hardware was already doing

The first measurement was an inbound offloaded SA on its own, with no flow
involved. It installs, and SEC decrypts every arriving ESP frame in hardware:

```
tx todec delta : 0      frames the software path handed to SEC
delivered      : 32/32  payloads the DUT's inner listener received
DUT  SA counters: 0 packets   xfrm_input() never ran
loki SA counters: 32 packets  the peer encrypted all 32
```

So the SPI-keyed half of inbound was complete before this increment started:
the inbound SA's own classifier entry steers ESP to SEC, and `xfrm_input()` is
not on the path. What was missing is everything after decryption.

#### The three defects, in the order the bench found them

**The decrypted frame is classified on the offline port.** An entry keyed on
the physical ingress port cannot match it, so the reverse direction's entry was
installed, counted as installed, and never matched a frame:

```
in=eth4 out=eth3  sa=0  packets=58    forward direction, hardware
in=eth3 out=eth4  sa=0  packets=0     reverse direction, installed and dead
```

Every decrypted frame reached the CPU instead, which the exception handler
counted 59 times for a 60-packet transfer.

**A transformed destination was refused by three generic helpers.**
`flow_offload_eth_src()`, `flow_offload_eth_dst()` and
`flow_offload_redirect()` each answer `-EOPNOTSUPP` for
`FLOW_OFFLOAD_XMIT_XFRM`, and the first of them fails
`nf_flow_offload_rule_alloc()` — which runs before any driver callback, for
both directions. A printk settled it where reading had not:

```
ASKDBG skip: sec_path present
ASKDBG route: dir=0 xmit[dir]=2 xmit[!dir]=1 this_dst_xfrm=1
ASKDBG route_common: dir=0 xmit=2 src=-95 -> REFUSED
```

`-95` is `-EOPNOTSUPP`, and `counter deltas {}` on the adapter's own statistics
confirms it never heard about the flow.

This is what makes the defect bigger than the increment. **Step 5's proof holds
only because its bench encrypted one direction.** A flow is created by whichever
packet reaches `nft flow add` first; with a plain return direction that is the
reply, whose destination carries no transform, so both tuples come out
`NEIGH` and nothing notices. Give the tunnel its other half and every reply
carries a `sec_path`, `nft_flow_offload_skip()` declines it, and the only packet
left to create the flow is the encrypted one — whose destination *is* the
bundle. The whole connection then falls back to software, both directions, with
no error anywhere. Measured: `tx toenc` tracking the transfer one for one at 60
of 60, and `conntrack -L` showing `[OFFLOAD]` without `[HW_OFFLOAD]`.

**`ft_next_hop()` resolved the wrong address past a transform.** The walk down
to the underlying route was already there, written for this case in step 5 and
never reached. What it then asked that route for was the flow's own
destination. Through a gateway route that is harmless, because `rt_nexthop()`
returns the gateway whatever it is handed; on an on-link route it returns what
it was given, so the next hop came back as the *inner* destination, which is
not on this segment and has no neighbour. The address to resolve is the
outermost state's `id.daddr`.

#### What the adapter now asks

A direction has two ends and they need different questions, so the one policy
lookup is asked twice: once about what the direction sends, and once about the
reversed tuple leaving by the ingress port, which is what the far end sent.
The second answer names an *outbound* SA, and the inbound half of that pair is
the state whose destination is our local endpoint and whose source is the peer
— `xfrm_state_lookup_byaddr()` answers exactly that, so the pairing stays the
kernel's fact rather than a second index kept here.

Refusal differs by end, and that asymmetry is the sharp edge:

- **sending** — a policy that claims the tuple and resolves to nothing the
  hardware can carry is a refusal, or the classifier forwards in the clear what
  the policy says to encrypt.
- **receiving** — a policy proves nothing about what the far end actually
  sends, so only a *state* does. An inbound SA for this pair that exists and
  cannot be named is a refusal, because its frames are decrypted before they
  could match this tuple. Its absence is simply a direction whose frames arrive
  in the clear, and must install exactly as it always did — a one-way tunnel is
  unusual but legal, and refusing it would give up an acceleration that works.

The handle then rides `cdx_ft_rule.in_sa_handle` into `hSAEntry[1]` with
`CONNTRACK_SEC`, and `cdx_ipsec_fill_sec_info()` does the rest: it recognises
the inbound direction, replaces the table descriptor and port id with the
offline port's, and the entry lands where the decrypted frame is actually
classified. That hook is the one CMM has been driving for years; only the
description reaching it is new.

#### Proved on hardware, 2026-09-18

`tools/tests/test_ipsec_inbound_flow_offload.py`, on a KASAN flowtable boot.
Both halves of the tunnel are offloaded, the DUT forwards between the WAN-side
orchestrator and an inner address on the LAN VM, and only the DUT is in
hardware.

```
in=eth4 out=eth3  sa=1  in_sa=0  packets=57   encrypted direction
in=eth3 out=eth4  sa=0  in_sa=2  packets=57   decrypted direction
tx toenc delta : 3     was 60, one per packet
tx todec delta : 0     inbound never reaches the software SEC submit
exception drops: 2     was 59, one per decrypted frame
conntrack      : [HW_OFFLOAD]
```

The reverse direction's own packet counter is the oracle, because it is what
separates an entry that exists from an entry that matches. It read zero for the
whole transfer before this increment while the echo still worked.

One log line was retired along the way. `ipsec_exception_pkt_handler()`
reported `packet dropped` whenever `netif_receive_skb()` answered
`NET_RX_DROP`, and that answer does not mean the frame was dropped:
`__netif_receive_skb_core()` leaves its return at `NET_RX_DROP` whenever an
ingress hook takes the frame, which is what the flowtable's software path does
to every decrypted frame it forwards. Fifty-nine of sixty "dropped" frames were
delivered. A counter that cannot tell a loss from a steal is worse than none,
and at line rate it is also a log flood.

### 7. Parity

A paired-boot measurement against CMM, same image, same tunnel, same traffic,
same CPU accounting, per the roadmap's parity table. Retirement needs parity,
not capability — and the first attempt did not have it.

#### The MTU the classifier is told is the outer one

Tunnelled TCP through the flowtable ran at 0.07 Gb/s against the legacy
owner's 2.54 on the same bench, with a quarter of the DUT's CPU spent and the
software SEC submit counting once per packet. Everything that looked like
evidence of an offload was there: both directions installed, the SA named, the
entry's own counter tracking every frame, and ESP on the wire. The entry was
matching and then excepting each frame to the CPU, which encrypted it — an
offload that works and performs like software.

The cause is one field. The microcode compares the size of what it
*transmits* against the MTU programmed in the entry, and for a direction handed
to SEC that is the outer frame: the expansion travels separately, in
`hdr_xpnd_sz`, and is added before the comparison. Netfilter's MTU for a
transformed flow is the tunnel-*reduced* inner one, so programming
`cls->nf_mtu` directly asks the hardware whether 1438 + 44 fits in 1438. It
does not, and every full-size frame took the exception path.

NXP wrote the rule down at the only other site that meets it, where a tunnel
interface's reduced MTU is corrected before programming:

```c
// In case of tunneling , interface MTU was reduced with tunnel header size
// In ucode , as we are checking the total packet size with MTU after tunneling ,
// We need to program MTU size in ucode including the tunnel header size.
l2_info->mtu += l3_info->header_size;
```

The legacy owner never met it because its route table holds interface MTUs
rather than per-flow ones. So a direction carrying an outbound SA now programs
the egress port's MTU, and `cdx_ft_rule.mtu` keeps meaning what it meant: the
flow's own bound, which admission still checks and `/proc` still reports.

Worth naming the shape of this, because it is the second time in this
increment: a hardware path that *degrades* rather than fails is invisible to
every functional test. The step 6 proofs all pass against the broken MTU —
they move sixty packets, and sixty packets through the CPU look exactly like
sixty packets through SEC. Only a rate measurement separates them, which is
what parity is for.

#### Proved on hardware, 2026-09-18

Paired boots, same non-KASAN image, same tunnel, same traffic, two settled
runs per cell with each boot's first run discarded, and every run gated on the
LAN segment not having flapped during it.

| Direction | Flowtable | CMM |
| --- | --- | --- |
| WAN to LAN, encrypting | 2.55 and 2.55 Gb/s | 2.55 and 2.55 Gb/s |
| LAN to WAN, decrypting | 2.65 and 2.65 Gb/s | 2.72 and 2.71 Gb/s |

Both owners were confirmed to be carrying it in hardware rather than reaching
the rate in software, and by the same oracle in both: `tx toenc`, the count of
frames the *software* path handed to SEC, stayed between 20 and 54 for
transfers of roughly two hundred thousand packets. The legacy owner's
connection table showed `IPSEC(Init:sa_nr=1 ...) (Reply:sa_nr=1 ...)`; the
adapter's showed both directions with their SA handles.

The encrypting direction is identical. The decrypting direction is 2.4 per cent
slower under the flowtable, consistently across three runs each — small, real,
and not explained here; it is the direction that crosses the offline port
twice, so a per-frame cost there is the first place to look if it ever matters.

The absolute rate is the LAN VM's software crypto ceiling, not the DUT's: only
the DUT's SAs are in hardware. That ceiling is identical on both sides of the
comparison, which is what makes the DUT's own cost the thing being measured.

A DUT reset was observed once during a UDP variant of this bench under the
legacy owner, with no console logger attached and nothing captured. ISSUES A155
was closed as wontfix on 2026-09-21 because CMM is being retired; its root cause
remains unconfirmed.

### 8. Following a peer that moves

The last piece of the legacy owner's control surface with no successor. An
outbound SA's next hop is resolved once, at install, and written into the
classifier entry's header-manipulation opcodes; nothing re-reads it per frame.
So a peer that moves — a gateway failover, a replaced NIC at the far end —
left the tunnel emitting to an address nobody answers to, with no error
anywhere. CMM was told about it as `CMD_IPSEC_SA_SET_TNL_ROUTE`.

Three things decide the shape, and the first two are what make it small.

**It is a rebuild, not a field update.** The address is in the entry's
opcodes, so the entry has to come out and go back in — which is exactly what
the legacy handler did, for the same reason. The SEC context is untouched:
`SA_SH_DESC_BUILT` keeps the shared descriptor, so the keys, the PDB and the
outer header stay as they were and the sequence numbers do not restart. The
old entry must be provably gone before the new one goes in, because both carry
the same key and a bucket holding two copies of one key cannot be cleared
afterwards; a delete that cannot prove it refuses the rebuild and leaves the
SA on the address it had, which is no worse than not trying.

**It is a watch, not a poll.** The notifiers that retire a flow whose
neighbour or route moved already fire for exactly this; an SA riding the same
segment is marked from the same place. Marking rather than retiring is the
whole difference between an SA and a flow: a flow is readmitted from scratch
by its next packet, which is why retiring it is enough, and nothing re-offers
an SA. Its hardware has to be corrected in place.

What a marked watch is worth telling about is narrower than it first looks. A
neighbour that has merely aged names the address the entry already carries;
one that has gone *unusable* — incomplete, failed, dead — names nothing
better to program, and chasing it is worse than useless. The re-resolution
probes what it finds, the probe fails, that failure is itself a neighbour
update, and the two keep each other going for as long as the peer stays down.
So only a usable neighbour naming a *different* address marks anything, which
is where this parts company with the flow watch: a flow with a dead neighbour
should be retired, because Linux resolves it again on readmission.

The port's own hardware address is in those same opcodes, so it is watched
too. That took fixing something older first. The encoder read that address
from a field in CDX's interface record which was filled once from `perm_addr`
at registration and never followed a change — so a rebuild would have re-read
the same stale bytes, reported success and cost a live tunnel a classifier gap
for nothing. `perm_addr` is the *permanent* address; it does not follow
`ip link set … address` by definition, and no FCI command ever updated the
copy either.

That field is gone. The ethernet arm reads `net_dev->dev_addr` where the
header is encoded, which is the only value that is ever right, and the record
has held a reference to the device since registration so the read is always
safe. Every other interface type in that family keeps its stored address,
because CMM invents those interfaces and describes them over FCI — there is no
kernel object to ask. This was the one arm that had one.

It is worth being clear about what that fixes, because "follows a change" is
the smaller half. An SA installed at any point *after* a MAC change previously
took the stale address and kept it for ever, with no event that could correct
it — which is the ordinary case for a gateway whose address is set in
configuration before the tunnel comes up. The legacy owner's route entries
read the same field and had the same defect.

A local change also has a second-order effect worth knowing: setting a port's
address flushes that device's neighbour table, so the rebuild it triggers
always finds the peer momentarily unresolvable and fails. What recovers it is
the neighbour coming back — carrying the address it always had. That is why an
*unchanged* neighbour still marks a watch that is already waiting to retry:
without it the SA would sit on the old framing until the peer happened to move
as well.

**The correction cannot happen where it is noticed.** The notifiers run under
`neigh->lock` and the adapter's watch lock; a rebuild needs the control mutex
and sleeps. So a work item does it, and the SA's lifetime gets one rule the
work depends on: `ft_xdo_state_delete()` unlinks the watch *before* it queues
the retirement that frees the SA, and that retirement takes the control mutex.
A watch still on the list while the mutex is held therefore names an SA that
is still there. Nothing dereferences a watch outside the lock, which is what
the per-watch cookie is for: a freed watch's memory can be reused by the next
SA installed, and an address would then name the wrong one.

Both of those unlink paths take their locks with softirqs off, and that is not
decoration. `xdo_dev_state_delete()` looks like an atomic-context callback —
`xfrm_state_delete()` holds `x->lock` across it and `xfrm_timer_handler()` runs
in a softirq — but `xfrm_add_sa()` also reaches it directly from netlink when a
state fails to insert, with softirqs enabled. The watch list is walked from
softirq by the neighbour notifier, so a plain `spin_lock` on that path would
deadlock against an ARP reply landing on the same CPU.

**A rebuild that fails is terminal for that SA's framing, not just for the
attempt.** The delete frees the entry's software bookkeeping whichever way it
went, so after a hard failure nothing distinguishes "no entry" from "an entry
still linked under a key we no longer track" — and a second attempt would add
that key on top of the one the hardware still holds, which is the duplicate
bucket the delete refuses to risk in the first place. So such an SA is marked
and never moved again; it keeps classifying on the framing it has until it is
deleted and reinstalled. An outbound NAT-T entry shared with another SA on the
same UDP tuple is refused for a different reason: its delete only drops a
reference, so a rebuild would change nothing and claiming otherwise would be a
lie. That one is retried once the twin is gone.

Re-resolution does not wait for a neighbour the way an install does. An
install has nowhere to retry from — packet offload has no software fallback,
so a refusal fails the tunnel — while a re-resolution has the neighbour event
that will arrive when the peer answers. So it probes and returns rather than
holding a shared workqueue for seconds, and a failed lookup leaves the SA on
the address it has.

A failure is said out loud, once per SA and again after any recovery, because
one case cannot be fixed at all: a peer that moves to a route leaving by a
*different* port. Packet offload binds a state to one device and this SA's
egress framing belongs to that device, so there is nothing to rebuild — and
nothing else would report it. The watch is re-marked rather than re-queued,
so the event that fixes the underlying problem is what brings the work back;
re-queueing would spin against a peer that is simply down.

`ipsec_next_hop_updates` in `/proc/cdx_flowtable` counts the rebuilds, beside
the invalidation counters.

#### Proved on hardware, 2026-09-18

An SA installed on `eth4`, then `ip link set dev eth4 address …`, watched
through `ipsec_next_hop_updates` and the adapter's own log:

```
device_moved match=1                         the address change marks the watch
follow rc=-113                               the peer is unresolvable: that change
                                             just flushed the neighbour table
neigh stale=1, ha unchanged                  the neighbour comes back
follow rc=0   was_src=e8:f6:d7:00:01:14      rebuilt on the port's new address
peer then moves to ..91:ee
follow rc=0   was_src=02:00:00:00:91:aa      rebuilt again, and the watch had
                                             recorded the new local address
ipsec_next_hop_updates                       0 -> 1 -> 2
```

**The bench lied first, and the lie is worth recording.** Every SA the test
helper installed was hard-expiring seconds after install, so the watch was
gone before any of this could be observed and the feature looked unreachable.
The cause was in the helper, not the adapter: it set all eight fields of
`xfrm_lifetime_cfg` to `XFRM_INF`, and while that is right for the byte and
packet limits, `xfrm_timer_handler()` computes the *time* limits into a signed
`time64_t` — where `XFRM_INF` is −1, so the state expires on the first tick.
iproute2 sends zero for those four. An SA that quietly disappears a moment
after install still passes a test that installs and acts at once, which is how
far this got before a `dump_stack()` in the delete callback named
`xfrm_timer_handler` as the caller and ended the argument.

#### Proved off the hardware

`tools/host_tests/test_ipsec_adapter.py`. The watch is the part a rig run
cannot show cheaply — a peer moves once, correctly, and the interesting cases
either do not occur or occur once in a way nothing distinguishes from
success — so the cases live in the harness: a neighbour that aged versus one
that moved, a peer that has gone away and must not be chased, a route event
that turns out to have changed nothing, a rebuild the hardware refuses, and
the delete-versus-resolve ordering, proved by draining the retirement queue
between the two and watching the work decline to touch the freed SA.

### 9. Two feeders, one sequence counter

Every outbound SA has two feeders into its SEC queue. The classifier enqueues
the frames of offloaded flows. The CPU enqueues everything else the policy
covers: a flow's frames before admission, ICMP, and anything the flowtable
never takes. Both land on the same queue, whose context names one shared
descriptor, and that descriptor's PDB holds the ESP sequence number. SERIAL
sharing and the per-job PDB store (see `cdx_ipsec_sh_desc_hdr_flags()`) order
the jobs of one descriptor so that no number is handed out twice.

SEC decides which jobs share a descriptor by its address **and the ICID** of
the frame (SEC RM §7.3.2). The ICID travels in each frame descriptor. QMan
stamps CPU-enqueued frames with the software portal's ICID, and an FMan port
stamps its own. The boot firmware gives both the same value, 63
(`FSL_DPAA1_STREAM_ID_END`). The SDK FMan driver then read the ports' values
back from the big-endian `FMBM_PPID` table with a native load, got 0, and
programmed 0 into every port after the FMan reset. To SEC the SA was two
descriptors. Classifier-fed and CPU-fed jobs ran side by side in separate
DECOs from the same stored number, and the peer dropped the later copy as a
replay. Each duplicate pair also shared its outer IPv4 ID, which comes from the
same PDB.

TCP absorbs this as a retransmit, which is why it went unnoticed.
The ~0.45 % replay-window rejections recorded in that function's comment
during the GCM work were this bug.
A UDP flow loses the datagram. The suite saw it as one protected datagram
missing right after a flow was admitted: its last CPU-path frames overlapped
hardware traffic on the same SA.

Patch 106 keeps the firmware's port ICIDs for every port type (Rx, OH, Tx and
the host-command port). Storage profiles take their port's value too: the VSP
ioctl, and `cdx/vsp_cfg.c` for the Wi-Fi profile. The fix trusts the boot
firmware, as mainline's FMan driver does. A bootloader that gives FMan ports
and QMan portals different ICIDs brings the reuse back.

#### Proved on hardware, 2026-09-23

`test_flowtable_service_ipsec_shared_sequence`: an offloaded UDP blast and a
CPU-path ICMP flood on one SA for 4 s, ESP captured at the peer. The DECO ICID
row samples SEC's per-DECO debug register while only hardware traffic runs.

```
                              before patch 106    after
CPU-fed frames                292                 1,965
(SPI, seq) pairs sent twice   272                 0
peer replay drops             274                 0
DECO ICID, classifier-fed     0                   63 (0x3F)
```

A pure CPU flood reused nothing even before the fix, because all its frames
carry one ICID.

## Tests

IPsec is described elsewhere as the most covered subsystem left on the board.
That is true by file count, and the useful question is not how many files
reach it through FCI — nearly all of them do — but **whether what a file
asserts survives the port**. Sorted that way the seven files split three ways,
and only the first group is dead.

**Removed, because the thing they assert is the thing being deleted.**
`test_ipsec_offload.py` asserted the wire layouts of `0x0A01`, `0x0A04`,
`0x0A07`, `0x0A02` and `0x0A0A`, and `test_concurrent_query_vs_mutator_ipsec.py`
asserted the per-cursor locking in `cdx/query_ipsec.c`. That cursor exists only
to serve FCI `ACTION_QUERY`; the `xfrmdev_ops` control plane has no query
command, so neither has a successor to move to. `query_sa()` and the two QUERY
command codes went out of `_ipsec_helpers.py` with them.

**Re-pointed, because FCI was only how they knocked.** `_key_zeroing` (H2,
`cdx_ipsec_sec_sa_context_free`), `_dma_balance` (H3, the shared-descriptor
DMA-map unwind), `_failslab` (M7-class, `cdx_ipsec_sec_sa_context_alloc`) and
`_natt_spi_bounds` (H5, the `spi_param[16]` overrun) are regression nets for
named memory-safety defects in `cdx/cdx_dpa_ipsec.c` — every one of those
functions is code the port keeps and calls harder. What they lost was the
door, not the subject, so each installs its SAs as `XFRM_MSG_NEWSA` now and
asserts the same thing. Three consequences worth recording, because each is a
simplification rather than a translation:

- **One message replaces five commands.** FCI spelled an install as CREATE,
  SET_KEYS, SET_NATT or SET_TUNNEL and SET_STATE, and the two failslab sweeps
  each armed a different step. There is one call to arm now, so what separates
  those two files is no longer *which command* but *where in the install* the
  fault lands. The install's faultable-allocation count is measured — arm
  fail-nth beyond any plausible depth and the residue says how many eligible
  allocations the send made — and `_failslab` sweeps the head, where the SA
  cache and the key buffers are, while `_dma_balance` sweeps the tail, where
  the descriptor maps and the classifier entry are. Guessing is gone.
- **`_natt_spi_bounds` no longer needs the test hook.** Its bound sits inside
  `if (natt_sa && natt_sa->ct)`, reachable only when a prior same-flow SA
  still holds a populated ct — which an FCI-installed SA could not, because
  production resolved its kernel state by handle and a synthetic SA had none.
  That is what `CDX_DEBUG_IPSEC_TEST_XFRM` was for. An offloaded SA is built
  *from* a real `xfrm_state` and `cdx_ipsec_sa_add()` binds it before the
  entry is installed, so the ct survives on its own and the array accumulates
  without help. Sixteen install, the seventeenth is refused.
- **The agent's fault injection stopped being FCI's.** `_netlink_send_failslab`
  was already protocol-generic; only `/fci/send` offered it. `/netlink/send`
  takes `failslab_times` too now, which is what lets an XFRM `NEWSA` drive the
  SA allocator's unwind with an armed window covering exactly one send. Letting
  `ip` send the message instead would spend the counter on its own startup long
  before the allocator ran.

**The one that transfers in shape, with a caveat worth knowing before step 4.**
`test_ipsec_esp_traffic.py` installs through `ip xfrm` and lets kernel XFRM
events drive the rest, which is exactly the new shape — but its *oracle* is the
FCI SA-statistics cursor, walking `0x0A0A`/`0x0A0B` for the SPI's packet and
byte counts. So the install half transfers and the verification half does not.
The replacement is the standard tool: the adapter's accounting pass publishes
SEC's counters into `x->curlft`, where `ip -s xfrm state` already reads them,
so that becomes the oracle and the test stops needing a private cursor at all.

**And the decision logic is compiled off the hardware.**
`tools/host_tests/ipsec_adapter.c` builds `ft_ipsec_resolve()`,
`ft_ipsec_spec()`, `ft_ipsec_peer_mac()`, `ft_ipsec_paired_inbound()`,
`ft_ipsec_offloaded()`, the `xfrmdev_ops` callbacks and the SA next-hop watch
from the adapter itself, against stubs for xfrm, the FIB and the backend. The
flowtable harness stubs these instead, which was the right call for what it
tests and the wrong one to leave as the only arrangement: the boundary is
worth stubbing, the *decisions* are not, and multicast had already shown the
better shape with its own harness.

Two of the cases exist because a rig run cannot show them cheaply. The
reference discipline in `ft_ipsec_resolve()` — a matching policy takes over
the caller's reference to a borrowed destination, and the harness models that
transfer, so an assertion says the borrowed destination came back exactly as
it was found rather than freed under the flowtable. And the ordering the
next-hop watch rests on: a state deleted while a re-resolution is outstanding
must find no watch for its cookie, which the harness proves by draining the
retirement queue between the two.

New coverage follows the house rule: the failing test comes first and is proved
to fail without the fix. The first one is the step 4 proof, because step 4 is
the first step that makes an observable promise.

## The consumer contract

`hw_offload` is the whole configuration surface. What that costs, checked
against the strongSwan actually in the OpenWrt tree for this target.

**The port must advertise `esp-hw-offload`.** strongSwan does not attempt
offload on a device whose ethtool features do not carry that bit: it resolves
the bit's position once at startup by enumerating feature strings on
`charon.plugins.kernel-netlink.hw_offload_feature_interface` (default `lo`,
which is fine — the string table is global), then tests the bit per interface
in `netlink_detect_offload()` before adding `XFRMA_OFFLOAD_DEV`. So the DPAA
netdev must set `NETIF_F_HW_ESP` in its features, and a port that does not is
invisible to the daemon rather than failing loudly. This is a driver
requirement, not a packaging one, and it belongs in step 3 below.

**OpenWrt's UCI wrapper rejects the value we need.** `swanctl.init` validates
`hw_offload` against `yes|no|auto|""` and calls `fatal` on anything else
(`feeds/packages/net/strongswan/files/swanctl.init:327`), so a UCI-configured
tunnel cannot say `packet` even though the library accepts it. Two ways
through, and the first is free: `auto` **already sets `XFRM_OFFLOAD_PACKET`**
and simply does not fail the SA when offload is unavailable
(`kernel_netlink_ipsec.c:1666`), so an unmodified OpenWrt gets packet offload
from `option hw_offload 'auto'` today. Adding `crypto|packet` to that
allowlist is a one-line package patch worth carrying anyway, because `auto`
silently degrades to software and an operator asking for hardware IPsec
usually wants to be told when they did not get it.

A swanctl file written by hand bypasses the wrapper entirely and takes
`hw_offload = packet` directly. That is the right form for the rig.

## Open questions

The one that carried real design risk — whether the offline port's table can
hold a flowtable-owned entry at all, or whether its descriptor assumes a
CMM-owned connection — is answered. It can: the entry is built by the same
encoder, relocated by the same `cdx_ipsec_fill_sec_info()` branch the legacy
owner uses, and it matches. Nothing in that descriptor knows who owns the
connection. See step 6 above for the measurement.

What is left is smaller and none of it blocks retirement:

- **A rekey names the newest inbound SA.** `xfrm_state_lookup_byaddr()` answers
  with the most recently installed state for a pair, which is the one a fresh
  flow should name; the older one keeps its own classifier entry until it is
  deleted, and that deletion retires whatever depends on it. Nothing here has
  been exercised against a live rekey under load.
- **A direction can hold both an inbound and an outbound SA**, and the rule has
  a slot for each, but nothing proves the opcode order for a flow decrypted
  from one tunnel and re-encrypted into another. Admission allows at most one
  per end, so such a flow is carried in software today.
- **`nft_flow_offload_skip()` declines every packet with a `sec_path`**, which
  is why only the encrypted direction can create a tunnelled flow. That is
  upstream behaviour and costs nothing here — one direction is enough to
  describe both — but it does mean a tunnel whose *only* traffic is inbound
  never offloads at all.

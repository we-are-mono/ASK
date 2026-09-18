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
state is programmed with the ESN flag and `xdo_dev_state_advance_esn` is where
the sequence-number window is kept, not in an ASK-private notifier.

**The device.** The state's `xso.dev` must be a registered physical CDX port.
A state bound to any other device is refused rather than accepted and ignored,
because packet offload has no silent software fallback and an accepted-but-dead
SA would black-hole the tunnel. This is an *identity* test and deliberately not
the liveness one a flow's ports face: an SA may legitimately be installed
before the link it will ride has carrier, and refusing then would fail the
tunnel outright instead of delaying it.

**The local endpoint must be an address on that port.** Not a contract this
work chose — it is how CDX resolves an SA to an interface at all.
`cdx_ipsec_add_classification_table_entry()` looks the SA up by address:
`sa->id.saddr` for an outbound SA, `sa->id.daddr` for an inbound one. A
tunnel whose local endpoint lives somewhere else is refused with
`dpa_get_iface_info_by_ipaddress returned error` in the log. Real deployments
satisfy this without trying, because strongSwan's local endpoint is the WAN
address; a bench that invents endpoints has to put one on the port.

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
purely because nothing had spoken to the peer yet. What has no equivalent yet is the *later* case: CMM
handled a route change under an SA with `CMD_IPSEC_SA_SET_TNL_ROUTE`, and
nothing here re-resolves one. That belongs with the dependency watches in the
increments below rather than with the SA install.

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

`xdo_dev_state_add` / `_delete` / `_free` / `_offload_ok` /
`_state_advance_esn` / `_state_update_stats`, registered by the adapter on the
bound physical ports rather than by the SDK driver, so CDX keeps no flowtable
dependency. `xdo_dev_state_add` maps the `xfrm_state` straight onto the
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
| Lifetimes | `x->lft.hard_*`/`soft_*`, `x->curlft.*` |
| ESN | `x->props.flags & XFRM_STATE_ESN` |
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

### 4. The slow path

Replace `x->offloaded` with `x->xso.type == XFRM_DEV_OFFLOAD_PACKET` at the
datapath sites, publish the backend's handle as `x->handle` so the SEC
completion path can still resolve a decrypted frame, and give packet-offload
tunnel output the sec_path and the finished Ethernet header SEC expects.

Three things in that hunk are not obvious, and each one was a failure first:

**It must not take `xfrm_dev_direct_output()`.** That path pushes
`hard_header_len` of uninitialised space and transmits without resolving a
neighbour, because it is written for hardware that writes the L2 header
itself. SEC is handed the frame complete with its Ethernet header, so every
packet takes the ordinary neighbour output instead — which is the reason the
comment beside it already gives for locally generated packets, and is simply
true of all of them here.

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
not capability.

**Not yet settled.** A first attempt ran on a non-KASAN image with the tunnel
between the DUT's LAN port and the LAN VM and iperf3 forwarded through it, and
it produced numbers that cannot be trusted: the rig's LAN segment began
flapping partway through (`ixgbe ... NIC Link is Up 10 Gbps` followed by
`Link is Down` twenty-eight milliseconds later, repeatedly) and eventually
stayed down. The DUT's own port kept reporting link, so the break is between
the switch and the LAN VM's NIC and needs a cable rather than a command.

What that attempt did establish, and what it did not:

- CMM carries this bench at 2.54 Gb/s forward and 2.70 Gb/s reverse, at
  1.3 to 2.1 per cent DUT CPU, with both directions offloaded — its connection
  table shows `IPSEC(Init:sa_nr=1 ...) (Reply:sa_nr=1 ...)`. So the comparison
  is like for like: both owners put the tunnel in hardware.
- The flowtable's decrypting direction matched it, at 2.63 to 2.66 Gb/s and
  1.1 to 2.4 per cent CPU.
- The flowtable's *encrypting* direction read 0.13 to 0.17 Gb/s at 26 to 39
  per cent CPU over TCP. That number is **not** reported as a regression,
  because a UDP transfer in the same direction on the same bench reached its
  full 400 Mb/s offered rate with 83 per cent of frames carried in hardware,
  which a broken encrypting path could not do. A TCP collapse with 116
  retransmits, alongside a link flapping on a sub-second cadence, is what a
  lossy segment looks like.

The measurement is therefore unfinished, not failed. Redo it once the segment
is repaired, and gate each run on link stability at both ends rather than
assuming it: the failure mode here was silent on the DUT, which reported
`Link detected: yes` throughout.

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

**Kept, because FCI is only how they knock.** `_key_zeroing` (H2,
`cdx_ipsec_sec_sa_context_free`), `_dma_balance` (H3, the shared-descriptor
DMA-map unwind), `_failslab` (M7-class, `cdx_ipsec_sec_sa_context_alloc`) and
`_natt_spi_bounds` (H5, the `spi_param[16]` overrun) are regression nets for
named memory-safety defects in `cdx/cdx_dpa_ipsec.c` — every one of those
functions is code the port keeps and calls harder. What they lose at step 3 is
the door, not the subject: `xdo_dev_state_add()` reaches the same allocator,
the same descriptor builder and the same classification-entry path, so each is
re-pointed rather than rewritten. `_natt_spi_bounds` needs one extra look,
because its reachability hook resolves an SA through
`xfrm_state_lookup_byhandle()`, which this design deletes.

**The one that transfers in shape, with a caveat worth knowing before step 4.**
`test_ipsec_esp_traffic.py` installs through `ip xfrm` and lets kernel XFRM
events drive the rest, which is exactly the new shape — but its *oracle* is the
FCI SA-statistics cursor, walking `0x0A0A`/`0x0A0B` for the SPI's packet and
byte counts. So the install half transfers and the verification half does not.
The replacement is upstream and better: `xdo_dev_state_update_stats()` puts
hardware counters where `ip -s xfrm state` already reads them, so the standard
tool becomes the oracle and the test stops needing a private cursor at all.

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
- **An SA's own next hop is resolved once, at install, and never re-resolved.**
  What leaves SEC is a finished frame, so the peer's Ethernet address is baked
  into the SA's hardware entry; a peer that moves — a gateway failover, a
  replaced NIC — leaves the tunnel emitting to an address nobody answers to,
  silently. The legacy owner had `CMD_IPSEC_SA_SET_TNL_ROUTE` for this and
  nothing here replaces it. Fixing it is not a watch on its own: the address
  reaches the hardware through the shared descriptor, so a change means
  rebuilding the SA's entry, which is the control plane's to drive. Scoped
  out of this increment deliberately, and the largest of the four.
- **`nft_flow_offload_skip()` declines every packet with a `sec_path`**, which
  is why only the encrypted direction can create a tunnelled flow. That is
  upstream behaviour and costs nothing here — one direction is enough to
  describe both — but it does mean a tunnel whose *only* traffic is inbound
  never offloads at all.

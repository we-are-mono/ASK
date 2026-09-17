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

- `cdx/cdx_cmdhandler.c:165` skips `CMD_INIT(ipsec)`. It is the only subsystem
  gated on ownership; `CMD_INIT(qm)`, `CMD_INIT(mc4)` and `CMD_INIT(mc6)` all
  run unconditionally. So the SA caches are not initialised, the CAAM job ring
  is not claimed and the datapath hook is not registered.
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
`real_dev`, `dir` and `type`. That removes the need for `xfrm_state.handle`,
`xfrm_state.byh`, `netns_xfrm.state_byh` and the whole handle-lookup hash 040
adds to `xfrm_state.c` — Linux already stores a driver cookie per state and
already indexes states for us.

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

**`type_offload` must exist for ESP.** `xfrm_dev_state_add()` refuses a state
whose `x->type_offload` is NULL before it ever reaches the driver, and that
type is registered by the ESP offload module. The test image's defconfig has
`CONFIG_INET_ESP_OFFLOAD=m` but `CONFIG_INET6_ESP_OFFLOAD=y`
(`meta-ask/recipes-kernel/linux/files/defconfig:99`, `:105`). The asymmetry is
not deliberate and IPv4 is the one that matters first, so the v4 symbol moves
to `=y` with this work rather than leaving a hardware feature dependent on
`esp4_offload` having been modprobed. The failure it would otherwise produce
is a clean `-EINVAL` from the netlink add, not a silent fallback, which is
easy to misread as the driver refusing the SA.

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

**The device.** The state's `xso.dev` must be a registered physical CDX port,
running, with carrier, and outside bridge and L3-slave configurations — the
same port predicate `cdx_ft_hw_add()` already applies to its ingress and
egress devices. A state bound to any other device is refused with `-EINVAL`
rather than accepted and ignored, because packet offload has no silent
software fallback and an accepted-but-dead SA would black-hole the tunnel.

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

Run `CMD_INIT(ipsec)` in both ownership modes and move the FCI dispatch
registration behind the ownership check instead of the whole init. After this
the SA caches exist, the CAAM job ring is claimed, the SEC era is detected and
`cdx_get_to_sec_fq_handler` is registered in a flowtable boot.

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
stats read-back and an opaque handle. No CDX control structures, no firmware
objects, no `xfrm` types — the adapter converts.

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
strongSwan never offers the state — see the consumer contract above.

Proof: `ip xfrm state add … offload packet dev ethN` succeeds, the SA appears
in CDX's cache, `ethtool -k ethN` reports `esp-hw-offload: on`, and deleting
the state releases the SEC context.

### 4. The slow path

Replace `x->offloaded` with `x->xso.type == XFRM_DEV_OFFLOAD_PACKET` and
`x->handle` with `x->xso.offload_handle` at the three datapath sites, and add
the sec_path hunk that packet-offload tunnel-mode output needs. Delete the
`skb->ipsec_offload` flag and its guards.

Proof: a tunnel carries traffic with no flowtable entry at all, at software
forwarding rates, with `tx_caam_enc` counting and the ESP visible on the wire.
This is the first end-to-end proof that the SA reached SEC, and it does not
depend on any classifier work.

### 5. The outbound fast path

`struct cdx_ft_rule` gains the SA handles; `cdx_ft_hw_add()` sets
`CONNTRACK_SEC` and `hSAEntry[]`; the adapter resolves `dst_xfrm()` on the
egress destination it already borrows, applies the eligibility contract and
publishes an SA watch.

Proof: line-rate LAN-to-WAN through the tunnel, the adapter's entry naming the
SA, and `devlink trap policer 2` counting without `cdx_devlink.c` being
touched — which is the check the QoS increment left behind on purpose.

### 6. The inbound fast path

The offline-port half. Scope after step 5 measures, because the reverse
direction is where reading has been least reliable in this subsystem and the
PPPoE increment's lesson was to measure before believing a parser.

### 7. Parity

A paired-boot measurement against CMM, same image, same tunnel, same traffic,
same CPU accounting, per the roadmap's parity table. Retirement needs parity,
not capability.

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

- Whether the inbound offline-port table can hold a flowtable-owned entry at
  all, or whether the OH port's descriptor assumes a CMM-owned connection.
  This is the one remaining unknown with real design risk, and it is settled
  by measuring at step 5 rather than by reading.

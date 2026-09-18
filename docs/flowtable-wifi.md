# Wi-Fi without CMM

Roadmap item 11. What the hardware already does, what the radio on this board
actually is, and why the port is asymmetric enough that one direction is worth
building and the other has to be measured before it is.

This document is written before any code, because the roadmap asks items 5 to
8 — and this one — to settle a feature-specific hardware eligibility contract
first, and because the shape of the answer here turns on facts about the
driver that were not in the roadmap's estimate.

## Three corrections to the estimate this work started from

The roadmap records item 11 as *"needs driver-side `dev_fill_forward_path`
support that does not exist"*, 345 lines, 3 FCI commands, effort High. Each
half of that is either wrong or misleading, and the corrections change what
the increment is.

**The radio is not a mac80211 device, so `fill_forward_path` was never the
mechanism.** The board carries an NXP 88W9098 (u-blox JODY-W3) on PCIe,
driven by NXP's out-of-tree `moal`/`mlan` driver — `kmod-nxp-mwifiex` and
`nxp-wifi-firmware-9098-pcie` in the shipping OpenWrt profile, with every
ath10k board package disabled. That driver is **full-MAC**: the firmware owns
802.11 and the driver presents a cfg80211 interface, not a mac80211 one.
`net/mac80211/iface.c` does implement `ndo_fill_forward_path`, but it
delegates to `local->ops->net_fill_forward_path`, and the only implementers in
this kernel are `mt7915` and `mt7996` — MediaTek wrote that interface for
their WED silicon. There is no path from here to it, and adding one would
mean implementing a forwarding-path concept the firmware does not expose.

**The driver side is needed for one direction, not both.** Reading the
datapath rather than the line count:

- *Wire to Wi-Fi.* The classifier enqueues the finished frame to a per-VAP
  frame queue. `vap_rx_fwd_pkt()` dequeues it, builds an skb and calls
  `dev_queue_xmit()` on the VAP's netdev. **The Wi-Fi driver is unmodified
  and unaware** — it receives an ordinary transmit, exactly as it would from
  the bridge.
- *Wi-Fi to wire.* Two mechanisms exist. `cdx_wifi_rx_fastpath()` is exported
  for a driver to call directly, and *nothing in any tree calls it*; VWD also
  registers a `NF_INET_PRE_ROUTING` hook at `NF_IP_PRI_FIRST` which needs
  nothing from the driver at all.

NXP's own configuration says which is which. `wifi_fastforward_conf_file` in
the reference tree carries a per-interface `direct_path_rx` flag and the
comment *"this option/optimization is implemented for atheros/QCA driver. For
other devices/drivers this option should be disabled."* Every non-QCA entry
sets it to 0. So the exported call was always the vendor-specific fast path,
and the general case was the netfilter hook.

**It is a capability to add, not behaviour to preserve.** `cdx_wifi_rx_fastpath`
has no caller, `dpaa_vwd_init()` is skipped outright in a flowtable boot, and
a production gateway's CMM has no `wifi` verb in its `set`/`show`/`query` CLI.
Three independent observations, all consistent: this offload has not been
running. The Wi-Fi *feature* is in daily use; the Wi-Fi *offload* is not what
has been carrying it. That sets the bar — there is no parity to restore, so
the increment is judged on what it adds.

## What the hardware already provides

Better shape than the control plane, and the same discovery IPsec had: the
encoder already knows about this.

`dpa_get_out_tx_info_by_itf_id()` has a WLAN arm alongside its ethernet one.
For an interface flagged `IF_TYPE_WLAN` it resolves the VAP's forwarding frame
queue and marks the descriptor:

```c
dpaa_get_vap_fwd_fq(iface_info->wlan_info.vap_id, &l2_info->fqid, 0);
l2_info->is_wlan_iface = 1;
```

So a classifier entry whose egress is a VAP is not a new kind of entry. It is
the same entry every routed flow builds, with its enqueue target pointed at a
VAP frame queue instead of a MAC port's. Everything downstream of that field
is code the encoder already runs.

VWD's own side is an **offline port** (`priv->oh_port_handle`) plus a frame
queue per VAP, and a netdev notifier that tears a VAP down when its device
unregisters. The OH port is the FMAN-side interface for the whole subsystem:
it is what a Wi-Fi-received frame is injected into for classification, and it
is why this is testable without a radio at all — a VAP binds to a netdev by
`net_dev->wifi_offload_dev`, and nothing on that path requires the netdev to
be wireless.

**The board provides that port, and provides it for this.** The DK ships two
offline ports and no more, one per subsystem that needs one:

```
dpa-fman0-oh@2   fman0_oh_0x3 (port@83000)   FQs 0x60/0x61   — IPsec
dpa-fman0-oh@3   fman0_oh_0x4 (port@84000)   FQs 0x62/0x63   — Wi-Fi
```

The device tree says so itself, on the second one's extended-args: *"Wi-Fi
frames need room for the offline-port pipeline and internal context as well as
the frame itself."* So the OH port this increment needs is not something to
find or free — it is already declared, sized for this traffic, and sitting
unused in a flowtable boot because `dpaa_vwd_init()` never runs to claim it.
FMAN declares six offline ports (0x2 to 0x7); the board exposes two, which is
a DTS decision rather than a silicon limit, and both are spoken for.

## What is gated today

`cdx/cdx_main.c:381`:

```c
rc = cdx_flowtable_enabled() ? 0 : dpaa_vwd_init();
```

In a flowtable boot the VAP frame queues, the buffer pools, the offline port
and the netdev notifier are never built. This is the same ownership gate IPsec
had at `cdx_main.c:395`, and it has the same consequence: the absence surfaces
several layers from the cause, as a frame queue that cannot be resolved rather
than as anything naming Wi-Fi.

Separately, admission refuses a VAP as an egress: `cdx_ft_port_supported()`
requires `dpa_netdev_is_physical()`, which a VAP netdev is not. So a flow to a
Wi-Fi client is declined before any of the above is reached.

## The decision: egress first, ingress measured

The two directions are not equally worth building, and stating that plainly is
what keeps this increment from being twice the size it needs to be.

**Wire to Wi-Fi is worth hardware.** The frame arrives on an FMAN port. The
classifier can do the whole route, NAT and header rewrite and drop it into the
VAP's frame queue, and the CPU's only remaining job is the queue-to-driver
handoff. That removes software forwarding from the path entirely, needs no
driver change, and uses an encoder arm that already exists.

**Wi-Fi to wire is not obviously worth it, and must be measured before it is
built.** The frame arrives from PCIe, already in DRAM, already an skb, already
past the driver's cost. Injecting it into FMAN means building a frame
descriptor and taking an offline-port round trip, against a software path
that — and this is the part the roadmap's estimate missed — **is already
accelerated**. The driver delivers through `netif_receive_skb()`, so the
flowtable's own ingress hook already sees these frames and already forwards
them without conntrack or a routing lookup. Wi-Fi flows should already show
`[OFFLOAD]` in conntrack today, on an unmodified system, with nothing ported.

So the question for the ingress half is not "how do we offload it" but "what
does offloading it buy over what Linux already does", and that is a
measurement, not a design. It is step 4 below, and it is allowed to conclude
that the answer is nothing.

## The control plane

A VAP reaches CDX today as `FPP_CMD_WIFI_VAP_ENTRY` (add, update, remove) sent
by CMM, which learns its interface list from a static UCI file naming
interfaces by name. That is three FCI commands, a userspace daemon and a
configuration file to describe something the kernel already knows.

The replacement is the move multicast and IPsec both made: **a netdev
notifier**. A VAP registering *is* the event. Its name, index and hardware
address come off the netdev; `NETDEV_UNREGISTER` is the teardown, and VWD
already has exactly that notifier for its own bookkeeping. No ASK userspace,
no configuration file, and `module_wifi.c` and `control_wifi.c` retire
together.

Two things this decides on the way past:

**Which netdevs count.** Not every netdev is a VAP. The identity test is a
running cfg80211 device in AP mode — `dev->ieee80211_ptr` with an `iftype` of
`NL80211_IFTYPE_AP` or `AP_VLAN` — which is a property of the device rather
than of a name in a file, and which a station-mode or monitor interface fails
without needing to be excluded by hand.

Running is part of it, and the first rig run is what established that. Two
things force it. `vwd_vap_up()` refuses a device that is not `IFF_UP`, so
offering one can only produce a failed registration — and the driver here
registers both AP interfaces at load and brings them up later, so without the
gate every boot spent two refusals before hostapd had done anything. And
`cfg80211_change_iface()` changes an interface's type without raising any
netdev event at all: no notifier, not even `netdev_state_change()`. So there is
no event on which to re-read the iftype directly. A type change goes through a
down and an up, both of which do raise events, so gating on running is what
turns "stopped being an AP" into something this can observe at all.

One driver-specific caveat, recorded because it will mislead the next person
who tries to test this by hand: `moal` declines to change the type of a `uap`
interface, logging `Skip change virtual intf type on uap: from 3 to 2` and
returning success. An `iw dev uap0 set type managed` against this board
therefore does nothing, and a VAP that stays registered afterwards is correct
rather than stale.

**Where the VAP's address comes from.** `wlan_iface_info.mac_addr` is filled
from the FCI command today. Under a notifier it comes from the netdev, and the
cached copy goes the way the ethernet one went in `f34908a` — for the same
reason, and now for the same arm of the same encoder.

## The eligibility contract

What the hardware may be asked to carry. Everything outside this goes to
Linux, in software, exactly as it does today.

**The device.** A cfg80211 netdev in AP or AP_VLAN mode whose VAP has been
registered with VWD and is `VAP_ST_OPEN`. A VAP mid-configuration is refused
rather than queued: the frame queues are built during the transition and an
entry naming one before it exists enqueues into nothing.

**The direction.** Egress only, for this increment. A flow whose *ingress* is
a VAP is admissible only if its egress is also offloadable by the ordinary
contract, and it is carried by the software fast path in the meantime.

**The flow.** Routed unicast TCP or UDP, assured established conntrack for
TCP, supported NAT and encapsulation — the existing contract, unchanged. A
VAP is an egress device like any other once its frame queue is known.

**Multicast and broadcast are refused.** `vwd_wifi_if_send_pkt()` already
declines a multicast destination, and the bridged multicast learner delivers
to a VAP through the bridge rather than through this path. The two must not
both claim the same frame.

**What has no equivalent and is not attempted.** A per-station hardware queue.
The classifier knows a VAP, not a client: the frame is enqueued to the VAP's
queue and the driver's own scheduler decides which station it goes to and
when. That is a real limit on what this can do — it offloads the forwarding
decision, not the 802.11 scheduling — and it is why the ingress measurement
matters, because the same limit applies there.

## Implementation plan

Ordered so each step is provable on the rig before the next depends on it.

### 1. A radio on the test image

The Yocto image had no Wi-Fi packaging at all, so none of this was testable
where the rest of the suite runs. Added, pinned to the exact commits the
shipping OpenWrt profile uses so the test image and the product run the same
driver and firmware:

- `nxp-mwifiex` — `moal`/`mlan` at `09f41e14`, PCIe-9098 only, cfg80211
  full-MAC.
- `nxp-wifi-firmware` — imx-firmware at `8c9b2780`, the five
  `FwImage_9098_PCIE` files.
- `hostapd`, `wpa-supplicant`, `iw` and `kernel-module-cfg80211` alongside.

The kernel needed nothing: `CONFIG_PCI`, `CONFIG_PCIEPORTBUS`,
`CONFIG_PCI_LAYERSCAPE`, `CONFIG_FW_LOADER` and `CFG80211=m` are all already
set, and the card enumerates on the rig DUT as `1b4b:2b43`/`2b44`.

One driver patch was needed and it is worth recording, because it is a class
of problem this pairing will keep producing. `.set_monitor_channel` gained a
`struct net_device *` in `4dae80dd259b`, authored 2024-10-09 and released in
**6.12** — but the driver only adds that argument from 6.13. Builds that use
the backports package never see it, because `CFG80211_VERSION_CODE` there
reports the backport's base version rather than the running kernel's. A native
6.12 cfg80211 does see it, and fails to compile. The driver is written against
a moving API and this build is the first to hold it against a stock kernel.

Proof: the image boots, `mlan` and `moal` load, and `iw dev` lists the VAP.

### 2. Ungate the hardware

Run `dpaa_vwd_init()` in both ownership modes, moving whatever belongs to one
owner inside it, exactly as `ipsec_init()` was handled. After this the offline
port, the buffer pools and the per-VAP frame queue machinery exist in a
flowtable boot.

This is a claim on `dpa-fman0-oh@3`, which the board declared for exactly this
and which nothing else takes. It is the cheaper half of what the IPsec
equivalent did — that one also had a CAAM job ring and an era detection behind
it — so a failure here has fewer places to hide.

Proof: a flowtable boot logs VWD's offline-port claim and its buffer pool, and
`/sys/class/vwd/vwd0/` is present with zero counts — unchanged behaviour,
since nothing steers to a VAP yet. The IPsec increment's own proof is the
control: `dpa-fman0-oh@2` must still come up, because the two are independent
claims on independent ports and a mistake that conflated them would show as
one of them failing to initialise.

### 3. VAP registration from a netdev notifier

Recognise an AP-mode cfg80211 netdev, register it with VWD, and publish the
binding the adapter needs: netdev to VAP id to forwarding frame queue. Retire
it on `NETDEV_UNREGISTER` and on a transition out of AP mode.

Proof: bringing up hostapd creates the VAP with no configuration file and no
FCI command; `ip link del` retires it; the counters show the registration.

### 4. Measure before building the ingress half

With a VAP registered and traffic flowing in software, record CPU and
throughput in both directions. This decides whether step 6 exists at all.

The oracle to be careful about is the one the QoS increment taught: a
functional test cannot tell hardware from software here, because both deliver
every packet. Only a rate and a CPU measurement separate them.

Measured 2026-09-18, with an iPhone on the 5 GHz AP.

The result that matters is not a rate. It is that **the hardware path to a
Wi-Fi client is already live and already refused**. `flags offload` will not
bind `uap0` -- a `moal` netdev supports no offload -- but the devices list
only names which ingresses are hooked, and wire-to-Wi-Fi ingresses on `eth4`:

```
flowtable fast { hook ingress priority 0; devices = { "eth4" }; flags offload; }
-> bindings 1
```

With that bound and a rule adding `ip daddr 192.168.2.0/24` to the flowtable, a
client's ordinary background traffic drove CDX's `rejects` from 40 to 100 in
thirty seconds while `installs` stayed at zero. Every Wi-Fi-destined flow
already reaches admission and dies on the `dpa_netdev_is_physical()` test named
above. That is step 5's blocker demonstrated rather than reasoned, and it gives
that step a far better proof than a transfer rate: those rejects become
installs.

Linux's own flowtable does accelerate Wi-Fi client flows once one exists --
ordinary browsing showed 24 of 88 conntracks `[OFFLOAD]` -- so the prediction
above is right about the mechanism and wrong about the default: the image ships
an empty nftables ruleset, and nothing accelerates until something installs a
flowtable.

**No throughput figure is recorded here, because none was taken with the
offload active.** Every rate measured during this step ran with `bindings 0`,
which is to say against a system where the classifier had no part -- software
forwarding compared with nothing. A number from that configuration describes a
misconfiguration, not the board. The comparison worth having is the same flows
installed and not, which step 5 makes possible for the first time.

One cost to weigh when it does: hardware egress removes the route lookup, NAT,
conntrack and header rewrite, but `process_vap_rx_fwd_pkt()` still builds an
skb, calls `dev_queue_xmit()` and takes the global `vaplock` **per packet** --
the shape of the lock `e67f0ba` removed from the classifier hooks. What it
keeps may dominate what it removes.

Step 6 remains the harder case: its direction genuinely needs the VAP's own
ingress hooked, which cannot be bound, so it is the offline-port injection or
nothing.

A measurement trap, filed as A159: a bound flowtable stops the port's own
**ingress** byte counters, because the ingress hook takes the packet before
the SDK driver accounts it. Ingress read 151 KB for a transfer egress and the
server both put at ~105 MB. Step 5's proof is written against a packet counter
on an offloaded path and has to pick one that still counts.

### 5. The egress fast path

`cdx_ft_rule` gains the VAP binding; admission accepts a VAP egress; the
encoder's existing WLAN arm does the rest. The flow's entry enqueues to the
VAP's frame queue instead of a MAC port's.

Proof: a WAN-to-Wi-Fi transfer offloaded, with the entry's own packet counter
tracking the transfer and the software forwarding path idle.

### 6. The ingress half -- not built, and the measurement says why

Step 4 was allowed to conclude that the ingress half buys nothing. It does.

**The egress offload is worth 1.6x, and that is its whole worth.** Measured
with a client on the 5 GHz AP, the same transfer with the flowtable bound and
flushed, both runs saturating one core:

```
offload off   ~92 Mbit/s    one core at 100%
offload on   ~145 Mbit/s    one core at 100%
```

So at a fixed core budget the per-packet cost falls to about 63% of what it
was: the route lookup, conntrack, NAT and header rewrite are about **37% of a
wire-to-Wi-Fi packet**, and hardware removes all of it. The other 63% is the
skb build, `dev_queue_xmit()`, `moal` and the PCIe transfer, and no amount of
classifier work touches it.

**It cannot be a bypass, because FMAN cannot reach the radio.** The 88W9098 is
a PCIe device; FMAN can only enqueue to its own MAC and offline ports. A VAP
frame queue is therefore a handoff point and not an egress: `vap_rx_fwd_pkt()`
is a qman dequeue callback, on the CPU, by construction. MediaTek's WED exists
precisely to close that gap, which is why `mt7915`/`mt7996` are the only
drivers implementing `net_fill_forward_path`; there is no equivalent here.

One consequence worth knowing: a flow is hashed to one of the VAP's 64
forwarding queues, so a single TCP connection is served by a single core and
tops out around 145 Mbit/s. Parallel connections spread and go faster. The
board's Wi-Fi ceiling is therefore per-flow, not aggregate.

**Against that, the ingress half is not worth building.** The uplink is not
CPU-bound at all -- during upload no core exceeds 70% while the download pegs
one -- so there is no bottleneck to relieve. And the trade is worse in that
direction: the frame is *already* an skb in the CPU when it arrives from PCIe,
so injection adds a descriptor build and an offline-port round trip to buy
back the same 37%.

NXP reached the same place, and their Programmer's Guide (BHR ASK for
LS1012x/LS104x/LS102x, Rev. E, 10.24) says so outright. Section 10.24.2.3
requires that "the WLAN driver needs to be modified to call
`comcerto_wifi_rx_fastpath()` instead of `netif_rx()`/`netif_receive_skb()`",
and records the path as enabled by default only for `ath0/ath1/ath2`. That is
our `cdx_wifi_rx_fastpath()`, which has no caller in any tree because `moal`
was never modified; their own `wifi_fastforward_conf_file` sets
`direct_rx_path = 0` for every non-QCA driver. The stated purpose is reducing
an NCNB cache penalty, which is a PPFE memory-architecture cost that DPAA does
not have -- so on this board even the motivation does not transfer.

The same section prices the egress side. Sending to the VAP through
`dev_queue_xmit()` is documented as the default, and the two optimisations of
it are worth "approximately 6% CPU saving" (10.24.2.1, skipping QDisc via
`ndo_start_xmit`) and "approximately 9%" (10.24.2.2, the custom NCNB skb) --
and the second is "implemented only for QCA driver/device and it does not work
with other devices or drivers". So the delivery cost measured above as ~63% of
the packet is, by the vendor's own accounting, shavable by single digits and
only on hardware this board does not have.

Section 10.24.2.4 documents the single-core ceiling as a known limitation:
"all HIF-Rx traffic is processed by the same processor context ... a single CPU
might not be enough to process this amount of data", with per-VAP
`rx_cpu_affinity` as the remedy. The equivalent here is that a VAP owns 64
forwarding frame queues and flows hash across them, so parallel connections
already spread while a single connection cannot.

One thing the guide corrects about this document's earlier reading: VWD's
`NF_INET_PRE_ROUTING` hook is not vestigial CMM machinery. 10.24.6.3 calls it
the default -- "By default VWD is enabled with only routing feature" -- with
`vwd_bridge_hook_enable` as its bridged counterpart. It is the sanctioned
mechanism for the legacy owner; what makes it wrong in flowtable mode is only
that nothing populates the uplink direction for it to match. Their round trip is
the VWD `NF_INET_PRE_ROUTING` hook, which this branch now disables in
flowtable mode: with no uplink entries for it to match, it was injecting every
packet into the offline port and taking every one straight back
(`pkts_tx_route` and `pkts_slow_forwarded` both 237240), for a global vaplock
and two DMAs each.

The mechanism therefore stays in the tree, off, and reachable if a future
board changes the arithmetic.

## Tests

The suite has no Wi-Fi coverage at all today, which is consistent with the
offload never having run.

**What can be tested without a radio**, and should be, because it is most of
the mechanism: a VAP binds to a netdev by `wifi_offload_dev` and nothing on
that path requires the netdev to be wireless. The frame-queue plumbing, the
classifier entry with `is_wlan_iface`, the registration and teardown
lifecycle, and the admission contract can all be driven against an ordinary
netdev standing in for a VAP.

**What needs the radio** is the measurement in step 4 and the end-to-end
proofs in steps 5 and 6, which need an associated station.

**The host harness gets the decision logic**, as multicast and IPsec both did:
which netdevs are VAPs, what admission accepts, and the registration
lifecycle, compiled from the adapter against stubs.

## Open questions

- ~~**What `no_l2_itf` means.**~~ Settled from the code: `dpa_wifi.c` says it
  above `vwd_is_no_l2_itf_device()` — *"will return 1 if the device is
  cellular"* — so it describes an interface with no L2 header at all. Zero for
  `moal`, and zero by construction rather than by choice: admission only
  accepts `ARPHRD_ETHER` devices with a six-byte address, so the case the flag
  describes is refused before it can reach the flag.
- **Whether the ingress half is worth building at all.** Step 4 decides it.
  The honest possibility is that Linux's own fast path is already close
  enough that the offline-port round trip buys nothing, in which case this
  increment ends at step 5 and says so.
- **Per-station scheduling stays the driver's.** Nothing here changes how the
  firmware schedules airtime, so the ceiling for any of this is what the radio
  and its driver can already do.

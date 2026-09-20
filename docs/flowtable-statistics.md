# Interface counters for offloaded traffic

How a port's and a VLAN device's byte and packet counters come to include the
frames the hardware forwarded on their behalf, why they read the way they do,
and what was measured to settle the units. Item 9 of the
[retirement roadmap](flowtable-cmm-porting-roadmap.md), the last of its
merge-gating rows.

## The rule that shaped it

Every counter is read through Linux's own tooling. `ip -s link`, `/proc/net/dev`
and anything else that calls `dev_get_stats()` see the offloaded traffic on the
device it belongs to, in the units that device's own counters use. There is no
FCI query, no socket and no ASK binary on the reading side; `/proc/cdx_flowtable`
keeps its raw rows as a diagnostic, and that is all it is.

CMM answered `cmm stat show vlan` and `cmm stat show interface` over FCI from
the same firmware records. Those records are what this increment reads; the
surface is the kernel's.

## Where the numbers come from

An offloaded frame never reaches the CPU, so nothing the driver counts sees it.
What does see it is the firmware: the classifier action list a flow installs
carries statistics pointers into a MURAM record area, and three of its opcodes
count into them.

- `UPDATE_ETH_RX_STATS` counts every frame the flow receives into the ingress
  **port's** record, and the enqueue at the end of the list counts every frame
  the flow transmits into the egress port's. These records have always existed:
  a physical port gets one when CDX registers it, in either ownership mode.
- `STRIP_ALL_VLAN_HDRS` and `INSERT_VLAN_HDR` take one pointer per tag. This is
  where a **VLAN device's** counters come from, and where the legacy owner
  needed a registered VLAN interface to allocate against. The flowtable owner
  registers none, so until now it emitted no pointer at all for a tag — the
  same suppression the bridge path uses for tags with no device behind them.
- `STRIP_PPPoE_HDR` and `INSERT_PPPoE_HDR` take one pointer each, into a
  timestamped record. This is where a **ppp device's** counters come from; the
  [PPPoE increment](flowtable-pppoe.md) already claimed the record, keyed on the
  session, and read it back through `/proc/cdx_flowtable` alone.

The adapter holds one record per logical device a flow's encapsulation crosses
(`struct cdx_ft_dev_stats` in `cdx/ask_flowtable.c`): a plain one for each VLAN
device in the tag stack, a timestamped one for the ppp device a session runs
on. The path walk that derives the tag stack records which device each tag
belongs to (`cdx_ft_vlan.ifindex`, zero for a tag a vlan-aware bridge adds with
no device of its own); the ppp device is the direction's logical device
whenever it carries a session, because the walk takes the session hop only from
a device of that type. The binding carries one slot per tag and one per session
to the encoder, and the opcodes take their pointers from the flow's description
rather than from an interface lookup.

Keying the session's record on the ppp device rather than on the session
itself is what the fold needs and what the reader means: a ppp device carries
one session at a time, and a session renegotiated under a device that stays is
still that device's traffic. The `/proc` row keeps the session identity the
walk resolved — id, concentrator, the device it runs over — following the last
direction admitted, so it still joins with the flow rows.

### Read-back

The kernel patch `010-ask-fman-dpaa-ehash.patch` has always hooked
`dev_get_stats()` in `net/core/dev.c` to a CDX callback,
`virt_iface_stats_callback()` in `cdx/devman.c`, which adds a registered
interface's firmware record to the `rtnl_link_stats64` the kernel is about to
return. That is how `ip -s link show eth4` under CMM included offloaded traffic
all along, and it is the one path the flowtable owner already had.

What is new is that a record can be *published* to a device by index rather
than by registration. `cdx_ft_ifstats_publish()` in `cdx/cdx_ifstats.c` puts a
slot on a list keyed by `ifindex`, with the per-packet framing to subtract;
`cdx_ft_ifstats_fold()` walks that list from the same callback and adds each
matching record. Both take `dpa_statslist_lock`, which is the allocator's own
lock and a process-context discipline, and `dev_get_stats()` is process context
under RCU or RTNL. Freeing a slot withdraws it under that lock, so a reader
finds a slot published with a live record or finds nothing.

### Lifetime

A device's record lives as long as the device, not as long as its flows. A slot
returned to the pool is zeroed when handed out again, so a record that came and
went with the flows would drop the device's counters back to zero every time it
went idle -- which is what the session-keyed record used to do. The record is
therefore claimed by the first flow that crosses the device and kept until the
device unregisters; `refs` counts the hardware directions whose opcodes name
its indices, and the record is freed by whichever comes last, the
unregistration or the last release, because the device can unregister while an
entry naming the record is still being retired and the slot has to outlive that
opcode. A record marked gone is never found by index again, so a device that
reuses the index starts a record of its own. The netdev notifier only marks,
and withdraws the record's publication at once -- a device moved to another
namespace keeps its index there and this one can hand it to a new device while
the old record waits, and the fold keys on the index alone; a work item then
takes the backend transaction and frees what nothing references.

pppd normally creates a ppp device per dial and destroys it when the session
ends, so a ppp device's record lives exactly as long as its session; with
`persist`, or a session renegotiated under a unit that stays, it lives across
them, which is what the device's own counters do too.

The plain pool is 122 records deep and the timestamped one 4, both shared with
the legacy owner. Exhaustion is an ordinary outcome: the record exists, says it
has no slot, the encoder is told there is none, and the flow forwards without
counting. The answer a device got is the answer it keeps for as long as it has
the record, so a live connection's counters never begin halfway through its
life. A tag stack is all or nothing: the opcodes' list form has no way to skip
one tag, and index zero there is another owner's record, so one tag without a
slot costs the whole stack its counters rather than counting the rest into
somebody else's.

## Units, measured

The firmware counts whole frames without the FCS. The kernel's own counters do
not, so a record is restated before it is added — per packet, saturating at
zero, because padding on a minimum-size frame is counted by the firmware and
cannot be told apart from payload afterwards. What to subtract was measured
rather than inferred, with bursts of 64 UDP datagrams of 256 bytes (284-byte IP
packets) through a tagged LAN on the DK, reading the raw records off
`/proc/cdx_flowtable` and the devices' counters at the same time.

| Frame | On the wire | Port rx record | Device rx record | Device tx record |
| --- | ---: | ---: | ---: | ---: |
| one tag, `eth3.271` | 302 | 302 | 298 | 302 |
| two tags, `eth3.271` (outer) | 306 | 306 | 302 | 306 |
| two tags, `eth3.271.272` (inner) | 306 | 306 | 298 | 302 |
| session over a tag, `ppp0` | 310 | 310 | 302 | 306 |

So the port's record counts the frame as it arrived, and a tag's record counts
the frame **as it stands once that tag has been handled**: the strip counts it
with the tag already off, the insert with the tag already on, and a two-tag
stack is counted progressively, 302 then 298 on the way in and 302 then 306 on
the way out. The session's record is not quite the same on receive: the strip
counts the frame as it arrived less the session header alone, so the tag under
the session is still in although the tag strip ran first. On transmit the
insert runs before any tag goes on and has the eight-byte session header on.

That decides four things.

- **A port's receive counter subtracts the Ethernet header.** The SDK driver
  counts `skb->len` after `eth_type_trans()` has pulled it, so the driver's
  software frames and the firmware's hardware frames only add up once the
  record is restated by 14 bytes per packet. Transmit needs nothing: the driver
  counts the whole frame it was handed and so does the firmware. This applies
  to the legacy owner too, whose port fold was raw before.
- **A VLAN device's receive counter subtracts the Ethernet header, and its
  transmit counter the tag, at every depth.** An 802.1Q device counts a
  received frame after the port pulled the header and its own tag came off,
  which is exactly the frame the firmware counted less the header. On transmit
  `vlan_dev_hard_start_xmit()` moves the device's own tag into the skb's
  metadata before it takes `skb->len` (`reorder_hdr`, the default), so the
  device counts the frame *without* its tag while the firmware counted it
  with. The software fast path shows the convention directly: the same burst
  forwarded by the CPU leaves 298 per frame on `eth3.271` for 302 on the wire.
  A device configured with `reorder_hdr off` counts its tag and would read
  4 bytes per frame low here; the default is pinned rather than the flag
  followed, because the flag can change under a live record.
- **The insert's record list is innermost-first.** The firmware inserts the
  innermost header first and counts the k-th listed record after the k-th
  insertion, so listing the records outermost-first — the order the strip uses
  beside its VIDs, and the order the legacy path has always written — would
  hand the outer device the frame with only the inner tag on. The flow path
  lists them the other way; the legacy path is left as it was.
- **A ppp device subtracts the Ethernet header plus one tag per VLAN device its
  session runs over on receive, and the Ethernet and session headers on
  transmit.** `ppp_generic.c` counts `skb->len - PPP_PROTO_LEN` both ways, the
  payload alone. The tag count is a property of the device -- a session's
  lower device is fixed for its life -- and is taken from the direction's own
  tag stack, which sits entirely under the session.

The residual is the one every restatement here shares: padding. A stream of
frames under 60 bytes reads high by what was padded, at most ten bytes each,
and the saturating subtraction is what keeps a total from wrapping when the
overhead exceeds it.

## The driver's own counters

Two things the driver counts were wrong or blind in ways this work had to
settle before the folded numbers could mean anything.

**A frame the software flowtable forwards was never counted** (ISSUES A159).
`_dpa_rx()` in `drivers/net/ethernet/freescale/sdk_dpaa/dpaa_eth_sg.c` counted
`rx_packets` and `rx_bytes` only when `netif_receive_skb()` returned something
other than `NET_RX_DROP`. That return is not a drop report:
`__netif_receive_skb_core()` initialises it to `NET_RX_DROP` and only a
delivered protocol handler overwrites it, so a frame consumed on the
`NF_NETDEV_INGRESS` hook comes back as `NET_RX_DROP` after being forwarded, and
the driver counted nothing — not even `rx_dropped`. GRO would have hidden it for
TCP, but `dpa_fix_features()` clears `NETIF_F_RXCSUM`, so every frame takes
that path. Kernel patch `104-sdk_dpaa-rx-stats-before-stack-verdict.patch`
counts the frame before the handoff, as every other driver does; the core's
own `rx_dropped` and `rx_nohandler` still record real drops.

**`ethtool -S` stays the driver's.** It reports the per-CPU software counters
and the CEETM class counters and nothing folded, which is deliberate: it is the
one native surface that separates what the CPU saw from what the hardware
forwarded, and the difference between it and `ip -s link` is the offloaded
traffic. The rig test uses exactly that to prove a burst went through
hardware.

## Proof

`tools/tests/test_flowtable_ifstats.py`, on the DK with the KASAN image, 64
frames each way per case:

- **One tag.** Both flow rows count 64 frames of 302 and 298 bytes; the
  `eth3.271` record reads 64 × 298 received and 64 × 302 transmitted; `ip -s
  link` and `/proc/net/dev` on `eth3`, `eth4` and `eth3.271` move by the burst
  restated as above (64 × 284 received and 64 × 298 transmitted on the VLAN
  device) plus the handful of frames the CPU forwarded meanwhile, and
  `ethtool -S eth3` moves by those few frames only.
- **Two tags.** Each device's record reads the progressive numbers in the table
  above, and each device's native counters move by its own restatement — the
  outer device sees the frame with the inner tag still on, the inner device
  sees it bare.
- **Software path.** With a software flowtable bound, the port's `ethtool -S`
  receive count and its native counters both move by the burst, which they did
  not before patch 104; and the VLAN device's own transmit counter, fed by
  Linux alone here, reads 298 per 302-byte frame, which is the convention the
  hardware fold restates to.
- **Session** (`test_flowtable_pppoe_session_counters`, a session over a tagged
  WAN). The record reads 64 × 302 received and 64 × 306 transmitted for 64
  frames of 284-byte payload; `ip -s link show ppp0` moves by 64 × 284 both
  ways plus the session's own LCP echoes; and retiring the connection leaves
  the record in place with no references, its totals intact.

Host tests carry what the bench cannot show cheaply: `test_ifstats.py` the
publication, fold, restatement and withdrawal against the real allocator on a
simulated MURAM; `test_vlan_hm.py` the two opcodes' record lists, their order
and the all-or-nothing rule against the shipped SDK header; `test_flowtable.py`
the record's lifetime across flows, unregistration and reuse of an index.

`/proc/cdx_flowtable` gained `vlan_records` and `vlan_slots` in its header and
one `vlan` row per device with a record, and its `session` rows now name the
device too:

```
session dev=ppp0 ifindex=18 pppoe=1@00:11:22:33:44:55 lower=7 refs=2 slot=yes rx_packets=64 rx_bytes=19328 tx_packets=64 tx_bytes=19584
vlan dev=eth3.271 ifindex=16 refs=2 slot=yes rx_packets=64 rx_bytes=19072 tx_packets=64 tx_bytes=19328
```

The numbers there are the firmware's own, whole frames; the device's `ip -s
link` shows the same records restated, so the two differ by the framing and
nothing else. `slot=none` is a device the pool had nothing for; `dev=-` is a
device that has unregistered while a direction still names its record. A
session row's `pppoe=` is the session the last admitted direction named, in the
form the flow rows use.

## What is not carried, and why

- **A tag with no device behind it has no counter.** A vlan-aware bridge's own
  tag — an untagged port with a PVID, which is the configuration the product
  ships — reaches the wire as no tag at all, so there is no strip or insert
  opcode to count on, and a tagged bridge port whose VLAN has no `br-lan.N`
  device above it has nothing to fold into. The physical ports count that
  traffic; the bridge device itself does not. CMM had the same gap: its
  bridge path suppressed the pointer for exactly these tags.
- **The software fast path is blind to VLAN devices.** Netfilter's flowtable
  hook runs on the physical port and forwards from there, so a frame it handles
  in software is counted by the port (after patch 104) but never reaches the
  8021q layer whose counters it would otherwise have crossed. That is the
  kernel's design, not a gap in the fold; the hardware path does not have it,
  because the record is the VLAN device's.
- **Frames handed to SEC are not counted by the enqueue.** The encoder emits no
  transmit pointer for a to-SEC enqueue (`stats_ptr = 0`), so an encrypted
  direction's egress port bytes are not accounted by the flow's own action
  list. Not measured here; the IPsec path's post-SEC enqueue is where that
  count would have to come from.
- **Legacy attribution in QinQ.** The registered-interface path writes the
  insert's record list outermost-first, which, given the measured pairing,
  credits the outer interface with the frame before its own tag went on. It is
  left unchanged: that owner is being retired and nothing exercises its QinQ
  counters.

# NAT64 and SIIT offload

Status:
- **Implemented:** the encoder and the translator-neutral admission source
  (`cdx/ask_xlat.h`).
- **Proved:** through the test client, on both lines' test images. 6.18 passed
  the full suite, the rig test included, and a line-rate load. 6.12 passed
  the host suite and the rig test.
- **Not done yet:** no translator is patched, so the feature is outside the
  [supported scope](README.md#supported-scope) until one ships
  ([Translator integration](#translator-integration-not-implemented)).

This guide covers:
- what the hardware does with a translation between IPv4 and IPv6;
- how cdx encodes one;
- how a translator offers its sessions;
- what stays in software;
- where hardware translation differs from Jool's;
- how it is observed and what proves it.

## Why a translation needs its own admission source

Jool (stateful NAT64, RFC 6146, and SIIT, RFC 7915) translates in one of two
places: its own PRE_ROUTING hook (priority -75, after defrag and conntrack),
or its iptables `JOOL`/`JOOL_SIIT` target. It keeps its own BIB and session
tables, builds a new skb, routes it itself and sends it with `dst_output()`.

The original packet is stolen and its conntrack entry is never confirmed.
The translated packet has its conntrack reset. So:
- no translated flow reaches FORWARD;
- nftables' `flow add` never sees one;
- a Linux flowtable has no action that changes the family anyway.

Offload therefore takes its sessions from the translator instead
([Admission](#admission)).

## The hardware primitive

### The opcodes

The ASK microcode has two flow-entry opcodes that replace the first IP header
with a per-flow template: `NATPT_4to6` (0x51) and `NATPT_6to4` (0x52).
- **Firmware:** 210.10.1, byte-identical to the firmware NXP shipped with its
  ASK 5.03.1, whose cdx used the opcodes for NAT-PT socket pairs.
- **What isn't needed:** neither the FMan header-manipulation engine's
  "custom IP replace" nor any microcode change.
- **Parameter:** one word, then the template. The word holds:
  - the flags, in bits 24-31;
  - the template length, in bits 16-23;
  - for 6to4, the IPv4 identification the flow starts counting from, in the
    low half.

### Measured behaviour

**Method:** hairpin entries on the WAN port, frames crafted on the WAN host,
and each result verified from the raw bytes.

| Property | What the microcode does |
| --- | --- |
| L4 checksum (TCP, UDP) | Correct in both directions, pseudo-header change included |
| IPv4 header | Writes the length, the checksum, and the protocol (from the IPv6 next header). The checksum is the template's sum plus those fields, so the template must hold 0 in protocol, length, ID, TTL and checksum. A template naming the protocol is off by the protocol value; one with its checksum field set, by twice that |
| IPv6 header | Writes the payload length; the next header comes from the template |
| TTL / hop limit | Carried over from the replaced header and decremented (bit 24). TTL 2 leaves with 1. A packet arriving with TTL 1 or 0 goes to the CPU untranslated |
| TOS / traffic class | The template's, unless the template's is **0xff**. Then each arriving packet's is copied, ECN included, and the IPv4 checksum follows it. 4to6 needs only the template value; 6to4 also needs bit 25. Measured with 0xb8, 0xbb (CE), 0x01 and 0x00 |
| IPv4 identification | 1, 2, 3, … per flow, from the word's low half; bit 26 takes the template's instead |
| IPv4 DF / fragment field (6to4) | The template's, checksummed |
| EtherType | Not written: the Ethernet header must be stripped and rebuilt. Without that, the old header's leftovers stay (0x36ff and 0xbfb5 were seen) |
| Frame length | Changes by the header difference **plus 2**: every translated frame carries 2 bytes past its IP packet ([The trailing 2 bytes](#the-trailing-2-bytes)) |
| Template length field | Must be the header's exact size (20 or 40). With 18, 22 or 24 the frame is lost |
| UDP checksum 0 (IPv4) | Passed through as 0, which IPv6 forbids |
| IPv6 extension headers | Not handled. The handler drops everything up to L4 but writes the IPv4 protocol from the *first* next header, so such packets must not reach the entry |
| IPv4 options | Dropped: the replaced header's length is the parser's |
| TCP SYN | Never reaches the flow entry: the classifier gives it to the CPU |

### The handlers

Decoded statically from the stock blob (210.10.1, SHA-256 `5f3ed8d3…`). The
starting point was the community microcode decompilation's tools and notes,
whose comparison wrongly lists NAT64 as impossible in hardware. Some
instruction classes are inferred, but the reading reproduces every
measurement above.

* **Dispatch.** w8682 loads the opcode byte and w8688 is a jump table on its
  high nibble.
  - Nibble 5 (w8699) jumps to w10408.
  - There, bit 0 selects 4to6 (w10409-w10548) and bit 1 selects 6to4
    (w10550-w10730).
  - Both exit at w10732, having consumed 4 bytes plus the template length of
    parameter.
* **Template.**
  - The length (bits 16-23) is read at w10414 and w10551.
  - The template is copied over the old header at w10462 and w10606.
  - The old header's length is the parser's L4 offset minus the current L3
    offset, so IPv4 options go, and so do IPv6 extension headers. But the
    IPv4 protocol is written from the first next header (w10563, w10626).
* **TTL** (bit 24): w10468 and w10613 write TTL−1 / hop−1.
* **IPv4 identification:** unless bit 26 is set, w10642-w10658 write the
  counter, add it to the checksum, increment it and store it back into the
  entry.
* **IPv4 checksum:** the template's sum, plus TTL, protocol, length and ID,
  folded and stored at w10659-w10673.
* **TOS/TC sentinel.**
  - 4to6: when the template's traffic class reads 0xff, w10480-w10487 insert
    the saved IPv4 TOS. No flag is involved.
  - 6to4: w10631 tests bit 25. Then, when the template TOS reads 0xff,
    w10633-w10640 insert the saved traffic class, subtracting the 0xff from
    the checksum and adding the real value (w10637, w10640).
* **The 2 bytes.** IC+0xc0 is the frame-length delta:
  - zeroed at w8668;
  - reduced by 14 by the Ethernet strip;
  - added to the frame descriptor's length at enqueue.

  NAT-PT adds the header difference plus a literal 2 to it: w10438 on 4to6,
  w10596 on 6to4. w10452, w10459, w10582 and w10603 do the same on paths the
  supported headers never take.

### The trailing 2 bytes

**The cause.** Every translated frame, in both directions, ends 2 bytes past
its IP packet, whether or not the Ethernet header is rebuilt. A plain NAT
entry with a rebuilt header has none. The 2 is the literal in the handlers
above, with no flag to turn it off.

**Proof.** Patching the two words, `f0415302 → f0415300` (w10438) and
`f4414302 → f4414300` (w10596), removes the bytes:
- built with `qef-patch.py` (SHA-256 `0f10775f…`);
- booted RAM-only through U-Boot's `fman_ucode`;
- every probe came back with no trailing bytes and correct checksums.

**Decision (2026-11-19):** keep the stock microcode and ask NXP to fix it;
the patch is not shipped. MTU accounting absorbs the bytes
(`CDX_NATPT_SLACK`, [MTU and DF](#mtu-and-df)).

**Cost.** A full-MTU translated frame is 1520 bytes on the wire (FCS
included), 2 over the 1518 a strict untagged receiver accepts. The bench's
NIC and switch took it.

When a fixed microcode arrives, `CDX_NATPT_SLACK` must follow the loaded
version. A slack of 2 on fixed firmware lets packets 1-2 bytes over the MTU
through: with the patch and the slack still 2, a 1481-byte IPv4 packet
without DF left whole, as 1501 bytes of IPv6. On fixed firmware the slack is
0 and the 4to6 expansion is 20.

## The encoder

**The rule.** Two fields on the backend's direction, `cdx_ft_rule.xlat_family`
and `xlat_tos`:
- **`xlat_family`:** the family `new_src`/`new_dst` are in, when it isn't
  `family`'s.
- **`xlat_tos`:** the TOS or traffic class translated frames leave with.
  `CDX_NATPT_TOS_COPY` (0xff) carries each packet's over, as RFC 7915 does. A
  fixed value serves Jool's `reset-tos`/`new-tos` and `reset-traffic-class`.

**The entry pair.** `ft_hw_add_one()` builds the usual entry/twin pair:
- the entry in its own family, since that is what the classifier keys on;
- the twin in the other family;
- the entry marked `FFTYPE_NATPT`;
- the entry's own `twin_*` fields left alone: they are IPv4 NAT's, and they
  overlay an IPv6 destination.

A translated direction is TCP or UDP only and carries no tunnel, SA or
detour: the opcode replaces the first IP header, which any of those would be.

`fill_actions()` then emits:

1. the preemptive checks (DF, TX validation, policer), as for any flow;
2. strip Ethernet, then the ingress VLAN/PPPoE strips;
3. `UPDATE_SPORT|UPDATE_DPORT` from the twin, while the frame is still in the
   family its checksum covers;
4. `NATPT_6to4` or `NATPT_4to6` with the template and TTL/hop-limit
   carry-over:
   - the template carries the addresses from the twin and the TOS from the
     rule, with bit 25 on 6to4 when the TOS is the copy sentinel;
   - it leaves the protocol, length, ID and checksum fields at 0;
   - on 6to4 it also sets DF;
5. the egress VLAN/PPPoE inserts;
6. `INSERT_L2_HDR` with the other family's EtherType;
7. `ENQUEUE_PKT`.

There is no TTL opcode: NAT-PT takes the TTL step.

### MTU and DF

**How the hardware checks.** The DF check, in the preemptive checks, compares
the frame as it arrived, plus the entry's `hdr_xpnd_sz`, against the entry
MTU. The fragmentation step after translation compares the translated frame
against the same MTU, adding nothing.

**What the encoder sets:**
- every translated entry's MTU is the egress MTU plus the 2 bytes of slack;
- an IPv4-to-IPv6 entry's expansion is 22: the 20-byte growth plus the
  slack.

**Measured with those values** (egress MTU 1500), IPv4 to IPv6:

| IPv4 packet | DF clear | DF set |
| --- | --- | --- |
| 1480 bytes | IPv6 payload 1460, whole | The same, whole |
| 1481 bytes | IPv6 fragments 0\|1448 and 1448\|13 | To the CPU untranslated |
| 1500 bytes | IPv6 fragments 0\|1448 and 1448\|32 | To the CPU untranslated |

That is RFC 7915's behaviour:
- an IPv4 packet whose translation fits goes through whole;
- one that would not fit becomes IPv6 fragments without DF;
- with DF set, it goes to the CPU untranslated, for the translator's
  Fragmentation Needed.

Without the slack, a 1480-byte packet was fragmented. IPv6 to IPv4 needs no
DF check, since IPv6 carries no DF bit, and its translations only shrink: a
1500-byte IPv6 packet became a 1480-byte IPv4 packet.

The fragments' payloads come back byte-identical (A452 measured a 1472-byte
datagram through a 4to6 entry). But the admission bound keeps UDP into a
smaller path in software until A452 is settled
([What stays in software](#what-stays-in-software)).

## Admission

### The interface

`cdx/ask_xlat.h` is the whole interface:
- **Register:** one client registers its two callbacks, `expired` and `used`.
- **Offer:** from softirq, the client offers a session. An offer carries:
  - the netns;
  - TCP or UDP;
  - the TOS mode;
  - a cookie;
  - both directions, each with the tuple it arrives with, the tuple it leaves
    with, and the device it arrives on.
- **Withdraw:** by cookie.
- **Unregister:** `ask_xlat_unregister()` takes the ops it registered and
  refuses any other.

**How an offer is decided.** It is copied into a bounded ring (64 deep) and
decided by a worker. The worker holds the backend transaction and takes RTNL
without waiting, as the bridged learner decides its pairs.

**How the paths are found:**
- each direction's egress is the route the translator would take for its
  translated destination;
- the next hop, neighbour and physical port (the kernel's forwarding-path
  walk) follow from it, as do the tags, bridge and session
  (`ft_path_stack()`);
- each direction's ingress is its sibling's egress, and the translator's
  ingress device has to match it.

Both directions go in through the install Netfilter's offers use
(`ft_install()`), or neither does. Translated entries share the backend's
budget, capped at half of it (16,384 directions).

### The answer contract

Each offered session is answered by exactly one `expired`, unless the client
withdraws it first. At any moment exactly one thing owes that answer: the
offer that stands for the session (queued, or in the worker's hands), or the
owner it installed. The cases:
- **An offer of a session something already stands for** is folded into it.
- **An offer of a session whose retired owner is still leaving the hardware**
  is queued, and takes the answer from that owner at once. Whichever comes
  first, the old entries' retirement or the offer's decision, nothing is said
  before the new session is installed.
- **A refused offer** hands the answer back to such an owner, which says it
  once its entries have left.
- **An offer or withdrawal that lands while an `expired` is being said**
  cannot stop it. The offer is turned away (`false`), the withdrawal returns
  `false`, and the call answers the session as it was.

### Lifetime

- **Withdrawal and restart.** A withdrawn session, and every session a
  datapath restart retires, is found by its cookie and retired directly by
  the translation worker, never by walking the table. A restart's sessions
  are said `expired`, and the translator offers them again.
- **Keepalive.** `used` is said once per counter pass that saw a session's
  packets. The pass runs while translated sessions are installed, even with
  `stats_ms` at 0 (then once a second).
- **Retirement.** The route, neighbour, device, tc and policy watches retire
  a translated session as they retire a flowtable flow, and its owner says
  `expired`. Route watches match each address in its own family
  (`ft_new_family()`), and so does `ft_policy_covers()`.

### The MTU bound

The bound is the flowtable's, measured on what a direction hands on: an IPv4
packet the port takes whole is 20 bytes longer as IPv6.
- **UDP, and TCP into IPv4,** are carried only where the largest such packet
  fits. TCP into IPv4 has no MSS clamp to rely on: the translator steals its
  packets at PREROUTING, before any FORWARD rule sees a SYN.
- **TCP into IPv6** is exempt: the entry's DF check hands an oversized IPv4
  segment with DF to the translator.

An offer that the route's MTU alone is certain to refuse is turned away
before it is queued (`xlat_mtu_refused`), without RTNL. The default NAT64
shape is one: UDP from a 1500-byte IPv4 uplink into a 1500-byte LAN. The
route is read again at each offer, so nothing is cached that could go stale.

### How a translated entry fits the adapter

Every entry reaches what it is in hardware for through a `struct ft_owner`,
with five operations: valid, invalidate, account, used and release.
Flowtable entries embed `struct ft_nf_owner`, which wraps Netfilter's handle.
A translated pair gets one owner shared by its two directions
(`cdx/ask_flowtable_xlat.c`).

* **No binding.** Every published entry is on a list by its `binding_node`:
  its binding's, or `ft_xlat_list` for a translated one.
  - So `ft_unlink()` takes it off unconditionally.
  - The translated directions drain by that list, as a binding's drain by
    its own (`ft_retire_list()`).
  - Their cookie, the translator's, shares `ft_cookies` with Netfilter's
    under a NULL binding, which no Netfilter lookup matches.
* **Unload and unregistration** retire the translated list explicitly, and
  unregistration waits for the barrier that proves it (`ft_hw_settle()`).
  - A port's unregistration latches the global invalidation. That retires
    every entry on `ft_entries`, and it runs even with a translation client
    registered and nothing bound (`ft_xlat_active`).
  - The same drain rearms admission for such a client.
* **The count.** `ft_owner_attach()` raises `ft_handle_refs` for every owner
  reference, whichever source took it.
* **The shared owner** holds one reference per entry, plus the admission's
  own while it installs them, and its last release says `expired`.
  Invalidation is final: a re-offer takes a fresh owner, superseding the
  retiring one.
* **A key collision** refuses in both orders, through `ft_key_holder()`:
  - a live Netfilter entry refuses a translated offer;
  - a live translated entry refuses a Netfilter offer (`-EEXIST`);
  - a key whose holder's owner is retired goes to the translated newcomer at
    once.
* **`account(dir, …)`** only notes that a direction moved: the translator
  counts its sessions by their timers.
* **Marks after publication.** After publishing, the admission rechecks both
  of its routes (`ft_dst_current()`), the latch and its own owner, and marks
  that owner.
* **The ingress port** is pinned by the entry itself; for a Netfilter entry,
  the binding pins it.

## What stays in software

* **Connection setup and teardown:** TCP SYN (measured), and FIN/RST, which
  the same classifier rule gives the CPU (to be confirmed with Jool).
* **Expiring TTL,** and DF packets too big once translated (both measured).
* **ICMP and ICMPv6 of every kind:** Jool rewrites types, ids and inner
  packets, and the ICMPv6 checksum depends on the length.
* **Fragments and IPv6 extension headers.** The opcode mistranslates an
  extension header, so the classifier's handling of them must be confirmed
  before an entry can see one. The opcode drops IPv4 options, as Jool does,
  but Jool answers an unexpired source route with an ICMP error.
* **IPv4 UDP with checksum 0.** Jool recomputes it (NAT64) or drops it (SIIT
  without `compute-udp-csum-zero`); hardware would send it as 0. A translator
  must not offer such a flow. A sender checksums per socket, so one flow does
  not mix the two.
* **A UDP session whose IPv4 side could outgrow the IPv6 path.** A 1500-byte
  IPv4 packet is 1520 bytes as IPv6. Without DF, the only thing that keeps it
  within the MTU in hardware is the microcode's fragmenter, which A452 has
  not cleared.

  The enqueue's `FRAG_DISABLE` bit is no way around it. Measured, it sends
  the oversized packet out whole, as 1520 bytes over a 1500-byte MTU, rather
  than to the CPU.

  So until A452 is settled, such a session stays with the translator. At
  equal MTUs that is every UDP session.

## Where hardware differs from Jool

| Field | Jool | Hardware | Handling |
| --- | --- | --- | --- |
| TOS / traffic class | Copied per packet, ECN included (unless `reset-tos` / `reset-traffic-class`) | The same, through the 0xff sentinel; or a fixed value | Matches. A fixed value follows Jool's reset configuration |
| Trailing bytes | None | 2 per frame | MTU accounting absorbs them; NXP is asked to fix the microcode ([The trailing 2 bytes](#the-trailing-2-bytes)) |
| IPv4 identification | `__ip_select_ident()` per packet | Counted per flow | Equivalent for uniqueness (RFC 6864) |
| DF on 6to4 output | Set when over 1260 bytes | The template's, fixed per flow | DF always set: the large packets are the ones it matters for |
| Fragmenting DF-clear 4to6 | Down to `lowest-ipv6-mtu` (default 1280) | Down to the egress MTU | Matches when `lowest-ipv6-mtu` is the link MTU. Otherwise the Jool integration programs `min(egress MTU, lowest-ipv6-mtu)` as the entry MTU and accepts a lower DF bound |

## Observing it

* **`/proc/ask_flowtable/flows`:** two rows per session ([procfs](procfs.md)).
  - `xlat=` names the family a row leaves in, and `new_src=`/`new_dst=` are
    in that family.
  - `tos=` is `copy` or the fixed value.
  - `cookie=` is the translator's cookie, in hex.
* **`status`:** `xlat_registered`, `xlat_sessions`, `xlat_entries`,
  `xlat_max_entries` and `xlat_pending`.
* **`stats`:** the `xlat_*` counters (offers, installs, refusals, expired,
  used, withdrawals, MTU refusals, restart invalidations).
* **The kernel log:** with cdx's `ask_debug` refusal bit set
  (`/sys/module/cdx/parameters/ask_debug`), every refusal logs one line
  naming the cookie, the direction and what decided it. Offers and the
  worker's waits are rate-limited:

  ```text
  ASK-DEBUG: xlat cookie=1 dir=0 neigh 10.0.0.232 on eth4 unresolved
  ```

## Proof

### Host

- `flowtable_hw.c` checks the pair, the overlay, the TOS and the slack in the
  MTU.
- `natpt_hm.c` runs the production selector and the NAT, NAT-PT and Ethernet
  emitters. It checks the opcode order, the flags and every parameter byte
  the microcode reads, in both directions, for TCP and UDP, and in both TOS
  modes.
- `flowtable.c`'s translated-session cases cover:
  - admission, refusals and the MTU bound;
  - collisions, and supersession of a retiring owner;
  - the ring and offers in flight;
  - keepalive and withdrawal;
  - registration;
  - retirement by ports, routes, policy and paths;
  - rearming after a global invalidation.
- `flowtable_procfs.py` checks that both `flows` row formats print the
  documented fields.

### Rig

`tools/tests/flowtable_xlat.py` drives the test client and skips on an image
without it. All of its cases are TCP sessions:
- **refusal:** without a neighbour, with exactly one `expired` and its log
  line;
- **the rows;**
- **the wire, both directions,** on a hairpin through the WAN port and from
  the LAN VM to the WAN host. Each frame is read from raw bytes: checksums,
  hop count, DF, and TOS 0x00/0xb8/0xbb copied;
- **keepalive** on traffic only;
- **withdrawal** without `expired`;
- **retirement** by a neighbour change and by a route removal;
- **the drain on unload;**
- **a load** through the upload's entry, which the entry counts exactly.

### Measured

| Run | Result |
| --- | --- |
| TCP, LAN VM → WAN host through the admission source, 5 s | 4,466,688 frames of 1,374 bytes, at 893 kpps and 9.82 Gbit/s on the wire. The entry counted every one and eth4 sent every one; the DUT CPU's eth3 receive count rose by 3 |
| UDP, WAN host hairpin through a hand-installed 6to4 entry, 5 s | 2,551,040 packets with 1400-byte payloads (510 kpps, the Python sender's rate). The entry counted every one; the DUT CPU received 12 frames, all background |

### Not yet proved

* FIN/RST handling with a real translator.
* A translated direction combined with VLAN or PPPoE.
* How the classifier treats IPv6 extension headers on an offloaded flow.

## Test client

Until a translator is patched, `ask_xlat_test.ko` (`cdx/ask_xlat_test.c`)
stands in for one:
- it is built only for the test image (`CONFIG_ASK_XLAT_TEST`, which
  meta-ask's recipe sets and no consumer's build does);
- it registers with `ask_xlat.h` when it loads and unregisters when it goes;
- it offers sessions described by hand, admitted exactly as a translator's
  would be.

```text
modprobe ask_xlat_test
echo "in=eth3 proto=tcp src=<v6 client> dst=64:ff9b::a00:e8 sport=40001 dport=5000
      nsrc=10.0.0.62 ndst=10.0.0.232 nsport=40001 ndport=5000
      tos=copy cookie=1" > /sys/module/ask_xlat_test/parameters/session
cat /sys/module/ask_xlat_test/parameters/session    # sessions still owed an answer, and totals
echo "withdraw cookie=1" > /sys/module/ask_xlat_test/parameters/session
echo flush > /sys/module/ask_xlat_test/parameters/session   # withdraw them all
```

**The line.** One line describes the first direction, as it arrives on `in`
and as it leaves translated. The second direction is its inverse, arriving on
`rin=` if given, otherwise on the device the route to `ndst` leaves by.
`tos` is `copy` (the default) or a fixed value. Routes, neighbours, ports and
the MTU are the adapter's to find, as for a translator's offer.

**UDP at equal MTUs is refused.** With both ports at 1500 bytes only TCP is
offloaded: the IPv4 side's 1500-byte UDP packets are 1520 bytes as IPv6. A
UDP session needs the LAN port at an MTU of 1520 or more, and otherwise the
write fails with `EOPNOTSUPP`.

**Slots.** A session's slot is given back when the session is said expired,
or withdrawn with nothing more to say. A withdrawal that lands while its
`expired` is being said keeps the slot until that call arrives, and the
cookie cannot be offered again until then (`EBUSY`).

## Translator integration (not implemented)

Jool exports no session API: jool_common's 11 symbols are the hooks, the
xlator flush and the instance get/put. Offload needs a small, upstreamable
Jool patch that calls `ask_xlat.h`.

**The Jool patch** (references are to Jool 4.1.15's `src/mod/common/`):

* **Create.** Call `ask_xlat_offer()` in `core_common()` (`core.c`), on the
  non-hairpin branch, after a successful translation and just before
  `sendpkt_send()`.
  - It describes both directions from the input skb (ingress device, L3
    header) and the translated skb (route attached).
  - For NAT64 it adds the session's two 5-tuples, protocol and state.
  - The context is softirq under RCU, with no Jool lock held, which is what
    `ask_xlat_offer()` takes.
* **Destroy.** Withdraw, from:
  - `rm()` and `detach_sessions()`: the table lock is held and BH is off;
    withdrawal only enqueues, so this is safe;
  - instance teardown and every configuration change that alters
    translation: pool4, EAMT, denylist, global and atomic replacement.
* **Keepalive.** On `used`, a new export, `jool_session_touch()`:
  - it finds the session under the table lock and calls
    `handle_fate_timer()`;
  - that must also move the session to its list's tail, because `__clean()`
    stops at the first unexpired session;
  - a session that is gone returns `-ESRCH`, and the client withdraws it.

  An `offloaded` pin keeps `__clean()` from expiring a pinned session between
  touches. Otherwise a reallocated pool4 port could meet a stale hardware
  entry.
* **`expired`** clears the pin and lets the session age normally in
  software.

**What the patch must not offer:**
- sessions of a joold-enabled instance (sync is per packet, and deletions are
  never synced);
- sessions of an iptables-mode instance (its per-packet rule matches would be
  skipped);
- ICMP;
- TCP before ESTABLISHED, or a session holding a stored packet;
- IPv4 UDP with checksum 0.

The adapter itself refuses an instance outside init_net, an egress that is
not an ASK port, and a 5-tuple held by a live conntrack-offloaded flow.

**SIIT** has no per-flow state: address mapping goes through pool6, the EAMT
and the denylist per packet. Its integration keeps its own per-flow table,
with an idle timeout from `used`, and flushes on any SIIT configuration
change or local IPv4 address change.

**Remaining work, in order:**

1. The Jool patch, for stateful NAT64, TCP and UDP.
2. Jool in the test image, so the rig runs a real NAT64 (Jool's netfilter
   mode in meta-ask, `set nat64` under VyOS), with line-rate and lifecycle
   tests.
3. SIIT.
4. VyOS packaging of the patched Jool modules.

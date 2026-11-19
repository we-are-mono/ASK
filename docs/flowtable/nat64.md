# NAT64 and SIIT offload

Status: **feasibility proved; encoder and translator-neutral admission source
on the `nat64-offload` branch, no translator patched yet; not in the
[supported scope](README.md#supported-scope).** This document records what the
hardware does with a translation between IPv4 and IPv6, how cdx encodes one,
what has to stay in software, where hardware translation differs from Jool's,
and the design for admitting Jool's translations. The measurements are in
[the feasibility record](history/nat64-feasibility.md).

## Why the flowtable path never sees a translation

Jool (stateful NAT64, RFC 6146, and SIIT, RFC 7915) translates in its own
PRE_ROUTING hook (priority -75, after defrag and conntrack) or in its
iptables `JOOL`/`JOOL_SIIT` target, with its own BIB and session tables. It
builds a new skb, routes it itself and emits it with `dst_output()`. The
original packet is stolen, its conntrack entry never confirmed; the
translated one has its conntrack reset. So no translated flow reaches FORWARD,
nftables' `flow add` never sees one, and a Linux flowtable has no action that
changes the family anyway. Offload needs its own admission source: Jool
saying when a translation can go to hardware and when it ends.

## The hardware primitive

The ASK microcode (210.10.1, byte-identical to the firmware NXP shipped with
its ASK 5.03.1, whose cdx used it for NAT-PT socket pairs) has two flow-entry
opcodes that replace the first IP header with a per-flow template:
`NATPT_4to6` (0x51) and `NATPT_6to4` (0x52). Neither the FMan header
manipulation engine's "custom IP replace" nor any microcode change is needed.
Their parameter is one word (flags in bits 24-31, template length in bits
16-23, and for 6to4 the IPv4 identification a flow starts counting from)
followed by the template.

Measured on the DK (hairpin entries on the WAN port, frames crafted on the WAN
host; [record](history/nat64-feasibility.md)):

| Property | What the microcode does |
| --- | --- |
| L4 checksum (TCP, UDP) | Correct in both directions, pseudo-header change included |
| IPv4 header | Length, checksum and protocol (from the IPv6 next header) computed. The protocol is counted in the checksum on top of the template's, so the template must leave it 0 |
| IPv6 header | Payload length computed; next header from the template |
| TTL / hop limit | Carried over from the replaced header and decremented (bit 24). TTL 1 or 0 goes to the CPU untranslated |
| TOS / traffic class | The template's, unless the template's is **0xff**: then each arriving packet's, ECN included, with the IPv4 checksum following it. 4to6 needs only the template value; 6to4 needs bit 25 as well |
| IPv4 identification | Counted per flow from the word's low half; bit 26 takes the template's instead |
| IPv4 DF / fragment field (6to4) | The template's, checksummed |
| EtherType | Not written: the Ethernet header has to be stripped and rebuilt |
| Frame length | Shrinks or grows by the header difference **plus 2**: every translated frame carries 2 bytes past its IP packet. The 2 is a literal in the handler (word 10438 for 4to6, 10596 for 6to4), with no flag |
| Template length field | Must be the header's exact size (20, 40); any other value loses the frame |
| UDP checksum 0 (IPv4) | Passed through as 0, which IPv6 forbids |
| IPv6 extension headers | Not handled. The handler drops everything up to L4 but writes the IPv4 protocol from the first next header, so such packets must not reach the entry |
| IPv4 options | Dropped. The replaced header's length is the parser's |
| TCP SYN | Never reaches the flow entry: the classifier gives it to the CPU |

The handlers are at words 10408-10730 of the stock blob (dispatch: opcode
high nibble 5 at w8699). The decoded walk-through, word by word, is in the
[feasibility record](history/nat64-feasibility.md#the-handlers).

## The encoder

The prototype adds one field pair to the backend's direction,
`cdx_ft_rule.xlat_family` and `xlat_tos`: the family `new_src`/`new_dst` are
in when it is not `family`'s, and the TOS/traffic class translated frames
leave with. That is `CDX_NATPT_TOS_COPY` (0xff) to carry each packet's over,
as RFC 7915 does, or a fixed value for Jool's `reset-tos`/`new-tos` and
`reset-traffic-class`. `ft_hw_add_one()` builds the usual entry/twin pair with the entry
in its own family (it is what the classifier keys on) and the twin in the
other, marks the entry `FFTYPE_NATPT`, and leaves the entry's own `twin_*`
fields alone (they are IPv4 NAT's and overlay an IPv6 destination). A
translated direction is TCP or UDP only, and carries no tunnel, SA or detour:
the opcode replaces the first IP header, which any of those would be.

`fill_actions()` then emits:

1. the preemptive checks (DF, TX validation, policer), as for any flow;
2. strip Ethernet, then the ingress VLAN/PPPoE strips;
3. `UPDATE_SPORT|UPDATE_DPORT` from the twin, while the frame is still in the
   family its checksum covers;
4. `NATPT_6to4` or `NATPT_4to6` with the template and TTL/hop-limit
   carry-over. The template carries the addresses from the twin and the TOS
   from the rule (with bit 25 on 6to4 when it is the copy sentinel), and
   leaves the protocol, length, ID and checksum fields 0. On 6to4 it also
   sets DF;
5. the egress VLAN/PPPoE inserts;
6. `INSERT_L2_HDR` with the other family's EtherType;
7. `ENQUEUE_PKT`.

No TTL opcode: NAT-PT takes the TTL step.

**MTU and DF.** The DF check (in the preemptive checks) compares the frame as
it arrived, plus the entry's `hdr_xpnd_sz`, against the entry MTU; the
fragmentation step after translation compares the translated frame against
the same MTU without adding anything. So:

* every translated entry's MTU is the egress MTU plus the 2 bytes of slack;
* an IPv4-to-IPv6 entry's expansion is 22 (the 20-byte growth plus the slack).

That gives exactly RFC 7915's behaviour, measured: an IPv4 packet whose
translation fits goes through whole; one that would not fit goes through as
IPv6 fragments without DF, and to the CPU untranslated with DF (for Jool's
Fragmentation Needed). An IPv6-to-IPv4 entry has no DF check (IPv6 carries
none); its translations only shrink.

## What stays in software

* Connection setup and teardown: TCP SYN (seen), and FIN/RST, which the same
  classifier rule gives the CPU (to be confirmed on the rig with Jool).
* Expiring TTL (seen), and DF packets too big once translated (seen).
* ICMP and ICMPv6 of every kind: Jool rewrites types, ids and inner packets,
  and the ICMPv6 checksum depends on the length.
* Fragments and IPv6 extension headers. The opcode mistranslates an
  extension header (above), so the classifier's handling of them has to be
  confirmed before the entry can see one. IPv4 options the opcode drops, as
  Jool does, but Jool answers an unexpired source route with an ICMP error.
* IPv4 UDP with checksum 0, which Jool recomputes (NAT64) or drops (SIIT
  without `compute-udp-csum-zero`). Hardware would emit it as 0. Admission
  refuses a UDP flow whose packets reached Jool with checksum 0; whether a
  sender checksums is a per-socket choice, so a flow does not mix the two.

## Where hardware differs from Jool

| Field | Jool | Hardware | Proposal |
| --- | --- | --- | --- |
| TOS / traffic class | Copied per packet, ECN included (unless `reset-tos` / `reset-traffic-class`) | The same, through the 0xff sentinel; or a fixed value | Matches. A fixed value follows Jool's reset configuration |
| Trailing bytes | None | 2 per frame | **Stock microcode stays** (decided 2026-11-19) and NXP is asked to fix it. MTU accounting absorbs the bytes. A full-MTU translated frame is 1520 bytes on the wire (FCS included), 2 over the 1518 a strict untagged receiver accepts; the bench's NIC and switch took it. Changing words 10438 and 10596 to `…00` removes the bytes (measured), but is not shipped. When a fixed microcode arrives, `CDX_NATPT_SLACK` must follow the loaded version: a slack of 2 on fixed firmware lets packets 1-2 bytes over the MTU through |
| IPv4 identification | `__ip_select_ident()` per packet | Counted per flow | Equivalent for uniqueness (RFC 6864) |
| DF on 6to4 output | Set when over 1260 bytes | The template's, fixed per flow (measured honoured) | DF set always: the large packets are the ones it matters for |
| Fragmenting DF-clear 4to6 | Down to `lowest-ipv6-mtu` (default 1280) | Down to the egress MTU | Matches when `lowest-ipv6-mtu` is the link MTU; otherwise program `min(egress MTU, lowest-ipv6-mtu)` as the entry MTU and accept a lower DF bound |

## Admission: a Jool hook and an adapter

Jool exports no session API. jool_common's 11 symbols are the hooks, the
xlator flush and the instance get/put. So offload needs a Jool patch, kept
small and upstreamable, plus an ASK adapter on the other side.

**Jool patch** (references are Jool 4.1.15's `src/mod/common/`):

* `struct jool_offload_ops`, published once through RCU with register and
  unregister (unregister clears it and waits a grace period).
* **Create:** called in `core_common()` (`core.c`) after a successful
  translation and just before `sendpkt_send()`, on the non-hairpin branch.
  It passes the input skb (ingress device, L3 header) and the translated skb
  (route attached), and, for NAT64, the session with both 5-tuples, protocol
  and state, plus the instance's BIB as a generation cookie. The context is
  softirq under RCU with no Jool lock held: the callback copies what it
  needs, defers the work and rate-limits itself.
* **Destroy:** called from `rm()` and `detach_sessions()` (table lock held,
  BH off: enqueue only), and from instance teardown and every configuration
  change that alters translation (process context: may flush synchronously):
  pool4, EAMT, denylist, global and atomic replacement.
* **Keepalive:** a new export, `jool_session_touch()`. It finds the session
  under the table lock and calls `handle_fate_timer()`, which must also move
  the session to its list's tail, because `__clean()` stops at the first
  unexpired session. A gone session returns `-ESRCH`, and the adapter
  retires the entry. An `offloaded` pin keeps `__clean()` from expiring a
  pinned session between touches; otherwise a reallocated pool4 port could
  meet a stale hardware entry.

**Adapter** (alongside `ask_flowtable`, sharing its device-path resolution):

* **On create:** check the refusals, then turn the two directions into two
  `cdx_ft_rule`s: matched tuple, translated tuple, `xlat_family`, `xlat_tos`,
  egress device, next hop and VLAN/PPPoE path, resolved from the translated
  skb's route the way the flowtable's are from its dst. Admit only once both
  directions have been seen and TCP is ESTABLISHED.
* **Refusals:**
  - a joold-enabled instance (sync is per packet and deletions are never
    synced);
  - an iptables-mode instance (its per-packet rule matches would be skipped);
  - an instance outside init_net, or an egress that is not an ASK port;
  - ICMP;
  - TCP in an INIT state, or a session holding a stored packet;
  - IPv4 UDP with checksum 0;
  - a 5-tuple colliding with a conntrack-offloaded flow. The v4 side shares
    addresses with Linux NAPT, and cdx must refuse the duplicate rather than
    shadow it.
* **Lifetime:** hardware counters drive `jool_session_touch()` the way they
  drive the flowtable's timeouts. The existing route, neighbour and device
  invalidation retires entries, as for flowtable directions.

**The adapter's seam.** Every entry reaches what it is in hardware on behalf
of through a `struct ft_owner`, with five operations: valid, invalidate,
account, used and release. Flowtable entries embed `struct ft_nf_owner`, which
wraps Netfilter's handle. A translated pair gets its own owner, shared by the
two directions (`cdx/ask_flowtable_xlat.c`). How a translated entry deals with
what the refactor's review listed:

* **No binding.** Every published entry is on a list by its `binding_node`:
  its binding's, or `ft_xlat_list` for a translated one, so `ft_unlink()`
  takes it off unconditionally, and the translated directions drain by that
  list as a binding's drain by its own (`ft_retire_list()`). Their cookie,
  the translator's, shares `ft_cookies` with Netfilter's under a NULL
  binding, which no Netfilter lookup matches.
* **Unload and unregistration** retire the translated list explicitly, and
  unregistration waits for the barrier that proves it (`ft_hw_settle()`). A
  port's unregistration latches the global invalidation, which retires every
  entry on `ft_entries` and now runs with a translation client registered
  and nothing bound (`ft_xlat_active`); the same drain rearms admission for
  such a client.
* **The count.** `ft_owner_attach()` raises `ft_handle_refs` for every owner
  reference, whichever source took it.
* **The shared owner** holds one reference per entry and the admission's own
  while it installs them; its last release says `expired`. Invalidate is for
  good, and a re-offer takes a fresh owner, the retiring one superseded.
* **A key collision** refuses in both orders through `ft_key_holder()`: a
  translated offer refused by a live Netfilter entry, a Netfilter offer
  (`-EEXIST`) by a live translated one. A key whose holder's owner is retired
  goes to the translated newcomer at once.
* **`account(dir, …)`** only notes that a direction moved: the translator
  counts its sessions by their timers. `used` says the keepalive, once a
  counter pass per session.
* **Marks after publication.** The translated admission rechecks both of its
  routes (`ft_dst_current()`), the latch and its own owner after publishing,
  and marks that owner.
* **The ingress port** is pinned by the entry itself, a binding pinning it for
  a Netfilter one.
* **Route watches** match each address in its own family (`ft_new_family()`),
  and so does `ft_policy_covers()`.

**What the client gets.** `cdx/ask_xlat.h` is the interface: one client
registers its two callbacks, offers a session (the netns, TCP or UDP, the TOS
mode, a cookie, and both directions with the tuple each arrives with, the one
it leaves with and the device it arrives on) from softirq, and withdraws it by
cookie. An offer is copied into a bounded ring and decided by a worker under
the backend transaction and RTNL taken without waiting, as the bridged learner
decides its pairs. Each direction's egress is the route the translator would
take for its translated destination; its next hop, neighbour, physical port
(the kernel's forwarding-path walk) and tags, bridge and session
(`ft_path_stack()`) follow, and each direction's ingress is its sibling's
egress, which the translator's ingress device has to match. Both go in
through the install Netfilter's offers use (`ft_install()`), or neither.

Each session offered is answered by exactly one `expired`, unless the client
withdraws it first. At any moment one thing owes that answer: the offer that
stands for the session, queued or in the worker's hands, or the owner it
installed. An offer of a session something already stands for is folded
into it; one of a session whose retired owner is still leaving the hardware
is queued and takes the answer from that owner at once, so whichever of the
old entries' retirement and the offer's decision comes first, nothing is
said before the new session is installed. A refused offer hands the answer
back to such an owner, which says it once its entries have left. An offer or
a withdrawal landing while an `expired` is being said cannot stop it: the
offer is turned away (`false`), the withdrawal returns `false`, and the call
answers the session as it was. `ask_xlat_unregister()` takes the ops it
registered and refuses any other.

A withdrawn session, and every session a datapath restart retires, is found
by its cookie and retired directly by the translation worker, never by
walking the table. `used` comes from the counter pass, which runs while
translated sessions are installed even with `stats_ms` at 0. A restart's
sessions are said `expired`, and the translator offers them again.

The MTU bound is the flowtable's, measured on what a direction hands on: an
IPv4 packet the port takes whole is 20 bytes longer as IPv6. UDP, and TCP
into IPv4, are carried only where the largest such packet fits. TCP into
IPv4 has no MSS clamp to rely on, because the translator steals its packets
at PREROUTING, before any FORWARD rule sees a SYN. TCP into IPv6 keeps the
exemption: the entry's DF check hands an oversized IPv4 segment with DF to
the translator. An offer the route's MTU alone is certain to refuse is turned
away before it is queued (`xlat_mtu_refused`), without RTNL. The default
NAT64 shape is one: UDP from a 1500-byte IPv4 uplink into a 1500-byte LAN.
The route is read again at each offer, so nothing is cached that could go
stale.

**SIIT** has no per-flow state at all: address mapping goes through pool6,
the EAMT and the denylist per packet. The adapter keeps its own per-flow
table with an idle timeout from hardware counters, and flushes on any SIIT
configuration change or local IPv4 address change.

## Order of work

1. Encoder and its host proof: done in the prototype.
   - `flowtable_hw.c` checks the pair, the overlay, the TOS and the slack in
     the MTU.
   - `natpt_hm.c` runs the production selector and the NAT, NAT-PT and
     Ethernet emitters. It checks the opcode order, the flags and every
     parameter byte the microcode reads, for both directions, TCP and UDP,
     and both TOS modes.
   - The rig checks the wire.
2. The adapter: done, translator-neutral (`ask_xlat.h`), proved on the host
   (`flowtable.c`'s translated-session cases) and drivable on the rig through
   the test client. Then the Jool patch for stateful NAT64, TCP and UDP. Jool
   goes into the test image so the rig can run a real NAT64 (`set nat64`
   under VyOS, Jool's netfilter mode in meta-ask), with line-rate and
   lifecycle tests.
3. SIIT.
4. VyOS packaging of the patched Jool modules.

## Test client

Until a translator is patched, `ask_xlat_test.ko` (`cdx/ask_xlat_test.c`)
stands in for one. It is built only for the test image (`CONFIG_ASK_XLAT_TEST`,
which meta-ask's recipe sets and no consumer's build does), registers with
`ask_xlat.h` when it loads and unregisters when it goes, and offers sessions
described by hand, admitted exactly as a translator's would be:

```text
modprobe ask_xlat_test
echo "in=eth3 proto=tcp src=<v6 client> dst=64:ff9b::a00:e8 sport=40001 dport=5000
      nsrc=10.0.0.62 ndst=10.0.0.232 nsport=40001 ndport=5000
      tos=copy cookie=1" > /sys/module/ask_xlat_test/parameters/session
cat /sys/module/ask_xlat_test/parameters/session    # sessions still owed an answer, and totals
echo "withdraw cookie=1" > /sys/module/ask_xlat_test/parameters/session
echo flush > /sys/module/ask_xlat_test/parameters/session   # withdraw them all
```

One line describes the first direction, as it arrives on `in` and as it
leaves translated; the second is its inverse, arriving on `rin=` if given,
else on the device the route to `ndst` leaves by. `tos` is `copy` (the
default) or a fixed value. Routes, neighbours, ports and the MTU are the
adapter's to find, as they are for a translator's offer; `/proc/ask_flowtable/
flows` shows the two rows (`xlat=`, `tos=`), and `status` and `stats` the
`xlat_*` keys. With both ports at 1500 bytes only TCP is offloaded: the IPv4
side's 1500-byte UDP packets are 1520 bytes as IPv6, so a UDP session needs
the LAN port at an MTU of 1520 or more, and is refused otherwise (the write
fails with `EOPNOTSUPP`). A session's slot is given back when it is said
expired, or withdrawn with nothing more to say. A withdrawal that lands while
its expired is being said keeps the slot until that call arrives, and the
cookie cannot be offered again until then (`EBUSY`).

It replaces the earlier `cdx.xlat_test` hook, which installed one direction by
hand straight through the encoder, MACs and MTU included. That hook could also
give a plain direction a tunnel or a session (`tun=`, `sess=`), which A452's
fragment measurements used; that shape is no longer installable by hand.

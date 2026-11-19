# NAT64 and SIIT offload

Status: **feasibility proved, prototype encoder on the `nat64-offload` branch;
not in the [supported scope](README.md#supported-scope).** This document
records what the hardware does with a translation between IPv4 and IPv6, how
cdx encodes one, what has to stay in software, where hardware translation
differs from Jool's, and the design for admitting Jool's translations. The
measurements are in [the feasibility record](history/nat64-feasibility.md).

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

**SIIT** has no per-flow state at all: address mapping goes through pool6,
the EAMT and the denylist per packet. The adapter keeps its own per-flow
table with an idle timeout from hardware counters, and flushes on any SIIT
configuration change or local IPv4 address change.

## Order of work

1. Encoder and its host proof: done in the prototype (`flowtable_hw.c`
   checks the pair, the overlay, the TOS and the slack in the MTU; the rig
   checks the wire).
2. The Jool patch and the adapter for stateful NAT64, TCP and UDP. Jool goes
   into the test image so the rig can run a real NAT64 (`set nat64` under
   VyOS, Jool's netfilter mode in meta-ask), with line-rate and lifecycle
   tests.
3. SIIT.
4. VyOS packaging of the patched Jool modules.

## Feasibility hook

Until the adapter exists, `cdx.xlat_test` installs a direction by hand:

```text
echo "in=eth4 out=eth4 proto=udp src=<v6 src> dst=64:ff9b::a00:e8 sport=40001 dport=5000
      nsrc=10.0.0.62 ndst=10.0.0.232 nsport=40001 ndport=5000
      smac=<eth4 MAC> dmac=<next hop MAC> mtu=1500 tos=0" > /sys/module/cdx/parameters/xlat_test
cat /sys/module/cdx/parameters/xlat_test      # each entry's hardware hits
echo flush > /sys/module/cdx/parameters/xlat_test
```

The hook is test-only. The adapter replaces it.

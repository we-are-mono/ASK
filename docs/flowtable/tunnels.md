# Linux flowtable tunnels

6o4 and 4o6 offload in the ASK flowtable adapter: why a tunnel hop cannot be
derived the way a tag can, what stands in for the neighbour a tunnel device
does not have, what the hardware cannot reproduce in the outer header, where the
tunnel device's byte counters live, and the hardware proof.

Two modes are in scope, and only two: **6o4**, IPv6 inside an IPv4 outer header
(`sit`, IP protocol 41), the 6rd and tunnel-broker shape; and **4o6**, IPv4
inside an IPv6 outer header (`ip6_tnl` in `ipip6` mode, next header 4), the
DS-Lite shape. EtherIP and GRE-over-IPv6 are out of scope, decided before this
increment. The [PPPoE guide](pppoe.md) is the closest template — a
tunnel is an encapsulation insert one layer up, an IP header where a session
had a session header — and the [IPsec guide](ipsec.md) is the
precedent for the decap half.

## Where the tunnel hop comes from

A tag is derived. A session is handed over. A tunnel is handed over too, and
for the same reason plus one of its own.

`ft_path_stack()` derives a tag stack by descending from the logical device to
the physical port, one lower neighbour at a time. That walk stopped dead at a
`sit` or `ip6_tnl` device in Linux 6.12: only vlan, bridge, dsa, ppp and
mac80211 devices carried an `ndo_fill_forward_path`, so the mechanism VLAN,
bridge and PPPoE rode never reached a tunnel. The first piece of this increment
is therefore a kernel hook, `patches/kernel/143-ask-flowtable-tunnel-path.patch`,
which gives `sit` and `ip6_tnl` that op. Each resolves the hop exactly as its
own transmit path would: it looks up the outer route the same way
`ipip6_tunnel_xmit()` and `ip6_tnl_xmit()` do, finds the neighbour on the
device below, and records the outer header it would prepend as a new
`DEV_PATH_TUNNEL` entry — family, protocol, TTL, traffic class, flow label, the
endpoints, and the next hop the outer packet leaves for. The walk then
continues on the outer route's device with `ctx->daddr` set to that next hop,
so a tunnel over a VLAN device, a bridge or a PPPoE session is descended past
like any upper device.

The hop is handed over rather than re-derived in the adapter, for the reasons a
session is and one more. A tunnel device registers no lower neighbour to
descend to; the outer endpoints and TTL live in a `netdev_priv` the walk cannot
reach through adjacency; and the outer *route* is chosen by the tunnel's
transmit path, not by the flow's own FIB lookup, so a second lookup in the
adapter could disagree with the one the frame will actually take. One walk, one
truth. What the adapter does with the record, in `ft_tunnel_hop()`, is check it
against the tunnel device it names: the endpoints, the TTL and the traffic class
are that device's configuration, read from `struct ip_tunnel` for `sit` and
`struct ip6_tnl` for `ip6_tnl`, and a record that no longer matches describes a
tunnel changed underneath the flow.

Only a point-to-point tunnel with a fixed remote is a hop at all. 6rd and
ISATAP derive the outer destination from the inner one per packet, an NBMA
tunnel picks it from a neighbour, a `collect_md` tunnel from metadata, and a
FOU/GUE tunnel wraps another encapsulation the insert opcode does not build —
the kernel hook refuses every one of these, so they never reach the adapter.

## The two halves

A connection through a tunnel has separate hardware state for each admitted
direction.

**Egress inserts the outer header.** The direction whose frames leave by the
tunnel is PPPoE-shaped: the walk records the tunnel hop, the encoder emits the
`INSERT_L3_HDR` opcode with the header the tunnel device would have built, and
everything below the tunnel — a VLAN tag, a bridge, even a PPPoE session on the
WAN link — is walked and encapsulated as usual. Its classifier key matches the
physical port and inner 5-tuple, plus fields identifying an unencapsulated
packet.

**Ingress strips it.** The reverse direction arrives on the physical port as an
outer packet addressed to the tunnel's local endpoint. The hardware matches
the inner tuple together with the outer source, destination and protocol,
then removes the outer header. Netfilter describes
this direction with *nothing* — there is no pop action and no dissector key for
a tunnel, exactly as there is none for an ingress session — so the rule for it
is byte-for-byte the rule an unencapsulated flow produces, and only the reverse
destination being a tunnel device says otherwise. The encoder emits
`REMOVE_FIRST_IP_HDR`, which the SDK already carried and CMM already drove; the
description also supplies the receive endpoints, reversed from the tunnel's
transmit configuration. Because the ingress half is the one
Netfilter hides, it is the half most likely to be silently refused, which is
why every hardware case below asserts both directions separately.

The loader appends these fields in C to the physical TCP/UDP classification
schemes. Including the PPPoE receive identity, IPv6 keys are 55 bytes and
IPv4 keys are 56 bytes; SEC's private
tables keep their original keys. The module rejects a loader configuration
with the old physical key sizes. Ordinary flows and inbound NAT-T roots use
the native IP protocol and zero tunnel fields, so an encapsulated packet
cannot borrow an ordinary flow's key.

A 4o6 receive direction owns two hardware matches: next header 4 directly,
and next header 60 followed by a destination-options header whose next
header is 4. This covers Linux's tunnel encapsulation-limit option. The direct
form also checks the inner IPv4 version/IHL byte against the plain header
supported by the native flowtable. Both matches share the tunnel
statistics record, and their flow counters are summed. Each keeps its resource
references until hardware retirement is proved. Other extension chains miss
these entries and return to Linux.

Admission also checks the inbound XFRM policy for the outer remote-to-local
packet. A matching block, a required transform, or a blocking default leaves
receive processing in Linux. An unrelated policy or a plain allow policy
still permits hardware decapsulation. Policy changes retire the old flow
generation and readmission repeats the check.

The ingress half is also the one Linux never offers again by itself. Its tuple
names the port below the tunnel, as the hardware needs, and there the software
fast path sees only the outer packet, which its tuple parser does not accept;
the inner packet the tunnel device delivers arrives on a device the tuple does
not name. Only the egress half's software traffic re-offers the flow, and that
stops the moment the egress half is in hardware. So a refusal of the ingress
half that clears by itself -- a lost RTNL, a hardware key still held by the
connection's previous generation -- retires the whole generation, and native GC
and the next packet readmit both halves, where a direction the fast path
forwards would simply wait for its next offer
([architecture](architecture.md#references-and-directional-resources)).

## What stands in for the neighbour

A tunnel device is `IFF_NOARP` and resolves no Ethernet destination of its own,
so an egress direction cannot take its next hop from a neighbour on the tunnel
the way a routed flow does. The real destination is the *outer* next hop — the
gateway the outer packet leaves for on the device below the tunnel — and the
kernel hook resolves it and its Ethernet address while it walks the outer
route. `ft_neigh_attach()` therefore holds and watches a neighbour on the lower
device keyed on that outer next hop, not on the tunnel; a change to it retires
the flow, and the outer route going away retires it through the route watch,
matched on the *outer* remote in the outer header's family rather than on the
inner destination the tuple names. The inner next hop the tuple carries is a
fiction with a zero address, and nothing watches it.

Before a direction is installed there is nothing to watch, and the outer
address is the one the walk recorded when Linux created the flow: no later
offer of that generation carries a newer one, and Linux never checks it -- it
resolves only the tunnel device's own NOARP neighbour. An outer neighbour still
resolving refuses the direction until its next offer. One that is usable but
names another address than the recorded one would refuse every offer of the
generation, so it is treated as stale, the way a changed source address is:
the generation is retired (`mac_invalidations`) and the next one walks the
path afresh.

One consequence surfaces in the Ethernet mangle words. A tunnel device is
NOARP but, unlike a ppp device, it has header ops and an address — its own
local IP endpoint — so `arp_constructor()`/`ndisc_constructor()` copy that
address into the neighbour's hardware address, and `flow_offload_eth_dst()`
writes its first six bytes into the four mangle words. The adapter requires the
words to be exactly those bytes, zero-padded for a four-byte IPv4 local
address, and takes the real destination from the outer next hop. Requiring the
tunnel's own address rather than ignoring the words is what keeps a future
kernel that starts writing something else there from being silently overridden
— the same discipline the session egress applies to its zero words.

A tunnel over a PPPoE session (6rd or DS-Lite on a PPPoE WAN) meets both
contracts at once, and the tunnel's is the one that holds: the words are the
tunnel's local address, because the route leaves by the tunnel, and the
session's zero words never reach the adapter. The check therefore follows the
tunnel whenever there is one, and the session only when it is outermost. The
destination is the concentrator either way: a ppp device resolves no neighbour
at all, so the outer next hop the kernel walked is the session's far end, and
its Ethernet address is the one the session records.

## What the hardware cannot reproduce

The outer IPv4 header carries no don't-fragment bit. This is a limitation of
the `INSERT_L3_HDR` opcode, not a choice: measured on the DK, the microcode
fills the outer fragment field itself and ignores the template's, so a header
built with DF still leaves the port without it. The legacy owner met the same
wall and hardcoded `Flags_FragmentOffset` to zero in `M_tnl_build_header`; this
matches it. The tunnel device's own `pmtudisc` setting therefore reaches the
wire only for frames the CPU forwards, which is the same behaviour CMM shipped
for years. The kernel hook still records the tunnel's DF as a property of the
path, and the adapter keeps it on the rule for completeness, but nothing
reproduces it — stated here rather than left as a silent divergence.

The outer TTL and traffic class *are* reproduced, from the tunnel's
configuration, with one refusal each. A TTL of zero means "inherit the inner
packet's hop count", which the insert cannot compute — it writes the header it
is given — so a tunnel configured that way is refused to software. A `sit`
tunnel set to inherit the inner TOS is refused for the same reason; an
`ip6_tnl` tunnel has a microcode flag for inheriting the traffic class and is
allowed. A tunnel inside an IPsec transform, or a transform inside a tunnel, is
refused: nothing here proves the opcode order a stacked encapsulation needs.

## The outer header, and the mode

The header the hardware inserts is built by the same `tnl_build_header()` the
legacy tunnel interface builds its own with, so both owners put the same bytes
on the wire, and the per-packet fields — the IPv4 length, identification and
checksum, the IPv6 payload length — are the microcode's to fill. The size it
returns has to be the one admission derived from the device, or the two would
be describing different headers.

The mode follows from the device and is checked against the flow's family. A
`sit` device inserts an IPv4 header around an IPv6 packet (6o4); an `ip6_tnl`
device in `ipip6` mode inserts an IPv6 header around an IPv4 one (4o6). Those
two are what the microcode's `INSERT_L3_HDR` builds, by its `TYPE_6o4` and
`TYPE_4o6` selectors. An IPv4 flow through a `sit` device would be IPv4 in
IPv4, and an IPv6 flow through an `ip6_tnl` device IPv6 in IPv6; neither is a
header the hardware builds, so a family that does not match the device's mode is
refused.

## The MTU

Netfilter's MTU for a tunnelled flow is the tunnel device's own, already reduced
by the outer header, and the microcode compares the size of what it *transmits*
— the outer frame — against the limit it is programmed with. Programming it with
the reduced inner MTU would fail every full-size frame, matching it, excepting
it to the CPU and forwarding it in software while every counter said the flow
was offloaded — the defect the IPsec increment measured at 0.07 Gb/s. So the
egress direction is programmed with the tunnel MTU plus the outer header size,
which is the arithmetic the legacy owner's tunnel-interface path in `devman.c`
already did. The full-MTU case below is the proof: a datagram that exactly fills
the tunnel MTU is carried in hardware rather than excepted.

A 6o4 egress direction is IPv6 into a path smaller than an ordinary LAN, and
the microcode would fragment the outer packet of an oversized one where Linux
sends the inner Packet Too Big. It is admitted only while the LAN's IPv6 MTU
is no larger than the tunnel's ([ipv6.md](ipv6.md#packets-larger-than-the-path)),
so the rig sets the LAN's IPv6 MTU to the tunnel's, the configuration a 6in4
LAN wants anyway. A 4o6 egress direction other than TCP stays in software
from an Ethernet LAN whatever its MTU, because the microcode's IPv4 fragments
of a received frame carry no payload
([architecture.md](architecture.md#native-context-and-admission)).

## Per-tunnel-device counters

The firmware counts bytes and packets into a record the two opcodes name, and
the adapter holds one such record per tunnel device — a plain record, the kind a
VLAN device gets, not the timestamped kind a session's opcodes read. The strip
counts into its receive half and the insert into its transmit half, so one
record describes the tunnel device rather than either flow, and `ip -s link
show` on the tunnel device includes what the hardware forwarded through it,
restated into the inner-packet bytes the device itself counts.

The framing to restate was measured on the DK, not inferred. With a 104-byte
inner packet on an untagged path, the strip's record read 118 bytes per frame
and the insert's read 138. A tunnel device counts the inner packet alone on
both sides, so the receive overhead is `ETH_HLEN` — the strip counts the
Ethernet header and the inner packet but not the outer header it removed — and
the transmit overhead is `ETH_HLEN` plus the outer header, the whole frame the
insert put on the wire. A tag or a PPPoE session under the tunnel adds its own
bytes to both, by the same reasoning the VLAN and session records follow. The
record is one per device and serves both directions, so each half's framing is
named from the side that feeds it, and where the two sides' under-tunnel stacks
differ the first direction admitted publishes, exactly as a session's record
does. `/proc/cdx_flowtable` carries `tunnel_records`/`tunnel_slots` in the
header and one `tunnel` row per device, keyed on the same `dev/mode:local>remote`
string the flow rows carry in `in_tnl=`/`out_tnl=`, so the two can be joined.

## Eligibility

Beyond the rules a routed flow already satisfies:

- The device must be a `sit` or `ip6_tnl` tunnel with a fixed remote, and its
  mode must match the flow's family: 6o4 for an IPv6 flow through `sit`, 4o6 for
  an IPv4 flow through `ip6_tnl`.
- The outer endpoints, TTL and traffic class the walk recorded must match the
  tunnel device's configuration, and the outer destination must be a routable
  unicast address with a resolved neighbour on the device below.
- The TTL must not be zero (inherit), and a `sit` tunnel must not inherit the
  inner TOS; the hardware writes the header it is given.
- The four Ethernet mangle words must be the tunnel's own local address,
  zero-padded, and the destination is taken from the outer next hop.
- The device below the tunnel must share the egress port's MAC address, the
  rule every logical device satisfies, imposed here on the device the outer
  packet actually leaves by.
- A tunnel and an IPsec transform may not appear on the same flow.
- The outer receive packet must be allowed by inbound XFRM policy without a
  transform.
- A tunnel the kernel's walk crossed but the adapter's did not reach is refused
  rather than dropped from the description, which would forward with no outer
  header at all.

## Verification

`tools/tests/test_flowtable_security.py` verifies on the DUT that correct
6o4 and 4o6 replies increment hardware counters, while changing only the outer
source, destination or encapsulation protocol produces neither delivery nor
hardware counter increments. It exercises 4o6 both directly and with
destination options. It also changes inbound XFRM policy after offload,
checks block, ESP requirement, blocking default and device selectors, then
checks recovery and policies that permit hardware forwarding.

Host-side, `tools/host_tests/flowtable.c::test_tunnel` compiles the production
decoder against a simulated kernel and covers a 6o4 and a 4o6 tunnel on each
side, both directions, a tunnel over a VLAN device, over a bridge and over a
PPPoE session, and the declined paths — a mode that does not match the family,
a TTL of zero, an inherited TOS on `sit`, endpoints that do not match the
device, a tunnel plus an SA, a hop the walk crossed but the adapter did not
reach, and the outer neighbour not resolving. `test_tunnel_stats` covers the
record ownership and the measured framing; `tools/host_tests/tunnel_hm.c`
pins both header manipulations against the shipped SDK header, including the
insert word's mode, size and IP-identification start, and the flow-described
statistics index the opcodes take from the description rather than from a
registered interface.

On hardware, `tools/tests/test_flowtable_tunnel.py` runs LAN VM → DUT → tunnel
→ orchestrator, with a real `sit` or `ip6_tnl` tunnel on both ends. Every
routed case captures the outer frames the DUT put on the wire and reads the
header back — the endpoints, protocol 41 or next header 4, the TTL, a correct
IPv4 checksum, the inner hop count decremented once, and the absence of DF —
which the counters alone cannot show:

| Case | Both modes | Evidence beyond the counters |
| --- | --- | --- |
| Routed UDP | yes | 64 hardware packets per admitted direction (4o6 upload stays in software); tunnel identity and captured outer header match the device's configuration, DF absent |
| Full-MTU datagram | yes | a datagram filling the tunnel MTU is carried in each admitted hardware direction, so the microcode's size check counts the outer header |
| TCP | yes | half a megabyte on one connection with both directions in hardware and the cookies unchanged |
| Reconfigure under load | 6o4 | `ip tunnel change` of the TTL retires the flow through the link watch, and the flow readmitted afterwards carries the new TTL on the wire |
| Delete under load | yes | deleting the tunnel device retires both directions and leaves the bindings up, so the next flow is judged against whatever tunnel exists then |
| Over a PPPoE session | yes | `test_flowtable_pppoe.py::test_flowtable_pppoe_tunnel`: the insert carries the outer header, the session header and the WAN tag, the strip removes all three; the outer frames reach the concentrator's ppp device, which only a frame addressed to it and to this session does; one session and one tunnel record, each held by both directions |

Both directions of both modes offload at the path's line rate: measured LAN VM
→ DUT → tunnel → orchestrator over four TCP streams, 6o4 ran 9.15 Gb/s
inserting and 9.14 Gb/s stripping, 4o6 ran 9.14 and 9.08, each at low single-
digit DUT CPU with the ports' software receive counters flat. That is the same
ceiling the delivered NAT and IPsec measurements reached, so a paired CMM boot
would only confirm a tie at line rate; it was not run. All of it on the KASAN
image, with the adapter's error, fatal and quarantine counters at zero
afterwards.

## What this does not carry

**The don't-fragment bit**, as above: the offloaded outer header never carries
it, matching CMM, so the tunnel's pmtudisc reaches the wire only for
CPU-forwarded frames.

**Routed multicast through a tunnel**, which is a different learner against the
same encoder and is not built.

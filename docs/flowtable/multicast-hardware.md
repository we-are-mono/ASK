# Multicast Ethernet preservation in hardware

Investigation status, 2026-09-22: hardware tests establish that multicast
entries qualified by the original Ethernet addresses can preserve those
addresses while inserting the required VLAN. Both IPv4 and IPv6 support the
larger key, including two entries for the same IP stream with different
source MACs.

Production status, A191: bridged groups now use this mechanism. See
[Production integration](#production-integration) at the end for the table
plan, the key, the ingress tags and what the rig asserts. The sections before
it are the investigation that justified it, kept as written.

This qualifies the original single-pass design in
[multicast.md](multicast.md). Producing the requested VLAN
stack and delivering the UDP payload is insufficient evidence of correct
bridging. The Ethernet addresses and IP hop count must survive too.

## Relevant NXP documents

These references use document titles, revisions and printed page numbers so
they remain useful independently of where a local PDF copy is stored.

| Document | Relevant material | Implication |
| --- | --- | --- |
| *BHR ASK Programmer's Guide for LS1012_LS104x_LS102x*, Rev. E, July 2019 (`BHR_ASK_Programmers_Guide_for_LS1012x_LS104x_LS102x_RevE.pdf`) | Section 10.6.1, p. 105; Tables 47–48, pp. 106–108 | Advertises multicast VLAN handling and routing/bridging modes. The API description does not specify the LS1046A ASK opcode sequence needed to preserve Ethernet addresses. |
| *Layerscape Linux Distribution POC User Guide*, Rev. L6.1.1_1.0.0, 10 May 2023 (`Nxp_document.pdf`) | FMan header manipulation, pp. 534–535; Tables 107–108, pp. 634–635 | Generic insertion and removal accept explicit byte offsets. Editing at Ethernet offset 12 can change a VLAN tag without replacing either MAC address. |
| Same guide | Frame Replicator, pp. 549–550 | Standard FMan manipulation may precede the entire replication group or follow its last member; arbitrary manipulation after other members is unsupported. |
| *LS1046A Reference Manual* (`LS1046ARM.pdf`) | FMan reference material | Refers detailed DPAA operation to the separate DPAA reference manual. It does not provide the missing ASK action implementation. |

The ASK statistics, QoS and release-note PDFs provide useful background but
do not document an Ethernet-offset parameter for the custom `INSERT_VLAN_HDR`
operation. The multicast mode field advertised by the programmer's guide is
not consumed by the vendor LS104x multicast encoder. Treat that guide as
evidence of intended behavior, not proof that this encoder implements it.

## Code and wire evidence

The multicast root and listener builders in `cdx/cdx_ehash.c` use ASK actions
stored in external-hash entries. The ordinary path strips Ethernet at the
root, inserts the listener's VLAN stack, and writes a literal Ethernet header
containing the egress interface MAC. A bridge cannot use that literal source:
successive packets of the same IP `(S,G)` may have different source MACs.

The bridge/routing distinction now suppresses TTL or hop-limit decrement for
bridged groups. It does not by itself fix Ethernet rewriting.

A diagnostic image built with kas/BitBake and KASAN exercised six action
sequences on the DUT. The WAN sent untagged frames; the configured LAN
listener required VLAN 289. Twelve marked frames per sequence alternated two
source MAC addresses while retaining the same IP `(S,G)`. The LAN captured
raw frames in promiscuous mode and reconstructed any VLAN removed by its NIC.
Both IPv4 and IPv6 produced the following results:

| ASK sequence | Wire result for all 12 probes |
| --- | --- |
| Ordinary Ethernet strip, VLAN insert, literal Ethernet insert | Correct VLAN and hop count 64; source MAC replaced by the DUT's egress MAC. |
| Retain Ethernet; omit VLAN edits and literal Ethernet insertion | Both original MACs and hop count preserved; still untagged, so not a valid solution for this listener. |
| Retain Ethernet; `STRIP_ALL_VLAN_HDRS`, then `INSERT_VLAN_HDR` | Four bytes prepended before the original destination MAC; malformed Ethernet. |
| Retain Ethernet; `STRIP_L2_HDR`, then `INSERT_VLAN_HDR` | Same malformed Ethernet. |
| Retain Ethernet; only `INSERT_VLAN_HDR` | Same malformed Ethernet. |
| Retain Ethernet; `STRIP_L2_HDR`, no insertion | Both original MACs and hop count preserved on these untagged inputs. |

Each sequence added 12 root matches. For IPv4, the malformed prefix was
`01 21 08 00`: TCI 289 followed by the IPv4 EtherType. For IPv6 it was
`01 21 86 dd`. This is consistent with `create_vlan_ins_hm()` encoding TCI and
the inner EtherType for insertion at the current frame start. The outer TPID
is normally supplied later by the literal Ethernet insertion.

These are diagnostic results, not passing recovery tests. Omitting VLAN
validation or the required output tag would violate the bridge's contract.
An installed entry or a rising root match counter also does not prove that
the firmware completed forwarding: a later validation action can send the
matched frame to Linux. Tagged-ingress probes require CPU-path evidence in
addition to the received frames and root counters.

The reverse-direction probe confirmed that distinction. It sent VLAN 289
from the LAN toward an untagged WAN listener. The ordinary encoder and both
strip variants delivered all 12 marked frames with the original source MACs,
but a DUT capture saw every probe enter Linux and leave its WAN interface.
All six variants still added 12 root matches. The two variants without any
strip/validation action had no CPU sightings and no WAN reception; the bench
upstream is not configured to carry that output tag. Those results do not
establish successful hardware tag removal.

There is a corresponding ingress-description gap: the bridge learner knows
the membership VID, but `cdx_mc_group_spec` carries only a physical input
device and the listeners' output tags. The root route is zero-initialized and
names that physical interface, so its validator receives no ingress VLAN or
PVID description. That explains the tagged frames matching the root and then
falling back. A fix must carry ingress acceptance separately from egress
framing. Simply disabling validation is unsafe because the hardware hash key
does not include VID.

## What the original ASK release establishes

The original CDX 5.03.1 source supplies a useful preservation pattern in
`cdx_ehash.c::add_l2flow_to_hw()`: it copies the received destination and
source MAC addresses into both the ordinary bridge match key and the literal
output Ethernet header. `fill_bridge_actions()` can therefore strip and
rebuild Ethernet around a VLAN edit without changing those addresses. A
different source MAC cannot match that same rule.

The original multicast path does not implement that invariant:

- DPA app 4.03.0's `files/etc/cdx_pcd.xml` extracts IP source, destination and
  protocol for multicast, with the ingress port added by the ASK key
  generator. It does not extract either Ethernet address.
- `cdx_ehash.c::fill_actions()` strips Ethernet before replication, and
  `fill_mcast_member_actions()` always rebuilds it. The listener header comes
  from `devman.c::dpa_get_out_tx_info_by_itf_id()`, which selects the egress
  port or bridge MAC as source.
- The multicast command structures carry `mode`, and CMM 17.03.1 forwards it,
  but CDX 5.03.1's `dpa_control_mc.c` never reads it. The advertised bridging
  mode is not a hidden switch that enables preservation in this encoder.

These source files and the DPA configuration were checked against the
supplied release archives. The firmware package contains a binary and its
license, not the implementation of its actions or key comparison.

The resulting approach is to qualify bridge multicast entries with both
original MAC addresses, retaining the full IP source and group as well.
Each matching entry could then rebuild Ethernet with its exact original
addresses using the existing VLAN and replication actions. Matching only the
multicast destination MAC would be insufficient because multiple IP groups
can map to the same MAC.

There is credible host-side support for the larger key. The original SDK's
`fm_ehash.c::ExternalHashTableSet()` copies `matchKeySize` into the table and
firmware descriptor; `ExternalHashTableAddKey()` hashes and compares the
supplied byte count. `fm_ehash.h` permits up to 56 key bytes. The multicast
table category is still `L3_TABLE`, however, and the binary firmware might
impose assumptions not visible in these sources. The source inspection alone
therefore justified an experiment; compatibility evidence comes from the
hardware results below.

The key generator orders known fields according to its hardware field IDs,
not their order in the XML. In the current SDK, `fm_kg.h` and the ordering
logic in `fm_kg.c` give the proposed layout as ingress port, destination MAC,
source MAC, source IP, group IP and protocol: 22 bytes for IPv4 or 46 for
IPv6. Appending MAC bytes to the existing software key would not match that
layout.

## Verified hardware proof: match the original MAC addresses

KASAN diagnostic images built with kas/BitBake and staged before boot paired
the larger key with matching key-generation fields and table lengths. The
first test retained the existing forwarding actions to isolate key matching;
the second enabled literal reconstruction with the matched source MAC.

For each family and each reconstruction mode, twelve marked packets tested
each of: the installed key, a changed source MAC, a changed destination MAC,
a changed source IP, a changed group IP, and the installed key again. Every
changed key was selected to share the installed entry's configured 8-bit
hash bucket. IPv4 and IPv6 each produced 48 positive hardware matches across
both modes, all with wire delivery and no DUT CPU observations. Every
negative window produced zero root matches and was observed by Linux. With
preservation enabled, every positive frame retained both MACs, VLAN 289 and
TTL/hop-limit 64. These bucket collisions alone are not full-CRC64 collision
tests or exhaustive testing of every key byte.

A stronger test then changed only the source and destination MAC addresses
while keeping the ingress port, IP addresses and protocol unchanged, and
solved for an identical complete CRC64. Independent bit-by-bit recomputation
confirmed the collision: `25c7f05782908982` for IPv4 and `54de3e86216e8840`
for IPv6. For each family, twelve original packets matched in hardware,
twelve colliding packets produced zero matches and twelve software
transmits, and twelve original packets matched again. Positive windows had
no CPU observations. All wire frames retained the actual injected MACs,
IP addresses, VLAN 289 and hop count. This rejects both a hash-only match
and a match based on the full hash plus only the IP fields for these cases.

The next test installed two keys with identical ingress port, destination
MAC, source IP, group IP and protocol, differing only in source MAC. Both
keys deliberately shared a bucket: 199 for IPv4 and 222 for IPv6. Each had
its own listener chain and literal source MAC. The diagnostic used two
logical multicast group aliases with the same destination MAC, overriding
only the second root's group IP, to exercise these exact hardware keys
without pretending the production learner already supports MAC variants.

For both families the three windows produced:

| State | Primary root matches | Secondary root matches | Correct wire frames | Software transmits |
| --- | --- | --- | --- | --- |
| Both entries installed | 12 | 12 | 24 | 0 |
| Secondary withdrawn | 12 | 0 | 24 | 12, all from the secondary MAC |
| Secondary reinstalled | 12 | 12 | 24 | 0 |

All wire samples had the expected unique window/sequence, original MACs,
VLAN 289 and TTL/hop-limit 64. Captures reported zero drops. Independent
review recomputed the buckets and checked both the wire samples and DUT
packet captures. This establishes coexistence, selective withdrawal and
reinsertion of these hardware entries; it does not establish production
membership ownership or automatic learning of MAC changes.

A supported implementation would also need bounded MAC variants beneath one
logical multicast membership, learning of new variants after the first
hardware installation, coherent replacement and retirement of all their
listener chains, and a scheme/table plan that preserves routed multicast.
The diagnostic source parameter was global and changed only between completed
entry installations; a production implementation must carry immutable
observed addresses through the learner and backend instead. The existing
shared table cannot mix short and extended key layouts. The
tagged-ingress acceptance/PVID gap described above remains a separate
requirement; MAC qualification does not fix it.

These tests cover UDP, one physical ingress, untagged input and one tagged
listener. They do not establish multiple-listener behavior, allocation-fault
recovery, capacity, complete payload integrity or sustained throughput.

## Why the generic FMan API is not a direct substitution

The generic manipulation interface is present in the SDK, but the ASK kernel
changes the classifier underneath it:

- `FM_PCD_HashTableSet()` creates ASK external-hash tables.
- `FM_PCD_CcRootBuild()` interprets CC child handles as `en_exthash_info` and
  copies their ASK descriptors into the root. A standard match-table handle
  is a different type and cannot safely be passed through that path.
- ASK hit entries contain the custom action list; no documented action jumps
  to a generic manipulation node. External-table miss actions do not provide
  such a handoff either.
- Root modification is explicitly unsupported for these ASK roots.

Generic offset insertion in the manual therefore proves a FMan capability,
not that the current ASK firmware/classifier combination can reach it.
Reserved fields in custom action parameters are not a documented offset API.

## Alternative hardware proof: generic insertion through an offline port

If the extended multicast key is unsupported, the proposed compatibility
test for generic manipulation uses a separately owned offline
port, with a standard result descriptor and no parser or key-generation
dependency (`CC_ONLY`). First prove direct enqueue of an intact, independently
owned frame, then attach a
generic insertion of four bytes at offset 12 and verify both changing source
MACs and the complete resulting frame. This needs explicit support for a
standard root; the existing ASK root cannot be overwritten or supplied a
different handle type.

If that succeeds, an integration could retain ASK admission and replication
and enqueue affected copies through the offline port. A classifier keyed by
the saved dequeue FQID could select each listener's generic VLAN edit and
final physical transmit queue. This would avoid the standard Frame
Replicator's per-member manipulation restriction.

Two facts must be proved before implementing that design as a supported
backend: the loaded ASK firmware must still execute standard CC/manipulation
descriptors, and replicated copies must permit independent header edits
without corrupting another listener's frame. The ASK guide describes zero-copy
multicast, and the generic manipulation API provides no copy-on-write
guarantee. Inspect replica FD/SG buffer ownership before attempting concurrent
edits; descriptor copying alone does not establish private packet headers.
Then validate isolation,
resource exhaustion, withdrawal/drain, module lifetime, multiple listeners,
IPv4/IPv6, tagged/untagged ingress and egress, and acceleration under load.
The offline pass adds hardware work per affected copy and needs measurement.

No software-fallback policy has been selected as part of this investigation.

## Production integration

A191 turned the proof into the bridged learner's path. What it adds, piece by
piece:

**Tables of their own, behind the routed ones.** A table cannot mix key
layouts, and a routed group cannot be keyed on MACs: the upstream router's
address is not in the MFC entry. So `cdx_pcd.xml` gains `cdx_bridged_mcast4_cc`
(22-byte key) and `cdx_bridged_mcast6_cc` (46 bytes). Their distributions list
`ethernet.dst`, `ethernet.src`, the source, the group and the protocol. In
every policy they come right after the routed multicast distributions. The key
generator selects the first distribution in policy order whose protocols a
frame has. fmc gives the policy's first distribution the lowest scheme id,
which the host-mode model dump confirms. So the routed ones match every
multicast frame first. The bridged ones are reached only as the routed tables'
miss, which `cdxdrv_set_miss_action()` points at them. Their miss then goes to
the Ethernet table, as the routed tables' used to. This is the pattern the
3-tuple UDP tables already follow behind the 5-tuple ones. A routed group's
ingress is never a bridge port and a bridged group's always is, so no frame
is a candidate for both. fmc numbers classification groups in reverse policy
order, so Ethernet, PPPoE and the two 3-tuple tables keep groups 0 to 3; the
soft parser's PPPoE path counts from that base. A configuration without the
new tables still loads: the routed miss falls back to Ethernet, and a bridged
group cannot then be installed.

**Types.** cdx indexes a port's tables by the type `dpa_cfg_publish()` publishes, so the
bridged tables take the two 3-tuple TCP slots the vendor reserved and nothing
creates (`IPV4_BRIDGED_MULTICAST_TABLE`, `IPV6_BRIDGED_MULTICAST_TABLE` in
`cdx_ioctl.h`). The kernel reads a table type only to choose the microcode
class, and these are multicast (L3) tables, the class the proof ran in. So
the kernel builder hands `FM_PCD_HashTableSet()` the multicast types for them, and no
kernel patch changes.

**The key and the rebuild.** `fill_mcast_mac_key()` composes port id,
destination MAC, source MAC, source, group and protocol, the order the key
generator extracts them in. Each listener is drawn from its port's bridged
table. It rebuilds Ethernet with exactly the pair its root matched
(`struct cdx_mc_member_frame`, applied after the interface walk), behind the
listener's own tags. The hop count is untouched, as before.

**Ingress tags.** `cdx_mc_group_spec` names the tags a group arrives with
(`in_vlan`, `in_vlans`). The root's `STRIP_ALL_VLAN_HDRS` validates and
strips exactly those, the way a flow's root does. An untagged stream, which
is what a port's PVID gives the group's VLAN, is validated as untagged. The
key names no VLAN, so the same key tagged differently on the same port is
excepted to Linux rather than replicated as this group's. The routed learner
now passes its parent VIF's tags too. Before that, a VLAN-device parent had
its root expect an untagged frame and never carried its stream.

**Streams.** The traffic hook records each frame's MAC pair and whether it
carried the group's VLAN as a single 802.1Q tag. It does not learn from
anything a root cannot validate: a second tag, a tag in another protocol, or
a tag on a bridge that does not filter, which forwards it intact. An installed
entry keeps its key while it carries traffic. A five-second refresh reads each
entry's counter. An entry idle for a whole interval reopens the hook, and a
stream seen then takes the key over. That covers a sender whose MAC changed, a
source that moved, and the same stream arriving on another port. Two live
senders do not trade one entry. A bridge VLAN change re-derives every group
on that bridge under RTNL: listener tags, listeners that left the VLAN, and
whether the ingress shape still resolves to the group's VLAN.

**What the rig asserts.** `flowtable_service_multicast_bridge.py` reads
the replica's frame, not just its datagram, in both directions:

- `flowtable_service_multicast_bridge.py::test_keeps_the_sender`: untagged in on
  the WAN port, tagged out to the LAN listener. The source MAC is the
  sender's, the destination is the group's MAC and the hop count is unchanged.
  The classifier counts at least 95% of the frames and the ingress CPU sees at
  most 10%. A second sender MAC then takes the key over once the first goes
  idle, with the same assertions for the new sender.
- `flowtable_service_multicast_bridge.py::test_tagged_ingress`: tagged in on the
  LAN port, out of the WAN port to the orchestrator's wire. The same
  assertions hold, and the `/proc` row names the ingress tag.

Not established by these: MAC-variant capacity beyond one stream per
membership, and bursty streams near the idle interval.

## Routed copies in a bridged group

A188 carries a stream that is both bridged and routed as one bridged group
([design](multicast-routed.md#one-stream-both-learners)). Its root is the
bridged one: MAC-keyed, validating the ingress tag, and preserving the hop
count, because most of its copies are bridged. The routed copies therefore
carry what a routed root would have done for them in their own listener
entries:

- `create_member_hop_hm()` emits `UPDATE_TTL` (IPv4) or `UPDATE_HOPLIMIT`
  (IPv6) as the entry's first opcode, while the frame still starts at its IP
  header — the root stripped Ethernet, and every insert after it moves the
  start. The opcode's parameter word is the DSCP marking a flow's conntrack mark
  can request; a replica has no mark, so it is written zero, which is what a
  routed root with no mark writes.
- The backend frames the copy as a router's: the address of the VIF ipmr sends
  it through as the source and the group's mapped address as the destination
  (`cdx_mcast_group_mac()`), not the matched pair. `struct cdx_mc_listener`
  says which copies are routed and names each one's address (`src_mac`), which
  is its port's own only when the VIF is the port; `struct cdx_mc_member_frame`
  carries the per-copy pair into the entry builder, which writes it over the
  port's address the interface walk filled in. Every copy of a routed group is
  framed the same way.

**This is unproven on hardware and is the first thing to measure.** Every
replica edit measured so far is a prepend: VLAN and Ethernet inserts, which the
A158 run showed are private to each copy. An L3 edit in a member entry is new.
The ASK guide describes zero-copy multicast, and nothing here establishes
whether a replica's IP header is its own or shared with its siblings. If it is
shared, a routed copy's decrement would reach the bridged copies too, or a
second routed copy would decrement twice. The rig case
`flowtable_service_multicast_bridge.py::test_bridge_and_route` is the discriminating
test: the bridged copy must arrive with hop count 64 and the routed one with
63, both whole, in one window. If it fails that way, the fallback is a refusal
rather than a redesign — `ft_mc_carriable()` would refuse a group with both
kinds of copy — and the entry falls back to what A188 replaced: the stream
carried in software.

Two smaller properties rest on existing behaviour rather than new measurement.
A frame arriving with TTL 1 is bridged by Linux but not routed; the parser ends
the parse for TTL 0 and 1 before any table is consulted, which is what makes a
routed root's decrement safe, and a merged group depends on the same thing. And
the counters folded into the MFC are the bridged root's, which counts each
frame once however many copies it makes.

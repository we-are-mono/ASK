# IPsec cross-SA forwarding provenance

Restoring an SA-bound forwarding decision without abandoning hardware offload.

## Status

**Known, accepted limitation** (ISSUES.md **A280 / A287**). The shared offline-port
classification restored by the A276 revert (`cdx: revert per-SA offline-port
classification`) keys a decrypted flow's forwarding entry on the inner tuple alone,
so a hardware forwarding hit does not prove *which* inbound SA decrypted the packet.
This matches how CMM / CDX-5.03.1 shipped. It is accepted for now because the only
mechanism that closed it — per-SA classification with an enqueue-FQID extraction —
is exactly what wedged the FMAN host-command channel (A276) and corrupted oversized
IPv6-in-ESP ICVs.

This document is the research for a *future* fix: a way to bind the hardware
forwarding lookup to the authenticating SA that does **not** use the FQID extraction.
It is a **credible hardware-preserving prototype, not a validated fix.** Nothing here
was compiled, programmed, or run on hardware.

## 1. The boundary that must be enforced

### 1.1 The vulnerable path today

```
Peer B's authenticated ESP packet
  -> SEC executes inbound SA B
  -> shared IPsec offline port (fman0-oh@2) receives the decrypted packet
  -> inner tuple matches an entry admitted under SA A
  -> hardware forwards without Linux checking B against A's policy
```

The attacker needs no legitimate overlapping selectors: a malicious authenticated
peer B can construct an inner packet with A's exact source, destination, protocol and
ports. Distinct assigned inner subnets do not prevent that forgery — the attacker
chooses the inner tuple. Software admission proves A's flow was allowed *under A*; it
does not prove a later packet that hits A's entry was authenticated *under A*.

### 1.2 The required invariant

For every post-decryption hardware forwarding hit:

```
the SA proven by the successful SEC operation
    == the inbound SA authorized when the forwarding entry was admitted
```

The identity must come from gateway-controlled execution context. A packet-supplied
inner address, an outer SPI read without binding it to the successful operation, a
packet mark, or an unmodified Ethernet address cannot establish it. The hardware must
still reject authentication, replay and other SEC failures — a tag on an output
buffer is not, by itself, evidence of successful authentication.

### 1.3 Two entry kinds need protection

The offline port carries both decrypted-inbound TCP/UDP forwarding entries and
encrypted-outbound ESP/NAT-T transmission roots. Fixing only the TCP/UDP keys is
incomplete: an authenticated peer can choose inner ESP or UDP/4500 contents and match
an outbound root. For a VPN-to-VPN gateway (`decrypt under A -> entry sends to
outbound SA C -> encrypt under C`), the plaintext entry needs A's provenance and the
encrypted-output root needs proof of C's output context; using C's identity for the
first lookup would be wrong.

## 2. Evidence in the current tree

Anchors are repository-relative (line numbers locate, not bound, the code).

- **Queue routing already knows the SA.** `cdx/dpa_ipsec.c` `create_ipsec_fqs()`
  configures each SA's `FQ_FROM_SEC` to the common IPsec offline-port channel, with
  Context A enabling FQID override + the A1 SEC-error check and Context B supplying
  the SA's `FQ_TO_CP` exception queue (`cdx/dpa_ipsec.h` context-override flags). This
  per-SA identity is used for software exception processing, not for the successful
  forwarding lookup.
- **Admission selects shared tables.** `cdx/cdx_dpa_ipsec.c` `cdx_ipsec_fill_sec_info()`
  sets `ipsec_inbound_flow` and gets the offline-port table via `dpa_ipsec_ofport_td()`
  with no SA discriminator. `cdx/cdx_ehash.c` `fill_key_info()` builds a tuple key, not
  SA provenance. `cdx/ask_flowtable.c` `ft_ipsec_paired_inbound()` selects the inbound
  SA and checks its policy at *admission* — necessary, but not a discriminator on later
  hardware hits.
- **Outbound roots also live on the offline port.** `cdx/cdx_dpa_ipsec.c`
  `cdx_ipsec_add_classification_table_entry()` installs outbound ESP/NAT-T roots there;
  `fill_ipsec_key_info()` / `fill_natt_key_info()` build those keys. Any fix must review
  all of them, plus NAT-T sharing and SPI preemptive checks.
- **SEC already emits a 14-byte Ethernet prefix.** `cdx/cdx_dpa_ipsec.c`
  `cdx_ipsec_build_shared_descriptor()` copies `bytes_to_copy` through the input FIFO to
  the output (`seq_fifo_load -> move(INFIFO->OUTFIFO) -> seq_fifo_store`), with
  `bytes_to_copy = ETH_HDR_LEN` (14) at SA creation. The copy precedes the protocol
  operation, so anything written there is gateway-generated context whose authorization
  is conditional on the SEC-error gate — not intrinsic proof of authentication.
- **Routed forwarding rebuilds Ethernet.** `cdx/cdx_ehash.c` includes inbound-IPsec in
  the header-operation condition; the normal action strips the old L2 header and
  `create_ethernet_hm()` builds the real egress MAC pair before enqueue. This supports
  using the temporary prefix as an internal carrier — but every output path
  (outbound-SA, exceptions, fragments, errors, tunnels, replication) must be checked to
  confirm the carrier is removed.
- **Software exceptions retain the real SA lookup.** `cdx/dpa_ipsec.c` (~exception
  handler) fetches the XFRM state from the exception context, fixes the EtherType, calls
  `eth_type_trans()` and creates an unverified secpath, leaving Linux to validate the
  receiving policy. A source-MAC carrier is length-neutral, but software can still
  observe Ethernet bytes; the design must not silently change a firewall predicate.

## 3. Why simply restoring the reverted code is wrong

Historical commit `11aa150` (reverted by `1bb1d60`) used the SA's TO_CP FQID as the
identity and appended it to decrypted-flow keys via `<nonheader source="fqid">`
extraction, also changing outbound ESP/NAT-T keys (14 -> 21 of 32 schemes). Note it was
**shared schemes with SA-distinguished entries, not a full table set per SA** — per-SA
cost is not linear.

The revert records two hardware failures tied specifically to the **enqueue-FQID
extraction**:

1. Exception/miss traffic strands an offline-port task; retained TNUMs starve the shared
   FMAN task pool and host commands fail-stop (A276).
2. Oversized IPv6-in-ESP fragmentation produces an incorrect ICV.

The A276 investigation (the revert commit `cdx: revert per-SA offline-port
classification` and ISSUES.md A276) found that direct-DONE miss steering and CC-removal
experiments did *not* remove the wedge, while removing the FQID extraction did. This is
sufficient to reject blindly restoring `11aa150`.

The historical exploit oracle
(`11aa150:tools/tests/test_flowtable_service_ipsec_binding.py::test_forged_inner_packet_under_a_second_sa_is_not_delivered`)
should be restored in intent even if its mechanism and host tests change completely.

Also note `sdk_fman/.../fm_kg.c` `GetGenCode()` maps parser-result **and** FQID
extraction to the same `KG_SCH_GEN_PARSE_RESULT_N_FQID` (FQID adds offset 32). So a
parser-result stamp shares the generic extraction source with FQID and does not, on its
own, prove the wedge is avoided. The prototype below deliberately uses an ordinary
**header** extraction (`ethernet.src`) instead, which is a different KeyGen path — but
that too must be proven on hardware (see Q4).

## 4. Preferred prototype: gateway-stamped Ethernet source identity

### 4.1 Carrier

Use the 6-byte source-MAC of SEC's temporary Ethernet prefix as an internal identity:

```
destination MAC (6): preserve current behaviour
source MAC (6):      gateway-assigned processing-context identity
EtherType (2):       preserve existing family handling
payload:             unchanged inner plaintext / encrypted output
```

The identifier denotes a specific hardware SA installation *including its
direction/context kind*. It is not a real MAC, SPI, subnet, or permanent peer identity.
A 32-bit allocation id is only illustrative — size it from lifecycle/reuse needs, not
the software handle width.

### 4.2 Write it through SEC

Modify the L2-prefix output construction so the source bytes come from gateway-owned
descriptor data rather than the incoming frame; preserve destination + EtherType for
the parser and exception path. The exact CAAM sequence is unresolved (FIFO moves, DECO
math-register loads exist, but ordering, FIFO consumption, automatic-info-FIFO
behaviour and later-command register use must be established). Do **not** DMA into
uninitialised headroom or a second buffer without a documented per-job address/ownership
contract, and do **not** change the shared PDB state-store ordering to gain words. The
tag is usable only *after* the existing SEC-error gate proves success; error frames
(including returned input FDs) must never reach tagged forwarding hits.

### 4.3 Extract it as an Ethernet field

Define offline-port keys combining ordinary `ethernet.src` extraction with the existing
protocol tuple. `dpa_app/files/etc/cdx_pcd.xml` already uses `<fieldref
name="ethernet.src"/>` in other distributions, so the vocabulary exists. Use *shared*
offline-port schemes/tables where each entry carries its own authorised identity; keep
Ethernet RX schemes unchanged so physical traffic can't enter the same authorization
domain via a synthetic MAC. The software key encoder must reproduce the actual generated
extraction order — `cdx/cdx_common.h` warns Ethernet fields can precede IP fields
regardless of XML declaration order, so appending bytes in C without checking the scheme
is unsafe.

### 4.4 Protect every output context

Encode the admitted inbound SA installation for plaintext decrypted flows, and the
outbound processing context for encrypted-output roots (a complete design may need to
stamp outbound descriptors too — a real budget constraint, see §5). Handle NAT-T shared
roots explicitly: sharing a UDP tuple and dispatching on SPI must not silently combine
entries with different authorization context. Do not assume inbound-only stamping makes
every ESP/NAT-T root safe.

### 4.5 Remove or restore the carrier

Normal routed forwarding already strips/rebuilds the real egress MAC pair — confirm for
every action combination (VLAN, PPPoE, VPN-to-VPN). Outbound roots must reconstruct the
Ethernet header and remove the identity before wire transmission. Software exceptions
must preserve MAC-sensitive semantics: if the original source MAC is needed, its storage
and retrieval need a separate mechanism — the six overwritten bytes are not recoverable
from the tag. Fragments must validate both classifier identity and final header
reconstruction.

### 4.6 Failure behaviour

Missing / malformed / unexpected context must miss to the correct software exception
path or drop — never fall through to an untagged table that can forward the same tuple.
A legitimate first-packet miss to Linux is fine; relying on software for *all* packets
would fail the "retain hardware forwarding" objective.

## 5. Resource and compatibility accounting

- **Key widths fit.** Packed IPv4 TCP/UDP tuple = 14 bytes, IPv6 = 38
  (`cdx/cdx_common.h`); +6 source-MAC gives 20 / 44, both under the 56-byte external-hash
  key limit (`patches/kernel/010-ask-fman-dpaa-ehash.patch`). This proves the two keys
  fit the format — not the generated extraction order, unit availability, or performance.
- **Action space.** `cdx/cdx_ehash.c` rounds the key to 4 bytes before the action
  region; IPv4 16->20 and IPv6 40->44 each consume 4 more action bytes. The entry need not
  grow, but every maximum-action combination (NAT, encap, QoS, stats, tunnel) must still
  fit. A newly refused combination is a loss of offload even at unchanged entry count.
- **Cumulative packing.** SDK `fm_ehash.c` `ExternalHashTableAddKey()` aligns cumulative
  keys to 8 bytes (>4-byte keys): IPv4 16->24, IPv6 40->48. Larger keys may increase
  chained records/allocations/DMA under collisions. **Fixed entry size is not proof of
  unchanged capacity** — measure at full-capacity, random *and* adversarially-colliding.
- **SEC descriptor budget.** `cdx/cdx_dpa_ipsec.c` refuses `desc_len >=
  MAX_CAAM_SHARED_DESCSIZE`; comments report 48-word worst-case outbound CBC/CCM and
  45-word GCM under the current builder. Outbound tagging near that limit is an immediate
  risk. Do not silently refuse near-limit SAs and call it "all capability retained"; do
  not restore the old extended-descriptor path without solving its state-ordering.
- **Throughput.** Replacing source-MAC bytes adds no length, but can add descriptor
  commands, wider extraction, and cumulative reads — no unchanged-throughput claim until
  measured.

## 6. Identity lifetime

Tie identity reuse to demonstrated hardware retirement, not software SA deletion:
reserve id + owner -> build descriptor/queues -> publish only matching entries -> admit
traffic only once descriptor/queue/classifier are coherent -> on rekey/policy change,
withdraw dependents and stop new admission -> prove classifier unlink + SEC completion +
queue retirement before releasing/recycling. Overlapping rekey SAs need distinct
identities (sharing reqid/peer/SPI/handle does not justify reuse). Failed unlink must
retain identity + reachable resources with fail-stop/quiescence if a revoked entry could
still be hit — this is the same retirement gap ISSUES.md tracks for IPsec roots, and it
must be fixed in the implementation, not bypassed with a new allocator. Define wrap
behaviour; refuse unsafe reuse.

## 7. Alternatives

| Alternative | Assessment |
| --- | --- |
| Restore enqueue-FQID extraction | Reject — recorded wedge + fragmentation evidence |
| **SEC-stamped source MAC + header extraction** | **Preferred prototype**; concrete carrier, unresolved descriptor/exception/resource details |
| SEC-written output scratch/headroom | Possible; per-job addressing/init/parser-access unproven |
| Parser-result stamp | Writer/provenance unresolved; shares FQID's generic extraction source |
| Dequeue-flow-ID indexed CC stage | SDK exposes primitives; no scalable design established |
| Separate classifier resources per SA | May isolate, but risks losing SA/flow capacity |
| Per-SA hardware inner-selector validation | Only sufficient if it enforces every boundary incl. overlap; none implemented |
| Decrypt in hardware, all plaintext to Linux | Closes the bypass but loses forwarding throughput — fails the objective |
| Rely on distinct assigned inner subnets | Does not stop malicious inner-source forgery |

A microcode repair of FQID extraction could preserve the old architecture, but no
source-level firmware fix / erratum workaround was established, and firmware source may
not be available or safe to modify.

## 8. Validation gates (for the eventual authorized change)

Run after the current suite, on a separately-identified image and an attended,
recoverable rig. Record exact git/image/module/firmware/parser identities.

- **A — format/descriptor:** enumerate the full supported SA matrix; record descriptor
  word counts before/after; verify stamp bytes/order/uniqueness both directions; confirm
  FIFO consumption + output lengths unchanged; confirm replay/PDB stores intact; inspect
  generated KeyGen extract order/sources/offsets/masks/key sizes; demonstrate no
  enqueue-FQID extraction remains; exercise max-action + cumulative packing.
- **B — actual SA provenance:** install A + B; warm A in hardware; send B-authenticated
  packets with A's exact inner tuple; require B's decrypt counter to advance, zero forged
  delivery, no forged increments of A's entry, A still accelerated. Repeat across outer
  peers, same peer different SPI/reqid, distinct + overlapping selectors, IPv4/IPv6,
  UDP/TCP, native ESP/NAT-T, tunnel/transport. Include wrong-key/wrong-ICV/replay so the
  carrier cannot bypass the SEC-error gate. The vulnerable shared implementation must
  *fail* this oracle.
- **C — other offline-port hits:** forge inner ESP + NAT-T UDP under B matching an
  outbound root; require zero wire emission / root hit; exercise A->C forwarding incl.
  NAT + rekey; multiple SPIs on one outer UDP tuple; prove outbound uses its own context.
- **D — exceptions/fragments:** ICMP, first packet, gateway-local, unsupported protocols,
  options/EH, fragments, MTU exceptions; compare software Ethernet metadata / packet type
  / secpath / firewall to today; capture egress and require real MACs (no synthetic
  carrier on the wire); oversized IPv6-in-ESP + hairpin with peer-side ICV; every miss
  retires the offline-port task.
- **E — wedge/control-plane:** shared-sequence >=3x on one boot + the single-ping-after-
  warmup reproducer; flood exception classes while adding/deleting flows/SAs and running
  host-command barriers; check confirmations/queue progress/errors/quarantine (HTTP
  reachability is insufficient); do not weaken HC fail-stop.
- **F — retirement/rekey:** overlap old/new + rapid same-tuple rekey; inject failure
  before unlink and after-unlink-before-sync (different states); delay SEC/queue
  retirement during new installs; require no id/FQID reuse while old work is reachable,
  no stale forwarding, no cross-hit.
- **G — capacity:** every currently supported SA/config still accepted; fill full
  capacity incl. 16,384 connections with *accelerated* entries; IPv4/IPv6 mixes, many
  SAs, duplicate inner tuples across SAs, NAT-T/NAT/VLAN/PPPoE/QoS; random + colliding
  keys; measure cumulative allocations/chains/memory/insertion failures and
  throughput/loss/latency/CPU before/after; multi-hour churn with bounded retained memory.

## 9. Unresolved questions

1. Shortest valid CAAM sequence to replace only the copied source MAC without disturbing
   the IPsec protocol FIFO state?
2. Does it fit every supported inbound descriptor, and any outbound descriptors needed?
3. Can the exception path preserve MAC-sensitive semantics without another carrier/storage
   dependency?
4. **Does ordinary `ethernet.src` extraction on post-SEC output avoid both recorded
   firmware failures (miss wedge, fragmentation)?** — the load-bearing unknown.
5. Actual cumulative-packing + worst-action costs at full capacity?
6. Which complete scheme prevents decrypted ESP/NAT-T from hitting outbound roots while
   supporting VPN-to-VPN forwarding?
7. What publication/retirement mechanism proves an installation identity is safe to
   reuse, including after unlink failures?

Until these are answered the honest conclusion is **credible hardware-preserving
prototype**, not **capacity-preserving fix proven viable**.

## 10. Expected implementation touchpoints

`cdx/cdx_dpa_ipsec.c` (descriptor stamping, identity, ESP/NAT-T keys, action-path
review) · `cdx/dpa_ipsec.c` + headers (queue/identity lifetime, exception
restoration/validation, error preservation) · `cdx/cdx_ehash.c` + shared structs
(authorized-context encoding, exact extraction order, action-space checks) ·
`dpa_app/files/etc/cdx_pcd.xml` or C-created PCD (shared header-extraction schemes,
table sizes, fallbacks) · `dpa_app/dpa.c`, `cdx/dpa_cfg.c`, `cdx/devoh.c` (table
recognition, publication, miss steering) · `cdx/cdx_ipsec_backend.c`,
`cdx/control_ipsec.c` (retirement contract, owner retention, failure propagation) ·
host + DUT tests (encoder/layout/lifetime + real wire-level isolation, wedge, capacity).

Merely adding a C field and appending it to a key cannot work unless the hardware
extracts matching bytes.

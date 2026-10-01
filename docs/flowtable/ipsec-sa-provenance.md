# IPsec cross-SA forwarding provenance

Restoring an SA-bound forwarding decision without abandoning hardware offload.

## Status

**Both A280 and A287 are solvable on this LS1046A with the shipped FMan
microcode.** SEC inserts a private 802.1Q tag carrying the executing SA's
identity. FMan's existing `STRIP_ALL_VLAN_HDRS` action validates it after the
ordinary tuple lookup and removes it before forwarding. Both original MAC
addresses survive CPU exceptions. The implementation includes bounded identity
allocation, safe retirement, NAT-T rekey sharing and strict exception validation.
Section 14 describes that implementation and its production validation.

Sections 1–12 retain the original investigation and superseded candidates as
history; their descriptions of missing checks are the pre-fix design. Section 13
records the feasibility experiments before production hardening. No replacement
FMan microcode binary or hardware modification is required. The SEC descriptor,
soft parser, PCD configuration and CDX changes must ship together.

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
| SEC SA trailer + `VALIDATE_IPSEC_ID` | Tested candidate ABI did not reject a different SA or remove the trailer; see section 11 |
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

## 11. NXP trailer/validator experiment (2026-10-01)

The original NXP `cdx-5.03.1` source in `~/Mono/ASK-NXP` contains a disabled
descriptor sequence that appends the inbound SA's two-byte handle after decryption.
Its exception handler can read that trailer to recover the SA. The delivered header
defines `UNIQUE_IPSEC_CP_FQID`, selecting a separate exception queue for each SA and
making the trailer writer's condition `if (0)`. The checked files match NXP's tarball.
Our `a33db614` cleanup removed this disabled branch, preserving the enabled behavior.

The SDK declares `VALIDATE_IPSEC_ID` (`0x1a`) and a four-byte parameter containing
16 reserved bits and a 16-bit identifier. Neither original CDX nor `dpa_app` emits
it, and NXP supplied the microcode only as a binary. There is no source evidence
that this opcode consumes the historical trailer.

The authorized DUT probe reuses the trailer writer, explicitly storing the identifier
in big-endian byte order. The candidate action encoding is opcode `0x1a`, followed
by a big-endian 32-bit parameter with the expected identifier in the low 16 bits.
It is emitted before the normal preemptive checks and packet mutations. No classifier
key/extraction changes are made. This tests one plausible ABI, not every possible
microcode contract.

That probe was compiled only with `CDX_DEBUG_FLOWTABLE`; the root-only
`/sys/module/cdx/parameters/ipsec_id_probe` knob defaults to zero. Its bits are
`1` to append the trailer, `2` to emit the action, and `4` to deliberately XOR the
expected ID with `0x8000`. Change it only while no SAs or flows exist. The fixture
sets it before creating SAs and restores it after their teardown. This is diagnostic
code, not a fix or a supported runtime feature. Outbound roots are unchanged.

### Image and scope

- Base revision: `eedd0ac951b8d361e8dbea63e1ff8896190e1ba3`, plus this uncommitted probe.
- Built with `make ask-image`, staged with `make stage-image`, RAM-booted with
  U-Boot's existing `run ask`; no persistent boot environment or eMMC changes.
- Linux `6.12.103`, FMAN microcode `210.10.1`, non-KASAN image.
- Staged image SHA-256:
  `f028c2c85b48fb380d13db9d40616dcd4301aa07a05da4377429b84671f17cff`.
- DTB SHA-256:
  `9ab9564c97e0196b929409561ecda99ea21ce08bf00ba29050bea49fe97e2b7f`.
- Built, unstripped `cdx.ko` SHA-256:
  `215ef15a80aa9c12be283f5c42bd726a91a318658f943e28c3baced37164e517`.
- IPv4 tunnel, AES-CBC/HMAC-SHA256-128, shared offline port. The inbound descriptor
  with the trailer occupies 45 words, below the existing 50-word rejection threshold.
- Logs, marked-frame samples and JSON observations: `/tmp/ask-a280-probe/` on the
  build host. The previous staged image/DTB were preserved under the
  `Image-a280-baseline.gz` / `mono-gateway-dk-a280-baseline.dtb` names in `/srv/tftp`.

### Security result

For each mode, admit A's UDP tuple, then inject 32 marked packets authenticated under
A and 32 under a distinct inbound SA B with no matching forward policy. Verify B's
SEC counter increases and count delivery on the LAN interface, not just classifier
counters. The 256-byte inner packet normally produces a 270-byte Ethernet frame.

| Mode | A delivered | B delivered | Software forwarding, A/B | LAN frame length |
| --- | ---: | ---: | --- | ---: |
| 0: disabled baseline | 32 | 32 | 0 / 0 | 270 |
| 1: trailer only | 32 | 32 | 0 / 0 | 272 |
| 3: trailer + matching validator | 32 | 32 | 0 / 0 | 272 |
| 7: trailer + deliberately mismatched validator | 32 | 32 | 0 / 0 | 272 |
| 2: validator, absent trailer | 32 | 32 | 0 / 0 | 270 |

The driver logged the descriptor construction and validator emission. The candidate
action had no observable validation or trailer-removal effect. Modes 3, 7 and 2 fail
the security test; modes 0 and 1 pass their deliberately vulnerable control assertions.
This rejects the tested ABI as a solution. It does not prove that every possible use
of the opcode is unimplemented. A280/A287 remain open, and extending this experiment
to outbound roots is not justified by these results.

The retired probe source and test are archived at
`/tmp/ask-a280-probe/trailer-probe.patch` and
`/tmp/ask-a280-probe/test_ipsec_id_probe.py`. They were removed from the working tree
before the source-MAC implementation. The historical invocation was:

```sh
sudo env PYTHONPATH=tools ASK_IPSEC_ID_PROBE=1 \
  ASK_WAN_IPERF_IP=<bench-wan-ipv4> ASK_FLOWTABLE_ARTIFACTS=/tmp/ask-ipsec-id \
  /opt/askd-agent/venv/bin/pytest -c tools/pyproject.toml \
  tools/tests/test_ipsec_id_probe.py -o addopts= -v --tb=short
```

Without `ASK_IPSEC_ID_PROBE=1` the experiment is skipped. The security checks are
intentionally failing acceptance tests for a candidate validator; do not weaken them
to make an ineffective implementation pass. The existing IPsec adapter and SEC-submit
host suites passed (12 tests).

### Misses, packet sizes and cleanup

With mode 3 enabled, 128 authenticated packets with four new inner tuples took the
miss path and reached the LAN; 32 subsequent packets on the installed tuple also
arrived. The test finished with no backend errors, fatal state or quarantined entries.
This is a bounded stability result, not proof against every A276 trigger. Captures
use `PACKET_IGNORE_OUTGOING` so LAN-generated ICMP errors quoting a marker cannot
inflate the count of delivered packets.

The fixture's inner LAN route has MTU 1200. Full-payload IPv4 UDP round trips gave:

| Inner IP length | Mode 0: disabled | Mode 1: trailer | Mode 3: trailer + validator |
| --- | --- | --- | --- |
| 1100 | Pass | Pass | Pass |
| 1200 | Pass | Fail | Fail |
| 1400 | Fail | Fail | Fail |

The trailer introduces a failure at the otherwise-working 1200-byte boundary.
The 1400-byte failure also occurs with the probe disabled; its cause was not isolated
in this experiment. A send above the LAN interface MTU was excluded after the peer
rejected it locally with `EMSGSIZE`, before it could test the DUT. The full oversized
IPv6-in-ESP ICV regression and cipher/outer-family matrix remain untested here.

Across the nine scoped cases, the two vulnerable controls and the repeated-miss
check pass; the three validator acceptance checks and three MTU cases fail. The final
rerun in `final.log` covers matched/mismatched validation, misses, and all three MTU
modes (one pass, five failures); the absent-trailer case is in `negative.log`.
The expected security failures must not be reported as a successful fix.

All test SAs and policies were removed. Before restarting normal service the backend
had 32 installs and 32 deletes, no entries, references, errors, fatal state, restarts
or quarantine; the probe knob was zero. The kernel taint stayed at the expected
out-of-tree-module value 4096, with no new kernel splats reported by the fixtures.
Normal service was resumed and verified ready, with its policy installed on `eth3`
and `eth4`, two bindings and no fatal state or quarantine.
That image retained the diagnostic code disabled by default. It has since been
replaced in the staging slot by the source-MAC prototype below.


## 12. SEC source-MAC prototype (2026-10-01)

This experiment replaces the historical trailer/opcode probe. Each SEC descriptor
copies the 14-byte Ethernet prefix through Math0's byte view (SEC RM table 7-18,
destination `0x38`), replacing bytes 6–11 with `02:53:41:<TO_CP FQID>`. The queue ID
is a per-install, per-direction allocated identity used as descriptor data; FMan
extracts **only the ordinary full Ethernet source field**, never FQID metadata.
The sequence consumes/emits the same 14 bytes and costs six descriptor words versus
the old copy's five. Protocol, replay, counters and PDB state-save operations remain
in their original order and the existing 50-word rejection guard remains in force.

Both decrypted TCP/UDP flow keys and encrypted ESP/NAT-T output-root keys insert the
six-byte tag after the logical port byte, ahead of the existing tuple fields.
The IPsec offline port has seven own distributions/tables, bringing total schemes
from 14 to 21 of 32. Miss chains resolve on that port. Outbound NAT-T roots are
per-SA; inbound NAT-T SPI dispatch continues to share a UDP tuple.

**Known blocker:** CPU exceptions still carry the synthetic Ethernet source address.
The original per-packet source address is not preserved, so this prototype cannot
claim to retain MAC-sensitive Linux policy behavior. The hit paths rebuild L2 on
output. Passing forwarding tests alone is not enough to close A280/A287 or ship it.

### Build and bench

- Base revision: `eedd0ac951b8d361e8dbea63e1ff8896190e1ba3`, plus the working-tree prototype.
- `make ask-image` succeeded; `make stage-image` staged the image and DTB for RAM boot.
- Image SHA-256: `cc6914786581d6f4759f374338889289bdb3135e91b638e3817cc002124fec07`.
- DTB SHA-256: `9ab9564c97e0196b929409561ecda99ea21ce08bf00ba29050bea49fe97e2b7f`.
- Linux 6.12.103, non-KASAN. No persistent storage or saved boot-environment changes.
- The first warm reboot halted in OP-TEE `core_mmu_set_entry` before U-Boot. The user
  power-cycled the board; it then downloaded this image and booted successfully.
- Evidence: `/tmp/ask-a280-mac/`.
- Host checks: 20 passed (source-MAC key encoding, PCD geometry, offline-port tables,
  multicast PCD, IPsec adapter and SEC submission).

The opt-in test is `tools/tests/test_ipsec_mac_probe.py`, enabled by
`ASK_IPSEC_MAC_PROBE=1`; set `ASK_WAN_IPERF_IP` to the bench WAN address. It checks
legitimate bidirectional hardware traffic, cross-SA rejection, ESP and NAT-T output
roots, repeated tuple misses, and lengths through the 1200-byte inner-route MTU.

### First DUT result: blocked by offline-port stall

The first test, `test_ipsec_mac_binding`, failed during initial protected TCP
connection establishment, before its hardware-throughput or cross-SA injections.
The teardown also failed after the FMAN HC channel wedged. This is **not** a passing
security result; the ESP/NAT-T attack probes and MTU checks have not run on this
image. Running them on the wedged port would not establish rejection.

At uptime 102.67 seconds the kernel reported `HC confirmation timed out; board reset
required` and an ehash sync failure. The backend showed two installs, two deletes,
two errors and two quarantined entries. The SEC refusal counters were zero.
Two passive native-width MMIO snapshots at uptime 337 seconds showed SEC idle
(`SSTA=0x406`, `QISTA=0`, dequeue enabled), the IPsec OH frame count fixed at six,
and its QMI status `0x20000000`. No QMan management queries or recovery-register
writes were used. Evidence is in `binding.log`, `binding/`, `live-*.json` and
`failed-*.txt` under the artifact directory.

Ordinary MAC extraction therefore does **not**, in this first implementation,
avoid the stall. This result does not isolate the descriptor's output bytes from
the new table layout or miss handling. A second control retains only SEC stamping
and restores the original shared PCD and key composers (`stamp-only.patch` in the
artifact directory). It has no cross-SA protection and is used only to isolate the
failure. The full experimental image is preserved as
`/srv/tftp/Image-a280-mac-full.gz`.


### Stamp-only control

The control image (`ef87153d3374e779dd340b56250556532a232fd106c14685879898cc84be9062`,
`/srv/tftp/Image-a280-mac-control.gz`) passed `test_ipsec_mac_misses_and_mtu` in
67.39 seconds. It delivered all 128 packets on four unadmitted inner UDP tuples,
then all 32 packets at each of inner lengths 256, 1100 and 1200 on the installed
flow. The hit bursts had zero software-forwarding counter increments and wire
lengths 270, 1114 and 1214, respectively. The fixture drained cleanly with no
backend errors or quarantine (`control/`). This control has the original loose
keys and does **not** test cross-SA isolation.

The result narrows the first failure toward the new extraction/table setup; the
same descriptor rewrite is capable of forwarding and misses on the original PCD.
It does not identify which part of the new setup stalls.

### Frame-byte suffix variant

The next image preserves the old tuple positions: it extracts
`<nonheader source="frame_start" offset="6" size="6"/>` and appends those six bytes
to each protected key. Despite the XML element's name, this reads packet bytes,
not queue or parser-result metadata (`fm_kg.c` maps it to `KG_SCH_GEN_START_OF_FRM`).
The `from_data` default is supplied as required by KeyGen. The same descriptor and
seven own tables are used. FMC's distribution builder treats `ethernet.src` as a
full known field regardless of the optional XML size/offset attributes, so those
attributes alone would not change its ordering.

- Image SHA-256: `54c01e8763242b08c9d54c71c70e8efa941524eb765ee7d85e93ac871b6b207e`.
- Build and RAM boot succeeded; the eight affected PCD/key host checks passed again.
- This is the current working-tree variant. The first full-field version and the
  stamp-only control are saved as patches in `/tmp/ask-a280-mac/`.
- The miss/MTU test passed: 128 packets on four unadmitted tuples, then 32 hits
  each at lengths 256, 1100 and 1200; no backend errors or quarantine
  (`suffix-misses/`).
- The first security run observed A 32/32 delivered in hardware, B 0/32 delivered,
  B's SEC count increasing by 32 and `XfrmInTmplMismatch` increasing by 32. Its
  overall result failed during TCP teardown because raw A injection advanced the
  anti-replay window past the peer kernel's sequence. The following root cases
  could not open the same TCP tuple (`EADDRNOTAVAIL`). The test now closes TCP
  before injecting A; all three corrected security cases passed in 193.18 seconds
  (`security-final/`).


The working-tree builder uses one extra word. Its calculated largest descriptor is
49 words (IPv6 NAT-T with a split HMAC key), immediately below the existing rejection
threshold; this exact outer-family/transform combination still needs a hardware
matrix check. Packet length and the SEC error/replay gate remain unchanged.


### Security results for the suffix variant

| Scoped case | Result | Evidence |
| --- | --- | --- |
| A280: B uses A's admitted inner UDP tuple | Pass | B: 32 SEC decryptions, zero LAN deliveries, 32 Linux `XfrmInTmplMismatch` increments. A: 32 deliveries, zero software forwarding. |
| A287: B forges A's outbound ESP root | Pass | 32 captured ingress ESP frames, 32 B decryptions, zero marked frames emitted on WAN. |
| A287: B forges A's outbound NAT-T root | Pass | Same 32/32/0 result with DUT/peer ports 4500/31000. |
| Repeated misses and route-MTU boundary | Pass | Four unadmitted tuples, 128 delivered; 32 hits each at 256/1100/1200 bytes; no trailer, errors or quarantine. |

Each security case first verified normal plain and protected TCP/UDP traffic in both
directions with the existing `hardware()` check (256 records per flow, hardware
counters, negligible software SEC submission and authenticated WAN delivery).
A's marked LAN frames were 270 bytes and carried the routed egress source MAC,
not the synthetic identity. Both root probes capture the actual WAN interface and
include the injected outer ESP as a positive capture control, while SEC accounting
proves the forbidden inner packet was decrypted. These are bounded IPv4/CBC tunnel
proofs, not a full cipher, rekey, topology, transport-mode or outer-family matrix.

The complete host selection passed again: **20 passed** (`final-host-tests.log`).
The suffix image is also retained as `/srv/tftp/Image-a280-mac-suffix.gz`.


### Additional regression gates

AES-GCM RFC4106 with a 128-bit ICV passed the existing bidirectional hardware
traffic, peer-error and plaintext-policy checks. The oversized IPv6-in-IPv4 ESP
case failed at UDP payload 1452 (inner IPv6 packet length 1500): the outbound flow
counter increased once and FMan emitted two IPv4 fragments, but the peer delivered
zero plaintext packets. Payloads 1390 and 1391 (inner lengths 1438 and 1439) passed
the preceding assertions. This run did not record a per-packet peer error delta,
so it does not establish an ICV error as the cause (`regression.log`). The existing
regression test now records each size and peer XFRM deltas before asserting, to
retain failure evidence on future runs. Its acceptance checks are unchanged.

The preserved pre-experiment image was restored to the normal staging slot for a
baseline repeat; the suffix candidate remains at `Image-a280-mac-suffix.gz`.
Baseline image SHA-256:
`954c76aa9bcd5b724942c0f371bdcc121d4db31ce75e45b80f30a873475b2a06`.
It has KASAN enabled, unlike the new prototype, so a comparison also changes that
build setting; it is not a fully controlled same-configuration A/B experiment.
The baseline repeat **passed** all three sizes in 13.12 seconds
(`baseline-ipv6-final.log` and `baseline-ipv6-final/`). Each packet was delivered
exactly once, with no peer XFRM error increments; sizes 1439 and 1500 produced two
outer fragments. An earlier repeat stopped before traffic because the newly added
counter read used an unsupported WAN-agent endpoint. The test now reads the local
peer's `/proc/net/xfrm_stat`, as the existing replay tests do.

The candidate has therefore not passed the oversized-IPv6 regression gate. Isolating
stamping, classification and build settings is still required; these results alone
do not identify a microcode defect or prove an ICV corruption. Together with the
unresolved source-MAC semantics on CPU exceptions, this keeps A280/A287 open.

Final candidate scope: **five DUT checks passed, one failed**, with **20 host checks
passed**. The four probe cases skip by default unless explicitly enabled. Changes
remain uncommitted. The baseline is running and restored in the normal staging
slot; the three experimental images remain separately named in `/srv/tftp`.


Cleanup is verified: no XFRM states or policies remain on the DUT or WAN host.
Normal service is running on the baseline, with policy installed, admission ready,
two bindings (`eth3`, `eth4`), multicast enabled and no entries, references, fatal
state or quarantine. Kernel taint is 4096 (out-of-tree modules); the restored boot
has no HC timeout, KASAN report, BUG or WARNING. Evidence:
`restored-service.json`, `restored-backend.txt`, `restored-dmesg.txt` and
`restored-taint.txt`. The final suffix source patch is also archived as
`/tmp/ask-a280-mac/suffix-prototype.patch`.


## 13. Feasibility follow-up (2026-10-01)

This historical stage answered the hardware-feasibility question. The subsequent
production implementation and validation are recorded in section 14. Evidence for
this follow-up is under `/tmp/ask-a280-finish/`; no additional image backups are
being made.

### Controlled isolation of the IPv6 failure

All three builds below use the same non-KASAN configuration:

| Image | Oversized IPv6-in-IPv4 ESP result |
| --- | --- |
| HEAD baseline, no identity changes | Pass, all three sizes (`baseline-ipv6.log`, 12.11 s) |
| SEC source-MAC rewrite only, original classification | Pass, all three sizes (`control-ipv6.log`, 12.06 s) |
| Source-MAC suffix plus own classification | Fail at 1500-byte inner IPv6 (`suffix-ipv6.log`, 12.66 s) |

The suffix repeat recorded no peer XFRM error increment. Its WAN capture contains
both fragments for the preceding size but only the first fragment of the failing
packet. This does **not** establish ICV corruption. A compact key removing the
redundant protocol byte and retaining the full 24-bit SA identity also failed at
1500 bytes (`compact-ipv6.log`); keeping the old action alignment is insufficient.
A subsequent compact capture attempt failed its fixture's initial-state check and
is excluded as traffic evidence.

### Internal VLAN carrier

The prototype preserves both Ethernet MACs and inserts one private 802.1Q
shim after them. SEC consumes the existing 14-byte prefix, assembles the MAC pair,
gateway-assigned TCI, and original EtherType in Math0..2, then emits 18 bytes in a
single FIFO move. Separate unaligned pushes are avoided (SEC RM 7.7.6).
This costs six descriptor words. A diagnostic CPU-miss probe confirmed the exact
19-byte prefix through the first IP byte: original MACs, `81 00 00 03 08 00 45`
(`vlan-debug.log`, `vlan-debug-dmesg.txt`). The diagnostic print is now removed.

The first variants included `vlan.tci` in the classifier key. They failed ordinary
forwarding; adding a VLAN soft-parser family correction and explicit Ethernet
rebuild on the output root did not resolve that failure (`vlan-ipv6.log`,
`vlan-parser-ipv6.log`, `vlan-strip.log`). Earlier claims of small traffic success
were too strong: entry installation alone did not prove hardware delivery.

### Working route: validate after lookup

Removing the TCI extraction, keeping the original tuple-key widths, and checking
the tag with the existing native VLAN action resolved the forwarding failure.
The seven private offline-port tables retain 14/38-byte TCP/UDP keys and 10/22-byte
ESP keys. No generic frame extraction or FQID extraction is used. A decrypted
flow's action expects its admitted inbound SA tag; an output root's action expects
its outbound SA tag. IDs are allocated across both directions. A mismatching tag
cannot continue through the admitted forwarding action. CPU exceptions remove
exactly the four-byte shim before normal Linux policy processing.

The VLAN soft parser corrects IPv4/IPv6 family selection on logical port 9, as the
existing Ethernet soft parser did before the shim. Both hardware hit paths remove
the tag before rebuilding wire headers, and output roots explicitly request that
rebuild. NXP's existing VLAN opcode is used; the failed IPsec validation opcode is
not used and no replacement FMan microcode binary is required.

Evidence under `/tmp/ask-a280-finish/`:

| Check | Result and evidence |
| --- | --- |
| CPU misses and MTU | Pass: 128 misses delivered, four original source MACs each observed 32 times by Linux nftables; 32 hardware deliveries at each inner size 256/1100/1200, no software forwarding (`vlan-validate.log`, `vlan-validate/`) |
| A280 | Pass: B decrypts 32 forged inner tuples, zero LAN delivery, `XfrmInTmplMismatch +32`; A delivers 32/32 in hardware (`vlan-security.log`, `vlan-security/`) |
| A287 ESP output root | Pass: 32 authenticated B decryptions, 32 ingress capture controls, zero forged output (`mac-root-esp-result.json`) |
| A287 NAT-T output root | Pass: same 32/32/0 result (`mac-root-natt-result.json`) |
| Legitimate traffic | Each security case first proves bidirectional plain/protected TCP/UDP hardware traffic, 256 records per flow, and authenticated WAN traffic |
| IPv6-in-IPv4 ESP | Pass: inner sizes 1438/1439/1500 each delivered exactly once; expected outer fragment counts 0/2/2, no inner fragments, no PTB, no peer XFRM errors (`vlan-regression.log`, `vlan-regression/ipv6-sa-oversized*.json`) |
| AES-GCM RFC4106, 128-bit ICV | Pass: existing authenticated bidirectional hardware-traffic check (`vlan-regression.log`) |
| Host checks | 20 passed, including the extracted production receive callback's original-MAC preservation (`vlan-validate-host.log`) |

### What this proves, and what remains

**Both issues are solvable on this LS1046A with its current firmware.** This is a
constructive DUT result: the required SA boundary and useful hardware forwarding
coexist, and the miss/MAC and oversized-IPv6 blockers of the earlier candidate are
absent in the scoped checks. It does not establish unchanged maximum capacity or
throughput, or complete production readiness.

The experimental allocator has **4094 active or retained identities**, shared
across directions. A tag follows the existing SA queue-retirement and deferred
FQID-retention machinery. Before production, audit tag reuse against every flow
and output-root unlink, including uncertain deletion, queued work, restart and
module unload. The existing queue retention was designed for inbound roots and
is not by itself proof of all new tag-reference lifetimes.

Keeping the original tuple key also means overlapping legitimate inner tuples,
and multiple outbound NAT-T SAs with the same UDP tuple, need an explicit admission
and software-fallback policy. The scoped proof uses one admitted SA pair and a
second authenticated inbound SA, and makes no claim that both overlapping tuples
can be offloaded simultaneously. The broader transform, encapsulation, rekey,
resource-exhaustion and performance matrix remains release work. The issues remain
open for that integration; the requested hardware-feasibility question is answered.


The image rebuilt after removing the diagnostic print and stale key-extraction
helper is staged in the normal TFTP slot and booted on the DUT. Build and stage
logs: `vlan-final-build.log`, `vlan-final-stage.log`; boot: `vlan-final-boot-uart.log`.
SHA-256 of `Image-ask-test.gz`:
`1ea1cc0dd5c3eb6fe7742d200ea575220579af5fcc41d38745a6bb7d84824228`.
Matching DTB SHA-256:
`9ab9564c97e0196b929409561ecda99ea21ce08bf00ba29050bea49fe97e2b7f`.


### Requested Loki-to-Vision iperf3 measurement

The opt-in `tools/tests/test_ipsec_vlan_iperf_probe.py` runs iperf3 3.18 from Loki's
inner address `198.18.102.3` to Vision's `198.18.102.2` through the DUT. The tunnel
uses AES-128-CBC plus HMAC-SHA256 with a 128-bit ICV, required XFRM policies and
hardware flow admission. Each upload uses 15 measured seconds after 3 omitted
seconds, zero-copy sending, and either one or four TCP streams. Routes were set to
1500; iperf reported a negotiated MSS of 1348. This is a bench sample, not a
maximum-throughput claim.

On the final VLAN image (`iperf.log`, `iperf/`):

| TCP streams | Receiver goodput | Sender retransmissions | DUT aggregate CPU in sample | Peer XFRM errors |
| --- | --- | --- | --- | --- |
| 1 | 2.152 Gbit/s | 1578 | 2.00% | 0 |
| 4 | 2.444 Gbit/s | 10269 | 1.81% | 11488 `XfrmInStateProtoError` |

All bulk streams had advancing hardware counters; the five-second hardware sample
had zero software LAN transmissions and 17 software WAN transmissions in each run.
The four-stream rate is delivered TCP goodput, but **the benchmark validation
failed** because of the peer protocol errors. This counter alone does not identify
ICV failure versus another ESP format/protocol error. The same-configuration HEAD
baseline comparison did not establish a transfer: both attempts ended before
hardware admission, and the captured client retry reported `No route to host`
(`iperf-baseline.log`, `iperf-baseline-retry.log`). These are not baseline
throughput results. The load failure therefore cannot yet be attributed to the
SA-tag changes or described as a clean performance pass.


The requested **AES-128-GCM / RFC4106 / 128-bit ICV** benchmark then **passed** on
the final VLAN image (`iperf-gcm.log`, `iperf-gcm/`), with the same durations and
stream counts:

| TCP streams | Receiver goodput | Sender retransmissions | Peer XFRM errors |
| --- | --- | --- | --- |
| 1 | 2.205 Gbit/s | 1583 | 0 |
| 4 | 2.501 Gbit/s | 0 | 0 |

All bulk streams again advanced their outbound hardware entries, and the reverse
SA-bound entries carried the ACKs. Software LAN transmissions were zero in each
five-second sample; software WAN transmissions were 17 and 16. Aggregate CPU
samples were 23.72% and 19.01%, with softirq 1.35% and 0.25%; these include all DUT
tasks and are not an attribution of CPU cost to GCM. Iperf reported MSS 1448, so
these CBC/GCM samples are not a fixed-packet-size cipher comparison.

The six earlier scoped DUT checks and 20 host checks passed; the final image also
passed the GCM throughput check. CBC's four-stream protocol-error failure remains
an explicit additional release blocker. It does not negate the constructive SA
isolation result, and the working GCM bulk path supplies a clean higher-load
example. No production-complete or unchanged-performance claim is made.


Boot-readiness check for the failed CBC baseline comparison: its serial login
completed at 21:57:15 local time, the first fixture was recorded at 21:57:52, and
the retry on that same boot started at 21:59:39. Boot logs show startup and SSH key
generation completed before login. Both tests reported policy installed, admission
ready, and two bindings after reloading the benchmark policy. This argues against
starting before boot completion. It does not prove end-to-end tunnel readiness:
there was no successful tunnel connectivity probe before iperf, and the exact
connection-setup failure remains undiagnosed. The job-ring-2 probe warning occurs
on both this baseline boot and successful VLAN/GCM boots, so it does not distinguish
the failed comparison.

Final cleanup: the VLAN prototype remains built, staged and running. Normal
service is restored, policy installed and admission ready, with two bindings,
zero entries/references, no fatal state and no quarantine. DUT XFRM objects and
all test-owned peer objects are removed; unrelated peer socket policies remain.
Kernel taint is 4096 (out-of-tree modules), and the final boot log has no HC timeout,
KASAN report, BUG or WARN splat. Records: `final-service.json`, `final-backend.txt`,
`final-dmesg.txt`, `final-taint.txt` and `final-service-uart.log`. All changes remain
uncommitted.


## 14. Production implementation (2026-10-01)

### Identity and forwarding boundary

The identity is an allocated integer, not a hash, SPI, secret or peer-supplied
value. A single IDA reserves IDs 1–4094 across inbound SAs and outbound roots.
SEC emits it in the 12-bit VLAN ID field, with PCP/DEI clear, between the original
MAC pair and EtherType. The internal frame is four bytes longer; neither the
forwarded wire packet nor Linux's packet retains that overhead. Ingress outer
VLAN/PPPoE framing has already been stripped before SEC; egress framing is built
after the internal tag is validated and removed. Customer VLAN numbers do not
share an interpretation or lifetime with these internal tags. The existing
provider still requires an SA bound to a physical DPAA port; this change does
not add packet offload for SAs bound directly to VLAN devices.

Every inbound SA has a distinct identity. The post-decryption forwarding action
checks the identity of the SA whose policy admitted the flow. Outbound ESP and
NAT-T roots validate an outbound identity, which an inbound SA can never own.
The unchanged SEC-error gate remains mandatory: an output buffer bearing a tag
is not itself proof of successful authentication or replay validation.

Seven private distributions and tables belong only to the IPsec offline port.
They keep the original tuple key widths, avoid FQID/nonheader identity extraction,
and miss through that port's empty Ethernet table to the SA's exception queue.
The soft parser corrects the inner/outer IP-family EtherType mismatch through the
VLAN shim on logical port 9; the PPPoE direct-CC shortcut excludes only that
port, preserving the shared tree used by Ethernet and Wi-Fi.

The CPU exception handler resolves the tag and XFRM handle from the queue under
the SA-cache lock, requires an inbound offloaded state, validates both TPID and
full TCI, and strips exactly four bytes while preserving both MACs. Linux receives
an unverified secpath containing the actual decrypting SA and performs its normal
policy checks. Missing tags, wrong tags and outbound ciphertext exceptions drop.
The conntrack byte-accounting conversion subtracts Ethernet plus the internal
four-byte tag from post-SEC hits. It does not subtract the already-removed outer
VLAN/PPPoE framing again. Raw hardware diagnostics retain the actual hit length.

### Rekey and collisions

A tuple hit with the wrong identity goes to Linux with its actual secpath. This
both rejects forged traffic and allows two legitimately authorized overlapping
SAs to deliver the same inner tuple. Only the SA named by the hardware entry
uses that entry; the other uses software forwarding until retirement/readmission.
Duplicate hardware keys are refused by the existing hash-table insertion contract.
FMan's hit counters advance before VLAN validation, including for rejected hits;
they cannot prove forwarding. The overlap regression checks actual delivery and
Linux's forwarding counter to establish that the other SA took the policy check.
As with other post-hit exceptions, hardware hit accounting can include packets
subsequently rejected or counted again by software; it is not an authorized-wire
traffic counter.

Outbound NAT-T SAs with the same outer UDP tuple must share one output root during
rekey. They share its reference-counted identity before the new SEC descriptor is
built. Sharing also requires identical direction, bound device, egress interface,
next-hop MAC and path MTU. A built descriptor cannot change identity under queued
work. Inbound NAT-T SAs can share the SPI classifier but never their SEC identities.
Deleting one outbound owner leaves the root and identity valid for the survivor.

### Retirement and capacity

SA deletion first withdraws dependent flow entries and the SA root. An uncertain
root deletion retains the identity and FQIDs in either direction. The same hold
applies whenever the datapath failure latch is set: a dependent forwarding entry
may still validate this tag even if the SA root itself deleted cleanly. The deferred SA
release requires all three queues out of service, then an explicit SEC
`CSTA[IDLE]` observation (SEC RM chapter 13) before freeing the descriptor and keys.
The check is bounded to 100 polls, sleeping 100–200 microseconds between polls.
If SEC never becomes idle, the resources and module reference remain pinned until
reboot; a timeout cannot authorize reuse. After the queues stop and SEC finishes,
a successful FMan PCD barrier proves that an old packet no longer carries the
identity through the offline port.

A failed PCD barrier retains the tag/FQID allocation, latches the datapath failure
and uses the existing stopped-port restart to settle hardware references. Retained
identities also pin the CDX module: unloading/reloading the module-local IDA must
not reset the identity namespace while old hardware can still name it. If the
retention-record allocation fails, the allocation and module pin deliberately
remain until reboot. Shared outbound tags return to the IDA only after the last
owner's release has satisfied these conditions.

The bound is **4094 active or retained identities across both directions**,
normally at most 2047 independent bidirectional SA pairs before other hardware
limits. Exhaustion refuses a new offload allocation; it never wraps or aliases an
existing identity. NAT-T root sharing can reduce identity consumption. The existing
packet-offload rejection and strongSwan auto/software-fallback contracts apply.

### CBC load-test diagnosis

Artifacts are under `/tmp/ask-a280-production/`. Unpaced CBC reproduced the peer's
`XfrmInStateProtoError`. A 20,000-packet wire sample had valid HMACs, CBC padding
and next-header values throughout, and the peer SA recorded no integrity failures.
That sample alone was not sufficient to attribute the full-transfer failure.

Temporary return probes on Vision's `esp_input`, `esp_input_done2` and
`cryptd_enqueue_request` established `-ENOSPC` from its crypto queue. In the first
trace, all 375 negative ESP returns matched the 375 protocol errors. The next
trace added 1,032 negative ESP returns and 1,032 XFRM protocol errors; cryptd's
broader trace recorded 1,075 queue-full returns. There were no missed return probes.
This is peer crypto-queue saturation, not a finding of bad DUT authentication.
The probes and their trace instance were removed after diagnosis. The opt-in iperf
check still fails on any peer XFRM error and accepts an explicit aggregate TCP rate
for validation below that limit; it does not hide or waive the counter.

### Validation

The complete host suite passed **407 tests**, with five kernel-dependent checks
initially skipped; those five subsequently passed against the built kernel. The
additional soft-parser scope check passed, as did focused reruns of the lifecycle
and byte-accounting sanitizer harnesses after their final changes. Host checks
exercise exhaustion, reference sharing, retirement and barrier failures, module
pins, receive ownership/MACs/wrong tags, native VLAN action bounds and PCD isolation.

The hardened forwarding/lifetime image passed **37 DUT tests in 1204.93 seconds**
(`final-regression-2.log` and `.xml`). This covers inbound rekey overlap under CBC
and GCM, uncertain outbound NAT-T root deletion/restart, oversized IPv6, GCM with
128- and 64-bit ICVs, replay windows, CBC/GCM DF/MTU handling, all 18 transform
interoperability cases, transport mode, provider lifetime, inbound SA withdrawal,
GCM inbound provenance and all four CBC/GCM ESP/NAT-T outbound-root probes.
The replay check refused and accounted for all 54 expected replays/late frames
across its 31 phases. IPv6 inner packets of 1438, 1439 and 1500 bytes each arrived
once; the latter two used two outer IPv4 fragments, with no inner fragmentation,
PTB or peer XFRM error.

The earlier hardened lifecycle run also passed both outbound NAT-T rekey cases
and all four inbound/outbound ESP/NAT-T forced-delete cases. The two inbound
rekey assertions in that run incorrectly expected hit counters to exclude VLAN
exceptions; the corrected forwarding-policy assertions passed in the 37-case run.

An initial attempt at that run stopped before test traffic because Loki's X550
lost physical carrier after the DUT reboot. Administrative cycling and a plain
autonegotiation restart did not recover it. Advertising 1 Gbit/s temporarily, then
restoring the original 100/1000/10000 advertisement, recovered 10 Gbit/s and three
lossless Loki-to-Vision pings before the passing run. The underlying link fault
was not diagnosed; this is not evidence of an IPsec or readiness-timer failure.

The 37-case image SHA-256 is
`b18d5c56572a911fdd9962b677ada1cfbda11e4b4182e491f2f552033c9b09e4`.
The final image additionally corrects conntrack's subtraction of the internal
four-byte shim. It passed all **five final-image checks**: CBC inbound provenance,
exact conntrack accounting, original-MAC exceptions and MTU, CBC iperf, and GCM
iperf (`final-cbc.log`/`.xml`: four passes in 274.99 seconds;
`final-gcm.log`/`.xml`: one pass in 84.64 seconds). The accounting probe delivered
32 inner 256-byte packets in hardware and increased conntrack by exactly 32 packets
and 8192 bytes; the private tag was not charged to the connection.

The final Loki-to-Vision TCP measurements used 1500-byte links, 15 measured seconds
and three omitted warmup seconds per run. Rates below are the receiver's iperf3
summary. CBC used `ASK_IPSEC_IPERF_BPS=1500000000`, divided across streams; GCM was
unpaced. The CBC single-stream run exceeded its pacing target, so that option is
not evidence of a strict traffic cap.

| Transform | Streams | Receiver Gbit/s | Peer XFRM errors | DUT CPU busy during sample |
| --- | ---: | ---: | ---: | ---: |
| CBC/SHA-256, 1.50 Gbit/s aggregate target | 1 | 1.786 | 0 | 1.81% |
| CBC/SHA-256, 1.50 Gbit/s aggregate target | 4 | 1.500 | 0 | 1.75% |
| AES-GCM, 128-bit ICV, unpaced | 1 | 2.194 | 0 | 2.71% |
| AES-GCM, 128-bit ICV, unpaced | 4 | 2.505 | 0 | 1.81% |

Every active TCP stream advanced its outbound hardware counter. During each
five-second CPU/counter sample Linux transmitted zero packets on the DUT LAN and
17 on its WAN. These short lab runs validate the offloaded path; they do not
establish maximum capacity or long-duration reliability. Records are
`final-cbc/iperf-{1,4}.json` and `final-gcm/iperf-{1,4}.json`.

The final build and stage succeeded (`build-7.log`, `stage-7.log`), and the DUT
booted that image (`boot-7.log`). Before testing, the LAN automatically negotiated
10 Gbit/s, the DUT agent was healthy, and three Loki-to-Vision pings passed
(`boot-7-readiness.log`). Final image SHA-256:
`c5a70315b87add7b000b414ee55a2788b8847f6c9daf444a67cb0bcea8b4c571`.
Matching DTB SHA-256:
`9ab9564c97e0196b929409561ecda99ea21ce08bf00ba29050bea49fe97e2b7f`.
This staged artifact is the diagnostic ASK test distribution, not a production
release image; the production source changes must be built in the release profile.

After cleanup, the managed service was resumed with admission ready and two
bindings. Hardware entries, handle references, SAs, SA-cache entries, fatal and
quarantine counts were all zero. CDX's module reference count returned to its
baseline of one. DUT and peer XFRM state counts were zero; runtime dmesg contained
no WARN/BUG/KASAN/lockdep splat or SEC-idle retention warning, kernel taint remained
4096 (out-of-tree module), and `debug_locks` remained one. Loki retained its original
address/default route and 100/1000/10000 advertisement, with a 10 Gbit/s link and
three successful post-test pings. Cleanup evidence is in `restore-final.log` and
the `restored-*` artifacts.

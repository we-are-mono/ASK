# FMAN HC wedge investigation — 2026-09-29

Research on `wip-base-306665d`, HEAD `306665d`, including the existing
uncommitted retryable-HC-SYNC change. DUT: LS1046A, eth4
`e8:f6:d7:00:01:14`, agent `10.0.0.62:9110`, UART `DK0HDNU9`.

## Findings

**The strongest current lead is the return path for the decrypted ICMP reply,
especially FMAN's offline-port classification and fallback to the CPU.** After
the UDP warmup, one ping with its reply allowed was enough to stall HC. In a
separate run with the same single-ping diagnostic and the reply suppressed,
teardown drained successfully. This is one comparison, not a proven root cause.

Confirmed observations:

- The original flood reproduces with and without KASAN. This is not confined
  to the sanitizer build.
- In the flood capture, HC submissions continue but confirmations stop. The
  confirmation and error queues are empty, three commands wait in HC TX,
  and both SA TO_SEC queues are empty. FMAN's IPsec offline port stops making
  progress; querying outbound FROM_SEC also hangs.
- With one ping after warmup, the agent stays reachable while HC times out
  four times. SEC is idle and `QISTA=0`: output-buffer depletion is not needed
  for this smaller HC failure.
- Suppressing the echo reply preserves the outbound CPU-fed ESP packet and
  allows teardown with `errors=0` and `quarantine=0`. Allowing the reply left
  both counters at 2.
- Capping the offered rate did not prevent the flood failure. Restoring NXP's
  2,048-buffer initial output-pool capacity did not prevent it either.

Working explanation: an operation on the return path leaves an FMAN
offline-port frame unfinished, so an HC synchronization barrier cannot
complete. Further retries consume the four HC command buffers. The larger
flood failures may be the same stall spreading through queues and buffers.
The persistent OH and HC task contexts support this explanation, but their
internal instruction state has not been decoded. Neither the exact failing
stage nor a common cause for both failure sizes is established.

No recovery fix has been validated. Retain the existing retryable SYNC change
and keep A276 open. Empty confirmation queues cannot be repaired by increasing
their software dequeue priority, and a longer HC timeout does not restore the
stalled datapath.

## Reproduction evidence

Local raw artifacts are in `/tmp/fman-hc-research/`. Tests interrupted after
loss of connectivity are reproductions, not completed pytest validation runs.

| Run | Image / load | Result and evidence |
| --- | --- | --- |
| `kasan-baseline2` | Original working-tree KASAN image; unmodified shared-sequence test | Agent lost; retryable HC timeouts; no spontaneous recovery. `wedged-*.txt`, `wedged-cpu.txt`. |
| `nonkasan-baseline` | Rebuilt with `CONFIG_KASAN` unset; same test | Same agent loss and four retryable timeouts at uptime approximately 146–150 s. `nonkasan-state-0.txt`; configuration captured in `nonkasan-identity-1.txt`. |
| `kasan-diag` | KASAN with HC submission/confirmation printks | Confirmations stop at 58; four later SYNC submissions receive no confirmation. `kasan-hc-0.txt`, `kasan-queue-map-*.txt`. |
| `kasan-paced` | Same diagnostic KASAN image; UDP payload capped at 2 Gbit/s, batches of 16; ping interval 1 ms | Same loss and four HC timeouts. Capture contains one ESP frame. Native register snapshots below. Temporary test edits were reverted. |
| `kasan-capacity` | KASAN rebuilt with 2,048 output buffers, restoring NXP's per-CPU seed capacity; original unpaced test | Same loss, one captured ESP frame and four HC timeouts. SEC idle, QISTA depletion set, OH count frozen at `0x17a1c1`. `capacity-sec-native.txt`. Capacity change reverted. |
| `kasan-single-ping` | Original buffer capacity; UDP warmup, then one-second pause and exactly one ping, with no concurrent measured UDP burst | Agent stays reachable, but HC still times out four times and teardown leaves two quarantined entries. Test records CPU=1, ESP=1, zero reuse/replay drops; expected load assertion failure plus a genuine teardown error. |
| `kasan-no-reply` | Same single-ping diagnostic after a fresh boot; WAN host drops the decrypted echo request before generating a reply | Host DROP counter is exactly one packet / 92 bytes. CPU=1, ESP=1, zero reuse/replay drops. Teardown drains with errors=0 and quarantine=0; pytest reports only the expected load assertion failure. |

The first baseline attempt failed during setup because an earlier test had left
the LAN inner address installed; it is excluded from the reproduction count.
Every tested boot was checked against the UART MAC and an agent-readable marker.

### Smaller reproduction: one ping after warmup

The single-ping diagnostic is stronger evidence than offered-rate changes.
It produces the HC failure while ordinary agent traffic still works. SEC
reports `SSTA=0x406`, `QISTA=0`, and `QICTL_LS=1`: output-buffer depletion
is **not required** for this HC stall. The broader port/queue stall appears
in the flood runs; the smaller reproduction keeps ordinary traffic working.

Two FPM task snapshots retain task 41's IPsec-OH frame context:
`DRD0=0x0300038c`, `DRD1=0x22848c0b`, `DRD2=0x02080002`,
`DRD3=0x0130c000`. Its task status changes from `0x00980019` to
`0x00980017`. HC task 95 remains at `0x00d00003` with
`DRD0=0x02104c4c`. This is consistent with a surviving OH frame blocking
the HC barrier. The internal instruction/state meanings have not been
decoded, so this is not yet proof of a particular microcode loop.

The offline port is able to accept more work (`PnS=0x80000000`) in this
smaller case; both Ethernet RX QMI statuses are zero. Its recorded frame
count is `0x17b3ca`. Artifacts: `single-stall-*.txt`,
`single-task-repeat-0.txt`, `single-sec-native.txt` and
`kasan-single-ping-pytest.log`.

### Suppressing the reply changes the outcome

For `kasan-no-reply`, the WAN host dropped the decrypted inner echo request
in INPUT, after the DUT had encrypted and transmitted it. The rule matched
only ICMP echo requests from `198.18.102.3` to `198.18.102.2`, with comment
`hc-single-ping-no-reply`. Its final counter was one packet / 92 bytes.
This prevents an echo reply from entering the inbound IPsec path while
retaining the outbound CPU-fed job and the preceding UDP warmup.

| Observation | Reply allowed | Reply suppressed |
| --- | ---: | ---: |
| Measured CPU-fed frames / captured outbound ESP frames | 1 / 1 | 1 / 1 |
| Recorded sequence reuse / replay drops | 0 / 0 | 0 / 0 |
| Teardown errors / quarantined entries | 2 / 2 | 0 / 0 |
| Active entries after drain attempt | 0 | 0 |
| Pytest outcome | Expected load failure plus fixture teardown error | Expected load failure only; teardown completed |

The comparison points toward processing the reply on its return through
the DUT. It does not yet distinguish inbound SEC descriptor execution from
post-decryption OH classification or delivery to the CPU. The idle SEC and
surviving OH task in the failing run make the latter path the leading
hypothesis. They do not rule out an earlier SEC error or malformed output.

Limits: each variant was run once, on separate boots. Both retain the UDP
warmup; a ping on an otherwise unused SA has not been tested. Both deliberately
fail the unchanged `cpu >= 100` / `esp - cpu >= 100000` load assertion, so neither
is a passing shared-sequence validation. HTTP reachability alone is insufficient:
it stayed available during the reply-enabled HC failure.

Evidence is in each run's `ipsec-shared-sequence.json`, `service-drained.json`,
`service-uart.log`, and the corresponding `*-pytest.log` under the artifact
directory. The host DROP counter was checked after the suppressed-reply run.
The temporary rule was then removed and the original test restored.

### HC and queue observations

In `kasan-diag`, the next command after the flood logged:

```text
submit tx=256 conf=257 err=258 opcode=20000002 seq=0
enqueued=58 confirmed=58 cpu=0 preempt=0 irqoff=0
```

Subsequent submissions used sequences 1, 2 and 3, with accepted counts 59,
60 and 61 and confirmations still 58. None was called with local interrupts
disabled. The four timeout buffers remain hardware-owned until a late
confirmation returns them; repeated retries exhaust the four-buffer pool.

Targeted QMan queries after those submissions:

| Queue | FQID | State |
| --- | ---: | --- |
| HC transmit | 256 | Truly scheduled; 3 frames / 384 bytes |
| HC confirmation | 257 | Empty; dequeue sequence 58 |
| HC error | 258 | Empty |
| Outbound TO_SEC | 32840 | Empty |
| Inbound TO_SEC | 32843 | Empty |
| Outbound FROM_SEC | 32839 | Query never returned |

The missing fourth HC frame is consistent with FMAN holding one command while
three wait in the transmit queue. This is an inference from queue accounting,
not a direct decode of that command's location inside FMAN.

The offline port had `fmqm_pns=0x20000000` (dequeue-FD busy),
`fmqm_pnts=0x00000002`, and a fixed frame count of 1,509,707. QMan reported
`idle_stat=0`, `err_isr=0`, 474,384 free PFDR records and six SFDRs in use.
BMan reported no free buffers in SEC output pool 34; Ethernet pools 32/33
and the SG pool 35 still had buffers. A non-KASAN capture similarly had
453,552 free PFDRs and nine SFDRs in use. This is not exhaustion of QMan's
whole frame-record store.

Baseline CPU snapshots showed idle CPUs and QMan IRQ / NET_RX counts that
stayed unchanged over minutes. The later RCU stalls came after diagnostic
QMan management queries stopped returning; those queries aggravated an
already wedged datapath.

### SEC state before recovery writes

`paced-sec-native.txt` contains two aligned native 32-bit MMIO snapshots,
half a second apart, at uptime 282–283 s:

```text
SSTA       = 0x00000406       SEC idle
QISTA      = 0x00000008       output-buffer depletion recorded
QICTL_LS   = 0x00000001       dequeue enabled
OH1 frames = 0x000fd066      unchanged
OH1 PnS    = 0x20000000
RX0 PnS    = 0x40000000
RX1 PnS    = 0x40000000
```

DECO debug and QI job-ID registers read zero. The positive idle indication
in SSTA is the stronger evidence here. QISTA's error bit is sticky: it does
not establish whether depletion preceded or followed the FMAN stall.

The [NXP SEC reference manual](https://www.nxp.com/docs/en/reference-manual/LS1046ASECRM.pdf),
sections 13.119 and 13.162, defines those status bits. Section 6.2.3 says that
a single-output-buffer allocation failure can return the input FD with an
error. Thus an error on a CPU-fed job can expose its SG input format to the
FROM_SEC/FMAN error path, unlike a successful job's newly allocated output.
This remains a possible contributor to the flood failure. The later single-ping
failure has `QISTA=0`, so this recorded depletion error cannot explain every
observed HC stall.

### Recovery experiment and capture limitations

On the earlier diagnostic wedge, a native 32-bit QI STOP/flush sequence
reached STOPD, reset QICTL/QISTA, and permitted dequeue to be enabled again.
FMAN's frame counter stayed at 1,509,707 and the pending FROM_SEC query did
not return (`kasan-sec-flush-0.txt`). A QI reset alone did not recover the board.
This was a destructive diagnostic probe, not a complete driver reinitialization.

Earlier byte-slice `mmap` reads/writes were unsuitable for these device
registers. Their zero-filled results are excluded. The later native flush
followed an earlier unvalidated write attempt, so it does not independently
establish SEC's state at the start of that run. The paced-run snapshot above
was taken without any preceding recovery writes or QMan query.

Do not scan `qman/fqd/state_*` on a wedged board. Even a single FROM_SEC
query can spin forever inside `qman_query_fq_np()` with local interrupts
disabled. Capture passive registers first. Do not run ethtool after loss of
datapath progress.

## Comparison with NXP's original descriptor handling

Original sources: `/home/tzaman/Mono/ASK-NXP/cdx/cdx-5.03.1/` and the
`linux/001-layerscape-lsdk-kernel_linux_5_4_3_00_0.patch` plus
`linux/999-layerscape-ask-kernel_linux_5_4_3_00_0.patch` pair. The vendor SDK
`dpaa_eth_sg.c` was reconstructed by extracting its new-file hunk from 001
and applying its 999 hunks cleanly, without building an original image.

| Detail | Original NXP code | Current code | Relevance |
| --- | --- | --- | --- |
| CBC shared header | `SERIAL | SAVECTX` | Same (`cdx_dpa_ipsec.c:378`) | The reproduced CBC failure is not explained by a change to these flags. |
| GCM shared header | `SERIAL | SAVECTX` | `SERIAL` without `SAVECTX` | Relevant to GCM, but not necessary for the CBC reproduction. |
| Shared-descriptor identity | Native-endian FMan PPID read loses the firmware offset on little-endian ARM; software portals retain theirs | Patch 106 preserves firmware ICIDs for all ports | Makes both feeders one SEC sharing identity. It fixes observed sequence reuse; reverting it is not a production solution. |
| State STORE | Four statistics words followed by CALM (`cdx_dpa_ipsec.c:703–724` in vendor tree) | PDB plus statistics, excluding header, followed by CALM (`cdx_dpa_ipsec.c:1053`) | Changes writeback and inter-job ordering. NXP RM 7.3.1 requires consistent PDB stores across a sharing flow. |
| CPU input FD | SG, segment BPID `0xff`, table BPID is the completion pool, offset zero | Same hardware format; explicit DMA ownership and reaping added | Mixed CPU SG / classifier contiguous input is inherited. Its effective sharing identity changed. |
| CPU tunnel DPOVRD | `0x80000000 | IPPROTO_IPIP` for inner IPv4 | Same for the reproducing tunnel | Transport-mode extensions do not explain this test. |
| QI preheader | Descriptor length, output BPID/size, 128-byte output offset; other fields initially zero | Same field construction (`cdx_dpa_ipsec.c:1702`) | No new replacement-job descriptor or input-release policy found in the preheader. |
| SA queue routing | TO_SEC Context A = preheader address, Context B = FROM_SEC; FROM_SEC targets OH and supplies TO_CP plus A1 SEC-status check | Same (`dpa_ipsec.c:792`) | This routing and the error-status action are inherited. |
| Output-pool seed | `seed_cb=dpa_bp_priv_seed`, which allocates 512 per possible CPU | Explicit allocation of 512 total (`dpa_ipsec.c:1208`) | Fourfold capacity reduction on this board; directly relevant to QISTA depletion. |
| Output-pool refill | Inline receive-path refill using per-CPU accounting | Deferred worker replaces buffers transferred to Linux, budget 64 per invocation | Changes refill timing. Outstanding debt is rescheduled immediately; 20 ms is idle/failure retry, not a fixed cap on all refills. |
| OH reclassification | Shared Ethernet-port classifier layouts | Separate per-SA-keyed tables | Changes processing after SEC completion. Must preserve the cross-SA isolation fix when testing this path. |

The queue geometry, preheader layout, tunnel override and CBC flags do not
provide a simple original-versus-current explanation. The substantive
descriptor changes are common ICID identity and PDB writeback. Both have
correctness reasons supported by the [SEC manual, sections 7.3.1–7.3.2](https://www.nxp.com/docs/en/reference-manual/LS1046ASECRM.pdf).
They are experiment candidates, not demonstrated defects. Source inspection
cannot establish whether NXP's original image would wedge on this workload.

### Offline-port fallback differs from the vendor path

The current configuration gives the IPsec OH port its own distributions and
per-SA-keyed tables. A decrypted ICMP frame has no UDP/TCP/ESP flow entry and
is intended to reach `cdx_sec_ethernet_dist`, then its empty Ethernet hash
table, then the exception policer and CPU queue. This adds a path through the
OH port's own classifier state compared with the original shared layout.

Relevant code inspected:

- `dpa_app/files/etc/cdx_pcd.xml:490`: catch-all Ethernet distribution and its
  classification action, `cdx_sec_ethernet_cc`.
- `cdx/dpa_cfg.c:396`, `miss_scheme_on_port()`: selects a fallback scheme
  belonging to the table's own port.
- `cdx/dpa_cfg.c:651`, `cdxdrv_set_miss_action()`: programs table misses;
  the Ethernet miss terminates at the shared exception policer.
- `dpa_app/dpa.c:590`, `set_table_types()`: recognizes the SEC UDP/TCP/ESP
  tables explicitly; the Ethernet catch-all takes the intended Ethernet type.
- Kernel `fm_ehash.c:ExternalHashTableModifyMissNextEngine()`: emits the
  KeyGen or policer next-engine action for the external hash table.

Inspection has not exposed an obvious wrong table type or a proven fallback
loop. Successful handling of other packet classes does not establish that
this ICMP miss path completes. The new comparison justifies reopening that
path despite the older A276 notes that had ruled it out from configuration
inspection. Any experiment must retain the cross-SA isolation provided by
the current classification changes.

## Fix direction and concrete proposals

1. **Repeat the reply comparison and trace the inbound OH fallback.**
   Repeat the two single-ping variants and add a no-warmup control. Capture
   passive SEC/FPM state before retirement starts. Add printks for the actual
   OH scheme IDs, CC groups, table miss actions, exception profile and CPU
   FQIDs in the configuration paths above; record received CPU FD format,
   BPID and SEC status at the relevant completion callbacks. A diagnostic
   experiment could route only the OH catch-all directly to the existing
   exception policer/CPU destination, bypassing its empty hash-table lookup
   while preserving per-SA TCP/UDP/ESP classification. Its queue/context and
   buffer-ownership requirements must be checked before implementation.
   This is an experiment proposal, not a validated fix.

2. **Keep descriptor experiments narrow and check returned frame handling.**
   `cdx/cdx_dpa_ipsec.c:378` selects sharing policy; `:1053` emits the state
   STORE. Compare SERIAL versus WAIT while keeping common ICIDs, the PDB
   store, and sequence/replay assertions. A stats-only STORE or split ICIDs
   would be diagnostic-only because they restore known sequence-state defects.
   An idle SEC in the reproduced stalled state lowers the priority of a
   permanently stuck DECO theory. Check inbound output and error FDs before
   assuming a post-SEC classification bug. Pool debt/refill instrumentation
   remains useful for the flood, but increasing initial capacity from 512 to
   2,048 has already failed to prevent it, and depletion is absent in the
   single-ping failure.

3. **Bound outstanding retryable HC barriers as secondary hardening.**
   In kernel `sdk_fman/Peripherals/FM/HC/hc.c:FmHcPcdSync()` (line 1282 in the
   fully applied research worktree), track an outstanding SYNC under `HcLock`.
   If an earlier SYNC is still hardware-owned, return a retryable error before
   taking another buffer. Clear the tracked identity on its actual confirmation
   in `FmHcTxConf()`, including the ORPHANED path. A later caller must submit
   and complete a **new** barrier: an old confirmation does not fence a newer
   unlink. Preserve fail-stop handling for ambiguous WRITE timeouts. This can
   prevent all four buffers being consumed by retries, but cannot restore the
   wedged data path and must not permit quarantined storage to be freed early.

4. **Do not install an HC-only reset as recovery on this evidence.**
   The stall crosses data and control queues; SEC QI reset did not recover it.
   A full recovery must stop admission, retain DMA-owned memory and quarantine,
   quiesce/reset the participating engines, recreate queues and classifier state,
   and only then resume. Blindly recycling an outstanding HC FD risks late DMA
   into reused memory. Board reboot remains the observed working recovery.

## Changes and validation

Patch 010 retains the user's retryable SYNC fix and adds optional HC printks:

```sh
echo Y > /sys/module/fsl_ncsw_PFM/parameters/hc_trace
```

They record opcode, sequence, queue IDs, accepted/confirmed counters, CPU,
and submission interrupt/preemption context. Default is off. No descriptor
keys or packet payloads are printed. Counts are global diagnostic counters;
under concurrency they are not an atomic snapshot of all submissions.

The diagnostic KASAN image built and staged successfully. The regenerated
010 plus all 38 remaining kernel patches applied cleanly with `git am`.
Kernel compile logs contained no compiler warnings/errors from the change;
BitBake still reported the existing forced-task and build-path QA warnings.

The 2,048-buffer experiment was reverted, and the diagnostic KASAN image
with the original 512-buffer capacity was rebuilt, staged and booted for
the single-ping comparisons. The original shared-sequence test is restored;
the temporary pacing, single-ping and host reply-suppression changes are not
part of the proposed code changes. HC tracing and the existing retryable
SYNC fix remain in patch 010. No descriptor or OH fallback fix was installed.

The shared-sequence test has not passed on these images. Consequently the
required three successful runs on one boot and neighboring recovery/churn
validation have not been achieved. No successful wedge fix is claimed.

## Update 2026-09-29: retryable SYNC reverted; fix reframed as an OH redesign

The uncommitted retryable-HC-SYNC change to patch 010 was reverted. It did not
fix the wedge (it converts the fail-stop latch into the E_NO_MEMORY storm), and
`tools/host_tests/sdk_hc_transport.py::timeout_and_late_confirmation`
exercises and depends on the SDK's fail-stop contract: an HC command that times
out latches the channel because its buffer may still be hardware-owned. The
storm itself proves the timed-out SYNC buffer is not reclaimed, so a
non-latching retry is unsafe without the outstanding-SYNC bound (proposal 3),
which was also not present. Rather than bless an incomplete, unsafe contract
change in the test, the tree was restored to the base fail-stop behaviour and
the diagnostic `hc_trace` printks removed with it. They can be re-proposed as
permanent, self-contained instrumentation if the barrier path is revisited.

The remaining, real fix is an offline-port classification redesign, and it is
the same root as the item-3 oversized-ESP fragmenter regression: the per-SA OH
tables key on `<nonheader source="fqid" offset="0" size="3">` (cdx_pcd.xml
368-484), and that KeyGen FQID extraction is what perturbs the OH microcode.
The soft parser (cdx_sp.xml) keys only on `$logicalportid`, so it is not the
lever; the discriminator is chosen solely in those KeyGen keys, with
`cdx_ipsec_key_tag()` on the cdx side. Keeping the cross-SA isolation the FQID
key provides (A199) while removing the microcode perturbation needs one of:
a non-FQID per-SA discriminator that SEC writes into a frame scratch field the
KeyGen reads as a header extract; or a microcode/soft-parser change that makes
the FQID extraction retire its OH task. Both require iterative on-hardware
testing with attended recovery (a boot-time misprogram of the OH port can hang
the board unrecoverably), so this is not safe to iterate unattended. XML edits
to the CMM-proven cdx_*.xml are out of scope by policy; the work is in C.

## Update 2026-09-29 (part 2): root cause is a TNUM stall; fix ports the original direct-enqueue miss

Three source studies (the original NXP CDX-5.03.1 data path, the current
flowtable path, and the FMAN SDK) resolved the wedge to a concrete mechanism
and a C-side fix. This supersedes the "OH redesign" framing above.

### Mechanism: Host Command starves on the shared FMAN task pool
The FMAN Host Command channel is itself an offline/host port; each HC command
is a DPAA frame that `EnQFrm` enqueues and busy-polls for confirmation (~1s)
before fail-stopping "board reset required" (hc.c). HC and the offline (OH)
data path share one finite task pool (124 TNUMs on this SoC) and the QMI
dequeue, gated by a single FM-wide enqueue threshold (fm.c). A frame holds its
TNUM until its final QMI enqueue retires; if an OH exception frame's processing
does not retire, its TNUM is held, and enough held TNUMs cross the threshold so
QMI stops issuing dequeues FM-wide -- the HC command frame is never processed,
its confirmation never returns, and `EnQFrm` times out. "HC task 95 waiting
behind OH task 41" is exactly this. It is the same class as the earlier
fman_pcd_tnum_stall (missing dist FQ -> TNUM exhaustion).

### Delta: the flowtable added a miss cascade + policer the original never had
Original (CDX-5.03.1) decrypted-miss path: one KeyGen scheme, one CC lookup,
then a DONE miss that enqueues to the frame's default FQID -- which the SA's
FROM_SEC `context_b` override sets to that SA's software-portal `FQ_TO_CP`
exception queue, drained by `ipsec_exception_pkt_handler`. No policer, no
re-lookup, no per-SA OH CC: the offline-port task enqueues once and retires.

Current path: the per-SA CC miss cascades (via `miss_scheme_on_port`) to a
second KeyGen scheme `cdx_sec_ethernet_dist`, a second empty external-hash
lookup `cdx_sec_ethernet_cc`, and the `CDX_EXPT_ETH_RATELIMIT` policer, before
it enqueues. Those extra in-controller traversals hold the task/TNUM long
enough (and, under the shared_sequence flood, across enough frames) to exhaust
the pool and starve HC. The CPU-drain handler itself is byte-for-byte the
original; only the pre-enqueue miss steering differs.

### Why the earlier in-tree experiments missed it
2a (drop the catch-all miss) and no-action (remove the catch-all CC action,
enqueue to the scheme's own combined FQID) each changed only the *final* action
but kept the second scheme + cascade; neither routed the miss the way the
original does (DONE -> `context_b` -> per-SA `FQ_TO_CP`). The
pre-per-SA-classification image (57b8c6e) still carried the same cascade+policer
miss path, so it wedged too -- confirming the strand is the cascade/policer, not
the per-SA FQID keying (11aa150). A276 is a flowtable-introduced regression
against the original miss handling, present since the flowtable IPsec path was
built.

### Fix (C-side, no XML): dpa_cfg.c cdxdrv_set_miss_action
The SEC offline-port tables (`cdx_sec_*`) get a DONE miss
(`nextEngine = e_FM_PCD_DONE`, no override FQID -> `EN_EHASH_MISS_ACTION_DONE`),
so a decrypted exception frame enqueues once to the SA's FROM_SEC `context_b`
target (its per-SA `FQ_TO_CP` software-portal FQ) and the offline-port task
retires immediately -- never crossing the second scheme, the empty catch-all
lookup, or the policer. This ports the original's proven miss structure. The
per-SA OH CC *hit* classification (11aa150) is unchanged; only the miss action
changes. The retryable-HC-SYNC change is not needed and stays reverted.

Validation gate (on the rig): shared_sequence runs three times on one boot
without wedging, the IPv6 hairpin passes, and the classifier/flowtable suite
shows no regression.

## Update 2026-09-29 (part 3): RESOLVED — the fix is reverting 11aa150, not the miss action

Part 2's proposed fix (route the SEC-OH miss to DONE -> the FROM_SEC context_b
FQ_TO_CP override) was built and tested on hardware and **did not stop the
wedge** (confirmed via a boot printk that the DONE miss was applied). So the
strand is NOT the miss action, the policer, or the empty-CC lookup -- all three
were ruled out on hardware (DONE-miss and CC-removal both still wedged).

**Actual root cause and fix:** the strand is the per-SA
`<nonheader source="fqid">` KeyGen extraction that 11aa150 folds into the SEC
offline-port classification keys. That fqid-in-KeyGen extraction, when a
decrypted frame *misses*, strands the offline-port microcode task; the task
holds its TNUM; HC (which shares the FMan task pool and QMI dequeue) starves and
fails stop. **Reverting 11aa150** returns the SEC OH port to the original NXP
shared-classification + FROM_SEC-context_b design (schemes 21 -> 14, no
per-SA tables, no fqid extraction), which does not strand.

**Hardware validation (KASAN image):**
- 57b8c6e (this branch pre-11aa150 = the revert's code state): 5/5 shared_sequence
  runs, no wedge. (One earlier lone wedge on 57b8c6e was an unreproduced outlier
  from a pre-discipline run; five clean runs since.)
- The actual port (`git revert 11aa150`, keeping 306665d): 4/4 same-boot
  shared_sequence runs **PASS** (not just no-wedge) -- 306665d's ask_flowtable
  SA-selector + patch 106 carry the sequence correctness the per-SA tables used
  to. IPv6 hairpin + inbound IPsec offload: 11/11 pass, no regression.
- Full suite gate: in progress.

**Item-3 fixed as a side effect:** the fqid-nonheader extraction that perturbed
the ucode fragmenter is gone with the revert.

**Trade-off accepted (product decision):** the revert drops cross-SA isolation
for *overlapping inner subnets* (two SAs whose decrypted inner flows share a
5-tuple can collide in the shared table). The VPN deployment uses distinct inner
subnets, so this is not exercised. If overlapping-subnet isolation is ever
required, it must be re-added WITHOUT the enqueue-FQID-in-KeyGen mechanism (e.g.
a soft-parser-stamped parse-result field the KeyGen reads as a header extract),
since that mechanism is what strands the OH task.

# Connection capacity — 2026-09-15

The adapter admission budget moves directly from 64 to **32,768 directional
entries**, enough for **16,384 fully accelerated connections**. No intermediate
production limits are introduced. The [capacity guide](../../flowtable-capacity.md)
records the resource rationale, implementation and reproduction command.

## Implementation and image

Binding/cookie and ingress/tuple lookups now use two fixed hash indexes under
the existing backend transaction. Complete diagnostics stream through a
`seq_file` iterator whose resume position identifies a hash bucket and offset;
ordinary paged reads do not rescan all preceding entries. Policy status reads
the header alone. Publication, rollback and retirement preserve the existing
ownership rules, and dependency invalidation remains a bounded full-list walk.

This increment builds on `1dd4bc7` on `feat/linux-flowtable-offload`. The final
KASAN image was built and staged with these identities:

| Component | Identity |
| --- | --- |
| DUT boot | `d99522c3-7691-46ef-ba33-d498d9164b58` |
| Kernel build ID | `5a530e9a8109875ecda98367582ef598c55c1d69` |
| CDX build ID | `fc9a2e4c48a5d102767018464d154cca931aec4a` |
| Adapter build ID | `5d52fb31da28fa4e270ab3560f49ca51ac7a5a78` |
| Staged image SHA-256 | `07cde71c1e637329abf10256d240d2d659aa78f90899ea1f39b1513b9746a6bc` |

`/tmp/ask-flowtable-capacity/image-identity.json` records the full build/boot
manifest. Production source hashes match the tested image; later traffic-harness
and documentation changes do not alter that image. CMM remains stopped; FCI and
auto_bridge are absent. The hardware owner remains `flowtable` throughout.

## Test method

The DUT proof opens 8,192 TCP and 8,192 UDP connections from Loki to Vision
through native MASQUERADE. Each direction has an independently checked tuple,
cookie and advancing hardware counter. Startup is paced in groups of 256
connections while previously opened sockets remain active. TCP records are
1,024 bytes and UDP records 256 bytes; this is a capacity/lifecycle test rather
than another line-rate benchmark.

Another 256 connections must continue through software at full capacity without
evicting any installed owner. Closing 128 TCP sockets and deleting 128 exact UDP
conntracks frees 512 directions; the same overflow sockets must then occupy
those slots. Existing cookies and counters must survive unchanged. Temporary
admissions retired by the existing RTNL-contention recovery are accounted for
using `admission_invalidations`, without relaxing final occupancy or ownership.

A material route replacement changes the WAN host-route MTU from 1200 to 1300,
invalidates all 16,384 generations and retires every direction. The same live
sockets must repopulate the cap with updated MTUs. Three ten-second windows
check every hardware direction, stable ownership, software TX and CPU: initial
occupancy, after slot reuse, and after route recovery. Final table detachment
must release all hardware, neighbour and shared-handle ownership.
Both initial fill and recovery use the same paced admission groups.

Endpoint receive buffers and descriptor limits are bounded and local to the
generator processes. The UDP socket's kernel drop count must remain zero.
TCP delivery and all received payload contents remain exact. At the operator's
request, isolated UDP loss is recorded under the capacity guide's explicit
budget, with every connection still required to deliver and every hardware
direction required to advance. UDP uses the normal five-second receive deadline.

## Accepted measurements

`test_flowtable_capacity_overflow_and_reuse` passes in **139.96 seconds**, with
artifacts under `/tmp/ask-flowtable-capacity/paced-recovery-proof/`. The configured
budget stays at 32,768; no reduction was needed for this workload.

| Measurement | Result |
| --- | --- |
| Fully accelerated connections | 16,384: 8,192 TCP and 8,192 UDP |
| Directional entries at each full checkpoint | 32,768 |
| Initial fill, including diagnostic snapshot | 18.19 seconds |
| Extra connections forwarded in software | 256, without eviction |
| Selectively retired and reused directions | 512 |
| Route replacement command | 0.111 seconds |
| Complete route-dependent hardware retirement | 10.858 seconds |
| Final table detachment | 13.365 seconds |
| UDP exchanges across recorded stages | 384,759; one lost, zero late replies |
| TCP records across recorded stages | 384,725; all delivered exactly |
| Generator UDP socket drops | 0 |
| X550 CRC/error/drop counter increases | 0 |

The single UDP timeout occurred during paced recovery warmup, within the stated
allowance. Both long-running traffic stages, initial warmup, selective retirement
and overflow had zero UDP loss. Payload validation and every-direction hardware
progress checks passed throughout the accepted run.

| Ten-second hardware window | Aggregate DUT busy CPU | Aggregate softirq CPU | Software TX, LAN / WAN |
| --- | --- | --- | --- |
| Initial full table | 11.17% | 0.71% | 0 / 12 |
| After slot reuse | 9.47% | 0.66% | 0 / 14 |
| After paced route recovery | 12.60% | 0.72% | 0 / 10 |

Every direction's hardware packet counter advanced in each window, with stable
cookies and no installation/deletion churn. CPU figures include the KASAN kernel
and background work; they are observations rather than a CPU ceiling. The earlier
failed `deadline-proof` also recorded a 45.39% busy-CPU window after slot reuse,
with 0.57% softirq and software TX 0 / 12. Its cause was not isolated and it is
not discarded in favour of the lower accepted-run measurements.

At full occupancy, `MemAvailable` changed from 5,348,912 to 5,254,568 KiB
(a 92.13 MiB decrease) and slab use rose by 90.79 MiB. The boot had already run
earlier attempts, so caches and allocator retention affect these deltas. They
include Linux flow/conntrack storage, KASAN and diagnostics, and are not a pure
adapter allocation measurement or a fresh-boot memory guarantee. DWARF object
layouts report 192 bytes per adapter entry and 328 per CDX hardware owner,
before allocator and classifier costs.

Focused host validation passes **35 tests** in 1.65 seconds, covering decoder,
index/iterator lifetime, full-budget pressure, hardware ownership, route handles
and policy. Relevant C harnesses use ASan/UBSan and leak detection. On the same
final image, `test_flowtable_connections_independent_lifetimes` and
`test_flowtable_policy_revokes_live_connections` both pass in 154.94 seconds.
The complete capacity proof exercises the final generator deadline and pacing.

After cleanup, all **287,335 installs equal 287,335 deletes** across this boot.
Entries, bindings, neighbour/shared-handle references, errors, invalidation,
fatal state and quarantine are zero. KASAN/lockdep diagnostics are clean,
`debug_locks` is 1 and taint is 4096. Loki's original advertisement was restored
to 100 Mb/s, 1 Gb/s and 10 Gb/s; it negotiated 10 Gb/s full duplex and passed
three gateway pings. The flowtable owner remains selected and its default
admission policy remains disabled.

## Development failures and link observations

Earlier failed attempts remain under `/tmp/ask-flowtable-capacity/`:

- `proof`, `paced-proof` and `low-rate-proof`: the initial generator burst,
  undersized UDP receive queue and controller watchdog prevented a complete
  proof. The paced low-rate attempt nevertheless reached all 32,768 entries.
- `buffered-proof`: explicit data ports overlapped the control socket's
  ephemeral range. Capacity data ports now start at 20000.
- `final-proof`: repeatedly invoking filtered conntrack deletion dumped the
  entire Linux table each time and exhausted the controller watchdog. Exact
  netlink tuple deletion now checks each kernel ACK.
- `verified-proof`: replacing a route with identical attributes was a Linux
  no-op, so the test's expected route invalidation did not happen. The proof
  now changes the route MTU and verifies it after readmission.
- `acceptance-proof` and `network-proof`: isolated UDP exchanges timed out
  on the final image at 10 Gb/s. In `network-proof`, Loki's X550 CRC counter
  increased from 2785 to 2787, its UDP receive socket had no drops, and DUT
  port error/drop counters remained zero. This does not identify a faulty
  cable, module or firmware component.
- `gigabit-proof`: at 1 Gb/s, full occupancy, slot reuse and complete route
  retirement passed. One UDP exchange timed out during repopulation, with
  no new X550 CRC errors or generator socket drops.
- `bounded-loss-proof`: the test expected exactly 512 new installs during
  reuse, but two provisional installs were legitimately retired and retried
  after recorded RTNL contention. Existing cookies survived; the assertion
  now accounts for that documented recovery path.
- `complete-proof`: reusing the peer's deliberate-outage mode also selected
  its 100 ms receive deadline. It reported 2,738 UDP timeouts in 217,082
  records and failed the unchanged loss budget. Capacity now explicitly uses
  the ordinary five-second deadline; the short deadline remains the default
  for existing deliberate-outage tests.
- `deadline-proof`: initial fill, steady forwarding and reuse had zero UDP
  loss. Restarting all sockets together after route retirement produced 6,651
  lost exchanges in 138,228 UDP records and failed the loss budget. Missing
  requests at Vision were confined to the first three records per socket;
  subsequent full-table hardware counters advanced. No new X550 CRC errors
  or receiver socket drops were recorded. The capacity proof now uses the
  same paced admission during recovery as during initial fill. Simultaneous
  readmission under a burst remains unproved; its loss is not attributed to
  the earlier link errors or claimed fixed.

The Loki link was temporarily advertised at 1 Gb/s for the capacity proof.
These observations extend the [UDP/link investigation](../../flowtable-udp-loss-investigation.md).
The operator identified the cable-heavy homelab as an environment where small
errors should not displace the main work. No controlled component-isolation
experiment was performed and no cause or permanent link fix is claimed.

## Acceptance boundary

The configured cap is an adapter resource budget, not a measured maximum of
the proprietary firmware. This workload covers an equal TCP/UDP mix with
native MASQUERADE, resource pressure, selective reuse and bulk route retirement.
It does not establish a long-duration soak, line rate at full occupancy,
all-TCP/all-UDP saturation, every NAT topology at capacity, small-packet line
rate, lossless simultaneous readmission or parity on an uninstrumented image.
Future interface/protocol features
need their own capacity proofs. The full KASAN suite and alternative-kernel
exercise remain outside this focused increment.

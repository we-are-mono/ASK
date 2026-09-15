# Flowtable capacity

The admission budget is **32,768 directional entries**, enough for **16,384
fully accelerated connections**. Directions consume slots independently. At
capacity, new hardware admissions fail without evicting existing owners;
Linux continues forwarding eligible overflow traffic in software. Linux's
conntrack limit is separate and does not resize this budget.

## Choosing the budget

This is a practical target, not a claim about the proprietary firmware's maximum.
The deployed [classifier configuration](../dpa_app/files/etc/cdx_pcd.xml) gives
each IPv4 TCP and UDP table a `0x7fff` hash mask: 32,768 buckets per protocol.
The enhanced external-hash implementation allocates entries in DDR as needed;
its allocation path does not treat the XML `max="512"` field as a 512-entry
ceiling. See `ExternalHashTableSet()` and `ExternalHashTableAllocEntry()` in the
pinned kernel's `fm_ehash.c`, introduced by
[patch 010](../patches/kernel/010-ask-fman-dpaa-ehash.patch).

At this adapter cap, an all-TCP or all-UDP workload averages one directional
entry per classifier bucket; a balanced mix averages half an entry per bucket.
Collisions still occur and require normal key comparison and collision handling.
Bucket count alone is not an admission or performance guarantee.

The DUT has approximately 6.5 GiB visible to its KASAN kernel and over 5 GiB
free before this workload. The adapter's two software indexes occupy 256 KiB
on arm64. Each adapter entry is 192 bytes before allocator overhead; its private
CDX hardware owner is 328 bytes, with classifier allocations and Linux
conntrack/flow storage additional. Measured memory use is recorded with the
DUT proof, including KASAN and allocator effects.

The target is tested directly at its full configured value. A failed test must
identify whether the constraint is hardware, adapter code, Linux, or the traffic
generator. A proven resource or performance constraint can justify lowering the
budget; a broken test or implementation should be corrected at its source.

## Implementation and diagnostics

Binding/cookie lookup and duplicate ingress/tuple detection use separate fixed
hash indexes under the existing backend transaction. Each has 16,384 buckets;
full comparisons disambiguate collisions, and the tuple hash seed changes on
module load. Statistics callbacks and ordinary admission no longer scan every
installed direction. Entry publication, rollback, retirement and ownership
retain their existing contracts.

Dependency invalidation still walks a bounded list because one route, device or
neighbour can affect every connection. Hardware deletion and whole-table
retirement remain serialized. Capacity verification therefore includes route
invalidation, resource reuse and complete table detachment.

`/proc/cdx_flowtable` retains its header and per-flow diagnostic format, streamed
through `seq_file`. Policy status reads only the header. A complete dump at
capacity requires several megabytes; consumers must not silently truncate it.
Paged reads resume within the cookie hash bucket rather than rescanning the
preceding entries. Separate reads can observe intervening mutations, so
snapshots should be taken outside admission/retirement transitions.

## Focused verification

Build and stage the KASAN image, boot with `ask.offload=flowtable`, and verify its
identity before the DUT proof. CMM must remain stopped and FCI unloaded.

```sh
sudo PYTHONPATH=tools /opt/askd-agent/venv/bin/pytest -q \
  tools/host_tests/test_flowtable.py \
  tools/host_tests/test_flowtable_handle.py \
  tools/host_tests/test_flowtable_route.py \
  tools/host_tests/test_flowtable_policy_host.py

ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 \
  ASK_FLOWTABLE_ARTIFACTS=/tmp/ask-flowtable-capacity/proof \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_capacity_overflow_and_reuse'
```

The DUT test creates 8,192 TCP and 8,192 UDP connections through native
MASQUERADE, using exact connection IDs and increasing serials in echoed payloads.
It bounds startup bursts while retaining the full production admission cap.
Small TCP records keep the test focused on connection capacity rather than
line rate, which has a [separate NAT benchmark](flowtable-nat.md).

It verifies every direction's hardware counters, stable surviving cookies,
software TX and CPU windows, 256 overflow connections, selective retirement and
reuse by the same overflow sockets. A route replacement then retires the entire
table; the same remaining sockets repopulate it using the initial admission
pacing before complete detachment.
The final state must have balanced installation/deletion counts and no retained
hardware, neighbour, shared-handle or quarantine ownership.

The [2026-09-15 DUT proof](flowtable/history/capacity.md#accepted-measurements)
passes at the full configured budget with 256 overflow connections and complete
resource reuse. Its three hardware windows show 9.47–12.60% aggregate DUT CPU
on KASAN, with zero LAN and 10–14 WAN software TX packets per window. Across
384,759 UDP exchanges, one recovery-warmup exchange was lost; all 384,725 TCP
records arrived exactly. The capacity workload used a 1 Gb/s LAN link; the
original advertisement and 10 Gb/s link were restored afterward.

TCP payloads must arrive exactly. UDP payload identity, contents and serials
remain checked, and every connection must deliver. To accommodate the lab's
observed intermittent link errors, each checked report group allows at most
`max(4, sent_udp_records / 1000)` lost UDP records (integer division). The test
records steady-traffic loss totals; payload corruption, persistent delivery
failure, stopped hardware counters and generator socket drops still fail.
This allowance applies only to the capacity test; existing delivery proofs
retain their own acceptance criteria. It does not establish the cause of loss.

Data sockets use source ports starting at 20000, below the lab’s ephemeral
range, to avoid colliding with their control connection.
The generator uses a bounded receive buffer on its own UDP socket and checks
that socket's drop counter. File descriptor budgets apply only to generator
processes. No host-wide networking sysctl is changed. This focused test does
not substitute for a long-duration soak or capacity proofs for future features.
An unpaced simultaneous restart after full route retirement produced material
UDP loss during readmission; see the [development evidence](flowtable/history/capacity.md#development-failures-and-link-observations).
Lossless recovery under that burst is outside the accepted paced workload.
The software-flowtable control reproduced the loss with hardware admission
disabled; investigation is deferred as **A139** in [ISSUES.md](../ISSUES.md).

## Sustained connection churn

The separate opt-in churn test holds 16,384 mixed TCP/UDP connections through
native MASQUERADE, with CMM off. It keeps 256 connections alive throughout and
rotates the other 16,128 in groups of 256. Each round retires 64 TCP connections
through FIN, 64 through RST and 128 UDP connections, then reopens the exact
tuples. Every eighth round waits for idle UDP **flowtable** expiry; other rounds
delete the exact UDP conntracks through acknowledged netlink requests. Idle
flowtable expiry does not imply that the Linux conntrack has expired.

The full hardware budget stays at 32,768 directions. Each round must free
exactly 512 directions and return to full occupancy, preserving every unaffected
cookie and accounting for any documented provisional-admission recovery.
The permanent survivors must advance their hardware counters each round.
These counters see software flowtable transmission as well as ordinary routed
transmission; initial software exchanges must hit both to validate the matches.
The ordinary forward-hook counter is recorded separately. Ten-second
windows before and after churn verify hardware progress for every direction,
software TX and CPU. TCP FIN/RST forward-hook counters independently verify
the expected close operations reached Linux.

Linux owns flow lifetime, and it can retire a live flow this round never
touched. A hardware-owned flow keeps its deadline only through a stats round
trip, which the flowtable core queues in the last tenth of the flow timeout and
skips while any offload work for that flow is still pending; every such read
shares one hardware transaction with this workload's installs and retirements.
A starved refresh therefore retires a healthy flow, which forwards in software
and returns to hardware with a fresh cookie on its next packet. The test does
not assert a race-free window. It requires the adapter to have retired nothing
on its own initiative — every counter describing an adapter-driven retirement is
frozen across the retirement — attributes each unrequested install to exactly
one surviving tuple whose identity changed, and bounds that turnover per round
and across the run. A survivor is entitled to forward-hook packets only when it
is one of those tuples, and only a fixed number per readmission; with none, both
its forward-hook and netdev egress counters stay exact. `/proc/net/stat/nf_flowtable`
(`CONFIG_NF_FLOW_TABLE_PROCFS`) records the offload backlog each round.
The underlying refresh cost is tracked separately as an open issue.

The offload timeouts are raised for the run — TCP to 120 seconds, UDP to 30 —
so the refresh window is not routinely starved. A conntrack Linux has already
reclaimed when the test goes to delete it reaches the same postcondition and is
counted rather than treated as a failed deletion.

The traffic peer carries its payload serial forward when reconnecting and checks
it against the receiver's previous count. Overlapping TCP generations are
rejected. Every received payload is checked for identity and contents. The UDP
loss allowance is the same explicit bound used by the capacity test. Both
endpoints retain bounded per-connection bookkeeping; the long-running UDP echo
receiver counts packets without retaining every complete datagram.

Each completed round records ownership, delivery, CPU, software TX, offload
backlog, turnover, conntrack count, memory and allocator data. The test bounds conntracks to the workload
plus 1,024 background entries and flags more than 32 MiB of unreclaimable-slab
growth between settled sample groups. That coarse memory guard is supplemented
by exact backend ownership checks and a scoped kmemleak scan after closing peers
and deleting test conntracks. Warm allocator caches need not return every page
to the free list. Final hardware installs/deletes must balance, with zero
entries, bindings, neighbour/shared-handle references, errors or quarantine.

```sh
ASK_FLOWTABLE_TESTS=1 ASK_FLOWTABLE_CHURN=1 ASK_WAN_IPERF_IP=10.0.0.232 \
  ASK_FLOWTABLE_SPORT=54900 \
  ASK_FLOWTABLE_ARTIFACTS=/tmp/ask-flowtable-churn/proof \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_sustained_churn'
```

The default is **900 seconds of churn**, plus setup, final hardware verification,
teardown and leak scanning. Every rotating tuple must be visited in the default
run. `ASK_FLOWTABLE_CHURN_SECONDS=60` selects a development smoke check and does
not satisfy that acceptance duration or coverage. Rounds are paced, taking at
least four seconds each; expiry and hardware convergence can take longer.
This is a bounded lifecycle proof, not a maximum connection-admission-rate
benchmark or a multi-day endurance claim.

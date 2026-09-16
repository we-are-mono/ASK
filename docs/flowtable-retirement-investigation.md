# Spurious flow retirement investigation — 2026-09-15

**Root caused 2026-09-16.** A flow being retired clears `IPS_OFFLOAD` on a
conntrack that a newer flow on the same tuple already owns. The surviving flow
then runs on a conntrack nothing can refresh, and it dies ninety seconds later,
retiring the live flow. This is an upstream defect in `flow_offload_teardown`;
no adapter code participates. See the [measured cause](#root-cause--2026-09-16)
below and **A140** in [ISSUES.md](../ISSUES.md).

Tracked as **A140** in [ISSUES.md](../ISSUES.md). This document records the
instrumentation, the measurements and — deliberately — the explanations that
were eliminated, so the next person does not re-derive them.

## How the defect presents

The [sustained churn proof](flowtable-capacity.md#sustained-connection-churn)
rotates 256 of 16,384 offloaded connections per round. Retiring a group must
free exactly 512 directions. Instead, some rounds also free directions
belonging to connections the round never touched, and those return moments
later under a new hardware entry.

It is intermittent. A 120-second pass saw 16 directions turn over across nine
rounds; a 180-second pass saw 116 across fourteen; two 60-second passes saw far
more, one reporting 192 directions in a single quiet window. Nothing yet
explains why a shorter run would be affected more, and that discrepancy is
still open.

## Instrumentation built for this

| Instrument | What it answers |
| --- | --- |
| `patches/kernel/141-ask-flowtable-teardown-attribution.patch` | Which of the flowtable GC's four teardown conditions fired |
| `CONFIG_NF_FLOW_TABLE_PROCFS` (`meta-ask/recipes-kernel/linux/files/ask.cfg`) | Offload work-queue backlog, and the host for the counters above |
| `flowtable_work()` / `work_peak()` in the churn proof | Backlog peak while a retirement drains, and exact cumulative causes per round |
| `settled()` absences, `hardware_window` `missing`/`unexpected` | Flows caught between teardown and readmission |

The GC evaluates its four teardown conditions in one expression with a single
call site, and three of the four predicates are inlined, so neither a function
tracer nor a stack trace can separate them. Patch 141 splits the expression
into an `if`/`else if` chain with a per-CPU counter on each branch, preserving
order and short-circuiting, and publishes the totals as four extra columns in
`/proc/net/stat/nf_flowtable`. It is diagnostic only; nothing depends on it.

## What the counters establish

Over a 14-round pass on the instrumented KASAN image, every unrequested
readmission was `gc_dying` — the conntrack was already dying when the GC
looked — and the correspondence was exact:

| Round | Unrequested readmissions | `gc_dying` surplus | `gc_expired` |
| ---: | ---: | ---: | ---: |
| 0 | 12 | 12 | 256 (intended idle expiry) |
| 5 | 44 | 44 | 0 |
| 8 | 60 | 60 | 256 (intended idle expiry) |
| others | 0 | 0 | 0 |

Every affected flow was UDP. No TCP flow was ever affected, in any pass.

## Eliminated explanations

Each of these was a working hypothesis at some point. None survived.

**The hardware stats round trip is starving.** This was the first filed cause of
A140 and it is wrong. `gc_expired` incremented only on the two intended
idle-expiry rounds, by exactly 256 each — never once spuriously. The offload
deadline is being refreshed correctly. A backlog does exist (`wq_stats` peaked
at 67 in one round) but it retires nothing.

**The adapter is invalidating handles.** `neighbour`, `route`, `mtu`, `link` and
`mac` invalidation counters stayed at zero across every pass. `gc_hw_invalid`
moved 0-4 per round, tracking ordinary admission contention (`rtnl_trylock`
failing in `cdx_ft_admission_begin`), which is the documented retry path.

**Conntrack table pressure is evicting entries.** `early_drop`, `insert_failed`,
`drop` and `clashres` in `/proc/net/stat/nf_conntrack` are zero for the whole
boot. `nf_conntrack_max` is 262,144 against a workload of ~16,390.

**The conntrack is never refreshed after offload.** `flow_offload_add`
(`net/netfilter/nf_flow_table_core.c`) calls `nf_ct_offload_timeout` on the way
in, which sets the conntrack to `NF_CT_DAY` immediately. It does not wait for
the conntrack GC to come around.

**It happens continuously at steady state.** In a quiet ten-second window at
full occupancy with no churn, every GC counter delta was zero and the table was
byte-identical. Retirement only accompanies churn.

**A hash-index defect in the 32,768-direction rework.** Audited against the
adapter's cookie and key indexes: identical key expressions at insert and
lookup, node-local `hash_del`, no resize or rehash, identity written once
before insertion. The data refutes it independently — a wrong-slot eviction is
protocol-blind, yet with ~8,100 live TCP and ~8,100 live UDP connections, every
single casualty was UDP.

## Traps

Four things silently produce wrong answers here.

**`/proc/net/nf_conntrack` omits the timeout column for offloaded conntracks.**
`ct_seq_show` guards it with `if (!test_bit(IPS_OFFLOAD_BIT, ...))`, so every
subsequent field shifts left and a naive `$5` reads `src=...`. The population
under investigation is exactly the population whose timeout is hidden. Use
`conntrack -L` (ctnetlink dumps `CTA_TIMEOUT` regardless of offload).

**The flow cookie is a recycled address.** `nf_flow_table_offload.c` sets
`cls_flow->cookie = (unsigned long)tuple`, so a readmitted flow can reappear
under its predecessor's cookie and a cookie diff will miss it. The adapter
already guards this with an `-ESTALE` check on a matching cookie with a
different handle. Detect a new generation by a restarted packet count as well.

**A settling retry hides the phenomenon.** `settled()` resamples until the key
set matches, which is right for reading a coherent snapshot and wrong for
measuring turnover — it converts a flow cycling through software into a clean
reading. It now reports what it had to retry through.

**A window sampled right after warmup proves nothing.** Every flow's deadline is
fresh, so no flow is near expiry and the window is quiet by construction. The
first pass that ever reached a *post-churn* quiet window was the one that
exposed this.

## Root cause — 2026-09-16

Complete, unsuppressed tracing over all 16,384 connections (19,403 lines, zero
rate-limited) shows one pattern behind 78 of 82 deaths:

```
teardown  86332 -> 90     old flow retires, conntrack cut to 90s
admit       119 -> 86400  new flow on the same tuple restores NF_CT_DAY
teardown  86399 -> 90     old flow's teardown clears IPS_OFFLOAD again
reap                      113s later, conntrack dead, live flow retired
```

Closing and reopening a tuple leaves two flows sharing one conntrack for
0.22-2.59 seconds, median 0.48. `flow_offload_teardown` clears
`IPS_OFFLOAD_BIT` and applies `flow_offload_fixup_ct` to `flow->ct` without
checking whether the conntrack still belongs to the flow being retired, so the
retiring flow poisons the surviving one. From then on `gc_worker` will not
refresh that conntrack — it tests bit 14 — and traffic cannot refresh it
either, because the surviving flow is forwarded in hardware and no packet
reaches `nft_flow_offload` to set the bit again. `status=0x819e` at the reap
confirms bit 14 clear while bit 15, `IPS_HW_OFFLOAD`, is still set.

Only UDP dies because the fixup leaves established TCP 431,880 seconds against
UDP's 90. The mid-run teardowns all come from `nf_flow_offload_gc_step`; the
much larger `nf_flow_table_do_cleanup` population is the flowtable being freed
at the end of the run and is unrelated.

The fix is to make the conntrack offload bit owned: record on the flow whether
its own admission set the bit, and let only that flow clear it and apply the
fixup. Widening `nf_conntrack_udp_timeout_stream` enlarges the window without
closing it.

## Measured cause — 2026-09-15, tracing image

Temporary printks at the three offload lifecycle transitions settle the
mechanism. They were removed once the cause was fixed; the per-cause
retirement counters in patch 141 remain.

`flow_offload_teardown` cuts the conntrack's remaining life from a full day to
ninety seconds and, in the same function, clears `IPS_OFFLOAD` — the bit whose
presence is the only reason `gc_worker` was topping that timeout up:

```
ASKDBG teardown proto=17 sport=27612 status=0x819a expires 86229 -> 90
```

Ninety seconds later the conntrack is reaped, with `IPS_OFFLOAD` (bit 14) clear
and `IPS_HW_OFFLOAD` (bit 15) still set — precisely the combination
`gc_worker`'s rescue does not cover, because it tests bit 14:

```
nf_conntrack: ASKDBG reap proto=17 sport=20229 status=0x819e
```

The reaped tuples belong to a group churned much earlier in the run, not to the
group being retired when they die. Retirement causes for the boot were
`gc_dying` 1898, `gc_expired` 512 (the two intended idle-expiry rounds),
`gc_hw_invalid` 48 and `gc_custom` 0 — conntrack death outweighs every other
cause three to one.

So each teardown lights a ninety-second fuse on its conntrack and disables the
refresh that would defuse it. When the fuse burns out the conntrack dies, which
retires the flow now occupying that tuple, which lights another fuse. That is
why turnover grew across successive runs on one boot (74, 98, 110) and why only
UDP is affected: the same fuse for established TCP is 432,000 seconds.

The remaining question is narrow. Readmission should defuse it —
`flow_offload_add` calls `nf_ct_offload_timeout`, which restores a day from any
value below half a day. The `add_fail` probe never fired, so the add never
failed. Either it is not reached, because `nft_flow_offload` returns early when
`test_and_set_bit(IPS_OFFLOAD_BIT)` finds the bit already set, or it is reached
and the refresh does not survive. Two more printks answer that; it is not a
question for another theory.

## Where it stands

The conntracks are neither evicted nor deleted by the test, and they die while
their flow is live and forwarding in hardware. The surviving suspicion is the
short timeout that `flow_offload_fixup_ct` restores on teardown not being
lifted again on readmission. It fits the UDP-only incidence — a replied UDP
stream times out in 120 seconds against five days for established TCP — and it
fits the observation that one round's casualties were all drawn from the group
churned eight rounds earlier. It is unverified, and the two prior causes in
this document were also plausible before they were measured.

The next measurement is a conntrack `DESTROY` event capture correlated with the
round timeline, plus a `conntrack -L` timeout histogram at steady state. If a
subset of offloaded UDP conntracks sits near 120 seconds while the rest sit near
a day, the victims are identifiable before they die. No fix should be written
before that lands.

Artifacts on `vision`: `/tmp/ask-flowtable-churn/` holds the per-round records,
counter snapshots and logs for every pass described here. These are bench files
and are not preserved.

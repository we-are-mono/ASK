# Flowtable resilience testing

Status: controller reconciliation, bounded nft execution and controller crash
supervision implemented 2026-09-21; broader fault coverage remains planned.
This document separates that implementation from the
remaining recovery requirements. Hardware validation is recorded below.

The objective is to prove both safe behavior during a failure and automatic
return to the desired service after recovery becomes possible. The scope is
native Linux flowtables, the ASK adapter/CDX backend, and their production
control plane, including interactions with IPsec, multicast and QoS. CMM is
being retired; new coverage must use the native interfaces.

## Recovery contract

| Condition | Required behavior |
| --- | --- |
| Transient allocation, admission or apply failure | Preserve policy and resource safety; retry automatically after the fault clears and restore eligible hardware forwarding within a defined deadline. |
| A route, interface, VLAN, neighbour or other prerequisite is unavailable | Retire stale hardware, follow Linux forwarding/drop behavior, preserve unaffected traffic where possible, and accelerate again when the responsible configuration owner restores the prerequisite. |
| Acceleration is intentionally disabled or stopped for maintenance | Respect the stop. Recovery must not race firewall updates or recreate admission while an authorized stop is in effect. |
| Desired configuration is malformed | Reject it and report the error. Follow the existing transaction contract for preserving the previous policy or leaving acceleration disabled; do not invent configuration or restore an obsolete security policy. Recover when valid desired configuration is supplied. |
| Another owner controls a table or backend binding | Refuse the conflict and report it; do not take ownership by deleting foreign objects. Reconcile when the conflict is legitimately resolved. |
| Hardware deletion cannot be proven | Fence unsafe hardware and preserve diagnostics. The current fatal-state contract requires provider teardown and a fresh boot; automatic restoration would require an explicitly implemented, bounded reset/reboot policy. |

Automatic recovery cannot make an invalid topology valid or repair a permanent
hardware fault. Its responsibilities are to reach a safe state, report why
service is degraded, and converge when prerequisites permit it. Zero packet
loss is not a universal requirement: each scenario needs a measured outage/loss
budget. Firewall, isolation and IPsec requirements remain mandatory throughout.

The controller owns only its admission table and backend lifecycle. It must
not recreate deliberately deleted routes/VLANs, change firewall permissions,
or bring back an intentionally disabled feature. See the
[policy transaction and revocation contract](flowtable-policy.md#firewall-ordering-and-revocation).

## Controller reconciliation — 2026-09-21

The controller now checks policy and observed backend health every five
seconds, with interface-triggered checks and retries capped at 30 seconds.
It repairs missing owned tables and invalidated bindings even when the desired
configuration hash is unchanged. Healthy checks leave working tables intact.

Manual `apply` and `stop` retain authority through a pause under the same lock
as reconciliation. `resume` hands authority back to the daemon's configured
policy; it does not select a candidate or certify that recovery has finished.
The pause survives process restarts, protecting temporary policies and firewall
maintenance. See the [command contract](flowtable-policy.md#automatic-recovery-and-manual-control).

[Host regressions](../tools/host_tests/test_flowtable_recovery.py) exercise the
real C controller, process I/O and locks under ASan/UBSan with isolated nft and
backend boundaries. The original controller failed all three initial cases:
quiet apply failure, missing table and invalidation. Additional cases cover
healthy no-ops, disable/malformed policy, manual ownership, foreign objects,
inspection errors, inactive/fatal providers, queued stops and event storms.

The [DUT service suite](../tools/tests/test_flowtable_service.py) uses the actual
boot service and configuration, surviving TCP/UDP sockets, new connections and
negative firewall probes. It requires controller readiness within 12 seconds
and completed directional hardware-counter proof within 35 seconds of fault
injection. The maintenance test explicitly resumes after proving that stop
survives a service restart; autonomous fault cases issue no repair command.

Expanded failslab coverage and fatal hardware reset policy remain outstanding.
The one-shot nft failure in this first DUT suite is a controlled process failure,
not an allocation-failure coverage claim.

Validation on the rebuilt, staged non-KASAN image (controller-only changes):
202 host tests passed, including 21 controller recovery cases under ASan/UBSan
and four service authority/exit-status cases. The four new DUT service cases
and two existing default-on/startup cases passed in 232.15 seconds.
The two existing live-policy revocation/foreign-ownership cases also passed
(73.88 seconds). Maintenance was repeated with an explicit PID-change
assertion (42.51 seconds): the replacement daemon preserved the pause.

| Injected fault | Controller ready | Directional hardware proof completed |
| --- | ---: | ---: |
| Missing owned table | 5.30 s | 14.68 s |
| Backend invalidation with unchanged policy | 5.51 s | 14.89 s |
| One failed nft commit | 7.03 s | 16.43 s |

The hardware proof includes a timed traffic window after admission; its
completion time is not a claim that forwarding was unavailable until then.
Existing TCP/UDP sockets survived, new connections offloaded, forbidden UDP
never reached the WAN receiver, and teardown balanced resources without new
backend errors. Maintenance stop stayed in effect across service restart
until explicit resume. Image/build logs, JUnit results, counter snapshots and
UART transcripts are under `/tmp/ask-flowtable-resilience-20260921/` on the
development host.

## Bounded nft execution — 2026-09-21

Every inspection, check, install and delete now has a five-second execution
deadline. A guardian pumps stdin and combined output concurrently and kills
and reaps the job on deadline or controller death. It handles descendants
that retain pipes or the transaction lease, including children that detach
from the original process group. Only complete, bounded output can be parsed.

The controller allows one further second for cleanup, then reports uncertainty
if cleanup remains incomplete. The guardian keeps the lease until every child
has exited; an unkillable kernel task cannot authorize a replacement. A timed
out invocation ends the current transaction. Subsequent reconciliation observes
the real table: a committed policy whose reply was lost stays installed if
healthy, while an uncommitted attempt is retried. Manual apply still preserves
the pause, including after a lost reply. See the
[process and transaction contract](flowtable-policy.md#firewall-ordering-and-revocation)
for Linux dependencies and failure semantics.

The [process fault tests](../tools/host_tests/test_flowtable_nft_process.py)
exercise input backpressure, output before input, silent/continuous-output
hangs, closed output with a live child, oversized output, early exit, partial
errors, pipe-holding and detached descendants, controller death, and delayed
cleanup retaining the lease after a bounded caller return. The real-controller
tests also verify automatic retry and inspection after a committed transaction
loses its reply. These run under ASan/UBSan. The original implementation failed
the delayed-writer regression by waiting for and committing the old transaction.

The DUT service suite adds a hung wrapper with a detached delayed writer and a
successful real commit followed by a hung reply. Recovery must occur within
20 seconds, retain the service PID and boot, reap every injected process, and
pass hardware checks for existing TCP/UDP sockets and a new TCP flow, plus
forbidden-traffic checks.
Neither autonomous case issues a repair command. Hardware proof must complete
within 35 seconds. Controller crash supervision is covered separately below.

Validation: all 218 host tests passed (70.04 seconds), including 37 controller
and process fault cases under ASan/UBSan. All controller sources compiled
warning-free with GCC 15.2. After rebuilding and staging the non-KASAN image,
all eight DUT service/default-on/startup cases passed (356.78 seconds).

| Injected fault | Controller ready | Directional hardware proof completed |
| --- | ---: | ---: |
| Hung install with a detached delayed writer | 12.21 s | 23.03 s |
| Committed install with a hung reply | 10.14 s | 21.00 s |

Both cases retained daemon/boot identity, reaped the injected processes,
preserved existing sockets, offloaded a new connection, blocked forbidden
traffic and balanced resources on teardown without new backend errors. The
lost reply required no duplicate install. The DUT was restored to a fresh
default-policy boot. Evidence, image identities, source hashes and logs are
under `/tmp/ask-flowtable-nft-deadlines-20260921/` on the development host.

## Controller crash supervision — 2026-09-21

The shipping service supervises one foreground controller. Unexpected exits
restart with 1/2/4/8/16/30-second capped backoff, resetting after 60 seconds of
stable uptime. Lifecycle commands use a protected control socket and separate
control/supervisor locks; PID files are never used to authorize signalling.
Only one controller can hold the daemon lifetime lock. The supervisor checks
the offload owner before spawning and idles while flowtable ownership is absent.

Service stop disables respawning before terminating and reaping the controller,
then performs the existing pause-and-drain transaction. Worker crashes and
service restarts preserve manual pauses. A failed drain remains an error; it
does not silently restart admission. Killing the supervisor kills its worker
through a parent-death signal; automatically replacing the supervisor itself
still requires PID 1 supervision, which the current BusyBox image does not
provide. The nft guardians independently retain transaction cleanup authority.

The [supervisor host tests](../tools/host_tests/test_flowtable_supervisor.py)
exercise crashes at retirement/install/commit boundaries, unexpected zero
exits, paused-worker crashes, stop during backoff, concurrent lifecycle calls,
stale PID files, inactive ownership, capped/resetting crash delays, failed drain,
supervisor death and a stalled logger. Both ASan and UBSan diagnostics are
retained even for automatically restarted workers.

The DUT wrapper kills the actual controller after real table deletion, before
installing its replacement, or immediately after a successful real commit. It
records ancestry, stage and backend state. Each test publishes a valid changed
policy to initiate replacement, then only observes and sends traffic after the
crash. Recovery requires the same supervisor and boot, one replacement worker,
the new policy hash, retired old writers, existing TCP/UDP sockets, a new
hardware TCP flow and blocked forbidden traffic. A committed healthy replacement
must not be installed twice. Readiness is required within 20 seconds and a
completed hardware-counter proof within 35 seconds of publishing the policy.
Separate maintenance checks crash a paused worker and prove an intentional
service stop stays stopped; restarting the service preserves the pause.

Host validation: all 234 tests passed (96.44 seconds), including 16 new
supervisor cases under ASan/UBSan. All controller sources compiled without
warnings under GCC 15.2. Independent review also exercised 24 overlapping
lifecycle commands, repeated controller crashes, supervisor death and the
stalled-logger regression.

Hardware validation used the rebuilt and staged non-KASAN image. All 12
service/default-on/startup cases passed (589.74 seconds). After making the
test's policy publication atomic, all three crash cases passed again
(170.49 seconds) on the same boot:

| Controller killed | Controller ready | Directional hardware proof completed |
| --- | ---: | ---: |
| After real table deletion | 7.09 s | 17.80 s |
| Before replacement install | 7.53 s | 18.33 s |
| After successful replacement commit | 6.60 s | 17.31 s |

Each crash replaced exactly one worker under the same supervisor, retired
the old transaction processes and recovered without harness repair. Existing
TCP/UDP sockets survived, a new TCP connection offloaded and forbidden traffic
remained blocked. Paused-worker crashes and explicit service restarts preserved
the pause; intentional service stop remained stopped.

The DUT remains on boot `f507eb7a-2f08-4df9-90da-7946d9d7fa93`, with the normal
policy resumed and test-owned faults removed. Final accumulated installs and
deletes both equal 142, with zero entries, handle/neighbour references, backend
errors, quarantine or fatal state. One rearm records the intentional invalidation
test. Kernel taint remains the out-of-tree baseline of 4096, with no kernel
splats. There was no cleanup reboot or counter reset. Evidence, image/source
identities, logs and final state are under
`/tmp/ask-flowtable-supervision-20260921/` on the development host.

The final audit retained the existing kmemleak report without clearing it or
forcing another scan. Its 15,977 objects all have boot-time DPAA/CDX buffer-pool
allocation stacks, consistent with the hardware-owned pool baseline. This is
not an allocation-failure sweep or a general leak-free claim.

## Coverage before this slice

The following observations motivated the work:

- [`cmd_daemon()`](../flowtable/src/main.c) previously waited indefinitely for
  interface events, retried failed applies only on later events, and skipped
  unchanged desired hashes without checking observed backend health. The first
  slice replaces those decisions with reconciliation.
- The [boot service](../meta-ask/recipes-ask/config/files/S50ask-flowtable)
  previously backgrounded the daemon once with `start-stop-daemon`. The
  supervisor now replaces crashed controllers.
- [Flowtable fault tests](../tools/tests/test_flowtable_offload.py) already
  exercise add failures, invalidation/rearm and terminal deletion failures.
  Their explicit table recreation and cleanup prove those operations, rather
  than autonomous service recovery. Global invalidation deliberately requires
  a fresh binding/reconciliation boundary; recovery must preserve that barrier.
- The [homelab profile](../tools/tests/test_profile_homelab.py) explicitly
  reapplies policy after VLAN invalidation. That is useful lifecycle coverage,
  but does not establish that the running service repairs itself.
- The [IPsec failslab sweep](../tools/tests/test_ipsec_failslab.py) exercises
  native XFRM installation with isolated `fail-nth` injection. It is a useful
  pattern for allocation coverage, with additional recovery assertions needed.

Keep the existing low-level tests. Add a separate service resilience suite
that leaves the shipping daemon running and uses the real desired policy.
Fixtures that stop the daemon and construct their own table cannot prove this
service contract.

## Scenario priorities

Start with deterministic cases that expose missing recovery mechanisms.

| Priority | Scenario | Main assertion |
| --- | --- | --- |
| First | Fail one apply, then leave interfaces quiet | Retry succeeds without a new interface event or a test-issued apply. |
| First | Delete the owned admission table while desired configuration is unchanged | The service detects the missing table and safely restores the enabled policy. |
| First | Leave the policy installed but globally invalidate the backend | The service detects stopped admission and performs the required safe reconciliation. |
| First | Kill the daemon during drain/install and immediately after nft commit | Product supervision restarts it; observed state determines recovery, and an older transaction cannot commit after a newer owner. |
| Next | Fail allocations during binding, flow admission, neighbour tracking, XFRM installation and multicast updates | Rollback balances resources; subsequent valid operations and hardware admission succeed. |
| Next | Lose a netlink reply, hold the apply lock temporarily, or fail an nft operation | Recovery distinguishes an uncommitted operation from a committed operation whose reply was lost, and retries safely. |
| Next | Remove/recreate VLANs, flap links, change routes/neighbours, and exhaust/release admission resources | Stale forwarding stops; unaffected traffic follows its contract; eligible flows return to hardware after prerequisites recover. |
| Next | Supply malformed policy, disable policy, request maintenance stop, or introduce foreign ownership | Recovery respects intent and ownership; it resumes only when the relevant blocking condition is resolved. |
| Later | Repeat faults, combine events in recorded sequences, and restart with incomplete runtime state | No cumulative leak, retry storm, stale state or dependence on a pristine fixture. |
| Separate destructive suite | Force unproven hardware deletion or an unrecoverable backend failure | Hardware is fenced, evidence survives, and the defined reset policy runs with a retry/boot-loop limit. |

Deleting the owned table is a deliberate fault test. It does not make arbitrary
external edits to that table a supported interface. Its configuration-hash
comment is not a tamper detector; checking the hash alone cannot validate
arbitrary rule contents.

## Allocation and hardware fault injection

Sweep deterministic failure positions before adding probabilistic stress.
For each operation, fail successive eligible allocation points, record whether
the fault was consumed, and attribute the failure to the intended path. A
refusal somewhere in a netlink/crypto allocation prefix is not evidence that
every adapter allocation was exercised.

Linux provides per-task `fail-nth` injection, slab cache/stack filters, and
separate page-allocation injection. `fail-nth` counts eligible fault points
and can affect more than slab allocation; record the enabled capabilities and
filters. Follow the [kernel fault-injection documentation](https://docs.kernel.org/fault-injection/fault-injection.html)
and verify which facilities the built DUT kernel supports.

Per-task injection in the request sender does not follow asynchronous work
onto another worker. Flow installation and multicast learning need coverage
in the context that performs the work. Use narrowly scoped allocation hooks
or suitable filters, with hit counters or traces proving the target was
reached. Avoid broad injection that primarily breaks the test agent.

Keep explicit hardware failure hooks as well: failslab does not model every
DMA/resource allocation, programming, synchronization or deletion failure.
The existing one-shot `flowtable_fail_stage` and terminal unlink hooks are
starting points. Inject errors through the real failure/unwind path, including
partial programming, rather than merely setting a final status flag.

For every covered point, require safe unwind, no invalid references or growing
resource debt, and successful operation after injection stops. A missing ACK
must trigger inspection of actual state before retrying or deleting an object.
Run memory-path sweeps on a KASAN image and use resource accounting/kmemleak
where applicable; absence of a crash alone is insufficient.

## Test protocol and pass criteria

1. Establish the real desired policy through the production service. Record
   image/module identities, boot ID, policy, topology and backend health.
2. Establish permitted traffic and prove directional hardware activity. Keep
   an unaffected control flow and negative probes for forbidden traffic.
3. Inject one named fault and prove it fired. Exercise both existing
   connections and attempts to establish new connections during the fault.
4. Assert the scenario's behavior while degraded: correct forwarding/drop
   policy, no stale destination or plaintext IPsec bypass, bounded resources,
   and no unexpected kernel diagnostics.
5. Remove only the injected fault or restore its missing prerequisite. Leave
   repair of the flowtable integration to the production components.
6. Wait for observable recovery within the scenario's deadline. Check service
   state, bindings/admission, actual hardware packet deltas in both directions,
   application traffic, and resource balance after quiescence.
7. Repeat to expose accumulation. Preserve a failure snapshot before teardown.

The harness must not call `apply`, restart the daemon, recreate its table or
reboot the DUT to make the recovery assertion pass. Product-issued retries,
supervised restarts and a specified product reboot policy are the behavior
under test. Harness rescue remains available after failure and is recorded
as a failed recovery, not a pass.

Define per-scenario detection, recovery and traffic-loss budgets before making
the tests gating. Use monotonic deadlines and state polling rather than fixed
sleeps. Measure recovery from the relevant point: fault occurrence for
detection, and fault removal/prerequisite restoration for convergence. Record
retry counts and distinguish time spent blocked from time spent recovering.
An unconsumed injection is missing coverage, not a successful fault test.

Exercise IPv4/IPv6 and TCP/UDP, then representative NAT, bridge/VLAN, PPPoE,
IPsec and multicast paths according to their feature contracts. Existing
sockets should survive recoverable transitions where the contract preserves
conntrack; a reboot has a separate connection-loss expectation. Multicast
checks must include absence of traffic on removed listeners.

For QoS, target approximately **2 Gbit/s** and offer traffic well above the
cap, for example 6 Gbit/s on this bench. This is below the roughly 9 Gbit/s
line rate and above software forwarding capacity. After recovery, require
delivery near the configured cap plus hardware admission and packet/drop
counters. During software fallback, apply the correctness and outage budget;
do not require 2 Gbit/s from the CPU. See the [QoS guide](flowtable-qos.md).

## Product work implied by the tests

- Reconcile desired configuration with observed table and backend health.
  Combine relevant events with periodic checks and bounded retry backoff so
  quiet periods and lost events cannot strand the system. Healthy checks must
  leave working tables alone.
- Reuse the existing serialized validate/drain/install/verify transaction.
  Preserve kernel invalidation and fatal-state barriers; do not clear latches
  to manufacture apparent health.
- Define maintenance-stop ownership/inhibition before adding retries. A
  reconciler must cooperate with firewall revocation and explicit disable,
  including across daemon restarts.
- Add crash supervision and observable recovery state: reason, last failure,
  attempts, last success, and whether progress is blocked by configuration,
  resource pressure or a fatal hardware condition.
- Specify reset escalation separately: diagnostics first, bounded attempts,
  restart/boot-loop protection, and an actionable terminal state if recovery
  remains impossible.

[Devlink health](https://docs.kernel.org/networking/devlink/devlink-health.html)
is a useful design reference for reporting errors, collecting diagnostics and
rate-limiting automatic recovery. The initial implementation can expose these
semantics through our existing status/control plane; adopting devlink is not a
prerequisite for this suite.

## Execution and evidence

Implement host tests for reconciliation decisions and transaction races, then
run service recovery cases on the DUT. Build and stage the intended image
before hardware validation and verify the running identities. Keep allocation
sweeps, repeated/seeded fault sequences and terminal reset tests as distinct
groups so normal regression runs remain bounded.

Preserve independent UART rescue. Faults should be one-shot or have bounded
duration, with cleanup available outside the process being faulted. Do not
change persistent boot/TFTP settings as part of a runtime resilience test.

Store the scenario and seed/failure index, injection-hit evidence, timeline,
policy/topology snapshots, process/boot identities, backend/resource counters,
directional traffic measurements, kernel logs and any rescue action. Redact
secrets such as IPsec key material. After a pass or captured failure, remove
test-owned state and verify the intended policy before the next case. Keep the
DUT on the same boot after validation, preserving accumulated runtime state
and counters for subsequent tests. Do not reboot merely to obtain a clean
baseline. Booting the rebuilt image before testing and a separately justified
terminal recovery reset are distinct operations; record their reasons and
boot identities.

The next deliverable is deterministic allocation-failure coverage, followed by
repeated fault sequences and missing-prerequisite recovery tests. Keep
this document's status and evidence current as each recovery guarantee is
implemented and verified.

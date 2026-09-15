# Route retirement: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

Committed IPv4 prefixes and the separate nexthop-object API.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## Selective IPv4 route retirement — verified 2026-09-15

This increment extends the existing shared invalidation handle and retirement
worker to committed IPv4 route-prefix changes. It keeps the 64-direction limit,
the no-NAT IPv4 TCP/UDP admission contract, and the existing firmware interface.
CDX matches both endpoints against the changed prefix across all routing tables
and DSCP aliases. This is deliberately conservative within a prefix and does
not claim complete policy-routing or device dependency tracking. Policy,
nexthop-object and device events retain whole-table invalidation.

`test_flowtable_routes_selective` creates two routed LAN peers, each with UDP
and a persistent TCP connection, for eight hardware directions. It proves:

- Replacing peer A's route changes its return MTU from 1200 to 1100; adding a
  more-specific host route changes it to 1000; deleting that route returns to
  1100. Each transition retires A's four directions and admits fresh ones.
- Withdrawing A's route leaves a covering blackhole. A's hardware directions
  stay absent while its original TCP socket attempts traffic. Restoring the
  route allows that socket and UDP to return to hardware automatically.
- Adding and deleting a non-selected DSCP alias also retires A, although the
  native selected-alias FIB notifier omits that alias. Default-TOS traffic
  returns using its 1100-byte route. An identical replacement and rejected
  duplicate insertion leave all entries unchanged.
- Peer B keeps the same four cookies and increasing hardware counters throughout
  all six changes, with continuous validated UDP/TCP exchanges. The table is
  never recreated: `rearms=0`, twelve shared generations invalidated, and final
  cleanup has 32 installs/deletes, zero errors and zero retained references.

The first hardware run exposed a reverse-route lookup problem: forcing an
output interface let Linux synthesize an on-link route after the blackhole FIB
failure. A's TCP flow was admitted again during withdrawal. The corrected
kernel requires successful FIB lookup for the opted-in reverse path, before
creating either a software or hardware cached flow. The failed run is retained
under `proof/`; the complete passing run is under `proof-strict/`. The withdrawal
assertion and packet-delivery checks were not relaxed.

Initial and final eight-second steady windows validate 256 echoes per flow.
UDP hardware deltas are exactly 256 packets and 76,288 bytes in each direction;
each TCP connection transfers 4 MiB and advances its hardware counters. Software
TX deltas are 6/16 packets initially and 3/15 finally on LAN/WAN, with aggregate
softirq time 0.31% in both windows. Total measured CPU busy time is 27.28% and
23.76% respectively; these are instrumented-system measurements, not an idle-CPU
claim or a throughput benchmark.

Seven focused host tests pass with ASan/UBSan. They compile production driver,
handle, lookup and teardown functions and cover prefix boundaries, other
namespaces, partial directional admission, stale or absent routes in either
direction, shared references, policy/nexthop global fallback, and strict FIB
failure handling. The strict lookup test also verifies that successful routes
and ordinary callers' existing fallback behaviour remain intact.

Five focused DUT tests pass: the new route lifecycle and route retirement-failure
tests, selective neighbour recovery, UDP gateway recovery, and global rearm.
Gateway replacement now recovers without table recreation. The rearm test uses
a routing-policy rule for its global routing trigger, alongside device MTU
change and an injected barrier failure. A failed selective route retirement
correctly escalates to global invalidation, drains all eight directions and
their references, preserves software forwarding, and permits healthy rearm.

Final state is 76 installs and 76 deletes, four expected errors from the two
deliberate two-failure barrier injections, and four rearms. Entries, bindings,
neighbour references, handle references, quarantine, fatal and invalidation
state are all zero. Test routes, policy rule, namespaces, NAT exemptions and
fault knobs are removed; endpoint configuration and NUD settings are restored.
There are no KASAN, lockdep, warning or oops reports, and taint remains 4096.

The corrected KASAN image was built, staged and verified against the running
kernel/module and userspace binaries. Kernel build ID is
`3492e3327a061c274ca163522edfe1a33dec0bc5`; CDX build ID is
`2a5741b965312b93386f8460960532080d7eb936`. Staged image SHA-256 is
`2c185dbdc67ab43ab0d89dcd1c69f4450e3dc245829c2ceb99bc233fe5f964b8`.
KASAN, lockdep, kmemleak and failslab stayed enabled. Only focused tests ran;
there was no full KASAN suite or forced kmemleak scan. All five passing DUT tests
ran on the same experimental boot with CMM disabled.

From a clean experimental boot, reproduce the two new tests with:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 \
  ASK_FLOWTABLE_ARTIFACTS=/tmp/ask-flowtable-routes \
  make ask-test ASK_TEST_ARGS='-k flowtable_routes -x -q'
```

Artifacts are under `/tmp/ask-flowtable-routes/`: `proof-strict/`, `regression/`,
`barrier/` and `rearm/`, corresponding logs/XML, host results, image/source
identities and final restoration evidence. The initial failing route proof is
under `proof/`. Build logs are `/tmp/ask-flowtable-routes-build.log` and
`/tmp/ask-flowtable-routes-strict-build.log`.

Stop at this increment. Selective device dependencies and broader foundation
coverage remain separate work. This does not add NAT, IPv6, encapsulation or a
new firmware capability, and does not change the chosen per-boot owner.

## Nexthop-object retirement — verified 2026-09-15

Linux's nexthop-object notifier is separate from built-in FIB nexthop events.
The adapter now subscribes in init_net and treats every event except the
read-only hardware statistics query as global invalidation. This covers shared
objects and resilient groups conservatively, without claiming selective
member tracking. Registration and unregistration dump existing objects; the
binding/stopping guards prevent these dumps from poisoning a fresh adapter.
Initialization failure stage 6 covers this registration, preserving stage 5's
existing indirect-registration meaning. Unwind and unload remove the notifier
before releasing the provider claim.

Five focused host checks passed in 1.17 seconds. The DUT object test passed in
65.51 seconds: reload with an existing object, two-direction UDP and TCP hardware
forwarding, replace the WAN object with a blackhole, retire all four directions
and references, and verify no subsequent UDP delivery. Restoring the object
leaves both existing sockets forwarding in software with global admission still
closed. Explicit table recreation readmits those same connections. Each hardware
window verifies 256 exact UDP hits per direction and 4 MiB of TCP per direction.
Software TX deltas were 4/15 before replacement and 5/15 after recovery. Softirq
was 0.37%/0.38%; total busy CPU was 18.00%/24.85%, retained without attributing
that background load. Hardware counters and software TX independently establish
execution in the hardware path.

The module lifecycle regression passed in 113.01 seconds, including all six
failed-load stages, provider pinning, healthy and barrier-recovery unload,
persistent sockets, fresh binding, and eight live-traffic unbind cycles. Final
KASAN/lockdep diagnostics are clean, debug_locks is 1 and taint is 4096. Bindings,
entries and references drain to zero, installs equal deletes, and no backend
errors or quarantine remain. CMM stayed disabled. No full suite was run.

The KASAN image was built and staged, then running IDs were verified: kernel
`20956f5977ed9aaf15874a317e61941a4d816772`, CDX
`ed4251e6275e1ecbe06998b28203deb1a659b67a`, adapter
`a085496c134eedd293fe2a87a438e33a7bac5cb0`. Image SHA-256 is
`9735596756cd0b54240384386ef45940d177e57d2ed1fe605f17453e047490a6`.
Artifacts and focused test logs are in `/tmp/ask-flowtable-nexthop/`; build log
is `/tmp/ask-flowtable-nexthop-build.log` (three existing forced-task warnings).

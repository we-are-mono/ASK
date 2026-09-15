# Backend and adapter module: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

Provider extraction, module lifetime, dependency filtering and lock-order corrections.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## CDX backend interface — verified 2026-09-15

The adapter now calls the private interface in `cdx_flowtable_backend.h`.
`cdx_flowtable_backend.c` remains inside `cdx.ko` with the firmware encoder;
`cdx_flowtable.c` remains linked there for this increment too. Kernel patch 140
and firmware behaviour are unchanged. The next separately proved increment is
extracting `ask_flowtable.ko`, including module references and load/unload rules.
No separate module or runtime owner switching is provided by this increment.

CDX now owns the immutable owner/observe options, exclusive adapter claim,
physical-port validation, live hardware count, retirement quarantine and the
terminal failure latch. Releasing a claim cannot reopen configuration or clear
fatal failure. A claim is refused in CMM mode, while another claim exists,
while retirement is pending, or after terminal failure. Release is refused
while live hardware directions remain. The adapter keeps Linux flow decoding,
route/neighbour dependency tracking, per-flow handles, counters and invalidation
work. It no longer reaches CDX control/device structures or firmware functions.

Explicit begin/end operations delimit transactions, using the same CDX control
mutex and lock order as the proved implementation. They also serialize adapter
state, so this extraction adds no second mutex or new nested lock ordering.
Admission tries RTNL while the transaction is held; recovery does the same
before quiescing hardware. Netfilter flushing happens outside a transaction.
Backend operations never call back into the adapter. This is a private source
interface which can evolve with the repository, not a frozen binary ABI.

The configuration gate becomes permanent after the first successful claim.
The ioctl wrapper rejects new requests early, and `cdx_ioc_set_dpa_params`
rechecks under the control mutex before acquiring RTNL or changing hardware.
This covers a request which passed the wrapper before the claim and then waited
for the same mutex. Adapter initialization failure releases its claim and all
acquired registrations; successful teardown releases the claim only after work,
callbacks and live directions have drained. CDX final shutdown owns any retained
hardware storage after adapter teardown.

Eight focused ASan/UBSan host tests pass. The production backend and firmware
encoder are compiled together to check ownership, port identity, observe mode,
live-direction accounting, failed barriers, quiescence and fatal refusal across
release/reclaim. Production adapter initialization/exit is tested with every
acquisition failing in turn, plus active-flow teardown and CMM-mode initialization.
The production configuration ioctl test seals ownership while a request acquires
the mutex and verifies rejection before allocation or hardware work. Existing
flow decoding, selective retirement, handle lifetime and CDX shutdown checks pass.

Four focused DUT tests pass on the KASAN image:

- Mixed TCP/UDP selective route recovery, including withdrawal/restoration and
  preservation of the other peer's cookies and hardware counters.
- Mixed TCP/UDP selective neighbour recovery, including MAC change, unreachable
  neighbour and neighbour-object replacement, with the other peer preserved.
- Global rearm after device and routing-policy changes, plus two deliberately
  failed retirement barriers. Cleanup finishes at 60 installs/deletes, two
  expected errors, three rearms and no entries, bindings or retained references.
- Unproven deletion during traffic. The CDX backend stops receive ports 6 and 7,
  preserves the fatal latch and rejects rearm. State reaches 62 installs/deletes
  and three expected errors, with no retained adapter references or quarantine.
  The possibly linked hardware key is deliberately retained until reset. CDX
  unload succeeds and all 64 subsequent software echoes pass.

The final steady route and neighbour windows each deliver 256 echoes per flow.
UDP hardware deltas remain exactly 256 packets and 76,288 bytes per direction;
each TCP connection transfers 4 MiB with advancing hardware counters. Software
TX deltas on LAN/WAN are 3/15 and 14/15; aggregate softirq time is 0.28% and
0.41% respectively. Raw total CPU busy measurements remain in the artifacts;
these are forwarding checks, not a throughput or idle-CPU benchmark.

All four tests ran on one experimental boot with CMM disabled. There were no
KASAN, lockdep, warning or oops reports, including after terminal CDX unload;
taint remained 4096. The DUT was then rebooted into the same flowtable image to
restore hardware after the intentionally terminal test. No CMM-mode DUT test
or full KASAN suite was run, and no forced kmemleak scan was requested.

The image was built and staged with KASAN, lockdep, kmemleak and failslab enabled.
Live kernel/CDX and userspace identities matched the build. Kernel build ID is
`9cd99ee30eac7bfaeddb55944d89328674f0c831`; CDX build ID is
`6ddf22b19d33e8e5d08cc57b8194643c3d955661`. Staged image SHA-256 is
`b2417573622aa24a4acd6480152b29c66dd6b051cff0b3f27bc9b9316554e439`.
The build emitted no compiler warnings; its four warnings were existing
forced-task/build-path packaging diagnostics.

Artifacts are under `/tmp/ask-flowtable-backend/`: host logs/XML, `healthy/`,
`rearm/` and `terminal/` measurements and corresponding logs/XML, verified image
identities, pre-terminal restoration evidence and post-unload diagnostics. The
final boot's identity and restoration checks are recorded separately from the
acceptance boot. Build log: `/tmp/ask-flowtable-backend-build.log`.

Stop at this increment. The next step extracts the adapter into
`ask_flowtable.ko` and proves provider references, loading, unloading and recovery
using this interface. The code remains in `cdx.ko` until that separate proof.

## Loadable flowtable adapter — verified 2026-09-15

`cdx/ask_flowtable.c` now builds as `ask_flowtable.ko`. The firmware encoder and
backend stay in `cdx.ko`; the adapter imports only the private backend exports,
in the GPL-only `ASK_CDX_FLOWTABLE` namespace. Module metadata confirms dependencies
on `cdx` and `nf_flow_table`, while CDX has no flowtable-module dependency. The
image installs both modules and loads the adapter only for flowtable ownership.
Kernel patch 140 and the firmware encoding are unchanged.

Initialization claims CDX before publishing procfs or registering callbacks.
Every failure unwinds its acquired registrations and releases the claim. Exit
invalidates installed Linux flow handles, unregisters notifiers, cancels work,
drains indirect callbacks and completes hardware retirement before releasing
CDX. Recovery retries release the transaction between attempts. CDX's immutable
owner/observe options, configuration seal and fatal latch survive adapter reload.
Adapter counters are per module instance, so save diagnostics before unloading.

Verification exposed an existing race in ordinary indirect UNBIND: the callback
was moved from the live list to Netfilter's temporary list without excluding a
concurrent statistics worker. The worker followed that temporary list head and
attempted to call `ft_block_list` as code. The adapter now takes the flowtable
write lock before moving the callback, ahead of the CDX transaction, matching
the statistics path's lock order. Netfilter's later locked free alone did not
protect the move. The host regression asserts this exclusion; removing the new
lock reproduces its failure. The DUT regression recreates a live table eight
times while the same TCP and UDP sockets keep sending.

Sixteen focused host cases pass under the applicable ASan/UBSan harnesses. They
cover decoder/backend/handle/route behavior, CDX startup/shutdown, initialization
unwind, retirement retries, fatal reload refusal and six boot-loader cases.
The boot-loader cases cover CMM, flowtable, observe mode, invalid selection and
module load failures. Three focused DUT tests pass on the corrected KASAN image:

| Test | Verified result |
| --- | --- |
| `test_flowtable_module_lifecycle` | With inactive FCI removed, CDX unload is refused solely because `ask_flowtable` holds it. All five injected initialization failures leave no adapter, proc node or holder; the provider reference count returns to zero and a healthy load succeeds each time. SET_PARAMS remains rejected while the adapter is absent. |
| Same lifecycle test, live traffic | TCP and UDP continue across healthy unload/reload and a second cycle failing all four directional deletion barriers. The same TCP socket survives both. Software TX advances while the adapter is absent. Reload leaves the existing table in software; recreating it restores four hardware directions. Eight further live UNBIND/rebind cycles pass. |
| `test_flowtable_routes_selective` | Mixed TCP/UDP selective route replacement, more/less-specific routes, DSCP aliases and withdrawal/restoration still work. The unaffected peer retains its cookies and hardware counters. |
| `test_flowtable_offload_terminal`, `ASK_FLOWTABLE_TERMINAL=unlink` | An unproven deletion stops receive ports 6/7 and rejects rearm. Unloading the adapter succeeds, but reloading it returns `EOPNOTSUPP` while the same CDX remains loaded. CDX unload then restores ordinary forwarding; all 64 subsequent echoes pass. |

Steady hardware windows transfer 256 UDP echoes and 4 MiB over TCP per connection.
UDP hardware deltas remain exactly 256 packets and 76,288 bytes per direction.
After both reloads and the repeated UNBIND exercise, software TX deltas are
4 LAN / 15 WAN packets per window, with aggregate softirq time 0.37–0.44%.
During the two adapter-absent windows, software TX instead advances by thousands
of packets. Total CPU busy time varies and is retained in the artifacts; these
measurements establish the forwarding path, not a throughput or idle-CPU result.

Before the terminal test, the last adapter instance has 68 installs/deletes,
zero errors and no entries, bindings, neighbour/handle references or quarantine.
Terminal retirement reaches 70 installs/deletes and one deliberately injected
error, with no retained adapter references or quarantine. The possibly linked
hardware key remains intentionally retained until reset. The corrected image
has no KASAN, lockdep, warning or oops reports through post-unload inspection;
taint remains 4096. The three final tests use one experimental boot with CMM
disabled. No CMM-mode DUT test, full KASAN suite or forced kmemleak scan was run.

After terminal testing, the DUT was rebooted into the same verified flowtable
image. CDX, the adapter and inactive FCI are loaded; all adapter counters,
references and fault controls are clear. CMM remains stopped. DUT and host
routes, nftables rules, neighbour settings and LAN test resources are restored.

Both image builds succeeded and were staged. The final image has KASAN, lockdep,
kmemleak and failslab enabled; live kernel/module and userspace identities match
the build. Kernel build ID is `61857ba9b3856d272b47440a1d3ee777678bae8d`, CDX
`1c4d4bdbf8e81af9e88303923dec8f9035fd54ac`, adapter
`0d06de0feb46477172f1e5463c842ebd66d7d7b0`. Staged image SHA-256 is
`8668fe993aae99bf763f7cc0e35ab7a48e9154d8f3ecb045c2d285fa24cf067f`.
The final build has no compiler warnings and three existing forced-task warnings.

Artifacts are under `/tmp/ask-flowtable-module/`: `host-fixed.log`, `lifecycle/`,
`routes/`, `terminal/`, their logs/XML, image identities, provider metadata and
restoration checks. `*-before-unbind-fix` preserves the earlier run and kernel
fault; `unbind-negative/` preserves the host regression with the lock removed.
The first lifecycle attempt also records a corrected test setup error: the
injection hook applies only to deletion, so four directions consume four armed
failures; recovery syncs are real. Build logs are
`/tmp/ask-flowtable-module-build.log` and
`/tmp/ask-flowtable-module-fixed-build.log`.

Stop at this increment. Healthy reload requires flowtable recreation to resume
hardware admission; fatal hardware failure still requires reset. This extraction
adds no new traffic features or runtime ownership switching. Selective device
dependencies and broader foundation coverage remain separate increments.

### 2026-09-15: device dependency filtering

Unrelated interface changes no longer disable hardware admission. The adapter
watches every binding, including an empty one, and both physical devices of
each installed direction. An egress device remains a dependency even without
its own ingress binding. Matching compares referenced device objects, so reused
names or interface indices cannot inherit a previous device's dependency.
Binding mutations now share the existing dependency watch lock with notifiers;
event selection and invalidation happen in the same critical section, without
taking a backend transaction from a notifier. No new lock or backend ABI is added.

The first DUT run passed the forwarding assertions but failed its diagnostic
check: bringing an unrelated dummy interface down exposed a lockdep cycle.
Linux's DOWN notifier holds RTNL while flushing native flowtable work. That
work needs the flow-block lock and CDX control mutex, while CDX's existing
SET_PARAMS startup path had established the opposite control-mutex-to-RTNL
dependency. The new dependency watch lock was not part of this cycle.

Configuration and final teardown now acquire RTNL and try the control mutex.
On contention they drop RTNL, wait for the control mutex with no other lock
held, release it, and retry before changing state. This also accommodates the
legacy FCI control-to-RTNL path without introducing a blocking reverse edge.
The authoritative configuration gate is checked after both locks are acquired,
so a claim during the wait still seals the ioctl. Final shutdown stops the CDX
timer first, retaining its storage until its normal exit callback; port and
QoS cleanup retries then release both locks. The adapter's runtime admission
and recovery continue to use the existing backend transaction and RTNL trylock.

Thirteen focused host tests pass in 2.29 seconds, covering device selection,
unbound egress dependencies, object identity, rollback, ownership sealing during
lock contention, and shutdown retries with the timer stopped and both locks
available. Existing decoder, handle, route, startup and QoS lifecycle coverage
also passes. The test image now includes the already configured dummy module
for isolated interface-event tests.

On the rebuilt KASAN image, `test_flowtable_device_dependencies` passes in
83.89 seconds. One TCP connection and one UDP flow retain their four hardware
cookies through twelve unrelated changes: dummy creation, up, MTU, MAC,
bridge creation, upper attach/detach, down, rename, up under the new name,
unregistration while up, and bridge deletion. Every step advances all four
hardware packet counters without installation, deletion or rearm changes.
The TCP socket remains connected throughout the test.

Changing each real port's MTU separately retires all four hardware directions
and releases their handle/neighbour references. Both protocols continue through
Linux; restoring MTU and recreating the table resumes hardware admission.
Across the four measured hardware windows, each UDP direction advances exactly
256 packets and 76,288 bytes, and TCP hardware counters cover the validated
4 MiB transfers in each direction. Software TX advances only four LAN packets
and 15–16 WAN packets per window; the software fallback windows advance roughly
2,900 packets per port. Sampled aggregate softirq usage is 0.28–0.67%. Total CPU
busy usage varies from 2.28% to 27.01% on this instrumented image, so this proof
does not claim zero CPU usage; hardware counters and software TX establish where
the measured traffic was forwarded.

`test_flowtable_module_lifecycle` passes in 110.74 seconds. It covers all five
adapter initialization failures, provider pinning and persistent configuration
sealing, live healthy and barrier-failure unloads, software continuation and
readmission after table recreation, and eight live UNBIND/rebind cycles. Device
watches and all other adapter references drain on each removal. Both focused
DUT tests finish without KASAN or lockdep reports.

The third focused DUT test, `test_flowtable_offload_terminal` with
`ASK_FLOWTABLE_TERMINAL=unlink`, passes in 27.18 seconds. An injected unproven
deletion stops both physical receive ports, refuses table rearm and adapter
reload, and retains the fatal latch until CDX unload. Final provider shutdown
completes with the timer stopped, and 64 software echoes pass afterward.
Post-unload dmesg has no KASAN, lockdep, warning or oops reports, lockdep remains
enabled (`debug_locks: 1`), and taint remains 4096 for the out-of-tree modules.

Both KASAN image builds succeeded and were staged. The corrected image's kernel
build ID is `d320991b5e8736f0f657bd3224a298f74e405a1a`, CDX
`c6c0f308d581d77ef1047ea1dcc68ab53b1802d5`, and adapter
`498b29824dd5837f4254e3e93d82fb68d55fa1ab`. Staged image SHA-256 is
`93571aeea152a56f7b2fed6758d4a8c1689bb6b1f2602fbbfa4879cc7886d6a1`.
KASAN, lockdep, kmemleak and failslab remain enabled. The build has no CDX
compiler warnings and three existing forced-task warnings. Only focused tests
ran; the full KASAN suite was not run.

Artifacts are under `/tmp/ask-flowtable-devices/`: `host-locks.log`, `proof/`,
`module/`, `terminal/`, their logs/XML, image identities, and post-unload
diagnostics. `first-image-lockdep/` preserves the failed diagnostic run and its
full dependency report. Build logs are
`/tmp/ask-flowtable-devices-build.log` and
`/tmp/ask-flowtable-devices-rebuild.log`.

The final fresh flowtable boot matches the staged kernel, modules and userspace
binaries. CDX and the adapter are loaded, CMM remains stopped, and counters,
bindings, references, quarantine and fault controls are clear. Both physical
MTUs are restored to 1500; test interfaces, routes and firewall rules are gone,
and host/LAN settings are restored. Final diagnostics remain clean with lockdep
enabled and taint 4096. `final-state.json` and `final-dmesg.txt` record this state.

Stop at this increment. Recognized changes to a relevant device still retire
the whole table and require recreation; automatic recovery after real-port
changes and down/up cycles remains a separate increment. This adds no VLAN,
bridge, tunnel or other traffic support, and does not change owner selection.

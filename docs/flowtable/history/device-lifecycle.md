# Physical device lifecycle: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

MTU, administrative state, MAC, rename, unregister and terminal restart safety.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## Automatic physical-port MTU recovery — verified 2026-09-15

MTU changes now invalidate only installed flow generations using the changed
device as ingress or egress. The existing shared handle invalidation and
retirement worker remove both hardware directions, stop cached Linux lookup,
and let native flowtable GC retire that generation. Bindings remain available;
fresh packets on the same connection can create a generation with current
routes and MTUs. This needs no table recreation, adapter reload, new recovery
gate or additional kernel patch. Other relevant device events remain global.

The pinned kernel's IPv4 `fib_netdev_event()` handles `NETDEV_CHANGEMTU` by
synchronizing route MTUs and flushing the route cache under RTNL. Admission
already revalidates both borrowed destinations after obtaining RTNL. A queued
request with stale context is therefore refused before allocation, including
when only its reverse route became stale. This dependency must be retained or
replaced explicitly when updating the kernel. Empty bindings have no installed
MTU state to retire. Diagnostics add `mtu_invalidations`, counting a shared
generation once even when both directions match or notifications repeat.

The handler never clears global invalidation or CDX's fatal latch. A retirement
barrier failure still escalates to the existing global recovery boundary; an
unproven unlink still stops classification and requires a hardware reset.

Five focused host tests pass in 1.12 seconds. ASan/UBSan exercise the production
adapter and hardware lifecycle, handle ownership and kernel route checks.
New cases cover UDP/TCP, ingress and unbound egress dependencies, empty bindings,
same-ifindex objects and other namespaces, repeated notification, stale reverse
routes, fresh MTU admission, global/fatal latch preservation, retirement errors
and shutdown without queuing new retirement work.

Three focused tests pass on the staged KASAN image:

| Proof | Result |
|---|---|
| Automatic MTU recovery | `test_flowtable_mtu_recovery`, 88.41 seconds. One persistent TCP connection and one UDP tuple survive 1500 → 1400 → 1500 on each real port. The nft flowtable object and handle remain unchanged throughout. Each transition retires exactly four hardware directions, invalidates two generations, installs four current directions and leaves global rearm at zero. |
| Global recovery boundary | `test_flowtable_offload_rearm`, 23.17 seconds. Rename, routing-policy change and injected retirement-barrier failures retain their global recovery boundary. MTU decrease/restore cannot reopen any of them. Table recreation then restores hardware forwarding, with 512 strict echoes and exactly 512 hardware hits per direction in each cycle. |
| Fatal retirement boundary | `test_flowtable_offload_terminal` with `ASK_FLOWTABLE_TERMINAL=unlink`, 26.89 seconds. MTU decrease/restore on each physical port leaves the fatal latch set and both physical receive ports disabled while traffic is active. Table rearm and adapter reload remain refused. CDX unload completes and 64 software echoes pass afterward. |

The MTU proof uses fixture-owned routes without a fixed MTU override. After
each transition, an eight-second hardware window delivers 256 UDP echoes and
4 MiB of validated TCP data in each direction. Each UDP hardware counter
advances exactly 256 packets and 76,288 bytes. Software TX advances only three
LAN packets and fourteen WAN packets per window; aggregate softirq usage is
0.31–0.41% and total busy usage is 2.18–4.07% on this instrumented image.
The TCP socket stays open across all four transitions; its serial payload
validation and the unchanged flowtable identity rule out reconnect/recreation
as the recovery mechanism.

The same table and UDP tuple then verify actual firmware packet-size limits.
At WAN MTU 1400, 256 datagrams with IP length 1400 advance each hardware
direction by exactly 256 packets and 361,984 Ethernet bytes. A same-tuple DF
packet with IP length 1401 produces ICMP type 3/code 4 advertising MTU 1400 and
never reaches the WAN echo endpoint. After restoring WAN MTU 1500, IP length
1460 advances each direction by 256 packets and 377,344 bytes. Both size windows
have zero LAN software TX and eight WAN software TX packets.

The first run failed the final large-packet raw-frame check despite successful
UDP payload delivery, consistent with endpoint PMTU/fragmentation affecting the
measurement. The boundary phase now uses `IP_PMTUDISC_PROBE` on both endpoint
sockets, restoring the WAN option afterward, so the full packet reaches the DUT
for the test. Exact payload, frame, hardware-counter and software-TX assertions
remain intact. No adapter change was needed for this test correction. The first
run and its endpoint observations are preserved separately from the passing run.

The KASAN image build succeeded and was staged. Kernel build ID is
`117089510f6f135400e45aedd59310562fd041bf`, CDX
`c6c0f308d581d77ef1047ea1dcc68ab53b1802d5`, and adapter
`0d210167e781b632321aaf9992aaf0f3589ded2e`. Staged image SHA-256 is
`0fc6173ec1c3d751cfe014d7819a60087fce2ff357c230bfebd9e39d4584d85e`.
There are no CDX compiler warnings; the build reports three existing forced-task
warnings. KASAN, lockdep, kmemleak and failslab remain enabled. The full KASAN
suite was not run.

Artifacts are under `/tmp/ask-flowtable-mtu/`: `host.log`, the `proof/`, `rearm/`
and `terminal/` directories and their logs/XML, image identities, post-unload
diagnostics, and `endpoint-pmtu-before-fix/`. The build log is
`/tmp/ask-flowtable-mtu-build.log`. Post-unload and final fresh-boot diagnostics
have no KASAN, lockdep, warning or oops reports; `debug_locks` remains 1 and taint
remains 4096. The final boot matches the staged image with CMM stopped, CDX and
the adapter loaded, zero counters/references/bindings and cleared fault controls.
Both MTUs are 1500, test routes/interfaces/firewall rules are gone, and host/LAN
settings are restored. `final-state.json` records the checked restoration.

Stop at this increment. Real-port down/up recovery remains a separately proved
step. The bounded IPv4 TCP/UDP, no-NAT admission contract, capacity limit and
owner selection are unchanged; this does not introduce further traffic features.

## Administrative port recovery — verified 2026-09-15

`NETDEV_GOING_DOWN` now invalidates dependent flow generations without latching
global failure. Native DOWN flushes flowtable work; hardware admission remains
conditional on both ports running with carrier and both routes still valid.
UP never clears a failure latch. Fresh packets can re-enter hardware through the
existing bindings after Linux networking becomes usable again.

The first DUT run identified another notification in the same transition:
IPv4 emits `FIB_EVENT_NH_DEL`/`ADD` while synchronizing built-in route nexthops.
These previously entered the global policy-invalidation case. They now retire
all installed generations conservatively, preserving the table; a newly usable
alternative may affect routing even through another device. RTNL and both
destination checks exclude stale queued admission. These notifications do not
cover the separate nexthop-object API, which remains foundation audit work.

`test_flowtable_link_recovery` passes in 106.39 seconds. It performs two down/up
cycles on each real port while keeping one TCP connection, one UDP socket and
the same nft flowtable object alive. Each DOWN returns four hardware directions
and all flow references to zero, keeps both bindings, and prevents further UDP
delivery during the measured one-second down window. Each completed cycle
installs four fresh directions without global rearm. TCP serial delivery remains
exact with no reconnect; each outage records 26 lost UDP attempts explicitly.
Only outage windows permit UDP loss. The reusable peer now completes console
cleanup even when its control connection resets, preserving failure evidence.

The control connection is exempt from NAT just like the measured traffic:
MASQUERADE legitimately deletes its conntracks on WAN DOWN, so leaving the test
controller on that path interrupted the original harness. Fixture-owned host
routes/neighbours are restored after UP if the transition discarded them.
Traffic can briefly use the connected route before the lower-MTU host route is
restored; the test accounts for additional retired generations in that window
and requires balanced installs/deletes, four current directions and MTU 1200.
The passing run needed exactly four new directions per cycle.

After every recovery, eight seconds of strict traffic validates 256 UDP echoes
and 4 MiB TCP data in each direction. UDP hardware counters advance exactly
256 packets and 76,288 bytes per direction. Software TX increases by three LAN
packets and 15–17 WAN packets; aggregate softirq usage is 0.38–0.47% and total
busy usage 2.10–2.19%. The table identity, TCP socket and boot remain unchanged.

Five focused ASan/UBSan host checks pass in 1.11 seconds. They cover shared
generation retirement, stale-route and unavailable-port admission, reference
drain, IPv4 nexthop synchronization and preservation of policy/failure state.
The existing global rearm test passes in 23.62 seconds, and terminal unproven
unlink in 27.42 seconds. Post-unload KASAN/lockdep diagnostics are clean,
`debug_locks` remains 1 and taint 4096. Terminal teardown releases the adapter
and CDX, and 64 software echoes succeed afterward. A fresh boot is required
before the following hardware increment.

Both KASAN builds succeeded and were staged. The corrected kernel build ID is
`e732d7ef9f004085a27a2e28febbf80532e1e317`, CDX
`c6c0f308d581d77ef1047ea1dcc68ab53b1802d5`, and adapter
`63ba4408b9237f40b1d6d337faf6c58379eaa077`. Staged SHA-256 is
`259f20701f7f51910703d8d0529dbabdc0b4438e5fa404e87c9d757b28b926a5`.
The adapter source matches the proved image. Builds have no CDX compiler
warnings and three existing forced-task warnings; the full KASAN suite was not
run. Artifacts are in `/tmp/ask-flowtable-link/`, including host/DUT logs/XML,
image identity and post-unload diagnostics. `first-global-stop/` preserves the
initial notification finding; `route-restoration-window/` and
`masqueraded-control/` preserve harness failures. Build logs are
`/tmp/ask-flowtable-link-build.log` and `/tmp/ask-flowtable-link-rebuild.log`.

The authorized continuation completes the remaining device lifecycle, useful
configuration and policy integration, startup independence, concurrent
reconfiguration and resource-pressure acceptance. Each increment is proved and
committed separately. Validation on a second kernel version is explicitly
excluded from this foundation work at the user's request. NAT, IPv6 and broader
traffic features remain subsequent work.

## Physical MAC and rename recovery — verified 2026-09-15

Physical-port lookup and statistics now use the retained kernel device object.
Renaming a port leaves installed hardware generations intact and permits a
fresh binding under the new OS name. The physical interface index and valid
CDX onif entry still have to agree; an unregistering device is inadmissible.

MAC changes retire dependent shared handles without disabling their bindings.
The decoder invalidates queued generations carrying an obsolete source MAC.
Admission checks the current address under RTNL and the backend transaction,
then synchronizes the legacy encoder's source cache under `dpa_devlist_lock`.
Linux's NEIGH fallback uses the live address. Carrier-loss notifications also
retire affected generations. None of these events clears a global/fatal stop.

Five focused ASan/UBSan host checks pass in 1.13 seconds. The two DUT identity
tests pass in 180.00 seconds: MAC recovery 103.31 seconds and rename identity
76.59 seconds. MAC recovery changes and restores each real port while retaining
one TCP connection, UDP socket and nft flowtable. Every recovered window checks
256 exact UDP hardware hits and 76,288 bytes per direction, 4 MiB TCP data per
direction, and 256 WAN Ethernet frames carrying the current source MAC. A raw
LAN receive test also verifies 256 hardware echoes using the changed LAN MAC.
Software TX is 3–4 LAN packets and 15 WAN packets per eight-second window;
aggregate softirq is 0.37–0.44% and busy CPU 2.10–2.31%. TCP remains connected
with exact serial delivery. Intentional MAC-transition windows report 0–1 UDP
losses each in the passing run; steady windows retain exact delivery checks.

Each port is then renamed while UP. Existing generations retain their cookies,
counters and table identity. Deleting and recreating the table while the port
is renamed admits fresh TCP/UDP hardware entries on the same sockets. Each
retained/rebound window verifies exact UDP counters, TCP payload delivery and
small software TX deltas. Both original port names and MACs are restored.

ARP's CHANGEADDR notifier can retire the shared handle before the adapter's MAC
notifier; the first invalidator owns the diagnostic counter. CHANGEADDR also
evicts fixture-owned permanent neighbours. The tests account for this ordering
and restore those records before normal fixture cleanup. These were two harness
corrections. A separate repeat received one UDP ENETUNREACH during a recovered
window, after successful admission; TCP stayed connected. A following run with
ARP/ICMP capture passed unchanged strict traffic checks and did not reproduce
that error. Its cause is unconfirmed; the failure evidence is retained rather
than silently counted as a passing run or weakening steady-state assertions.

The KASAN image was built and staged. Running kernel build ID is
`ccb4027552dba75cfd057f215fa8810f30e0f80f`, CDX
`39b4e97367935f61d634be70e24658e5d80e2357`, and adapter
`71dc918ea3cdbcde2b765c358321927a35f0795c`. Staged SHA-256 is
`1d741690933e2096dca08566902611627c93afecdddb8e8276e934e2a9ede21c`.
Artifacts live in `/tmp/ask-flowtable-mac/`: host and DUT logs/XML, image identity,
MAC/name evidence, and ARP/ICMP captures. `first-invalidator/`,
`mac-pass-neighbour-cleanup/`, and `delayed-udp-error/` retain the earlier runs.
The successful build log is `/tmp/ask-flowtable-mac-rebuild.log`; the earlier
build caught and corrected an SDK header include-order problem. The successful
build has no compiler warnings and three existing forced-task warnings.

The updated device-dependency and global rearm regressions pass together in
106.29 seconds. Twelve unrelated dummy/bridge events preserve established
hardware entries; attaching/removing an upper device on either real port
retires both connections and keeps admission stopped until explicit table
recreation. UDP loss is allowed only during that intentional routed-path
interruption. Rule invalidation, rejected reuse of a populated table, and
recovery after retried deletion barriers remain verified. KASAN and lockdep
diagnostics are clean, `debug_locks` is 1, taint is 4096, and both original port
names, MACs, MTUs and UP states are restored. No full suite was run.

## Physical removal and terminal restart guard — verified 2026-09-15

An unproven hardware unlink now prevents `NETDEV_PRE_UP` on every physical
port still owned by the failed CDX provider. The SDK's ordinary open method
otherwise enables FMAN ports independently of the adapter. The guard belongs
to CDX, survives adapter unload and uses device identity under the interface
list lock; it never takes the control mutex from an RTNL notifier. CDX publishes
its fatal latch with WRITE_ONCE. The guard is absent in default CMM mode and
is unregistered only after provider configuration teardown has detached PCD
and released physical interface records. Full provider teardown allows Linux
port operation again; restarting hardware offload still requires a fresh boot.

Physical driver removal is an explicit maintenance operation. Native netdevice
teardown removes ingress hooks, flushes flowtable work and retires dependent
hardware. CDX also holds physical configuration and queue references, which
outlive adapter bindings. A blocking `fsl_dpa` unbind therefore needs full
provider teardown to release those pins. The preferred maintenance sequence is
to remove the flowtable, unload `ask_flowtable` and any inactive dependent FCI
module, unload CDX, then unbind the physical driver. Do not force module removal
or drop CDX's device references while its queues/classifier still use them.
Recovery to offload uses a fresh boot with the intended physical topology.

The focused terminal unlink test passes in 38.14 seconds. After injected hard
unlink, both physical receive ports are stopped. Administrative DOWN followed
by UP returns EIO for both ports, and actual FMAN receive-port state remains
disabled. The same restart attempts are refused after unloading the adapter;
loading a fresh adapter also remains refused. Full CDX unload followed by UP
restores software forwarding, verified with 64 exact echoes. DOWN discards the
fixture's host routes; its cleanup now restores those before normal undo actions.

The physical unregister test passes in 34.01 seconds. It starts real LAN driver
unbind during an active UDP hardware flow. Both directions and their handle/
neighbour references drain to zero, the removed ingress binding disappears,
and the pending unbind remains pinned by CDX. Full adapter/provider teardown
then completes the unbind. Driver rebind restores the original interface and
IPv4 state; 256 exact software echoes pass afterward. The intentional 24-second
transition reports 2,795 sends and 2,377 validated echoes. The private unbind
worker publishes completion atomically and its result directory is removed.

Five ASan/UBSan flowtable host checks pass in 1.15 seconds, including failed
guard registration, legacy no-op, both physical ports, renamed identity,
unrelated same-name objects, and retained fatal state after consumer release.
Five startup/shutdown host checks also pass. Both DUT runs leave clean KASAN
and lockdep diagnostics, debug_locks 1 and taint 4096 after full provider unload.
The KASAN image was built and staged without compiler warnings (three existing
forced-task warnings). Kernel build ID is
`f29af715ee88846a3abd8ef3ef6b819ae8495de7`, CDX
`ed4251e6275e1ecbe06998b28203deb1a659b67a`, and adapter
`71dc918ea3cdbcde2b765c358321927a35f0795c`. Staged SHA-256 is
`964e1ca377e1d1f330f25e0f5d75c06e9c0bcb796f2c37a4b979efd1dd20f93b`.
Evidence is in `/tmp/ask-flowtable-lifecycle/`; build log is
`/tmp/ask-flowtable-lifecycle-build.log`. No full suite was run.

One attempt stopped before fault injection because admission encountered RTNL
contention: one direction installed and its peer stayed in software. This is a
separate foundation recovery gap, retained in `partial-admission-before-fault/`.
Transient admission recovery will be addressed next; the terminal guard proof
subsequently passed with both initial directions installed.

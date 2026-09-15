# Neighbours and gateways: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

Ordinary ARP, gateway routes and selective neighbour retirement.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## Ordinary ARP increment (2026-09-14)

The direct-route topology now supports ordinary ARP neighbours for both UDP and
TCP. Routing, two physical ports, the two-direction limit and explicit
flowtable recreation remain the boundaries. This does not add gateway next-hop
resolution or per-flow invalidation.

Each installed direction pins its actual Linux neighbour and publishes a watch
before hardware insertion. Publication rechecks the address and state under the
neighbour lock; a notification during insertion can therefore latch invalidation
and force rollback. The watch contains immutable dependency data, protected by
`ft_neigh_lock` against removal. Lock ordering is control mutex, neighbour lock,
then watch lock. The notifier never acquires the control mutex or calls firmware.
Removal withdraws the watch before releasing the reference and entry storage.
`neighbour_refs` in `/proc/cdx_flowtable` exposes the reference count, including
zero after failed installation, invalidation and table removal. Recovery also
requires that count to be zero.

An alive neighbour with an unchanged address can progress through REACHABLE,
STALE, DELAY and PROBE without interrupting hardware forwarding. PERMANENT
continues to work. An unusable state, changed MAC or detached neighbour object
latches whole-table invalidation. Unrelated ARP notifications do not invalidate
the table; route and device invalidation retain their conservative scope.

Positive hardware counter deltas call `neigh_event_send(neigh, NULL)` through
the existing Netfilter statistics work. This records use and lets Linux's own
timers send ARP probes. It does not call `neigh_confirm()`: classifier activity,
including reverse traffic, is not treated as proof of reachability. Idle counter
samples do not refresh neighbour use. A valid cache entry remains usable during
probing, as in ordinary Linux output; failed resolution retires hardware.

This increment also fixes the software fallback contract. Native hardware
flowtables can select `FLOW_OFFLOAD_XMIT_DIRECT`, caching Ethernet addresses even
when hardware admission is rejected. A focused counter-enabled-table test
reproduced lost replies after Linux had learned the peer's changed MAC, with
zero hardware entries. That path bypassed normal neighbour output.

Patch 140 now lets CDX request neighbour output for ASK-owned tables. The
kernel initializes this request to false; CDX sets it only on a successful bind,
and it remains set for that table after unbinding. Routed software tuples keep
their route reference and use native `FLOW_OFFLOAD_XMIT_NEIGH`, including when
the hardware request is declined. Hardware rule generation remains available.
A DIRECT tuple constructed concurrently with binding is retired before packet
rewriting in either IP family; its union contains no retained route pointer and
must never be reinterpreted as a NEIGH tuple. Initial binding, like recovery,
requires an empty table. Other tables and the default CMM mode retain their
existing policy. This is a downstream kernel-internal extension, not a new
userspace interface.

The tests in `tools/tests/test_flowtable_arp.py` exercise cold ARP resolution
after binding, sustained forwarding through natural ageing, a real endpoint
MAC change announced through ARP, unsuccessful probes and recovery. Failure
injection suppresses only LAN ARP replies while leaving IP traffic possible.
Starting that bounded failure from STALE avoids depending on a randomized
reachable timer; the preceding steady phase exercises natural ageing. The TCP
peer restores ARP after a finite local lease, allowing the same TCP connection
to recover without relying on an unreachable control path. Packet capture uses
the endpoint's normal receive filter. Temporary parameters, addresses and
capture processes are restored after each case.

One early test used an incorrectly formed gratuitous ARP reply, which Linux
could ignore during its neighbour locktime. The helper now sends a proper ARP
announcement request. That test attempt and the pre-fix software fallback
failure are excluded from complete acceptance and retained as development
evidence in `/tmp/ask-flowtable-arp/initial-image/`.

The first run on the final image encountered RTNL contention during a short
admission burst: every attempted installation returned the existing busy result.
No decoder rejection or hardware error occurred. The warmup now keeps verified
traffic moving across Linux's hardware-refresh interval, with a bounded admission
wait, instead of sending a sub-second burst and only polling state afterward.
The failed warmup is retained in `admission-attempt/`; steady measurement still
requires exact UDP delivery and hardware packet deltas without retries.

The final KASAN image was rebuilt, staged and booted. Live kernel/CDX GNU build
notes and userspace hashes matched the built files. KASAN, lockdep, FAILSLAB and
kmemleak instrumentation remained enabled. There were no compiler warnings.
The final incremental image build reported three previously forced task warnings;
the preceding full kernel rebuild also reported three packaging `buildpaths`
QA warnings for `auto_bridge.ko`, `raid6_pq.ko.zst` and `vmlinux`. These concern
embedded build paths. Only focused tests ran; neither the full KASAN suite nor
a kmemleak scan was run.

| Identity | Value |
| --- | --- |
| Staged image SHA-256 | `cc67474f04cecd330cd7669949fb1eaff24aa096ea6c07dbd8d25c7a23c5fcb4` |
| Kernel build ID | `ddfbd362fefc78efc2174f8f296692fe526e4ff1` |
| CDX build ID | `c5cdb78e7c1d6b3605c3293a28eeb85c8a77e8cb` |
| Test boot | `47987f94-671e-4953-83c3-f6f4c68a94b0` |

| Check | Confirmed result |
| --- | --- |
| Focused host checks | 12 passed in 0.65 seconds. ASan/UBSan cover neighbour state and reference ownership, changes before publication and during insertion, shared dependencies, invalidation/rearm, and the production kernel's DIRECT-union guard. Existing decoder/backend/failure/shutdown checks remain included. |
| Software fallback | Counter-enabled hardware table declined all hardware installation. After a real peer MAC change, all 128 further UDP echoes arrived with the new MAC; LAN software TX increased by 129. Passed in 10.57 seconds. |
| ARP lifecycle | UDP and TCP cases both passed in 73.26 seconds. Each invalidation retired both hardware entries and all neighbour references; explicit table recreation restored hardware admission. No CMM restart or reboot occurred between transitions. |
| UDP ageing | 1,024 exact echoes produced 1,024 additional hardware hits in each direction, with LAN software TX increasing by 8. Capture recorded 8 unicast ARP probes answered by the original peer MAC. The accelerated natural NUD cycle did not reinstall or invalidate hardware. |
| UDP recovery | After MAC replacement and again after failed reachability, 512 exact echoes produced 512 hardware hits per direction. LAN software TX deltas were 2 and 1 respectively. The reachability fault exhausted 3 unanswered probes and reached FAILED. |
| TCP ageing | One connection delivered and verified 64 MiB upload in 8.00 seconds, with 59,393 data-direction hardware hits and no retransmissions. Software TX deltas were eth3 3 / eth4 72. Aggregate CPU was 4.99%, softirq 1.04%, while polling neighbour state every half-second. Capture recorded 3 answered unicast ARP probes. |
| TCP MAC recovery | The same connection delivered through software after the MAC change, then offloaded after table recreation. A verified 64 MiB download in 8.00 seconds produced 59,394 data-direction hardware hits; software TX deltas eth3 3 / eth4 12, CPU 2.05%, softirq 0.44%. |
| TCP reachability recovery | ARP reply suppression reached FAILED and removed hardware. A queued command and verified 1 MiB transfer survived until the peer's eight-second local lease restored ARP. The capture's six-second fault window contained 16 unanswered probes and no replies. After explicit rearm, that same connection delivered another verified 64 MiB upload: 59,393 data-direction hardware hits, software TX eth3 2 / eth4 12, CPU 1.86%, softirq 0.41%. FIN then removed both entries and references. |
| Permanent-neighbour regressions | Reference/lifecycle passed in 112.81 seconds, including removal under traffic and idle expiry. UDP TTL/MTU/options/fragment exceptions and TCP expiry/reuse/FIN checks both passed in 40.87 seconds. |
| Sanitizers | No KASAN, UBSan or lockdep splats during the successful focused hardware tests. |

CPU includes management polling, ARP and other background work; the ageing
measurement has more observer traffic than the recovery measurements. Delivery,
hardware deltas and software TX counters together establish the forwarding path.
These paced tests do not claim maximum throughput or close the earlier unrelated
UDP-loss investigation. The ARP timers were shortened for testing; the production
adapter changes no NUD parameters and grants no synthetic reachability confirmation.

On an experimental boot, select only the three ordinary-ARP cases with:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=<WAN-address> make ask-test \
  ASK_TEST_ARGS='-k flowtable_arp -x -q'
```

Canonical acceptance artifacts are in `/tmp/ask-flowtable-arp/`: `host.xml`,
`software.xml`, `lifecycle.xml`, `regression.xml`, `permanent-lifecycle.log`,
per-case JSON, `arp-udp.pcap`, `arp-tcp.pcap`, `arp-software.pcap`,
`image-identity.json` and `final-state.json`. The final build log is
`/tmp/ask-flowtable-arp-candidate-build.log`; the full kernel rebuild log is
`/tmp/ask-flowtable-arp-final-build.log`.

Final runtime state: experimental ownership, CMM and auto_bridge absent, both
fault controls disabled, 26 installs matched by 26 deletes, and entries,
bindings, neighbour references, errors, invalidation, fatal and quarantine all
zero. Four explicit rearms completed. Test tables, host routes and NAT exemptions
are gone; the LAN MAC and ARP response policy and both DUT ports' NUD parameters
are restored. The DUT remains in flowtable mode. Stop at this proven increment;
gateway routes and selective invalidation remain future work.

## Gateway next-hop increment

This increment extends IPv4 UDP/TCP admission to destinations reached through
an IPv4 gateway on a supported physical port. The two-direction limit, no-NAT
contract, whole-table invalidation and explicit recreation boundary remain.

Patch 140 supplies the selected directional route as borrowed `nf_dst` context
only for `FLOW_OFFLOAD_XMIT_NEIGH`. DIRECT, TC and XFRM provide NULL; their tuple
union must never be read as a retained route pointer. CDX requires a current
IPv4 unicast route whose egress device matches the redirect action, with no XFRM
or lightweight tunnel transformation. IPv6 gateways remain unsupported.

The adapter uses `rt_nexthop()` on that route, preserving Linux's routing choice
without repeating a FIB lookup or reconstructing its policy context. Direct
routes use the destination address; gateway routes use the selected gateway
address. The resolved ARP neighbour must match the hardware Ethernet action.
The entry retains only the next-hop address and its pinned neighbour, not the
borrowed route. Publication revalidation, NUD use reporting and watched-neighbour
invalidation follow the existing ARP lifecycle. An otherwise identical hardware
rule with a different next hop must replace its watch. Per-flow diagnostics now
include `nexthop`, separately from the IP destination used in classification.

The focused gateway fixture places a remote endpoint in a network namespace
behind loki, connected through a veth pair. Loki performs ordinary IP forwarding
between that endpoint and its physical X550 interface. The DUT reaches the
endpoint through loki's IPv4 address; a second address on that same router
allows changing next hops without changing the destination or Ethernet MAC.
The DUT ports remain physical and in the initial namespace. The fixture installs
no NAT and restores its routes, address, namespace, interface and forwarding
settings. UDP checks TTL 62 after the two routers and validates the veth Ethernet
headers; DUT diagnostics must identify the gateway, and the DUT must never learn
an ARP neighbour for the remote endpoint.

The TCP endpoint socket is created in the remote namespace. Its process returns
to loki's namespace for gateway ARP controls; the socket retains its original
network namespace. This keeps one tested TCP connection alive across gateway
MAC changes, route replacement and failed ARP resolution, using the existing
finite local ARP restoration lease.

The image was rebuilt with KASAN and staged before boot. Live kernel/CDX build
notes and userspace hashes matched the candidate. KASAN, lockdep, FAILSLAB and
kmemleak instrumentation were enabled; no full KASAN suite or kmemleak scan ran.
There were no compiler warnings. The six BitBake warnings were the three
previously forced recipe tasks and the existing packaging build-path warnings
for `auto_bridge.ko`, `raid6_pq.ko.zst` and `vmlinux`.

| Identity | Value |
| --- | --- |
| Staged image SHA-256 | `9d93dce7606ac0b6d2e61f63aab9f29bf271b8377987bd1d1dcd7a8e92e4b2e0` |
| Kernel build ID | `5373954a79ef44bd2403375b163f21c18c295686` |
| CDX build ID | `75a20191a4dac5371396897aec54f351ad05c802` |
| Test boot | `a01503e0-03ee-4f41-88f5-29c8f327a00d` |

| Check | Confirmed result |
| --- | --- |
| Focused host checks | 5 passed in 0.83 seconds. ASan/UBSan cover production decoder/backend/neighbour ownership, 32 alternating TCP/UDP gateway lifecycles, stale/mismatched/transformed route refusal, next-hop validation, same-MAC gateway replacement, and kernel union/pointer guards. Shutdown and ehash teardown checks also passed. |
| Routed UDP | Passed in 44.61 seconds. During natural ARP ageing, 1,024 exact echoes produced 1,024 hardware hits per direction and 3 LAN software TX packets. Replies had TTL 62 through DUT and loki. |
| Destination versus gateway | Endpoint `198.18.27.2` remained the classified destination. Its hardware entry used next hop `192.168.1.122`, then `198.18.28.2` after route replacement. The DUT never acquired an ARP neighbour for the remote endpoint. |
| UDP recovery | Gateway MAC change, next-hop replacement and failed reachability each invalidated the table and released neighbour references. After explicit recreation, each 512-echo window produced exactly 512 hardware hits per direction with zero LAN software TX. ARP capture recorded 4 answered healthy unicast probes and 3 unanswered failure probes. |
| Routed TCP | Passed in 44.34 seconds. The socket stayed established through gateway MAC change, route replacement and failed resolution. Correct software transfers bridged each recovery; explicit recreation restored hardware. FIN removed both entries and references. |
| TCP sustained upload | Verified 64 MiB in 8.00 seconds, with 59,393 data-direction hardware hits and zero retransmissions. Software TX: eth3 5 / eth4 76. Aggregate CPU 4.99%, softirq 1.04%, with neighbour polling active. |
| TCP after MAC change | Verified 64 MiB download in 8.00 seconds, with 59,394 data-direction hardware hits and zero retransmissions. Software TX: eth3 5 / eth4 12. Aggregate CPU 5.55%, softirq 0.38%. |
| TCP after reachability recovery | The eight-second local lease restored gateway ARP; the queued command and 1 MiB transfer completed on the same socket. Following recreation, a verified 64 MiB upload produced 59,393 data-direction hits, zero retransmissions, software TX eth3 4 / eth4 12, CPU 1.89% and softirq 0.41%. Capture recorded 5 answered healthy probes and 13 unanswered probes in the six-second fault window. |
| Direct-route regressions | Ordinary ARP UDP lifecycle and TCP transfer/idle-expiry/reuse/FIN checks both passed in 67.52 seconds on this image. |
| Kernel diagnostics | No KASAN, UBSan or lockdep splats in the four focused DUT tests; final diagnostics remained clean. |

These are paced forwarding measurements, not throughput limits. CPU includes
management, ARP and background kernel work; delivery and software TX counters
identify the hardware path. The gateway backend uses the existing firmware
encoding unchanged. Acceptance covers a directly attached IPv4 router with
ordinary unicast routes; it does not establish ECMP, policy-routing variations,
IPv6 next hops, NAT or a larger connection population.

Run only this increment with:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=<WAN-address> make ask-test \
  ASK_TEST_ARGS='-k flowtable_gateway -x -q'
```

Artifacts are in `/tmp/ask-flowtable-gateway/`: `host.xml`, `udp.xml`, `tcp.xml`,
`regression.xml`, per-case JSON, `arp-gateway-udp.pcap`, `arp-gateway-tcp.pcap`,
`image-identity.json`, UART logs and final cleanup evidence. The build log is
`/tmp/ask-flowtable-gateway-build.log`.

Final state: 26 installs and 26 deletes, eight explicit rearms, and zero entries,
bindings, neighbour references, errors, invalidation, fatal or quarantine. Fault
controls are disabled. CMM and auto_bridge remain absent. The remote endpoint
namespace, both veth devices, alternate gateway address, test host routes and
NAT exemptions are removed; loki's forwarding setting, physical MAC and ARP
policy and the DUT's NUD parameters are restored. The DUT remains in experimental
flowtable mode. Stop at this increment; connection scaling, selective invalidation
and NAT remain subsequent work.

## Selective neighbour invalidation verified (2026-09-15)

This increment narrows neighbour invalidation to the connections that actually
use that neighbour. A changed MAC, unusable NUD state or detached neighbour
invalidates the connection's two directions, even when only one direction uses
the changed dependency. Other connections retain their hardware entries and
counters. Valid resolution and fresh traffic restore offload automatically,
without deleting conntrack, reconnecting TCP or recreating the flowtable.
Route and device changes still use the conservative global recovery boundary.

Patch 140 context version 4 provides the lifetime contract. Before admission,
CDX opts the table into allocation of an opaque handle per cached Linux flow.
Both directions borrow that handle during callbacks and each installed CDX
direction takes a reference. The handle contains only a reference count, an
atomic invalid bit and RCU reclamation state. It cannot pin or dereference a
flow, table, conntrack, route or namespace. Tables that do not opt in allocate
no handles. Allocation failure follows the existing flow-add failure path and
leaves ordinary stack forwarding available.

The neighbour notifier atomically invalidates every dependent handle under the
watch lock and queues selective work. Cached software lookup declines the
invalid generation immediately; native Netfilter GC performs its usual teardown
and hardware-delete callbacks. The CDX worker independently removes every
installed direction sharing that invalid handle. It does not flush a table or
retain borrowed Linux pointers. Handles are immutable identities until their
last reference is released, and RCU reclamation protects existing lockless
lookups. A stale callback with a reused directional cookie cannot remove,
update or replace an entry belonging to another handle.

Hardware retirement still uses the existing consuming deletion contract. A
barrier failure or unproven unlink escalates to the global worker; selective
recovery cannot bypass quarantine or clear fatal state. Module exit serializes
the stopping flag with callbacks, unregisters notifiers synchronously and
cancels both workers before releasing bindings. `/proc/cdx_flowtable` now
reports `handle_refs` for installed adapter references and
`neighbour_invalidations` for distinct handles first invalidated by neighbour
handling. Ordinary selective recovery leaves `invalidated`, `invalidation_done`
and `rearms` unchanged. The driver reference count does not count Linux's own
references or objects awaiting an RCU grace period.

The acceptance fixture creates two macvlan peers in separate loki network
namespaces, with distinct IPs and real receive MACs on the existing X550 port.
Each peer runs one TCP and one UDP connection; both protocols use the same
source/destination ports. A separate control socket permits ARP restoration
while the affected data path is unavailable. Every data record includes its
connection identity and serial; the WAN TCP server refuses reconnects. Peer B
keeps sending throughout peer A's MAC change, ARP failure and neighbour-object
deletion. The fixture removes its namespaces, addresses, routes, NAT exemptions,
conntracks, table and NUD tuning on exit.

| Check | Observed result |
| --- | --- |
| Host ownership and failure checks | Four focused ASan/UBSan tests passed in 0.81 seconds. They compile production adapter and kernel handle/add/lookup/GC paths, covering allocation/hash rollback, shared references, deferred reclamation, stale callbacks, tuple/cookie reuse, selective retirement and global escalation. Shutdown and ehash teardown checks also passed, two tests in 0.21 seconds. |
| Two-peer acceptance | Passed in 33.94 seconds. Each of three faults reduced entries, neighbour references and adapter handle references from eight to four, preserving all four peer-B cookies and their counters. Recovered traffic restored eight entries without any rearm or unexpected error. |
| Persistent TCP | The original peer-A socket completed verified records across a 3.54-second ARP suppression window. Peer B continued on its original TCP/UDP sockets. No TCP reconnect was accepted. |
| Steady forwarding after recovery | Both TCP connections each sent and received 4 MiB of verified payload over eight seconds. Both UDP connections exchanged 256 verified echoes, with exactly 256 hardware hits and 76,288 hardware bytes in each direction. Software TX was eth3 8 / eth4 15; aggregate CPU was 2.13%, softirq 0.41%. |
| Earlier steady window | The same packet and counter checks passed before faults, with software TX eth3 8 / eth4 16. CPU was 8.85%, softirq 0.44%; retain this separate sample rather than treating either paced window as a line-rate benchmark. |
| Multiple-connection and gateway regressions | Both passed, 104.17 seconds combined. The 64-direction mixed TCP/UDP lifecycle retained independent ownership. Gateway MAC/ARP recovery became selective; next-hop route replacement still required explicit table recreation. |
| Selective retirement failure | Passed in 11.57 seconds. Two injected barrier failures during peer-A neighbour deletion escalated to global invalidation: all eight directions retired, both reference counts and quarantine drained to zero, fatal remained clear, and verified traffic continued in software. Hardware admission remained closed until explicit table recreation. |
| Global recovery regression | Passed in 22.76 seconds. Device MTU change under traffic, route MTU change and two injected barrier failures each recovered after table recreation. Rebinding a populated table remained refused. |
| Final restoration | Cumulative installs/deletes both 134; entries, bindings, neighbour/handle references, quarantine, fatal and invalidation all zero. Four cumulative errors were the four deliberately injected barrier failures. Five global rearms came from route/device/failure checks; the selective acceptance needed none. Test routes, addresses, namespaces, NAT rules, traffic and NUD tuning were removed/restored. |
| Instrumentation | No KASAN, lockdep, Oops or panic reports in the test windows or final dmesg; taint remained 4096 for the existing out-of-tree modules. |

Two earlier acceptance attempts stopped on harness assumptions: sysfs still
represented the original namespace after `setns()`, and a TCP ARP retry could
advance FAILED to INCOMPLETE before the diagnostic read. The helper now queries
links through namespace-aware Netlink, and the fault check accepts either
unusable resolution state. Those logs remain under `proof/` and `proof2/`;
`proof3/` is the complete successful lifecycle. No forwarding-loss tolerance
or hardware counter assertion was relaxed.

The KASAN image was built and staged. Live kernel build ID is
`d8cf2f0ee1cecbb8f51c718edccf422285e17059`; CDX build ID is
`6b35e016d661b58fd677721adeb708a48aefad48`. The final rebuild after a comment-only
clarification produced the same binaries and staged image SHA-256:
`83c134b98e8305747baf910891248a6afde662c89d32cee80192cb6f4af478e4`.
KASAN, lockdep, kmemleak and failslab remained enabled. Only focused tests ran;
there was no full KASAN suite or forced kmemleak scan. CMM stayed disabled and
there was no reboot between acceptance and regression tests.

From a clean experimental boot, reproduce the two new checks with:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 \
  ASK_FLOWTABLE_ARTIFACTS=/tmp/ask-flowtable-selective \
  make ask-test ASK_TEST_ARGS='-k selective_neighbour -x -q'
```

Artifacts are under `/tmp/ask-flowtable-selective/`: successful `proof3/`,
`regression/`, `barrier/` and `rearm/` measurements, matching logs/XML, host logs,
image/source identities and restoration evidence. Initial and final build logs
are `/tmp/ask-flowtable-selective-build.log` and
`/tmp/ask-flowtable-selective-final-build.log`.

Stop at this increment. This proves selective neighbour recovery for the
existing bounded IPv4 TCP/UDP scope. Selective route/device handling and further
foundation work remain separate increments; no additional encapsulation,
forwarding feature or firmware capability is introduced here.

# Connections, admission and capacity: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

TCP, independent connection lifetimes, partial-admission recovery and resource pressure.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## TCP increment and validation (2026-09-14)

This increment admits one IPv4 TCP connection using the same physical ports,
direct host routes, permanent neighbours and two-direction limit. CMM remains
absent. It adds no NAT, dynamic ARP or gateway resolution. The backend carries
the protocol through both private tuple objects, hashing and classifier table
selection; the existing TCP encoder provides the forwarding actions. UDP and
TCP tuples with identical addresses and ports are distinct keys. Hardware
ownership, retirement, quarantine and healthy rearm mechanisms are unchanged.

Admission requires the rule protocol to match its borrowed conntrack context.
TCP requires `nf_conntrack_tcp_established()` (ESTABLISHED plus ASSURED) and
exactly Netfilter's TCP flags key zero with mask FIN|RST. Missing flags, extra
selectors, different masks and unsupported protocols are declined before
allocation. No TCP sequence/window tracker is added to CDX.

This relies on a concrete parser contract: the `tcpschema` section of
`dpa_app/files/etc/cdx_sp.xml` exits to the host when `tcp.flags & 7` is nonzero,
before TCP hash lookup. SYN, FIN and RST therefore cannot bypass Linux through
an installed TCP entry. The live soft-parser and PCD XML files were compared
byte-for-byte with this repository. Any change to that parser or firmware
requires revalidation of this contract; merely accepting a flags selector in
the adapter would not establish hardware support.

Linux's observable conntrack state during offloaded teardown is asynchronous:

- A FIN punts and marks the flow for teardown immediately. The flowtable GC
  queues hardware deletion separately. A final pure ACK can cross hardware
  before deletion, leaving conntrack in LAST_ACK even though both endpoints
  completed closure. The test requires both FINs at Linux's forward hook, the
  final ACK in a WAN packet capture, prompt hardware removal, no OFFLOAD flag,
  and eventual conntrack expiry.
- After offloaded data, Linux's saved sequence/ACK state can be stale. The
  RST handling in `nf_conntrack_proto_tcp.c` deliberately permits ESTABLISHED
  to remain while allowing a possible RFC5961 challenge ACK, but applies the
  short CLOSE timeout. The test requires the receiving socket to report reset,
  RST at Linux's forward hook, prompt hardware removal, no OFFLOAD flag, a
  bounded CLOSE timeout and eventual conntrack expiry. It does not require a
  particular intermediate state label.

These are Linux flowtable/conntrack semantics, not new CDX timeout policy.
The two initial test runs stopped on overly strict TIME_WAIT and CLOSE label
assertions respectively. Those runs are excluded from complete acceptance;
the replacement assertions establish delivery, visibility and bounded cleanup.

`tools/tests/test_flowtable_tcp.py` uses a TCP variant of the shared fixture.
The staged `flowtable_tcp_peer.py` keeps a single LAN console operation alive
while commands and payloads travel over the tested TCP connection. Each payload
block is checked and the complete transfer is hashed. Test-only endpoint packet
loss and sysctl changes are restored in cleanup. The FIN test temporarily uses
a four-second flowtable timeout and ten-second LAST_ACK/TIME_WAIT timeouts;
the latter leave time to inspect state after asynchronous retirement.

The KASAN image was rebuilt and staged. Live kernel/CDX build notes and userspace
hashes matched the built files; KASAN, lockdep and FAILSLAB remained enabled.
There were no compiler warnings. The three BitBake warnings concerned previously
forced recipe tasks. Only focused tests were run, not the full KASAN suite.

| Identity | Value |
| --- | --- |
| Staged image SHA-256 | `d49400be27012f9498278f1b38380c330e88acf0b8647911bda240a34dd852fe` |
| Kernel build ID | `c1a3c3ef605c24e3a3bda6dfc45f2c0a4e79d7d6` |
| CDX build ID | `8dac0662d4e27299d067083fb017be7d8f8af907` |
| Test boot | `346ef62e-bfc2-4242-8790-444373f1d214` |

| Check | Confirmed result |
| --- | --- |
| Focused host checks | 11 passed. ASan/UBSan checks cover protocol/state/flag rejection, protocol-separated keys, 128 alternating TCP/UDP adapter and backend lifecycle cycles, and existing failure/shutdown guards. |
| TCP lifecycle | Both TCP tests passed in 57.32 seconds. After increasing the FIN inspection timeout margin, the FIN/expiry test and UDP exception regression passed in 41.94 seconds. |
| Admission | Both handshake SYN packets reached Linux; hardware entries reported protocol 6. Both installed directions remained live through transfers lasting twice the configured idle timeout. |
| Sustained upload | 64 MiB delivered and verified in 8.00 seconds; 59,393 data-direction hardware hits. Software TX deltas: eth3 0, eth4 11. Aggregate DUT CPU 1.80%, versus 2.01% idle; softirq 0.38%. |
| Sustained download | 64 MiB delivered and verified in 8.00 seconds; 59,394 data-direction hardware hits. Software TX deltas: eth3 0, eth4 10. Aggregate DUT CPU 1.80%; softirq 0.35%. |
| Idle and reuse | Both hardware entries expired while the TCP socket remained open. Sending again installed exactly two new entries on the same connection. |
| Retransmission | An exact-tuple WAN INPUT drop rule counted 4 dropped packets. The LAN sender reported 22 retransmissions; all 8 MiB arrived correctly. The temporary rule was removed. |
| Withdrawal during traffic | Deleting the flowtable during a 16 MiB download preserved correct delivery. Entries/bindings/quarantine reached zero; LAN software TX increased by 12,587, demonstrating software forwarding. |
| Recreated table | The same TCP connection offloaded again and delivered another verified 64 MiB, with 59,393 data-direction hits and software TX deltas eth3 0/eth4 10. No CMM restart or reboot was needed. |
| FIN | Both FINs reached Linux, the final ACK appeared on the wire, both sockets closed, hardware entries disappeared within the three-second check, and LAST_ACK expired without an OFFLOAD flag. |
| RST | The WAN socket reported reset, Linux counted RST, hardware entries disappeared within the three-second check, and conntrack expired within the native ten-second CLOSE timeout plus polling margin. |
| UDP regression | Same-tuple TTL expiry, MTU/DF ICMP, IPv4 options, fragments and ordinary echo checks passed. |
| Sanitizers | No KASAN, UBSan or lockdep splats in the successful focused hardware tests. |

These are paced forwarding and lifecycle results, not a maximum-throughput
claim. CPU readings include background work and management traffic; endpoint
delivery together with hardware hits and software TX counters identifies the
forwarding path. The previous unexplained UDP loss is not closed by these tests.

Artifacts are in `/tmp/ask-flowtable-tcp/`: `tcp.xml`, `final-fin-udp.xml`,
`host.xml`, per-case JSON, `tcp-fin.pcap`, image/parser identities and UART logs.
`attempt1.xml` and `attempt2.xml` preserve the excluded runs. The build log is
`/tmp/ask-flowtable-tcp-build.log`. The DUT remains in experimental ownership
with test tables, routes, neighbours, NAT exemptions and timeout changes cleaned
up. Stop at this increment; dynamic ARP and gateway support remain future work.

## Bounded multiple connections — 2026-09-15

The adapter now admits 64 independent hardware directions, enough for 32
two-way IPv4 TCP/UDP connections in the existing one-table, two-physical-port
topology. The previous two-entry limit was an explicit admission restriction;
the binding/cookie ownership, per-direction hardware objects, statistics and
neighbour references already supported independent lifetimes. The firmware
encoder, kernel patch and CMM ownership boundary did not need changes.

`CDX_FT_MAX_ENTRIES` bounds both control-mutex list walks and the atomic
neighbour-notifier walk. The diagnostic `max_entries` reports the bound. It is
not the hardware's capacity and makes no throughput or large-scale claim.
Admission never evicts another direction. Duplicate updates remain idempotent
at the limit; a distinct owner of the same hardware key is refused, and a new
key beyond the bound receives `-ENOSPC`. Directions are admitted independently;
this increment does not introduce paired reservations or capacity fairness.

Individual connection deletion, TCP close and idle expiry leave other owners
intact. Route/device/dependency changes still invalidate the whole table and
require explicit table recreation. Selective invalidation is the next separate
increment, followed by further resource-pressure and concurrent lifecycle work.
NAT, IPv6 and additional interface types remain outside the admitted contract.

### Verification

The production-code host test fills all 64 directional slots with alternating
TCP/UDP rules sharing addresses, port pairs and a neighbour. It verifies
independent counter deltas, full-capacity idempotency and refusal, removal and
reuse of a middle key, arbitrary deletion order, balanced references and
conservative invalidation of the full set. Host sanitizers cover the existing
decoder, backend ownership and neighbour fallback as well.

The DUT test admits 16 TCP and 16 UDP connections simultaneously. Each TCP/UDP
pair shares addresses and ports, so protocol separation is tested on actual
hardware. The endpoint checks every echoed record's connection ID, serial and
payload. TCP records are also checked independently by the WAN echo server.
The test uses permanent neighbours and the established direct-route fixture;
gateway/ordinary-ARP behaviour is covered by the focused regression below.

A separate, unoffloaded TCP connection controls one concurrent LAN peer through
the existing console transport. Individual streams can stop while others
continue. Cleanup closes the sockets, drains the console operation, deletes the
table and conntracks, and restores NAT exemptions and timeout settings. The
multi-connection source ports use a separate range from the single-connection
tests; TCP sockets set `SO_REUSEADDR` for repeat runs.

| Item | Evidence |
| --- | --- |
| Kernel / firmware | Linux `6.12.103`; existing ASK FMAN firmware `210.10.1` |
| Test boot | `8dadf05e-e894-47e1-9c5f-a7240e3ad9fa` |
| Staged image SHA-256 | `ea09a6e73d93d8fdcd78170a234fedb57d84e4456a7c73fa33a6bb9d43c1dea8` |
| Kernel GNU build ID | `8d242ae536a60881a990c8fa89b17a1abd0036d6` |
| CDX GNU build ID | `2a84a70c05075f8bb490f8bbc12048d2586bf20f` |
| Instrumentation | KASAN generic, lockdep, kmemleak tracking and failslab enabled; taint `4096` only |
| Build | Successful KASAN image build and staging. No compiler warnings; three existing forced-task warnings. Running module/kernel identities matched the image. |
| Focused host tests | 5 passed in 0.87 seconds under ASan/UBSan, including CDX shutdown and ehash teardown. |
| Mixed connection acceptance | Passed in 66.16 seconds on the final harness. All 64 directions and 64 neighbour references were present. |
| Full set traffic | Over eight seconds, 16 TCP connections sent and received verified echoes of 64 MiB in total; each of 16 UDP connections exchanged 256 verified datagrams. All 32 UDP directions counted exactly 256 packets and the expected bytes. Hardware recorded 141,269 classifier hits; software TX was eth3 4 / eth4 23. |
| Explicit UDP deletion | Deleting one conntrack reduced entries/references from 64 to 62 and added exactly two deletes. Every other cookie and counter remained intact. |
| TCP close | FIN reduced entries/references from 62 to 60, adding exactly two more deletes while other traffic continued. |
| Independent idle expiry | Stopping one UDP stream reduced entries/references from 60 to 58. All remaining directions kept their cookies and increased their counters despite sharing the same two neighbours. |
| Tuple reuse and refresh | Sending again on the explicitly deleted UDP tuple and the idle UDP connection added exactly four new directions, with fresh counters; the other owners remained unchanged. |
| Surviving set traffic | A further eight-second window verified 60 MiB of TCP data and its echoes, plus 256 datagrams on each UDP connection. Hardware recorded 133,836 classifier hits; software TX was eth3 5 / eth4 15. |
| CPU | Unloaded baseline 1.83% busy / 0.44% softirq; full set 2.29% / 0.41%; surviving set 2.17% / 0.35%. Raw per-CPU ticks are retained. |
| UDP delivery | 18,595 unique records across warmup, steady traffic, concurrent retirement and reuse; no duplicated records. |
| Focused DUT regressions | IPv4 gateway UDP lifecycle and single-connection TCP transfer/expiry/FIN both passed, in 77.94 seconds combined. |
| Cleanup | Final cumulative installs/deletes both 148, with zero entries, bindings, neighbour references, errors, fatal state, quarantine or invalidation. Three earlier regression rearms; none needed during either mixed-connection lifecycle. |

The first mixed lifecycle also passed, in 62.94 seconds, but total CPU was
21.44–24.75% despite similarly low software forwarding counts. Those early-boot
samples are retained, not used as the performance baseline. The boot's kmemleak
scanner had accumulated 25.51 CPU seconds before the later measurement and was
then asleep; the repeat above measured the quiet baseline and active traffic
without changing instrumentation. This is consistent with background load
affecting the early samples, rather than evidence of sustained forwarding cost.
An intervening rerun stopped before admission on a test-harness TCP bind conflict
with the preceding single-connection regression. The separate source-port range
and socket reuse fix are included in the verified harness.

These are paced correctness and CPU measurements, not a line-rate benchmark.
Only the focused tests were run; no full KASAN suite or forced kmemleak scan was
requested. CMM remained disabled throughout, with no reboot between tests.

Reproduce the focused acceptance on an experimental boot with:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 \
  ASK_FLOWTABLE_ARTIFACTS=/tmp/ask-flowtable-connections \
  make ask-test ASK_TEST_ARGS='-k flowtable_connections -x -q'
```

Artifacts are under `/tmp/ask-flowtable-connections/`: `host.xml`, `dut.xml`,
`regression.xml`, `verified.xml`, matching logs, `verified/connections-*.json`,
image and source identities, boot logs and final restoration evidence. The
excluded harness attempt is retained under `steady/` with its log/XML. The build
log is `/tmp/ask-flowtable-connections-build.log`.

Stop at this increment. The DUT remains available in experimental flowtable
ownership with the test configuration and traffic removed. Selective
invalidation has not been implemented.

## Transient admission recovery — verified 2026-09-15

RTNL contention during one directional ADD could leave the peer direction
installed indefinitely: native hardware statistics kept that generation active,
while the rejected direction remained in software. A matching busy request now
invalidates its shared handle and schedules selective retirement. Native GC
releases the old generation, and fresh traffic can retry without replacing the
flowtable or socket. This does not clear global/fatal state and is inactive in
observe or stopping state. Unsupported and capacity refusals retain their
existing software-fallback contract.

Native work visits every bound device for each direction. The adapter first
checks immutable META ingress identity, so a visit to the other port cannot
consume the fault hook, contend unnecessarily for RTNL, or invalidate a valid
connection. `admission_invalidations` reports retired generations. Debug failure
stage 4 is consumed only after another directional cookie for the same handle
already owns an entry; it exercises the actual busy-recovery path without
blocking a kernel lock.

Five focused ASan/UBSan host checks pass in 1.16 seconds. They prove UDP/TCP
partial retirement, real and injected contention, wrong-ingress rejection,
refusal of the obsolete generation, balanced references, fresh admission, and
preservation of observe/global/fatal/stopping states. The two DUT transient
admission cases pass in 104.75 seconds. Each fault retires one installed
direction and recovers two fresh directions on the same socket/table. The UDP
window delivers 256 exact echoes with 256 hardware hits per direction; TCP
transfers 4 MiB per direction. Software TX is 4/17 packets for UDP and 3/15 for
TCP. Aggregate softirq is 0.82% and 0.34%; total busy CPU is 27.69% and 2.06%,
respectively. The UDP busy spike is retained in the raw measurements without
attributing it to an unmeasured background task.

The existing bounded 32-connection regression passes in 69.93 seconds. It
proves 64 installed directions, selective conntrack deletion, TCP FIN, idle
expiry, unaffected surviving flows and resource reuse. Idle CPU is 1.89%; the
full-set hardware window is 2.23% busy / 0.41% softirq with 4/17 software TX
packets. Surviving flows use 2.14% busy / 0.38% softirq with 4/16 software TX.
No full suite was run.

The first hardware attempt ended before admission because loki's X550 had no
physical carrier after reboot. Peer/DUT administrative cycling and X550
renegotiation did not restore it. The SFP core reports no attached upstream
controller and asserted TX_DISABLE; temporarily releasing that pin did not
restore carrier either, so no causality is claimed. Its original driver/GPIO
ownership was restored. Restricting X550 advertisement to 1 Gb/s restored the
link. Its default route, removed during administrative cycling, was also
restored. Initial diagnostic pings did not pass, but the subsequent TCP control
connections and strict UDP/TCP hardware proofs above did. The remaining tests
use that 1 Gb/s link, as authorized; line-rate throughput is not the criterion.

Kernel build ID is `eee2d20d6df912752efb8e414fe83c8cfc57f8d9`, CDX
`ed4251e6275e1ecbe06998b28203deb1a659b67a`, and adapter
`ffa21d2010260477d080a0895d0e78e3192ae0bb`. The KASAN image was built and staged;
SHA-256 is `931805066a369cba022afd588cc85b2bcd7039ce132ecc07325278980858f437`.
Build log is `/tmp/ask-flowtable-admission-build.log` (no compiler warnings,
three existing forced-task warnings). Artifacts in `/tmp/ask-flowtable-admission/`
retain host/DUT logs, image identities, all failed pre-traffic diagnostics and
passing hardware/connection evidence.
KASAN/lockdep diagnostics remain clean, `debug_locks` is 1 and taint is 4096.
All entries/bindings/references are drained, installs equal deletes, and no
backend error or quarantine remains. SFP driver/GPIO ownership is restored.

## Resource pressure and concurrent reconfiguration — verified 2026-09-15

The capacity test passes in 72.02 seconds. It fills all 64 hardware directions
with 32 independent UDP/TCP connections, then opens one additional UDP and TCP
connection. Both overflow connections deliver exact data in software while all
existing hardware cookies/counters remain valid and the 64-direction bound holds.
Their software TX window counts 5900/5854 packets. Deleting one original UDP
conntrack and closing one original TCP socket releases four directions. Native
software refresh then admits the same overflow sockets/conntracks into those
slots, without disturbing the 30 survivors. The overflow hardware window verifies
256 UDP hits per direction and 4 MiB TCP per direction, with software TX 4/10.
The initial full-set hardware window has software TX 4/17, busy CPU 2.29% and
softirq 0.44%. All connections and references drain after the test.

The concurrent test passes in 75.25 seconds. Three workers each launch
three controller calls with alternating policies while another performs twelve real
route-metric replacements and twelve physical MTU changes. All nine policies
complete their proven drain boundary; all 24 network operations succeed. The
same UDP and TCP sockets each complete 1,447 numbered records without loss or
late delivery (23,707,648 bytes in each TCP direction). Route retirement advances
by four generations and MTU retirement by two. An explicit final desired policy
then admits both sockets into stable hardware: 256 exact UDP hits per direction,
4 MiB TCP per direction, software TX 4/15, busy CPU 2.19% and softirq 0.47%.

The first concurrent run passed with identical route replacement and real MTU
changes, but it did not establish a route-metric change. The strengthened probe
initially overrequired both cause counters to advance: route retirement can
invalidate a shared generation before the paired MTU notification arrives, so
only the first cause is counted. That failed test assertion is preserved with
its source and logs. The corrected test requires observed route retirement,
successful MTU changes and balanced lifecycle state without double-counting a
coalesced generation. No product change was needed for either pressure proof.

KASAN/lockdep diagnostics are clean, debug_locks is 1, taint is 4096, all backend
references and bindings drain, installs equal deletes, and no backend error or
quarantine remains. CMM stayed stopped and FCI absent throughout these proofs.
They ran on the already verified/staged startup image, without another build or
an alternative kernel. Artifacts are in `/tmp/ask-flowtable-pressure/`, including
`capacity/`, `concurrent-final/` and the retained earlier probes. No full suite
was run.

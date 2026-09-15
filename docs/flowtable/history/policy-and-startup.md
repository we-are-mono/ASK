# Policy, startup and foundation acceptance: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

Configuration/revocation, CMM/FCI-free startup and final legacy compatibility.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## Configuration and live exclusion replacement — verified 2026-09-15

`ask-flowtable` now provides validated JSON admission/exclusion policy and a
serialized delete/drain/check/drain/install boundary. It owns one named nftables
table, preserves conntracks and sockets, refuses foreign ownership, and reports
failed cleanup rather than claiming an unproved software fallback. The lock
survives controller death while an nft child can still commit. The applied hash
lives in the kernel table comment; status distinguishes installed policy from
healthy admission. No mutable backend sysctl or CMM restart is introduced.

The image installs the controller, a disabled default policy carrying the three
existing ALG-control exclusions, and a flowtable-only boot hook after gateway
setup. External source checksums make policy/script edits invalidate the recipe's
install signature. Python dependencies follow this repository's package manifest.
[Policy operations and CMM setting migration](../../flowtable-policy.md) document
scope, tuple selectors, native sysctls, firewall ordering, revocation, failure
semantics and remaining feature limits.

Thirty focused host tests pass in 0.16 seconds, including invalid configuration,
asynchronous retirement, kernel rejection cleanup, foreign ownership, fatal and
timeout refusal, startup ownership/error propagation, and an actual orphaned
child process retaining the controller lease. Generated tuple selectors also
passed nftables syntax validation on the DUT.

Two DUT cases pass in 135.29 seconds. With persistent UDP and TCP sockets,
applying a UDP port exclusion retires all four existing hardware entries; TCP
readmits while UDP remains in software. A 256-record UDP measurement produces
260/266 software TX packets, while a separate 4 MiB TCP transfer produces only
3/10 software TX packets with increasing hardware counters. Invalid JSON leaves
the installed TCP generation unchanged. Removing the exclusion restores both
connections to hardware without deleting either conntrack. Before/after hardware
windows each verify 256 exact UDP hits and 4 MiB TCP per direction, 4/15 software
TX packets, and aggregate busy CPU 2.10%/2.22% (softirq 0.50%).

A structurally valid candidate using loopback as an offload device is rejected
by the kernel after old hardware drains. No policy/bindings/entries/references
remain, and both sockets continue in software (128 records, software TX
2947/2957). Separate foreign-binding and unmarked-table collisions are refused
without modifying the foreign table. KASAN/lockdep remain clean, debug_locks is
1, taint is 4096, installs equal deletes and all backend resources drain. CMM
stays disabled; no full suite was run.

The KASAN image was built/staged and installed controller/config/init-script
hashes were checked on the DUT. Kernel ID is
`3f9b9232f4cc77786b6d358bf81518cdbc251c90`, with CDX
`ed4251e6275e1ecbe06998b28203deb1a659b67a` and adapter
`a085496c134eedd293fe2a87a438e33a7bac5cb0`. Image SHA-256 is
`2699569ab2a26ffb613ce6cdfd16c1ab7729b29493695a67648d089a0514b9f3`.
Evidence is in `/tmp/ask-flowtable-policy/`; the build log is
`/tmp/ask-flowtable-policy-build.log` (three existing forced-task warnings).

## Startup independence — verified 2026-09-15

Flowtable and observe boots now omit FCI as well as automatic bridging and CMM.
The configuration package no longer requires the CMM package; the combined test
image still explicitly ships legacy components so a normal boot remains possible.
The flowtable controller has no legacy per-flow command dependency. CDX imports
no FCI module symbols; the adapter depends on CDX and nf_flow_table. dpa_app and
FMC import no CMM/FCI library. Their shared one-shot hardware initialization uses
FMC and the exclusive CDX configuration ioctls before the adapter claims/seals
configuration. This hardware setup remains part of the provider, not a retired
connection-manager responsibility.

Thirty-six focused host checks pass in 0.17 seconds: both active/observe boot
selections omit FCI, legacy mode retains its order, and ownership/failure/policy
contracts remain covered. The new clean-boot DUT test passes in 54.15 seconds.
CMM has never started and FCI/auto_bridge are absent; requesting CMM startup is
gated, and the shipped disabled policy hook completes with no bindings. UDP and
TCP then offload without either legacy component: 256 exact UDP hits per
direction, 4 MiB TCP per direction, software TX 4/15, aggregate busy CPU 2.03%
and softirq 0.41%.

The reference/lifecycle regression passes in 113.54 seconds. It explicitly loads
FCI just for unknown/reset rejection probes, then removes it before any traffic.
Counter-enabled hardware refusal, wire MAC/TTL/checksum/padding checks, three
live unbind/rebind cycles, active lifetime refresh and idle expiry all pass.
Final bindings, entries and references are zero; installs equal deletes, errors
and quarantine are zero. KASAN/lockdep diagnostics are clean, debug_locks is 1,
and taint is 4096. No full suite or alternative kernel was used.

The KASAN image was built and staged. Verified kernel ID is
`0b87e8d7167d903063914ad76d34bd2e6078ecd4`, CDX
`ed4251e6275e1ecbe06998b28203deb1a659b67a`, adapter
`a085496c134eedd293fe2a87a438e33a7bac5cb0`, and image SHA-256
`ad701fa10ff4f2fd3365cca2305634fa40d71cc0dd1845813f884b7ac7b5409a`.
Logs, dependency evidence and traffic records are in `/tmp/ask-flowtable-startup/`;
build log is `/tmp/ask-flowtable-startup-build.log` (three existing forced-task
warnings). Default-CMM compatibility is a separate final acceptance check.

## Foundation closure and legacy return — 2026-09-15

The planned foundation increments are complete within the bounded IPv4 TCP/UDP
scope. This includes automatic device/route/neighbour recovery, physical identity
and removal, provider terminal safety, partial-admission recovery, nexthop-object
retirement, policy/configuration migration with live revocation, CMM/FCI-free
startup, and concurrent reconfiguration/resource-pressure acceptance. The
[checkpoint](../../flowtable-foundation.md) separates those supported contracts from
future CMM feature parity. Existing proprietary firmware and initial FMC hardware
setup remain in use. No eBPF/XDP implementation or alternative-kernel work was
required to establish this boundary.

The final image was booted once into default CMM ownership for compatibility.
CMM/FCI/auto_bridge loaded, the experimental adapter stayed absent, and its policy
startup hook made no change. Both paced TCP hardware forwarding and unsupported
CMM control replies passed in 17.41 seconds. TCP delivered 500,170,752 bytes at
799.95 Mb/s; CMM's hardware connection table grew from zero to two identifiable
TCP connections. Software LAN RX increased by 428 packets versus at least 333,447
data frames. Idle/traffic busy CPU was 1.76%/3.44%, with traffic softirq 1.38%.
This proof uses hardware entries and software packet counts without requiring a
10 Gb/s link or a throughput threshold.

The first CMM traffic attempt ended before connection establishment with
"No route to host" and an empty hardware table. The LAN gateway neighbour was
FAILED while the 1 Gb/s link reported carrier. Ordinary ARP during a two-packet
gateway ping recovered the neighbour and both pings succeeded. The same CMM boot
then passed the two tests without configuration, reset or code changes. The
failure and connectivity observations remain in the artifacts; no cause or
network fix is inferred. Default-mode KASAN/lockdep diagnostics were clean,
debug_locks was 1 and taint was 4096.

Compatibility evidence is in `/tmp/ask-flowtable-acceptance/cmm/`, with the
successful run in `retry/`. This is the same staged KASAN image identified in
the startup increment above. The full KASAN suite and alternative kernel were
explicitly excluded. Each implementation or proved acceptance increment was
committed separately; no persistent boot environment, flash deployment or branch
push is part of this work.


A final fresh flowtable boot then passed the independent UDP/TCP startup proof
in 53.76 seconds, with CMM never started and FCI/auto_bridge absent. The hardware
window again delivered 256 exact UDP hits and 4 MiB TCP per direction. Software
TX was 4/15; aggregate busy CPU was
2.27% and softirq 0.41%.
The running kernel/module IDs match the staged image. Final state has
4 installs and 4 deletes, zero bindings/entries/handles/neighbour references,
zero invalidation/fatal/quarantine/errors, and all fault controls clear. KASAN and
lockdep remain clean with debug_locks 1 and taint 4096. Test tables, host routes,
NAT exemptions and temporary devices are removed; physical MTUs, NUD settings
and endpoint configuration are restored. The shipped policy remains disabled.
The LAN retains its verified 1 Gb/s link and default gateway. Final image,
traffic, cleanup and diagnostics evidence is in
`/tmp/ask-flowtable-acceptance/final/`.

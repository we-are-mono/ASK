# Consolidated implementation snapshot: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

Earlier consolidated contracts and focused-check instructions; some restrictions are superseded.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

This snapshot predates the completed current contract: its no-NAT and
permanent-source-MAC restrictions, partial fault-stage list and some test
instructions are historical. Use the current architecture and feature guides
for implementation and operation.

The snapshot's reference to an acceptance matrix points to the
[proposal's acceptance evidence](initial-proposal.md#acceptance-evidence).

## Implemented PoC contracts

The implementation is on `feat/linux-flowtable-offload`. The interfaces below
are implemented; the acceptance matrix above remains the gate for claiming a
verified foundation. Hardware measurements and any resulting restrictions will
be recorded alongside the tests.

The test initramfs reads `ask.offload=cmm|flowtable` from the kernel command line;
absence selects CMM. `ask.flowtable_observe=1` with flowtable ownership validates
requests but refuses hardware installation. CDX exposes these as read-only module
parameters `offload_owner` and `flowtable_observe`. Selecting a mode requires a
clean boot. The experimental init script skips `fci`, `auto_bridge` and CMM;
CDX skips the Wi-Fi and IPsec runtime offload hooks. If FCI is explicitly loaded
for a compatibility probe, all its commands return `-EOPNOTSUPP` in experimental
mode, including queries. Initial `dpa_app` setup is
shared, and subsequent SET_PARAMS requests are rejected. The boot script loads
`ask_flowtable.ko` after `cdx.ko` only for flowtable ownership. Read-only hardware
inspection is available through `/proc/cdx_flowtable` while the adapter is loaded,
independently of CMM.
The systemd CMM service also checks ownership; the kernel-command-line selector
itself is currently implemented by the test initramfs, not a production installer.

`cdx/ask_flowtable.c` uses Linux's indirect `TC_SETUP_FT` binding callbacks and
`TC_SETUP_CLSFLOWER` requests. It accepts one flowtable, at most two initial-netns
physical Ethernet ports, and at most 64 directional entries (up to 32 two-way
connections). This is a conservative adapter admission bound, not a firmware
capacity claim; it bounds the list walks under the control mutex and neighbour
spinlock. `/proc/cdx_flowtable` exposes it as `max_entries`. Directions consume
slots independently; existing owners are not evicted to admit another flow.
Cookies are opaque
and local to a binding. Unsupported selectors and actions fail before insertion.
The admitted rule has exact IPv4 TCP or UDP addresses and ports, an ingress
ifindex, four Ethernet rewrite words, and a redirect. TCP additionally requires
an assured, established Linux conntrack and the exact FIN/RST exclusion generated
by Netfilter; the parser contract and teardown semantics are described below.
The protocol participates in private hardware encoding and duplicate-key checks.
NAT, nondefault conntrack zones, conntrack marks, unsupported devices, and other
action lists are rejected. An alive, resolved ARP neighbour for the selected route
next hop on the egress port must match the requested destination MAC. Permanent entries
remain supported; ordinary REACHABLE, STALE, DELAY and PROBE entries are also
eligible. NOARP, unresolved, failed and detached entries are declined.
The current source MAC must equal the physical port's
permanent MAC. Both directly reachable destinations and IPv4 gateways are
supported through the route supplied by Linux. IPv6 gateways remain excluded.

Patch `140-ask-flowtable-context.patch` supplies borrowed conntrack and selected
route context for both directions, the directional effective MTU, and the
table's accounting requirement to callbacks. Context version 5 includes an
opaque, reference counted invalidation handle shared by a flow's two directions. The driver owns
one reference per installed direction; the handle retains no flow, conntrack,
route, table or namespace pointer. No borrowed context pointer or Linux flow
object is retained. This explicit, downstream, kernel-internal
interface avoids recovering a parent flow by casting its cookie. The adapter
must be built against this patch; the test image includes the native flowtable
and nftables modules it needs.

`cdx_flowtable_backend.h` defines the private adapter/CDX interface. Its CDX
implementation owns transactions, physical-port identity, an exclusive adapter
claim, hardware admission, statistics, retirement, quarantine recovery and the
terminal failure latch. Immutable owner/observe parameters remain on `cdx.ko`.
The adapter uses no CDX device, control or firmware structures. Transactions
currently use the existing CDX control mutex and also serialize adapter state;
they expose no mutex or internal structure to the adapter. Each transaction
must end before a Netfilter flush. Admission tries RTNL inside a transaction;
bind-time port checks are provisional and admission repeats them under RTNL.
Indirect UNBIND takes the flowtable's write lock before the CDX transaction.
Moving a published callback to the temporary unbind list must exclude native
statistics/add/delete walkers; Netfilter's later locked free alone is insufficient.

CDX configuration and final teardown acquire RTNL, try the control mutex, and
release RTNL before waiting for a busy control mutex and retrying. Neither lock
is waited on while holding the other. This matters even for an unrelated device:
Linux's DOWN notifier flushes native flowtable work, whose callbacks need the
control mutex. Final CDX shutdown stops its timer before releasing both locks
between hardware cleanup retries; external users have already released their
module references. Timer storage survives until the normal teardown callback.

Device events are relevant only when the device is bound or appears as an
installed direction's ingress/egress. Empty bindings remain watched, and egress
devices need not have their own binding. Matching uses pinned device objects,
not names or interface indices. `ft_watch_lock` protects binding publication,
removal and the existing flow dependency watches; a notifier latches invalidation
under that lock without taking a backend transaction. MTU and going-down events invalidate
affected per-flow handles and retire their hardware directions, leaving bindings
available for automatic admission of fresh Linux flow generations. Both routes
are revalidated under RTNL: the IPv4 MTU notifier flushes route caches under the
same lock, so an older queued request cannot install stale context. Empty
bindings need no MTU recovery. `mtu_invalidations` counts affected generations,
once per handle, rather than directions or notifications. Other recognized
events on relevant devices still invalidate the whole table and require table
recreation after recovery. Unrelated device events leave hardware flows alone.
Device recovery never clears a global invalidation or terminal hardware latch;
retirement errors escalate through the existing global recovery path.

Releasing a claim requires zero live directions. CDX keeps any retired storage,
the terminal failure latch and the sealed configuration gate independently of
the adapter. A fresh claim cannot bypass fatal failure or pending retirement.
The configuration ioctl rechecks the gate under the same transaction lock, so
a request already waiting when ownership is claimed cannot mutate configuration.

The interface uses GPL-only exports in the `ASK_CDX_FLOWTABLE` namespace.
`ask_flowtable.ko` depends on `cdx.ko` and `nf_flow_table.ko`; CDX itself has no
flowtable-module dependency. Normal module references prevent unloading CDX
while the adapter is loaded. Adapter exit invalidates its Linux flow handles,
unregisters notifiers, drains work and indirect callbacks, and completes hardware
retirement before releasing its claim. It retries with the transaction lock
released between attempts if a barrier or hardware quiescence is not yet proven.
Unload can therefore wait indefinitely for safe retirement.

Healthy adapter reload preserves CDX configuration and ownership. Existing nft
flowtables continue in software; recreate the table to bind the new adapter and
resume hardware admission. Adapter diagnostic counters reset on reload, while
CDX's sealed configuration and terminal failure latch persist. Reload is not a
recovery mechanism for a fatal hardware failure and cannot switch owners.

`cdx_flowtable_hw.c` is the CDX-internal firmware encoder behind this interface.
Each installed direction owns a private CDX encoding object, a dummy
reverse tuple, and an embedded route. These objects never enter the legacy
connection hash, route hash, CMM notification path, or ageing wheel. The existing
classifier encoder supplies routing actions, preemptive checks, and hardware
statistics. The adapter holds one ingress-device reference per binding and one
egress-device reference per installed direction. Installation uses the existing
ehash encoder and allocator. The adapter's backend owns its installed hardware
handles and their retirement; legacy objects retain their existing ownership.

Linux submits the two directions independently. A direction reports success
only after hardware installation succeeds. An identical replacement is
idempotent; a changed replacement retires the old entry before adding the new
one. A conflicting cookie for an existing hardware key is rejected. A rejected
second direction can leave the valid first direction installed, as permitted by
Linux flowtable semantics; the other direction uses software. Linux's
`[HW_OFFLOAD]` flag is therefore explicitly insufficient evidence that both
directions are accelerated. Tests inspect both hardware entries and both
physical software RX counters.

Statistics use monotonically increasing 64-bit hardware packet/byte counters;
callbacks report only the delta since the previous callback. A backwards sample
disables admission and retires the experiment instead of causing unsigned
underflow. Firmware timestamps use CDX's 32-bit jiffies clock. The adapter expands
them relative to current kernel jiffies; the supported idle interval must remain
below half that clock's range. Linux owns activity refresh and idle expiry.

Firmware counts classifier matches, including some later punts to Linux.
Hardware bytes include the Ethernet header and minimum-frame padding, excluding
FCS. Measurements give 298 bytes for a 256-byte UDP payload and 60 bytes for an
8-byte payload, in both directions. Same-tuple TTL/MTU exceptions also increment
the match counters before Linux handles them. These aggregates cannot recover
independently forwarded packets or exact IP bytes. Passing them into conntrack
accounting would mix byte units and count some packets twice.

The adapter therefore rejects a table with nftables `counter` enabled, leaving
it on software forwarding and accounting. If an existing table enables counters,
the next statistics callback invalidates the experiment without reporting its
hardware deltas to conntrack. Recreate the table to change accounting policy at
a defined boundary; do not interpret a running table's flag change as an atomic
accounting transition. Admitted tables use hardware activity for ageing, while
proc diagnostics expose raw classifier counters. Conntrack does not receive
hardware accounting contributions when the native `counter` flag is absent.
Accurate hardware accounting requires a separately verified post-punt firmware
measurement facility; it is outside this PoC's contract.

Backend transactions serialize list changes and all firmware operations. Netfilter
rule callbacks execute in workqueue context. Binding release runs after the flow
block excludes its callbacks. Notifiers latch invalidation and queue work; they
never enter a backend transaction. ARP callbacks inspect pinned, immutable
dependencies under a separate spinlock, nested inside the neighbour lock.
Global invalidation deletes the experimental entries before flushing Linux
flowtable work, ending the transaction before that flush. Selective
neighbour work removes entries sharing an invalid handle and leaves Linux
teardown to native GC. Module exit removes the proc entry and notifiers, cancels invalidation
work, and unregisters indirect callbacks before global CDX teardown acquires its
locks. The backend uses RTNL trylock for installation and fatal recovery,
because RTNL holders can wait for Netfilter callbacks. A busy RTNL lock on the
request's matching ingress retires that shared generation. Native GC and fresh
traffic can then retry through the same table. Requests visiting the other bound
port are declined before RTNL and cannot invalidate a successful direction.
Fatal recovery ends the transaction and retries. A port
must also match the netdevice recorded by CDX, not merely its name. Flowtables
must be bound after CDX initializes; incomplete indirect replay requests are
declined.

Initial-netns routing-policy events and relevant interface unregister or
upper-device changes conservatively disable hardware admission
until the recovery boundary below. Committed IPv4 route changes invalidate
connections with either endpoint in the changed prefix, conservatively across
all tables and DSCP aliases. Physical-port MTU changes invalidate generations
with that device as ingress or egress, preserving the table for automatic
readmission with current route MTUs. Going-down notifications use the same
per-device generation retirement; native DOWN also flushes Linux flowtable work.
Carrier loss also retires dependent generations. Physical MAC changes retire
both directions for automatic readmission with the current source address.
Queued requests with a stale source MAC invalidate their generation. The
firmware encoder's physical source cache is synchronized under its reader lock
within the admission transaction and RTNL. An OS rename preserves existing
entries and fresh binding because physical lookup and statistics use the pinned
device object, independent of its current name.
The backend refuses admission while either port is down, lacks carrier, or is
no longer registered.
IPv4's built-in nexthop ADD/DEL notifications arise during device/address
synchronization. They conservatively retire all installed generations, since a
revived alternative can change a route through another port. They preserve
bindings and are distinct from the nexthop-object API. Object replacement,
member/bucket changes and deletion conservatively invalidate the whole table;
statistics queries do not. Recovery requires table recreation after routing
has settled. Registration dumps before binding and teardown dumps are ignored.
A watched neighbour's changed MAC, unusable state
or detached object invalidates only dependent flow generations, including both directions. Their
cached Linux lookup stops immediately and native GC tears them down. Once
resolution is valid, fresh traffic can return to hardware without recreating
the table. Same-MAC NUD progress and unrelated ARP updates need no retirement.
Routes may change and neighbours may resolve through ordinary ARP after binding.
Selective and global retirement are asynchronous: inspect the affected
entries and reference counts for selective retirement, or `invalidation_done`
for global retirement. A hardware retirement error escalates to global recovery.

The committed-prefix netevent covers every IPv4 FIB alias insertion, replacement,
deletion and flush. The native FIB notifier reports selected aliases only and
can run before commit, so its entry notifications are not used for retirement.
Identical replacements and failed insertions emit no committed event. Both
endpoints are checked even when only one hardware direction exists; this relies
on the current no-NAT admission contract. CDX rechecks both borrowed destinations
under RTNL before admission to reject work queued before a route change. Linux's
existing route generation and expiry checks remain intact; unrelated software
cache entries may still expire under those native rules.

For opted-in flowtables, reverse IPv4 lookup also requires FIB success. The
normal forced-output-interface lookup permits an on-link route after a FIB
error, which could otherwise bypass withdrawal or a blackhole route through
software and hardware offload. The new internal lookup flag disables that
fallback for these tables; ordinary callers retain their existing behaviour.
The driver neither repeats policy routing with incomplete packet context nor
retains FIB objects. `route_invalidations` counts newly invalidated flow
generations, once per shared handle, including stale admission context.

Healthy global invalidation can recover by deleting and recreating the flowtable after
configuration has settled. Admission remains closed while any old binding or
entry exists, invalidation work is incomplete, or either retirement quarantine
contains storage. With all of these cleared, `rearm_ready=1` reports that the
driver can accept recovery. The candidate Linux table must also be empty: a
table with its hooks removed can still contain cached flows and queued callbacks.
The first successful binding to an empty table clears `invalidated` and
`invalidation_done`.
That binding increments `rearms`; adding the second port does not. Allocation
failure leaves the recovery state untouched. Install, delete and error counters
remain cumulative. Every new rule still passes the full Linux-context validation.

The control mutex protects this transition. The worker publishes completion as
its last state change, after hardware retirement and Linux flow cleanup. Binding
never waits for the worker: Netfilter locks held by a binding operation can be
needed by the cleanup being awaited. Recovery depends on complete withdrawal of
the old bindings, not a comparison of opaque table pointers, which can be reused.
The `TC_SETUP_FT` setup call borrows a live `struct nf_flowtable` from Netfilter;
only this call reads its hash population. The retained table pointer is used
solely for identity in other paths. This check is against the exact downstream
kernel interface and must be reviewed when porting the adapter.
Keeping an invalidated table bound does not re-enable it automatically. Fully
detaching and reattaching its devices is refused while cached flows remain;
deleting and recreating the table provides an empty candidate. Fatal
state independently refuses binding and installation, even with empty quarantine;
there is no runtime command to clear the fatal latch.

Deletion has three outcomes: synchronized removal, unlinked storage retained for
a barrier, or unproven unlink. All outcomes consume the adapter's software
handle. Failed deletion retains the already allocated backend owner in a private
retirement list, requiring no new allocation on the failure path. The worker
retries barriers until they succeed; it never retries the destructive unlink.
Quarantine and errors remain observable; a null handle is never treated as proof
of synchronization. Unproven unlink latches a fatal condition
and retries datapath quiescence until it succeeds or module shutdown takes over.
Fatal completion means the datapath was stopped, not that software fallback is
available. Reboot is required. Possibly linked hardware storage stays allocated
until reset; freeing it would leave a dangling hash-chain link. Shutdown releases
unlinked storage only after global datapath quiescence is proven. Healthy
invalidation waits for retirement barriers and flushes the affected software
flowtables, allowing ordinary forwarding.

The test build exposes a one-shot `ask_flowtable.flowtable_fail_stage` parameter: 1 before
adapter allocation, 2 before hardware installation, and 3 after installation,
forcing rollback through the real delete path. Production builds omit this
parameter. The load-only `ask_flowtable.init_fail_stage` parameter injects adapter
initialization failure after claim: 1 proc creation, 2 netdev notifier,
3 neighbour notifier, 4 FIB notifier, 5 indirect registration. A separate
test-only `cdx.flowtable_fail_unlink` boolean consumes one
delete attempt before destructive unlink, leaving the real key linked and
forcing fatal retirement. It exercises stopped classifier ports and retained
storage; it does not simulate a recoverable synchronization failure.
Host tests compile the production rule decoder and lifecycle code
with fault-injected kernel/firmware boundaries under ASan and UBSan; hardware
acceptance uses the real classifier and endpoint traffic.

`tools/tests/test_flowtable_offload.py` is explicitly gated by
`ASK_FLOWTABLE_TESTS=1`. It supplies a selected-protocol NAT exemption, permanent DUT
neighbours, a WAN host return route, and a numbered echo server, then restores
the fixture. TCP tests reuse the topology with a TCP peer instead of the echo
server. It uses the LAN UART and target/WAN agents without CMM helpers.
Runs can set `ASK_FLOWTABLE_ARTIFACTS` to retain measurements and packet captures.
The rearm test exercises three recovery cycles without rebooting. It changes the
DUT LAN device MTU, then adds a routing-policy rule, then injects two
retirement-barrier failures.
Each cycle proves software forwarding during invalidation and fresh hardware
forwarding after table recreation. Strict delivery checks use the NIC's normal
receive filter. Software TX enqueues distinguish software forwarding from
hardware delivery. The SDK RX statistic alone cannot do so: with GRO disabled,
software flowtable forwarding can consume an skb and return before the driver
increments RX. The test also refuses reattachment of a populated table whose
hooks have all been withdrawn. The separate invalidation test covers selective
neighbour deletion and global counter-policy or retirement-barrier failures.

`ASK_FLOWTABLE_TERMINAL=unload|unlink` separately selects a terminal lifecycle
test with `-k flowtable_offload_terminal`. Use a fresh experimental boot for
each variant. The test removes the inactive FCI module dependency, verifies
both hardware directions under traffic, and then unloads CDX or injects an
unproven unlink. The latter checks fatal status and disabled FMan receive ports,
refuses hardware bindings for a newly created flowtable, then removes CDX for
cleanup. Both variants finish by checking 64 ordinary UDP
exchanges with CDX absent. A continuous sender spans the intentional datapath
stop and validates every received payload; interruption during that stop is
recorded separately from the normal zero-loss forwarding oracle. DUT control
and fixture restoration use UART when the datapath can be unavailable. Neither
variant reloads CDX or switches owners; reboot afterward.

## Running the focused checks

Build with `KASAN=1 make ask-image`, then run `make stage-image`. Boot the staged
RAM image with `ask.offload=flowtable`; add `ask.flowtable_observe=1` for an
observe-only boot. Start from a clean boot for each invalidation variant. The
boot selector is transient; returning to CMM means rebooting with both experimental
arguments absent. Do not unload/reload modules to switch owners.

With the normal LAN UART and DUT/WAN agents available, run:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=<WAN-address> make ask-test \
  ASK_TEST_ARGS='-k flowtable_offload -x -q'
```

The ordinary run selects five PoC scenarios: reference/forwarding/lifecycle,
same-tuple exceptions, installation rollback, recovery, and neighbour invalidation. The
optional long-exchange diagnostic skips by default. The lifecycle includes a
512-packet hardware measurement, minimum-size packets, three removals under
traffic, 65 seconds of activity refresh, and a bounded idle-expiry wait. Tests
validate payloads and Ethernet/IP behaviour; they never equate classifier hits
or Linux's hardware flag with successful delivery.

For the recovery increment alone, select just the recovery and fatal-refusal
checks on a fresh experimental boot:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_FLOWTABLE_TERMINAL=unlink \
  ASK_WAN_IPERF_IP=<WAN-address> make ask-test \
  ASK_TEST_ARGS='-k "flowtable_offload_rearm or flowtable_offload_terminal" -x -q'
```

The terminal test removes CDX, so reboot in experimental mode afterward. The
recovery test itself needs no reboot or return to CMM between its cycles.

On a separate experimental boot, exercise failed retirement barriers with:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_FLOWTABLE_INVALIDATION=barrier \
  ASK_WAN_IPERF_IP=<WAN-address> make ask-test \
  ASK_TEST_ARGS='-k flowtable_offload_invalidation -x -q'
```

`ASK_FLOWTABLE_BASELINE=software|flowtable|hardware` with
`-k flowtable_offload_long_exchange` selects an explicit 4,096-packet diagnostic
through ordinary routing, software flowtable, or hardware offload. It leaves the
LAN NIC out of promiscuous mode and records raw frames, classifier state,
conntrack, and endpoint error counters on a timeout. Other packet checks use
promiscuous capture so an unexpected Ethernet destination remains observable.

After a normal CMM boot, the selected compatibility checks are:

```sh
ASK_WAN_IPERF_IP=<WAN-address> make ask-test \
  ASK_TEST_ARGS='-k "test_cmm_unsupported_commands or test_iperf_ipv4_tcp_offload" -x -q'
```

The focused host command is `sudo /opt/askd-agent/venv/bin/pytest -c
tools/pyproject.toml tools/host_tests -k 'flowtable or cdx_shutdown' -q` with the
standard host setup. These tests compile production decoder, backend ownership,
and teardown code under ASan/UBSan. This procedure does not run the full DUT
KASAN suite.

`ASK_FLOWTABLE_INVALIDATION=counter` selects a separate-boot test which enables
accounting on an active hardware table and verifies retirement and software
fallback. It exercises the runtime accounting guard in addition to the normal
test's refusal to install into a table that already requests counters.

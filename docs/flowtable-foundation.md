# CMM retirement foundation

Accepted on 2026-09-15 for the supported boundary below. Recovery/lifecycle,
configuration and revocation, startup independence, pressure/concurrency, legacy
compatibility, and the final return to flowtable mode have passed their focused
proofs. Each increment is committed in the development branch.

This checkpoint covers the maintained Linux flowtable/CDX foundation on the
repository's Linux 6.12.103 kernel and existing proprietary NXP firmware. It
does not imply feature parity with CMM. The detailed implementation and dated
evidence remain in [the design record](linux-flowtable-offload.md). Subsequent
feature increments extend this checkpoint; [static UDP SNAT](flowtable-nat.md)
is the first such addition.

## Supported boundary

Linux owns IPv4 TCP/UDP conntracks, flow lifetimes, routing, neighbours and
admission policy. The loadable `ask_flowtable` adapter supplies native flowtable
callbacks; CDX owns hardware encoding, resources and safe retirement. The
adapter uses a kernel backend interface, with no per-flow FCI commands.
dpa_app/FMC still initialize the hardware once at provider startup.

The accepted foundation supports one hardware flowtable over two initial-network-
namespace physical ports, at most 64 directional entries, and routed IPv4
TCP/UDP without NAT. Addresses can resolve through ordinary ARP and IPv4 gateway
routes. The controller starts disabled and applies explicit nftables scope and
exclusions. Unsupported traffic remains subject to ordinary Linux forwarding
and firewall policy.

This is sufficient to build subsequent CMM-retirement features on a proved
ownership and lifecycle boundary. NAT, IPv6, VLAN/bridge/PPPoE, multicast, IPsec,
tunnels, Wi-Fi and asymmetric acceleration need their own implementations and
proofs. Their legacy availability does not establish support in the new path.
eBPF/XDP is an optional later consumer or policy mechanism, not a prerequisite
for operating the supported flowtable/CDX path.

## Recovery and policy contracts

| Event | Recovery |
| --- | --- |
| Neighbour MAC/state change | Retire dependent generations; fresh traffic readmits after resolution |
| IPv4 route-prefix change | Retire affected generations; fresh route lookup readmits |
| Physical MTU, MAC, carrier or administrative down/up change | Retire dependent generations; current device/route state gates automatic readmission |
| Rename | Preserve physical identity, installed cookies and fresh binding under the new name |
| Transient matching admission contention | Retire a partial generation; native GC and fresh traffic retry both directions |
| Routing policy, nexthop-object or unsupported topology change | Globally stop admission; recreate/apply the table after configuration settles |
| Healthy adapter unload | Drain hardware; existing sockets forward in Linux; reload and recreate the table to regain hardware |
| Actual physical driver removal | Retire flow references; full CDX teardown releases remaining configuration/queue pins before driver removal completes |
| Recoverable hardware barrier failure | Retry safe retirement according to the provider contract; quarantine remains accounted for |
| Terminal hardware failure | Preserve the stop and quarantine; administrative UP and adapter reload cannot bypass it; full provider teardown and fresh boot are required |
| Exclusion/policy replacement | Delete the owned table and prove hardware/reference drain before publishing the new policy |

The [policy guide](flowtable-policy.md) specifies CLI use, useful CMM setting
mapping, native sysctls, forward-chain priority and the firewall-change
revocation sequence. Changing external firewall rules alone does not revoke a
cached hardware flow. Configuration apply preserves sockets and conntracks,
serializes concurrent controllers, and refuses foreign ownership. A failed
candidate after retirement leaves acceleration disabled; a failed retirement
reports recovery requirements instead of claiming a safe state.

## Acceptance and limits

Acceptance combines host checks of production code with focused DUT tests using
KASAN and lockdep. It includes exact numbered UDP payloads, persistent TCP,
independent hardware counters, software interface packet counts, CPU windows,
allocation/install/retirement faults, notifier changes, module lifecycle and
balanced references. A conntrack hardware flag or throughput alone is not proof.

The bounded connection test verifies independent conntrack deletion, FIN, idle
expiry, unaffected surviving cookies and resource reuse. The pressure and
concurrent-policy results, plus final legacy compatibility and return-to-
flowtable verification, are recorded in the dated design log.

Hardware counters report classifier hits, including packets subsequently punted
for exceptions. Exact Linux post-punt conntrack accounting remains outside the
contract; counter-enabled hardware tables are refused. Capacity and allocation
refusals preserve software forwarding and bounded ownership. Hardware admission
is directional; resource refusal is not a promise of atomic two-direction
installation. Transient lock contention has explicit partial-generation recovery.

Validation uses the existing 6.12.103 KASAN image, with the relevant tests only.
The alternative-kernel exercise and full KASAN suite were explicitly excluded.
This is not validation of every kernel version, a non-KASAN production image,
unbounded resources, long-duration soak, or every combination of future features.
Previously observed intermittent link loss remains documented; it has not been
reclassified as solved by an unrelated change. The current hardware proofs use
the stable 1 Gb/s lab link and actual offload counters.

Legacy mode remains the default boot selection and retains CMM/FCI. The
experimental selector is temporary, and no persistent boot environment or
flash update is required. Hardware ownership cannot be switched live by the
policy tool. Production image packaging and deployment policy remain separate
from this foundation acceptance.

## Focused reproduction

Build the instrumented image with `KASAN=1 make ask-image`, then run
`make stage-image`. Boot it with `ask.offload=flowtable` for the flowtable
checks. Use the bench's WAN address and distinct source-port ranges between
TCP tests to avoid endpoint TIME_WAIT conflicts. For this bench:

```sh
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=54000 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_startup_without_cmm_or_fci'
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=54100 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_capacity_overflow_and_reuse'
ASK_FLOWTABLE_TESTS=1 ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=54200 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_concurrent_policy_and_routes'
```

After a separate default-CMM boot, its focused compatibility checks are:

```sh
ASK_CMM_COMPAT=1 ASK_WAN_IPERF_IP=10.0.0.232 \
  make ask-test ASK_TEST_ARGS='-q -k "test_cmm_paced_tcp_compatibility or test_cmm_unsupported_commands"'
```

Return to a fresh flowtable boot afterward if continuing development. These
commands select specific tests; omitting `-k` would collect and run unrelated
tests. The detailed design record contains the individual recovery/fault probes
and their required boot boundaries.

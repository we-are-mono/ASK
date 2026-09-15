# Double NAT and hairpin routing — 2026-09-15

The decoder now accepts completed source and destination translations in the
same IPv4 TCP/UDP conntrack. It validates the native SNAT edit pair, DNAT edit
pair, shared checksum action and redirect against the inverse opposite tuple.
Both completion flags are required. Same-port routing is admitted only for this
combined NAT contract; single-translation and untranslated same-port traffic
remain outside adapter eligibility.

CDX's provider no longer independently forbids same-port output. The adapter is
its only production caller and owns NAT eligibility; the provider still checks
ownership, retirement state, physical device identity and current source MAC.
The firmware encoder and kernel patch remain unchanged.

## Verification

All 35 focused host tests pass with ASan/UBSan. They exercise both directions and
protocols, malformed and incomplete combined action lists, all three insertion
rollback stages, partial-direction route retirement, same-device reference
balance, and continued rejection of source-only/destination-only same-port NAT.
The encoder tests cover simultaneous address/port changes and same-port routes.
A provider-level test exercises `cdx_ft_add()` through successful same-port
insertion and retirement, so its admission guard cannot silently exclude the
adapter's supported mapping.

The rebuilt and staged Linux 6.12.103 KASAN image proves two topologies:

- WAN-to-LAN double NAT: Vision connects to DUT public port 49271, forwarded to
  Loki port 48271, while the source becomes the DUT LAN address with a forced
  source port. Every address and transport port rewrite is checked in hardware.
- Same-port hairpin: two separate MAC/IP endpoints in Loki namespaces use
  `198.18.42.2` and `.3`, with DUT LAN gateway `.1`. Client traffic targets the
  DUT's WAN address and public port. Native DNAT selects the internal server;
  SNAT forces replies back through the DUT. All four TCP/UDP hardware directions
  enter and leave `eth3`. Raw receive frames have the DUT's source MAC and TTL 63,
  proving a routed hop rather than a direct macvlan exchange.

Each topology runs with ordinary and zero UDP checksums. Each case validates
three hardware windows of 256 UDP records and 4 MiB TCP per direction. UDP
counters increase by exactly 256 packets and 76,288 bytes per direction; TCP
classifier counters exceed the payload packet lower bound. Both endpoint UDP
captures independently validate checksums and exact payload sequences. TCP
endpoints validate exact 16 KiB records. No packet loss or corruption is allowed.

The same sockets cross one-shot post-insert rollback, dependent route
replacement, policy removal during active traffic, software forwarding and
policy reapplication. Conntrack IDs remain unchanged across policy withdrawal.
Native FIN removes both TCP hardware directions while UDP stays installed;
LAST_ACK/TIME_WAIT retains the established foundation semantics.

Both hairpin cases pass in 100.49 seconds with automatic cleanup. Software TX
is 3–5 LAN / 14–16 WAN per hardware window. Ordinary-checksum windows record
16.56–25.25% aggregate busy CPU while the initial kmemleak scan is active; the
post-test process snapshot records 26.22 CPU seconds in kmemleak, the largest
consumer. Those windows are not a near-idle CPU proof. Two later zero-checksum
windows record 1.89% busy CPU with 0.38–0.41% softirq; its route window records
5.29% busy with 0.25% softirq. Hardware cookies and counters and low software TX
remain consistent throughout. The scanner remains enabled.

## Development finding and artifacts

The first image passed both cross-port double NAT cases but could not install
hairpin directions: CDX's provider retained an independent `in == out` rejection.
The failed run and image identity are retained under `proof/` and
`initial-image-identity.json`. Extending the provider and its host test fixes
that incomplete admission path; the authoritative hairpin result uses the
rebuilt image in `hairpin-proof/`.

Artifacts are under `/tmp/ask-flowtable-double-nat/`; final cross-port and TCP
MASQUERADE regression evidence is in `regression-proof/`. No CMM detour,
alternative kernel or full KASAN suite is used. All builds are staged; only the
three pre-existing forced-task notices appear, with no compiler warnings.

Kernel build ID: `c74354b87985d29ae04a8027b180a8f04b5303c9`.
CDX build ID: `fc9a2e4c48a5d102767018464d154cca931aec4a`.
Adapter build ID: `07400102cf0f45474668adc1126e07d4dea7a527`.
Staged image SHA-256:
`d59bc317af2af3d32abd7644c41a5ac548a889076bafb303eadf19acae139050`.
Running kernel/module identities, userspace hashes and staged/built image hashes
match. The in-memory boot uses `ask.offload=flowtable`; CMM, FCI and auto_bridge
remain absent.

The final regression run passes five tests in 238.41 seconds: both double-NAT
cases, both hairpin cases again, and TCP MASQUERADE. The twelve combined-NAT
hardware windows record software TX 2/11 for cross-port forwarding and 3–4/14
for hairpin forwarding. Ten windows have aggregate busy CPU 1.64–1.92%; two
route/initial windows record 5.36–5.41%. All softirq readings are 0.28–0.44%. The ordinary-checksum
hairpin repeat supplies the quiet-CPU evidence absent during the first scan.
TCP MASQUERADE survives 23 deliberately dropped packets with 25 retransmissions,
a 16 MiB transfer during policy withdrawal, a subsequent 64 MiB hardware window
with software TX 0/10 and CPU 1.70%, and native RST expiry.

Final diagnostics balance all 82 hardware installs/deletes in this boot. Entries,
bindings, neighbour/handle references, errors, fatal state, quarantine and global
invalidation are zero. KASAN/lockdep remain clean, debug_locks is 1 and taint is
4096. Temporary namespaces, policy/NAT tables, addresses and routes are removed;
accounting and timeout settings are restored. Loki had negotiated 1 Gb/s after
the reboot; an explicit autonegotiation restart restores 10 Gb/s and three
lossless gateway pings before the subsequent throughput work. The final cleanup
check confirms 10 Gb/s, the original LAN MAC and default gateway.

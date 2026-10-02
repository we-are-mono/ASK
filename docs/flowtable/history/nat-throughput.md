# Full-rate TCP NAT — 2026-09-15

Loki → DUT → Vision reaches **9.414 Gb/s TCP receive throughput** with native
MASQUERADE and Linux flowtable/CDX hardware forwarding. Both endpoint links are
10 Gb/s full duplex. This is approximately the payload ceiling for 1500-byte
Ethernet frames with IPv4/TCP timestamps; it is not a 10 Gb/s application-payload
claim.

## Method and result

The opt-in `test_flowtable_nat_throughput` uses iperf3 3.18 on both endpoints,
four parallel TCP streams, a three-second warmup and a 20-second measured run.
Loki uses zero-copy sending. The test configures native MASQUERADE for the exact
peer/service and production acceleration policy for that scope. It selects all
four bulk sockets by measured hardware activity, independently of iperf's
control connection, and checks both translated directions for each.

Temporary endpoint host routes provide fresh MTU 1500 metrics, avoiding cached
MTU 1200 from prior exception tests. The corresponding DUT host routes use MTU
1500. Endpoint routes, NAT rules, policy and test conntracks are removed after
completion. The benchmark requires at least 9 Gb/s by default; the minimum can
be explicitly configured with `ASK_FLOWTABLE_MIN_GBPS`.

| Measurement | Result |
| --- | --- |
| Vision received payload | 23,536,992,256 bytes over 20.000979 seconds |
| Vision receive rate | 9,414,336,071 bit/s |
| Loki send rate | 9,413,492,934 bit/s |
| TCP payload MSS | 1448 bytes |
| TCP retransmissions | 101 across the four measured streams |
| DUT aggregate busy CPU during the hardware window | 1.84% |
| DUT aggregate softirq CPU | 0.43% |
| DUT software TX during that window | LAN 0 / WAN 10 packets |
| Hardware data-direction classifier deltas | 8,270,597 packets; 12,521,682,786 bytes |
| Hardware reply-direction classifier deltas | 2,881,887 packets |
| Vision NIC CRC/error/drop counter increases | 0 |

The hardware window includes ten seconds of sustained transfer plus the counter
read boundaries. Its eight bulk-direction cookies remain stable, and the table
has ten directions including iperf's control connection. Hardware counters count
classifier hits, not independently verified forwarded packets; the measured
receiver throughput and near-zero software TX establish the accelerated path.
The benchmark supplies throughput evidence. Exact data/checksum and lifecycle
correctness comes from the separate NAT acceptance tests.

The complete focused benchmark passes in 34.34 seconds. It does not establish
long-duration soak, small-packet line rate, a single-stream ceiling, every NAT
topology at line rate, or production-image parity. The DUT retains KASAN,
kmemleak and lockdep instrumentation. CMM, FCI and auto_bridge remain absent.

## Link preparation and reproducibility

Following the final image reboot, Loki negotiated 1 Gb/s despite advertising
10 Gb/s. Reapplying unchanged advertisement did not restart negotiation.
`ethtool -r enp4s0` restored 10 Gb/s and three lossless gateway pings, preserving
the default route. The benchmark verifies Loki's 10 Gb/s/full-duplex state;
Vision's physical `enp1s0` link and NIC counters are recorded separately.

```sh
ASK_FLOWTABLE_TESTS=1 ASK_FLOWTABLE_THROUGHPUT=1 \
  ASK_WAN_IPERF_IP=10.0.0.232 ASK_FLOWTABLE_SPORT=55700 \
  make ask-test ASK_TEST_ARGS='-q -k test_flowtable_nat_throughput'
```

Evidence is under `/tmp/ask-flowtable-nat-throughput/`, with benchmark JSON in
`proof/`. It uses the same running image and verified identities as the
[combined NAT proof](double-nat.md). No additional image build, alternative
kernel or full KASAN suite is required for this test/documentation increment.

Final diagnostics balance all 92 installs and deletes in this boot. Entries,
bindings, neighbour/handle references, errors, fatal state, quarantine and global
invalidation are zero. KASAN/lockdep are clean, debug_locks is 1 and taint is
4096. Both links remain at 10 Gb/s; temporary benchmark routes, rules, processes
and conntracks are removed. The default flowtable policy remains disabled.

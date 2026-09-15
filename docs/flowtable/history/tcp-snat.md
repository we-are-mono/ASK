# Static TCP source NAT — 2026-09-15

The adapter accepts Linux's native static IPv4 TCP SNAT and inverse reply
actions. TCP state, assured status and exact FIN/RST exclusion remain mandatory.
The transport edit and checksum action must match TCP; UDP-shaped actions are
rejected. The existing CDX translation encoder handles the resolved mapping.
No kernel patch, firmware change, CMM or FCI dependency was added.

The policy tool now admits static TCP SNAT within its configured scope. Native
Linux conntrack still owns NAT allocation and lifetime. MASQUERADE, DNAT and
hairpin/double NAT remain subsequent increments at this checkpoint.

## Verification

All 35 focused host tests pass, including production action decoding and backend
encoding for TCP and UDP in both directions, address-only/port-only edits,
malformed actions, TCP-state rejection and balanced rollback/retirement.

On the rebuilt and staged Linux 6.12.103 KASAN image:

- The FIN/idle test passes in 42.03 seconds. A forced source address and source
  port change is checked in both hardware tuples and at the receiving TCP socket.
  Each direction transfers 64 MiB with exact payload/SHA-256 validation. Upload
  records 59,393 forward classifier packets and download 59,406. LAN software TX
  is zero in both windows; WAN software TX is 10 and 19 packets. Aggregate busy
  CPU is 1.98% and 1.83%, versus 1.88% during the idle reference; softirq is
  0.35% and 0.44%.
- The same connection survives hardware idle expiry and reinstallation. Linux
  sees both SYNs and both FINs. A WAN capture proves both FINs and the final ACK
  using the translated endpoint. Hardware disappears promptly, and the native
  LAST_ACK conntrack expires without an OFFLOAD flag.
- The retransmit/withdraw/RST test passes in 36.94 seconds. Deliberate WAN loss
  drops 39 translated TCP packets; the exact 8 MiB upload completes with sender
  retransmissions. The production policy is stopped during a 16 MiB download.
  The transfer completes through software with the original conntrack ID.
  Policy reapplication accelerates that same socket again: a further 64 MiB
  upload records 59,393 forward classifier packets, software TX 0/10 and
  aggregate busy CPU 1.86% (0.41% softirq).
- RST reaches the endpoint and Linux, removes hardware promptly, and applies the
  native short CLOSE timeout. Linux temporarily retains ESTABLISHED because its
  last observed sequence predates offloaded data; the conntrack then expires.

These TCP tests validate payload integrity and TCP operation at both endpoints;
they do not claim the UDP proof's independent raw checksum capture in both
transport directions. FIN capture, exact translation/action checks, hardware
counters and software TX are recorded separately.

## Image and artifacts

Kernel build ID: `1c90d0816c964670b3bd8001c3c93dd35a9822b7`.
CDX build ID: `d429365f186f75210e4bc0ca00e580469fb1f109`.
Adapter build ID: `251d28c2f500d0ebcf30f56ffb78555485e9b05e`.
Staged image SHA-256: `5067352df221d3668e65cfa5b2d53de401028a9a9440b4198efdd347ecd7f5db`.

Running build IDs and userspace hashes match the built image; staged and built
image hashes match. The build has no compiler warnings, with only the three
existing forced-task notices. Artifacts are under `/tmp/ask-flowtable-tcp-snat/`.
Only focused tests run; no full KASAN suite or alternative kernel is used.

The focused UDP SNAT checksum regression and CMM/FCI-free TCP/UDP startup
regression both pass (132.88 seconds combined). UDP retains exact 256-packet,
76,288-byte hardware deltas in each direction across its three windows;
software TX is 5/14. Startup records software TX 4/16 and aggregate busy CPU
2.15%. The UDP initial window's aggregate busy CPU is 5.26%; its later windows
are 1.91%, with low softirq throughout.

Final cleanup balances all 19 installs with deletes. Entries, bindings,
handle/neighbour references, errors, quarantine and invalidation are zero.
KASAN/lockdep diagnostics are clean, debug_locks remains 1, and taint is 4096
(out-of-tree modules only). Fault knobs, test tables, routes and NAT exemptions
are cleared. CMM/FCI/auto_bridge remain absent and the default policy is disabled.
The DUT remains in flowtable mode with Loki at 1 Gb/s.

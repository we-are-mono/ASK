# MASQUERADE — 2026-09-15

TCP/UDP MASQUERADE uses the same exact native source translation action contract
as static SNAT. The adapter no longer rejects Linux's masquerade metadata.
Linux selects the address/port and owns interface/address-triggered conntrack
cleanup; the existing flowtable and device/route retirement paths remove the
hardware. The image packages `nft_masq`. No firmware or kernel patch is changed.

## Verified behavior

All 35 focused host tests pass. The production decoder accepts native TCP/UDP
masquerade mappings while retaining tuple, mask, checksum and TCP-state checks.
The rebuilt/staged Linux 6.12.103 KASAN image passes these focused DUT tests:

- UDP and TCP translation tests pass together in 116.77 seconds. UDP checks
  forced source address/port translation and raw receive checksums at both
  endpoints, rollback, route readmission and live policy stop/reapply. Its three
  hardware windows each add exactly 256 packets and 76,288 bytes per direction;
  software TX is 4–5 LAN / 14 WAN, aggregate busy CPU 1.79–1.88%. The software
  window records 259/265 TX packets and preserves the socket/conntrack ID.
- TCP completes an 8 MiB upload despite 20 deliberately dropped packets and 21
  retransmissions. A 16 MiB download crosses policy withdrawal without changing
  its conntrack ID. After reapplication, 64 MiB transfers through hardware with
  software TX 0/10 and aggregate busy CPU 1.92% (0.38% softirq). RST reaches Linux,
  removes offload and expires the conntrack under the native close timeout.
- The final WAN lifecycle test passes in 83.06 seconds with automatic cleanup.
  It uses temporary WAN subnet `198.18.40.0/24`, preserving the management IP.
  Active UDP and TCP mappings use `198.18.40.1` with forced source ports. Removing
  that address deletes both conntracks and all four hardware directions.
  Replacement `198.18.40.3` is used by fresh connections; taking the WAN device
  down again deletes both mappings/directions. Fresh connections after UP return
  to hardware with the same policy bindings and no global invalidation/rearm.
- Each of the three lifecycle windows transfers 256 exact UDP records and
  4 MiB TCP in each direction. UDP replies have independent raw receive checksum
  checks. Hardware cookies and install/delete counts stay stable within every
  window. Software TX is 4/14, 4/14 and 4/18; aggregate busy CPU is 1.89%, 1.98%
  and 2.08% (softirq 0.35%, 0.35%, 0.50%). Both destructive transitions leave zero
  entries, neighbour references and handle references, with all deletes balanced.

This establishes the tested Linux address/interface lifecycle, not instantaneous
revocation or survival of established sockets after their mapping is destroyed.
Policy stop/apply preserves mappings; address/device removal has different native
semantics. DNAT and hairpin/double NAT remain subsequent increments.

## Setup and harness corrections

The first TFTP attempt timed out during ARP; retry loaded the staged image.
After boot, Loki could not resolve the DUT LAN gateway before any flow installed.
An X550 restart alone did not restore traffic. Restarting DUT `eth3` did, with
three pings received without loss. Loki's default route, removed by its restart,
was restored before verification. Both endpoints retain their original MACs;
Loki remains at 1 Gb/s. These observations do not establish a link-failure cause.

The initial lifecycle poller mistook conntrack's stderr entry-count summary
(merged into UART stdout) for a live mapping. It now selects actual ID rows.
The TCP harness also waited for Python 3.13 listening-server closure before
closing unreachable accepted clients. Teardown now aborts remaining accepted
transports before waiting for server closure, bounds control-channel closure,
and permits explicit abort of test sockets whose NAT mapping was destroyed.
One interrupted attempt and one manually drained attempt are retained as failed
verification runs. The final 83.06-second run requires neither intervention.

## Image and artifacts

Kernel build ID: `d545b58bd9cdf9435af9c1f95e517aec9687617e`.
CDX build ID: `d429365f186f75210e4bc0ca00e580469fb1f109`.
Adapter build ID: `49ac835dd82a0947dac31ea9fb25f704d4d6f8a5`.
Staged image SHA-256: `cf2f54590bbe537285c5b7663f1068426e84aec80641251e059a1048f1adfc12`.

Running module/kernel identities, userspace hashes and staged/built image hashes
match. No compiler warnings occurred; the three existing forced-task notices
remain. Evidence, including unsuccessful setup/harness runs, is under
`/tmp/ask-flowtable-masquerade/`; final proofs are `translation-final/` and
`lifecycle-verified/`. Only focused tests ran, without the full KASAN suite,
an alternative kernel or a return to CMM.

Final diagnostics balance all 39 installs/deletes, including earlier
failed harness attempts. Entries, bindings, handle/neighbour references, errors,
fatal state, quarantine and global invalidation are zero. KASAN/lockdep are
clean, debug_locks is 1 and taint is 4096. Test tables, NAT exemptions, temporary
addresses and routes are gone; timeouts/accounting and LAN settings are restored.
CMM/FCI/auto_bridge remain absent and the default policy is disabled.

# Destination NAT — 2026-09-15

The adapter accepts Linux's completed IPv4 TCP/UDP destination translation and
its inverse reply actions. It checks the exact conntrack tuples, unchanged
client endpoint, IPv4/transport edits and checksum action before admission.
The policy tool permits DNAT within the configured original/reply tuple scope.
No kernel patch, firmware change or legacy encoder change is required.

## Verified behavior

All 35 focused host tests pass with ASan/UBSan. They cover both TCP/UDP directions,
malformed or incomplete actions, hidden double NAT, insertion rollback and
retirement of a translated route with only one direction installed.

The staged Linux 6.12.103 KASAN image passes ordinary- and zero-checksum DNAT,
UDP MASQUERADE regression, and startup independence tests. WAN client
`10.0.0.232` connects to public `10.0.0.62:49271`, forwarded to
`192.168.1.122:48271` on Loki. Both endpoint links negotiate 10 Gb/s full duplex.
These are paced correctness tests; they do not measure maximum throughput.

Each DNAT case proves:

- Both address and port changes, all four TCP/UDP hardware directions, correct
  translated next hops and MTU 1200. Raw receive captures at both endpoints check
  Ethernet/IP/UDP fields, TTL 63, exact payload sequence and checksums. Zero UDP
  checksums remain zero. TCP endpoints echo exact 16 KiB records.
- One-shot post-insert rollback, route replacement affecting the internal
  destination, live policy withdrawal, software forwarding and readmission.
  The same two sockets and conntrack IDs survive policy stop/apply.
- Three hardware windows each deliver 256 UDP records and 4 MiB TCP in each
  direction. UDP counters increase by exactly 256 packets and 76,288 bytes per
  direction. TCP classifier counts exceed the payload packet lower bound;
  cookies and install/delete counts remain stable throughout each window.
- Software TX is 2 LAN / 11 WAN in every hardware window. Aggregate busy CPU is
  1.76–2.02% in five windows; the last zero-checksum window records 5.26%, with
  0.25% softirq. The software windows record 5,893/5,896 and 5,896/5,906 TX packets.
- Both TCP hardware directions retire after FIN while UDP remains installed.
  Conntrack reaches LAST_ACK, which is permitted by the existing TCP contract:
  the final ACK can cross hardware before asynchronous removal completes.
  This test does not independently prove DNAT conntrack close-timeout expiry.
- Endpoint totals are 1,536 and 1,600 exact records per protocol for ordinary and
  zero-checksum cases respectively, with no server validation errors.

## Harness corrections and evidence

Initial broad packet sockets overflowed while queueing concurrent TCP and
unrelated host UDP traffic. Socket drop counters confirmed the capture loss.
The receive helper now uses classic socket BPF to select the test UDP destination
port; the independent validator retains every tuple, payload and checksum check.
The controller checks server status between batches and maintains the peer's
bounded lease. The first complete run's TIME_WAIT-only assertion was corrected
to the foundation's documented LAST_ACK/TIME_WAIT contract. Failed attempts are
retained as such; the final focused run completed with automatic cleanup.

Artifacts are under `/tmp/ask-flowtable-dnat/`, with authoritative data in
`final-proof/`. Kernel build ID: `a7a91fffdeb935620f57587b661790666a1c4f16`.
CDX build ID: `d429365f186f75210e4bc0ca00e580469fb1f109`.
Adapter build ID: `2865f54b6e21d52d6c09d2411ce1877251638abd`.
Staged image SHA-256:
`10a3ab769a1871161fd8f933fc323a035422ac4228e4e66346d0bf52ca2328f2`.
Running identities and userspace hashes match the built and staged artifacts.
Only the three pre-existing forced-task notices appear during the build; there
are no compiler warnings. No full KASAN suite, alternative kernel or CMM detour
was used. Double NAT and same-port hairpin remain the next increment.

The final focused run passes all four DUT tests in 235.87 seconds. Final
diagnostics balance 69 installs and deletes, including failed harness attempts.
Entries, bindings, neighbour/handle references, errors, fatal state, quarantine
and global invalidation are zero. KASAN/lockdep remain clean, debug_locks is 1
and taint is 4096. Temporary policy/NAT tables and routes are removed, timeouts
and accounting are restored, and Loki retains 10 Gb/s with its original MAC and
default gateway. CMM, FCI and auto_bridge are absent.

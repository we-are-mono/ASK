# Static UDP SNAT: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

Forced translation, endpoint checksums, route recovery and live software fallback.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## Static UDP source NAT — 2026-09-15

The first feature increment after foundation acceptance admits static IPv4 UDP
SNAT, including source-port translation and its inverse on replies. Linux owns
the resolved conntrack mapping. The adapter validates the exact native action
sequence against both tuples and passes complete match/translated tuples through
the private backend API. CDX's standalone directional entry supplies the existing
encoder with an inverse translated twin; the legacy encoder and proprietary
firmware are unchanged. TCP NAT, MASQUERADE, DNAT and double/hairpin NAT remain
outside hardware eligibility. See the [NAT contract](../../flowtable-nat.md).

Reply neighbour lookup now uses the translated LAN destination. Route-prefix
retirement watches each direction's translated destination and match source,
covering both routed endpoints even with only one direction installed. Diagnostics
expose the original match and translated tuple. The policy renderer permits UDP
source NAT while retaining TCP-NAT/DNAT guards; backend validation additionally
declines masquerade mappings. No new NAT allocation/configuration interface or
kernel patch is introduced.

The test image now includes `nft_nat` and `nft_chain_nat`. Both were already
enabled in the kernel but absent from the image. Initial setup probes established
that the image lacked the legacy iptables SNAT target and then the native nftables
NAT modules; an intervening single-line nft syntax error was also corrected.
Those attempts ended before traffic or hardware NAT admission. The final proof
uses a clean rebuilt/staged image and native nftables SNAT at priority 90, before
the fixture's legacy NAT exemption. No temporary module injection was used.

Validation on Linux 6.12.103 with KASAN and lockdep:

- All 35 focused host tests pass. Production decoder tests cover both SNAT
  directions, identity address/port edits, exact masks/checksum actions, malformed
  mappings and unsupported NAT rejection, partial-route dependencies and rollback.
  Hardware-wrapper tests cover individual and combined address/port edits without
  changing classifier matches, plus allocation-free retirement and reference
  recovery. The existing handle/route/policy tests also pass under ASan/UBSan
  where applicable.
- The checksum-enabled DUT case passes in 83.33 seconds; the zero-checksum case
  passes in 81.21 seconds. Each uses one persistent UDP socket and forces the LAN
  source to the DUT WAN address with a different source port. Both raw receive
  endpoints verify Ethernet/IP/UDP fields, TTL, checksums and exact payloads.
  Zero IPv4 UDP checksums remain zero in both directions.
- Each case proves three stable hardware windows: initial admission, automatic
  readmission after a dependent LAN route update, and policy reapplication after
  software fallback. Every window adds exactly 256 packets and 76,288 bytes per
  hardware direction, with unchanged cookies and no install/delete churn within
  the window. Software TX is 4–5 LAN / 14–15 WAN packets, including control traffic.
- A post-insert fault rolls back once before admission. Each case then records
  one dependent route-generation retirement. Policy removal runs during traffic,
  with no lost or late payloads. The following software window delivers 256
  echoes with software TX 259/265 and no hardware entries or references. The
  original conntrack ID and NAT mapping survive, and reapplication accelerates
  the same socket again. Each case returns all seven installs/deletes to balance.
- Aggregate busy CPU in the final checksum-enabled window is 1.72%, with 0.34%
  softirq; the three zero-checksum windows are 2.07%, 1.79% and 1.75%, with
  0.47%, 0.28% and 0.31% softirq. The first two checksum-enabled windows measured
  24.65% and 24.60% aggregate busy CPU, despite low software TX and 0.32%/0.22%
  softirq. Their higher aggregate load is retained in the evidence without an
  established cause; it is not presented as uniformly low CPU throughout the run.
- The existing CMM/FCI-free TCP/UDP startup regression passes in 53.73 seconds:
  256 exact UDP packets and 4 MiB TCP per direction, software TX 4/16, aggregate
  busy CPU 2.12% and softirq 0.44%. CMM, FCI and auto_bridge remain absent.

The final running kernel build ID is `4209d9dda18f2df33eca2af12ed9d568fc2cca8c`,
CDX is `36f6515eebdb95bec3cdc77a599b8073e6dc4510`, and the adapter is
`8e0e5f98377928ee82c5132f2ce851727f568516`. The staged image SHA-256 is
`89c5537aaeaed6259115f701cc833121195105468cdf3aeb770270d7a88d6725`.
Running identities, policy script and staged/built images match. Both builds
had no compiler warnings; only the three previously recorded forced-task warnings
were emitted. The image was staged after each successful build.

Final diagnostics are clean for KASAN/lockdep, with debug_locks 1 and taint 4096.
All 18 installs have corresponding deletes; bindings, entries, shared handles,
neighbour references, quarantine, fatal state, global invalidation and errors are
zero. Fault controls are clear. NAT/admission test tables, exemptions and host
routes are removed, endpoint settings are restored, and the default policy is
disabled. The DUT remains in flowtable mode with the verified 1 Gb/s LAN link.

Artifacts, including the failed setup probes, are under
`/tmp/ask-flowtable-snat/`; final-image proofs are in `native-image/checksum/`,
`native-image/zero-checksum/` and `native-image/regression/`, with image identities
and final cleanup/diagnostics alongside them. Only these focused tests ran; no
full suite, alternative kernel, CMM-mode detour, persistent boot change or push
was part of this increment. Broader NAT exception combinations and sustained
scale are not established by this first proof.

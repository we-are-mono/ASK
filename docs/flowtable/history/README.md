# Flowtable design and validation history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md)

These records preserve the consolidated document at `cc34cef`, through the
static TCP SNAT proof on 2026-09-15. They are historical evidence, including
superseded contracts and failed attempts. Current operating guidance lives in the
[foundation](../../flowtable-foundation.md), [policy](../../flowtable-policy.md)
and [NAT](../../flowtable-nat.md) guides.

The split preserves every original section from “Purpose and constraints”
onward, with only relative Markdown links rebased. The former overview is
replaced by the current project entry point. Topic grouping does not change
the order of increments shown below. Temporary artifact paths identify the
original bench records; they are not a promise of permanent artifact storage.

## Topics

| Record | Contents |
| --- | --- |
| [Initial proposal](initial-proposal.md) | Original objectives, ownership constraints, engineering standards and proposed increments. |
| [Consolidated implementation snapshot](implementation-snapshot.md) | Earlier consolidated contracts and focused-check instructions; some restrictions are superseded. |
| [UDP PoC and initial recovery](udp-poc.md) | First hardware proof, terminal lifecycle and healthy global recovery. |
| [Connections, admission and capacity](connections-and-admission.md) | TCP, independent connection lifetimes, partial-admission recovery and resource pressure. |
| [Neighbours and gateways](neighbours-and-gateways.md) | Ordinary ARP, gateway routes and selective neighbour retirement. |
| [Route retirement](route-retirement.md) | Committed IPv4 prefixes and the separate nexthop-object API. |
| [Backend and adapter module](backend-and-module.md) | Provider extraction, module lifetime, dependency filtering and lock-order corrections. |
| [Physical device lifecycle](device-lifecycle.md) | MTU, administrative state, MAC, rename, unregister and terminal restart safety. |
| [Policy, startup and foundation acceptance](policy-and-startup.md) | Configuration/revocation, CMM/FCI-free startup and final legacy compatibility. |
| [Static TCP SNAT](tcp-snat.md) | Bulk transfers, idle expiry, retransmission, live policy withdrawal and FIN/RST. |
| [Static UDP SNAT](udp-snat.md) | Forced translation, endpoint checksums, route recovery and live software fallback. |

The separate [UDP loss investigation](../../flowtable-udp-loss-investigation.md)
remains intact. Unexplained failures are retained; later passing measurements do
not silently reclassify them as fixed.

## Chronology

This follows the section order of the former consolidated document, including
multiple increments recorded on the same date. The original proposal and the
consolidated implementation snapshot are linked above; the dated evidence starts
with the UDP proof.

| Increment | Record |
| --- | --- |
| Validation record — 2026-09-14 | [Evidence](udp-poc.md#validation-record--2026-09-14) |
| Terminal lifecycle validation — 2026-09-14 | [Evidence](udp-poc.md#terminal-lifecycle-validation--2026-09-14) |
| Healthy invalidation recovery verified (2026-09-14) | [Evidence](udp-poc.md#healthy-invalidation-recovery-verified-2026-09-14) |
| TCP increment and validation (2026-09-14) | [Evidence](connections-and-admission.md#tcp-increment-and-validation-2026-09-14) |
| Ordinary ARP increment (2026-09-14) | [Evidence](neighbours-and-gateways.md#ordinary-arp-increment-2026-09-14) |
| Gateway next-hop increment | [Evidence](neighbours-and-gateways.md#gateway-next-hop-increment) |
| Bounded multiple connections — 2026-09-15 | [Evidence](connections-and-admission.md#bounded-multiple-connections--2026-09-15) |
| Selective neighbour invalidation verified (2026-09-15) | [Evidence](neighbours-and-gateways.md#selective-neighbour-invalidation-verified-2026-09-15) |
| Selective IPv4 route retirement — verified 2026-09-15 | [Evidence](route-retirement.md#selective-ipv4-route-retirement--verified-2026-09-15) |
| CDX backend interface — verified 2026-09-15 | [Evidence](backend-and-module.md#cdx-backend-interface--verified-2026-09-15) |
| Loadable flowtable adapter — verified 2026-09-15 | [Evidence](backend-and-module.md#loadable-flowtable-adapter--verified-2026-09-15) |
| Automatic physical-port MTU recovery — verified 2026-09-15 | [Evidence](device-lifecycle.md#automatic-physical-port-mtu-recovery--verified-2026-09-15) |
| Administrative port recovery — verified 2026-09-15 | [Evidence](device-lifecycle.md#administrative-port-recovery--verified-2026-09-15) |
| Physical MAC and rename recovery — verified 2026-09-15 | [Evidence](device-lifecycle.md#physical-mac-and-rename-recovery--verified-2026-09-15) |
| Physical removal and terminal restart guard — verified 2026-09-15 | [Evidence](device-lifecycle.md#physical-removal-and-terminal-restart-guard--verified-2026-09-15) |
| Transient admission recovery — verified 2026-09-15 | [Evidence](connections-and-admission.md#transient-admission-recovery--verified-2026-09-15) |
| Nexthop-object retirement — verified 2026-09-15 | [Evidence](route-retirement.md#nexthop-object-retirement--verified-2026-09-15) |
| Configuration and live exclusion replacement — verified 2026-09-15 | [Evidence](policy-and-startup.md#configuration-and-live-exclusion-replacement--verified-2026-09-15) |
| Startup independence — verified 2026-09-15 | [Evidence](policy-and-startup.md#startup-independence--verified-2026-09-15) |
| Resource pressure and concurrent reconfiguration — verified 2026-09-15 | [Evidence](connections-and-admission.md#resource-pressure-and-concurrent-reconfiguration--verified-2026-09-15) |
| Foundation closure and legacy return — 2026-09-15 | [Evidence](policy-and-startup.md#foundation-closure-and-legacy-return--2026-09-15) |
| Static UDP source NAT — 2026-09-15 | [Evidence](udp-snat.md#static-udp-source-nat--2026-09-15) |
| Static TCP source NAT — 2026-09-15 | [Evidence](tcp-snat.md) |

## Maintaining the records

For each proved increment, update its current architecture or feature contract
and append a dated record to the relevant topic. Record what changed, the source
and image identities, focused tests, measurements, failures and acceptance limits.
Create a new descriptive topic file when the work belongs to a new feature or
an existing topic becomes unwieldy; avoid work-phase names and date-only files.

Keep repeated current explanations in the guides and link to them from new
records. Preserve existing measurements and failed attempts. Clearly identify
corrections to earlier evidence rather than rewriting an old result into a new
claim. Maintain this chronology and the overview's scope/next-work summary.

# UDP loss investigation — 2026-09-14

Acceptance remains open. The final PoC image reproduces intermittent missing
UDP replies. One ordinary-routing failure coincided with exactly one receive
CRC error at the LAN endpoint. Two hardware failures reached the DUT's LAN
transmit MAC counters without a corresponding LAN reply or endpoint error
increment. This narrows the observation gap, but neither identifies a failed
component nor establishes that all losses have the same cause.

## Configuration and observation points

The image, kernel and CDX identities are those in the
[PoC validation record](flowtable/history/udp-poc.md#validation-record--2026-09-14):
image SHA-256
`dfcdbc950f5bb3a84f8982a16e360f0d673602f4454da28a44ae13de006600c5`.
KASAN and lockdep remained enabled. No forwarding implementation changed during
this investigation, and the full KASAN suite was not run.

| Endpoint | Physical path and access |
| --- | --- |
| LAN | DUT `eth3`, MAC `e8:f6:d7:00:01:13`, SFP cage 0 containing FS SFP-10G-T rev A, serial F2220691640; RJ45 cable to Intel X550 |
| LAN generator | X550 PCI device passed through to libvirt VM `loki`; interface `enp4s0`, MAC `64:9d:99:b2:33:02`, IPv4 `192.168.1.122`; access through `Console.lan()` / libvirt serial console |
| WAN | DUT `eth4`, MAC `e8:f6:d7:00:01:14`, SFP cage 1 containing FLEXOPTIX P.C30.1 DAC; echo endpoint `10.0.0.232` on the orchestrator's `br0` |

The X550 reported a 10 Gb/s full-duplex link, ixgbe driver on Linux
`6.12.101+deb13-amd64`, and firmware `0x8000172d, 1.3105.0`. No host bridge or
virtio NIC carries the LAN test traffic.

The existing long-exchange test sends one numbered 256-byte UDP payload at a
time, waits up to two seconds for its echo, verifies the payload, TTL and raw
Ethernet addresses, and sleeps three milliseconds. The WAN endpoint records
every request. Loss tolerance remains zero. Routes, permanent neighbours and
the NAT exemption are controlled by the test fixture; ordinary routing does
not create an nftables flowtable.

Additional temporary pytest instrumentation captures before/after snapshots:

- `/proc/cdx_flowtable`, conntrack and DUT software ethtool counters.
- FMan MAC statistics through `FM_PORT_IOC_GET_MAC_STATISTICS` on
  `/dev/fm0-port-rx6` (LAN) and `rx7` (WAN), using the exact image's 29-u64 ABI.
- FMan receive/transmit port frame, discard and enqueue counters.
- Full X550 ethtool statistics and LAN IP/UDP statistics inside `loki`.

The MAC TX totals come from mEMAC hardware registers, independently of CDX's
classifier counters and the augmented netdev totals. For these packets, MAC
octets count 302 bytes per UDP frame including FCS; the classifier counts 298.
ARP exchanges account for the additional 64-byte frames noted below. The SDK
hardcodes MAC `ifInDiscards` and `ifOutDiscards` to zero, so those fields are not
evidence of an absence of drops. Its MAC error fields and separate FMan port
discard registers are read from hardware. A MAC count still does not reveal the
missing frame's contents or prove that it reached the X550 intact.

## Valid packet results

Artifact names identify directories below
`/tmp/ask-flowtable-investigation/` on the build host.

| Artifact | Result | Evidence at the failure or end of the window |
| --- | --- | --- |
| `hardware-first` | 4,096 echoes passed | Original long-exchange test, normal LAN receive filtering |
| `hardware-instrumented` | Reply 4,109 missing | WAN received request 4,109; both classifier counts 4,107; DUT LAN MAC RX/TX 4,110 frames and 1,240,982 bytes, consistent with 4,109 UDP frames plus ARP; LAN capture contained the outgoing request only; sampled X550 errors unchanged |
| `software-instrumented` | Reply 115 missing | No installed flowtable; WAN received 115 requests; DUT software TX and MAC TX both 115, MAC TX 34,730 bytes; X550 TX 115, good RX 114, `rx_errors` +1 and `rx_crc_errors` +1; no LAN UDP errors or drops |
| `hardware-full-counters` | Reply 6,670 missing | WAN received request 6,670; both classifier counts 6,668; DUT LAN MAC RX/TX 6,671 frames and 2,014,404 bytes; X550 TX 6,671 and RX 6,670 including ARP; all captured endpoint error/drop counters unchanged; no reply in LAN capture |
| `software-no-installs` | 16,384 echoes passed in 69.89 seconds | After a fresh DUT boot; entries, bindings, installs and deletes all zero before and after; DUT LAN MAC and X550 RX/TX each 16,386 frames including two ARP frames, with matching MAC octets and no new endpoint errors |
| `hardware-promisc` | 16,384 echoes passed in 59.81 seconds | Same boot as the passing software window; LAN promiscuous capture enabled; both classifier counts 16,382; DUT LAN MAC and X550 RX/TX each 16,385 frames including ARP; no new endpoint errors |
| `hardware-normal-after-reset` | 16,384 echoes passed in 59.26 seconds | Hardware forwarding with normal LAN receive filtering restored; both classifier counts 16,382; no new endpoint errors |

The first ordinary-routing failure occurred after hardware tables had been
installed and removed earlier in the same boot. It demonstrates loss with
ordinary software forwarding, but does not exclude residual effects of earlier
hardware activity. The later passing software run used boot ID
`a3b52269-ebc2-460a-a0fc-b45d671fb0f3`, with no experimental installation at any
point before that run. A successful window does not disprove an intermittent
fault. The CRC event does not by itself explain the hardware losses with no
error increments.

## Excluded diagnostic attempts

`hardware-rxall` is not a forwarding result. Enabling X550 `rx-all` reset the NIC
and caused link retraining; the first request did not reach the DUT and X550
TX-drop counters increased. The setting was restored to `rx-all off`, carrier
was polled until it recovered, and 10 Gb/s operation was verified before the
fresh-boot software test. This perturbation also separates the earlier failed
windows from the later passing software window; do not treat those as an
otherwise unchanged comparison.

`software-clean-boot` is also excluded. The temporary increase from 4,096 to
16,384 packets exceeded the original console command deadline while traffic
was still running. Its before/after snapshots were taken while packets were in
flight and cannot be used as a loss measurement. The temporary diagnostic then
extended the outer command deadline only; the two-second per-packet deadline
and all packet checks remained unchanged. `software-no-installs` is the valid
completed replacement.

## I2C is a separate finding

The earlier stuck mux condition was isolated to the downstream branch serving
the FLEXOPTIX DAC, rather than the FS copper module's branch. Unplugging and
reinserting the DAC restored both EEPROMs. A subsequent normal reboot with SFP
monitoring active passed the board self-tests, as confirmed by the operator.
That single reboot does not establish the original trigger or a permanent fix.

The UDP failures above were reproduced after that recovery, with both native
SFP identifications successful and no `SCL is stuck` messages in the
investigation boot. The I2C fault is therefore not required to reproduce the
UDP symptom. Evidence for the separate I2C investigation remains under
`/tmp/ask-i2c-stuck/`.

## Remaining discriminating checks

The passing promiscuous window did not reproduce a missing reply, so it cannot
resolve whether any earlier missing frame had an incorrect destination MAC.
The following normal-filtering window also passed. Both followed the X550 reset
and fresh DUT boot; none establishes which change, if any, affected the fault.

Physical isolation should change one component at a time: a known-good
RJ45 cable, followed by a replacement copper module or an alternate LAN link.
Repeat the same software and hardware packet oracle and counter snapshots after
each change. A suspected cable or module must not be recorded as defective
without that comparison.

The checkpoint remains a narrow, working PoC with unresolved delivery
acceptance. Hard unlink failure and module unload with live experimental
traffic were still unverified when this UDP investigation ended; subsequent
lifecycle results belong in the architecture document's validation record.
Neither passing windows nor evidence of one link CRC event closes unrelated
requirements.

The operator subsequently replaced only the RJ45 cable, keeping the FS module
and endpoint ports. At the operator's request, dedicated loss diagnosis was
deferred and work resumed on the PoC lifecycle checks using that replacement
cable. No controlled cable comparison was completed, so the replacement is not
recorded as a demonstrated fix.

Raw evidence includes pytest logs/XML, `before.json`, `after.json`, delivery or
failed-exchange reports, image/source identity manifests, and UART logs. The
temporary instrumentation is `lossdiag.py` in the artifact directory; it is an
investigation aid and has not been made part of the maintained test harness.

After the last hardware window, the experimental owner reported four installs
and four deletes, with entries, bindings, errors, invalidated, fatal and
quarantine all zero. No nftables table or LAN echo generator remained. The LAN
NIC had promiscuity zero, `rx-all off`, and a 10 Gb/s link. The experimental
boot's captured kernel log contained no splats or I2C stuck messages.

## Capacity-run observation — 2026-09-15

During later mixed TCP/UDP capacity testing, one 10 Gb/s UDP failure coincided
with two new X550 receive CRC errors (2785 → 2787). The generator UDP socket
had no drops and DUT port error/drop counters remained zero. This occurred
after the operator's cable replacement; it neither identifies a faulty
component nor establishes that the cable replacement had no benefit.

The operator requested that isolated errors in the cable-heavy homelab not
displace the main work. The capacity test therefore records a small explicit
UDP loss allowance while retaining exact payload checks, per-connection
delivery, advancing hardware counters and lifecycle requirements. Its
separate loss during unpaced bulk readmission is not attributed to these
CRC events. See the [capacity record](flowtable/history/capacity.md) for the
measurements, failed attempts and acceptance boundary. No new component
isolation was performed and this investigation remains open.

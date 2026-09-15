# UDP PoC and initial recovery: history

[Project overview](../../linux-flowtable-offload.md) · [Current architecture](../../flowtable-architecture.md) · [History index](README.md)

First hardware proof, terminal lifecycle and healthy global recovery.

Archived from the consolidated record at `cc34cef`. Sections retain their
original wording, commands, measurements, failures and limits; relative links
have been adjusted for this location. Claims and next-step instructions apply
to their recorded increment, and may be superseded. References to earlier or
later work follow the chronology in the [history index](README.md#chronology).

## Validation record — 2026-09-14

The final candidate was built and staged with KASAN, lockdep, kmemleak support,
and FAILSLAB enabled. Running kernel/CDX build IDs and the dpa_app, CMM, and FMC
hashes matched the build. Image SHA-256:
`dfcdbc950f5bb3a84f8982a16e360f0d673602f4454da28a44ae13de006600c5`.
Kernel build ID: `e5a2b9c4cbd3e2c2f6b2f3bdf46fcbb9a57e274a`.
CDX build ID: `1fd916d9338c3e2a8464e6ed3431da1f2ba2dc7a`.
Build output contained six existing forced-task/build-path notices and no
compiler warnings. Source manifests include the new, untracked files as well as
the tracked diff captured before this checkpoint.

| Check | Result and bounds |
| --- | --- |
| Focused host checks | 3 passed under ASan/UBSan: decoder/lifecycle, backend ownership, and shutdown ordering |
| Current PoC lifecycle, exceptions, rollback | 3 passed in 128.26 seconds on the final candidate |
| Hardware execution | Both directions advanced from 62 to 574 classifier hits during 512 successful echoes; software RX increased by 1 on eth3 and 9 on eth4; payload, MAC, TTL, and request checksum checks passed |
| Minimum frames | 32 eight-byte UDP payloads advanced each hardware counter by 32 packets and 1,920 Ethernet bytes |
| Activity/removal | Three removals under traffic returned entries/bindings to zero; 65 seconds of active traffic stayed installed; idle expiry retired both directions |
| Counter admission | A counter-enabled table forwarded in software and installed zero hardware entries |
| Counter change | Enabling counters on an active table completed invalidation with zero entries, errors, fatal state, or quarantine; subsequent echoes succeeded |
| Longer forwarding windows | Final candidate passed 4,096 echoes through software flowtable and another 4,096 through hardware, with LAN promiscuous mode disabled |
| Earlier observe/invalidation checks | Observe mode, neighbour invalidation, and two injected delete-barrier failures passed on earlier instrumented builds; the retirement backend is unchanged in the final candidate |
| Kernel diagnostics | Selected scenarios reported no KASAN/UBSAN/BUG/WARN/lockdep findings; a separate I2C error flood is described below |
| CMM return | Final candidate rebooted with CMM ownership; unsupported-command handling and IPv4 TCP hardware offload both passed in 17.11 seconds |

The barrier-failure run consumed both injected failures, recorded two errors,
completed invalidation, drained quarantine to zero, and continued forwarding in
Linux. Host tests additionally exercise failed barrier retries, unproven unlink,
and failed/busy quiescence. Hard unlink failure and module unload with live
experimental traffic had not yet been demonstrated in this initial validation;
the later terminal lifecycle validation is recorded below. Host checks do not
substitute for those hardware cases.

During development, several hardware runs lost an individual UDP request or
reply, including after table removal. In one long run, request 3,014 reached the
WAN endpoint and both directional classifier counters reached 3,012 (the first
two packets had used software), but the reply did not appear in the LAN capture.
LAN NIC error counters did not increase. Ordinary-routing windows of 4,096
packets and CMM windows of 4,096 and 8,192 packets passed. Those failures used the
earlier counter-enabled experiment, which the final adapter now declines because
its accounting is incorrect. The counter restriction is not a demonstrated
explanation or fix for the loss. Preserve this as an open acceptance item;
successful subsequent windows are bounded evidence, not grounds to erase it or
increase test loss tolerances. Do not broaden the PoC on an assumption that this
failure has been explained.

The DUT later began repeatedly reporting `i2c-1: SCL is stuck low` across warm
boots in both ownership modes. That also disrupted UART command parsing. Final
diagnostic boots used `loglevel=1 log_buf_len=4M` to keep UART usable and retain
kernel messages; instrumentation remained enabled. A subsequent live
investigation isolated the stuck branch to the FLEXOPTIX DAC's mux channel;
unplugging and reinserting the DAC restored both modules, and a normal reboot
passed the board self-tests. The original trigger remains unresolved.

The [follow-up UDP investigation](../../flowtable-udp-loss-investigation.md)
reproduced losses on this exact final image with I2C healthy. It recorded one
ordinary-routing loss with an X550 receive CRC error, and hardware losses
counted by the DUT's LAN transmit MAC without a corresponding LAN reply or
endpoint error increment. Subsequent 16,384-packet software and hardware
windows passed after a diagnostic X550 reset and fresh DUT boot. These results
narrow the investigation but do not establish a common cause or close delivery
acceptance. Detailed counter deltas, excluded diagnostic attempts and the
physical isolation plan are retained in the linked record.

Artifacts are retained under `/tmp/ask-flowtable/` on the build host: image/source
identity, build and boot logs, pytest XML, endpoint capture, hardware counters,
exception results, fault recovery, and failed-exchange diagnostics. The full
suite was stopped at the user's request after 159 passes and no failures; it was
not resumed. No full-suite or full kmemleak-scan acceptance is claimed.

At the end of these initial checks, the DUT returned to default CMM ownership.
No persistent boot configuration or flash image was changed.

## Terminal lifecycle validation — 2026-09-14

A subsequent test image adds the test-only hard-unlink hook described above.
The forwarding and retirement implementation is unchanged; the new hook leaves
one real installed key linked to exercise the existing fatal path. It is absent
from production builds. The image was built and staged with the same KASAN,
lockdep, kmemleak and FAILSLAB configuration. Build output contained three
existing forced-task notices and no compiler warnings. Running identities
matched the build:

- Image SHA-256: `f1afad25011630343366d2c5a1abb89e950f1693abbf1ee656bd743cbbc78bec`.
- Kernel build ID: `365a93b26ed2ecc05966696c1e6e87a7111be0b1`.
- CDX build ID: `65912f90a0bac30c99cf1db93c923f67f02792bb`.

These runs used the operator's replacement RJ45 cable with the same FS module,
X550 and physical ports. They are lifecycle tests, not a controlled comparison
establishing that the original cable caused the earlier UDP loss. The LAN link
was checked after the terminal tests and reported 1 Gb/s. No 10 Gb/s
performance acceptance is claimed or required for these lifecycle checks.

| Check | Result and bounds |
| --- | --- |
| Focused host checks | 3 passed under ASan/UBSan, including one-shot hard-unlink injection, preservation of the linked key, no destructive retry, and a subsequent healthy delete |
| Module unload under traffic | Passed in 23.45 seconds. Both hardware directions had 164 hits immediately before unload. CDX and its proc entry disappeared; 64 subsequent ordinary-routing echoes passed. The 12-second stream spanning shutdown received 1,837 of 1,906 sent packets; lossless unload is not claimed. |
| Hard unlink failure | Passed in 22.54 seconds. Both directions were active before injection; the one-shot hook was consumed, errors increased by one, and fatal invalidation completed with entries/bindings zero. FMan receive ports 6 and 7 both changed from enabled to disabled. The kernel recorded one retained linked key; WAN delivery stopped while the LAN sender continued. |
| Fatal cleanup | Removing CDX after the hard-unlink test restored ordinary forwarding; 64 echoes passed with the module absent. This is explicit teardown after the fatal observation, not software fallback by the invalidation worker. The boot was then reset before using ASK again. |
| Kernel diagnostics | Both successful terminal tests completed their capture windows without KASAN/UBSAN/BUG/WARN/lockdep findings. No full suite or kmemleak scan was run. |
| CMM control compatibility | Unsupported-command handling passed in 4.81 seconds after rebooting the same image with default ownership. |
| CMM forwarding compatibility | A separate five-second paced TCP measurement delivered 500,170,752 bytes at 799.94 Mb/s. CMM's hardware connection table grew from zero to two entries. DUT LAN software RX increased by only 268 packets versus a conservative lower bound of 333,447 data frames. No kernel splats were recorded. |
| DUT CPU during CMM forwarding | `/proc/stat` showed 1.87% average busy time over an idle baseline and 3.46% over the traffic window, averaged across all four CPUs. The busiest core during traffic was 4.68%. These are DUT measurements; iperf's endpoint CPU figures are not used. |

The first hard-unlink attempt stopped before injection because interactive shell
prompts contaminated the test's JSON output. Cleanup succeeded; it is excluded
from hard-unlink acceptance. The maintained test now sends Python as a single
encoded command and explicitly frames actual console output. The successful
replacement run used that framing. The finite traffic task is awaited before
UART reuse, and fatal cleanup runs even if its packet checks fail.

The existing CMM throughput test requires at least 1 Gb/s of application
throughput, which the replacement link cannot supply. Its threshold was not
changed. The paced compatibility measurement instead combines received data,
hardware table population, software-path packet counts and DUT CPU usage. Its
temporary checker and raw measurements are retained with the lifecycle
artifacts. Low CPU usage corroborates the software-path counters; it is not
treated as a delivery oracle by itself.

Artifacts are under `/tmp/ask-flowtable-lifecycle/`: image/source manifests,
build and boot logs, pytest XML, live-entry snapshots, port-enable states,
terminal traffic counts and raw UART logs. The build log is
`/tmp/ask-flowtable-lifecycle-build.log`. The two previously missing terminal
hardware cases now have direct DUT evidence. Earlier unexplained UDP loss
remains documented; the operator explicitly deferred further dedicated loss
diagnosis so work could continue on this foundation.

For subsequent work, keep the DUT in experimental ownership between tests.
Recreate the table after healthy invalidation; reboot within that mode after a
fatal failure or a test that removes CDX. Return
to CMM only when the compatibility test itself requires it. The operator has
made the DUT available for continued development.

Final runtime state: the tested image is booted with `ask.offload=flowtable`,
observe mode off, and entries, bindings, installs, deletes, errors, invalidated,
fatal and quarantine all zero. CMM and auto_bridge are absent, both fault knobs
are clear, and no experimental nftables table remains. The ready boot has no
kernel splats or I2C stuck messages. Persistent boot settings and flash remain
unchanged.

## Healthy invalidation recovery verified (2026-09-14)

The first follow-on increment is complete: healthy invalidation can restore
hardware admission after full detachment and binding an empty Linux flowtable.
Fatal retirement remains latched. Work stops at this increment; ordinary ARP,
gateway routes and selective invalidation are subsequent work.

The KASAN image was rebuilt and staged, and live kernel/CDX build notes matched
the built artifacts before both hardware checks. KASAN, lockdep and FAILSLAB
were enabled; the full KASAN suite was not run. The build had no compiler
warnings; its three BitBake warnings concerned previously forced recipe tasks.

| Identity | Value |
| --- | --- |
| Staged image SHA-256 | `50d8b8510421e8f6998e423baa1f99c958f66731ac06f2c7a1eba5039362af9a` |
| Kernel build ID | `2da28a7c60a44c08886618dfa4bda39e3eeb363b` |
| CDX build ID | `3f04f3e1c4082d88053ddb2c9cbe7dbfc063ec3a` |
| Recovery test boot | `724fcb2a-5349-4580-836e-9fed961aeb1e` |
| Successful fatal test boot | `45bb4344-a8ae-4e36-b604-641b69216e98` |

| Check | Confirmed result |
| --- | --- |
| Focused host checks | 11 passed in 0.48 seconds. Production adapter/backend lifecycle and shutdown checks use ASan/UBSan; counter-parser checks cover both directions. |
| Recovery admission guards | Host checks exercise incomplete cleanup, failed barriers, both quarantine lists, partial detachment, populated Linux tables, allocation failures, shutdown and fatal state. A notifier arriving during ordinary bind allocation remains latched. Eight recovery cycles preserve references and cumulative counters. |
| Healthy DUT recovery | Passed in 24.17 seconds. MAC change, host-route MTU change and two injected retirement-barrier failures each completed invalidation and recovered after table recreation, all within one boot. `rearms` advanced exactly once per cycle, from 0 to 3. |
| Closed admission | Each cycle delivered 64 strict echoes through software with no new hardware installs and exactly 64 LAN software TX enqueues. Existing bindings did not reopen admission. Reattaching the populated, fully detached table returned `Operation not supported`. |
| Recovered forwarding | Each cycle delivered 512 strict echoes with the normal LAN receive filter, exactly 512 hardware hits per direction, and software TX deltas of 0 on eth3 and 8 on eth4. The changed destination MAC was accepted by the endpoint; after the MTU change, the reply rule used 1100 and the original direction retained 1200. |
| Barrier history | Both injected delete-barrier failures were consumed, quarantine drained, and recovery retained the cumulative error count of 2. No fatal condition was raised. |
| Fatal refusal | Passed in 25.64 seconds on the same image. Unproven unlink raised one error, completed fatal invalidation and disabled FMan receive ports 6 and 7. Creating a hardware flowtable returned `Operation not supported`; bindings, entries, `rearm_ready` and `rearms` remained zero. |
| Fatal cleanup | WAN delivery ceased while the finite sender continued attempting traffic. After explicit CDX removal, all 64 ordinary software echoes passed. Neither the worker nor flowtable recreation cleared the fatal latch. |
| Sanitizers | Neither successful DUT check reported a KASAN, UBSan or lockdep splat. |

Transition measurements remain separate from stable forwarding acceptance. The
MAC transition received 980 of 997 datagrams during the deliberate address
mismatch. The successful fatal observation sent 1,158 datagrams, received 687
and recorded 20 send timeouts across the intentional stop. The finite sender
records backpressure and keeps attempting sends; every received payload is
validated. These are not lossless-transition or throughput claims.

The first recovery attempt exposed an unsuitable RX-counter assertion, not a
delivery failure. The SDK counter excludes some software flowtable traffic when
GRO is disabled; the recovered-forwarding proof now uses software TX counters.
Earlier fatal attempts are excluded: malformed nft syntax, a corrupted UART
script, LAN unavailability before the first flow, an already removed FCI module,
and unhandled send backpressure prevented full acceptance. The harness now
requires the specific offload-refusal error, verifies chunked UART scripts by
SHA-256 before execution, tolerates an absent inactive FCI dependency, and records
send timeouts only in the intentional-stop traffic helper. Strict exchange
checks retain their zero-loss requirement.

Artifacts are in `/tmp/ask-flowtable-rearm/`, with the build log at
`/tmp/ask-flowtable-rearm-build.log`. `focused.xml` contains the successful
recovery case and the excluded earlier terminal case; `terminal.xml` contains
the successful replacement terminal run. Separate manifests identify both
boots. Excluded attempts and raw UART logs are retained in subdirectories.
The DUT is restored to a clean boot of this image in experimental ownership;
no return to CMM is needed between healthy recovery cycles.

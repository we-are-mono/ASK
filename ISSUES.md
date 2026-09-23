# ASK Kernel-Module Security & Memory-Safety Issues

Working list from the security review of `cdx/`, `fci/`, and `auto_bridge/`.
Entries are short by design — each fix's reasoning lives in the commit
referenced as `Fixed: <hash>`. Read the commit message for context.

Closed items are collapsed to one-liners under **[Archive](#archive)**;
the full reasoning for each lives in its referenced commit and in this
file's git history. The **Open** section below is the live work list.

**Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` wontfix/not-a-bug

An adversarial re-audit (2026-08-09, 12 grouped correctness passes over all
89 closed items) confirmed 74 closures on repo evidence and reopened the
items below. Every reopening is static-conclusive — none needs on-DUT
verification. Bookkeeping corrections from that audit (wrong commit hashes,
stale line refs) are folded into the archive one-liners.

## A135–A136 targeted validation — 2026-09-14

The A135–A136 fixes passed 43 host tests (including ASan/UBSan) and 13
DUT tests on a newly built, staged and TFTP-booted KASAN image. Zero failures
or skips in the final runs. The tunnel HM harness also passed under ARM64
QEMU with interface statistics enabled and disabled; the SDK header patch
sequence applies cleanly and reproduces the compiled header.

The old image delivered 300 6o4 echoes while tunnel RX increased by only 1,
failing the new accounting regression. With the fix, 300 echoes produced
300 tunnel RX packets and 12 software ingress packets. The 4o6 window
counted 300 tunnel RX packets and 13 software ingress packets. TX reached
9.13 Gbit/s with 39 software RX packets out of 6,489,126 ingress packets
and 20.00 bytes/packet encapsulation overhead. All ten edge goldens remained
unchanged when read through software-only counters.

Loaded kernel/CDX build IDs and userspace hashes matched the build. No
KASAN/UBSAN/BUG/WARN/lockdep findings; the DUT remains on the tested image.
This was targeted validation, not a rerun of the full suite below. The build
reported six existing forced-task/build-path notices and no compiler warnings.
Artifacts: `/tmp/ask-a135-a136/` on `vision` (report, XML, build/boot logs,
source manifest and image identity). Image SHA-256:
`8dc5959edbf7747a42e0cb3a584f6da2d36d3455e5b63bc06f9df1d9e82addd0`.

## Latest full validation — 2026-09-13

Release `mono-1.0.7` contains the production source tested at commit
`3d412fe39c6497b1201a32de8aa962b94487bb0c`; the release bookkeeping changes
only this ledger. Built with `KASAN=1 make ask-image`, staged with
`make stage-image`, and booted explicitly over TFTP.

| Suite | Passed | Duration |
| --- | ---: | ---: |
| Main: 33 host + 377 DUT tests | 410 | 79m 28s |
| Startup rollback: 15 checkpoints and normal unload | 1 | 11m 02s |
| Route recovery and SA teardown | 10 | 1m 12s |
| **Total** | **421** | **91m 41s** |

Zero failures, errors or skips. KASAN (generic), kmemleak, lockdep and
FAILSLAB were enabled; no KASAN/UBSAN/kernel BUG/WARN/lockdep findings.
Every startup checkpoint restored MURAM and port state, followed by normal
CDX initialization and unload. The leak scan found no unexpected objects
after excluding 12,798 known DPAA boot-pool objects under the existing policy.

Kernel/CDX build IDs and dpa_app/CMM/FMC hashes matched the build before and
after runtime testing. Main and route suites ran in the same normal boot.
Normal CMM was restored, test shims removed, fault controls disarmed, and
the DUT and WAN agents were healthy. The DUT remains on the tested image.

Image SHA-256: `03696b8ca2b5945562aa49e51bdbdd05162856ee96feaab26cbac79b3f8dc727`.
Kernel build ID: `406562256ec79675a08c3bfef8260c28b13157ed`.
CDX build ID: `6e5014fea8f0e26dec7b4e95613a9a6fd665d5fe`.

Build notices comprised three existing forced-task markers and three
embedded-build-path QA warnings. Pytest reported two JUnit property-format
warnings. The PPPoE traffic/offload test passed, but its optional CPU-usage
sample could not be parsed.

Artifacts on `vision`: `/tmp/ask-full-20260913-124324/` contains `report.md`,
`build-manifest.json`, all three suite XML/logs, per-test captures, initial
and final image identities, kernel diagnostics and `validation.json`.

## Teardown follow-up validation — 2026-09-13

Validated A133–A134 with 33 host ASan/UBSan tests (8.54s), all passing.
ARM64 compile checks for `cdx_main.c`, `control_qm.c` and SDK `fm_port.c`
passed with `-Werror` and no warnings. Each regression fails against its
previous implementation. The regenerated SDK patch applies to the pinned
vendor base and reproduces the tested source. The full image and DUT
validation above subsequently covered these changes.

Artifacts on `vision`: `/tmp/ask-teardown-followup-pt93edh9/` contains
`host.xml`, compiler commands/logs, patch verification and negative checks.

## Review follow-up validation — 2026-09-13

Validated A120–A132 on KASAN image commit `7636537`.
All 53 tests passed with zero failures, errors or skips:

| Suite | Passed | Duration |
| --- | ---: | ---: |
| Host ASan/UBSan | 32 | 8.53s |
| DUT startup rollback and unload | 1 | 11m 03s |
| Targeted runtime and ABI | 20 | 1m 55s |

Every one of the 15 startup failure checkpoints restored baseline MURAM
and port state, followed by successful normal load/unload in the same boot.
The leak scan found no unexpected objects after excluding 12,798 known DPAA
boot-pool objects. Runtime checks included 128 scheme lifecycle cycles,
all 128 QoS queues and forwarding offload. Kernel/CDX build IDs and userspace
hashes matched the build; final KASAN/UBSAN/BUG/WARN/lockdep checks were clean.
Native/compat ioctl wrappers and compat conversion also compile with active
kernel FORTIFY and `-Werror`, with KASAN disabled for those compiler checks.

Image SHA-256: `0831c0ee7920850b6aa6e90a61e8a5bb17931038260ec032c2de79aad1fc0f88`.
Artifacts on `vision`: `/tmp/ask-review-eytntij1/` (`validation.json`,
`build-manifest.json`, compiler logs, suite XML and per-test captures).
The full-suite record below describes the earlier September 12 image.

## Previous full validation — 2026-09-12

Built commit `12f7318b37395513de434d91ed37913bdbecbcc7` with
`KASAN=1 make ask-image`, staged it with `make stage-image`, and booted the
DUT over TFTP. KASAN (generic), kmemleak, lockdep and FAILSLAB were enabled.
Kernel/CDX build IDs and dpa_app/CMM hashes matched the build before and
after testing. Image SHA-256:
`144bbe9f2a53868b9e3fce40832c0ed9bd7c3496895a803f3fa9e06cb18ebd98`.

| Suite | Passed | Duration |
| --- | ---: | ---: |
| Main: 30 host + 377 DUT tests | 407 | 78m 57s |
| Dedicated startup rollback: 15 injected checkpoints | 1 | 10m 43s |
| Dedicated route recovery and SA teardown | 10 | 1m 17s |
| **Total** | **418** | **90m 57s** |

Zero failures, errors or skips. No KASAN, UBSAN, kernel BUG/WARN or lockdep
findings were reported; the final kernel log scan was clean. Startup rollback
restored baseline MURAM at all 15 checkpoints and allowed normal CDX loading
in the same boot. Its leak scan found no unexpected objects after the existing
test policy excluded 12,783 known DPAA boot-pool objects.

After startup testing, the DUT was rebooted normally. The main and route
suites then passed without another reboot; normal CMM was restored, fault
controls were disarmed, and DUT/WAN agents were healthy. The build completed
with three existing BitBake warnings for previously forced CDX, CMM and
dpa_app compile tasks.

Bench artifacts on `vision`: `/tmp/ask-full-20260912-205415/` contains
`report.md`, `build-manifest.json`, the three `*-suite.xml` reports and logs,
per-test captures, and `validation.json`. This dated record preserves the
result independently of those temporary files.

---

## Open

- [ ] **A194 — cdx and the kernel patches still carry CMM's control plane.**
  Retiring CMM left dead code behind, kept deliberately while the cmm/, fci/
  and auto_bridge/ reference sources are still consulted. `cdx/cdx_cmdhandler.c`
  `comcerto_fpp_send_command()` now refuses every command, so the FCI command
  handlers registered across `cdx/control_*.c`, `cdx_cmd_handler()`, the
  `comcerto_fpp_register_event_cb()` event path and the command-validation
  tables are unreachable. `cdx/dpa_wifi.c` keeps CMM's Wi-Fi fast path (the
  NF_INET_PRE_ROUTING hook behind the `vwd_fast_path_enable` sysfs knob), which
  nothing enables. On the kernel side, audit which parts of
  `patches/kernel/020-ask-bridge-hooks.patch` (the BREVENT hooks auto_bridge
  consumed) and `060-ask-netfilter-fastpath-hooks.patch` serve only CMM or
  auto_bridge. Remove what the flowtable path does not use, with host-test
  coverage for the shared machinery the handlers sit beside.

- [ ] **A139.** DPAA slow-path packet loss during a simultaneous restart of
  16,384 connections. **Investigated (2026-09-15), deferred at user request:**
  outside the CMM-retirement work; no fix or tuning retained. On the KASAN
  image for `507c404`, restart 8,192 TCP and 8,192 UDP connections together
  after a route-MTU change retires their flow entries. With CMM off throughout,
  hardware flow offload lost 5,953 of 197,970 UDP exchanges (3.01%); the
  software-only Linux flowtable control lost 8,739 of 206,479 (4.23%), with
  zero hardware flow entries installed. TCP records arrived intact and the
  WAN UDP receiver reported no socket drops. Hardware occupancy recovered to
  all 32,768 directions in 16.6 seconds. This establishes that the loss does
  not require hardware-flow admission; a legacy-CMM comparison was not run.
  Follow-up measurements found FMan RX buffer-exhaustion and filter counters
  increasing without MAC errors. The existing Ethernet miss policer is active
  at 195,312 packets/s with a 64-packet burst (`dpa_app/dpa.c`,
  `cdx/cdx_qos.c`); receive-buffer exhaustion has its own
  `port_rx_out_of_buffers_discard` counter and can occur with
  `port_discard_frame` and Linux drop traces nearly silent. These observations
  identify slow-path constraints, but their individual contributions to the
  UDP loss were not isolated. RPS across four CPUs and serializing the flow
  admission workqueue did not resolve it; both settings were restored.
  The accepted paced-capacity result remains recorded in
  [capacity validation](docs/flowtable/capacity.md). If revisited, measure RX
  buffer and miss-policer drops separately before changing either mechanism.
  Captures, image identity and diagnostic scripts:
  `/tmp/ask-flowtable-burst/` on `vision` (temporary artifacts).

## Feature enablement (not bugs)

Config-gated capabilities that are OFF in the current product — not defects.
Each path either never executes in this deployment or fails cleanly if invoked
(no corruption), so there is nothing to fix; each becomes a work item only when
the product decides to enable that feature. The enabling recipe is kept with
each so the open bug list stays honest.

- [ ] **A38 — macvlan hardware offload.** CMM sent
  FPP_CMD_MACVLAN_ENTRY/RESET on macvlan interface events (`itf.c`
  cmmFeMacVlanUpdate, gated on ITF_MACVLAN), but cdx never had an
  FC_MACVLAN/EVENT_MACVLAN handler, and the flowtable adapter has no macvlan
  path either. The gateway creates no macvlan netdevs today (CONFIG_MACVLAN
  built but unused).
  **Decision (2026-09-11): defer.** Traffic terminating on a local macvlan
  endpoint still needs kernel and application processing; a separate MAC
  does not make it an offloadable forwarding path. No concrete forwarding
  use case has been established. Revisit only after identifying one and
  confirming that CDX can accelerate it while preserving required kernel
  processing. Adding a command handler alone would not establish that.

- [ ] **A39 — transport-mode ESP offload.** cdx can run transport-mode SAs
  (SA_MODE_TUNNEL is set only by FPP_CMD_IPSEC_SA_SET_TUNNEL), but the product
  config and the whole rig suite exercise tunnel mode exclusively, so the
  transport path never runs. The SEC-era fix (_7cfd157_) means era 8 now enables
  PDBOPTS_ESP_AOFL in the transport-mode decap PDB (tunnel mode is unaffected by
  era). To enable: add a transport-mode rig case and validate the path plus the
  AOFL-adjusted lengths before it ships.

- [ ] **A103 — fmlib PCD-modify / FrmReplic / VSPAlloc verbs.** fmlib omits the
  `DEV_TO_ID` handle→id conversion at several sites, so a userspace `t_Device *`
  is sent where the kernel now expects a cookie:
  `FM_PCD_CcRootBuild`/`FrmReplicSetGroup`/`AddMember` FR arm (`frm_replic_id`),
  `PlcrProfileSet` modify-arm `p_profile`, `ManipNodeReplace` `p_next_manip`, the
  two PORT modify verbs
  (`PcdKgModifyInitialScheme`/`PcdPlcrModifyInitialProfile`) +
  `VSPAlloc`. Post-A85 the kernel rejects these cleanly (`E_INVALID_SELECTION`) —
  no corruption, the features are simply unusable until fixed. No rig config
  exercises any of them. To enable: add the missing `DEV_TO_ID`/loop-bound
  conversions in `sources/fmlib/src/fm_lib.c` (`patches/fmlib/`).
  Whole-tree replacement (`PcdCcModifyTree`) is deliberately unsupported
  under A113 and is excluded from this enablement work.

- [x] **A150.** The CEETM tree was built in flowtable mode with no consumer, and the choice
  was to gate `qm_init()` or give the flowtable a way to use it —
  resolved by the second: the tree is the pool `tc` HTB offload claims from
  (`cdx_htb.c:6`, "nothing new is claimed here"), with the ingress policers and the DSCP
  map drawing on it too. Gating it would now break those. Not a resource spent on nothing.

---

<a name="archive"></a>
# Archive

Closed items, one line each. Detail lives in the referenced commit and in this
file's git history.

## Gating

- [x] **A271.** Bridged multicast in hardware bypassed bridge netfilter (nftables bridge chains, ebtables, br_netfilter), so a drop rule stopped applying once a flow was offloaded —
  fixed (_:/^flowtable: keep bridged multicast in software while a bridge hook filters_).

- [x] **A270.** A port moved straight to another bridge kept its memberships, a reference and a listener, on the bridge it left —
  fixed (_:/^flowtable: drop a port's memberships on the bridge it leaves_).

- [x] **A269.** On NETDEV_UNREGISTER the multicast learners released a group's ingress before the worker deleted the entry that unsubscribes through it —
  fixed (_:/^flowtable: hold a multicast entry's ingress until the entry is deleted_).

- [x] **A268.** Patch 161 sent PORT_MROUTER=true on every per-family router transition, leaking a reference per extra true in drivers that count them (mlxsw) —
  fixed (_:/^patches: send PORT_MROUTER only when the bridge's union changes_).

- [x] **A267.** A failed routed multicast install spent all four retries within one worker pass and went refused-failed before anything could change —
  fixed (_:/^flowtable: retry a failed routed multicast install once per refresh_).

- [x] **A266.** Bridged memberships standing when the adapter loaded were never offloaded until joined afresh (nothing replayed them, and patch 160's replay could be dropped) —
  fixed (_:/^cdx: offload the bridged memberships standing when the adapter loads_).

- [x] **A265.** Bridged multicast ignored IGMPv3/MLDv2 source filters, so a source the bridge stopped forwarding to a port still reached it in hardware —
  fixed (_:/^cdx: ask the bridge where a bridged multicast flow's frames go_).

- [x] **A264.** A bridged group whose chain swap failed stayed counted installed on its old listener set, its route reported carried and the MFC flagged offloaded —
  fixed (_:/^flowtable: take a bridged multicast group out when its chain swap fails_).

- [x] **A263.** The multicast hook's dedup slot kept a frame recorded while no group matched, so a group created later stayed pending-source for as long as the stream ran —
  fixed (_:/^flowtable: forget the multicast hook's last frame when its answer changes_).

- [x] **A262.** Removing the multicast hook did not wait for frames inside it, which could rewrite the cleared dedup slot or queue the worker after exit cancelled it —
  fixed (_:/^flowtable: wait out the multicast hook's readers when it is removed_).

- [x] **A188.** A group both bridged and routed was carried by whichever learner claimed it first, leaving the other half in software —
  fixed (_:/^cdx: carry a stream both bridged and routed as one hardware group_).

- [x] **A191.** Bridged multicast rewrote the source MAC to the egress port's and sent tagged ingress to the CPU —
  fixed (_:/^cdx: bridge multicast with the sender's MAC and its ingress tag_).

- [x] **A196.** The microcode fragmented multicast replicas over a listener's MTU, where Linux sends Packet Too Big or drops —
  fixed (_:/^flowtable: keep a multicast group that could fragment in software_).

- [x] **A260.** CDX read any Ethernet netdev's private area as a DPAA port's, bridges and VLAN devices included, in registration, the FMan-port walk and the queue lookups —
  fixed (_:/^cdx: read netdev_priv as a DPAA port's only for a DPAA port_).

- [x] **A259.** ip6t_NPT rewrote a confirmed conntrack's reply tuple in place, so a related ICMPv6 error could leave a hashed entry holding a tuple it is not hashed under —
  fixed (_:/^netfilter: rewrite an NPT connection's reply tuple only before confirmation_).

- [x] **A258.** CPU-forwarded frames lost their QoS class (the software flowtable dropped the conntrack, PPPoE and tunnels scrubbed it) and took queue 7 above the tree, unremarked —
  fixed (_:/^cdx: classify frames by their headers, not by what a scrub left_).

- [x] **A255.** Traffic naming no HTB leaf took an unconfigured, excess-only queue 7 (a saturated leaf starved ARP, LCP and DHCP) or an unshaped claimed channel; `default` was ignored —
  fixed (_:/^cdx: keep unclassified traffic on a channel a class holds_).

- [x] **A243.** Unregistering a hook (`ndo_setup_tc`, TC_SETUP_FT, the Tx and SEC hooks) waited for no caller, so a racing tc command, bind or frame could run freed text —
  fixed (_:/^sdk_dpaa, cdx: wait out every call into a hook before its module goes_).

- [x] **A257.** `tc filter replace` of a DSCP filter was refused as a duplicate, and the old filter's destroy then unmapped the codepoint —
  fixed (_:/^cdx: keep a DSCP codepoint across tc filter replace_).

- [x] **A256.** A class's DSCP remark was applied only in hardware, so a flow changed codepoint when offloaded and one never offloaded was never remarked —
  fixed (_:/^cdx: remark forwarded frames in software as the hardware does_).

- [x] **A253.** A refused RED change left the old curve running under a qdisc showing the new one, stats cleared `offloaded`, and a RED could program an unrelated leaf's queue —
  fixed (_:/^cdx: make a RED qdisc's offload state what the class queue runs_).

- [x] **A252.** The devlink policers reported their ranges' ceilings until first set, so restoring what `show` reported switched both meters off —
  fixed (_:/^cdx: register the devlink policers with what the meters run_).

- [x] **A251.** `xfrm_state_update()` moved a packet-offloaded SA's NAT-T ports or output mark in place without telling the driver, leaving the hardware on the old ones —
  fixed (_:/^xfrm: refuse changing a packet-offloaded state's output mark in place_).

- [x] **A249.** Frames SEC never got were counted as sent (`tx toenc`, the Wi-Fi local path's count) and freed without a drop count, and every failed submit printed —
  fixed (_:/^sdk_dpaa: rate-limit SEC submit failures; count Wi-Fi SEC frames given_).

- [x] **A250.** SA peer lookups dropped the output mark, VRF, protocol and NAT-T ports (plain ESP took stale ports), so hardware and Linux could pick different next hops —
  fixed (_:/^xfrm: route plain ESP without the stack's leftovers for ports_).

- [x] **A248.** A transport-mode SA's frames were given the tunnel's DPOVRD, so SEC encrypted their IP header, named IPIP in the trailer and no peer could decode them —
  fixed (_:/^sdk_dpaa: describe a transport-mode frame's own IP header to SEC_).

- [x] **A247.** A bundle of two packet-offloaded transforms left with only the first applied —
  fixed (_:/^xfrm: refuse a nested packet-offload bundle_).

- [x] **A246.** GSO packets for a packet-offloaded SA hit `skb_checksum_help()`'s WARN and were dropped: all local TCP and GRO-merged forwarded traffic on the software path —
  fixed (_:/^xfrm: segment GSO packets for a packet-offloaded SA in software_).

- [x] **A245.** IPv6-in-IPv4 over a packet-offloaded SA failed every bundle without an IPv6 default route: the SA's IPv4 endpoints were looked up as IPv6 —
  fixed (_:/^xfrm: route a cross-family packet-offload tunnel by the flow_).

- [x] **A244.** A packet-offloaded SA's plaintext left in the clear by whatever device the bundle's route named once the peer route moved off the SA's port —
  fixed (_:/^xfrm: keep packet-offload plaintext on the SA's port_).

- [x] **A242.** A wedged host-command channel logged every failed sync retry, several lines each, for as long as the board ran —
  fixed (_:/^sdk_fman: report a run of HC sync failures once, and its end_).

- [x] **A241.** A failed ehash barrier leaked the cumulative node its delete or rebuilding add displaced, one per failure (A98's accepted residue) —
  fixed (_:/^sdk_fman: park the cumulative nodes a failed ehash barrier displaces_).

- [x] **A240.** Teardown left Netfilter able to call freed adapter text: a passive binding's indirect callback outlived unload, and a failed load kept its direct binds and works —
  fixed (_:/^flowtable: unwind a failed load's binds and work as unload does_).

- [x] **A239.** Flowtable mode never released entries a failed multicast or IPsec barrier parked, refusing unicast offload, the parked rearm and the adapter's load —
  fixed (_:/^cdx: release parked ehash entries on any completed barrier_).

- [x] **A238.** `display_pppoehdr_insert_opc()` decoded the big-endian PPPoE insert words through bitfields: session id byte-swapped, stats pointer byte-reversed —
  fixed (_:/^sdk_fman: decode the PPPoE insert opcode's big-endian words by shift_).

- [x] **A237.** A flowtable bound while an invalidation was latched was refused, so every atomic reload (fw4's included) failed whole and offload never rearmed —
  fixed (_:/^flowtable: park binds made during an invalidation instead of refusing them_).

- [x] **A219.** ask-flowtable took a second flowtable bound beside its own for a table to repair, and replaced its own into a drain the other held up —
  fixed (_:/^flowtable: keep the daemon's table while another is bound beside it_).

- [x] **A218.** Linux never asked for a partially offloaded flow's hardware counters while software kept refreshing it —
  fixed (_:/^netfilter: poll a partially offloaded flow's hardware counters_).

- [x] **A217.** A partially offloaded flow's periodic re-offer took RTNL for its installed half, and a lost trylock retired the whole generation —
  fixed (_:/^flowtable: answer a re-offered installed direction without RTNL_).

- [x] **A216.** Devices a path crosses without naming (a VLAN device under a session or tunnel, the ppp device under a tunnel) were neither held nor watched —
  fixed (_:/^flowtable: hold and watch the devices a path crosses without naming_).

- [x] **A202.** The microcode's IPv4 fragments of a frame received on an Ethernet port carry an all-zero payload, and a UDP direction into a smaller path was offloaded —
  fixed (_:/^flowtable: keep non-TCP IPv4 out of a path smaller than its ingress_).

- [x] **A215.** An MSTI remap or MST switched off stopped bridge ports without naming them, and their software flows were never swept —
  fixed (_:/^cdx: sweep a bridge whose MST events stop ports without saying which_).

- [x] **A214.** Software flows already through a port that stopped forwarding were never swept, and kept bypassing the bridge —
  fixed (_:/^cdx: sweep software flows off a port that stops forwarding_).

- [x] **A213.** The bridge's forward-path walk resolved a port STP or a VLAN state had stopped, so the software flowtable forwarded through it —
  fixed (_:/^bridge: keep flow offload off ports that are not forwarding_).

- [x] **A193.** Multicast quarantine on a failed hardware delete had no flowtable-mode driver —
  covered (_:/^tests: prove a failed multicast barrier parks and the next one frees_).

- [x] **A212.** The routed multicast fold wrote hardware counts over the MFC's, erasing ipmr's own and running `ip -s mroute` backwards —
  fixed (_:/^cdx: add routed multicast hardware counts to the MFC, never set them_).

- [x] **A201.** Oversized IPv6 into an SA was unmeasured — measured: SEC encrypts it whole and only the outer IPv4 packet is fragmented, so no bound
  is needed (_:/^tests: measure what an oversized IPv6 packet into an SA becomes_).

- [x] **A210.** Offloaded SAs started at sequence zero with a fixed 64-entry window, and SEC's numbering never reached xfrm —
  fixed (_:/^cdx: carry the IPsec starting sequence and replay window to SEC_).

- [x] **A209.** Offloaded IPsec SAs never accounted into xfrm's lifetimes, so byte and packet expiry never fired —
  fixed (_:/^cdx: account offloaded IPsec SAs into xfrm lifetimes_).

- [x] **A208.** Under `devices auto` any port's link change replaced the daemon's table, draining every offloaded flow —
  fixed (_:/^flowtable: follow auto device membership without replacing the table_).

- [x] **A207.** Interface packet counts stepped back by 2^32 at the firmware's 32-bit packet wrap —
  fixed (_:/^cdx: carry interface packet counts past the firmware's 32 bits_).

- [x] **A200.** Consumers did not advertise a smaller upstream's IPv6 MTU, so LAN-to-WAN IPv6 behind PPPoE or 6in4 stayed in software —
  documented as the integrating distribution's contract (_:/^docs: state what an integration owes an IPv6 LAN behind a narrower uplink_).

- [x] **A192.** VLAN and PPPoE admissions had no allocation-failure coverage —
  covered (_:/^tests: fail the allocations of tagged and session admissions_).

- [x] **A186.** A 6o4/4o6 tunnel whose outer packets leave by a PPPoE session was refused rather than offloaded —
  fixed (_:/^flowtable: offload a tunnel over a PPPoE session_).

- [x] **A206.** A flow admitted through a bridge port went on being bridged in hardware after STP blocked the port —
  fixed (_:/^flowtable: retire flows bridged through a port STP stops_).

- [x] **A205.** Hardware entries kept enqueuing to a port's old frame queues after an HTB tree switched it to or from CEETM —
  fixed (_:/^cdx: retire flows when a port's egress queues change_).

- [x] **A204.** A second flowtable bound at once was refused with EBUSY, failing every atomic reload and silently sending fw4's probe to software offload —
  fixed (_:/^flowtable: let a consumer reload its table in one transaction_).

- [x] **A203.** Every offloaded NAT-T SA sent and expected byte-swapped UDP ports, and a transport-mode one would have left as bare ESP —
  fixed (_:/^cdx: store NAT-T ports in host order, refuse transport-mode NAT-T_).

- [x] **A181.** ask-flowtable could validate a maximal policy and then refuse it at apply for overflowing the render buffer —
  fixed (_:/^flowtable: size the render buffer to what the validator accepts_).

- [x] **A187.** `display_l3hdr_insert_opc()` decoded the tunnel insert word's flag bits and stats pointer wrongly —
  fixed (_:/^cdx: decode the tunnel insert word's flag bits and stats pointer_).

- [x] **A197.** Two later upstream flowtable lifetime fixes (2014ac62df9d, e75a9fa1d44b) were missing from the tree —
  backported as patch 145 (_:/^netfilter: backport two upstream flowtable lifetime fixes_).

- [x] **A199.** CPU- and FMan-fed jobs of one SA reused ESP sequence numbers (the SDK zeroed the firmware's FMan port ICIDs) —
  fixed (_:/^sdk_fman: keep the boot firmware's port ICIDs_).

- [x] **A198.** The microcode fragmented forwarded IPv6 into a smaller path instead of Packet Too Big —
  fixed (_:/^flowtable: keep an IPv6 direction into a smaller path in software_).

- [x] **A195.** An offloaded flow's conntrack could expire under it (only gc_worker extended it) —
  fixed (_:/^flowtable: extend offloaded conntrack timeouts from the flowtable GC_).

- [x] **A190.** IPsec skipped the opposite LAN bridge/VLAN path and prevented flow offload —
  fixed (_:/^flowtable: resolve bridged LAN paths beside IPsec_).

- [x] **A158.** Multicast listener ceiling and replication across physical ports —
  hardware validation completed 2026-09-21 on a rebuilt, staged and TFTP-booted
  KASAN flowtable image. All four IPv4/IPv6 cases passed: eight exact hardware
  copies, whole-group software fallback at nine, recovery to eight, and simultaneous
  LAN/WAN replicas. Every expected receiver got all 256 sequences once per window;
  no malformed copies or kernel reports, and teardown left no test routes or devices.
  WAN replication uses the existing VLAN 3900 because this bench filters VLAN 320.
  See [measurements and artifacts](docs/flowtable/multicast-routed.md#a158-hardware-completion--2026-09-21).

- [x] **A189.** Routed bridge oifs omitted multicast router ports — fixed in kernel patch
  161 and `ft_mr_expand_bridge()`: snapshot the live MDB/router union per protocol and
  VLAN, deduplicate ports, and honour querier, forwarding and VLAN state. Router changes
  refresh the set; the five-second worker covers unreported changes without rebuilding
  unchanged chains. Unsupported/overflowing sets and failed replacements return the whole
  stream to software. No router cache or additional device references. Validation:
  154 ASan/UBSan snapshot scenarios, worker refresh/failure/device-removal/teardown cases,
  ten rejected regression mutations, 158 host tests, ARM64 `-Werror` checks and a full
  KASAN image build. The image was staged and booted for A158; its plain VLAN-oif
  cases do not cover A189's bridge/router semantics, whose DUT validation remains pending.
  See [routed multicast](docs/flowtable/multicast-routed.md#a189-follow-up--2026-09-21).

- [x] **A140.** Repeated teardown of a retiring flow cleared a newer flow's conntrack
  offload bit and shortened its timeout — fixed in _6e50c4f_: kernel patch 142 hands the
  conntrack back only on the first `NF_FLOW_TEARDOWN` transition. The 16,384-connection
  churn proof passed with zero conntracks reaped (82 before). Stale open entry archived
  2026-09-21; the patch remains included by the kernel recipe.

- [x] **A141.** The claim that `tx_init()` was never called was stale: current
  `cdx_cmdhandler_init()` starts with `CMD_INIT(tx)`, which registers the TX handler,
  seeds physical port IDs and sets `gDscpVlanPcpMapCtx.portid = NO_TX_PORT`.
  Closed on source verification 2026-09-21; no code change needed.

- [x] **A178.** moal could lose or double-complete scan requests during cancellation, timeout
  and teardown — fixed in driver patch 0008: all accepted scans (including cached scans and
  ACS) have an interface owner and generation under `scan_req_lock`; queued results carry
  that generation. Request preparation failures reject without completing, and accepted
  submission failures complete without also returning an error. Real timeouts complete even
  when firmware recovery is suppressed. Cleanup drains timer and result work before queue or
  interface removal, reset reopens admission, and competing firmware/cancel paths release the
  scan semaphore once. Validation: 134 ASan/UBSan scenarios, nine rejected regression mutations,
  155 host tests and full ARM64 `-Werror` Wi-Fi module build; DUT validation remains pending.

- [x] **A177.** IPsec exit and partial-init unwind left PCD queues and seeded buffers live —
  fixed (this commit): separate allocated PCD queues from embedded SA queues; drain callbacks
  before releasing the port, skb-backed pool and BPID mapping. SAs pin CDX until their queues
  are freed; failed SA creation now waits for retirement. CGR deletion runs on its owning CPU
  and retains resources on error. SDK patch 105 fixes zero-buffer seed failures and DMA-error
  double frees. Validation: 194 ASan/UBSan lifecycle cases, 154 host tests and ARM64 `-Werror`
  compilation of CDX and the SDK seeder; DUT validation remains pending.

- [x] **A33.** Routed multicast resolved listeners through `get_onif_by_name`, NULL for a `br-lan.N` —
  superseded: the flowtable learner hands the encoder ports and tag stacks, so there is no name (_pending_).

- [x] **A185.** `test_flowtable_bridge_fdb_roaming` (from da0b00a) read the bridge FDB once after the
  roam, but the parent carries the same MAC and its background traffic relearns the entry, so the
  single snapshot raced — fixed (this commit): re-send the tagged probe and poll until the roam port shows.

- [x] **A184.** sfp-led probing before sfp.c held MOD_DEF0 (sfp requests it only after its I²C adapter)
  won the line, and sfp's exclusive retry then failed for good — fixed (this commit): a port defers until
  the sfp device is bound, so it only ever borrows; KUnit `sfp_unbound` took the line without it.

- [x] **A183.** sfp-led put a borrowed MOD_DEF0 descriptor on deferred probe and unload: the sfp driver's
  line and active-low flag were released under it and a device ref it never took dropped — fixed (this
  commit): borrow without devm, put only an owned line; KUnit `shared_gpio` crashed UML without it.

- [x] **A182.** `test_flowtable_ipv6_mtu_recovery` flaked in the full suite: a readmission that lost
  `rtnl_trylock` (the sfp-led poll held RTNL 18×/s) needs two GC ticks, more than ten quick rounds — fixed
  (this commit): deadline settles with the busy path injected every run; the LED poll no longer takes RTNL.

- [x] **A176.** `moal_init_lock()` gave every mlan spinlock the one lockdep class of its single
  `spin_lock_init()` site, so the first client's ADDBA (command lock inside the TX ralist lock) reported
  "possible recursive locking" and switched lockdep off for the run — fixed (this commit): driver patch
  0006, a dynamic key per lock.

- [x] **A173.** moal reported scan results to cfg80211 under `scan_req_lock` (irqsave): GFP_KERNEL allocs,
  `bss_lock` taken `_bh`, and the first scan's waited ioctl — fixed (this commit): driver patch 0005
  reports outside the lock and completes only the request it took.

- [x] **A167.** `cdx_dpa_ipsec_init()` failing refused to load `cdx.ko`, so a board without the IPsec
  offline port or a SEC job ring had no offload at all — fixed (this commit): non-fatal, with
  `cdx_ipsec_ready()` refusing SA admission by both owners, the xfrmdev attachment and the encoder's
  table lookup; proved with `cdx.dpa_init_fail_site=cdx_dpa_ipsec_init`.

- [x] **A159.** A bound flowtable stopped the port's rx counters: the SDK driver counted a frame only
  when `netif_receive_skb()` returned other than `NET_RX_DROP`, which a frame stolen on the ingress
  hook always does — fixed (this commit): patch 104 counts before the handoff; hardware-forwarded
  frames come from the firmware records `dev_get_stats()` folds in, see `docs/flowtable/statistics.md`.

- [x] **A165.** The "single TX worker is the wire-to-Wi-Fi ceiling" was an instrumentation artifact:
  a production-config kernel (no KASAN/lockdep/kmemleak) with the flow offloaded runs 654 Mbit/s median,
  666 peak on VHT80 2x2 — the air ceiling, not the worker. The 160–201 figures were KASAN+lockdep
  roughly halving a CPU-borne path plus offload not engaged. Lock-churn lever landed in _c14ecd5_
  (patch 0007); the single-worker structural limit is dormant below a faster PHY. Numbers in memory.

- [x] **A175.** `ft_wifi_exit()` blocked on RTNL with the CDX transaction held, the reverse of the bind
  path's order (transaction under RTNL via `dpa_setup_tc`) — a lock inversion lockdep reports at unload
  once a table has been bound; hidden until A174 restored lockdep — fixed (this commit): RTNL first.

- [x] **A174.** The netlink cb_mutex lockdep name table stopped at 33 while `MAX_LINKS` is 64, and moal's
  socket sits at 63: a nameless class WARNs, `debug_locks_off()` disables lockdep and sets the console
  to level 15 on every test-image boot since the radio was added — fixed (this commit): patch 093 names
  every slot.

- [x] **A172.** VWD drained its queues through `eth0`'s NAPI, which is enabled only while `eth0` is
  open — never, on this board — so the portal's dequeue interrupt stayed masked and only the WAN port's
  transmit confirmations kept the path moving — fixed (this commit): VWD owns a NAPI per CPU and portal.

- [x] **A166.** `dpaa_get_vap_fwd_fq()` dereferenced a slot whose queues may not exist yet (legacy
  owner creates the record before the open) — fixed (this commit): failing return, all callers check.

- [x] **A164.** `process_vap_rx_fwd_pkt()` took the global `vaplock` and a `dev_hold`/`dev_put` pair per
  frame — fixed (this commit): RCU read section; the retire path publishes with release semantics.

- [x] **A171.** A non-DPAA device in an offload flowtable (a VAP, which fw4 always lists once Wi-Fi
  is in the LAN bridge) was refused, which fails the whole table and drops every port to software —
  fixed (this commit): bound passively, its flows declined into the software fast path.

- [x] **A170.** `dpa_get_ifinfo_by_netdev()` matched a VAP record by address alone, and the record
  outlives its device by one workqueue hop — fixed (this commit): VWD must still own the device.

- [x] **A169.** The VAP-id allocator rotated through all 32 slots before reusing one, and each slot's
  65 frame queues live until module exit, so restarts grew the table to 2080 queues —
  fixed (this commit): prefer a free slot whose queues exist, bounded by peak concurrent VAPs.

- [x] **A168.** `dpaa_vwd_init()` failing refused to load `cdx.ko`, so a board without the Wi-Fi
  offline port had no offload at all — fixed (this commit): non-fatal; `dpaa_vwd_ready()` gates
  every later use.

- [x] **A163.** The IPsec egress encoder passed hash 0 to `dpaa_get_vap_fwd_fq()`, pinning every
  encrypted flow to a VAP onto queue 0 and one CPU — fixed (this commit): spread by SA handle.

- [x] **A162.** `moal` defaulted `tx_skb_clone=1` and so `pskb_copy`'d every transmitted frame on
  its single TX worker, the second-largest item on the pegged core — fixed (this commit): default 0,
  the cloned/headroom predicate it bypassed still copies what needs copying (patch 0004).

- [x] **A161.** Use-after-free in the Wi-Fi driver's transmit path: `wlan_dequeue_tx_packet()` read
  `ptr->sta` after the send helpers dropped `ra_list_spinlock`, racing `wlan_wmm_delete_peer_ralist()`
  on a station leaving under load — fixed (this commit): re-validate under the lock (patch 0003).

- [x] **A160.** Use-after-free in the Wi-Fi driver's receive path: `moal_recv_packet()` read the skb
  after `netif_rx()` consumed it — fixed: record the handoff, gate the epilogue (_f07beac_, patch 0002).

- [x] **A157.** Bridged multicast looked installed-but-never-matching on the
  first rig run; not a defect — the injector used a plain UDP socket, whose
  default multicast TTL of 1 the soft parser excepts before classification.
  With TTL 64 the group matches every frame (_9550336_).

- [x] **G1.** `/dev/cdx_ctrl` ioctl dispatcher was ungated — added a CAP_NET_ADMIN
  check ahead of the command-table lookup (_815a0ca_).

- [x] **N1.** FCI/abm/NETLINK_KEY ipsec-offload bus had no capability gate —
  fixed: per-message `netlink_capable(skb, CAP_NET_ADMIN)` on all three handlers (`test_fci_netlink_caps.py`).

- [x] **G2.** Single-open gate had a mis-rejection window — replaced with a single
  atomic_cmpxchg(1→0).

## Critical

- [x] **C1.** auto_bridge L2FLOWA_IP_SRC/DST memcpy trusted attacker nla_len into a
  16-byte union — nla_policy caps NLA_BINARY len to the field size.

- [x] **C2.** FCI inbound trusted sender nlmsg_len for OOB-sized payloads —
  validate fci_msg->length against skb->len and FCI_MSG_MAX_PAYLOAD.

- [x] **C3.** IPR release loop walked FMAN-supplied num_entries unbounded — cap
  against reassly_bp->size / entry-size before the release loop.

- [x] **C4.** IPR ref_count (uint8_t) could wrap on double-decrement — zero-check
  and drop before decrementing.

- [x] **C5.** IPR deinit was a stub leaving the timer kthread and FQs live (UAF on
  unload) — full kthread-stop + FQ retire/oos/destroy + bpool free.

- [x] **C6.** dpa_cfg scaled allocations by attacker-influenced counts — sanity
  caps + kcalloc, num_fmans==0 rejected, sub-counts allow legit zero.

- [x] **C7.** Six fm_index checks used `> num_fmans` (one index OOB) — all flipped
  to `>=`.

- [x] **Bonus.** cdx_ctrl_deinit (.text) referenced cdx_cmdhandler_exit
  (.exit.text) — dropped __exit so the section reference is legal.

- [x] **C8.** queue_no/port_idx/dscp used as unchecked array indices from userspace
  — entry bounds checks added in dpa_cfg.c and cdx_ehash.c.

- [x] **C9.** Test ioctl kzalloc overflow — mooted (_815a0ca_): the buggy code
  was deleted with the testapp scaffolding (see C9b), not sanity-capped.

- [x] **C9b.** Dead testapp scaffolding remained compiled-in — deleted dpa_test.c,
  testapp.c and the CDX_CTRL_DPA_CONNADD ioctl + structs (moots H10).

- [x] **C10.** Raw netlink `.input` handlers (FCI cap-fail ack/`fci_outbound_err`
  over-read, `ipsec_nlkey_rcv` short-skb memcpy) got no core length validation —
  fixed: all bounded against `skb->len`. Distinct from C2 (payload-parse path).

## High

- [x] **H1.** Concurrent CDX_CTRL_DPA_SET_PARAMS ioctls could UAF fman_info —
  dpa_cfg_lock mutex, -EBUSY re-init reject, err_ret unwind (_815a0ca_).

- [x] **H3.** IPsec shared-desc error paths leaked auth/cipher key DMA maps —
  two-label unwind + SA_SH_DESC_BUILT rollback on add failure.

- [-] **H4.** CAAM shared-desc map-then-unmap suspected bug — wontfix: deliberate
  cache-flush idiom; SEC reads the desc via the ipsecsa handle; documented.

- [x] **H5.** NAT-T SPI slot check used `> MAX_SPI_PER_FLOW`, letting the "full"
  sentinel index the array — reject with `>=`.

- [-] **H6.** auto_bridge per-bucket lock-drop iteration suspected UAF — wontfix:
  no state crosses the drop; entries rebound per bucket under lock.

- [x] **H8.** abm sysctls lacked a capability gate and abm_max_entries accepted 0 —
  CAP_NET_ADMIN check + proc_douintvec_minmax bounds 1..1e6.

- [x] **H9.** Static query-snapshot cursors raced concurrent enumerators — per-file
  query mutexes + mc bucket spinlocks; mutator walks tracked under A2.

- [x] **H10.** strncpy_from_user truncation unchecked — mooted: all four sites
  lived in dpa_test.c, deleted with the C9b test-scaffolding removal.

- [x] **H7 (partial).** net_device stored without dev_hold — dev_hold/balanced
  dev_put added; the drain's sleep-under-spinlock residual closed as H7-r.

- [x] **H7-r.** `rtnl_lock()` under `spin_lock_bh(&abm_lock)` on the abm drain —
  fixed: `bridge_list_rtevent` spliced to a local list under the lock, notify
  after unlock (`test_abm_port_flap.py`).

- [x] **H2 (partial).** IPsec keys not zeroed on free — kfree_sensitive on the
  SA-context keys; the query-snapshot sibling leak is reopened as H2-r.

- [x] **H11.** `abm_fdb_can_expire` took `abm_lock` with plain `spin_lock`
  (self-deadlock / `{SOFTIRQ-ON-W}` lockdep hazard) — fixed: all three sites
  switched to `spin_lock_bh`.

- [x] **N3.** `cdx_get_ipsec_fq_hookfn` had no unregister (failed init wedged
  every later load until reboot) — fixed (_81421c2_ patch 010 regen, _b2342ce_
  cdx): all five hook families get unregister-on-deinit. Sibling filed as N7.

- [x] **H2-r.** SA query snapshots memcpy'd full cipher/auth keys and were
  plain-`kfree`d — fixed (_5376281_): frees switched to `kfree_sensitive`,
  fill slice zeroed. Closes H2 fully.

- [x] **N5.** Five CAAM/bman `dma_map_single` results tested with `!addr` (real
  failures reached hardware) — fixed (_5376281_): all use `dma_mapping_error()`.

- [x] **N8.** Five iface stats getters dropped `dpa_devlist_lock` between lookup
  and use — fixed (_062484a_, _9c103b9_): lock held across read/reset, eth HW
  teardown moved outside the lock. Non-FCI walkers filed as N10.

## Medium

- [x] **M1.** Query of 6-8 listener groups OOB'd the reply buffer — pagination
  reserves 2 cmds/group, pages via bIsValidEntry look-ahead.

- [-] **M2.** dev_get_by_name leaks (control_vlan) — wontfix: control_vlan paths
  are NULL-guarded and balanced; a missed dpa_wifi sibling is filed as N4.

- [x] **M3.** Unbounded sprintf chain in the fqid_stats procfs handler — converted
  to seq_file; two ucode_frag siblings of the same class filed as N2.

- [x] **M4.** %px and raw %p handle prints in cdx debug output — %px removed,
  sensitive handle prints flipped to %pK; hashed %p left per policy.

- [x] **M5.** auto_bridge netlink dispatch used signed nlmsg_type with no default
  arm — narrowed to u16, unknown types return -EINVAL.

- [x] **M6.** auto_bridge exit hot-spun on bare schedule() waiting for l2flow drain
  — bounded 5s wait with 1-jiffy sleeps and pr_warn on timeout.

- [x] **M7.** IPsec table-entry add left the shared descriptor dangling on failure
  (explicit TBD) — SA_SH_DESC_BUILT rolled back, entry/ct/info freed on unwind.

- [x] **M8.** Full-group mcast delete unlinked shared list state lock-free —
  list_del now under the bucket spinlock, sleeping HW teardown after unlock.

- [x] **M9.** mcast ADD unwind could leak pCtEntry/pRtEntry if a future path failed
  after wiring them — err_ret now frees both, defense in depth (_c23817b_).

- [x] **M10.** Cdx_GetMcastMemberId returned ids stale across dropped bucket locks
  — mc_mutators_mutex serializes ADD/REMOVE/UPDATE at the dispatcher.

- [x] **M11.** GetMcastGrp returned a group pointer freeable after the bucket lock
  dropped — the same mc_mutators_mutex closes the window.

- [x] **M12.** REMOVE fast path keyed on count alone; wrong names wiped the group —
  every listener pre-validated, mismatch returns ERR_MC_CONFIG.

- [x] **M13.** Duplicate names in REMOVE still tripped the count-match full delete —
  member_id bitmap dedupes, repeats rejected with ERR_MC_CONFIG.

- [x] **M14.** cmm_parse_rtattr logged rta->rta_len after loop exit (OOB read on
  a truncated rtattr) — fixed: logs remaining length only.

- [x] **M15 (partial).** FMAN PCD didn't replicate IPv4 mcast to listener subifs
  — fixed: dev_mc_add/del + wmb before ADD publish; UPDATE barrier → M15-r.

- [x] **N2.** `/proc/ucode_frag/*` read handlers sprintf'd into the `__user`
  buffer (M3's class) — fixed (_b593f93_): converted to seq_file, proc entries
  removed at deinit, NULL `bp->pool` deref dropped.

- [x] **M15-r.** UPDATE-path mcast publish lacked the ADD-path's `wmb()`, and the
  REMOVE unlink's invalid-flag store used a host-order macro on BE flags —
  fixed (_5376281_): barrier added, store now ORs `cpu_to_be16(1<<15)`. Closes M15.

- [x] **N4.** `dpaa_vwd_init`'s `err7` unwind nulled `vwd.eth_priv` without
  dropping the `get_eth_priv` ref — fixed (_5376281_): `dev_put` added.

- [x] **N9.** `alloc_iface_stats` returned SUCCESS with a NULL slot on freelist
  exhaustion — fixed (_1f996c0_): frees `last_stats` and returns FAILURE; add
  cascades free stats on `dpa_add_port_to_list` failure.

- [x] **N11.** The VAP ioctl state machine slept under `spin_lock_bh(vaplock)` —
  fixed (_7510673_): ADD claims the slot `VAP_ST_CONFIGURING`, sleeps unlocked,
  publishes under the re-taken lock. Lifetime residue filed as N13.

- [x] **N12.** Deinit never freed the interface list (`dpa_release_iflist` had
  zero callers) — fixed (_a34063c_): pop-under-lock/release-outside sweep,
  registered after `tx_exit`. Adjacent teardown leaks filed as N14.

- [x] **N13.** VAP REMOVE/RESET tore down state lock-free consumers could still
  reach — fixed (_de0aef4_): rtnl-held `vwd_unpublish_vap` + `synchronize_rcu`
  grace before `vwd_vap_down`. Residue filed as N15.

- [x] **N14.** Teardown gaps (un-ifdef'd `destroy_fwd_tx_fqs`, unreclaimed proc
  dirs, fqid tracking nodes, stats MURAM carve) — fixed (_79089f1_). Failed-
  injection MURAM/HW residue accepted.

- [x] **N15.** VAP/netdev lifetime residue — fixed (_f094aba_): NETDEV_UNREGISTER
  notifier, VLAN aliases republished on re-ADD, rtnl-held ioctl drain; cdx.ko
  now depends on 8021q.ko.

- [x] **N19.** CBC+HMAC wire showed 26x the seq-duplicates of GCM (per-job PDB
  STORE was GCM-only) — fixed (_1055403_): extended to every cipher, CBC dupes
  0.154%→0.006%.

- [x] **N18.** Descriptor KEY commands DMA-read key bus addresses unmapped at
  build time (fatal under IOMMU/SWIOTLB) — fixed (_14722d1_): mappings live in
  the SA context, released in `cdx_ipsec_sec_sa_context_free`.

- [-] **N17.** "cmm-programmed IPsec inner flows heavily lossy" — not-a-bug: not
  reproducible on a clean boot (TCP 2.54 Gbit/s, 99.996% classified); evidence
  was test/boot artifacts, the one real residual refiled as N19.

- [x] **N10.** Devlist discipline sweep (OH `itf_id` 0 aliasing onif 0, non-FCI
  walkers lockless, missing `dpa_add_wlan_if` checks) — fixed (_26b408a_).
  Sleeping-under-vaplock and deinit list leak filed as N11/N12.

## Low / Hardening

- [x] **L1.** Fixed-seed Jenkins/jhash on attacker-chosen L2-flow keys — fixed
  (_89e5b32_ + _bf8c453_): per-boot-keyed hsiphash/siphash; jenk_hash.h deleted.

- [x] **L2.** strcpy into equal-sized IF_NAME_SIZE buffers across cdx control paths
  — full sweep to strscpy(dst, src, sizeof(dst)); none remain.

- [x] **L3.** sprintf into small fixed name buffers in cdx procfs — snprintf
  bounded by sizeof(node->name).

- [x] **L4.** proc_create("fci", 0, ...) left permissions implicit — mode set to
  0444, read-only intent explicit.

- [x] **L5.** Dead unimplemented ioctl prototypes in cdx_ioctl.h — stubs plus
  supporting structs/macros removed (incl. a cmd-number collision).

- [x] **L6.** Reassembly release misnamed cpu_to_be* on BE-to-host reads — renamed
  be*_to_cpu, u8→u16 zero-extend documented; no-op on LE.

- [x] **L7.** UBSAN array-bounds on the flex-array subscript in create_ethernet_hm
  — store converted to pointer arithmetic, semantics unchanged.

- [x] **L8.** cmm sig_term_hdlr logged benign ENOENT for an already-removed pidfile
  — both cleanup sites report only errno != ENOENT.

- [x] **N6.** `abm_retransmit_delay` accepted 0 (work spins) and negatives (work
  parked ~forever) — fixed (_d8083c6_): handler rejects `<= 0` with -EINVAL,
  restores the previous value.

- [x] **N16.** eth4 (LAN) FMAN ingress came up dead on a fraction of boots (rx=0,
  link up) — closed as a one-off (not reproduced since; test tooling gates each
  boot on eth4 rx>0 with static neighbors). Reopen if it recurs.

## Corrections to the original review (wontfix / not-a-bug)

- [-] **A142 (wontfix, CMM retirement).** Interface-statistics offsets truncating
  past record 121 — reachable only through CMM's interface registration, now retired (this commit).

- [-] **A79 (wontfix, CMM retirement).** `cmmUpdateFlows` iterator invalidation —
  CMM no longer runs; the source is kept only as reference (this commit).

- [-] **A156 (wontfix, CMM retirement).** A failed legacy multicast UPDATE in
  `cdx_update_mcast_group()` leaves listeners from earlier in the batch live,
  so FCI receives failure while hardware keeps the partial update. Closed on
  2026-09-21 under the CMM retirement decision: its callers are the IPv4/IPv6
  FCI handlers and the legacy ADD-on-existing-group path. Flowtable ownership
  rejects FCI dispatch in `comcerto_fpp_send_command()`. Both flowtable multicast
  learners instead call `cdx_mc_group_replace()`, which builds the new chain
  unpublished, frees it on build failure, and publishes only after all listeners
  succeed. The legacy defect is retained until that control path is removed.

- [-] **A155 (wontfix, CMM retirement).** One DUT reset was observed during a
  CMM-owned IPsec UDP transfer (400 Mb/s, 1300-byte datagrams, WAN to LAN,
  non-KASAN image). No console trace was captured, and the LAN segment was
  flapping; the root cause remains unconfirmed. Closed by scope decision on
  2026-09-21: CMM is being retired, so further legacy-mode reproduction and
  repair are out of scope.

- [-] **N20 (not a bug).** "Same-SPI reinstall blackholes the tunnel" was a test
  artifact — reinstalling one peer's SA rewinds ESP seq to 1, the other peer
  correctly rejects the rewound seqs (RFC 4303); no cdx defect.

- [-] **X1.** "256B memset + partial fill info leak" — wontfix: memset(p,0,256)
  zeros the full rbuf before the partial fill; surplus bytes are zeros.

- [-] **X2.** "strcpy IF_NAME_SIZE overflow" — wontfix/fixed: downgraded to L2 and
  swept to strscpy (_89e5b32_); all cdx name copies now dst-size bounded.

- [-] **X3.** "dpaa_eth_refill_bpools suspected leaks" — wontfix: the skb
  backpointer lives in the BMan hardware-owned frag pool; error paths free clean.

- [-] **A9 (not a bug).** "Tunnel TX encap never offloads — ucode `INSERT_L3_HDR`
  punts" — the oracle was wrong, not the ucode; rig re-test measured encap
  offloaded at 9.14 Gbit/s with the A72s 96.4% idle. Residue filed as A135-A136.

- [-] **A12.** "PPPoE RX-decap missing classifier install" — wontfix: the PPPoE
  strip is an HM chained on the inner CT entry, not a table.

- [-] **A15.** "cmm has no incoming xfrm subscription" — wontfix: the af_key km
  hook broadcasts SA events on NETLINK_KEY grp1, cmm binds via libfci; restart
  confirmed no resync gap (recoverable via `ip xfrm state flush`).

- [-] **N7.** "vwd nf hooks leak on cdx unload with fast path enabled" —
  wontfix/not-a-bug: hooks registered at module init (toggle only flips the gate
  flag), every path unregisters exactly once.

## Architectural themes

- [x] **A1.** External command fields validated ad hoc per cmdproc — fixed: FCI
  bus + cdx dispatcher routed through one validator-table idiom (2 latent bugs fixed).

- [x] **A1a.** No shared bounds-check idiom — fixed (_cf1fa1b_): added
  cdx_cmd_validator.{h,c} (spec table + cdx_dispatch_cmd).

- [x] **A1b.** control_vlan migrated as the prototype — VlanCommand length + action
  validator, cmdproc reduced to a dispatch tail-call (_f2f3a82_, _c4d3965_).

- [x] **A1c.** Remaining 13 cmdprocs (~120 codes) migrated to validator tables with
  per-command length bounds.

- [x] **A1d.** /dev/cdx_ctrl ioctl switch replaced by table-driven
  cdx_ioctl_table[] with CAP_NET_ADMIN gate + ENOTTY on unknown cmd (_ed082ea_).

- [x] **A1e.** Per-subsystem inner cmd_code switches removed — each cmdproc is a
  one-line dispatch tail-call.

- [x] **A2.** Locking assumptions were implicit per-file folklore — top-of-file
  Concurrency: blocks + sparse __must_hold() across cdx/abm/fci (_d99bb62_).

- [x] **A3a.** IPR init leaked bpools/kthread/FQs on failure — fixed (_b5a7bf8_ +
  _78ac2af_): nested unwind cascade; deinit tears down FQs via ipr_fqs[].

- [x] **A3b.** fqid procfs mkdirs left earlier dirs on later failure — nested
  err_remove_* cascade; deinit proc_removes the whole tree.

- [x] **A3c.** l2flow_cache leaked when brroute_cache creation failed —
  destroy+NULL l2flow_cache on that error path.

- [x] **A3d.** abm_init leaked earlier subsystems on later init failure — goto
  cascade runs each matching _fini/_exit in reverse order.

- [x] **A3e-r.** `dpa_add_eth_if` cascade leaked the netdev ref + stats slot, eth
  removal leaked `last_stats`/`priv->ifinfo` — fixed (_dffbbd6_): guarded
  `dev_put`, `err_stats` unwind, eth arm in `free_stats`. Closes A3; N8/N9 filed.

- [x] **A4.** Debug scaffolding shipped as production — dpa_test.c removed, IPR
  deinit stub implemented, %px/%p prints flipped to %pK.

- [x] **A5.** Sanitizer bring-up surfaced 4 vendored-kernel bugs (qbman, sdk_dpaa,
  sdk_fman, netlink) — fixed as patches 090-093, shipped to both images.

- [x] **A5a.** qbman dpa_alloc_new kmalloc'd GFP_KERNEL under spin_lock_irq —
  patch 090 preallocates all list nodes before the lock, frees leftovers after.

- [x] **A5b.** dpa_get_channel held a spinlock over qman_alloc_pool (sleeps) —
  patch 091 swaps it for a mutex; the only caller is probe-time process context.

- [x] **A5c.** A shared lockdep class made FmPcdLockTryLockAll's inner locks look
  recursive — patch 092 adds a SINGLE_DEPTH_NESTING try-lock variant.

- [x] **A5d.** NETLINK_L2FLOW=33 got a NULL lockdep name from the 0..32-only
  cb_mutex string table — patch 093 names indices 32 (KEY) and 33 (L2FLOW).

- [x] **A6.** Tunnel handlers walked 16-byte FCI name fields as C strings (KASAN
  OOB) — fixed (_9f9b69d_): HASH_TUNNEL_NAME/M_tnl_get_by_name take maxlen.

- [x] **A7.** Fuzzer only hit dispatcher length checks — fixed (_0bf177b_): 30
  payload-body mutation cases (10 cmds × all_ff/high_enum/no_nul_str) + oracle.

- [x] **A8.** cdx never freed its CAAM job ring, tripping the caam_jr busy check on
  reboot — idempotent release from the deinit chain + reboot notifier.

- [x] **A9 (decap portion).** TX-offload test was a false positive (stale
  baseline) — fixed: reframed as a tripwire; RX decap proven offloaded (6o4+4o6).
  TX-encap residual stays open as A9.

- [x] **A10.** RouteEntry.id stored the U32 wire route id as U16, silently
  truncating on ADD — widened to U32; API/hash/wire already U32 (_d61c50f_).

- [x] **A11.** FORTIFY warned on memcpy into [0]-tails in fm_ehash.h (patch 099 not
  in SRC_URI) — all 7 tails now C99 flex arrays, recipe ships 099 (_e499b98_).

- [x] **A13.** Vendored CPE_FAST_PATH hunk took rtnl_lock under all_ppp_mutex —
  NEWLINK now sent after mutex drop via dev_hold (patch 070).

- [x] **A14.** H2 key-zeroing was unobservable — test-image-only probe snapshots the
  post-kfree_sensitive cipher_key to /proc/cdx (_5358b5b_).

- [x] **A16.** NAT-T fast-path push threw away the classification-entry rc (reply
  stayed NO_ERR) — fixed (_d5be3ae_): rc captured, propagated as ERR_CREATION_FAILED.

- [x] **A17.** SET_KEYS wrote through sa before the NULL check — stale-sagd
  NULL-deref; assignment moved after the ERR_SA_UNKNOWN return (_d5be3ae_).

- [x] **A18.** NAT-T push wrote sa->ct->natt_in_refcnt after ignoring add-entry
  failure — now bails to err_ret; the callee frees+NULLs sa->ct (_d5be3ae_).

- [x] **A19.** Three SA leaks (procfs wrapper on mkdir-fail, release-path wrapper,
  shdesc_mem) — symmetric kfrees added (_cd0548c_).

- [x] **A20.** ipsec_nlkey_rcv took x->lock without BH disable vs the softirq
  xfrm_timer — fixed (patch 040, _d5be3ae_): three NLKEY pairs → spin_lock_bh.

- [x] **A21.** Deinit from a failed init crashed in qman_ceetm_sp_release(sp=
  NULL) — fixed (_d236aa3_): SP claim passed explicitly + NULL-guarded, init
  failure propagates.

- [x] **A22.** gateway-dk cdx_cfg.xml OH portid 8/9 tripped the espschema
  `$logicalportid lt 9` gate, breaking ESP recognition — fixed (_d5be3ae_):
  restored to NXP 9/10.

- [x] **A23.** ipsec_bp registered but never seeded — SEC hit BPDERR, silent drops;
  dpaa_bp_alloc_n_add_buffs(512, act_skb=1) added with unwind (_d5be3ae_).

- [x] **A24.** DNCPE-2358: two SEC descriptor defects (SAVECTX carried GCM class-1
  context forward; cross-DECO refetches unordered vs PDB.seq writeback) — fixed
  (_451bc18_): SERIAL without SAVECTX + per-job PDB+stats STORE; GCM re-enabled.

- [x] **A25.** AES-128-CTR lacked the RFC 3686 nonce trim and CTR PDB fields —
  fixed (_d5be3ae_): extra_size=4 trim + ctr_nonce/ctr_initial=1 in both PDBs.

- [x] **A26.** ASK patch stack compiled with ~52 warnings — fixed (_3b93e0e_):
  010/040 regenerated warning-free.

- [x] **A27.** IPsec SA handle set by a lockless `xfrm_state_handle++` (aliased
  handles, u16 wrap → ERR_SA_DUPLICATED rekey blackhole) — fixed (patch 040):
  assigned at byh-insert under xfrm_state_lock with dedup, counter seeded once.

- [x] **A28.** xfrm_input inbound-offload submit passed x->handle to SEC before
  the XFRM_STATE_VALID check, and x->offloaded was never cleared on delete —
  fixed (patch 040): submit gated on VALID, `__xfrm_state_delete` clears it.

- [x] **A29.** af_key SET_OFFLOAD could re-mark a DEAD SA offloaded — fixed
  (_bad0464_): sets `offloaded=1` only under `km.state==XFRM_STATE_VALID` inside
  `x->lock`; clearing stays unconditional.

- [x] **A30.** `ctnetlink_change_permanent()` short-circuited the whole ct update
  when CTA_STATUS carried IPS_PERMANENT, dropping bundled attrs — fixed (patch
  050): gates on the IPS_PERMANENT *delta*, pin via atomic set_bit.

- [x] **A31.** `ctnetlink_change_permanent` unpin-on-IPS_PERMANENT-absence looked
  unsafe — proven safe (patch 050): the sole controller (cmm) always echoes full
  status and clears the bit only on a deliberate teardown; routine updates send
  no CTA_STATUS. Invariant documented in the handler, no behavior change.

- [x] **A32.** Forwarded NATed flows through a vlan-aware bridge (`br-lan.N`) ran
  on the CPU (not a cdx onif → ingress/egress resolution failed) — fixed
  (_d85724d_): physical-port substitution + `underlying_input_itf` fallback.

- [x] **A34.** cmm `VLAN_FILTER` build asymmetry (`make cmm` omitted it, the
  recipe defined it) — fixed (_25f85e8_): `cmm/Makefile` carries the single
  authoritative define list; also fixed a short netlink attribute space.

- [x] **A35.** Two patch-010 TODOs — fixed: (a) `skb_fraglist_to_sg_fd`
  linearizes oversized-fragment frames instead of dropping (_8ffdd9c_); (b) the
  `skb_scrub_packet` ipsec_offload secpath exemption proven correct, TODO
  replaced with a rationale (_639ca25_).

- [x] **A36.** Five audit smells confirmed + **fixed** (_051b8c4_): ehash lock leaks,
  sysfs IRQ-off returns (new patch 101), RICP clobber, libnfnetlink UAF, fmc dedup.

- [x] **A37.** Two IPsec-FQ setup leaks in cdx `dpa_ipsec.c` — fixed (_dd37089_):
  `err_ret` unwinds the exception FQs, `err_ret2` releases the fqid range.

- [x] **A40.** fmc's `fmc_exec_htnode` marshalled fmlib's 88-byte struct into the
  120-byte uapi ioc struct, so every ehash node got `table_type=0` (wrong ucode
  AD class) — fixed (_953051c_): struct made layout-identical + ioc buffer memset.

- [x] **A41.** The kas dpa_app build didn't enforce `-Wall -Werror` (its recipe
  CFLAGS override dropped them), so the shipped binary escaped the warning-free
  policy — fixed (`dpa-app_1.0.bb` CFLAGS append).

- [x] **A44.** `ipv4/ipv6_reassly_offset` in `FM_PCD_CcRootBuild` were declared
  uninitialized yet written into every non-ETHERNET table's AD (stack residue
  into ucode descriptors) — fixed (_953051c_): both init to the 0xff sentinel.

- [x] **A45.** `externalHash` type-confusion — real but unreachable; dead surface
  excised (_bd9f289_), marshalling half already resolved (_953051c_).

- [x] **A42.** Socket-update mutate-then-fail — already fixed (_dd96e1d_): HEAD is
  validate-then-commit (entry was stale). The confirm pass surfaced four live
  same-shape route-ref bugs → A48-A51.

- [x] **A46.** `FM_PCD_HashTableAddKey` type confusion on the
  `FM_PCD_IOC_HASH_TABLE_ADD_KEY` path — fixed (_e690063_): ioctl case deleted,
  function removed, entry param tightened so the confusion is a compile error.

- [x] **A47.** FMan sysfs handlers used `local_irq_save` as an illusory
  pseudo-lock; `show_fm_risc_load` even slept 1s under it — fixed (_this
  commit_): removed the illegal sleep-with-IRQs-off and dropped the guard from
  15 read-only/inner-locked handlers. 3 debug-only register-select handlers keep
  a documented weak guard (a real FM-level lock is deferred, near-zero payoff).

- [x] **A52.** `/dev/fmX` FM_PCD modify/query ioctls dereferenced a user-supplied
  `param->id` as a kernel `t_Handle` (NXP-labelled "Security Hole") — fixed
  (patch 010): the 12 runtime modify/query verbs are stubbed to
  `E_INVALID_SELECTION` (A46 pattern), re-verified caller-free against the shipped
  fmc (build tree, not the incomplete `sources/fmc`). The six `*Delete` verbs are
  deliberately left live — fmc's teardown calls them, so stubbing them would
  break PCD teardown (don't "finish the family"); accepted unvalidated given the
  0600-root node and dormant delete path. DUT-boot (PCD still builds) is the gate.

- [x] **A43.** cmm MSP socket surface — closed (verified 2026-08-18, no code
  change needed): cmm-side deletions shipped in _dd96e1d_, cdx's
  `ERR_WRONG_SOCK_TYPE` rejection is the desired terminal state.

- [x] **A48.** cdx v4 socket-open resolved `route_id` twice, leaking one `nbref`
  per open — fixed (_6a62e61_): drop the orphan get, mirror v6. Runtime-confirmed.

- [x] **A49.** cdx `tunnel_free` was a bare `kfree` with no `L2_route_put`,
  leaking a route ref per tunnel delete — fixed (_6a62e61_): NULL-safe put +
  release before `remove_onif_by_index`. Runtime-confirmed.

- [x] **A50/A51.** cdx tunnel/SA route-set handlers dropped the old route then
  took the new one unchecked, committing a routeless binding with `NO_ERR` —
  fixed (_69ab942_): resolve-then-commit; cmm smells split to A54/A55.

- [x] **A53.** Dangling `RouteEntry->itf` slab-UAF on interface teardown (pinned
  routes survived `remove_onif_by_index` with the pointer intact) — fixed
  (_7432ef6_): pinned routes quarantined, deref sites NULL-guarded, onifs removed
  before free. KASAN-validated. Residue filed as A63/A64.

- [x] **A54.** cmm assumed the pre-A42 "cdx drops the old route on failure"
  contract, so a rejected route swap orphaned the fpp route handle — fixed
  (_733c599_): CTs torn out of HW on rejected re-register, holders roll back +
  re-arm `FPP_NEEDS_UPDATE`. Residue A66; A65/A67/A68 surfaced en route.

- [x] **A55.** cmm `module_socket.c` error-code truncation (negative rc narrowed
  to 65535) — fixed (_42379cb_): `int rc`, alloc failure → `CMMD_ERR_MEMORY`,
  negative transport errors keep their sign. Reporting residue filed as A75.

- [x] **A56.** `ipsec_push_sa_to_fast_path` installed the HW entry before
  resolving the xfrm state, and overwrote `sa->xfrm_state` without putting the
  prior ref — fixed (_02d4968_): unwind via `cdx_ipsec_delete_fp_entry` on lookup
  failure, put the old ref first; adjacent NAT-T `sa->ct` dangle also fixed.

- [x] **A57.** `M_tnl_add` hash-linked the tunnel before the fallible
  `dpa_add_tunnel_if` and discarded its result (real failure reported `NO_ERR`)
  — fixed (_02d4968_): program HW first, hash-link only on success, release onif
  + route on the failure arm (`test_tunnel_failslab.py`).

- [x] **A58.** `M_ipsec_sa_cache_create` linked the SA onto `sa_cache_by_fqid`
  before the fallible `sa_add` — fixed (_42379cb_): `sa_add` first, fqid link
  only on success, failure arm releases the SEC context.

- [x] **A59.** `struct _cdx_ctrl.lock` was a dead spinlock (never acquired; timer
  wheels run under `ctrl.mutex`) with a misdescribing concurrency comment —
  fixed (_6b6d9f2_): field/init deleted, comment rewritten.

- [x] **A60.** MURAM `dc zva` oops: socket-open `memset` of the MURAM stats block
  faulted on Device-nGnRE memory and wedged `ctrl.mutex` — fixed (_849b90f_): all
  five generic mem-ops switched to `memset_io`/`memcpy_fromio`. Comment falsehood
  tracked as A61.

- [x] **A61.** Patch 010's `etc/memcpy.c` aliased the IO copy helpers to plain
  `memcpy()` with a false "MURAM is cacheable" comment — comment fixed
  (_6b6d9f2_) and call-sites converted (_bad0464_): fm_replic + `fmbm_spliodn`
  use `_fromio`/`_toio` bounces.

- [x] **A62.** cdx RTP-relay opcode wrote truncated 64-bit VAs where the ucode
  expects MURAM offsets — fixed (_dd37089_): convert via
  `MURAM_VIRT_TO_PHYS_ADDR`.

- [x] **A63.** `mc4_exit`/`mc6_exit` leaked every live mcast group on unload —
  fixed (_f9afea9_): teardown extracted to a shared `cdx_mcast_group_destroy()`
  called by both the DELETE arm and a new exit drain.

- [-] **A64.** "insert_*_in_classif_table don't unwind `add_incoming_iface_info`
  on error" — closed (2026-08-20, not a bug): its only success effect is a scalar
  `entry->inPhyPortNum` copy (no alloc/refcount/link); nothing to unwind.

- [x] **A65.** cmm `sa_lock` ABBA inversion — fixed (_6b61392_): `sa_lock` is now
  a leaf taken after the canonical `itf → ct → rt → neigh` chain at every
  multi-lock site (`test_cmm_lock_order.py`). Review residue filed as A69–A73.

- [x] **A67.** `__cmmRouteNew` passed the tunnel's/SA's own family to the
  route-match helpers, so the family filters never fired — fixed (_42379cb_):
  both scans pass the route event's `rtm->rtm_family`.

- [x] **A68.** `__cmmSATunnelRegister` dereferenced `__cmmNeighAdd()`'s result
  with no NULL check (malloc failure crashed the daemon) — fixed (_6b6d9f2_):
  result checked, SA waits for the real neighbor event on failure.

- [x] **A69.** cmm `cmmCtShow` stack overflow: the render offset into the 1024-
  byte stack buffer was never clamped against `snprintf`'s would-be length —
  fixed (_23166a5_): offset clamped after every render call, terminated on error.

- [x] **A70.** cmm zombie SA on flow-update failure — fixed (_ae77bad_):
  `cmmSADelete`/`cmmSASetState` record the failure and still run `__cmmSARemove`
  (safe: `cmmUpdateFlows` unlinks every conntrack first).

- [x] **A71.** cmm `cmmSAFlush` could not report failure — fixed (_42379cb_): a
  per-entry `cmmUpdateFlows()` failure records `rc=-1`, flush still removes every
  entry, keytrack answers FCI_CB_STOP.

- [x] **A72.** cmm sa_table walk without `sa_lock` from the client-daemon thread
  (`cmmCtChange → … → cmmSAFind` racing `cmmSACreate`'s insert) — fixed
  (_42379cb_): `cmmCtChange` takes `sa_lock` (leaf) around the registration.

- [x] **A73.** cmm `cmm_print` called libcli's `cli_vabufprint` on the shared CLI
  handle from four threads unlocked, corrupting the buffer — fixed: the existing
  leaf `logMutex` now spans the whole output block, and is init'd unconditionally
  at startup (was gated on a logfile being configured). Lock-order test green.

- [x] **A74.** `cmmFeReset` dangling holder refs, missing `sa_lock`, fpp-route
  leaks — fixed (_ae77bad_): reset detaches SA/tunnel holders before the drains,
  releases ct/socket fpp-route refs, takes `sa_lock` innermost, `__cmmCtRemove`
  unlinks tunnel-route hash nodes. KASAN-validated.

- [x] **A75.** cmm client error reporting gaps (A55 residue) — fixed (_f9afea9_):
  daemon puts `CMMD_ERR_UNKNOWN` for transport `rc<0`, `cmmSendToDaemon`
  distinguishes msgrcv from `daemon_errno` failure, `getErrorString` names the
  five 32000-range codes.

- [x] **A76.** unbounded local-registration recursion — fixed (_f9afea9_): a
  function-static depth counter in `____cmmCtLocalRegister` saturates at 4
  (safe: `ctMutex` serializes entry). Iterator-invalidation half is residue A79.

- [x] **A77.** RT_POLICY routes escaped `cmmFeReset`'s rt drain — fixed
  (_f9afea9_): the ct drain releases each conntrack's policy-route reference per
  direction, the `rt_table_by_gw_ip` unlink handled inside `__cmmRouteRemove`.

- [-] **A78.** "Whether the forward engine preserves tunnel objects across
  `FPP_CMD_IPV4/IPV6_RESET`" — closed (2026-08-20, not a bug): the reset handlers
  tear down only cts/sockets/routes; tunnels freed solely via `TNL_handle_DELETE`.

- [x] **A81.** cmm `cmmd.h` hard-coded MC error wire values — fixed (_eb594f0_):
  `CMMD_ERR_MC_*` now alias the `FPP_ERR_MC_*` constants so drift is a compile
  error (numerically identical).

- [x] **A82.** cmm `CMMD_CMD_SOCKET_SHOW` missing length check — fixed
  (_eb594f0_): added a `cmd_len < sizeof(*cmd)` guard before the first deref.

- [x] **A83.** cdx `rtp_flow_free`'s NULL-MURAM-handle leak branch is provably
  unreachable (fm0 handle is a write-once init global, non-NULL whenever
  `rtp_info` exists) — invariant documented in-code, no behavior change.

- [x] **A86.** cdx sdk_dpaa `dpaa_submit_{outb,inb}_pkt_to_SEC` rewrote
  `skb->data` in place, corrupting a live tcpdump clone on the offload iface —
  fixed (_99013a7_): `skb_cow_head` before the in-place writes (net-header
  pointer re-derived after; audit-confirmed COW-safe). Diagnostic-only.

- [x] **A87.** cdx sdk_dpaa `dpa_add_dummy_eth_hdr` (cellular offload inbound)
  wrote a dummy Ethernet header into a possibly-shared head — fixed (patch 010):
  `skb_cow_head` before the in-place write (after the existing realloc, no
  double-realloc; audit-confirmed). Same class as A86.

- [x] **A88.** cdx sdk_dpaa `dpaa_submit_inb_pkt_to_SEC` handed Linux a shifted
  `skb->data`/inflated `len` on its post-shift give-to-linux failure returns —
  fixed (patch 010): a shared `err_giveback` path restores data/len (delta form,
  realloc-safe) on all three post-shift returns. Error-path only.

- [x] **A89.** cdx sdk_dpaa enqueue-failure recycled the SGT buffer with a stale
  skb `opaque` + unreleased DMA maps — fixed (patch 010): unmap + clear opaque
  before recycle. Defensive hygiene (audit: opaque was dangling-but-shadowed,
  unmaps no-op on this coherent-DMA SoC); sibling paths → A90.

- [x] **A91.** `ip_output()` ipsec-offload early-return leaked `rcu_read_lock` on
  mainline 6.12.103 (rcu-wraps `ip_output`, unlike NXP 6.12.49) — fixed (patch 030):
  unlock before the offload return. Surfaced by the mainline-regen audit.

- [x] **A92.** `xfrm_output_one()` overflow guard leaked ≤6 `xfrm_state` refs + the skb
  on ≥6-transform bundles — fixed (patch 040): `goto out` → `goto error_nolock`. Latent,
  inherited verbatim from NXP; sibling A94 (async path) left open.

- [x] **A93.** mcast failslab sweeps flaked under KASAN — `fail-nth` counted page-alloc
  faults (`CONFIG_FAIL_PAGE_ALLOC`), burning the sweep window before the cdx allocs —
  fixed (ask.cfg): dropped `FAIL_PAGE_ALLOC` so `fail-nth` counts slab only. A70 residual.

- [x] **A69.** CT register leaked the main-route refs on the tunnel-route failure
  path (`ct_free()` never released the orig/rep `L2_route_get` nbrefs, pinning
  the routes forever), same family as A48/A49/A50 — fixed (_616db95_): new
  `ct_free_unresolved()` releases all four refs; register sites funnel through it.

- [x] **A70.** Intermittent failslab-sweep failures ("never drove <alloc> to
  NULL") — root-caused and fixed (harness-only): the askd-agent's per-request
  flip of the *global* `failslab/ignore-gfp-wait` knob left sweeps running with
  GFP_KERNEL exempt. Fix: set it once at startup, arming read-verifies + fails loud.

- [x] **A90.** A89's SGT-recycle siblings (`dpaa_submit_outb_pkt_to_SEC`,
  `dpa_ipsec_ern_cb`) — fixed (_5dedd89_): outbound mirrors the A89 unwind, the
  ERN cb fully unwinds software SGT FDs; bman-release scrub + bounded walks folded in.

- [x] **A94.** `xfrm_output_one()` async `-EINPROGRESS` exit leaked the collected
  offload vec refs — fixed (_466d0e7_, patch 040); unreachable under valid
  config, hardening only.

- [x] **A85.** Raw kernel `t_Handle`s crossing the FM_PCD ioctl + cdx
  `SET_PARAMS` boundaries — fixed (_6781310_): generation-tagged cookie
  registry in the FMD wrapper, translation on both boundaries (fmc/dpa_app
  unchanged). Folded in from the audit: a MATCH_TABLE_SET heap overflow
  (toothless `ASSERT_COND` → hard reject), the `pcd_handle` fd type check
  (`fm_file_is_pcd`), and a `release_cfg_info` kfree-of-userspace-pointer on
  error unwinds. Residue A102-A104.

- [x] **A80.** mcast REMOVE clear-before-HC-sync leak — fixed (_5261828_):
  pending-free quarantine drained on the next successful sync; DeleteKey gained a
  tri-state so pre-unlink failures leak loudly instead of deferred-freeing live
  chains. Residue filed as A95-A97.

- [x] **A95.** Free-after-failed-DeleteKey on the non-mcast paths (ct_remove,
  socket, rtp, ipsec, l2br) — fixed (_42ad324_): quarantine generalized to
  cdx_ehash.c, a central `cdx_ehash_delete_entry()` owns handle disposition,
  CT gets a no-reoffload latch and the bridge a tombstone on pre-unlink
  failures. Residue filed as A98-A101.

- [x] **A98.** AddKey published the replacement cumulative node before its sync,
  then returned -1 on sync failure — every caller freed the still-linked entry
  (hardware UAF) — fixed (_334bb26_): the add stands (returns the index),
  the replaced node leaks loudly; -1 now strictly means never-linked.

- [x] **A96.** DeleteKey's pre-unlink bails left `EN_INVALID_CUMULATIVE_NODE`
  set on a still-linked node — fixed (_2a13911_): both arms restore the
  flag before returning; the unsynced arms keep it on the replaced (unlinked)
  node, where it belongs.

- [x] **A100.** SA caches walked from atomic context (dqrr `by_fqid`, the
  datapath hook on `by_h`) racing `ctrl.mutex` writers — fixed (_3bc8a5e_,
  a/b/d bullets in _2a13911_): one irqsave `sa_cache_lock` around every list
  mutation and both atomic readers, copy-out before unlock; per-SA skip
  replaces the bucket-wide SA_DELETE abort.

- [x] **A101.** L2 bridge flows leaked on unload (`M_bridge_handle_reset` was a
  stub, `CMD_RX_L2BRIDGE_FLOW_RESET` a no-op) — fixed (_402c01b_): reset
  flushes all buckets via `l2flow_remove()` under `ctrl.mutex`, command wired.

- [x] **A102.** FM_VSP ioctl family leaked/deref'd raw kernel VSP handles over
  /dev/fmX — fixed (_d564bb5_): 9th cookie class `FM_PCD_COOKIE_VSP` through
  the seven VSP verbs; non-Rx `p_fm_tx_port` rejected (A103-coupled). Residue A105.

- [x] **A104.** `cdxdrv_set_miss_action` fed CC-node (EXACT_MATCH) handles to the
  hash-only `FM_PCD_HashTableModifyMissNextEngine` (wrong-offset near-NULL MMIO
  read, exercised for any PCD with CC-nodes) — fixed (_876d051_): skip non-hash
  `dpa_type`s via the `get_cctbl_info` predicate.

- [x] **A105.** Six `LnxwrpFmPcdIOCTL` arms (VSP `INIT`/`FREE` +
  `FM_PCD_IOC_FRM_REPLIC_GROUP_DELETE`, compat+native each) returned `E_OK` on a
  `copy_from_user` fault (bare `break` → E_OK tail) — fixed (_1d21c8f_): all
  now `RETURN_ERROR(MINOR, E_WRITE_FAILED, NO_MSG)`, whole class closed.

- [x] **A99.** Re-add-after-failed-delete duplicate-key residuals (socket v4/v6,
  RTP, ipsec) — fixed (_ceaa861_): v4/RTP/ipsec capture the delete rc and
  refuse the re-add on hard FAILURE (tombstone for retry); v6's make-before-break
  keeps its intentional transient duplicate, logging a failed trailing delete
  without failing the command.

- [-] **A97 (not a bug).** `cdx_delete_mcast_group_member` returning NO_ERR on
  `cdx_mcast_group_destroy`'s hard-FAILURE arm is by design — that arm is the
  accepted A95-class leak (abandoned + logged loudly) and the group is already
  software-gone, so an error return buys nothing but a compounding retry.

- [x] **A106.** Late CDX SET_PARAMS failures leaked queues, interfaces, policers and statistics —
  fixed (_2cf97d1_): stop producers, drain queues and unwind dependents; 15 KASAN hardware checkpoints pass.

- [x] **A66.** Route-event retries reused rolled-back tunnel/socket/SA bindings and stale next-hops —
  fixed (_1e02d82_): retry through route-swap transactions; host faults and six hardware recovery cases pass.

- [x] **A107.** SA deletion and hard expiry retained the last FPP route —
  fixed (_81155da_): detach flows and delete the SA before its counted route; use CDX for expiry route deletion.

- [x] **A108.** Partial SDK `SetPcd` failures pinned classifier bindings —
  fixed (_cf1e3a7_): unwind completed stages and failed classification-plan acquisition.

- [x] **A109.** Forced CEETM draining discarded descriptors and leaked buffers —
  fixed (_cf1e3a7_): preserve portal results and reclaim every returned FD in CDX.

- [x] **A110.** Interface removal freed TX FQs during asynchronous retirement —
  fixed (_cf1e3a7_): drain every queue and finish callbacks before destroying storage.

- [x] **A111.** Public SDK PCD setup/delete leaked locks and ownership on errors —
  fixed (_9a15ccf_): track completed acquisitions, preserve unfinished cleanup and balance retries.

- [x] **A112.** SDK port destruction dereferenced discarded initialization parameters —
  fixed (_8f1063b_): retain charged dequeue depth and release successfully acquired FM resources once.

- [x] **A113.** Whole-tree replacement leaked bindings and omitted PCD locks —
  resolved (_37534e1_): remove the implementation; retain APIs/ioctl numbers with explicit unsupported errors.

- [x] **A114.** Reassembly scheme teardown retained stale handles and hid failures —
  resolved (_1685a5a_): remove unsupported SDK/ASK reassembly; reject creation and attachment at API/ioctl boundaries.

- [x] **A115.** FM port allocation left partial charges and locked error exits —
  fixed (_ee9e210_): validate before committing resources; serialize updates and preserve failed FIFO resize state.

- [x] **A116.** Scheme deletion discarded live software ownership before hardware success —
  fixed (_42c8b34_): preserve refused/failed deletion state; commit once and retire the scheme lock atomically.

- [x] **A119.** Public KG scheme flags used the SDK layout and mishandled cookies/missing netenvs —
  fixed (_bada8ce_): translate kernel/fmlib flags and validate before mutation; native/compat and KASAN lifecycle tests pass.

- [x] **A117.** SDK HC failures recycled hardware-owned frames —
  fixed (_bd99777_): separate acceptance/completion, quarantine timeouts and require board reset; guard pool/PCD recovery.

- [x] **A118.** Scheme creation/modification published partial state on failure —
  fixed (_12f7318_): program a locked private candidate and commit netenv ownership only on success; host/KASAN tests pass.

- [x] **A120.** FORTIFY rejected intentional kernel/fmlib scheme-tail copies and an oversized compat union copy —
  fixed (_5326829_): copy through enclosing objects with correct bounds; real ARM64 FORTIFY/`-Werror` and 30 host tests pass.

- [x] **A121.** Forwarding TX queue teardown volatile-dequeued through a NULL callback —
  fixed (_86326e5_): register a drain-only callback; native descriptor/empty-completion tests cover 8 and 16 queues.

- [x] **A122.** CEETM fallback drains retried forever and one failure force-popped later queues —
  fixed (_555acd9_, _7636537_): bound each drain, retain failed CQs/device refs for retry and guard late NULL-device skb notifications.

- [x] **A123.** CDX/FMC setup and cleanup forced port enable state or left the Linux path stopped —
  fixed (_555acd9_, _7636537_): query/save/restore actual state; detach failed PCD before rollback and preserve initially down ports.

- [x] **A124.** Legacy SDK root retargeting could corrupt external-hash ownership —
  resolved (_555acd9_): reject both SDK entry points and fmlib; the native/compat ioctls were already blocked.

- [x] **A125.** Scheme publication could overwrite dynamic owners; failed create locking could clear another operation —
  fixed (_555acd9_): publish under the scheme spinlock and acquire the operation flag atomically; userspace was already serialized.

- [x] **A126.** Missing SDK sources silently skipped host regressions and EQCR lacked UBSan halt-on-error —
  fixed (_555acd9_): fail missing dependencies explicitly and enable the same sanitizer environment for EQCR.

- [x] **A127.** The fmlib scheme serializer depended on an unchecked cross-struct tail layout —
  fixed (_555acd9_): add a compile-time layout assertion alongside the enclosing-object FORTIFY copy.

- [x] **A128.** Compat hash copy-out failures leaked cookies and busy deletes discarded mappings —
  fixed (_555acd9_): release failed creations and retire mappings only on the last accepted delete; shared aliases remain valid.

- [x] **A129.** Normal CDX unload omitted PCD queues and private/shared policer cleanup —
  fixed (_555acd9_, _7636537_): quiesce before subsystem teardown and release resources before FMAN metadata; host retry and KASAN unload checks pass.

- [x] **A130.** FM_PORT_SetPCD dereferenced a missing netenv —
  fixed (_555acd9_): reject NULL before locking or mutating port state; RX/offline host cases pass.

- [x] **A131.** The loader shifted signed 1 by an unchecked config port ID —
  fixed (_555acd9_): reject IDs outside the bitmap and use `1U`; boundary tests include bits 0/31 and invalid 32.

- [x] **A132.** Bridge command allowlist reasons and CMM help described nonexistent behavior —
  fixed (_555acd9_): describe actual fixed-buffer reads and remove the nonexistent set-ipsec branch.

- [x] **A133.** Terminal port and QoS retries held RTNL throughout hardware-fault waits —
  fixed (_3d412fe_).

- [x] **A134.** Detaching an initialized port without PCD made rollback and unload fail —
  fixed (_3d412fe_).

- [x] **A135.** Tunnel-decap stats pointers were shifted and the DSCP display was false —
  fixed (this commit): serialize/decode the whole BE word; DSCP enable encoding was already correct on ARM64.

- [x] **A136.** Tests mistook combined netdev statistics for software counters —
  fixed (this commit): use SDK ethtool software RX plus delivery; retain totals for accounting and preserve capture names.

- [x] **A143.** Enabling QoS drove the excess rate of an already-shaped channel to
  zero, starving every class queue on it —
  fixed (this commit): hold the excess rate in `shaper_info` so all five programming sites pass the same value.

- [x] **A144.** Disabling QoS left the LNI shaper enabled, so a port could only ever be
  enabled once; the second attempt failed inside `ceetm_setup_lni` with the port half committed —
  fixed (this commit): disable the shaper on the way out, which is what makes a qdisc rebuild or a QOSENABLE toggle work.

- [x] **A145.** `cpe_fp_tx()` confirmed on a frame queue chosen by class-queue id rather than
  by sending Tx queue, so every DSCP-classified frame confirmed on `conf_fqs[0]` whichever core sent it —
  fixed (this commit): index by `skb_get_queue_mapping()`, which is what the non-CEETM branch already used.

- [x] **A147.** Ingress policer rates had no surface in flowtable mode (the FCI
  family that reaches them is sealed and its only client does not run there) —
  fixed (this commit): `tc action police` offloads via `TC_SETUP_BLOCK`, `matchall`
  onto the port profile and `flower` onto the seven per-flow profiles, bound to
  flows at admission; the per-flow path was also discarding the caller's burst.

- [x] **A146.** The libnetfilter-conntrack ASK patches still declared `ATTR_QOSCONNMARK`,
  `CTA_QOSCONNMARK` and their build/parse/copy/compare/print helpers, mirroring a kernel
  attribute that no longer exists, which made it look as though rebuilding cmm with
  `-DUSE_QOSCONNMARK` would still work —
  fixed (this commit): both patches regenerated against their upstream tags with the QoS
  hunks dropped, verified by applying each to a pristine tree and diffing the result.

- [x] **A153.** Counter-enabled flowtables were refused, which refuses every flow under the
  configuration consumers ship — OpenWrt renders `counter` unconditionally —
  fixed (this commit): `ft_l2_overhead()` restates each delta in Netfilter's units.

- [x] **A152.** The adapter refused a third binding (`ft_bound >= 2`, the proof of concept's
  acceptance limit), and invalidation snapshotted bound devices into a two-element array —
  fixed (this commit): both sized by `CDX_FT_MAX_BINDINGS`, asserted equal to `MAX_PHY_PORTS`.

- [x] **A151.** The DSCP egress map was unreachable on both paths: the hardware enable tested the
  whole `qosmark` word, which `cdx_ft_hw_add()` never leaves zero because it always raises
  `iqid_valid`, and the software branch tested `pfe_eth_get_queuenum()`, which answers
  `QOS_DEFAULT_QUEUE` for an unmarked frame —
  fixed (this commit): the hardware enable reads the egress nibbles only, and the software path is
  served from `ndo_select_queue` off the same published table rather than from `dpa_tx()`.

- [x] **A149.** `ceetm_get_egressfq()` ORed the class-queue policer's profile number into the
  shared `qman_fq`'s own fqid, where the clearing branch could not undo it and the software Tx
  path would have enqueued to it — the DSCP map stored the pointer from one call and the value
  from the next —
  fixed (this commit): the fqid is composed by value in `ceetm_egress_fqid()`, the lookup no
  longer writes, and one channel resolver serves both readings. Was filed as a second A141.

- [x] **A148.** Unload left the flow_block_cb of a direct bind in a live flowtable, so the next
  offload work called freed module text (`flow_offload_work_handler` oops) — latent since the
  driver grew an `ndo_setup_tc` and `flow_indr_dev_unregister()` unwinds only indirect binds —
  fixed (this commit): drain the driver block list on exit under each table's `flow_block_lock`.

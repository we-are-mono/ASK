# AGENTS.md

ASK is an NXP LS1046A packet-offload stack using DPAA1/FMAN hardware classification
(ASK microcode v210.10.1, loaded by U-Boot; USE_ENHANCED_EHASH external hash tables
in DDR). Offload runs through **Linux flowtables**: `cdx.ko` is the load-once
hardware bring-up, `ask_flowtable.ko` the reloadable flowtable adapter, driven by the
default-on userspace daemon `ask-flowtable`. Production ships on Armbian and OpenWrt;
`meta-ask/` is the TFTP-booted test image. The old CMM/FCI control plane is retired.

## Reference implementation

The original NXP ASK sources show how the stack was first designed. Use them for
intent and data flow, but they target kernel 5.4 and carry a lot of dead code: where
they conflict with modern kernel APIs or clean design, prefer the modern approach.

## Working style

- **Implement the full solution, not a minimal slice.** Agents aren't bound by human
  timelines: if a fix spans N files or a feature needs the whole data path wired up,
  do all of it.
- **Fix root causes, never workarounds.** This code ships to millions of devices —
  production-quality fixes only. Prefer bounded-retry / fail-loudly over
  remove-the-wait; preserve safety invariants; make structural changes rather than
  skipping a safety mechanism. Flag known risks (UAF, deadlock) and ask before
  committing an uncertain-shape fix.
- **Failing-test-first** for any testable fix: write the regression test, confirm it
  FAILS on the unfixed tree, then fix, then confirm it passes. (Exempt: pure
  refactors, docs, hardware-only behaviour with no harness hook.)
- **Analyze actual errors; don't assume or parrot.** Read error output literally,
  trace the real call chain. Treat claims in the user's own prompt as hypotheses to
  verify, not facts to copy into plans/commits.
- **Trace ≥3-4 layers before scoping a feature gap.** On cdx/FMAN, default to
  "config + test-setup gap" over "implementation gap"; cross-check the NXP reference
  early — same shape there means it is not our regression.
- **printk liberally while hunting** (many at once, whole suspect path incl. "did we
  even get here" beacons; greppable markers). Remove when fixed; propose surviving
  sites as permanent ASK-DEBUG (`ask_dbg()`/`ask_refuse()` in `cdx_flowtable_backend.h`,
  knob `/sys/module/cdx/parameters/ask_debug`) — but ask before adding it.
- **Manual before scripts.** Drive the rig one short command at a time, reading each
  result; script only a sequence already proven manually, and only for scale.
- **Treat compiler warnings as errors** — keep builds warning-free.
- **Plow through plan stages** end-to-end; don't pause at a *successful* stage
  boundary for a go-ahead. Interrupt only for a genuine fork, stating a
  recommendation.
- **Defects the flowtable port introduced are ours to fix now**, not to defer. Before
  calling anything "pre-existing", verify provenance (`git log -S`,
  `git merge-base --is-ancestor`): it must predate the port, not just the increment.
- **Runtime recovery without reboot is a baseline requirement** — tunnels, SAs, FQs,
  pools must tear down and re-establish via control-plane verbs (`swanctl`,
  `ip xfrm ... flush`, reload), never a power-cycle. No "reboot required" latches.
- **Consumer packaging decides the control-plane verb** — go check what OpenWrt
  (fw4/nftables, kmod bundles) can actually ship before choosing. Answer consumer
  questions assuming the post-CMM world (no owner-selection caveats).
- **Don't file defense-in-depth / confirmation steps** on trusted dormant paths as
  tracked issues.
- **Tools:** edit files with an edit tool, never `sed`/python rewrites — one bounded
  exception: `sed -i 'A,Bd'` / `unifdef` for grep-verified contiguous dead NXP C
  blocks. Search with `rg` (ripgrep), never `grep` (except on the DUT if it lacks rg).
- **Delegated work:** the coordinating session plans and verifies; delegated
  (sub-)agents **never touch the DUT** (no UART, no test runs, no KASAN sweeps, no
  reboots, no agent HTTP) — all hardware is the coordinating session's job.
- **Bug handling:** when a test surfaces a suspected kernel/userspace bug (not a
  harness issue), have an independent reviewer confirm it IS a bug from the code paths
  and first principles before fixing. After fixing, a second independent review signs
  off that it addresses the root cause, preserves other call-site invariants and opens
  no new path to the same class of bug. Adjacent pre-existing issues the review finds:
  fix small obvious ones in place; otherwise file an ISSUES.md entry (where, why it
  matters).

## Build & deploy

- **Build only through kas/Yocto** (`meta-ask/.config.yaml`): the kernel (v6.12.112 +
  `patches/kernel/`), cdx, ask_flowtable and the flowtable daemon. Never raw
  `bitbake`, never standalone `make modules` / GCC-15 recipes — those use different
  toolchains/defines and don't prove the shipped build is clean. A GCC 15 cross
  toolchain is fine for compile-only warning checks; it isn't a build.
- **Always build the KASAN image** (`make ask-image`, or `KASAN=1` on a direct
  `kas build`). DUT tests require it: the conftest preflight refuses a kernel without
  `CONFIG_KASAN=y`. KASAN never explains low throughput — offloaded frames bypass the
  CPU, so there is no instrumented code on that path. A number far below line rate
  means **offload isn't active** (check `bindings` in `/proc/ask_flowtable/status`,
  the rule carries `flags offload`, `flows` rows present) — not KASAN.
- Make targets: `setup` (host deps, one-time sudo), `ask-image`, `stage-image`,
  `deploy-agents`, `test-env`, and the test targets under **Testing**.
- **After every successful build run `make stage-image`** — it copies the image and
  the DTB into `TFTP_ROOT` (`build/deploy.mk`), which U-Boot fetches; without it the
  next boot silently loads the previous image. Run it **unpiped** (a pipe into `tail`
  masks failure and leaves the stale image) and assert a build marker (`pr_info` at
  module init) in dmesg after boot.
- Redirect build output to a log file **outside the checkout** — an untracked file in
  it changes the checkout fingerprint that release preflight compares.
- The test image is **TFTP-booted** by U-Boot, never flashed (`docs/testing.md`,
  "Booting the image"). The KASAN initramfs is large (~360 MiB uncompressed) and needs
  high load addresses. rootfs is initramfs — every reboot wipes `/etc` and `/tmp`.
  `meta-ask` is test-only and may carry KASAN/lockdep/kmemleak unconditionally.
- Don't poll a backgrounded build with `pgrep -f "kas build"` — it matches its own
  shell and never exits. Use a `[k]as build` pattern or the completion notification.

## Kernel patches

- **`patches/kernel/*.patch` is the single source of truth**; any kernel checkout is
  only a place to regenerate from. The series order is the explicit per-patch
  `SRC_URI` list in `meta-ask/recipes-kernel/linux/linux-ask_6.12.bb` — hand-edit it for
  every new patch (old `0*`/`0[1-9]*` globs silently dropped patches numbered ≥100).
- **Changing a patch:** in a scratch clone, check out the base — the recipe's
  `KERNEL_SRCREV` (v6.12.112) with the NXP SDK overlay at `pins/nxp-sdk-srcrev.inc`
  applied as `do_overlay_sdk` does. `git am` the current series in `SRC_URI` order,
  change the patch's commit (fixup + `git rebase --autosquash`), regenerate with
  `git format-patch --no-numbered` (subjects stay `[PATCH] subsystem: …`; the filename
  prefix carries order), confirm the whole series applies to a fresh base, then build
  with kas.
- Patches are organized **per-concern, not per-fix-site**: when a new bug fits an
  existing patch's concern (another iomem mem-op crash → extend 095, another lockdep
  nesting site → extend 092), add a hunk to that patch. New numbers are for *distinct*
  concerns, and filenames name the concern (`095-sdk_fman-iomem-mem-ops.patch`), not
  the first site that hit it.

## Git, commits and releases

- **Branches and tags follow the kernel line** — ASK is coupled to its kernel (patch
  series, NXP SDK pin, cdx↔hook ABI), so a kernel line is the unit of release:
  - `master` is the development branch and stays releasable. Work on short-lived
    branches off `master`, test, merge back.
  - `mt-<line>.y` (`mt-6.12.y`, later `mt-6.18.y`) is a line's release branch. It only
    fast-forwards to each new release tag of its line. **Never commit to it directly.**
  - Releases are annotated tags `mono-X.Y.Z` on the release commit. The major names the
    kernel line (1.x = 6.12, 2.x = 6.18); a stable bump within a line is a patch
    release. A pushed tag never moves.
  - A new kernel line is ported on a topic branch (e.g. `kernel-6.18`) and merges into
    `master` only at parity (full suite green). Its first release is X.0.0 and cuts
    `mt-<line>.y`. From then on the previous line's fixes go on a branch off its
    `mt-<line>.y`, are tagged there, and are forward-ported to `master` where they
    apply. A line retires when the fleet's OpenWrt leaves its kernel.
- CMM, FCI (with libfci) and auto_bridge are gone from the tree; their sources live on
  in the `mono-1.0.x` tags (`git show mono-1.0.7:cmm/src/module_ipsec.c`). Docs citing
  `cmm/`, `fci/` or `auto_bridge/` paths refer to those.
- **No `Co-Authored-By` or any Claude/Anthropic/AI references** in commit messages.
  **No word "agent"** describing process (say "audit"/"review"); real components named
  with "agent" (askd-agent, ask-test-agent) stay.
- **No work-phase identifiers** (`phase2`, `item_3b`) in filenames, runtime paths
  (`/tmp/ask_mcast_*`, not `/tmp/ask_3b_*`) or code comments — name things by what
  they do. No session-local labels ("Bug A") in shipped code.
- **No SPDX/copyright headers on Python** test/tooling files (docstring OK); kernel C
  and NXP-origin files keep theirs.
- Keep commit bodies **≤20-25 lines**, bullets, "why" not process narration; no
  "Follow-up:" paragraphs.
- **Never amend pushed commits** (new commit instead); amend/soft-reset is fine on
  unpushed work. Commit **once an investigation concludes**, not per step.

## ISSUES.md

- **Closed entries are 1-2 lines, hard cap:** what it was + the verdict + the commit
  ref (`_hash_`). All mechanism, proof and validation detail lives in the commit; if a
  close seems to need a third line, that goes in the commit message.
- Open entries keep their full actionable body.
- Commit the ISSUES.md update **in the same commit as the fix**, never a follow-up.

## Testing

`docs/testing.md` is the reference: topology, what each node needs, harness
configuration and invocation. Bench-specific settings (addresses, serial devices, LAN
VM and NIC) go in the gitignored `.ask-test.mk` (start from `.ask-test.mk.example`).

- **Topology** (generic in code): `lan` = traffic client VM (libvirt, driven over its
  QEMU guest agent) behind the DUT's NAT; `target` = the DUT; `wan` = WAN host,
  pytest orchestrator and TFTP server. Board defaults: `eth4` = WAN, `eth3` = LAN.
- **Targets:** `make test` (host + DUT suites; `ask-test` is an alias), `test-host`,
  `test-dut`, `test-startup`, `test-release RUN=…` (one release-matrix run, recorded in
  the ledger) and `release-status`. Select with `K='ipsec or mcast'`; `ARGS=` adds
  pytest options. Paths in `ARGS`/`ASK_TEST_ARGS` **add** collection targets, they
  don't filter — use `K`. `WAN_IP` sets both `ASK_WAN_IP` and `ASK_WAN_IPERF_IP`; if
  the WAN host's address is dynamic, re-check it before a run, or tunnel/iperf tests
  hang.
- **Run one file directly** with pytest (`-c tools/pyproject.toml`, `PYTHONPATH=tools`,
  sudo, the runner venv under `WAN_PREFIX`). Direct pytest needs exported `ASK_*`
  variables; it does not read `.ask-test.mk`.
- **Scope runs to the change.** Run only the tests that pertain to it, never the full
  suite in an iteration loop. The full suite belongs before a release, but it isn't
  mandatory there: when it passed recently and the work since then confidently can't
  have broken anything outside its scoped tests, the release can go without it.
- **Stop at the first failure.** The runner doesn't fail fast by default
  (`tools/pyproject.toml` has no `-x`); pass `ARGS=-x`, full suites included, then fix,
  clean up leftovers and rerun. Stop a run with **one** SIGINT and wait, so fixture
  teardown runs; a second one leaves rig state behind. If a release-matrix entry fails
  after the suite passed, fix and rerun that entry only.
- **Never reboot between tests.** Boot once per *image*. After resilience tests, remove
  test-owned faults and restore the normal policy on the same boot, so accumulated
  state and counters keep later failures observable; record any separate recovery
  reset and why. A failure that appears only on a same-boot rerun is a
  teardown/deregistration bug to fix (leaked binding, stale baseline, orphaned nft
  table/route/netns). Asserting absolute zeros on `/proc/ask_flowtable/stats` (only
  ever grows) is a test bug — baseline in the test. `invalidated 1` at idle in
  `status` is a benign lazy latch cleared by the next bind; clean slate =
  `entries == 0 && bindings == 0 && fatal == 0`.
- **QoS rate tests** target ~2 Gbit/s with offered load well above the cap: below the
  ~9 Gbit/s line rate and above software forwarding capacity, so throughput near the
  cap proves both enforcement and hardware forwarding. Keep the hardware admission and
  counter checks too.
- **Warm up** before a run: ping LAN→WAN from the client once (post-boot ARP can be
  FAILED, forwarding still settling) and wait for a reply.
- **UART is one-reader-only.** The suite's session owns the DUT console;
  `Console.target()` borrows that session, so never open a second reader (kill any
  background `cat` of the tty first). Tee long runs to a durable log path and announce
  it up front so the user can `tail -f` it.
- **LAN-side scripting** via QGA: `lan_run_python(lan, script, label=…, timeout=…)`
  (`tools/tests/_topology.py`) sends compressed source and checks completion;
  independent LAN commands may run concurrently. Background LAN traffic uses bounded
  processes coordinated through files or local Unix sockets. Push files over a console
  with base64 (`echo <b64> | base64 -d > f`), **never heredocs over UART**.
- **DUT agent** (`askd-agent`) runs over the shared serial session
  (`tools/ask_orch/client.py`): the UART, or USB CDC-ACM with `ASK_TARGET_AGENT_DEV`.
  The DUT opens **no** test-control network listener (`S70askd-agent` only retains
  boot kernel evidence); HTTP `:9110` is the WAN agent's only. `ASK_TARGET_IP` is the
  DUT's traffic address, not a control endpoint. `exec` is argv[0]-allowlisted (`ip`,
  `ethtool`, `nft`, `sysctl`, `tcpdump`, `conntrack`, `bridge`, `insmod`/`rmmod`/…) — no
  `sh`, but `["ip","netns","exec","<ns>","sh","-c",…]` gives a shell *in that netns*
  (fine for dmesg/proc/kill; **run `nft` via plain exec, not netns-wrapped** — nft is
  netns-scoped). Also `fs/read` (hex), `fs/write`, `kmemleak-*`, `health`.
- **Goldens** (`tools/tests/golden/`): `cdx_abi_snapshot.json` regenerates with
  `ASK_REGEN_ABI_SNAPSHOT=1` (**never in CI** — a regression would be silently
  overwritten); `dmesg_allowlist.yaml` is hand-written, every entry a pattern plus a
  reason.
- **Killed runs leave state**: `nf_flowtable_{tcp,udp}_timeout=5`, nat POSTROUTING
  rules, `/32` host routes (DUT and orchestrator), orphaned `smcrouted`, nft tables.
  Restore before rerunning. The agent `sh()` helper runs in an `askshell` netns — its
  sysctls/`/sys` are that namespace's; read init_net via `fs_read('/proc/sys/...')`.
- **FMAN XML edits** (`cdx_sp.xml`, `cdx_pcd.xml`) are allowed but break far-away paths
  more often than not — prefer doing parser/classifier/keying work in **C**; gate any
  XML change on a broad rig run (hairpin v4/v6, VLAN, PPPoE, IPsec, multicast, failslab).
- **Never `ethtool` a wedged port** — it hard-locks a CPU under RTNL. Diagnose with
  `ip -s link`, `tcpdump -w` under `timeout`, `/proc/interrupts`,
  `/proc/ask_flowtable/`, and serial-break sysrq (`send_break`, then `8`,`w`,`t`,`l`;
  `s`,`b` resets).
- UART quirks: drive **U-Boot with `\r`**, not `\n`; send `\x03` yourself to a wedged
  prompt (`Console.send("\x03")`). Lockdep can be silently off — before trusting a
  KASAN run check `/proc/sys/kernel/printk == 5 4 1 7` and no `WARNING:` in dmesg.
- Bridging a port that carries the DUT's management address cuts the agent — move the
  address over to the bridge on the serial console, and make the fixture self-healing.

## Architecture quick-reference

- **Modules load once at boot.** `cdx.ko` stays loaded for the system's life (no
  supported unload; init-error paths are validated by KASAN + code review, not
  rmmod/failslab). `ask_flowtable.ko` is the reloadable adapter (restart tests reload
  it).
- **SDK staging drivers, not mainline:** FMAN/QMan/BMan/DPAA come from
  `drivers/staging/fsl_qbman/` and `drivers/net/ethernet/freescale/{sdk_dpaa,sdk_fman}/`
  — NOT `drivers/soc/fsl/qbman/`. A probe added to the mainline path compiles but never
  fires (wrong TU linked). Verify with `strings` on the image.
- **Offload keys on the physical ingress port** (`port_idx` + `portid` + 5-tuple), not
  the logical L3 iface; a VLAN on a vlan-aware bridge (`br-lan.N`) has no single physical
  parent, so cdx uses a physical-port fallback. Debugging gauge: watch a tuple's
  `packets=` in `/proc/net/nf_conntrack` — **frozen = hardware-offloaded**, climbing =
  software (CPU, shows as softirq/ksoftirqd).
- **CDX OH portid chain:** `number` = DT `cell-index`, `portid` = the flat logical index
  the soft parser reads as `$logicalportid` (**OH ports must be ≥9**; gateway-dk ships
  9/10). The formula is SoC-derived and the whole configuration is derivable from the
  DT (optional override `mono,cdx-logical-portid` on the MAC / dpa-oh nodes) — do not
  reintroduce per-board config files.
- **OH ports:** FMAN declares six; CDX permanently claims two (PORT_TYPE_IPSEC,
  PORT_TYPE_WIFI) + the PCD host-command port; `0x5/0x6/0x7` are spare. The limit is the
  board DTS, not silicon. Idle MACs are a different port type and can't be repurposed.
- **ehash:** external hash table bucket = `crc64_ecma_reflected(key)` folded. Fills that
  vary only one 16-bit port field never crowd a bucket (CRC is affine); for crowded-bucket
  / delete-path tests use `crowded_ipv4()` in `tools/tests/_ehash_bucket.py`.
- **SEC descriptor identity = address + frame ICID** (RM §7.3.2); one SA must map to one
  descriptor, so zeroed FMan-port ICIDs reuse ESP sequence numbers (peer drops as
  replay). GCM hardware offload works (SERIAL sharing without SAVECTX + per-job PDB
  store) and is faster than CBC+HMAC. GMAC offload is **refused** (`EOPNOTSUPP`,
  nothing installed; SEC GMAC ICV limitation, `cdx/ask_flowtable_ipsec.c`): add GMAC
  SAs without offload. For replay/dup-seq symptoms check ICIDs first.
  Operational: a one-ended SA reinstall reusing the SPI rewinds ESP seq → reset both
  peers together or use fresh SPIs.
- **Classifier MTU is the outer one** — a to-SEC/tunnel direction must be programmed
  with the egress **port** MTU (microcode adds the tunnel expansion before comparing),
  never the Netfilter flow MTU; getting it wrong silently excepts full-size frames to
  the CPU (a rate-only degradation — oracle: `tx toenc`).
- **Flow counters:** hardware per-entry counters are **L2-inclusive classifier hits**;
  `ft_l2_overhead()` restates them into Netfilter's post-decap units. `ip -s link` /
  `/proc/net/dev` on a port or VLAN/ppp device **include** offloaded traffic; `ethtool -S`
  is driver-software-only — `ip -s` minus `ethtool -S` = hardware-forwarded packets
  (`docs/flowtable/statistics.md`).
- **Statistics surface through standard tools only** — `ethtool -S`, rtnetlink
  (`ip -s link`), procfs. `/proc/ask_flowtable/` (`status` levels, `stats` counters,
  one row kind per file; reference `docs/flowtable/procfs.md`) is the diagnostic beside
  them. Never a private socket or an ASK-only binary as the sole door (an `ask`
  presentation layer over them is fine).
- **Classifier is built in-kernel:** `cdx` constructs the PCD at module init
  (`dpa_app`, `fmc` and `fmlib` are retired). `cdx/cdx_softparse.h` and
  `tools/host_tests/golden/cdx_pcd_model.json` are the source of truth; regenerating
  them means rebuilding host-mode fmc from the `mono-1.0.x` tags
  (`docs/in-kernel-pcd.md`).
- `mac_dev->fm_dev` is the Linux wrapper carrying `h_PcdDev`/`h_MuramDev`; `mac_dev->fm`
  is the bare FMD object — casting `->fm` to the wrapper compiles but yields NULL
  handles. Use `->fm_dev`.
- **Tunnel offload:** only **6o4 (`sit`) and 4o6 (`ip6tnl`)** are in scope
  (EtherIP/GRE-over-IPv6/MACVLAN out); flowtable kernel hook `patches/kernel/143-*`;
  the outer header carries no DF (hardware limit, don't retry). **Routed multicast** is
  an in-kernel learner on the FIB notifier chain (IPMR/IP6MR MFC events) feeding the
  same encoder as bridged MDB; no ASK userspace (consumer runs smcroute/igmpproxy/omcproxy).
- clsact's **egress** mini-Qdisc has `block == NULL`; get a device's tc filter block via
  the qdisc (`cl_ops->tcf_block`), and model that asymmetry in host harnesses. CEETM/qdisc
  teardown must stay symmetric or egress wedges silently.
- **CMM = Conntrack Management Module** (bridged netfilter conntrack → FCI classifier).
  Retired: the image is flowtable-only (no `ask.offload=`, no `offload_owner`).

## Project state (durable bits)

- Most of the old CMM backlog was **never actually offloaded under CMM** (tunnels, RTP,
  Wi-Fi, sockets dormant); only statistics was live. Don't re-infer scope from test
  surface or from features used.
- A delivered offload feature is proven by a line-rate run with offload confirmed
  active.
- OpenWrt integration = **ASK declares the flowtable**: the `ask-flowtable` package runs
  the C daemon, and a fw4 patch marks both `flow_offloading` options unsupported so fw4
  never declares a second one. The fw4-owns-the-table route was abandoned
  (`docs/flowtable/qos.md`, "Resolved by patching fw4, not by ASK").
- Wire→Wi-Fi ceiling is **~654 Mbit/s** (VHT80 2x2 air, not a driver wall) once offloaded
  on a non-debug kernel.

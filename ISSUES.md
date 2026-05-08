# ASK Kernel-Module Security & Memory-Safety Issues

Working list from the security review of `cdx/`, `fci/`, and `auto_bridge/`.
Entries are short by design — each fix's reasoning lives in the commit
referenced as `Fixed: <hash>`. Read the commit message for context.

**Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` wontfix/not-a-bug

---

## Gating

- [x] **G1. `/dev/cdx_ctrl` ioctl had no capability check.**
  [cdx/cdx_dev.c:110-140](cdx/cdx_dev.c#L110-L140). Unprivileged users could reconfigure the DPAA datapath. _Fixed: 815a0ca_ — `CAP_NET_ADMIN` gate on the dispatcher.

- [x] **G2. Racy single-open gate.**
  [cdx/cdx_dev.c:48-56](cdx/cdx_dev.c#L48-L56). `atomic_dec_and_test` + `atomic_inc` was check-then-act with a transient mis-rejection window. _Fixed: 815a0ca_ — `atomic_cmpxchg(1→0)`.

---

## CRITICAL

Memory corruption or info-leak reachable from userspace.

- [x] **C1. Netlink attr length trusted as memcpy size (auto_bridge).**
  [auto_bridge/auto_bridge.c:540-544](auto_bridge/auto_bridge.c#L540-L544). `nla_len` controlled the memcpy into a 16-byte stack union. _Fixed: 815a0ca_ — `nla_policy[]` for L2FLOWA_*.

- [x] **C2. FCI netlink message — no length validation.**
  [fci/fci.c:417-475](fci/fci.c#L417-L475). Short `nlmsg_len` + large `fci_msg->length` → OOB read. _Fixed: 815a0ca, corrected in 0a8a5f6_ — gate on `skb->len`, not on the sender-supplied `nlmsg_len`.

- [x] **C3. Reassembly trusts hardware-sourced `num_entries`.**
  [cdx/cdx_reassm.c:141,163-189](cdx/cdx_reassm.c#L141-L189). Loop walked `list` past the pool on malformed frames. _Fixed: 815a0ca_ — bound against `reassly_bp->size`.

- [x] **C4. Reassembly refcount is `uint8_t` with no underflow guard.**
  [cdx/cdx_reassm.c:157,163](cdx/cdx_reassm.c#L157-L163). Wrap to 255 on double-decrement. _Fixed: 815a0ca_ — zero-guard before decrement.

- [x] **C5. IP reassembly deinit was a stub.**
  [cdx/cdx_reassm.c](cdx/cdx_reassm.c). `printk("implement this")` while `ipr_timer` kthread kept running → UAF on unload. _Fixed in stages:_ 815a0ca (kthread stop), b5a7bf8 (bpool free + hook unregister), 78ac2af (FQ retire/oos/destroy + fqid range release via private `ipr_fqs[]` tracking).

- [x] **C6. Integer-scaled allocations driven by userspace (dpa_cfg).**
  [cdx/dpa_cfg.c](cdx/dpa_cfg.c). `sizeof(...) * num_fmans/max_ports/max_dist/num_tables` with attacker-influenced counts. _Fixed: 815a0ca, corrected in 0a8a5f6_ — sanity caps + `kcalloc`; legitimate zero counts allowed for unused-resource sub-structs.

- [x] **C7. Off-by-one `fm_index` checks.**
  [cdx/dpa_cfg.c:367,993,1008,1022,1035,1048](cdx/dpa_cfg.c#L367). All six `> num_fmans` flipped to `>=` in _815a0ca_.

- [x] **Bonus. Pre-existing modpost section mismatch.**
  `cdx_ctrl_deinit` (.text) called `cdx_cmdhandler_exit` (.exit.text). _Fixed: 815a0ca_ — dropped `__exit`.

- [x] **C8. Unbounded user-controlled array indices.**
  [cdx/dpa_cfg.c](cdx/dpa_cfg.c) `queue_no`, `port_idx`, [cdx/cdx_ehash.c:288-289](cdx/cdx_ehash.c#L288) `dscp`. _Fixed: 815a0ca_ — bound checks at entry.

- [x] **C9. Test ioctl always compiled in, broken kzalloc flags.**
  [cdx/dpa_test.c:61-63](cdx/dpa_test.c#L61-L63). `kzalloc(... * num_conn, 0)` with unbounded `num_conn`, dispatched unconditionally. _Fixed: 815a0ca_ — sanity-cap + `kcalloc`.

- [x] **C9b. Remove dead testapp scaffolding entirely.**
  After C9 the surface was safe but still exposed. _Fixed: 815a0ca_ — deleted `cdx/dpa_test.c`, `dpa_app/testapp.c`, and the `CDX_CTRL_DPA_CONNADD` ioctl. H10 mooted by this.

---

## HIGH

- [x] **H1. `cdx_ioc_set_dpa_params` mutated globals without locking.**
  [cdx/dpa_cfg.c:588-719](cdx/dpa_cfg.c#L588-L719). Concurrent ioctls → UAF on the old `fman_info`. _Fixed: 613efa3_ — `dpa_cfg_lock` mutex, reject re-init, convert bare-return leaks to `goto err_ret`.

- [x] **H2. IPsec SA key material not zeroed on free.**
  [cdx/cdx_dpa_ipsec.c:205-222](cdx/cdx_dpa_ipsec.c#L205-L222). _Fixed: 613efa3_ — `kfree_sensitive()` on the three key fields.

- [x] **H3. IPsec error paths leak DMA mappings.**
  [cdx/cdx_dpa_ipsec.c:1964-1995,2580-2593](cdx/cdx_dpa_ipsec.c#L1964-L1995). _Fixed: 613efa3_ — two-label unwind in `cdx_ipsec_create_shareddescriptor`; `SA_SH_DESC_BUILT` rolls back on entry-add failure (M7 folded in).

- [-] **H4. Suspicious DMA map-then-immediately-unmap for CAAM descriptor.**
  [cdx/cdx_dpa_ipsec.c:2028-2033](cdx/cdx_dpa_ipsec.c#L2028-L2033). Not a bug — `shared_desc_dma` is a local never stored anywhere. The pair is a legitimate cache-flush idiom on non-coherent ARM64; SEC reads the descriptor later via the handle stored in `dpa_ipsecsa_handle`. Comment added documenting intent.

- [x] **H5. NAT-T SPI array bound is off-by-one.**
  [cdx/cdx_dpa_ipsec.c:2310-2318](cdx/cdx_dpa_ipsec.c#L2310-L2318). `> MAX_SPI_PER_FLOW` should be `>=`. _Fixed: 613efa3_.

- [-] **H6. auto_bridge iterates hash buckets with lock drop between buckets.**
  [auto_bridge/auto_bridge.c:232-251](auto_bridge/auto_bridge.c#L232-L251). Not a bug — `table_entry` is rebound each inner iteration via `container_of`, never persisted across outer iterations; the lock-drop is a deliberate bounded-hold-time design. Hash keys are immutable post-insert.

- [x] **H7. auto_bridge stores `net_device *` without `dev_hold()`.**
  [auto_bridge/auto_bridge.c:210](auto_bridge/auto_bridge.c#L210). Pointer crossed a workqueue boundary unrefcounted. _Fixed: 613efa3_ — `dev_hold`/`dev_put` balance + module-exit drain.

- [x] **H8. auto_bridge sysctl, missing CAP check + accepts 0.**
  [auto_bridge/auto_bridge.c:1385-1406](auto_bridge/auto_bridge.c#L1385-L1406). `0644` on proc/sys is owner-write-only (not "world-writable" as originally claimed), but a `CAP_NET_ADMIN` gate is sound defense-in-depth. _Fixed: 613efa3_ — explicit cap check + `proc_douintvec_minmax` bounds.

- [x] **H9. Query-snapshot static state shared and lock-free.**
  [cdx/cdx_mc_query.c](cdx/cdx_mc_query.c), [cdx/query_Rx.c:65-140](cdx/query_Rx.c#L65-L140), and the per-`control_*.c` cursor sites. Two concurrent enumerators corrupted each other's cursors. _Fixed: 613efa3 + 75dfbba_ — per-file query mutex around each cursor + bucket spinlock around list walks. The mutator-side lock-free walks (l2flow, ipv4/6/tunnel/pppoe tables) remain — covered by A2's documentation pass.

- [x] **H10. `strncpy_from_user` truncation not checked.**
  Mooted: all four sites were in `cdx/dpa_test.c` which C9b deleted.

---

## MEDIUM

- [x] **M1. Multicast listener-count mismatch.**
  [cdx/dpa_control_mc.c:541](cdx/dpa_control_mc.c#L541) vs [cdx/cdx_mc_query.c:60](cdx/cdx_mc_query.c#L60). Group with 6-8 listeners OOB'd the query response buffer. _Fixed: 5f9fbf0, refined in a578eca_ — pagination reserves 2 cmds per group, look-ahead over `members[]` instead of fragile counter math.

- [-] **M2. `dev_get_by_name` leaks on error paths (control_vlan).**
  Not a bug. Both `device` and `parent_device` are NULL-init at L89; all switch-arms fall to `end:` which has NULL-guarded `dev_put`s. Audited the other three callers (devman, cdx_ehash, dpa_wifi); all balanced.

- [x] **M3. Unbounded `sprintf` chain in procfs read handler.**
  [cdx/procfs.c:22-69](cdx/procfs.c#L22-L69). The original handler was `sprintf`-ing into a `char __user *buff` (kernel-vs-userspace pointer confusion, would fault under KUAP). _Fixed: 5f9fbf0_ — full `seq_file` conversion.

- [x] **M4. Kernel pointer leaks in debug output.**
  [cdx/procfs.c:167](cdx/procfs.c#L167) (`%px`) + production-path `%p` in `cdx/dpa_cfg.c`. Modern `%p` is hashed by default since 4.15, so the original "defeats KASLR" claim only held with `no_hash_pointers`. _Fixed: 5f9fbf0 + c776317_ — `%px` → `%pK`; production-path `display_*` and the always-on debug print → `%pK`; the two remaining `DPA_INFO` debug-gated `%p` sites in `dpa_cfg.c` flipped under A4.

- [x] **M5. `nlh->nlmsg_type` signedness / missing default.**
  [auto_bridge/auto_bridge.c:494-560](auto_bridge/auto_bridge.c#L494-L560). _Fixed: 5f9fbf0_ — `type` narrowed to `u16`, `default: -EINVAL` added.

- [x] **M6. auto_bridge module-exit busy-loop.**
  [auto_bridge/auto_bridge.c:1109-1125](auto_bridge/auto_bridge.c#L1109-L1125). Bare `schedule()` could hot-spin. _Fixed: 5f9fbf0_ — bounded 5s wait via `schedule_timeout_uninterruptible(1)` with `pr_warn` on timeout.

- [x] **M7. `cdx_ipsec_add_classification_table_entry` explicit TBD leak.**
  Folded into H3.

- [x] **M8. Full-group mcast delete tore down shared state without bucket spinlock.**
  [cdx/dpa_control_mc.c:883-897](cdx/dpa_control_mc.c#L883-L897). _Fixed: 61f1904_ — `list_del` under `mc{4,6}_spinlocks[uiHash]`, HW teardown unlocked (FmPcdLock is sleeping). Surfaced two pre-existing follow-ons (M10, M11).

- [x] **M9. Conditional `pCtEntry` leak on ADD err_ret unwind.**
  [cdx/dpa_control_mc.c:599-617](cdx/dpa_control_mc.c#L599-L617). _Fixed: 782700d_ — defense-in-depth pCtEntry guard in outer err_ret.

- [x] **M10. `Cdx_GetMcastMember*` lookup leaks member_id across dropped spinlock.**
  [cdx/dpa_control_mc.c:256-335](cdx/dpa_control_mc.c#L256-L335). Implicit single-writer-per-group invariant was undocumented. _Fixed: c23817b_ — `mc_mutators_mutex` taken at MC4/6 dispatcher level makes the invariant explicit.

- [x] **M11. `GetMcastGrp` returned a pointer freeable after the bucket spinlock dropped.**
  [cdx/dpa_control_mc.c:200-252](cdx/dpa_control_mc.c#L200-L252). Same root cause as M10. _Fixed: c23817b_ — same `mc_mutators_mutex` closes the dangling-pointer window.

- [x] **M12. Full-group-delete fast path keyed off count alone, ignored listener names.**
  [cdx/dpa_control_mc.c:912](cdx/dpa_control_mc.c#L912). `REMOVE [foo]` against `{ bar }` (both count 1) wiped the entire group. _Fixed: 2d7689f_ — pre-validation walks every requested listener; mismatches bail with `ERR_MC_CONFIG`. Regression test in `tools/tests/test_mcast_failslab.py`.

- [x] **M13. Duplicate listener names in REMOVE still tripped the count-match fast path.**
  [cdx/dpa_control_mc.c:912](cdx/dpa_control_mc.c#L912). M12's pre-validation didn't dedupe. _Fixed: c23817b_ — bitmap tracks resolved member_ids, duplicate hits return `ERR_MC_CONFIG`.

- [x] **M14. cmm `cmm_parse_rtattr` tail dereference on truncated rtattr.**
  [cmm/src/rtnl.c:280-281](cmm/src/rtnl.c#L280-L281). When the parser loop exited with `len != 0` (truncated trailing rtattr), the next line passed `rta->rta_len` to `cmm_print` — but `rta` may point past the buffer at that point, so the read was OOB by up to 2 bytes. Surfaced while authoring [tools/tests/test_cmm_rtnl_fuzz.py](tools/tests/test_cmm_rtnl_fuzz.py); ASAN-instrumented input `04 00 01 00 99` reproduces. _Fixed_ — extracted parser body into [cmm/src/rtnl_parse.c](cmm/src/rtnl_parse.c) so cmm and the fuzzer link the same code; dropped `rta->rta_len` from the diagnostic (only `len_remaining` is logged now); fuzzer ASAN run confirms no further OOB.

- [x] **M15. FMAN PCD does not replicate IPv4 multicast frames to listener subifs.**
  [cdx/dpa_control_mc.c](cdx/dpa_control_mc.c). Two independent kernel-side bugs in the MC4 ADD path: (a) no `dev_mc_add()` on the ingress netdev, so FMAN MEMAC's hardware multicast filter dropped frames at L2 before PCD ran (PROMISC doesn't bypass mcast filtering on FMAN); (b) no write barrier between the per-listener EHASH chain writes and `ExternalHashTableAddKey()`'s bucket-head publish, so on weak-ordered ARM64 FMAN could read the new bucket head and walk a still-stale chain — CC counters tick but listener TX FQs stay at 0. _Fixed_ — early `dev_mc_add`/`dev_mc_del` in create + err_ret + REMOVE-all branches; `wmb()` in `insert_mcast_entry_in_classif_table` before AddKey; replication-correctness tests in [test_mcast_replication.py](tools/tests/test_mcast_replication.py) un-skipped and pass.

---

## LOW / Hardening

- [x] **L1. Jenkins hash where collision DoS matters.**
  [cdx/jenk_hash.h](cdx/jenk_hash.h). Only used in `cdx/control_bridge.c:330` for kernel-side `l2flow_hash_table[]` indexing — software-only lookup, attacker-controllable 5-tuple. _Fixed: bf8c453_ — keyed `hsiphash` with boot-random key; `jenk_hash.h` deleted.

- [x] **L2. `strcpy` into equal-sized `IF_NAME_SIZE` buffers.**
  Multiple sites in `cdx/control_*.c`. Mostly bounded today (kernel `net_device->name` is NUL-terminated) but command-sourced names aren't guaranteed. _Fixed: 89e5b32_ — broader sweep to `strscpy` across `cdx/`.

- [x] **L3. `sprintf` into small fixed name buffers (procfs).**
  [cdx/procfs.c:224,226](cdx/procfs.c#L224). _Fixed: 5f9fbf0_ alongside M3 (`snprintf`).

- [x] **L4. `proc_create("fci", 0, …)`.**
  [fci/fci.c:542](fci/fci.c#L542). Mode `0` is fragile. _Fixed: 89e5b32_ — `0444`.

- [x] **L5. Unimplemented ioctl stub declarations.**
  [cdx/cdx_ioctl.h:317-321](cdx/cdx_ioctl.h#L317-L321). _Fixed: 89e5b32_ — removed the stubs and the supporting struct/macro dead code.

- [x] **L6. Inconsistent endian conversion in reassembly release.**
  [cdx/cdx_reassm.c:150-172](cdx/cdx_reassm.c#L150-L172). Type mismatch (u8 ↔ u16 zero-extend), not endian bug. _Fixed: 89e5b32_ — renamed `cpu_to_be*` → `be*_to_cpu` to document intent (no-op on LE).

- [x] **L7. UBSAN array-bounds: flex-array subscript in `create_ethernet_hm`.**
  [cdx/cdx_ehash.c:1849](cdx/cdx_ehash.c#L1849). `*(uint16_t*)(&l2param->l2hdr[2*ETHER_ADDR_LEN]) = ...` warned under UBSAN. _Fixed: f717ba7_ — pointer arithmetic.

- [x] **L8. cmm `sig_term_hdlr` benign ENOENT noise on reboot.**
  [cmm/src/cmm.c:318-320](cmm/src/cmm.c#L318-L320). `remove()` of an already-cleaned pidfile printed misleading error. _Fixed: ff1be40_ — gate on `errno != ENOENT`.

---

## Corrections to the original review

Flagged as critical by deep-dive agents but don't hold up on verification.

- [-] **X1. "256-byte memset + partial fill = info leak."**
  False positive. `memset(p, 0, 256)` zeros the buffer *before* the partial fill — uninitialized bytes copied back are zeros.

- [-] **X2. "strcpy IF_NAME_SIZE → IF_NAME_SIZE overflows."**
  Downgraded to L2. Kernel `net_device->name` is NUL-terminated within `IFNAMSIZ` so when source is `dev->name`, strcpy is bounded.

- [-] **X3. "N new suspected memory leaks" from `dpaa_eth_refill_bpools`.**
  Not a leak. The DPAA SDK hands skb addresses to hardware via descriptor rings; during the hardware-owned phase kmemleak's pointer scanner can't find a kernel-side reference. RSS stays flat for hours on idle. Tests that use kmemleak as an oracle must filter to specific function-name needles, never to the broad `[cdx]`/`[auto_bridge]` module-tag matcher.

---

## Architectural themes

- [x] **A1. Every external field needs a bounds check at its entry point.**
  Hardware descriptors, netlink attrs, ioctl structs, kernel-internal state all looked alike. _Fixed in stages: A1a-A1e._ The whole FCI command bus (~120 codes across 14 cmdprocs) plus the cdx ioctl dispatcher now route through a single validator-table idiom. Two pre-existing latent bugs surfaced and silently fixed in the migration (MC4/MC6 zero-byte reply on unknown cmd; misleading `ERR_STAT_FEATURE_NOT_ENABLED` for unknown stat cmd).

- [x] **A1a. Validator-table pattern (`cdx/cdx_cmd_validator.{h,c}`).**
  Spec struct + dispatcher: lookup by cmd_code, range-check len, run validate(), run handle(). _Fixed: cf1fa1b_.

- [x] **A1b. Prototype on `control_vlan.c`.**
  _Fixed: f2f3a82_. Migration template documented in commit message + ISSUES history. Permissive-validator follow-up pass to tighten min-length bounds: _c4d3965_.

- [x] **A1c. Migrate the rest, ordered by risk + simplicity.**
  - [x] **A1c-1.** `dpa_control_mc.c` (MC4+MC6) — _cbc2a6e_.
  - [x] **A1c-2.** `control_pppoe.c` — _37f0e37_.
  - [x] **A1c-3.** `control_ipv6.c` — _f5e1bba_.
  - [x] **A1c-4.** `control_ipv4.c` — _394452b_.
  - [x] **A1c-5.** `control_tunnel.c` — _74643c8_.
  - [x] **A1c-6.** `control_bridge.c` — _5059240_.
  - [x] **A1c-7.** `control_ipsec.c` — _37f99e3_.
  - [x] **A1c-8.** `control_stat.c` — _4fa6df7_.
  - [x] **A1c-9.** `control_{rx,rtp_relay,wifi,tx,qm}.c` (5 files, 41 codes) — _56dbb07_.

- [x] **A1d. cdx ioctl dispatcher onto the same idiom.**
  ABI is different enough (no cmd_len, copy_{from,to}_user, errno return) that forcing it onto `cdx_dispatch_cmd` would fork the dispatcher. _Fixed: ed082ea_ — file-local `cdx_ioctl_table[]` with same spec-struct shape.

- [x] **A1e. Drop the per-subsystem inner switches.**
  Done in-line with each A1b/A1c migration — every commit replaced the whole cmdproc body in one shot. No separate cleanup pass.

- [x] **A2. Concurrency assumed, not enforced.**
  Globals in `dpa_cfg.c`, static cursors in every `control_*.c`, lock-drop iteration in auto_bridge. _Fixed: d99bb62_ — top-of-file `Concurrency:` block per .c file documenting locks/contexts/ordering, plus sparse `__must_hold()` annotations on internal helpers. Runtime enforcement via `CONFIG_PROVE_LOCKING` (Armbian config flip, out-of-repo).

- [x] **A3. Error paths don't unwind.**
  Recurring leak-on-failure pattern. _Fixed in A3a-A3e_ plus two follow-ons: `dpa_release_interface` sibling (d0d0b3f) and the IPR FQ teardown originally noted as A3a residual (78ac2af).

- [x] **A3a. `cdx_init_ip_reassembly` / `cdx_deinit_ip_reassembly` — init/deinit asymmetry.**
  _Fixed: b5a7bf8 + 78ac2af_ — full nested-label cascade; deinit retires/oos/destroys IPR FQs via private `ipr_fqs[]` tracking and releases the fqid range.

- [x] **A3b. `cdx_init_fqid_procfs` — sequential `proc_mkdir` without unwind.**
  [cdx/procfs.c:76-114](cdx/procfs.c#L76-L114). _Fixed: b5a7bf8_ — nested `err_remove_*` cascade.

- [x] **A3c. `abm_l2flow_table_init` — `l2flow_cache` leaked on `brroute_cache` failure.**
  [auto_bridge/auto_bridge.c:1176-1197](auto_bridge/auto_bridge.c#L1176-L1197). _Fixed: b5a7bf8_.

- [x] **A3d. `abm_init` — cascading subsystem init leaks.**
  [auto_bridge/auto_bridge.c](auto_bridge/auto_bridge.c). _Fixed: b5a7bf8_ — every failed init step routes to its matching `_fini`/`_exit` in reverse.

- [x] **A3e. `dpa_add_eth_if` — `err_ret*` cascade had three explicit TODO gaps.**
  [cdx/devman.c:1983-2128](cdx/devman.c#L1983-L2128). _Fixed: ba1ac4e_ — three new helpers: `dpa_remove_ethport_ff_policier_profile`, `dpa_bman_restore_discard_mask`, `cdx_disable_ceetm_on_iface`. Sibling follow-on `dpa_release_interface` calls these in reverse acquisition order — _d0d0b3f_.

  _Test coverage:_ A3a-e fixes are validated by code review only. The natural design (`failslab_times` over modprobe of cdx/fci/auto_bridge) doesn't work because those modules are persistent — daemons hold their refcounts. Runtime err_ret coverage continues via the FCI-reachable mcast paths in [test_mcast_failslab.py](tools/tests/test_mcast_failslab.py).

- [x] **A4. Debug code is production code.**
  `dpa_test.c` (C9), debug `%p` (M4), `cdx_deinit_ip_reassembly` stub (C5). All resolved across C9b, M4, C5/A3a, plus the two debug-gated `%p` sites in `dpa_cfg.c` flipped to `%pK` (_c776317_). Other debug-gated `%p` across cdx/ left alone (default-hashed by kernel; out-of-scope churn).

- [x] **A5. Kernel-side fixes unblocking sanitizer coverage.**
  Bringing up the test image with LOCKDEP/PROVE_LOCKING/DEBUG_ATOMIC_SLEEP/UBSAN surfaced four pre-existing bugs in vendored kernel code (qbman, sdk_dpaa, sdk_fman, netlink). Two would deadlock under memory pressure; one is a lockdep annotation gap; one is a kernel-internal name-table gap. Patches live in `patches/kernel/` (`090-…` through `093-…`) so Armbian production picks them up.

- [x] **A5a. qbman `dpa_alloc_new` sleeps under `spin_lock_irq`.**
  Patch `090-qbman-dpa_alloc-preallocate-nodes.patch`.

- [x] **A5b. `dpa_get_channel` holds a spinlock over a sleeping allocation.**
  Patch `091-sdk_dpaa-dpa_get_channel-use-mutex.patch`.

- [x] **A5c. FMAN `FmPcdLockTryLockAll` false-positive recursive-lock warning.**
  Patch `092-sdk_fman-FmPcdLockTryLockAll-nest-annotation.patch`.

- [x] **A5d. Netlink `nlk_cb_mutex_key_strings[]` underpopulated for `NETLINK_L2FLOW = 33`.**
  Patch `093-netlink-name-L2FLOW-cb-mutex.patch`.

- [x] **A6. CDX tunnel handlers walked untrusted name fields as C strings.**
  `cdx/control_tunnel.c`. `TNL_handle_DELETE/UPDATE` `memcpy`'d a fixed-size `cmd.name[16]` then walked it as a C string — KASAN OOB on a 16-byte payload with no NUL. Caught by the new payload-mutation fuzzer (A7) on first run under `KASAN=1`. _Fixed: 9f9b69d_ — `HASH_TUNNEL_NAME(name, maxlen)`, `M_tnl_get_by_name(name, maxlen)`, `strncmp` instead of `strcmp`.

- [x] **A7. Fuzzer payload-body coverage for the validator-table surface.**
  Original fuzzer hit dispatcher-level length checks only. _Fixed: 0bf177b_ — 30 mutation cases (10 sized commands × {`all_ff`, `high_enum`, `no_nul_str`}) with KASAN/UBSAN/lockdep splat oracle. First run caught A6.

- [ ] **A8. CAAM job ring consumers not released at shutdown.**
  On `reboot`, kernel logs `caam_jr 17{1,2}0000.jr: Device is busy; consumers might start to crash`. JR3/JR4 still have registered consumers when `caam_jr` is being torn down. Mostly cosmetic on a hard reboot but indicates a real cleanup gap. **Likely culprits:** (a) IPsec SAs registered via [cdx/cdx_dpa_ipsec.c](cdx/cdx_dpa_ipsec.c); (b) async crypto contexts held by in-kernel `caamalg`/`caamhash`/`caamrng` users; (c) a daemon (cmm/askd-agent) pinning SAs across systemd's stop-units phase. **Investigation:** (1) confirm reproducibility with no IPsec SAs ever installed; (2) if IPsec-related, audit `cdx_ipsec_sec_sa_context_free` for paths that don't unregister from JR; (3) test daemon-stop-first. Sibling-thread to C5/A3a.

- [ ] **A9. Tunnel RX-side decap not offloaded — deferred.**
  No kernel path installs outer-keyed entries (proto=41/47/4) in a `cdx_*_cc` classification table; decap falls through to Linux's sit module in software. TX-side encap is fully wired and offloaded ([test_tunnel_tx_offload.py](tools/tests/test_tunnel_tx_offload.py) confirms ~8.8 Gbps). RX offload is a follow-up — see [test_tunnel_offload.py::test_tunnel_6o4_decap_to_lan](tools/tests/test_tunnel_offload.py)'s xfail for the tripwire.

- [ ] **A10. `RouteEntry.id` is U16 but `RtCommand.id` is U32 — silent truncation on store.**
  [cdx/layer2.h:56](cdx/layer2.h#L56) declares `RouteEntry.id` as U16 while the wire format `RtCommand.id` carries U32. `CMD_IP_ROUTE` ADD with `id ≥ 0x10000` succeeds (returns `reply_rc=0`) but the entry is silently truncated on store, leaving it unfindable on subsequent lookup keyed by the original U32 id. Surfaced while authoring the tunnel-offload test fixture — initial route ids in the 0x06040001 range hit this. **Severity:** latent footgun, not a security bug — userspace callers (cmm, the test harness) need to know the implicit ≤U16 cap; absence of validation means the failure mode is "route silently doesn't exist" rather than "ADD fails loudly." **Fix:** either widen `RouteEntry.id` to U32 (preferred — matches the wire format) or reject `RtCommand.id ≥ 0x10000` in the route-add validator with an explicit error code. Cross-check IPv6 route entries for the same asymmetry. Test workaround already in place: cap test-generated route ids at U16.

- [ ] **A11. FORTIFY_SOURCE false positive on `create_tunnel_insert_hm` flex-array memcpy.**
  [cdx/cdx_ehash.c:2298](cdx/cdx_ehash.c#L2298) does `memcpy(&ptr->l3hdr[0], &info->l3_info.header_v4, info->l3_info.header_size)` where `l3hdr` is a zero-length array (`uint8_t l3hdr[0]`) at the tail of `struct en_ehash_insert_l3_hdr` (kernel header [drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h](drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h)). With `CONFIG_FORTIFY_SOURCE` enabled in the meta-ask test image, the memcpy fires a runtime WARNING because the compile-time destination size is 0 — even though the caller correctly pre-allocates `sizeof(struct) + header_size` at [cdx_ehash.c:2280](cdx/cdx_ehash.c#L2280). The same warning fires from line 2290 for TNL_MODE_4O6. **Surfaced** by [test_tunnel_tx_offload.py](tools/tests/test_tunnel_tx_offload.py) — the iperf3-over-sit-tunnel test exercised the encap path for the first time. **Severity:** false positive — no actual OOB; the buffer is sized for `header_size` bytes by the caller. The data plane works (8.8 Gbps offloaded throughput observed). **Fix:** change `l3hdr[0]` to a proper C99 flexible-array `l3hdr[]` (preferred — silences FORTIFY without disabling it), or use `unsafe_memcpy()` at the call site. Header lives in the vendored sdk_fman tree; fix as a `patches/kernel/` patch alongside the other 09x correctness fixes. **Tripwire:** allowlist entry in [tools/tests/golden/dmesg_allowlist.yaml](tools/tests/golden/dmesg_allowlist.yaml) suppresses for `test_tunnel_tx_offload` until the kernel fix lands; expires 2026-07-01.

- [ ] **A13. Upstream `ppp_generic` lockdep WARNING — `all_ppp_mutex` ↔ `rtnl_mutex` inversion.**
  Lockdep splat on first `PPPIOCNEWUNIT` ioctl issued by pppd:
  ```
  pppd is trying to acquire lock: rtnl_mutex, at: rtnl_lock
  but task is already holding lock: &pn->all_ppp_mutex, at: ppp_ioctl+0x3b8 [ppp_generic]
  ...
  CPU0: lock(&pn->all_ppp_mutex); lock(rtnl_mutex)
  CPU1: lock(rtnl_mutex);         lock(&pn->all_ppp_mutex)
  ```
  Path A (pppd ioctl): `ppp_ioctl` → `ppp_dev_configure` → `register_netdev` → `rtnl_lock` (with `all_ppp_mutex` held). Path B (rtnetlink): `ppp_link_ops` newlink callback runs with `rtnl_mutex` held, then takes `all_ppp_mutex`. Genuine lock-order inversion in upstream `drivers/net/ppp/ppp_generic.c` (Linux 6.12.49). Lockdep WARNING only — fires once per boot on first detection; no actual deadlock observed because the rtnetlink-side path isn't typically exercised concurrently with pppd ioctls in practice. **Severity:** latent risk — would deadlock if a PPP rtnetlink config raced with pppd's PPPIOCNEWUNIT. **Surfaced** by [test_pppoe_e2e.py::test_pppoe_session_lifecycle](tools/tests/test_pppoe_e2e.py) on first PPPIOCNEWUNIT after a fresh boot. **Fix:** upstream-track. Likely solution is to drop `all_ppp_mutex` before calling `register_netdev` in `ppp_dev_configure`, or restructure the rtnetlink path to defer `all_ppp_mutex` acquisition. Out of scope for ASK; track upstream stable backport. **Tripwire:** allowlist entry in [tools/tests/golden/dmesg_allowlist.yaml](tools/tests/golden/dmesg_allowlist.yaml) suppresses for `test_pppoe_e2e` until 2026-10-01; expiry forces re-review.

- [-] **A12. PPPoE RX-decap "missing classifier-table install" — not a bug.**
  Endpoint RX is intentionally inner-keyed: PCD `dist_order` ([dpa_app/files/etc/cdx_pcd.xml:335-352](dpa_app/files/etc/cdx_pcd.xml#L335-L352)) tries `cdx_udp4_dist`/`cdx_tcp4_dist` before `cdx_pppoe_dist`, and `STRIP_PPPoE_HDR` chains in at CT-add time via `pppoe_present` metadata ([cdx/cdx_ehash.c:740](cdx/cdx_ehash.c#L740)). `cdx_pppoe_cc` is for relay only. Filed during synthetic-FCI wire-tracing then retracted after audit; [test_pppoe_e2e.py](tools/tests/test_pppoe_e2e.py) confirms the path works under real pppd at 1.55 Gbps / 0.5% CPU.

- [ ] **A14. H2 key-zeroing regression test needs kernel-side observability probe.**
  Parked at [tools/tests/test_ipsec_key_zeroing.py](tools/tests/test_ipsec_key_zeroing.py); no userspace surface for freed-slab contents (kmemleak reports refs not contents).

- [ ] **A15. cmm has no incoming xfrm netlink subscription.**
  [cmm/src/keytrack.c:1613](cmm/src/keytrack.c#L1613) only sends outbound `XFRM_MSG_EXPIRE`; nothing watches incoming `NEWSA`/`NEWPOLICY`. Design finding — slice-2 fixture drives `ip xfrm` AND FCI in parallel.

- [x] **A16. NAT-T fast-path push discarded classification-table-entry failure.**
  [cdx/control_ipsec.c:720](cdx/control_ipsec.c#L720) — return of `cdx_ipsec_process_udp_classification_table_entry` was thrown away on the NAT-T branch, so `reply_rc` stayed NO_ERR on H5/lookup failures. _Fixed: pending commit_ — capture and propagate, matching the non-NAT-T branch.

- [x] **A17. `IPsec_handle_SA_SET_KEYS` derefed `sa` before NULL check.**
  [cdx/control_ipsec.c:617](cdx/control_ipsec.c#L617) wrote through `sa` BEFORE the line 619 `sa == NULL` check; SET_KEYS on a stale sagd NULL-derefed. _Fixed: pending commit_ — assignment moved after the check.

- [x] **A18. NAT-T fast-path push NULL-derefed `sa->ct`.**
  [cdx/cdx_dpa_ipsec.c:2382-2388](cdx/cdx_dpa_ipsec.c#L2382-L2388) — else-branch ignored `cdx_ipsec_add_classification_table_entry`'s return then wrote `sa->ct->natt_in_refcnt`; oops on any NAT-T SA whose dst_ip wasn't bound to an iface. _Fixed: pending commit_ — `goto err_ret` on failure.

- [x] **A20. `ipsec_nlkey_rcv` took xfrm state lock without softirq disable.**
  [patches/kernel/040-ask-xfrm-ipsec-offload.patch](patches/kernel/040-ask-xfrm-ipsec-offload.patch) ipsec_nlkey_rcv used `spin_lock(&x->lock)` from netlink-callback (process) context; upstream `xfrm_timer_handler` takes the same per-state lock from softirq. Lockdep flagged `SOFTIRQ-ON-W -> IN-SOFTIRQ-W` on the first xfrm operation each boot. Surfaced while bringing up slice-2's static-`ip xfrm` fixture. _Fixed: pending commit_ — three pairs flipped to `spin_lock_bh()` / `spin_unlock_bh()` (NLKEY_SA_NOTIFY, NLKEY_SA_INFO_UPDATE, NLKEY_SA_SET_OFFLOAD).

- [x] **A19. IPsec SA install/release leak triad.**
  Three asymmetric-cleanup leaks surfaced by failslab + kmemleak: [cdx/procfs.c:158](cdx/procfs.c#L158) `cdx_create_dir_in_procfs` missed `kfree` on `proc_mkdir` NULL; [cdx/dpa_ipsec.c](cdx/dpa_ipsec.c) `cdx_dpa_ipsecsa_release` missed `kfree` on the `cdx_proc_dir_entry_t` wrapper struct (8 B per SA) and on `sainfo->shdesc_mem` (~512 B per SA — `create_ipsec_fqs:err_ret1` freed it but the success-then-release path didn't). _Fixed: cd0548c_.

- [ ] **A21. `cdx_module_deinit()` NULL-derefs when called from a failed `cdx_module_init`.**
  The init path goes `cdx_module_init → ... → cdx_dpa_ipsec_init failure → exit: label → cdx_module_deinit (only if rc != 0)`. When deinit runs from a partially-initialised state, [cdx/cdx_main.c](cdx/cdx_main.c) → `cdx_ctrl_deinit` → `cdx_cmdhandler_exit` → `tx_exit` → `remove_onif_by_index` → `dpa_release_interface` → `cdx_disable_ceetm_on_iface` → `ceetm_release_lni` → `qman_ceetm_sp_release+0x28/0x108` NULL-derefs (data abort at `0x20`, modprobe segfaults, no `/dev/cdx_ctrl` ever appears, CMM cannot start). The historical workaround was to *not* set `rc` on `cdx_dpa_ipsec_init` failure (cdx_main.c:294-297 leaves `rc=0` so the exit path is never taken and the rest of cdx loads despite a half-initialised IPsec subsystem). Confirmed by enabling `rc = -EIO` in that branch and observing the deref. **Severity:** masks A22 (next entry) — until A21 is fixed, we can't propagate IPsec init failures cleanly. **Fix direction:** ceetm/onif/dpa-iface release functions need NULL-guards on every list head and table-descriptor pointer they touch. This is a structural fix; budget it for a focused pass over `cdx_disable_ceetm_on_iface`, `dpa_release_interface`, `tx_exit`.

- [x] **A23. IPsec offload silent drop — `ipsec_bp` (BPID 37) registered but never seeded.**
  [add_ipsec_bpool()](cdx/dpa_ipsec.c#L1131) called `dpa_bp_alloc()` but not `dpaa_bp_alloc_n_add_buffs(bp, IPSEC_BUFCOUNT, 1)` — SEC saw `BPDERR`. `act_skb=1` is load-bearing for the inbound-decap cb's `contig_fd_to_skb`. _Fixed in this branch._

- [x] **A25. cdx AES-128-CTR — missing nonce trim + missing CTR PDB writes.**
  CTR case in [`M_ipsec_sa_set_cipher_key`](cdx/control_ipsec.c#L264) didn't set `comb_mode=1; extra_size=4;` (RFC 3686 nonce wasn't split off the 20-byte key), and `cdx_ipsec_build_{in,out}_sa_pdb` had no branch writing `pdb.ctr.ctr_nonce`/`ctr_initial=1`. Lifted on the existing GCM precedent. Verified at 2.58 Gbit/s (CBC parity). _Fixed in this branch._

- [x] **A24. SEC GCM offload — cross-DECO race on PDB.seq has no clean cdx-side fix; refused at SA install. CBC+HMAC and CCM unaffected.**
  Both share modes failed: `HDR_SHARE_SERIAL` → ~86 % ICV-fail (cross-DECO GHASH contention); `HDR_SHARE_NEVER` → ~21–25 % wire-seq dupes above ~100 Mbit/s per SA (per-DECO PDB.seq counters diverge — matches NXP DNCPE-2358). IV-uniqueness empirically preserved (53 323 dupe-seq pairs in 223 k frames @ 500 Mbit/s, all with distinct IVs — SEC IVSRC independent of PDB.seq), so this is RFC 4303 anti-replay non-compliance, not a Joux-class break. Refused at [patches/kernel/040-ask-xfrm-ipsec-offload.patch](patches/kernel/040-ask-xfrm-ipsec-offload.patch) (kernel `ipsec_xfrm2nlkey` NLKEY_SA_CREATE — load-bearing gate; cmm fire-and-forgets cdx replies so the cdx-side refusal alone cannot prevent `x->offloaded=1`) plus [cdx/control_ipsec.c::M_ipsec_sa_set_cipher_key](cdx/control_ipsec.c) (defense-in-depth for direct-FCI tooling). GCM falls through to kernel xfrm via `rfc4106-gcm-aes-caam` (JR variant, the higher-priority one in `/proc/crypto` on this kernel; ~77 Mbit/s TCP measured, replay-window=32 correct, 0 ICV/seq errors). Reopen with feature gate if NXP delivers PDB.seq atomicity. _Fixed in this branch._

- [x] **A22. IPsec OH-port classifier miss — gateway-dk cdx_cfg.xml portid tripped cdx_sp.xml espschema gate.**
  Soft-parser hooks in [cdx_sp.xml](dpa_app/files/etc/cdx_sp.xml) gate policing/early-exit on `$logicalportid lt 9` — NXP-reference OH portids 9/10 sit above; the gateway-dk override at 2/3 tripped it, breaking ESP recognition on SEC's encrypted output. Restored OH portids to 9/10. _Fixed in this branch._

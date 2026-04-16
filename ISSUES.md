# ASK Kernel-Module Security & Memory-Safety Issues

Working list from the security review of `cdx/`, `fci/`, and `auto_bridge/`.
Each item has enough context to be picked up in isolation. Check off as we fix.

**Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` wontfix/not-a-bug (explain inline)

---

## Gating Issue — fix this first

It changes the reachability (and therefore severity) of almost everything else.

- [x] **G1. `/dev/cdx_ctrl` ioctl has no capability check.**
  [cdx/cdx_dev.c:110-140](cdx/cdx_dev.c#L110-L140). `cdx_ctrl_ioctl` dispatches `CDX_CTRL_DPA_SET_PARAMS`, `CDX_CTRL_DPA_CONNADD`, and (when built with `DPAA_DEBUG_ENABLE`) `CDX_CTRL_DPA_GET_MURAM_DATA` with no `capable(CAP_NET_ADMIN)` / `CAP_SYS_ADMIN` guard. Combined with whatever udev mode the device node gets, unprivileged users may be able to reconfigure the entire DPAA datapath. **Fix:** add `if (!capable(CAP_NET_ADMIN)) return -EPERM;` at the top of the dispatcher (or per-command for finer granularity). Confirm device node perms in the target rootfs.
  _Done on branch `fix/cdx-ioctl-cap-check`: added `CAP_NET_ADMIN` gate + `<linux/capability.h>` include in `cdx_dev.c`._

- [x] **G2. Racy single-open gate.**
  [cdx/cdx_dev.c:48-56](cdx/cdx_dev.c#L48-L56). `atomic_dec_and_test` followed by `atomic_inc` on failure is check-then-act: two concurrent `open()`s can both succeed. **Fix:** use a mutex, or `atomic_cmpxchg(&cnt, 1, 0)` to flip from "free" to "taken" atomically.
  _Done on branch `fix/cdx-ioctl-cap-check`: switched open to `atomic_cmpxchg(1→0)`, release to `atomic_set(1)`. Correction: the original dec/inc can't actually let two openers both succeed (`atomic_dec_and_test` is itself atomic), but it does have a transient window where a new opener is spuriously rejected between release and the failed-opener's inc; and a stray release inflates the counter past 1. Both are resolved._

---

## CRITICAL

Memory corruption or info-leak reachable from userspace (unprivileged once G1 is open, privileged if G1 is fixed).

- [x] **C1. Netlink attribute length trusted as memcpy size (auto_bridge).**
  [auto_bridge/auto_bridge.c:540-544](auto_bridge/auto_bridge.c#L540-L544). `memcpy(&l2flow_temp.l3.saddr.all, nla_data(tb[L2FLOWA_IP_SRC]), nla_len(tb[L2FLOWA_IP_SRC]))` — destination is a 16-byte union on the stack, length is attacker-controlled. `nlmsg_parse` at line 501 passes `NULL` policy, so per-attribute lengths are never validated. Same pattern on `L2FLOWA_IP_DST`. **Fix:** define a `struct nla_policy[]` that constrains `L2FLOWA_IP_SRC`/`_DST` to `NLA_BINARY` with `.len = sizeof(union)`, or guard with `if (nla_len(..) > sizeof(l2flow_temp.l3.saddr.all)) return -EINVAL;` before each memcpy.
  _Done: added `abm_l2flow_policy[]` covering all L2FLOWA_* attrs (IP_SRC/DST bounded to `sizeof_field(struct l2flow, l3.saddr.all)` = 16 B via `NLA_BINARY`; integer attrs strict-typed as `NLA_U8/U16/U32`), passed to `nlmsg_parse`. Oversized or mistyped attributes are now rejected before the memcpy runs._

- [x] **C2. FCI netlink message — no length validation.**
  [fci/fci.c:417-475](fci/fci.c#L417-L475). `__fci_fe_inbound_data` does `fci_msg = nlmsg_data(nlh)` and then calls `comcerto_fpp_send_command(fci_msg->fcode, fci_msg->length, fci_msg->payload, …)` with zero checks that (a) `nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(FCI_MSG))`, (b) `fci_msg->length <= FCI_MSG_MAX_PAYLOAD`, (c) `fci_msg->length <= nlmsg_len(nlh) - FCI_MSG_HDR_SIZE`. Short nlmsg + large `length` → OOB read into the FPP command path. **Fix:** validate all three before dispatch; reject malformed messages with `-EINVAL`.
  _Done: `__fci_fe_inbound_data` now rejects short skbs, messages with `nlmsg_len > skb->len` or `< NLMSG_LENGTH(FCI_MSG_HDR_SIZE)`, and any `fci_msg->length` that exceeds `FCI_MSG_MAX_PAYLOAD` or the bytes actually carried. rx_msg_err incremented on each failure._

- [x] **C3. Reassembly trusts hardware-sourced `num_entries`.**
  [cdx/cdx_reassm.c:141,163-189](cdx/cdx_reassm.c#L141-L189). `num_entries = list->num_entries;` is read from a reassembly context populated by FMAN and used unbounded in the buffer-release loop (`for (ii = 0; ii < num_entries; ii++) … list++`). A malformed frame walks `list` past the allocated pool and feeds garbage addrs/bpids to `bman_release`. **Fix:** bound-check `num_entries` against the known max fragments per context (derived from `ipr_info.max_frags_per_ctx` or similar); skip release on overflow.
  _Done: `num_entries > reassly_bp->size / sizeof(*list)` rejects the frame (consume without acting) before the release loop runs. Uses physical buffer capacity as the bound, the tightest defense that requires no config plumbing._

- [x] **C4. Reassembly refcount is a `uint8_t` with no underflow guard.**
  [cdx/cdx_reassm.c:157,163](cdx/cdx_reassm.c#L157-L163). `list->ref_count--;` then `if (!list->ref_count)` releases buffers. Double-entry into this callback for the same context wraps the counter to 255 and skips release — or, if the hardware delivers the same context N+1 times, the (N+1)th decrement flips zero→255 and silently leaks the release. **Fix:** change to `uint32_t` (cheap) and guard with `if (list->ref_count == 0) { WARN_ON(1); return …; }` before the decrement.
  _Done: guard `if (list->ref_count == 0) { DPA_ERROR(...); return consume; }` placed before the decrement. Kept `uint8_t` since the struct is hardware-populated and layout-sensitive._

- [x] **C5. IP reassembly deinit is a stub → UAF on module unload.**
  [cdx/cdx_reassm.c:366-380](cdx/cdx_reassm.c#L366-L380). `cdx_deinit_ip_reassembly()` is literally `printk("implement this\n")`. The `ipr_timer` kthread keeps running after init resources are freed. **Fix:** implement deinit: `kthread_stop(ipr_timer_thread)` first, then tear down FQs/bpool/ehash in reverse init order. Also cover the partial-init failure path in `cdx_init_ip_reassembly()`.
  _Partial done: `kthread_stop(ipr_timer_thread)` now runs on unload (resolves the UAF-via-code-gone). FQ/bpool/hook teardown remains TODO and is flagged inline; those leak on unload but no longer crash._

- [x] **C6. Integer-scaled/unbounded allocations driven by userspace (dpa_cfg).**
  Repeated pattern in [cdx/dpa_cfg.c](cdx/dpa_cfg.c):
    - `sizeof(struct cdx_fman_info) * params.num_fmans` at [L602](cdx/dpa_cfg.c#L602)
    - `sizeof(struct cdx_port_info) * finfo->max_ports` at [L280](cdx/dpa_cfg.c#L280)
    - `sizeof(struct cdx_dist_info) * port_info->max_dist` at [L182](cdx/dpa_cfg.c#L182)
    - `sizeof(struct table_info) * finfo->num_tables` at [L343](cdx/dpa_cfg.c#L343)

  On 64-bit the pure-overflow angle is weak, but userspace can drive arbitrarily large allocations (DoS), and the results land in globals with no locking. **Fix:** reject unreasonable counts up-front (`if (num > MAX_SANE) return -EINVAL;`), use `kmalloc_array`/`kcalloc` for overflow-safe scaling.
  _Done: defined `CDX_MAX_FMANS=16`, `CDX_MAX_PORTS=128`, `CDX_MAX_DIST=256`, `CDX_MAX_TABLES=256` at the top of dpa_cfg.c (4x-16x current hardware/userspace ceilings). All four sites now reject zero and oversize up-front, then use `kcalloc` for overflow-safe allocation. Redundant `memset` after zero-alloc removed; unused `mem_size` in `cdx_ioc_set_dpa_params` removed._

- [x] **C7. Off-by-one index validation in `fm_index` checks.**
  [cdx/dpa_cfg.c:367](cdx/dpa_cfg.c#L367) plus near-identical sites at ~993, 1008, 1022, 1035, 1048: `if (fm_index > num_fmans) return -1;` should be `>=`. Allows one-past-end access to `fman_info[]`. **Fix:** change all six to `>=` and grep the file for the pattern `> num_fmans` / `> max_ports` to catch siblings.
  _Done: all six `fm_index > num_fmans` sites flipped to `>=`._

- [x] **C8. Unbounded user-controlled array indices.**
  [cdx/dpa_cfg.c:981,998,1013,1053](cdx/dpa_cfg.c#L981) use `queue_no` as an index into `ingress_policer_info[]` with no bound. [cdx/dpa_cfg.c:902](cdx/dpa_cfg.c#L902) does `1 << port_idx` with no `port_idx < 32` check (UB). [cdx/cdx_ehash.c:288-289](cdx/cdx_ehash.c#L288) indexes `dscp_vlanpcp_map.dscp_vlanpcp[dscp]` with no `dscp < 64` check. **Fix:** bound-check all three at entry.
  _Done: `queue_no >= INGRESS_ALL_POLICER_QUEUES` added to `cdx_get_policer_profile_id`, `cdx_ingress_enable_or_disable_qos`, `cdx_ingress_policer_modify_config`, `cdx_ingress_policer_stats`. `port_idx >= 32` guard added to `dpa_get_tdinfo` and shift made `1U << port_idx`. `dscp >= ARRAY_SIZE(dscp_vlanpcp_map.dscp_vlanpcp)` guard in `set_dscp_vlan_pcp_map_cfg`._

- [x] **Bonus. Pre-existing modpost section mismatch.**
  `cdx_ctrl_deinit` (.text) called `cdx_cmdhandler_exit` (.exit.text). Dropped the `__exit` attribute from `cdx_cmdhandler_exit`; loadable module gets no real benefit from `.exit.text` here and the cross-section call is now clean. Hidden from earlier builds by `tail -10` truncation; surfaced with `tail -25`.

- [x] **C9. Test ioctl is always compiled in, has broken kzalloc flags.**
  [cdx/dpa_test.c:61-63](cdx/dpa_test.c#L61-L63): `kzalloc(sizeof(struct test_conn_info) * add_conn.num_conn, 0)` — GFP flag is literally `0`, and `num_conn` is unbounded from userspace. [cdx/cdx_dev.c:121-124](cdx/cdx_dev.c#L121-L124) dispatches `cdx_ioc_dpa_connadd` unconditionally (not behind `DPAA_DEBUG_ENABLE`). **Fix:** either gate the handler behind `#ifdef DPAA_DEBUG_ENABLE` like `CDX_CTRL_DPA_GET_MURAM_DATA`, or remove `dpa_test.c` from the Kbuild list entirely. If kept, use `kcalloc(num_conn, sizeof(*conn_info), GFP_KERNEL)` with a sanity bound on `num_conn`.
  _Done (kept-and-fixed): added `CDX_MAX_TEST_CONN=64` sanity cap (real usage = 1), rejected zero/oversize up-front, replaced `kzalloc(size*n, 0)` with `kcalloc(num_conn, sizeof(*conn_info), GFP_KERNEL)`. Correction on the "wired to production" claim I made mid-session: `test_app_init()` is actually **dead code** — `#define ENABLE_TESTAPP 1` in `dpa_app/main.c:18` is commented out, so userspace never calls it. But `testapp.o` is still linked into `dpa_app` and the kernel dispatcher exposes `CDX_CTRL_DPA_CONNADD` unconditionally. See follow-up C9b._

- [x] **C9b. Follow-up: remove the dead testapp scaffolding entirely.**
  Now that C9 is fixed, the test surface is safe but still exposed. Cleaner end-state: (a) drop `testapp.o` from [dpa_app/Makefile](dpa_app/Makefile#L13) and delete [dpa_app/testapp.c](dpa_app/testapp.c) + its extern in [dpa_app/main.c](dpa_app/main.c#L21-L30); (b) gate `CDX_CTRL_DPA_CONNADD` in [cdx/cdx_dev.c](cdx/cdx_dev.c#L121-L124) behind `#ifdef DPAA_DEBUG_ENABLE` like `CDX_CTRL_DPA_GET_MURAM_DATA`. Also moves `cdx/dpa_test.c` compilation under the same guard or drops it from the Kbuild list. Deferred to the userspace review session since (a) is userspace-side.
  _Done — full removal instead of gating._ Kernel: deleted `cdx/dpa_test.c`, removed `dpa_test.o` from `cdx/Kbuild` and `cdx/Makefile`, removed the `CDX_CTRL_DPA_CONNADD` dispatcher case in `cdx/cdx_dev.c`, removed `struct test_flow_info`, `struct test_conn_info`, `struct add_conn_info`, the `CDX_CTRL_DPA_CONNADD` macro, and the `cdx_ioc_dpa_connadd` prototype from `cdx/cdx_ioctl.h`. Userspace: deleted `dpa_app/testapp.c`, removed `testapp.o` from `dpa_app/Makefile`, removed the `ENABLE_TESTAPP` block and `test_app_init` extern from `dpa_app/main.c`, removed the orphan `show_muram_temp` forward decl in `dpa_app/dpa.c`. H10 (the `strncpy_from_user` truncation issue) is now moot since dpa_test.c is gone._

---

## HIGH

- [x] **H1. `cdx_ioc_set_dpa_params` mutates globals without locking.**
  [cdx/dpa_cfg.c:588-719](cdx/dpa_cfg.c#L588-L719). `fman_info` and `num_fmans` are rewritten while other contexts (policer, query, etc.) read them lock-free. Concurrent ioctls → UAF on the old `fman_info`. **Fix:** take a dedicated module-level mutex for the whole config-set operation; audit readers and either take the same mutex or convert to RCU.
  _Done: added `static DEFINE_MUTEX(dpa_cfg_lock)` in dpa_cfg.c and took it for the whole `cdx_ioc_set_dpa_params` body. On entry, reject re-init with `-EBUSY` if `fman_info` is already set — the original code just overwrote and leaked the old pointer, which was the real UAF vector. Converted the three mid-function bare `return -1;` leaks (`cdxdrv_get_fman_handles`, `cdxdrv_init_stats`, `cdx_create_port_fqs` failure paths) into `retval = -EIO; goto err_ret;` so teardown and unlock run. Same for the three goto-err-ret sites that previously left `retval` uninitialized (`cdxdrv_create_ingress_qos_policer_profiles`, `ceetm_init_cq_plcr`, `cdxdrv_set_miss_action`). Reader-during-init race remains theoretical (A2): in practice init runs once at boot before any traffic, so readers never see partial state._

- [x] **H2. IPsec SA key material not zeroed on free.**
  [cdx/cdx_dpa_ipsec.c:205-222](cdx/cdx_dpa_ipsec.c#L205-L222). `cipher_key`, `auth_key`, `split_key` are freed with plain `kfree()`. **Fix:** replace with `kfree_sensitive()` (Linux ≥5.10), or `memzero_explicit(ptr, len); kfree(ptr);`. Track each buffer's length alongside the pointer since `kfree_sensitive` handles that automatically.
  _Done: three key-field `kfree` calls in `cdx_ipsec_sec_sa_context_free` replaced with `kfree_sensitive`. Non-key descriptor fields (`sec_desc_extra_cmds_unaligned`, `rjob_desc_unaligned`) kept as plain `kfree`._

- [x] **H3. IPsec error paths leak DMA mappings.**
  [cdx/cdx_dpa_ipsec.c:1964-1995](cdx/cdx_dpa_ipsec.c#L1964-L1995). On non-zero return from `cdx_ipsec_build_shared_descriptor`, `auth_key_dma` and `crypto_key_dma` are left mapped. Also [cdx/cdx_dpa_ipsec.c:2580-2593](cdx/cdx_dpa_ipsec.c#L2580-L2593) has an explicit `TBD???` comment about leaking the shared descriptor on table-insert failure. **Fix:** single error label that unmaps in reverse of the success order; free the shared-descriptor context via `cdx_ipsec_sec_sa_context_free()` on failure.
  _Done: `cdx_ipsec_create_shareddescriptor` now has a two-label unwind (`err_unmap_crypto` / `err_unmap_auth`) covering the three previous leak paths — crypto-key map failure, default switch case (build_shared_descriptor returning other than 0 or -EPERM), and extended-build failure. `cdx_ipsec_add_classification_table_entry` tracks whether it built the shared descriptor in this call; on failure it clears `SA_SH_DESC_BUILT` so a retry rebuilds cleanly (addresses the `TBD???` without making lifetime assumptions about `pSec_sa_context`, which is owned elsewhere). M7 collapses into H3._

- [-] **H4. Suspicious DMA map-then-immediately-unmap for CAAM descriptor.**
  [cdx/cdx_dpa_ipsec.c:2028-2033](cdx/cdx_dpa_ipsec.c#L2028-L2033). The shared descriptor is mapped, then unmapped, both within the same call site, with no intervening hardware access visible here. If the descriptor's bus address is being cached elsewhere for later use by SEC, this is a DMA use-after-unmap. **Fix:** verify on hardware whether CAAM actually needs the cached DMA handle beyond this call. If yes, keep the mapping alive and unmap on SA teardown; if no, delete the dead `dma_map_single` entirely.
  _Not a bug, correction to the agent's claim:_ `shared_desc_dma` is a local that is never stored or passed anywhere, so there's no use-after-unmap. The pair is a legitimate cache-flush idiom — `dma_map_single(..., DMA_TO_DEVICE)` flushes the CPU-cached writes to `sec_desc` (preheader, PDB, shared_desc) out to memory, and the matching unmap on `DMA_TO_DEVICE` is a no-op that releases bookkeeping. On non-coherent ARM64 this flush is necessary; the SEC engine reads the descriptor later via the handle stored in `dpa_ipsecsa_handle`. Added a comment documenting the intent so a future reader doesn't flag it again._

- [x] **H5. NAT-T SPI array bound is off-by-one.**
  [cdx/cdx_dpa_ipsec.c:2310-2318](cdx/cdx_dpa_ipsec.c#L2310-L2318). `if (arr_index > MAX_SPI_PER_FLOW) goto err_ret;` admits `arr_index == MAX_SPI_PER_FLOW`, one past the array. **Fix:** change to `>=`.
  _Done: `>` → `>=`. `get_free_natt_arr_index` returns `MAX_SPI_PER_FLOW` when the mask is full, so that exact value must be rejected._

- [-] **H6. auto_bridge iterates hash buckets with lock drop between buckets.**
  [auto_bridge/auto_bridge.c:232-251](auto_bridge/auto_bridge.c#L232-L251). `spin_lock_bh(&abm_lock) / spin_unlock_bh` inside the `for (i < L2FLOW_HASH_TABLE_SIZE)` loop. A cached `table_entry` pointer carried across iterations can be freed by a concurrent writer. **Fix:** either hold the lock across the whole scan (check it's not called from a softirq path that would dead-bh), or take references / use RCU for the entries.
  _Not a concrete bug, correction to the agent's claim:_ `table_entry` is rebound each inner iteration via `container_of`, never persisted across outer iterations. The only mutator called inside (`__abm_go_dying`) does not remove the entry from the current bucket — it only flips state/flags, adds to `l2flow_list_wait_for_ack`, and schedules a timer. Hash keys are immutable after insert, so entries never rehash between buckets. The lock-drop between buckets is a deliberate bounded-hold-time design for port-down sweeps that can touch thousands of entries. Concurrent writers serialize on the same lock. Filed-away improvement: switch to `list_for_each_safe` inside each bucket so a future modification that does `list_del` won't silently UAF — but that's forward-hardening, not a current fix._

- [x] **H7. auto_bridge stores `net_device *` without `dev_hold()`.**
  [auto_bridge/auto_bridge.c:210](auto_bridge/auto_bridge.c#L210) and use at [line 139-143](auto_bridge/auto_bridge.c#L139-L143). Pointer persists across a workqueue boundary with no refcount. **Fix:** `dev_hold()` at capture, `dev_put()` when the work completes or the entry is freed. Prefer storing `ifindex` and re-resolving with `dev_get_by_index_rcu()` at use time if the pointer isn't needed for identity.
  _Done: `dev_hold()` added in `add_brevent` (caller already guarantees non-NULL brdev), paired `dev_put()` in the `abm_do_work_send_msg` drain and a new drain in `abm_l2flow_table_exit` so entries pending at module unload are balanced. Also lifted the "skip everything if no L2FLOW_NL_GRP listener" early return — bridge events use RTNL netlink, not abm_nl, and were being starved (plus, once dev_hold was added, a pile-up with no listeners would have indefinitely blocked `unregister_netdevice`). The l2flow msg drain stays gated on abm_nl listeners; the bridge drain runs unconditionally._

- [x] **H8. auto_bridge sysctl is world-writable, triggers state flush.**
  [auto_bridge/auto_bridge.c:1385-1406](auto_bridge/auto_bridge.c#L1385-L1406). `abm_l3_filtering` is mode `0644`; a write calls `abm_l2flow_table_flush()`. `abm_max_entries` (same file, ~1453) accepts any `u32` including 0. **Fix:** set mode to `0600`, or add an explicit `capable(CAP_NET_ADMIN)` check in a custom `.proc_handler`. Add a lower bound on `abm_max_entries`.
  _Correction + done:_ `0644` on proc/sys nodes is owner-writable only (others read-only), not "world-writable" — the agent's phrasing was off. The defense-in-depth concern stands, so `abm_sysctl_l3_filtering` now rejects writes from callers without `CAP_NET_ADMIN`. `abm_max_entries` switched from `proc_dointvec` to `proc_douintvec_minmax` with bounds [1, 1_000_000] — rejects 0 (which silently broke the `abm_nb_entries >= abm_max_entries` gate) and rejects absurd upper values. The timeout/retransmit sysctls stay on `proc_dointvec_jiffies`; they only adjust timing, not state-mutating._

- [x] **H9. Query-snapshot static state is shared and lock-free.**
  Statics for pagination in multiple files — [cdx/cdx_mc_query.c](cdx/cdx_mc_query.c) (mc4/mc6 snapshot globals), [cdx/query_Rx.c:65-140](cdx/query_Rx.c#L65-L140), [cdx/control_ipv4.c:1542-1543](cdx/control_ipv4.c#L1542-L1543), [cdx/control_ipv6.c:716-717](cdx/control_ipv6.c#L716-L717), [cdx/control_vlan.c:315-316](cdx/control_vlan.c#L315-L316), [cdx/control_tunnel.c:714-715](cdx/control_tunnel.c#L714-L715). Two concurrent enumerators corrupt each other's cursors; the walked lists can be mutated concurrently → UAF. **Fix:** move cursor state into the per-open `file->private_data`, or at minimum take the corresponding table lock during the entire snapshot build. List walks in `cdx_mc_query.c` ([lines 29,49,180,202](cdx/cdx_mc_query.c#L29)) must take the same `mc4_spinlocks`/`mc6_spinlocks` the mutators use.
  _Partial done:_
  - `cdx_mc_query.c`: added `mc_query_mutex` serializing MC4/MC6 cursor state, and took the existing `mc4_spinlocks[hash]`/`mc6_spinlocks[hash]` around the inner list walks in `MC{4,6}_Get_Hash_Entries` and `MC{4,6}_Get_Hash_Snapshot`. Now matches the locking the mutators use. Exported the spinlock symbols in `dpa_control_mc.h`.
  - `cdx/query_Rx.c`: added `l2flow_query_mutex` around `rx_Get_Next_Hash_L2FlowEntry`. The list walk itself stays unprotected because the underlying `l2flow_hash_table` subsystem is lock-free on the mutator side too (see `control_bridge.c` — walks and inserts with no lock). That's an architectural fix tied to A2, not fixable from the query path alone.
  - **Follow-up done:** every file with the static-cursor pattern now has a file-local query mutex and single `out:` unwind: `control_ipv4.c` (`ipv4_query_mutex` covers both CT and RT queries), `control_ipv6.c` (`ipv6_query_mutex` covers the CT query), `control_vlan.c` (`vlan_query_mutex` covers both session and stat queries), `control_tunnel.c` (`tnl_query_mutex` covers both tunnel queries), `control_pppoe.c` (`pppoe_query_mutex` covers both session and stat queries), and `query_ipsec.c` (`ipsec_query_mutex` covers both SA queries). Each of the 11 query functions had its multiple return paths converted to a single `goto out;` pattern so the mutex always unwinds on every exit._

- [x] **H10. `strncpy_from_user` truncation not checked.**
  [cdx/dpa_test.c:127,143,187,203](cdx/dpa_test.c#L127). Return value only tested for `== -EFAULT`; positive return equal to buffer size means "truncated, no NUL". **Fix:** `n = strncpy_from_user(buf, src, sizeof(buf)); if (n < 0) return -EFAULT; if (n >= sizeof(buf)) return -ENAMETOOLONG;` and ensure `buf[sizeof(buf)-1] = '\0'` anyway. (May be mooted if C9 removes `dpa_test.c`.)
  _Moot — all four cited sites were in `cdx/dpa_test.c` which C9b deleted._

---

## MEDIUM

- [x] **M1. Multicast listener-count mismatch.**
  [cdx/dpa_control_mc.c:541](cdx/dpa_control_mc.c#L541) enforces `uiNoOfListeners <= MC_MAX_LISTENERS_PER_GROUP` (8), but query output in [cdx/cdx_mc_query.c:60](cdx/cdx_mc_query.c#L60) loops with that bound while writing into `output_list[]` sized at `MC_MAX_LISTENERS_IN_QUERY` (5). A group with 6–8 listeners OOBs the query response buffer. **Fix:** pick one bound, or clamp the loop with `min(listeners, MC_MAX_LISTENERS_IN_QUERY)` and document that queries are paginated.
  _Done, correction on the original claim:_ the existing pagination actually handles 6–8 listeners correctly *provided* `uiListenerCnt` stays in sync with the `bIsValidEntry` flags — but the `(uiListenerCnt - i)` "more to come" test is fragile (any drift between the counter and the flags can either OOB or truncate). Two-part fix: (1) `MC{4,6}_Get_Hash_Entries` now reserves `ceil(MC_MAX_LISTENERS_PER_GROUP / MC_MAX_LISTENERS_IN_QUERY) = 2` cmds per group unconditionally, so the caller's snapshot buffer can never be undersized. (2) `MC{4,6}_Get_Hash_Snapshot` replaces the `uiListenerCnt - i` check with a local look-ahead over `members[]` for the next `bIsValidEntry`, so pagination depends only on the truth of the flag array (which is what's actually walked)._

- [-] **M2. `dev_get_by_name` leaks on error paths (control_vlan).**
  [cdx/control_vlan.c:103-112,123-134](cdx/control_vlan.c#L103-L134). Both deregister and register call `dev_get_by_name` twice but only `dev_put` on the happy path. **Fix:** refcount-balanced goto-out pattern; `dev_put(device)` / `dev_put(parent_device)` only if non-NULL. Audit other control_*.c for the same pattern.
  _Not a bug on re-reading._ Both `device` and `parent_device` are `NULL`-initialized at [line 89](cdx/control_vlan.c#L89). Every `break` in the switch falls through to the `end:` label at [line 199](cdx/control_vlan.c#L199) which already does `if (device) dev_put(...); if (parent_device) dev_put(...);` — the NULL guard correctly handles the DEREGISTER case (which sets only `device`) and every error break in REGISTER. The only paths that bypass `end:` are `QUERY`/`QUERY_CONT`/`default`, all of which return before touching `dev_get_by_name`, so no refs are leaked. Audit of the other three cdx files using `dev_get_by_name` (`devman.c`, `cdx_ehash.c`, `dpa_wifi.c`) found all paths balanced — `devman.c:447` and `:2851` transfer the ref into stored structs with matching `dev_put` on teardown, local uses in `cdx_ehash.c:2832` and `dpa_wifi.c:2315/2812` pair with `dev_put` in the same scope. Agent misread the cleanup flow._

- [x] **M3. Unbounded `sprintf` chain in procfs read handler.**
  [cdx/procfs.c:22-69](cdx/procfs.c#L22-L69). `proc_fqid_stats_read` does `sprintf(buff + len, …)` repeatedly without tracking remaining space against the caller's `size`. **Fix:** migrate to `seq_file` (`single_open` + `seq_printf`) — this is the standard approach and eliminates the issue.
  _Done, plus a bigger issue uncovered:_ the original handler was `sprintf`-ing directly into the `char __user *buff` it received, which is straight-up wrong — that's a user pointer, not a kernel buffer, and on ARM64 with KUAP any dereference would fault. Converted to the standard `seq_file` pattern: `proc_fqid_stats_show` / `proc_fqid_stats_open` / `single_open` / `seq_read` / `seq_lseek` / `single_release`. All `sprintf` calls replaced with `seq_printf`/`seq_puts`. The node pointer flows via `proc_create_data` → `pde_data(inode)` → `single_open`'s private._

- [x] **M4. Kernel pointer leaks in debug output.**
  [cdx/procfs.c:167](cdx/procfs.c#L167) uses `%px`. [cdx/dpa_cfg.c](cdx/dpa_cfg.c) has ~10 debug `printk("…%p…", kernel_ptr)` sites around lines 59, 79, 100, 101, 401, 421, 517, 558, 565, 571. Gated by `DPA_CFG_DEBUG` / `CDX_DPA_DEBUG`, but still: if ever enabled, defeats KASLR. **Fix:** bulk replace `%p` → `%pK` and `%px` → `%pK` in debug-only prints; remove gratuitous pointer dumps.
  _Scoped fix:_ Modern kernel `%p` is hashed by default since 4.15 (and always-on default since ~5.x), so the agent's "defeats KASLR" claim only held if `no_hash_pointers` is passed on the cmdline. The one real unconditional leak was the single `%px` in `procfs.c:164` — that always prints raw regardless of `kptr_restrict`. Changed to `%pK`. Also changed the production-path pointer dumps in `dpa_cfg.c` (the four `display_*` helpers that run every SET_PARAMS ioctl, plus the `#if 1//def DPA_CFG_DEBUG` site that's effectively always-on) from `%p` → `%pK` so `kptr_restrict=2` forces them to zero. Debug-gated-only `%p` sites left alone (`%p` is already safe under default config; would be defense-in-depth but not security-blocking). `DPA_ERROR` sites printing `finfo->pcd_handle` left as `%p` because that value is user-supplied, not a kernel address._

- [x] **M5. `nlh->nlmsg_type` signedness / missing default.**
  [auto_bridge/auto_bridge.c:494-560](auto_bridge/auto_bridge.c#L494-L560). `type` is `int`, compared `>= L2FLOW_MSG_MAX`; `nlmsg_type` is `__u16` so currently safe, but the switch has no `default` arm. **Fix:** declare `type` as `u16`, add a `default: err = -EINVAL; goto out;` to the switch for protocol hygiene.
  _Done: `type` narrowed to `u16` matching `nlmsg_type`'s underlying type; added `default: err = -EINVAL; break;` to the switch._

- [x] **M6. auto_bridge module-exit busy-loop.**
  [auto_bridge/auto_bridge.c:1109-1125](auto_bridge/auto_bridge.c#L1109-L1125). `abm_l2flow_table_wait_timers` spins with `schedule()` until all buckets empty. Module unload can hang indefinitely. **Fix:** cancel timers synchronously (`timer_shutdown_sync` per entry) during exit, then a single empty-check instead of a loop.
  _Scoped fix._ On re-reading, the loop actually drains quickly in practice — `abm_l2flow_table_flush` sets `FL_DEAD` on every entry and triggers `__abm_go_dying` for any whose timer it could cancel or that were in `STATE_FF`; entries whose timers already fired will run their callback soon and free themselves (since `__abm_go_dying` now takes the DEAD-branch and calls `abm_l2flow_del`). The "hang indefinitely" claim was pessimistic; the real bugs were (a) bare `schedule()` gives no yield pressure and can hot-spin, (b) no deadline guard if timer firing goes wrong. Replaced with a 5-second bounded wait using `schedule_timeout_uninterruptible(1)` (sleeps one jiffy instead of busy-yielding), plus a `pr_warn` on timeout. The proper `timer_shutdown_sync`-per-entry fix is trickier than the agent suggested (callback race on the embedded `timer_list` when the entry is freed); this improvement fixes the observable symptom without introducing that race._

- [x] **M7. `cdx_ipsec_add_classification_table_entry` explicit TBD leak.**
  Same issue as H3 but with a self-acknowledged `TBD???` comment at [cdx/cdx_dpa_ipsec.c:2586](cdx/cdx_dpa_ipsec.c#L2586). Track separately so it gets a real fix rather than a move.
  _Done as part of H3 — SA_SH_DESC_BUILT now rolls back on error._

---

## LOW / Hardening

- [x] **L1. Jenkins hash used where collision DoS matters.**
  [cdx/jenk_hash.h](cdx/jenk_hash.h). Lookup2 is non-cryptographic; if an attacker controls any of the 5-tuple feeding the EHASH, they can craft colliding keys and chain a single bucket → CPU DoS in lookups. **Fix:** switch to `siphash_*_to_u32()` (in `<linux/siphash.h>`) with a random per-module key.
  _Scope check first:_ `compute_jenkins_hash` turned out to be called in exactly one place — `cdx/control_bridge.c:330` — indexing the kernel's internal `l2flow_hash_table[]`. That's a software-only lookup; the FMAN EHASH microcode contract was not involved. So normal C fix. _Done:_ added `static hsiphash_key_t l2flow_hashkey __read_mostly;` at file scope, initialized once in `bridge_init` via `get_random_bytes`, and replaced the hash call with `hsiphash(&l2flow, sizeof(struct L2Flow), &l2flow_hashkey)`. `cdx/jenk_hash.h` deleted (no other users). An attacker choosing source/dest MACs, VLAN tags, ethertype, or session_id can no longer precompute colliders because the key is boot-random and SipHash is algorithmically collision-resistant._

- [x] **L2. `strcpy` into equal-sized `IF_NAME_SIZE` buffers.**
  [cdx/control_bridge.c:362-363](cdx/control_bridge.c#L362-L363), [cdx/control_vlan.c:295-296](cdx/control_vlan.c#L295-L296), [cdx/control_pppoe.c:500-506](cdx/control_pppoe.c#L500-L506), [cdx/control_ipv4.c:1650,1659](cdx/control_ipv4.c#L1650), [cdx/control_tunnel.c:819](cdx/control_tunnel.c#L819), [cdx/dpa_cfg.c:311](cdx/dpa_cfg.c#L311). Kernel `net_device->name` is guaranteed NUL-terminated so these are mostly benign, but command-sourced names aren't guaranteed. **Fix:** `strscpy` everywhere; it's the modern canonical form.
  _Done, broader sweep:_ all `strcpy` uses across `cdx/` converted to `strscpy(dst, src, sizeof(dst))` — the originally-flagged sites plus `cdx/control_vlan.c:436-437` (the stat query mirror), `cdx/control_bridge.c:368-369`, `cdx/query_Rx.c:63-64`, `cdx/procfs.c:123/128/133/138`, `cdx/dpa_cfg.c:337`, `cdx/dpa_wifi.c:2843`. All destinations are fixed-size array fields so `sizeof(dst)` yields the right bound (and tracks future size changes automatically)._

- [x] **L3. `sprintf` into small fixed name buffers (procfs).**
  [cdx/procfs.c:224,226](cdx/procfs.c#L224). **Fix:** `snprintf(node->name, sizeof(node->name), …)`.
  _Done alongside M3._

- [x] **L4. `proc_create("fci", 0, …)`.**
  [fci/fci.c:542](fci/fci.c#L542). Mode `0` is fragile — should be explicit `S_IRUSR` or similar. Not a security hole (proc default is root-only), but code hygiene.
  _Done: mode `0` → `0444` (world-readable, no write). The file just exposes stats; readable by any user is fine._

- [x] **L5. Unimplemented ioctl stub declarations.**
  [cdx/cdx_ioctl.h:317-321](cdx/cdx_ioctl.h#L317-L321). `cdx_ioc_create_mc_group`, `cdx_ioc_add_member_to_group`, `cdx_ioc_add_mcast_table_entry` declared without implementations. Not wired into current dispatcher. **Fix:** remove the prototypes to eliminate the land mine.
  _Done, broader cleanup:_ removed the three stub prototypes plus the entire supporting cast that was equally dead: `struct QoSConfig_Info` + `CDX_CTRL_DPA_QOS_CONFIG_ADD`, `struct add_mc_group_info` + `CDX_CTRL_DPA_ADD_MCAST_GROUP`, `struct dpa_member_to_mcast_group` + `CDX_CTRL_DPA_ADD_MCAST_MEMBER`, `struct add_mc_entry_info` + `CDX_CTRL_DPA_ADD_MCAST_TABLE_ENTRY`. All were defined only in `cdx_ioctl.h` and referenced nowhere else — same pattern as C9b, no userspace users, no kernel dispatch, pure dead ABI surface. Also note: the removed QOS macro was colliding with (the also-now-removed) `CDX_CTRL_DPA_CONNADD` on command number 3._

- [x] **L6. Inconsistent endian conversion in reassembly release.**
  [cdx/cdx_reassm.c:150-172](cdx/cdx_reassm.c#L150-L172). `buf.hi = list->addr_hi;` is not converted while `buf.lo = cpu_to_be32(list->addr_lo);` is. Either both should be converted or neither — the asymmetry is a bug-in-waiting. **Fix:** pick a canonical byte order for `struct bm_buffer` in this path and be consistent; add a comment stating the convention.
  _Not actually a bug, fix is cosmetic:_ `struct ip_reassembly_frag_list.addr_hi` is a `uint8_t` (single byte, no endian applicable), and `struct bm_buffer.hi` is `u16` in host order. `buf.hi = list->addr_hi` zero-extends u8 → u16 correctly on LE ARM64. The apparent asymmetry is field-type mismatch, not endian inconsistency. However the `cpu_to_be32`/`cpu_to_be16` calls on reads from an FMAN-populated (BE) struct are semantically misnamed — they're byte-swaps to decode BE into host order, so should be `be32_to_cpu`/`be16_to_cpu`. On LE those are the same bytes; the rename documents intent and will behave correctly if anyone ever cross-compiles this for a BE target. Applied the rename in both the debug print and the release path, with a comment noting the source is BE from microcode._

---

## Corrections to the original review

These were flagged as "critical" by the deep-dive agents but don't hold up on verification — leaving here so we don't chase them.

- [-] **X1. "256-byte memset + partial fill = info leak" in `control_ipv4.c:1231` / `control_ipv6.c:170`.**
  False positive. `memset(p, 0, 256)` zeros the buffer *before* the partial fill, so uninitialized bytes that get copied back are zeros, not kernel stack. No leak.

- [-] **X2. "strcpy IF_NAME_SIZE → IF_NAME_SIZE overflows" in multiple control_*.c.**
  Downgraded to L2. Kernel net_device names are guaranteed NUL-terminated within `IFNAMSIZ` (16), so when the source is `dev->name`, strcpy is bounded. Stays a hygiene issue, not a corruption bug.

---

## Architectural themes

Not single issues — broader patterns worth an agenda item each.

- [ ] **A1. Every external field needs a bounds check at its entry point.**
  Hardware descriptors, netlink attributes, ioctl structs, and kernel-internal state all look identical in this code. A pass that tags trust boundaries (comments, helper macros, or just discipline) would prevent a whole class of the above.

- [ ] **A2. Concurrency is assumed, not enforced.**
  Globals in `dpa_cfg.c`, static cursors in every `control_*.c` snapshot path, lock-drop iteration in `auto_bridge.c`. Needs a concurrency model spelled out per subsystem (which lock protects which data, which contexts run each function).

- [ ] **A3. Error paths don't unwind.**
  Recurring leak-on-failure pattern for DMA mappings, hash entries, device refs. A single-label goto-out idiom (with a counter/flag for "how far did init get") would catch most of these.

- [~] **A4. Debug code is production code.**
  `dpa_test.c` is always compiled in (C9). Debug `%p` is one Kconfig flip from leaking KASLR (M4). `cdx_deinit_ip_reassembly` is a `printk("implement this")` stub (C5). Either delete or `#ifdef`-gate.
  _Mostly resolved:_ `dpa_test.c` deleted entirely (C9b). `cdx_deinit_ip_reassembly` at least stops the kthread now (C5); full DPAA teardown still TODO but no longer leaves code-freed-while-kthread-running. Remaining: the `%p`/`%px` debug prints under M4._

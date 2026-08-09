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

---

## Open

- [ ] **A9. Tunnel TX encap never offloads — ucode 210.10.1 `INSERT_L3_HDR` punts unconditionally.**
  The completed A9 work (RX decap offload for 6o4+4o6, the `ip6_tunnel.c`
  underlying_iif RX stamp in patch 030, the second 10G port in
  `cdx_cfg.xml`, patch 099 shipped, the honest TX tripwire test, the
  occupancy-golden re-oracle) is archived. The residual is external: the
  encap ehash entry is byte-perfect in DDR and matches in hardware (per-entry
  stats count the packets), but the HM chain aborts at `INSERT_L3_HDR(0x44)`
  and punts every frame to the exception path. Every other opcode in the
  chain is proven working in live decap/forward chains; `create_tunnel_insert_hm`
  is line-identical to the NXP reference and the ucode is md5-identical to
  NXP's ASK release, so the reference shipped the same untested path.
  **Disposition: NXP-support ticket** (memory `a9-insert-l3-hdr-ucode-blocked`).
  Practical impact is CPU headroom only — kernel sit encap sustains 9.15 Gbit/s
  and decap is hardware-offloaded. Keep open as the tracking anchor.

- [ ] **H2-r. SA query snapshot leaks full key material through plain `kfree`.** (reopened)
  The primary H2 fix (`kfree_sensitive` on cipher/auth/split keys at
  [cdx/cdx_dpa_ipsec.c:461-470](cdx/cdx_dpa_ipsec.c#L461)) is correct, but the
  same class survives at a sibling site the closure claimed clean:
  [cdx/query_ipsec.c:181,188](cdx/query_ipsec.c#L181) memcpy the full
  `cipher_key[64]`/`auth_key[64]` into the `SAQueryCommand` snapshot, which is
  released with `Heap_Free` (= plain `kfree`, [cdx/cdx_hal.c:67-69](cdx/cdx_hal.c#L67))
  at query_ipsec.c:278/299/322. Any SA-QUERY therefore leaves complete key
  copies in freed slab — exactly what H2 set out to eliminate. Fix: zeroize the
  snapshot (or route it through `kfree_sensitive`) before free. The stat
  snapshot carries no keys and is fine.

- [ ] **A3e-r. `dpa_add_eth_if` leaks a netdev refcount and iface stats on error paths.** (reopened)
  The A3e helpers (policer/discard-mask/CEETM teardown) landed correctly, but two
  acquisitions inside the same cascade are released on no error path:
  (1) `get_eth_iface_info` takes a netdev ref via `dev_get_by_name`
  ([cdx/devman.c:472](cdx/devman.c#L472)); no `err_ret*` label does the matching
  `dev_put`, so every failure after devman.c:2076 leaks it — later surfacing as
  the `unregister_netdevice: waiting for ethX to become free` hang (the internal
  returns at :547/:568 leak too). (2) `alloc_iface_stats` (:2104) kzallocs
  `last_stats` and consumes a freelist slot with no error-path `free_iface_stats`,
  and the stale pointer is already published via `dpa_set_eth_ifinfo` (:2108).
  Related: `free_stats` ([:1873](cdx/devman.c#L1873)) has no `IF_TYPE_ETHERNET`
  arm, so even the normal release path leaks `last_stats` on every eth removal.
  A3 (umbrella) stays open until this is fixed. Fix: `dev_put` +
  `free_iface_stats` + `dpa_set_eth_ifinfo(priv, NULL)` in the cascade, plus an
  eth arm in `free_stats`.

- [ ] **M15-r. Mcast replication write-barrier missing on the UPDATE-path chain publish.** (reopened)
  M15's `dev_mc_add/del` sequencing and the `wmb()` before the *initial-ADD*
  ehash publish ([cdx/cdx_ehash.c:1174](cdx/cdx_ehash.c#L1174)) are correct, but
  `cdx_exthash_update_first_mcast_member_addr` publishes a freshly built listener
  entry into a *live* chain with no barrier between the entry-fill stores and the
  `first_member_flow_addr` store at
  [cdx/dpa_control_mc.c:1242](cdx/dpa_control_mc.c#L1242); the intervening
  spinlock is acquire-only and orders nothing for FMAN. UPDATE is the only way to
  reach the 6-8 listener case, so this is the same "CC ticks, listener TX FQ
  stays 0" hazard for any listener added to an existing group. Fix: `wmb()` before
  the :1242 publish; review the REMOVE unlink at :1176-1196 (lower risk).

- [ ] **N2. `/proc/ucode_frag/*` read handlers `sprintf` into the `__user` buffer.**
  `stats_read` ([cdx/cdx_ehash.c:3061](cdx/cdx_ehash.c#L3061)) and
  `buff_alloc_test` (:3084) `sprintf` directly into `char __user *buf` with no
  `copy_to_user` — the exact KUAP/PAN-broken pattern M3 fixed in procfs.c. Both
  are registered world-readable (0444) as `/proc/ucode_frag/stats` and
  `/proc/ucode_frag/test_alloc_buf_n_free`, created unconditionally at cdx init,
  so any local user's `cat` makes the kernel write through a user pointer (PAN
  fault/oops = local DoS). `buff_alloc_test` additionally runs 128 bman
  acquire/release cycles per read. Fix: same seq_file conversion as M3.
  (Independently flagged by two audit passes — high confidence.)

- [ ] **N3. `cdx_get_ipsec_fq_hookfn` is never cleared — a failed init after ipsec wedges all future cdx loads.**
  The kernel-side hook (patch 010, `dpaa_eth_common`) set by `ipsec_init` has no
  unregister API, and `dpa_register_ipsec_fq_handler` refuses re-registration.
  If `CMD_INIT(ipsec)` succeeds but a later `CMD_INIT` (mc4/mc6/rtp_relay) fails,
  the failed load leaves the hook pointing into freed module text and every
  subsequent cdx load fails permanently at `ipsec_init` until reboot. Crash
  reachability is near-zero (the hook needs offloaded SA state that can't exist
  without cdx/cmm alive) and cdx is persistent in practice, so this didn't block
  A21's closure — but it deserves an unregister-on-deinit fix. (Found by the
  tunnel/route audit pass.)

- [ ] **N4. `dpaa_vwd_driver_init` leaks the eth0 netdev ref on its `err7` unwind.**
  `get_eth_priv("eth0")` ([cdx/dpa_wifi.c:2944](cdx/dpa_wifi.c#L2944)) takes a
  netdev ref held for VWD lifetime; the init-failure path at `err7:` (:2986) does
  `vwd.eth_priv = NULL` without `dev_put(vwd.eth_priv->net_dev)`, so any failure
  of the tx-bpool/xmit-hook/stats setup leaks the ref permanently. This also
  refutes M2's closure claim that "the other three callers are all balanced."
  Fix: one `dev_put` before nulling. (Found by the cmm/cdx-misc audit pass.)

- [ ] **N5. `cdx_ipsec_create_shareddescriptor` tests DMA maps with `!addr` instead of `dma_mapping_error()`.**
  [cdx/cdx_dpa_ipsec.c:2240,2250,2260](cdx/cdx_dpa_ipsec.c#L2240) check
  `if (!auth_key_dma)` / `if (!crypto_key_dma)`; a real mapping failure returns
  `DMA_MAPPING_ERROR` (~0UL, truthy) and sails past the guard, so the H3 unwind
  never fires on an actual map failure. Fix: `dma_mapping_error(dev, addr)`.
  (Adjacent finding from the H-series audit pass.)

- [ ] **N6. `abm_retransmit_delay` sysctl accepts 0, spinning the self-requeuing retransmit work.** (minor)
  Root-only footgun, not a security issue — the H8 bounds were applied to
  `abm_max_entries` but `abm_retransmit_delay` still accepts 0. Fix: min bound 1.
  (Adjacent finding from the H-series audit pass.)

---

<a name="archive"></a>
# Archive

Closed items, one line each. Detail lives in the referenced commit and in this
file's git history.

## Gating
- **G1.** `/dev/cdx_ctrl` ioctl dispatcher was ungated — added a CAP_NET_ADMIN check ahead of the command-table lookup (_815a0ca_).
- **N1.** FCI (`NETLINK_FF`), abm (`NETLINK_L2FLOW`) and the NETLINK_KEY ipsec-offload bus (patch 040) had no capability gate, bypassing G1 — per-message `netlink_capable(skb, CAP_NET_ADMIN)` (init userns) in all three input handlers; unprivileged senders now get NLMSG_ERROR/-EPERM (FF/L2FLOW) or a silent drop (KEY sends no reply) before any parsing. Covered by `test_fci_netlink_caps.py` (uid-drop + unmapped-userns cases; agent /fci/send and /netlink/send grew `uid`/`userns`).
- **G2.** Single-open gate had a mis-rejection window — replaced with a single atomic_cmpxchg(1→0).

## Critical
- **C1.** auto_bridge L2FLOWA_IP_SRC/DST memcpy trusted attacker nla_len into a 16-byte union — nla_policy caps NLA_BINARY len to the field size.
- **C2.** FCI inbound trusted sender nlmsg_len for OOB-sized payloads — validate fci_msg->length against skb->len and FCI_MSG_MAX_PAYLOAD.
- **C3.** IPR release loop walked FMAN-supplied num_entries unbounded — cap against reassly_bp->size / entry-size before the release loop.
- **C4.** IPR ref_count (uint8_t) could wrap on double-decrement — zero-check and drop before decrementing.
- **C5.** IPR deinit was a stub leaving the timer kthread and FQs live (UAF on unload) — full kthread-stop + FQ retire/oos/destroy + bpool free.
- **C6.** dpa_cfg scaled allocations by attacker-influenced counts — sanity caps + kcalloc, num_fmans==0 rejected, sub-counts allow legit zero.
- **C7.** Six fm_index checks used `> num_fmans` (one index OOB) — all flipped to `>=`.
- **Bonus.** cdx_ctrl_deinit (.text) referenced cdx_cmdhandler_exit (.exit.text) — dropped __exit so the section reference is legal.
- **C8.** queue_no/port_idx/dscp used as unchecked array indices from userspace — entry bounds checks added in dpa_cfg.c and cdx_ehash.c.
- **C9.** Test ioctl kzalloc overflow — mooted: the buggy code was deleted outright with the testapp scaffolding (see C9b), not sanity-capped (_815a0ca_).
- **C9b.** Dead testapp scaffolding remained compiled-in — deleted dpa_test.c, testapp.c and the CDX_CTRL_DPA_CONNADD ioctl + structs (moots H10).
- **C10.** Raw netlink `.input` handlers get no core nlmsg_len/length validation — FCI's cap-fail `-EPERM` ack and `fci_outbound_err` echoed `nlmsg_len`-indexed bytes out of the request skb (unprivileged heap over-read / nlmsgerr-reservation overflow), and `ipsec_nlkey_rcv` memcpy'd per-command structs out of a possibly-short skb. Bounded all against the real skb: `nlmsg_len ≤ NLMSG_ALIGN(skb->len)` before the ack (libfci sends the NLMSG_ALIGN'd length), header-only echo in `fci_outbound_err`, per-command `payload_len` guards in `ipsec_nlkey_rcv`. The cap-fail `-EPERM` ack also trims its echo to `skb->len` so the ≤3 alignment-pad bytes `netlink_sendmsg` never wrote aren't disclosed to an unprivileged caller (CWE-200). Distinct from C2 (payload-parse path).

## High
- **H1.** Concurrent CDX_CTRL_DPA_SET_PARAMS ioctls could UAF fman_info — dpa_cfg_lock mutex, -EBUSY re-init reject, err_ret unwind (_815a0ca_).
- **H3.** IPsec shared-desc error paths leaked auth/cipher key DMA maps — two-label unwind + SA_SH_DESC_BUILT rollback on add failure.
- **H4.** CAAM shared-desc map-then-unmap suspected bug — wontfix: deliberate cache-flush idiom; SEC reads the desc via the ipsecsa handle; documented.
- **H5.** NAT-T SPI slot check used `> MAX_SPI_PER_FLOW`, letting the "full" sentinel index the array — reject with `>=`.
- **H6.** auto_bridge per-bucket lock-drop iteration suspected UAF — wontfix: no state crosses the drop; entries rebound per bucket under lock.
- **H8.** abm sysctls lacked a capability gate and abm_max_entries accepted 0 — CAP_NET_ADMIN check + proc_douintvec_minmax bounds 1..1e6.
- **H9.** Static query-snapshot cursors raced concurrent enumerators — per-file query mutexes + mc bucket spinlocks; mutator walks tracked under A2.
- **H10.** strncpy_from_user truncation unchecked — mooted: all four sites lived in dpa_test.c, deleted with the C9b test-scaffolding removal.
- **H7 (partial).** net_device stored without dev_hold — dev_hold/balanced dev_put added; the drain's sleep-under-spinlock residual closed as H7-r.
- **H7-r.** `rtnl_lock()` under `spin_lock_bh(&abm_lock)` on the *regular* abm workqueue drain (not exit-only as the in-code comment claimed) — `bridge_list_rtevent` is now spliced to a local list under the lock and `rtmsg_ifinfo`/`dev_put` run after unlock (GFP_KERNEL); concurrency comment corrected. Exercised by `test_abm_port_flap.py` under PROVE_LOCKING/DEBUG_ATOMIC_SLEEP.
- **H2 (partial).** IPsec keys not zeroed on free — kfree_sensitive on the SA-context keys; the query-snapshot sibling leak is reopened as H2-r.
- **H11.** `abm_fdb_can_expire` (a `br_fdb_cleanup` workqueue callback — process context, BH enabled) took `abm_lock` with plain `spin_lock`, violating the BH-disable discipline it shares with the softirq-context timer/EBT paths — a self-deadlock / `{SOFTIRQ-ON-W}` lockdep hazard. All three sites switched to `spin_lock_bh`/`spin_unlock_bh`.

## Medium
- **M1.** Query of 6-8 listener groups OOB'd the reply buffer — pagination reserves 2 cmds/group, pages via bIsValidEntry look-ahead.
- **M2.** dev_get_by_name leaks (control_vlan) — wontfix: control_vlan paths are NULL-guarded and balanced; a missed dpa_wifi sibling is filed as N4.
- **M3.** Unbounded sprintf chain in the fqid_stats procfs handler — converted to seq_file; two ucode_frag siblings of the same class filed as N2.
- **M4.** %px and raw %p handle prints in cdx debug output — %px removed, sensitive handle prints flipped to %pK; hashed %p left per policy.
- **M5.** auto_bridge netlink dispatch used signed nlmsg_type with no default arm — narrowed to u16, unknown types return -EINVAL.
- **M6.** auto_bridge exit hot-spun on bare schedule() waiting for l2flow drain — bounded 5s wait with 1-jiffy sleeps and pr_warn on timeout.
- **M7.** IPsec table-entry add left the shared descriptor dangling on failure (explicit TBD) — SA_SH_DESC_BUILT rolled back, entry/ct/info freed on unwind.
- **M8.** Full-group mcast delete unlinked shared list state lock-free — list_del now under the bucket spinlock, sleeping HW teardown after unlock.
- **M9.** mcast ADD unwind could leak pCtEntry/pRtEntry if a future path failed after wiring them — err_ret now frees both, defense in depth (_c23817b_).
- **M10.** Cdx_GetMcastMemberId returned ids stale across dropped bucket locks — mc_mutators_mutex serializes ADD/REMOVE/UPDATE at the dispatcher.
- **M11.** GetMcastGrp returned a group pointer freeable after the bucket lock dropped — the same mc_mutators_mutex closes the window.
- **M12.** REMOVE fast path keyed on count alone; wrong names wiped the group — every listener pre-validated, mismatch returns ERR_MC_CONFIG.
- **M13.** Duplicate names in REMOVE still tripped the count-match full delete — member_id bitmap dedupes, repeats rejected with ERR_MC_CONFIG.
- **M14.** cmm_parse_rtattr logged rta->rta_len after loop exit (OOB read on a truncated rtattr) — parser shared with the ASAN fuzzer, logs remaining length only.
- **M15 (partial).** FMAN PCD didn't replicate IPv4 mcast to listener subifs — dev_mc_add/del sequencing + wmb before the ADD-path publish; UPDATE-path barrier reopened as M15-r.

## Low / Hardening
- **L1.** Fixed-seed Jenkins/jhash on attacker-chosen L2-flow keys (cdx + auto_bridge) — per-boot-keyed hsiphash/siphash; jenk_hash.h deleted (_89e5b32_ + _bf8c453_).
- **L2.** strcpy into equal-sized IF_NAME_SIZE buffers across cdx control paths — full sweep to strscpy(dst, src, sizeof(dst)); none remain.
- **L3.** sprintf into small fixed name buffers in cdx procfs — snprintf bounded by sizeof(node->name).
- **L4.** proc_create("fci", 0, ...) left permissions implicit — mode set to 0444, read-only intent explicit.
- **L5.** Dead unimplemented ioctl prototypes in cdx_ioctl.h — stubs plus supporting structs/macros removed (incl. a cmd-number collision).
- **L6.** Reassembly release misnamed cpu_to_be* on BE-to-host reads — renamed be*_to_cpu, u8→u16 zero-extend documented; no-op on LE.
- **L7.** UBSAN array-bounds on the flex-array subscript in create_ethernet_hm — store converted to pointer arithmetic, semantics unchanged.
- **L8.** cmm sig_term_hdlr logged benign ENOENT for an already-removed pidfile — both cleanup sites report only errno != ENOENT.

## Corrections to the original review (wontfix / not-a-bug)
- **X1.** "256B memset + partial fill info leak" — wontfix: memset(p,0,256) zeros the full rbuf before the Get_Timeout partial fill; surplus bytes are zeros.
- **X2.** "strcpy IF_NAME_SIZE overflow" — wontfix/fixed: downgraded to L2 and swept to strscpy (_89e5b32_); all cdx name copies now dst-size bounded.
- **X3.** "dpaa_eth_refill_bpools suspected leaks" — wontfix: the skb backpointer lives in the BMan hardware-owned frag pool kmemleak can't scan; error paths free cleanly.
- **A12.** "PPPoE RX-decap missing classifier install" — wontfix: inner udp4/tcp4 dist precedes pppoe_dist; the PPPoE strip is an HM chained on the inner CT entry, not a table.
- **A15.** "cmm has no incoming xfrm subscription" — wontfix: the af_key km hook broadcasts every SA event on NETLINK_KEY grp1 (before the no-PF_KEY early-return); cmm binds it via libfci. On-DUT restart experiment (2026-08-09) confirmed no resync gap; only cmm-downtime events are lost, recoverable via `ip xfrm state flush`.

## Architectural themes
- **A1.** External command fields validated ad hoc per cmdproc — the whole FCI bus + cdx ioctl dispatcher routed through one validator-table idiom (2 latent bugs fixed en route).
- **A1a.** No shared bounds-check idiom — added cdx_cmd_validator.{h,c}: spec table + cdx_dispatch_cmd (lookup, [min,max] length, validate, then handle) (_cf1fa1b_).
- **A1b.** control_vlan migrated as the prototype — VlanCommand length + action validator, cmdproc reduced to a dispatch tail-call (_f2f3a82_, _c4d3965_).
- **A1c.** Remaining 13 cmdprocs (~120 codes) migrated to validator tables with per-command length bounds.
- **A1d.** /dev/cdx_ctrl ioctl switch replaced by a table-driven cdx_ioctl_table[] with CAP_NET_ADMIN gate and ENOTTY on unknown cmd (_ed082ea_).
- **A1e.** Per-subsystem inner cmd_code switches removed — each cmdproc is a one-line dispatch tail-call.
- **A2.** Locking assumptions were implicit per-file folklore — top-of-file Concurrency: blocks + sparse __must_hold() across cdx/abm/fci (_d99bb62_).
- **A3a.** IPR init leaked bpools/kthread/FQs on failure — nested unwind cascade; deinit tears down FQs via private ipr_fqs[] tracking (_b5a7bf8_ + _78ac2af_).
- **A3b.** fqid procfs mkdirs left earlier dirs on later failure — nested err_remove_* cascade; deinit proc_removes the whole tree.
- **A3c.** l2flow_cache leaked when brroute_cache creation failed — destroy+NULL l2flow_cache on that error path.
- **A3d.** abm_init leaked earlier subsystems on later init failure — goto cascade runs each matching _fini/_exit in reverse order.
- **A4.** Debug scaffolding shipped as production — dpa_test.c removed, IPR deinit stub implemented, %px/%p prints flipped to %pK.
- **A5.** Sanitizer bring-up surfaced 4 vendored-kernel bugs (qbman, sdk_dpaa, sdk_fman, netlink) — fixed as patches 090-093, shipped to both images.
- **A5a.** qbman dpa_alloc_new kmalloc'd GFP_KERNEL under spin_lock_irq — patch 090 preallocates all list nodes before the lock, frees leftovers after.
- **A5b.** dpa_get_channel held a spinlock over qman_alloc_pool (sleeps) — patch 091 swaps it for a mutex; the only caller is probe-time process context.
- **A5c.** A shared lockdep class made FmPcdLockTryLockAll's inner locks look recursive — patch 092 adds a SINGLE_DEPTH_NESTING try-lock variant.
- **A5d.** NETLINK_L2FLOW=33 got a NULL lockdep name from the 0..32-only cb_mutex string table — patch 093 names indices 32 (KEY) and 33 (L2FLOW).
- **A6.** Tunnel handlers walked 16-byte FCI name fields as C strings (KASAN OOB) — HASH_TUNNEL_NAME/M_tnl_get_by_name take maxlen, strncmp lookup (_9f9b69d_).
- **A7.** Fuzzer only hit dispatcher length checks — 30 payload-body mutation cases (10 cmds × all_ff/high_enum/no_nul_str) with a splat oracle (_0bf177b_).
- **A8.** cdx never freed its CAAM job ring, tripping the caam_jr busy check on reboot — idempotent release from the deinit chain + reboot notifier.
- **A9 (decap portion).** TX-offload test was a false positive (stale 165 Mbps baseline) — reframed as a software-path tripwire; RX decap proven offloaded (6o4+4o6) after the ip6_tunnel iif stamp + second 10G port wired. TX-encap residual stays open as A9.
- **A10.** RouteEntry.id stored the U32 wire route id as U16, silently truncating on ADD — widened to U32; API/hash/wire already U32 (_d61c50f_).
- **A11.** FORTIFY warned on memcpy into [0]-tails in fm_ehash.h (patch 099 not in SRC_URI) — all 7 tails now C99 flex arrays, recipe ships 099 (_e499b98_).
- **A13.** Vendored CPE_FAST_PATH hunk took rtnl_lock under all_ppp_mutex — NEWLINK now sent after mutex drop via dev_hold (patch 070).
- **A14.** H2 key-zeroing was unobservable — test-image-only probe snapshots the post-kfree_sensitive cipher_key to /proc/cdx (_5358b5b_).
- **A16.** NAT-T fast-path push threw away the classification-entry rc, reply stayed NO_ERR — rc captured and propagated as ERR_CREATION_FAILED (_d5be3ae_).
- **A17.** SET_KEYS wrote through sa before the NULL check — stale-sagd NULL-deref; assignment moved after the ERR_SA_UNKNOWN return (_d5be3ae_).
- **A18.** NAT-T push wrote sa->ct->natt_in_refcnt after ignoring add-entry failure — now bails to err_ret; the callee frees+NULLs sa->ct (_d5be3ae_).
- **A19.** Three SA leaks (procfs wrapper on mkdir-fail, release-path wrapper, shdesc_mem) — symmetric kfrees added (_cd0548c_).
- **A20.** ipsec_nlkey_rcv took x->lock without BH disable vs the softirq xfrm_timer — all three NLKEY pairs flipped to spin_lock_bh (patch 040, _d5be3ae_).
- **A21.** Deinit from a failed init crashed in qman_ceetm_sp_release(lni->sp=NULL) — SP claim passed explicitly + NULL-guarded; init failure now propagates (_d236aa3_).
- **A22.** gateway-dk cdx_cfg.xml OH portid 8/9 tripped the cdx_sp.xml espschema `$logicalportid lt 9` policing gate, breaking ESP recognition — restored to NXP 9/10 (_d5be3ae_).
- **A23.** ipsec_bp registered but never seeded — SEC hit BPDERR, silent drops; dpaa_bp_alloc_n_add_buffs(512, act_skb=1) added with unwind (_d5be3ae_).
- **A24.** SEC GCM per-DECO PDB.seq divergence broke RFC4303 anti-replay (no cdx-side fix) — GCM/GMAC refused at SA install (kernel NLKEY gate + cdx); CBC+HMAC/CCM still offload.
- **A25.** AES-128-CTR lacked the RFC 3686 nonce trim and CTR PDB fields — comb_mode/extra_size=4 trim + ctr_nonce/ctr_initial=1 in both PDBs (_d5be3ae_).
- **A26.** ASK patch stack compiled with ~52 warnings (missing prototypes, bad formats, one wrong-signature extern) — 010/040 regenerated warning-free (_3b93e0e_).

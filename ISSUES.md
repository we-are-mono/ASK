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

- [ ] **A9. Tunnel TX encap never offloads — ucode 210.10.1 `INSERT_L3_HDR`
  punts unconditionally.**
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

- [ ] **A31.** ctnetlink_change_permanent()'s unpin trigger is "CTA_STATUS present
  but omitting IPS_PERMANENT on a pinned ct" (the bit going 1->0): a routine
  update that merely omits the bit silently unpins the ct and short-circuits
  (dropping bundled attrs). Pre-existing (A30 preserves it per the "don't break
  unpin" constraint); benign as long as the controller always echoes the full
  status of a pinned ct. Open (defense-in-depth: gate unpin on an explicit
  signal rather than bit-absence).

- [ ] **A33.** *(Static inference, untested — deprioritized.)* The **routed**-
  multicast offload path resolves interfaces via `get_onif_by_name`, which
  returns NULL for `br-lan.N`, so routed mcast through a vlan-aware bridge
  would fail like the unicast A32 case. **Not applicable to the Mono Gateway
  deployment, which does not route multicast** — IPTV is bridged at L2
  (`br-iptv`: `eth0.3999` ↔ `br-lan.3999`, IGMP snooping), a separate
  ABM/L2-flow path. Left unfixed unless a routed-mcast use case appears; the
  fix would mirror A32 (physical-port fallback in `dpa_control_mc.c` /
  `insert_mcast_entry_in_classif_table`). Open (low priority).

- [ ] **A35.** Two TODO markers in shipped patch 010. (a) `skb_fraglist_to_sg_fd`
  dropped frames with more than `DPA_SGT_MAX_ENTRIES` fragments — the ratelimited
  print landed (_051b8c4_) and the linearize path landed (patch 010:
  `skb_linearize` then drop only on OOM; skb ownership audit-confirmed at all
  three callers). **(a) done.** (b) `skb_scrub_packet` (~010:13680) still carries
  an `sp`-init workaround note for work not done elsewhere — not a correctness
  bug, kept so it isn't lost. Open (only (b) remains).

- [ ] **A38.** Wire macvlan hardware offload in cdx (planned). cmm sends
  FPP_CMD_MACVLAN_ENTRY/RESET automatically on macvlan interface events
  (`itf.c` cmmFeMacVlanUpdate, gated on ITF_MACVLAN), but cdx has no
  FC_MACVLAN/EVENT_MACVLAN handler, so every send returns ERR_UNKNOWN_COMMAND
  and logs an error whenever a macvlan interface exists. The gateway doesn't
  currently create macvlan netdevs (CONFIG_MACVLAN is built but nothing creates
  one), so it's latent today. Decision (2026-08-16): **keep the cmm sender** and
  wire a cdx handler when macvlan forwarding is added to the product — mirror
  the A32 physical-port approach (FC_MACVLAN → EVENT_MACVLAN dispatch + program
  the classifier / insert into the classif table). The sibling dead command
  families (module_prf/pktcap/icc/expt/alt_conf/voicebuf) were deleted; macvlan
  is the one kept for future wiring. Open (planned).

- [ ] **A39.** Transport-mode ESP offload is reachable but untested end-to-end. cdx
  SAs default to transport mode (SA_MODE_TUNNEL is set only by
  FPP_CMD_IPSEC_SA_SET_TUNNEL, which cmm sends for tunnel-mode xfrm states),
  yet the product config and the entire rig suite exercise tunnel mode
  exclusively. The SEC-era fix (_7cfd157_) means the CAAM-reported era 8 now
  enables PDBOPTS_ESP_AOFL in the transport-mode decap PDB (SEC >= 5.3
  output-length adjustment; under the old hardcoded era 4 it was off, likely
  counting ESP trailer bytes in the output length) — tunnel mode is unaffected
  by era entirely. Before transport-mode offload ever becomes a product path,
  add a transport-mode case to the rig suite and validate both the pre-existing
  path and the AOFL-adjusted lengths. Open.

- [ ] **A47.** `show_fm_risc_load` (lnxwrp_sysfs_fm.c) calls `msleep(1000)` with
  hard IRQs disabled — `__schedule()` re-enables them on the context switch, so
  the intended IRQ-off protection of the FM_CtrlMon start/stop window is
  illusory, and a world-readable sysfs read blocks for a full second. More
  broadly the sysfs dump handlers hold IRQs off across hundreds of MMIO
  accesses (plus a register write per iteration in `fm_dump_ccqueue`) —
  `local_irq_save` used as a pseudo-lock with zero cross-CPU effect. Latency +
  design smell, not a leak (patch 101 fixed those). Candidate fix: replace the
  IRQ fiction with a real lock (or drop the save entirely where the hardware
  window doesn't need it) on the next sysfs-wrapper touch. Open.

- [ ] **A66.** A54 freshness residual (documented by the fix's audit): after a
  rollback, the next route event re-attaches the OLD fpp route id (holder's
  `fpp_route` restored → `__cmmFPPRouteRegister` no-ops), cdx accepts the
  same-id update, and `FPP_NEEDS_UPDATE` clears with no pending convergence
  event when the refusal was transient and the new gateway's neighbor was
  already NUD_VALID — stale next-hop persists until unrelated neigh/route
  churn. Consistent (no orphan, both sides agree) and strictly better than
  pre-A54, but not fresh. Fix shape: compare the held `fpp_rt` against the
  RtEntry's current MAC/oif/mtu on retry and stash-and-rebuild on mismatch.
  Open (low priority).

- [ ] **A73.** cmm `cmm_print` calls `cli_vabufprint` on the shared libcli
  handle from any thread; libcli has no internal locking, so concurrent
  output can interleave or corrupt CLI buffers. Display-only impact. Open
  (low).

- [ ] **A79.** `cmmUpdateFlows` iterator invalidation (A76 residue): the nested
  local-registration recursion (`____cmmCtLocalRegister → __cmmRouteLocalNew
  → ____cmmCtRegister`) reaches `__cmm_ct_get_SA`, which on an SPI-mismatch
  rekey `list_del`s (and may head-`list_add` onto another SA) the
  `list_by_sa` node the outer walk saved as `next` — so the next
  `container_of` walks a moved/foreign node. **Investigated (2026-08-20):
  no safe localized fix.** ct *objects* are pointer-stable (the reprogram
  path never frees a ctTable — only the deregister path does), so this is
  list-node movement, not UAF. The current node is already `list_del`'d
  before the reprogram; the hazard is the saved-next. Exposed walks:
  `cmmUpdateFlows` and `cmmUpdateCtEntriesInFlowNoSAList` (both hold a
  saved-next across the reprogram); `cmmUpdateFlowsWithNewSAInfo`'s own loop
  is safe (touches no list) but funnels into `cmmUpdateFlows`. "Re-fetch
  next from the head" fails: `list_add` is head-insert, so a ct re-added by
  the recursion is re-read — terminates for the three `SA_DELETE` paths
  (the `SA_DELETE` gate refuses re-link) but infinite-loops the two
  non-delete cases (flow_no_sa re-add, rekey-to-old-SA). A snapshot needs
  per-node re-validation that it still references this SA/direction plus a
  dynamically-sized copy of an unbounded list. Fix shape (design): a
  per-pass generation/visited marker on `ctTable`, or a walk-in-progress
  guard that stops the A76 recursion from re-entering a list being walked —
  new struct field, deliberate change. Open (investigate; contrived
  trigger, low priority).

- [ ] **A80.** cdx `dpa_control_mc.c` per-listener REMOVE clears member state
  (`bIsValidEntry=0`, `tbl_entry=NULL`, count--) BEFORE checking the
  `ExternalHashTableFmPcdHcSync` result, so a sync failure leaks the
  `tbl_entry` and mis-decrements `uiListenerCnt` (latent: the query walker
  was hardened to re-scan `bIsValidEntry` and ignore the counter).
  **Investigated (2026-08-20): the obvious check-then-clear reorder is
  unsafe and was NOT applied.** HC-sync can fail transiently (HC frame-pool
  exhaustion, not just a wedge), so the fix must keep the entry reclaimable
  on failure — but leaving `bIsValidEntry=1` lets a re-REMOVE re-enter the
  first-listener surgery after `first_listener_entry` already advanced,
  hitting a NULL `temp_entry->next` deref (:1295) → handler oops → orphaned
  `ctrl.mutex` → all FCI hangs → reboot (worse than the leak). The
  two-field state has no localized assignment satisfying
  {no-leak, no-unsafe-free, no-crash-on-retry}. A correct fix needs a
  quarantine/pending-free list drained when the HC channel recovers (the
  in-tree `ExternalHashTableDeleteKey` sync-then-free discipline can't be
  applied here because the surgery is destructive before the sync). The
  current `return -1` abort-the-batch behavior is correct and unchanged (a
  wedged HC fails every later member too). Open (investigate — needs the
  pending-free design).

- [ ] **A83.** cdx `rtp_flow_free` (`control_rtp_relay.c:68-84`) leaks the MURAM
  `rtp_info` carve if `dpa_get_fm_MURAM_handle` returns NULL — it frees
  `hw_flow` but not `rtp_info`, losing its only pointer. Latent (the MURAM
  handle is a stable init-time global). Surfaced by the A62 trace. Open (low).

- [ ] **A85.** The FM_PCD `*Set`/`*Build` ioctls copy the raw kernel `t_Handle`
  pointer back to userspace in the reply (the value later handed to `*Delete`) —
  a KASLR pointer info-leak from the 0600 `/dev/fmX-pcd` node. Real fix is opaque
  handle cookies (type+generation tokens) instead of raw pointers. Open (low;
  root-only).

- [ ] **A86.** cdx sdk_dpaa `dpaa_submit_{outb,inb}_pkt_to_SEC` rewrite
  `skb->data` in place (outbound L2-shift, inbound PPPoE/proto bytes) before
  handing the skb to the FMAN offload — if a tap holds a live clone (tcpdump on
  the offload iface: `skb_cloned()`, `users==1`), the shared data buffer is
  mutated and the capture shows corrupted bytes. Pre-existing, orthogonal to
  A35a (whose `skb_linearize` is itself COW-correct); surfaced by the A35a
  audit. Diagnostic-only (the forwarded packet is fine). Fix: `skb_cow_head`/
  `skb_ensure_writable` before the in-place header edits. Open (low).

---

<a name="archive"></a>
# Archive

Closed items, one line each. Detail lives in the referenced commit and in this
file's git history.

## Gating

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

- [-] **N20 (not a bug).** "Same-SPI reinstall blackholes the tunnel" was a test
  artifact — reinstalling one peer's SA rewinds ESP seq to 1, the other peer
  correctly rejects the rewound seqs (RFC 4303); no cdx defect.

- [-] **X1.** "256B memset + partial fill info leak" — wontfix: memset(p,0,256)
  zeros the full rbuf before the partial fill; surplus bytes are zeros.

- [-] **X2.** "strcpy IF_NAME_SIZE overflow" — wontfix/fixed: downgraded to L2 and
  swept to strscpy (_89e5b32_); all cdx name copies now dst-size bounded.

- [-] **X3.** "dpaa_eth_refill_bpools suspected leaks" — wontfix: the skb
  backpointer lives in the BMan hardware-owned frag pool; error paths free clean.

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

- [x] **A32.** Forwarded NATed flows through a vlan-aware bridge (`br-lan.N`) ran
  on the CPU (not a cdx onif → ingress/egress resolution failed) — fixed
  (_d85724d_): physical-port substitution + `underlying_input_itf` fallback.

- [x] **A34.** cmm `VLAN_FILTER` build asymmetry (`make cmm` omitted it, the
  recipe defined it) — fixed (_25f85e8_): `cmm/Makefile` carries the single
  authoritative define list; also fixed a short netlink attribute space.

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

- [x] **A69.** CT register leaked the main-route refs on the tunnel-route failure
  path (`ct_free()` never released the orig/rep `L2_route_get` nbrefs, pinning
  the routes forever), same family as A48/A49/A50 — fixed (_616db95_): new
  `ct_free_unresolved()` releases all four refs; register sites funnel through it.

- [x] **A70.** Intermittent failslab-sweep failures ("never drove <alloc> to
  NULL") — root-caused and fixed (harness-only): the askd-agent's per-request
  flip of the *global* `failslab/ignore-gfp-wait` knob left sweeps running with
  GFP_KERNEL exempt. Fix: set it once at startup, arming read-verifies + fails loud.

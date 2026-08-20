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

---

<a name="archive"></a>
# Archive

Closed items, one line each. Detail lives in the referenced commit and in this
file's git history.

## Gating

- **G1.** `/dev/cdx_ctrl` ioctl dispatcher was ungated — added a CAP_NET_ADMIN
  check ahead of the command-table lookup (_815a0ca_).

- **N1.** FCI (`NETLINK_FF`), abm (`NETLINK_L2FLOW`) and the NETLINK_KEY
  ipsec-offload bus (patch 040) had no capability gate — per-message
  `netlink_capable(skb, CAP_NET_ADMIN)` added to all three input handlers;
  covered by `test_fci_netlink_caps.py`.

- **G2.** Single-open gate had a mis-rejection window — replaced with a single
  atomic_cmpxchg(1→0).

## Critical

- **C1.** auto_bridge L2FLOWA_IP_SRC/DST memcpy trusted attacker nla_len into a
  16-byte union — nla_policy caps NLA_BINARY len to the field size.

- **C2.** FCI inbound trusted sender nlmsg_len for OOB-sized payloads —
  validate fci_msg->length against skb->len and FCI_MSG_MAX_PAYLOAD.

- **C3.** IPR release loop walked FMAN-supplied num_entries unbounded — cap
  against reassly_bp->size / entry-size before the release loop.

- **C4.** IPR ref_count (uint8_t) could wrap on double-decrement — zero-check
  and drop before decrementing.

- **C5.** IPR deinit was a stub leaving the timer kthread and FQs live (UAF on
  unload) — full kthread-stop + FQ retire/oos/destroy + bpool free.

- **C6.** dpa_cfg scaled allocations by attacker-influenced counts — sanity
  caps + kcalloc, num_fmans==0 rejected, sub-counts allow legit zero.

- **C7.** Six fm_index checks used `> num_fmans` (one index OOB) — all flipped
  to `>=`.

- **Bonus.** cdx_ctrl_deinit (.text) referenced cdx_cmdhandler_exit
  (.exit.text) — dropped __exit so the section reference is legal.

- **C8.** queue_no/port_idx/dscp used as unchecked array indices from userspace
  — entry bounds checks added in dpa_cfg.c and cdx_ehash.c.

- **C9.** Test ioctl kzalloc overflow — mooted: the buggy code was deleted
  outright with the testapp scaffolding (see C9b), not sanity-capped
  (_815a0ca_).

- **C9b.** Dead testapp scaffolding remained compiled-in — deleted dpa_test.c,
  testapp.c and the CDX_CTRL_DPA_CONNADD ioctl + structs (moots H10).

- **C10.** Raw netlink `.input` handlers got no core length validation — FCI's
  cap-fail `-EPERM` ack and `fci_outbound_err` echoed bytes past the request
  skb (unprivileged heap over-read) and `ipsec_nlkey_rcv` memcpy'd per-command
  structs out of a possibly-short skb; all now bounded against `skb->len`.
  Distinct from C2 (payload-parse path).

## High

- **H1.** Concurrent CDX_CTRL_DPA_SET_PARAMS ioctls could UAF fman_info —
  dpa_cfg_lock mutex, -EBUSY re-init reject, err_ret unwind (_815a0ca_).

- **H3.** IPsec shared-desc error paths leaked auth/cipher key DMA maps —
  two-label unwind + SA_SH_DESC_BUILT rollback on add failure.

- **H4.** CAAM shared-desc map-then-unmap suspected bug — wontfix: deliberate
  cache-flush idiom; SEC reads the desc via the ipsecsa handle; documented.

- **H5.** NAT-T SPI slot check used `> MAX_SPI_PER_FLOW`, letting the "full"
  sentinel index the array — reject with `>=`.

- **H6.** auto_bridge per-bucket lock-drop iteration suspected UAF — wontfix:
  no state crosses the drop; entries rebound per bucket under lock.

- **H8.** abm sysctls lacked a capability gate and abm_max_entries accepted 0 —
  CAP_NET_ADMIN check + proc_douintvec_minmax bounds 1..1e6.

- **H9.** Static query-snapshot cursors raced concurrent enumerators — per-file
  query mutexes + mc bucket spinlocks; mutator walks tracked under A2.

- **H10.** strncpy_from_user truncation unchecked — mooted: all four sites
  lived in dpa_test.c, deleted with the C9b test-scaffolding removal.

- **H7 (partial).** net_device stored without dev_hold — dev_hold/balanced
  dev_put added; the drain's sleep-under-spinlock residual closed as H7-r.

- **H7-r.** `rtnl_lock()` under `spin_lock_bh(&abm_lock)` on the regular abm
  workqueue drain — `bridge_list_rtevent` is now spliced to a local list under
  the lock with `rtmsg_ifinfo`/`dev_put` run after unlock; exercised by
  `test_abm_port_flap.py`.

- **H2 (partial).** IPsec keys not zeroed on free — kfree_sensitive on the
  SA-context keys; the query-snapshot sibling leak is reopened as H2-r.

- **H11.** `abm_fdb_can_expire` (a process-context `br_fdb_cleanup` workqueue
  callback) took `abm_lock` with plain `spin_lock`, a self-deadlock /
  `{SOFTIRQ-ON-W}` lockdep hazard — all three sites switched to
  `spin_lock_bh`/`spin_unlock_bh`.

- **N3.** `cdx_get_ipsec_fq_hookfn` had no unregister, so a failed cdx init
  wedged every later load at `ipsec_init` until reboot — all five cdx-facing
  hook families got unregister-on-deinit with `synchronize_rcu` teardown,
  release-publish registers and snapshot readers (_81421c2_ patch 010 regen,
  _b2342ce_ cdx). Sibling vwd nf-hook leak filed as N7.

- **H2-r.** SA query snapshots memcpy'd full cipher/auth keys and were freed
  with plain kfree — all three frees switched to `kfree_sensitive` and the
  fill slice is zeroed per bucket (_5376281_). Closes H2 fully.

- **N5.** Five CAAM/bman `dma_map_single` results tested with `!addr` —
  `DMA_MAPPING_ERROR` is truthy, so real failures reached hardware; all sites
  now use `dma_mapping_error()` (_5376281_).

- **N8.** Five iface stats getters dropped `dpa_devlist_lock` between the
  `dpa_get_ifinfo_by_itfid` lookup and the use — all five now hold the lock
  across the read/reset (_062484a_); the follow-up (_9c103b9_) moved
  `dpa_release_interface`'s eth HW teardown outside the lock and corrected the
  stale concurrency comments. Non-FCI walkers filed as N10.

## Medium

- **M1.** Query of 6-8 listener groups OOB'd the reply buffer — pagination
  reserves 2 cmds/group, pages via bIsValidEntry look-ahead.

- **M2.** dev_get_by_name leaks (control_vlan) — wontfix: control_vlan paths
  are NULL-guarded and balanced; a missed dpa_wifi sibling is filed as N4.

- **M3.** Unbounded sprintf chain in the fqid_stats procfs handler — converted
  to seq_file; two ucode_frag siblings of the same class filed as N2.

- **M4.** %px and raw %p handle prints in cdx debug output — %px removed,
  sensitive handle prints flipped to %pK; hashed %p left per policy.

- **M5.** auto_bridge netlink dispatch used signed nlmsg_type with no default
  arm — narrowed to u16, unknown types return -EINVAL.

- **M6.** auto_bridge exit hot-spun on bare schedule() waiting for l2flow drain
  — bounded 5s wait with 1-jiffy sleeps and pr_warn on timeout.

- **M7.** IPsec table-entry add left the shared descriptor dangling on failure
  (explicit TBD) — SA_SH_DESC_BUILT rolled back, entry/ct/info freed on unwind.

- **M8.** Full-group mcast delete unlinked shared list state lock-free —
  list_del now under the bucket spinlock, sleeping HW teardown after unlock.

- **M9.** mcast ADD unwind could leak pCtEntry/pRtEntry if a future path failed
  after wiring them — err_ret now frees both, defense in depth (_c23817b_).

- **M10.** Cdx_GetMcastMemberId returned ids stale across dropped bucket locks
  — mc_mutators_mutex serializes ADD/REMOVE/UPDATE at the dispatcher.

- **M11.** GetMcastGrp returned a group pointer freeable after the bucket lock
  dropped — the same mc_mutators_mutex closes the window.

- **M12.** REMOVE fast path keyed on count alone; wrong names wiped the group —
  every listener pre-validated, mismatch returns ERR_MC_CONFIG.

- **M13.** Duplicate names in REMOVE still tripped the count-match full delete —
  member_id bitmap dedupes, repeats rejected with ERR_MC_CONFIG.

- **M14.** cmm_parse_rtattr logged rta->rta_len after loop exit (OOB read on a
  truncated rtattr) — parser shared with the ASAN fuzzer, logs remaining length
  only.

- **M15 (partial).** FMAN PCD didn't replicate IPv4 mcast to listener subifs —
  dev_mc_add/del sequencing + wmb before the ADD-path publish; UPDATE-path
  barrier reopened as M15-r.

- **N2.** `/proc/ucode_frag/*` read handlers sprintf'd into the `__user` buffer
  (M3's class) — both converted to single_open/seq_file, proc entries now
  removed at deinit ahead of bufpool/MURAM teardown, and a NULL `bp->pool`
  deref dropped from the bufpool-create error path (_b593f93_).

- **M15-r.** UPDATE-path mcast publish (`first_member_flow_addr` into a live
  FMAN chain) lacked the ADD-path's `wmb()` — barrier added; the REMOVE
  unlink's invalid-flag store also used the host-order macro on BE-stored flags
  (corrupting the live entry) and now ORs `cpu_to_be16(1<<15)` (_5376281_).
  Closes M15 fully.

- **N4.** `dpaa_vwd_init`'s `err7` unwind nulled `vwd.eth_priv` without dropping
  the `dev_get_by_name` ref from `get_eth_priv` — `dev_put` added, mirroring
  `dpaa_vwd_exit` (_5376281_).

- **N9.** `alloc_iface_stats` returned SUCCESS with a NULL slot on freelist
  exhaustion (NULL deref waiting in the FCI stats query) — now frees
  `last_stats` and returns FAILURE; the pppoe/vlan/tunnel add cascades also
  free stats on `dpa_add_port_to_list` failure (_1f996c0_).

- **N11.** The VAP ioctl state machine slept under `spin_lock_bh(vaplock)` —
  ADD now claims the slot with `VAP_ST_CONFIGURING`, sleeps unlocked and
  publishes/rolls back under the re-taken lock; UPDATE/RESET are
  transition-aware and sysfs create is deferred past the final unlock
  (_7510673_). Remaining lifetime residue filed as N13.

- **N12.** Deinit never freed the interface list (`dpa_release_iflist` had zero
  callers and only kfree'd) — rewritten as a pop-under-lock/release-outside
  sweep and registered so the LIFO chain runs it after `tx_exit` (_a34063c_).
  Adjacent teardown leaks filed as N14.

- **N13.** VAP REMOVE/RESET tore down state lock-free consumers could still
  reach — new rtnl-held `vwd_unpublish_vap` clears every `wifi_offload_dev`
  alias, REMOVE/RESET wait a `synchronize_rcu` grace before `vwd_vap_down`, and
  the exit path gained the same discipline plus a global alias sweep
  (_de0aef4_). Residue filed as N15.

- **N14.** Teardown gaps closed: `destroy_fwd_tx_fqs` un-ifdef'd (was compiled
  out) and called on release, per-iface proc dirs reclaimed,
  `cdx_deinit_fqid_procfs` frees its tracking nodes, stats MURAM carve freed
  (_79089f1_). Failed-injection MURAM/HW residue stays accepted.

- **N15.** VAP/netdev lifetime residue closed — NETDEV_UNREGISTER notifier,
  VLAN aliases republished on vap re-ADD, rtnl-held FCI VLAN-REGISTER copy,
  spinlocked `fqid_files_g`, exit drains in-flight ioctls under rtnl
  (_f094aba_); cdx.ko now depends on 8021q.ko. Accepted residue: a failed-init
  teardown can still be poked from a held-open fd, and frames parked in
  SEC/FMAN can outlive a netdev unregister.

- **N19.** CBC+HMAC wire showed 26x the seq-duplicates of fixed GCM — the RM
  §7.3.1 per-job PDB STORE was GCM-only; extended to every cipher, CBC dupes
  0.154%→0.006% at unchanged throughput (_1055403_).

- **N18.** Descriptor KEY commands DMA-read key bus addresses unmapped at build
  time (harmless on identity mapping, fatal under IOMMU/SWIOTLB) — mappings now
  live in the SA context for the SA lifetime, released in
  `cdx_ipsec_sec_sa_context_free` (_14722d1_).

- **N17.** cmm-programmed IPsec inner flows suspected heavily lossy — not
  reproducible on a clean boot (TCP at 2.54 Gbit/s, 99.996 % hardware-
  classified). The original evidence decomposed into a Vision-side UDP
  source-selection artifact, WAIT-mode burst tail-drops, and a state-degraded
  boot; the one real residual refiled as N19.

- **N10.** Devlist discipline sweep — OH fixtures carried `itf_id` 0 (aliasing
  the legitimate onif index 0; now `~0U`-sentinelled at creation), the two
  non-FCI walkers now walk under the list lock, `dpa_add_wlan_if` gained the
  missing `iface_count++`/cap/rc checks, `remove_onif_by_index` bails on invalid
  slots, and several dead functions were removed (_26b408a_).
  Sleeping-under-vaplock and the deinit list leak filed as N11/N12.

## Low / Hardening

- **L1.** Fixed-seed Jenkins/jhash on attacker-chosen L2-flow keys (cdx +
  auto_bridge) — per-boot-keyed hsiphash/siphash; jenk_hash.h deleted
  (_89e5b32_ + _bf8c453_).

- **L2.** strcpy into equal-sized IF_NAME_SIZE buffers across cdx control paths
  — full sweep to strscpy(dst, src, sizeof(dst)); none remain.

- **L3.** sprintf into small fixed name buffers in cdx procfs — snprintf
  bounded by sizeof(node->name).

- **L4.** proc_create("fci", 0, ...) left permissions implicit — mode set to
  0444, read-only intent explicit.

- **L5.** Dead unimplemented ioctl prototypes in cdx_ioctl.h — stubs plus
  supporting structs/macros removed (incl. a cmd-number collision).

- **L6.** Reassembly release misnamed cpu_to_be* on BE-to-host reads — renamed
  be*_to_cpu, u8→u16 zero-extend documented; no-op on LE.

- **L7.** UBSAN array-bounds on the flex-array subscript in create_ethernet_hm
  — store converted to pointer arithmetic, semantics unchanged.

- **L8.** cmm sig_term_hdlr logged benign ENOENT for an already-removed pidfile
  — both cleanup sites report only errno != ENOENT.

- **N6.** `abm_retransmit_delay` accepted 0 (retransmit work spins) and
  negatives (parks the work ~forever) — dedicated handler rejects `<= 0` with
  -EINVAL and restores the previous value (_d8083c6_).

- **N16.** eth4 (LAN) FMAN ingress came up dead on a fraction of boots (rx=0,
  link up, so ARP never reached the kernel), masked by loki's cached neighbor
  entry; suspected same family as fman-pcd-tnum-stall (missing dist FQs → port
  stall). **Closed as a one-off — not reproduced since; reopen and investigate
  boot-time bring-up ordering (fmc/dpa_app vs cdx init vs VAP reset) if it
  recurs.** Test tooling gates each boot on eth4 rx>0 with static neighbors
  pinned on both LAN peers.

## Corrections to the original review (wontfix / not-a-bug)

- **N20 (not a bug).** "Same-SPI reinstall blackholes the tunnel" was a test
  artifact — reinstalling one peer's SA rewinds its ESP sequence to 1 while the
  other peer's inbound SA correctly rejects the rewound seqs (RFC 4303).
  Runtime SA replacement must reset both peers together or use fresh SPIs
  (which real IKE always does); no cdx defect.

- **X1.** "256B memset + partial fill info leak" — wontfix: memset(p,0,256)
  zeros the full rbuf before the Get_Timeout partial fill; surplus bytes are
  zeros.

- **X2.** "strcpy IF_NAME_SIZE overflow" — wontfix/fixed: downgraded to L2 and
  swept to strscpy (_89e5b32_); all cdx name copies now dst-size bounded.

- **X3.** "dpaa_eth_refill_bpools suspected leaks" — wontfix: the skb
  backpointer lives in the BMan hardware-owned frag pool kmemleak can't scan;
  error paths free cleanly.

- **A12.** "PPPoE RX-decap missing classifier install" — wontfix: inner
  udp4/tcp4 dist precedes pppoe_dist; the PPPoE strip is an HM chained on the
  inner CT entry, not a table.

- **A15.** "cmm has no incoming xfrm subscription" — wontfix: the af_key km hook
  broadcasts every SA event on NETLINK_KEY grp1 and cmm binds it via libfci; an
  on-DUT restart confirmed no resync gap (only cmm-downtime events are lost,
  recoverable via `ip xfrm state flush`).

- **N7.** "vwd nf hooks leak on cdx unload with fast path enabled" —
  wontfix/not-a-bug: the three hooks are registered at module init (the sysfs
  toggle only flips the per-packet gate flag) and every path unregisters them
  exactly once; traced link-by-link and independently re-verified.

## Architectural themes

- **A1.** External command fields validated ad hoc per cmdproc — the whole FCI
  bus + cdx ioctl dispatcher routed through one validator-table idiom (2 latent
  bugs fixed en route).

- **A1a.** No shared bounds-check idiom — added cdx_cmd_validator.{h,c}: spec
  table + cdx_dispatch_cmd (lookup, [min,max] length, validate, then handle)
  (_cf1fa1b_).

- **A1b.** control_vlan migrated as the prototype — VlanCommand length + action
  validator, cmdproc reduced to a dispatch tail-call (_f2f3a82_, _c4d3965_).

- **A1c.** Remaining 13 cmdprocs (~120 codes) migrated to validator tables with
  per-command length bounds.

- **A1d.** /dev/cdx_ctrl ioctl switch replaced by a table-driven
  cdx_ioctl_table[] with CAP_NET_ADMIN gate and ENOTTY on unknown cmd
  (_ed082ea_).

- **A1e.** Per-subsystem inner cmd_code switches removed — each cmdproc is a
  one-line dispatch tail-call.

- **A2.** Locking assumptions were implicit per-file folklore — top-of-file
  Concurrency: blocks + sparse __must_hold() across cdx/abm/fci (_d99bb62_).

- **A3a.** IPR init leaked bpools/kthread/FQs on failure — nested unwind
  cascade; deinit tears down FQs via private ipr_fqs[] tracking (_b5a7bf8_ +
  _78ac2af_).

- **A3b.** fqid procfs mkdirs left earlier dirs on later failure — nested
  err_remove_* cascade; deinit proc_removes the whole tree.

- **A3c.** l2flow_cache leaked when brroute_cache creation failed —
  destroy+NULL l2flow_cache on that error path.

- **A3d.** abm_init leaked earlier subsystems on later init failure — goto
  cascade runs each matching _fini/_exit in reverse order.

- **A3e-r.** `dpa_add_eth_if`'s cascade leaked the `get_eth_iface_info` netdev
  ref and the published stats slot, and normal eth removal leaked `last_stats`
  and never unpublished `priv->ifinfo` — guarded `dev_put`, a new `err_stats`
  unwind, an eth arm in `free_stats`, and the discard-mask restore un-nested
  from `ENABLE_EGRESS_QOS` (_dffbbd6_). Closes the A3 umbrella; query-path race
  and alloc-contract landmine filed as N8/N9.

- **A4.** Debug scaffolding shipped as production — dpa_test.c removed, IPR
  deinit stub implemented, %px/%p prints flipped to %pK.

- **A5.** Sanitizer bring-up surfaced 4 vendored-kernel bugs (qbman, sdk_dpaa,
  sdk_fman, netlink) — fixed as patches 090-093, shipped to both images.

- **A5a.** qbman dpa_alloc_new kmalloc'd GFP_KERNEL under spin_lock_irq —
  patch 090 preallocates all list nodes before the lock, frees leftovers after.

- **A5b.** dpa_get_channel held a spinlock over qman_alloc_pool (sleeps) —
  patch 091 swaps it for a mutex; the only caller is probe-time process context.

- **A5c.** A shared lockdep class made FmPcdLockTryLockAll's inner locks look
  recursive — patch 092 adds a SINGLE_DEPTH_NESTING try-lock variant.

- **A5d.** NETLINK_L2FLOW=33 got a NULL lockdep name from the 0..32-only
  cb_mutex string table — patch 093 names indices 32 (KEY) and 33 (L2FLOW).

- **A6.** Tunnel handlers walked 16-byte FCI name fields as C strings (KASAN
  OOB) — HASH_TUNNEL_NAME/M_tnl_get_by_name take maxlen, strncmp lookup
  (_9f9b69d_).

- **A7.** Fuzzer only hit dispatcher length checks — 30 payload-body mutation
  cases (10 cmds × all_ff/high_enum/no_nul_str) with a splat oracle
  (_0bf177b_).

- **A8.** cdx never freed its CAAM job ring, tripping the caam_jr busy check on
  reboot — idempotent release from the deinit chain + reboot notifier.

- **A9 (decap portion).** TX-offload test was a false positive (stale 165 Mbps
  baseline) — reframed as a software-path tripwire; RX decap proven offloaded
  (6o4+4o6) after the ip6_tunnel iif stamp + second 10G port wired. TX-encap
  residual stays open as A9.

- **A10.** RouteEntry.id stored the U32 wire route id as U16, silently
  truncating on ADD — widened to U32; API/hash/wire already U32 (_d61c50f_).

- **A11.** FORTIFY warned on memcpy into [0]-tails in fm_ehash.h (patch 099 not
  in SRC_URI) — all 7 tails now C99 flex arrays, recipe ships 099 (_e499b98_).

- **A13.** Vendored CPE_FAST_PATH hunk took rtnl_lock under all_ppp_mutex —
  NEWLINK now sent after mutex drop via dev_hold (patch 070).

- **A14.** H2 key-zeroing was unobservable — test-image-only probe snapshots the
  post-kfree_sensitive cipher_key to /proc/cdx (_5358b5b_).

- **A16.** NAT-T fast-path push threw away the classification-entry rc, reply
  stayed NO_ERR — rc captured and propagated as ERR_CREATION_FAILED
  (_d5be3ae_).

- **A17.** SET_KEYS wrote through sa before the NULL check — stale-sagd
  NULL-deref; assignment moved after the ERR_SA_UNKNOWN return (_d5be3ae_).

- **A18.** NAT-T push wrote sa->ct->natt_in_refcnt after ignoring add-entry
  failure — now bails to err_ret; the callee frees+NULLs sa->ct (_d5be3ae_).

- **A19.** Three SA leaks (procfs wrapper on mkdir-fail, release-path wrapper,
  shdesc_mem) — symmetric kfrees added (_cd0548c_).

- **A20.** ipsec_nlkey_rcv took x->lock without BH disable vs the softirq
  xfrm_timer — all three NLKEY pairs flipped to spin_lock_bh (patch 040,
  _d5be3ae_).

- **A21.** Deinit from a failed init crashed in qman_ceetm_sp_release(lni->sp=
  NULL) — SP claim passed explicitly + NULL-guarded; init failure now propagates
  (_d236aa3_).

- **A22.** gateway-dk cdx_cfg.xml OH portid 8/9 tripped the cdx_sp.xml espschema
  `$logicalportid lt 9` policing gate, breaking ESP recognition — restored to
  NXP 9/10 (_d5be3ae_).

- **A23.** ipsec_bp registered but never seeded — SEC hit BPDERR, silent drops;
  dpaa_bp_alloc_n_add_buffs(512, act_skb=1) added with unwind (_d5be3ae_).

- **A24.** DNCPE-2358 root-caused and fixed; GCM/GMAC offload re-enabled. Two
  SEC descriptor defects: HDR_SAVECTX let SERIAL self-sharing carry GCM's
  class-1 context into the next packet, and cross-DECO refetches weren't
  ordered against PDB.seq writeback (RM §7.3.1) — fixed by SERIAL sharing
  without SAVECTX plus a per-job PDB+stats STORE, with the encap PDB now
  seeding sa->seq+1 (_451bc18_).

- **A25.** AES-128-CTR lacked the RFC 3686 nonce trim and CTR PDB fields —
  comb_mode/extra_size=4 trim + ctr_nonce/ctr_initial=1 in both PDBs
  (_d5be3ae_).

- **A26.** ASK patch stack compiled with ~52 warnings (missing prototypes, bad
  formats, one wrong-signature extern) — 010/040 regenerated warning-free
  (_3b93e0e_).

- **A27.** IPsec-offload SA handle was set by a lockless `xfrm_state_handle++`
  in xfrm_state_alloc — concurrent allocs aliased handles and the u16 counter
  wrapped onto live ones, mis-resolving `xfrm_state_lookup_byhandle` and
  tripping cdx ERR_SA_DUPLICATED (rekey blackhole); the handle is now assigned
  at byh-insert under xfrm_state_lock with a dedup (new
  `xfrm_state_insert_byh`) and the counter seeded once (patch 040).

- **A28.** xfrm_input.c's inbound-offload submit passed x->handle to SEC gated
  only by x->offloaded and *before* the XFRM_STATE_VALID check, and x->offloaded
  was never cleared on SA delete (stale handle into a freed hardware context) —
  submit now gated on km.state==XFRM_STATE_VALID and `__xfrm_state_delete`
  clears x->offloaded (patch 040).

- **A29.** af_key.c SET_OFFLOAD could re-mark a DEAD SA offloaded (impact
  already neutralized by A28's gates) — **fixed** (_bad0464_): the handler sets
  `offloaded=1` only under `km.state==XFRM_STATE_VALID` inside the existing
  `x->lock` section (the lock that serializes the DEAD transition); clearing
  stays unconditional.

- **A30.** `ctnetlink_change_permanent()` short-circuited the entire conntrack
  update whenever CTA_STATUS merely carried IPS_PERMANENT, silently dropping
  the bundled CTA_MARK/CTA_NAT/CTA_PROTOINFO/CTA_QOSCONNMARK changes — now
  gates on the IPS_PERMANENT *delta* (only a real flip is a pin/unpin), with
  the pin switched to atomic set_bit (patch 050).

- **A31.** ctnetlink_change_permanent()'s unpin trigger is "CTA_STATUS present
  but omitting IPS_PERMANENT on a pinned ct" (the bit going 1->0): a routine
  update that merely omits the bit silently unpins the ct and short-circuits
  (dropping bundled attrs). Pre-existing (A30 preserves it per the "don't break
  unpin" constraint); benign as long as the controller always echoes the full
  status of a pinned ct. Open (defense-in-depth: gate unpin on an explicit
  signal rather than bit-absence).

- **A32.** Forwarded (NATed) flows through a vlan-aware bridge (`br-lan.N`) ran
  on the CPU in both directions, because `br-lan.N` is not a registrable cdx
  onif so ingress (`input_itf`) and egress onif resolution both failed (same
  limitation in NXP ASK, not a regression) — cmm now substitutes the physical
  port for a VLAN-on-bridge input and resolves the egress physical port from
  the underlying-bridge FDB, cdx falls back to `underlying_input_itf` at the
  three insert gates, and a rate-limited `ASK-DIAG` fires only when a flow has
  no offloadable ingress at all; hardware-validated in both directions
  (_d85724d_).

- **A33.** *(Static inference, untested — deprioritized.)* The **routed**-
  multicast offload path resolves interfaces via `get_onif_by_name`, which
  returns NULL for `br-lan.N`, so routed mcast through a vlan-aware bridge
  would fail like the unicast A32 case. **Not applicable to the Mono Gateway
  deployment, which does not route multicast** — IPTV is bridged at L2
  (`br-iptv`: `eth0.3999` ↔ `br-lan.3999`, IGMP snooping), a separate
  ABM/L2-flow path. Left unfixed unless a routed-mcast use case appears; the
  fix would mirror A32 (physical-port fallback in `dpa_control_mc.c` /
  `insert_mcast_entry_in_classif_table`). Open (low priority).

- **A34.** cmm `VLAN_FILTER` build asymmetry: top-level `make cmm` omitted
  `-DVLAN_FILTER` while `meta-ask`'s `cmm_1.0.bb` defined it — resolved
  (_25f85e8_): `cmm/Makefile` now carries the single authoritative define list
  and the recipe adds none; the same change fixed a netlink attribute space 2
  entries shorter than auto_bridge's.

- **A35.** Two live TODO markers in shipped patch 010 (report-only, from the
  leftover audit). (a) `skb_fraglist_to_sg_fd` (~010:1168) silently drops
  frames with more than `DPA_SGT_MAX_ENTRIES` fragments ("TODO linearize") and
  logs an *unratelimited* `pr_err` per drop — a burst of oversized-SGT frames
  floods the log. Fix: linearize/bounce instead of drop, and ratelimit the
  print. (b) `skb_scrub_packet` (~010:13680) carries an `sp`-init workaround
  note for work not done elsewhere. Neither is a correctness bug today; filed
  so the ratelimit + the linearize path aren't lost. The pr_err ratelimit
  landed (_051b8c4_); the linearize/bounce path and the scrub note remain.
  Open.

- **A36.** Five audit smells confirmed + **fixed** (_051b8c4_): ehash lock leaks,
  sysfs IRQ-off returns (new patch 101), RICP clobber, libnfnetlink UAF, fmc dedup.

- **A37.** Two IPsec-FQ setup leaks in cdx `dpa_ipsec.c` — **fixed**
  (_dd37089_): `err_ret` unwinds the exception FQs (add moved after procfs so
  the failing FQ is never double-retired); `err_ret2` releases the fqid
  range. Probe-only path, compile-validated.

- **A38.** Wire macvlan hardware offload in cdx (planned). cmm sends
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

- **A39.** Transport-mode ESP offload is reachable but untested end-to-end. cdx
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

- **A40.** fmc's `fmc_exec_htnode` marshalled fmlib's 88-byte
  `t_FmPcdHashTableParams` into the 120-byte shared uapi ioc struct, so
  `table_type` landed in the `aging_support` byte and every ehash node got
  `table_type=0` (wrong ucode AD class), with bytes 88-111 uninitialized stack
  — **fixed** (_953051c_): fmlib's struct made layout-identical
  (compile-time-asserted) and the ioc buffer memset; OpenWrt's copy of the patch
  synced in that tree.

- **A44.** `ipv4_reassly_offset`/`ipv6_reassly_offset` in `FM_PCD_CcRootBuild`
  (patch 010, fm_cc.c ~:7239) were declared uninitialized yet written into every
  non-ETHERNET table's AD, OR'ing stack residue into microcode descriptors —
  **fixed** (_953051c_): both initialized to the 0xff no-reassembly sentinel in
  010.

- **A45.** `externalHash` type-confusion — real but unreachable; dead surface
  excised (_bd9f289_), marshalling half already resolved (_953051c_).

- **A41.** The kas/Yocto build of dpa_app compiles with neither `-Wall` nor
  `-Werror`: `dpa-app_1.0.bb` overrides CFLAGS wholesale with Yocto's default
  `-O2 -g -pipe` plus its define/include set (confirmed: zero `-Wall`/`-Werror`
  in a fresh `log.do_compile`), while the top-level `make userspace` path does
  build it `-Wall -Werror`. So the shipped dpa_app binary is the one built
  without warning enforcement — against the repo's warning-free policy. Fix is a
  recipe CFLAGS append, but enabling may surface latent warnings in dpa_app that
  need cleaning first; do it as its own validated change, not a drive-by. Open.

- **A42.** Socket-update mutate-then-fail — **already fixed** (_dd96e1d_), entry
  was stale (v4 only, not both families; pre-fix it validated the *old* route_id
  then silently returned `NO_ERR` after stripping the route). HEAD is
  validate-then-commit. The confirm pass surfaced four live same-shape route-ref
  bugs → A48-A51 below.

- **A46.** `FM_PCD_HashTableAddKey` type confusion on the
  `FM_PCD_IOC_HASH_TABLE_ADD_KEY` ioctl path — **fixed** (_e690063_): the
  ioctl case body is deleted (falls into the `E_INVALID_SELECTION` stub arm,
  matching the already-stubbed DELETE/REMOVE_KEY siblings),
  `FM_PCD_HashTableAddKey` is removed outright (definition, export, header),
  and `ExternalHashTableAddKey`'s entry parameter is tightened to
  `struct en_exthash_tbl_entry *` so the confusion is a compile error.
  Re-verified against the shipped patch 010 hunks before closing.

- **A47.** `show_fm_risc_load` (lnxwrp_sysfs_fm.c) calls `msleep(1000)` with
  hard IRQs disabled — `__schedule()` re-enables them on the context switch, so
  the intended IRQ-off protection of the FM_CtrlMon start/stop window is
  illusory, and a world-readable sysfs read blocks for a full second. More
  broadly the sysfs dump handlers hold IRQs off across hundreds of MMIO
  accesses (plus a register write per iteration in `fm_dump_ccqueue`) —
  `local_irq_save` used as a pseudo-lock with zero cross-CPU effect. Latency +
  design smell, not a leak (patch 101 fixed those). Candidate fix: replace the
  IRQ fiction with a real lock (or drop the save entirely where the hardware
  window doesn't need it) on the next sysfs-wrapper touch. Open.

- **A43.** cmm MSP socket surface — **closed** (verified 2026-08-18, no code
  change needed): the cmm-side deletions shipped in _dd96e1d_ (no `msp` CLI
  keyword, no CMMD_SOCKET_TYPE_MSP plumbing, no reverse-route pre-check), and
  cdx's `ERR_WRONG_SOCK_TYPE` rejection on both open paths with the wire enum
  value reserved is the desired terminal state.

- **A48.** cdx v4 socket-open resolved `route_id` twice (orphan `L2_route_get`
  gate + the stored `SOCKET4_check_route` ref), leaking one `nbref` per open —
  **fixed** (_6a62e61_): drop the orphan get, mirror v6. Runtime-confirmed
  (open+close returns the route to removable).

- **A49.** cdx `tunnel_free` was a bare `kfree` with no `L2_route_put`, leaking
  a route ref on every tunnel delete and both create `err1` exits — **fixed**
  (_6a62e61_): NULL-safe put in `tunnel_free`, and release before
  `remove_onif_by_index` in DELETE. Runtime-confirmed (dereg 202→0 after delete).

- **A50/A51.** cdx `IPsec_handle_SA_SET_TNL_ROUTE` and `TNL_handle_UPDATE` (and
  `TNL_handle_CREATE`) dropped the old route then took the new one unchecked,
  committing a routeless SA/tunnel and returning `NO_ERR` — **fixed** (_69ab942_):
  resolve-then-commit, real `ERR_RT_ENTRY_NOT_FOUND` on a non-zero unresolvable
  id (route_id 0 stays the detach sentinel), old binding untouched on failure.
  Runtime-confirmed (failed update keeps the old route pinned; error returned).
  The A51-adjacent cmm smells were split out to A54 (route-update contract)
  and A55 (socket_open unsigned rc).

- **A52.** `/dev/fmX` FM_PCD ioctl family passes user-supplied `param->id`
  straight through as a kernel `t_Handle` with no validation — NXP documents it
  verbatim as a "Security Hole" in `lnxwrp_ioctls_fm.c` (~:2501, above
  `FM_PCD_ManipNodeReplace((t_Handle)param->id, ...)`). ~11 live sibling sites
  share the shape: KgSchemeGetCounter, CcRootModifyNextEngine, MatchTableModify
  {,Miss}NextEngine, MatchTableRemoveKey, MatchTableModifyKeyAndNextEngine,
  MatchTableGet{Key,Miss}Statistics, MatchTableModifyKey, ManipGetStatistics. A
  root-only (0600 /dev node) arbitrary-kernel-pointer-deref primitive; the A46
  stub removed the one `p_hash_tbl` instance but the pattern persists on
  `param->id`. Not cleanup — needs a handle-validation design (registry of
  live LLD handles, or reject the affected ioctls if no legit userspace uses
  them; fmlib/fmc call-surface audit first). Own concern. Open (investigate).

- **A53.** Dangling `RouteEntry->itf` slab-UAF on interface teardown (itf
  embedded in the kfree'd VlanEntry/PPPoE_Info/TnlEntry owner; pinned routes
  survived `remove_onif_by_index` with the pointer intact) — **fixed**
  (_7432ef6_): pinned routes are quarantined (itf/input/underlying cleared,
  making `L2_route_get`'s dead NULL gate live), every held-route deref site
  NULL-guarded, mcast group routes cleared via a new locked walk, and
  `tunnel_exit` now removes onifs before freeing. Rig-validated under KASAN
  (quarantine chain splat-free; new pins refused; 202→0 nbref discipline
  intact). Residue filed as A63 (mcast unload leak) and A64
  (`add_incoming_iface_info` unwind).

- **A54.** cmm assumed the pre-A42 "cdx drops the old route on failure"
  contract, so a rejected route swap orphaned the fpp route handle (count 0,
  id unreleased) while cdx kept forwarding on the dropped route — **fixed**
  (_733c599_): CTs are torn out of hardware on a rejected re-register (traffic
  re-offloads them), tunnel/SA/socket holders roll back to the old binding and
  re-arm `FPP_NEEDS_UPDATE`, the route-event retry gates widened to match
  needs-update holders, `socket_update` became snapshot-atomic, the update rc
  is consulted before any deregister, and the orphan-handle path logs the id.
  Rig-validated (gateway flap under an offloaded flow re-offloads cleanly, no
  count-0 orphans). Freshness residual filed as A66; the `sa_lock` inversion
  and two smells surfaced en route as A65/A67/A68.

- **A55.** cmm `module_socket.c` error-code truncation (negative rc narrowed
  to 65535, reported as a bogus positive FPP error) — **fixed** (_42379cb_):
  `int rc` in socket_open/socket_update, socket_add's allocation failure maps
  to `CMMD_ERR_MEMORY`, and negative transport errors keep their sign into the
  daemon's errno answer path. Client-side reporting residue filed as A75.

- **A56.** `ipsec_push_sa_to_fast_path` installed the HW classification entry
  before resolving the xfrm state (leaving a live entry classifying into a
  stateless SEC context on lookup failure) and overwrote `sa->xfrm_state`
  without putting the prior reference (one xfrm hold leaked per outbound-SA
  route-update re-push) — **fixed** (_02d4968_): resolve-first is impossible
  (`sa->netdev` is populated only inside the install), so the install is
  unwound via `cdx_ipsec_delete_fp_entry` on lookup failure and the old xfrm
  reference is put before storing the new one. Same commit fixes an adjacent
  NAT-T arr-index-full path that left `sa->ct` dangling on a shared ct.

- **A57.** `M_tnl_add` hash-linked the tunnel before the fallible
  `dpa_add_tunnel_if` and discarded its result (a real add failure reported
  `NO_ERR`; propagating it would have freed a still-linked entry) — **fixed**
  (_02d4968_): program hardware first, hash-link only on success, and release
  the onif + route in the create-failure arm before `tunnel_free`.
  Rig-validated by a failslab sweep (no half-linked entry, route never pinned;
  `test_tunnel_failslab.py`).

- **A58.** `M_ipsec_sa_cache_create` linked the SA onto `sa_cache_by_fqid`
  before the fallible `sa_add` (latent leak-while-reachable trap; dead today
  since `sa_add` cannot fail) — **fixed** (_42379cb_): `sa_add` first, fqid
  link only on success, and the failure arm releases the SEC context and frees
  the unpublished entry.

- **A59.** `struct _cdx_ctrl.lock` was a dead spinlock (init'ed, never
  acquired; the timer wheels actually run under `ctrl.mutex`) and the
  `cdx_main.c` concurrency comment described it plus nonexistent
  `ctrl->work`/`ctrl->msg_list` fields as load-bearing — **fixed**
  (_6b6d9f2_): field and init deleted, comment rewritten to the real
  mutex-only discipline.

- **A60.** MURAM `dc zva` oops family: socket-open `memset` of the 128-byte
  MURAM stats block faulted on Device-nGnRE memory and wedged `ctrl.mutex` —
  **fixed** (_849b90f_): all five generic mem-ops on `FM_MURAM_AllocMem`
  memory (socket v4/v6 open, RTCP read-back, both ifstats freelist zeroings)
  switched to `memset_io`/`memcpy_fromio` with `__iomem` casts. Verified by a
  full sweep of all four MURAM allocation heads: every remaining access is
  either the iomem-safe `cdx_qos.c` bounce helpers or aligned scalar
  loads/stores (safe on ARM64, `WRITE_UINT32` class); socket open exercised
  live during the A48 runtime confirmation. Comment falsehood in patch 010's
  `memcpy.c` hunk stays tracked as A61.

- **A61.** Patch 010's `etc/memcpy.c` hunk justified aliasing the IO copy
  helpers to plain `memcpy()` with a false "MURAM is normal cacheable memory"
  comment (it is Device-nGnRE iomem) — **comment fixed** (_6b6d9f2_): now
  states the truth — tolerated only because arm64 `memcpy` never emits
  `dc zva`, with `memcpy_fromio/_toio` named as the preferable forms.
  **Call-site conversion done** (_bad0464_): fm_replic's member-AD shadow
  copy goes through a stack bounce (`_fromio` then `_toio`, both sides
  MURAM) and the `fmbm_spliodn` save/restore pair uses `_fromio`/`_toio`
  (dead code under a never-defined errata ifdef, converted anyway); the
  three `IO2*Cpy32` helpers now have zero in-tree callers and remain for
  out-of-tree users. (`IOMemSet32` keeps its `WRITE_UINT32` loop — why
  `FmMuramClear` and friends are safe.)

- **A62.** cdx RTP-relay opcode wrote truncated 64-bit VAs where the ucode
  expects MURAM offsets — **fixed** (_dd37089_): convert via
  `MURAM_VIRT_TO_PHYS_ADDR` (rtp_info non-NULL by construction, socket-stats
  guarded NULL→0). Confirmed real; CLI-only path, compile-validated.

- **A63.** `mc4_exit`/`mc6_exit` leaked every live mcast group on module
  unload — **fixed** (_f9afea9_): the group-DELETE teardown is extracted to
  a shared `cdx_mcast_group_destroy()` (classif-table evict before any
  backing-memory free) and both the DELETE arm and a new exit drain call it,
  so the two stay in lockstep; the drain runs before the spinlock and
  grp-id arrays are freed. Unload-only path — cdx is persistent in
  production, so audit-confirmed rather than rig-exercised.

- **A64.** ~~`insert_entry_in_classif_table`/`insert_mcast_entry_in_classif_table`
  don't unwind `add_incoming_iface_info()` on error paths.~~ **Closed
  (2026-08-20, not a bug):** `add_incoming_iface_info` (`cdx_dpa.c:96-172`)
  has exactly one success side effect — `entry->inPhyPortNum = iif->index`
  (`:170`), a scalar int copy. No alloc, no refcount, no list link; it reads
  `pRtEntry->input_itf` as a borrowed pointer and returns on both failure
  modes before that write. There is nothing to unwind; the existing
  `err_ret` paths are correct. (Cosmetic residue: the `add_*` name
  misleadingly implies acquisition.)

- **A65.** cmm `sa_lock` ABBA inversion — **fixed** (_6b61392_): `sa_lock` is
  now a leaf taken after the canonical `itf → ct → rt → neigh` chain at every
  multi-lock site. Topology note: keytrack and rtnl handlers share
  `cmmCtThread`, so that inversion was latent; the live deadlock pair was the
  CLI thread in `cmmCtShow` (sa → ct, held across per-entry FCI round-trips)
  vs the ct thread's route/neigh path (chain → sa). Guarded by the static
  lock-order test (`test_cmm_lock_order.py`); rig-validated
  (query-vs-mutator + ipsec subset). Review residue filed as A69–A73.

- **A66.** A54 freshness residual (documented by the fix's audit): after a
  rollback, the next route event re-attaches the OLD fpp route id (holder's
  `fpp_route` restored → `__cmmFPPRouteRegister` no-ops), cdx accepts the
  same-id update, and `FPP_NEEDS_UPDATE` clears with no pending convergence
  event when the refusal was transient and the new gateway's neighbor was
  already NUD_VALID — stale next-hop persists until unrelated neigh/route
  churn. Consistent (no orphan, both sides agree) and strictly better than
  pre-A54, but not fresh. Fix shape: compare the held `fpp_rt` against the
  RtEntry's current MAC/oif/mtu on retry and stash-and-rebuild on mismatch.
  Open (low priority).

- **A67.** `__cmmRouteNew` passed the tunnel's (and, same shape, the SA's)
  own family to the route-match helpers, so the family filters never fired —
  **fixed** (_42379cb_): both scans now pass the route event's
  `rtm->rtm_family` (PROTO_FAMILY_* values equal AF_*), mirroring
  `__cmmRouteLocalNew`. Also stops transport-mode SAs (family 0) from
  matching every default-route event.

- **A68.** `__cmmSATunnelRegister` dereferenced `__cmmNeighAdd()`'s result
  (`->count++`) with no NULL check — malloc failure crashed the daemon —
  **fixed** (_6b6d9f2_): result checked; on failure no dummy neighbor entry
  is published and the SA waits for the real neighbor event like any other
  unresolved route (every downstream consumer already tolerates a NULL
  `neighEntry`).

- **A69.** cmm `cmmCtShow` stack overflow (surfaced by the A65 review):
  `nfct_snprintf`/`snprintf` return the would-be output length (negative on
  error) and the running render offset into the 1024-byte stack buffer was
  never clamped — truncation walked `buf + len` past the array with a
  negative remaining size wrapped to a huge `size_t`; an error return wrote
  at `buf - 1` — **fixed** (_23166a5_): offset clamped back into the buffer
  after every render call, buffer terminated on render errors.

- **A70.** cmm zombie SA on flow-update failure — **fixed** (_ae77bad_):
  `cmmSADelete`/`cmmSASetState` record the failure and still run
  `__cmmSARemove` (safe: `cmmUpdateFlows` provably unlinks every conntrack
  before returning — contract now documented at the function). Unreachable
  armor today (`cmmUpdateFlows` cannot fail); removes the latent
  wedged-sagd path.

- **A71.** cmm `cmmSAFlush` could not report failure — **fixed** (_42379cb_):
  a per-entry `cmmUpdateFlows()` failure records `rc=-1` while the flush
  still removes every entry; keytrack answers FCI_CB_STOP. (Currently
  unreachable armor — `cmmUpdateFlows` has no failure path today.)

- **A72.** cmm sa_table walk without `sa_lock` from the client-daemon thread
  (`cmmCtChange → ____cmmCtRegister → __cmm_ct_get_SA → cmmSAFind` racing
  `cmmSACreate`'s insert under only `sa_lock`) — **fixed** (_42379cb_):
  `cmmCtChange` takes `sa_lock` (leaf, innermost) around the registration.
  Placement note: the lock cannot go inside `__cmm_ct_get_SA` — the SA
  handlers reach it via `cmmUpdateFlows` with `sa_lock` already held, and
  `____cmmCtRegister` recurses. Audit walked the full registration subtree:
  no other mutex acquired inside, and every other caller either holds
  `sa_lock` or runs on the ct thread. `cmmSAFind`'s locking/lifetime
  contract is now documented at the function.

- **A73.** cmm `cmm_print` calls `cli_vabufprint` on the shared libcli
  handle from any thread; libcli has no internal locking, so concurrent
  output can interleave or corrupt CLI buffers. Display-only impact. Open
  (low).

- **A74.** `cmmFeReset` dangling holder references, missing `sa_lock`, and
  fpp-route reference leaks — **fixed** (_ae77bad_): the reset detaches SA
  and tunnel holders before the drains (fpp-route put + route NULL +
  `FPP_NEEDS_UPDATE`), releases ct/socket fpp-route references in the
  drains, takes `sa_lock` innermost, and `__cmmCtRemove` now unlinks the
  tunnel-route hash nodes. Audit-confirmed refcount-balanced and
  order-safe; rig-validated on normal and KASAN images (CLI
  `set activate 0/1` with live programmed flows: drain → refill of the
  same flow, zero splats; full suite 291 passed).

- **A75.** cmm client error reporting gaps (A55 residue) — **fixed**
  (_f9afea9_): a daemon-side failure now reports as one (the daemon puts
  `CMMD_ERR_UNKNOWN` on the wire for a transport `rc<0` instead of a
  "malformed request" code, and `cmmSendToDaemon` zeroes the response and
  distinguishes a real msgrcv failure from a `daemon_errno` failure), and
  `getErrorString` names the five 32000-range CMMD codes. The audit found
  the original "client never consults daemon_errno" premise was already
  false (`cmm_recv` did); the real defects were the on-wire lie and the
  missing strings. cmm-only, reporting path.

- **A76.** unbounded local-registration recursion — **fixed** (_f9afea9_):
  a function-static depth counter in `____cmmCtLocalRegister` saturates at
  4 (legitimate nesting is 1), logging and returning without re-registering
  at the bound; safe as a static because every entry into the recursion
  holds `ctMutex` (non-recursive), so at most one thread is ever in it.
  Below the bound behavior is bit-identical. Note the recursion terminates
  on its own today (`__cmmRouteLocalNew` skips `LOCAL_CONN`) — the guard
  bounds stack depth, not a live hang. **Residue (A79):** the iterator-
  invalidation half of this entry (nested registration rekey-unlinking the
  node `cmmUpdateFlows` saved as next) is not addressed by the depth guard.

- **A77.** RT_POLICY routes escaped `cmmFeReset`'s rt drain — **fixed**
  (_f9afea9_): the reset's ct drain now releases each conntrack's
  policy-route reference per direction (`orig/rep.route`) the same way the
  normal `____cmmCtDeregister` path does — one route put per counted
  reference, the `rt_table_by_gw_ip` unlink handled inside
  `__cmmRouteRemove`, no FCI traffic (engine already reset). Audit-confirmed
  no double-put with the adjacent fpp-route puts. Rig exercise of the reset
  path under KASAN with policy routing configured deferred to the next DUT
  window.

- **A78.** ~~Whether the forward engine preserves tunnel objects across
  `FPP_CMD_IPV4/IPV6_RESET` is unconfirmed.~~ **Closed (2026-08-20, not a
  bug):** the cdx reset handlers tear down only conntracks, sockets and
  routes — `IPv4_HandleIP_RESET` (`control_ipv4.c:1126-1163`: `ct_remove`,
  `SOCKET4_free_entries`, `L2_route_remove`) and `IPv6_handle_RESET`
  (`SOCKET6_free_entries` only); a grep of both for tunnel/SA/ipsec teardown
  is empty. Tunnels are freed solely via `TNL_handle_DELETE`. So the engine
  preserves tunnel objects across reset, cmm keeping `FPP_PROGRAMMED` on
  tunnel itfs is correct, and the first post-reset `ACTION_UPDATE` targets a
  live object. No change needed.

- **A79.** `cmmUpdateFlows` iterator invalidation (A76 residue): the nested
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

- **A80.** cdx `dpa_control_mc.c` per-listener REMOVE clears member state
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

- **A81.** cmm `cmmd.h` hard-coded MC error wire values — **fixed**
  (_eb594f0_): the `CMMD_ERR_MC_*` codes now alias the `FPP_ERR_MC_*`
  constants (fpp.h already included; sibling `ENTRY_NOT_FOUND` already did),
  so drift is a compile error. Numerically identical (701/703/704/705
  verified equal), no behavior change.

- **A82.** cmm `CMMD_CMD_SOCKET_SHOW` missing length check — **fixed**
  (_eb594f0_): added a `cmd_len < sizeof(*cmd)` guard matching the sibling
  arms' shape before the first deref. Purely additive (was bounded only by
  the pre-receive memset).

- **A83.** cdx `rtp_flow_free` (`control_rtp_relay.c:68-84`) leaks the MURAM
  `rtp_info` carve if `dpa_get_fm_MURAM_handle` returns NULL — it frees
  `hw_flow` but not `rtp_info`, losing its only pointer. Latent (the MURAM
  handle is a stable init-time global). Surfaced by the A62 trace. Open (low).

- **A69.** CT register leaked the main-route references on the tunnel-route
  failure path: `IP_Check_Route()` took an `L2_route_get` nbref on each of
  the orig/rep main routes, then an unresolvable `tunnel_route_id` exited via
  a plain `ct_free()` (kfree only), never releasing them — the routes stayed
  pinned against removal forever (`L2_route_remove` → `ERR_RT_ENTRY_LINKED`),
  same family as A48/A49/A50. Both families, four sites (`control_ipv4.c`
  ~766/778, `control_ipv6.c` ~335/346). A53 widened reachability: a
  quarantined tunnel route now returns NULL from `L2_route_get`, so tearing
  down a tunnel's parent iface then registering a CT that names its route
  hits the leak. **Fixed** (_616db95_): new `ct_free_unresolved()` mirrors
  `ct_add`'s err0 unwind (release both main refs + both tnl refs, then free);
  the four register sites and `ct_add`'s err0 now funnel through it.
  Rig-validated pre→post under KASAN (`test_ct_tunnel_route_leak.py`:
  pre-fix DEREGISTER=202, post-fix=0). Invisible to failslab/kmemleak (a
  stuck nbref is a live ref, not lost memory) — needs the nbref oracle.

- **A70.** Intermittent failslab-sweep failures ("never drove <alloc> to
  NULL"; hit `test_ipv6_ct_failslab` and `test_vlan_failslab` in full-suite
  runs, passing scoped minutes later) — root-caused and **fixed** (this
  round, harness-only): the askd-agent armed fault-eligibility by writing
  the *global* `failslab/ignore-gfp-wait` debugfs knob to N per request and
  restoring Y per request, with the arm write wrapped in a silent
  `except OSError: pass` — one swallowed failure left a whole sweep running
  with GFP_KERNEL allocations exempt, so only the ~11 atomic netlink-scaffold
  allocs were faultable (the errno-105 signature) and every register
  "succeeded". Fix: the knob is set to N once at agent startup and left
  there (faults nothing at rest — per-task fail-nth is the only trigger),
  the per-request write/restore flip-flop is deleted, and arming now
  read-verifies the knob and fails loudly instead of sweeping in the dark.
  The earlier "warm-run drift / reboot-first" theory in the runbook was a
  correlate, not the mechanism.

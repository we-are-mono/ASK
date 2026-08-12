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

- [ ] **N16. eth4 (LAN) FMAN ingress comes up dead on a fraction of boots.**
  `ethtool -S eth4` shows `rx packets [TOTAL]: 0` and 0 interrupts from boot
  with link UP while eth3 works; ARP goes unanswered because requests never
  reach the kernel. The rig masked this for months by running off loki's
  cached neighbor entry for the DUT's constant MAC (a seeded entry survives
  indefinitely under bidirectional traffic without ARP), so it surfaces as
  seemingly random delayed LAN blackouts when the cache expires. Same family
  as the fman-pcd-tnum-stall finding (missing dist FQs → port stall); needs a
  boot-time bring-up ordering investigation (fmc/dpa_app vs cdx init vs VAP
  reset). Test-tooling workaround: gate each boot on eth4 rx>0 (reboot until
  alive) and pin static neighbors on both LAN peers.


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
- **N3.** `cdx_get_ipsec_fq_hookfn` had no unregister and the register refuses overwrite — a failed cdx init after `CMD_INIT(ipsec)` wedged every later load at `ipsec_init` until reboot (same wedge reachable via the wifi hook on the vwd stats-failure unwind). All five cdx-facing hook families (ipsec fq / ceetm fq / bpool replenish / wifi xmit / fp stats) got unregister-on-deinit with `synchronize_rcu` teardown, release-publish registers, snapshot readers, explicit RCU sections at the two process-context readers, and the ceetm dscp NULL guard (_81421c2_ patch 010 regen, _b2342ce_ cdx). Sibling vwd nf-hook unload leak filed as N7.
- **H2-r.** SA query snapshots memcpy'd full cipher/auth keys and were freed with plain kfree — all three frees switched to `kfree_sensitive`, and the fill slice is zeroed per bucket so partially-filled entries and buffer reuse no longer leak slab garbage or a previous bucket's keys into the fixed-size replies (_5376281_). Closes H2 fully.
- **N5.** Five CAAM/bman `dma_map_single` results tested with `!addr` (or not at all) — `DMA_MAPPING_ERROR` is ~0UL/truthy, so real failures sailed past the H3 unwind or reached hardware; all sites (shared-desc keys ×3, extended-desc extra-cmds ×2, vwd sg-fd) now use `dma_mapping_error()` (_5376281_).
- **N8.** Five iface stats getters (phyif/reset/tunnel/vlan/pppoe) dropped `dpa_devlist_lock` between the `dpa_get_ifinfo_by_itfid` lookup and the `iface_info`/`last_stats` use — theoretical today (getters and `dpa_release_interface` are both FCI-dispatched, serialized by the dispatcher mutex) but the safety was non-local; all five now hold the lock across the read/reset (_062484a_). Follow-up (_9c103b9_): `dpa_release_interface` unlinks under the lock but runs the eth HW teardown (FM_PCD HC busy-waits ~10ms) and frees after unlock; the false "softirq callers" claims in the devman/cdx_ifstats concurrency blocks corrected (every taker is process context); the remaining lock-free FCI-path lookups documented safe under the remove-side invariant (all unlinks/frees of live nodes are dispatcher-mutex-serialized — adds from the boot injection ioctl only publish fresh nodes). Non-FCI walkers filed as N10.

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
- **N2.** `/proc/ucode_frag/*` read handlers sprintf'd into the `__user` buffer (M3's class) — both converted to single_open/seq_file; proc entries now removed at deinit ahead of bufpool/MURAM teardown (stale-proc_ops class A3b fixed for fqid), partial-create unwound, test file 0400 with honest acquire count, and a NULL `bp->pool` deref dropped from the bufpool-create error path (_b593f93_).
- **M15-r.** UPDATE-path mcast publish (`first_member_flow_addr` into a live FMAN chain) lacked the ADD-path's `wmb()` — barrier added before the store; REMOVE unlink reviewed barrier-free-correct (redirects target already-published entries, free is HcSync-gated), but its invalid-flag store used the host-order macro on the BE-stored flags (set an OPC_OFFSET bit, corrupting the live entry) — now ORs `cpu_to_be16(1<<15)` per the reference driver's swap-modify idiom (_5376281_). Closes M15 fully.
- **N4.** `dpaa_vwd_init`'s `err7` unwind nulled `vwd.eth_priv` without dropping the `dev_get_by_name` ref from `get_eth_priv` — `dev_put` added, mirroring `dpaa_vwd_exit`; all other `dev_get_by_name` sites re-audited balanced except devman.c:472 (already open as A3e-r) (_5376281_).
- **N9.** `alloc_iface_stats` returned SUCCESS with a NULL slot on freelist exhaustion (stats indices aliasing slot 0, NULL deref waiting in the FCI stats query) — now frees `last_stats` and returns FAILURE; the pppoe/vlan/tunnel add cascades also free stats on (currently-impossible) `dpa_add_port_to_list` failure, mirroring the eth path (_1f996c0_).
- **N11.** The VAP ioctl state machine slept under `spin_lock_bh(vaplock)` (GFP_KERNEL + qman FQ creation in the ADD arm, plus an unlock/relock hack for `device_create_file`) — ADD now claims the slot with the previously-unused `VAP_ST_CONFIGURING`, sleeps unlocked, and publishes/rolls back under the re-taken lock; UPDATE/RESET are transition-aware; `wifi_offload_dev` is release-published only after the FQs are live and unpublished first on REMOVE; sysfs create deferred past the final unlock; `vap_count` balanced (_7510673_). Remaining lifetime residue filed as N13.
- **N12.** Deinit never freed the interface list (`dpa_release_iflist` had zero callers and only kfree'd) — rewritten as a pop-under-lock/release-outside sweep (eth backstop: reset ifinfo + `dev_put`; `free_stats` + kfree for all), counters zeroed, registered so the LIFO chain runs it after `tx_exit`'s onif releases — frees the OFPORT fixtures and backstops leaked netdev refs on failed init (_a34063c_). Adjacent teardown leaks filed as N14.
- **N13.** VAP REMOVE/RESET tore down state lock-free consumers could still reach — new rtnl-held `vwd_unpublish_vap` clears every `wifi_offload_dev` alias (incl. VLAN-on-vap), REMOVE/RESET claim the slot and wait a `synchronize_rcu` grace before `vwd_vap_down`, RESET also drops the per-vap sysfs attrs (double-create fixed), and the exit path gained the same discipline plus an explicit grace (`nf_unregister_net_hook` stopped synchronizing in 4.14) and a global alias sweep (_de0aef4_). Residue filed as N15.
- **N14.** Teardown gaps closed: `destroy_fwd_tx_fqs` un-ifdef'd (was compiled out — fwd tx FQs undestroyable) and called on release; per-iface proc dirs + wrappers reclaimed via tree-aliveness-aware `cdx_remove_dir_in_procfs`; `cdx_deinit_fqid_procfs` frees the tracking nodes it leaked; stats MURAM carve freed from the sweep tail (_79089f1_). Failed-injection MURAM/HW residue stays accepted (handle gone by then).
- **N15.** VAP/netdev lifetime residue closed: NETDEV_UNREGISTER notifier (unpublish + grace + down for OPEN vaps on a dying wifi netdev, multi-vap aware, alias-clearing without relying on 8021q ordering; also covers netns moves); VLAN aliases republished on vap re-ADD (by netdev relationship — never-FCI-registered VLANs now get the alias too, safe via the SEC round-trip/exception path); the FCI VLAN-REGISTER copy runs under rtnl; `fqid_files_g` spinlocked with sleeping ops outside; exit drains in-flight ioctls under rtnl (mid-ADD FQ leak gone) (_f094aba_). Accepted residue: a CONFIGURE→ADD issued on a held-open fd after a failed-init teardown can still poke freed OH state (pre-existing class, failed-init-only, needs a shutting-down gate); frames parked in SEC/FMAN can outlive a netdev unregister (inherent, narrowed by the notifier). cdx.ko now depends on 8021q.ko (vlan_dev_real_dev).
- **N19.** CBC+HMAC wire showed 26x the seq-duplicates of fixed GCM (308 vs 12 per 200k after the fix) — the RM §7.3.1 per-job PDB STORE was GCM-only; extended to every cipher, CBC dupes 0.154%→0.006% at unchanged 2.4-2.5 Gbit/s, GCM 0 dupes/0 dup-IVs per 200k. The ~840-retx signal that opened this was a flow-setup transient, not steady-state loss (_1055403_).
- **N18.** Descriptor KEY commands DMA-read key bus addresses that were unmapped at build time (use-after-unmap by the DMA-API contract; harmless on identity mapping, fatal under IOMMU/SWIOTLB) — mappings now live in the SA context for the SA lifetime, released beside the key buffers in cdx_ipsec_sec_sa_context_free (_14722d1_).
- **N17.** cmm-programmed IPsec inner flows suspected heavily lossy — not reproducible on a clean boot: mid-run FPP conntrack shows the iperf flows programmed with IPsec annotations while TCP runs 2.54 Gbit/s, and tx-toenc moves +41 across ~1.1M packets (99.996 % hardware-classified path, 20-22 retx). Original evidence decomposed: the iperf3 UDP-mode control deaths were a Vision-side source-selection artifact (unconnected UDP replies left plaintext via the br0 source, missing the src-10.99.0.2 policy — fixed by the `ip route … src 10.99.0.2` pin, now in the IPSEC.md recipes); the 0.84 Mbit/s GCM run was WAIT-mode burst tail-drops (default since moved to SERIAL, 43f29a0); the 63 Mbit/s CBC cmm-up/down comparison ran on a state-degraded boot. The one real residual — CBC's ~840 retx vs GCM's 20 — refiled as N19 (descriptor store, not path).
- **N10.** Devlist discipline sweep — OH fixtures carried `itf_id` 0, so releasing/looking up the legitimate onif index 0 could alias one (release now skips OFPORT + `~0U` sentinel at creation); the two non-FCI walkers (`dpa_get_ohifinfo_by_portid` — which also lacked the union type check — and `cdx_copy_eth_rx_channel_info`) now walk under the list lock; `dpa_add_wlan_if` gained the missing `iface_count++`/cap/rc checks (vap cycles underflowed the u8 counter until all adds were rejected); `remove_onif_by_index` bails on invalid slots; injection-precedes-FCI serialization documented; dead code removed (`dpa_update_wlan_if`, `dpa_get_itfid_by_fman_params`, the caller-less `comcerto_fpp_send_command_simple`/`_atomic`, `cdx_ctrl_send_command_simple`) (_26b408a_). Sleeping-under-vaplock and the deinit list leak filed as N11/N12.

## Low / Hardening
- **L1.** Fixed-seed Jenkins/jhash on attacker-chosen L2-flow keys (cdx + auto_bridge) — per-boot-keyed hsiphash/siphash; jenk_hash.h deleted (_89e5b32_ + _bf8c453_).
- **L2.** strcpy into equal-sized IF_NAME_SIZE buffers across cdx control paths — full sweep to strscpy(dst, src, sizeof(dst)); none remain.
- **L3.** sprintf into small fixed name buffers in cdx procfs — snprintf bounded by sizeof(node->name).
- **L4.** proc_create("fci", 0, ...) left permissions implicit — mode set to 0444, read-only intent explicit.
- **L5.** Dead unimplemented ioctl prototypes in cdx_ioctl.h — stubs plus supporting structs/macros removed (incl. a cmd-number collision).
- **L6.** Reassembly release misnamed cpu_to_be* on BE-to-host reads — renamed be*_to_cpu, u8→u16 zero-extend documented; no-op on LE.
- **L7.** UBSAN array-bounds on the flex-array subscript in create_ethernet_hm — store converted to pointer arithmetic, semantics unchanged.
- **L8.** cmm sig_term_hdlr logged benign ENOENT for an already-removed pidfile — both cleanup sites report only errno != ENOENT.
- **N6.** `abm_retransmit_delay` accepted 0 (retransmit work spins) and negatives (`-N*HZ` cast to unsigned parks the work ~forever with no rescheduler) — dedicated handler rejects `<= 0` with -EINVAL and restores the previous value (_d8083c6_).

## Corrections to the original review (wontfix / not-a-bug)
- **N20 (not a bug).** "Same-SPI reinstall blackholes the tunnel" was a test artifact: reinstalling one peer's SA rewinds its ESP sequence to 1 while the other peer's inbound SA retains the old replay-window high-water mark and correctly rejects the rewound seqs (RFC 4303). Proven by isolation — a DUT-only reinstall drops 100% with the peer's XfrmInStateSeqError ticking one-per-packet; resetting only the peer's replay window (DUT untouched) restores it instantly. Runtime SA replacement must reset both peers together or use fresh SPIs (which real IKE always does); no cdx defect.
- **X1.** "256B memset + partial fill info leak" — wontfix: memset(p,0,256) zeros the full rbuf before the Get_Timeout partial fill; surplus bytes are zeros.
- **X2.** "strcpy IF_NAME_SIZE overflow" — wontfix/fixed: downgraded to L2 and swept to strscpy (_89e5b32_); all cdx name copies now dst-size bounded.
- **X3.** "dpaa_eth_refill_bpools suspected leaks" — wontfix: the skb backpointer lives in the BMan hardware-owned frag pool kmemleak can't scan; error paths free cleanly.
- **A12.** "PPPoE RX-decap missing classifier install" — wontfix: inner udp4/tcp4 dist precedes pppoe_dist; the PPPoE strip is an HM chained on the inner CT entry, not a table.
- **A15.** "cmm has no incoming xfrm subscription" — wontfix: the af_key km hook broadcasts every SA event on NETLINK_KEY grp1 (before the no-PF_KEY early-return); cmm binds it via libfci. On-DUT restart experiment (2026-08-09) confirmed no resync gap; only cmm-downtime events are lost, recoverable via `ip xfrm state flush`.
- **N7.** "vwd nf hooks leak on cdx unload with fast path enabled" — wontfix/not-a-bug: the audit claim misread the wiring. The three hooks are registered at module init (the sysfs toggle only flips the per-packet gate flag) and every path unregisters them exactly once — `dpaa_vwd_exit` → `dpaa_vwd_driver_remove` → `dpaa_vwd_down`, the failed-init unwind via `err4` (a `driver_init` failure goes to `err3`, below it — no double-unregister), and `dpaa_vwd_up`'s own `err0`. Traced link-by-link and independently re-verified.

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
- **A3e-r.** `dpa_add_eth_if`'s cascade leaked the `get_eth_iface_info` netdev ref (every post-acquisition failure incl. the helper's internal returns) and the published stats slot; normal eth removal leaked `last_stats` + the slot too (no eth arm in `free_stats`) and never unpublished `priv->ifinfo` — guarded `dev_put` at `err_ret`, new `err_stats` unwind (`dpa_reset_eth_ifinfo` + `free_iface_stats`), eth arm added, `free_iface_stats` NULL-slot-guarded and now NULLs its pointers, reset-before-free on the release path, and the discard-mask restore un-nested from `ENABLE_EGRESS_QOS` so non-QoS builds restore it on late failures (_dffbbd6_). Closes the A3 umbrella. Query-path race and alloc-contract landmine filed as N8/N9.
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
- **A24.** DNCPE-2358 root-caused and fixed; GCM/GMAC offload re-enabled. Two descriptor defects per the SEC RM: HDR_SAVECTX let SERIAL self-sharing carry GCM's class-1 GHASH/counter context into the next packet (the >18%-load ICV failures — CBC/CTR/CCM re-init context and were immune), and cross-DECO refetches weren't ordered against PDB.seq writeback because jobs only STOREd the stats words, not the PDB (RM §7.3.1 interlock — A24a's wire-seq dupes). Fix: SERIAL sharing without SAVECTX + per-job PDB+stats STORE; encap PDB now seeds sa->seq+1 (first packet of every SA used to go out as seq 0 and be replay-dropped, all ciphers). Measured at ~185 Mbit/s hardware encap: legacy ~2.8M ICV fails/12s + 0.4-0.5% dup seqs → fix 0 ICV fails + 0.086% dup seqs (CBC baseline: 0.154%) (_451bc18_).
- **A25.** AES-128-CTR lacked the RFC 3686 nonce trim and CTR PDB fields — comb_mode/extra_size=4 trim + ctr_nonce/ctr_initial=1 in both PDBs (_d5be3ae_).
- **A26.** ASK patch stack compiled with ~52 warnings (missing prototypes, bad formats, one wrong-signature extern) — 010/040 regenerated warning-free (_3b93e0e_).
- **A27.** IPsec-offload SA handle was set by a lockless `xfrm_state_handle++` in xfrm_state_alloc — non-atomic (concurrent allocs alias the same handle) and the u16 counter wrapped onto still-live handles (a per-netns get_random_bytes reseed of the shared global amplified it, colliding without even a full wrap); a duplicate mis-resolves xfrm_state_lookup_byhandle (expiry/counters/offload-flag hit the wrong SA) and trips cdx ERR_SA_DUPLICATED (rekey blackhole). Handle now assigned at byh-insert time under xfrm_state_lock with a byh dedup (new xfrm_state_insert_byh); alloc no longer burns handle values; counter seeded once from init_net (patch 040).
- **A28.** xfrm_input.c inbound-offload submit passed x->handle to SEC gated only by x->offloaded, *before* the XFRM_STATE_VALID check, and x->offloaded was never cleared on SA delete — a dead-but-still-offloaded SA could submit a stale handle to a hardware context cmm had already freed/reused. Gate the inbound submit on km.state==XFRM_STATE_VALID and clear x->offloaded in __xfrm_state_delete (before the DELSA that triggers cmm teardown; also covers the outbound path, which cdx additionally FQ-NULL-checks). Patch 040.
- **A29.** af_key.c SET_OFFLOAD handler sets x->offloaded=1 without re-checking km.state, so a lookup_byhandle racing ahead of a concurrent delete's byh unlink can resurrect offloaded=1 on a DEAD SA. Pre-existing; impact neutralized by A28 (VALID gate blocks DEAD inbound, get_ipsec_fq NULL-check blocks outbound). Optional defense-in-depth: set offloaded=1 only when km.state==XFRM_STATE_VALID. Open.

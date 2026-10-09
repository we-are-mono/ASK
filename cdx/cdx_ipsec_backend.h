/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_IPSEC_BACKEND_H
#define CDX_IPSEC_BACKEND_H

#include <linux/types.h>
#include <linux/netfilter.h>

struct net_device;
struct netlink_ext_ack;
struct xfrm_state;
struct cdx_ipsec_sa;

/* The widest key the SEC context can hold, matching IPSEC_MAX_KEY_SIZE in
 * control_ipsec.h. An AEAD key includes its salt, so a 256-bit GCM key
 * arrives here as 288 bits; the bound is on the whole buffer, not the
 * cipher's nominal strength. */
#define CDX_IPSEC_KEY_MAX 64

/* The widest anti-replay window SEC keeps for an inbound SA, in packets, and
 * so how much of a scorecard the spec and the PDB carry. */
#define CDX_IPSEC_REPLAY_WINDOW_MAX 128

/* Whether SEC keeps an inbound SA's anti-replay window at exactly `window`
 * packets, in the protocol a tunnel-mode SA, or else a transport one, runs.
 *
 * The ESP decapsulation PDB names three widths in the ARS bits of its options
 * byte, 32, 64 and 128, and nothing between them. The 128-packet one belongs
 * to the tunnel-mode protocol (OP_PCLID_IPSEC_TUNNEL, SEC's "new mode"); a
 * transport SA runs the legacy protocol (OP_PCLID_IPSEC), which has only the
 * other two. Zero is anti-replay off. Any other width is refused rather than
 * carried on another: Linux drops a number replay_window or more behind the
 * top, so a wider window would take late frames the state's own check refuses
 * and a narrower one would drop frames it takes -- the same SA judged two ways
 * depending on whether SEC or the stack sees the frame. mlx5 refuses every
 * width its hardware does not keep as well (mlx5e_xfrm_validate_state()).
 * Needs neither a transaction nor RTNL. */
static inline bool cdx_ipsec_replay_window_supported(u32 window, bool tunnel)
{
	switch (window) {
	case 0:
	case 32:
	case 64:
		return true;
	case CDX_IPSEC_REPLAY_WINDOW_MAX:
		return tunnel;
	default:
		return false;
	}
}

enum cdx_ipsec_dir {
	CDX_IPSEC_DIR_IN,
	CDX_IPSEC_DIR_OUT,
};

/* One key, in the numbering PF_KEY defines and the SEC descriptor builder
 * already consumes: SADB_AALG_* for authentication, SADB_EALG_* and
 * SADB_X_EALG_* for encryption. Those constants are UAPI, so no private
 * enumeration has to be invented, kept in step with two other tables, or
 * transcribed at the boundary -- the same reasoning that puts a
 * union nf_inet_addr in cdx_ft_rule rather than a tuple of its own.
 *
 * An AEAD transform is one key with an alg that names its ICV length
 * (SADB_X_EALG_AES_GCM_ICV8/12/16, SADB_X_EALG_AES_CCM_ICV8/12/16), so it occupies
 * `crypt` alone and leaves `auth` empty. Its icv_bits stays zero: the length
 * is part of the algorithm's identity there, and a second field naming it
 * could disagree with the first.
 *
 * An authenticator is the opposite case. PF_KEY numbers it by algorithm
 * alone, and the ICV it leaves on each frame is the SA's own truncation --
 * xfrm's alg_trunc_len, which peers choose -- so `auth` carries that length
 * beside the identity, and SEC can carry only the pairs cdx_ipsec_auth_supported()
 * admits.
 *
 * Algorithm zero is absence. SADB_AALG_NONE and SADB_EALG_NONE are both 0,
 * so a zeroed spec describes an SA with neither, which the SEC context
 * already defaults to (OP_PCL_IPSEC_HMAC_NULL / OP_PCL_IPSEC_NULL_ENC).
 */
struct cdx_ipsec_key {
	u16 alg;
	u16 bits;
	/* The ICV an authenticator leaves on each frame, in bits. Zero for a
	 * cipher and for AEAD. */
	u16 icv_bits;
	u8 key[CDX_IPSEC_KEY_MAX];
};

/* Everything an SA needs, in one value.
 *
 * xdo_dev_state_add() is handed a complete xfrm_state, so the SA is described
 * once and installed once, and there is no window in which a half-built SA is
 * reachable by handle.
 *
 * Addresses are the SA's own endpoints. In tunnel mode they are also the outer
 * header's, which the backend builds rather than receiving prebuilt: the
 * constants that header needs (the ESP next-header, the two header sizes) are
 * the backend's, and a caller assembling them would be writing hardware
 * knowledge into the adapter. Addresses and ports are in network byte order;
 * `family` selects the arm of each address and the unused bytes are zero.
 *
 * Lifetimes are not part of it. The hardware enforces none, and nothing in
 * this backend compares them either: the caller reads the counters back with
 * cdx_ipsec_sa_stats() and leaves the limits to xfrm, which holds them.
 */
struct cdx_ipsec_sa_spec {
	/* The port this SA is bound to. Packet offload binds a state to one
	 * device, and this is that device: the ingress port an inbound SA's
	 * frames arrive on, and the egress port an outbound SA's leave by.
	 * The caller pins it for as long as the SA lives. */
	struct net_device *dev;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	/* For an outbound SA, the neighbour dst_mac was resolved from: the
	 * peer when it is on-link, the route's gateway otherwise. */
	union nf_inet_addr next_hop;
	__be32 spi;
	struct cdx_ipsec_key auth;
	struct cdx_ipsec_key crypt;
	/* Non-zero on both when the SA is encapsulated in UDP. The pair is
	 * what makes it NAT-T, and the classifier keys such an SA on the full
	 * 5-tuple instead of on the SPI alone. */
	__be16 natt_sport;
	__be16 natt_dport;
	/* The SA's own MTU and that of the device it rides. The difference is
	 * the tunnel header expansion the classifier needs, so both are
	 * carried rather than the difference: the encoder wants the expansion
	 * and the fragmentation check wants the SA's own bound. */
	u16 mtu;
	u16 dev_mtu;
	/* For an outbound SA, the MTU of the path to the peer as the caller
	 * resolved it with the next hop -- a learned PMTU, a route's own or the
	 * port's -- which the entry SEC's output is classified by fragments it
	 * to. Zero takes dev_mtu. */
	u16 path_mtu;
	/* Where the SA's sequence space stands, in the units xfrm keeps it:
	 * the ESN high word included when the SA has one. For an outbound SA
	 * it is the last sequence number sent, and SEC sends the one after it
	 * first; for an inbound SA it is the highest received, where the
	 * anti-replay window starts. Zero for a fresh SA. A migrated or
	 * re-offered state carries on from where it was, rather than sending
	 * numbers its peer has already seen. */
	u64 seq;
	/* The anti-replay window an inbound SA asked for, in packets. Zero
	 * turns anti-replay off, which the SA cache records as
	 * SA_ALLOW_SEQ_ROLL. SEC keeps 32, 64 or, in tunnel mode, 128
	 * entries, and any other width is refused
	 * (cdx_ipsec_replay_window_supported()). An outbound SA checks
	 * nothing and ignores it. */
	u32 replay_window;
	/* Which sequence numbers an inbound SA has already received, at and
	 * below seq: bit k of replay_seen[k / 32] stands for seq - k. All
	 * clear for a fresh SA; a re-added state carries its history here,
	 * so that nothing it accepted before can be accepted again. */
	u32 replay_seen[CDX_IPSEC_REPLAY_WINDOW_MAX / 32];
	/* The next hop toward the remote tunnel endpoint, for an outbound SA.
	 *
	 * An outbound SA needs egress framing at install time, because the
	 * encapsulated frame leaves SEC already addressed. The caller resolves
	 * the peer itself and names the result here, exactly as a flow's rule
	 * names its own destination MAC. Ignored for an inbound SA, which is
	 * classified rather than transmitted.
	 */
	u8 dst_mac[ETH_ALEN];
	u8 family;
	u8 dir;
	/* Outer header fields for tunnel mode. `tos` is the traffic class the
	 * caller has already resolved, including whatever ECN policy the state
	 * asked for, so the backend copies it rather than deciding it. */
	u8 ttl;
	u8 tos;
	bool tunnel;
	/* Extended sequence numbers. The SEC descriptor is built differently
	 * for these, so it is part of the SA's identity rather than a runtime
	 * mode that can be turned on later. */
	bool esn;
	/* Copy the inner header's DF bit to the outer one. Meaningful for an
	 * IPv4 outbound tunnel and ignored otherwise. */
	bool copy_df;
	/* Propagate an outer CE to the inner header at decapsulation (RFC
	 * 6040), as Linux does unless the state has `noecn`. Meaningful for an
	 * inbound tunnel and ignored otherwise. */
	bool ecn;
};

/* What SEC counted for this SA, since it was installed. Packets and bytes are
 * SEC's own per-SA totals, kept in the shared descriptor, and move only
 * forward; the caller turns them into whatever units its own accounting keeps.
 */
struct cdx_ipsec_counters {
	u64 packets;
	u64 bytes;
	/* The last sequence number an outbound SA put on the wire, in the
	 * units xfrm's own oseq counts: the ESN high word included when the SA
	 * has one, the low 32 bits alone when it does not. The number the SA
	 * was installed with until the first frame; zero for an inbound SA. */
	u64 oseq;
	/* Where an inbound SA's anti-replay window stands: the highest
	 * sequence number received, in the units xfrm's own seq counts, and
	 * which numbers at and below it have been seen -- bit k of seen[k / 32]
	 * stands for seq - k, over the widest window SEC keeps. SEC checks the
	 * frames, so this is the only record of them. Zero when the SA is
	 * outbound, checks nothing, or could not be read cleanly. */
	u64 seq;
	u32 seen[CDX_IPSEC_REPLAY_WINDOW_MAX / 32];
};

/* The classes the FMan microcode counts SEC's refusals in, one counter each,
 * in the order of its own table (en_SEC_failure_stats, fm_ehash.h; microcode
 * v210.10.1), each beside the field it comes from. The table is the only
 * record of a refused frame: SEC returns it with its job status to the SA's
 * FROM_SEC queue, the IPsec offline port's microcode counts it here and drops
 * it, and nothing in software ever sees it. Global, not per SA.
 */
enum cdx_sec_refusal {
	CDX_SEC_REFUSED_ICV,		  /* icv_failures */
	CDX_SEC_REFUSED_HW,		  /* hw_errs */
	CDX_SEC_REFUSED_CCM_AAD_SIZE,	  /* CCM_AAD_size_errs */
	CDX_SEC_REFUSED_LATE,		  /* anti_replay_late_errs */
	CDX_SEC_REFUSED_REPLAY,		  /* anti_replay_replay_errs */
	CDX_SEC_REFUSED_SEQ_OVERFLOW,	  /* seq_num_overflows */
	CDX_SEC_REFUSED_DMA,		  /* DMA_errs */
	CDX_SEC_REFUSED_DECO_WATCHDOG,	  /* DECO_watchdog_timer_timedout_errs */
	CDX_SEC_REFUSED_INPUT_READ,	  /* input_frame_read_errs */
	CDX_SEC_REFUSED_PROTOCOL_FORMAT,  /* protocol_format_errs */
	CDX_SEC_REFUSED_TTL_ZERO,	  /* ipsec_ttl_zero_errs */
	CDX_SEC_REFUSED_PAD_CHECK,	  /* ipsec_pad_chk_failures */
	CDX_SEC_REFUSED_LENGTH_ROLLOVER,  /* output_frame_length_rollover_errs */
	CDX_SEC_REFUSED_TABLE_TOO_SMALL,  /* tbl_buff_too_small_errs */
	CDX_SEC_REFUSED_TABLE_DEPLETION,  /* tbl_buff_pool_depletion_errs */
	CDX_SEC_REFUSED_OUTPUT_TOO_LARGE, /* output_frame_too_large_errs */
	CDX_SEC_REFUSED_COMPOUND_WRITE,	  /* cmpnd_frame_write_errs */
	CDX_SEC_REFUSED_BUFFER_TOO_SMALL, /* buff_too_small_errs */
	CDX_SEC_REFUSED_BUFFER_DEPLETION, /* buff_pool_depletion_errs */
	CDX_SEC_REFUSED_OUTPUT_WRITE,	  /* output_frame_write_errs */
	CDX_SEC_REFUSED_COMPOUND_READ,	  /* cmpnd_frame_read_errs */
	CDX_SEC_REFUSED_PREHEADER_READ,	  /* prehdr_read_errs */
	CDX_SEC_REFUSED_OTHER,		  /* other_errs */
	CDX_SEC_REFUSAL_CLASSES
};

/* The microcode's counts as they stand, in host order. Each is a u32 that
 * only moves forward and wraps; the caller takes differences. Beside them,
 * the frames SEC did produce that the IPsec offline port then dropped because
 * QMan refused to enqueue them: its exception group full, the CPU behind, or
 * an egress port's group full. The same kind of u32, valid with `rejected_ok`. */
struct cdx_sec_refusals {
	u32 count[CDX_SEC_REFUSAL_CLASSES];
	u32 rejected;
	bool rejected_ok;
};

/* SA operations run inside the flowtable backend's transaction, taken with
 * cdx_ft_begin() and asserted with cdx_ft_assert_held(). There is deliberately
 * no second transaction here: an SA and a flow reach the same classifier
 * through the same control mutex, and a lock of this subsystem's own would
 * have to be ordered against that one for no gain. Every operation below
 * requires the transaction unless it says otherwise, and no backend operation
 * calls back into the adapter.
 */

/* Whether this device is a CDX physical port, and so can carry an offloaded
 * SA. This is an identity question and deliberately not a liveness one: an SA
 * may legitimately be installed before the link it will ride has carrier, and
 * packet offload has no software fallback, so refusing then would fail the
 * tunnel outright rather than delay it. A flow over the SA is checked against
 * the stricter cdx_ft_port_supported() when it is admitted.
 *
 * It also answers whether there is an IPsec engine behind the port at all. A
 * board without the IPsec offline port or a SEC job ring loads CDX without
 * IPsec, and then this is false for every port, for the module's life: no
 * ops are attached, no capability advertised, no SA admitted.
 *
 * Needs neither a transaction nor RTNL, so the ops attachment can call it from
 * a netdev notifier.
 */
bool cdx_ipsec_port_supported(struct net_device *dev);

/* Whether SEC can authenticate as PF_KEY algorithm `alg` with an ICV of
 * `icv_bits`: the pairs its IPsec protocol operation has, and no others (SEC
 * RM table 7-54). SEC fixes the ICV in the operation, so an SA whose
 * truncation it lacks would send every frame with an ICV of the wrong length
 * and refuse every frame its peer sent. cdx_ipsec_sa_add() refuses such an SA
 * too; this lets a caller refuse it first, with its own reason, before
 * anything is built. Needs neither a transaction nor RTNL. */
bool cdx_ipsec_auth_supported(u16 alg, unsigned int icv_bits);

/* How many SAs cdx's SA cache holds, whichever owner added them -- beside
 * cdx_ipsec_sa_count(), which counts this interface's alone, it is what shows
 * that a refused install left nothing behind. Needs no transaction. */
unsigned int cdx_ipsec_sa_cache_entries(void);

/* Install an SA and return its opaque owner.
 *
 * `x` is the kernel state this SA was built from. The backend neither keeps
 * the pointer nor takes a reference: the SEC completion path finds the state
 * by the SA's handle, which the caller publishes as x->handle, and a
 * reference here would be a cycle -- the caller destroys this SA from inside
 * the kernel's own teardown of that state, which only runs once every
 * reference is gone.
 *
 * The handle is allocated here rather than supplied. A caller has no way to
 * know which values are free -- the SA cache is indexed by them. Read it back
 * with cdx_ipsec_sa_handle() and store it wherever the caller needs to
 * recognise this SA later.
 *
 * -EOPNOTSUPP: the device, direction or transform cannot be carried.
 * -EADDRNOTAVAIL: an inbound SA's local address is not on the device.
 * -ENOSPC: no free handle or no free SEC context.
 * -EIO: the descriptor or classifier entry could not be built, or SEC failed
 *  the job deriving the HMAC split key.
 * -EBUSY, -ENOMEM: the split-key job found the job ring full, or could not be
 *  built.
 * A split-key failure also says so in `extack`.
 * On any error nothing is installed and *result is NULL.
 */
int cdx_ipsec_sa_add(const struct cdx_ipsec_sa_spec *spec, struct xfrm_state *x,
		     struct cdx_ipsec_sa **result, struct netlink_ext_ack *extack);

/* Always consumes *sa. Releases the SEC context, the classifier entry and the
 * handle. A flow still naming this SA is not the backend's problem to
 * solve: the caller retires its dependent directions first, exactly as it
 * does for a neighbour or a route.
 *
 * `last`, when not NULL, is where SEC left the SA's sequence space, read as
 * cdx_ipsec_sa_replay_state() reads it once the SA's classifier entry has
 * come out and SEC has finished the frames it had taken: nothing moves it
 * after that. All zero when there was nothing to read. Finishing takes a
 * short, bounded sleep.
 */
void cdx_ipsec_sa_del(struct cdx_ipsec_sa **sa, struct cdx_ipsec_counters *last);

/* How many SAs added here are not yet deleted, whatever became of the module
 * that added them. Transaction held. */
unsigned int cdx_ipsec_sa_count(void);

/* CDX's own, for the datapath restart: install again the entry of every SA a
 * failed delete stranded. Transaction and RTNL held. */
void cdx_ipsec_sa_restarted(void);

/* Point an outbound SA's egress framing at a different next hop.
 *
 * The peer's Ethernet address is not consulted per frame. It is written into
 * the classifier entry's header-manipulation opcodes when that entry is
 * built, so a peer that moves cannot be followed by storing a new value
 * anywhere: the entry has to come out and go back in, which is what this does.
 *
 * The SEC context is untouched. SA_SH_DESC_BUILT keeps the shared descriptor
 * -- the keys, the PDB and the outer header -- exactly as it was, so the
 * transform is never half-built and the sequence numbers do not restart.
 *
 * The rebuild re-reads the whole of the SA's egress framing, not only the
 * address named here -- the port's own hardware address included, since that
 * shares the same opcodes and the encoder now reads it from the netdev rather
 * than from a registration-time copy. So a caller that knows anything about
 * the framing has moved may pass the address it already has and let the rest
 * be picked up.
 *
 * `path_mtu` is the MTU of the path to the peer now, which the entry
 * fragments SEC's output to, capped at the port's; zero keeps the one it had.
 * It is framing too, and moves the same way: a route or a learned PMTU that
 * narrowed, or a port whose MTU changed.
 *
 * Inbound SAs are refused: they are classified rather than transmitted and
 * hold no egress framing to move.
 *
 * -EINVAL: not an outbound SA, or no usable address.
 * -EBUSY: an outbound NAT-T entry shared with another SA on the same UDP
 *  tuple. Its framing belongs to whichever SA built it and a rebuild would
 *  change nothing; try again once the other SA is gone.
 * -EIO: the old entry could not be proved gone, so nothing was rebuilt, or
 *  the rebuild failed. Either way the SA is left on the framing it had, and
 *  in the first case it can no longer be moved at all -- a second attempt
 *  would add a key the hardware still holds.
 */
int cdx_ipsec_sa_set_next_hop(struct cdx_ipsec_sa *sa, const u8 *dst_mac,
			      u16 path_mtu);

/* The handle SEC and the classifier know this SA by. Stable for the SA's
 * life, never zero, and reusable by a later SA once this one is deleted.
 */
u16 cdx_ipsec_sa_handle(const struct cdx_ipsec_sa *sa);

/* Reads the SEC context's own counters.
 *
 * SEC keeps the packet count in 32 bits and lets it wrap, so the total is
 * built here from successive readings, and that is why this takes the SA
 * mutably: a caller must read at least once per 2^32 packets the SA carries,
 * which at any rate SEC sustains is more than half an hour. A reading that
 * cannot be taken cleanly while SEC is writing is skipped, and the totals of
 * the previous one are reported again.
 */
void cdx_ipsec_sa_stats(struct cdx_ipsec_sa *sa,
			struct cdx_ipsec_counters *counters);

/* Reads where an SA's sequence space stands in SEC's PDB right now: oseq for
 * an outbound SA, seq and seen for an inbound one, as cdx_ipsec_sa_stats()
 * reports them, which it reads them with. Nothing else in `state` is touched,
 * and nothing of the SA's is: its packet and byte totals are the
 * transaction's, and this does not take it.
 *
 * So the caller has to keep the SA installed across the call by other means
 * -- the adapter holds the lock its deletion takes before the SA can be
 * retired. Needs no transaction and does not sleep, so a caller under a
 * spinlock may use it. SEC stores the PDB back after every frame; an inbound
 * window that never holds still for two readings is left unread, as the
 * stats read leaves it.
 *
 * False, with the three fields zero, when there is nothing to read: an
 * inbound SA with anti-replay off, a window that would not hold still, or a
 * descriptor that stores no PDB back.
 */
bool cdx_ipsec_sa_replay_state(const struct cdx_ipsec_sa *sa,
			       struct cdx_ipsec_counters *state);

/* Reads the microcode's count of the frames SEC refused, every class of it.
 *
 * What it counts is every refusal on every SA, whichever feeder brought the
 * frame to SEC -- the classifier's or the CPU's -- and in either direction.
 * The total loses an increment now and then when refusals arrive back to
 * back; the class a refusal lands in is the microcode's choice and not a
 * reliable one (see cdx_sec_refusal). Nothing is reset: the
 * microcode updates these read-modify-write, and a caller keeps its own
 * reading to take differences from.
 *
 * -ENODEV while the counters do not exist: FMan places them with the first
 * external hash table, and until then there is nothing to read. Needs no
 * transaction.
 */
int cdx_ipsec_sec_refusals(struct cdx_sec_refusals *refusals);

#endif

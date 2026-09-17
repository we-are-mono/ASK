/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_IPSEC_BACKEND_H
#define CDX_IPSEC_BACKEND_H

#include <linux/types.h>
#include <linux/netfilter.h>

struct net_device;
struct xfrm_state;
struct cdx_ipsec_sa;

/* The widest key the SEC context can hold, matching IPSEC_MAX_KEY_SIZE in
 * control_ipsec.h. An AEAD key includes its salt, so a 256-bit GCM key
 * arrives here as 288 bits; the bound is on the whole buffer, not the
 * cipher's nominal strength. */
#define CDX_IPSEC_KEY_MAX 64

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
 * (SADB_X_EALG_AES_GCM_ICV8/12/16, SADB_X_EALG_NULL_AES_GMAC), so it occupies
 * `crypt` alone and leaves `auth` empty. There is deliberately no separate
 * ICV field: the length is part of the algorithm's identity here, and a
 * second field naming it could disagree with the first.
 *
 * Algorithm zero is absence. SADB_AALG_NONE and SADB_EALG_NONE are both 0,
 * so a zeroed spec describes an SA with neither, which the SEC context
 * already defaults to (OP_PCL_IPSEC_HMAC_NULL / OP_PCL_IPSEC_NULL_ENC).
 */
struct cdx_ipsec_key {
	u16 alg;
	u16 bits;
	u8 key[CDX_IPSEC_KEY_MAX];
};

/* Lifetimes, in the units xfrm keeps them. Zero is unlimited, matching
 * XFRM_INF at the caller. The hardware does not enforce these: the SA timer
 * compares them against the counters SEC reports and raises the soft and hard
 * expiries, exactly as it does for the legacy owner. */
struct cdx_ipsec_lifetime {
	u64 soft_bytes;
	u64 hard_bytes;
	u64 soft_packets;
	u64 hard_packets;
};

/* Everything an SA needs, in one value.
 *
 * The legacy control plane spells this as five FCI commands in sequence --
 * CREATE, SET_KEYS, SET_TUNNEL or SET_NATT, SET_LIFETIME, SET_STATE -- because
 * PF_KEY delivers an SA to userspace in installments and CMM forwards each one
 * as it arrives. Nothing here has that constraint: xdo_dev_state_add() is
 * handed a complete xfrm_state, so the SA is described once and installed
 * once, and there is no window in which a half-built SA is reachable by
 * handle.
 *
 * Addresses are the SA's own endpoints. In tunnel mode they are also the outer
 * header's, which the backend builds rather than receiving prebuilt: the
 * constants that header needs (the ESP next-header, the two header sizes) are
 * the backend's, and a caller assembling them would be writing hardware
 * knowledge into the adapter. Addresses and ports are in network byte order;
 * `family` selects the arm of each address and the unused bytes are zero.
 */
struct cdx_ipsec_sa_spec {
	/* The port this SA is bound to. Packet offload binds a state to one
	 * device, and this is that device: the ingress port an inbound SA's
	 * frames arrive on, and the egress port an outbound SA's leave by.
	 * The caller pins it for as long as the SA lives. */
	struct net_device *dev;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	__be32 spi;
	struct cdx_ipsec_key auth;
	struct cdx_ipsec_key crypt;
	struct cdx_ipsec_lifetime lft;
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
	/* The next hop toward the remote tunnel endpoint, for an outbound SA.
	 *
	 * An outbound SA needs egress framing at install time, because the
	 * encapsulated frame leaves SEC already addressed. The legacy owner
	 * supplied that as a route object it had already been told about over
	 * FCI; this ownership mode keeps no such table, so the caller resolves
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
	/* Anti-replay is being checked. False lets the sequence number roll,
	 * which is what the legacy owner's SA_ALLOW_SEQ_ROLL means. */
	bool replay;
	/* Copy the inner header's DF bit to the outer one. Meaningful for an
	 * IPv4 outbound tunnel and ignored otherwise. */
	bool copy_df;
};

/* What SEC counted for this SA. Packets and bytes are the classifier's own
 * totals and move only forward; the caller turns them into whatever units its
 * own accounting keeps. */
struct cdx_ipsec_counters {
	u64 packets;
	u64 bytes;
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
 * Needs neither a transaction nor RTNL, so the ops attachment can call it from
 * a netdev notifier.
 */
bool cdx_ipsec_port_supported(struct net_device *dev);

/* Install an SA and return its opaque owner.
 *
 * `x` is the kernel state this SA was built from, and it is **borrowed**: the
 * backend records the pointer and takes no reference. It needs the pointer
 * because the SEC completion path has nothing but the SA's handle to work
 * from and the stack drops a decrypted frame unless a sec_path naming the
 * state is attached first. It must not take a reference because the caller is
 * expected to destroy this SA from inside the kernel's own teardown of that
 * state, which only runs once every reference is gone -- a reference here
 * would be waiting for the teardown that is waiting for it. The pointer is
 * therefore valid exactly as long as the caller honours that: destroy the SA
 * while the state is still allocated.
 *
 * The handle is allocated here rather than supplied. A caller has no way to
 * know which values are free -- the SA cache is indexed by them -- and the
 * legacy owner only got to choose because it was the only client. Read it back
 * with cdx_ipsec_sa_handle() and store it wherever the caller needs to
 * recognise this SA later.
 *
 * -EOPNOTSUPP: the device, direction or transform cannot be carried.
 * -ENOSPC: no free handle or no free SEC context.
 * -EIO: the descriptor or classifier entry could not be built.
 * On any error nothing is installed and *result is NULL.
 */
int cdx_ipsec_sa_add(const struct cdx_ipsec_sa_spec *spec, struct xfrm_state *x,
		     struct cdx_ipsec_sa **result);

/* Always consumes *sa. Releases the SEC context, the classifier entry and the
 * handle, and drops the borrowed state pointer without putting a reference it
 * never took. A flow still naming this SA is not the backend's problem to
 * solve: the caller retires its dependent directions first, exactly as it
 * does for a neighbour or a route.
 */
void cdx_ipsec_sa_del(struct cdx_ipsec_sa **sa);

/* The handle SEC and the classifier know this SA by. Stable for the SA's
 * life, never zero, and reusable by a later SA once this one is deleted.
 */
u16 cdx_ipsec_sa_handle(const struct cdx_ipsec_sa *sa);

/* Reads the SEC context's own counters. Zeroes them if the SA has not yet
 * carried a frame, which is not distinguishable from a genuinely idle SA and
 * does not need to be.
 */
void cdx_ipsec_sa_stats(const struct cdx_ipsec_sa *sa,
			struct cdx_ipsec_counters *counters);

#endif

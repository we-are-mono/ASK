// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Typed SA interface for the flowtable owner.
 *
 * An SA arrives as one complete description from a caller that already holds
 * the kernel state, and is installed in a single pass under the control mutex.
 * Everything below the translation -- the cache, the SEC context, the shared
 * descriptor, the classifier entry -- is control_ipsec.c's and
 * cdx_dpa_ipsec.c's, reached through the helpers control_ipsec.h declares.
 */

#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/xfrm.h>

#include "portdefs.h"
#include "cdx.h"
#include "cdx_common.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_ipsec.h"
#include "cdx_dpa_ipsec.h"
#include "cdx_flowtable.h"
#include "cdx_flowtable_backend.h"
#include "cdx_ipsec_backend.h"
#include "fe.h"
#include "misc.h"

#ifdef DPA_IPSEC_OFFLOAD

/* The adapter's view of an installed SA. It holds the entry rather than the
 * handle so a caller can never reach a different SA by presenting a stale
 * number: a handle is reusable once its SA is deleted, and this owner is not.
 */
struct cdx_ipsec_sa {
	PSAEntry entry;
	struct net_device *dev;
	/* The outbound SA's own egress route, embedded rather than looked up,
	 * as the flowtable gives each direction a private route: built from
	 * what the caller resolved, and owned by this SA alone. */
	RouteEntry route;
	/* The packet total cdx_ipsec_sa_stats() reports, and SEC's own count
	 * as that function last read it. SEC keeps the count in 32 bits and
	 * lets it wrap, so the total grows by the difference between readings
	 * rather than being read. */
	u64 packets;
	u32 sec_packets;
	/* SEC's byte count as last believed, which is 64 bits wide and
	 * reported as it stands, and a forward jump too large to believe on
	 * its own, waiting for the next reading to confirm it. See
	 * cdx_ipsec_sa_bytes_believable(). */
	u64 bytes;
	u64 unconfirmed_bytes;
	u16 handle;
	/* A classifier entry this SA could not prove it had removed. The
	 * delete path frees its software bookkeeping on every arm, including
	 * failure, so afterwards nothing distinguishes "no entry" from "an
	 * entry still linked under a key we no longer track" -- and a later
	 * rebuild would add that key a second time, which is exactly the
	 * duplicate bucket the delete refuses to risk. Once set, this SA's
	 * framing stops being rewritable. */
	bool stranded;
};

/* Rotating hint for the handle search below. Static because the handle space
 * is per-instance in exactly the way the SA cache is, and both are global. */
static u16 cdx_ipsec_next_handle = 1;
/* SAs installed through this interface and not yet deleted. Under the
 * transaction. */
static unsigned int cdx_ipsec_sa_owned;

unsigned int cdx_ipsec_sa_count(void)
{
	cdx_ft_assert_held();
	return cdx_ipsec_sa_owned;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_count, ASK_CDX_FLOWTABLE);

/* Find a handle no live SA holds.
 *
 * The handle is what indexes sa_cache_by_h and what SEC stamps into a
 * decrypted frame's trailer,
 * so it has to be unique among live SAs and it has to be non-zero -- zero is
 * what an absent handle reads as on both paths.
 *
 * Rotating rather than scanning from one keeps a deleted SA's handle out of
 * circulation for as long as possible. That is not a correctness requirement,
 * because deletion unlinks the entry before this can hand the number out
 * again; it means a frame still in flight from SEC when its SA went away
 * resolves to nothing rather than to whichever SA was created next.
 */
static int cdx_ipsec_alloc_handle(u16 *out)
{
	unsigned int tries;
	u16 cand;

	for (tries = 0; tries <= U16_MAX; tries++) {
		cand = cdx_ipsec_next_handle++;
		if (!cand)
			continue;
		if (M_ipsec_sa_cache_lookup_by_h(cand))
			continue;
		*out = cand;
		return 0;
	}
	return -ENOSPC;
}

bool cdx_ipsec_port_supported(struct net_device *dev)
{
	/* Identity, not liveness, and the difference is the whole point of not
	 * reusing cdx_ft_port_supported() here.
	 *
	 * That predicate also requires the port to be running with carrier,
	 * which is right for a flow: a direction installed on a dead port
	 * forwards nothing. An SA is not a flow. strongSwan can complete an
	 * exchange and install a state before the link it will ride has
	 * settled, and packet offload has no software fallback to degrade
	 * into -- a refusal fails the SA outright. Gating on carrier would
	 * therefore turn a momentary link event into a tunnel that never comes
	 * up, for no gain: a flow over this SA is checked again, under RTNL,
	 * when it is admitted.
	 *
	 * What must hold is that the device really is a CDX physical port, and
	 * dpa_netdev_is_physical() answers exactly that under its own lock --
	 * so this is safe from a notifier and from a caller holding RTNL,
	 * which is where the ops attachment runs.
	 *
	 * And that there is an engine behind the port. A board whose device
	 * tree lacks the IPsec offline port or a SEC job ring loads this module
	 * without IPsec, and the port must then not advertise a capability it
	 * cannot honour: the adapter attaches the xfrmdev ops through this
	 * predicate, so a false here is what keeps strongSwan from ever being
	 * offered hardware ESP on that port, and what refuses an SA that
	 * reaches admission anyway. Decided at module init and withdrawn only
	 * at shutdown, so like the identity beside it, never a momentary
	 * condition. */
	return dev && net_eq(dev_net(dev), &init_net) &&
	       dev->type == ARPHRD_ETHER && dev->addr_len == ETH_ALEN &&
	       dpa_netdev_is_physical(dev) && cdx_ipsec_ready();
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_port_supported, ASK_CDX_FLOWTABLE);

bool cdx_ipsec_auth_supported(u16 alg, unsigned int icv_bits)
{
	return cdx_ipsec_auth_op(alg, icv_bits) >= 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_auth_supported, ASK_CDX_FLOWTABLE);

unsigned int cdx_ipsec_sa_cache_entries(void)
{
	return M_ipsec_sa_cache_entries();
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_cache_entries, ASK_CDX_FLOWTABLE);

/* Build the outer header a tunnel-mode SA prepends.
 *
 * Built here, from the spec, keeps the ESP next header and the two header
 * sizes on this side of the interface, where the rest of the hardware's
 * format knowledge already is.
 *
 * TotalLength, Identification, the fragment fields and the checksum are left
 * zero deliberately: SEC computes them per frame, and a value placed here
 * would be overwritten rather than honoured.
 */
static void cdx_ipsec_build_tunnel(PSAEntry sa,
				   const struct cdx_ipsec_sa_spec *spec)
{
	if (spec->family == AF_INET6) {
		ipv6_hdr_t *h = &sa->tunnel.ip6;

		sa->header_len = IPV6_HDR_SIZE;
		memset(h, 0, sizeof(*h));
		h->Ver_TC_FL = (6u << 28) | ((u32)spec->tos << 20);
		h->HopLimit = spec->ttl;
		h->NextHeader = IPPROTOCOL_ESP;
		memcpy(h->SourceAddress, spec->src.ip6, sizeof(h->SourceAddress));
		memcpy(h->DestinationAddress, spec->dst.ip6,
		       sizeof(h->DestinationAddress));
	} else {
		ipv4_hdr_t *h = &sa->tunnel.ip4;

		sa->header_len = IPV4_HDR_SIZE;
		memset(h, 0, sizeof(*h));
		h->Version_IHL = 0x45;
		h->TypeOfService = spec->tos;
		h->TTL = spec->ttl;
		h->Protocol = IPPROTOCOL_ESP;
		h->SourceAddress = spec->src.ip;
		h->DestinationAddress = spec->dst.ip;
	}
	sa->mode = SA_MODE_TUNNEL;
}

/* xfrm, and so the spec, carry the NAT-T ports in network order. The SA
 * cache keeps sa->natt in host order: its consumers convert from that when
 * they build the ESP-in-UDP header and the inbound classifier key. Storing
 * the network-order value sent every UDP-encapsulated SA to a byte-swapped
 * port. */
static void cdx_ipsec_set_natt(unsigned short *sport, unsigned short *dport,
			       __be16 natt_sport, __be16 natt_dport)
{
	*sport = be16_to_cpu(natt_sport);
	*dport = be16_to_cpu(natt_dport);
}

static int cdx_ipsec_set_keys(PSAEntry sa, const struct cdx_ipsec_sa_spec *spec,
			      struct netlink_ext_ack *extack)
{
	int rc;

	if (spec->auth.alg) {
		rc = M_ipsec_sa_set_digest_key(sa, spec->auth.alg,
					       spec->auth.icv_bits,
					       spec->auth.bits,
					       (U8 *)spec->auth.key);
		/* Anything but a transform SEC lacks is the split-key job
		 * failing: a hardware failure, passed on as it is rather than
		 * as a capability the SA did not ask for. */
		if (rc && rc != -EOPNOTSUPP)
			NL_SET_ERR_MSG(extack, "cdx: SEC could not derive the HMAC split key");
		if (rc)
			return rc;
	}
	if (spec->crypt.alg &&
	    M_ipsec_sa_set_cipher_key(sa, spec->crypt.alg, spec->crypt.bits,
				      (U8 *)spec->crypt.key))
		return -EOPNOTSUPP;
	return 0;
}

/* Where the SA's sequence space starts, and the window that guards it.
 *
 * The cache create starts every SA at zero with no window of its own. Both
 * PDB builders read these when the
 * SA is installed, so this runs before that: the outbound one seeds SEC one
 * past sa->seq, the inbound one anchors its window at sa->seq and starts its
 * scorecard from what the spec says was already received. The window is an
 * inbound SA's alone; SA_ALLOW_SEQ_ROLL, set at create from a zero width, is
 * what turns it off. The spec and the PDB number the scorecard the same way,
 * so it is copied as it stands.
 */
static void cdx_ipsec_set_sequence(PSAEntry sa,
				   const struct cdx_ipsec_sa_spec *spec)
{
	static_assert(ARRAY_SIZE(spec->replay_seen) == SA_REPLAY_SEEN_WORDS);

	sa->seq = spec->seq;
	if (spec->dir != CDX_IPSEC_DIR_IN)
		return;
	sa->replay_window = spec->replay_window;
	memcpy(sa->replay_seen, spec->replay_seen, sizeof(sa->replay_seen));
}

static int cdx_ipsec_validate(const struct cdx_ipsec_sa_spec *spec)
{
	if (!spec->dev || !spec->spi)
		return -EINVAL;
	if (spec->family != AF_INET && spec->family != AF_INET6)
		return -EOPNOTSUPP;
	if (spec->dir != CDX_IPSEC_DIR_IN && spec->dir != CDX_IPSEC_DIR_OUT)
		return -EINVAL;
	/* Both or neither. One port alone does not describe an encapsulation,
	 * and the classifier would key such an SA on a tuple it cannot match. */
	if (!spec->natt_sport != !spec->natt_dport)
		return -EINVAL;
	if (spec->auth.bits > CDX_IPSEC_KEY_MAX * 8 ||
	    spec->crypt.bits > CDX_IPSEC_KEY_MAX * 8)
		return -EINVAL;
	/* A transform with neither key is a null SA. SEC would carry it, but
	 * nothing should ask: it is the shape a zeroed spec has, so accepting
	 * it turns a caller's omission into plaintext on the wire. */
	if (!spec->auth.alg && !spec->crypt.alg)
		return -EOPNOTSUPP;
	/* What SEC adds to a frame, dev_mtu - mtu, reaches the classifier in a
	 * byte (hdr_xpnd_sz). No admitted transform comes near it -- an IPv6
	 * outer header, NAT-T, a 16-byte IV and a 32-byte ICV with the worst
	 * padding is 121 -- but one that did would wrap it silently. */
	if (spec->mtu > spec->dev_mtu || spec->dev_mtu - spec->mtu > U8_MAX)
		return -EOPNOTSUPP;
	/* SEC fixes the ICV in the operation, so a truncation it has no
	 * operation for is refused here, before anything is built, rather
	 * than by the key setter once the SA exists. */
	if (spec->auth.alg &&
	    !cdx_ipsec_auth_supported(spec->auth.alg, spec->auth.icv_bits))
		return -EOPNOTSUPP;
	/* An outbound SA leaves SEC already addressed, so a next hop is part
	 * of describing it rather than something to discover later. */
	if (spec->dir == CDX_IPSEC_DIR_OUT && is_zero_ether_addr(spec->dst_mac))
		return -EINVAL;
	/* A window SEC cannot keep is refused rather than narrowed: a
	 * narrower one would drop late frames the configuration accepts. */
	if (spec->dir == CDX_IPSEC_DIR_IN &&
	    spec->replay_window > CDX_IPSEC_REPLAY_WINDOW_MAX)
		return -EOPNOTSUPP;
	/* Without ESN the sequence space is 32 bits. An outbound SA has to
	 * have a number left to send: SEC starts one past this one, and
	 * refuses to send the all-ones number itself -- FFFFFFFF without ESN,
	 * FFFFFFFF:FFFFFFFF with it (SEC RM table 9-2) -- so the last it can
	 * send is one below that. */
	if (!spec->esn && spec->seq > U32_MAX)
		return -EINVAL;
	if (spec->dir == CDX_IPSEC_DIR_OUT &&
	    spec->seq >= (spec->esn ? U64_MAX : U32_MAX) - 1)
		return -EINVAL;
	if (!cdx_ipsec_port_supported(spec->dev))
		return -EOPNOTSUPP;
	return 0;
}

/* An inbound SA's local endpoint has to be an address on the port the SA is
 * bound to. Its classifier entry is keyed on the port the address is found on,
 * and what SEC hands back is delivered through the bound port with the
 * Ethernet header of the frame that went in: on two ports, the entry would sit
 * on one and the frames be delivered on the other, addressed to someone else.
 * An address on no registered port has nothing to key the entry on at all.
 * Caller holds the control transaction. */
static int cdx_ipsec_local_on_port(const struct cdx_ipsec_sa_spec *spec,
				   U32 *daddr)
{
	struct dpa_iface_info *port;
	uint32_t itf_id;

	if (spec->dir != CDX_IPSEC_DIR_IN)
		return 0;
	port = dpa_get_ifinfo_by_netdev(spec->dev);
	if (!port)
		return -EOPNOTSUPP;
	if (dpa_get_iface_info_by_ipaddress(spec->family == AF_INET6 ? PROTO_IPV6
								     : PROTO_IPV4,
					    daddr, NULL, &itf_id, NULL, 0) != SUCCESS ||
	    itf_id != port->itf_id)
		return -EADDRNOTAVAIL;
	return 0;
}

int cdx_ipsec_sa_add(const struct cdx_ipsec_sa_spec *spec, struct xfrm_state *x,
		     struct cdx_ipsec_sa **result, struct netlink_ext_ack *extack)
{
	struct cdx_ipsec_sa *owner;
	PSAEntry sa;
	U32 saddr[4] = {};
	U32 daddr[4] = {};
	u16 handle;
	int rc;

	cdx_ft_assert_held();
	*result = NULL;
	if (!x)
		return -EINVAL;
	rc = cdx_ipsec_validate(spec);
	if (rc)
		return rc;
	if (cdx_ft_failed())
		return -EIO;

	if (spec->family == AF_INET6) {
		memcpy(saddr, spec->src.ip6, sizeof(saddr));
		memcpy(daddr, spec->dst.ip6, sizeof(daddr));
	} else {
		saddr[0] = spec->src.ip;
		daddr[0] = spec->dst.ip;
	}
	rc = cdx_ipsec_local_on_port(spec, daddr);
	if (rc)
		return rc;

	owner = kzalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner)
		return -ENOMEM;
	rc = cdx_ipsec_alloc_handle(&handle);
	if (rc)
		goto err_free_owner;

	/* The cache create allocates the SEC context and links the entry into
	 * both indexes, so from here on failure has to unwind through
	 * M_ipsec_sa_cache_delete() rather than by freeing anything directly. */
	sa = M_ipsec_sa_cache_create(saddr, daddr, spec->spi, IPPROTOCOL_ESP,
				     spec->family == AF_INET6 ? PROTO_IPV6
							      : PROTO_IPV4,
				     handle, spec->replay_window != 0, spec->esn,
				     spec->mtu, spec->dev_mtu,
				     spec->dir == CDX_IPSEC_DIR_IN
					     ? CDX_DPA_IPSEC_INBOUND
					     : CDX_DPA_IPSEC_OUTBOUND);
	if (!sa) {
		rc = -ENOSPC;
		goto err_free_owner;
	}
	cdx_ipsec_set_sequence(sa, spec);

	rc = cdx_ipsec_set_keys(sa, spec, extack);
	if (rc)
		goto err_delete_sa;

	if (spec->tunnel)
		cdx_ipsec_build_tunnel(sa, spec);
	else
		sa->mode = SA_MODE_TRANSPORT;

	/* Whether the outer header copies DF is the state's own flag, which the
	 * caller read. */
	if (spec->copy_df)
		sa->hdr_flags |= SA_HDR_COPY_DF;

	if (spec->natt_sport)
		cdx_ipsec_set_natt(&sa->natt.sport, &sa->natt.dport,
				   spec->natt_sport, spec->natt_dport);

	/* An outbound SA transmits, so it needs the egress framing now. The
	 * onif is the hardware identity of the port the caller bound the SA
	 * to, and the MAC is the next hop it resolved toward the peer. An
	 * inbound SA is classified rather than transmitted and leaves this
	 * NULL. */
	if (spec->dir == CDX_IPSEC_DIR_OUT) {
		struct dpa_iface_info *iface;
		POnifDesc onif;

		iface = dpa_get_ifinfo_by_netdev(spec->dev);
		if (!iface || iface->itf_id >= L2_MAX_ONIF) {
			rc = -EOPNOTSUPP;
			goto err_delete_sa;
		}
		onif = get_onif_by_index(iface->itf_id);
		if (!(onif->flags & ENTRY_VALID) || !onif->itf ||
		    onif->itf->index != iface->itf_id) {
			rc = -EOPNOTSUPP;
			goto err_delete_sa;
		}
		owner->route.itf = onif->itf;
		owner->route.mtu = spec->path_mtu ?
			min(spec->path_mtu, spec->dev_mtu) : spec->dev_mtu;
		ether_addr_copy(owner->route.dstmac, spec->dst_mac);
		sa->pRtEntry = &owner->route;
	}

	/* What SEC hands back on the SA's exception queue is delivered through
	 * the receive context of this device, as a DPAA port's. So it is the
	 * port the state is bound to, which validation proved is one and the
	 * caller holds -- for an inbound SA also the port its local endpoint
	 * was found on above -- and never what an address lookup finds, which
	 * can be a Wi-Fi VAP. */
	sa->netdev = spec->dev;

	rc = ipsec_install_fp_entry(sa);
	if (rc) {
		rc = -EIO;
		goto err_delete_sa;
	}

	sa->flags |= SA_ENABLED;

	owner->entry = sa;
	owner->handle = handle;
	owner->dev = spec->dev;
	cdx_ipsec_sa_owned++;
	*result = owner;
	return 0;

err_delete_sa:
	M_ipsec_sa_cache_delete(handle);
err_free_owner:
	kfree(owner);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_add, ASK_CDX_FLOWTABLE);

void cdx_ipsec_sa_del(struct cdx_ipsec_sa **sa)
{
	struct cdx_ipsec_sa *owner = *sa;
	int rc;

	cdx_ft_assert_held();
	if (!owner)
		return;
	*sa = NULL;
	if (!WARN_ON_ONCE(!cdx_ipsec_sa_owned))
		cdx_ipsec_sa_owned--;
	rc = M_ipsec_sa_cache_delete(owner->handle);
	/* The only way this fails is a handle the cache never had, which would
	 * mean this owner outlived its entry -- worth saying out loud, because
	 * the hardware entry then stays in the classifier and the next SA with
	 * the same key is refused by the hash table rather than by us. */
	if (rc)
		pr_warn("cdx: IPsec SA handle %u was not in the cache (%d); its hardware entry may be stranded\n",
			owner->handle, rc);
	kfree(owner);
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_del, ASK_CDX_FLOWTABLE);

int cdx_ipsec_sa_set_next_hop(struct cdx_ipsec_sa *sa, const u8 *dst_mac,
			      u16 path_mtu)
{
	u8 previous[ETH_ALEN];
	u16 previous_mtu;
	PSAEntry entry;
	int rc;

	cdx_ft_assert_held();
	if (!sa || !sa->entry || !dst_mac || is_zero_ether_addr(dst_mac))
		return -EINVAL;
	entry = sa->entry;
	/* Only an outbound SA has egress framing at all, and only this owner's
	 * embedded route can be rewritten -- an entry holding someone else's
	 * route is not this interface's to move. */
	if (entry->pRtEntry != &sa->route)
		return -EINVAL;
	if (sa->stranded)
		return -EIO;
	if (cdx_ft_failed())
		return -EIO;
	/* An outbound NAT-T entry shared with another SA on the same UDP
	 * tuple, which a rekey overlap produces. Its delete only drops a
	 * reference, leaving the entry -- and the address in its opcodes --
	 * exactly as it was, and the reinstall would find the same entry and
	 * take the reference back. Nothing would change and this would report
	 * that it had, so refuse instead: when the other SA goes the count
	 * falls to one and the next attempt rewrites it for real. */
	if (IS_NATT_SA(entry) && entry->ct && entry->ct->natt_out_refcnt > 1)
		return -EBUSY;

	/* The old entry has to be provably out before the new one goes in.
	 * Both carry the same key, and a bucket holding two copies of one key
	 * cannot be fully cleared afterwards -- so a delete that cannot prove
	 * the key is gone refuses the rebuild rather than making the SA
	 * unrecoverable. The unsynced arm is the exception: it parks the key
	 * in the quarantine, provably out of the table, so a rebuild over it
	 * is safe.
	 *
	 * A hard failure is terminal for this SA's framing rather than merely
	 * this attempt. The delete frees its software bookkeeping whichever
	 * way it went, so a later attempt would find no entry to remove, skip
	 * the removal, and add the same key again on top of the one still
	 * linked. The SA keeps classifying on the framing it has -- which is
	 * the state it was already in -- until it is deleted and reinstalled. */
	if (entry->ct && entry->ct->handle) {
		rc = cdx_ipsec_delete_fp_entry(entry);
		if (rc && rc != EN_EHASH_DELETE_UNSYNCED) {
			sa->stranded = true;
			pr_warn("cdx: IPsec SA handle %u could not release its classifier entry (%d); it is left on its previous next hop and cannot be moved again\n",
				sa->handle, rc);
			return -EIO;
		}
	}
	ether_addr_copy(previous, sa->route.dstmac);
	ether_addr_copy(sa->route.dstmac, dst_mac);
	previous_mtu = sa->route.mtu;
	if (path_mtu)
		sa->route.mtu = min_t(u16, path_mtu, READ_ONCE(sa->dev->mtu));
	rc = ipsec_install_fp_entry(entry);
	if (!rc)
		return 0;

	/* Put the SA back rather than leave it with no entry at all. What just
	 * failed is the same install that succeeded when this SA was created,
	 * so the retry is very likely to work -- and it ends with the SA where
	 * it started, reachable on an address that has moved, instead of with
	 * frames leaving SEC to match nothing. */
	ether_addr_copy(sa->route.dstmac, previous);
	sa->route.mtu = previous_mtu;
	if (ipsec_install_fp_entry(entry)) {
		sa->stranded = true;
		pr_err("cdx: IPsec SA handle %u lost its classifier entry while following its peer; its tunnel carries nothing until the SA is reinstalled\n",
		       sa->handle);
	}
	return -EIO;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_set_next_hop, ASK_CDX_FLOWTABLE);

u16 cdx_ipsec_sa_handle(const struct cdx_ipsec_sa *sa)
{
	return sa ? sa->handle : 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_handle, ASK_CDX_FLOWTABLE);

/* How many times to read SEC's counters again before giving up on a clean
 * reading of them. */
#define CDX_IPSEC_SAMPLE_TRIES 8

/* How far SEC's byte count may move between two readings and be believed
 * without a second look. A torn 64-bit count is out by a whole 2^32, and no
 * SA moves that much in one accounting period: at 10 Gbit/s it takes 3.4 s. */
#define CDX_IPSEC_BYTES_STEP_MAX (1ULL << 32)

/* Read SEC's per-SA counters without tearing them.
 *
 * SEC stores them back into the shared descriptor after every frame, and
 * nothing orders that store against this read. The byte count is 64 bits
 * wide and, behind an IPv4 outer header, only 4-byte aligned in the
 * descriptor, so a read that overlaps a store can take one half old and the
 * other new -- near a 2^32 boundary a count four gigabytes out, which
 * against a byte limit is a hard expiry nobody asked for. Two consecutive
 * readings that agree rule most of that out, but not all of it: the store
 * covers the PDB and the counters together, across cache lines, and two
 * reads can fall between the same two line updates. So the byte count is
 * checked for plausibility as well, below. An SA busy enough to keep the
 * readings from agreeing every time costs one skipped reading.
 */
static bool cdx_ipsec_sa_sample(PSAEntry entry, u32 *packets, u64 *bytes)
{
	unsigned int tries;
	u32 again_packets;
	u64 again_bytes;

	get_stats_from_sa(entry, packets, bytes);
	for (tries = 0; tries < CDX_IPSEC_SAMPLE_TRIES; tries++) {
		get_stats_from_sa(entry, &again_packets, &again_bytes);
		if (again_packets == *packets && again_bytes == *bytes)
			return true;
		*packets = again_packets;
		*bytes = again_bytes;
	}
	return false;
}

/* Read where an inbound SA's anti-replay window stands, as two readings that
 * agree. SEC stores the sequence number and the scorecard together after
 * every frame, and a sequence number from one frame against a scorecard from
 * another would put every bit in the wrong place. A window busy enough never
 * to hold still for two readings is left unread this time.
 */
static bool cdx_ipsec_sa_replay_sample(PSAEntry entry, u64 *seq, u32 *seen)
{
	u32 again_seen[SA_REPLAY_SEEN_WORDS];
	unsigned int tries;
	u64 again_seq;

	get_replay_from_sa(entry, seq, seen);
	for (tries = 0; tries < CDX_IPSEC_SAMPLE_TRIES; tries++) {
		get_replay_from_sa(entry, &again_seq, again_seen);
		if (again_seq == *seq &&
		    !memcmp(again_seen, seen, sizeof(again_seen)))
			return true;
		*seq = again_seq;
		memcpy(seen, again_seen, sizeof(again_seen));
	}
	return false;
}

/* Whether a clean reading of SEC's byte count can be believed.
 *
 * SEC's count only ever moves forward, so a reading that went back is torn.
 * One that rose by CDX_IPSEC_BYTES_STEP_MAX or more is torn too -- or the
 * pass was held off for seconds while the SA ran near line rate. The two are
 * told apart by the next reading: a stalled count carries on from where the
 * jump landed, within one step of it, which a torn value does not do for two
 * readings a period apart. So such a jump is held back once, and believed
 * when the reading after it confirms it; accounting never wedges on a count
 * that really did move that far.
 */
static bool cdx_ipsec_sa_bytes_believable(struct cdx_ipsec_sa *sa, u64 bytes)
{
	u64 pending = sa->unconfirmed_bytes;

	sa->unconfirmed_bytes = 0;
	if (bytes < sa->bytes)
		return false;
	if (bytes - sa->bytes < CDX_IPSEC_BYTES_STEP_MAX)
		return true;
	if (pending && bytes >= pending &&
	    bytes - pending < CDX_IPSEC_BYTES_STEP_MAX)
		return true;
	sa->unconfirmed_bytes = bytes;
	return false;
}

void cdx_ipsec_sa_stats(struct cdx_ipsec_sa *sa,
			struct cdx_ipsec_counters *counters)
{
	u32 packets;
	u64 bytes;

	static_assert(ARRAY_SIZE(counters->seen) == SA_REPLAY_SEEN_WORDS);
	cdx_ft_assert_held();
	memset(counters, 0, sizeof(*counters));
	if (!sa || !sa->entry)
		return;
	/* The extended encapsulation descriptor, which an outbound SA gets only
	 * when its features overflow the normal one, keeps no counters: its
	 * builder never enables them and leaves stats_offset at zero, where a
	 * read would take the PDB's options word for a packet count. Such an
	 * SA reports none, and xfrm judges its time limits alone. Its sequence
	 * number reads as installed, because that builder does not store the
	 * PDB back either; a stale number only ever errs low. */
	if (!sa->entry->stats_offset)
		goto sequence;
	if (cdx_ipsec_sa_sample(sa->entry, &packets, &bytes) &&
	    cdx_ipsec_sa_bytes_believable(sa, bytes)) {
		/* Unsigned 32-bit difference, so a count that wrapped since
		 * the last reading still adds what it carried. */
		sa->packets += (u32)(packets - sa->sec_packets);
		sa->sec_packets = packets;
		sa->bytes = bytes;
	}
	counters->packets = sa->packets;
	counters->bytes = sa->bytes;
sequence:
	if (sa->entry->direction == CDX_DPA_IPSEC_OUTBOUND) {
		counters->oseq = get_oseq_from_sa(sa->entry);
	} else if (!(sa->entry->flags & SA_ALLOW_SEQ_ROLL) &&
		   !cdx_ipsec_sa_replay_sample(sa->entry, &counters->seq,
					       counters->seen)) {
		counters->seq = 0;
		memset(counters->seen, 0, sizeof(counters->seen));
	}
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_stats, ASK_CDX_FLOWTABLE);

int cdx_ipsec_sec_refusals(struct cdx_sec_refusals *refusals)
{
	/* Zeroed, so a field the reader left unset could only ever read as
	 * nothing counted, never as a stack word taken for a count. */
	en_SEC_failure_stats stats = { 0 };
	u32 *count = refusals->count;

	/* One class per counter of the microcode's: a counter added to its
	 * table has to be given a class here before this builds again. */
	static_assert(sizeof(stats) == sizeof(refusals->count));
	/* The reader converts from MURAM's big-endian itself (GET_UINT32). */
	if (ExternalHashGetSECfailureStats(&stats))
		return -ENODEV;
	count[CDX_SEC_REFUSED_ICV] = stats.icv_failures;
	count[CDX_SEC_REFUSED_HW] = stats.hw_errs;
	count[CDX_SEC_REFUSED_CCM_AAD_SIZE] = stats.CCM_AAD_size_errs;
	count[CDX_SEC_REFUSED_LATE] = stats.anti_replay_late_errs;
	count[CDX_SEC_REFUSED_REPLAY] = stats.anti_replay_replay_errs;
	count[CDX_SEC_REFUSED_SEQ_OVERFLOW] = stats.seq_num_overflows;
	count[CDX_SEC_REFUSED_DMA] = stats.DMA_errs;
	count[CDX_SEC_REFUSED_DECO_WATCHDOG] = stats.DECO_watchdog_timer_timedout_errs;
	count[CDX_SEC_REFUSED_INPUT_READ] = stats.input_frame_read_errs;
	count[CDX_SEC_REFUSED_PROTOCOL_FORMAT] = stats.protocol_format_errs;
	count[CDX_SEC_REFUSED_TTL_ZERO] = stats.ipsec_ttl_zero_errs;
	count[CDX_SEC_REFUSED_PAD_CHECK] = stats.ipsec_pad_chk_failures;
	count[CDX_SEC_REFUSED_LENGTH_ROLLOVER] = stats.output_frame_length_rollover_errs;
	count[CDX_SEC_REFUSED_TABLE_TOO_SMALL] = stats.tbl_buff_too_small_errs;
	count[CDX_SEC_REFUSED_TABLE_DEPLETION] = stats.tbl_buff_pool_depletion_errs;
	count[CDX_SEC_REFUSED_OUTPUT_TOO_LARGE] = stats.output_frame_too_large_errs;
	count[CDX_SEC_REFUSED_COMPOUND_WRITE] = stats.cmpnd_frame_write_errs;
	count[CDX_SEC_REFUSED_BUFFER_TOO_SMALL] = stats.buff_too_small_errs;
	count[CDX_SEC_REFUSED_BUFFER_DEPLETION] = stats.buff_pool_depletion_errs;
	count[CDX_SEC_REFUSED_OUTPUT_WRITE] = stats.output_frame_write_errs;
	count[CDX_SEC_REFUSED_COMPOUND_READ] = stats.cmpnd_frame_read_errs;
	count[CDX_SEC_REFUSED_PREHEADER_READ] = stats.prehdr_read_errs;
	count[CDX_SEC_REFUSED_OTHER] = stats.other_errs;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sec_refusals, ASK_CDX_FLOWTABLE);

#endif /* DPA_IPSEC_OFFLOAD */

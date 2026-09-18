// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Typed SA interface for the flowtable owner.
 *
 * The legacy control plane reaches the same SA cache through FCI: strongSwan
 * programs XFRM, the kernel broadcasts the state on a private netlink family,
 * CMM re-encodes each message as an FCI command and cdx decodes it again. This
 * file is what replaces every hop of that but the first. An SA arrives as one
 * complete description from a caller that already holds the kernel state, and
 * is installed in a single pass under the control mutex.
 *
 * What it does not do is duplicate the SA machinery. Everything below the
 * translation -- the cache, the SEC context, the shared descriptor, the
 * classifier entry -- is the code control_ipsec.c and cdx_dpa_ipsec.c already
 * run for the legacy owner, reached through the helpers control_ipsec.h now
 * declares. Only the door is new.
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

#ifdef DPA_IPSEC_OFFLOAD

/* The adapter's view of an installed SA. It holds the entry rather than the
 * handle so a caller can never reach a different SA by presenting a stale
 * number: a handle is reusable once its SA is deleted, and this owner is not.
 */
struct cdx_ipsec_sa {
	PSAEntry entry;
	struct net_device *dev;
	/* The outbound SA's own egress route, embedded rather than looked up.
	 *
	 * The legacy owner resolves sa->pRtEntry out of CDX's route table,
	 * which CMM fills over FCI and which this ownership mode leaves empty
	 * by design -- the flowtable gives each direction a private route for
	 * the same reason. So an SA gets one too, built from what the caller
	 * resolved, and it never joins the legacy route hash, its reference
	 * counting or its ageing. */
	RouteEntry route;
	u16 handle;
};

/* Rotating hint for the handle search below. Static because the handle space
 * is per-instance in exactly the way the SA cache is, and both are global. */
static u16 cdx_ipsec_next_handle = 1;

/* Find a handle no live SA holds.
 *
 * The legacy owner never needed this: CMM chose the sagd and cdx trusted it,
 * which works only while there is exactly one client. The handle is what
 * indexes sa_cache_by_h and what SEC stamps into a decrypted frame's trailer,
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
	 * which is where the ops attachment runs. */
	return dev && net_eq(dev_net(dev), &init_net) &&
	       dev->type == ARPHRD_ETHER && dev->addr_len == ETH_ALEN &&
	       dpa_netdev_is_physical(dev);
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_port_supported, ASK_CDX_FLOWTABLE);

/* Build the outer header a tunnel-mode SA prepends.
 *
 * The legacy path receives this prebuilt over FCI, assembled by the kernel
 * patch that serialises the state. Doing it here instead keeps the ESP next
 * header and the two header sizes on this side of the interface, where the
 * rest of the hardware's format knowledge already is.
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

static int cdx_ipsec_set_keys(PSAEntry sa, const struct cdx_ipsec_sa_spec *spec)
{
	if (spec->auth.alg &&
	    M_ipsec_sa_set_digest_key(sa, spec->auth.alg, spec->auth.bits,
				      (U8 *)spec->auth.key))
		return -EOPNOTSUPP;
	if (spec->crypt.alg &&
	    M_ipsec_sa_set_cipher_key(sa, spec->crypt.alg, spec->crypt.bits,
				      (U8 *)spec->crypt.key))
		return -EOPNOTSUPP;
	return 0;
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
	/* An outbound SA leaves SEC already addressed, so a next hop is part
	 * of describing it rather than something to discover later. */
	if (spec->dir == CDX_IPSEC_DIR_OUT && is_zero_ether_addr(spec->dst_mac))
		return -EINVAL;
	if (!cdx_ipsec_port_supported(spec->dev))
		return -EOPNOTSUPP;
	return 0;
}

int cdx_ipsec_sa_add(const struct cdx_ipsec_sa_spec *spec, struct xfrm_state *x,
		     struct cdx_ipsec_sa **result)
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

	owner = kzalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner)
		return -ENOMEM;
	rc = cdx_ipsec_alloc_handle(&handle);
	if (rc)
		goto err_free_owner;

	/* The cache create allocates the SEC context and links the entry into
	 * all three indexes, so from here on failure has to unwind through
	 * M_ipsec_sa_cache_delete() rather than by freeing anything directly. */
	sa = M_ipsec_sa_cache_create(saddr, daddr, spec->spi, IPPROTOCOL_ESP,
				     spec->family == AF_INET6 ? PROTO_IPV6
							      : PROTO_IPV4,
				     handle, spec->replay, spec->esn,
				     spec->mtu, spec->dev_mtu,
				     spec->dir == CDX_IPSEC_DIR_IN
					     ? CDX_DPA_IPSEC_INBOUND
					     : CDX_DPA_IPSEC_OUTBOUND);
	if (!sa) {
		rc = -ENOSPC;
		goto err_free_owner;
	}

	rc = cdx_ipsec_set_keys(sa, spec);
	if (rc)
		goto err_delete_sa;

	if (spec->tunnel)
		cdx_ipsec_build_tunnel(sa, spec);
	else
		sa->mode = SA_MODE_TRANSPORT;

	/* The cache create decides SA_HDR_COPY_DF for an IPv4 outbound SA on
	 * its own, which is the legacy owner's fixed policy. Honour what the
	 * caller asked instead: it read the state's own flags. */
	if (spec->copy_df)
		sa->hdr_flags |= SA_HDR_COPY_DF;
	else
		sa->hdr_flags &= ~SA_HDR_COPY_DF;

	if (spec->natt_sport) {
		sa->natt.sport = spec->natt_sport;
		sa->natt.dport = spec->natt_dport;
		sa->natt.socket = NULL;
	}

	/* An outbound SA transmits, so it needs the egress framing now. The
	 * onif is the hardware identity of the port the caller bound the SA
	 * to, and the MAC is the next hop it resolved toward the peer. An
	 * inbound SA is classified rather than transmitted and leaves this
	 * NULL, which is what the legacy path also does for it. */
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
		owner->route.mtu = spec->dev_mtu;
		ether_addr_copy(owner->route.dstmac, spec->dst_mac);
		/* One holder: this SA. sa_remove() puts the route on teardown,
		 * and that put warns on an unbalanced count -- so the embedded
		 * route carries the reference a table-held one would have,
		 * rather than the shared release path learning to special-case
		 * a route it did not hand out. */
		owner->route.nbref = 1;
		sa->pRtEntry = &owner->route;
	}

	sa->lft_conf.soft_byte_limit = spec->lft.soft_bytes;
	sa->lft_conf.hard_byte_limit = spec->lft.hard_bytes;
	sa->lft_conf.soft_packet_limit = spec->lft.soft_packets;
	sa->lft_conf.hard_packet_limit = spec->lft.hard_packets;

	/* Borrowed, deliberately without a reference.
	 *
	 * A reference here would be a cycle. The kernel tears an offloaded SA
	 * down through xdo_dev_state_free(), which ___xfrm_state_destroy()
	 * reaches only once the last reference to the state is gone -- so a
	 * reference held by this SA would be waiting for the teardown that is
	 * waiting for it, and neither would ever happen. The pointer is safe
	 * without one because the caller destroys this SA from inside that
	 * same free callback, while the state is still allocated.
	 *
	 * It is bound before the entry is installed rather than after, because
	 * frames can arrive from SEC the moment the entry exists and the
	 * completion path needs the state to attach a sec_path to them. */
	sa->xfrm_state = x;

	rc = ipsec_install_fp_entry(sa);
	if (rc) {
		rc = -EIO;
		goto err_clear_state;
	}

	sa->flags |= SA_ENABLED;
	sa->state = SA_STATE_VALID;
	sa->lft_cur.bytes = 0;
	sa->lft_cur.packets = 0;

	owner->entry = sa;
	owner->handle = handle;
	owner->dev = spec->dev;
	*result = owner;
	return 0;

err_clear_state:
	sa->xfrm_state = NULL;
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
	/* Drop the borrowed state pointer before the release path runs. That
	 * path puts a reference for the legacy owner, which does hold one --
	 * this SA does not, for the reason cdx_ipsec_sa_add() gives, so the
	 * put has to be given nothing to do rather than a reference that was
	 * never taken. */
	if (owner->entry)
		owner->entry->xfrm_state = NULL;
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

u16 cdx_ipsec_sa_handle(const struct cdx_ipsec_sa *sa)
{
	return sa ? sa->handle : 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_handle, ASK_CDX_FLOWTABLE);

void cdx_ipsec_sa_stats(const struct cdx_ipsec_sa *sa,
			struct cdx_ipsec_counters *counters)
{
	cdx_ft_assert_held();
	counters->packets = 0;
	counters->bytes = 0;
	if (!sa || !sa->entry)
		return;
	counters->packets = sa->entry->stats.total_pkts_processed;
	counters->bytes = sa->entry->stats.total_bytes_processed;
}
EXPORT_SYMBOL_NS_GPL(cdx_ipsec_sa_stats, ASK_CDX_FLOWTABLE);

#endif /* DPA_IPSEC_OFFLOAD */

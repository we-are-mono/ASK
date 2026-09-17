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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/xfrm.h>

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
	/* An SA rides a flow, and a flow's ports must already satisfy the
	 * flowtable contract. Answering anything wider here would accept an SA
	 * bound to a device no direction could ever be installed on, which
	 * fails later and further from the cause -- and, under packet offload,
	 * fails as a black hole rather than as a refusal, because the stack
	 * has already stopped encrypting for a state the hardware accepted. */
	return cdx_ft_port_supported(dev);
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

	sa->lft_conf.soft_byte_limit = spec->lft.soft_bytes;
	sa->lft_conf.hard_byte_limit = spec->lft.hard_bytes;
	sa->lft_conf.soft_packet_limit = spec->lft.soft_packets;
	sa->lft_conf.hard_packet_limit = spec->lft.hard_packets;

	/* Bind the state before the entry exists, not after. The SEC
	 * completion path resolves a decrypted frame's SA from the handle in
	 * its trailer and needs the state to attach a sec_path; installing the
	 * entry first would open a window in which frames arrive for an SA
	 * whose state is not yet reachable, and they would be dropped. */
	xfrm_state_hold(x);
	sa->xfrm_state = x;

	rc = ipsec_install_fp_entry(sa);
	if (rc) {
		rc = -EIO;
		goto err_put_state;
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

err_put_state:
	sa->xfrm_state = NULL;
	xfrm_state_put(x);
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

	cdx_ft_assert_held();
	if (!owner)
		return;
	*sa = NULL;
	/* The cache delete releases the state reference along with the SEC
	 * context and the classifier entry, which is why none is dropped here:
	 * the teardown can be deferred behind an FQ retire, and the state has
	 * to outlive whatever is still in flight. */
	M_ipsec_sa_cache_delete(owner->handle);
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

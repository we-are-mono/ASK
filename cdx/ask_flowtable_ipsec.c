// SPDX-License-Identifier: GPL-2.0-or-later
/* The IPsec adapter: xfrm packet offload state and policy ops, the SA
 * watch and its follow work, path MTU, and SEC accounting.
 */
#include "ask_flowtable_internal.h"

/* The largest inner packet an ESP state carries in one frame of `mtu` bytes:
 * what xfrm_state_mtu() answers for the state once it is valid, with the
 * outer and ESP headers, the IV, the ICV, the trailer and the worst-case
 * padding all taken off.
 *
 * Not xfrm_state_mtu() itself, which answers by the state's lifecycle rather
 * than its transform. xfrm_user hands the state to the driver before
 * inserting it, while it is still XFRM_STATE_VOID, and for such a state that
 * function returns only mtu - header_len; a migrated state arrives already
 * valid. The same SA was programmed two ways, and on the add path its
 * classifier expansion (dev_mtu - mtu) left out the ICV, trailer and padding.
 * The microcode adds that expansion to a packet bound for SEC before its size
 * check, the one that hands an oversized IPv4 packet with DF to Linux for
 * Fragmentation Needed: a DF packet over the SA's MTU by up to that much went
 * to SEC instead and left it larger than the port, DF copied to the outer
 * header, where Linux would have answered with the SA's MTU.
 *
 * x->data is ESP's AEAD transform, which __xfrm_init_state() has built by the
 * time any driver sees the state, and the only thing this reads of it is
 * what xfrm_state_mtu() reads.
 */
static u32 ft_ipsec_esp_mtu(struct xfrm_state *x, u32 mtu)
{
	struct crypto_aead *aead = x->data;
	u32 header_len = x->props.header_len;
	u32 blksize, net_adj = 0, overhead, payload_mtu;

	if (!aead)
		return mtu > header_len ? mtu - header_len : 1;
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	if (x->props.mode == XFRM_MODE_TRANSPORT)
		net_adj = x->props.family == AF_INET6 ? sizeof(struct ipv6hdr)
						      : sizeof(struct iphdr);
	overhead = header_len + crypto_aead_authsize(aead) + net_adj;
	if (mtu <= overhead)
		return 1;
	payload_mtu = (mtu - overhead) & ~(blksize - 1);
	if (payload_mtu <= 2)
		return 1;
	return payload_mtu + net_adj - 2;
}

/* The bound an outbound SA puts on a direction over the path its frames take
 * now, and what SEC adds to a packet at that bound.
 *
 * `outer` is the route the SA's frames leave by: the child of the bundle the
 * direction's lookup built, which is where Linux's own bound for the
 * direction starts (xfrm_init_pmtu()). Its MTU is the PMTU learned for the
 * peer while one is current, else the route's own, else its device's
 * (dst_mtu()), so a hop narrower than the port -- a DSL modem at 1492 -- is
 * in it, and so is a port whose MTU changed after the SA was installed; the
 * SA's own figures date from its install and see neither.
 *
 * False when the expansion does not fit the byte the classifier carries it in
 * (hdr_xpnd_sz), which no admitted transform comes near.
 */
static bool ft_ipsec_bound(struct xfrm_state *x, const struct dst_entry *outer,
			   u16 *mtu, u8 *expansion)
{
	u32 path = dst_mtu(outer), inner = ft_ipsec_esp_mtu(x, path);

	if (path <= inner || path - inner > U8_MAX)
		return false;
	*mtu = inner;
	*expansion = path - inner;
	return true;
}

/* Borrow the route selected by Netfilter, not a second FIB lookup which could
 * lose its policy/ingress context. The callback supplies retained NEIGH and
 * XFRM dsts with the cookie they were selected under: an IPv6 destination
 * belongs to one FIB generation and dst_check() rejects every one of them
 * against a zero cookie. No route pointer escapes the callback. A transformed
 * destination is handed over rather than withheld, and ft_next_hop()
 * says what that costs: the route that transmits is the one under the bundle,
 * and the address to resolve on it is the tunnel's far end. dev is the
 * logical egress device, which is the VLAN subinterface rather than the
 * physical port when the flow is tagged; the destination Netfilter selected
 * belongs to that device. */
/* The one offloaded SA a resolved transform names, or NULL.
 *
 * A bundle deeper than one transform is refused here rather than by each
 * caller: nothing proves the opcode order a stacked bundle needs, so such a
 * flow belongs in software whichever end asked about it.
 */
static struct xfrm_state *ft_ipsec_offloaded(const struct dst_entry *bundle,
					     struct net_device *dev)
{
	struct xfrm_state *x = dst_xfrm(bundle);

	if (!x || dst_xfrm(xfrm_dst_child(bundle)))
		return NULL;		/* nothing, or a bundle deeper than one */
	if (x->xso.type != XFRM_DEV_OFFLOAD_PACKET || !x->xso.offload_handle ||
	    x->km.state != XFRM_STATE_VALID)
		return NULL;		/* the stack is doing this one */
	if (x->xso.dev != dev)
		return NULL;		/* another port's SEC context */
	return x;
}

/* The receiving end of a direction, as the SAs that could have decrypted its
 * frames are asked about it: the port those frames arrive by, and the tuple
 * they carry once decrypted, in the flow's own family. */
struct ft_ipsec_receiver {
	struct net_device *in;
	struct flowi fl;
	u16 family;
};

/* How many inbound SAs one pair of endpoints is asked about, newest first:
 * one per child SA between the two, and two for each while a rekey overlaps.
 * A pair with more carries the flows of the oldest in software. */
#define FT_IPSEC_PAIRED_MAX	16

static unsigned int ft_ipsec_inbound_candidates(const struct xfrm_state *out,
						const struct net_device *in,
						struct xfrm_state **held,
						unsigned int max);

/* Name the offloaded inbound SA paired with an outbound one, for the tuple the
 * receiving end is asked about.
 *
 * A child SA is installed as a pair with mirrored endpoints, so the inbound
 * halves of `out` are the states whose destination is our local endpoint and
 * whose source is the peer. There can be several: one per child SA the two
 * endpoints negotiated, each for its own traffic selectors, and two for one
 * child while a rekey overlaps. The one named is the one the kernel itself
 * would accept this tuple from -- its selector covers the tuple and the
 * forwarding policy's templates take it (xfrm_flowtable_policy_check()) -- and
 * of those the most recently installed, which is the one a peer moves its
 * traffic to after a rekey. The offline-port lookup uses the inner tuple, and
 * its forwarding action validates the decrypting SA's SEC-inserted VLAN tag.
 * Another SA's frame goes to Linux with its own secpath for a fresh policy
 * check, even when the tuple matches this entry (A280/A287).
 *
 * Three outcomes. A usable one is named. With none among this adapter's SAs,
 * xfrm's own index decides as it always has: no state for the pair at all, or
 * only offloaded ones that do not take this tuple, leaves the receiving handle
 * unset, and the caller must still prove that forwarding policy permits
 * plaintext before admitting the connection. One that exists and is not usable
 * -- software, another port's, dead -- is a refusal: its frames are decrypted
 * before they could match this tuple, so the entry would be installed, counted
 * and never matched.
 *
 * A flow named for the older SA of a rekey keeps validating that SA until
 * its retirement. The newer SA's frames take the CPU exception during that
 * overlap; after withdrawal and readmission the entry validates the newer
 * SA. Both can deliver legitimate traffic, and neither inherits the other's
 * policy authorization through a tuple collision.
 */
static bool ft_ipsec_paired_inbound(const struct xfrm_state *out,
				    const struct ft_ipsec_receiver *recv,
				    u16 *handle, struct xfrm_state **received)
{
	struct xfrm_state *held[FT_IPSEC_PAIRED_MAX], *x, *named = NULL;
	unsigned int count, i;
	bool usable;

	*handle = 0;
	count = ft_ipsec_inbound_candidates(out, recv->in, held, ARRAY_SIZE(held));
	for (i = 0; i < count; i++) {
		x = held[i];
		if (!named && x->km.state == XFRM_STATE_VALID &&
		    xfrm_flowtable_policy_check(&init_net, &recv->fl, recv->family, x)) {
			*handle = cdx_ipsec_sa_handle(
				(struct cdx_ipsec_sa *)READ_ONCE(x->xso.offload_handle));
			if (*handle) {
				named = x;
				continue;
			}
		}
		xfrm_state_put(x);
	}
	if (named) {
		if (received)
			*received = named;
		else
			xfrm_state_put(named);
		return true;
	}
	x = xfrm_state_lookup_byaddr(&init_net, out->mark.v, &out->props.saddr,
				     &out->id.daddr, IPPROTO_ESP,
				     out->props.family);
	if (!x)
		return true;		/* caller checks receiving policy */
	usable = x->xso.type == XFRM_DEV_OFFLOAD_PACKET &&
		 x->xso.dir == XFRM_DEV_OFFLOAD_IN && x->xso.offload_handle &&
		 x->xso.dev == recv->in && x->km.state == XFRM_STATE_VALID;
	xfrm_state_put(x);
	return usable;			/* and the caller checks receiving policy */
}

/* Record the handle this end of the direction needs, and say whether the
 * direction may be installed at all.
 *
 * The sending end names the state it found. The receiving end names that
 * state's inbound half instead. A missing half is usable only if the caller
 * proves the receiving policy allows plaintext; one-way tunnels remain legal.
 */
static bool ft_ipsec_record(const struct xfrm_state *x,
			    const struct ft_ipsec_receiver *recv,
			    u16 *handle, struct xfrm_state **received)
{
	if (!recv) {
		*handle = cdx_ipsec_sa_handle(
			(struct cdx_ipsec_sa *)READ_ONCE(x->xso.offload_handle));
		return *handle != 0;
	}
	return ft_ipsec_paired_inbound(x, recv, handle, received);
}

/* What transform covers `fl` leaving `dev`, and which SA handle this direction
 * should record because of it.
 *
 * Two questions share this one lookup, because they are the same question
 * asked from opposite ends of a direction:
 *
 *   `recv == NULL` -- what encrypts the frames this direction *sends*.
 *     *handle receives that outbound SA's handle.
 *   `recv != NULL` -- what the frames this direction *receives* were
 *     encrypted by. The tuple passed is the reversed one, so the policy found
 *     is the one that would transform those frames had this gateway sent them,
 *     and the SA that actually decrypted them is that policy's inbound half on
 *     `recv->in` that takes `recv->fl`. *handle receives its handle.
 *
 * The question has to be asked of the policy, not only of the borrowed
 * destination. A transformed dst reaches the flowtable only when the packet
 * that created the flow was itself transformed, which is whichever direction
 * won the race -- the other one is routed by nf_route() with a plain FIB
 * lookup and transformed later, so its cached destination carries nothing.
 * Reading the destination alone therefore answers "no policy" for exactly the
 * flows a gateway encrypts. A carried bundle can also predate a policy change,
 * so both cases resolve the current policy from the underlying route.
 *
 * Refusal differs by end, and deliberately so:
 *
 *   sending   -- a policy that claims the tuple and resolves to nothing the
 *     hardware can carry is a refusal. An entry that forwards in hardware what
 *     a policy says to encrypt sends it in the clear, and the policy never
 *     gets a say; fifty-nine packets went that way on the bench.
 *   receiving -- a policy proves nothing about what the far end actually
 *     sends, so only a *state* does. An inbound SA for this pair that exists
 *     and cannot be named is a refusal, because its frames are decrypted
 *     before they could match this tuple and an entry keyed on the physical
 *     port would match nothing at all. Its absence is simply a direction whose
 *     frames arrive in the clear. The caller checks the receiving policy
 *     separately before accepting that interpretation.
 *
 * KEEP_DST_REF is what makes the lookup safe on a destination this code does
 * not own: without it a matching policy releases the reference the caller
 * borrowed.
 *
 * The sending end also takes its bound from the same bundle, into `sa_mtu`
 * and `sa_expansion` when given (ft_ipsec_bound()).
 */
static bool ft_ipsec_resolve(struct dst_entry *dst, struct flowi *fl,
			     struct net_device *dev,
			     const struct ft_ipsec_receiver *recv,
			     u16 *handle, struct xfrm_state **received,
			     u16 *sa_mtu, u8 *sa_expansion)
{
	struct dst_entry *bundle;
	struct xfrm_state *x;
	bool ok;

	*handle = 0;
	if (received)
		*received = NULL;
	if (!dst)
		return true;
	/* A packet may carry a bundle selected before the current policy
	 * generation. Resolve against its underlying route so that a fresh
	 * admission cannot reuse an old policy decision. */
	dst = xfrm_dst_path(dst);

	/* Take a reference before asking, because a matching policy consumes
	 * one. xfrm_bundle_create() links the destination into the bundle it
	 * builds and takes over the caller's reference to it; KEEP_DST_REF
	 * only suppresses the extra release on the paths that fail. The
	 * destination here is borrowed from the callback and this code owns no
	 * reference to it, so without this the bundle would consume one that
	 * was never ours -- and releasing the bundle below would free a
	 * destination the flowtable still uses. KASAN caught exactly that, as
	 * a slab-use-after-free in rcuref_put(). */
	dst_hold(dst);
	bundle = xfrm_lookup(&init_net, dst, fl, NULL,
			     XFRM_LOOKUP_KEEP_DST_REF);
	if (IS_ERR(bundle)) {
		dst_release(dst);
		/* A policy matched and no state could be resolved. Sending
		 * this in hardware would bypass it, so refuse and let the
		 * software path make whatever decision the policy asks for --
		 * an acquire, a block, or a drop. Receiving is unaffected:
		 * nothing has been decrypted, so nothing is arriving. */
		return !!recv;
	}
	if (bundle == dst) {
		u16 family = dst->ops->family;
		/* A device with disable_xfrm: Linux sends by it without
		 * asking policy at all, so neither does this. */
		bool noxfrm = dst->flags & DST_NOXFRM;

		/* No transform applies. Nothing consumed the reference taken
		 * above, so give it back. For the sending end that is not yet
		 * the answer: an optional ("level use") template whose SA does
		 * not exist yet resolves to nothing as well, and an entry
		 * admitted plain would stay plain once the SA appears -- where
		 * Linux, checking policy on every packet (patch 140 keeps them
		 * off the software flowtable while a policy exists), encrypts.
		 * So a direction is sent in hardware only where policy asks
		 * for no transform at all. */
		dst_release(dst);
		return recv || noxfrm || xfrm_flowtable_out_plain(&init_net, fl, family);
	}

	x = ft_ipsec_offloaded(bundle, dev);
	ok = x ? ft_ipsec_record(x, recv, handle, received) : !!recv;
	if (ok && x && !recv && sa_mtu &&
	    !ft_ipsec_bound(x, xfrm_dst_child(bundle), sa_mtu, sa_expansion))
		ok = false;
	/* Releases the whole chain, including the reference the bundle took
	 * over from us above. */
	dst_release(bundle);
	return ok;
}

/* The tuple a direction presents to policy on its way out of a port.
 *
 * `reverse` builds the other direction's, which is this one's inverse: what
 * this direction received is what the far end sent, and the untranslated pair
 * is what the peer addressed. Ports are carried because a policy selector can
 * name them, and a flowi missing them would fail to match a policy that does.
 * So is the mark, which the kernel decodes from the packet: the connection's,
 * as the receiving end takes it, since admission allows only marks the QoS
 * mask covers and the packets of an admitted flow carry its connection's.
 */
static void ft_ipsec_flowi(const struct cdx_ft_rule *rule, bool reverse,
			   struct net_device *out, u32 mark, struct flowi *fl)
{
	const union nf_inet_addr *src = reverse ? &rule->dst : &rule->new_src;
	const union nf_inet_addr *dst = reverse ? &rule->src : &rule->new_dst;
	__be16 sport = reverse ? rule->dport : rule->new_sport;
	__be16 dport = reverse ? rule->sport : rule->new_dport;

	memset(fl, 0, sizeof(*fl));
	if (rule->family != AF_INET) {
		fl->u.ip6.daddr = dst->in6;
		fl->u.ip6.saddr = src->in6;
		fl->u.ip6.fl6_dport = dport;
		fl->u.ip6.fl6_sport = sport;
	} else {
		fl->u.ip4.daddr = dst->ip;
		fl->u.ip4.saddr = src->ip;
		fl->u.ip4.fl4_dport = dport;
		fl->u.ip4.fl4_sport = sport;
	}
	fl->flowi_proto = rule->proto;
	fl->flowi_oif = out->ifindex;
	fl->flowi_mark = mark;
}

/* Whether output policy lets the tuple `fl` through at all. A lookup that fails
 * is a block, or a transform with no state to apply; which transform one that
 * succeeds resolves to is not asked here. The reference handling is
 * ft_ipsec_resolve()'s. */
static bool ft_ipsec_permits(struct dst_entry *dst, struct flowi *fl)
{
	struct dst_entry *bundle;

	if (!dst)
		return true;
	dst = xfrm_dst_path(dst);
	dst_hold(dst);
	bundle = xfrm_lookup(&init_net, dst, fl, NULL, XFRM_LOOKUP_KEEP_DST_REF);
	if (IS_ERR(bundle)) {
		dst_release(dst);
		return false;
	}
	/* The plain route, or a bundle that took over the reference above. */
	dst_release(bundle);
	return true;
}

/* The tuple ip_forward() and ip6_forward() present to output policy before
 * NF_INET_FORWARD (xfrm4_route_forward(), xfrm6_route_forward()): between the
 * translations, with DNAT done and this direction's SNAT not yet. Whether it
 * differs from the one ft_ipsec_flowi() builds is the return value. */
static bool ft_ipsec_forward_flowi(const struct cdx_ft_rule *rule,
				   struct net_device *out, u32 mark, struct flowi *fl)
{
	ft_ipsec_flowi(rule, false, out, mark, fl);
	if (nf_inet_addr_cmp(&rule->src, &rule->new_src) &&
	    rule->sport == rule->new_sport)
		return false;
	if (rule->family != AF_INET) {
		fl->u.ip6.saddr = rule->src.in6;
		fl->u.ip6.fl6_sport = rule->sport;
	} else {
		fl->u.ip4.saddr = rule->src.ip;
		fl->u.ip4.fl4_sport = rule->sport;
	}
	return true;
}

/* Whether a change to `pol` can alter what admission concluded about a
 * direction. A policy changes an xfrm lookup only for a tuple its selector
 * matches, so the selector is asked about every tuple ft_ipsec_handle()
 * presents to policy: what leaves, the tuple between the translations, the
 * reverse direction's outbound tuple, and the two receiving ones. What the
 * selector alone cannot bound covers every direction: no policy named (a
 * default changed), a mark or interface in the policy's key, and a tunnelled
 * direction, whose outer header policy judges with a tuple of its own. */
bool ft_policy_covers(const struct xfrm_policy *pol,
		      const struct cdx_ft_rule *rule)
{
	const struct {
		const union nf_inet_addr *src, *dst;
		__be16 sport, dport;
	} tuples[] = {
		{ &rule->new_src, &rule->new_dst, rule->new_sport, rule->new_dport },
		{ &rule->src, &rule->new_dst, rule->sport, rule->new_dport },
		{ &rule->dst, &rule->src, rule->dport, rule->sport },
		{ &rule->new_dst, &rule->new_src, rule->new_dport, rule->new_sport },
		{ &rule->src, &rule->dst, rule->sport, rule->dport },
	};
	struct flowi fl;
	unsigned int i;

	if (!pol || pol->mark.v || pol->mark.m || pol->if_id ||
	    pol->selector.ifindex || rule->in_tunnel.present ||
	    rule->out_tunnel.present)
		return true;
	if (pol->family != rule->family)
		return false;
	/* Every field a tuple sets is set for each one; the rest stay zero. */
	memset(&fl, 0, sizeof(fl));
	fl.flowi_proto = rule->proto;
	for (i = 0; i < ARRAY_SIZE(tuples); i++) {
		if (rule->family == AF_INET) {
			fl.u.ip4.saddr = tuples[i].src->ip;
			fl.u.ip4.daddr = tuples[i].dst->ip;
			fl.u.ip4.fl4_sport = tuples[i].sport;
			fl.u.ip4.fl4_dport = tuples[i].dport;
		} else {
			fl.u.ip6.saddr = tuples[i].src->in6;
			fl.u.ip6.daddr = tuples[i].dst->in6;
			fl.u.ip6.fl6_sport = tuples[i].sport;
			fl.u.ip6.fl6_dport = tuples[i].dport;
		}
		if (xfrm_selector_match(&pol->selector, &fl, rule->family))
			return true;
	}
	return false;
}

/* The receiving end of a direction, or with `reverse` of the other one: the
 * physical port its frames arrive by, and the tuple they carry as the
 * forwarding policy judges it. */
static void ft_ipsec_receiver(const struct flow_cls_offload *cls,
			      const struct cdx_ft_rule *rule, bool reverse,
			      struct ft_ipsec_receiver *recv)
{
	struct flowi *fl = &recv->fl;
	const union nf_inet_addr *src = reverse ? &rule->new_dst : &rule->src;
	const union nf_inet_addr *dst = reverse ? &rule->new_src : &rule->dst;
	__be16 sport = reverse ? rule->new_dport : rule->sport;
	__be16 dport = reverse ? rule->new_sport : rule->dport;
	struct net_device *in = reverse ? rule->out_logical : rule->in_logical;
	struct net_device *out = reverse ? rule->in_logical : rule->out_logical;

	memset(recv, 0, sizeof(*recv));
	recv->in = reverse ? rule->out : rule->in;
	recv->family = rule->family;
	if (rule->family == AF_INET) {
		fl->u.ip4.saddr = src->ip;
		fl->u.ip4.daddr = dst->ip;
		fl->u.ip4.fl4_sport = sport;
		fl->u.ip4.fl4_dport = dport;
	} else {
		fl->u.ip6.saddr = src->in6;
		fl->u.ip6.daddr = dst->in6;
		fl->u.ip6.fl6_sport = sport;
		fl->u.ip6.fl6_dport = dport;
	}
	fl->flowi_proto = rule->proto;
	fl->flowi_iif = in->ifindex;
	fl->flowi_oif = out->ifindex;
	fl->flowi_mark = READ_ONCE(cls->nf_ct->mark);
}

static bool ft_ipsec_receiving(const struct ft_ipsec_receiver *recv,
			       struct xfrm_state *received)
{
	return xfrm_flowtable_policy_check(&init_net, &recv->fl, recv->family,
					   received);
}

/* Both ends of one direction: what encrypts what it sends, and what decrypted
 * what it receives. The sending end is asked of the destination this callback
 * borrowed; the receiving end of the reverse direction's, which is the path
 * the far end's frames took to get here.
 */
bool ft_ipsec_handle(const struct flow_cls_offload *cls,
		     struct cdx_ft_rule *rule, struct net_device *out,
		     struct net_device *in)
{
	u32 mark = READ_ONCE(cls->nf_ct->mark);
	struct ft_ipsec_receiver recv;
	struct xfrm_state *received = NULL;
	struct flowi fl;
	u16 reverse_in;
	bool allowed;

	/* The forwarding path asks output policy twice. Before NF_INET_FORWARD
	 * it asks about the tuple between the translations, and drops what
	 * policy refuses there -- a block, or a transform with no state. A
	 * POSTROUTING that translates the source then asks again about the
	 * tuple that leaves, and only that answer chooses the transform (the
	 * question below). So the first can only refuse; without SNAT the two
	 * tuples are one, and the second question covers both. */
	if (ft_ipsec_forward_flowi(rule, out, mark, &fl) &&
	    !ft_ipsec_permits(cls->nf_dst, &fl))
		goto denied;
	ft_ipsec_flowi(rule, false, out, mark, &fl);
	if (!ft_ipsec_resolve(cls->nf_dst, &fl, out, NULL, &rule->sa_handle, NULL,
			      &rule->sa_mtu, &rule->sa_expansion))
		goto denied;
	/* Both directions share one Linux generation. Validate both receiving
	 * ends even when their SAs exist: policy may now require a different
	 * transform, or forbid the tuple altogether. */
	ft_ipsec_receiver(cls, rule, true, &recv);
	if (!ft_ipsec_resolve(cls->nf_dst, &fl, out, &recv, &reverse_in,
			     &received, NULL, NULL))
		goto denied;
	allowed = ft_ipsec_receiving(&recv, received);
	if (received)
		xfrm_state_put(received);
	if (!allowed)
		goto denied;
	ft_ipsec_flowi(rule, true, in, mark, &fl);
	ft_ipsec_receiver(cls, rule, false, &recv);
	if (!ft_ipsec_resolve(cls->nf_dst_reverse, &fl, in, &recv,
			     &rule->in_sa_handle, &received, NULL, NULL))
		goto denied;
	allowed = ft_ipsec_receiving(&recv, received);
	if (received)
		xfrm_state_put(received);
	if (allowed)
		return true;
denied:
	/* Refusal alone leaves the software generation and its other hardware
	 * direction alive. Invalidate both before they can bypass the policy. */
	ft_handle_invalidate(cls->nf_handle, &ft_admission_invalidations);
	return false;
}

/* Retire every direction encrypted by an SA that is going away.
 *
 * An offloaded SA is a dependency of the same kind as a route or a neighbour:
 * a direction names it by handle, and when it stops existing the hardware
 * entry points at a SEC context that no longer describes anything. Handles are
 * reused once their SA is deleted, so this has to run before the hardware is
 * retired -- which it does, because the caller queues that retirement and this
 * happens first, under a lock the datapath never takes.
 *
 * Retiring rather than rewriting is deliberate, and matches every other
 * dependency here: Linux stops using its cached lookup immediately, the flow
 * is readmitted from scratch on the next packet, and the SA it then names is
 * whichever one the policy resolves to by that point.
 */
static void ft_ipsec_retire_sa(u16 handle)
{
	struct cdx_ft_entry *entry;

	if (!handle)
		return;
	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
		if (entry->rule.sa_handle == handle ||
		    entry->rule.in_sa_handle == handle)
			ft_handle_invalidate(entry->handle, &ft_ipsec_invalidations);
	spin_unlock_bh(&ft_watch_lock);
}

/* The path an outbound SA's frames take has a different MTU now, so every
 * direction the SA encrypts was admitted under a bound that no longer holds
 * (cdx_ft_rule.sa_mtu). Retired rather than rewritten, like any dependency:
 * Linux readmits each on its next packet, and admission takes the bound from
 * the path as it now stands. Only the sending end: a direction decrypted by
 * the SA transmits into its own path. Caller holds ft_watch_lock. */
static void ft_ipsec_path_moved(u16 handle)
{
	struct cdx_ft_entry *entry;

	list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
		if (handle && entry->rule.sa_handle == handle)
			ft_handle_invalidate(entry->handle, &ft_mtu_invalidations);
}

/* ------------------------------------------- following a peer that moves
 *
 * An outbound SA's next hop is resolved once, when the state is installed,
 * and written into its classifier entry -- because what leaves SEC is a
 * finished frame and the hardware has to be told the destination before the
 * first packet, not after. Nothing re-reads it per frame, so a peer that
 * moves (a gateway failover, a replaced NIC on the far end) would leave the
 * tunnel emitting to an address nobody answers to, with no error anywhere.
 * Nothing tells CDX about such a move, so the adapter has to notice it
 * itself.
 *
 * So each outbound SA keeps a watch here, and the same notifiers that retire
 * a flow whose neighbour or route moved mark the watch instead. Marking
 * rather than retiring is the whole difference between an SA and a flow: a
 * flow is readmitted from scratch on its next packet, which is why retiring
 * it is enough, while nothing re-offers an SA. Its hardware has to be
 * corrected in place.
 *
 * The correction cannot happen where it is noticed -- the notifiers run under
 * neigh->lock and ft_watch_lock, and rebuilding an entry needs the control
 * mutex and sleeps -- so a work item does it. That gives the SA's lifetime
 * one rule the work depends on: ft_xdo_state_delete() unlinks the watch
 * before it queues the retirement that frees the SA, and the retirement takes
 * the control mutex to do it. So a watch still on this list while the control
 * mutex is held names an SA that is still there.
 */

/* What the kernel routes an SA's peer with besides the two endpoints
 * (xfrm_dst_lookup()): the SA's output mark, and the protocol and ports its
 * frames leave with. A rule on any of them, or a multipath hash over the
 * ports, has to answer the adapter's lookup as it answers the kernel's, or
 * the hardware addresses one next hop while Linux's frames take another. */
struct ft_ipsec_route {
	u32 mark;
	__be16 sport;
	__be16 dport;
	u8 proto;
};

struct ft_ipsec_watch {
	struct list_head list;
	/* Identity that survives the memory. The work drops every lock to
	 * resolve, and a watch freed meanwhile could have its allocation
	 * reused by the next SA -- so it comes back and looks for this,
	 * never for the pointer it started with. */
	u64 cookie;
	/* Which pass of the follow work last took this watch on. The work
	 * re-marks a watch whose rebuild failed, so without this a failure
	 * would be picked straight back up inside the same pass and spin. */
	u64 pass;
	/* Which accounting pass last asked after this watch's path. That pass
	 * drops the lock for each lookup too, and this is its guard against
	 * taking a watch twice. */
	u64 sampled;
	struct cdx_ipsec_sa *sa;
	struct net_device *dev;
	union nf_inet_addr local;
	union nf_inet_addr peer;
	/* The neighbour the SA's frames are addressed to: the peer on-link,
	 * the route's gateway otherwise, as the last resolution found it. A
	 * neighbour event is matched against this, not the peer, or a peer
	 * behind a router would never see its router move. */
	union nf_inet_addr hop;
	/* What the peer is routed with besides the two addresses. */
	struct ft_ipsec_route route;
	/* What the hardware is currently writing: the peer's address and the
	 * port's own. Both are in the entry's header-manipulation opcodes, so
	 * either changing is the same defect and takes the same rebuild. */
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	/* The MTU of the path to the peer: the one the entry fragments SEC's
	 * output to (built_mtu), and the one the SA's directions were last
	 * admitted under (path_mtu), each bounded by the SA on that path. The
	 * path narrowing or widening under either is followed -- the entry
	 * rebuilt, the directions retired -- and they are kept apart because
	 * a rebuild can fail and be retried where a retirement need not be. */
	u32 built_mtu;
	u32 path_mtu;
	u8 family;
	bool stale;
	/* Rebuild even though neither address moved: the port's egress queues
	 * changed under the entry, which names one of them. Set until a
	 * rebuild succeeds, not merely until a pass takes the watch on, since
	 * a caller waiting for the change to reach the hardware reads it
	 * (ft_ipsec_rebuild_pending()); `rebuilds_asked' counts the changes,
	 * so a rebuild clears it only if no other change landed meanwhile. */
	bool rebuild;
	u32 rebuilds_asked;
	/* A failure has been reported for this watch, so the next one stays
	 * quiet. Cleared by a rebuild that works, because the next failure
	 * after a recovery is news again. */
	bool reported;
};

static LIST_HEAD(ft_ipsec_watches);
static u64 ft_ipsec_watch_cookies;
static u64 ft_ipsec_follow_pass;
static u64 ft_ipsec_sample_pass;
atomic64_t ft_ipsec_next_hop_updates = ATOMIC64_INIT(0);
/* Egress changes seen so far, on any port (ft_egress_changed()). Something
 * being built while one lands -- an SA, a multicast chain -- is not yet where
 * the change can mark it, and may have been built from either side of it; the
 * builder compares this across the build and marks itself instead. */
atomic64_t ft_egress_changes = ATOMIC64_INIT(0);

static void ft_ipsec_follow_work(struct work_struct *work);
DECLARE_WORK(ft_ipsec_follow, ft_ipsec_follow_work);

/* Caller holds ft_watch_lock. */
static void ft_ipsec_mark(struct ft_ipsec_watch *watch)
{
	watch->stale = true;
	schedule_work(&ft_ipsec_follow);
}

/* Find a watch by the identity it was created with, never by its address.
 * Caller holds ft_watch_lock.
 */
static struct ft_ipsec_watch *ft_ipsec_watch_find(u64 cookie)
{
	struct ft_ipsec_watch *watch;

	list_for_each_entry(watch, &ft_ipsec_watches, list)
		if (watch->cookie == cookie)
			return watch;
	return NULL;
}

/* The next watch this accounting pass has not asked after yet. Caller holds
 * ft_watch_lock. */
static struct ft_ipsec_watch *ft_ipsec_watch_unsampled(u64 pass)
{
	struct ft_ipsec_watch *watch;

	list_for_each_entry(watch, &ft_ipsec_watches, list)
		if (watch->sampled != pass)
			return watch;
	return NULL;
}

/* A neighbour this adapter may have resolved an SA against has changed.
 *
 * Matched by address and device rather than by a held neighbour pointer, the
 * way a flow matches: an SA is not worth a neighbour reference, since it has
 * no per-packet use for one and holding it would keep a dead entry alive.
 * Caller holds neigh->lock and ft_watch_lock.
 *
 * Only a neighbour that is usable *and* names a different address is worth
 * anything here, and both halves matter. An unchanged one is ordinary NUD
 * ageing, and the entry already carries it. An unusable one -- incomplete,
 * failed, dead -- names nothing better to program, and marking it would be
 * worse than useless: the re-resolution probes what it finds, the probe fails,
 * the failure is itself a neighbour update, and the two would keep each other
 * going for as long as the peer stayed down. The SA keeps the address it has
 * and the neighbour table does its own backoff.
 */
void ft_ipsec_neigh_moved(struct neighbour *neigh)
{
	struct ft_ipsec_watch *watch;
	u8 family;

	if ((neigh->tbl != &arp_tbl && neigh->tbl != &nd_tbl) || neigh->dead ||
	    !(neigh->nud_state & NUD_VALID))
		return;
	family = neigh->tbl == &nd_tbl ? AF_INET6 : AF_INET;
	list_for_each_entry(watch, &ft_ipsec_watches, list) {
		if (watch->family != family || watch->dev != neigh->dev)
			continue;
		if (family == AF_INET ?
		    *(__be32 *)neigh->primary_key != watch->hop.ip :
		    !ipv6_addr_equal((const struct in6_addr *)neigh->primary_key,
				     &watch->hop.in6))
			continue;
		/* A different address is the case this watch exists for. An
		 * unchanged one still matters when a previous attempt failed
		 * and left the watch waiting: a usable neighbour appearing is
		 * exactly the event that retry is waiting for, and the reason
		 * it failed need not have been the peer at all. Changing this
		 * port's own address flushes its neighbour table, so the
		 * rebuild that change asks for always finds the peer
		 * momentarily unresolvable -- and the neighbour that comes
		 * back carries the address it always had. */
		if (!ether_addr_equal(neigh->ha, watch->dst_mac) || watch->stale)
			ft_ipsec_mark(watch);
	}
}

/* A route covering this prefix changed, so the gateway an SA's frames leave
 * by may have. Unlike the neighbour case there is nothing to compare here --
 * the answer is whatever the FIB now returns -- so every SA under the prefix
 * is re-resolved and the work discards the ones that did not move.
 * Caller holds ft_watch_lock.
 */
void ft_ipsec_route_moved(u8 family, const void *dst, __be32 mask,
			  unsigned int prefixlen)
{
	struct ft_ipsec_watch *watch;

	list_for_each_entry(watch, &ft_ipsec_watches, list) {
		if (watch->family != family)
			continue;
		if (family == AF_INET) {
			if ((watch->peer.ip ^ *(const __be32 *)dst) & mask)
				continue;
		} else if (!ipv6_prefix_equal(&watch->peer.in6, dst, prefixlen)) {
			continue;
		}
		ft_ipsec_mark(watch);
	}
}

/* Everything, for the events that say only that routing changed. */
void ft_ipsec_all_moved(void)
{
	struct ft_ipsec_watch *watch;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(watch, &ft_ipsec_watches, list)
		ft_ipsec_mark(watch);
	spin_unlock_bh(&ft_watch_lock);
}

/* This port's own hardware address changed. It is written into the same
 * opcodes as the peer's, so an SA riding the port is as silently wrong as one
 * whose peer moved -- and unlike the flows on that port, which the caller
 * retires and which are readmitted with the new address, nothing re-offers an
 * SA. The encoder reads the port's address from its netdev, so rebuilding the
 * entry genuinely picks the new one up.
 */
void ft_ipsec_device_moved(const struct net_device *dev)
{
	struct ft_ipsec_watch *watch;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(watch, &ft_ipsec_watches, list)
		if (watch->dev == dev)
			ft_ipsec_mark(watch);
	spin_unlock_bh(&ft_watch_lock);
}

/* This port's egress queues changed under the SAs riding it: an outbound SA's
 * entry, the one SEC's output is classified by, names the queue it transmits
 * on, chosen when it was built. Neither address moved, so this asks for the
 * rebuild outright rather than for a check.
 *
 * The caller has counted the change (ft_egress_changes) before this walk: an
 * install that read the count before it built from the old state, and it
 * either sees the new count when it publishes its watch or publishes it before
 * the walk below finds it. */
void ft_ipsec_egress_changed(const struct net_device *dev)
{
	struct ft_ipsec_watch *watch;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(watch, &ft_ipsec_watches, list)
		if (watch->dev == dev) {
			watch->rebuild = true;
			watch->rebuilds_asked++;
			ft_ipsec_mark(watch);
		}
	spin_unlock_bh(&ft_watch_lock);
}

/* Whether an SA on this port still has the rebuild an egress change asked for
 * outstanding. The flag stays set while a pass is rebuilding the entry and
 * after a rebuild that failed, whose entry keeps the egress it was built with:
 * that is the thing a caller waiting on the change needs to know. */
bool ft_ipsec_rebuild_pending(const struct net_device *dev)
{
	struct ft_ipsec_watch *watch;
	bool pending = false;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(watch, &ft_ipsec_watches, list)
		if (watch->dev == dev && watch->rebuild) {
			pending = true;
			break;
		}
	spin_unlock_bh(&ft_watch_lock);
	return pending;
}

/* Publish a freshly installed outbound SA's next hop for watching.
 *
 * The watch is allocated by the caller before the SA is installed, so a
 * failure to allocate one refuses the SA with nothing built rather than
 * leaving hardware behind that nothing is following.
 *
 * It is published stale, which costs one resolution that almost always finds
 * nothing to do. Resolving the peer at install can wait seconds for a cold
 * ARP cache, and the watch does not exist for any of it; an event arriving in
 * that window would be lost. Starting stale closes it.
 *
 * An egress change is the one event a check cannot recover, because it moves
 * nothing a check compares: @changes is the count the install read before
 * building, and a count that has moved since publishes the watch asking for
 * the rebuild outright. Called in the install's control transaction, so a
 * caller that passes through one after changing the port finds the watch
 * already listed.
 */
static void ft_ipsec_watch_add(struct ft_ipsec_watch *watch,
			       const struct cdx_ipsec_sa_spec *spec,
			       struct cdx_ipsec_sa *sa,
			       const struct ft_ipsec_route *route, s64 changes)
{
	watch->sa = sa;
	watch->dev = spec->dev;
	watch->family = spec->family;
	watch->route = *route;
	watch->local = spec->src;
	watch->peer = spec->dst;
	watch->hop = spec->next_hop;
	ether_addr_copy(watch->dst_mac, spec->dst_mac);
	ether_addr_copy(watch->src_mac, spec->dev->dev_addr);
	watch->built_mtu = watch->path_mtu = spec->path_mtu;
	spin_lock_bh(&ft_watch_lock);
	watch->cookie = ++ft_ipsec_watch_cookies;
	watch->rebuild = atomic64_read(&ft_egress_changes) != changes;
	list_add_tail(&watch->list, &ft_ipsec_watches);
	ft_ipsec_mark(watch);
	spin_unlock_bh(&ft_watch_lock);
}

/* Unlink the watch for an SA that is going away, before anything frees the SA
 * itself.
 *
 * _bh, because xdo_dev_state_delete() does not always arrive with softirqs
 * already off and this lock is taken from softirq. xfrm_state_delete() holds
 * x->lock across it and xfrm_timer_handler() runs in one, which is the shape
 * the callback contract describes -- but xfrm_add_sa() also reaches it
 * directly, from netlink, when a state fails to insert. On that path a
 * neighbour update landing on the same CPU would spin on a lock this holds.
 */
static void ft_ipsec_watch_del(const struct cdx_ipsec_sa *sa)
{
	struct ft_ipsec_watch *watch, *next;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry_safe(watch, next, &ft_ipsec_watches, list) {
		if (watch->sa != sa)
			continue;
		list_del(&watch->list);
		kfree(watch);
	}
	spin_unlock_bh(&ft_watch_lock);
}

/* Nothing is watching any more. Module exit only: the states themselves are
 * the kernel's and outlive this, so there is no SA to retire here -- only the
 * watches, which point into text about to be unmapped.
 */
void ft_ipsec_watch_flush(void)
{
	struct ft_ipsec_watch *watch, *next;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry_safe(watch, next, &ft_ipsec_watches, list) {
		list_del(&watch->list);
		kfree(watch);
	}
	spin_unlock_bh(&ft_watch_lock);
}

/* ---------------------------------------------------------------- IPsec
 *
 * Mainline's device offload API, used in its packet mode. strongSwan asks for
 * it per child SA with `hw_offload = packet` (or `auto`), the kernel resolves
 * the state and hands it to xdo_dev_state_add(), and everything below is
 * translation: the hardware SA machinery is CDX's, reached through
 * cdx_ipsec_backend.h.
 *
 * Why the adapter rather than CDX, when CDX is already xfrm-aware: an SA's
 * eligibility is policy, and policy lives on this side of the interface for
 * the same reason a flow's does. Retiring the directions that depend on an SA
 * will need the watch list too, which is here.
 */

/* Resolve the next hop toward the remote tunnel endpoint.
 *
 * An outbound SA needs this at install time, because what leaves SEC is a
 * finished frame: the hardware writes the outer header and the Ethernet
 * addresses, so it has to be told the destination before the first packet,
 * not after. CDX keeps no route table to look the peer up in, so the adapter
 * answers the question the same way it answers it for a flow.
 *
 * The lookup is the ordinary FIB with the context the kernel's own route to
 * the peer has, and no more: the SA's output mark, the protocol and ports its
 * frames leave with (struct ft_ipsec_route) and its port's VRF, as
 * xfrm_dev_peer_route() asks. A missing route or an unresolved neighbour is a
 * refusal rather than something to retry, because packet offload has no
 * software fallback to wait in.
 */
/* The route to the peer, as the kernel's own lookup of it finds it.
 *
 * The SA's own local endpoint is part of the question, not decoration: an
 * output lookup carrying a source address answers for the route that address
 * may actually use, which is the one this tunnel's frames will take.
 *
 * No output interface, though. A lookup bound to the SA's port answers
 * through that port whatever the table says -- a less specific route via it,
 * or the destination assumed on-link -- so a caller's check that the route
 * leaves by the port could never fail, and a peer whose route had moved to
 * another port was followed to a next hop on the old one. The kernel drops
 * frames for a bundle routed off the SA's port, so this has to agree with it,
 * and asks with what the kernel's own lookup of the peer carries: the table
 * of the VRF the port is enslaved to, if any, and the SA's `route`.
 *
 * And it asks the FIB alone, as __xfrm4_dst_lookup() does for a bundle's
 * outer packet. ip_route_output_key() would not: with a protocol in the flow
 * it goes on through xfrm_lookup_route(), and a policy whose selector covers
 * the SA's own endpoints for that protocol -- transport mode between two
 * hosts, any protocol, which is strongSwan's default, or any host-to-host
 * tunnel -- answers with the SA's own bundle. That leaves by the port, so it
 * passes for the route, and its dst_mtu() is xfrm_mtu(): the SA's inner bound
 * (1458 for AES-CBC with HMAC-SHA256-128 in transport mode on a 1500-byte
 * port), which the SA's entry then fragmented or excepted every full-size
 * frame leaving SEC against. With no state for such a policy yet -- a trap
 * policy at install -- the answer, with the default xfrm_larval_drop, was a
 * blackhole on the loopback device, which refused the SA, and the lookup
 * could send an ACQUIRE for a flow nothing had sent.
 *
 * An IPv6 peer is asked the same way: ip6_route_output() is the FIB alone, as
 * __xfrm6_dst_lookup() uses it, and fails into dst->error rather than a
 * pointer. Either answer is released with dst_release().
 */
static struct dst_entry *ft_ipsec_peer_route(struct net_device *dev, u8 family,
					     const union nf_inet_addr *local,
					     const union nf_inet_addr *peer,
					     const struct ft_ipsec_route *route)
{
	struct dst_entry *dst;
	struct flowi6 fl6;
	struct flowi4 fl4;
	struct rtable *rt;
	int err;

	if (family == AF_INET) {
		fl4 = (struct flowi4){
			.daddr = peer->ip,
			.saddr = local->ip,
			.flowi4_mark = route->mark,
			.flowi4_l3mdev = l3mdev_master_ifindex(dev),
			.flowi4_proto = route->proto,
			.fl4_sport = route->sport,
			.fl4_dport = route->dport,
		};
		rt = __ip_route_output_key(&init_net, &fl4);
		return IS_ERR(rt) ? ERR_CAST(rt) : &rt->dst;
	}
	if (family != AF_INET6)
		return ERR_PTR(-EAFNOSUPPORT);
	fl6 = (struct flowi6){
		.daddr = peer->in6,
		.saddr = local->in6,
		.flowi6_mark = route->mark,
		.flowi6_l3mdev = l3mdev_master_ifindex(dev),
		.flowi6_proto = route->proto,
		.fl6_sport = route->sport,
		.fl6_dport = route->dport,
	};
	dst = ip6_route_output(&init_net, NULL, &fl6);
	err = dst->error;
	if (err) {
		dst_release(dst);
		return ERR_PTR(err);
	}
	return dst;
}

/* What the SA's frames can carry to the peer on `dst`: its learned PMTU while
 * one is current, else its own MTU, else the device's (dst_mtu()), and never
 * more than the port's. What the entry SEC's output is classified by
 * fragments them to, and the path every direction the SA encrypts is bounded
 * on (ft_ipsec_bound()). */
static u32 ft_ipsec_route_mtu(const struct dst_entry *dst,
			      const struct net_device *dev)
{
	return min_t(u32, dst_mtu(dst), READ_ONCE(dev->mtu));
}

/* The MTU of the path to an SA's peer now, asked of the FIB alone.
 *
 * This is the accounting pass's question (ft_ipsec_sample_paths()), and the
 * route is all of it on purpose. The neighbour belongs to the real triggers
 * -- a neighbour or route event, a port's address or MTU changing -- which
 * run the whole re-resolution. Asking it on a clock would probe an
 * unresolved peer once a period, which ft_ipsec_neigh_moved() is written not
 * to do, and retry a rebuild the backend refused on the same clock rather
 * than on the event that could change the answer.
 *
 * Fails, and says nothing about the path, when there is no route or it no
 * longer leaves by the SA's port; a route event is what follows those.
 */
static int ft_ipsec_path_mtu(struct net_device *dev, u8 family,
			     const union nf_inet_addr *local,
			     const union nf_inet_addr *peer,
			     const struct ft_ipsec_route *route, u32 *path_mtu)
{
	struct dst_entry *dst;
	int rc = 0;

	dst = ft_ipsec_peer_route(dev, family, local, peer, route);
	if (IS_ERR(dst))
		return PTR_ERR(dst);
	if (dst->dev == dev)
		*path_mtu = ft_ipsec_route_mtu(dst, dev);
	else
		rc = -EOPNOTSUPP;
	dst_release(dst);
	return rc;
}

/* How long to wait for the peer's neighbour entry, and in how many steps.
 * Two seconds total: an ARP exchange on a LAN completes in microseconds, so
 * this is a bound on something going wrong rather than an expected cost. */
#define FT_IPSEC_NEIGH_TRIES	20
#define FT_IPSEC_NEIGH_WAIT_MS	100

/* Ask the FIB and the neighbour table where the peer is now.
 *
 * `wait` is the difference between the two callers, and it is not a tuning
 * knob. At install time there is nowhere to retry from: packet offload has no
 * software fallback, so a refusal fails the tunnel outright and a cold ARP
 * cache has to be waited out. A re-resolution has somewhere to wait instead --
 * the neighbour event that arrives when the peer answers brings it straight
 * back here -- so it probes and returns rather than holding a shared
 * workqueue for seconds.
 *
 * `path_mtu` receives the path's MTU (ft_ipsec_route_mtu()) once the route
 * is found, and keeps it when the neighbour then fails to resolve: the path
 * is the route's, whatever the peer on it does. `hop` likewise receives the
 * neighbour's address -- the route's gateway, or the peer on-link -- once it
 * is looked up, resolved or not, and is left as the caller had it when no
 * entry could be had: the neighbour event the SA's watch has to answer is
 * that one's, and a failed allocation says nothing new about which it is.
 */
static int ft_ipsec_peer_mac(struct net_device *dev, u8 family,
			     const union nf_inet_addr *local,
			     const union nf_inet_addr *peer,
			     const struct ft_ipsec_route *route, bool wait,
			     u8 *mac, u32 *path_mtu, union nf_inet_addr *hop,
			     struct netlink_ext_ack *extack)
{
	struct neighbour *neighbour;
	struct dst_entry *dst;
	unsigned int attempt;
	int rc = 0;

	eth_zero_addr(mac);
	dst = ft_ipsec_peer_route(dev, family, local, peer, route);
	if (IS_ERR(dst)) {
		NL_SET_ERR_MSG(extack, "cdx: no route to the remote tunnel endpoint");
		return PTR_ERR(dst);
	}
	if (dst->dev != dev) {
		NL_SET_ERR_MSG(extack, "cdx: the route to the peer does not leave by the offload device");
		rc = -EOPNOTSUPP;
		goto out;
	}
	*path_mtu = ft_ipsec_route_mtu(dst, dev);
	/* Resolve the peer, asking for it if nobody has yet.
	 *
	 * An offloaded SA is usually installed moments after an IKE exchange
	 * with this same peer, so the neighbour is normally already there. It
	 * is not guaranteed: the exchange may have run over a different
	 * address, or the entry may have been evicted, and on a freshly booted
	 * gateway the table can simply be empty. Refusing then would fail the
	 * tunnel outright, so ask the ordinary way rather than turn a cold ARP
	 * cache into a tunnel that never comes up.
	 *
	 * The waiting caller runs in process context on the netlink path,
	 * before any CDX lock or RTNL is taken, so waiting blocks only the
	 * caller that asked for the SA. The bound is short enough to be
	 * invisible next to the exchange that preceded it and long enough for
	 * ARP or neighbour discovery on a LAN. The route's own lookup picks the
	 * next hop, its gateway or the peer on-link, in either family.
	 */
	neighbour = dst_neigh_lookup(dst, peer);
	if (!neighbour) {
		rc = -EHOSTUNREACH;
		goto report;
	}
	memset(hop, 0, sizeof(*hop));
	memcpy(hop, neighbour->primary_key, family == AF_INET ? sizeof(hop->ip) : sizeof(hop->in6));
	for (attempt = 0; attempt < (wait ? FT_IPSEC_NEIGH_TRIES : 1); attempt++) {
		/* Every usable state, which is the same set admission accepts:
		 * a neighbour that is merely stale still has the address that
		 * was last confirmed, and Linux refreshes it in its own time. */
		if (READ_ONCE(neighbour->nud_state) & NUD_VALID) {
			read_lock_bh(&neighbour->lock);
			ether_addr_copy(mac, neighbour->ha);
			read_unlock_bh(&neighbour->lock);
			break;
		}
		neigh_event_send(neighbour, NULL);
		if (wait)
			msleep(FT_IPSEC_NEIGH_WAIT_MS);
	}
	if (is_zero_ether_addr(mac))
		rc = -EHOSTUNREACH;
	neigh_release(neighbour);
report:
	if (rc)
		NL_SET_ERR_MSG(extack, "cdx: the remote tunnel endpoint did not resolve");
out:
	dst_release(dst);
	return rc;
}

/* Whether the peer resolves now, asked without probing it: the same route
 * and neighbour ft_ipsec_peer_mac() would use, usable and with an address.
 *
 * The follow work probes a peer that does not resolve and returns, leaving
 * the neighbour event the answer raises to bring it back. That event marks a
 * watch whose address it does not change only while the watch is stale, and
 * the work sets that after its probe -- so an answer landing in between is
 * lost, and the SA keeps its old framing until something else moves. The work
 * asks this once the watch is stale again, and goes round once more if the
 * answer has come. Called with no lock held.
 */
static bool ft_ipsec_peer_resolved(struct net_device *dev, u8 family,
				   const union nf_inet_addr *local,
				   const union nf_inet_addr *peer,
				   const struct ft_ipsec_route *route)
{
	struct neighbour *neighbour;
	struct dst_entry *dst;
	bool resolved = false;
	u8 mac[ETH_ALEN];

	dst = ft_ipsec_peer_route(dev, family, local, peer, route);
	if (IS_ERR(dst))
		return false;
	neighbour = dst->dev == dev ? dst_neigh_lookup(dst, peer) : NULL;
	if (neighbour) {
		if (READ_ONCE(neighbour->nud_state) & NUD_VALID) {
			read_lock_bh(&neighbour->lock);
			ether_addr_copy(mac, neighbour->ha);
			read_unlock_bh(&neighbour->lock);
			resolved = !is_zero_ether_addr(mac);
		}
		neigh_release(neighbour);
	}
	dst_release(dst);
	return resolved;
}

static void ft_ipsec_route_of(struct xfrm_state *x, struct ft_ipsec_route *route)
{
	*route = (struct ft_ipsec_route){
		.mark = xfrm_smark_get(0, x),
		.proto = x->id.proto,
	};
	/* The one encapsulation ft_ipsec_spec() admits. */
	if (x->encap && x->encap->encap_type == UDP_ENCAP_ESPINUDP) {
		route->proto = IPPROTO_UDP;
		route->sport = x->encap->encap_sport;
		route->dport = x->encap->encap_dport;
	}
}

static int ft_ipsec_next_hop(struct xfrm_state *x,
			     struct cdx_ipsec_sa_spec *spec,
			     struct netlink_ext_ack *extack)
{
	struct ft_ipsec_route route;
	u32 path_mtu;
	int rc;

	ft_ipsec_route_of(x, &route);
	spec->next_hop = spec->dst;
	rc = ft_ipsec_peer_mac(spec->dev, spec->family, &spec->src, &spec->dst,
			       &route, true, spec->dst_mac, &path_mtu,
			       &spec->next_hop, extack);
	if (!rc)
		spec->path_mtu = path_mtu;
	return rc;
}

/* Whether an inbound SA's peer is reached by the SA's own device.
 *
 * The question the outbound SA to the same peer is asked (ft_ipsec_peer_mac()),
 * asked of the inbound half first: strongSwan installs a child SA's inbound SA
 * before its outbound one and binds both to the device holding the local
 * address. When the route to the peer leaves by another device, the outbound
 * half is refused, and under `hw_offload = auto` strongSwan installs it in
 * software instead. The inbound half would then be the only one in hardware,
 * and the peer's ESP, which comes in the way the route to the peer goes out --
 * a LAN client tunnelling to the WAN address arrives on the LAN bridge --
 * reaches SEC only through the SA's own port, where it never arrives, and is
 * dropped everywhere else (xfrm_state_sec_only()). Refused here, `auto`
 * installs it in software as well and the whole child SA works there;
 * `packet` fails the child SA, as the outbound half would have.
 *
 * The lookup is the outbound one reversed: from the local endpoint to the
 * peer, in the SA's family and its port's VRF, carrying the protocol and
 * ports a reply to the peer would. No output mark, which an inbound SA does
 * not have to give: neither of its marks says how its peer is routed, and the
 * outbound half, which does carry one, is installed after it. The unmarked
 * route is also the one strict reverse-path filtering asks of the peer's
 * frames. An uplink reached only by a mark is therefore refused here, and a
 * source rule for the local address (`ip rule from <address> lookup <table>`)
 * is what lets this lookup see it (docs/flowtable/ipsec.md; ISSUES.md A235).
 */
static int ft_ipsec_peer_on_port(struct xfrm_state *x,
				 struct netlink_ext_ack *extack)
{
	struct net_device *dev = x->xso.dev;
	struct xfrm_dst_lookup_params params = {
		.net = xs_net(x),
		.saddr = &x->id.daddr,
		.daddr = &x->props.saddr,
		/* Only its L3 master is used, and only for the table. */
		.oif = dev->ifindex,
		.ipproto = x->id.proto,
	};
	struct dst_entry *dst;
	bool on_port;

	/* The one encapsulation ft_ipsec_spec() admits, with the state's ports
	 * the other way round: an inbound state's source port is the peer's. */
	if (x->encap && x->encap->encap_type == UDP_ENCAP_ESPINUDP) {
		params.ipproto = IPPROTO_UDP;
		params.uli.ports.sport = x->encap->encap_dport;
		params.uli.ports.dport = x->encap->encap_sport;
	}
	dst = __xfrm_dst_lookup(x->props.family, &params);
	if (IS_ERR(dst)) {
		NL_SET_ERR_MSG(extack, "cdx: no route to the remote tunnel endpoint");
		return PTR_ERR(dst);
	}
	on_port = dst->dev == dev;
	dst_release(dst);
	if (!on_port) {
		NL_SET_ERR_MSG(extack, "cdx: the route to the peer does not leave by the offload device");
		return -EOPNOTSUPP;
	}
	return 0;
}

/* Where xfrm keeps the bit for sequence number top - k in a replay_esn ring.
 *
 * The legacy bitmap is linear, bit k for top - k. The replay_esn one is a
 * ring of replay_window bits in which top sits at (top - 1) % window and each
 * older number one position before it, wrapping -- the arithmetic
 * xfrm_replay_check_bmp() and xfrm_replay_check_esn() use, on the low 32 bits
 * of the number.
 */
static u32 ft_ipsec_replay_bit(u32 top, u32 window, u32 k)
{
	u32 pos = (top - 1) % window;

	return pos >= k ? pos - k : window - (k - pos);
}

/* What an inbound state has already received, in the spec's orientation:
 * bit k of replay_seen for spec->seq - k.
 *
 * A fresh state has none. A re-added one carries the window it was read with,
 * and SEC's scorecard starts from it, so nothing the old SA accepted can be
 * accepted again. Positions past the state's own window are history xfrm does
 * not keep, and past SEC's too, which is exactly as wide (ft_ipsec_spec()):
 * they are marked received all the same, so the scorecard never calls unseen
 * a number xfrm would refuse as too old.
 */
static void ft_ipsec_replay_seen(const struct xfrm_state *x,
				 struct cdx_ipsec_sa_spec *spec)
{
	const struct xfrm_replay_state_esn *esn = x->replay_esn;
	u32 window = spec->replay_window;
	u32 top = lower_32_bits(spec->seq);
	bool seen;
	u32 k, bit;

	if (!window || !spec->seq)
		return;
	for (k = 0; k < CDX_IPSEC_REPLAY_WINDOW_MAX; k++) {
		if (k >= window) {
			seen = true;
		} else if (!esn) {
			seen = k < 32 && (x->replay.bitmap & (1U << k));
		} else {
			bit = ft_ipsec_replay_bit(top, window, k);
			seen = esn->bmp[bit / 32] & (1U << (bit % 32));
		}
		if (seen)
			spec->replay_seen[k / 32] |= 1U << (k % 32);
	}
}

/* Translate a kernel state into the backend's description of one.
 *
 * Algorithm identities come straight from x->props.aalgo and x->props.ealgo,
 * which are the PF_KEY numbers whatever configured the state resolved for us:
 * xfrm_user sets them from the algorithm's own descriptor, including for AEAD,
 * where xfrm_aead_get_byname() has already picked the descriptor matching the
 * requested ICV length. So GCM at 8, 12 and 16 bytes arrive as three distinct
 * identities with nothing here to derive -- the legacy serialiser matched on
 * alg_name substrings and ICV arithmetic to reach the same three constants.
 * An authenticator's identity names no ICV length, so its truncation is
 * carried beside it.
 */
static int ft_ipsec_spec(struct xfrm_state *x, struct cdx_ipsec_sa_spec *spec,
			 struct netlink_ext_ack *extack)
{
	struct net_device *dev = x->xso.dev;

	memset(spec, 0, sizeof(*spec));
	spec->dev = dev;
	spec->family = x->props.family;
	spec->spi = x->id.spi;
	spec->dir = x->xso.dir == XFRM_DEV_OFFLOAD_IN ? CDX_IPSEC_DIR_IN
						      : CDX_IPSEC_DIR_OUT;
	spec->tunnel = x->props.mode == XFRM_MODE_TUNNEL;
	spec->esn = !!(x->props.flags & XFRM_STATE_ESN);
	/* Where the sequence space stands and how wide a window guards it, in
	 * xfrm's own terms. A state with a replay_esn keeps both there -- one
	 * with ESN always, one without when its window is wider than the
	 * legacy 32-bit bitmap -- and only ESN makes the high word part of the
	 * number. Each direction's own number is the one that matters: the
	 * last sent going out, the highest received coming in. */
	if (x->replay_esn) {
		const struct xfrm_replay_state_esn *esn = x->replay_esn;
		bool out = spec->dir == CDX_IPSEC_DIR_OUT;

		spec->replay_window = esn->replay_window;
		spec->seq = out ? esn->oseq : esn->seq;
		if (spec->esn)
			spec->seq |= (u64)(out ? esn->oseq_hi : esn->seq_hi) << 32;
	} else {
		spec->replay_window = x->props.replay_window;
		spec->seq = spec->dir == CDX_IPSEC_DIR_OUT ? x->replay.oseq
							   : x->replay.seq;
	}
	/* SEC keeps an inbound window at exactly the width asked for, or not
	 * at all (cdx_ipsec_replay_window_supported()): carried on another
	 * width, it would take or drop late frames otherwise than xfrm's own
	 * check of the same state. An outbound SA checks nothing, and its
	 * window is no reason to refuse it. */
	if (spec->dir == CDX_IPSEC_DIR_IN &&
	    !cdx_ipsec_replay_window_supported(spec->replay_window, spec->tunnel)) {
		if (spec->replay_window == CDX_IPSEC_REPLAY_WINDOW_MAX)
			NL_SET_ERR_MSG(extack, "cdx: SEC keeps a 128-packet replay window only in tunnel mode");
		else
			NL_SET_ERR_MSG(extack, "cdx: SEC keeps 32/64/128-packet replay windows");
		return -EOPNOTSUPP;
	}
	if (spec->dir == CDX_IPSEC_DIR_IN)
		ft_ipsec_replay_seen(x, spec);
	if (spec->family == AF_INET6) {
		memcpy(spec->src.ip6, x->props.saddr.a6, sizeof(spec->src.ip6));
		memcpy(spec->dst.ip6, x->id.daddr.a6, sizeof(spec->dst.ip6));
	} else {
		spec->src.ip = x->props.saddr.a4;
		spec->dst.ip = x->id.daddr.a4;
	}
	/* The outer header's own fields, which are not the inner packet's.
	 * Both constants match what the legacy serialiser emitted: a fixed hop
	 * limit, and a traffic class of zero because the ECN and DSCP an
	 * encapsulated frame carries are copied per frame by the hardware
	 * rather than fixed once in the template. */
	spec->ttl = 64;
	spec->tos = 0;
	/* Copying DF makes the tunnel report the inner path's fragmentation
	 * needs, which is what path MTU discovery is. A state that asked for
	 * no PMTU discovery is asking for the opposite. */
	spec->copy_df = spec->family == AF_INET &&
			spec->dir == CDX_IPSEC_DIR_OUT &&
			!(x->props.flags & XFRM_STATE_NOPMTUDISC);
	spec->ecn = !(x->props.flags & XFRM_STATE_NOECN);
	if (x->encap) {
		if (x->encap->encap_type != UDP_ENCAP_ESPINUDP) {
			NL_SET_ERR_MSG(extack, "cdx: only UDP-encapsulated ESP is supported");
			return -EOPNOTSUPP;
		}
		/* SEC builds the UDP header, and the decap offset past it, only
		 * on its tunnel arms: a transport SA would leave as bare ESP. */
		if (!spec->tunnel) {
			NL_SET_ERR_MSG(extack, "cdx: UDP encapsulation needs tunnel mode");
			return -EOPNOTSUPP;
		}
		/* IPv6 forbids the zero UDP checksum IPv4 NAT-T sends, and
		 * esp6 computes one; what SEC writes there has never been
		 * proved, so ESP-in-UDP over IPv6 stays in software. */
		if (spec->family != AF_INET) {
			NL_SET_ERR_MSG(extack, "cdx: UDP encapsulation is supported over IPv4 only");
			return -EOPNOTSUPP;
		}
		spec->natt_sport = x->encap->encap_sport;
		spec->natt_dport = x->encap->encap_dport;
	}
	if (x->aalg) {
		if (x->aalg->alg_key_len > CDX_IPSEC_KEY_MAX * 8) {
			NL_SET_ERR_MSG(extack, "cdx: authentication key too long");
			return -EINVAL;
		}
		/* The ICV is the state's truncation, which peers choose: RFC
		 * 4868 gives SHA-2 half its digest, while strongSwan's
		 * sha256_96, and xfrm's default for a state that names no
		 * truncation, give SHA-256 96 bits. SEC fixes the ICV in the
		 * protocol operation, so a pair it has no operation for would
		 * send every frame with an ICV of the wrong length and refuse
		 * every frame received. An authenticator with no PF_KEY number,
		 * xfrm's cmac(aes), arrives as algorithm 0 with a key, and zero
		 * is "no authenticator" to the backend: it is refused here with
		 * the rest, never skipped, or the SA would carry no
		 * authentication at all. */
		if (!cdx_ipsec_auth_supported(x->props.aalgo, x->aalg->alg_trunc_len)) {
			NL_SET_ERR_MSG(extack, "cdx: SEC cannot produce this authenticator at this ICV length");
			return -EOPNOTSUPP;
		}
		spec->auth.alg = x->props.aalgo;
		spec->auth.icv_bits = x->aalg->alg_trunc_len;
		spec->auth.bits = x->aalg->alg_key_len;
		memcpy(spec->auth.key, x->aalg->alg_key, x->aalg->alg_key_len / 8);
	}
	/* ealg and aead are exclusive: a transform is either a cipher with a
	 * separate authenticator or a single combined mode. Both land in the
	 * same slot because SEC builds one descriptor either way, and the
	 * algorithm identity already says which it is. */
	if (x->ealg) {
		if (x->ealg->alg_key_len > CDX_IPSEC_KEY_MAX * 8) {
			NL_SET_ERR_MSG(extack, "cdx: cipher key too long");
			return -EINVAL;
		}
		spec->crypt.alg = x->props.ealgo;
		spec->crypt.bits = x->ealg->alg_key_len;
		memcpy(spec->crypt.key, x->ealg->alg_key, x->ealg->alg_key_len / 8);
	} else if (x->aead) {
		/* SEC's IPsec protocol runs AES-GMAC as GCM with the payload left
		 * unencrypted (SEC RM §9.1), so its ICV covers the ESP header and
		 * payload but not the IV. RFC 4543 (Figure 4, erratum 62) and
		 * every software peer include the IV, so no frame would
		 * authenticate in either direction, and no PDB option changes
		 * what SEC authenticates. Refused: xfrm hands the error back for
		 * packet offload and installs nothing, and the SA belongs in
		 * software, added without offload. */
		if (x->props.ealgo == SADB_X_EALG_NULL_AES_GMAC) {
			NL_SET_ERR_MSG(extack, "cdx: SEC's AES-GMAC leaves the IV out of the ICV");
			return -EOPNOTSUPP;
		}
		if (x->aead->alg_key_len > CDX_IPSEC_KEY_MAX * 8) {
			NL_SET_ERR_MSG(extack, "cdx: AEAD key too long");
			return -EINVAL;
		}
		spec->crypt.alg = x->props.ealgo;
		spec->crypt.bits = x->aead->alg_key_len;
		memcpy(spec->crypt.key, x->aead->alg_key, x->aead->alg_key_len / 8);
	}
	/* SEC moves a tunnel's traffic class only as the whole byte, DSCP and
	 * ECN together. Decapsulation leaves the inner byte alone, which is what
	 * Linux does by default (RFC 4301 5.1.2.1), and propagates an outer CE
	 * by RFC 6040 unless the state has `noecn`; a state asking for the outer
	 * DSCP (decap-dscp) would need SEC to overwrite the inner ECN field too,
	 * which RFC 6040 forbids. Encapsulation copies the inner byte out, so
	 * neither a state asking for no DSCP copy (dont-encap-dscp) nor one
	 * asking for a Not-ECT outer header (noecn) can be honoured. All three
	 * stay in software. */
	if (spec->tunnel && spec->dir == CDX_IPSEC_DIR_IN &&
	    (x->props.flags & XFRM_STATE_DECAP_DSCP)) {
		NL_SET_ERR_MSG(extack, "cdx: SEC cannot take the outer DSCP without the outer ECN");
		return -EOPNOTSUPP;
	}
	if (spec->tunnel && spec->dir == CDX_IPSEC_DIR_OUT &&
	    (x->props.extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)) {
		NL_SET_ERR_MSG(extack, "cdx: SEC copies the inner DSCP into the outer header");
		return -EOPNOTSUPP;
	}
	if (spec->tunnel && spec->dir == CDX_IPSEC_DIR_OUT &&
	    (x->props.flags & XFRM_STATE_NOECN)) {
		NL_SET_ERR_MSG(extack, "cdx: SEC copies the inner ECN into the outer header");
		return -EOPNOTSUPP;
	}
	spec->dev_mtu = dev->mtu;
	spec->mtu = ft_ipsec_esp_mtu(x, dev->mtu);
	if (spec->dir == CDX_IPSEC_DIR_OUT)
		return ft_ipsec_next_hop(x, spec, extack);
	return ft_ipsec_peer_on_port(x, extack);
}

/* Who an SA is to a re-add of it (ft_ipsec_fold()): its SPI and direction,
 * and a digest of its transform and keys (ft_ipsec_identify()). A re-add
 * keeps all three wherever it moves the SA -- a MOBIKE move changes one
 * direction's destination, even its family -- and a new SA reusing an SPI
 * has other keys. The window and ESN say how its replay state reads. Its
 * destination and family are what its classifier entry is keyed on, which
 * another SA with the same SPI can collide with (ft_ipsec_in_the_way()). */
struct ft_ipsec_identity {
	union nf_inet_addr daddr;
	__be32 spi;
	u32 replay_window;
	u64 digest;
	u8 family;
	u8 dir;
	bool esn;
};

/* Retirement storage belongs to an SA from its initial installation.
 * Deletion can run from expiry under a spinlock and must never allocate.
 *
 * While the SA is owned, the same entry is what the accounting pass below
 * walks, which is why it names the state as well as the SA. Once the SA is
 * out of the hardware, the entry may stay a little longer as the record of
 * where SEC left it, on ft_ipsec_remembered. */
struct ft_ipsec_retirement {
	struct list_head list;
	struct cdx_ipsec_sa *sa;
	/* Borrowed, like the backend's own copy, and safe to take a reference
	 * on exactly while this entry is on ft_ipsec_owned: xfrm drops the
	 * reference that keeps an offloaded state alive only once
	 * xdo_dev_state_delete() has returned, and ft_xdo_state_delete() moves
	 * the entry off that list under ft_ipsec_retired_lock first. */
	struct xfrm_state *x;
	/* The accounting pass's own linkage, touched by nothing else. */
	struct list_head pass;
	/* What the pass last published into the state. The next pass adds
	 * only the difference, so a state installed with traffic already
	 * counted -- xfrm_user takes a current lifetime at install -- keeps
	 * it. */
	struct cdx_ipsec_counters published;
	/* How many frames the SA carries in an accounting period: the rate a
	 * re-add of an outbound SA is carried past the old one's last number
	 * with (ft_ipsec_fold_oseq()), kept on the record once it retires.
	 * Halved each period it is not topped up, so one reading SEC's
	 * counters would not give up does not take it to nothing while the SA
	 * is at its busiest. Under ft_ipsec_retired_lock. */
	u64 sent;
	/* Set at install, read by a re-add. */
	struct ft_ipsec_identity id;
	/* Where SEC left the SA's sequence space once it was out of the
	 * hardware, and when that was (jiffies): what ft_ipsec_fold() carries
	 * into a re-add of it. Written by the retirement, then read under
	 * ft_ipsec_retired_lock. */
	struct cdx_ipsec_counters last;
	unsigned long retired;
};
static LIST_HEAD(ft_ipsec_owned);
static LIST_HEAD(ft_ipsec_retired);
static DEFINE_SPINLOCK(ft_ipsec_retired_lock);
/* Retired SAs whose last state a re-add of them may still ask for, oldest
 * first, one per identity. strongSwan re-adds an SA at a new address a
 * moment after deleting it (MOBIKE, a NAT's new mapping), so a few seconds
 * are plenty; the bound on the count keeps a flood of deletions from growing
 * it. Under ft_ipsec_retired_lock. */
static LIST_HEAD(ft_ipsec_remembered);
static unsigned int ft_ipsec_remembered_count;
#define FT_IPSEC_REMEMBERED	256
#define FT_IPSEC_REMEMBER_FOR	(10 * HZ)
/* Woken as each retirement finishes, for an add waiting on one
 * (ft_xdo_state_add()), which gives up after FT_IPSEC_RETIRE_WAIT: a
 * retirement a wedged classifier keeps from finishing must not hold every
 * xfrm configuration change behind the xfrm_cfg_mutex the add is under. */
static DECLARE_WAIT_QUEUE_HEAD(ft_ipsec_retired_wait);
#define FT_IPSEC_RETIRE_WAIT	(5 * HZ)
/* The key ft_ipsec_identify() digests an SA's keys with: this module's own,
 * so a digest says nothing of the keys it stands for. */
static siphash_key_t ft_ipsec_digest_key;
/* SAs whose deletion has begun and whose hardware entries are not yet out:
 * counted before the SA's watch goes, and uncounted by ft_ipsec_retire inside
 * the transaction that deletes them. An outbound SA's entry transmits on its
 * port and may read the port's DSCP map; once its watch has gone, this count
 * is the only trace of it the egress drain can find. */
static atomic_t ft_ipsec_retiring = ATOMIC_INIT(0);

/* Whether an SA deletion is still on its way to the hardware. Read after the
 * watch list, and inside the transaction ft_ipsec_retire deletes in, so a
 * deletion either left its watch where ft_ipsec_rebuild_pending() saw it, is
 * counted here, or has finished. */
bool ft_ipsec_retire_pending(void)
{
	return atomic_read(&ft_ipsec_retiring) != 0;
}

/* ------------------------------------------------ what SEC counted, for xfrm
 *
 * xfrm keeps an SA's lifetime in two halves: the limits the state was given,
 * x->lft, and what it has carried so far, x->curlft. Byte and packet expiry
 * exist only as xfrm_state_check_expire() comparing the two, which the stack
 * calls per packet from xfrm_output_one() and xfrm_input(). Packet offload
 * reaches neither: an outbound frame skips xfrm_output_one() entirely, and an
 * inbound one comes back from SEC already decrypted and stamps only use_time.
 * Left alone, curlft stays at zero, `ip -s xfrm state` shows an idle SA, and
 * a byte or packet limit never fires -- the SA lives until its time limit
 * however much it carries.
 *
 * The counters that do move are SEC's, kept per SA in its shared descriptor.
 * This pass carries them across once a period: it reads them inside the
 * control transaction, which is what keeps each SA installed while it is
 * read, and publishes them into curlft under x->lock before asking xfrm to
 * judge -- the lock and the call the software path uses per packet. A limit
 * therefore fires within one period of being crossed, through xfrm's own soft
 * and hard expiry and nothing private. A hard expiry does not stop SEC at
 * once, though: the SA's entries keep forwarding until the deletion that
 * follows retires them, so an SA can run past its hard limit by up to one
 * period plus the retirement's own latency.
 *
 * The replay state goes back the same way, in both directions: SEC numbers
 * and checks the frames, so xfrm's own copy never moves unless this moves it.
 * A period is too long for that copy, though. A keying daemon re-adding an SA
 * at a new address reads it and deletes the SA straight after, and a copy up
 * to a period old would start the new SA over numbers the old one had
 * already sent, or anchor its window below frames the old one had already
 * taken. So xdo_dev_state_update_stats() publishes it too, from a live
 * reading, whenever xfrm is about to read it: XFRM_MSG_GETSA and GETAE, state
 * dumps and notifications, the state timer, xfrm_state_check_expire() and the
 * clone xfrm_state_migrate() makes (patch 040 asks for the last two it did
 * not).
 *
 * The op publishes the replay state alone. Its callers hold x->lock or
 * xfrm_state_lock, or are in atomic context, so it cannot take the control
 * mutex the 64-bit packet total is built under, and a second reader of SEC's
 * counters outside it would race the pass. curlft stays the pass's, at most
 * one period old -- as stale as mlx5's, whose flow counters are cached on the
 * same one-second period (MLX5_FC_STATS_PERIOD) and whose software limits are
 * judged by a one-second work (mlx5e_ipsec_handle_sw_limits()). The replay
 * state needs neither: the backend reads it from the PDB alone
 * (cdx_ipsec_sa_replay_state()), and ft_ipsec_retired_lock keeps the SA
 * installed across the reading (ft_xdo_state_update_stats()).
 *
 * Nor an xdo_dev_state_advance_esn(). xfrm_dev_state_add() asks for it only
 * for crypto offload, and SEC keeps an ESN SA's high word in its PDB and
 * advances it there.
 */
#define FT_IPSEC_STATS_PERIOD	HZ

/* How far past the old SA's number a re-add of an outbound SA starts at the
 * least, whatever the old one sent in its last period (ft_ipsec_fold_oseq()).
 * 2^16 frames is 47 ms at 1.4 Mpps: far more than SEC can still have been
 * holding of the old SA when its last number was read. */
#define FT_IPSEC_OSEQ_FLOOR	(1ULL << 16)

/* How close to the end of its sequence space a non-ESN outbound SA may come
 * before the pass asks for a rekey.
 *
 * Such an SA's numbers end at FFFFFFFE -- SEC refuses to send FFFFFFFF (SEC
 * RM table 9-2) and will not wrap -- and past that every frame fails in SEC
 * and the tunnel carries nothing that way.
 * Linux's software path stops at the same wall and warns nobody either, but
 * it rarely gets there; the offload does. At 1.4 Mpps the space lasts 51
 * minutes, less than strongSwan's default hour between rekeys. The approach
 * is reported as a soft expire, which is what makes strongSwan rekey. 2^28 is
 * a sixteenth of the space and over three minutes at that rate, enough for an
 * IKE exchange and its retransmissions.
 * An ESN SA has 2^64 and never comes close.
 */
#define FT_IPSEC_SEQ_HEADROOM	(1ULL << 28)

static void ft_ipsec_stats_work(struct work_struct *work);
DECLARE_DELAYED_WORK(ft_ipsec_stats, ft_ipsec_stats_work);

static bool ft_ipsec_seq_exhausting(const struct xfrm_state *x, u64 oseq)
{
	return x->xso.dir == XFRM_DEV_OFFLOAD_OUT &&
	       !(x->props.flags & XFRM_STATE_ESN) &&
	       oseq >= (1ULL << 32) - FT_IPSEC_SEQ_HEADROOM;
}

/* Tell xfrm where an outbound SA's sequence space stands.
 *
 * Packet offload never advances xfrm's own copy -- SEC numbers the frames --
 * so it would stay wherever the SA was installed, and whatever carries a
 * state's sequence number on reads that copy: XFRM_MSG_GETSA and GETAE, which
 * a keying daemon reads to carry the number over when it re-adds an SA at a
 * new address, and the clone xfrm_state_migrate() makes. Either would start
 * the new SA over numbers its peer has already seen, and the peer drops every
 * frame until they pass.
 *
 * What goes back is SEC's number as it is, the last one sent, so what `ip
 * xfrm state` shows and what the exhaustion check sees are numbers SEC has
 * put on the wire. SEC goes on numbering after any reading until the SA is
 * out of the hardware, but covering that is the re-add's business, not the
 * published number's: a re-add is carried past wherever the retirement left
 * SEC, with a margin (ft_ipsec_fold()). Only forward, so a reading older than
 * the one published never undoes it.
 *
 * Caller holds ft_ipsec_retired_lock, which every publication takes, and
 * x->lock unless it is one of xfrm's own readers that do not
 * (ft_xdo_state_update_stats()). Each word is stored whole (WRITE_ONCE); a
 * reader without x->lock can still pair an ESN number's two words from either
 * side of a publication, as it can with any update xfrm makes under that
 * lock, and nothing here orders the two for it. A re-add read that way is
 * carried past the old SA all the same, by the fold.
 */
static void ft_ipsec_publish_oseq(struct xfrm_state *x, u64 oseq)
{
	struct xfrm_replay_state_esn *esn = x->replay_esn;

	if (x->xso.dir != XFRM_DEV_OFFLOAD_OUT)
		return;
	if (!esn) {
		if (oseq > x->replay.oseq)
			WRITE_ONCE(x->replay.oseq, oseq);
	} else if (x->props.flags & XFRM_STATE_ESN) {
		if (oseq > ((u64)esn->oseq_hi << 32 | esn->oseq)) {
			WRITE_ONCE(esn->oseq_hi, upper_32_bits(oseq));
			WRITE_ONCE(esn->oseq, lower_32_bits(oseq));
		}
	} else if (oseq > esn->oseq) {
		WRITE_ONCE(esn->oseq, oseq);
	}
}

/* Tell xfrm where an inbound SA's anti-replay window stands.
 *
 * SEC checks the frames, so the state's own window never moves either. Left
 * alone it stays where the SA was installed, and a keying daemon that re-adds
 * the SA from it anchors the new one there, where every number the old SA
 * ever accepted counts as new -- each of them replayable once. What SEC's
 * scorecard says goes into the state's bitmap instead, in xfrm's orientation
 * (ft_ipsec_replay_bit()). Only forward: a window behind the state's is not
 * applied, one level with it only adds what SEC has seen since, and one ahead
 * replaces it. The new bitmap is built whole before any word of it is stored,
 * so the state never holds a cleared one waiting to be refilled.
 *
 * Locking as ft_ipsec_publish_oseq(). Nothing orders the bitmap's stores
 * against the top's for a reader without x->lock, which can pair a new bitmap
 * with the old top or the other way about; a re-add read that way is folded
 * forward from where SEC left the old SA all the same.
 */
static void ft_ipsec_publish_window(struct xfrm_state *x,
				    const struct cdx_ipsec_counters *counters)
{
	struct xfrm_replay_state_esn *esn = x->replay_esn;
	u32 window = esn ? esn->replay_window : x->props.replay_window;
	u32 ring[CDX_IPSEC_REPLAY_WINDOW_MAX / 32] = {};
	u32 top = lower_32_bits(counters->seq);
	u32 k, bit, words;
	bool ahead;
	u64 now;

	if (!window || !counters->seq)
		return;
	if (!esn) {
		u32 seen = counters->seen[0] &
			   (window < 32 ? (1U << window) - 1 : ~0U);

		if (counters->seq < x->replay.seq)
			return;
		if (counters->seq > x->replay.seq) {
			WRITE_ONCE(x->replay.bitmap, seen);
			WRITE_ONCE(x->replay.seq, top);
		} else {
			WRITE_ONCE(x->replay.bitmap, x->replay.bitmap | seen);
		}
		return;
	}
	/* An inbound SA's window is at most CDX_IPSEC_REPLAY_WINDOW_MAX
	 * (ft_ipsec_spec()), so the ring's live words fit here; any beyond
	 * them xfrm never reads. */
	if (window > CDX_IPSEC_REPLAY_WINDOW_MAX)
		return;
	words = min_t(u32, DIV_ROUND_UP(window, 32), esn->bmp_len);
	now = esn->seq;
	if (x->props.flags & XFRM_STATE_ESN)
		now |= (u64)esn->seq_hi << 32;
	if (counters->seq < now)
		return;
	ahead = counters->seq > now;
	if (!ahead)
		memcpy(ring, esn->bmp, words * sizeof(ring[0]));
	for (k = 0; k < window; k++) {
		if (!(counters->seen[k / 32] & (1U << (k % 32))))
			continue;
		bit = ft_ipsec_replay_bit(top, window, k);
		ring[bit / 32] |= 1U << (bit % 32);
	}
	for (k = 0; k < words; k++)
		WRITE_ONCE(esn->bmp[k], ring[k]);
	if (ahead) {
		if (x->props.flags & XFRM_STATE_ESN)
			WRITE_ONCE(esn->seq_hi, upper_32_bits(counters->seq));
		WRITE_ONCE(esn->seq, top);
	}
}

/* Publish one reading of SEC's into the state, the direction's own way.
 * Locking as ft_ipsec_publish_oseq(). */
static void ft_ipsec_publish(struct xfrm_state *x,
			     const struct cdx_ipsec_counters *counters)
{
	if (x->xso.dir == XFRM_DEV_OFFLOAD_OUT)
		ft_ipsec_publish_oseq(x, counters->oseq);
	else
		ft_ipsec_publish_window(x, counters);
}

/* ------------------------------------------------- what SEC refused, for xfrm
 *
 * A frame SEC refuses never reaches Linux. SEC hands it back with its job
 * status to the SA's FROM_SEC queue, which feeds the IPsec offline port; the
 * FMan microcode there checks the status, counts the refusal in a table of
 * its own in MURAM and drops the frame inside FMan. Both feeders end there:
 * the classifier's, and the CPU's (`tx todec`), which enqueues to the same SA
 * queue before xfrm_input() gets as far as its own replay check. So neither
 * xfrm nor cdx ever holds a refused frame to count, and the microcode's table
 * (cdx_ipsec_sec_refusals()) is the only record of one.
 *
 * Its classes are not exact. Measured on microcode v210.10.1, replayed and
 * late frames all land in other_errs and never in the anti-replay counters,
 * and the ICV failures of one GCM burst split between icv_failures and
 * other_errs differently from the next. Nor, under a dense burst, is its
 * total: the offline port's tasks update it read-modify-write, and refusals
 * arriving back to back lose increments (up to 2.5% of a buffer-depletion
 * burst). And it is global: nothing in it names an SA, or a direction.
 *
 * So the pass folds the table into /proc/net/xfrm_stat, each class that has
 * one into the counter xfrm raises for its own equivalent drop
 * (ft_sec_refusal[]), and into no state: `ip -s xfrm state` replay/failed
 * stay at zero for an offloaded SA, because no per-SA count of them exists.
 * What the folded counters gain is exactly what the microcode sorted into
 * those classes, no more reliable than its sorting; the nearest to a count of
 * every refusal is the total in /proc/cdx_flowtable, which carries every
 * class. The classes that are no doing of the traffic's -- SEC's own faults,
 * and resources it ran out of -- are said out loud as well. Without
 * CONFIG_XFRM_STATISTICS the fold into xfrm compiles to nothing, and
 * /proc/cdx_flowtable is where the counts are.
 *
 * Differences, never a reset: the microcode updates these read-modify-write,
 * and a reset from here would race it. The reading taken at load is where
 * this module's counting starts, so nothing refused before it existed is put
 * down to it, and the counters' 32-bit wrap costs nothing at one reading a
 * period. Into init_net: the ops are attached only to ports there
 * (ft_netdev_event()), and xfrm offloads a state only to a device in its own
 * namespace, so every SA these can have been counted for is init_net's.
 */
static const struct {
	/* The class's row in /proc/cdx_flowtable, after "ipsec_sec_refused_". */
	const char *name;
	/* The xfrm_stat counter it is folded into, or zero -- LINUX_MIB_XFRMNUM,
	 * which counts nothing -- for none. */
	u8 mib;
	/* SEC's own fault or a resource it ran out of: nothing the traffic
	 * did, and nothing xfrm counts. */
	bool fault;
} ft_sec_refusal[CDX_SEC_REFUSAL_CLASSES] = {
	/* xfrm_input() counts as a protocol error whatever the ESP transform
	 * refuses: a failed ICV, the -EBADMSG it audits as one; a CCM job the
	 * cipher rejects, crypto_aead_decrypt() failing in esp_input(); a
	 * frame the transform cannot parse, and a malformed trailer, both of
	 * which esp_input() fails with -EINVAL. */
	[CDX_SEC_REFUSED_ICV]		  = { "icv", LINUX_MIB_XFRMINSTATEPROTOERROR },
	[CDX_SEC_REFUSED_CCM_AAD_SIZE]	  = { "ccm_aad_size", LINUX_MIB_XFRMINSTATEPROTOERROR },
	[CDX_SEC_REFUSED_PROTOCOL_FORMAT] = { "protocol_format", LINUX_MIB_XFRMINSTATEPROTOERROR },
	[CDX_SEC_REFUSED_PAD_CHECK]	  = { "pad_check", LINUX_MIB_XFRMINSTATEPROTOERROR },
	/* Both are xfrm_replay_check()'s sequence errors. */
	[CDX_SEC_REFUSED_LATE]		  = { "late", LINUX_MIB_XFRMINSTATESEQERROR },
	[CDX_SEC_REFUSED_REPLAY]	  = { "replay", LINUX_MIB_XFRMINSTATESEQERROR },
	/* SEC raises this on either side (SEC RM table 9-2), and the count
	 * does not say which. The outbound one is the one the offload reaches:
	 * SEC will not number a non-ESN SA past FFFFFFFE, and an SA whose rekey
	 * never came runs into that at line rate. xfrm counts its own outbound
	 * exhaustion here: xfrm_output_one() does, when xfrm_replay_overflow()
	 * finds no number left. The inbound one needs a peer
	 * sending past its own sequence space, which RFC 4303 forbids a sender
	 * and Linux's own output refuses. */
	[CDX_SEC_REFUSED_SEQ_OVERFLOW]	  = { "seq_overflow", LINUX_MIB_XFRMOUTSTATESEQERROR },
	/* A TTL or hop limit SEC took to zero. No xfrm counter: Linux's ESP
	 * input decapsulates such a frame, and it is ip_forward() that drops it,
	 * as an IP header error. No SA here asks SEC to decrement the TTL, so
	 * this is not expected to move. */
	[CDX_SEC_REFUSED_TTL_ZERO]	  = { "ttl_zero" },
	/* xfrm's "errors not matched by others". Replays and ICV failures both
	 * land here, so putting it down to either would be wrong. */
	[CDX_SEC_REFUSED_OTHER]		  = { "other", LINUX_MIB_XFRMINERROR },
	[CDX_SEC_REFUSED_HW]		  = { "hw", 0, true },
	[CDX_SEC_REFUSED_DMA]		  = { "dma", 0, true },
	[CDX_SEC_REFUSED_DECO_WATCHDOG]	  = { "deco_watchdog", 0, true },
	[CDX_SEC_REFUSED_INPUT_READ]	  = { "input_read", 0, true },
	[CDX_SEC_REFUSED_LENGTH_ROLLOVER] = { "length_rollover", 0, true },
	[CDX_SEC_REFUSED_TABLE_TOO_SMALL] = { "table_too_small", 0, true },
	[CDX_SEC_REFUSED_TABLE_DEPLETION] = { "table_depletion", 0, true },
	[CDX_SEC_REFUSED_OUTPUT_TOO_LARGE] = { "output_too_large", 0, true },
	[CDX_SEC_REFUSED_COMPOUND_WRITE]  = { "compound_write", 0, true },
	[CDX_SEC_REFUSED_BUFFER_TOO_SMALL] = { "buffer_too_small", 0, true },
	[CDX_SEC_REFUSED_BUFFER_DEPLETION] = { "buffer_depletion", 0, true },
	[CDX_SEC_REFUSED_OUTPUT_WRITE]	  = { "output_write", 0, true },
	[CDX_SEC_REFUSED_COMPOUND_READ]	  = { "compound_read", 0, true },
	[CDX_SEC_REFUSED_PREHEADER_READ]  = { "preheader_read", 0, true },
};

/* The microcode's counts as last read, whether they have been read at all,
 * and what this module has counted of them since it loaded. Under the
 * control transaction. */
static u32 ft_sec_seen[CDX_SEC_REFUSAL_CLASSES];
static bool ft_sec_known;
static u64 ft_sec_counted[CDX_SEC_REFUSAL_CLASSES];

/* Room for every fault class moving at once, at ten digits each: 343 bytes.
 * scnprintf() truncates rather than overruns if a name ever grows. */
#define FT_SEC_FAULT_TEXT	384

/* Count what SEC refused since the last reading. Transaction held.
 *
 * The first reading only sets where counting starts. Until one succeeds there
 * is nothing to start from: FMan places the counters with the first external
 * hash table, and nothing is offloaded -- so nothing refused -- before one
 * exists.
 */
void ft_sec_refusals_fold(void)
{
	char faults[FT_SEC_FAULT_TEXT];
	struct cdx_sec_refusals now;
	unsigned int i, at = 0;
	u64 faulted = 0;
	u32 moved;

	if (cdx_ipsec_sec_refusals(&now))
		return;
	if (!ft_sec_known) {
		memcpy(ft_sec_seen, now.count, sizeof(ft_sec_seen));
		ft_sec_known = true;
		return;
	}
	for (i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++) {
		/* Unsigned 32-bit difference: a count that wrapped since the
		 * last reading still adds what it counted. */
		moved = now.count[i] - ft_sec_seen[i];
		ft_sec_seen[i] = now.count[i];
		if (!moved)
			continue;
		ft_sec_counted[i] += moved;
		if (ft_sec_refusal[i].mib)
			XFRM_ADD_STATS(&init_net, ft_sec_refusal[i].mib, moved);
		if (!ft_sec_refusal[i].fault)
			continue;
		faulted += moved;
		at += scnprintf(faults + at, sizeof(faults) - at, " %s=%u",
				ft_sec_refusal[i].name, moved);
	}
	if (faulted)
		pr_warn_ratelimited("ask_flowtable: %llu IPsec frames dropped, SEC could not process them:%s\n",
				    faulted, faults);
}

/* Publish one SA's counters into its state and let xfrm judge them.
 *
 * A VALID state only. One that is being deleted has nothing left to expire,
 * and one already hard-expired is on its way there; xfrm_state_check_expire()
 * would only rearm the timer that is deleting it. x->lock is held across the
 * test and everything after it, and __xfrm_state_delete() runs under the same
 * lock, so a state seen VALID here stays so until the lock drops.
 *
 * The replay state is published under ft_ipsec_retired_lock as well, taken
 * inside x->lock as deletion takes it, because ft_xdo_state_update_stats()
 * publishes it too, from callers that do not hold x->lock. The SA's rate,
 * which a re-add of an outbound SA is carried past the old one by
 * (ft_ipsec_fold_oseq()), is kept under the same lock. The lock is dropped
 * before xfrm judges: xfrm_state_check_expire() asks that op again.
 */
static void ft_ipsec_account(struct ft_ipsec_retirement *owned,
			     const struct cdx_ipsec_counters *counters)
{
	struct xfrm_state *x = owned->x;
	u64 carried = 0;

	spin_lock_bh(&x->lock);
	if (x->km.state != XFRM_STATE_VALID)
		goto out;
	/* Only ever forward. The backend's totals do not go back, and if one
	 * ever did, adding the difference would wrap curlft to a limit's
	 * worth of traffic nobody sent; this waits for it to pass the figure
	 * already published instead. */
	if (counters->bytes > owned->published.bytes) {
		x->curlft.bytes += counters->bytes - owned->published.bytes;
		owned->published.bytes = counters->bytes;
	}
	if (counters->packets > owned->published.packets) {
		carried = counters->packets - owned->published.packets;
		x->curlft.packets += carried;
		owned->published.packets = counters->packets;
	}
	spin_lock_bh(&ft_ipsec_retired_lock);
	owned->sent = max(carried, owned->sent / 2);
	ft_ipsec_publish(x, counters);
	spin_unlock_bh(&ft_ipsec_retired_lock);
	/* An SA that has carried nothing has nothing to judge, and asking
	 * anyway would stamp use_time on it -- the moment its use-based
	 * lifetimes count from. */
	if (counters->packets && xfrm_state_check_expire(x))
		goto out;
	/* The same soft expiry xfrm_state_check_expire() raises for a byte or
	 * packet limit, and the same flag that makes it happen once. */
	if (ft_ipsec_seq_exhausting(x, counters->oseq) && !x->km.dying) {
		x->km.dying = 1;
		km_state_expired(x, 0, 0);
	}
out:
	spin_unlock_bh(&x->lock);
}

/* xfrm is about to read the state: publish where SEC has the SA's sequence
 * space now, rather than where the last accounting pass found it.
 *
 * Every caller either holds x->lock (the state timer,
 * xfrm_state_check_expire(), XFRM_MSG_GETAE, xfrm_state_migrate()) or reads
 * the state without it (XFRM_MSG_GETSA, dumps and notifications, some under
 * xfrm_state_lock, some in atomic context), so this neither sleeps nor takes
 * x->lock. What serialises the publications is ft_ipsec_retired_lock, which
 * every one of them takes, inside x->lock where that is held -- the order
 * deletion takes the two in.
 *
 * The same lock is what keeps the SA installed while it is read. Deletion
 * clears the handle before it moves the SA's entry off ft_ipsec_owned under
 * this lock, and only the retirement that follows, and takes the entry from
 * there, frees the SA -- descriptor, PDB and all. So a handle still set,
 * read under the lock, names an SA whose entry is still owned, and it stays
 * so until the lock drops; nothing has to be looked up to know it. A state
 * whose deletion has begun reads no handle and publishes nothing: its last
 * word is kept for a re-add instead (ft_ipsec_fold()).
 *
 * The lifetime is left to the accounting pass (see "what SEC counted, for
 * xfrm" above). A reader without x->lock can meet a publication midway, as
 * it can any update xfrm makes under that lock (ft_ipsec_publish_oseq());
 * forward-only publication and the fold a re-add gets keep that from ever
 * starting a new SA behind the old one.
 */
static void ft_xdo_state_update_stats(struct xfrm_state *x)
{
	struct cdx_ipsec_counters now;
	struct cdx_ipsec_sa *sa;

	spin_lock_bh(&ft_ipsec_retired_lock);
	sa = (struct cdx_ipsec_sa *)READ_ONCE(x->xso.offload_handle);
	if (sa && cdx_ipsec_sa_replay_state(sa, &now))
		ft_ipsec_publish(x, &now);
	spin_unlock_bh(&ft_ipsec_retired_lock);
}

/* Ask after every SA's path, and mark for the follow work only the watches
 * whose path's MTU has moved since they last followed it.
 *
 * A PMTU learned for a peer changes the path an SA's frames take and is
 * announced to nobody: __ip_rt_update_pmtu() records an exception on the
 * nexthop, which no FIB notification or netevent carries. So the accounting
 * pass samples it, and a path that narrows between two passes is followed
 * within a period.
 *
 * The FIB alone, and only a moved MTU marked (ft_ipsec_path_mtu()): the
 * follow work's whole re-resolution stays on the events that can change its
 * answer. A watch that is marked gets it once; the work records the path it
 * found whether or not the peer then resolved, so the next pass finds
 * nothing to mark.
 *
 * Every lock is dropped across each lookup, with the same shape and the same
 * per-pass guard as the follow work: a route lookup per SA is no work for
 * under a lock the neighbour and route notifiers take.
 */
static void ft_ipsec_sample_paths(void)
{
	struct ft_ipsec_watch *watch;
	struct ft_ipsec_route route;
	union nf_inet_addr local;
	union nf_inet_addr peer;
	struct net_device *dev;
	u64 cookie, pass;
	u32 path_mtu;
	u8 family;

	spin_lock_bh(&ft_watch_lock);
	pass = ++ft_ipsec_sample_pass;
	spin_unlock_bh(&ft_watch_lock);

	for (;;) {
		spin_lock_bh(&ft_watch_lock);
		watch = ft_ipsec_watch_unsampled(pass);
		if (!watch) {
			spin_unlock_bh(&ft_watch_lock);
			return;
		}
		watch->sampled = pass;
		cookie = watch->cookie;
		dev = watch->dev;
		family = watch->family;
		route = watch->route;
		local = watch->local;
		peer = watch->peer;
		dev_hold(dev);
		spin_unlock_bh(&ft_watch_lock);

		if (!ft_ipsec_path_mtu(dev, family, &local, &peer, &route,
				       &path_mtu)) {
			spin_lock_bh(&ft_watch_lock);
			watch = ft_ipsec_watch_find(cookie);
			if (watch && watch->path_mtu != path_mtu)
				ft_ipsec_mark(watch);
			spin_unlock_bh(&ft_watch_lock);
		}
		dev_put(dev);
	}
}

/* One accounting pass over every owned SA.
 *
 * The control transaction is held throughout, and it is what makes the walk
 * safe with ft_ipsec_retired_lock dropped: the retirement that frees an SA,
 * and the entry naming it, takes the transaction first. So every entry
 * gathered here stays allocated, with its SA installed, until the pass ends.
 * The state is held separately, for the same span, because it is xfrm's to
 * free and xfrm does not ask. x->lock is taken only after
 * ft_ipsec_retired_lock is dropped: deletion holds x->lock when it takes
 * that one.
 *
 * The pass keeps itself going while any SA is owned, and ft_xdo_state_add()
 * starts it again for the first SA after a gap.
 */
static void ft_ipsec_stats_work(struct work_struct *work)
{
	struct ft_ipsec_retirement *owned, *next;
	struct cdx_ipsec_counters counters;
	LIST_HEAD(pass);
	bool more;

	cdx_ft_begin();
	spin_lock_bh(&ft_ipsec_retired_lock);
	list_for_each_entry(owned, &ft_ipsec_owned, list) {
		xfrm_state_hold(owned->x);
		list_add_tail(&owned->pass, &pass);
	}
	spin_unlock_bh(&ft_ipsec_retired_lock);
	list_for_each_entry_safe(owned, next, &pass, pass) {
		list_del(&owned->pass);
		cdx_ipsec_sa_stats(owned->sa, &counters);
		ft_ipsec_account(owned, &counters);
		xfrm_state_put(owned->x);
	}
	/* What SEC refused is counted for no SA in particular, so once a pass
	 * rather than once an SA. */
	ft_sec_refusals_fold();
	spin_lock_bh(&ft_ipsec_retired_lock);
	more = !list_empty(&ft_ipsec_owned);
	spin_unlock_bh(&ft_ipsec_retired_lock);
	cdx_ft_end();
	if (more) {
		ft_ipsec_sample_paths();
		schedule_delayed_work(&ft_ipsec_stats, FT_IPSEC_STATS_PERIOD);
	}
}

/* Who the SA a spec describes is, for a re-add of it to find
 * (struct ft_ipsec_identity). The digest covers each key with its algorithm,
 * width and ICV length, as the spec carries them, and nothing of them
 * outlives the call but the digest. */
static void ft_ipsec_identify(const struct cdx_ipsec_sa_spec *spec,
			      struct ft_ipsec_identity *id)
{
	struct {
		struct cdx_ipsec_key auth;
		struct cdx_ipsec_key crypt;
	} keys;

	get_random_once(&ft_ipsec_digest_key, sizeof(ft_ipsec_digest_key));
	memset(id, 0, sizeof(*id));
	id->daddr = spec->dst;
	id->spi = spec->spi;
	id->replay_window = spec->replay_window;
	id->family = spec->family;
	id->dir = spec->dir;
	id->esn = spec->esn;
	keys.auth = spec->auth;
	keys.crypt = spec->crypt;
	id->digest = siphash(&keys, sizeof(keys), &ft_ipsec_digest_key);
	memzero_explicit(&keys, sizeof(keys));
}

/* Whether two identities are the same SA: the same SPI and direction under
 * the same keys, and numbering the same way, wherever each is bound. */
static bool ft_ipsec_same(const struct ft_ipsec_identity *a,
			  const struct ft_ipsec_identity *b)
{
	return a->dir == b->dir && a->spi == b->spi && a->digest == b->digest &&
	       a->esn == b->esn;
}

/* Whether an SA being installed has to wait for another to be out of the
 * hardware first: the same SA, whose last state it is to be carried on from,
 * or any SA whose classifier entry would take this one's key -- the same
 * direction, SPI and destination -- which the hash table refuses. */
static bool ft_ipsec_in_the_way(const struct ft_ipsec_identity *a,
				const struct ft_ipsec_identity *b)
{
	return ft_ipsec_same(a, b) ||
	       (a->dir == b->dir && a->spi == b->spi && a->family == b->family &&
		!memcmp(&a->daddr, &b->daddr, sizeof(a->daddr)));
}

/* Whether an SA in the way of `id` has been deleted and is not yet out of the
 * hardware. A retirement stays on ft_ipsec_retired until it has finished. */
static bool ft_ipsec_retiring_in_the_way(const struct ft_ipsec_identity *id)
{
	struct ft_ipsec_retirement *retiring;
	bool found = false;

	spin_lock_bh(&ft_ipsec_retired_lock);
	list_for_each_entry(retiring, &ft_ipsec_retired, list) {
		if (ft_ipsec_in_the_way(&retiring->id, id)) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&ft_ipsec_retired_lock);
	return found;
}

/* Keep a retired SA's entry as the record of where SEC left it, in place of
 * any older record of the same SA, and forget whatever is too old or one too
 * many. An SA SEC left nothing of -- an outbound one that sent nothing, an
 * inbound one checking no window -- has nothing to keep. Caller holds
 * ft_ipsec_retired_lock; true when the entry is kept, and is no longer the
 * caller's to free. */
static bool ft_ipsec_remember(struct ft_ipsec_retirement *retired)
{
	struct ft_ipsec_retirement *old, *next;

	if (!retired->last.oseq && !retired->last.seq)
		return false;
	/* The state is xfrm's to free from here on; nothing reads it again. */
	retired->x = NULL;
	retired->retired = jiffies;
	list_for_each_entry_safe(old, next, &ft_ipsec_remembered, list) {
		if (!ft_ipsec_same(&old->id, &retired->id) &&
		    time_before(retired->retired, old->retired + FT_IPSEC_REMEMBER_FOR))
			continue;
		list_del(&old->list);
		ft_ipsec_remembered_count--;
		kfree(old);
	}
	while (ft_ipsec_remembered_count >= FT_IPSEC_REMEMBERED) {
		old = list_first_entry(&ft_ipsec_remembered,
				       struct ft_ipsec_retirement, list);
		list_del(&old->list);
		ft_ipsec_remembered_count--;
		kfree(old);
	}
	list_add_tail(&retired->list, &ft_ipsec_remembered);
	ft_ipsec_remembered_count++;
	return true;
}

/* Forget every retired SA. Only once no retirement can run any more. */
void ft_ipsec_forget_all(void)
{
	struct ft_ipsec_retirement *old, *next;

	spin_lock_bh(&ft_ipsec_retired_lock);
	list_for_each_entry_safe(old, next, &ft_ipsec_remembered, list) {
		list_del(&old->list);
		kfree(old);
	}
	ft_ipsec_remembered_count = 0;
	spin_unlock_bh(&ft_ipsec_retired_lock);
}

/* Whether a window whose highest number is `top`, with `seen` in the spec's
 * orientation (bit k for top - k) over `window` numbers, would refuse `n`:
 * as seen, or as too old for it. A number above its top it has not seen. */
static bool ft_ipsec_refuses(u64 top, const u32 *seen, u32 window, u64 n)
{
	u64 behind;

	if (n > top)
		return false;
	behind = top - n;
	if (behind >= window)
		return true;
	return seen[behind / 32] & (1U << (behind % 32));
}

/* An inbound spec's window, moved on to cover a retired SA's too: the higher
 * of the two tops, every number either refuses marked seen. Past the spec's
 * own width is marked seen too, as ft_ipsec_replay_seen() marks it. */
static void ft_ipsec_fold_window(struct cdx_ipsec_sa_spec *spec,
				 const struct cdx_ipsec_counters *last,
				 u32 last_window)
{
	u32 seen[ARRAY_SIZE(spec->replay_seen)] = {};
	u64 top = max(spec->seq, last->seq);
	u32 k;

	for (k = 0; k < CDX_IPSEC_REPLAY_WINDOW_MAX; k++)
		if (k >= spec->replay_window ||
		    ft_ipsec_refuses(spec->seq, spec->replay_seen,
				     spec->replay_window, top - k) ||
		    ft_ipsec_refuses(last->seq, last->seen, last_window, top - k))
			seen[k / 32] |= 1U << (k % 32);
	spec->seq = top;
	memcpy(spec->replay_seen, seen, sizeof(seen));
}

/* An outbound spec's number when it re-adds a retired SA: past the higher of
 * the number it carried and the old SA's last, by twice what the old SA sent
 * in its last period and by FT_IPSEC_OSEQ_FLOOR at the least.
 *
 * A margin that would run past the last number SEC sends -- FFFFFFFE, or
 * FFFFFFFF:FFFFFFFE with ESN (SEC RM table 9-2) -- stops at it. Starting
 * there leaves the SA nothing to send, and the backend refuses it with
 * -EINVAL (cdx_ipsec_validate()): an old SA that close to the end of its
 * space leaves a re-add no number it could send without reusing one, so the
 * re-add fails, and the rekey the old SA's soft expiry asked for long before
 * is what carries the tunnel on.
 *
 * The old SA's last number was read once it was out of the hardware, so the
 * margin only has to cover what SEC may still have been holding of it then,
 * which the floor alone does many times over; a busy SA is skipped further
 * because skipping costs its peer nothing -- a gap in the sequence is what
 * loss looks like -- and reusing a number costs it the frame. This is the one
 * place a number goes ahead of SEC's: what is published is SEC's own
 * (ft_ipsec_publish_oseq()), and an add that re-adds nothing starts exactly
 * where it asked to. */
static void ft_ipsec_fold_oseq(struct cdx_ipsec_sa_spec *spec, u64 oseq, u64 sent)
{
	u64 last = spec->esn ? U64_MAX - 1 : U32_MAX - 1;
	u64 ahead = max(2 * sent, FT_IPSEC_OSEQ_FLOOR);

	oseq = max(spec->seq, oseq);
	spec->seq = oseq < last - min(last, ahead) ? oseq + ahead : last;
}

/* Carry a retired SA's last state into a re-add of it.
 *
 * A keying daemon that moves an SA to a new address -- strongSwan's MOBIKE
 * update, or a NAT's new mapping -- reads the state, deletes it and adds it
 * again with the same SPI and keys, carrying over the replay state it read.
 * That reading is as fresh as xdo_dev_state_update_stats() makes it, but SEC
 * goes on taking and sending the old SA's frames until its retirement takes
 * it out of the hardware: an inbound frame taken after the reading would be
 * taken once more by the new SA, and an outbound number sent after it would
 * be sent again. The retirement records where SEC left the SA
 * (ft_ipsec_remember()), and this carries that forward into the spec: the
 * higher window top with everything either window refuses, or the higher
 * outbound number and a margin past it (ft_ipsec_fold_oseq()).
 *
 * Into the same SA only: the same SPI and direction under the same keys,
 * wherever the re-add binds it -- a MOBIKE move changes one direction's
 * destination, and can change its family. A new SA reusing an SPI has other
 * keys and starts where it asked to. The same SA added again with nothing
 * carried is carried forward all the same: an inbound SA that had taken
 * nothing when it was read exports nothing, and still takes frames until it
 * is out of the hardware; and under the same keys a number the old SA took
 * or sent is one the new one must not take or send again, however it is
 * added (RFC 4303 3.3.3 lets a sequence number cycle only under a new SA).
 * Which is what manual keying with a window has to live with: an inbound SA
 * re-added within FT_IPSEC_REMEMBER_FOR under the same SPI and keys refuses a
 * peer that restarted at 1 until the peer passes the old top. With no window,
 * iproute2's default, nothing inbound is folded.
 * Only ever forward, so the spec never ends up behind what it brought.
 * Refusing the carried state instead would fail the re-add, and packet
 * offload has no software to fall back on: every MOBIKE update would take
 * the child SA down with it.
 */
static void ft_ipsec_fold(struct cdx_ipsec_sa_spec *spec,
			  const struct ft_ipsec_identity *id)
{
	struct ft_ipsec_retirement *old;

	spin_lock_bh(&ft_ipsec_retired_lock);
	list_for_each_entry(old, &ft_ipsec_remembered, list) {
		if (!ft_ipsec_same(&old->id, id) ||
		    !time_before(jiffies, old->retired + FT_IPSEC_REMEMBER_FOR))
			continue;
		if (spec->dir == CDX_IPSEC_DIR_OUT)
			ft_ipsec_fold_oseq(spec, old->last.oseq, old->sent);
		else if (spec->replay_window && old->last.seq)
			ft_ipsec_fold_window(spec, &old->last,
					     old->id.replay_window);
		break;
	}
	spin_unlock_bh(&ft_ipsec_retired_lock);
}

static int ft_xdo_state_add(struct xfrm_state *x, struct netlink_ext_ack *extack)
{
	struct ft_ipsec_watch *watch = NULL;
	struct ft_ipsec_retirement *retirement;
	struct cdx_ipsec_sa_spec spec;
	struct ft_ipsec_identity id;
	struct ft_ipsec_route route;
	struct cdx_ipsec_sa *sa;
	s64 changes;
	int rc;

	/* Crypto offload would leave the stack building every ESP header and
	 * hand SEC only the cipher, which is not what this hardware is for and
	 * not what the classifier can steer. Refusing is the honest answer;
	 * a caller asking for `auto` gets software instead, which works. */
	if (x->xso.type != XFRM_DEV_OFFLOAD_PACKET) {
		NL_SET_ERR_MSG(extack, "cdx: only packet offload is supported");
		return -EOPNOTSUPP;
	}
	/* An acquire placeholder, created by xfrm_state_find() when a policy
	 * matched and no SA existed yet. It carries no keys and no SPI, so
	 * there is nothing to program -- and it arrives under xfrm_state_lock
	 * with GFP_ATOMIC, where none of the work below is legal. Accept it
	 * and do nothing: the real state that replaces it comes through here
	 * again, from netlink, in a context that can do the work.
	 *
	 * Accepting rather than refusing matters. A refusal fails the acquire,
	 * and with it the on-demand tunnel that was being negotiated. */
	if (x->xso.flags & XFRM_DEV_OFFLOAD_FLAG_ACQ)
		return 0;
	if (x->id.proto != IPPROTO_ESP) {
		NL_SET_ERR_MSG(extack, "cdx: only ESP can be offloaded");
		return -EOPNOTSUPP;
	}
	if (x->props.mode != XFRM_MODE_TUNNEL &&
	    x->props.mode != XFRM_MODE_TRANSPORT) {
		NL_SET_ERR_MSG(extack, "cdx: only tunnel and transport mode can be offloaded");
		return -EOPNOTSUPP;
	}
	/* From here on the spec holds the SA's keys, which go no further than
	 * the backend's own copy: it is wiped on every way out. */
	rc = ft_ipsec_spec(x, &spec, extack);
	if (rc)
		goto wipe;
	ft_ipsec_identify(&spec, &id);
	/* Before the hardware, so that an SA nothing could follow is never
	 * installed at all. An outbound SA's next hop is written into its
	 * entry and never re-read, so the watch is part of installing one
	 * rather than an improvement on it. */
	if (spec.dir == CDX_IPSEC_DIR_OUT) {
		watch = kzalloc(sizeof(*watch), GFP_KERNEL);
		if (!watch) {
			rc = -ENOMEM;
			goto wipe;
		}
	}
	retirement = kzalloc(sizeof(*retirement), GFP_KERNEL);
	if (!retirement) {
		rc = -ENOMEM;
		goto free_watch;
	}
	/* The same SA may still be on its way out of the hardware: deleted a
	 * moment ago by a keying daemon now adding it again at a new address.
	 * Its retirement is finished first. That is what makes where SEC left
	 * it final for the fold below, and what keeps the two SAs from taking
	 * frames at once. With the destination unchanged, an ESP entry's key
	 * -- destination and SPI -- is the old one's, which the hash table
	 * refuses, failing this SA whatever its keys; with a new destination,
	 * or under NAT-T a new peer address or port, the keys differ, and both
	 * SAs would take frames, each against its own window, so a frame one
	 * had taken the other would take again. Waited for, not flushed, and
	 * not forever: see FT_IPSEC_RETIRE_WAIT. */
	if (!wait_event_timeout(ft_ipsec_retired_wait,
				!ft_ipsec_retiring_in_the_way(&id),
				FT_IPSEC_RETIRE_WAIT)) {
		NL_SET_ERR_MSG(extack, "cdx: an SA with this SPI is still leaving the hardware");
		rc = -EBUSY;
		goto free_retirement;
	}
	ft_ipsec_fold(&spec, &id);
	cdx_ft_begin();
	/* Before the build reads the port's egress, which an egress change
	 * updates before counting itself. */
	changes = atomic64_read_acquire(&ft_egress_changes);
	rc = cdx_ipsec_sa_add(&spec, x, &sa, extack);
	if (!rc && watch) {
		ft_ipsec_route_of(x, &route);
		ft_ipsec_watch_add(watch, &spec, sa, &route, changes);
	}
	cdx_ft_end();
	if (rc) {
		if (rc == -EADDRNOTAVAIL)
			NL_SET_ERR_MSG(extack, "cdx: an inbound SA's local address must be on the device it is offloaded to");
		NL_SET_ERR_MSG_WEAK(extack, "cdx: the hardware refused this SA");
		goto free_retirement;
	}
	memzero_explicit(&spec, sizeof(spec));
	retirement->sa = sa;
	retirement->x = x;
	retirement->id = id;
	spin_lock_bh(&ft_ipsec_retired_lock);
	list_add_tail(&retirement->list, &ft_ipsec_owned);
	spin_unlock_bh(&ft_ipsec_retired_lock);
	/* Nothing if the accounting pass is already queued, and otherwise the
	 * start of it: the pass stops itself once no SA is owned. */
	schedule_delayed_work(&ft_ipsec_stats, FT_IPSEC_STATS_PERIOD);
	/* The opaque owner, not the sixteen-bit handle: it identifies this SA
	 * for as long as it lives, whereas a handle becomes reusable the
	 * moment the SA is deleted. cdx_ipsec_sa_handle() still answers for
	 * anything that needs the number the hardware knows. */
	x->xso.offload_handle = (unsigned long)sa;
	/* Publish the hardware's own name for this SA as well.
	 *
	 * The datapath works in handles rather than pointers. A frame SEC hands
	 * back to the CPU carries nothing of its SA, but it arrives on the SA's
	 * own exception queue, whose id names the handle
	 * (get_netdev_of_SA_by_fqid()), and the state is found by that; the
	 * transmit path looks the SA's frame queue up by it too. Setting it
	 * here, before the state is inserted, is what puts the
	 * state in the kernel's handle index at all: xfrm_state_insert_byh()
	 * indexes only states whose driver has set a handle, so the index holds
	 * nothing but the handles the hardware knows.
	 */
	x->handle = cdx_ipsec_sa_handle(sa);
	return 0;

free_retirement:
	kfree(retirement);
free_watch:
	kfree(watch);
wipe:
	memzero_explicit(&spec, sizeof(spec));
	return rc;
}

/* Whether the SAs are all gone: none owned, and no retirement still queued. */
static bool ft_ipsec_none_left(void)
{
	bool none;

	spin_lock_bh(&ft_ipsec_retired_lock);
	none = list_empty(&ft_ipsec_owned) && list_empty(&ft_ipsec_retired);
	spin_unlock_bh(&ft_ipsec_retired_lock);
	return none;
}

/* Take deleted SAs out of the hardware, oldest first.
 *
 * Each stays on ft_ipsec_retired until it is out, so an add it is in the way
 * of can tell it is still on its way and wait for it (ft_xdo_state_add()),
 * woken on ft_ipsec_retired_wait as each one finishes.
 * Only this work takes entries off that list, and one instance of it runs at
 * a time, so the first entry is this pass's to finish. Where SEC left the SA
 * is read as it goes (cdx_ipsec_sa_del()) and kept for a re-add of it
 * (ft_ipsec_remember()).
 */
static bool ft_names_sa(const struct cdx_ft_entry *entry, const void *handle)
{
	return entry->rule.sa_handle == *(const u16 *)handle ||
	       entry->rule.in_sa_handle == *(const u16 *)handle;
}

static void ft_ipsec_retire_work(struct work_struct *work)
{
	struct ft_ipsec_retirement *retirement;
	struct cdx_ft_entry *entry;
	bool kept, marked;
	u16 handle;

	for (;;) {
		spin_lock_bh(&ft_ipsec_retired_lock);
		retirement = list_first_entry_or_null(&ft_ipsec_retired,
						      struct ft_ipsec_retirement, list);
		spin_unlock_bh(&ft_ipsec_retired_lock);
		if (!retirement)
			return;
		handle = cdx_ipsec_sa_handle(retirement->sa);
		marked = false;
		for (;;) {
			bool more;

			cdx_ft_begin();
			/* Serialize with admission, including an admission the atomic
			 * deletion callback missed before its watch was published.
			 * Never reuse an SA handle while a flow can still name it.
			 * Linux stops using every such flow at once; the batches
			 * that follow need not look again, and still take out a
			 * flow admitted meanwhile, as they match on the SA. */
			if (!marked) {
				list_for_each_entry(entry, &ft_entries, list)
					if (ft_names_sa(entry, &handle))
						ft_handle_invalidate(entry->handle,
								     &ft_ipsec_invalidations);
				marked = true;
			}
			more = ft_retire_batch(ft_names_sa, &handle);
			/* A deletion barrier can defer reclaim or require datapath
			 * quiescence. Retain the SA until that proof completes. */
			if (!more && (!cdx_ft_pending() || !cdx_ft_recover()))
				break;
			cdx_ft_end();
			if (more)
				cond_resched();
			else
				msleep(20);
		}
		cdx_ipsec_sa_del(&retirement->sa, &retirement->last);
		/* Out of the hardware: an egress drain waiting on it may now
		 * say so, having taken this transaction to look. */
		atomic_dec(&ft_ipsec_retiring);
		spin_lock_bh(&ft_ipsec_retired_lock);
		list_del(&retirement->list);
		kept = ft_ipsec_remember(retirement);
		spin_unlock_bh(&ft_ipsec_retired_lock);
		wake_up_all(&ft_ipsec_retired_wait);
		/* The accounting pass stops once no SA is owned. The last one
		 * out counts what SEC refused up to its going, so that is not
		 * left waiting for the next SA to be installed. */
		if (ft_ipsec_none_left())
			ft_sec_refusals_fold();
		cdx_ft_end();
		if (!kept)
			kfree(retirement);
	}
}

DECLARE_WORK(ft_ipsec_retire, ft_ipsec_retire_work);

/* The next watch this pass has not already taken on. Caller holds
 * ft_watch_lock. */
static struct ft_ipsec_watch *ft_ipsec_watch_stale(u64 pass)
{
	struct ft_ipsec_watch *watch;

	list_for_each_entry(watch, &ft_ipsec_watches, list)
		if (watch->stale && watch->pass != pass)
			return watch;
	return NULL;
}

/* Ask again where each marked SA's peer is, and correct the ones that moved.
 *
 * Two things make this safe to do with every lock dropped across the lookup,
 * which it has to be because resolving sleeps:
 *
 * The device is pinned for the pass. xfrm holds a reference to an offloaded
 * state's device, but that reference goes with the state, and the state can be
 * destroyed while this is resolving -- so the pass takes its own.
 *
 * The SA is alive whenever its watch is. ft_xdo_state_delete() unlinks the
 * watch before queueing the retirement, and that retirement takes the control
 * mutex to free the SA; so a watch found under both is an SA the rebuild can
 * still be handed. Nothing here dereferences a watch pointer outside the lock,
 * which is why the cookie exists: a freed watch's memory can be reused by the
 * next SA installed, and an address would then name the wrong one.
 *
 * A failure leaves the SA on the address it has, which is what it would have
 * had anyway, and re-marks the watch without queueing itself again: the
 * neighbour or route event that fixes the underlying problem is what brings
 * the work back, and re-queueing here would spin against a peer that is
 * simply down. The re-mark is why each pass takes a watch at most once --
 * otherwise the loop below would pick the same failure straight back up.
 *
 * A failure is also said out loud, once per watch. The silent cases are the
 * ones worth naming: a peer that has moved to a route leaving by a different
 * port cannot be followed at all, because packet offload binds a state to one
 * device and this SA's egress framing belongs to that device. Nothing retires
 * the SA and nothing else would report it.
 */
static void ft_ipsec_follow_work(struct work_struct *work)
{
	struct ft_ipsec_watch *watch;
	struct cdx_ipsec_sa *sa;
	union nf_inet_addr local;
	union nf_inet_addr peer;
	union nf_inet_addr hop;
	struct net_device *dev;
	u8 was_dst[ETH_ALEN];
	u8 was_src[ETH_ALEN];
	u8 mac[ETH_ALEN];
	bool reported, rebuild, moved, reframe, resolved, listed;
	u32 asked, was_built, was_path, path_mtu;
	u64 cookie;
	u64 pass;
	struct ft_ipsec_route route;
	u8 family;
	int rc;

	spin_lock_bh(&ft_watch_lock);
	pass = ++ft_ipsec_follow_pass;
	spin_unlock_bh(&ft_watch_lock);

	for (;;) {
		spin_lock_bh(&ft_watch_lock);
		watch = ft_ipsec_watch_stale(pass);
		if (!watch) {
			spin_unlock_bh(&ft_watch_lock);
			return;
		}
		watch->stale = false;
		watch->pass = pass;
		cookie = watch->cookie;
		dev = watch->dev;
		family = watch->family;
		route = watch->route;
		local = watch->local;
		peer = watch->peer;
		hop = watch->hop;
		reported = watch->reported;
		/* Left set: it is cleared below once the rebuild has happened,
		 * and only if no egress change asked for another meanwhile. */
		rebuild = watch->rebuild;
		asked = watch->rebuilds_asked;
		ether_addr_copy(was_dst, watch->dst_mac);
		ether_addr_copy(was_src, watch->src_mac);
		was_built = watch->built_mtu;
		was_path = watch->path_mtu;
		dev_hold(dev);
		spin_unlock_bh(&ft_watch_lock);

		path_mtu = 0;
		rc = ft_ipsec_peer_mac(dev, family, &local, &peer, &route, false,
				       mac, &path_mtu, &hop, NULL);
		resolved = !rc;
		if (path_mtu) {
			/* The route was found, and with it, unless no entry
			 * could be allocated, the neighbour whose events now
			 * concern this SA, resolved or not: the gateway may
			 * have changed with the route, and a peer that did not
			 * resolve is waited for by its answer. */
			spin_lock_bh(&ft_watch_lock);
			watch = ft_ipsec_watch_find(cookie);
			if (watch)
				watch->hop = hop;
			spin_unlock_bh(&ft_watch_lock);
		}
		/* The path's MTU is framing as much as the addresses are: the
		 * entry fragments SEC's output to it, and every direction the
		 * SA encrypts was bounded by the SA on it. It is known once the
		 * route is, whether or not the peer then resolved. */
		moved = path_mtu && path_mtu != was_path;
		reframe = !rc && path_mtu != was_built;
		if (moved) {
			/* The directions follow the path even when the peer
			 * does not resolve or the rebuild below fails: their
			 * bound is Linux's, which moved with the path already.
			 * Recording the path here rather than after a rebuild
			 * is also what keeps the accounting pass from marking
			 * this watch again every period while its peer is
			 * down. A watch still listed names an SA not yet queued
			 * for retirement, so its handle is still its own. */
			spin_lock_bh(&ft_watch_lock);
			watch = ft_ipsec_watch_find(cookie);
			if (watch && watch->sa) {
				ft_ipsec_path_moved(cdx_ipsec_sa_handle(watch->sa));
				watch->path_mtu = path_mtu;
			}
			spin_unlock_bh(&ft_watch_lock);
		}
		if (!rc && !rebuild && !reframe && ether_addr_equal(mac, was_dst) &&
		    ether_addr_equal(dev->dev_addr, was_src)) {
			/* Nothing to rebuild. A route event marks every SA
			 * under the changed prefix, so most passes end here. */
			dev_put(dev);
			continue;
		}
		if (!rc) {
			cdx_ft_begin();
			spin_lock_bh(&ft_watch_lock);
			watch = ft_ipsec_watch_find(cookie);
			sa = watch ? watch->sa : NULL;
			spin_unlock_bh(&ft_watch_lock);
			rc = sa ? cdx_ipsec_sa_set_next_hop(sa, mac, path_mtu) : 0;
			if (sa && !rc) {
				spin_lock_bh(&ft_watch_lock);
				watch = ft_ipsec_watch_find(cookie);
				if (watch) {
					ether_addr_copy(watch->dst_mac, mac);
					ether_addr_copy(watch->src_mac,
							dev->dev_addr);
					watch->built_mtu = path_mtu;
					watch->reported = false;
					if (watch->rebuilds_asked == asked)
						watch->rebuild = false;
				}
				spin_unlock_bh(&ft_watch_lock);
				atomic64_inc(&ft_ipsec_next_hop_updates);
				if (reframe && family == AF_INET6)
					netdev_info(dev, "cdx: IPsec SA to %pI6c follows its path's MTU, now %u\n",
						    &peer.in6, path_mtu);
				else if (reframe)
					netdev_info(dev, "cdx: IPsec SA to %pI4 follows its path's MTU, now %u\n",
						    &peer.ip, path_mtu);
				else
					netdev_info(dev, "cdx: IPsec SA followed its peer to %pM\n",
						    mac);
			}
			cdx_ft_end();
		}
		if (rc) {
			spin_lock_bh(&ft_watch_lock);
			watch = ft_ipsec_watch_find(cookie);
			listed = !!watch;
			if (watch) {
				watch->stale = true;
				watch->reported = true;
			}
			spin_unlock_bh(&ft_watch_lock);
			/* The peer's answer to the probe above may have landed
			 * before the watch was stale again, and been lost; ask
			 * once more now that it is. A rebuild that failed with
			 * the peer resolved waits for an event, as before. */
			if (!resolved && listed &&
			    ft_ipsec_peer_resolved(dev, family, &local, &peer, &route))
				schedule_work(&ft_ipsec_follow);
			if (!reported && family == AF_INET6)
				netdev_warn(dev,
					    "cdx: IPsec SA to %pI6c could not follow its peer (%d); its tunnel keeps emitting to %pM\n",
					    &peer.in6, rc, was_dst);
			else if (!reported)
				netdev_warn(dev,
					    "cdx: IPsec SA to %pI4 could not follow its peer (%d); its tunnel keeps emitting to %pM\n",
					    &peer.ip, rc, was_dst);
		}
		dev_put(dev);
	}
}

/* xfrm_state_delete() holds x->lock with bottom halves disabled, whereas
 * backend retirement needs the control mutex. Queue it promptly without
 * waiting for the state's final free: in-flight SEC skbs retain secpath
 * references until their input buffers complete and are reaped. The backend
 * clears its borrowed state pointer before anything can follow it again. */
static void ft_xdo_state_delete(struct xfrm_state *x)
{
	struct cdx_ipsec_sa *sa = (void *)xchg(&x->xso.offload_handle, 0);
	struct ft_ipsec_retirement *retirement, *owned = NULL;

	if (!sa)
		return;
	/* Close the admission-before-watch race independently of policy
	 * changes; an SA expiry leaves policy itself unchanged. */
	atomic64_inc_return_release(&ft_ipsec_genid);
	/* Counted before the watch goes, which is what the egress drain saw
	 * of the SA until now: it reads the watches and then this, under the
	 * watch lock the removal releases. */
	atomic_inc(&ft_ipsec_retiring);
	ft_ipsec_watch_del(sa);
	ft_ipsec_retire_sa(cdx_ipsec_sa_handle(sa));
	spin_lock_bh(&ft_ipsec_retired_lock);
	list_for_each_entry(retirement, &ft_ipsec_owned, list) {
		if (retirement->sa != sa)
			continue;
		owned = retirement;
		list_move_tail(&retirement->list, &ft_ipsec_retired);
		break;
	}
	spin_unlock_bh(&ft_ipsec_retired_lock);
	if (WARN_ON_ONCE(!owned)) {
		atomic_dec(&ft_ipsec_retiring);
		return;
	}
	schedule_work(&ft_ipsec_retire);
}

/* Nothing left to do: delete has already queued the hardware retirement, and
 * the handle it took is gone. This exists so the core has something to call
 * and so a state that somehow reaches free still un-owns its SA.
 */
static void ft_xdo_state_free(struct xfrm_state *x)
{
	WARN_ON_ONCE(x->xso.offload_handle);
}

static bool ft_xdo_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	/* Reached only after the core's own size check. There is nothing
	 * per-frame left to refuse: an SA the hardware accepted stays
	 * installed until the state is deleted, and a port that has gone down
	 * takes its flows with it rather than its SAs. */
	return true;
}

/* Whether @t names an outbound SA this adapter holds on @dev.
 *
 * Matched on the fields xfrm_state_find() pairs a template with a
 * packet-offloaded state by, less three: the policy's mark and if_id and a
 * tunnel template's source address. So this accepts a superset of what the
 * kernel would pair: it never refuses a policy the kernel pairs with a held
 * SA, and for strongSwan, whose policies and SAs agree on those three, it is
 * exact. Caller holds ft_ipsec_retired_lock, which keeps each owned entry's
 * state valid. */
static bool ft_ipsec_names_owned(const struct net_device *dev,
				 const struct xfrm_tmpl *t)
{
	struct ft_ipsec_retirement *owned;
	const struct xfrm_state *x;

	list_for_each_entry(owned, &ft_ipsec_owned, list) {
		x = owned->x;
		if (x->xso.dir == XFRM_DEV_OFFLOAD_OUT && x->xso.dev == dev &&
		    x->id.spi == t->id.spi && x->id.proto == t->id.proto &&
		    x->props.reqid == t->reqid && x->props.mode == t->mode &&
		    x->props.family == t->encap_family &&
		    (xfrm_addr_any(&t->id.daddr, t->encap_family) ||
		     xfrm_addr_equal(&x->id.daddr, &t->id.daddr, t->encap_family)))
			return true;
	}
	return false;
}

/* The inbound halves of `out` this adapter holds on `in`, newest first, each
 * with a reference the caller puts: the states whose destination is `out`'s
 * source and whose source is its destination, with its protocol, family and
 * a mark its own would select, as xfrm_state_lookup_byaddr() matches them. At
 * most `max`; ft_ipsec_paired_inbound() judges which takes a tuple, outside
 * the lock, since that judgement takes xfrm's own policy locks. */
static unsigned int ft_ipsec_inbound_candidates(const struct xfrm_state *out,
						const struct net_device *in,
						struct xfrm_state **held,
						unsigned int max)
{
	struct ft_ipsec_retirement *owned;
	unsigned int count = 0;
	struct xfrm_state *x;

	spin_lock_bh(&ft_ipsec_retired_lock);
	list_for_each_entry_reverse(owned, &ft_ipsec_owned, list) {
		if (count == max)
			break;
		x = owned->x;
		if (x->xso.type != XFRM_DEV_OFFLOAD_PACKET ||
		    x->xso.dir != XFRM_DEV_OFFLOAD_IN || x->xso.dev != in ||
		    x->props.family != out->props.family ||
		    x->id.proto != IPPROTO_ESP ||
		    (out->mark.v & x->mark.m) != x->mark.v ||
		    !xfrm_addr_equal(&x->id.daddr, &out->props.saddr, x->props.family) ||
		    !xfrm_addr_equal(&x->props.saddr, &out->id.daddr, x->props.family))
			continue;
		xfrm_state_hold(x);
		held[count++] = x;
	}
	spin_unlock_bh(&ft_ipsec_retired_lock);
	return count;
}

/* Whether every SA an outbound policy names by SPI is one this adapter holds
 * on the policy's device.
 *
 * A packet-offloaded outbound policy selects packet-offloaded states only, and
 * only on its own device (xfrm_state_find()), so a policy naming a state that
 * is not one could never select it: every packet it matched would wait on an
 * acquire instead, with the child SA up. That is what strongSwan's
 * `hw_offload = auto` builds whenever this adapter refuses a child SA's
 * outbound SA: it installs the SA in software, and then asks for the policy
 * with offload regardless. Refused here, `auto` installs the policy in
 * software too, where it selects the software SA. strongSwan names the SA's
 * SPI in an outbound policy's template; a policy that names none -- a trap
 * policy, installed before any SA exists -- is taken as before. */
static bool ft_ipsec_policy_served(const struct xfrm_policy *xp)
{
	bool served = true;
	int i;

	spin_lock_bh(&ft_ipsec_retired_lock);
	for (i = 0; i < xp->xfrm_nr && served; i++)
		if (xp->xfrm_vec[i].id.spi)
			served = ft_ipsec_names_owned(xp->xdo.dev, &xp->xfrm_vec[i]);
	spin_unlock_bh(&ft_ipsec_retired_lock);
	return served;
}

/* Policy offload, which is not optional however little the hardware needs it.
 *
 * CDX steers on flows and SPIs, not on policy selectors, so there is nothing
 * here to program -- and the first version of this driver therefore left the
 * policy ops out. That was wrong, and silently: xfrm_state_find() skips a
 * packet-offloaded state whenever the policy that reached it is not offloaded
 * too ("Skip HW policy for SW lookups"), so every offloaded SA was invisible
 * to the lookup and no packet ever selected one. The SA installed, reported
 * itself installed, and carried nothing.
 *
 * So these exist to make the pairing hold. Accepting a policy means agreeing
 * that flows matching it may select this device's offloaded SAs, which is
 * exactly what is wanted; the steering those flows then get is the SA's, and
 * the classifier entry belongs to the flow rather than to the policy.
 *
 * The pairing cuts both ways, though: an outbound policy is refused when it
 * names an SA it could never pair with (ft_ipsec_policy_served()).
 */
static int ft_xdo_policy_add(struct xfrm_policy *xp, struct netlink_ext_ack *extack)
{
	if (xp->xdo.type != XFRM_DEV_OFFLOAD_PACKET) {
		NL_SET_ERR_MSG(extack, "cdx: only packet offload is supported");
		return -EOPNOTSUPP;
	}
	if (!cdx_ipsec_port_supported(xp->xdo.dev)) {
		NL_SET_ERR_MSG(extack, "cdx: not an offload-capable port");
		return -EOPNOTSUPP;
	}
	if (xp->xdo.dir == XFRM_DEV_OFFLOAD_OUT && !ft_ipsec_policy_served(xp)) {
		NL_SET_ERR_MSG(extack, "cdx: the SA this policy names is not offloaded to its device");
		return -EOPNOTSUPP;
	}
	/* These policies select SAs for flow admission; the hardware does not
	 * implement their full selectors. Linux must check receiving packets,
	 * including plaintext arriving without a secpath. */
	xp->xdo.software_policy = true;
	return 0;
}

static void ft_xdo_policy_delete(struct xfrm_policy *xp)
{
}

static void ft_xdo_policy_free(struct xfrm_policy *xp)
{
}

static const struct xfrmdev_ops ft_xfrmdev_ops = {
	.owner			= THIS_MODULE,
	.xdo_dev_state_add	= ft_xdo_state_add,
	.xdo_dev_state_delete	= ft_xdo_state_delete,
	.xdo_dev_state_free	= ft_xdo_state_free,
	.xdo_dev_state_update_stats = ft_xdo_state_update_stats,
	.xdo_dev_offload_ok	= ft_xdo_offload_ok,
	.xdo_dev_policy_add	= ft_xdo_policy_add,
	.xdo_dev_policy_delete	= ft_xdo_policy_delete,
	.xdo_dev_policy_free	= ft_xdo_policy_free,
};

/* Attach the ops to a CDX physical port, and say so in its features.
 *
 * The feature bit is not decoration. strongSwan resolves the position of
 * `esp-hw-offload` once at startup and then tests it per interface before it
 * will even ask the kernel for offload, so a port that does not advertise it
 * is simply never offered an SA -- silently, and with the tunnel working in
 * software. Whatever sets the ops must set this too.
 */
void ft_ipsec_attach(struct net_device *dev)
{
	ASSERT_RTNL();
	if (dev->xfrmdev_ops || !cdx_ipsec_port_supported(dev))
		return;
	WRITE_ONCE(dev->xfrmdev_ops, &ft_xfrmdev_ops);
	/* All three, and wanted_features is the one that is easy to miss.
	 * netdev_get_wanted_features() is (features & ~hw_features) |
	 * wanted_features, so the moment the bit is advertised in hw_features
	 * the first term stops carrying it. Anything that recomputes features
	 * afterwards -- an MTU change, joining a bridge, an unrelated ethtool
	 * call -- would then clear it, and the only symptom would be
	 * strongSwan quietly declining to offload from that point on. */
	dev->hw_features |= NETIF_F_HW_ESP;
	dev->wanted_features |= NETIF_F_HW_ESP;
	dev->features |= NETIF_F_HW_ESP;
	netdev_features_change(dev);
}

void ft_ipsec_detach(struct net_device *dev)
{
	ASSERT_RTNL();
	if (dev->xfrmdev_ops != &ft_xfrmdev_ops)
		return;
	dev->features &= ~NETIF_F_HW_ESP;
	dev->wanted_features &= ~NETIF_F_HW_ESP;
	dev->hw_features &= ~NETIF_F_HW_ESP;
	WRITE_ONCE(dev->xfrmdev_ops, NULL);
	netdev_features_change(dev);
}

/* Detach from every port this module attached to. Unload cannot leave an ops
 * pointer into freed module text behind, and there is no notifier replay for
 * unregistration to do it for us. */
void ft_ipsec_detach_all(void)
{
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(&init_net, dev)
		ft_ipsec_detach(dev);
	rtnl_unlock();
	/* Core dispatch pins our module inside RCU before calling an op. */
	synchronize_rcu();
}

/* The frames SEC refused since this module loaded: all of them, which is
 * exact, and then each class the microcode counted them in, which is only as
 * good as its sorting; see ft_sec_refusal[]. As of the accounting pass's last
 * reading. Transaction held. */
void ft_sec_refusal_rows(struct seq_file *seq)
{
	u64 total = 0;
	unsigned int i;

	for (i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++)
		total += ft_sec_counted[i];
	seq_printf(seq, "ipsec_sec_refused %llu\n", total);
	for (i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++)
		seq_printf(seq, "ipsec_sec_refused_%s %llu\n", ft_sec_refusal[i].name,
			   ft_sec_counted[i]);
}

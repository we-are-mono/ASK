// SPDX-License-Identifier: GPL-2.0-or-later
/* The bridged multicast learner's traffic half: the hooks that see the
 * streams a bridge forwards, and what they record.
 */
#include "ask_flowtable_internal.h"

/* ---- the traffic half -------------------------------------------------
 *
 * A membership says which ports want a group. It cannot say which source is
 * sending it or which port that source is behind, because until a frame
 * arrives neither is a fact about anything. Both are read off the frames the
 * bridge is still forwarding in software, which is what it does for every
 * flow that has no hardware entry -- and stops doing the moment one appears,
 * so an installed flow costs the hook nothing.
 *
 * The hook stays registered while a membership or a route could name a flow
 * not learned yet: a group can have a second source at any time, and only a
 * frame says so.
 *
 * The hook runs in softirq and may not sleep, so it records into a small ring
 * and wakes the worker. No allocation, no mutex, no hardware.
 */

struct ft_mc_seen ft_mc_ring[FT_MC_RING];
unsigned int ft_mc_ring_head, ft_mc_ring_tail;
DEFINE_SPINLOCK(ft_mc_ring_lock);
/* What was recorded, so streams at line rate do not fill the ring with
 * restatements of the same facts between two runs of the worker -- and so
 * streams the worker can do nothing with do not wake it on every frame. The
 * hook stays registered while any membership or route stands, and a stream
 * nothing names, one turned away at FT_MC_MAX_FLOWS, a flow refused, each
 * reaches it on every frame; every fact recorded is a pass of the worker,
 * which takes the transaction. So there are slots for as many streams as a
 * LAN sends, not only the last few: more streams interleaving than the slots
 * hold would push each other out, and each would be news on every frame.
 *
 * That makes them a promise as well as a filter: the same frame is not
 * recorded again, however long the stream runs, until the slots are forgotten
 * or its slot goes to another fact. So they are forgotten (ft_mc_forget_seen())
 * whenever the answer a recorded frame got may have changed -- a membership or
 * a route created that could now name it, a flow retired, an entry taken out
 * of hardware -- and at no other time: forgetting them after every drain would
 * record every frame of a stream that never installs. A change that concerns
 * one fact supersedes its slot alone (ft_mc_supersede()). A cleared slot names
 * ifindex zero, which no frame arrives on.
 *
 * A fact is kept in one set of slots, chosen by a seeded hash of its stream,
 * and takes a free slot there or the one recorded longest ago -- but only one
 * recorded at least a refresh interval ago. Facts that each took their slot
 * within the interval are not pushed out by a newer one, which would make
 * them news again on their next frame; the newer one waits, counted in
 * mcast_deferred, and its next frame asks again. However many streams share a
 * set, it records no more facts in an interval than it has slots. A stream
 * waits only while every slot of its set holds a fact younger than that, and
 * a slot that lapses goes to the first frame that asks for it: with more
 * streams than slots in a set, each takes a slot within a few intervals. */
#define FT_MC_SEEN_SETS 64
#define FT_MC_SEEN_WAYS 4
struct ft_mc_seen_slot {
	struct ft_mc_seen seen;
	/* When it was recorded, and whether the answer it got has since
	 * changed in a way only its next frame can tell: it then lapses an
	 * interval after it was recorded, and that frame is recorded again. */
	unsigned long at;
	bool superseded;
};
static struct ft_mc_seen_slot ft_mc_last[FT_MC_SEEN_SETS][FT_MC_SEEN_WAYS];
u64 ft_mc_observed, ft_mc_dropped, ft_mc_deferred, ft_mc_hook_errors;
/* Runs of the worker. */
u64 ft_mc_passes;
bool ft_mc_hooked;
static DEFINE_MUTEX(ft_mc_hook_lock);

/* Let the next frame of any stream be recorded again, however it compares
 * with the last. Called with ft_mc_lock held, after the change that makes it
 * worth recording is visible on the lists, so the worker that drains the frame
 * matches it against the new state. */
void ft_mc_forget_seen(void)
{
	lockdep_assert_held(&ft_mc_lock);
	spin_lock_bh(&ft_mc_ring_lock);
	memset(ft_mc_last, 0, sizeof(ft_mc_last));
	spin_unlock_bh(&ft_mc_ring_lock);
}

static bool ft_mc_seen_eq(const struct ft_mc_seen *a, const struct ft_mc_seen *b)
{
	return a->bridge_ifindex == b->bridge_ifindex &&
	       a->in_ifindex == b->in_ifindex &&
	       !memcmp(&a->addr, &b->addr, sizeof(a->addr)) &&
	       !memcmp(&a->src, &b->src, sizeof(a->src)) &&
	       ether_addr_equal(a->dst_mac, b->dst_mac) &&
	       ether_addr_equal(a->src_mac, b->src_mac) &&
	       a->tagged == b->tagged;
}

/* The set of slots a fact is kept in: by its stream -- the port, the VLAN, the
 * group and the source -- under the adapter's seed, so no sender can choose
 * the streams that share one. */
static unsigned int ft_mc_seen_set(const struct ft_mc_seen *seen)
{
	u32 key[2 + 2 * sizeof(seen->src) / sizeof(u32)];

	BUILD_BUG_ON(sizeof(seen->addr.dst) != sizeof(seen->src));
	BUILD_BUG_ON(FT_MC_SEEN_SETS & (FT_MC_SEEN_SETS - 1));
	key[0] = seen->in_ifindex;
	key[1] = seen->addr.vid;
	memcpy(key + 2, &seen->addr.dst, sizeof(seen->addr.dst));
	memcpy(key + 2 + sizeof(seen->src) / sizeof(u32), &seen->src, sizeof(seen->src));
	return jhash2(key, ARRAY_SIZE(key), ft_hash_seed) & (FT_MC_SEEN_SETS - 1);
}

/* The answer `seen` got has changed, and only its next frame can say whether
 * it still holds: its slot lapses an interval after it was recorded, and the
 * next frame after that is recorded again. Not sooner, and not by forgetting
 * every slot: a stream that arrives in two shapes at once -- two senders of
 * one source, a port carrying it both tagged and untagged -- would otherwise
 * be news on every frame, and make every other stream news with it. Called
 * with ft_mc_lock held. */
void ft_mc_supersede(const struct ft_mc_seen *seen)
{
	struct ft_mc_seen_slot *set = ft_mc_last[ft_mc_seen_set(seen)];
	unsigned int i;

	lockdep_assert_held(&ft_mc_lock);
	spin_lock_bh(&ft_mc_ring_lock);
	for (i = 0; i < FT_MC_SEEN_WAYS; i++)
		if (ft_mc_seen_eq(seen, &set[i].seen))
			set[i].superseded = true;
	spin_unlock_bh(&ft_mc_ring_lock);
}

/* What the hook records for a frame of `f` in `shape`: the inverse of
 * ft_mc_seen_key(), byte for byte, so it finds the slot that frame took. */
void ft_mc_flow_seen(const struct ft_mc_flow *f,
		     const struct ft_mc_stream *shape,
		     struct ft_mc_seen *seen)
{
	memset(seen, 0, sizeof(*seen));
	seen->bridge_ifindex = f->bridge->ifindex;
	seen->in_ifindex = f->in->ifindex;
	seen->addr = f->addr;
	memset(&seen->addr.src, 0, sizeof(seen->addr.src));
	if (f->addr.proto == htons(ETH_P_IPV6))
		seen->src.in6 = f->addr.src.ip6;
	else
		seen->src.ip = f->addr.src.ip4;
	ether_addr_copy(seen->dst_mac, shape->dst_mac);
	ether_addr_copy(seen->src_mac, shape->src_mac);
	seen->tagged = shape->tagged;
}

/* The VLAN this frame is on, as the bridge will resolve it a moment later in
 * br_allowed_ingress(): the tag it carries, or the ingress port's PVID when it
 * carries none. Reading it here rather than waiting for the bridge to do it is
 * what lets the observation name the same VLAN the MDB entry does. */
static u16 ft_mc_frame_vid(struct net_device *bridge, struct net_device *port,
			   struct sk_buff *skb)
{
	u16 vid = 0;

	/* A bridge that does not filter resolves every frame to VLAN zero, and
	 * every MDB entry it reports carries vid zero -- br_allowed_ingress()
	 * returns without touching the caller's `vid = 0` when
	 * BROPT_VLAN_ENABLED is clear. The port's PVID is *not* zero there:
	 * nbp_vlan_init() installs the bridge's default_pvid on enslavement
	 * whatever the filtering setting, so asking for it unconditionally
	 * returns 1 and no observation ever matches a membership. That made
	 * the whole learner inert on the commonest configuration there is. */
	if (!br_vlan_enabled(bridge))
		return 0;
	if (skb_vlan_tag_present(skb))
		return skb_vlan_tag_get_id(skb);
	if (skb->protocol == htons(ETH_P_8021Q)) {
		struct vlan_hdr *vhdr;

		if (!pskb_may_pull(skb, VLAN_HLEN))
			return 0;
		vhdr = (struct vlan_hdr *)skb->data;
		return ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
	}
	br_vlan_get_pvid_rcu(port, &vid);
	return vid;
}

/* Put one observation in the ring for the worker, unless it restates one
 * recorded, its set of slots has none to give it yet, or the ring is full.
 * Returns whether it was recorded. Called from the hook, in softirq. */
static bool ft_mc_record(const struct ft_mc_seen *seen)
{
	struct ft_mc_seen_slot *set = ft_mc_last[ft_mc_seen_set(seen)];
	struct ft_mc_seen_slot *slot = NULL;
	unsigned long now = jiffies;
	bool recorded = false, again = false;
	unsigned int next, i;

	spin_lock(&ft_mc_ring_lock);
	for (i = 0; i < FT_MC_SEEN_WAYS; i++) {
		struct ft_mc_seen_slot *s = &set[i];

		if (ft_mc_seen_eq(seen, &s->seen)) {
			/* Recorded already, and nothing has changed since --
			 * or something has, and the record has not lapsed. */
			if (!s->superseded ||
			    time_before(now, s->at + FT_MC_REFRESH_INTERVAL))
				goto out;
			slot = s;
			again = true;
			break;
		}
		/* A free slot first, then the one recorded longest ago. */
		if (!slot || (slot->seen.in_ifindex &&
			      (!s->seen.in_ifindex || time_before(s->at, slot->at))))
			slot = s;
	}
	if (!again && slot->seen.in_ifindex &&
	    time_before(now, slot->at + FT_MC_REFRESH_INTERVAL)) {
		ft_mc_deferred++;
		goto out;
	}
	next = (ft_mc_ring_head + 1) % FT_MC_RING;
	if (next == ft_mc_ring_tail) {
		ft_mc_dropped++;
		goto out;
	}
	ft_mc_ring[ft_mc_ring_head] = *seen;
	ft_mc_ring_head = next;
	slot->seen = *seen;
	slot->at = now;
	slot->superseded = false;
	ft_mc_observed++;
	recorded = true;
	schedule_work(&ft_mc_work);
out:
	spin_unlock(&ft_mc_ring_lock);
	return recorded;
}

static unsigned int ft_mc_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct net_device *port = state->in;
	struct net_device *bridge;
	struct ft_mc_seen seen = {};
	unsigned int l3_off;
	__be16 proto;
	u16 bproto;

	/* Cheapest tests first: this sits in the bridge's receive path. A
	 * source that is not a station's cannot key an entry whose listeners
	 * write it back. */
	if (!port || !skb || !is_multicast_ether_addr(eth_hdr(skb)->h_dest) ||
	    is_broadcast_ether_addr(eth_hdr(skb)->h_dest) ||
	    !is_valid_ether_addr(eth_hdr(skb)->h_source))
		return NF_ACCEPT;
	bridge = netdev_master_upper_dev_get_rcu(port);
	if (!bridge || !netif_is_bridge_master(bridge))
		return NF_ACCEPT;

	/* The L3 header's offset from skb->data, which is not zero for a frame
	 * that still carries its tag inline. skb_vlan_untag() moves a single
	 * tag into metadata and resets the network header before the bridge's
	 * rx handler runs, so this is the QinQ case -- but when it happens,
	 * reading through ip_hdr() would take the L3 fields four bytes early
	 * and record an observation of nothing. */
	proto = skb->protocol;
	l3_off = 0;
	if (proto == htons(ETH_P_8021Q)) {
		struct vlan_hdr *vhdr;

		if (!pskb_may_pull(skb, VLAN_HLEN))
			return NF_ACCEPT;
		vhdr = (struct vlan_hdr *)skb->data;
		proto = vhdr->h_vlan_encapsulated_proto;
		l3_off = VLAN_HLEN;
	}
	/* The one framing a group can be learned from is a single tag in the
	 * bridge's own protocol, or none. A tag still inline here is a second
	 * one, and a root validates one stack only; a tag in another protocol
	 * is one br_allowed_ingress() treats as payload. Both keep the stream
	 * in software, which is where they were anyway: before a group could
	 * say what it arrives with, its root refused every tagged frame. And a
	 * bridge that does not filter forwards a tagged frame with its tag,
	 * which a listener given the bridge's (empty) egress tags would drop.
	 * The bridge's protocol has to be 802.1Q as well as the tag's: an
	 * 802.1ad bridge takes an 802.1Q tag for payload and resolves the frame
	 * to its PVID, which is not the VLAN the tag names. */
	if (l3_off ||
	    (skb_vlan_tag_present(skb) &&
	     (!br_vlan_enabled(bridge) || skb->vlan_proto != htons(ETH_P_8021Q) ||
	      br_vlan_get_proto(bridge, &bproto) || bproto != ETH_P_8021Q)))
		return NF_ACCEPT;

	if (proto == htons(ETH_P_IP)) {
		const struct iphdr *iph;

		/* Pull before taking the pointer, not after: pskb_may_pull()
		 * can reallocate the head and leave an earlier one dangling. */
		if (!pskb_may_pull(skb, l3_off + sizeof(*iph)))
			return NF_ACCEPT;
		iph = (const struct iphdr *)(skb->data + l3_off);
		/* The parser ends the parse of a frame whose TTL is 0 or 1
		 * before any table is consulted, so no entry ever matches one:
		 * the stream stays in software whatever is installed. A flow
		 * learned from it would be an entry that counts nothing, aged
		 * out and learned again from the next frame for as long as the
		 * stream runs. The same holds for the IPv6 hop limit. */
		if (iph->ttl <= 1)
			return NF_ACCEPT;
		seen.addr.dst.ip4 = iph->daddr;
		seen.src.ip = iph->saddr;
		seen.addr.proto = htons(ETH_P_IP);
	} else if (proto == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6h;

		if (!pskb_may_pull(skb, l3_off + sizeof(*ip6h)))
			return NF_ACCEPT;
		ip6h = (const struct ipv6hdr *)(skb->data + l3_off);
		if (ip6h->hop_limit <= 1)
			return NF_ACCEPT;
		seen.addr.dst.ip6 = ip6h->daddr;
		seen.src.in6 = ip6h->saddr;
		seen.addr.proto = htons(ETH_P_IPV6);
	} else {
		return NF_ACCEPT;
	}
	/* Never a candidate; see ft_mc_link_local(). */
	if (ft_mc_link_local(&seen.addr))
		return NF_ACCEPT;

	seen.addr.vid = ft_mc_frame_vid(bridge, port, skb);
	seen.bridge_ifindex = bridge->ifindex;
	seen.in_ifindex = port->ifindex;
	ether_addr_copy(seen.dst_mac, eth_hdr(skb)->h_dest);
	ether_addr_copy(seen.src_mac, eth_hdr(skb)->h_source);
	seen.tagged = skb_vlan_tag_present(skb);
	/* This hook runs before br_allowed_ingress(), which drops a tagged
	 * frame in a VLAN the port is not a member of. A flow learned from one
	 * would be asked of the bridge, found not to resolve, retired, and
	 * learned again from the next such frame, for as long as a host sends
	 * them -- so it is not learned at all. */
	if (seen.tagged) {
		struct bridge_vlan_info info;

		if (br_vlan_get_info_rcu(port, seen.addr.vid, &info))
			return NF_ACCEPT;
	}

	ft_mc_record(&seen);
	return NF_ACCEPT;	/* always: this observes, it never diverts */
}

static struct nf_hook_ops ft_mc_hook_ops = {
	.hook = ft_mc_hook,
	.pf = NFPROTO_BRIDGE,
	.hooknum = NF_BR_PRE_ROUTING,
	/* Last on the hook, deliberately.
	 *
	 * Every NF_BR_PRE_ROUTING hook already runs before the bridge resolves
	 * the frame's VLAN, so being first buys nothing the design needs. What
	 * it would buy is seeing frames a bridge filter rule at a later
	 * priority is about to drop -- and installing a hardware entry for one
	 * of those is worse than not offloading it, because the entry matches
	 * at the classifier and the operator's rule never runs again. Learning
	 * only from frames that survive filtering keeps the offload a faster
	 * version of what the box would have done anyway. */
	.priority = NF_BR_PRI_LAST,
};

/* Whether a bridge hook that could decide a frame's fate is registered in
 * init_net at any of `hooks`, a mask of NF_BR_* bits. The bridged learner's
 * own is not: it only observes. Asked of the hook lists themselves, which
 * cost a few loads under RCU: no event says a hook was registered. */
bool ft_bridge_hooked(unsigned int hooks)
{
#if IS_ENABLED(CONFIG_NETFILTER_FAMILY_BRIDGE)
	const struct nf_hook_entries *e;
	struct nf_hook_ops **ops;
	bool hooked = false;
	unsigned int i, j;

	rcu_read_lock();
	/* The array's own bound: it has NF_INET_NUMHOOKS slots, one fewer than
	 * NF_BR_NUMHOOKS counts, since BROUTING is no netfilter hook. */
	for (i = 0; i < ARRAY_SIZE(init_net.nf.hooks_bridge) && !hooked; i++) {
		if (!(hooks & BIT(i)))
			continue;
		e = rcu_dereference(init_net.nf.hooks_bridge[i]);
		if (!e)
			continue;
		ops = nf_hook_entries_get_hook_ops(e);
		for (j = 0; j < e->num_hook_entries; j++)
			if (ops[j] != &ft_mc_hook_ops) {
				hooked = true;
				break;
			}
	}
	rcu_read_unlock();
	return hooked;
#else
	return false;
#endif
}

/* Whether netfilter runs a chain on what `dev` receives, at its own netdev
 * ingress hook: an nftables netdev chain, or an inet one at ingress -- and a
 * netfilter BPF program, which 6.12 attaches to no netdev hook but would read
 * what it liked. A flowtable's hook, the one other user of the hook, does not
 * count: it acts only on the conntrack flows a rule offered it. Asked by type,
 * as nfnetlink_hook tells them apart, rather than by excluding the
 * flowtable's, which this kernel does not label. Under RCU or RTNL. */
bool ft_dev_nf_ingress_hooked(const struct net_device *dev)
{
#if IS_ENABLED(CONFIG_NETFILTER_INGRESS)
	const struct nf_hook_entries *e;
	struct nf_hook_ops **ops;
	bool hooked = false;
	unsigned int i;

	rcu_read_lock();
	e = rcu_dereference(dev->nf_hooks_ingress);
	if (e) {
		ops = nf_hook_entries_get_hook_ops(e);
		for (i = 0; i < e->num_hook_entries && !hooked; i++)
			hooked = ops[i]->hook_ops_type == NF_HOOK_OP_NF_TABLES ||
				 ops[i]->hook_ops_type == NF_HOOK_OP_BPF;
	}
	rcu_read_unlock();
	return hooked;
#else
	return false;
#endif
}

/* Whether a bridge hook sees the frames a bridge forwards: at PRE_ROUTING,
 * FORWARD or POST_ROUTING. An nftables bridge-family chain, an ebtables
 * table, br_netfilter handing bridged traffic to iptables -- any of them can
 * drop, count or mark a forwarded frame, and an installed entry replicates at
 * the classifier where none of them runs. So while one is registered, no
 * bridged flow is carried.
 *
 * The worker asks at every pass, and the refresh runs one every interval
 * while any flow exists. br_netfilter is counted whatever its call-iptables
 * settings say, since those are its own and its hooks sit at FORWARD and
 * POST_ROUTING regardless. */
bool ft_mc_bridge_filtered(void)
{
	return ft_bridge_hooked(BIT(NF_BR_PRE_ROUTING) | BIT(NF_BR_FORWARD) |
				BIT(NF_BR_POST_ROUTING));
}

/* The hook exists only while a membership or a route could name a flow. A box
 * with neither pays the static key in nf_hook_bridge_pre() and nothing else.
 *
 * Registration sleeps, so this runs from the worker. Called without
 * ft_mc_lock. */
void ft_mc_hook_sync(bool wanted)
{
	/* A lock of its own, because the flag alone is not enough: registering
	 * sleeps for as long as nf_register_net_hook() takes, and teardown
	 * running in that window would read `not hooked`, do nothing, and let
	 * the worker finish planting a hook into text about to be unmapped.
	 * Consulting ft_mc_stopping from inside the lock closes it from the
	 * other side too -- whichever of the two gets here first, the other
	 * sees a consistent state and the hook ends up unregistered. */
	mutex_lock(&ft_mc_hook_lock);
	if (READ_ONCE(ft_mc_stopping))
		wanted = false;
	if (wanted == ft_mc_hooked)
		goto out;
	if (wanted) {
		int rc = nf_register_net_hook(&init_net, &ft_mc_hook_ops);

		if (rc) {
			/* Nothing will retry on its own -- the only things
			 * that wake the worker are a membership change and
			 * the hook that did not register. Say so rather than
			 * leaving a box that silently never offloads. */
			ft_mc_hook_errors++;
			pr_warn_ratelimited("cdx: multicast learner could not register its hook (%d); groups will stay in software\n",
					    rc);
			goto out;
		}
	} else {
		nf_unregister_net_hook(&init_net, &ft_mc_hook_ops);
		/* Unregistering does not wait for the frames already inside
		 * the hook: the entries are freed through call_rcu() and the
		 * caller returns at once. A reader still running could write
		 * a slot after they are cleared below, or queue the worker
		 * after ft_mc_exit() has cancelled it. The hook runs under the
		 * RCU read lock of the receive path, so one grace period is
		 * every such reader gone. */
		synchronize_net();
		spin_lock_bh(&ft_mc_ring_lock);
		memset(ft_mc_last, 0, sizeof(ft_mc_last));
		spin_unlock_bh(&ft_mc_ring_lock);
	}
	ft_mc_hooked = wanted;
out:
	mutex_unlock(&ft_mc_hook_lock);
}

/* The key a flow would have for this observation: its group, VLAN and family,
 * and its source. */
static void ft_mc_seen_key(const struct ft_mc_seen *seen, struct br_ip *key)
{
	*key = seen->addr;
	if (key->proto == htons(ETH_P_IPV6))
		key->src.ip6 = seen->src.in6;
	else
		key->src.ip4 = seen->src.ip;
}

static bool ft_mc_same_shape(const struct ft_mc_stream *shape,
			     const struct ft_mc_seen *seen)
{
	return ether_addr_equal(shape->dst_mac, seen->dst_mac) &&
	       ether_addr_equal(shape->src_mac, seen->src_mac) &&
	       shape->tagged == seen->tagged;
}

/* The flow an observation belongs to, if one exists. Called with ft_mc_lock
 * held. */
static struct ft_mc_flow *ft_mc_flow_find(const struct br_ip *key,
					  const struct ft_mc_seen *seen)
{
	struct ft_mc_flow *f;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list)
		if (!f->gone && f->in && f->in->ifindex == seen->in_ifindex &&
		    f->bridge->ifindex == seen->bridge_ifindex &&
		    !memcmp(&f->addr, key, sizeof(*key)))
			return f;
	return NULL;
}

/* Whether a published route names this source through its own bridge: only
 * while the bridge hands its streams to the host, as a multicast router or a
 * promiscuous bridge does, since otherwise the host never sees them for the
 * route to forward. Called with ft_mc_lock held. */
static bool ft_mc_route_learns(const struct ft_mc_route *r,
			       const struct br_ip *key)
{
	return r->bridge && ft_mc_route_reaches(r, r->bridge, key) &&
	       !memcmp(&r->src, &key->src, sizeof(key->src)) &&
	       (br_multicast_router(r->bridge) ||
		(READ_ONCE(r->bridge->flags) & IFF_PROMISC));
}

/* The bridge whose membership or route names a flow with this key, or NULL
 * when nothing does. Called with ft_mc_lock held.
 *
 * A (*,G) membership names any source and an (S,G) one -- which an IGMPv3
 * report produces -- only its own; either is only a reason to ask, and the
 * bridge's answer decides what the flow is. A route names its own source;
 * see ft_mc_route_learns(). */
static struct net_device *ft_mc_namer(const struct br_ip *key, int bridge_ifindex)
{
	const struct ft_mc_group *g;
	const struct ft_mc_route *r;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(g, &ft_mc_groups, list) {
		if (g->bridge->ifindex != bridge_ifindex ||
		    (!g->ports && !g->host) ||
		    !ft_mc_same_vlan_group(&g->addr, key))
			continue;
		if (!memchr_inv(&g->addr.src, 0, sizeof(g->addr.src)) ||
		    !memcmp(&g->addr.src, &key->src, sizeof(key->src)))
			return g->bridge;
	}
	list_for_each_entry(r, &ft_mc_routes, list)
		if (r->bridge && r->bridge->ifindex == bridge_ifindex &&
		    ft_mc_route_learns(r, key))
			return r->bridge;
	return NULL;
}

/* Whether something on this bridge asked for this source of the group by
 * name, rather than for the group whatever its source: an (S,G) membership,
 * which an IGMPv3 or MLDv2 INCLUDE report produces, or a route, which always
 * names its source. Called with ft_mc_lock held. */
static bool ft_mc_source_named(const struct net_device *bridge,
			       const struct br_ip *key)
{
	const struct ft_mc_group *g;
	const struct ft_mc_route *r;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(g, &ft_mc_groups, list)
		if (g->bridge == bridge && (g->ports || g->host) &&
		    ft_mc_same_vlan_group(&g->addr, key) &&
		    memchr_inv(&g->addr.src, 0, sizeof(g->addr.src)) &&
		    !memcmp(&g->addr.src, &key->src, sizeof(key->src)))
			return true;
	list_for_each_entry(r, &ft_mc_routes, list)
		if (r->bridge == bridge && ft_mc_route_learns(r, key))
			return true;
	return false;
}

/* Whether the host has joined this group on this bridge VLAN. The bridge
 * records a host join as (*,G) only, and hands the host every source of the
 * group for it, so the answer for each of them is refused-host. Called with
 * ft_mc_lock held. */
static bool ft_mc_host_joined(const struct net_device *bridge,
			      const struct br_ip *key)
{
	const struct ft_mc_group *g;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(g, &ft_mc_groups, list)
		if (g->bridge == bridge && g->host &&
		    ft_mc_same_vlan_group(&g->addr, key))
			return true;
	return false;
}

/* Whether two flows are the same classifier key: the key names the port, the
 * Ethernet pair and the address pair, and no VLAN. */
bool ft_mc_same_key(const struct ft_mc_flow *a, const struct ft_mc_flow *b)
{
	return a->in && a->in == b->in && a->addr.proto == b->addr.proto &&
	       !memcmp(&a->addr.dst, &b->addr.dst, sizeof(a->addr.dst)) &&
	       !memcmp(&a->addr.src, &b->addr.src, sizeof(a->addr.src)) &&
	       ether_addr_equal(a->src_mac, b->src_mac) &&
	       ether_addr_equal(a->dst_mac, b->dst_mac);
}

/* Take what the hook observed: a frame of a flow already known, or the first
 * of one that something names. Called with ft_mc_lock held. */
void ft_mc_observe(const struct ft_mc_seen *seen)
{
	bool counted = false, shared = false;
	unsigned int flows = 0, port_flows = 0, total = 0;
	struct net_device *bridge, *in;
	struct ft_mc_seen other;
	struct ft_mc_flow *f, *o;
	struct br_ip key;

	lockdep_assert_held(&ft_mc_lock);
	ft_mc_seen_key(seen, &key);
	f = ft_mc_flow_find(&key, seen);
	if (f) {
		/* Its stream is arriving, which answers a flow that asked. */
		f->seen_at = jiffies;
		f->probing = false;
		if (ether_addr_equal(f->dst_mac, seen->dst_mac) &&
		    ether_addr_equal(f->src_mac, seen->src_mac) &&
		    f->in_tagged == seen->tagged)
			return;	/* already what we have */
		/* An installed flow keeps the key it was installed with for
		 * as long as that key carries traffic.
		 *
		 * cdx_mc_group_replace() exchanges a listener set under a
		 * fixed key and refuses anything else, so a new shape is a new
		 * entry rather than a modified one. And two live senders of
		 * one source -- a MAC that moved between two hosts, a port that
		 * now carries the tag -- must not trade one entry between them
		 * on every frame, taking the global control mutex each time.
		 * So the shape is kept for later, and takes over once the
		 * refresh finds the installed key idle. A tag the flow did not
		 * arrive with is asked of the bridge first, which validates
		 * it; a MAC changes nothing the bridge decides. */
		if (f->hw) {
			if (f->has_next && ft_mc_same_shape(&f->next, seen))
				return;	/* already waiting to take over */
			ether_addr_copy(f->next.dst_mac, seen->dst_mac);
			ether_addr_copy(f->next.src_mac, seen->src_mac);
			f->next.tagged = seen->tagged;
			f->has_next = true;
			if (seen->tagged != f->in_tagged)
				f->dirty = true;
			if (f->idle)
				f->stale = true;
			return;
		}
		/* With nothing installed there is nothing to wait for: the flow
		 * takes the shape it is seen in, and one kept from an installed
		 * phase is stale. The shape it had, and the one it kept, are a
		 * different answer now, and their next frames have to be able
		 * to say so. */
		other = *seen;
		ether_addr_copy(other.dst_mac, f->dst_mac);
		ether_addr_copy(other.src_mac, f->src_mac);
		other.tagged = f->in_tagged;
		ft_mc_supersede(&other);
		if (f->has_next && !ft_mc_same_shape(&f->next, seen)) {
			ether_addr_copy(other.dst_mac, f->next.dst_mac);
			ether_addr_copy(other.src_mac, f->next.src_mac);
			other.tagged = f->next.tagged;
			ft_mc_supersede(&other);
		}
		ft_mc_drop_next(f);
		if (seen->tagged != f->in_tagged)
			f->dirty = true;
		ether_addr_copy(f->dst_mac, seen->dst_mac);
		ether_addr_copy(f->src_mac, seen->src_mac);
		f->in_tagged = seen->tagged;
		f->retries = 0;
		f->stale = true;
		return;
	}

	bridge = ft_mc_namer(&key, seen->bridge_ifindex);
	if (!bridge)
		return;
	in = dev_get_by_index(&init_net, seen->in_ifindex);
	if (!in)
		return;
	if (!cdx_mc_port_identity(in)) {
		dev_put(in);
		return;
	}
	/* The group's flows on this bridge VLAN, and the one to give way if
	 * there are as many as it may have.
	 *
	 * Past FT_MC_MAX_FLOWS a new source takes a place only when something
	 * asked for that source by name -- an (S,G) membership, which an SSM
	 * listener's report produces, or a route -- and only from a flow that
	 * nothing names that way and nothing carries: one not in hardware,
	 * which gives way at no cost, or failing that a discard, whose entry
	 * only drops what nobody wants. So a source an SSM listener asked for is not
	 * refused because the group's other senders got here first, and none
	 * of those can take a place back: a group every host sends to keeps
	 * the first eight it saw, and the rest cost a lookup here rather than
	 * a flow made, asked of the bridge under RTNL and retired again on
	 * each of their frames. Nor is a place given up while the whole group
	 * is refused -- the host joined it, it floods, or a bridge filter hook
	 * refuses every flow -- since the new source would be refused the same
	 * way. */
	o = NULL;
	list_for_each_entry(f, &ft_mc_flows, list) {
		/* The caps count what may still be carried. An installed
		 * discard is bounded by the group id it holds, and gives that
		 * id up to a stream somebody wants (A292): counted here, a
		 * port's discards would turn that stream away before it ever
		 * reached the add that takes the id (A314). */
		if (!f->gone && !f->hw_discard) {
			total++;
			port_flows += f->in == in;
		}
		if (f->gone || f->bridge != bridge ||
		    !ft_mc_same_vlan_group(&f->addr, &key))
			continue;
		flows++;
		counted |= f->turned;
		shared |= f->derived && ft_mc_host_wants(f);
		if ((!f->hw || (f->hw_discard && !o)) &&
		    !ft_mc_source_named(bridge, &f->addr))
			o = f;
	}
	if (flows >= FT_MC_MAX_FLOWS) {
		/* The new flow counts toward both bounds; the one giving way
		 * made room in them only if it counted there itself. */
		if (!o || shared || ft_mc_filtered ||
		    ((o->in != in || o->hw_discard) &&
		     port_flows >= FT_MC_MAX_PORT_FLOWS) ||
		    (o->hw_discard && total >= FT_MC_MAX_TOTAL_FLOWS) ||
		    ft_mc_host_joined(bridge, &key) ||
		    !ft_mc_source_named(bridge, &key)) {
			/* Counted once until the group's flows change, which
			 * the mark on each of them says. */
			if (!counted) {
				ft_mc_refused++;
				list_for_each_entry(f, &ft_mc_flows, list)
					if (!f->gone && f->bridge == bridge &&
					    ft_mc_same_vlan_group(&f->addr, &key))
						f->turned = true;
			}
			dev_put(in);
			return;
		}
		ft_mc_refused++;
		o->gone = true;
	} else if (total >= FT_MC_MAX_TOTAL_FLOWS ||
		   port_flows >= FT_MC_MAX_PORT_FLOWS) {
		/* A place given up above makes none; a new one would.
		 * Counted per frame the dedup slots let through, which is
		 * once until something is forgotten or lapses. */
		ft_mc_refused++;
		dev_put(in);
		return;
	}
	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f) {
		dev_put(in);
		/* Nothing else would ask for the frame again: its record
		 * lapses, rather than every record now, which a run of
		 * failures would make news on every frame. */
		ft_mc_supersede(seen);
		return;
	}
	dev_hold(bridge);
	f->bridge = bridge;
	f->addr = key;
	f->in = in;
	ether_addr_copy(f->dst_mac, seen->dst_mac);
	ether_addr_copy(f->src_mac, seen->src_mac);
	f->in_tagged = seen->tagged;
	f->seen_at = jiffies;
	f->dirty = true;
	f->stale = true;
	list_add_tail(&f->list, &ft_mc_flows);
	ft_mc_flow_count++;
	list_for_each_entry(o, &ft_mc_flows, list) {
		/* The same key on another VLAN of the bridge: both are asked
		 * again, and neither installs while both stand. */
		if (o != f && ft_mc_same_key(o, f))
			o->stale = true;
		/* The group's flows changed, so a source turned away from now
		 * on is news again. */
		if (o->bridge == bridge && ft_mc_same_vlan_group(&o->addr, &key))
			o->turned = false;
	}
}

/* Put the shape a flow was keeping in place of the one it is keyed on. Called
 * with ft_mc_lock held, once the installed key has been taken out of
 * hardware. */
void ft_mc_adopt_next(struct ft_mc_flow *f)
{
	lockdep_assert_held(&ft_mc_lock);
	if (!f->has_next)
		return;
	ether_addr_copy(f->dst_mac, f->next.dst_mac);
	ether_addr_copy(f->src_mac, f->next.src_mac);
	f->in_tagged = f->next.tagged;
	ft_mc_drop_next(f);
	f->retries = 0;
}

/* Whether frames arriving on `in` in this shape resolve to `vid`, as
 * br_allowed_ingress() would resolve them now: a tag the port is a member of,
 * or no tag and the port's PVID. Asked of every flow at every derivation,
 * because none of the settings it reads emits a netdev event when it changes,
 * and a root still accepting untagged frames on a port whose PVID moved would
 * replicate another VLAN's traffic. A bridge that does not filter resolves
 * everything to VLAN zero and forwards a tagged frame with its tag, which the
 * copies it resolves carry none of; see ft_mc_hook(). Called with RTNL held. */
bool ft_mc_shape_resolves(struct net_device *bridge,
			  struct net_device *in, bool tagged, u16 vid)
{
	struct bridge_vlan_info info;
	u16 pvid, proto;

	if (!br_vlan_enabled(bridge))
		return !tagged && !vid;
	if (tagged)
		return !br_vlan_get_proto(bridge, &proto) &&
		       proto == ETH_P_8021Q && !br_vlan_get_info(in, vid, &info);
	return !br_vlan_get_pvid(in, &pvid) && pvid == vid;
}

bool ft_mc_listeners_same(const struct cdx_mc_listener *a,
			  const struct cdx_mc_listener *b, u8 n)
{
	u8 i;

	/* Field by field, so no padding can decide it, and every field that
	 * identifies a listener -- a bridged one's address is always zero. */
	for (i = 0; i < n; i++)
		if (a[i].dev != b[i].dev || a[i].vlans != b[i].vlans ||
		    memcmp(a[i].vlan, b[i].vlan, sizeof(a[i].vlan)) ||
		    !ether_addr_equal(a[i].src_mac, b[i].src_mac))
			return false;
	return true;
}

// SPDX-License-Identifier: GPL-2.0-or-later
/* What the routed multicast learner asks of Linux before it carries a
 * group: the confirm hooks, the ruleset and xtables probes, and tc.
 */
#include "ask_flowtable_internal.h"

/* ---- what Linux itself forwarded ----------------------------------------
 *
 * The MFC says where ipmr and ip6mr would send a stream, not whether the
 * firewall lets it go. A forward chain dropping the group toward an oif --
 * fw4's default from WAN to LAN -- is as much a part of the routing decision
 * as the MFC, and a hardware entry replicates at the classifier, where no
 * hook runs again. So a copy of the (S,G) has to be seen leaving each oif at
 * POST_ROUTING, at a priority after every filter and NAT hook, having arrived
 * by the parent VIF, before the group is carried: such a copy passed
 * PRE_ROUTING, FORWARD and the earlier POST_ROUTING chains on its way, judged
 * by where it came from as well as where it goes. ipmr_queue_xmit() and
 * ip6mr_forward2() mark each copy forwarded and send it through
 * NF_INET_FORWARD to dst_output(), whose multicast output -- ip_mc_output(),
 * ip6_output() -- runs NF_INET_POST_ROUTING with the VIF as the output
 * device: a bridge or a VLAN device above one as much as a port. skb_iif is
 * the device ipmr saw the stream arrive on, which is the parent VIF's for
 * every copy it forwards. A group routed through a bridge is forwarded by
 * ipmr the same way once the bridge has handed its stream up, so its copies
 * are confirmed like any other before they are published.
 *
 * All or nothing. A root consumes every frame it matches, and no listener the
 * encoder expresses delivers to the CPU -- the bridged learner's refused-host
 * is the same gap -- so an entry carrying the confirmed oifs would starve an
 * unconfirmed one Linux still forwards to. A group waits in software,
 * pending-confirm, until every MFC oif has been seen.
 *
 * A confirmation proves that the ruleset forwards the copies seen there, not
 * what it does to every other packet of the group. The key the classifier
 * matches stops at L3, so a stream on another UDP port rides the same entry,
 * and one a rule drops -- or sends elsewhere, rate-limits, meters -- would be
 * replicated regardless. That the ruleset treats every packet of the group
 * alike is judged from the ruleset itself: nft_port_dependent() walks each
 * nftables chain a copy crosses, netdev ingress and egress on the devices
 * below the VIFs included, with everything about the stream known but its
 * ports, and a group whose packets could fare differently stays in software,
 * refused-ports. iptables-legacy is judged the same way and first:
 * nf_xt_port_dependent() walks each x_tables table a copy crosses, the NAT
 * tables the NAT core runs included, and a group its rules could tell apart
 * stays in software, refused-xtables. Nor does a confirmation see past the
 * observer: an nftables chain that runs after it at POST_ROUTING keeps the
 * group in software too. And tc, which runs on the devices rather than at a
 * hook, is ruled out device by device: a filter that runs in software where
 * the stream arrives or a copy leaves keeps the group in software,
 * refused-tc; see what tc does to a group's packets.
 *
 * A ruleset change takes every confirmation back. An nftables commit --
 * iptables-nft included -- moves init_net's base_seq and then the cursor the
 * packet path reads rules through, and confirmations are good only for the
 * pair they were made under. When either moves, every group returns to
 * software, so a drop rule added later stops the stream rather than being
 * bypassed. A commit goes on applying some of itself after it has moved the
 * pair -- a new chain's policy, element timeouts, a concatenated set's new
 * contents -- which nft_commit_in_progress() says it is still doing. So
 * confirmations start again only once the commit behind the pair has been
 * applied whole, and the pair has stood still for FT_MR_RULESET_SETTLE, which
 * bounds how often a run of commits can move a group in and out of hardware.
 * An iptables-legacy table carries no generation of its own; the kernel counts
 * every table registered, replaced and removed (nf_xt_seq()), and every group
 * is asked again once the count moves. No confirmation is taken back for it:
 * the walk's 0 says x_tables accepts every packet of the group untouched,
 * whatever the copies that confirmed it met, and its 1 keeps the group in
 * software regardless.
 */

#define FT_MR_WATCH_BUCKETS	64
static struct hlist_head ft_mr_watches[FT_MR_WATCH_BUCKETS];
/* The table's writers take it; the hook reads under RCU. */
static DEFINE_SPINLOCK(ft_mr_watch_lock);
static unsigned int ft_mr_watch_count[2];
/* The ruleset confirmations are good for -- nftables' commit counter and its
 * rules cursor -- when it was first seen, and whether the hook may make
 * them. Written by the worker alone. */
static unsigned int ft_mr_gen_seq;
static u8 ft_mr_gen_cursor;
static unsigned long ft_mr_gen_since;
bool ft_mr_gen_open;
static bool ft_mr_gen_armed;
/* Commits that took confirmations back; failures to register the observer
 * or to allocate a watch, each of which keeps groups in software. */
u64 ft_mr_ruleset_changes, ft_mr_confirm_errors;
/* Rulesets nft_port_dependent() or nf_xt_port_dependent() could not judge for
 * a group -- too large for their bounds, or no memory -- each of which kept
 * the group in software. */
u64 ft_mr_port_probe_errors;
/* The x_tables change count every group was last asked again for, and how
 * many times it moved while any group existed. Written by the worker alone. */
unsigned int ft_mr_xt_seen;
u64 ft_mr_xtables_changes;
/* A port walk a commit interrupted, whose group the ruleset poll has the
 * worker ask again. Set by the worker, taken by the poll. */
bool ft_mr_probe_again;
static void ft_mr_ruleset_fn(struct work_struct *work);
DECLARE_DELAYED_WORK(ft_mr_ruleset, ft_mr_ruleset_fn);

/* The ruleset in force, as the packet path reads it. The commit stores its
 * counter before it moves the cursor, and pairs that store with this
 * acquire. */
static void ft_mr_ruleset_read(unsigned int *seq, u8 *cursor)
{
#if IS_ENABLED(CONFIG_NF_TABLES)
	*seq = smp_load_acquire(&init_net.nft.base_seq);
	*cursor = READ_ONCE(init_net.nft.gencursor);
#else
	*seq = 0;
	*cursor = 0;
#endif
}

/* Whether nftables is still applying a commit: after moving the pair, it goes
 * on changing what a packet sees until the whole transaction is in place.
 * Read after the pair, with an acquire the commit's release pairs with, a
 * false here means the commit that produced the pair read is complete. */
static bool ft_mr_ruleset_applying(void)
{
#if IS_ENABLED(CONFIG_NF_TABLES)
	return nft_commit_in_progress(&init_net);
#else
	return false;
#endif
}

/* Whether the ruleset is still the one confirmations were armed for. */
static bool ft_mr_ruleset_current(void)
{
	unsigned int seq;
	u8 cursor;

	ft_mr_ruleset_read(&seq, &cursor);
	return seq == READ_ONCE(ft_mr_gen_seq) &&
	       cursor == READ_ONCE(ft_mr_gen_cursor);
}

static unsigned int ft_mr_watch_bucket(u8 family,
				       const union nf_inet_addr *src,
				       const union nf_inet_addr *dst)
{
	u32 key[8];

	memcpy(key, src->all, sizeof(src->all));
	memcpy(key + 4, dst->all, sizeof(dst->all));
	return jhash2(key, ARRAY_SIZE(key), family) & (FT_MR_WATCH_BUCKETS - 1);
}

/* Whether every oif of the watch has been seen. */
static bool ft_mr_watch_complete(const struct ft_mr_watch *w)
{
	unsigned long all = w->oifs >= BITS_PER_LONG ? ~0UL : BIT(w->oifs) - 1;

	return (READ_ONCE(w->seen) & all) == all;
}

/* A copy of (S,G) that arrived by `iif` was seen leaving by `ifindex` at
 * POST_ROUTING. Called from the hook, under RCU. The last oif of a group wakes
 * the worker. */
static void ft_mr_confirm_seen(u8 family, const union nf_inet_addr *src,
			       const union nf_inet_addr *dst, int ifindex,
			       int iif)
{
	struct ft_mr_watch *w;
	unsigned int i;

	if (READ_ONCE(ft_mr_stopping) || !READ_ONCE(ft_mr_gen_open))
		return;
	/* A commit the worker has not caught up with: this copy may have been
	 * judged by rules confirmations are not armed for, and the worker has
	 * to re-arm them. */
	if (!ft_mr_ruleset_current()) {
		schedule_work(&ft_mr_work);
		return;
	}
	/* One MFC entry per (S,G) in the table this learner reads, so one
	 * watch in practice; every one that matches is told all the same. */
	hlist_for_each_entry_rcu(w, &ft_mr_watches[ft_mr_watch_bucket(family, src, dst)],
				 node) {
		/* A copy from another parent was judged as coming from there:
		 * one the MFC entry moved away from, still in flight, or one
		 * the watch has not caught up with. */
		if (w->family != family || memcmp(&w->src, src, sizeof(*src)) ||
		    memcmp(&w->dst, dst, sizeof(*dst)) || w->parent != iif)
			continue;
		for (i = 0; i < w->oifs; i++) {
			if (w->oif[i] != ifindex)
				continue;
			/* Read first: every copy of a stream in software passes
			 * here, and only the first may write. */
			if (test_bit(i, &w->seen) || test_and_set_bit(i, &w->seen))
				break;
			if (ft_mr_watch_complete(w)) {
				WRITE_ONCE(w->news, true);
				schedule_work(&ft_mr_work);
			}
			break;
		}
	}
}

/* The last word on a forwarded multicast copy before it is transmitted. The
 * test every packet pays is whether its destination is multicast; a
 * forwarded copy of a group then costs one hash lookup. */
static unsigned int ft_mr_confirm_hook(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	union nf_inet_addr src = {}, dst = {};

	if (!state->out)
		return NF_ACCEPT;
	if (state->pf == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);

		if (!ipv4_is_multicast(iph->daddr) ||
		    !(IPCB(skb)->flags & IPSKB_FORWARDED))
			return NF_ACCEPT;
		src.ip = iph->saddr;
		dst.ip = iph->daddr;
		ft_mr_confirm_seen(AF_INET, &src, &dst, state->out->ifindex,
				   skb->skb_iif);
	} else {
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);

		if (!ipv6_addr_is_multicast(&ip6h->daddr) ||
		    !(IP6CB(skb)->flags & IP6SKB_FORWARDED))
			return NF_ACCEPT;
		src.in6 = ip6h->saddr;
		dst.in6 = ip6h->daddr;
		ft_mr_confirm_seen(AF_INET6, &src, &dst, state->out->ifindex,
				   skb->skb_iif);
	}
	return NF_ACCEPT;	/* always: this observes, it never diverts */
}

/* Last, so that every filter and NAT chain at POST_ROUTING has had the copy
 * first. At the very same priority netfilter puts a hook registered later
 * ahead of the ones already there, so what follows the observer is whatever
 * sat at the last priority when it was registered: conntrack's confirmation,
 * which only drops a copy it cannot insert, and any nftables chain placed
 * there. A BPF program cannot be: a netfilter BPF link refuses the last
 * priority, which it leaves to conntrack. ft_mr_observer_followed() looks for
 * the chains. */
static struct nf_hook_ops ft_mr_confirm_ops[2] = {
	{
		.hook = ft_mr_confirm_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = ft_mr_confirm_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP6_PRI_LAST,
	},
};
static bool ft_mr_confirm_hooked[2];
static DEFINE_MUTEX(ft_mr_confirm_hook_lock);

/* The hook for a family is registered while a group of it is watched, and
 * only then. Registration sleeps, so the worker and teardown call this, with
 * no lock held. */
void ft_mr_confirm_sync(void)
{
	unsigned int idx;
	bool dropped = false;

	mutex_lock(&ft_mr_confirm_hook_lock);
	for (idx = 0; idx < ARRAY_SIZE(ft_mr_confirm_ops); idx++) {
		bool wanted = !READ_ONCE(ft_mr_stopping) &&
			      READ_ONCE(ft_mr_watch_count[idx]);

		if (wanted == ft_mr_confirm_hooked[idx])
			continue;
		if (wanted) {
			int rc = nf_register_net_hook(&init_net,
						      &ft_mr_confirm_ops[idx]);

			/* Tried again at the worker's next pass; meanwhile
			 * nothing confirms and every group of the family stays
			 * in software, which is the safe side. */
			if (rc) {
				ft_mr_confirm_errors++;
				pr_warn_ratelimited("cdx: routed multicast could not register its forwarding check (%d); groups stay in software\n",
						    rc);
				continue;
			}
		} else {
			nf_unregister_net_hook(&init_net,
					       &ft_mr_confirm_ops[idx]);
			dropped = true;
		}
		ft_mr_confirm_hooked[idx] = wanted;
	}
	/* Unregistering does not wait for the copies already inside the hook,
	 * which read the table and may wake the worker. */
	if (dropped)
		synchronize_net();
	mutex_unlock(&ft_mr_confirm_hook_lock);
}

/* Follow the ruleset. When nftables has committed since confirmations were
 * armed, every one is taken back and the new pair is timed; once it has stood
 * still for FT_MR_RULESET_SETTLE, copies confirm under it. Called by the
 * worker with no lock held. Returns whether confirmations were taken back;
 * the first arming has none to take. */
bool ft_mr_ruleset_sync(void)
{
	struct ft_mr_watch *w;
	unsigned int seq, b;
	bool armed, watched;
	u8 cursor;

	if (ft_mr_gen_armed && ft_mr_ruleset_current()) {
		if (READ_ONCE(ft_mr_gen_open) ||
		    time_before(jiffies, ft_mr_gen_since + FT_MR_RULESET_SETTLE))
			return false;
		/* Stood still long enough, but not settled while the commit
		 * behind it is still being applied, however long that takes:
		 * a copy judged meanwhile saw part of it. Asked after the pair
		 * was read, which ft_mr_ruleset_current() just did. */
		if (ft_mr_ruleset_applying())
			return false;
		/* Applied whole. A copy already past FORWARD by now may have
		 * been judged by the rules before it, or by the commit half
		 * applied: every such one finishes first. After this, a copy
		 * the hook sees started under the pair applied whole, or under
		 * a later one it will not match. */
		synchronize_rcu();
		if (ft_mr_ruleset_current())
			WRITE_ONCE(ft_mr_gen_open, true);
		return false;
	}
	/* No confirmation from here, and none still being made: a copy the
	 * hook has in hand may have passed the old rules. */
	WRITE_ONCE(ft_mr_gen_open, false);
	synchronize_rcu();
	spin_lock_bh(&ft_mr_watch_lock);
	for (b = 0; b < FT_MR_WATCH_BUCKETS; b++)
		hlist_for_each_entry(w, &ft_mr_watches[b], node) {
			WRITE_ONCE(w->seen, 0);
			WRITE_ONCE(w->news, false);
		}
	ft_mr_ruleset_read(&seq, &cursor);
	WRITE_ONCE(ft_mr_gen_seq, seq);
	WRITE_ONCE(ft_mr_gen_cursor, cursor);
	watched = ft_mr_watch_count[0] || ft_mr_watch_count[1];
	spin_unlock_bh(&ft_mr_watch_lock);
	ft_mr_gen_since = jiffies;
	armed = ft_mr_gen_armed;
	ft_mr_gen_armed = true;
	/* Counted when there was something to take back. */
	if (armed && watched)
		ft_mr_ruleset_changes++;
	return armed;
}

/* How long until the ruleset in force may have settled: the rest of its
 * settling time, or once that is over -- the commit behind it still being
 * applied, or a newer one to arm for -- a short while. */
unsigned long ft_mr_ruleset_wait(void)
{
	unsigned long due = ft_mr_gen_since + FT_MR_RULESET_SETTLE;

	return time_after(due, jiffies) ? due - jiffies : FT_MR_RULESET_APPLYING;
}

/* Watch for a group's copies arriving by the parent VIF of its plan and
 * leaving by each of its oifs. The same parent and oifs keep their
 * confirmations. Changed oifs are a new watch, which carries over those of
 * the oifs it shares with the old one; a changed parent is a new watch that
 * carries over none, since every copy seen came from somewhere else. A failed
 * allocation leaves none either -- a list the watch no longer describes must
 * not admit the group. Called by the worker under RTNL with neither learner
 * lock held. */
void ft_mr_watch_arm(struct ft_mr_group *g, const struct ft_mr_plan *plan)
{
	unsigned int idx = ft_mr_idx(g->family);
	struct ft_mr_watch *old = g->watch, *w;
	unsigned long seen;
	u8 i, j;

	if (old && old->parent == plan->parent &&
	    old->oifs == plan->oif_count &&
	    !memcmp(old->oif, plan->oif, plan->oif_count * sizeof(plan->oif[0])))
		return;
	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (w) {
		w->family = g->family;
		w->src = g->src;
		w->dst = g->dst;
		w->parent = plan->parent;
		w->oifs = plan->oif_count;
		memcpy(w->oif, plan->oif, sizeof(w->oif));
		seen = old && old->parent == w->parent ? READ_ONCE(old->seen) : 0;
		for (i = 0; old && i < w->oifs; i++)
			for (j = 0; j < old->oifs; j++)
				if (old->oif[j] == w->oif[i] && test_bit(j, &seen))
					__set_bit(i, &w->seen);
	} else {
		ft_mr_confirm_errors++;
	}
	spin_lock_bh(&ft_mr_watch_lock);
	if (old && w) {
		hlist_replace_rcu(&old->node, &w->node);
	} else if (old) {
		hlist_del_rcu(&old->node);
		ft_mr_watch_count[idx]--;
	} else if (w) {
		hlist_add_head_rcu(&w->node, &ft_mr_watches[
			ft_mr_watch_bucket(g->family, &g->src, &g->dst)]);
		ft_mr_watch_count[idx]++;
	}
	spin_unlock_bh(&ft_mr_watch_lock);
	mutex_lock(&ft_mr_lock);
	g->watch = w;
	mutex_unlock(&ft_mr_lock);
	if (old)
		kfree_rcu(old, rcu);
}

/* A group's watch goes with it. Called with the group off the list. */
void ft_mr_watch_drop(struct ft_mr_group *g)
{
	struct ft_mr_watch *w = g->watch;

	if (!w)
		return;
	spin_lock_bh(&ft_mr_watch_lock);
	hlist_del_rcu(&w->node);
	ft_mr_watch_count[ft_mr_idx(g->family)]--;
	spin_unlock_bh(&ft_mr_watch_lock);
	g->watch = NULL;
	kfree_rcu(w, rcu);
}

/* Whether an nftables chain runs after the family's observer at POST_ROUTING,
 * where it could still drop, queue or steal a copy the observer has
 * confirmed. Only a hook at the last priority can follow the observer, and a
 * netfilter BPF link refuses that priority, so a hook there with a type is a
 * chain; any typed hook counts. The hooks registered with no type --
 * conntrack's confirmation, which sits at the same last priority -- are the
 * kernel's own. A registration publishes a new array, read here under RCU; an
 * unregistration may instead leave netfilter's placeholder in place, which
 * has no type either. */
static bool ft_mr_observer_followed(u8 family)
{
	const struct nf_hook_ops *mine = &ft_mr_confirm_ops[ft_mr_idx(family)];
	const struct nf_hook_entries *e;
	struct nf_hook_ops **ops;
	bool after = false, followed = false;
	unsigned int j;

	rcu_read_lock();
	if (family == AF_INET6)
		e = rcu_dereference(init_net.nf.hooks_ipv6[NF_INET_POST_ROUTING]);
	else
		e = rcu_dereference(init_net.nf.hooks_ipv4[NF_INET_POST_ROUTING]);
	if (e) {
		ops = nf_hook_entries_get_hook_ops(e);
		for (j = 0; j < e->num_hook_entries && !followed; j++) {
			if (ops[j] == mine)
				after = true;
			else if (after &&
				 ops[j]->hook_ops_type != NF_HOOK_OP_UNDEFINED)
				followed = true;
		}
	}
	rcu_read_unlock();
	return followed;
}

/* Whether a netfilter BPF program runs where the family's copies pass:
 * prerouting, forward or postrouting. Like a chain it can judge a copy by its
 * ports, and neither port walk can read it, so while one is attached every
 * group of the family stays in software. Asked of the hook lists themselves,
 * under RCU: nothing reports a link attached or released. */
static bool ft_mr_bpf_hooked(u8 family)
{
	static const u8 hooks[] = {
		NF_INET_PRE_ROUTING, NF_INET_FORWARD, NF_INET_POST_ROUTING,
	};
	const struct nf_hook_entries *e;
	struct nf_hook_ops **ops;
	bool hooked = false;
	unsigned int i, j;

	rcu_read_lock();
	for (i = 0; i < ARRAY_SIZE(hooks) && !hooked; i++) {
		if (family == AF_INET6)
			e = rcu_dereference(init_net.nf.hooks_ipv6[hooks[i]]);
		else
			e = rcu_dereference(init_net.nf.hooks_ipv4[hooks[i]]);
		if (!e)
			continue;
		ops = nf_hook_entries_get_hook_ops(e);
		for (j = 0; j < e->num_hook_entries && !hooked; j++)
			hooked = ops[j]->hook_ops_type == NF_HOOK_OP_BPF;
	}
	rcu_read_unlock();
	return hooked;
}

/* Whether the ruleset could treat two packets of a group differently, where
 * the copies that confirmed it tell nothing of the rest: 0 when it treats
 * them all alike, 1 when it may not, or negative when it could not be judged
 * (see nf_xt_port_dependent() and nft_port_dependent()); and in `why', which
 * of the two said so. x_tables first: the cheaper walk, and one that never
 * answers -EAGAIN. The stream is what the contract has made it:
 * UDP to a group address -- ipmr and ip6mr forward nothing else in hardware
 * -- arriving by the parent VIF and sent out of every oif, none of them a
 * tunnel or a register VIF. Called under RTNL, which keeps every VIF device
 * registered. */
static int ft_mr_ports_matter(const struct ft_mr_group *g,
			      const struct ft_mr_plan *plan,
			      enum ft_mr_state *why)
{
	const struct net_device *out[MAXVIFS];
	struct nft_port_probe probe = {
		.family = g->family == AF_INET6 ? NFPROTO_IPV6 : NFPROTO_IPV4,
		.saddr = g->src,
		.daddr = g->dst,
		.out = out,
	};
	int rc = 1;
	u8 i;

	ASSERT_RTNL();
	*why = FT_MR_REFUSED_PORTS;
	rcu_read_lock();
	probe.in = dev_get_by_index_rcu(&init_net, plan->parent);
	for (i = 0; i < plan->oif_count; i++) {
		out[i] = dev_get_by_index_rcu(&init_net, plan->oif[i]);
		if (!out[i])
			goto unlock;
	}
	probe.nout = plan->oif_count;
	if (!probe.in)
		goto unlock;
	rc = nf_xt_port_dependent(&init_net, &probe);
	if (rc)
		*why = FT_MR_REFUSED_XTABLES;
	else
		rc = nft_port_dependent(&init_net, &probe);
unlock:
	rcu_read_unlock();
	return rc;
}

/* ---- what tc does to a group's packets -----------------------------------
 *
 * A tc filter runs on a device, on every packet Linux forwards through it and
 * on none the classifier replicates, and what it reads -- the ports first of
 * all -- no confirmation vouches for. So a group stays in software,
 * refused-tc, while anything tc runs in software sits on the parent VIF's
 * device or a device below it, on the way in, or on an oif's or a device
 * below one, on the way out: a filter in an ingress or egress block, one on
 * any class of an egress qdisc tree, a tcx BPF program, and on the way in an
 * XDP program. Below, because a frame crosses each device of the stack. A
 * block whose filters all skip software runs nothing in software -- tc_run()
 * bypasses it on the way in, and each classifier passes over its own skip_sw
 * filters on the way out -- and counts for nothing, and so does a filter the
 * hardware applies as it is to every frame it replicates
 * (cdx_tc_filter_mirrored()).
 *
 * Nothing reports a filter added or removed, so a group already carried is
 * asked again at the refresh, every FT_MR_STATS_INTERVAL.
 */

struct ft_tc_filters {
	struct tcf_walker w;
	struct net_device *dev;
	bool ingress;
	bool soft;
};

#if IS_ENABLED(CONFIG_NET_CLS_ACT)
/* One filter of a classifier that runs in software. Its node is what the
 * classifier offloads it under: the cookie flower and matchall hand a block
 * callback. */
static int ft_tc_filter(struct tcf_proto *tp, void *node, struct tcf_walker *arg)
{
	struct ft_tc_filters *walk = container_of(arg, struct ft_tc_filters, w);

	if (cdx_tc_filter_mirrored(walk->dev, walk->ingress, (unsigned long)node))
		return 0;
	walk->soft = true;
	return -1;
}
#endif

/* Whether a filter block runs anything in software on `dev''s frames that the
 * hardware does not run as it is. Every chain and every classifier is
 * visited, to the end: each iterator holds what it returned until asked for
 * the next, and only cls_api can let go of it otherwise. */
static bool ft_tc_block_soft(struct tcf_block *block, struct net_device *dev,
			     bool ingress)
{
#if IS_ENABLED(CONFIG_NET_CLS)
	struct ft_tc_filters walk = { .dev = dev, .ingress = ingress };
	struct tcf_chain *chain;
	struct tcf_proto *tp;

	if (!block)
		return false;
#if IS_ENABLED(CONFIG_NET_CLS_ACT)
	if (!atomic_read(&block->useswcnt))
		return false;
#endif
	for (chain = tcf_get_next_chain(block, NULL); chain;
	     chain = tcf_get_next_chain(block, chain))
		for (tp = tcf_get_next_proto(chain, NULL); tp;
		     tp = tcf_get_next_proto(chain, tp)) {
			if (walk.soft)
				continue;
#if IS_ENABLED(CONFIG_NET_CLS_ACT)
			/* A classifier none of whose filters ever ran in
			 * software. Sticky the other way: once one has, the
			 * classifier counts until it is deleted. */
			if (!tp->usesw)
				continue;
			if (tp->ops->walk) {
				walk.w = (struct tcf_walker){ .fn = ft_tc_filter };
				tp->ops->walk(tp, &walk.w, true);
				continue;
			}
#endif
			walk.soft = true;
		}
	return walk.soft;
#else
	return false;
#endif
}

#if IS_ENABLED(CONFIG_NET_SCHED)
struct ft_tc_classes {
	struct qdisc_walker w;
	struct net_device *dev;
	bool soft;
};

static int ft_tc_class(struct Qdisc *q, unsigned long cl,
		       struct qdisc_walker *arg)
{
	struct ft_tc_classes *walk = container_of(arg, struct ft_tc_classes, w);

	if (!ft_tc_block_soft(q->ops->cl_ops->tcf_block(q, cl, NULL),
			      walk->dev, false))
		return 0;
	walk->soft = true;
	return -1;
}

/* An egress qdisc's own filters, and each of its classes'. */
static bool ft_qdisc_soft(struct Qdisc *q, struct net_device *dev)
{
	const struct Qdisc_class_ops *cops = q->ops->cl_ops;
	struct ft_tc_classes walk = { .dev = dev };

	if (!cops || !cops->tcf_block)
		return false;
	if (ft_tc_block_soft(cops->tcf_block(q, 0, NULL), dev, false))
		return true;
	if (cops->walk) {
		walk.w.fn = ft_tc_class;
		cops->walk(q, &walk.w);
	}
	return walk.soft;
}
#endif

/* The root qdisc and every qdisc below it but the ingress one, whose block
 * tc_run() reaches through the device's tcx entry instead. */
static bool ft_qdisc_tree_soft(struct net_device *dev)
{
#if IS_ENABLED(CONFIG_NET_SCHED)
	struct Qdisc *q = rtnl_dereference(dev->qdisc);
	unsigned int b;

	if (q && ft_qdisc_soft(q, dev))
		return true;
	hash_for_each(dev->qdisc_hash, b, q, hash)
		if (!(q->flags & TCQ_F_INGRESS) && ft_qdisc_soft(q, dev))
			return true;
#endif
	return false;
}

#if IS_ENABLED(CONFIG_NET_XGRESS)
/* The filter block of the clsact or ingress qdisc on `dev' for one direction.
 * Asked of the qdisc, because the miniq tc_run() starts from names its block
 * on the way in only: clsact never gives the egress one a block, which
 * tc_run() does without there. Under RTNL. */
static struct tcf_block *ft_tc_xgress_block(struct net_device *dev, bool ingress)
{
#if IS_ENABLED(CONFIG_NET_SCHED)
	struct netdev_queue *queue = rtnl_dereference(dev->ingress_queue);
	struct Qdisc *q = queue ? rtnl_dereference(queue->qdisc_sleeping) : NULL;
	const struct Qdisc_class_ops *cops = q ? q->ops->cl_ops : NULL;

	if (!cops || !cops->tcf_block)
		return NULL;
	return cops->tcf_block(q, TC_H_MIN(ingress ? TC_H_MIN_INGRESS : TC_H_MIN_EGRESS),
			       NULL);
#else
	return NULL;
#endif
}
#endif

/* Whether tc runs anything in software on frames `dev' receives, or sends,
 * that the hardware does not run as it is. Under RTNL. */
bool ft_dev_tc_soft(struct net_device *dev, bool ingress)
{
#if IS_ENABLED(CONFIG_NET_XGRESS)
	struct bpf_mprog_entry *entry;
	struct tcf_block *block = NULL;
	struct mini_Qdisc *miniq;

	entry = rtnl_dereference(ingress ? dev->tcx_ingress : dev->tcx_egress);
	if (entry) {
		/* A tcx BPF program, which nothing here can read. */
		if (bpf_mprog_total(entry))
			return true;
		/* The clsact or ingress qdisc's filters, which tc_run() starts
		 * on from chain 0's head: none run while it is empty. The
		 * pointer moves with that head, which an unlocked classifier
		 * changes without RTNL; the block lives as long as the qdisc,
		 * which RTNL keeps. */
		rcu_read_lock();
		miniq = rcu_dereference(tcx_entry(entry)->miniq);
		rcu_read_unlock();
		if (miniq)
			block = ft_tc_xgress_block(dev, ingress);
		if (ft_tc_block_soft(block, dev, ingress))
			return true;
	}
#endif
	if (ingress)
		return dev_xdp_prog_count(dev) > 0;
	return ft_qdisc_tree_soft(dev);
}

struct ft_tc_lowers {
	bool ingress;
	bool soft;
};

static int ft_tc_lower(struct net_device *lower, struct netdev_nested_priv *priv)
{
	struct ft_tc_lowers *walk = priv->data;

	walk->soft = ft_dev_tc_soft(lower, walk->ingress);
	return walk->soft;
}

/* `dev' and every device below it. */
bool ft_dev_stack_tc_soft(struct net_device *dev, bool ingress)
{
	struct ft_tc_lowers walk = { .ingress = ingress };
	struct netdev_nested_priv priv = { .data = &walk };

	if (ft_dev_tc_soft(dev, ingress))
		return true;
	netdev_walk_all_lower_dev(dev, ft_tc_lower, &priv);
	return walk.soft;
}

/* Whether tc runs anything in software on the group's stream where it arrives
 * or where a copy leaves; see what tc does to a group's packets. A VIF device
 * gone meanwhile is one nothing can be said of. Called under RTNL. */
static bool ft_mr_tc_filtered(const struct ft_mr_plan *plan)
{
	struct net_device *dev;
	u8 i;

	ASSERT_RTNL();
	dev = __dev_get_by_index(&init_net, plan->parent);
	if (!dev || ft_dev_stack_tc_soft(dev, true))
		return true;
	for (i = 0; i < plan->oif_count; i++) {
		dev = __dev_get_by_index(&init_net, plan->oif[i]);
		if (!dev || ft_dev_stack_tc_soft(dev, false))
			return true;
	}
	return false;
}

/* Whether a group the contract accepts may be carried now. Called by the
 * worker under RTNL, after an accepting derivation has armed its watch.
 *
 * The confirmation covers the inet hooks up to the observer. A copy routed
 * into a bridge then passes the bridge's own LOCAL_OUT and POST_ROUTING hooks
 * after it was confirmed, so any hook there keeps the group in software, as a
 * bridge hook keeps a bridged flow. A stream that arrives through a bridge
 * passes the bridge's LOCAL_IN hook on its way up to ipmr: the copies that
 * confirmed the group passed it, but a hook there may judge the rest by their
 * ports, so any hook there keeps a group whose parent VIF is on a bridge in
 * software too -- an nftables bridge chain the port walk would refuse anyway,
 * ebtables and br_netfilter nothing else reads. So does a chain that runs
 * after the observer at POST_ROUTING itself, and a netfilter BPF program at
 * any hook a copy crosses, which nothing reads. And a confirmed group is
 * carried only if the ruleset would treat every other packet of it as it did
 * the copies that confirmed it; see what Linux itself forwarded. tc, which
 * nothing confirms and no generation describes, keeps a group out whatever
 * its confirmations; see what tc does to a group's packets. */
enum ft_mr_state ft_mr_admit(struct ft_mr_group *g,
			     const struct ft_mr_plan *plan)
{
	enum ft_mr_state why;
	int rc;

	if (plan->out_bridged &&
	    ft_bridge_hooked(BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING)))
		return FT_MR_REFUSED_FILTER;
	if (plan->via && ft_bridge_hooked(BIT(NF_BR_LOCAL_IN)))
		return FT_MR_REFUSED_FILTER;
	if (ft_mr_observer_followed(g->family) || ft_mr_bpf_hooked(g->family))
		return FT_MR_REFUSED_FILTER;
	if (ft_mr_tc_filtered(plan))
		return FT_MR_REFUSED_TC;
	/* A commit since the pass began: confirmations are not good for it,
	 * and the next pass re-arms them. */
	if (!ft_mr_ruleset_current()) {
		schedule_work(&ft_mr_work);
		return FT_MR_UNCONFIRMED;
	}
	if (!g->watch || !READ_ONCE(ft_mr_gen_open) ||
	    !ft_mr_watch_complete(g->watch))
		return FT_MR_UNCONFIRMED;
	/* Last, as the costliest test and one only a confirmed group needs.
	 * Its answer is for the ruleset the confirmations were made under: a
	 * commit before or during the walk is one they are not good for
	 * either. One that has not moved the pair yet -- still being prepared,
	 * or about to publish -- leaves the next pass nothing to ask, so every
	 * group is asked again once it has had time to land; see
	 * ft_mr_probe_again. */
	rc = ft_mr_ports_matter(g, plan, &why);
	if (rc == -EAGAIN) {
		WRITE_ONCE(ft_mr_probe_again, true);
		return FT_MR_UNCONFIRMED;
	}
	if (rc < 0)
		ft_mr_port_probe_errors++;
	if (rc)
		return why;
	return FT_MR_PENDING;
}

/* A rule added under a carried group has to take it out, and nothing reports
 * a commit: while any group exists, the ruleset is looked at this often. A
 * ruleset still settling is looked at when it will have settled, which the
 * worker schedules; the worker opens it. An x_tables change is the worker's
 * to apply, at its next pass. */
static void ft_mr_ruleset_fn(struct work_struct *work)
{
	if (READ_ONCE(ft_mr_stopping))
		return;
	if (xchg(&ft_mr_probe_again, false))
		ft_mr_kick();
	if (!ft_mr_ruleset_current() || !READ_ONCE(ft_mr_gen_open) ||
	    nf_xt_seq(&init_net) != READ_ONCE(ft_mr_xt_seen))
		schedule_work(&ft_mr_work);
	if (READ_ONCE(ft_mr_count))
		schedule_delayed_work(&ft_mr_ruleset, FT_MR_RULESET_INTERVAL);
}

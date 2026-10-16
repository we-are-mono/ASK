// SPDX-License-Identifier: GPL-2.0-or-later
/* The bridged unicast learner: LAN-to-LAN switching in hardware.
 *
 * A bridge over several DPAA ports forwards a station's frames to another
 * station in software, one frame at a time, unless something installs an
 * entry for them. Nothing in Linux does: a flowtable is routed, and a bridged
 * pair crosses no route. So this learner does, the way 1.0.7's auto_bridge
 * did with CMM behind it: it watches the frames the bridge forwards, and for a
 * unicast pair between two bound ports it installs an entry in the ingress
 * port's Ethernet table (insert_l2_entry_in_classif_table()) that forwards the
 * pair's frames to the port the FDB names, untouched but for the tags the two
 * ports' VLAN membership differs in. Every IP table's miss falls through to
 * that table, so the pair's frames meet the entry and never reach the CPU.
 *
 * Three halves, as the bridged multicast learner has (ask_flowtable_mc*.c):
 *
 * - the hook, at the bridge's PRE_ROUTING, before the bridge has given an
 *   untagged frame its port's PVID -- the only place the frame's wire form is
 *   still known, and the wire form is the hardware key. It records, it never
 *   diverts, and it records each pair at most once a second;
 * - the worker, which asks the bridge itself -- under RTNL, taken without
 *   waiting -- where the pair goes, whether both ports forward and how each
 *   tags, installs, and retires what idles or what something invalidated;
 * - the events, which mark pairs dead from wherever they arrive (the FDB, a
 *   port's state, a device going away) and wake the worker to retire them.
 *
 * A pair is admitted only while no bridge-family netfilter hook other than the
 * learners' own observers is registered: an ebtables or nftables bridge chain,
 * or br_netfilter, can drop or mark a forwarded frame, and an installed entry
 * forwards where none of them runs (ft_bridge_hooked()).
 */
#include "ask_flowtable_internal.h"

static bool ft_l2_enabled = true;
module_param_named(l2_bridge, ft_l2_enabled, bool, 0444);
MODULE_PARM_DESC(l2_bridge, "Switch unicast traffic between two bound bridge ports in hardware");

/* How long a pair no frame has hit stays installed. Its FDB entries are kept
 * fresh meanwhile (ft_l2_refresh()), so this is what ages a pair out once its
 * stations stop talking. */
static unsigned int ft_l2_idle_ms = 30000;
module_param_named(l2_idle_ms, ft_l2_idle_ms, uint, 0644);
MODULE_PARM_DESC(l2_idle_ms, "Milliseconds a bridged pair no frame hits stays in hardware");
/* A pass while anything is installed or pending: idle ageing, FDB refresh and
 * the retries admission deferred for RTNL. */
#define FT_L2_PASS	HZ
/* A pass that could not have RTNL, or whose admission asked to be tried
 * again: soon, but not at once, which would spin while RTNL is held. */
#define FT_L2_RETRY	(HZ / 20)
/* How often every installed pair is asked of the bridge again: nothing
 * reports a tc filter, a netdev chain or a port flag changing under one. */
#define FT_L2_RECHECK	(5 * HZ)
/* Pairs, bounded well below what the Ethernet tables of the ports hold. */
#define FT_L2_MAX	4096
/* The most pairs one hold of the transaction visits. With FT_RETIRE_BATCH, the
 * most it unlinks before the barrier that settles them, a walk over thousands
 * of pairs goes in holds of milliseconds rather than one hold over all of
 * them, as routed retirement does (A327, A382). */
#define FT_L2_VISIT_BATCH	256U
#define FT_L2_RING	256
#define FT_L2_SEEN	256
/* How long a refused pair is left to software before it is asked again,
 * unless something it depends on changes first -- an FDB entry of either
 * station, a port, the bindings, the pair it collided with. auto_bridge
 * parked a pair CMM denied in its LINUX state until ten seconds without a
 * frame, or a change; this holds ten seconds at most (A383). */
#define FT_L2_REFUSE_HOLD	(10 * HZ)
#define FT_L2_REFUSALS	256

struct ft_l2_seen {
	int bridge_ifindex;
	int in_ifindex;
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];
	/* The frame's own EtherType inside any tag: ETH_P_IP or ETH_P_IPV6. */
	u16 ethertype;
	/* The VLAN the bridge resolves the frame to, 0 when it does not
	 * filter, and whether the frame arrived tagged with it. */
	u16 vid;
	bool tagged;
};

/* A pair's place in the index FDB events are matched through, one per
 * station: an event names one address, and walking every pair for each one
 * would cost a full walk per learned address under a MAC flood. */
struct ft_l2_station {
	struct hlist_node node;
	struct ft_l2_pair *pair;
};

struct ft_l2_pair {
	struct hlist_node node;
	struct ft_l2_station dst_station, src_station;
	struct list_head list;
	struct ft_l2_seen key;
	/* The bridge, its two ports -- what the FDB and the bridge's own
	 * events name -- and, in the rule, the physical ports beneath them,
	 * which are the same devices unless a port is a VLAN device. */
	struct net_device *bridge, *in, *out;
	struct cdx_ft_l2_rule rule;
	struct cdx_ft_hw *hw;
	u64 packets, bytes;
	unsigned long hit;	/* jiffies the counters last moved */
	/* The generation of each walk that last visited the pair
	 * (ft_l2_walk_batch()). */
	unsigned int walked[2];
	bool dead;
};

/* The walks over every pair that may let the transaction go between batches:
 * the sweep that reads counters and retires what is dead or idle, and the
 * recheck that asks the bridge again. */
enum ft_l2_walk {
	FT_L2_SWEEP,
	FT_L2_RECHECK_WALK,
};

static DEFINE_HASHTABLE(ft_l2_pairs, 10);
static DEFINE_HASHTABLE(ft_l2_stations, 10);
static LIST_HEAD(ft_l2_list);
static unsigned int ft_l2_count;
/* The ring, each pair's dead mark, and the membership of the pair list and
 * the station index: events walk them from atomic context to mark pairs, so
 * they are added to and removed from under this lock as well as the backend
 * transaction, which is what everything else that walks them holds. */
static DEFINE_SPINLOCK(ft_l2_lock);
static struct ft_l2_seen ft_l2_ring[FT_L2_RING];
static unsigned int ft_l2_head, ft_l2_tail;
/* What each CPU recorded lately, so the hook takes the lock once a second per
 * pair rather than once a frame: the software path crosses it on every frame
 * a bridge forwards. Only a cache -- a slot overwritten mid-compare by a
 * softirq on the same CPU costs a repeat record or a second's delay.
 * FT_L2_SEEN slots per CPU, allocated at init: a module's static per-CPU data
 * comes from a reserve of a few kilobytes that this alone would exceed. */
struct ft_l2_recent {
	struct ft_l2_seen seen;
	unsigned long at;
};
static struct ft_l2_recent __percpu *ft_l2_recent;
static bool ft_l2_hooked, ft_l2_stopping;
static unsigned long ft_l2_checked;
static unsigned int ft_l2_walk_gen[2];
/* A recheck that RTNL cut short resumes where it stopped. */
static bool ft_l2_rechecking;
static void ft_l2_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_l2_work, ft_l2_workfn);

/* Counters for /proc. */
static u64 ft_l2_installs, ft_l2_refused, ft_l2_retired, ft_l2_dropped, ft_l2_deferred;
/* Observations the refusal cache kept from the worker. */
static u64 ft_l2_held;

/* The pairs refused lately, one slot per hash, a later refusal taking the
 * slot of an earlier one it collides with; and a count of the events that
 * clear them, which a refusal decided across one is not cached against.
 * Under ft_l2_lock. */
static struct {
	struct ft_l2_seen seen;
	unsigned long until;
} ft_l2_refusals[FT_L2_REFUSALS];
static unsigned int ft_l2_events;
/* Slots holding a refusal, expired or not: a clear with none to clear
 * skips the walk, which every FDB event pays for. */
static unsigned int ft_l2_refusals_used;

/* By the stations and EtherType alone, so that one bucket holds the pair on
 * every port: two bridge ports that are VLAN devices of one physical port
 * share its hardware key. */
static u32 ft_l2_hash(const struct ft_l2_seen *s)
{
	return jhash(s->dst, 2 * ETH_ALEN, s->ethertype);
}

static u32 ft_l2_station_hash(const u8 *addr, u16 vid)
{
	return jhash(addr, ETH_ALEN, vid);
}

/* Two observations share one hardware key when they arrive on one bridge
 * port with one pair and one EtherType. Neither the VLAN nor the tag is in the
 * key -- its EtherType is the frame's own, inside any tag -- so a pair tagged
 * and untagged, or tagged in two VLANs, on one port is one key; and so is the
 * pair on two VLAN devices of one physical port, which admission compares by
 * the physical port it resolved. */
static bool ft_l2_same_key(const struct ft_l2_seen *a, const struct ft_l2_seen *b)
{
	return a->in_ifindex == b->in_ifindex && a->ethertype == b->ethertype &&
	       ether_addr_equal(a->dst, b->dst) && ether_addr_equal(a->src, b->src);
}

static bool ft_l2_same(const struct ft_l2_seen *a, const struct ft_l2_seen *b)
{
	return ft_l2_same_key(a, b) && a->vid == b->vid && a->tagged == b->tagged;
}

/* ------------------------------------------------------------ refusals */

/* Empty a slot. Under ft_l2_lock. */
static void ft_l2_refusal_drop(unsigned int slot)
{
	if (!ft_l2_refusals[slot].until)
		return;
	ft_l2_refusals[slot].until = 0;
	ft_l2_refusals_used--;
}

/* Whether `s` was refused within FT_L2_REFUSE_HOLD and nothing it depends on
 * has changed since; a slot found expired is emptied. Under ft_l2_lock. */
static bool ft_l2_refused_lately(const struct ft_l2_seen *s)
{
	unsigned int slot = ft_l2_hash(s) % FT_L2_REFUSALS;

	if (!ft_l2_refusals[slot].until)
		return false;
	if (!time_before(jiffies, ft_l2_refusals[slot].until)) {
		ft_l2_refusal_drop(slot);
		return false;
	}
	return ft_l2_same(&ft_l2_refusals[slot].seen, s);
}

/* Remember a refusal the worker decided, unless an event that clears
 * refusals came in while it decided: the event cleared nothing yet, and the
 * refusal may rest on what it changed. `events` is ft_l2_events as the worker
 * read it before deciding. */
static void ft_l2_refusal(const struct ft_l2_seen *s, unsigned int events)
{
	unsigned int slot = ft_l2_hash(s) % FT_L2_REFUSALS;

	spin_lock_bh(&ft_l2_lock);
	if (events == ft_l2_events) {
		if (!ft_l2_refusals[slot].until)
			ft_l2_refusals_used++;
		ft_l2_refusals[slot].seen = *s;
		ft_l2_refusals[slot].until = jiffies + FT_L2_REFUSE_HOLD ?: 1;
	}
	spin_unlock_bh(&ft_l2_lock);
}

/* Forget the refusals `addr` in `vid` is a station of, or every one when
 * addr is NULL. Under ft_l2_lock. */
static void ft_l2_refusals_clear(const u8 *addr, u16 vid)
{
	unsigned int i;

	ft_l2_events++;
	for (i = 0; i < FT_L2_REFUSALS && ft_l2_refusals_used; i++) {
		if (!ft_l2_refusals[i].until)
			continue;
		/* Expired ones go whatever they name, so that a refusal no
		 * frame asks about again does not keep the walk going. */
		if (addr && time_before(jiffies, ft_l2_refusals[i].until) &&
		    (ft_l2_refusals[i].seen.vid != vid ||
		     (!ether_addr_equal(ft_l2_refusals[i].seen.dst, addr) &&
		      !ether_addr_equal(ft_l2_refusals[i].seen.src, addr))))
			continue;
		ft_l2_refusal_drop(i);
	}
}

/* Something every refusal may rest on changed: a binding came, went or was
 * rearmed, or the datapath restarted after a backend gate refused pairs. */
void ft_l2_refusals_reset(void)
{
	spin_lock_bh(&ft_l2_lock);
	ft_l2_refusals_clear(NULL, 0);
	spin_unlock_bh(&ft_l2_lock);
}

/* ------------------------------------------------------------------ hook */

static unsigned int ft_l2_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct net_device *port = state->in, *bridge;
	struct ft_l2_recent *recent;
	struct ft_l2_seen seen = {};
	unsigned int l3_off = 0;
	__be16 proto = skb->protocol;

	if (!READ_ONCE(ft_l2_hooked) || !port || !netif_is_bridge_port(port))
		return NF_ACCEPT;
	/* Copied before anything below pulls: a pull may move the head. */
	ether_addr_copy(seen.dst, eth_hdr(skb)->h_dest);
	ether_addr_copy(seen.src, eth_hdr(skb)->h_source);
	if (!is_unicast_ether_addr(seen.dst) || !is_valid_ether_addr(seen.src))
		return NF_ACCEPT;
	bridge = netdev_master_upper_dev_get_rcu(port);
	/* The router's own traffic, routed rather than bridged: the bulk of
	 * what crosses a LAN bridge, and never a pair. A promiscuous bridge
	 * hands every frame it forwards up as well -- to a capture, or to an
	 * upper device with an address of its own -- and an entry would take
	 * that copy away. */
	if (!bridge || ether_addr_equal(seen.dst, bridge->dev_addr) ||
	    (READ_ONCE(bridge->flags) & IFF_PROMISC))
		return NF_ACCEPT;
	if (skb_vlan_tag_present(skb)) {
		/* An 802.1ad tag is no tag to an 802.1Q bridge, which is the
		 * only kind admission takes. */
		if (skb->vlan_proto != htons(ETH_P_8021Q))
			return NF_ACCEPT;
		seen.tagged = true;
		seen.vid = skb_vlan_tag_get_id(skb);
	} else if (proto == htons(ETH_P_8021Q)) {
		const struct vlan_hdr *vhdr;

		if (!pskb_may_pull(skb, VLAN_HLEN))
			return NF_ACCEPT;
		vhdr = (const struct vlan_hdr *)skb->data;
		seen.tagged = true;
		seen.vid = ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
		proto = vhdr->h_vlan_encapsulated_proto;
		l3_off = VLAN_HLEN;
	}
	/* A tagged frame on a bridge that does not filter is forwarded with
	 * its tag as payload, and a priority tag (VID 0) is the port's PVID to
	 * one that does, with the tag's priority kept; the learner leaves both
	 * to software. */
	if (seen.tagged && (!br_vlan_enabled(bridge) || !seen.vid))
		return NF_ACCEPT;
	if (!seen.tagged && br_vlan_enabled(bridge) && br_vlan_get_pvid_rcu(port, &seen.vid))
		return NF_ACCEPT;
	/* The parser ends the parse of a frame whose TTL or hop limit is 0 or
	 * 1 before any table is consulted, so no entry would ever match one. */
	if (proto == htons(ETH_P_IP)) {
		const struct iphdr *iph;

		if (!pskb_may_pull(skb, l3_off + sizeof(*iph)))
			return NF_ACCEPT;
		iph = (const struct iphdr *)(skb->data + l3_off);
		if (iph->ttl <= 1)
			return NF_ACCEPT;
		seen.ethertype = ETH_P_IP;
	} else if (proto == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6h;

		if (!pskb_may_pull(skb, l3_off + sizeof(*ip6h)))
			return NF_ACCEPT;
		ip6h = (const struct ipv6hdr *)(skb->data + l3_off);
		if (ip6h->hop_limit <= 1)
			return NF_ACCEPT;
		seen.ethertype = ETH_P_IPV6;
	} else {
		return NF_ACCEPT;
	}
	seen.bridge_ifindex = bridge->ifindex;
	seen.in_ifindex = port->ifindex;

	/* At most once a second per pair and CPU: a stream at line rate
	 * would otherwise fill the ring with restatements of one fact. */
	recent = get_cpu_ptr(ft_l2_recent) + ft_l2_hash(&seen) % FT_L2_SEEN;
	if (ft_l2_same(&recent->seen, &seen) &&
	    time_before(jiffies, recent->at + FT_L2_PASS)) {
		put_cpu_ptr(ft_l2_recent);
		return NF_ACCEPT;
	}
	recent->seen = seen;
	recent->at = jiffies;
	put_cpu_ptr(ft_l2_recent);
	spin_lock_bh(&ft_l2_lock);
	if (ft_l2_refused_lately(&seen)) {
		ft_l2_held++;
		spin_unlock_bh(&ft_l2_lock);
		return NF_ACCEPT;
	}
	if (ft_l2_head - ft_l2_tail < FT_L2_RING) {
		ft_l2_ring[ft_l2_head++ % FT_L2_RING] = seen;
	} else {
		ft_l2_dropped++;
	}
	spin_unlock_bh(&ft_l2_lock);
	if (!READ_ONCE(ft_l2_stopping))
		mod_delayed_work(system_wq, &ft_l2_work, 0);
	return NF_ACCEPT;	/* always: this observes, it never diverts */
}

static struct nf_hook_ops ft_l2_hook_ops = {
	.hook = ft_l2_hook,
	.pf = NFPROTO_BRIDGE,
	.hooknum = NF_BR_PRE_ROUTING,
	/* Last, as the multicast learner's: what a later bridge rule would
	 * drop is never learned. */
	.priority = NF_BR_PRI_LAST,
};

bool ft_l2_hook_is(const struct nf_hook_ops *ops)
{
	return ops == &ft_l2_hook_ops;
}

/* --------------------------------------------------------------- admission */

static bool ft_l2_bound(const struct net_device *dev)
{
	struct cdx_ft_binding *binding;

	list_for_each_entry(binding, &ft_bindings, list)
		if (binding->dev == dev && !binding->parked)
			return true;
	return false;
}

/* Whether netfilter runs a chain on what `dev` sends, at its netdev egress
 * hook. The ingress question is ft_dev_nf_ingress_hooked()'s. */
static bool ft_l2_nf_egress_hooked(const struct net_device *dev)
{
#if IS_ENABLED(CONFIG_NETFILTER_EGRESS)
	const struct nf_hook_entries *e;
	bool hooked;

	rcu_read_lock();
	e = rcu_dereference(dev->nf_hooks_egress);
	hooked = e && e->num_hook_entries;
	rcu_read_unlock();
	return hooked;
#else
	return false;
#endif
}

/* Down from a bridge port to the physical port it rides on: the port itself,
 * or through 802.1Q VLAN devices only, whose tags are appended to `tags`
 * outermost first. NULL for any other device, or more tags than a direction
 * carries. Under RTNL. */
static struct net_device *ft_l2_lower(struct net_device *port, struct cdx_ft_vlan *tags,
				      u8 *count)
{
	struct cdx_ft_vlan found[CDX_FT_VLAN_MAX];
	unsigned int n = 0, i;

	while (is_vlan_dev(port)) {
		if (n == CDX_FT_VLAN_MAX || vlan_dev_vlan_proto(port) != htons(ETH_P_8021Q))
			return NULL;
		found[n].proto = htons(ETH_P_8021Q);
		found[n].id = vlan_dev_vlan_id(port);
		found[n].ifindex = port->ifindex;
		n++;
		port = vlan_dev_priv(port)->real_dev;
	}
	if (*count + n > CDX_FT_VLAN_MAX)
		return NULL;
	/* Found innermost first; the wire has the lowest device's outermost. */
	for (i = 0; i < n; i++)
		tags[(*count)++] = found[n - 1 - i];
	return port;
}

/* Whether a netdev chain runs on any VLAN device of a port's stack, on the
 * way in or out: every one of them sees the frame in software. */
static bool ft_l2_stack_hooked(const struct cdx_ft_vlan *tags, u8 count, bool ingress)
{
	struct net_device *dev;
	u8 i;

	for (i = 0; i < count; i++) {
		dev = tags[i].ifindex ? __dev_get_by_index(&init_net, tags[i].ifindex) : NULL;
		if (dev && (ingress ? ft_dev_nf_ingress_hooked(dev) : ft_l2_nf_egress_hooked(dev)))
			return true;
	}
	return false;
}

/* How the bridge carries `vid` through `port`: whether the port is a member
 * and whether it sends the VLAN untagged. A bridge that does not filter
 * carries everything untagged. Under RTNL. */
static bool ft_l2_member(struct net_device *bridge, struct net_device *port, u16 vid,
			 bool *untagged)
{
	struct bridge_vlan_info info;

	if (!br_vlan_enabled(bridge)) {
		*untagged = true;
		return true;
	}
	if (br_vlan_get_info(port, vid, &info))
		return false;
	*untagged = !!(info.flags & BRIDGE_VLAN_INFO_UNTAGGED);
	return true;
}

/* Everything the bridge would decide about one frame of the pair, asked of
 * the bridge, under RTNL: both ports this bridge's and bound, both
 * forwarding in the VLAN, the destination learned on another port and the
 * source on the ingress, how each port tags, and an egress that carries what
 * the ingress can deliver. Fills the rule; false leaves the pair to software. */
static bool ft_l2_resolve(const struct ft_l2_seen *s, struct ft_l2_pair *p)
{
	struct net_device *bridge, *in, *out, *lower_in, *lower_out;
	bool in_untagged, out_untagged;
	u16 proto, pvid;

	bridge = __dev_get_by_index(&init_net, s->bridge_ifindex);
	in = __dev_get_by_index(&init_net, s->in_ifindex);
	if (!bridge || !in || !netif_is_bridge_master(bridge) ||
	    netdev_master_upper_dev_get(in) != bridge || br_mst_enabled(bridge) ||
	    (bridge->flags & IFF_PROMISC))
		return false;
	/* The VLAN the observation names has to be the one the bridge puts the
	 * frame in now, not when the frame was seen: a PVID changed since, or
	 * filtering switched off or on, would otherwise install the pair in a
	 * VLAN the bridge no longer forwards it in -- and the FDB entries in
	 * the old one can outlive the change. */
	if (br_vlan_enabled(bridge)) {
		if (br_vlan_get_proto(bridge, &proto) || proto != ETH_P_8021Q || !s->vid)
			return false;
		if (!s->tagged && (br_vlan_get_pvid(in, &pvid) || pvid != s->vid))
			return false;
	} else if (s->tagged || s->vid) {
		return false;
	}
	/* Learned entries only: a frame for the bridge's or a port's own
	 * address is the router's, and is never bridged. */
	out = br_fdb_forward_port(bridge, s->dst, s->vid);
	if (!out || out == in || br_fdb_forward_port(bridge, s->src, s->vid) != in)
		return false;
	memset(&p->rule, 0, sizeof(p->rule));
	/* The tags of a port that is a VLAN device are outermost on the wire,
	 * outside any the bridge adds. */
	lower_in = ft_l2_lower(in, p->rule.in_vlan, &p->rule.in_vlans);
	lower_out = ft_l2_lower(out, p->rule.out_vlan, &p->rule.out_vlans);
	if (!lower_in || !lower_out || lower_in == lower_out ||
	    !ft_l2_bound(lower_in) || !ft_l2_bound(lower_out) ||
	    !cdx_ft_port_supported(lower_in) || !cdx_ft_port_supported(lower_out))
		return false;
	/* Port to port: the bridge's own VLAN entry plays no part. */
	if (!br_port_bridging(in, s->vid) || !br_port_bridging(out, s->vid))
		return false;
	/* Two isolated ports never forward to each other; a locked or MAB
	 * port admits a source only as 802.1X decides, frame by frame; a VLAN
	 * tunnel port hands tunnel metadata to the egress. */
	if ((br_port_flag_is_set(in, BR_ISOLATED) && br_port_flag_is_set(out, BR_ISOLATED)) ||
	    br_port_flag_is_set(in, BR_PORT_LOCKED) || br_port_flag_is_set(in, BR_PORT_MAB) ||
	    br_port_flag_is_set(in, BR_VLAN_TUNNEL) || br_port_flag_is_set(out, BR_VLAN_TUNNEL))
		return false;
	/* What tc or a netdev chain runs on either port runs on every frame the
	 * bridge forwards in software and on none an entry forwards. */
	if (ft_dev_stack_tc_soft(in, true) || ft_dev_stack_tc_soft(out, false) ||
	    ft_dev_nf_ingress_hooked(lower_in) || ft_l2_nf_egress_hooked(lower_out) ||
	    ft_l2_stack_hooked(p->rule.in_vlan, p->rule.in_vlans, true) ||
	    ft_l2_stack_hooked(p->rule.out_vlan, p->rule.out_vlans, false))
		return false;
	if (!ft_l2_member(bridge, in, s->vid, &in_untagged) ||
	    !ft_l2_member(bridge, out, s->vid, &out_untagged))
		return false;
	/* A frame the bridge would send bigger than the egress carries is one
	 * it drops; the hardware would fragment it instead. What can arrive is
	 * what the physical port's MAC accepts, whatever a VLAN device on it
	 * says; what leaves is bounded by the bridge's port, which a VLAN
	 * device on the physical one may set lower. */
	if (out->mtu < ft_port_arriving(lower_in))
		return false;
	p->rule.in = lower_in;
	p->rule.out = lower_out;
	ether_addr_copy(p->rule.dst_mac, s->dst);
	ether_addr_copy(p->rule.src_mac, s->src);
	p->rule.ethertype = s->ethertype;
	p->rule.mtu = out->mtu;
	p->rule.qos = ft_qos_class(0);
	/* The bridge's own tag is innermost. A frame tagged on the wire and
	 * leaving tagged in the same VLAN is still stripped and tagged again:
	 * the strip is what checks the VID, which the key does not carry, and
	 * without it the pair's frames in any other VLAN of the port would
	 * leave in theirs. */
	if (s->tagged) {
		if (p->rule.in_vlans == CDX_FT_VLAN_MAX)
			return false;
		p->rule.in_vlan[p->rule.in_vlans].proto = htons(ETH_P_8021Q);
		p->rule.in_vlan[p->rule.in_vlans++].id = s->vid;
	}
	if (br_vlan_enabled(bridge) && !out_untagged) {
		if (p->rule.out_vlans == CDX_FT_VLAN_MAX)
			return false;
		p->rule.out_vlan[p->rule.out_vlans].proto = htons(ETH_P_8021Q);
		p->rule.out_vlan[p->rule.out_vlans++].id = s->vid;
	}
	p->bridge = bridge;
	p->in = in;
	p->out = out;
	return true;
}

/* Out of the hardware and every list, its devices let go. Under the
 * transaction. */
static void ft_l2_release(struct ft_l2_pair *p)
{
	if (cdx_ft_unlink(&p->hw))
		ft_invalidate();
	spin_lock_bh(&ft_l2_lock);
	hash_del(&p->node);
	hash_del(&p->dst_station.node);
	hash_del(&p->src_station.node);
	list_del(&p->list);
	spin_unlock_bh(&ft_l2_lock);
	dev_put(p->bridge);
	dev_put(p->in);
	dev_put(p->out);
	dev_put(p->rule.in);
	dev_put(p->rule.out);
	kfree(p);
	ft_l2_count--;
}

static void ft_l2_unlink(struct ft_l2_pair *p)
{
	unsigned int slot = ft_l2_hash(&p->key) % FT_L2_REFUSALS;
	bool full = ft_l2_count == FT_L2_MAX;

	ft_l2_release(p);
	ft_l2_retired++;
	/* A pair refused for colliding with this one -- the same stations
	 * in another form, or through another VLAN device of the port --
	 * shares its slot; one refused for want of room may go in now. No
	 * event count: admission, the only other writer of a refusal, runs
	 * under the same transaction. */
	spin_lock_bh(&ft_l2_lock);
	if (full) {
		for (slot = 0; slot < FT_L2_REFUSALS; slot++)
			ft_l2_refusal_drop(slot);
	} else {
		ft_l2_refusal_drop(slot);
	}
	spin_unlock_bh(&ft_l2_lock);
}

/* One observation, under the transaction and RTNL. -EAGAIN: try again later.
 *
 * The pair is published -- where an FDB event or a device's can mark it --
 * before the bridge is asked the last time and before anything is built, so
 * that nothing the bridge does between the answer and the entry goes unseen:
 * a change before publication shows in the second answer, one after it marks
 * the pair, which the next pass retires. */
static int ft_l2_admit(const struct ft_l2_seen *s)
{
	struct ft_l2_pair *p, *other;
	unsigned int events;
	s64 changes;
	int rc;

	spin_lock_bh(&ft_l2_lock);
	/* Another CPU's observation of a pair this pass already refused. */
	if (ft_l2_refused_lately(s)) {
		ft_l2_held++;
		spin_unlock_bh(&ft_l2_lock);
		return 0;
	}
	events = ft_l2_events;
	spin_unlock_bh(&ft_l2_lock);
	hash_for_each_possible(ft_l2_pairs, p, node, ft_l2_hash(s)) {
		if (!ft_l2_same_key(&p->key, s))
			continue;
		/* The pair itself, or the same pair in another wire form or
		 * VLAN of the port, which would need the one key twice:
		 * software. */
		if (!ft_l2_same(&p->key, s)) {
			ft_l2_refused++;
			ft_l2_refusal(s, events);
		}
		return 0;
	}
	if (ft_l2_count >= FT_L2_MAX) {
		ft_l2_refusal(s, events);
		return -ENOSPC;
	}
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->key = *s;
	if (!ft_l2_resolve(s, p)) {
		kfree(p);
		ft_l2_refused++;
		ft_l2_refusal(s, events);
		return 0;
	}
	/* The same stations from another VLAN device of the physical port
	 * would need its key twice. */
	hash_for_each_possible(ft_l2_pairs, other, node, ft_l2_hash(s)) {
		if (other->rule.in == p->rule.in && other->key.ethertype == s->ethertype &&
		    ether_addr_equal(other->key.dst, s->dst) &&
		    ether_addr_equal(other->key.src, s->src)) {
			kfree(p);
			ft_l2_refused++;
			ft_l2_refusal(s, events);
			return 0;
		}
	}
	dev_hold(p->bridge);
	dev_hold(p->in);
	dev_hold(p->out);
	dev_hold(p->rule.in);
	dev_hold(p->rule.out);
	p->hit = jiffies;
	/* Fresh: no walk in progress needs to visit it. */
	p->walked[FT_L2_SWEEP] = ft_l2_walk_gen[FT_L2_SWEEP];
	p->walked[FT_L2_RECHECK_WALK] = ft_l2_walk_gen[FT_L2_RECHECK_WALK];
	p->dst_station.pair = p->src_station.pair = p;
	spin_lock_bh(&ft_l2_lock);
	hash_add(ft_l2_pairs, &p->node, ft_l2_hash(s));
	hash_add(ft_l2_stations, &p->dst_station.node, ft_l2_station_hash(s->dst, s->vid));
	hash_add(ft_l2_stations, &p->src_station.node, ft_l2_station_hash(s->src, s->vid));
	list_add_tail(&p->list, &ft_l2_list);
	spin_unlock_bh(&ft_l2_lock);
	ft_l2_count++;
	if (br_fdb_forward_port(p->bridge, s->dst, s->vid) != p->out ||
	    br_fdb_forward_port(p->bridge, s->src, s->vid) != p->in) {
		ft_l2_release(p);
		ft_l2_refused++;
		return 0;
	}
	/* Before anything is built: an egress change counted after this is
	 * one the entry may predate (ft_egress_changes). */
	changes = atomic64_read_acquire(&ft_egress_changes);
	rc = cdx_ft_l2_add(&p->rule, &p->hw);
	if (!rc && atomic64_read(&ft_egress_changes) != changes)
		rc = -EAGAIN;
	if (rc) {
		ft_l2_release(p);
		ft_l2_refused++;
		if (rc == -EAGAIN)
			return -EAGAIN;
		/* The backend's refusal holds as one of the bridge's does: a
		 * full table, a port it will not program, or a gate it shuts
		 * while the datapath restarts, whose end clears it
		 * (ft_egress_restarted()). */
		ft_l2_refusal(s, events);
		return 0;
	}
	ft_l2_installs++;
	return 0;
}

/* ---------------------------------------------------------------- worker */

/* Whether the bridge would still carry an installed pair as it is installed.
 * Under the transaction and RTNL. */
static bool ft_l2_current(const struct ft_l2_pair *p)
{
	struct ft_l2_pair now;

	return ft_l2_resolve(&p->key, &now) && now.in == p->in && now.out == p->out &&
	       !memcmp(&now.rule, &p->rule, sizeof(now.rule));
}

/* Keep the source station's FDB entry from ageing out while the hardware
 * carries what it sends: those frames never reach the bridge to refresh it,
 * and an entry that ages out retires the pair (ft_l2_fdb_event()) only for the
 * next frame to learn it again. Only the source's, as the bridge itself
 * refreshes only from what a station sends: the destination's is the reverse
 * pair's to keep, and a station that went silent is the bridge's to age and
 * flood for. */
static void ft_l2_refresh(struct ft_l2_pair *p)
{
	br_fdb_refresh(p->bridge, p->key.src, p->key.vid, p->in);
}

/* One batch of a walk over every pair: the pairs this generation of the walk
 * has not visited, up to FT_L2_VISIT_BATCH of them or FT_RETIRE_BATCH unlinks,
 * each unlinked where `visit` says so, and what was unlinked settled. Each
 * visited pair is stamped with the generation, so the walk holds no pointer
 * across the transaction its caller lets go between batches, and a pair
 * admitted meanwhile, stamped as it is published, waits for the next walk.
 * True once every pair has been visited. Under the transaction. */
static bool ft_l2_walk_batch(enum ft_l2_walk walk,
			     bool (*visit)(struct ft_l2_pair *p, const void *arg), const void *arg)
{
	struct ft_l2_pair *p, *next;
	unsigned int visited = 0, unlinked = 0;
	bool done = true;

	cdx_ft_assert_held();
	list_for_each_entry_safe(p, next, &ft_l2_list, list) {
		if (p->walked[walk] == ft_l2_walk_gen[walk])
			continue;
		if (visited == FT_L2_VISIT_BATCH || unlinked == FT_RETIRE_BATCH) {
			done = false;
			break;
		}
		p->walked[walk] = ft_l2_walk_gen[walk];
		visited++;
		if (visit(p, arg)) {
			ft_l2_unlink(p);
			unlinked++;
		}
	}
	ft_settle();
	return done;
}

/* Up to FT_RETIRE_BATCH of the pairs `match` names out of the hardware and
 * settled. True when some remain: the caller lets the transaction go before
 * asking again, as for ft_retire_batch(). Under the transaction. */
static bool ft_l2_retire_batch_of(bool (*match)(const struct ft_l2_pair *p, const void *arg),
				  const void *arg, int *settled)
{
	struct ft_l2_pair *p, *next;
	unsigned int n = 0;
	bool more = false;
	int rc;

	cdx_ft_assert_held();
	list_for_each_entry_safe(p, next, &ft_l2_list, list) {
		if (!match(p, arg))
			continue;
		if (n == FT_RETIRE_BATCH) {
			more = true;
			break;
		}
		ft_l2_unlink(p);
		n++;
	}
	rc = ft_settle();
	if (settled && rc)
		*settled = rc;
	return more;
}

/* Let the transaction go between two batches of a walk, and take it back. */
static void ft_l2_yield(void)
{
	cdx_ft_end();
	cond_resched();
	cdx_ft_begin();
}

struct ft_l2_sweeping {
	bool filtered;
};

/* Dead, idle, or under a bridge filter: out of hardware. Otherwise the
 * pair's counters are read, and a pair they moved for keeps its source
 * station's FDB entry fresh. */
static bool ft_l2_sweep_one(struct ft_l2_pair *p, const void *arg)
{
	const struct ft_l2_sweeping *sweep = arg;
	struct cdx_ft_counters c = {};
	bool dead;

	spin_lock_bh(&ft_l2_lock);
	dead = p->dead;
	spin_unlock_bh(&ft_l2_lock);
	if (dead || sweep->filtered || READ_ONCE(ft_l2_stopping) || atomic_read(&ft_invalid))
		return true;
	cdx_ft_stats(p->hw, &c);
	if (c.packets != p->packets) {
		p->packets = c.packets;
		p->bytes = c.bytes;
		p->hit = jiffies;
		ft_l2_refresh(p);
	}
	return !time_before(jiffies, p->hit + msecs_to_jiffies(READ_ONCE(ft_l2_idle_ms)));
}

static bool ft_l2_filtered(void)
{
	return ft_bridge_hooked(BIT(NF_BR_PRE_ROUTING) | BIT(NF_BR_FORWARD) |
				BIT(NF_BR_POST_ROUTING));
}

/* Whether a pair may be admitted now. Asked in the hold of the transaction
 * the admission runs in: a walk that let it go meanwhile may have seen it
 * latched by an invalidation, a filter appear, or unload begin. */
static bool ft_l2_live(void)
{
	return !ft_l2_filtered() && !READ_ONCE(ft_l2_stopping) && !atomic_read(&ft_invalid) &&
	       READ_ONCE(ft_l2_enabled);
}

/* Every pair visited once, a batch per hold of the transaction. Called and
 * returning with it held. */
static void ft_l2_sweep(void)
{
	struct ft_l2_sweeping sweep;

	ft_l2_walk_gen[FT_L2_SWEEP]++;
	for (;;) {
		sweep.filtered = ft_l2_filtered();
		if (ft_l2_walk_batch(FT_L2_SWEEP, ft_l2_sweep_one, &sweep))
			return;
		ft_l2_yield();
	}
}

static bool ft_l2_recheck_one(struct ft_l2_pair *p, const void *arg)
{
	return !ft_l2_current(p);
}

/* Every installed pair asked of the bridge again, a batch per hold of the
 * transaction and of RTNL, which is taken without waiting: a batch that
 * cannot have it leaves the rest of the walk to the next pass, which
 * resumes it rather than starting over. Called and returning with the
 * transaction held and RTNL not. */
static void ft_l2_recheck(void)
{
	bool done;

	for (;;) {
		if (cdx_ft_admission_begin())
			return;
		/* A walk starts with the first batch that has RTNL: one that
		 * never could stays due at the ordinary pass, rather than
		 * retrying at FT_L2_RETRY with a sweep each time. */
		if (!ft_l2_rechecking) {
			ft_l2_walk_gen[FT_L2_RECHECK_WALK]++;
			ft_l2_rechecking = true;
		}
		done = ft_l2_walk_batch(FT_L2_RECHECK_WALK, ft_l2_recheck_one, NULL);
		cdx_ft_admission_end();
		if (done) {
			ft_l2_rechecking = false;
			ft_l2_checked = jiffies;
			return;
		}
		ft_l2_yield();
	}
}

static void ft_l2_workfn(struct work_struct *work)
{
	struct ft_l2_seen batch[32];
	unsigned int n = 0, i, retry = 0;
	bool rtnl = false, again, live;

	spin_lock_bh(&ft_l2_lock);
	while (ft_l2_tail != ft_l2_head && n < ARRAY_SIZE(batch))
		batch[n++] = ft_l2_ring[ft_l2_tail++ % FT_L2_RING];
	again = ft_l2_tail != ft_l2_head;
	spin_unlock_bh(&ft_l2_lock);

	cdx_ft_begin();
	ft_l2_sweep();
	live = ft_l2_live();
	/* A recheck cut short with nothing left to check, or nothing it may
	 * keep, is abandoned: the next starts afresh when due. */
	if (!live || list_empty(&ft_l2_list))
		ft_l2_rechecking = false;
	if (live && !list_empty(&ft_l2_list) &&
	    (ft_l2_rechecking || time_after_eq(jiffies, ft_l2_checked + FT_L2_RECHECK)))
		ft_l2_recheck();
	/* Asked again: the recheck may have let the transaction go. */
	if (n && ft_l2_live()) {
		rtnl = !cdx_ft_admission_begin();
		for (i = 0; i < n; i++) {
			if (rtnl && ft_l2_admit(&batch[i]) != -EAGAIN)
				continue;
			/* Back in the ring for the next pass: admission takes
			 * RTNL without waiting, and nothing else re-offers a
			 * pair the way a packet re-offers a flow. */
			spin_lock_bh(&ft_l2_lock);
			if (ft_l2_head - ft_l2_tail < FT_L2_RING)
				ft_l2_ring[ft_l2_head++ % FT_L2_RING] = batch[i];
			spin_unlock_bh(&ft_l2_lock);
			ft_l2_deferred++;
			retry++;
		}
		if (rtnl)
			cdx_ft_admission_end();
	}
	ft_settle();
	cdx_ft_end();
	if (READ_ONCE(ft_l2_stopping))
		return;
	if (again || retry || ft_l2_rechecking)
		mod_delayed_work(system_wq, &ft_l2_work, rtnl && !retry ? 0 : FT_L2_RETRY);
	else if (!list_empty(&ft_l2_list))
		mod_delayed_work(system_wq, &ft_l2_work, FT_L2_PASS);
}

/* ---------------------------------------------------------------- events */

static void ft_l2_mark(bool (*match)(const struct ft_l2_pair *p, const void *arg),
		       const void *arg)
{
	struct ft_l2_pair *p;
	bool any = false;

	spin_lock_bh(&ft_l2_lock);
	/* Whatever changed a device may have been what a refusal rested on. */
	ft_l2_refusals_clear(NULL, 0);
	list_for_each_entry(p, &ft_l2_list, list) {
		if (!p->dead && match(p, arg)) {
			p->dead = true;
			any = true;
		}
	}
	spin_unlock_bh(&ft_l2_lock);
	if (any && !READ_ONCE(ft_l2_stopping))
		mod_delayed_work(system_wq, &ft_l2_work, 0);
}

/* An FDB entry for either station of a pair moved, aged out or was deleted:
 * the bridge would now forward the pair elsewhere, or flood it. A refresh
 * raises no event, so the learner's own keep-alive costs nothing here. From
 * the switchdev chain, atomic. */
void ft_l2_fdb_event(unsigned long event, const u8 *addr, u16 vid,
		     const struct net_device *port)
{
	struct ft_l2_station *station;
	struct ft_l2_pair *p;
	bool any = false, dst;

	/* Nothing installed and nothing refused while the hook is off, but
	 * for an unload's last moments, which retire everything anyway. */
	if (!READ_ONCE(ft_l2_hooked))
		return;
	spin_lock_bh(&ft_l2_lock);
	/* A station learned, moved or gone may be what a refusal rested on:
	 * the destination not yet learned is the commonest. */
	ft_l2_refusals_clear(addr, vid);
	hash_for_each_possible(ft_l2_stations, station, node, ft_l2_station_hash(addr, vid)) {
		p = station->pair;
		dst = station == &p->dst_station;
		if (p->dead || p->key.vid != vid ||
		    !ether_addr_equal(dst ? p->key.dst : p->key.src, addr))
			continue;
		/* An add naming the port the pair already uses for the
		 * station restates it rather than moving it. */
		if (event == SWITCHDEV_FDB_ADD_TO_DEVICE && port == (dst ? p->out : p->in))
			continue;
		p->dead = true;
		any = true;
	}
	spin_unlock_bh(&ft_l2_lock);
	if (any && !READ_ONCE(ft_l2_stopping))
		mod_delayed_work(system_wq, &ft_l2_work, 0);
}

static bool ft_l2_names_dev(const struct ft_l2_pair *p, const void *arg)
{
	const struct net_device *dev = arg;
	u8 i;

	if (p->bridge == dev || p->in == dev || p->out == dev ||
	    p->rule.in == dev || p->rule.out == dev)
		return true;
	/* A VLAN device between a port and its physical port. */
	for (i = 0; i < p->rule.in_vlans; i++)
		if (p->rule.in_vlan[i].ifindex == dev->ifindex)
			return true;
	for (i = 0; i < p->rule.out_vlans; i++)
		if (p->rule.out_vlan[i].ifindex == dev->ifindex)
			return true;
	return false;
}

/* A port's or the bridge's state, VLAN membership, filtering, MTU, link or
 * membership changed: every pair crossing it is asked of the bridge again. */
void ft_l2_dev_changed(const struct net_device *dev)
{
	ft_l2_mark(ft_l2_names_dev, dev);
}

/* CDX is about to hand a port's queues, or the DSCP map, to something else
 * (ft_egress_drain()): every pair through the port goes now, rather than
 * when the worker gets to the mark ft_egress_changed() left -- an entry still
 * enqueuing by the old plan would transmit on the new owner's queues. A pair
 * admitted from here on reads the new plan; one built across the change
 * found ft_egress_changes moved and was taken out again. Takes the
 * transaction. */
static bool ft_l2_on_port(const struct ft_l2_pair *p, const void *dev)
{
	return p->rule.in == dev || p->rule.out == dev;
}

int ft_l2_egress_drain(const struct net_device *dev)
{
	int rc = 0;

	cdx_ft_begin();
	/* A barrier that failed in any batch fails the drain, as it would
	 * have failed the one walk this was. */
	while (ft_l2_retire_batch_of(ft_l2_on_port, dev, &rc))
		ft_l2_yield();
	cdx_ft_end();
	return rc;
}

static bool ft_l2_any(const struct ft_l2_pair *p, const void *arg)
{
	return true;
}

/* Global invalidation, from its worker, and unload: everything goes, and the
 * next frames learn it again once admission is rearmed. One batch, under the
 * transaction; true while pairs remain, and the caller lets the transaction go
 * before asking again (A382). */
bool ft_l2_retire_batch(void)
{
	return ft_l2_retire_batch_of(ft_l2_any, NULL, NULL);
}

/* -------------------------------------------------------------------- proc */

/* A tag stack outermost first, dot separated, "-" for none. */
static void ft_l2_tags(const struct cdx_ft_vlan *tags, u8 count, char *text, size_t size)
{
	unsigned int at = 0;
	u8 i;

	if (!count) {
		strscpy(text, "-", size);
		return;
	}
	for (i = 0; i < count && at < size; i++)
		at += scnprintf(text + at, size - at, "%s%u", i ? "." : "", tags[i].id);
}

/* The totals, in the header of /proc/cdx_flowtable. */
void ft_l2_show(struct seq_file *seq)
{
	seq_printf(seq, "l2_enabled %u\nl2_entries %u\nl2_installs %llu\nl2_refused %llu\n"
		   "l2_held %llu\nl2_retired %llu\nl2_dropped %llu\nl2_deferred %llu\n",
		   READ_ONCE(ft_l2_enabled) && READ_ONCE(ft_l2_hooked), ft_l2_count,
		   ft_l2_installs, ft_l2_refused, READ_ONCE(ft_l2_held), ft_l2_retired,
		   ft_l2_dropped, ft_l2_deferred);
}

/* The rows, one seq_file record each, after the flows' (main.c's
 * ft_position()): a read holds the transaction for one buffer of them, never
 * for all (A382). Addressed as the flows are, by hash bucket and offset in it,
 * so no pair pointer survives the transaction between reads. */
unsigned int ft_l2_row_buckets(void)
{
	return HASH_SIZE(ft_l2_pairs);
}

struct list_head *ft_l2_row(unsigned int bucket, unsigned int *skip)
{
	struct ft_l2_pair *p;

	hlist_for_each_entry(p, &ft_l2_pairs[bucket], node) {
		if (*skip) {
			(*skip)--;
			continue;
		}
		return &p->list;
	}
	return NULL;
}

struct list_head *ft_l2_row_next(struct list_head *row)
{
	struct ft_l2_pair *p = list_entry(row, struct ft_l2_pair, list);

	if (!p->node.next)
		return NULL;
	return &hlist_entry(p->node.next, struct ft_l2_pair, node)->list;
}

/* in and out are the bridge's ports, port_in and port_out the physical ports
 * beneath them; in_vlan is the stack each frame arrives with and the entry
 * checks and strips, out_vlan the one it leaves with. */
void ft_l2_show_row(struct seq_file *seq, struct list_head *row)
{
	struct ft_l2_pair *p = list_entry(row, struct ft_l2_pair, list);
	char in_vlan[16], out_vlan[16];

	ft_l2_tags(p->rule.in_vlan, p->rule.in_vlans, in_vlan, sizeof(in_vlan));
	ft_l2_tags(p->rule.out_vlan, p->rule.out_vlans, out_vlan, sizeof(out_vlan));
	seq_printf(seq, "l2flow in=%s out=%s port_in=%s port_out=%s br=%s dst=%pM src=%pM type=%#06x vid=%u tagged=%u in_vlan=%s out_vlan=%s packets=%llu bytes=%llu\n",
		   netdev_name(p->in), netdev_name(p->out), netdev_name(p->rule.in),
		   netdev_name(p->rule.out), netdev_name(p->bridge),
		   p->key.dst, p->key.src, p->key.ethertype, p->key.vid, p->key.tagged,
		   in_vlan, out_vlan, p->packets, p->bytes);
}

/* --------------------------------------------------------- start and stop */

int ft_l2_init(void)
{
	int rc;

	if (!ft_l2_enabled)
		return 0;
	ft_l2_recent = __alloc_percpu(FT_L2_SEEN * sizeof(*ft_l2_recent),
				      __alignof__(*ft_l2_recent));
	rc = ft_l2_recent ? nf_register_net_hook(&init_net, &ft_l2_hook_ops) : -ENOMEM;
	if (rc) {
		pr_warn("cdx flowtable: bridged unicast learner could not register its hook (%d); bridged pairs stay in software\n",
			rc);
		free_percpu(ft_l2_recent);
		ft_l2_recent = NULL;
		return 0;
	}
	WRITE_ONCE(ft_l2_hooked, true);
	return 0;
}

/* Called with no transaction held: unregisters the hook, waits out the
 * frames inside it and the worker, then retires everything installed. */
void ft_l2_exit(void)
{
	WRITE_ONCE(ft_l2_stopping, true);
	if (READ_ONCE(ft_l2_hooked)) {
		WRITE_ONCE(ft_l2_hooked, false);
		nf_unregister_net_hook(&init_net, &ft_l2_hook_ops);
		synchronize_net();
	}
	free_percpu(ft_l2_recent);
	ft_l2_recent = NULL;
	cancel_delayed_work_sync(&ft_l2_work);
	cdx_ft_begin();
	while (ft_l2_retire_batch())
		ft_l2_yield();
	cdx_ft_end();
}

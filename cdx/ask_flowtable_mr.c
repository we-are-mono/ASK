// SPDX-License-Identifier: GPL-2.0-or-later
/* The routed multicast learner.
 */
#include "ask_flowtable_internal.h"

/* ------------------------------------------------------- Routed multicast
 *
 * The second learner, and the one with nothing to learn. Where a bridge's MDB
 * describes a permission that traffic has to complete -- see the bridged
 * learner, ask_flowtable_mc.c -- ipmr's MFC is already the classifier's key:
 * mfc_origin and mfc_mcastgrp are an exact (S,G), mfc_parent names the
 * interface the stream arrives on, and ttls[] is the replication list. Every fact the bridged learner had to
 * recover from frames is stated outright here, so nothing is ever waiting on
 * a source. What the MFC does not say is whether the firewall lets the
 * stream through, and a copy of it has to be seen leaving every oif before
 * the group is carried; see the section on what Linux itself forwarded.
 *
 * Both learners use the same encoder, with explicit forwarding semantics.
 * This learner requests a routed root, which decrements TTL or hop limit;
 * the bridge learner preserves it. The parser refuses to classify a frame
 * arriving with 0 or 1, matching the router's `ttl > 1` rule. Listener entries
 * rebuild Ethernet from the address of the VIF each copy is sent through to
 * the group's mapped multicast destination, as ipmr's own copies are built.
 *
 * An entry whose parent VIF is a bridge, or an 802.1Q device above one, is the
 * exception: its stream arrives on a bridge port, which only the bridged
 * learner can key, so it installs nothing and publishes its copies to the
 * bridged group carrying that stream instead. See the section on the
 * learners' streams.
 *
 * The control plane is whatever fills the MFC -- igmpproxy, omcproxy,
 * smcroute, pimd -- and none of them needs anything from ASK. They install
 * (S,G) entries at threshold 1 in the default table, which is what the
 * contract below accepts. See docs/flowtable/multicast-routed.md.
 *
 * Locking, which is where this differs from every other notifier in this file.
 * The FIB chain is an *atomic* chain and every mr_* caller asserts RTNL, so
 * the handler runs in process context under RTNL and may not sleep: it holds
 * the mfc and the device, appends to a queue under a spinlock, and wakes a
 * worker. The worker takes ft_mr_lock to choose a group, releases it, takes
 * RTNL to decide -- device walks, bridge VLAN state and the kernel's multicast
 * egress snapshot -- releases RTNL, and only then takes the transaction, which
 * it holds until the outcome is recorded. What the handler queued while the
 * worker waited for RTNL, and could change the answer, is applied before the
 * group is decided under it (ft_mr_queue_behind()). Three rules hold, and
 * tools/host_tests/test_mroute_learner.py greps for each:
 *
 *   - ft_mr_lock is never held across cdx_ft_begin(). /proc takes the
 *     transaction and then the lock, so the other order would close a cycle;
 *     the worker and the drain take the lock inside the transaction, which is
 *     the same order. The worker takes it there only to record: it programs
 *     the hardware with the transaction alone, so nothing that takes the lock
 *     under RTNL waits behind a hardware call. The drain keeps it across its
 *     rebuilds, which delays nothing under RTNL: its caller holds RTNL.
 *   - The worker never holds RTNL across cdx_ft_begin(). One caller does:
 *     ft_mr_egress_drain(), which runs under the RTNL a tc command holds and
 *     takes the transaction there -- RTNL then the transaction, the order the
 *     flowtable's bind path and the DSCP map's barrier already take.
 *     cdx_ctrl_lock_with_rtnl() forbids waiting for either lock while holding
 *     the other, and no path waits for RTNL while holding the transaction:
 *     admission only trylocks it. So that order closes no cycle, and the
 *     worker, which may wait for RTNL, never holds the transaction then. The
 *     bridged learner's drain, ft_mc_egress_drain(), is the same.
 *   - ft_mr_lock and ft_mc_lock are never nested. The bridged side only
 *     kicks this worker; the routed side reads bridge state from the kernel,
 *     and publishes its routes and taps through functions that take
 *     ft_mc_lock themselves, called with ft_mr_lock released. One of them is
 *     called inside the transaction: an add that finds no group id asks the
 *     bridged learner for one a discard holds (ft_mc_evict_discard()), with
 *     ft_mr_lock and RTNL both released -- the transaction then ft_mc_lock,
 *     /proc's order.
 */

/* Enough to ride out a transient -- a port bouncing, a moment of capacity
 * pressure; the tries are a refresh interval apart -- and few enough that a
 * group which genuinely cannot be carried stops costing anything. Anything
 * that changes the answer resets it. */
#define FT_MR_MAX_RETRIES	4
/* mlxsw folds its hardware counters every five seconds and nothing here wants
 * to be finer: the numbers feed `ip -s mroute` and a daemon's SIOCGETSGCNT,
 * both of which an operator reads by hand. */
#define FT_MR_STATS_INTERVAL	(5 * HZ)
/* How many times one worker run goes back to apply what the chain queued while
 * it waited for RTNL before deciding a group anyway: enough to take in the
 * burst one RTNL holder writes -- a device going takes its VIFs and a daemon
 * its entries -- and few enough that a chain that never falls quiet cannot
 * keep every group waiting. Per run rather than per group: every go back
 * applies events that can ask again groups the run has already decided, so a
 * budget each pick renewed would let a steady writer keep one run going for
 * ever. What spends it is what ft_mr_queue_behind() waits for: any VIF or
 * rule event of the picked group's family -- a VIF in a table this learner
 * does not mirror and the default rule included, which cannot change the
 * answer but are not told apart -- an event of the group's own entry, and a
 * resync asked for since the run last tried one. The other family's events
 * and another entry's never do. */
#define FT_MR_MAX_RESTARTS	4

/* Why a group is not being replicated, for an operator looking at a stream
 * that is not offloaded. Every refusal in the contract has a word of its own:
 * one "refused" would answer ten different questions the same way. */
static const char *ft_mr_state_text(enum ft_mr_state state)
{
	switch (state) {
	case FT_MR_PENDING:		return "pending";
	case FT_MR_INSTALLED:		return "installed";
	case FT_MR_BRIDGED:		return "pending-bridged";
	case FT_MR_UNCONFIRMED:		return "pending-confirm";
	case FT_MR_REFUSED_TABLE:	return "refused-table";
	case FT_MR_REFUSED_PAUSED:	return "refused-paused";
	case FT_MR_REFUSED_POLICY:	return "refused-policy";
	case FT_MR_REFUSED_WILDCARD:	return "refused-wildcard";
	case FT_MR_REFUSED_SCOPE:	return "refused-scope";
	case FT_MR_REFUSED_INGRESS:	return "refused-ingress";
	case FT_MR_REFUSED_HOST:	return "refused-host";
	case FT_MR_REFUSED_THRESHOLD:	return "refused-threshold";
	case FT_MR_REFUSED_LISTENER:	return "refused-listener";
	case FT_MR_REFUSED_MTU:		return "refused-mtu";
	case FT_MR_REFUSED_XFRM:	return "refused-xfrm";
	case FT_MR_REFUSED_FILTER:	return "refused-filter";
	case FT_MR_REFUSED_TC:		return "refused-tc";
	case FT_MR_REFUSED_XTABLES:	return "refused-xtables";
	case FT_MR_REFUSED_PORTS:	return "refused-ports";
	case FT_MR_REFUSED_CONTESTED:	return "refused-contested";
	case FT_MR_REFUSED_FAILED:	return "refused-failed";
	case FT_MR_REFUSED_RESYNC:	return "refused-resync";
	}
	return "unknown";
}

static bool ft_mr_refusal(enum ft_mr_state state)
{
	return state >= FT_MR_REFUSED_TABLE;
}

/* One VIF, mirrored from the chain rather than read out of ipmr.
 *
 * The MFC notification carries mfc_parent and ttls[] as VIF *indexes* and
 * nothing that resolves them; mr_table is private to ipmr. So the VIF table is
 * kept here, built from the VIF_ADD and VIF_DEL the same chain delivers -- and
 * the registration dump replays every existing VIF before any MFC entry
 * (mr_dump()), so it is complete before the first group arrives.
 */
struct ft_mr_vif {
	struct net_device *dev;
	unsigned short flags;
};

/* What the atomic handler hands the worker. The mfc and the device are held
 * here rather than looked up later: by the time the worker runs, the entry may
 * have been deleted and the device unregistered. */
struct ft_mr_event {
	struct list_head list;
	unsigned long event;
	u8 family;
	u32 table;
	struct mr_mfc *mfc;
	struct net_device *dev;
	unsigned short vif_index;
	unsigned short vif_flags;
	bool rule_default;
};

static LIST_HEAD(ft_mr_groups);
DEFINE_MUTEX(ft_mr_lock);
static LIST_HEAD(ft_mr_queue);
static DEFINE_SPINLOCK(ft_mr_queue_lock);
static struct ft_mr_vif ft_mr_vif[2][MAXVIFS];
unsigned int ft_mr_count, ft_mr_installed;
/* The groups followed at once per family, the group ids cdx_mc has for each
 * (shared with the bridged learner): every one is re-derived under RTNL each
 * stats interval, and one past what the hardware could hold buys nothing. An
 * MFC entry past it stays in software, counted in mroute_capped (each time
 * the chain or a resync offers it), and the families it was turned away in
 * (a bit each) are resynced once a group is freed, which picks it up if there
 * is room. */
#define FT_MR_MAX_GROUPS	512
static unsigned long ft_mr_capped;
u64 ft_mr_capped_entries;
unsigned int ft_mr_policy[2];
u64 ft_mr_refused, ft_mr_install_errors, ft_mr_lost;
bool ft_mr_stopping;
bool ft_mr_ready;
static bool ft_mr_recheck;
/* The VIF table changed and the bridged learner has not been told where the
 * VIFs on bridges now are. */
static bool ft_mr_taps_stale = true;
/* A group gave up an entry, so a group refused its key may now have it. */
static bool ft_mr_key_freed;
/* A lost notification invalidates the mirror, including a family with no
 * cached groups. Only a complete dump under RTNL clears its bit. */
unsigned long ft_mr_resync_pending;
static void ft_mr_work_fn(struct work_struct *work);
static void ft_mr_stats_fn(struct work_struct *work);
DECLARE_WORK(ft_mr_work, ft_mr_work_fn);
static DECLARE_DELAYED_WORK(ft_mr_stats, ft_mr_stats_fn);

unsigned int ft_mr_idx(u8 family)
{
	return family == AF_INET6 ? 1 : 0;
}

/* The one multicast routing table this learner reads. ipmr_rules_init()
 * creates RT_TABLE_DEFAULT and ip6mr_rules_init() RT6_TABLE_DFLT; reaching any
 * other one takes a policy rule, and a policy rule is what ft_mr_derive()
 * refuses the whole family over. */
static u32 ft_mr_default_table(u8 family)
{
	return family == AF_INET6 ? RT6_TABLE_DFLT : RT_TABLE_DEFAULT;
}

/* Wake the worker and have it reconsider every answer it has given.
 *
 * Reached from the netdev chain, the switchdev chain and the shared key
 * register, all of which can change a decision without changing an MFC entry.
 * Retries go with it: a group that failed against a port with no carrier is
 * not a group that cannot be carried, and nothing else would ever look again.
 */
void ft_mr_kick(void)
{
	if (READ_ONCE(ft_mr_stopping))
		return;
	WRITE_ONCE(ft_mr_recheck, true);
	schedule_work(&ft_mr_work);
}

/* ---- the contract's tests, each answerable on its own ------------------ */

/* The classifier composes {portid, saddr, daddr, protocol} into an external
 * *hash* table, so a masked source cannot match -- a wildcard would change the
 * hash rather than widen it. An (*,G) MFC entry, and the (*,*) form ipmr also
 * carries, therefore have no key to install. */
static bool ft_mr_specific(u8 family, const union nf_inet_addr *src,
			   const union nf_inet_addr *dst)
{
	if (family == AF_INET6)
		return !ipv6_addr_any(&src->in6) && !ipv6_addr_any(&dst->in6);
	return src->ip != htonl(INADDR_ANY) && dst->ip != htonl(INADDR_ANY);
}

/* Link-local scope carries the membership protocols themselves. The backend
 * refuses it too; mirroring the test here is what makes /proc say
 * "refused-scope" instead of "refused-failed" four retries later. */
static bool ft_mr_scope_ok(u8 family, const union nf_inet_addr *dst)
{
	if (family == AF_INET6)
		return ipv6_addr_is_multicast(&dst->in6) &&
		       __ipv6_addr_src_scope(__ipv6_addr_type(&dst->in6)) >
			       IPV6_ADDR_SCOPE_LINKLOCAL;
	return ipv4_is_multicast(dst->ip) &&
	       (ntohl(dst->ip) & 0xffffff00) != 0xe0000000;
}

/* Whether the box itself has joined this group on `dev`: the interface the
 * stream arrives on, or one it is forwarded out of.
 *
 * ip_mr_input() delivers locally as well as forwarding when the input device
 * has -- ip_route_input_mc() asks ip_check_mc_rcu() on it, and IPv6 asks the
 * idev's own list -- and each forwarded copy is looped back to the host when
 * its output device has. A hardware entry replicates to ports without the
 * frame ever reaching the CPU. Such a group is refused rather than carried
 * with a starved local listener, which is the bridged learner's answer to the
 * same question. Any membership counts, whatever its source filter: refusing
 * one the filter would not deliver costs only the offload. Neither check is
 * exported, so the lists are walked here.
 */
static bool ft_mr_host_member(struct net_device *dev, u8 family,
			      const union nf_inet_addr *group)
{
	bool found = false;

	rcu_read_lock();
	if (family == AF_INET6) {
		struct inet6_dev *idev = __in6_dev_get(dev);
		struct ifmcaddr6 *mc;

		for (mc = idev ? rcu_dereference(idev->mc_list) : NULL;
		     mc && !found; mc = rcu_dereference(mc->next))
			found = ipv6_addr_equal(&mc->mca_addr, &group->in6);
	} else {
		struct in_device *in_dev = __in_dev_get_rcu(dev);
		struct ip_mc_list *im;

		for (im = in_dev ? rcu_dereference(in_dev->mc_list) : NULL;
		     im && !found; im = rcu_dereference(im->next_rcu))
			found = im->multiaddr == group->ip;
	}
	rcu_read_unlock();
	return found;
}

/* The one physical port a VIF's traffic arrives on, and the framing it arrives
 * with, in a listener's own shape.
 *
 * The classifier key names a port, not a VLAN, and the per-listener rebuild
 * strips whatever L2 the frame came in with -- so a VIF that is a VLAN device
 * keys on the port beneath it. A bridge cannot be an ingress at all: it is
 * many ports and the key is one. A bridge *port* is refused for the opposite
 * reason -- its frames go to the bridge's rx handler and never reach a VIF
 * above it, so a VIF naming one describes traffic that does not exist.
 *
 * The tags are returned as well as counted, for two things. The counter fold
 * subtracts the framing they represent. And a copy is refused only when its
 * port *and* its tags equal the ingress's, which is the rule ft_parse()
 * already applies to a flow: re-entering the port a frame arrived on is
 * refused only when the two stacks match, because differing stacks are
 * "ordinary routing between VLANs carried on one trunk". See ft_mr_listener().
 */
static struct net_device *ft_mr_ingress_port(struct net_device *dev,
					     struct cdx_mc_listener *in)
{
	struct cdx_ft_vlan inner[CDX_FT_VLAN_MAX] = {};
	unsigned int n = 0, i;

	memset(in, 0, sizeof(*in));
	for (;;) {
		if (!dev || netif_is_bridge_master(dev) ||
		    netif_is_bridge_port(dev) || dev->type == ARPHRD_PPP)
			return NULL;
		if (cdx_mc_port_identity(dev)) {
			/* Outermost first, as a listener's are and as the wire
			 * carries them; the walk accumulates the other way. */
			for (i = 0; i < n; i++)
				in->vlan[i] = inner[n - 1 - i];
			in->vlans = n;
			in->dev = dev;
			return dev;
		}
		if (!is_vlan_dev(dev) || n == CDX_FT_VLAN_MAX ||
		    vlan_dev_vlan_proto(dev) != htons(ETH_P_8021Q))
			return NULL;
		inner[n].proto = vlan_dev_vlan_proto(dev);
		inner[n].id = vlan_dev_vlan_id(dev);
		n++;
		dev = ft_vlan_lower(dev);
	}
}

/* The bridge a VIF receives its stream through, when it is not a port: the
 * bridge device itself, or one 802.1Q device above it, in the terms struct
 * ft_mc_route describes. Such a stream arrives on a bridge port and is handed
 * to the host by the bridge, so it is keyed and carried by the bridged group
 * for that port, and this entry contributes its copies to it.
 *
 * Which VLANs reach the VIF is the bridge's own membership's answer and is
 * read where the stream is known; here only the shape is decided. A bridge
 * that does not filter hands a tagged frame up with its tag, and its streams
 * are learned untagged only, so a VLAN device above one names nothing a group
 * can carry. */
static struct net_device *ft_mr_ingress_bridge(struct net_device *dev,
					       u16 *vid, bool *tagged)
{
	struct net_device *bridge = dev;

	*vid = 0;
	*tagged = false;
	if (dev && is_vlan_dev(dev)) {
		if (vlan_dev_vlan_proto(dev) != htons(ETH_P_8021Q))
			return NULL;
		*vid = vlan_dev_vlan_id(dev);
		*tagged = true;
		bridge = ft_vlan_lower(dev);
	}
	if (!bridge || !netif_is_bridge_master(bridge))
		return NULL;
	if (*tagged && !br_vlan_enabled(bridge))
		return NULL;
	return bridge;
}

/* Append one resolved listener.
 *
 * `inner` is innermost first, the order the device walk accumulates in and the
 * order ft_bridge_vlan() reads; a listener is described outermost first, the
 * order the wire carries. The reversal happens here, at the one place the two
 * conventions meet.
 *
 * `path_mtu` is the smallest MTU on the way from the oif down to this port,
 * and *mtu the smallest over every copy the group makes -- including one that
 * collapses into a copy another oif already produced, because Linux would have
 * sent that one down its own, possibly narrower, path. `src_mac` is the oif's
 * own address, which the copy leaves with; see ft_mr_expand().
 */
static int ft_mr_listener(struct net_device *port,
			  const struct cdx_mc_listener *ingress,
			  const struct cdx_ft_vlan *inner, unsigned int tags,
			  u32 path_mtu, const u8 *src_mac,
			  struct cdx_mc_listener *out, u8 *count, u32 *mtu)
{
	struct cdx_mc_listener add = {};
	unsigned int i;

	if (tags > CDX_FT_VLAN_MAX)
		return -EOPNOTSUPP;
	add.dev = port;
	add.vlans = tags;
	add.routed = true;
	ether_addr_copy(add.src_mac, src_mac);
	for (i = 0; i < tags; i++)
		add.vlan[i] = inner[tags - 1 - i];
	/* A copy that would leave the way the frame arrived is not a copy: a
	 * router does not send a group back where it came from, and
	 * ip_mr_forward() will not either -- a threshold on the parent VIF is
	 * honoured only for the (*,*) form.
	 *
	 * "The way it arrived" is the port *and* its tags, which is the rule
	 * ft_parse() has been applying to a flow since the IPv6 increment:
	 * re-entering the ingress port is refused only when the two tag stacks
	 * match, because differing stacks are ordinary routing between VLANs
	 * carried on one trunk. The hardware demonstrably enqueues back to the
	 * port a frame arrived on -- the hairpin double-NAT case is measured
	 * at full rate in both directions on one port (docs/flowtable/ipv6.md)
	 * -- so multicast agreeing with that rule is the two paths saying the
	 * same thing, not a new capability being claimed. Unicast additionally
	 * lets full NAT make an identical-stack hairpin distinct; a group has
	 * no NAT, so identical is refused outright. */
	if (add.dev == ingress->dev && add.vlans == ingress->vlans &&
	    !memcmp(add.vlan, ingress->vlan, sizeof(add.vlan)))
		return -EOPNOTSUPP;
	/* Two oifs resolving to the same port with the same framing and the
	 * same address are one copy and collapse; with different framing they
	 * are two, and the backend takes both -- it identifies a listener by
	 * its whole framing rather than by its device, and each gets its own
	 * entry in the chain. A gateway serving several VLANs out of one port
	 * replicates that way, and so does the bench: the rig has one LAN port
	 * with carrier and every group's other port is its ingress, so two
	 * tagged oifs on that port are the only way replication to several
	 * listeners and the chain swap a join performs can be exercised there
	 * at all (ISSUES.md A158). Two oifs with one framing and different
	 * addresses -- the port itself and a bridge over it given an address
	 * of its own -- are two frames on the wire in Linux, and two here. */
	*mtu = min(*mtu, path_mtu);
	for (i = 0; i < *count; i++)
		if (out[i].dev == add.dev && out[i].vlans == add.vlans &&
		    !memcmp(out[i].vlan, add.vlan, sizeof(add.vlan)) &&
		    ether_addr_equal(out[i].src_mac, add.src_mac))
			return 0;
	if (*count == CDX_MC_MAX_LISTENERS)
		return -EOPNOTSUPP;
	out[*count] = add;
	(*count)++;
	return 0;
}

/* The VLAN a bridge forwards this group within, which is one answer for the
 * whole bridge: the outermost tag above it when the frame already carries one
 * in the bridge's protocol, and the bridge's PVID otherwise. It is the first
 * half of what ft_bridge_vlan() decides per port, asked once because the MDB
 * lookup needs it before any port has been chosen. */
static int ft_mr_bridge_vid(struct net_device *bridge,
			    const struct cdx_ft_vlan *inner, unsigned int tags,
			    u16 *vid)
{
	u16 proto;

	*vid = 0;
	if (!br_vlan_enabled(bridge))
		return 0;
	if (br_vlan_get_proto(bridge, &proto) || proto != ETH_P_8021Q)
		return -EOPNOTSUPP;
	if (tags && inner[tags - 1].proto == htons(proto)) {
		*vid = inner[tags - 1].id;
		return 0;
	}
	return br_vlan_get_pvid(bridge, vid) ? -EOPNOTSUPP : 0;
}

/* A bridge oif uses a live kernel snapshot, including router ports. The
 * switchdev MDB mirror alone cannot supply that set, and a cached MROUTER
 * boolean loses the protocol and VLAN. RTNL keeps the borrowed ports alive
 * until the completed plan takes its references.
 *
 * A copy routed into a bridge meets two limits: the bridge device's own, which
 * ip_mr_forward() sends it against, and then each port's, which the bridge
 * drops it against rather than fragmenting. */
static int ft_mr_expand_bridge(struct net_device *bridge,
			       const struct cdx_mc_listener *ingress,
			       const struct cdx_ft_vlan *inner,
			       unsigned int tags, u8 family,
			       const union nf_inet_addr *src,
			       const union nf_inet_addr *dst, u32 path_mtu,
			       const u8 *src_mac, struct cdx_mc_listener *out,
			       u8 *count, u32 *mtu)
{
	struct net_device *chosen[CDX_MC_MAX_LISTENERS];
	struct br_ip group = {};
	int n, rc;
	u8 i;

	rc = ft_mr_bridge_vid(bridge, inner, tags, &group.vid);
	if (rc)
		return rc;
	if (family == AF_INET6) {
		group.proto = htons(ETH_P_IPV6);
		group.src.ip6 = src->in6;
		group.dst.ip6 = dst->in6;
	} else {
		group.proto = htons(ETH_P_IP);
		group.src.ip4 = src->ip;
		group.dst.ip4 = dst->ip;
	}
	/* Sent by the host through the bridge device, as ipmr's copy is: no
	 * ingress port, and nothing handed back up to the host. */
	n = br_multicast_list_ports(bridge, &group, NULL, NULL, chosen,
				    ARRAY_SIZE(chosen));
	if (n < 0)
		return n;
	for (i = 0; i < n; i++) {
		struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
		unsigned int c = tags;

		/* Every selected destination must be carried. An unsupported
		 * router or listener refuses the whole group, never a subset. */
		if (!cdx_mc_port_identity(chosen[i]))
			return -EOPNOTSUPP;
		memcpy(stack, inner, sizeof(stack));
		if (ft_bridge_vlan(bridge, chosen[i], stack, &c) < 0)
			return -EOPNOTSUPP;
		rc = ft_mr_listener(chosen[i], ingress, stack, c,
				    min_t(u32, path_mtu, READ_ONCE(chosen[i]->mtu)),
				    src_mac, out, count, mtu);
		if (rc)
			return rc;
	}
	/* An empty bridge contributes no copies; another oif may still do so.
	 * ft_mr_derive() refuses a completely empty replication set. */
	return 0;
}

/* One oif, resolved to the listeners the hardware has to be given.
 *
 * A physical port is itself. A VLAN device is the port beneath it plus its
 * tag, up to the two a rule can describe, 802.1Q only for the reason
 * ft_bridge_vlan() gives. A bridge is its ports. Anything else -- a bond, a
 * MACVLAN, a ppp device, a tunnel -- is refused rather than approximated,
 * which is ft_path_stack()'s rule for a flow's path applied to a replica's.
 *
 * *mtu comes back lowered to the smallest MTU any resulting copy leaves by:
 * each device on the way down counts, because the oif is what ipmr and ip6mr
 * send against and the port is what the listener's enqueue fragments at.
 * *bridged comes back true when the oif is a bridge or sits on one.
 *
 * Every copy leaves with the oif's own address, read here before the walk goes
 * down, because that is the one ipmr's copy carries: ip_finish_output2() and
 * ip6_finish_output2() build the header on the VIF device, and a bridge, or a
 * VLAN device on a port or a bridge, sends it on unchanged. It is the port's
 * only when the oif is the port -- a VLAN device can be given another, and a
 * bridge carries one of its ports' or its own -- and the unicast path's answer
 * to the same divergence, refusing it, would keep a whole IPTV stream in
 * software on the ordinary br-lan.N layout. An oif with no unicast address of
 * its own names no frame the hardware could write, and is refused. Read under
 * RTNL, which every address change holds, so the plan and the device agree;
 * NETDEV_CHANGEADDR asks for the plan again.
 */
static int ft_mr_expand(struct net_device *dev,
			const struct cdx_mc_listener *ingress,
			u8 family, const union nf_inet_addr *src,
			const union nf_inet_addr *dst,
			struct cdx_mc_listener *out, u8 *count, u32 *mtu,
			bool *bridged)
{
	struct cdx_ft_vlan inner[CDX_FT_VLAN_MAX] = {};
	unsigned int tags = 0;
	u32 path_mtu = U32_MAX;
	u8 src_mac[ETH_ALEN];

	if (!dev || dev->addr_len != ETH_ALEN ||
	    !is_valid_ether_addr(dev->dev_addr))
		return -EOPNOTSUPP;
	ether_addr_copy(src_mac, dev->dev_addr);
	for (;;) {
		if (!dev)
			return -EOPNOTSUPP;
		path_mtu = min(path_mtu, ft_mc_link_mtu(dev, family));
		if (netif_is_bridge_master(dev)) {
			*bridged = true;
			return ft_mr_expand_bridge(dev, ingress, inner, tags,
						   family, src, dst, path_mtu,
						   src_mac, out, count, mtu);
		}
		if (cdx_mc_port_identity(dev))
			return ft_mr_listener(dev, ingress, inner, tags,
					      path_mtu, src_mac, out, count,
					      mtu);
		if (!is_vlan_dev(dev) || tags == CDX_FT_VLAN_MAX ||
		    vlan_dev_vlan_proto(dev) != htons(ETH_P_8021Q))
			return -EOPNOTSUPP;
		inner[tags].proto = vlan_dev_vlan_proto(dev);
		inner[tags].id = vlan_dev_vlan_id(dev);
		tags++;
		dev = ft_vlan_lower(dev);
	}
}

static void ft_mr_plan_put(struct ft_mr_plan *plan)
{
	u8 i;

	for (i = 0; i < plan->spec.listeners; i++)
		if (plan->spec.listener[i].dev)
			dev_put(plan->spec.listener[i].dev);
	if (plan->spec.in)
		dev_put(plan->spec.in);
	if (plan->via)
		dev_put(plan->via);
	memset(plan, 0, sizeof(*plan));
}

/* The device VIF `ct` names, as ipmr and ip6mr see it now. Called under RTNL.
 *
 * The mirror is applied by the worker from a queue the chain fills under RTNL,
 * so a derivation that takes RTNL straight after a device went -- its worker
 * had picked the group and was waiting for the lock -- still finds the VIF
 * the device's removal deleted. ipmr and ip6mr delete every VIF naming a
 * device on NETDEV_UNREGISTER, in the RTNL hold that takes it off
 * NETREG_REGISTERED or out of the namespace, so under RTNL a mirrored device
 * no longer registered here is exactly a VIF the kernel has removed, and is
 * answered like one. The queued VIF_DEL lets go of it on the next pass. */
static struct net_device *ft_mr_vif_dev(unsigned int idx, int ct)
{
	struct net_device *dev;

	ASSERT_RTNL();
	if (ct < 0 || ct >= MAXVIFS)
		return NULL;
	dev = ft_mr_vif[idx][ct].dev;
	if (dev && (READ_ONCE(dev->reg_state) != NETREG_REGISTERED ||
		    !net_eq(dev_net(dev), &init_net)))
		return NULL;
	return dev;
}

/* Whether every IPv4 copy of a group leaves untransformed and unblocked by
 * XFRM, which a hardware copy -- one that never takes the output route -- is.
 *
 * ipmr_queue_xmit() routes each copy with an output lookup of its own: to the
 * group, source chosen by the route, IPPROTO_IPIP, ports zero, through the
 * VIF's device. That lookup's XFRM step applies the output policy, which can
 * block the copy or bundle it into a transform (dropped for want of a state,
 * or encrypted). The lookup is rebuilt here as ipmr makes it, the flow's oif
 * rewritten to the route's device as ip_route_output_flow() does, and the
 * output policy asked for it. A route through a device with disable_xfrm set
 * skips the policies, and meets only the default. A tunnel or register VIF
 * encapsulates before that lookup, which this does not model, so it counts as
 * governed; and a copy with no route at all, which Linux never sends.
 *
 * Nothing reports a change of what the lookup reads besides the policies --
 * an oif's address, which a policy's source selector may match, or its
 * disable_xfrm switch -- and the five-second refresh finds it.
 *
 * IPv6 needs nothing: ip6mr routes its copies with a lookup that takes no
 * XFRM step, and a bridge takes none either, so an ip6 policy governs no
 * forwarded copy in software and none in hardware alike. Called under RTNL. */
static bool ft_mr_xfrm_plain(const struct ft_mr_group *g)
{
	struct net *net = &init_net;
	struct mr_mfc *mfc = g->mfc;
	bool blocked, bypass;
	int ct;

	ASSERT_RTNL();
	if (g->family != AF_INET)
		return true;
	/* No output policy and an accepting default: every lookup passes. */
	blocked = READ_ONCE(net->xfrm.policy_default[XFRM_POLICY_OUT]) ==
		  XFRM_USERPOLICY_BLOCK;
	if (!READ_ONCE(net->xfrm.policy_count[XFRM_POLICY_OUT]) && !blocked)
		return true;
	for (ct = mfc->mfc_un.res.minvif; ct < mfc->mfc_un.res.maxvif; ct++) {
		struct net_device *oif = ft_mr_vif_dev(0, ct);
		struct flowi4 fl4 = {};
		struct rtable *rt;

		if (mfc->mfc_un.res.ttls[ct] == 255 || !oif)
			continue;
		if (ft_mr_vif[0][ct].flags & (VIFF_TUNNEL | VIFF_REGISTER))
			return false;
		fl4.daddr = g->dst.ip;
		fl4.flowi4_proto = IPPROTO_IPIP;
		fl4.flowi4_oif = oif->ifindex;
		rt = __ip_route_output_key(net, &fl4);
		if (IS_ERR(rt))
			return false;
		fl4.flowi4_oif = rt->dst.dev->ifindex;
		bypass = rt->dst.flags & DST_NOXFRM;
		ip_rt_put(rt);
		/* xfrm_lookup_with_ifid() takes such a route straight to its
		 * no-policy answer. */
		if (bypass) {
			if (blocked)
				return false;
			continue;
		}
		if (!xfrm_flowtable_out_plain(net, flowi4_to_flowi(&fl4), AF_INET))
			return false;
	}
	return true;
}

/* The whole contract, in the order an operator would want it answered.
 *
 * Runs under RTNL with neither learner mutex held, and touches no hardware.
 * Every refusal returns with the plan owing no reference; only the last line,
 * which is the only success, takes any. The oif list, which holds nothing, is
 * filled in by every derivation that gets past the table.
 */
static enum ft_mr_state ft_mr_derive(struct ft_mr_group *g,
				     struct ft_mr_plan *plan)
{
	struct cdx_mc_group_spec spec = {};
	unsigned int idx = ft_mr_idx(g->family);
	struct net_device *vif_dev, *via = NULL;
	char oifs[FT_MR_OIF_TEXT];
	struct cdx_mc_listener in;
	unsigned short bad_flags;
	struct mr_mfc *mfc = g->mfc;
	bool via_tagged = false;
	u32 out_mtu = U32_MAX;
	u16 via_vid = 0;
	size_t at = 0;
	int ct;

	ASSERT_RTNL();
	oifs[0] = '\0';
	if (g->table != ft_mr_default_table(g->family))
		return FT_MR_REFUSED_TABLE;
	/* Every oif ipmr forwards the stream to, by the device it sends each
	 * copy through: what has to be seen leaving by each before the group is
	 * carried. Listed ahead of every other test, which the VIF mirror of
	 * this table is all it needs, so a group waiting in software for its
	 * policy rule, a host membership or its MTU gathers its confirmations
	 * meanwhile, and is carried the moment it is otherwise eligible. */
	for (ct = mfc->mfc_un.res.minvif; ct < mfc->mfc_un.res.maxvif; ct++) {
		struct net_device *oif = ft_mr_vif_dev(idx, ct);

		if (mfc->mfc_un.res.ttls[ct] != 255 && oif)
			plan->oif[plan->oif_count++] = oif->ifindex;
	}
	/* And the VIF each copy has to have arrived by: an iif-keyed forward
	 * rule -- fw4's zones are -- judges a stream by where it comes from,
	 * so copies seen from one parent confirm nothing for another. No
	 * device is no index, which no copy arrives by. */
	vif_dev = ft_mr_vif_dev(idx, mfc->mfc_parent);
	plan->parent = vif_dev ? vif_dev->ifindex : 0;
	plan->oifs_known = true;
	/* Switched off: in software, still gathering its confirmations, so the
	 * switch coming back on carries it at once if the ruleset has not
	 * moved -- and a ruleset commit meanwhile takes them back as ever. */
	if (!READ_ONCE(ft_mc_enabled))
		return FT_MR_REFUSED_PAUSED;
	/* A policy rule that is not the default one can send a stream to a
	 * table this learner does not read, and the hardware entry would keep
	 * matching whatever the rule decided afterwards. One such rule
	 * anywhere in a family therefore keeps the whole family in software.
	 * The registration dump replays the existing rules, so the count is
	 * right from load rather than from the first change. */
	if (ft_mr_policy[idx])
		return FT_MR_REFUSED_POLICY;
	if (!ft_mr_specific(g->family, &g->src, &g->dst))
		return FT_MR_REFUSED_WILDCARD;
	if (!ft_mr_scope_ok(g->family, &g->dst))
		return FT_MR_REFUSED_SCOPE;

	if (mfc->mfc_parent >= MAXVIFS)
		return FT_MR_REFUSED_INGRESS;
	/* A PIM register VIF is a tunnel to the rendezvous point built in
	 * software, and an IPIP VIF encapsulates on egress; neither is a port
	 * and the hardware would be asked to forward onto nothing. */
	bad_flags = g->family == AF_INET6 ? MIFF_REGISTER :
					    (VIFF_TUNNEL | VIFF_REGISTER);
	vif_dev = ft_mr_vif_dev(idx, mfc->mfc_parent);
	if (!vif_dev || (ft_mr_vif[idx][mfc->mfc_parent].flags & bad_flags))
		return FT_MR_REFUSED_INGRESS;
	spec.in = ft_mr_ingress_port(vif_dev, &in);
	/* A bridge, or a VLAN device above one: the stream's port is whichever
	 * bridge port it arrives on, which the bridged learner learns, and the
	 * copies below ride its group. `in` stays empty, so no copy is
	 * mistaken for the ingress: every one leaves by a VIF other than the
	 * parent, which ipmr sends even back out of the port it came in by. */
	if (!spec.in)
		via = ft_mr_ingress_bridge(vif_dev, &via_vid, &via_tagged);
	if (!spec.in && !via)
		return FT_MR_REFUSED_INGRESS;
	/* The classifier key names the port and not the VLAN, so the root is
	 * told which tags the stream arrives with and accepts only those: the
	 * same (S,G) on another VLAN of the port -- or untagged -- is excepted
	 * to Linux, which counts it wrong_if as ip_mr_forward() would. Without
	 * it the root validated an untagged frame and a VLAN-device parent
	 * never carried its stream at all. */
	spec.in_vlans = in.vlans;
	memcpy(spec.in_vlan, in.vlan, sizeof(spec.in_vlan));
	if (ft_mr_host_member(vif_dev, g->family, &g->dst))
		return FT_MR_REFUSED_HOST;
	/* Nor on an oif. ip_mc_output() and ip6_finish_output2() loop each
	 * forwarded copy back to the host when it has joined the group on the
	 * device the copy leaves by, and a copy the classifier replicates
	 * never comes back up: a process on the router listening there would
	 * be starved. */
	for (ct = mfc->mfc_un.res.minvif; ct < mfc->mfc_un.res.maxvif; ct++) {
		struct net_device *oif = ft_mr_vif_dev(idx, ct);

		if (mfc->mfc_un.res.ttls[ct] != 255 && oif &&
		    ft_mr_host_member(oif, g->family, &g->dst))
			return FT_MR_REFUSED_HOST;
	}

	/* ip_mr_forward() forwards out vif ct when ttl > ttls[ct], and 255
	 * means "not an oif". The hardware's own rule is ttl >= 2, because the
	 * parser ends the parse for 0 and 1 -- which is exactly threshold 1
	 * and nothing else. A scoped threshold is a decision the classifier
	 * cannot express, so the group stays in software rather than being
	 * carried with the scope silently dropped. */
	for (ct = mfc->mfc_un.res.minvif; ct < mfc->mfc_un.res.maxvif; ct++) {
		unsigned char ttl = mfc->mfc_un.res.ttls[ct];
		struct net_device *oif;
		int rc;

		if (ttl == 255)
			continue;
		if (ttl != 1)
			return FT_MR_REFUSED_THRESHOLD;
		if (ct == mfc->mfc_parent)
			return FT_MR_REFUSED_LISTENER;
		oif = ft_mr_vif_dev(idx, ct);
		/* A VIF the kernel has removed is dropped rather than
		 * refused: what is left is a smaller replication list, and an
		 * empty one is caught below. Whatever flags it had went with
		 * it. */
		if (!oif)
			continue;
		if (ft_mr_vif[idx][ct].flags & bad_flags)
			return FT_MR_REFUSED_LISTENER;
		rc = ft_mr_expand(oif, &in, g->family, &g->src, &g->dst,
				  spec.listener, &spec.listeners, &out_mtu,
				  &plan->out_bridged);
		if (rc)
			return FT_MR_REFUSED_LISTENER;
		at += scnprintf(oifs + at, sizeof(oifs) - at, "%s%s",
				at ? "," : "", oif->name);
	}
	if (!spec.listeners)
		return FT_MR_REFUSED_LISTENER;
	/* The largest packet the parent VIF can hand ipmr has to fit every copy,
	 * or the microcode would fragment one Linux never would: ip6mr answers
	 * an oversized IPv6 replica with Packet Too Big and ipmr drops an IPv4
	 * one with DF set. Nothing an MTU change or the IPv6 MTU sysctl does
	 * raises an MFC event, so this is rechecked by the periodic refresh as
	 * well as on NETDEV_CHANGEMTU.
	 *
	 * Both families are bounded by what arrives rather than by what the link
	 * is told, as unicast is: the parent's port hands ipmr whatever its MAC
	 * accepts, its own MTU but never less than a full Ethernet frame
	 * (ft_port_arriving()), so a 1500-byte VLAN parent over a 9000-byte port,
	 * a parent lowered to 1400, or a source ignoring the IPv6 MTU its link
	 * advertises, delivers more than the parent's own. The port's bound is
	 * the whole of it, as unicast's is (A346): a VLAN parent cannot be set
	 * above its port's MTU, and nothing strips a header on the way up.
	 *
	 * Through a bridge the bound is the bridge port the stream arrives on,
	 * which the bridge hands up whatever the bridge device's own MTU, and
	 * which only the bridged group knows: the plan carries the narrowest
	 * copy for it to hold against that. */
	if (spec.in && out_mtu < ft_port_arriving(spec.in))
		return FT_MR_REFUSED_MTU;
	/* An XFRM output policy Linux would apply to a copy, which hardware
	 * cannot. Asked last, of oifs every test above has let through. The
	 * generation is taken first, so a policy change after it is caught by
	 * the transaction's recheck. */
	plan->xfrm_genid = xfrm_flowtable_genid(&init_net);
	if (!ft_mr_xfrm_plain(g))
		return FT_MR_REFUSED_XFRM;

	spec.family = g->family;
	spec.src = g->src;
	spec.dst = g->dst;
	/* From here the plan owns one reference per device, which the caller
	 * either hands to the group or returns through ft_mr_plan_put(). */
	if (spec.in)
		dev_hold(spec.in);
	if (via)
		dev_hold(via);
	for (ct = 0; ct < spec.listeners; ct++)
		dev_hold(spec.listener[ct].dev);
	plan->via = via;
	plan->via_vid = via_vid;
	plan->via_tagged = via_tagged;
	plan->mtu = out_mtu;
	plan->spec = spec;
	plan->in_tags = in.vlans;
	strscpy(plan->oifs, oifs, sizeof(plan->oifs));
	return FT_MR_PENDING;
}

/* A refresh need not replace an unchanged chain. Compare the forwarding
 * fields, not padding or the logical oif names: two oifs can resolve to the
 * same physical copies. Called under RTNL, which also protects device removal. */
static bool ft_mr_plan_same(const struct ft_mr_group *g,
			    const struct ft_mr_plan *plan)
{
	u8 i, j;

	if (g->in != plan->spec.in || g->in_tags != plan->in_tags ||
	    g->listeners != plan->spec.listeners)
		return false;
	if (g->via != plan->via || g->via_vid != plan->via_vid ||
	    g->via_tagged != plan->via_tagged || g->mtu != plan->mtu)
		return false;
	for (j = 0; j < g->in_tags; j++)
		if (g->in_vlan[j].proto != plan->spec.in_vlan[j].proto ||
		    g->in_vlan[j].id != plan->spec.in_vlan[j].id)
			return false;
	for (i = 0; i < g->listeners; i++) {
		const struct cdx_mc_listener *a = &g->listener[i];
		const struct cdx_mc_listener *b = &plan->spec.listener[i];

		/* The address too: an oif given another one is a chain that
		 * writes the old one until it is replaced. */
		if (a->dev != b->dev || a->vlans != b->vlans ||
		    !ether_addr_equal(a->src_mac, b->src_mac))
			return false;
		for (j = 0; j < a->vlans; j++)
			if (a->vlan[j].proto != b->vlan[j].proto ||
			    a->vlan[j].id != b->vlan[j].id)
				return false;
	}
	return true;
}

/* ---- the chain, the queue and the worker ------------------------------- */

static struct ft_mr_group *ft_mr_find(const struct mr_mfc *mfc)
{
	struct ft_mr_group *g;

	list_for_each_entry(g, &ft_mr_groups, list)
		if (g->mfc == mfc)
			return g;
	return NULL;
}

static void ft_mr_dirty_family(u8 family)
{
	struct ft_mr_group *g;

	list_for_each_entry(g, &ft_mr_groups, list)
		if (g->family == family) {
			g->retries = 0;
			g->dirty = true;
		}
}

/* One queued event, applied to this learner's own state. Called with
 * ft_mr_lock held, from the worker; no hardware, no RTNL, no device walks --
 * every decision is deferred to ft_mr_derive(). */
static bool ft_mr_apply(struct ft_mr_event *ev)
{
	struct ft_mr_vif *vif;
	struct ft_mr_group *g;
	unsigned int idx = ft_mr_idx(ev->family);

	lockdep_assert_held(&ft_mr_lock);
	switch (ev->event) {
	case FIB_EVENT_RULE_ADD:
	case FIB_EVENT_RULE_DEL:
		if (ev->rule_default)
			return true;
		if (ev->event == FIB_EVENT_RULE_ADD)
			ft_mr_policy[idx]++;
		else if (ft_mr_policy[idx])
			ft_mr_policy[idx]--;
		ft_mr_dirty_family(ev->family);
		ft_mr_taps_stale = true;	/* see ft_mr_publish_taps() */
		return true;
	case FIB_EVENT_VIF_ADD:
	case FIB_EVENT_VIF_DEL:
		if (ev->table != ft_mr_default_table(ev->family) ||
		    ev->vif_index >= MAXVIFS)
			return true;
		vif = &ft_mr_vif[idx][ev->vif_index];
		if (vif->dev)
			dev_put(vif->dev);
		vif->dev = NULL;
		vif->flags = 0;
		if (ev->event == FIB_EVENT_VIF_ADD && ev->dev) {
			dev_hold(ev->dev);
			vif->dev = ev->dev;
			vif->flags = ev->vif_flags;
		}
		/* An index is only meaningful against the table it indexes, so
		 * every group of this family is re-derived rather than only
		 * those that name this one. And the bridged learner is told
		 * again where VIFs sit on bridges. */
		ft_mr_dirty_family(ev->family);
		ft_mr_taps_stale = true;
		return true;
	default:
		break;
	}

	g = ft_mr_find(ev->mfc);
	if (ev->event == FIB_EVENT_ENTRY_DEL) {
		if (g) {
			g->gone = true;
			g->dirty = true;
		}
		return true;
	}
	if (!g) {
		unsigned int family_groups = 0;

		list_for_each_entry(g, &ft_mr_groups, list)
			family_groups += g->family == ev->family;
		if (family_groups >= FT_MR_MAX_GROUPS) {
			ft_mr_capped_entries++;
			set_bit(idx, &ft_mr_capped);
			return true;
		}
		g = kzalloc(sizeof(*g), GFP_KERNEL);
		if (!g)
			return false;
		/* The event's own reference is released when it is freed, so
		 * the group takes one of its own for as long as it refers to
		 * the entry -- which is what keeps the pointer it is keyed on
		 * from being reused. */
		mr_cache_hold(ev->mfc);
		g->mfc = ev->mfc;
		g->table = ev->table;
		g->family = ev->family;
		if (ev->family == AF_INET6) {
			const struct mfc6_cache *c =
				container_of(ev->mfc, struct mfc6_cache, _c);

			g->src.in6 = c->mf6c_origin;
			g->dst.in6 = c->mf6c_mcastgrp;
		} else {
			const struct mfc_cache *c =
				container_of(ev->mfc, struct mfc_cache, _c);

			g->src.ip = c->mfc_origin;
			g->dst.ip = c->mfc_mcastgrp;
		}
		list_add(&g->list, &ft_mr_groups);
		ft_mr_count++;
	}
	/* The addresses are the rhashtable key and cannot change, so a
	 * replace is a new parent or a new threshold set and both are read
	 * fresh by the derivation. */
	g->retries = 0;
	g->dirty = true;
	g->gone = false;
	g->seen = true;
	return true;
}

/* Both live notifications and dumps run in atomic context. A captured event
 * owns its references independently of the source table's lifetime. */
static struct ft_mr_event *ft_mr_event_alloc(unsigned long event,
					   struct fib_notifier_info *info)
{
	struct vif_entry_notifier_info *ven;
	struct mfc_entry_notifier_info *men;
	struct fib_rule_notifier_info *fri;
	struct ft_mr_event *ev;

	switch (event) {
	case FIB_EVENT_RULE_ADD:
	case FIB_EVENT_RULE_DEL:
	case FIB_EVENT_VIF_ADD:
	case FIB_EVENT_VIF_DEL:
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_DEL:
		break;
	default:
		return NULL;
	}
	ev = kzalloc(sizeof(*ev), GFP_ATOMIC);
	if (!ev)
		return ERR_PTR(-ENOMEM);
	ev->event = event;
	ev->family = info->family == RTNL_FAMILY_IP6MR ? AF_INET6 : AF_INET;
	switch (event) {
	case FIB_EVENT_RULE_ADD:
	case FIB_EVENT_RULE_DEL:
		fri = container_of(info, struct fib_rule_notifier_info, info);
		ev->rule_default = ev->family == AF_INET6 ?
			ip6mr_rule_default(fri->rule) :
			ipmr_rule_default(fri->rule);
		break;
	case FIB_EVENT_VIF_ADD:
	case FIB_EVENT_VIF_DEL:
		ven = container_of(info, struct vif_entry_notifier_info, info);
		ev->table = ven->tb_id;
		ev->vif_index = ven->vif_index;
		ev->vif_flags = ven->vif_flags;
		ev->dev = ven->dev;
		if (ev->dev)
			dev_hold(ev->dev);
		break;
	default:
		men = container_of(info, struct mfc_entry_notifier_info, info);
		ev->table = men->tb_id;
		ev->mfc = men->mfc;
		mr_cache_hold(ev->mfc);
		break;
	}
	return ev;
}

static void ft_mr_event_free(struct ft_mr_event *ev)
{
	if (ev->mfc)
		mr_cache_put(ev->mfc);
	if (ev->dev)
		dev_put(ev->dev);
	kfree(ev);
}

static void ft_mr_lost_event(u8 family)
{
	set_bit(ft_mr_idx(family), &ft_mr_resync_pending);
	spin_lock_bh(&ft_mr_queue_lock);
	ft_mr_lost++;
	spin_unlock_bh(&ft_mr_queue_lock);
	pr_warn_ratelimited("cdx: routed multicast event lost; resynchronizing\n");
}

/* Live multicast changes hold RTNL; the worker takes it before replacing
 * the mirror so no older queued event can undo an authoritative snapshot. */
int ft_mr_fib_event(unsigned long event, struct fib_notifier_info *info)
{
	struct ft_mr_event *ev;

	if (READ_ONCE(ft_mr_stopping))
		return NOTIFY_DONE;
	ev = ft_mr_event_alloc(event, info);
	if (!ev)
		return NOTIFY_DONE;
	if (IS_ERR(ev)) {
		ft_mr_lost_event(info->family == RTNL_FAMILY_IP6MR ?
				 AF_INET6 : AF_INET);
		schedule_work(&ft_mr_work);
		return NOTIFY_DONE;
	}
	spin_lock_bh(&ft_mr_queue_lock);
	list_add_tail(&ev->list, &ft_mr_queue);
	spin_unlock_bh(&ft_mr_queue_lock);
	schedule_work(&ft_mr_work);
	return NOTIFY_DONE;
}

/* Whether the chain has said anything the worker has not applied yet that
 * could change `g`'s answer. Asked by the worker under the RTNL it decides
 * under.
 *
 * Once registration is over, every producer runs under RTNL: the mr_* callers
 * of the VIF and entry notifiers assert it, and rule changes arrive from RTNL
 * doit handlers. So what is found here stays as found until this RTNL is let
 * go of, and when nothing is, the mirror the derivation reads is exactly
 * ipmr's and ip6mr's -- their VIFs, their rules and this entry -- as of this
 * hold. Anything found was written while the worker waited for the lock, by
 * whoever held it: a VIF a daemon deleted, or a device took with it, that the
 * mirror still names; a rule that would refuse the family; the delete of the
 * very entry the worker picked; or, as a pending resync, one of those lost
 * for want of memory. Deciding against that would carry the stream to a port
 * ipmr has stopped forwarding to, put in hardware an entry ipmr no longer
 * has, or take the group out of hardware for a resync one pass would have
 * finished.
 *
 * What cannot change `g`'s answer is not waited for: the other family, whose
 * VIFs, rules and entries are a table of their own, and another entry's add,
 * replace or delete, which touches nothing the derivation reads. A resync
 * this run already tried and could not finish (`failed`) is not tried again
 * here either; the group is refused until it succeeds, as before. */
static bool ft_mr_queue_behind(const struct ft_mr_group *g,
			       unsigned long failed)
{
	unsigned int idx = ft_mr_idx(g->family);
	struct ft_mr_event *ev;
	bool behind;

	ASSERT_RTNL();
	behind = test_bit(idx, &ft_mr_resync_pending) && !test_bit(idx, &failed);
	spin_lock_bh(&ft_mr_queue_lock);
	list_for_each_entry(ev, &ft_mr_queue, list) {
		if (behind)
			break;
		behind = ev->family == g->family &&
			 (!ev->mfc || ev->mfc == g->mfc);
	}
	spin_unlock_bh(&ft_mr_queue_lock);
	return behind;
}

struct ft_mr_snapshot {
	struct notifier_block nb;
	struct list_head events;
};

static int ft_mr_snapshot_event(struct notifier_block *nb, unsigned long event,
				void *data)
{
	struct ft_mr_snapshot *snapshot =
		container_of(nb, struct ft_mr_snapshot, nb);
	struct ft_mr_event *ev = ft_mr_event_alloc(event, data);

	if (IS_ERR(ev))
		return notifier_from_errno(PTR_ERR(ev));
	if (ev)
		list_add_tail(&ev->list, &snapshot->events);
	return NOTIFY_DONE;
}

/* The provider's dump includes rules, VIFs and resolved MFCs. RTNL excludes
 * table changes across capture AND commit; RCU protects the provider and its
 * table walks. The private callback owns no hardware and never sleeps.
 *
 * Returns the families it tried and could not finish, decided under the RTNL
 * each attempt holds: a family asked for again once that is let go of -- an
 * event lost behind it -- is one this pass did not try, and the worker's look
 * under its own RTNL (ft_mr_queue_behind()) has to tell the two apart. */
static unsigned long ft_mr_resync(void)
{
	unsigned long failed = 0;
	unsigned int idx;

	for (idx = 0; idx < ARRAY_SIZE(ft_mr_vif); idx++) {
		struct ft_mr_snapshot snapshot = {
			.nb.notifier_call = ft_mr_snapshot_event,
		};
		struct fib_notifier_ops *ops;
		struct ft_mr_event *ev, *tmp;
		struct ft_mr_group *g;
		u8 family = idx ? AF_INET6 : AF_INET;
		unsigned int i;
		LIST_HEAD(stale);
		int rc = -EAGAIN;

		if (!test_bit(idx, &ft_mr_resync_pending))
			continue;
		INIT_LIST_HEAD(&snapshot.events);
		rtnl_lock();
		rcu_read_lock();
		ops = idx ? init_net.ipv6.ip6mr_notifier_ops :
			    init_net.ipv4.ipmr_notifier_ops;
		if (ops && try_module_get(ops->owner)) {
			rc = ops->fib_dump(&init_net, &snapshot.nb, NULL);
			module_put(ops->owner);
		}
		rcu_read_unlock();
		if (!rc) {
			/* These events predate the snapshot, including any queued
			 * while the worker waited for RTNL. Replaying them later
			 * would double rule counts or resurrect a deleted MFC. */
			spin_lock_bh(&ft_mr_queue_lock);
			list_for_each_entry_safe(ev, tmp, &ft_mr_queue, list)
				if (ev->family == family)
					list_move_tail(&ev->list, &stale);
			spin_unlock_bh(&ft_mr_queue_lock);
			mutex_lock(&ft_mr_lock);
			ft_mr_policy[idx] = 0;
			for (i = 0; i < MAXVIFS; i++) {
				if (ft_mr_vif[idx][i].dev)
					dev_put(ft_mr_vif[idx][i].dev);
				memset(&ft_mr_vif[idx][i], 0,
				       sizeof(ft_mr_vif[idx][i]));
			}
			ft_mr_taps_stale = true;
			list_for_each_entry(g, &ft_mr_groups, list)
				if (g->family == family)
					g->seen = false;
			list_for_each_entry(ev, &snapshot.events, list)
				if (!ft_mr_apply(ev)) {
					rc = -ENOMEM;
					break;
				}
			if (!rc) {
				list_for_each_entry(g, &ft_mr_groups, list)
					if (g->family == family && !g->seen)
						g->gone = true;
				/* No live callback can set this bit under RTNL.
				 * The worker is the sole other producer. */
				clear_bit(idx, &ft_mr_resync_pending);
			}
			mutex_unlock(&ft_mr_lock);
		}
		if (rc)
			failed |= BIT(idx);
		rtnl_unlock();
		list_splice_tail_init(&stale, &snapshot.events);
		list_for_each_entry_safe(ev, tmp, &snapshot.events, list) {
			list_del(&ev->list);
			ft_mr_event_free(ev);
		}
		/* Incomplete mirrors may not authorize forwarding. The normal
		 * worker withdraws this family's hardware and delayed work
		 * retries even when the lost event was the very first ADD. */
		mutex_lock(&ft_mr_lock);
		ft_mr_dirty_family(family);
		mutex_unlock(&ft_mr_lock);
	}
	return failed;
}

/* MFC_OFFLOAD is what makes `ip mroute show` print `offload` against an entry,
 * and it is the only standard-tool surface this learner has. ipmr writes
 * mfc_flags under RTNL, from ipmr_mfc_add(), so this does too rather than
 * racing a read-modify-write with it -- which means it must never be called
 * from the derivation, where RTNL is already held. */
static void ft_mr_offload_flag(struct ft_mr_group *g, bool on)
{
	if (g->offloaded == on)
		return;
	rtnl_lock();
	if (on)
		g->mfc->mfc_flags |= MFC_OFFLOAD;
	else
		g->mfc->mfc_flags &= ~MFC_OFFLOAD;
	rtnl_unlock();
	g->offloaded = on;
}

/* What the hardware counted since the last fold, restated in the units the
 * kernel counts in and added where the standard tools read it.
 *
 * ip_mr_forward() counts skb->len, which is the L3 packet; the classifier
 * counts the L2 frame it matched. The difference is the ingress framing, the
 * same correction ft_l2_overhead() makes for a flow -- and the same residual,
 * since padding on a short frame is not recoverable.
 *
 * Added, never set. The CPU counts into the same fields: the packets that
 * resolve an entry, every one before the worker installs it, and all of them
 * while a refusal keeps the group in software. And a hardware group counts
 * from zero each time one is added, so setting its total erased the first
 * kind and sent the count backwards on every reinstall -- which is what a
 * daemon polling SIOCGETSGCNT prunes on. mlxsw can set, because its counter
 * is the route's from creation and counts trapped packets too; this one
 * exists only while the group is in hardware.
 *
 * What the hardware matched after the last fold is read before a group's entry
 * is deleted and folded then, so nothing is lost when it leaves hardware, and
 * the count never goes backwards.
 */
static void ft_mr_fold(struct ft_mr_group *g, const struct cdx_ft_counters *c,
		       u8 tags)
{
	u64 packets, bytes;

	/* One hardware group's counters only grow, and so does a route's, and
	 * the worker zeroes the baseline for a new group; a sample below it adds
	 * nothing, and a second in a row moves the baseline there. See
	 * ft_mc_count_delta(). */
	if (!ft_mc_count_delta(&g->folded_packets, &g->folded_bytes,
			       &g->fold_suspect, c, &packets, &bytes))
		return;
	/* Bytes without a packet are a sample taken between the two loads;
	 * they belong to the next fold, which will see the packet too. */
	if (!packets)
		return;
	g->folded_packets = c->packets;
	g->folded_bytes = c->bytes;
	bytes -= min_t(u64, bytes,
		       packets * (u64)(ETH_HLEN + tags * VLAN_HLEN));
	atomic_long_add(packets, &g->mfc->mfc_un.res.pkt);
	atomic_long_add(bytes, &g->mfc->mfc_un.res.bytes);
	WRITE_ONCE(g->mfc->mfc_un.res.lastuse, jiffies);
}

/* What the hardware counted for a group, and the ingress framing that count
 * includes: its own entry's, or for a group routed through a bridge, what the
 * bridged group carrying its copies counted -- every frame of which the bridge
 * would have handed to ipmr. False, with nothing counted, while nothing in
 * hardware carries it or its count could not be read; see
 * cdx_mc_group_stats(). Called with ft_mr_lock and the transaction held.
 *
 * A route's count starts from zero only when the route is linked or
 * withdrawn, and says so with a new series; the baseline goes back to zero
 * with it and at no other time. Not when the group lets go of its bridge and
 * derives it again -- a bridge going down and coming back leaves the route
 * published and its count going on, and a baseline taken from zero then would
 * add everything the route had carried to the MFC's count a second time. */
static void ft_mr_route_baseline(struct ft_mr_group *g, u32 series)
{
	if (series == g->folded_series)
		return;
	g->folded_series = series;
	g->folded_packets = g->folded_bytes = 0;
	g->fold_suspect = false;
}

static bool ft_mr_counters(struct ft_mr_group *g, struct cdx_ft_counters *c,
			   u8 *tags)
{
	u32 series;

	*tags = g->in_tags;
	if (g->hw)
		return cdx_mc_group_stats(g->hw, c);
	if (g->route && ft_mc_route_state(g->route, c, tags, &series)) {
		ft_mr_route_baseline(g, series);
		return true;
	}
	memset(c, 0, sizeof(*c));
	return false;
}

/* Take a group's route back, and fold what it counted since the last fold
 * first: the route's count goes to zero with it, and what ipmr would have
 * counted of those frames is the MFC's all the same. Folded against the
 * baseline of its own run, and so called while that is still the baseline --
 * before an entry of the group's own is added, which takes the baseline from
 * zero, and before the group lets go of the MFC entry. What a bridged entry
 * carrying the route matched since the bridged learner last sampled it is
 * not in the count yet and is not folded: sampling it here, off that
 * learner's schedule, would shorten the interval its ageing judges an entry
 * idle by.
 *
 * Takes ft_mc_lock for the withdrawal and ft_mr_lock for the fold, one after
 * the other and never nested, so it is called holding neither. */
static void ft_mr_route_retire(struct ft_mr_group *g)
{
	struct cdx_ft_counters last;
	u32 series;
	u8 tags;

	if (!ft_mc_route_withdraw(g->route, &last, &tags, &series))
		return;
	mutex_lock(&ft_mr_lock);
	ft_mr_route_baseline(g, series);
	ft_mr_fold(g, &last, tags);
	mutex_unlock(&ft_mr_lock);
}

/* The copies half of the installed set: the listeners, what was derived from
 * them, and the recorded spec, which borrows them. */
static void ft_mr_release_copies(struct ft_mr_group *g)
{
	u8 i;

	for (i = 0; i < g->listeners; i++)
		if (g->listener[i].dev)
			dev_put(g->listener[i].dev);
	memset(g->listener, 0, sizeof(g->listener));
	g->listeners = 0;
	g->mtu = 0;
	g->oifs[0] = '\0';
	memset(&g->hw_spec, 0, sizeof(g->hw_spec));
}

static void ft_mr_release_set(struct ft_mr_group *g)
{
	ft_mr_release_copies(g);
	if (g->in)
		dev_put(g->in);
	g->in = NULL;
	g->in_tags = 0;
	memset(g->in_vlan, 0, sizeof(g->in_vlan));
	if (g->via)
		dev_put(g->via);
	g->via = NULL;
	g->via_vid = 0;
	g->via_tagged = false;
}

static void ft_mr_group_free(struct ft_mr_group *g)
{
	/* Before the reference goes. mr_cache_put() can free the entry through
	 * RCU, and a flag cleared after that is written into freed memory. */
	ft_mr_offload_flag(g, false);
	ft_mr_release_set(g);
	/* The entry's hold, once the caller has deleted the entry. */
	WARN_ON_ONCE(g->hw);
	if (g->hw_in)
		dev_put(g->hw_in);
	g->hw_in = NULL;
	ft_mr_watch_drop(g);
	/* Off the bridged learner's list before it is freed: that is what
	 * clears every pointer the bridged groups hold to it. And what it
	 * counted since the last fold into the MFC entry while the group still
	 * holds it: at unload the entry outlives the adapter. */
	if (g->route) {
		ft_mr_route_retire(g);
		kfree(g->route);
	}
	mr_cache_put(g->mfc);
	kfree(g);
}

/* A device this learner holds is going away or has stopped forwarding.
 *
 * Runs from the netdev chain under RTNL, so it may take ft_mr_lock and must
 * not touch the backend. The group's own references on the device are dropped
 * here and the group asked again.
 *
 * A listener's device takes the copies half of the set with it and nothing
 * else: the ingress is still the one the entry is keyed on, so the worker can
 * rebuild the chain under the same root rather than read a released ingress
 * as a new key and take the stream out of hardware to re-add it. Only the
 * ingress's own device, or its bridge's, releases the whole set; the entry
 * still naming it is then deleted by the worker this schedules, and keeps a
 * reference of its own on its ingress until then (`hw_in`), because the
 * delete goes through it; unregistration waits for that only as long as the
 * worker takes to run. The bridged learner answers the same window the same
 * way.
 */
void ft_mr_device_gone(struct net_device *dev)
{
	struct ft_mr_group *g;
	bool changed = false;
	u8 i;

	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list) {
		bool ingress = g->in == dev || g->via == dev;
		bool copy = false;

		for (i = 0; i < g->listeners; i++)
			copy |= g->listener[i].dev == dev;
		if (!ingress && !copy)
			continue;
		if (ingress)
			ft_mr_release_set(g);
		else
			ft_mr_release_copies(g);
		g->retries = 0;
		g->dirty = true;
		changed = true;
	}
	/* The bridged learner lets go of the taps on a bridge that goes down,
	 * and ipmr keeps its VIFs across a down and up, so no VIF event would
	 * ever publish them again. */
	if (netif_is_bridge_master(dev)) {
		ft_mr_taps_stale = true;
		changed = true;
	}
	mutex_unlock(&ft_mr_lock);
	if (changed && !READ_ONCE(ft_mr_stopping))
		schedule_work(&ft_mr_work);
}

/* Whether a group's installed chain may have a listener on `dev`. `listener[]`
 * is the installed set, and stays so while the worker decides a group: it is
 * replaced only when the outcome is recorded. A group whose copies were
 * released (ft_mr_device_gone()) while its hardware stayed could have any port
 * in it.
 * Called with ft_mr_lock held. */
static bool ft_mr_may_list(const struct ft_mr_group *g,
			   const struct net_device *dev)
{
	u8 i;

	if (!g->listeners)
		return true;
	for (i = 0; i < g->listeners; i++)
		if (g->listener[i].dev == dev)
			return true;
	return false;
}

/* This learner's half of ft_mc_egress_changed(): every installed group that
 * may copy out of `dev` is marked stale and handed to the worker, whose replace
 * rebuilds the whole chain even when the plan has not changed. A group the
 * worker is deciding is marked and left to it: the worker sees the mark, or
 * the count, when it records the outcome. A group routed through a bridge has
 * no chain of its own; its copies are the bridged flow's, marked by the other
 * half. Takes ft_mr_lock and nothing else. Returns how many were marked. */
static unsigned int ft_mr_egress_mark(const struct net_device *dev)
{
	unsigned int marked = 0;
	struct ft_mr_group *g;

	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list) {
		if (!g->hw || !ft_mr_may_list(g, dev))
			continue;
		g->egress_stale = true;
		if (!g->busy)
			g->dirty = true;
		marked++;
	}
	if (marked && !ft_mr_stopping)
		schedule_work(&ft_mr_work);
	mutex_unlock(&ft_mr_lock);
	return marked;
}

/* Rebuild what ft_mr_egress_mark(dev) marked, here and now.
 *
 * Waiting for the worker is not an option: it takes RTNL to decide, and the
 * caller holds RTNL. Nor is a decision needed. The port's membership did not
 * change, only its queues, so the installed chain is replaced by itself --
 * the spec it was built from, recorded whole, ingress tags included, its
 * devices still pinned by the installed set -- which rebuilds every listener
 * entry against the port as it is now. Transaction first and ft_mr_lock
 * inside it, the order /proc takes them in. A group the kernel deleted leaves
 * the list and the hardware in one transaction hold (ft_mr_work_fn(), step
 * 4), so none is missed here for being off the list with its entry still
 * installed.
 *
 * That holds for a group the worker is deciding too, which is the common case:
 * the refresh keeps the worker busy, and a worker that picked a group is
 * waiting for the RTNL this caller holds. The worker builds and records inside
 * the transaction, so here a group is never half-built; its hardware and set
 * are the installed ones until the worker's own pass replaces them.
 *
 * A group that cannot be rebuilt here -- its copies were released, or the
 * replace failed and it is handed back to the worker, whose own failed
 * replace withdraws it in one pass -- is reported with -EAGAIN. */
int ft_mr_egress_drain(const struct net_device *dev)
{
	struct ft_mr_group *g;
	bool kick = false;
	int rc = 0;

	cdx_ft_begin();
	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list) {
		if (!g->egress_stale || !ft_mr_may_list(g, dev))
			continue;
		if (!g->hw) {
			g->egress_stale = false;
			continue;
		}
		if (!g->hw_spec.listeners ||
		    cdx_mc_group_replace(g->hw, &g->hw_spec)) {
			g->dirty = true;
			kick = true;
			rc = -EAGAIN;
			continue;
		}
		g->egress_stale = false;
	}
	mutex_unlock(&ft_mr_lock);
	cdx_ft_end();
	if (kick && !READ_ONCE(ft_mr_stopping))
		schedule_work(&ft_mr_work);
	return rc;
}

/* Whether another group of this learner has an entry under the key a spec
 * would install: the same port and address pair. Called with ft_mr_lock
 * held. */
static bool ft_mr_key_taken(const struct ft_mr_group *g,
			    const struct cdx_mc_group_spec *spec)
{
	const struct ft_mr_group *o;

	list_for_each_entry(o, &ft_mr_groups, list)
		if (o != g && o->hw && o->in == spec->in &&
		    o->family == g->family &&
		    !memcmp(&o->src, &g->src, sizeof(o->src)) &&
		    !memcmp(&o->dst, &g->dst, sizeof(o->dst)))
			return true;
	return false;
}

/* Publish the copies of a group routed through a bridge. Returns 1 when a
 * bridged group is carrying them, 0 when none is yet, or -ENOMEM. Called from
 * the worker with no lock held: the publication takes ft_mc_lock, and the
 * route is reached from /proc under ft_mr_lock, so it is attached under that
 * and filled in outside it. */
static int ft_mr_publish(struct ft_mr_group *g, const struct ft_mr_plan *plan)
{
	struct ft_mc_route want = {};

	if (!g->route) {
		struct ft_mc_route *route = kzalloc(sizeof(*route), GFP_KERNEL);

		if (!route)
			return -ENOMEM;
		INIT_LIST_HEAD(&route->list);
		mutex_lock(&ft_mr_lock);
		g->route = route;
		mutex_unlock(&ft_mr_lock);
	}
	want.bridge = plan->via;
	want.vid = plan->via_vid;
	want.tagged = plan->via_tagged;
	want.family = g->family;
	want.src = g->src;
	want.dst = g->dst;
	memcpy(want.listener, plan->spec.listener, sizeof(want.listener));
	want.listeners = plan->spec.listeners;
	want.mtu = plan->mtu;
	return ft_mc_route_publish(g->route, &want) ? 1 : 0;
}

/* Tell the bridged learner where this learner's VIFs sit on bridges: where
 * the host receives what a bridge hands it, route or none. Called from the
 * worker with no lock held. The table is read under ft_mr_lock and each
 * bridge held for the moment between the two locks.
 *
 * A mirror a lost notification invalidated cannot say where the VIFs are,
 * and says instead that they may be anywhere -- which keeps every group a
 * multicast-router bridge hands the host in software until it is whole. */
static void ft_mr_publish_taps(void)
{
	struct ft_mc_tap taps[FT_MC_TAPS] = {};
	unsigned int idx, i, n = 0;
	bool overflow;

	mutex_lock(&ft_mr_lock);
	if (!ft_mr_taps_stale && !READ_ONCE(ft_mr_resync_pending)) {
		mutex_unlock(&ft_mr_lock);
		return;
	}
	ft_mr_taps_stale = false;
	/* A policy rule can send a stream to a table whose VIFs this learner
	 * does not mirror, so with one present they may be anywhere too. */
	overflow = READ_ONCE(ft_mr_resync_pending) != 0 ||
		   ft_mr_policy[0] || ft_mr_policy[1];
	for (idx = 0; idx < ARRAY_SIZE(ft_mr_vif); idx++)
		for (i = 0; i < MAXVIFS; i++) {
			struct net_device *dev = ft_mr_vif[idx][i].dev;
			struct net_device *bridge;
			bool tagged;
			u16 vid;

			if (!dev)
				continue;
			bridge = ft_mr_ingress_bridge(dev, &vid, &tagged);
			if (!bridge)
				continue;
			if (n == FT_MC_TAPS) {
				overflow = true;
				continue;
			}
			dev_hold(bridge);
			taps[n].bridge = bridge;
			taps[n].vid = vid;
			taps[n].tagged = tagged;
			taps[n].family = idx ? AF_INET6 : AF_INET;
			n++;
		}
	mutex_unlock(&ft_mr_lock);
	ft_mc_taps_publish(taps, n, overflow);
	for (i = 0; i < n; i++)
		dev_put(taps[i].bridge);
}

/* What the worker's pass for `g` came to, recorded with ft_mr_lock held and,
 * when the pass built anything, still inside its transaction, so nothing else
 * that takes the transaction -- /proc, the fold, the egress drain -- sees the
 * group half changed. `hw` is the group's hardware now and `plan` what the
 * pass derived; `touched` says the pass programmed the hardware, with the
 * egress count read as `changes` before it did. `last` is what an entry the
 * pass deleted had counted, if that was read, and `added` and `deleted` say
 * the entry is new or went; the ingress hold of one that went is handed back
 * in `put_in`, to be dropped outside the lock. Returns the group's state.
 *
 * A chain built whole after the last egress change is current; one built
 * across a change is not, and neither is one left alone while a change asked
 * for it meanwhile. Nothing installed is nothing stale. */
static enum ft_mr_state ft_mr_record(struct ft_mr_group *g, struct cdx_mc_group *hw,
				     enum ft_mr_state state, int rc,
				     struct ft_mr_plan *plan, bool touched, s64 changes,
				     const struct cdx_ft_counters *last, bool deleted,
				     bool added, struct net_device **put_in)
{
	lockdep_assert_held(&ft_mr_lock);
	if (state == FT_MR_PENDING && !plan->via && !rc && hw)
		state = FT_MR_INSTALLED;
	g->hw = hw;
	/* The entry's own hold on its ingress: let go with the entry just
	 * deleted, taken for the one just added. */
	if (deleted) {
		*put_in = g->hw_in;
		g->hw_in = NULL;
	}
	if (added) {
		dev_hold(plan->spec.in);
		g->hw_in = plan->spec.in;
	}
	/* The entry just deleted, folded against the baseline it was counted
	 * from and with the framing it was installed with -- both still the
	 * old set's until the plan is adopted below. */
	if (last)
		ft_mr_fold(g, last, g->in_tags);
	/* A group made in this pass counts from zero, whatever the last one
	 * had reached. Here, not by comparing handles: the one a delete frees
	 * is the next add's allocation often enough. A route's count is told
	 * apart by its series instead (ft_mr_counters()), which the baseline
	 * no longer belongs to once it is the entry's. */
	if (added) {
		g->folded_packets = g->folded_bytes = 0;
		g->folded_series = 0;
		g->fold_suspect = false;
		g->adds++;
	}
	if (state == FT_MR_INSTALLED || state == FT_MR_BRIDGED) {
		/* Adopt the plan whole, references included: the backend
		 * borrows exactly these pointers, so a group owning some of them
		 * would name one it did not. */
		ft_mr_release_set(g);
		g->in = plan->spec.in;
		g->in_tags = plan->in_tags;
		memcpy(g->in_vlan, plan->spec.in_vlan, sizeof(g->in_vlan));
		g->via = plan->via;
		g->via_vid = plan->via_vid;
		g->via_tagged = plan->via_tagged;
		g->mtu = plan->mtu;
		g->listeners = plan->spec.listeners;
		memcpy(g->listener, plan->spec.listener, sizeof(g->listener));
		strscpy(g->oifs, plan->oifs, sizeof(g->oifs));
		/* And the spec itself, for the egress drain to rebuild the
		 * entry with -- only for an entry of the group's own. */
		if (hw)
			g->hw_spec = plan->spec;
		memset(plan, 0, sizeof(*plan));
		g->retries = 0;
	} else {
		/* A failed update was withdrawn: an incomplete old listener
		 * set cannot stand in for the requested one. */
		if (!hw)
			ft_mr_release_set(g);
		/* Named in /proc beside the ones still unseen. */
		if (state == FT_MR_UNCONFIRMED)
			strscpy(g->oifs, plan->oifs, sizeof(g->oifs));
		/* Tried again at the next refresh, which asks every group below
		 * the ceiling again, not now: a port that lost carrier, or room
		 * another entry is about to give back, needs time rather than
		 * repetition. */
		if (rc && ++g->retries >= FT_MR_MAX_RETRIES)
			state = FT_MR_REFUSED_FAILED;
	}
	if (ft_mr_refusal(state) && !ft_mr_refusal(g->state))
		ft_mr_refused++;
	g->state = state;
	g->busy = false;
	if (!hw) {
		g->egress_stale = false;
	} else if (touched && atomic64_read(&ft_egress_changes) != changes) {
		g->egress_stale = true;
		g->dirty = true;
	} else if (touched && !rc) {
		g->egress_stale = false;
	} else if (g->egress_stale) {
		g->dirty = true;
	}
	return state;
}

static void ft_mr_work_fn(struct work_struct *work)
{
	struct ft_mr_group *g, *tmp;
	struct ft_mr_event *ev;
	unsigned int restarts = 0, xt_seq, budget;
	unsigned long unresolved;
	bool retiring, more = false;
	LIST_HEAD(dead);

	/* Registration may replay its dump after a sequence mismatch. Do not
	 * apply those attempts before the initial authoritative resync. */
	if (!smp_load_acquire(&ft_mr_ready))
		return;
	/* How many decisions this run makes before it hands the rest to the
	 * next: every group twice, room for one rebuilt in the same run, and
	 * no more, so a run ends even while the stats tick re-dirties groups
	 * faster than they can be decided (each takes RTNL). */
	budget = 2 * READ_ONCE(ft_mr_count) + 8;
again:
	retiring = false;
	/* 1. What the chain saw. */
	for (;;) {
		spin_lock_bh(&ft_mr_queue_lock);
		ev = list_first_entry_or_null(&ft_mr_queue,
					      struct ft_mr_event, list);
		if (ev)
			list_del(&ev->list);
		spin_unlock_bh(&ft_mr_queue_lock);
		if (!ev)
			break;
		mutex_lock(&ft_mr_lock);
		if (!ft_mr_stopping && !ft_mr_apply(ev))
			ft_mr_lost_event(ev->family);
		mutex_unlock(&ft_mr_lock);
		ft_mr_event_free(ev);
	}
	/* The families this run tried to resync and could not, as the resync
	 * found them: a group of one is refused below rather than sent back to
	 * try again, while one asked for since is resynced first. */
	unresolved = 0;
	if (READ_ONCE(ft_mr_resync_pending) && !READ_ONCE(ft_mr_stopping))
		unresolved = ft_mr_resync();

	/* 2. Anything outside this learner that stales an answer it gave: a
	 * ruleset commit takes back every confirmation, and every group is
	 * asked again, the carried ones going back to software. An x_tables
	 * change takes back no confirmation, but every group is asked again
	 * all the same: read before any walk, a change after it moves the
	 * count again. */
	if (!READ_ONCE(ft_mr_stopping) && ft_mr_ruleset_sync())
		WRITE_ONCE(ft_mr_recheck, true);
	xt_seq = nf_xt_seq(&init_net);
	if (!READ_ONCE(ft_mr_stopping) && xt_seq != ft_mr_xt_seen) {
		WRITE_ONCE(ft_mr_xt_seen, xt_seq);
		if (ft_mr_count)
			ft_mr_xtables_changes++;
		WRITE_ONCE(ft_mr_recheck, true);
	}
	if (READ_ONCE(ft_mr_recheck)) {
		WRITE_ONCE(ft_mr_recheck, false);
		mutex_lock(&ft_mr_lock);
		ft_mr_dirty_family(AF_INET);
		ft_mr_dirty_family(AF_INET6);
		mutex_unlock(&ft_mr_lock);
	}
	/* And a group whose last oif has just been seen is asked again, which
	 * is what carries it. */
	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list)
		if (g->watch && xchg(&g->watch->news, false))
			g->dirty = true;
	mutex_unlock(&ft_mr_lock);

	/* 3. Where VIFs sit on bridges, for the bridged learner. */
	if (!READ_ONCE(ft_mr_stopping))
		ft_mr_publish_taps();

	/* 4. Entries the kernel has deleted. Off the list and out of the
	 * hardware in one transaction hold, for the reason the bridged learner
	 * retires its flows that way: the egress drain reads the list under
	 * the transaction, and a group gone from it with its entry still
	 * installed is one the drain would vouch for without having seen.
	 * Only this worker marks a group gone, so the look beforehand, which
	 * spares a pass with nothing to retire the transaction, cannot miss
	 * one. */
	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list)
		if (g->gone) {
			retiring = true;
			break;
		}
	mutex_unlock(&ft_mr_lock);
	if (retiring) {
		cdx_ft_begin();
		mutex_lock(&ft_mr_lock);
		list_for_each_entry_safe(g, tmp, &ft_mr_groups, list) {
			if (!g->gone)
				continue;
			list_move(&g->list, &dead);
			ft_mr_count--;
		}
		mutex_unlock(&ft_mr_lock);
		list_for_each_entry(g, &dead, list) {
			if (!g->hw)
				continue;
			/* Even while stopping: this group is already off the
			 * list ft_mr_exit() drains, so leaving it would strand
			 * the entry, its group id and its listener chain with
			 * nothing left to own them. */
			cdx_mc_group_del(&g->hw);
			ft_mr_installed--;
			ft_mr_key_freed = true;
		}
		cdx_ft_end();
	}
	list_for_each_entry_safe(g, tmp, &dead, list) {
		list_del(&g->list);
		ft_mr_group_free(g);
	}
	/* Room again for an entry the cap turned away: the resync, at the top
	 * of the next run, finds it. */
	if (retiring && READ_ONCE(ft_mr_capped) && !READ_ONCE(ft_mr_stopping)) {
		unsigned long capped = xchg(&ft_mr_capped, 0);
		unsigned int idx;

		for_each_set_bit(idx, &capped, 2)
			set_bit(idx, &ft_mr_resync_pending);
		schedule_work(&ft_mr_work);
	}

	/* 5. One group per pass: the transaction is dropped between each,
	 * because ft_mr_lock is never held across taking it.
	 *
	 * The group is marked busy while it is decided, but its hardware and
	 * installed set stay the group's until this pass is inside the
	 * transaction, and the outcome is recorded, with ft_mr_lock taken
	 * inside the transaction for the record alone, before the pass leaves
	 * it.
	 * A drain (ft_mr_egress_drain()) takes the transaction too, so it only
	 * ever sees a group that is either not yet being built or already
	 * recorded -- and can rebuild it in place, rather than wait for a worker
	 * that may itself be waiting on the drain's caller for RTNL. */
	for (;;) {
		struct ft_mr_group *target = NULL;
		struct net_device *put_in = NULL;
		struct cdx_mc_group *hw = NULL;
		struct ft_mr_plan plan = {};
		enum ft_mr_state state;
		bool rekey = false, same = false, via, installed;
		bool added = false, counted = false, deleted = false;
		bool touched = false, recorded = false;
		struct cdx_ft_counters last;
		s64 changes = 0;
		u8 retries = 0;
		int rc = 0;

		mutex_lock(&ft_mr_lock);
		/* A group refused a key another gave up since is asked again,
		 * within this same pass. */
		if (ft_mr_key_freed) {
			ft_mr_key_freed = false;
			list_for_each_entry(g, &ft_mr_groups, list)
				if (g->state == FT_MR_REFUSED_CONTESTED)
					g->dirty = true;
		}
		list_for_each_entry(g, &ft_mr_groups, list) {
			if (!g->dirty || g->gone || ft_mr_stopping)
				continue;
			/* Spent: the next run, which the end of this one
			 * queues, takes it. */
			if (!budget) {
				more = true;
				break;
			}
			budget--;
			target = g;
			break;
		}
		if (target) {
			target->dirty = false;
			target->busy = true;
			retries = target->retries;
			/* To the back of the list, so a run the stats tick
			 * re-dirties every group behind reaches the tail
			 * before it decides the head again. */
			list_move_tail(&target->list, &ft_mr_groups);
		}
		mutex_unlock(&ft_mr_lock);
		if (!target)
			break;

		/* Decide under RTNL with no learner mutex held across the walk:
		 * it reads bridge and netdev state, including the kernel's
		 * current MDB and router-port set. Nothing in it touches
		 * hardware, and nothing but this worker adds or deletes the
		 * group's entry -- a drain only rebuilds it in place -- so
		 * whether it has one is the same answer inside the transaction
		 * below. */
		rtnl_lock();
		/* And against the chain as it stands now, not as it stood when
		 * the queue was last applied: what it said while this worker
		 * waited for the lock is applied first, from the top, and the
		 * group is picked again. It is handed back as it was picked --
		 * nothing of it was decided or built -- and asked again: what
		 * was queued need not ask it, a VIF in another table or the
		 * default rule for one. Bounded, so a chain that never falls
		 * quiet delays a decision rather than preventing it; a removed
		 * VIF is still answered then, by ft_mr_vif_dev(). */
		if (restarts < FT_MR_MAX_RESTARTS &&
		    ft_mr_queue_behind(target, unresolved)) {
			rtnl_unlock();
			mutex_lock(&ft_mr_lock);
			target->busy = false;
			target->dirty = true;
			budget++;	/* handed back undecided */
			mutex_unlock(&ft_mr_lock);
			restarts++;
			goto again;
		}
		if (test_bit(ft_mr_idx(target->family), &ft_mr_resync_pending))
			state = FT_MR_REFUSED_RESYNC;
		else
			state = retries >= FT_MR_MAX_RETRIES ?
				FT_MR_REFUSED_FAILED : ft_mr_derive(target, &plan);
		/* Watched for its oifs once they are known, refused or not, so
		 * a group held back for its policy, a host membership or its
		 * MTU is confirmed meanwhile; and carried only once every one of
		 * them has been seen. */
		if (plan.oifs_known)
			ft_mr_watch_arm(target, &plan);
		if (state == FT_MR_PENDING)
			state = ft_mr_admit(target, &plan);
		mutex_lock(&ft_mr_lock);
		installed = !!target->hw;
		/* cdx_mc_group_replace() refuses a spec whose ingress differs
		 * from the installed one -- the port is part of the classifier
		 * key -- so a parent VIF that moved is a delete and an add
		 * rather than a replacement. Decided here rather than after
		 * the unlock because ft_mr_device_gone() clears the installed
		 * ingress when its device goes, and holds RTNL to do it. */
		via = state == FT_MR_PENDING && plan.via;
		rekey = installed && (via || plan.spec.in != target->in ||
				      plan.in_tags != target->in_tags ||
				      memcmp(plan.spec.in_vlan, target->in_vlan,
					     sizeof(target->in_vlan)));
		/* An unchanged plan still rebuilds a chain an egress change
		 * marked: every entry in it names the queue it was built with. */
		same = installed && !via && !target->egress_stale &&
		       state == FT_MR_PENDING && ft_mr_plan_same(target, &plan);
		mutex_unlock(&ft_mr_lock);
		rtnl_unlock();

		/* Not routed through a bridge from here on: what it published,
		 * if it ever did, is taken back, and what that counted since the
		 * last fold is folded first -- here, before an entry of its own
		 * can be added below and take the baseline from zero. It takes
		 * ft_mc_lock, so it runs under no lock of this learner. */
		if (!via && target->route)
			ft_mr_route_retire(target);

		/* A new root needs its key to itself. Any other group of this
		 * learner holding it arrives on the same port, from the same
		 * source to the same group -- another VLAN of the port, which
		 * the key does not name -- and the one root could validate only
		 * one of the two tag stacks. A replace keeps its key. */
		if (state == FT_MR_PENDING && !via && (!installed || rekey)) {
			mutex_lock(&ft_mr_lock);
			if (ft_mr_key_taken(target, &plan.spec))
				state = FT_MR_REFUSED_CONTESTED;
			mutex_unlock(&ft_mr_lock);
		}

		if (!same && (installed || (state == FT_MR_PENDING && !via))) {
			/* The hardware with the transaction alone, and ft_mr_lock
			 * only to record: what must not see a group half built
			 * takes the transaction first, and what takes only the
			 * lock under RTNL -- the netdev events, the egress mark --
			 * never waits behind a hardware call. What they change
			 * meanwhile is the record's to see: a mark by the egress
			 * count, a released set by the plan's own references,
			 * which the record adopts. The group's entry is changed
			 * only here, so it is read without the lock. */
			cdx_ft_begin();
			hw = target->hw;
			/* Before anything is built: see ft_egress_changes. */
			changes = atomic64_read_acquire(&ft_egress_changes);
			touched = true;
			/* The switch again, under the transaction /proc is read
			 * through: the contract was answered before it, and a
			 * stop that has read nothing installed must not see
			 * this pass's add land afterwards. As a refusal, it
			 * takes the delete below and records like any other. */
			if (state == FT_MR_PENDING && !READ_ONCE(ft_mc_enabled))
				state = FT_MR_REFUSED_PAUSED;
			/* And an XFRM policy that changed since the contract
			 * was answered: this pass is refused, and the next,
			 * which the change queued, asks again. */
			if (state == FT_MR_PENDING && target->family == AF_INET &&
			    xfrm_flowtable_genid(&init_net) != plan.xfrm_genid)
				state = FT_MR_REFUSED_XFRM;
			/* What an entry counted since the last fold goes with it
			 * unless it is read first; it is folded as the outcome is
			 * recorded, against the set it was installed with. */
			if (hw && (rekey || state != FT_MR_PENDING)) {
				counted = cdx_mc_group_stats(hw, &last);
				cdx_mc_group_del(&hw);
				deleted = true;
				ft_mr_installed--;
				ft_mr_key_freed = true;
			}
			if (state == FT_MR_PENDING && !via) {
				if (hw) {
					rc = cdx_mc_group_replace(hw,
								  &plan.spec);
					if (rc) {
						/* The old set can omit a newly learned
						 * router. Return the entire stream to
						 * software until a full set installs. */
						counted = cdx_mc_group_stats(hw, &last);
						cdx_mc_group_del(&hw);
						deleted = true;
						ft_mr_installed--;
						ft_mr_key_freed = true;
					}
				} else {
					rc = cdx_mc_group_add(&plan.spec, &hw);
					/* The ids are both learners': one a
					 * bridged discard holds is given up
					 * for this group's copies, and the add
					 * made again at once. ft_mr_lock and
					 * RTNL are both let go of here. */
					if (rc == -ENOSPC &&
					    ft_mc_evict_discard(plan.spec.family))
						rc = cdx_mc_group_add(&plan.spec, &hw);
					if (rc) {
						hw = NULL;
					} else {
						ft_mr_installed++;
						added = true;
					}
				}
			}
			if (rc)
				ft_mr_install_errors++;
			mutex_lock(&ft_mr_lock);
			if (!via) {
				state = ft_mr_record(target, hw, state, rc, &plan,
						     touched, changes,
						     counted ? &last : NULL,
						     deleted, added, &put_in);
				recorded = true;
			} else {
				/* Routed through a bridge from here on: its own
				 * entry is gone, and recorded gone before the
				 * transaction is let go. The rest is recorded
				 * once the copies are published below. */
				target->hw = NULL;
				if (deleted) {
					put_in = target->hw_in;
					target->hw_in = NULL;
				}
				if (counted)
					ft_mr_fold(target, &last, target->in_tags);
			}
			mutex_unlock(&ft_mr_lock);
			cdx_ft_end();
		}

		/* Routed through a bridge: the copies are the bridged group's to
		 * carry, and whether it does is this group's state. It takes
		 * ft_mc_lock, so it runs under no lock of this learner. Not once
		 * the transaction found the switch off: the next pass, which the
		 * switch queued, takes the route back. */
		if (via && state == FT_MR_PENDING) {
			rc = ft_mr_publish(target, &plan);
			if (rc < 0)
				ft_mr_install_errors++;
			else
				state = rc ? FT_MR_INSTALLED : FT_MR_BRIDGED;
			rc = min(rc, 0);
		}

		if (!recorded) {
			mutex_lock(&ft_mr_lock);
			state = ft_mr_record(target, target->hw, state, rc, &plan,
					     touched, changes, NULL, false, false,
					     &put_in);
			mutex_unlock(&ft_mr_lock);
		}

		/* Outside every lock this worker holds, because it takes
		 * RTNL. */
		ft_mr_offload_flag(target, state == FT_MR_INSTALLED);
		ft_mr_plan_put(&plan);
		if (put_in)
			dev_put(put_in);
	}

	/* What the budget left undecided is the next run's. */
	if (more && !READ_ONCE(ft_mr_stopping))
		schedule_work(&ft_mr_work);

	/* The forwarding check exists while a group is watched; the ruleset is
	 * followed while any group exists, and a settling one is looked at
	 * again when it will have settled. */
	ft_mr_confirm_sync();
	if (ft_mr_count && !READ_ONCE(ft_mr_stopping)) {
		if (READ_ONCE(ft_mr_gen_open))
			schedule_delayed_work(&ft_mr_ruleset,
					      FT_MR_RULESET_INTERVAL);
		else
			mod_delayed_work(system_wq, &ft_mr_ruleset,
					 ft_mr_ruleset_wait());
		/* A port walk a commit interrupted is asked again a short while
		 * on, not at once: a commit being prepared can take a while to
		 * land, and asking in a loop meanwhile would spin the worker. */
		if (READ_ONCE(ft_mr_probe_again))
			mod_delayed_work(system_wq, &ft_mr_ruleset,
					 FT_MR_RULESET_APPLYING);
	}
	if ((ft_mr_count || READ_ONCE(ft_mr_resync_pending)) &&
	    !READ_ONCE(ft_mr_stopping))
		schedule_delayed_work(&ft_mr_stats, FT_MR_STATS_INTERVAL);
}

/* The periodic half of the counter fold. /proc does the other half on read, so
 * a reader always sees fresh numbers and a daemon polling SIOCGETSGCNT sees
 * them within one interval without anybody reading /proc at all. */
static void ft_mr_stats_fn(struct work_struct *work)
{
	struct cdx_ft_counters stats;
	struct ft_mr_group *g;
	u8 tags;

	if (READ_ONCE(ft_mr_stopping))
		return;
	/* The transaction first and the lock second, which is the order /proc
	 * takes them in and therefore the only one either may. */
	cdx_ft_begin();
	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list) {
		/* Querier timers and per-VLAN snooping changes have no complete
		 * switchdev notification. Refresh from the live bridge within
		 * one interval, including groups currently refused. Preserve
		 * the retry ceiling; real control-plane events reset it. */
		if (!g->gone && g->retries < FT_MR_MAX_RETRIES)
			g->dirty = true;
		if (ft_mr_counters(g, &stats, &tags))
			ft_mr_fold(g, &stats, tags);
	}
	mutex_unlock(&ft_mr_lock);
	cdx_ft_end();
	if ((ft_mr_count || READ_ONCE(ft_mr_resync_pending)) &&
	    !READ_ONCE(ft_mr_stopping)) {
		schedule_work(&ft_mr_work);
		schedule_delayed_work(&ft_mr_stats, FT_MR_STATS_INTERVAL);
	}
}

void ft_mr_exit(void)
{
	struct ft_mr_group *g, *tmp;
	struct ft_mr_event *ev, *evtmp;
	unsigned int idx, i;

	mutex_lock(&ft_mr_lock);
	WRITE_ONCE(ft_mr_stopping, true);
	mutex_unlock(&ft_mr_lock);
	/* The forwarding check wakes the worker, so it goes first, and waits
	 * out the copies already inside it. */
	ft_mr_confirm_sync();
	/* The refresh and the ruleset watch can queue the worker, and the
	 * worker can rearm both. Drain the producers first, then the worker,
	 * then any timer a worker already past its stopping check rearmed
	 * during the drain -- and any hook it registered. */
	cancel_delayed_work_sync(&ft_mr_stats);
	cancel_delayed_work_sync(&ft_mr_ruleset);
	cancel_work_sync(&ft_mr_work);
	cancel_delayed_work_sync(&ft_mr_stats);
	cancel_delayed_work_sync(&ft_mr_ruleset);
	ft_mr_confirm_sync();
	/* The chain is already unregistered by the caller, so nothing can add
	 * to either list while they drain. */
	list_for_each_entry_safe(ev, evtmp, &ft_mr_queue, list) {
		list_del(&ev->list);
		if (ev->mfc)
			mr_cache_put(ev->mfc);
		if (ev->dev)
			dev_put(ev->dev);
		kfree(ev);
	}
	list_for_each_entry_safe(g, tmp, &ft_mr_groups, list) {
		if (g->hw) {
			struct cdx_ft_counters last;

			cdx_ft_begin();
			/* What the entry counted since the last fold, into the
			 * MFC entry, which outlives the adapter; the worker's own
			 * deletes read it the same way. */
			mutex_lock(&ft_mr_lock);
			if (cdx_mc_group_stats(g->hw, &last))
				ft_mr_fold(g, &last, g->in_tags);
			mutex_unlock(&ft_mr_lock);
			cdx_mc_group_del(&g->hw);
			cdx_ft_end();
		}
		list_del(&g->list);
		ft_mr_group_free(g);
	}
	for (idx = 0; idx < ARRAY_SIZE(ft_mr_vif); idx++)
		for (i = 0; i < MAXVIFS; i++) {
			if (ft_mr_vif[idx][i].dev)
				dev_put(ft_mr_vif[idx][i].dev);
			ft_mr_vif[idx][i].dev = NULL;
			ft_mr_vif[idx][i].flags = 0;
		}
	ft_mr_count = 0;
	ft_mr_installed = 0;
	ft_mr_policy[0] = 0;
	ft_mr_policy[1] = 0;
}

/* Have both learners reconsider every group they know: the bridged one
 * through its installable test, the routed one through its contract. Each is
 * woken under its own lock, where its exit sets the stopping flag before
 * cancelling its worker, so no wake can queue a worker exit has already
 * drained. The parameter stays writable through exit and until the module is
 * freed. */
void ft_mc_switched(void)
{
	mutex_lock(&ft_mc_lock);
	if (!ft_mc_stopping) {
		WRITE_ONCE(ft_mc_recheck, true);
		schedule_work(&ft_mc_work);
	}
	mutex_unlock(&ft_mc_lock);
	mutex_lock(&ft_mr_lock);
	if (!ft_mr_stopping) {
		WRITE_ONCE(ft_mr_recheck, true);
		schedule_work(&ft_mr_work);
	}
	mutex_unlock(&ft_mr_lock);
}

/* Woken only once initialization has both learners running; a value set
 * before that is read by their passes, and initialization wakes them once
 * more when it is done, for a flip that fell between. The barrier pairs with
 * the one queueing that wake implies, so one of the two sees the other's
 * store. Writers are serialized by the parameter lock. */
static int ft_mc_enabled_set(const char *val, const struct kernel_param *kp)
{
	bool was = READ_ONCE(ft_mc_enabled);
	int rc = param_set_bool(val, kp);

	if (rc || READ_ONCE(ft_mc_enabled) == was)
		return rc;
	pr_info("cdx flowtable: multicast acceleration %s\n",
		READ_ONCE(ft_mc_enabled) ? "on" : "off; every group returns to software");
	smp_mb();
	if (READ_ONCE(ft_ready))
		ft_mc_switched();
	return 0;
}

static const struct kernel_param_ops ft_mc_enabled_ops = {
	.set = ft_mc_enabled_set,
	.get = param_get_bool,
};
module_param_cb(multicast, &ft_mc_enabled_ops, &ft_mc_enabled, 0644);
MODULE_PARM_DESC(multicast, "Multicast acceleration: N returns every bridged and routed group to software and carries none until Y");

/* The oifs Linux has not yet been seen forwarding the group to under the
 * ruleset in force: what keeps a pending-confirm group in software. Written
 * name by name, since there can be as many as there are VIFs. The watch is
 * replaced under ft_mr_lock, which the caller holds, and freed after a grace
 * period; the names are read under RCU. */
static void ft_mr_unconfirmed(struct seq_file *seq, const struct ft_mr_group *g)
{
	bool any = false;
	u8 i;

	rcu_read_lock();
	for (i = 0; g->watch && i < g->watch->oifs; i++) {
		struct net_device *dev;

		if (test_bit(i, &g->watch->seen))
			continue;
		dev = dev_get_by_index_rcu(&init_net, g->watch->oif[i]);
		seq_printf(seq, "%s%s", any ? "," : "", dev ? dev->name : "?");
		any = true;
	}
	rcu_read_unlock();
	if (!any)
		seq_putc(seq, '-');
}

void ft_mr_rows(struct seq_file *seq)
{
	char listeners[224];
	struct cdx_ft_counters stats;
	struct ft_mr_group *g;
	u8 i, tags;

	/* Read outside the transaction the caller holds, which is what the
	 * ordering rule requires: /proc takes cdx_ft_begin() then this, so the
	 * worker must never take them the other way round. It does not. */
	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list) {
		size_t n = 0;

		/* A read is also a fold, so `ip -s mroute` and this file never
		 * disagree about how much the hardware has carried. A group
		 * routed through a bridge reads what the bridged learner last
		 * sampled, which lags by up to its refresh. */
		if (ft_mr_counters(g, &stats, &tags))
			ft_mr_fold(g, &stats, tags);
		listeners[0] = '\0';
		for (i = 0; i < g->listeners; i++)
			n += scnprintf(listeners + n, sizeof(listeners) - n,
				       "%s%s/%u", i ? "," : "",
				       g->listener[i].dev->name,
				       g->listener[i].vlans ?
					       g->listener[i].vlan[0].id : 0);
		if (g->family == AF_INET6)
			seq_printf(seq,
				   "mroute family=6 table=%u group=%pI6c src=%pI6c",
				   g->table, &g->dst.in6, &g->src.in6);
		else
			seq_printf(seq,
				   "mroute family=4 table=%u group=%pI4 src=%pI4",
				   g->table, &g->dst.ip, &g->src.ip);
		/* `in` names the port, or for a stream arriving through a
		 * bridge the bridge: its port is the bridged group's to know,
		 * and that group's row names it. */
		seq_printf(seq, " in=%s oifs=%s listeners=%s state=%s unconfirmed=",
			   g->in ? g->in->name : g->via ? g->via->name : "-",
			   g->oifs[0] ? g->oifs : "-",
			   g->listeners ? listeners : "-",
			   ft_mr_state_text(g->state));
		ft_mr_unconfirmed(seq, g);
		/* `adds` is the group's own: see struct ft_mr_group. */
		seq_printf(seq, " adds=%u packets=%llu bytes=%llu\n",
			   g->adds, stats.packets, stats.bytes);
	}
	mutex_unlock(&ft_mr_lock);
}

/* A port's egress queues changed under the multicast groups copying out of it.
 *
 * Every listener entry names what its port had when the entry was built: the
 * frame queue dpa_get_tx_info_by_itf() asked cdx_get_txfqid() for, and whether
 * the port's DSCP map was on. An HTB tree moving the port to or from CEETM, a
 * class moving or going, or the map changing leaves those entries enqueuing to
 * a queue nothing dequeues, or past the classes the operator configured. So
 * every installed group with a copy on the port is rebuilt, whichever learner
 * owns it: cdx_mc_group_replace() builds a whole new listener chain, which
 * asks the port again, and swaps it in under the same key, so the stream does
 * not leave hardware while it happens. A rebuild that fails withdraws the
 * group to software, as any failed replace does.
 *
 * Both learners' groups are marked and handed to their workers, which do the
 * hardware; a caller that has to know the rebuilds happened -- the DSCP map
 * leaving the port -- asks the drains, which rebuild in place what is still
 * marked (ft_mc_egress_drain(), ft_mr_egress_drain()). Nothing here needs
 * RTNL or sleeps under a spinlock: it takes each learner's mutex in turn and
 * never both, which a caller holding RTNL may do -- it is the order the
 * notifiers take them in -- and one holding nothing may too. A group whose
 * chain is being built while this runs is not always on its learner's list to
 * be marked, so ft_egress_changed() counts the change before calling this, and
 * each worker compares the count across its build when it records it, and
 * marks the chain again if it moved. */
void ft_mc_egress_changed(const struct net_device *dev)
{
	unsigned int rebuilt;

	rebuilt = ft_mc_egress_mark(dev);
	rebuilt += ft_mr_egress_mark(dev);
	atomic64_add(rebuilt, &ft_mc_egress_rebuilds);
}

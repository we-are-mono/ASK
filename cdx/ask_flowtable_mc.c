// SPDX-License-Identifier: GPL-2.0-or-later
/* The bridged multicast learner.
 */
#include "ask_flowtable_internal.h"

/* ------------------------------------------- The multicast learners' streams
 *
 * Two learners reach one classifier, and they do not share a key. A routed
 * group is keyed on its ingress port and address pair in the routed multicast
 * tables, and that port is never a bridge port: a bridge port's frames go to
 * the bridge's receive handler and never reach a VIF above it. A bridged group
 * is keyed on its ingress port, its frames' Ethernet pair and the address pair
 * in the bridged tables, and its port always is one. No frame is a candidate
 * for both, so neither learner can take a key from the other. Each refuses
 * only its own collisions: two MFC entries arriving on one port with different
 * tags, whose one root could validate only one stack (ft_mr_key_taken()), and
 * two bridged flows that are one key on two VLANs (ft_mc_key_contested()).
 *
 * What the two can share is a stream. An IPTV VLAN bridged to a set-top box
 * and routed to the rest of the house arrives on a bridge port; the bridge
 * forwards it to its member ports and, as a multicast router, hands it to the
 * host, where ipmr routes it out of the others. That is one classifier key,
 * the bridged one, so it is one hardware group carrying the union of both
 * learners' copies: the bridge's with the sender's Ethernet pair and hop
 * count, ipmr's with its VIF's address and one hop fewer.
 *
 * The bridged learner owns that group, as one of its flows, because only its
 * traffic hook knows the port, the pair and the tag the stream arrives with.
 * An MFC entry whose parent VIF is a bridge, or an 802.1Q device above one,
 * installs nothing of its own: the routed learner publishes its copies as an
 * ft_mc_route and reads back whether a bridged flow carries them and what it
 * counted. Each learner keeps its own copies -- the bridge's come and go with
 * its answer, a route's with the MFC -- and the group is replaced in place
 * when either set changes and retired only when neither learner names it.
 *
 * The bridge handing a stream to the host is also what makes the host's copy
 * something the hardware has to account for. A flow the bridge delivers to a
 * VIF is carried only together with the route that forwards it. Without one --
 * no MFC entry yet, which is how a routing daemon learns a source, or one the
 * routed learner refuses -- it stays in software, where ipmr sees it. So the
 * routed learner also publishes where its VIFs sit on bridges, as ft_mc_tap.
 * See docs/flowtable/multicast-routed.md.
 */

/* ------------------------------------------------------------- Multicast
 *
 * The bridge's own IGMP and MLD snooping is the control plane. It maintains
 * the MDB, reports every port group on the switchdev chain this adapter is
 * already registered on, and needs nothing installed, configured or packaged
 * by us -- which is the whole point: a consumer that bridges an ISP's IPTV
 * VLAN already has the memberships, and what changes is who replicates them.
 *
 * What the MDB cannot supply is the rest of a classifier key. CDX matches an
 * exact (S,G) on an exact ingress port, and an IGMPv2 join produces a (*,G)
 * with neither a source nor any notion of where the traffic comes from. Both
 * are properties of the traffic rather than of the membership, so both are
 * learned from the stream -- see docs/flowtable/multicast.md.
 *
 * So there are two kinds of object. A membership (struct ft_mc_group) records
 * what the bridge says -- a port group or a host membership -- and installs
 * nothing: it is what makes a group's traffic worth learning. A flow (struct
 * ft_mc_flow) is what the hardware carries: one source's frames of a group as
 * they arrive on one bridge port, keyed the way the classifier is. Where a
 * flow's frames go is not read off the memberships either. The bridge decides
 * that per frame -- an (S,G) entry before the (*,G) one under IGMPv3 and
 * MLDv2, INCLUDE port groups the (*,G) lookup skips, ports that block the
 * source, multicast router ports, the ingress never -- and a switchdev object
 * carries none of it. The worker asks the bridge instead, through
 * br_multicast_list_ports() with the flow's ingress, and a membership changing
 * only tells it which flows to ask about again.
 *
 * Locking, which is not incidental here. The switchdev handler runs holding
 * RTNL (switchdev_port_obj_add_deferred() asserts it), and a backend operation
 * needs the transaction, and cdx_ctrl_lock_with_rtnl() states the rule those
 * two live under: never wait for either lock while holding the other. So the
 * handler only ever takes ft_mc_lock and marks, and a work item asks the
 * bridge -- under RTNL, then ft_mc_lock, the handler's own order -- and then
 * does the hardware without RTNL.
 *
 * That leaves one ordering obligation, which every function below keeps:
 * **ft_mc_lock is never held across cdx_ft_begin()**. /proc reads the lists
 * from inside the transaction, so a worker that took the transaction while
 * holding ft_mc_lock would close a cycle with it. The worker therefore
 * snapshots under the lock and releases it, takes the transaction, programs
 * the hardware with the transaction alone, and takes the lock again inside it
 * only to record what it did -- /proc's order -- so nothing else that takes
 * the transaction sees an entry half built, and nothing that takes only the
 * lock under RTNL waits behind a hardware call. The egress drain is the one
 * caller that takes the transaction holding RTNL, a tc command's: RTNL then
 * the transaction, the order the routed learner's drain explains, and the
 * worker never waits for RTNL while it holds the transaction. The drain holds
 * ft_mc_lock across its rebuilds, which delays nothing under RTNL: its caller
 * holds RTNL. And a discard giving up its group id to an add that found none,
 * which either learner's worker asks for from inside its transaction
 * (ft_mc_evict_discard()), takes the lock there too, and deletes with the
 * transaction alone once it has let go of it.
 */

/* The largest packet `dev` carries for `family`, in the units the forwarding
 * decision on that device is made in: the IPv6 MTU for IPv6 -- the value a
 * link's hosts learn from router advertisements and the one ip6_forward()
 * quotes in a Packet Too Big -- and the device MTU otherwise.
 *
 * Both learners bound a group with it, for one reason. A listener's entry ends
 * in ENQUEUE_PKT, and the microcode fragments any replica larger than the MTU
 * that opcode carries; no preemptive check stands in front of it, because a
 * member entry has none and a check on the root could only except the whole
 * packet for IPv4 with DF set (PREEMPT_DFBIT_HONOR acts on IPv4 alone, measured
 * for A198). Linux never does what that fragmenter does: ip6mr answers an
 * oversized IPv6 replica with Packet Too Big, ipmr drops an IPv4 one with DF
 * set, and a bridge fragments nothing at all. So a group is carried only while
 * nothing larger than every listener's MTU can arrive on its ingress, and the
 * oversized packet that cannot arrive in hardware is Linux's to handle in
 * software. See docs/flowtable/multicast.md. */
u32 ft_mc_link_mtu(const struct net_device *dev, u8 family)
{
	u32 mtu = READ_ONCE(dev->mtu);

	if (family == AF_INET6) {
		struct inet6_dev *idev;

		rcu_read_lock();
		idev = __in6_dev_get(dev);
		if (idev)
			mtu = min_t(u32, mtu, (u32)READ_ONCE(idev->cnf.mtu6));
		rcu_read_unlock();
	}
	return mtu;
}

/* Enough to ride out a transient -- a port bouncing, a moment of capacity
 * pressure; the tries are a refresh interval apart -- and few enough that a
 * flow which genuinely cannot be carried stops costing anything. A changed
 * answer from the bridge starts the count again. */
#define FT_MC_MAX_RETRIES 4

/* How long a flow nothing carries keeps its place without a frame. Its frames
 * are not recorded again once seen (ft_mc_record()), so at this age it asks
 * -- see ft_mc_flow_probe() -- and goes at the next if nothing answered. */
#define FT_MC_UNCARRIED_AGE	(6 * FT_MC_REFRESH_INTERVAL)

LIST_HEAD(ft_mc_groups);
/* The memberships by (bridge, VLAN, group), for what a flow asks of them on
 * every retirement pass: as many memberships as the bridge keeps, and walking
 * them all for each flow made every pass flows x memberships. */
static DEFINE_HASHTABLE(ft_mc_group_index, 8);
LIST_HEAD(ft_mc_flows);
DEFINE_MUTEX(ft_mc_lock);
unsigned int ft_mc_count, ft_mc_flow_count, ft_mc_installed;
/* Of ft_mc_installed, the entries that discard; under the transaction, as
 * ft_mc_installed is. */
unsigned int ft_mc_discarding;
/* Discards taken out of hardware to give their group id to a stream somebody
 * wants; see ft_mc_evict_discard(). Under the transaction. */
u64 ft_mc_discards_evicted;
u64 ft_mc_refused, ft_mc_install_errors;
/* Netdev chains nft_port_dependent() could not judge for a flow -- too large
 * for its bounds, or a probe it refused -- each of which kept the flow in
 * software. */
u64 ft_mc_port_probe_errors;
/* Installed groups of either learner marked for a rebuild because a port they
 * copy out of changed its egress; see ft_mc_egress_changed(). A build racing
 * the change compares ft_egress_changes instead. */
atomic64_t ft_mc_egress_rebuilds = ATOMIC64_INIT(0);
static void ft_mc_work_fn(struct work_struct *work);
DECLARE_WORK(ft_mc_work, ft_mc_work_fn);
static void ft_mc_refresh_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_mc_refresh, ft_mc_refresh_fn);
/* Set once the adapter is tearing down, so a queued worker that runs during
 * exit does nothing rather than reaching a backend that is going away. */
bool ft_mc_stopping;
/* Multicast acceleration as a whole, bridged and routed: the global switch
 * the offload service turns off when it stops or its policy is disabled, and
 * on again when it applies an enabled one (the `multicast` parameter, with
 * ft_mc_switched()).
 * Off, both learners go on learning -- memberships, routes and confirmations
 * are the kernel's and stay exactly as they are -- but every group they have
 * in hardware goes back to software, and none goes in, each saying
 * refused-paused; on, each is asked again and carried as before. On at load,
 * so a consumer with no service carries multicast as it always did. */
bool ft_mc_enabled = true;
/* Something outside this learner changed an answer it had already given, with
 * no membership event to say so: a device MTU changed, and a flow whose ports
 * no longer bound its ingress has to leave hardware rather than wait for its
 * membership to change. Every flow is reconsidered on the next pass,
 * installed ones included. */
bool ft_mc_recheck;
/* A bridge hook other than the learner's own was registered at the worker's
 * last pass, and no flow may be carried: see ft_mc_bridge_filtered(). Written
 * by the worker under ft_mc_lock. */
bool ft_mc_filtered;
/* The routes and taps the routed learner publishes, under ft_mc_lock; what
 * each route is told back, under the leaf below. */
LIST_HEAD(ft_mc_routes);
static DEFINE_SPINLOCK(ft_mc_route_lock);
static struct ft_mc_tap ft_mc_taps[FT_MC_TAPS];
static unsigned int ft_mc_tap_count;
/* Until the routed learner first says where its VIFs are, they may be
 * anywhere. */
static bool ft_mc_taps_overflow = true;

void ft_mc_kick_all(void)
{
	if (READ_ONCE(ft_mc_stopping))
		return;
	WRITE_ONCE(ft_mc_recheck, true);
	schedule_work(&ft_mc_work);
}

static u8 ft_mc_family(const struct br_ip *addr)
{
	return addr->proto == htons(ETH_P_IPV6) ? AF_INET6 : AF_INET;
}

/* Link-local scope: 224.0.0.0/24, and ff01::/16 and ff02::/16. It carries IGMP,
 * MLD and neighbour discovery, and the querier the whole design depends on;
 * taking any of it away from the bridge would take the control plane with
 * it, so no flow of it is ever learned -- and a membership of it would be a
 * reason to learn nothing, so none is recorded. The bridge's own IPv6
 * addresses join a solicited-node group each, and recording those kept the
 * hook registered on every IPv6 LAN for nothing. */
bool ft_mc_link_local(const struct br_ip *addr)
{
	if (addr->proto == htons(ETH_P_IP))
		return ipv4_is_local_multicast(addr->dst.ip4);
	return __ipv6_addr_src_scope(__ipv6_addr_type(&addr->dst.ip6)) <=
	       IPV6_ADDR_SCOPE_LINKLOCAL;
}

/* Whether a membership and a flow are about the same group on the same bridge
 * VLAN, which is what makes a change to the one a question about the other. */
bool ft_mc_same_vlan_group(const struct br_ip *a, const struct br_ip *b)
{
	return a->proto == b->proto && a->vid == b->vid &&
	       !memcmp(&a->dst, &b->dst, sizeof(a->dst));
}

/* The ft_mc_group_index key of a bridge VLAN's group: what
 * ft_mc_same_vlan_group() compares, and the bridge, under the adapter's seed. */
static u32 ft_mc_group_key(const struct net_device *bridge, const struct br_ip *addr)
{
	u32 key[2 + sizeof(addr->dst) / sizeof(u32)];

	key[0] = (u32)(unsigned long)bridge;
	key[1] = (__force u32)addr->proto << 16 | addr->vid;
	memcpy(key + 2, &addr->dst, sizeof(addr->dst));
	return jhash2(key, ARRAY_SIZE(key), ft_hash_seed);
}

/* Ask the bridge again about every flow of this group on this bridge VLAN,
 * whatever its source: a membership changing -- a join, a leave, an (S,G)
 * port group created or blocked, a filter mode switched -- can change the
 * answer for any of them. Called with ft_mc_lock held. */
static void ft_mc_touch(const struct net_device *bridge, const struct br_ip *addr)
{
	struct ft_mc_flow *f;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list)
		if (f->bridge == bridge && ft_mc_same_vlan_group(&f->addr, addr))
			f->dirty = true;
}

static bool ft_mc_same_group(const struct ft_mc_group *g,
			     const struct net_device *bridge,
			     const struct br_ip *addr)
{
	return g->bridge == bridge && !memcmp(&g->addr, addr, sizeof(*addr));
}

static struct ft_mc_group *ft_mc_find(const struct net_device *bridge,
				      const struct br_ip *addr)
{
	struct ft_mc_group *g;

	list_for_each_entry(g, &ft_mc_groups, list)
		if (ft_mc_same_group(g, bridge, addr))
			return g;
	return NULL;
}

/* Whether every port the bridge delivers this flow to is one the hardware can
 * be given, together with the copies of the route riding it.
 *
 * All or nothing, and the reason is that there is no half. A matched frame
 * never reaches the bridge, so a port left out of the hardware set does not
 * fall back to software -- it stops receiving, silently. A flow with a Wi-Fi
 * VAP among its ports, which is what br-lan looks like the moment a phone
 * joins the same stream as a set-top box, is therefore carried by the bridge
 * in software in its entirety rather than by the hardware in part; the
 * derivation records that as `error`.
 *
 * A route riding the flow is part of the same set, and the union has to fit
 * one group. A routed copy leaving by the same port with the same tags as a
 * bridged one -- one port, two VLANs untagged on it -- is still a copy of its
 * own and is carried as one: it leaves with its VIF's address and one hop
 * fewer where the bridged copy keeps its sender's pair and hop count, which
 * are two frames Linux sends, and the backend tells its listeners apart by the
 * address as well as by the framing.
 */
static bool ft_mc_carriable(const struct ft_mc_flow *f)
{
	const struct ft_mc_route *r = f->route;

	if (f->error)
		return false;
	return !r || f->ports + r->listeners <= CDX_MC_MAX_LISTENERS;
}

/* Whether every frame the ingress port can deliver fits every port the flow
 * is replicated to, which is what lets the hardware carry it without ever
 * fragmenting a copy.
 *
 * A bridge fragments nothing: br_dev_queue_push_xmit() drops a frame that
 * does not fit the egress port, whatever its family and whatever its DF bit,
 * and the microcode would instead fragment it at the listener's enqueue. The
 * two can only agree while no such frame arrives, so a port whose MTU is below
 * the ingress's keeps the whole flow in software, where the bridge makes that
 * decision per frame. The comparison is in device MTUs because a bridge
 * decides in them; see ft_mc_link_mtu() for why the bound is an admission
 * test at all. What the ingress can deliver is what its MAC accepts, its MTU
 * but never less than a full Ethernet frame (ft_port_arriving()): a port
 * lowered to 1400 still receives 1500-byte frames, which the bridge would
 * drop at a 1400-byte listener and the microcode would fragment. A flow whose
 * ingress has gone has nothing left to bound.
 *
 * A route's copies are bounded by the same port: whatever the bridge hands the
 * host arrived there, and ipmr and ip6mr would drop or answer rather than
 * fragment what does not fit. The route states its narrowest path in the
 * family's own units, the IPv6 MTU for IPv6. */
static bool ft_mc_mtu_bounded(const struct ft_mc_flow *f)
{
	u32 in_mtu;
	u8 i;

	if (!f->in)
		return true;
	in_mtu = ft_port_arriving(f->in);
	for (i = 0; i < f->ports; i++)
		if (READ_ONCE(f->port[i].dev->mtu) < in_mtu)
			return false;
	return !f->route || f->route->mtu >= in_mtu;
}

/* Whether this port could carry a replica, asked the only way a caller holding
 * RTNL may ask it.
 *
 * Deliberately not cdx_mc_port_supported(), which resolves an onif and so
 * needs the transaction. dpa_netdev_is_physical() exists for exactly this
 * position -- the tree describes it as a notifier-safe identity check that
 * never takes the control mutex while the caller owns RTNL. The authoritative
 * test runs in the worker; this one decides what the adapter tells the bridge.
 */
static bool ft_mc_port_eligible(struct net_device *dev)
{
	return cdx_mc_port_identity(dev);
}

/* The tags a copy of a group in `vid` leaves `port` with.
 *
 * ft_bridge_vlan() asks the same question from the other end -- it walks a
 * flow's path down to a port and works out what the bridge added along the
 * way. Here the VLAN is already known, because the membership or the flow
 * names it, so only the port's membership of it is in question.
 *
 * Two kinds of failure. -ENOENT means the bridge would not deliver to this
 * port at all. -EOPNOTSUPP means it would and this side cannot describe the
 * framing, which makes the port one a flow has to be refused over.
 */
static int ft_mc_port_tags(struct net_device *bridge, struct net_device *port,
			   u16 vid, struct cdx_ft_vlan *stack, u8 *count)
{
	struct bridge_vlan_info vinfo;
	u16 proto;

	*count = 0;
	if (!br_vlan_enabled(bridge))
		return 0;
	/* Only 802.1Q, for the reason ft_bridge_vlan() gives: the kernel
	 * describes no selector for an 802.1ad tag, so it is one the hardware
	 * would be asked to reproduce blind. */
	if (br_vlan_get_proto(bridge, &proto) || proto != ETH_P_8021Q)
		return -EOPNOTSUPP;
	if (!vid)
		return -EOPNOTSUPP;
	/* A port that is not a member of the group's VLAN would not receive
	 * this group in software either -- br_allowed_egress() drops the copy
	 * -- so it is not a listener rather than an uncarriable one. */
	if (br_vlan_get_info(port, vid, &vinfo))
		return -ENOENT;
	if (vinfo.flags & BRIDGE_VLAN_INFO_UNTAGGED)
		return 0;
	stack[0].proto = htons(proto);
	stack[0].id = vid;
	*count = 1;
	return 0;
}

/* Take one port out of a membership. Returns whether it was there. Called with
 * ft_mc_lock held. */
static bool ft_mc_group_drop(struct ft_mc_group *g, const struct net_device *port)
{
	u8 i;

	lockdep_assert_held(&ft_mc_lock);
	for (i = 0; i < g->ports; i++) {
		if (g->port[i] != port)
			continue;
		dev_put(g->port[i]);
		memmove(&g->port[i], &g->port[i + 1],
			(g->ports - i - 1) * sizeof(g->port[0]));
		g->ports--;
		g->port[g->ports] = NULL;
		return true;
	}
	return false;
}

/* Remove a port from every membership that lists it, wherever the caller could
 * not say which. Called with ft_mc_lock held. */
static void ft_mc_drop_port(struct net_device *port)
{
	struct ft_mc_group *g;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(g, &ft_mc_groups, list)
		if (ft_mc_group_drop(g, port))
			ft_mc_touch(g->bridge, &g->addr);
}

/* Take one port out of a flow's derived copies: the port is going away, and
 * the bridge's next answer will not name it either. The flow is asked again
 * and its entry rebuilt without it. Called with ft_mc_lock held. */
static void ft_mc_flow_drop_port(struct ft_mc_flow *f,
				 const struct net_device *port)
{
	u8 i;

	lockdep_assert_held(&ft_mc_lock);
	for (i = 0; i < f->ports; i++) {
		if (f->port[i].dev != port)
			continue;
		dev_put(f->port[i].dev);
		memmove(&f->port[i], &f->port[i + 1],
			(f->ports - i - 1) * sizeof(f->port[0]));
		f->ports--;
		memset(&f->port[f->ports], 0, sizeof(f->port[0]));
		f->dirty = true;
		f->stale = true;
		return;
	}
}

/* Forget the shape a flow was keeping for later. */
void ft_mc_drop_next(struct ft_mc_flow *f)
{
	memset(&f->next, 0, sizeof(f->next));
	f->has_next = false;
}

static void ft_mc_group_free(struct ft_mc_group *g)
{
	u8 i;

	for (i = 0; i < g->ports; i++)
		dev_put(g->port[i]);
	dev_put(g->bridge);
	kfree(g);
}

/* Let go of every copy a flow's last derivation named. */
static void ft_mc_flow_release_ports(struct ft_mc_flow *f)
{
	u8 i;

	for (i = 0; i < f->ports; i++)
		dev_put(f->port[i].dev);
	memset(f->port, 0, sizeof(f->port));
	f->ports = 0;
}

/* Forget the chain recorded for a flow's entry, and the references it held
 * (ft_mc_chain_record()). With ft_mc_lock held, or on a flow nothing else can
 * reach any more. */
static void ft_mc_chain_forget(struct ft_mc_flow *f)
{
	u8 i;

	if (!f->hw_spec.listeners)
		return;
	dev_put(f->hw_spec.in);
	for (i = 0; i < f->hw_spec.listeners; i++)
		dev_put(f->hw_spec.listener[i].dev);
	memset(&f->hw_spec, 0, sizeof(f->hw_spec));
}

static void ft_mc_flow_free(struct ft_mc_flow *f)
{
	ft_mc_chain_forget(f);
	ft_mc_flow_release_ports(f);
	if (f->in)
		dev_put(f->in);
	dev_put(f->bridge);
	kfree(f);
}

/* ---- what the routed learner publishes -----------------------------------
 *
 * Each of these takes ft_mc_lock itself and is called holding no other lock of
 * either learner -- the routed worker calls them between its own sections,
 * never inside ft_mr_lock -- so the two learners' locks are never nested. The
 * worker acts on what changed at its next pass.
 */

static bool ft_mc_route_same(const struct ft_mc_route *a,
			     const struct ft_mc_route *b)
{
	u8 i;

	if (a->bridge != b->bridge || a->vid != b->vid ||
	    a->tagged != b->tagged || a->family != b->family ||
	    memcmp(&a->src, &b->src, sizeof(a->src)) ||
	    memcmp(&a->dst, &b->dst, sizeof(a->dst)) ||
	    a->listeners != b->listeners || a->mtu != b->mtu)
		return false;
	/* Field by field, so no padding can decide it. The address a copy
	 * leaves with is part of it: a VIF given another one changes what the
	 * carrying flow has to write, and nothing else about the route moves. */
	for (i = 0; i < a->listeners; i++)
		if (a->listener[i].dev != b->listener[i].dev ||
		    a->listener[i].vlans != b->listener[i].vlans ||
		    a->listener[i].routed != b->listener[i].routed ||
		    memcmp(a->listener[i].vlan, b->listener[i].vlan,
			   sizeof(a->listener[i].vlan)) ||
		    !ether_addr_equal(a->listener[i].src_mac,
				      b->listener[i].src_mac))
			return false;
	return true;
}

/* Drop every device a route names, leaving it describing nothing. Called with
 * ft_mc_lock held. */
static void ft_mc_route_clear(struct ft_mc_route *r)
{
	u8 i;

	for (i = 0; i < r->listeners; i++)
		dev_put(r->listener[i].dev);
	memset(r->listener, 0, sizeof(r->listener));
	r->listeners = 0;
	if (r->bridge)
		dev_put(r->bridge);
	r->bridge = NULL;
}

/* Publish a route, or restate one already published. `want` is a description
 * the caller holds every device of for the call; the route takes references
 * of its own. Returns whether a bridged group is carrying it now. */
bool ft_mc_route_publish(struct ft_mc_route *r,
			 const struct ft_mc_route *want)
{
	bool carried, learns;
	struct ft_mc_flow *f;
	u8 i;

	/* Read before the lock like everything else the route describes; the
	 * bridge is the caller's for the call. */
	learns = want->bridge &&
		 (br_multicast_router(want->bridge) ||
		  (READ_ONCE(want->bridge->flags) & IFF_PROMISC));
	mutex_lock(&ft_mc_lock);
	/* The same route through a bridge that now hands the host its streams,
	 * or no longer does: a frame of the stream recorded while nothing named
	 * it has to be recorded again. */
	if (!ft_mc_stopping && r->linked && r->learns != learns)
		ft_mc_forget_seen();
	r->learns = learns;
	if (!ft_mc_stopping && (!r->linked || !ft_mc_route_same(r, want))) {
		ft_mc_route_clear(r);
		dev_hold(want->bridge);
		for (i = 0; i < want->listeners; i++)
			dev_hold(want->listener[i].dev);
		r->bridge = want->bridge;
		r->vid = want->vid;
		r->tagged = want->tagged;
		r->family = want->family;
		r->src = want->src;
		r->dst = want->dst;
		memcpy(r->listener, want->listener, sizeof(r->listener));
		r->listeners = want->listeners;
		r->mtu = want->mtu;
		if (!r->linked) {
			list_add_tail(&r->list, &ft_mc_routes);
			r->linked = true;
			/* The count only grows while the route is published; its
			 * owner folds it from zero again from here, which the
			 * new series tells it. */
			spin_lock_bh(&ft_mc_route_lock);
			memset(&r->stats, 0, sizeof(r->stats));
			r->series++;
			spin_unlock_bh(&ft_mc_route_lock);
		}
		/* The worker re-matches every flow each pass, but a flow
		 * already matched to this route would not see its copies
		 * change without being told. */
		list_for_each_entry(f, &ft_mc_flows, list)
			if (f->route == r || f->carried_route == r)
				f->stale = true;
		/* A route names its stream's flow into existence, and a frame
		 * of it recorded while nothing named it has to be recorded
		 * again. */
		ft_mc_forget_seen();
		schedule_work(&ft_mc_work);
	}
	mutex_unlock(&ft_mc_lock);
	spin_lock_bh(&ft_mc_route_lock);
	carried = r->carried;
	spin_unlock_bh(&ft_mc_route_lock);
	return carried;
}

/* Take a route back. Its flow loses those copies at the worker's next pass,
 * and is retired then if nothing else names it. Safe on a route that was never
 * published, and after ft_mc_exit(), which unlinks every route itself.
 *
 * `last` is what the route had counted when it went, with the framing and
 * series that count belongs to: taken in the hold that zeroes it, after every
 * flow that could add to it has let go, so nothing counted is in neither.
 * Returns whether there was any, for the owner to fold. */
bool ft_mc_route_withdraw(struct ft_mc_route *r,
			  struct cdx_ft_counters *last, u8 *in_tags,
			  u32 *series)
{
	struct ft_mc_flow *f;
	bool counted;

	mutex_lock(&ft_mc_lock);
	if (r->linked) {
		list_del(&r->list);
		r->linked = false;
	}
	ft_mc_route_clear(r);
	list_for_each_entry(f, &ft_mc_flows, list) {
		if (f->route == r) {
			f->route = NULL;
			f->stale = true;
		}
		if (f->carried_route == r) {
			f->carried_route = NULL;
			f->stale = true;
		}
	}
	if (!ft_mc_stopping)
		schedule_work(&ft_mc_work);
	mutex_unlock(&ft_mc_lock);
	spin_lock_bh(&ft_mc_route_lock);
	counted = r->stats.packets || r->stats.bytes;
	*last = r->stats;
	*in_tags = r->in_tags;
	*series = r->series;
	r->carried = false;
	memset(&r->stats, 0, sizeof(r->stats));
	/* The routed learner would not miss this one: a withdrawn route
	 * reports nothing carried until it is linked again, which moves the
	 * series itself. It moves here too so that the series means what it
	 * says -- a new one for every run of the count from zero -- without
	 * resting on when the count is read. */
	r->series++;
	spin_unlock_bh(&ft_mc_route_lock);
	return counted;
}

/* What the bridged learner last said about a route: whether its copies are in
 * hardware, and if so what the carrying group counted, which run of that count
 * it is, and the ingress framing it includes. Takes only the leaf lock, so it
 * may be called holding ft_mr_lock. */
bool ft_mc_route_state(struct ft_mc_route *r,
		       struct cdx_ft_counters *stats, u8 *in_tags,
		       u32 *series)
{
	bool carried;

	spin_lock_bh(&ft_mc_route_lock);
	carried = r->carried;
	*stats = r->stats;
	*in_tags = r->in_tags;
	*series = r->series;
	spin_unlock_bh(&ft_mc_route_lock);
	return carried;
}

/* Replace the table of VIFs on bridges. `taps` is borrowed, with every bridge
 * in it held by the caller for the call. */
void ft_mc_taps_publish(const struct ft_mc_tap *taps, unsigned int n,
			bool overflow)
{
	unsigned int i;
	bool changed;

	mutex_lock(&ft_mc_lock);
	changed = n != ft_mc_tap_count || overflow != ft_mc_taps_overflow;
	for (i = 0; !changed && i < n; i++)
		changed = taps[i].bridge != ft_mc_taps[i].bridge ||
			  taps[i].vid != ft_mc_taps[i].vid ||
			  taps[i].tagged != ft_mc_taps[i].tagged ||
			  taps[i].family != ft_mc_taps[i].family;
	if (changed && !ft_mc_stopping) {
		for (i = 0; i < ft_mc_tap_count; i++)
			dev_put(ft_mc_taps[i].bridge);
		memset(ft_mc_taps, 0, sizeof(ft_mc_taps));
		for (i = 0; i < n; i++) {
			dev_hold(taps[i].bridge);
			ft_mc_taps[i] = taps[i];
		}
		ft_mc_tap_count = n;
		ft_mc_taps_overflow = overflow;
		schedule_work(&ft_mc_work);
	}
	mutex_unlock(&ft_mc_lock);
}

/* Whether a VIF on `bridge`, described as a route or a tap describes one,
 * receives what that bridge forwards within `vid`.
 *
 * br_pass_frame_up() hands the host a frame only when the bridge itself is a
 * member of the frame's VLAN, and hands it up untagged when that membership
 * is untagged and tagged otherwise, so the frame surfaces either on the bridge
 * device or on the 802.1Q device above it, never both. A bridge that does not
 * filter hands everything up as it forwards it, within VLAN zero. The
 * membership is read under RCU, which is what lets the worker ask this under
 * ft_mc_lock without RTNL. */
static bool ft_mc_via_receives(const struct net_device *bridge, u16 via_vid,
			       bool tagged, u16 vid)
{
	struct bridge_vlan_info info;
	int rc;

	if (!br_vlan_enabled(bridge))
		return !tagged && !vid;
	if (tagged && via_vid != vid)
		return false;
	rcu_read_lock();
	rc = br_vlan_get_info_rcu(bridge, vid, &info);
	rcu_read_unlock();
	if (rc || !(info.flags & BRIDGE_VLAN_INFO_BRENTRY))
		return false;
	return !(info.flags & BRIDGE_VLAN_INFO_UNTAGGED) == tagged;
}

/* Whether a route's parent VIF receives a group of this family on this bridge
 * VLAN, whatever its source. Called with ft_mc_lock held. */
bool ft_mc_route_reaches(const struct ft_mc_route *r,
			 const struct net_device *bridge,
			 const struct br_ip *addr)
{
	if (!r->listeners || r->bridge != bridge ||
	    r->family != ft_mc_family(addr) ||
	    memcmp(&r->dst, &addr->dst, sizeof(r->dst)))
		return false;
	return ft_mc_via_receives(r->bridge, r->vid, r->tagged, addr->vid);
}

/* Whether a route is this flow's stream routed: the same bridge VLAN, group
 * and source. Called with ft_mc_lock held. */
static bool ft_mc_route_names(const struct ft_mc_route *r,
			      const struct ft_mc_flow *f)
{
	return ft_mc_route_reaches(r, f->bridge, &f->addr) &&
	       !memcmp(&r->src, &f->addr.src, sizeof(f->addr.src));
}

/* Whether a VIF receives this flow's bridge VLAN, route or none. Called with
 * ft_mc_lock held. */
static bool ft_mc_tapped(const struct ft_mc_flow *f)
{
	unsigned int i;

	if (ft_mc_taps_overflow)
		return true;
	for (i = 0; i < ft_mc_tap_count; i++)
		if (ft_mc_taps[i].bridge == f->bridge &&
		    ft_mc_taps[i].family == ft_mc_family(&f->addr) &&
		    ft_mc_via_receives(f->bridge, ft_mc_taps[i].vid,
				       ft_mc_taps[i].tagged, f->addr.vid))
			return true;
	return false;
}

/* Match a flow against the routes and taps. Called by the worker with
 * ft_mc_lock held, after the flow's derivation and before anything is retired
 * or installed; a flow whose answer changed is marked for the install pass.
 *
 * A route counts only while the bridge hands this flow's frames to the host
 * for a VIF to see: as a multicast router, or because the bridge device is
 * promiscuous -- the derivation's BR_MCAST_TO_HOST_ROUTER and _PROMISC. A
 * bridge that is neither hands the host only what the host itself joined, and
 * a host membership keeps a flow in software regardless -- so a route through
 * such a bridge forwards nothing in Linux either, and carrying it would
 * forward what Linux does not. */
static void ft_mc_match_flow(struct ft_mc_flow *f)
{
	bool up = f->local & (BR_MCAST_TO_HOST_ROUTER | BR_MCAST_TO_HOST_PROMISC);
	struct ft_mc_route *r, *found = NULL;
	bool routed_host, routes = false;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(r, &ft_mc_routes, list) {
		if (!up || !ft_mc_route_reaches(r, f->bridge, &f->addr))
			continue;
		routes = true;
		if (!memcmp(&r->src, &f->addr.src, sizeof(f->addr.src)))
			found = r;
	}
	routed_host = up && (routes || ft_mc_tapped(f));
	/* A changed answer is a new question: retries spent against the old
	 * one say nothing about this one. */
	if (found != f->route || routed_host != f->routed_host) {
		f->stale = true;
		f->retries = 0;
	}
	f->route = found;
	f->routed_host = routed_host;
}

/* The route whose copies ride a flow, while it names any: a route a departing
 * device emptied stays matched until the next pass drops it, and must not be
 * carried as though it were none in the meantime. */
static const struct ft_mc_route *ft_mc_live_route(const struct ft_mc_flow *f)
{
	return f->route && f->route->listeners ? f->route : NULL;
}

static void ft_mc_match_routes(void)
{
	struct ft_mc_flow *f;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list) {
		ft_mc_match_flow(f);
		/* A key another flow held may have been given up since; a
		 * refused flow asks again, at no cost to the hardware. */
		if (f->contested)
			f->stale = true;
	}
}

/* Whether the bridge needs a local copy: the host joined, flooding sends it
 * one, or router/promiscuous delivery has no routing consumer. A known VIF
 * or route is checked separately: only an offloaded route can replace that
 * copy. Host delivery must reach Linux even if Linux ultimately drops it. */
bool ft_mc_host_wants(const struct ft_mc_flow *f)
{
	return (f->local & (BR_MCAST_TO_HOST_JOINED | BR_MCAST_TO_HOST_FLOOD)) ||
	       ((f->local & (BR_MCAST_TO_HOST_ROUTER | BR_MCAST_TO_HOST_PROMISC)) &&
		!f->routed_host);
}

/* Whether a flow can go into hardware as it stands, short of the key check
 * the worker makes and the retry ceiling. Called with ft_mc_lock held.
 *
 * A flow the bridge hands to a VIF is carried only together with the route
 * that forwards its stream there: installing the bridged copies alone would
 * take every frame away from the host, and with it ipmr's upcall, its
 * forwarding and the daemon's view of the source. And a flow the bridge
 * forwards nowhere -- every listener is behind the port it arrives on, or
 * blocks its source -- has nothing to replicate: it stays with the bridge,
 * which drops it. And no flow is carried while a bridge filter hook would see
 * its frames; see ft_mc_bridge_filtered(). Nor while tc or a netdev chain
 * runs anything in software where it arrives or where a copy leaves; see what
 * runs in software on a bridged flow's ports. Nor while multicast
 * acceleration is switched off; see ft_mc_enabled. */
static bool ft_mc_installable(const struct ft_mc_flow *f)
{
	const struct ft_mc_route *r = ft_mc_live_route(f);

	return READ_ONCE(ft_mc_enabled) && !ft_mc_filtered &&
	       !f->tc_soft && !f->nf_hooked &&
	       f->derived && f->in && !f->gone && !ft_mc_host_wants(f) &&
	       (f->ports || r) && (r || !f->routed_host) &&
	       ft_mc_carriable(f) && ft_mc_mtu_bounded(f);
}

/* Whether a flow's frames are ones the bridge drops, so the hardware can drop
 * them where they are matched instead of every one reaching the CPU to be
 * dropped there -- what a stream still arriving after its last listener left
 * would otherwise cost, until upstream stops sending it.
 *
 * Only on the bridge's own snooping answer (BR_MCAST_SNOOPED): an empty port
 * set it gave because it could not say -- the bridge down, the VID missing,
 * the ingress not forwarding -- is not a drop. Nothing else may want the
 * frames either: no port, no route riding the flow, no reason at all to hand
 * them up to the host, not even one only a VIF would act on, and nothing that
 * refuses every flow. Nor tc where they arrive, which runs before the bridge
 * drops them -- a mirror, a redirect or a police would stop seeing the stream
 * -- nor a netdev chain there that could tell its streams apart. Called with
 * ft_mc_lock held. */
static bool ft_mc_discardable(const struct ft_mc_flow *f)
{
	return READ_ONCE(ft_mc_enabled) && !ft_mc_filtered &&
	       !f->tc_soft && !f->nf_hooked &&
	       f->derived && f->in && !f->gone && !f->error &&
	       !f->ports && !f->routed_host && !ft_mc_live_route(f) &&
	       f->local == BR_MCAST_SNOOPED;
}

/* The key a flow's hardware group is installed under: its port, its stream
 * and the one ingress shape the root accepts. Called with ft_mc_lock held. */
static void ft_mc_flow_key(const struct ft_mc_flow *f,
			   struct cdx_mc_group_spec *spec)
{
	lockdep_assert_held(&ft_mc_lock);
	memset(spec, 0, sizeof(*spec));
	spec->in = f->in;
	spec->bridged = true;
	spec->family = ft_mc_family(&f->addr);
	if (spec->family == AF_INET6) {
		spec->src.in6 = f->addr.src.ip6;
		spec->dst.in6 = f->addr.dst.ip6;
	} else {
		spec->src.ip = f->addr.src.ip4;
		spec->dst.ip = f->addr.dst.ip4;
	}
	/* The frames' own pair, which the root is keyed on and every bridged
	 * copy is rebuilt with, and the one ingress shape the root accepts. */
	ether_addr_copy(spec->dst_mac, f->dst_mac);
	ether_addr_copy(spec->src_mac, f->src_mac);
	if (f->in_tagged) {
		spec->in_vlan[0].proto = htons(ETH_P_8021Q);
		spec->in_vlan[0].id = f->addr.vid;
		spec->in_vlans = 1;
	}
}

/* The hardware group a flow becomes: the ports the bridge forwards it to, and
 * the copies of the route riding it. Called with ft_mc_lock held on a flow
 * ft_mc_installable() accepts. The devices are borrowed; the caller holds its
 * own for the hardware call. */
static void ft_mc_flow_spec(const struct ft_mc_flow *f,
			    struct cdx_mc_group_spec *spec)
{
	const struct ft_mc_route *r = ft_mc_live_route(f);
	u8 i;

	ft_mc_flow_key(f, spec);
	/* The bridge's copies, as its answer named them: never the ingress,
	 * which br_multicast_list_ports() leaves out as should_deliver() does. */
	for (i = 0; i < f->ports; i++)
		spec->listener[spec->listeners++] = f->port[i];
	/* The routed copies take the address of the VIF each is sent through,
	 * which the route names per copy, and one hop off, as ipmr's would; a
	 * routed copy back out of the ingress port is one ipmr sends too,
	 * since it leaves by another VIF. */
	for (i = 0; r && i < r->listeners; i++) {
		spec->listener[spec->listeners] = r->listener[i];
		spec->listener[spec->listeners++].routed = true;
	}
}

/* The hardware group a flow ft_mc_discardable() accepts becomes: its key, and
 * no listener, dropping what it matches. The same key a replicating group has,
 * so the one becomes the other by a replace that never takes the key out of
 * the table. Called with ft_mc_lock held. */
static void ft_mc_discard_spec(const struct ft_mc_flow *f,
			       struct cdx_mc_group_spec *spec)
{
	ft_mc_flow_key(f, spec);
	spec->discard = true;
}

/* Record `spec` as the chain the flow's entry was built from, for the egress
 * drain to replay, with a reference of its own on every device it names.
 *
 * Borrowing them would not do. The flow and its route hold the devices the
 * flow names now, which is not what an installed chain names once the bridge
 * or the route has moved on; and the build holds its own only while it runs.
 * A device leaving while a build runs -- unregistered, or moved to another
 * namespace, which stays registered and reports nothing here afterwards --
 * empties the chain recorded before, but the build then records one naming
 * it, and once the build let go nothing would hold the device that chain
 * names. So the record holds it: a device going away waits for this worker,
 * whose next pass, which the device's own event asked for, records a chain
 * without it and lets it go. Called with ft_mc_lock held. */
static void ft_mc_chain_record(struct ft_mc_flow *f,
			       const struct cdx_mc_group_spec *spec)
{
	u8 i;

	lockdep_assert_held(&ft_mc_lock);
	dev_hold(spec->in);
	for (i = 0; i < spec->listeners; i++)
		dev_hold(spec->listener[i].dev);
	ft_mc_chain_forget(f);
	f->hw_spec = *spec;
}

/* Whether anything still names a flow: a membership of its group on its
 * bridge VLAN that takes its source -- any, for a (*,G) one -- or a route that
 * is its stream routed. Called with ft_mc_lock held. */
static bool ft_mc_flow_named(const struct ft_mc_flow *f)
{
	const struct ft_mc_route *r;
	const struct ft_mc_group *g;

	lockdep_assert_held(&ft_mc_lock);
	hash_for_each_possible(ft_mc_group_index, g, index,
			       ft_mc_group_key(f->bridge, &f->addr)) {
		if (g->bridge != f->bridge || (!g->ports && !g->host) ||
		    !ft_mc_same_vlan_group(&g->addr, &f->addr))
			continue;
		if (!memchr_inv(&g->addr.src, 0, sizeof(g->addr.src)) ||
		    !memcmp(&g->addr.src, &f->addr.src, sizeof(g->addr.src)))
			return true;
	}
	list_for_each_entry(r, &ft_mc_routes, list)
		if (ft_mc_route_names(r, f))
			return true;
	return false;
}

/* Move every membership nothing holds any more onto `dead`, and every flow
 * nothing names or that cannot exist any more onto `gone`, for the worker to
 * take out of hardware and free. A host-only membership is kept -- it has no
 * ports by definition, and forgetting it would let the next port join install
 * a flow the host is still listening to -- and a flow a route names is kept
 * with no membership left, because its copies are the other half of its set:
 * the entry goes only when both learners are done with it. Called with
 * ft_mc_lock held. */
static void ft_mc_retire(struct list_head *dead, struct list_head *gone)
{
	struct ft_mc_group *g, *gtmp;
	struct ft_mc_flow *f, *ftmp;
	bool retired = false;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry_safe(g, gtmp, &ft_mc_groups, list) {
		if (g->ports || g->host)
			continue;
		hash_del(&g->index);
		list_move(&g->list, dead);
		ft_mc_count--;
		retired = true;
	}
	list_for_each_entry_safe(f, ftmp, &ft_mc_flows, list) {
		/* Nothing names a stream its last listener left, but it may
		 * still be arriving: an installed flow the bridge would drop is
		 * kept, and its entry turned into a discard, until the stream
		 * stops and it ages out. Retired straight away it would reach
		 * the CPU, frame by frame, with nothing to learn it again. So
		 * is one whose membership went after this pass asked the bridge
		 * about it: its answer is stale, and the next pass, which the
		 * membership's event queued, asks again. */
		if (!f->gone && (ft_mc_flow_named(f) ||
				 (f->hw && (f->dirty || ft_mc_discardable(f)))))
			continue;
		list_move(&f->list, gone);
		ft_mc_flow_count--;
		retired = true;
	}
	/* A frame recorded against what just went -- a flow whose ingress
	 * left, a membership that named it -- may be one a new flow is to be
	 * learned from, so it may be recorded again. */
	if (retired)
		ft_mc_forget_seen();
}

/* Tell each route whether an installed flow is carrying it. Called by the
 * worker with ft_mc_lock held; returns true when an answer changed, which the
 * routed learner has to hear about. */
static bool ft_mc_route_feedback(void)
{
	struct ft_mc_route *r;
	struct ft_mc_flow *f;
	bool changed = false;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(r, &ft_mc_routes, list) {
		bool carried = false;
		u8 tags = 0;

		list_for_each_entry(f, &ft_mc_flows, list)
			if (f->hw && f->carried_route == r) {
				carried = true;
				tags = f->in_tagged;
				break;
			}
		spin_lock_bh(&ft_mc_route_lock);
		changed |= r->carried != carried;
		r->carried = carried;
		/* Kept while nothing carries it: the count the route holds was
		 * made with the framing of the flow that last did, and is
		 * folded with it when the route goes. */
		if (carried)
			r->in_tags = tags;
		spin_unlock_bh(&ft_mc_route_lock);
	}
	return changed;
}

/* A membership nothing recorded before. Called with ft_mc_lock held. */
static struct ft_mc_group *ft_mc_group_new(struct net_device *bridge,
					   const struct br_ip *addr)
{
	struct ft_mc_group *g = kzalloc(sizeof(*g), GFP_KERNEL);

	lockdep_assert_held(&ft_mc_lock);
	if (!g)
		return NULL;
	dev_hold(bridge);
	g->bridge = bridge;
	g->addr = *addr;
	list_add(&g->list, &ft_mc_groups);
	hash_add(ft_mc_group_index, &g->index, ft_mc_group_key(bridge, addr));
	ft_mc_count++;
	/* A frame of this group recorded before the membership existed was
	 * named by nothing; it is worth recording again now that something
	 * names it. The MDB add is deferred, so that order is the ordinary
	 * one. */
	ft_mc_forget_seen();
	return g;
}

/* Add or remove one port group, or the host's membership. Called with
 * ft_mc_lock held and no hardware touched; the worker is what acts on the
 * result. Returns true when the adapter takes responsibility for this port's
 * membership, which is what the switchdev answer reports: `handled` becomes
 * MDB_PG_FLAGS_OFFLOAD, shown by `bridge mdb show`, so a port the hardware
 * could never replicate to, or a membership the host shares, must not claim
 * it. */
static bool ft_mc_membership(struct net_device *bridge, struct net_device *port,
			     const struct br_ip *addr, bool adding, bool host)
{
	struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
	struct ft_mc_group *g;
	bool named;
	u8 i, tags;

	lockdep_assert_held(&ft_mc_lock);
	g = ft_mc_find(bridge, addr);
	/* Whatever changed, the bridge's answer for every flow of the group on
	 * this VLAN may have with it. */
	ft_mc_touch(bridge, addr);
	/* A membership whose last port left and which the worker has not
	 * retired yet names nothing; a frame drained meanwhile was named by
	 * nothing either, and has to be recorded again once it names flows. */
	named = g && (g->ports || g->host);
	if (g && adding && !named)
		ft_mc_forget_seen();

	if (host) {
		/* A host membership carries no port of its own; it says the
		 * bridge itself wants a copy, which the derivation reads as
		 * BR_MCAST_TO_HOST_JOINED and refuses every flow of the group
		 * over for as long as it holds.
		 *
		 * It has to create the membership when none exists yet, and
		 * this is the common ordering rather than a corner:
		 * br_multicast_add_group() calls br_multicast_host_join() on a
		 * freshly created mdb entry, so the host membership is emitted
		 * *before* any port group for that address. */
		if (!adding) {
			/* A source turned away while the host's join refused
			 * the group may be one a flow is learned from now. */
			if (g && g->host) {
				g->host = false;
				ft_mc_forget_seen();
			}
			return false;
		}
		if (!g)
			g = ft_mc_group_new(bridge, addr);
		if (g)
			g->host = true;
		return false;
	}

	if (!adding) {
		if (g)
			ft_mc_group_drop(g, port);
		return false;
	}

	if (!g)
		g = ft_mc_group_new(bridge, addr);
	if (!g)
		return false;
	for (i = 0; i < g->ports && g->port[i] != port; i++)
		;
	if (i == g->ports) {
		/* A port the bridge restates is already here; past the last
		 * slot it is not recorded, and not claimed. */
		if (g->ports == FT_MC_MAX_MEMBERS)
			return false;
		dev_hold(port);
		g->port[g->ports++] = port;
	}
	/* Claimed when the hardware could replicate to the port with the tags
	 * the bridge adds there. Whether a given flow is carried is a later
	 * question with its own answer in /proc. */
	return !g->host && ft_mc_port_eligible(port) &&
	       !ft_mc_port_tags(bridge, port, addr->vid, stack, &tags);
}

/* ---- what runs in software on a bridged flow's ports -----------------------
 *
 * A bridge port's frames cross more than the bridge's own hooks. tc runs on
 * the way in and on the way out of every port, and so does netfilter at the
 * port's own netdev hooks: on every frame the bridge forwards in software, and
 * on none an installed entry replicates. And the entry's key, which stops at
 * the addresses, cannot tell apart what a filter there reads -- the UDP port
 * above all: one filter dropping one port of a group would be bypassed for
 * every port of it.
 *
 * tc keeps a flow in software, refused-tc, while it runs anything in software
 * where the flow arrives -- a filter, a tcx program, XDP -- or where a bridged
 * copy leaves, by the routed learner's own predicate, ft_dev_stack_tc_soft().
 * A netdev chain -- or an inet one at ingress -- is judged as the routed
 * learner judges its groups', by nft_port_dependent() asked about a bridged
 * stream: the chains of the input's stack at ingress and of each output's at
 * egress, refusing only what could tell the group's streams apart, drop them
 * or translate them. One that only counts them, or never looks at them, keeps
 * nothing out, and nor does a flowtable's hook, which is no chain. That is
 * refused-filter, as a bridge hook is.
 *
 * And the bridge's own way in, for a flow the bridge also hands up to the host
 * as a multicast router or a promiscuous bridge does: the copy it hands up
 * crosses the bridge device and a VLAN device above it, and a carried flow
 * takes that copy away, so anything tc or a chain runs there keeps the flow
 * out. Only those devices: what the ports below the bridge run is the ports'
 * own question, and a frame the bridge forwards crosses nothing of the bridge
 * device's. Nothing reports a filter or a chain added or removed; the refresh
 * asks every flow again.
 *
 * tc is asked of every bridge and bridge port under RTNL before the derivation
 * takes ft_mc_lock, and never under it: walking a tc block can drop the last
 * reference to a classifier being deleted, whose destruction can reach the
 * egress hook, ft_egress_changed(), and through it ft_mc_egress_mark(), which
 * takes ft_mc_lock. The chains are walked under RCU, which no lock minds.
 */
struct ft_mc_soft_dev {
	const struct net_device *dev;
	/* A port's tc on what it receives and what it sends, the devices
	 * below it included; a bridge's on what it hands up, and netfilter's
	 * there, it and the VLAN devices above it. */
	bool tc_in;
	bool tc_out;
	bool nf_in;
};

struct ft_mc_soft {
	struct ft_mc_soft_dev *dev;
	unsigned int devs;
};

static bool ft_mc_soft_bridged(const struct net_device *dev)
{
	return netif_is_bridge_port(dev) || netif_is_bridge_master(dev);
}

/* What a bridge's hand-up copy crosses: the bridge's own LOCAL_IN hook, the
 * bridge device's way in, and that of the devices above it -- a VLAN device, a
 * macvlan -- which the receive path hands it on to. Under RTNL, which keeps
 * the upper list as RCU would, and lets the tc walk sleep. */
static void ft_mc_soft_bridge(struct ft_mc_soft_dev *d, struct net_device *br)
{
	struct net_device *upper;
	struct list_head *iter;

	ASSERT_RTNL();
	d->tc_in = ft_dev_tc_soft(br, true);
	d->nf_in = ft_dev_nf_ingress_hooked(br) ||
		   ft_bridge_hooked(BIT(NF_BR_LOCAL_IN));
	netdev_for_each_upper_dev_rcu(br, upper, iter) {
		d->tc_in |= ft_dev_tc_soft(upper, true);
		d->nf_in |= ft_dev_nf_ingress_hooked(upper);
	}
}

/* Ask about every bridge and bridge port. Returns false when there was no
 * memory for the table: the derivation waits for a pass that can ask, rather
 * than take every flow out of hardware for want of an answer. Called by the
 * worker with RTNL held and no learner lock; ft_mc_soft_free() lets the table
 * go. */
static bool ft_mc_soft_ask(struct ft_mc_soft *soft)
{
	struct ft_mc_soft_dev *d;
	struct net_device *dev;
	unsigned int n = 0;

	ASSERT_RTNL();
	soft->devs = 0;
	for_each_netdev(&init_net, dev)
		n += ft_mc_soft_bridged(dev);
	soft->dev = n ? kcalloc(n, sizeof(*soft->dev), GFP_KERNEL) : NULL;
	if (n && !soft->dev)
		return false;
	for_each_netdev(&init_net, dev) {
		if (!ft_mc_soft_bridged(dev) || soft->devs == n)
			continue;
		d = &soft->dev[soft->devs++];
		d->dev = dev;
		if (netif_is_bridge_master(dev)) {
			ft_mc_soft_bridge(d, dev);
			continue;
		}
		d->tc_in = ft_dev_stack_tc_soft(dev, true);
		d->tc_out = ft_dev_stack_tc_soft(dev, false);
	}
	return true;
}

static void ft_mc_soft_free(struct ft_mc_soft *soft)
{
	kfree(soft->dev);
	soft->dev = NULL;
	soft->devs = 0;
}

/* Add what the table says runs in software on what `dev` receives, or sends:
 * tc to *tc, a bridge's netfilter to *nf. A device the table does not name is
 * one nothing can be said of. */
static void ft_mc_soft_on(const struct ft_mc_soft *soft, const struct net_device *dev,
			  bool ingress, bool *tc, bool *nf)
{
	const struct ft_mc_soft_dev *d;
	unsigned int i;

	for (i = 0; i < soft->devs; i++) {
		d = &soft->dev[i];
		if (d->dev != dev)
			continue;
		*tc |= ingress ? d->tc_in : d->tc_out;
		*nf |= ingress && d->nf_in;
		return;
	}
	*tc = *nf = true;
}

/* Whether a netdev chain where the flow's frames arrive, or where a copy
 * leaves, could tell its streams apart -- by their ports above all -- drop
 * them or translate them, as the routed learner asks of its groups. A walk a
 * commit interrupted, or that found no memory, says nothing: the flow keeps
 * the answer it had for the same ports (`same`), or is refused, until the
 * refresh asks again. Called with RTNL and ft_mc_lock held; the walk takes
 * neither, and does not sleep. */
static bool ft_mc_netdev_dependent(const struct ft_mc_flow *f,
				   const struct cdx_mc_listener *port, u8 ports,
				   bool same)
{
	const struct net_device *out[CDX_MC_MAX_LISTENERS];
	struct nft_port_probe probe = {
		.in = f->in,
		.out = out,
		.nout = ports,
		.bridged = true,
	};
	int rc;
	u8 i;

	if (ft_mc_family(&f->addr) == AF_INET6) {
		probe.family = NFPROTO_IPV6;
		probe.saddr.in6 = f->addr.src.ip6;
		probe.daddr.in6 = f->addr.dst.ip6;
	} else {
		probe.family = NFPROTO_IPV4;
		probe.saddr.ip = f->addr.src.ip4;
		probe.daddr.ip = f->addr.dst.ip4;
	}
	for (i = 0; i < ports; i++)
		out[i] = port[i].dev;
	rcu_read_lock();
	rc = nft_port_dependent(&init_net, &probe);
	rcu_read_unlock();
	if (rc == -EAGAIN || rc == -ENOMEM)
		return !same || f->nf_hooked;
	if (rc < 0)
		ft_mc_port_probe_errors++;
	return rc != 0;
}

/* Ask the bridge what it does with this flow's frames, and keep the answer.
 *
 * br_multicast_list_ports() models the bridge's own receive path for a frame
 * of this source and group arriving on this port: an (S,G) entry before the
 * (*,G) one under IGMPv3 and MLDv2, INCLUDE port groups the (*,G) lookup
 * skips, ports that block the source, multicast router ports, never the
 * ingress, no isolated port from an isolated one, and whether the frame also
 * goes up to the host. Every one of those is a decision a membership alone
 * cannot reproduce -- a switchdev object carries no filter mode -- and reading
 * them off the bridge is what keeps the hardware from delivering a source a
 * port excluded. Each port it names must be one the hardware can replicate to
 * with the tags the bridge adds there, or the flow is refused whole.
 *
 * A changed answer marks the flow for the install pass, and an unchanged one
 * does not, so asking again at every refresh costs the hardware nothing.
 *
 * Called from the worker with RTNL, which the snapshot and the bridge VLAN
 * lookups need, and then ft_mc_lock -- the order the switchdev handler takes
 * them in -- with what runs in software on the ports, asked under the same
 * RTNL before the lock. The ports the bridge names are borrowed until RTNL is
 * released; the flow pins the ones it keeps. */
static void ft_mc_flow_derive(struct ft_mc_flow *f, const struct ft_mc_soft *soft)
{
	struct net_device *chosen[CDX_MC_MAX_LISTENERS];
	struct cdx_mc_listener port[CDX_MC_MAX_LISTENERS];
	bool tc_soft = false, nf_hooked = false, same;
	struct ft_mc_seen seen;
	unsigned int local = 0;
	int n, error = 0;
	u8 ports = 0, i;

	ASSERT_RTNL();
	lockdep_assert_held(&ft_mc_lock);
	f->dirty = false;
	if (f->gone || !f->in)
		return;
	if (!ft_mc_shape_resolves(f->bridge, f->in, f->in_tagged, f->addr.vid)) {
		/* Frames in this shape are another VLAN's now, or none: the
		 * flow is over, and learned again from its next frame. */
		f->gone = true;
		return;
	}
	if (f->has_next &&
	    !ft_mc_shape_resolves(f->bridge, f->in, f->next.tagged, f->addr.vid)) {
		/* Its frames are another VLAN's now; should they become this
		 * one's again, they have to be able to say so. */
		ft_mc_flow_seen(f, &f->next, &seen);
		ft_mc_supersede(&seen);
		ft_mc_drop_next(f);
	}
	/* Read at every derivation, and so followed within a refresh when
	 * whoever configures the bridge changes it; it changes nothing the
	 * hardware holds. Never shorter than two refreshes: the count is read
	 * one refresh apart, and an interval the next read could overrun would
	 * take a stream whose frames that read has not seen yet for one that
	 * stopped. */
	f->age = br_multicast_membership_interval(f->bridge, f->addr.vid);
	if (f->age && f->age < 2 * FT_MC_REFRESH_INTERVAL)
		f->age = 2 * FT_MC_REFRESH_INTERVAL;
	memset(port, 0, sizeof(port));
	n = br_multicast_list_ports(f->bridge, &f->addr, f->in, &local, chosen,
				    ARRAY_SIZE(chosen));
	if (n == -EINVAL) {
		/* The ingress is no longer a port of this bridge: it left, and
		 * its frames go wherever its new master sends them. */
		f->gone = true;
		return;
	}
	if (n < 0) {
		error = n;
		local = 0;
	}
	for (i = 0; !error && i < n; i++) {
		if (!ft_mc_port_eligible(chosen[i]) ||
		    ft_mc_port_tags(f->bridge, chosen[i], f->addr.vid,
				    port[ports].vlan, &port[ports].vlans)) {
			error = -EOPNOTSUPP;
			break;
		}
		port[ports++].dev = chosen[i];
	}
	if (error) {
		memset(port, 0, sizeof(port));
		ports = 0;
	}
	/* Where the frames arrive, where each copy leaves, and where the bridge
	 * hands them up; see what runs in software on a bridged flow's ports.
	 * A host that joined, or a bridge flooding everything up, refuses the
	 * flow whatever runs there. */
	ft_mc_soft_on(soft, f->in, true, &tc_soft, &nf_hooked);
	if (local & (BR_MCAST_TO_HOST_ROUTER | BR_MCAST_TO_HOST_PROMISC))
		ft_mc_soft_on(soft, f->bridge, true, &tc_soft, &nf_hooked);
	for (i = 0; i < ports; i++)
		ft_mc_soft_on(soft, port[i].dev, false, &tc_soft, &nf_hooked);
	same = f->derived && ports == f->ports &&
	       ft_mc_listeners_same(port, f->port, ports);
	if (ft_mc_netdev_dependent(f, port, ports, same))
		nf_hooked = true;
	if (same && error == f->error && local == f->local &&
	    tc_soft == f->tc_soft && nf_hooked == f->nf_hooked)
		return;
	/* Refused where it was not, for whichever reasons: one refusal. */
	if ((error || tc_soft || nf_hooked) &&
	    (!f->derived || !(f->error || f->tc_soft || f->nf_hooked)))
		ft_mc_refused++;
	ft_mc_flow_release_ports(f);
	for (i = 0; i < ports; i++)
		dev_hold(port[i].dev);
	memcpy(f->port, port, sizeof(f->port));
	f->ports = ports;
	f->local = local;
	f->error = error;
	f->tc_soft = tc_soft;
	f->nf_hooked = nf_hooked;
	f->derived = true;
	/* A changed answer is a new question: retries spent against the old
	 * one say nothing about this one. */
	f->stale = true;
	f->retries = 0;
}

/* Whether another flow on this bridge is the same classifier key: the same
 * port, sender and source of the group, on another VLAN of the bridge. The
 * one root could validate only one of the two tags, so neither may install.
 * A flow the bridge hands to the host, or not asked yet, makes no claim.
 * Called with ft_mc_lock held. */
static bool ft_mc_key_contested(const struct ft_mc_flow *f)
{
	const struct ft_mc_flow *o;

	lockdep_assert_held(&ft_mc_lock);
	list_for_each_entry(o, &ft_mc_flows, list) {
		if (o == f || o->gone || !ft_mc_same_key(o, f))
			continue;
		if (!o->hw && (!o->derived || ft_mc_host_wants(o)))
			continue;	/* not a claim on the key */
		return true;
	}
	return false;
}

/* Take what the hook observed, oldest first. Called by the worker with no lock
 * held; each observation is taken under the ring's lock and matched under
 * ft_mc_lock. */
static void ft_mc_drain(void)
{
	struct ft_mc_seen seen;

	for (;;) {
		spin_lock_bh(&ft_mc_ring_lock);
		if (ft_mc_ring_head == ft_mc_ring_tail) {
			spin_unlock_bh(&ft_mc_ring_lock);
			break;
		}
		seen = ft_mc_ring[ft_mc_ring_tail];
		ft_mc_ring_tail = (ft_mc_ring_tail + 1) % FT_MC_RING;
		spin_unlock_bh(&ft_mc_ring_lock);

		mutex_lock(&ft_mc_lock);
		if (!ft_mc_stopping)
			ft_mc_observe(&seen);
		mutex_unlock(&ft_mc_lock);
	}
}

/* Give a group id to a stream somebody wants: an add of `family` that
 * replicates found none free. One discard of the family leaves the hardware,
 * and the caller adds again at once, in the same transaction hold. Returns
 * whether one did.
 *
 * Both learners' groups take ids from one space per family, and a discard
 * holds its id for as long as its stream keeps arriving -- for good, from a
 * static upstream or a sender that never stops. Enough of them would starve
 * every stream that has a listener, so a discard gives way, and it gives way
 * at once rather than at the next refresh: the stream it drops reaches the CPU
 * again, where the bridge drops it in software, while a listener refused would
 * wait with nothing to watch. The one that goes is the one that saves least:
 * the fewest frames counted over the last whole refresh interval. One not yet
 * counted over a whole interval ranks after every one that has, so a discard
 * just added does not go on a count it had no time to make, and ties go to
 * the flow learned first. Discards never displace each
 * other, and nothing displaces a group that replicates: only an add that
 * replicates asks.
 *
 * Never the flow the bridged worker holds between its pick and its record,
 * whose entry is its own -- after a swap, one already deleted -- nor one
 * marked for the worker's next pass, which may be about to make it replicate.
 * The flow that gave way stays a flow. Named by nothing, the next pass,
 * asked for here, retires it; named still -- every listener behind its
 * ingress, or blocking its source -- it is tried again a refresh apart, as a
 * failed install is, and goes back in if an id frees before its tries run
 * out.
 *
 * Called by either worker inside the transaction, holding no learner lock and
 * no RTNL. ft_mc_lock is taken inside the transaction, /proc's order, and the
 * entry is deleted with the transaction alone, as the worker deletes. It
 * leaves the books under the lock, so whatever takes the lock or the
 * transaction next finds the flow without an entry; the delete holds the
 * ingress it unsubscribes through, which an exit draining the flows may let go
 * of meanwhile. */
bool ft_mc_evict_discard(u8 family)
{
	struct ft_mc_flow *f, *victim = NULL;
	struct cdx_mc_group *hw;
	struct net_device *in;

	cdx_ft_assert_held();
	mutex_lock(&ft_mc_lock);
	if (!ft_mc_stopping) {
		list_for_each_entry(f, &ft_mc_flows, list) {
			if (!f->hw || !f->hw_discard || f->busy || f->stale ||
			    ft_mc_family(&f->addr) != family)
				continue;
			if (!victim || f->interval_packets < victim->interval_packets)
				victim = f;
		}
	}
	if (!victim) {
		mutex_unlock(&ft_mc_lock);
		return false;
	}
	hw = victim->hw;
	victim->hw = NULL;
	victim->hw_discard = false;
	ft_mc_installed--;
	ft_mc_discarding--;
	ft_mc_discards_evicted++;
	/* Spent as a failed install is: a flow still named waits for the
	 * refresh to try it again, and one named by nothing is retired first. */
	victim->retries++;
	in = victim->in;
	dev_hold(in);
	/* Its frames reach the CPU again, and one recorded while the entry
	 * dropped them has to be able to be recorded again. */
	ft_mc_forget_seen();
	schedule_work(&ft_mc_work);
	mutex_unlock(&ft_mc_lock);
	cdx_mc_group_del(&hw);
	dev_put(in);
	return true;
}

/* The worker. Runs outside RTNL except while it asks the bridge, so it may
 * take the transaction -- and never while holding ft_mc_lock or RTNL, which is
 * the ordering obligation stated above; ft_mc_lock it takes inside it.
 */
static void ft_mc_work_fn(struct work_struct *work)
{
	bool want_hook, told, derive = false, filtered;
	struct ft_mc_group *g, *gtmp;
	struct ft_mc_flow *f, *ftmp;
	struct ft_mc_route *r;
	struct ft_mc_soft soft;
	LIST_HEAD(dead);
	LIST_HEAD(gone);

	/* Every pass takes the transaction; see ft_mc_record(). */
	WRITE_ONCE(ft_mc_passes, ft_mc_passes + 1);

	/* Something outside this learner changed an answer it gave -- a device
	 * MTU, or a bridge filter hook registered or gone -- so every answer is
	 * stale, installed ones included. Retries go with it: a flow that failed
	 * against a port that has since changed is not a flow that cannot be
	 * carried. */
	filtered = ft_mc_bridge_filtered();
	/* Said once per change: a hook that is never unregistered --
	 * br_netfilter once loaded, an ebtables table once used -- keeps every
	 * bridged stream in software for the boot, and without this only /proc
	 * would say why. */
	if (filtered != READ_ONCE(ft_mc_filtered)) {
		if (filtered)
			pr_info("cdx: a bridge netfilter hook is registered; bridged multicast stays in software while it is\n");
		else
			pr_info("cdx: no bridge netfilter hook remains; bridged multicast offload resumes\n");
	}
	if (READ_ONCE(ft_mc_recheck) || filtered != READ_ONCE(ft_mc_filtered)) {
		WRITE_ONCE(ft_mc_recheck, false);
		mutex_lock(&ft_mc_lock);
		WRITE_ONCE(ft_mc_filtered, filtered);
		list_for_each_entry(f, &ft_mc_flows, list) {
			f->retries = 0;
			f->stale = true;
		}
		/* And a source turned away under the old answer -- a filter
		 * hook refusing its group -- may be learned under this one. */
		ft_mc_forget_seen();
		mutex_unlock(&ft_mc_lock);
	}

	ft_mc_drain();

	/* Ask the bridge about every flow whose answer may have changed. The
	 * snapshot and the VLAN lookups need RTNL, taken before ft_mc_lock as
	 * the switchdev handler takes them, and neither is held across the
	 * transaction below. What runs in software on the ports is asked under
	 * the same RTNL, before the lock; see what runs in software on a bridged
	 * flow's ports. */
	mutex_lock(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list)
		derive |= f->dirty;
	mutex_unlock(&ft_mc_lock);
	if (derive) {
		rtnl_lock();
		/* With no answer to give, the flows stay marked for the next
		 * pass that has one -- the refresh's, at the latest. */
		if (ft_mc_soft_ask(&soft)) {
			mutex_lock(&ft_mc_lock);
			list_for_each_entry(f, &ft_mc_flows, list)
				if (f->dirty && !ft_mc_stopping)
					ft_mc_flow_derive(f, &soft);
			mutex_unlock(&ft_mc_lock);
		}
		rtnl_unlock();
		ft_mc_soft_free(&soft);
	}

	/* Match the routed learner's routes against the answers just derived,
	 * then retire what nothing holds or names any more.
	 *
	 * A retired flow leaves the list and its entry leaves the hardware in
	 * one transaction hold. Everything else that has to know every entry
	 * still installed -- the egress drain above all, which vouches that no
	 * entry built before an egress change is left -- takes the transaction
	 * and reads the list, so it sees the flow either still listed or
	 * already out of the hardware, never gone from the list with its entry
	 * still installed. ft_mc_lock is held only for the lists, not for the
	 * hardware: nothing but this worker reaches a flow once it is off
	 * them. */
	cdx_ft_begin();
	mutex_lock(&ft_mc_lock);
	if (!ft_mc_stopping)
		ft_mc_match_routes();
	ft_mc_retire(&dead, &gone);
	mutex_unlock(&ft_mc_lock);
	list_for_each_entry(f, &gone, list) {
		if (f->hw) {
			/* Even while stopping. Skipping the delete would strand
			 * the classifier entry, its group id and its listener
			 * chain in hardware with nothing left to own them --
			 * this flow is already off the list ft_mc_exit()
			 * drains, so nobody else would ever see it. */
			cdx_mc_group_del(&f->hw);
			ft_mc_installed--;
			ft_mc_discarding -= f->hw_discard;
			f->hw_discard = false;
		}
	}
	cdx_ft_end();

	list_for_each_entry_safe(g, gtmp, &dead, list) {
		list_del(&g->list);
		ft_mc_group_free(g);
	}
	list_for_each_entry_safe(f, ftmp, &gone, list) {
		list_del(&f->list);
		ft_mc_flow_free(f);
	}

	/* Install or update whatever is now installable. One flow per pass
	 * through the list, because the transaction is dropped between each --
	 * ft_mc_lock is never held across taking it.
	 *
	 * A flow's entry and the chain recorded for it stay the flow's until
	 * this pass is inside the transaction, and what the pass built is
	 * recorded before it leaves it, with ft_mc_lock taken inside the
	 * transaction for the record -- the order /proc, the refresh and the
	 * egress drain take the two in. None of them ever sees an entry built
	 * but not yet recorded, or recorded but not yet built -- the drain,
	 * which rebuilds the recorded chain in place, least of all. */
	for (;;) {
		struct cdx_mc_group_spec spec = {};
		struct ft_mc_route *route = NULL;
		struct ft_mc_flow *target = NULL;
		bool swap = false, swapped = false, withdrew = false;
		bool added = false, paused, build;
		struct cdx_mc_group *hw;
		s64 changes;
		int rc = 0;
		u8 i;

		mutex_lock(&ft_mc_lock);
		list_for_each_entry(f, &ft_mc_flows, list) {
			if (!f->stale || ft_mc_stopping)
				continue;
			/* Not installable, or its key another's: nothing to put
			 * in hardware and nothing there to take out, so no
			 * transaction. A flow that was installed and has become
			 * either is taken out below rather than left carrying
			 * stale ports. */
			if (!f->hw) {
				bool wanted = ft_mc_installable(f) ||
					      ft_mc_discardable(f);

				f->contested = wanted && ft_mc_key_contested(f);
				if (!wanted || f->contested) {
					f->stale = false;
					continue;
				}
			}
			target = f;
			break;
		}
		if (!target) {
			mutex_unlock(&ft_mc_lock);
			break;
		}
		target->stale = false;
		/* Its entry is this pass's until the record below; see
		 * ft_mc_evict_discard(). */
		target->busy = true;
		/* The installed key has carried nothing for a whole refresh while
		 * the flow reached the CPU in another shape: that shape takes
		 * over. The old entry comes out first -- it matches nothing, so
		 * its going costs no frame -- and the new one goes in as an add,
		 * because a different key is a different entry. Both happen in
		 * the transaction below; until then the old entry, and the chain
		 * recorded for it, are still the flow's. */
		if (target->hw && target->has_next && target->idle) {
			swap = true;
			ft_mc_adopt_next(target);
		}
		target->contested = ft_mc_key_contested(target);
		/* Snapshot under the lock; the hardware call is made in the
		 * transaction below. Every device in the spec gets a reference of
		 * its own for that window: the flow's own pins are dropped when a
		 * port goes away, from the netdev chain under RTNL, which takes
		 * no part in this transaction -- and a route's by the routed
		 * learner. Borrowing either would leave the spec naming a
		 * device whose last reference had just gone. */
		if (!target->contested && target->retries < FT_MC_MAX_RETRIES) {
			if (ft_mc_installable(target))
				ft_mc_flow_spec(target, &spec);
			else if (ft_mc_discardable(target))
				ft_mc_discard_spec(target, &spec);
		}
		/* Something to program: listeners, or a discard. */
		build = spec.listeners || spec.discard;
		if (build) {
			/* The route whose copies the spec carries, if any. */
			if (spec.listeners && ft_mc_live_route(target))
				route = target->route;
			dev_hold(spec.in);
			for (i = 0; i < spec.listeners; i++)
				dev_hold(spec.listener[i].dev);
		}
		mutex_unlock(&ft_mc_lock);

		/* The hardware is programmed with the transaction alone, and
		 * ft_mc_lock is taken only to record the outcome. What must not
		 * see an entry half built -- /proc, the refresh, the egress
		 * drain -- takes the transaction first; what takes only the lock
		 * -- the MDB handler, the netdev events and the egress mark, all
		 * under RTNL -- never waits behind a hardware call, and nothing
		 * it changes meanwhile is lost: a mark is caught by the egress
		 * count, a device going by the references the record takes, and
		 * a route withdrawn by the check below.
		 *
		 * The flow is still allocated: only this function frees one, and
		 * it is not reentrant. Its entry is changed only here, and is
		 * what it is now: a drain may have rebuilt it in place since the
		 * pick, never replaced it. */
		cdx_ft_begin();
		hw = target->hw;
		/* Before anything is built: see ft_egress_changes. */
		changes = atomic64_read_acquire(&ft_egress_changes);
		/* The switch again, under the transaction /proc is read through:
		 * the spec was taken before it, and a stop that has read nothing
		 * installed must not see this pass's add land afterwards. With no
		 * entry left, everything recorded below follows from hw alone. */
		paused = build && !READ_ONCE(ft_mc_enabled);
		if (swap && hw) {
			cdx_mc_group_del(&hw);
			ft_mc_installed--;
			swapped = true;
		}
		if (!build || paused) {
			/* Became ineligible: take it out of hardware and keep
			 * the flow, which may become installable again when the
			 * host leaves, a port returns or a route arrives. A
			 * discard that has become a listener set, or the other
			 * way, is not this: it is the replace below. */
			if (hw) {
				cdx_mc_group_del(&hw);
				ft_mc_installed--;
				withdrew = true;
			}
		} else if (hw) {
			rc = cdx_mc_group_replace(hw, &spec);
			if (rc) {
				/* The old chain can omit a port that has just
				 * joined, or the routed copies the host now needs
				 * carried; an incomplete set cannot stand in for
				 * the one asked for. Back to software until a whole
				 * set installs, as a routed group's failed update
				 * goes. Recorded below before the transaction is let
				 * go, so /proc and the refresh, which read the entry
				 * under it, never find it freed. */
				ft_mc_install_errors++;
				cdx_mc_group_del(&hw);
				ft_mc_installed--;
				withdrew = true;
			}
		} else {
			rc = cdx_mc_group_add(&spec, &hw);
			/* No group id left for a stream with somebody to send
			 * it to: a discard gives its own up, and the add is made
			 * again now rather than a refresh on. A discard asks
			 * for none. */
			if (rc == -ENOSPC && !spec.discard &&
			    ft_mc_evict_discard(spec.family))
				rc = cdx_mc_group_add(&spec, &hw);
			if (rc) {
				ft_mc_install_errors++;
				hw = NULL;
			} else {
				ft_mc_installed++;
				added = true;
			}
		}

		mutex_lock(&ft_mc_lock);
		target->busy = false;
		target->hw = hw;
		/* What the entry was built with. A route withdrawn while the
		 * spec was being taken has already cleared the flow's pointer and
		 * marked it for another pass, and must not be recorded: its owner
		 * is free to release it the moment it is off the list. */
		if (build && !rc)
			target->carried_route = route && target->route == route ?
						route : NULL;
		if (!hw)
			target->carried_route = NULL;
		ft_mc_discarding -= target->hw_discard;
		target->hw_discard = hw && spec.discard;
		ft_mc_discarding += target->hw_discard;
		/* And the chain itself, whole, for the egress drain to replace
		 * the entry with, holding what it names; nothing is recorded for
		 * an entry this pass took out, or one it could not build. Nor
		 * for a discard, which names no port's queue to rebuild for --
		 * and a chain left recorded from before it would have the drain
		 * rebuild the entry to replicate to listeners that left. */
		if (hw && spec.listeners && !rc)
			ft_mc_chain_record(target, &spec);
		else if (!hw || target->hw_discard)
			ft_mc_chain_forget(target);
		/* A new entry has counted nothing yet, is not idle until a
		 * whole refresh says so, ages from now, and has not been
		 * counted over any interval. */
		if (added) {
			target->hw_packets = target->hw_bytes = 0;
			target->count_suspect = false;
			target->idle = false;
			target->active = jiffies;
			target->interval_packets = U64_MAX;
			target->interval_whole = false;
		}
		/* A chain built whole after the last egress change is current;
		 * one built across a change is not, and is built again -- the
		 * change could not mark a flow that had no entry yet. Nothing
		 * installed is nothing stale, and nor is a discard, whose queue
		 * is no port's. */
		if (!hw || target->hw_discard) {
			target->egress_stale = false;
		} else if (atomic64_read(&ft_egress_changes) != changes) {
			target->egress_stale = true;
			target->stale = true;
		} else if (spec.listeners && !rc) {
			target->egress_stale = false;
		}
		if (build && rc) {
			/* Tried again at the next refresh, not now: a port
			 * that lost carrier, or room another entry is about to
			 * give back, needs time rather than repetition. See
			 * ft_mc_refresh_fn(). */
			target->retries++;
		} else if (!rc) {
			target->retries = 0;
		}
		/* Out of hardware and still a flow, or keyed on another shape:
		 * frames the entry matched reach the CPU again, and one recorded
		 * while the entry carried a different answer must be able to be
		 * recorded again. */
		if (withdrew || swapped)
			ft_mc_forget_seen();
		mutex_unlock(&ft_mc_lock);
		cdx_ft_end();
		if (build) {
			dev_put(spec.in);
			for (i = 0; i < spec.listeners; i++)
				dev_put(spec.listener[i].dev);
		}
	}

	/* A membership with a port, or a route, keeps the hook registered: any
	 * of them can name a flow no frame has shown yet -- a second source, the
	 * same one on another port -- and only a frame can say so. A host-only
	 * membership cannot, since every flow of it goes to the host. And every
	 * route hears whether it is in hardware now, which the routed learner
	 * reports and folds. */
	mutex_lock(&ft_mc_lock);
	want_hook = false;
	list_for_each_entry(g, &ft_mc_groups, list)
		if (g->ports && !g->host) {
			want_hook = true;
			break;
		}
	list_for_each_entry(r, &ft_mc_routes, list)
		if (r->listeners) {
			want_hook = true;
			break;
		}
	told = ft_mc_route_feedback();
	mutex_unlock(&ft_mc_lock);
	if (told)
		ft_mr_kick();
	if (!ft_mc_stopping)
		ft_mc_hook_sync(want_hook);
	else
		ft_mc_hook_sync(false);
	/* The refresh runs while any flow exists; see ft_mc_refresh_fn(). */
	if (READ_ONCE(ft_mc_flow_count) && !READ_ONCE(ft_mc_stopping))
		schedule_delayed_work(&ft_mc_refresh, FT_MC_REFRESH_INTERVAL);
}

/* How far a hardware entry's counters moved from a baseline, or false for a
 * sample below it. Both learners' folds take their deltas from here.
 *
 * One entry's counters only grow -- a listener swap keeps its root -- and each
 * learner starts a baseline from zero when it adds an entry, so a sample below
 * the baseline means one of the two readings was wrong, and one sample cannot
 * say which. The two counters are separate loads of fields the classifier
 * writes, and nothing documents that its 64-bit update is single-copy atomic
 * against a CPU load: a read taken while a carry propagates can be off by 2^32
 * either way. The byte count carries every 4 GiB, which an IPTV stream passes
 * within the hour.
 *
 * A low sample followed by a sane one was the glitch: the baseline stands, and
 * nothing is lost or counted twice. A second low sample in a row says the
 * baseline is what is wrong -- a high glitch folded as real, which cannot be
 * taken back, since the counts are only ever added to -- and it is taken up
 * again from there. Keeping it would fold nothing, and leave a route's count
 * and lastuse standing, until the true count passed the bad baseline: to a
 * daemon that ages routes by either, a stream that stopped for an hour. */
bool ft_mc_count_delta(u64 *base_packets, u64 *base_bytes,
		       bool *suspect, const struct cdx_ft_counters *c,
		       u64 *packets, u64 *bytes)
{
	if (c->packets < *base_packets || c->bytes < *base_bytes) {
		if (*suspect) {
			*base_packets = c->packets;
			*base_bytes = c->bytes;
		}
		*suspect = !*suspect;
		return false;
	}
	*suspect = false;
	*packets = c->packets - *base_packets;
	*bytes = c->bytes - *base_bytes;
	return true;
}

/* What an installed flow's entry counted since the last refresh, read at `now`.
 *
 * An entry that counted nothing for a whole interval is idle, and an idle
 * entry is either a stream that stopped or one whose frames no longer match
 * it -- a sender whose MAC changed, a tag the port now carries -- and those
 * are reaching the CPU and the bridge in software. A shape the hook saw in the
 * meantime takes over the key.
 *
 * An entry that has counted nothing for as long as the bridge keeps a
 * membership nobody refreshes is a stream that stopped. It goes: the entry
 * and its place among the group's flows are for a source that is sending, and
 * a source that resumes reaches the CPU again, where the hook learns it as it
 * learned it the first time. Only an entry's own count says so; a flow never
 * in hardware has none, and is bounded by the group's flows instead.
 *
 * The interval's count is kept, too: it is what a discard saves, and the
 * discard that saves least is the one that gives its group id up when a stream
 * somebody wants finds none (ft_mc_evict_discard()).
 *
 * Called with the transaction and ft_mc_lock held. */
static void ft_mc_flow_counted(struct ft_mc_flow *f,
			       const struct cdx_ft_counters *stats,
			       unsigned long now)
{
	u64 packets = 0, bytes = 0;
	bool counted;

	/* A sample below the last is no answer either way: the entry is
	 * neither idle nor active on it. See ft_mc_count_delta(). */
	counted = ft_mc_count_delta(&f->hw_packets, &f->hw_bytes,
				    &f->count_suspect, stats, &packets, &bytes);
	if (counted) {
		/* Every frame the root matched since the last pass is one the
		 * bridge would have handed the host for ipmr to route, so it is
		 * added to the route's count, which the routed learner folds
		 * into the MFC's. Added, because more than one flow can carry
		 * a route and an entry counts from zero again when it is
		 * replaced by another. */
		if (f->carried_route) {
			spin_lock_bh(&ft_mc_route_lock);
			f->carried_route->stats.packets += packets;
			f->carried_route->stats.bytes += bytes;
			spin_unlock_bh(&ft_mc_route_lock);
		}
		if (packets)
			f->active = now;
		f->hw_packets = stats->packets;
		f->hw_bytes = stats->bytes;
		if (f->interval_whole)
			f->interval_packets = packets;
		f->interval_whole = true;
	}
	f->idle = counted && !packets;
	if (f->idle && f->has_next)
		f->stale = true;
	/* Aged only on a sample that answers: one below the baseline cannot
	 * tell a stream that stopped from one that is running. A discard goes
	 * at the first refresh that counts nothing, not on the membership
	 * interval an entry with listeners ages on: nothing wants the stream,
	 * a live one is never a whole refresh without a frame, and a channel
	 * changed back and forth should not leave an entry for every one it
	 * passed through. */
	if (counted && ((f->hw_discard && !packets) ||
			(f->age && time_after(now, f->active + f->age))))
		f->gone = true;
}

/* Whether a flow nothing carries still has a stream. With no entry there is
 * no count to age it by, and its frames are not recorded again once seen
 * (ft_mc_record()): a flow that has heard nothing for FT_MC_UNCARRIED_AGE
 * supersedes its slot, so its next frame is recorded and drained -- clearing
 * the question in ft_mc_observe() -- and one still asking an age later goes.
 * One record per live flow per age, against a flow every source of every
 * named group would otherwise keep for as long as the group was named.
 * Called with ft_mc_lock held. */
static void ft_mc_flow_probe(struct ft_mc_flow *f, unsigned long now)
{
	struct ft_mc_stream shape;
	struct ft_mc_seen seen;

	lockdep_assert_held(&ft_mc_lock);
	/* A carried flow is aged by its counts. Its clock starts over, and any
	 * question asked before it was installed is dropped: an entry
	 * withdrawn later begins a fresh age rather than going on the spot. */
	if (f->hw) {
		f->probing = false;
		f->seen_at = now;
		return;
	}
	if (f->gone || !time_after(now, f->seen_at + FT_MC_UNCARRIED_AGE))
		return;
	if (f->probing) {
		f->gone = true;
		return;
	}
	f->probing = true;
	f->seen_at = now;
	ether_addr_copy(shape.dst_mac, f->dst_mac);
	ether_addr_copy(shape.src_mac, f->src_mac);
	shape.tagged = f->in_tagged;
	ft_mc_flow_seen(f, &shape, &seen);
	ft_mc_supersede(&seen);
}

/* The periodic half of the bridged learner: what each installed entry has
 * counted since the last pass, and every flow asked of the bridge again.
 *
 * Asking every flow again is for what the bridge decides by and never
 * announces: a querier appearing or timing out turns snooping, and so every
 * answer, on and off with no switchdev event at all. An unchanged answer costs
 * RTNL for the asking and nothing in hardware. The transaction first and the
 * lock second, which is /proc's order and so the only one either may use. */
static void ft_mc_refresh_fn(struct work_struct *work)
{
	struct cdx_ft_counters stats;
	struct ft_mc_flow *f;

	if (READ_ONCE(ft_mc_stopping))
		return;
	cdx_ft_begin();
	mutex_lock(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list) {
		f->dirty = true;
		/* A failed install is tried again one interval apart, up to the
		 * ceiling, which is what stops a flow that cannot be carried
		 * from costing a transaction every interval for good. */
		if (!f->hw && f->retries && f->retries < FT_MC_MAX_RETRIES)
			f->stale = true;
		/* A read that failed is no sample: taken as one, it is a count
		 * gone backwards, and two in a row would re-base the entry at
		 * zero and count the whole stream again into its route. */
		if (f->hw && cdx_mc_group_stats(f->hw, &stats))
			ft_mc_flow_counted(f, &stats, jiffies);
		ft_mc_flow_probe(f, jiffies);
	}
	mutex_unlock(&ft_mc_lock);
	cdx_ft_end();
	if (READ_ONCE(ft_mc_stopping))
		return;
	if (READ_ONCE(ft_mc_flow_count)) {
		schedule_work(&ft_mc_work);
		schedule_delayed_work(&ft_mc_refresh, FT_MC_REFRESH_INTERVAL);
	}
}

/* The MDB half of the switchdev chain.
 *
 * Takes ft_mc_lock and nothing else, and never waits behind a hardware call
 * for it: the worker takes it only around its records, and the one holder
 * that keeps it across a rebuild, the egress drain, holds RTNL as this
 * handler does. Never touches hardware, and answers `handled` for a
 * membership the adapter has taken on -- which is earlier than having
 * installed it, for the reason the section header gives. /proc is the
 * surface that says what is actually in hardware.
 */
bool ft_mc_swdev_obj(unsigned long event,
		     struct switchdev_notifier_port_obj_info *obj)
{
	const struct switchdev_obj_port_mdb *mdb;
	struct net_device *port, *bridge;
	bool host, adding, taken;

	if (obj->obj->id != SWITCHDEV_OBJ_ID_PORT_MDB &&
	    obj->obj->id != SWITCHDEV_OBJ_ID_HOST_MDB)
		return false;
	host = obj->obj->id == SWITCHDEV_OBJ_ID_HOST_MDB;
	adding = event == SWITCHDEV_PORT_OBJ_ADD;
	mdb = SWITCHDEV_OBJ_PORT_MDB(obj->obj);
	/* orig_dev is the bridge for a host membership and the port for a port
	 * group; the bridge is the object's own device in the first case and
	 * the port's master in the second. */
	port = obj->info.dev;
	if (!port || !net_eq(dev_net(port), &init_net))
		return false;
	/* A routed group's bridge snapshot includes the MDB and router ports,
	 * so every membership change can change a routed listener set. The
	 * second set-top box joining on a second port is the case: the routed
	 * group has to grow from one listener to two. Only a kick, and here
	 * rather than at each of the arms below, because this handler holds
	 * RTNL and reaches no hardware whichever way it ends. */
	ft_mr_kick();
	bridge = host ? obj->obj->orig_dev : netdev_master_upper_dev_get(port);
	if (!bridge || !netif_is_bridge_master(bridge)) {
		/* A delete can legitimately arrive after the port has left.
		 * del_nbp() flushes permanent mdb entries from
		 * br_multicast_del_port(), which runs *after*
		 * netdev_upper_dev_unlink(), so the master lookup comes back
		 * empty and the membership would never be removed -- leaving
		 * this module holding a reference that blocks the port's
		 * unregistration for good. Fall back to dropping the port from
		 * wherever it is still a listener. */
		if (!adding && !host) {
			mutex_lock(&ft_mc_lock);
			ft_mc_drop_port(port);
			mutex_unlock(&ft_mc_lock);
			if (!READ_ONCE(ft_mc_stopping))
				schedule_work(&ft_mc_work);
		}
		return false;
	}
	/* The MDB carries the group the bridge learned; addr[] is the
	 * multicast MAC it folds into, which 32 groups share and which this
	 * classifier cannot key on at all. A zero proto means the object came
	 * from a path that does not populate it. */
	if (!mdb->group.proto || ft_mc_link_local(&mdb->group))
		return false;
	/* A blocked port group is one an IGMPv3 source filter says must NOT
	 * receive this source; br_forward() skips it. As a membership it holds
	 * nothing, so it is a leave of the (S,G) record; what it does to the
	 * group's flows is the bridge's answer, which leaves the port out and
	 * which every flow of the group is asked for again below. */
	if (mdb->flags & SWITCHDEV_OBJ_MDB_F_BLOCKED)
		adding = false;

	mutex_lock(&ft_mc_lock);
	taken = READ_ONCE(ft_mc_stopping) ? false :
		ft_mc_membership(bridge, port, &mdb->group, adding, host);
	mutex_unlock(&ft_mc_lock);
	if (!ft_mc_stopping)
		schedule_work(&ft_mc_work);
	return taken;
}

/* The bridge's replay of one port's objects. It sends everything it would
 * send a driver offloading the port -- the VLANs of every port and the
 * bridge, VLAN attributes, the port's MDB -- to this notifier alone; only an
 * added MDB object is a membership, and only it may be read as one: an
 * attribute event's `ptr` is not an object at all. Not ft_swdev_event(),
 * whose VLAN arm would retire every unicast flow on the bridge for nothing. */
static int ft_mc_replay_event(struct notifier_block *nb, unsigned long event,
			      void *ptr)
{
	struct switchdev_notifier_port_obj_info *info = ptr;

	if (event != SWITCHDEV_PORT_OBJ_ADD || !info->obj ||
	    (info->obj->id != SWITCHDEV_OBJ_ID_PORT_MDB &&
	     info->obj->id != SWITCHDEV_OBJ_ID_HOST_MDB))
		return NOTIFY_DONE;
	ft_mc_swdev_obj(event, info);
	return NOTIFY_DONE;
}

static struct notifier_block ft_mc_replay_nb = {
	.notifier_call = ft_mc_replay_event,
};

/* Ask every bridge port for the memberships it already holds.
 *
 * Registering on the switchdev chain replays nothing, and a membership that
 * stands is never announced again: a refreshing report finds its port group
 * and only restarts a timer. So a group joined before this module loaded --
 * a reload is the ordinary case -- would never be offloaded. The bridge's own
 * replay of a port (patch 160 carries each port group's group and blocked
 * flag through it) gives the objects the chain would have. Called after the
 * blocking notifier is registered, so nothing falls between the two; an
 * object arriving both ways is harmless, because ft_mc_membership() takes a
 * restatement as one. Under RTNL, which the replay asserts. */
void ft_mc_replay(void)
{
	struct net_device *dev;
	unsigned int failed = 0;

	rtnl_lock();
	for_each_netdev(&init_net, dev)
		if (netif_is_bridge_port(dev) &&
		    switchdev_bridge_port_replay(dev, dev, NULL, NULL,
						 &ft_mc_replay_nb, NULL))
			failed++;
	rtnl_unlock();
	/* A port whose replay failed part-way keeps what arrived; the rest of
	 * its memberships come back only when announced again. Say so. */
	if (failed)
		pr_warn("cdx: %u bridge ports could not replay their multicast memberships; those stay in software until rejoined\n",
			failed);
}

/* Whether a flow names a device: its bridge, its ingress, or a copy. */
static bool ft_mc_flow_names_dev(const struct ft_mc_flow *f,
				 const struct net_device *dev)
{
	u8 i;

	if (f->bridge == dev || f->in == dev)
		return true;
	for (i = 0; i < f->ports; i++)
		if (f->port[i].dev == dev)
			return true;
	return false;
}

/* A device this learner holds is going away (`unregistering`) or has stopped
 * forwarding.
 *
 * Runs from the netdev chain under RTNL, so it may take ft_mc_lock and must
 * not touch the backend -- the worker does that.
 *
 * A device that stopped forwarding is still what it was: the bridge keeps a
 * permanent port group across a link going down, and never announces it again
 * when the link returns, so a membership naming the device stands. Every flow
 * naming it is asked of the bridge again, whose answer leaves out a port that
 * is not forwarding and forwards nothing received on one.
 *
 * One going away is four roles to clear: a membership's port, a flow's copy, a
 * flow's ingress, and the bridge itself. The bridge reports the first through
 * the MDB, but only sometimes and sometimes too late, and it reports the
 * others never.
 */
void ft_mc_device_gone(struct net_device *dev, bool unregistering)
{
	bool changed = false;
	struct ft_mc_route *r;
	struct ft_mc_group *g;
	struct ft_mc_flow *f;
	unsigned int i, n;
	u8 j;

	mutex_lock(&ft_mc_lock);
	/* A route or a tap naming it is emptied rather than repaired. The
	 * routed learner hears of the same device from the same chain, and its
	 * next derivation publishes whatever is left. */
	list_for_each_entry(r, &ft_mc_routes, list) {
		bool hit = r->bridge == dev;

		for (j = 0; j < r->listeners; j++)
			hit |= r->listener[j].dev == dev;
		if (!hit)
			continue;
		ft_mc_route_clear(r);
		changed = true;
	}
	for (i = 0, n = 0; i < ft_mc_tap_count; i++) {
		if (ft_mc_taps[i].bridge == dev) {
			dev_put(dev);
			changed = true;
			continue;
		}
		ft_mc_taps[n++] = ft_mc_taps[i];
	}
	memset(&ft_mc_taps[n], 0, (ft_mc_tap_count - n) * sizeof(ft_mc_taps[0]));
	ft_mc_tap_count = n;
	if (!unregistering) {
		list_for_each_entry(f, &ft_mc_flows, list) {
			if (!ft_mc_flow_names_dev(f, dev))
				continue;
			f->dirty = true;
			changed = true;
		}
		goto out;
	}
	ft_mc_drop_port(dev);
	list_for_each_entry(g, &ft_mc_groups, list) {
		if (g->bridge != dev)
			continue;
		/* The bridge itself. Its memberships cannot outlive it, and
		 * emptying them is what makes the worker retire them. */
		while (g->ports) {
			g->ports--;
			dev_put(g->port[g->ports]);
			g->port[g->ports] = NULL;
		}
		g->host = false;
		changed = true;
	}
	list_for_each_entry(f, &ft_mc_flows, list) {
		if (f->in == dev || f->bridge == dev) {
			/* The flow's ingress, or its bridge: the flow is over.
			 * Its references go when the worker frees it, and not
			 * before: an installed entry names the ingress, which
			 * the backend borrows and unsubscribes the port's
			 * multicast address through when the entry is deleted,
			 * and an install in flight may be about to leave one.
			 * The device waits for them only as long as the worker
			 * this schedules takes to run. */
			f->gone = true;
			changed = true;
		}
		ft_mc_flow_drop_port(f, dev);
		changed |= f->dirty;
		/* The chain recorded for the entry names this device, which is
		 * going: nothing may replay it now, and its hold must not keep
		 * the device past this worker's next pass. The entry itself is
		 * the worker's to rebuild or take out, which the marks above ask
		 * for -- a routed copy's device reaches the flow through its
		 * route, which the routed learner withdraws. A build running now
		 * may record a chain naming the device again; that record holds
		 * it until the pass this asks for records one without it. */
		for (j = 0; j < f->hw_spec.listeners; j++)
			if (f->hw_spec.listener[j].dev == dev)
				break;
		if (f->hw_spec.in == dev || j < f->hw_spec.listeners) {
			ft_mc_chain_forget(f);
			f->stale = true;
			changed = true;
		}
	}
out:
	mutex_unlock(&ft_mc_lock);
	if (changed && !READ_ONCE(ft_mc_stopping))
		schedule_work(&ft_mc_work);
}

/* Mark every flow on the bridge `dev` is, or is a port of, to be asked of the
 * bridge again. Called from the switchdev chain under RTNL for whatever the
 * bridge decides a flow's ports by and reports as an attribute or a VLAN
 * object: a port's VLAN membership, the bridge's own, its filtering or
 * protocol, a port's STP state, its flags, its multicast router state, the
 * bridge's snooping and its own router state.
 *
 * Marked rather than asked here. A port VLAN object is notified before the
 * bridge applies it, so the state it describes is not yet the state the
 * snapshot would read; the worker reads it afterwards, under RTNL of its own.
 * See ft_mc_flow_derive().
 *
 * What names a stream can change here too: a route names its source only
 * while the bridge is a multicast router (see ft_mc_route_learns()), so a
 * stream recorded while it was not has to be recorded again now that it may
 * be. */
void ft_mc_bridge_changed(struct net_device *dev)
{
	struct net_device *bridge;
	struct ft_mc_flow *f;
	bool marked = false;

	bridge = netif_is_bridge_master(dev) ? dev :
		 netdev_master_upper_dev_get(dev);
	if (!bridge || !netif_is_bridge_master(bridge))
		return;
	mutex_lock(&ft_mc_lock);
	ft_mc_forget_seen();
	list_for_each_entry(f, &ft_mc_flows, list) {
		if (f->bridge != bridge)
			continue;
		f->dirty = true;
		marked = true;
	}
	mutex_unlock(&ft_mc_lock);
	if (marked && !READ_ONCE(ft_mc_stopping))
		schedule_work(&ft_mc_work);
}

/* A device changed its master: a port joined or left a bridge -- `left`, when
 * it is one it left. A flow keyed on a port that left is over, and one copying
 * to it loses that copy, but the bridge says neither -- the port's memberships
 * are flushed after it is unlinked, and nothing at all is said about an
 * ingress -- so every flow naming the device is asked of the bridge again,
 * which answers both.
 *
 * The memberships themselves go here too, from the bridge the port left.
 * del_nbp() flushes every port group the port had, but defers the deletes,
 * and a port moved straight to another bridge is that bridge's port by the
 * time they arrive: the MDB handler, which finds a membership through the
 * port's master, would look on the wrong bridge and leave the old one holding
 * the port for good. What is dropped here is exactly what that flush deletes,
 * and its deletes then find nothing. Called from the netdev chain under
 * RTNL. */
void ft_mc_port_moved(struct net_device *dev, struct net_device *left)
{
	struct ft_mc_group *g;
	struct ft_mc_flow *f;
	bool marked = false;

	mutex_lock(&ft_mc_lock);
	if (left && netif_is_bridge_master(left))
		list_for_each_entry(g, &ft_mc_groups, list)
			if (g->bridge == left && ft_mc_group_drop(g, dev)) {
				ft_mc_touch(g->bridge, &g->addr);
				marked = true;
			}
	list_for_each_entry(f, &ft_mc_flows, list) {
		if (!ft_mc_flow_names_dev(f, dev))
			continue;
		f->dirty = true;
		marked = true;
	}
	mutex_unlock(&ft_mc_lock);
	if (marked && !READ_ONCE(ft_mc_stopping))
		schedule_work(&ft_mc_work);
}

/* Whether a flow's installed chain may have a copy on `dev`: a port the bridge
 * forwards it to, or a route's copy riding it. The recorded chain is exactly
 * what was built; a flow with an entry and nothing recorded -- a device in it
 * went away -- could have any port in it. Called with ft_mc_lock held. */
static bool ft_mc_flow_hw_lists(const struct ft_mc_flow *f,
				const struct net_device *dev)
{
	u8 i;

	lockdep_assert_held(&ft_mc_lock);
	/* A discard copies out of no port, and records nothing for that
	 * reason rather than for having lost a device. */
	if (f->hw_discard)
		return false;
	if (!f->hw_spec.listeners)
		return true;
	for (i = 0; i < f->hw_spec.listeners; i++)
		if (f->hw_spec.listener[i].dev == dev)
			return true;
	return false;
}

/* This learner's half of ft_mc_egress_changed(): every installed flow whose
 * chain may have a copy on `dev` is marked stale for the egress drain and
 * handed to the worker, whose replace rebuilds the whole chain. Takes
 * ft_mc_lock and nothing else. Returns how many were marked. */
unsigned int ft_mc_egress_mark(const struct net_device *dev)
{
	unsigned int marked = 0;
	struct ft_mc_flow *f;

	mutex_lock(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list) {
		if (!f->hw || !ft_mc_flow_hw_lists(f, dev))
			continue;
		f->egress_stale = true;
		f->stale = true;
		marked++;
	}
	if (marked && !ft_mc_stopping)
		schedule_work(&ft_mc_work);
	mutex_unlock(&ft_mc_lock);
	return marked;
}

/* Rebuild what ft_mc_egress_mark(dev) marked, here and now.
 *
 * Called under the RTNL a tc command holds, or without it by CDX's release of
 * a torn-down tree's channels; either way the worker, which takes RTNL to ask
 * the bridge, is never waited for. Nor is anything decided: the port's
 * forwarding did not change, only its queues, so each flow's recorded chain
 * -- the bridge's copies and the routed copies riding it, as they were built,
 * with the flow's own ingress tag and sender -- is replaced by itself, which
 * builds every listener entry against the port as it is now. Transaction
 * first and ft_mc_lock inside it, the order the worker records in, so an entry
 * is never seen here half built -- nor retired from the list with its entry
 * still installed, which the worker does in one transaction hold.
 *
 * A flow this cannot vouch for is handed to the worker and reported with
 * -EAGAIN: its recorded chain lost a device, whose own event has already
 * marked the flow, or the replace failed -- which left the old chain in place,
 * and which the worker's own replace answers by rebuilding or withdrawing the
 * flow, either way in one pass. The caller asks again later; nothing here
 * waits for a retry the refresh paces. */
int ft_mc_egress_drain(const struct net_device *dev)
{
	struct ft_mc_flow *f;
	bool kick = false;
	int rc = 0;

	cdx_ft_begin();
	mutex_lock(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list) {
		if (!f->egress_stale || !ft_mc_flow_hw_lists(f, dev))
			continue;
		if (!f->hw) {
			f->egress_stale = false;
			continue;
		}
		if (!f->hw_spec.listeners ||
		    cdx_mc_group_replace(f->hw, &f->hw_spec)) {
			f->stale = true;
			kick = true;
			rc = -EAGAIN;
			continue;
		}
		f->egress_stale = false;
	}
	if (kick && !ft_mc_stopping)
		schedule_work(&ft_mc_work);
	mutex_unlock(&ft_mc_lock);
	cdx_ft_end();
	return rc;
}

void ft_mc_exit(void)
{
	struct ft_mc_route *r, *rtmp;
	struct ft_mc_group *g, *gtmp;
	struct ft_mc_flow *f, *ftmp;
	LIST_HEAD(dead);
	LIST_HEAD(gone);
	unsigned int i;

	mutex_lock(&ft_mc_lock);
	WRITE_ONCE(ft_mc_stopping, true);
	mutex_unlock(&ft_mc_lock);
	/* Before the work is cancelled, so a hook still registered cannot
	 * re-arm what was just drained; ft_mc_hook_sync() waits out the
	 * readers already inside it, which unregistering alone does not. And
	 * again afterwards, because the worker may have
	 * been part-way through registering one when the flag went up -- the
	 * second call is what actually removes it in that ordering. Both are
	 * serialized against the worker by ft_mc_hook_lock.
	 *
	 * The refresh can queue the worker and the worker can rearm the
	 * refresh, so the refresh is drained on both sides of the worker, the
	 * way the routed learner drains its own pair. */
	ft_mc_hook_sync(false);
	cancel_delayed_work_sync(&ft_mc_refresh);
	cancel_work_sync(&ft_mc_work);
	cancel_delayed_work_sync(&ft_mc_refresh);
	ft_mc_hook_sync(false);
	/* The chain is already unregistered by the caller, so nothing can add
	 * a membership while this drains. The routed learner still runs until
	 * ft_mr_exit() and still reaches the routes, the taps and the flows
	 * through the functions above, so all are emptied under the lock; with
	 * ft_mc_stopping set, nothing it calls refills them. Routes stay
	 * allocated -- their owners free them -- and only come off the list
	 * and let go of their devices. */
	mutex_lock(&ft_mc_lock);
	list_splice_init(&ft_mc_groups, &dead);
	hash_init(ft_mc_group_index);
	list_splice_init(&ft_mc_flows, &gone);
	list_for_each_entry_safe(r, rtmp, &ft_mc_routes, list) {
		list_del(&r->list);
		r->linked = false;
		ft_mc_route_clear(r);
		spin_lock_bh(&ft_mc_route_lock);
		r->carried = false;
		spin_unlock_bh(&ft_mc_route_lock);
	}
	for (i = 0; i < ft_mc_tap_count; i++)
		dev_put(ft_mc_taps[i].bridge);
	memset(ft_mc_taps, 0, sizeof(ft_mc_taps));
	ft_mc_tap_count = 0;
	mutex_unlock(&ft_mc_lock);
	list_for_each_entry_safe(f, ftmp, &gone, list) {
		if (f->hw) {
			cdx_ft_begin();
			cdx_mc_group_del(&f->hw);
			cdx_ft_end();
		}
		list_del(&f->list);
		ft_mc_flow_free(f);
	}
	list_for_each_entry_safe(g, gtmp, &dead, list) {
		list_del(&g->list);
		ft_mc_group_free(g);
	}
	ft_mc_count = 0;
	ft_mc_flow_count = 0;
	ft_mc_installed = 0;
	ft_mc_discarding = 0;
}

/* Why a flow is not being replicated, for an operator looking at a stream
 * that is not offloaded. "Pending" alone would answer several different
 * questions with one word. */
static const char *ft_mc_state(const struct ft_mc_flow *f)
{
	/* Aged or taken back, and listed until the worker retires it: what it
	 * is about to do, not a reason its flags would give a live flow. An
	 * entry it still has stays in hardware and counted meanwhile. */
	if (f->gone)
		return "retiring";
	if (!f->derived)
		return "pending";
	/* Before "installed", deliberately: a flow whose answer has just
	 * changed is still in the table for one more worker pass, and what an
	 * operator needs to read in that window is the reason it is about to
	 * come out. The global switch first, then a bridge filter hook: each
	 * refuses every flow, and undoing it is what would let this one in. */
	if (!READ_ONCE(ft_mc_enabled))
		return "refused-paused";
	if (ft_mc_filtered)
		return "refused-filter";
	if (ft_mc_host_wants(f))
		return "refused-host";
	/* The host routes this stream and no route of it can ride the flow. */
	if (f->routed_host && !ft_mc_live_route(f))
		return "refused-routed";
	/* What runs on the flow's own ports: a netdev chain is netfilter
	 * seeing its frames as a bridge hook would, and tc the same of tc. */
	if (f->nf_hooked)
		return "refused-filter";
	if (f->tc_soft)
		return "refused-tc";
	/* Nowhere to forward it and nothing else wanting it: the bridge drops
	 * it, and the hardware does instead -- or will, once installed. */
	if (ft_mc_discardable(f)) {
		if (f->contested)
			return "refused-contested";
		if (f->retries >= FT_MC_MAX_RETRIES)
			return "refused-failed";
		return f->hw && f->hw_discard ? "discarding" : "pending";
	}
	/* A port the hardware cannot carry, more of them than it can, or none
	 * at all: every listener is behind the ingress, or blocks the source. */
	if (!ft_mc_carriable(f) || (!f->ports && !ft_mc_live_route(f)))
		return "refused-listener";
	if (!ft_mc_mtu_bounded(f))
		return "refused-mtu";
	if (f->contested)
		return "refused-contested";
	if (f->retries >= FT_MC_MAX_RETRIES)
		return "refused-failed";
	/* Still a discard until the replace that brings the listeners in. */
	if (f->hw && !f->hw_discard)
		return "installed";
	return "pending";
}

/* The source of the most specific membership naming a flow: its own for an
 * (S,G) one, zero for a (*,G) one. Called with ft_mc_lock held. */
static const struct br_ip *ft_mc_member_src(const struct ft_mc_flow *f)
{
	static const struct br_ip any;
	const struct ft_mc_group *g;

	list_for_each_entry(g, &ft_mc_groups, list)
		if (g->bridge == f->bridge && (g->ports || g->host) &&
		    ft_mc_same_vlan_group(&g->addr, &f->addr) &&
		    !memcmp(&g->addr.src, &f->addr.src, sizeof(g->addr.src)))
			return &g->addr;
	return &any;
}

/* Whether a membership names any flow, which then speaks for it in /proc.
 * Called with ft_mc_lock held. */
static bool ft_mc_group_has_flow(const struct ft_mc_group *g)
{
	const struct ft_mc_flow *f;

	list_for_each_entry(f, &ft_mc_flows, list)
		if (f->bridge == g->bridge &&
		    ft_mc_same_vlan_group(&g->addr, &f->addr) &&
		    (!memchr_inv(&g->addr.src, 0, sizeof(g->addr.src)) ||
		     !memcmp(&g->addr.src, &f->addr.src, sizeof(g->addr.src))))
			return true;
	return false;
}

static void ft_mc_row(struct seq_file *seq, const struct net_device *bridge,
		      const struct br_ip *addr, const struct br_ip *member,
		      const char *ports, const char *routed,
		      const struct net_device *in, u16 in_vid, const u8 *smac,
		      const u8 *dmac, const char *state,
		      const struct cdx_ft_counters *stats)
{
	if (addr->proto == htons(ETH_P_IPV6))
		seq_printf(seq,
			   "mcast br=%s family=6 group=%pI6c member_src=%pI6c src=%pI6c vid=%u ports=%s routed=%s in=%s in_vid=%u smac=%pM dmac=%pM state=%s packets=%llu bytes=%llu\n",
			   bridge->name, &addr->dst.ip6, &member->src.ip6,
			   &addr->src.ip6, addr->vid, ports, routed,
			   in ? in->name : "-", in_vid, smac, dmac, state,
			   stats->packets, stats->bytes);
	else
		seq_printf(seq,
			   "mcast br=%s family=4 group=%pI4 member_src=%pI4 src=%pI4 vid=%u ports=%s routed=%s in=%s in_vid=%u smac=%pM dmac=%pM state=%s packets=%llu bytes=%llu\n",
			   bridge->name, &addr->dst.ip4, &member->src.ip4,
			   &addr->src.ip4, addr->vid, ports, routed,
			   in ? in->name : "-", in_vid, smac, dmac, state,
			   stats->packets, stats->bytes);
}

/* One row per flow, and one per membership that names none yet -- the
 * memberships a flow speaks for are the reason it exists, not rows of their
 * own. */
void ft_mc_rows(struct seq_file *seq)
{
	static const u8 none[ETH_ALEN];
	char ports[192], routed[192];
	struct cdx_ft_counters stats;
	struct ft_mc_group *g;
	struct ft_mc_flow *f;
	u8 i;

	/* Read outside the transaction the caller holds, which is what the
	 * ordering rule requires: /proc takes cdx_ft_begin() then this, so the
	 * worker must never take them the other way round. It does not. */
	mutex_lock(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list) {
		const struct ft_mc_route *r = f->carried_route ?: f->route;
		size_t n = 0;

		/* What the classifier entry actually matched. The one number
		 * that distinguishes a flow the hardware is carrying from one
		 * that is merely in the table: an installed flow whose count
		 * stays at zero while its stream runs is being forwarded by
		 * the bridge in software, and every other field looks
		 * identical in both cases. The caller holds the transaction
		 * this read needs. */
		cdx_mc_group_stats(f->hw, &stats);
		ports[0] = '\0';
		for (i = 0; i < f->ports; i++)
			n += scnprintf(ports + n, sizeof(ports) - n, "%s%s/%u",
				       i ? "," : "", f->port[i].dev->name,
				       f->port[i].vlans ? f->port[i].vlan[0].id : 0);
		/* The route's copies beside the bridge's own: the ports each
		 * leaves and the tag it leaves with. */
		routed[0] = '\0';
		for (i = 0, n = 0; r && i < r->listeners; i++)
			n += scnprintf(routed + n, sizeof(routed) - n, "%s%s/%u",
				       i ? "," : "", r->listener[i].dev->name,
				       r->listener[i].vlans ?
					       r->listener[i].vlan[0].id : 0);
		/* Two sources, and the difference is the whole design:
		 * `member_src` is what the bridge was asked for -- zero for a
		 * (*,G) join -- and `src` is what the traffic taught us, which
		 * is the one in the hardware key. The Ethernet pair and the
		 * ingress tag are the rest of that key; `in_vid` is 0 for a
		 * stream that arrives untagged on the port's PVID. */
		ft_mc_row(seq, f->bridge, &f->addr, ft_mc_member_src(f),
			  f->ports ? ports : "-", routed[0] ? routed : "-",
			  f->in, f->in_tagged ? f->addr.vid : 0, f->src_mac,
			  f->dst_mac, ft_mc_state(f), &stats);
	}
	memset(&stats, 0, sizeof(stats));
	list_for_each_entry(g, &ft_mc_groups, list) {
		struct br_ip unlearned = g->addr;
		size_t n = 0;

		if (ft_mc_group_has_flow(g))
			continue;
		/* A membership waiting for its first frame: the ports holding
		 * it, which are not yet anything the bridge forwards to, and no
		 * source the traffic has taught. */
		ports[0] = '\0';
		for (i = 0; i < g->ports; i++)
			n += scnprintf(ports + n, sizeof(ports) - n, "%s%s",
				       i ? "," : "", g->port[i]->name);
		memset(&unlearned.src, 0, sizeof(unlearned.src));
		ft_mc_row(seq, g->bridge, &unlearned, &g->addr,
			  g->ports ? ports : "-", "-", NULL, 0, none, none,
			  g->host ? "refused-host" : "pending-source", &stats);
	}
	mutex_unlock(&ft_mc_lock);
}

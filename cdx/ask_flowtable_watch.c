// SPDX-License-Identifier: GPL-2.0-or-later
/* Dependency watches: the neighbour, route, FDB, netdev and switchdev
 * notifiers that invalidate offloaded directions, the invalidation and
 * retirement workers, and the egress hook.
 */
#include "ask_flowtable_internal.h"

/* Caller holds neigh->lock. STALE/DELAY/PROBE still have usable L2 addresses;
 * NOARP is outside this physical Ethernet/ARP contract. Do not keep using a
 * detached object even if its address and NUD state still look usable. */
static bool ft_neigh_matches(struct neighbour *neigh, const u8 *mac)
{
	if (neigh->dead || !ether_addr_equal(neigh->ha, mac))
		return false;
	switch (neigh->nud_state) {
	case NUD_PERMANENT:
	case NUD_REACHABLE:
	case NUD_STALE:
	case NUD_DELAY:
	case NUD_PROBE:
		return true;
	default:
		return false;
	}
}

/* Both tables key on the leading bytes of the address union, so the same
 * pointer resolves an ARP and a neighbour-discovery entry. */
static struct neigh_table *ft_neigh_table(u8 family)
{
	return family == AF_INET6 ? &nd_tbl : &arp_tbl;
}

bool ft_neigh_check(u8 family, struct net_device *dev,
		    const union nf_inet_addr *dst, const u8 *mac)
{
	struct neighbour *neigh = neigh_lookup(ft_neigh_table(family), dst, dev);
	bool valid;

	if (!neigh)
		return false;
	read_lock_bh(&neigh->lock);
	valid = ft_neigh_matches(neigh, mac);
	read_unlock_bh(&neigh->lock);
	neigh_release(neigh);
	return valid;
}

/* Whether the neighbour at @dst is usable and names an address other than
 * @mac: not a neighbour still resolving or gone, but one that has moved. */
bool ft_neigh_moved(u8 family, struct net_device *dev,
		    const union nf_inet_addr *dst, const u8 *mac)
{
	struct neighbour *neigh = neigh_lookup(ft_neigh_table(family), dst, dev);
	bool moved;

	if (!neigh)
		return false;
	read_lock_bh(&neigh->lock);
	moved = ft_neigh_matches(neigh, neigh->ha) && !ether_addr_equal(neigh->ha, mac);
	read_unlock_bh(&neigh->lock);
	neigh_release(neigh);
	return moved;
}

/* A gateway is normally link-local, which a flow endpoint may never be, so
 * this is deliberately weaker than the endpoint test. */
bool ft_nexthop_usable(u8 family, const union nf_inet_addr *next_hop)
{
	int type;

	if (family != AF_INET6)
		return !ipv4_is_multicast(next_hop->ip) && !ipv4_is_zeronet(next_hop->ip) &&
			!ipv4_is_loopback(next_hop->ip) && !ipv4_is_lbcast(next_hop->ip);
	type = ipv6_addr_type(&next_hop->in6);
	return (type & IPV6_ADDR_UNICAST) && !(type & IPV6_ADDR_LOOPBACK);
}

/* The ft_fdb_watch key of a bridged egress: the address the bridge looked its
 * port up under, and the VID, under the adapter's seed. */
static u32 ft_fdb_key(const u8 *mac, u16 vid)
{
	u32 key[2] = {};

	memcpy(key, mac, ETH_ALEN);
	key[1] ^= (u32)vid << 16;
	return jhash2(key, ARRAY_SIZE(key), ft_hash_seed);
}

/* Put an entry on the watch list and into the indexes its dependencies name.
 * Called with ft_watch_lock held. */
static void ft_watch_publish(struct cdx_ft_entry *entry)
{
	list_add_tail(&entry->neigh_list, &ft_neigh_entries);
	if (entry->rule.out_bridge)
		hash_add(ft_fdb_watch, &entry->fdb_node,
			 ft_fdb_key(entry->rule.dst_mac, entry->rule.out_bridge_vid));
	if (entry->neigh)
		hash_add(ft_neigh_watch, &entry->neigh_node, (unsigned long)entry->neigh);
}

int ft_neigh_attach(struct cdx_ft_entry *entry)
{
	struct neighbour *neigh;
	bool valid;

	/* A PPPoE egress has no neighbour to attach. Its Ethernet destination
	 * is the session's concentrator, which no neighbour ever names: a ppp
	 * device is NOARP, arp_constructor() rewrites the key of every
	 * neighbour on it to INADDR_ANY and leaves the hardware address zero,
	 * so there is nothing to validate against and nothing to keep warm.
	 * Publish the entry on the watch list all the same -- that list is what
	 * every device and route notifier scans, and an entry missing from it
	 * is retired by nothing at all. */
	if (entry->rule.out_session.present) {
		spin_lock_bh(&ft_watch_lock);
		ft_watch_publish(entry);
		spin_unlock_bh(&ft_watch_lock);
		return 0;
	}
	if (entry->rule.out_tunnel.present) {
		const struct cdx_ft_tunnel *tunnel = &entry->rule.out_tunnel;
		struct net_device *lower;

		/* A tunnel device is NOARP too and resolves nothing; what this
		 * direction depends on is the outer next hop, which lives on
		 * the device below the tunnel in the outer header's family.
		 * That is the neighbour to hold and to watch, and a change to
		 * it is what retires the entry -- the inner next hop on the
		 * tunnel device is a fiction with a zero address. Admission
		 * holds RTNL, so the index still names the device the walk
		 * resolved. */
		lower = __dev_get_by_index(&init_net, tunnel->lower_ifindex);
		if (!lower)
			return -EOPNOTSUPP;
		neigh = neigh_lookup(ft_neigh_table(tunnel->family), &tunnel->nexthop,
				     lower);
	} else {
		/* Neighbours belong to the device the route names, which is
		 * the VLAN subinterface for a tagged flow; the physical port
		 * never sees them. In the next hop's family, which is the
		 * SA's for a flow encrypted by an SA of the other family. */
		neigh = neigh_lookup(ft_neigh_table(entry->rule.next_hop_family),
				     &entry->next_hop, entry->rule.out_logical);
	}
	if (!neigh)
		return -EOPNOTSUPP;
	/* Recheck at watch publication: the mapping may have changed after the
	 * decoder validated it. Publish before hardware insertion so a notifier
	 * during insertion latches invalidation and forces the normal rollback. */
	read_lock_bh(&neigh->lock);
	valid = ft_neigh_matches(neigh, entry->rule.dst_mac);
	if (valid) {
		spin_lock(&ft_watch_lock);
		entry->neigh = neigh;
		ft_watch_publish(entry);
		spin_unlock(&ft_watch_lock);
		ft_neighbour_refs++;
	}
	read_unlock_bh(&neigh->lock);
	if (!valid)
		neigh_release(neigh);
	return valid ? 0 : -EOPNOTSUPP;
}

/* Watch-list membership and neighbour ownership are no longer the same thing:
 * a PPPoE egress is published with no neighbour at all. Unlink by the list's
 * own emptiness, which admission initialises, so this stays correct both for
 * an entry that never reached the list and for one holding no neighbour. */
void ft_neigh_detach(struct cdx_ft_entry *entry)
{
	struct neighbour *neigh = entry->neigh;

	spin_lock_bh(&ft_watch_lock);
	if (!list_empty(&entry->neigh_list))
		list_del_init(&entry->neigh_list);
	if (!hlist_unhashed(&entry->fdb_node))
		hash_del(&entry->fdb_node);
	if (!hlist_unhashed(&entry->neigh_node))
		hash_del(&entry->neigh_node);
	spin_unlock_bh(&ft_watch_lock);
	if (!neigh)
		return;
	entry->neigh = NULL;
	ft_neighbour_refs--;
	neigh_release(neigh);
}

bool ft_neigh_used(struct cdx_ft_entry *entry, bool active)
{
	struct neighbour *neigh = entry->neigh;
	bool valid;

	/* Nothing to revalidate for a PPPoE egress, and nothing to solicit:
	 * the ppp device answers no ARP. What replaces the neighbour as this
	 * direction's dependency is the ppp device itself, which the netdev
	 * watch already covers through out_logical. */
	if (!neigh)
		return true;
	read_lock_bh(&neigh->lock);
	valid = ft_neigh_matches(neigh, entry->rule.dst_mac);
	read_unlock_bh(&neigh->lock);
	if (!valid) {
		ft_neigh_invalidate(entry);
		return false;
	}
	/* Classifier hits establish use, not reachability. Let Linux advance
	 * STALE -> DELAY -> PROBE and solicit ARP using its own timers. Never
	 * call neigh_confirm() based on hardware activity, including reverse
	 * traffic. No neighbour/watch lock may be held across the protocol call. */
	if (active && neigh_event_send(neigh, NULL)) {
		ft_neigh_invalidate(entry);
		return false;
	}
	return true;
}

void ft_invalidate_work(struct work_struct *work)
{
	/* Every bound device has to be flushed, and the flush has to happen
	 * outside the transaction the binding list is walked under, so the walk
	 * copies the list out first. Sized by the bound admission enforces, which
	 * makes the guard below unreachable rather than a silently short flush. */
	struct net_device *devices[CDX_FT_MAX_BINDINGS];
	struct cdx_ft_binding *binding;
	struct cdx_ft_entry *entry, *next;
	unsigned int n = 0, i;
	int seq;

	cdx_ft_begin();
	/* A pass queued for an event a rearm has since covered finds the latch
	 * clear and has nothing to do. */
	if (!atomic_read(&ft_invalid)) {
		cdx_ft_end();
		return;
	}
	/* Sampled before anything is retired or snapshotted: an event counted
	 * after this has queued a pass of its own. */
	seq = atomic_read(&ft_invalid_seq);
	/* After a failure CDX cannot settle nothing is ever admitted again, so a
	 * repeat pass has no flow to protect. One it is restarting after is
	 * not that: the parked tables' flows go live after the restart, and the
	 * pass has to have flushed them first. */
	if (ft_invalid_done && cdx_ft_terminal()) {
		ft_done_seq = seq;
		cdx_ft_end();
		return;
	}
	list_for_each_entry_safe(entry, next, &ft_entries, list)
		ft_remove(entry);
	/* CDX retains failed deletions and owns the hardware latch. Retry until
	 * a barrier or the stopped datapath makes retirement safe. */
	if (cdx_ft_recover()) {
		cdx_ft_end();
		if (!READ_ONCE(ft_stopping))
			schedule_delayed_work(&ft_work, HZ);
		return;
	}
	list_for_each_entry(binding, &ft_bindings, list) {
		if (WARN_ON_ONCE(n == ARRAY_SIZE(devices)))
			break;
		devices[n++] = binding->dev;
		dev_hold(binding->dev);
	}
	cdx_ft_end();
	/* This flush waits for rule callbacks: end the backend transaction first. */
	for (i = 0; i < n; i++) {
		nf_flow_table_cleanup(devices[i]);
		dev_put(devices[i]);
	}
	cdx_ft_begin();
	if (!ft_invalid_done)
		pr_info("cdx flowtable: invalidated; hardware admission disabled\n");
	/* Publishing completion is this worker's last change of its own, so it
	 * cannot touch a table admitted after it. A later first bind may now
	 * recover if every old binding has gone; a binding parked while this
	 * ran recovers here instead, in the same transaction. */
	ft_invalid_done = true;
	ft_done_seq = seq;
	ft_rearm();
	cdx_ft_end();
}

static bool ft_entry_crosses(const struct cdx_ft_entry *entry, const struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < entry->ncrossed; i++)
		if (entry->crossed[i] == dev)
			return true;
	return false;
}

/* Every device a flow's forwarding depends on: both physical ports, both
 * logical devices, any bridge between them, and every device the walk crossed
 * on the way down -- a VLAN device under a session, a tunnel or another tag,
 * and the ppp device under a tunnel. A VLAN device carries its own MTU and
 * administrative state, a bridge carries both plus the FDB that chose the
 * egress port, and a device under a session or a tunnel had to carry the
 * port's address for the walk to admit the direction, so a flow depends on
 * each exactly as it depends on the physical port underneath. */
bool ft_entry_uses(const struct cdx_ft_entry *entry, const struct net_device *dev)
{
	return ft_rule_names(&entry->rule, dev) || ft_entry_crosses(entry, dev);
}

static bool ft_device_used(const struct net_device *dev)
{
	struct cdx_ft_binding *binding;
	struct cdx_ft_entry *entry;

	lockdep_assert_held(&ft_watch_lock);
	/* Bindings matter before the first flow arrives, and a directional
	 * flow's egress need not have an ingress binding of its own. Compare
	 * pinned device objects, never names or recyclable interface indices. */
	list_for_each_entry(binding, &ft_bindings, list)
		if (binding->dev == dev)
			return true;
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
		if (ft_entry_uses(entry, dev))
			return true;
	return false;
}

/* The strongest part @dev plays here. Pinned device objects are compared,
 * never names or recyclable interface indices. A physical port is never
 * crossed -- a path's walk ends on it -- so a crossed device is never a
 * port as well. */
static enum ft_device_role ft_device_role(const struct net_device *dev)
{
	bool port = false, named = false, crossed = false;
	struct cdx_ft_binding *binding;
	struct cdx_ft_entry *entry;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(binding, &ft_bindings, list)
		port |= binding->dev == dev;
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
		port |= entry->rule.in == dev || entry->rule.out == dev;
		named |= ft_rule_names(&entry->rule, dev);
		crossed |= ft_entry_crosses(entry, dev);
	}
	spin_unlock_bh(&ft_watch_lock);
	return port ? FT_DEV_PORT : named ? FT_DEV_NAMED :
	       crossed ? FT_DEV_CROSSED : FT_DEV_UNUSED;
}

static void ft_device_retire(const struct net_device *dev, atomic64_t *counter)
{
	struct cdx_ft_entry *entry;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
		if (ft_entry_uses(entry, dev))
			ft_handle_invalidate(entry->handle, counter);
	spin_unlock_bh(&ft_watch_lock);
}

/* A port, or a VLAN of one, that stops forwarding has to stop carrying
 * software flows as well as hardware ones. ft_device_retire() reaches only
 * entries this adapter admitted. A flow it refused, never saw, or that
 * another table owns keeps a valid handle, and one naming the port as its
 * ingress is matched by the flowtable hook, which __netif_receive_skb_core()
 * runs before the bridge's rx_handler -- so br_handle_frame() never gets to
 * drop the frame. The forward-path walk refuses such a port from now on;
 * this takes away what it described before.
 *
 * Native cleanup does the teardown, but it sleeps: it takes flowtable_lock
 * and flushes the offload work that runs this module's rule callbacks. An
 * MSTI's state arrives inside br_mst_set_state()'s RCU read-side section, so
 * the port is queued instead.
 */
struct ft_stopped {
	struct list_head list;
	struct net_device *dev;
	netdevice_tracker tracker;
};

static LIST_HEAD(ft_stopped_list);
static DEFINE_SPINLOCK(ft_stopped_lock);
/* An allocation failed and lost which port stopped: sweep every one. */
static bool ft_stopped_all;
static void ft_stopped_workfn(struct work_struct *work);
DECLARE_WORK(ft_stopped_work, ft_stopped_workfn);

static void ft_port_stopped(struct net_device *dev)
{
	struct ft_stopped *stopped;

	/* Unload unregisters the chain that calls this before it flushes the
	 * work, so queueing needs no lifetime test of its own. */
	spin_lock_bh(&ft_stopped_lock);
	list_for_each_entry(stopped, &ft_stopped_list, list)
		if (stopped->dev == dev)
			goto out;
	stopped = kzalloc(sizeof(*stopped), GFP_ATOMIC);
	if (stopped) {
		stopped->dev = dev;
		netdev_hold(dev, &stopped->tracker, GFP_ATOMIC);
		list_add_tail(&stopped->list, &ft_stopped_list);
	} else {
		ft_stopped_all = true;
	}
	schedule_work(&ft_stopped_work);
out:
	spin_unlock_bh(&ft_stopped_lock);
}

/* Every device a flow through dev names as its ingress: the port itself and,
 * for a port that is a VLAN device, the real device at the bottom of it,
 * where the forward-path walk ends. A bridge, whose own entry's VLAN
 * stopped, stands for all of its ports. */
static void ft_stopped_clean(struct net_device *dev)
{
	struct net_device *lower;
	struct list_head *iter;

	ASSERT_RTNL();
	if (netif_is_bridge_master(dev)) {
		netdev_for_each_lower_dev(dev, lower, iter)
			ft_stopped_clean(lower);
		return;
	}
	nf_flow_table_cleanup(dev);
	if (is_vlan_dev(dev))
		nf_flow_table_cleanup(vlan_dev_real_dev(dev));
}

static void ft_stopped_workfn(struct work_struct *work)
{
	struct ft_stopped *stopped, *next;
	struct net_device *dev;
	LIST_HEAD(todo);
	bool all;

	spin_lock_bh(&ft_stopped_lock);
	list_splice_init(&ft_stopped_list, &todo);
	all = ft_stopped_all;
	ft_stopped_all = false;
	spin_unlock_bh(&ft_stopped_lock);
	/* Under RTNL, as the native NETDEV_DOWN cleanup runs: rule callbacks
	 * only try for it, so the flush inside cannot wait on this. Never
	 * inside the backend transaction, which those callbacks take. */
	rtnl_lock();
	/* The forward hook walks the path and inserts the flow inside one RCU
	 * read-side section. After a grace period every flow a walk described
	 * before the state changed is in a table for the sweep to find, and
	 * every later walk sees the new state and refuses the path. The grace
	 * period starts only once RTNL is held: several events are raised
	 * before the change they report, inside the RTNL section that makes
	 * it, so only then is the change certain to be in place. */
	synchronize_net();
	if (all)
		for_each_netdev(&init_net, dev)
			if (netif_is_bridge_port(dev))
				ft_stopped_clean(dev);
	list_for_each_entry_safe(stopped, next, &todo, list) {
		ft_stopped_clean(stopped->dev);
		list_del(&stopped->list);
		netdev_put(stopped->dev, &stopped->tracker);
		kfree(stopped);
	}
	rtnl_unlock();
}

/* XFRM policy changes the routed learner re-derived every group for, counted
 * from the atomic netevent. */
atomic64_t ft_mr_xfrm_changes = ATOMIC64_INIT(0);

int ft_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;
	switch (event) {
	case NETDEV_REGISTER:
		/* Also how every port that already exists is reached:
		 * register_netdevice_notifier() replays this event for each of
		 * them, under the RTNL the attachment needs, so there is no
		 * separate startup walk to keep in step with this one. */
		ft_ipsec_attach(dev);
		/* And the same replay is how an AP interface that already
		 * exists at load is found. */
		ft_wifi_reconsider(dev);
		break;
	case NETDEV_UP:
	case NETDEV_DOWN:
		/* The pair that carries every VAP transition. An interface is
		 * registered by the driver long before hostapd configures it,
		 * so UP is where it becomes a VAP; and because changing an
		 * interface's type raises no event of its own, DOWN is the
		 * only thing that reliably precedes one -- so retiring here is
		 * what keeps a device that comes back as a station from
		 * keeping the VAP it held as an AP. */
		ft_wifi_reconsider(dev);
		/* A routed group refused because one of its ports had no
		 * carrier has nothing else that would ever reconsider it: the
		 * MFC entry does not change when a link returns, and no frame
		 * re-offers a group the way a packet re-offers a flow. */
		ft_mr_kick();
		break;
	case NETDEV_CHANGE:
		/* Covers the reverse too: an interface leaving AP mode stops
		 * being a VAP, and the worker retires it. */
		ft_wifi_reconsider(dev);
		/* A tunnel device raises only this when `ip tunnel change`
		 * rewrites its endpoints, TTL or traffic class in place, and it
		 * is always running with carrier, so the check below would
		 * pass it. Every flow through it was admitted against the old
		 * parameters and would keep inserting the old header from
		 * hardware while software inserted the new one; retire them
		 * and let the next packet re-offer each against the tunnel as
		 * it now is. */
		if (ft_tunnel_dev(dev)) {
			ft_device_retire(dev, &ft_link_invalidations);
			break;
		}
		if (netif_running(dev) && netif_carrier_ok(dev))
			break;
		fallthrough;
	case NETDEV_GOING_DOWN:
		/* Native DOWN also flushes flowtable work. Admission rechecks
		 * both ports under RTNL; UP never clears failure state. */
		ft_device_retire(dev, &ft_link_invalidations);
		/* A multicast flow's ports are not flowtable entries and no
		 * admission recheck reaches them, so they need telling
		 * separately: every flow naming the device is asked of the
		 * bridge again, and its memberships stand. */
		ft_mc_device_gone(dev, false);
		/* And a routed group's, which ipmr reports only when the VIF
		 * itself is removed -- a link going down leaves the VIF in
		 * place and the entry keyed on a port carrying nothing. */
		ft_mr_device_gone(dev);
		break;
	case NETDEV_CHANGEMTU:
		/* IPv4 flushes route caches under this event's RTNL. Admission
		 * rechecks both destinations before publishing queued context. */
		ft_device_retire(dev, &ft_mtu_invalidations);
		/* And an SA riding the port fragments SEC's output to the old
		 * MTU; nothing re-offers an SA, so it is asked to follow its
		 * path, which is where the new MTU shows. */
		ft_ipsec_device_moved(dev);
		/* A multicast group is carried only while no packet its ingress
		 * can deliver is larger than a listener's MTU, and an installed
		 * group is no exception: both learners reconsider every group,
		 * installed ones included. */
		ft_mc_kick_all();
		ft_mr_kick();
		break;
	case NETDEV_CHANGEADDR:
		/* NEIGH software output uses the current MAC. Reject a queued
		 * stale hardware source too, invalidating its entire generation. */
		ft_device_retire(dev, &ft_mac_invalidations);
		/* An SA on this port carries the same address in its own entry
		 * and is not re-offered the way a retired flow is, so it is
		 * corrected rather than retired. */
		ft_ipsec_device_moved(dev);
		/* A VAP carries it too, in the port and in the encoder's
		 * record, and neither can be rewritten in place -- so it is
		 * registered again instead. */
		ft_wifi_address_changed(dev);
		/* And every routed multicast copy sent through the device, in
		 * its own entry or riding a bridged group: each is written with
		 * its oif's address, which no MFC event follows. A VLAN device
		 * that took its address from the device below follows it and
		 * raises this again for itself. Asked of every group, because
		 * the device may be an oif of any; one whose address did not
		 * change derives the plan it already has, which costs the
		 * hardware nothing. A bridged copy keeps its sender's address
		 * and has nothing to follow. */
		ft_mr_kick();
		break;
	case NETDEV_CHANGENAME:
		/* Names carry no forwarding semantics; backend lookup uses the
		 * pinned physical device, including after table recreation. */
		break;
	case NETDEV_UNREGISTER:
		/* Drop the ops before the device goes, so nothing can reach
		 * this module through a device it no longer owns. Any SA still
		 * bound to it has already been deleted by the core, which
		 * unwinds offloaded states when their device unregisters. */
		ft_ipsec_detach(dev);
		/* And every multicast reference to it, which is what would
		 * otherwise hold the unregistration open forever. Both
		 * learners: a routed group pins its ingress port and every
		 * listener exactly as a bridged one does. */
		ft_mc_device_gone(dev, true);
		ft_mr_device_gone(dev);
		/* Same shape for a VAP: the watch stops naming the device here
		 * so nothing can follow the pointer, and the worker releases
		 * what is left using only what it copied. */
		ft_wifi_device_gone(dev);
		/* And a VLAN device's counter record, which outlives its flows
		 * and so has nothing but this event to end it. */
		ft_dev_stats_gone(dev);
		/* A device that is neither bound nor any direction's port --
		 * a VLAN device, a bridge, a ppp or tunnel device, named by a
		 * flow or only crossed by one -- is a dependency of the flows
		 * through it and nothing more, so its removal retires exactly
		 * those and leaves the bindings and admission up. That is also
		 * what its route going away does, but not reliably first: a
		 * session dropping or `ip link del` removes the route in the
		 * same RTNL transaction, and the retirement that causes runs
		 * asynchronously, so the watch list can still name the device
		 * when this arrives. Only a port's removal stops admission
		 * globally, below. */
		if (ft_device_role(dev) != FT_DEV_PORT) {
			ft_device_retire(dev, &ft_link_invalidations);
			break;
		}
		fallthrough;
	case NETDEV_CHANGEUPPER:
		/* A port joining or leaving a bridge, which no switchdev event
		 * reports for a multicast flow's ingress; and when leaving,
		 * the bridge it left. */
		if (event == NETDEV_CHANGEUPPER) {
			struct netdev_notifier_changeupper_info *upper = ptr;

			ft_mc_port_moved(dev, upper->linking ? NULL :
					      upper->upper_dev);
		}
		/* A device paths only cross gaining or losing an upper changes
		 * those paths and nothing any flow names; retire them the same
		 * way. Anywhere else an upper change may change what a port or
		 * a flow's own device carries, and stops admission globally. */
		if (event == NETDEV_CHANGEUPPER && ft_device_role(dev) == FT_DEV_CROSSED) {
			ft_device_retire(dev, &ft_link_invalidations);
			break;
		}
		spin_lock_bh(&ft_watch_lock);
		/* Latch before releasing the watch lock: a concurrent last unbind
		 * and fresh bind must not redirect this event to a new table. */
		if (ft_device_used(dev))
			ft_invalidate();
		spin_unlock_bh(&ft_watch_lock);
		break;
	}
	return NOTIFY_DONE;
}

static int ft_route_event(const struct netevent_ipv4_route *event)
{
	struct cdx_ft_entry *entry;
	__be32 mask;

	if (!net_eq(event->net, &init_net))
		return NOTIFY_DONE;
	if (event->prefixlen > 32) {
		ft_invalidate();
		ft_ipsec_all_moved();
		return NOTIFY_DONE;
	}
	mask = inet_make_mask(event->prefixlen);
	spin_lock_bh(&ft_watch_lock);
	ft_ipsec_route_moved(AF_INET, &event->dst, mask, event->prefixlen);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
		/* The outer route of an egress tunnel is a dependency of its
		 * own, in the outer header's family rather than the flow's,
		 * and nothing borrowed from the flow watches it: the inner
		 * destination is on the tunnel device whatever the outer
		 * route does. Matched on the outer destination, by the same
		 * conservative rule as the inner endpoints below. */
		if (entry->rule.out_tunnel.present &&
		    entry->rule.out_tunnel.family == AF_INET &&
		    !((entry->rule.out_tunnel.remote.ip ^ event->dst) & mask)) {
			ft_handle_invalidate(entry->handle, &ft_route_invalidations);
			continue;
		}
		/* After NAT, current egress uses new_dst; reverse egress uses src.
		 * Check both endpoints even if only one direction installed. Match
		 * all tables/DSCP aliases conservatively: a new more-specific route
		 * can supersede a route which never emitted a deletion event. */
		if (entry->rule.family != AF_INET)
			continue;
		if (!((entry->rule.new_dst.ip ^ event->dst) & mask) ||
		    !((entry->rule.src.ip ^ event->dst) & mask))
			ft_handle_invalidate(entry->handle, &ft_route_invalidations);
	}
	spin_unlock_bh(&ft_watch_lock);
	return NOTIFY_DONE;
}

/* The same contract one family over. This one can arrive in softirq under the
 * FIB table lock, so it must stay non-blocking; ft_watch_lock never nests the
 * other way round. */
static int ft_route6_event(const struct netevent_ipv6_route *event)
{
	struct cdx_ft_entry *entry;

	if (!net_eq(event->net, &init_net))
		return NOTIFY_DONE;
	if (event->prefixlen > 128) {
		ft_invalidate();
		ft_ipsec_all_moved();
		return NOTIFY_DONE;
	}
	spin_lock_bh(&ft_watch_lock);
	ft_ipsec_route_moved(AF_INET6, &event->dst, 0, event->prefixlen);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
		if (entry->rule.out_tunnel.present &&
		    entry->rule.out_tunnel.family == AF_INET6 &&
		    ipv6_prefix_equal(&entry->rule.out_tunnel.remote.in6, &event->dst,
				      event->prefixlen)) {
			ft_handle_invalidate(entry->handle, &ft_route_invalidations);
			continue;
		}
		if (entry->rule.family != AF_INET6)
			continue;
		if (ipv6_prefix_equal(&entry->rule.new_dst.in6, &event->dst, event->prefixlen) ||
		    ipv6_prefix_equal(&entry->rule.src.in6, &event->dst, event->prefixlen))
			ft_handle_invalidate(entry->handle, &ft_route_invalidations);
	}
	spin_unlock_bh(&ft_watch_lock);
	return NOTIFY_DONE;
}

int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct neighbour *neigh = ptr;
	struct cdx_ft_entry *entry;

	if (event == NETEVENT_XFRM_POLICY_UPDATE) {
		const struct xfrm_flowtable_change *change = ptr;

		if (!net_eq(change->net, &init_net))
			return NOTIFY_DONE;
		/* Atomic notification, including policy expiry. Never enter the
		 * hardware backend while the XFRM policy lock is held. Only the
		 * directions the changed policy can select are retired: every
		 * published handle is watched, so Linux no longer retires the
		 * rest on the generation alone. */
		spin_lock_bh(&ft_watch_lock);
		list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
			if (nf_flow_offload_handle_valid(entry->handle) &&
			    ft_policy_covers(change->pol, &entry->rule))
				ft_handle_invalidate(entry->handle,
						     &ft_ipsec_policy_invalidations);
		spin_unlock_bh(&ft_watch_lock);
		/* An output policy can govern a routed multicast copy, which
		 * nothing else about the group changes to report: every group
		 * is asked again. The kick only queues work. */
		atomic64_inc(&ft_mr_xfrm_changes);
		ft_mr_kick();
		return NOTIFY_DONE;
	}
	if (event == NETEVENT_IPV4_ROUTE_UPDATE)
		return ft_route_event(ptr);
	if (event == NETEVENT_IPV6_ROUTE_UPDATE)
		return ft_route6_event(ptr);
	if (event != NETEVENT_NEIGH_UPDATE ||
	    (neigh->tbl != &arp_tbl && neigh->tbl != &nd_tbl) ||
	    !net_eq(dev_net(neigh->dev), &init_net))
		return NOTIFY_DONE;
	read_lock_bh(&neigh->lock);
	spin_lock(&ft_watch_lock);
	hash_for_each_possible(ft_neigh_watch, entry, neigh_node, (unsigned long)neigh) {
		if (entry->neigh == neigh &&
		    !ft_neigh_matches(neigh, entry->rule.dst_mac)) {
			/* Ordinary NUD ageing with a usable MAC needs no retirement.
			 * Every connection sharing the bad neighbour is marked, and
			 * its other direction observes the same handle invalidation. */
			ft_neigh_invalidate(entry);
		}
	}
	/* An SA watching this peer is corrected rather than retired: nothing
	 * re-offers an SA the way a packet re-offers a flow. */
	ft_ipsec_neigh_moved(neigh);
	spin_unlock(&ft_watch_lock);
	read_unlock_bh(&neigh->lock);
	return NOTIFY_DONE;
}

int ft_fib_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct fib_notifier_info *info = ptr;
	struct cdx_ft_entry *entry;

	/* ipmr and ip6mr announce their VIFs, their MFC entries and their
	 * policy rules on this same chain under two families of their own.
	 * They describe a replication list rather than a route, so they are
	 * answered by the routed multicast learner and never reach the unicast
	 * retirement below -- which would otherwise see an unknown event and
	 * retire the whole table on every MFC change. */
	if (info->family == RTNL_FAMILY_IPMR ||
	    info->family == RTNL_FAMILY_IP6MR)
		return ft_mr_fib_event(event, info);
	if (info->family != AF_INET && info->family != AF_INET6)
		return NOTIFY_DONE;
	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_APPEND:
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_DEL:
		/* These selected-alias notifications can precede commit and omit
		 * other aliases. The routing core reports every committed prefix in both
		 * families through NETEVENT_IPV[46]_ROUTE_UPDATE, including table
		 * flushes. This also absorbs the registration dump. */
		break;
	case FIB_EVENT_NH_ADD:
	case FIB_EVENT_NH_DEL:
		/* IPv4 emits these while synchronizing built-in nexthops on
		 * device/address transitions. A revived alternative can change
		 * routing even for flows not using that device. Retire all flow
		 * generations without closing bindings; RTNL/dst revalidation
		 * excludes queued routes from before the completed transition.
		 * These are not notifications from the nexthop-object API. */
		spin_lock_bh(&ft_watch_lock);
		list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
			ft_handle_invalidate(entry->handle, &ft_link_invalidations);
		spin_unlock_bh(&ft_watch_lock);
		break;
	default:
		/* Policy changes and unknown events require explicit recovery. */
		ft_invalidate();
	}
	return NOTIFY_DONE;
}

int ft_nexthop_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	/* The nexthop-object API is separate from FIB_EVENT_NH_*. Replacing
	 * a shared member or resilient bucket can redirect installed flows
	 * without changing a FIB alias. Until these dependencies are tracked,
	 * require full table recreation. Statistics queries change no route.
	 * Registration/unregistration dumps are harmless before first bind or
	 * after ft_stopping; ft_invalidate() enforces those lifetime guards. */
	if (event != NEXTHOP_EVENT_HW_STATS_REPORT_DELTA)
		ft_invalidate();
	return NOTIFY_DONE;
}

/* The bridge FDB is the fifth dependency class, and the only one Linux does
 * not already retire a software flow for. br_fill_forward_path() picked this
 * flow's egress port with br_fdb_find_rcu(bridge, destination MAC, VID), so
 * the hardware entry is pinned to whichever port that entry named at
 * admission; a station that roams, or an entry that ages out and is relearned
 * elsewhere, otherwise keeps forwarding to the old port until something
 * unrelated retires the flow. Nothing in net/bridge/ consults a flowtable, so
 * an upstream bridged flow caches the same port in its DIRECT tuple and is
 * stale for exactly as long in software.
 *
 * fdb_notify() reaches this chain for a plain, non-switchdev bridge too, and
 * covers every way the pinning can change: a roam emits a delete against the
 * old port and then an add against the new one, ageing and explicit deletion
 * emit a delete, and a port leaving the bridge deletes everything it learned.
 * The chain is atomic -- br_fdb_update() learns from softirq -- so this only
 * latches invalidation, like every other notifier here.
 *
 * Matching on the destination MAC and VID alone is deliberately broader than
 * the bridge membership this cannot check without RTNL: a same-address event
 * on an unrelated bridge costs one retirement and readmission, where missing
 * a real move costs silent misforwarding.
 */
int ft_fdb_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	const struct switchdev_notifier_fdb_info *info = ptr;
	struct net_device *port = switchdev_notifier_info_to_dev(ptr);
	struct cdx_ft_entry *entry;

	if ((event != SWITCHDEV_FDB_ADD_TO_DEVICE &&
	     event != SWITCHDEV_FDB_DEL_TO_DEVICE) ||
	    !port || !net_eq(dev_net(port), &init_net))
		return NOTIFY_DONE;
	spin_lock_bh(&ft_watch_lock);
	hash_for_each_possible(ft_fdb_watch, entry, fdb_node, ft_fdb_key(info->addr, info->vid)) {
		/* Only the egress direction is chosen by an FDB entry, and the
		 * address it was looked up under is this rule's destination
		 * MAC. An add naming the port the flow already leaves by
		 * re-states the pinning rather than changing it. */
		if (!entry->rule.out_bridge ||
		    entry->rule.out_bridge_vid != info->vid ||
		    !ether_addr_equal(entry->rule.dst_mac, info->addr) ||
		    (event == SWITCHDEV_FDB_ADD_TO_DEVICE && port == entry->rule.out))
			continue;
		ft_handle_invalidate(entry->handle, &ft_fdb_invalidations);
	}
	spin_unlock_bh(&ft_watch_lock);
	return NOTIFY_DONE;
}

/* ft_bridge_vlan() reads three pieces of bridge configuration: whether the
 * bridge filters by VLAN at all, which protocol it filters in, and each
 * port's membership. A flow's tag stack depends on all three exactly as it
 * depends on a VLAN device, and none of them emits a netdev event: the ports
 * stay up across every one of these changes, so nothing else here would
 * notice. Each arrives on this chain instead -- memberships as PORT_VLAN
 * objects against the port, the two bridge-wide settings as attributes
 * against the bridge -- and each is administrative and rare, so a device this
 * adapter depends on takes the same coarse route as a nexthop-object change
 * rather than pricing a per-entry match into a blocking chain.
 *
 * The scope test is not optional. Every bridge installs its default PVID on a
 * port the moment that port is enslaved, whatever its VLAN filtering setting,
 * so without it enslaving any device anywhere would retire every flow on the
 * hardware.
 *
 * Never set handled: the bridge treats a handled object or attribute as
 * installed in hardware, and for a port VLAN it then skips vlan_vid_add(),
 * which would leave the port filtering that VLAN out. This is an observer,
 * and an observer must leave -EOPNOTSUPP to be the chain's answer.
 */

/* Whether a port attribute takes a bridge port, one MSTI of it, or one VLAN
 * of it or of the bridge's own entry, out of FORWARDING -- or may take any
 * port of a bridge out of it, for the two bridge-wide MST events. A VLAN
 * moved to another MSTI takes up, on every port, the state that MSTI has
 * there, or DISABLED if none, and has no event of its own for it; switching
 * MST off makes each port's own STP state, which MST ignored, apply again. */
static bool ft_stp_stopped(const struct switchdev_attr *attr)
{
	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_STP_STATE:
		return attr->u.stp_state != BR_STATE_FORWARDING;
	case SWITCHDEV_ATTR_ID_PORT_MST_STATE:
		return attr->u.mst_state.state != BR_STATE_FORWARDING;
	case SWITCHDEV_ATTR_ID_PORT_VLAN_STATE:
		return attr->u.vlan_state.state != BR_STATE_FORWARDING;
	case SWITCHDEV_ATTR_ID_VLAN_MSTI:
		return true;
	case SWITCHDEV_ATTR_ID_BRIDGE_MST:
		return !attr->u.mst;
	default:
		return false;
	}
}

int ft_swdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	const struct switchdev_notifier_port_attr_info *attr;
	const struct switchdev_notifier_port_obj_info *obj;
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);

	if (!dev || !net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	switch (event) {
	case SWITCHDEV_PORT_OBJ_ADD:
	case SWITCHDEV_PORT_OBJ_DEL:
		obj = ptr;
		if (!obj->obj)
			return NOTIFY_DONE;
		/* An MDB object is a membership rather than a dependency: it
		 * describes something to install, not something to retire, and
		 * it is answered rather than merely observed. See the
		 * Multicast section. */
		if (obj->obj->id == SWITCHDEV_OBJ_ID_PORT_MDB ||
		    obj->obj->id == SWITCHDEV_OBJ_ID_HOST_MDB) {
			struct switchdev_notifier_port_obj_info *info = ptr;

			if (ft_mc_swdev_obj(event, info))
				info->handled = true;
			return NOTIFY_DONE;
		}
		if (obj->obj->id != SWITCHDEV_OBJ_ID_PORT_VLAN)
			return NOTIFY_DONE;
		break;
	case SWITCHDEV_PORT_ATTR_SET:
		attr = ptr;
		if (!attr->attr)
			return NOTIFY_DONE;
		switch (attr->attr->id) {
		case SWITCHDEV_ATTR_ID_BRIDGE_MROUTER:
		case SWITCHDEV_ATTR_ID_PORT_MROUTER:
		case SWITCHDEV_ATTR_ID_BRIDGE_MC_DISABLED:
		case SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS:
		case SWITCHDEV_ATTR_ID_PORT_STP_STATE:
		case SWITCHDEV_ATTR_ID_PORT_MST_STATE:
		case SWITCHDEV_ATTR_ID_PORT_VLAN_STATE:
		case SWITCHDEV_ATTR_ID_BRIDGE_MST:
		case SWITCHDEV_ATTR_ID_VLAN_MSTI:
			/* Observe only: each of these can change where the
			 * bridge forwards a stream, and whether it hands one to
			 * the host, without changing any MFC entry or MDB
			 * membership -- a bridge oif's copy set for the routed
			 * learner, a flow's ports and host delivery for the
			 * bridged one. The kernel snapshot, not the event's
			 * coarse boolean, is authority for both. */
			ft_mr_kick();
			ft_mc_bridge_changed(dev);
			/* A port STP takes out of FORWARDING carries nothing in
			 * the bridge from here on, while its hardware entries
			 * would forward on in both directions under the shared
			 * handle, and a software flow naming it as ingress would
			 * carry on past br_handle_frame(). Admission refuses such
			 * a port too; this retires what was admitted or cached
			 * before. An MSTI or a VLAN leaving FORWARDING retires
			 * the whole port, and the bridge's own entry every port:
			 * rules are not mapped onto VLANs here. The bridge-wide
			 * MST events, on the bridge itself, retire every port of
			 * it; admission keeps such a bridge out of hardware, so
			 * what they reach is software. */
			if (ft_stp_stopped(attr->attr)) {
				ft_device_retire(dev, &ft_stp_invalidations);
				ft_port_stopped(dev);
			}
			return NOTIFY_DONE;
		default:
			break;
		}
		if (attr->attr->id != SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING &&
		    attr->attr->id != SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL)
			return NOTIFY_DONE;
		break;
	default:
		return NOTIFY_DONE;
	}
	/* A routed group that expands through a bridge derives every
	 * listener's tag from exactly the three settings this case carries, so
	 * a change to any of them makes its recorded set describe something
	 * the bridge no longer does. It is re-derived rather than retired; the
	 * worker decides whether the group survives the new configuration.
	 * A bridged flow holds the same three decisions for its copies and its
	 * ingress, and is asked of the bridge again the same way. */
	ft_mr_kick();
	ft_mc_bridge_changed(dev);
	spin_lock_bh(&ft_watch_lock);
	/* Latch before releasing the watch lock, exactly as the netdev
	 * upper-device event does: a concurrent last unbind and fresh bind must
	 * not redirect this event to a new table. */
	if (ft_device_used(dev))
		ft_invalidate();
	spin_unlock_bh(&ft_watch_lock);
	return NOTIFY_DONE;
}

/* CDX changed a port's egress: an HTB tree switched it to or from CEETM, a
 * class moved or went away, or the DSCP map was turned on or off for it
 * (struct cdx_ft_egress_ops). Each hardware entry transmitting on the port
 * names a queue chosen when it was installed -- or the map, which reads one
 * per frame -- and nothing drains the queues of the mode the port left, so
 * everything on it is re-installed against what the port has now. Flows are
 * retired and readmitted on their next packet, which is the same treatment a
 * route or MTU change gets; SAs and multicast groups are rebuilt in place,
 * because nothing re-offers one -- a group's whole listener chain, since every
 * listener entry names its own queue.
 *
 * Relies on no lock of the caller's: both callers hold RTNL, but admission is
 * caught without it. It sleeps, on the learners' mutexes. The change is
 * counted first, fully ordered after whatever the caller changed and before
 * any walk: something being built meanwhile either reads the new state or sees
 * the count move when it records what it built (ft_ipsec_watch_add(), the
 * multicast workers), and marks itself. Admission publishes a flow on the
 * watch list before building its hardware entry and removes it if the handle
 * was invalidated meanwhile, to the same effect. */
static void ft_egress_changed(struct net_device *dev)
{
	atomic64_inc_return(&ft_egress_changes);
	ft_device_retire(dev, &ft_qos_invalidations);
	ft_ipsec_egress_changed(dev);
	ft_mc_egress_changed(dev);
}

/* Wait until everything ft_egress_changed(dev) started has finished: every
 * flow it retired is out of the hardware, and every SA and multicast group on
 * the port it asked to rebuild has been rebuilt. CDX calls this before handing
 * the microcode's DSCP map to another port: the map is one table with no port
 * in it, so an entry still reading it after the hand-over would transmit on the
 * other port's queues.
 *
 * Retirement stands aside for a global invalidation, which removes every
 * entry itself, so that is waited for too -- and a recovery that cannot finish
 * yet, the hardware not proven stopped, is reported rather than waited out.
 * So is an unload in progress, which retires everything on its own schedule,
 * an SA whose rebuild failed and is waiting for its peer, an SA being deleted
 * whose entries are not out of the hardware yet, and a multicast group whose
 * recorded chain lost a device or whose rebuild failed, which its worker now
 * owns. -EAGAIN leaves nothing to undo; the caller asks again later.
 *
 * Sleeps. Safe under RTNL, which none of the work waited on takes except by
 * trying. Both multicast workers do take RTNL, to ask the bridge and ipmr, so
 * their groups are rebuilt here rather than waited for. Not under the control
 * mutex, which all of it takes. */
static int ft_egress_drain(struct net_device *dev)
{
	bool done, retiring;
	int rc;

	might_sleep();
	flush_work(&ft_retire_work);
	if (atomic_read(&ft_invalid)) {
		flush_delayed_work(&ft_work);
		/* A rearm since the read above cleared the latch and reset the
		 * done flag with it -- which it only does once the invalidation
		 * has finished, so that counts as done too. */
		cdx_ft_begin();
		done = ft_invalid_done || !atomic_read(&ft_invalid);
		cdx_ft_end();
		if (!done)
			return -EAGAIN;
	}
	if (READ_ONCE(ft_stopping))
		return -EAGAIN;
	/* An SA installing across the change publishes its watch, marked if
	 * the change reached it too late, inside its control transaction; one
	 * passed through here has finished doing so. */
	cdx_ft_begin();
	cdx_ft_end();
	/* The flag stays set until the rebuild has happened, through a pass
	 * running now and through a failure, which waits for the next event
	 * that would retry it; so ask for a pass and wait for it rather than
	 * for one that nothing may be running. */
	if (ft_ipsec_rebuild_pending(dev)) {
		schedule_work(&ft_ipsec_follow);
		flush_work(&ft_ipsec_follow);
		if (ft_ipsec_rebuild_pending(dev))
			return -EAGAIN;
	}
	/* An SA being deleted has left the watch list already, and its entries
	 * leave the hardware only when ft_ipsec_retire gets to it. Reported,
	 * not waited for: that work may be waiting on a recovery that needs
	 * RTNL, which the caller can hold. */
	cdx_ft_begin();
	retiring = ft_ipsec_retire_pending();
	cdx_ft_end();
	if (retiring)
		return -EAGAIN;
	/* And every multicast group with a copy on the port, both learners'
	 * whatever the first says: each rebuilds what it can. */
	rc = ft_mc_egress_drain(dev);
	return ft_mr_egress_drain(dev) ?: rc;
}

/* CDX restarted the datapath after a deletion it could not prove (struct
 * cdx_ft_egress_ops). While it was stopped every flow was declined, every
 * multicast group and SA rebuild refused, and a binding parked behind an
 * invalidation held back, since none of that drains while the latch is held.
 * Flows come back on their next offer by themselves; the rest is asked for
 * here: both learners reconsider every group, every SA has its peer looked up
 * again -- which rebuilds only the ones that need it -- and a parked binding is
 * rearmed if its invalidation has drained. Each queues its own work and takes
 * no lock of CDX's here. */
static void ft_egress_restarted(void)
{
	ft_mc_kick_all();
	ft_mr_kick();
	ft_ipsec_all_moved();
	schedule_work(&ft_ipsec_follow);
	schedule_delayed_work(&ft_rearm_work, 0);
}

const struct cdx_ft_egress_ops ft_egress_ops = {
	.changed = ft_egress_changed,
	.drain = ft_egress_drain,
	.restarted = ft_egress_restarted,
};

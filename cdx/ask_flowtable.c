// SPDX-License-Identifier: GPL-2.0-or-later
/* Linux flowtable adapter for bounded IPv4 and IPv6 TCP and UDP offload.
 *
 * Backend transactions serialize hardware operations and adapter lists. Rule callbacks are
 * process-context NF workqueue callbacks. Binding release runs after the
 * flow-block core excludes callbacks. Notifiers only latch invalidation and
 * queue work; they never start a backend transaction. Dependency notifications inspect
 * bound devices and immutable flow dependencies under ft_watch_lock. Neighbour
 * notifications nest this lock inside neigh->lock, and bridge FDB
 * notifications nest it inside the bridge's own hash lock, from softirq.
 * Nothing takes a neighbour or bridge lock while holding ft_watch_lock, so
 * neither nesting has an opposite order.
 * Invalidation ends its transaction before flushing Netfilter work. The backend
 * uses RTNL trylock for admission and fatal recovery, never a blocking acquire.
 * Each binding pins its ingress device; each installed direction pins egress.
 */
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/hashtable.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/fib_notifier.h>
#include <net/flow_offload.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/netevent.h>
#include <net/nexthop.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/switchdev.h>
#include "cdx_flowtable_backend.h"
#include "cdx_flowtable.h"

#if !defined(FLOW_CLS_HAS_NF_CONTEXT) || FLOW_CLS_HAS_NF_CONTEXT < 8
#error "CDX flowtable requires patches/kernel/140-ask-flowtable-context.patch"
#endif

/* The bridge FDB pins a bridged flow's egress port, and this is the only
 * chain a plain bridge reports FDB and VLAN-membership changes on. Building
 * without it would offload bridged flows and never retire a stale one, which
 * is a silent misforward rather than a missing feature. */
#if !IS_ENABLED(CONFIG_NET_SWITCHDEV)
#error "CDX flowtable requires CONFIG_NET_SWITCHDEV for bridge FDB invalidation"
#endif

/* A rule must be able to describe every encapsulation a tuple can carry;
 * otherwise a stack Netfilter admits would be silently truncated here. */
static_assert(CDX_FT_VLAN_MAX == NF_FLOW_TABLE_ENCAP_MAX);

#ifdef CDX_DEBUG_FLOWTABLE
static unsigned int ft_fail_stage;
static unsigned int ft_init_fail_stage;
module_param_named(init_fail_stage, ft_init_fail_stage, uint, 0444);
MODULE_PARM_DESC(init_fail_stage, "Fail adapter load: 1 proc, 2 netdev, 3 neighbour, 4 FIB, 5 indirect registration, 6 nexthop objects, 7 bridge FDB, 8 bridge VLAN configuration");
module_param_named(flowtable_fail_stage, ft_fail_stage, uint, 0600);
MODULE_PARM_DESC(flowtable_fail_stage, "One-shot add failure: 1 before allocation, 2 before hardware, 3 after hardware, 4 busy after peer direction");
#endif

/* Egress QoS classification. The conntrack mark is the only key the software
 * and hardware paths can share: an offloaded flow produces no skb, so nothing
 * a tc filter decides can reach it. Reading it here keeps one source of truth.
 *
 * Both are boot-immutable, like offload_owner, because a mask that changed
 * under live flows would leave already-installed entries encoding a layout
 * nothing else still agrees with.
 *
 * A zero mask disables classification entirely and restores the historical
 * contract exactly: any nonzero mark refuses admission, so a mark meant for
 * policy routing is never silently reinterpreted as a queue. The mask is
 * reported in the proc header, and the controller renders its own admission
 * test from that rather than restating this one.
 *
 * A masked value of zero is indistinguishable from an unmarked flow, as with
 * every other fwmark scheme; that case takes the default class rather than
 * naming class zero.
 */
static unsigned int ft_qos_mark_mask;
static unsigned int ft_qos_default_class;
module_param_named(qos_mark_mask, ft_qos_mark_mask, uint, 0444);
MODULE_PARM_DESC(qos_mark_mask, "Conntrack mark bits holding the egress class; 0 disables classification and refuses marked flows");
module_param_named(qos_default_class, ft_qos_default_class, uint, 0444);
MODULE_PARM_DESC(qos_default_class, "Class for flows whose masked mark is zero: low nibble class queue, high nibble channel");

/* Reject a class the hardware cannot express rather than truncating it into a
 * different queue, which would accelerate the flow onto a queue nobody asked
 * for instead of declining it. */
static bool ft_qos_class_valid(unsigned int class)
{
	return class <= U8_MAX &&
		((class & CDX_FT_QOS_CHANNEL_MASK) >> CDX_FT_QOS_CHANNEL_SHIFT) <=
			CDX_FT_QOS_MAX_CHANNEL;
}

/* Map a conntrack mark onto an egress class. The masked bits are shifted down
 * to their own base so an operator can place the field anywhere in the word
 * and share the rest with policy routing or a VPN's own marks. */
static u8 ft_qos_class(u32 mark)
{
	if (!ft_qos_mark_mask)
		return 0;
	mark = (mark & ft_qos_mark_mask) >> __ffs(ft_qos_mark_mask);
	return mark ? (u8)mark : (u8)ft_qos_default_class;
}

struct cdx_ft_binding {
	struct list_head list;
	struct net_device *dev;
	struct nf_flowtable *table; /* retained as identity; borrowed in bind only */
};

/* One PPPoE session's statistics record, shared by every direction naming that
 * session: claimed when the first is admitted and returned when the last
 * retires, so the counters describe the session rather than any one flow and
 * survive a connection coming and going underneath them.
 *
 * Keyed on the identity the path walk already derived, the device the session
 * runs over included: a session id is unique only per concentrator and per
 * client, and two sessions to different concentrators can share one. The
 * device is held as an index rather than a pinned object because nothing here
 * dereferences it -- an index that was recycled could only match after every
 * entry naming the old one had retired and freed this record.
 *
 * slot is NULL for a session admitted while the firmware's small pool was
 * empty. That is a session without counters, not a flow without hardware, and
 * it stays that way for the session's life so the answer does not change
 * underneath a running connection.
 */
struct cdx_ft_session_stats {
	struct list_head list;
	int lower_ifindex;
	u16 id;
	u8 mac[ETH_ALEN];
	unsigned int refs;
	struct cdx_ft_stats_slot *slot;
};

struct cdx_ft_entry {
	struct list_head list;
	struct hlist_node cookie_node;
	struct hlist_node key_node;
	struct list_head neigh_list;
	struct neighbour *neigh;
	struct nf_flow_offload_handle *handle;
	union nf_inet_addr next_hop;
	struct cdx_ft_binding *binding;
	/* The session record each half of this direction counts into, or NULL.
	 * Held on the entry rather than in the rule: a rule is compared
	 * bytewise against a stored one to decide whether anything changed,
	 * and an attached resource is not part of that description. */
	struct cdx_ft_session_stats *in_stats;
	struct cdx_ft_session_stats *out_stats;
	unsigned long cookie;
	struct cdx_ft_rule rule;
	struct cdx_ft_hw *hw;
	struct cdx_ft_counters reported;
};

/* Admission budget, not a firmware maximum. Directions consume slots
 * independently without eviction. The deployed TCP/UDP classifiers each have
 * 32768 buckets and dynamically allocated entries, one pair per family, so
 * this single budget is the more conservative bound once both are in use.
 * Keep software indexes at a maximum average load of two; dependency
 * invalidation remains a bounded walk because a single route/device/neighbour
 * event can affect every flow.
 */
#define CDX_FT_MAX_ENTRIES 32768U
#define CDX_FT_HASH_BITS 14

/* Binding mutations hold both the backend transaction and ft_watch_lock.
 * Transaction readers and device notifiers can therefore use their own lock.
 * The binding's existing device reference covers its entire watch lifetime. */
static LIST_HEAD(ft_bindings);
static LIST_HEAD(ft_entries);
/* Both indexes share the backend transaction and the entry's list lifetime. */
static DEFINE_HASHTABLE(ft_cookies, CDX_FT_HASH_BITS);
static DEFINE_HASHTABLE(ft_keys, CDX_FT_HASH_BITS);
static u32 ft_hash_seed;
/* Flow watch publication/removal is serialized by the backend transaction.
 * Neighbour, route and device notifiers share the immutable rule, neigh and
 * handle, protected against entry removal here. Never take a neighbour lock
 * or start a backend transaction while holding this lock. */
static LIST_HEAD(ft_neigh_entries);
static DEFINE_SPINLOCK(ft_watch_lock);
static LIST_HEAD(ft_block_list);
/* Session statistics records, under the backend transaction like the entries
 * that reference them. No notifier walks this list. */
static LIST_HEAD(ft_session_stats);
static unsigned int ft_bound, ft_count;
static unsigned int ft_neighbour_refs;
static unsigned int ft_handle_refs;
static atomic64_t ft_neigh_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_route_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_mtu_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_link_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_mac_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_fdb_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_admission_invalidations = ATOMIC64_INIT(0);
static u64 ft_installs, ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy;
static u64 ft_rearms;
static bool ft_ready, ft_stopping;
static atomic_t ft_invalid = ATOMIC_INIT(0);
static bool ft_invalid_done;
static struct proc_dir_entry *ft_proc;
static void ft_invalidate_work(struct work_struct *work);
static void ft_neigh_detach(struct cdx_ft_entry *entry);
static void ft_retire_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_work, ft_invalidate_work);
static DECLARE_WORK(ft_retire_work, ft_retire_workfn);

static bool ft_fault(unsigned int stage)
{
#ifdef CDX_DEBUG_FLOWTABLE
	return cmpxchg(&ft_fail_stage, stage, 0) == stage;
#else
	return false;
#endif
}

static void ft_invalidate(void)
{
	if (READ_ONCE(ft_bound) && !READ_ONCE(ft_stopping) &&
	    atomic_cmpxchg(&ft_invalid, 0, 1) == 0)
		schedule_delayed_work(&ft_work, 0);
}

static struct cdx_ft_entry *ft_find(struct cdx_ft_binding *binding,
				  unsigned long cookie)
{
	struct cdx_ft_entry *entry;

	hash_for_each_possible(ft_cookies, entry, cookie_node,
			       cookie ^ (unsigned long)binding)
		if (entry->binding == binding && entry->cookie == cookie)
			return entry;
	return NULL;
}

/* Called with either the backend transaction or the notifier's ft_watch_lock held. The
 * handle is immutable, owned before watch publication and shared by both
 * directions. Marking it also excludes Linux's cached flow immediately;
 * native GC later retires that generation without flushing unrelated flows.
 */
static void ft_handle_invalidate(struct nf_flow_offload_handle *handle,
				 atomic64_t *counter)
{
	if (nf_flow_offload_handle_invalidate(handle))
		atomic64_inc(counter);
	if (!READ_ONCE(ft_stopping))
		schedule_work(&ft_retire_work);
}

static void ft_neigh_invalidate(struct cdx_ft_entry *entry)
{
	ft_handle_invalidate(entry->handle, &ft_neigh_invalidations);
}

/* The binding already pins the ingress port for its whole lifetime, so only
 * the egress port and any VLAN device the rule names still need a reference.
 * A logical device equal to its physical port must not be counted twice. */
static void ft_devices_hold(const struct cdx_ft_rule *rule)
{
	dev_hold(rule->out);
	if (rule->out_logical != rule->out)
		dev_hold(rule->out_logical);
	if (rule->in_logical != rule->in)
		dev_hold(rule->in_logical);
	/* A bridge is a device of its own, and is the logical device itself
	 * when the route is through the bridge rather than a VLAN on it. One
	 * bridge can also carry both directions, when a flow is routed between
	 * two VLANs of the same bridge. Count each object once. */
	if (rule->out_bridge && rule->out_bridge != rule->out_logical)
		dev_hold(rule->out_bridge);
	if (rule->in_bridge && rule->in_bridge != rule->in_logical &&
	    rule->in_bridge != rule->out_bridge)
		dev_hold(rule->in_bridge);
}

static void ft_devices_put(const struct cdx_ft_rule *rule)
{
	if (rule->in_bridge && rule->in_bridge != rule->in_logical &&
	    rule->in_bridge != rule->out_bridge)
		dev_put(rule->in_bridge);
	if (rule->out_bridge && rule->out_bridge != rule->out_logical)
		dev_put(rule->out_bridge);
	if (rule->in_logical != rule->in)
		dev_put(rule->in_logical);
	if (rule->out_logical != rule->out)
		dev_put(rule->out_logical);
	dev_put(rule->out);
}

/* The record for one session, created on first reference. Exhaustion of the
 * firmware pool is deliberately not a failure: counters are observability and
 * forwarding is the product, so the record is created regardless and simply
 * carries no slot. That also keeps the reference counting uniform -- every
 * direction naming a session holds a reference whether or not a slot exists,
 * so the session shows up in the read-back either way and the degradation is
 * visible rather than silent. */
static struct cdx_ft_session_stats *ft_session_stats_get(const struct cdx_ft_session *session)
{
	struct cdx_ft_session_stats *record;

	/* Asserted past the early return, not before it: a direction with no
	 * session touches neither the list nor the firmware pool, and claiming
	 * it needs a transaction would say something about this call that is
	 * not true of it. */
	if (!session->present)
		return NULL;
	cdx_ft_assert_held();
	list_for_each_entry(record, &ft_session_stats, list)
		if (record->id == session->id &&
		    record->lower_ifindex == session->lower_ifindex &&
		    ether_addr_equal(record->mac, session->mac)) {
			record->refs++;
			return record;
		}
	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return NULL;
	record->id = session->id;
	record->lower_ifindex = session->lower_ifindex;
	ether_addr_copy(record->mac, session->mac);
	record->refs = 1;
	if (cdx_ft_stats_alloc(CDX_FT_STATS_TIMESTAMPED, &record->slot))
		record->slot = NULL;
	list_add_tail(&record->list, &ft_session_stats);
	return record;
}

static void ft_session_stats_put(struct cdx_ft_session_stats **held)
{
	struct cdx_ft_session_stats *record = *held;

	if (!record)
		return;
	cdx_ft_assert_held();
	*held = NULL;
	if (--record->refs)
		return;
	/* The last direction naming this session has retired, so the firmware
	 * is no longer counting into the record and the slot can go back to a
	 * pool the next session will draw from. */
	cdx_ft_stats_free(&record->slot);
	list_del(&record->list);
	kfree(record);
}

/* Both halves of one connection name the same session and therefore share one
 * record, so a connection holds two references to it. Nothing here can fail:
 * a direction whose record could not be created counts nowhere and forwards
 * regardless. */
static void ft_stats_attach(struct cdx_ft_entry *entry)
{
	entry->in_stats = ft_session_stats_get(&entry->rule.in_session);
	entry->out_stats = ft_session_stats_get(&entry->rule.out_session);
}

static void ft_stats_detach(struct cdx_ft_entry *entry)
{
	ft_session_stats_put(&entry->in_stats);
	ft_session_stats_put(&entry->out_stats);
}

static void ft_stats_binding(const struct cdx_ft_entry *entry,
			     struct cdx_ft_stats_binding *binding)
{
	binding->in_session = entry->in_stats ? entry->in_stats->slot : NULL;
	binding->out_session = entry->out_stats ? entry->out_stats->slot : NULL;
}

static int ft_remove(struct cdx_ft_entry *entry)
{
	int rc = cdx_ft_del(&entry->hw);

	if (rc) {
		ft_errors++;
		ft_invalidate();
	}
	list_del(&entry->list);
	hash_del(&entry->cookie_node);
	hash_del(&entry->key_node);
	ft_neigh_detach(entry);
	/* After the hardware entry is gone, so the firmware has stopped
	 * counting into the record before it can be handed to anyone else. */
	ft_stats_detach(entry);
	nf_flow_offload_handle_put(entry->handle);
	ft_handle_refs--;
	ft_devices_put(&entry->rule);
	kfree(entry);
	ft_count--;
	ft_deletes++;
	return rc;
}

static void ft_retire_workfn(struct work_struct *work)
{
	struct cdx_ft_entry *entry, *next;

	cdx_ft_begin();
	list_for_each_entry_safe(entry, next, &ft_entries, list) {
		/* A failed retirement escalates to the existing global recovery.
		 * That worker proves a barrier or quiesces the datapath before
		 * reporting completion. Never rearm a terminal hardware failure. */
		if (ft_stopping || atomic_read(&ft_invalid))
			break;
		if (!nf_flow_offload_handle_valid(entry->handle))
			ft_remove(entry);
	}
	cdx_ft_end();
}

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

static bool ft_neigh_check(u8 family, struct net_device *dev,
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

/* A gateway is normally link-local, which a flow endpoint may never be, so
 * this is deliberately weaker than the endpoint test. */
static bool ft_nexthop_usable(u8 family, const union nf_inet_addr *next_hop)
{
	int type;

	if (family != AF_INET6)
		return !ipv4_is_multicast(next_hop->ip) && !ipv4_is_zeronet(next_hop->ip) &&
			!ipv4_is_loopback(next_hop->ip) && !ipv4_is_lbcast(next_hop->ip);
	type = ipv6_addr_type(&next_hop->in6);
	return (type & IPV6_ADDR_UNICAST) && !(type & IPV6_ADDR_LOOPBACK);
}

/* Borrow the route selected by Netfilter, not a second FIB lookup which could
 * lose its policy/ingress context. Patch 140 supplies only retained NEIGH dsts
 * with the cookie they were selected under: an IPv6 destination belongs to one
 * FIB generation and dst_check() rejects every one of them against a zero
 * cookie. No route pointer escapes the callback. Transformed routes need a
 * separate contract in either family. dev is the logical egress device, which
 * is the VLAN subinterface rather than the physical port when the flow is
 * tagged; the destination Netfilter selected belongs to that device. */
static bool ft_next_hop(const struct flow_cls_offload *cls,
			struct net_device *dev, u8 family,
			const union nf_inet_addr *daddr,
			union nf_inet_addr *next_hop)
{
	struct dst_entry *dst = cls->nf_dst;

	if (!dst || dst->ops->family != family || dst->dev != dev ||
	    dst_xfrm(dst) || dst->lwtstate || dst->error ||
	    !dst_check(dst, cls->nf_dst_cookie))
		return false;
	memset(next_hop, 0, sizeof(*next_hop));
	if (family == AF_INET6) {
		const struct rt6_info *rt = dst_rt6_info(dst);

		/* RTF_CACHE routes name their own destination as the next hop,
		 * which is correct, but a local/anycast route is not forwarding. */
		if (rt->rt6i_flags & (RTF_REJECT | RTF_LOCAL | RTF_ANYCAST))
			return false;
		next_hop->in6 = *rt6_nexthop(rt, &daddr->in6);
	} else {
		const struct rtable *rt = dst_rtable(dst);

		if (rt->rt_type != RTN_UNICAST ||
		    (rt->rt_gw_family && rt->rt_gw_family != AF_INET))
			return false;
		next_hop->ip = rt_nexthop(rt, daddr->ip);
	}
	return ft_nexthop_usable(family, next_hop);
}

/* Admission holds RTNL. Check both borrowed destinations after taking it:
 * a callback queued before a route change must not install even its otherwise
 * valid direction. The invalid handle makes Linux retire that generation.
 * RTNL does not exclude an IPv6 route change, which router advertisements
 * commit from softirq, so this is also repeated once the entry is published.
 * Never re-resolve a route here with an incomplete policy/ingress context.
 */
static bool ft_routes_valid(const struct flow_cls_offload *cls)
{
	return cls->nf_dst && cls->nf_dst_reverse &&
		dst_check(cls->nf_dst, cls->nf_dst_cookie) &&
		dst_check(cls->nf_dst_reverse, cls->nf_dst_reverse_cookie);
}

static int ft_neigh_attach(struct cdx_ft_entry *entry)
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
		list_add_tail(&entry->neigh_list, &ft_neigh_entries);
		spin_unlock_bh(&ft_watch_lock);
		return 0;
	}
	/* Neighbours belong to the device the route names, which is the VLAN
	 * subinterface for a tagged flow; the physical port never sees them. */
	neigh = neigh_lookup(ft_neigh_table(entry->rule.family), &entry->next_hop,
			     entry->rule.out_logical);
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
		list_add_tail(&entry->neigh_list, &ft_neigh_entries);
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
static void ft_neigh_detach(struct cdx_ft_entry *entry)
{
	struct neighbour *neigh = entry->neigh;

	spin_lock_bh(&ft_watch_lock);
	if (!list_empty(&entry->neigh_list))
		list_del_init(&entry->neigh_list);
	spin_unlock_bh(&ft_watch_lock);
	if (!neigh)
		return;
	entry->neigh = NULL;
	ft_neighbour_refs--;
	neigh_release(neigh);
}

static bool ft_neigh_used(struct cdx_ft_entry *entry, bool active)
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

/* A flow endpoint must be globally routable between the two ports: an IPv6
 * link-local address is scoped to one link and cannot be forwarded off it. */
static bool ft_endpoint(u8 family, const union nf_inet_addr *address)
{
	int type;

	if (family != AF_INET6)
		return !ipv4_is_multicast(address->ip) && !ipv4_is_zeronet(address->ip) &&
			!ipv4_is_loopback(address->ip) && !ipv4_is_lbcast(address->ip);
	type = ipv6_addr_type(&address->in6);
	return (type & IPV6_ADDR_UNICAST) &&
		!(type & (IPV6_ADDR_LOOPBACK | IPV6_ADDR_LINKLOCAL |
			  IPV6_ADDR_MAPPED | IPV6_ADDR_COMPATv4));
}

static bool ft_exact6(const struct in6_addr *mask)
{
	int i;

	for (i = 0; i < 4; i++)
		if (mask->s6_addr32[i] != htonl(0xffffffff))
			return false;
	return true;
}

/* Conntrack zeroes the whole address union, so does ft_parse: the unused arm
 * never carries stale bytes and both families compare with one helper. */
static bool ft_tuple_matches(const struct cdx_ft_rule *rule,
			     const struct nf_conntrack_tuple *tuple)
{
	return nf_inet_addr_cmp(&rule->src, &tuple->src.u3) &&
		nf_inet_addr_cmp(&rule->dst, &tuple->dst.u3) &&
		rule->sport == tuple->src.u.all && rule->dport == tuple->dst.u.all;
}

/* Validate one native address/port edit group against the resolved conntrack
 * mapping. Netfilter orders SNAT before DNAT, including inverse reply edits.
 * IPv4 rewrites its address in a single mangle word; IPv6 emits one word per
 * quarter, in address order, and the port edit follows the last of them. */
static bool ft_nat_edit(const struct flow_action_entry *ip,
			const struct cdx_ft_rule *out, bool source)
{
	bool v6 = out->family == AF_INET6;
	const union nf_inet_addr *addr = source ? &out->new_src : &out->new_dst;
	unsigned int words = v6 ? 4 : 1;
	unsigned int offset = v6 ?
		(source ? offsetof(struct ipv6hdr, saddr) : offsetof(struct ipv6hdr, daddr)) :
		(source ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr));
	enum flow_action_mangle_base htype = v6 ? FLOW_ACT_MANGLE_HDR_TYPE_IP6 :
						  FLOW_ACT_MANGLE_HDR_TYPE_IP4;
	const struct flow_action_entry *port = ip + words;
	u32 value = source ? htonl((u32)ntohs(out->new_sport) << 16) :
			     htonl(ntohs(out->new_dport));
	u32 mask = source ? ~htonl(0xffff0000) : ~htonl(0x0000ffff);
	unsigned int i;

	for (i = 0; i < words; i++) {
		const struct flow_action_entry *word = ip + i;

		if (word->id != FLOW_ACTION_MANGLE || word->mangle.htype != htype ||
		    word->mangle.offset != offset + i * sizeof(u32) ||
		    word->mangle.mask || word->mangle.val != addr->all[i])
			return false;
	}
	return port->id == FLOW_ACTION_MANGLE && port->mangle.htype == (out->proto == IPPROTO_TCP ?
			FLOW_ACT_MANGLE_HDR_TYPE_TCP : FLOW_ACT_MANGLE_HDR_TYPE_UDP) &&
		!port->mangle.offset && port->mangle.mask == mask && port->mangle.val == value;
}

/* Linux owns allocation and lifetime of every resolved NAT mapping. No
 * arbitrary flower edit or partly resolved translation is admissible. */
static bool ft_translation(const struct flow_cls_offload *cls, struct cdx_ft_rule *out)
{
	const struct nf_conn *ct = cls->nf_ct;
	const struct nf_conntrack_tuple *orig = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	const struct nf_conntrack_tuple *reply = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	const struct nf_conntrack_tuple *opposite;
	const struct flow_action *actions = &cls->rule->action;
	const struct flow_action_entry *csum;
	unsigned long status = READ_ONCE(ct->status), nat = status & IPS_NAT_MASK;
	unsigned int edits = !!(nat & IPS_SRC_NAT) + !!(nat & IPS_DST_NAT);
	/* Four Ethernet mangles, then one action per ingress tag popped and
	 * per egress tag pushed, then the translation, then the redirect. IPv4
	 * spends two actions per edit and appends one checksum action; IPv6
	 * spends five and has no header checksum to recompute. An egress
	 * session adds one push; an ingress session adds nothing, because
	 * Linux emits no pop for one. */
	unsigned int encaps = out->in_vlans + out->out_vlans +
			      out->out_session.present, offset = 4 + encaps;
	unsigned int per_edit = out->family == AF_INET6 ? 5 : 2;
	unsigned int fixed = out->family == AF_INET6 ? 5 : 6;
	bool forward;

	out->new_src = out->src;
	out->new_dst = out->dst;
	out->new_sport = out->sport;
	out->new_dport = out->dport;
	if (!nat)
		return actions->num_entries == 5 + encaps;
	if (((nat & IPS_SRC_NAT) && !(status & IPS_SRC_NAT_DONE)) ||
	    ((nat & IPS_DST_NAT) && !(status & IPS_DST_NAT_DONE)) ||
	    (out->proto != IPPROTO_UDP && out->proto != IPPROTO_TCP) ||
	    actions->num_entries != fixed + encaps + per_edit * edits)
		return false;
	forward = ft_tuple_matches(out, orig);
	if (forward == ft_tuple_matches(out, reply))
		return false;
	/* Every endpoint without translation must agree in both tuples. */
	if (!(nat & IPS_DST_NAT) &&
	    (!nf_inet_addr_cmp(&orig->dst.u3, &reply->src.u3) ||
	     orig->dst.u.all != reply->src.u.all))
		return false;
	if (!(nat & IPS_SRC_NAT) &&
	    (!nf_inet_addr_cmp(&orig->src.u3, &reply->dst.u3) ||
	     orig->src.u.all != reply->dst.u.all))
		return false;
	opposite = forward ? reply : orig;
	out->new_src = opposite->dst.u3;
	out->new_dst = opposite->src.u3;
	out->new_sport = opposite->dst.u.all;
	out->new_dport = opposite->src.u.all;
	if (!ft_endpoint(out->family, &out->new_src) ||
	    !ft_endpoint(out->family, &out->new_dst) ||
	    !out->new_sport || !out->new_dport)
		return false;
	if (nat & IPS_SRC_NAT) {
		if (!ft_nat_edit(&actions->entries[offset], out, forward))
			return false;
		offset += per_edit;
	}
	if (nat & IPS_DST_NAT) {
		if (!ft_nat_edit(&actions->entries[offset], out, !forward))
			return false;
		offset += per_edit;
	}
	if (out->family == AF_INET6)
		return true;
	csum = &actions->entries[offset];
	return csum->id == FLOW_ACTION_CSUM &&
		csum->csum_flags == (TCA_CSUM_UPDATE_FLAG_IPV4HDR | (out->proto == IPPROTO_TCP ?
			TCA_CSUM_UPDATE_FLAG_TCP : TCA_CSUM_UPDATE_FLAG_UDP));
}

/* The immediate lower device. vlan_dev_real_dev() is emphatically not it: it
 * descends through every stacked VLAN in one call and returns the bottom
 * device, which would collapse a QinQ pair into its inner tag alone. A VLAN
 * device has exactly one lower neighbour, and admission holds RTNL, which is
 * what walking that list requires.
 */
static struct net_device *ft_vlan_lower(struct net_device *dev)
{
	struct net_device *lower;
	struct list_head *iter;

	netdev_for_each_lower_dev(dev, lower, iter)
		return lower;
	return NULL;
}

/* A vlan-aware bridge transforms the tag stack itself, through its own VLAN
 * groups rather than through any netdev, so the devices above it do not
 * describe what the wire carries. Mirror the two functions that made that
 * decision -- br_vlan_fill_forward_path_pvid() and its _mode() companion --
 * through the same bridge state they read, so the devices and the bridge
 * configuration together remain the authority and the rule's POP/PUSH actions
 * are still checked against the result rather than read as truth.
 *
 * stack holds the tags found above the bridge, innermost first, and count is
 * updated in place: the bridge acts on the outermost tag, which is the last
 * element, exactly as br_fill_forward_path() acts on ctx->vlan[num_vlans - 1].
 * Returns the VID its FDB lookup was keyed on, or -EOPNOTSUPP.
 *
 * DEV_PATH_BR_VLAN_UNTAG_HW has no counterpart here and needs none: the
 * bridge chooses it only for a VLAN a switchdev driver accepted, and
 * cdx_ft_port_supported() admits no port belonging to a switch ASIC. It is
 * the one shape whose tag is on the wire while the rule describes neither a
 * selector nor a POP for it, so it must not be derivable as an ordinary
 * untagged port.
 */
static int ft_bridge_vlan(struct net_device *bridge, struct net_device *port,
			  struct cdx_ft_vlan *stack, unsigned int *count)
{
	struct bridge_vlan_info vinfo;
	bool push = false;
	u16 proto, vid;

	if (!br_vlan_enabled(bridge))
		return 0;
	/* Only 802.1Q, for the reason the VLAN-device arm gives: the kernel
	 * describes no selector for an 802.1ad tag and emits no push action for
	 * one, so it is a tag the hardware would be asked to reproduce blind. A
	 * bridge filtering in 802.1ad currently fails further down for want of
	 * those, which is the right answer arrived at by accident; say it here
	 * instead. */
	if (br_vlan_get_proto(bridge, &proto) || proto != ETH_P_8021Q)
		return -EOPNOTSUPP;
	if (*count && stack[*count - 1].proto == htons(proto)) {
		/* The frame already carries a tag in the bridge's protocol, so
		 * the bridge forwards within that VLAN and adds nothing. */
		vid = stack[*count - 1].id;
	} else {
		/* Otherwise it enters on the bridge's PVID, and leaves tagged
		 * with it unless the egress port is untagged for it. */
		if (*count == CDX_FT_VLAN_MAX || br_vlan_get_pvid(bridge, &vid))
			return -EOPNOTSUPP;
		push = true;
	}
	/* A port that is not a member of the resolved VLAN would have made the
	 * path walk fail outright, so Netfilter would never have described this
	 * flow; decline it for the same reason. */
	if (br_vlan_get_info(port, vid, &vinfo))
		return -EOPNOTSUPP;
	if (vinfo.flags & BRIDGE_VLAN_INFO_UNTAGGED) {
		/* push is false only where the frame already carried a tag in
		 * this bridge's protocol, so there is always one to remove. */
		if (push)
			push = false;
		else
			(*count)--;
	}
	if (push) {
		stack[*count].proto = htons(proto);
		stack[*count].id = vid;
		(*count)++;
	}
	return vid;
}

/* Derive the encapsulation Linux would add between a logical device and its
 * physical port, outermost first, and name the bridge and the PPPoE session
 * the path crosses, if any. Netfilter also describes this stack in its
 * POP/PUSH actions, but the devices are the authority and the actions are
 * checked against them, exactly as a NAT mangle is checked against its
 * conntrack. Stopping on anything that is neither an 802.1Q VLAN device, a
 * bridge master nor a ppp device is what declines a bond or a MACVLAN here,
 * rather than admitting a flow whose encapsulation the hardware would not
 * reproduce.
 *
 * The PPPoE hop is the one part not derived here, because it cannot be: a ppp
 * device registers no lower neighbour, so there is nothing to descend to, and
 * the session id and the concentrator's address live in a pppox socket this
 * module has no view of. session carries what the kernel's own forwarding-path
 * walk resolved, and that walk is the single authority for the hop -- a second
 * walk could disagree with the one the rule was built from and then describe
 * something Netfilter never did. Everything below the hop is walked here as
 * usual, so a session over a VLAN device or a bridge is still derived.
 * Returns the tag count, or -EOPNOTSUPP for a path this contract excludes.
 */
static int ft_path_stack(struct net_device *logical, struct net_device *physical,
			 const struct nf_flow_session *session,
			 struct cdx_ft_vlan *stack, struct net_device **bridge,
			 u16 *bridge_vid, struct cdx_ft_session *out_session)
{
	struct cdx_ft_vlan inner[CDX_FT_VLAN_MAX];
	unsigned int count = 0, i;
	int vid;

	*bridge = NULL;
	*bridge_vid = 0;
	memset(out_session, 0, sizeof(*out_session));
	if (!logical || !physical || !session)
		return -EOPNOTSUPP;
	/* The session hop is taken before the walk rather than inside it, which
	 * is what makes "at most one, and outermost" structural instead of
	 * guarded: the loop never comes back here, so a second ppp device, or
	 * one beneath a tag, is declined by the loop exactly as any other
	 * unsupported upper device is. That is also what the wire says, since a
	 * session sits inside every tag. */
	if (logical->type == ARPHRD_PPP) {
		struct net_device *lower;

		/* A session that has not completed discovery names no
		 * concentrator and no usable id; the hardware would insert a
		 * header nothing answers. Session id 0 is reserved for
		 * discovery itself. */
		if (!session->id || !is_valid_ether_addr(session->h_dest))
			return -EOPNOTSUPP;
		lower = __dev_get_by_index(&init_net, session->lower_ifindex);
		if (!lower)
			return -EOPNOTSUPP;
		/* The rule the VLAN increment imposes on a logical device,
		 * applied to the one device a session hides: the Ethernet
		 * source of a neighbour-output flow is the port's and the
		 * encoder caches one address per port, so a device below the
		 * session that overrides it would have software and hardware
		 * disagree. A ppp device carries no address of its own, so this
		 * is where that rule has to be stated. */
		if (!ether_addr_equal(lower->dev_addr, physical->dev_addr))
			return -EOPNOTSUPP;
		out_session->present = true;
		out_session->id = session->id;
		out_session->lower_ifindex = session->lower_ifindex;
		ether_addr_copy(out_session->mac, session->h_dest);
		logical = lower;
	}
	/* Each step strictly descends and the tag count is bounded, so a path
	 * that never reaches the port terminates at the bound. The bridge hop
	 * is terminal, which is what bounds it there. */
	while (logical != physical) {
		if (netif_is_bridge_master(logical)) {
			/* Which port a bridged flow leaves by was decided by
			 * the FDB, and Netfilter already resolved that into the
			 * redirect and the binding; a bridge has many lower
			 * devices and descending by adjacency would pick an
			 * arbitrary one. So require the port to be this
			 * bridge's own, and stop. A bridge port that is itself
			 * a stacked device hides a tag from this walk and is
			 * declined by the same requirement. */
			if (netdev_master_upper_dev_get(physical) != logical)
				return -EOPNOTSUPP;
			vid = ft_bridge_vlan(logical, physical, inner, &count);
			if (vid < 0)
				return vid;
			*bridge = logical;
			*bridge_vid = vid;
			break;
		}
		if (!is_vlan_dev(logical) || count == CDX_FT_VLAN_MAX ||
		    vlan_dev_vlan_proto(logical) != htons(ETH_P_8021Q))
			return -EOPNOTSUPP;
		inner[count].proto = vlan_dev_vlan_proto(logical);
		inner[count].id = vlan_dev_vlan_id(logical);
		count++;
		logical = ft_vlan_lower(logical);
		if (!logical)
			return -EOPNOTSUPP;
	}
	/* A session the kernel's walk crossed but this one did not reach is a
	 * path shape this contract does not describe, and the hardware would be
	 * asked to forward it with no session header at all. Refuse rather than
	 * silently drop the hop. */
	if (session->lower_ifindex && !out_session->present)
		return -EOPNOTSUPP;
	/* A session spends one of the encapsulation slots a direction has, so a
	 * session and a full tag stack together exceed what a tuple can
	 * describe. Netfilter refuses such a path first, leaving this
	 * unreachable through it; state the budget anyway rather than let the
	 * bound be an accident of somebody else's loop. */
	if (count + out_session->present > CDX_FT_VLAN_MAX)
		return -EOPNOTSUPP;
	for (i = 0; i < count; i++)
		stack[i] = inner[count - 1 - i];
	return count;
}

/* Netfilter records the ingress tags in the VLAN and CVLAN dissector values,
 * outermost first, without ever advertising either key in used_keys -- only
 * their offsets are registered. They are therefore readable but not
 * selectable, and only meaningful for as many tags as the device walk found,
 * which is what bounds this loop. Each must name the tag that walk derived,
 * under Netfilter's own exact masks, and must impose neither priority nor
 * DEI, which the hardware does not reproduce. */
static bool ft_vlan_match(struct flow_rule *rule, const struct cdx_ft_rule *out)
{
	struct flow_match_vlan vlan;
	unsigned int i;

	for (i = 0; i < out->in_vlans; i++) {
		if (i)
			flow_rule_match_cvlan(rule, &vlan);
		else
			flow_rule_match_vlan(rule, &vlan);
		if (vlan.mask->vlan_id != VLAN_VID_MASK ||
		    vlan.mask->vlan_tpid != htons(0xffff) ||
		    vlan.mask->vlan_priority || vlan.mask->vlan_dei ||
		    vlan.mask->vlan_eth_type ||
		    vlan.key->vlan_id != out->in_vlan[i].id ||
		    vlan.key->vlan_tpid != out->in_vlan[i].proto ||
		    vlan.key->vlan_priority || vlan.key->vlan_dei)
			return false;
	}
	return true;
}

/* The encapsulation block sits between the Ethernet rewrites and the
 * translation: one POP per ingress tag, then one PUSH per egress tag and one
 * more for an egress session, each outermost first. A POP carries no identity,
 * so the ingress stack is proven by the devices and the selectors above; a
 * PUSH carries its own and must agree with the stack. An action of any other
 * kind here is a capability this contract does not describe -- a tunnel -- and
 * is declined rather than dropped on the floor.
 *
 * An ingress session contributes nothing to this block, which is the one place
 * the two sides are not mirror images: nf_flow_rule_route_common() emits a POP
 * for an 802.1Q tag only, and Linux has no PPPoE pop action to emit. So an
 * ingress session is proven by the devices alone, and this arithmetic counts
 * the egress one only. The session push comes last because the session is the
 * innermost header and the pushes are emitted outermost first.
 */
static bool ft_vlan_actions(const struct flow_action *actions,
			    const struct cdx_ft_rule *out)
{
	unsigned int i, at = 4;

	for (i = 0; i < out->in_vlans; i++, at++)
		if (actions->entries[at].id != FLOW_ACTION_VLAN_POP)
			return false;
	for (i = 0; i < out->out_vlans; i++, at++) {
		const struct flow_action_entry *push = &actions->entries[at];

		if (push->id != FLOW_ACTION_VLAN_PUSH ||
		    push->vlan.vid != out->out_vlan[i].id ||
		    push->vlan.proto != out->out_vlan[i].proto ||
		    push->vlan.prio)
			return false;
	}
	if (out->out_session.present) {
		const struct flow_action_entry *push = &actions->entries[at];

		/* The one thing about the hop the rule does describe, so it is
		 * the one thing that can be cross-checked against the walk the
		 * session came from. */
		if (push->id != FLOW_ACTION_PPPOE_PUSH ||
		    push->pppoe.sid != out->out_session.id)
			return false;
	}
	return true;
}

/* Exact masks preserve every selector. Native flowtables supply routing
 * semantics (including TTL decrement), four Ethernet mangle words, an
 * encapsulation block, optional translation/checksum actions and a final
 * redirect. */
static int ft_parse(struct cdx_ft_binding *binding,
		    const struct flow_cls_offload *cls, struct cdx_ft_rule *out,
		    union nf_inet_addr *next_hop)
{
	const unsigned long long common = BIT_ULL(FLOW_DISSECTOR_KEY_META) |
		BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
		BIT_ULL(FLOW_DISSECTOR_KEY_PORTS);
	const unsigned long long keys4 = common | BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS);
	const unsigned long long keys6 = common | BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS);
	unsigned long long used, keys;
	struct flow_rule *rule = cls->rule;
	struct flow_match_meta meta;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ipv4_addrs ipv4;
	struct flow_match_ipv6_addrs ipv6;
	struct flow_match_ports ports;
	struct flow_match_tcp tcp;
	const struct flow_action_entry *action;
	u32 mark;
	static const u32 offsets[4] = { 4, 8, 0, 4 };
	static const u32 masks[4] = { 0x0000ffff, 0, 0, 0xffff0000 };
	u8 ethernet[12] = {};
	u8 family;
	u32 word;
	int i, vlans;

	if (!rule)
		return -EOPNOTSUPP;
	used = rule->match.dissector->used_keys;
	/* An ingress tag adds no selector here. nf_flow_rule_match() registers
	 * the VLAN and CVLAN dissector offsets and fills their values, but
	 * never advertises either key, so the described set is the same with a
	 * tag as without one and this comparison stays exact. The tags are
	 * still read back through those offsets, and cross-checked against the
	 * devices, in ft_vlan_match(). */
	if (used == keys4 || used == (keys4 | BIT_ULL(FLOW_DISSECTOR_KEY_TCP)))
		family = AF_INET;
	else if (used == keys6 || used == (keys6 | BIT_ULL(FLOW_DISSECTOR_KEY_TCP)))
		family = AF_INET6;
	else
		return -EOPNOTSUPP;
	keys = family == AF_INET6 ? keys6 : keys4;
	if (!cls->nf_ct)
		return -EOPNOTSUPP;
	/* Sampled once: the admission test below and the class derived further
	 * down have to describe the same mark, or a concurrent change could
	 * install a class taken from a value that would not have been admitted. */
	mark = READ_ONCE(cls->nf_ct->mark);
	if (!cls->nf_mtu || cls->nf_counter ||
	    !nf_flow_offload_handle_valid(cls->nf_handle) ||
	    !net_eq(nf_ct_net(cls->nf_ct), &init_net) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_ORIGINAL) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_REPLY) ||
	    /* Outside the classification mask the mark still means something
	     * this adapter cannot honour, so it still refuses. With no mask
	     * configured that is every mark, exactly as before. */
	    (mark & ~ft_qos_mark_mask) ||
	    cls->common.chain_index || cls->common.protocol != ETH_P_ALL)
		return -EOPNOTSUPP;
	flow_rule_match_meta(rule, &meta);
	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	flow_rule_match_ports(rule, &ports);
	if (meta.mask->ingress_ifindex != -1 || meta.mask->ingress_iftype ||
	    meta.mask->l2_miss || meta.key->ingress_ifindex != binding->dev->ifindex ||
	    control.mask->addr_type != 0xffff || control.mask->flags ||
	    control.mask->thoff ||
	    control.key->addr_type != (family == AF_INET6 ? FLOW_DISSECTOR_KEY_IPV6_ADDRS :
						           FLOW_DISSECTOR_KEY_IPV4_ADDRS) ||
	    basic.mask->n_proto != htons(0xffff) || basic.mask->ip_proto != 0xff ||
	    basic.key->n_proto != htons(family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP) ||
	    basic.key->ip_proto != nf_ct_protonum(cls->nf_ct) ||
	    nf_ct_l3num(cls->nf_ct) != family ||
	    ports.mask->src != htons(0xffff) || ports.mask->dst != htons(0xffff) ||
	    !ports.key->src || !ports.key->dst)
		return -EOPNOTSUPP;
	memset(out, 0, sizeof(*out));
	out->family = family;
	if (family == AF_INET6) {
		flow_rule_match_ipv6_addrs(rule, &ipv6);
		if (!ft_exact6(&ipv6.mask->src) || !ft_exact6(&ipv6.mask->dst))
			return -EOPNOTSUPP;
		out->src.in6 = ipv6.key->src;
		out->dst.in6 = ipv6.key->dst;
	} else {
		flow_rule_match_ipv4_addrs(rule, &ipv4);
		if (ipv4.mask->src != htonl(0xffffffff) || ipv4.mask->dst != htonl(0xffffffff))
			return -EOPNOTSUPP;
		out->src.ip = ipv4.key->src;
		out->dst.ip = ipv4.key->dst;
	}
	if (!ft_endpoint(family, &out->src) || !ft_endpoint(family, &out->dst))
		return -EOPNOTSUPP;
	out->sport = ports.key->src;
	out->dport = ports.key->dst;
	out->proto = basic.key->ip_proto;
	/* Four Ethernet mangles and a redirect are the shortest admissible
	 * action list. Resolve the devices before the translation, because the
	 * encapsulation they imply decides where every later action sits; from
	 * there the exact count ft_translation requires bounds each index. */
	if (rule->action.num_entries < 5)
		return -EOPNOTSUPP;
	action = &rule->action.entries[rule->action.num_entries - 1];
	if (action->id != FLOW_ACTION_REDIRECT || !cdx_ft_port_supported(action->dev) ||
	    !cdx_ft_port_supported(binding->dev) || !cls->nf_dst || !cls->nf_dst_reverse)
		return -EOPNOTSUPP;
	out->in = binding->dev;
	out->out = action->dev;
	/* This direction's destination names the device it leaves by; the
	 * reverse direction's names the device it arrives on. Requiring each
	 * to reach its physical port through VLAN devices alone is what ties
	 * the borrowed destinations to the redirect and the binding. Both are
	 * now required, where only the egress one used to be: patch 140
	 * supplies a destination only for a neighbour-output direction, so a
	 * missing reverse one means that direction is transformed or direct,
	 * neither of which this contract describes. */
	out->out_logical = cls->nf_dst->dev;
	out->in_logical = cls->nf_dst_reverse->dev;
	/* The two sessions are named the way the two destinations are: the one
	 * paired with this direction's destination is what it inserts, and the
	 * one paired with the reverse destination is what it strips. */
	vlans = ft_path_stack(out->out_logical, out->out, cls->nf_session,
			      out->out_vlan, &out->out_bridge,
			      &out->out_bridge_vid, &out->out_session);
	if (vlans < 0)
		return vlans;
	out->out_vlans = vlans;
	vlans = ft_path_stack(out->in_logical, out->in, cls->nf_session_reverse,
			      out->in_vlan, &out->in_bridge,
			      &out->in_bridge_vid, &out->in_session);
	if (vlans < 0)
		return vlans;
	out->in_vlans = vlans;
	/* The Ethernet source a neighbour-output flow carries is the physical
	 * port's, and the encoder caches exactly one address per port. A logical
	 * device that does not share that address would have software emit one
	 * source MAC and hardware another for the same flow, so it is declined
	 * rather than left silently divergent. A VLAN device normally inherits
	 * its parent's address; a bridge normally takes its lowest port's, so
	 * this also decides which ports of a multi-port bridge are eligible.
	 * A ppp device has no address at all -- addr_len is zero -- so where a
	 * session is present the same rule is imposed by the walk, on the
	 * device below it, which is the one that does have one. */
	if (!out->out_session.present &&
	    !ether_addr_equal(out->out_logical->dev_addr, out->out->dev_addr))
		return -EOPNOTSUPP;
	/* Re-entering the port a frame arrived on is a hairpin, and needs full
	 * NAT to be a distinct path -- unless the two stacks differ, which is
	 * ordinary routing between VLANs carried on one trunk, or the two
	 * sessions do, which is the same thing one layer down. */
	if (out->out == out->in && out->out_vlans == out->in_vlans &&
	    !memcmp(out->out_vlan, out->in_vlan, sizeof(out->out_vlan)) &&
	    out->out_session.present == out->in_session.present &&
	    (READ_ONCE(cls->nf_ct->status) & IPS_NAT_MASK) != IPS_NAT_MASK)
		return -EOPNOTSUPP;
	if (!ft_translation(cls, out))
		return -EOPNOTSUPP;
	/* Each direction is admitted as its own rule, so this is already a
	 * per-direction class even though both directions read one mark. The
	 * channel nibble is normally zero, which resolves to whichever channel
	 * the egress port owns, so one class index means "this priority, on
	 * whatever port this direction leaves by". A class the hardware cannot
	 * express declines the flow to software rather than guessing a queue. */
	out->qos = ft_qos_class(mark);
	if (!ft_qos_class_valid(out->qos))
		return -EOPNOTSUPP;
	switch (basic.key->ip_proto) {
	case IPPROTO_TCP:
		if (used != (keys | BIT_ULL(FLOW_DISSECTOR_KEY_TCP)) ||
		    !nf_conntrack_tcp_established(cls->nf_ct))
			return -EOPNOTSUPP;
		flow_rule_match_tcp(rule, &tcp);
		/* cdx_sp.xml punts SYN/FIN/RST before TCP hash lookup. Accept
		 * precisely Netfilter's FIN/RST exclusion; never discard an
		 * additional selector which that parser cannot enforce. */
		if (tcp.key->flags || tcp.mask->flags != htons(TCPHDR_FIN | TCPHDR_RST))
			return -EOPNOTSUPP;
		break;
	case IPPROTO_UDP:
		if (used != keys)
			return -EOPNOTSUPP;
		break;
	default:
		return -EOPNOTSUPP;
	}
	/* Bounded by the tag count the devices produced, which is the only
	 * thing that makes these reads meaningful: the keys are never in
	 * used_keys, so nothing about them can be established from the set
	 * compared above. A tag the devices found but Netfilter did not
	 * describe leaves the dissector offset at zero, and the meta key
	 * living there carries an all-ones ingress mask, which fails the
	 * priority and DEI test below rather than being read as a tag. */
	if (!ft_vlan_match(rule, out))
		return -EOPNOTSUPP;
	for (i = 0; i < 4; i++) {
		action = &rule->action.entries[i];
		if (action->id != FLOW_ACTION_MANGLE ||
		    action->mangle.htype != FLOW_ACT_MANGLE_HDR_TYPE_ETH ||
		    action->mangle.offset != offsets[i] || action->mangle.mask != masks[i] ||
		    (action->mangle.val & masks[i]))
			return -EOPNOTSUPP;
		memcpy(&word, ethernet + offsets[i], sizeof(word));
		word = (word & masks[i]) | action->mangle.val;
		memcpy(ethernet + offsets[i], &word, sizeof(word));
	}
	/* Neighbours, the borrowed destination and the payload bound all belong
	 * to the logical egress device. The Ethernet source is the physical
	 * port's, because that is the address Netfilter writes for a
	 * neighbour-output flow and the only one the encoder can cache. */
	if (!ft_vlan_actions(&rule->action, out) ||
	    !ft_next_hop(cls, out->out_logical, family, &out->new_dst, next_hop) ||
	    cls->nf_mtu > out->out_logical->mtu ||
	    cls->nf_mtu < (family == AF_INET6 ? IPV6_MIN_MTU : 68))
		return -EOPNOTSUPP;
	if (out->out_session.present) {
		/* A ppp device resolves no Ethernet destination and Netfilter
		 * writes none: flow_offload_eth_dst() reads the NOARP neighbour
		 * arp_constructor() built on it, whose hardware address is the
		 * zero one a device with no address length leaves behind. So
		 * the four mangle words must be exactly that, and the real
		 * destination is the concentrator the session names. Requiring
		 * the zero rather than ignoring the words is what keeps a
		 * future kernel that starts writing something here from being
		 * silently overridden. */
		if (!is_zero_ether_addr(ethernet))
			return -EOPNOTSUPP;
		ether_addr_copy(out->dst_mac, out->out_session.mac);
	} else {
		if (!is_valid_ether_addr(ethernet) ||
		    !ft_neigh_check(family, out->out_logical, next_hop, ethernet))
			return -EOPNOTSUPP;
		ether_addr_copy(out->dst_mac, ethernet);
	}
	if (!ether_addr_equal(ethernet + ETH_ALEN, out->out->dev_addr))
		return -ESTALE;
	out->mtu = cls->nf_mtu;
	ether_addr_copy(out->src_mac, ethernet + ETH_ALEN);
	return 0;
}

static bool ft_same_key(const struct cdx_ft_rule *a, const struct cdx_ft_rule *b)
{
	return a->in == b->in && a->family == b->family &&
		nf_inet_addr_cmp(&a->src, &b->src) && nf_inet_addr_cmp(&a->dst, &b->dst) &&
		a->sport == b->sport && a->dport == b->dport && a->proto == b->proto;
}

/* The unused arm of each address is zero, so hashing all four words keeps one
 * expression for both families without collapsing distinct IPv6 keys. */
static u32 ft_key_hash(const struct cdx_ft_rule *rule)
{
	u32 addresses = jhash2(rule->src.all, ARRAY_SIZE(rule->src.all),
			       jhash2(rule->dst.all, ARRAY_SIZE(rule->dst.all),
				      ft_hash_seed));

	return jhash_3words(addresses,
			   (u32)(__force u16)rule->sport << 16 |
			   (__force u16)rule->dport, rule->family,
			   ft_hash_seed ^ hash_ptr(rule->in, 32) ^ rule->proto);
}

static int ft_replace(struct cdx_ft_binding *binding, struct flow_cls_offload *cls)
{
	struct cdx_ft_entry *entry = ft_find(binding, cls->cookie), *other;
	struct cdx_ft_rule rule;
	union nf_inet_addr next_hop;
	int rc;

	/* A delayed request must never replace a different flow generation
	 * merely because its opaque directional cookie has the same value. */
	if (entry && entry->handle != cls->nf_handle)
		return -ESTALE;
	if (nf_flow_offload_handle_valid(cls->nf_handle) && !ft_routes_valid(cls))
		ft_handle_invalidate(cls->nf_handle, &ft_route_invalidations);
	rc = ft_parse(binding, cls, &rule, &next_hop);
	if (rc == -ESTALE)
		ft_handle_invalidate(cls->nf_handle, &ft_mac_invalidations);
	if (!rc)
		ft_validated++;
	if (rc || cdx_ft_observing() || atomic_read(&ft_invalid) || ft_stopping || cdx_ft_failed()) {
		if (entry)
			ft_remove(entry);
		return rc ? rc : -EOPNOTSUPP;
	}
	if (entry) {
		if (nf_inet_addr_cmp(&entry->next_hop, &next_hop) &&
		    !memcmp(&entry->rule, &rule, sizeof(rule)))
			return 0;
		rc = ft_remove(entry);
		if (rc)
			return rc;
	}
	hash_for_each_possible(ft_keys, other, key_node, ft_key_hash(&rule))
		if (ft_same_key(&other->rule, &rule))
			return -EEXIST;
	if (ft_count >= CDX_FT_MAX_ENTRIES)
		return -ENOSPC;
	if (ft_fault(1))
		return -ENOMEM;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	/* ft_neigh_detach() unlinks by emptiness, because an entry can reach
	 * the watch list holding no neighbour, and a kzalloc'd list head is
	 * not an empty one. */
	INIT_LIST_HEAD(&entry->neigh_list);
	entry->rule = rule;
	entry->next_hop = next_hop;
	entry->binding = binding;
	entry->cookie = cls->cookie;
	entry->handle = cls->nf_handle;
	nf_flow_offload_handle_get(entry->handle);
	ft_handle_refs++;
	ft_devices_hold(&rule);
	rc = ft_neigh_attach(entry);
	if (!rc) {
		struct cdx_ft_stats_binding binding;

		/* Claimed before the hardware entry exists, so the indices the
		 * encoder writes name a record this entry already holds a
		 * reference to; a record acquired afterwards could be the one
		 * a concurrent retirement had just returned. */
		ft_stats_attach(entry);
		ft_stats_binding(entry, &binding);
		rc = ft_fault(2) ? -EIO : cdx_ft_add(&rule, &binding, &entry->hw);
	}
	if (rc) {
		ft_stats_detach(entry);
		ft_neigh_detach(entry);
		nf_flow_offload_handle_put(entry->handle);
		ft_handle_refs--;
		ft_devices_put(&rule);
		kfree(entry);
		return rc;
	}
	list_add_tail(&entry->list, &ft_entries);
	hash_add(ft_cookies, &entry->cookie_node,
		 entry->cookie ^ (unsigned long)entry->binding);
	hash_add(ft_keys, &entry->key_node, ft_key_hash(&entry->rule));
	ft_count++;
	ft_installs++;
	/* IPv6 commits routes from softirq without RTNL, so a change between
	 * the validation above and publication here reaches neither: the entry
	 * was not yet watched, and RTNL did not exclude it. Recheck once the
	 * notifier can see this entry; an invalid handle then retires it below
	 * through the same path as a change observed during insertion. */
	if (!ft_routes_valid(cls))
		ft_handle_invalidate(cls->nf_handle, &ft_route_invalidations);
	if (ft_fault(3) || atomic_read(&ft_invalid) ||
	    !nf_flow_offload_handle_valid(entry->handle)) {
		ft_remove(entry);
		return -EIO;
	}
	return 0;
}

static int ft_stats(struct cdx_ft_entry *entry, struct flow_cls_offload *cls)
{
	struct cdx_ft_counters now;
	u64 packets, bytes;
	unsigned long lastused;

	if (!nf_flow_offload_handle_valid(entry->handle)) {
		ft_neigh_invalidate(entry);
		return -EOPNOTSUPP;
	}
	/* A table can enable counters after installation. Its matching frames
	 * may already have been counted again on a punt to Linux. Retire all
	 * directions and leave accounting to software; never publish hit counts
	 * as independently forwarded packets. */
	if (cls->nf_counter) {
		ft_invalidate();
		return -EOPNOTSUPP;
	}
	cdx_ft_stats(entry->hw, &now);
	/* 64-bit counters cannot wrap during this PoC's lifetime. A backwards
	 * sample means hardware state was reset or could not be read reliably;
	 * never turn it into an enormous unsigned delta or activity refresh. */
	if (now.packets < entry->reported.packets || now.bytes < entry->reported.bytes) {
		ft_errors++;
		ft_invalidate();
		return -EIO;
	}
	packets = now.packets - entry->reported.packets;
	bytes = now.bytes - entry->reported.bytes;
	if (!ft_neigh_used(entry, packets != 0))
		return -EOPNOTSUPP;
	/* These are classifier hits, including some later punts, and Ethernet
	 * bytes including padding but excluding FCS. Only tables without native
	 * counter accounting are admitted. Linux uses lastused for ageing; proc
	 * exposes the raw counters for diagnostics, not delivery accounting. */
	/* Firmware uses the same 32-bit jiffies counter as CDX. Expand relative
	 * to the current kernel clock; admitted idle durations are below 2^31. */
	lastused = jiffies - (u32)((u32)jiffies - now.lastused);
	flow_stats_update(&cls->stats, bytes, packets, 0, lastused,
			  FLOW_ACTION_HW_STATS_DELAYED);
	entry->reported = now;
	return 0;
}

/* Native flowtable work visits all bound devices for each direction. Decline
 * the other ingress before taking RTNL or attributing a transient failure to
 * its shared generation. These immutable match fields need no RTNL. */
static bool ft_request_targets(const struct cdx_ft_binding *binding,
			       const struct flow_cls_offload *cls)
{
	struct flow_match_meta meta;

	if (!cls->rule ||
	    !(cls->rule->match.dissector->used_keys & BIT(FLOW_DISSECTOR_KEY_META)))
		return false;
	flow_rule_match_meta(cls->rule, &meta);
	return meta.mask->ingress_ifindex == -1 &&
	       meta.key->ingress_ifindex == binding->dev->ifindex;
}

static bool ft_admission_fault(const struct flow_cls_offload *cls)
{
#ifdef CDX_DEBUG_FLOWTABLE
	struct cdx_ft_entry *entry;

	if (READ_ONCE(ft_fail_stage) != 4)
		return false;
	list_for_each_entry(entry, &ft_entries, list)
		if (entry->handle == cls->nf_handle && entry->cookie != cls->cookie)
			return ft_fault(4);
#endif
	return false;
}

static int ft_rule_callback(enum tc_setup_type type, void *data, void *priv)
{
	struct cdx_ft_binding *binding = priv;
	struct flow_cls_offload *cls = data;
	struct cdx_ft_entry *entry;
	int rc;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;
	cdx_ft_begin();
	entry = ft_find(binding, cls->cookie);
	if (entry && entry->handle != cls->nf_handle)
		entry = NULL;
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		/* Never wait for RTNL here: device teardown under RTNL may be
		 * flushing this workqueue. Retire a busy generation so fresh
		 * traffic retries after native GC, rather than retaining one
		 * accelerated direction indefinitely. */
		if (!ft_request_targets(binding, cls)) {
			rc = -EOPNOTSUPP;
		} else if (ft_admission_fault(cls) || cdx_ft_admission_begin()) {
			ft_busy++;
			if (!cdx_ft_observing() && !ft_stopping &&
			    !atomic_read(&ft_invalid) && !cdx_ft_failed())
				ft_handle_invalidate(cls->nf_handle, &ft_admission_invalidations);
			rc = -EAGAIN;
		} else {
			rc = ft_replace(binding, cls);
			cdx_ft_admission_end();
		}
		if (rc)
			ft_rejects++;
		break;
	case FLOW_CLS_DESTROY:
		rc = entry ? ft_remove(entry) : 0;
		break;
	case FLOW_CLS_STATS:
		rc = entry ? ft_stats(entry, cls) : -ENOENT;
		break;
	default:
		rc = -EOPNOTSUPP;
	}
	cdx_ft_end();
	return rc;
}

static void ft_release(void *priv)
{
	struct cdx_ft_binding *binding = priv;
	struct cdx_ft_entry *entry, *next;

	cdx_ft_begin();
	list_for_each_entry_safe(entry, next, &ft_entries, list)
		if (entry->binding == binding)
			ft_remove(entry);
	spin_lock_bh(&ft_watch_lock);
	list_del(&binding->list);
	ft_bound--;
	spin_unlock_bh(&ft_watch_lock);
	cdx_ft_end();
	dev_put(binding->dev);
	kfree(binding);
}

/* All previous callbacks must have lost their bindings, and the worker must
 * have finished both hardware retirement and Linux flow cleanup. Completion
 * is published as its last action under the backend transaction, so an old worker cannot
 * change a newly admitted table. Never reset the fatal latch or error history.
 */
static bool ft_can_rearm(void)
{
	cdx_ft_assert_held();
	return ft_ready && !ft_stopping && !cdx_ft_failed() &&
		atomic_read(&ft_invalid) && ft_invalid_done &&
		!ft_bound && !ft_count && !ft_neighbour_refs && !ft_handle_refs && !cdx_ft_pending();
}

/* Netfilter reaches a driver by one of two routes, and they disagree about two
 * things that no build can check.
 *
 * nf_flow_table_offload_setup() picks between them purely on whether the netdev
 * has an ndo_setup_tc, so which route runs is a property of the driver rather
 * than of this adapter, and it can change underneath it.
 *
 * The indirect route calls us before block_setup takes flow_block_lock, so
 * UNBIND has to take it here. The direct route already holds it across
 * ndo_setup_tc, for both commands, so taking it there would deadlock on a
 * non-recursive rwsem at the first unbind. The callback also has to be
 * allocated and removed with the matching pair of helpers.
 *
 * Everything else is identical, so both routes share this body and differ only
 * in the two places named above.
 */
static int ft_block_setup(struct net_device *dev, struct flow_block_offload *bo,
			  struct nf_flowtable *flowtable, bool indirect,
			  struct Qdisc *sch, void (*cleanup)(struct flow_block_cb *))
{
	struct cdx_ft_binding *binding, *other;
	struct flow_block_cb *cb;
	bool rearm;
	int rc = 0;

	if (!bo || !bo->block || !bo->net || !dev || !flowtable ||
	    !net_eq(bo->net, &init_net) ||
	    bo->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;
	bo->driver_block_list = &ft_block_list;
	/* UNBIND moves a live callback onto bo's temporary list: exclude
	 * statistics/replace/delete walkers for that move as well as for the
	 * later free. Otherwise a walker can follow the temporary list head as
	 * if it were a callback. Take this before the CDX transaction, matching
	 * the order used by rule callbacks under the read lock. On the direct
	 * route the caller has already taken it. */
	if (indirect && bo->command == FLOW_BLOCK_UNBIND)
		down_write(&flowtable->flow_block_lock);
	cdx_ft_begin();
	if (bo->command == FLOW_BLOCK_BIND) {
		rearm = atomic_read(&ft_invalid);
		if (!ft_ready || ft_stopping || cdx_ft_failed() || !cdx_ft_port_supported(dev) ||
		    ft_bound >= 2 || (rearm && !ft_can_rearm())) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		/* TC_SETUP_FT borrows this live table from Netfilter. A table
		 * whose hooks were detached can still contain cached flows and
		 * queued callbacks. Only an empty table may start recovery; its
		 * pointer value alone cannot distinguish reuse from recreation. */
		if (!ft_bound && atomic_read(&flowtable->rhashtable.nelems)) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		list_for_each_entry(other, &ft_bindings, list)
			if (other->table != flowtable || other->dev == dev) {
				rc = -EBUSY;
				goto out;
			}
		binding = kzalloc(sizeof(*binding), GFP_KERNEL);
		if (!binding) {
			rc = -ENOMEM;
			goto out;
		}
		binding->dev = dev;
		binding->table = flowtable;
		cb = indirect ?
			flow_indr_block_cb_alloc(ft_rule_callback, dev, binding,
				ft_release, bo, dev, sch, flowtable, NULL, cleanup) :
			flow_block_cb_alloc(ft_rule_callback, dev, binding, ft_release);
		if (IS_ERR(cb)) {
			kfree(binding);
			rc = PTR_ERR(cb);
			goto out;
		}
		/* Hardware rejection must leave neighbour-aware software routing,
		 * not a DIRECT tuple with a stale Ethernet rewrite. This request
		 * is monotonic for the table, including after unbind. Patch 140
		 * also retires DIRECT flows constructed concurrently with bind. */
		WRITE_ONCE(flowtable->use_neigh, true);
		WRITE_ONCE(flowtable->use_hw_handles, true);
		/* Commit recovery only after allocating a binding successfully.
		 * While ft_bound is zero, a notifier cannot invalidate new entries:
		 * none exist yet. A normal bind must not clear an invalidation
		 * raised during allocation. Rules validate fresh Linux context. */
		if (rearm) {
			ft_invalid_done = false;
			atomic_set(&ft_invalid, 0);
			ft_rearms++;
			pr_info("cdx flowtable: admission rearmed for a new binding\n");
		}
		dev_hold(dev);
		spin_lock_bh(&ft_watch_lock);
		list_add_tail(&binding->list, &ft_bindings);
		ft_bound++;
		spin_unlock_bh(&ft_watch_lock);
		flow_block_cb_add(cb, bo);
		list_add_tail(&cb->driver_list, &ft_block_list);
	} else if (bo->command == FLOW_BLOCK_UNBIND) {
		cb = flow_block_cb_lookup(bo->block, ft_rule_callback, dev);
		if (!cb) {
			rc = -ENOENT;
			goto out;
		}
		if (indirect)
			flow_indr_block_cb_remove(cb, bo);
		else
			flow_block_cb_remove(cb, bo);
		list_del(&cb->driver_list);
	} else {
		rc = -EOPNOTSUPP;
	}
out:
	cdx_ft_end();
	if (indirect && bo->command == FLOW_BLOCK_UNBIND)
		up_write(&flowtable->flow_block_lock);
	return rc;
}

/* The indirect route. Netfilter hands the flowtable across as its own argument
 * here, and a Qdisc is never expected on a TC_SETUP_FT bind. */
static int ft_bind(struct net_device *dev, struct Qdisc *sch, void *priv,
		   enum tc_setup_type type, void *data, void *table,
		   void (*cleanup)(struct flow_block_cb *))
{
	if (type != TC_SETUP_FT || sch)
		return -EOPNOTSUPP;
	return ft_block_setup(dev, data, table, true, sch, cleanup);
}

/* The direct route, for a netdev that has grown an ndo_setup_tc. Netfilter
 * passes no flowtable here, but it set bo->block to that flowtable's own
 * embedded block, so the owner is recoverable rather than absent. Nothing
 * calls this until a driver registers it, and that registration is what moves
 * every bind on the device from the indirect route to this one. */
int cdx_ft_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data)
{
	struct flow_block_offload *bo = type_data;

	if (type != TC_SETUP_FT || !bo || !bo->block)
		return -EOPNOTSUPP;
	return ft_block_setup(dev, bo,
			      container_of(bo->block, struct nf_flowtable, flow_block),
			      false, NULL, NULL);
}
EXPORT_SYMBOL(cdx_ft_setup_tc);

static void ft_invalidate_work(struct work_struct *work)
{
	struct net_device *devices[2];
	struct cdx_ft_binding *binding;
	struct cdx_ft_entry *entry, *next;
	unsigned int n = 0, i;

	cdx_ft_begin();
	list_for_each_entry_safe(entry, next, &ft_entries, list)
		ft_remove(entry);
	/* CDX retains failed deletions and owns the terminal hardware latch.
	 * Retry until a barrier or datapath quiescence makes retirement safe. */
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
	pr_info("cdx flowtable: invalidated; hardware admission disabled\n");
	/* No state changes or deferred work after publishing completion. A
	 * later first bind may now recover if every old binding has gone. */
	ft_invalid_done = true;
	cdx_ft_end();
}

/* Every device a flow's forwarding depends on: both physical ports, both
 * logical devices, and any bridge between them. A VLAN device carries its own
 * MTU and administrative state, and a bridge carries both plus the FDB that
 * chose the egress port, so a flow depends on each exactly as it depends on
 * the physical port underneath. */
static bool ft_entry_uses(const struct cdx_ft_entry *entry, const struct net_device *dev)
{
	return entry->rule.in == dev || entry->rule.out == dev ||
		entry->rule.in_logical == dev || entry->rule.out_logical == dev ||
		entry->rule.in_bridge == dev || entry->rule.out_bridge == dev;
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

static void ft_device_retire(const struct net_device *dev, atomic64_t *counter)
{
	struct cdx_ft_entry *entry;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
		if (ft_entry_uses(entry, dev))
			ft_handle_invalidate(entry->handle, counter);
	spin_unlock_bh(&ft_watch_lock);
}

static int ft_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;
	switch (event) {
	case NETDEV_CHANGE:
		if (netif_running(dev) && netif_carrier_ok(dev))
			break;
		fallthrough;
	case NETDEV_GOING_DOWN:
		/* Native DOWN also flushes flowtable work. Admission rechecks
		 * both ports under RTNL; UP never clears failure state. */
		ft_device_retire(dev, &ft_link_invalidations);
		break;
	case NETDEV_CHANGEMTU:
		/* IPv4 flushes route caches under this event's RTNL. Admission
		 * rechecks both destinations before publishing queued context. */
		ft_device_retire(dev, &ft_mtu_invalidations);
		break;
	case NETDEV_CHANGEADDR:
		/* NEIGH software output uses the current MAC. Reject a queued
		 * stale hardware source too, invalidating its entire generation. */
		ft_device_retire(dev, &ft_mac_invalidations);
		break;
	case NETDEV_CHANGENAME:
		/* Names carry no forwarding semantics; backend lookup uses the
		 * pinned physical device, including after table recreation. */
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGEUPPER:
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
		return NOTIFY_DONE;
	}
	mask = inet_make_mask(event->prefixlen);
	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
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
		return NOTIFY_DONE;
	}
	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
		if (entry->rule.family != AF_INET6)
			continue;
		if (ipv6_prefix_equal(&entry->rule.new_dst.in6, &event->dst, event->prefixlen) ||
		    ipv6_prefix_equal(&entry->rule.src.in6, &event->dst, event->prefixlen))
			ft_handle_invalidate(entry->handle, &ft_route_invalidations);
	}
	spin_unlock_bh(&ft_watch_lock);
	return NOTIFY_DONE;
}

static int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct neighbour *neigh = ptr;
	struct cdx_ft_entry *entry;

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
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
		if (entry->neigh == neigh &&
		    !ft_neigh_matches(neigh, entry->rule.dst_mac)) {
			/* Ordinary NUD ageing with a usable MAC needs no retirement.
			 * Every connection sharing the bad neighbour is marked, and
			 * its other direction observes the same handle invalidation. */
			ft_neigh_invalidate(entry);
		}
	}
	spin_unlock(&ft_watch_lock);
	read_unlock_bh(&neigh->lock);
	return NOTIFY_DONE;
}

static int ft_fib_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct fib_notifier_info *info = ptr;
	struct cdx_ft_entry *entry;

	if (info->family != AF_INET && info->family != AF_INET6)
		return NOTIFY_DONE;
	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_APPEND:
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_DEL:
		/* These selected-alias notifications can precede commit and omit
		 * other aliases. Patch 140 reports every committed prefix in both
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

static int ft_nexthop_event(struct notifier_block *nb, unsigned long event, void *ptr)
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
static int ft_fdb_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	const struct switchdev_notifier_fdb_info *info = ptr;
	struct net_device *port = switchdev_notifier_info_to_dev(ptr);
	struct cdx_ft_entry *entry;

	if ((event != SWITCHDEV_FDB_ADD_TO_DEVICE &&
	     event != SWITCHDEV_FDB_DEL_TO_DEVICE) ||
	    !port || !net_eq(dev_net(port), &init_net))
		return NOTIFY_DONE;
	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
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
static int ft_swdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	const struct switchdev_notifier_port_attr_info *attr;
	const struct switchdev_notifier_port_obj_info *obj;
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);

	switch (event) {
	case SWITCHDEV_PORT_OBJ_ADD:
	case SWITCHDEV_PORT_OBJ_DEL:
		obj = ptr;
		if (!obj->obj || obj->obj->id != SWITCHDEV_OBJ_ID_PORT_VLAN)
			return NOTIFY_DONE;
		break;
	case SWITCHDEV_PORT_ATTR_SET:
		attr = ptr;
		if (!attr->attr ||
		    (attr->attr->id != SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING &&
		     attr->attr->id != SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL))
			return NOTIFY_DONE;
		break;
	default:
		return NOTIFY_DONE;
	}
	if (!dev)
		return NOTIFY_DONE;
	spin_lock_bh(&ft_watch_lock);
	/* Latch before releasing the watch lock, exactly as the netdev
	 * upper-device event does: a concurrent last unbind and fresh bind must
	 * not redirect this event to a new table. */
	if (ft_device_used(dev))
		ft_invalidate();
	spin_unlock_bh(&ft_watch_lock);
	return NOTIFY_DONE;
}

static struct notifier_block ft_netdev_nb = { .notifier_call = ft_netdev_event };
static struct notifier_block ft_fdb_nb = { .notifier_call = ft_fdb_event };
static struct notifier_block ft_swdev_nb = { .notifier_call = ft_swdev_event };
static struct notifier_block ft_neigh_nb = { .notifier_call = ft_neigh_event };
static struct notifier_block ft_fib_nb = { .notifier_call = ft_fib_event };
static struct notifier_block ft_nexthop_nb = { .notifier_call = ft_nexthop_event };

/* seq_file retains the transaction throughout each read iteration, including
 * the header and its rows. It resumes by position after releasing the lock;
 * userspace doing multiple reads must tolerate intervening flow changes. */
/* Position zero is the header. Other positions encode bucket+1 in the upper
 * word and the entry offset within that bucket in the lower word. Resuming a
 * paged read therefore walks only its bucket, not all preceding flow entries.
 * No entry pointer survives release of the transaction between reads. */
static void *ft_position(loff_t *pos)
{
	unsigned int bucket = (*pos >> 32) - 1, skip = (u32)*pos;
	struct cdx_ft_entry *entry;

	for (; bucket < HASH_SIZE(ft_cookies); bucket++) {
		hlist_for_each_entry(entry, &ft_cookies[bucket], cookie_node) {
			if (skip) {
				skip--;
				continue;
			}
			return &entry->list;
		}
		*pos = (loff_t)(bucket + 2) << 32;
		skip = 0;
	}
	return NULL;
}

static void *ft_start(struct seq_file *seq, loff_t *pos)
{
	cdx_ft_begin();
	return *pos ? ft_position(pos) : &ft_entries;
}

static void *ft_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct cdx_ft_entry *entry;

	if (v != &ft_entries) {
		entry = list_entry(v, struct cdx_ft_entry, list);
		if (entry->cookie_node.next) {
			(*pos)++;
			entry = hlist_entry(entry->cookie_node.next,
					    struct cdx_ft_entry, cookie_node);
			return &entry->list;
		}
	}
	*pos = ((*pos >> 32) + 1) << 32;
	return ft_position(pos);
}

static void ft_stop(struct seq_file *seq, void *v)
{
	cdx_ft_end();
}

/* Outermost first, dot separated, "-" when the direction carries no tag. One
 * whitespace-free token per direction keeps the row parseable. */
static void ft_vlan_text(const struct cdx_ft_vlan *stack, u8 count, char *text, size_t size)
{
	unsigned int at = 0;
	u8 i;

	if (!count) {
		strscpy(text, "-", size);
		return;
	}
	for (i = 0; i < count; i++)
		at += scnprintf(text + at, size - at, i ? ".%u" : "%u", stack[i].id);
}

/* One row per session carrying live flows, whether or not it has a firmware
 * record. A session without one is the visible face of an exhausted pool: the
 * flows are forwarded either way, and this is what says which of them are
 * being counted. The rows sit with the header rather than in the paged flow
 * iteration because there is one per distinct session with live flows, which
 * is the number of uplinks rather than the number of connections.
 *
 * pppoe= repeats exactly what the flow rows carry in in_ppp=/out_ppp=, so the
 * two can be joined.
 */
static void ft_session_rows(struct seq_file *seq)
{
	struct cdx_ft_session_stats *record;
	struct cdx_ft_stats rx, tx;

	list_for_each_entry(record, &ft_session_stats, list) {
		cdx_ft_stats_read(record->slot, &rx, &tx);
		seq_printf(seq,
			   "session pppoe=%u@%pM lower=%d refs=%u slot=%s rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu\n",
			   record->id, record->mac, record->lower_ifindex,
			   record->refs, record->slot ? "yes" : "none",
			   rx.packets, rx.bytes, tx.packets, tx.bytes);
	}
}

/* The PPPoE session, as the id and the concentrator the path walk resolved.
 * Both are shown for either direction even though only an egress session is
 * inserted: the two come from the same walk, so a direction that strips and
 * one that inserts naming the same pair is what shows the connection agrees
 * with itself. Both match one line of /proc/net/pppoe, which is where the
 * negotiated session can be read back independently. */
static void ft_session_text(const struct cdx_ft_session *session, char *text,
			    size_t size)
{
	if (!session->present)
		strscpy(text, "-", size);
	else
		scnprintf(text, size, "%u@%pM", session->id, session->mac);
}

/* The bridge, and the VID its FDB lookup was keyed on. That VID is not always
 * one of the tags: on an untagged egress port the frame carries none at all,
 * which is exactly the configuration a vlan-aware bridge ships with. */
static void ft_bridge_text(const struct net_device *bridge, u16 vid, char *text,
			   size_t size)
{
	if (!bridge)
		strscpy(text, "-", size);
	else if (vid)
		scnprintf(text, size, "%s.%u", bridge->name, vid);
	else
		strscpy(text, bridge->name, size);
}

static int ft_show(struct seq_file *seq, void *v)
{
	struct cdx_ft_session_stats *record;
	struct cdx_ft_entry *entry;
	struct cdx_ft_counters stats;
	unsigned int records = 0, slots = 0;
	char in_vlan[16], out_vlan[16];
	char in_br[IFNAMSIZ + 8], out_br[IFNAMSIZ + 8];
	char in_ppp[26], out_ppp[26];

	if (v != &ft_entries) {
		entry = list_entry(v, struct cdx_ft_entry, list);
		cdx_ft_stats(entry->hw, &stats);
		ft_vlan_text(entry->rule.in_vlan, entry->rule.in_vlans, in_vlan, sizeof(in_vlan));
		ft_vlan_text(entry->rule.out_vlan, entry->rule.out_vlans, out_vlan,
			     sizeof(out_vlan));
		ft_bridge_text(entry->rule.in_bridge, entry->rule.in_bridge_vid, in_br,
			       sizeof(in_br));
		ft_bridge_text(entry->rule.out_bridge, entry->rule.out_bridge_vid, out_br,
			       sizeof(out_br));
		ft_session_text(&entry->rule.in_session, in_ppp, sizeof(in_ppp));
		ft_session_text(&entry->rule.out_session, out_ppp, sizeof(out_ppp));
		/* One row shape per family. Brackets keep an IPv6 address and its
		 * port a single whitespace-free token, as the IPv4 rows already are. */
		if (entry->rule.family == AF_INET6)
			seq_printf(seq, "flow cookie=%lx in=%s out=%s in_vlan=%s out_vlan=%s in_br=%s out_br=%s in_ppp=%s out_ppp=%s family=6 src=[%pI6c]:%u dst=[%pI6c]:%u new_src=[%pI6c]:%u new_dst=[%pI6c]:%u proto=%u mtu=%u qos=%02x nexthop=%pI6c packets=%llu bytes=%llu lastused=%u\n",
				   entry->cookie, entry->rule.in->name, entry->rule.out->name,
				   in_vlan, out_vlan, in_br, out_br, in_ppp, out_ppp,
				   &entry->rule.src.in6, ntohs(entry->rule.sport),
				   &entry->rule.dst.in6, ntohs(entry->rule.dport),
				   &entry->rule.new_src.in6, ntohs(entry->rule.new_sport),
				   &entry->rule.new_dst.in6, ntohs(entry->rule.new_dport),
				   entry->rule.proto, entry->rule.mtu, entry->rule.qos,
				   &entry->next_hop.in6, stats.packets, stats.bytes, stats.lastused);
		else
			seq_printf(seq, "flow cookie=%lx in=%s out=%s in_vlan=%s out_vlan=%s in_br=%s out_br=%s in_ppp=%s out_ppp=%s family=4 src=%pI4:%u dst=%pI4:%u new_src=%pI4:%u new_dst=%pI4:%u proto=%u mtu=%u qos=%02x nexthop=%pI4 packets=%llu bytes=%llu lastused=%u\n",
				   entry->cookie, entry->rule.in->name, entry->rule.out->name,
				   in_vlan, out_vlan, in_br, out_br, in_ppp, out_ppp,
				   &entry->rule.src.ip, ntohs(entry->rule.sport),
				   &entry->rule.dst.ip, ntohs(entry->rule.dport),
				   &entry->rule.new_src.ip, ntohs(entry->rule.new_sport),
				   &entry->rule.new_dst.ip, ntohs(entry->rule.new_dport),
				   entry->rule.proto, entry->rule.mtu, entry->rule.qos,
				   &entry->next_hop.ip, stats.packets, stats.bytes, stats.lastused);
		return 0;
	}
	list_for_each_entry(record, &ft_session_stats, list) {
		records++;
		slots += !!record->slot;
	}
	/* The controller reads the mask back from here rather than from sysfs,
	 * because it already parses this header and must refuse a policy whose
	 * mark selectors contradict what the running adapter will decode. */
	seq_printf(seq, "qos_mark_mask %u\nqos_default_class %u\n",
		   ft_qos_mark_mask, ft_qos_default_class);
	seq_printf(seq, "owner %s\nobserve %u\nbindings %u\nentries %u\nmax_entries %u\n"
		   "installs %llu\ndeletes %llu\nrejects %llu\nerrors %llu\nvalidated %llu\nbusy %llu\n"
		   "invalidated %u\ninvalidation_done %u\nfatal %u\nquarantine %u\n"
		   "rearm_ready %u\nrearms %llu\nneighbour_refs %u\nhandle_refs %u\n"
		   "neighbour_invalidations %lld\nroute_invalidations %lld\nmtu_invalidations %lld\nlink_invalidations %lld\nmac_invalidations %lld\nfdb_invalidations %lld\nadmission_invalidations %lld\n",
		   "flowtable", cdx_ft_observing(), ft_bound, ft_count, CDX_FT_MAX_ENTRIES, ft_installs,
		   ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy, atomic_read(&ft_invalid),
		   ft_invalid_done, cdx_ft_failed(),
		   cdx_ft_pending(),
		   ft_can_rearm(), ft_rearms, ft_neighbour_refs, ft_handle_refs,
		   atomic64_read(&ft_neigh_invalidations),
		   atomic64_read(&ft_route_invalidations),
		   atomic64_read(&ft_mtu_invalidations),
		   atomic64_read(&ft_link_invalidations),
		   atomic64_read(&ft_mac_invalidations),
		   atomic64_read(&ft_fdb_invalidations),
		   atomic64_read(&ft_admission_invalidations));
	seq_printf(seq, "session_records %u\nsession_slots %u\n",
		   records, slots);
	ft_session_rows(seq);
	return 0;
}

static const struct seq_operations ft_seq_ops = {
	.start = ft_start,
	.next = ft_next,
	.stop = ft_stop,
	.show = ft_show,
};
static int ft_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ft_seq_ops);
}

static const struct proc_ops ft_proc_ops = {
	.proc_open = ft_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release,
};

static bool ft_init_fault(unsigned int stage)
{
#ifdef CDX_DEBUG_FLOWTABLE
	return ft_init_fail_stage == stage;
#else
	return false;
#endif
}

static int __init ask_flowtable_init(void)
{
	int rc;

	/* Refuse a classification the adapter would have to truncate. Both
	 * values are boot-immutable, so checking once here is the only chance
	 * to say so out loud; silently narrowing them would accelerate flows
	 * onto queues the operator never named. */
	if (ft_qos_mark_mask &&
	    (ft_qos_mark_mask >> __ffs(ft_qos_mark_mask)) > U8_MAX) {
		pr_err("cdx flowtable: qos_mark_mask %#x spans more than the eight bits of a class\n",
		       ft_qos_mark_mask);
		return -EINVAL;
	}
	if (!ft_qos_class_valid(ft_qos_default_class)) {
		pr_err("cdx flowtable: qos_default_class %#x names no CEETM queue\n",
		       ft_qos_default_class);
		return -EINVAL;
	}
	ft_hash_seed = get_random_u32();
	/* Exported symbol dependencies pin a fully initialized CDX throughout
	 * this module's lifetime, including failed initialization and exit. */
	cdx_ft_begin();
	rc = cdx_ft_claim();
	cdx_ft_end();
	if (rc)
		return rc;
	ft_proc = ft_init_fault(1) ? NULL :
		proc_create("cdx_flowtable", 0400, NULL, &ft_proc_ops);
	if (!ft_proc) {
		rc = -ENOMEM;
		goto release;
	}
	rc = ft_init_fault(2) ? -ENOMEM : register_netdevice_notifier(&ft_netdev_nb);
	if (rc)
		goto proc;
	rc = ft_init_fault(3) ? -ENOMEM : register_netevent_notifier(&ft_neigh_nb);
	if (rc)
		goto netdev;
	rc = ft_init_fault(4) ? -ENOMEM : register_fib_notifier(&init_net, &ft_fib_nb, NULL, NULL);
	if (rc)
		goto neigh;
	rc = ft_init_fault(6) ? -ENOMEM : register_nexthop_notifier(&init_net, &ft_nexthop_nb, NULL);
	if (rc)
		goto fib;
	rc = ft_init_fault(7) ? -ENOMEM : register_switchdev_notifier(&ft_fdb_nb);
	if (rc)
		goto nexthop;
	rc = ft_init_fault(8) ? -ENOMEM : register_switchdev_blocking_notifier(&ft_swdev_nb);
	if (rc)
		goto fdb;
	WRITE_ONCE(ft_ready, true);
	rc = ft_init_fault(5) ? -ENOMEM : flow_indr_dev_register(ft_bind, NULL);
	if (!rc)
		return 0;
	WRITE_ONCE(ft_ready, false);
	unregister_switchdev_blocking_notifier(&ft_swdev_nb);
fdb:
	unregister_switchdev_notifier(&ft_fdb_nb);
nexthop:
	unregister_nexthop_notifier(&init_net, &ft_nexthop_nb);
fib:
	unregister_fib_notifier(&init_net, &ft_fib_nb);
neigh:
	unregister_netevent_notifier(&ft_neigh_nb);
netdev:
	unregister_netdevice_notifier(&ft_netdev_nb);
proc:
	proc_remove(ft_proc);
	ft_proc = NULL;
release:
	cdx_ft_begin();
	WARN_ON_ONCE(cdx_ft_release());
	cdx_ft_end();
	return rc;
}

static void __exit ask_flowtable_exit(void)
{
	struct cdx_ft_entry *entry;
	int rc;

	proc_remove(ft_proc);
	ft_proc = NULL;
	/* Exclude cached Linux lookup before draining hardware. Unregistering
	 * indirect blocks then performs native flow cleanup and excludes all
	 * callbacks before releasing their binding storage. */
	cdx_ft_begin();
	WRITE_ONCE(ft_stopping, true);
	list_for_each_entry(entry, &ft_entries, list)
		nf_flow_offload_handle_invalidate(entry->handle);
	cdx_ft_end();
	unregister_switchdev_blocking_notifier(&ft_swdev_nb);
	unregister_switchdev_notifier(&ft_fdb_nb);
	unregister_nexthop_notifier(&init_net, &ft_nexthop_nb);
	unregister_fib_notifier(&init_net, &ft_fib_nb);
	unregister_netevent_notifier(&ft_neigh_nb);
	unregister_netdevice_notifier(&ft_netdev_nb);
	cancel_work_sync(&ft_retire_work);
	cancel_delayed_work_sync(&ft_work);
	flow_indr_dev_unregister(ft_bind, NULL, ft_release);
	WRITE_ONCE(ft_ready, false);
	/* Exit cannot fail. Complete every barrier, or prove hardware stopped,
	 * before releasing CDX. Release the transaction between retries so
	 * configuration and other kernel work can progress. Fatal state stays
	 * in CDX and a subsequent adapter load cannot clear it. */
	do {
		cdx_ft_begin();
		rc = cdx_ft_recover();
		if (!rc)
			rc = cdx_ft_release();
		cdx_ft_end();
		if (rc) {
			pr_warn_ratelimited("ask_flowtable: waiting for safe hardware retirement before unload\n");
			msleep(1000);
		}
	} while (rc);
	/* Every record is held by the entries naming its session, and the
	 * release above only succeeds with none of those left, so the list has
	 * drained with them. Say so rather than assume it: a slot never
	 * returned is a firmware record no later session can claim, and
	 * nothing else would ever report that. */
	WARN_ON_ONCE(!list_empty(&ft_session_stats));
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ASK Linux flowtable adapter using the CDX hardware backend");
MODULE_IMPORT_NS(ASK_CDX_FLOWTABLE);
module_init(ask_flowtable_init);
module_exit(ask_flowtable_exit);

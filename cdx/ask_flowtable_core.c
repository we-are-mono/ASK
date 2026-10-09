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
#include "ask_flowtable_internal.h"

#ifdef CDX_DEBUG_FLOWTABLE
static unsigned int ft_fail_stage;
unsigned int ft_init_fail_stage;
module_param_named(init_fail_stage, ft_init_fail_stage, uint, 0444);
MODULE_PARM_DESC(init_fail_stage, "Fail adapter load: 1 proc, 2 netdev, 3 neighbour, 4 FIB, 5 indirect registration, 6 nexthop objects, 7 bridge FDB, 8 bridge VLAN configuration, 9 direct registration");
module_param_named(flowtable_fail_stage, ft_fail_stage, uint, 0600);
MODULE_PARM_DESC(flowtable_fail_stage, "One-shot add failure: 1 before allocation, 2 before hardware, 3 after hardware, 4 busy after peer direction");
#endif

/* Binding mutations hold both the backend transaction and ft_watch_lock.
 * Transaction readers and device notifiers can therefore use their own lock.
 * The binding's existing device reference covers its entire watch lifetime. */
LIST_HEAD(ft_bindings);
LIST_HEAD(ft_entries);
/* Both indexes share the backend transaction and the entry's list lifetime. */
DEFINE_HASHTABLE(ft_cookies, CDX_FT_HASH_BITS);
static DEFINE_HASHTABLE(ft_keys, CDX_FT_HASH_BITS);
u32 ft_hash_seed;
/* Flow watch publication/removal is serialized by the backend transaction.
 * Neighbour, route and device notifiers share the immutable rule, neigh and
 * handle, protected against entry removal here. Never take a neighbour lock
 * or start a backend transaction while holding this lock. */
LIST_HEAD(ft_neigh_entries);
/* The same entries by what the FDB and neighbour notifiers carry: the
 * destination MAC and VID a bridged egress was pinned under, and the
 * neighbour an entry holds. Both events come at the rate stations learn and
 * resolve -- a new source MAC is one -- under the bridge's or the neighbour's
 * own lock, so each costs a bucket rather than a walk of every flow. Same lock
 * and lifetime as ft_neigh_entries. */
DEFINE_HASHTABLE(ft_fdb_watch, CDX_FT_HASH_BITS);
DEFINE_HASHTABLE(ft_neigh_watch, CDX_FT_HASH_BITS);
DEFINE_SPINLOCK(ft_watch_lock);
LIST_HEAD(ft_block_list);
/* Device counter records, VLAN and ppp alike. Mutated under the backend
 * transaction like the entries that reference them, and additionally under
 * ft_dev_stats_lock, because the netdev notifier marks a record's device gone
 * without a transaction: the reaper then frees what nothing references. */
LIST_HEAD(ft_dev_stats);
static DEFINE_SPINLOCK(ft_dev_stats_lock);
unsigned int ft_bound, ft_count;
/* How many of ft_bound are parked. Written only in the transaction, like
 * the flag, but ft_invalidate() reads it without one: every write is
 * WRITE_ONCE, so that read sees either value, never a torn one. */
unsigned int ft_parked;
/* Passive bindings, which ft_bound does not count. Transaction-only. */
unsigned int ft_passive;
unsigned int ft_neighbour_refs;
unsigned int ft_handle_refs;
atomic64_t ft_neigh_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_route_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_mtu_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_link_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_mac_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_fdb_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_stp_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_qos_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_admission_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_destroy_deferrals = ATOMIC64_INIT(0);
atomic64_t ft_ipsec_invalidations = ATOMIC64_INIT(0);
atomic64_t ft_ipsec_genid = ATOMIC64_INIT(0);
atomic64_t ft_ipsec_policy_invalidations = ATOMIC64_INIT(0);
u64 ft_installs, ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy;
u64 ft_rearms;
bool ft_ready, ft_stopping;
atomic_t ft_invalid = ATOMIC_INIT(0);
bool ft_invalid_done;
/* A parked table keeps collecting software flows while the latch is held, so
 * an event raised then must be covered by a worker pass that flushes them
 * before the table can go live -- folding it into the latch, as an event
 * with nothing parked safely is, would let those flows into hardware later.
 * ft_invalid_seq counts such events (notifier context, no transaction); the
 * worker samples it before a pass and publishes what that pass covered in
 * ft_done_seq (under the transaction). */
atomic_t ft_invalid_seq = ATOMIC_INIT(0);
int ft_done_seq;
struct proc_dir_entry *ft_proc;
static void ft_retire_workfn(struct work_struct *work);
static void ft_settle_workfn(struct work_struct *work);
static void ft_rearm_workfn(struct work_struct *work);
static void ft_dev_stats_reap(struct work_struct *work);
DECLARE_DELAYED_WORK(ft_work, ft_invalidate_work);
DECLARE_WORK(ft_retire_work, ft_retire_workfn);
DECLARE_WORK(ft_settle_work, ft_settle_workfn);
DECLARE_DELAYED_WORK(ft_rearm_work, ft_rearm_workfn);
DECLARE_WORK(ft_dev_stats_work, ft_dev_stats_reap);

static bool ft_fault(unsigned int stage)
{
#ifdef CDX_DEBUG_FLOWTABLE
	return cmpxchg(&ft_fail_stage, stage, 0) == stage;
#else
	return false;
#endif
}

void ft_invalidate(void)
{
	bool parked;

	if (!READ_ONCE(ft_bound) || READ_ONCE(ft_stopping))
		return;
	/* Counted before the latch is read, with a full barrier between, so
	 * that ft_rearm(), which clears the latch before reading the count,
	 * either sees the count move and keeps the latch, or this finds the
	 * latch clear and takes it -- an ordinary invalidation of bindings
	 * that are live by then. With nothing parked there is nothing to
	 * count: a table parked later holds only flows made after its bind. */
	parked = READ_ONCE(ft_parked);
	if (parked) {
		atomic_inc(&ft_invalid_seq);
		smp_mb__after_atomic();
	}
	if (atomic_cmpxchg(&ft_invalid, 0, 1) == 0 || parked)
		schedule_delayed_work(&ft_work, 0);
}

static struct cdx_ft_entry *ft_find(const struct cdx_ft_binding *binding,
				  unsigned long cookie)
{
	struct cdx_ft_entry *entry;

	hash_for_each_possible(ft_cookies, entry, cookie_node,
			       cookie ^ (unsigned long)binding)
		if (entry->binding == binding && entry->cookie == cookie)
			return entry;
	return NULL;
}

/* Handles have been marked that the retirement worker can find only by walking
 * the table. */
static atomic_t ft_retire_scan = ATOMIC_INIT(0);

/* Called with either the backend transaction or the notifier's ft_watch_lock held. The
 * handle is immutable, owned before watch publication and shared by both
 * directions. Marking it also excludes Linux's cached flow immediately;
 * native GC later retires that generation without flushing unrelated flows.
 */
void ft_handle_invalidate(struct nf_flow_offload_handle *handle,
			  atomic64_t *counter)
{
	if (nf_flow_offload_handle_invalidate(handle))
		atomic64_inc(counter);
	/* The worker has to walk the table for this one: nothing says which
	 * entries name the handle. */
	atomic_set(&ft_retire_scan, 1);
	if (!READ_ONCE(ft_stopping))
		schedule_work(&ft_retire_work);
}

/* A Linux deletion that found the transaction held (ft_rule_callback()):
 * what the retirement worker needs to find its entry without walking the
 * table. The binding is only compared, never dereferenced -- it may be
 * released first -- and the handle is held, so no later generation can be
 * mistaken for this one. */
struct ft_deferred_destroy {
	struct llist_node node;
	const struct cdx_ft_binding *binding;
	unsigned long cookie;
	struct nf_flow_offload_handle *handle;
};

static LLIST_HEAD(ft_deferred_destroys);

static void ft_destroy_defer(const struct cdx_ft_binding *binding,
			     const struct flow_cls_offload *cls)
{
	struct ft_deferred_destroy *deferred;

	if (nf_flow_offload_handle_invalidate(cls->nf_handle))
		atomic64_inc(&ft_destroy_deferrals);
	deferred = kmalloc(sizeof(*deferred), GFP_NOWAIT | __GFP_NOWARN);
	if (deferred) {
		deferred->binding = binding;
		deferred->cookie = cls->cookie;
		deferred->handle = cls->nf_handle;
		nf_flow_offload_handle_get(deferred->handle);
		llist_add(&deferred->node, &ft_deferred_destroys);
	} else {
		/* The handle is marked all the same; the walk finds it. */
		atomic_set(&ft_retire_scan, 1);
	}
	if (!READ_ONCE(ft_stopping))
		schedule_work(&ft_retire_work);
}

/* Unlink the entries deferred deletions name, at most FT_RETIRE_BATCH of them;
 * true when records are left for the next run. A record whose entry is gone
 * -- released with its binding, retired by a walk, or never in hardware --
 * is simply dropped. */
static bool ft_retire_deferred(void)
{
	struct llist_node *list = llist_del_all(&ft_deferred_destroys);
	struct ft_deferred_destroy *deferred, *next;
	struct cdx_ft_entry *entry;
	unsigned int n = 0;
	bool more = false;

	llist_for_each_entry_safe(deferred, next, list, node) {
		if (n == FT_RETIRE_BATCH) {
			llist_add(&deferred->node, &ft_deferred_destroys);
			more = true;
			continue;
		}
		entry = ft_find(deferred->binding, deferred->cookie);
		if (entry && entry->handle == deferred->handle) {
			ft_unlink(entry);
			n++;
		}
		nf_flow_offload_handle_put(deferred->handle);
		kfree(deferred);
	}
	return more;
}

/* Every record left once nothing can add one: unload, after the bindings'
 * release. Their entries went with the bindings. */
void ft_deferred_destroys_drop(void)
{
	struct ft_deferred_destroy *deferred, *next;

	llist_for_each_entry_safe(deferred, next, llist_del_all(&ft_deferred_destroys), node) {
		nf_flow_offload_handle_put(deferred->handle);
		kfree(deferred);
	}
}

void ft_neigh_invalidate(struct cdx_ft_entry *entry)
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

bool ft_rule_names(const struct cdx_ft_rule *rule, const struct net_device *dev)
{
	return rule->in == dev || rule->out == dev ||
		rule->in_logical == dev || rule->out_logical == dev ||
		rule->in_bridge == dev || rule->out_bridge == dev;
}

/* Hold one device the walk crossed, by the index the rule recorded it under,
 * unless the rule names it already or it is held for this entry once. Under
 * the admission's RTNL, the same hold the walk resolved the index under, so it
 * still names that device. */
static void ft_crossed_hold(struct cdx_ft_entry *entry, int ifindex)
{
	struct net_device *dev;
	unsigned int i;

	if (!ifindex)
		return;
	dev = __dev_get_by_index(&init_net, ifindex);
	if (!dev || ft_rule_names(&entry->rule, dev))
		return;
	for (i = 0; i < entry->ncrossed; i++)
		if (entry->crossed[i] == dev)
			return;
	if (WARN_ON_ONCE(entry->ncrossed == ARRAY_SIZE(entry->crossed)))
		return;
	dev_hold(dev);
	entry->crossed[entry->ncrossed++] = dev;
}

/* A tag the bridge adds has no device and records index zero. A tunnel's own
 * device is the logical one, and so is the top of the tag stack whenever
 * nothing sits above it. */
static void ft_crossed_hold_all(struct cdx_ft_entry *entry)
{
	const struct cdx_ft_rule *rule = &entry->rule;
	unsigned int i;

	if (rule->out_tunnel.present)
		ft_crossed_hold(entry, rule->out_tunnel.lower_ifindex);
	if (rule->out_session.present)
		ft_crossed_hold(entry, rule->out_session.lower_ifindex);
	for (i = 0; i < rule->out_vlans; i++)
		ft_crossed_hold(entry, rule->out_vlan[i].ifindex);
	if (rule->in_tunnel.present)
		ft_crossed_hold(entry, rule->in_tunnel.lower_ifindex);
	if (rule->in_session.present)
		ft_crossed_hold(entry, rule->in_session.lower_ifindex);
	for (i = 0; i < rule->in_vlans; i++)
		ft_crossed_hold(entry, rule->in_vlan[i].ifindex);
}

static void ft_crossed_put_all(struct cdx_ft_entry *entry)
{
	while (entry->ncrossed)
		dev_put(entry->crossed[--entry->ncrossed]);
}

/* What the firmware's VLAN opcodes count into a device's record and the
 * device's own counters would not, per packet.
 *
 * Measured on hardware rather than inferred (docs/flowtable/statistics.md has
 * the frames): the firmware counts a tag's record with the frame as it stands
 * once that tag has been handled, so the strip counts the frame with the tag
 * already gone and the insert counts it with the tag already on -- for a
 * double-tagged 306-byte frame the two records read 302 and 298 on the way in
 * and 302 and 306 on the way out. An 802.1Q device counts a received frame after
 * the port pulled the Ethernet header and its own tag came off, and a
 * transmitted one after vlan_dev_hard_start_xmit() moved its own tag into the
 * skb's metadata (reorder_hdr, the default) -- so on both sides the device's
 * number is the frame without the device's tag, and the framing to take off is
 * the Ethernet header on receive and the tag itself on transmit, at every depth
 * of the stack. The software fast path confirms the transmit side: the same
 * burst forwarded by the CPU leaves 298 per frame on eth3.271 for 302 on the
 * wire.
 */
#define FT_VLAN_RX_OVERHEAD ETH_HLEN
#define FT_VLAN_TX_OVERHEAD VLAN_HLEN

/* The same for a ppp device and the two PPPoE opcodes, measured on the DK with
 * a session over one tag (docs/flowtable/statistics.md has the frames). The
 * strip counts the frame as it arrived less the session header alone: for a
 * 310-byte frame its record reads 302, so the tags under the session are still
 * in the count even though the tag strip ran first. The insert runs before any
 * tag goes on and counts the frame with the session header already on, 306 for
 * the same payload. A ppp device counts the payload alone on both sides --
 * ppp_generic.c takes the PPP protocol word off before it adds skb->len -- so
 * the framing to take off is the Ethernet header plus one tag per VLAN device
 * the session runs over on receive, and the Ethernet and PPPoE headers on
 * transmit. The tag count is taken from the first direction admitted and
 * published once: a session's lower device is fixed for the session's life,
 * and a device that outlives its session (pppd's persist) and redials over a
 * differently tagged path would read four bytes per frame off on receive
 * until it is recreated, which is preferred to restating totals already
 * accumulated. */
static unsigned int ft_ppp_rx_overhead(unsigned int lower_tags)
{
	return ETH_HLEN + lower_tags * VLAN_HLEN;
}

#define FT_PPP_TX_OVERHEAD (ETH_HLEN + PPPOE_SES_HLEN)

/* What the firmware counts into a tunnel device's record and the device's own
 * counters do not, per packet, measured on the DK (docs/flowtable/tunnels.md
 * has the frames). A tunnel device counts the inner packet alone on both
 * sides: sit and ip6_tnl add skb->len after the outer header has been pulled
 * on receive, and the inner length on transmit. Measured with a 104-byte
 * inner packet on an untagged path: the strip's record read 118, so it counts
 * the Ethernet header and the inner packet but not the outer header it has
 * removed -- receive overhead ETH_HLEN; the insert's read 138, the whole frame
 * with the outer header on -- transmit overhead ETH_HLEN + the outer header.
 * A tag or a session under the tunnel adds its own bytes to both, by the same
 * reasoning the VLAN and session records follow.
 *
 * The record is one per device and serves both directions, so the framing is
 * named per side rather than per rule: the direction that strips over the
 * device supplies the receive framing from its own ingress stack, the one that
 * inserts supplies the transmit framing from its egress stack. The two are the
 * same physical stack for one connection; where they differ, the first
 * direction admitted publishes, as a session's record does. */
static unsigned int ft_tunnel_under(unsigned int vlans, bool session)
{
	return vlans * VLAN_HLEN + (session ? PPPOE_SES_HLEN : 0);
}

static void ft_dev_stats_release(struct cdx_ft_dev_stats *record)
{
	cdx_ft_stats_free(&record->slot);
	kfree(record);
}

/* The record for one device, created on first reference and published to the
 * device at once. Exhaustion of the firmware pool is deliberately not a
 * failure: counters are observability and forwarding is the product, so the
 * record is created regardless and simply carries no slot. That also keeps
 * the reference counting uniform -- every direction holds a reference whether
 * or not a slot exists -- and the device shows up in the read-back either way,
 * so the degradation is visible rather than silent. A tag with no device -- a
 * vlan-aware bridge's own -- has no record, because there is no interface
 * whose counters it could be folded into. */
static struct cdx_ft_dev_stats *ft_dev_stats_get(int ifindex, enum cdx_ft_stats_kind kind,
						 const struct cdx_ft_session *session,
						 const struct cdx_ft_tunnel *tunnel,
						 unsigned int rx_overhead,
						 unsigned int tx_overhead)
{
	struct cdx_ft_dev_stats *record;

	if (!ifindex)
		return NULL;
	cdx_ft_assert_held();
	/* Under RTNL as well, which the caller holds for the device walk the
	 * rule came from: the device cannot unregister between the search and
	 * the insertion, so a record is never added for a device already gone. */
	ASSERT_RTNL();
	spin_lock_bh(&ft_dev_stats_lock);
	list_for_each_entry(record, &ft_dev_stats, list)
		if (record->ifindex == ifindex && !record->gone) {
			/* A device's kind is fixed by what it is; a record of
			 * the other kind under a live index would mean the
			 * unregistration that marks a record gone was missed.
			 * Counting nowhere is the safe answer then: the other
			 * pool's index would aim an opcode at a record of the
			 * wrong shape. A tunnel device and a VLAN device share
			 * a pool but not a shape either. */
			if (WARN_ON_ONCE(record->kind != kind ||
					 record->tunnel.present != !!tunnel)) {
				spin_unlock_bh(&ft_dev_stats_lock);
				return NULL;
			}
			record->refs++;
			if (session)
				record->session = *session;
			if (tunnel)
				record->tunnel = *tunnel;
			spin_unlock_bh(&ft_dev_stats_lock);
			return record;
		}
	spin_unlock_bh(&ft_dev_stats_lock);
	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return NULL;
	record->ifindex = ifindex;
	record->kind = kind;
	record->refs = 1;
	if (session)
		record->session = *session;
	if (tunnel)
		record->tunnel = *tunnel;
	if (cdx_ft_stats_alloc(kind, &record->slot))
		record->slot = NULL;
	else
		cdx_ft_stats_publish(record->slot, ifindex, rx_overhead, tx_overhead);
	spin_lock_bh(&ft_dev_stats_lock);
	list_add_tail(&record->list, &ft_dev_stats);
	spin_unlock_bh(&ft_dev_stats_lock);
	return record;
}

static void ft_dev_stats_put(struct cdx_ft_dev_stats **held)
{
	struct cdx_ft_dev_stats *record = *held;
	bool last;

	if (!record)
		return;
	cdx_ft_assert_held();
	*held = NULL;
	spin_lock_bh(&ft_dev_stats_lock);
	/* The last direction naming a record whose device has already gone:
	 * nothing will find it again, so it goes with the direction. A device
	 * that is still here keeps its record and its totals. */
	last = !--record->refs && record->gone;
	if (last)
		list_del(&record->list);
	spin_unlock_bh(&ft_dev_stats_lock);
	if (last)
		ft_dev_stats_release(record);
}

/* From the netdev notifier, under RTNL and without a transaction, so only the
 * mark is made here; a record nothing references is freed by the reaper, which
 * takes the transaction the backend requires. One still referenced is freed by
 * the last release instead.
 *
 * The publication is withdrawn now rather than with the slot. A device that
 * has left init_net for another namespace keeps its index there, and this
 * namespace can hand the same index to a new device while the old record waits
 * on its last direction; the fold keys on the index alone, so a record left
 * published would be counted into that new device. Withdrawing needs only the
 * allocator's spinlock, which is why it can be done from here. */
void ft_dev_stats_gone(const struct net_device *dev)
{
	struct cdx_ft_dev_stats *record;
	bool reap = false;

	spin_lock_bh(&ft_dev_stats_lock);
	list_for_each_entry(record, &ft_dev_stats, list)
		if (record->ifindex == dev->ifindex && !READ_ONCE(record->gone)) {
			WRITE_ONCE(record->gone, true);
			cdx_ft_stats_unpublish(record->slot);
			reap |= !record->refs;
		}
	spin_unlock_bh(&ft_dev_stats_lock);
	if (reap)
		schedule_work(&ft_dev_stats_work);
}

static void ft_dev_stats_reap(struct work_struct *work)
{
	struct cdx_ft_dev_stats *record, *next;
	LIST_HEAD(free);

	cdx_ft_begin();
	spin_lock_bh(&ft_dev_stats_lock);
	list_for_each_entry_safe(record, next, &ft_dev_stats, list)
		if (record->gone && !record->refs)
			list_move(&record->list, &free);
	spin_unlock_bh(&ft_dev_stats_lock);
	list_for_each_entry_safe(record, next, &free, list) {
		list_del(&record->list);
		ft_dev_stats_release(record);
	}
	cdx_ft_end();
}

/* At unload, once no hardware direction is left and every retirement has been
 * proven (ft_hw_settle()): the devices are still registered, so the list does
 * not drain by construction, and every record is freed here. */
void ft_dev_stats_drop_all(void)
{
	struct cdx_ft_dev_stats *record, *next;
	LIST_HEAD(free);

	cdx_ft_begin();
	spin_lock_bh(&ft_dev_stats_lock);
	list_splice_init(&ft_dev_stats, &free);
	spin_unlock_bh(&ft_dev_stats_lock);
	list_for_each_entry_safe(record, next, &free, list) {
		WARN_ON_ONCE(record->refs);
		list_del(&record->list);
		ft_dev_stats_release(record);
	}
	cdx_ft_end();
}

/* Both halves of one connection cross the same ppp device and therefore share
 * one record, so a connection holds two references to it; likewise each tag's
 * VLAN device, where one half strips and the other inserts. The ppp device is
 * the direction's logical device whenever it carries a session: the path walk
 * takes the session hop only from a device of that type. Nothing here can
 * fail: a direction whose record could not be created counts nowhere and
 * forwards regardless. */
static void ft_stats_attach(struct cdx_ft_entry *entry)
{
	const struct cdx_ft_rule *rule = &entry->rule;
	unsigned int i;

	/* A session is outermost on its L2 path, so the direction's whole tag
	 * stack is what sits under it. The ppp device is the direction's
	 * logical device unless a tunnel runs over the session, in which case
	 * it is the device the tunnel hop named. */
	entry->in_stats = rule->in_session.present ?
		ft_dev_stats_get(rule->in_session.lower_ifindex ?
				 (rule->in_tunnel.present ? rule->in_tunnel.lower_ifindex :
				  rule->in_logical->ifindex) : 0,
				 CDX_FT_STATS_TIMESTAMPED, &rule->in_session, NULL,
				 ft_ppp_rx_overhead(rule->in_vlans), FT_PPP_TX_OVERHEAD) : NULL;
	entry->out_stats = rule->out_session.present ?
		ft_dev_stats_get(rule->out_tunnel.present ? rule->out_tunnel.lower_ifindex :
				 rule->out_logical->ifindex,
				 CDX_FT_STATS_TIMESTAMPED, &rule->out_session, NULL,
				 ft_ppp_rx_overhead(rule->out_vlans), FT_PPP_TX_OVERHEAD) : NULL;
	for (i = 0; i < rule->in_vlans; i++)
		entry->in_vlan_stats[i] = ft_dev_stats_get(rule->in_vlan[i].ifindex,
							   CDX_FT_STATS_PLAIN, NULL, NULL,
							   FT_VLAN_RX_OVERHEAD, FT_VLAN_TX_OVERHEAD);
	for (i = 0; i < rule->out_vlans; i++)
		entry->out_vlan_stats[i] = ft_dev_stats_get(rule->out_vlan[i].ifindex,
							    CDX_FT_STATS_PLAIN, NULL, NULL,
							    FT_VLAN_RX_OVERHEAD, FT_VLAN_TX_OVERHEAD);
	/* A tunnel is outermost of all, so the tunnel device is always the
	 * direction's logical device when it carries one. The receive framing
	 * is this direction's ingress stack under the tunnel and the transmit
	 * framing its egress stack plus the outer header, each named from the
	 * side that feeds that half of the shared record. */
	entry->in_tunnel_stats = rule->in_tunnel.present ?
		ft_dev_stats_get(rule->in_tunnel.ifindex, CDX_FT_STATS_PLAIN, NULL,
				 &rule->in_tunnel,
				 ETH_HLEN + ft_tunnel_under(rule->in_vlans,
							    rule->in_session.present),
				 ETH_HLEN + rule->in_tunnel.header_size +
				 ft_tunnel_under(rule->in_vlans,
						 rule->in_session.present)) : NULL;
	entry->out_tunnel_stats = rule->out_tunnel.present ?
		ft_dev_stats_get(rule->out_tunnel.ifindex, CDX_FT_STATS_PLAIN, NULL,
				 &rule->out_tunnel,
				 ETH_HLEN + ft_tunnel_under(rule->out_vlans,
							    rule->out_session.present),
				 ETH_HLEN + rule->out_tunnel.header_size +
				 ft_tunnel_under(rule->out_vlans,
						 rule->out_session.present)) : NULL;
}

static void ft_stats_detach(struct cdx_ft_entry *entry)
{
	unsigned int i;

	ft_dev_stats_put(&entry->in_stats);
	ft_dev_stats_put(&entry->out_stats);
	for (i = 0; i < CDX_FT_VLAN_MAX; i++) {
		ft_dev_stats_put(&entry->in_vlan_stats[i]);
		ft_dev_stats_put(&entry->out_vlan_stats[i]);
	}
	ft_dev_stats_put(&entry->in_tunnel_stats);
	ft_dev_stats_put(&entry->out_tunnel_stats);
}

static void ft_stats_binding(const struct cdx_ft_entry *entry,
			     struct cdx_ft_stats_binding *binding)
{
	unsigned int i;

	binding->in_session = entry->in_stats ? entry->in_stats->slot : NULL;
	binding->out_session = entry->out_stats ? entry->out_stats->slot : NULL;
	binding->in_tunnel = entry->in_tunnel_stats ? entry->in_tunnel_stats->slot : NULL;
	binding->out_tunnel = entry->out_tunnel_stats ? entry->out_tunnel_stats->slot : NULL;
	for (i = 0; i < CDX_FT_VLAN_MAX; i++) {
		binding->in_vlan[i] = entry->in_vlan_stats[i] ?
			entry->in_vlan_stats[i]->slot : NULL;
		binding->out_vlan[i] = entry->out_vlan_stats[i] ?
			entry->out_vlan_stats[i]->slot : NULL;
	}
}

/* Out of the adapter, and out of the classifier with the barrier that proves
 * the firmware has left it still owed: ft_settle() asks for that, once for
 * every entry unlinked since. A barrier is a host-command round trip, two
 * thirds of what a delete costs, so a walk that retires many entries settles
 * them behind one. Whatever owes a barrier settles it before the transaction
 * ends or queues ft_settle_work to, so nothing outside the transaction finds
 * an unlink unproven unless its barrier failed. */
int ft_unlink(struct cdx_ft_entry *entry)
{
	int rc = cdx_ft_unlink(&entry->hw);

	if (rc) {
		ft_errors++;
		ft_invalidate();
	}
	list_del(&entry->list);
	hash_del(&entry->cookie_node);
	hash_del(&entry->key_node);
	ft_neigh_detach(entry);
	/* After the delete, whatever it returned. This only drops the
	 * adapter's references: a delete that could not prove the firmware
	 * has stopped walking the entry leaves CDX's retained owner holding
	 * every record the entry names, so a record freed here stays out of
	 * the pool until that proof arrives. */
	ft_stats_detach(entry);
	nf_flow_offload_handle_put(entry->handle);
	ft_handle_refs--;
	ft_devices_put(&entry->rule);
	ft_crossed_put_all(entry);
	kfree(entry);
	ft_count--;
	ft_deletes++;
	return rc;
}

/* The barrier every unlink since the last one is owed. A failed one is a
 * failed deletion, counted once and escalated to global recovery as a delete
 * whose own barrier failed always was: that recovery retries the barrier
 * until it completes, or stops the datapath. */
int ft_settle(void)
{
	unsigned int unproven;

	cdx_ft_assert_held();
	if (!cdx_ft_owed() || !cdx_ft_settle(&unproven))
		return 0;
	ft_errors++;
	ft_invalidate();
	return -EAGAIN;
}

int ft_remove(struct cdx_ft_entry *entry)
{
	int rc = ft_unlink(entry);
	int settled = ft_settle();

	return rc ?: settled;
}

/* Unlink at most FT_RETIRE_BATCH of the entries @match selects and settle them
 * behind one barrier. True when it stopped at that bound with more selected:
 * the caller lets the transaction go before asking again, so retiring a full
 * table never holds it for more than one batch, and readers, admission and
 * Linux's own callbacks interleave with the retirement instead of queueing
 * behind all of it (A327). */
bool ft_retire_batch(bool (*match)(const struct cdx_ft_entry *entry, const void *arg),
		     const void *arg)
{
	struct cdx_ft_entry *entry, *next;
	unsigned int n = 0;
	bool more = false;

	cdx_ft_assert_held();
	list_for_each_entry_safe(entry, next, &ft_entries, list) {
		if (!match(entry, arg))
			continue;
		if (n == FT_RETIRE_BATCH) {
			more = true;
			break;
		}
		ft_unlink(entry);
		n++;
	}
	ft_settle();
	return more;
}

static bool ft_handle_retired(const struct cdx_ft_entry *entry, const void *arg)
{
	return !nf_flow_offload_handle_valid(entry->handle);
}

static void ft_retire_workfn(struct work_struct *work)
{
	bool more;

	cdx_ft_begin();
	/* Deferred deletions first: each names its entry, so retiring them
	 * costs nothing like a walk of the table, which only marked handles
	 * nothing names need. */
	more = ft_retire_deferred();
	/* A failed retirement escalates to the existing global recovery.
	 * That worker proves a barrier or stops the datapath before
	 * reporting completion. Nothing rearms while CDX's latch holds:
	 * it clears only once CDX has restarted the datapath. */
	if (!ft_stopping && !atomic_read(&ft_invalid) && atomic_xchg(&ft_retire_scan, 0) &&
	    ft_retire_batch(ft_handle_retired, NULL)) {
		atomic_set(&ft_retire_scan, 1);
		more = true;
	}
	ft_settle();
	cdx_ft_end();
	/* Behind whatever queued for the transaction meanwhile. */
	if (more && !READ_ONCE(ft_stopping))
		schedule_work(&ft_retire_work);
}

/* For unlinks whose callers could not settle them in the same transaction:
 * Linux's own deletions, one flow at a time. A burst of them shares the one
 * barrier this asks for. */
static void ft_settle_workfn(struct work_struct *work)
{
	cdx_ft_begin();
	ft_settle();
	cdx_ft_end();
}

static bool ft_next_hop(const struct flow_cls_offload *cls,
			struct net_device *dev, u8 family,
			const union nf_inet_addr *daddr,
			union nf_inet_addr *next_hop, u8 *next_hop_family)
{
	struct dst_entry *dst = cls->nf_dst;
	struct xfrm_state *x = NULL;
	union nf_inet_addr peer;

	*next_hop_family = family;
	if (!dst || dst->ops->family != family || dst->error ||
	    !dst_check(dst, cls->nf_dst_cookie))
		return false;
	/* An encrypted flow's destination is the transform, and the route to
	 * the peer is underneath it. The next hop belongs to that route: what
	 * leaves this port is the outer packet, addressed to the tunnel's far
	 * end rather than to the inner destination the tuple names. Walk down
	 * to it and judge that route by the same rules as any other.
	 *
	 * The SA itself is checked separately, by ft_ipsec_handle(); this is
	 * only about where the finished frame goes. */
	while (dst_xfrm(dst)) {
		x = dst_xfrm(dst);
		dst = xfrm_dst_child(dst);
		if (!dst || dst->ops->family != family || dst->error)
			return false;
	}
	/* Asked of the route that transmits, which is the one under any
	 * transform. The bundle above it carries the encapsulating device and
	 * whatever tunnel encapsulation the transform brings, neither of which
	 * describes the frame this port puts on the wire. */
	if (dst->dev != dev || dst->lwtstate)
		return false;
	/* An SA of the other family: the route under its bundle is the flow's
	 * own, which has no neighbour for an endpoint of the SA's family, so
	 * the kernel routes the endpoint in that family. The next hop and its
	 * neighbour are then that family's, and so is everything that checks
	 * or watches them. */
	if (x && x->props.family != family) {
		struct neighbour *neigh = xfrm_dev_peer_neigh(x);

		if (!neigh)
			return false;
		memset(next_hop, 0, sizeof(*next_hop));
		memcpy(next_hop, &neigh->primary_key, neigh->tbl->key_len);
		*next_hop_family = neigh->tbl->family;
		neigh_release(neigh);
		return ft_nexthop_usable(*next_hop_family, next_hop);
	}
	/* Past a transform the address to resolve is the tunnel's far end, not
	 * the flow's own destination. Both reach the same answer through a
	 * gateway route, which is why this went unnoticed: rt_nexthop() returns
	 * the gateway whatever it is handed. On an on-link route it returns
	 * what it was given, so asking with the inner destination named a next
	 * hop that is not on this segment and has no neighbour -- and the
	 * direction was refused rather than encrypted. */
	if (x) {
		memset(&peer, 0, sizeof(peer));
		if (family == AF_INET6)
			memcpy(&peer.in6, x->id.daddr.a6, sizeof(peer.in6));
		else
			peer.ip = x->id.daddr.a4;
		daddr = &peer;
	}
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

/* The two routes an offer borrows, which no lock orders against it: either
 * one having moved on retires the offer's whole generation. Needs no RTNL, so
 * an offer answered without admission is held to it as well. Returns whether
 * the generation is still valid. */
static bool ft_offer_routes_current(const struct flow_cls_offload *cls)
{
	if (nf_flow_offload_handle_valid(cls->nf_handle) && !ft_routes_valid(cls))
		ft_handle_invalidate(cls->nf_handle, &ft_route_invalidations);
	return nf_flow_offload_handle_valid(cls->nf_handle);
}

/* The routes, and the policy generation the offer was queued under. That is
 * the flow's creation generation on every offer, so it is asked only of an
 * offer not yet published: once published the handle is watched, and a policy
 * change retires the entry only if it can select it (ft_policy_covers()). An
 * installed direction's offer is held to its routes alone. */
static bool ft_offer_current(const struct flow_cls_offload *cls)
{
	if (cls->nf_xfrm_genid != xfrm_flowtable_genid(&init_net))
		ft_handle_invalidate(cls->nf_handle, &ft_ipsec_policy_invalidations);
	return ft_offer_routes_current(cls);
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
	unsigned int edits;
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
	if (((nat & IPS_SRC_NAT) && !(status & IPS_SRC_NAT_DONE)) ||
	    ((nat & IPS_DST_NAT) && !(status & IPS_DST_NAT_DONE)))
		return false;
	/* ip6t_NPT records the translated addresses in the reply tuple without
	 * setting IPS_NAT. Match the flowtable's tuple-derived address rewrites;
	 * Linux's NAT status must stay untouched for normal NPT forwarding. */
	if (out->family == AF_INET6) {
		if (!nf_inet_addr_cmp(&orig->src.u3, &reply->dst.u3))
			nat |= IPS_SRC_NAT;
		if (!nf_inet_addr_cmp(&orig->dst.u3, &reply->src.u3))
			nat |= IPS_DST_NAT;
	}
	edits = !!(nat & IPS_SRC_NAT) + !!(nat & IPS_DST_NAT);
	if (!nat)
		return actions->num_entries == 5 + encaps;
	if ((out->proto != IPPROTO_UDP && out->proto != IPPROTO_TCP) ||
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
struct net_device *ft_vlan_lower(struct net_device *dev)
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
int ft_bridge_vlan(struct net_device *bridge, struct net_device *port,
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
bool ft_tunnel_dev(const struct net_device *dev)
{
	return dev->type == ARPHRD_SIT || dev->type == ARPHRD_TUNNEL6;
}

/* The tunnel hop, taken from the kernel's own forwarding-path walk and checked
 * against the tunnel device it names.
 *
 * The hop is handed over rather than derived, for the same reason a session
 * is: the outer route is looked up by the tunnel's transmit path rather than
 * by the flow's, a tunnel device registers no lower neighbour to descend to,
 * and a second walk could disagree with the one the rule was built from. What
 * the device itself says is used as the cross-check -- the endpoints, the TTL
 * and the traffic class are its configuration, and a record that no longer
 * matches it describes a tunnel that has since been changed underneath the
 * flow. The mode follows from the device: a sit device inserts an IPv4 header
 * around an IPv6 packet, an ip6tnl device in ipip6 mode an IPv6 header around
 * an IPv4 one. Those two are what the hardware builds; every other shape --
 * 6rd and ISATAP, which pick the outer destination per packet, IPv6 in IPv6,
 * IPv4 in IPv4, GRE -- is refused here or was already refused by the walk.
 *
 * Two things the hardware cannot do are refused rather than approximated. A
 * TTL of zero means the inner packet's, and the insert writes the header it
 * is given; a TOS of "inherit" on a sit tunnel likewise, where the ip6tnl
 * insert has a flag for it and the sit one does not. Returns the device the
 * outer packet leaves by, which is where the walk continues.
 */
static struct net_device *ft_tunnel_hop(struct net_device *logical,
					const struct nf_flow_tunnel *hop,
					struct cdx_ft_tunnel *out)
{
	struct net_device *lower;

	if (!hop->lower_ifindex)
		return NULL;
	lower = __dev_get_by_index(&init_net, hop->lower_ifindex);
	if (!lower || lower == logical || !hop->ttl ||
	    (hop->flags & CDX_FT_TUNNEL_DSCP_COPY && logical->type != ARPHRD_TUNNEL6))
		return NULL;
	memset(out, 0, sizeof(*out));
	if (logical->type == ARPHRD_SIT) {
		const struct ip_tunnel *tunnel = netdev_priv(logical);
		const struct iphdr *tiph = &tunnel->parms.iph;

		if (hop->family != AF_INET || hop->proto != IPPROTO_IPV6 ||
		    (hop->flags & CDX_FT_TUNNEL_INHERIT_TOS) ||
		    !tiph->daddr || tiph->daddr != hop->daddr.ip ||
		    (tiph->saddr && tiph->saddr != hop->saddr.ip) ||
		    !hop->saddr.ip || tiph->ttl != hop->ttl ||
		    tiph->tos != hop->tos ||
		    ipv4_is_multicast(hop->daddr.ip) || ipv4_is_lbcast(hop->daddr.ip))
			return NULL;
		out->mode = CDX_FT_TUNNEL_6O4;
		out->header_size = sizeof(struct iphdr);
	} else if (logical->type == ARPHRD_TUNNEL6) {
		const struct ip6_tnl *tunnel = netdev_priv(logical);
		const struct __ip6_tnl_parm *parms = &tunnel->parms;

		if (hop->family != AF_INET6 || hop->proto != IPPROTO_IPIP ||
		    (parms->proto != IPPROTO_IPIP && parms->proto) ||
		    !ipv6_addr_equal(&parms->laddr, &hop->saddr.in6) ||
		    !ipv6_addr_equal(&parms->raddr, &hop->daddr.in6) ||
		    parms->hop_limit != hop->ttl ||
		    ipv6_addr_is_multicast(&hop->daddr.in6) ||
		    !!(parms->flags & IP6_TNL_F_USE_ORIG_TCLASS) !=
		    !!(hop->flags & CDX_FT_TUNNEL_INHERIT_TOS))
			return NULL;
		out->mode = CDX_FT_TUNNEL_4O6;
		out->header_size = sizeof(struct ipv6hdr);
	} else {
		return NULL;
	}
	/* The outer next hop has to be somewhere the hardware can send to. A
	 * ppp device below the tunnel resolves no address at all -- its
	 * neighbours carry the zero one -- and the session hop then names the
	 * concentrator instead, so only a lower device that does resolve
	 * neighbours is held to this. */
	if (lower->type != ARPHRD_PPP && !is_valid_ether_addr(hop->h_dest))
		return NULL;
	out->present = true;
	out->family = hop->family;
	out->proto = hop->proto;
	out->ttl = hop->ttl;
	out->tos = hop->tos;
	out->flags = hop->flags;
	out->flowlabel = hop->flowlabel;
	out->local = hop->saddr;
	out->remote = hop->daddr;
	out->nexthop = hop->nexthop;
	ether_addr_copy(out->mac, hop->h_dest);
	out->ifindex = logical->ifindex;
	out->lower_ifindex = hop->lower_ifindex;
	return lower;
}

static int ft_path_stack(struct net_device *logical, struct net_device *physical,
			 const struct nf_flow_session *session,
			 const struct nf_flow_tunnel *tunnel,
			 struct cdx_ft_vlan *stack, struct net_device **bridge,
			 u16 *bridge_vid, struct cdx_ft_session *out_session,
			 struct cdx_ft_tunnel *out_tunnel)
{
	/* Zeroed so a tag the bridge adds carries no device: ft_bridge_vlan()
	 * writes the tag and leaves ifindex alone. */
	struct cdx_ft_vlan inner[CDX_FT_VLAN_MAX] = {};
	unsigned int count = 0, i;
	int vid;

	*bridge = NULL;
	*bridge_vid = 0;
	memset(out_session, 0, sizeof(*out_session));
	memset(out_tunnel, 0, sizeof(*out_tunnel));
	if (!logical || !physical || !session || !tunnel)
		return -EOPNOTSUPP;
	/* The tunnel hop comes first of all, for the same structural reason
	 * the session hop comes before the loop: a tunnel is the outermost
	 * header a direction inserts, so the device it leaves by may be a ppp
	 * device, a VLAN device, a bridge or the port itself, and each of those
	 * is then walked as usual. The loop never returns here, so a tunnel
	 * anywhere else on the path is declined as any other unsupported upper
	 * device is. */
	if (ft_tunnel_dev(logical)) {
		logical = ft_tunnel_hop(logical, tunnel, out_tunnel);
		if (!logical)
			return -EOPNOTSUPP;
	}
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
			/* The bridge carries nothing through a port, or a VLAN
			 * of one, that is not FORWARDING. Admission runs
			 * asynchronously to the event that retires such a
			 * port's flows, and a refresh re-offers a flow the walk
			 * described while the port still forwarded, so ask the
			 * bridge, per VLAN, with the predicate its own walk
			 * applies. MST stays software-only: a VID-to-MSTI remap
			 * moves per-VLAN states under one bridge-wide event
			 * that this adapter does not map onto flows. */
			if (br_mst_enabled(logical) || !br_port_forwarding(physical, vid))
				return -EOPNOTSUPP;
			*bridge = logical;
			*bridge_vid = vid;
			break;
		}
		if (!is_vlan_dev(logical) || count == CDX_FT_VLAN_MAX ||
		    vlan_dev_vlan_proto(logical) != htons(ETH_P_8021Q))
			return -EOPNOTSUPP;
		inner[count].proto = vlan_dev_vlan_proto(logical);
		inner[count].id = vlan_dev_vlan_id(logical);
		/* The device whose counters this tag's traffic belongs to. */
		inner[count].ifindex = logical->ifindex;
		count++;
		logical = ft_vlan_lower(logical);
		if (!logical)
			return -EOPNOTSUPP;
	}
	/* A session the kernel's walk crossed but this one did not reach is a
	 * path shape this contract does not describe, and the hardware would be
	 * asked to forward it with no session header at all. Refuse rather than
	 * silently drop the hop. The same for a tunnel. */
	if ((session->lower_ifindex && !out_session->present) ||
	    (tunnel->lower_ifindex && !out_tunnel->present))
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
/* Whether two stacks put the same tags on the wire. The device behind a tag is
 * not part of that: a tag a vlan-aware bridge adds and the same tag from an
 * 802.1Q device look identical to the hardware, and the hairpin question is
 * about what the hardware sees. */
static bool ft_same_tags(const struct cdx_ft_vlan *a, const struct cdx_ft_vlan *b,
			 unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		if (a[i].proto != b[i].proto || a[i].id != b[i].id)
			return false;
	return true;
}

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

/* The largest untagged payload @port's MAC accepts: its MTU, but never less
 * than a standard Ethernet frame. Patch 109 programs each DPAA port's MAXFRM
 * from its MTU as max(mtu, 1500) plus the Ethernet header and FCS, and a tag
 * more while the port has any upper device -- a VLAN, a bridge, a bond, a
 * macvlan -- or two once a VLAN on it is 802.1ad or carries a VLAN, so that a
 * tagged frame still carries a full payload. A port lowered below 1500 thus
 * keeps receiving full frames, and a port raised above it receives what its
 * MTU allows whatever the devices above it say.
 *
 * Those tag bytes also let an untagged frame of a port with uppers exceed this
 * by four, or eight. That window is not counted: counting it would refuse
 * every 1500-byte UDP direction between two bridged 1500-byte ports, and only
 * a host sending more than the link's own MTU reaches it. */
u32 ft_port_arriving(const struct net_device *port)
{
	return max_t(u32, READ_ONCE(port->mtu), ETH_DATA_LEN);
}

/* An MTU less the header inserted below it, never wrapping. */
static u32 ft_mtu_less(u32 mtu, u32 header)
{
	return mtu > header ? mtu - header : 0;
}

/* The largest packet the devices below a direction's route carry for it: the
 * physical port's MTU, the session's and the tunnel's lower device's, each
 * less the session and tunnel headers inserted beneath it. A route's MTU is
 * its logical device's, and a bridge's MTU may be set above its ports' --
 * br_change_mtu() bounds it by nothing, and OpenWrt gives a bridge a jumbo MTU
 * a member may not follow -- where Linux then drops at the port whatever the
 * port's own MTU forbids (is_skb_forwardable()). A tunnel's MTU may be set
 * above its lower device's less the outer header, which Linux then enforces
 * on the outer packet. A VLAN device is bounded by its lower one. So a
 * direction is bounded by this as well as by its route, and hardware never
 * sends what Linux would not (A340). Under RTNL, which the lower devices are
 * found under; a change of any of their MTUs retires the direction
 * (ft_rule_names(), and the devices the walk crossed). */
u32 ft_port_mtu(const struct cdx_ft_rule *rule)
{
	u32 session = rule->out_session.present ? PPPOE_SES_HLEN : 0;
	/* The largest outer packet: what carries it, less the session. */
	u32 outer = ft_mtu_less(READ_ONCE(rule->out->mtu), session);
	struct net_device *lower;

	if (rule->out_session.present) {
		lower = __dev_get_by_index(&init_net, rule->out_session.lower_ifindex);
		if (lower)
			outer = min_t(u32, outer, ft_mtu_less(READ_ONCE(lower->mtu), session));
	}
	if (!rule->out_tunnel.present)
		return outer;
	/* The device the outer packet leaves by: a ppp device's MTU is already
	 * net of the session, any other device's is the packet's own. */
	lower = __dev_get_by_index(&init_net, rule->out_tunnel.lower_ifindex);
	if (lower)
		outer = min_t(u32, outer, READ_ONCE(lower->mtu));
	return ft_mtu_less(outer, rule->out_tunnel.header_size);
}

/* The session and tunnel header a direction's ingress takes off before the
 * packet reaches the bound its path is measured against. */
static unsigned int ft_rule_stripped(const struct cdx_ft_rule *rule)
{
	return (rule->in_session.present ? PPPOE_SES_HLEN : 0) +
	       (rule->in_tunnel.present ? rule->in_tunnel.header_size : 0);
}

/* The largest packet a direction arriving on @in through physical port @port
 * may be handed once its ingress has taken @stripped bytes of session and
 * tunnel header off: whichever is larger of the logical device's MTU and what
 * the port's MAC accepts (ft_port_arriving()) less the same stripping. The
 * logical device can be the smaller -- a 1500-byte bridge or VLAN over a
 * 9000-byte port still receives 9000-byte frames -- and a tunnel device's MTU
 * says nothing about the outer packets its port receives. The MTU bound and
 * its refusal ahead of admission both measure a path against this, so the two
 * cannot disagree about what arrives. */
static u32 ft_arriving(const struct net_device *in, const struct net_device *port,
		       unsigned int stripped)
{
	return max_t(u32, READ_ONCE(in->mtu), ft_port_arriving(port) - stripped);
}

/* Whether a direction leaving by a path of @mtu can be carried although a
 * packet arriving on @in could be larger. The microcode fragments an oversized
 * packet itself, and for a frame an Ethernet port received, the fragments it
 * builds carry the headers but not the payload: measured on the DK, every
 * payload byte of every fragment is zero, whatever the memory the buffers sit
 * in and with no VSP on the port. Into a 6in4 tunnel it is the outer IPv4
 * packet it fragments, the IPv6 one inside lost with it. The one packet it
 * hands to Linux instead is IPv4 with DF set, for the ICMP; nothing makes it
 * hand over IPv6 -- PREEMPT_DFBIT_HONOR and the fragmenter's DF action were
 * both tried on the board -- so an oversized IPv6 packet would never get the
 * Packet Too Big Linux sends. Any direction into a smaller path therefore
 * stays in software, where Linux fragments IPv4 and answers IPv6 with Packet
 * Too Big, with two exceptions. A TCP direction stays in hardware: a PPPoE or
 * tunnel uplink clamps its MSS, and IPv4 TCP sets DF besides; an IPv6 segment
 * over the clamp from a host that ignores it would be lost. And an IPv4
 * direction to or from SEC: its enqueue to SEC fragments nothing, and what SEC
 * returns is fragmented on the offline port, where the microcode's fragments
 * are whole and an IPv4 router may make them. An IPv6 one is not exempt: out of
 * SEC the offline port would fragment the decrypted IPv6 packet itself, which
 * no router may do.
 *
 * What may arrive is bounded by the ingress port's MAC rather than by what
 * the link tells its hosts (ft_arriving()): the port takes whatever its own
 * MTU allows, never less than a full Ethernet frame, and a host that ignores
 * a smaller advertised MTU -- DHCP's option for it widely is, and a router
 * advertisement's can be -- or that sits on the port's wider segment keeps
 * sending such frames. The logical and physical ingress and the path are
 * device and route MTUs, whose changes retire the flow through their own
 * events, so admission alone decides. */
static bool ft_mtu_carried(const struct cdx_ft_rule *rule, u32 mtu)
{
	return rule->proto == IPPROTO_TCP ||
	       (rule->family == AF_INET && (rule->sa_handle || rule->in_sa_handle)) ||
	       ft_arriving(rule->in_logical, rule->in, ft_rule_stripped(rule)) <= mtu;
}

static u32 ft_ipv6_dev_mtu(const struct net_device *dev)
{
	struct inet6_dev *idev;
	u32 mtu = 0;

	rcu_read_lock();
	idev = __in6_dev_get(dev);
	if (idev)
		mtu = READ_ONCE(idev->cnf.mtu6);
	rcu_read_unlock();
	return mtu;
}

/* Whether an IPv6 direction's egress still carries the MTU it describes. IPv6
 * forwarding reads an unlocked route's MTU from its device's IPv6 MTU
 * (ip6_dst_mtu_maybe_forward()), a sysctl whose writes no notifier reports,
 * so lowering it leaves an entry forwarding what Linux would answer with
 * Packet Too Big. Raising it needs nothing: the entry stays bounded by what it
 * was admitted with. A locked route MTU ignores the sysctl and changes through
 * a route event, and IPv4 has no such sysctl, so only an unlocked IPv6 route
 * follows its device. Its MTU is never above the device's when Linux creates
 * the flow, so a retired flow comes back carried and nothing loops. Checked at
 * admission, since Linux's flow keeps the MTU it was created with and the
 * sysctl may have dropped since, and on every stats pass and re-offer. */
static bool ft_egress_mtu_current(const struct cdx_ft_rule *rule)
{
	return !rule->mtu_follows_dev || ft_ipv6_dev_mtu(rule->out_logical) >= rule->mtu;
}

/* Whether the decoder is certain to refuse this offer on its MTU bound, decided
 * from the request alone and before RTNL. Linux offers a flow again about once
 * a second for as long as software forwards any of it, so a direction the bound
 * keeps out keeps coming back while it carries traffic -- on a PPPoE uplink
 * that is every UDP upload -- and each offer would otherwise take RTNL and
 * walk the whole path only to be refused again.
 *
 * Only a refusal that holds whatever the walk would find is made here. The
 * ingress device is the reverse destination's and the physical port @port the
 * one the offer is bound to, exactly as the decoder takes them. The bound is
 * taken with the most any ingress can strip -- a session and an IPv6 outer
 * header, the larger of the two tunnel modes' -- which is where it is lowest. And
 * no transform may be in reach: neither destination carries one and no
 * policy or blocking default is configured, so every lookup
 * ft_ipsec_handle() makes returns the plain route. No SA can then exempt the
 * direction, and no policy can deny it -- a denial retires the whole
 * generation, which a refusal here would otherwise skip. A socket's own
 * policy is not one of those: it never governs a forwarded packet, and
 * neither the lookups nor xfrm_flowtable_policy_check() consult it. Everything
 * that passes still meets the exact bound in the decoder. */
static bool ft_mtu_refused(const struct flow_cls_offload *cls, const struct net_device *port)
{
	struct flow_rule *rule = cls->rule;
	struct flow_match_basic basic;
	struct net_device *in;
	bool refused;

	if (!rule || !cls->nf_dst || !cls->nf_dst_reverse ||
	    !(rule->match.dissector->used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_BASIC)) ||
	    dst_xfrm(cls->nf_dst) || dst_xfrm(cls->nf_dst_reverse) ||
	    !xfrm_flowtable_enabled(&init_net))
		return false;
	flow_rule_match_basic(rule, &basic);
	if (basic.mask->n_proto != htons(0xffff) || basic.mask->ip_proto != 0xff)
		return false;
	/* Without RTNL the destination's device can be swapped for the
	 * blackhole one while its own unregisters; the device read here stays
	 * valid until the grace period unregistration waits for. */
	rcu_read_lock();
	in = READ_ONCE(cls->nf_dst_reverse->dev);
	refused = (basic.key->n_proto == htons(ETH_P_IP) ||
		   basic.key->n_proto == htons(ETH_P_IPV6)) &&
		  basic.key->ip_proto != IPPROTO_TCP &&
		  ft_arriving(in, port, PPPOE_SES_HLEN + sizeof(struct ipv6hdr)) > cls->nf_mtu;
	if (refused)
		ask_dbg(ASK_DBG_DEVICE, "proto %u mtu %u below ingress %s before RTNL\n",
			basic.key->ip_proto, cls->nf_mtu, netdev_name(in));
	rcu_read_unlock();
	return refused;
}

static bool ft_tunnel_inbound_allowed(const struct cdx_ft_tunnel *tunnel)
{
	struct flowi flow = {};

	if (!tunnel->present)
		return true;
	/* Decapsulation receives a plaintext outer packet. A policy requiring
	 * transport ESP, a block or a blocking default cannot be bypassed by
	 * a hardware inner-tuple hit. The normal policy generation check also
	 * retires this direction when that answer changes. */
	if (tunnel->family == AF_INET6) {
		flow.u.ip6.saddr = tunnel->remote.in6;
		flow.u.ip6.daddr = tunnel->local.in6;
		flow.u.ip6.flowi6_proto = tunnel->proto;
		flow.u.ip6.flowi6_iif = tunnel->lower_ifindex;
		flow.u.ip6.flowi6_oif = LOOPBACK_IFINDEX;
	} else {
		flow.u.ip4.saddr = tunnel->remote.ip;
		flow.u.ip4.daddr = tunnel->local.ip;
		flow.u.ip4.flowi4_proto = tunnel->proto;
		flow.u.ip4.flowi4_iif = tunnel->lower_ifindex;
		flow.u.ip4.flowi4_oif = LOOPBACK_IFINDEX;
	}
	return xfrm_flowtable_in_plain(&init_net, &flow, tunnel->family);
}

static bool ft_bridge_egress_filtered(const struct cdx_ft_rule *rule)
{
	return rule->out_bridge &&
	       ft_bridge_hooked(BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING));
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
	u32 mark, mtu;
	u8 policer;
	static const u32 offsets[4] = { 4, 8, 0, 4 };
	static const u32 masks[4] = { 0x0000ffff, 0, 0, 0xffff0000 };
	u8 ethernet[12] = {};
	u8 family;
	u32 word;
	int i, vlans;

	if (!rule)
		return ask_refuse(-EOPNOTSUPP);
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
		return ask_refuse(-EOPNOTSUPP);
	keys = family == AF_INET6 ? keys6 : keys4;
	if (!cls->nf_ct)
		return ask_refuse(-EOPNOTSUPP);
	/* Sampled once: the admission test below and the class derived further
	 * down have to describe the same mark, or a concurrent change could
	 * install a class taken from a value that would not have been admitted. */
	mark = READ_ONCE(cls->nf_ct->mark);
	/* A counter-enabled table is admitted: the consumer's firewall declares
	 * one unconditionally, and ft_stats() restates the hardware delta in
	 * Netfilter's own units rather than refusing every flow over framing. */
	if (!cls->nf_mtu ||
	    !nf_flow_offload_handle_valid(cls->nf_handle) ||
	    !net_eq(nf_ct_net(cls->nf_ct), &init_net) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_ORIGINAL) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_REPLY) ||
	    /* Outside the classification mask the mark still means something
	     * this adapter cannot honour, so it still refuses. With no mask
	     * configured that is every mark, exactly as before. */
	    (mark & ~ft_qos_mark_mask) ||
	    cls->common.chain_index || cls->common.protocol != ETH_P_ALL)
		return ask_refuse(-EOPNOTSUPP);
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
		return ask_refuse(-EOPNOTSUPP);
	memset(out, 0, sizeof(*out));
	out->family = family;
	if (family == AF_INET6) {
		flow_rule_match_ipv6_addrs(rule, &ipv6);
		if (!ft_exact6(&ipv6.mask->src) || !ft_exact6(&ipv6.mask->dst))
			return ask_refuse(-EOPNOTSUPP);
		out->src.in6 = ipv6.key->src;
		out->dst.in6 = ipv6.key->dst;
	} else {
		flow_rule_match_ipv4_addrs(rule, &ipv4);
		if (ipv4.mask->src != htonl(0xffffffff) || ipv4.mask->dst != htonl(0xffffffff))
			return ask_refuse(-EOPNOTSUPP);
		out->src.ip = ipv4.key->src;
		out->dst.ip = ipv4.key->dst;
	}
	if (!ft_endpoint(family, &out->src) || !ft_endpoint(family, &out->dst))
		return ask_refuse(-EOPNOTSUPP);
	out->sport = ports.key->src;
	out->dport = ports.key->dst;
	out->proto = basic.key->ip_proto;
	/* Four Ethernet mangles and a redirect are the shortest admissible
	 * action list. Resolve the devices before the translation, because the
	 * encapsulation they imply decides where every later action sits; from
	 * there the exact count ft_translation requires bounds each index. */
	if (rule->action.num_entries < 5)
		return ask_refuse(-EOPNOTSUPP);
	action = &rule->action.entries[rule->action.num_entries - 1];
	if (action->id != FLOW_ACTION_REDIRECT || !cdx_ft_egress_supported(action->dev) ||
	    !cdx_ft_port_supported(binding->dev) || !cls->nf_dst || !cls->nf_dst_reverse) {
		/* The one gate worth naming its operands rather than just its
		 * line: six conditions, and which failed is the whole
		 * question. */
		ask_dbg(ASK_DBG_DEVICE,
			"gate redirect=%d out=%s egress_ok=%d in=%s in_ok=%d dst=%d rdst=%d\n",
			action->id == FLOW_ACTION_REDIRECT,
			action->dev ? netdev_name(action->dev) : "(null)",
			action->dev ? cdx_ft_egress_supported(action->dev) : -1,
			binding->dev ? netdev_name(binding->dev) : "(null)",
			binding->dev ? cdx_ft_port_supported(binding->dev) : -1,
			!!cls->nf_dst, !!cls->nf_dst_reverse);
		return ask_refuse(-EOPNOTSUPP);
	}
	out->in = binding->dev;
	out->out = action->dev;
	/* This direction's destination names the device it leaves by; the
	 * reverse direction's names the device it arrives on. Requiring each
	 * to reach its physical port through VLAN devices alone is what ties
	 * the borrowed destinations to the redirect and the binding. Both
	 * destinations must be present so each logical path can be validated. */
	out->out_logical = cls->nf_dst->dev;
	out->in_logical = cls->nf_dst_reverse->dev;
	/* The two sessions are named the way the two destinations are: the one
	 * paired with this direction's destination is what it inserts, and the
	 * one paired with the reverse destination is what it strips. */
	vlans = ft_path_stack(out->out_logical, out->out, cls->nf_session,
			      cls->nf_tunnel, out->out_vlan, &out->out_bridge,
			      &out->out_bridge_vid, &out->out_session,
			      &out->out_tunnel);
	if (vlans < 0)
		return vlans;
	out->out_vlans = vlans;
	vlans = ft_path_stack(out->in_logical, out->in, cls->nf_session_reverse,
			      cls->nf_tunnel_reverse, out->in_vlan, &out->in_bridge,
			      &out->in_bridge_vid, &out->in_session, &out->in_tunnel);
	if (vlans < 0)
		return vlans;
	out->in_vlans = vlans;
	if (ft_bridge_egress_filtered(out) || !ft_tunnel_inbound_allowed(&out->in_tunnel))
		return ask_refuse(-EOPNOTSUPP);
	/* A tunnel carries one family inside the other, and the mode the device
	 * decided has to be the one the flow's family asks for: a sit device
	 * with an IPv4 flow through it is IPv4 in IPv4, which the hardware does
	 * not build, and an ip6tnl device in "any" mode carrying IPv6 is IPv6
	 * in IPv6, which it does not build either. */
	if ((out->out_tunnel.present &&
	     out->out_tunnel.mode != (family == AF_INET6 ? CDX_FT_TUNNEL_6O4 :
				      CDX_FT_TUNNEL_4O6)) ||
	    (out->in_tunnel.present &&
	     out->in_tunnel.mode != (family == AF_INET6 ? CDX_FT_TUNNEL_6O4 :
				     CDX_FT_TUNNEL_4O6)))
		return ask_refuse(-EOPNOTSUPP);
	/* The Ethernet source a neighbour-output flow carries is the physical
	 * port's, and the encoder caches exactly one address per port. A logical
	 * device that does not share that address would have software emit one
	 * source MAC and hardware another for the same flow, so it is declined
	 * rather than left silently divergent. A VLAN device normally inherits
	 * its parent's address; a bridge normally takes its lowest port's, so
	 * this also decides which ports of a multi-port bridge are eligible.
	 * A ppp device has no address at all -- addr_len is zero -- so where a
	 * session is present the same rule is imposed by the walk, on the
	 * device below it, which is the one that does have one. A tunnel
	 * device's address is its local IP address, so the same applies. */
	if (!out->out_session.present && !out->out_tunnel.present &&
	    !ether_addr_equal(out->out_logical->dev_addr, out->out->dev_addr))
		return ask_refuse(-EOPNOTSUPP);
	if (out->out_tunnel.present && !out->out_session.present) {
		struct net_device *lower = __dev_get_by_index(
			&init_net, out->out_tunnel.lower_ifindex);

		if (!lower || !ether_addr_equal(lower->dev_addr, out->out->dev_addr))
			return ask_refuse(-EOPNOTSUPP);
	}
	/* Re-entering the port a frame arrived on is a hairpin, and needs full
	 * NAT to be a distinct path -- unless the two stacks differ, which is
	 * ordinary routing between VLANs carried on one trunk, or the two
	 * sessions do, which is the same thing one layer down, or the two
	 * tunnels do, one layer up. */
	if (out->out == out->in && out->out_vlans == out->in_vlans &&
	    ft_same_tags(out->out_vlan, out->in_vlan, out->in_vlans) &&
	    out->out_session.present == out->in_session.present &&
	    out->out_tunnel.present == out->in_tunnel.present &&
	    (READ_ONCE(cls->nf_ct->status) & IPS_NAT_MASK) != IPS_NAT_MASK)
		return ask_refuse(-EOPNOTSUPP);
	if (!ft_translation(cls, out))
		return ask_refuse(-EOPNOTSUPP);
	/* Each direction is admitted as its own rule, so this is already a
	 * per-direction class even though both directions read one mark. The
	 * channel nibble is normally zero, which resolves to whichever channel
	 * the egress port owns, so one class index means "this priority, on
	 * whatever port this direction leaves by". A class the hardware cannot
	 * express declines the flow to software rather than guessing a queue. */
	out->qos = ft_qos_class(mark);
	if (!ft_qos_class_valid(out->qos))
		return ask_refuse(-EOPNOTSUPP);
	switch (basic.key->ip_proto) {
	case IPPROTO_TCP:
		if (used != (keys | BIT_ULL(FLOW_DISSECTOR_KEY_TCP)) ||
		    !nf_conntrack_tcp_established(cls->nf_ct))
			return ask_refuse(-EOPNOTSUPP);
		flow_rule_match_tcp(rule, &tcp);
		/* cdx_sp.xml punts SYN/FIN/RST before TCP hash lookup. Accept
		 * precisely Netfilter's FIN/RST exclusion; never discard an
		 * additional selector which that parser cannot enforce. */
		if (tcp.key->flags || tcp.mask->flags != htons(TCPHDR_FIN | TCPHDR_RST))
			return ask_refuse(-EOPNOTSUPP);
		break;
	case IPPROTO_UDP:
		if (used != keys)
			return ask_refuse(-EOPNOTSUPP);
		break;
	default:
		return ask_refuse(-EOPNOTSUPP);
	}
	/* Bounded by the tag count the devices produced, which is the only
	 * thing that makes these reads meaningful: the keys are never in
	 * used_keys, so nothing about them can be established from the set
	 * compared above. A tag the devices found but Netfilter did not
	 * describe leaves the dissector offset at zero, and the meta key
	 * living there carries an all-ones ingress mask, which fails the
	 * priority and DEI test below rather than being read as a tag. */
	if (!ft_vlan_match(rule, out))
		return ask_refuse(-EOPNOTSUPP);
	for (i = 0; i < 4; i++) {
		action = &rule->action.entries[i];
		if (action->id != FLOW_ACTION_MANGLE ||
		    action->mangle.htype != FLOW_ACT_MANGLE_HDR_TYPE_ETH ||
		    action->mangle.offset != offsets[i] || action->mangle.mask != masks[i] ||
		    (action->mangle.val & masks[i]))
			return ask_refuse(-EOPNOTSUPP);
		memcpy(&word, ethernet + offsets[i], sizeof(word));
		word = (word & masks[i]) | action->mangle.val;
		memcpy(ethernet + offsets[i], &word, sizeof(word));
	}
	/* Neighbours, the borrowed destination and the payload bound all belong
	 * to the logical egress device. The Ethernet source is the physical
	 * port's, because that is the address Netfilter writes for a
	 * neighbour-output flow and the only one the encoder can cache. */
	if (!ft_vlan_actions(&rule->action, out) ||
	    !ft_next_hop(cls, out->out_logical, family, &out->new_dst, next_hop,
			 &out->next_hop_family) ||
	    !ft_ipsec_handle(cls, out, out->out_logical, out->in_logical) ||
	    cls->nf_mtu > out->out_logical->mtu)
		return ask_refuse(-EOPNOTSUPP);
	/* The route's MTU, and no more than the port carries (ft_port_mtu()):
	 * what the bridge would drop above it, the hardware punts or is never
	 * given, as for any path smaller than what may arrive. */
	mtu = min_t(u32, cls->nf_mtu, ft_port_mtu(out));
	if (mtu < (family == AF_INET6 ? IPV6_MIN_MTU : 68))
		return ask_refuse(-EOPNOTSUPP);
	if (!ft_mtu_carried(out, mtu)) {
		ask_dbg(ASK_DBG_DEVICE, "family %u proto %u mtu %u below ingress %s\n",
			family, out->proto, mtu, netdev_name(out->in_logical));
		return ask_refuse(-EOPNOTSUPP);
	}
	/* A tunnel inside a transform, or a transform inside a tunnel, is a
	 * header order nothing here proves. The walk already refuses an outer
	 * packet a policy would transform; this refuses an inner one. */
	if ((out->out_tunnel.present || out->in_tunnel.present) &&
	    (out->sa_handle || out->in_sa_handle))
		return ask_refuse(-EOPNOTSUPP);
	/* What Netfilter writes into the four mangle words is the neighbour of
	 * the device the route leaves by, and that is the outermost one the
	 * walk took: the tunnel where there is one, else the ppp device. Each
	 * is required exactly, rather than ignored, so a kernel that started
	 * resolving something else there is not silently overridden.
	 *
	 * A tunnel device is NOARP, but unlike a ppp device it has header ops
	 * and an address -- its local IP address, four or sixteen bytes -- and
	 * for such a device ndisc_constructor() and arp_constructor() both copy
	 * that address into the neighbour's hardware address. So the words are
	 * the tunnel's own local address, zero-padded to six bytes. */
	if (out->out_tunnel.present) {
		u8 own[ETH_ALEN] = {};

		memcpy(own, out->out_logical->dev_addr,
		       min_t(unsigned int, out->out_logical->addr_len, ETH_ALEN));
		if (memcmp(ethernet, own, ETH_ALEN))
			return ask_refuse(-EOPNOTSUPP);
	}
	if (out->out_session.present) {
		/* A ppp device resolves no Ethernet destination: its NOARP
		 * neighbour, the one arp_constructor() builds, carries the zero
		 * address a device with no address length leaves behind. So
		 * with no tunnel above it the words must be that zero, and
		 * either way the real destination is the concentrator the
		 * session names: a tunnel's outer packet over the session is
		 * addressed to it as well. */
		if (!out->out_tunnel.present && !is_zero_ether_addr(ethernet))
			return ask_refuse(-EOPNOTSUPP);
		ether_addr_copy(out->dst_mac, out->out_session.mac);
	} else if (out->out_tunnel.present) {
		struct net_device *lower = __dev_get_by_index(
			&init_net, out->out_tunnel.lower_ifindex);

		/* The destination is the outer next hop the walk resolved on
		 * the device below, checked against that device's neighbour as
		 * a routed flow's is checked against its own.
		 *
		 * Unlike a routed flow's, that address is recorded once, when
		 * Linux creates the flow, and no later offer of the same
		 * generation carries a newer one. A neighbour that is usable
		 * but has moved to another address therefore never matches
		 * again for this generation: it is stale the way a changed
		 * source address is, and retires the generation so that the
		 * next one walks the path afresh. */
		if (!lower)
			return ask_refuse(-EOPNOTSUPP);
		if (!ft_neigh_check(out->out_tunnel.family, lower,
				    &out->out_tunnel.nexthop, out->out_tunnel.mac))
			return ask_refuse(ft_neigh_moved(out->out_tunnel.family, lower,
							 &out->out_tunnel.nexthop,
							 out->out_tunnel.mac) ?
					  -ESTALE : -EOPNOTSUPP);
		ether_addr_copy(out->dst_mac, out->out_tunnel.mac);
	} else {
		if (!is_valid_ether_addr(ethernet) ||
		    !ft_neigh_check(out->next_hop_family, out->out_logical, next_hop,
				    ethernet))
			return ask_refuse(-EOPNOTSUPP);
		ether_addr_copy(out->dst_mac, ethernet);
	}
	if (!ether_addr_equal(ethernet + ETH_ALEN, out->out->dev_addr))
		return ask_refuse(-ESTALE);
	out->mtu = mtu;
	out->mtu_follows_dev = family == AF_INET6 && !dst_metric_locked(cls->nf_dst, RTAX_MTU);
	if (!ft_egress_mtu_current(out)) {
		/* Retired rather than only refused, so Linux makes the flow again
		 * with the MTU its egress carries now. */
		ft_handle_invalidate(cls->nf_handle, &ft_mtu_invalidations);
		return ask_refuse(-EOPNOTSUPP);
	}
	ether_addr_copy(out->src_mac, ethernet + ETH_ALEN);
	/* Last, because a tc police filter is matched against the finished
	 * tuple. A filter is the more specific statement of the same intent as
	 * the mark, so where one claims this flow its profile replaces the
	 * mark's nibble; with none, the mark's stands.
	 *
	 * Resolved into the rule rather than further down, so that the rule is
	 * what the hardware is given *and* what /proc reports. Doing it below
	 * left the two disagreeing: a policed flow metered against the filter's
	 * profile while the row said qos=000. */
	policer = cdx_police_lookup(out);
	if (policer)
		out->qos = (out->qos & ~CDX_FT_QOS_POLICER_MASK) |
			   (policer << CDX_FT_QOS_POLICER_SHIFT);
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
	u64 ipsec_genid = atomic64_read_acquire(&ft_ipsec_genid);
	union nf_inet_addr next_hop;
	int rc;

	/* A delayed request must never replace a different flow generation
	 * merely because its opaque directional cookie has the same value. */
	if (entry && entry->handle != cls->nf_handle)
		return ask_refuse(-ESTALE);
	/* An invalid generation is refused by the parse below. */
	ft_offer_current(cls);
	rc = ft_parse(binding, cls, &rule, &next_hop);
	if (rc == -ESTALE)
		ft_handle_invalidate(cls->nf_handle, &ft_mac_invalidations);
	if (!rc)
		ft_validated++;
	if (rc || cdx_ft_observing() || atomic_read(&ft_invalid) || ft_stopping || cdx_ft_failed()) {
		/* Four latches and a parse result behind one return. A flow
		 * that parsed cleanly and dies here died for a reason that has
		 * nothing to do with the flow, which is worth distinguishing
		 * from one the decoder refused. */
		ask_dbg(ASK_DBG_DEVICE,
			"replace parse=%d observe=%d invalid=%d stopping=%d failed=%d\n",
			rc, cdx_ft_observing(), atomic_read(&ft_invalid),
			ft_stopping, cdx_ft_failed());
		if (entry)
			ft_remove(entry);
		return ask_refuse(rc ? rc : -EOPNOTSUPP);
	}
	if (entry) {
		if (nf_inet_addr_cmp(&entry->next_hop, &next_hop) &&
		    !memcmp(&entry->rule, &rule, sizeof(rule)))
			return 0;
		rc = ft_remove(entry);
		if (rc)
			return ask_refuse(rc);
	}
	hash_for_each_possible(ft_keys, other, key_node, ft_key_hash(&rule))
		if (ft_same_key(&other->rule, &rule))
			return ask_refuse(-EEXIST);
	if (ft_count >= CDX_FT_MAX_ENTRIES)
		return ask_refuse(-ENOSPC);
	if (ft_fault(1))
		return ask_refuse(-ENOMEM);
	/* The backend admits nothing while a retirement is unproven, and one
	 * whose barrier is merely owed is that until it is asked for. */
	if (ft_settle())
		return ask_refuse(-EAGAIN);
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ask_refuse(-ENOMEM);
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
	/* Before the watch list can see the entry, so an event on any of them
	 * finds it from the moment it is published. */
	ft_crossed_hold_all(entry);
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
		ft_crossed_put_all(entry);
		kfree(entry);
		return ask_refuse(rc);
	}
	list_add_tail(&entry->list, &ft_entries);
	hash_add(ft_cookies, &entry->cookie_node,
		 entry->cookie ^ (unsigned long)entry->binding);
	hash_add(ft_keys, &entry->key_node, ft_key_hash(&entry->rule));
	ft_count++;
	ft_installs++;
	/* An SA may expire before this entry joins the dependency watch. */
	if (ipsec_genid != atomic64_read_acquire(&ft_ipsec_genid))
		ft_handle_invalidate(cls->nf_handle, &ft_ipsec_invalidations);
	/* IPv6 commits routes from softirq without RTNL, so a change between
	 * the validation above and publication here reaches neither: the entry
	 * was not yet watched, and RTNL did not exclude it. Recheck once the
	 * notifier can see this entry; an invalid handle then retires it below
	 * through the same path as a change observed during insertion. */
	ft_offer_current(cls);
	if (ft_fault(3) || atomic_read(&ft_invalid) ||
	    !nf_flow_offload_handle_valid(entry->handle)) {
		ft_remove(entry);
		return -EIO;
	}
	/* Watched, and current after it: from here a policy change retires
	 * this generation only if it can select one of its directions, and
	 * Linux leaves the rest to the walk rather than retiring the flow on a
	 * generation that any policy anywhere moves on. */
	nf_flow_offload_handle_watch(cls->nf_handle);
	return 0;
}

/* What the hardware's byte counter includes and Netfilter's does not.
 *
 * A classifier hit counts the frame as it arrived: Ethernet header, every tag
 * above it, and a PPPoE session header, padded to the medium's minimum and
 * without the FCS. Netfilter counts skb->len where it forwards, which is after
 * nf_flow_encap_pop() has removed exactly that stack. Reporting a hardware
 * delta into conntrack accounting without this subtraction adds a constant to
 * every frame of every flow.
 *
 * Ingress framing only: an egress tag or session is pushed after the hit was
 * counted, and the reverse direction is a hardware entry of its own.
 *
 * Padding is not recoverable and is not corrected for. It is invisible in a
 * total, so a flow whose frames fall below the sixty-byte minimum still reads
 * high by what was padded -- at most ten bytes on the frames that carry the
 * least. Frames punted to Linux have also been counted here and counted again
 * by the slow path that handled them; that is bounded by exception traffic,
 * which is zero on a healthy flow. Both residuals are documented in
 * docs/flowtable/architecture.md rather than silently absorbed.
 */
static unsigned int ft_l2_overhead(const struct cdx_ft_rule *rule)
{
	/* The post-SEC hit sees the decrypted packet with only Ethernet and
	 * the internal identity VLAN. Ingress encapsulation was removed on
	 * the way to SEC; do not charge it or the shim to conntrack. */
	if (rule->in_sa_handle)
		return ETH_HLEN + VLAN_HLEN;
	/* An ingress tunnel's outer header is stripped before the inner packet
	 * is what Netfilter would count, so it is framing here too, one layer
	 * up. A peer that adds an encapsulation-limit option to its IPv6 outer
	 * header sends eight bytes more than this, which is not recoverable
	 * per frame and is documented rather than guessed at. */
	return ETH_HLEN + rule->in_vlans * VLAN_HLEN +
	       (rule->in_session.present ? PPPOE_SES_HLEN : 0) +
	       (rule->in_tunnel.present ? rule->in_tunnel.header_size : 0);
}

/* Recheck admission conditions with no device notification on every offer
 * and stats pass. Needs no RTNL: the entry holds its devices and hook lookup
 * uses RCU. Retiring the generation also prevents its sibling keeping it alive. */
static bool ft_entry_bounded(struct cdx_ft_entry *entry)
{
	if (ft_bridge_egress_filtered(&entry->rule)) {
		ft_handle_invalidate(entry->handle, &ft_admission_invalidations);
		return false;
	}
	if (!ft_egress_mtu_current(&entry->rule)) {
		ft_handle_invalidate(entry->handle, &ft_mtu_invalidations);
		return false;
	}
	return true;
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
	if (!ft_entry_bounded(entry))
		return -EOPNOTSUPP;
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
	/* Restate the delta in the units Netfilter counts in. Saturate rather
	 * than wrap: a delta that cannot carry its own framing describes frames
	 * this adapter cannot account for, and zero is the honest answer. */
	bytes -= min_t(u64, bytes, packets * ft_l2_overhead(&entry->rule));
	if (!ft_neigh_used(entry, packets != 0))
		return -EOPNOTSUPP;
	/* These are classifier hits, so a frame punted after its hit has been
	 * counted here and counted again by the path that handled it. Linux uses
	 * lastused for ageing; proc exposes the raw hardware counters for
	 * diagnostics, separately from what is reported into accounting. */
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

/* Whether Linux will offer this direction again on its own. flow_offload_refresh()
 * does, at most about once a second, for as long as the software fast path
 * forwards the direction's packets: it queues the whole flow, and
 * flow_offload_work_add() offers both directions. The normal stack never offers
 * a flow that already exists, so a direction whose packets never reach the
 * fast path is never offered again by its own traffic. Two kinds never do:
 *
 * - every direction, while any xfrm policy or a default other than accept is
 *   configured: nf_flow_offload_ip_hook() and its IPv6 twin then hand every
 *   packet of a table with hardware handles to the normal stack;
 * - one that arrives through a tunnel. For a table with neighbour output its
 *   tuple names the port below the tunnel, where the fast path sees only the
 *   outer packet and cannot parse it, and the inner packet the tunnel device
 *   delivers arrives on a device the tuple does not name.
 *
 * The second is offered again only by its sibling's software traffic, which
 * stops the moment the sibling is in hardware; and in either case it is then
 * the sibling's hardware counters that keep the generation alive. */
static bool ft_software_reoffers(const struct flow_cls_offload *cls)
{
	return xfrm_flowtable_enabled(&init_net) && cls->nf_tunnel_reverse &&
	       !cls->nf_tunnel_reverse->lower_ifindex;
}

/* Whether an offer names a direction this generation already has in hardware,
 * with no global latch pending. Such an offer is answered without RTNL and
 * without a new walk, because nothing it describes can have changed without
 * something else retiring the entry first. Its rule comes from the flow's tuple,
 * destinations, session and tunnel records and MTU, all fixed for the
 * generation; what those resolve through -- routes, neighbours, a device's MTU,
 * address, link and uppers, bridge forwarding state, tunnel parameters, egress
 * queues, SAs -- retires the generation through its own event, as it has to for
 * a fully offloaded flow, which is never offered again at all. The conntrack
 * mark and a police filter are sampled once, at admission, which is all a fully
 * offloaded flow ever gets of them either. The routes ft_replace() checks
 * ahead of any parse still apply, through ft_offer_routes_current(), as do the
 * admission conditions no event reports, through ft_entry_bounded(). The
 * policy generation does not: the offer carries the flow's creation one, and
 * the watch the entry joined at publication answers for policy instead. */
static bool ft_offer_installed(const struct cdx_ft_entry *entry,
			       const struct flow_cls_offload *cls)
{
	return entry && entry->handle == cls->nf_handle &&
	       nf_flow_offload_handle_valid(cls->nf_handle) && !cdx_ft_observing() &&
	       !atomic_read(&ft_invalid) && !ft_stopping && !cdx_ft_failed();
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
	/* Linux deletes one flow per work item, from an unbound workqueue
	 * that runs up to 256 of them at once, and a route change or a
	 * conntrack flush queues one for every flow. Each waiting for the
	 * transaction put hundreds of workers to sleep behind whatever held
	 * it (A327). A deletion that finds it held retires the generation
	 * instead, as a dependency change does: the handle is marked, the
	 * retirement worker takes the entry out in its next batch, and until
	 * then the entry's cookie refuses a new generation (-ESTALE) rather
	 * than being taken for it. The entry forwards until that batch, as it
	 * did while a deletion waited here for the transaction; what changes
	 * is only that Linux, told the deletion is done, may release its flow
	 * and conntrack first, and a new connection on the same tuple meets
	 * the old entry until the batch -- for no longer than the wait was. */
	if (cls->command == FLOW_CLS_DESTROY && !cdx_ft_trybegin()) {
		ft_destroy_defer(binding, cls);
		return 0;
	}
	if (cls->command != FLOW_CLS_DESTROY)
		cdx_ft_begin();
	entry = ft_find(binding, cls->cookie);
	if (entry && entry->handle != cls->nf_handle)
		entry = NULL;
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		/* Native work offers each direction to every bound port. The
		 * other ports' visits are not refusals, so they are neither
		 * counted nor allowed near RTNL. */
		if (!ft_request_targets(binding, cls)) {
			rc = -EOPNOTSUPP;
			break;
		}
		/* Linux re-offers a flow while software forwards any part of
		 * it, installed half included, so the offers that cannot change
		 * anything are answered first, without RTNL: a direction already
		 * installed, one whose MTU bound is certain to refuse it, and one
		 * a full table would refuse.
		 *
		 * Never wait for RTNL here: device teardown under RTNL may be
		 * flushing this workqueue. An offer that cannot take it retires
		 * nothing while software will offer the direction again -- it
		 * stays on the software path until the next offer, and whatever
		 * is already installed stays installed. Where nothing will (see
		 * ft_software_reoffers()) an installed direction would keep the
		 * generation alive from hardware alone; retire it, so that
		 * fresh traffic retries both directions after native GC. */
		if (ft_offer_installed(entry, cls)) {
			rc = ft_offer_routes_current(cls) && ft_entry_bounded(entry) ?
			     0 : ask_refuse(-EOPNOTSUPP);
		} else if (!entry && ft_mtu_refused(cls, binding->dev)) {
			rc = ask_refuse(-EOPNOTSUPP);
		} else if (!entry && ft_count >= CDX_FT_MAX_ENTRIES &&
			   ft_software_reoffers(cls)) {
			/* A full table refuses whatever the walk finds, and a
			 * direction software keeps offering would otherwise take
			 * RTNL and walk its path every second until a slot frees.
			 * One nothing offers again goes on to admission, where a
			 * key its previous generation still holds retires it
			 * before capacity refuses it. */
			rc = ask_refuse(-ENOSPC);
		} else if (binding->parked) {
			/* Declined without touching the flow: its handle stays
			 * valid, so Netfilter offers it again -- on its next
			 * refresh, or, while an XFRM policy keeps the software fast
			 * path out of use, once it expires and is added afresh --
			 * and once ft_rearm() has made this binding live that offer
			 * is admitted with no reload. */
			rc = -EOPNOTSUPP;
		} else if (ft_admission_fault(cls) || cdx_ft_admission_begin()) {
			ft_busy++;
			if (!ft_software_reoffers(cls) && !cdx_ft_observing() && !ft_stopping &&
			    !atomic_read(&ft_invalid) && !cdx_ft_failed())
				ft_handle_invalidate(cls->nf_handle, &ft_admission_invalidations);
			rc = -EAGAIN;
		} else {
			rc = ft_replace(binding, cls);
			/* Two more refusals can clear by themselves, and each is
			 * retried by retiring only this generation, so native GC
			 * permits a fresh admission.
			 *
			 * An allocation failure always: memory pressure is when
			 * a retry is least likely to succeed a second later, and
			 * where nothing offers the direction again its installed
			 * sibling would otherwise hold the generation from
			 * hardware alone.
			 *
			 * A hardware key another generation of the connection
			 * still holds, where nothing offers the direction again:
			 * Linux queues the old generation's removal on another
			 * workqueue than this offer, and it is gone within a GC
			 * pass. Where software re-offers it, that suffices.
			 *
			 * Capacity is not retried this way: the readmission would
			 * compete for the same full table, and the direction that
			 * holds a slot is worth more than a flow churning in and
			 * out of it. Nor is a neighbour this adapter cannot use.
			 * For a routed direction Linux builds neither direction's
			 * rule unless that neighbour is valid, so what reaches
			 * here is a change racing the offer or a state this
			 * adapter never accepts, and retiring on the latter would
			 * readmit forever. A tunnel's egress is the exception:
			 * Linux resolves only the tunnel device's own NOARP
			 * neighbour, and the outer next hop this adapter checks
			 * may still be resolving. That refusal waits for the next
			 * offer, which software makes unless a policy is
			 * configured; an outer neighbour that resolved to another
			 * address than the walk recorded has already retired the
			 * generation in the parse. */
			if (rc == -ENOMEM || (rc == -EEXIST && !ft_software_reoffers(cls)))
				ft_handle_invalidate(cls->nf_handle, &ft_admission_invalidations);
			cdx_ft_admission_end();
		}
		if (rc)
			ft_rejects++;
		break;
	case FLOW_CLS_DESTROY:
		/* Linux deletes one flow per callback, and one route change can
		 * delete the whole table: the deletions queued behind each other
		 * share a barrier, at most FT_RETIRE_BATCH unlinks to one, and
		 * the last of a burst leaves it to ft_settle_work -- unless an
		 * unload, which set ft_stopping under this transaction, may
		 * already have cancelled that work for good. */
		rc = entry ? ft_unlink(entry) : 0;
		if (cdx_ft_owed() >= FT_RETIRE_BATCH || ft_stopping)
			ft_settle();
		else if (cdx_ft_owed())
			schedule_work(&ft_settle_work);
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

/* Whether the worker has finished a pass covering every event counted so
 * far, not merely the one that took the latch. */
bool ft_invalid_complete(void)
{
	return ft_invalid_done && ft_done_seq == atomic_read(&ft_invalid_seq);
}

/* Everything an invalidation leaves behind is gone, except perhaps a deletion
 * the hardware has not proven yet: every binding that was live when it was
 * raised has lost its callback, and the worker has finished both hardware
 * retirement and Linux flow cleanup, for every event raised since as well. A
 * parked binding is not one of those -- it was made after the latch and owns
 * no entries. Completion is published as the worker's last action under the
 * backend transaction, so an old worker cannot change a newly admitted table.
 * Never reset the fatal latch or error history.
 */
static bool ft_drained(void)
{
	cdx_ft_assert_held();
	return ft_ready && !ft_stopping && !cdx_ft_failed() &&
		atomic_read(&ft_invalid) && ft_invalid_complete() &&
		ft_bound == ft_parked && !ft_count && !ft_neighbour_refs && !ft_handle_refs;
}

bool ft_can_rearm(void)
{
	return ft_drained() && !cdx_ft_pending();
}

/* Make every parked binding live again, once the invalidation they were parked
 * behind has drained.
 *
 * A consumer that reloads atomically binds its new table while the old one is
 * still bound, so the bind that would once have rearmed admission always finds
 * a live binding in the way. The bind path parks it instead, and this is
 * where it comes back. Each event that can complete the drain calls this under
 * the backend transaction -- the release of the last live binding, the worker
 * publishing completion, and a parking bind itself, which is how the first
 * bind after a full detach still rearms at once -- so admission reopens in the
 * same transaction as the event that allowed it. The parked tables' flows are
 * offered again by their next refresh and enter hardware with no reload.
 *
 * The one condition no adapter event completes is a deletion the hardware has
 * not proven, including one CDX parked for a path of its own. While every
 * binding is parked nothing else retries that barrier, so this does, and comes
 * back every second until it succeeds.
 */
void ft_rearm(void)
{
	struct cdx_ft_binding *binding;

	cdx_ft_assert_held();
	if (!ft_parked || !ft_drained())
		return;
	if (cdx_ft_pending()) {
		cdx_ft_recover();
		if (cdx_ft_pending()) {
			schedule_delayed_work(&ft_rearm_work, HZ);
			return;
		}
	}
	/* Notifiers count events without the transaction. Clear the latch
	 * first and look at the count after: an event counted in between keeps
	 * the latch and the bindings parked for the pass it has queued. */
	atomic_set(&ft_invalid, 0);
	smp_mb();
	if (ft_done_seq != atomic_read(&ft_invalid_seq)) {
		atomic_set(&ft_invalid, 1);
		return;
	}
	list_for_each_entry(binding, &ft_bindings, list)
		binding->parked = false;
	pr_info("cdx flowtable: admission rearmed for %u parked binding%s\n",
		ft_parked, ft_parked == 1 ? "" : "s");
	WRITE_ONCE(ft_parked, 0);
	ft_invalid_done = false;
	ft_rearms++;
}

static void ft_rearm_workfn(struct work_struct *work)
{
	cdx_ft_begin();
	ft_rearm();
	cdx_ft_end();
}

static bool ft_bound_to(const struct cdx_ft_entry *entry, const void *binding)
{
	return entry->binding == binding;
}

void ft_release(void *priv)
{
	struct cdx_ft_binding *binding = priv;

	cdx_ft_begin();
	/* Counted here rather than at unbind, because this is the one place
	 * every route away from a binding passes: unbind, a device's indirect
	 * cleanup, and the unload drain. */
	if (binding->passive) {
		ft_passive--;
		cdx_ft_end();
		kfree(binding);
		return;
	}
	/* A batch at a time, letting the transaction go between batches. No
	 * callback reaches this binding any more -- Netfilter has taken it off
	 * the block -- so the entries left are only fewer when it comes back;
	 * anything else retiring some of them meanwhile is no matter. */
	while (ft_retire_batch(ft_bound_to, binding)) {
		cdx_ft_end();
		cond_resched();
		cdx_ft_begin();
	}
	spin_lock_bh(&ft_watch_lock);
	list_del(&binding->list);
	ft_bound--;
	spin_unlock_bh(&ft_watch_lock);
	/* A live binding going may be the last one a parked binding waits
	 * for: this is the commit of an atomic reload, releasing the table it
	 * replaced. */
	if (binding->parked)
		WRITE_ONCE(ft_parked, ft_parked - 1);
	else
		ft_rearm();
	cdx_ft_end();
	dev_put(binding->dev);
	kfree(binding);
}

/* A device the classifier cannot program, bound anyway.
 *
 * Netfilter registers an offload flowtable only if every listed device accepts
 * its block: one refusal fails the whole table, and fw4 then falls back to
 * software offload for every port. The list it hands over is the physical
 * lowers of the zone devices, so on a gateway with Wi-Fi in the LAN bridge a
 * VAP is always on it. Refusing the VAP therefore cost the wired ports their
 * hardware path -- the opposite of what the refusal was written to protect.
 *
 * So a device that is not a DPAA port is bound with this callback instead,
 * which declines every request. Netfilter counts a declined direction as "not
 * offloaded" and leaves it on the software fast path, which is exactly where a
 * Wi-Fi ingress belongs; the DPAA ports in the same table keep their hardware
 * path. Nothing is allocated for the device beyond a binding marked passive,
 * which is what ft_release() and the unload drain need to find its table.
 * The bind path binds a DPAA port the same way when the hardware cannot take
 * it for the rest of the boot, and says why there.
 */
static int ft_passive_callback(enum tc_setup_type type, void *data, void *priv)
{
	return -EOPNOTSUPP;
}

/* Bind dev with ft_passive_callback. why names the reason in the log, which is
 * the only place a consumer whose table committed can learn that one of its
 * ports stays in software. */
static int ft_bind_passive(struct net_device *dev, struct flow_block_offload *bo,
			   struct nf_flowtable *flowtable, bool indirect, struct Qdisc *sch,
			   void (*cleanup)(struct flow_block_cb *), const char *why)
{
	struct cdx_ft_binding *passive;
	struct flow_block_cb *cb;

	cdx_ft_assert_held();
	passive = kzalloc(sizeof(*passive), GFP_KERNEL);
	if (!passive)
		return -ENOMEM;
	passive->dev = dev;
	passive->table = flowtable;
	passive->passive = true;
	cb = indirect ?
		flow_indr_block_cb_alloc(ft_passive_callback, dev, passive,
			ft_release, bo, dev, sch, flowtable, NULL, cleanup) :
		flow_block_cb_alloc(ft_passive_callback, dev, passive, ft_release);
	if (IS_ERR(cb)) {
		kfree(passive);
		return PTR_ERR(cb);
	}
	flow_block_cb_add(cb, bo);
	list_add_tail(&cb->driver_list, &ft_block_list);
	ft_passive++;
	pr_info("cdx flowtable: %s bound passively (%s), its flows stay in software\n",
		netdev_name(dev), why);
	return 0;
}

/* Whether flowtable may bind dev beside the tables already bound.
 *
 * Several tables can be bound at once, for a moment: Netfilter binds a table
 * while preparing the transaction that adds it and unbinds the one it replaces
 * only at commit, and a consumer probing offload binds a second table beside
 * its own. Refusing either aborts the consumer's firewall transaction, or turns
 * its probe into a silent fallback to software. Each binding owns only its own
 * entries, and a conntrack belongs to one flowtable at a time, so two tables
 * never describe the same flow to the hardware.
 *
 * Still refused: a table past its device bound, the same table twice on one
 * device, and a third table at once.
 */
static int ft_bind_admissible(const struct nf_flowtable *flowtable,
			      const struct net_device *dev)
{
	const struct nf_flowtable *others[CDX_FT_MAX_TABLES - 1];
	struct cdx_ft_binding *other;
	unsigned int devices = 0, nothers = 0, i;
	bool duplicate = false, crowded = false;

	cdx_ft_assert_held();
	list_for_each_entry(other, &ft_bindings, list) {
		if (other->table == flowtable) {
			devices++;
			duplicate |= other->dev == dev;
			continue;
		}
		for (i = 0; i < nothers && others[i] != other->table; i++)
			;
		if (i < nothers)
			continue;
		if (nothers == ARRAY_SIZE(others))
			crowded = true;
		else
			others[nothers++] = other->table;
	}
	if (devices >= CDX_FT_MAX_TABLE_DEVICES)
		return -EOPNOTSUPP;
	return duplicate || crowded ? -EBUSY : 0;
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
	struct cdx_ft_binding *binding;
	struct flow_block_cb *cb;
	const char *passive;
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
		if (!ft_ready || ft_stopping) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		/* A bind the hardware cannot take must not fail the consumer's
		 * transaction: that would fail its whole firewall reload, which is
		 * far worse than a port forwarding in software. A port the
		 * classifier cannot program is bound passively, and so are two
		 * refusals that nothing in this boot will lift. A failed deletion
		 * CDX cannot settle latches admission off until a fresh boot, so a
		 * parked binding would wait for a rearm that never comes; one CDX
		 * is restarting the datapath after is different, and its bindings
		 * are made as any other's, every flow declined until the restart
		 * and the rearm it asks for. A binding past the bound could not be
		 * flushed by ft_invalidate_work(), whose device snapshot that bound
		 * sizes; passive bindings are not counted in it. An invalidation
		 * recovers in this boot once the bindings it caught are gone: a
		 * binding made under one is parked below and takes over by
		 * itself. */
		passive = !cdx_ft_port_supported(dev) ? "not a classifier port" :
			  cdx_ft_terminal() ? "admission stopped until reboot" : NULL;
		if (passive) {
			rc = ft_bind_passive(dev, bo, flowtable, indirect, sch, cleanup,
					     passive);
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
		rc = ft_bind_admissible(flowtable, dev);
		if (rc)
			goto out;
		/* After the table and device checks, so a bind they refuse is
		 * refused here too rather than accepted passively. */
		if (ft_bound >= CDX_FT_MAX_BINDINGS) {
			rc = ft_bind_passive(dev, bo, flowtable, indirect, sch, cleanup,
					     "no binding left");
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
		 * is monotonic for the table, including after unbind. The core
		 * also retires DIRECT flows constructed concurrently with bind. */
		WRITE_ONCE(flowtable->use_neigh, true);
		WRITE_ONCE(flowtable->use_hw_handles, true);
		/* A binding made while an invalidation is latched is parked:
		 * the transaction commits, and the table's flows forward in
		 * software until ft_rearm() makes the binding live. Read only
		 * after the allocations, so an invalidation raised during them
		 * parks this binding too; nothing here clears one. ft_rearm()
		 * does, and only once it has drained -- which it already has
		 * when every old binding is gone, so the first bind after a full
		 * detach still rearms at once. That is committed only after the
		 * binding was allocated successfully, and while no live binding
		 * exists a notifier cannot invalidate new entries: none exist yet.
		 * Rules validate fresh Linux context. */
		binding->parked = atomic_read(&ft_invalid);
		dev_hold(dev);
		spin_lock_bh(&ft_watch_lock);
		list_add_tail(&binding->list, &ft_bindings);
		ft_bound++;
		spin_unlock_bh(&ft_watch_lock);
		if (binding->parked) {
			WRITE_ONCE(ft_parked, ft_parked + 1);
			/* A table that already holds flows -- one gaining a
			 * device -- may hold some made before the latch, through
			 * a device no pass flushed. Count that like an event, so
			 * a pass flushes this device's flows before it can go
			 * live. A table created by this transaction is empty. */
			if (atomic_read(&flowtable->rhashtable.nelems)) {
				atomic_inc(&ft_invalid_seq);
				schedule_delayed_work(&ft_work, 0);
			}
			ft_rearm();
			if (binding->parked)
				pr_info("cdx flowtable: %s bound parked, its flows stay in software until the invalidated bindings drain\n",
					netdev_name(dev));
		}
		flow_block_cb_add(cb, bo);
		list_add_tail(&cb->driver_list, &ft_block_list);
	} else if (bo->command == FLOW_BLOCK_UNBIND) {
		cb = flow_block_cb_lookup(bo->block, ft_rule_callback, dev);
		if (!cb)
			cb = flow_block_cb_lookup(bo->block, ft_passive_callback, dev);
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
int ft_bind(struct net_device *dev, struct Qdisc *sch, void *priv,
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

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
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_pppox.h>
#include <linux/if_vlan.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/workqueue.h>
#include <net/addrconf.h>
#include <net/arp.h>
#include <net/fib_notifier.h>
#include <net/fib_rules.h>
#include <net/flow_offload.h>
#include <net/if_inet6.h>
#include <net/ip6_route.h>
#include <net/ip6_tunnel.h>
#include <net/ip_tunnels.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/netevent.h>
#include <net/nexthop.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_tables.h>
#include <net/switchdev.h>
#include <net/l3mdev.h>
#include <net/xfrm.h>
#include <net/cfg80211.h>
#include <dpaa_eth_common.h>
#include "cdx_flowtable_backend.h"
#include "cdx_mcast_backend.h"
#include "cdx_flowtable.h"
#include "cdx_ipsec_backend.h"
#include "cdx_wifi_backend.h"
#include "cdx_police.h"

#if !defined(FLOW_CLS_HAS_NF_CONTEXT) || FLOW_CLS_HAS_NF_CONTEXT < 12
#error "CDX flowtable requires kernel flowtable context version 12 or later"
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
MODULE_PARM_DESC(init_fail_stage, "Fail adapter load: 1 proc, 2 netdev, 3 neighbour, 4 FIB, 5 indirect registration, 6 nexthop objects, 7 bridge FDB, 8 bridge VLAN configuration, 9 direct registration");
module_param_named(flowtable_fail_stage, ft_fail_stage, uint, 0600);
MODULE_PARM_DESC(flowtable_fail_stage, "One-shot add failure: 1 before allocation, 2 before hardware, 3 after hardware, 4 busy after peer direction");
#endif

/* Egress QoS classification. The conntrack mark is the only key the software
 * and hardware paths can share: an offloaded flow produces no skb, so nothing
 * a tc filter decides can reach it. Reading it here keeps one source of truth.
 *
 * Both are boot-immutable because a mask that changed
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
MODULE_PARM_DESC(qos_mark_mask, "Conntrack mark bits holding the class; 0 disables classification and refuses marked flows");
module_param_named(qos_default_class, ft_qos_default_class, uint, 0444);
MODULE_PARM_DESC(qos_default_class, "Class for flows whose masked mark is zero: nibbles low to high are class queue, channel, ingress policer profile, then a remark flag and six bits of DSCP");

/* Reject a class the hardware cannot express rather than truncating it into a
 * different queue, which would accelerate the flow onto a queue nobody asked
 * for instead of declining it. */
static bool ft_qos_class_valid(unsigned int class)
{
	return !(class & ~CDX_FT_QOS_MASK) &&
		((class & CDX_FT_QOS_CHANNEL_MASK) >> CDX_FT_QOS_CHANNEL_SHIFT) <=
			CDX_FT_QOS_MAX_CHANNEL &&
		((class & CDX_FT_QOS_POLICER_MASK) >> CDX_FT_QOS_POLICER_SHIFT) <=
			CDX_FT_QOS_MAX_POLICER;
}

/* Map a conntrack mark onto a class. The masked bits are shifted down to their
 * own base so an operator can place the field anywhere in the word and share
 * the rest with policy routing or a VPN's own marks.
 *
 * Nineteen bits are spoken for — four each for class queue, channel and ingress
 * policer, then a flag and six bits of DSCP to remark with — leaving thirteen
 * of a 32-bit mark to the operator. A mask narrower than the fields an operator
 * uses is not an error: the bits it does not cover read zero, which is this
 * encoding's "unspecified" in every position, including a clear remark flag. */
static u32 ft_qos_class(u32 mark)
{
	if (!ft_qos_mark_mask)
		return 0;
	mark = (mark & ft_qos_mark_mask) >> __ffs(ft_qos_mark_mask);
	return mark ? mark : ft_qos_default_class;
}

/* Whether any class this decode can produce carries a remark: a bit of the
 * mark that shifts onto the remark flag, or a default class with one. Fixed
 * for the module's life, since both parameters are. */
static bool ft_qos_remarks(void)
{
	if (!ft_qos_mark_mask)
		return false;
	return ((ft_qos_mark_mask >> __ffs(ft_qos_mark_mask)) & CDX_FT_QOS_REMARK_MASK) ||
	       (ft_qos_default_class & CDX_FT_QOS_REMARK_MASK);
}

/* The class of the connection an IP packet belongs to, for cdx's software Tx
 * path (cdx_ft_qos_class_fn): the decode above, applied to the same mark the
 * flow's hardware rule was given its class from.
 *
 * The conntrack an skb carries answers for its own header. A frame reaches the
 * port without it when a scrub took it -- ppp_start_xmit() and the IP tunnels
 * drop it, and the ingress index with it -- and a packet an IP-in-IP frame
 * carries never had one on this skb at all. Conntrack is then asked by the
 * packet's tuple. The port sees a packet after NAT, which makes its tuple the
 * inverse of the tuple the other direction is keyed on, so the inverse is
 * what is looked up; for an untranslated packet it is the reply tuple, which
 * finds the same entry. Only the default zone is searched.
 *
 * Not looked up: a frame untracked on purpose (_nfct without a conntrack is
 * IP_CT_UNTRACKED), and one still carrying its ingress index, which crossed no
 * scrub and so kept whatever it had. Nor while interrupts are off, as netpoll
 * sends: the reference dropped below could be the last, and freeing a
 * conntrack takes locks that must not be taken there. With no mask every
 * class is zero, and no lookup can change that. */
static bool ft_qos_flow_class(const struct sk_buff *skb, unsigned int nhoff,
			      u8 family, bool own, u32 *class)
{
	struct nf_conntrack_tuple tuple, inverse;
	struct nf_conntrack_tuple_hash *h;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct net *net;
	u32 mark;

	if (own) {
		ct = nf_ct_get(skb, &ctinfo);
		if (ct) {
			*class = ft_qos_class(READ_ONCE(ct->mark));
			return true;
		}
		if (skb->_nfct || skb->skb_iif)
			return false;
	}
	if (!family || !ft_qos_mark_mask || irqs_disabled() || !skb->dev)
		return false;
	net = dev_net(skb->dev);
	if (!nf_ct_get_tuplepr(skb, nhoff, family == AF_INET6 ? NFPROTO_IPV6 : NFPROTO_IPV4,
			       net, &tuple) ||
	    !nf_ct_invert_tuple(&inverse, &tuple))
		return false;
	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &inverse);
	if (!h)
		return false;
	ct = nf_ct_tuplehash_to_ctrack(h);
	mark = READ_ONCE(ct->mark);
	nf_ct_put(ct);
	*class = ft_qos_class(mark);
	return true;
}

struct cdx_ft_binding {
	struct list_head list;
	struct net_device *dev;
	struct nf_flowtable *table; /* retained as identity; borrowed in bind only */
	/* Bound while an invalidation was latched: counted and watched like any
	 * other binding, but every flow it is offered stays in software until
	 * ft_rearm() makes it live. Changed only under the backend transaction,
	 * which is also what its reader, the rule callback, holds. */
	bool parked;
	/* Bound with ft_passive_callback: never on ft_bindings, no device
	 * reference, no entries -- only what ft_release() and the unload drain
	 * need. It shares ft_release() with a real binding because Netfilter
	 * unwinds indirect callbacks by their release function alone
	 * (flow_indr_dev_unregister()); one with a release of its own stayed on
	 * the indirect list after the drain freed it. */
	bool passive;
};

/* One logical device's interface counters: the record its encapsulation counts
 * into, which dev_get_stats() folds into the device's own counters -- so
 * `ip -s link` and /proc/net/dev show traffic that never reached the CPU. A
 * VLAN device's record is a plain one that its tag's two opcodes name; a ppp
 * device's is a timestamped one that its session's two opcodes name. Both are
 * keyed on the device, because that is what the reader names: a ppp device
 * carries one session at a time, and a session renegotiated under a device
 * that stays is still that device's traffic. The identity the walk derived for
 * the session is kept alongside, for the /proc row to be joined with the flow
 * rows, and follows the last direction admitted.
 *
 * Held for the device's lifetime rather than its flows': a slot returned to
 * the pool is zeroed when handed out again, so a record that came and went
 * with the flows would drop the device's counters back to zero every time it
 * went idle. refs counts the hardware directions whose opcodes name the
 * record's indices and is what makes freeing safe: the device can unregister
 * while an entry naming the record is still being retired, and the slot has
 * to outlive that opcode. gone marks the device as unregistered. The record is
 * freed by whichever comes last, the unregistration or the last release, and a
 * gone record is never found by index again, so a device that reuses the index
 * starts a record of its own.
 *
 * slot is NULL for a device admitted while its pool was empty: its flows
 * forward without counting, and the row in /proc/cdx_flowtable says so. The
 * answer a device got is the answer it keeps, so a live connection's counters
 * never begin halfway through its life.
 */
struct cdx_ft_dev_stats {
	struct list_head list;
	int ifindex;
	enum cdx_ft_stats_kind kind;
	unsigned int refs;
	bool gone;
	struct cdx_ft_stats_slot *slot;
	struct cdx_ft_session session;
	/* A tunnel device's record is a plain one, like a VLAN device's; this
	 * is what tells the two apart in the read-back and carries the
	 * identity the flow rows print, following the last direction admitted
	 * exactly as a session's does. */
	struct cdx_ft_tunnel tunnel;
};

/* Per side: a device under a tunnel and one under a session, and every tag's
 * device. Fewer are ever distinct, since most of these are the same device
 * seen from two hops or a device the rule already names. */
#define CDX_FT_CROSSED_MAX (2 * (CDX_FT_VLAN_MAX + 2))

/* What a device is to the installed flows, weakest first: nothing; a device
 * paths only cross on their way down to a port; some direction's own logical
 * device or bridge; a port -- bound, or some direction's physical ingress or
 * egress. How far a change to it reaches follows from which. */
enum ft_device_role { FT_DEV_UNUSED, FT_DEV_CROSSED, FT_DEV_NAMED, FT_DEV_PORT };

struct cdx_ft_entry {
	struct list_head list;
	struct hlist_node cookie_node;
	struct hlist_node key_node;
	struct list_head neigh_list;
	struct neighbour *neigh;
	struct nf_flow_offload_handle *handle;
	union nf_inet_addr next_hop;
	struct cdx_ft_binding *binding;
	/* The ppp device record each half of this direction's session counts
	 * into, or NULL. Held on the entry rather than in the rule: a rule is
	 * compared bytewise against a stored one to decide whether anything
	 * changed, and an attached resource is not part of that description. */
	struct cdx_ft_dev_stats *in_stats;
	struct cdx_ft_dev_stats *out_stats;
	/* And the VLAN device record each tag counts into, indexed like the
	 * rule's stacks; NULL for a tag with no device or no record. */
	struct cdx_ft_dev_stats *in_vlan_stats[CDX_FT_VLAN_MAX];
	struct cdx_ft_dev_stats *out_vlan_stats[CDX_FT_VLAN_MAX];
	/* And the tunnel device's, held the same way. */
	struct cdx_ft_dev_stats *in_tunnel_stats;
	struct cdx_ft_dev_stats *out_tunnel_stats;
	/* The devices each side's frames cross that the rule names only by
	 * index: a VLAN device between the logical device and the port, and
	 * the ppp device a tunnel runs over. The walk that admitted the
	 * direction required each of them -- up, carrying the port's address,
	 * stacked exactly so -- so each is held and watched like the devices
	 * the rule does name. Kept on the entry for the reason the records
	 * above are. */
	struct net_device *crossed[CDX_FT_CROSSED_MAX];
	unsigned int ncrossed;
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
/* Device counter records, VLAN and ppp alike. Mutated under the backend
 * transaction like the entries that reference them, and additionally under
 * ft_dev_stats_lock, because the netdev notifier marks a record's device gone
 * without a transaction: the reaper then frees what nothing references. */
static LIST_HEAD(ft_dev_stats);
static DEFINE_SPINLOCK(ft_dev_stats_lock);
static unsigned int ft_bound, ft_count;
/* How many of ft_bound are parked. Written only in the transaction, like
 * the flag, but ft_invalidate() reads it without one: every write is
 * WRITE_ONCE, so that read sees either value, never a torn one. */
static unsigned int ft_parked;
/* Passive bindings, which ft_bound does not count. Transaction-only. */
static unsigned int ft_passive;
static unsigned int ft_neighbour_refs;
static unsigned int ft_handle_refs;
static atomic64_t ft_neigh_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_route_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_mtu_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_link_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_mac_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_fdb_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_stp_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_qos_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_admission_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_ipsec_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_ipsec_genid = ATOMIC64_INIT(0);
static atomic64_t ft_ipsec_policy_invalidations = ATOMIC64_INIT(0);
static u64 ft_installs, ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy;
static u64 ft_rearms;
static bool ft_ready, ft_stopping;
static atomic_t ft_invalid = ATOMIC_INIT(0);
static bool ft_invalid_done;
/* A parked table keeps collecting software flows while the latch is held, so
 * an event raised then must be covered by a worker pass that flushes them
 * before the table can go live -- folding it into the latch, as an event
 * with nothing parked safely is, would let those flows into hardware later.
 * ft_invalid_seq counts such events (notifier context, no transaction); the
 * worker samples it before a pass and publishes what that pass covered in
 * ft_done_seq (under the transaction). */
static atomic_t ft_invalid_seq = ATOMIC_INIT(0);
static int ft_done_seq;
static struct proc_dir_entry *ft_proc;
static void ft_invalidate_work(struct work_struct *work);
static void ft_neigh_detach(struct cdx_ft_entry *entry);
static void ft_retire_workfn(struct work_struct *work);
static void ft_rearm_workfn(struct work_struct *work);
static void ft_dev_stats_reap(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_work, ft_invalidate_work);
static DECLARE_WORK(ft_retire_work, ft_retire_workfn);
static DECLARE_DELAYED_WORK(ft_rearm_work, ft_rearm_workfn);
static DECLARE_WORK(ft_dev_stats_work, ft_dev_stats_reap);

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

static bool ft_rule_names(const struct cdx_ft_rule *rule, const struct net_device *dev)
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
static void ft_dev_stats_gone(const struct net_device *dev)
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

/* At unload, after the backend release has proved no hardware direction is
 * left: the devices are still registered, so the list does not drain by
 * construction, and every record is freed here. */
static void ft_dev_stats_drop_all(void)
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
	ft_crossed_put_all(entry);
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

/* Whether the neighbour at @dst is usable and names an address other than
 * @mac: not a neighbour still resolving or gone, but one that has moved. */
static bool ft_neigh_moved(u8 family, struct net_device *dev,
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
 * lose its policy/ingress context. The callback supplies retained NEIGH and
 * XFRM dsts with the cookie they were selected under: an IPv6 destination
 * belongs to one FIB generation and dst_check() rejects every one of them
 * against a zero cookie. No route pointer escapes the callback. A transformed
 * destination is handed over rather than withheld, and ft_next_hop() below
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

/* Name the offloaded inbound SA paired with an outbound one.
 *
 * A child SA is installed as a pair with mirrored endpoints, so the inbound
 * half of `out` is the state whose destination is our local endpoint and whose
 * source is the peer. Asking xfrm's own index for it beats keeping a second
 * one here: the pair is the kernel's fact, not this adapter's, and a private
 * copy would have to be kept in step with every rekey.
 *
 * Three outcomes. No such state leaves the receiving handle unset; the
 * caller must still prove that forwarding policy permits plaintext before
 * admitting the connection. A usable one is
 * named. One that exists and is not usable -- software, another port's, dead
 * -- is a refusal: its frames are decrypted before they could match this
 * tuple, so the entry would be installed, counted and never matched.
 *
 * A rekey briefly leaves two inbound states for one pair; the lookup answers
 * with the most recently installed, which is the one a fresh flow should name.
 * The older one keeps its own classifier entry until it is deleted, and that
 * deletion retires whatever still depends on it.
 */
static bool ft_ipsec_paired_inbound(const struct xfrm_state *out,
				    struct net_device *in, u16 *handle,
				    struct xfrm_state **received)
{
	struct xfrm_state *x;
	bool ok = false;

	*handle = 0;
	x = xfrm_state_lookup_byaddr(&init_net, out->mark.v, &out->props.saddr,
				     &out->id.daddr, IPPROTO_ESP,
				     out->props.family);
	if (!x)
		return true;		/* caller checks receiving policy */
	if (x->xso.type == XFRM_DEV_OFFLOAD_PACKET &&
	    x->xso.dir == XFRM_DEV_OFFLOAD_IN && x->xso.offload_handle &&
	    x->xso.dev == in && x->km.state == XFRM_STATE_VALID) {
		*handle = cdx_ipsec_sa_handle(
			(struct cdx_ipsec_sa *)READ_ONCE(x->xso.offload_handle));
		ok = *handle != 0;
	}
	if (ok && received)
		*received = x;
	else
		xfrm_state_put(x);
	return ok;
}

/* Record the handle this end of the direction needs, and say whether the
 * direction may be installed at all.
 *
 * The sending end names the state it found. The receiving end names that
 * state's inbound half instead. A missing half is usable only if the caller
 * proves the receiving policy allows plaintext; one-way tunnels remain legal.
 */
static bool ft_ipsec_record(const struct xfrm_state *x, struct net_device *pair_in,
			    u16 *handle, struct xfrm_state **received)
{
	if (!pair_in) {
		*handle = cdx_ipsec_sa_handle(
			(struct cdx_ipsec_sa *)READ_ONCE(x->xso.offload_handle));
		return *handle != 0;
	}
	return ft_ipsec_paired_inbound(x, pair_in, handle, received);
}

/* What transform covers `fl` leaving `dev`, and which SA handle this direction
 * should record because of it.
 *
 * Two questions share this one lookup, because they are the same question
 * asked from opposite ends of a direction:
 *
 *   `pair_in == NULL` -- what encrypts the frames this direction *sends*.
 *     *handle receives that outbound SA's handle.
 *   `pair_in != NULL` -- what the frames this direction *receives* were
 *     encrypted by. The tuple passed is the reversed one, so the policy found
 *     is the one that would transform those frames had this gateway sent them,
 *     and the SA that actually decrypted them is that policy's inbound half on
 *     `pair_in`. *handle receives its handle.
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
 */
static bool ft_ipsec_resolve(struct dst_entry *dst, struct flowi *fl,
			     struct net_device *dev, struct net_device *pair_in,
			     u16 *handle, struct xfrm_state **received)
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
		return !!pair_in;
	}
	if (bundle == dst) {
		/* No policy: an ordinary plain end. Nothing consumed the
		 * reference taken above, so give it back. */
		dst_release(dst);
		return true;
	}

	x = ft_ipsec_offloaded(bundle, dev);
	ok = x ? ft_ipsec_record(x, pair_in, handle, received) : !!pair_in;
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
 */
static void ft_ipsec_flowi(const struct cdx_ft_rule *rule, bool reverse,
			   struct net_device *out, struct flowi *fl)
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
}

static bool ft_ipsec_receiving(const struct flow_cls_offload *cls,
			   const struct cdx_ft_rule *rule, bool reverse,
			       struct xfrm_state *received)
{
	struct flowi fl = {};
	const union nf_inet_addr *src = reverse ? &rule->new_dst : &rule->src;
	const union nf_inet_addr *dst = reverse ? &rule->new_src : &rule->dst;
	__be16 sport = reverse ? rule->new_dport : rule->sport;
	__be16 dport = reverse ? rule->new_sport : rule->dport;
	struct net_device *in = reverse ? rule->out_logical : rule->in_logical;
	struct net_device *out = reverse ? rule->in_logical : rule->out_logical;

	if (rule->family == AF_INET) {
		fl.u.ip4.saddr = src->ip;
		fl.u.ip4.daddr = dst->ip;
		fl.u.ip4.fl4_sport = sport;
		fl.u.ip4.fl4_dport = dport;
	} else {
		fl.u.ip6.saddr = src->in6;
		fl.u.ip6.daddr = dst->in6;
		fl.u.ip6.fl6_sport = sport;
		fl.u.ip6.fl6_dport = dport;
	}
	fl.flowi_proto = rule->proto;
	fl.flowi_iif = in->ifindex;
	fl.flowi_oif = out->ifindex;
	fl.flowi_mark = READ_ONCE(cls->nf_ct->mark);
	return xfrm_flowtable_policy_check(&init_net, &fl, rule->family, received);
}

/* Both ends of one direction: what encrypts what it sends, and what decrypted
 * what it receives. The sending end is asked of the destination this callback
 * borrowed; the receiving end of the reverse direction's, which is the path
 * the far end's frames took to get here.
 */
static bool ft_ipsec_handle(const struct flow_cls_offload *cls,
			    struct cdx_ft_rule *rule, struct net_device *out,
			    struct net_device *in)
{
	struct xfrm_state *received = NULL;
	struct flowi fl;
	u16 reverse_in;
	bool allowed;

	ft_ipsec_flowi(rule, false, out, &fl);
	if (!ft_ipsec_resolve(cls->nf_dst, &fl, out, NULL, &rule->sa_handle, NULL))
		goto denied;
	/* Both directions share one Linux generation. Validate both receiving
	 * ends even when their SAs exist: policy may now require a different
	 * transform, or forbid the tuple altogether. */
	if (!ft_ipsec_resolve(cls->nf_dst, &fl, out, rule->out, &reverse_in,
			     &received))
		goto denied;
	allowed = ft_ipsec_receiving(cls, rule, true, received);
	if (received)
		xfrm_state_put(received);
	if (!allowed)
		goto denied;
	ft_ipsec_flowi(rule, true, in, &fl);
	if (!ft_ipsec_resolve(cls->nf_dst_reverse, &fl, in, rule->in,
			     &rule->in_sa_handle, &received))
		goto denied;
	allowed = ft_ipsec_receiving(cls, rule, false, received);
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

/* The two things about an offer that no lock orders against it: the policy
 * generation it was queued under, and the two routes it borrows. Either one
 * having moved on retires the offer's whole generation. Needs no RTNL, so an
 * offer answered without admission is held to it as well. Returns whether the
 * generation is still valid. */
static bool ft_offer_current(const struct flow_cls_offload *cls)
{
	if (cls->nf_xfrm_genid != xfrm_flowtable_genid(&init_net))
		ft_handle_invalidate(cls->nf_handle, &ft_ipsec_policy_invalidations);
	if (nf_flow_offload_handle_valid(cls->nf_handle) && !ft_routes_valid(cls))
		ft_handle_invalidate(cls->nf_handle, &ft_route_invalidations);
	return nf_flow_offload_handle_valid(cls->nf_handle);
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
static bool ft_tunnel_dev(const struct net_device *dev)
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

/* Whether an IPv6 direction leaving by a path of @mtu can only ever be handed
 * packets that fit it. The microcode fragments anything over the entry's MTU
 * itself, IPv6 included, and nothing hands such a packet to Linux instead:
 * PREEMPT_DFBIT_HONOR and the fragmenter's DF action were both tried on the
 * board and act on IPv4 alone. A router never fragments IPv6 -- Linux answers
 * with Packet Too Big -- so the hardware may carry a direction only while its
 * ingress interface's IPv6 MTU, the one its hosts learn from router
 * advertisements, is no larger. Anything else stays on the software path,
 * which sends the Packet Too Big: IPv6 from a 1500-byte LAN to PPPoE or a 6in4
 * tunnel, unless that LAN's IPv6 MTU is set to the smaller path's. An SA does
 * not narrow the bound: through a transform the flow's MTU is its outer
 * device's, because ip6_dst_mtu_maybe_forward() ignores the bundle's unlocked
 * RTAX_MTU. Checked at admission, and for an installed direction on every
 * stats pass and every time Linux offers it again, because the IPv6 MTU is a
 * sysctl of its own that no device event reports. */
static bool ft_ipv6_mtu_bounded(struct net_device *in, u32 mtu)
{
	struct inet6_dev *idev;
	bool bounded = false;

	rcu_read_lock();
	idev = __in6_dev_get(in);
	if (idev)
		bounded = (u32)READ_ONCE(idev->cnf.mtu6) <= mtu;
	rcu_read_unlock();
	return bounded;
}

/* The largest IPv4 packet a direction arriving on @in may be handed once its
 * ingress has taken @stripped bytes of session and tunnel header off: the
 * device's MTU, but never less than a standard Ethernet frame carries through
 * the same stripping. The IPv4 MTU bound and its refusal ahead of admission
 * both measure a path against this, so the two cannot disagree about what
 * arrives. */
static u32 ft_ipv4_arriving(const struct net_device *in, unsigned int stripped)
{
	return max_t(u32, READ_ONCE(in->mtu), ETH_DATA_LEN - stripped);
}

/* Whether an IPv4 direction leaving by a path of @mtu can be carried although
 * a packet arriving on @in could be larger. The microcode fragments an
 * oversized IPv4 packet without DF itself, and for a frame an Ethernet port
 * received, the fragments it builds carry the headers but not the payload:
 * measured on the DK, every payload byte of every fragment is zero, whatever
 * the memory the buffers sit in and with no VSP on the port. One with DF it
 * hands to Linux for the ICMP. TCP sets DF, and a PPPoE or tunnel uplink
 * clamps its MSS besides, so a TCP direction stays in hardware; any other
 * direction into a smaller path stays in software, where Linux fragments.
 * A direction to or from SEC is exempt: its enqueue to SEC fragments nothing,
 * and what SEC returns is fragmented on the offline port, where the
 * microcode's fragments are whole.
 *
 * What may arrive is the ingress device's MTU, but never less than a
 * standard Ethernet frame carries through whatever the direction strips: a
 * port keeps receiving full frames after its MTU is lowered, and a host that
 * was not told the smaller MTU -- DHCP's option for it is widely ignored --
 * keeps sending them. The ingress and the path are device and route MTUs,
 * whose changes retire the flow through their own events, so admission alone
 * decides. */
static bool ft_ipv4_mtu_carried(const struct cdx_ft_rule *rule, const struct net_device *in,
				u32 mtu)
{
	unsigned int stripped = (rule->in_session.present ? PPPOE_SES_HLEN : 0) +
				(rule->in_tunnel.present ? rule->in_tunnel.header_size : 0);

	return rule->proto == IPPROTO_TCP || rule->sa_handle || rule->in_sa_handle ||
	       ft_ipv4_arriving(in, stripped) <= mtu;
}

/* Whether the decoder is certain to refuse this offer on its MTU bound, decided
 * from the request alone and before RTNL. Linux offers a flow again about once
 * a second for as long as software forwards any of it, so a direction the bound
 * keeps out keeps coming back while it carries traffic -- on a PPPoE uplink
 * that is every IPv4 UDP upload -- and each offer would otherwise take RTNL and
 * walk the whole path only to be refused again.
 *
 * Only a refusal that holds whatever the walk would find is made here. The
 * ingress device is the reverse destination's, exactly as the decoder takes
 * it, and the IPv6 bound reads nothing else. The IPv4 one is taken with the
 * most any ingress of an IPv4 flow can strip -- a session and the IPv6 outer
 * header of 4in6, the one tunnel mode that carries IPv4 -- which is where it is
 * lowest. And no transform may be in reach: neither destination carries one
 * and no policy or blocking default is configured, so every lookup
 * ft_ipsec_handle() makes returns the plain route. No SA can then exempt the
 * direction, and no policy can deny it -- a denial retires the whole
 * generation, which a refusal here would otherwise skip. A socket's own
 * policy is not one of those: it never governs a forwarded packet, and
 * neither the lookups nor xfrm_flowtable_policy_check() consult it. Everything
 * that passes still meets the exact bound in the decoder. */
static bool ft_mtu_refused(const struct flow_cls_offload *cls)
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
	if (basic.key->n_proto == htons(ETH_P_IP))
		refused = basic.key->ip_proto != IPPROTO_TCP &&
			  ft_ipv4_arriving(in, PPPOE_SES_HLEN + sizeof(struct ipv6hdr)) >
			  cls->nf_mtu;
	else
		refused = basic.key->n_proto == htons(ETH_P_IPV6) &&
			  !ft_ipv6_mtu_bounded(in, cls->nf_mtu);
	if (refused)
		ask_dbg(ASK_DBG_DEVICE, "proto %u mtu %u below ingress %s before RTNL\n",
			basic.key->ip_proto, cls->nf_mtu, netdev_name(in));
	rcu_read_unlock();
	return refused;
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
	    cls->nf_mtu > out->out_logical->mtu ||
	    cls->nf_mtu < (family == AF_INET6 ? IPV6_MIN_MTU : 68))
		return ask_refuse(-EOPNOTSUPP);
	if (family == AF_INET6 && !ft_ipv6_mtu_bounded(out->in_logical, cls->nf_mtu)) {
		ask_dbg(ASK_DBG_DEVICE, "ipv6 mtu %u below ingress %s\n",
			cls->nf_mtu, netdev_name(out->in_logical));
		return ask_refuse(-EOPNOTSUPP);
	}
	if (family == AF_INET && !ft_ipv4_mtu_carried(out, out->in_logical, cls->nf_mtu)) {
		ask_dbg(ASK_DBG_DEVICE, "ipv4 proto %u mtu %u below ingress %s\n",
			out->proto, cls->nf_mtu, netdev_name(out->in_logical));
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
	out->mtu = cls->nf_mtu;
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
	/* An ingress tunnel's outer header is stripped before the inner packet
	 * is what Netfilter would count, so it is framing here too, one layer
	 * up. A peer that adds an encapsulation-limit option to its IPv6 outer
	 * header sends eight bytes more than this, which is not recoverable
	 * per frame and is documented rather than guessed at. */
	return ETH_HLEN + rule->in_vlans * VLAN_HLEN +
	       (rule->in_session.present ? PPPOE_SES_HLEN : 0) +
	       (rule->in_tunnel.present ? rule->in_tunnel.header_size : 0);
}

/* Whether an installed direction still holds its IPv6 ingress bound, retiring
 * its generation when it does not. The one admission condition no event
 * reports, so it is asked whenever Linux touches the direction again. Needs
 * no RTNL: the entry holds its ingress logical device. */
static bool ft_entry_bounded(struct cdx_ft_entry *entry)
{
	if (entry->rule.family != AF_INET6 ||
	    ft_ipv6_mtu_bounded(entry->rule.in_logical, entry->rule.mtu))
		return true;
	ft_handle_invalidate(entry->handle, &ft_mtu_invalidations);
	return false;
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
 * offloaded flow ever gets of them either. What ft_replace() checks ahead of
 * any parse still applies, through ft_offer_current(), and so does the one
 * admission bound no event reports, through ft_entry_bounded(). */
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
			rc = ft_offer_current(cls) && ft_entry_bounded(entry) ?
			     0 : ask_refuse(-EOPNOTSUPP);
		} else if (!entry && ft_mtu_refused(cls)) {
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

/* Whether the worker has finished a pass covering every event counted so
 * far, not merely the one that took the latch. */
static bool ft_invalid_complete(void)
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

static bool ft_can_rearm(void)
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
static void ft_rearm(void)
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

static void ft_release(void *priv)
{
	struct cdx_ft_binding *binding = priv;
	struct cdx_ft_entry *entry, *next;

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
	list_for_each_entry_safe(entry, next, &ft_entries, list)
		if (entry->binding == binding)
			ft_remove(entry);
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
		 * latches admission off until a fresh boot, so a parked binding
		 * would wait for a rearm that never comes. A binding past the bound
		 * could not be flushed by ft_invalidate_work(), whose device
		 * snapshot that bound sizes; passive bindings are not counted in
		 * it. An invalidation is different, because it recovers in this
		 * boot once the bindings it caught are gone: a binding made under
		 * one is parked below and takes over by itself. */
		passive = !cdx_ft_port_supported(dev) ? "not a classifier port" :
			  cdx_ft_failed() ? "admission stopped until reboot" : NULL;
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
	/* After a terminal failure nothing is ever admitted again, so a repeat
	 * pass has no flow to protect. */
	if (ft_invalid_done && cdx_ft_failed()) {
		ft_done_seq = seq;
		cdx_ft_end();
		return;
	}
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
static bool ft_entry_uses(const struct cdx_ft_entry *entry, const struct net_device *dev)
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
static DECLARE_WORK(ft_stopped_work, ft_stopped_workfn);

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
	struct cdx_ipsec_sa *sa;
	struct net_device *dev;
	union nf_inet_addr local;
	union nf_inet_addr peer;
	/* What the peer is routed with besides the two addresses. */
	struct ft_ipsec_route route;
	/* What the hardware is currently writing: the peer's address and the
	 * port's own. Both are in the entry's header-manipulation opcodes, so
	 * either changing is the same defect and takes the same rebuild. */
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
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
static atomic64_t ft_ipsec_next_hop_updates = ATOMIC64_INIT(0);
/* Egress changes seen so far, on any port (ft_egress_changed()). Something
 * being built while one lands -- an SA, a multicast chain -- is not yet where
 * the change can mark it, and may have been built from either side of it; the
 * builder compares this across the build and marks itself instead. */
static atomic64_t ft_egress_changes = ATOMIC64_INIT(0);

static void ft_ipsec_follow_work(struct work_struct *work);
static DECLARE_WORK(ft_ipsec_follow, ft_ipsec_follow_work);

/* Caller holds ft_watch_lock. */
static void ft_ipsec_mark(struct ft_ipsec_watch *watch)
{
	watch->stale = true;
	schedule_work(&ft_ipsec_follow);
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
static void ft_ipsec_neigh_moved(struct neighbour *neigh)
{
	struct ft_ipsec_watch *watch;

	if (neigh->tbl != &arp_tbl || neigh->dead ||
	    !(neigh->nud_state & NUD_VALID))
		return;
	list_for_each_entry(watch, &ft_ipsec_watches, list) {
		if (watch->family != AF_INET || watch->dev != neigh->dev)
			continue;
		if (*(__be32 *)neigh->primary_key != watch->peer.ip)
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
static void ft_ipsec_route_moved(u8 family, const void *dst, __be32 mask,
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
static void ft_ipsec_all_moved(void)
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
static void ft_ipsec_device_moved(const struct net_device *dev)
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
static void ft_ipsec_egress_changed(const struct net_device *dev)
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
static bool ft_ipsec_rebuild_pending(const struct net_device *dev)
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
	ether_addr_copy(watch->dst_mac, spec->dst_mac);
	ether_addr_copy(watch->src_mac, spec->dev->dev_addr);
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
static void ft_ipsec_watch_flush(void)
{
	struct ft_ipsec_watch *watch, *next;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry_safe(watch, next, &ft_ipsec_watches, list) {
		list_del(&watch->list);
		kfree(watch);
	}
	spin_unlock_bh(&ft_watch_lock);
}

static void ft_ipsec_attach(struct net_device *dev);
static void ft_ipsec_detach(struct net_device *dev);

/* Defined with the VAP watch below, for the same reason the multicast one is:
 * they belong with the state they keep rather than with the chain that reaches
 * them. */
static void ft_wifi_reconsider(struct net_device *dev);
static void ft_wifi_device_gone(struct net_device *dev);
static void ft_wifi_address_changed(struct net_device *dev);

/* Defined with the multicast learners below, because they belong with that
 * state rather than with the chains they are reached from. */
static void ft_mc_device_gone(struct net_device *dev, bool unregistering);
static void ft_mc_port_moved(struct net_device *dev, struct net_device *left);
static void ft_mr_device_gone(struct net_device *dev);
static void ft_mc_kick_all(void);
static void ft_mr_kick(void);
/* The multicast halves of the egress hook: every group copying out of a port
 * whose egress changed is marked for its learner's worker, and a drain
 * rebuilds what is still marked in place. See ft_mc_egress_changed(). */
static void ft_mc_egress_changed(const struct net_device *dev);
static int ft_mc_egress_drain(const struct net_device *dev);
static int ft_mr_egress_drain(const struct net_device *dev);
/* And the SA deletions still on their way to the hardware, for the same
 * drain; see ft_ipsec_retiring. */
static bool ft_ipsec_retire_pending(void);

static int ft_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
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

static int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct neighbour *neigh = ptr;
	struct cdx_ft_entry *entry;

	if (event == NETEVENT_XFRM_POLICY_UPDATE) {
		if (!net_eq(ptr, &init_net))
			return NOTIFY_DONE;
		/* Atomic notification, including policy expiry. Never enter the
		 * hardware backend while the XFRM policy lock is held. */
		spin_lock_bh(&ft_watch_lock);
		list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
			ft_handle_invalidate(entry->handle, &ft_ipsec_policy_invalidations);
		spin_unlock_bh(&ft_watch_lock);
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
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
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

/* Defined with the routed multicast learner below, because it belongs with
 * that state rather than with this chain's other cases. */
static int ft_mr_fib_event(unsigned long event, struct fib_notifier_info *info);

static int ft_fib_event(struct notifier_block *nb, unsigned long event, void *ptr)
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
/* Defined with the rest of the multicast learner below, because it belongs
 * with that state rather than with this chain's other cases. */
static bool ft_mc_swdev_obj(unsigned long event,
			    struct switchdev_notifier_port_obj_info *obj);
static void ft_mc_bridge_changed(struct net_device *dev);

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

static int ft_swdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	const struct switchdev_notifier_port_attr_info *attr;
	const struct switchdev_notifier_port_obj_info *obj;
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);

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
			if (dev && net_eq(dev_net(dev), &init_net)) {
				ft_mr_kick();
				ft_mc_bridge_changed(dev);
			}
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
			if (dev && ft_stp_stopped(attr->attr)) {
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
	if (!dev)
		return NOTIFY_DONE;
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

static const struct cdx_ft_egress_ops ft_egress_ops = {
	.changed = ft_egress_changed,
	.drain = ft_egress_drain,
};

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
 * count, ipmr's with the egress port's address and one hop fewer.
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

/* What an MFC entry routed through a bridge contributes to the bridged group
 * carrying its stream.
 *
 * Owned by the routed group, which allocates it on first publication and frees
 * it after withdrawing it. The description is written under ft_mc_lock and
 * holds a reference on every device it names, so the bridged learner can build
 * a group from it and drop what a departing device takes with it. What the
 * bridged learner reports back is written under ft_mc_route_lock, a leaf, so
 * the routed learner can read it while holding its own lock. */
struct ft_mc_route {
	struct list_head list;
	bool linked;
	/* Where the parent VIF receives the stream: the bridge, and either the
	 * VLAN whose 802.1Q device the VIF is (`tagged`), or every VLAN the
	 * bridge's own membership leaves untagged, which surfaces on the bridge
	 * device itself. */
	struct net_device *bridge;
	u16 vid;
	bool tagged;
	u8 family;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	/* The routed copies, and the smallest MTU any of them leaves by: the
	 * bound the bridged group holds against the port the stream actually
	 * arrives on, which only that group knows. */
	struct cdx_mc_listener listener[CDX_MC_MAX_LISTENERS];
	u8 listeners;
	u32 mtu;
	/* Whether the bridge handed its streams to the host at the last
	 * publication, which is when the route names its stream's flow into
	 * existence: see ft_mc_route_learns(). A bridge turning promiscuous
	 * raises no event at all, so each publication -- one per refresh of
	 * the routed learner -- compares. Under ft_mc_lock. */
	bool learns;
	/* Reported back. `in_tags` is the ingress framing the counters include,
	 * which the fold into the MFC's counters takes off again. */
	bool carried;
	u8 in_tags;
	struct cdx_ft_counters stats;
};

/* A VIF on a bridge, in an ft_mc_route's terms: the host receives that bridge
 * VLAN's frames there, and ipmr sees them whether or not it has a route. */
struct ft_mc_tap {
	struct net_device *bridge;
	u16 vid;
	bool tagged;
	u8 family;
};

/* A gateway has one or two. Past this the table stops naming them and every
 * bridge VLAN counts as one the host routes, which keeps groups in software
 * rather than starving a VIF nothing recorded. */
#define FT_MC_TAPS	8

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
 * holds RTNL.
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
static u32 ft_mc_link_mtu(const struct net_device *dev, u8 family)
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

/* How many ports one membership keeps a record of: more than a board has.
 *
 * A membership's ports say only that it stands -- which ports a flow's frames
 * go to is the bridge's answer, not this list -- so a join past the last slot
 * is simply not recorded. The cost is bounded and safe: the membership may
 * retire while that port still holds it, which takes its flows back to the
 * bridge in software rather than carrying them for a set missing somebody.
 */
#define FT_MC_MAX_MEMBERS	(CDX_MC_MAX_LISTENERS + 1)

/* The shape a flow's frames arrive in: their own Ethernet pair, and whether
 * they carry the group's VLAN as a tag. The rest of a bridged entry's key --
 * the port, the source and the group -- is the flow's identity; this is what
 * can change under it. */
struct ft_mc_stream {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	bool tagged;
};

/* A membership the bridge has told us about.
 *
 * Keyed on (bridge, br_ip), which is what the MDB itself is keyed on: the
 * group address, the VLAN, the address family, and -- for a source-specific
 * membership -- the source. It installs nothing. It says which flows are
 * worth learning and keeping, and a change to it says which flows to ask the
 * bridge about again.
 */
struct ft_mc_group {
	struct list_head list;
	struct net_device *bridge;
	struct br_ip addr;
	/* The ports holding the membership, each pinned. */
	struct net_device *port[FT_MC_MAX_MEMBERS];
	u8 ports;
	/* The bridge itself has joined. The flows this membership names hear
	 * the same from the bridge's answer, and are refused rather than
	 * carried: a hardware entry replicates to ports and the frame never
	 * reaches the CPU, which would starve a local listener silently. Kept
	 * here because it keeps the membership: br_multicast_host_join() emits
	 * it before any port group. */
	bool host;
};

/* A flow: one source's frames of a group as they arrive on one bridge port,
 * which is exactly what one classifier entry matches, and so what the
 * hardware carries. Learned from traffic -- see the traffic half below -- and
 * kept while a membership or a route names it.
 *
 * `addr` is the group, its VLAN and family, and the source; `in` the port.
 * Two sources of a group are two flows, and so is one source arriving on two
 * ports: the bridge forwards each frame on its own, and so does each entry.
 */
struct ft_mc_flow {
	struct list_head list;
	struct net_device *bridge;
	struct br_ip addr;
	struct net_device *in;
	/* The frames' own Ethernet pair, which a bridged entry is keyed on and
	 * every bridged copy is rebuilt with, and whether they carry the
	 * group's VLAN as a tag or arrive untagged on the port's PVID, which
	 * is the one shape the root accepts. */
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	bool in_tagged;
	struct cdx_mc_group *hw;
	/* The flow in another shape reached the CPU while an entry was
	 * installed -- the only way it can, because the entry's own frames
	 * never do: a sender whose MAC changed, a tag the port now carries. It
	 * takes over the key once the installed one has gone idle, and not
	 * while that one is still carrying traffic, so two live senders do not
	 * trade one entry back and forth. */
	struct ft_mc_stream next;
	bool has_next;
	/* What the classifier had counted at the last refresh, and whether it
	 * has counted nothing since. An idle entry is how `next` takes over.
	 * `count_suspect` is a sample below the baseline just seen; see
	 * ft_mc_count_delta(). */
	u64 hw_packets;
	u64 hw_bytes;
	bool count_suspect;
	bool idle;
	/* When the entry last counted a frame, or was added, and how long it
	 * may then count nothing before the stream is taken to have stopped:
	 * the bridge's group membership interval for the flow's VLAN, read at
	 * each derivation, so the entry ages on the clock the bridge ages its
	 * memberships by. Zero never ages. */
	unsigned long active;
	unsigned long age;
	/* What the bridge would do with the flow's frames, asked under RTNL at
	 * the last derivation; see ft_mc_flow_derive(). `port` holds the
	 * bridged copies with the tags each leaves with, every device pinned;
	 * `local` the BR_MCAST_TO_HOST_* reasons the bridge also hands a frame
	 * up; `error` what the bridge said instead of a port set, or
	 * -EOPNOTSUPP for a port the hardware cannot carry, which refuses the
	 * whole flow: a matched frame never reaches the bridge, so a port left
	 * out of the hardware set would not fall back to software, it would
	 * stop receiving. */
	struct cdx_mc_listener port[CDX_MC_MAX_LISTENERS];
	u8 ports;
	unsigned int local;
	int error;
	bool derived;
	/* The routed half of the flow's stream; see the section on the
	 * learners' streams above. `route` is the published route whose
	 * source and bridge VLAN are this flow's, matched by the worker and
	 * never owned: the routed learner withdraws a route before freeing
	 * it, which clears every pointer to it here. `carried_route` is the
	 * one the installed entry was built with, which is what tells the
	 * routed learner its copies are in hardware. `routed_host` says the
	 * bridge hands the flow's frames to a VIF, so the host routes them and
	 * the flow is carried only together with its route. */
	struct ft_mc_route *route;
	struct ft_mc_route *carried_route;
	bool routed_host;
	/* Another flow has the same classifier key -- the same port, sender
	 * and source, on another VLAN of the bridge -- so neither may be
	 * installed: the key names no VLAN, and one root validates one tag. */
	bool contested;
	/* The derivation is due (`dirty`); an answer changed and the hardware
	 * has not caught up (`stale`); the flow cannot exist any more -- its
	 * ingress went, left the bridge, or no longer resolves to its VLAN --
	 * and the worker is to take it out (`gone`). */
	bool dirty;
	bool stale;
	bool gone;
	/* The chain `hw` was built from, whole -- the routed copies riding it
	 * included -- recorded with `hw` inside the transaction that built it,
	 * and what the egress drain replaces it with. It holds a reference on
	 * every device it names (ft_mc_chain_record()); a device going away
	 * empties it (ft_mc_device_gone()). No listeners means none is
	 * recorded, and nothing held. */
	struct cdx_mc_group_spec hw_spec;
	/* The installed chain may hold an entry built before an egress change
	 * on a port it copies out of -- an HTB tree, the DSCP map -- naming the
	 * queue, or reading the map, of the state before it. Unlike `stale`,
	 * which a pass consumes when it picks the flow, it is cleared only by a
	 * build that started after the last change (ft_egress_changes), since
	 * a caller waiting for the change to reach the hardware reads it. */
	bool egress_stale;
	/* A source of the group was turned away at FT_MC_MAX_FLOWS while this
	 * flow held its place, and counted in mcast_refused. The next one is
	 * not counted again until the group's flows change: a group every host
	 * sends to would otherwise count one on every frame the dedup slots
	 * could not hold. */
	bool turned;
	/* Consecutive failed installs. A failure is not permanent -- a port
	 * that lost carrier gets it back -- but retrying on every frame of a
	 * live stream would spin the worker against a flow that cannot be
	 * carried, so it is bounded and then reported. */
	u8 retries;
};

/* Enough to ride out a transient -- a port bouncing, a moment of capacity
 * pressure; the tries are a refresh interval apart -- and few enough that a
 * flow which genuinely cannot be carried stops costing anything. A changed
 * answer from the bridge starts the count again. */
#define FT_MC_MAX_RETRIES 4

/* Sources one group may have in hardware on one bridge. An IPTV channel has
 * one; a group every host on a LAN sends to -- SSDP's 239.255.255.250 is the
 * common one -- has as many as there are hosts, and each would take an entry
 * the table is short of. Past this a source is left to the bridge. */
#define FT_MC_MAX_FLOWS	8

static LIST_HEAD(ft_mc_groups);
static LIST_HEAD(ft_mc_flows);
static DEFINE_MUTEX(ft_mc_lock);
static unsigned int ft_mc_count, ft_mc_flow_count, ft_mc_installed;
static u64 ft_mc_refused, ft_mc_install_errors;
/* Installed groups of either learner marked for a rebuild because a port they
 * copy out of changed its egress; see ft_mc_egress_changed(). A build racing
 * the change compares ft_egress_changes instead. */
static atomic64_t ft_mc_egress_rebuilds = ATOMIC64_INIT(0);
static void ft_mc_work_fn(struct work_struct *work);
static DECLARE_WORK(ft_mc_work, ft_mc_work_fn);
/* How often an installed flow's entry is asked what it has counted, and every
 * flow's answer is asked of the bridge again. The routed learner's fold and
 * re-derivation run at the same pace, for the same reason: some of what the
 * bridge decides by -- a querier appearing or timing out -- changes with no
 * notification at all. */
#define FT_MC_REFRESH_INTERVAL	(5 * HZ)
static void ft_mc_refresh_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_mc_refresh, ft_mc_refresh_fn);
/* Set once the adapter is tearing down, so a queued worker that runs during
 * exit does nothing rather than reaching a backend that is going away. */
static bool ft_mc_stopping;
/* Something outside this learner changed an answer it had already given, with
 * no membership event to say so: a device MTU changed, and a flow whose ports
 * no longer bound its ingress has to leave hardware rather than wait for its
 * membership to change. Every flow is reconsidered on the next pass,
 * installed ones included. */
static bool ft_mc_recheck;
/* A bridge hook other than the learner's own was registered at the worker's
 * last pass, and no flow may be carried: see ft_mc_bridge_filtered(). Written
 * by the worker under ft_mc_lock. */
static bool ft_mc_filtered;
/* The routes and taps the routed learner publishes, under ft_mc_lock; what
 * each route is told back, under the leaf below. */
static LIST_HEAD(ft_mc_routes);
static DEFINE_SPINLOCK(ft_mc_route_lock);
static struct ft_mc_tap ft_mc_taps[FT_MC_TAPS];
static unsigned int ft_mc_tap_count;
/* Until the routed learner first says where its VIFs are, they may be
 * anywhere. */
static bool ft_mc_taps_overflow = true;

static void ft_mc_kick_all(void)
{
	if (READ_ONCE(ft_mc_stopping))
		return;
	WRITE_ONCE(ft_mc_recheck, true);
	schedule_work(&ft_mc_work);
}

/* Defined with the traffic half below, whose dedup slots it clears; called
 * wherever the answer a recorded frame got may have changed. */
static void ft_mc_forget_seen(void);

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
static bool ft_mc_link_local(const struct br_ip *addr)
{
	if (addr->proto == htons(ETH_P_IP))
		return ipv4_is_local_multicast(addr->dst.ip4);
	return __ipv6_addr_src_scope(__ipv6_addr_type(&addr->dst.ip6)) <=
	       IPV6_ADDR_SCOPE_LINKLOCAL;
}

/* Whether a membership and a flow are about the same group on the same bridge
 * VLAN, which is what makes a change to the one a question about the other. */
static bool ft_mc_same_vlan_group(const struct br_ip *a, const struct br_ip *b)
{
	return a->proto == b->proto && a->vid == b->vid &&
	       !memcmp(&a->dst, &b->dst, sizeof(a->dst));
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
 * A route riding the flow is part of the same set. The union has to fit one
 * group, and a routed copy framed exactly like a bridged one -- one port, one
 * tag stack, two VLANs untagged on it -- is refused rather than programmed as
 * a second entry the backend would take for a duplicate.
 */
static bool ft_mc_carriable(const struct ft_mc_flow *f)
{
	const struct ft_mc_route *r = f->route;
	u8 i, j;

	if (f->error)
		return false;
	if (!r)
		return true;
	if (f->ports + r->listeners > CDX_MC_MAX_LISTENERS)
		return false;
	for (j = 0; j < r->listeners; j++)
		for (i = 0; i < f->ports; i++) {
			const struct cdx_mc_listener *p = &f->port[i];

			if (p->dev == r->listener[j].dev &&
			    p->vlans == r->listener[j].vlans &&
			    !memcmp(p->vlan, r->listener[j].vlan, sizeof(p->vlan)))
				return false;
		}
	return true;
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
 * test at all. A flow whose ingress has gone has nothing left to bound.
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
	in_mtu = READ_ONCE(f->in->mtu);
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
static void ft_mc_drop_next(struct ft_mc_flow *f)
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
	/* Field by field: the listener struct has tail padding. */
	for (i = 0; i < a->listeners; i++)
		if (a->listener[i].dev != b->listener[i].dev ||
		    a->listener[i].vlans != b->listener[i].vlans ||
		    a->listener[i].routed != b->listener[i].routed ||
		    memcmp(a->listener[i].vlan, b->listener[i].vlan,
			   sizeof(a->listener[i].vlan)))
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
static bool ft_mc_route_publish(struct ft_mc_route *r,
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
			 * owner folds it from zero again from here. */
			spin_lock_bh(&ft_mc_route_lock);
			memset(&r->stats, 0, sizeof(r->stats));
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
 * published, and after ft_mc_exit(), which unlinks every route itself. */
static void ft_mc_route_withdraw(struct ft_mc_route *r)
{
	struct ft_mc_flow *f;

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
	r->carried = false;
	memset(&r->stats, 0, sizeof(r->stats));
	spin_unlock_bh(&ft_mc_route_lock);
}

/* What the bridged learner last said about a route: whether its copies are in
 * hardware, and if so what the carrying group counted and the ingress framing
 * that count includes. Takes only the leaf lock, so it may be called holding
 * ft_mr_lock. */
static bool ft_mc_route_state(struct ft_mc_route *r,
			      struct cdx_ft_counters *stats, u8 *in_tags)
{
	bool carried;

	spin_lock_bh(&ft_mc_route_lock);
	carried = r->carried;
	*stats = r->stats;
	*in_tags = r->in_tags;
	spin_unlock_bh(&ft_mc_route_lock);
	return carried;
}

/* Replace the table of VIFs on bridges. `taps` is borrowed, with every bridge
 * in it held by the caller for the call. */
static void ft_mc_taps_publish(const struct ft_mc_tap *taps, unsigned int n,
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
static bool ft_mc_route_reaches(const struct ft_mc_route *r,
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

/* Whether the bridge also hands this flow's frames to the host for a reason no
 * route can stand in for: the host joined the group, or nothing is snooping
 * and the bridge floods it up with everything else. */
static bool ft_mc_host_wants(const struct ft_mc_flow *f)
{
	return f->local & (BR_MCAST_TO_HOST_JOINED | BR_MCAST_TO_HOST_FLOOD);
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
 * its frames; see ft_mc_bridge_filtered(). */
static bool ft_mc_installable(const struct ft_mc_flow *f)
{
	const struct ft_mc_route *r = ft_mc_live_route(f);

	return !ft_mc_filtered &&
	       f->derived && f->in && !f->gone && !ft_mc_host_wants(f) &&
	       (f->ports || r) && (r || !f->routed_host) &&
	       ft_mc_carriable(f) && ft_mc_mtu_bounded(f);
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
	/* The bridge's copies, as its answer named them: never the ingress,
	 * which br_multicast_list_ports() leaves out as should_deliver() does. */
	for (i = 0; i < f->ports; i++)
		spec->listener[spec->listeners++] = f->port[i];
	/* The routed copies take the egress port's address and one hop off,
	 * as ipmr's would; a routed copy back out of the ingress port is one
	 * ipmr sends too, since it leaves by another VIF. */
	for (i = 0; r && i < r->listeners; i++) {
		spec->listener[spec->listeners] = r->listener[i];
		spec->listener[spec->listeners++].routed = true;
	}
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
	list_for_each_entry(g, &ft_mc_groups, list) {
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
		list_move(&g->list, dead);
		ft_mc_count--;
		retired = true;
	}
	list_for_each_entry_safe(f, ftmp, &ft_mc_flows, list) {
		if (!f->gone && ft_mc_flow_named(f))
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
			if (g)
				g->host = false;
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

struct ft_mc_seen {
	int bridge_ifindex;
	int in_ifindex;
	struct br_ip addr;
	union nf_inet_addr src;
	/* The frame's own Ethernet pair, which a bridged group is keyed on and
	 * which every copy is rebuilt with; see the bridged multicast tables in
	 * cdx_ioctl.h. */
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	/* The frame carried the group's VLAN as an 802.1Q tag, rather than
	 * arriving untagged and being given it by the port's PVID. The root
	 * accepts exactly one of the two shapes, and it has to be the one the
	 * stream has. */
	bool tagged;
};

/* Deep enough to absorb the few frames between an observation and the worker
 * installing its entry, and no deeper: past that the stream is either
 * offloaded or its flow was refused, and in both cases further observations
 * describe nothing new. Overflow drops the newest, which costs a retry on the
 * next frame rather than anything permanent. */
#define FT_MC_RING 16
static struct ft_mc_seen ft_mc_ring[FT_MC_RING];
static unsigned int ft_mc_ring_head, ft_mc_ring_tail;
static DEFINE_SPINLOCK(ft_mc_ring_lock);
/* The last few things recorded, so streams at line rate do not fill the ring
 * with restatements of the same facts between two runs of the worker. Several,
 * because the hook stays registered while flows are refused: two refused
 * streams interleaving would otherwise each restate itself on every frame.
 *
 * That makes them a promise as well as a filter: the same frame is not
 * recorded again until the slots are forgotten, however long the stream runs.
 * So they are forgotten (ft_mc_forget_seen()) whenever the answer a recorded
 * frame got may have changed -- a membership or a route created that could
 * now name it, a flow retired, an entry taken out of hardware -- and at no
 * other time: forgetting them after every drain would record every frame of a
 * stream that never installs. A cleared slot names ifindex zero, which no
 * frame arrives on. */
#define FT_MC_SEEN_SLOTS 8
static struct ft_mc_seen ft_mc_last[FT_MC_SEEN_SLOTS];
static unsigned int ft_mc_last_next;
static u64 ft_mc_observed, ft_mc_dropped, ft_mc_hook_errors;
static bool ft_mc_hooked;
static DEFINE_MUTEX(ft_mc_hook_lock);

/* Let the next frame of any stream be recorded again, however it compares
 * with the last. Called with ft_mc_lock held, after the change that makes it
 * worth recording is visible on the lists, so the worker that drains the frame
 * matches it against the new state. */
static void ft_mc_forget_seen(void)
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

/* Put one observation in the ring for the worker, unless it restates one of
 * the last recorded or the ring is full. Returns whether it was recorded.
 * Called from the hook, in softirq. */
static bool ft_mc_record(const struct ft_mc_seen *seen)
{
	bool recorded = false;
	unsigned int next, i;

	spin_lock(&ft_mc_ring_lock);
	for (i = 0; i < FT_MC_SEEN_SLOTS; i++)
		if (ft_mc_seen_eq(seen, &ft_mc_last[i]))
			goto out;	/* recorded already, and nothing has changed since */
	next = (ft_mc_ring_head + 1) % FT_MC_RING;
	if (next == ft_mc_ring_tail) {
		ft_mc_dropped++;
		goto out;
	}
	ft_mc_ring[ft_mc_ring_head] = *seen;
	ft_mc_ring_head = next;
	ft_mc_last[ft_mc_last_next] = *seen;
	ft_mc_last_next = (ft_mc_last_next + 1) % FT_MC_SEEN_SLOTS;
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
static bool ft_bridge_hooked(unsigned int hooks)
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
static bool ft_mc_bridge_filtered(void)
{
	return ft_bridge_hooked(BIT(NF_BR_PRE_ROUTING) | BIT(NF_BR_FORWARD) |
				BIT(NF_BR_POST_ROUTING));
}

/* The hook exists only while a membership or a route could name a flow. A box
 * with neither pays the static key in nf_hook_bridge_pre() and nothing else.
 *
 * Registration sleeps, so this runs from the worker. Called without
 * ft_mc_lock. */
static void ft_mc_hook_sync(bool wanted)
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
static bool ft_mc_same_key(const struct ft_mc_flow *a, const struct ft_mc_flow *b)
{
	return a->in && a->in == b->in && a->addr.proto == b->addr.proto &&
	       !memcmp(&a->addr.dst, &b->addr.dst, sizeof(a->addr.dst)) &&
	       !memcmp(&a->addr.src, &b->addr.src, sizeof(a->addr.src)) &&
	       ether_addr_equal(a->src_mac, b->src_mac) &&
	       ether_addr_equal(a->dst_mac, b->dst_mac);
}

/* Take what the hook observed: a frame of a flow already known, or the first
 * of one that something names. Called with ft_mc_lock held. */
static void ft_mc_observe(const struct ft_mc_seen *seen)
{
	bool counted = false, shared = false;
	struct net_device *bridge, *in;
	struct ft_mc_flow *f, *o;
	unsigned int flows = 0;
	struct br_ip key;

	lockdep_assert_held(&ft_mc_lock);
	ft_mc_seen_key(seen, &key);
	f = ft_mc_flow_find(&key, seen);
	if (f) {
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
		 * phase is stale. The shape it had is a different answer now,
		 * and its next frame has to be able to say so. */
		ft_mc_drop_next(f);
		if (seen->tagged != f->in_tagged)
			f->dirty = true;
		ether_addr_copy(f->dst_mac, seen->dst_mac);
		ether_addr_copy(f->src_mac, seen->src_mac);
		f->in_tagged = seen->tagged;
		f->retries = 0;
		f->stale = true;
		ft_mc_forget_seen();
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
	 * nothing names that way and nothing carries, which gives way at no
	 * cost to the hardware. So a source an SSM listener asked for is not
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
		if (f->gone || f->bridge != bridge ||
		    !ft_mc_same_vlan_group(&f->addr, &key))
			continue;
		flows++;
		counted |= f->turned;
		shared |= f->derived && ft_mc_host_wants(f);
		if (!f->hw && !ft_mc_source_named(bridge, &f->addr))
			o = f;
	}
	if (flows >= FT_MC_MAX_FLOWS) {
		if (!o || shared || ft_mc_filtered ||
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
	}
	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f) {
		dev_put(in);
		/* Nothing else would ask for the frame again. */
		ft_mc_forget_seen();
		return;
	}
	dev_hold(bridge);
	f->bridge = bridge;
	f->addr = key;
	f->in = in;
	ether_addr_copy(f->dst_mac, seen->dst_mac);
	ether_addr_copy(f->src_mac, seen->src_mac);
	f->in_tagged = seen->tagged;
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
static void ft_mc_adopt_next(struct ft_mc_flow *f)
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
static bool ft_mc_shape_resolves(struct net_device *bridge,
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

static bool ft_mc_listeners_same(const struct cdx_mc_listener *a,
				 const struct cdx_mc_listener *b, u8 n)
{
	u8 i;

	/* Field by field: the listener struct has tail padding. */
	for (i = 0; i < n; i++)
		if (a[i].dev != b[i].dev || a[i].vlans != b[i].vlans ||
		    memcmp(a[i].vlan, b[i].vlan, sizeof(a[i].vlan)))
			return false;
	return true;
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
 * them in. The ports the bridge names are borrowed until RTNL is released;
 * the flow pins the ones it keeps. */
static void ft_mc_flow_derive(struct ft_mc_flow *f)
{
	struct net_device *chosen[CDX_MC_MAX_LISTENERS];
	struct cdx_mc_listener port[CDX_MC_MAX_LISTENERS];
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
	    !ft_mc_shape_resolves(f->bridge, f->in, f->next.tagged, f->addr.vid))
		ft_mc_drop_next(f);
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
	if (f->derived && error == f->error && local == f->local &&
	    ports == f->ports && ft_mc_listeners_same(port, f->port, ports))
		return;
	if (error && (!f->derived || !f->error))
		ft_mc_refused++;
	ft_mc_flow_release_ports(f);
	for (i = 0; i < ports; i++)
		dev_hold(port[i].dev);
	memcpy(f->port, port, sizeof(f->port));
	f->ports = ports;
	f->local = local;
	f->error = error;
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
	LIST_HEAD(dead);
	LIST_HEAD(gone);

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
		mutex_unlock(&ft_mc_lock);
	}

	ft_mc_drain();

	/* Ask the bridge about every flow whose answer may have changed. The
	 * snapshot and the VLAN lookups need RTNL, taken before ft_mc_lock as
	 * the switchdev handler takes them, and neither is held across the
	 * transaction below. */
	mutex_lock(&ft_mc_lock);
	list_for_each_entry(f, &ft_mc_flows, list)
		derive |= f->dirty;
	mutex_unlock(&ft_mc_lock);
	if (derive) {
		rtnl_lock();
		mutex_lock(&ft_mc_lock);
		list_for_each_entry(f, &ft_mc_flows, list)
			if (f->dirty && !ft_mc_stopping)
				ft_mc_flow_derive(f);
		mutex_unlock(&ft_mc_lock);
		rtnl_unlock();
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
		bool added = false;
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
				f->contested = ft_mc_installable(f) &&
					       ft_mc_key_contested(f);
				if (!ft_mc_installable(f) || f->contested) {
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
		if (!target->contested && ft_mc_installable(target) &&
		    target->retries < FT_MC_MAX_RETRIES)
			ft_mc_flow_spec(target, &spec);
		if (spec.listeners) {
			/* The route whose copies the spec carries, if any. */
			if (ft_mc_live_route(target))
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
		if (swap && hw) {
			cdx_mc_group_del(&hw);
			ft_mc_installed--;
			swapped = true;
		}
		if (!spec.listeners) {
			/* Became ineligible: take it out of hardware and keep
			 * the flow, which may become installable again when the
			 * host leaves, a port returns or a route arrives. */
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
			if (rc) {
				ft_mc_install_errors++;
				hw = NULL;
			} else {
				ft_mc_installed++;
				added = true;
			}
		}

		mutex_lock(&ft_mc_lock);
		target->hw = hw;
		/* What the entry was built with. A route withdrawn while the
		 * spec was being taken has already cleared the flow's pointer and
		 * marked it for another pass, and must not be recorded: its owner
		 * is free to release it the moment it is off the list. */
		if (spec.listeners && !rc)
			target->carried_route = route && target->route == route ?
						route : NULL;
		if (!hw)
			target->carried_route = NULL;
		/* And the chain itself, whole, for the egress drain to replace
		 * the entry with, holding what it names; nothing is recorded for
		 * an entry this pass took out, or one it could not build. */
		if (hw && spec.listeners && !rc)
			ft_mc_chain_record(target, &spec);
		else if (!hw)
			ft_mc_chain_forget(target);
		/* A new entry has counted nothing yet, is not idle until a
		 * whole refresh says so, and ages from now. */
		if (added) {
			target->hw_packets = target->hw_bytes = 0;
			target->count_suspect = false;
			target->idle = false;
			target->active = jiffies;
		}
		/* A chain built whole after the last egress change is current;
		 * one built across a change is not, and is built again -- the
		 * change could not mark a flow that had no entry yet. Nothing
		 * installed is nothing stale. */
		if (!hw) {
			target->egress_stale = false;
		} else if (atomic64_read(&ft_egress_changes) != changes) {
			target->egress_stale = true;
			target->stale = true;
		} else if (spec.listeners && !rc) {
			target->egress_stale = false;
		}
		if (spec.listeners && rc) {
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
		if (spec.listeners) {
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
static bool ft_mc_count_delta(u64 *base_packets, u64 *base_bytes,
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
	}
	f->idle = counted && !packets;
	if (f->idle && f->has_next)
		f->stale = true;
	/* Aged only on a sample that answers: one below the baseline cannot
	 * tell a stream that stopped from one that is running. */
	if (counted && f->age && time_after(now, f->active + f->age))
		f->gone = true;
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
static bool ft_mc_swdev_obj(unsigned long event,
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
static void ft_mc_replay(void)
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
static void ft_mc_device_gone(struct net_device *dev, bool unregistering)
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
static void ft_mc_bridge_changed(struct net_device *dev)
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
static void ft_mc_port_moved(struct net_device *dev, struct net_device *left)
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
static unsigned int ft_mc_egress_mark(const struct net_device *dev)
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
 * Called under the RTNL a tc command holds, so the worker, which takes RTNL
 * to ask the bridge, is never waited for. Nor is anything decided: the port's
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
static int ft_mc_egress_drain(const struct net_device *dev)
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

static void ft_mc_exit(void)
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
}

/* Why a flow is not being replicated, for an operator looking at a stream
 * that is not offloaded. "Pending" alone would answer several different
 * questions with one word. */
static const char *ft_mc_state(const struct ft_mc_flow *f)
{
	if (!f->derived)
		return "pending";
	/* Before "installed", deliberately: a flow whose answer has just
	 * changed is still in the table for one more worker pass, and what an
	 * operator needs to read in that window is the reason it is about to
	 * come out. A bridge filter hook first: it refuses every flow, and
	 * removing it is what would let this one in. */
	if (ft_mc_filtered)
		return "refused-filter";
	if (ft_mc_host_wants(f))
		return "refused-host";
	/* The host routes this stream and no route of it can ride the flow. */
	if (f->routed_host && !ft_mc_live_route(f))
		return "refused-routed";
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
	if (f->hw)
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
static void ft_mc_rows(struct seq_file *seq)
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

/* ------------------------------------------------------- Routed multicast
 *
 * The second learner, and the one with nothing to learn. Where a bridge's MDB
 * describes a permission that traffic has to complete -- see the section above
 * -- ipmr's MFC is already the classifier's key: mfc_origin and mfc_mcastgrp
 * are an exact (S,G), mfc_parent names the interface the stream arrives on,
 * and ttls[] is the replication list. Every fact the bridged learner had to
 * recover from frames is stated outright here, so nothing is ever waiting on
 * a source. What the MFC does not say is whether the firewall lets the
 * stream through, and a copy of it has to be seen leaving every oif before
 * the group is carried; see the section on what Linux itself forwarded.
 *
 * Both learners use the same encoder, with explicit forwarding semantics.
 * This learner requests a routed root, which decrements TTL or hop limit;
 * the bridge learner preserves it. The parser refuses to classify a frame
 * arriving with 0 or 1, matching the router's `ttl > 1` rule. Listener entries
 * rebuild Ethernet with the egress port's address and the group's mapped
 * multicast destination, as this routed path requires.
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
 * it holds until the outcome is recorded. Three rules hold, and
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
 *     the other, and the one path that waits for RTNL while holding the
 *     transaction is the legacy FCI command plane, which is sealed once the
 *     flowtable owns the hardware. So that order closes no cycle, and the
 *     worker, which may wait for RTNL, never holds the transaction then. The
 *     bridged learner's drain, ft_mc_egress_drain(), is the same.
 *   - ft_mr_lock and ft_mc_lock are never nested. The bridged side only
 *     kicks this worker; the routed side reads bridge state from the kernel,
 *     and publishes its routes and taps through functions that take
 *     ft_mc_lock themselves, called with ft_mr_lock released.
 */

/* Enough to ride out a transient -- a port bouncing, a moment of capacity
 * pressure; the tries are a refresh interval apart -- and few enough that a
 * group which genuinely cannot be carried stops costing anything. Anything
 * that changes the answer resets it. */
#define FT_MR_MAX_RETRIES	4
/* One name per oif, and an oif produces at least one listener, so the listener
 * ceiling bounds the count. */
#define FT_MR_OIF_TEXT		(CDX_MC_MAX_LISTENERS * (IFNAMSIZ + 1))
/* mlxsw folds its hardware counters every five seconds and nothing here wants
 * to be finer: the numbers feed `ip -s mroute` and a daemon's SIOCGETSGCNT,
 * both of which an operator reads by hand. */
#define FT_MR_STATS_INTERVAL	(5 * HZ)

enum ft_mr_state {
	/* Eligible, and the worker has not installed it yet. */
	FT_MR_PENDING,
	FT_MR_INSTALLED,
	/* Eligible and routed through a bridge, and the bridged group that
	 * would carry its copies is not in hardware: waiting for its stream,
	 * or refused for a reason its own /proc row names. */
	FT_MR_BRIDGED,
	/* Eligible, and Linux has not yet been seen forwarding it to every
	 * oif under the ruleset as it stands; see the section on what Linux
	 * itself forwarded. */
	FT_MR_UNCONFIRMED,
	/* Everything from here down is a refusal, in the order the contract
	 * tests them. ft_mr_refusal() depends on the four above staying below
	 * the first of them. */
	FT_MR_REFUSED_TABLE,
	FT_MR_REFUSED_POLICY,
	FT_MR_REFUSED_WILDCARD,
	FT_MR_REFUSED_SCOPE,
	FT_MR_REFUSED_INGRESS,
	FT_MR_REFUSED_HOST,
	FT_MR_REFUSED_THRESHOLD,
	FT_MR_REFUSED_LISTENER,
	FT_MR_REFUSED_MTU,
	/* A copy leaves through a bridge whose own output hooks would see it;
	 * see ft_mr_admit(). */
	FT_MR_REFUSED_FILTER,
	FT_MR_REFUSED_CONTESTED,
	FT_MR_REFUSED_FAILED,
	FT_MR_REFUSED_RESYNC,
};

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
	case FT_MR_REFUSED_POLICY:	return "refused-policy";
	case FT_MR_REFUSED_WILDCARD:	return "refused-wildcard";
	case FT_MR_REFUSED_SCOPE:	return "refused-scope";
	case FT_MR_REFUSED_INGRESS:	return "refused-ingress";
	case FT_MR_REFUSED_HOST:	return "refused-host";
	case FT_MR_REFUSED_THRESHOLD:	return "refused-threshold";
	case FT_MR_REFUSED_LISTENER:	return "refused-listener";
	case FT_MR_REFUSED_MTU:		return "refused-mtu";
	case FT_MR_REFUSED_FILTER:	return "refused-filter";
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

struct ft_mr_watch;

/* One routed group: an MFC entry this learner has an opinion about.
 *
 * Keyed on the mfc pointer, which is exact -- ipmr emits ENTRY_REPLACE against
 * the same pointer when thresholds or the parent change, ENTRY_ADD for a new
 * one, and ENTRY_DEL for that one -- and safe, because the reference taken
 * with mr_cache_hold() keeps the object from being freed and its address from
 * being reused underneath us.
 *
 * `in` and `listener[]` are what the last successful derivation installed,
 * each pinned for as long as the hardware entry names it. They are what /proc
 * reports, so they describe the hardware rather than the intent -- except for
 * a group routed through a bridge, whose set is what it published, and whose
 * state says whether the bridged group carries it.
 */
struct ft_mr_group {
	struct list_head list;
	struct mr_mfc *mfc;
	u32 table;
	u8 family;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	struct net_device *in;
	/* The tags the stream arrives with on `in`, outermost first: what the
	 * root validates, and what the counter fold takes off each frame. */
	struct cdx_ft_vlan in_vlan[CDX_FT_VLAN_MAX];
	u8 in_tags;
	/* For a parent VIF on a bridge, in place of `in`: the bridge, pinned,
	 * and where on it the VIF receives -- see struct ft_mc_route. `mtu` is
	 * the narrowest path a copy leaves by, which the bridged group bounds
	 * against the port the stream arrives on. */
	struct net_device *via;
	u16 via_vid;
	bool via_tagged;
	u32 mtu;
	struct cdx_mc_listener listener[CDX_MC_MAX_LISTENERS];
	u8 listeners;
	char oifs[FT_MR_OIF_TEXT];
	struct cdx_mc_group *hw;
	/* The ingress `hw` was added with, held from the add to the delete.
	 * The backend borrows it and unsubscribes the port's multicast address
	 * through it when the entry is deleted, so it has to outlive `in`,
	 * which a device going away releases at once. Only the worker and
	 * teardown add or delete an entry, and only they touch this. */
	struct net_device *hw_in;
	/* What a group routed through a bridge publishes; allocated at its
	 * first publication and freed with the group. */
	struct ft_mc_route *route;
	/* Which of its oifs Linux has been seen forwarding it to; see the
	 * section on what Linux itself forwarded. Replaced by the worker when
	 * the oifs change, under ft_mr_lock as well as the table's own lock,
	 * so /proc may read it under either. */
	struct ft_mr_watch *watch;
	/* How much of the hardware's count the MFC entry already holds, raw as
	 * it is reported: `hw`'s own, which a group the worker has just added
	 * counts from zero again, or for a group routed through a bridge the
	 * route's, which only ever grows. `fold_suspect` is a sample below it
	 * just seen; see ft_mc_count_delta(). */
	u64 folded_packets;
	u64 folded_bytes;
	bool fold_suspect;
	enum ft_mr_state state;
	/* MFC_OFFLOAD is set on the kernel's entry. */
	bool offloaded;
	bool dirty;
	/* The worker has picked the group and not yet recorded the outcome.
	 * `hw` and the installed set stay the group's meanwhile: the worker
	 * builds and records inside one transaction (ft_mr_record()), so
	 * nothing else that takes the transaction sees them half-changed. */
	bool busy;
	/* The installed listener chain may hold an entry built before an
	 * egress change on a port it copies out of -- an HTB tree, the DSCP
	 * map -- naming the queue, or reading the map, of the state before it.
	 * The next pass replaces the chain even when the plan has not changed.
	 * Cleared only by a rebuild that started after the last change
	 * (ft_egress_changes), because a caller waiting for the change reads it
	 * (ft_mr_egress_drain()). */
	bool egress_stale;
	/* The spec `hw` was built from, whole -- ingress tags included -- and
	 * what the egress drain replaces it with. It borrows the installed
	 * set's pinned devices, and goes with that set (ft_mr_release_set()).
	 * No listeners means none is recorded. */
	struct cdx_mc_group_spec hw_spec;
	/* The kernel deleted the entry; retire and forget it. */
	bool gone;
	bool seen;
	u8 retries;
};

/* What one derivation produced, with a reference of its own on every device in
 * it. Either the group adopts the whole thing or ft_mr_plan_put() returns it;
 * there is no half-adopted state, because the backend borrows exactly these
 * pointers and a group that owned some of them would name one it did not. */
struct ft_mr_plan {
	struct cdx_mc_group_spec spec;
	char oifs[FT_MR_OIF_TEXT];
	u8 in_tags;
	/* A parent VIF on a bridge: `spec.in` is empty and these say where the
	 * stream is received instead; the copies are published, not installed. */
	struct net_device *via;
	u16 via_vid;
	bool via_tagged;
	u32 mtu;
	/* The MFC oifs by ifindex, which is what a copy is seen leaving by at
	 * POST_ROUTING, and the parent VIF's, which is what it arrived by:
	 * listed by every derivation past the table, whatever it then decides,
	 * so a refused group still gathers its confirmations. No references:
	 * an index names, it does not hold. `out_bridged` says a copy leaves
	 * through a bridge. */
	int oif[MAXVIFS];
	int parent;
	u8 oif_count;
	bool oifs_known;
	bool out_bridged;
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
static DEFINE_MUTEX(ft_mr_lock);
static LIST_HEAD(ft_mr_queue);
static DEFINE_SPINLOCK(ft_mr_queue_lock);
static struct ft_mr_vif ft_mr_vif[2][MAXVIFS];
static unsigned int ft_mr_count, ft_mr_installed;
static unsigned int ft_mr_policy[2];
static u64 ft_mr_refused, ft_mr_install_errors, ft_mr_lost;
static bool ft_mr_stopping;
static bool ft_mr_ready;
static bool ft_mr_recheck;
/* The VIF table changed and the bridged learner has not been told where the
 * VIFs on bridges now are. */
static bool ft_mr_taps_stale = true;
/* A group gave up an entry, so a group refused its key may now have it. */
static bool ft_mr_key_freed;
/* A lost notification invalidates the mirror, including a family with no
 * cached groups. Only a complete dump under RTNL clears its bit. */
static unsigned long ft_mr_resync_pending;
static void ft_mr_work_fn(struct work_struct *work);
static void ft_mr_stats_fn(struct work_struct *work);
static DECLARE_WORK(ft_mr_work, ft_mr_work_fn);
static DECLARE_DELAYED_WORK(ft_mr_stats, ft_mr_stats_fn);

static unsigned int ft_mr_idx(u8 family)
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
static void ft_mr_kick(void)
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
 * sent that one down its own, possibly narrower, path.
 */
static int ft_mr_listener(struct net_device *port,
			  const struct cdx_mc_listener *ingress,
			  const struct cdx_ft_vlan *inner, unsigned int tags,
			  u32 path_mtu, struct cdx_mc_listener *out, u8 *count,
			  u32 *mtu)
{
	struct cdx_mc_listener add = {};
	unsigned int i;

	if (tags > CDX_FT_VLAN_MAX)
		return -EOPNOTSUPP;
	add.dev = port;
	add.vlans = tags;
	add.routed = true;
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
	/* Two oifs resolving to the same port with the same framing are one
	 * copy and collapse; with different framing they are two, and the
	 * backend takes both -- it identifies a listener by its whole framing
	 * rather than by its device, and each gets its own entry in the chain.
	 * A gateway serving several VLANs out of one port replicates that way,
	 * and so does the bench: the rig has one LAN port with carrier and
	 * every group's other port is its ingress, so two tagged oifs on that
	 * port are the only way replication to several listeners and the chain
	 * swap a join performs can be exercised there at all (ISSUES.md
	 * A158). */
	*mtu = min(*mtu, path_mtu);
	for (i = 0; i < *count; i++)
		if (out[i].dev == add.dev && out[i].vlans == add.vlans &&
		    !memcmp(out[i].vlan, add.vlan, sizeof(add.vlan)))
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
			       struct cdx_mc_listener *out, u8 *count, u32 *mtu)
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
				    out, count, mtu);
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

	for (;;) {
		if (!dev)
			return -EOPNOTSUPP;
		path_mtu = min(path_mtu, ft_mc_link_mtu(dev, family));
		if (netif_is_bridge_master(dev)) {
			*bridged = true;
			return ft_mr_expand_bridge(dev, ingress, inner, tags,
						   family, src, dst, path_mtu,
						   out, count, mtu);
		}
		if (cdx_mc_port_identity(dev))
			return ft_mr_listener(dev, ingress, inner, tags,
					      path_mtu, out, count, mtu);
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
		struct net_device *oif = ct < MAXVIFS ? ft_mr_vif[idx][ct].dev : NULL;

		if (mfc->mfc_un.res.ttls[ct] != 255 && oif)
			plan->oif[plan->oif_count++] = oif->ifindex;
	}
	/* And the VIF each copy has to have arrived by: an iif-keyed forward
	 * rule -- fw4's zones are -- judges a stream by where it comes from,
	 * so copies seen from one parent confirm nothing for another. No
	 * device is no index, which no copy arrives by. */
	vif_dev = mfc->mfc_parent < MAXVIFS ?
		  ft_mr_vif[idx][mfc->mfc_parent].dev : NULL;
	plan->parent = vif_dev ? vif_dev->ifindex : 0;
	plan->oifs_known = true;
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
	vif_dev = ft_mr_vif[idx][mfc->mfc_parent].dev;
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
		struct net_device *oif = ct < MAXVIFS ? ft_mr_vif[idx][ct].dev : NULL;

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
		if (ft_mr_vif[idx][ct].flags & bad_flags)
			return FT_MR_REFUSED_LISTENER;
		oif = ft_mr_vif[idx][ct].dev;
		/* A VIF the kernel has removed is dropped rather than
		 * refused: what is left is a smaller replication list, and an
		 * empty one is caught below. */
		if (!oif)
			continue;
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
	 * one with DF set. The IPv6 side is the parent's IPv6 MTU, the value
	 * its link is told, which is the bound the unicast IPv6 path uses for
	 * the same reason. Nothing an MTU change or the IPv6 MTU sysctl does
	 * raises an MFC event, so this is rechecked by the periodic refresh as
	 * well as on NETDEV_CHANGEMTU.
	 *
	 * Through a bridge the bound is the bridge port the stream arrives on,
	 * which the bridge hands up whatever the bridge device's own MTU, and
	 * which only the bridged group knows: the plan carries the narrowest
	 * copy for it to hold against that. */
	if (spec.in && out_mtu < ft_mc_link_mtu(vif_dev, g->family))
		return FT_MR_REFUSED_MTU;

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

		if (a->dev != b->dev || a->vlans != b->vlans)
			return false;
		for (j = 0; j < a->vlans; j++)
			if (a->vlan[j].proto != b->vlan[j].proto ||
			    a->vlan[j].id != b->vlan[j].id)
				return false;
	}
	return true;
}

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
 * A confirmation proves that the ruleset forwards the stream there, not what
 * it does to each packet: a rate limit, a quota, a counter or a match that
 * differs from packet to packet stops applying once the group is carried, as
 * it does for a flowtable flow. Nor does it see past the observer: an
 * nftables chain that runs after it at POST_ROUTING keeps the group in
 * software, and a chain at a device's egress is not seen at all.
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
 * An iptables-legacy table is replaced with no generation anyone can read, so
 * a change there is followed only once something else takes the group back.
 */

/* One group's confirmations, in a table the hook reads under RCU. */
struct ft_mr_watch {
	struct hlist_node node;
	struct rcu_head rcu;
	u8 family;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	/* The MFC oifs by ifindex, and bit i of `seen` for oif[i] seen leaving
	 * under the ruleset the table is armed for, by a copy that arrived by
	 * the parent VIF `parent`. The lists are fixed once published -- a
	 * changed one is a new watch -- so a reader never sees half of one. */
	u8 oifs;
	int oif[MAXVIFS];
	int parent;
	unsigned long seen;
	/* Every oif seen, and the worker not told yet. */
	bool news;
};

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
static bool ft_mr_gen_open, ft_mr_gen_armed;
/* Commits that took confirmations back; failures to register the observer
 * or to allocate a watch, each of which keeps groups in software. */
static u64 ft_mr_ruleset_changes, ft_mr_confirm_errors;
/* How soon a rule added under a carried group takes effect: the ruleset is
 * looked at this often while any group exists. Two loads. */
#define FT_MR_RULESET_INTERVAL	HZ
/* How long a ruleset has to stand still before copies confirm under it: the
 * software episode every commit costs a carried group, less the first copy
 * of it after that. And how soon to look again at one whose commit is still
 * being applied after that. */
#define FT_MR_RULESET_SETTLE	HZ
#define FT_MR_RULESET_APPLYING	(HZ / 10)
static void ft_mr_ruleset_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_mr_ruleset, ft_mr_ruleset_fn);

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
static void ft_mr_confirm_sync(void)
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
static bool ft_mr_ruleset_sync(void)
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
static unsigned long ft_mr_ruleset_wait(void)
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
static void ft_mr_watch_arm(struct ft_mr_group *g, const struct ft_mr_plan *plan)
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
static void ft_mr_watch_drop(struct ft_mr_group *g)
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

/* Whether a group the contract accepts may be carried now. Called by the
 * worker under RTNL, after an accepting derivation has armed its watch.
 *
 * The confirmation covers the inet hooks up to the observer. A copy routed
 * into a bridge then passes the bridge's own LOCAL_OUT and POST_ROUTING hooks
 * after it was confirmed, so any hook there keeps the group in software, as a
 * bridge hook keeps a bridged flow; and so does a chain that runs after the
 * observer at POST_ROUTING itself. */
static enum ft_mr_state ft_mr_admit(struct ft_mr_group *g,
				    const struct ft_mr_plan *plan)
{
	if (plan->out_bridged &&
	    ft_bridge_hooked(BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING)))
		return FT_MR_REFUSED_FILTER;
	if (ft_mr_observer_followed(g->family))
		return FT_MR_REFUSED_FILTER;
	/* A commit since the pass began: confirmations are not good for it,
	 * and the next pass re-arms them. */
	if (!ft_mr_ruleset_current()) {
		schedule_work(&ft_mr_work);
		return FT_MR_UNCONFIRMED;
	}
	if (!g->watch || !READ_ONCE(ft_mr_gen_open) ||
	    !ft_mr_watch_complete(g->watch))
		return FT_MR_UNCONFIRMED;
	return FT_MR_PENDING;
}

/* A rule added under a carried group has to take it out, and nothing reports
 * a commit: while any group exists, the ruleset is looked at this often. A
 * ruleset still settling is looked at when it will have settled, which the
 * worker schedules; the worker opens it. */
static void ft_mr_ruleset_fn(struct work_struct *work)
{
	if (READ_ONCE(ft_mr_stopping))
		return;
	if (!ft_mr_ruleset_current() || !READ_ONCE(ft_mr_gen_open))
		schedule_work(&ft_mr_work);
	if (READ_ONCE(ft_mr_count))
		schedule_delayed_work(&ft_mr_ruleset, FT_MR_RULESET_INTERVAL);
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
static int ft_mr_fib_event(unsigned long event, struct fib_notifier_info *info)
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
 * table walks. The private callback owns no hardware and never sleeps. */
static void ft_mr_resync(void)
{
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
 * cdx_mc_group_stats(). Called with ft_mr_lock and the transaction held. */
static bool ft_mr_counters(struct ft_mr_group *g, struct cdx_ft_counters *c,
			   u8 *tags)
{
	*tags = g->in_tags;
	if (g->hw)
		return cdx_mc_group_stats(g->hw, c);
	if (g->route && ft_mc_route_state(g->route, c, tags))
		return true;
	memset(c, 0, sizeof(*c));
	return false;
}

static void ft_mr_release_set(struct ft_mr_group *g)
{
	u8 i;

	for (i = 0; i < g->listeners; i++)
		if (g->listener[i].dev)
			dev_put(g->listener[i].dev);
	memset(g->listener, 0, sizeof(g->listener));
	g->listeners = 0;
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
	g->mtu = 0;
	g->oifs[0] = '\0';
	/* It borrowed the devices just let go of. */
	memset(&g->hw_spec, 0, sizeof(g->hw_spec));
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
	 * clears every pointer the bridged groups hold to it. */
	if (g->route) {
		ft_mc_route_withdraw(g->route);
		kfree(g->route);
	}
	mr_cache_put(g->mfc);
	kfree(g);
}

/* A device this learner holds is going away or has stopped forwarding.
 *
 * Runs from the netdev chain under RTNL, so it may take ft_mr_lock and must
 * not touch the backend. The group's own references are dropped here and the
 * group asked again. The hardware entry still naming the device is deleted by
 * the worker this schedules, and keeps a reference of its own on its ingress
 * until then (`hw_in`), because the delete goes through it; unregistration
 * waits for that only as long as the worker takes to run. The bridged learner
 * answers the same window the same way.
 */
static void ft_mr_device_gone(struct net_device *dev)
{
	struct ft_mr_group *g;
	bool changed = false;
	u8 i;

	mutex_lock(&ft_mr_lock);
	list_for_each_entry(g, &ft_mr_groups, list) {
		bool hit = g->in == dev || g->via == dev;

		for (i = 0; i < g->listeners; i++)
			hit |= g->listener[i].dev == dev;
		if (!hit)
			continue;
		ft_mr_release_set(g);
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
 * replaced only when the outcome is recorded. A group whose set was released
 * (ft_mr_device_gone()) while its hardware stayed could have any port in it.
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
 * A group that cannot be rebuilt here -- its set was released, or the replace
 * failed and it is handed back to the worker, whose own failed replace
 * withdraws it in one pass -- is reported with -EAGAIN. */
static int ft_mr_egress_drain(const struct net_device *dev)
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
	 * is the next add's allocation often enough. So does a route this
	 * group has just begun riding: it was zeroed when it was published. */
	if (added || (plan->via && !g->via)) {
		g->folded_packets = g->folded_bytes = 0;
		g->fold_suspect = false;
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
	bool retiring = false;
	LIST_HEAD(dead);

	/* Registration may replay its dump after a sequence mismatch. Do not
	 * apply those attempts before the initial authoritative resync. */
	if (!smp_load_acquire(&ft_mr_ready))
		return;
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
	if (READ_ONCE(ft_mr_resync_pending) && !READ_ONCE(ft_mr_stopping))
		ft_mr_resync();

	/* 2. Anything outside this learner that stales an answer it gave: a
	 * ruleset commit takes back every confirmation, and every group is
	 * asked again, the carried ones going back to software. */
	if (!READ_ONCE(ft_mr_stopping) && ft_mr_ruleset_sync())
		WRITE_ONCE(ft_mr_recheck, true);
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
			target = g;
			break;
		}
		if (target) {
			target->dirty = false;
			target->busy = true;
			retries = target->retries;
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
		 * the unlock because the installed ingress is the other thing
		 * ft_mr_device_gone() clears, and it holds RTNL to do it. */
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
		 * carry, and whether it does is this group's state. Anything
		 * else takes back what it published, if it ever did. Both take
		 * ft_mc_lock, so neither runs under this learner's lock. */
		if (via) {
			rc = ft_mr_publish(target, &plan);
			if (rc < 0)
				ft_mr_install_errors++;
			else
				state = rc ? FT_MR_INSTALLED : FT_MR_BRIDGED;
			rc = min(rc, 0);
		} else if (target->route) {
			ft_mc_route_withdraw(target->route);
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

static void ft_mr_exit(void)
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
			cdx_ft_begin();
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

static void ft_mr_rows(struct seq_file *seq)
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
		seq_printf(seq, " packets=%llu bytes=%llu\n",
			   stats.packets, stats.bytes);
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
static void ft_mc_egress_changed(const struct net_device *dev)
{
	unsigned int rebuilt;

	rebuilt = ft_mc_egress_mark(dev);
	rebuilt += ft_mr_egress_mark(dev);
	atomic64_add(rebuilt, &ft_mc_egress_rebuilds);
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
 */
static int ft_ipsec_peer_mac(struct net_device *dev, u8 family,
			     const union nf_inet_addr *local,
			     const union nf_inet_addr *peer,
			     const struct ft_ipsec_route *route, bool wait,
			     u8 *mac, struct netlink_ext_ack *extack)
{
	struct neighbour *neighbour;
	unsigned int attempt;
	struct rtable *rt;
	/* The SA's own local endpoint is part of the question, not decoration:
	 * an output lookup carrying a source address answers for the route
	 * that address may actually use, which is the one this tunnel's frames
	 * will take.
	 *
	 * No output interface, though. A lookup bound to the SA's port answers
	 * through that port whatever the table says -- a less specific route
	 * via it, or the destination assumed on-link -- so the refusal below
	 * could never fire, and a peer whose route had moved to another port
	 * was followed to a next hop on the old one. The kernel now drops
	 * frames for a bundle routed off the SA's port, so this has to agree
	 * with it, and asks with what the kernel's own lookup of the peer
	 * carries: the table of the VRF the port is enslaved to, if any, and
	 * the SA's `route`. */
	struct flowi4 fl4 = {
		.daddr = peer->ip,
		.saddr = local->ip,
		.flowi4_mark = route->mark,
		.flowi4_l3mdev = l3mdev_master_ifindex(dev),
		.flowi4_proto = route->proto,
		.fl4_sport = route->sport,
		.fl4_dport = route->dport,
	};
	int rc = 0;

	eth_zero_addr(mac);
	if (family != AF_INET) {
		NL_SET_ERR_MSG(extack, "cdx: only IPv4 tunnel endpoints are supported");
		return -EOPNOTSUPP;
	}
	rt = ip_route_output_key(&init_net, &fl4);
	if (IS_ERR(rt)) {
		NL_SET_ERR_MSG(extack, "cdx: no route to the remote tunnel endpoint");
		return PTR_ERR(rt);
	}
	if (rt->dst.dev != dev) {
		NL_SET_ERR_MSG(extack, "cdx: the route to the peer does not leave by the offload device");
		rc = -EOPNOTSUPP;
		goto out;
	}
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
	 * ARP on a LAN.
	 */
	neighbour = dst_neigh_lookup(&rt->dst, &fl4.daddr);
	if (!neighbour) {
		rc = -EHOSTUNREACH;
		goto report;
	}
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
	ip_rt_put(rt);
	return rc;
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

	ft_ipsec_route_of(x, &route);
	return ft_ipsec_peer_mac(spec->dev, spec->family, &spec->src, &spec->dst,
				 &route, true, spec->dst_mac, extack);
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
 * not keep, and SEC may keep a wider window than the state asked for: they are
 * marked received, so a number xfrm would refuse as too old is refused rather
 * than taken once more.
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
	if (spec->dir == CDX_IPSEC_DIR_IN &&
	    spec->replay_window > CDX_IPSEC_REPLAY_WINDOW_MAX) {
		NL_SET_ERR_MSG(extack, "cdx: SEC's anti-replay window is at most 128 packets");
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
		spec->natt_sport = x->encap->encap_sport;
		spec->natt_dport = x->encap->encap_dport;
	}
	if (x->aalg) {
		if (x->aalg->alg_key_len > CDX_IPSEC_KEY_MAX * 8) {
			NL_SET_ERR_MSG(extack, "cdx: authentication key too long");
			return -EINVAL;
		}
		spec->auth.alg = x->props.aalgo;
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
		if (x->aead->alg_key_len > CDX_IPSEC_KEY_MAX * 8) {
			NL_SET_ERR_MSG(extack, "cdx: AEAD key too long");
			return -EINVAL;
		}
		spec->crypt.alg = x->props.ealgo;
		spec->crypt.bits = x->aead->alg_key_len;
		memcpy(spec->crypt.key, x->aead->alg_key, x->aead->alg_key_len / 8);
	}
	spec->dev_mtu = dev->mtu;
	spec->mtu = xfrm_state_mtu(x, dev->mtu);
	if (spec->dir == CDX_IPSEC_DIR_OUT)
		return ft_ipsec_next_hop(x, spec, extack);
	return 0;
}

/* Retirement storage belongs to an SA from its initial installation.
 * Deletion can run from expiry under a spinlock and must never allocate.
 *
 * While the SA is owned, the same entry is what the accounting pass below
 * walks, which is why it names the state as well as the SA. */
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
};
static LIST_HEAD(ft_ipsec_owned);
static LIST_HEAD(ft_ipsec_retired);
static DEFINE_SPINLOCK(ft_ipsec_retired_lock);
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
static bool ft_ipsec_retire_pending(void)
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
 *
 * There is deliberately no xdo_dev_state_update_stats(). Most of its callers
 * hold x->lock or xfrm_state_lock -- the state timer, xfrm_state_check_expire(),
 * state dumps -- so it cannot sleep for the control mutex, and the 64-bit
 * packet total is built under that mutex; a second reader outside it would
 * race the pass. XFRM_MSG_GETSA reaches it holding only xfrm_cfg_mutex, where
 * nothing even keeps the SA from being retired underneath it. What the op
 * could publish, curlft already holds, at most one period old -- as stale as
 * mlx5's, whose flow counters are cached on the same one-second period
 * (MLX5_FC_STATS_PERIOD) and whose software limits are judged by a
 * one-second work (mlx5e_ipsec_handle_sw_limits()).
 *
 * Nor an xdo_dev_state_advance_esn(). xfrm_dev_state_add() asks for it only
 * for crypto offload, and SEC keeps an ESN SA's high word in its PDB and
 * advances it there.
 */
#define FT_IPSEC_STATS_PERIOD	HZ

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
static DECLARE_DELAYED_WORK(ft_ipsec_stats, ft_ipsec_stats_work);

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
 * state's sequence number on reads that copy: XFRM_MSG_GETAE, which a keying
 * daemon reads to carry the number over when it re-adds an SA at a new
 * address, and the clone xfrm_state_migrate() makes. Either would start the
 * new SA over numbers its peer has already seen, and the peer drops every
 * frame until they pass. Only forward, so a stale reading never undoes a
 * value set by other means. Caller holds x->lock.
 *
 * The number goes back ahead of SEC's by twice what the SA sent in the last
 * period (`sent`). SEC goes on numbering after this reading until the SA is
 * deleted -- up to a period later, plus however long a daemon takes between
 * reading the state and deleting it -- and a re-added SA that started behind
 * that would reuse numbers. Skipping ahead costs the peer nothing: a gap in
 * the sequence is what loss looks like to it. Twice covers a rate that rises
 * into the next period; a burst out of idle in the last period before a
 * re-add is the case it can still fall short on. The margin stops at the last
 * number SEC will send, one below all-ones (SEC RM table 9-2).
 */
static void ft_ipsec_publish_oseq(struct xfrm_state *x, u64 oseq, u64 sent)
{
	struct xfrm_replay_state_esn *esn = x->replay_esn;
	u64 last = x->props.flags & XFRM_STATE_ESN ? U64_MAX - 1 : U32_MAX - 1;

	if (x->xso.dir != XFRM_DEV_OFFLOAD_OUT)
		return;
	oseq = oseq < last - min(last, 2 * sent) ? oseq + 2 * sent : last;
	if (!esn) {
		if (oseq > x->replay.oseq)
			x->replay.oseq = oseq;
	} else if (x->props.flags & XFRM_STATE_ESN) {
		if (oseq > ((u64)esn->oseq_hi << 32 | esn->oseq)) {
			esn->oseq = lower_32_bits(oseq);
			esn->oseq_hi = upper_32_bits(oseq);
		}
	} else if (oseq > esn->oseq) {
		esn->oseq = oseq;
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
 * replaces it. Caller holds x->lock.
 */
static void ft_ipsec_publish_window(struct xfrm_state *x,
				    const struct cdx_ipsec_counters *counters)
{
	struct xfrm_replay_state_esn *esn = x->replay_esn;
	u32 window = esn ? esn->replay_window : x->props.replay_window;
	u32 top = lower_32_bits(counters->seq);
	u64 now;
	u32 k, bit;

	if (!window || !counters->seq)
		return;
	if (!esn) {
		if (counters->seq < x->replay.seq)
			return;
		if (counters->seq > x->replay.seq) {
			x->replay.seq = top;
			x->replay.bitmap = 0;
		}
		x->replay.bitmap |= counters->seen[0] &
				    (window < 32 ? (1U << window) - 1 : ~0U);
		return;
	}
	now = esn->seq;
	if (x->props.flags & XFRM_STATE_ESN)
		now |= (u64)esn->seq_hi << 32;
	if (counters->seq < now)
		return;
	if (counters->seq > now) {
		esn->seq = top;
		if (x->props.flags & XFRM_STATE_ESN)
			esn->seq_hi = upper_32_bits(counters->seq);
		memset(esn->bmp, 0, esn->bmp_len * sizeof(esn->bmp[0]));
	}
	for (k = 0; k < min_t(u32, window, CDX_IPSEC_REPLAY_WINDOW_MAX); k++) {
		if (!(counters->seen[k / 32] & (1U << (k % 32))))
			continue;
		bit = ft_ipsec_replay_bit(top, window, k);
		esn->bmp[bit / 32] |= 1U << (bit % 32);
	}
}

/* Publish one SA's counters into its state and let xfrm judge them.
 *
 * A VALID state only. One that is being deleted has nothing left to expire,
 * and one already hard-expired is on its way there; xfrm_state_check_expire()
 * would only rearm the timer that is deleting it. x->lock is held across the
 * test and everything after it, and __xfrm_state_delete() runs under the same
 * lock, so a state seen VALID here stays so until the lock drops.
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
	if (x->xso.dir == XFRM_DEV_OFFLOAD_OUT)
		ft_ipsec_publish_oseq(x, counters->oseq, carried);
	else
		ft_ipsec_publish_window(x, counters);
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
	spin_lock_bh(&ft_ipsec_retired_lock);
	more = !list_empty(&ft_ipsec_owned);
	spin_unlock_bh(&ft_ipsec_retired_lock);
	cdx_ft_end();
	if (more)
		schedule_delayed_work(&ft_ipsec_stats, FT_IPSEC_STATS_PERIOD);
}

static int ft_xdo_state_add(struct xfrm_state *x, struct netlink_ext_ack *extack)
{
	struct ft_ipsec_watch *watch = NULL;
	struct ft_ipsec_retirement *retirement;
	struct cdx_ipsec_sa_spec spec;
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
	rc = ft_ipsec_spec(x, &spec, extack);
	if (rc)
		return rc;
	/* Before the hardware, so that an SA nothing could follow is never
	 * installed at all. An outbound SA's next hop is written into its
	 * entry and never re-read, so the watch is part of installing one
	 * rather than an improvement on it. */
	if (spec.dir == CDX_IPSEC_DIR_OUT) {
		watch = kzalloc(sizeof(*watch), GFP_KERNEL);
		if (!watch)
			return -ENOMEM;
	}
	retirement = kzalloc(sizeof(*retirement), GFP_KERNEL);
	if (!retirement) {
		kfree(watch);
		return -ENOMEM;
	}
	cdx_ft_begin();
	/* Before the build reads the port's egress, which an egress change
	 * updates before counting itself. */
	changes = atomic64_read_acquire(&ft_egress_changes);
	rc = cdx_ipsec_sa_add(&spec, x, &sa);
	if (!rc && watch) {
		ft_ipsec_route_of(x, &route);
		ft_ipsec_watch_add(watch, &spec, sa, &route, changes);
	}
	cdx_ft_end();
	if (rc) {
		kfree(retirement);
		kfree(watch);
		NL_SET_ERR_MSG_WEAK(extack, "cdx: the hardware refused this SA");
		return rc;
	}
	retirement->sa = sa;
	retirement->x = x;
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
	 * The datapath works in handles rather than pointers, because that is
	 * all a frame can carry: SEC stamps the handle into a decrypted
	 * frame's trailer, and the transmit path looks the frame queue up by
	 * it. Setting it here, before the state is inserted, is what makes the
	 * kernel's handle index point at the SA the hardware actually has --
	 * xfrm_state_insert_byh() honours a handle that is already set rather
	 * than allocating over it.
	 */
	x->handle = cdx_ipsec_sa_handle(sa);
	return 0;
}

static void ft_ipsec_retire_work(struct work_struct *work)
{
	struct ft_ipsec_retirement *retirement;
	struct cdx_ft_entry *entry, *next;
	u16 handle;

	for (;;) {
		spin_lock_bh(&ft_ipsec_retired_lock);
		retirement = list_first_entry_or_null(&ft_ipsec_retired,
						      struct ft_ipsec_retirement, list);
		if (retirement)
			list_del(&retirement->list);
		spin_unlock_bh(&ft_ipsec_retired_lock);
		if (!retirement)
			return;
		handle = cdx_ipsec_sa_handle(retirement->sa);
		for (;;) {
			cdx_ft_begin();
			/* Serialize with admission, including an admission the atomic
			 * deletion callback missed before its watch was published.
			 * Never reuse an SA handle while a flow can still name it. */
			list_for_each_entry_safe(entry, next, &ft_entries, list) {
				if (entry->rule.sa_handle != handle &&
				    entry->rule.in_sa_handle != handle)
					continue;
				ft_handle_invalidate(entry->handle, &ft_ipsec_invalidations);
				ft_remove(entry);
			}
			/* A deletion barrier can defer reclaim or require datapath
			 * quiescence. Retain the SA until that proof completes. */
			if (!cdx_ft_pending() || !cdx_ft_recover())
				break;
			cdx_ft_end();
			msleep(20);
		}
		cdx_ipsec_sa_del(&retirement->sa);
		/* Out of the hardware: an egress drain waiting on it may now
		 * say so, having taken this transaction to look. */
		atomic_dec(&ft_ipsec_retiring);
		cdx_ft_end();
		kfree(retirement);
	}
}

static DECLARE_WORK(ft_ipsec_retire, ft_ipsec_retire_work);

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
	struct net_device *dev;
	u8 was_dst[ETH_ALEN];
	u8 was_src[ETH_ALEN];
	u8 mac[ETH_ALEN];
	bool reported, rebuild;
	u32 asked;
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
		reported = watch->reported;
		/* Left set: it is cleared below once the rebuild has happened,
		 * and only if no egress change asked for another meanwhile. */
		rebuild = watch->rebuild;
		asked = watch->rebuilds_asked;
		ether_addr_copy(was_dst, watch->dst_mac);
		ether_addr_copy(was_src, watch->src_mac);
		dev_hold(dev);
		spin_unlock_bh(&ft_watch_lock);

		rc = ft_ipsec_peer_mac(dev, family, &local, &peer, &route, false,
				       mac, NULL);
		if (!rc && !rebuild && ether_addr_equal(mac, was_dst) &&
		    ether_addr_equal(dev->dev_addr, was_src)) {
			/* Neither address moved. A route event marks every SA
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
			rc = sa ? cdx_ipsec_sa_set_next_hop(sa, mac) : 0;
			if (sa && !rc) {
				spin_lock_bh(&ft_watch_lock);
				watch = ft_ipsec_watch_find(cookie);
				if (watch) {
					ether_addr_copy(watch->dst_mac, mac);
					ether_addr_copy(watch->src_mac,
							dev->dev_addr);
					watch->reported = false;
					if (watch->rebuilds_asked == asked)
						watch->rebuild = false;
				}
				spin_unlock_bh(&ft_watch_lock);
				atomic64_inc(&ft_ipsec_next_hop_updates);
				netdev_info(dev, "cdx: IPsec SA followed its peer to %pM\n",
					    mac);
			}
			cdx_ft_end();
		}
		if (rc) {
			spin_lock_bh(&ft_watch_lock);
			watch = ft_ipsec_watch_find(cookie);
			if (watch) {
				watch->stale = true;
				watch->reported = true;
			}
			spin_unlock_bh(&ft_watch_lock);
			if (!reported)
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
static void ft_ipsec_attach(struct net_device *dev)
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

static void ft_ipsec_detach(struct net_device *dev)
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
static void ft_ipsec_detach_all(void)
{
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(&init_net, dev)
		ft_ipsec_detach(dev);
	rtnl_unlock();
	/* Core dispatch pins our module inside RCU before calling an op. */
	synchronize_rcu();
}

/* Wi-Fi VAPs.
 *
 * A VAP registering is a netdev event, and that is the whole of the control
 * plane that FPP_CMD_WIFI_VAP_ENTRY, a userspace daemon and a static UCI file
 * used to be.
 *
 * It cannot be done where it is noticed. Registration needs the backend
 * transaction and RTNL, and the two have one safe order: RTNL is taken under
 * the transaction only by trying (cdx_ft_admission_begin()), because the bind
 * path already takes the transaction under RTNL and a blocking rtnl_lock()
 * inside the transaction would invert that -- lockdep reported exactly this at
 * unload, where the exit path once blocked on RTNL with the transaction held;
 * it now takes RTNL first. A netdev notifier arrives already holding RTNL, so
 * the notifier records what it saw and a worker reconciles it, as the multicast
 * learner and the IPsec next-hop watch both do, for the same reason.
 */
struct ft_wifi_watch {
	struct list_head list;
	/* NULL once the device has unregistered. Only ever compared or
	 * referenced under ft_wifi_lock, never stored beyond a worker pass. */
	struct net_device *dev;
	struct cdx_wifi_vap *vap;
	bool wanted;
	bool gone;
	/* The registration copied this device's hardware address into the
	 * port and into the encoder's record of it, and neither is re-read per
	 * frame -- so an address that changes afterwards leaves the classifier
	 * writing the old one as the source of every frame leaving this VAP.
	 * There is no way to correct it in place, for the same reason an SA's
	 * next hop cannot be: it is built into what was registered. So the VAP
	 * is retired and registered again, which this asks the worker to do. */
	bool stale;
};

static LIST_HEAD(ft_wifi_watches);
static DEFINE_MUTEX(ft_wifi_lock);
static bool ft_wifi_stopping;
static unsigned int ft_wifi_registered;
static atomic64_t ft_wifi_refusals = ATOMIC64_INIT(0);
static void ft_wifi_work_fn(struct work_struct *work);
static DECLARE_WORK(ft_wifi_work, ft_wifi_work_fn);

/* Which netdevs are VAPs, and the reason this is policy rather than mechanism.
 *
 * A cfg80211 device in AP or AP_VLAN mode. That is a property of the device
 * instead of a name in a configuration file, so a station-mode, monitor or P2P
 * interface fails it without having to be excluded by hand, and an interface
 * that changes mode stops being a VAP at the moment it does. AP_VLAN counts
 * because it is an AP's per-station egress and carries frames the same way.
 *
 * Running is part of it, and not as a policy preference -- the backend cannot
 * do anything else. vwd_vap_up() refuses a device that is not IFF_UP, so
 * offering one can only produce a failed registration; a board that registers
 * its AP interfaces at driver load and brings them up later (which is what
 * hostapd does here) would otherwise spend a refusal on every interface at
 * every boot, and count it.
 *
 * It also happens to be the only way the other half of this predicate is
 * observable. cfg80211_change_iface() changes an interface's type without
 * raising any netdev event at all -- no notifier, not even
 * netdev_state_change() -- so nothing would re-read the iftype on its own. A
 * type change goes through a down and an up, and those do raise events, so
 * gating on running is what makes "stopped being an AP" reach this at all.
 */
static bool ft_wifi_is_vap(struct net_device *dev)
{
	struct wireless_dev *wdev;

	ASSERT_RTNL();
	if (!netif_running(dev))
		return false;
	wdev = dev->ieee80211_ptr;
	return wdev && (wdev->iftype == NL80211_IFTYPE_AP ||
			wdev->iftype == NL80211_IFTYPE_AP_VLAN);
}

/* Record what this device should be and let the worker make it so. Called for
 * every event that can change the answer, including the ones that only change
 * it indirectly: hostapd sets the interface type and then brings it up, and
 * the type change alone raises no netdev event of its own. */
static void ft_wifi_reconsider(struct net_device *dev)
{
	struct ft_wifi_watch *w, *found = NULL;
	bool want, changed = false;

	ASSERT_RTNL();
	want = ft_wifi_is_vap(dev) && cdx_wifi_vap_supported(dev);

	mutex_lock(&ft_wifi_lock);
	if (ft_wifi_stopping)
		goto out;
	list_for_each_entry(w, &ft_wifi_watches, list) {
		if (w->dev == dev) {
			found = w;
			break;
		}
	}
	if (!found) {
		if (!want)
			goto out;
		found = kzalloc(sizeof(*found), GFP_KERNEL);
		if (!found) {
			/* Nothing was registered, so nothing is inconsistent:
			 * the device simply is not offloaded until an event
			 * brings it past here again. */
			atomic64_inc(&ft_wifi_refusals);
			goto out;
		}
		found->dev = dev;
		list_add(&found->list, &ft_wifi_watches);
	}
	changed = found->wanted != want;
	found->wanted = want;
out:
	mutex_unlock(&ft_wifi_lock);
	if (changed)
		schedule_work(&ft_wifi_work);
}

/* This device's hardware address moved, so what was registered for it no
 * longer describes it. Marked rather than corrected: see ft_wifi_watch.stale.
 */
static void ft_wifi_address_changed(struct net_device *dev)
{
	struct ft_wifi_watch *w;
	bool changed = false;

	ASSERT_RTNL();
	mutex_lock(&ft_wifi_lock);
	list_for_each_entry(w, &ft_wifi_watches, list) {
		if (w->dev != dev || !w->vap)
			continue;
		w->stale = true;
		changed = true;
	}
	mutex_unlock(&ft_wifi_lock);
	if (changed)
		schedule_work(&ft_wifi_work);
}

/* The device is going. Nothing may follow the pointer after this returns.
 *
 * VWD's own netdev notifier takes the hardware half of the VAP down as the
 * device unregisters, so what the worker still has to release is the logical
 * interface and the devman record -- neither of which needs the device, which
 * is why the backend copied what it needs at registration time. */
static void ft_wifi_device_gone(struct net_device *dev)
{
	struct ft_wifi_watch *w;
	bool changed = false;

	ASSERT_RTNL();
	mutex_lock(&ft_wifi_lock);
	list_for_each_entry(w, &ft_wifi_watches, list) {
		if (w->dev != dev)
			continue;
		w->dev = NULL;
		w->gone = true;
		w->wanted = false;
		changed = true;
	}
	mutex_unlock(&ft_wifi_lock);
	if (changed)
		schedule_work(&ft_wifi_work);
}

static void ft_wifi_work_fn(struct work_struct *work)
{
	struct ft_wifi_watch *w, *tmp;

	/* One VAP per pass. The transaction is taken and dropped around each,
	 * and ft_wifi_lock is never held across it -- the same discipline the
	 * multicast worker keeps, and for the same reason: the backend sleeps.
	 */
	for (;;) {
		struct cdx_wifi_vap *vap = NULL;
		struct net_device *dev = NULL;
		int rc;

		mutex_lock(&ft_wifi_lock);
		list_for_each_entry_safe(w, tmp, &ft_wifi_watches, list) {
			if (w->wanted && !w->vap) {
				/* Referenced here, under the lock that
				 * ft_wifi_device_gone() also takes, so the
				 * device cannot be freed between choosing it
				 * and using it below. Released at the end of
				 * this pass; a reference held any longer would
				 * be one unregister_netdevice() waits on. */
				dev = w->dev;
				dev_hold(dev);
				break;
			}
			if (w->vap && (!w->wanted || w->stale)) {
				/* Claimed here rather than cleared after the
				 * delete: the watch must stop naming this VAP
				 * before the lock is dropped, or a later pass
				 * finds the same pointer again and hands it to
				 * the backend twice.
				 *
				 * A stale one is retired the same way, and
				 * leaves `wanted` set -- so the next pass sees
				 * a wanted watch with no VAP and registers it
				 * again, this time reading the address the
				 * device has now. */
				vap = w->vap;
				w->vap = NULL;
				w->stale = false;
				ft_wifi_registered--;
				break;
			}
			if (!w->wanted && !w->vap && w->gone) {
				list_del(&w->list);
				kfree(w);
			}
		}
		mutex_unlock(&ft_wifi_lock);

		if (!dev && !vap)
			return;

		cdx_ft_begin();
		if (cdx_ft_admission_begin()) {
			/* RTNL is held by something that can wait for this
			 * transaction. Come back rather than invert the two. */
			cdx_ft_end();
			if (dev)
				dev_put(dev);
			schedule_work(&ft_wifi_work);
			return;
		}

		if (dev) {
			struct cdx_wifi_vap *made = NULL;

			/* Re-read the decision under the locks that make it
			 * true rather than trusting what the notifier saw: the
			 * device may have changed mode or started
			 * unregistering since. */
			if (dev->reg_state != NETREG_REGISTERED ||
			    !ft_wifi_is_vap(dev))
				rc = -ENODEV;
			else
				rc = cdx_wifi_vap_add(dev, &made);

			mutex_lock(&ft_wifi_lock);
			list_for_each_entry(w, &ft_wifi_watches, list) {
				if (w->dev != dev)
					continue;
				if (made) {
					w->vap = made;
					made = NULL;
					ft_wifi_registered++;
				} else {
					/* Give up on this device rather than
					 * spin: an add that failed once will
					 * fail the same way until something
					 * about the device changes, and every
					 * such change comes back through
					 * ft_wifi_reconsider(). */
					w->wanted = false;
					atomic64_inc(&ft_wifi_refusals);
				}
				break;
			}
			mutex_unlock(&ft_wifi_lock);

			/* Nothing on the list claimed it -- the watch went
			 * away while the transaction was open. Do not leak the
			 * registration it no longer owns. */
			if (made)
				cdx_wifi_vap_del(&made);
			if (rc && rc != -ENODEV)
				pr_warn_ratelimited("cdx flowtable: %s could not be offloaded as a Wi-Fi VAP (%d)\n",
						    netdev_name(dev), rc);
		} else {
			/* Already unlinked from its watch above, so this owns
			 * it outright and nothing else can reach it. */
			cdx_wifi_vap_del(&vap);
		}

		cdx_ft_admission_end();
		cdx_ft_end();
		if (dev)
			dev_put(dev);
	}
}

/* Retire every VAP this module registered. Unload cannot leave a logical
 * interface or a VWD slot owned by a module that is going away, and there is
 * no notifier replay for unregistration to do it. */
static void ft_wifi_exit(void)
{
	struct ft_wifi_watch *w, *tmp;

	mutex_lock(&ft_wifi_lock);
	ft_wifi_stopping = true;
	mutex_unlock(&ft_wifi_lock);
	cancel_work_sync(&ft_wifi_work);

	list_for_each_entry_safe(w, tmp, &ft_wifi_watches, list) {
		if (w->vap) {
			/* RTNL before the transaction, never after it: the bind
			 * path takes the transaction under RTNL (via dpa_setup_tc),
			 * so the reverse order here is a lock inversion lockdep
			 * reports at unload once a table has ever been bound. */
			rtnl_lock();
			cdx_ft_begin();
			cdx_wifi_vap_del(&w->vap);
			cdx_ft_end();
			rtnl_unlock();
			ft_wifi_registered--;
		}
		list_del(&w->list);
		kfree(w);
	}
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

/* The name a record's device has now, or "-" once it has left this namespace
 * and the record is waiting on the last direction naming it. gone is written
 * by the notifier under its own lock, which this walk, under the transaction,
 * does not take. */
static const char *ft_dev_stats_name(const struct cdx_ft_dev_stats *record, char *name)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = READ_ONCE(record->gone) ? NULL :
		dev_get_by_index_rcu(&init_net, record->ifindex);
	strscpy(name, dev ? netdev_name(dev) : "-", IFNAMSIZ);
	rcu_read_unlock();
	return name;
}

/* One row per device with a record of the given kind, whether or not the pool
 * had a slot for it: a device without one is the visible face of an exhausted
 * pool -- the flows forward either way, and this is what says which of them
 * are being counted. The counts are the firmware's own totals, whole frames,
 * with packets carried past the 32 bits the firmware keeps exactly as the fold
 * carries them; the device's `ip -s link` shows the same records restated in
 * its units, so the two differ by exactly the framing and nothing else. A ppp
 * device's row also carries the session its last admitted direction named, in
 * the form the flow rows use in in_ppp=/out_ppp=, so the two can be joined.
 * The rows sit with the header rather than in the paged flow iteration because
 * there is one per device, which is the number of uplinks and VLANs rather
 * than the number of connections. */
static void ft_tunnel_text(const struct cdx_ft_tunnel *tunnel, char *text, size_t size);

static void ft_dev_rows(struct seq_file *seq, enum cdx_ft_stats_kind kind, bool tunnel)
{
	struct cdx_ft_dev_stats *record;
	struct cdx_ft_stats rx, tx;
	char name[IFNAMSIZ], tnl[IFNAMSIZ + 100];

	list_for_each_entry(record, &ft_dev_stats, list) {
		if (record->kind != kind || record->tunnel.present != tunnel)
			continue;
		cdx_ft_stats_read(record->slot, &rx, &tx);
		if (kind == CDX_FT_STATS_TIMESTAMPED)
			seq_printf(seq,
				   "session dev=%s ifindex=%d pppoe=%u@%pM lower=%d refs=%u slot=%s rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu\n",
				   ft_dev_stats_name(record, name), record->ifindex,
				   record->session.id, record->session.mac,
				   record->session.lower_ifindex, record->refs,
				   record->slot ? "yes" : "none",
				   rx.packets, rx.bytes, tx.packets, tx.bytes);
		else if (tunnel) {
			/* The same identity the flow rows carry, so the two can
			 * be joined, plus the device the outer packet leaves by. */
			ft_tunnel_text(&record->tunnel, tnl, sizeof(tnl));
			seq_printf(seq,
				   "tunnel dev=%s ifindex=%d tnl=%s lower=%d refs=%u slot=%s rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu\n",
				   ft_dev_stats_name(record, name), record->ifindex, tnl,
				   record->tunnel.lower_ifindex, record->refs,
				   record->slot ? "yes" : "none",
				   rx.packets, rx.bytes, tx.packets, tx.bytes);
		} else
			seq_printf(seq,
				   "vlan dev=%s ifindex=%d refs=%u slot=%s rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu\n",
				   ft_dev_stats_name(record, name), record->ifindex, record->refs,
				   record->slot ? "yes" : "none",
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

/* The tunnel as the device, the mode and the outer endpoints local first,
 * which is how `ip -d link show` describes the device too. Shown for either
 * direction, because both come from the same walk and the strip side naming
 * the same tunnel as the insert side is what shows the connection agrees with
 * itself. An IPv6 endpoint is bracketed, as the row's other addresses are, so
 * the whole stays one whitespace-free token. */
static void ft_tunnel_text(const struct cdx_ft_tunnel *tunnel, char *text, size_t size)
{
	struct net_device *dev;
	const char *mode = tunnel->mode == CDX_FT_TUNNEL_6O4 ? "6o4" : "4o6";
	char name[IFNAMSIZ];

	if (!tunnel->present) {
		strscpy(text, "-", size);
		return;
	}
	/* By index and under RCU rather than by a pinned pointer: the record
	 * rows outlive the flows that pinned the device. */
	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, tunnel->ifindex);
	strscpy(name, dev ? dev->name : "?", sizeof(name));
	rcu_read_unlock();
	if (tunnel->family == AF_INET6)
		scnprintf(text, size, "%s/%s:[%pI6c]>[%pI6c]", name, mode,
			  &tunnel->local.in6, &tunnel->remote.in6);
	else
		scnprintf(text, size, "%s/%s:%pI4>%pI4", name, mode,
			  &tunnel->local.ip, &tunnel->remote.ip);
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
	struct cdx_ft_dev_stats *record;
	struct cdx_ft_entry *entry;
	struct cdx_ft_counters stats;
	unsigned int session_records = 0, session_slots = 0, vlan_records = 0, vlan_slots = 0;
	unsigned int tunnel_records = 0, tunnel_slots = 0;
	char in_vlan[16], out_vlan[16];
	char in_br[IFNAMSIZ + 8], out_br[IFNAMSIZ + 8];
	char in_ppp[26], out_ppp[26];
	char in_tnl[IFNAMSIZ + 100], out_tnl[IFNAMSIZ + 100];
	char nexthop[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];

	if (v != &ft_entries) {
		entry = list_entry(v, struct cdx_ft_entry, list);
		cdx_ft_stats(entry->hw, &stats);
		ft_tunnel_text(&entry->rule.in_tunnel, in_tnl, sizeof(in_tnl));
		ft_tunnel_text(&entry->rule.out_tunnel, out_tnl, sizeof(out_tnl));
		ft_vlan_text(entry->rule.in_vlan, entry->rule.in_vlans, in_vlan, sizeof(in_vlan));
		ft_vlan_text(entry->rule.out_vlan, entry->rule.out_vlans, out_vlan,
			     sizeof(out_vlan));
		ft_bridge_text(entry->rule.in_bridge, entry->rule.in_bridge_vid, in_br,
			       sizeof(in_br));
		ft_bridge_text(entry->rule.out_bridge, entry->rule.out_bridge_vid, out_br,
			       sizeof(out_br));
		ft_session_text(&entry->rule.in_session, in_ppp, sizeof(in_ppp));
		ft_session_text(&entry->rule.out_session, out_ppp, sizeof(out_ppp));
		/* In its own family, which is not the row's for a flow encrypted
		 * by an SA of the other family. */
		if (entry->rule.next_hop_family == AF_INET6)
			snprintf(nexthop, sizeof(nexthop), "%pI6c", &entry->next_hop.in6);
		else
			snprintf(nexthop, sizeof(nexthop), "%pI4", &entry->next_hop.ip);
		/* One row shape per family. Brackets keep an IPv6 address and its
		 * port a single whitespace-free token, as the IPv4 rows already are. */
		if (entry->rule.family == AF_INET6)
			seq_printf(seq, "flow cookie=%lx in=%s out=%s in_vlan=%s out_vlan=%s in_br=%s out_br=%s in_ppp=%s out_ppp=%s in_tnl=%s out_tnl=%s family=6 src=[%pI6c]:%u dst=[%pI6c]:%u new_src=[%pI6c]:%u new_dst=[%pI6c]:%u proto=%u mtu=%u qos=%05x sa=%u in_sa=%u nexthop=%s packets=%llu bytes=%llu lastused=%u\n",
				   entry->cookie, entry->rule.in->name, entry->rule.out->name,
				   in_vlan, out_vlan, in_br, out_br, in_ppp, out_ppp,
				   in_tnl, out_tnl,
				   &entry->rule.src.in6, ntohs(entry->rule.sport),
				   &entry->rule.dst.in6, ntohs(entry->rule.dport),
				   &entry->rule.new_src.in6, ntohs(entry->rule.new_sport),
				   &entry->rule.new_dst.in6, ntohs(entry->rule.new_dport),
				   entry->rule.proto, entry->rule.mtu, entry->rule.qos,
				   entry->rule.sa_handle, entry->rule.in_sa_handle,
				   nexthop, stats.packets, stats.bytes, stats.lastused);
		else
			seq_printf(seq, "flow cookie=%lx in=%s out=%s in_vlan=%s out_vlan=%s in_br=%s out_br=%s in_ppp=%s out_ppp=%s in_tnl=%s out_tnl=%s family=4 src=%pI4:%u dst=%pI4:%u new_src=%pI4:%u new_dst=%pI4:%u proto=%u mtu=%u qos=%05x sa=%u in_sa=%u nexthop=%s packets=%llu bytes=%llu lastused=%u\n",
				   entry->cookie, entry->rule.in->name, entry->rule.out->name,
				   in_vlan, out_vlan, in_br, out_br, in_ppp, out_ppp,
				   in_tnl, out_tnl,
				   &entry->rule.src.ip, ntohs(entry->rule.sport),
				   &entry->rule.dst.ip, ntohs(entry->rule.dport),
				   &entry->rule.new_src.ip, ntohs(entry->rule.new_sport),
				   &entry->rule.new_dst.ip, ntohs(entry->rule.new_dport),
				   entry->rule.proto, entry->rule.mtu, entry->rule.qos,
				   entry->rule.sa_handle, entry->rule.in_sa_handle,
				   nexthop, stats.packets, stats.bytes, stats.lastused);
		return 0;
	}
	list_for_each_entry(record, &ft_dev_stats, list) {
		if (record->kind == CDX_FT_STATS_TIMESTAMPED) {
			session_records++;
			session_slots += !!record->slot;
		} else if (record->tunnel.present) {
			tunnel_records++;
			tunnel_slots += !!record->slot;
		} else {
			vlan_records++;
			vlan_slots += !!record->slot;
		}
	}
	/* The controller reads the mask back from here rather than from sysfs,
	 * because it already parses this header and must refuse a policy whose
	 * mark selectors contradict what the running adapter will decode. */
	seq_printf(seq, "qos_mark_mask %u\nqos_default_class %u\n",
		   ft_qos_mark_mask, ft_qos_default_class);
	/* Frames the software path forwarded unchanged because their header
	 * could not be made writable for the remark their class asks for. */
	seq_printf(seq, "qos_remark_failures %llu\n", cdx_ft_qos_remark_failures());
	/* Control frames sent as unclassified traffic because their port's
	 * control budget was spent. */
	seq_printf(seq, "qos_control_overruns %llu\n", cdx_ft_qos_control_overruns());
	seq_printf(seq, "observe %u\nbindings %u\npassive %u\nparked %u\nentries %u\nmax_entries %u\n"
		   "installs %llu\ndeletes %llu\nrejects %llu\nerrors %llu\nvalidated %llu\nbusy %llu\n"
		   "invalidated %u\ninvalidation_done %u\nfatal %u\nquarantine %u\n"
		   "rearm_ready %u\nrearms %llu\nneighbour_refs %u\nhandle_refs %u\n"
		   "neighbour_invalidations %lld\nroute_invalidations %lld\nmtu_invalidations %lld\nlink_invalidations %lld\nmac_invalidations %lld\nfdb_invalidations %lld\nstp_invalidations %lld\nqos_invalidations %lld\nadmission_invalidations %lld\nipsec_invalidations %lld\nipsec_policy_invalidations %lld\nipsec_next_hop_updates %lld\n",
		   cdx_ft_observing(), ft_bound, ft_passive, ft_parked, ft_count, CDX_FT_MAX_ENTRIES, ft_installs,
		   ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy, atomic_read(&ft_invalid),
		   ft_invalid_complete(), cdx_ft_failed(),
		   cdx_ft_pending(),
		   ft_can_rearm(), ft_rearms, ft_neighbour_refs, ft_handle_refs,
		   atomic64_read(&ft_neigh_invalidations),
		   atomic64_read(&ft_route_invalidations),
		   atomic64_read(&ft_mtu_invalidations),
		   atomic64_read(&ft_link_invalidations),
		   atomic64_read(&ft_mac_invalidations),
		   atomic64_read(&ft_fdb_invalidations),
		   atomic64_read(&ft_stp_invalidations),
		   atomic64_read(&ft_qos_invalidations),
		   atomic64_read(&ft_admission_invalidations),
		   atomic64_read(&ft_ipsec_invalidations),
		   atomic64_read(&ft_ipsec_policy_invalidations),
		   atomic64_read(&ft_ipsec_next_hop_updates));
	seq_printf(seq, "session_records %u\nsession_slots %u\n",
		   session_records, session_slots);
	ft_dev_rows(seq, CDX_FT_STATS_TIMESTAMPED, false);
	seq_printf(seq, "vlan_records %u\nvlan_slots %u\n", vlan_records, vlan_slots);
	ft_dev_rows(seq, CDX_FT_STATS_PLAIN, false);
	seq_printf(seq, "tunnel_records %u\ntunnel_slots %u\n", tunnel_records, tunnel_slots);
	ft_dev_rows(seq, CDX_FT_STATS_PLAIN, true);
	/* Memberships the bridge reported, and the flows learned from traffic
	 * that they and the routed learner's routes name; `installed` counts
	 * flows, each one classifier entry. */
	seq_printf(seq, "mcast_groups %u\nmcast_flows %u\nmcast_installed %u\nmcast_refused %llu\n"
		   "mcast_install_errors %llu\nmcast_observed %llu\nmcast_dropped %llu\n"
		   "mcast_hooked %u\nmcast_hook_errors %llu\n",
		   ft_mc_count, ft_mc_flow_count, ft_mc_installed, ft_mc_refused,
		   ft_mc_install_errors, ft_mc_observed, ft_mc_dropped,
		   ft_mc_hooked, ft_mc_hook_errors);
	/* Installed groups of either learner marked for a rebuild because a
	 * port they copy out of changed its egress -- its queues or its DSCP
	 * map; see ft_mc_egress_changed(). */
	seq_printf(seq, "mcast_egress_rebuilds %lld\n",
		   atomic64_read(&ft_mc_egress_rebuilds));
	/* The routed learner's own totals. mroute_policy_rules is the one an
	 * operator is most likely to need: a single non-default ipmr rule
	 * keeps every group of that family in software, and nothing else on
	 * the box would say so. mroute_lost counts chain events dropped for
	 * want of memory, which is the only way this learner's view can be
	 * behind the kernel's. */
	seq_printf(seq, "mroute_groups %u\nmroute_installed %u\nmroute_refused %llu\n"
		   "mroute_install_errors %llu\nmroute_policy_rules %u\nmroute_lost %llu\n",
		   ft_mr_count, ft_mr_installed, ft_mr_refused,
		   ft_mr_install_errors, ft_mr_policy[0] + ft_mr_policy[1],
		   ft_mr_lost);
	/* How many times an nftables commit took every routed group back to
	 * software to be confirmed again; whether the ruleset has stood still
	 * long enough since for copies to confirm under it -- followed only
	 * while a routed group exists, so with none it is the last value read,
	 * which may predate a commit; and how often the
	 * forwarding check could not be registered or a group's watch
	 * allocated -- which keeps groups in software with nothing else to say
	 * why. */
	seq_printf(seq, "mroute_ruleset_changes %llu\nmroute_ruleset_settled %d\nmroute_confirm_errors %llu\n",
		   READ_ONCE(ft_mr_ruleset_changes), READ_ONCE(ft_mr_gen_open),
		   READ_ONCE(ft_mr_confirm_errors));
	/* How many AP-mode devices this module currently has registered, and
	 * how many it looked at and did not. The second is what separates "no
	 * Wi-Fi offload because nothing asked" from "no Wi-Fi offload because
	 * the registration failed", which are otherwise the same absence: the
	 * per-VAP sysfs file under /sys/class/vwd/ appears only on success, so
	 * without this a refusal leaves no trace anywhere. */
	seq_printf(seq, "wifi_vaps %u\nwifi_refused %llu\n",
		   ft_wifi_registered, atomic64_read(&ft_wifi_refusals));
	ft_mc_rows(seq);
	ft_mr_rows(seq);
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

/* Give back the callbacks Netfilter is still holding.
 *
 * A bind installs a flow_block_cb into the flowtable's own block, and
 * Netfilter keeps it until something unbinds. flow_indr_dev_unregister()
 * unwinds the *indirect* binds for us and knows nothing about the direct
 * ones -- which is every bind since the driver grew an ndo_setup_tc, because
 * that is what nf_flow_table_offload_setup() prefers once it exists. Left
 * behind, the callback still points into this module's text, and the next
 * queued offload calls it: flow_offload_work_handler faulting on freed text
 * with the flowtable itself perfectly healthy. Both exit and a load that
 * fails after opening a route owe this.
 *
 * Any callback still on the driver list belongs to a table that is still
 * live, because a table on its way out unbinds first. Its lock is therefore
 * safe to take, and taking it for write is also what waits out a callback
 * already running on nf_flow_offload_tuple()'s read side -- so no caller is
 * inside this text by the time it goes.
 */
static void ft_block_drain(void)
{
	struct flow_block_cb *cb, *next;
	struct nf_flowtable *table;

	list_for_each_entry_safe(cb, next, &ft_block_list, driver_list) {
		/* Passive or real alike: both carry their table. */
		table = ((struct cdx_ft_binding *)cb->cb_priv)->table;
		down_write(&table->flow_block_lock);
		list_del(&cb->list);
		up_write(&table->flow_block_lock);
		list_del(&cb->driver_list);
		/* Runs ft_release(), which retires this binding's entries and
		 * drops its device reference, exactly as an unbind would. */
		flow_block_cb_free(cb);
	}
}

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
	    (ft_qos_mark_mask >> __ffs(ft_qos_mark_mask)) > CDX_FT_QOS_MASK) {
		pr_err("cdx flowtable: qos_mark_mask %#x spans more than the %u bits of a class\n",
		       ft_qos_mark_mask, (unsigned int)fls(CDX_FT_QOS_MASK));
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
	/* Be told when a port's egress changes under its entries -- before
	 * anything can build one. The netdev replay below attaches the ports
	 * an SA is installed through, and a flow needs the binds after it; an
	 * entry built before this, from egress that changed before it too,
	 * would never be re-installed. */
	rc = ft_init_fault(11) ? -EBUSY : cdx_register_ft_egress(&ft_egress_ops);
	if (rc)
		goto proc;
	rc = ft_init_fault(2) ? -ENOMEM : register_netdevice_notifier(&ft_netdev_nb);
	if (rc)
		goto egress;
	rc = ft_init_fault(3) ? -ENOMEM : register_netevent_notifier(&ft_neigh_nb);
	if (rc)
		goto netdev;
	rc = ft_init_fault(4) ? -ENOMEM : register_fib_notifier(&init_net, &ft_fib_nb, NULL, NULL);
	if (rc)
		goto neigh;
	/* A registration retry can replay the same rules more than once.
	 * Replace its queued multicast mirror before authorizing hardware. */
	set_bit(0, &ft_mr_resync_pending);
	set_bit(1, &ft_mr_resync_pending);
	smp_store_release(&ft_mr_ready, true);
	schedule_work(&ft_mr_work);
	rc = ft_init_fault(6) ? -ENOMEM : register_nexthop_notifier(&init_net, &ft_nexthop_nb, NULL);
	if (rc)
		goto fib;
	rc = ft_init_fault(7) ? -ENOMEM : register_switchdev_notifier(&ft_fdb_nb);
	if (rc)
		goto nexthop;
	rc = ft_init_fault(8) ? -ENOMEM : register_switchdev_blocking_notifier(&ft_swdev_nb);
	if (rc)
		goto fdb;
	/* The chain replays nothing on registration; the memberships already
	 * standing are asked for instead. */
	ft_mc_replay();
	WRITE_ONCE(ft_ready, true);
	rc = ft_init_fault(5) ? -ENOMEM : flow_indr_dev_register(ft_bind, NULL);
	if (rc)
		goto not_ready;
	/* Both routes stay registered. Which one Netfilter uses is the driver's
	 * choice, not ours, and a kernel without the ndo has only the indirect
	 * one -- so the adapter has to serve whichever arrives. The direct route
	 * arrives through CDX, which holds the driver's single ndo_setup_tc slot
	 * because it also serves the hardware qdisc on the same callback. */
	rc = ft_init_fault(9) ? -EBUSY : cdx_register_ft_setup_tc(cdx_ft_setup_tc);
	if (rc)
		goto indirect;
	/* Hand the classifier over too, so a frame the software path sends
	 * takes the class this same decode gave the flow's hardware rule. */
	rc = ft_init_fault(10) ? -EBUSY :
	     cdx_register_ft_qos_class(ft_qos_flow_class, ft_qos_remarks());
	if (!rc)
		return 0;
	cdx_unregister_ft_setup_tc();
indirect:
	/* A route was open, so binds may have arrived and be carrying flows,
	 * with work queued on their behalf. Unwind them the way exit does:
	 * stop new binds and requeueing, and exclude Linux's cached lookups,
	 * in one transaction; give the indirect binds back, then drain the
	 * direct ones, which Netfilter would otherwise keep pointing into
	 * text about to go. */
	cdx_ft_begin();
	WRITE_ONCE(ft_stopping, true);
	{
		struct cdx_ft_entry *entry;

		list_for_each_entry(entry, &ft_entries, list)
			nf_flow_offload_handle_invalidate(entry->handle);
	}
	cdx_ft_end();
	flow_indr_dev_unregister(ft_bind, NULL, ft_release);
	ft_block_drain();
not_ready:
	/* ft_rearm() reads ft_ready under the transaction, so clearing it
	 * there means no pass that starts later requeues a parked retry. The
	 * works themselves are cancelled below, once CDX's egress hook, which
	 * can queue retirement, is closed too. */
	cdx_ft_begin();
	WRITE_ONCE(ft_ready, false);
	cdx_ft_end();
	unregister_switchdev_blocking_notifier(&ft_swdev_nb);
	/* A port may have stopped since the chain was registered: its sweep
	 * runs this module's code, so it finishes before the text goes. */
	flush_work(&ft_stopped_work);
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
	/* Before the work below is cancelled, as on unload: the hook marks
	 * entries and SAs and queues the passes that act on them. */
	cdx_unregister_ft_egress();
	/* A route may have been open, with work queued on a binding's behalf.
	 * With ft_stopping set nothing requeues retirement or the installer,
	 * with ft_ready clear nothing requeues a parked retry, and with every
	 * binding gone and the notifiers and the egress hook closed nothing is
	 * left to queue any of them, so these cancels are final. */
	cancel_work_sync(&ft_retire_work);
	cancel_delayed_work_sync(&ft_work);
	cancel_delayed_work_sync(&ft_rearm_work);
	/* Both chains are unregistered above, so nothing can add a membership
	 * or an MFC entry while these drain. What already existed was replayed
	 * at registration -- the FIB notifier dumps every VIF and MFC entry,
	 * and ft_mc_replay() asks every bridge port for its port groups -- so a
	 * failure after those points has memberships, flows, hardware entries
	 * and pinned devices to give back, and a worker holding a pointer into
	 * text about to go. */
	ft_mc_exit();
	ft_mr_exit();
	/* The notifier's registration replayed NETDEV_REGISTER and attached
	 * every port, so a failure after that point has ports to give back.
	 * No SA can have been installed through them: xfrm_dev_ops_get()
	 * hands out the ops of a module only once it is live, so xfrm offers
	 * this one no state or policy until init has returned. */
	ft_ipsec_detach_all();
	/* The same replay could have registered a VAP for an AP interface that
	 * already existed, so this failure path owes them back too. */
	ft_wifi_exit();
	/* Idle for that reason, and drained anyway: each costs nothing when
	 * there is nothing queued, and none may outlive this text. */
	flush_work(&ft_ipsec_retire);
	cancel_delayed_work_sync(&ft_ipsec_stats);
	cancel_work_sync(&ft_ipsec_follow);
	ft_ipsec_watch_flush();
	/* A flow admitted through the indirect bind before the failure claimed
	 * device records, and those outlive their flows by design, so the
	 * unwind has to drop them: left behind, their slots would stay
	 * published against live devices from memory about to be unmapped. The
	 * notifier that could queue the reaper is already unregistered above. */
	cancel_work_sync(&ft_dev_stats_work);
	ft_dev_stats_drop_all();
	goto proc;
egress:
	/* Nothing the hook could mark exists before the netdev replay. */
	cdx_unregister_ft_egress();
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
	/* After the chain that queues it, and while the rule callbacks its
	 * native cleanup flushes are still registered: a port that stopped
	 * forwarding just before unload still has its software flows taken
	 * away, and the work's text outlives it. */
	flush_work(&ft_stopped_work);
	unregister_switchdev_notifier(&ft_fdb_nb);
	unregister_nexthop_notifier(&init_net, &ft_nexthop_nb);
	unregister_fib_notifier(&init_net, &ft_fib_nb);
	unregister_netevent_notifier(&ft_neigh_nb);
	unregister_netdevice_notifier(&ft_netdev_nb);
	/* CDX's egress hook is the other thing that marks entries and SAs, and
	 * no notifier above is what excludes it. Close it with them, before
	 * any of the work it queues is cancelled below; this also waits out a
	 * call already inside it. */
	cdx_unregister_ft_egress();
	/* After the switchdev chain is gone, so nothing can add a membership
	 * while the groups drain, and before the module's text does -- the
	 * worker holds a pointer into it. */
	ft_mc_exit();
	/* And after the FIB chain, for the same reason one family over: the
	 * routed learner's events arrive there. It goes second so that a key
	 * the bridged learner hands back cannot wake a worker this has already
	 * stopped -- ft_mr_kick() answers to ft_mr_stopping either way, but
	 * the order makes that a property rather than a coincidence. */
	ft_mr_exit();
	/* Likewise for the VAPs, and before the module's text goes: the
	 * reconciling worker holds a pointer into it. */
	ft_wifi_exit();
	/* Unregistration replays nothing, so the ops this module planted on
	 * each port have to be taken back by hand -- they point into text
	 * that is about to go away. */
	ft_ipsec_detach_all();
	/* Detaching stops new retirements being queued; this drains the ones
	 * already queued. Both are needed before the work item's own code can
	 * be unmapped, and this order is the only one that ends with an empty
	 * list. */
	flush_work(&ft_ipsec_retire);
	/* The accounting pass requeues itself only while an SA is owned, and
	 * none is by now: every offloaded state pins this module through its
	 * ops, and xfrm deletes a state before it lets it go. */
	cancel_delayed_work_sync(&ft_ipsec_stats);
	/* The notifiers that mark a watch are gone above, so nothing can queue
	 * this again; stop the pass in flight and drop the watches it walked,
	 * which are this module's memory rather than the kernel's. */
	cancel_work_sync(&ft_ipsec_follow);
	ft_ipsec_watch_flush();
	cancel_work_sync(&ft_retire_work);
	cancel_delayed_work_sync(&ft_work);
	/* ft_stopping, set above, already stops a parked rearm requeueing
	 * itself; this waits out the pass in flight. */
	cancel_delayed_work_sync(&ft_rearm_work);
	/* Direct first: it is the route a DPAA port actually takes, so closing
	 * it stops new binds before the indirect one is torn down. The
	 * classifier goes with it, and waits out the frames inside it. */
	cdx_unregister_ft_setup_tc();
	cdx_unregister_ft_qos_class();
	flow_indr_dev_unregister(ft_bind, NULL, ft_release);
	/* Indirect binds are gone with the line above; the direct ones are
	 * still Netfilter's, and nothing else will ever hand them back. */
	ft_block_drain();
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
	/* The device records are held by their devices, which are still here,
	 * so the list does not drain on its own; the release above proved that
	 * nothing references them. The notifier that could queue the reaper is
	 * already unregistered above. */
	cancel_work_sync(&ft_dev_stats_work);
	ft_dev_stats_drop_all();
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ASK Linux flowtable adapter using the CDX hardware backend");
MODULE_IMPORT_NS(ASK_CDX_FLOWTABLE);
module_init(ask_flowtable_init);
module_exit(ask_flowtable_exit);

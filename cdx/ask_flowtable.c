// SPDX-License-Identifier: GPL-2.0-or-later
/* Linux flowtable adapter for bounded IPv4 TCP and UDP offload.
 *
 * Backend transactions serialize hardware operations and adapter lists. Rule callbacks are
 * process-context NF workqueue callbacks. Binding release runs after the
 * flow-block core excludes callbacks. Notifiers only latch invalidation and
 * queue work; they never start a backend transaction. Neighbour notifications inspect
 * immutable watched dependencies under ft_neigh_lock, nested inside neigh->lock.
 * Invalidation ends its transaction before flushing Netfilter work. The backend
 * uses RTNL trylock for admission and fatal recovery, never a blocking acquire.
 * Each binding pins its ingress device; each installed direction pins egress.
 */
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/fib_notifier.h>
#include <net/flow_offload.h>
#include <net/netevent.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_flow_table.h>
#include "cdx_flowtable_backend.h"

#if !defined(FLOW_CLS_HAS_NF_CONTEXT) || FLOW_CLS_HAS_NF_CONTEXT < 5
#error "CDX flowtable requires patches/kernel/140-ask-flowtable-context.patch"
#endif

#ifdef CDX_DEBUG_FLOWTABLE
static unsigned int ft_fail_stage;
static unsigned int ft_init_fail_stage;
module_param_named(init_fail_stage, ft_init_fail_stage, uint, 0444);
MODULE_PARM_DESC(init_fail_stage, "Fail adapter load: 1 proc, 2 netdev, 3 neighbour, 4 FIB, 5 indirect registration");
module_param_named(flowtable_fail_stage, ft_fail_stage, uint, 0600);
MODULE_PARM_DESC(flowtable_fail_stage, "One-shot add failure: 1 before allocation, 2 before hardware, 3 after hardware");
#endif

struct cdx_ft_binding {
	struct list_head list;
	struct net_device *dev;
	struct nf_flowtable *table; /* retained as identity; borrowed in bind only */
};

struct cdx_ft_entry {
	struct list_head list;
	struct list_head neigh_list;
	struct neighbour *neigh;
	struct nf_flow_offload_handle *handle;
	__be32 next_hop;
	struct cdx_ft_binding *binding;
	unsigned long cookie;
	struct cdx_ft_rule rule;
	struct cdx_ft_hw *hw;
	struct cdx_ft_counters reported;
};

/* Bound the backend transaction and atomic neighbour-list walks while proving
 * independent connection lifetimes. This is an adapter admission limit, not
 * firmware capacity; directions consume slots independently, without eviction.
 */
#define CDX_FT_MAX_ENTRIES 64U

static LIST_HEAD(ft_bindings);
static LIST_HEAD(ft_entries);
/* Watch publication/removal is serialized by the backend transaction. Atomic neighbour and
 * route notifiers share the immutable rule, neigh and handle, protected against
 * entry removal here. Never take a neighbour lock while holding this lock. */
static LIST_HEAD(ft_neigh_entries);
static DEFINE_SPINLOCK(ft_neigh_lock);
static LIST_HEAD(ft_block_list);
static unsigned int ft_bound, ft_count;
static unsigned int ft_neighbour_refs;
static unsigned int ft_handle_refs;
static atomic64_t ft_neigh_invalidations = ATOMIC64_INIT(0);
static atomic64_t ft_route_invalidations = ATOMIC64_INIT(0);
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

	list_for_each_entry(entry, &ft_entries, list)
		if (entry->binding == binding && entry->cookie == cookie)
			return entry;
	return NULL;
}

/* Called with either the backend transaction or the notifier's ft_neigh_lock held. The
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

static int ft_remove(struct cdx_ft_entry *entry)
{
	int rc = cdx_ft_del(&entry->hw);

	if (rc) {
		ft_errors++;
		ft_invalidate();
	}
	list_del(&entry->list);
	ft_neigh_detach(entry);
	nf_flow_offload_handle_put(entry->handle);
	ft_handle_refs--;
	dev_put(entry->rule.out);
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

static bool ft_neigh_check(struct net_device *dev, __be32 dst, const u8 *mac)
{
	struct neighbour *neigh = neigh_lookup(&arp_tbl, &dst, dev);
	bool valid;

	if (!neigh)
		return false;
	read_lock_bh(&neigh->lock);
	valid = ft_neigh_matches(neigh, mac);
	read_unlock_bh(&neigh->lock);
	neigh_release(neigh);
	return valid;
}

/* Borrow the route selected by Netfilter, not a second FIB lookup which could
 * lose its policy/ingress context. Patch 140 supplies only retained NEIGH dsts.
 * No route pointer escapes the callback. IPv6 gateways and transformed routes
 * need separate contracts even when the matched packet itself is IPv4. */
static bool ft_next_hop(const struct flow_cls_offload *cls,
			struct net_device *dev, __be32 daddr, __be32 *next_hop)
{
	struct dst_entry *dst = cls->nf_dst;
	const struct rtable *rt;

	if (!dst || dst->ops->family != AF_INET || dst->dev != dev ||
	    dst_xfrm(dst) || dst->lwtstate || !dst_check(dst, 0))
		return false;
	rt = dst_rtable(dst);
	if (rt->rt_type != RTN_UNICAST ||
	    (rt->rt_gw_family && rt->rt_gw_family != AF_INET))
		return false;
	*next_hop = rt_nexthop(rt, daddr);
	return !ipv4_is_multicast(*next_hop) && !ipv4_is_zeronet(*next_hop) &&
		!ipv4_is_loopback(*next_hop) && !ipv4_is_lbcast(*next_hop);
}

/* Admission holds RTNL. Check both borrowed destinations after taking it:
 * a callback queued before a route change must not install even its otherwise
 * valid direction. The invalid handle makes Linux retire that generation.
 * Never re-resolve a route here with an incomplete policy/ingress context.
 */
static bool ft_routes_valid(const struct flow_cls_offload *cls)
{
	return cls->nf_dst && cls->nf_dst_reverse &&
		dst_check(cls->nf_dst, 0) && dst_check(cls->nf_dst_reverse, 0);
}

static int ft_neigh_attach(struct cdx_ft_entry *entry)
{
	struct neighbour *neigh;
	bool valid;

	neigh = neigh_lookup(&arp_tbl, &entry->next_hop, entry->rule.out);
	if (!neigh)
		return -EOPNOTSUPP;
	/* Recheck at watch publication: the mapping may have changed after the
	 * decoder validated it. Publish before hardware insertion so a notifier
	 * during insertion latches invalidation and forces the normal rollback. */
	read_lock_bh(&neigh->lock);
	valid = ft_neigh_matches(neigh, entry->rule.dst_mac);
	if (valid) {
		spin_lock(&ft_neigh_lock);
		entry->neigh = neigh;
		list_add_tail(&entry->neigh_list, &ft_neigh_entries);
		spin_unlock(&ft_neigh_lock);
		ft_neighbour_refs++;
	}
	read_unlock_bh(&neigh->lock);
	if (!valid)
		neigh_release(neigh);
	return valid ? 0 : -EOPNOTSUPP;
}

static void ft_neigh_detach(struct cdx_ft_entry *entry)
{
	struct neighbour *neigh = entry->neigh;

	if (!neigh)
		return;
	spin_lock_bh(&ft_neigh_lock);
	list_del(&entry->neigh_list);
	spin_unlock_bh(&ft_neigh_lock);
	entry->neigh = NULL;
	ft_neighbour_refs--;
	neigh_release(neigh);
}

static bool ft_neigh_used(struct cdx_ft_entry *entry, bool active)
{
	struct neighbour *neigh = entry->neigh;
	bool valid;

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

/* Exact masks ensure that no selector which hardware cannot enforce is lost.
 * nf_flowtable supplies the routing semantics (including TTL decrement); its
 * Ethernet rewrites are four native-endian mangle words and a final redirect. */
static int ft_parse(struct cdx_ft_binding *binding,
		    const struct flow_cls_offload *cls, struct cdx_ft_rule *out,
		    __be32 *next_hop)
{
	const unsigned long keys = BIT(FLOW_DISSECTOR_KEY_META) |
		BIT(FLOW_DISSECTOR_KEY_CONTROL) | BIT(FLOW_DISSECTOR_KEY_BASIC) |
		BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) | BIT(FLOW_DISSECTOR_KEY_PORTS);
	struct flow_rule *rule = cls->rule;
	struct flow_match_meta meta;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ipv4_addrs ipv4;
	struct flow_match_ports ports;
	struct flow_match_tcp tcp;
	const struct flow_action_entry *action;
	static const u32 offsets[4] = { 4, 8, 0, 4 };
	static const u32 masks[4] = { 0x0000ffff, 0, 0, 0xffff0000 };
	u8 ethernet[12] = {};
	u32 word;
	int i;

	if (!rule || !cls->nf_ct || !cls->nf_mtu || cls->nf_counter ||
	    !nf_flow_offload_handle_valid(cls->nf_handle) ||
	    !net_eq(nf_ct_net(cls->nf_ct), &init_net) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_ORIGINAL) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_REPLY) ||
	    READ_ONCE(cls->nf_ct->mark) ||
	    (READ_ONCE(cls->nf_ct->status) & IPS_NAT_MASK) ||
	    cls->common.chain_index || cls->common.protocol != ETH_P_ALL ||
	    (rule->match.dissector->used_keys != keys &&
	     rule->match.dissector->used_keys != (keys | BIT(FLOW_DISSECTOR_KEY_TCP))))
		return -EOPNOTSUPP;
	flow_rule_match_meta(rule, &meta);
	flow_rule_match_control(rule, &control);
	flow_rule_match_basic(rule, &basic);
	flow_rule_match_ipv4_addrs(rule, &ipv4);
	flow_rule_match_ports(rule, &ports);
	if (meta.mask->ingress_ifindex != -1 || meta.mask->ingress_iftype ||
	    meta.mask->l2_miss || meta.key->ingress_ifindex != binding->dev->ifindex ||
	    control.mask->addr_type != 0xffff || control.mask->flags ||
	    control.mask->thoff || control.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS ||
	    basic.mask->n_proto != htons(0xffff) || basic.mask->ip_proto != 0xff ||
	    basic.key->n_proto != htons(ETH_P_IP) ||
	    basic.key->ip_proto != nf_ct_protonum(cls->nf_ct) ||
	    ipv4.mask->src != htonl(0xffffffff) || ipv4.mask->dst != htonl(0xffffffff) ||
	    ports.mask->src != htons(0xffff) || ports.mask->dst != htons(0xffff) ||
	    !ports.key->src || !ports.key->dst ||
	    ipv4_is_multicast(ipv4.key->src) || ipv4_is_multicast(ipv4.key->dst) ||
	    ipv4_is_zeronet(ipv4.key->src) || ipv4_is_zeronet(ipv4.key->dst) ||
	    ipv4_is_loopback(ipv4.key->src) || ipv4_is_loopback(ipv4.key->dst) ||
	    ipv4_is_lbcast(ipv4.key->src) || ipv4_is_lbcast(ipv4.key->dst) ||
	    rule->action.num_entries != 5)
		return -EOPNOTSUPP;
	switch (basic.key->ip_proto) {
	case IPPROTO_TCP:
		if (rule->match.dissector->used_keys !=
		    (keys | BIT(FLOW_DISSECTOR_KEY_TCP)) ||
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
		if (rule->match.dissector->used_keys != keys)
			return -EOPNOTSUPP;
		break;
	default:
		return -EOPNOTSUPP;
	}
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
	action = &rule->action.entries[4];
	if (action->id != FLOW_ACTION_REDIRECT || !cdx_ft_port_supported(action->dev) ||
	    !cdx_ft_port_supported(binding->dev) || action->dev == binding->dev ||
	    !is_valid_ether_addr(ethernet) ||
	    !ether_addr_equal(ethernet + ETH_ALEN, action->dev->dev_addr) ||
	    !ft_next_hop(cls, action->dev, ipv4.key->dst, next_hop) ||
	    !ft_neigh_check(action->dev, *next_hop, ethernet) ||
	    cls->nf_mtu > action->dev->mtu || cls->nf_mtu < 68)
		return -EOPNOTSUPP;
	memset(out, 0, sizeof(*out));
	out->in = binding->dev;
	out->out = action->dev;
	out->src = ipv4.key->src;
	out->dst = ipv4.key->dst;
	out->sport = ports.key->src;
	out->dport = ports.key->dst;
	out->proto = basic.key->ip_proto;
	out->mtu = cls->nf_mtu;
	ether_addr_copy(out->dst_mac, ethernet);
	ether_addr_copy(out->src_mac, ethernet + ETH_ALEN);
	return 0;
}

static bool ft_same_key(const struct cdx_ft_rule *a, const struct cdx_ft_rule *b)
{
	return a->in == b->in && a->src == b->src && a->dst == b->dst &&
		a->sport == b->sport && a->dport == b->dport && a->proto == b->proto;
}

static int ft_replace(struct cdx_ft_binding *binding, struct flow_cls_offload *cls)
{
	struct cdx_ft_entry *entry = ft_find(binding, cls->cookie), *other;
	struct cdx_ft_rule rule;
	__be32 next_hop;
	int rc;

	/* A delayed request must never replace a different flow generation
	 * merely because its opaque directional cookie has the same value. */
	if (entry && entry->handle != cls->nf_handle)
		return -ESTALE;
	if (nf_flow_offload_handle_valid(cls->nf_handle) && !ft_routes_valid(cls))
		ft_handle_invalidate(cls->nf_handle, &ft_route_invalidations);
	rc = ft_parse(binding, cls, &rule, &next_hop);
	if (!rc)
		ft_validated++;
	if (rc || cdx_ft_observing() || atomic_read(&ft_invalid) || ft_stopping || cdx_ft_failed()) {
		if (entry)
			ft_remove(entry);
		return rc ? rc : -EOPNOTSUPP;
	}
	if (entry) {
		if (entry->next_hop == next_hop &&
		    !memcmp(&entry->rule, &rule, sizeof(rule)))
			return 0;
		rc = ft_remove(entry);
		if (rc)
			return rc;
	}
	list_for_each_entry(other, &ft_entries, list)
		if (ft_same_key(&other->rule, &rule))
			return -EEXIST;
	if (ft_count >= CDX_FT_MAX_ENTRIES)
		return -ENOSPC;
	if (ft_fault(1))
		return -ENOMEM;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->rule = rule;
	entry->next_hop = next_hop;
	entry->binding = binding;
	entry->cookie = cls->cookie;
	entry->handle = cls->nf_handle;
	nf_flow_offload_handle_get(entry->handle);
	ft_handle_refs++;
	dev_hold(rule.out);
	rc = ft_neigh_attach(entry);
	if (!rc)
		rc = ft_fault(2) ? -EIO : cdx_ft_add(&rule, &entry->hw);
	if (rc) {
		ft_neigh_detach(entry);
		nf_flow_offload_handle_put(entry->handle);
		ft_handle_refs--;
		dev_put(rule.out);
		kfree(entry);
		return rc;
	}
	list_add_tail(&entry->list, &ft_entries);
	ft_count++;
	ft_installs++;
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
		 * flushing this workqueue. A busy configuration uses software. */
		if (cdx_ft_admission_begin()) {
			ft_busy++;
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
	list_del(&binding->list);
	ft_bound--;
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

static int ft_bind(struct net_device *dev, struct Qdisc *sch, void *priv,
		   enum tc_setup_type type, void *data, void *table,
		   void (*cleanup)(struct flow_block_cb *))
{
	struct flow_block_offload *bo = data;
	struct nf_flowtable *flowtable = table;
	struct cdx_ft_binding *binding, *other;
	struct flow_block_cb *cb;
	bool rearm;
	int rc = 0;

	if (type != TC_SETUP_FT || sch || !bo || !bo->block || !bo->net || !dev || !table ||
	    !net_eq(bo->net, &init_net) ||
	    bo->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;
	bo->driver_block_list = &ft_block_list;
	/* The indirect Netfilter path invokes us before block_setup takes its
	 * write lock. UNBIND moves a live callback onto bo's temporary list:
	 * exclude statistics/replace/delete walkers for that move as well as
	 * for the later free. Otherwise a walker can follow the temporary list
	 * head as if it were a callback. Take this before the CDX transaction,
	 * matching the order used by rule callbacks under the read lock. */
	if (bo->command == FLOW_BLOCK_UNBIND)
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
			if (other->table != table || other->dev == dev) {
				rc = -EBUSY;
				goto out;
			}
		binding = kzalloc(sizeof(*binding), GFP_KERNEL);
		if (!binding) {
			rc = -ENOMEM;
			goto out;
		}
		binding->dev = dev;
		binding->table = table;
		cb = flow_indr_block_cb_alloc(ft_rule_callback, dev, binding,
			ft_release, bo, dev, sch, table, NULL, cleanup);
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
		list_add_tail(&binding->list, &ft_bindings);
		ft_bound++;
		flow_block_cb_add(cb, bo);
		list_add_tail(&cb->driver_list, &ft_block_list);
	} else if (bo->command == FLOW_BLOCK_UNBIND) {
		cb = flow_block_cb_lookup(bo->block, ft_rule_callback, dev);
		if (!cb) {
			rc = -ENOENT;
			goto out;
		}
		flow_indr_block_cb_remove(cb, bo);
		list_del(&cb->driver_list);
	} else {
		rc = -EOPNOTSUPP;
	}
out:
	cdx_ft_end();
	if (bo->command == FLOW_BLOCK_UNBIND)
		up_write(&flowtable->flow_block_lock);
	return rc;
}

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

static int ft_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;
	switch (event) {
	case NETDEV_GOING_DOWN:
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEUPPER:
	case NETDEV_CHANGENAME:
		ft_invalidate();
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
	spin_lock_bh(&ft_neigh_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
		/* No NAT is admitted, so source is the reverse route destination.
		 * Check both endpoints even if only one direction installed. Match
		 * all tables/DSCP aliases conservatively: a new more-specific route
		 * can supersede a route which never emitted a deletion event. */
		if (!((entry->rule.dst ^ event->dst) & mask) ||
		    !((entry->rule.src ^ event->dst) & mask))
			ft_handle_invalidate(entry->handle, &ft_route_invalidations);
	}
	spin_unlock_bh(&ft_neigh_lock);
	return NOTIFY_DONE;
}

static int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct neighbour *neigh = ptr;
	struct cdx_ft_entry *entry;

	if (event == NETEVENT_IPV4_ROUTE_UPDATE)
		return ft_route_event(ptr);
	if (event != NETEVENT_NEIGH_UPDATE || neigh->tbl != &arp_tbl ||
	    !net_eq(dev_net(neigh->dev), &init_net))
		return NOTIFY_DONE;
	read_lock_bh(&neigh->lock);
	spin_lock(&ft_neigh_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list) {
		if (entry->neigh == neigh &&
		    !ft_neigh_matches(neigh, entry->rule.dst_mac)) {
			/* Ordinary NUD ageing with a usable MAC needs no retirement.
			 * Every connection sharing the bad neighbour is marked, and
			 * its other direction observes the same handle invalidation. */
			ft_neigh_invalidate(entry);
		}
	}
	spin_unlock(&ft_neigh_lock);
	read_unlock_bh(&neigh->lock);
	return NOTIFY_DONE;
}

static int ft_fib_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct fib_notifier_info *info = ptr;

	if (info->family != AF_INET)
		return NOTIFY_DONE;
	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_APPEND:
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_DEL:
		/* These selected-alias notifications can precede commit and omit
		 * other aliases. Patch 140 reports every committed prefix through
		 * NETEVENT_IPV4_ROUTE_UPDATE, including table flushes. */
		break;
	default:
		/* Rule/nexthop changes have no safe destination-prefix scope. */
		ft_invalidate();
	}
	return NOTIFY_DONE;
}

static struct notifier_block ft_netdev_nb = { .notifier_call = ft_netdev_event };
static struct notifier_block ft_neigh_nb = { .notifier_call = ft_neigh_event };
static struct notifier_block ft_fib_nb = { .notifier_call = ft_fib_event };

static int ft_show(struct seq_file *seq, void *unused)
{
	struct cdx_ft_entry *entry;
	struct cdx_ft_counters stats;

	cdx_ft_begin();
	seq_printf(seq, "owner %s\nobserve %u\nbindings %u\nentries %u\nmax_entries %u\n"
		   "installs %llu\ndeletes %llu\nrejects %llu\nerrors %llu\nvalidated %llu\nbusy %llu\n"
		   "invalidated %u\ninvalidation_done %u\nfatal %u\nquarantine %u\n"
		   "rearm_ready %u\nrearms %llu\nneighbour_refs %u\nhandle_refs %u\n"
		   "neighbour_invalidations %lld\nroute_invalidations %lld\n",
		   "flowtable", cdx_ft_observing(), ft_bound, ft_count, CDX_FT_MAX_ENTRIES, ft_installs,
		   ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy, atomic_read(&ft_invalid),
		   ft_invalid_done, cdx_ft_failed(),
		   cdx_ft_pending(),
		   ft_can_rearm(), ft_rearms, ft_neighbour_refs, ft_handle_refs,
		   atomic64_read(&ft_neigh_invalidations),
		   atomic64_read(&ft_route_invalidations));
	list_for_each_entry(entry, &ft_entries, list) {
		cdx_ft_stats(entry->hw, &stats);
		seq_printf(seq, "flow cookie=%lx in=%s out=%s src=%pI4:%u dst=%pI4:%u proto=%u mtu=%u nexthop=%pI4 packets=%llu bytes=%llu lastused=%u\n",
			   entry->cookie, entry->rule.in->name, entry->rule.out->name,
			   &entry->rule.src, ntohs(entry->rule.sport),
			   &entry->rule.dst, ntohs(entry->rule.dport), entry->rule.proto, entry->rule.mtu,
			   &entry->next_hop, stats.packets, stats.bytes, stats.lastused);
	}
	cdx_ft_end();
	return 0;
}
DEFINE_PROC_SHOW_ATTRIBUTE(ft);

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
	WRITE_ONCE(ft_ready, true);
	rc = ft_init_fault(5) ? -ENOMEM : flow_indr_dev_register(ft_bind, NULL);
	if (!rc)
		return 0;
	WRITE_ONCE(ft_ready, false);
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
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ASK Linux flowtable adapter using the CDX hardware backend");
MODULE_IMPORT_NS(ASK_CDX_FLOWTABLE);
module_init(ask_flowtable_init);
module_exit(ask_flowtable_exit);

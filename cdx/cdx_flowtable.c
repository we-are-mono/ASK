// SPDX-License-Identifier: GPL-2.0-or-later
/* Linux flowtable adapter, initially limited to two IPv4/UDP directions.
 *
 * Hardware operations and lists: cdx_info->ctrl.mutex. Rule callbacks are
 * process-context NF workqueue callbacks. Binding release runs after the
 * flow-block core excludes callbacks. Notifiers only latch invalidation and
 * queue work; they never take the control mutex or dereference rule objects.
 * Invalidation releases the mutex before flushing Netfilter work. Installation
 * and fatal recovery use RTNL trylock under the mutex, never a blocking acquire.
 * Each binding pins its ingress device; each installed direction pins egress.
 */
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/fib_notifier.h>
#include <net/flow_offload.h>
#include <net/netevent.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_flow_table.h>
#include "portdefs.h"
#include "cdx.h"
#include "control_ipv4.h"
#include "cdx_flowtable.h"
#include "cdx_flowtable_hw.h"
#include "devman.h"

#ifndef FLOW_CLS_HAS_NF_CONTEXT
#error "CDX flowtable requires patches/kernel/140-ask-flowtable-context.patch"
#endif

static char *offload_owner = "cmm";
module_param(offload_owner, charp, 0444);
MODULE_PARM_DESC(offload_owner, "Hardware flow owner: cmm (default) or flowtable; boot selection only");

static bool ft_observe;
module_param_named(flowtable_observe, ft_observe, bool, 0444);
MODULE_PARM_DESC(flowtable_observe, "Validate requests but decline hardware installation");

#ifdef CDX_DEBUG_FLOWTABLE
static unsigned int ft_fail_stage;
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
	struct cdx_ft_binding *binding;
	unsigned long cookie;
	struct cdx_ft_rule rule;
	struct cdx_ft_hw *hw;
	struct cdx_ft_counters reported;
};

static LIST_HEAD(ft_bindings);
static LIST_HEAD(ft_entries);
static LIST_HEAD(ft_block_list);
static unsigned int ft_bound, ft_count;
static u64 ft_installs, ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy;
static u64 ft_rearms;
static bool ft_ready, ft_stopping, ft_fatal;
static atomic_t ft_invalid = ATOMIC_INIT(0);
static bool ft_invalid_done;
static struct proc_dir_entry *ft_proc;
static void ft_invalidate_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_work, ft_invalidate_work);

bool cdx_flowtable_enabled(void)
{
	return !strcmp(offload_owner, "flowtable");
}

bool cdx_flowtable_ready(void)
{
	return READ_ONCE(ft_ready);
}

int cdx_flowtable_mode_check(void)
{
	if (strcmp(offload_owner, "cmm") && strcmp(offload_owner, "flowtable"))
		return -EINVAL;
	if (ft_observe && !cdx_flowtable_enabled())
		return -EINVAL;
	return 0;
}

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

static int ft_remove(struct cdx_ft_entry *entry)
{
	int rc = cdx_ft_hw_del(&entry->hw);

	if (rc) {
		ft_errors++;
		if (rc == -EIO)
			ft_fatal = true;
		ft_invalidate();
	}
	list_del(&entry->list);
	dev_put(entry->rule.out);
	kfree(entry);
	ft_count--;
	ft_deletes++;
	return rc;
}

static bool ft_physical(struct net_device *dev)
{
	POnifDesc onif;
	struct dpa_iface_info *iface;

	if (!dev || !net_eq(dev_net(dev), &init_net) ||
	    dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN ||
	    netif_is_bridge_port(dev) || netif_is_l3_slave(dev) ||
	    !netif_running(dev) || !netif_carrier_ok(dev) ||
	    !ether_addr_equal(dev->dev_addr, dev->perm_addr))
		return false;
	onif = get_onif_by_name(dev->name);
	if (!onif || onif->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL))
		return false;
	/* A name reused after a rename is not proof of physical-port identity. */
	iface = dpa_get_ifinfo_by_itfid(onif->itf->index);
	return iface && iface->eth_info.net_dev == dev;
}

static bool ft_permanent_neigh(struct net_device *dev, __be32 dst, const u8 *mac)
{
	struct neighbour *neigh = neigh_lookup(&arp_tbl, &dst, dev);
	bool valid;

	if (!neigh)
		return false;
	read_lock_bh(&neigh->lock);
	valid = neigh->nud_state == NUD_PERMANENT &&
		ether_addr_equal(neigh->ha, mac);
	read_unlock_bh(&neigh->lock);
	neigh_release(neigh);
	return valid;
}

/* Exact masks ensure that no selector which hardware cannot enforce is lost.
 * nf_flowtable supplies the routing semantics (including TTL decrement); its
 * Ethernet rewrites are four native-endian mangle words and a final redirect. */
static int ft_parse(struct cdx_ft_binding *binding,
		    const struct flow_cls_offload *cls, struct cdx_ft_rule *out)
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
	const struct flow_action_entry *action;
	static const u32 offsets[4] = { 4, 8, 0, 4 };
	static const u32 masks[4] = { 0x0000ffff, 0, 0, 0xffff0000 };
	u8 ethernet[12] = {};
	u32 word;
	int i;

	if (!rule || !cls->nf_ct || !cls->nf_mtu || cls->nf_counter ||
	    !net_eq(nf_ct_net(cls->nf_ct), &init_net) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_ORIGINAL) ||
	    nf_ct_zone_id(nf_ct_zone(cls->nf_ct), IP_CT_DIR_REPLY) ||
	    READ_ONCE(cls->nf_ct->mark) ||
	    (READ_ONCE(cls->nf_ct->status) & IPS_NAT_MASK) ||
	    cls->common.chain_index || cls->common.protocol != ETH_P_ALL ||
	    rule->match.dissector->used_keys != keys)
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
	    basic.key->n_proto != htons(ETH_P_IP) || basic.key->ip_proto != IPPROTO_UDP ||
	    ipv4.mask->src != htonl(0xffffffff) || ipv4.mask->dst != htonl(0xffffffff) ||
	    ports.mask->src != htons(0xffff) || ports.mask->dst != htons(0xffff) ||
	    !ports.key->src || !ports.key->dst ||
	    ipv4_is_multicast(ipv4.key->src) || ipv4_is_multicast(ipv4.key->dst) ||
	    ipv4_is_zeronet(ipv4.key->src) || ipv4_is_zeronet(ipv4.key->dst) ||
	    ipv4_is_loopback(ipv4.key->src) || ipv4_is_loopback(ipv4.key->dst) ||
	    ipv4_is_lbcast(ipv4.key->src) || ipv4_is_lbcast(ipv4.key->dst) ||
	    rule->action.num_entries != 5)
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
	action = &rule->action.entries[4];
	if (action->id != FLOW_ACTION_REDIRECT || !ft_physical(action->dev) ||
	    !ft_physical(binding->dev) || action->dev == binding->dev ||
	    !is_valid_ether_addr(ethernet) ||
	    !ether_addr_equal(ethernet + ETH_ALEN, action->dev->dev_addr) ||
	    !ft_permanent_neigh(action->dev, ipv4.key->dst, ethernet) ||
	    cls->nf_mtu > action->dev->mtu || cls->nf_mtu < 68)
		return -EOPNOTSUPP;
	memset(out, 0, sizeof(*out));
	out->in = binding->dev;
	out->out = action->dev;
	out->src = ipv4.key->src;
	out->dst = ipv4.key->dst;
	out->sport = ports.key->src;
	out->dport = ports.key->dst;
	out->mtu = cls->nf_mtu;
	ether_addr_copy(out->dst_mac, ethernet);
	ether_addr_copy(out->src_mac, ethernet + ETH_ALEN);
	return 0;
}

static bool ft_same_key(const struct cdx_ft_rule *a, const struct cdx_ft_rule *b)
{
	return a->in == b->in && a->src == b->src && a->dst == b->dst &&
		a->sport == b->sport && a->dport == b->dport;
}

static int ft_replace(struct cdx_ft_binding *binding, struct flow_cls_offload *cls)
{
	struct cdx_ft_entry *entry = ft_find(binding, cls->cookie), *other;
	struct cdx_ft_rule rule;
	int rc;

	rc = ft_parse(binding, cls, &rule);
	if (!rc)
		ft_validated++;
	if (rc || ft_observe || atomic_read(&ft_invalid) || ft_stopping || ft_fatal) {
		if (entry)
			ft_remove(entry);
		return rc ? rc : -EOPNOTSUPP;
	}
	if (entry) {
		if (!memcmp(&entry->rule, &rule, sizeof(rule)))
			return 0;
		rc = ft_remove(entry);
		if (rc)
			return rc;
	}
	list_for_each_entry(other, &ft_entries, list)
		if (ft_same_key(&other->rule, &rule))
			return -EEXIST;
	if (ft_count >= 2)
		return -ENOSPC;
	if (ft_fault(1))
		return -ENOMEM;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->rule = rule;
	entry->binding = binding;
	entry->cookie = cls->cookie;
	dev_hold(rule.out);
	rc = ft_fault(2) ? -EIO : cdx_ft_hw_add(&rule, &entry->hw);
	if (rc) {
		dev_put(rule.out);
		kfree(entry);
		return rc;
	}
	list_add_tail(&entry->list, &ft_entries);
	ft_count++;
	ft_installs++;
	if (ft_fault(3) || atomic_read(&ft_invalid)) {
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

	/* A table can enable counters after installation. Its matching frames
	 * may already have been counted again on a punt to Linux. Retire all
	 * directions and leave accounting to software; never publish hit counts
	 * as independently forwarded packets. */
	if (cls->nf_counter) {
		ft_invalidate();
		return -EOPNOTSUPP;
	}
	cdx_ft_hw_stats(entry->hw, &now);
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
	mutex_lock(&cdx_info->ctrl.mutex);
	entry = ft_find(binding, cls->cookie);
	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		/* Never wait for RTNL here: device teardown under RTNL may be
		 * flushing this workqueue. A busy configuration uses software. */
		if (!rtnl_trylock()) {
			ft_busy++;
			rc = -EAGAIN;
		} else {
			rc = ft_replace(binding, cls);
			rtnl_unlock();
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
	mutex_unlock(&cdx_info->ctrl.mutex);
	return rc;
}

static void ft_release(void *priv)
{
	struct cdx_ft_binding *binding = priv;
	struct cdx_ft_entry *entry, *next;

	mutex_lock(&cdx_info->ctrl.mutex);
	list_for_each_entry_safe(entry, next, &ft_entries, list)
		if (entry->binding == binding)
			ft_remove(entry);
	list_del(&binding->list);
	ft_bound--;
	mutex_unlock(&cdx_info->ctrl.mutex);
	dev_put(binding->dev);
	kfree(binding);
}

/* All previous callbacks must have lost their bindings, and the worker must
 * have finished both hardware retirement and Linux flow cleanup. Completion
 * is published as its last action under ctrl.mutex, so an old worker cannot
 * change a newly admitted table. Never reset the fatal latch or error history.
 */
static bool ft_can_rearm(void)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
	return ft_ready && !ft_stopping && !ft_fatal &&
		atomic_read(&ft_invalid) && ft_invalid_done &&
		!ft_bound && !ft_count && !cdx_ft_hw_pending() &&
		!cdx_ehash_quarantine_pending();
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
	mutex_lock(&cdx_info->ctrl.mutex);
	if (bo->command == FLOW_BLOCK_BIND) {
		rearm = atomic_read(&ft_invalid);
		if (!ft_ready || ft_stopping || ft_fatal || !ft_physical(dev) ||
		    ft_bound >= 2 || (rearm && !ft_can_rearm())) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		/* TC_SETUP_FT borrows this live table from Netfilter. A table
		 * whose hooks were detached can still contain cached flows and
		 * queued callbacks. Only an empty table may start recovery; its
		 * pointer value alone cannot distinguish reuse from recreation. */
		if (rearm && atomic_read(&flowtable->rhashtable.nelems)) {
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
	mutex_unlock(&cdx_info->ctrl.mutex);
	return rc;
}

static void ft_invalidate_work(struct work_struct *work)
{
	struct net_device *devices[2];
	struct cdx_ft_binding *binding;
	struct cdx_ft_entry *entry, *next;
	unsigned int n = 0, i;

	mutex_lock(&cdx_info->ctrl.mutex);
	list_for_each_entry_safe(entry, next, &ft_entries, list)
		ft_remove(entry);
	/* RTNL holders may flush Netfilter callbacks waiting for ctrl.mutex.
	 * Never block acquiring RTNL under that mutex. Retry quiescence until
	 * proven; software fallback is not declared while a key may be live. */
	if (ft_fatal) {
		int rc = -EAGAIN;

		if (rtnl_trylock()) {
			rc = dpa_cfg_quiesce();
			rtnl_unlock();
		}
		if (rc) {
			mutex_unlock(&cdx_info->ctrl.mutex);
			pr_err_ratelimited("cdx flowtable: waiting for hardware quiescence; reboot required\n");
			if (!READ_ONCE(ft_stopping))
				schedule_delayed_work(&ft_work, HZ);
			return;
		}
		pr_err("cdx flowtable: hardware stopped after unproven deletion; reboot required\n");
		cdx_ft_hw_quiesced();
	}
	if (cdx_ft_hw_retry()) {
		mutex_unlock(&cdx_info->ctrl.mutex);
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
	mutex_unlock(&cdx_info->ctrl.mutex);
	/* This flush waits for rule callbacks: never hold the control mutex. */
	for (i = 0; i < n; i++) {
		nf_flow_table_cleanup(devices[i]);
		dev_put(devices[i]);
	}
	mutex_lock(&cdx_info->ctrl.mutex);
	pr_info("cdx flowtable: invalidated; hardware admission disabled\n");
	/* No state changes or deferred work after publishing completion. A
	 * later first bind may now recover if every old binding has gone. */
	ft_invalid_done = true;
	mutex_unlock(&cdx_info->ctrl.mutex);
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

static int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct neighbour *neigh = ptr;

	if (event == NETEVENT_NEIGH_UPDATE && neigh->tbl == &arp_tbl &&
	    net_eq(dev_net(neigh->dev), &init_net))
		ft_invalidate();
	return NOTIFY_DONE;
}

static int ft_fib_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct fib_notifier_info *info = ptr;

	if (info->family == AF_INET)
		ft_invalidate();
	return NOTIFY_DONE;
}

static struct notifier_block ft_netdev_nb = { .notifier_call = ft_netdev_event };
static struct notifier_block ft_neigh_nb = { .notifier_call = ft_neigh_event };
static struct notifier_block ft_fib_nb = { .notifier_call = ft_fib_event };

static int ft_show(struct seq_file *seq, void *unused)
{
	struct cdx_ft_entry *entry;
	struct cdx_ft_counters stats;

	mutex_lock(&cdx_info->ctrl.mutex);
	seq_printf(seq, "owner %s\nobserve %u\nbindings %u\nentries %u\n"
		   "installs %llu\ndeletes %llu\nrejects %llu\nerrors %llu\nvalidated %llu\nbusy %llu\n"
		   "invalidated %u\ninvalidation_done %u\nfatal %u\nquarantine %u\n"
		   "rearm_ready %u\nrearms %llu\n",
		   offload_owner, ft_observe, ft_bound, ft_count, ft_installs,
		   ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy, atomic_read(&ft_invalid),
		   ft_invalid_done, ft_fatal,
		   cdx_ft_hw_pending() + cdx_ehash_quarantine_pending(),
		   ft_can_rearm(), ft_rearms);
	list_for_each_entry(entry, &ft_entries, list) {
		cdx_ft_hw_stats(entry->hw, &stats);
		seq_printf(seq, "flow cookie=%lx in=%s out=%s src=%pI4:%u dst=%pI4:%u mtu=%u packets=%llu bytes=%llu lastused=%u\n",
			   entry->cookie, entry->rule.in->name, entry->rule.out->name,
			   &entry->rule.src, ntohs(entry->rule.sport),
			   &entry->rule.dst, ntohs(entry->rule.dport), entry->rule.mtu,
			   stats.packets, stats.bytes, stats.lastused);
	}
	mutex_unlock(&cdx_info->ctrl.mutex);
	return 0;
}
DEFINE_PROC_SHOW_ATTRIBUTE(ft);

int cdx_flowtable_init(void)
{
	int rc;

	ft_proc = proc_create("cdx_flowtable", 0400, NULL, &ft_proc_ops);
	if (!ft_proc)
		return -ENOMEM;
	if (!cdx_flowtable_enabled())
		return 0;
	rc = register_netdevice_notifier(&ft_netdev_nb);
	if (rc)
		goto proc;
	rc = register_netevent_notifier(&ft_neigh_nb);
	if (rc)
		goto netdev;
	rc = register_fib_notifier(&init_net, &ft_fib_nb, NULL, NULL);
	if (rc)
		goto neigh;
	WRITE_ONCE(ft_ready, true);
	rc = flow_indr_dev_register(ft_bind, NULL);
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
	return rc;
}

void cdx_flowtable_exit(void)
{
	if (!ft_proc)
		return;
	proc_remove(ft_proc);
	ft_proc = NULL;
	if (!ft_ready)
		return;
	WRITE_ONCE(ft_stopping, true);
	unregister_fib_notifier(&init_net, &ft_fib_nb);
	unregister_netevent_notifier(&ft_neigh_nb);
	unregister_netdevice_notifier(&ft_netdev_nb);
	cancel_delayed_work_sync(&ft_work);
	flow_indr_dev_unregister(ft_bind, NULL, ft_release);
	WRITE_ONCE(ft_ready, false);
}

void cdx_flowtable_quiesced(void)
{
	cdx_ft_hw_quiesced();
}

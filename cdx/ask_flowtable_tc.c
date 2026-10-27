// SPDX-License-Identifier: GPL-2.0-or-later
/* What tc runs in software on each device, for the decisions that cannot ask.
 *
 * A direction the classifier forwards meets no qdisc and no tc filter: its
 * frames go from the port they arrive on straight to the queues of the port
 * they leave by. So a direction whose path runs tc in software stays in
 * software -- a shaper such as SQM's cake, a filter, a tcx or XDP program --
 * and only the hardware's own scheduler (`htb offload`) and the filters it
 * applies itself let one through (ft_dev_tc_soft()). The bridged unicast
 * learner asks the same of a pair's ports.
 *
 * Both decide inside the backend transaction, and tc cannot be asked there:
 * walking a filter block can run a classifier's destroy, which can drain a
 * port's egress and take the transaction (ft_dev_tc_soft_for()). Nor can a
 * routed offer afford RTNL to ask: a direction kept out is offered again about
 * once a second for as long as it carries traffic, which under SQM is every
 * upload, for its whole life.
 *
 * So this worker asks for them, about once a second while a binding or a
 * bridged pair could use the answer, under RTNL taken as the multicast workers
 * take it -- waiting for it, and holding nothing of this module's while it
 * walks -- and publishes the devices with something to say through RCU.
 * Admission reads it before RTNL for the devices an offer names, and after the
 * path walk for every device the walk crossed; the counter pass and an
 * installed direction's offers read it again for those. A device whose answer
 * changed is said so in the log. Where the answer tightened, a direction
 * installed through the device that it now keeps out is retired within the
 * second, and so is every bridged pair through the device. Where it loosened,
 * nothing is retired: a direction it now lets through is offered again only
 * where software would offer it anyway (ft_software_reoffers()) -- not while
 * an xfrm policy is configured, nor one arriving through a tunnel while its
 * sibling stays in hardware, which stays in software until its flow ends --
 * and a bridged pair refused lately is asked again by its next frame. The
 * multicast learners ask tc for themselves, outside the transaction, and are
 * woken to.
 *
 * Two costs are accepted. The retire scan walks every installed direction
 * with bottom halves off, under ft_watch_lock, but only after an answer
 * tightened, which takes an operator's tc change. And RTNL held for the walk,
 * about once a second, is RTNL an admission's trylock can lose meanwhile
 * (cdx_ft_admission_begin()): slightly more offers answered busy, as any
 * other RTNL holder makes them.
 */
#include "ask_flowtable_internal.h"

/* How often every device is asked again while anything could use it. */
#define FT_TC_INTERVAL	HZ

/* One device with something to say. Named by its pointer, which a lookup
 * compares and never follows, and by its index, which a rule keeps for a
 * device it names only that way. A device that went and one that took its
 * place meanwhile are told apart within the interval. */
struct ft_tc_dev {
	const struct net_device *dev;
	int ifindex;
	u8 soft;
};

struct ft_tc_sample {
	struct rcu_head rcu;
	unsigned int n;
	struct ft_tc_dev dev[];
};

/* Written by the worker alone, and by unload once the worker is disabled;
 * read under RCU from anywhere. NULL until the first sample after a binding
 * appears, and again once nothing could use one: nothing is known then. */
static struct ft_tc_sample __rcu *ft_tc_sample;
static void ft_tc_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_tc_work, ft_tc_workfn);

bool ft_tc_known(void)
{
	return rcu_access_pointer(ft_tc_sample) != NULL;
}

/* Whether any device has anything to say: the common case is none, and then
 * a direction's every device need not be looked up. */
bool ft_tc_any(void)
{
	const struct ft_tc_sample *s;
	bool any;

	rcu_read_lock();
	s = rcu_dereference(ft_tc_sample);
	any = s && s->n;
	rcu_read_unlock();
	return any;
}

static u8 ft_tc_find(const struct net_device *dev, int ifindex)
{
	const struct ft_tc_sample *s;
	unsigned int i;
	u8 soft = 0;

	rcu_read_lock();
	s = rcu_dereference(ft_tc_sample);
	for (i = 0; s && i < s->n; i++)
		if (dev ? s->dev[i].dev == dev : s->dev[i].ifindex == ifindex) {
			soft = s->dev[i].soft;
			break;
		}
	rcu_read_unlock();
	return soft;
}

/* FT_TC_* for a device, by pointer: one an offer names before RTNL is never
 * followed. Any context. */
u8 ft_tc_dev_bits(const struct net_device *dev)
{
	return dev ? ft_tc_find(dev, 0) : 0;
}

/* The same by index, for a device a rule names only that way: a tag's, the
 * one under a session or a tunnel. Zero names none. Any context. */
u8 ft_tc_index_bits(int ifindex)
{
	return ifindex ? ft_tc_find(NULL, ifindex) : 0;
}

/* The answer `old' had for a device, which the worker alone reads, holding
 * RTNL: the device it names is registered. */
static u8 ft_tc_was(const struct ft_tc_sample *old, const struct net_device *dev)
{
	unsigned int i;

	for (i = 0; old && i < old->n; i++)
		if (old->dev[i].dev == dev && old->dev[i].ifindex == dev->ifindex)
			return old->dev[i].soft;
	return 0;
}

/* What tc runs in software on one device. The routed answers on the way in can
 * only be narrower than the plain one, so they are asked only when it is yes.
 * Under RTNL, outside the transaction. */
static u8 ft_tc_ask(struct net_device *dev)
{
	u8 soft = 0;

	if (ft_dev_tc_soft(dev, false))
		soft |= FT_TC_TX;
	if (ft_dev_tc_soft(dev, true)) {
		soft |= FT_TC_RX;
		if (ft_dev_tc_soft_routed(dev, CDX_POLICE_L4))
			soft |= FT_TC_RX_L4;
		if (ft_dev_tc_soft_routed(dev, CDX_POLICE_ESP))
			soft |= FT_TC_RX_ESP;
		/* The ESP answer excepts less than the TCP and UDP one, so it is
		 * yes wherever that one is -- unless a filter changed, with no
		 * RTNL to stop it, between the two walks above. */
		if (soft & FT_TC_RX_L4)
			soft |= FT_TC_RX_ESP;
	}
	return soft;
}

/* One line per side whose answer changed, for the operator who changed it:
 * what it means for the flows through the device. Under RTNL. */
static void ft_tc_report(const struct net_device *dev, u8 was, u8 soft)
{
	const u8 rx = FT_TC_RX | FT_TC_RX_L4 | FT_TC_RX_ESP;

	if ((was ^ soft) & FT_TC_TX)
		pr_info("cdx flowtable: %s %s tc in software on what it sends; flows leaving through it %s\n",
			netdev_name(dev), soft & FT_TC_TX ? "runs" : "no longer runs",
			soft & FT_TC_TX ? "stay in software" : "may be offloaded again");
	if (!((was ^ soft) & rx))
		return;
	if (soft & FT_TC_RX_L4)
		pr_info("cdx flowtable: %s runs tc in software on what it receives; flows Linux receives through it stay in software\n",
			netdev_name(dev));
	else if (soft & FT_TC_RX_ESP)
		pr_info("cdx flowtable: %s runs tc in software on what it receives, police the hardware applies to routed TCP and UDP flows aside; those may be offloaded, other flows Linux receives through it stay in software, a decrypted or tunnelled one among them\n",
			netdev_name(dev));
	else if (soft & FT_TC_RX)
		pr_info("cdx flowtable: %s runs tc in software on what it receives, the rate limiter the hardware applies to routed TCP, UDP and ESP flows aside; those may be offloaded, flows arriving through a tunnel or of another protocol stay in software\n",
			netdev_name(dev));
	else
		pr_info("cdx flowtable: %s no longer runs tc in software on what it receives; flows Linux receives through it may be offloaded again\n",
			netdev_name(dev));
}

/* Every installed direction the sample just published keeps out, retired as
 * a device change retires what crosses the device: the handle is marked, so
 * Linux's own flow stops using it at once, and the retirement worker takes
 * the entry out. Software offers the direction again, and admission refuses
 * it for as long as the sample says so. */
static void ft_tc_retire(void)
{
	struct cdx_ft_entry *entry;

	spin_lock_bh(&ft_watch_lock);
	list_for_each_entry(entry, &ft_neigh_entries, neigh_list)
		if (ft_rule_tc_soft(&entry->rule))
			ft_handle_invalidate(entry->handle, &ft_tc_invalidations);
	spin_unlock_bh(&ft_watch_lock);
}

static bool ft_tc_wanted(void)
{
	return READ_ONCE(ft_bound) || ft_l2_paired();
}

static void ft_tc_workfn(struct work_struct *work)
{
	struct ft_tc_sample *old, *new;
	struct net_device *dev;
	unsigned int n = 0;
	bool tighter = false, looser = false, changed = false;
	u8 soft, was;

	old = rcu_dereference_protected(ft_tc_sample, true);
	if (!ft_tc_wanted()) {
		/* Nothing could use an answer, and nothing asks again until
		 * something could: forget this one rather than let it go stale
		 * under the next binding. Admission waits for a fresh one. */
		RCU_INIT_POINTER(ft_tc_sample, NULL);
		if (old)
			kfree_rcu(old, rcu);
		return;
	}
	rtnl_lock();
	for_each_netdev(&init_net, dev)
		n++;
	new = kzalloc(struct_size(new, dev, n), GFP_KERNEL);
	if (!new) {
		/* The last answer stands, and the next pass asks again. */
		rtnl_unlock();
		goto again;
	}
	for_each_netdev(&init_net, dev) {
		soft = ft_tc_ask(dev);
		was = ft_tc_was(old, dev);
		if (soft != was) {
			ft_tc_report(dev, was, soft);
			changed = true;
			tighter |= !!(soft & ~was);
			/* A bridged pair meets the plain answers alone. Every
			 * pair through a device whose answer tightened is
			 * retired and asked again, which asks every refusal
			 * again too. One that only loosened keeps out nothing a
			 * pair was admitted by, so none is retired -- each would
			 * leave the hardware for nothing -- and only the pairs
			 * refused lately, perhaps for what went, are asked
			 * again (below). */
			if (soft & ~was & (FT_TC_TX | FT_TC_RX))
				ft_l2_dev_changed(dev);
			else if (was & ~soft & (FT_TC_TX | FT_TC_RX))
				looser = true;
		}
		/* RTNL held since the count: the same devices, no more. */
		if (soft)
			new->dev[new->n++] = (struct ft_tc_dev){
				.dev = dev, .ifindex = dev->ifindex, .soft = soft,
			};
	}
	rcu_assign_pointer(ft_tc_sample, new);
	rtnl_unlock();
	if (old)
		kfree_rcu(old, rcu);
	/* Published first, so an offer made meanwhile is judged by it, and so is
	 * a pair asked again. */
	if (tighter)
		ft_tc_retire();
	if (looser)
		ft_l2_refusals_reset();
	if (changed) {
		ft_mc_kick_all();
		ft_mr_kick();
	}
again:
	if (ft_tc_wanted())
		queue_delayed_work(system_unbound_wq, &ft_tc_work, FT_TC_INTERVAL);
}

/* A binding appeared: a sample now, rather than at the next interval, and the
 * passes from there on. Any context. */
void ft_tc_kick(void)
{
	mod_delayed_work(system_unbound_wq, &ft_tc_work, 0);
}

/* Unload, before the learners' own exits: the worker kicks them. Disabled, so
 * a binding made from here on queues nothing. Readers after this find
 * nothing known, and refuse. */
void ft_tc_exit(void)
{
	struct ft_tc_sample *old;

	disable_delayed_work_sync(&ft_tc_work);
	old = rcu_dereference_protected(ft_tc_sample, true);
	RCU_INIT_POINTER(ft_tc_sample, NULL);
	if (old)
		kfree_rcu(old, rcu);
}

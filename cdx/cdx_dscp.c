// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2026 Mono
 *
 * Egress classification by DSCP, as a tc verb.
 *
 * The hardware has always had a second classifier beside the conntrack mark: a
 * per-port table of sixty-four frame queues, one per DSCP, consulted when a
 * frame names no class of its own. `dpa_tx()` reads it on the software path and
 * the microcode reads its own copy on the hardware one. Until now the only way
 * to fill either was CMD_QM_DSCP_Q_MAP_CFG -- an FCI command, on a control
 * plane that is sealed in flowtable mode and whose only client does not run
 * there.
 *
 *	tc qdisc  add dev eth3 clsact
 *	tc filter add dev eth3 egress protocol ip flower ip_dscp 46 \
 *	    action skbedit priority 1:10
 *
 * says the same thing in a vocabulary every distribution already ships, and it
 * says it against the tree `tc class add ... htb` built, so what class 1:10 *is*
 * has one definition rather than two.
 *
 * Two properties of the hardware shape the whole file.
 *
 * The map answers only for frames that named no class. That is the hardware's
 * own precedence, not a choice made here: `cdx_get_tx_dscp_fq_map()` clears the
 * ucode's enable bit for any entry whose mark carries a class, and `dpa_tx()`
 * reaches the DSCP branch only when `markval` is zero. So a DSCP filter is a
 * default for unmarked traffic, and a conntrack mark outranks it.
 *
 * And the microcode's copy of the table is a *singleton*. `dscp_fq_map_ff_g`
 * holds one port id -- "Now supporting only one interface", as the code that
 * enables it says -- so a second port asking for a DSCP map is refused rather
 * than silently taking the first one's table away.
 */

#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>
/* Before cdx.h, which defines TRUE and FALSE that the SDK headers below
 * define again. cdx_htb.c orders them the same way for the same reason. */
#include <dpaa_eth.h>
#include <dpaa_eth_common.h>
#include "cdx.h"
#include "portdefs.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "cdx_htb.h"
#include "cdx_dscp.h"

/* The six bits of the tos byte that are the DSCP, and how far up they sit. */
#define CDX_DSCP_MASK		0xfcu
#define CDX_DSCP_SHIFT		2
#define CDX_DSCP_COUNT		64

/* A class in the encoding the qdisc's published map is indexed by. The channel
 * is stored one higher so that zero is free to mean "no class", which is how a
 * codepoint nobody has claimed reads. */
#define CDX_DSCP_CLASS(channel, cq)	((u16)(((channel) + 1) << 4 | (cq)))

/* One filter: a DSCP, and the class an operator named for it. The class is
 * kept as the operator wrote it rather than as the (channel, class queue) it
 * resolves to, because the tree can be rebuilt underneath and the filter still
 * means the same class afterwards. */
struct cdx_dscp_filter {
	struct list_head	list;
	unsigned long		cookie;
	u32			classid;
	u8			dscp;
	/* Where the class currently sits, in the encoding the qdisc's own
	 * published map is indexed by: (channel + 1) << 4 | class queue, so
	 * zero is free to mean "that class does not exist just now". A filter
	 * outlives a `tc class del' and selects again if the class comes back,
	 * but while it is gone the codepoint must select nothing. */
	u16			klass;
};

struct cdx_dscp_port {
	struct list_head	filters;
	struct net_device	*dev;
	bool			enabled;	/* the map is on for this port */
	/* What the software Tx path reads, and the only part of this structure
	 * it may: one class per codepoint, republished whole after every
	 * change. ndo_select_queue cannot take the mutex above, and a walk of
	 * the list would be reading records while they are being freed. */
	u16			dscp_class[CDX_DSCP_COUNT];
};

static struct cdx_dscp_port cdx_dscp_ports[MAX_PHY_PORTS];
/* Serialises the filter lists and the enable, which cls_flower's unlocked
 * path can reach concurrently with each other and with an HTB command. */
static DEFINE_MUTEX(cdx_dscp_mutex);

/* Indexed the way gQMCtx is, as the qdisc's own port table is, so the two
 * always mean the same port whichever key the caller has. */
static struct cdx_dscp_port *cdx_dscp_entry(struct tQM_context_ctl *qm_ctx)
{
	if (!qm_ctx || qm_ctx < gQMCtx || qm_ctx >= gQMCtx + ARRAY_SIZE(gQMCtx))
		return NULL;
	return &cdx_dscp_ports[qm_ctx - gQMCtx];
}

static struct cdx_dscp_port *cdx_dscp_port_of(struct net_device *dev)
{
	struct dpa_priv_s *priv = netdev_priv(dev);
	struct cdx_dscp_port *port = cdx_dscp_entry(priv->qm_ctx);

	if (port && !port->dev) {
		INIT_LIST_HEAD(&port->filters);
		port->dev = dev;
	}
	return port;
}

static struct tQM_context_ctl *cdx_dscp_qm_ctx(struct net_device *dev)
{
	struct dpa_priv_s *priv = netdev_priv(dev);

	return priv->qm_ctx;
}

/* Runs under cdx_dscp_mutex. */
static struct cdx_dscp_filter *cdx_dscp_find(struct cdx_dscp_port *port,
					     unsigned long cookie)
{
	struct cdx_dscp_filter *f;

	list_for_each_entry(f, &port->filters, list)
		if (f->cookie == cookie)
			return f;
	return NULL;
}

/* Program one filter, or clear its DSCP when the class it names no longer
 * exists. A class that has gone is not an error here -- the operator deleted
 * it, and the honest answer is that this DSCP no longer selects anything --
 * but it must not be left pointing at whatever now holds those indices. */
static int cdx_dscp_program(struct net_device *dev, struct cdx_dscp_filter *f,
			    struct netlink_ext_ack *extack)
{
	struct tQM_context_ctl *qm_ctx = cdx_dscp_qm_ctx(dev);
	u8 channel, cq;
	int rc;

	rc = cdx_htb_class_queue(dev, f->classid, &channel, &cq, extack);
	if (rc) {
		f->klass = 0;
		ceetm_dscp_fq_unmap(qm_ctx, f->dscp);
		return rc;
	}
	/* ceetm_dscp_fq_map() numbers channels the way a conntrack mark does,
	 * where zero means "whichever channel this port owns"; the tree names
	 * them from zero, so a class that knows its channel says so one
	 * higher. */
	if (ceetm_dscp_fq_map(qm_ctx, f->dscp, channel + 1, cq) != CEETM_SUCCESS) {
		f->klass = 0;
		NL_SET_ERR_MSG_MOD(extack, "the DSCP map could not be programmed");
		return -EINVAL;
	}
	f->klass = CDX_DSCP_CLASS(channel, cq);
	return 0;
}

/* Republish what the software Tx path reads. Called under the mutex after
 * every change, and cheap enough to redo whole rather than patch in place. */
static void cdx_dscp_publish(struct cdx_dscp_port *port)
{
	struct cdx_dscp_filter *f;
	unsigned int dscp;

	for (dscp = 0; dscp < CDX_DSCP_COUNT; dscp++)
		WRITE_ONCE(port->dscp_class[dscp], 0);
	list_for_each_entry(f, &port->filters, list)
		if (f->klass)
			WRITE_ONCE(port->dscp_class[f->dscp], f->klass);
}

/* Turn the map on for this port, which is where the singleton bites: the
 * microcode's table carries one port id, so the second port to ask is told so
 * rather than quietly taking the first one's table. */
static int cdx_dscp_enable(struct cdx_dscp_port *port,
			   struct netlink_ext_ack *extack)
{
	struct tQM_context_ctl *qm_ctx = cdx_dscp_qm_ctx(port->dev);

	if (port->enabled)
		return 0;
	if (!qm_ctx) {
		NL_SET_ERR_MSG_MOD(extack, "CEETM is not configured on this interface");
		return -EOPNOTSUPP;
	}
	if (ceetm_enable_disable_dscp_fq_map(qm_ctx, 1) != CEETM_SUCCESS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "the hardware DSCP map serves one port at a time, and another port holds it");
		return -EBUSY;
	}
	port->enabled = true;
	return 0;
}

static void cdx_dscp_disable(struct cdx_dscp_port *port)
{
	struct tQM_context_ctl *qm_ctx = cdx_dscp_qm_ctx(port->dev);

	if (!port->enabled)
		return;
	if (qm_ctx)
		ceetm_enable_disable_dscp_fq_map(qm_ctx, 0);
	port->enabled = false;
}

/* Only the keys that make a DSCP. Anything else would select a subset of the
 * frames carrying that DSCP, and the table has one entry per DSCP and no way
 * to say "these and not those". */
static int cdx_dscp_parse(struct flow_cls_offload *f, u8 *dscp)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_control control;
	struct flow_match_ip ip;
	unsigned long long used;
	const unsigned long long allowed =
		BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
		BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
		BIT_ULL(FLOW_DISSECTOR_KEY_IP);

	used = rule->match.dissector->used_keys;
	if (used & ~allowed) {
		NL_SET_ERR_MSG_MOD(extack, "flower: only ip_dscp is supported on egress");
		return -EOPNOTSUPP;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		flow_rule_match_control(rule, &control);
		if (control.mask->flags) {
			NL_SET_ERR_MSG_MOD(extack, "flower: fragment matching is not supported");
			return -EOPNOTSUPP;
		}
	}
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		NL_SET_ERR_MSG_MOD(extack, "flower: an ip_dscp match is required");
		return -EOPNOTSUPP;
	}
	flow_rule_match_ip(rule, &ip);
	if (ip.mask->ttl) {
		NL_SET_ERR_MSG_MOD(extack, "flower: matching ttl is not supported");
		return -EOPNOTSUPP;
	}
	/* The table is indexed by a whole DSCP, so a partial one would claim
	 * more codepoints than the filter named. The two ECN bits are not ours
	 * to match on and tc keeps them in the same byte. */
	if (ip.mask->tos != CDX_DSCP_MASK) {
		NL_SET_ERR_MSG_MOD(extack,
				   "flower: the whole DSCP has to be matched, and the ECN bits cannot be");
		return -EOPNOTSUPP;
	}
	*dscp = (ip.key->tos & CDX_DSCP_MASK) >> CDX_DSCP_SHIFT;
	return 0;
}

/* The class an operator named, from the one action this accepts.
 *
 * `action skbedit priority' is what tc calls setting a frame's class, and it
 * arrives as FLOW_ACTION_PRIORITY carrying the handle verbatim. Nothing else
 * is accepted: an action that dropped or redirected would describe something
 * this table cannot do, and accepting it would silently classify instead.
 */
static int cdx_dscp_action(struct flow_cls_offload *f, u32 *classid)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	const struct flow_action_entry *act;

	if (!flow_offload_has_one_action(&rule->action)) {
		NL_SET_ERR_MSG_MOD(extack, "flower: exactly one action is supported");
		return -EOPNOTSUPP;
	}
	act = &rule->action.entries[0];
	if (act->id != FLOW_ACTION_PRIORITY) {
		NL_SET_ERR_MSG_MOD(extack, "flower: only skbedit priority is supported on egress");
		return -EOPNOTSUPP;
	}
	if (!act->priority) {
		NL_SET_ERR_MSG_MOD(extack, "flower: priority has to name a class");
		return -EOPNOTSUPP;
	}
	*classid = act->priority;
	return 0;
}

static int cdx_dscp_replace(struct net_device *dev, struct flow_cls_offload *f)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct cdx_dscp_port *port = cdx_dscp_port_of(dev);
	struct cdx_dscp_filter *filter, *existing;
	u32 classid;
	u8 dscp;
	int rc;

	if (!port)
		return -EOPNOTSUPP;
	rc = cdx_dscp_parse(f, &dscp);
	if (rc)
		return rc;
	rc = cdx_dscp_action(f, &classid);
	if (rc)
		return rc;

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return -ENOMEM;
	filter->cookie = f->cookie;
	filter->classid = classid;
	filter->dscp = dscp;

	mutex_lock(&cdx_dscp_mutex);
	/* Two filters on one DSCP would each be the whole of that codepoint's
	 * answer, and the second to be programmed would win with nothing
	 * saying so. tc keeps both, so this has to refuse the second. */
	list_for_each_entry(existing, &port->filters, list)
		if (existing->dscp == dscp && existing->cookie != f->cookie) {
			NL_SET_ERR_MSG_MOD(extack, "another filter already claims that DSCP");
			rc = -EEXIST;
			goto out;
		}
	rc = cdx_dscp_enable(port, extack);
	if (rc)
		goto out;
	rc = cdx_dscp_program(dev, filter, extack);
	if (rc)
		goto out_disable;
	/* tc replays a filter onto a block callback that binds after it, so the
	 * same cookie can arrive twice; the second time reprograms and keeps
	 * the record already there. */
	existing = cdx_dscp_find(port, f->cookie);
	if (existing) {
		existing->classid = classid;
		existing->dscp = dscp;
		kfree(filter);
	} else {
		list_add_tail(&filter->list, &port->filters);
	}
	cdx_dscp_publish(port);
	mutex_unlock(&cdx_dscp_mutex);
	return 0;

out_disable:
	if (list_empty(&port->filters))
		cdx_dscp_disable(port);
out:
	mutex_unlock(&cdx_dscp_mutex);
	kfree(filter);
	return rc;
}

static int cdx_dscp_destroy(struct net_device *dev, struct flow_cls_offload *f)
{
	struct cdx_dscp_port *port = cdx_dscp_port_of(dev);
	struct cdx_dscp_filter *filter;

	if (!port)
		return -EOPNOTSUPP;
	mutex_lock(&cdx_dscp_mutex);
	filter = cdx_dscp_find(port, f->cookie);
	if (filter) {
		ceetm_dscp_fq_unmap(cdx_dscp_qm_ctx(dev), filter->dscp);
		list_del(&filter->list);
		/* The last filter takes the map with it, so a port with no
		 * filters classifies exactly as it did before one existed --
		 * and hands the microcode's single table back to whichever
		 * port asks next. */
		if (list_empty(&port->filters))
			cdx_dscp_disable(port);
		cdx_dscp_publish(port);
	}
	mutex_unlock(&cdx_dscp_mutex);
	if (!filter)
		return -ENOENT;
	kfree(filter);
	return 0;
}

void cdx_dscp_tree_changed(struct net_device *dev)
{
	struct cdx_dscp_port *port = cdx_dscp_port_of(dev);
	struct cdx_dscp_filter *filter;

	if (!port)
		return;
	mutex_lock(&cdx_dscp_mutex);
	list_for_each_entry(filter, &port->filters, list)
		cdx_dscp_program(dev, filter, NULL);
	cdx_dscp_publish(port);
	mutex_unlock(&cdx_dscp_mutex);
}

void cdx_dscp_port_gone(struct tQM_context_ctl *qm_ctx)
{
	struct cdx_dscp_port *port = cdx_dscp_entry(qm_ctx);
	struct cdx_dscp_filter *filter, *next;

	if (!port)
		return;
	mutex_lock(&cdx_dscp_mutex);
	/* The caller is releasing the CEETM context, so the map goes with it
	 * and only the bookkeeping is ours. */
	list_for_each_entry_safe(filter, next, &port->filters, list) {
		list_del(&filter->list);
		kfree(filter);
	}
	port->enabled = false;
	cdx_dscp_publish(port);
	mutex_unlock(&cdx_dscp_mutex);
}

/* The class a DSCP names on this port, or zero for none.
 *
 * The software Tx path asks this for a frame that named no class of its own,
 * so both paths answer from the same filter: the hardware reads the
 * microcode's copy of the table, and a frame the CPU sends comes here.
 * Deriving the same answer twice would be two things to keep in step.
 *
 * Called from ndo_select_queue, which is not a place to take a mutex, so the
 * answer comes from a plain array republished on every change rather than from
 * a walk of the filter list. A reader racing a republish sees an old class or
 * a new one, never a freed record.
 */
u16 cdx_dscp_class(struct tQM_context_ctl *qm_ctx, u8 dscp)
{
	struct cdx_dscp_port *port = cdx_dscp_entry(qm_ctx);

	if (!port || dscp >= CDX_DSCP_COUNT)
		return 0;
	return READ_ONCE(port->dscp_class[dscp]);
}

static int cdx_dscp_flower(struct net_device *dev, struct flow_cls_offload *f)
{
	switch (f->command) {
	case FLOW_CLS_REPLACE:
		return cdx_dscp_replace(dev, f);
	case FLOW_CLS_DESTROY:
		return cdx_dscp_destroy(dev, f);
	default:
		/* The table keeps no counters of its own: what a class queue
		 * dequeued is a property of the class, and ethtool -S reports
		 * it per leaf slot. A filter statistic here would have to
		 * divide that by DSCP, which the hardware does not do. */
		return -EOPNOTSUPP;
	}
}

static int cdx_dscp_block_cb(enum tc_setup_type type, void *type_data,
			     void *cb_priv)
{
	struct net_device *dev = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return cdx_dscp_flower(dev, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(cdx_dscp_block_list);

/* Egress only. The ingress half of a clsact qdisc carries the police action
 * and belongs to cdx_police.c; a priority named there would describe a frame
 * on its way in, which has no class queue yet. */
int cdx_dscp_setup_block(struct net_device *dev, struct flow_block_offload *f)
{
	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS)
		return -EOPNOTSUPP;
	f->driver_block_list = &cdx_dscp_block_list;
	/* Not the helper's own ingress_only gate, which only knows how to
	 * insist on ingress; the binder type is checked above instead. */
	return flow_block_cb_setup_simple(f, &cdx_dscp_block_list,
					  cdx_dscp_block_cb, dev, dev, false);
}

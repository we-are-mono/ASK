// SPDX-License-Identifier: GPL-2.0-or-later
/* A hardware qdisc for the DPAA netdev: HTB offload driving CEETM.
 *
 * The scheduler CMM builds with twelve CMD_QM_* commands is the same scheduler
 * sch_htb asks for with tc_htb_qopt_offload, so this translates one into the
 * other. Nothing new is claimed here: ceetm_init_channels() already built every
 * channel, class queue and logical FQ at module load, and each setter in
 * cdx_ceetm_app.c is a thin function over a (channel, class queue) pair. What
 * this file owns is which pair a tc class means, and giving it back.
 *
 * The tree maps onto the hardware's own three levels:
 *
 *   qdisc root         the port, that is its LNI
 *   class under root   a CEETM channel; its rate and ceil are the channel's
 *                      committed and excess shapers
 *   class under that   a class queue on that channel; prio picks one of the
 *                      eight strict-priority queues, quantum instead puts it
 *                      in the weighted group
 *
 * A class under the root that has no children yet is both: it holds a channel
 * and occupies one class queue on it, because sch_htb gives every leaf a netdev
 * Tx queue and expects frames to be able to reach it. Deeper than that is
 * refused -- there is no fourth level in CEETM to put it on.
 *
 * Classification is not here and must not come here. An offloaded flow produces
 * no skb, reaches no qdisc and touches no Tx queue, so a tc filter could only
 * ever steer the software half; the conntrack mark is the one key both halves
 * can read. HTB supplies the tree, the mark picks the leaf.
 *
 * Everything below runs under RTNL in process context, and sch_htb wraps every
 * leaf add, delete and graft in dev_deactivate()/dev_activate(), so the netdev
 * can be quiesced the moment a callback returns. RTNL is also what serialises
 * this against itself. It does not serialise it against the FCI QM command
 * family, which is the other control plane over these objects; they are not
 * meant to be used together, and where it matters the hardware layer already
 * refuses -- ceetm_assign_chnl() will not hand out a channel the other side
 * holds, and TC_HTB_CREATE below will not take a port that is already
 * configured.
 */
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/netfilter/nf_conntrack.h>
#include <dpaa_eth.h>
#include <dpaa_eth_common.h>
#include "cdx.h"
#include "portdefs.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "cdx_flowtable.h"
#include "cdx_htb.h"

/* Leaf classes are handed netdev Tx queue indices out of the headroom patch 150
 * reserved above the direct queues, and sch_htb turns the index this file
 * returns straight into netdev_get_tx_queue() with no bounds check.
 *
 * real_num_tx_queues grows to cover them as classes come into service, because
 * netdev_cap_txqueue() rewrites anything at or above it to queue zero. The
 * driver keeps ordinary traffic off the range by folding its own queue choice
 * back below the base, so what the count decides is only whether a leaf can be
 * named -- not whether unclassified frames can wander onto one.
 */
#define CDX_HTB_QID_BASE	DPAA_ETH_TX_QUEUES
#define CDX_HTB_MAX_LEAVES	DPAA_ETH_CEETM_LEAF_QUEUES

/* No such queue, no such class. Both maps below are byte arrays, so one
 * sentinel serves for a whole memset. */
#define CDX_HTB_NONE		0xffu

/* Every value a decoded conntrack mark can take. */
#define CDX_HTB_CLASSES		256

/* Frames a leaf's class queue may hold before tail drop.
 *
 * The hardware layer's default is eight, which is what CMM configured and is
 * far too shallow for a queue that is deliberately being shaped: a class whose
 * arrival rate exceeds its share has nowhere to wait, so it loses frames rather
 * than queueing them. A hundred and twenty-eight is about a millisecond at a
 * gigabit and stays a bounded claim on the buffer pool at sixteen leaves per
 * port. HTB carries no queue-depth field, so this is a default rather than a
 * setting; increment 6 replaces tail drop with WRED and revisits it.
 */
#define CDX_HTB_CQ_DEPTH	128

struct cdx_htb_class {
	struct list_head list;
	/* Minors only. sch_htb truncates classid to u16 in the offload
	 * structure, and every command that names a parent names its minor, so
	 * the major never reaches this file except once, from TC_HTB_CREATE. */
	u16 classid;
	u16 parent;		/* 0 when the parent is the qdisc root */
	u16 qid;		/* netdev Tx queue, leaves only */
	u32 quantum;		/* weighted-group weight, 0 for strict priority */
	u8 channel;		/* CEETM channel index, both kinds */
	u8 cq;			/* class-queue index, leaves only */
	bool inner;		/* a channel with children, so not a queue */
};

struct cdx_htb_port {
	struct tQM_context_ctl *qm_ctx;
	struct list_head classes;
	u16 cq_used[CDX_CEETM_MAX_CHANNELS];
	u16 channels;		/* channels claimed for this port */
	u16 major;		/* the qdisc handle's major */
	u16 defcls;
	u16 leaves;		/* qids in use, dense from CDX_HTB_QID_BASE */
	bool live;
	/* What the Tx path reads, and the only part of this structure it may.
	 * Plain byte arrays rather than a walk of the class list, because both
	 * are read from ndo_select_queue and cpe_fp_tx without RTNL while that
	 * list is being mutated under it. A reader racing a rebuild sees an old
	 * byte or a new one, never a freed node. */
	u8 class_txq[CDX_HTB_CLASSES];		/* class -> leaf slot */
	u8 txq_channel[CDX_HTB_MAX_LEAVES];	/* leaf slot -> CEETM channel */
	u8 txq_cq[CDX_HTB_MAX_LEAVES];		/* leaf slot -> class queue */
};

/* Indexed the way gQMCtx is, so a netdev's stashed QoS context names its
 * entry. Ports without CEETM never reach here at all. */
static struct cdx_htb_port cdx_htb_ports[MAX_PHY_PORTS];

static struct cdx_htb_port *cdx_htb_entry(struct tQM_context_ctl *qm_ctx)
{
	if (!qm_ctx || qm_ctx < gQMCtx || qm_ctx >= gQMCtx + ARRAY_SIZE(gQMCtx))
		return NULL;
	return &cdx_htb_ports[qm_ctx - gQMCtx];
}

static struct cdx_htb_port *cdx_htb_port_of(struct net_device *dev)
{
	struct dpa_priv_s *priv = netdev_priv(dev);
	struct cdx_htb_port *port = cdx_htb_entry(priv->qm_ctx);

	if (port)
		port->qm_ctx = priv->qm_ctx;
	return port;
}

static struct cdx_htb_class *cdx_htb_find(struct cdx_htb_port *port, u16 classid)
{
	struct cdx_htb_class *cl;

	list_for_each_entry(cl, &port->classes, list)
		if (cl->classid == classid)
			return cl;
	return NULL;
}

static struct cdx_htb_class *cdx_htb_find_qid(struct cdx_htb_port *port, u16 qid)
{
	struct cdx_htb_class *cl;

	list_for_each_entry(cl, &port->classes, list)
		if (!cl->inner && cl->qid == qid)
			return cl;
	return NULL;
}

static bool cdx_htb_channel_owned(struct cdx_htb_port *port, u8 channel)
{
	struct cdx_htb_class *cl;

	list_for_each_entry(cl, &port->classes, list)
		if (!cl->parent && cl->channel == channel)
			return true;
	return false;
}

/* Republish what the Tx path reads. Called after every change to the tree,
 * under RTNL, and cheap enough to redo whole rather than patch in place.
 *
 * A class names its channel the way a conntrack mark does, where a channel
 * nibble of zero means "whichever channel this port owns" rather than channel
 * zero, and ceetm_get_egressfq() resolves that to the highest one it has. The
 * same answer has to come out here, or a flow the hardware put on a class
 * would take a different one in software. */
static void cdx_htb_publish(struct cdx_htb_port *port)
{
	struct cdx_htb_class *cl;
	u8 top = CDX_HTB_NONE;
	unsigned int ii;

	memset(port->class_txq, CDX_HTB_NONE, sizeof(port->class_txq));
	memset(port->txq_channel, CDX_HTB_NONE, sizeof(port->txq_channel));
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++)
		if (port->channels & BIT(ii))
			top = ii;
	list_for_each_entry(cl, &port->classes, list) {
		u8 slot;

		if (cl->inner)
			continue;
		slot = (u8)(cl->qid - CDX_HTB_QID_BASE);
		if (WARN_ON_ONCE(slot >= CDX_HTB_MAX_LEAVES))
			continue;
		port->txq_cq[slot] = cl->cq;
		WRITE_ONCE(port->txq_channel[slot], cl->channel);
		WRITE_ONCE(port->class_txq[((cl->channel + 1) << 4) | cl->cq], slot);
		if (cl->channel == top)
			WRITE_ONCE(port->class_txq[cl->cq], slot);
	}
}

/* Narrow or widen the usable Tx queues to cover the leaf classes in service.
 * Ordinary traffic is folded below this range by the driver, so what it really
 * decides is whether a leaf's queue can be named at all: sch_htb grafts a qdisc
 * on it either way, but netdev_cap_txqueue() rewrites anything at or above the
 * count to queue zero. */
static int cdx_htb_resize(struct cdx_htb_port *port, u16 leaves)
{
	if (!port->qm_ctx->net_dev)
		return 0;
	return netif_set_real_num_tx_queues(port->qm_ctx->net_dev,
					    CDX_HTB_QID_BASE + leaves);
}

/* A channel for a class directly under the qdisc root.
 *
 * Channels are returned to the global pool only when the qdisc goes away. One
 * this port has already claimed but no class holds any more is handed out
 * again instead of being detached and rebound: detaching a live channel means
 * draining it while frames are still being classified onto it, and a claim that
 * lasts as long as the qdisc costs nothing but a bit in chnl_map.
 */
static int cdx_htb_channel_get(struct cdx_htb_port *port, u8 *channel,
			       struct netlink_ext_ack *extack)
{
	uint32_t claimed;
	u8 ii;

	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++)
		if ((port->channels & BIT(ii)) && !cdx_htb_channel_owned(port, ii)) {
			*channel = ii;
			return 0;
		}
	if (ceetm_claim_channel(port->qm_ctx, &claimed)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "no CEETM channel left; the SoC has eight and every port shares them");
		return -ENOSPC;
	}
	port->channels |= BIT(claimed);
	*channel = claimed;
	return 0;
}

/* Which class queue a leaf's scheduling parameters name.
 *
 * The eight strict-priority queues are one per priority, so prio names a queue
 * directly and two leaves cannot share one; asking for a priority that is taken
 * is an error rather than a silent demotion. A leaf that gives a quantum is
 * asking to share bandwidth rather than to pre-empt, which is the weighted
 * group, and there are eight of those because cdx claims group A only.
 *
 * GET_CEETM_PRIORITY() inverts the strict range: configuration index 0 is CEETM
 * queue 7, the lowest priority. Indexing from the top of the range is what
 * makes prio 0 the queue that actually wins.
 */
static int cdx_htb_cq_get(struct cdx_htb_port *port, u8 channel, u8 prio,
			  u32 quantum, u8 *cq, struct netlink_ext_ack *extack)
{
	u8 ii;

	if (quantum) {
		for (ii = NUM_PQS; ii < MAX_SCHEDULER_QUEUES; ii++)
			if (!(port->cq_used[channel] & BIT(ii))) {
				*cq = ii;
				return 0;
			}
		NL_SET_ERR_MSG_MOD(extack,
				   "no weighted class queue left on this channel; there are eight");
		return -ENOSPC;
	}
	if (prio >= NUM_PQS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "prio must be 0 to 7, one per strict-priority class queue");
		return -EINVAL;
	}
	ii = NUM_PQS - 1 - prio;
	if (port->cq_used[channel] & BIT(ii)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "another class already holds this priority on this channel; give a quantum to share instead");
		return -EEXIST;
	}
	*cq = ii;
	return 0;
}

/* Program a leaf's class queue, and remember that it is taken. */
static int cdx_htb_cq_configure(struct cdx_htb_port *port, u8 channel, u8 cq,
				u32 quantum, struct netlink_ext_ack *extack)
{
	int rc = ceetm_set_class_queue(channel, cq, quantum, CDX_HTB_CQ_DEPTH);

	if (rc) {
		NL_SET_ERR_MSG_MOD(extack,
				   "CEETM rejected the class queue; a quantum is a weight of 1 to 255, not a byte count");
		return rc;
	}
	port->cq_used[channel] |= BIT(cq);
	return 0;
}

static void cdx_htb_cq_release(struct cdx_htb_port *port, u8 channel, u8 cq)
{
	if (!(port->cq_used[channel] & BIT(cq)))
		return;
	port->cq_used[channel] &= (u16)~BIT(cq);
	if (ceetm_reset_class_queue(channel, cq))
		pr_warn("cdx: CEETM channel %u queue %u did not return to its defaults\n",
			channel, cq);
}

/* Put a class queue back the way it was, after a change that could not be
 * completed. Nothing else can be done about a failure here: the caller is
 * already unwinding. */
static void cdx_htb_cq_restore(struct cdx_htb_port *port, struct cdx_htb_class *cl)
{
	if (cdx_htb_cq_configure(port, cl->channel, cl->cq, cl->quantum, NULL))
		pr_warn("cdx: CEETM channel %u queue %u lost its configuration\n",
			cl->channel, cl->cq);
}

/* tc rates are bytes per second; CEETM shapers are programmed in bits.
 *
 * A channel's two token buckets are additive, not nested: a class queue
 * eligible for both transmits against the committed rate and then again
 * against the excess one, so the channel's output approaches their sum. HTB
 * means ceil as a total ceiling, which makes the excess rate ceil *minus* the
 * committed rate rather than ceil itself. Measured on the rig: a class given
 * rate 200mbit ceil 200mbit ran at 376 Mbit/s when both buckets were
 * programmed at 200, which is 400 Mbit of frame rate less TCP's header share.
 *
 * ceil equal to rate therefore leaves nothing to borrow, which is what an HTB
 * class with no ceil of its own is asking for.
 */
static int cdx_htb_shape(u8 channel, u64 rate, u64 ceil,
			 struct netlink_ext_ack *extack)
{
	u64 excess = ceil > rate ? ceil - rate : 0;

	if (ceetm_set_channel_rates(channel, rate * 8, excess * 8)) {
		NL_SET_ERR_MSG_MOD(extack, "CEETM cannot shape at the requested rate");
		return -EINVAL;
	}
	return 0;
}

static void cdx_htb_class_free(struct cdx_htb_port *port, struct cdx_htb_class *cl)
{
	list_del(&cl->list);
	kfree(cl);
}

/* Keep the qid range dense by moving the last leaf into the hole, and report
 * which class moved so sch_htb can migrate that class's qdisc with it. Skipping
 * this fragments a budget of sixteen slots per port. Only the netdev queue
 * index moves: a leaf's channel and class queue are what its frames actually
 * reach, and neither changes. Returns the moved class's id, or zero. */
static u16 cdx_htb_qid_free(struct cdx_htb_port *port, u16 qid)
{
	struct cdx_htb_class *last;

	port->leaves--;
	if (qid == CDX_HTB_QID_BASE + port->leaves)
		return 0;
	last = cdx_htb_find_qid(port, CDX_HTB_QID_BASE + port->leaves);
	if (WARN_ON_ONCE(!last))
		return 0;
	last->qid = qid;
	return last->classid;
}

static int cdx_htb_create(struct cdx_htb_port *port, struct tc_htb_qopt_offload *opt)
{
	if (port->live) {
		NL_SET_ERR_MSG_MOD(opt->extack, "a hardware qdisc already owns this port");
		return -EBUSY;
	}
	/* CMM configures the same LNI, channels and class queues through the
	 * FCI QM commands. Two control planes over one scheduler would each
	 * undo the other, so whichever configured the port first keeps it. */
	if (port->qm_ctx->qos_enabled || port->qm_ctx->chnl_map) {
		NL_SET_ERR_MSG_MOD(opt->extack,
				   "CEETM on this port is already configured by another control plane");
		return -EBUSY;
	}
	INIT_LIST_HEAD(&port->classes);
	memset(port->cq_used, 0, sizeof(port->cq_used));
	port->channels = 0;
	port->leaves = 0;
	port->major = opt->parent_classid;
	/* Advisory until increment 4: unclassified software traffic does not
	 * reach a leaf's Tx queue yet, it takes the class queue the hardware
	 * layer resolves a zero mark to. */
	port->defcls = opt->classid;
	port->live = true;
	cdx_htb_publish(port);
	return 0;
}

/* Teardown, for a command whose return value sch_htb discards.
 *
 * Every claim has to come back whatever the hardware says, so this reports
 * trouble and keeps going rather than stopping at the first failure. The
 * channels return to the global pool here; a channel whose drain failed stays
 * marked as such inside the hardware layer, which is what stops it being handed
 * out again.
 */
static void cdx_htb_destroy(struct cdx_htb_port *port)
{
	struct cdx_htb_class *cl, *next;

	if (ceetm_stop_qos(port->qm_ctx))
		pr_warn("cdx: CEETM on %s did not stop cleanly\n",
			port->qm_ctx->iface_info ?
			(const char *)port->qm_ctx->iface_info->name : "?");
	list_for_each_entry_safe(cl, next, &port->classes, list)
		cdx_htb_class_free(port, cl);
	memset(port->cq_used, 0, sizeof(port->cq_used));
	port->channels = 0;
	port->leaves = 0;
	port->live = false;
	/* Stop the Tx path naming a leaf before the queues stop existing. */
	cdx_htb_publish(port);
	if (cdx_htb_resize(port, 0))
		pr_warn("cdx: %s kept Tx queues no class is using\n",
			port->qm_ctx->net_dev ? port->qm_ctx->net_dev->name : "?");
}

static int cdx_htb_leaf_alloc(struct cdx_htb_port *port,
			      struct tc_htb_qopt_offload *opt)
{
	bool root = opt->parent_classid == TC_HTB_CLASSID_ROOT;
	struct cdx_htb_class *parent, *cl;
	u8 channel, cq;
	int rc;

	if (port->leaves == CDX_HTB_MAX_LEAVES) {
		NL_SET_ERR_MSG_MOD(opt->extack,
				   "no Tx queue left for another leaf class on this port");
		return -ENOSPC;
	}
	if (cdx_htb_find(port, opt->classid))
		return -EEXIST;
	if (root) {
		rc = cdx_htb_channel_get(port, &channel, opt->extack);
		if (rc)
			return rc;
	} else {
		parent = cdx_htb_find(port, (u16)opt->parent_classid);
		if (!parent || !parent->inner)
			return -ENOENT;
		channel = parent->channel;
	}
	rc = cdx_htb_cq_get(port, channel, opt->prio, opt->quantum, &cq, opt->extack);
	if (rc)
		return rc;
	cl = kzalloc(sizeof(*cl), GFP_KERNEL);
	if (!cl)
		return -ENOMEM;
	/* Shape before the port starts scheduling, so the first frame out of a
	 * new channel already meets the rate it was given. */
	if (root) {
		rc = cdx_htb_shape(channel, opt->rate, opt->ceil, opt->extack);
		if (rc)
			goto err_class;
	}
	rc = cdx_htb_cq_configure(port, channel, cq, opt->quantum, opt->extack);
	if (rc)
		goto err_class;
	/* The switch that makes any of this real: until CEETM is enabled the
	 * port still sends through its plain forwarding FQs and the whole tree
	 * is inert. It needs a channel bound first, which is why it happens
	 * here and not at TC_HTB_CREATE. Already-enabled is a no-op, so this
	 * also recovers a port whose first attempt failed. */
	if (ceetm_enable_or_disable_qos(port->qm_ctx, 1)) {
		NL_SET_ERR_MSG_MOD(opt->extack, "CEETM would not start on this port");
		rc = -EIO;
		goto err_cq;
	}
	/* Last thing that can fail: growing the usable range is what lets the
	 * stack put a frame on this leaf's queue at all. */
	rc = cdx_htb_resize(port, port->leaves + 1);
	if (rc) {
		NL_SET_ERR_MSG_MOD(opt->extack, "cannot put another Tx queue into service");
		goto err_cq;
	}
	cl->classid = opt->classid;
	cl->parent = root ? 0 : (u16)opt->parent_classid;
	cl->channel = channel;
	cl->cq = cq;
	cl->quantum = opt->quantum;
	cl->qid = CDX_HTB_QID_BASE + port->leaves++;
	list_add_tail(&cl->list, &port->classes);
	cdx_htb_publish(port);
	opt->qid = cl->qid;
	return 0;

err_cq:
	cdx_htb_cq_release(port, channel, cq);
err_class:
	kfree(cl);
	/* A channel claimed for a class that did not come into being stays
	 * bound to this port and unowned, so the next class reuses it. Nothing
	 * reaches it meanwhile: no class queue on it is configured, and a mark
	 * cannot name a channel the port is not scheduling on. */
	return rc;
}

/* The parent was a leaf holding a class queue on its own channel; it becomes
 * that channel and the new child takes over both its Tx queue and its place on
 * the channel. Only a class directly under the qdisc root can do this: a class
 * queue has nothing below it to turn into. */
static int cdx_htb_leaf_to_inner(struct cdx_htb_port *port,
				 struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *parent, *cl;
	u8 cq;
	int rc;

	parent = cdx_htb_find(port, (u16)opt->parent_classid);
	if (!parent || parent->inner)
		return -ENOENT;
	if (parent->parent) {
		NL_SET_ERR_MSG_MOD(opt->extack,
				   "CEETM is two levels deep: classes under the qdisc are channels, their children are class queues");
		return -EOPNOTSUPP;
	}
	if (cdx_htb_find(port, opt->classid))
		return -EEXIST;
	cl = kzalloc(sizeof(*cl), GFP_KERNEL);
	if (!cl)
		return -ENOMEM;
	/* Free the parent's queue before choosing the child's, so a child that
	 * asks for the priority its parent held gets it. */
	cdx_htb_cq_release(port, parent->channel, parent->cq);
	rc = cdx_htb_cq_get(port, parent->channel, opt->prio, opt->quantum, &cq,
			    opt->extack);
	if (!rc)
		rc = cdx_htb_cq_configure(port, parent->channel, cq, opt->quantum,
					  opt->extack);
	if (rc) {
		cdx_htb_cq_restore(port, parent);
		kfree(cl);
		return rc;
	}
	cl->classid = opt->classid;
	cl->parent = parent->classid;
	cl->channel = parent->channel;
	cl->cq = cq;
	cl->quantum = opt->quantum;
	cl->qid = parent->qid;
	list_add_tail(&cl->list, &port->classes);
	parent->inner = true;
	parent->qid = 0;
	parent->cq = 0;
	parent->quantum = 0;
	cdx_htb_publish(port);
	return 0;
}

/* TC_HTB_LEAF_DEL, with siblings left behind. The class queue and the Tx queue
 * both come back; the channel does not, because the qdisc may still hand it to
 * the next class under the root. */
static int cdx_htb_leaf_del(struct cdx_htb_port *port,
			    struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);
	u16 moved;

	if (!cl || cl->inner)
		return -ENOENT;
	cdx_htb_cq_release(port, cl->channel, cl->cq);
	/* A class under the root takes its channel out of service with it.
	 * Leaving the rate it asked for programmed would shape whatever class
	 * is given the channel next, before that class has said anything. */
	if (!cl->parent && ceetm_set_channel_rates(cl->channel, 0, 0))
		pr_warn("cdx: CEETM channel %u kept a rate it no longer has a class for\n",
			cl->channel);
	moved = cdx_htb_qid_free(port, cl->qid);
	cdx_htb_class_free(port, cl);
	cdx_htb_publish(port);
	if (moved)
		opt->classid = moved;
	return 0;
}

/* TC_HTB_LEAF_DEL_LAST and its _FORCE twin, whose return value sch_htb
 * discards. The parent becomes a leaf again and inherits both the Tx queue and
 * the class queue the child was using, which is what "preserving qid" means for
 * hardware that has nowhere else to put the parent's frames. */
static int cdx_htb_leaf_del_last(struct cdx_htb_port *port,
				 struct tc_htb_qopt_offload *opt, bool force)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);
	struct cdx_htb_class *parent;

	if (!cl || cl->inner)
		return force ? 0 : -ENOENT;
	parent = cdx_htb_find(port, cl->parent);
	if (!parent) {
		/* Nothing to hand the queues back to. Return them rather than
		 * leak them; a forced teardown still has to balance. */
		cdx_htb_cq_release(port, cl->channel, cl->cq);
		cdx_htb_qid_free(port, cl->qid);
		cdx_htb_class_free(port, cl);
		cdx_htb_publish(port);
		return force ? 0 : -ENOENT;
	}
	parent->inner = false;
	parent->qid = cl->qid;
	parent->cq = cl->cq;
	parent->quantum = cl->quantum;
	cdx_htb_class_free(port, cl);
	cdx_htb_publish(port);
	return 0;
}

static int cdx_htb_node_modify(struct cdx_htb_port *port,
			       struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);
	u8 cq;
	int rc;

	if (!cl)
		return -ENOENT;
	/* A class under the root is a channel, and a channel is the only thing
	 * here with a shaper. A class queue's rate and ceil have no hardware
	 * behind them, so what a leaf can change is where it sits among its
	 * siblings. */
	if (!cl->parent)
		return cdx_htb_shape(cl->channel, opt->rate, opt->ceil, opt->extack);
	cdx_htb_cq_release(port, cl->channel, cl->cq);
	rc = cdx_htb_cq_get(port, cl->channel, opt->prio, opt->quantum, &cq, opt->extack);
	if (!rc)
		rc = cdx_htb_cq_configure(port, cl->channel, cq, opt->quantum, opt->extack);
	if (rc) {
		cdx_htb_cq_restore(port, cl);
		return rc;
	}
	cl->cq = cq;
	cl->quantum = opt->quantum;
	cdx_htb_publish(port);
	return 0;
}

static int cdx_htb_query_queue(struct cdx_htb_port *port,
			       struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);

	if (!cl || cl->inner)
		return -ENOENT;
	opt->qid = cl->qid;
	return 0;
}

static int cdx_htb_setup_tc(struct net_device *dev, struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_port *port = cdx_htb_port_of(dev);

	ASSERT_RTNL();
	if (!port) {
		NL_SET_ERR_MSG_MOD(opt->extack, "CEETM is not configured on this interface");
		return -EOPNOTSUPP;
	}
	if (opt->command != TC_HTB_CREATE && !port->live)
		return -ENOENT;

	switch (opt->command) {
	case TC_HTB_CREATE:
		return cdx_htb_create(port, opt);
	case TC_HTB_DESTROY:
		cdx_htb_destroy(port);
		return 0;
	case TC_HTB_LEAF_ALLOC_QUEUE:
		return cdx_htb_leaf_alloc(port, opt);
	case TC_HTB_LEAF_TO_INNER:
		return cdx_htb_leaf_to_inner(port, opt);
	case TC_HTB_LEAF_DEL:
		return cdx_htb_leaf_del(port, opt);
	case TC_HTB_LEAF_DEL_LAST:
		return cdx_htb_leaf_del_last(port, opt, false);
	case TC_HTB_LEAF_DEL_LAST_FORCE:
		return cdx_htb_leaf_del_last(port, opt, true);
	case TC_HTB_NODE_MODIFY:
		return cdx_htb_node_modify(port, opt);
	case TC_HTB_LEAF_QUERY_QUEUE:
		return cdx_htb_query_queue(port, opt);
	}
	return -EOPNOTSUPP;
}

void cdx_htb_port_gone(struct tQM_context_ctl *qm_ctx)
{
	struct cdx_htb_port *port = cdx_htb_entry(qm_ctx);
	struct cdx_htb_class *cl, *next;

	if (!port || !port->live)
		return;
	/* The caller is releasing the whole CEETM context, so the hardware is
	 * its problem; only the bookkeeping is ours. A qdisc still attached to
	 * a netdev being unregistered is destroyed by dev_shutdown() before the
	 * netdev goes, so this normally finds nothing. */
	list_for_each_entry_safe(cl, next, &port->classes, list)
		cdx_htb_class_free(port, cl);
	memset(port, 0, sizeof(*port));
	INIT_LIST_HEAD(&port->classes);
}

/* The data path. Both callbacks run per frame, without RTNL, against the byte
 * maps cdx_htb_publish() keeps.
 *
 * The class comes from the adapter's own classifier, registered below, so the
 * frame lands on the class the hardware rule would have given the same flow. No
 * classifier registered means nothing here has an opinion: the frame keeps the
 * queue the stack chose, and cpe_fp_tx() resolves it exactly as it did before
 * any of this existed. That is what CMM's ports do, and why enabling a qdisc
 * there builds a tree without changing how a frame reaches it.
 */
static cdx_ft_qos_class_fn cdx_ft_qos_class_func;

int cdx_register_ft_qos_class(cdx_ft_qos_class_fn fn)
{
	if (!fn)
		return -EINVAL;
	if (cmpxchg(&cdx_ft_qos_class_func, NULL, fn))
		return -EBUSY;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_register_ft_qos_class, ASK_CDX_FLOWTABLE);

void cdx_unregister_ft_qos_class(void)
{
	WRITE_ONCE(cdx_ft_qos_class_func, NULL);
	/* Finish the Tx readers that may be inside it before its module goes. */
	synchronize_net();
}
EXPORT_SYMBOL_NS_GPL(cdx_unregister_ft_qos_class, ASK_CDX_FLOWTABLE);

static u16 cdx_htb_select_queue(struct net_device *dev, struct sk_buff *skb)
{
	cdx_ft_qos_class_fn decode = READ_ONCE(cdx_ft_qos_class_func);
	struct dpa_priv_s *priv = netdev_priv(dev);
	struct cdx_htb_port *port;
	enum ip_conntrack_info cinfo;
	struct nf_conn *ct;
	u8 slot;

	if (!decode)
		return DPA_SELECT_QUEUE_NONE;
	port = cdx_htb_entry(priv->qm_ctx);
	if (!port)
		return DPA_SELECT_QUEUE_NONE;
	ct = nf_ct_get(skb, &cinfo);
	if (!ct)
		return DPA_SELECT_QUEUE_NONE;
	/* One read of the mark, as the adapter takes one when it admits a flow:
	 * a class chosen from a value that changed underneath would put this
	 * frame somewhere the flow's own rule does not name. */
	slot = READ_ONCE(port->class_txq[decode(READ_ONCE(ct->mark))]);
	if (slot == CDX_HTB_NONE)
		return DPA_SELECT_QUEUE_NONE;
	return CDX_HTB_QID_BASE + slot;
}

static struct qman_fq *cdx_htb_txq_fq(void *qm_ctx, u16 txq)
{
	struct cdx_htb_port *port = cdx_htb_entry(qm_ctx);
	u8 channel;
	u16 slot;

	if (!port || txq < CDX_HTB_QID_BASE)
		return NULL;
	slot = txq - CDX_HTB_QID_BASE;
	if (slot >= CDX_HTB_MAX_LEAVES)
		return NULL;
	channel = READ_ONCE(port->txq_channel[slot]);
	if (channel == CDX_HTB_NONE)
		return NULL;
	return ceetm_class_fq(qm_ctx, channel, READ_ONCE(port->txq_cq[slot]));
}

static const struct dpa_qdisc_ops cdx_htb_qdisc_ops = {
	.select_queue = cdx_htb_select_queue,
	.txq_fq = cdx_htb_txq_fq,
};

/* The flowtable adapter's half of the ndo.
 *
 * Only one handler can be registered with the driver, and this one is it,
 * because cdx is loaded whichever ownership mode the box booted in while the
 * adapter is loaded in one of them. TC_SETUP_FT therefore arrives here and is
 * passed on. Netfilter chooses between this route and the adapter's indirect
 * block registration purely on whether the netdev has an ndo_setup_tc at all,
 * so a bind that arrives with nothing registered has to be refused rather than
 * quietly served by neither.
 */
static cdx_ft_setup_tc_handler cdx_ft_handler;

int cdx_register_ft_setup_tc(cdx_ft_setup_tc_handler handler)
{
	if (!handler)
		return -EINVAL;
	if (cmpxchg(&cdx_ft_handler, NULL, handler))
		return -EBUSY;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_register_ft_setup_tc, ASK_CDX_FLOWTABLE);

void cdx_unregister_ft_setup_tc(void)
{
	WRITE_ONCE(cdx_ft_handler, NULL);
}
EXPORT_SYMBOL_NS_GPL(cdx_unregister_ft_setup_tc, ASK_CDX_FLOWTABLE);

static int cdx_setup_tc(struct net_device *dev, enum tc_setup_type type,
			void *type_data)
{
	/* Read the handler once: an unregister can NULL it concurrently, and a
	 * half-torn read would call through freed module text. */
	cdx_ft_setup_tc_handler handler;

	switch (type) {
	case TC_SETUP_QDISC_HTB:
		return cdx_htb_setup_tc(dev, type_data);
	case TC_SETUP_ROOT_QDISC:
		/* A notification that the netdev's root qdisc changed, not a
		 * request. This driver's scheduler state comes from the HTB
		 * commands themselves, so there is nothing to do -- but
		 * answering -EOPNOTSUPP makes qdisc_offload_graft_helper()
		 * report "Offloading graft operation failed" on every
		 * successful `tc qdisc add ... htb offload`, because by then
		 * the qdisc is already flagged as offloaded. */
		return 0;
	case TC_SETUP_FT:
		handler = READ_ONCE(cdx_ft_handler);
		return handler ? handler(dev, type, type_data) : -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}
}

int cdx_htb_init(void)
{
	unsigned int ii;
	int rc;

	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++) {
		INIT_LIST_HEAD(&cdx_htb_ports[ii].classes);
		cdx_htb_publish(&cdx_htb_ports[ii]);
	}
	rc = dpa_register_qdisc_ops(&cdx_htb_qdisc_ops);
	if (rc)
		return rc;
	rc = dpa_register_setup_tc(cdx_setup_tc);
	if (rc)
		dpa_unregister_qdisc_ops();
	return rc;
}

void cdx_htb_exit(void)
{
	unsigned int ii;

	/* Stop new commands before releasing anything: the driver holds a
	 * pointer into this module's text rather than a symbol reference, so a
	 * tc command can arrive until this returns. The data path is retired
	 * the same way, and waits out the frames already inside it. */
	dpa_unregister_setup_tc();
	dpa_unregister_qdisc_ops();
	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++)
		cdx_htb_port_gone(&gQMCtx[ii]);
}

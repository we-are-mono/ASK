/* Drive the sch_htb offload command sequence against the production HTB code.
 *
 * The commands come in the order and with the field overloading sch_htb really
 * uses, because that is where this interface is sharp: classid is a minor,
 * LEAF_TO_INNER names child and parent the opposite way round to the intuitive
 * reading, and TC_HTB_DESTROY and TC_HTB_LEAF_DEL_LAST_FORCE have their return
 * value discarded, so teardown has to balance whatever the hardware said.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAX_PHY_PORTS			40
#define CDX_CEETM_MAX_CHANNELS		8
#define NUM_PQS				8
#define NUM_WBFQS			8
#define MAX_SCHEDULER_QUEUES		(NUM_PQS + NUM_WBFQS)
#define DPAA_ETH_TX_QUEUES		16
#define DPAA_ETH_CEETM_LEAF_QUEUES	16
#define GFP_KERNEL			0

#define BIT(n)			(1U << (n))
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define READ_ONCE(x)		(x)
#define WRITE_ONCE(x, v)	((x) = (v))
#define cmpxchg(p, old, new)	({					\
		__typeof__(*(p)) __o = *(p);				\
		if (__o == (old))					\
			*(p) = (new);					\
		__o;							\
	})
#define pr_warn(...)		((void)0)
#define WARN_ON_ONCE(c)		({ int __c = !!(c); assert(!__c); __c; })

static bool rtnl = true;
#define ASSERT_RTNL()		assert(rtnl)

static const char *last_extack;
#define NL_SET_ERR_MSG_MOD(extack, msg)	do { (void)(extack); last_extack = (msg); } while (0)

struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(h)	((h)->next = (h)->prev = (h))
static void list_add_tail(struct list_head *n, struct list_head *h)
{
	n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n;
}
static void list_del(struct list_head *n)
{
	n->prev->next = n->next; n->next->prev = n->prev;
	n->next = n->prev = NULL;
}
static bool list_empty(const struct list_head *h) { return h->next == h; }
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define list_entry(p, type, member)	container_of(p, type, member)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, __typeof__(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, __typeof__(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, __typeof__(*pos), member),	\
	     n = list_entry(pos->member.next, __typeof__(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, __typeof__(*n), member))

static unsigned allocations;
static void *kzalloc(size_t size, int flags)
{
	(void)flags;
	allocations++;
	return calloc(1, size);
}
static void kfree(void *p) { if (p) allocations--; free(p); }

/* Kernel side of the interface, as much of it as this file touches. */
enum tc_setup_type { TC_SETUP_QDISC_HTB, TC_SETUP_FT, TC_SETUP_ROOT_QDISC, TC_SETUP_BLOCK };
enum tc_htb_command {
	TC_HTB_CREATE,
	TC_HTB_DESTROY,
	TC_HTB_LEAF_ALLOC_QUEUE,
	TC_HTB_LEAF_TO_INNER,
	TC_HTB_LEAF_DEL,
	TC_HTB_LEAF_DEL_LAST,
	TC_HTB_LEAF_DEL_LAST_FORCE,
	TC_HTB_NODE_MODIFY,
	TC_HTB_LEAF_QUERY_QUEUE,
};
struct netlink_ext_ack { int unused; };
struct tc_htb_qopt_offload {
	struct netlink_ext_ack *extack;
	enum tc_htb_command command;
	u32 parent_classid;
	u16 classid;
	u16 qid;
	u32 quantum;
	u64 rate;
	u64 ceil;
	u8 prio;
};
#define TC_HTB_CLASSID_ROOT	UINT32_MAX

struct dpa_iface_info { char name[16]; };
struct net_device;
struct tQM_context_ctl {
	struct dpa_iface_info *iface_info;
	struct net_device *net_dev;
	u32 qos_enabled;
	u32 chnl_map;
};
struct dpa_priv_s { void *qm_ctx; };
struct net_device {
	struct dpa_priv_s priv;
	char name[16];
	unsigned real_num_tx_queues;
};
static struct dpa_priv_s *netdev_priv(struct net_device *dev) { return &dev->priv; }

/* What the stack does with a queue index the driver hands back. */
#define DPA_SELECT_QUEUE_NONE	((u16)~0U)
struct sk_buff;
struct qman_fq;
struct dpa_qdisc_ops {
	u16 (*select_queue)(struct net_device *dev, struct sk_buff *skb);
	struct qman_fq *(*txq_fq)(void *qm_ctx, u16 txq);
};

/* Conntrack, as much of it as the queue selection touches. */
enum ip_conntrack_info { IP_CT_NEW, IP_CT_ESTABLISHED };
struct nf_conn { u32 mark; };
struct sk_buff { struct nf_conn *ct; };
struct qman_fq { unsigned channel, quenum; };
static struct nf_conn *nf_ct_get(struct sk_buff *skb, enum ip_conntrack_info *info)
{
	*info = IP_CT_ESTABLISHED;
	return skb->ct;
}
static void synchronize_net(void) {}

static int real_num_tx_queues_fails;
static int netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq)
{
	assert(txq >= 1 && txq <= DPAA_ETH_TX_QUEUES + DPAA_ETH_CEETM_LEAF_QUEUES);
	if (real_num_tx_queues_fails && txq > dev->real_num_tx_queues)
		return -ENOMEM;
	dev->real_num_tx_queues = txq;
	return 0;
}

/* One frame queue per (channel, class queue), so a test can name the pair a
 * Tx queue resolved to rather than just that it resolved to something. */
static struct qman_fq class_fqs[CDX_CEETM_MAX_CHANNELS][MAX_SCHEDULER_QUEUES];
static struct qman_fq *ceetm_class_fq(struct tQM_context_ctl *qm_ctx,
				      u32 channel, u32 quenum)
{
	assert(qm_ctx);
	if (channel >= CDX_CEETM_MAX_CHANNELS || quenum >= MAX_SCHEDULER_QUEUES)
		return NULL;
	return &class_fqs[channel][quenum];
}

static const struct dpa_qdisc_ops *registered_qdisc_ops;
static int dpa_register_qdisc_ops(const struct dpa_qdisc_ops *ops)
{
	if (!ops || !ops->select_queue || !ops->txq_fq)
		return -EINVAL;
	if (registered_qdisc_ops)
		return -EBUSY;
	registered_qdisc_ops = ops;
	return 0;
}
static void dpa_unregister_qdisc_ops(void) { registered_qdisc_ops = NULL; }

static struct tQM_context_ctl gQMCtx[MAX_PHY_PORTS];

/* The hardware layer, counted rather than performed. Every claim this file
 * hands out has to come back, so the test asserts on these totals. */
static bool chan_owner_set[CDX_CEETM_MAX_CHANNELS];
static struct tQM_context_ctl *chan_owner[CDX_CEETM_MAX_CHANNELS];
static bool cq_live[CDX_CEETM_MAX_CHANNELS][MAX_SCHEDULER_QUEUES];
static u32 cq_weight[CDX_CEETM_MAX_CHANNELS][MAX_SCHEDULER_QUEUES];
static u64 chan_cir[CDX_CEETM_MAX_CHANNELS], chan_eir[CDX_CEETM_MAX_CHANNELS];
static unsigned stop_calls;

/* One failure at a time, so every error path is walked without any other being
 * in the way. -1 means no fault. */
static int fault_point = -1;
static int fault_seen;
static bool fault(void)
{
	return fault_seen++ == fault_point;
}

static int ceetm_claim_channel(struct tQM_context_ctl *qm_ctx, u32 *channel_num)
{
	u32 ii;

	if (fault())
		return -ENOSPC;
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		if (chan_owner_set[ii])
			continue;
		chan_owner_set[ii] = true;
		chan_owner[ii] = qm_ctx;
		qm_ctx->chnl_map |= BIT(ii);
		*channel_num = ii;
		return 0;
	}
	return -ENOSPC;
}

static int ceetm_set_channel_rates(u32 channel_num, u64 cir_bps, u64 eir_bps)
{
	assert(channel_num < CDX_CEETM_MAX_CHANNELS);
	if (fault())
		return -EINVAL;
	chan_cir[channel_num] = cir_bps;
	chan_eir[channel_num] = eir_bps;
	return 0;
}

static int ceetm_set_class_queue(u32 channel_num, u32 quenum, u32 weight, u32 depth)
{
	assert(channel_num < CDX_CEETM_MAX_CHANNELS);
	assert(quenum < MAX_SCHEDULER_QUEUES);
	assert(depth != 0);
	/* A weight belongs to the weighted range and nowhere else. */
	assert((weight != 0) == (quenum >= NUM_PQS));
	if (fault())
		return -EIO;
	cq_live[channel_num][quenum] = true;
	cq_weight[channel_num][quenum] = weight;
	return 0;
}

static int ceetm_reset_class_queue(u32 channel_num, u32 quenum)
{
	assert(channel_num < CDX_CEETM_MAX_CHANNELS);
	assert(quenum < MAX_SCHEDULER_QUEUES);
	cq_live[channel_num][quenum] = false;
	cq_weight[channel_num][quenum] = 0;
	return 0;
}

static int ceetm_enable_or_disable_qos(struct tQM_context_ctl *qm_ctx, u32 oper)
{
	assert(oper == 1);
	if (!qm_ctx->chnl_map)
		return 1;
	if (qm_ctx->qos_enabled)
		return 0;
	if (fault())
		return 2;
	qm_ctx->qos_enabled = 1;
	return 0;
}

static int ceetm_stop_qos(struct tQM_context_ctl *qm_ctx)
{
	u32 ii, jj;

	stop_calls++;
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		if (chan_owner[ii] != qm_ctx)
			continue;
		for (jj = 0; jj < MAX_SCHEDULER_QUEUES; jj++) {
			cq_live[ii][jj] = false;
			cq_weight[ii][jj] = 0;
		}
		chan_cir[ii] = chan_eir[ii] = 0;
		chan_owner_set[ii] = false;
		chan_owner[ii] = NULL;
	}
	qm_ctx->chnl_map = 0;
	qm_ctx->qos_enabled = 0;
	/* Teardown reporting a problem must still leave nothing behind. */
	return fault() ? -EIO : 0;
}

typedef int (*cdx_ft_setup_tc_handler)(struct net_device *dev,
				       enum tc_setup_type type, void *type_data);
static cdx_ft_setup_tc_handler cdx_ft_handler;
typedef u8 (*cdx_ft_qos_class_fn)(u32 mark);
static cdx_ft_qos_class_fn cdx_ft_qos_class_func;

/* The ops table is file-scope data rather than a function, so the harness
 * builds its own from the production callbacks it does compile. */
static u16 cdx_htb_select_queue(struct net_device *dev, struct sk_buff *skb);
static struct qman_fq *cdx_htb_txq_fq(void *qm_ctx, u16 txq);
static const struct dpa_qdisc_ops cdx_htb_qdisc_ops = {
	.select_queue = cdx_htb_select_queue,
	.txq_fq = cdx_htb_txq_fq,
};
static cdx_ft_setup_tc_handler registered_ndo;
static int dpa_register_setup_tc(cdx_ft_setup_tc_handler handler)
{
	if (registered_ndo)
		return -EBUSY;
	registered_ndo = handler;
	return 0;
}
static void dpa_unregister_setup_tc(void) { registered_ndo = NULL; }
#define EXPORT_SYMBOL_NS_GPL(sym, ns)	extern int __unused_##sym

#include "htb_types.inc"

static struct cdx_htb_port cdx_htb_ports[MAX_PHY_PORTS];

#include "htb_production.inc"

/* ------------------------------------------------------------------ */

static struct net_device devices[2];

static void reset_world(void)
{
	unsigned ii;

	memset(chan_owner_set, 0, sizeof(chan_owner_set));
	memset(chan_owner, 0, sizeof(chan_owner));
	memset(cq_live, 0, sizeof(cq_live));
	memset(cq_weight, 0, sizeof(cq_weight));
	memset(chan_cir, 0, sizeof(chan_cir));
	memset(chan_eir, 0, sizeof(chan_eir));
	memset(gQMCtx, 0, sizeof(gQMCtx));
	memset(cdx_htb_ports, 0, sizeof(cdx_htb_ports));
	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++)
		INIT_LIST_HEAD(&cdx_htb_ports[ii].classes);
	devices[0].priv.qm_ctx = &gQMCtx[3];
	devices[1].priv.qm_ctx = &gQMCtx[4];
	gQMCtx[3].net_dev = &devices[0];
	gQMCtx[4].net_dev = &devices[1];
	devices[0].real_num_tx_queues = DPAA_ETH_TX_QUEUES;
	devices[1].real_num_tx_queues = DPAA_ETH_TX_QUEUES;
	memset(class_fqs, 0, sizeof(class_fqs));
	real_num_tx_queues_fails = 0;
	cdx_ft_qos_class_func = NULL;
	stop_calls = 0;
	fault_point = -1;
	fault_seen = 0;
	last_extack = NULL;
}

static int cmd(struct net_device *dev, struct tc_htb_qopt_offload *opt)
{
	return cdx_htb_setup_tc(dev, opt);
}

static int create(struct net_device *dev, u16 major, u16 defcls)
{
	struct tc_htb_qopt_offload opt = {
		.command = TC_HTB_CREATE,
		.parent_classid = major,
		.classid = defcls,
	};
	return cmd(dev, &opt);
}

/* parent == 0 means the qdisc root, the way sch_htb spells it. */
static int add_leaf(struct net_device *dev, u16 classid, u16 parent, u8 prio,
		    u32 quantum, u64 rate, u64 ceil, u16 *qid)
{
	struct tc_htb_qopt_offload opt = {
		.command = TC_HTB_LEAF_ALLOC_QUEUE,
		.classid = classid,
		.parent_classid = parent ? parent : TC_HTB_CLASSID_ROOT,
		.prio = prio,
		.quantum = quantum,
		.rate = rate,
		.ceil = ceil,
	};
	int rc = cmd(dev, &opt);

	if (!rc && qid)
		*qid = opt.qid;
	return rc;
}

/* sch_htb keeps the parent's netdev queue across this one and never reads qid
 * back, so the tests ask for the child's with a query instead. */
static int to_inner(struct net_device *dev, u16 child, u16 parent, u8 prio,
		    u32 quantum)
{
	struct tc_htb_qopt_offload opt = {
		.command = TC_HTB_LEAF_TO_INNER,
		.classid = child,
		.parent_classid = parent,
		.prio = prio,
		.quantum = quantum,
	};
	return cmd(dev, &opt);
}

static int del_leaf(struct net_device *dev, u16 classid, u16 *moved)
{
	struct tc_htb_qopt_offload opt = {
		.command = TC_HTB_LEAF_DEL,
		.classid = classid,
	};
	int rc = cmd(dev, &opt);

	if (moved)
		*moved = opt.classid == classid ? 0 : opt.classid;
	return rc;
}

static int del_last(struct net_device *dev, u16 classid, bool force)
{
	struct tc_htb_qopt_offload opt = {
		.command = force ? TC_HTB_LEAF_DEL_LAST_FORCE : TC_HTB_LEAF_DEL_LAST,
		.classid = classid,
	};
	return cmd(dev, &opt);
}

static int query(struct net_device *dev, u16 classid, u16 *qid)
{
	struct tc_htb_qopt_offload opt = {
		.command = TC_HTB_LEAF_QUERY_QUEUE,
		.classid = classid,
		/* sch_htb asks this one with no extack at all. */
		.extack = NULL,
	};
	int rc = cmd(dev, &opt);

	if (!rc)
		*qid = opt.qid;
	return rc;
}

static int modify(struct net_device *dev, u16 classid, u8 prio, u32 quantum,
		  u64 rate, u64 ceil)
{
	struct tc_htb_qopt_offload opt = {
		.command = TC_HTB_NODE_MODIFY,
		.classid = classid,
		.prio = prio,
		.quantum = quantum,
		.rate = rate,
		.ceil = ceil,
	};
	return cmd(dev, &opt);
}

static int destroy(struct net_device *dev)
{
	struct tc_htb_qopt_offload opt = { .command = TC_HTB_DESTROY };

	return cmd(dev, &opt);
}

static void assert_balanced(struct net_device *dev)
{
	struct cdx_htb_port *port = cdx_htb_port_of(dev);
	unsigned ii, jj;

	assert(!port->live);
	assert(!port->leaves);
	assert(!port->channels);
	assert(list_empty(&port->classes));
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		assert(!port->cq_used[ii]);
		assert(chan_owner[ii] != port->qm_ctx);
		for (jj = 0; jj < MAX_SCHEDULER_QUEUES; jj++)
			assert(!cq_live[ii][jj]);
	}
	assert(!port->qm_ctx->chnl_map);
	assert(!port->qm_ctx->qos_enabled);
}

/* A tree the way an operator writes one: a link-rate class with children that
 * divide it, plus a second top-level class alongside. */
static void test_tree(void)
{
	struct net_device *dev = &devices[0];
	struct cdx_htb_port *port;
	u16 qid1, qid2, qid10, qid11, qid12, got;

	reset_world();
	assert(!create(dev, 1, 20));
	port = cdx_htb_port_of(dev);
	assert(port->live && port->major == 1 && port->defcls == 20);
	/* A second qdisc on the same port is refused, not stacked. */
	assert(create(dev, 2, 0) == -EBUSY);

	/* A class under the root is a channel, and its first one starts the
	 * port scheduling. */
	assert(!add_leaf(dev, 1, 0, 0, 0, 125000000, 125000000, &qid1));
	assert(qid1 == DPAA_ETH_TX_QUEUES);
	assert(port->qm_ctx->qos_enabled);
	/* The buckets are additive, so ceil equal to rate leaves no excess. */
	assert(chan_cir[0] == 125000000ULL * 8);
	assert(chan_eir[0] == 0);

	assert(!add_leaf(dev, 2, 0, 0, 0, 25000000, 125000000, &qid2));
	assert(qid2 == DPAA_ETH_TX_QUEUES + 1);
	assert(chan_owner[1] == port->qm_ctx);
	assert(chan_cir[1] == 25000000ULL * 8);
	assert(chan_eir[1] == (125000000ULL - 25000000ULL) * 8);

	/* The first child turns its parent into the channel and takes over the
	 * parent's Tx queue. prio 0 is the top of the strict range, which is
	 * configuration index 7 because GET_CEETM_PRIORITY inverts it. */
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid10) && qid10 == qid1);
	assert(cq_live[0][NUM_PQS - 1]);
	assert(port->leaves == 2);

	assert(!add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid11));
	assert(qid11 == DPAA_ETH_TX_QUEUES + 2);
	assert(cq_live[0][NUM_PQS - 2]);

	/* One class per priority. A second class wanting prio 1 is told so. */
	assert(add_leaf(dev, 99, 1, 1, 0, 0, 0, NULL) == -EEXIST);
	assert(last_extack);

	/* A quantum asks to share instead, which is the weighted group. */
	assert(!add_leaf(dev, 12, 1, 0, 4, 0, 0, &qid12));
	assert(qid12 == DPAA_ETH_TX_QUEUES + 3);
	assert(cq_live[0][NUM_PQS] && cq_weight[0][NUM_PQS] == 4);

	assert(!query(dev, 12, &got) && got == qid12);
	assert(query(dev, 1, &got) == -ENOENT);	/* an inner class has no queue */

	/* Shaping a channel again is a modify on the class that is the channel;
	 * a leaf's modify moves it among its siblings instead. */
	assert(!modify(dev, 1, 0, 0, 12500000, 125000000));
	assert(chan_cir[0] == 12500000ULL * 8);
	assert(!modify(dev, 11, 3, 0, 0, 0));
	assert(!cq_live[0][NUM_PQS - 2] && cq_live[0][NUM_PQS - 4]);

	assert(!destroy(dev));
	assert(stop_calls == 1);
	assert_balanced(dev);
}

/* Deleting a leaf that is not the last one has to keep the qid range dense,
 * and say which class it moved to do it. */
static void test_density(void)
{
	struct net_device *dev = &devices[0];
	u16 qid[4], moved, got;
	unsigned ii;

	reset_world();
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid[0]));
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid[1]));
	assert(!add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid[2]));
	assert(!add_leaf(dev, 12, 1, 2, 0, 0, 0, &qid[3]));
	assert(qid[1] == DPAA_ETH_TX_QUEUES && qid[2] == DPAA_ETH_TX_QUEUES + 1 &&
	       qid[3] == DPAA_ETH_TX_QUEUES + 2);

	/* Delete the middle one: the last leaf moves into the hole. */
	assert(!del_leaf(dev, 11, &moved));
	assert(moved == 12);
	assert(!query(dev, 12, &got) && got == qid[2]);
	assert(!cq_live[0][NUM_PQS - 2]);	/* 11's priority came back */
	for (ii = 0; ii < 2; ii++)
		assert(cdx_htb_find_qid(cdx_htb_port_of(dev),
					DPAA_ETH_TX_QUEUES + ii));

	/* Deleting the last leaf moves nothing. */
	assert(!del_leaf(dev, 12, &moved));
	assert(moved == 0);

	/* The last child hands its queues back to its parent, which is a leaf
	 * again and keeps the same qid. */
	assert(!del_last(dev, 10, false));
	assert(!query(dev, 1, &got) && got == qid[1]);
	assert(cq_live[0][NUM_PQS - 1]);

	assert(!del_leaf(dev, 1, &moved));
	assert(!destroy(dev));
	assert_balanced(dev);
}

/* CEETM is two levels deep, and asking for a third says so rather than
 * quietly putting the class somewhere else. */
static void test_depth_and_limits(void)
{
	struct net_device *dev = &devices[0];
	u16 qid;
	int ii;

	reset_world();
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid));
	assert(!to_inner(dev, 10, 1, 0, 0));
	last_extack = NULL;
	assert(to_inner(dev, 100, 10, 0, 0) == -EOPNOTSUPP);
	assert(last_extack);
	assert(!destroy(dev));
	assert_balanced(dev);

	/* Eight weighted queues per channel, and no more. */
	reset_world();
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid));
	assert(!to_inner(dev, 10, 1, 0, 1));
	for (ii = 1; ii < NUM_WBFQS; ii++)
		assert(!add_leaf(dev, 10 + ii, 1, 0, 1, 0, 0, &qid));
	assert(add_leaf(dev, 90, 1, 0, 1, 0, 0, &qid) == -ENOSPC);
	assert(!destroy(dev));
	assert_balanced(dev);

	/* Eight channels for the whole SoC, shared by every port. */
	reset_world();
	assert(!create(&devices[0], 1, 0));
	assert(!create(&devices[1], 1, 0));
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++)
		assert(!add_leaf(&devices[ii & 1], 1 + ii, 0, 0, 0, 1000, 1000, &qid));
	assert(add_leaf(&devices[0], 99, 0, 0, 0, 1000, 1000, &qid) == -ENOSPC);
	assert(!destroy(&devices[0]));
	assert(!destroy(&devices[1]));
	assert_balanced(&devices[0]);
	assert_balanced(&devices[1]);

	/* prio names one of eight strict queues; anything else is an error
	 * rather than a silent demotion. */
	reset_world();
	assert(!create(dev, 1, 0));
	assert(add_leaf(dev, 1, 0, NUM_PQS, 0, 1000, 1000, &qid) == -EINVAL);
	assert(!destroy(dev));
	assert_balanced(dev);
}

/* A channel a class gave up is handed to the next one rather than detached,
 * and it does not carry the old class's rate with it. */
static void test_channel_reuse(void)
{
	struct net_device *dev = &devices[0];
	struct cdx_htb_port *port;
	u16 qid, moved;

	reset_world();
	assert(!create(dev, 1, 0));
	port = cdx_htb_port_of(dev);
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 2000, &qid));
	assert(chan_cir[0] == 8000 && chan_eir[0] == 8000);
	assert(!del_leaf(dev, 1, &moved));
	assert(port->channels == BIT(0));	/* still this port's */
	assert(chan_cir[0] == 0 && chan_eir[0] == 0);

	assert(!add_leaf(dev, 2, 0, 0, 0, 3000, 4000, &qid));
	assert(port->channels == BIT(0));	/* the same one, not a second */
	assert(chan_cir[0] == 24000 && chan_eir[0] == 8000);
	assert(!destroy(dev));
	assert_balanced(dev);
}

/* Whatever fails, and whenever, teardown balances. sch_htb discards what
 * TC_HTB_DESTROY and TC_HTB_LEAF_DEL_LAST_FORCE return, so there is no second
 * chance to give a claim back. */
static void test_faults(void)
{
	struct net_device *dev = &devices[0];
	int point;

	for (point = 0; point < 24; point++) {
		u16 qid;

		reset_world();
		fault_point = point;
		assert(!create(dev, 1, 0));
		add_leaf(dev, 1, 0, 0, 0, 1000, 2000, &qid);
		add_leaf(dev, 2, 0, 1, 0, 3000, 4000, &qid);
		to_inner(dev, 10, 1, 0, 0);
		add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid);
		add_leaf(dev, 12, 1, 0, 2, 0, 0, &qid);
		modify(dev, 11, 4, 0, 0, 0);
		del_leaf(dev, 11, NULL);
		del_last(dev, 12, true);
		del_leaf(dev, 1, NULL);
		del_leaf(dev, 2, NULL);
		destroy(dev);
		assert_balanced(dev);
		assert(allocations == 0);
	}
}

/* The dispatcher is the only handler the driver has, so it has to serve the
 * flowtable's verb as well as its own, and refuse a bind rather than answer a
 * question nothing is going to service. */
static int ft_calls;
static int ft_stub(struct net_device *dev, enum tc_setup_type type, void *data)
{
	(void)dev; (void)data;
	assert(type == TC_SETUP_FT);
	ft_calls++;
	return 0;
}

static void test_dispatch(void)
{
	struct tc_htb_qopt_offload opt = { .command = TC_HTB_CREATE, .parent_classid = 1 };
	int block = 0;

	reset_world();
	registered_ndo = NULL;
	cdx_ft_handler = NULL;
	assert(!cdx_htb_init());
	assert(registered_ndo == cdx_setup_tc);
	/* A second registration is refused rather than allowed to displace. */
	assert(cdx_htb_init() == -EBUSY);

	assert(cdx_setup_tc(&devices[0], TC_SETUP_FT, &block) == -EOPNOTSUPP);
	assert(!cdx_register_ft_setup_tc(ft_stub));
	assert(cdx_register_ft_setup_tc(ft_stub) == -EBUSY);
	assert(!cdx_setup_tc(&devices[0], TC_SETUP_FT, &block));
	assert(ft_calls == 1);
	assert(cdx_setup_tc(&devices[0], TC_SETUP_BLOCK, &block) == -EOPNOTSUPP);
	/* The root-qdisc graft is a notification. Refusing it makes every
	 * successful `tc qdisc add ... htb offload` report a failed graft. */
	assert(!cdx_setup_tc(&devices[0], TC_SETUP_ROOT_QDISC, &block));
	assert(!cdx_setup_tc(&devices[0], TC_SETUP_QDISC_HTB, &opt));

	cdx_unregister_ft_setup_tc();
	assert(cdx_setup_tc(&devices[0], TC_SETUP_FT, &block) == -EOPNOTSUPP);

	/* Unloading gives the ndo up before anything it reaches goes away, and
	 * drops the bookkeeping for a qdisc that outlived its module. */
	cdx_htb_exit();
	assert(!registered_ndo);
	assert(!cdx_htb_ports[3].live);
	assert(allocations == 0);
}

/* The classifier the adapter registers, as ft_qos_class() decodes a mark: the
 * masked bits shifted down to their own base. Eight bits wide, because a class
 * is a channel nibble and a class-queue nibble and a narrower field can only
 * ever name the queue. */
static u8 test_qos_class(u32 mark) { return (mark & 0xff00) >> 8; }

/* Send a frame whose conntrack carries the mark that decodes to `class`. */
static u16 pick(struct net_device *dev, u8 class)
{
	struct nf_conn ct = { .mark = (u32)class << 8 };
	struct sk_buff skb = { .ct = &ct };

	return cdx_htb_select_queue(dev, &skb);
}

/* The software path has to reach the class the hardware path would have put
 * the same flow on, and reach it from the queue index rather than by decoding
 * the mark a second time. */
static void test_software_path(void)
{
	struct net_device *dev = &devices[0];
	struct sk_buff skb = { .ct = NULL };
	u16 qid1, qid2, qid10, qid11, moved;

	reset_world();
	assert(!cdx_register_ft_qos_class(test_qos_class));
	assert(cdx_register_ft_qos_class(test_qos_class) == -EBUSY);
	assert(!create(dev, 1, 0));

	/* Two channels, so the channel nibble has something to choose between. */
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!add_leaf(dev, 2, 0, 0, 0, 1000, 1000, &qid2));
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid10));
	assert(!add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid11));
	/* Each leaf's queue is usable, which is the count the stack caps to. */
	assert(dev->real_num_tx_queues == DPAA_ETH_TX_QUEUES + 3);

	/* Channel 1 is the first channel, class queue 7 is prio 0: the mark
	 * 0x70 | 0x0 that named 1:10 in hardware picks 1:10's Tx queue here.
	 * The mark's channel nibble is one-based, as ceetm_get_egressfq()
	 * numbers them. */
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == qid10);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 2)) == qid11);
	/* Channel 2's only leaf is class 2, which still holds its own queue. */
	assert(pick(dev, (2 << 4) | (NUM_PQS - 1)) == qid2);
	/* A channel nibble of zero means the highest channel this port owns,
	 * which is the second one -- the same answer the hardware gives. */
	assert(pick(dev, NUM_PQS - 1) == qid2);
	/* A class no leaf holds leaves the stack's own choice alone. */
	assert(pick(dev, 0x00) == DPA_SELECT_QUEUE_NONE);
	assert(pick(dev, 0x03) == DPA_SELECT_QUEUE_NONE);
	/* A frame with no conntrack has no class to read. */
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);

	/* And the Tx path resolves the pair back out of the queue index. */
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid10) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid11) == &class_fqs[0][NUM_PQS - 2]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid2) == &class_fqs[1][NUM_PQS - 1]);
	/* Ordinary queues are not leaf classes, and neither is a slot no class
	 * holds; both send the frame down the path it took before. */
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, 0));
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES - 1));
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES + 3));
	assert(!cdx_htb_txq_fq(NULL, qid10));

	/* Deleting a leaf that is not the last one takes its class off the map,
	 * and the leaf that moved into the hole answers for the hole -- with
	 * the channel and class queue it already had, because only the Tx queue
	 * index moved. */
	assert(!del_leaf(dev, 2, &moved));
	assert(moved == 11);
	assert(pick(dev, (2 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 2)) == qid2);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid2) == &class_fqs[0][NUM_PQS - 2]);
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, qid11));
	/* Channel 2 stays claimed for the next class under the root, so the
	 * mark that names "whichever channel this port owns" still resolves the
	 * way ceetm_get_egressfq() resolves it: to that channel, which now
	 * holds no class of its own. */
	assert(pick(dev, NUM_PQS - 1) == DPA_SELECT_QUEUE_NONE);

	assert(!destroy(dev));
	assert(dev->real_num_tx_queues == DPAA_ETH_TX_QUEUES);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES));
	assert_balanced(dev);

	/* With no classifier registered nothing here has an opinion, which is
	 * what leaves a CMM port's Tx path exactly as it was. */
	cdx_unregister_ft_qos_class();
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	assert(!destroy(dev));
	assert_balanced(dev);
}

/* A queue that cannot be put into service is a class that cannot be created,
 * and it has to leave nothing behind. */
static void test_queue_budget(void)
{
	struct net_device *dev = &devices[0];
	u16 qid;

	reset_world();
	assert(!create(dev, 1, 0));
	real_num_tx_queues_fails = 1;
	assert(add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid) == -ENOMEM);
	assert(dev->real_num_tx_queues == DPAA_ETH_TX_QUEUES);
	real_num_tx_queues_fails = 0;
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid));
	assert(dev->real_num_tx_queues == DPAA_ETH_TX_QUEUES + 1);
	assert(!destroy(dev));
	assert_balanced(dev);
	assert(allocations == 0);
}

/* An interface with no CEETM context cannot host this qdisc, and neither can a
 * port another control plane already configured. */
static void test_refusals(void)
{
	struct net_device bare = { 0 };

	reset_world();
	assert(create(&bare, 1, 0) == -EOPNOTSUPP);

	gQMCtx[3].chnl_map = BIT(2);
	assert(create(&devices[0], 1, 0) == -EBUSY);
	gQMCtx[3].chnl_map = 0;
	gQMCtx[3].qos_enabled = 1;
	assert(create(&devices[0], 1, 0) == -EBUSY);
	gQMCtx[3].qos_enabled = 0;

	/* Every command but create needs a qdisc to exist first, teardown
	 * included: sch_htb only issues one for a qdisc whose create took. */
	assert(del_leaf(&devices[0], 1, NULL) == -ENOENT);
	assert(destroy(&devices[0]) == -ENOENT);
}

int main(void)
{
	test_tree();
	test_density();
	test_depth_and_limits();
	test_channel_reuse();
	test_software_path();
	test_queue_budget();
	test_faults();
	test_dispatch();
	test_refusals();
	assert(allocations == 0);
	printf("htb offload: tree, density, limits, reuse, software path, "
	       "%d fault points, dispatch passed\n", 24);
	return 0;
}

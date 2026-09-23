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
/* Formatted and discarded, so the compiler checks every format against its
 * arguments the way the kernel's printk attribute would. */
#define pr_warn(...)		((void)snprintf(NULL, 0, __VA_ARGS__))
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
enum tc_setup_type { TC_SETUP_QDISC_HTB, TC_SETUP_FT, TC_SETUP_ROOT_QDISC,
		     TC_SETUP_QDISC_RED, TC_SETUP_BLOCK };
enum tc_red_command { TC_RED_REPLACE, TC_RED_DESTROY, TC_RED_STATS,
		      TC_RED_XSTATS, TC_RED_GRAFT };
struct tc_red_qopt_offload_params {
	u32 min, max, probability, limit;
	bool is_ecn, is_harddrop, is_nodrop;
};
struct tc_red_qopt_offload {
	enum tc_red_command command;
	u32 handle;
	u32 parent;
	struct tc_red_qopt_offload_params set;
};
#define TC_H_MAJ_MASK	0xFFFF0000U
#define TC_H_MIN_MASK	0x0000FFFFU
#define TC_H_MIN(h)	((h) & TC_H_MIN_MASK)
#define TC_H_MAJ(h)	((h) & TC_H_MAJ_MASK)
#define TC_H_MAKE(maj, min) (((maj) & TC_H_MAJ_MASK) | ((min) & TC_H_MIN_MASK))
#define TC_H_ROOT	0xFFFFFFFFU
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
#define DPA_CEETM_CLASS_STATS	3
struct sk_buff;
struct qman_fq;
struct dpa_qdisc_ops {
	u16 (*select_queue)(struct net_device *dev, struct sk_buff *skb);
	struct qman_fq *(*txq_fq)(void *qm_ctx, u16 txq, struct sk_buff *skb);
	void (*class_stats)(void *qm_ctx, u64 *data);
};

/* Conntrack, and the frame's own header, as much of each as the queue
 * selection touches. A frame carries a DSCP whether or not it has a
 * conntrack: the map answers for the ones that named no class. */
enum ip_conntrack_info { IP_CT_NEW, IP_CT_ESTABLISHED };
struct nf_conn { u32 mark; };
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD
/* A macro rather than a function, because the production switch uses it in
 * case labels, where the kernel's own htons() is equally constant-foldable. */
#define htons(v)	((u16)((((u16)(v)) >> 8) | (((u16)(v)) << 8)))
struct iphdr { u8 tos; };
struct ipv6hdr { u8 dsfield; };
struct sock;
struct sk_buff {
	struct nf_conn *ct;
	u16 protocol;		/* big-endian, as the kernel keeps it */
	u8 tos;			/* the whole dsfield, as a header carries it */
	bool short_header;	/* too short to read the network header */
	int skb_iif;		/* the ingress a forwarded frame arrived on */
	struct sock *sk;	/* the gateway's own frames carry their socket */
};
struct qman_fq { unsigned channel, quenum; };
static struct nf_conn *nf_ct_get(struct sk_buff *skb, enum ip_conntrack_info *info)
{
	*info = IP_CT_ESTABLISHED;
	return skb->ct;
}
static bool pskb_network_may_pull(struct sk_buff *skb, unsigned len)
{ (void)len; return !skb->short_header; }
static struct iphdr *ip_hdr(struct sk_buff *skb)
{ static struct iphdr h; h.tos = skb->tos; return &h; }
static struct ipv6hdr *ipv6_hdr(struct sk_buff *skb)
{ static struct ipv6hdr h; h.dsfield = skb->tos; return &h; }
static u8 ipv4_get_dsfield(const struct iphdr *h) { return h->tos; }
static u8 ipv6_get_dsfield(const struct ipv6hdr *h) { return h->dsfield; }

/* The DSCP filters, which own what a codepoint means. Their own validation is
 * tools/host_tests/dscp_map.c; here all that matters is that a frame naming no
 * class reaches them and lands on the class they answer with. */
static u16 dscp_classes[64];
static u16 cdx_dscp_class(struct tQM_context_ctl *qm_ctx, u8 dscp)
{
	assert(qm_ctx);
	return dscp < 64 ? dscp_classes[dscp] : 0;
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

/* A synthetic total per (channel, class queue), so a test can say which pair a
 * leaf slot's counters came from. Queues the hardware will not answer for stay
 * at whatever the caller had. */
static bool class_counters_fail;
static int ceetm_class_counters(u32 channel, u32 quenum, u64 *deq_frames,
				u64 *deq_bytes, u64 *rej_frames)
{
	if (channel >= CDX_CEETM_MAX_CHANNELS || quenum >= MAX_SCHEDULER_QUEUES)
		return -EINVAL;
	if (class_counters_fail)
		return -EIO;
	*deq_frames = 1000u * channel + quenum;
	*deq_bytes = 100000u * channel + 100u * quenum;
	*rej_frames = 10u * channel + quenum;
	return 0;
}

/* The WRED curve a class queue was last given, so a test can say which class
 * a RED qdisc reached. The hardware layer's own handling of the curve --
 * including that configuring or resetting a class queue turns it off -- is
 * compiled in tools/host_tests/ceetm_wred.c; the stubs below mirror that. */
static struct { u32 min, max, probability, limit; bool set; }
	wred[CDX_CEETM_MAX_CHANNELS][MAX_SCHEDULER_QUEUES];
static unsigned wred_sets, wred_clears;
static bool wred_fail;
static int ceetm_set_class_wred(u32 channel, u32 quenum, u32 min, u32 max,
				u32 probability, u32 limit)
{
	assert(channel < CDX_CEETM_MAX_CHANNELS && quenum < MAX_SCHEDULER_QUEUES);
	wred_sets++;
	if (wred_fail)
		return -EIO;
	wred[channel][quenum] = (__typeof__(wred[0][0])){ min, max, probability,
							  limit, true };
	return 0;
}
static int ceetm_clear_class_wred(u32 channel, u32 quenum, u32 depth)
{
	assert(channel < CDX_CEETM_MAX_CHANNELS && quenum < MAX_SCHEDULER_QUEUES);
	assert(depth == 128);
	wred_clears++;
	memset(&wred[channel][quenum], 0, sizeof(wred[0][0]));
	return 0;
}
static unsigned warnings;
static char warning[256];
#define netdev_warn(dev, ...)	\
	((void)(dev), warnings++, (void)snprintf(warning, sizeof(warning), __VA_ARGS__))

static const struct dpa_qdisc_ops *registered_qdisc_ops;
static int dpa_register_qdisc_ops(const struct dpa_qdisc_ops *ops)
{
	if (!ops || !ops->select_queue || !ops->txq_fq || !ops->class_stats)
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
	/* Configured afresh, which starts it on tail drop. */
	memset(&wred[channel_num][quenum], 0, sizeof(wred[0][0]));
	return 0;
}

static int ceetm_reset_class_queue(u32 channel_num, u32 quenum)
{
	assert(channel_num < CDX_CEETM_MAX_CHANNELS);
	assert(quenum < MAX_SCHEDULER_QUEUES);
	cq_live[channel_num][quenum] = false;
	cq_weight[channel_num][quenum] = 0;
	memset(&wred[channel_num][quenum], 0, sizeof(wred[0][0]));
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
			memset(&wred[ii][jj], 0, sizeof(wred[0][0]));
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
/* SRCU is a read-side depth here, which the registration's wait asserts is
 * zero -- a caller that forgot the read lock, or an unregister that did not
 * wait, fails an assertion rather than a race. Two domains share it: the
 * egress hook's, below, and the flowtable handler's. One thread cannot run an
 * unregister beside a call, so what is checked for the handler is the shape
 * that makes waiting enough: the call is inside the read section, and the
 * unregister clears the pointer before it waits on the same srcu_struct. */
struct srcu_struct { int readers; unsigned syncs; };
#define DEFINE_STATIC_SRCU(name)	static struct srcu_struct name
static struct srcu_struct cdx_ft_handler_srcu;
static int srcu_read_lock(struct srcu_struct *ssp) { return ssp->readers++; }
static void srcu_read_unlock(struct srcu_struct *ssp, int idx)
{ assert(ssp->readers > 0 && idx == --ssp->readers); }
static unsigned srcu_syncs;
static void synchronize_srcu(struct srcu_struct *ssp)
{
	assert(!ssp->readers);
	if (ssp == &cdx_ft_handler_srcu)
		assert(!cdx_ft_handler);
	ssp->syncs++;
	srcu_syncs++;
}
typedef u16 (*cdx_ft_qos_class_fn)(u32 mark);
static cdx_ft_qos_class_fn cdx_ft_qos_class_func;

/* The flowtable's hook for a port whose egress changed, kept alive by an SRCU
 * domain rather than by its callers' RTNL, which the adapter's unload does not
 * take (the SRCU stubs are above). */
struct cdx_ft_egress_ops {
	void (*changed)(struct net_device *dev);
	int (*drain)(struct net_device *dev);
};
#define __rcu
#define srcu_dereference(p, s)	({ assert((s)->readers > 0); (p); })
#define rcu_access_pointer(p)	(p)
#define rcu_assign_pointer(p, v)	((p) = (v))
#define RCU_INIT_POINTER(p, v)	((p) = (v))
#define might_sleep()		do { } while (0)
/* Whether the backend holds any direction, for a drain with no adapter. */
static bool backend_idle = true;
static bool cdx_ft_idle(void) { return backend_idle; }
static struct net_device *egress_changed_dev;
static unsigned egress_changes, egress_drains;
static int egress_drain_rc;
static void egress_hook(struct net_device *dev)
{
	assert(dev);
	egress_changed_dev = dev;
	egress_changes++;
}
static int egress_drain(struct net_device *dev)
{
	assert(dev);
	egress_drains++;
	return egress_drain_rc;
}
static const struct cdx_ft_egress_ops egress_ops = {
	.changed = egress_hook,
	.drain = egress_drain,
};

/* The filter layers, which own what a police action and a DSCP filter mean.
 * This file is about the qdisc layer and the one ndo_setup_tc they all share,
 * so all that matters here is that a block request reaches the half that owns
 * its direction; their own validation is police.c and dscp_map.c. */
enum flow_block_binder_type {
	FLOW_BLOCK_BINDER_TYPE_UNSPEC,
	FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS,
	FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS,
};
struct flow_block_offload { enum flow_block_binder_type binder_type; };
static unsigned police_blocks, dscp_blocks;
static int cdx_police_setup_block(struct net_device *dev, struct flow_block_offload *f)
{
	assert(dev && f);
	police_blocks++;
	return -EOPNOTSUPP;
}
static int cdx_dscp_setup_block(struct net_device *dev, struct flow_block_offload *f)
{
	assert(dev && f);
	dscp_blocks++;
	return -EOPNOTSUPP;
}

/* A tree change is announced to the DSCP map, which names classes in it. */
static unsigned dscp_tree_changes;
static void cdx_dscp_tree_changed(struct net_device *dev)
{
	assert(dev);
	dscp_tree_changes++;
}
static void cdx_dscp_port_gone(struct tQM_context_ctl *qm_ctx) { (void)qm_ctx; }

/* One lock over the class lists. The production file takes it around every
 * command so a filter resolving a classid cannot walk a list mid-edit; here it
 * only has to assert it is never taken twice. */
typedef int mutex_t;
#define DEFINE_MUTEX(x) mutex_t x
static void mutex_lock(mutex_t *m) { assert(!*m); *m = 1; }
static void mutex_unlock(mutex_t *m) { assert(*m); *m = 0; }

/* The ops table is file-scope data rather than a function, so the harness
 * builds its own from the production callbacks it does compile. */
static u16 cdx_htb_select_queue(struct net_device *dev, struct sk_buff *skb);
static struct qman_fq *cdx_htb_txq_fq(void *qm_ctx, u16 txq, struct sk_buff *skb);
static void cdx_htb_class_stats(void *qm_ctx, u64 *data);
static const struct dpa_qdisc_ops cdx_htb_qdisc_ops = {
	.select_queue = cdx_htb_select_queue,
	.txq_fq = cdx_htb_txq_fq,
	.class_stats = cdx_htb_class_stats,
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
static DEFINE_MUTEX(cdx_htb_mutex);
DEFINE_STATIC_SRCU(cdx_ft_egress_srcu);
static const struct cdx_ft_egress_ops __rcu *cdx_ft_egress_ops;
static DEFINE_MUTEX(cdx_ft_egress_lock);

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
	/* As cdx_htb_init() leaves them: zero is a channel and a leaf slot, so
	 * the maps have to be published as saying none. */
	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++) {
		INIT_LIST_HEAD(&cdx_htb_ports[ii].classes);
		cdx_htb_publish(&cdx_htb_ports[ii]);
	}
	devices[0].priv.qm_ctx = &gQMCtx[3];
	devices[1].priv.qm_ctx = &gQMCtx[4];
	gQMCtx[3].net_dev = &devices[0];
	gQMCtx[4].net_dev = &devices[1];
	devices[0].real_num_tx_queues = DPAA_ETH_TX_QUEUES;
	devices[1].real_num_tx_queues = DPAA_ETH_TX_QUEUES;
	memset(class_fqs, 0, sizeof(class_fqs));
	memset(wred, 0, sizeof(wred));
	wred_sets = wred_clears = warnings = 0;
	wred_fail = false;
	real_num_tx_queues_fails = 0;
	class_counters_fail = false;
	cdx_ft_qos_class_func = NULL;
	cdx_ft_egress_ops = NULL;
	egress_changed_dev = NULL;
	egress_changes = egress_drains = srcu_syncs = 0;
	egress_drain_rc = 0;
	backend_idle = true;
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
	/* Inside the section the unregister waits out. */
	assert(cdx_ft_handler_srcu.readers == 1);
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
	/* A block is the filter layer's, not the qdisc layer's: this ndo only
	 * has to route it there. It used to fall through to the default arm
	 * and be refused before anything could offload a police action. */
	police_blocks = 0;
	assert(cdx_setup_tc(&devices[0], TC_SETUP_BLOCK, &block) == -EOPNOTSUPP);
	assert(police_blocks == 1);
	/* The root-qdisc graft is a notification. Refusing it makes every
	 * successful `tc qdisc add ... htb offload` report a failed graft. */
	assert(!cdx_setup_tc(&devices[0], TC_SETUP_ROOT_QDISC, &block));
	assert(!cdx_setup_tc(&devices[0], TC_SETUP_QDISC_HTB, &opt));

	assert(!cdx_ft_handler_srcu.readers && !cdx_ft_handler_srcu.syncs);
	/* Unregistering waits out the calls already inside the handler before
	 * the module that owns its text may go. */
	cdx_unregister_ft_setup_tc();
	assert(cdx_ft_handler_srcu.syncs == 1);
	assert(cdx_setup_tc(&devices[0], TC_SETUP_FT, &block) == -EOPNOTSUPP);
	assert(!cdx_ft_handler_srcu.readers && ft_calls == 1);

	/* Unloading gives the ndo up before anything it reaches goes away, and
	 * drops the bookkeeping for a qdisc that outlived its module. */
	cdx_htb_exit();
	assert(!registered_ndo);
	assert(!cdx_htb_ports[3].live);
	assert(allocations == 0);
}

/* The classifier the adapter registers, as ft_qos_class() decodes a mark: the
 * masked bits shifted down to their own base. Twelve bits wide, because a class
 * names a class queue, a channel and an ingress policer profile, one nibble
 * each, and a narrower field can only ever name the queue. */
static u16 test_qos_class(u32 mark) { return (mark & 0xfff00) >> 8; }

/* Send a frame whose conntrack carries the mark that decodes to `class`. */
static u16 pick(struct net_device *dev, u16 class)
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
	/* The class also names an ingress policer profile, which says nothing
	 * about where a frame leaves. Every profile has to give the same queue
	 * as no profile, and none of them may index past a table sized for the
	 * egress class -- the reason this path masks before it looks. */
	for (unsigned profile = 0; profile <= CDX_FT_QOS_MAX_POLICER; profile++) {
		u16 policed = (u16)(profile << CDX_FT_QOS_POLICER_SHIFT);

		assert(pick(dev, policed | (1 << 4) | (NUM_PQS - 1)) == qid10);
		assert(pick(dev, policed | (2 << 4) | (NUM_PQS - 1)) == qid2);
		assert(pick(dev, policed | 0x03) == DPA_SELECT_QUEUE_NONE);
	}
	/* A frame with no conntrack has no class to read, and no DSCP filter
	 * claims one either. */
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);

	/* ---- the DSCP map answers for frames that named no class ---- */

	memset(dscp_classes, 0, sizeof(dscp_classes));
	/* EF on channel 1, class queue 7 -- 1:10's pair, in the encoding the
	 * published class map is indexed by. */
	dscp_classes[46] = (1 << 4) | (NUM_PQS - 1);
	struct sk_buff ef = { .ct = NULL, .protocol = htons(ETH_P_IP), .tos = 46 << 2 };
	assert(cdx_htb_select_queue(dev, &ef) == qid10);
	/* Including over IPv6, where the same six bits sit in a different
	 * header. */
	struct sk_buff ef6 = { .ct = NULL, .protocol = htons(ETH_P_IPV6), .tos = 46 << 2 };
	assert(cdx_htb_select_queue(dev, &ef6) == qid10);
	/* A codepoint nobody claimed leaves the stack's own choice alone. */
	struct sk_buff be = { .ct = NULL, .protocol = htons(ETH_P_IP), .tos = 0 };
	assert(cdx_htb_select_queue(dev, &be) == DPA_SELECT_QUEUE_NONE);
	/* So does a frame that is not IP at all, and one whose header cannot
	 * be read without pulling it. */
	struct sk_buff arp = { .ct = NULL, .protocol = htons(0x0806), .tos = 46 << 2 };
	assert(cdx_htb_select_queue(dev, &arp) == DPA_SELECT_QUEUE_NONE);
	struct sk_buff runt = { .ct = NULL, .protocol = htons(ETH_P_IP),
				.tos = 46 << 2, .short_header = true };
	assert(cdx_htb_select_queue(dev, &runt) == DPA_SELECT_QUEUE_NONE);

	/* A frame that *did* name a class keeps it: the mark outranks the map,
	 * which is the precedence the hardware applies to the same frame. */
	struct nf_conn marked = { .mark = (u32)((2 << 4) | (NUM_PQS - 1)) << 8 };
	struct sk_buff both = { .ct = &marked, .protocol = htons(ETH_P_IP),
				.tos = 46 << 2 };
	assert(cdx_htb_select_queue(dev, &both) == qid2);
	/* And a conntracked frame whose mark names nothing still gets the map's
	 * answer, rather than falling through to the stack's choice. */
	struct nf_conn unmarked = { .mark = 0 };
	struct sk_buff ct_ef = { .ct = &unmarked, .protocol = htons(ETH_P_IP),
				 .tos = 46 << 2 };
	assert(cdx_htb_select_queue(dev, &ct_ef) == qid10);

	/* A class the map names but no leaf holds is not a queue. */
	dscp_classes[46] = 0x03;
	assert(cdx_htb_select_queue(dev, &ef) == DPA_SELECT_QUEUE_NONE);
	/* Nor is one past the table the class map is sized for. */
	dscp_classes[46] = CDX_HTB_CLASSES + 1;
	assert(cdx_htb_select_queue(dev, &ef) == DPA_SELECT_QUEUE_NONE);
	memset(dscp_classes, 0, sizeof(dscp_classes));

	/* And the Tx path resolves the pair back out of the queue index. */
	struct sk_buff own = { .ct = NULL };
	struct nf_conn plain = { .mark = 0 };
	struct sk_buff forwarded = { .ct = &plain, .skb_iif = 5 };
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid10, &own) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid11, &own) == &class_fqs[0][NUM_PQS - 2]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid2, &own) == &class_fqs[1][NUM_PQS - 1]);
	/* An ordinary queue, or a slot no class holds, carries a frame that
	 * named no leaf -- and on a port with a tree that frame is the tree's
	 * to place too, never the driver's mark-based guess. The gateway's own
	 * frame takes the top channel's control queue; a forwarded, tracked
	 * one takes class queue 0 there, where the hardware puts its flow. */
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &own) == &class_fqs[1][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES - 1, &forwarded) ==
	       &class_fqs[1][0]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES + 3, &own) ==
	       &class_fqs[1][NUM_PQS - 1]);
	assert(!cdx_htb_txq_fq(NULL, qid10, &own));

	/* Deleting a leaf that is not the last one takes its class off the map,
	 * and the leaf that moved into the hole answers for the hole -- with
	 * the channel and class queue it already had, because only the Tx queue
	 * index moved. */
	assert(!del_leaf(dev, 2, &moved));
	assert(moved == 11);
	assert(pick(dev, (2 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 2)) == qid2);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid2, &own) == &class_fqs[0][NUM_PQS - 2]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid11, &own) == &class_fqs[1][NUM_PQS - 1]);
	/* Channel 2 stays claimed for the next class under the root, so the
	 * mark that names "whichever channel this port owns" still resolves the
	 * way ceetm_get_egressfq() resolves it: to that channel, which now
	 * holds no class of its own. */
	assert(pick(dev, NUM_PQS - 1) == DPA_SELECT_QUEUE_NONE);

	assert(!destroy(dev));
	assert(dev->real_num_tx_queues == DPAA_ETH_TX_QUEUES);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	/* No tree, no opinion: the driver's own resolution is back. */
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES, &own));
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &forwarded));
	assert_balanced(dev);

	/* With no classifier registered no mark is decoded, and no frame is put
	 * on a leaf's queue. The tree still owns the port, though, so every
	 * frame still lands on one of its queues rather than wherever the
	 * driver's mark field would have sent it. */
	cdx_unregister_ft_qos_class();
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &own) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &forwarded) == &class_fqs[0][0]);
	assert(!destroy(dev));
	assert_balanced(dev);
}

/* Traffic that names no leaf, on a port whose tree is live.
 *
 * It used to go wherever the driver's mark field said: class queue 7 for every
 * frame with no mark, a queue no leaf configured and eligible only for excess
 * tokens. With rate equal to ceil a channel has none except what its classes
 * leave over, so one saturated leaf starved the gateway's own frames, and the
 * same flow sat on queue 7 in software and queue 0 in hardware. Now both
 * paths resolve it the same way, onto a queue the tree keeps eligible for
 * committed tokens, and `default' is honoured. */
static void test_unclassified(void)
{
	struct net_device *dev = &devices[0];
	struct tQM_context_ctl *ctx = dev->priv.qm_ctx;
	struct nf_conn plain = { .mark = 0 };
	struct nf_conn stray = { .mark = (u32)((1 << 4) | 3) << 8 };	/* no leaf holds it */
	struct sk_buff own = { .ct = NULL };
	struct sk_buff own_tracked = { .ct = &plain };
	struct sk_buff forwarded = { .ct = &plain, .skb_iif = 5 };
	struct sk_buff forwarded_stray = { .ct = &stray, .skb_iif = 5 };
	struct sk_buff bridged = { .ct = NULL, .skb_iif = 5 };
	u16 qid1, qid10, qid20, qid17, qid2;
	u32 channel, cq;

	/* ---- no default: control on queue 7, unclassified on queue 0 ---- */
	reset_world();
	assert(!cdx_register_ft_qos_class(test_qos_class));
	channel = 0; cq = 0;
	assert(!cdx_htb_resolve_class(ctx, &channel, &cq));	/* no tree yet */
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!to_inner(dev, 10, 1, 1, 0));			/* prio 1: queue 6 */
	assert(!query(dev, 10, &qid10));
	/* Both queues those frames take are eligible for the channel's
	 * committed rate, configured as a leaf's would be. */
	assert(cq_live[0][0] && cq_weight[0][0] == 0);
	assert(cq_live[0][NUM_PQS - 1] && cq_weight[0][NUM_PQS - 1] == 0);
	/* The gateway's own frames, and those conntrack never saw, take the
	 * control queue; a forwarded, tracked frame takes queue 0 -- as does
	 * one naming a class no leaf holds. */
	assert(cdx_htb_select_queue(dev, &own) == DPA_SELECT_QUEUE_NONE);
	assert(cdx_htb_select_queue(dev, &own_tracked) == DPA_SELECT_QUEUE_NONE);
	assert(cdx_htb_select_queue(dev, &forwarded) == DPA_SELECT_QUEUE_NONE);
	assert(cdx_htb_txq_fq(ctx, 3, &own) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(ctx, 3, &own_tracked) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(ctx, 3, &bridged) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(ctx, 3, &forwarded) == &class_fqs[0][0]);
	assert(cdx_htb_txq_fq(ctx, 3, &forwarded_stray) == &class_fqs[0][0]);
	/* And the hardware agrees: no class, or a class no leaf holds, is the
	 * top channel's queue 0; a leaf's class is the leaf's. The channel is
	 * in the mark's numbering both ways. */
	channel = 0; cq = 0;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == 0);
	channel = 1; cq = 3;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == 0);
	channel = 0; cq = NUM_PQS - 2;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == NUM_PQS - 2);
	channel = 15; cq = 15;					/* no such channel */
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == 0);

	/* A leaf on queue 0 (prio 7) is where the unclassified already went, so
	 * it is now the class they land on in software too, from the leaf's
	 * own Tx queue. The gateway's own frames stay on the control queue. */
	assert(!add_leaf(dev, 17, 1, 7, 0, 0, 0, &qid17));
	assert(cdx_htb_select_queue(dev, &forwarded) == qid17);
	assert(cdx_htb_select_queue(dev, &forwarded_stray) == qid17);
	assert(cdx_htb_select_queue(dev, &own) == DPA_SELECT_QUEUE_NONE);
	/* It is the leaf's queue now, and deleting the leaf gives it back to
	 * the unclassified: reset, then eligible again. */
	assert(!del_leaf(dev, 17, NULL));
	assert(cq_live[0][0] && cdx_htb_select_queue(dev, &forwarded) == DPA_SELECT_QUEUE_NONE);
	/* A prio 0 leaf shares the control queue rather than displacing it. */
	assert(!add_leaf(dev, 11, 1, 0, 0, 0, 0, NULL));
	assert(cdx_htb_txq_fq(ctx, 3, &own) == &class_fqs[0][NUM_PQS - 1]);
	assert(!del_leaf(dev, 11, NULL));
	assert(cq_live[0][NUM_PQS - 1]);

	/* A class under the root on a higher channel moves the top channel, and
	 * the eligible queues move with it; the ones left behind are reset. */
	assert(!add_leaf(dev, 2, 0, 3, 0, 1000, 1000, &qid2));	/* channel 1 */
	assert(cq_live[1][0] && cq_live[1][NUM_PQS - 1]);
	assert(!cq_live[0][0] && !cq_live[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(ctx, 3, &own) == &class_fqs[1][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(ctx, 3, &forwarded) == &class_fqs[1][0]);
	assert(!destroy(dev));
	assert_balanced(dev);

	/* ---- a default leaf takes all of it ---- */
	reset_world();
	assert(!cdx_register_ft_qos_class(test_qos_class));
	assert(!create(dev, 1, 20));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!to_inner(dev, 10, 1, 0, 0));			/* queue 7 */
	assert(!query(dev, 10, &qid10));
	/* Named before the leaf exists, as `tc qdisc add ... default 20' is:
	 * nothing to honour until a leaf by that minor arrives. */
	assert(cdx_htb_select_queue(dev, &forwarded) == DPA_SELECT_QUEUE_NONE);
	assert(!add_leaf(dev, 20, 1, 2, 0, 0, 0, &qid20));	/* queue 5 */
	/* Tracked or not, forwarded or the gateway's own, with no class or a
	 * class no leaf holds: the default leaf, from its own Tx queue. */
	assert(cdx_htb_select_queue(dev, &own) == qid20);
	assert(cdx_htb_select_queue(dev, &own_tracked) == qid20);
	assert(cdx_htb_select_queue(dev, &forwarded) == qid20);
	assert(cdx_htb_select_queue(dev, &forwarded_stray) == qid20);
	assert(cdx_htb_select_queue(dev, &bridged) == qid20);
	/* A class a leaf does hold is still that leaf. */
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == qid10);
	/* A frame caught on a direct queue anyway goes there too. */
	assert(cdx_htb_txq_fq(ctx, 3, &own) == &class_fqs[0][NUM_PQS - 3]);
	/* The hardware resolves no class, and a class no leaf holds, to it. */
	channel = 0; cq = 0;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == NUM_PQS - 3);
	channel = 1; cq = 3;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == NUM_PQS - 3);
	channel = 1; cq = NUM_PQS - 1;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == NUM_PQS - 1);
	/* Deleting the default leaf takes it back to queue 0. */
	assert(!del_leaf(dev, 20, NULL));
	channel = 0; cq = 0;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == 0);
	assert(cdx_htb_select_queue(dev, &own) == DPA_SELECT_QUEUE_NONE);
	assert(!destroy(dev));
	assert_balanced(dev);
	cdx_unregister_ft_qos_class();
	assert(allocations == 0);
}

/* ethtool asks for a fixed number of values and gets one for every leaf slot,
 * whatever the tree looks like -- names and values arrive in separate ioctls,
 * so a count that moved with the tree would misalign them. */
static void test_class_statistics(void)
{
	u64 data[CDX_HTB_MAX_LEAVES * DPA_CEETM_CLASS_STATS];
	struct net_device *dev = &devices[0];
	u16 qid1, qid2, qid10;
	unsigned ii;

	reset_world();
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!add_leaf(dev, 2, 0, 0, 0, 1000, 1000, &qid2));
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid10));

	memset(data, 0xff, sizeof(data));
	cdx_htb_class_stats(dev->priv.qm_ctx, data);
	/* Slot 0 is class 10: channel 0, the top strict-priority queue. */
	assert(data[0] == NUM_PQS - 1 && data[1] == 100u * (NUM_PQS - 1));
	assert(data[2] == NUM_PQS - 1);
	/* Slot 1 is class 2, on the second channel. */
	assert(data[3] == 1000u + NUM_PQS - 1);
	assert(data[4] == 100000u + 100u * (NUM_PQS - 1));
	assert(data[5] == 10u + NUM_PQS - 1);
	/* Every other slot is left exactly as the caller had it, which is the
	 * zero the driver writes before asking. */
	for (ii = 2 * DPA_CEETM_CLASS_STATS; ii < ARRAY_SIZE(data); ii++)
		assert(data[ii] == UINT64_MAX);

	/* A queue the hardware will not answer for leaves its slot alone rather
	 * than reporting a number nothing stands behind. */
	memset(data, 0, sizeof(data));
	class_counters_fail = true;
	cdx_htb_class_stats(dev->priv.qm_ctx, data);
	for (ii = 0; ii < ARRAY_SIZE(data); ii++)
		assert(data[ii] == 0);
	class_counters_fail = false;

	/* A port with no context at all still has to be safe to ask. */
	cdx_htb_class_stats(NULL, data);

	assert(!destroy(dev));
	memset(data, 0, sizeof(data));
	cdx_htb_class_stats(dev->priv.qm_ctx, data);
	for (ii = 0; ii < ARRAY_SIZE(data); ii++)
		assert(data[ii] == 0);
	assert_balanced(dev);
}

/* A RED qdisc names the class it was grafted under, and that class is the
 * class queue whose congestion group it configures. */
/* The RED qdisc the calls below come from, by handle. */
#define RED_QDISC	TC_H_MAKE(20u << 16, 0)
static u32 red_qdisc = RED_QDISC;

static int red(struct net_device *dev, u32 parent, enum tc_red_command cmd,
	       u32 min, u32 max, u32 probability, u32 limit, bool ecn)
{
	struct tc_red_qopt_offload opt = {
		.command = cmd,
		.handle = red_qdisc,
		.parent = parent,
		.set = { .min = min, .max = max, .probability = probability,
			 .limit = limit, .is_ecn = ecn },
	};

	return cdx_htb_setup_red(dev, &opt);
}

/* A curve the hardware takes, on whichever class `parent' names. */
static int red_good(struct net_device *dev, u32 parent)
{
	return red(dev, parent, TC_RED_REPLACE, 1000, 4000, 1u << 26, 16000, false);
}

/* What tc reads as "offloaded": the statistics call answering at all. */
static bool red_offloaded(struct net_device *dev, u32 parent)
{
	int rc = red(dev, parent, TC_RED_STATS, 0, 0, 0, 0, false);

	assert(!rc || rc == -EOPNOTSUPP);
	return !rc;
}

static void test_red(void)
{
	struct net_device *dev = &devices[0];
	const u32 on1 = TC_H_MAKE(1 << 16, 1), on10 = TC_H_MAKE(1 << 16, 10);
	const u32 on11 = TC_H_MAKE(1 << 16, 11), on12 = TC_H_MAKE(1 << 16, 12);
	unsigned sets, clears;
	u16 qid1, qid10, qid11;

	reset_world();
	/* Nothing to graft onto before a qdisc exists, and the log says so. */
	assert(red_good(dev, on10) == -EOPNOTSUPP);
	assert(warnings == 1 && !wred_sets);

	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid10));
	assert(!red_offloaded(dev, on10));

	/* Class 10 is channel 0's top strict-priority queue. */
	assert(!red_good(dev, on10));
	assert(wred[0][NUM_PQS - 1].set);
	assert(wred[0][NUM_PQS - 1].min == 1000 && wred[0][NUM_PQS - 1].max == 4000);
	assert(wred[0][NUM_PQS - 1].limit == 16000);
	/* Only now does the qdisc report itself offloaded. Its counters stay
	 * software's -- ethtool -S has the class queue's -- so the extended
	 * statistics answer without changing them. */
	assert(red_offloaded(dev, on10));
	assert(!red(dev, on10, TC_RED_XSTATS, 0, 0, 0, 0, false));
	/* A qdisc under RED would sit below the class queue. */
	assert(red(dev, on10, TC_RED_GRAFT, 0, 0, 0, 0, false) == -EOPNOTSUPP);

	/* ECN is a request to mark, and this hardware only drops. It is refused
	 * without the curve setter being asked, and -- because sch_red keeps the
	 * changed qdisc in software whatever this says -- the curve the class
	 * had comes off too, rather than running under a qdisc showing another. */
	sets = wred_sets;
	warnings = 0;
	assert(red(dev, on10, TC_RED_REPLACE, 2000, 8000, 1u << 26, 16000, true) == -EOPNOTSUPP);
	assert(wred_sets == sets && !wred[0][NUM_PQS - 1].set && warnings == 1);
	assert(!red_offloaded(dev, on10));
	/* The same for a curve with no band, one with no limit, and one the
	 * hardware will not take. */
	assert(!red_good(dev, on10));
	assert(red(dev, on10, TC_RED_REPLACE, 4000, 4000, 1u << 26, 16000, false) == -EINVAL);
	assert(!wred[0][NUM_PQS - 1].set && !red_offloaded(dev, on10));
	assert(!red_good(dev, on10));
	assert(red(dev, on10, TC_RED_REPLACE, 1000, 4000, 1u << 26, 0, false) == -EINVAL);
	assert(!wred[0][NUM_PQS - 1].set && !red_offloaded(dev, on10));
	assert(!red_good(dev, on10));
	wred_fail = true;
	assert(red(dev, on10, TC_RED_REPLACE, 2000, 8000, 1u << 26, 16000, false) == -EIO);
	wred_fail = false;
	assert(!wred[0][NUM_PQS - 1].set && !red_offloaded(dev, on10));
	/* A destroy after a refusal has nothing left to take off. */
	clears = wred_clears;
	assert(!red(dev, on10, TC_RED_DESTROY, 0, 0, 0, 0, false));
	assert(wred_clears == clears);

	/* The root qdisc is the port, not a class queue; an inner class is a
	 * channel, which has no congestion group of its own; and a class the
	 * tree does not have is nothing. None of them reaches the setter. */
	sets = wred_sets;
	assert(red_good(dev, TC_H_ROOT) == -EOPNOTSUPP);
	assert(red_good(dev, on1) == -EOPNOTSUPP);
	assert(red_good(dev, TC_H_MAKE(1 << 16, 99)) == -EOPNOTSUPP);
	/* A RED one level further down -- under a qdisc 10: grafted on the
	 * leaf -- names minor 10 too. Its major is not the tree's, so it
	 * programs nothing, rather than class 1:10's queue. */
	assert(red_good(dev, TC_H_MAKE(10 << 16, 10)) == -EOPNOTSUPP);
	assert(!red_offloaded(dev, TC_H_MAKE(10 << 16, 10)));
	assert(wred_sets == sets && !wred[0][NUM_PQS - 1].set);

	/* Moving the leaf to another priority takes its curve along: the queue
	 * it leaves is reset and the one it takes starts on tail drop. */
	assert(!red_good(dev, on10));
	assert(!modify(dev, 10, 2, 0, 0, 0));
	assert(!wred[0][NUM_PQS - 1].set && wred[0][NUM_PQS - 3].set);
	assert(wred[0][NUM_PQS - 3].min == 1000 && wred[0][NUM_PQS - 3].limit == 16000);
	assert(red_offloaded(dev, on10));

	/* A leaf deleted with its RED qdisc still on it. sch_htb deletes the
	 * class first and destroys the qdisc afterwards, naming a class that
	 * is gone by then, so the delete is what has to take the curve off. */
	assert(!add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid11));
	assert(!red_good(dev, on11));
	assert(wred[0][NUM_PQS - 2].set);
	assert(!del_leaf(dev, 11, NULL));
	assert(!wred[0][NUM_PQS - 2].set);
	assert(red(dev, on11, TC_RED_DESTROY, 0, 0, 0, 0, false) == -EOPNOTSUPP);

	/* The last child's curve does not pass to the parent that inherits its
	 * class queue: its RED qdisc belonged to the child. */
	assert(wred[0][NUM_PQS - 3].set);
	assert(!del_last(dev, 10, false));
	assert(!wred[0][NUM_PQS - 3].set);
	assert(!red_offloaded(dev, on1));

	/* A leaf that becomes a channel loses its curve with its queue. */
	assert(!red_good(dev, on1));
	assert(wred[0][NUM_PQS - 3].set && red_offloaded(dev, on1));
	assert(!to_inner(dev, 12, 1, 0, 0));
	assert(!wred[0][NUM_PQS - 3].set && !wred[0][NUM_PQS - 1].set);
	assert(red(dev, on1, TC_RED_DESTROY, 0, 0, 0, 0, false) == -EOPNOTSUPP);

	/* A destroy of a curve that is running takes it off. */
	assert(!red_good(dev, on12));
	clears = wred_clears;
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));
	assert(wred_clears == clears + 1 && !wred[0][NUM_PQS - 1].set);
	assert(!red_offloaded(dev, on12));

	/* `tc qdisc replace' of one RED qdisc by another on the same class
	 * creates the new one before it destroys the old one. The old one's
	 * destroy leaves the new curve running, and the old one never reports
	 * the new curve as its own. */
	assert(!red_good(dev, on12));
	red_qdisc = TC_H_MAKE(21u << 16, 0);
	assert(!red(dev, on12, TC_RED_REPLACE, 2000, 8000, 1u << 26, 32000, false));
	assert(red_offloaded(dev, on12));
	red_qdisc = RED_QDISC;
	assert(!red_offloaded(dev, on12));
	clears = wred_clears;
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));
	assert(wred_clears == clears && wred[0][NUM_PQS - 1].limit == 32000);
	/* A replacement refused leaves the running curve for its own qdisc's
	 * destroy, and the log does not claim tail drop meanwhile; a change
	 * refused to the qdisc whose curve runs takes it off at once. */
	red_qdisc = TC_H_MAKE(22u << 16, 0);
	warnings = 0;
	assert(red(dev, on12, TC_RED_REPLACE, 2000, 8000, 1u << 26, 16000, true) == -EOPNOTSUPP);
	assert(warnings == 1 && !strstr(warning, "tail drop"));
	assert(strstr(warning, "keeps RED qdisc 15's curve"));
	assert(wred[0][NUM_PQS - 1].set && !red_offloaded(dev, on12));
	red_qdisc = TC_H_MAKE(21u << 16, 0);
	assert(red_offloaded(dev, on12));
	assert(red(dev, on12, TC_RED_REPLACE, 2000, 8000, 1u << 26, 16000, true) == -EOPNOTSUPP);
	assert(warnings == 2 && strstr(warning, "tail drop"));
	assert(!wred[0][NUM_PQS - 1].set && !red_offloaded(dev, on12));
	clears = wred_clears;
	red_qdisc = TC_H_MAKE(22u << 16, 0);
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));
	red_qdisc = TC_H_MAKE(21u << 16, 0);
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));
	assert(wred_clears == clears);
	/* A replacement that fails after its REPLACE programmed the queue --
	 * sch_red's qevents or estimator refusing -- is destroyed with the
	 * qdisc it would have replaced still grafted, and that one gets its
	 * curve back rather than silently losing it. */
	red_qdisc = RED_QDISC;
	assert(!red_good(dev, on12) && wred[0][NUM_PQS - 1].limit == 16000);
	red_qdisc = TC_H_MAKE(23u << 16, 0);
	assert(!red(dev, on12, TC_RED_REPLACE, 2000, 8000, 1u << 26, 32000, false));
	assert(wred[0][NUM_PQS - 1].limit == 32000);
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));
	assert(!red_offloaded(dev, on12));
	red_qdisc = RED_QDISC;
	assert(red_offloaded(dev, on12));
	assert(wred[0][NUM_PQS - 1].set && wred[0][NUM_PQS - 1].limit == 16000);
	/* And once the curve is its own again, its destroy takes it off. */
	clears = wred_clears;
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));
	assert(wred_clears == clears + 1 && !wred[0][NUM_PQS - 1].set);
	/* A curve that will not go back leaves tail drop and says so. */
	assert(!red_good(dev, on12));
	red_qdisc = TC_H_MAKE(23u << 16, 0);
	assert(!red(dev, on12, TC_RED_REPLACE, 2000, 8000, 1u << 26, 32000, false));
	wred_fail = true;
	warnings = 0;
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));
	wred_fail = false;
	assert(warnings == 1 && strstr(warning, "tail drop"));
	assert(!wred[0][NUM_PQS - 1].set);
	red_qdisc = RED_QDISC;
	assert(!red_offloaded(dev, on12));
	assert(!red(dev, on12, TC_RED_DESTROY, 0, 0, 0, 0, false));

	/* Tearing the tree down with a curve still running leaves none behind:
	 * the RED qdisc's own destroy comes after the tree's. */
	assert(!red_good(dev, on12));
	assert(!destroy(dev));
	assert(!wred[0][NUM_PQS - 1].set);
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

/* Every command that can change which queues a port drains tells the
 * flowtable, naming that port: the first leaf switches it to CEETM, a class
 * change moves or removes the queue a class names, and destroy switches it
 * back. A query changes nothing and says nothing. A failed command still
 * tells, because it may have got as far as switching the mode. */
static void test_egress_changed(void)
{
	struct net_device *dev = &devices[0];
	u16 qid1, qid11, moved, got;
	unsigned n;

	reset_world();
	/* Both ops or nothing: a registrant that cannot drain would let the
	 * DSCP map move while entries still read it. */
	static const struct cdx_ft_egress_ops no_drain = { .changed = egress_hook };
	assert(cdx_register_ft_egress(NULL) == -EINVAL);
	assert(cdx_register_ft_egress(&no_drain) == -EINVAL);
	assert(!cdx_register_ft_egress(&egress_ops));
	assert(cdx_register_ft_egress(&egress_ops) == -EBUSY);
	assert(!create(dev, 1, 20));
	assert(egress_changes == 1 && egress_changed_dev == dev);
	assert(!add_leaf(dev, 1, 0, 0, 0, 125000000, 125000000, &qid1));
	assert(egress_changes == 2 && cdx_htb_port_of(dev)->qm_ctx->qos_enabled);
	assert(!query(dev, 1, &got) && egress_changes == 2);
	assert(!to_inner(dev, 10, 1, 0, 0) && egress_changes == 3);
	assert(!add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid11) && egress_changes == 4);
	assert(!modify(dev, 11, 3, 0, 0, 0) && egress_changes == 5);
	assert(!del_leaf(dev, 11, &moved) && egress_changes == 6);
	n = egress_changes;
	assert(add_leaf(dev, 99, 1, 0, 0, 0, 0, NULL) == -EEXIST);
	assert(egress_changes == n + 1 && egress_changed_dev == dev);
	egress_changed_dev = NULL;
	assert(!destroy(dev));
	assert(egress_changes == n + 2 && egress_changed_dev == dev);

	/* The DSCP map's callers hold RTNL today, but the hook relies on none
	 * of the caller's locks, so it works without. */
	rtnl = false;
	cdx_ft_egress_changed(&devices[1]);
	assert(egress_changes == n + 3 && egress_changed_dev == &devices[1]);
	egress_drain_rc = -EAGAIN;
	assert(cdx_ft_egress_drain(&devices[1]) == -EAGAIN && egress_drains == 1);
	egress_drain_rc = 0;
	assert(!cdx_ft_egress_drain(&devices[1]) && egress_drains == 2);
	assert(!cdx_ft_egress_srcu.readers);
	rtnl = true;

	/* Unregistering waits out whoever is inside, and from then on nothing
	 * reaches the adapter. A drain with no adapter to ask answers from the
	 * backend: nothing installed, nothing to wait for. */
	cdx_unregister_ft_egress();
	assert(srcu_syncs == 1);
	assert(!create(dev, 1, 20) && egress_changes == n + 3);
	assert(!destroy(dev));
	assert(!cdx_ft_egress_drain(dev) && egress_drains == 2);
	backend_idle = false;
	assert(cdx_ft_egress_drain(dev) == -EAGAIN);
	assert_balanced(dev);
}

int main(void)
{
	test_tree();
	test_egress_changed();
	test_density();
	test_depth_and_limits();
	test_channel_reuse();
	test_software_path();
	test_unclassified();
	test_class_statistics();
	test_red();
	test_queue_budget();
	test_faults();
	test_dispatch();
	test_refusals();
	assert(allocations == 0);
	printf("htb offload: tree, density, limits, reuse, software path, "
	       "statistics, WRED, %d fault points, dispatch passed\n", 24);
	return 0;
}

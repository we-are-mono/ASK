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
typedef int64_t s64;

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
#define DPA_CEETM_IMPLICIT_QUEUES	2
struct sk_buff;
struct qman_fq;
struct dpa_qdisc_ops {
	u16 (*select_queue)(struct net_device *dev, struct sk_buff *skb);
	struct qman_fq *(*txq_fq)(void *qm_ctx, u16 txq, struct sk_buff *skb);
	void (*class_stats)(void *qm_ctx, u64 *data);
};

/* A frame as the port receives it, and as much of the stack's view of it as
 * the queue selection touches: bytes from the Ethernet header on, the socket
 * the gateway's own frames carry, and pkt_type. What the stack attached on the
 * way -- a conntrack, an ingress index -- is deliberately absent: scrubs take
 * it, so nothing in the Tx path may depend on it, and the adapter's
 * classifier below stands in for the conntrack lookup that finds the
 * connection again. */
#define ETH_HLEN	14
#define VLAN_HLEN	4
#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806
#define ETH_P_8021Q	0x8100
#define ETH_P_8021AD	0x88A8
#define ETH_P_IPV6	0x86DD
#define ETH_P_PPP_DISC	0x8863
#define ETH_P_PPP_SES	0x8864
#define PPP_IP		0x21
#define PPP_IPV6	0x57
#define PPP_LCP		0xc021
#define PPPOE_SES_HLEN	8
#define PACKET_HOST	0
#define PACKET_OTHERHOST	3
#define AF_INET		2
#define AF_INET6	10
#define IPPROTO_ICMP	1
#define IPPROTO_IGMP	2
#define IPPROTO_IPIP	4
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17
#define IPPROTO_IPV6	41
#define IPPROTO_ICMPV6	58
#define IP_OFFSET	0x1FFF
#define IP_MF		0x2000
#define IP6_MF		0x0001
#define ICMPV6_ECHO_REQUEST	128
#define ICMPV6_MGM_QUERY	130
#define ICMPV6_MGM_REPORT	131
#define ICMPV6_MGM_REDUCTION	132
#define ICMPV6_MLD2_REPORT	143
#define NDISC_ROUTER_SOLICITATION	133
#define NDISC_ROUTER_ADVERTISEMENT	134
#define NDISC_NEIGHBOUR_SOLICITATION	135
#define NDISC_NEIGHBOUR_ADVERTISEMENT	136
#define NDISC_REDIRECT		137
#define INET_ECN_MASK	3
#define NSEC_PER_SEC	1000000000LL
/* A macro rather than a function, because the production switch uses it in
 * case labels, where the kernel's own htons() is equally constant-foldable. */
#define htons(v)	((u16)((((u16)(v)) >> 8) | (((u16)(v)) << 8)))
#define ntohs(v)	htons(v)
#define __force
#define min_t(t, a, b)	((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max(a, b)	((a) > (b) ? (a) : (b))
static u64 div64_u64(u64 a, u64 b) { return a / b; }
static u32 ntohl(u32 v) { return __builtin_bswap32(v); }
static bool ipv4_is_multicast(u32 addr) { return (ntohl(addr) & 0xf0000000) == 0xe0000000; }
static bool ipv4_is_lbcast(u32 addr) { return addr == 0xffffffff; }
typedef u8 __u8;
typedef u32 __u32;
typedef u16 __be16;
typedef u32 __be32;
typedef u16 __sum16;
static bool eth_type_vlan(__be16 type)
{ return type == htons(ETH_P_8021Q) || type == htons(ETH_P_8021AD); }
/* The real headers, and the kernel's own dsfield helpers (dsfield.inc), so a
 * rewrite is checked against the bytes and the checksum a wire would see. */
struct iphdr {
	u8 ihl:4, version:4;
	u8 tos;
	__be16 tot_len, id, frag_off;
	u8 ttl, protocol;
	__sum16 check;
	u32 saddr, daddr;
};
struct in6_addr { u8 s6_addr[16]; };
struct ipv6hdr {
	u8 priority:4, version:4;
	u8 flow_lbl[3];
	__be16 payload_len;
	u8 nexthdr, hop_limit;
	struct in6_addr saddr, daddr;
};
struct pppoe_hdr { u8 type_ver, code; __be16 sid, length; };
struct udphdr { __be16 source, dest, len, check; };
struct ipv6_opt_hdr { u8 nexthdr, hdrlen; };
struct frag_hdr { u8 nexthdr, reserved; __be16 frag_off; u32 identification; };
#include "dsfield.inc"
struct sock;
struct sk_buff {
	u8 *data;
	unsigned int len;
	struct sock *sk;	/* the gateway's own frames carry their socket */
	int skb_iif;		/* where a received frame came in; a scrub clears it */
	u8 pkt_type;
	/* A head shared with a clone cannot be written until it is copied,
	 * and here the copy fails. */
	bool unwritable;
	u8 head[160];
};
static void *skb_header_pointer(const struct sk_buff *skb, int offset, int len, void *buffer)
{
	if (offset < 0 || len < 0 || (unsigned)offset + (unsigned)len > skb->len)
		return NULL;
	memcpy(buffer, skb->data + offset, len);
	return buffer;
}
static int skb_ensure_writable(struct sk_buff *skb, unsigned int len)
{
	assert(len <= skb->len);
	return skb->unwritable ? -ENOMEM : 0;
}
/* The kernel's own test for an IPv6 extension header (exthdrs.inc). */
#include "exthdrs.inc"
typedef struct { long long counter; } atomic64_t;
#define ATOMIC64_INIT(v)	{ (v) }
static void atomic64_inc(atomic64_t *v) { v->counter++; }
static long long atomic64_read(const atomic64_t *v) { return v->counter; }
static bool atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
{
	if (v->counter != *old) {
		*old = v->counter;
		return false;
	}
	v->counter = new;
	return true;
}
struct qman_fq { unsigned channel, quenum; };
/* netpoll sends with interrupts off, which the tests say. */
static bool irqs_off;
static bool irqs_disabled(void) { return irqs_off; }
/* One CPU, whose per-CPU cache is only ever touched with interrupts off. */
static int irq_depth;
#define DEFINE_PER_CPU(type, name)	type name
#define local_irq_save(flags)		((flags) = (unsigned long)irq_depth++)
#define local_irq_restore(flags)	do { (void)(flags); assert(irq_depth > 0); irq_depth--; } while (0)
#define this_cpu_ptr(p)			(assert(irq_depth > 0), (p))
/* The clock the control budget runs on, which the tests move. */
static s64 now_ns = 1000000000;
static u64 ktime_get_mono_fast_ns(void) { return (u64)now_ns; }

/* The DSCP filters, which own what a codepoint means. Their own validation is
 * tools/host_tests/dscp_map.c; here all that matters is that a frame naming no
 * class reaches them and lands on the class they answer with. */
static u16 dscp_classes[64];
static u16 cdx_dscp_class(struct tQM_context_ctl *qm_ctx, u8 dscp)
{
	/* A port no tc command has touched yet has no context recorded, and
	 * no filter either: the production lookup answers zero for it. */
	if (!qm_ctx)
		return 0;
	return dscp < 64 ? dscp_classes[dscp] : 0;
}
/* RCU read-side depth. A hook called on the transmit path takes its own
 * section around the pointer and the call; a grace period cannot be waited
 * for from inside one. */
static int rcu_depth;
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth > 0); rcu_depth--; }
static unsigned net_syncs;
static void synchronize_net(void) { assert(!rcu_depth); net_syncs++; }

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
/* As cdx_flowtable.h declares it: the class of the connection the IP header
 * at nhoff belongs to. The class is nineteen bits wide, the remark flag and its
 * codepoint above the sixteen a narrower type would keep. */
typedef bool (*cdx_ft_qos_class_fn)(const struct sk_buff *skb, unsigned int nhoff,
				    u8 family, bool own, u32 *class);
static cdx_ft_qos_class_fn cdx_ft_qos_class_func;
static bool cdx_ft_qos_remarks;
/* File-scope in the production file, so declared here. */
static atomic64_t cdx_htb_remark_failures = ATOMIC64_INIT(0);
static atomic64_t cdx_htb_control_overruns = ATOMIC64_INIT(0);

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
	cdx_ft_qos_remarks = false;
	memset(&cdx_htb_datagrams, 0, sizeof(cdx_htb_datagrams));
	irqs_off = false;
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
	/* Inside the section its unregister waits for: a bind racing the
	 * adapter's unload must finish before the adapter's text goes. */
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
	/* The adapter's unregister waits out the binds already inside its
	 * handler, so its text can go once it returns. */
	srcu_syncs = 0;
	cdx_unregister_ft_setup_tc();
	assert(cdx_ft_handler_srcu.syncs == 1 && srcu_syncs == 1);
	assert(cdx_setup_tc(&devices[0], TC_SETUP_FT, &block) == -EOPNOTSUPP);
	assert(!cdx_ft_handler_srcu.readers && ft_calls == 1);

	/* Unloading gives the ndo up before anything it reaches goes away, and
	 * drops the bookkeeping for a qdisc that outlived its module. */
	cdx_htb_exit();
	assert(!registered_ndo);
	assert(!cdx_htb_ports[3].live);
	assert(allocations == 0);
}

/* ---- frames ---------------------------------------------------------- */

/* RFC 1071, for an oracle independent of the incremental update being checked:
 * a header whose checksum is right sums to zero. */
static u16 fold_sum(const u8 *p, unsigned len)
{
	u32 sum = 0;

	for (unsigned i = 0; i < len; i += 2)
		sum += (u32)p[i] << 8 | p[i + 1];
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (u16)~sum;
}

static void put16(u8 *at, u16 value) { at[0] = value >> 8; at[1] = value & 0xff; }

/* What a test frame is made of. Every field left zero means the plain case:
 * an untagged Ethernet frame carrying IPv4 UDP. */
struct frame {
	u16 tags[CDX_HTB_MAX_TAGS + 1];	/* outermost first, as TPIDs */
	unsigned ntags;
	bool pppoe;			/* a PPPoE session header */
	u16 ppp;			/* its PPP protocol, when not IP */
	u16 ethertype;			/* a frame that is not IP at all */
	u8 family;			/* AF_INET by default */
	u8 tos;
	u8 proto;			/* UDP by default */
	u16 dport;
	u8 icmp6;			/* the ICMPv6 type, for proto ICMPv6 */
	/* The destination: 0 off the link, 1 a multicast group (the limited
	 * broadcast for DHCP), 2 IPv6 link-local. */
	unsigned scope;
	/* A fragment: the first of its datagram, or a later one, which
	 * carries no transport header; the datagram's identification. */
	bool first_fragment, later_fragment, last_fragment;
	u16 id;
	bool hop_by_hop;		/* IPv6: an extension header first */
	u8 inner_family;		/* the IP header an IP-in-IP frame carries */
	u8 inner_tos;
	unsigned truncate;		/* bytes to cut off the end */
};

/* An IP header at `at', and the length of it with any extension headers.
 * `fragment' is 0 for a whole datagram, 1 for its first fragment, 2 for a
 * later one and 3 for the last. `scope' as struct frame has it. */
static unsigned put_ip(u8 *at, u8 family, u8 tos, u8 proto, unsigned fragment,
		       u16 id, bool hop_by_hop, unsigned scope)
{
	unsigned len = 40;

	if (family == AF_INET6) {
		at[0] = 0x60 | tos >> 4;
		/* Traffic class low nibble, then a flow label that has to
		 * survive a rewrite. */
		at[1] = (u8)(tos << 4) | 0x0a;
		at[2] = 0xbc;
		at[3] = 0xde;
		put16(at + 4, 64);
		at[7] = 63;
		memcpy(at + 8, "\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 16);
		memcpy(at + 24, scope == 1 ? "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x01" :
				scope == 2 ? "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" :
				"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16);
		u8 *next = at + 6;
		if (hop_by_hop) {
			*next = 0;
			next = at + len;
			at[len + 1] = 0;
			len += 8;
		}
		if (fragment) {
			*next = 44;
			next = at + len;
			put16(at + len + 2, fragment == 1 ? IP6_MF :
					    fragment == 2 ? 185 << 3 | IP6_MF : 370 << 3);
			put16(at + len + 6, id);
			len += 8;
		}
		*next = proto;
		return len;
	}
	at[0] = 0x45;
	at[1] = tos;
	put16(at + 2, 60);
	put16(at + 4, id);
	if (fragment)
		put16(at + 6, fragment == 1 ? IP_MF : fragment == 2 ? 185 | IP_MF : 370);
	at[8] = 63;
	at[9] = proto;
	memcpy(at + 12, "\xc0\xa8\x01\x01", 4);
	memcpy(at + 16, !scope ? "\x0a\x00\x00\xe8" : proto == IPPROTO_UDP ? "\xff\xff\xff\xff" :
			"\xe0\x00\x00\x16", 4);
	put16(at + 10, fold_sum(at, 20));
	return 20;
}

/* Build `f' into `skb', and return where its own IP header starts, or 0. */
static unsigned build(struct sk_buff *skb, const struct frame *f)
{
	u8 family = f->family ?: AF_INET;
	u8 proto = f->proto ?: IPPROTO_UDP;
	unsigned off = 12, nh, thoff;

	memset(skb, 0, sizeof(*skb));
	skb->data = skb->head;
	memcpy(skb->head, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02", 12);
	for (unsigned i = 0; i < f->ntags; i++, off += VLAN_HLEN) {
		put16(skb->head + off, f->tags[i]);
		put16(skb->head + off + 2, 100 + i);
	}
	if (f->ethertype) {
		put16(skb->head + off, f->ethertype);
		skb->len = off + 2 + 46 - f->truncate;
		return 0;
	}
	if (f->pppoe) {
		put16(skb->head + off, ETH_P_PPP_SES);
		off += 2;
		skb->head[off] = 0x11;
		put16(skb->head + off + 2, 0x1234);
		put16(skb->head + off + 6, f->ppp ? f->ppp :
		      family == AF_INET6 ? PPP_IPV6 : PPP_IP);
		nh = off + PPPOE_SES_HLEN;
		if (f->ppp) {
			skb->len = nh + 40 - f->truncate;
			return 0;
		}
	} else {
		put16(skb->head + off, family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP);
		nh = off + 2;
	}
	if (f->inner_family)
		proto = f->inner_family == AF_INET ? IPPROTO_IPIP : IPPROTO_IPV6;
	thoff = nh + put_ip(skb->head + nh, family, f->tos, proto,
			    f->last_fragment ? 3 : f->later_fragment ? 2 :
			    f->first_fragment ? 1 : 0, f->id, f->hop_by_hop, f->scope);
	if (f->inner_family)
		thoff += put_ip(skb->head + thoff, f->inner_family, f->inner_tos,
				IPPROTO_UDP, 0, 0, false, 0);
	if (proto == IPPROTO_ICMPV6 && !f->later_fragment && !f->last_fragment) {
		skb->head[thoff] = f->icmp6 ? f->icmp6 : ICMPV6_ECHO_REQUEST;
	} else {
		put16(skb->head + thoff, 5000);
		put16(skb->head + thoff + 2, f->dport ? f->dport : 5001);
	}
	skb->len = thoff + 8 + 32 - f->truncate;
	assert(skb->len <= sizeof(skb->head));
	return nh;
}

static u8 dsfield_at(struct sk_buff *skb, unsigned at)
{
	return skb->data[at] >> 4 == 6 ? ipv6_get_dsfield((struct ipv6hdr *)(skb->data + at)) :
					  ipv4_get_dsfield((struct iphdr *)(skb->data + at));
}
static bool ipv4_sum_ok(struct sk_buff *skb, unsigned at)
{ return fold_sum(skb->data + at, sizeof(struct iphdr)) == 0; }

/* ---- the adapter's classifier ----------------------------------------- */

/* What the connection of the frame's own header, and of the header an IP-in-IP
 * frame carries, would be found as: known with a class, or not known. The
 * classifier checks what it is handed -- a header of the family it is told,
 * at the offset it is told, inside a read-side section the caller took -- and
 * records it. A family of zero is a frame whose network header was not found,
 * which only the conntrack an skb carries can answer for. */
static struct conn { bool known; u32 class; } own_conn, inner_conn;
static unsigned own_asked, inner_asked, last_nhoff;
static u8 last_family;
static bool test_classify(const struct sk_buff *skb, unsigned int nhoff, u8 family,
			  bool own, u32 *class)
{
	const struct conn *conn = own ? &own_conn : &inner_conn;

	assert(rcu_depth == 1);
	if (family)
		assert(nhoff < skb->len &&
		       skb->data[nhoff] >> 4 == (family == AF_INET ? 4 : 6));
	else
		assert(own);
	own ? own_asked++ : inner_asked++;
	last_nhoff = nhoff;
	last_family = family;
	if (!conn->known)
		return false;
	*class = conn->class;
	return true;
}

static void connections(struct conn own, struct conn inner)
{
	own_conn = own;
	inner_conn = inner;
	own_asked = inner_asked = 0;
}
#define KNOWN(c)	((struct conn){ true, (c) })
#define UNKNOWN		((struct conn){ false, 0 })

/* Queue selection for a frame built from `f', its connection known with
 * `class'. */
static u16 pick_frame(struct net_device *dev, const struct frame *f, u32 class)
{
	struct sk_buff skb;

	build(&skb, f);
	connections(KNOWN(class), UNKNOWN);
	return cdx_htb_select_queue(dev, &skb);
}
static u16 pick(struct net_device *dev, u32 class)
{
	return pick_frame(dev, &(struct frame){ 0 }, class);
}

/* The software path has to reach the class the hardware path would have put
 * the same flow on, and reach it from the queue index rather than by decoding
 * the mark a second time. */
static void test_software_path(void)
{
	struct net_device *dev = &devices[0];
	struct sk_buff skb;
	u16 qid1, qid2, qid10, qid11, moved;

	reset_world();
	assert(!cdx_register_ft_qos_class(test_classify, true));
	assert(cdx_register_ft_qos_class(test_classify, true) == -EBUSY);
	assert(!create(dev, 1, 0));

	/* Two channels, so the channel nibble has something to choose between. */
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!add_leaf(dev, 2, 0, 0, 0, 1000, 1000, &qid2));
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid10));
	assert(!add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid11));
	/* Each leaf's queue is usable, which is the count the stack caps to. */
	assert(dev->real_num_tx_queues == DPAA_ETH_TX_QUEUES + 3);

	/* Channel 1 is the first channel, class queue 7 is prio 0: the class
	 * 0x70 | 0x0 that named 1:10 in hardware picks 1:10's Tx queue here.
	 * The class's channel nibble is one-based, as ceetm_get_egressfq()
	 * numbers them. */
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == qid10);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 2)) == qid11);
	/* The classifier was asked about the frame's own IPv4 header. */
	assert(own_asked == 1 && !inner_asked && last_nhoff == ETH_HLEN && last_family == AF_INET);
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
	/* A frame whose connection is not known has no class to read, and no
	 * DSCP filter claims one either. */
	build(&skb, &(struct frame){ 0 });
	connections(UNKNOWN, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);

	/* However the frame is framed, the class of its connection reaches the
	 * same leaf: behind a VLAN tag or two, in a PPPoE session, with an IPv6
	 * extension header first. Each time the classifier is handed the IP
	 * header where it really starts. */
	const u32 ef_class = (1 << 4) | (NUM_PQS - 1);
	assert(pick_frame(dev, &(struct frame){ .ntags = 1, .tags = { ETH_P_8021Q } },
			  ef_class) == qid10 && last_nhoff == ETH_HLEN + VLAN_HLEN);
	assert(pick_frame(dev, &(struct frame){ .ntags = 2,
						.tags = { ETH_P_8021AD, ETH_P_8021Q } },
			  ef_class) == qid10 && last_nhoff == ETH_HLEN + 2 * VLAN_HLEN);
	assert(pick_frame(dev, &(struct frame){ .pppoe = true }, ef_class) == qid10 &&
	       last_nhoff == ETH_HLEN + PPPOE_SES_HLEN && last_family == AF_INET);
	assert(pick_frame(dev, &(struct frame){ .ntags = 1, .tags = { ETH_P_8021Q },
						.pppoe = true, .family = AF_INET6 },
			  ef_class) == qid10 &&
	       last_nhoff == ETH_HLEN + VLAN_HLEN + PPPOE_SES_HLEN && last_family == AF_INET6);
	/* Behind more tags than a port can carry the IP header is not read, so
	 * the classifier is handed none: only a conntrack the skb still
	 * carries can answer, and here it does. */
	assert(pick_frame(dev, &(struct frame){ .ntags = 3,
						.tags = { ETH_P_8021AD, ETH_P_8021Q, ETH_P_8021Q } },
			  ef_class) == qid10 && !last_family);

	/* ---- the DSCP map answers for frames that named no class ---- */

	memset(dscp_classes, 0, sizeof(dscp_classes));
	/* EF on channel 1, class queue 7 -- 1:10's pair, in the encoding the
	 * published class map is indexed by. */
	dscp_classes[46] = (1 << 4) | (NUM_PQS - 1);
	connections(UNKNOWN, UNKNOWN);
	build(&skb, &(struct frame){ .tos = 46 << 2 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	/* Including over IPv6, where the same six bits sit in a different
	 * header, and behind a tag or a session header, which the map used to
	 * miss because it read only the frame's own protocol. */
	build(&skb, &(struct frame){ .family = AF_INET6, .tos = 46 << 2 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .pppoe = true, .tos = 46 << 2 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .ntags = 1, .tags = { ETH_P_8021Q },
				     .family = AF_INET6, .tos = 46 << 2 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	/* Inside an IP-in-IP frame, the carried packet's codepoint: the one its
	 * sender set, whatever the tunnel wrote outside. */
	build(&skb, &(struct frame){ .inner_family = AF_INET6, .inner_tos = 46 << 2 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .tos = 46 << 2, .inner_family = AF_INET6 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	/* A codepoint nobody claimed leaves the stack's own choice alone. */
	build(&skb, &(struct frame){ .tos = 0 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	/* So does a frame that is not IP at all, one whose header is cut
	 * short, and a PPP frame that is not IP. */
	build(&skb, &(struct frame){ .ethertype = ETH_P_ARP });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	build(&skb, &(struct frame){ .tos = 46 << 2 });
	skb.len = ETH_HLEN + 12;
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	build(&skb, &(struct frame){ .pppoe = true, .ppp = PPP_LCP });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);

	/* A frame that *did* name a class keeps it: the mark outranks the map,
	 * which is the precedence the hardware applies to the same frame. */
	build(&skb, &(struct frame){ .tos = 46 << 2 });
	connections(KNOWN((2 << 4) | (NUM_PQS - 1)), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid2);
	/* And a connection whose mark names nothing still gets the map's
	 * answer, rather than falling through to the stack's choice. */
	connections(KNOWN(0), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);

	/* A class the map names but no leaf holds is not a queue. */
	dscp_classes[46] = 0x03;
	connections(UNKNOWN, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	/* Nor is one past the table the class map is sized for. */
	dscp_classes[46] = CDX_HTB_CLASSES + 1;
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	memset(dscp_classes, 0, sizeof(dscp_classes));

	/* And the Tx path resolves the pair back out of the queue index. */
	struct sk_buff data_frame;
	build(&data_frame, &(struct frame){ 0 });
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid10, &data_frame) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid11, &data_frame) == &class_fqs[0][NUM_PQS - 2]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid2, &data_frame) == &class_fqs[1][NUM_PQS - 1]);
	/* An ordinary queue, or a slot no class holds, carries a frame that
	 * named no leaf -- and on a port with a tree that frame is the tree's
	 * to place too, never the driver's mark-based guess: class queue 0 of
	 * the top channel, where the hardware puts a flow with no class. */
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &data_frame) == &class_fqs[1][0]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES + 3, &data_frame) ==
	       &class_fqs[1][0]);
	assert(!cdx_htb_txq_fq(NULL, qid10, &data_frame));

	/* Deleting a leaf that is not the last one takes its class off the map,
	 * and the leaf that moved into the hole answers for the hole -- with
	 * the channel and class queue it already had, because only the Tx queue
	 * index moved. */
	assert(!del_leaf(dev, 2, &moved));
	assert(moved == 11);
	assert(pick(dev, (2 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 2)) == qid2);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid2, &data_frame) == &class_fqs[0][NUM_PQS - 2]);
	/* Channel 2 stays claimed for the next class under the root, but no
	 * class holds it and it runs unshaped, so it is no longer the top
	 * channel: frames on a queue no class holds take the first channel's
	 * class queue 0, and the class that names "whichever channel this port
	 * owns" means the first channel -- where 1:10 holds queue 7. */
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, qid11, &data_frame) == &class_fqs[0][0]);
	assert(pick(dev, NUM_PQS - 1) == qid10);

	assert(!destroy(dev));
	assert(dev->real_num_tx_queues == DPAA_ETH_TX_QUEUES);
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	/* No tree, no opinion: the driver's own resolution is back. */
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, DPAA_ETH_TX_QUEUES, &data_frame));
	assert(!cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &data_frame));
	assert_balanced(dev);

	/* With no classifier registered no class is decoded, and no frame is
	 * put on a leaf's queue. The tree still owns the port, though, so every
	 * frame still lands on one of its queues rather than wherever the
	 * driver's mark field would have sent it. */
	net_syncs = 0;
	cdx_unregister_ft_qos_class();
	assert(net_syncs == 1 && !rcu_depth);
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == DPA_SELECT_QUEUE_NONE);
	assert(!own_asked && !rcu_depth);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &data_frame) == &class_fqs[0][0]);
	build(&skb, &(struct frame){ .ethertype = ETH_P_ARP });
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &skb) == &class_fqs[0][NUM_PQS - 1]);
	assert(!destroy(dev));
	assert_balanced(dev);
}

/* A frame for the port, and the queue the Tx path puts it on when it names no
 * leaf: selected, then resolved from the direct queue if it is left there. */
static struct qman_fq *queue_of(struct net_device *dev, struct sk_buff *skb)
{
	u16 qid = cdx_htb_select_queue(dev, skb);

	return cdx_htb_txq_fq(dev->priv.qm_ctx, qid == DPA_SELECT_QUEUE_NONE ? 3 : qid, skb);
}

/* Traffic that names no leaf, on a port whose tree is live.
 *
 * It used to go wherever the driver's mark field said: class queue 7 for every
 * frame with no mark, a queue no leaf configured and eligible only for excess
 * tokens, so one saturated leaf starved the gateway's own frames. Then it was
 * split on whether the frame still had its conntrack and ingress index, which a
 * PPPoE session or a tunnel scrubs, so every frame the CPU sent into a session
 * rode the top of the tree. Now the split is on what the frame is: anything
 * whose connection names no class is unclassified -- class queue 0, or the
 * default leaf -- wherever it came from; link traffic and the gateway's own
 * are control -- class queue 7, never the default leaf, and inside a budget. */
static void test_unclassified(void)
{
	struct net_device *dev = &devices[0];
	struct tQM_context_ctl *ctx = dev->priv.qm_ctx;
	struct sock *owner = (struct sock *)&own_conn;
	struct sk_buff skb;
	u16 qid1, qid10, qid20, qid17, qid2;
	u32 channel, cq;

	/* ---- no default: control on queue 7, unclassified on queue 0 ---- */
	reset_world();
	assert(!cdx_register_ft_qos_class(test_classify, true));
	channel = 0; cq = 0;
	assert(!cdx_htb_resolve_class(ctx, &channel, &cq));	/* no tree yet */
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000000, 1000000, &qid1));
	assert(!to_inner(dev, 10, 1, 1, 0));			/* prio 1: queue 6 */
	assert(!query(dev, 10, &qid10));
	/* Both queues those frames take are eligible for the channel's
	 * committed rate, configured as a leaf's would be. */
	assert(cq_live[0][0] && cq_weight[0][0] == 0);
	assert(cq_live[0][NUM_PQS - 1] && cq_weight[0][NUM_PQS - 1] == 0);

	/* Unclassified, whatever the stack did or did not attach on the way: a
	 * forwarded frame with no class, one naming a class no leaf holds, a
	 * frame bridged without conntrack, one untracked on purpose. */
	struct conn stray = KNOWN((1 << 4) | 3);
	build(&skb, &(struct frame){ 0 });
	connections(KNOWN(0), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	connections(stray, UNKNOWN);
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	connections(UNKNOWN, UNKNOWN);
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	skb.pkt_type = PACKET_OTHERHOST;
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	/* A frame for a PPPoE session reaches the port with no conntrack and
	 * no ingress -- ppp_start_xmit() scrubbed both -- and is unclassified
	 * too, not control: it used to take the top of the tree. */
	build(&skb, &(struct frame){ .ntags = 1, .tags = { ETH_P_8021Q }, .pppoe = true });
	connections(UNKNOWN, UNKNOWN);
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	/* And its connection, found again from its tuple, picks its leaf. */
	connections(KNOWN((1 << 4) | (NUM_PQS - 2)), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	assert(last_nhoff == ETH_HLEN + VLAN_HLEN + PPPOE_SES_HLEN);

	/* An IP-in-IP frame takes the class of the connection it carries,
	 * which is what the hardware entry of the offloaded flow carries; the
	 * tunnel's own conntrack only when the carried one is not known. */
	build(&skb, &(struct frame){ .inner_family = AF_INET6 });
	connections(KNOWN((1 << 4) | 3), KNOWN((1 << 4) | (NUM_PQS - 2)));
	assert(cdx_htb_select_queue(dev, &skb) == qid10 && inner_asked == 1 && !own_asked);
	assert(last_nhoff == ETH_HLEN + 20 && last_family == AF_INET6);
	connections(KNOWN((1 << 4) | (NUM_PQS - 2)), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10 && inner_asked == 1 && own_asked == 1);
	connections(UNKNOWN, UNKNOWN);
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	build(&skb, &(struct frame){ .family = AF_INET6, .inner_family = AF_INET });
	connections(UNKNOWN, KNOWN((1 << 4) | (NUM_PQS - 2)));
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	assert(last_nhoff == ETH_HLEN + 40 && last_family == AF_INET);

	/* Link protocols the gateway originates -- no socket and no ingress,
	 * as ARP, LCP and IGMP leave it, and in IP addressed on the link --
	 * are control, and take queue 7. */
	const struct frame link[] = {
		{ .ethertype = ETH_P_ARP },
		{ .ethertype = ETH_P_PPP_DISC },
		{ .pppoe = true, .ppp = PPP_LCP },
		{ .ntags = 1, .tags = { ETH_P_8021Q }, .ethertype = ETH_P_ARP },
		{ .proto = IPPROTO_IGMP, .scope = 1 },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6, .icmp6 = NDISC_NEIGHBOUR_SOLICITATION,
		  .scope = 1 },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6, .icmp6 = NDISC_ROUTER_ADVERTISEMENT,
		  .hop_by_hop = true, .scope = 1 },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6, .icmp6 = ICMPV6_MLD2_REPORT,
		  .hop_by_hop = true, .scope = 1 },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6,
		  .icmp6 = NDISC_NEIGHBOUR_ADVERTISEMENT, .scope = 2 },
		{ .dport = 67, .scope = 1 }, { .dport = 68, .scope = 1 },
		{ .family = AF_INET6, .dport = 546, .scope = 2 },
		{ .family = AF_INET6, .dport = 547, .scope = 1 },
		{ .ethertype = 0x88cc },			/* LLDP */
	};
	for (unsigned i = 0; i < ARRAY_SIZE(link); i++) {
		bool ip = !link[i].ethertype && !link[i].ppp;
		struct frame off_link = link[i];

		build(&skb, &link[i]);
		connections(UNKNOWN, UNKNOWN);
		assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
		assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
		/* So is one the bridge forwards between ports, received on one
		 * and addressed to another host. */
		skb.skb_iif = 4;
		skb.pkt_type = PACKET_OTHERHOST;
		assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
		/* One routing forwarded is traffic, on its flow's queue: a
		 * link protocol is never routed but DHCP, and a unicast DHCP
		 * flow can be offloaded like any other. Not IP, it cannot have
		 * been routed at all. */
		skb.pkt_type = PACKET_HOST;
		assert(queue_of(dev, &skb) == &class_fqs[0][ip ? 0 : NUM_PQS - 1]);
		if (!ip)
			continue;
		/* Nor is one shaped like a link protocol and addressed off the
		 * link, that reached the port with its ingress scrubbed -- a
		 * host routing it into a PPPoE session. It would otherwise
		 * spend the reserve the gateway's own link traffic has. */
		off_link.scope = 0;
		build(&skb, &off_link);
		assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
		assert(queue_of(dev, &skb) == &class_fqs[0][0]);
		off_link.pppoe = true;
		build(&skb, &off_link);
		assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	}
	/* The gateway's own frames of every other kind, by their socket --
	 * its ICMP echoes and errors, its sessions -- and whatever netpoll
	 * sends with interrupts off. */
	const struct frame own[] = {
		{ .proto = IPPROTO_UDP },
		{ .proto = IPPROTO_ICMP },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6 },
		{ .pppoe = true, .proto = IPPROTO_ICMP },
		{ .proto = IPPROTO_TCP },
	};
	for (unsigned i = 0; i < ARRAY_SIZE(own); i++) {
		build(&skb, &own[i]);
		connections(UNKNOWN, UNKNOWN);
		skb.sk = owner;
		assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
		assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
		skb.sk = NULL;
		irqs_off = true;
		assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
		irqs_off = false;
	}
	/* Not control: ICMP a host sent through the gateway, however it was
	 * framed; a protocol number or a DHCP port in the wrong family; and a
	 * fragment whose transport header is not in it -- nothing says what it
	 * carries. */
	const struct frame data[] = {
		{ .proto = IPPROTO_ICMP },
		{ .pppoe = true, .proto = IPPROTO_ICMP },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6 },
		{ .family = AF_INET6, .proto = IPPROTO_ICMP },
		{ .proto = IPPROTO_ICMPV6 },
		{ .proto = IPPROTO_IGMP, .family = AF_INET6 },
		{ .family = AF_INET6, .dport = 67 },
		{ .dport = 547 },
		{ .dport = 67, .later_fragment = true },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6,
		  .icmp6 = NDISC_NEIGHBOUR_SOLICITATION, .later_fragment = true },
		{ .family = AF_INET6, .proto = IPPROTO_ICMPV6, .hop_by_hop = true,
		  .later_fragment = true },
	};
	for (unsigned i = 0; i < ARRAY_SIZE(data); i++) {
		build(&skb, &data[i]);
		connections(UNKNOWN, UNKNOWN);
		assert(queue_of(dev, &skb) == &class_fqs[0][0]);
		skb.skb_iif = 4;
		assert(queue_of(dev, &skb) == &class_fqs[0][0]);
		skb.pkt_type = PACKET_OTHERHOST;
		assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	}
	/* A control frame whose connection does name a leaf takes it. */
	build(&skb, &(struct frame){ .proto = IPPROTO_ICMP });
	connections(KNOWN((1 << 4) | (NUM_PQS - 2)), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);

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
	 * own Tx queue. Control stays on the control queue. */
	assert(!add_leaf(dev, 17, 1, 7, 0, 0, 0, &qid17));
	build(&skb, &(struct frame){ 0 });
	connections(KNOWN(0), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid17);
	connections(stray, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid17);
	skb.sk = owner;
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	/* It is the leaf's queue now, and deleting the leaf gives it back to
	 * the unclassified: reset, then eligible again. */
	assert(!del_leaf(dev, 17, NULL));
	skb.sk = NULL;
	assert(cq_live[0][0] && cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	/* A prio 0 leaf shares the control queue rather than displacing it. */
	assert(!add_leaf(dev, 11, 1, 0, 0, 0, 0, NULL));
	build(&skb, &(struct frame){ .ethertype = ETH_P_ARP });
	assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
	assert(!del_leaf(dev, 11, NULL));
	assert(cq_live[0][NUM_PQS - 1]);

	/* A class under the root on a higher channel moves the top channel, and
	 * the eligible queues move with it; the ones left behind are reset. */
	assert(!add_leaf(dev, 2, 0, 3, 0, 1000000, 1000000, &qid2));	/* channel 1 */
	assert(cq_live[1][0] && cq_live[1][NUM_PQS - 1]);
	assert(!cq_live[0][0] && !cq_live[0][NUM_PQS - 1]);
	assert(queue_of(dev, &skb) == &class_fqs[1][NUM_PQS - 1]);
	build(&skb, &(struct frame){ 0 });
	connections(UNKNOWN, UNKNOWN);
	assert(queue_of(dev, &skb) == &class_fqs[1][0]);

	/* Deleting that class leaves its channel claimed and unshaped, and the
	 * top channel goes back to the one a class still holds: frames that
	 * name no leaf stay under a cap. The hardware is told the same channel,
	 * explicitly. */
	assert(!del_leaf(dev, 2, NULL));
	assert(cdx_htb_port_of(dev)->channels == (BIT(0) | BIT(1)));
	assert(chan_cir[1] == 0 && chan_eir[1] == 0);
	assert(cq_live[0][0] && cq_live[0][NUM_PQS - 1]);
	assert(!cq_live[1][0] && !cq_live[1][NUM_PQS - 1]);
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	skb.sk = owner;
	assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
	skb.sk = NULL;
	channel = 0; cq = 0;
	assert(cdx_htb_resolve_class(ctx, &channel, &cq) && channel == 1 && cq == 0);
	/* A class under the root that fails after the claim changes nothing
	 * either: refused outright, or refused after its channel was shaped,
	 * in which case the rate goes back with it. */
	assert(add_leaf(dev, 3, 0, NUM_PQS, 0, 1000, 1000, NULL) == -EINVAL);
	fault_seen = 0;
	fault_point = 1;	/* the class queue, after the channel's rates */
	assert(add_leaf(dev, 3, 0, 2, 0, 5000, 5000, NULL) == -EIO);
	fault_point = -1;
	assert(chan_cir[1] == 0 && chan_eir[1] == 0);
	assert(queue_of(dev, &skb) == &class_fqs[0][0]);
	assert(cq_live[0][0] && cq_live[0][NUM_PQS - 1]);

	/* A leaf that takes one of those queues and then fails to come into
	 * service hands the queue back eligible, not reset and forgotten. The
	 * Tx queue count only fails to grow, so a weighted leaf takes the one
	 * the deleted classes left in service first. */
	assert(!add_leaf(dev, 12, 1, 0, 1, 0, 0, NULL));
	assert(dev->real_num_tx_queues == CDX_HTB_QID_BASE + (unsigned)cdx_htb_port_of(dev)->leaves);
	real_num_tx_queues_fails = 1;
	assert(add_leaf(dev, 11, 1, 0, 0, 0, 0, NULL) == -ENOMEM);
	assert(add_leaf(dev, 17, 1, 7, 0, 0, 0, NULL) == -ENOMEM);
	real_num_tx_queues_fails = 0;
	assert(cq_live[0][0] && cq_live[0][NUM_PQS - 1]);
	assert(cdx_htb_port_of(dev)->implicit == (BIT(0) | BIT(NUM_PQS - 1)));
	assert(!del_leaf(dev, 12, NULL));
	/* And so does one whose class queue the hardware refused. */
	fault_seen = 0;
	fault_point = 0;
	assert(add_leaf(dev, 11, 1, 0, 0, 0, 0, NULL) == -EIO);
	fault_point = -1;
	assert(cq_live[0][NUM_PQS - 1]);
	assert(cdx_htb_port_of(dev)->implicit == (BIT(0) | BIT(NUM_PQS - 1)));
	/* A leaf moved onto one and back off by a failed modify likewise. */
	fault_seen = 0;
	fault_point = 0;
	assert(modify(dev, 10, 7, 0, 0, 0) == -EIO);
	fault_point = -1;
	assert(cq_live[0][0] && cq_live[0][NUM_PQS - 2]);
	assert(cdx_htb_port_of(dev)->implicit == (BIT(0) | BIT(NUM_PQS - 1)));
	assert(!destroy(dev));
	assert_balanced(dev);

	/* ---- a default leaf takes unclassified traffic, never control ---- */
	reset_world();
	assert(!cdx_register_ft_qos_class(test_classify, true));
	assert(!create(dev, 1, 20));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000000, 1000000, &qid1));
	assert(!to_inner(dev, 10, 1, 0, 0));			/* queue 7 */
	assert(!query(dev, 10, &qid10));
	/* Named before the leaf exists, as `tc qdisc add ... default 20' is:
	 * nothing to honour until a leaf by that minor arrives. */
	build(&skb, &(struct frame){ 0 });
	connections(KNOWN(0), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	assert(!add_leaf(dev, 20, 1, 2, 0, 0, 0, &qid20));	/* queue 5 */
	/* Tracked or not, forwarded or bridged, with no class or a class no
	 * leaf holds: the default leaf, from its own Tx queue. */
	assert(cdx_htb_select_queue(dev, &skb) == qid20);
	connections(stray, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid20);
	connections(UNKNOWN, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid20);
	skb.pkt_type = PACKET_OTHERHOST;
	assert(cdx_htb_select_queue(dev, &skb) == qid20);
	/* A class a leaf does hold is still that leaf. */
	assert(pick(dev, (1 << 4) | (NUM_PQS - 1)) == qid10);
	/* Control does not follow it: a default is commonly the lowest class,
	 * and a saturated leaf above it would starve an LCP echo there. It
	 * takes queue 7, which the prio 0 leaf shares. */
	for (unsigned i = 0; i < ARRAY_SIZE(link); i++) {
		build(&skb, &link[i]);
		connections(UNKNOWN, UNKNOWN);
		assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
		assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
	}
	build(&skb, &(struct frame){ 0 });
	skb.sk = owner;
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	assert(queue_of(dev, &skb) == &class_fqs[0][NUM_PQS - 1]);
	/* ICMP a host sent through the gateway is its traffic, and takes the
	 * default leaf with everything else unclassified. */
	build(&skb, &(struct frame){ .proto = IPPROTO_ICMP });
	skb.skb_iif = 4;
	assert(cdx_htb_select_queue(dev, &skb) == qid20);
	build(&skb, &(struct frame){ 0 });
	/* A frame caught on a direct queue anyway goes to the default leaf. */
	skb.sk = NULL;
	assert(cdx_htb_txq_fq(ctx, 3, &skb) == &class_fqs[0][NUM_PQS - 3]);
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
	connections(KNOWN(0), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	assert(!destroy(dev));
	assert_balanced(dev);
	cdx_unregister_ft_qos_class();
	assert(allocations == 0);
}

/* Control traffic's budget: what it may take of the top channel before the
 * rest of it is sent as unclassified traffic. */
static void test_control_budget(void)
{
	struct net_device *dev = &devices[0];
	struct cdx_htb_port *port;
	struct sock *owner = (struct sock *)&own_conn;
	struct sk_buff arp, own;
	unsigned sessions, links;
	u64 overruns;
	u16 qid1;

	reset_world();
	assert(!cdx_register_ft_qos_class(test_classify, true));
	connections(UNKNOWN, UNKNOWN);
	assert(!create(dev, 1, 0));
	port = cdx_htb_port_of(dev);
	/* No tree yet: nothing to budget, and nothing asks. */
	assert(!port->control_rate);
	/* A sixteenth of the top channel's committed rate. */
	assert(!add_leaf(dev, 1, 0, 0, 0, 16000000, 32000000, &qid1));
	assert(port->control_rate == 1000000);
	assert(port->control_tau == (s64)CDX_HTB_CONTROL_BURST * 1000);
	/* And it follows the rate. */
	assert(!modify(dev, 1, 0, 0, 125000000, 125000000));
	assert(port->control_rate == 125000000 / 16);
	/* Never under the floor, unless the channel is slower than twice it. */
	assert(!modify(dev, 1, 0, 0, 64000, 64000));
	assert(port->control_rate == CDX_HTB_CONTROL_FLOOR);
	assert(!modify(dev, 1, 0, 0, 10000, 10000));
	assert(port->control_rate == 5000);
	assert(!modify(dev, 1, 0, 0, 16000000, 32000000));

	/* The gateway's own sessions spend the budget down to one burst ahead
	 * of now; after that their frames go where unclassified traffic goes. */
	build(&own, &(struct frame){ 0 });
	own.sk = owner;
	own.len = 1000;
	overruns = cdx_ft_qos_control_overruns();
	for (sessions = 0;
	     cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &own) == &class_fqs[0][NUM_PQS - 1];
	     sessions++)
		assert(sessions < 100);
	/* A burst of CDX_HTB_CONTROL_BURST bytes, give or take the frame that
	 * crosses it. */
	assert(sessions * 1000 >= CDX_HTB_CONTROL_BURST &&
	       sessions * 1000 <= CDX_HTB_CONTROL_BURST + 1000);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &own) == &class_fqs[0][0]);
	assert(cdx_ft_qos_control_overruns() == overruns + 2);
	/* A host's broadcast the bridge carries between ports is control, but
	 * it spends what the gateway's sessions spend, not the reserve the
	 * gateway's own link traffic has. */
	struct sk_buff bridged;
	build(&bridged, &(struct frame){ .ethertype = ETH_P_ARP });
	bridged.skb_iif = 4;
	bridged.pkt_type = PACKET_OTHERHOST;
	bridged.len = 1000;
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &bridged) == &class_fqs[0][0]);
	/* Link traffic has a second burst of its own beyond that, so the
	 * gateway's sessions cannot push an ARP reply or an LCP echo off the
	 * top of the tree. */
	build(&arp, &(struct frame){ .ethertype = ETH_P_ARP });
	arp.len = 1000;
	for (links = 0;
	     cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &arp) == &class_fqs[0][NUM_PQS - 1];
	     links++)
		assert(links < 100);
	assert(links * 1000 >= CDX_HTB_CONTROL_BURST - 1000 &&
	       links * 1000 <= CDX_HTB_CONTROL_BURST + 1000);
	/* Past both, link traffic too is sent on as unclassified, not dropped:
	 * a flood of it is bounded like anything else. */
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &arp) == &class_fqs[0][0]);
	/* The budget refills at its rate: a millisecond is a thousand bytes at
	 * a megabyte a second, so a session frame fits again once the clock
	 * has moved past both bursts' worth and a frame more. */
	now_ns += (s64)(sessions + links + 1) * 1000 * 1000;
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &own) == &class_fqs[0][NUM_PQS - 1]);
	assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &arp) == &class_fqs[0][NUM_PQS - 1]);
	/* Unclassified traffic never touches the budget. */
	build(&own, &(struct frame){ 0 });
	overruns = cdx_ft_qos_control_overruns();
	for (unsigned i = 0; i < 100; i++)
		assert(cdx_htb_txq_fq(dev->priv.qm_ctx, 0, &own) == &class_fqs[0][0]);
	assert(cdx_ft_qos_control_overruns() == overruns);
	assert(!destroy(dev));
	assert(!port->control_rate);
	assert_balanced(dev);
	cdx_unregister_ft_qos_class();
}

/* A datagram's fragments take one class. Where a scrub left none of them a
 * conntrack, the first finds its connection by its tuple, and the later ones --
 * which carry no transport header, so no tuple -- follow it rather than being
 * sent unclassified behind it, reordered and starved under a saturated class. */
static void test_fragments(void)
{
	struct net_device *dev = &devices[0];
	const u32 class = (1 << 4) | (NUM_PQS - 2);
	const u32 remark = CDX_FT_QOS_REMARK_MASK | 46u << CDX_FT_QOS_DSCP_SHIFT;
	struct sk_buff skb;
	unsigned nh;
	u16 qid1, qid10;

	reset_world();
	assert(!cdx_register_ft_qos_class(test_classify, true));
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!to_inner(dev, 10, 1, 1, 0));
	assert(!query(dev, 10, &qid10));
	for (u8 family = AF_INET; family; family = family == AF_INET ? AF_INET6 : 0) {
		build(&skb, &(struct frame){ .family = family, .pppoe = true,
					     .first_fragment = true, .id = 7 });
		connections(KNOWN(class), UNKNOWN);
		assert(cdx_htb_select_queue(dev, &skb) == qid10);
		build(&skb, &(struct frame){ .family = family, .pppoe = true,
					     .later_fragment = true, .id = 7 });
		connections(UNKNOWN, UNKNOWN);
		assert(cdx_htb_select_queue(dev, &skb) == qid10);
		/* Another datagram's later fragment is not this one's. */
		build(&skb, &(struct frame){ .family = family, .pppoe = true,
					     .later_fragment = true, .id = 8 });
		assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	}
	/* The class was found for the fragment's own header, which every later
	 * fragment repeats, so a remark rewrites each of them. */
	build(&skb, &(struct frame){ .first_fragment = true, .id = 11, .tos = 10 << 2 });
	connections(KNOWN(remark | class), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	nh = build(&skb, &(struct frame){ .later_fragment = true, .id = 11, .tos = 10 << 2 });
	connections(UNKNOWN, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	assert(dsfield_at(&skb, nh) == 46 << 2 && ipv4_sum_ok(&skb, nh));
	/* A tunnel's later fragment follows the class of the connection its
	 * first carried, but holds no carried header to remark, and its own
	 * is the tunnel's. */
	build(&skb, &(struct frame){ .first_fragment = true, .id = 12,
				     .inner_family = AF_INET6, .inner_tos = 10 << 2 });
	connections(UNKNOWN, KNOWN(remark | class));
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	nh = build(&skb, &(struct frame){ .later_fragment = true, .id = 12,
					  .proto = IPPROTO_IPV6, .tos = 10 << 2 });
	connections(UNKNOWN, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	assert(dsfield_at(&skb, nh) == 10 << 2);
	/* The last fragment retires the datagram: a later datagram reusing its
	 * identity -- IPv4 IDs wrap, and after translation every host shares
	 * the source -- does not inherit its class. */
	build(&skb, &(struct frame){ .first_fragment = true, .id = 13 });
	connections(KNOWN(class), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	connections(UNKNOWN, UNKNOWN);
	build(&skb, &(struct frame){ .later_fragment = true, .id = 13 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .last_fragment = true, .id = 13 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .later_fragment = true, .id = 13 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	build(&skb, &(struct frame){ .family = AF_INET6, .first_fragment = true, .id = 14 });
	connections(KNOWN(class), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	connections(UNKNOWN, UNKNOWN);
	build(&skb, &(struct frame){ .family = AF_INET6, .later_fragment = true, .id = 14 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .family = AF_INET6, .last_fragment = true, .id = 14 });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .family = AF_INET6, .later_fragment = true, .id = 14 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	/* A first fragment replaces what an earlier datagram with its identity
	 * left, whether its own connection is known or not. */
	build(&skb, &(struct frame){ .first_fragment = true, .id = 15 });
	connections(KNOWN(class), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	build(&skb, &(struct frame){ .first_fragment = true, .id = 15 });
	connections(UNKNOWN, UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	build(&skb, &(struct frame){ .later_fragment = true, .id = 15 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	/* A handful of datagrams per CPU is remembered, the oldest going
	 * first; fragments leave back to back, so that covers the ones in
	 * flight. */
	for (u16 id = 20; id < 20 + CDX_HTB_DATAGRAMS + 1; id++) {
		build(&skb, &(struct frame){ .first_fragment = true, .id = id });
		connections(KNOWN(class), UNKNOWN);
		assert(cdx_htb_select_queue(dev, &skb) == qid10);
	}
	connections(UNKNOWN, UNKNOWN);
	build(&skb, &(struct frame){ .later_fragment = true, .id = 20 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	build(&skb, &(struct frame){ .later_fragment = true, .id = 20 + CDX_HTB_DATAGRAMS });
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	/* A first fragment of no known connection leaves nothing behind, and
	 * a later fragment that kept its conntrack needs nothing remembered. */
	build(&skb, &(struct frame){ .first_fragment = true, .id = 40 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	build(&skb, &(struct frame){ .later_fragment = true, .id = 40 });
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	build(&skb, &(struct frame){ .later_fragment = true, .id = 41 });
	connections(KNOWN(class), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid10);
	assert(!irq_depth);
	assert(!destroy(dev));
	assert_balanced(dev);
	cdx_unregister_ft_qos_class();
}

/* On a port with no tree a class can only remark, so the port asks the
 * classifier only when some class can carry a remark. */
static void test_treeless_port(void)
{
	struct net_device *dev = &devices[0];
	const u32 ef = CDX_FT_QOS_REMARK_MASK | 46u << CDX_FT_QOS_DSCP_SHIFT;
	struct sk_buff skb;
	unsigned nh;
	u16 qid1;

	reset_world();
	assert(!cdx_register_ft_qos_class(test_classify, false));
	nh = build(&skb, &(struct frame){ .pppoe = true, .tos = 10 << 2 });
	connections(KNOWN(ef), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	assert(!own_asked && dsfield_at(&skb, nh) == 10 << 2);
	/* A tree is something to choose a queue in, so it asks then. */
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	connections(KNOWN(ef), UNKNOWN);
	cdx_htb_select_queue(dev, &skb);
	assert(own_asked == 1);
	assert(!destroy(dev));
	cdx_unregister_ft_qos_class();
	assert(!cdx_ft_qos_remarks);
	/* And with a remark to be had, it asks, and remarks. */
	assert(!cdx_register_ft_qos_class(test_classify, true));
	connections(KNOWN(ef), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == DPA_SELECT_QUEUE_NONE);
	assert(own_asked == 1 && dsfield_at(&skb, nh) == 46 << 2);
	assert_balanced(dev);
	cdx_unregister_ft_qos_class();
}

/* The software path remarks what the hardware remarks.
 *
 * A class carrying a remark makes the hardware rewrite the DSCP of every routed
 * flow it carries. The frames the CPU forwards -- a flow's first, and every one
 * of a flow never offloaded -- used to leave as they arrived, so a flow changed
 * codepoint the moment it was offloaded. Now they are rewritten too, the ECN
 * bits kept and the IPv4 checksum with it, in the header the class belongs to,
 * however the frame is framed -- including a frame for a PPPoE session, which
 * reaches the port with its conntrack scrubbed. The gateway's own frames, a
 * bridged frame, a class with no remark, and anything not IP are left alone. */
static void test_remark(void)
{
	struct net_device *dev = &devices[0];
	const u32 ef = CDX_FT_QOS_REMARK_MASK | 46u << CDX_FT_QOS_DSCP_SHIFT;
	struct sock *owner = (struct sock *)&own_conn;
	struct sk_buff skb;
	u64 failures;
	unsigned nh;
	u16 qid1, qid10, qid11;

	reset_world();
	assert(!cdx_register_ft_qos_class(test_classify, true));

	/* IPv4 at AF11 with ECT(0): EF, ECN kept, a checksum that verifies. */
	nh = build(&skb, &(struct frame){ .tos = 10 << 2 | 2 });
	connections(KNOWN(ef), UNKNOWN);
	assert(ipv4_sum_ok(&skb, nh));
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == (46 << 2 | 2) && ipv4_sum_ok(&skb, nh));
	/* IPv6 at AF11 with ECT(1): the traffic class rewritten, ECN, version
	 * and flow label kept. */
	nh = build(&skb, &(struct frame){ .family = AF_INET6, .tos = 10 << 2 | 1 });
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == (46 << 2 | 1));
	assert(skb.data[nh] >> 4 == 6 && (skb.data[nh + 1] & 0x0f) == 0x0a);
	assert(skb.data[nh + 2] == 0xbc && skb.data[nh + 3] == 0xde);
	/* Inside a PPPoE session over a tag, which is how a frame for one
	 * reaches the port: the IP header, and the headers before it
	 * untouched. */
	struct frame session = { .ntags = 1, .tags = { ETH_P_8021Q }, .pppoe = true };
	nh = build(&skb, &session);
	cdx_htb_select_queue(dev, &skb);
	assert(nh == ETH_HLEN + VLAN_HLEN + PPPOE_SES_HLEN);
	assert(dsfield_at(&skb, nh) == 46 << 2 && ipv4_sum_ok(&skb, nh));
	assert(skb.data[nh - PPPOE_SES_HLEN] == 0x11 && skb.data[nh - 1] == PPP_IP);
	session.family = AF_INET6;
	session.tos = 3;
	nh = build(&skb, &session);
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == (46 << 2 | 3));
	/* An IP-in-IP frame whose carried connection has the remark: the
	 * carried header, which is the flow the hardware entry is for; the
	 * tunnel's header is the tunnel's. */
	nh = build(&skb, &(struct frame){ .tos = 10 << 2, .inner_family = AF_INET6 });
	connections(UNKNOWN, KNOWN(ef));
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == 10 << 2 && ipv4_sum_ok(&skb, nh));
	assert(dsfield_at(&skb, nh + 20) == 46 << 2);
	nh = build(&skb, &(struct frame){ .family = AF_INET6, .inner_family = AF_INET });
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh + 40) == 46 << 2 && ipv4_sum_ok(&skb, nh + 40));
	/* Or the tunnel's own, when only that connection is known. */
	nh = build(&skb, &(struct frame){ .inner_family = AF_INET6 });
	connections(KNOWN(ef), UNKNOWN);
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == 46 << 2 && dsfield_at(&skb, nh + 20) == 0);

	/* The gateway's own frame, by its socket: untouched. */
	nh = build(&skb, &(struct frame){ .tos = 10 << 2 });
	skb.sk = owner;
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == 10 << 2);
	/* A bridged frame: the hardware remark rides the opcode that
	 * decrements TTL, which a bridged flow's entry does not carry. */
	nh = build(&skb, &(struct frame){ .tos = 10 << 2 });
	skb.pkt_type = PACKET_OTHERHOST;
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == 10 << 2);
	/* A class with no remark, and a frame with no connection at all. */
	nh = build(&skb, &(struct frame){ .tos = 10 << 2 });
	connections(KNOWN(0), UNKNOWN);
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == 10 << 2);
	connections(UNKNOWN, UNKNOWN);
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == 10 << 2);
	/* Not IP: nothing to mark, and not a failure either. */
	failures = cdx_ft_qos_remark_failures();
	build(&skb, &(struct frame){ .ethertype = ETH_P_ARP });
	connections(KNOWN(ef), UNKNOWN);
	cdx_htb_select_queue(dev, &skb);
	assert(cdx_ft_qos_remark_failures() == failures);

	/* A header that cannot be made writable, or cannot be read whole, is
	 * counted and the frame sent as it is rather than dropped. */
	nh = build(&skb, &(struct frame){ .tos = 10 << 2 });
	skb.unwritable = true;
	cdx_htb_select_queue(dev, &skb);
	assert(dsfield_at(&skb, nh) == 10 << 2 && ipv4_sum_ok(&skb, nh));
	assert(cdx_ft_qos_remark_failures() == failures + 1);
	build(&skb, &(struct frame){ .pppoe = true });
	skb.len = ETH_HLEN + PPPOE_SES_HLEN + 12;
	cdx_htb_select_queue(dev, &skb);
	assert(cdx_ft_qos_remark_failures() == failures + 2);
	/* One already at the codepoint needs no write, so a header that could
	 * not be written costs nothing either. */
	build(&skb, &(struct frame){ .tos = 46 << 2 });
	skb.unwritable = true;
	cdx_htb_select_queue(dev, &skb);
	assert(cdx_ft_qos_remark_failures() == failures + 2);

	/* The DSCP map reads the codepoint the frame leaves with: a remark to EF
	 * with no egress class of its own lands where the EF filter says. */
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid10));
	assert(!add_leaf(dev, 11, 1, 1, 0, 0, 0, &qid11));
	memset(dscp_classes, 0, sizeof(dscp_classes));
	dscp_classes[46] = (1 << 4) | (NUM_PQS - 2);		/* EF: 1:11 */
	dscp_classes[10] = (1 << 4) | (NUM_PQS - 1);		/* AF11: 1:10 */
	build(&skb, &(struct frame){ .tos = 10 << 2 });
	connections(KNOWN(ef), UNKNOWN);
	assert(cdx_htb_select_queue(dev, &skb) == qid11);
	build(&skb, &(struct frame){ .pppoe = true, .tos = 10 << 2 });
	assert(cdx_htb_select_queue(dev, &skb) == qid11);
	memset(dscp_classes, 0, sizeof(dscp_classes));
	assert(!destroy(dev));
	assert_balanced(dev);
	cdx_unregister_ft_qos_class();
}

/* ethtool asks for a fixed number of values and gets one for every leaf slot,
 * whatever the tree looks like -- names and values arrive in separate ioctls,
 * so a count that moved with the tree would misalign them. */
static void test_class_statistics(void)
{
	u64 data[(CDX_HTB_MAX_LEAVES + DPA_CEETM_IMPLICIT_QUEUES) * DPA_CEETM_CLASS_STATS];
	u64 *implicit = data + CDX_HTB_MAX_LEAVES * DPA_CEETM_CLASS_STATS;
	struct net_device *dev = &devices[0];
	u16 qid1, qid2, qid10;
	unsigned ii;

	reset_world();
	assert(!create(dev, 1, 0));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!add_leaf(dev, 2, 0, 1, 0, 1000, 1000, &qid2));
	assert(!to_inner(dev, 10, 1, 0, 0));
	assert(!query(dev, 10, &qid10));

	memset(data, 0xff, sizeof(data));
	cdx_htb_class_stats(dev->priv.qm_ctx, data);
	/* Slot 0 is class 10: channel 0, the top strict-priority queue. */
	assert(data[0] == NUM_PQS - 1 && data[1] == 100u * (NUM_PQS - 1));
	assert(data[2] == NUM_PQS - 1);
	/* Slot 1 is class 2, on the second channel, at prio 1. */
	assert(data[3] == 1000u + NUM_PQS - 2);
	assert(data[4] == 100000u + 100u * (NUM_PQS - 2));
	assert(data[5] == 10u + NUM_PQS - 2);
	/* Every other slot is left exactly as the caller had it, which is the
	 * zero the driver writes before asking. */
	for (ii = 2 * DPA_CEETM_CLASS_STATS; ii < CDX_HTB_MAX_LEAVES * DPA_CEETM_CLASS_STATS; ii++)
		assert(data[ii] == UINT64_MAX);
	/* Then the two queues no leaf need hold, on the top channel -- the
	 * second: where unclassified traffic goes, class queue 0, and where
	 * control traffic goes, class queue 7. */
	assert(implicit[0] == 1000u && implicit[1] == 100000u && implicit[2] == 10u);
	assert(implicit[3] == 1000u + NUM_PQS - 1);
	assert(implicit[4] == 100000u + 100u * (NUM_PQS - 1));
	assert(implicit[5] == 10u + NUM_PQS - 1);

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

	/* With `default', unclassified traffic goes to the default leaf, and
	 * that is the queue reported for it: the same counters as its slot. */
	assert(!create(dev, 1, 10));
	assert(!add_leaf(dev, 1, 0, 0, 0, 1000, 1000, &qid1));
	assert(!to_inner(dev, 10, 1, 2, 0));
	memset(data, 0, sizeof(data));
	cdx_htb_class_stats(dev->priv.qm_ctx, data);
	assert(data[0] == NUM_PQS - 3 && !memcmp(implicit, data, 3 * sizeof(*data)));
	assert(implicit[3] == NUM_PQS - 1);
	assert(!destroy(dev));
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
 * port still configured by a tree that was never taken down. */
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
	test_control_budget();
	test_fragments();
	test_treeless_port();
	test_remark();
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

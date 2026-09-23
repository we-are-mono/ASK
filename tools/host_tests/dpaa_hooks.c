/* The DPAA driver's end of every hook the offload module registers, compiled
 * from the kernel source.
 *
 * The module is loadable and the driver built in, so the driver calls into it
 * through pointers the module sets and clears. Each unregister waits for the
 * calls already inside the module before its text may go -- an SRCU domain
 * for ndo_setup_tc, whose handler sleeps, and an RCU grace period for the
 * data-path callbacks, which do not. That only holds if every call is inside
 * the read-side section the unregister waits for, and the driver takes it
 * itself: ndo_select_queue has callers that hold none (AF_PACKET's qdisc
 * bypass), and a frame queue a lookup answers has to stay valid through the
 * enqueue after it. Here the read-side sections are depths, and a callback
 * reached outside one, or an unregister that waits from inside one, fails an
 * assertion.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define READ_ONCE(x)		(x)
#define WRITE_ONCE(x, v)	((x) = (v))
#define smp_store_release(p, v)	(*(p) = (v))
#define cmpxchg(p, o, n)	({ __typeof__(*(p)) __old = *(p);	\
				   if (__old == (o)) {			\
					   *(p) = (n);			\
				   }					\
				   __old; })
#define cmpxchg_release(p, o, n)	cmpxchg(p, o, n)
#define EXPORT_SYMBOL(sym)	extern int __unused_##sym
#define __hot
#define pr_err(...)		((void)0)
#define NETDEV_TX_OK		0
#define DPAA_ETH_TX_QUEUES		16
#define DPAA_ETH_CEETM_LEAF_QUEUES	16

struct net_device { int ifindex; };
struct sk_buff { u16 queue_mapping; };
struct qman_fq { int fqid; };
struct dpa_bp { int bpid; };
enum tc_setup_type { TC_SETUP_QDISC_HTB, TC_SETUP_FT };

/* --- read-side sections, as depths ---------------------------------- */
static int rcu_depth;
static unsigned rcu_syncs;
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth > 0); rcu_depth--; }
static void synchronize_rcu(void) { assert(!rcu_depth); rcu_syncs++; }
static void synchronize_net(void) { synchronize_rcu(); }
struct srcu_struct { int readers; };
#define DEFINE_STATIC_SRCU(name)	static struct srcu_struct name
static int srcu_read_lock(struct srcu_struct *s) { return s->readers++; }
static void srcu_read_unlock(struct srcu_struct *s, int idx)
{ (void)idx; assert(s->readers > 0); s->readers--; }
static unsigned srcu_syncs;
static void synchronize_srcu(struct srcu_struct *s) { assert(!s->readers); srcu_syncs++; }

/* The hook types and the qdisc contract, from the driver's own header. */
#include "dpaa_hooks_types.inc"

/* --- the rest of the driver ------------------------------------------ */
static u16 stack_choice;
static u16 netdev_pick_tx(struct net_device *dev, struct sk_buff *skb,
			  struct net_device *sb_dev) { return stack_choice; }
/* The bodies the wrappers hold RCU across: the hook lookups and the enqueue
 * of the frame queue they answer. */
static unsigned bodies;
static int __cpe_fp_tx(struct sk_buff *skb, struct net_device *dev)
{ assert(rcu_depth == 1); bodies++; return NETDEV_TX_OK; }
static int __dpaa_submit_outb_pkt_to_SEC(struct sk_buff *skb, struct net_device *dev,
					 struct dpa_bp *bp)
{ assert(rcu_depth == 1); bodies++; return 0; }
static int __dpaa_submit_inb_pkt_to_SEC(struct sk_buff *skb, uint16_t sagd)
{ assert(rcu_depth == 1); bodies++; return -1; }

/* File-scope state in the driver, declared where the harness can see it. */
static dpa_setup_tc_handler dpa_setup_tc_func;
DEFINE_STATIC_SRCU(dpa_setup_tc_srcu);
static const struct dpa_qdisc_ops *dpa_qdisc;
static cdx_get_ceetm_egressfq ceetm_fqget_func;
static cdx_get_ceetm_dscp_fq ceetm_dscp_fqget_func;
static cdx_get_ipsec_fq_hook_t cdx_get_ipsec_fq_hookfn;

#include "dpaa_hooks_production.inc"

/* --- the module's side ------------------------------------------------ */
static unsigned handled;
static int handler(struct net_device *dev, enum tc_setup_type type, void *data)
{ assert(dpa_setup_tc_srcu.readers == 1 && !rcu_depth); handled++; return 0; }

static struct qman_fq leaf_fq = { 7 };
static u16 answer;
static unsigned selected, fqs, stats;
static u16 select_queue(struct net_device *dev, struct sk_buff *skb)
{ assert(rcu_depth == 1); selected++; return answer; }
static struct qman_fq *txq_fq(void *qm_ctx, u16 txq, struct sk_buff *skb)
{ assert(rcu_depth == 1); fqs++; return &leaf_fq; }
static void class_stats(void *qm_ctx, u64 *data)
{
	assert(rcu_depth == 1);
	stats++;
	data[0] = 42;
	/* The last value the driver's string set names, after the leaves: the
	 * control queue's rejected frames. */
	data[(DPAA_ETH_CEETM_LEAF_QUEUES + DPA_CEETM_IMPLICIT_QUEUES) *
	     DPA_CEETM_CLASS_STATS - 1] = 7;
}
static const struct dpa_qdisc_ops ops = {
	.select_queue = select_queue, .txq_fq = txq_fq, .class_stats = class_stats,
};

static struct qman_fq *egress(void *ctx, uint32_t ch, uint32_t cq, uint32_t ff) { return &leaf_fq; }
static struct qman_fq *by_dscp(void *ctx, uint8_t dscp) { return &leaf_fq; }
static struct qman_fq *to_sec(u32 handle) { return &leaf_fq; }

int main(void)
{
	struct net_device dev = { 3 };
	struct sk_buff skb = { 0 };
	struct dpa_bp bp = { 0 };
	u64 data[(DPAA_ETH_CEETM_LEAF_QUEUES + DPA_CEETM_IMPLICIT_QUEUES) *
		 DPA_CEETM_CLASS_STATS];
	int ctx = 0;

	/* ndo_setup_tc: refused with nothing registered, called inside the
	 * SRCU section while registered, and the unregister waits for that
	 * section before returning. */
	assert(dpa_setup_tc(&dev, TC_SETUP_FT, NULL) == -EOPNOTSUPP);
	assert(!dpa_register_setup_tc(handler));
	assert(dpa_register_setup_tc(handler) == -EBUSY);
	assert(!dpa_setup_tc(&dev, TC_SETUP_QDISC_HTB, NULL) && handled == 1);
	assert(!dpa_setup_tc_srcu.readers);
	dpa_unregister_setup_tc();
	assert(srcu_syncs == 1);
	assert(dpa_setup_tc(&dev, TC_SETUP_FT, NULL) == -EOPNOTSUPP && handled == 1);

	/* The qdisc callbacks: each inside an RCU section the driver takes,
	 * whatever the caller holds -- none, here, as AF_PACKET's bypass. */
	stack_choice = 21;
	assert(dpa_qdisc_select_queue(&dev, &skb, NULL) == (21 & (DPAA_ETH_TX_QUEUES - 1)));
	assert(!dpa_qdisc_txq_fq(&ctx, 0, &skb));
	assert(!dpa_register_qdisc_ops(&ops));
	answer = DPAA_ETH_TX_QUEUES + 2;
	assert(dpa_qdisc_select_queue(&dev, &skb, NULL) == DPAA_ETH_TX_QUEUES + 2);
	answer = DPA_SELECT_QUEUE_NONE;
	assert(dpa_qdisc_select_queue(&dev, &skb, NULL) == (21 & (DPAA_ETH_TX_QUEUES - 1)));
	assert(selected == 2 && !rcu_depth);
	assert(dpa_qdisc_txq_fq(&ctx, 0, &skb) == &leaf_fq && fqs == 1 && !rcu_depth);
	/* Every value the string set names is cleared first, the two queues
	 * after the leaves included, and the module fills them all. */
	memset(data, 0xff, sizeof(data));
	dpa_qdisc_class_stats(&ctx, data);
	assert(stats == 1 && data[0] == 42 && !data[1] && !rcu_depth);
	assert(data[ARRAY_SIZE(data) - 1] == 7 && !data[ARRAY_SIZE(data) - 2]);
	dpa_unregister_qdisc_ops();
	assert(rcu_syncs == 1);
	assert(!dpa_qdisc_txq_fq(&ctx, 0, &skb) && fqs == 1);

	/* The transmit and SEC submit paths hold RCU across their bodies, where
	 * the lookups and the enqueue that uses their answer both happen. */
	assert(!dpa_register_ceetm_get_egress_fq(egress, by_dscp));
	assert(!dpa_register_ipsec_fq_handler(to_sec));
	assert(cpe_fp_tx(&skb, &dev) == NETDEV_TX_OK && !rcu_depth);
	/* The body's answer comes back through the section: 0 is a frame SEC
	 * has, which is what a caller counting what it gave SEC counts. */
	assert(dpaa_submit_outb_pkt_to_SEC(&skb, &dev, &bp) == 0 && !rcu_depth);
	assert(dpaa_submit_inb_pkt_to_SEC(&skb, 5) == -1 && !rcu_depth);
	assert(bodies == 3);
	dpa_unregister_ceetm_get_egress_fq();
	dpa_unregister_ipsec_fq_handler();
	assert(rcu_syncs == 3);
	assert(!ceetm_fqget_func && !ceetm_dscp_fqget_func && !cdx_get_ipsec_fq_hookfn);
	return 0;
}

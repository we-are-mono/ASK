// SPDX-License-Identifier: GPL-2.0+
/*
 * Directions into a smaller path, carried through an offline port (A385).
 *
 * The microcode fragments an IPv4 packet without DF that exceeds its entry's
 * MTU, and the fragments it builds of a frame an Ethernet port received carry
 * the headers and an all-zero payload, measured on the DK; of a frame an
 * offline port took they are whole. Only an offline port fetches the whole
 * frame before its PCD runs (fm_port.c, the pre-BMI full-frame fetch). So an
 * IPv4 UDP direction whose path is smaller than what its ingress port delivers
 * -- every upload into a PPPoE session from a 1500-byte LAN -- is carried by
 * two entries. The receive port's checks and counts each frame and hands it on
 * untouched, Ethernet header, tags and session included, to the queue into
 * the offline port; and the offline port's entry, keyed with that port's id and
 * the same tuple, does what the receive port's otherwise would, fragmenting
 * included. The port is dpa-fman0-oh@4, the board's third, so that nothing
 * else's frames share its queues.
 *
 * DF is the receive entry's to honour: it carries the path's MTU, so a packet
 * that may not be fragmented goes to Linux from the port it arrived on, as any
 * other direction's would, and is answered with the ICMP Linux sends; and it
 * fragments nothing itself (FRAG_DISABLE).
 *
 * What the offline port hands back instead of forwarding -- its entry gone
 * between the two lookups, anything its checks refuse -- reaches one of its
 * PCD queues, the detour queue's context B or the port's default queue, with
 * nothing to say which port it came in by. Every detoured direction is
 * recorded by its tuple for that (cdx_detour_flow_add()): the frame, still as
 * it arrived, is parsed down to the tuple, copied and given to Linux on that
 * port, as if the receive port had handed it over itself. The
 * same record refuses a second direction with the tuple of one already carried,
 * whose offline-port entry would be that one's, and outlives its direction by
 * a grace period for the frames still on their way through the port.
 *
 * Every queue tail-drops, so a direction the offline port cannot keep up with
 * -- some 530k fragmented packets a second, measured -- loses frames at the
 * queue rather than holding its ingress port's buffers until the port drops
 * everyone's. QMan discards an FMan enqueue it rejects and the buffers go back
 * to their pool (cdx_discard_fqid()), so no ERN needs handling.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/unaligned.h>
#include <net/ip.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include "dpaa_eth_common.h"
#include "dpaa_eth.h"
#include "portdefs.h"
#include "layer2.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "cdx.h"
#include "cdx_common.h"
#include "procfs.h"
#include "dpa_ipsec.h"
#include "cdx_flowtable_backend.h"
#include "cdx_detour.h"

#define CDX_DETOUR_PORTID_SHIFT	8
/* What each queue holds before it tail-drops: some 85 full-sized frames,
 * 0.2 ms of what the offline port forwards. */
#define CDX_DETOUR_TAILDROP	(128 * 1024)
#define CDX_DETOUR_FLOW_BITS	8
/* How long a direction's record outlives the direction: far longer than a
 * frame spends in a queue bounded as above. */
#define CDX_DETOUR_GRACE	(HZ / 10)

struct cdx_detour_flow {
	struct hlist_node node;
	struct list_head dying;
	struct rcu_head rcu;
	unsigned long expires;
	__be32 saddr, daddr;
	__be16 sport, dport;
	int ifindex;
	bool dead;
};

static struct {
	bool ready;
	int handle;
	u32 portid;
	u32 channel;
	struct dpa_fq detour;
	struct dpa_fq exception;
	bool exception_made;
	bool detour_made;
	u32 fqids;
	struct dpa_fq *pcd;
	unsigned int flows;
	atomic64_t delivered;
	atomic64_t unknown;
	atomic64_t failed;
	atomic64_t errors;
} cdx_detour = { .handle = -1 };

/* Written under the lock, read under RCU by the queues' callbacks. */
static DEFINE_HASHTABLE(cdx_detour_flows, CDX_DETOUR_FLOW_BITS);
static DEFINE_SPINLOCK(cdx_detour_flows_lock);
static LIST_HEAD(cdx_detour_dying);
static void cdx_detour_reap(struct work_struct *work);
static DECLARE_DELAYED_WORK(cdx_detour_reaper, cdx_detour_reap);

static u32 cdx_detour_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	return jhash_3words((__force u32)saddr, (__force u32)daddr,
			    ((__force u32)sport << 16) | (__force u32)dport, 0);
}

/* The port a direction with this tuple arrives by: a live direction's, else
 * one gone within the grace period, else none (0). */
static int cdx_detour_ingress(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct cdx_detour_flow *flow;
	int gone = 0;

	hash_for_each_possible_rcu(cdx_detour_flows, flow, node,
				   cdx_detour_key(saddr, daddr, sport, dport)) {
		if (flow->saddr != saddr || flow->daddr != daddr ||
		    flow->sport != sport || flow->dport != dport)
			continue;
		if (!READ_ONCE(flow->dead))
			return flow->ifindex;
		gone = gone ?: flow->ifindex;
	}
	return gone;
}

int cdx_detour_flow_add(const struct cdx_ft_rule *rule, struct cdx_detour_flow **out)
{
	struct cdx_detour_flow *flow, *other;
	u32 key;

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	if (!flow)
		return -ENOMEM;
	flow->saddr = rule->src.ip;
	flow->daddr = rule->dst.ip;
	flow->sport = rule->sport;
	flow->dport = rule->dport;
	flow->ifindex = rule->in->ifindex;
	INIT_LIST_HEAD(&flow->dying);
	key = cdx_detour_key(flow->saddr, flow->daddr, flow->sport, flow->dport);
	spin_lock_bh(&cdx_detour_flows_lock);
	hash_for_each_possible(cdx_detour_flows, other, node, key)
		if (!other->dead && other->saddr == flow->saddr && other->daddr == flow->daddr &&
		    other->sport == flow->sport && other->dport == flow->dport) {
			spin_unlock_bh(&cdx_detour_flows_lock);
			kfree(flow);
			return -EBUSY;
		}
	/* At the head, ahead of any record of this tuple's that is going. */
	hash_add_rcu(cdx_detour_flows, &flow->node, key);
	cdx_detour.flows++;
	spin_unlock_bh(&cdx_detour_flows_lock);
	*out = flow;
	return 0;
}

void cdx_detour_flow_del(struct cdx_detour_flow *flow)
{
	if (!flow)
		return;
	spin_lock_bh(&cdx_detour_flows_lock);
	WRITE_ONCE(flow->dead, true);
	flow->expires = jiffies + CDX_DETOUR_GRACE;
	list_add_tail(&flow->dying, &cdx_detour_dying);
	cdx_detour.flows--;
	spin_unlock_bh(&cdx_detour_flows_lock);
	queue_delayed_work(system_wq, &cdx_detour_reaper, CDX_DETOUR_GRACE);
}

/* Records go in the order their grace ends. */
static void cdx_detour_reap(struct work_struct *work)
{
	struct cdx_detour_flow *flow, *next;
	unsigned long wait = 0;

	spin_lock_bh(&cdx_detour_flows_lock);
	list_for_each_entry_safe(flow, next, &cdx_detour_dying, dying) {
		if (time_before(jiffies, flow->expires)) {
			wait = flow->expires - jiffies;
			break;
		}
		list_del(&flow->dying);
		hash_del_rcu(&flow->node);
		kfree_rcu(flow, rcu);
	}
	spin_unlock_bh(&cdx_detour_flows_lock);
	if (wait)
		queue_delayed_work(system_wq, &cdx_detour_reaper, wait);
}

/* The frame as the receive port took it, copied. It is in one buffer: no port
 * a detoured direction arrives by delivers more than a standard frame
 * (ft_detours()). */
static struct sk_buff *cdx_detour_copy(const struct qm_fd *fd)
{
	const struct dpa_bp *bp = dpa_bpid2pool(fd->bpid);
	dma_addr_t addr = qm_fd_addr(fd);
	unsigned int off = dpa_fd_offset(fd), len = dpa_fd_length(fd);
	struct sk_buff *skb;

	if (!bp || fd->format != qm_fd_contig || off + len > bp->size)
		return NULL;
	skb = netdev_alloc_skb_ip_align(NULL, len);
	if (!skb)
		return NULL;
	dma_sync_single_range_for_cpu(bp->dev, addr, off, len, DMA_BIDIRECTIONAL);
	skb_put_data(skb, phys_to_virt(addr) + off, len);
	dma_sync_single_range_for_device(bp->dev, addr, off, len, DMA_BIDIRECTIONAL);
	return skb;
}

/* The ingress port of a copied frame: its tags skipped, as the receive port's
 * parser skips them, down to the IPv4 UDP tuple a detoured direction is
 * recorded by. No detoured direction arrives in a session (ft_detours()). */
static int cdx_detour_frame_ingress(const struct sk_buff *skb)
{
	const u8 *data = skb->data;
	unsigned int off = ETH_HLEN, tags;
	const struct iphdr *iph;
	const struct udphdr *uh;
	__be16 proto;

	if (skb->len < ETH_HLEN)
		return 0;
	proto = get_unaligned(&((const struct ethhdr *)data)->h_proto);
	for (tags = 0; tags < 2 && eth_type_vlan(proto); tags++) {
		if (skb->len < off + VLAN_HLEN)
			return 0;
		proto = get_unaligned((const __be16 *)(data + off + 2));
		off += VLAN_HLEN;
	}
	if (proto != htons(ETH_P_IP) || skb->len < off + sizeof(*iph))
		return 0;
	iph = (const struct iphdr *)(data + off);
	if (iph->version != 4 || iph->ihl < 5 || iph->protocol != IPPROTO_UDP ||
	    ip_is_fragment(iph) || skb->len < off + iph->ihl * 4 + sizeof(*uh))
		return 0;
	uh = (const struct udphdr *)(data + off + iph->ihl * 4);
	return cdx_detour_ingress(get_unaligned(&iph->saddr), get_unaligned(&iph->daddr),
				  get_unaligned(&uh->source), get_unaligned(&uh->dest));
}

/* A frame the offline port handed back: to Linux, on the port it arrived by. */
static enum qman_cb_dqrr_result cdx_detour_rx(struct qman_portal *portal,
					      struct qman_fq *fq,
					      const struct qm_dqrr_entry *dq)
{
	struct net_device *dev;
	struct sk_buff *skb;
	int ifindex;

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	skb = cdx_detour_copy(&dq->fd);
	dpa_fd_release(NULL, &dq->fd);
	if (!skb) {
		atomic64_inc(&cdx_detour.failed);
		return qman_cb_dqrr_consume;
	}
	rcu_read_lock();
	ifindex = cdx_detour_frame_ingress(skb);
	dev = ifindex ? dev_get_by_index_rcu(&init_net, ifindex) : NULL;
	if (!dev || !(dev->flags & IFF_UP)) {
		rcu_read_unlock();
		atomic64_inc(&cdx_detour.unknown);
		kfree_skb(skb);
		return qman_cb_dqrr_consume;
	}
	skb->protocol = eth_type_trans(skb, dev);
	netif_rx(skb);
	rcu_read_unlock();
	atomic64_inc(&cdx_detour.delivered);
	return qman_cb_dqrr_consume;
}

/* The port's error queue: a frame with an error the receive port did not
 * see has nothing Linux could do with it. */
static enum qman_cb_dqrr_result cdx_detour_error(struct qman_portal *portal,
						 struct qman_fq *fq,
						 const struct qm_dqrr_entry *dq)
{
	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	atomic64_inc(&cdx_detour.errors);
	dpa_fd_release(NULL, &dq->fd);
	return qman_cb_dqrr_consume;
}

/* What the queue into the port still holds when it is torn down. */
static enum qman_cb_dqrr_result cdx_detour_drain(struct qman_portal *portal,
						 struct qman_fq *fq,
						 const struct qm_dqrr_entry *dq)
{
	if (dq->stat & QM_DQRR_STAT_FD_VALID)
		dpa_fd_release(NULL, &dq->fd);
	return qman_cb_dqrr_consume;
}

/* A queue to the CPU: what the port hands back, on the portal's channel. */
static int cdx_detour_consumer(struct dpa_fq *dpa_fq, u32 fqid, u16 channel)
{
	struct qman_fq *fq = &dpa_fq->fq_base;
	struct qm_mcc_initfq opts = {};
	int rc;

	dpa_fq->fqid = fqid;
	dpa_fq->fq_type = FQ_TYPE_RX_PCD;
	dpa_fq->channel = channel;
	dpa_fq->wq = CDX_CPU_RX_WQ;
	fq->cb.dqrr = cdx_detour_rx;
	rc = qman_create_fq(fqid, 0, fq);
	if (rc)
		return rc;
	opts.fqid = fqid;
	opts.count = 1;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = CDX_CPU_RX_WQ;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE | QM_FQCTRL_TDE;
	qm_fqd_taildrop_set(&opts.fqd.td, CDX_DETOUR_TAILDROP, 1);
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_TDTHRESH;
	rc = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (rc)
		qman_destroy_fq(fq, 0);
	return rc;
}

/* The port's PCD queues: each distribution's base, with the port id in its
 * second byte, as create_ipsec_pcd_fqs() builds the SEC port's, spread over
 * the CPUs' portals. Distributions share bases -- a PPPoE scheme its native
 * one's -- and each queue is made once. */
static int cdx_detour_pcd_queues(void)
{
	u32 max_dist = 0, base, count, dist, i, next = 0;
	struct dpa_iface_info *oh_iface;
	unsigned int cpu;

	if (get_ofport_max_dist(FMAN_IDX, cdx_detour.handle, &max_dist) < 0 ||
	    cpumask_empty(qman_affine_cpus()))
		return -ENODEV;
	oh_iface = dpa_get_ohifinfo_by_portid(cdx_detour.portid);
	for (dist = 0; dist < max_dist; dist++) {
		if (get_oh_port_pcd_fqinfo(FMAN_IDX, cdx_detour.handle, dist, &base, &count))
			return -ENODEV;
		base |= cdx_detour.portid << CDX_DETOUR_PORTID_SHIFT;
		for (i = 0; i < count; i++) {
			struct dpa_fq *made, *dpa_fq;
			int rc;

			for (made = cdx_detour.pcd; made; made = (struct dpa_fq *)made->list.next)
				if (made->fqid == base + i)
					break;
			if (made)
				continue;
			dpa_fq = kzalloc(sizeof(*dpa_fq), GFP_KERNEL);
			if (!dpa_fq)
				return -ENOMEM;
			cpu = cpumask_nth(next++ % cpumask_weight(qman_affine_cpus()),
					  qman_affine_cpus());
			rc = cdx_detour_consumer(dpa_fq, base + i, qman_affine_channel(cpu));
			if (rc) {
				pr_err("cdx: detour: PCD queue 0x%x: %d\n", base + i, rc);
				kfree(dpa_fq);
				return rc;
			}
			if (oh_iface && oh_iface->pcd_proc_entry)
				cdx_create_type_fqid_info_in_procfs(&dpa_fq->fq_base, PCD_DIR,
								    oh_iface->pcd_proc_entry, NULL);
			dpa_fq->list.next = (struct list_head *)cdx_detour.pcd;
			cdx_detour.pcd = dpa_fq;
		}
	}
	return 0;
}

/* Into the offline port, as FROM_SEC is into SEC's: whatever the port's PCD
 * would leave on its default queue goes to context B, the exception queue. */
static int cdx_detour_queue(u32 fqid)
{
	struct qman_fq *fq = &cdx_detour.detour.fq_base;
	struct qm_mcc_initfq opts = {};
	int rc;

	cdx_detour.detour.fqid = fqid;
	cdx_detour.detour.channel = cdx_detour.channel;
	cdx_detour.detour.wq = DEFA_WQ_ID;
	fq->cb.dqrr = cdx_detour_drain;
	rc = qman_create_fq(fqid, QMAN_FQ_FLAG_TO_DCPORTAL, fq);
	if (rc)
		return rc;
	opts.fqid = fqid;
	opts.count = 1;
	opts.fqd.dest.channel = cdx_detour.channel;
	opts.fqd.dest.wq = DEFA_WQ_ID;
	opts.fqd.fq_ctrl = QM_FQCTRL_TDE;
	qm_fqd_taildrop_set(&opts.fqd.td, CDX_DETOUR_TAILDROP, 1);
	opts.fqd.context_a.hi = CDX_FQD_CTX_A_OVERRIDE_FQ << CDX_FQD_CTX_A_SHIFT_BITS;
	opts.fqd.context_b = cdx_detour.exception.fqid;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_TDTHRESH |
		       QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB;
	rc = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (rc)
		qman_destroy_fq(fq, 0);
	return rc;
}

/* Unload, or a failed load. The adapter that admitted every detoured
 * direction pins CDX, so they are gone; the ports are stopped. */
static void cdx_detour_exit(void)
{
	struct cdx_detour_flow *flow;
	struct hlist_node *tmp;
	unsigned int bucket;

	WRITE_ONCE(cdx_detour.ready, false);
	if (cdx_detour.detour_made) {
		cdx_destroy_fq(&cdx_detour.detour.fq_base);
		cdx_detour.detour_made = false;
	}
	cdx_destroy_fq_list(&cdx_detour.pcd);
	if (cdx_detour.exception_made) {
		cdx_destroy_fq(&cdx_detour.exception.fq_base);
		cdx_detour.exception_made = false;
	}
	/* The two FQIDs go back unless a deletion failed: then an entry
	 * enqueueing to the first may still be linked, and the range is held
	 * for the reboot that alone settles it, as an SA's are. */
	if (cdx_detour.fqids && !cdx_ft_failed())
		qman_release_fqid_range(cdx_detour.fqids, 2);
	cdx_detour.fqids = 0;
	if (cdx_detour.handle >= 0) {
		release_offline_port(FMAN_IDX, cdx_detour.handle);
		cdx_detour.handle = -1;
	}
	cancel_delayed_work_sync(&cdx_detour_reaper);
	spin_lock_bh(&cdx_detour_flows_lock);
	hash_for_each_safe(cdx_detour_flows, bucket, tmp, flow, node) {
		hash_del_rcu(&flow->node);
		if (!list_empty(&flow->dying))
			list_del(&flow->dying);
		kfree_rcu(flow, rcu);
	}
	cdx_detour.flows = 0;
	spin_unlock_bh(&cdx_detour_flows_lock);
}

/* Not fatal: a board without the port -- an older device tree -- is a
 * gateway that keeps such directions in software, as it always did. */
int cdx_detour_init(void)
{
	void *td[MAX_MATCH_TABLES];
	u32 fqid;
	int rc = -ENODEV;

	if (cdx_dpa_init_fault())
		goto fail;
	cdx_detour.handle = alloc_offline_port(FMAN_IDX, PORT_TYPE_DETOUR,
					       cdx_detour_rx, cdx_detour_error);
	if (cdx_detour.handle < 0)
		goto fail;
	if (get_ofport_portid(FMAN_IDX, cdx_detour.handle, &cdx_detour.portid) ||
	    get_ofport_info(FMAN_IDX, cdx_detour.handle, &cdx_detour.channel, td))
		goto fail;
	/* Every queue the port can reach first, then the one into it. */
	rc = cdx_detour_pcd_queues();
	if (rc)
		goto fail;
	rc = -ENOMEM;
	if (qman_alloc_fqid_range(&fqid, 2, 0, 0) < 2)
		goto fail;
	cdx_detour.fqids = fqid;
	rc = cdx_detour_consumer(&cdx_detour.exception, fqid + 1,
				 qman_affine_channel(cpumask_first(qman_affine_cpus())));
	if (rc)
		goto fail;
	cdx_detour.exception_made = true;
	rc = cdx_detour_queue(fqid);
	if (rc)
		goto fail;
	cdx_detour.detour_made = true;
	register_cdx_deinit_func(cdx_detour_exit);
	pr_info("cdx: detour through offline port %u (channel 0x%x): queue 0x%x\n",
		cdx_detour.portid, cdx_detour.channel, cdx_detour.detour.fqid);
	/* Last: a reader that sees it sees the queues. */
	smp_store_release(&cdx_detour.ready, true);
	return 0;
fail:
	pr_warn("cdx: no offline-port detour (%d): directions into a smaller path stay in software\n",
		rc);
	cdx_detour_exit();
	return rc;
}

/* Whether directions into a smaller path take the detour at all; off, they
 * stay in software, as they did before it. Read at admission: what it carries
 * goes as its flow does, or as Linux offers that flow again, which turning it
 * off then refuses. */
static bool cdx_detour_enabled = true;
module_param_named(detour, cdx_detour_enabled, bool, 0644);
MODULE_PARM_DESC(detour, "Carry IPv4 UDP into a smaller path through the offline-port detour; 0 keeps it in software");

#ifdef CDX_DEBUG_FLOWTABLE
/* Test only: a detoured direction gets its receive entry alone, so that every
 * frame of it misses on the offline port and comes back by its queues -- the
 * path a frame takes whose entry went between the two lookups, made
 * deterministic (cdx_ft_hw_add()). */
bool cdx_detour_strand;
module_param_named(detour_strand, cdx_detour_strand, bool, 0600);
MODULE_PARM_DESC(detour_strand, "Install a detour's receive entry alone, so the offline port hands every frame back (test)");
#endif

bool cdx_ft_detour_ready(void)
{
	return smp_load_acquire(&cdx_detour.ready) && READ_ONCE(cdx_detour_enabled);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_detour_ready, ASK_CDX_FLOWTABLE);

u32 cdx_detour_fqid(void)
{
	return cdx_detour.detour.fqid;
}

u32 cdx_detour_portid(void)
{
	return cdx_detour.portid;
}

#ifdef CDX_DEBUG_FLOWTABLE
/* Where the exception queue lives, the one queue cdx pins to the first CPU:
 * its channel and work queue, for a test to load that portal as its traffic
 * would (cdx_portal_faults.c). */
int cdx_detour_exception_placement(u16 *channel, u8 *wq)
{
	if (!smp_load_acquire(&cdx_detour.ready))
		return -ENODEV;
	*channel = cdx_detour.exception.channel;
	*wq = cdx_detour.exception.wq;
	return 0;
}
#endif

void cdx_detour_counters(struct cdx_detour_counters *counters)
{
	spin_lock_bh(&cdx_detour_flows_lock);
	counters->flows = cdx_detour.flows;
	spin_unlock_bh(&cdx_detour_flows_lock);
	counters->delivered = atomic64_read(&cdx_detour.delivered);
	counters->unknown = atomic64_read(&cdx_detour.unknown);
	counters->failed = atomic64_read(&cdx_detour.failed);
	counters->errors = atomic64_read(&cdx_detour.errors);
}
EXPORT_SYMBOL_NS_GPL(cdx_detour_counters, ASK_CDX_FLOWTABLE);

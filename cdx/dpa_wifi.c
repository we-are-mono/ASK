/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <net/pkt_sched.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/irqnr.h>
#include <linux/ppp_defs.h>
#include <linux/highmem.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#include <linux/fsl_bman.h>

#include "portdefs.h"
#include "misc.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "dpa_wifi.h"
#include "dpa_ipsec.h"
#include "layer2.h"
#include "cdx.h"
#include "cdx_wifi_backend.h"
#include "procfs.h"

//uncomment to allow debug prints
//#define DPA_WIFI_DEBUG  1

static bool vwd_stopping = true;
#define DPAWIFI_ERROR(fmt, ...)\
{\
        printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#ifdef CDX_DPA_DEBUG
#define DPAWIFI_INFO(fmt, ...)\
{\
        printk(KERN_INFO fmt, ## __VA_ARGS__);\
}
#else
#define DPAWIFI_INFO(fmt, ...)
#endif

#define INCR_PER_CPU_STAT(ptr, stat)\
{\
        get_cpu_ptr((ptr))->stat++;\
        put_cpu_ptr((ptr));\
}

/*
 * Concurrency (VWD, virtual wifi driver):
 *   vwd.vaplock (spinlock_t in dpaa_vwd_priv_s)
 *      - Guards the VAP table (vwd.vap[] and dev_attr_vap[]) and
 *        the associated sysfs attribute bindings. Taken _bh on the
 *        VAP command path and by the softirq dequeue paths, so
 *        NOTHING may sleep under it. Sleeping VAP setup (vwd_vap_up:
 *        GFP_KERNEL allocs, qman FQ creation; device_create_file)
 *        runs outside the lock: dpaa_vwd_vap_cmd() claims the slot
 *        with VAP_ST_CONFIGURING under the lock, drops it for the
 *        work, and re-takes it to publish VAP_ST_OPEN or roll back.
 *        Datapath consumers key on net_dev->wifi_offload_dev
 *        (release-published only after the FQs are live) and on
 *        VAP_ST_OPEN (the forwarding dequeue path), so they never
 *        observe a half-built VAP.
 *   vwd (file-scope struct)
 *      - Initialized once in dpaa_vwd_init(), torn down in
 *        dpaa_vwd_exit(). VWD holds the Ethernet netdev reference
 *        returned by dpa_first_eth_priv() until callbacks have
 *        drained, then releases it during initialization failure or
 *        exit.
 *
 * Contexts:
 *   dpaa_vwd_vap_cmd                        - process, under RTNL.
 *   dequeue callbacks                       - softirq.
 *   dpaa_vwd_{init,exit,up,down}           - module init/exit.
 */

struct dpaa_vwd_priv_s vwd;

extern struct dpa_bp *dpa_bpid2pool(int bpid);
extern struct dpa_priv_s *dpa_first_eth_priv(void);

static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_show_vap_stats(struct device *dev, struct device_attribute *attr, char *buf);
static DEVICE_ATTR(vwd_debug_stats, 0444, vwd_show_dump_stats, NULL);
static struct device_attribute dev_attr_vap[MAX_WIFI_VAPS];
static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq);

static ssize_t vwd_show_vap_stats(struct device *dev, struct device_attribute *attribute, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	int ii = 0;

	struct vap_stats_s *per_cpu_stats;
	struct vap_stats_s total_stats;
	int i;

	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		if (!strcmp(attribute->attr.name, priv->vaps[ii].ifname)) {
			break;
		}
	}

	/* No vap entry */
	if (ii == MAX_WIFI_VAPS)
		return 0;

	memset(&total_stats, 0, sizeof(struct vap_stats_s));
	for_each_possible_cpu(i) {
		per_cpu_stats = per_cpu_ptr(priv->vaps[ii].vap_stats, i);
		total_stats.pkts_rx_fast_forwarded += per_cpu_stats->pkts_rx_fast_forwarded;
		total_stats.pkts_rx_ipsec += per_cpu_stats->pkts_rx_ipsec;
	}

	len += sprintf(buf, "VAP (id : %d  name : %s)\n",ii,priv->vaps[ii].ifname);
	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  WiFi Tx pkts : %u \n", total_stats.pkts_rx_fast_forwarded);
	len += sprintf(buf + len, "  WiFi Tx ipsec pkts : %u\n", total_stats.pkts_rx_ipsec);

	return len;
}

/** vwd_show_dump_stats
 *
 */
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vwd_global_stats_s *per_cpu_stats;
	struct vwd_global_stats_s total_stats;
	int i;

	memset(&total_stats, 0, sizeof(struct vwd_global_stats_s));
	for_each_possible_cpu(i) {
		per_cpu_stats = per_cpu_ptr(priv->vwd_global_stats, i);
		total_stats.pkts_slow_fail += per_cpu_stats->pkts_slow_fail;
		total_stats.pkts_dev_down_drop += per_cpu_stats->pkts_dev_down_drop;
	}

	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  WiFI Rx Fails : %u\n", total_stats.pkts_slow_fail);
	len += sprintf(buf + len, "  WiFI Device Down Drops : %u\n", total_stats.pkts_dev_down_drop);

	return len;
}



/** dpaa_vwd_sysfs_init
 *
 */
static int dpaa_vwd_sysfs_init( struct dpaa_vwd_priv_s *priv )
{

	if (device_create_file(priv->vwd_device, &dev_attr_vwd_debug_stats))
		return -1;
	return 0;
}

/** dpaa_vwd_sysfs_exit
 *
 */
static void dpaa_vwd_sysfs_exit(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;

	device_remove_file(priv->vwd_device, &dev_attr_vwd_debug_stats);
}

/* This function converts the fd from ipsec  and frag bufferpool to skb */
static struct sk_buff* sec_frag_fd_to_vwd_skb(const struct qm_dqrr_entry *dq, struct dpa_bp* dpa_bp)
{
	uint8_t *ptr, *skb_ptr;
	uint32_t len;
	struct sk_buff *skb;
	struct bm_buffer bmb;

	len = dq->fd.length20;
	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);

	skb = dev_alloc_skb(len + dq->fd.offset + 32);
	if (!skb) {
		DPAWIFI_ERROR("%s::skb alloc failed\n", __func__);
		return NULL;
	}
	skb_reserve(skb, dq->fd.offset);
	skb_ptr = skb_put(skb, len);
	memcpy(skb_ptr, ptr, len);

	/* Release FD */
	bmb.bpid = dq->fd.bpid;
	bmb.addr = dq->fd.addr;
	while (bman_release(dpa_bp->pool, &bmb, 1, 0))
		cpu_relax();

	return skb;
}

static struct sk_buff *__hot contig_fd_to_vwd_skb(const struct dpa_priv_s *priv,
		const struct qm_fd *fd)
{
	struct dpa_bp *dpa_bp;
	dma_addr_t addr;
	void *vaddr;
	struct sk_buff *skb;
	struct sk_buff **skbh;
	ssize_t fd_off;

	dpa_bp = dpa_bpid2pool(fd->bpid);
	if (!dpa_bp) {
		DPAWIFI_ERROR("%s::invalid buffer pool id %d\n", __func__, fd->bpid);
		return NULL;
	}
	//get phys addressa and virt address
	addr = qm_fd_addr(fd);
	vaddr = phys_to_virt(addr);
	fd_off = dpa_fd_offset(fd);

	dma_unmap_single(dpa_bp->dev, addr, dpa_bp->size,
			 DMA_BIDIRECTIONAL);
	DPA_READ_SKB_PTR(skb, skbh, vaddr, -1);
	if (!skb)
		return NULL;

#ifdef DPA_WIFI_DEBUG
	if (fd_off > priv->rx_headroom) {
		DPAWIFI_ERROR("%s:: no headroom %d:%d\n", __func__, (int)fd_off, priv->rx_headroom);
		//return NULL;
	}	
#endif

	/* The Ethernet pool uses the SDK's truesize accounting. */
#ifdef FM_ERRATUM_A050385
	if (likely(!fm_has_errata_a050385())) {
#else
	if (likely(!dpaa_errata_a010022)) {
#endif
		skb->truesize = SKB_TRUESIZE(dpa_fd_length(fd));
	}
	skb->data = vaddr;
	skb->len = 0;
	skb_reset_tail_pointer(skb);
	skb_reserve(skb, fd_off);
	skb_put(skb, dpa_fd_length(fd));
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::skb:%p head %p data %p headroom %d\n", 
			__func__, skb, skb->head, skb->data, skb_headroom(skb));
	DPAWIFI_INFO("%s::skb:len %d tail %d end %d\n", __func__, skb->len, skb->tail, skb->end);
#endif
	return skb;

}

void drain_tx_bp_pool(struct dpa_bp *bp)
{
	int ret, num = 8;

	do {
		struct bm_buffer bmb[8];
		int i;

		ret = bman_acquire(bp->pool, bmb, num, 0);
		if (ret < 0) {
			if (num == 8) {
				/* we have less than 8 buffers left;
				 * drain them one by one
				 */
				num = 1;
				ret = 1;
				continue;
			} else {
				/* Pool is fully drained */
				break;
			}
		}

		for (i = 0; i < num; i++) {
			dma_addr_t addr = bm_buf_addr(&bmb[i]);

			dma_unmap_single(bp->dev, addr, bp->size,
					DMA_BIDIRECTIONAL);

			_dpa_bp_free_pf(phys_to_virt(addr));
		}
	} while (ret > 0);
}


/* Dequeue context for VWD's own frame queues.
 *
 * A DQRR callback runs in hard-IRQ context the first time a portal has work,
 * and the SDK's convention is to mask DQRI there and leave the rest to a NAPI
 * poll. VWD used to borrow eth0's per-portal NAPI for that, and a port's NAPI
 * is enabled only while the port is open: on a board whose first port is
 * unused it never is, napi_schedule() is then a no-op, and every VAP frame
 * that arrives on an idle portal leaves DQRI masked with nothing to unmask
 * it. That the path worked at all was an accident of TCP: the client's
 * acknowledgements produce transmit confirmations on the WAN port, whose own
 * NAPI drains the same portal and re-enables the interrupt.
 *
 * So VWD owns its polling: one NAPI per possible CPU and portal, on a dummy
 * device, enabled for the module's life, polled by the SDK's dpaa_eth_poll().
 */
struct vwd_napi {
	struct dpa_napi_portal *np;
};
static struct vwd_napi __percpu *vwd_napi;
static struct net_device *vwd_napi_dev;

static void vwd_napi_del(void)
{
	int cpu, i;

	if (vwd_napi) {
		for_each_possible_cpu(cpu) {
			struct vwd_napi *vn = per_cpu_ptr(vwd_napi, cpu);

			if (!vn->np)
				continue;
			for (i = 0; i < qman_portal_max; i++) {
				napi_disable(&vn->np[i].napi);
				netif_napi_del(&vn->np[i].napi);
			}
			kfree(vn->np);
			vn->np = NULL;
		}
		free_percpu(vwd_napi);
		vwd_napi = NULL;
	}
	if (vwd_napi_dev) {
		free_netdev(vwd_napi_dev);
		vwd_napi_dev = NULL;
	}
}

static int vwd_napi_add(void)
{
	int cpu, i;

	vwd_napi_dev = alloc_netdev_dummy(0);
	if (!vwd_napi_dev)
		return -ENOMEM;
	vwd_napi = alloc_percpu(struct vwd_napi);
	if (!vwd_napi)
		goto err;
	for_each_possible_cpu(cpu) {
		struct vwd_napi *vn = per_cpu_ptr(vwd_napi, cpu);

		vn->np = kcalloc(qman_portal_max, sizeof(*vn->np), GFP_KERNEL);
		if (!vn->np)
			goto err;
		for (i = 0; i < qman_portal_max; i++) {
			netif_napi_add(vwd_napi_dev, &vn->np[i].napi, dpaa_eth_poll);
			napi_enable(&vn->np[i].napi);
		}
	}
	return 0;
err:
	vwd_napi_del();
	return -ENOMEM;
}

/* dpaa_eth_napi_schedule() on VWD's own contexts: in interrupt context, mask
 * DQRI and hand the portal to the poll; in a poll already, process inline. */
static int vwd_napi_schedule(struct qman_portal *portal)
{
	if (unlikely(in_irq() || !in_serving_softirq())) {
		if (likely(!qman_p_irqsource_remove(portal, QM_PIRQ_DQRI))) {
			const struct qman_portal_config *pc =
				qman_p_get_portal_config(portal);
			struct dpa_napi_portal *np =
				&raw_cpu_ptr(vwd_napi)->np[pc->index];

			np->p = portal;
			napi_schedule(&np->napi);
			return 1;
		}
	}
	return 0;
}

static void vwd_send_to_vap(struct sk_buff* skb)
{
	struct ethhdr *hdr;

	hdr = (struct ethhdr *)skb->data;
	skb->protocol = hdr->h_proto;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof(struct ethhdr));
	skb->priority = 0;
	dev_queue_xmit(skb);
	return;
}

static enum qman_cb_dqrr_result vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;

	if (unlikely(vwd_napi_schedule(portal)))
		return qman_cb_dqrr_stop;
	process_vap_rx_fwd_pkt(portal, fq, dq);
	return qman_cb_dqrr_consume;
}

static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq )
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct sk_buff *skb;
	struct net_device *net_dev;
	struct dpa_bp *dpa_bp, *ipsec_bp, *frag_bp;
	struct vap_desc_s *vap;
	int *count_ptr;

	dpa_bp = dpa_bpid2pool(dq->fd.bpid);
	if (!dpa_bp) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		return 0;
	}
	/* Published under RCU rather than a lock: vwd_vap_down() clears the
	 * device's wifi_offload_dev, then every queue's net_dev, before the
	 * state leaves OPEN, and a device being unregistered is only freed
	 * after the core's synchronize_net(), which this read section is
	 * inside of. So a queue whose device we still see is a device that
	 * is still alive for the length of dev_queue_xmit(), and no per-frame
	 * reference is needed. The state is the last thing the open path
	 * publishes, and the first thing checked here.
	 */
	rcu_read_lock();
	net_dev = READ_ONCE(((struct dpa_fq *)fq)->net_dev);
	if (net_dev) {
		vap = (void *)READ_ONCE(net_dev->wifi_offload_dev);
		if (!vap || smp_load_acquire(&vap->state) != VAP_ST_OPEN ||
		    !netif_running(net_dev))
			net_dev = NULL;
	}
	/*If vap interface is down then fq net_dev is NULL, in this case release the fd.*/
	if (!net_dev)
	{
		if (printk_ratelimit())
			DPAWIFI_ERROR("%s::vap interface is down, releasing the frame from fq %u.\n ", 
							__func__, fq->fqid);
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_dev_down_drop);
		goto rel_fd;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::forwarding packet\n", __func__);
	DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s addr %llx\n", __func__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset, net_dev, net_dev->name, (uint64_t)dq->fd.addr);
#endif
	ipsec_bp = get_ipsec_bp();
	if (dq->fd.format != qm_fd_contig) {
		DPAWIFI_ERROR("%s::TBD discarding SG frame :%d\n ", __func__,dq->fd.format);
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		goto rel_fd;
	}

	/* If the packet is recieved from ipsec, then the buffer used is not
	   from ethernet buffer pool or from kernel, so this buffer has to be
	   copied to skb and to be sent to wifi driver, and the buffer from ipsec bufferpool 
	   is released */ 
	/* If the packet is fragmented in fast path, then one of the packet will be received
	   from fragment buffer pool */
	frag_bp  = get_frag_bp();
	if ( (dpa_bp == ipsec_bp) || (dpa_bp == frag_bp) )
	{
		/* Process secure packet transmitted to wifi */
		skb = sec_frag_fd_to_vwd_skb(dq, dpa_bp);
		if (!skb)
			goto rel_fd;
		goto process_skb;
	}
	/* The buffer is from an Ethernet pool: refill that pool for the
	   frame the Wi-Fi driver takes, as its buffers are skb buffers that
	   will be freed to the kernel */
	count_ptr = raw_cpu_ptr(vwd.eth_priv->percpu_count);
	if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
			CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD))) {
		//if we cant refill give this up
		goto rel_fd;
	}
	*count_ptr -= 1;

	skb = contig_fd_to_vwd_skb(priv->eth_priv, &dq->fd);

	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s::contig_fd_to_vwd_skb failed\n", __func__);
		goto rel_fd;
	}

process_skb:
	skb->dev = net_dev;

	INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_fast_forwarded);
	if (dpa_bp == ipsec_bp) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_ipsec);
	}

	vwd_send_to_vap(skb);
done:
	rcu_read_unlock();
	return 0;

rel_fd:
	/* Every buffer of the frame: a scatter/gather frame's data buffers
	 * as well as its table, which is all a release of the FD's own
	 * address gave back. */
	dpa_fd_release(NULL, &dq->fd);
	goto done;
}

/* Frames every VAP's forwarding queues may hold together before QMan refuses
 * the classifier's enqueue and FMan drops the frame. The CPU drains them,
 * copying out a frame in SEC's output pool and taking one in an Ethernet pool
 * as it is, and hands each to the radio's own queue behind dev_queue_xmit(),
 * which is where Wi-Fi traffic is meant to wait. A stream faster than that
 * drain -- a tunnel at its line rate into one radio -- backed up here without
 * bound: SEC's buffers until SEC refused every SA's jobs, an Ethernet pool's
 * until the ports dropped what they received. This covers the CPU's lag, and
 * is the Wi-Fi share of SEC's pool beside the exception queues' and each
 * Ethernet port's (IPSEC_EGRESS_FRAMES). One group for every VAP, though a
 * flow's queue is drained by one CPU: a share per portal would multiply the
 * pool's commitment, and a CPU that falls behind holds the group at its
 * threshold for every VAP until it catches up. */
#define VWD_FWD_FRAMES	(IPSEC_BUFCOUNT / 8)

/* No state-change notifications, so no portal owns the group; the egress
 * groups set theirs up the same way (devman.c). */
static int vwd_fwd_cgr_init(struct dpaa_vwd_priv_s *priv)
{
	struct qm_mcc_initcgr opts;

	if (qman_alloc_cgrid(&priv->fwd_cgr.cgrid) < 0)
		return -ENOSPC;
	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_CGR_WE_MODE | QM_CGR_WE_CS_THRES | QM_CGR_WE_CSTD_EN |
		       QM_CGR_WE_CSCN_EN;
	opts.cgr.mode = QMAN_CGR_MODE_FRAME;
	opts.cgr.cstd_en = QM_CGR_EN;
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, VWD_FWD_FRAMES, 1);
	if (qman_modify_cgr(&priv->fwd_cgr, QMAN_CGR_FLAG_USE_INIT, &opts)) {
		qman_release_cgrid(priv->fwd_cgr.cgrid);
		return -EIO;
	}
	return 0;
}

/* Every VAP's queues are out of service by now, which the release requires. */
static void vwd_fwd_cgr_exit(struct dpaa_vwd_priv_s *priv)
{
	struct qm_mcc_initcgr opts;

	memset(&opts, 0, sizeof(opts));
	qman_modify_cgr(&priv->fwd_cgr, QMAN_CGR_FLAG_USE_INIT, &opts);
	qman_release_cgrid(priv->fwd_cgr.cgrid);
}

static int create_vap_fwd_from_fman_fqs(struct vap_desc_s *vap, void *proc_entry)
{
	uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	const cpumask_t *affine_cpus;

	/* get cpu portal channel info */
	num_portals = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}

	if (!num_portals) {
		DPAWIFI_ERROR("%s::unable to get affined portal info\n",
				__func__);
		return -1;
	}

	for (ii = 0; ii < CDX_VWD_FWD_FQ_MAX; ii++) {
		uint32_t flags;

		/* create FQ for forward from DPAA to wireless interface */
		dpa_fq = kzalloc(sizeof(struct dpa_fq), GFP_KERNEL);

		if (!dpa_fq) {
			DPAWIFI_ERROR("%s::unable to alloc mem for dpa_fq\n", __func__) ;
			return -1;
		}
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		fq = &dpa_fq->fq_base;
		flags = 0;

		/* fwd fq */
		fq->cb.dqrr = vap_rx_fwd_pkt;
		if (cdx_copy_eth_rx_channel_info(FMAN_IDX, dpa_fq)) {
			DPAWIFI_ERROR("%s::unable to get cpu channel info\n", __func__) ;
			kfree(dpa_fq);
			return -1;
		}

		/* opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE); */
		opts.fqd.context_a.stashing.exclusive =
			(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
		opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
		opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
		dpa_fq->fq_type = FQ_TYPE_RX_PCD;
		dpa_fq->wq = DEFA_VWD_WQ_ID;
		dpa_fq->net_dev = vap->wifi_dev;

		if (!dpa_fq->fqid)
			flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;

		if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
			DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
					__func__, dpa_fq->fqid);
			kfree(dpa_fq);
			return -1;
		}

		dpa_fq->channel = portal_channel[ii % num_portals];

		dpa_fq->fqid = fq->fqid;
		opts.fqid = dpa_fq->fqid;
		opts.count = 1;
		opts.fqd.dest.channel = dpa_fq->channel;
		opts.fqd.dest.wq = dpa_fq->wq;
		opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA |
				QM_INITFQ_WE_CGID);
		opts.fqd.fq_ctrl = QM_FQCTRL_CGE;
		opts.fqd.cgid = (u8)vap->vwd->fwd_cgr.cgrid;
		if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
			DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
					__func__, dpa_fq->fqid);
			qman_destroy_fq(fq, 0);
			kfree(dpa_fq);
			return -1;
		}	

		/* TX OH2 */
		cdx_create_type_fqid_info_in_procfs(fq, TX_DIR, proc_entry, NULL);
		vap->wlan_fq_from_fman[ii] = dpa_fq;

#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s::created fq %x(%d) for wlan packets "
				"channel 0x%x\n", __func__,
				dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
	}

	return 0;
}

static int create_vap_fqs(struct vap_desc_s *vap)
{
	struct dpa_iface_info *oh_iface_info;
	uint32_t portid;

	/*get port id required for FQ creation*/
	if (get_ofport_portid(FMAN_IDX, vap->vwd->oh_port_handle, &portid)) {
		DPAWIFI_ERROR("%s::err getting of port id\n", __func__) ;
		return -1;
	}
	DPAWIFI_INFO("%s:portid %d \n", __func__, portid);

	if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
		DPAWIFI_ERROR("%s::err getting oh iface info of port id %u\n", __func__, portid) ;
		return -1;
	}
	if (oh_iface_info->tx_proc_entry == NULL)
	{
		DPAWIFI_ERROR("%s()::%d OH iface tx proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}

	if (create_vap_fwd_from_fman_fqs(vap, oh_iface_info->tx_proc_entry)) {
		DPAWIFI_ERROR("%s::unable to create fwd fqs\n", __func__) ;
		return -1;
	}
	return 0;
}

/* Whether a slot's forwarding queues exist. They are created in order, and
 * vwd_vap_up() releases every one already made if any of them fails, so the
 * last one standing means every one does. */
static bool vwd_vap_fqs_built(const struct vap_desc_s *vap)
{
	return READ_ONCE(vap->wlan_fq_from_fman[CDX_VWD_FWD_FQ_MAX - 1]) != NULL;
}

static int release_vap_fqs(struct vap_desc_s *vap)
{
	int i;

	for (i = 0; i < CDX_VWD_FWD_FQ_MAX; i++) {
		if (vap->wlan_fq_from_fman[i])
		{
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s:: releasing fq from fman :%d\n", __func__, vap->wlan_fq_from_fman[i]->fqid);
#endif
			cdx_destroy_fq(&vap->wlan_fq_from_fman[i]->fq_base);
			kfree(vap->wlan_fq_from_fman[i]);
			vap->wlan_fq_from_fman[i] = NULL;
		}
	}
	return 0;
}

int dpaa_get_vap_fwd_fq(uint16_t vap_id, uint32_t* fqid, uint32_t hash)
{
	struct dpa_fq *dpa_fq;

	/* A slot's queues exist only from its first open. cdx_wifi_vap_add()
	 * creates the devman record before it opens the slot, so the encoder
	 * can ask about a slot that has none; answer failure, not a NULL. */
	if (vap_id >= MAX_WIFI_VAPS)
		return -1;
	dpa_fq = vwd.vaps[vap_id].wlan_fq_from_fman[hash & (CDX_VWD_FWD_FQ_MAX - 1)];
	if (!dpa_fq)
		return -1;
	*fqid = dpa_fq->fqid;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: fwd_fq :%x\n",__func__, *fqid);
#endif
	return 0;
}

/* This function returns  WIFI related OH port handle */
int dpaa_get_wifi_ohport_handle( uint32_t* oh_handle)
{
	*oh_handle = vwd.oh_port_handle;
	return 0;
}


/* Both publish to the lock-free dequeue path, process_vap_rx_fwd_pkt(). */
static int set_vap_fqs_netdev(struct vap_desc_s *vap)
{
	int index = 0;
	for (index = 0; index < CDX_VWD_FWD_FQ_MAX; index++)
		WRITE_ONCE(vap->wlan_fq_from_fman[index]->net_dev, vap->wifi_dev);
	return 0;
}

/*
 * This function resets the vap fq net_dev to NULL.
 */
static int reset_vap_fqs_netdev(struct vap_desc_s *vap)
{
	int index = 0;
	for (index = 0; index < CDX_VWD_FWD_FQ_MAX; index++)
		WRITE_ONCE(vap->wlan_fq_from_fman[index]->net_dev, NULL);
	return 0;
}

static int vwd_vap_up(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
	struct net_device *wifi_dev;

	wifi_dev = dev_get_by_name(&init_net, cmd->ifname);
	if (!wifi_dev) {
		DPAWIFI_ERROR("%s::No WiFi device %s\n", 
				__func__, &cmd->ifname[0]);
		return -1;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: wifidev found.. %s\n", __func__, cmd->ifname);
#endif
	if (!(wifi_dev->flags & IFF_UP)) {
		DPAWIFI_ERROR("%s::WiFi device %s not UP\n",
				__func__, &cmd->ifname[0]);
		dev_put(wifi_dev);
		return -1;
	}

	vap->ifindex = cmd->ifindex;

	memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->wifi_dev = wifi_dev;
	vap->vwd = priv;

	/* A slot opened for the first time creates its frame queues, which
	   are kept until the cdx module is unloaded. */
	if (!vwd_vap_fqs_built(vap))
	{
		/* create frame queues */
		if (create_vap_fqs(vap)) {
			DPAWIFI_ERROR("%s::unable to create vap fqs for device %s\n",
					__func__, &cmd->ifname[0]);
			release_vap_fqs(vap);
			vap->wifi_dev = NULL;
			dev_put(wifi_dev);
			return -1;
		}
	}
	else
	{
		set_vap_fqs_netdev(vap);
	}

	/* In struct net_device , wifi_offload_dev field is defined,
	 * using this field to store the vap_desc_t structure pointer.
	 * Published only now, after the FQs are live: the forwarding
	 * dequeue path consumes this pointer lock-free, so a
	 * release-publish after the FQ stores is what keeps it from seeing
	 * a half-built VAP. The caller flips vap->state to VAP_ST_OPEN
	 * under vaplock.
	 */
	vap->generation++;
	smp_store_release(&wifi_dev->wifi_offload_dev,
			(struct net_device *)vap);

	dev_put(wifi_dev);
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: UP: name:%s, vapid:%d, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
			__func__, vap->ifname, vap->vapid, vap->ifindex,
			vap->macaddr[0], vap->macaddr[1],
			vap->macaddr[2], vap->macaddr[3],
			vap->macaddr[4], vap->macaddr[5] );

#endif
	return 0;
}

static int vwd_vap_down(struct dpaa_vwd_priv_s *priv , struct vap_desc_s *vap)
{
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
	DPAWIFI_INFO("%s:DOWN: name:%s, vapid:%d, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
			__func__, vap->ifname, vap->vapid, vap->ifindex,
			vap->macaddr[0], vap->macaddr[1],
			vap->macaddr[2], vap->macaddr[3],
			vap->macaddr[4], vap->macaddr[5] );
#endif

	/* unpublish from the lock-free dequeue path first, then tear down
	 * the fq netdev links it would have used */
	if(vap->wifi_dev)
		WRITE_ONCE(vap->wifi_dev->wifi_offload_dev, NULL);

	reset_vap_fqs_netdev(vap);

	smp_store_release(&vap->state, VAP_ST_CONFIGURED);

	vap->wifi_dev = NULL;

	return 0;
}

/** vwd_vap_configure
 *
 */
static int vwd_vap_configure(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
	vap->vapid = cmd->vapid;
	vap->ifindex = cmd->ifindex;
	/* The whole name, not the first 12 bytes of it. Both sides are
	 * IFNAMSIZ and the hard-coded length silently truncated anything
	 * longer -- which CMM never produced, because it named VAPs from a
	 * config file that used short ones. A name taken from a netdev has no
	 * such habit, and the truncated copy is what the sysfs attribute below
	 * is named after, so the damage would show up as a mislabelled stats
	 * file rather than as anything failing. */
	strscpy(vap->ifname, (const char *)cmd->ifname, sizeof(vap->ifname));
	memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->state = VAP_ST_CONFIGURED;

	/* Configure sysfs attributes */
	dev_attr_vap[vap->vapid].attr.name=vap->ifname;
	dev_attr_vap[vap->vapid].attr.mode=0444;
	dev_attr_vap[vap->vapid].show=vwd_show_vap_stats;
	dev_attr_vap[vap->vapid].store = NULL;

	return 0;
}

/* Clear every netdev's wifi_offload_dev alias pointing at this VAP —
 * the wifi netdev itself and any VLAN-on-vap device
 * vwd_publish_vlan_aliases() copied the pointer onto. Caller holds rtnl
 * (dpaa_vwd_vap_cmd() asserts it), which is what makes the netdev walk
 * safe. */
static void vwd_unpublish_vap(struct vap_desc_s *vap)
{
	struct net_device *dev;

	ASSERT_RTNL();
	for_each_netdev(&init_net, dev) {
		if (READ_ONCE(dev->wifi_offload_dev) ==
				(struct net_device *)vap)
			WRITE_ONCE(dev->wifi_offload_dev, NULL);
	}
}

/* Publish the vap pointer onto VLAN devices riding on its wifi netdev,
 * by netdev relationship, each time the VAP opens: a REMOVE clears the
 * aliases and nothing else puts them back. Safe for any such VLAN: ESP
 * arriving on it did not arrive on an SA's own DPAA port, so the DPAA
 * driver gives it back rather than submit it to SEC, and xfrm drops it
 * for an SA the hardware holds. Caller holds rtnl. */
static void vwd_publish_vlan_aliases(struct vap_desc_s *vap)
{
	struct net_device *dev;

	ASSERT_RTNL();
	if (!vap->wifi_dev)
		return;
	for_each_netdev(&init_net, dev) {
		if (is_vlan_dev(dev) &&
		    vlan_dev_real_dev(dev) == vap->wifi_dev)
			WRITE_ONCE(dev->wifi_offload_dev,
					(struct net_device *)vap);
	}
}

/** dpaa_vwd_handle_vap
 *
 */
static int dpaa_vwd_handle_vap( struct dpaa_vwd_priv_s *priv, struct vap_cmd_s *cmd )
{
	int rc = 0;
	int create_sysfs = 0, remove_sysfs = 0;
	struct vap_desc_s *vap;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO( "%s function called %d: %s\n", __func__, cmd->action, cmd->ifname);
#endif
	if (cmd->vapid < 0) {
		DPAWIFI_ERROR("%s : Invalid VAPID (%d)\n", __func__, cmd->vapid);
		return -1;
	}

	if (cmd->vapid >= MAX_WIFI_VAPS) {
		DPAWIFI_ERROR("%s : VAPID (%d)  >=  MAX_WIFI_VAPS(%d)\n", __func__, cmd->vapid, MAX_WIFI_VAPS);
		return -1;
	}

	spin_lock_bh(&priv->vaplock);
	vap = &priv->vaps[cmd->vapid];
	switch (cmd->action) {
		case CONFIGURE:
			DPAWIFI_INFO("%s: CONFIGURE ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_CLOSE) {
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not in close state\n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}

			if (!(rc = vwd_vap_configure(priv, vap, cmd)))
			{
				DPAWIFI_INFO("%s: Configured VAP (id : %d  name : %s)\n", __func__, cmd->vapid, cmd->ifname);
				/* device_create_file sleeps; do it after the
				 * final unlock below */
				create_sysfs = 1;
			}
			else
			{
				DPAWIFI_ERROR("%s: Failed to configure VAP (id : %d  name : %s)\n",
						__func__, cmd->vapid, cmd->ifname);
			}
			break;


		case ADD:
			DPAWIFI_INFO("%s: ADD ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_CONFIGURED) {
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not configured \n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}

			/* vwd_vap_up sleeps (GFP_KERNEL allocs, qman FQ
			 * setup) and must not run under the BH spinlock the
			 * softirq dequeue paths share. Claim the slot so a
			 * concurrent command sees it mid-transition and bails;
			 * the dequeue path keys on VAP_ST_OPEN /
			 * wifi_offload_dev and stays away. */
			vap->state = VAP_ST_CONFIGURING;
			spin_unlock_bh(&priv->vaplock);
			rc = vwd_vap_up(priv, vap, cmd);
			if (!rc)
				vwd_publish_vlan_aliases(vap);
			spin_lock_bh(&priv->vaplock);
			if (rc < 0)
			{
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not UP \n",
						__func__, cmd->vapid, cmd->ifname);
				vap->state = VAP_ST_CONFIGURED;
				rc = -1;
			}
			else
			{
				/* Last: the dequeue path reads this first, and
				 * the queues' device pointers were stored above. */
				smp_store_release(&vap->state, VAP_ST_OPEN);
			}
			break;
		case REMOVE:
			DPAWIFI_INFO("%s: REMOVE ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_OPEN) {
				DPAWIFI_INFO("%s : VAP (id : %d  name : %s) is not opened \n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}
			/* Claim the slot (other commands are also rtnl-
			 * serialized; the claim additionally keeps the exit
			 * walk away), unpublish every wifi_offload_dev alias
			 * and wait out in-flight lock-free consumers before
			 * vwd_vap_down tears down the fq netdev links they
			 * use. synchronize_rcu sleeps, hence the unlock. */
			vap->state = VAP_ST_CONFIGURING;
			spin_unlock_bh(&priv->vaplock);
			vwd_unpublish_vap(vap);
			synchronize_rcu();
			spin_lock_bh(&priv->vaplock);
			vwd_vap_down(priv, vap);

			break;
		case RELEASE:
			/* Hand a slot back to the free pool.
			 *
			 * REMOVE stops at VAP_ST_CONFIGURED, leaving the
			 * configured fields in place. Once a VAP's netdev is
			 * gone its slot has to become reusable by a different
			 * device, and a CONFIGURE onto a slot still holding the
			 * old ifname is refused -- so without this the id space
			 * would drain one VAP at a time until the allocator
			 * wrapped onto an unusable slot. The sysfs attribute
			 * goes with it: it is named after the old interface,
			 * and a later CONFIGURE would otherwise double-create
			 * it.
			 */
			DPAWIFI_INFO("%s: RELEASE ... %s\n", __func__, vap->ifname);
			if (vap->state != VAP_ST_CONFIGURED) {
				DPAWIFI_ERROR("%s : VAP (id : %d) is not configured\n",
						__func__, cmd->vapid);
				rc = -1;
				break;
			}
			vap->state = VAP_ST_CLOSE;
			remove_sysfs = 1;
			break;

		default:
			DPAWIFI_INFO("%s::unhandled cmd %d\n", __func__, cmd->action);
			rc = -1;
			break;
	}

	spin_unlock_bh(&priv->vaplock);

	/* device_create_file() and device_remove_file() sleep, so both run
	 * here, after the unlock. */
	if (create_sysfs) {
		/* Create sysfs entry for vap interface */
		if (device_create_file(priv->vwd_device, &dev_attr_vap[cmd->vapid])) {
			DPAWIFI_ERROR("%s::unable to create sysfs entry for vap iface %s\n",
					__func__, cmd->ifname);
		}
	}
	if (remove_sysfs)
		device_remove_file(priv->vwd_device, &dev_attr_vap[cmd->vapid]);
	return rc;

}

/* The VAP table's one door, driven by cdx_wifi_backend.c from netdev events.
 * RTNL is asserted rather than taken: the notifier-driven caller already
 * holds it, and taking it here would deadlock. */
int dpaa_vwd_vap_cmd(struct vap_cmd_s *cmd)
{
	ASSERT_RTNL();
	if (READ_ONCE(vwd_stopping))
		return -ENODEV;
	return dpaa_vwd_handle_vap(&vwd, cmd);
}

/* Whether VWD is up far enough to hold a VAP. False before dpaa_vwd_init()
 * has finished and again as soon as teardown starts, which is what makes it
 * safe to ask from a notifier that may be running against either edge. */
bool dpaa_vwd_ready(void)
{
	return !READ_ONCE(vwd_stopping);
}

/* Whether this device is a VAP the classifier may enqueue to right now.
 *
 * VAP_ST_OPEN and nothing weaker. A slot that is merely configured has no
 * frame queues yet -- they are built during the transition to open -- so an
 * entry naming one would enqueue into nothing, and a slot mid-transition is
 * refused rather than queued for the same reason. The state is read under
 * vaplock because that is what the transition holds.
 */
bool dpaa_vwd_vap_is_open(const struct net_device *dev)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	bool open = false;
	int ii;

	if (!dev || READ_ONCE(vwd_stopping))
		return false;
	spin_lock_bh(&priv->vaplock);
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		if (priv->vaps[ii].state == VAP_ST_OPEN &&
		    priv->vaps[ii].wifi_dev == dev) {
			open = true;
			break;
		}
	}
	spin_unlock_bh(&priv->vaplock);
	return open;
}

/* Whether VWD still binds this slot to this device. The devman record that
 * names a VAP by id is freed one workqueue hop after the device goes, and a
 * netdev freed and reallocated inside that hop would otherwise match the
 * stale record by address alone. Released slots keep their device pointer,
 * so the state is part of the answer.
 */
bool dpaa_vwd_vap_owns(uint16_t vap_id, const struct net_device *dev)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	bool owns;

	if (!dev || vap_id >= MAX_WIFI_VAPS || READ_ONCE(vwd_stopping))
		return false;
	spin_lock_bh(&priv->vaplock);
	owns = priv->vaps[vap_id].wifi_dev == dev &&
	       priv->vaps[vap_id].state != VAP_ST_CLOSE;
	spin_unlock_bh(&priv->vaplock);
	return owns;
}

/* Whether this slot already carries its frame queues. They are built on a
 * slot's first open and kept until module exit, so a slot that has them is
 * cheaper to hand out again than a fresh one, and the id allocator prefers
 * it for that reason.
 */
bool dpaa_vwd_vap_built(uint16_t vap_id)
{
	if (vap_id >= MAX_WIFI_VAPS || READ_ONCE(vwd_stopping))
		return false;
	return vwd_vap_fqs_built(&vwd.vaps[vap_id]);
}

static int vwd_init_ohport(struct dpaa_vwd_priv_s *priv)
{
	int handle;

	/* Claim the Wi-Fi offline port. Its port id is what names a VAP to the
	 * classifier (see get_wlan_iface_info()), but nothing enqueues frames
	 * into the port itself: a flow leaving through a VAP is enqueued by the
	 * classifier straight to the VAP's forwarding queues. So its default and
	 * error queues keep devoh.c's own handlers, which report and release
	 * whatever should ever arrive there. */
	handle = alloc_offline_port(FMAN_IDX, PORT_TYPE_WIFI, NULL, NULL);
	if (handle < 0)
	{
		DPAWIFI_ERROR("%s: Error in allocating OH port Channel\n", __func__);
		return -1;
	}
	priv->oh_port_handle = handle;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: allocated oh port %d\n", __func__, priv->oh_port_handle);
#endif
	return 0;
}

static int vwd_init_stats(struct dpaa_vwd_priv_s *priv)
{
	int i = 0;

	/* Allocate per cpu structure for each vap */
	for (i = 0; i< MAX_WIFI_VAPS; i++) {
		priv->vaps[i].vap_stats = alloc_percpu(struct vap_stats_s);
		if (!priv->vaps[i].vap_stats)
			return -1;
	}

	/* Allocate per cpu structure for vwd global stats */
	priv->vwd_global_stats = alloc_percpu(struct vwd_global_stats_s);
	if (!priv->vwd_global_stats)
		return -1;
	return 0;
}

static void vwd_release_stats(struct dpaa_vwd_priv_s *priv)
{
	int i = 0;
	/* Free up the per cpu structure of each vap */
	for (i = 0; i< MAX_WIFI_VAPS; i++) {
		if (priv->vaps[i].vap_stats) {
			free_percpu(priv->vaps[i].vap_stats);
			priv->vaps[i].vap_stats = NULL;
		}
	}

	/* Free up the per cpu structure of vwd global stats */
	if (priv->vwd_global_stats) {
		free_percpu(priv->vwd_global_stats);
		priv->vwd_global_stats = NULL;
	}
}

static int vwd_free_ohport(struct dpaa_vwd_priv_s *priv)
{

	int rc;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: releasing oh port %d\n", __func__, priv->oh_port_handle);
#endif
	rc = release_offline_port(FMAN_IDX, priv->oh_port_handle);
	if (rc < 0)
	{
		DPAWIFI_ERROR("%s: Error in releasing OH port Channel\n", __func__);
		return -1;
	}

	return 0;
}

/* NETDEV_UNREGISTER teardown: cdx deliberately holds no ref on the
 * wifi netdev (vwd_vap_up dev_puts after publishing), so an unregister
 * while a VAP is OPEN would leave vap->wifi_dev and the fq net_dev
 * links dangling. Notifiers run in process context under rtnl, so the
 * unpublish + grace + down sequence the REMOVE arm uses works
 * here too. Upper devices (VLAN aliases) unregister before their real
 * device and each event clears its own dev's pointer. */
static int vwd_netdev_event(struct notifier_block *nb,
		unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vap_desc_s *found = NULL;
	struct net_device *p;
	int ii;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	p = READ_ONCE(dev->wifi_offload_dev);
	if ((void *)p >= (void *)&priv->vaps[0] &&
	    (void *)p < (void *)&priv->vaps[MAX_WIFI_VAPS])
		WRITE_ONCE(dev->wifi_offload_dev, NULL);

	/* claim every OPEN vap riding on the dying dev (a pathological
	 * config can point several at one ifname) */
	spin_lock_bh(&priv->vaplock);
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		struct vap_desc_s *vap = &priv->vaps[ii];

		if (vap->state == VAP_ST_OPEN && vap->wifi_dev == dev) {
			vap->state = VAP_ST_CONFIGURING;
			found = vap;
		}
	}
	spin_unlock_bh(&priv->vaplock);

	if (found) {
		/* clear the claimed vaps' remaining aliases ourselves
		 * rather than relying on upper devices (8021q) having
		 * unregistered first — rtnl is held here */
		for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
			struct vap_desc_s *vap = &priv->vaps[ii];

			if (vap->state == VAP_ST_CONFIGURING &&
					vap->wifi_dev == dev)
				vwd_unpublish_vap(vap);
		}
		/* wait out in-flight lock-free consumers before the fq
		 * net_dev links go; the netdev itself outlives the
		 * notifier chain, so vwd_vap_down's derefs are safe */
		synchronize_rcu();
		spin_lock_bh(&priv->vaplock);
		for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
			struct vap_desc_s *vap = &priv->vaps[ii];

			if (vap->state == VAP_ST_CONFIGURING &&
					vap->wifi_dev == dev)
				vwd_vap_down(priv, vap);
		}
		spin_unlock_bh(&priv->vaplock);
	}
	return NOTIFY_DONE;
}

static struct notifier_block vwd_netdev_notifier = {
	.notifier_call = vwd_netdev_event,
};

/** dpaa_vwd_up
 *
 */
static int dpaa_vwd_up(struct dpaa_vwd_priv_s *priv)
{
	int ret;

	ret = register_netdevice_notifier(&vwd_netdev_notifier);
	if (ret)
		return ret;
	ret = dpaa_vwd_sysfs_init(priv);
	if (ret)
		goto err_sysfs;
	return 0;

err_sysfs:
	unregister_netdevice_notifier(&vwd_netdev_notifier);
	return ret;
}

/** dpaa_vwd_down
 *
 */
static int dpaa_vwd_down( struct dpaa_vwd_priv_s *priv )
{
	int ii;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO( "%s: %s\n", priv->name, __func__);
#endif
	DECLARE_BITMAP(attr_mask, MAX_WIFI_VAPS);
	struct net_device *dev;

	bitmap_zero(attr_mask, MAX_WIFI_VAPS);

	/* unregister_netdevice_notifier replays a synthesized
	 * NETDEV_UNREGISTER for every live netdev to the departing
	 * notifier, so this line already runs the notifier's
	 * claim/grace/down sequence for each still-OPEN vap; the walk
	 * below then finds them CONFIGURED and still releases their FQs
	 * and attrs exactly once via the masks */
	unregister_netdevice_notifier(&vwd_netdev_notifier);
	/* Wait out in-flight lock-free consumers of the VAPs' published
	 * pointers so release_vap_fqs below can't free FQs under them. */
	synchronize_rcu();

	/* rtnl taken for the whole vap teardown: it drains any in-flight
	 * vap command (dpaa_vwd_vap_cmd() runs under rtnl), so no slot can
	 * be mid-ADD when the walk below runs, and it covers the netdev walk
	 * in the alias sweep. Commands arriving after we drop it find
	 * vwd_stopping set and bail. */
	rtnl_lock();

	/* state transitions under the lock; sleeping teardown after */
	spin_lock_bh(&priv->vaplock);
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++)
	{
		struct vap_desc_s *vap = &priv->vaps[ii];

		/* unreachable now that rtnl above drains in-flight commands
		 * before this walk; kept as a defensive skip */
		if (vap->state == VAP_ST_CONFIGURING)
			continue;

		if (vap->state == VAP_ST_OPEN)
			vwd_vap_down(priv, vap);
		if (vap->state == VAP_ST_CONFIGURED) {
			__set_bit(ii, attr_mask);
			vap->state = VAP_ST_CLOSE;
		}
	}
	spin_unlock_bh(&priv->vaplock);

	/* clear every wifi_offload_dev still pointing into the vap table —
	 * covers the wifi netdevs and any VLAN-on-vap aliases; a stale
	 * pointer surviving module unload would hand a later cdx instance
	 * a dangling vap */
	for_each_netdev(&init_net, dev) {
		struct net_device *p = READ_ONCE(dev->wifi_offload_dev);

		if ((void *)p >= (void *)&priv->vaps[0] &&
		    (void *)p < (void *)&priv->vaps[MAX_WIFI_VAPS])
			WRITE_ONCE(dev->wifi_offload_dev, NULL);
	}
	rtnl_unlock();

	for (ii = 0; ii < MAX_WIFI_VAPS; ii++)
	{
		if (test_bit(ii, attr_mask))
			device_remove_file(priv->vwd_device, &dev_attr_vap[ii]);
	}
	dpaa_vwd_sysfs_exit();

	return 0;
}

/* Publish the interfaces only after their callback resources are ready. */
int dpaa_vwd_init(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int rc;

	memset(priv, 0, sizeof(*priv));
	strscpy(priv->name, "vwd", sizeof(priv->name));
	spin_lock_init(&priv->vaplock);
	WRITE_ONCE(vwd_stopping, true);

	rc = vwd_init_stats(priv);
	if (rc)
		goto err_stats;
	rc = vwd_napi_add();
	if (rc)
		goto err_stats;
	/* Any DPAA port will do: what is read from it is the buffer layout
	 * every port shares (headroom, errata handling) and a per-CPU count
	 * for refilling the pool its frames came from. It used to be "eth0"
	 * by name, which a board is free not to have. */
	priv->eth_priv = dpa_first_eth_priv();
	if (!priv->eth_priv) {
		rc = -ENODEV;
		goto err_napi;
	}
	rc = vwd_init_ohport(priv);
	if (rc < 0)
		goto err_eth;
	rc = vwd_fwd_cgr_init(priv);
	if (rc)
		goto err_oh;

	/* The class and its device carry no character device: they are where
	 * the statistics and per-VAP files live, under /sys/class/vwd/vwd0. */
	priv->vwd_class = class_create("vwd");
	if (IS_ERR(priv->vwd_class)) {
		rc = PTR_ERR(priv->vwd_class);
		goto err_cgr;
	}
	priv->vwd_device = device_create(priv->vwd_class, NULL, 0, NULL,
					 "vwd0");
	if (IS_ERR(priv->vwd_device)) {
		rc = PTR_ERR(priv->vwd_device);
		goto err_class;
	}
	rc = dpaa_vwd_up(priv);
	if (rc)
		goto err_device;

	WRITE_ONCE(vwd_stopping, false);
	register_cdx_deinit_func(dpaa_vwd_exit);
	return 0;

err_device:
	device_unregister(priv->vwd_device);
err_class:
	class_destroy(priv->vwd_class);
err_cgr:
	vwd_fwd_cgr_exit(priv);
err_oh:
	vwd_free_ohport(priv);
	synchronize_net();
err_eth:
	dev_put(priv->eth_priv->net_dev);
	priv->eth_priv = NULL;
err_napi:
	vwd_napi_del();
err_stats:
	vwd_release_stats(priv);
	return rc;
}

void dpaa_vwd_exit(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int i;

	/* Refuse VAP commands before tearing anything down. */
	WRITE_ONCE(vwd_stopping, true);
	dpaa_vwd_down(priv);
	for (i = 0; i < MAX_WIFI_VAPS; i++)
		release_vap_fqs(&priv->vaps[i]);
	vwd_fwd_cgr_exit(priv);
	vwd_free_ohport(priv);
	synchronize_net();
	/* Every queue is retired, so no poll can be scheduled any more. */
	vwd_napi_del();
	vwd_release_stats(priv);
	dev_put(priv->eth_priv->net_dev);
	priv->eth_priv = NULL;
	device_unregister(priv->vwd_device);
	class_destroy(priv->vwd_class);
}

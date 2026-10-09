/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <net/pkt_sched.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/idr.h>
#include <linux/refcount.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/irqnr.h>
#include <linux/ppp_defs.h>
#include <linux/highmem.h>
#include <linux/proc_fs.h>
#include <linux/workqueue.h>
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
#include <net/xfrm.h>
#endif

#include <linux/spinlock.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#include "portdefs.h"
#include "dpa_ipsec.h"
#include "cdx_ioctl.h"
#include "cdx.h"
#include "cdx_flowtable.h"
#include "cdx_flowtable_backend.h"
#include "misc.h"
#include "dpaa_eth_common.h"
#include "dpa_wifi.h"
#include "procfs.h"

/*
* DPA_FQ_TD_BYTES is frame queue tail drop bytes mode  threshold value. This 
* threshold is per frame queue.
*/
#define DPA_FQ_TD_BYTES	316000000

#ifdef DPA_IPSEC_OFFLOAD 
//#define DPA_IPSEC_DEBUG  	1

#define DPAIPSEC_ERROR(fmt, ...)\
{\
        printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#ifdef CDX_DPA_DEBUG
#define DPAIPSEC_INFO(fmt, ...)\
{\
        printk(KERN_INFO fmt, ## __VA_ARGS__);\
}
#else
#define DPAIPSEC_INFO(fmt, ...)
#endif

#define IPSEC_WQ_ID		2

/*
* FQ_TAIL_DROP support for the tail drop support per frame queue base.
* It means based on the on the threshold(default is in bytes mode, DPA_FQ_TD_BYTES)
* value it drops the packet per frame queue. Basically this support framework is
* added only for "to sec ipsec" frame queues only. Now it is disabled, as CS_TAIL_DROP
* support is enabled and that is sufficient. To enable FQ_TAIL_DROP support uncomment
* below macro.
*/
//#define FQ_TAIL_DROP

/*
* CS_TAIL_DROP support for the tail drop support is per congestion group record.
* Each congestion group record can have multiple frame queues can group together.
* In our case all "to sec ipsec" frame queues are grouped into one congestion group.
* This threshold works on group all frame queues bytes at that moment. This also
* by default in bytes mode. It checks thresold with CDX_DPAA_INGRESS_CS_TD.
*/
#define CS_TAIL_DROP
#ifdef CS_TAIL_DROP
struct cgr_priv {
/*	bool use_ingress_cgr;*/
	struct qman_cgr ingress_cgr;
	int cpu;
	int delete_result;
};
/* The following macro is used as default value before introducing module param */

#define SEC_CONGESTION_DISABLE	0

unsigned int sec_congestion = SEC_CONGESTION_DISABLE;
module_param(sec_congestion, uint, S_IRUGO);
MODULE_PARM_DESC(sec_congestion, "0: congestion disable n: congestion threshold");

#endif

struct dpa_ipsec_sainfo {
	void *shdesc_mem;
	struct sec_descriptor *shared_desc;
	struct dpa_fq sec_fq[NUM_FQS_PER_SA];
	void *sa_proc_entry;
	/* Nonzero when the FQIDs outlive the queues: the datapath epoch in
	 * which a classifier entry naming them could not be proven gone. See
	 * cdx_dpa_ipsecsa_keep_fqids(). */
	u32 keep_epoch;
	u16 key_tag;
};

/* FQID ranges an SA released while an entry that may still be linked named
 * them, until the datapath restart that settles the entry. Under the control
 * mutex: the SA's release runs on the CDX timer, which holds it, and so does
 * the restart. */
struct dpa_ipsec_held_fqids {
	struct list_head list;
	u32 base;
	u16 key_tag;
};
static LIST_HEAD(dpa_ipsec_held);
static DEFINE_IDA(ipsec_key_tags);
static refcount_t ipsec_key_tag_refs[VLAN_N_VID];

static void ipsec_put_key_tag(u16 tag)
{
	if (refcount_dec_and_test(&ipsec_key_tag_refs[tag]))
		ida_free(&ipsec_key_tags, tag);
}

uint32_t ipsec_get_key_tag(void *handle)
{
	return ((struct dpa_ipsec_sainfo *)handle)->key_tag;
}

/* Only before this SA's descriptor is built, under ctrl.mutex. Outbound
 * NAT-T rekeying SAs share a root; the tag outlives all of their queues. */
void ipsec_share_key_tag(void *handle, void *other)
{
	struct dpa_ipsec_sainfo *sa = handle, *owner = other;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	if (sa->key_tag == owner->key_tag)
		return;
	refcount_inc(&ipsec_key_tag_refs[owner->key_tag]);
	ipsec_put_key_tag(sa->key_tag);
	sa->key_tag = owner->key_tag;
}


struct ipsec_info {
	uint32_t crypto_channel_id;
	int ofport_handle;
	uint32_t ofport_channel;
	uint32_t ofport_portid;
	void *ofport_td[MAX_MATCH_TABLES];
	uint32_t expt_fq_count ;
	struct dpa_bp *ipsec_bp;
	/* PCD wrappers are individually allocated; SA queues are embedded in
	 * dpa_ipsec_sainfo and must only be freed by their SA owner. */
	struct dpa_fq *ipsec_pcd_fqs;
	struct dpa_fq *ipsec_exception_fq;
	struct port_bman_pool_info parent_pool_info;
#ifdef CS_TAIL_DROP
	struct cgr_priv	cgr;
	bool cgr_initialized;
#endif
	/* Every exception queue the offline port feeds: IPSEC_EXCEPTION_FRAMES. */
	struct qman_cgr exception_cgr;
	bool exception_cgr_initialized;
};

static struct ipsec_info ipsecinfo = { .ofport_handle = -1 };

/* Join a queue the offline port feeds frames to the CPU on to the exception
 * group (IPSEC_EXCEPTION_FRAMES). Once the group holds that many, QMan refuses
 * the port's enqueue and FMan drops the frame, giving its buffer back to the
 * pool: the CPU loses frames it had no time for, not SEC its output buffers. */
static void ipsec_exception_fq_bound(struct qm_mcc_initfq *opts)
{
	opts->we_mask |= QM_INITFQ_WE_CGID;
	opts->fqd.fq_ctrl |= QM_FQCTRL_CGE;
	opts->fqd.cgid = (u8)ipsecinfo.exception_cgr.cgrid;
}

#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
extern struct xfrm_state *xfrm_state_lookup_byhandle(struct net *net, u16 handle);
#endif

/* The dedicated SEC pool's BPID, which BMan hands out at runtime; -1 while
 * there is no pool. Published so BMan's count for it can be found without
 * the boot log, which a long-running system overwrites. A copy rather than a
 * read through ipsecinfo.ipsec_bp, which is freed on release. */
static int ipsec_bpid = -1;

static int ipsec_bpid_get(char *buffer, const struct kernel_param *kp)
{
	return sysfs_emit(buffer, "%d\n", READ_ONCE(ipsec_bpid));
}

static const struct kernel_param_ops ipsec_bpid_ops = {
	.get = ipsec_bpid_get,
};
module_param_cb(ipsec_bpid, &ipsec_bpid_ops, NULL, 0444);

/* Forward declarations for internal functions */
static int cdx_find_ipsec_pcd_fqinfo(int fqid, struct ipsec_info *info);
static void ipsec_addfq_to_exceptionfq_list(struct dpa_fq *frameq,
		struct ipsec_info *info);
static void ipsec_delfq_from_exceptionfq_list(uint32_t fqid,
		struct ipsec_info *info);

/* Only buffers transferred permanently to Linux need replacing. Hardware
 * acquisitions are temporary and must not inflate the pool while in flight.
 * This accounting is independent of every Ethernet port's receive pool. */
static atomic_t ipsec_pool_debt = ATOMIC_INIT(0);
static bool ipsec_refill_enabled;
static void ipsec_pool_refill_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(ipsec_refill_work, ipsec_pool_refill_work);

static void ipsec_pool_refill_work(struct work_struct *work)
{
	unsigned int budget = 64;
	unsigned long delay = 0;

	if (!smp_load_acquire(&ipsec_refill_enabled))
		return;
	/* Completed input skbs may carry the last reference to a deleted SA.
	 * Reap them even when no further traffic arrives to reuse their SGT. */
	dpaa_sec_sg_reap(64);
	while (budget-- && atomic_read(&ipsec_pool_debt)) {
		/* A one-buffer request cannot partially succeed. Retain its debt
		 * on any allocation/DMA failure and retry even if SEC has no
		 * buffers left to generate another receive callback. */
		if (dpaa_bp_alloc_n_add_buffs(ipsecinfo.ipsec_bp, 1, true)) {
			delay = msecs_to_jiffies(20);
			break;
		}
		atomic_dec(&ipsec_pool_debt);
	}
	/* Retry a spent refill budget immediately; idle polling and allocation
	 * failures wait so neither an empty pool nor an idle tunnel spins. */
	if (!atomic_read(&ipsec_pool_debt))
		delay = msecs_to_jiffies(20);
	if (smp_load_acquire(&ipsec_refill_enabled))
		schedule_delayed_work(&ipsec_refill_work, delay);
}

static void ipsec_pool_consumed(unsigned int count)
{
	/* New debt must not wait behind idle reaping. Further receive events
	 * retain the failure backoff while outstanding debt is already queued. */
	if (atomic_add_return(count, &ipsec_pool_debt) == (int)count &&
	    smp_load_acquire(&ipsec_refill_enabled))
		mod_delayed_work(system_wq, &ipsec_refill_work, 0);
}

static void ipsec_pool_refill_start(void)
{
	atomic_set(&ipsec_pool_debt, 0);
	smp_store_release(&ipsec_refill_enabled, true);
	schedule_delayed_work(&ipsec_refill_work, 0);
}

static void ipsec_pool_refill_stop(void)
{
	WRITE_ONCE(ipsec_refill_enabled, false);
	cancel_delayed_work_sync(&ipsec_refill_work);
}
struct dpa_bp* get_ipsec_bp(void)
{
	return (ipsecinfo.ipsec_bp);
}
struct sec_descriptor *get_shared_desc(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->shared_desc);
}

uint32_t get_fqid_to_sec(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_SEC].fqid);
}

struct qman_fq *get_to_sec_fq(void *handle)
{
	return (struct qman_fq *)&(((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_SEC]);
} 

uint32_t ipsec_get_to_cp_fqid(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_CP].fqid);
}

extern struct dpa_bp *sg_bpool_g; // buffer reqd to frame SG list for skb fraglist
extern struct dpa_bp *skb_2bfreed_bpool_g; //if no recyclable skbs exist in skb fraglist, those should be freed back, SEC engine will add to this bman pool

/* Drop a frame an SA queue gave back without delivering it: one QMan
 * rejected, or one left on a queue being emptied for the SA's release. The
 * buffers behind it still belong to their BMan pools, and one not given back
 * is lost for good: under load that empties the pool SEC writes into, and
 * every later SEC job fails.
 *
 * A software input to SEC is a scatter/gather frame whose table comes from
 * the SEC input pool and still owns its skb and payload mappings; it is
 * completed the way normal reuse and the idle reaper complete one. Anything else
 * -- a frame FMan classified onto TO_SEC, or SEC's output on FROM_SEC -- is
 * plain pool buffers, contiguous or scatter/gather.
 *
 * QMan portal context (softirq or hardirq, no sleeping): the releases spin
 * on BMan, nothing is allocated, and the skb free is the any-context one. */
static void dpa_ipsec_fd_drop(const struct qm_fd *fd)
{
	struct dpa_bp *done = READ_ONCE(skb_2bfreed_bpool_g);

	if (fd->format == qm_fd_sg && done && READ_ONCE(sg_bpool_g) &&
	    fd->bpid == done->bpid) {
		dpaa_sec_sg_release(fd, true);
		return;
	}
	dpa_fd_release(NULL, fd);
}

/*
 * QMan Enqueue-Reject Notification on FQ_TO_SEC.
 *
 * QMan rejects a software enqueue (FQ retired/OOS, congestion, etc.) and the
 * rejected FD is delivered here, to be given back (ISSUES.md A24). Counted,
 * with a rate-gated dmesg line, so a wedge is observable.
 */
static atomic_t dpa_ipsec_ern_count = ATOMIC_INIT(0);

static void dpa_ipsec_ern_cb(struct qman_portal *qm, struct qman_fq *fq,
		const struct qm_mr_entry *msg)
{
	const struct qm_fd *fd = &msg->ern.fd;
	int n = atomic_inc_return(&dpa_ipsec_ern_count);

	if (n <= 16 || (n & 0xff) == 0)
		pr_warn_ratelimited(
			"cdx: IPsec ERN on FQ 0x%x rc=0x%02x bpid=%u addr=0x%llx (count=%d)\n",
			fq->fqid, msg->ern.rc, fd->bpid,
			(unsigned long long)qm_fd_addr_get64(fd), n);
	dpa_ipsec_fd_drop(fd);
}

/* FROM_SEC and TO_SEC are consumed by hardware, SEC and the offline port, and
 * software dequeues them only to empty them for the SA's release
 * (cdx_dpa_ipsec_fq_stop()): what is left on them then is dropped. A volatile
 * dequeue can end on an entry with no frame. */
static enum qman_cb_dqrr_result dpa_ipsec_drain_dqrr(struct qman_portal *qm,
		struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
	if (dq->stat & QM_DQRR_STAT_FD_VALID)
		dpa_ipsec_fd_drop(&dq->fd);
	return qman_cb_dqrr_consume;
}

/* A decrypted frame Linux takes is copied out of SEC's output pool, and its
 * buffer goes straight back to it. Handed to the stack instead, the buffer is
 * missing from the pool until the refill worker replaces it, and a stream of
 * misses as fast as SEC can decrypt keeps the whole pool on that loan: SEC
 * then refuses every SA's jobs for want of an output buffer, at whatever rate
 * the worker allocates. The copy is one frame, into an skb its own size. NULL,
 * with the buffer given back, when no skb can be had. */
static struct sk_buff *ipsec_copy_contig_fd(struct net_device *net_dev,
		const struct dpa_bp *dpa_bp, const struct qm_fd *fd)
{
	dma_addr_t addr = qm_fd_addr(fd);
	unsigned int off = dpa_fd_offset(fd), len = dpa_fd_length(fd);
	struct sk_buff *skb = NULL;

	if (likely(off + len <= dpa_bp->size)) {
		dma_sync_single_range_for_cpu(dpa_bp->dev, addr, off, len,
					      DMA_BIDIRECTIONAL);
		skb = netdev_alloc_skb(net_dev, off + len);
		if (likely(skb)) {
			skb_reserve(skb, off);
			skb_put_data(skb, phys_to_virt(addr) + off, len);
		}
		dma_sync_single_range_for_device(dpa_bp->dev, addr, off, len,
						 DMA_BIDIRECTIONAL);
	}
	dpa_fd_release(net_dev, fd);
	return skb;
}



extern 	struct net_device *get_netdev_of_SA_by_fqid(uint32_t fqid,
		uint16_t *sagd_pkt, uint16_t *tag);
static enum qman_cb_dqrr_result ipsec_exception_pkt_handler(struct qman_portal *qm,
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{

	/* Decrypted frames that missed hardware forwarding re-enter Linux. */
	uint8_t *ptr;
	struct sk_buff *skb;
	struct net_device *net_dev;
	struct dpa_bp *dpa_bp;
	struct dpa_priv_s               *priv;
	struct dpa_percpu_priv_s        *percpu_priv;
	unsigned short eth_type;
	unsigned short sagd_pkt;
	uint16_t tag;
	struct sec_path *sp;
	struct xfrm_state *x;
	bool use_gro;
	int pool_balance = 0;
	gro_result_t gro_result;
	const struct qman_portal_config *pc;
	struct dpa_napi_portal *np;

	/* A volatile dequeue may finish without a frame descriptor. */
	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	/* The exception queue identifies the receiving SA and device. */
	net_dev = get_netdev_of_SA_by_fqid(dq->fqid, &sagd_pkt, &tag);

	if(!net_dev ){
#ifdef DPA_IPSEC_DEBUG
		DPAIPSEC_INFO("%s:: Could not find or delete mark set in inbound SA, droping pkt \n",__func__);
#endif
		goto rel_fd;
	}

	/* The frame is delivered below through this device's receive context,
	 * read from its private area as a DPAA port's. The SA's device is the
	 * port it is bound to, which admission accepts only when it is one;
	 * any other device's private area is some other driver's state, so
	 * the frame is dropped rather than built from it. */
	if (unlikely(!dpa_netdev_is_dpaa(net_dev))) {
		dev_core_stats_rx_dropped_inc(net_dev);
		pr_err_ratelimited(
			"cdx: IPsec SA 0x%x is bound to %s, not a DPAA port - dropping\n",
			sagd_pkt, net_dev->name);
		goto rel_fd;
	}

	/* A frame SEC refused, which this queue is not expected to carry: the
	 * offline port's microcode checks SEC's status on the way here, counts
	 * a refusal and drops the frame in FMan (see the adapter's
	 * ft_sec_refusals_fold()). One that got through anyway would still be
	 * SEC's output for a job it refused -- for a replay the whole decrypted
	 * packet, since SEC checks the ICV before the window -- and delivering
	 * it would pass it off as authenticated. Dropped, and said out loud,
	 * because it means FMan no longer does what the accounting counts on. */
	if (unlikely(dq->fd.status & FM_FD_RX_STATUS_ERR_NON_FM)) {
		pr_err_ratelimited(
			"cdx: IPsec SEC error on %s, fqid=0x%x sagd=0x%x status=0x%08x - dropping\n",
			net_dev->name, dq->fqid, sagd_pkt, dq->fd.status);
		goto rel_fd;
	}

	use_gro = !!(net_dev->features & NETIF_F_GRO);
	if ((x = xfrm_state_lookup_byhandle(dev_net(net_dev), sagd_pkt )) == NULL)
	{
#ifdef DPA_IPSEC_DEBUG
		DPAIPSEC_INFO("%s(%d) xfrm_state not found. Dropping pkt\n", __func__,__LINE__);
#endif
		goto rel_fd;
	}

	/* Output-root misses carry ciphertext. They must never be labelled
	 * as an authenticated inbound packet when returned to Linux. */
	if (unlikely(x->xso.dir != XFRM_DEV_OFFLOAD_IN)) {
		xfrm_state_put(x);
		goto rel_fd;
	}

	priv = netdev_priv(net_dev); 
	DPA_BUG_ON(!priv);
	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, qm)))
	{
		DPAIPSEC_ERROR("%s(%d) dpaa_eth_napi_schedule failed\n",
				__func__,__LINE__);
		xfrm_state_put(x);
		return qman_cb_dqrr_stop;
	}
#endif /* CONFIG_FSL_ASK_QMAN_PORTAL_NAPI */

	/* sg_fd_to_skb accounts each data buffer and the recycled SGT in
	 * this packet-local balance. It must never touch the Ethernet count. */
	dpa_bp = dpa_bpid2pool(dq->fd.bpid);
	if (unlikely(!dpa_bp)) {
		xfrm_state_put(x);
		goto rel_fd;
	}
	if (likely(dq->fd.format == qm_fd_contig)) {
		skb = ipsec_copy_contig_fd(net_dev, dpa_bp, &dq->fd);
		if (unlikely(!skb)) {
			dev_core_stats_rx_dropped_inc(net_dev);
			xfrm_state_put(x);
			return qman_cb_dqrr_consume;
		}
		/* As contig_fd_to_skb() leaves a frame whose L4 checksum FMan
		 * did not vouch for: CHECKSUM_NONE, and no GRO. */
		use_gro = false;
	} else {
		/* Conversion owns the buffers from here. SG conversion also
		 * returns the table to BMan after remapping it, so unmap its
		 * old mapping first. */
		dma_unmap_single(dpa_bp->dev, qm_fd_addr(&dq->fd), dpa_bp->size,
				 DMA_BIDIRECTIONAL);
		skb = sg_fd_to_skb(priv, &dq->fd, &use_gro, &pool_balance, false);
		percpu_priv->rx_sg++;
		pool_balance--;
		ipsec_pool_consumed(-pool_balance);
	}

	if (unlikely(!pskb_may_pull(skb, ETH_HLEN + VLAN_HLEN + 1)))
		goto pkt_drop;
	/* This tag was inserted by the executing SEC descriptor. Remove
	 * exactly that shim, preserving both original per-packet MACs. */
	if (unlikely(((struct vlan_ethhdr *)skb->data)->h_vlan_proto != htons(ETH_P_8021Q) ||
		     ((struct vlan_ethhdr *)skb->data)->h_vlan_TCI != htons(tag)))
		goto pkt_drop;
	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	skb_pull(skb, VLAN_HLEN);
	ptr = skb->data;
	/*  When V6 SA is applied to v4 packet and vice versa, since ether header is
	 *  copied from input packet, it will be wrong. Below logic is added just
	 *  make the required correction in this case.
	 */
	memcpy(&eth_type,(ptr+12),2);
	if((eth_type == htons(ETHERTYPE_IPV4)) && ((ptr[14] & 0xF0) == 0x60))
	{
		ptr[12]= 0x86;
		ptr[13] = 0xDD;
	}
	if((eth_type == htons(ETHERTYPE_IPV6)) && ((ptr[14] & 0xF0) == 0x40))
	{
		ptr[12]= 0x08;
		ptr[13] = 0x00;
	}

	skb->dev = net_dev;
	skb->protocol = eth_type_trans(skb, net_dev);

	/* SEC has decrypted the packet, but has not checked the complete
	 * receiving policy. Initialize the secpath with olen/verified_cnt zero
	 * so Linux validates it rather than trusting stale offload metadata. */
	sp = secpath_set(skb);

	if (!sp)
	{
		pr_err_ratelimited("cdx: unable to allocate IPsec security path\n");
		goto pkt_drop;
	}

	sp->xvec[0] = x;

	/* First use, stamped without x->lock: this runs per frame in the
	 * portal callback, while the SA's accounting pass and the state timer
	 * read the field under the lock. One marked load and store, as
	 * xfrm_state_check_expire() makes its own. */
	if (!READ_ONCE(x->curlft.use_time))
		WRITE_ONCE(x->curlft.use_time, ktime_get_real_seconds());
	sp->len = 1;

#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::len %d\n", __func__, skb->len);
#endif
	/* netif_receive_skb(skb); */
	if (use_gro)
	{
		pc = qman_p_get_portal_config(qm);
		np = &percpu_priv->np[pc->index];

		np->p = qm;
		gro_result = napi_gro_receive(&np->napi, skb);
		(void)gro_result; /* Result no longer checked - GRO_DROP removed in kernel 6.12 */

	}
	else
		/* NET_RX_DROP here does not mean the frame was dropped, so it
		 * is deliberately not reported. __netif_receive_skb_core()
		 * leaves its return at NET_RX_DROP whenever an ingress hook
		 * takes the frame, and the flowtable's is exactly such a hook:
		 * every decrypted frame it forwards in software comes back
		 * through here looking like a loss. Measured on the bench:
		 * fifty-nine of sixty "dropped" frames were delivered. A
		 * counter that cannot tell a loss from a steal is worse than
		 * none, and at line rate it is also a log flood. */
		netif_receive_skb(skb);
	return qman_cb_dqrr_consume;
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
pkt_drop:
#endif
	/* The skb owns its data: a copy, whose buffer is back in the pool, or
	 * a scatter/gather frame's buffers, which conversion transferred to it
	 * and which returning the FD here would recycle as the skb frees them.
	 * The SA has not yet been transferred to a secpath on either failure
	 * branch. A receive drop of the SA's device, as a failed copy is. */
	dev_core_stats_rx_dropped_inc(net_dev);
	xfrm_state_put(x);
	dev_kfree_skb(skb);
	return qman_cb_dqrr_consume;
rel_fd:
	dpa_fd_release(net_dev, &dq->fd);
	return qman_cb_dqrr_consume;
}


#define PORTID_SHIFT_VAL 8

static int cdx_find_ipsec_pcd_fqinfo(int fqid, struct ipsec_info *info)
{
	struct dpa_fq *list = info->ipsec_pcd_fqs;
	while (list)
	{
		if (list->fqid == fqid)
			return 0;
		list = (struct dpa_fq *)list->list.next;
	}
	return -1;
}

static void ipsec_addfq_to_exceptionfq_list(struct dpa_fq *frameq,
		struct ipsec_info *info)
{
	frameq->list.next = (struct list_head *)info->ipsec_exception_fq;
	info->ipsec_exception_fq = frameq;
}

static void ipsec_delfq_from_exceptionfq_list(uint32_t fqid,
		struct ipsec_info *info)
{
	struct dpa_fq *prev, *list = info->ipsec_exception_fq;
	prev = list;
	while (list)
	{
		if (list->fqid == fqid)
		{
			if (prev == list)
			{
				info->ipsec_exception_fq = (struct dpa_fq *)list->list.next;
				return;
			}
			prev->list.next = list->list.next;
			return;
		}
		prev = list;
		list = (struct dpa_fq *)list->list.next;
	}
	return;
}

static int create_ipsec_pcd_fqs(struct ipsec_info *info, uint32_t schedule)
{
	struct dpa_fq *dpa_fq;
	uint32_t fqbase;
	uint32_t fqcount;
	uint32_t portid;
	uint32_t ii,jj;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals, max_dist = 0;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	struct dpa_iface_info *oh_iface_info;

	//get cpu portal channel info
	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
	if (!num_portals) {
		DPAIPSEC_ERROR("%s::unable to get affined portal info\n",
				__func__);
		return -1;
	}

#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::num_portals %d ::", __func__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPAIPSEC_INFO("%d ", portal_channel[ii]);
	DPAIPSEC_INFO("\n");
#endif

	if (get_ofport_max_dist(IPSEC_FMAN_IDX, info->ofport_handle, &max_dist) < 0)
	{
		DPAIPSEC_ERROR("%s::unable to get distributions for oh port\n", __func__);
		return -1;
	}

	DPAIPSEC_INFO("%s::max_dist : %d\n", __func__, max_dist) ;

	/* create all FQs */
	info->expt_fq_count = 0;
	/* get port id required for FQ creation */
	if (get_ofport_portid(IPSEC_FMAN_IDX, info->ofport_handle, &portid)) {
		DPAIPSEC_ERROR("%s::err getting of port id\n", __func__) ;
		return -1;
	}

	if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
		DPAIPSEC_ERROR("%s::err getting oh iface info of port id %u\n", __func__, portid) ;
		return -1;
	}
	if (oh_iface_info->pcd_proc_entry == NULL)
	{
		DPAIPSEC_ERROR("%s()::%d OH iface pcd proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}

	for (jj = 0; jj < max_dist; jj++)
	{
		/* get FQbase and count used for each distribution
			 with scheme sharing this is the only distribution that will be used */

		if (get_oh_port_pcd_fqinfo(IPSEC_FMAN_IDX, info->ofport_handle,
					jj , &fqbase, &fqcount)) {
			DPAIPSEC_ERROR("%s::err getting pcd fqinfo for dist %d\n",
					__func__,jj) ;
			return FAILURE;
		}

		/* add port id into FQID */
		fqbase |= (portid << PORTID_SHIFT_VAL);

		DPAIPSEC_INFO("%s::pcd FQ base for portid %d and  distribution id(%d): %x(%d), count %d\n",
				__func__, portid, jj, fqbase, fqbase, fqcount);

		for (ii = 0; ii < fqcount; ii++)
		{
			DPAIPSEC_INFO("%s(%d) calling cdx_find_ipsec_pcd_fqinfo (%x)\n",
					__func__,__LINE__, fqbase);
			if (!cdx_find_ipsec_pcd_fqinfo(fqbase, info))
			{
				fqbase++;
				continue;
			}

			/* create FQ for exception packets from ipsec ofline  port */
			dpa_fq = kzalloc((sizeof(struct dpa_fq)), GFP_KERNEL);
			if (!dpa_fq) {
				DPAIPSEC_ERROR("%s::unable to alloc mem for dpa_fq\n", __func__) ;
				/* The caller drains all previously published queues. */
				goto err_ret;
			}

			/* set FQ parameters */
			/* use wan port as the device for this FQ */
			//dpa_fq->net_dev = net_dev;
			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
			dpa_fq->fqid = fqbase;
			/* set call back function pointer */
			fq = &dpa_fq->fq_base;
			fq->cb.dqrr = ipsec_exception_pkt_handler;
			/* round robin channel like ethernet driver does */
			dpa_fq->channel = portal_channel[next_portal_ch_idx];
			if (next_portal_ch_idx == (num_portals - 1))
				next_portal_ch_idx = 0;
			else
				next_portal_ch_idx++;
			dpa_fq->wq = DEFA_WQ_ID;
			/* set options similar to ethernet driver */
			memset(&opts, 0, sizeof(struct qm_mcc_initfq));
			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
			opts.fqd.context_a.stashing.exclusive =
				(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
			/* create FQ */
			{
				int qrc = qman_create_fq(dpa_fq->fqid, 0, fq);
				if (qrc) {
					DPAIPSEC_ERROR("%s::qman_create_fq failed for fqid 0x%x (%d): err=%d, dist=%d\n",
							__func__, dpa_fq->fqid, dpa_fq->fqid,
							qrc, jj);
					/* Not on the PCD list yet; the caller cannot
					 * release this wrapper for us. */
					kfree(dpa_fq);
					goto err_ret;
				}
			}
			opts.fqid = dpa_fq->fqid;
			opts.count = 1;
			opts.fqd.dest.channel = dpa_fq->channel;
			opts.fqd.dest.wq = dpa_fq->wq;
			opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
					QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
			ipsec_exception_fq_bound(&opts);
			if (schedule)
				schedule = QMAN_INITFQ_FLAG_SCHED;

			/* init FQ */
			{
				int qrc = qman_init_fq(fq, schedule, &opts);
				if (qrc) {
					DPAIPSEC_ERROR("%s::qman_init_fq failed for fqid 0x%x (%d): err=%d, dist=%d, base=0x%x, portid=%u, channel=0x%x\n",
							__func__, dpa_fq->fqid, dpa_fq->fqid,
							qrc, jj, fqbase & 0xFFFF, portid, dpa_fq->channel);
					qman_destroy_fq(fq, 0);
					/* Not on the PCD list yet; the FQ is
					 * already destroyed, so just free the wrapper. */
					kfree(dpa_fq);
					goto err_ret;
				}
			}
			cdx_create_type_fqid_info_in_procfs(fq, PCD_DIR, oh_iface_info->pcd_proc_entry, NULL);
			/* Track only fully initialized queues. The common cleanup
			 * retains them and the buffer pool until draining completes. */
			dpa_fq->list.next = (struct list_head *)info->ipsec_pcd_fqs;
			info->ipsec_pcd_fqs = dpa_fq;
#ifdef DPA_IPSEC_DEBUG
			DPAIPSEC_INFO("%s::created pcd fq %x(%d) for wlan packets "
					"channel 0x%x\n", __func__,
					dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
			/* next FQ */
			fqbase++;
			info->expt_fq_count++;
			if (cdx_dpa_init_fault())
				goto err_ret;
		}
	}
	return SUCCESS;
err_ret:
	/* Includes failures between distributions, not just inside a batch. */
	return FAILURE;
}

static int create_ipsec_fqs(struct dpa_ipsec_sainfo *ipsecsa_info, uint32_t schedule, uint32_t handle)
{
	int32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	int errno;
	uint32_t flags = 0;
	uint64_t addr;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;
	uint32_t fqids_base;
	int to_sec_fq = 0;
	uint8_t sa_id_name[8]="";

	//get cpu portal channel info
	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
		/* need only one channel for one frame queue */
		break;
	}
	if (!num_portals) {
		DPAIPSEC_ERROR("%s::unable to get affined portal info\n",
				__func__);
		return -1;
	}

#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::num_portals %d ::", __func__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPAIPSEC_INFO("%d ", portal_channel[ii]);
	DPAIPSEC_INFO("\n");
#endif



	ipsecsa_info->shdesc_mem = 
		kzalloc((sizeof(struct sec_descriptor) + PRE_HDR_ALIGN), GFP_KERNEL);
	if (!ipsecsa_info->shdesc_mem)
	{
		DPAIPSEC_ERROR("%s::kzalloc failed for SEC descriptor\n",
				__func__);
		goto err_ret0;
	}
	memset(ipsecsa_info->shdesc_mem, 0, (sizeof(struct sec_descriptor)+PRE_HDR_ALIGN));
	ipsecsa_info->shared_desc = (struct sec_descriptor *)
		PTR_ALIGN(ipsecsa_info->shdesc_mem, PRE_HDR_ALIGN);

	errno = qman_alloc_fqid_range(&fqids_base, NUM_FQS_PER_SA, 0, 0);
	if (errno < NUM_FQS_PER_SA)
	{
		DPAIPSEC_ERROR("%s::qman_alloc_fqid_range failed for allocating frame queues\n",
				__func__);
		goto err_ret1;
	}

	sprintf(sa_id_name, "0x%x", handle);
	if (cdx_create_dir_in_procfs(&ipsecsa_info->sa_proc_entry, sa_id_name, SA_DIR)) {
		DPAIPSEC_ERROR("%s:: create pcd proc entry failed %s\n", 
				__func__, sa_id_name);
		goto err_ret2;
	}

	for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {

		dpa_fq = &ipsecsa_info->sec_fq[ii];
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		fq = &dpa_fq->fq_base;
		to_sec_fq = 0;
		switch (ii) {
			case FQ_FROM_SEC:
				{
#ifdef DPA_IPSEC_DEBUG
					printk("%s::handle %x\n", __func__, handle);
#endif
					flags = QMAN_FQ_FLAG_TO_DCPORTAL;
					dpa_fq->channel = ipsecinfo.ofport_channel;
					dpa_fq->fq_base.cb.dqrr = dpa_ipsec_drain_dqrr;
					/* setting A1 value to 2 and setting a  bit to copy A1 value in  context A field  */
					/* setting override frame queue option */
					opts.fqd.context_a.hi = 
						(((
							 CDX_FQD_CTX_A_OVERRIDE_FQ |
							 /*CDX_FQD_CTX_A_B0_FIELD_VALID | */
							 CDX_FQD_CTX_A_A1_FIELD_VALID) <<
							CDX_FQD_CTX_A_SHIFT_BITS) |
						 CDX_FQD_CTX_A_A1_VAL_TO_CHECK_SECERR );
					opts.fqd.context_b = fqids_base + FQ_TO_CP;
					break;
				}
			case FQ_TO_SEC:
				{
					flags = QMAN_FQ_FLAG_TO_DCPORTAL;
					addr = virt_to_phys(ipsecsa_info->shared_desc);
					dpa_fq->channel = ipsecinfo.crypto_channel_id;
					dpa_fq->fq_base.cb.ern = dpa_ipsec_ern_cb;
					dpa_fq->fq_base.cb.dqrr = dpa_ipsec_drain_dqrr;
					opts.fqd.context_b = ipsecsa_info->sec_fq[FQ_FROM_SEC].fqid;
					opts.fqd.context_a.hi = (uint32_t) (addr >> 32);
					opts.fqd.context_a.lo = (uint32_t) (addr);
					to_sec_fq = 1;
					break;
				}
			case FQ_TO_CP:
				{
					flags = 0;
					/* set FQ parameters */
					/* dpa_fq->net_dev = net_dev; */
					/* No net_dev is attached to FQ as its being fetched from sagd */
					dpa_fq->fq_type = FQ_TYPE_RX_PCD;
					/* creating CP fqid as the fqid value of FROM_SEC FQID +1 */
					/* The CPU's receive callback also empties the
					 * queue for the SA's release: that starts by
					 * marking the SA SA_DELETE, which the handler's
					 * lookup skips, so whatever is left is dropped
					 * back to its pools there. */
					dpa_fq->fq_base.cb.dqrr = ipsec_exception_pkt_handler;
					/* round robin channel like ethernet driver does */
					dpa_fq->channel = portal_channel[next_portal_ch_idx];
					break;
				}

		}
		dpa_fq->wq = IPSEC_WQ_ID;
		if (qman_create_fq(fqids_base+ii, flags, fq)) 
		{
			DPAIPSEC_ERROR("%s::qman_create_fq failed for fqid %d\n",
					__func__, dpa_fq->fqid);
			goto err_ret3;
		}
		dpa_fq->fqid = fq->fqid;
		opts.fqid = dpa_fq->fqid;
		opts.count = 1;
		opts.fqd.dest.channel = dpa_fq->channel;
		opts.fqd.dest.wq = dpa_fq->wq;
		if (ii != FQ_TO_CP)
		{
			opts.fqd.fq_ctrl = QM_FQCTRL_CPCSTASH;
		}
		else
		{
			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
			opts.fqd.context_a.stashing.exclusive =
				(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
			ipsec_exception_fq_bound(&opts);
		}
		if (to_sec_fq == 1)
		{
#ifdef FQ_TAIL_DROP
			/* Enabling the FQ tail drop threshold */
			opts.we_mask = QM_INITFQ_WE_TDTHRESH;
			/* Setting the frame queue tail drop threshold value. */
			qm_fqd_taildrop_set(&opts.fqd.td, DPA_FQ_TD_BYTES, 1);
			/* Enabling the FQ tail drop support. */
			opts.fqd.fq_ctrl |= QM_FQCTRL_TDE;
#endif
#ifdef CS_TAIL_DROP
			if (sec_congestion)
			{
				/* CS tail drop start*/
				opts.we_mask |= QM_INITFQ_WE_CGID;
				/* Enabling the congestion group */
				opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
				/* setting congestion group record id, which is created at the time of initialization. */
				opts.fqd.cgid = (u8)ipsecinfo.cgr.ingress_cgr.cgrid;
				/* CS tail drop end*/
			}
#endif
		}
		opts.we_mask |= (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		if(schedule)
			schedule = QMAN_INITFQ_FLAG_SCHED;
		if((errno=qman_init_fq(fq, schedule, &opts)))
		{
			DPAIPSEC_ERROR("%s::qman_init_fq failed for fqid %d errno= %d\n",
					__func__, dpa_fq->fqid,errno);
			qman_destroy_fq(fq, 0);
			goto err_ret4;
		}

		ipsec_addfq_to_exceptionfq_list(dpa_fq, &ipsecinfo);

		if (ii == FQ_FROM_SEC)
		{
			cdx_create_type_fqid_info_in_procfs(fq, SA_DIR, ipsecsa_info->sa_proc_entry, "from_sec");
		}
		else if (ii == FQ_TO_SEC)
		{
			cdx_create_type_fqid_info_in_procfs(fq, SA_DIR, ipsecsa_info->sa_proc_entry, "to_sec");
		}
		else if (ii == FQ_TO_CP)
		{
			cdx_create_type_fqid_info_in_procfs(fq, SA_DIR, ipsecsa_info->sa_proc_entry, "to_cp");
		}

#ifdef DPA_IPSEC_DEBUG
		DPAIPSEC_INFO("%s::created fq %x(%d) for ipsec - type %d "
				"channel 0x%x\n", __func__,
				dpa_fq->fqid, dpa_fq->fqid, ii, dpa_fq->channel);
#endif
	}
	return SUCCESS;

err_ret4:
err_ret3:
	for (; ii>0 ; ii--)
	{
		fq = &(ipsecsa_info->sec_fq[ii-1].fq_base);
		/* No caller has received this SA, so no producer can submit to
		 * it. Wait out asynchronous retirement before releasing the
		 * embedded queues, shared descriptor or module reference. */
		cdx_destroy_fq(fq);
		ipsec_delfq_from_exceptionfq_list(fq->fqid,&ipsecinfo);
	}
	if (ipsecsa_info->sa_proc_entry) {
		proc_remove(((cdx_proc_dir_entry_t *)(ipsecsa_info->sa_proc_entry))->proc_dir);
		kfree(ipsecsa_info->sa_proc_entry);
		ipsecsa_info->sa_proc_entry = NULL;
	}
err_ret2:
	/* Reached only after the qman_alloc_fqid_range above succeeded (the
	 * alloc-failure path jumps straight to err_ret1); the range is released
	 * nowhere else in this function, and the normal SA teardown releases it
	 * only for SAs that reached SUCCESS — so this is an exactly-once release. */
	qman_release_fqid_range(fqids_base, NUM_FQS_PER_SA);
err_ret1:
	kfree(ipsecsa_info->shdesc_mem);
err_ret0:
	return FAILURE;
}



static int ipsec_init_ohport(struct ipsec_info *info)
{

	/* Get OH port for this driver */
	info->ofport_handle = alloc_offline_port(IPSEC_FMAN_IDX, PORT_TYPE_IPSEC,
			NULL, NULL);
	if (info->ofport_handle < 0)
	{
		DPAIPSEC_ERROR("%s: Error in allocating OH port Channel\n", __func__);
		return FAILURE;
	}
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s: allocated oh port %d\n", __func__, info->ofport_handle);
#endif
	if (get_ofport_info(IPSEC_FMAN_IDX, info->ofport_handle, &info->ofport_channel,
				&info->ofport_td[0])) {
		DPAIPSEC_ERROR("%s: Error in getting OH port info\n", __func__);
		goto release;
	}
	if (get_ofport_portid(IPSEC_FMAN_IDX, info->ofport_handle, &info->ofport_portid)) {
		DPAIPSEC_ERROR("%s: Error in getting OH port id\n", __func__);
		goto release;
	}
	printk("%s:: ipsec of port id = %d\n ", __func__, info->ofport_portid);
	return SUCCESS;

release:
	/* The common init unwind releases the tracked port claim. */
	return FAILURE;
}

void *  dpa_get_ipsec_instance(void)
{
	return &ipsecinfo; 
}

int dpa_ipsec_ofport_td(struct ipsec_info *info, uint32_t table_type, void **td,
		uint32_t* portid)
{
	if (table_type >= MAX_MATCH_TABLES) {
		DPAIPSEC_ERROR("%s::invalid table type %d\n", __func__, table_type);
		return FAILURE;
	}
	/* No port, no tables: the descriptors below are only filled in by a
	 * successful cdx_dpa_ipsec_init(), and a NULL one handed out here
	 * would fault in the table insert rather than fail it. */
	if (!cdx_dpa_ipsec_ready())
		return FAILURE;
	/* The IPsec policy has only SA-bound unicast tables and a catch-all. */
	if (!info->ofport_td[table_type])
		return FAILURE;
	*td = info->ofport_td[table_type];
	*portid = info->ofport_portid;
	return SUCCESS;
}

extern int dpaa_bp_alloc_n_add_buffs(const struct dpa_bp *dpa_bp, 
		uint32_t nbuffs, bool act_skb);
#define CDX_MAX_SG_BUFF_SIZE 1024
#define CDX_MAX_SG_BUFF_COUNT 512

static void ipsec_free_sg_buffer(void *addr)
{
	kfree(addr);
}

static void release_ipsec_sg_pools(void)
{
	struct dpa_bp *clean = sg_bpool_g;
	struct dpa_bp *done = skb_2bfreed_bpool_g;

	/* The caller has stopped producers, portal callbacks and the worker. */
	dpaa_sec_sg_reap(CDX_MAX_SG_BUFF_COUNT);
	WRITE_ONCE(skb_2bfreed_bpool_g, NULL);
	WRITE_ONCE(sg_bpool_g, NULL);
	if (done) {
		_dpa_bp_free(done);
		kfree(done);
	}
	if (clean) {
		_dpa_bp_free(clean);
		kfree(clean);
	}
}

int cdx_init_skb_2bfreed_bpool(void)
{
	struct dpa_bp *bp, *bp_parent;
	struct port_bman_pool_info parent_pool_info;

	// allocate memory for bpool
	bp = kzalloc(sizeof(struct dpa_bp), GFP_KERNEL);
	if (unlikely(bp == NULL)) {
		DPAIPSEC_ERROR("%s(%d)::failed to mem for non_recyclable SKB free bman pool\n",
				__func__,__LINE__);
		return -1;
	}
	bp->size = CDX_MAX_SG_BUFF_SIZE;
	bp->config_count = CDX_MAX_SG_BUFF_COUNT;

	//find pools used by ethernet devices
	if (get_phys_port_poolinfo_bysize(bp->size, &parent_pool_info)) {
		DPAIPSEC_ERROR("%s::failed to locate eth bman pool for ipsec\n", 
				__func__);
		kfree(bp);
		return -1;
	}
	bp_parent = dpa_bpid2pool(parent_pool_info.pool_id);
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAIPSEC_ERROR("%s::dpa_bp_alloc failed for bufpool of freeing skbs\n", 
				__func__);
		kfree(bp);
		return -1;
	}
	DPAIPSEC_INFO("%s::bp->size :%zu, bpid %d\n", 
			__func__, bp->size, bp->bpid);
	smp_store_release(&skb_2bfreed_bpool_g, bp);
	return 0;
}

int cdx_init_scatter_gather_bpool(void)
{
	struct dpa_bp *bp,*bp_parent;
	struct port_bman_pool_info parent_pool_info;
	int ret =0;

	bp = kzalloc(sizeof(struct dpa_bp), GFP_KERNEL);
	if (unlikely(bp == NULL)) {
		DPAIPSEC_ERROR("%s::failed to allocate mem for SG bman pool\n", 
				__func__);
		return -1;
	}
	bp->size = CDX_MAX_SG_BUFF_SIZE;
	bp->config_count = CDX_MAX_SG_BUFF_COUNT;
	bp->free_buf_cb = ipsec_free_sg_buffer;

	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(bp->size, &parent_pool_info)) {
		DPAIPSEC_ERROR("%s::failed to locate eth bman pool for ipsec\n", 
				__func__);
		kfree(bp);
		return -1;
	}
	bp_parent = dpa_bpid2pool(parent_pool_info.pool_id);
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::parent bman pool for SG - bp %p, bpid %d paddr %lx vaddr %p dev %p\n", 
			__func__, bp, parent_pool_info.pool_id,
			(unsigned long)bp->paddr, bp->vaddr, bp->dev);
#endif
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAIPSEC_ERROR("%s::dpa_bp_alloc failed for ipsec\n", 
				__func__);
		kfree(bp);
		return -1;
	}
	DPAIPSEC_INFO("%s::bp->size :%zu, bpid %d\n", 
			__func__, bp->size, bp->bpid);
	ret = dpaa_bp_alloc_n_add_buffs(bp, CDX_MAX_SG_BUFF_COUNT, 0);
	if (ret) {
		_dpa_bp_free(bp);
		kfree(bp);
		return ret;
	}
	smp_store_release(&sg_bpool_g, bp);
	DPAIPSEC_INFO("%s(%d) buffers added to ipsec pool %d info size %zu \n", 
			__func__,__LINE__,sg_bpool_g->bpid,
			sg_bpool_g->size);
	return 0;
}

static void ipsec_free_pool_buffer(void *addr)
{
	struct sk_buff *skb, **skbh;

	/* The pool seeder stores an skb immediately before the DMA buffer.
	 * Freeing that skb releases its backing pages too. */
	DPA_READ_SKB_PTR(skb, skbh, addr, -1);
	dev_kfree_skb_any(skb);
}

static void release_ipsec_bpool(struct ipsec_info *info)
{
	struct dpa_bp *bp = info->ipsec_bp;

	if (!bp)
		return;
	ipsec_pool_refill_stop();
	WRITE_ONCE(ipsec_bpid, -1);
	/* Unmap and drain through free_buf_cb, then remove the BPID lookup
	 * before recycling it. bman_free_pool alone does neither. */
	_dpa_bp_free(bp);
	kfree(bp);
	info->ipsec_bp = NULL;
}

static int add_ipsec_bpool(struct ipsec_info *info)
{
	struct dpa_bp *bp,*bp_parent;
	//int buffer_count = 0, ret = 0, refill_cnt ;
	//int ret =0;
	printk (KERN_INFO"\n ################## %s", 
			__func__);

	bp = kzalloc(sizeof(struct dpa_bp), GFP_KERNEL);
	if (unlikely(bp == NULL)) {
		DPAIPSEC_ERROR("%s::failed to allocate mem for bman pool for ipsec\n", 
				__func__);
		return -1;
	}

	/* SEC writes a whole ESP frame, as large as the largest a port
	 * accepts, into one buffer of this pool: the ports' own buffer size.
	 * Only the device the buffers are mapped for is taken from a port's
	 * pool, which is that size too. */
	bp->size = IPSEC_BUFSIZE;
	if (get_phys_port_poolinfo_bysize(bp->size, &info->parent_pool_info)) {
		DPAIPSEC_ERROR("%s::failed to locate eth bman pool for ipsec\n", 
				__func__);
		kfree(bp);
		return -1;
	}
	bp_parent = dpa_bpid2pool(info->parent_pool_info.pool_id);
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::parent bman pool for ipsec - bp %p, bpid %d paddr %lx vaddr %p dev %p\n", 
			__func__, bp, info->parent_pool_info.pool_id,
			(unsigned long)bp->paddr, bp->vaddr, bp->dev);
#endif
	bp->dev = bp_parent->dev;
	bp->config_count = IPSEC_BUFCOUNT;
	bp->free_buf_cb = ipsec_free_pool_buffer;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAIPSEC_ERROR("%s::dpa_bp_alloc failed for ipsec\n",
				__func__);
		kfree(bp);
		return -1;
	}
	DPAIPSEC_INFO("%s::bp->size :%zu, bpid %d\n",
			__func__, bp->size, bp->bpid);
	printk (KERN_INFO"\n ################## %s::bp->size :%zu, bpid %d\n",
			__func__, bp->size, bp->bpid);
	info->ipsec_bp = bp;
	WRITE_ONCE(ipsec_bpid, bp->bpid);

	/*
	 * Seed the BMan pool. dpa_bp_alloc only registers the pool with BMan;
	 * SEC needs *buffers* in it to write encrypted output. Without this
	 * call the pool is empty, every cdx-format SEC submission lands in
	 * QISTA_BPDERR and is silently dropped (no ERN, no error response,
	 * ob_rq_encrypted never increments).
	 *
	 * act_skb=true is load-bearing: ipsec_exception_pkt_handler routes
	 * inbound-decrypt-result frames through contig_fd_to_skb, which reads
	 * an embedded skb back-pointer at vaddr - sizeof(void *). Without
	 * skb-backed buffers the read returns slab poison and the cb faults
	 * in softirq context.
	 */
	if (dpaa_bp_alloc_n_add_buffs(bp, IPSEC_BUFCOUNT, 1)) {
		DPAIPSEC_ERROR("%s::dpaa_bp_alloc_n_add_buffs failed for ipsec\n",
				__func__);
		/* Earlier batches (and part of the last one) are already in
		 * BMan. The caller drains them through the common unwind. */
		return -1;
	}
	ipsec_pool_refill_start();

	return cdx_dpa_init_fault() ? FAILURE : SUCCESS;
}

int cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size)
{
	if (!ipsecinfo.ipsec_bp) 	
		return -1;
	*bpid = ipsecinfo.ipsec_bp->bpid;
	//*buf_size =ipsecinfo.parent_pool_info.buf_size;
	*buf_size = ipsecinfo.ipsec_bp->size;
	return 0;

}

void *cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle)
{
	struct dpa_ipsec_sainfo *sainfo;
	int tag;

	/* An SA can still own SEC work while its deferred deletion runs.
	 * Keep the pool and callback text loaded until all its queues are
	 * gone, however long the release waits on QMan or SEC. */
	if (!try_module_get(THIS_MODULE))
		return NULL;
	sainfo = (struct dpa_ipsec_sainfo *)
		kzalloc(sizeof(struct dpa_ipsec_sainfo), GFP_KERNEL);
	if (!sainfo) {
		DPAIPSEC_ERROR("%s::Error in allocating sainfo\n",
				__func__);
		module_put(THIS_MODULE);
		return NULL;
	}
	memset(sainfo, 0, sizeof(struct dpa_ipsec_sainfo));
	/* One 12-bit VLAN identity per inbound SA or outbound root. Refuse
	 * exhaustion; never alias an active or retained identity. */
	tag = ida_alloc_range(&ipsec_key_tags, 1, VLAN_VID_MASK - 1, GFP_KERNEL);
	if (tag < 0) {
		kfree(sainfo);
		module_put(THIS_MODULE);
		return NULL;
	}
	sainfo->key_tag = tag;
	refcount_set(&ipsec_key_tag_refs[tag], 1);
	//create fqs in scheduled state
	if (create_ipsec_fqs(sainfo, 1, handle)) {
		ipsec_put_key_tag(sainfo->key_tag);
		kfree(sainfo);
		module_put(THIS_MODULE);
		return NULL;
	}
	return sainfo;
}

/* change the state of frame queues */
int cdx_dpa_ipsec_retire_fq(void *handle, int fq_num)
{
	struct dpa_ipsec_sainfo *sainfo;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	int32_t flags, ret;

	sainfo = (struct dpa_ipsec_sainfo *)handle;
	dpa_fq = &sainfo->sec_fq[fq_num];
	fq = &dpa_fq->fq_base; 
	ret = qman_retire_fq(fq, &flags);
	if (ret < 0) {
		DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n",
				__func__, fq->fqid, fq->fqid);
	}
	return ret;
}

/* One step towards taking one of an SA's queues out of service, never
 * waiting on QMan: 0 once it is out of service; 1 while it is retired -- its
 * consumer takes nothing more from it -- but not yet empty or out of service;
 * -EBUSY while its retirement has not completed. The caller comes back a
 * timer period later, for as long as it takes.
 *
 * A retirement that failed, or was never asked for, is asked for again. What
 * a retired queue still holds is dequeued by a volatile dequeue and dropped
 * by the queue's own callback, whose portal delivers it after this returns;
 * the queue goes out of service only once that dequeue has finished and
 * QMan has seen it empty. Control mutex held. */
int cdx_dpa_ipsec_fq_stop(void *handle, int fq_num)
{
	struct qman_fq *fq = &((struct dpa_ipsec_sainfo *)handle)->sec_fq[fq_num].fq_base;
	enum qman_fq_state state;
	u32 flags;
	int ret;

	qman_fq_state(fq, &state, &flags);
	if (state == qman_fq_state_oos)
		return 0;
	if (flags & QMAN_FQ_STATE_CHANGING)
		return -EBUSY;
	if (state != qman_fq_state_retired) {
		ret = qman_retire_fq(fq, NULL);
		if (ret < 0)
			pr_warn_ratelimited("cdx: cannot retire IPsec SA queue 0x%x: %d\n",
					    fq->fqid, ret);
		/* Asynchronous, it completes with QMan's notification. */
		if (ret)
			return -EBUSY;
		qman_fq_state(fq, &state, &flags);
	}
	if (flags & (QMAN_FQ_STATE_VDQCR | QMAN_FQ_STATE_ORL))
		return 1;
	if (flags & QMAN_FQ_STATE_NE) {
		/* Refused while another queue holds this portal's volatile
		 * dequeue; tried again next time. */
		qman_volatile_dequeue(fq, 0, QM_VDQCR_NUMFRAMES_TILLEMPTY);
		return 1;
	}
	ret = qman_oos_fq(fq);
	if (ret) {
		pr_warn_ratelimited("cdx: cannot take IPsec SA queue 0x%x out of service: %d\n",
				    fq->fqid, ret);
		/* QMan found it not empty after all: dequeue again, which
		 * costs nothing on a queue that is. */
		qman_volatile_dequeue(fq, 0, QM_VDQCR_NUMFRAMES_TILLEMPTY);
		return 1;
	}
	return 0;
}

/* An SA's FQIDs going back with its queues: at once, unless a classifier entry
 * that may still be linked named them in this datapath epoch, when they are
 * held for the restart that ends it. One kept in an earlier epoch has been
 * settled by the restart since, whether its release came before that restart
 * (held, then released by it) or after. */
static void dpa_ipsec_release_fqids(struct dpa_ipsec_sainfo *sainfo)
{
	u32 base = sainfo->sec_fq[FQ_FROM_SEC].fqid;
	struct dpa_ipsec_held_fqids *held;
	void *td = dpa_get_ehash_td();

	/* FROM_SEC can be empty while FMan still holds its last packet.
	 * After every SA queue is OOS, a PCD barrier proves that packet no
	 * longer carries this tag or exception FQID. A failed proof pins both
	 * until a stopped-port restart completes the barrier. */
	if (!td || ExternalHashTableFmPcdHcSync(td)) {
		cdx_ft_fatal();
	}
	/* A failed dependent-flow delete can leave a tag-validating entry
	 * linked even when this SA's own root deleted cleanly. Admission is
	 * stopped by that latch; retain the namespace across module unload
	 * too, until restart has settled all such entries. */
	if (cdx_ft_failed())
		sainfo->keep_epoch = cdx_ft_epoch();

	if (!sainfo->keep_epoch || sainfo->keep_epoch != cdx_ft_epoch()) {
		qman_release_fqid_range(base, NUM_FQS_PER_SA);
		ipsec_put_key_tag(sainfo->key_tag);
		return;
	}
	/* The tag allocator is module-local. Reloading it while a stale
	 * classifier may still carry a tag would make that tag reusable. */
	__module_get(THIS_MODULE);
	held = kmalloc(sizeof(*held), GFP_KERNEL);
	if (!held) {
		pr_err("cdx: IPsec SA FQIDs 0x%x-0x%x leaked: a classifier entry may still name them and they could not be held\n",
		       base, base + NUM_FQS_PER_SA - 1);
		return;
	}
	held->base = base;
	held->key_tag = sainfo->key_tag;
	list_add_tail(&held->list, &dpa_ipsec_held);
}

/* The SA's queues, descriptor, FQIDs and tag, and its module reference, once
 * nothing can use them any more: every queue out of service and SEC proven
 * done with every job it took (cdx_ipsec_release_sa_ctx_cbk()). The caller
 * frees the keys the descriptor names after this. A queue still in service
 * means that was not established, and then nothing is freed. */
int cdx_dpa_ipsecsa_release(void *handle)
{
	struct dpa_ipsec_sainfo *sainfo;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	enum qman_fq_state state;
	uint32_t ii;

	if (!handle)
		return FAILURE;
	sainfo = (struct dpa_ipsec_sainfo *)handle;

	for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
		qman_fq_state(&sainfo->sec_fq[ii].fq_base, &state, NULL);
		if (WARN_ON_ONCE(state != qman_fq_state_oos))
			return FAILURE;
	}
	/* QMan can publish the last state change before the callback that
	 * delivered it returns, and a software submit that found TO_SEC
	 * before the SA was marked for deletion enqueues inside an RCU read
	 * section. Retain both the embedded queues and the module until
	 * those are done; the rejection such an enqueue earns came back
	 * timer periods ago. */
	synchronize_net();
	for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
		dpa_fq = &sainfo->sec_fq[ii];
		fq = &dpa_fq->fq_base;
		ipsec_delfq_from_exceptionfq_list(fq->fqid,&ipsecinfo);
		cdx_remove_fqid_info_in_procfs(fq->fqid);
		qman_destroy_fq(fq, 0);
	}
	if (sainfo->sa_proc_entry)
	{
		proc_remove(((cdx_proc_dir_entry_t *)(sainfo->sa_proc_entry))->proc_dir);
		kfree(sainfo->sa_proc_entry);
	}
	/* shdesc_mem was allocated in create_ipsec_fqs and the SEC shared
	 * descriptor lives inside it (sainfo->shared_desc points into this
	 * buffer with PTR_ALIGN offset). The err_ret1 unwind in
	 * create_ipsec_fqs frees it on partial-init failure; this is the
	 * matching free on the normal release path. */
	kfree(sainfo->shdesc_mem);
	dpa_ipsec_release_fqids(sainfo);
	kfree(sainfo);
	module_put(THIS_MODULE);
	return SUCCESS;
}

/* A classifier entry whose delete could not prove it unlinked may still match
 * and enqueue to this SA's TO_SEC FQID. The queues themselves still go -- an
 * out-of-service FQ rejects the enqueue -- but a later SA or any other queue
 * given the same FQIDs would be fed frames it was never admitted for, so the
 * FQIDs stay allocated until the datapath restart that settles the entry, or
 * the reboot that replaces it when none can. */
void cdx_dpa_ipsecsa_keep_fqids(void *handle)
{
	((struct dpa_ipsec_sainfo *)handle)->keep_epoch = cdx_ft_epoch();
}

unsigned int cdx_dpa_ipsec_release_held_fqids(void)
{
	struct dpa_ipsec_held_fqids *held, *next;
	unsigned int released = 0;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	list_for_each_entry_safe(held, next, &dpa_ipsec_held, list) {
		qman_release_fqid_range(held->base, NUM_FQS_PER_SA);
		ipsec_put_key_tag(held->key_tag);
		list_del(&held->list);
		kfree(held);
		module_put(THIS_MODULE);
		released++;
	}
	return released;
}

void cdx_dpa_ipsec_held_fqids_exit(bool settled)
{
	struct dpa_ipsec_held_fqids *held, *next;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	if (settled) {
		cdx_dpa_ipsec_release_held_fqids();
		ida_destroy(&ipsec_key_tags);
		return;
	}
	list_for_each_entry_safe(held, next, &dpa_ipsec_held, list) {
		pr_err("cdx: IPsec SA FQIDs 0x%x-0x%x stay allocated until reset: a classifier entry may still name them\n",
		       held->base, held->base + NUM_FQS_PER_SA - 1);
		list_del(&held->list);
		kfree(held);
	}
}

int cdx_ipsec_sa_fq_check_if_retired_state(void *dpa_ipsecsa_handle, int fq_num)
{
	struct dpa_ipsec_sainfo *sainfo;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	sainfo = (struct dpa_ipsec_sainfo *)dpa_ipsecsa_handle;
	dpa_fq = &sainfo->sec_fq[fq_num];
	fq = &dpa_fq->fq_base;
	/* Nonzero while the queue may still feed its consumer. */
	return fq->state != qman_fq_state_retired &&
	       fq->state != qman_fq_state_oos;
}

#ifdef CS_TAIL_DROP
static void cgr_cb(struct qman_portal *qm, struct qman_cgr *cgr, int congested)
{
	static u32 no_of_cong_entry = 0;
#define PRINT_DURATION 500000

#ifdef DPA_IPSEC_DEBUG
	if (congested) {
		if (((no_of_cong_entry/2) % PRINT_DURATION) == 0)
			printk("%s()::%d entered congestion %d\n", __func__, __LINE__, no_of_cong_entry);

	} else {
		if (((no_of_cong_entry/2) % PRINT_DURATION) == 0)
			printk("%s()::%d EXITED congestion %d.\n", __func__, __LINE__, no_of_cong_entry);
	}
#endif
	++no_of_cong_entry;
	return;
}

static int cdx_dpaa_ingress_cgr_init(struct cgr_priv *cgr)
{
	struct qm_mcc_initcgr initcgr;
	u32 cs_th;
	int err;

	memset(&initcgr, 0, sizeof(struct qm_mcc_initcgr));
	memset(cgr, 0, sizeof(struct cgr_priv));
	err = qman_alloc_cgrid(&cgr->ingress_cgr.cgrid);
	if (err < 0) {
		pr_err("Error %d allocating CGR ID\n", err);
		goto out_error;
	}

	cgr->ingress_cgr.cb = cgr_cb;
	/* Enable CS TD, Congestion State Change Notifications. */
	initcgr.we_mask = QM_CGR_WE_CSCN_EN | QM_CGR_WE_CS_THRES | QM_CGR_WE_MODE;
	initcgr.cgr.cscn_en = QM_CGR_EN;
	initcgr.cgr.mode= 0; /*Byte mode*/
	cs_th = sec_congestion;

	qm_cgr_cs_thres_set64(&initcgr.cgr.cs_thres, cs_th, 1);
	printk("%s()::%d cs_th: %u mant %d exp %d\n", __func__, __LINE__,cs_th,
			initcgr.cgr.cs_thres.TA, initcgr.cgr.cs_thres.Tn);

	initcgr.we_mask |= QM_CGR_WE_CSTD_EN;
	initcgr.cgr.cstd_en = QM_CGR_EN;

	/* Deletion must use this same affine portal, even after migration. */
	preempt_disable();
	cgr->cpu = smp_processor_id();
	err = qman_create_cgr(&cgr->ingress_cgr, QMAN_CGR_FLAG_USE_INIT,
			&initcgr);
	preempt_enable();
	if (err < 0) {
		pr_err("Error %d creating ingress CGR with ID %d\n", err,
				cgr->ingress_cgr.cgrid);
		qman_release_cgrid(cgr->ingress_cgr.cgrid);
		goto out_error;
	}
	pr_debug("Created ingress CGR %d\n", cgr->ingress_cgr.cgrid);

	/* cgr->use_ingress_cgr = true;*/

out_error:
	return err;
}

static void ipsec_delete_cgr_on_cpu(void *arg)
{
	struct cgr_priv *cgr = arg;

	cgr->delete_result = qman_delete_cgr(&cgr->ingress_cgr);
}

static void cdx_dpaa_ingress_cgr_exit(struct cgr_priv *cgr)
{
	int ret;

	/* qman_delete_cgr_safe() discards errors. Keep callback storage and
	 * module text alive until deletion on the owning portal succeeds. */
	for (;;) {
		ret = smp_call_function_single(cgr->cpu, ipsec_delete_cgr_on_cpu,
					       cgr, 1);
		if (!ret)
			ret = cgr->delete_result;
		if (!ret)
			break;
		pr_warn_ratelimited("cdx: cannot delete IPsec CGR: %d\n", ret);
		usleep_range(1000, 2000);
	}
	qman_release_cgrid(cgr->ingress_cgr.cgrid);
}
#endif

/* The exception group counts frames, each of which holds one pool buffer, and
 * drops at the tail. It asks for no state-change notifications, so no portal
 * owns it, and the egress groups' way of setting one up serves (devman.c). */
static int ipsec_exception_cgr_init(void)
{
	struct qm_mcc_initcgr opts;

	if (qman_alloc_cgrid(&ipsecinfo.exception_cgr.cgrid) < 0)
		return -ENOSPC;
	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_CGR_WE_MODE | QM_CGR_WE_CS_THRES | QM_CGR_WE_CSTD_EN |
		       QM_CGR_WE_CSCN_EN;
	opts.cgr.mode = QMAN_CGR_MODE_FRAME;
	opts.cgr.cstd_en = QM_CGR_EN;
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, IPSEC_EXCEPTION_FRAMES, 1);
	if (qman_modify_cgr(&ipsecinfo.exception_cgr, QMAN_CGR_FLAG_USE_INIT, &opts)) {
		qman_release_cgrid(ipsecinfo.exception_cgr.cgrid);
		return -EIO;
	}
	ipsecinfo.exception_cgr_initialized = true;
	return 0;
}

/* Its members are out of service by now, which the release requires: the PCD
 * queues, and every SA's exception queue, gone with the SA, which holds the
 * module until it is released. */
static void ipsec_exception_cgr_exit(void)
{
	struct qm_mcc_initcgr opts;

	if (!ipsecinfo.exception_cgr_initialized)
		return;
	memset(&opts, 0, sizeof(opts));
	qman_modify_cgr(&ipsecinfo.exception_cgr, QMAN_CGR_FLAG_USE_INIT, &opts);
	qman_release_cgrid(ipsecinfo.exception_cgr.cgrid);
	ipsecinfo.exception_cgr_initialized = false;
}


/* Whether the DPA side of IPsec -- the offline port, its tables, the SEC
 * buffer pool and the PCD frame queues -- is there to be used. False until
 * cdx_dpa_ipsec_init() has finished, and again as soon as teardown starts.
 * A board whose device tree lacks the IPsec offline port leaves it false for
 * the module's whole life, and that is the only way the rest of the module
 * learns of it: every path that would touch this state asks here first,
 * through cdx_ipsec_ready(). */
static bool dpa_ipsec_ready;

bool cdx_dpa_ipsec_ready(void)
{
	/* Paired with the release below: a reader that sees true also sees
	 * the table descriptors and pools stored before it. */
	return smp_load_acquire(&dpa_ipsec_ready);
}

int cdx_dpa_ipsec_init(void)
{

	DPAIPSEC_INFO("%s::\n", __func__);
	ipsecinfo.crypto_channel_id = qm_channel_caam;
	/* Each step undoes the ones before it on failure. The module carries
	 * on without IPsec, so a half-built claim on the port or the pool
	 * would otherwise be held for nothing. The fault hook is the same one
	 * the other startup acquisitions expose, so a test can boot a board
	 * "without" the port and prove the rest still comes up. */
	if (cdx_dpa_init_fault() || ipsec_init_ohport(&ipsecinfo))
		goto failure;
	/* One SA's jobs must reach SEC as one shared descriptor whichever
	 * producer enqueues them; see dpa_cfg_shared_icid(). */
	if (dpa_cfg_shared_icid() < 0)
		goto failure;
	if (add_ipsec_bpool(&ipsecinfo))
		goto failure;
	if (cdx_init_scatter_gather_bpool() || cdx_init_skb_2bfreed_bpool())
		goto failure;
#ifdef CS_TAIL_DROP
	if (sec_congestion){
		if (cdx_dpaa_ingress_cgr_init(&ipsecinfo.cgr)) {
			goto failure;
		}
		ipsecinfo.cgr_initialized = true;
	}
#endif
	/* Before any queue that joins it: the PCD queues below, and every SA's
	 * exception queue. */
	if (ipsec_exception_cgr_init())
		goto failure;
	if (create_ipsec_pcd_fqs(&ipsecinfo, 1)) {
		goto failure;
	}
	register_cdx_deinit_func(cdx_dpa_ipsec_exit);
	/* Last, once everything a reader could reach through it exists, and
	 * ordered after it: a reader that sees the flag must see all of it. */
	smp_store_release(&dpa_ipsec_ready, true);
	return SUCCESS;

failure:
	cdx_dpa_ipsec_exit();
	return FAILURE;
}

void cdx_dpa_ipsec_exit(void)
{
	DPAIPSEC_INFO("%s::\n", __func__);
	/* First, so that nothing admitted from here on finds state that is
	 * being torn down below it. */
	WRITE_ONCE(dpa_ipsec_ready, false);
	/* Live and retiring SAs pin the module; module shutdown stops the
	 * producer ports before this callback. Init rollback admits no SA.
	 * Retain the pool while queues retire, return pending frames and
	 * finish portal callbacks. */
	cdx_destroy_fq_list(&ipsecinfo.ipsec_pcd_fqs);
	ipsecinfo.expt_fq_count = 0;
	if (ipsecinfo.ofport_handle >= 0) {
		release_offline_port(IPSEC_FMAN_IDX, ipsecinfo.ofport_handle);
		ipsecinfo.ofport_handle = -1;
	}
	memset(ipsecinfo.ofport_td, 0, sizeof(ipsecinfo.ofport_td));
#ifdef CS_TAIL_DROP
	if (ipsecinfo.cgr_initialized) {
		cdx_dpaa_ingress_cgr_exit(&ipsecinfo.cgr);
		ipsecinfo.cgr_initialized = false;
	}
#endif
	ipsec_exception_cgr_exit();
	release_ipsec_bpool(&ipsecinfo);
	release_ipsec_sg_pools();
	/* Held FQIDs stay listed: what becomes of them is decided once CDX has
	 * settled what it recorded as possibly linked, after this
	 * (cdx_dpa_ipsec_held_fqids_exit()). */
	return;
}
#else
#define cdx_dpa_ipsec_init()
struct dpa_bp* get_ipsec_bp(void)
{
	return NULL;
}
bool cdx_dpa_ipsec_ready(void)
{
	return false;
}
unsigned int cdx_dpa_ipsec_release_held_fqids(void)
{
	return 0;
}
void cdx_dpa_ipsec_held_fqids_exit(bool settled)
{
}
#endif

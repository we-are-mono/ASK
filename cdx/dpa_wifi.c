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
#include "layer2.h"
#include "cdx.h"
#include "cdx_wifi_backend.h"
#include "procfs.h"

//uncomment to allow debug prints
//#define DPA_WIFI_DEBUG  1

static DEFINE_PER_CPU(unsigned int, num_tx_done);
static atomic_t vwd_tx_pending = ATOMIC_INIT(0);
static struct delayed_work vwd_tx_work;
static bool vwd_stopping = true;
#define PORTID_SHIFT_VAL 	8
#define VAP_TX_CONF_BUF_COUNT	128
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

#define percpu_var_sum(var, total)\
{\
	unsigned int ii; \
	total = 0;\
	for_each_possible_cpu(ii)\
		total += per_cpu(var, ii);\
}

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
 *        Datapath consumers key on net_dev->wifi_offload_dev (the
 *        lock-free ipsec xmit hook -- release-published only after
 *        the FQs are live) or on VAP_ST_OPEN (the forwarding dequeue
 *        path), so they never observe a half-built VAP.
 *   vwd.txlock (spinlock_t)
 *      - Serializes draining the tx-done buffer pool, from the
 *        reclaim work and from exit, against the vwd_stopping
 *        transition.
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
static void vwd_release_pcd_fqs(struct dpaa_vwd_priv_s *priv);
void drain_bp_tx_done_bpool(struct dpa_bp *bp);

/* In case VWD OFFLOAD , headers can be added in ucode, and the length of the 
	 original buffer can be increased. And this increased length is written from 
	 fixed offset (192) for packets coming from OH port causing headers to grow at tail.
	 So tailroom is introduced to allow the tail to grow upto 64 bytes */
#define SKB_ASK_TAILROOM 	64

/* This function transmits local ESP packets to SEC for processing */
static int vwd_xmit_local_packet(struct sk_buff *skb)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vap_desc_s *vap;

	INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_total_local_tx);
	if (!skb->dev->wifi_offload_dev)
		goto send_pkt;

	vap = (struct vap_desc_s *)skb->dev->wifi_offload_dev;

	/* Only what SEC was given: a frame the submit could not hand over is
	 * already freed and counted as the device's transmit drop. */
	if (!dpaa_submit_outb_pkt_to_SEC(skb, skb->dev, priv->txconf_bp))
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_local_tx_dpaa);

	return 0;
send_pkt:
	return original_dev_queue_xmit(skb);
}

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
		total_stats.pkts_local_tx_dpaa += per_cpu_stats->pkts_local_tx_dpaa;
		total_stats.pkts_slow_forwarded += per_cpu_stats->pkts_slow_forwarded;
		total_stats.pkts_rx_fast_forwarded += per_cpu_stats->pkts_rx_fast_forwarded;
		total_stats.pkts_rx_ipsec += per_cpu_stats->pkts_rx_ipsec;
		total_stats.pkts_slow_path_drop += per_cpu_stats->pkts_slow_path_drop;
	}

	len += sprintf(buf, "VAP (id : %d  name : %s)\n",ii,priv->vaps[ii].ifname);
	len += sprintf(buf + len, "\nTo DPAA\n");
	len += sprintf(buf + len, "  WiFi local Tx pkts submitted to DPAA : %u\n", total_stats.pkts_local_tx_dpaa);

	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  WiFi Rx pkts : %u \n", total_stats.pkts_slow_forwarded);
	len += sprintf(buf + len, "  WiFi Tx pkts : %u \n", total_stats.pkts_rx_fast_forwarded);
	len += sprintf(buf + len, "  WiFi Tx ipsec pkts : %u\n", total_stats.pkts_rx_ipsec);
	len += sprintf(buf + len, "  WiFI Rx slow path drops : %u\n", total_stats.pkts_slow_path_drop);

	return len;
}

/** vwd_show_dump_stats
 *
 */
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	unsigned int total_num_tx_done;
	//int ii;
	struct vwd_global_stats_s *per_cpu_stats;
	struct vwd_global_stats_s total_stats;
	int i;

	memset(&total_stats, 0, sizeof(struct vwd_global_stats_s));
	for_each_possible_cpu(i) {
		per_cpu_stats = per_cpu_ptr(priv->vwd_global_stats, i);
		total_stats.pkts_total_local_tx += per_cpu_stats->pkts_total_local_tx;
		total_stats.pkts_slow_fail += per_cpu_stats->pkts_slow_fail;
		total_stats.pkts_dev_down_drop += per_cpu_stats->pkts_dev_down_drop;
		total_stats.pkts_tx_errors += per_cpu_stats->pkts_tx_errors;
	}

	len += sprintf(buf + len, "\nStatus\n");
	percpu_var_sum(num_tx_done, total_num_tx_done);
	len += sprintf(buf + len, "  tx done  %u\n", total_num_tx_done);
	len += sprintf(buf + len, "  Hardware-owned frames : %d\n",
			atomic_read(&vwd_tx_pending));

	len += sprintf(buf + len, "\nTo DPAA\n");
	len += sprintf(buf + len, "  WiFi local Tx pkts : %u\n", total_stats.pkts_total_local_tx);

	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  Hardware/enqueue errors : %u\n", total_stats.pkts_tx_errors);
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



struct vwd_dma_mapping {
	dma_addr_t addr;
	unsigned int size;
	unsigned int page_offset;
	struct page *page;
};

/* Completion in BMan returns only the buffer address, not the FD. Keep
 * ownership and the original mappings before the DMA area, on separate
 * cache lines. Never use hardware-writable SG entries to unmap a frame.
 */
struct vwd_tx_buffer {
	struct sk_buff *skb;
	struct net_device *dev;
	struct vap_desc_s *vap;
	u32 generation;
	unsigned int size;
	unsigned int num_maps;
	bool page_allocated;
	struct vwd_dma_mapping maps[DPA_SGT_MAX_ENTRIES];
	u8 buffer[] __aligned(SMP_CACHE_BYTES);
};

static void vwd_free_tx_buffer(struct vwd_tx_buffer *tx)
{
	dev_put(tx->dev);
	if (tx->page_allocated)
		free_page((unsigned long)tx);
	else
		kfree(tx);
}

static void vwd_complete_tx_buffer(struct vwd_tx_buffer *tx)
{
	vwd_free_tx_buffer(tx);
	get_cpu_var(num_tx_done)++;
	put_cpu_var(num_tx_done);
	atomic_dec(&vwd_tx_pending);
}

static void vwd_unmap_payload(struct dpa_bp *bp, struct vwd_tx_buffer *tx)
{
	unsigned int i;

	for (i = 0; i < tx->num_maps; i++) {
		struct vwd_dma_mapping *map = &tx->maps[i];

		if (map->page)
			dma_unmap_page(bp->dev, map->addr, map->size,
				       DMA_BIDIRECTIONAL);
		else
			dma_unmap_single(bp->dev, map->addr, map->size,
					 DMA_BIDIRECTIONAL);
	}
}

static struct vwd_tx_buffer *vwd_unmap_tx_buffer(struct dpa_bp *bp,
					       dma_addr_t addr)
{
	/* Like the surrounding DPAA SDK, this path uses direct DMA addresses. */
	struct vwd_tx_buffer *tx = (void *)((u8 *)phys_to_virt(addr) -
					offsetof(struct vwd_tx_buffer, buffer));

	dma_unmap_single(bp->dev, addr, tx->size, DMA_BIDIRECTIONAL);
	vwd_unmap_payload(bp, tx);
	return tx;
}

/* Locate a returned segment in the original DMA mappings before reading it.
 * Hardware may adjust descriptors when it changes packet headers.
 */
static int vwd_sg_mapping(struct vwd_tx_buffer *tx, const struct qm_sg_entry *sg,
			 unsigned int *offset)
{
	dma_addr_t addr = qm_sg_addr(sg) + qm_sg_entry_get_offset(sg);
	unsigned int len = qm_sg_entry_get_len(sg);
	unsigned int i;

	if (qm_sg_entry_get_ext(sg) || !len)
		return -EINVAL;
	for (i = 0; i < tx->num_maps; i++) {
		struct vwd_dma_mapping *map = &tx->maps[i];

		if (addr >= map->addr && addr - map->addr <= map->size &&
		    len <= map->size - (addr - map->addr)) {
			*offset = addr - map->addr;
			return i;
		}
	}
	return -EINVAL;
}

static void vwd_copy_segment(struct vwd_tx_buffer *tx, unsigned int index,
			     unsigned int offset, u8 *dst, unsigned int len)
{
	struct vwd_dma_mapping *map = &tx->maps[index];

	if (!map->page) {
		memcpy(dst, tx->skb->head + offset, len);
		return;
	}
	offset += map->page_offset;
	while (len) {
		struct page *page = nth_page(map->page, offset >> PAGE_SHIFT);
		unsigned int off = offset_in_page(offset);
		unsigned int count = min(len, (unsigned int)PAGE_SIZE - off);
		void *src = kmap_local_page(page);

		memcpy(dst, src + off, count);
		kunmap_local(src);
		dst += count;
		offset += count;
		len -= count;
	}
}

static struct sk_buff *vwd_tx_fd_to_skb(const struct qm_fd *fd,
				      struct vwd_tx_buffer **owner)
{
	struct vwd_tx_buffer *tx = vwd_unmap_tx_buffer(vwd.txconf_bp,
						     qm_fd_addr(fd));
	struct sk_buff *skb = tx->skb, *nskb = NULL;
	unsigned int off = dpa_fd_offset(fd), total = 0, count = 0, i;
	struct qm_sg_entry *sgt;
	bool unchanged = true;

	/* The caller retains the device reference through delivery or drop. */
	*owner = tx;
	if (fd->format != qm_fd_sg || off > tx->size - DPA_SGT_SIZE)
		goto drop;
	sgt = (void *)(tx->buffer + off);
	for (i = 0; i < DPA_SGT_MAX_ENTRIES; i++) {
		unsigned int offset, len = qm_sg_entry_get_len(&sgt[i]);
		int index = vwd_sg_mapping(tx, &sgt[i], &offset);

		if (index < 0 || total > dpa_fd_length(fd) ||
		    len > dpa_fd_length(fd) - total)
			goto drop;
		if (index != i || offset != (i ? 0 : skb_headroom(skb)) ||
		    len != (i ? tx->maps[index].size : skb_headlen(skb)))
			unchanged = false;
		total += len;
		if (qm_sg_entry_get_final(&sgt[i])) {
			count = i + 1;
			break;
		}
	}
	if (!count || total != dpa_fd_length(fd) || total < ETH_HLEN ||
	    total > ETH_FRAME_LEN + SKB_ASK_TAILROOM)
		goto drop;
	if (unchanged && count == tx->num_maps && total == skb->len) {
		return skb;
	}

	/* Preserve a hardware-modified layout, including Wi-Fi-to-Wi-Fi
	 * forwarding. Ordinary exceptions retain their original nonlinear skb.
	 */
	nskb = alloc_skb(NET_SKB_PAD + NET_IP_ALIGN + total, GFP_ATOMIC);
	if (!nskb)
		goto drop;
	skb_reserve(nskb, NET_SKB_PAD + NET_IP_ALIGN);
	skb_copy_header(nskb, skb);
	skb_headers_offset_update(nskb, skb_headroom(nskb) - skb_headroom(skb));
	for (i = 0; i < count; i++) {
		unsigned int offset, len = qm_sg_entry_get_len(&sgt[i]);
		int index = vwd_sg_mapping(tx, &sgt[i], &offset);

		vwd_copy_segment(tx, index, offset, skb_put(nskb, len), len);
	}
	skb_reset_mac_header(nskb);
	skb_set_network_header(nskb, ETH_HLEN);
	skb_reset_transport_header(nskb);
	/* A changed layout invalidates receive checksum metadata. */
	nskb->ip_summed = CHECKSUM_NONE;
	nskb->csum = 0;
drop:
	dev_kfree_skb_any(skb);
	return nskb;
}

static void vwd_release_tx_frame(const struct qm_fd *fd)
{
	struct vwd_tx_buffer *tx = vwd_unmap_tx_buffer(vwd.txconf_bp,
						     qm_fd_addr(fd));

	dev_kfree_skb_any(tx->skb);
	vwd_complete_tx_buffer(tx);
}

static void vwd_ern(struct qman_portal *portal, struct qman_fq *fq,
		    const struct qm_mr_entry *msg)
{
	INCR_PER_CPU_STAT(vwd.vwd_global_stats, pkts_tx_errors);
	vwd_release_tx_frame(&msg->ern.fd);
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

static int process_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct sk_buff *skb;
	struct net_device *dev;
	struct vap_desc_s *vap;
	struct vwd_tx_buffer *tx;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::exception packet\n", __func__);
	DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d addr %llx status %08x\n", __func__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset,  (uint64_t)dq->fd.addr, dq->fd.status);
#endif

	skb = vwd_tx_fd_to_skb(&dq->fd, &tx);

	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s::unable to get skb pointer for fd\n", __func__);
		goto rel_fd;
	}

	dev = tx->dev;
	vap = tx->vap;
	/* A completion may outlive removal and re-registration of its VAP. */
	if (READ_ONCE(vap->state) != VAP_ST_OPEN ||
	    READ_ONCE(vap->generation) != tx->generation ||
	    (void *)READ_ONCE(dev->wifi_offload_dev) != vap ||
	    READ_ONCE(dev->reg_state) != NETREG_REGISTERED) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_dev_down_drop);
		dev_kfree_skb(skb);
		goto rel_fd;
	}
	skb->protocol = eth_type_trans(skb, dev);
	skb->expt_pkt = 1;
	if (netif_receive_skb(skb) == NET_RX_DROP) {
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_ERROR("%s::netif_receive_skb:NET_RX_DROP\n", __func__);
#endif
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_path_drop);
	}
	INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_forwarded);
rel_fd:
	vwd_complete_tx_buffer(tx);
	return 0;
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

static enum qman_cb_dqrr_result vwd_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;

	if (unlikely(vwd_napi_schedule(portal)))
		return qman_cb_dqrr_stop;

	process_rx_exception_pkt(portal, fq, dq);
	return qman_cb_dqrr_consume;
}


static enum qman_cb_dqrr_result vwd_rx_error(struct qman_portal *portal,
		struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;

	if (unlikely(vwd_napi_schedule(portal)))
		return qman_cb_dqrr_stop;
	INCR_PER_CPU_STAT(vwd.vwd_global_stats, pkts_tx_errors);
	vwd_release_tx_frame(&dq->fd);
	return qman_cb_dqrr_consume;
}


static void vwd_send_to_vap(struct sk_buff* skb)
{
	struct ethhdr *hdr;

	hdr = (struct ethhdr *)skb->data;
	skb->protocol = hdr->h_proto;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof(struct ethhdr));
	skb->priority = 0;
	original_dev_queue_xmit(skb);
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
	struct vwd_tx_buffer *tx = NULL;
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
	if (dpa_bp == priv->txconf_bp) {
		skb = vwd_tx_fd_to_skb(&dq->fd, &tx);
		goto process_skb;
	}
	/* Other pools retain their Ethernet/IPsec ownership rules. */
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
	/* Check if buffer is from ethernet pool to refill buffer pool
	   for wifi packets, buffers are skb buffers and they will get freed to kernel */
	if (dpa_bp != priv->txconf_bp)
	{
		count_ptr = raw_cpu_ptr(vwd.eth_priv->percpu_count);
		if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
				CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD))) {
			//if we cant refill give this up
			goto rel_fd;
		}
		*count_ptr -= 1;
	}

	skb = contig_fd_to_vwd_skb(priv->eth_priv, &dq->fd);

	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s::contig_fd_to_vwd_skb failed\n", __func__);
		goto rel_fd;
	}

process_skb:
	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		goto done;
	}
	skb->dev = net_dev;

	INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_fast_forwarded);
	if (dpa_bp == ipsec_bp) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_ipsec);
	}

	vwd_send_to_vap(skb);
done:
	if (tx)
		vwd_complete_tx_buffer(tx);
	rcu_read_unlock();
	return 0;

rel_fd:
	if (dpa_bp == priv->txconf_bp) {
		vwd_release_tx_frame(&dq->fd);
		goto done;
	}
	{
		struct bm_buffer bmb;

		memset(&bmb, 0, sizeof(struct bm_buffer));
		bmb.bpid = dq->fd.bpid;
		bmb.addr = dq->fd.addr;
		while (bman_release(dpa_bp->pool, &bmb, 1, 0))
			cpu_relax();	
	}
	goto done;
}


static int vwd_init_pcd_fqs(struct dpaa_vwd_priv_s *priv)
{
	uint32_t fqbase;
	uint32_t fqcount;
	uint32_t portid;
	uint32_t ii,jj;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals, max_dist;
	uint32_t next_portal_ch_idx = 0;
	const cpumask_t *affine_cpus;
	struct dpa_fq *dpa_fq;
	struct dpa_iface_info *oh_iface_info;
	struct qman_fq *fq;

	/*get cpu portal channel info */
	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
	if (!num_portals) {
		DPAWIFI_ERROR("%s::unable to get affined portal info\n", __func__);
		return -1;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::num_portals %d ::", __func__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPAWIFI_INFO("%d ", portal_channel[ii]);
	DPAWIFI_INFO("\n");
#endif

	if (get_ofport_max_dist(FMAN_IDX, priv->oh_port_handle, &max_dist) < 0)
	{
		DPAWIFI_ERROR("%s::unable to get distributions for oh port\n", __func__);
		return -1;
	}

	for(jj = 0;jj < max_dist; jj++)
	{

		if (get_oh_port_pcd_fqinfo(FMAN_IDX, priv->oh_port_handle, 
					jj, &fqbase, &fqcount)) {
			DPAWIFI_ERROR("%s::err getting pcd fq\n", __func__) ;
			return -1;
		}
		/*get port id required for FQ creation*/
		if (get_ofport_portid(FMAN_IDX, priv->oh_port_handle, &portid)) {
			DPAWIFI_ERROR("%s::err getting of port id\n", __func__) ;
			return -1;
		}
		DPAWIFI_INFO("%s::pcd FQ base for portid %d  dist %x(%d), count %d\n",
				__func__, portid, fqbase, fqbase, fqcount);

		if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
			DPAWIFI_ERROR("%s::err getting oh iface info of port id %u\n", __func__, portid) ;
			return -1;
		}
		if (oh_iface_info->pcd_proc_entry == NULL)
		{
			DPAWIFI_ERROR("%s()::%d OH iface pcd proc entry is invalid:\n", __func__, __LINE__);
			return -1;
		}

		/*alloc for as many fqs as required */
		priv->wlan_exception_fq = kzalloc((sizeof(struct dpa_fq) * fqcount), GFP_KERNEL);
		if (!priv->wlan_exception_fq) {
			DPAWIFI_ERROR("%s::err allocating fq mem\n", __func__) ;
			return -1;
		}
		/*save dpa_fq base info */
		dpa_fq = priv->wlan_exception_fq;
		/*add port id into FQID */
		fqbase |= (portid << PORTID_SHIFT_VAL);
		/*create all FQs */
		priv->expt_fq_count = 0;
		for (ii = 0; ii < fqcount; ii++) {
			struct qm_mcc_initfq opts;

			memset(dpa_fq, 0, sizeof(struct dpa_fq));
			/*set FQ parameters 
			  dpa_fq->net_dev = vap->wifi_dev; */
			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
			dpa_fq->fqid = fqbase;
			/*set call back function pointer*/
			fq = &dpa_fq->fq_base;
			fq->cb.dqrr = vwd_rx_exception_pkt;
			/*round robin channel like ethernet driver does */
			dpa_fq->channel = portal_channel[next_portal_ch_idx];
			if (next_portal_ch_idx == (num_portals - 1))
				next_portal_ch_idx = 0;
			else
				next_portal_ch_idx++;
			dpa_fq->wq = DEFA_WQ_ID;
			/*set options similar to ethernet driver */
			memset(&opts, 0, sizeof(struct qm_mcc_initfq));
			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
			opts.fqd.context_a.stashing.exclusive =
				(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
			/*create FQ */
			if (qman_create_fq(dpa_fq->fqid, 0, fq)) {
				DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
						__func__, dpa_fq->fqid);
				goto err_ret;
			}
			opts.fqid = dpa_fq->fqid;
			opts.count = 1;
			opts.fqd.dest.channel = dpa_fq->channel;
			opts.fqd.dest.wq = dpa_fq->wq;
			opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
					QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);

			/*init FQ */
			if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
				DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
						__func__, dpa_fq->fqid);
				qman_destroy_fq(fq, 0);
				goto err_ret;
			}

			cdx_create_type_fqid_info_in_procfs(fq, PCD_DIR, oh_iface_info->pcd_proc_entry, NULL);
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s::created pcd fq %x(%d) for wlan packets "
					"channel 0x%x\n", __func__,
					dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
			/*next FQ */
			dpa_fq++;
			fqbase++;
			priv->expt_fq_count++;
		}
	}
	return 0;
err_ret:
	vwd_release_pcd_fqs(priv);
	return -1;
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
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
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
	//uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	struct dpa_fq **dpa_fq_ptr;
	struct dpa_iface_info *oh_iface_info;
	uint32_t flags;
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

	if (oh_iface_info->rx_proc_entry == NULL)
	{
		DPAWIFI_ERROR("%s()::%d OH iface rx proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}


	/* create FQ for exception packets from wireless interface */
	dpa_fq = kzalloc(sizeof(struct dpa_fq), GFP_KERNEL);
	if (!dpa_fq) {
		DPAWIFI_ERROR("%s::unable to alloc mem for dpa_fq\n", __func__) ;
		return -1;
	}
	memset(dpa_fq, 0, sizeof(struct dpa_fq));
	memset(&opts, 0, sizeof(struct qm_mcc_initfq));
	fq = &dpa_fq->fq_base;
	fq->cb.ern = vwd_ern;
	/* Retirement can return frames that have not reached FMan. */
	fq->cb.dqrr = vwd_rx_error;
	dpa_fq_ptr = NULL;
	flags = 0;
	/* offline port fq */
	flags |= QMAN_FQ_FLAG_TO_DCPORTAL;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	dpa_fq->channel = vap->channel;
	/* contexta, b  */
	opts.fqd.context_a.hi = 0; //0x12000000; //OVFQ, A2V, OVOM
	opts.fqd.context_a.lo = 0x00000000; //0;
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

	dpa_fq->fqid = fq->fqid;
	opts.fqid = dpa_fq->fqid;
	opts.count = 1;
	opts.fqd.dest.channel = dpa_fq->channel;
	opts.fqd.dest.wq = dpa_fq->wq;
	opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
	if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
		DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
				__func__, dpa_fq->fqid);
		qman_destroy_fq(fq, 0);
		kfree(dpa_fq);
		return -1;
	}	

	/* RX OH2 */
	cdx_create_type_fqid_info_in_procfs(fq, RX_DIR, 
				oh_iface_info->rx_proc_entry, NULL);
	vap->wlan_fq_to_fman = dpa_fq;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::created fq %x(%d) for wlan packets "
			"channel 0x%x\n", __func__,
			dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
	return 0;
}



static int release_vap_fqs(struct vap_desc_s *vap)
{
	int i;
	/* This WLAN exception FQ is used for all vwd interfaces */
	/* TODO - Need to modify to delete only for last interface, and add 
	   for 1st interface */	
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: vwd count :%d\n", __func__, vap->vwd->expt_fq_count);
#endif

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

	if (vap->wlan_fq_to_fman)
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:: releasing fq to fman :%d\n", __func__, vap->wlan_fq_to_fman->fqid);
#endif
		cdx_destroy_fq(&vap->wlan_fq_to_fman->fq_base);
		kfree(vap->wlan_fq_to_fman);
		vap->wlan_fq_to_fman = NULL;
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

/* This function returns net dev with VAP id */
int dpaa_get_wifi_dev(uint16_t vap_id, void** netdev)
{
	*netdev = (void*)vwd.vaps[vap_id].wifi_dev;
	return 0;
}

/* This function returns  WIFI related OH port handle */
int dpaa_get_wifi_ohport_handle( uint32_t* oh_handle)
{
	*oh_handle = vwd.oh_port_handle;
	return 0;
}

static int add_device_tx_done_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	struct dpa_bp *bp;
	struct dpa_bp *bp_parent;

	if (get_phys_port_poolinfo_bysize(VAPDEV_BUFSIZE, &vwd->parent_pool_info)) {
		DPAWIFI_ERROR("%s::failed to locate eth bman pool for dev %s\n", __func__, vwd->name);
		return -1;
	}
	bp_parent = dpa_bpid2pool(vwd->parent_pool_info.pool_id);
	if (!bp_parent)
		return -ENODEV;

	bp = kzalloc(sizeof(struct dpa_bp), GFP_KERNEL);

	if (unlikely(bp == NULL)) {
		DPAWIFI_ERROR("%s::failed to allocate mem for bman pool for dev %s\n",
				__func__,vwd->name);
		return -1;
	}
	bp->size = VAPDEV_BUFSIZE;
	bp->config_count = VAP_TX_CONF_BUF_COUNT;
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAWIFI_ERROR("%s::dpa_bp_alloc failed for dev %s\n", __func__, vwd->name);
		kfree(bp);
		return -1;
	}
	vwd->txconf_bp = bp;
	printk("%s::txconf bpid %d, for dev %s\n", __func__, bp->bpid, vwd->name);

	return 0;
}

void drain_bp_tx_done_bpool(struct dpa_bp *bp)
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
			struct vwd_tx_buffer *tx;

			tx = vwd_unmap_tx_buffer(bp, bm_buf_addr(&bmb[i]));
			dev_kfree_skb_any(tx->skb);
			vwd_complete_tx_buffer(tx);
		}
	} while (ret > 0);

}

/* Hardware may return the last few frames after traffic has stopped.
 * Reclaim them without waiting for another transmit, including the netdev
 * references that otherwise prevent interface unregistration from finishing.
 */
static void vwd_tx_reclaim_work(struct work_struct *work)
{
	spin_lock_bh(&vwd.txlock);
	drain_bp_tx_done_bpool(vwd.txconf_bp);
	if (!vwd_stopping && atomic_read(&vwd_tx_pending))
		queue_delayed_work(system_wq, &vwd_tx_work, msecs_to_jiffies(10));
	spin_unlock_bh(&vwd.txlock);
}

static int release_device_tx_done_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	if (!vwd->txconf_bp)
		return 0;
	drain_bp_tx_done_bpool(vwd->txconf_bp);
	_dpa_bp_free(vwd->txconf_bp);
	kfree(vwd->txconf_bp);
	vwd->txconf_bp = NULL;
	return 0;
}


/* Both publish to the lock-free dequeue path, process_vap_rx_fwd_pkt(). */
static int set_vap_fqs_netdev(struct vap_desc_s *vap)
{
	int index = 0;
	for (index = 0; index < CDX_VWD_FWD_FQ_MAX; index++)
		WRITE_ONCE(vap->wlan_fq_from_fman[index]->net_dev, vap->wifi_dev);
	WRITE_ONCE(vap->wlan_fq_to_fman->net_dev, vap->wifi_dev);
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
	WRITE_ONCE(vap->wlan_fq_to_fman->net_dev, NULL);
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
	if (get_ofport_info(FMAN_IDX, priv->oh_port_handle, &vap->channel,
				&vap->td[0]))
	{
		dev_put(wifi_dev);
		return -1;
	}

	vap->ifindex = cmd->ifindex;

	memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->wifi_dev = wifi_dev;
	vap->vwd = priv;

	/* vap->wlan_fq_to_fman is NULL means so far this interface is not up. If it gets up first time
	   it creates all the frame queues. These frame queues can delete only cdx module gets unloaded.*/
	if (!vap->wlan_fq_to_fman)
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
	 * Published only now, after the FQs are live: the ipsec xmit
	 * hook consumes this pointer lock-free, so a release-publish
	 * after the FQ stores is what keeps it from seeing a half-built
	 * VAP. The caller flips vap->state to VAP_ST_OPEN under vaplock.
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

	/* unpublish from the lock-free ipsec xmit hook and the dequeue path
	 * first, then tear down the fq netdev links they would have used */
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
 * aliases and nothing else puts them back. Safe for any such VLAN: its
 * ESP traffic takes the SEC round-trip and falls back to the
 * exception/software path. Caller holds rtnl. */
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
			 * the dequeue path and the ipsec xmit hook key on
			 * VAP_ST_OPEN / wifi_offload_dev and stay away. */
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
	return READ_ONCE(vwd.vaps[vap_id].wlan_fq_to_fman) != NULL;
}

static int vwd_init_ohport(struct dpaa_vwd_priv_s *priv)
{
	int handle;

	/* Get OH port for this driver */
	handle = alloc_offline_port(FMAN_IDX, PORT_TYPE_WIFI, vwd_rx_exception_pkt, vwd_rx_error);
	if (handle < 0)
	{
		DPAWIFI_ERROR("%s: Error in allocating OH port Channel\n", __func__);
		return -1;
	}
	priv->oh_port_handle = handle;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: allocated oh port %d\n", __func__, priv->oh_port_handle);
#endif


	/* Send exceptions to the parser, without the SEC error check. */
	handle = ohport_set_ofne(priv->oh_port_handle, 0x440000);
	if (handle < 0)
		release_offline_port(FMAN_IDX, priv->oh_port_handle);
	return handle;
}

static void vwd_release_pcd_fqs(struct dpaa_vwd_priv_s *priv)
{
	struct qman_fq* fq;
	struct dpa_fq* dpafq;
	int i;

	if (priv->wlan_exception_fq)
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:: releasing expt fq :%d\n", __func__, priv->expt_fq_count);
#endif
		dpafq = priv->wlan_exception_fq;
		for (i = 0; i < priv->expt_fq_count; i++)
		{
			fq= &dpafq->fq_base;
			cdx_destroy_fq(fq);
			dpafq++;
		}
		kfree(priv->wlan_exception_fq);
		priv->wlan_exception_fq = NULL;
		priv->expt_fq_count = 0;
	}

	return;
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
	spin_lock_init(&priv->txlock);
	INIT_DELAYED_WORK(&vwd_tx_work, vwd_tx_reclaim_work);
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
	rc = add_device_tx_done_bpool(priv);
	if (rc)
		goto err_eth;
	rc = vwd_init_ohport(priv);
	if (rc < 0)
		goto err_pool;
	rc = vwd_init_pcd_fqs(priv);
	if (rc)
		goto err_oh;

	/* The class and its device carry no character device: they are where
	 * the statistics and per-VAP files live, under /sys/class/vwd/vwd0. */
	priv->vwd_class = class_create("vwd");
	if (IS_ERR(priv->vwd_class)) {
		rc = PTR_ERR(priv->vwd_class);
		goto err_fqs;
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
	rc = dpa_register_wifi_xmit_local_hook(vwd_xmit_local_packet);
	if (rc < 0)
		goto err_hooks;

	WRITE_ONCE(vwd_stopping, false);
	register_cdx_deinit_func(dpaa_vwd_exit);
	return 0;

err_hooks:
	dpaa_vwd_down(priv);
err_device:
	device_unregister(priv->vwd_device);
err_class:
	class_destroy(priv->vwd_class);
err_fqs:
	vwd_release_pcd_fqs(priv);
err_oh:
	vwd_free_ohport(priv);
	synchronize_net();
err_pool:
	release_device_tx_done_bpool(priv);
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
	unsigned long deadline = jiffies + 5 * HZ;
	int i;

	/* Block new submissions before unpublishing any callback resources. */
	spin_lock_bh(&priv->txlock);
	WRITE_ONCE(vwd_stopping, true);
	spin_unlock_bh(&priv->txlock);
	dpa_unregister_wifi_xmit_local_hook();
	dpaa_vwd_down(priv);
	cancel_delayed_work_sync(&vwd_tx_work);

	/* Keep completion callbacks and the pool alive until hardware gives
	 * back every descriptor. A timeout cannot make DMA memory safe to free.
	 */
	for (;;) {
		spin_lock_bh(&priv->txlock);
		drain_bp_tx_done_bpool(priv->txconf_bp);
		spin_unlock_bh(&priv->txlock);
		if (!atomic_read(&vwd_tx_pending))
			break;
		if (time_after(jiffies, deadline)) {
			pr_warn("vwd: waiting for %d hardware-owned frames\n",
				atomic_read(&vwd_tx_pending));
			deadline = jiffies + 5 * HZ;
		}
		usleep_range(1000, 2000);
	}
	for (i = 0; i < MAX_WIFI_VAPS; i++)
		release_vap_fqs(&priv->vaps[i]);
	vwd_release_pcd_fqs(priv);
	vwd_free_ohport(priv);
	synchronize_net();
	/* Every queue is retired, so no poll can be scheduled any more. */
	vwd_napi_del();
	release_device_tx_done_bpool(priv);
	vwd_release_stats(priv);
	dev_put(priv->eth_priv->net_dev);
	priv->eth_priv = NULL;
	device_unregister(priv->vwd_device);
	class_destroy(priv->vwd_class);
}

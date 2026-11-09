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
#include <linux/if_arp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/wg_fastpath.h>
#include <net/netfilter/nf_flow_table.h>
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
#include "cdx_flowtable_backend.h"
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

/* A WireGuard VAP's receive steers, summed over its installed slots. */
struct vwd_wg_rx_stats {
	unsigned int steers;
	unsigned long delivered, to_stack, dropped, forwarded, opened;
	unsigned long skipped, skip_fail;
};
static void vwd_wg_steers_stats(const struct net_device *wg,
				struct vwd_wg_rx_stats *st);

static ssize_t vwd_show_vap_stats(struct device *dev, struct device_attribute *attribute, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	int ii = 0;

	struct vap_stats_s *per_cpu_stats;
	struct vap_stats_s total_stats;
	struct vwd_wg_rx_stats wg_rx;
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
		total_stats.pkts_wg_sealed += per_cpu_stats->pkts_wg_sealed;
		total_stats.pkts_wg_tx_fail += per_cpu_stats->pkts_wg_tx_fail;
	}

	len += sprintf(buf, "VAP (id : %d  name : %s)\n",ii,priv->vaps[ii].ifname);
	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  WiFi Tx pkts : %u \n", total_stats.pkts_rx_fast_forwarded);
	len += sprintf(buf + len, "  WiFi Tx ipsec pkts : %u\n", total_stats.pkts_rx_ipsec);
	len += sprintf(buf + len, "  WireGuard sealed : %u\n", total_stats.pkts_wg_sealed);
	len += sprintf(buf + len, "  WireGuard tx fail : %u\n", total_stats.pkts_wg_tx_fail);
	vwd_wg_steers_stats(READ_ONCE(priv->vaps[ii].wifi_dev), &wg_rx);
	len += sprintf(buf + len, "  WireGuard rx steers : %u\n", wg_rx.steers);
	len += sprintf(buf + len, "  WireGuard rx delivered : %lu\n", wg_rx.delivered);
	len += sprintf(buf + len, "  WireGuard rx to stack : %lu\n", wg_rx.to_stack);
	len += sprintf(buf + len, "  WireGuard rx dropped : %lu\n", wg_rx.dropped);
	len += sprintf(buf + len, "  WireGuard rx forwarded : %lu\n", wg_rx.forwarded);
	len += sprintf(buf + len, "  WireGuard rx opened : %lu\n", wg_rx.opened);
	len += sprintf(buf + len, "  WireGuard rx order skipped : %lu\n", wg_rx.skipped);
	len += sprintf(buf + len, "  WireGuard rx order skip fail : %lu\n", wg_rx.skip_fail);

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
	/* A device with no link layer (WireGuard) takes the packet, not the
	 * frame the classifier finished with a made-up header. */
	if (skb->dev->type != ARPHRD_ETHER) {
		skb_pull(skb, sizeof(struct ethhdr));
		skb_reset_network_header(skb);
	}
	skb->priority = 0;
	dev_queue_xmit(skb);
	return;
}

static void vap_fwd_ern(struct qman_portal *portal, struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	dpa_fd_release(NULL, &msg->ern.fd);
}

/* The DPAA ports a WireGuard VAP's sealed frames may leave by, with cdx's
 * forwarding queues to each: the queues the classifier itself sends on, which
 * return a buffer to its pool instead of confirming it to the driver (the
 * driver's own egress queues confirm every frame, and its confirmation path
 * would look for an skb). Ports are load-once, so the table is filled under
 * the control mutex and RTNL and read without a lock. */
#define VWD_WG_PORTS 16
static struct {
	struct net_device *dev;
	struct eth_iface_info *eth;
} vwd_wg_ports[VWD_WG_PORTS];
static unsigned int vwd_wg_nports;

void vwd_wg_ports_update(void)
{
	struct dpa_iface_info *iface;
	struct net_device *dev;
	unsigned int n = 0;

	ASSERT_RTNL();
	for_each_netdev(&init_net, dev) {
		if (n == VWD_WG_PORTS)
			break;
		if (!dpa_netdev_is_dpaa(dev))
			continue;
		iface = dpa_get_ifinfo_by_netdev(dev);
		if (!iface || !(iface->if_flags & IF_TYPE_ETHERNET))
			continue;
		WRITE_ONCE(vwd_wg_ports[n].eth, &iface->eth_info);
		WRITE_ONCE(vwd_wg_ports[n].dev, dev);
		n++;
	}
	smp_store_release(&vwd_wg_nports, n);
}

static struct eth_iface_info *vwd_wg_port(const struct net_device *dev)
{
	unsigned int i, n = smp_load_acquire(&vwd_wg_nports);

	for (i = 0; i < n; i++)
		if (READ_ONCE(vwd_wg_ports[i].dev) == dev)
			return READ_ONCE(vwd_wg_ports[i].eth);
	return NULL;
}

static bool vwd_wg_can_tx(const struct net_device *dev)
{
	if (!vwd_wg_port(dev))
		return false;
#ifdef CONFIG_FSL_DPAA_CEETM
	/* ponytail: a port a hardware qdisc owns shapes through its class
	 * queues, which this does not pick; such a port keeps the slow path. */
	if (((struct dpa_priv_s *)netdev_priv(dev))->ceetm_en)
		return false;
#endif
	return true;
}

/* Receive steers for WireGuard peers.
 *
 * A peer's packets arrive on the port its sealed frames leave by, addressed to
 * the router, so they miss every classifier table and end in the port's
 * Ethernet distribution -- which hashes only the L2 pair, the same for every
 * tunnel behind one upstream gateway, so every tunnel lands on one queue and
 * one CPU, through the exception policer. The seal reports the outer tuple it
 * wrote; its reverse is the peer's, and a classifier entry for that exact
 * tuple (cdx_ehash_steer4_add()) enqueues it, unmodified, to a frame queue of
 * the slot's own on a CPU picked round robin (struct vwd_wg_rxq below), whose
 * dequeue hands the datagram straight to WireGuard, as its socket would --
 * without the IP input, routing, netfilter and socket lookup the stack spends
 * on every packet.
 *
 * Security: a steered tuple skips the exception policer
 * CDX_EXPT_ETH_RATELIMIT, and its datagrams skip the netfilter PREROUTING and
 * INPUT hooks (and conntrack, tc ingress and rp_filter with them). Only an
 * established peer's exact five-tuple is ever steered, the one the router
 * itself just sealed for, and WireGuard authenticates every datagram it takes.
 *
 * The fast path only notes a tuple: it claims an empty slot without a lock
 * (EMPTY -> CLAIMING by cmpxchg, the fields written, then PENDING with
 * release) and schedules the worker. Everything after that -- the install,
 * the delete, every transition out of PENDING, INSTALLED or FAILED, and the
 * slot's `ct` and `rxq` -- happens under the control mutex. The fast path reads the
 * fields of a slot it does not own racily: a torn read can only make it skip
 * one claim, which the next frame makes again.
 *
 * Neither netdev is referenced. `wg` is compared by the slot: the worker
 * installs only for a device VWD still holds open as a VAP, and
 * cdx_wifi_vap_del() drops every slot of the device before the VAP's record
 * goes. The queue's dequeue does follow its device, and so may not rely on
 * that drop -- which can come after the device has unregistered -- but only on
 * VWD's own unregister notifier: see vwd_wg_rxq_dev(). `port` is a DPAA port,
 * which is load-once (vwd_wg_ports above).
 *
 * ponytail: 16 slots, first come; a peer past them stays on the miss path.
 * ponytail: endpoint roaming is not followed. A roamed peer's new tuple takes a
 * new slot; the old entry stays until the VAP is deleted.
 * ponytail: a FAILED slot is not retried while its device lives. */
enum {
	VWD_WG_STEER_EMPTY,
	VWD_WG_STEER_CLAIMING,
	VWD_WG_STEER_PENDING,
	VWD_WG_STEER_INSTALLED,
	VWD_WG_STEER_FAILED,
};

/* A steer queue's counters, per CPU, as an ordered queue is dequeued on every
 * CPU at once; read racily for statistics. */
struct vwd_wg_rxq_pc {
	unsigned long delivered, to_stack, dropped;
	/* Of delivered: opened where they lay and sent out of a port from the
	 * same buffer, or opened and handed to the device as an skb. */
	unsigned long forwarded, opened;
	/* Ordered queues: sequence numbers given up for a frame not sent on in
	 * order (vwd_wg_skip()), and those QMan never took. */
	unsigned long skipped, skip_fail;
};

/* An installed steer's frame queue, in VWD's forwarding congestion group,
 * polled by VWD's NAPI like a VAP's forwarding queues
 * (create_vap_fwd_from_fman_fqs()). Allocated per install rather than
 * embedded in the slot, because a delete that cannot prove the entry unlinked
 * must leave the queue standing after the slot is reused
 * (vwd_wg_rxq_abandon()).
 *
 * Either on one CPU's portal channel, or `ordered`: on the port's pool
 * channel, which every CPU's portal dequeues, avoiding blocking, so one
 * tunnel's frames are opened on every CPU at once, and with an order
 * restoration point, so QMan puts the frames sent on back in the order they
 * arrived (vwd_wg_rxq_create()). An ordered queue's forwarded frames all
 * leave by egress queue `txq`: restored order across two queues would be lost
 * again at the port.
 *
 * `wg`, `vap` and `gen` name the device the dequeue delivers to and the VWD
 * open it must still be in (vwd_wg_rxq_dev()); `wg` is cleared before the queue
 * is drained or abandoned, after which every frame goes to the stack. */
struct vwd_wg_rxq {
	struct qman_fq fq;
	struct net_device *port;
	struct net_device *wg;
	struct vap_desc_s *vap;
	u32 gen;
	unsigned int cpu;
	bool ordered;
	unsigned int txq;
	struct vwd_wg_rxq_pc __percpu *pc;
	/* delivered at the last vwd_wg_inline_update() tick. */
	unsigned long seen;
};

#define VWD_WG_STEERS 16
static struct vwd_wg_steer {
	unsigned int state;
	struct net_device *wg;
	struct net_device *port;
	/* As the peer sends them: peer -> router, network order. */
	__be32 saddr, daddr;
	__be16 sport, dport;
	struct hw_ct *ct;
	/* Set with the entry, cleared before the queue is freed; statistics
	 * read it under RCU, which the free waits out (cdx_destroy_fq()). */
	struct vwd_wg_rxq *rxq;
} vwd_wg_steers[VWD_WG_STEERS];
/* The next CPU, round robin over the affine ones; under the control mutex. */
static unsigned int vwd_wg_steer_cpu;

static void vwd_wg_steer_work_fn(struct work_struct *work);
static DECLARE_WORK(vwd_wg_steer_work, vwd_wg_steer_work_fn);

static bool vwd_wg_steer_same(const struct vwd_wg_steer *a, const struct vwd_wg_steer *b)
{
	return a->wg == b->wg && a->port == b->port &&
	       a->saddr == b->saddr && a->daddr == b->daddr &&
	       a->sport == b->sport && a->dport == b->dport;
}

/* The fast path's half: lock-free, never sleeps. */
static void vwd_wg_steer_note(struct net_device *wg, const struct wg_fastpath_tx *tx)
{
	struct vwd_wg_steer *s;
	int i, slot = -1;

	if (READ_ONCE(vwd_stopping))
		return;
	for (i = 0; i < VWD_WG_STEERS; i++) {
		s = &vwd_wg_steers[i];
		switch (smp_load_acquire(&s->state)) {
		case VWD_WG_STEER_EMPTY:
			if (slot < 0)
				slot = i;
			break;
		case VWD_WG_STEER_CLAIMING:
			break;
		default:
			if (READ_ONCE(s->wg) == wg && READ_ONCE(s->port) == tx->dev &&
			    READ_ONCE(s->saddr) == tx->daddr &&
			    READ_ONCE(s->daddr) == tx->saddr &&
			    READ_ONCE(s->sport) == tx->dport &&
			    READ_ONCE(s->dport) == tx->sport)
				return;
		}
	}
	if (slot < 0)
		return;
	s = &vwd_wg_steers[slot];
	/* Lost to another CPU: the next frame looks again. */
	if (cmpxchg(&s->state, VWD_WG_STEER_EMPTY, VWD_WG_STEER_CLAIMING) !=
	    VWD_WG_STEER_EMPTY)
		return;
	WRITE_ONCE(s->wg, wg);
	WRITE_ONCE(s->port, tx->dev);
	WRITE_ONCE(s->saddr, tx->daddr);
	WRITE_ONCE(s->daddr, tx->saddr);
	WRITE_ONCE(s->sport, tx->dport);
	WRITE_ONCE(s->dport, tx->sport);
	smp_store_release(&s->state, VWD_WG_STEER_PENDING);
	schedule_work(&vwd_wg_steer_work);
}

/* The VAP `dev` is open as, and that open's generation. Under vaplock, which
 * every state change holds; the generation only moves while the slot is
 * VAP_ST_CONFIGURING (vwd_vap_up()), so an open slot's is stable. */
static struct vap_desc_s *vwd_wg_open_vap(const struct net_device *dev, u32 *gen)
{
	struct vap_desc_s *found = NULL;
	int ii;

	spin_lock_bh(&vwd.vaplock);
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		struct vap_desc_s *vap = &vwd.vaps[ii];

		if (vap->state == VAP_ST_OPEN && vap->wifi_dev == dev) {
			*gen = vap->generation;
			found = vap;
			break;
		}
	}
	spin_unlock_bh(&vwd.vaplock);
	return found;
}

#define vwd_wg_count(q, f)	this_cpu_inc((q)->pc->f)

static unsigned long vwd_wg_sum(const struct vwd_wg_rxq *q, size_t off)
{
	unsigned long sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += READ_ONCE(*(unsigned long *)((u8 *)per_cpu_ptr(q->pc, cpu) + off));
	return sum;
}
#define vwd_wg_total(q, f)	vwd_wg_sum(q, offsetof(struct vwd_wg_rxq_pc, f))

/* An ordered queue's frame owes the queue's order restoration point exactly
 * one enqueue under its sequence number: the frame itself, sent on in order,
 * or a hole, which lets the frames behind it go. */
struct vwd_wg_seq {
	u16 seq;
	bool owed;
};

/* How long an enqueue under an order restoration point waits for room in the
 * portal's ring. It must not be given up lightly: a sequence number never
 * enqueued holds every later frame until the window overflows, and at idle
 * for good. QMan leaves every portal's ring full at once for up to ~200 us
 * under load (measured), past a fixed retry count's reach.
 * ponytail: a ring full past this is not recovered; the queue's next open
 * (wg down/up) gives it a fresh restoration point. */
#define VWD_WG_ORP_WAIT_NS	(5 * NSEC_PER_MSEC)

static int vwd_wg_orp_enqueue(struct vwd_wg_rxq *q, struct qman_fq *fq,
			      const struct qm_fd *fd, u32 flags, u16 seq)
{
	u64 start = 0, now;
	int err;

	while ((err = qman_enqueue_orp(fq, fd, flags, &q->fq, seq)) == -EBUSY) {
		now = ktime_get_ns();
		if (!start)
			start = now;
		else if (now - start > VWD_WG_ORP_WAIT_NS)
			break;
		cpu_relax();
	}
	if (unlikely(err))
		pr_warn_ratelimited("cdx: WireGuard rx order: portal ring full for 5 ms, sequence %u of fqid 0x%x lost\n",
				    seq, q->fq.fqid);
	return err;
}

/* Give up the frame's place in the order, before anything slow is done with
 * it. A hole goes in under the steer queue's own object with an empty
 * descriptor, so a rejection has nothing to free (vwd_wg_hole_ern()). */
static void vwd_wg_skip(struct vwd_wg_rxq *q, struct vwd_wg_seq *s)
{
	static const struct qm_fd none;

	if (!s->owed)
		return;
	s->owed = false;
	if (unlikely(vwd_wg_orp_enqueue(q, &q->fq, &none, QMAN_ENQUEUE_FLAG_HOLE, s->seq)))
		vwd_wg_count(q, skip_fail);
	else
		vwd_wg_count(q, skipped);
}

/* The device a steered datagram may be handed to, or NULL for the stack.
 *
 * Under rcu_read_lock(). The device is not referenced, and the slot's delete
 * (cdx_wifi_vap_del()) may come after the device has unregistered, so what
 * keeps it alive here is VWD's own binding: vwd_netdev_event() takes the VAP
 * out of VAP_ST_OPEN inside the device's NETDEV_UNREGISTER notifier, and the
 * core runs synchronize_net() after its notifiers and before the device can be
 * freed or WireGuard's destructor run (unregister_netdevice_many_notify(), then
 * netdev_run_todo()). A read section that saw the open therefore began before
 * that grace period and ends before either. The generation, bumped by every
 * open (vwd_vap_up()) before the state is published, keeps a later open of the
 * slot -- by another device at a reused address, say -- from passing for the
 * one the steer was installed under. netif_running() keeps a device being
 * closed, whose socket WireGuard has already let go of, on the stack's path. */
static struct net_device *vwd_wg_rxq_dev(const struct vwd_wg_rxq *q)
{
	struct net_device *wg = READ_ONCE(q->wg);
	const struct vap_desc_s *vap = q->vap;

	if (!wg || smp_load_acquire(&vap->state) != VAP_ST_OPEN)
		return NULL;
	if (READ_ONCE(vap->generation) != q->gen || READ_ONCE(vap->wifi_dev) != wg)
		return NULL;
	if (!netif_running(wg))
		return NULL;
	return wg;
}

enum {
	VWD_WG_RX_DELIVER,
	VWD_WG_RX_STACK,
	VWD_WG_RX_DROP,
};

/* What becomes of a steered frame, the skb at its IPv4 header: delivered as
 * WireGuard's socket would take it, handed to the stack for anything that is
 * well formed but not a plain datagram, or dropped as malformed. On delivery
 * the transport header is set and the UDP checksum is validated --
 * CHECKSUM_UNNECESSARY when the parser vouched for it (contig_fd_to_skb() and
 * sg_fd_to_skb() trust FM_FD_STAT_L4CV only with the parse result's checksum
 * at its valid value, and only on a port with NETIF_F_RXCSUM), otherwise
 * checked here over the UDP length. WireGuard checks the UDP length framing
 * again itself (prepare_skb_header()). */
static int vwd_wg_rx_check(struct sk_buff *skb)
{
	const struct iphdr *iph;
	const struct udphdr *uh;
	unsigned int ihl, len, ulen;

	if (skb->protocol != htons(ETH_P_IP) || skb->pkt_type != PACKET_HOST)
		return VWD_WG_RX_STACK;
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return VWD_WG_RX_DROP;
	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->ihl < 5)
		return VWD_WG_RX_DROP;
	ihl = iph->ihl * 4;
	if (!pskb_may_pull(skb, ihl))
		return VWD_WG_RX_DROP;
	iph = ip_hdr(skb);
	if (ip_fast_csum((const u8 *)iph, iph->ihl))
		return VWD_WG_RX_DROP;
	len = ntohs(iph->tot_len);
	if (len < ihl || skb->len < len)
		return VWD_WG_RX_DROP;
	if (pskb_trim_rcsum(skb, len))
		return VWD_WG_RX_DROP;
	iph = ip_hdr(skb);
	/* Options are the stack's to act on and a fragment its to reassemble;
	 * neither is how a WireGuard peer sends. */
	if (ihl != sizeof(*iph) || ip_is_fragment(iph) ||
	    iph->protocol != IPPROTO_UDP)
		return VWD_WG_RX_STACK;
	skb_set_transport_header(skb, ihl);
	if (!pskb_may_pull(skb, ihl + sizeof(*uh)))
		return VWD_WG_RX_DROP;
	iph = ip_hdr(skb);
	uh = udp_hdr(skb);
	ulen = ntohs(uh->len);
	if (ulen < sizeof(*uh) || ulen > len - ihl)
		return VWD_WG_RX_DROP;
	/* A zero checksum is IPv4 UDP's "none", which the socket takes too. */
	if (uh->check && skb->ip_summed != CHECKSUM_UNNECESSARY &&
	    csum_tcpudp_magic(iph->saddr, iph->daddr, ulen, IPPROTO_UDP,
			      skb_checksum(skb, ihl, ulen, 0)))
		return VWD_WG_RX_DROP;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return VWD_WG_RX_DELIVER;
}

static struct eth_iface_info *vwd_wg_port(const struct net_device *dev);
static bool vwd_wg_can_tx(const struct net_device *dev);

/* The download fast path (vwd_wg_rx_raw()): 0 off, 1 on, 2 while the steered
 * tunnels that delivered in the last second sit on two CPUs or more, or for
 * an ordered queue (wg_rx_spread) always. A tunnel on one receive CPU is
 * opened there in arrival order, which its decryption workers outrun; two or
 * more such tunnels, or one opened on every CPU, do not.
 * ponytail: a knob while the trade-off is measured. */
static unsigned int wg_rx_raw = 2;
module_param(wg_rx_raw, uint, 0644);
MODULE_PARM_DESC(wg_rx_raw, "WireGuard download fast path: 0 off, 1 on, 2 with two or more active tunnels");
static bool vwd_wg_raw_auto;

/* Steer queues ordered (struct vwd_wg_rxq): a tunnel opened on every CPU
 * rather than on one receive CPU of its own. Read as a steer is installed and
 * as a tunnel opens, so a change takes effect on the tunnel's next open.
 * ponytail: a knob while the trade-off is measured. */
static unsigned int wg_rx_spread = 1;
module_param(wg_rx_spread, uint, 0644);
MODULE_PARM_DESC(wg_rx_spread, "WireGuard receive: 1 opens each tunnel on every CPU, order restored by QMan; 0 on one CPU per tunnel");

/* The restoration window, as QMan encodes it (0: 32 frames, doubling, 7: 4096):
 * how far ahead of the oldest frame still owed a frame may be sent on before
 * QMan moves on without it -- which it then takes late, out of order (OA and
 * OLWS, vwd_wg_rxq_create()), rather than rejecting either. */
#define VWD_WG_ORP_WINDOW	5

/* The parser's checksum verdict, as _dpa_process_parse_results() reads it. */
#define VWD_WG_CSUM_VALID	0xFFFF

/* A packet the open path decrypted but cannot send out of a port itself,
 * handed to the WireGuard device as an skb over the same buffer, as its own
 * receive path hands one on (wg_packet_consume_data_done()). Built from the
 * frame as received, then cut to the plaintext. */
static void vwd_wg_rx_open_stack(struct vwd_wg_rxq *q, struct net_device *wg,
				 const struct qm_fd *fd, u8 *data, u8 *inner,
				 unsigned int ilen)
{
	struct dpa_priv_s *priv = netdev_priv(q->port);
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	int *count_ptr = raw_cpu_ptr(priv->percpu_count);
	bool use_gro = false;
	struct sk_buff *skb;

	if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
					    CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD))) {
		dpa_fd_release(q->port, fd);
		vwd_wg_count(q, dropped);
		return;
	}
	dma_unmap_single(dpa_bp->dev, qm_fd_addr(fd), dpa_bp->size,
			 DMA_BIDIRECTIONAL);
	skb = contig_fd_to_skb(priv, fd, &use_gro, false);
	(*count_ptr)--;
	__skb_pull(skb, inner - data);
	__skb_trim(skb, ilen);
	skb->dev = wg;
	skb->protocol = (inner[0] >> 4) == 4 ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->pkt_type = PACKET_HOST;
	/* Authenticated by its tag, so every checksum inside is as received. */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = ~0;
	netif_receive_skb(skb);
	vwd_wg_count(q, opened);
}

/* A steered frame opened where it lies (wg_fastpath_open()) and, when the
 * flowtable already holds its flow -- one the forward chain admitted -- sent
 * out of a DPAA port from the same buffer: the buffer keeps its pool, so the
 * port returns it on transmission and the pool's count is left alone, as for
 * a frame the classifier forwards. Returns false, with the frame untouched,
 * for the skb path; true once the frame is forwarded, delivered or dropped.
 * An ordered queue's frame is sent on in order under `s`, or gives its place
 * up before the slow path. */
static bool vwd_wg_rx_raw(struct vwd_wg_rxq *q, const struct qm_fd *fd,
			  struct vwd_wg_seq *s)
{
	struct net_device *port = q->port, *wg;
	struct dpa_priv_s *priv = netdev_priv(port);
	struct dpa_percpu_priv_s *percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	unsigned int len, tot, ulen, ilen;
	struct nf_flow_raw_xmit x;
	struct eth_iface_info *eth;
	struct nf_flowtable *ft;
	u8 *vaddr, *data, *inner;
	struct udphdr *uh;
	struct iphdr *iph;
	struct qm_fd tfd;
	int i, err;

	/* An ordered queue is opened on every CPU already, so auto is on. */
	if (fd->format != qm_fd_contig || !READ_ONCE(wg_rx_raw) ||
	    (READ_ONCE(wg_rx_raw) == 2 && !READ_ONCE(vwd_wg_raw_auto) && !q->ordered))
		return false;
	wg = vwd_wg_rxq_dev(q);
	if (!wg)
		return false;
	vaddr = phys_to_virt(qm_fd_addr(fd));
	data = vaddr + dpa_fd_offset(fd);
	len = dpa_fd_length(fd);
	if (len < ETH_HLEN + sizeof(*iph) + sizeof(*uh) ||
	    ((struct ethhdr *)data)->h_proto != htons(ETH_P_IP))
		return false;
	iph = (struct iphdr *)(data + ETH_HLEN);
	if (iph->version != 4 || iph->ihl != 5 || ip_fast_csum((u8 *)iph, 5) ||
	    ip_is_fragment(iph) || iph->protocol != IPPROTO_UDP)
		return false;
	tot = ntohs(iph->tot_len);
	if (tot < sizeof(*iph) + sizeof(*uh) || tot > len - ETH_HLEN)
		return false;
	uh = (struct udphdr *)(iph + 1);
	ulen = ntohs(uh->len);
	if (ulen < sizeof(*uh) || ulen > tot - sizeof(*iph))
		return false;
	/* The parser's verdict when the port asked for it, else checked here;
	 * a bad one is the skb path's to drop and count. */
	if (uh->check) {
		const fm_prs_result_t *pr =
			(const fm_prs_result_t *)(vaddr + DPA_RX_PRIV_DATA_SIZE);

		if (!((READ_ONCE(port->features) & NETIF_F_RXCSUM) &&
		      (fd->status & FM_FD_STAT_L4CV) && pr->cksum == VWD_WG_CSUM_VALID) &&
		    csum_tcpudp_magic(iph->saddr, iph->daddr, ulen, IPPROTO_UDP,
				      csum_partial(uh, ulen, 0)))
			return false;
	}

	switch (wg_fastpath_open(wg, iph, uh, port->ifindex, (u8 *)(uh + 1),
				 ulen - sizeof(*uh), &inner, &ilen)) {
	case WG_FP_PASS:
		return false;
	case WG_FP_CONSUMED:
		percpu_priv->stats.rx_packets++;
		percpu_priv->stats.rx_bytes += len;
		dpa_fd_release(port, fd);
		vwd_wg_count(q, dropped);
		return true;
	}
	percpu_priv->stats.rx_packets++;
	percpu_priv->stats.rx_bytes += len;
	vwd_wg_count(q, delivered);

	if ((inner[0] >> 4) != 4 || !(ft = nf_flow_table_ingress(wg)) ||
	    nf_flow_offload_ip_raw(ft, wg, (struct iphdr *)inner, ilen,
				   vwd_wg_can_tx, &x)) {
		vwd_wg_skip(q, s);
		vwd_wg_rx_open_stack(q, wg, fd, data, inner, ilen);
		return true;
	}
	/* vwd_wg_can_tx() passed it, so the port is in the table. */
	eth = vwd_wg_port(x.dev);
	data = inner - ETH_HLEN;
	ether_addr_copy(data, x.h_dest);
	ether_addr_copy(data + ETH_ALEN, x.h_source);
	((struct ethhdr *)data)->h_proto = htons(ETH_P_IP);
	tfd = *fd;
	tfd.offset = data - vaddr;
	tfd.length20 = ilen + ETH_HLEN;
	tfd.cmd = 0;
	err = -EBUSY;
	if (s->owed) {
		err = vwd_wg_orp_enqueue(q, &eth->fwd_tx_fqinfo[q->txq], &tfd, 0, s->seq);
		/* Still owed on failure: the caller gives the place up. */
		s->owed = !!err;
	} else {
		/* One CPU's queue: the frames are in order already. */
		for (i = 0; i < 1000 && err == -EBUSY; i++)
			err = qman_enqueue(&eth->fwd_tx_fqinfo[smp_processor_id() &
							       (DPAA_FWD_TX_QUEUES - 1)],
					   &tfd, 0);
	}
	if (unlikely(err)) {
		dpa_fd_release(port, &tfd);
		vwd_wg_count(q, dropped);
	} else {
		vwd_wg_count(q, forwarded);
	}
	return true;
}

/* One steered frame, under rcu_read_lock(). It was received by `port` and
 * enqueued as it arrived, so it is taken exactly as the port's own receive
 * would take it (priv_rx_default_dqrr(), _dpa_rx()): the port's pool refilled
 * against the port's per-CPU count, the skb built zero-copy over the buffer
 * (scatter/gather too, a jumbo frame's), the parse results read for the L4
 * checksum, and the port's receive counters advanced. */
static void vwd_wg_rxq_rx(struct vwd_wg_rxq *q, const struct qm_fd *fd,
			  struct vwd_wg_seq *s)
{
	struct net_device *port = q->port, *wg;
	struct dpa_priv_s *priv = netdev_priv(port);
	struct dpa_percpu_priv_s *percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	bool use_gro = false, l4c;
	struct sk_buff *skb;
	int *count_ptr;

	if (unlikely(fd->status & FM_FD_STAT_RX_ERRORS)) {
		percpu_priv->stats.rx_errors++;
		goto release;
	}
	/* Only the port's own pool: anything else -- SEC's output pool or the
	 * fragment pool, which the VAP queues copy out of -- was not received
	 * by the port, and no steer enqueues it. */
	if (unlikely(dpa_bpid2pool(fd->bpid) != dpa_bp ||
		     (fd->format != qm_fd_contig && fd->format != qm_fd_sg)))
		goto release;
	if (vwd_wg_rx_raw(q, fd, s))
		return;
	vwd_wg_skip(q, s);
	count_ptr = raw_cpu_ptr(priv->percpu_count);
	if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
					    CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD)))
		goto release;
	dma_unmap_single(dpa_bp->dev, qm_fd_addr(fd), dpa_bp->size,
			 DMA_BIDIRECTIONAL);
	l4c = !!(READ_ONCE(port->features) & NETIF_F_RXCSUM);
	if (likely(fd->format == qm_fd_contig)) {
		skb = contig_fd_to_skb(priv, fd, &use_gro, l4c);
	} else {
		skb = sg_fd_to_skb(priv, fd, &use_gro, count_ptr, l4c);
		percpu_priv->rx_sg++;
	}
	/* The contig buffer or the table, as _dpa_rx() accounts it. */
	(*count_ptr)--;
	if (unlikely(skb->len < ETH_HLEN)) {
		dev_core_stats_rx_dropped_inc(port);
		kfree_skb(skb);
		vwd_wg_count(q, dropped);
		return;
	}
	skb->protocol = eth_type_trans(skb, port);
	percpu_priv->stats.rx_packets++;
	percpu_priv->stats.rx_bytes += skb->len;
	skb_record_rx_queue(skb, raw_smp_processor_id());
	skb_reset_network_header(skb);
	skb->skb_iif = port->ifindex;

	switch (vwd_wg_rx_check(skb)) {
	case VWD_WG_RX_DROP:
		dev_core_stats_rx_dropped_inc(port);
		kfree_skb(skb);
		vwd_wg_count(q, dropped);
		return;
	case VWD_WG_RX_DELIVER:
		wg = vwd_wg_rxq_dev(q);
		if (likely(wg)) {
			wg_fastpath_receive(wg, skb);
			vwd_wg_count(q, delivered);
			return;
		}
		fallthrough;
	default:
		/* A well-formed frame with its network header set: the stack
		 * receives it as the port would have. */
		netif_receive_skb(skb);
		vwd_wg_count(q, to_stack);
		return;
	}

release:
	/* Every buffer of the frame, a scatter/gather frame's too. */
	dpa_fd_release(port, fd);
	vwd_wg_count(q, dropped);
}

static enum qman_cb_dqrr_result vwd_wg_rxq_dqrr(struct qman_portal *portal,
						struct qman_fq *fq,
						const struct qm_dqrr_entry *dq)
{
	struct vwd_wg_rxq *q = container_of(fq, struct vwd_wg_rxq, fq);
	struct vwd_wg_seq s;

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	if (unlikely(vwd_napi_schedule(portal)))
		return qman_cb_dqrr_stop;
	s.seq = dq->seqnum & QM_EQCR_SEQNUM_SEQMASK;
	s.owed = q->ordered;
	rcu_read_lock();
	vwd_wg_rxq_rx(q, &dq->fd, &s);
	/* Whatever path the frame took, its place is settled. */
	vwd_wg_skip(q, &s);
	rcu_read_unlock();
	return qman_cb_dqrr_consume;
}

/* Only a hole is enqueued under the steer queue's own object (the classifier
 * enqueues the frames, and takes its own rejections back), with an empty
 * descriptor: nothing to free, and the place it gave up is QMan's to skip on
 * its own (VWD_WG_ORP_WINDOW). */
static void vwd_wg_hole_ern(struct qman_portal *portal, struct qman_fq *fq,
			    const struct qm_mr_entry *msg)
{
	struct vwd_wg_rxq *q = container_of(fq, struct vwd_wg_rxq, fq);

	pr_warn_ratelimited("cdx: WireGuard rx order: hole %u of fqid 0x%x rejected (rc 0x%02x)\n",
			    msg->ern.seqnum, q->fq.fqid, msg->ern.rc);
	vwd_wg_count(q, skip_fail);
}

/* A steer's queue, set up as a VAP's forwarding queues are
 * (create_vap_fwd_from_fman_fqs()): VWD's work queue and stashing, VWD's
 * forwarding congestion group and VWD's NAPI. On `cpu`'s portal channel, or
 * `ordered` (struct vwd_wg_rxq): on the port's pool channel with an order
 * restoration point that, past its window, moves on without a frame still
 * owed (OA) and takes that frame late rather than rejecting it (OLWS 3), so a
 * CPU held up costs order, never a frame. Control mutex held. */
static struct vwd_wg_rxq *vwd_wg_rxq_create(struct net_device *port,
					    struct net_device *wg,
					    struct vap_desc_s *vap, u32 gen,
					    unsigned int cpu, bool ordered)
{
	struct qm_mcc_initfq opts;
	struct vwd_wg_rxq *q;

	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return ERR_PTR(-ENOMEM);
	q->pc = alloc_percpu(struct vwd_wg_rxq_pc);
	if (!q->pc) {
		kfree(q);
		return ERR_PTR(-ENOMEM);
	}
	q->port = port;
	q->wg = wg;
	q->vap = vap;
	q->gen = gen;
	q->cpu = cpu;
	q->ordered = ordered;
	q->txq = cpu & (DPAA_FWD_TX_QUEUES - 1);
	q->fq.cb.dqrr = vwd_wg_rxq_dqrr;
	q->fq.cb.ern = vwd_wg_hole_ern;
	if (qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, &q->fq)) {
		free_percpu(q->pc);
		kfree(q);
		return ERR_PTR(-ENOMEM);
	}
	memset(&opts, 0, sizeof(opts));
	opts.fqid = q->fq.fqid;
	opts.count = 1;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA |
		       QM_INITFQ_WE_CGID;
	opts.fqd.dest.channel = qman_affine_channel(cpu);
	opts.fqd.dest.wq = DEFA_VWD_WQ_ID;
	opts.fqd.fq_ctrl = QM_FQCTRL_CGE;
	opts.fqd.cgid = (u8)vwd.fwd_cgr.cgrid;
	opts.fqd.context_a.stashing.exclusive =
		QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION;
	opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
	opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
	if (ordered) {
		opts.fqd.dest.channel = ((struct dpa_priv_s *)netdev_priv(port))->channel;
		/* Default scheduling keeps an active queue on the one portal it
		 * was given, waiting on that portal's ring while the others idle;
		 * avoid-blocking hands each frame to any portal with room. */
		opts.fqd.fq_ctrl |= QM_FQCTRL_ORP | QM_FQCTRL_AVOIDBLOCK;
		opts.we_mask |= QM_INITFQ_WE_ORPC;
		opts.fqd.orprws = VWD_WG_ORP_WINDOW;
		opts.fqd.oa = 1;
		opts.fqd.olws = 3;
	}
	if (qman_init_fq(&q->fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
		/* Never initialised, so out of service already. */
		qman_destroy_fq(&q->fq, 0);
		free_percpu(q->pc);
		kfree(q);
		return ERR_PTR(-EIO);
	}
	return q;
}

/* Control mutex held, and nothing left to enqueue to the queue: its entry was
 * never linked, or is out of the table. Frames still queued go to the stack
 * (`wg` cleared first); cdx_destroy_fq() retires the queue, waits out its
 * asynchronous retirement, drains it through the callback and takes it out of
 * service, as release_vap_fqs() does a VAP's, then runs synchronize_net()
 * before destroying it -- after which no callback and no statistics reader
 * still holds `q` (the slot's pointer was cleared before this). */
static void vwd_wg_rxq_destroy(struct vwd_wg_rxq *q)
{
	WRITE_ONCE(q->wg, NULL);
	cdx_destroy_fq(&q->fq);
	free_percpu(q->pc);
	kfree(q);
}

/* The entry may still be linked (cdx_ehash_steer_del() could not prove the
 * unlink), so frames may still arrive: a queue destroyed under them would
 * raise enqueue errors, and once its FQID went back to the allocator they
 * would land in whatever queue took it next. So the queue is left in service,
 * delivering to the stack from now on, and deliberately leaked -- one per
 * failed delete, which has latched the datapath restart that settles the key.
 * The module is pinned with it: the callback must not be unloaded from under a
 * queue still in service. */
static void vwd_wg_rxq_abandon(struct vwd_wg_rxq *q)
{
	WRITE_ONCE(q->wg, NULL);
	__module_get(THIS_MODULE);
	pr_warn("cdx: WireGuard rx steer queue 0x%x left in service: its entry may still be linked\n",
		q->fq.fqid);
}

/* Control mutex held, and the slot not CLAIMING. */
static void vwd_wg_steer_clear(struct vwd_wg_steer *s)
{
	struct vwd_wg_rxq *q = s->rxq;
	int rc;

	if (READ_ONCE(s->state) == VWD_WG_STEER_INSTALLED) {
		/* The entry first, as it is what enqueues to the queue. Owns
		 * the entry from here on, whichever way it goes. */
		rc = cdx_ehash_steer_del(s->ct);
		WRITE_ONCE(s->rxq, NULL);
		/* Unsynced is out of every chain, parked until the next sync
		 * proves the microcode has left it; it needs no queue, as the
		 * IPsec SA release frees the FQIDs such an entry named
		 * (cdx_ipsec_delete_fp_entry()). */
		if (!rc || rc == EN_EHASH_DELETE_UNSYNCED)
			vwd_wg_rxq_destroy(q);
		else
			vwd_wg_rxq_abandon(q);
	}
	s->ct = NULL;
	WRITE_ONCE(s->wg, NULL);
	WRITE_ONCE(s->port, NULL);
	smp_store_release(&s->state, VWD_WG_STEER_EMPTY);
}

/* Control mutex held. The queue first, then the entry that feeds it; on
 * success the slot's queue is published for statistics before the caller
 * publishes INSTALLED. */
static int vwd_wg_steer_install(struct vwd_wg_steer *s, struct vap_desc_s *vap,
				u32 gen)
{
	const struct cpumask *cpus = qman_affine_cpus();
	bool ordered = READ_ONCE(wg_rx_spread);
	struct vwd_wg_rxq *q;
	unsigned int cpu, n;
	int rc;

	/* An unproven delete is latched and not yet settled: the key may be
	 * one still linked. */
	if (cdx_ft_failed())
		return -EIO;
	n = cpumask_weight(cpus);
	if (!n)
		return -ENODEV;
	/* An ordered queue's turn only picks its egress queue. */
	cpu = !ordered && vap->wg_rx_cpu >= 0 ? vap->wg_rx_cpu :
	      cpumask_nth(vwd_wg_steer_cpu++ % n, cpus);
	q = vwd_wg_rxq_create(s->port, s->wg, vap, gen, cpu, ordered);
	if (IS_ERR(q))
		return PTR_ERR(q);
	rc = cdx_ehash_steer4_add(s->port, s->saddr, s->daddr, s->sport,
				  s->dport, q->fq.fqid, &s->ct);
	if (rc) {
		/* Nothing was linked (cdx_ehash_steer4_add()), so nothing ever
		 * enqueued to the queue. */
		vwd_wg_rxq_destroy(q);
		return rc;
	}
	WRITE_ONCE(s->rxq, q);
	pr_info("cdx: WireGuard rx steer %pI4:%u -> %pI4:%u on %s to fqid 0x%x (%s %u)\n",
		&s->saddr, ntohs(s->sport), &s->daddr, ntohs(s->dport),
		netdev_name(s->port), q->fq.fqid,
		ordered ? "every cpu, ordered, txq" : "cpu", ordered ? q->txq : cpu);
	return 0;
}

/* Once every CPU is receiving a steered tunnel of its own, WireGuard decrypts
 * where packets arrive instead of handing them to a worker on another, equally
 * busy CPU (wg_fastpath_rx_inline()). Only a tunnel that delivered since the
 * last tick counts, so an idle one leaves its CPU to the workers. Runs every
 * second while a steer is installed; reads the queues under RCU, as the
 * statistics do. ponytail: one-second hysteresis, no traffic weighting. */
static void vwd_wg_inline_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(vwd_wg_inline_work, vwd_wg_inline_fn);

static void vwd_wg_inline_fn(struct work_struct *work)
{
	struct cpumask cpus;
	unsigned int i, installed = 0;

	cpumask_clear(&cpus);
	rcu_read_lock();
	for (i = 0; i < VWD_WG_STEERS; i++) {
		struct vwd_wg_steer *s = &vwd_wg_steers[i];
		struct vwd_wg_rxq *q;
		unsigned long d;

		if (smp_load_acquire(&s->state) != VWD_WG_STEER_INSTALLED)
			continue;
		installed++;
		q = READ_ONCE(s->rxq);
		if (!q)
			continue;
		d = vwd_wg_total(q, delivered);
		if (d != q->seen) {
			if (q->ordered)
				cpumask_or(&cpus, &cpus, qman_affine_cpus());
			else
				cpumask_set_cpu(q->cpu, &cpus);
		}
		q->seen = d;
	}
	rcu_read_unlock();
	wg_fastpath_rx_inline(cpumask_weight(&cpus) >= num_online_cpus());
	WRITE_ONCE(vwd_wg_raw_auto, cpumask_weight(&cpus) >= 2);
	if (installed && !READ_ONCE(vwd_stopping))
		schedule_delayed_work(&vwd_wg_inline_work, HZ);
}

static void vwd_wg_steer_work_fn(struct work_struct *work)
{
	unsigned int i, j;

	cdx_ft_begin();
	for (i = 0; i < VWD_WG_STEERS; i++) {
		struct vwd_wg_steer *s = &vwd_wg_steers[i];
		struct dpa_iface_info *iface;
		struct vap_desc_s *vap;
		u32 gen;
		int rc;

		if (smp_load_acquire(&s->state) != VWD_WG_STEER_PENDING)
			continue;
		/* Noted by a frame in flight as the VAP went: nothing to do. */
		iface = dpa_get_ifinfo_by_netdev(s->wg);
		vap = vwd_wg_open_vap(s->wg, &gen);
		if (READ_ONCE(vwd_stopping) || !iface ||
		    !(iface->if_flags & IF_TYPE_WLAN) || !vap) {
			vwd_wg_steer_clear(s);
			continue;
		}
		/* Two CPUs noted the same tuple at once. */
		for (j = 0; j < VWD_WG_STEERS; j++) {
			unsigned int st = smp_load_acquire(&vwd_wg_steers[j].state);

			if (j != i && st >= VWD_WG_STEER_PENDING &&
			    vwd_wg_steer_same(s, &vwd_wg_steers[j]))
				break;
		}
		if (j < VWD_WG_STEERS) {
			vwd_wg_steer_clear(s);
			continue;
		}
		rc = vwd_wg_steer_install(s, vap, gen);
		if (rc) {
			pr_warn_ratelimited("cdx: WireGuard rx steer %pI4:%u -> %pI4:%u not installed (%d)\n",
					    &s->saddr, ntohs(s->sport), &s->daddr,
					    ntohs(s->dport), rc);
			smp_store_release(&s->state, VWD_WG_STEER_FAILED);
			continue;
		}
		smp_store_release(&s->state, VWD_WG_STEER_INSTALLED);
	}
	if (!READ_ONCE(vwd_stopping))
		schedule_delayed_work(&vwd_wg_inline_work, HZ);
	cdx_ft_end();
}

/* Delete the steers of WireGuard device `wg`, or every one when NULL. Control
 * mutex held: so the worker, which takes it, is not waited for here -- a slot
 * it has yet to look at is either dropped here or dropped by it, since it
 * installs only for a device that is still a VAP. A slot still CLAIMING
 * becomes PENDING and goes the same way. */
void vwd_wg_steers_drop(const struct net_device *wg)
{
	unsigned int i;

	cdx_ft_assert_held();
	for (i = 0; i < VWD_WG_STEERS; i++) {
		struct vwd_wg_steer *s = &vwd_wg_steers[i];
		unsigned int st = smp_load_acquire(&s->state);

		if (st == VWD_WG_STEER_EMPTY || st == VWD_WG_STEER_CLAIMING)
			continue;
		if (wg && s->wg != wg)
			continue;
		vwd_wg_steer_clear(s);
	}
}

/* Module exit: no frame notes a tuple once vwd_stopping is seen (every note is
 * made inside the dequeue path's RCU read section), and then no work is left
 * to run, so every slot is either EMPTY or the control mutex's. */
static void vwd_wg_steers_exit(void)
{
	synchronize_net();
	cancel_work_sync(&vwd_wg_steer_work);
	/* After the steer worker, which arms it; it re-arms only while not
	 * stopping. */
	cancel_delayed_work_sync(&vwd_wg_inline_work);
	wg_fastpath_rx_inline(false);
	cdx_ft_begin();
	vwd_wg_steers_drop(NULL);
	cdx_ft_end();
}

/* Racy reads for statistics. A slot's queue is freed only after its pointer is
 * cleared and a grace period has passed (vwd_wg_rxq_destroy()), so the RCU
 * read section keeps every queue it finds. */
static void vwd_wg_steers_stats(const struct net_device *wg,
				struct vwd_wg_rx_stats *st)
{
	unsigned int i;

	memset(st, 0, sizeof(*st));
	if (!wg)
		return;
	rcu_read_lock();
	for (i = 0; i < VWD_WG_STEERS; i++) {
		struct vwd_wg_steer *s = &vwd_wg_steers[i];
		const struct vwd_wg_rxq *q;

		if (smp_load_acquire(&s->state) != VWD_WG_STEER_INSTALLED ||
		    READ_ONCE(s->wg) != wg)
			continue;
		st->steers++;
		q = READ_ONCE(s->rxq);
		if (!q)
			continue;
		st->delivered += vwd_wg_total(q, delivered);
		st->to_stack += vwd_wg_total(q, to_stack);
		st->dropped += vwd_wg_total(q, dropped);
		st->forwarded += vwd_wg_total(q, forwarded);
		st->opened += vwd_wg_total(q, opened);
		st->skipped += vwd_wg_total(q, skipped);
		st->skip_fail += vwd_wg_total(q, skip_fail);
	}
	rcu_read_unlock();
}

/* A WireGuard VAP's frame sealed where it lies and sent from the same buffer.
 * The FD keeps its pool, so the egress port returns the buffer to it after
 * transmission, as it does for a frame the classifier forwards; the pool's
 * per-CPU count is therefore left alone. Returns false, with the frame
 * untouched, for anything the seal declines. */
/* wgdbg: where the WireGuard fast path's work lands, per CPU, dumped every
 * 2 s. Diagnostic only; remove once the PoC's scaling is understood. */
struct wgdbg_pc {
	unsigned long in, sealed, bounce, decl;
	int last_err;
};
static DEFINE_PER_CPU(struct wgdbg_pc, wgdbg_pc);
static unsigned long wgdbg_next;

static void wgdbg_dump(void)
{
	int c;

	if (!time_after(jiffies, READ_ONCE(wgdbg_next)))
		return;
	WRITE_ONCE(wgdbg_next, jiffies + 2 * HZ);
	for_each_online_cpu(c) {
		const struct wgdbg_pc *p = per_cpu_ptr(&wgdbg_pc, c);

		pr_info("wgdbg cpu%d in %lu sealed %lu bounce %lu decl %lu err %d\n",
			c, p->in, p->sealed, p->bounce, p->decl, p->last_err);
	}
}

static bool vwd_wg_fast(struct net_device *net_dev, struct vap_desc_s *vap,
			struct dpa_bp *dpa_bp, const struct qm_fd *in)
{
	struct eth_iface_info *eth;
	struct wg_fastpath_tx tx;
	struct qman_fq *fq;
	struct qm_fd fd = *in;
	int i, err = -EBUSY;

	this_cpu_inc(wgdbg_pc.in);
	wgdbg_dump();
	err = wg_fastpath_seal(net_dev, vwd_wg_can_tx, phys_to_virt(qm_fd_addr(in)),
			       dpa_fd_offset(in), dpa_fd_length(in), dpa_bp->size, &tx);
	if (err == -EXDEV)
		this_cpu_inc(wgdbg_pc.bounce);
	else if (err) {
		this_cpu_inc(wgdbg_pc.decl);
		this_cpu_write(wgdbg_pc.last_err, err);
	} else {
		this_cpu_inc(wgdbg_pc.sealed);
	}
	if (err == -EXDEV) {
		/* This CPU receives the tunnel: hand the frame, untouched, to
		 * the VAP's queue on the next CPU (queue i is on the i-th
		 * affine CPU's portal). A flow's frames all take the same
		 * turn, so they stay in order. */
		struct dpa_fq *next = vap->wlan_fq_from_fman[(smp_processor_id() + 1) %
							     num_online_cpus()];

		for (i = 0; i < 1000 && (err = qman_enqueue(&next->fq_base, &fd, 0)) == -EBUSY; i++)
			;
		if (unlikely(err)) {
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_wg_tx_fail);
			dpa_fd_release(NULL, &fd);
		}
		return true;
	}
	if (err)
		return false;
	vwd_wg_steer_note(net_dev, &tx);
	err = -EBUSY;
	fd.offset = tx.off;
	fd.length20 = tx.len;
	fd.cmd = 0;
	eth = vwd_wg_port(tx.dev);
	if (unlikely(!eth)) {
		/* Sealed for a port that left the table since: none do. */
		err = -ENODEV;
		goto out;
	}
	/* One flow's frames arrive on one VAP queue, so on one CPU: a queue
	 * per CPU keeps them in order. */
	fq = &eth->fwd_tx_fqinfo[smp_processor_id() & (DPAA_FWD_TX_QUEUES - 1)];
	for (i = 0; i < 1000 && err == -EBUSY; i++)
		err = qman_enqueue(fq, &fd, 0);
out:
	if (unlikely(err)) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_wg_tx_fail);
		dpa_fd_release(NULL, &fd);
	} else {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_wg_sealed);
	}
	return true;
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
	if (net_dev->type != ARPHRD_ETHER &&
	    vwd_wg_fast(net_dev, vap, dpa_bp, &dq->fd)) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_fast_forwarded);
		goto done;
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
/* ponytail: raised for the WireGuard fast path experiment, whose frames are
 * Ethernet-pool frames; a WireGuard VAP needs its own group before this ships. */
#define VWD_FWD_FRAMES	2048

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
		/* Software enqueues here too (vwd_wg_fast()); a rejected one
		 * goes back to its pool. */
		fq->cb.ern = vap_fwd_ern;
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
	/* A WireGuard VAP's queue is where its frames are sealed, a CPU's worth
	 * of work per flow; queue i is on the i-th CPU's portal. Flows are dealt
	 * in turn over every CPU but the one receiving their tunnel, which
	 * carries all its ACKs (and would bounce them, vwd_wg_fast()). */
	if (vwd.vaps[vap_id].wifi_dev && vwd.vaps[vap_id].wifi_dev->type != ARPHRD_ETHER) {
		static atomic_t wg_turn;
		unsigned int n = num_online_cpus();
		int rx = READ_ONCE(vwd.vaps[vap_id].wg_rx_cpu);

		do
			hash = (unsigned int)atomic_inc_return(&wg_turn) % n;
		while (n > 1 && (int)hash == rx);
	}
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
				/* A WireGuard tunnel's receive CPU, dealt in turn
				 * when it opens, so its steer and its flows' seal
				 * queues agree before the first entry exists. None
				 * when its steer is ordered: every CPU receives it. */
				static unsigned int wg_rx_turn;
				const struct cpumask *cpus = qman_affine_cpus();

				vap->wg_rx_cpu = -1;
				if (vap->wifi_dev && vap->wifi_dev->type != ARPHRD_ETHER &&
				    !READ_ONCE(wg_rx_spread) && cpumask_weight(cpus))
					vap->wg_rx_cpu = cpumask_nth(wg_rx_turn++ %
								     cpumask_weight(cpus), cpus);
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
	vwd_wg_steers_exit();
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

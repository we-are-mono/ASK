/* Copyright 2008-2013 Freescale Semiconductor Inc.
 * Copyright 2019 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define pr_fmt(fmt) \
	KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <linux/io.h>
#include <linux/if_arp.h>	/* arp_hdr_len() */
#include <linux/if_vlan.h>	/* VLAN_HLEN */
#include <linux/icmp.h>		/* struct icmphdr */
#include <linux/ip.h>		/* struct iphdr */
#include <linux/ipv6.h>		/* struct ipv6hdr */
#include <linux/udp.h>		/* struct udphdr */
#include <linux/tcp.h>		/* struct tcphdr */
#include <linux/net.h>		/* net_ratelimit() */
#include <linux/if_ether.h>	/* ETH_P_IP and ETH_P_IPV6 */
#include <linux/highmem.h>
#include <linux/percpu.h>
#include <linux/srcu.h>
#include <linux/dma-mapping.h>
#include <linux/fsl_bman.h>
#ifdef CONFIG_SOC_BUS
#include <linux/sys_soc.h>      /* soc_device_match */
#endif

#include "fsl_fman.h"
#include "fm_ext.h"
#include "fm_port_ext.h"

#include "mac.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"

/* CREATE_TRACE_POINTS only needs to be defined once. Other dpa files
 * using trace events only need to #include <trace/events/sched.h>
 */
#define CREATE_TRACE_POINTS
#include "dpaa_eth_trace.h"

#define DPA_NAPI_WEIGHT		64

/* Valid checksum indication */
#define DPA_CSUM_VALID		0xFFFF

#define DPA_DESCRIPTION "FSL DPAA Ethernet driver"

MODULE_LICENSE("Dual BSD/GPL");

MODULE_AUTHOR("Andy Fleming <afleming@freescale.com>");

MODULE_DESCRIPTION(DPA_DESCRIPTION);

static uint8_t debug = -1;
module_param(debug, byte, S_IRUGO);
MODULE_PARM_DESC(debug, "Module/Driver verbosity level");

/* How many quarters of what a port seeds the pool with its queues to the CPU
 * may hold (dpaa_eth_priv_ingress_cgr_init()): half by default. */
static uint ingress_quarters = 2;
module_param(ingress_quarters, uint, 0444);
MODULE_PARM_DESC(ingress_quarters,
		 "Quarters of a port's pool seed its queues to the CPU may hold (1-4)");

/* This has to work in tandem with the DPA_CS_THRESHOLD_xxx values. */
static uint16_t tx_timeout = 1000;
module_param(tx_timeout, ushort, S_IRUGO);
MODULE_PARM_DESC(tx_timeout, "The Tx timeout in ms");

/* BM */

#define DPAA_ETH_MAX_PAD (L1_CACHE_BYTES * 8)

static uint8_t dpa_priv_common_bpid;
/* The per-CPU fill of that common pool, counted once for every private port
 * (dpaa_eth_priv_probe()). Allocated with the first port and kept: private
 * ports are not removed. */
static int __percpu *dpa_priv_common_count;



#ifdef CONFIG_PM

static int dpaa_suspend(struct device *dev)
{
	struct net_device	*net_dev;
	struct dpa_priv_s	*priv;
	struct mac_device	*mac_dev;
	int			err = 0;

	net_dev = dev_get_drvdata(dev);

	if (net_dev->flags & IFF_UP) {
		priv = netdev_priv(net_dev);
		mac_dev = priv->mac_dev;

		if (priv->wol & DPAA_WOL_MAGIC) {
			err = priv->mac_dev->set_wol(mac_dev->port_dev[RX],
				priv->mac_dev->get_mac_handle(mac_dev), true);
			if (err) {
				netdev_err(net_dev, "set_wol() = %d\n", err);
				goto set_wol_failed;
			}
		}

		err = fm_port_suspend(mac_dev->port_dev[RX]);
		if (err) {
			netdev_err(net_dev, "fm_port_suspend(RX) = %d\n", err);
			goto rx_port_suspend_failed;
		}

		err = fm_port_suspend(mac_dev->port_dev[TX]);
		if (err) {
			netdev_err(net_dev, "fm_port_suspend(TX) = %d\n", err);
			goto tx_port_suspend_failed;
		}
	}

	return 0;

tx_port_suspend_failed:
	fm_port_resume(mac_dev->port_dev[RX]);
rx_port_suspend_failed:
	if (priv->wol & DPAA_WOL_MAGIC) {
		priv->mac_dev->set_wol(mac_dev->port_dev[RX],
			priv->mac_dev->get_mac_handle(mac_dev), false);
	}
set_wol_failed:
	return err;
}

static int dpaa_resume(struct device *dev)
{
	struct net_device	*net_dev;
	struct dpa_priv_s	*priv;
	struct mac_device	*mac_dev;
	int			err = 0;

	net_dev = dev_get_drvdata(dev);

	if (net_dev->flags & IFF_UP) {
		priv = netdev_priv(net_dev);
		mac_dev = priv->mac_dev;

		err = fm_mac_resume(mac_dev->get_mac_handle(mac_dev));
		if (err) {
			netdev_err(net_dev, "fm_mac_resume = %d\n", err);
			goto resume_failed;
		}

		err = fm_port_resume(mac_dev->port_dev[TX]);
		if (err) {
			netdev_err(net_dev, "fm_port_resume(TX) = %d\n", err);
			goto resume_failed;
		}

		err = fm_port_resume(mac_dev->port_dev[RX]);
		if (err) {
			netdev_err(net_dev, "fm_port_resume(RX) = %d\n", err);
			goto resume_failed;
		}

		if (priv->wol & DPAA_WOL_MAGIC) {
			err = priv->mac_dev->set_wol(mac_dev->port_dev[RX],
				priv->mac_dev->get_mac_handle(mac_dev), false);
			if (err) {
				netdev_err(net_dev, "set_wol() = %d\n", err);
				goto resume_failed;
			}
		}
	}

	return 0;

resume_failed:
	return err;
}

static const struct dev_pm_ops dpaa_pm_ops = {
	.suspend = dpaa_suspend,
	.resume = dpaa_resume,
};

#define DPAA_PM_OPS (&dpaa_pm_ops)

#else /* CONFIG_PM */

#define DPAA_PM_OPS NULL

#endif /* CONFIG_PM */

/* Checks whether the checksum field in Parse Results array is valid
 * (equals 0xFFFF) and increments the .cse counter otherwise
 */
static inline void
dpa_csum_validation(const struct dpa_priv_s	*priv,
		struct dpa_percpu_priv_s *percpu_priv,
		const struct qm_fd *fd)
{
	dma_addr_t addr = qm_fd_addr(fd);
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	void *frm = phys_to_virt(addr);
	fm_prs_result_t *parse_result;

	if (unlikely(!frm))
		return;

	dma_sync_single_for_cpu(dpa_bp->dev, addr, DPA_RX_PRIV_DATA_SIZE +
				DPA_PARSE_RESULTS_SIZE, DMA_BIDIRECTIONAL);

	parse_result = (fm_prs_result_t *)(frm + DPA_RX_PRIV_DATA_SIZE);

	if (parse_result->cksum != DPA_CSUM_VALID)
		percpu_priv->rx_errors.cse++;
}

static void _dpa_rx_error(struct net_device *net_dev,
		const struct dpa_priv_s	*priv,
		struct dpa_percpu_priv_s *percpu_priv,
		const struct qm_fd *fd,
		u32 fqid)
{
	/* limit common, possibly innocuous Rx FIFO Overflow errors'
	 * interference with zero-loss convergence benchmark results.
	 */
	if (likely(fd->status & FM_FD_STAT_ERR_PHYSICAL))
		pr_warn_once("fsl-dpa: non-zero error counters in fman statistics (sysfs)\n");
	else
		if (netif_msg_hw(priv) && net_ratelimit())
			netdev_dbg(net_dev, "Err FD status = 0x%08x\n",
					fd->status & FM_FD_STAT_RX_ERRORS);
	percpu_priv->stats.rx_errors++;

	if (fd->status & FM_PORT_FRM_ERR_DMA)
		percpu_priv->rx_errors.dme++;
	if (fd->status & FM_PORT_FRM_ERR_PHYSICAL)
		percpu_priv->rx_errors.fpe++;
	if (fd->status & FM_PORT_FRM_ERR_SIZE)
		percpu_priv->rx_errors.fse++;
	if (fd->status & FM_PORT_FRM_ERR_PRS_HDR_ERR)
		percpu_priv->rx_errors.phe++;
	if (fd->status & FM_FD_STAT_L4CV)
		dpa_csum_validation(priv, percpu_priv, fd);

	dpa_fd_release(net_dev, fd);
}

static void _dpa_tx_error(struct net_device		*net_dev,
			  const struct dpa_priv_s	*priv,
			  struct dpa_percpu_priv_s	*percpu_priv,
			  const struct qm_fd		*fd,
			  u32				 fqid)
{
	struct sk_buff *skb;

	if (netif_msg_hw(priv) && net_ratelimit())
		netdev_warn(net_dev, "  _dpa_tx_error :FD status = 0x%08x\n",
				fd->status & FM_FD_STAT_TX_ERRORS);
	percpu_priv->stats.tx_errors++;

	/* If we intended the buffers from this frame to go into the bpools
	 * when the FMan transmit was done, we need to put it in manually.
	 */
	if (fd->bpid != 0xff) {
		dpa_fd_release(net_dev, fd);
		return;
	}

	skb = _dpa_cleanup_tx_fd(priv, fd);
	dev_kfree_skb(skb);
}

/**
 * _dpa_process_parse_results() - Process parse result for RX FD
 *
 * @parse_results: Pointer to structure holding the parse results of the frame
 * @fd: Pointer to QMan frame descriptor structure
 * @skb: Pointer to socket buffer which will have its ip_summed field
 *	overwritten
 * @use_gro: will only be written with 0, if the frame is definitely not
 *	GRO-able; otherwise, it will be left unchanged
 * @dcl4c_valid: if set, we assume no parser errors, since any error frame is
 *	dropped before this function is called. When FMBM_RFNE[FDCS] is set, RX
 *	checksum validation does not run and needs to be re-done in software,
 *	which means we may get invalid frames.
 *
 * Helper function to factor out frame validation logic on all Rx paths. Its
 * purpose is to extract from the Parse Results structure information about
 * the integrity of the frame, its checksum, the length of the parsed headers
 * and whether the frame is suitable for GRO.
 */
void __hot _dpa_process_parse_results(const fm_prs_result_t *parse_results,
				      const struct qm_fd *fd,
				      struct sk_buff *skb, bool *use_gro,
				      bool dcl4c_valid)
{
	if (dcl4c_valid && fd->status & FM_FD_STAT_L4CV) {
		/* FM_FD_STAT_L4CV only indicates validation was ATTEMPTED.
		 * We must also verify parse_results->cksum == 0xFFFF to
		 * confirm the checksum actually PASSED.
		 */
		if (parse_results->cksum != DPA_CSUM_VALID) {
			/* Checksum validation failed - use software checksum */
			skb->ip_summed = CHECKSUM_NONE;
			*use_gro = false;
			return;
		}
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		/* Don't go through GRO for certain types of traffic that
		 * we know are not GRO-able, such as dgram-based protocols.
		 * In the worst-case scenarios, such as small-pkt terminating
		 * UDP, the extra GRO processing would be overkill.
		 *
		 * The only protocol the Parser supports that is also GRO-able
		 * is currently TCP.
		 */
		if (!fm_l4_frame_is_tcp(parse_results))
			*use_gro = false;

		return;
	}

	/* We're here because either the parser didn't run or the L4 checksum
	 * was not verified. This may include the case of a UDP frame with
	 * checksum zero or an L4 proto other than TCP/UDP
	 */
	skb->ip_summed = CHECKSUM_NONE;

	/* Bypass GRO for unknown traffic or if no PCDs are applied */
	*use_gro = false;
}

int dpaa_eth_poll(struct napi_struct *napi, int budget)
{
	struct dpa_napi_portal *np =
			container_of(napi, struct dpa_napi_portal, napi);

	int cleaned = qman_p_poll_dqrr(np->p, budget, napi);

	if (cleaned < budget && napi_complete_done(napi, cleaned)) {
		int tmp;

		tmp = qman_p_irqsource_add(np->p, QM_PIRQ_DQRI);
		DPA_BUG_ON(tmp);
	}

	return cleaned;
}
EXPORT_SYMBOL(dpaa_eth_poll);

static void __hot _dpa_tx_conf(struct net_device	*net_dev,
			  const struct dpa_priv_s	*priv,
			  struct dpa_percpu_priv_s	*percpu_priv,
			  const struct qm_fd		*fd,
			  u32				 fqid)
{
	struct sk_buff	*skb;

	/* do we need the timestamp for the error frames? */

	if (unlikely(fd->status & FM_FD_STAT_TX_ERRORS) != 0) {
		if (netif_msg_hw(priv) && net_ratelimit())
			netdev_warn(net_dev, "FD status = 0x%08x\n",
					fd->status & FM_FD_STAT_TX_ERRORS);

		percpu_priv->stats.tx_errors++;
	}

	/* hopefully we need not get the timestamp before the hook */
	/* This might not perfectly reflect the reality, if the core dequeuing
	 * the Tx confirmation is different from the one that did the enqueue,
	 * but at least it'll show up in the total count.
	 */
	percpu_priv->tx_confirm++;

	skb = _dpa_cleanup_tx_fd(priv, fd);

	dev_kfree_skb(skb);
}

static enum qman_cb_dqrr_result priv_rx_error_dqrr(struct qman_portal *portal,
						   struct qman_fq *fq,
						   const struct qm_dqrr_entry *dq,
						   bool sched_napi,
						   struct qman_poll_ctx *ctx)
{
	struct net_device		*net_dev;
	struct dpa_priv_s		*priv;
	struct dpa_percpu_priv_s	*percpu_priv;
	int				*count_ptr;

	net_dev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(net_dev);

	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	count_ptr = raw_cpu_ptr(priv->percpu_count);
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (dpaa_eth_napi_schedule(percpu_priv, portal, sched_napi))
		return qman_cb_dqrr_stop;
#endif

	if (unlikely(dpaa_eth_refill_bpools(priv->dpa_bp, count_ptr,
			CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD)))
		/* Unable to refill the buffer pool due to insufficient
		 * system memory. Just release the frame back into the pool,
		 * otherwise we'll soon end up with an empty buffer pool.
		 */
		dpa_fd_release(net_dev, &dq->fd);
	else
		_dpa_rx_error(net_dev, priv, percpu_priv, &dq->fd, fq->fqid);

	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result __hot
priv_rx_default_dqrr(struct qman_portal *portal, struct qman_fq *fq,
		     const struct qm_dqrr_entry *dq, bool sched_napi,
		     struct qman_poll_ctx *ctx)
{
	struct net_device		*net_dev;
	struct dpa_priv_s		*priv;
	struct dpa_percpu_priv_s	*percpu_priv;
	int                             *count_ptr;
	struct dpa_bp			*dpa_bp;

	net_dev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(net_dev);
	dpa_bp = priv->dpa_bp;

	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	count_ptr = raw_cpu_ptr(priv->percpu_count);
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal, sched_napi)))
		return qman_cb_dqrr_stop;
#endif

	/* Trace the Rx fd */
	trace_dpa_rx_fd(net_dev, fq, &dq->fd);

	/* Vale of plenty: make sure we didn't run out of buffers */

	if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
			CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD)))
		/* Unable to refill the buffer pool due to insufficient
		 * system memory. Just release the frame back into the pool,
		 * otherwise we'll soon end up with an empty buffer pool.
		 */
		dpa_fd_release(net_dev, &dq->fd);
	else
		_dpa_rx(net_dev, portal, priv, percpu_priv, &dq->fd, fq->fqid,
			count_ptr, ctx);

	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
priv_tx_conf_error_dqrr(struct qman_portal *portal, struct qman_fq *fq,
		        const struct qm_dqrr_entry *dq, bool sched_napi,
		        struct qman_poll_ctx *ctx)
{
	struct net_device		*net_dev;
	struct dpa_priv_s		*priv;
	struct dpa_percpu_priv_s	*percpu_priv;

	net_dev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(net_dev);

	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (dpaa_eth_napi_schedule(percpu_priv, portal, sched_napi))
		return qman_cb_dqrr_stop;
#endif

	_dpa_tx_error(net_dev, priv, percpu_priv, &dq->fd, fq->fqid);

	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result __hot
priv_tx_conf_default_dqrr(struct qman_portal *portal, struct qman_fq *fq,
			  const struct qm_dqrr_entry *dq, bool sched_napi,
			  struct qman_poll_ctx *ctx)
{
	struct net_device		*net_dev;
	struct dpa_priv_s		*priv;
	struct dpa_percpu_priv_s	*percpu_priv;

	net_dev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(net_dev);

	/* Non-migratable context, safe to use raw_cpu_ptr */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (dpaa_eth_napi_schedule(percpu_priv, portal, sched_napi))
		return qman_cb_dqrr_stop;
#endif

	/* Trace the fd */
	trace_dpa_tx_conf_fd(net_dev, fq, &dq->fd);

	_dpa_tx_conf(net_dev, priv, percpu_priv, &dq->fd, fq->fqid);

	return qman_cb_dqrr_consume;
}

static void priv_ern(struct qman_portal *portal, struct qman_fq *fq,
		     const struct qm_mr_entry *msg)
{
	struct net_device	*net_dev;
	const struct dpa_priv_s	*priv;
	struct sk_buff *skb;
	struct dpa_percpu_priv_s	*percpu_priv;
	struct qm_fd fd = msg->ern.fd;

	net_dev = ((struct dpa_fq *)fq)->net_dev;
	priv = netdev_priv(net_dev);
	/* Non-migratable context, safe to use raw_cpu_ptr */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);

	percpu_priv->stats.tx_dropped++;
	percpu_priv->stats.tx_fifo_errors++;
	count_ern(percpu_priv, msg);

	/* If we intended this buffer to go into the pool
	 * when the FM was done, we need to put it in
	 * manually.
	 */
	if (msg->ern.fd.bpid != 0xff) {
		dpa_fd_release(net_dev, &fd);
		return;
	}

	skb = _dpa_cleanup_tx_fd(priv, &fd);
	dev_kfree_skb_any(skb);
}

const struct dpa_fq_cbs_t private_fq_cbs = {
	.rx_defq = { .cb = { .dqrr = priv_rx_default_dqrr } },
	.tx_defq = { .cb = { .dqrr = priv_tx_conf_default_dqrr } },
	.rx_errq = { .cb = { .dqrr = priv_rx_error_dqrr } },
	.tx_errq = { .cb = { .dqrr = priv_tx_conf_error_dqrr } },
	.egress_ern = { .cb = { .ern = priv_ern } }
};
EXPORT_SYMBOL(private_fq_cbs);

static void dpaa_eth_napi_enable(struct dpa_priv_s *priv)
{
	struct dpa_percpu_priv_s *percpu_priv;
	int i;

	for_each_possible_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);

		napi_enable(&percpu_priv->np.napi);
	}
}

static void dpaa_eth_napi_disable(struct dpa_priv_s *priv)
{
	struct dpa_percpu_priv_s *percpu_priv;
	int i;

	for_each_possible_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);

		napi_disable(&percpu_priv->np.napi);
	}
}

static int __cold dpa_eth_priv_start(struct net_device *net_dev)
{
	int err;
	struct dpa_priv_s *priv;

	priv = netdev_priv(net_dev);

	dpaa_eth_napi_enable(priv);

	err = dpa_start(net_dev);
	if (err < 0)
		dpaa_eth_napi_disable(priv);

	return err;
}



static int __cold dpa_eth_priv_stop(struct net_device *net_dev)
{
	int _errno;
	struct dpa_priv_s *priv;

	_errno = dpa_stop(net_dev);
	/* Allow NAPI to consume any frame still in the Rx/TxConfirm
	 * ingress queues. This is to avoid a race between the current
	 * context and ksoftirqd which could leave NAPI disabled while
	 * in fact there's still Rx traffic to be processed.
	 */
	usleep_range(5000, 10000);

	priv = netdev_priv(net_dev);
	dpaa_eth_napi_disable(priv);

	return _errno;
}

/* The tags a full-size frame on the port may carry: none while nothing is
 * stacked on it, one once anything is -- a VLAN, a bridge forwarding tagged
 * frames through, a bond, a macvlan -- and two once a VLAN on the port is an
 * 802.1ad service VLAN or carries a VLAN of its own: a VLAN device above it,
 * or a bridge it is a port of, which tags the frames it forwards there or
 * carries tagged ones through.
 */
static int dpa_upper_tags(struct net_device *net_dev)
{
	struct net_device *upper, *inner;
	struct list_head *iter, *inner_iter;
	int tags = 0;

	rcu_read_lock();
	netdev_for_each_upper_dev_rcu(net_dev, upper, iter) {
		tags = max(tags, 1);
		if (!is_vlan_dev(upper))
			continue;
		if (vlan_dev_vlan_proto(upper) == htons(ETH_P_8021AD))
			tags = 2;
		netdev_for_each_upper_dev_rcu(upper, inner, inner_iter)
			if (is_vlan_dev(inner) || netif_is_bridge_master(inner))
				tags = 2;
	}
	rcu_read_unlock();
	return tags;
}

/* The mEMAC holds every received frame, FCS included, to its max frame length
 * and makes no allowance of its own for a VLAN tag. Size the limit to what the
 * port may carry at @mtu, with the tags dpa_upper_tags() allows for. Never
 * below a standard frame, never above the FMan-wide maximum the ports are
 * sized for.
 *
 * RTNL serializes every caller, so the limit follows the latest MTU and upper
 * set.
 */
static int dpa_set_mac_max_frame(struct net_device *net_dev, int mtu)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	struct mac_device *mac_dev = priv->mac_dev;
	int len;

	ASSERT_RTNL();

	if (!mac_dev->set_max_frame)
		return 0;

	len = max(mtu, ETH_DATA_LEN) + ETH_HLEN + ETH_FCS_LEN +
	      dpa_upper_tags(net_dev) * VLAN_HLEN;
	len = min(len, dpa_get_max_frm());

	return mac_dev->set_max_frame(mac_dev->get_mac_handle(mac_dev), len);
}

static int dpa_change_mtu(struct net_device *net_dev, int new_mtu)
{
	int err;

	err = dpa_set_mac_max_frame(net_dev, new_mtu);
	if (err)
		return err;

	WRITE_ONCE(net_dev->mtu, new_mtu);
	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void dpaa_eth_poll_controller(struct net_device *net_dev)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	struct dpa_percpu_priv_s *percpu_priv =
		raw_cpu_ptr(priv->percpu_priv);
	struct dpa_napi_portal *np;
	struct napi_struct *napi;

	np = &percpu_priv->np;
	napi = &np->napi;

	qman_p_irqsource_remove(np->p, QM_PIRQ_DQRI);
	qman_p_poll_dqrr(np->p, napi->weight, napi);
	qman_p_irqsource_add(np->p, QM_PIRQ_DQRI);
}
#endif

#ifdef CONFIG_CPE_FAST_PATH
/* Set by the offload module; a built-in driver cannot link against one. The
 * handler sleeps, so its calls are counted by an SRCU domain rather than by
 * RCU: the unregister waits for the ones already inside it. */
static dpa_setup_tc_handler dpa_setup_tc_func;
DEFINE_STATIC_SRCU(dpa_setup_tc_srcu);

int dpa_register_setup_tc(dpa_setup_tc_handler handler)
{
	if (!handler)
		return -EINVAL;
	if (cmpxchg(&dpa_setup_tc_func, NULL, handler))
		return -EBUSY;
	return 0;
}
EXPORT_SYMBOL(dpa_register_setup_tc);

/* Returns once no call is inside the handler, so the module's text -- and
 * the state the handler reaches, its own SRCU domains among it -- may be freed
 * after. Must not be called from inside the handler, nor with anything held
 * that a handler call waits for. */
void dpa_unregister_setup_tc(void)
{
	WRITE_ONCE(dpa_setup_tc_func, NULL);
	synchronize_srcu(&dpa_setup_tc_srcu);
}
EXPORT_SYMBOL(dpa_unregister_setup_tc);

/* Read the handler once, inside the read-side section the unregister waits
 * for: an unregister can NULL it concurrently, and a call that began before
 * it must finish before the module's text goes.
 *
 * Refusing when nothing is registered is deliberate rather than convenient.
 * Netfilter has already chosen this route over the module's indirect
 * registration by the time it gets here, so answering anything but an error
 * would claim a binding no one is going to service.
 */
static int dpa_setup_tc(struct net_device *dev, enum tc_setup_type type,
			void *type_data)
{
	dpa_setup_tc_handler handler;
	int idx, rc;

	idx = srcu_read_lock(&dpa_setup_tc_srcu);
	handler = READ_ONCE(dpa_setup_tc_func);
	rc = handler ? handler(dev, type, type_data) : -EOPNOTSUPP;
	srcu_read_unlock(&dpa_setup_tc_srcu, idx);
	return rc;
}

/* The data-path half, published and retired as one pointer so a frame never
 * sees one callback without the other. */
static const struct dpa_qdisc_ops *dpa_qdisc;

int dpa_register_qdisc_ops(const struct dpa_qdisc_ops *ops)
{
	if (!ops || !ops->select_queue || !ops->txq_fq || !ops->class_stats)
		return -EINVAL;
	/* release-publish so a frame cannot see the pointer before the queue
	 * map it walks is initialized */
	if (cmpxchg_release(&dpa_qdisc, NULL, ops))
		return -EBUSY;
	return 0;
}
EXPORT_SYMBOL(dpa_register_qdisc_ops);

/* Waits for a grace period before returning, so the callbacks' module text
 * may be freed once it does. Every caller below takes its own rcu_read_lock()
 * around the pointer and the call, so that holds whatever context it was
 * entered from. */
void dpa_unregister_qdisc_ops(void)
{
	WRITE_ONCE(dpa_qdisc, NULL);
	synchronize_net();
}
EXPORT_SYMBOL(dpa_unregister_qdisc_ops);

/* The frame queue answered is used for the enqueue after this returns, which
 * cpe_fp_tx() keeps inside its own read-side section. */
struct qman_fq *dpa_qdisc_txq_fq(void *qm_ctx, u16 txq, struct sk_buff *skb)
{
	const struct dpa_qdisc_ops *ops;
	struct qman_fq *fq = NULL;

	rcu_read_lock();
	ops = READ_ONCE(dpa_qdisc);
	if (ops)
		fq = ops->txq_fq(qm_ctx, txq, skb);
	rcu_read_unlock();
	return fq;
}

/* Always answers, so the count of statistics this driver reports is a
 * compile-time constant rather than something that changes when a module
 * loads. Unclaimed leaf slots, and every value when nothing is registered,
 * read zero. */
void dpa_qdisc_class_stats(void *qm_ctx, u64 *data)
{
	const struct dpa_qdisc_ops *ops;

	memset(data, 0, (DPAA_ETH_CEETM_LEAF_QUEUES + DPA_CEETM_IMPLICIT_QUEUES) *
			DPA_CEETM_CLASS_STATS * sizeof(*data));
	rcu_read_lock();
	ops = READ_ONCE(dpa_qdisc);
	if (ops && qm_ctx)
		ops->class_stats(qm_ctx, data);
	rcu_read_unlock();
}

/* Not always entered with a read-side section held: AF_PACKET's qdisc bypass
 * calls ndo_select_queue from plain process context, which under PREEMPT_RCU
 * is no reader at all. So the section is taken here. */
static u16 dpa_qdisc_select_queue(struct net_device *dev, struct sk_buff *skb,
				  struct net_device *sb_dev)
{
	const struct dpa_qdisc_ops *ops;
	u16 queue = DPA_SELECT_QUEUE_NONE;

	rcu_read_lock();
	ops = READ_ONCE(dpa_qdisc);
	if (ops)
		queue = ops->select_queue(dev, skb);
	rcu_read_unlock();
	if (queue != DPA_SELECT_QUEUE_NONE)
		return queue;
	/* Traffic that named no class keeps the stack's own choice -- socket
	 * affinity and XPS included -- folded back into the queues that carry
	 * it. The fold is what keeps it off the leaf classes above them, which
	 * real_num_tx_queues now covers and which are reached only by naming
	 * one; DPAA_ETH_TX_QUEUES is a power of two for exactly this kind of
	 * masking. */
	return netdev_pick_tx(dev, skb, sb_dev) & (DPAA_ETH_TX_QUEUES - 1);
}
#endif

static const struct net_device_ops dpa_private_ops = {
	.ndo_open = dpa_eth_priv_start,
	.ndo_start_xmit = dpa_tx,
	.ndo_stop = dpa_eth_priv_stop,
	.ndo_tx_timeout = dpa_timeout,
	.ndo_get_stats64 = dpa_get_stats64,
	.ndo_set_mac_address = dpa_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
#ifdef CONFIG_CPE_FAST_PATH
	/* Load-bearing beyond the qdisc: the leaf-class queues live above
	 * real_num_tx_queues' probe-time value, and once one is in service the
	 * stack's own hash would otherwise spread ordinary traffic across it. */
	.ndo_select_queue = dpa_qdisc_select_queue,
#endif
	.ndo_set_rx_mode = dpa_set_rx_mode,
	.ndo_init = dpa_ndo_init,
	.ndo_eth_ioctl = dpa_ioctl,
	.ndo_change_mtu = dpa_change_mtu,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = dpaa_eth_poll_controller,
#endif
	.ndo_set_features = dpa_set_features,
	.ndo_fix_features = dpa_fix_features,
#ifdef CONFIG_CPE_FAST_PATH
	.ndo_setup_tc = dpa_setup_tc,
#endif
};

static int dpa_private_napi_add(struct net_device *net_dev)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	struct dpa_percpu_priv_s *percpu_priv;
	int cpu;

	for_each_possible_cpu(cpu) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, cpu);

		/* It drains this CPU's portal, which only this CPU's poll may
		 * do, with DQRI masked: never from a busy-polling socket's task.
		 * Out of the NAPI hash, as netif_napi_add_tx() keeps a NAPI, so
		 * GRO has no id of its to stamp either. */
		set_bit(NAPI_STATE_NO_BUSY_POLL, &percpu_priv->np.napi.state);
		netif_napi_add(net_dev, &percpu_priv->np.napi, dpaa_eth_poll);
	}

	return 0;
}

void dpa_private_napi_del(struct net_device *net_dev)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	struct dpa_percpu_priv_s *percpu_priv;
	int cpu;

	for_each_possible_cpu(cpu) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, cpu);

		netif_napi_del(&percpu_priv->np.napi);
	}
}
EXPORT_SYMBOL(dpa_private_napi_del);

/* Without the jumbo buffer layout an Rx buffer is sized for one standard
 * frame, yet fsl_fm_max_frm may raise the FMan-wide maximum far past it. Cap
 * the MTU at what one buffer holds behind its headroom, a VLAN tag and the
 * forwarded FCS included, so a frame the MAC accepts lands in one piece. The
 * standard MTU stays available whatever the layout.
 */
static int dpa_priv_max_mtu(const struct dpa_priv_s *priv)
{
	int max_mtu = dpa_get_max_mtu();
#ifndef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
	int buf_mtu = (int)priv->dpa_bp->size - priv->rx_headroom -
		      (VLAN_ETH_HLEN + ETH_FCS_LEN);

	max_mtu = min(max_mtu, max(buf_mtu, ETH_DATA_LEN));
#endif

	return max_mtu;
}

static int dpa_private_netdev_init(struct net_device *net_dev)
{
	int i;
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	struct dpa_percpu_priv_s *percpu_priv;
	const uint8_t *mac_addr;

	/* Although we access another CPU's private data here
	 * we do it at initialization so it is safe
	 */
	for_each_possible_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);
		percpu_priv->net_dev = net_dev;
	}

	net_dev->netdev_ops = &dpa_private_ops;
	mac_addr = priv->mac_dev->addr;

	net_dev->mem_start = priv->mac_dev->res->start;
	net_dev->mem_end = priv->mac_dev->res->end;

	/* Configure the maximum MTU according to the FMan's MAXFRM */
	net_dev->min_mtu = ETH_MIN_MTU;
	net_dev->max_mtu = dpa_priv_max_mtu(priv);

	net_dev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
				NETIF_F_RXCSUM;
	net_dev->lltx               = true;

#ifdef CONFIG_CPE_FAST_PATH
	/* tc_can_offload() gates every hardware qdisc on this bit, and it has
	 * to be in features rather than only in hw_features to be on by
	 * default. Offered alongside ndo_setup_tc, since neither is any use
	 * without the other. */
	net_dev->hw_features |= NETIF_F_HW_TC;
	net_dev->features |= NETIF_F_HW_TC;
#endif

	/* Advertise S/G and HIGHDMA support for private interfaces */
	net_dev->hw_features |= NETIF_F_SG | NETIF_F_HIGHDMA;
	/* Recent kernels enable GSO automatically, if
	 * we declare NETIF_F_SG. For conformity, we'll
	 * still declare GSO explicitly.
	 */
	net_dev->features |= NETIF_F_GSO;

	/* Advertise GRO support */
	net_dev->features |= NETIF_F_GRO;

	return dpa_netdev_init(net_dev, mac_addr, tx_timeout);
}

static struct dpa_bp * __cold
dpa_priv_bp_probe(struct device *dev)
{
	struct dpa_bp *dpa_bp;

	dpa_bp = devm_kzalloc(dev, sizeof(*dpa_bp), GFP_KERNEL);
	if (unlikely(dpa_bp == NULL)) {
		dev_err(dev, "devm_kzalloc() failed\n");
		return ERR_PTR(-ENOMEM);
	}

	dpa_bp->target_count = CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;

	dpa_bp->free_buf_cb = _dpa_bp_free_pf;

	return dpa_bp;
}

static int dpaa_eth_priv_ingress_cgr_init(struct qman_cgr *cgr, u64 cs_th)
{
	struct qm_mcc_initcgr initcgr;
	int err;

	err = qman_alloc_cgrid(&cgr->cgrid);
	if (err < 0) {
		pr_err("Error %d allocating CGR ID\n", err);
		return err;
	}

	memset(&initcgr, 0, sizeof(initcgr));
	initcgr.we_mask = QM_CGR_WE_MODE | QM_CGR_WE_CS_THRES | QM_CGR_WE_CSCN_EN;
	initcgr.cgr.mode = QMAN_CGR_MODE_FRAME;
	initcgr.cgr.cscn_en = 0;
	qm_cgr_cs_thres_set64(&initcgr.cgr.cs_thres, cs_th, 1);

	initcgr.we_mask |= QM_CGR_WE_CSTD_EN;
	initcgr.cgr.cstd_en = QM_CGR_EN;

	/* This is actually a hack, because this CGR will be associated with
	 * our affine SWP. However, we'll place our ingress FQs in it.
	 */
	err = qman_create_cgr(cgr, QMAN_CGR_FLAG_USE_INIT, &initcgr);
	if (err < 0) {
		pr_err("Error %d creating ingress CGR with ID %d\n", err,
			cgr->cgrid);
		qman_release_cgrid(cgr->cgrid);
		return err;
	}

	return 0;
}

/* Place all ingress FQs (Rx Default, Rx Error, PCD FQs) in a dedicated CGR,
 * and the high priority PCD FQs in one of their own, each of which refuses
 * FMan's enqueue past its threshold, so FMan drops the frame.
 *
 * A frame waiting on these queues for the CPU holds a buffer of the pool
 * every port receives into, and only the CPU taking it puts one back
 * (dpaa_eth_refill_bpools()). The group counted bytes, up to 256 MB, so a
 * flood the CPU could not keep up with -- traffic for the gateway itself, or
 * for a flow not yet in hardware -- held the whole pool, and every port missed
 * whatever it received, forwarding in hardware included. So it counts frames,
 * at half of what this port seeds the pool with (ingress_quarters): a port's
 * queues to the CPU then never hold more than half its own share, and a flood
 * of one port leaves the others theirs. A quarter was measured too tight for
 * the CPU's own forwarding -- some one frame in a hundred refused while 16,384
 * connections were admitted at a measured pace, where half refused none -- and
 * a whole share lost no less of a mass re-admission in hardware while leaving
 * the pool less to receive into. The high priority group gets the same bound,
 * so its traffic is never refused for the other's backlog. Nothing consumes
 * congestion state changes, so none are raised.
 */
static int dpaa_eth_priv_ingress_cgrs_init(struct dpa_priv_s *priv)
{
	/* What this port seeds the pool with, not the pool's running total
	 * (config_count), which every port probed after the first raises by
	 * its own seed: bounded by that, the bound grew with probe order. */
	u64 cs_th = max_t(u64, (u64)CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT *
			       num_possible_cpus() *
			       clamp_t(uint, ingress_quarters, 1, 4) / 4, 1);
	int ret;

	ret = dpaa_eth_priv_ingress_cgr_init(&priv->ingress_cgr, cs_th);
	if (ret)
		return ret;

	ret = dpaa_eth_priv_ingress_cgr_init(&priv->ingress_cgr_hi_prio, cs_th);
	if (ret) {
		dpa_destroy_cgr(&priv->ingress_cgr);
		return ret;
	}

	pr_debug("Created ingress CGR %d and hi prio CGR %d for netdev with hwaddr %pM\n",
		 priv->ingress_cgr.cgrid, priv->ingress_cgr_hi_prio.cgrid,
		 priv->mac_dev->addr);

	/* struct qman_cgr allows special cgrid values (i.e. outside the 0..255
	 * range), but we have no common initialization path between the
	 * different variants of the DPAA Eth driver, so we do it here rather
	 * than modifying every other variant than "private Eth".
	 */
	priv->use_ingress_cgr = true;

	return 0;
}

static int dpa_priv_bp_create(struct net_device *net_dev, struct dpa_bp *dpa_bp,
		size_t count)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	int i;

	if (netif_msg_probe(priv))
		dev_dbg(net_dev->dev.parent,
			"Using private BM buffer pools\n");

	priv->bp_count = count;

	for (i = 0; i < count; i++) {
		int err;
		err = dpa_bp_alloc(&dpa_bp[i], net_dev->dev.parent);
		if (err < 0) {
			dpa_bp_free(priv);
			priv->dpa_bp = NULL;
			return err;
		}

		priv->dpa_bp = &dpa_bp[i];
	}

	dpa_priv_common_bpid = priv->dpa_bp->bpid;
	return 0;
}

static void dpa_priv_bp_seed(struct net_device *net_dev)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	int i;

	/* Give each CPU an allotment of buffers */
	for_each_possible_cpu(i) {
		/* Although we access another CPU's counters here
		 * we do it at boot time so it is safe
		 */
		int *count_ptr = per_cpu_ptr(priv->percpu_count, i);

		dpaa_eth_refill_bpools(dpa_bp, count_ptr,
			CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD);
	}
}

static const struct of_device_id dpa_match[];


static int
dpaa_eth_priv_probe(struct platform_device *_of_dev)
{
	int err = 0, i, channel;
	struct device *dev;
	struct device_node *dpa_node;
	struct dpa_bp *dpa_bp;
	size_t count = 1;
	struct net_device *net_dev = NULL;
	struct dpa_priv_s *priv = NULL;
	struct dpa_percpu_priv_s *percpu_priv;
	struct fm_port_fqs port_fqs;
	struct dpa_buffer_layout_s *buf_layout = NULL;
	struct mac_device *mac_dev;

	dev = &_of_dev->dev;

	dpa_node = dev->of_node;

	if (!of_device_is_available(dpa_node))
		return -ENODEV;

	/* Get the buffer pools assigned to this interface;
	 * run only once the default pool probing code
	 *
	 * The pool's record is the first port's device memory, which every
	 * later port borrows: unbinding that port by hand would leave the
	 * others' record, and the pool watch's, dangling. Private ports are
	 * never removed.
	 */
	dpa_bp = (dpa_bpid2pool(dpa_priv_common_bpid)) ? :
			dpa_priv_bp_probe(dev);
	if (IS_ERR(dpa_bp))
		return PTR_ERR(dpa_bp);

	/* Allocate this early, so we can store relevant information in
	 * the private area (needed by 1588 code in dpa_mac_probe)
	 */
	/* Allocate the leaf-class headroom up front, the way every other
	 * hardware-qdisc driver does: sch_htb turns the qid a driver hands back
	 * straight into netdev_get_tx_queue() with no bounds check, so those
	 * slots have to exist before a class can name one. Only the direct
	 * queues are live until then; see the real_num_tx_queues call below. */
	net_dev = alloc_etherdev_mq(sizeof(*priv), DPAA_ETH_TX_QUEUES_MAX);
	if (!net_dev) {
		dev_err(dev, "alloc_etherdev_mq() failed\n");
		goto alloc_etherdev_mq_failed;
	}
	/* alloc_etherdev_mq() reports every allocated queue as usable. Narrow
	 * that to the queues that actually have an egress FQ behind them, so
	 * ordinary traffic never hashes into the reserved range and a later
	 * qdisc sees an honest count of pre-existing direct queues. */
	err = netif_set_real_num_tx_queues(net_dev, DPAA_ETH_TX_QUEUES);
	if (err) {
		dev_err(dev, "netif_set_real_num_tx_queues() = %d\n", err);
		goto netif_set_real_num_tx_queues_failed;
	}

	/* Do this here, so we can be verbose early */
	SET_NETDEV_DEV(net_dev, dev);
	dev_set_drvdata(dev, net_dev);

	priv = netdev_priv(net_dev);
	priv->net_dev = net_dev;
	strcpy(priv->if_type, "private");

	priv->msg_enable = netif_msg_init(debug, -1);


	mac_dev = dpa_mac_probe(_of_dev);
	if (IS_ERR(mac_dev) || !mac_dev) {
		err = PTR_ERR(mac_dev);
		goto mac_probe_failed;
	}

	/* We have physical ports, so we need to establish
	 * the buffer layout.
	 */
	buf_layout = devm_kzalloc(dev, 2 * sizeof(*buf_layout),
				  GFP_KERNEL);
	if (!buf_layout) {
		dev_err(dev, "devm_kzalloc() failed\n");
		goto alloc_failed;
	}
	dpa_set_buffers_layout(mac_dev, buf_layout);

	/* For private ports, need to compute the size of the default
	 * buffer pool, based on FMan port buffer layout;also update
	 * the maximum buffer size for private ports if necessary
	 */
	dpa_bp->size = dpa_bp_size(&buf_layout[RX]);

#ifdef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
	/* The jumbo buffer layout is only of use when the L2 maximum frame
	 * size admits jumbo frames as well.
	 */
	if (fm_get_max_frm() < 9600)
		dev_warn(dev,
			"Invalid configuration: if jumbo frames support is on, FSL_FM_MAX_FRAME_SIZE should be set to 9600\n");
#endif

	INIT_LIST_HEAD(&priv->dpa_fq_list);

	memset(&port_fqs, 0, sizeof(port_fqs));

	err = dpa_fq_probe_mac(dev, &priv->dpa_fq_list, &port_fqs, true, RX);
	if (!err)
		err = dpa_fq_probe_mac(dev, &priv->dpa_fq_list,
				       &port_fqs, true, TX);

	if (err < 0)
		goto fq_probe_failed;
	/* bp init */
	pr_debug("%s: bpid %d, count %d\n", __func__,
			dpa_bp->bpid, dpa_bp->config_count);
	err = dpa_priv_bp_create(net_dev, dpa_bp, count);

	if (err < 0)
		goto bp_create_failed;

	priv->mac_dev = mac_dev;

	channel = dpa_get_channel();

	if (channel < 0) {
		err = channel;
		goto get_channel_failed;
	}

	priv->channel = (uint16_t)channel;
	dpaa_eth_add_channel(priv->channel);

	dpa_fq_setup(priv, &private_fq_cbs, priv->mac_dev->port_dev[TX]);

	/* Create a congestion group for this netdev, with
	 * dynamically-allocated CGR ID.
	 * Must be executed after probing the MAC, but before
	 * assigning the egress FQs to the CGRs.
	 */
	err = dpaa_eth_cgr_init(priv);
	if (err < 0) {
		dev_err(dev, "Error initializing CGR\n");
		goto tx_cgr_init_failed;
	}
	err = dpaa_eth_priv_ingress_cgrs_init(priv);
	if (err < 0) {
		dev_err(dev, "Error initializing ingress CGR\n");
		goto rx_cgr_init_failed;
	}

	/* Add the FQs to the interface, and make them active */
	err = dpa_fqs_init(dev,  &priv->dpa_fq_list, false);
	if (err < 0)
		goto fq_alloc_failed;

	priv->buf_layout = buf_layout;
	priv->tx_headroom = dpa_get_headroom(&priv->buf_layout[TX]);
	priv->rx_headroom = dpa_get_headroom(&priv->buf_layout[RX]);

	/* All real interfaces need their ports initialized */
	dpaa_eth_init_ports(mac_dev, dpa_bp, count, &port_fqs,
			buf_layout, dev);


	priv->percpu_priv = devm_alloc_percpu(dev, *priv->percpu_priv);

	if (priv->percpu_priv == NULL) {
		dev_err(dev, "devm_alloc_percpu() failed\n");
		err = -ENOMEM;
		goto alloc_percpu_failed;
	}

	for_each_possible_cpu(i) {
		percpu_priv = per_cpu_ptr(priv->percpu_priv, i);
		memset(percpu_priv, 0, sizeof(*percpu_priv));
	}

	/* Every private port receives into the one common pool, so its fill is
	 * counted once. Counted per port, a frame received on one port and
	 * sent out of another found the sender's count already full and was
	 * confirmed and freed, while the receiver refilled with new buffers --
	 * an allocation and a free per forwarded frame. Each port still adds
	 * its own share to what the pool is kept at, so the pool holds what
	 * it did. */
	if (!dpa_priv_common_count) {
		dpa_priv_common_count = alloc_percpu(int);
		if (!dpa_priv_common_count) {
			dev_err(dev, "alloc_percpu() failed\n");
			err = -ENOMEM;
			goto alloc_percpu_failed;
		}
	} else {
		dpa_bp->config_count += CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;
	}
	priv->percpu_count = dpa_priv_common_count;

	/* Initialize NAPI */
	err = dpa_private_napi_add(net_dev);

	if (err < 0)
		goto napi_add_failed;

	err = dpa_private_netdev_init(net_dev);

	dpa_priv_bp_seed(net_dev);

	if (err < 0)
		goto netdev_init_failed;

	dpaa_eth_sysfs_init(&net_dev->dev);

#ifdef CONFIG_PM
	device_set_wakeup_capable(dev, true);
#endif

	priv->ifinfo = NULL;

	/* Watched from here, as it receives into the shared pool. */
	dpa_pool_watch_add(priv);

	pr_info("fsl_dpa: Probed interface %s\n", net_dev->name);

	return 0;

netdev_init_failed:
napi_add_failed:
	dpa_private_napi_del(net_dev);
alloc_percpu_failed:
	dpa_fq_free(dev, &priv->dpa_fq_list);
fq_alloc_failed:
	dpa_destroy_cgr(&priv->ingress_cgr);
	dpa_destroy_cgr(&priv->ingress_cgr_hi_prio);
rx_cgr_init_failed:
	dpa_destroy_cgr(&priv->cgr_data.cgr);
tx_cgr_init_failed:
get_channel_failed:
	dpa_bp_free(priv);
bp_create_failed:
fq_probe_failed:
alloc_failed:
mac_probe_failed:
	dev_set_drvdata(dev, NULL);
	/* Reached before drvdata is set, so it has nothing to undo. */
netif_set_real_num_tx_queues_failed:
	free_netdev(net_dev);
alloc_etherdev_mq_failed:
	if (atomic_read(&dpa_bp->refs) == 0)
		devm_kfree(dev, dpa_bp);

	return err;
}

/* Off the pool's watch first: dpa_remove() takes down the port's congestion
 * groups and its hold on the pool, which the watch reads through it. */
static void __cold dpaa_eth_priv_remove(struct platform_device *of_dev)
{
	struct net_device *net_dev = dev_get_drvdata(&of_dev->dev);

	dpa_pool_watch_del(netdev_priv(net_dev));
	dpa_remove(of_dev);
}

static const struct of_device_id dpa_match[] = {
	{
		.compatible	= "fsl,dpa-ethernet"
	},
	{}
};
MODULE_DEVICE_TABLE(of, dpa_match);

static struct platform_driver dpa_driver = {
	.driver = {
		.name		= KBUILD_MODNAME,
		.of_match_table	= dpa_match,
		.owner		= THIS_MODULE,
		.pm		= DPAA_PM_OPS,
	},
	.probe		= dpaa_eth_priv_probe,
	.remove		= dpaa_eth_priv_remove
};

/* A port's max frame length depends on its uppers as well as its MTU, so
 * follow uppers being linked and unlinked, on the port and on a VLAN over it
 * (a VLAN stacked on that VLAN adds a tag). Registration applies the first
 * per-port limit: the MAC was initialized with the FMan-wide maximum, and a
 * port left there would take frames its MTU says it cannot, so a failure
 * fails the registration.
 */
static int dpa_netdev_event(struct notifier_block *nb, unsigned long event,
			    void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);
	int err;

	if (event == NETDEV_CHANGEUPPER && is_vlan_dev(net_dev))
		net_dev = vlan_dev_real_dev(net_dev);
	if (net_dev->netdev_ops != &dpa_private_ops)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		return notifier_from_errno(dpa_set_mac_max_frame(net_dev,
								 net_dev->mtu));
	case NETDEV_CHANGEUPPER:
		err = dpa_set_mac_max_frame(net_dev, net_dev->mtu);
		if (unlikely(err < 0))
			netdev_err(net_dev, "mac_dev->set_max_frame() = %d\n",
				   err);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block dpa_netdev_nb = {
	.notifier_call = dpa_netdev_event,
};

static int __init __cold dpa_load(void)
{
	int	 _errno;

	pr_info(DPA_DESCRIPTION "\n");

	_errno = register_netdevice_notifier(&dpa_netdev_nb);
	if (unlikely(_errno < 0)) {
		pr_err(KBUILD_MODNAME ": register_netdevice_notifier() = %d\n",
		       _errno);
		return _errno;
	}


	/* initialise dpaa_eth mirror values */
	dpa_rx_extra_headroom = fm_get_rx_extra_headroom();
	dpa_max_frm = fm_get_max_frm();
	dpa_num_cpus = num_possible_cpus();


	_errno = platform_driver_register(&dpa_driver);
	if (unlikely(_errno < 0)) {
		pr_err(KBUILD_MODNAME
			": %s:%hu:%s(): platform_driver_register() = %d\n",
			KBUILD_BASENAME".c", __LINE__, __func__, _errno);
		unregister_netdevice_notifier(&dpa_netdev_nb);
	}

	pr_debug(KBUILD_MODNAME ": %s:%s() ->\n",
		KBUILD_BASENAME".c", __func__);


	return _errno;
}
module_init(dpa_load);

static void __exit __cold dpa_unload(void)
{
	pr_debug(KBUILD_MODNAME ": -> %s:%s()\n",
		KBUILD_BASENAME".c", __func__);


	platform_driver_unregister(&dpa_driver);
	dpa_pool_watch_stop();
	unregister_netdevice_notifier(&dpa_netdev_nb);


	/* Only one channel is used and needs to be relased after all
	 * interfaces are removed
	 */
	dpa_release_channel();

	pr_debug(KBUILD_MODNAME ": %s:%s() ->\n",
		KBUILD_BASENAME".c", __func__);
}
module_exit(dpa_unload);

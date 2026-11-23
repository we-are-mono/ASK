/* Copyright 2012 Freescale Semiconductor Inc.
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
#include <linux/skbuff.h>
#include <linux/highmem.h>
#include <linux/fsl_bman.h>
#include <net/sock.h>

#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#ifdef CONFIG_FSL_DPAA_1588
#include "dpaa_1588.h"
#endif
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ppp_defs.h>
#include <uapi/linux/if_pppox.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/xfrm.h>
#endif

#define DPAA_EXTRA_BUF_SIZE_4_SKB SMP_CACHE_BYTES + DPA_MAX_FD_OFFSET + \
		sizeof(struct skb_shared_info) +  128 

/* registered function to get ceetm Fqs */
#ifdef CONFIG_CPE_FAST_PATH
static cdx_get_ceetm_egressfq ceetm_fqget_func;
static cdx_get_ceetm_dscp_fq ceetm_dscp_fqget_func;
/* This function registers two cdx functions, which are to get the egress fq.
   One is based on channel and classqueue and another one is based on dscp. */
int dpa_register_ceetm_get_egress_fq(cdx_get_ceetm_egressfq egress_fq_func, cdx_get_ceetm_dscp_fq dscp_fq_func)
{
	/* release-publish so readers can't see the hooks before the
	 * ceetm state they walk is initialized */
	smp_store_release(&ceetm_fqget_func, egress_fq_func);
	smp_store_release(&ceetm_dscp_fqget_func, dscp_fq_func);
	return 0;
}
EXPORT_SYMBOL(dpa_register_ceetm_get_egress_fq);

/* Called on cdx deinit. Waits out in-flight datapath readers so the
 * hooks' module text, and the frame queues they hand back, may be freed once
 * this returns: every reader holds its own rcu_read_lock() across the call and
 * the enqueue that uses the answer (cpe_fp_tx()), so this does not depend on
 * which context the frame was transmitted from. */
void dpa_unregister_ceetm_get_egress_fq(void)
{
	WRITE_ONCE(ceetm_fqget_func, NULL);
	WRITE_ONCE(ceetm_dscp_fqget_func, NULL);
	synchronize_rcu();
}
EXPORT_SYMBOL(dpa_unregister_ceetm_get_egress_fq);
#endif

#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
cdx_get_ipsec_fq_hook_t cdx_get_ipsec_fq_hookfn;

int dpa_register_ipsec_fq_handler(cdx_get_ipsec_fq_hook_t hookfn)
{
	if (cdx_get_ipsec_fq_hookfn) {
		pr_err("%s: hook already registered\n", __func__);
		return -1;
	}
	/* release-publish so readers can't see the hook before the SA
	 * state it walks is initialized */
	smp_store_release(&cdx_get_ipsec_fq_hookfn, hookfn);
	return 0;
}
EXPORT_SYMBOL(dpa_register_ipsec_fq_handler);

/* Called on cdx deinit, including the failed-init unwind. Clearing the
 * hook is what lets the next cdx load register again (the register
 * refuses to overwrite); the synchronize_rcu makes sure no reader is still
 * inside the old hook once this returns. Each reader holds its own
 * rcu_read_lock() across the call and the enqueue that uses the answer, so
 * that holds whatever context submitted the frame. */
void dpa_unregister_ipsec_fq_handler(void)
{
	WRITE_ONCE(cdx_get_ipsec_fq_hookfn, NULL);
	synchronize_rcu();
}
EXPORT_SYMBOL(dpa_unregister_ipsec_fq_handler);
#endif

/* DMA map and add a page frag back into the bpool.
 * @vaddr fragment must have been allocated with netdev_alloc_frag(),
 * specifically for fitting into @dpa_bp.
 */
static void dpa_bp_recycle_frag(struct dpa_bp *dpa_bp, unsigned long vaddr,
				int *count_ptr)
{
	struct bm_buffer bmb;
	dma_addr_t addr;

	bmb.opaque = 0;

	addr = dma_map_single(dpa_bp->dev, (void *)vaddr, dpa_bp->size,
			      DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		struct sk_buff *skb, **skbh;

		dev_err(dpa_bp->dev, "DMA mapping failed");
		DPA_READ_SKB_PTR(skb, skbh, (void *)vaddr, -1);
		dev_kfree_skb_any(skb);
		return;
	}

	bm_buffer_set64(&bmb, addr);

	while (bman_release(dpa_bp->pool, &bmb, 1, 0))
		cpu_relax();

	(*count_ptr)++;
}

// adding a new function which allocates memory for buffers and adds bman pool
int dpaa_bp_alloc_n_add_buffs(const struct dpa_bp *dpa_bp, uint32_t nbuffs, bool act_skb)
{
	struct bm_buffer bmb[8];
	char *new_buf, *ptr_buf;
	dma_addr_t addr;
	int ii,entries_in_bmb,buffs2fill;
	int err = -ENOMEM;
	struct device *dev = dpa_bp->dev;
	struct sk_buff *skb = NULL, **skbh;
	uint32_t bufsize;

	if (act_skb)
		bufsize = PAGE_SIZE << get_order(DPAA_EXTRA_BUF_SIZE_4_SKB +
					       dpa_bp->size);
	else
		bufsize =  SMP_CACHE_BYTES + dpa_bp->size + DPA_MAX_FD_OFFSET + 128;

	/* aligning to SMP_CACHE_BYTES */
	bufsize = DPA_SKB_SIZE(bufsize);

	buffs2fill= 0;
	while (buffs2fill < nbuffs)
	{
		memset(bmb, 0, sizeof(struct bm_buffer) * 8);

		if ((nbuffs -   buffs2fill) < 8)
			entries_in_bmb = (nbuffs - buffs2fill);
		else
			entries_in_bmb = 8;
		for (ii= 0; ii<entries_in_bmb; ii++) {
			/* Secondary SG buffers become skb page fragments. Their
			 * storage must remain pinned after the skb shell is freed;
			 * a page reference cannot retain a kmalloc slab object. */
			if (act_skb) {
				struct page *page = alloc_pages(GFP_DMA | GFP_ATOMIC |
							       __GFP_COMP, get_order(bufsize));

				ptr_buf = page ? page_address(page) : NULL;
			} else {
				ptr_buf = kmalloc(bufsize, GFP_DMA | GFP_ATOMIC);
			}

			if (unlikely(!ptr_buf))
			{
				pr_err_ratelimited("%s(%d) ii %d,  buffs2fill %d buffer allocation failed \n",
						__func__,__LINE__,ii, buffs2fill);
				goto handle_fail;
			}

			new_buf = ptr_buf;
			if (act_skb)
			{
				/* We'll prepend the skb back-pointer; can't use the DPA
				 * priv space, because FMan will overwrite it (from offset 0)
				 * if it ends up being the second, third, etc. fragment
				 * in a S/G frame.
				 *
				 * We only need enough space to store a pointer, but allocate
				 * an entire cacheline for performance reasons.
				 */
				skb = build_skb(ptr_buf, bufsize);
				if (unlikely(!skb)) {
					pr_err_ratelimited("%s(%d) ii %d , buffs2fill %d build_skb failed \n",
							__func__,__LINE__, ii, buffs2fill);
					put_page(virt_to_head_page(new_buf));
					goto handle_fail;
				}
				ptr_buf = PTR_ALIGN(ptr_buf, SMP_CACHE_BYTES) + SMP_CACHE_BYTES;
				skb_reserve(skb, (ptr_buf-new_buf));
				DPA_WRITE_SKB_PTR(skb, skbh, ptr_buf, -1);
			}
			else
				ptr_buf = PTR_ALIGN(ptr_buf /*+ SMP_CACHE_BYTES */, SMP_CACHE_BYTES);

			addr = dma_map_single(dev, ptr_buf, dpa_bp->size, DMA_BIDIRECTIONAL);
			if (unlikely(dma_mapping_error(dev, addr)))
			{
				pr_err_ratelimited("%s(%d) ii %d buffs2fill %d dma_mapping_error failed \n",
						__func__,__LINE__,ii,buffs2fill);
				if (act_skb)
					kfree_skb(skb);
				else
					kfree(new_buf);
				err = -EIO;
				goto handle_fail;
			}
			bm_buffer_set64(&bmb[ii], addr);

			bmb[ii].bpid = cpu_to_be16(dpa_bp->bpid & 0xff);
		}
		while (unlikely(bman_release(dpa_bp->pool, bmb, entries_in_bmb, 0)))
			cpu_relax();
		buffs2fill+= entries_in_bmb;
	}
	return 0;

handle_fail:
	if (ii)
	{
		while (unlikely(bman_release(dpa_bp->pool, bmb, ii, 0)))
			cpu_relax();
	}
	/* Zero buffers seeded is still a failure. The caller owns every
	 * buffer already released to BMan and must drain its pool. */
	return err;

}
EXPORT_SYMBOL(dpaa_bp_alloc_n_add_buffs);


#ifdef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
/* A jumbo Rx buffer is larger than a page, and the page fragment cache serves
 * nothing larger than one: it fails such a request outright. The buffers are
 * carved from compound pages here instead, as many to a page as fit, each
 * holding one reference on its page, which the skb built on it drops when it
 * is freed (skb_free_frag()). A page the order cannot be had at is replaced by
 * one a single buffer fits in. One carve serves one _dpa_bp_add_8_bufs() call;
 * the references of buffers it never handed out go with dpa_jumbo_end().
 */
#define DPA_JUMBO_PAGE_ORDER	3

struct dpa_jumbo_carve {
	struct page *page;
	void *next;
	unsigned int left;
};

static void *dpa_jumbo_buf(struct dpa_jumbo_carve *c, unsigned int size,
			   gfp_t gfp)
{
	unsigned int order = DPA_JUMBO_PAGE_ORDER;
	void *buf;

	if (!c->left) {
		c->page = alloc_pages(gfp | __GFP_COMP | __GFP_NOWARN, order);
		if (!c->page) {
			order = get_order(size);
			c->page = alloc_pages(gfp | __GFP_COMP | __GFP_NOWARN,
					      order);
			if (!c->page)
				return NULL;
		}
		c->left = (PAGE_SIZE << order) / size;
		page_ref_add(c->page, c->left - 1);
		c->next = page_address(c->page);
	}
	buf = c->next;
	c->next += size;
	c->left--;
	return buf;
}

static void dpa_jumbo_end(struct dpa_jumbo_carve *c)
{
	while (c->left) {
		c->left--;
		put_page(c->page);
	}
}
#endif

/* gfp is GFP_ATOMIC from the receive path, which refills from softirq;
 * the pool watch reseeds from process context (dpaa_eth_reseed_bpool()).
 * netdev_alloc_frag() and build_skb() allocate atomically either way. */
static int _dpa_bp_add_8_bufs(const struct dpa_bp *dpa_bp, gfp_t gfp)
{
	void *new_buf, *fman_buf;
	struct bm_buffer bmb[8];
	dma_addr_t addr;
	uint8_t i;
	struct device *dev = dpa_bp->dev;
	struct sk_buff *skb, **skbh;
#ifdef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
	struct dpa_jumbo_carve carve = {};
#endif

	memset(bmb, 0, sizeof(struct bm_buffer) * 8);

	for (i = 0; i < 8; i++) {
		/* We'll prepend the skb back-pointer; can't use the DPA
		 * priv space, because FMan will overwrite it (from offset 0)
		 * if it ends up being the second, third, etc. fragment
		 * in a S/G frame.
		 *
		 * We only need enough space to store a pointer, but allocate
		 * an entire cacheline for performance reasons.
		 */
		if (unlikely(fm_has_errata_a050385())) {
			struct page *new_page = alloc_page(gfp);
			if (unlikely(!new_page)) {
				dev_err_ratelimited(dev, "%s: alloc_page() failed\n",
						    __func__);
				goto err_release_previous_bufs;
			}
			new_buf = page_address(new_page);
		} else {
#ifdef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
			new_buf = dpa_jumbo_buf(&carve, SMP_CACHE_BYTES +
						DPA_BP_RAW_SIZE_JUMBO, gfp);
			if (unlikely(!new_buf)) {
				dev_err_ratelimited(dev, "%s: jumbo buffer of %zu bytes failed\n",
						    __func__, SMP_CACHE_BYTES +
						    DPA_BP_RAW_SIZE_JUMBO);
				goto err_release_previous_bufs;
			}
#else
			new_buf = netdev_alloc_frag(SMP_CACHE_BYTES +
						    DPA_BP_RAW_SIZE);
			if (unlikely(!new_buf)) {
				dev_err_ratelimited(dev, "%s: netdev_alloc_frag(%d) failed\n",
						    __func__, SMP_CACHE_BYTES + DPA_BP_RAW_SIZE);
				goto err_release_previous_bufs;
			}
#endif
		}

		new_buf = PTR_ALIGN(new_buf, SMP_CACHE_BYTES);

		/* Apart from the buffer that will be used by the FMan, the
		 * skb also guarantees enough space to hold the backpointer
		 * in the headroom and the shared info at the end.
		 */
		skb = build_skb(new_buf,
				SMP_CACHE_BYTES + DPA_SKB_SIZE(dpa_bp->size) +
				SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
		if (unlikely(!skb)) {
			put_page(virt_to_head_page(new_buf));
			dev_err_ratelimited(dev, "%s: build_skb(%zu) failed \n",
					    __func__, SMP_CACHE_BYTES +
					    DPA_SKB_SIZE(dpa_bp->size) +
					    SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
			goto err_release_previous_bufs;
		}

		/* Reserve SMP_CACHE_BYTES in the skb's headroom to store the
		 * backpointer. This area will not be synced to, or
		 * overwritten by, the FMan.
		 */
		skb_reserve(skb, SMP_CACHE_BYTES);

		/* We don't sync the first SMP_CACHE_BYTES of the buffer to
		 * the FMan. The skb backpointer is stored at the end of the
		 * reserved headroom. Otherwise it will be overwritten by the
		 * FMan.
		 * The buffer synced with the FMan starts right after the
		 * reserved headroom.
		 */
		fman_buf = new_buf + SMP_CACHE_BYTES;
		DPA_WRITE_SKB_PTR(skb, skbh, fman_buf, -1);

		addr = dma_map_single(dev, fman_buf, dpa_bp->size,
				      DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(dev, addr))) {
			dev_err_ratelimited(dev, "%s: dma_map_single(%zu) failed\n",
					    __func__, dpa_bp->size);
			goto err_free_skb;
		}

		bm_buffer_set64(&bmb[i], addr);
	}

release_bufs:
#ifdef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
	dpa_jumbo_end(&carve);
#endif
	/* Release the buffers. In case bman is busy, keep trying
	 * until successful. bman_release() is guaranteed to succeed
	 * in a reasonable amount of time
	 */
	while (unlikely(bman_release(dpa_bp->pool, bmb, i, 0)))
		cpu_relax();
	return i;

err_free_skb:
	kfree_skb(skb);
err_release_previous_bufs:
	bm_buffer_set64(&bmb[i], 0);
	/* Avoid releasing a completely null buffer; bman_release() requires
	 * at least one buffer.
	 */
	if (likely(i))
		goto release_bufs;

#ifdef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
	dpa_jumbo_end(&carve);
#endif
	return 0;
}

/* Add buffers/(pages) for Rx processing whenever bpool count falls below
 * REFILL_THRESHOLD.
 */
int dpaa_eth_refill_bpools(struct dpa_bp *dpa_bp, int *countptr, int threshold)
{
	int count = *countptr;
	int new_bufs;
	int percpu_buf_cfg_count = dpa_bp->config_count;

	if (unlikely(count <= (percpu_buf_cfg_count - threshold))) {
		do {
			new_bufs = _dpa_bp_add_8_bufs(dpa_bp, GFP_ATOMIC);
			if (unlikely(!new_bufs)) {
				/* Avoid looping forever if we've temporarily
				 * run out of memory. We'll try again at the
				 * next NAPI cycle.
				 */
				break;
			}
			count += new_bufs;
		} while (count < percpu_buf_cfg_count);

		*countptr = count;
		if (unlikely(count < percpu_buf_cfg_count))
			return -ENOMEM;
	}

	return 0;
}
EXPORT_SYMBOL(dpaa_eth_refill_bpools);

/* Put back into the pool, for the pool watch (dpaa_eth_pool.c), buffers its
 * per-CPU counts already hold to be there: none of them is raised. Eight at
 * a time, as the receive path's refill adds them, while eight more stay
 * within @count -- never past it, so short of it by up to seven -- or until
 * an allocation fails, and returns how many went in. Process context: it
 * may sleep, and it neither dips into the atomic reserves the receive path's
 * own refill needs nor has the OOM killer free memory for it. */
int dpaa_eth_reseed_bpool(struct dpa_bp *dpa_bp, int count)
{
	int added = 0, new_bufs;

	might_sleep();
	while (count - added >= 8) {
		new_bufs = _dpa_bp_add_8_bufs(dpa_bp, GFP_KERNEL | __GFP_NORETRY |
					      __GFP_NOWARN);
		if (!new_bufs)
			break;
		added += new_bufs;
		cond_resched();
	}
	return added;
}

/* Cleanup function for outgoing frame descriptors that were built on Tx path,
 * either contiguous frames or scatter/gather ones.
 * Skb freeing is not handled here.
 *
 * This function may be called on error paths in the Tx function, so guard
 * against cases when not all fd relevant fields were filled in.
 *
 * Return the skb backpointer, since for S/G frames the buffer containing it
 * gets freed here.
 */
struct sk_buff *_dpa_cleanup_tx_fd(const struct dpa_priv_s *priv,
	const struct qm_fd *fd)
{
	const struct qm_sg_entry *sgt;
	int i;
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	dma_addr_t addr = qm_fd_addr(fd);
	dma_addr_t sg_addr;
	struct sk_buff **skbh;
	struct sk_buff *skb = NULL;
	const enum dma_data_direction dma_dir = DMA_TO_DEVICE;
	int nr_frags;
	int sg_len;

	/* retrieve skb back pointer */
	DPA_READ_SKB_PTR(skb, skbh, phys_to_virt(addr), 0);

	if (unlikely(fd->format == qm_fd_sg)) {
		nr_frags = skb_shinfo(skb)->nr_frags;
		dma_unmap_single(dpa_bp->dev, addr,
				 dpa_fd_offset(fd) + DPA_SGT_SIZE,
				 dma_dir);

		/* The sgt buffer has been allocated with netdev_alloc_frag(),
		 * it's from lowmem.
		 */
		sgt = phys_to_virt(addr + dpa_fd_offset(fd));
#ifdef CONFIG_FSL_DPAA_1588
		if (priv->tsu && priv->tsu->valid &&
				priv->tsu->hwts_tx_en_ioctl)
			dpa_ptp_store_txstamp(priv, skb, (void *)skbh);
#endif
#ifdef CONFIG_FSL_DPAA_TS
		if (unlikely(priv->ts_tx_en &&
			skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
			struct skb_shared_hwtstamps shhwtstamps;

			dpa_get_ts(priv, TX, &shhwtstamps, (void *)skbh);
			skb_tstamp_tx(skb, &shhwtstamps);
		}
#endif /* CONFIG_FSL_DPAA_TS */

		/* sgt[0] is from lowmem, was dma_map_single()-ed */
		sg_addr = qm_sg_addr(&sgt[0]);
		sg_len = qm_sg_entry_get_len(&sgt[0]);
		dma_unmap_single(dpa_bp->dev, sg_addr, sg_len, dma_dir);

		/* remaining pages were mapped with dma_map_page() */
		for (i = 1; i <= nr_frags; i++) {
			DPA_BUG_ON(qm_sg_entry_get_ext(&sgt[i]));
			sg_addr = qm_sg_addr(&sgt[i]);
			sg_len = qm_sg_entry_get_len(&sgt[i]);
			dma_unmap_page(dpa_bp->dev, sg_addr, sg_len, dma_dir);
		}

		/* Free the page frag that we allocated on Tx */
		put_page(virt_to_head_page(sgt));
	} else {
		dma_unmap_single(dpa_bp->dev, addr,
				 skb_tail_pointer(skb) - (u8 *)skbh, dma_dir);
#ifdef CONFIG_FSL_DPAA_TS
		/* get the timestamp for non-SG frames */
#ifdef CONFIG_FSL_DPAA_1588
		if (priv->tsu && priv->tsu->valid &&
						priv->tsu->hwts_tx_en_ioctl)
			dpa_ptp_store_txstamp(priv, skb, (void *)skbh);
#endif
		if (unlikely(priv->ts_tx_en &&
				skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
			struct skb_shared_hwtstamps shhwtstamps;

			dpa_get_ts(priv, TX, &shhwtstamps, (void *)skbh);
			skb_tstamp_tx(skb, &shhwtstamps);
		}
#endif
	}

	return skb;
}
EXPORT_SYMBOL(_dpa_cleanup_tx_fd);

#ifndef CONFIG_FSL_DPAA_TS
bool dpa_skb_is_recyclable(struct sk_buff *skb)
{
	/* No recycling possible if skb buffer is kmalloc'ed  */
	if (skb->head_frag == 0)
		return false;

	/* or if it's an userspace buffer */
	if (skb_shinfo(skb)->flags & SKBFL_ZEROCOPY_ENABLE)
		return false;

	/* or if it's cloned or shared */
	if (skb_shared(skb) || skb_cloned(skb) ||
	    skb->fclone != SKB_FCLONE_UNAVAILABLE)
		return false;

	return true;
}
EXPORT_SYMBOL(dpa_skb_is_recyclable);

bool dpa_buf_is_recyclable(struct sk_buff *skb,
				  uint32_t min_size,
				  uint16_t min_offset,
				  unsigned char **new_buf_start)
{
	unsigned char *new;

	/* In order to recycle a buffer, the following conditions must be met:
	 * - buffer size no less than the buffer pool size
	 * - buffer size no higher than an upper limit (to avoid moving too much
	 *   system memory to the buffer pools)
	 * - buffer address aligned to cacheline bytes
	 * - offset of data from start of buffer no lower than a minimum value
	 * - offset of data from start of buffer no higher than a maximum value
	 * - the skb back-pointer is stored safely
	 */

	/* guarantee both the minimum size and the minimum data offset */
	new = min(skb_end_pointer(skb) - min_size, skb->data - min_offset);

	/* left align to the nearest cacheline */
	new = (unsigned char *)((unsigned long)new & ~(SMP_CACHE_BYTES - 1));

	/* Make sure there is enough space to store the skb back-pointer in
	 * the headroom, right before the start of the buffer.
	 *
	 * Guarantee that both maximum size and maximum data offsets aren't
	 * crossed.
	 */
	if (likely(new >= (skb->head + sizeof(void *)) &&
		   new >= (skb->data - DPA_MAX_FD_OFFSET) &&
		   skb_end_pointer(skb) - new <= DPA_RECYCLE_MAX_SIZE)) {
		*new_buf_start = new;
		return true;
	}

	return false;
}
EXPORT_SYMBOL(dpa_buf_is_recyclable);
#endif

/* Build a linear skb around the received buffer.
 * We are guaranteed there is enough room at the end of the data buffer to
 * accommodate the shared info area of the skb.
 */
struct sk_buff *__hot contig_fd_to_skb(const struct dpa_priv_s *priv,
					      const struct qm_fd *fd,
					      bool *use_gro, bool dcl4c_valid)
{
	dma_addr_t addr = qm_fd_addr(fd);
	ssize_t fd_off = dpa_fd_offset(fd);
	void *vaddr;
	const fm_prs_result_t *parse_results;
	struct sk_buff *skb = NULL, **skbh;

	vaddr = phys_to_virt(addr);
	DPA_BUG_ON(!IS_ALIGNED((unsigned long)vaddr, SMP_CACHE_BYTES));

	/* Retrieve the skb and adjust data and tail pointers, to make sure
	 * forwarded skbs will have enough space on Tx if extra headers
	 * are added.
	 */
	DPA_READ_SKB_PTR(skb, skbh, vaddr, -1);

#ifdef CONFIG_FSL_DPAA_ETH_JUMBO_FRAME
	/* With jumbo Rx buffers, frames risk being dropped as the socket
	 * backlog reaches its maximum allowed size. Use the frame length for
	 * the skb truesize instead of the buffer size, as this is the size of
	 * the data that actually gets copied to userspace. The stack may grow
	 * the payload; it then warns that the frame is larger than its
	 * truesize, which this accepts.
	 */
	skb->truesize = SKB_TRUESIZE(dpa_fd_length(fd));
#endif

	DPA_BUG_ON(fd_off != priv->rx_headroom);
	skb_reserve(skb, fd_off);
	skb_put(skb, dpa_fd_length(fd));

	/* Peek at the parse results for csum validation */
	parse_results = (const fm_prs_result_t *)(vaddr +
				DPA_RX_PRIV_DATA_SIZE);
	_dpa_process_parse_results(parse_results, fd, skb, use_gro, dcl4c_valid);

#ifdef CONFIG_FSL_DPAA_1588
	if (priv->tsu && priv->tsu->valid && priv->tsu->hwts_rx_en_ioctl)
		dpa_ptp_store_rxstamp(priv, skb, vaddr);
#endif
#ifdef CONFIG_FSL_DPAA_TS
	if (priv->ts_rx_en)
		dpa_get_ts(priv, RX, skb_hwtstamps(skb), vaddr);
#endif /* CONFIG_FSL_DPAA_TS */

	return skb;
}
EXPORT_SYMBOL(contig_fd_to_skb);

/* Build an skb with the data of the first S/G entry in the linear portion and
 * the rest of the frame as skb fragments.
 *
 * The page fragment holding the S/G Table is recycled here.
 */
struct sk_buff *__hot sg_fd_to_skb(const struct dpa_priv_s *priv,
					  const struct qm_fd *fd, bool *use_gro,
					  int *count_ptr, bool dcl4c_valid)
{
	const struct qm_sg_entry *sgt;
	dma_addr_t addr = qm_fd_addr(fd);
	ssize_t fd_off = dpa_fd_offset(fd);
	dma_addr_t sg_addr;
	void *vaddr, *sg_vaddr;
	struct dpa_bp *dpa_bp;
	struct page *page, *head_page;
	int frag_offset, frag_len;
	int page_offset;
	int i;
	const fm_prs_result_t *parse_results;
	struct sk_buff *skb = NULL, *skb_tmp, **skbh;

	vaddr = phys_to_virt(addr);
	DPA_BUG_ON(!IS_ALIGNED((unsigned long)vaddr, SMP_CACHE_BYTES));

	dpa_bp =  dpa_bpid2pool(fd->bpid);
	/* Iterate through the SGT entries and add data buffers to the skb */
	sgt = vaddr + fd_off;
	for (i = 0; i < DPA_SGT_MAX_ENTRIES; i++) {
		/* Extension bit is not supported */
		DPA_BUG_ON(qm_sg_entry_get_ext(&sgt[i]));

		sg_addr = qm_sg_addr(&sgt[i]);
		sg_vaddr = phys_to_virt(sg_addr);
		DPA_BUG_ON(!IS_ALIGNED((unsigned long)sg_vaddr,
				SMP_CACHE_BYTES));

		dma_unmap_single(dpa_bp->dev, sg_addr, dpa_bp->size,
				 DMA_BIDIRECTIONAL);
		if (i == 0) {
			DPA_READ_SKB_PTR(skb, skbh, sg_vaddr, -1);
#ifdef CONFIG_FSL_DPAA_1588
			if (priv->tsu && priv->tsu->valid &&
			    priv->tsu->hwts_rx_en_ioctl)
				dpa_ptp_store_rxstamp(priv, skb, vaddr);
#endif
#ifdef CONFIG_FSL_DPAA_TS
			if (priv->ts_rx_en)
				dpa_get_ts(priv, RX, skb_hwtstamps(skb), vaddr);
#endif /* CONFIG_FSL_DPAA_TS */

			/* In the case of a SG frame, FMan stores the Internal
			 * Context in the buffer containing the sgt.
			 * Inspect the parse results before anything else.
			 */
			parse_results = (const fm_prs_result_t *)(vaddr +
						DPA_RX_PRIV_DATA_SIZE);
			_dpa_process_parse_results(parse_results, fd, skb,
						   use_gro, dcl4c_valid);

			/* Make sure forwarded skbs will have enough space
			 * on Tx, if extra headers are added.
			 */
			DPA_BUG_ON(fd_off != priv->rx_headroom);
			skb_reserve(skb, fd_off);
			skb_put(skb, qm_sg_entry_get_len(&sgt[i]));
		} else {
			/* Not the first S/G entry; all data from buffer will
			 * be added in an skb fragment; fragment index is offset
			 * by one since first S/G entry was incorporated in the
			 * linear part of the skb.
			 *
			 * Caution: 'page' may be a tail page.
			 */
			DPA_READ_SKB_PTR(skb_tmp, skbh, sg_vaddr, -1);
			page = virt_to_page(sg_vaddr);
			head_page = virt_to_head_page(sg_vaddr);

			/* Free (only) the skbuff shell because its data buffer
			 * is already a frag in the main skb.
			 */
			get_page(head_page);
			dev_kfree_skb(skb_tmp);

			/* Compute offset in (possibly tail) page */
			page_offset = ((unsigned long)sg_vaddr &
					(PAGE_SIZE - 1)) +
				(page_address(page) - page_address(head_page));
			/* page_offset only refers to the beginning of sgt[i];
			 * but the buffer itself may have an internal offset.
			 */
			frag_offset = qm_sg_entry_get_offset(&sgt[i]) +
					page_offset;
			frag_len = qm_sg_entry_get_len(&sgt[i]);
			/* skb_add_rx_frag() does no checking on the page; if
			 * we pass it a tail page, we'll end up with
			 * bad page accounting and eventually with segafults.
			 */
			skb_add_rx_frag(skb, i - 1, head_page, frag_offset,
				frag_len, dpa_bp->size);
		}
		/* Update the pool count for the current {cpu x bpool} */
		(*count_ptr)--;

		if (qm_sg_entry_get_final(&sgt[i]))
			break;
	}
	WARN_ONCE(i == DPA_SGT_MAX_ENTRIES, "No final bit on SGT\n");

	/* recycle the SGT fragment */
	DPA_BUG_ON(dpa_bp != dpa_bpid2pool(fd->bpid));
	dpa_bp_recycle_frag(dpa_bp, (unsigned long)vaddr, count_ptr);
	return skb;
}
EXPORT_SYMBOL(sg_fd_to_skb);


void __hot _dpa_rx(struct net_device *net_dev,
		struct qman_portal *portal,
		const struct dpa_priv_s *priv,
		struct dpa_percpu_priv_s *percpu_priv,
		const struct qm_fd *fd,
		u32 fqid,
		int *count_ptr,
		struct qman_poll_ctx *ctx)
{
	bool dcl4c_valid = !!(net_dev->features & NETIF_F_RXCSUM);
	bool use_gro = !!(net_dev->features & NETIF_F_GRO);
	struct dpa_bp *dpa_bp;
	struct sk_buff *skb;
	dma_addr_t addr = qm_fd_addr(fd);
	u32 fd_status = fd->status;
	unsigned int skb_len;
	struct rtnl_link_stats64 *percpu_stats = &percpu_priv->stats;

	if (unlikely(fd_status & FM_FD_STAT_RX_ERRORS) != 0) {
		if (netif_msg_hw(priv) && net_ratelimit())
			netdev_warn(net_dev, "_dpa_rx FD status = 0x%08x\n",
					fd_status & FM_FD_STAT_RX_ERRORS);

		percpu_stats->rx_errors++;
		goto _release_frame;
	}

	dpa_bp = priv->dpa_bp;
	DPA_BUG_ON(dpa_bp != dpa_bpid2pool(fd->bpid));

	/* prefetch the first 64 bytes of the frame or the SGT start */
	dma_unmap_single(dpa_bp->dev, addr, dpa_bp->size, DMA_BIDIRECTIONAL);
	prefetch(phys_to_virt(addr) + dpa_fd_offset(fd));

	/* The only FD types that we may receive are contig and S/G */
	DPA_BUG_ON((fd->format != qm_fd_contig) && (fd->format != qm_fd_sg));

	if (likely(fd->format == qm_fd_contig)) {
		skb = contig_fd_to_skb(priv, fd, &use_gro, dcl4c_valid);
	} else {
		skb = sg_fd_to_skb(priv, fd, &use_gro, count_ptr, dcl4c_valid);
		percpu_priv->rx_sg++;
	}

	/* Account for either the contig buffer or the SGT buffer (depending on
	 * which case we were in) having been removed from the pool.
	 */
	(*count_ptr)--;
	skb->protocol = eth_type_trans(skb, net_dev);

	skb_len = skb->len;

	/* Account the frame before handing it to the stack, as every other
	 * driver does. netif_receive_skb()'s return value is not a drop
	 * report: __netif_receive_skb_core() initialises it to NET_RX_DROP and
	 * only a delivered protocol handler overwrites it, so a frame consumed
	 * on the NF_NETDEV_INGRESS hook -- which is every frame an nftables
	 * flowtable forwards in software -- comes back as NET_RX_DROP after
	 * being forwarded. Counting only on any other value made such frames
	 * vanish from rx_packets and rx_bytes without incrementing rx_dropped
	 * either. Real drops are already counted by the core in its own
	 * rx_dropped and rx_nohandler, which dev_get_stats() adds on top.
	 */
	percpu_stats->rx_packets++;
	percpu_stats->rx_bytes += skb_len;


	skb_record_rx_queue(skb, raw_smp_processor_id());

	if (use_gro) {
		struct dpa_napi_portal *np = &percpu_priv->np;

		np->p = portal;
		qman_portal_napi_gro_receive(ctx, &np->napi, skb);
	} else {
		netif_receive_skb(skb);
	}

	return;

_release_frame:
	dpa_fd_release(net_dev, fd);
}

int __hot skb_to_contig_fd(struct dpa_priv_s *priv,
			   struct sk_buff *skb, struct qm_fd *fd,
			   int *count_ptr, int *offset)
{
	struct sk_buff **skbh;
	dma_addr_t addr;
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	struct net_device *net_dev = priv->net_dev;
	int err;
	enum dma_data_direction dma_dir;
	unsigned char *buffer_start;
	int dma_map_size;

#ifndef CONFIG_FSL_DPAA_TS
	/* Check recycling conditions; only if timestamp support is not
	 * enabled, otherwise we need the fd back on tx confirmation
	 */

	/* We can recycle the buffer if:
	 * - the pool is not full
	 * - the buffer meets the skb recycling conditions
	 * - the buffer meets our own (size, offset, align) conditions
	 */
	if (likely((*count_ptr < dpa_bp->target_count) &&
		   dpa_skb_is_recyclable(skb) &&
		   dpa_buf_is_recyclable(skb, dpa_bp->size,
					 priv->tx_headroom, &buffer_start))) {
		/* Buffer is recyclable; use the new start address
		 * and set fd parameters and DMA mapping direction
		 */
		fd->bpid = dpa_bp->bpid;
		DPA_BUG_ON(skb->data - buffer_start > DPA_MAX_FD_OFFSET);
		fd->offset = (uint16_t)(skb->data - buffer_start);
		dma_dir = DMA_BIDIRECTIONAL;
		dma_map_size = dpa_bp->size;

		/* Store the skb back-pointer before the start of the buffer.
		 * Otherwise it will be overwritten by the FMan.
		 */
		DPA_WRITE_SKB_PTR(skb, skbh, buffer_start, -1);
		*offset = skb_headroom(skb) - fd->offset;
	} else
#endif
	{
		/* Not recyclable.
		 * We are guaranteed to have at least tx_headroom bytes
		 * available, so just use that for offset.
		 */
		fd->bpid = 0xff;
		buffer_start = skb->data - priv->tx_headroom;
		fd->offset = priv->tx_headroom;
		dma_dir = DMA_TO_DEVICE;
		dma_map_size = skb_tail_pointer(skb) - buffer_start;

		/* The buffer will be Tx-confirmed, but the TxConf cb must
		 * necessarily look at our Tx private data to retrieve the
		 * skbuff. Store the back-pointer inside the buffer.
		 */
		DPA_WRITE_SKB_PTR(skb, skbh, buffer_start, 0);
	}

	/* Enable L3/L4 hardware checksum computation.
	 *
	 * We must do this before dma_map_single(DMA_TO_DEVICE), because we may
	 * need to write into the skb.
	 */
	err = dpa_enable_tx_csum(priv, skb, fd,
				 ((char *)skbh) + DPA_TX_PRIV_DATA_SIZE);
	if (unlikely(err < 0)) {
		if (netif_msg_tx_err(priv) && net_ratelimit())
			netdev_err(net_dev, "HW csum error: %d\n", err);
		return err;
	}

	/* Fill in the rest of the FD fields */
	fd->format = qm_fd_contig;
	fd->length20 = skb->len;
	fd->cmd |= FM_FD_CMD_FCO;

	/* Map the entire buffer size that may be seen by FMan, but no more */
	addr = dma_map_single(dpa_bp->dev, skbh, dma_map_size, dma_dir);
	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		if (netif_msg_tx_err(priv) && net_ratelimit())
			netdev_err(net_dev, "dma_map_single() failed\n");
		return -EINVAL;
	}
	qm_fd_addr_set64(fd, addr);

	return 0;
}
EXPORT_SYMBOL(skb_to_contig_fd);

/* Verify the conditions that trigger the A050385 errata:
 * - 4K memory address boundary crossings when the data/SG fragments aren't
 *   aligned to 256 bytes
 * - data and SG fragments that aren't aligned to 16 bytes
 * - SG fragments that aren't mod 16 bytes in size (except for the last
 *   fragment)
 */
static bool a050385_check_skb(struct sk_buff *skb, struct dpa_priv_s *priv)
{
	skb_frag_t *frag;
	int i, nr_frags;

	nr_frags = skb_shinfo(skb)->nr_frags;

	/* Check if the linear data is 16 byte aligned */
	if ((uintptr_t)skb->data % 16)
		return true;

	/* Check if the needed headroom crosses a 4K address boundary without
	 * being 256 byte aligned
	 */
	if (CROSS_4K(skb->data - priv->tx_headroom, priv->tx_headroom) &&
	    (((uintptr_t)skb->data - priv->tx_headroom) % 256))
		return true;

	/* Check if the linear data crosses a 4K address boundary without
	 * being 256 byte aligned
	 */
	if (CROSS_4K(skb->data, skb_headlen(skb)) &&
	    ((uintptr_t)skb->data % 256))
		return true;

	/* When using Scatter/Gather, the linear data becomes the first
	 * fragment in the list and must follow the same restrictions as the
	 * other fragments.
	 *
	 * Check if the linear data is mod 16 bytes in size.
	 */
	if (nr_frags && (skb_headlen(skb) % 16))
		return true;

	/* Check the SG fragments. They must follow the same rules as the
	 * linear data with and additional restriction: they must be multiple
	 * of 16 bytes in size to account for the hardware carryover effect.
	 */
	for (i = 0; i < nr_frags; i++) {
		frag = &skb_shinfo(skb)->frags[i];

		/* Check if the fragment is a multiple of 16 bytes in size.
		 * The last fragment is exempt from this restriction.
		 */
		if ((i != (nr_frags - 1)) && (skb_frag_size(frag) % 16))
			return true;

		/* Check if the fragment is 16 byte aligned */
		if (skb_frag_off(frag) % 16)
			return true;

		/* Check if the fragment crosses a 4K address boundary. Since
		 * the alignment of previous fragments can influence the
		 * current fragment, checking for the 256 byte alignment
		 * isn't relevant.
		 */
		if (CROSS_4K(skb_frag_off(frag), skb_frag_size(frag)))
			return true;
	}

	return false;
}

/* Realign the skb by copying its contents at the start of a newly allocated
 * page. Build a new skb around the new buffer and release the old one.
 * A performance drop should be expected.
 */
static struct sk_buff *a050385_realign_skb(struct sk_buff *skb,
					   struct dpa_priv_s *priv)
{
	int trans_offset = skb_transport_offset(skb);
	int net_offset = skb_network_offset(skb);
	struct sk_buff *nskb = NULL;
	int nsize, headroom;
	struct page *npage;
	void *npage_addr;

	headroom = DPAA_A050385_HEADROOM;

	/* For the new skb we only need the old one's data (both non-paged and
	 * paged). We can skip the old tailroom.
	 *
	 * Make sure the skb_shinfo is cache-line aligned.
	 */
	nsize = SMP_CACHE_BYTES + DPA_SKB_SIZE(headroom + skb->len) +
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	/* Reserve enough memory to accommodate Jumbo frames */
	npage = alloc_pages(GFP_ATOMIC | __GFP_COMP, get_order(nsize));
	if (unlikely(!npage)) {
		WARN_ONCE(1, "Memory allocation failure\n");
		return NULL;
	}
	npage_addr = page_address(npage);

	nskb = build_skb(npage_addr, nsize);
	if (unlikely(!nskb))
		goto err;

	/* Reserve only the needed headroom in order to guarantee the data's
	 * alignment.
	 * Code borrowed and adapted from skb_copy().
	 */
	skb_reserve(nskb, headroom);
	skb_put(nskb, skb->len);
	if (skb_copy_bits(skb, 0, nskb->data, skb->len)) {
		WARN_ONCE(1, "skb parsing failure\n");
		goto err;
	}
	skb_copy_header(nskb, skb);

#ifdef CONFIG_FSL_DPAA_TS
	/* Copy relevant timestamp info from the old skb to the new */
	if (priv->ts_tx_en) {
		skb_shinfo(nskb)->tx_flags = skb_shinfo(skb)->tx_flags;
		skb_shinfo(nskb)->hwtstamps = skb_shinfo(skb)->hwtstamps;
		skb_shinfo(nskb)->tskey = skb_shinfo(skb)->tskey;
		if (skb->sk)
			skb_set_owner_w(nskb, skb->sk);
	}
#endif
	/* We move the headroom when we align it so we have to reset the
	 * network and transport header offsets relative to the new data
	 * pointer. The checksum offload relies on these offsets.
	 */
	skb_set_network_header(nskb, net_offset);
	skb_set_transport_header(nskb, trans_offset);

	return nskb;

err:
	if (nskb)
		dev_kfree_skb(nskb);
	put_page(npage);
	return NULL;
}

struct dpa_bp *sg_bpool_g;
EXPORT_SYMBOL(sg_bpool_g);

struct dpa_bp *skb_2bfreed_bpool_g; //if no recyclable skbs exist in skb fraglist, those should be freed back, SEC engine will add to this bman pool
EXPORT_SYMBOL(skb_2bfreed_bpool_g);

/* 
 *This functions unmaps all the mapped skb sg so far and stored in sgt.  
*/
static void dma_unmap_skb_sg_addrs(struct device *dev, struct sk_buff *skb,
			struct qm_sg_entry *sgt, int skb_list_frags)
{
	dma_addr_t addr;
	struct sk_buff *list_skb;
	struct sk_buff *cur_skb;
	const enum dma_data_direction dma_dir = DMA_TO_DEVICE;
	int sgt_idx = 0;
	int nr_frags = 0;


	for (cur_skb = skb, list_skb = skb_shinfo(skb)->frag_list; 
		(sgt_idx < skb_list_frags) && (cur_skb); )
	{
		addr = qm_sg_addr(&sgt[sgt_idx]);
		dma_unmap_single(dev, addr, qm_sg_entry_get_len(&sgt[sgt_idx]), dma_dir);
		sgt_idx++;

		nr_frags = skb_shinfo(cur_skb)->nr_frags;
		while (nr_frags && sgt_idx < skb_list_frags)
		{
			addr = qm_sg_addr(&sgt[sgt_idx]);
			dma_unmap_page(dev, addr, qm_sg_entry_get_len(&sgt[sgt_idx]), dma_dir);
			nr_frags--;
			sgt_idx++;
		}
		cur_skb = list_skb;
		if (list_skb)
			list_skb = list_skb->next;
	}

	return;
}

/*
 * This inline function updates the sgt entry parameters.
 */
static inline void prepare_qm_sg_entry(struct qm_sg_entry *sgt, int sgt_idx, 
					unsigned int len, dma_addr_t addr)
{
	qm_sg_entry_set_ext(&sgt[sgt_idx], 0);
	qm_sg_entry_set_final(&sgt[sgt_idx], 0);
	/* fill the first entry with skb details */
	qm_sg_entry_set_bpid(&sgt[sgt_idx], 0xff);
	/* set the offset and addr pointers such that
	   in next alloc, that addr should point to skb*/
	qm_sg_entry_set_offset(&sgt[sgt_idx],0);
	qm_sg_entry_set_len(&sgt[sgt_idx], len);
	qm_sg_entry_set64(&sgt[sgt_idx], addr);

	return;
}

/* The SGT has one permanent bidirectional mapping from pool seeding.
 * Software ownership lives beyond the largest hardware table, so completion
 * never has to infer a pointer or mapping device from hardware final bits. */
#define DPA_SEC_SG_OWNER_OFFSET \
	ALIGN(sizeof(struct qm_sg_entry) * (DPA_SGT_MAX_ENTRIES + 1), SMP_CACHE_BYTES)
struct dpa_sec_sg_owner {
	struct sk_buff *skb;
	struct device *dev;
	unsigned int mapped;
};

static struct dpa_sec_sg_owner *dpa_sec_sg_owner(struct qm_sg_entry *sgt)
{
	return (void *)sgt + DPA_SEC_SG_OWNER_OFFSET;
}

/* Only a successful BMan acquire or a rejected enqueue grants CPU ownership.
 * The caller holds the buffer until its next release/enqueue, excluding both
 * concurrent reuse and the idle reaper. */
static struct qm_sg_entry *dpa_sec_sg_acquire(struct dpa_bp *bp, dma_addr_t addr)
{
	dma_sync_single_for_cpu(bp->dev, addr, bp->size, DMA_BIDIRECTIONAL);
	return phys_to_virt(addr);
}

static void dpa_sec_sg_complete(struct qm_sg_entry *sgt, bool free_skb)
{
	struct dpa_sec_sg_owner *owner = dpa_sec_sg_owner(sgt);
	struct sk_buff *skb = owner->skb;
	struct device *dev = owner->dev;

	if (!skb)
		return;
	dma_unmap_skb_sg_addrs(dev, skb, sgt, owner->mapped);
	memset(owner, 0, sizeof(*owner));
	put_device(dev);
	if (free_skb)
		dev_kfree_skb_any(skb);
}

static void dpa_sec_sg_recycle(struct dpa_bp *bp, dma_addr_t addr)
{
	struct bm_buffer bmb = { .opaque = 0 };

	dma_sync_single_for_device(bp->dev, addr, bp->size, DMA_BIDIRECTIONAL);
	bm_buffer_set64(&bmb, addr);
	while (bman_release(bp->pool, &bmb, 1, 0))
		cpu_relax();
}

/* Synchronous submit failure must preserve the skb for its caller; an
 * asynchronous rejection owns it and releases it here. */
void dpaa_sec_sg_release(const struct qm_fd *fd, bool free_skb)
{
	struct dpa_bp *bp = smp_load_acquire(&sg_bpool_g);
	dma_addr_t addr = qm_fd_addr(fd);

	dpa_sec_sg_complete(dpa_sec_sg_acquire(bp, addr), free_skb);
	dpa_sec_sg_recycle(bp, addr);
}
EXPORT_SYMBOL(dpaa_sec_sg_release);

unsigned int dpaa_sec_sg_reap(unsigned int budget)
{
	struct dpa_bp *clean = smp_load_acquire(&sg_bpool_g);
	struct dpa_bp *done = smp_load_acquire(&skb_2bfreed_bpool_g);
	unsigned int reaped = 0;
	struct bm_buffer bmb;

	/* The output-pool worker can start before the input pools exist. */
	if (!clean || !done)
		return 0;
	while (reaped < budget && bman_acquire(done->pool, &bmb, 1, 0) == 1) {
		dma_addr_t addr = bmb.addr;

		dpa_sec_sg_complete(dpa_sec_sg_acquire(clean, addr), true);
		dpa_sec_sg_recycle(clean, addr);
		reaped++;
	}
	return reaped;
}
EXPORT_SYMBOL(dpaa_sec_sg_reap);

static int __hot skb_fraglist_to_sg_fd(struct device *dev, struct net_device *net_dev,
				       struct sk_buff *skb, struct qm_fd *fd, u32 fd_cmd)
{
	struct dpa_bp *clean = smp_load_acquire(&sg_bpool_g);
	struct dpa_bp *done = smp_load_acquire(&skb_2bfreed_bpool_g);
	struct dpa_sec_sg_owner *owner;
	struct sk_buff *cur_skb, *list_skb;
	struct qm_sg_entry *sgt;
	struct bm_buffer bmb;
	dma_addr_t addr, sg_addr;
	unsigned int nr_frags, i;
	skb_frag_t *frag;

	if (!clean || !done ||
	    clean->size < DPA_SEC_SG_OWNER_OFFSET + sizeof(*owner))
		return -EINVAL;
	nr_frags = 1 + skb_shinfo(skb)->nr_frags;
	skb_walk_frags(skb, list_skb)
		nr_frags += 1 + skb_shinfo(list_skb)->nr_frags;
	if (nr_frags > DPA_SGT_MAX_ENTRIES) {
		/* The submitter owns the skb and already permits header rewrites. */
		if (skb_linearize(skb))
			return -ENOMEM;
	}

	if (bman_acquire(done->pool, &bmb, 1, 0) == 1) {
		sgt = dpa_sec_sg_acquire(clean, bmb.addr);
		dpa_sec_sg_complete(sgt, true);
	} else if (bman_acquire(clean->pool, &bmb, 1, 0) == 1) {
		sgt = dpa_sec_sg_acquire(clean, bmb.addr);
	} else {
		return -ENOBUFS;
	}
	sg_addr = bmb.addr;
	memset(sgt, 0, DPA_SEC_SG_OWNER_OFFSET + sizeof(*owner));
	owner = dpa_sec_sg_owner(sgt);
	owner->skb = skb;
	owner->dev = get_device(dev);

	for (cur_skb = skb, list_skb = skb_shinfo(skb)->frag_list; cur_skb;) {
		addr = dma_map_single(dev, cur_skb->data, skb_headlen(cur_skb),
				      DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev, addr)))
			goto mapping_failed;
		prepare_qm_sg_entry(sgt, owner->mapped++, skb_headlen(cur_skb), addr);
		for (i = 0; i < skb_shinfo(cur_skb)->nr_frags; i++) {
			frag = &skb_shinfo(cur_skb)->frags[i];
			addr = skb_frag_dma_map(dev, frag, 0, skb_frag_size(frag),
						DMA_TO_DEVICE);
			if (unlikely(dma_mapping_error(dev, addr)))
				goto mapping_failed;
			prepare_qm_sg_entry(sgt, owner->mapped++, skb_frag_size(frag), addr);
		}
		cur_skb = list_skb;
		if (list_skb)
			list_skb = list_skb->next;
	}
	qm_sg_entry_set_final(&sgt[owner->mapped - 1], 1);
	dma_sync_single_for_device(clean->dev, sg_addr, clean->size, DMA_BIDIRECTIONAL);
	fd->format = qm_fd_sg;
	qm_fd_addr_set64(fd, sg_addr);
	fd->bpid = done->bpid;
	fd->cmd = fd_cmd;
	fd->length20 = skb->len;
	fd->offset = 0;
	return 0;

mapping_failed:
	if (net_ratelimit())
		netdev_err(net_dev, "SEC input DMA mapping failed\n");
	dpa_sec_sg_complete(sgt, false);
	dpa_sec_sg_recycle(clean, sg_addr);
	return -ENOMEM;
}

int __hot skb_to_sg_fd(struct dpa_priv_s *priv,
		       struct sk_buff *skb, struct qm_fd *fd)
{
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	dma_addr_t addr;
	dma_addr_t sg_addr;
	struct sk_buff **skbh;
	struct net_device *net_dev = priv->net_dev;
	int sg_len, sgt_size;
	int err;

	struct qm_sg_entry *sgt;
	void *sgt_buf;
	skb_frag_t *frag;
	int i = 0, j = 0;
	int nr_frags;
	const enum dma_data_direction dma_dir = DMA_TO_DEVICE;

	nr_frags = skb_shinfo(skb)->nr_frags;
	fd->format = qm_fd_sg;

	/* The FMan reads 256 bytes from the start of the SGT regardless of
	 * its size. In accordance, we reserve the same amount of memory as
	 * well.
	 */
	sgt_size = DPA_SGT_SIZE;

	/* Get a page frag to store the SGTable, or a full page if the errata
	 * is in place and we need to avoid crossing a 4k boundary.
	 */
	if (unlikely(fm_has_errata_a050385())) {
		struct page *new_page = alloc_page(GFP_ATOMIC);

		if (unlikely(!new_page))
			return -ENOMEM;
		sgt_buf = page_address(new_page);
	} else {
		sgt_buf = netdev_alloc_frag(priv->tx_headroom + sgt_size);
	}
	if (unlikely(!sgt_buf)) {
		dev_err(dpa_bp->dev, "netdev_alloc_frag() failed\n");
		return -ENOMEM;
	}

	/* it seems that the memory allocator does not zero the allocated mem */
	memset(sgt_buf, 0, priv->tx_headroom + sgt_size);

	/* Enable L3/L4 hardware checksum computation.
	 *
	 * We must do this before dma_map_single(DMA_TO_DEVICE), because we may
	 * need to write into the skb.
	 */
	err = dpa_enable_tx_csum(priv, skb, fd,
				 sgt_buf + DPA_TX_PRIV_DATA_SIZE);
	if (unlikely(err < 0)) {
		if (netif_msg_tx_err(priv) && net_ratelimit())
			netdev_err(net_dev, "HW csum error: %d\n", err);
		goto csum_failed;
	}

	/* Assign the data from skb->data to the first SG list entry */
	sgt = (struct qm_sg_entry *)(sgt_buf + priv->tx_headroom);
	sg_len = skb_headlen(skb);
	qm_sg_entry_set_bpid(&sgt[0], 0xff);
	qm_sg_entry_set_offset(&sgt[0], 0);
	qm_sg_entry_set_len(&sgt[0], sg_len);
	qm_sg_entry_set_ext(&sgt[0], 0);
	qm_sg_entry_set_final(&sgt[0], 0);

	addr = dma_map_single(dpa_bp->dev, skb->data, sg_len, dma_dir);
	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		dev_err(dpa_bp->dev, "DMA mapping failed");
		err = -EINVAL;
		goto sg0_map_failed;
	}

	qm_sg_entry_set64(&sgt[0], addr);

	/* populate the rest of SGT entries */
	for (i = 1; i <= nr_frags; i++) {
		frag = &skb_shinfo(skb)->frags[i - 1];
		qm_sg_entry_set_bpid(&sgt[i], 0xff);
		qm_sg_entry_set_offset(&sgt[i], 0);
		qm_sg_entry_set_len(&sgt[i], skb_frag_size(frag));
		qm_sg_entry_set_ext(&sgt[i], 0);

		if (i == nr_frags)
			qm_sg_entry_set_final(&sgt[i], 1);
		else
			qm_sg_entry_set_final(&sgt[i], 0);

		DPA_BUG_ON(!skb_frag_page(frag));
		addr = skb_frag_dma_map(dpa_bp->dev, frag, 0,
					skb_frag_size(frag), dma_dir);
		if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
			dev_err(dpa_bp->dev, "DMA mapping failed");
			err = -EINVAL;
			goto sg_map_failed;
		}

		/* keep the offset in the address */
		qm_sg_entry_set64(&sgt[i], addr);
	}

	fd->length20 = skb->len;
	fd->offset = priv->tx_headroom;

	/* DMA map the SGT page
	 *
	 * It's safe to store the skb back-pointer inside the buffer since
	 * S/G frames are non-recyclable.
	 */
	DPA_WRITE_SKB_PTR(skb, skbh, sgt_buf, 0);
	addr = dma_map_single(dpa_bp->dev, sgt_buf,
			      priv->tx_headroom + sgt_size,
			      dma_dir);

	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		dev_err(dpa_bp->dev, "DMA mapping failed");
		err = -EINVAL;
		goto sgt_map_failed;
	}

	qm_fd_addr_set64(fd, addr);
	fd->bpid = 0xff;
	fd->cmd |= FM_FD_CMD_FCO;

	return 0;

sgt_map_failed:
sg_map_failed:
	for (j = 0; j < i; j++) {
		sg_addr = qm_sg_addr(&sgt[j]);
		dma_unmap_page(dpa_bp->dev, sg_addr,
			       qm_sg_entry_get_len(&sgt[j]), dma_dir);
	}
sg0_map_failed:
csum_failed:
	put_page(virt_to_head_page(sgt_buf));

	return err;
}
EXPORT_SYMBOL(skb_to_sg_fd);

#define EMAC_QUEUENUM_MASK 0xff

#ifdef CONFIG_CPE_FAST_PATH
/* Resolve a frame's CEETM class from the skb mark. This is the resolution for
 * a port with no hardware qdisc; on a port with one, the qdisc module names
 * every frame's queue itself (dpa_qdisc_txq_fq()).
 */
static int pfe_eth_get_queuenum( struct sk_buff *skb )
{
	if (skb->mark)
		return (skb->mark & EMAC_QUEUENUM_MASK);
	/* These are packets through control path, assign highest priority */
	return (QOS_DEFAULT_QUEUE);
}
#endif /*endif for CONFIG_CPE_FAST_PATH */

#ifdef CONFIG_XFRM
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)

#define ETH_HDR_SIZE            14
#define VLAN_HDR_SIZE           4
#define PPPOE_HDR_SIZE          8
#define ETHHDR_MACEND_OFFSET    12

#define DPOVRD_ENABLE		0x80000000
/* A tunnel SA's decapsulation word (SEC RM table 9-27) carries the length of
 * the outer IP header material SEC strips in its low twelve bits. The offset
 * of the IP header within that material, the bits above, stays zero. */
#define DPOVRD_TUNNEL_DECAP_LEN	0xfff

/* The longest IP header SEC may keep ahead of a transport SA's ESP, either
 * way. Whatever SEC outputs is parsed next by the IPsec offline port, behind
 * the Ethernet header and the SA's 4-byte VLAN tag the descriptor inserts:
 * outbound it finds the SA by ESP's SPI, inbound the decrypted flow by its
 * transport header. FMan's parser reads only a frame's first 256-byte
 * internal buffer, of which the board DTS's buffer-layout keeps the first 96
 * bytes (FMBM_RIM[FOF]) as headroom for the headers the microcode inserts:
 * it reaches byte 160 of the frame. A header it cannot finish there leaves
 * the frame marked block-limit-exceeded, and the microcode discards many
 * such frames (A367). Measured with IPv6 extension headers: ESP's SPI
 * and sequence number ending at byte 154 of SEC's output were always
 * classified, ending at 162 almost never. The eight bytes left here are
 * ESP's or a UDP header's. A decrypted TCP header is longer and meets the
 * limit with a shorter IP header: SEC decrypts such a packet and the offline
 * port discards it, which nothing here can tell before decryption. The bound
 * is well inside DPOVRD's eight-bit length field. */
#define DPA_IPSEC_PARSE_REACH	(256 - 96)
#define DPA_IPSEC_TRANSPORT_HDR_MAX \
	(DPA_IPSEC_PARSE_REACH - ETH_HDR_SIZE - VLAN_HDR_SIZE - 8)

static unsigned char* dpa_get_skb_nh(struct sk_buff* skb, unsigned short *l3_proto, unsigned short* l3_offset)
{
	unsigned short type_id;
	unsigned short offset = ETH_HDR_SIZE;
	type_id = *((unsigned short*) (skb->data + offset - 2));
	while (1)
	{
		switch (type_id)
		{
			case htons(ETH_P_PPP_SES):
				offset += PPPOE_HDR_SIZE;
				type_id = *(unsigned short*)(skb->data + offset - 2);

				if (type_id == htons(PPP_IP))
					type_id = ntohs(ETH_P_IP);
				else if (type_id == htons(PPP_IPV6))
					type_id = ntohs(ETH_P_IPV6);
				break;
			case htons(ETH_P_8021Q):
				offset += VLAN_HDR_SIZE;
				type_id = *(unsigned short*) (skb->data + offset - 2);
				break;
			case htons(ETH_P_IP):
			case htons(ETH_P_IPV6):
				*l3_proto = type_id;
				*l3_offset = offset;
				return (skb->data + offset);
			default:
				*l3_proto = type_id;
				*l3_offset = offset;
				return NULL;
		}
	}
}

/* The transport-mode DPOVRD for an IP header `hdr_len` bytes long whose byte
 * `at` is the next header ESP follows, with `next` in the next-header field;
 * false if SEC cannot be told about that header.
 *
 * With the override bit set SEC takes the header's length and the offset of
 * that byte from here instead of from the SA's PDB. It encrypts or decrypts
 * only what follows the header. Encapsulating, it moves the byte into the ESP
 * trailer and writes `next` in its place; decapsulating, it writes the
 * protocol it finds in the trailer there, and `next` is reserved.
 */
static bool dpa_ipsec_transport_dpovrd(const u8 *nh, unsigned int hdr_len,
				       unsigned int at, u8 next, u32 *dpovrd)
{
	unsigned int nh_offset;

	if (hdr_len > DPA_IPSEC_TRANSPORT_HDR_MAX)
		return false;
	if ((*nh >> 4) == IPVERSION)
		/* Any non-zero offset names byte 9 of an IPv4 header. */
		nh_offset = 1;
	else if (at == offsetof(struct ipv6hdr, nexthdr))
		/* SEC reads byte 6 for an offset of one... */
		nh_offset = 1;
	else if (at % 8 == 0)
		/* ...and eight times the offset otherwise, which is where
		 * every extension header, starting on an eight-byte boundary,
		 * keeps its own. */
		nh_offset = at / 8;
	else
		return false;
	*dpovrd = DPOVRD_ENABLE | hdr_len << 16 | nh_offset << 8 | next;
	return true;
}

/* The DPOVRD value SEC encrypts a frame for `x` with; false if the frame's IP
 * header is one it cannot be told about.
 *
 * A tunnel's is the inner packet's own protocol for the ESP trailer, IPIP or
 * IPv6. A transport SA's describes the frame's own IP header, with ESP for
 * the next header (dpa_ipsec_transport_dpovrd()). Given a tunnel's value --
 * offset and length zero -- a transport frame has its IP header encrypted and
 * IPIP named in the trailer, which no peer decodes. The PDB's own values fit
 * only a header of the plain length, so a transport frame's are taken from
 * the frame, IPv4 options and IPv6 extension headers included.
 */
static bool dpa_ipsec_dpovrd(const struct xfrm_state *x, const u8 *nh,
			     unsigned int len, u32 *dpovrd)
{
	unsigned int hdr_len, at;

	if (x->props.mode != XFRM_MODE_TRANSPORT) {
		*dpovrd = DPOVRD_ENABLE |
			  ((*nh >> 4) == IPVERSION ? IPPROTO_IPIP : IPPROTO_IPV6);
		return true;
	}
	if ((*nh >> 4) == IPVERSION) {
		hdr_len = (nh[0] & 0xf) * 4;
		if (hdr_len < sizeof(struct iphdr) || hdr_len > len)
			return false;
		at = offsetof(struct iphdr, protocol);
	} else {
		bool routing = false;
		u8 next;

		at = offsetof(struct ipv6hdr, nexthdr);
		hdr_len = sizeof(struct ipv6hdr);
		if (hdr_len > len)
			return false;
		next = nh[at];
		/* ESP follows hop-by-hop options, a routing header and any
		 * destination options ahead of one, where ip6_find_1stfragopt()
		 * puts the transport header. */
		for (;;) {
			if (next == NEXTHDR_ROUTING)
				routing = true;
			else if (next != NEXTHDR_HOP &&
				 (next != NEXTHDR_DEST || routing))
				break;
			if (hdr_len + 2 > len)
				return false;
			at = hdr_len;
			next = nh[at];
			hdr_len += (nh[at + 1] + 1) * 8;
			if (hdr_len > len)
				return false;
		}
		/* The offline port sends a frame with a hop limit of 1 or 0 to
		 * the CPU unless its fixed header names ESP: it cannot see ESP
		 * behind extension headers before it decides, and anything else
		 * there may be a decrypted packet its forwarding entry would
		 * pass on expired. On the CPU an outbound SA's output can only
		 * be freed, so such a frame is not encrypted at all. */
		if (at != offsetof(struct ipv6hdr, nexthdr) &&
		    nh[offsetof(struct ipv6hdr, hop_limit)] <= 1)
			return false;
	}
	return dpa_ipsec_transport_dpovrd(nh, hdr_len, at, IPPROTO_ESP, dpovrd);
}

static __hot int __dpaa_submit_outb_pkt_to_SEC(struct sk_buff *skb, struct net_device *net_dev, struct dpa_bp *dpa_bp)
{
	struct xfrm_state *x;
	struct qman_fq *egress_fq = NULL;
	struct qm_fd		 fd;
	int err = -ENOENT, ii;
	int new_ethhdr_end, old_ethhdr_end;
	unsigned short l3_proto, l3_offset;
	unsigned char* skb_nh ;
	struct sec_path *sp;
	u32 dpovrd = 0;
	/* snapshot: dpa_unregister_ipsec_fq_handler may NULL the hook
	 * concurrently; never read the global twice */
	cdx_get_ipsec_fq_hook_t get_ipsec_fq = READ_ONCE(cdx_get_ipsec_fq_hookfn);

	sp = skb_sec_path(skb);

	if ((get_ipsec_fq) && (sp) && (sp->len))
	{
		x = sp->xvec[0];

		egress_fq = get_ipsec_fq(x->handle);

		/* when a packet is submitting to SEC engine,
		use the below code */
		if (!egress_fq)
		{
			net_err_ratelimited("%s: no SEC queue for SA handle %u\n",
					    __func__, x->handle);
			goto sec_submit_failed;
		}

		/*
		* For packets with L2 headers other than ethernet header, L2 headers are
		* stripped off and only ethernet header is maintained. These L2 headers
		* will be added again in offline port classification table entry
		* after SEC processing.
		*/

		skb_nh = dpa_get_skb_nh(skb, &l3_proto, &l3_offset);

		if (skb_nh)
		{
			if(l3_offset != ETH_HDR_SIZE)
			{
				/* The loop below rewrites the L2 header in place. If the head
				 * buffer is shared with a clone (e.g. a tcpdump tap on the
				 * offload interface), COW it first so the capture is not
				 * corrupted. skb_cow_head() is a cheap branch when the skb is
				 * not cloned; on failure drop the packet like the paths below. */
				err = skb_cow_head(skb, 0);
				if (err)
					goto sec_submit_failed;
				/* skb_cow_head() may have reallocated skb->head, so the cached
				 * network-header pointer is now stale; re-derive it against the
				 * new buffer before the in-place rewrite reads it back. */
				skb_nh = dpa_get_skb_nh(skb, &l3_proto, &l3_offset);

				new_ethhdr_end = l3_offset - 2  ; /*l3 offset - protocol(2bytes) */
				old_ethhdr_end = ETHHDR_MACEND_OFFSET ;
				while(old_ethhdr_end >= 0)
					skb->data[new_ethhdr_end--] = skb->data[old_ethhdr_end--];

				*((unsigned short*) (skb->data + l3_offset - 2) ) = l3_proto;
				skb->data = skb->data + l3_offset - ETH_HDR_SIZE;
				skb->len = skb->len - l3_offset + ETH_HDR_SIZE;
			}
			if (!dpa_ipsec_dpovrd(x, skb_nh,
					      skb_headlen(skb) - (skb_nh - skb->data),
					      &dpovrd)) {
				err = -EINVAL;
				goto sec_submit_failed;
			}
		}


		err =  skb_fraglist_to_sg_fd(dpa_bp->dev, net_dev, skb, &fd, dpovrd);
		if (unlikely(err < 0))
		{
			net_err_ratelimited("%s: no S/G frame for SEC: %d\n",
					    __func__, err);
			goto sec_submit_failed;
		}


		for (ii = 0; ii < 100000; ii++) {
			err = qman_enqueue(egress_fq, &fd, 0);
			if (err != -EBUSY)
				break;
		}

		if (unlikely(err < 0)) {
			pr_err_ratelimited("%s: dpa_xmit failed\n", __func__);
			dpaa_sec_sg_release(&fd, false);
			goto sec_submit_failed;
		}

		/* sucessful transmit to CAAM */
		netif_trans_update(net_dev);
		return 0;
	}
sec_submit_failed:
	dev_core_stats_tx_dropped_inc(net_dev);
	kfree_skb(skb);
	return err;
}

/* Hand a frame for a packet-offloaded SA to SEC. 0 means SEC has it; anything
 * else means it was freed here instead and counted as dropped on net_dev, so
 * a caller counting what it gave SEC counts only a 0.
 *
 * The IPsec hook and the SEC frame queue it answers belong to the offload
 * module, which unregisters the hook and then waits for an RCU grace period
 * before anything it answered with may go. Hold the read-side section here,
 * across the lookup and the enqueue, rather than trusting the caller's
 * context to be one. */
static __hot int dpaa_submit_outb_pkt_to_SEC(struct sk_buff *skb, struct net_device *net_dev, struct dpa_bp *dpa_bp)
{
	int rc;

	rcu_read_lock();
	rc = __dpaa_submit_outb_pkt_to_SEC(skb, net_dev, dpa_bp);
	rcu_read_unlock();
	return rc;
}

/* Whether @dev is a port of this driver, and so has a struct dpa_priv_s as
 * its private area. The ops table is the driver's own, and dpa_ndo_init is
 * the one member of it exported, so no other driver's ops carry it: the test
 * the offload module makes too (dpa_netdev_is_dpaa()). */
static bool dpa_netdev_is_dpaa_port(const struct net_device *dev)
{
	return dev && dev->netdev_ops && dev->netdev_ops->ndo_init == dpa_ndo_init;
}

/* Whether @port may lend its receive state to a frame of @x: a port of this
 * driver, and the one the state is bound to. xfrm_input() finds the state by
 * address and SPI, not by device, so the frame may have reached the stack on
 * anything: a bridge, a VLAN over one, a veth, a Wi-Fi VAP or another port.
 * Only a port has a dpa_priv_s to lend. And only the state's own port is
 * where SEC's output goes back to Linux, with the Ethernet header the frame
 * came in with, so from any other port it would arrive addressed elsewhere. */
static bool dpa_inb_port_ok(const struct net_device *port,
			    const struct xfrm_state *x)
{
	return dpa_netdev_is_dpaa_port(port) && port == READ_ONCE(x->xso.dev);
}

/* The DPOVRD value SEC decrypts @skb, an inbound frame of @x, with; false if
 * its IP header is one SEC cannot be told about. Read as xfrm_input() has the
 * frame: data at ESP, the network header at the IP header ESP came in.
 *
 * Either mode's PDB states a plain IP header of the SA's family
 * (cdx_ipsec_build_in_sa_pdb()), so a frame with IPv4 options or IPv6
 * extension headers ahead of ESP would have them read as ESP and fail SEC's
 * ICV check. Each frame's value describes its own header instead, as the
 * stack found it, and so as the stack would have decrypted it.
 *
 * A tunnel's gives the length of everything ahead of ESP, which SEC strips:
 * the outer IP header and, for ESP-in-UDP, the UDP header behind it. The
 * frame has to come the way the state receives, which xfrm_input() checks
 * only after this: through the state's UDP encapsulation if it has one, bare
 * otherwise. Only ESP-in-UDP without a non-ESP marker is offloaded
 * (ft_ipsec_spec()), from which xfrm4_udp_encap_rcv() and
 * xfrm6_udp_encap_rcv() pull exactly the UDP header.
 *
 * A transport SA's gives SEC the frame's header up to ESP and the byte naming
 * ESP, the one the stack found it by (IP6CB()'s nhoff, where
 * xfrm6_transport_finish() writes the protocol too), for SEC to write the
 * protocol from the trailer into. ESP the stack found anywhere else -- behind
 * a UDP header, say -- is not this SA's to decrypt.
 */
static bool dpa_ipsec_inb_dpovrd(const struct xfrm_state *x,
				 const struct sk_buff *skb, u32 *dpovrd)
{
	const u8 *nh = skb_network_header(skb);
	bool tunnel = x->props.mode != XFRM_MODE_TRANSPORT;
	unsigned int hdr_len, ip_len, at;
	u8 next = IPPROTO_ESP;

	*dpovrd = 0;
	if (skb->data <= nh)
		return false;
	hdr_len = ip_len = skb->data - nh;
	if (x->encap) {
		if (!tunnel || ip_len <= sizeof(struct udphdr))
			return false;
		ip_len -= sizeof(struct udphdr);
		next = IPPROTO_UDP;
	}
	switch (*nh >> 4) {
	case IPVERSION:
		if (ip_len != (nh[0] & 0xf) * 4)
			return false;
		at = offsetof(struct iphdr, protocol);
		break;
	case 6:
		at = IP6CB(skb)->nhoff;
		if (ip_len < sizeof(struct ipv6hdr) || at >= ip_len)
			return false;
		break;
	default:
		return false;
	}
	if (nh[at] != next)
		return false;
	if (tunnel) {
		if (hdr_len > DPOVRD_TUNNEL_DECAP_LEN)
			return false;
		*dpovrd = DPOVRD_ENABLE | hdr_len;
		return true;
	}
	return dpa_ipsec_transport_dpovrd(nh, hdr_len, at, 0, dpovrd);
}

/* Hand an inbound ESP frame of the packet-offloaded state @x to SEC, from
 * xfrm_input(). 0: SEC has the frame. Anything else: SEC was not given it --
 * no hook, no queue for the state's handle, a frame that did not arrive on
 * the state's own port (directly, over a VLAN or in a PPPoE session), a
 * header SEC cannot be told about, or one that could not be queued -- and the
 * skb is as it came, a stale IPv4 header checksum at most put right, for
 * xfrm_input() to decide what becomes of it.
 */
static int __dpaa_submit_inb_pkt_to_SEC(struct sk_buff *skb,
					const struct xfrm_state *x)
{
	struct qman_fq *sec_fq = NULL;
	struct dpa_priv_s	*priv = NULL;
	struct dpa_percpu_priv_s *percpu_priv = NULL;
	struct qm_fd		 fd;
	int err, ii;
	/* How far the frame is moved back to its MAC header: past a tunnel's
	 * outer header, which may run to DPOVRD_TUNNEL_DECAP_LEN. */
	unsigned int tmp_len = 0;
	uint8_t data[ETH_HLEN], ipvsn;
	struct net_device *netdev;
	struct device* dev;
	struct net_device *real_dev = NULL;
	u32 dpovrd;
	/* snapshot: dpa_unregister_ipsec_fq_handler may NULL the hook
	 * concurrently; never read the global twice */
	cdx_get_ipsec_fq_hook_t get_ipsec_fq = READ_ONCE(cdx_get_ipsec_fq_hookfn);

	if (get_ipsec_fq)
	{
		/* Get the SEC FQID corresponding to the state's handle */
		sec_fq = get_ipsec_fq(x->handle);

		/*if no SEC FQID found, return non-zero to return pkt to linux*/
		if (!sec_fq || !(skb->dev))
		{
			return -1; /* give packet to linux */
		}
		/* Measured from ESP, before the frame is moved to its MAC
		 * header below. */
		if (!dpa_ipsec_inb_dpovrd(x, skb, &dpovrd))
			return -1;
		if (skb->dev->type == ARPHRD_ETHER)
		{
			/* Get the corresponding physical device info, if the skb->dev corresponds to vlan*/
			real_dev = is_vlan_dev(skb->dev) ? vlan_dev_real_dev(skb->dev) : skb->dev;
			/* Anything but the state's own port goes back untouched,
			 * before its private area is read or the frame moved. */
			if (!dpa_inb_port_ok(real_dev, x))
				return -1;
			priv = netdev_priv(real_dev);
			/* SEC shared descriptor designed to take packet including MAC hdr */
			/* modify skb->data to point to MAC hdr */
			tmp_len = (skb->data - skb_mac_header(skb));
			skb->len += tmp_len;
			skb->data = skb_mac_header(skb);
		}
		else if (skb->dev->type == ARPHRD_PPP)
		{
			/* Get the corresponding physica device info */
			netdev = dev_get_by_index_rcu(dev_net(skb->dev), skb->iif_index);
			/* The device the frame entered the stack by, below any
			 * VLAN or bridge, looked up under the RCU read side the
			 * submit runs in, without RTNL. Given back as above
			 * unless it is the state's own port. */
			if (!dpa_inb_port_ok(netdev, x))
			{
				return -1;
			}
			priv = netdev_priv(netdev);
			/* The PPPoE-to-Ethernet header reconstruction below rewrites
			 * skb->data in place. COW the head first so a live clone (e.g. a
			 * tcpdump tap) is not corrupted; on failure give the packet back
			 * to linux like the other early-outs in this branch. skb->data and
			 * skb->len are still untouched here, so the packet stays intact. */
			if (skb_cow_head(skb, 0))
				return -1;
			/* observation in case of PPPoE skb_mac_header is pointing to IP header*/
			/* get the IP version*/
			ipvsn = ((skb->head[skb->mac_header]) & 0xf0) >> 4;
			/* SEC shared descriptor designed to take packet including MAC hdr */
			/* modify skb->data to point to MAC hdr */
			tmp_len = (skb->data - skb_mac_header(skb) + ETH_HLEN);
			skb->len += tmp_len;
			skb->data = skb_mac_header(skb) - ETH_HLEN;
			/* Copy MAC hdr to the skb->data */
			/* have a backup data in case of failure */
			memcpy(data, skb->data, ETH_HLEN);
			/* copying 8 bytes and then 4 bytes from the backup , as there is overlap*/
			memcpy(skb->data, skb->data-PPPOE_SES_HLEN, PPPOE_SES_HLEN);
			memcpy(skb->data+PPPOE_SES_HLEN, data, 4);
			/* setting IPv4/IPv6 ethernet protocol value */
			if (ipvsn == DPAA_IP_VERSION_4)
			{
				skb->data[12] = 0x08;
				skb->data[13] = 0x00;
			}
			else /* IP v6 */
			{
				skb->data[12] = 0x86;
				skb->data[13] = 0xdd;
			}
		}
		/* Neither Ethernet nor PPP: a tunnel or any other device with
		 * no port under it, so not the state's own port either. */
		if (!priv)
			return -1;

		/* The stack writes its address into a Record Route or
		 * Timestamp option of a packet it delivers, in place, after
		 * checking the header checksum and without updating it. SEC
		 * updates that checksum for the transport header it passes on
		 * rather than computing it afresh, so the decrypted packet
		 * would carry the stale one and the offline port discard it.
		 * The header may be shared again since, with a raw socket's
		 * clone say, so it is unshared before it is written. A
		 * tunnel's outer header is stripped, checksum and all. */
		if (x->props.mode == XFRM_MODE_TRANSPORT && dpovrd &&
		    (skb_network_header(skb)[0] >> 4) == IPVERSION) {
			struct iphdr *iph = ip_hdr(skb);

			if (iph->ihl > 5 && ip_fast_csum(iph, iph->ihl)) {
				if (skb_cow_head(skb, 0))
					goto err_giveback;
				ip_send_check(ip_hdr(skb));
			}
		}

		/* Both arms above leave the state's own port in priv, so the
		 * frame is mapped for that port's pool whatever device it
		 * reached the stack by. */
		dev = priv->dpa_bp->dev;
		netdev = priv->net_dev;
		err =  skb_fraglist_to_sg_fd(dev, netdev, skb, &fd, dpovrd);
		if (unlikely(err < 0))
		{
			net_err_ratelimited("%s: no S/G frame for SEC: %d\n",
					    __func__, err);
			goto err_giveback; /* give packet to linux */
		}

		for (ii = 0; ii < 100000; ii++) {
			err = qman_enqueue(sec_fq, &fd, 0);
			if (err != -EBUSY)
				break;
		}

		if (unlikely(err < 0)) {
			pr_err_ratelimited("%s: qman_enqueue failed\n", __func__);
			dpaa_sec_sg_release(&fd, false);
			goto err_giveback; /* give packet to linux */
		}
		if (priv)
		{
			percpu_priv = raw_cpu_ptr(priv->percpu_priv);
			percpu_priv->tx_caam_dec++;
		}
		return 0;
	}
	/* No hook, so nothing was given to SEC. xfrm_input() asks about any
	 * packet-offloaded state, not only this driver's, and a frame claimed
	 * here would be left with no owner. */
	return -1; /* give packet to linux */

	/* Inbound offload failed after the branch above shifted skb->data/len
	 * (the ARPHRD_ETHER / ARPHRD_PPP reposition). The skb is handed back to
	 * Linux, not consumed, so undo the shift first or Linux sees a packet
	 * with a shifted data pointer / inflated length. tmp_len is the shift
	 * delta; adjusting the live skb->data pointer (rather than restoring a
	 * saved one) stays correct across an intervening skb_cow_head() that
	 * may have reallocated the head. The PPP branch additionally rewrote
	 * ETH_HLEN bytes in place, so restore them from the backup before
	 * moving the pointer back. */
err_giveback:
	if (skb->dev->type == ARPHRD_PPP)
		memcpy(skb->data, data, ETH_HLEN);
	skb->len -= tmp_len;
	skb->data += tmp_len;
	return -1; /* give packet to linux */
}

/* As dpaa_submit_outb_pkt_to_SEC(): xfrm_input() reaches this from softirq and
 * from resumed asynchronous transforms alike, and the read-side section the
 * hook's unregister waits for is taken here. */
int dpaa_submit_inb_pkt_to_SEC(struct sk_buff *skb, const struct xfrm_state *x)
{
	int rc;

	rcu_read_lock();
	rc = __dpaa_submit_inb_pkt_to_SEC(skb, x);
	rcu_read_unlock();
	return rc;
}
#endif
#endif

#ifdef CONFIG_CPE_FAST_PATH
#define CHANNEL_BIT_POSITION 24

static int __cpe_fp_tx(struct sk_buff *skb, struct net_device *net_dev)
{
	struct dpa_priv_s	*priv;
	struct dpa_percpu_priv_s *percpu_priv;
	int channel_id;
	int queuenum;
	int markval,ff=0;
	struct qman_fq *egress_fq, *conf_fq;
	uint8_t get_ceetm_cm_egress_fq;
	uint8_t dscp;
	unsigned char* skb_nh ;
	uint16_t l3_proto = 0, l3_offset = 0;

	priv = netdev_priv(net_dev);
#ifdef CONFIG_XFRM
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
	if(skb->ipsec_offload) {
		/* tx toenc counts frames SEC was given; one freed instead is
		 * already counted as dropped. */
		if (!dpaa_submit_outb_pkt_to_SEC(skb, net_dev, priv->dpa_bp)) {
			percpu_priv = raw_cpu_ptr(priv->percpu_priv);
			percpu_priv->tx_caam_enc++;
		}
		return NETDEV_TX_OK;
	}
#endif
#endif
	if (priv->ceetm_en) {
		/* snapshot: dpa_unregister_ceetm_get_egress_fq may NULL the
		 * hooks concurrently; never read the globals twice */
		cdx_get_ceetm_egressfq ceetm_get_fq = READ_ONCE(ceetm_fqget_func);
		cdx_get_ceetm_dscp_fq ceetm_get_dscp_fq = READ_ONCE(ceetm_dscp_fqget_func);

		/* markval carries both the class and whether one was asked for
		 * at all: zero means this frame names no class, so the DSCP map
		 * below gets to choose instead. */
		markval = pfe_eth_get_queuenum(skb);
		queuenum = markval & 0xf;
		channel_id = (markval >> CHANNEL_BIT_POSITION) & 0xf;
		egress_fq = NULL;
		get_ceetm_cm_egress_fq = 1; /* This becomes 0 when the frame names
						no class and the DSCP map answers */
		/* A hardware qdisc has already decided this frame's class, in
		 * ndo_select_queue and from the same key the hardware rule used,
		 * and put the frame on that leaf's Tx queue. Reading the class
		 * back out of the queue index is what stops the two paths
		 * resolving it twice and disagreeing. A frame on an ordinary
		 * queue named no class, and on a port the qdisc owns the qdisc
		 * decides where it goes too, from the frame. Only a port with no
		 * qdisc answers NULL, and the mark and DSCP paths below are
		 * reached there exactly as before -- and nowhere else. */
		egress_fq = dpa_qdisc_txq_fq(priv->qm_ctx, skb_get_queue_mapping(skb),
					     skb);
		if (egress_fq)
			get_ceetm_cm_egress_fq = 0;
		/* No class named, so take the DSCP from the frame and let the
		 * map choose the egress fq. */
		if (get_ceetm_cm_egress_fq && !markval && ceetm_get_dscp_fq) {
			skb_nh = dpa_get_skb_nh(skb, &l3_proto, &l3_offset);
			if (skb_nh)
			{
				/* skb_nh is non NULL means either it is pointing to ipv4 or ipv6 header only */
				if (l3_proto ==  htons(ETH_P_IP))
				{
					/* Getting the DSCP value from IPv4 header*/
					dscp = (((struct iphdr *)skb_nh)->tos) >> 2; /* tos 8 bit size, DSCP 6 bit value, shifting 2 bits right to get actual DSCP value*/
				}
				else
				{
					 /* Getting the DSCP value from IPv6 header*/
					dscp = ((((struct ipv6hdr *)skb_nh)->priority) << 2) /* priority is 4 bit size, shifting 2 bits left to give space for flow_lbl[0] 2 bits */
						+ ((((struct ipv6hdr *)skb_nh)->flow_lbl[0]) >> 6); /* flow_lbl[0] is 8 bit size, DSCP 2 bits are here, so shifting 6 bits right*/
				}
				egress_fq = ceetm_get_dscp_fq(priv->qm_ctx, dscp);
				if (egress_fq)
					get_ceetm_cm_egress_fq = 0;
			}
		}
		if (get_ceetm_cm_egress_fq)
		{
			if (ceetm_get_fq) {
				egress_fq = ceetm_get_fq(priv->qm_ctx,
					channel_id,queuenum,ff);
			}
			if (!egress_fq) {
				printk(KERN_CRIT "%s::unable to get ceetm fq, mark %08x registered func %p"
						"dropping packet\n",
						__func__, markval , ceetm_get_fq);
				dev_kfree_skb(skb);
				return NETDEV_TX_OK;
			}
		}
	}  else
	{
		queuenum = dpa_get_queue_mapping(skb);
		if (unlikely(queuenum >= DPAA_ETH_TX_QUEUES))
			queuenum = queuenum % DPAA_ETH_TX_QUEUES;
		egress_fq = priv->egress_fqs[queuenum];
	}
	/* Confirm on the queue that sent the frame. This indexed conf_fqs[] with
	 * queuenum, which in the CEETM branch is a class-queue id and not a Tx
	 * queue at all -- so a DSCP-classified frame, whose queuenum is always
	 * zero, confirmed on conf_fqs[0] whichever core sent it, and a marked
	 * one confirmed on whichever conf queue its class happened to number.
	 * Neither is the queue whose Tx ring the frame left by, which is what
	 * confirmation accounting and completion affinity both assume. */
	conf_fq = priv->conf_fqs[skb_get_queue_mapping(skb) & (DPAA_ETH_TX_QUEUES - 1)];
	return dpa_tx_extended(skb, net_dev, egress_fq, conf_fq);
}

/* Every hook this path calls belongs to the offload module: the CEETM and IPsec
 * frame-queue lookups, and the frame queues they answer with, which the
 * enqueue below uses after the lookup has returned. The module unregisters its
 * hooks and waits for an RCU grace period before tearing any of that down, so
 * the read-side section has to cover the lookup and the enqueue both -- and it
 * is taken here rather than assumed of the caller. ndo_start_xmit normally runs
 * with bottom halves off, which a grace period also waits for, but not every
 * caller of this path is the stack's own transmit. */
static int cpe_fp_tx(struct sk_buff *skb, struct net_device *net_dev)
{
	int rc;

	rcu_read_lock();
	rc = __cpe_fp_tx(skb, net_dev);
	rcu_read_unlock();
	return rc;
}
#endif

static inline void skb_reset_truesize(struct sk_buff *skb, unsigned int size)
{
	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	skb->truesize = SKB_TRUESIZE(size);

	return;
}

int __hot dpa_tx(struct sk_buff *skb, struct net_device *net_dev)
{
	struct dpa_priv_s       *priv;
	int queue_mapping = dpa_get_queue_mapping(skb);
	struct qman_fq *egress_fq, *conf_fq;


#ifdef CONFIG_CPE_FAST_PATH
	return cpe_fp_tx(skb, net_dev);
#endif

	priv = netdev_priv(net_dev);


	if (unlikely(queue_mapping >= DPAA_ETH_TX_QUEUES))
		queue_mapping = queue_mapping % DPAA_ETH_TX_QUEUES;

	egress_fq = priv->egress_fqs[queue_mapping];
	conf_fq = priv->conf_fqs[queue_mapping];

	return dpa_tx_extended(skb, net_dev, egress_fq, conf_fq);
}

int __hot dpa_tx_extended(struct sk_buff *skb, struct net_device *net_dev,
		struct qman_fq *egress_fq, struct qman_fq *conf_fq)
{
	struct dpa_priv_s	*priv;
	struct qm_fd		 fd;
	struct dpa_percpu_priv_s *percpu_priv;
	struct rtnl_link_stats64 *percpu_stats;
	int err = 0;
	bool nonlinear, skb_changed, skb_need_wa;
	int *countptr, offset = 0;
	struct sk_buff *nskb;
	struct netdev_queue *txq;
	int txq_id = skb_get_queue_mapping(skb);

	/* Flags to help optimize the A050385 errata restriction checks.
	 *
	 * First flag marks if the skb changed between the first A050385 check
	 * and the moment it's converted to an FD.
	 *
	 * The second flag marks if the skb needs to be realigned in order to
	 * avoid the errata.
	 *
	 * The flags should have minimal impact on platforms not impacted by
	 * the errata.
	 */
	skb_changed = false;
	skb_need_wa = false;

	priv = netdev_priv(net_dev);
	/* Non-migratable context, safe to use raw_cpu_ptr */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	percpu_stats = &percpu_priv->stats;
	countptr = raw_cpu_ptr(priv->percpu_count);

	clear_fd(&fd);

	if (unlikely(fm_has_errata_a050385()) && a050385_check_skb(skb, priv))
		skb_need_wa = true;

	nonlinear = skb_is_nonlinear(skb);

#ifdef CONFIG_FSL_DPAA_1588
	if (priv->tsu && priv->tsu->valid && priv->tsu->hwts_tx_en_ioctl)
		fd.cmd |= FM_FD_CMD_UPD;
#endif
#ifdef CONFIG_FSL_DPAA_TS
	if (unlikely(priv->ts_tx_en &&
			skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		fd.cmd |= FM_FD_CMD_UPD;
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
#endif /* CONFIG_FSL_DPAA_TS */

	/* MAX_SKB_FRAGS is larger than our DPA_SGT_MAX_ENTRIES; make sure
	 * we don't feed FMan with more fragments than it supports.
	 * Btw, we're using the first sgt entry to store the linear part of
	 * the skb, so we're one extra frag short.
	 */
	if (nonlinear && !skb_need_wa &&
	    likely(skb_shinfo(skb)->nr_frags < DPA_SGT_MAX_ENTRIES)) {
		/* Just create a S/G fd based on the skb */
		err = skb_to_sg_fd(priv, skb, &fd);
		percpu_priv->tx_frag_skbuffs++;
	} else {
		/* Make sure we have enough headroom to accommodate private
		 * data, parse results, etc. Normally this shouldn't happen if
		 * we're here via the standard kernel stack.
		 */
		if (unlikely(skb_headroom(skb) < priv->tx_headroom)) {
			struct sk_buff *skb_new;

			skb_new = skb_realloc_headroom(skb, priv->tx_headroom);
			if (unlikely(!skb_new)) {
				dev_kfree_skb(skb);
				percpu_stats->tx_errors++;
				return NETDEV_TX_OK;
			}

			/* propagate the skb ownership information */
			if (skb->sk)
				skb_set_owner_w(skb_new, skb->sk);

			dev_kfree_skb(skb);
			skb = skb_new;
			skb_changed = true;
		}

		/* We're going to store the skb backpointer at the beginning
		 * of the data buffer, so we need a privately owned skb
		 *
		 * Under the A050385 errata, we are going to have a privately
		 * owned skb after realigning the current one, so no point in
		 * copying it here in that case.
		 */

		/* Code borrowed from skb_unshare(). */
		if (skb_cloned(skb) && !skb_need_wa) {
			nskb = skb_copy(skb, GFP_ATOMIC);
			consume_skb(skb);
			skb = nskb;
			skb_changed = true;

			/* skb_copy() has now linearized the skbuff. */
		} else if (unlikely(nonlinear) && !skb_need_wa) {
			/* We are here because the egress skb contains
			 * more fragments than we support. In this case,
			 * we have no choice but to linearize it ourselves.
			 */
			/* No point in linearizing the skb now if we are going
			 * to realign and linearize it again further down due
			 * to the A050385 errata
			 */
			if (unlikely(fm_has_errata_a050385()))
				skb_need_wa = true;
			else
				err = __skb_linearize(skb);
		}
		if (unlikely(!skb || err < 0))
			/* Common out-of-memory error path */
			goto enomem;

		/* Verify the skb a second time if it has been updated since
		 * the previous check
		 */
		if (unlikely(fm_has_errata_a050385()) && skb_changed &&
		    a050385_check_skb(skb, priv))
			skb_need_wa = true;

		if (unlikely(fm_has_errata_a050385()) && skb_need_wa) {
			nskb = a050385_realign_skb(skb, priv);
			if (!nskb)
				goto skb_to_fd_failed;
			dev_kfree_skb(skb);
			skb = nskb;
		}

		err = skb_to_contig_fd(priv, skb, &fd, countptr, &offset);
	}
	if (unlikely(err < 0))
		goto skb_to_fd_failed;

	if (fd.bpid != 0xff) {
		skb_recycle(skb);
		/* skb_recycle() reserves NET_SKB_PAD as skb headroom,
		 * but we need the skb to look as if returned by build_skb().
		 * We need to manually adjust the tailptr as well.
		 */
		/* skb_reset_truesize() resets the skb truesize, to avoid 
		 * skb truesize gets increment continuously when the same 
		 * skb used for next fragments.
		 */
		skb_reset_truesize(skb, SMP_CACHE_BYTES + DPA_SKB_SIZE(priv->dpa_bp->size) +
				SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
		skb->data = skb->head + offset;
		skb_reset_tail_pointer(skb);

		(*countptr)++;
		percpu_priv->tx_returned++;
	}
	if (unlikely(dpa_xmit(priv, percpu_stats, &fd, egress_fq, conf_fq) < 0))
		goto xmit_failed;

	/* LLTX forces us to update our own jiffies for each netdev queue.
	 * Use the queue mapping registered in the skb.
	 */
	txq = netdev_get_tx_queue(net_dev, txq_id);
	txq->trans_start = jiffies;
	return NETDEV_TX_OK;

xmit_failed:
	if (fd.bpid != 0xff) {
		(*countptr)--;
		percpu_priv->tx_returned--;
		dpa_fd_release(net_dev, &fd);
		percpu_stats->tx_errors++;
		return NETDEV_TX_OK;
	}
	_dpa_cleanup_tx_fd(priv, &fd);
skb_to_fd_failed:
enomem:
	percpu_stats->tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(dpa_tx_extended);

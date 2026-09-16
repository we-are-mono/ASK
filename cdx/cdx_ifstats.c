/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                ifstats.c     
 * @description         interface statistics management routines.
 */

#include "fm_muram_ext.h"
#include "dpaa_eth.h"
#include "fm_ehash.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "layer2.h"
#include "portdefs.h"
#include "fm_muram_ext.h"
#include "cdx_flowtable_hw.h"

#ifdef INCLUDE_IFSTATS_SUPPORT

//uncomment to enable debug prints fron this file
//#define IFSTATS_DEBUG	1


/*
 * Concurrency:
 *   dpa_statslist_lock (spinlock)
 *      - Guards the cdx_iface_ifinfo free lists (ifstats_freelist
 *        and the PPPoE variant) and their backing stats_mem
 *        region. All takers are process context (ioctl-path
 *        alloc/free and the dev_get_stats callback), which is why
 *        plain spin_lock() is sufficient; do not add a softirq
 *        taker without switching the discipline to _bh.
 *   stats_mem, stats_mem_phys
 *      - Set once at init in cdx_init_stats; after that read-only.
 *
 * Contexts:
 *   cdx_alloc_ifstats, cdx_free_ifstats     - process, ioctl.
 *   cdx_iface_stats_get                     - any context.
 *   cdx_init_stats                          - module init.
 */
DEFINE_SPINLOCK(dpa_statslist_lock);
//base of stats area
static void *stats_mem;
//stats area phys addr
uint32_t stats_mem_phys;
//free lists will be manipulated under device locks
//free list all interface other than PPPoE
struct cdx_iface_ifinfo *ifstats_freelist;
//free list for pppoe
struct cdx_pppoe_iface_ifinfo *pppoe_ifstats_freelist;

extern void *FmMurambaseAddr;

/* Free the stats MURAM carve and drop the freelists. Called from the
 * dpa_release_iflist deinit sweep, after every slot has been returned —
 * nothing may touch stats_mem-backed slots past this point. */
void cdx_deinit_iface_stats(void *muram_handle)
{
	if (!stats_mem)
		return;
	if (muram_handle)
		FM_MURAM_FreeMem(muram_handle, stats_mem);
	spin_lock(&dpa_statslist_lock);
	stats_mem = NULL;
	stats_mem_phys = 0;
	ifstats_freelist = NULL;
	pppoe_ifstats_freelist = NULL;
	spin_unlock(&dpa_statslist_lock);
}

/* allocate muram and create free lists */
int cdxdrv_init_stats(void *muram_handle)
{
	uint32_t ii;
	uint32_t num_log_ifaces;
	uint32_t size;
	struct cdx_pppoe_iface_ifinfo *pppoe_stats;
	struct cdx_iface_ifinfo *ifstats;

	size = (MAX_PPPoE_INTERFACES * sizeof(struct cdx_pppoe_iface_ifinfo)) + 
			((MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES) * sizeof(struct cdx_iface_ifinfo));
	stats_mem = FM_MURAM_AllocMem(muram_handle, size, sizeof(uint64_t));
	if (!stats_mem) {
		printk("%s::unable to allocate muram for iface stats, size %u\n", __func__, size );
		return -1;
	}
	stats_mem_phys = (uint32_t)((uint8_t *)stats_mem - (uint8_t *)FmMurambaseAddr);
#ifdef IFSTATS_DEBUG
	printk("%s::ifstats mem base %p phys %x size %ld\n", __func__, stats_mem, stats_mem_phys, size);
	/* fill pppoe stats free lists */
	printk("%s::pppoe ifstats at %p\n", __func__, stats_mem);
#endif
	spin_lock(&dpa_statslist_lock);
	pppoe_ifstats_freelist = (struct cdx_pppoe_iface_ifinfo *)stats_mem;
	pppoe_stats = pppoe_ifstats_freelist;
	for (ii = 0; ii < MAX_PPPoE_INTERFACES; ii++) {
		if (ii != (MAX_PPPoE_INTERFACES - 1))
			pppoe_stats->next = (pppoe_stats + 1);
		else
			pppoe_stats->next = NULL;
		pppoe_stats++;
	}
	ifstats = (struct cdx_iface_ifinfo *)pppoe_stats;
	/* calculate space remaining for other logical interfaces */
	num_log_ifaces = (MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES); 
#ifdef IFSTATS_DEBUG
	printk("%s::ifstats at %p max log ifaces %d\n", __func__, ifstats,
		num_log_ifaces);
#endif
	ifstats_freelist = ifstats;
	/* fill other iface stats free lists */
	for (ii = 0; ii < num_log_ifaces; ii++) {
		if (ii != (num_log_ifaces - 1))
			ifstats->next = (ifstats + 1);
		else
			ifstats->next = NULL;
		ifstats++;
	} 
	spin_unlock(&dpa_statslist_lock);
	return 0;
}

int alloc_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{
	iface->last_stats = (struct iface_stats *)kzalloc(sizeof(struct iface_stats), GFP_KERNEL);  
	if (!iface->last_stats) {
		DPA_ERROR("%s:: memory alloc failed for iface last stats\n", __func__);
		return FAILURE;
	}

	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_ifinfo *pppoe_stats;

		spin_lock(&dpa_statslist_lock);
		pppoe_stats = pppoe_ifstats_freelist;
		if (pppoe_stats) {
			pppoe_ifstats_freelist = pppoe_stats->next;
			/* Use memset_io for MURAM - it's device memory on ARM64; plain memset emits dc zva, which faults. */
			memset_io((void __iomem *)pppoe_stats, 0, sizeof(struct cdx_pppoe_iface_ifinfo));
			iface->rxstats_index = (((uint32_t)((uint8_t *)&pppoe_stats->stats.rxstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats_with_ts)) | STATS_WITH_TS);
			iface->txstats_index = (((uint32_t)((uint8_t *)&pppoe_stats->stats.txstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats_with_ts)) | STATS_WITH_TS);
#ifdef IFSTATS_DEBUG
			printk("%s::allocated pppoe stats %p, rx_offset %x tx_offset %x\n", 
				__func__, pppoe_stats, iface->rxstats_index, iface->txstats_index);
#endif
		}
		iface->stats = pppoe_stats;
		spin_unlock(&dpa_statslist_lock);
	} else {
		struct cdx_iface_ifinfo *ifstats;

		spin_lock(&dpa_statslist_lock);
		ifstats = ifstats_freelist;
		if (ifstats) {
			ifstats_freelist = ifstats->next;
			/* Use memset_io for MURAM - it's device memory on ARM64; plain memset emits dc zva, which faults. */
			memset_io((void __iomem *)ifstats, 0, sizeof(struct cdx_iface_ifinfo));
			iface->rxstats_index = ((uint32_t )((uint8_t *)&ifstats->stats.rxstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats));
			iface->txstats_index = ((uint32_t )((uint8_t *)&ifstats->stats.txstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats));
#ifdef IFSTATS_DEBUG
			printk("%s::rxstats %p, txstats %p, mem %p\n", __func__,
					&ifstats->stats.rxstats,
					&ifstats->stats.txstats,
					stats_mem);
			printk("%s::allocated stats %p, rxoffset %x txoffet %x\n", __func__, 
				ifstats, iface->rxstats_index, iface->txstats_index);
#endif
		}
		iface->stats = ifstats;
		spin_unlock(&dpa_statslist_lock);
	}
	if (!iface->stats) {
		/* freelist exhausted. Returning SUCCESS here would leave
		 * rxstats_index/txstats_index aliasing slot 0 and a NULL
		 * stats pointer that the FCI stats query would deref. */
		DPA_ERROR("%s::stats freelist exhausted for type %x\n",
				__func__, dev_type);
		kfree(iface->last_stats);
		iface->last_stats = NULL;
		return FAILURE;
	}
	return SUCCESS;
}

void free_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{
	/* NULL-guarded for idempotence: callers may legitimately hold
	 * an iface whose slot was already returned, and the guards make
	 * a double call harmless */
	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_ifinfo *pppoe_stats;

		pppoe_stats = (struct cdx_pppoe_iface_ifinfo *)iface->stats;
		if (pppoe_stats) {
			spin_lock(&dpa_statslist_lock);
			pppoe_stats->next = pppoe_ifstats_freelist;
			pppoe_ifstats_freelist = pppoe_stats;
			spin_unlock(&dpa_statslist_lock);
			iface->stats = NULL;
		}
	} else {
		struct cdx_iface_ifinfo *ifstats;

		ifstats = (struct cdx_iface_ifinfo *)iface->stats;
		if (ifstats) {
			spin_lock(&dpa_statslist_lock);
			ifstats->next = ifstats_freelist;
			ifstats_freelist = ifstats;
			spin_unlock(&dpa_statslist_lock);
			iface->stats = NULL;
		}
	}
	if (iface->last_stats) {
		kfree(iface->last_stats);
		iface->last_stats = NULL;
	}
}

uint32_t get_logical_ifstats_base(void)
{
	return (stats_mem_phys);
}

/* The index a header manipulation carries for one record half, in units of its
 * own pool's record. Both fields that eventually hold it are eight bits wide
 * (dpa_iface_info's rxstats_index, dpa_l2hdr_info's offsets), so a plain
 * record far enough into the area cannot be named at all -- the legacy path
 * truncates there silently, and refusing is the only honest answer. */
static int ifstats_slot_index(const void *half, size_t stride, u8 *index)
{
	unsigned long units = ((const uint8_t *)half - (const uint8_t *)stats_mem) / stride;

	if (units > U8_MAX)
		return -ERANGE;
	*index = (u8)units;
	return 0;
}

int cdx_ft_ifstats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **out)
{
	struct cdx_ft_stats_slot *slot;
	int rc = -ENOSPC;

	*out = NULL;
	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return -ENOMEM;
	slot->kind = kind;
	spin_lock(&dpa_statslist_lock);
	if (!stats_mem) {
		/* Deinit has returned the carve; there is nothing to index. */
	} else if (kind == CDX_FT_STATS_TIMESTAMPED) {
		struct cdx_pppoe_iface_ifinfo *record = pppoe_ifstats_freelist;

		if (record &&
		    !ifstats_slot_index(&record->stats.rxstats,
					sizeof(struct en_ehash_stats_with_ts),
					&slot->rx_index) &&
		    !ifstats_slot_index(&record->stats.txstats,
					sizeof(struct en_ehash_stats_with_ts),
					&slot->tx_index)) {
			pppoe_ifstats_freelist = record->next;
			/* memset_io for MURAM: it is device memory on ARM64 and
			 * a plain memset emits dc zva, which faults. Reads of
			 * the same region do not, which is why the read below
			 * is an ordinary struct access. */
			memset_io((void __iomem *)record, 0, sizeof(*record));
			slot->rx_index |= STATS_WITH_TS;
			slot->tx_index |= STATS_WITH_TS;
			slot->record = record;
			rc = 0;
		}
	} else {
		struct cdx_iface_ifinfo *record = ifstats_freelist;

		if (record &&
		    !ifstats_slot_index(&record->stats.rxstats,
					sizeof(struct en_ehash_stats), &slot->rx_index) &&
		    !ifstats_slot_index(&record->stats.txstats,
					sizeof(struct en_ehash_stats), &slot->tx_index)) {
			ifstats_freelist = record->next;
			memset_io((void __iomem *)record, 0, sizeof(*record));
			slot->record = record;
			rc = 0;
		}
	}
	spin_unlock(&dpa_statslist_lock);
	if (rc) {
		kfree(slot);
		return rc;
	}
	*out = slot;
	return 0;
}

void cdx_ft_ifstats_free(struct cdx_ft_stats_slot **out)
{
	struct cdx_ft_stats_slot *slot = *out;

	if (!slot)
		return;
	*out = NULL;
	spin_lock(&dpa_statslist_lock);
	/* Deinit may already have dropped the carve and both lists, in which
	 * case there is no list to return this record to and nothing that
	 * could hand it out again. */
	if (stats_mem && slot->kind == CDX_FT_STATS_TIMESTAMPED) {
		struct cdx_pppoe_iface_ifinfo *record = slot->record;

		record->next = pppoe_ifstats_freelist;
		pppoe_ifstats_freelist = record;
	} else if (stats_mem) {
		struct cdx_iface_ifinfo *record = slot->record;

		record->next = ifstats_freelist;
		ifstats_freelist = record;
	}
	spin_unlock(&dpa_statslist_lock);
	kfree(slot);
}

/* The firmware writes these fields big-endian, so the read is a be-to-cpu
 * conversion. control_stat.c spells the same conversion cpu_to_be32/64, which
 * is the identical byte swap under a name that says the opposite; it is not
 * copied here, because a reader of this path should be able to tell which way
 * the value is travelling. */
void cdx_ft_ifstats_read(const struct cdx_ft_stats_slot *slot,
			 struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
	if (rx)
		*rx = (struct cdx_ft_stats){};
	if (tx)
		*tx = (struct cdx_ft_stats){};
	if (!slot)
		return;
	if (slot->kind == CDX_FT_STATS_TIMESTAMPED) {
		const struct en_ehash_ifstats_with_ts *record = slot->record;

		if (rx) {
			rx->bytes = be64_to_cpu(record->rxstats.bytes);
			rx->packets = be32_to_cpu(record->rxstats.pkts);
		}
		if (tx) {
			tx->bytes = be64_to_cpu(record->txstats.bytes);
			tx->packets = be32_to_cpu(record->txstats.pkts);
		}
	} else {
		const struct en_ehash_ifstats *record = slot->record;

		if (rx) {
			rx->bytes = be64_to_cpu(record->rxstats.bytes);
			rx->packets = be32_to_cpu(record->rxstats.pkts);
		}
		if (tx) {
			tx->bytes = be64_to_cpu(record->txstats.bytes);
			tx->packets = be32_to_cpu(record->txstats.pkts);
		}
	}
}
#endif


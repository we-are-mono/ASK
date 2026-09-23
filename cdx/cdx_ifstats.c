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
 *        alloc/free, the dev_get_stats callback and the sampler's
 *        work item), which is why plain spin_lock() is sufficient;
 *        do not add a softirq taker without switching the
 *        discipline to _bh. Taken inside dpa_devlist_lock by the
 *        registered-interface fold in devman.c; nothing here takes
 *        that lock, so the order is fixed.
 *   stats_mem, stats_mem_phys
 *      - Set under the lock once at init in cdxdrv_init_stats, cleared
 *        under it before the carve is returned, so a taker that finds
 *        stats_mem set may read the records.
 *
 *   published_slots
 *      - The flowtable owner's records that dev_get_stats() folds into a
 *        device's counters, under the same lock: the fold runs in
 *        process context (RTNL or RCU) and must find a slot either
 *        published with a live record or gone, never freed.
 *
 *   ifstats_wide
 *      - Each record's packet counts carried past 32 bits, under the
 *        same lock: every read of a record advances them.
 *
 *   ifstats_sampler
 *      - Reads every record handed out, once a period, so that no count
 *        comes round twice between two reads. It touches the carve and
 *        ifstats_wide alone, under the lock and only while stats_mem is
 *        set -- never a slot or an interface, whose lifetimes are their
 *        owners'. Queued by cdx_ifstats_start() when devman registers the
 *        dev_get_stats hook and cancelled synchronously by
 *        cdx_ifstats_stop() when it deregisters it, so it cannot outlive
 *        the module.
 *
 * Contexts:
 *   alloc_iface_stats, free_iface_stats     - process, interface registration.
 *   cdx_ft_ifstats_alloc, _free, _read,
 *   _publish, _unpublish                    - process, flowtable transaction.
 *   cdxdrv_init_stats                       - module init.
 *   cdx_deinit_iface_stats                  - module exit.
 *   cdx_ft_ifstats_fold, cdx_ifstats_read   - process, dev_get_stats().
 *   ifstats_sampler_run                     - process, system workqueue.
 *   cdx_ifstats_start, cdx_ifstats_stop     - process, module init/exit.
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
//flowtable-owned records published to a net device
static LIST_HEAD(published_slots);
/* Where the plain pool starts: past the timestamped records, in bytes from the
 * start of the carve. */
#define IFSTATS_PLAIN_OFFSET \
	(MAX_PPPoE_INTERFACES * sizeof(struct cdx_pppoe_iface_ifinfo))

/* The firmware counts packets in 32 bits and carries nothing out of them: the
 * word after the count is reserved in a plain record and padding in a
 * timestamped one. A count therefore comes round after 2^32 frames, under five
 * minutes of minimum-size frames at 10G, and a total built on the raw count
 * would step back by 2^32 there. So each record half keeps the count as it was
 * last read and the total that count has advanced by since the record was
 * handed out, each advance taken modulo 2^32. The total is exact as long as
 * the record is read at least once per wrap, which the sampler guarantees
 * whether or not anything reads the device's counters. One entry per record,
 * the timestamped pool first, in carve order; live while the record is handed
 * out. */
struct ifstats_wide_half {
	u32 raw;
	u64 packets;
};

struct ifstats_wide {
	bool live;
	struct ifstats_wide_half rx;
	struct ifstats_wide_half tx;
};

static struct ifstats_wide ifstats_wide[MAX_LOGICAL_INTERFACES];

/* Well inside the fastest wrap: 2^32 minimum-size frames take 289 s at 10G
 * line rate, so a record counting nine times that fast is still read before
 * its count can come round. */
#define IFSTATS_SAMPLE_PERIOD	(30 * HZ)
static void ifstats_sampler_run(struct work_struct *work);
static DECLARE_DELAYED_WORK(ifstats_sampler, ifstats_sampler_run);

extern void *FmMurambaseAddr;

/* Which record the carve holds at this address, as its entry in ifstats_wide,
 * or MAX_LOGICAL_INTERFACES for an address the carve does not hold -- which is
 * every address once the carve is gone. The pool is the record's position in
 * the carve rather than anything its holder says, so both owners' records are
 * found the same way. Caller holds dpa_statslist_lock. */
static unsigned int ifstats_record_index(const void *record)
{
	size_t offset, index;

	if (!stats_mem || !record)
		return MAX_LOGICAL_INTERFACES;
	offset = (const uint8_t *)record - (const uint8_t *)stats_mem;
	if (offset < IFSTATS_PLAIN_OFFSET)
		index = offset / sizeof(struct cdx_pppoe_iface_ifinfo);
	else
		index = MAX_PPPoE_INTERFACES + (offset - IFSTATS_PLAIN_OFFSET) /
			sizeof(struct cdx_iface_ifinfo);
	return min_t(size_t, index, MAX_LOGICAL_INTERFACES);
}

/* The total advanced by what the raw count moved since it was last read,
 * modulo 2^32: a count that came round in between moved by the same amount. */
static u64 ifstats_widen(struct ifstats_wide_half *half, u32 raw)
{
	half->packets += (u32)(raw - half->raw);
	half->raw = raw;
	return half->packets;
}

/* One record read and its packet counts advanced. The firmware writes these
 * fields big-endian, so the read is a be-to-cpu conversion. control_stat.c
 * spells the same conversion cpu_to_be32/64, which is the identical byte swap
 * under a name that says the opposite; it is not copied here, because a reader
 * of this path should be able to tell which way the value is travelling.
 * Caller holds dpa_statslist_lock, with the index one ifstats_record_index()
 * returned while the carve was present. */
static void ifstats_sample(unsigned int index, struct cdx_ft_stats *rx,
			   struct cdx_ft_stats *tx)
{
	struct ifstats_wide *wide = &ifstats_wide[index];
	u32 rx_raw, tx_raw;

	if (index < MAX_PPPoE_INTERFACES) {
		const struct cdx_pppoe_iface_ifinfo *record =
			(const struct cdx_pppoe_iface_ifinfo *)stats_mem + index;

		rx->bytes = be64_to_cpu(record->stats.rxstats.bytes);
		rx_raw = be32_to_cpu(record->stats.rxstats.pkts);
		tx->bytes = be64_to_cpu(record->stats.txstats.bytes);
		tx_raw = be32_to_cpu(record->stats.txstats.pkts);
	} else {
		const struct cdx_iface_ifinfo *record =
			(const struct cdx_iface_ifinfo *)((const uint8_t *)stats_mem +
							  IFSTATS_PLAIN_OFFSET) +
			(index - MAX_PPPoE_INTERFACES);

		rx->bytes = be64_to_cpu(record->stats.rxstats.bytes);
		rx_raw = be32_to_cpu(record->stats.rxstats.pkts);
		tx->bytes = be64_to_cpu(record->stats.txstats.bytes);
		tx_raw = be32_to_cpu(record->stats.txstats.pkts);
	}
	rx->packets = ifstats_widen(&wide->rx, rx_raw);
	tx->packets = ifstats_widen(&wide->tx, tx_raw);
}

/* A record handed out starts from the zero it was just cleared to, and one
 * returned is sampled no more; either way nothing counted under its previous
 * holder carries over to the next. Caller holds dpa_statslist_lock. */
static void ifstats_wide_claim(const void *record, bool live)
{
	unsigned int index = ifstats_record_index(record);

	if (index < MAX_LOGICAL_INTERFACES)
		ifstats_wide[index] = (struct ifstats_wide){ .live = live };
}

/* Free the stats MURAM carve and drop the freelists. Called from the
 * dpa_release_iflist deinit sweep, after every slot has been returned —
 * nothing may touch stats_mem-backed slots past this point. The carve is
 * withdrawn under the lock before it is returned, so the fold and the sampler,
 * which read it under that lock, find it present or find nothing. */
void cdx_deinit_iface_stats(void *muram_handle)
{
	void *carve;

	spin_lock(&dpa_statslist_lock);
	carve = stats_mem;
	stats_mem = NULL;
	stats_mem_phys = 0;
	ifstats_freelist = NULL;
	pppoe_ifstats_freelist = NULL;
	memset(ifstats_wide, 0, sizeof(ifstats_wide));
	spin_unlock(&dpa_statslist_lock);
	if (carve && muram_handle)
		FM_MURAM_FreeMem(muram_handle, carve);
}

/* allocate muram and create free lists */
int cdxdrv_init_stats(void *muram_handle)
{
	uint32_t ii;
	uint32_t num_log_ifaces;
	uint32_t size;
	struct cdx_pppoe_iface_ifinfo *pppoe_stats;
	struct cdx_iface_ifinfo *ifstats;
	void *mem;

	size = (MAX_PPPoE_INTERFACES * sizeof(struct cdx_pppoe_iface_ifinfo)) +
			((MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES) * sizeof(struct cdx_iface_ifinfo));
	mem = FM_MURAM_AllocMem(muram_handle, size, sizeof(uint64_t));
	if (!mem) {
		printk("%s::unable to allocate muram for iface stats, size %u\n", __func__, size );
		return -1;
	}
#ifdef IFSTATS_DEBUG
	printk("%s::ifstats mem base %p size %u\n", __func__, mem, size);
#endif
	spin_lock(&dpa_statslist_lock);
	stats_mem = mem;
	stats_mem_phys = (uint32_t)((uint8_t *)mem - (uint8_t *)FmMurambaseAddr);
	pppoe_ifstats_freelist = (struct cdx_pppoe_iface_ifinfo *)mem;
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
			ifstats_wide_claim(pppoe_stats, true);
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
			ifstats_wide_claim(ifstats, true);
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
			ifstats_wide_claim(pppoe_stats, false);
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
			ifstats_wide_claim(ifstats, false);
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
	INIT_LIST_HEAD(&slot->published);
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
			ifstats_wide_claim(record, true);
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
			ifstats_wide_claim(record, true);
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
	/* Withdrawn under the same lock the fold reads under, so a reader
	 * finds the slot published or finds nothing; never a freed one. */
	list_del_init(&slot->published);
	/* Deinit may already have dropped the carve and both lists, in which
	 * case there is no list to return this record to and nothing that
	 * could hand it out again. */
	ifstats_wide_claim(slot->record, false);
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

/* Zeroes for a record the carve does not hold, including every record once the
 * carve is gone. Both halves are advanced whichever the caller wants, since
 * either read is a sample. Caller holds dpa_statslist_lock. */
static void ifstats_read_locked(const void *record, struct cdx_ft_stats *rx,
				struct cdx_ft_stats *tx)
{
	unsigned int index = ifstats_record_index(record);

	*rx = (struct cdx_ft_stats){};
	*tx = (struct cdx_ft_stats){};
	if (index < MAX_LOGICAL_INTERFACES)
		ifstats_sample(index, rx, tx);
}

void cdx_ifstats_read(const void *record, struct cdx_ft_stats *rx,
		      struct cdx_ft_stats *tx)
{
	spin_lock(&dpa_statslist_lock);
	ifstats_read_locked(record, rx, tx);
	spin_unlock(&dpa_statslist_lock);
}

void cdx_ft_ifstats_read(const struct cdx_ft_stats_slot *slot,
			 struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
	struct cdx_ft_stats rx_read, tx_read;

	cdx_ifstats_read(slot ? slot->record : NULL, &rx_read, &tx_read);
	if (rx)
		*rx = rx_read;
	if (tx)
		*tx = tx_read;
}

void cdx_ft_ifstats_publish(struct cdx_ft_stats_slot *slot, int ifindex,
			    unsigned int rx_overhead, unsigned int tx_overhead)
{
	if (!slot)
		return;
	spin_lock(&dpa_statslist_lock);
	slot->ifindex = ifindex;
	slot->rx_overhead = rx_overhead;
	slot->tx_overhead = tx_overhead;
	/* One device per slot: a republication moves it rather than listing
	 * it twice, which would count the record twice into the new device. */
	list_move_tail(&slot->published, &published_slots);
	spin_unlock(&dpa_statslist_lock);
}

void cdx_ft_ifstats_unpublish(struct cdx_ft_stats_slot *slot)
{
	if (!slot)
		return;
	spin_lock(&dpa_statslist_lock);
	list_del_init(&slot->published);
	spin_unlock(&dpa_statslist_lock);
}

/* The framing the firmware counted and the device's own counter would not,
 * taken off per packet. Saturating: a minimum-size frame is padded on the
 * wire and the firmware counts the padding, so a stream of small frames can
 * carry less payload than the overhead says, and a wrapped difference would
 * report a byte count in the exabytes. */
static u64 ifstats_restated(u64 bytes, u64 packets, unsigned int overhead)
{
	u64 framing = packets * overhead;

	return bytes - min(bytes, framing);
}

void cdx_ifstats_fold(struct rtnl_link_stats64 *storage,
		      u64 rx_bytes, u64 rx_packets, u64 tx_bytes, u64 tx_packets,
		      unsigned int rx_overhead, unsigned int tx_overhead)
{
	storage->rx_packets += rx_packets;
	storage->rx_bytes += ifstats_restated(rx_bytes, rx_packets, rx_overhead);
	storage->tx_packets += tx_packets;
	storage->tx_bytes += ifstats_restated(tx_bytes, tx_packets, tx_overhead);
}

void cdx_ft_ifstats_fold(const struct net_device *dev, struct rtnl_link_stats64 *storage)
{
	struct cdx_ft_stats_slot *slot;
	struct cdx_ft_stats rx, tx;

	/* Indices are per namespace and every record here is init_net's. */
	if (!net_eq(dev_net(dev), &init_net))
		return;
	spin_lock(&dpa_statslist_lock);
	/* A record outliving the carve names memory the driver no longer owns;
	 * cdx_ft_ifstats_free() leaves such a slot published until the owner
	 * returns it, so the guard belongs here. */
	if (stats_mem)
		list_for_each_entry(slot, &published_slots, published) {
			if (slot->ifindex != dev->ifindex)
				continue;
			ifstats_read_locked(slot->record, &rx, &tx);
			cdx_ifstats_fold(storage, rx.bytes, rx.packets, tx.bytes,
					 tx.packets, slot->rx_overhead, slot->tx_overhead);
		}
	spin_unlock(&dpa_statslist_lock);
}

/* Every record handed out, read so that its count cannot come round twice
 * between two reads, then queued again. A period with no carve reads nothing
 * and still requeues: the carve comes and goes with the configuration, the
 * sampler with the module. */
static void ifstats_sampler_run(struct work_struct *work)
{
	struct cdx_ft_stats rx, tx;
	unsigned int ii;

	spin_lock(&dpa_statslist_lock);
	if (stats_mem)
		for (ii = 0; ii < MAX_LOGICAL_INTERFACES; ii++)
			if (ifstats_wide[ii].live)
				ifstats_sample(ii, &rx, &tx);
	spin_unlock(&dpa_statslist_lock);
	schedule_delayed_work(to_delayed_work(work), IFSTATS_SAMPLE_PERIOD);
}

void cdx_ifstats_start(void)
{
	schedule_delayed_work(&ifstats_sampler, IFSTATS_SAMPLE_PERIOD);
}

/* Returns with the sampler neither queued nor running, and unable to requeue
 * itself: cancel_delayed_work_sync() holds off the requeue of a run it waits
 * for. May sleep, so never under dpa_statslist_lock. */
void cdx_ifstats_stop(void)
{
	cancel_delayed_work_sync(&ifstats_sampler);
}
#endif


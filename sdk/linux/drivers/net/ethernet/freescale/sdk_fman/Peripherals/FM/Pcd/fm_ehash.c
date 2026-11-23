// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2018 NXP
 */

/*
 * @file                fm_ehash.c
 * @description         DPAA enhanced external hash functions
 */

#define __ERR_MODULE__ MODULE_FM_PCD

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include "fm_common.h"
#include "fm_muram_ext.h"
#include "fm_ehash.h"
#include "fm_pcd.h"
#include "fm_cc.h"
#include "endian_ext.h"

/* FM_EHASH_DEBUG was a commented-out toggle gating printk dumps that had
 * bit-rotted (they no longer compiled when enabled). The dumps are removed;
 * FM_EHASH_PRINT is now an unconditional no-op so its call sites stay valid. */
#define FM_EHASH_PRINT(fmt, ...)


extern void *FmMurambaseAddr;
en_exthash_global_mem *en_global_muram_mem = NULL;

extern void get_indexed_hash_bucket(uint8_t key_size,  uint8_t *key_ptr,
	        uint8_t crc_shift, uint16_t mask, uint16_t *bucket_index);

#ifdef CONFIG_FSL_SDK_FMAN_EHASH_SYNC_FAULT
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

/* Test-only fault injection. /proc/fm_ehash_hcsync_fail arms a countdown
 * of DeleteKey-internal HC syncs to report failure without touching
 * hardware, so the unlinked-but-unsynced (EN_EHASH_DELETE_UNSYNCED)
 * paths and the caller-side quarantine handling can be driven
 * deterministically from a rig test. Scoped to the syncs
 * ExternalHashTableDeleteKey issues itself, and to
 * ExternalHashTableDeleteSync(), which issues the same sync for unlinks that
 * deferred it (ExternalHashTableUnlinkKey()) - the standalone
 * ExternalHashTableFmPcdHcSync() barrier is deliberately NOT covered, so
 * a quarantine reclaim drain keeps working while the knob is armed.
 * Compiled out unless the ASK test image's config fragment enables it. */
static atomic_t ehash_hcsync_fail_countdown = ATOMIC_INIT(0);
static struct proc_dir_entry *ehash_hcsync_fail_proc;

static int ehash_hcsync_fail_show(struct seq_file *m, void *v)
{
	seq_printf(m, "armed=%d\n", atomic_read(&ehash_hcsync_fail_countdown));
	return 0;
}

static int ehash_hcsync_fail_open(struct inode *inode, struct file *file)
{
	return single_open(file, ehash_hcsync_fail_show, NULL);
}

static ssize_t ehash_hcsync_fail_write(struct file *file,
		const char __user *buf, size_t len, loff_t *ppos)
{
	char kbuf[16];
	unsigned int n;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	if (kstrtouint(strim(kbuf), 10, &n))
		return -EINVAL;
	if (n > (unsigned int)INT_MAX)
		return -EINVAL;
	atomic_set(&ehash_hcsync_fail_countdown, (int)n);
	return len;
}

static const struct proc_ops ehash_hcsync_fail_proc_ops = {
	.proc_open    = ehash_hcsync_fail_open,
	.proc_read    = seq_read,
	.proc_write   = ehash_hcsync_fail_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* Lazily registered from ExternalHashTableSet, which any caller of the
 * exported FM_PCD_HashTableSet reaches; the mutex makes the
 * check-then-create race-free. sdk_fman is built-in and never unloads,
 * so there is no removal path. */
static DEFINE_MUTEX(ehash_hcsync_fail_proc_lock);

static void ehash_hcsync_fault_proc_init(void)
{
	mutex_lock(&ehash_hcsync_fail_proc_lock);
	if (!ehash_hcsync_fail_proc) {
		pr_warn_once("fm_ehash: CONFIG_FSL_SDK_FMAN_EHASH_SYNC_FAULT is on - /proc/fm_ehash_hcsync_fail can force DeleteKey sync failures; do not ship\n");
		ehash_hcsync_fail_proc = proc_create("fm_ehash_hcsync_fail", 0600,
						     NULL, &ehash_hcsync_fail_proc_ops);
		if (!ehash_hcsync_fail_proc)
			pr_err("fm_ehash: hcsync fault knob proc_create failed; injection unavailable\n");
	}
	mutex_unlock(&ehash_hcsync_fail_proc_lock);
}

static int ehash_delete_hcsync(struct en_exthash_info *info)
{
	/* atomic_dec_if_positive() returns the post-decrement value, so
	 * >= 0 means a fail credit was consumed. */
	if (atomic_dec_if_positive(&ehash_hcsync_fail_countdown) >= 0) {
		printk("%s::injected DeleteKey HC-sync failure, %d left armed\n",
		       __func__, atomic_read(&ehash_hcsync_fail_countdown));
		return -1;
	}
	return FmPcdHcSync(info->pcd);
}
#else
static inline void ehash_hcsync_fault_proc_init(void) {}

static inline int ehash_delete_hcsync(struct en_exthash_info *info)
{
	return FmPcdHcSync(info->pcd);
}
#endif /* CONFIG_FSL_SDK_FMAN_EHASH_SYNC_FAULT */

static inline struct en_exthash_tbl_entry *find_entry_in_bucket(struct en_exthash_tbl_entry *entry,
		uint8_t *key, uint32_t size)
{
	struct en_cumulative_tbl_entry *cumulative_tbl_node = (struct en_cumulative_tbl_entry *)entry;
	struct en_cumulative_entry *cumulative_node;
	int ii;
	if (!entry)
		return NULL;
	cumulative_node = &cumulative_tbl_node->cumulative_entry;
	if (cumulative_node->flags & EN_CUMULATIVE_NODE)
	{
		while (cumulative_node)
		{
			for(ii=0; ii<cumulative_node->num_key_entries; ii++)
				if (memcmp(key, &cumulative_node->data[ii*cumulative_node->key_size], size) == 0)
					return entry;
			if (cumulative_tbl_node->next_entry)
			{
				cumulative_tbl_node = cumulative_tbl_node->next_entry;
				cumulative_node = &cumulative_tbl_node->cumulative_entry;
			}
			else
				cumulative_node = NULL;
		}
	}
	else if(memcmp(key, &entry->hashentry.key[0], size) == 0)
		return entry;
	return NULL;
}

/* The most keys one bucket chains. The bucket index is an unkeyed CRC the
 * FMan computes, so keys that share a bucket can be chosen offline, and every
 * add and delete walks the whole chain with interrupts off. Uniform keys put
 * a handful in a bucket at the table's full load; past this bound an add is
 * refused (EHASH_ADD_BUCKET_FULL) and the flow stays in software. */
#define EHASH_BUCKET_KEYS_MAX	32

/* The keys a bucket's chain holds, the first entry included. */
static unsigned int ehash_bucket_keys(struct en_exthash_tbl_entry *entry)
{
	struct en_cumulative_tbl_entry *node = (struct en_cumulative_tbl_entry *)entry;
	unsigned int keys = 0;

	if (!entry)
		return 0;
	if (!(node->cumulative_entry.flags & EN_CUMULATIVE_NODE))
		return 1;
	for (; node; node = node->next_entry)
		keys += node->cumulative_entry.num_key_entries;
	return keys;
}

/* The table entry slot ii of a cumulative node links, as the microcode reads
 * it: a big-endian address after the node's keys. */
static inline struct en_exthash_tbl_entry *ehash_node_entry(struct en_cumulative_entry *node,
							    unsigned int ii)
{
	uint64_t phyaddr;

	phyaddr = *((uint64_t *)(&node->data[node->tbl_entry_index - EN_CU_FIXED_ELEMENTS_SIZE +
					     ii * EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE]));
	return XX_PhysToVirt(SwapUint64(phyaddr));
}

void *ExternalHashTableAllocEntry(t_Handle h_HashTbl) 
{
	void *entry;
	struct en_exthash_info *info;
	
	entry = NULL;
	info = (struct en_exthash_info *)h_HashTbl;
	if (info) {
		//allocate new entry
		entry = XX_MallocSmart(sizeof(struct en_exthash_tbl_entry),
                        0 /*info->dataMemId not used */, EN_EHASH_ENTRY_ALIGN);
		if (entry) 
			memset(entry, 0, sizeof(struct en_exthash_tbl_entry));
		else {
        		REPORT_ERROR(MAJOR, E_NO_MEMORY,
                		     ("en_ext_hash_entry"));
		}
	}
	return entry;
}
EXPORT_SYMBOL(ExternalHashTableAllocEntry); 

void ExternalHashTableEntryFree(void *entry)
{
	XX_FreeSmart(entry);
}
EXPORT_SYMBOL(ExternalHashTableEntryFree); 

void *ExternalHashTableAllocCumulativeEntry(t_Handle h_HashTbl)
{
	void *entry;

	entry = XX_MallocSmart(sizeof(struct en_cumulative_tbl_entry), 0 /*info->dataMemId not used */, EN_EHASH_ENTRY_ALIGN);
	if (entry)
	        memset(entry, 0, sizeof(struct en_cumulative_tbl_entry));
	else
	{
	        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("en_cumulative_entry"));
	}
	return entry;
}
void ExternalHashTableCumulativeEntryFree(void *entry)
{
	XX_FreeSmart(entry);
}

/* The table's spare, if it holds one. A released node keeps whatever its
 * chain or the parked list last wrote into it, so it is zeroed like a new one:
 * the rebuild that links it sets only the links its neighbours need. */
static struct en_cumulative_tbl_entry *ehash_node_take_spare(struct en_exthash_info *info)
{
	struct en_cumulative_tbl_entry *node = xchg(&info->spare, NULL);

	if (node)
		memset(node, 0, sizeof(*node));
	return node;
}

/* The replacement cumulative node a delete needs when it rebuilds a crowded
 * bucket's node without the key. The allocator is atomic and can fail under
 * memory pressure, and a delete that fails for want of the node leaves the
 * key linked: the caller then has to abandon the entry, which CDX treats as
 * terminal. So a delete that finds, under the bucket lock, that it needs one
 * drops the lock without changing anything, takes one here -- from the
 * allocator or, when that fails, from the table's spare -- and starts over
 * (ExternalHashTableDeleteKey()).
 *
 * The spare is refilled by the first node released on the table after it was
 * taken (ehash_node_release()): every node a completed barrier proves
 * unreachable -- the one a rebuild replaced, the ones a shrinking chain
 * dropped, and the parked ones, which go back to the table they were parked
 * from whichever table the barrier was issued through -- and a node a delete
 * took but did not link. A rebuild that took
 * the spare releases the node it replaced once its barrier completes, so the
 * spare is back before the next delete however long the allocator keeps
 * failing, as long as the barriers complete. The add path never takes it: a
 * failed add links nothing, so its allocations may fail. */
static struct en_cumulative_tbl_entry *ehash_node_alloc(struct en_exthash_info *info)
{
	struct en_cumulative_tbl_entry *node;

	node = XX_MallocSmart(sizeof(*node), 0 /*info->dataMemId not used */,
			      EN_EHASH_ENTRY_ALIGN);
	if (node) {
		memset(node, 0, sizeof(*node));
		return node;
	}
	return ehash_node_take_spare(info);
}

/* A cumulative node nothing can reach any more: one a completed barrier proved
 * the microcode has left, or one never linked. It refills the table's spare if
 * that is empty, and goes back to the allocator otherwise. */
static void ehash_node_release(struct en_exthash_info *info,
			       struct en_cumulative_tbl_entry *node)
{
	if (node && cmpxchg(&info->spare, NULL, node))
		ExternalHashTableCumulativeEntryFree(node);
}

/* Cumulative nodes an add or a delete took out of a bucket's chain when the
 * sync that would prove the microcode had left them failed. Such a node can
 * be neither freed -- a walker that entered before the splice may still be
 * reading it -- nor spliced out again, so it is parked here and released by
 * the next sync on the PCD that completes, the same way callers park the
 * table entry a failed delete hands back to them.
 *
 * Linked through next_entry, which only software reads: the microcode follows
 * cumulative_entry.next_entry_addr, and nothing in software reaches a node
 * once it is out of its chain. Its prev_entry is dead for the same reason and
 * names its table instead (parked_on), whose spare it refills: a delete that
 * defers its barrier leaves nodes from many tables behind one barrier.
 * Parking therefore allocates nothing on a path that has just failed.
 *
 * One sync proves every unlink before it only because every table lives on
 * one PCD, as on LS1046A. A node from a second PCD would need a list of its
 * own; none is expected, so one is refused loudly and leaked rather than
 * freed on the strength of a barrier that proves nothing about it.
 */
static DEFINE_SPINLOCK(ehash_parked_lock);
static struct en_cumulative_tbl_entry *ehash_parked;
static void *ehash_parked_pcd;
/* Barriers failed since one last completed, also under ehash_parked_lock.
 * CDX retries a barrier once a second while one is owed, so a run of
 * failures reports its first only, and the barrier that ends it says how
 * many there were: a new run always reports again. */
static unsigned int ehash_barrier_failures;

/* The nodes a barrier took off the parked list, while its sync runs, and the
 * PCD they were parked for. They are still parked as far as a table delete is
 * concerned (ehash_unpark_table()) and as far as the one-PCD rule is: each
 * in-flight batch stays reachable under ehash_parked_lock until it is
 * released or parked again. */
struct ehash_batch {
	struct en_cumulative_tbl_entry *nodes;
	void *pcd;
	struct ehash_batch *next;
};
static struct ehash_batch *ehash_inflight;

static void ehash_park_node(struct en_exthash_info *info,
			    struct en_cumulative_tbl_entry *node)
{
	struct ehash_batch *batch;
	unsigned long flags;
	bool foreign;

	if (!node)
		return;
	spin_lock_irqsave(&ehash_parked_lock, flags);
	foreign = ehash_parked && ehash_parked_pcd != info->pcd;
	for (batch = ehash_inflight; batch; batch = batch->next)
		foreign |= batch->nodes && batch->pcd != info->pcd;
	if (foreign) {
		spin_unlock_irqrestore(&ehash_parked_lock, flags);
		WARN_ONCE(1, "fm_ehash: a second PCD's node cannot share the parked list, leaking %p\n",
			  node);
		return;
	}
	ehash_parked_pcd = info->pcd;
	node->parked_on = info;
	node->next_entry = ehash_parked;
	ehash_parked = node;
	spin_unlock_irqrestore(&ehash_parked_lock, flags);
}

/* A sync on this table's PCD. What was parked before it is issued is freed
 * if it completes and parked again if it does not; a node parked while it
 * runs was unlinked too late to be proven by it, and waits for the next.
 * delete_barrier routes the sync through the DeleteKey fault knob.
 *
 * The release reads each node's table and refills that table's spare, so it
 * runs under ehash_parked_lock: a table deleted meanwhile has already had its
 * nodes, in-flight ones included, turned over to the allocator, and one being
 * deleted waits for the release to finish. Releasing allocates nothing and
 * frees with kfree, so the lock covers it. */
static int ehash_barrier(struct en_exthash_info *info, bool delete_barrier)
{
	struct ehash_batch batch = { NULL, info->pcd, NULL }, **link;
	struct en_cumulative_tbl_entry *node;
	unsigned long flags;
	unsigned int failures;
	bool reparked = false;
	int rc;

	spin_lock_irqsave(&ehash_parked_lock, flags);
	if (ehash_parked_pcd == info->pcd) {
		batch.nodes = ehash_parked;
		ehash_parked = NULL;
	}
	batch.next = ehash_inflight;
	ehash_inflight = &batch;
	spin_unlock_irqrestore(&ehash_parked_lock, flags);
	rc = delete_barrier ? ehash_delete_hcsync(info) : FmPcdHcSync(info->pcd);
	spin_lock_irqsave(&ehash_parked_lock, flags);
	for (link = &ehash_inflight; *link != &batch; link = &(*link)->next)
		;
	*link = batch.next;
	failures = ehash_barrier_failures;
	ehash_barrier_failures = rc ? failures + 1 : 0;
	while (batch.nodes) {
		node = batch.nodes;
		batch.nodes = node->next_entry;
		if (rc) {
			/* Back where they were, already accepted for this PCD:
			 * parking refused another's while they were away. */
			node->next_entry = ehash_parked;
			ehash_parked = node;
			reparked = true;
		} else if (node->parked_on) {
			ehash_node_release(node->parked_on, node);
		} else {
			ExternalHashTableCumulativeEntryFree(node);
		}
	}
	if (reparked)
		ehash_parked_pcd = info->pcd;
	spin_unlock_irqrestore(&ehash_parked_lock, flags);
	if (rc && !failures)
		pr_err("fm_ehash: FmPcdHcSync failed; unlinked storage stays parked until one completes\n");
	if (!rc && failures)
		pr_info("fm_ehash: FmPcdHcSync completed after %u failed\n", failures);
	return rc;
}

/* Before @info is freed: its parked nodes go back to the allocator, not to
 * its spare, when a barrier proves them -- those a barrier in flight holds
 * too, which its release then frees rather than handing to a table that is
 * gone. */
static void ehash_unpark_table(struct en_exthash_info *info)
{
	struct en_cumulative_tbl_entry *node;
	struct ehash_batch *batch;
	unsigned long flags;

	spin_lock_irqsave(&ehash_parked_lock, flags);
	for (node = ehash_parked; node; node = node->next_entry)
		if (node->parked_on == info)
			node->parked_on = NULL;
	for (batch = ehash_inflight; batch; batch = batch->next)
		for (node = batch->nodes; node; node = node->next_entry)
			if (node->parked_on == info)
				node->parked_on = NULL;
	spin_unlock_irqrestore(&ehash_parked_lock, flags);
}



#define MAX_HIST_SIZE	15

int ExternalHashTableEntryGetStatsAndTS(void *tbl_entry,
				struct en_tbl_entry_stats *stats)
{
	struct en_exthash_tbl_entry *hash_node;
	struct en_ehash_entry *entry;
//	uint32_t val;
	uint16_t flags;

	hash_node = (struct en_exthash_tbl_entry *)tbl_entry;
	if(!hash_node)
		return -1;
	entry = &hash_node->hashentry;
	flags = cpu_to_be16(entry->flags);
	stats->flags = 0;
        if (GET_TIMESTAMP_ENABLE(flags)) {
		stats->flags |= TIMESTAMP_VALID;
		stats->timestamp = cpu_to_be32(entry->timestamp);
        }
	if (GET_STATS_ENABLE(flags))
	{
		stats->flags |= STATS_VALID;
		stats->pkts = be64_to_cpu(entry->packet_count);
		stats->bytes = be64_to_cpu(entry->packet_bytes);
	}
	return 0;
}
EXPORT_SYMBOL(ExternalHashTableEntryGetStatsAndTS);

/* The FMan walks these tables coherently, but nothing orders its reads
 * against the CPU's stores: a table entry or cumulative node filled just
 * before the store that links it -- the bucket head, or the previous node's
 * next_entry_addr -- could be seen linked before its contents are. The add
 * and the delete therefore issue dma_wmb() before every store that links
 * memory written just before it, the caller's table entry included. A store
 * that links something the FMan could already reach needs none, except the
 * one unlink that clears a node's next-node flag and then its address: the
 * two are ordered the same way, so the FMan never follows a cleared
 * address. */
int ExternalHashTableAddKey(void *h_HashTbl, uint8_t keySize,
                                      struct en_exthash_tbl_entry *tbl_entry)
{
	struct en_exthash_info *info;
	struct en_exthash_tbl_entry *first_entry;
	struct en_exthash_tbl_entry *new_entry;
	uint16_t index;
	struct en_exthash_bucket *bucket;
	t_Handle h_Spinlock;
	uint32_t intFlags;
	int retval;
	uint64_t phyaddr;
	uint8_t key_align, flags;
//	uint32_t ii;
	struct en_cumulative_entry *cumulative_entry, *tmp;
	struct en_cumulative_tbl_entry *tmp_tbl_entry, *cumulative_tbl_entry;
	uint64_t bucket_phyaddr;

	SANITY_CHECK_RETURN_ERROR(h_HashTbl, E_INVALID_HANDLE);
    	SANITY_CHECK_RETURN_ERROR(tbl_entry, E_NULL_POINTER);

	new_entry = (struct en_exthash_tbl_entry *)tbl_entry;
	info = (struct en_exthash_info *)h_HashTbl;
	get_indexed_hash_bucket(keySize, &new_entry->hashentry.key[0],
                                info->hashshift,
                                (uint16_t)info->hashmask, &index);
	bucket = ((struct en_exthash_bucket *)(info->table_base) + index);

	h_Spinlock = &info->bucket_lock[index];
   	intFlags = XX_LockIntrSpinlock(h_Spinlock);

	retval = index;
	phyaddr = bucket->h;
	/* key should be aligned to  8 byte boundary if size > 4*/
	if (keySize <= 2)
		key_align =  keySize;
	else if (keySize <= 4)
		key_align =  4;
	else
		key_align =  (keySize + 7) & 0x38;

	FM_EHASH_PRINT("%s(%d) tbl_entry %p, key size %d, key-align %d\n",
		__func__,__LINE__,tbl_entry, keySize, key_align);
	key_align -= keySize;

	// if no nodes in bucket, just add the node as it is
	if (!phyaddr)
	{
		new_entry->next =  NULL;
		//change the head pointer in the bucket
		phyaddr = XX_VirtToPhys(new_entry);
		dma_wmb();
		bucket->h = SwapUint64(phyaddr);
	}
	else
	{
		FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
		first_entry = XX_PhysToVirt(SwapUint64(phyaddr));
		if (find_entry_in_bucket(first_entry, &new_entry->hashentry.key[0],
				keySize)) {
        		REPORT_ERROR(MAJOR, E_ALREADY_EXISTS,
                	     ("en_ext_hash_entry"));
			retval = -1;
			goto func_ret;
		}
		/* Refused without a report: a sender that chose colliding keys
		 * reaches this at the rate it offers flows. */
		if (ehash_bucket_keys(first_entry) >= EHASH_BUCKET_KEYS_MAX) {
			retval = EHASH_ADD_BUCKET_FULL;
			goto func_ret;
		}
		FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
		// check if node is cumulative or not
		// if not cumulative, allocate cumulative node 
		// add the existing node and the current node to the cumulative node
		cumulative_tbl_entry = XX_PhysToVirt(SwapUint64(phyaddr));
		cumulative_entry = &cumulative_tbl_entry->cumulative_entry;
		FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
		if (cumulative_entry->flags & EN_CUMULATIVE_NODE)
		{
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
			if (((cumulative_entry->key_size+EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE) * 
				    (cumulative_entry->num_key_entries+1) + EN_CU_FIXED_ELEMENTS_SIZE) <= EN_CUMULATIVE_NODE_MAX_SIZE)
			{
				tmp_tbl_entry = ExternalHashTableAllocCumulativeEntry (h_HashTbl);
				if (!tmp_tbl_entry)
				{
					REPORT_ERROR(MAJOR, E_NO_MEMORY,
								 ("en_cumulative_entry"));
					retval = -1;
					goto func_ret;
				}
				FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
				tmp = &tmp_tbl_entry->cumulative_entry;
				tmp->flags = cumulative_entry->flags; 
				tmp->key_size =  cumulative_entry->key_size;
				tmp->next_entry_addr = cumulative_entry->next_entry_addr;
				tmp->num_key_entries = cumulative_entry->num_key_entries+1;
				tmp->tbl_entry_index = cumulative_entry->tbl_entry_index + cumulative_entry->key_size;
				memcpy(tmp->data, new_entry->hashentry.key, keySize);
				memset(tmp->data+keySize, 0, key_align);
				memcpy(tmp->data+keySize+key_align, cumulative_entry->data,
							1+cumulative_entry->num_key_entries*cumulative_entry->key_size);
				phyaddr = XX_VirtToPhys(new_entry);
				phyaddr = SwapUint64(phyaddr);
				memcpy(tmp->data+(cumulative_entry->num_key_entries+1)*cumulative_entry->key_size+1, &phyaddr,
					EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE);
				memcpy(tmp->data+(cumulative_entry->num_key_entries+1)*cumulative_entry->key_size+1+EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE, 
					cumulative_entry->data+1+cumulative_entry->num_key_entries*cumulative_entry->key_size, 
					8*cumulative_entry->num_key_entries);
				tmp_tbl_entry->next_entry = cumulative_tbl_entry->next_entry;
				if (cumulative_tbl_entry->next_entry)
					cumulative_tbl_entry->next_entry->prev_entry = tmp_tbl_entry;
				// initiate host command
				FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
				dma_wmb();
				if (cumulative_tbl_entry->prev_entry)
				{
					phyaddr =  XX_VirtToPhys(tmp_tbl_entry);
					phyaddr =  SwapUint64(phyaddr);
					cumulative_tbl_entry->prev_entry->cumulative_entry.next_entry_addr =  phyaddr;
					cumulative_tbl_entry->prev_entry->next_entry = tmp_tbl_entry;
					tmp_tbl_entry->prev_entry =  cumulative_tbl_entry->prev_entry;
				}
				phyaddr =  XX_VirtToPhys(cumulative_tbl_entry);
				phyaddr =  SwapUint64(phyaddr);
				bucket_phyaddr = bucket->h;
				if (bucket_phyaddr == phyaddr)
				{
					phyaddr =  XX_VirtToPhys(tmp_tbl_entry);
					phyaddr =  SwapUint64(phyaddr);
					bucket->h = phyaddr;
				}
				flags = cumulative_entry->flags;
				flags = flags | EN_INVALID_CUMULATIVE_NODE;
				cumulative_entry->flags = flags;
				info = (struct en_exthash_info *)h_HashTbl;
				XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
				if (ehash_barrier(info, false)) {
					/* The replacement cumulative node - with the
					 * caller's entry inside it - is already
					 * published, so the add stands regardless of
					 * the barrier: report success (the bucket
					 * index), or the caller would free an entry
					 * the ucode can reach. Only the REPLACED
					 * node's free needed the barrier; it waits
					 * for the next one, the same discipline as
					 * the DeleteKey sync-failure arms. */
					ehash_park_node(info, cumulative_tbl_entry);
					return retval;
				}
				ehash_node_release(info, cumulative_tbl_entry);
				return retval;
			}
			else
			{
				FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
				tmp_tbl_entry = ExternalHashTableAllocCumulativeEntry (h_HashTbl);
				if (!tmp_tbl_entry)
				{
					REPORT_ERROR(MAJOR, E_NO_MEMORY,
								 ("en_cumulative_entry"));
					retval = -1;
					goto func_ret;
				}
				tmp = &tmp_tbl_entry->cumulative_entry;
				phyaddr = XX_VirtToPhys(cumulative_tbl_entry);
				tmp->flags = EN_NEXT_CUMULATIVE_NODE | EN_CUMULATIVE_NODE;
				tmp->next_entry_addr = SwapUint64(phyaddr);
				tmp_tbl_entry->next_entry =  cumulative_tbl_entry;
				cumulative_tbl_entry->prev_entry =  tmp_tbl_entry;
				cumulative_entry = tmp;
				cumulative_entry->key_size = keySize+key_align;
				cumulative_entry->num_key_entries = 1;
				memcpy(cumulative_entry->data, new_entry->hashentry.key, keySize);
				memset(cumulative_entry->data+keySize, 0, key_align);
				cumulative_entry->data[keySize+key_align] = 0;
				cumulative_entry->tbl_entry_index =  EN_CU_FIXED_ELEMENTS_SIZE+1+cumulative_entry->num_key_entries*cumulative_entry->key_size;
				phyaddr = XX_VirtToPhys(new_entry);
				phyaddr = SwapUint64(phyaddr);
				memcpy(&cumulative_entry->data[cumulative_entry->key_size+1], &phyaddr, EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE);
				
				//change the head pointer in the bucket
				phyaddr = XX_VirtToPhys(tmp_tbl_entry);
				dma_wmb();
				bucket->h = SwapUint64(phyaddr);
			}
		}
		else
		{
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
			cumulative_tbl_entry = ExternalHashTableAllocCumulativeEntry (h_HashTbl);
			if (!cumulative_tbl_entry)
			{
				REPORT_ERROR(MAJOR, E_NO_MEMORY,
							 ("en_cumulative_entry"));
				retval = -1;
				goto func_ret;

			}
			cumulative_entry = &cumulative_tbl_entry->cumulative_entry;
			cumulative_entry->flags = EN_CUMULATIVE_NODE;
			cumulative_entry->key_size = keySize+key_align;
			cumulative_entry->num_key_entries = 2;
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
			memcpy(cumulative_entry->data, new_entry->hashentry.key, keySize);
			memset(cumulative_entry->data+keySize, 0, key_align);
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
			memcpy(cumulative_entry->data+keySize+key_align, first_entry->hashentry.key, keySize);
			memset(cumulative_entry->data+2*keySize+key_align, 0, key_align);
			cumulative_entry->data[2*(keySize+key_align)] = 0;
			cumulative_entry->tbl_entry_index =  EN_CU_FIXED_ELEMENTS_SIZE+1+cumulative_entry->num_key_entries*(keySize+key_align);
			phyaddr = XX_VirtToPhys(new_entry);
			phyaddr = SwapUint64(phyaddr);
			*((uint64_t *)(cumulative_entry->data+2*(keySize+key_align)+1)) = phyaddr;
			phyaddr = XX_VirtToPhys(first_entry);
			phyaddr = SwapUint64(phyaddr);
			*((uint64_t *)(cumulative_entry->data+2*(keySize+key_align)+1+EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE)) = phyaddr;
			//change the head pointer in the bucket
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
			phyaddr = XX_VirtToPhys(cumulative_tbl_entry);
			dma_wmb();
			bucket->h = SwapUint64(phyaddr);
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
		}
		
	}	
func_ret:
    	XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
	return retval;	
}
EXPORT_SYMBOL(ExternalHashTableAddKey); 

static void FreeEnEhashInfo(t_Handle handle)
{
	struct en_exthash_info *info;

	info = (struct en_exthash_info *)handle;
	if (info) {
		kvfree(info->bucket_lock);
		if (info->table_base)
			free_pages_exact(info->table_base, info->tablesize);
		if (info->spare)
			ExternalHashTableCumulativeEntryFree(info->spare);
		kfree(info);
	}
}

t_Error FM_PCD_HashTableDelete(t_Handle h_HashTbl)
{
	struct en_exthash_info *info = h_HashTbl;
	struct en_exthash_bucket *buckets;
	uint32_t i;

	might_sleep();
	SANITY_CHECK_RETURN_ERROR(info, E_INVALID_HANDLE);
	/* Root deletion follows port detachment. Keep tables alive while a
	 * root or a flow can still reach them. */
	if (info->tree_owners || info->num_keys)
		RETURN_ERROR(MINOR, E_BUSY, ("external hash table is in use"));
	buckets = info->table_base;
	for (i = 0; i <= info->hashmask; i++)
		if (READ_ONCE(buckets[i].h))
			RETURN_ERROR(MINOR, E_BUSY, ("external hash bucket is in use"));

	/* A node parked from this table outlives it, waiting for a barrier;
	 * it must not refill a spare that is gone. */
	ehash_unpark_table(info);
	FreeEnEhashInfo(info);
	return E_OK;
}

t_Handle ExternalHashTableSet(t_Handle h_FmPcd, t_FmPcdHashTableParams *p_Param)
{
	struct en_exthash_info *info;
	t_Handle h_FmMuram;
	uint32_t ii;
	uint8_t num_of_zeroes = 0;
	struct en_exthash_node *node;
	uint64_t tblphysaddr;
	t_FmPcd *p_FmPcd = (t_FmPcd*)h_FmPcd;
	uint32_t table_type;

	might_sleep();
	/* Reject reserved reassembly types before touching PCD state or parameters. */
	if ((p_Param->table_type & TABLE_TYPE_MASK) == IPV4_REASSM_TABLE ||
	    (p_Param->table_type & TABLE_TYPE_MASK) == IPV6_REASSM_TABLE) {
		REPORT_ERROR(MAJOR, E_NOT_SUPPORTED, ("Hardware reassembly is unsupported in Mono"));
		return NULL;
	}
	ehash_hcsync_fault_proc_init();
	p_Param->table_type &= TABLE_TYPE_MASK;
	switch (p_Param->table_type) {
		case IPV4_UDP_TABLE:
		case IPV4_TCP_TABLE:
		case ESP_IPV4_TABLE:
		case IPV6_UDP_TABLE:
		case IPV6_TCP_TABLE:
		case ESP_IPV6_TABLE:
		case IPV4_3TUPLE_UDP_TABLE:
		case IPV4_3TUPLE_TCP_TABLE:
		case IPV6_3TUPLE_UDP_TABLE:
		case IPV6_3TUPLE_TCP_TABLE:
			table_type = L4_TABLE;
			break;

		case IPV4_MULTICAST_TABLE:
		case IPV6_MULTICAST_TABLE:
			table_type = L3_TABLE;
			break;
		default:
			table_type = L2_TABLE;
			break;

	}
	//allocate table info structure
	info = kzalloc(sizeof(struct en_exthash_info), GFP_KERNEL);
	if (!info) {
        	REPORT_ERROR(MAJOR, E_NO_MEMORY,
                	     ("allocation for en_ext_hash_info"));
        	return NULL;
	}
	memset(info, 0, sizeof(struct en_exthash_info));
		
	//determine number of bits set in the hash mask
	ii = p_Param->hashResMask;
        __asm__ ("clz %0,%1\n"
                        : "=r"(num_of_zeroes)
                        : "r"(ii));
	h_FmMuram = FmPcdGetMuramHandle(h_FmPcd);
    	if (!h_FmMuram) {
        	REPORT_ERROR(MAJOR, E_INVALID_HANDLE,
                	     ("muram"));
		goto err_ret;
	}
	info->hashmask = p_Param->hashResMask;
	info->pcd = h_FmPcd;
	info->type = p_Param->table_type;
	/* Spin locks are required for tables filled by GPP: one per bucket,
	 * in a single array, so that neither creating nor deleting a table
	 * costs an allocation per bucket. */
	info->bucket_lock = kvcalloc(info->hashmask + 1, sizeof(*info->bucket_lock),
				     GFP_KERNEL);
	if (!info->bucket_lock) {
		REPORT_ERROR(MAJOR, E_NO_MEMORY,
			("spin lock array"));
		goto err_ret;
	}
	for (ii = 0; ii <= info->hashmask; ii++)
		spin_lock_init(&info->bucket_lock[ii]);

	/* The FMan reads the buckets by DMA at their physical address, so
	 * they are physically contiguous; page alignment covers
	 * EN_EXTHASH_TBL_ALIGNMENT. */
	BUILD_BUG_ON(EN_EXTHASH_TBL_ALIGNMENT > PAGE_SIZE);
	info->tablesize = (sizeof(struct en_exthash_bucket) << (64 - num_of_zeroes) );
	info->table_base = alloc_pages_exact(info->tablesize, GFP_KERNEL | __GFP_ZERO);
    	if (!info->table_base)
    	{
        	REPORT_ERROR(MAJOR, E_NO_MEMORY,
                	     ("en_ext_hash_table"));
		goto err_ret;
    	}
	/* The node a delete falls back on when the allocator fails it
	 * (ehash_node_alloc()). */
	info->spare = ExternalHashTableAllocCumulativeEntry(info);
	if (!info->spare)
		goto err_ret;
	info->keysize = p_Param->matchKeySize;
        info->hashshift = p_Param->hashShift;
	/* Flow timestamps are always on: the cdx fast path reads them. */
	info->flags |= TIMESTAMP_EN;
	if (p_Param->statisticsMode)
		info->flags |= STATS_EN;
	//fill AD
	node = &info->node;
	memset(node, 0, sizeof(struct en_exthash_node));
	node->key_size = info->keysize;		
	node->hash_bytes_offset = info->hashshift;	
	/* convert the hash mask value to hash mask bits */
	if (info->hashmask > 0x7fff)
	{
		REPORT_ERROR(MAJOR, E_INVALID_VALUE, 
			("unsupported hash mask value"));
		goto err_ret;
	}
	for (ii =0; ii <15; ii++)
	{
		if ((info->hashmask + 1) & (1 << ii))
			break;
	}

	if ((1 << ii) != (info->hashmask +1))
	{
		REPORT_ERROR(MAJOR, E_INVALID_VALUE, 
			("unsupported hash mask value"));
		goto err_ret;
	}
	node->hash_mask_bits = ii;
	node->int_buf_pool_addr = p_FmPcd->InternalBufMgmtMuramArea;
	node->global_mem_offset = EN_INTERNAL_BUFF_POOL_SIZE >> 8; /* value compressed */
	/* assign the MURAM reserved space of global params/stats to global muram pointer */
	if (!en_global_muram_mem)
	{
		en_global_muram_mem = (en_exthash_global_mem *)
			((uint8_t *)(p_FmPcd->pIntMuramPtr)+EN_INTERNAL_BUFF_POOL_SIZE);
	}
	tblphysaddr = XX_VirtToPhys(info->table_base);
	node->table_base_hi = ((tblphysaddr >> 32) & 0xffff);	
	node->table_base_lo = (tblphysaddr & 0xffffffff);		
	node->table_type = table_type;
	//check next engine for miss action
	switch (p_Param->ccNextEngineParamsForMiss.nextEngine) {
		case e_FM_PCD_KG:
		{
			//Keygen
			t_FmPcdCcNextKgParams *kgparams;
			kgparams =
				&p_Param->ccNextEngineParamsForMiss.params.kgParams;
			node->nia = (NIA_ENG_KG | NIA_KG_DIRECT);
			if (kgparams->overrideFqid)
                    			node->nia |= (kgparams->newFqid | NIA_KG_CC_EN);
                		node->nia |= FmPcdKgGetSchemeId(kgparams->h_DirectScheme);
			node->miss_action_type = EN_EHASH_MISS_ACTION_NIA;
			break;
	}
	case e_FM_PCD_DONE:
	{
			//BMI
			t_FmPcdCcNextEnqueueParams *enqparams;
			enqparams =
				&p_Param->ccNextEngineParamsForMiss.params.enqueueParams;
			if (enqparams->overrideFqid)
				node->fqid = enqparams->newFqid;
			if (enqparams->overrideFqid)
			{
				node->miss_action_type = EN_EHASH_MISS_ACTION_ENQUE;
			}
			else
				node->miss_action_type = EN_EHASH_MISS_ACTION_DONE;
			break;
	}
	default:
		node->miss_action_type = EN_EHASH_MISS_ACTION_DROP;
		break;
	}





	return (t_Handle)info;
err_ret:
	FreeEnEhashInfo(info);
	return NULL;
}


t_Error ExternalHashTableModifyMissNextEngine(t_Handle h_HashTbl, t_FmPcdCcNextEngineParams *p_FmPcdCcNextEngineParams)
{
	struct en_exthash_info *info;
	struct en_exthash_node node;

	info = (struct en_exthash_info *)h_HashTbl;

	node.word_0 = GET_UINT32(((struct en_exthash_node *)info->h_Ad)->word_0);
	node.word_2 = GET_UINT32(((struct en_exthash_node *)info->h_Ad)->word_2);

	//set action type to miss temporarily
	node.miss_action_type = EN_EHASH_MISS_ACTION_DROP;
	WRITE_UINT32(((struct en_exthash_node *)info->h_Ad)->word_0, node.word_0);

	//set new miss action
	switch (p_FmPcdCcNextEngineParams->nextEngine) {
		case e_FM_PCD_KG:
		{
			//Keygen
			t_FmPcdCcNextKgParams *kgparams;
			kgparams = &p_FmPcdCcNextEngineParams->params.kgParams;
			node.nia = (NIA_ENG_KG | NIA_KG_DIRECT | NIA_KG_CC_EN);
			node.nia |= FmPcdKgGetSchemeId(kgparams->h_DirectScheme);
			node.miss_action_type = EN_EHASH_MISS_ACTION_NIA;
			break;
		}
               case e_FM_PCD_DONE:
		{
			//BMI
			t_FmPcdCcNextEnqueueParams *enqparams;
			enqparams =
				&p_FmPcdCcNextEngineParams->params.enqueueParams;
			if (enqparams->overrideFqid)
				node.fqid = enqparams->newFqid;
			if (enqparams->overrideFqid)
			{
				node.miss_action_type = EN_EHASH_MISS_ACTION_ENQUE;
			}
			else
				node.miss_action_type = EN_EHASH_MISS_ACTION_DONE;
			break;
		}
		case e_FM_PCD_PLCR:
		{
			t_FmPcdCcNextPlcrParams *plcrparams;

			plcrparams =
				&p_FmPcdCcNextEngineParams->params.plcrParams;
			node.miss_action_type = EN_EHASH_MISS_ACTION_NIA;
			if (plcrparams->sharedProfile)
				node.nia = (NIA_ENG_PLCR | NIA_PLCR_ABSOLUTE | plcrparams->newRelativeProfileId);
			else
				node.nia = (NIA_ENG_PLCR | plcrparams->newRelativeProfileId);
			break;
		}

		default:
			node.miss_action_type = EN_EHASH_MISS_ACTION_DROP;
			break;
	}
	//write the new params
	WRITE_UINT32(((struct en_exthash_node *)info->h_Ad)->word_2, node.word_2);
	WRITE_UINT32(((struct en_exthash_node *)info->h_Ad)->word_0, node.word_0);
	return E_OK;
}

int ExternalHashTableFmPcdHcSync(void *h_HashTbl)
{
	struct en_exthash_info *info;
	info = (struct en_exthash_info *)h_HashTbl;
	/* ehash_barrier() reports the first failure of a run. */
	if (ehash_barrier(info, false))
		return -1;
	return 0;
}
EXPORT_SYMBOL(ExternalHashTableFmPcdHcSync);

/* ehash_delete_key() asking for a replacement node; never returned by
 * ehash_delete(). */
#define EHASH_DELETE_NEEDS_NODE	1

/* The delete proper, for ehash_delete(). *node is a zeroed cumulative node
 * taken outside the bucket lock, or NULL. The one arm that rebuilds a node
 * without the key links *node and clears it; with *node NULL it returns
 * EHASH_DELETE_NEEDS_NODE instead, before changing anything and with the lock
 * dropped, so the caller can take one and start over. A node still in *node
 * on return is the caller's to release. Without sync every unlink ends as one
 * whose barrier failed does: what it displaced is parked, and the result is
 * EN_EHASH_DELETE_UNSYNCED. */
static int ehash_delete_key(struct en_exthash_info *info, uint16_t index,
			    void *tbl_entry, struct en_cumulative_tbl_entry **node,
			    bool sync)
{
	t_Handle h_Spinlock;
	uint32_t intFlags;
	uint64_t phyaddr;
	struct en_exthash_bucket *bucket;
	struct en_exthash_tbl_entry *entry;
	struct en_cumulative_entry *cumulative_entry, *tmp;
	struct en_cumulative_tbl_entry *cumulative_tbl_entry, *tmp_tbl_entry = NULL;
	uint8_t ii, match=0, flags;
	bool rebuild;

	bucket = ((struct en_exthash_bucket *)info->table_base + index);
	entry = (struct en_exthash_tbl_entry *)tbl_entry;
	h_Spinlock = &info->bucket_lock[index];
	intFlags = XX_LockIntrSpinlock(h_Spinlock);
	FM_EHASH_PRINT("%s(%d) tbl_entry %p\n", __func__,__LINE__,tbl_entry);
	// check if it normal node or cumulative node 
	// no cumulative node, its only one node in hash bucket, delete
	phyaddr = XX_VirtToPhys(entry);
	if (bucket->h == SwapUint64(phyaddr))
	{
		FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
		bucket->h = 0;
		XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
		if (!sync || ehash_barrier(info, true))
			return EN_EHASH_DELETE_UNSYNCED;
		return 0;
	}
	else
	{
		FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
		// get cumulative entry node address.
		phyaddr = bucket->h;
		/* An empty bucket links nothing, the caller's entry included;
		 * there is no node at address zero to look in. */
		if (!phyaddr)
		{
			XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
			REPORT_ERROR(MAJOR, E_INVALID_STATE, ("No matching node"));
			return -1;
		}
		cumulative_tbl_entry = XX_PhysToVirt(SwapUint64(phyaddr));
		cumulative_entry = &cumulative_tbl_entry->cumulative_entry;
		if (!(cumulative_entry->flags & EN_CUMULATIVE_NODE))
		{
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
       		REPORT_ERROR(MAJOR, E_INVALID_STATE,
                	     ("Invalid state"));
			XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
			return -1;
		}
		// find matching cumulative entry
		do
		{
			for (ii=0; ii<cumulative_entry->num_key_entries; ii++)
			{
				FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
				if (ehash_node_entry(cumulative_entry, ii) == tbl_entry)
				{
					match = 1;
					break;
				}
			}
			if (match)
				break;
			if (cumulative_tbl_entry->next_entry)
			{
				cumulative_tbl_entry = cumulative_tbl_entry->next_entry;
				cumulative_entry = &cumulative_tbl_entry->cumulative_entry;
			}
			else
				cumulative_entry =  NULL;
		}while (cumulative_entry);
		if (match) // if found
		{
			FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
			rebuild = cumulative_entry->num_key_entries > 2 ||
				  (cumulative_entry->num_key_entries == 2 &&
				   (cumulative_tbl_entry->prev_entry ||
				    cumulative_tbl_entry->next_entry));
			if (rebuild && !*node) {
				/* Nothing is changed yet, not even the invalid
				 * flag below, which must never stay set on a node
				 * that stays linked: it would blackhole every
				 * co-resident key if the ucode honors the bit. */
				XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
				return EHASH_DELETE_NEEDS_NODE;
			}
			// cumulative entry might have the next entry, in that case, get the last table entry in last cumulative entry
			// and overwrite it with to-be-deleted table entry
			flags =  cumulative_entry->flags | EN_INVALID_CUMULATIVE_NODE;
			cumulative_entry->flags = flags;
			if (rebuild)
			{
				tmp_tbl_entry = *node;
				*node = NULL;
				FM_EHASH_PRINT(" case 1 num keys > 1 %s(%d)\n",__func__,__LINE__);
				tmp = &tmp_tbl_entry->cumulative_entry;
				tmp->flags = cumulative_entry->flags & 0xbf; 
				tmp->key_size =  cumulative_entry->key_size;
				tmp->next_entry_addr = cumulative_entry->next_entry_addr;
				tmp->num_key_entries = cumulative_entry->num_key_entries-1;
				tmp->tbl_entry_index = cumulative_entry->tbl_entry_index - cumulative_entry->key_size;
				FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
				if (ii)
				{
					FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
					memcpy(tmp->data, &cumulative_entry->data, (ii*cumulative_entry->key_size));
					memcpy(&tmp->data[tmp->num_key_entries*tmp->key_size+1], 
						&cumulative_entry->data[cumulative_entry->num_key_entries*tmp->key_size+1], ii*EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE);
				}
				if (ii < cumulative_entry->num_key_entries-1)
				{
					FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
					memcpy(tmp->data+(ii*cumulative_entry->key_size), 
						&cumulative_entry->data[(ii+1)*cumulative_entry->key_size],
					(cumulative_entry->num_key_entries-ii-1)*cumulative_entry->key_size+1);
					memcpy(&tmp->data[(tmp->num_key_entries*tmp->key_size)+1+(ii*EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE)], 
						&cumulative_entry->data[cumulative_entry->num_key_entries*tmp->key_size+1+((ii+1)*EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE)],
						(tmp->num_key_entries - ii)*EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE);
				}
				if (cumulative_tbl_entry->next_entry)
				{
					FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
					tmp_tbl_entry->next_entry = cumulative_tbl_entry->next_entry;
					cumulative_tbl_entry->next_entry->prev_entry = tmp_tbl_entry;
				}
				phyaddr = SwapUint64(XX_VirtToPhys(tmp_tbl_entry));
				dma_wmb();
				if (cumulative_tbl_entry->prev_entry)
				{
					FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
					cumulative_tbl_entry->prev_entry->cumulative_entry.next_entry_addr = phyaddr;
					tmp_tbl_entry->prev_entry = cumulative_tbl_entry->prev_entry;
					cumulative_tbl_entry->prev_entry->next_entry =  tmp_tbl_entry;
				}
				else
				{
					FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
					bucket->h = phyaddr;
				}
				XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
				if (!sync || ehash_barrier(info, true)) {
					/* The replaced node is out of the chain
					 * just as the caller's entry is, and waits
					 * for the next barrier the same way. */
					ehash_park_node(info, cumulative_tbl_entry);
					return EN_EHASH_DELETE_UNSYNCED;
				}
				/* Refills the spare if this delete took it. */
				ehash_node_release(info, cumulative_tbl_entry);
			}
			else  // if only one entry in list and there is next pointer
			{
				FM_EHASH_PRINT("%s(%d)\n",__func__,__LINE__);
				if ((!(cumulative_tbl_entry->next_entry) &&
					  !(cumulative_tbl_entry->prev_entry) &&
					 (cumulative_entry->num_key_entries == 2)) || 
					((!cumulative_tbl_entry->prev_entry) && 
					 (cumulative_tbl_entry->next_entry) && 
					 (cumulative_tbl_entry->next_entry->cumulative_entry.num_key_entries == 1) &&
					 (!cumulative_tbl_entry->next_entry->next_entry)) ||
					((cumulative_tbl_entry->prev_entry) && 
					 !(cumulative_tbl_entry->next_entry) && 
					 (cumulative_tbl_entry->prev_entry->cumulative_entry.num_key_entries == 1) &&
					 (!cumulative_tbl_entry->prev_entry->prev_entry))) 
				{
					// special case where only one entry in list exists
					if (cumulative_tbl_entry->next_entry)
					{
						FM_EHASH_PRINT("%s(%d) special case where only one entry in list exists\n",__func__,__LINE__);
						tmp_tbl_entry = cumulative_tbl_entry->next_entry;
						flags = tmp_tbl_entry->cumulative_entry.flags | EN_INVALID_CUMULATIVE_NODE;
						tmp_tbl_entry->cumulative_entry.flags =	flags;
						phyaddr = *((uint64_t *)
							(&tmp_tbl_entry->cumulative_entry.data[tmp_tbl_entry->cumulative_entry.tbl_entry_index-EN_CU_FIXED_ELEMENTS_SIZE]));
						bucket->h = phyaddr;
					}
					else if (cumulative_tbl_entry->prev_entry)
					{
						FM_EHASH_PRINT("%s(%d) special case where only one entry in list exists\n",__func__,__LINE__);
						tmp_tbl_entry = cumulative_tbl_entry->prev_entry;
						flags = tmp_tbl_entry->cumulative_entry.flags | EN_INVALID_CUMULATIVE_NODE;
						tmp_tbl_entry->cumulative_entry.flags =	flags;
						phyaddr = *((uint64_t *)
							(&tmp_tbl_entry->cumulative_entry.data[tmp_tbl_entry->cumulative_entry.tbl_entry_index-EN_CU_FIXED_ELEMENTS_SIZE]));
						bucket->h = phyaddr;
					}
					else
					{
						tmp_tbl_entry = NULL;
						if (ii)
							phyaddr = *((uint64_t *)(&cumulative_entry->data[cumulative_entry->tbl_entry_index-EN_CU_FIXED_ELEMENTS_SIZE]));
						else					
							phyaddr = *((uint64_t *)(&cumulative_entry->data[cumulative_entry->tbl_entry_index-EN_CU_FIXED_ELEMENTS_SIZE+EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE]));
						bucket->h = phyaddr;
						FM_EHASH_PRINT("%s(%d) special case where only one entry %p in list exists\n",__func__,__LINE__,
							XX_PhysToVirt(SwapUint64(phyaddr)));
					}
					XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
					if (!sync || ehash_barrier(info, true)) {
						/* Both nodes left the chain when the
						 * bucket took the last entry directly. */
						ehash_park_node(info, tmp_tbl_entry);
						ehash_park_node(info, cumulative_tbl_entry);
						return EN_EHASH_DELETE_UNSYNCED;
					}
					ehash_node_release(info, tmp_tbl_entry);
					ehash_node_release(info, cumulative_tbl_entry);
				}
				else if (!cumulative_tbl_entry->prev_entry) // this is the first cumulative entry in list
				{
					if (cumulative_tbl_entry->next_entry)
					{
						// update the bucket with next cumulative node
						FM_EHASH_PRINT("%s(%d) update the bucket with next cumulative node as no prev entry \n",__func__,__LINE__);
						cumulative_tbl_entry->next_entry->prev_entry =  NULL;
						phyaddr = SwapUint64(XX_VirtToPhys(cumulative_tbl_entry->next_entry));
						bucket->h = phyaddr;
						XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
						if (!sync || ehash_barrier(info, true)) {
							ehash_park_node(info, cumulative_tbl_entry);
							return EN_EHASH_DELETE_UNSYNCED;
						}
						ehash_node_release(info, cumulative_tbl_entry);
					}
					else // no next node , no prev node , only table entry in node ==> invalid case
					{
						FM_EHASH_PRINT("%s(%d)no next node , no prev node , only table entry in node ==> invalid case\n",__func__,__LINE__);
						REPORT_ERROR(MAJOR, E_INVALID_STATE,
									 ("Invalid state"));
						/* The node stays linked, so the invalid
						 * flag set on entry to the match arm must
						 * not stick: it would blackhole every
						 * co-resident key if the ucode honors it. */
						cumulative_entry->flags &= ~EN_INVALID_CUMULATIVE_NODE;
						XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
						return -1;
					}
				}
				else // this node is not the first node
				{
					FM_EHASH_PRINT("%s(%d) this node is not the first node \n",__func__,__LINE__);
					if (cumulative_tbl_entry->next_entry)
					{
						// update the bucket with next cumulative node
						FM_EHASH_PRINT("%s(%d) update the next cumulative node with prev entry\n",__func__,__LINE__);
						cumulative_tbl_entry->next_entry->prev_entry =  cumulative_tbl_entry->prev_entry;
						cumulative_tbl_entry->prev_entry->next_entry =	cumulative_tbl_entry->next_entry;
						cumulative_tbl_entry->prev_entry->cumulative_entry.next_entry_addr = cumulative_tbl_entry->cumulative_entry.next_entry_addr ;
					}
					else
					{
						flags = cumulative_tbl_entry->prev_entry->cumulative_entry.flags & ~EN_NEXT_CUMULATIVE_NODE;
						FM_EHASH_PRINT("%s(%d) update the next cumulative node with prev entry\n",__func__,__LINE__);
						cumulative_tbl_entry->prev_entry->cumulative_entry.flags = flags;
						cumulative_tbl_entry->prev_entry->next_entry =	NULL;
						dma_wmb();
						cumulative_tbl_entry->prev_entry->cumulative_entry.next_entry_addr = 0;
					}
					XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
					if (!sync || ehash_barrier(info, true)) {
						ehash_park_node(info, cumulative_tbl_entry);
						return EN_EHASH_DELETE_UNSYNCED;
					}
					ehash_node_release(info, cumulative_tbl_entry);
				}
			}
		}// match not found
		else
		{
			XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
			REPORT_ERROR(MAJOR, E_INVALID_STATE,
						 ("No matching node"));
			return -1;
		}
		
	}

	return 0;
}

static int ehash_delete(struct en_exthash_info *info, uint16_t index, void *tbl_entry,
			bool sync)
{
	struct en_cumulative_tbl_entry *node = NULL;
	int rc;

	rc = ehash_delete_key(info, index, tbl_entry, &node, sync);
	if (rc == EHASH_DELETE_NEEDS_NODE) {
		node = ehash_node_alloc(info);
		/* The spare is empty after a rebuild on this table took it
		 * while the allocator was failing and then parked the node it
		 * replaced on a failed or deferred barrier
		 * (EN_EHASH_DELETE_UNSYNCED). A barrier that completes now
		 * releases that node into this table's spare, as
		 * ehash_barrier() does every parked node into its own. */
		if (!node && READ_ONCE(ehash_parked) && !ehash_barrier(info, false))
			node = ehash_node_take_spare(info);
		if (!node) {
			/* So a delete fails for memory only when the allocator
			 * fails now, an earlier rebuild on this table left the
			 * spare empty as above, and this barrier fails too.
			 * One rarer way leaves the spare empty with nothing
			 * parked to refill it: another delete on this table
			 * holds the spare at this moment, which CDX's
			 * serialized deletes never do. The bucket is untouched
			 * and the key still linked, as -1 tells the caller. */
			REPORT_ERROR(MAJOR, E_NO_MEMORY, ("en_cumulative_entry"));
			return -1;
		}
		/* With a node in hand the delete cannot ask again. */
		rc = ehash_delete_key(info, index, tbl_entry, &node, sync);
	}
	/* A node is left over only if the bucket changed while the lock was
	 * dropped and the delete no longer rebuilt one. */
	ehash_node_release(info, node);
	return rc;
}

int ExternalHashTableDeleteKey(void *h_HashTbl, uint16_t index, void *tbl_entry)
{
	return ehash_delete(h_HashTbl, index, tbl_entry, true);
}
EXPORT_SYMBOL(ExternalHashTableDeleteKey);

int ExternalHashTableUnlinkKey(void *h_HashTbl, uint16_t index, void *tbl_entry)
{
	return ehash_delete(h_HashTbl, index, tbl_entry, false);
}
EXPORT_SYMBOL(ExternalHashTableUnlinkKey);

int ExternalHashTableDeleteSync(void *h_HashTbl)
{
	/* ehash_barrier() reports the first failure of a run. */
	return ehash_barrier(h_HashTbl, true) ? -1 : 0;
}
EXPORT_SYMBOL(ExternalHashTableDeleteSync);

/* More cumulative nodes than any bucket can chain: each holds a key, and a
 * bucket index is sixteen bits wide. A walk that has not ended by then is going
 * round a loop. */
#define EHASH_CHAIN_MAX	65536

/* Whether one bucket links tbl_entry: directly, or through one of the
 * cumulative nodes it chains. 1 linked, 0 not, -EUCLEAN for a chain whose
 * software links and the microcode's disagree or that does not end -- what
 * the delete walks and what the hardware walks would then be two chains --
 * and for a node no add or delete leaves: one holding no key, or a lone node
 * holding a single key, which a bucket links directly instead. A delete
 * refuses that last one every time it is asked. */
static int ehash_bucket_links(struct en_exthash_info *info, uint32_t index,
			      void *tbl_entry)
{
	struct en_exthash_bucket *bucket;
	struct en_cumulative_tbl_entry *node;
	struct en_cumulative_entry *cumulative;
	t_Handle h_Spinlock;
	uint32_t intFlags, nodes = 0;
	uint8_t ii;
	int rc = 0;

	bucket = (struct en_exthash_bucket *)info->table_base + index;
	h_Spinlock = &info->bucket_lock[index];
	intFlags = XX_LockIntrSpinlock(h_Spinlock);
	if (!bucket->h)
		goto out;
	if (bucket->h == SwapUint64(XX_VirtToPhys(tbl_entry))) {
		rc = 1;
		goto out;
	}
	node = XX_PhysToVirt(SwapUint64(bucket->h));
	/* A bucket holding one other entry directly. */
	if (!(node->cumulative_entry.flags & EN_CUMULATIVE_NODE))
		goto out;
	for (; node; node = node->next_entry) {
		cumulative = &node->cumulative_entry;
		if (++nodes > EHASH_CHAIN_MAX ||
		    !(cumulative->flags & EN_CUMULATIVE_NODE) ||
		    !(cumulative->flags & EN_NEXT_CUMULATIVE_NODE) != !node->next_entry ||
		    (node->next_entry && cumulative->next_entry_addr !=
		     SwapUint64(XX_VirtToPhys(node->next_entry))) ||
		    !cumulative->num_key_entries ||
		    (nodes == 1 && !node->next_entry &&
		     cumulative->num_key_entries < 2)) {
			rc = -EUCLEAN;
			break;
		}
		for (ii = 0; ii < cumulative->num_key_entries; ii++)
			if (ehash_node_entry(cumulative, ii) == tbl_entry) {
				rc = 1;
				goto out;
			}
	}
out:
	XX_UnlockIntrSpinlock(h_Spinlock, intFlags);
	return rc;
}

/* Where tbl_entry is linked in the table, for an owner that could not prove
 * its delete unlinked it and has to know before freeing it. *index names the
 * bucket the entry was added to, which is looked in first; every other bucket
 * is looked in after it. Returns 0 with *index set to the bucket that links
 * the entry, -ENOENT when none does, -EUCLEAN for a malformed chain. Each
 * bucket is read under its own lock, so the answer holds only while nothing
 * else adds or deletes keys -- which the caller has to arrange. */
int ExternalHashTableFindEntry(void *h_HashTbl, void *tbl_entry, uint16_t *index)
{
	struct en_exthash_info *info = (struct en_exthash_info *)h_HashTbl;
	uint32_t ii;
	int rc;

	if (!info || !tbl_entry || !index)
		return -EINVAL;
	if (*index <= info->hashmask) {
		rc = ehash_bucket_links(info, *index, tbl_entry);
		if (rc)
			return rc < 0 ? rc : 0;
	}
	for (ii = 0; ii <= info->hashmask; ii++) {
		if (ii == *index)
			continue;
		rc = ehash_bucket_links(info, ii, tbl_entry);
		if (rc < 0)
			return rc;
		if (rc) {
			*index = (uint16_t)ii;
			return 0;
		}
	}
	return -ENOENT;
}
EXPORT_SYMBOL(ExternalHashTableFindEntry);

int32_t ExternalHashGetSECfailureStats(en_SEC_failure_stats *stats)
{
	/* The block is placed with the first external hash table; until then
	 * there are no counters to read. */
	if (!stats || !en_global_muram_mem)
		return -1;

	stats->anti_replay_late_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.anti_replay_late_errs);
		

	stats->anti_replay_replay_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.anti_replay_replay_errs);
	
	stats->buff_pool_depletion_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.buff_pool_depletion_errs);
	
	stats->buff_too_small_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.buff_too_small_errs);

	stats->CCM_AAD_size_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.CCM_AAD_size_errs);

	stats->cmpnd_frame_read_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.cmpnd_frame_read_errs);
	
	stats->cmpnd_frame_write_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.cmpnd_frame_write_errs);
	
	stats->DECO_watchdog_timer_timedout_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.DECO_watchdog_timer_timedout_errs);
	
	stats->DMA_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.DMA_errs);
	
	stats->hw_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.hw_errs);
	
	stats->icv_failures =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.icv_failures);
	
	stats->input_frame_read_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.input_frame_read_errs);
	
	stats->ipsec_pad_chk_failures =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.ipsec_pad_chk_failures);

	stats->ipsec_ttl_zero_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.ipsec_ttl_zero_errs);
	
	stats->other_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.other_errs);
	
	stats->output_frame_length_rollover_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.output_frame_length_rollover_errs);
	
	stats->output_frame_too_large_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.output_frame_too_large_errs);
	
	stats->output_frame_write_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.output_frame_write_errs);
	
	stats->prehdr_read_errs = 
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.prehdr_read_errs);
	
	stats->protocol_format_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.protocol_format_errs);
	
	stats->seq_num_overflows =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.seq_num_overflows);
	
	stats->tbl_buff_pool_depletion_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.tbl_buff_pool_depletion_errs);
	
	stats->tbl_buff_too_small_errs =
		GET_UINT32(en_global_muram_mem->SEC_failure_stats.tbl_buff_too_small_errs);

	return 0;
}
EXPORT_SYMBOL(ExternalHashGetSECfailureStats);


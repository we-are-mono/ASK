/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include <linux/mutex.h>
#include "cdx.h"
#include "cdx_cmd_validator.h"
#include "list.h"
#include "cdx_common.h"
#include "misc.h"
#include "control_ipv4.h"
#include "dpa_control_mc.h"
#include "control_ipv6.h"
#include "linux/netdevice.h"
#include <linux/if_ether.h>
#include <net/net_namespace.h>

typedef union ucode_phyaddr_u {
	struct {
		uint16_t rsvd;
		uint16_t addr_hi;
		uint32_t addr_lo;
	};
	uint64_t addr;
}ucode_phyaddr_t;

/*
 * Concurrency:
 *   mc4_spinlocks[hash], mc6_spinlocks[hash]
 *      - Per-bucket spinlocks. Allocated during module init as
 *        arrays of MC{4,6}_NUM_HASH_ENTRIES entries. A given
 *        bucket's list (mc{4,6}_grp_list[hash]) is walked and
 *        mutated under its matching spinlock. Mutators and walkers
 *        (the latter in cdx_mc_query.c) must agree on the
 *        convention - use plain spin_lock()/unlock() everywhere
 *        so process-context and softirq-context callers don't
 *        disagree on bh state.
 *   mc4_grp_list[], mc6_grp_list[]
 *      - Arrays of list heads, one per hash bucket. Protected by
 *        the matching spinlock above.
 *   mc{4,6}grp_ids, max_mc{4,6}grp_ids
 *      - Allocated once at init, not mutated on the datapath;
 *        read-only after init.
 *   mc_pending_frees, mc_pending_free_cnt
 *      - Quarantine of listener table entries that are already out
 *        of the FMAN replication chain but not yet provably
 *        walker-free. No lock of its own: every touch happens from
 *        a mcast mutator - serialized by the FCI ctrl.mutex plus
 *        mc_mutators_mutex below - or from mc{4,6}_exit(), which
 *        runs at module unload with no handler in flight. The query
 *        walkers never see it, so no softirq-safe variant is needed.
 *
 * Contexts:
 *   AddToMcastGrpList(), GetMcastGrp(), cdx_delete_mcast_group_*()
 *                        - process, IGMP/MLD-driven slow path.
 *   Lookups from mc_query.c
 *                        - process, ioctl query path.
 *
 * Lock ordering: these spinlocks are leaves - do not take any
 * other cdx lock while holding one.
 */

struct list_head mc4_grp_list[MC4_NUM_HASH_ENTRIES];
struct list_head mc6_grp_list[MC6_NUM_HASH_ENTRIES];

extern uint64_t XX_VirtToPhys(void * addr);

uint8_t *mc4grp_ids=NULL, *mc6grp_ids=NULL;
spinlock_t *mc4_spinlocks =  NULL, *mc6_spinlocks = NULL;
uint16_t  max_mc4grp_ids, max_mc6grp_ids;

/* Serializes mcast mutators (ADD / REMOVE / UPDATE). The lookup-then-
 * mutate sequences inside cdx_create/update/delete_mcast_group_member
 * unavoidably drop the per-bucket spinlock between GetMcastGrp /
 * Cdx_GetMcastMemberId and the eventual members[] / list mutation —
 * helpers like ExternalHashTableFmPcdHcSync sleep on FmPcdLock and
 * can't be held under spinlock. Without an outer lock, two concurrent
 * mutators of the same group could TOCTOU each other's member_id /
 * pMcastGrpInfo pointer (ISSUES.md M10, M11). Today's FCI dispatcher
 * happens to run one command at a time, providing the invariant
 * implicitly; this mutex makes it explicit and survives any future
 * caller that runs from a kthread / workqueue.
 *
 * Held only across mutators in MC{4,6}_Command_Handler; queries
 * stay outside it (they're protected by mc{4,6}_spinlocks[] for
 * list traversal plus mc_query_mutex in cdx_mc_query.c for the
 * paginated snapshot state). */
static DEFINE_MUTEX(mc_mutators_mutex);

static inline bool mcast_action_is_mutator(uint16_t action)
{
	return action == CDX_MC_ACTION_ADD ||
	       action == CDX_MC_ACTION_REMOVE ||
	       action == CDX_MC_ACTION_UPDATE;
}

#ifdef CDX_DEBUG_MC_HCSYNC_FAIL
/*
 * HC-sync fault injection — DEBUG-ONLY, NOT FOR PRODUCTION.
 *
 * The quarantine below only ever engages when a host-command sync
 * fails, which on real hardware means a transient HC frame-pool
 * shortage or a wedged HC channel — neither reproducible on demand.
 * This knob makes the failure arm reachable from user space: write a
 * decimal count to /proc/cdx_mc_hcsync_fail and that many subsequent
 * HC barriers issued by this file report failure without touching the
 * hardware. Reading the file back reports the remaining armed count
 * and the number of entries currently quarantined.
 *
 * Only this file's barriers are affected; the ones inside
 * ExternalHashTableDeleteKey and the rest of cdx run untouched, so an
 * armed knob cannot corrupt classifier state that this file does not
 * own.
 *
 * Production (Armbian) builds DO NOT define CDX_DEBUG_MC_HCSYNC_FAIL.
 * The flag is set only in the meta-ask test image, and the probe
 * pr_warn_once's at init so an accidental enable surfaces loudly.
 */
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define MC_HCSYNC_FAIL_PROC_NAME "cdx_mc_hcsync_fail"

static atomic_t mc_hcsync_fail_countdown = ATOMIC_INIT(0);
static struct proc_dir_entry *mc_hcsync_fail_proc;
#endif /* CDX_DEBUG_MC_HCSYNC_FAIL */

/* Single funnel for every FMAN host-command barrier this file issues.
 * Returns 0 when the sync completed, non-zero when it did not. */
static int mc_hcsync(void *td)
{
#ifdef CDX_DEBUG_MC_HCSYNC_FAIL
	/* atomic_dec_if_positive() returns the post-decrement value, so
	 * >= 0 means a fail credit was actually consumed; -1 means the
	 * counter was already at 0 and nothing was taken. */
	if (atomic_dec_if_positive(&mc_hcsync_fail_countdown) >= 0) {
		DPA_ERROR("%s::injected FmPcdHcSync failure, %d left armed\n",
			  __func__, atomic_read(&mc_hcsync_fail_countdown));
		return -1;
	}
#endif
	return ExternalHashTableFmPcdHcSync(td);
}

/* Pending-free quarantine (ISSUES.md A80).
 *
 * A listener's en_exthash_tbl_entry is spliced out of the live FMAN
 * replication chain under the bucket spinlock, i.e. destructively and
 * before any barrier. ExternalHashTableFmPcdHcSync() is what proves
 * that a ucode walker which entered the chain before the splice has
 * left it; until one succeeds, the unlinked memory may still be
 * dereferenced by hardware, so it must not go back to the allocator.
 *
 * A failed sync therefore leaves an entry that can neither be freed
 * nor re-unlinked (the surgery is not idempotent - replaying it would
 * walk pointers that have already been advanced). Park it here
 * instead: software state for the member is cleared as usual, the
 * memory stays allocated but unreachable, and the backlog is released
 * the next time any sync on this PCD succeeds.
 *
 * One successful sync clears the whole backlog:
 * ExternalHashTableFmPcdHcSync() syncs the table handle's PCD, and
 * LS1046A runs a single FMAN PCD, so a success reached via any table
 * or any group is a valid barrier for every entry unlinked before it.
 */
struct mc_pending_free {
	struct list_head list;
	void *tbl_entry;
};

static LIST_HEAD(mc_pending_frees);
static unsigned int mc_pending_free_cnt;

static void mc_quarantine_entry(void *tbl_entry)
{
	struct mc_pending_free *node;

	if (!tbl_entry)
		return;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
	{
		/* No safe alternative: the entry is already out of the
		 * chain, so it can neither be freed without a barrier nor
		 * reached again through members[]. Leak it - the same
		 * outcome the code had before the quarantine existed - and
		 * make the leak visible in the log. */
		DPA_ERROR("%s::quarantine alloc failed, leaking tbl_entry %p\n",
			  __func__, tbl_entry);
		return;
	}
	node->tbl_entry = tbl_entry;
	list_add_tail(&node->list, &mc_pending_frees);
	/* WRITE_ONCE pairs with the debug proc reader's READ_ONCE - the
	 * count is advisory there, but the store should not tear. */
	WRITE_ONCE(mc_pending_free_cnt, mc_pending_free_cnt + 1);
}

/* Release the whole backlog. Callers must have just observed a
 * successful HC sync on this PCD, or be running at module exit where
 * the PCD teardown has already quiesced the FMAN. Calling it without
 * such a barrier reintroduces the use-after-free the quarantine
 * exists to prevent. */
static void mc_quarantine_free_all(void)
{
	struct mc_pending_free *node, *tmp;

	list_for_each_entry_safe(node, tmp, &mc_pending_frees, list)
	{
		list_del(&node->list);
		ExternalHashTableEntryFree(node->tbl_entry);
		kfree(node);
	}
	WRITE_ONCE(mc_pending_free_cnt, 0);
}

/* Module-exit disposition of a backlog no drain could clear. cdx does
 * NOT tear down the FMAN PCD on unload (sdk_fman owns it and stays
 * loaded), so there is no barrier here either: by this point every
 * group teardown has already retried the sync and failed, meaning the
 * HC channel is wedged and the ucode may still be walking the parked
 * memory. Leaking a handful of entries at rmmod (test images only;
 * cdx is never unloaded in production) is the only safe terminal
 * state. */
static void mc_quarantine_abandon(void)
{
	if (mc_pending_free_cnt)
		DPA_ERROR("%s::HC channel never recovered, leaking %u quarantined entries\n",
			  __func__, mc_pending_free_cnt);
}

/* Retry the barrier for entries parked by an earlier failed sync. HC
 * failures are frequently transient (frame-pool exhaustion rather than
 * a wedged channel), so the reclaim attempt belongs on the next
 * mutator that touches the same PCD; a freshly created group never
 * issues one (its ADD path has no post-resolution hook), so a backlog
 * can outlive an ADD-only workload until the next UPDATE, REMOVE, or
 * DELETE - bounded and safe. No-op when nothing is pending, which is
 * the common case. */
static void mc_quarantine_drain(void *td)
{
	if (list_empty(&mc_pending_frees))
		return;

	if (mc_hcsync(td))
	{
		DPA_ERROR("%s::FmPcdHcSync failed, %u entries still quarantined\n",
			  __func__, mc_pending_free_cnt);
		return;
	}
	mc_quarantine_free_all();
}

#ifdef CDX_DEBUG_MC_HCSYNC_FAIL
static int mc_hcsync_fail_show(struct seq_file *m, void *v)
{
	/* mc_pending_free_cnt is written only under the mutator
	 * serialization; this reader is outside it, and an aligned
	 * unsigned int cannot tear, so a plain snapshot is enough. */
	seq_printf(m, "armed=%d pending=%u\n",
		   atomic_read(&mc_hcsync_fail_countdown),
		   READ_ONCE(mc_pending_free_cnt));
	return 0;
}

static int mc_hcsync_fail_open(struct inode *inode, struct file *file)
{
	return single_open(file, mc_hcsync_fail_show, NULL);
}

static ssize_t mc_hcsync_fail_write(struct file *file, const char __user *buf,
				    size_t len, loff_t *ppos)
{
	char kbuf[16];
	unsigned int n;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	if (kstrtouint(strim(kbuf), 0, &n))
		return -EINVAL;
	/* The countdown is an atomic_t, so anything that would not survive
	 * the cast is rejected rather than silently wrapped negative. */
	if (n > (unsigned int)INT_MAX)
		return -EINVAL;
	atomic_set(&mc_hcsync_fail_countdown, (int)n);
	return len;
}

static const struct proc_ops mc_hcsync_fail_proc_ops = {
	.proc_open    = mc_hcsync_fail_open,
	.proc_read    = seq_read,
	.proc_write   = mc_hcsync_fail_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int cdx_mc_init_hcsync_fail_probe(void)
{
	pr_warn_once("cdx: CDX_DEBUG_MC_HCSYNC_FAIL is on - /proc/%s can force multicast HC-sync failures; do not ship\n",
		     MC_HCSYNC_FAIL_PROC_NAME);
	mc_hcsync_fail_proc = proc_create(MC_HCSYNC_FAIL_PROC_NAME, 0600, NULL,
					  &mc_hcsync_fail_proc_ops);
	if (!mc_hcsync_fail_proc)
		return -ENOMEM;
	return 0;
}

void cdx_mc_remove_hcsync_fail_probe(void)
{
	if (mc_hcsync_fail_proc)
	{
		proc_remove(mc_hcsync_fail_proc);
		mc_hcsync_fail_proc = NULL;
	}
}
#endif /* CDX_DEBUG_MC_HCSYNC_FAIL */

/* The ingress netdev must be subscribed to the group's L2 multicast
 * MAC — otherwise the FMAN MEMAC hardware filter drops matching
 * frames before PCD can classify and replicate them. PROMISC on this
 * driver bypasses unicast filtering only; multicast filtering still
 * applies. Without an explicit dev_mc_add() during MC4 ADD, an
 * offload-managed group silently fails: FCI returns NO_ERR, cmm
 * query mc4 shows the group, zero frames replicate. */
static void cdx_mcast_compute_mac(const struct mcast_group_info *grp,
				  uint8_t mac[ETH_ALEN])
{
	if (grp->mctype == 0) {
		/* IPv4: 01:00:5E:<low 23 bits of dst>. The mask on byte 3
		 * matches the on-disk daddr endianness used elsewhere in
		 * this file (see cdx_add_mcast_table_entry's pRtEntry->dstmac
		 * computation). */
		mac[0] = 0x01;
		mac[1] = 0x00;
		mac[2] = 0x5e;
		mac[3] = (grp->ipv4_daddr >> 8)  & 0x7f;
		mac[4] = (grp->ipv4_daddr >> 16) & 0xff;
		mac[5] = (grp->ipv4_daddr >> 24) & 0xff;
	} else {
		/* IPv6: 33:33:<low 32 bits of dst>. Same byte-order convention
		 * as the existing pRtEntry->dstmac code below. */
		uint32_t lo = grp->ipv6_daddr[3];
		mac[0] = 0x33;
		mac[1] = 0x33;
		mac[2] = (lo) & 0xff;
		mac[3] = (lo >> 8) & 0xff;
		mac[4] = (lo >> 16) & 0xff;
		mac[5] = (lo >> 24) & 0xff;
	}
}

static int cdx_mcast_subscribe_ingress_mac(const char *ifname,
					   const uint8_t mac[ETH_ALEN])
{
	struct net_device *dev;
	int rc;

	dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		DPA_ERROR("%s::ingress netdev %s not found\n", __func__, ifname);
		return -ENODEV;
	}
	rc = dev_mc_add(dev, mac);
	dev_put(dev);
	if (rc)
		DPA_ERROR("%s::dev_mc_add(%s, %pM) failed: %d\n",
			  __func__, ifname, mac, rc);
	return rc;
}

static void cdx_mcast_unsubscribe_ingress_mac(const char *ifname,
					      const uint8_t mac[ETH_ALEN])
{
	struct net_device *dev;

	dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		/* Interface gone (e.g. removed before group teardown). The
		 * subscription is gone with it; nothing to undo. */
		return;
	}
	(void)dev_mc_del(dev, mac);
	dev_put(dev);
}


void AddToMcastGrpList(struct mcast_group_info *pMcastGrpInfo)
{
	unsigned int uiHash;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_add(&(pMcastGrpInfo->list),&mc4_grp_list[uiHash]);
		spin_unlock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		DPA_INFO("%s(%d) hash %d , ptr %p\n",__func__,__LINE__, uiHash, &pMcastGrpInfo->list);
		spin_lock(&mc6_spinlocks[uiHash]);
		list_add(&(pMcastGrpInfo->list),&mc6_grp_list[uiHash]);
		spin_unlock(&mc6_spinlocks[uiHash]);
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__func__,__LINE__, pMcastGrpInfo->uiListenerCnt, pMcastGrpInfo->ipv6_saddr[0], pMcastGrpInfo->ipv6_saddr[1],
				pMcastGrpInfo->ipv6_saddr[2],pMcastGrpInfo->ipv6_saddr[3], 
				pMcastGrpInfo->ipv6_daddr[0], pMcastGrpInfo->ipv6_daddr[1],pMcastGrpInfo->ipv6_daddr[2],
				pMcastGrpInfo->ipv6_daddr[3]);
	}

	return;
}

int GetMcastGrpId( struct mcast_group_info *pMcastGrpInfo,
		uint8_t *ingress_iface)
{
	struct mcast_group_info *tmp;
	struct list_head *ptr;
	unsigned int uiHash;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);

		spin_lock(&mc4_spinlocks[uiHash]);
		list_for_each(ptr, &mc4_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);

			DPA_INFO("%s(%d) tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s dst-addr 0x%x, s-addr %x\n",
					__func__,__LINE__, tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface, tmp->ipv4_daddr,
					tmp->ipv4_saddr);
			if((tmp->ipv4_daddr == pMcastGrpInfo->ipv4_daddr)
					&& (tmp->ipv4_saddr == pMcastGrpInfo->ipv4_saddr))
			{
				if (ingress_iface)
					strncpy(ingress_iface,tmp->ucIngressIface, IF_NAME_SIZE);
				spin_unlock(&mc4_spinlocks[uiHash]);
				return tmp->grpid;
			}
		}
		spin_unlock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
		list_for_each(ptr, &mc6_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);
			DPA_INFO("%s(%d) ptr %p tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s\n",
					__func__,__LINE__, tmp,  tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface);
			DPA_INFO("%s(%d) tmp ipv6daddr: 0x%x:%x:%x:%x src-addr: 0x%x:%x:%x:%x \n",
					__func__,__LINE__, tmp->ipv6_daddr[0], tmp->ipv6_daddr[1],
					tmp->ipv6_daddr[2], tmp->ipv6_daddr[3], tmp->ipv6_saddr[0],
					tmp->ipv6_saddr[1], tmp->ipv6_saddr[2], tmp->ipv6_saddr[3]);

			if(!IPV6_CMP(tmp->ipv6_daddr, pMcastGrpInfo->ipv6_daddr) 
					&& !IPV6_CMP(tmp->ipv6_saddr, pMcastGrpInfo->ipv6_saddr))   
			{
				if (ingress_iface)
					strncpy(ingress_iface,tmp->ucIngressIface, IF_NAME_SIZE);
				spin_unlock(&mc6_spinlocks[uiHash]);
				return tmp->grpid;
			}
		}
		spin_unlock(&mc6_spinlocks[uiHash]);
	}
	return -1;
}

static int GetNewMcastGrpId(uint8_t mctype)
{
	unsigned int ii;

	if(mctype == 0)
	{
		for (ii=0; ii<max_mc4grp_ids; ii++)
		{
			if (!mc4grp_ids[ii])
			{
				mc4grp_ids[ii] = 1;
				return ii+1;
			}
		}
	}
	else
	{
		for (ii=0; ii<max_mc6grp_ids; ii++)
		{
			if (!mc6grp_ids[ii])
			{
				mc6grp_ids[ii] = 1;
				return ii+1;
			}
		}
	}
	return -1;
}

static void FreeMcastGrpID(uint8_t mctype, int grp_id)
{
	if (mctype == 0)
	{
		if ((grp_id > 0) && (grp_id <= max_mc4grp_ids))
		{
			mc4grp_ids[grp_id -1] = 0;
		}
	}
	else
	{
		if ((grp_id > 0) && (grp_id <= max_mc6grp_ids))
		{
			mc6grp_ids[grp_id -1] = 0;
		}
	}
}

struct mcast_group_info* GetMcastGrp( struct mcast_group_info *pMcastGrpInfo)
{
	struct mcast_group_info *tmp;
	struct list_head *ptr;
	unsigned int uiHash;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_for_each(ptr, &mc4_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);

			DPA_INFO("%s(%d) tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s dst-addr 0x%x, s-addr %x\n",
					__func__,__LINE__, tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface, tmp->ipv4_daddr,
					tmp->ipv4_saddr);
			if((tmp->ipv4_daddr == pMcastGrpInfo->ipv4_daddr)
					&& (!strncmp(pMcastGrpInfo->ucIngressIface, tmp->ucIngressIface, IF_NAME_SIZE))
					&& (tmp->ipv4_saddr == pMcastGrpInfo->ipv4_saddr))
			{
				spin_unlock(&mc4_spinlocks[uiHash]);
				return tmp;
			}
		}
		spin_unlock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
		list_for_each(ptr, &mc6_grp_list[uiHash])
		{
			tmp = list_entry(ptr,struct mcast_group_info,list);

			DPA_INFO("%s(%d) ptr %p, tmp->ucIngressIface %s, pMcastGrpInfo->ucIngressIface %s\n",
					__func__,__LINE__,tmp, tmp->ucIngressIface, pMcastGrpInfo->ucIngressIface);
			DPA_INFO("%s(%d) tmp ipv6daddr: 0x%x:%x:%x:%x src-addr: 0x%x:%x:%x:%x \n",
					__func__,__LINE__, tmp->ipv6_daddr[0], tmp->ipv6_daddr[1],
					tmp->ipv6_daddr[2], tmp->ipv6_daddr[3], tmp->ipv6_saddr[0],
					tmp->ipv6_saddr[1], tmp->ipv6_saddr[2], tmp->ipv6_saddr[3]);
			if(!strncmp(pMcastGrpInfo->ucIngressIface, tmp->ucIngressIface, IF_NAME_SIZE))
			{
				if(!IPV6_CMP(tmp->ipv6_daddr, pMcastGrpInfo->ipv6_daddr) 
						&& !IPV6_CMP(tmp->ipv6_saddr, pMcastGrpInfo->ipv6_saddr))   
				{
					spin_unlock(&mc6_spinlocks[uiHash]);
					return tmp;
				}
			}
		}
		spin_unlock(&mc6_spinlocks[uiHash]);
	}
	return NULL;
}

/* Drops every reference the groups in one hash bucket hold on the interface
 * being removed. Called with the bucket's spinlock held. */
static void ClearMcastGrpItfRefs(struct list_head *pGrpList, U32 if_index)
{
	struct mcast_group_info *tmp;
	struct list_head *ptr;
	RouteEntry *pRtEntry;

	list_for_each(ptr, pGrpList)
	{
		tmp = list_entry(ptr, struct mcast_group_info, list);

		if (!tmp->pCtEntry)
			continue;
		pRtEntry = tmp->pCtEntry->pRtEntry;
		if (!pRtEntry)
			continue;

		if (pRtEntry->itf && pRtEntry->itf->index == if_index)
			pRtEntry->itf = NULL;
		if (pRtEntry->input_itf &&
				pRtEntry->input_itf->index == if_index)
			pRtEntry->input_itf = NULL;
		if (pRtEntry->underlying_input_itf &&
				pRtEntry->underlying_input_itf->index == if_index)
			pRtEntry->underlying_input_itf = NULL;
	}
}

/* Called by remove_onif_by_index() while the dying interface is still valid.
 * A multicast group's RouteEntry is allocated on its own, outside rt_cache,
 * so the route walk in layer2.c cannot quarantine it; do it here instead.
 * The bucket spinlocks order us against the ioctl-side query walkers,
 * mc_mutators_mutex against the ADD / REMOVE / UPDATE handlers. */
void cdx_mcast_clear_itf_refs(U32 if_index)
{
	unsigned int uiHash;

	mutex_lock(&mc_mutators_mutex);

	/* mc{4,6}_exit() frees the bucket lock arrays before the command
	 * handler teardown reaches the tx and tunnel exits, which also remove
	 * onifs. Any groups still on the lists at that point are unload-time
	 * leaks nothing will dereference again, so skipping the walk is safe. */
	if (mc4_spinlocks)
	{
		for (uiHash = 0; uiHash < MC4_NUM_HASH_ENTRIES; uiHash++)
		{
			spin_lock(&mc4_spinlocks[uiHash]);
			ClearMcastGrpItfRefs(&mc4_grp_list[uiHash], if_index);
			spin_unlock(&mc4_spinlocks[uiHash]);
		}
	}

	if (mc6_spinlocks)
	{
		for (uiHash = 0; uiHash < MC6_NUM_HASH_ENTRIES; uiHash++)
		{
			spin_lock(&mc6_spinlocks[uiHash]);
			ClearMcastGrpItfRefs(&mc6_grp_list[uiHash], if_index);
			spin_unlock(&mc6_spinlocks[uiHash]);
		}
	}

	mutex_unlock(&mc_mutators_mutex);
}

static int Cdx_GetMcastMemberId(char *pIn_Info, struct mcast_group_info *pMcastGrpInfo)
{
	int ii;
	struct mcast_group_member *pMember;
	unsigned int uiHash;

	if(!pMcastGrpInfo)
		return -1;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
	}
	for(ii=0; ii < MC4_MAX_LISTENERS_PER_GROUP; ii++)
	{
		pMember = &(pMcastGrpInfo->members[ii]);
		if(pMember->bIsValidEntry == 1)
		{
			if(strcmp(pIn_Info,pMember->if_info )== 0)
			{
				if(pMcastGrpInfo->mctype == 0)
					spin_unlock(&mc4_spinlocks[uiHash]);
				else
					spin_unlock(&mc6_spinlocks[uiHash]);
				return pMember->member_id;
			}
		}
	}  
	if(pMcastGrpInfo->mctype == 0)
		spin_unlock(&mc4_spinlocks[uiHash]);
	else
		spin_unlock(&mc6_spinlocks[uiHash]);
	return -1;
}


static int Cdx_GetMcastMemberFreeIndex(struct mcast_group_info *pMcastGrpInfo)
{
	int ii;
	struct mcast_group_member *pMember;
	unsigned int uiHash;

	if(!pMcastGrpInfo)
		return -1;

	if(pMcastGrpInfo->mctype == 0)
	{
		uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
	}
	else
	{
		uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
	}

	for(ii=0; ii < MC4_MAX_LISTENERS_PER_GROUP; ii++)
	{
		pMember = &(pMcastGrpInfo->members[ii]);
		if (pMember->bIsValidEntry == 0)
		{
			if(pMcastGrpInfo->mctype == 0)
				spin_unlock(&mc4_spinlocks[uiHash]);
			else
				spin_unlock(&mc6_spinlocks[uiHash]);
			return ii;
		}
	}  
	if(pMcastGrpInfo->mctype == 0)
		spin_unlock(&mc4_spinlocks[uiHash]);
	else
		spin_unlock(&mc6_spinlocks[uiHash]);
	return -1;
}


int cdx_free_exthash_mcast_members(struct mcast_group_info *pMcastGrpInfo);
static int cdx_add_mcast_table_entry(void *mcast_cmd,
		struct mcast_group_info *pMcastGrpInfo)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	RouteEntry *pRtEntry;
	POnifDesc onif_desc;
	struct _tCtEntry *pCtEntry;
	int retval,ii;
	uint64_t phyaddr=0;
	char ucInterface[IF_NAME_SIZE];

	pRtEntry = NULL;
	pCtEntry = NULL;
	mcast4_group = NULL;
	mcast6_group = NULL;

	if (mcast_cmd == NULL)
		return FAILURE;

	if(pMcastGrpInfo->mctype == 0)
	{
		mcast4_group = (PMC4Command)(mcast_cmd);
		strncpy(ucInterface,mcast4_group->input_device_str,IF_NAME_SIZE-1);
	}
	else
	{
		mcast6_group = (PMC6Command)(mcast_cmd);
		strncpy(ucInterface,mcast6_group->input_device_str,IF_NAME_SIZE-1);
	}

	pRtEntry = kzalloc((sizeof(RouteEntry)), GFP_KERNEL);
	if (!pRtEntry)
	{
		return -ENOMEM;	
	}

	pCtEntry = kzalloc((sizeof(struct _tCtEntry)), GFP_KERNEL);
	if (!pCtEntry)
	{
		retval = -ENOMEM;	
		goto err_ret;
	}

	pCtEntry->proto = IPPROTOCOL_UDP;
	/** proto is UDP for any mutlicast packet **/

	pCtEntry->Sport = 0;
	pCtEntry->Dport = 0;
	/** port fields should be masked in match key**/

	if(pMcastGrpInfo->mctype == 0)
	{
		pCtEntry->Saddr_v4 = (mcast4_group->src_addr);
		pCtEntry->Daddr_v4 = (mcast4_group->dst_addr);
		pCtEntry->twin_Daddr = pCtEntry->Saddr_v4;
		pCtEntry->twin_Saddr = pCtEntry->Daddr_v4;
		pCtEntry->fftype = FFTYPE_IPV4;
	}
	else
	{
		memcpy(pCtEntry->Saddr_v6,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pCtEntry->Daddr_v6,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		pCtEntry->fftype = FFTYPE_IPV6;
	}

	onif_desc = get_onif_by_name(ucInterface); 
	if (!onif_desc)
	{
		DPA_ERROR("%s::unable to get onif for iface %s\n",__func__, ucInterface);
		retval = -EIO;
		goto err_ret;
	}

	pRtEntry->itf = onif_desc->itf;
	pRtEntry->input_itf = onif_desc->itf;
	pRtEntry->underlying_input_itf = pRtEntry->input_itf;
	pCtEntry->pRtEntry = pRtEntry;
	for (ii=0; ii<pMcastGrpInfo->uiListenerCnt; ii++)
	{
		if(pMcastGrpInfo->members[ii].bIsValidEntry)
		{
			phyaddr = XX_VirtToPhys(pMcastGrpInfo->members[ii].tbl_entry);
			DPA_INFO("%s(%d) phyaddr %llx, addr %p\n",
					__func__,__LINE__,phyaddr, pMcastGrpInfo->members[ii].tbl_entry);
			break;
		}
	}
	/* No valid member leaves ii == uiListenerCnt, and members[ii] would
	 * read past the array when the group is at capacity. */
	if (ii >= pMcastGrpInfo->uiListenerCnt)
	{
		DPA_ERROR("%s::no valid member in mcast group\r\n", __func__);
		retval = -EINVAL;
		goto err_ret;
	}
	retval = insert_mcast_entry_in_classif_table(pCtEntry, pMcastGrpInfo->uiListenerCnt, phyaddr,
			pMcastGrpInfo->members[ii].tbl_entry);
	if(retval)
	{
		DPA_ERROR("%s::Insert Mcast entry failed \r\n",__func__);
		goto err_ret;
	}

	pMcastGrpInfo->pCtEntry  = pCtEntry;

	return retval;

err_ret:
	if (pRtEntry)
	{
		kfree(pRtEntry);
	}
	if (pCtEntry)
	{
		kfree(pCtEntry);
	}
	return retval;
}


static int cdx_create_mcast_group(void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	MC4Output	*pListener;
	RouteEntry *pRtEntry, RtEntry;
	int iRet = 0;
	struct ins_entry_info *pInsEntryInfo, InsEntryInfo;
	struct mcast_group_info *pMcastGrpInfo;
	int ii, member_id = 0;
	unsigned int uiNoOfListeners;
	char *pInIface;
	uint8_t IngressIface[IF_NAME_SIZE];
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	uint32_t tbl_type;

	// memory allocation for multicast group
	pMcastGrpInfo = (struct mcast_group_info *)kzalloc((sizeof(struct mcast_group_info)), GFP_KERNEL);
	if(!pMcastGrpInfo)
	{
		DPA_ERROR("%s::%d  failed to allocate memory \r\n", __func__, __LINE__);
		return ERR_NOT_ENOUGH_MEMORY;
	}

	INIT_LIST_HEAD(&pMcastGrpInfo->list); 
	DPA_INFO("%s(%d) : IP type %s\n", __func__,__LINE__,
			(bIsIPv6) ? "IPv6" : "IPv4");
	memset(&mcast4_group, 0, sizeof(mcast4_group));
	memset(&mcast6_group, 0, sizeof(mcast6_group));
	pMcastGrpInfo->mctype = bIsIPv6;
	if(pMcastGrpInfo->mctype == 0)
	{
		mcast4_group = (PMC4Command)mcast_cmd;
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		uiNoOfListeners = mcast4_group->num_output;
		pInIface = mcast4_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IP addr 0x%x,Dst IP addr 0x%x\n",
				__func__,__LINE__, uiNoOfListeners, mcast4_group->src_addr,
				mcast4_group->dst_addr);
	}
	else
	{
		mcast6_group = (PMC6Command)mcast_cmd;
		memcpy(pMcastGrpInfo->ipv6_saddr,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		uiNoOfListeners = mcast6_group->num_output;
		pInIface = mcast6_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__func__,__LINE__, uiNoOfListeners, mcast6_group->src_addr[0], mcast6_group->src_addr[1],
				mcast6_group->src_addr[2],mcast6_group->src_addr[3], 
				mcast6_group->dst_addr[0], mcast6_group->dst_addr[1],mcast6_group->dst_addr[2],
				mcast6_group->dst_addr[3]);
	}

	pMcastGrpInfo->grpid = -1; 
	strncpy(pMcastGrpInfo->ucIngressIface, pInIface, IF_NAME_SIZE-1);

	if((uiNoOfListeners) > MC_MAX_LISTENERS_PER_GROUP)
	{
		DPA_ERROR("%s::%d Exceeding max members(%d) in the group \r\n",
				__func__, __LINE__,MC_MAX_LISTENERS_PER_GROUP);
		iRet	= ERR_MC_MAX_LISTENERS_PER_GROUP;
		goto err_ret;
	}

	if((iRet = GetMcastGrpId(pMcastGrpInfo, IngressIface))!= -1)
	{
		if (strncmp(pMcastGrpInfo->ucIngressIface, 
					IngressIface, IF_NAME_SIZE))
		{
			DPA_ERROR("%s::%d multiple ingress interfaces(%s, existing %s) are not allowed \n"
					"for the same set of source IP and dest.IP pair \r\n",
					__func__, __LINE__,pMcastGrpInfo->ucIngressIface,
					IngressIface);
			iRet	= -1;
			goto err_ret;
		}
		kfree(pMcastGrpInfo);
		DPA_INFO("%s(%d) GetMcastGrpId returned %d, calling update_mcast_grp\n",
				__func__,__LINE__,iRet);
		return (cdx_update_mcast_group(mcast_cmd, bIsIPv6));
	}

	if ((pMcastGrpInfo->grpid = GetNewMcastGrpId(pMcastGrpInfo->mctype)) == -1)
	{
		DPA_ERROR("Exceeding max number of multicast entries\n");
		/* iRet currently equals -1 here only as a side-effect of
		 * line 518's `if((iRet = GetMcastGrpId(...))!= -1)` test —
		 * a refactor of that idiom would silently regress this path
		 * to NO_ERR. Set explicitly. */
		iRet = -1;
		goto err_ret;
	}
	memset(&InsEntryInfo, 0, sizeof(struct ins_entry_info));
	pInsEntryInfo = &InsEntryInfo;
	memset(&RtEntry,0, sizeof(RouteEntry));
	pRtEntry = &RtEntry; 

	if(pMcastGrpInfo->mctype == 0)
	{
		pRtEntry->dstmac[0] = 0x01;
		pRtEntry->dstmac[1] = 0x00;
		pRtEntry->dstmac[2] = 0x5E;
		pRtEntry->dstmac[3] = (mcast4_group->dst_addr >> 8)&0x7f;
		pRtEntry->dstmac[4] = (mcast4_group->dst_addr >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast4_group->dst_addr >> 24) & 0xff;
		tbl_type = IPV4_MULTICAST_TABLE;
	}
	else
	{
		pRtEntry->dstmac[0] = 0x33;
		pRtEntry->dstmac[1] = 0x33;
		pRtEntry->dstmac[2] = (mcast6_group->dst_addr[3]) &  0xff;
		pRtEntry->dstmac[3] = (mcast6_group->dst_addr[3] >> 8) & 0xff;
		pRtEntry->dstmac[4] = (mcast6_group->dst_addr[3] >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast6_group->dst_addr[3] >> 24) & 0xff;
		tbl_type = IPV6_MULTICAST_TABLE;
	}

	/* Subscribe the ingress netdev to the group's L2 multicast MAC
	 * BEFORE any HW state is committed. Sequencing this first means a
	 * subscribe failure (e.g. -ENOMEM under memory pressure / failslab)
	 * unwinds with no FMAN-side cleanup needed — keeping the err_ret
	 * cascade simple and (per ISSUES.md M9) reachable only via paths
	 * that haven't installed an EHASH entry yet. */
	{
		uint8_t mac[ETH_ALEN];
		cdx_mcast_compute_mac(pMcastGrpInfo, mac);
		iRet = cdx_mcast_subscribe_ingress_mac(
			pMcastGrpInfo->ucIngressIface, mac);
		if (iRet) {
			DPA_ERROR("%s::%d MAC filter subscription failed (%d)\n",
				  __func__, __LINE__, iRet);
			goto err_ret;
		}
	}

	pMcastGrpInfo->uiListenerCnt = 0;

	for (ii=0; ii< uiNoOfListeners; ii++)
	{
		if(pMcastGrpInfo->mctype == 0)
			pListener = &mcast4_group->output_list[ii];
		else
			pListener = &mcast6_group->output_list[ii];

		DPA_INFO("%s(%d) creating table entry of mcast member %s\n",
				__func__,__LINE__, pListener->output_device_str);
		tbl_entry = create_exthash_entry4mcast_member(pRtEntry, pInsEntryInfo, pListener, tbl_entry, tbl_type);
		if (!tbl_entry)
		{
			DPA_ERROR("%s(%d) : create_exthash_entry4mcast_member failed\n",
					__func__, __LINE__);
			/* See note at the GetNewMcastGrpId failure above —
			 * don't depend on iRet's value carried in from the
			 * GetMcastGrpId-test side-effect. */
			iRet = -1;
			goto err_ret;
		}
		pMcastGrpInfo->members[member_id].bIsValidEntry = 1;
		strncpy(pMcastGrpInfo->members[member_id].if_info, pListener->output_device_str,IF_NAME_SIZE-1);
		pMcastGrpInfo->members[member_id].member_id = member_id;
		pMcastGrpInfo->members[member_id].tbl_entry= tbl_entry;
		pMcastGrpInfo->uiListenerCnt++;
		member_id++;
	}

	if(pMcastGrpInfo->mctype == 0)
		iRet = cdx_add_mcast_table_entry(mcast4_group, pMcastGrpInfo);
	else
		iRet = cdx_add_mcast_table_entry(mcast6_group, pMcastGrpInfo);

	if(iRet != 0)
	{
		DPA_ERROR(" %s::%d Adding mcast table entry failed \r\n", __func__, __LINE__);
		goto err_ret;
	}

	AddToMcastGrpList(pMcastGrpInfo);
	return 0;

err_ret:
	if(pMcastGrpInfo)
	{
		/* Undo the dev_mc_add() done above (if it ran). dev_mc_del
		 * is refcounted and silently no-ops when the address isn't
		 * present, so calling it unconditionally is safe — covers
		 * both "subscribe failed at the call site" and "subscribe
		 * succeeded then a later step failed". */
		{
			uint8_t mac[ETH_ALEN];
			cdx_mcast_compute_mac(pMcastGrpInfo, mac);
			cdx_mcast_unsubscribe_ingress_mac(
				pMcastGrpInfo->ucIngressIface, mac);
		}
		/* Use a local for the cleanup return; reassigning iRet here
		 * would clobber the original failure code set by whichever
		 * arm of the create path jumped here. cdx_free_exthash_mcast_members
		 * always returns 0 today, so a reassignment would make every
		 * err_ret path return "success" to the caller even though the
		 * group has been torn down. */
		int free_rc = cdx_free_exthash_mcast_members(pMcastGrpInfo);
		if (free_rc)
			DPA_ERROR("%s::%d mcast group deletion failed (rc=%d)\n",
				  __func__, __LINE__, free_rc);
		/* Defense in depth (ISSUES.md M9): pMcastGrpInfo->pCtEntry
		 * is only assigned inside cdx_add_mcast_table_entry's
		 * success arm at line ~435, after which the outer caller
		 * returns 0 without taking err_ret — so today this branch
		 * is unreachable. Any future path that lands here with
		 * pCtEntry already wired in would silently leak the CT
		 * chain; freeing it here keeps the err_ret invariant
		 * "no caller-owned allocation survives" intact. */
		if (pMcastGrpInfo->pCtEntry) {
			if (pMcastGrpInfo->pCtEntry->pRtEntry)
				kfree(pMcastGrpInfo->pCtEntry->pRtEntry);
			kfree(pMcastGrpInfo->pCtEntry);
			pMcastGrpInfo->pCtEntry = NULL;
		}
		kfree(pMcastGrpInfo);
	}
	return iRet;
}

int cdx_free_exthash_mcast_members(struct mcast_group_info *pMcastGrpInfo)
{
	unsigned int ii;
	FreeMcastGrpID(pMcastGrpInfo->mctype, pMcastGrpInfo->grpid);
	/* Walk every slot in members[], not just the first uiListenerCnt:
	 * after a partial REMOVE followed by UPDATE, valid entries can sit
	 * at any index, with invalid slots interleaved. Using uiListenerCnt
	 * as the loop bound misses the high-index valid entries and leaks
	 * their ExternalHashTable allocations. Filter by bIsValidEntry
	 * (the invariant the rest of this file uses for slot ownership). */
	for (ii = 0; ii < MC_MAX_LISTENERS_PER_GROUP; ii++)
	{
		if (pMcastGrpInfo->members[ii].bIsValidEntry &&
		    pMcastGrpInfo->members[ii].tbl_entry)
			ExternalHashTableEntryFree(pMcastGrpInfo->members[ii].tbl_entry);
	}
	return 0;
}

/* Failure-path twin of cdx_free_exthash_mcast_members(): same walk over
 * every members[] slot with the same bIsValidEntry filter, but the
 * entries go into the quarantine instead of back to the allocator,
 * because no HC barrier has proven the ucode is done walking them.
 * Slots are cleared so nothing can reach the parked memory through the
 * group again - the group itself is freed right after. */
static void mc_quarantine_members(struct mcast_group_info *pMcastGrpInfo)
{
	unsigned int ii;

	for (ii = 0; ii < MC_MAX_LISTENERS_PER_GROUP; ii++)
	{
		if (!pMcastGrpInfo->members[ii].bIsValidEntry)
			continue;
		mc_quarantine_entry(pMcastGrpInfo->members[ii].tbl_entry);
		pMcastGrpInfo->members[ii].tbl_entry = NULL;
		pMcastGrpInfo->members[ii].bIsValidEntry = 0;
	}
}

/* Whole-group teardown, shared by the group-DELETE command path and the
 * module-exit drain so the two can't diverge.
 *
 * The caller must already have unlinked pMcastGrpInfo from its bucket list.
 * delete_entry_from_classif_table() and cdx_free_exthash_mcast_members()
 * reach ExternalHashTable* helpers that issue FMAN host commands, and
 * EnQFrm() waits for each completion with an XX_UDelay(100) busy-loop
 * (sdk_fman .../Peripherals/FM/HC/hc.c) — up to ~10 ms of spinning per
 * command. That is legal under a spinlock (FmPcdLock is spin_lock_irqsave,
 * not a sleeping lock) but wasteful, and the group-DELETE path already runs
 * this teardown unlocked. Once the node is off the list no reader
 * (cdx_mc_query.c) can find it, which is what makes that safe.
 *
 * Order is load-bearing: the classifier entry leaves the hardware table
 * first, then the listener table entries, then the CT/route backing memory.
 * Freeing in the other direction would leave the ucode replicating through
 * entries whose memory has already been handed back to the allocator. */
static void cdx_mcast_group_destroy(struct mcast_group_info *pMcastGrpInfo)
{
	uint8_t mac[ETH_ALEN];
	int rc;

	/* Delete entry in ct table */
	rc = delete_entry_from_classif_table(pMcastGrpInfo->pCtEntry);
	if (rc == SUCCESS)
	{
		/* ExternalHashTableDeleteKey() syncs the PCD before
		 * reporting success, so the classifier entry - and the
		 * listener chain hanging off it - is provably out of reach
		 * of the ucode walkers. Release the members outright, and
		 * clear the quarantine backlog on the strength of that same
		 * barrier. */
		cdx_free_exthash_mcast_members(pMcastGrpInfo);
		mc_quarantine_free_all();
	}
	else if (rc == EN_EHASH_DELETE_UNSYNCED)
	{
		/* The classifier key left the table but the HC barrier
		 * failed, so the listener entries are in exactly the state
		 * the per-listener REMOVE path quarantines: gone from
		 * software, unproven in hardware. Park them rather than free
		 * them. The group id is released either way - it is pure
		 * software bookkeeping, and cdx_free_exthash_mcast_members()
		 * (skipped here) is where it normally happens.
		 *
		 * The classifier's own table entry is in the same
		 * unlinked-but-unsynced state as the members, so it is parked
		 * the same way instead of being orphaned; the hw_ct wrapper is
		 * pure software with no hardware reference and can go now. */
		FreeMcastGrpID(pMcastGrpInfo->mctype, pMcastGrpInfo->grpid);
		mc_quarantine_members(pMcastGrpInfo);
		if (pMcastGrpInfo->pCtEntry->ct)
		{
			mc_quarantine_entry(pMcastGrpInfo->pCtEntry->ct->handle);
			kfree(pMcastGrpInfo->pCtEntry->ct);
			pMcastGrpInfo->pCtEntry->ct = NULL;
		}
	}
	else
	{
		/* The classifier key was NOT provably unlinked (invalid table
		 * state, or no memory for a replacement cumulative node), so
		 * the ucode may still resolve it and replicate through the
		 * listener chain indefinitely. These entries must never reach
		 * the allocator - not now, and not via the quarantine, whose
		 * backlog is freed on the next successful sync. Leak them
		 * loudly and clear the slots so nothing else can. The group id
		 * is software bookkeeping and is released regardless. */
		unsigned int ii, leaked = 0;

		FreeMcastGrpID(pMcastGrpInfo->mctype, pMcastGrpInfo->grpid);
		for (ii = 0; ii < MC_MAX_LISTENERS_PER_GROUP; ii++)
		{
			if (!pMcastGrpInfo->members[ii].bIsValidEntry)
				continue;
			pMcastGrpInfo->members[ii].tbl_entry = NULL;
			pMcastGrpInfo->members[ii].bIsValidEntry = 0;
			leaked++;
		}
		/* The classifier's table entry leaks with the members (it may
		 * still be linked); its software-only hw_ct wrapper does not
		 * need to. */
		if (pMcastGrpInfo->pCtEntry->ct)
		{
			kfree(pMcastGrpInfo->pCtEntry->ct);
			pMcastGrpInfo->pCtEntry->ct = NULL;
		}
		DPA_ERROR("%s::classifier delete failed pre-unlink (rc %d), leaking %u listener entries + the classifier entry\n",
			  __func__, rc, leaked);
	}
	if (pMcastGrpInfo->pCtEntry)
	{
		if (pMcastGrpInfo->pCtEntry->pRtEntry)
			kfree(pMcastGrpInfo->pCtEntry->pRtEntry);
		kfree(pMcastGrpInfo->pCtEntry);
		pMcastGrpInfo->pCtEntry = NULL;
	}
	/* Undo the dev_mc_add() from the create path so the FMAN MAC's
	 * hardware multicast filter doesn't keep accepting frames for a
	 * now-gone group. dev_mc_add/del refcount, so groups sharing a MAC
	 * (IPv4 32→23-bit collisions) decrement cleanly. */
	cdx_mcast_compute_mac(pMcastGrpInfo, mac);
	cdx_mcast_unsubscribe_ingress_mac(pMcastGrpInfo->ucIngressIface, mac);
	kfree(pMcastGrpInfo);
}

void cdx_exthash_update_first_mcast_member_addr(struct en_exthash_tbl_entry *temp_entry,
		uint64_t listener_phyaddri,
		struct en_exthash_tbl_entry *listener);

int cdx_update_mcast_group(void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	RouteEntry *pRtEntry, RtEntry;
	struct ins_entry_info *pInsEntryInfo, InsEntryInfo;
	struct mcast_group_info *pMcastGrpInfo, McastGrpInfo;
	struct mcast_group_info *pTempGrpInfo;
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	unsigned int uiNoOfListeners, uiHash;
	int iRet, ii;
	int member_id;
	MC4Output   *pListener;
	char *pInIface;
	uint32_t tbl_type;
	uint64_t phyaddr;


	memset(&InsEntryInfo, 0, sizeof(struct ins_entry_info));
	pInsEntryInfo = &InsEntryInfo;
	/* The create path zeroes its stack RouteEntry; without this the
	 * vlan_filter_flags read by dpa_get_tx_info_by_itf is stack garbage. */
	memset(&RtEntry, 0, sizeof(RouteEntry));
	pRtEntry = &RtEntry;
	mcast4_group = NULL;
	mcast6_group = NULL;
	iRet = 0;

	if(bIsIPv6)
		mcast6_group = (PMC6Command)mcast_cmd;
	else
		mcast4_group = (PMC4Command)mcast_cmd;

	pMcastGrpInfo = &McastGrpInfo;
	memset(pMcastGrpInfo, 0,sizeof(struct mcast_group_info));

	pMcastGrpInfo->mctype = bIsIPv6;
	if(pMcastGrpInfo->mctype == 0)
	{
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		pMcastGrpInfo->mctype  = 0;
		uiNoOfListeners = mcast4_group->num_output;
		pInIface = mcast4_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IP addr 0x%x,Dst IP addr 0x%x\n",
				__func__,__LINE__, uiNoOfListeners, mcast4_group->src_addr,
				mcast4_group->dst_addr);
	}
	else
	{
		memcpy(pMcastGrpInfo->ipv6_saddr,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		pMcastGrpInfo->mctype  = 1;
		uiNoOfListeners = mcast6_group->num_output;
		pInIface = mcast6_group->input_device_str;
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__func__,__LINE__, uiNoOfListeners, mcast6_group->src_addr[0], mcast6_group->src_addr[1],
				mcast6_group->src_addr[2],mcast6_group->src_addr[3], 
				mcast6_group->dst_addr[0], mcast6_group->dst_addr[1],mcast6_group->dst_addr[2],
				mcast6_group->dst_addr[3]);
	}
	strncpy(pMcastGrpInfo->ucIngressIface, pInIface, IF_NAME_SIZE-1);

	if((pTempGrpInfo = GetMcastGrp(pMcastGrpInfo)) == NULL)
	{
		DPA_ERROR("%s::%d multicast group does not exist \r\n", __func__, __LINE__);
		iRet = -1;
		goto err_ret;
	}

	pMcastGrpInfo = pTempGrpInfo;

	/* Reclaim anything a previous failed barrier left parked before
	 * touching the chain again. Cheap: no-op unless something is
	 * pending, and the group is resolved so the PCD handle is valid. */
	mc_quarantine_drain(pMcastGrpInfo->pCtEntry->ct->td);

	if((uiNoOfListeners +  pMcastGrpInfo->uiListenerCnt) > MC_MAX_LISTENERS_PER_GROUP)
	{
		DPA_ERROR("%s::%d Exceeding max members(%d) in the group \r\n",
				__func__, __LINE__,MC_MAX_LISTENERS_PER_GROUP);
		iRet = ERR_MC_MAX_LISTENERS_PER_GROUP;
		goto err_ret;
	}

	if(!bIsIPv6)
	{
		pRtEntry->dstmac[0] = 0x01;
		pRtEntry->dstmac[1] = 0x00;
		pRtEntry->dstmac[2] = 0x5E;
		pRtEntry->dstmac[3] = (mcast4_group->dst_addr >> 8)&0x7f;
		pRtEntry->dstmac[4] = (mcast4_group->dst_addr >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast4_group->dst_addr >> 24) & 0xff;
		tbl_type = IPV4_MULTICAST_TABLE;
	}
	else
	{
		pRtEntry->dstmac[0] = 0x33;
		pRtEntry->dstmac[1] = 0x33;
		pRtEntry->dstmac[2] = (mcast6_group->dst_addr[3]) &  0xff;
		pRtEntry->dstmac[3] = (mcast6_group->dst_addr[3] >> 8) & 0xff;
		pRtEntry->dstmac[4] = (mcast6_group->dst_addr[3] >> 16) & 0xff;
		pRtEntry->dstmac[5] = (mcast6_group->dst_addr[3] >> 24) & 0xff;
		tbl_type = IPV6_MULTICAST_TABLE;
	}

	for(ii=0 ; ii < uiNoOfListeners; ii++)
	{
		if(bIsIPv6)
		{
			pListener = &(mcast6_group->output_list[ii]);
		}
		else
		{
			pListener = &(mcast4_group->output_list[ii]);
		}

		if((member_id = Cdx_GetMcastMemberId(pListener->output_device_str ,pMcastGrpInfo)) != -1)
		{
			DPA_ERROR("%s::%d member:%s already exists in the mcgroup \r\n",
					__func__, __LINE__, pListener->output_device_str );
			iRet = -1;
			goto err_ret;    
		}

		DPA_INFO("%s(%d) creating table entry of mcast member %s\n",
				__func__,__LINE__, pListener->output_device_str);

		if( (member_id = Cdx_GetMcastMemberFreeIndex(pMcastGrpInfo)) == -1)
		{
			DPA_ERROR("%s::%d Exceeding max members(%d) in the group \r\n",
					__func__, __LINE__,MC_MAX_LISTENERS_PER_GROUP);
			iRet = -1;
			goto err_ret;
		}

		tbl_entry = create_exthash_entry4mcast_member(pRtEntry, pInsEntryInfo, pListener, NULL, tbl_type);
		if (!tbl_entry)
		{
			DPA_ERROR("%s(%d) : create_exthash_entry4mcast_member failed\n",
					__func__, __LINE__);
			/* Preserve a non-zero status all the way back to the
			 * FCI handler. iRet is initialised to 0 at function
			 * entry and the loop body only sets it on error
			 * branches, so without an explicit assignment here
			 * the err_ret label returns 0 = NO_ERR even though
			 * the listener add failed and any prior listeners
			 * in this UPDATE batch are about to be torn down. */
			iRet = -1;
			goto err_ret;
		}
		phyaddr = XX_VirtToPhys(tbl_entry);
		DPA_INFO("%s(%d) member_id %d, tbl_entry %p, phy_tbl_entry %p\n",
				__func__,__LINE__, member_id, tbl_entry, (uint64_t *)phyaddr);
		if(pMcastGrpInfo->mctype == 0)
		{
			uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
			spin_lock(&mc4_spinlocks[uiHash]);
		}
		else
		{
			uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
			spin_lock(&mc6_spinlocks[uiHash]);
		}
		pMcastGrpInfo->members[member_id].bIsValidEntry = 1;
		strncpy(pMcastGrpInfo->members[member_id].if_info, pListener->output_device_str,IF_NAME_SIZE-1);
		pMcastGrpInfo->members[member_id].member_id = member_id;
		pMcastGrpInfo->members[member_id].tbl_entry= tbl_entry;
		pMcastGrpInfo->uiListenerCnt++; 
		//fill next pointer info and link into chain
		//adjust the prev pointer in the old entry
		//fill next pointer physaddr for uCode

		cdx_exthash_update_first_mcast_member_addr((struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle, phyaddr,
				tbl_entry);
		if(pMcastGrpInfo->mctype == 0)
			spin_unlock(&mc4_spinlocks[uiHash]);
		else
			spin_unlock(&mc6_spinlocks[uiHash]);

	}

	tbl_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle;
#ifdef CDX_DPA_DEBUG
	{
		if (pMcastGrpInfo->mctype == 0)
			display_ehash_tbl_entry(&tbl_entry->hashentry, 10);
		else
			display_ehash_tbl_entry(&tbl_entry->hashentry, 34);
	}
#endif // CDX_DPA_DEBUG
err_ret:
	return iRet;
}

int cdx_delete_mcast_group_member( void *mcast_cmd, int bIsIPv6)
{
	PMC4Command mcast4_group;
	PMC6Command mcast6_group;
	int mcast_grpd, member_id;
	struct mcast_group_info  McastGrpInfo, *pMcastGrpInfo;
	int iRet = 0;
	MC4Output *pListener;
	int ii;
	unsigned int uiNoOfListeners, uiHash;
	struct mcast_group_info *pTempGrpInfo;
	struct en_exthash_tbl_entry *tbl_entry, *temp_entry;
	uint64_t phyaddr;
	struct en_ehash_replicate_param *replicate_params; 
	ucode_phyaddr_t tmp_val;

	mcast4_group = NULL;
	mcast6_group = NULL;

	if(bIsIPv6 == 0)
		mcast4_group =  (PMC4Command)mcast_cmd;
	else 
		mcast6_group =  (PMC6Command)mcast_cmd;

	pMcastGrpInfo = &McastGrpInfo;

	INIT_LIST_HEAD(&pMcastGrpInfo->list); 
	pMcastGrpInfo->mctype = bIsIPv6;
	if(pMcastGrpInfo->mctype == 0)
	{
		DPA_INFO("%s(%d) IPv4 \n",__func__,__LINE__);
		pMcastGrpInfo->ipv4_saddr = mcast4_group->src_addr;
		pMcastGrpInfo->ipv4_daddr = mcast4_group->dst_addr;
		pMcastGrpInfo->mctype  = 0;
		uiNoOfListeners = mcast4_group->num_output;
		strncpy(pMcastGrpInfo->ucIngressIface,
				mcast4_group->input_device_str, IF_NAME_SIZE-1);
		DPA_INFO("%s(%d) listeners %d, Src IP addr 0x%x,Dst IP addr 0x%x\n",
				__func__,__LINE__, uiNoOfListeners, mcast4_group->src_addr,
				mcast4_group->dst_addr);
	}
	else
	{
		DPA_INFO("%s(%d) IPv6 \n",__func__,__LINE__);
		memcpy(pMcastGrpInfo->ipv6_saddr,mcast6_group->src_addr, IPV6_ADDRESS_LENGTH);
		memcpy(pMcastGrpInfo->ipv6_daddr,mcast6_group->dst_addr, IPV6_ADDRESS_LENGTH);
		pMcastGrpInfo->mctype  = 1;
		uiNoOfListeners = mcast6_group->num_output;
		strncpy(pMcastGrpInfo->ucIngressIface,
				mcast6_group->input_device_str, IF_NAME_SIZE-1);
		DPA_INFO("%s(%d) listeners %d, Src IPv6 addr 0x%x.%x.%x.%x,Dst IPv6 addr 0x%x.%x.%x.%x\n",
				__func__,__LINE__, uiNoOfListeners, mcast6_group->src_addr[0], mcast6_group->src_addr[1],
				mcast6_group->src_addr[2],mcast6_group->src_addr[3], 
				mcast6_group->dst_addr[0], mcast6_group->dst_addr[1],mcast6_group->dst_addr[2],
				mcast6_group->dst_addr[3]);
	}

	if((pTempGrpInfo = GetMcastGrp(pMcastGrpInfo)) == NULL)
	{
		DPA_ERROR("%s::%d multicast group does not exist \r\n", __func__, __LINE__);
		iRet = -1;
		goto err_ret;
	}

	pMcastGrpInfo = pTempGrpInfo;

	/* Reclaim anything a previous failed barrier left parked before
	 * touching the chain again. Cheap: no-op unless something is
	 * pending, and the group is resolved so the PCD handle is valid. */
	mc_quarantine_drain(pMcastGrpInfo->pCtEntry->ct->td);

	mcast_grpd = pMcastGrpInfo->grpid;

	/* Validate every listener in the request actually exists in the
	 * group before touching any state. The count-match fast path
	 * below (and the per-listener loop further down) used to assume
	 * the request was well-formed: REMOVE [foo] against a group
	 * { bar } whose count happened to equal 1 would hit the fast
	 * path and delete the whole group, even though `foo` was never
	 * a member (ISSUES.md M12). Validating up-front rejects mismatched
	 * requests atomically, before either path mutates members[] or
	 * unlinks the group.
	 *
	 * Also dedupe by tracking which members[] slot each requested
	 * name resolved to. A request like REMOVE [a, a] against
	 * { a, b } would otherwise validate twice against the same
	 * member_id, the count-match fast path would trigger, and the
	 * whole group would be wiped (ISSUES.md M13). MC_MAX_LISTENERS_PER_GROUP
	 * is 8 so a u8 bitmap fits the slot space exactly. */
	{
		uint8_t seen_members = 0;
		int found_id;
		BUILD_BUG_ON(MC_MAX_LISTENERS_PER_GROUP > 8);
		for (ii = 0; ii < uiNoOfListeners; ii++) {
			if (bIsIPv6)
				pListener = &(mcast6_group->output_list[ii]);
			else
				pListener = &(mcast4_group->output_list[ii]);
			found_id = Cdx_GetMcastMemberId(
				pListener->output_device_str, pMcastGrpInfo);
			if (found_id == -1) {
				DPA_ERROR("%s::%d member:%s does not exist in the mcgroup\n",
					  __func__, __LINE__,
					  pListener->output_device_str);
				iRet = -1;
				goto err_ret;
			}
			if (seen_members & (1u << found_id)) {
				DPA_ERROR("%s::%d duplicate listener %s in REMOVE\n",
					  __func__, __LINE__,
					  pListener->output_device_str);
				iRet = -1;
				goto err_ret;
			}
			seen_members |= (1u << found_id);
		}
	}

	if(pMcastGrpInfo->uiListenerCnt == uiNoOfListeners)
	{
		/* Unlink the group from the per-bucket list under the same
		 * spinlock that cdx_mc_query.c readers hold during traversal.
		 * Once we release the lock, no reader can find the node, so
		 * the rest of teardown (HW table evict + listener tbl_entry
		 * frees + pCtEntry/pRtEntry/group frees) runs unlocked — the
		 * ExternalHashTable* helpers issue hardware completions and
		 * can sleep, which the per-listener REMOVE path at lines
		 * 967-975 likewise performs outside the spinlock. */
		if (pMcastGrpInfo->mctype == 0) {
			uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
			spin_lock(&mc4_spinlocks[uiHash]);
			list_del(&(pMcastGrpInfo->list));
			spin_unlock(&mc4_spinlocks[uiHash]);
		} else {
			uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
			spin_lock(&mc6_spinlocks[uiHash]);
			list_del(&(pMcastGrpInfo->list));
			spin_unlock(&mc6_spinlocks[uiHash]);
		}

		cdx_mcast_group_destroy(pMcastGrpInfo);
		return 0;
	}


	for(ii=0 ; ii < uiNoOfListeners; ii++)
	{
		if(bIsIPv6)
			pListener = &(mcast6_group->output_list[ii]);
		else
			pListener = &(mcast4_group->output_list[ii]);

		if((member_id = Cdx_GetMcastMemberId(pListener->output_device_str ,pMcastGrpInfo)) == -1)
		{
			DPA_ERROR("%s::%d member:%s does not exist in the mcgroup \r\n",
					__func__, __LINE__, pListener->output_device_str );
			iRet = -1;
			goto err_ret;    
		}

		if(pMcastGrpInfo->mctype == 0)
		{
			uiHash = HASH_MC4(pMcastGrpInfo->ipv4_daddr);
			spin_lock(&mc4_spinlocks[uiHash]);
		}
		else
		{
			uiHash = HASH_MC6((void *)(pMcastGrpInfo->ipv6_daddr));
			spin_lock(&mc6_spinlocks[uiHash]);
		}
		tbl_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->members[member_id].tbl_entry;

		temp_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle;
		replicate_params = (struct en_ehash_replicate_param *)temp_entry->replicate_params;

		if (tbl_entry)
		{
			/* flags is stored big-endian (cpu_to_be16 at entry build), so
			 * SET_INVALID_ENTRY's host-order 1<<15 would set BE bit 7 — an
			 * OPC_OFFSET bit — corrupting the live entry instead of
			 * invalidating it. The reference driver switched to a
			 * swap-modify-swap of the whole word for the same reason. */
			tbl_entry->hashentry.flags |= cpu_to_be16(1 << 15);
			if (tbl_entry == replicate_params->first_listener_entry)  // first listener
			{
				phyaddr = XX_VirtToPhys(tbl_entry->next);
				tmp_val.rsvd = 0;
				tmp_val.addr_hi = cpu_to_be16((phyaddr >> 32) & 0xffff);
				tmp_val.addr_lo = cpu_to_be32(phyaddr  & 0xffffffff);
				replicate_params->first_member_flow_addr =  tmp_val.addr;
				replicate_params->first_listener_entry = tbl_entry->next;
				if (tbl_entry->next)
					tbl_entry->next->prev = NULL;
			} 
			else 
			{
				temp_entry =  tbl_entry->prev;
				if (tbl_entry->next)
					(tbl_entry->next)->prev = temp_entry;
				temp_entry->next = tbl_entry->next;
				tmp_val.rsvd = temp_entry->hashentry.flags;
				tmp_val.addr_hi = tbl_entry->hashentry.next_entry_hi;
				tmp_val.addr_lo = tbl_entry->hashentry.next_entry_lo;
				temp_entry->hashentry.next_entry = tmp_val.addr;
			}
		}

		pMcastGrpInfo->members[member_id].bIsValidEntry = 0;
		pMcastGrpInfo->uiListenerCnt -= 1;
		pMcastGrpInfo->members[member_id].tbl_entry = NULL;
		if(pMcastGrpInfo->mctype == 0)
			spin_unlock(&mc4_spinlocks[uiHash]);
		else
			spin_unlock(&mc6_spinlocks[uiHash]);
		if (mc_hcsync(pMcastGrpInfo->pCtEntry->ct->td)) {
			DPA_ERROR("%s::FmPcdHcSync failed\n", __func__);
			/* The splice above already happened, so the entry is
			 * out of the chain but has no barrier proving the
			 * ucode left it. It cannot be freed here and cannot
			 * be unlinked a second time. Park it; the next
			 * mutator that reaches this PCD reclaims it.
			 *
			 * Abandon the rest of the batch: a sync failure is a
			 * property of the HC channel, not of this listener,
			 * so every remaining member would fail the same way
			 * and pile up more quarantined entries. */
			mc_quarantine_entry(tbl_entry);
			return -1;
		}
		ExternalHashTableEntryFree(tbl_entry);
		/* That sync is a barrier for the whole PCD, not just this
		 * entry - anything parked by an earlier failure is now
		 * provably walker-free too, with no second round-trip. */
		mc_quarantine_free_all();
	}

	tbl_entry = (struct en_exthash_tbl_entry *)pMcastGrpInfo->pCtEntry->ct->handle;
#ifdef CDX_DPA_DEBUG
	if (pMcastGrpInfo->mctype == 0)
		display_ehash_tbl_entry(&tbl_entry->hashentry, 10);
	else
		display_ehash_tbl_entry(&tbl_entry->hashentry, 34);
#endif // CDX_DPA_DEBUG
err_ret:
	return iRet;
}


void cdx_exthash_update_first_mcast_member_addr(struct en_exthash_tbl_entry *temp_entry,
		uint64_t listener_phyaddr, 
		struct en_exthash_tbl_entry *listener)
{
	struct en_ehash_replicate_param *param = 
		(struct en_ehash_replicate_param *)temp_entry->replicate_params;
	struct en_exthash_tbl_entry *entry;
	ucode_phyaddr_t tmp_val;

	if (temp_entry->replicate_params)
	{
		listener->hashentry.next_entry_hi = param->first_member_flow_addr_hi;
		listener->hashentry.next_entry_lo = param->first_member_flow_addr_lo;
		tmp_val.rsvd = 0;
		tmp_val.addr_hi = cpu_to_be16((listener_phyaddr >> 32) & 0xffff);
		tmp_val.addr_lo = cpu_to_be32(listener_phyaddr  & 0xffffffff);
		/* The freshly built listener entry (opcodes, params, and the
		 * next_entry chain words written just above) sits in coherent
		 * DDR that FMAN walks the moment first_member_flow_addr below
		 * points at it. This publishes into a live chain — the bucket
		 * spinlock held by the caller only orders CPU accesses, not
		 * FMAN's. Same hazard as the ADD-path publish in
		 * cdx_create_hw_entry; drain the store buffer first. */
		wmb();
		param->first_member_flow_addr = tmp_val.addr;
		entry = (struct en_exthash_tbl_entry *)param->first_listener_entry;
		DPA_INFO("%s(%d) updated first_member_flow_addr %p, next_entry addr %p \n",
				__func__,__LINE__,(uint64_t*)param->first_member_flow_addr,
				(uint64_t *)listener->hashentry.next_entry);
		if (entry)
		{
			entry->prev = listener;
		}
		listener->next = param->first_listener_entry;
		param->first_listener_entry = listener;
		return;

	}
}


static int MC6_Command_Handler(PMC6Command cmd)
{
	int rc = NO_ERR;
	int reset_action = 0;
	bool locked = false;

	if(cmd->action != ACTION_QUERY && cmd->action != ACTION_QUERY_CONT)
	{
		if(cmd->num_output > MC6_MAX_LISTENERS_IN_QUERY) {
			*((unsigned short *)cmd)= ERR_MC_MAX_LISTENERS;
			return sizeof(unsigned short);
		}
	}

	/* See MC4_Command_Handler — mutators run serialized via
	 * mc_mutators_mutex. Same mutex protects v4 and v6 paths
	 * because they share the same mutator functions. */
	if (mcast_action_is_mutator(cmd->action)) {
		mutex_lock(&mc_mutators_mutex);
		locked = true;
	}

	switch(cmd->action)
	{
		case CDX_MC_ACTION_ADD:
			rc = cdx_create_mcast_group((void *)cmd,1);
			break;
		case CDX_MC_ACTION_REMOVE:
			rc = cdx_delete_mcast_group_member((void *)cmd, 1);
			break;
		case CDX_MC_ACTION_UPDATE:
			rc = cdx_update_mcast_group((void *)cmd, 1);
			break;
		case ACTION_QUERY:
			reset_action = 1;
			fallthrough;
		case ACTION_QUERY_CONT:
			rc = MC6_Get_Next_Hash_Entry(cmd, reset_action);
			if(rc == NO_ERR)
			{
				rc = sizeof(MC6Command);
			}
			else
			{
				*((unsigned short *)cmd)= rc;
				rc = sizeof(unsigned short);
			}
			goto out;
		default:
			DPA_ERROR("%s::%d Command:%d not yet handled in cdx \r\n", __func__, __LINE__,cmd->action);
			rc = 0;
	}

	if ( rc == -1 )
		*((unsigned short *)cmd)= ERR_MC_CONFIG;
	else
		*((unsigned short *)cmd)= rc;

	rc = sizeof(unsigned short);

out:
	if (locked)
		mutex_unlock(&mc_mutators_mutex);
	return rc;
}

static int MC4_Command_Handler(PMC4Command cmd)
{
	int rc = NO_ERR;
	int reset_action=0;
	bool locked = false;

	/* some errors parsing on the command*/
	if(cmd->action != ACTION_QUERY && cmd->action != ACTION_QUERY_CONT)
	{
		if(cmd->num_output > MC4_MAX_LISTENERS_IN_QUERY) {
			*((unsigned short *)cmd) = ERR_MC_MAX_LISTENERS;
			return sizeof(unsigned short);
		}

		// IPv4 MC addresses must be 224.x.x.x through 239.x.x.x (i.e., high byte => 0xE0-0xEF)
		if ((ntohl(cmd->dst_addr) & 0xF0000000) != 0xE0000000)
		{
			DPA_ERROR("%s::%d \r\n", __func__, __LINE__);
			*((unsigned short *)cmd) = ERR_MC_INVALID_ADDR;
			return sizeof(unsigned short);
		}
	}

	/* Mutators run serialized — see mc_mutators_mutex docstring at
	 * the top of this file. cdx_create_mcast_group can recursively
	 * invoke cdx_update_mcast_group on the duplicate-group fast
	 * path, so the mutex is taken here at the dispatcher rather
	 * than inside each mutator (which would deadlock). */
	if (mcast_action_is_mutator(cmd->action)) {
		mutex_lock(&mc_mutators_mutex);
		locked = true;
	}

	switch(cmd->action)
	{
		case CDX_MC_ACTION_ADD:
			rc = cdx_create_mcast_group((void*)cmd, 0);
			break;
		case CDX_MC_ACTION_REMOVE:
			rc = cdx_delete_mcast_group_member((void *)cmd, 0);
			break;
		case CDX_MC_ACTION_UPDATE:
			rc = cdx_update_mcast_group((void *)cmd, 0);
			break;
		case ACTION_QUERY:
			reset_action = 1;
			fallthrough;
		case ACTION_QUERY_CONT:
			rc = MC4_Get_Next_Hash_Entry(cmd, reset_action);
			if(rc == NO_ERR)
			{
				rc = sizeof(MC4Command);
			}
			else
			{
				*((unsigned short *)cmd)= rc;
				rc = sizeof(unsigned short);
			}
			goto out;
		default:
			DPA_ERROR("%s::%d Command:%d not yet handled in cdx \r\n", __func__, __LINE__,cmd->action);
			rc = 0;
	}

	if ( rc == -1 )
		*((unsigned short *)cmd)= ERR_MC_CONFIG;
	else
		*((unsigned short *)cmd)= rc;

	rc = sizeof(unsigned short);

out:
	if (locked)
		mutex_unlock(&mc_mutators_mutex);
	return rc;
}

/*
 * MC wrapper discipline is different from the other control_*.c
 * subsystems: MC{4,6}_Command_Handler writes the status word (or
 * query reply payload) directly into pcmd and returns the total
 * reply length in bytes, not a U16 status code. The dispatcher's
 * contract is the other way around - handler returns a U16 status,
 * dispatcher stamps pcmd[0] afterwards. To fit, the wrapper reads
 * pcmd[0] back after the inner call (the value the inner just
 * wrote) and returns it, so the dispatcher's pcmd[0] = rc stamp
 * is a no-op. The inner-returned length flows through
 * *out_reply_len unchanged.
 *
 * Query-success path in the inner handler returns sizeof(MC{4,6}
 * Command) - larger than sizeof(U16) - and leaves pcmd holding
 * the query data. Matches PPPoE's "struct-as-reply-status word
 * replaces action field at offset 0" wire contract.
 */
static U16 mc4_multicast_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int rc_len;

	(void)cmd_len;
	rc_len = MC4_Command_Handler((PMC4Command)pcmd);
	*out_reply_len = (U16)rc_len;
	return *(U16 *)pcmd;
}

static U16 mc6_multicast_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int rc_len;

	(void)cmd_len;
	rc_len = MC6_Command_Handler((PMC6Command)pcmd);
	*out_reply_len = (U16)rc_len;
	return *(U16 *)pcmd;
}

static const struct cdx_cmd_spec mc4_cmd_table[] = {
	CDX_CMD_VAR(CMD_MC4_MULTICAST, MC4_MIN_COMMAND_SIZE, sizeof(MC4Command),
		    NULL, mc4_multicast_handle),
};

static const struct cdx_cmd_spec mc6_cmd_table[] = {
	CDX_CMD_VAR(CMD_MC6_MULTICAST, MC6_MIN_COMMAND_SIZE, sizeof(MC6Command),
		    NULL, mc6_multicast_handle),
};

U16 M_mc6_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(mc6_cmd_table, ARRAY_SIZE(mc6_cmd_table),
				cmd_code, cmd_len, pcmd);
}

U16 M_mc4_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(mc4_cmd_table, ARRAY_SIZE(mc4_cmd_table),
				cmd_code, cmd_len, pcmd);
}

#define MAX_MC4_ENTRIES 512
#define MAX_MC6_ENTRIES 512
int mc4_init(void)
{
	int ii;

	/* Allocate before publishing the handler: registering first would
	 * leave a live dispatch target over NULL tables if an allocation
	 * failed (mc4_exit is not run when this init fails). */
	mc4grp_ids = kzalloc((sizeof(uint8_t)*MAX_MC4_ENTRIES), GFP_KERNEL);
	if (!mc4grp_ids)
	{
		return -ENOMEM;
	}
	max_mc4grp_ids = MAX_MC4_ENTRIES;
	mc4_spinlocks = kzalloc((sizeof(spinlock_t) * MC4_NUM_HASH_ENTRIES), GFP_KERNEL);
	if (!mc4_spinlocks)
	{
		kfree(mc4grp_ids);
		mc4grp_ids =  NULL;
		return -ENOMEM;
	}
	for (ii = 0; ii < MC4_NUM_HASH_ENTRIES; ii++)
	{
		INIT_LIST_HEAD(&mc4_grp_list[ii]);
		spin_lock_init(&mc4_spinlocks[ii]);
	}
	set_cmd_handler(EVENT_MC4, M_mc4_cmdproc);

	return 0;
}

int mc6_init(void)
{
	int ii;

	/* Same ordering constraint as mc4_init(). */
	mc6grp_ids = kzalloc((sizeof(uint8_t)*MAX_MC6_ENTRIES), GFP_KERNEL);
	if (!mc6grp_ids)
	{
		return -ENOMEM;
	}
	max_mc6grp_ids = MAX_MC6_ENTRIES;
	mc6_spinlocks = kzalloc((sizeof(spinlock_t) * MC6_NUM_HASH_ENTRIES), GFP_KERNEL);
	if (!mc6_spinlocks)
	{
		kfree(mc6grp_ids);
		mc6grp_ids =  NULL;
		return -ENOMEM;
	}
	for (ii = 0; ii < MC6_NUM_HASH_ENTRIES; ii++)
	{
		INIT_LIST_HEAD(&mc6_grp_list[ii]);
		spin_lock_init(&mc6_spinlocks[ii]);
	}
	set_cmd_handler(EVENT_MC6, M_mc6_cmdproc);

	return 0;
}

/* Tears down every group still linked on a bucket array at module exit.
 *
 * Locking: concurrent FCI access is already excluded here — cdx_ctrl_deinit()
 * holds ctrl->mutex across the whole of cdx_cmdhandler_exit(), and
 * comcerto_fpp_send_command(), the only way into cdx_cmd_handler, takes that
 * same mutex. So the query walkers in cdx_mc_query.c cannot run against these
 * lists while the drain does. The bucket spinlocks are taken anyway: it keeps
 * the drain structurally identical to the group-DELETE path (unlink locked,
 * destroy unlocked) and leaves it correct without depending on that outer
 * exclusion, which nothing here enforces locally.
 *
 * Sibling exits (tunnel_exit, vlan_exit, pppoe_exit) drain their caches
 * lock-free only because those caches have no per-bucket lock at all; they
 * set no precedent for skipping one that exists.
 *
 * Must run before the caller frees the spinlock and group-id arrays:
 * cdx_free_exthash_mcast_members() releases each group's id back into
 * mc{4,6}grp_ids[]. */
static void cdx_mcast_drain_grp_lists(struct list_head *pGrpList,
				      spinlock_t *pLocks,
				      unsigned int uiNumBuckets)
{
	struct mcast_group_info *pMcastGrpInfo;
	unsigned int ii;

	if (!pLocks)
		return;

	for (ii = 0; ii < uiNumBuckets; ii++)
	{
		for (;;)
		{
			spin_lock(&pLocks[ii]);
			if (list_empty(&pGrpList[ii]))
			{
				spin_unlock(&pLocks[ii]);
				break;
			}
			pMcastGrpInfo = list_first_entry(&pGrpList[ii],
					struct mcast_group_info, list);
			list_del(&pMcastGrpInfo->list);
			spin_unlock(&pLocks[ii]);

			cdx_mcast_group_destroy(pMcastGrpInfo);
		}
	}
}

void mc4_exit(void)
{
	cdx_mcast_drain_grp_lists(mc4_grp_list, mc4_spinlocks,
				  MC4_NUM_HASH_ENTRIES);
	mc_quarantine_abandon();
	if (mc4_spinlocks)
	{
		kfree(mc4_spinlocks);
		mc4_spinlocks = NULL;
	}
	if (mc4grp_ids)
	{
		kfree(mc4grp_ids);
		mc4grp_ids = NULL;
	}
	return;
}

void mc6_exit(void)
{
	cdx_mcast_drain_grp_lists(mc6_grp_list, mc6_spinlocks,
				  MC6_NUM_HASH_ENTRIES);
	mc_quarantine_abandon();
	if (mc6_spinlocks)
	{
		kfree(mc6_spinlocks);
		mc6_spinlocks = NULL;
	}
	if (mc6grp_ids)
	{
		kfree(mc6grp_ids);
		mc6grp_ids = NULL;
	}

	return;
}

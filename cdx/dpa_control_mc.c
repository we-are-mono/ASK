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
/* Before cdx.h, as every other file that needs it does: it reaches the SDK's
 * own types_linux.h, which defines TRUE and FALSE and is -Werror about
 * redefining them. */
#include "portdefs.h"
#include "cdx.h"
#include "cdx_cmd_validator.h"
#include "list.h"
#include "cdx_common.h"
#include "misc.h"
#include "control_ipv4.h"
#include "dpa_control_mc.h"
#include "control_ipv6.h"
#include "cdx_flowtable_backend.h"
#include "cdx_mcast_backend.h"
#include "linux/netdevice.h"
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <net/ipv6.h>
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
 *   cdx_ehash quarantine (cdx_ehash.c)
 *      - Shared, cdx-wide backlog of table entries that are already
 *        out of the FMAN replication chain but not yet provably
 *        walker-free. This file only places entries into it and
 *        retires them; the lock discipline (none of its own; the
 *        mcast callers hold the FCI ctrl.mutex plus
 *        mc_mutators_mutex below, mc{4,6}_exit() runs at module
 *        unload with no handler in flight) is documented at the
 *        implementation.
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
 * The quarantine only ever engages when a host-command sync fails,
 * which on real hardware means a transient HC frame-pool shortage or a
 * wedged HC channel — neither reproducible on demand. This knob makes
 * the failure arm reachable from user space: write a decimal count to
 * /proc/cdx_mc_hcsync_fail and that many subsequent HC barriers issued
 * by this file report failure without touching the hardware. Reading
 * the file back reports the remaining armed count and the current
 * quarantine depth — the latter is cdx-wide, not mcast-only, since the
 * backlog is shared (cdx_ehash.c); the sibling knob at
 * /proc/fm_ehash_hcsync_fail arms the barriers inside
 * ExternalHashTableDeleteKey and reads back only its own armed count.
 *
 * Only this file's hand-issued barriers are affected here; the ones
 * inside ExternalHashTableDeleteKey and the rest of cdx run untouched,
 * so an armed knob cannot corrupt classifier state that this file does
 * not own.
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

/* Single funnel for every FMAN host-command barrier this file issues by
 * hand - i.e. the one that follows the open-coded listener splice.
 * Barriers issued inside the shared ehash helpers (DeleteKey's internal
 * sync, cdx_ehash_quarantine_drain()) are not routed through here and
 * are not affected by this file's knob.
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

/* The pending-free quarantine this file used to own now lives in
 * cdx_ehash.c (ISSUES.md A80, generalized by A95) - every classifier
 * path needs the same backlog, and one successful sync on the single
 * LS1046A PCD is a barrier for all of them, so a per-file backlog would
 * be strictly worse. cdx_ehash_quarantine_entry() / _free_all() /
 * _drain() / _abandon() are the entry points; the rationale and the
 * lock discipline are documented there. Mcast semantics are unchanged:
 * the listener splice below still parks on a failed barrier and still
 * reclaims on the next successful one.
 *
 * Note the drain barrier is issued by the shared helper, i.e. it is not
 * routed through mc_hcsync() and the knob below cannot force it to
 * fail. */

#ifdef CDX_DEBUG_MC_HCSYNC_FAIL
static int mc_hcsync_fail_show(struct seq_file *m, void *v)
{
	/* The quarantine depth is cdx-wide, not mcast-only, and is written
	 * only under the mutator serialization; this reader is outside it,
	 * and an aligned unsigned int cannot tear, so a plain snapshot is
	 * enough. */
	seq_printf(m, "armed=%d pending=%u\n",
		   atomic_read(&mc_hcsync_fail_countdown),
		   cdx_ehash_quarantine_pending());
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

/* The group's ingress device.
 *
 * A group whose owner holds the device uses it; one that only has a name looks
 * the name up. The distinction matters at teardown rather than at install: a
 * rename between the two would leave the name lookup finding nothing, and the
 * dev_mc_add() refcount would never be dropped. Returns NULL with nothing held
 * when the device is gone, which for an unsubscribe means the subscription
 * went with it. */
static struct net_device *cdx_mcast_ingress_dev(const struct mcast_group_info *grp,
						bool *put)
{
	*put = false;
	if (grp->in_dev)
		return grp->in_dev;
	*put = true;
	return dev_get_by_name(&init_net, grp->ucIngressIface);
}

static int cdx_mcast_subscribe_ingress_mac(const struct mcast_group_info *grp,
					   const uint8_t mac[ETH_ALEN])
{
	struct net_device *dev;
	bool put;
	int rc;

	dev = cdx_mcast_ingress_dev(grp, &put);
	if (!dev) {
		DPA_ERROR("%s::ingress netdev %s not found\n", __func__,
			  grp->ucIngressIface);
		return -ENODEV;
	}
	rc = dev_mc_add(dev, mac);
	if (put)
		dev_put(dev);
	if (rc)
		DPA_ERROR("%s::dev_mc_add(%s, %pM) failed: %d\n",
			  __func__, grp->ucIngressIface, mac, rc);
	return rc;
}

static void cdx_mcast_unsubscribe_ingress_mac(const struct mcast_group_info *grp,
					      const uint8_t mac[ETH_ALEN])
{
	struct net_device *dev;
	bool put;

	dev = cdx_mcast_ingress_dev(grp, &put);
	if (!dev) {
		/* Interface gone (e.g. removed before group teardown). The
		 * subscription is gone with it; nothing to undo. */
		return;
	}
	(void)dev_mc_del(dev, mac);
	if (put)
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

/* One listener of an FCI-described group.
 *
 * The legacy control plane names a registered interface, so both halves of the
 * listener -- the onif its classification and egress framing come from, and the
 * netdev whose MTU the enqueue opcode carries -- are found by that one name.
 * Whatever tags it carries are the interface's own, which is why no
 * encapsulation is named here; see create_exthash_entry4mcast_member().
 */
static struct en_exthash_tbl_entry *mcast_member_by_name(RouteEntry *pRtEntry,
		U8 *name, struct en_exthash_tbl_entry *prev_tbl_entry,
		uint32_t tbl_type)
{
	struct en_exthash_tbl_entry *tbl_entry;
	struct net_device *dev;
	POnifDesc onif_desc;

	onif_desc = get_onif_by_name(name);
	if (!onif_desc) {
		DPA_ERROR("%s::unable to get onif for iface %s\n", __func__, name);
		return NULL;
	}
	dev = dev_get_by_name(&init_net, (const char *)name);
	if (!dev) {
		DPA_ERROR("%s::no netdev for iface %s\n", __func__, name);
		return NULL;
	}
	tbl_entry = create_exthash_entry4mcast_member(pRtEntry, onif_desc, dev, NULL,
						     prev_tbl_entry, tbl_type);
	dev_put(dev);
	return tbl_entry;
}

/* The group's root entry: the classifier key, and the pointer to the head of
 * the listener chain the microcode replicates along.
 *
 * Everything this needs is already in the group -- the ingress interface name,
 * both addresses and the family -- so it takes no command. It used to read the
 * FCI message for the same three things, which meant the only way to build a
 * group's root entry was to have a wire message to hand. */
static int cdx_add_mcast_table_entry(struct mcast_group_info *pMcastGrpInfo)
{
	RouteEntry *pRtEntry;
	POnifDesc onif_desc;
	struct _tCtEntry *pCtEntry;
	int retval,ii;
	uint64_t phyaddr=0;
	char ucInterface[IF_NAME_SIZE];

	pRtEntry = NULL;
	pCtEntry = NULL;

	strncpy(ucInterface, pMcastGrpInfo->ucIngressIface, IF_NAME_SIZE-1);
	ucInterface[IF_NAME_SIZE-1] = '\0';

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
		pCtEntry->Saddr_v4 = pMcastGrpInfo->ipv4_saddr;
		pCtEntry->Daddr_v4 = pMcastGrpInfo->ipv4_daddr;
		pCtEntry->twin_Daddr = pCtEntry->Saddr_v4;
		pCtEntry->twin_Saddr = pCtEntry->Daddr_v4;
		pCtEntry->fftype = FFTYPE_IPV4;
	}
	else
	{
		memcpy(pCtEntry->Saddr_v6,pMcastGrpInfo->ipv6_saddr, IPV6_ADDRESS_LENGTH);
		memcpy(pCtEntry->Daddr_v6,pMcastGrpInfo->ipv6_daddr, IPV6_ADDRESS_LENGTH);
		pCtEntry->fftype = FFTYPE_IPV6;
	}

	/* By device where the owner holds one, by name otherwise -- the same
	 * split, and for the same reason, as a listener's resolution. */
	if (pMcastGrpInfo->in_dev) {
		struct dpa_iface_info *iface;

		iface = dpa_get_ifinfo_by_netdev(pMcastGrpInfo->in_dev);
		onif_desc = (iface && iface->itf_id < L2_MAX_ONIF) ?
			get_onif_by_index(iface->itf_id) : NULL;
		if (onif_desc && (!(onif_desc->flags & ENTRY_VALID) ||
				  !onif_desc->itf ||
				  onif_desc->itf->index != iface->itf_id))
			onif_desc = NULL;
	} else {
		onif_desc = get_onif_by_name(ucInterface);
	}
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
		iRet = cdx_mcast_subscribe_ingress_mac(pMcastGrpInfo, mac);
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
		tbl_entry = mcast_member_by_name(pRtEntry, pListener->output_device_str,
						 tbl_entry, tbl_type);
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

	iRet = cdx_add_mcast_table_entry(pMcastGrpInfo);

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
			cdx_mcast_unsubscribe_ingress_mac(pMcastGrpInfo, mac);
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
		cdx_ehash_quarantine_entry(pMcastGrpInfo->members[ii].tbl_entry);
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
		cdx_ehash_quarantine_free_all();
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
		 * unlinked-but-unsynced state as the members; parking it, and
		 * releasing its software-only hw_ct wrapper, is
		 * delete_entry_from_classif_table()'s job (ISSUES.md A95). */
		FreeMcastGrpID(pMcastGrpInfo->mctype, pMcastGrpInfo->grpid);
		mc_quarantine_members(pMcastGrpInfo);
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
		/* The classifier's own table entry leaks with the members (it
		 * may still be linked); delete_entry_from_classif_table()
		 * already abandoned it and released its software-only hw_ct
		 * wrapper. */
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
	cdx_mcast_unsubscribe_ingress_mac(pMcastGrpInfo, mac);
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
	cdx_ehash_quarantine_drain(pMcastGrpInfo->pCtEntry->ct->td);

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

		tbl_entry = mcast_member_by_name(pRtEntry, pListener->output_device_str,
						 NULL, tbl_type);
		if (!tbl_entry)
		{
			DPA_ERROR("%s(%d) : create_exthash_entry4mcast_member failed\n",
					__func__, __LINE__);
			/* Preserve a non-zero status all the way back to the
			 * FCI handler. iRet is initialised to 0 at function
			 * entry and the loop body only sets it on error
			 * branches, so without an explicit assignment here
			 * the err_ret label returns 0 = NO_ERR even though
			 * the listener add failed.
			 *
			 * Note what the caller is NOT told: listeners earlier
			 * in this batch are already spliced into the live
			 * chain and keep replicating, because err_ret unwinds
			 * nothing. See ISSUES.md A156. */
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
	cdx_ehash_quarantine_drain(pMcastGrpInfo->pCtEntry->ct->td);

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
			cdx_ehash_quarantine_entry(tbl_entry);
			return -1;
		}
		ExternalHashTableEntryFree(tbl_entry);
		/* That sync is a barrier for the whole PCD, not just this
		 * entry - anything parked by an earlier failure is now
		 * provably walker-free too, with no second round-trip. */
		cdx_ehash_quarantine_free_all();
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
	/* No abandon here: later exits in the chain (ipsec/socket/ipv4/ipv6
	 * resets) can still park entries, so the terminal disposition runs
	 * once from cdx_ctrl_deinit() after the whole chain. */
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
	/* Terminal disposition runs once from cdx_ctrl_deinit(); see mc4_exit. */
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

/* ------------------------------------------------- the flowtable owner's door
 *
 * The typed group interface cdx_mcast_backend.h declares.
 *
 * The legacy control plane reaches the machinery below through FCI: something
 * outside the box sends CMD_MC4_MULTICAST, CMM forwards it, and this file
 * decodes a wire message back into a group. Nothing in the product ever sent
 * that command -- `query mc4` on a production gateway carrying IPTV answers
 * "table empty" -- so what follows is not a second way in to a working feature.
 * It is the first one.
 *
 * What it is not is a second implementation. The group list, the id allocator,
 * the ingress MAC subscription, the per-listener entry builder, the root entry
 * and the whole of teardown are the code the legacy owner already runs; only
 * the door is new. A caller here describes a group whole, in kernel types, and
 * it is installed in one pass -- there is no ADD-then-UPDATE sequence because
 * there is no five-listener wire message to split it across.
 */

struct cdx_mc_group {
	struct mcast_group_info *info;
};

/* The public bound and the array it indexes are declared in different headers,
 * and raising the public one alone would overrun struct mcast_group_info's
 * member array on the heap. The file already pins the array's own width with
 * BUILD_BUG_ON(MC_MAX_LISTENERS_PER_GROUP > 8); this pins the two to each
 * other, the way CDX_FT_MAX_BINDINGS and CDX_FT_VLAN_MAX are pinned to theirs. */
static_assert(CDX_MC_MAX_LISTENERS == MC_MAX_LISTENERS_PER_GROUP,
	      "the group interface's listener bound must be the member array's");

bool cdx_mc_port_supported(struct net_device *dev)
{
	/* Deliberately the flowtable's own test rather than a weaker one of
	 * this subsystem's: a group's ports are the flowtable's ports, and a
	 * device that could not carry a flow cannot carry a replica either. */
	return cdx_ft_port_supported(dev);
}
EXPORT_SYMBOL_NS_GPL(cdx_mc_port_supported, ASK_CDX_FLOWTABLE);

bool cdx_mc_port_identity(struct net_device *dev)
{
	/* No transaction, no RTNL: dpa_netdev_is_physical() answers under its
	 * own lock, which is what lets the MDB handler ask this while holding
	 * RTNL -- where cdx_mc_port_supported() could not be called at all. */
	return dev && net_eq(dev_net(dev), &init_net) &&
	       dev->type == ARPHRD_ETHER && dev->addr_len == ETH_ALEN &&
	       dev->reg_state == NETREG_REGISTERED &&
	       !netif_is_l3_slave(dev) && dpa_netdev_is_physical(dev);
}
EXPORT_SYMBOL_NS_GPL(cdx_mc_port_identity, ASK_CDX_FLOWTABLE);

/* The group address, as the classifier requires it and as the contract narrows
 * it. Link-local scope is refused rather than carried: 224.0.0.0/24 and IPv6
 * scopes 1 and 2 are where IGMP, MLD and the querier itself live, and
 * replicating those in hardware would take the membership protocol away from
 * the bridge whose snooping is the source of truth for every group here. */
static int cdx_mc_check_group(const struct cdx_mc_group_spec *spec)
{
	if (spec->family == AF_INET) {
		u32 dst = ntohl(spec->dst.ip);

		if ((dst & 0xf0000000) != 0xe0000000)
			return -EOPNOTSUPP;
		if ((dst & 0xffffff00) == 0xe0000000)
			return -EOPNOTSUPP;
		/* A source is part of the key and an external hash cannot mask
		 * one, so a caller holding a (*,G) membership has nothing to
		 * install yet. Saying so here keeps that from becoming a
		 * group keyed on 0.0.0.0 that matches nothing. */
		if (!spec->src.ip)
			return -EOPNOTSUPP;
		return 0;
	}
	if (spec->family == AF_INET6) {
		const struct in6_addr *dst = &spec->dst.in6;

		if (!ipv6_addr_is_multicast(dst))
			return -EOPNOTSUPP;
		if (__ipv6_addr_src_scope(__ipv6_addr_type(dst)) <=
		    IPV6_ADDR_SCOPE_LINKLOCAL)
			return -EOPNOTSUPP;
		if (ipv6_addr_any(&spec->src.in6))
			return -EOPNOTSUPP;
		return 0;
	}
	return -EOPNOTSUPP;
}

static int cdx_mc_check(const struct cdx_mc_group_spec *spec)
{
	unsigned int ii, jj;
	int rc;

	if (!spec->in || !spec->listeners ||
	    spec->listeners > CDX_MC_MAX_LISTENERS)
		return -EOPNOTSUPP;
	rc = cdx_mc_check_group(spec);
	if (rc)
		return rc;
	if (!cdx_mc_port_supported(spec->in))
		return -EOPNOTSUPP;
	for (ii = 0; ii < spec->listeners; ii++) {
		const struct cdx_mc_listener *l = &spec->listener[ii];

		if (!l->dev || l->vlans > CDX_FT_VLAN_MAX)
			return -EOPNOTSUPP;
		if (!cdx_mc_port_supported(l->dev))
			return -EOPNOTSUPP;
		/* A port named twice would be programmed twice and receive
		 * two copies of every frame. The bridge cannot produce such a
		 * membership, so this is a caller error rather than a
		 * configuration, and it fails rather than being deduplicated
		 * -- silently forwarding a different group than the one asked
		 * for is the worse outcome. */
		for (jj = 0; jj < ii; jj++)
			if (spec->listener[jj].dev == l->dev)
				return -EOPNOTSUPP;
	}
	return 0;
}

/* One listener's entry. The onif comes from the netdev by index, which is the
 * resolution this ownership mode can do -- see create_exthash_entry4mcast_member
 * for why the legacy owner's name lookup is not interchangeable with it. */
static struct en_exthash_tbl_entry *cdx_mc_listener_entry(RouteEntry *pRtEntry,
		const struct cdx_mc_listener *listener,
		struct en_exthash_tbl_entry *prev, uint32_t tbl_type)
{
	struct cdx_l2_encap encap = {};
	struct dpa_iface_info *iface;
	POnifDesc onif_desc;
	u8 ii;

	iface = dpa_get_ifinfo_by_netdev(listener->dev);
	if (!iface || iface->itf_id >= L2_MAX_ONIF) {
		DPA_ERROR("%s::no interface for %s\n", __func__,
			  listener->dev->name);
		return NULL;
	}
	onif_desc = get_onif_by_index(iface->itf_id);
	if (!onif_desc || !(onif_desc->flags & ENTRY_VALID) || !onif_desc->itf ||
	    onif_desc->itf->index != iface->itf_id) {
		DPA_ERROR("%s::no valid onif for %s\n", __func__,
			  listener->dev->name);
		return NULL;
	}
	/* The rule orders tags outermost first, as the wire and the bridge do;
	 * dpa_l2hdr_info orders them innermost first. Reversed here, at the one
	 * place in this path the two conventions meet -- the same reversal
	 * ft_encap() performs for a flow's direction. */
	for (ii = 0; ii < listener->vlans; ii++) {
		encap.egress[listener->vlans - 1 - ii].tpid =
			ntohs(listener->vlan[ii].proto);
		encap.egress[listener->vlans - 1 - ii].tci = listener->vlan[ii].id;
	}
	encap.num_egress = listener->vlans;
	/* An untagged listener asks for no override, and must not be given
	 * one: apply_l2_encap() refuses a description the interface walk
	 * already filled in, and a DSCP-to-PCP egress map fills one in -- it
	 * pushes a priority tag on a plain physical port. Overriding nothing
	 * would then fail the whole group for a listener that wanted nothing.
	 * The flowtable's own encoder guards the same way. */
	return create_exthash_entry4mcast_member(pRtEntry, onif_desc,
						 listener->dev,
						 listener->vlans ? &encap : NULL,
						 prev, tbl_type);
}

/* Builds a whole listener chain into `grp`, threaded head to tail, and leaves
 * it unpublished: nothing in the classifier points at it until a caller makes
 * something do so. On failure nothing of it survives -- an unpublished chain is
 * unreachable by the microcode, so its entries are released outright rather
 * than quarantined, which is the create path's own reasoning. */
static int cdx_mc_build_listeners(struct mcast_group_info *grp,
				  const struct cdx_mc_group_spec *spec)
{
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	RouteEntry RtEntry, *pRtEntry = &RtEntry;
	uint32_t tbl_type;
	unsigned int ii;

	memset(&RtEntry, 0, sizeof(RouteEntry));
	cdx_mcast_compute_mac(grp, pRtEntry->dstmac);
	tbl_type = grp->mctype ? IPV6_MULTICAST_TABLE : IPV4_MULTICAST_TABLE;

	for (ii = 0; ii < spec->listeners; ii++) {
		tbl_entry = cdx_mc_listener_entry(pRtEntry, &spec->listener[ii],
						  tbl_entry, tbl_type);
		if (!tbl_entry) {
			/* Releases the entries built so far and clears their
			 * slots. It also hands back the group id, so a caller
			 * that allocated one must not release it again. */
			cdx_free_exthash_mcast_members(grp);
			grp->uiListenerCnt = 0;
			grp->grpid = -1;
			return -EIO;
		}
		grp->members[ii].bIsValidEntry = 1;
		grp->members[ii].member_id = ii;
		grp->members[ii].tbl_entry = tbl_entry;
		strncpy(grp->members[ii].if_info, spec->listener[ii].dev->name,
			IF_NAME_SIZE - 1);
		grp->uiListenerCnt++;
	}
	return 0;
}

/* Programs a described group's listener chain and root entry into an otherwise
 * empty mcast_group_info. On failure nothing of it is installed. */
static int cdx_mc_program(struct mcast_group_info *grp,
			  const struct cdx_mc_group_spec *spec)
{
	uint8_t mac[ETH_ALEN];
	int rc;

	cdx_mcast_compute_mac(grp, mac);
	/* Before any hardware state, so a failure here unwinds with nothing to
	 * undo -- the sequencing the legacy create path settled on. */
	rc = cdx_mcast_subscribe_ingress_mac(grp, mac);
	if (rc) {
		DPA_ERROR("%s::MAC filter subscription failed (%d)\n",
			  __func__, rc);
		return rc;
	}
	rc = cdx_mc_build_listeners(grp, spec);
	if (rc)
		goto err_ret;

	rc = cdx_add_mcast_table_entry(grp);
	if (rc) {
		DPA_ERROR("%s::adding mcast table entry failed (%d)\n",
			  __func__, rc);
		rc = rc < 0 ? rc : -EIO;
		cdx_free_exthash_mcast_members(grp);
		grp->uiListenerCnt = 0;
		grp->grpid = -1;
		goto err_ret;
	}
	return 0;

err_ret:
	cdx_mcast_unsubscribe_ingress_mac(grp, mac);
	return rc;
}

int cdx_mc_group_add(const struct cdx_mc_group_spec *spec,
		     struct cdx_mc_group **result)
{
	struct mcast_group_info *grp;
	uint8_t IngressIface[IF_NAME_SIZE];
	struct cdx_mc_group *group;
	int rc;

	cdx_ft_assert_held();
	*result = NULL;
	rc = cdx_mc_check(spec);
	if (rc)
		return rc;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return -ENOMEM;
	grp = kzalloc(sizeof(*grp), GFP_KERNEL);
	if (!grp) {
		kfree(group);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&grp->list);
	grp->grpid = -1;
	grp->mctype = spec->family == AF_INET6;
	if (grp->mctype) {
		memcpy(grp->ipv6_saddr, &spec->src.in6, IPV6_ADDRESS_LENGTH);
		memcpy(grp->ipv6_daddr, &spec->dst.in6, IPV6_ADDRESS_LENGTH);
	} else {
		grp->ipv4_saddr = spec->src.ip;
		grp->ipv4_daddr = spec->dst.ip;
	}
	strncpy(grp->ucIngressIface, spec->in->name, IF_NAME_SIZE - 1);
	/* Keyed on the device rather than on that name. The caller pins it for
	 * the group's life, nothing in cdx handles NETDEV_CHANGENAME, and a
	 * group that stopped recognising its own ingress after a rename would
	 * refuse every subsequent replace and freeze its listener set. */
	grp->in_dev = spec->in;

	/* Serialized against the FCI mutators, which is the discipline this
	 * file's own header states for any caller that does not arrive through
	 * the command dispatcher. Both owners never run at once, but the rule
	 * is about this file's state rather than about who is driving. */
	mutex_lock(&mc_mutators_mutex);
	/* GetMcastGrpId() matches on the address pair alone -- the ingress is
	 * reported back rather than compared -- so this refuses a second
	 * ingress for one (S,G) as well as a genuine duplicate. That is the
	 * legacy owner's restriction and it is inherited deliberately: one
	 * group id and one root entry exist per address pair here, and lifting
	 * it is a change to that structure rather than to this check. A caller
	 * wanting a different listener set for an installed key wants replace. */
	if (GetMcastGrpId(grp, IngressIface) != -1) {
		rc = -EEXIST;
		goto err_unlock;
	}
	grp->grpid = GetNewMcastGrpId(grp->mctype);
	if (grp->grpid == -1) {
		rc = -ENOSPC;
		goto err_unlock;
	}
	rc = cdx_mc_program(grp, spec);
	if (rc) {
		/* Released only if it is still held. The arms of
		 * cdx_mc_program() that get as far as building listeners
		 * unwind through cdx_free_exthash_mcast_members(), which hands
		 * the id back itself and leaves grpid -1; releasing it twice
		 * would free a slot a later add may already hold. */
		if (grp->grpid != -1)
			FreeMcastGrpID(grp->mctype, grp->grpid);
		goto err_unlock;
	}
	AddToMcastGrpList(grp);
	mutex_unlock(&mc_mutators_mutex);

	group->info = grp;
	*result = group;
	return 0;

err_unlock:
	mutex_unlock(&mc_mutators_mutex);
	kfree(grp);
	kfree(group);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_mc_group_add, ASK_CDX_FLOWTABLE);

/* Whether a spec describes the group already installed. The key is what a
 * replace may not change: a different one is a different entry in a different
 * hash bucket, which is an add and a delete rather than a replacement. */
static bool cdx_mc_same_key(const struct mcast_group_info *grp,
			    const struct cdx_mc_group_spec *spec)
{
	if (grp->mctype != (spec->family == AF_INET6))
		return false;
	/* The device, not its name. A group installed through this interface
	 * holds a pinned netdev precisely so a rename cannot make it stop
	 * recognising its own ingress -- which would refuse every subsequent
	 * replace and freeze the listener set for good. */
	if (grp->in_dev != spec->in)
		return false;
	if (grp->mctype)
		return !memcmp(grp->ipv6_saddr, &spec->src.in6, IPV6_ADDRESS_LENGTH) &&
		       !memcmp(grp->ipv6_daddr, &spec->dst.in6, IPV6_ADDRESS_LENGTH);
	return grp->ipv4_saddr == spec->src.ip && grp->ipv4_daddr == spec->dst.ip;
}

/* Points a group's root entry at a different listener chain.
 *
 * The root entry's REPLICATE opcode holds one pointer, the head of the chain
 * the microcode walks, so a whole listener set is exchanged by rewriting that
 * pointer -- the same publish cdx_exthash_update_first_mcast_member_addr()
 * performs to prepend a single listener, for the same reason and with the same
 * barrier. The classifier key never leaves the table, so no frame of this group
 * misses while the set changes.
 *
 * The caller owns the ordering: the new chain must be fully built and the old
 * one must not be released until after this returns, because the microcode may
 * be part-way along it. */
static int cdx_mc_publish_chain(struct mcast_group_info *grp,
				struct en_exthash_tbl_entry *head)
{
	struct en_exthash_tbl_entry *root = grp->pCtEntry->ct->handle;
	struct en_ehash_replicate_param *param;
	ucode_phyaddr_t tmp_val;
	uint64_t phyaddr;

	param = (struct en_ehash_replicate_param *)root->replicate_params;
	if (!param) {
		/* A multicast root always carries REPLICATE, so this is
		 * unreachable -- but it must be an error rather than a silent
		 * return, because the caller destroys the old chain on the
		 * strength of this having happened. */
		DPA_ERROR("%s::root entry carries no replicate parameter\n",
			  __func__);
		return -EIO;
	}
	phyaddr = XX_VirtToPhys(head);
	tmp_val.rsvd = 0;
	tmp_val.addr_hi = cpu_to_be16((phyaddr >> 32) & 0xffff);
	tmp_val.addr_lo = cpu_to_be32(phyaddr & 0xffffffff);
	/* The new chain's opcodes, parameters and next_entry words are all
	 * stores that must be visible before FMAN can reach them, and it can
	 * reach them the instant the pointer below lands. */
	wmb();
	param->first_member_flow_addr = tmp_val.addr;
	param->first_listener_entry = head;
	return 0;
}

int cdx_mc_group_replace(struct cdx_mc_group *group,
			 const struct cdx_mc_group_spec *spec)
{
	struct mcast_group_info *grp, *fresh;
	unsigned int ii;
	int rc;

	cdx_ft_assert_held();
	if (!group || !group->info)
		return -EINVAL;
	grp = group->info;
	if (!grp->pCtEntry || !grp->pCtEntry->ct)
		return -EINVAL;
	rc = cdx_mc_check(spec);
	if (rc)
		return rc;
	if (!cdx_mc_same_key(grp, spec))
		return -EINVAL;
	/* fresh borrows the installed group's key, and must borrow its device
	 * too: the ingress onif is resolved from it, and a name lookup would
	 * be the one thing keying on the device was meant to avoid. */

	/* The new chain is built beside the installed one rather than over it,
	 * so a set that cannot be carried costs the listeners that already were
	 * nothing at all: on failure the old chain is still the one the root
	 * entry names and still the one replicating.
	 *
	 * `fresh` is scratch. It borrows the group's key only because the entry
	 * builder derives the group MAC and table type from it, and it never
	 * reaches a list or an id -- FreeMcastGrpID() ignores the -1. */
	fresh = kzalloc(sizeof(*fresh), GFP_KERNEL);
	if (!fresh)
		return -ENOMEM;
	INIT_LIST_HEAD(&fresh->list);
	fresh->grpid = -1;
	fresh->mctype = grp->mctype;
	/* The two address pairs are one union, so these copy the key whichever
	 * family it is; the v4 fields are not a separate assignment. */
	memcpy(fresh->ipv6_saddr, grp->ipv6_saddr, sizeof(fresh->ipv6_saddr));
	memcpy(fresh->ipv6_daddr, grp->ipv6_daddr, sizeof(fresh->ipv6_daddr));
	strncpy(fresh->ucIngressIface, grp->ucIngressIface, IF_NAME_SIZE - 1);
	fresh->in_dev = grp->in_dev;

	mutex_lock(&mc_mutators_mutex);
	/* Reclaim anything a previous failed barrier left parked before adding
	 * to the backlog again, exactly as the legacy mutators open. */
	cdx_ehash_quarantine_drain(grp->pCtEntry->ct->td);
	rc = cdx_mc_build_listeners(fresh, spec);
	if (rc)
		goto err_unlock;
	rc = cdx_mc_publish_chain(grp, fresh->members[0].tbl_entry);
	if (rc) {
		/* Nothing was published, so the new chain is unreachable and
		 * the old one is still the group's. */
		cdx_free_exthash_mcast_members(fresh);
		goto err_unlock;
	}
	/* The displaced chain is out of the root entry's reach but a walk
	 * already under way can still be inside it, so it is parked rather
	 * than freed. Swapping members[] is what the bucket lock protects --
	 * the parameter store above is not ordered by it and does not need to
	 * be -- so take the old entries out under the lock and park them
	 * after: cdx_ehash_quarantine_entry() allocates. */
	{
		struct mcast_group_member old[MC_MAX_LISTENERS_PER_GROUP];
		unsigned int uiHash;
		spinlock_t *lock;

		if (grp->mctype == 0) {
			uiHash = HASH_MC4(grp->ipv4_daddr);
			lock = &mc4_spinlocks[uiHash];
		} else {
			uiHash = HASH_MC6((void *)(grp->ipv6_daddr));
			lock = &mc6_spinlocks[uiHash];
		}
		spin_lock(lock);
		for (ii = 0; ii < MC_MAX_LISTENERS_PER_GROUP; ii++) {
			old[ii] = grp->members[ii];
			grp->members[ii] = fresh->members[ii];
		}
		grp->uiListenerCnt = fresh->uiListenerCnt;
		spin_unlock(lock);

		for (ii = 0; ii < MC_MAX_LISTENERS_PER_GROUP; ii++)
			if (old[ii].bIsValidEntry)
				cdx_ehash_quarantine_entry(old[ii].tbl_entry);
	}
	/* And drain what was just parked. The chain is unlinked and the
	 * barrier proves the microcode is done with it, so the backlog settles
	 * at zero rather than growing by a chain per channel change. */
	cdx_ehash_quarantine_drain(grp->pCtEntry->ct->td);
	mutex_unlock(&mc_mutators_mutex);
	kfree(fresh);
	return 0;

err_unlock:
	mutex_unlock(&mc_mutators_mutex);
	kfree(fresh);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_mc_group_replace, ASK_CDX_FLOWTABLE);

void cdx_mc_group_del(struct cdx_mc_group **group)
{
	struct mcast_group_info *grp;
	unsigned int uiHash;

	cdx_ft_assert_held();
	if (!group || !*group)
		return;
	grp = (*group)->info;
	kfree(*group);
	*group = NULL;
	if (!grp)
		return;

	mutex_lock(&mc_mutators_mutex);
	/* Unlink under the bucket lock the query walkers hold, then tear down
	 * unlocked: the hash-table helpers issue hardware completions and can
	 * sleep, and once the node is out of the list no reader can reach it.
	 * The legacy delete path splits it the same way. */
	if (grp->mctype == 0) {
		uiHash = HASH_MC4(grp->ipv4_daddr);
		spin_lock(&mc4_spinlocks[uiHash]);
		list_del(&grp->list);
		spin_unlock(&mc4_spinlocks[uiHash]);
	} else {
		uiHash = HASH_MC6((void *)(grp->ipv6_daddr));
		spin_lock(&mc6_spinlocks[uiHash]);
		list_del(&grp->list);
		spin_unlock(&mc6_spinlocks[uiHash]);
	}
	mutex_unlock(&mc_mutators_mutex);
	cdx_mcast_group_destroy(grp);
}
EXPORT_SYMBOL_NS_GPL(cdx_mc_group_del, ASK_CDX_FLOWTABLE);

void cdx_mc_group_stats(const struct cdx_mc_group *group,
			struct cdx_ft_counters *stats)
{
	struct mcast_group_info *grp;

	/* Under the transaction like every other operation here, and not
	 * merely by convention: hw_ct_get_active() reads and writes back
	 * through ct, which cdx_mc_group_del() frees. The NULL tests below do
	 * not help against that -- they test pointers a concurrent delete is
	 * part-way through invalidating. */
	cdx_ft_assert_held();
	memset(stats, 0, sizeof(*stats));
	if (!group || !group->info)
		return;
	grp = group->info;
	if (!grp->pCtEntry || !grp->pCtEntry->ct)
		return;
	/* The root entry's own counters: frames matched on ingress, once each.
	 * The replication happens below this entry and nothing between here and
	 * the wire counts a replica separately, so a caller reporting
	 * per-listener delivery wants the ports' own counters. */
	hw_ct_get_active(grp->pCtEntry->ct);
	stats->packets = grp->pCtEntry->ct->pkts;
	stats->bytes = grp->pCtEntry->ct->bytes;
	stats->lastused = grp->pCtEntry->ct->timestamp;
}
EXPORT_SYMBOL_NS_GPL(cdx_mc_group_stats, ASK_CDX_FLOWTABLE);

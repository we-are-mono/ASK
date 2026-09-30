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
#include <linux/etherdevice.h>
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
 *        must agree on the convention - use plain
 *        spin_lock()/unlock() everywhere so process-context and
 *        softirq-context callers don't disagree on bh state.
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
 *        mcast callers hold ctrl.mutex plus mc_mutators_mutex
 *        below, mc{4,6}_exit() runs at module unload with no
 *        caller in flight) is documented at the implementation.
 *
 * Contexts:
 *   cdx_mc_group_add/replace/del()
 *                        - process, under the flowtable transaction.
 *   cdx_mcast_clear_itf_refs()
 *                        - process, interface removal.
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

/* Serializes the group mutators (cdx_mc_group_add/replace/del) and the
 * interface-removal sweep. Their lookup-then-mutate sequences unavoidably
 * drop the per-bucket spinlock between finding a group and mutating its
 * members[] or list linkage -- helpers like ExternalHashTableFmPcdHcSync
 * sleep on FmPcdLock and can't be held under spinlock. Without an outer
 * lock, two mutators of the same group could TOCTOU each other's
 * pMcastGrpInfo pointer (ISSUES.md M10, M11). The flowtable transaction
 * happens to serialize every current caller; this mutex makes the invariant
 * explicit and survives any future caller that runs from a kthread or
 * workqueue. */
static DEFINE_MUTEX(mc_mutators_mutex);

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
 * hand - i.e. the one that follows cdx_mc_group_replace()'s chain swap.
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
 * a listener splice still parks on a failed barrier and still reclaims
 * on the next successful one.
 *
 * Note the reclaim drain a mutator opens with is issued by the shared
 * helper, i.e. it is not routed through mc_hcsync() and the knob below
 * cannot force it to fail - so an armed knob never stops a backlog from
 * being released. */

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
 * applies. Without an explicit dev_mc_add() when the group is added, an
 * offload-managed group silently fails: the add succeeds, the group is
 * installed, and zero frames replicate. */
static void cdx_mcast_group_mac(const struct mcast_group_info *grp,
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

/* The destination the group's frames arrive with: the mapped group address,
 * or, for a group keyed on its frames' own Ethernet pair, exactly that
 * destination, which is the one the port has to let through. */
static void cdx_mcast_compute_mac(const struct mcast_group_info *grp,
				  uint8_t mac[ETH_ALEN])
{
	if (grp->mac_keyed)
		memcpy(mac, grp->mac_pair, ETH_ALEN);
	else
		cdx_mcast_group_mac(grp, mac);
}

/* Both go through the group's ingress device, which the owner pins for the
 * group's life (cdx_mcast_backend.h), never its name: a rename between the
 * two would leave a name lookup finding nothing, and the dev_mc_add()
 * refcount would never be dropped. */
static int cdx_mcast_subscribe_ingress_mac(const struct mcast_group_info *grp,
					   const uint8_t mac[ETH_ALEN])
{
	int rc;

	rc = dev_mc_add(grp->in_dev, mac);
	if (rc)
		DPA_ERROR("%s::dev_mc_add(%s, %pM) failed: %d\n",
			  __func__, grp->ucIngressIface, mac, rc);
	return rc;
}

static void cdx_mcast_unsubscribe_ingress_mac(const struct mcast_group_info *grp,
					      const uint8_t mac[ETH_ALEN])
{
	(void)dev_mc_del(grp->in_dev, mac);
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

/* Called by remove_onif_by_index() while the dying interface is still valid:
 * a multicast group's RouteEntry names the interface, so clear it before the
 * caller frees what it points into. mc_mutators_mutex orders us against the
 * group mutators, the bucket spinlocks against the list walkers. */
void cdx_mcast_clear_itf_refs(U32 if_index)
{
	unsigned int uiHash;

	mutex_lock(&mc_mutators_mutex);

	/* mc{4,6}_exit() frees the bucket lock arrays before the subsystem
	 * teardown reaches tx_exit, which also removes onifs. Any groups still
	 * on the lists at that point are unload-time leaks nothing will
	 * dereference again, so skipping the walk is safe. */
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



int cdx_free_exthash_mcast_members(struct mcast_group_info *pMcastGrpInfo);

/* The group's root entry: the classifier key, and the pointer to the head of
 * the listener chain the microcode replicates along.
 *
 * Everything this needs is already in the group -- the ingress device, both
 * addresses and the family. */
static int cdx_add_mcast_table_entry(struct mcast_group_info *pMcastGrpInfo)
{
	struct dpa_iface_info *iface;
	RouteEntry *pRtEntry;
	POnifDesc onif_desc;
	struct _tCtEntry *pCtEntry;
	int retval,ii;
	uint64_t phyaddr=0;

	pRtEntry = NULL;
	pCtEntry = NULL;

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

	/* By device, as a listener's resolution is: the owner pins it, and a
	 * name would stop matching after a rename. */
	iface = dpa_get_ifinfo_by_netdev(pMcastGrpInfo->in_dev);
	onif_desc = (iface && iface->itf_id < L2_MAX_ONIF) ?
		get_onif_by_index(iface->itf_id) : NULL;
	if (onif_desc && (!(onif_desc->flags & ENTRY_VALID) ||
			  !onif_desc->itf ||
			  onif_desc->itf->index != iface->itf_id))
		onif_desc = NULL;
	if (!onif_desc)
	{
		DPA_ERROR("%s::unable to get onif for iface %s\n",__func__,
			  pMcastGrpInfo->ucIngressIface);
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
	{
		/* What the group arrives as: the ingress tags the root validates
		 * and, for a group keyed on them, its frames' own addresses. A
		 * group that names neither keeps its routed root. */
		struct cdx_l2_encap in_encap = {};

		in_encap.num_ingress = pMcastGrpInfo->in_vlans;
		memcpy(in_encap.ingress, pMcastGrpInfo->in_vlan,
		       sizeof(in_encap.ingress));
		retval = insert_mcast_entry_in_classif_table(pCtEntry,
				pMcastGrpInfo->uiListenerCnt, phyaddr,
				pMcastGrpInfo->members[ii].tbl_entry,
				pMcastGrpInfo->bridged,
				pMcastGrpInfo->mac_keyed ? pMcastGrpInfo->mac_pair : NULL,
				&in_encap);
	}
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
 * group again - the group itself is freed right after. td is the group's
 * classifier table, which the caller has to read before the delete that
 * frees the group's hw_ct. */
static void mc_quarantine_members(struct mcast_group_info *pMcastGrpInfo, void *td)
{
	unsigned int ii;

	for (ii = 0; ii < MC_MAX_LISTENERS_PER_GROUP; ii++)
	{
		if (!pMcastGrpInfo->members[ii].bIsValidEntry)
			continue;
		cdx_ehash_quarantine_entry(td, pMcastGrpInfo->members[ii].tbl_entry);
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
 * not a sleeping lock) but wasteful, and the group-delete path already runs
 * this teardown unlocked. Once the node is off the list no reader can find
 * it, which is what makes that safe.
 *
 * Order is load-bearing: the classifier entry leaves the hardware table
 * first, then the listener table entries, then the CT/route backing memory.
 * Freeing in the other direction would leave the ucode replicating through
 * entries whose memory has already been handed back to the allocator. */
static void cdx_mcast_group_destroy(struct mcast_group_info *pMcastGrpInfo)
{
	uint8_t mac[ETH_ALEN];
	void *td;
	int rc;

	/* The table the members may have to be parked against, read before
	 * the delete below frees the hw_ct that holds it. */
	td = pMcastGrpInfo->pCtEntry && pMcastGrpInfo->pCtEntry->ct ?
		pMcastGrpInfo->pCtEntry->ct->td : NULL;
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
		mc_quarantine_members(pMcastGrpInfo, td);
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
		/* The root may still be linked and replicate through the leaked
		 * listener chain. Latch terminal failure, as the unicast delete
		 * does on -EIO, so the datapath fail-stops and demands a reset
		 * rather than forwarding to a revoked listener on unnoticed. */
		cdx_ft_fatal();
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

#define MAX_MC4_ENTRIES 512
#define MAX_MC6_ENTRIES 512
int mc4_init(void)
{
	int ii;

	/* mc4_exit is not run when this init fails, so a failure here
	 * releases what it already allocated. */
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

	return 0;
}

int mc6_init(void)
{
	int ii;

	/* As in mc4_init(), a failure here releases what it already
	 * allocated. */
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

	return 0;
}

/* Tears down every group still linked on a bucket array at module exit.
 *
 * Locking: cdx_ctrl_deinit() holds ctrl->mutex across the whole of the
 * subsystem teardown, and every group mutator (cdx_mc_group_add/replace/del)
 * runs under that same mutex, so nothing can change these lists while the
 * drain runs. The bucket spinlocks are taken anyway: it keeps the drain
 * structurally identical to the group-delete path (unlink locked, destroy
 * unlocked) and leaves it correct without depending on that outer exclusion,
 * which nothing here enforces locally.
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
	/* No abandon here: later exits in the chain (the IPsec teardown) can
	 * still park entries, so the terminal disposition runs once from
	 * cdx_ctrl_deinit() after the whole chain. */
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
 * The typed group interface cdx_mcast_backend.h declares, and the only way in
 * to the machinery above: the group list, the id allocator, the ingress MAC
 * subscription, the per-listener entry builder, the root entry and the whole
 * of teardown. A caller here describes a group whole, in kernel types, and it
 * is installed in one pass.
 */

struct cdx_mc_group {
	struct mcast_group_info *info;
};

/* The public bound and the array it indexes are declared in different headers,
 * and raising the public one alone would overrun struct mcast_group_info's
 * member array on the heap. The file already pins the array's own width with
 * BUILD_BUG_ON(MC_MAX_LISTENERS_PER_GROUP > 8); this pins the two to each
 * other, the way CDX_FT_MAX_TABLE_DEVICES and CDX_FT_VLAN_MAX are pinned to theirs. */
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
	    spec->listeners > CDX_MC_MAX_LISTENERS ||
	    spec->in_vlans > CDX_FT_VLAN_MAX)
		return -EOPNOTSUPP;
	rc = cdx_mc_check_group(spec);
	if (rc)
		return rc;
	/* A bridged group is keyed on its frames' own addresses and its
	 * listeners write them back, so it has to have them: a multicast
	 * destination, and a source that is a station. Without them there is
	 * nothing to key on but the routed key, and a routed key cannot
	 * preserve a sender's address. */
	if (spec->bridged && (!is_multicast_ether_addr(spec->dst_mac) ||
			      !is_valid_ether_addr(spec->src_mac)))
		return -EOPNOTSUPP;
	if (!cdx_mc_port_supported(spec->in))
		return -EOPNOTSUPP;
	for (ii = 0; ii < spec->listeners; ii++) {
		const struct cdx_mc_listener *l = &spec->listener[ii];

		if (!l->dev || l->vlans > CDX_FT_VLAN_MAX)
			return -EOPNOTSUPP;
		if (!cdx_mc_port_supported(l->dev))
			return -EOPNOTSUPP;
		/* A routed copy leaves with the address of the device ipmr
		 * sends it through, which only the caller knows. Without one
		 * it could only take its port's, which is not what Linux sends
		 * whenever that device is a bridge or a VLAN device given an
		 * address of its own -- so it is refused rather than defaulted,
		 * and a caller that forgot it is told instead of diverging
		 * silently. A bridged copy keeps its sender's pair and names
		 * none, which keeps the address a part of what tells two
		 * listeners apart below. */
		if ((!spec->bridged || l->routed) ?
		    !is_valid_ether_addr(l->src_mac) :
		    !is_zero_ether_addr(l->src_mac))
			return -EOPNOTSUPP;
		/* A listener repeated exactly would be programmed twice and
		 * that port would receive two identical copies of every frame.
		 * It fails rather than being deduplicated, because silently
		 * forwarding something other than what was asked for is the
		 * worse outcome.
		 *
		 * The same port with *different* framing is not that, and is
		 * not refused: those are two different copies, one tagged for
		 * each VLAN the port serves, which is what a gateway carrying
		 * several VLANs on one link replicates -- or one from each of
		 * two devices ipmr sends through, which differ in address, or
		 * a bridged copy beside a routed one, which differ in address
		 * and hop count. Nothing below this interface identifies a
		 * member by its device. Each one gets its own external-hash
		 * entry from its own ins_entry_info, built from the onif plus
		 * the caller's cdx_l2_encap and threaded into the chain by
		 * pointer; the group's members[] is indexed by position, and
		 * the name copied into if_info is for the log alone. */
		for (jj = 0; jj < ii; jj++) {
			const struct cdx_mc_listener *o = &spec->listener[jj];

			if (o->dev == l->dev && o->vlans == l->vlans &&
			    !memcmp(o->vlan, l->vlan, sizeof(o->vlan)) &&
			    ether_addr_equal(o->src_mac, l->src_mac))
				return -EOPNOTSUPP;
		}
	}
	return 0;
}

/* One listener's entry. The onif comes from the netdev by index, never by
 * name, which would stop matching after a rename. */
static struct en_exthash_tbl_entry *cdx_mc_listener_entry(RouteEntry *pRtEntry,
		const struct cdx_mc_listener *listener,
		const struct cdx_mc_member_frame *frame,
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
	/* An untagged listener asks for no override, and is given none:
	 * apply_l2_encap() refuses a description the interface walk already
	 * filled in, so overriding nothing could only fail the whole group
	 * for a listener that wanted nothing. The flowtable's own encoder
	 * guards the same way. */
	return create_exthash_entry4mcast_member(pRtEntry, onif_desc,
						 listener->dev,
						 listener->vlans ? &encap : NULL,
						 frame, prev, tbl_type);
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
	uint8_t arrived[ETH_ALEN], mapped[ETH_ALEN];
	struct cdx_mc_member_frame frame = {};
	uint32_t tbl_type;
	unsigned int ii;

	memset(&RtEntry, 0, sizeof(RouteEntry));
	cdx_mcast_compute_mac(grp, arrived);
	cdx_mcast_group_mac(grp, mapped);
	/* A listener's entry comes from its port's table of the root's type,
	 * and a bridged copy writes back the pair its root matched. */
	if (grp->mac_keyed) {
		tbl_type = grp->mctype ? IPV6_BRIDGED_MULTICAST_TABLE :
					 IPV4_BRIDGED_MULTICAST_TABLE;
		frame.mac_pair = grp->mac_pair;
	} else {
		tbl_type = grp->mctype ? IPV6_MULTICAST_TABLE :
					 IPV4_MULTICAST_TABLE;
	}

	for (ii = 0; ii < spec->listeners; ii++) {
		const struct cdx_mc_listener *listener = &spec->listener[ii];
		struct cdx_mc_member_frame copy = frame;
		uint8_t routed_pair[2 * ETH_ALEN];

		/* A routed copy is a router's frame: from the address of the
		 * device ipmr sends it through, which the listener names, to
		 * the group's mapped address -- written over the walk's header
		 * as a bridged pair is, because the walk writes the port's own
		 * address, and that is what Linux sends only when the device
		 * is the port. Every copy of a routed group is one, and so is
		 * a routed copy of a bridged group. That one also takes a hop
		 * off in its own entry, because a bridged root keeps the count
		 * for its bridged copies; a routed root decrements for all of
		 * its copies itself. */
		memcpy(pRtEntry->dstmac, arrived, ETH_ALEN);
		if (!grp->mac_keyed || listener->routed) {
			memcpy(routed_pair, mapped, ETH_ALEN);
			memcpy(routed_pair + ETH_ALEN, listener->src_mac, ETH_ALEN);
			copy.mac_pair = routed_pair;
			copy.hop = grp->mac_keyed;
			memcpy(pRtEntry->dstmac, mapped, ETH_ALEN);
		}
		tbl_entry = cdx_mc_listener_entry(pRtEntry, listener, &copy,
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
	 * undo. */
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

/* Groups added through this interface and not yet deleted. Under the
 * transaction. */
static unsigned int cdx_mc_groups_owned;

unsigned int cdx_mc_group_count(void)
{
	cdx_ft_assert_held();
	return cdx_mc_groups_owned;
}

/* Fill in everything about a group its root entry is built from: the family,
 * the addresses, the ingress and what the group's frames arrive as. Shared by
 * add and by replace's scratch group, so the two can never describe one key
 * two ways. */
static void cdx_mc_describe(struct mcast_group_info *grp,
			    const struct cdx_mc_group_spec *spec)
{
	u8 ii;

	grp->mctype = spec->family == AF_INET6;
	grp->bridged = spec->bridged;
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
	grp->mac_keyed = spec->bridged;
	if (grp->mac_keyed) {
		memcpy(grp->mac_pair, spec->dst_mac, ETH_ALEN);
		memcpy(grp->mac_pair + ETH_ALEN, spec->src_mac, ETH_ALEN);
	}
	/* The spec orders tags outermost first, the encapsulation innermost
	 * first -- the same reversal a listener's tags take. */
	grp->in_vlans = spec->in_vlans;
	for (ii = 0; ii < spec->in_vlans; ii++) {
		grp->in_vlan[spec->in_vlans - 1 - ii].tpid =
			ntohs(spec->in_vlan[ii].proto);
		grp->in_vlan[spec->in_vlans - 1 - ii].tci = spec->in_vlan[ii].id;
	}
}

/* Whether a group already holds this one's classifier key.
 *
 * The key is what the root entry is hashed on: the ingress port, the address
 * pair, and -- in the bridged multicast table -- the frame's own Ethernet pair.
 * Two groups that differ in any of those are two entries the classifier tells
 * apart, and both may exist: the same (S,G) arriving on two ports, or from two
 * senders into a bridge. Two that agree on all of them are one entry, whatever
 * else differs, and the second is refused -- including one that differs only
 * in its ingress tags, because the key names no VLAN and the classifier would
 * hold two entries it cannot choose between.
 *
 * Called with mc_mutators_mutex held; the bucket lock is taken here. */
static bool cdx_mc_key_taken(const struct mcast_group_info *grp)
{
	struct mcast_group_info *tmp;
	struct list_head *head;
	spinlock_t *lock;
	bool taken = false;

	if (grp->mctype) {
		unsigned int hash = HASH_MC6((void *)grp->ipv6_daddr);

		head = &mc6_grp_list[hash];
		lock = &mc6_spinlocks[hash];
	} else {
		unsigned int hash = HASH_MC4(grp->ipv4_daddr);

		head = &mc4_grp_list[hash];
		lock = &mc4_spinlocks[hash];
	}
	spin_lock(lock);
	list_for_each_entry(tmp, head, list) {
		if (tmp->mctype != grp->mctype)
			continue;
		if (grp->mctype ?
		    (memcmp(tmp->ipv6_daddr, grp->ipv6_daddr, IPV6_ADDRESS_LENGTH) ||
		     memcmp(tmp->ipv6_saddr, grp->ipv6_saddr, IPV6_ADDRESS_LENGTH)) :
		    (tmp->ipv4_daddr != grp->ipv4_daddr ||
		     tmp->ipv4_saddr != grp->ipv4_saddr))
			continue;
		if (tmp->in_dev != grp->in_dev || tmp->mac_keyed != grp->mac_keyed)
			continue;
		if (grp->mac_keyed &&
		    memcmp(tmp->mac_pair, grp->mac_pair, sizeof(grp->mac_pair)))
			continue;
		taken = true;
		break;
	}
	spin_unlock(lock);
	return taken;
}

int cdx_mc_group_add(const struct cdx_mc_group_spec *spec,
		     struct cdx_mc_group **result)
{
	struct mcast_group_info *grp;
	struct cdx_mc_group *group;
	int rc;

	cdx_ft_assert_held();
	*result = NULL;
	/* After a root that may still be linked left the group list, the key
	 * check below can no longer see it: a re-learned (S,G) would insert a
	 * second copy beside it. The latch refuses every key, as unicast's does. */
	if (cdx_ft_failed())
		return -EIO;
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
	cdx_mc_describe(grp, spec);

	/* Serialized against the other mutators and the interface-removal
	 * sweep, which is the discipline this file's header states. */
	mutex_lock(&mc_mutators_mutex);
	/* One entry per classifier key; see cdx_mc_key_taken(). A caller
	 * wanting a different listener set for an installed key wants
	 * replace. */
	if (cdx_mc_key_taken(grp)) {
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
	cdx_mc_groups_owned++;
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
	/* Replacement swaps only the listener chain. The root's hop-count
	 * action must remain compatible with the new description. */
	if (grp->bridged != spec->bridged)
		return false;
	if (grp->mctype != (spec->family == AF_INET6))
		return false;
	/* The device, not its name. A group installed through this interface
	 * holds a pinned netdev precisely so a rename cannot make it stop
	 * recognising its own ingress -- which would refuse every subsequent
	 * replace and freeze the listener set for good. */
	if (grp->in_dev != spec->in)
		return false;
	/* What the frames arrive as is the root's too: the Ethernet pair is
	 * in the key, and the ingress tags are what its STRIP_ALL_VLAN_HDRS
	 * validates. A chain swap changes neither. */
	{
		struct mcast_group_info described = {};

		cdx_mc_describe(&described, spec);
		if (described.mac_keyed != grp->mac_keyed ||
		    (grp->mac_keyed && memcmp(described.mac_pair, grp->mac_pair,
					      sizeof(grp->mac_pair))) ||
		    described.in_vlans != grp->in_vlans ||
		    memcmp(described.in_vlan, grp->in_vlan, sizeof(grp->in_vlan)))
			return false;
	}
	if (grp->mctype)
		return !memcmp(grp->ipv6_saddr, &spec->src.in6, IPV6_ADDRESS_LENGTH) &&
		       !memcmp(grp->ipv6_daddr, &spec->dst.in6, IPV6_ADDRESS_LENGTH);
	return grp->ipv4_saddr == spec->src.ip && grp->ipv4_daddr == spec->dst.ip;
}

/* Points a group's root entry at a different listener chain.
 *
 * The root entry's REPLICATE opcode holds one pointer, the head of the chain
 * the microcode walks, so a whole listener set is exchanged by rewriting that
 * pointer, behind a barrier that makes the new chain visible first. The
 * classifier key never leaves the table, so no frame of this group misses
 * while the set changes.
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
	/* Nor build listener chains for a datapath that is stopping; the
	 * caller withdraws the group instead. */
	if (cdx_ft_failed())
		return -EIO;
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
	fresh->bridged = grp->bridged;
	/* The two address pairs are one union, so these copy the key whichever
	 * family it is; the v4 fields are not a separate assignment. */
	memcpy(fresh->ipv6_saddr, grp->ipv6_saddr, sizeof(fresh->ipv6_saddr));
	memcpy(fresh->ipv6_daddr, grp->ipv6_daddr, sizeof(fresh->ipv6_daddr));
	strncpy(fresh->ucIngressIface, grp->ucIngressIface, IF_NAME_SIZE - 1);
	fresh->in_dev = grp->in_dev;
	/* And the pair a bridged copy writes back, with the table its entries
	 * come from. */
	fresh->mac_keyed = grp->mac_keyed;
	memcpy(fresh->mac_pair, grp->mac_pair, sizeof(fresh->mac_pair));

	mutex_lock(&mc_mutators_mutex);
	/* Reclaim anything a previous failed barrier left parked before adding
	 * to the backlog again. */
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
				cdx_ehash_quarantine_entry(grp->pCtEntry->ct->td,
							   old[ii].tbl_entry);
	}
	/* And the barrier proving the microcode has left the chain just
	 * unlinked, which releases it and anything parked before it, so the
	 * backlog settles at zero rather than growing by a chain per channel
	 * change. This is the listener splice this interface performs, so its
	 * barrier goes through mc_hcsync(): a failure leaves the displaced chain
	 * parked for the next barrier on this PCD, and the test image can make
	 * one fail on demand. */
	if (mc_hcsync(grp->pCtEntry->ct->td)) {
		DPA_ERROR("%s::FmPcdHcSync failed, %u entries still quarantined\n",
			  __func__, cdx_ehash_quarantine_pending());
	} else {
		cdx_ehash_quarantine_free_all();
	}
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
	if (!WARN_ON_ONCE(!cdx_mc_groups_owned))
		cdx_mc_groups_owned--;
	if (!grp)
		return;

	mutex_lock(&mc_mutators_mutex);
	/* Unlink under the bucket lock the list walkers hold, then tear down
	 * unlocked: the hash-table helpers issue hardware completions and can
	 * sleep, and once the node is out of the list no reader can reach it. */
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

bool cdx_mc_group_stats(const struct cdx_mc_group *group,
			struct cdx_ft_counters *stats)
{
	struct mcast_group_info *grp;
	bool read;

	/* Under the transaction like every other operation here, and not
	 * merely by convention: hw_ct_get_active() reads and writes back
	 * through ct, which cdx_mc_group_del() frees. The NULL tests below do
	 * not help against that -- they test pointers a concurrent delete is
	 * part-way through invalidating. */
	cdx_ft_assert_held();
	memset(stats, 0, sizeof(*stats));
	if (!group || !group->info)
		return false;
	grp = group->info;
	if (!grp->pCtEntry || !grp->pCtEntry->ct)
		return false;
	/* The root entry's own counters: frames matched on ingress, once each.
	 * The replication happens below this entry and nothing between here and
	 * the wire counts a replica separately, so a caller reporting
	 * per-listener delivery wants the ports' own counters. */
	read = !hw_ct_get_active(grp->pCtEntry->ct);
	stats->packets = grp->pCtEntry->ct->pkts;
	stats->bytes = grp->pCtEntry->ct->bytes;
	stats->lastused = grp->pCtEntry->ct->timestamp;
	return read;
}
EXPORT_SYMBOL_NS_GPL(cdx_mc_group_stats, ASK_CDX_FLOWTABLE);

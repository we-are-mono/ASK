// SPDX-License-Identifier: GPL-2.0-or-later
/* Firmware backend for independent Linux flowtable directions. No legacy CT
 * hash, route hash, CMM notification, or ageing timer owns these objects. */
#include <linux/etherdevice.h>
#include <linux/module.h>
#include "cdx.h"
#include "control_ipv4.h"
#include "fm_ehash.h"
#include "cdx_flowtable_hw.h"

struct cdx_ft_hw {
	CtEntry entry;
	CtEntry twin;
	RouteEntry route;
	struct list_head retired;
	int delete_rc;
};

/* Retirement needs no allocation after unlink. Unlike the legacy quarantine,
 * the adapter can retain the already allocated owner until the barrier passes. */
static LIST_HEAD(ft_retired);

#ifdef CDX_DEBUG_FLOWTABLE
static bool ft_fail_unlink;
module_param_named(flowtable_fail_unlink, ft_fail_unlink, bool, 0600);
MODULE_PARM_DESC(flowtable_fail_unlink, "One-shot delete failure leaving a live key linked; reboot required");
#endif

static bool ft_unlink_fault(void)
{
#ifdef CDX_DEBUG_FLOWTABLE
	return xchg(&ft_fail_unlink, false);
#else
	return false;
#endif
}

int cdx_ft_hw_add(const struct cdx_ft_rule *rule, struct cdx_ft_hw **result)
{
	POnifDesc in, out;
	struct cdx_ft_hw *hw;
	PCtEntry ct;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	*result = NULL;
	in = get_onif_by_name(rule->in->name);
	out = get_onif_by_name(rule->out->name);
	if (!in || !out || in->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL) ||
	    out->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL))
		return -EOPNOTSUPP;
	hw = kzalloc(sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;
	hw->route.itf = out->itf;
	hw->route.input_itf = in->itf;
	hw->route.underlying_input_itf = in->itf;
	hw->route.mtu = rule->mtu;
	ether_addr_copy(hw->route.dstmac, rule->dst_mac);
	ct = &hw->entry;
	ct->twin = &hw->twin;
	hw->twin.twin = ct;
	ct->pRtEntry = &hw->route;
	ct->fftype = FFTYPE_IPV4;
	ct->status = CONNTRACK_ORIG;
	ct->proto = IPPROTO_UDP;
	ct->Saddr_v4 = rule->src;
	ct->Daddr_v4 = rule->dst;
	ct->Sport = rule->sport;
	ct->Dport = rule->dport;
	ct->twin_Saddr = rule->dst;
	ct->twin_Daddr = rule->src;
	ct->twin_Sport = rule->dport;
	ct->twin_Dport = rule->sport;
	hw->twin.Saddr_v4 = rule->dst;
	hw->twin.Daddr_v4 = rule->src;
	hw->twin.Sport = rule->dport;
	hw->twin.Dport = rule->sport;
	hw->twin.proto = IPPROTO_UDP;
	ct->hash = HASH_CT(rule->src, rule->dst, rule->sport, rule->dport,
			   IPPROTO_UDP);
	if (insert_entry_in_classif_table(ct)) {
		kfree(hw);
		return -EIO;
	}
	*result = hw;
	return 0;
}

void cdx_ft_hw_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
	hw_ct_get_active(hw->entry.ct);
	stats->packets = hw->entry.ct->pkts;
	stats->bytes = hw->entry.ct->bytes;
	stats->lastused = hw->entry.ct->timestamp;
}

int cdx_ft_hw_del(struct cdx_ft_hw **entry)
{
	struct cdx_ft_hw *hw = *entry;
	struct hw_ct *ct;
	int rc;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	if (!hw)
		return 0;
	ct = hw->entry.ct;
	/* Preserve the real linked allocation to exercise fatal retirement.
	 * Never inject a hard error after a successful destructive unlink. */
	rc = ft_unlink_fault() ? -EIO :
		ExternalHashTableDeleteKey(ct->td, ct->index, ct->handle);
	*entry = NULL;
	if (!rc) {
		ExternalHashTableEntryFree(ct->handle);
		kfree(ct);
		kfree(hw);
		return 0;
	}
	hw->delete_rc = rc;
	list_add_tail(&hw->retired, &ft_retired);
	if (rc == EN_EHASH_DELETE_UNSYNCED)
		return -EAGAIN;
	return -EIO;
}

unsigned int cdx_ft_hw_pending(void)
{
	struct cdx_ft_hw *hw;
	unsigned int n = 0;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	list_for_each_entry(hw, &ft_retired, retired)
		n++;
	return n;
}

int cdx_ft_hw_retry(void)
{
	struct cdx_ft_hw *hw, *next;
	int rc = 0;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	list_for_each_entry_safe(hw, next, &ft_retired, retired) {
		/* Never attempt a second unlink, including after a hard error. */
		if (hw->delete_rc != EN_EHASH_DELETE_UNSYNCED ||
		    ExternalHashTableFmPcdHcSync(hw->entry.ct->td)) {
			rc = -EAGAIN;
			continue;
		}
		ExternalHashTableEntryFree(hw->entry.ct->handle);
		kfree(hw->entry.ct);
		list_del(&hw->retired);
		kfree(hw);
	}
	return rc;
}

/* Caller has stopped and detached all classifier ports. Unlinked storage can
 * now be freed even if HC never recovered. A possibly linked key must remain
 * allocated until reset: freeing it would leave a dangling hash-chain link. */
void cdx_ft_hw_quiesced(void)
{
	struct cdx_ft_hw *hw, *next;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	list_for_each_entry_safe(hw, next, &ft_retired, retired) {
		if (hw->delete_rc == EN_EHASH_DELETE_UNSYNCED)
			ExternalHashTableEntryFree(hw->entry.ct->handle);
		else
			pr_err("cdx flowtable: retaining possibly linked key %p until hardware reset\n",
			       hw->entry.ct->handle);
		kfree(hw->entry.ct);
		list_del(&hw->retired);
		kfree(hw);
	}
}

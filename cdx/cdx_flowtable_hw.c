// SPDX-License-Identifier: GPL-2.0-or-later
/* Firmware backend for independent Linux flowtable directions. No legacy CT
 * hash, route hash, CMM notification, or ageing timer owns these objects. */
#include <linux/etherdevice.h>
#include <linux/module.h>
#include "portdefs.h"
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
	struct dpa_iface_info *in_iface, *out_iface;
	struct cdx_ft_hw *hw;
	PCtEntry ct;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	*result = NULL;
	if (rule->proto != IPPROTO_TCP && rule->proto != IPPROTO_UDP)
		return -EOPNOTSUPP;
	in_iface = dpa_get_ifinfo_by_netdev(rule->in);
	out_iface = dpa_get_ifinfo_by_netdev(rule->out);
	if (!in_iface || !out_iface || in_iface->itf_id >= L2_MAX_ONIF ||
	    out_iface->itf_id >= L2_MAX_ONIF)
		return -EOPNOTSUPP;
	in = get_onif_by_index(in_iface->itf_id);
	out = get_onif_by_index(out_iface->itf_id);
	if (!(in->flags & ENTRY_VALID) || !(out->flags & ENTRY_VALID) ||
	    !in->itf || !out->itf ||
	    in->itf->index != in_iface->itf_id || out->itf->index != out_iface->itf_id ||
	    in->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL) ||
	    out->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL))
		return -EOPNOTSUPP;
	/* The legacy encoder obtains its Ethernet source from this cache.
	 * Admission validated the requested MAC under RTNL; synchronize the
	 * cache under its reader lock before encoding the new direction.
	 * Legacy control is sealed throughout this ownership mode. */
	spin_lock(&dpa_devlist_lock);
	ether_addr_copy(out_iface->eth_info.mac_addr, rule->src_mac);
	spin_unlock(&dpa_devlist_lock);
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
	if (rule->new_src != rule->src || rule->new_dst != rule->dst ||
	    rule->new_sport != rule->sport || rule->new_dport != rule->dport)
		ct->status |= CONNTRACK_NAT;
	ct->proto = rule->proto;
	ct->Saddr_v4 = rule->src;
	ct->Daddr_v4 = rule->dst;
	ct->Sport = rule->sport;
	ct->Dport = rule->dport;
	/* The shared encoder derives rewrites from the inverse translated tuple.
	 * Only the original match participates in classifier key/hash creation. */
	ct->twin_Saddr = hw->twin.Saddr_v4 = rule->new_dst;
	ct->twin_Daddr = hw->twin.Daddr_v4 = rule->new_src;
	ct->twin_Sport = hw->twin.Sport = rule->new_dport;
	ct->twin_Dport = hw->twin.Dport = rule->new_sport;
	hw->twin.proto = rule->proto;
	ct->hash = HASH_CT(rule->src, rule->dst, rule->sport, rule->dport,
			   rule->proto);
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

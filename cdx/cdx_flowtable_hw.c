// SPDX-License-Identifier: GPL-2.0-or-later
/* Firmware backend for independent Linux flowtable directions. No legacy CT
 * hash, route hash, CMM notification, or ageing timer owns these objects. */
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <net/ipv6.h>
#include "portdefs.h"
#include "cdx.h"
#include "control_ipv4.h"
#include "fm_ehash.h"
#include "cdx_flowtable_hw.h"
#include "cdx_police.h"

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

/* The rule orders its tags outermost first, as the wire and Netfilter do;
 * dpa_l2hdr_info orders them innermost first, because it is built by walking
 * a VLAN interface up towards its parent. Reverse them here, at the one place
 * the two conventions meet. tpid and tci are host-order in that description:
 * the header manipulation applies cpu_to_be16/32 when it lays them out. */
static void ft_encap(const struct cdx_ft_vlan *stack, u8 count,
		     struct vlan_header *headers, u32 *num)
{
	u8 i;

	for (i = 0; i < count; i++) {
		headers[count - 1 - i].tpid = ntohs(stack[i].proto);
		headers[count - 1 - i].tci = stack[i].id;
	}
	*num = count;
}

int cdx_ft_hw_add(const struct cdx_ft_rule *rule,
		  const struct cdx_ft_stats_binding *stats,
		  struct cdx_ft_hw **result)
{
	POnifDesc in, out;
	struct dpa_iface_info *in_iface, *out_iface;
	struct cdx_l2_encap encap = {};
	struct cdx_ft_hw *hw;
	PCtEntry ct;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	*result = NULL;
	if ((rule->proto != IPPROTO_TCP && rule->proto != IPPROTO_UDP) ||
	    (rule->family != AF_INET && rule->family != AF_INET6))
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
	/* The ucode checks the size of what it *transmits* against this, and
	 * for a direction handed to SEC that is the outer frame: the entry
	 * carries the expansion separately, in hdr_xpnd_sz, and the check adds
	 * it before comparing. Netfilter's MTU for such a flow is the
	 * tunnel-reduced inner one, so programming it directly fails every
	 * full-size frame -- 1438 + 62 against 1438 -- and each one takes the
	 * exception path instead. The flow is then matched and counted and
	 * forwarded by the CPU anyway, which looks like an offload that works
	 * and performs like software: measured at 0.07 Gb/s against the legacy
	 * owner's 2.54 on the same tunnel, with the software SEC submit
	 * counting once per packet.
	 *
	 * The limit that belongs here is the egress port's own. The legacy
	 * owner never met this because its route table holds interface MTUs
	 * rather than per-flow ones, and the same reasoning is already written
	 * down beside the tunnel-interface case in devman.c. */
	hw->route.mtu = rule->sa_handle ? rule->out_logical->mtu : rule->mtu;
	ether_addr_copy(hw->route.dstmac, rule->dst_mac);
	ct = &hw->entry;
	ct->twin = &hw->twin;
	hw->twin.twin = ct;
	ct->pRtEntry = &hw->route;
	ct->status = CONNTRACK_ORIG;
	ct->proto = rule->proto;
	ct->Sport = rule->sport;
	ct->Dport = rule->dport;
	/* The shared encoder derives rewrites from the inverse translated tuple.
	 * Only the original match participates in classifier key/hash creation.
	 * Ports always come from the twin object; addresses come from the twin
	 * for IPv6 and from the entry's own twin_* fields for IPv4. Those fields
	 * overlay the second half of Daddr_v6, so an IPv6 entry must leave every
	 * one of them alone or it corrupts its own destination address. */
	hw->twin.Sport = rule->new_dport;
	hw->twin.Dport = rule->new_sport;
	hw->twin.proto = rule->proto;
	if (rule->family == AF_INET6) {
		ct->fftype = FFTYPE_IPV6;
		memcpy(ct->Saddr_v6, rule->src.ip6, sizeof(ct->Saddr_v6));
		memcpy(ct->Daddr_v6, rule->dst.ip6, sizeof(ct->Daddr_v6));
		memcpy(hw->twin.Saddr_v6, rule->new_dst.ip6, sizeof(hw->twin.Saddr_v6));
		memcpy(hw->twin.Daddr_v6, rule->new_src.ip6, sizeof(hw->twin.Daddr_v6));
		/* The IPv6 encoder rewrites each address whenever its bit is set
		 * and never compares the two, and it gates the port rewrite on
		 * either bit. Mark a direction translated when its address or its
		 * port moved, exactly as the legacy IPv6 control path does. */
		if (!ipv6_addr_equal(&rule->new_src.in6, &rule->src.in6) ||
		    rule->new_sport != rule->sport)
			ct->status |= CONNTRACK_SNAT;
		if (!ipv6_addr_equal(&rule->new_dst.in6, &rule->dst.in6) ||
		    rule->new_dport != rule->dport)
			ct->status |= CONNTRACK_DNAT;
		ct->hash = HASH_CT6(ct->Saddr_v6, ct->Daddr_v6, rule->sport,
				    rule->dport, rule->proto);
	} else {
		ct->fftype = FFTYPE_IPV4;
		ct->Saddr_v4 = rule->src.ip;
		ct->Daddr_v4 = rule->dst.ip;
		ct->twin_Saddr = hw->twin.Saddr_v4 = rule->new_dst.ip;
		ct->twin_Daddr = hw->twin.Daddr_v4 = rule->new_src.ip;
		ct->twin_Sport = rule->new_dport;
		ct->twin_Dport = rule->new_sport;
		if (rule->new_src.ip != rule->src.ip || rule->new_dst.ip != rule->dst.ip ||
		    rule->new_sport != rule->sport || rule->new_dport != rule->dport)
			ct->status |= CONNTRACK_NAT;
		ct->hash = HASH_CT(rule->src.ip, rule->dst.ip, rule->sport,
				   rule->dport, rule->proto);
	}
	/* Both ports are physical, so the interface walk describes no
	 * encapsulation at all; the tags and sessions admission derived from
	 * the devices Linux routed through are the whole description. A session
	 * needs no reversal: there is at most one per direction, and it is
	 * always the innermost header, which is where the opcode order already
	 * puts it. */
	ft_encap(rule->in_vlan, rule->in_vlans, encap.ingress, &encap.num_ingress);
	ft_encap(rule->out_vlan, rule->out_vlans, encap.egress, &encap.num_egress);
	encap.ingress_pppoe = rule->in_session.present;
	encap.egress_pppoe = rule->out_session.present;
	encap.egress_session_id = rule->out_session.id;
	ether_addr_copy(encap.egress_session_mac, rule->out_session.mac);
	/* A direction that strips counts into its session's receive half and
	 * one that inserts into the transmit half of its own, which are the
	 * two halves of the same record when one connection crosses one
	 * session. A session without a record leaves the index zero, which the
	 * opcodes read as no record rather than as record zero. */
	if (stats->in_session)
		encap.ingress_stats_index = stats->in_session->rx_index;
	if (stats->out_session)
		encap.egress_stats_index = stats->out_session->tx_index;
	/* The shared encoder reads this on its way to cdx_get_txfqid(), which
	 * resolves the pair to a CEETM logical FQ and bakes that FQID into the
	 * classifier action. Leaving it zero, as this backend did before, asks
	 * for class queue zero of the port's least-priority channel — which
	 * GET_CEETM_PRIORITY inverts to the *lowest* strict priority. That is a
	 * defensible best-effort default, but only when it is chosen rather
	 * than inherited from kzalloc, which is why the adapter always supplies
	 * a class and names the default explicitly. */
	ct->qosmark.queue = rule->qos & CDX_FT_QOS_QUEUE_MASK;
	ct->qosmark.chnl_id = (rule->qos & CDX_FT_QOS_CHANNEL_MASK) >>
			      CDX_FT_QOS_CHANNEL_SHIFT;
	/* The ingress policer travels the same field but reaches the hardware by
	 * a different route: create_preemptive_checks_hm() turns iqid into the
	 * ucode's pp_no, so this selects which of the eight RFC-2698 profiles
	 * the flow's ingress frames are metered against.
	 *
	 * The valid bit is always set, including for profile 0. It is not a
	 * "policer wanted" flag -- the encoder's own default is profile 0, so
	 * leaving the bit clear selects profile 0 too. Setting it unconditionally
	 * makes the rule say exactly which profile it means and keeps the nibble
	 * a plain profile number.
	 *
	 * Which profile that is was settled by the adapter, which resolves a tc
	 * police filter against the finished tuple before handing the rule over.
	 * Doing it here instead would leave the rule -- and so /proc -- saying
	 * something different from what the hardware was told. */
	ct->qosmark.iqid = (rule->qos & CDX_FT_QOS_POLICER_MASK) >>
			   CDX_FT_QOS_POLICER_SHIFT;
	ct->qosmark.iqid_valid = 1;
	/* The remark rides an opcode every routed flow already carries:
	 * create_update_dscp_hm() writes the codepoint into the header
	 * manipulation that decrements TTL, so this costs no extra opcode.
	 *
	 * Unlike the policer the flag is conditional, because DSCP zero is a
	 * real codepoint -- CS0 is what an operator remarks *to* for best
	 * effort -- so "remark to zero" and "do not remark" have to be
	 * different states. These two fields are the first thing in the tree
	 * ever to write them: the hardware has always read them, and NXP left
	 * filling them to an iptables target nobody packaged. */
	ct->qosmark.dscp_mark_flag = (rule->qos & CDX_FT_QOS_REMARK_MASK) ? 1 : 0;
	ct->qosmark.dscp_mark_value = (rule->qos & CDX_FT_QOS_DSCP_MASK) >>
				      CDX_FT_QOS_DSCP_SHIFT;
	/* An encrypted direction names its SA, and the shared encoder does the
	 * rest: insert_entry_in_classif_table_encap() reads CONNTRACK_SEC and
	 * calls cdx_ipsec_fill_sec_info(), which resolves these handles and
	 * points the entry's action at the SEC frame queue instead of the
	 * egress port. That hook has been there all along, driven by the FCI
	 * conntrack command's SA_handle fields; this is the same description
	 * arriving from a different control plane.
	 *
	 * The array holds SA_MAX_OP so a stacked bundle (ESP under AH) can name
	 * both, and nothing here proves the opcode order such a bundle needs --
	 * so admission refuses more than one per end and the two slots are one
	 * per direction of travel rather than a stack.
	 *
	 * The two ends are independent. An outbound SA decides where the frame
	 * goes once it has matched; an inbound one decides where the entry has
	 * to live to be matched at all, because cdx_ipsec_fill_sec_info()
	 * answers it by replacing the table descriptor and port id with the
	 * offline port's. A direction can name either, or both when one tunnel
	 * feeds another. */
	if (rule->sa_handle) {
		ct->hSAEntry[0] = rule->sa_handle;
		ct->status |= CONNTRACK_SEC;
	}
	if (rule->in_sa_handle) {
		ct->hSAEntry[1] = rule->in_sa_handle;
		ct->status |= CONNTRACK_SEC;
	}
	/* A flow with no encapsulation asks for no override, and takes exactly
	 * the path it took before tags existed. The override refuses a
	 * description the interfaces already filled in -- a DSCP-to-PCP egress
	 * map is the one thing that does so -- and that refusal must not reach
	 * a flow that is not asking to replace anything. */
	if (insert_entry_in_classif_table_encap(
		    ct, encap.num_ingress || encap.num_egress ||
			encap.ingress_pppoe || encap.egress_pppoe ? &encap : NULL)) {
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

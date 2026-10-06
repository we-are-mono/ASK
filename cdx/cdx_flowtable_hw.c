// SPDX-License-Identifier: GPL-2.0-or-later
/* Firmware backend for independent Linux flowtable directions. The adapter
 * owns each direction's objects; no hash, notification or ageing timer here
 * does. */
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include "portdefs.h"
#include "cdx.h"
#include "control_ipv4.h"
#include "control_ipsec.h"
#include "control_tunnel.h"
#include "fm_ehash.h"
#include "cdx_flowtable_backend.h"
#include "cdx_flowtable_hw.h"
#include "cdx_police.h"

struct cdx_ft_hw {
	struct cdx_ft_hw *options;
	CtEntry entry;
	CtEntry twin;
	RouteEntry route;
	struct list_head retired;
	int delete_rc;
	/* Unlinked with its barrier deferred to the caller's next settle, and
	 * not yet failed by one (ft_owed). */
	bool owed;
	/* The ingress policer profile the rule named, kept so removal can unref
	 * it against the pool; also in delete_rc's padding. */
	u8 policer;
	/* In the padding delete_rc leaves, so an entry naming no record takes
	 * no more memory than one without the array. */
	unsigned int nstats;
	/* The statistics records the entry's opcodes name, recorded when the
	 * owner is allocated, so retirement still allocates nothing, and each
	 * held from the moment the key is linked until the entry is proven
	 * gone. */
	struct cdx_ft_stats_slot *stats[] __counted_by(nstats);
};

/* What nstats can reach: a session and a tunnel on each side and one record
 * per tag of each stack, which is every slot a binding can name -- the binding
 * being nothing else. A slot added to it fails here until the walk below
 * learns it. */
#define FT_HW_STATS_MAX (2 * (2 + CDX_FT_VLAN_MAX))
static_assert(sizeof(struct cdx_ft_stats_binding) ==
	      FT_HW_STATS_MAX * sizeof(struct cdx_ft_stats_slot *));

/* Retirement needs no allocation after unlink. Unlike the ehash quarantine
 * (cdx_ehash.c), the adapter can retain the already allocated owner until the
 * barrier passes. */
static LIST_HEAD(ft_retired);
/* The retired owners whose unlink deferred its barrier and that no barrier has
 * failed yet: what one settle owes. A delete's own barrier costs a
 * host-command round trip per key, which retiring a full table one key at a
 * time made seconds of control-mutex hold (A327). */
static unsigned int ft_owed;

#ifdef CDX_DEBUG_FLOWTABLE
static bool ft_fail_unlink;
module_param_named(flowtable_fail_unlink, ft_fail_unlink, bool, 0600);
MODULE_PARM_DESC(flowtable_fail_unlink, "One-shot delete failure leaving a live key linked; the datapath stops and restarts");
/* A count rather than a flag: a connection is two entries, and the retry that
 * follows a failed barrier runs at once, so a single withheld proof is settled
 * by the other direction's delete before anything that waits on it can be
 * observed. */
static unsigned int ft_fail_sync;
module_param_named(flowtable_fail_sync, ft_fail_sync, uint, 0600);
MODULE_PARM_DESC(flowtable_fail_sync, "Proofs to withhold: each completed unlink reports its barrier failed and each retry barrier fails, until spent");
#endif

static bool ft_unlink_fault(void)
{
#ifdef CDX_DEBUG_FLOWTABLE
	return xchg(&ft_fail_unlink, false);
#else
	return false;
#endif
}

/* One withheld proof: an unlink that completed, reported as one whose barrier
 * failed, or a retry barrier reported failed without being issued. Either
 * leaves the owner parked exactly as a real failure does, and recovery takes
 * its ordinary course once the count is spent. */
static bool ft_sync_fault(void)
{
#ifdef CDX_DEBUG_FLOWTABLE
	unsigned int left = READ_ONCE(ft_fail_sync);

	return left && cmpxchg(&ft_fail_sync, left, left - 1) == left;
#else
	return false;
#endif
}

static unsigned int ft_hw_note(struct cdx_ft_stats_slot *slot,
			       struct cdx_ft_stats_slot **table, unsigned int n)
{
	if (slot && table)
		table[n] = slot;
	return n + !!slot;
}

/* Every slot the binding names, whether or not the encoding carries its index:
 * holding one the opcodes do not reach only delays its reuse. One per name, so
 * a record named twice is held twice and put twice. Counts them, at most
 * FT_HW_STATS_MAX, and lists them in table when there is one. */
static unsigned int ft_hw_stats_walk(const struct cdx_ft_stats_binding *stats,
				     struct cdx_ft_stats_slot **table)
{
	unsigned int i, n = 0;

	n = ft_hw_note(stats->in_session, table, n);
	n = ft_hw_note(stats->out_session, table, n);
	n = ft_hw_note(stats->in_tunnel, table, n);
	n = ft_hw_note(stats->out_tunnel, table, n);
	for (i = 0; i < CDX_FT_VLAN_MAX; i++) {
		n = ft_hw_note(stats->in_vlan[i], table, n);
		n = ft_hw_note(stats->out_vlan[i], table, n);
	}
	return n;
}

/* The owner's end, only once nothing can walk its entry: a barrier completed
 * after the unlink, or the ports are stopped and detached. The records it
 * named go back to whoever else holds them, or to their pools. */
static void ft_hw_free(struct cdx_ft_hw *hw)
{
	unsigned int i;

	for (i = 0; i < hw->nstats; i++)
		cdx_ft_ifstats_put(hw->stats[i]);
	cdx_police_profile_unref(hw->policer);
	kfree(hw);
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

/* The record half each tag counts into, in the same reversed order. A tag
 * with no slot leaves zero, which the header manipulations read as no record;
 * they then emit no pointer for the stack at all, so one missing record costs
 * the whole stack its counters rather than counting the rest into slot zero. */
static void ft_encap_stats(struct cdx_ft_stats_slot *const *slots, u8 count,
			   bool receive, U8 *indices)
{
	u8 i;

	for (i = 0; i < count; i++) {
		const struct cdx_ft_stats_slot *slot = slots[i];

		if (slot)
			indices[count - 1 - i] = receive ? slot->rx_index : slot->tx_index;
	}
}

/* What this path will encode an egress to, which is the same set
 * cdx_ft_egress_supported() admits: an ethernet port, or a Wi-Fi VAP.
 *
 * Stated again here rather than delegated, because the two ask different
 * questions of different things. Admission resolves a netdev and asks whether
 * it may be used; this holds the onif already and asks what it is. The ingress
 * beside it stays ethernet-only, so a single shared predicate would have to be
 * told which side it was being asked about.
 *
 * A VAP egress needs nothing else from here: the shared encoder's
 * dpa_get_tx_fqid_devinfo_by_iface() already has a WLAN arm that resolves the
 * VAP's forwarding frame queue and the Wi-Fi offline port, so what this builds
 * is an ordinary entry with its enqueue target pointed elsewhere.
 */
static bool ft_hw_egress_onif(U8 type)
{
	return type == (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL) ||
	       type == (IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
}

static int ft_hw_add_one(const struct cdx_ft_rule *rule,
		  const struct cdx_ft_stats_binding *stats,
		  struct cdx_ft_hw **result, bool options)
{
	POnifDesc in, out;
	struct dpa_iface_info *in_iface, *out_iface;
	struct cdx_l2_encap encap = {};
	struct cdx_ft_hw *hw;
	unsigned int nstats, i;
	PCtEntry ct;
	int rc;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	*result = NULL;
	if ((rule->proto != IPPROTO_TCP && rule->proto != IPPROTO_UDP) ||
	    (rule->family != AF_INET && rule->family != AF_INET6))
		return ask_refuse(-EOPNOTSUPP);
	/* A direction handed to SEC carries the bound its SA puts on it and
	 * what SEC adds, both from admission, and names an SA that has to be
	 * there to encrypt it. */
	if (rule->sa_handle &&
	    (!rule->sa_mtu || !rule->sa_expansion ||
	     !cdx_ipsec_sa_outbound(rule->sa_handle))) {
		ask_dbg(ASK_DBG_DEVICE, "hw sa %u bound %u+%u names no outbound SA\n",
			rule->sa_handle, rule->sa_mtu, rule->sa_expansion);
		return ask_refuse(-EOPNOTSUPP);
	}
	/* The last gate before hardware, and the one whose silence is most
	 * expensive: a direction that reaches here has already satisfied
	 * admission, so a refusal means the two disagree, and the operands are
	 * what say how. */
	in_iface = dpa_get_ifinfo_by_netdev(rule->in);
	out_iface = dpa_get_ifinfo_by_netdev(rule->out);
	if (!in_iface || !out_iface || in_iface->itf_id >= L2_MAX_ONIF ||
	    out_iface->itf_id >= L2_MAX_ONIF) {
		ask_dbg(ASK_DBG_DEVICE, "hw iface in=%s(%s) out=%s(%s)\n",
			netdev_name(rule->in), in_iface ? "found" : "unresolved",
			netdev_name(rule->out), out_iface ? "found" : "unresolved");
		return ask_refuse(-EOPNOTSUPP);
	}
	in = get_onif_by_index(in_iface->itf_id);
	out = get_onif_by_index(out_iface->itf_id);
	if (!(in->flags & ENTRY_VALID) || !(out->flags & ENTRY_VALID) ||
	    !in->itf || !out->itf ||
	    in->itf->index != in_iface->itf_id || out->itf->index != out_iface->itf_id ||
	    in->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL) ||
	    !ft_hw_egress_onif(out->itf->type)) {
		ask_dbg(ASK_DBG_DEVICE,
			"hw onif in=%s type=0x%x valid=%d out=%s type=0x%x valid=%d\n",
			netdev_name(rule->in), in->itf ? in->itf->type : 0,
			!!(in->flags & ENTRY_VALID),
			netdev_name(rule->out), out->itf ? out->itf->type : 0,
			!!(out->flags & ENTRY_VALID));
		return ask_refuse(-EOPNOTSUPP);
	}
	/* Nothing to synchronize before encoding any more. This used to copy
	 * the admission-validated source MAC into the interface record,
	 * because the encoder read its Ethernet source from a cache that was
	 * filled once from perm_addr and never followed a change. The encoder
	 * reads the netdev directly now, and admission has already refused any
	 * direction whose source is not that port's current address, so the
	 * two agree by construction rather than by being copied. */
	nstats = ft_hw_stats_walk(stats, NULL);
	hw = kzalloc(struct_size(hw, stats, nstats), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;
	hw->nstats = nstats;
	ft_hw_stats_walk(stats, hw->stats);
	hw->route.itf = out->itf;
	hw->route.input_itf = in->itf;
	hw->route.underlying_input_itf = in->itf;
	/* The ucode checks the size of what it *transmits* against this, and
	 * for a direction handed to SEC that is the outer frame: the entry
	 * carries the expansion separately, in hdr_xpnd_sz, and the check adds
	 * it before comparing. Netfilter's MTU for such a flow is an inner one,
	 * so programming it directly fails every full-size frame -- 1438 + 62
	 * against 1438 -- and each one takes the exception path instead. The
	 * flow is then matched and counted and forwarded by the CPU anyway,
	 * which looks like an offload that works and performs like software:
	 * measured at 0.07 Gb/s against CMM's 2.54 on the same tunnel, with
	 * the software SEC submit counting once per packet.
	 *
	 * So the entry compares the inner packet against the bound Linux
	 * itself enforces for the direction -- the bundle's MTU, the smaller
	 * of the SA's on its outer path and the inner route's
	 * (xfrm_init_pmtu()) -- with the expansion put back on, as it is for a
	 * tunnel below: an oversized packet with DF goes to Linux for
	 * Fragmentation Needed with that bound. Netfilter's MTU is the
	 * bundle's when the packet that created the flow was transformed, and
	 * the plain inner route's when it was the reply, so the SA's MTU is
	 * taken in again here and the bound is the bundle's either way.
	 * Programming the egress port's MTU instead let a DF packet over an
	 * inner route's MTU through to SEC (A230). The SA's MTU and the
	 * expansion are the direction's, from the outer path at admission
	 * (cdx_ft_rule.sa_mtu): the SA's own date from its install, before a
	 * narrower path or a lower port MTU (A231). The entry is given the
	 * same expansion to add (ct->sec_expansion), so the two cannot differ. */
	if (rule->sa_handle)
		hw->route.mtu = min_t(u32, min_t(u32, rule->mtu, rule->sa_mtu) +
					   rule->sa_expansion,
				      rule->out_logical->mtu);
	else
		hw->route.mtu = rule->mtu;
	/* The same reasoning for a tunnel, where the expansion is a fixed
	 * header rather than SEC's variable one: Netfilter's MTU is the tunnel
	 * device's, already reduced by the outer header, and the microcode
	 * compares the outer packet against what it is given, so the header
	 * goes back on here. This is the arithmetic the tunnel-interface arm in
	 * devman.c does. */
	if (rule->out_tunnel.present)
		hw->route.mtu += rule->out_tunnel.header_size;
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
		 * port moved. */
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
	encap.ingress_session_id = rule->in_session.id;
	ether_addr_copy(encap.ingress_session_mac, rule->in_session.mac);
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
	/* The same halves for each tag's VLAN device, reversed as the tags
	 * themselves were: the binding is ordered like the rule and the
	 * description like dpa_l2hdr_info. */
	ft_encap_stats(stats->in_vlan, rule->in_vlans, true, encap.ingress_vlan_stats_index);
	ft_encap_stats(stats->out_vlan, rule->out_vlans, false, encap.egress_vlan_stats_index);
	/* A tunnel on either side, outside everything above. The egress header
	 * is built by tnl_build_header() from the endpoints, TTL and traffic
	 * class the walk recorded; the per-packet fields are the microcode's.
	 * The size it comes back with has to be
	 * the one admission derived from the device, or the two would be
	 * describing different headers. */
	if (rule->out_tunnel.present) {
		const struct cdx_ft_tunnel *tunnel = &rule->out_tunnel;
		struct cdx_tunnel_encap *egress = &encap.egress_tunnel;
		u32 fl = tunnel->family == AF_INET6 ?
			(htonl((u32)tunnel->tos << 20) | tunnel->flowlabel) : tunnel->tos;

		egress->present = 1;
		egress->mode = tunnel->mode == CDX_FT_TUNNEL_6O4 ? TNL_MODE_6O4 : TNL_MODE_4O6;
		egress->flags = tunnel->flags & CDX_FT_TUNNEL_INHERIT_TOS ? INHERIT_TC : 0;
		/* The outer IPv4 header carries no don't-fragment bit, which is
		 * a limitation of the INSERT_L3_HDR opcode rather than a choice:
		 * measured on the DK, the microcode fills the fragment field
		 * itself and ignores the template's, so a header built with DF
		 * still leaves the port without it. CMM's tunnel interface met
		 * the same wall and hardcoded frag_off to zero; this matches it.
		 * So the tunnel device's pmtudisc setting
		 * reaches the wire only for frames the CPU forwards. */
		egress->header_size = tnl_build_header(egress->mode, tunnel->local.all,
						       tunnel->remote.all, fl, tunnel->ttl,
						       0, egress->header);
		if (egress->header_size != tunnel->header_size) {
			kfree(hw);
			return ask_refuse(-EOPNOTSUPP);
		}
		egress->stats_index = stats->out_tunnel ? stats->out_tunnel->tx_index : 0;
	}
	if (rule->in_tunnel.present) {
		const struct cdx_ft_tunnel *tunnel = &rule->in_tunnel;
		struct cdx_tunnel_encap *ingress = &encap.ingress_tunnel;

		ingress->present = 1;
		ingress->mode = tunnel->mode == CDX_FT_TUNNEL_6O4 ? TNL_MODE_6O4 : TNL_MODE_4O6;
		ingress->header_size = tunnel->header_size;
		ingress->flags = tunnel->flags & CDX_FT_TUNNEL_DSCP_COPY ? DSCP_COPY : 0;
		ingress->stats_index = stats->in_tunnel ? stats->in_tunnel->rx_index : 0;
		/* Receive endpoints are the reverse of the configured transmit
		 * header. The classifier matches these before executing the strip. */
		if (tunnel->family == AF_INET) {
			struct iphdr header = {
				.protocol = IPPROTO_IPV6,
				.saddr = tunnel->remote.ip,
				.daddr = tunnel->local.ip,
			};

			memcpy(ingress->header, &header, sizeof(header));
		} else {
			struct ipv6hdr header = {
				.nexthdr = options ? IPPROTO_DSTOPTS : IPPROTO_IPIP,
				.saddr = tunnel->remote.in6,
				.daddr = tunnel->local.in6,
			};

			memcpy(ingress->header, &header, sizeof(header));
		}
	}
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
	 * egress port.
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
		ct->sec_expansion = rule->sa_expansion;
		ct->status |= CONNTRACK_SEC;
	}
	if (rule->in_sa_handle) {
		ct->hSAEntry[1] = rule->in_sa_handle;
		ct->status |= CONNTRACK_SEC;
	}
	/* A flow with no encapsulation asks for no override, and takes exactly
	 * the path it took before tags existed. The override refuses a
	 * description the interfaces already filled in, and that refusal must
	 * not reach a flow that is not asking to replace anything. */
	rc = insert_entry_in_classif_table_encap(
		ct, encap.num_ingress || encap.num_egress ||
		encap.ingress_pppoe || encap.egress_pppoe ||
		encap.ingress_tunnel.present || encap.egress_tunnel.present ?
		&encap : NULL);
	if (rc) {
		kfree(hw);
		/* A full bucket refuses the flow as a full table would. */
		return rc == -ENOSPC ? -ENOSPC : -EIO;
	}
	/* Linked, so the microcode can reach every record the opcodes name
	 * from the next hit on, and it may still reach them after the adapter
	 * has let the records go: this entry holds them itself. Every failure
	 * above freed an owner that held nothing. */
	for (i = 0; i < hw->nstats; i++)
		cdx_ft_ifstats_hold(hw->stats[i]);
	/* Hold the ingress policer profile this flow names so its filter's
	 * teardown cannot hand the profile to a new filter -- reprogramming its
	 * rate -- while this flow still meters against it. Released in ft_hw_free,
	 * once the entry is proven gone. The error paths above freed an hw whose
	 * policer is still zero, so their kfree needs no unref. */
	hw->policer = (rule->qos & CDX_FT_QOS_POLICER_MASK) >> CDX_FT_QOS_POLICER_SHIFT;
	cdx_police_profile_ref(hw->policer);
	*result = hw;
	return 0;
}

int cdx_ft_hw_add(const struct cdx_ft_rule *rule,
		  const struct cdx_ft_stats_binding *stats,
		  struct cdx_ft_hw **result)
{
	int rc = ft_hw_add_one(rule, stats, result, false);

	if (rc || !rule->in_tunnel.present || rule->in_tunnel.family != AF_INET6)
		return rc;
	/* Linux may send an encapsulation-limit destination option. Match
	 * its next-header byte too, so another encapsulation cannot borrow
	 * this entry merely by starting with a destination-options header. */
	rc = ft_hw_add_one(rule, stats, &(*result)->options, true);
	if (rc) {
		int retired = cdx_ft_hw_del(result);

		if (retired && retired != -EAGAIN)
			cdx_ft_fatal();
	}
	return rc;
}

void cdx_ft_hw_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
	hw_ct_get_active(hw->entry.ct);
	stats->packets = hw->entry.ct->pkts;
	stats->bytes = hw->entry.ct->bytes;
	stats->lastused = hw->entry.ct->timestamp;
	if (hw->options) {
		struct cdx_ft_counters extra;

		cdx_ft_hw_stats(hw->options, &extra);
		stats->packets += extra.packets;
		stats->bytes += extra.bytes;
		if ((s32)(extra.lastused - stats->lastused) > 0)
			stats->lastused = extra.lastused;
	}
}

/* Everything unlinked before a barrier that has just completed: the retired
 * entries still waiting on one, and the entries CDX parked for paths of its
 * own. LS1046A runs a single FMan PCD, so a sync issued through any table
 * proves them all; cdx_ft_claim() refuses a configuration spanning more than
 * one, where it would not. A possibly linked key -- any other delete_rc -- is
 * never released: no barrier makes freeing it safe. */
static unsigned int ft_retired_count;

static void ft_hw_retire(struct cdx_ft_hw *hw)
{
	list_add_tail(&hw->retired, &ft_retired);
	ft_retired_count++;
	ft_owed += hw->owed;
}

static void ft_hw_unretire(struct cdx_ft_hw *hw)
{
	list_del(&hw->retired);
	ft_retired_count--;
	ft_owed -= hw->owed;
}

static void ft_hw_release_synced(void)
{
	struct cdx_ft_hw *hw, *next;

	list_for_each_entry_safe(hw, next, &ft_retired, retired) {
		if (hw->delete_rc != EN_EHASH_DELETE_UNSYNCED)
			continue;
		ExternalHashTableEntryFree(hw->entry.ct->handle);
		kfree(hw->entry.ct);
		ft_hw_unretire(hw);
		ft_hw_free(hw);
	}
	cdx_ehash_quarantine_free_all();
}

static int ft_hw_del(struct cdx_ft_hw **entry, bool defer)
{
	struct cdx_ft_hw *hw = *entry;
	struct hw_ct *ct;
	int rc, options_rc = 0;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	if (!hw)
		return 0;
	if (hw->options)
		options_rc = ft_hw_del(&hw->options, defer);
	ct = hw->entry.ct;
	/* Preserve the real linked allocation to exercise fatal retirement.
	 * Never inject a hard error after a successful destructive unlink; a
	 * withheld proof is the one failure that can truthfully follow it --
	 * for a deferred unlink, at the settle that asks for it. */
	if (ft_unlink_fault())
		rc = -EIO;
	else if (defer)
		rc = ExternalHashTableUnlinkKey(ct->td, ct->index, ct->handle);
	else
		rc = ExternalHashTableDeleteKey(ct->td, ct->index, ct->handle);
	if (!rc && ft_sync_fault())
		rc = EN_EHASH_DELETE_UNSYNCED;
	*entry = NULL;
	if (!rc) {
		ExternalHashTableEntryFree(ct->handle);
		kfree(ct);
		ft_hw_free(hw);
		/* DeleteKey synced the PCD before reporting success, after
		 * every earlier unlink, so the same barrier settles those. */
		ft_hw_release_synced();
		return options_rc == -EIO ? -EIO : 0;
	}
	hw->delete_rc = rc;
	hw->owed = defer && rc == EN_EHASH_DELETE_UNSYNCED;
	ft_hw_retire(hw);
	if (rc == EN_EHASH_DELETE_UNSYNCED && options_rc != -EIO)
		return defer ? 0 : -EAGAIN;
	return -EIO;
}

int cdx_ft_hw_del(struct cdx_ft_hw **hw)
{
	return ft_hw_del(hw, false);
}

int cdx_ft_hw_unlink(struct cdx_ft_hw **hw)
{
	return ft_hw_del(hw, true);
}

unsigned int cdx_ft_hw_pending(void)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
	return ft_retired_count;
}

unsigned int cdx_ft_hw_owed(void)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
	return ft_owed;
}

/* The barrier every deferred unlink is owed, through the delete's fault knob
 * like the barrier each would have issued itself. A completed one releases
 * every unsynced owner, owed or not, as any barrier does. A failed one leaves
 * the owed owners exactly where a delete whose own barrier failed leaves its
 * owner, and says how many there were: they are owed nothing more than any
 * other unproven retirement, which cdx_ft_hw_retry() goes on asking for. */
int cdx_ft_hw_settle(unsigned int *unproven)
{
	struct cdx_ft_hw *hw;
	void *td = NULL;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	*unproven = 0;
	list_for_each_entry(hw, &ft_retired, retired)
		if (hw->owed) {
			td = hw->entry.ct->td;
			break;
		}
	if (!td)
		return 0;
	if (!ft_sync_fault() && !ExternalHashTableDeleteSync(td)) {
		ft_hw_release_synced();
		return 0;
	}
	list_for_each_entry(hw, &ft_retired, retired)
		if (hw->owed) {
			hw->owed = false;
			(*unproven)++;
		}
	ft_owed = 0;
	return -EAGAIN;
}

/* One barrier, since one proves every unlink before it: through the first
 * retired entry still waiting on one, or, with none, through CDX's own parked
 * backlog, which the backend waits on as well (cdx_ft_pending()) and which
 * nothing else would release until an unrelated delete happened to sync.
 *
 * Returns -EAGAIN while one of the backend's own retirements is unproven:
 * that barrier failed, or a hard failure remains. That one is not deleted
 * again here, with the ports running and its chain possibly half rewritten;
 * only stopped ports settle it (cdx_ft_hw_quiesced(), then the datapath
 * restart, which finds where the key is still linked before deleting it
 * there). CDX's backlog is released on the same success but
 * does not hold this up: it is not the backend's, and the callers that wait
 * on it read cdx_ft_pending() themselves. */
int cdx_ft_hw_retry(void)
{
	struct cdx_ft_hw *hw;
	void *td = NULL;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	list_for_each_entry(hw, &ft_retired, retired)
		if (hw->delete_rc == EN_EHASH_DELETE_UNSYNCED) {
			td = hw->entry.ct->td;
			break;
		}
	if (!td)
		cdx_ehash_quarantine_retry();
	else if (ft_sync_fault() || ExternalHashTableFmPcdHcSync(td))
		return -EAGAIN;
	else
		ft_hw_release_synced();
	return list_empty(&ft_retired) ? 0 : -EAGAIN;
}

/* Caller has stopped every classifier port, seen it idle, and completed a PCD
 * barrier since, which nothing a port had in hand outlasts. Unlinked storage
 * can now be freed even though its own barrier never completed. A possibly
 * linked key must stay allocated: freeing it would leave a dangling hash-chain
 * link. It goes to CDX's record of such keys, which the datapath restart
 * settles with the ports still stopped (cdx_ehash_resolve_abandoned()); its
 * statistics records and policer are released all the same, since no port is
 * left to deliver a frame that could reach its opcodes. Idempotent. */
void cdx_ft_hw_quiesced(void)
{
	struct cdx_ft_hw *hw, *next;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	list_for_each_entry_safe(hw, next, &ft_retired, retired) {
		if (hw->delete_rc == EN_EHASH_DELETE_UNSYNCED)
			ExternalHashTableEntryFree(hw->entry.ct->handle);
		else
			cdx_ehash_abandon(hw->entry.ct->td, hw->entry.ct->index,
					  hw->entry.ct->handle);
		kfree(hw->entry.ct);
		ft_hw_unretire(hw);
		ft_hw_free(hw);
	}
}

/* Nothing can prove the classifier done with the retired entries: a port CDX
 * did not configure still reaches it, or the host-command channel every
 * barrier goes through has failed. Each entry stays allocated, and so do the
 * statistics records and policer its opcodes name, for the reset that alone
 * settles them. It is recorded as possibly linked (cdx_ehash_abandon()), so
 * an unload that can prove it gone still frees it; only the backend's own
 * bookkeeping goes now. Idempotent. */
void cdx_ft_hw_strand(void)
{
	struct cdx_ft_hw *hw, *next;
	unsigned int kept = 0;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	list_for_each_entry_safe(hw, next, &ft_retired, retired) {
		cdx_ehash_abandon(hw->entry.ct->td, hw->entry.ct->index,
				  hw->entry.ct->handle);
		kfree(hw->entry.ct);
		ft_hw_unretire(hw);
		/* Not ft_hw_free(): its holds stay taken. */
		kfree(hw);
		kept++;
	}
	if (kept)
		pr_err("cdx flowtable: keeping %u retired entries and the records they name until reset\n",
		       kept);
}

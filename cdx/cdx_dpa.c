/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
        
/**     
 * @file                cdx_dpa.c     
 * @description         cdx DPAA interface functions
 */             

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "misc.h"
#include "cdx.h"
#include "cdx_common.h"
#include "types.h"
#include "list.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_tunnel.h"
#include "control_bridge.h"
#include "dpa_ipsec.h"
#include "devman.h"


//#define CDX_DPA_DEBUG 1

#ifdef CDX_DPA_DEBUG
#define CDX_DPA_DPRINT(fmt, args...) printk(KERN_ERR "%s:: " fmt, __func__, ##args)
#else
#define CDX_DPA_DPRINT(fmt, args...) do { } while(0)
#endif

//disable flow statistics



/* add ethernet type device */
int cdx_add_eth_onif(char *name)
{
	uint32_t ii;

	CDX_DPA_DPRINT("adding iface %s\n", name);
	//find free slot in phys list
	for (ii = 0; ii < MAX_PHY_PORTS; ii++) {
		if (!phy_port[ii].flags) {
			phy_port[ii].id = ii;
			phy_port[ii].flags = 
				(IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
			break;
		}
	}
	if (ii == MAX_PHY_PORTS) {
		DPA_ERROR("%s::mac phys port limit reached\n", __func__);
		return -EINVAL;
	}
	//call add onif to add device
	if (add_onif(name, &phy_port[ii].itf, NULL, 
				(IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL)) == NULL) 	{
		memset(&phy_port[ii], 0, sizeof(struct physical_port));
		DPA_ERROR("%s::add_onif failed\n", __func__);
		return -EIO;
	}
	//fill mac address in phys port
	dpa_get_mac_addr(name, &phy_port[ii].mac_addr[0]);
	CDX_DPA_DPRINT("added iface %s\n", name);
	return 0;
}

int cdx_add_oh_iface(char *name)
{

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::adding oh iface %s\n", __func__,
			name);
#endif
	if (dpa_add_oh_if(name)) {
		DPA_ERROR("%s::add oh port failed\n", __func__);
		return -EIO;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::added oh iface %s\n", __func__,
			name);
#endif
	return 0;
}

int add_incoming_iface_info(PCtEntry entry)
{
	struct _itf *iif;

	if (!entry->pRtEntry) {
		/* ASK-DIAG: offload attempted with no route entry at all */
		pr_err_ratelimited("ASK-DIAG add_incoming_iface_info: NO-ROUTE proto=%u sport=%u dport=%u status=0x%04x fftype=0x%02x\n",
				(unsigned int)entry->proto,
				(unsigned int)ntohs(entry->Sport),
				(unsigned int)ntohs(entry->Dport),
				(unsigned int)entry->status,
				(unsigned int)entry->fftype);
		return 1;
	}
	/* Prefer the logical input interface, but fall back to the physical
	 * ingress port when the logical one didn't resolve to a cdx onif
	 * (e.g. a VLAN on a vlan-aware bridge -- br-lan.N is not a
	 * registrable onif). The FMan classifier keys on physical port +
	 * 5-tuple, so the physical ingress alone is a complete discriminator;
	 * input_itf only fed per-VLAN ingress byte counters. */
	iif = entry->pRtEntry->input_itf;
	if (!iif)
		iif = entry->pRtEntry->underlying_input_itf;

	if (!iif)
	{
		PRouteEntry rt = entry->pRtEntry;
		const char *pn =
			entry->proto == IPPROTOCOL_TCP ? "TCP"  :
			entry->proto == IPPROTOCOL_UDP ? "UDP"  :
			entry->proto == 1              ? "ICMP" :
			entry->proto == 50             ? "ESP"  :
			entry->proto == 47             ? "GRE"  : "?";

		/* ASK-DIAG (permanent -- keep in production): neither the logical
		 * input interface nor the physical ingress port
		 * (underlying_input_itf) resolved, so the flow has no offloadable
		 * ingress at all -- typically a router-local flow (iif=0). With
		 * the VLAN-on-bridge fallback above, a healthy forwarded flow
		 * never reaches here, so seeing this in production means
		 * something is genuinely wrong. Full flow identity dumped to
		 * identify it; rate-limited (fires once per rejected flow). */
		if (IS_IPV6_FLOW(entry))
			pr_err_ratelimited("ASK-DIAG no-input-itf: %s %pI6c.%u -> %pI6c.%u %s status=0x%04x fftype=0x%02x route_id=0x%x oif[idx=%u type=0x%x phys=%d] onif_idx=%u underlying_iif[idx=%d] inPhyPort=%u\n",
				pn,
				entry->Saddr_v6, (unsigned int)ntohs(entry->Sport),
				entry->Daddr_v6, (unsigned int)ntohs(entry->Dport),
				(entry->status & CONNTRACK_ORIG) ? "ORIG" : "REPLY",
				(unsigned int)entry->status, (unsigned int)entry->fftype,
				(unsigned int)rt->id,
				(unsigned int)(rt->itf ? rt->itf->index : 0xff),
				(unsigned int)(rt->itf ? rt->itf->type : 0),
				(rt->itf && rt->itf->phys) ? (int)rt->itf->phys->index : -1,
				(unsigned int)rt->onif_index,
				rt->underlying_input_itf ? (int)rt->underlying_input_itf->index : -1,
				(unsigned int)entry->inPhyPortNum);
		else
			pr_err_ratelimited("ASK-DIAG no-input-itf: %s %pI4.%u -> %pI4.%u %s status=0x%04x fftype=0x%02x route_id=0x%x oif[idx=%u type=0x%x phys=%d] onif_idx=%u underlying_iif[idx=%d] inPhyPort=%u\n",
				pn,
				&entry->Saddr_v4, (unsigned int)ntohs(entry->Sport),
				&entry->Daddr_v4, (unsigned int)ntohs(entry->Dport),
				(entry->status & CONNTRACK_ORIG) ? "ORIG" : "REPLY",
				(unsigned int)entry->status, (unsigned int)entry->fftype,
				(unsigned int)rt->id,
				(unsigned int)(rt->itf ? rt->itf->index : 0xff),
				(unsigned int)(rt->itf ? rt->itf->type : 0),
				(rt->itf && rt->itf->phys) ? (int)rt->itf->phys->index : -1,
				(unsigned int)rt->onif_index,
				rt->underlying_input_itf ? (int)rt->underlying_input_itf->index : -1,
				(unsigned int)entry->inPhyPortNum);

		return ERR_UNKNOWN_INTERFACE;
	}

	entry->inPhyPortNum = iif->index;
	return NO_ERR;
}



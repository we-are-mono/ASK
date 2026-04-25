/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "portdefs.h"
#include "cdx.h"
#include "cdx_cmd_validator.h"
#include "control_stat.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_socket.h"
#include "control_bridge.h"
#include "control_tunnel.h"
#include "control_ipsec.h"
#include "control_pppoe.h"
#include "control_vlan.h"
#include "misc.h"

#define MAX_QUERY_TIMER_VAL 900
extern spinlock_t dpa_devlist_lock;
int stat_Get_Next_SAEntry(PStatIpsecEntryResponse pSACmd, int reset_action);
void reset_stats_of_sa(PSAEntry pEntry);
extern int fmdev_get_port_base_addr(struct device *dev, uint32_t *base);
int gStatIpsecQueryStatus;
int gIPSecStatQueryTimer;

U16 dpa_iface_stats_get( struct dpa_iface_info *iface_info, struct iface_stats *ifstats)
{
	if (!(iface_info->if_flags & IF_STATS_ENABLED))
	{
		DPA_ERROR("%s:: iface stats not enabled if_flags 0x%x\n", __func__, iface_info->if_flags);
		return ERR_STAT_FEATURE_NOT_ENABLED;
	}

	if(iface_info->if_flags & IF_TYPE_PPPOE) {
		struct en_ehash_ifstats_with_ts *stats;

		stats = (struct en_ehash_ifstats_with_ts *)iface_info->stats;
		ifstats->rx_packets = cpu_to_be32(stats->rxstats.pkts);
		ifstats->tx_packets = cpu_to_be32(stats->txstats.pkts);
		ifstats->rx_bytes = cpu_to_be64(stats->rxstats.bytes);
		ifstats->tx_bytes = cpu_to_be64(stats->txstats.bytes);
	} 
	else if(iface_info->if_flags & (IF_TYPE_TUNNEL | IF_TYPE_VLAN | IF_TYPE_ETHERNET)) {
		struct en_ehash_ifstats *stats;

		stats = (struct en_ehash_ifstats *)iface_info->stats;
		ifstats->rx_packets = cpu_to_be32(stats->rxstats.pkts);
		ifstats->tx_packets = cpu_to_be32(stats->txstats.pkts);
		ifstats->rx_bytes = cpu_to_be64(stats->rxstats.bytes);
		ifstats->tx_bytes = cpu_to_be64(stats->txstats.bytes);
	}
	else
	{
		DPA_ERROR("%s:: Invalid interface type 0x%x\n", __func__, iface_info->if_flags);
		return ERR_INVALID_INTERFACE_TYPE;
	}

	return NO_ERR;
}

void  dpa_iface_stats_reset(struct dpa_iface_info *iface_info, struct iface_stats *stats)
{
	struct iface_stats *last_stats;

	last_stats = iface_info->last_stats;
	last_stats->rx_packets = stats->rx_packets;
	last_stats->tx_packets = stats->tx_packets;
	last_stats->rx_bytes = stats->rx_bytes;
	last_stats->tx_bytes = stats->tx_bytes;

	return;
}

U16 interface_stats_reset(uint32_t interface)
{
	struct dpa_iface_info *iface_info;
	struct iface_stats ifstats;
	U16 ret = 0;

	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid(interface)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __func__, interface);
		return ERR_UNKNOWN_INTERFACE;
	}
	spin_unlock(&dpa_devlist_lock);
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __func__, ret);
		return ret;
	}
	dpa_iface_stats_reset(iface_info, &ifstats);

	return NO_ERR;
}

static U16 phyif_stats_get(U16 interface, PStatInterfacePktResponse rsp, U8 do_reset)
{
	struct iface_stats ifstats;
	struct dpa_iface_info *iface_info = NULL;
	struct iface_stats *last_stats;
	U16 ret = 0;

	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid((uint32_t)interface)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __func__, interface);
		return ERR_UNKNOWN_INTERFACE;
	}
	spin_unlock(&dpa_devlist_lock);
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __func__, ret);
		return ret;
	}
	
	last_stats = iface_info->last_stats;
	rsp->total_bytes_received[0] = statistics_get_lsb(ifstats.rx_bytes - last_stats->rx_bytes);
	rsp->total_bytes_received[1] = statistics_get_msb(ifstats.rx_bytes - last_stats->rx_bytes);
	rsp->total_pkts_received = ifstats.rx_packets - last_stats->rx_packets;

	rsp->total_bytes_transmitted[0] = statistics_get_lsb(ifstats.tx_bytes - last_stats->tx_bytes);
	rsp->total_bytes_transmitted[1] = statistics_get_msb(ifstats.tx_bytes - last_stats->tx_bytes);
	rsp->total_pkts_transmitted = ifstats.tx_packets - last_stats->tx_packets;

	if (do_reset)
		dpa_iface_stats_reset(iface_info, &ifstats);
	return NO_ERR;
}


static U16 stats_interface_pkt(U8 action, U16 interface, PStatInterfacePktResponse statInterfacePktRsp, U16 *acklen)
{
	U16 ackstatus = CMD_OK;

	if(action & FPP_STAT_QUERY)
	{
		if ((ackstatus = phyif_stats_get(interface, statInterfacePktRsp,
							action & FPP_STAT_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface(%d) stats, return value %d\n", __func__, interface, ackstatus);
			return ackstatus;
		}

		statInterfacePktRsp->rsvd1 = 0;
		*acklen = sizeof(StatInterfacePktResponse);
	}
	else if(action & FPP_STAT_RESET)
	{
		if ((ackstatus = interface_stats_reset((uint32_t)interface)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to reset interface(%d) stats, return value %d\n", __func__, interface, ackstatus);
			return ackstatus;
		}
	}
	else
		ackstatus = ERR_WRONG_COMMAND_PARAM;

	return ackstatus;
}



static U16 stats_connection(U16 action, PStatConnResponse statConnRsp, U16 *acklen)
{
	U16 ackstatus = CMD_OK;

	if(action & FPP_STAT_QUERY)
	{
		statConnRsp->num_active_connections = atomic_read(&num_active_connections);
		*acklen = sizeof(StatConnResponse);
	}
	else
		ackstatus = ERR_WRONG_COMMAND_PARAM;

	return ackstatus;
}


U32 stats_bitmask_enable_g = STAT_IPSEC_BITMASK;

static void stat_ct_flow_get(struct hw_ct *ct, U64 *pkts, U64 *bytes, int do_reset)
{
	if (!ct)
	{
		*pkts = 0;
		*bytes = 0;
		return;
	}
	hw_ct_get_active(ct);
	*pkts = ct->pkts - ct->reset_pkts;
	*bytes = ct->bytes - ct->reset_bytes;
	if (do_reset)
	{
		ct->reset_pkts = ct->pkts;
		ct->reset_bytes = ct->bytes;
	}
}

static void stat_ct_flow_reset(struct hw_ct *ct)
{
	U64 pkts;
	U64 bytes;

	stat_ct_flow_get(ct, &pkts, &bytes, TRUE);

	return;
}

/**
 * This function resets all IPv4 and IPv6 connections statistics counters
 */
static void ResetAllFlowStats(void)
{
	PCtEntry pCtEntry;
	struct slist_entry *entry;
	int ct_hash_index;

	for (ct_hash_index = 0; ct_hash_index < NUM_CT_ENTRIES; ct_hash_index++)
	{
		slist_for_each(pCtEntry, entry, &ct_cache[ct_hash_index], list)
		{
			stat_ct_flow_reset(pCtEntry->ct);
		}
	}
}

static U16 Get_Flow_stats(PStatFlowEntryResp flowStats, int do_reset)
{
	PCtEntry pEntry;

	if (flowStats->ip_family == 4)
	{
		pEntry = IPv4_find_ctentry(flowStats->Saddr, flowStats->Daddr, flowStats->Sport, flowStats->Dport, flowStats->Protocol);
		if (!pEntry)
		{
			printk("No connection for flow: saddr=%pI4 daddr=%pI4 sport=%u dport=%u proto=%u\n",
					&flowStats->Saddr, &flowStats->Daddr, htons(flowStats->Sport), htons(flowStats->Dport), flowStats->Protocol);
			return ERR_FLOW_ENTRY_NOT_FOUND;
		}
		stat_ct_flow_get(pEntry->ct, &flowStats->TotalPackets, &flowStats->TotalBytes, do_reset);
	}
	else if (flowStats->ip_family == 6)
	{
		pEntry = IPv6_find_ctentry(flowStats->Saddr_v6, flowStats->Daddr_v6, flowStats->Sport, flowStats->Dport, flowStats->Protocol);
		if (!pEntry)
		{
			printk("No connection for flow: saddr=%pI6c daddr=%pI6c sport=%u dport=%u proto=%u\n",
					flowStats->Saddr_v6, flowStats->Daddr_v6, htons(flowStats->Sport), htons(flowStats->Dport), flowStats->Protocol);
			return ERR_FLOW_ENTRY_NOT_FOUND;
		}
		stat_ct_flow_get(pEntry->ct, &flowStats->TotalPackets, &flowStats->TotalBytes, do_reset);
	}
	else
	{
		printk("ERROR: Invalid IP address family <0x%x>\n", flowStats->ip_family);
		return ERR_INVALID_IP_FAMILY;
	}

	return NO_ERR;
}

/**
 * M_stat_cmdproc
 *
 *
 *
 */
static U16 stat_enable_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	StatEnableCmd statcmd;

	(void)cmd_len;
	(void)out_reply_len;
	memcpy((U8 *)&statcmd, (U8 *)pcmd, sizeof(StatEnableCmd));

	if (statcmd.action == 1) {
		stats_bitmask_enable_g |= statcmd.bitmask;
	} else {
		if (statcmd.bitmask & STAT_IPSEC_BITMASK) {
			printk("ERROR: Disable IPSec stats not allowed. Because it disables ESP Sequence overfow rekeying.\n");
			return ERR_STAT_FEATURE_NOT_ALLOWED_TO_DISABLE;
		}
		stats_bitmask_enable_g &= ~(statcmd.bitmask);
	}
	return NO_ERR;
}

static U16 stat_interface_pkt_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U16 interface;
	U16 action;
	StatInterfaceCmd intPktCmd;
	PStatInterfacePktResponse statInterfacePktRsp;

	(void)cmd_len;
	if (!(stats_bitmask_enable_g & STAT_INTERFACE_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	memcpy((U8 *)&intPktCmd, (U8 *)pcmd, sizeof(StatInterfaceCmd));
	interface = intPktCmd.interface;
	action = intPktCmd.action;
	statInterfacePktRsp = (PStatInterfacePktResponse)pcmd;
	return (U16)stats_interface_pkt(action, interface, statInterfacePktRsp, out_reply_len);
}

static U16 stat_conn_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	StatConnectionCmd connCmd;
	PStatConnResponse statConnRsp;
	U16 action;

	(void)cmd_len;
	memcpy((U8 *)&connCmd, (U8 *)pcmd, sizeof(StatConnectionCmd));
	action = connCmd.action;
	statConnRsp = (PStatConnResponse)pcmd;
	return (U16)stats_connection(action, statConnRsp, out_reply_len);
}

static U16 stat_pppoe_status_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int x;
	struct slist_entry *entry;
	pPPPoE_Info pEntry;
	StatPPPoEStatusCmd pppoeStatusCmd;
	U16 action;
	U16 rc;

	(void)cmd_len;
	(void)out_reply_len;
	if (!(stats_bitmask_enable_g & STAT_PPPOE_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	memcpy((U8 *)&pppoeStatusCmd, (U8 *)pcmd, sizeof(StatPPPoEStatusCmd));
	action = pppoeStatusCmd.action;

	if (action == FPP_STAT_RESET) {
		for (x = 0; x < NUM_PPPOE_ENTRIES; x++) {
			slist_for_each(pEntry, entry, &pppoe_cache[x], list) {
				rc = (U16)interface_stats_reset((uint32_t)pEntry->itf.index);
				if (rc != NO_ERR) {
					DPA_ERROR("%s:: Failed to reset the pppoe stats.\n", __func__);
					return rc;
				}
			}
		}
		return NO_ERR;
	} else if (action == FPP_STAT_QUERY || action == FPP_STAT_QUERY_RESET) {
		gStatPPPoEQueryStatus = 0;
		if (action == FPP_STAT_QUERY_RESET)
			gStatPPPoEQueryStatus |= STAT_PPPOE_QUERY_RESET;
		return (U16)stat_PPPoE_Get_Next_SessionEntry((PStatPPPoEEntryResponse)pcmd, 1);
	}
	return ERR_WRONG_COMMAND_PARAM;
}

static U16 stat_pppoe_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PStatPPPoEEntryResponse prsp = (PStatPPPoEEntryResponse)pcmd;
	int result;

	(void)cmd_len;
	if (!(stats_bitmask_enable_g & STAT_PPPOE_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	result = stat_PPPoE_Get_Next_SessionEntry(prsp, 0);
	if (result != NO_ERR)
		prsp->eof = 1;
	*out_reply_len = sizeof(StatPPPoEEntryResponse);
	return NO_ERR;
}

static U16 stat_bridge_disabled_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)pcmd;
	(void)cmd_len;
	(void)out_reply_len;
	return ERR_STAT_FEATURE_NOT_ENABLED;
}

static U16 stat_vlan_status_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int x;
	PVlanEntry pEntry;
	struct slist_entry *entry;
	StatVlanStatusCmd vlanStatusCmd;
	U16 action;
	U16 rc;

	(void)cmd_len;
	(void)out_reply_len;
	if (!(stats_bitmask_enable_g & STAT_VLAN_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	memcpy((U8 *)&vlanStatusCmd, (U8 *)pcmd, sizeof(StatVlanStatusCmd));
	action = vlanStatusCmd.action;

	if (action == FPP_STAT_RESET) {
		for (x = 0; x < NUM_VLAN_ENTRIES; x++) {
			slist_for_each(pEntry, entry, &vlan_cache[x], list) {
				rc = (U16)interface_stats_reset((uint32_t)pEntry->itf.index);
				if (rc != NO_ERR) {
					DPA_ERROR("%s:: Failed to reset the vlan stats.\n", __func__);
					return rc;
				}
			}
		}
		return NO_ERR;
	} else if (action == FPP_STAT_QUERY || action == FPP_STAT_QUERY_RESET) {
		gStatVlanQueryStatus = 0;
		if (action == FPP_STAT_QUERY_RESET)
			gStatVlanQueryStatus |= STAT_VLAN_QUERY_RESET;
		return (U16)stat_VLAN_Get_Next_SessionEntry((PStatVlanEntryResponse)pcmd, 1);
	}
	return ERR_WRONG_COMMAND_PARAM;
}

static U16 stat_vlan_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PStatVlanEntryResponse prsp = (PStatVlanEntryResponse)pcmd;
	int result;

	(void)cmd_len;
	if (!(stats_bitmask_enable_g & STAT_VLAN_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	result = stat_VLAN_Get_Next_SessionEntry(prsp, 0);
	if (result != NO_ERR)
		prsp->eof = 1;
	*out_reply_len = sizeof(StatVlanEntryResponse);
	return NO_ERR;
}

static U16 stat_tunnel_status_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int x;
	PTnlEntry pEntry;
	struct slist_entry *entry;
	StatTunnelStatusCmd tunnelStatusCmd;
	U16 action;
	U16 rc;

	(void)cmd_len;
	(void)out_reply_len;
	if (!(stats_bitmask_enable_g & STAT_TUNNEL_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	memcpy((U8 *)&tunnelStatusCmd, (U8 *)pcmd, sizeof(StatTunnelStatusCmd));
	action = tunnelStatusCmd.action;

	if (action == FPP_STAT_RESET) {
		for (x = 0; x < NUM_TUNNEL_ENTRIES; x++) {
			slist_for_each(pEntry, entry, &tunnel_name_cache[x], list) {
				rc = (U16)interface_stats_reset((uint32_t)pEntry->itf.index);
				if (rc != NO_ERR) {
					DPA_ERROR("%s:: Failed to reset the tunnel stats.\n", __func__);
					return rc;
				}
			}
		}
		return NO_ERR;
	} else if (action == FPP_STAT_QUERY || action == FPP_STAT_QUERY_RESET) {
		gStatTunnelQueryStatus = 0;
		if (action == FPP_STAT_QUERY_RESET)
			gStatTunnelQueryStatus |= STAT_TUNNEL_QUERY_RESET;
		return (U16)stat_tunnel_Get_Next_SessionEntry((PStatTunnelEntryResponse)pcmd, 1);
	}
	return ERR_WRONG_COMMAND_PARAM;
}

static U16 stat_tunnel_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PStatTunnelEntryResponse prsp = (PStatTunnelEntryResponse)pcmd;
	int result;

	(void)cmd_len;
	if (!(stats_bitmask_enable_g & STAT_TUNNEL_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	result = stat_tunnel_Get_Next_SessionEntry(prsp, 0);
	if (result != NO_ERR)
		prsp->eof = 1;
	*out_reply_len = sizeof(StatTunnelEntryResponse);
	return NO_ERR;
}

#ifdef DPA_IPSEC_OFFLOAD
static U16 stat_ipsec_status_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int x;
	PSAEntry pEntry;
	struct slist_entry *entry;
	StatIpsecStatusCmd ipsecStatusCmd;
	U16 action;

	(void)cmd_len;
	(void)out_reply_len;
	if (!(stats_bitmask_enable_g & STAT_IPSEC_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	memcpy((U8 *)&ipsecStatusCmd, (U8 *)pcmd, sizeof(StatIpsecStatusCmd));
	action = ipsecStatusCmd.action;
	if (ipsecStatusCmd.iQueryTimerVal > MAX_QUERY_TIMER_VAL)
		return ERR_WRONG_COMMAND_PARAM;
	gIPSecStatQueryTimer = ipsecStatusCmd.iQueryTimerVal;

	if (action == FPP_STAT_RESET) {
		for (x = 0; x < NUM_SA_ENTRIES; x++) {
			slist_for_each(pEntry, entry, &sa_cache_by_h[x], list_h)
				reset_stats_of_sa(pEntry);
		}
		return NO_ERR;
	} else if (action == FPP_STAT_QUERY || action == FPP_STAT_QUERY_RESET) {
		gStatIpsecQueryStatus = 0;
		if (action == FPP_STAT_QUERY_RESET)
			gStatIpsecQueryStatus |= STAT_IPSEC_QUERY_RESET;
		/* Just initializes the static variables and returns. */
		stat_Get_Next_SAEntry((PStatIpsecEntryResponse)pcmd, 1);
		return NO_ERR;
	}
	return ERR_WRONG_COMMAND_PARAM;
}

static U16 stat_ipsec_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PStatIpsecEntryResponse prsp = (PStatIpsecEntryResponse)pcmd;
	int result;

	(void)cmd_len;
	if (!(stats_bitmask_enable_g & STAT_IPSEC_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	result = stat_Get_Next_SAEntry(prsp, 0);
	if (result != NO_ERR)
		prsp->eof = 1;
	*out_reply_len = sizeof(StatIpsecEntryResponse);
	return NO_ERR;
}
#endif

static U16 stat_flow_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	StatFlowStatusCmd flowEntryCmd;
	PStatFlowEntryResp pflowEntryResp;
	U16 action;
	U16 rc;
	int i;

	(void)cmd_len;
	if (!(stats_bitmask_enable_g & STAT_FLOW_BITMASK))
		return ERR_STAT_FEATURE_NOT_ENABLED;

	memcpy((U8 *)&flowEntryCmd, (U8 *)pcmd, sizeof(StatFlowStatusCmd));
	pflowEntryResp = (PStatFlowEntryResp)pcmd;
	action = flowEntryCmd.action;

	if (action == FPP_STAT_RESET) {
		ResetAllFlowStats();
		return NO_ERR;
	} else if (action == FPP_STAT_QUERY || action == FPP_STAT_QUERY_RESET) {
		pflowEntryResp->ip_family = flowEntryCmd.ip_family;
		if (pflowEntryResp->ip_family == 4) {
			pflowEntryResp->Saddr = flowEntryCmd.Saddr;
			pflowEntryResp->Daddr = flowEntryCmd.Daddr;
		} else {
			for (i = 0; i < 4; i++) {
				pflowEntryResp->Saddr_v6[i] = flowEntryCmd.Saddr_v6[i];
				pflowEntryResp->Daddr_v6[i] = flowEntryCmd.Daddr_v6[i];
			}
		}
		pflowEntryResp->Sport = flowEntryCmd.Sport;
		pflowEntryResp->Dport = flowEntryCmd.Dport;
		pflowEntryResp->Protocol = flowEntryCmd.Protocol;
		rc = (U16)Get_Flow_stats(pflowEntryResp, action == FPP_STAT_QUERY_RESET);
		if (rc == NO_ERR)
			*out_reply_len = sizeof(StatFlowEntryResp);
		return rc;
	}
	return ERR_WRONG_COMMAND_PARAM;
}

/*
 * FPP_CMD_IPR_V{4,6}_STATS: inner returns -1 on error, otherwise
 * the reply length in bytes (not a status). Pre-migration set
 * acklen = (U16)rc on success and ackstatus = ERR_WRONG_COMMAND_PARAM
 * on rc == -1. Preserve by passing the inner rc through
 * *out_reply_len on success and returning ERR_WRONG_COMMAND_PARAM
 * on failure.
 */
static U16 stat_ipr_v4_stats_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int rc;

	(void)cmd_len;
	rc = cdx_get_ipr_v4_stats((void *)pcmd);
	if (rc == -1)
		return ERR_WRONG_COMMAND_PARAM;
	*out_reply_len = (U16)rc;
	return NO_ERR;
}

static U16 stat_ipr_v6_stats_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	int rc;

	(void)cmd_len;
	rc = cdx_get_ipr_v6_stats((void *)pcmd);
	if (rc == -1)
		return ERR_WRONG_COMMAND_PARAM;
	*out_reply_len = (U16)rc;
	return NO_ERR;
}

/*
 * Lower bounds tightened from CDX_CMD_VAR(0, U16_MAX) to
 * sizeof(request struct) for every entry whose handler reads pcmd
 * via memcpy/cast (ISSUES.md A1b item 6). The handlers don't
 * length-check internally, so an undersized input would memcpy
 * uninit bytes from the FCI rbuf and read those as the request.
 * Setting min == sizeof(struct) makes the dispatcher reject those
 * before they reach the handler. Max stays at U16_MAX to preserve
 * compatibility with libfci callers that pre-size the buffer for
 * a larger response struct.
 *
 * Two exceptions:
 *  - CMD_STAT_BRIDGE_{STATUS,ENTRY} route to stat_bridge_disabled_handle
 *    which `(void)pcmd; (void)cmd_len;` — bridge stats aren't built
 *    in this port. No read-uninit risk; left at (0, U16_MAX).
 *  - FPP_CMD_IPR_V{4,6}_STATS write `struct ipr_statistics` into pcmd
 *    but the type is private to cdx_reassm.c. Promoting it to a
 *    shared header just to express the bound is more churn than
 *    the read-of-uninit risk justifies (write-only handler — no
 *    bytes from pcmd are read). Left at (0, U16_MAX).
 */
static const struct cdx_cmd_spec stat_cmd_table[] = {
	CDX_CMD_VAR(CMD_STAT_ENABLE,        sizeof(StatEnableCmd),         U16_MAX, NULL, stat_enable_handle),
	CDX_CMD_VAR(CMD_STAT_INTERFACE_PKT, sizeof(StatInterfaceCmd),      U16_MAX, NULL, stat_interface_pkt_handle),
	CDX_CMD_VAR(CMD_STAT_CONN,          sizeof(StatConnectionCmd),     U16_MAX, NULL, stat_conn_handle),
	CDX_CMD_VAR(CMD_STAT_PPPOE_STATUS,  sizeof(StatPPPoEStatusCmd),    U16_MAX, NULL, stat_pppoe_status_handle),
	CDX_CMD_VAR(CMD_STAT_PPPOE_ENTRY,   sizeof(StatPPPoEEntryResponse), U16_MAX, NULL, stat_pppoe_entry_handle),
	/* bridge stats not built — handlers ignore pcmd entirely. */
	CDX_CMD_VAR(CMD_STAT_BRIDGE_STATUS, 0, U16_MAX, NULL, stat_bridge_disabled_handle),
	CDX_CMD_VAR(CMD_STAT_BRIDGE_ENTRY,  0, U16_MAX, NULL, stat_bridge_disabled_handle),
	CDX_CMD_VAR(CMD_STAT_VLAN_STATUS,   sizeof(StatVlanStatusCmd),     U16_MAX, NULL, stat_vlan_status_handle),
	CDX_CMD_VAR(CMD_STAT_VLAN_ENTRY,    sizeof(StatVlanEntryResponse), U16_MAX, NULL, stat_vlan_entry_handle),
	CDX_CMD_VAR(CMD_STAT_TUNNEL_STATUS, sizeof(StatTunnelStatusCmd),   U16_MAX, NULL, stat_tunnel_status_handle),
	CDX_CMD_VAR(CMD_STAT_TUNNEL_ENTRY,  sizeof(StatTunnelEntryResponse), U16_MAX, NULL, stat_tunnel_entry_handle),
#ifdef DPA_IPSEC_OFFLOAD
	CDX_CMD_VAR(CMD_STAT_IPSEC_STATUS,  sizeof(StatIpsecStatusCmd),    U16_MAX, NULL, stat_ipsec_status_handle),
	CDX_CMD_VAR(CMD_STAT_IPSEC_ENTRY,   sizeof(StatIpsecEntryResponse), U16_MAX, NULL, stat_ipsec_entry_handle),
#endif
	CDX_CMD_VAR(CMD_STAT_FLOW,          sizeof(StatFlowStatusCmd),     U16_MAX, NULL, stat_flow_handle),
	/* IPR stats: see comment above re: ipr_statistics privacy. */
	CDX_CMD_VAR(FPP_CMD_IPR_V4_STATS,   0, U16_MAX, NULL, stat_ipr_v4_stats_handle),
	CDX_CMD_VAR(FPP_CMD_IPR_V6_STATS,   0, U16_MAX, NULL, stat_ipr_v6_stats_handle),
};

static U16 M_stat_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(stat_cmd_table, ARRAY_SIZE(stat_cmd_table),
				cmd_code, cmd_len, pcmd);
}


int statistics_init(void)
{
	set_cmd_handler(EVENT_STAT, M_stat_cmdproc);

	return 0;
}

void statistics_exit(void)
{

}



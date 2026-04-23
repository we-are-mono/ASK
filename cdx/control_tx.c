/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "cdx.h"
#include "cdx_cmd_validator.h"
#include "control_tx.h"
#include "misc.h"


char IF0_NAME[16] = TOSTR(DEFAULT_NAME_0);
char IF1_NAME[16] = TOSTR(DEFAULT_NAME_1);
char IF2_NAME[16] = TOSTR(DEFAULT_NAME_2);

DSCP_Vlan_PCP_Map_context gDscpVlanPcpMapCtx;

bool cdx_get_tx_dscp_vlanpcp_map_enable(uint32_t portid)
{
	return gDscpVlanPcpMapCtx.portid == portid ? 1 : 0;
}

static U16 update_port_dscp_vlan_pcp_map_cfg(uint8_t *ifname, uint8_t dscp, uint8_t vlan_pcp)
{
	struct cdx_port_info *port_info;

	port_info = get_dpa_port_info(ifname);
	if (!port_info)
	{
		DPA_ERROR("%s()::%d invalid interface name <%s>\n", __func__, __LINE__, ifname);
		return CMD_ERR;
	}

	if (gDscpVlanPcpMapCtx.portid == NO_TX_PORT)
	{
		DPA_ERROR("DSCP VLANPCP map is disabled on %s, first enable to configure it\n" , ifname);
		return CMD_OK;
	}
	if (gDscpVlanPcpMapCtx.portid != port_info->portid)
	{
		DPA_ERROR("To configure DSCP VLAN PCP mapping on %s, first disable on %s\n",
				 	ifname, get_dpa_port_name(gDscpVlanPcpMapCtx.portid));
		return CMD_OK;
	}
	if (set_dscp_vlan_pcp_map_cfg(dscp, vlan_pcp) != SUCCESS)
	{
		DPA_ERROR("%s (%d) failed to set DSCP VLAN PCP map cfg in muram memory\n", __func__,__LINE__);
		return CMD_ERR;
	}

	return CMD_OK;
}

static U16 update_port_dscp_vlan_pcp_map_status(uint8_t *ifname, uint8_t status)
{
	struct cdx_port_info *port_info;

	port_info = get_dpa_port_info(ifname);
	if (!port_info)
	{
		DPA_ERROR("%s()::%d invalid interface name <%s>\n", __func__, __LINE__, ifname);
		return CMD_ERR;
	}

	if (gDscpVlanPcpMapCtx.portid == NO_TX_PORT)
	{ 
		if (status == DSCP_VLAN_PCP_MAP_ENABLE)
		{
			if (reset_dscp_vlan_pcp_map_cfg() != SUCCESS)
			{
				DPA_ERROR("%s (%d) unable to enable DSCP VLAN PCP mapping on %s.\n",
									__func__,__LINE__, ifname);
				return CMD_ERR;
			}
			gDscpVlanPcpMapCtx.portid = (int32_t)port_info->portid;
		}
		else
		{
			DPA_ERROR("DSCP VLAN PCP mapping is already disabled on %s.\n", ifname);
			return CMD_OK;
		}
	}
	else if (gDscpVlanPcpMapCtx.portid == port_info->portid)
	{
		if (status == DSCP_VLAN_PCP_MAP_DISABLE)
		{
			if (reset_dscp_vlan_pcp_map_cfg() != SUCCESS)
			{
				DPA_ERROR("%s (%d) unable to disable DSCP VLAN PCP mapping on %s.\n",
									__func__,__LINE__, ifname);
				return CMD_ERR;
			}
			gDscpVlanPcpMapCtx.portid = NO_TX_PORT;
		}
		else
		{
			DPA_ERROR("DSCP VLAN PCP mapping on %s already enabled\n", ifname);
			return CMD_OK;
		}
	
	}
	else
	{
		DPA_ERROR("To configure DSCP VLAN PCP mapping on %s, first disable on %s\n",
				 	ifname, get_dpa_port_name(gDscpVlanPcpMapCtx.portid));
		return CMD_OK;
	}
	return CMD_OK;
}

static U16 get_port_dscp_vlan_pcp_map_cfg(PQueryDSCPVlanPCPMapCmd pCmd)
{
	struct cdx_port_info *port_info;

	port_info = get_dpa_port_info(pCmd->ifname);
	if (!port_info)
	{
		DPA_ERROR("%s()::%d invalid interface name <%s>\n", __func__, __LINE__, pCmd->ifname);
		return CMD_ERR;
	}

	pCmd->enable = DSCP_VLAN_PCP_MAP_DISABLE;
	if (gDscpVlanPcpMapCtx.portid == NO_TX_PORT)
	{
		DPA_INFO("DSCP VLAN PCP map is disabled on all ports.\n");
		return CMD_OK;
	}
	if (gDscpVlanPcpMapCtx.portid != port_info->portid)
	{
		DPA_INFO("DSCP VLAN PCP map is disabled on %s port and enabled on %s port.\n",
					pCmd->ifname, get_dpa_port_name(gDscpVlanPcpMapCtx.portid ));
		return CMD_OK;
	}
	pCmd->enable = DSCP_VLAN_PCP_MAP_ENABLE;

	if (get_dscp_vlan_pcp_map_cfg(pCmd) != SUCCESS)
	{
		DPA_ERROR("%s (%d) Failed to get DSCP VLAN PCP map configuration on port %s.\n",
					__func__,__LINE__, pCmd->ifname);
		return CMD_ERR;
	}

	return CMD_OK;
}

static void M_tx_port_update(PPortUpdateCommand cmd)
{
	char *if_name = get_onif_name(phy_port[cmd->portid].itf.index);

	strncpy(if_name, cmd->ifname, INTERFACE_NAME_LENGTH);
	if_name[INTERFACE_NAME_LENGTH - 1] = '\0';
}

/*
 * CMD_TX_ENABLE / CMD_TX_DISABLE / CMD_PORT_UPDATE share a
 * portid = pcmd[0] and bound-check portid < GEM_PORTS. The
 * dispatcher doesn't pass a group identifier, so each of the
 * three handlers does the check inline. DSCP/VLANPCP-map codes
 * do not use the portid from pcmd[0] and have no such check —
 * matches pre-migration `if (cmd_code < CMD_TX_DSCP_VLANPCP_MAP_STATUS)` gate.
 */
static inline U16 tx_portid_check(U16 *pcmd, U32 *portid_out)
{
	U32 portid = *pcmd;

	if (portid >= GEM_PORTS)
		return CMD_ERR;
	*portid_out = portid;
	return CMD_OK;
}

static U16 tx_enable_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U32 portid;
	U16 rc;

	(void)out_reply_len;
	rc = tx_portid_check((U16 *)pcmd, &portid);
	if (rc != CMD_OK)
		return rc;
	if (cmd_len > 2 && cmd_len > 14) {
		memcpy(phy_port[portid].mac_addr, &(((U8 *)pcmd)[14]), 6);
		phy_port[portid].flags |= TX_ENABLED;
	}
	return CMD_OK;
}

static U16 tx_disable_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U32 portid;
	U16 rc;

	(void)cmd_len;
	(void)out_reply_len;
	rc = tx_portid_check((U16 *)pcmd, &portid);
	if (rc != CMD_OK)
		return rc;
	phy_port[portid].flags &= ~TX_ENABLED;
	return CMD_OK;
}

static U16 tx_port_update_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U32 portid;
	U16 rc;

	(void)cmd_len;
	(void)out_reply_len;
	rc = tx_portid_check((U16 *)pcmd, &portid);
	if (rc != CMD_OK)
		return rc;
	M_tx_port_update((PPortUpdateCommand)pcmd);
	return CMD_OK;
}

static U16 tx_dscp_vlanpcp_map_status_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PDSCPVlanPCPMapCmd pMapCmd = (PDSCPVlanPCPMapCmd)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	return update_port_dscp_vlan_pcp_map_status(pMapCmd->ifname, pMapCmd->status);
}

static U16 tx_dscp_vlanpcp_map_cfg_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PDSCPVlanPCPMapCmd pMapCmd = (PDSCPVlanPCPMapCmd)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	return update_port_dscp_vlan_pcp_map_cfg(pMapCmd->ifname,
						pMapCmd->dscp, pMapCmd->vlan_pcp);
}

static U16 tx_query_iface_dscp_vlanpcp_map_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQueryDSCPVlanPCPMapCmd pQueryCmd = (PQueryDSCPVlanPCPMapCmd)pcmd;
	U16 rc;

	(void)cmd_len;
	rc = get_port_dscp_vlan_pcp_map_cfg(pQueryCmd);
	if (rc == CMD_OK)
		*out_reply_len = sizeof(QueryDSCPVlanPCPMapCmd);
	return rc;
}

static const struct cdx_cmd_spec tx_cmd_table[] = {
	CDX_CMD_VAR(CMD_TX_ENABLE,                  0, U16_MAX, NULL, tx_enable_handle),
	CDX_CMD_VAR(CMD_TX_DISABLE,                 0, U16_MAX, NULL, tx_disable_handle),
	CDX_CMD_VAR(CMD_PORT_UPDATE,                0, U16_MAX, NULL, tx_port_update_handle),
	CDX_CMD_VAR(CMD_TX_DSCP_VLANPCP_MAP_STATUS, 0, U16_MAX, NULL, tx_dscp_vlanpcp_map_status_handle),
	CDX_CMD_VAR(CMD_TX_DSCP_VLANPCP_MAP_CFG,    0, U16_MAX, NULL, tx_dscp_vlanpcp_map_cfg_handle),
	CDX_CMD_VAR(CMD_TX_QUERY_IFACE_DSCP_VLANPCP_MAP, 0, U16_MAX, NULL, tx_query_iface_dscp_vlanpcp_map_handle),
};

static U16 M_tx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(tx_cmd_table, ARRAY_SIZE(tx_cmd_table),
				cmd_code, cmd_len, pcmd);
}


int tx_init(void)
{
	int i;

	set_cmd_handler(EVENT_PKT_TX, M_tx_cmdproc);

	for (i = 0; i < MAX_PHY_PORTS; i++) {
		phy_port[i].id = i;
	}

	gDscpVlanPcpMapCtx.portid = NO_TX_PORT;

	return 0;
}

void tx_exit(void)
{
	int i;

	for (i = 0; i < GEM_PORTS; i++)
		remove_onif_by_index(phy_port[i].itf.index);
}

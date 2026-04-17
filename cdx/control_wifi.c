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
#include "system.h"
#include "layer2.h"
#include "globals.h"
#include "control_wifi.h"

#ifdef CFG_WIFI_OFFLOAD


struct 	tWifiIfDesc wifiDesc[MAX_WIFI_VAPS];

struct tRX_wifi_context gWifiRxCtx;


static int wifi_vap_entry( U16 *ptr, U16 len )
{
	struct wifiCmd cmd;
	struct tRX_wifi_context *rxc;
	int portid;
	struct physical_port	*port;

	rxc = &gWifiRxCtx;
	//printk("%s:%d\n", __func__, __LINE__);

	if (len != sizeof(struct wifiCmd))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy( &cmd, ptr, sizeof(struct wifiCmd));

	if( cmd.VAPID >= MAX_WIFI_VAPS )
		return ERR_UNKNOWN_ACTION;

	portid = PORT_WIFI_IDX + cmd.VAPID;
	port = phy_port_get(portid);

	switch (cmd.action)
	{
		case WIFI_REMOVE_VAP:
			printk(KERN_INFO "%s:%d Remove entry\n", __func__, __LINE__);
			if( wifiDesc[cmd.VAPID].VAPID == 0XFFFF )
				return ERR_WLAN_DUPLICATE_OPERATION;
			//printk("%s: PHYID:%d vapid:%d\n", __func__, portid, cmd.VAPID);

			wifiDesc[cmd.VAPID].VAPID = 0xFFFF;

			//bridge_interface_deregister(portid);

			remove_onif_by_index(port->itf.index);

			if ( rxc->users  )
				rxc->users--;

			break;

		case WIFI_ADD_VAP:
			if ( rxc->users >= MAX_WIFI_VAPS )
				return CMD_ERR;

			printk(KERN_INFO "%s:%d ADD entry \n", __func__, __LINE__);
			if( wifiDesc[cmd.VAPID].VAPID != 0XFFFF )
				return ERR_WLAN_DUPLICATE_OPERATION;

			if(!add_onif(cmd.ifname, &port->itf, NULL, IF_TYPE_WLAN | IF_TYPE_PHYSICAL))
			{
				return CMD_ERR;
			}

			if (dpa_add_wlan_if(cmd.ifname, &port->itf, cmd.VAPID, cmd.mac_addr)) {
				remove_onif_by_index(port->itf.index);
				wifiDesc[cmd.VAPID].VAPID = 0xFFFF;
				return CMD_ERR;
			}


			wifiDesc[cmd.VAPID].VAPID = cmd.VAPID;
			//bridge_interface_register(cmd.ifname, portid);

			memcpy(port->mac_addr, cmd.mac_addr, 6);
			if ( rxc->users < MAX_WIFI_VAPS )
				rxc->users++;

			break;
			/* Removed UPDATE_VAP as it is updating bridge mac address with vap's mac address 
				 This is handled using seperate command for all interfaces */
		default:
			return ERR_UNKNOWN_ACTION;


	}

	return NO_ERR;


}


static U16 wifi_vap_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)out_reply_len;
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	return (U16)wifi_vap_entry(pcmd, cmd_len);
}

static U16 wifi_vap_query_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	wifi_vap_query_response_t *vaps = (wifi_vap_query_response_t *)pcmd;
	struct physical_port *port;
	U16 i;

	(void)cmd_len;
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	printk("%s:%d\n", __func__, __LINE__);

	for (i = 0; i < MAX_WIFI_VAPS; i++) {
		vaps[i].vap_id = wifiDesc[i].VAPID;
		if (vaps[i].vap_id != 0xFFFF)
			vaps[i].phy_port_id = PORT_WIFI_IDX + i;
		port = phy_port_get(PORT_WIFI_IDX + i);
		memcpy(vaps[i].ifname, get_onif_name(port->itf.index), IF_NAME_SIZE);
	}

	*out_reply_len = sizeof(U16) + MAX_WIFI_VAPS * sizeof(wifi_vap_query_response_t);
	return CMD_OK;
}

static U16 wifi_vap_reset_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	struct tRX_wifi_context *rxc = &gWifiRxCtx;
	struct physical_port *port;
	U16 i;

	(void)pcmd;
	(void)cmd_len;
	(void)out_reply_len;
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	for (i = 0; i < MAX_WIFI_VAPS; i++) {
		if (wifiDesc[i].VAPID != 0xFFFF) {
			wifiDesc[i].VAPID = 0xFFFF;
			port = phy_port_get(PORT_WIFI_IDX + i);
			remove_onif_by_index(port->itf.index);
			if (rxc->users)
				rxc->users--;
		}
	}
	return CMD_OK;
}

static const struct cdx_cmd_spec wifi_rx_cmd_table[] = {
	CDX_CMD_VAR(CMD_WIFI_VAP_ENTRY, 0, U16_MAX, NULL, wifi_vap_entry_handle),
	CDX_CMD_VAR(CMD_WIFI_VAP_QUERY, 0, U16_MAX, NULL, wifi_vap_query_handle),
	CDX_CMD_VAR(CMD_WIFI_VAP_RESET, 0, U16_MAX, NULL, wifi_vap_reset_handle),
};

static U16 M_wifi_rx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(wifi_rx_cmd_table, ARRAY_SIZE(wifi_rx_cmd_table),
				cmd_code, cmd_len, pcmd);
}



static void M_wifi_init_rx(void)
{
	int i;
	struct physical_port	*port;


	set_cmd_handler(EVENT_PKT_WIFIRX, M_wifi_rx_cmdproc);

	for ( i = 0; i < MAX_WIFI_VAPS; i++ )
	{
		wifiDesc[i].VAPID = 0xFFFF;
		port = phy_port_get(PORT_WIFI_IDX + i);
		port->id = PORT_WIFI_IDX + i;
	}
}

int wifi_init(void)
{
	M_wifi_init_rx();

	return 0;
}

void wifi_exit(void)
{
}
#endif /* CFG_WIFI_OFFLOAD */

/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _CDX_CMDHANDLER_H_
#define _CDX_CMDHANDLER_H_

typedef U16 (*CmdProc)(U16 fcode, U16 length, U16 *rbuf);

extern CmdProc gCmdProcTable[];

#define set_cmd_handler(event, handler)		gCmdProcTable[event] = handler;

enum EVENTS {
	EVENT_FIRST = 0,
	EVENT_QM = EVENT_FIRST,
	EVENT_PKT_TX,
	EVENT_PKT_RX,
	EVENT_PKT_WIFIRX,
	EVENT_MC6,
	EVENT_MC4,
	EVENT_BRIDGE,
	EVENT_VLAN,
	EVENT_PPPOE,
	EVENT_IPV4,
	EVENT_IPV6,
	EVENT_IPS_IN,
	EVENT_TNL_IN,
	EVENT_STAT,
	EVENT_RTP_RELAY,
	EVENT_MAX
};

// Function codes
// 0x0000 -> 0x00FF : RX module
#define 	FC_RX				0x0000
#define	CMD_RX_ENABLE		0x0001	
#define	CMD_RX_DISABLE	0x0002	
#define CMD_RX_L2BRIDGE_ENABLE	0x0008
#define L2BRIDGE_FIRST_COMMAND	CMD_RX_L2BRIDGE_ENABLE
#define CMD_RX_L2BRIDGE_ADD	0x0009
#define CMD_RX_L2BRIDGE_REMOVE	0x000a
#define CMD_RX_L2BRIDGE_QUERY_STATUS	0x000b
#define CMD_RX_L2BRIDGE_QUERY_ENTRY	0x000c
#define CMD_RX_L2BRIDGE_FLOW_ENTRY	0x000d
#define CMD_RX_L2BRIDGE_MODE		0x000e
#define CMD_RX_L2BRIDGE_FLOW_TIMEOUT	0x000f
#define CMD_RX_L2BRIDGE_FLOW_RESET	0x0010
#define CMD_BRIDGED_ITF_UPDATE			0x0011

#define L2BRIDGE_LAST_COMMAND	CMD_BRIDGED_ITF_UPDATE
#define CMD_RX_LRO				0x0012

// 0x0100 -> 0x01FF : Ethernet module
#define 	FC_ETH				0x0001

// 0x0200 -> 0x02FF : QM module
#define 	FC_QM				0x0002
#define CMD_QM_QOSENABLE			0x0201
#define CMD_QM_FF_RATE				0x0208
#define CMD_QM_QUERY_FF_RATE			0x0209
#define CMD_QM_QUERY_IFACE_DSCP_FQID_MAP	0x020a /* This command to returns the DSCP FQID mapping on specific interface*/
#define CMD_QM_EXPT_RATE			0x020c
#define CMD_QM_QUERY				0x020d
#define CMD_QM_QUERY_EXPT_RATE  		0x020e

#define CMD_QM_RESET				0x0210
#define CMD_QM_SHAPER_CONFIG			0x0211
#define CMD_QM_WBFQ_CONFIG			0x0215
#define CMD_QM_CQ_CONFIG			0x0216
#define CMD_QM_CHNL_ASSIGN			0x0217
#define CMD_QM_DSCP_Q_MAP_STATUS		0x0218 /* This command sets the DSCP FQ mapping status either enable/disable. */
#define CMD_QM_DSCP_Q_MAP_CFG			0x0219 /* This command maps one DSCP value to a FQ using the provided configuration. */
#define CMD_QM_DSCP_Q_MAP_RESET 		0x021a /* This command resets the one DSCP mapping to none. */

#define CMD_QM_QUERY_QUEUE			0x0221

#define CMD_QM_INGRESS_POLICER_ENABLE		0x0224
#define CMD_QM_INGRESS_POLICER_CONFIG		0x0225
#define CMD_QM_INGRESS_POLICER_RESET		0x0226
#define CMD_QM_INGRESS_POLICER_QUERY_STATS	0x0227

#ifdef SEC_PROFILE_SUPPORT
#define CMD_QM_SEC_POLICER_CONFIG		0x0230
#define CMD_QM_SEC_POLICER_QUERY_STATS		0x0231
#define CMD_QM_SEC_POLICER_RESET		0x0232
#endif /* endif for SEC_PROFILE_SUPPORT */

// 0x0300 -> 0x03FF : IPv4 module
#define FC_IPV4						0x0003
#define CMD_IP_ROUTE				0x0313
#define CMD_IPV4_CONNTRACK			0x0314
#define CMD_IPV4_CONNTRACK_CHANGE	0x0315
#define CMD_IPV4_RESET				0x0316
#define CMD_IPV4_SET_TIMEOUT 		0x0319
#define CMD_IPV4_GET_TIMEOUT 		0x0320
#define CMD_IPV4_FF_CONTROL		0x0321

#define CMD_IPV4_SOCK_OPEN		0x0330
#define CMD_IPV4_SOCK_CLOSE		0x0331
#define CMD_IPV4_SOCK_UPDATE		0x0332


// 0x0400 -> 0x04FF : IPv6 module
#define FC_IPV6						0x0004
#define CMD_IPV6_CONNTRACK			0x0414
#define CMD_IPV6_CONNTRACK_CHANGE	0x0415
#define CMD_IPV6_RESET				0x0416
#define CMD_IPV6_GET_TIMEOUT 		0x0420
#define CMD_IPV6_SOCK_OPEN		0x0430
#define CMD_IPV6_SOCK_CLOSE		0x0431
#define CMD_IPV6_SOCK_UPDATE		0x0432


// 0x0500 -> 0x05FF : Tx module
#define FC_TX				0x0005
#define CMD_TX_ENABLE				0x0501
#define CMD_TX_DISABLE				0x0502
#define CMD_PORT_UPDATE				0x0505
#define CMD_TX_DSCP_VLANPCP_MAP_STATUS		0x0506
#define CMD_TX_DSCP_VLANPCP_MAP_CFG		0x0507
#define CMD_TX_QUERY_IFACE_DSCP_VLANPCP_MAP	0x0508

// 0x0600 -> 0x06FF : PPPoE module
#define FC_PPPOE                    0x0006
#define CMD_PPPOE_ENTRY             0x0601
#define CMD_PPPOE_ENTRY_CHANGE    	0x0602
#define CMD_PPPOE_GET_IDLE			0x0603
#define CMD_PPPOE_RELAY_ENTRY   	0x0610


// 0x0700 -> 0x07FF : MC4 and MC6 modules
#define	FC_MC						0x0007
#define	CMD_MC4_MULTICAST		0x0701
#define	CMD_MC4_RESET				0x0702
#define	CMD_MC6_MULTICAST		0x0703
#define	CMD_MC6_RESET				0x0704

// 0x0800 -> 0x08FF : RTP relay module
#define	FC_RTP						0x0008
#define	CMD_RTP_OPEN				0x0801
#define	CMD_RTP_UPDATE			0x0802
#define	CMD_RTP_TAKEOVER			0x0803
#define	CMD_RTP_CONTROL			0x0804
#define	CMD_RTP_SPECTX_PLD		0x0805
#define	CMD_RTP_SPECTX_CTRL		0x0806
#define	CMD_RTCP_QUERY			0x0807
#define	CMD_RTP_CLOSE				0x0808

#define CMD_RTP_STATS_DTMF_PT		0x0813

#define CMD_VOICE_BUFFER_RESET		0x0824

// 0x0900 -> 0x09FF : VLAN module
#define FC_VLAN                     0x0009
#define CMD_VLAN_ENTRY				0x0901
#define CMD_VLAN_ENTRY_RESET		0x0902

// 0x0a00 -> 0x0aff : IPSec module
#define   FC_IPSEC		                     0x000A
#define 	CMD_IPSEC_SA_CREATE		0x0A01	
#define 	CMD_IPSEC_SA_DELETE 		0x0A02
#define 	CMD_IPSEC_SA_FLUSH 		0x0A03
#define 	CMD_IPSEC_SA_SET_KEYS 	0x0A04
#define 	CMD_IPSEC_SA_SET_TUNNEL 	0x0A05
#define 	CMD_IPSEC_SA_SET_NATT 	0x0A06
#define 	CMD_IPSEC_SA_SET_STATE 	0x0A07
#define 	CMD_IPSEC_SA_SET_LIFETIME 	0x0A08
#define   	CMD_IPSEC_SA_NOTIFY		0x0A09
#define   	CMD_IPSEC_SA_ACTION_QUERY	0x0A0A
#define 	CMD_IPSEC_SA_ACTION_QUERY_CONT	0x0A0B
#define   	CMD_IPSEC_FRAG_CFG		0x0A14
#define     CMD_IPSEC_SA_SET_TNL_ROUTE      0x0A15
#define 	CMD_IPSEC_SEC_FAILURE_STATS         0x0A17
#define 	CMD_IPSEC_RESET_SEC_FAILURE_STATS   0xA18

// 0x0b00 -> 0x0bff : Tunnel module
#define   FC_TNL		                     0x000B
#define 	CMD_TNL_CREATE		0x0B01	
#define 	CMD_TNL_DELETE 		0x0B02
#define 	CMD_TNL_UPDATE		0x0B03
#define	CMD_TNL_IPSEC			0x0B04
#define	CMD_TNL_QUERY			0x0B05
#define	CMD_TNL_QUERY_CONT		0x0B06
#define CMD_TNL_4o6_ID_CONVERSION_dupsport 0x0B07
#define CMD_TNL_4o6_ID_CONVERSION_psid  0x0B08

// 0x0c00 -> 0x0cFF : QM module
#define 	FC_EXPT					0x000c
#define  CMD_EXPT_QUEUE_DSCP		0x0c01
#define  CMD_EXPT_QUEUE_CTRL		0x0c02
#define  CMD_EXPT_QUEUE_RESET		0x0c03

// 0x0d00-> 0x0dFF : Packet capture module


/* 0x0e00 -> 0x0eff : Stat module */
#define FC_STAT                          	0x000E
#define CMD_STAT_ENABLE                 	0x0E01 
#define CMD_STAT_INTERFACE_PKT              	0x0E03
#define CMD_STAT_CONN           		0x0E04
#define CMD_STAT_PPPOE_STATUS			0x0E05
#define CMD_STAT_PPPOE_ENTRY			0x0E06
#define CMD_STAT_BRIDGE_STATUS			0x0E07
#define CMD_STAT_BRIDGE_ENTRY			0x0E08
#define CMD_STAT_IPSEC_STATUS			0x0E09
#define CMD_STAT_IPSEC_ENTRY			0x0E0A
#define CMD_STAT_VLAN_STATUS			0x0E0B
#define CMD_STAT_VLAN_ENTRY			0x0E0C
#define CMD_STAT_TUNNEL_STATUS			0x0E0D
#define CMD_STAT_TUNNEL_ENTRY			0x0E0E
#define CMD_STAT_FLOW				0x0E0F 
#define FPP_CMD_IPR_V4_STATS                    0x0E10
#define FPP_CMD_IPR_V6_STATS                    0x0E11

// 0x0f00 ->0x0fff : Trace/Profiling/Debugging
#define         FC_TRC                          	0x000f
/* Command return codes */

// 0x1000: Alternate Configuration
#define FC_ALTCONF				0x0010

//0x2000: WiFi Rx module
#define FC_WIFI_RX			0x0020 
#define CMD_WIFI_VAP_ENTRY              0x2001
#define CMD_WIFI_VAP_QUERY              0x2004
#define CMD_WIFI_VAP_RESET              0x2005

// 0x1400 -> 0x14ff : MACVLAN module
#define   	FC_MACVLAN		        0x0014
#define 	CMD_MACVLAN_ENTRY		0x1401	
#define 	CMD_MACVLAN_ENTRY_RESET 	0x1402
// 0x1200: Fppdiag configuration
#define FC_FPPDIAG					0x0012

// 0x1500: ICC

// return codes
#define CMD_OK	0x0000
#define CMD_ERR 0xFFFE

int FCODE_TO_EVENT(U32 fcode);
void cdx_cmd_handler(U16 fcode, U16 length, U16 *payload, U16 *rlen, U16 *rbuf);
int cdx_cmdhandler_init(void);
void cdx_cmdhandler_exit(void);

int comcerto_fpp_send_command(u16 fcode, u16 length, u16 *payload, u16 *rlen, u16 *rbuf);
int comcerto_fpp_register_event_cb(int (*event_cb)(u16, u16, u16*));

#endif /* _CDX_CMDHANDLER_H_ */

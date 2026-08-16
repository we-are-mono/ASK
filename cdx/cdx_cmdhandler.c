/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include "cdx.h"

/*
 * Concurrency:
 *   gCmdProcTable[EVENT_MAX] (file-scope array of function ptrs)
 *      - Populated in cdx_cmdhandler_init() (module init) via
 *        set_cmd_handler() calls. cdx_main.c holds ctrl->mutex
 *        across init and across exit. No per-command mutation
 *        at runtime.
 *
 *   Command dispatch itself is serialized by cdx_info->ctrl.mutex
 *   (owned by cdx_main.c): the FCI inbound netlink callback takes
 *   this mutex, looks up the handler in gCmdProcTable, and invokes
 *   it. Handlers therefore run single-threaded within the FCI
 *   transport and rely on their own subsystem locks (the various
 *   *_query_mutex, dpa_cfg_lock, abm_lock, etc.) only for
 *   synchronization against non-FCI callers.
 *
 * Contexts:
 *   cdx_cmdhandler_init/exit              - module load/unload,
 *                                           under ctrl->mutex.
 *   set_cmd_handler, FCODE_TO_EVENT       - process, init-time
 *                                           or callback-time.
 *   comcerto_fpp_send_command / dispatch  - process, under
 *                                           ctrl->mutex.
 */

CmdProc gCmdProcTable[EVENT_MAX];

int FCODE_TO_EVENT(U32 fcode)
{
	int eventid;
	switch((fcode & 0xFF00) >> 8)
	{
		case FC_RX:
			if (fcode >= L2BRIDGE_FIRST_COMMAND && fcode <= L2BRIDGE_LAST_COMMAND)
				eventid = EVENT_BRIDGE;
			else
				eventid = EVENT_PKT_RX;
			break;

		case FC_IPV4: eventid = EVENT_IPV4; break;

		case FC_IPV6: eventid = EVENT_IPV6; break;

		case FC_QM: eventid = EVENT_QM; break;

		case FC_TX: eventid = EVENT_PKT_TX; break;

		case FC_PPPOE: eventid = EVENT_PPPOE; break;

		case FC_MC: if(fcode <= CMD_MC4_RESET)
									eventid = EVENT_MC4;
								else 
									eventid = EVENT_MC6;             
								break;

		case FC_RTP: eventid = EVENT_RTP_RELAY; break;

		case FC_VLAN: eventid = EVENT_VLAN; break;

		case FC_IPSEC: eventid = EVENT_IPS_IN; break;

		case FC_TNL:eventid = EVENT_TNL_IN; break;

		case FC_STAT: eventid = EVENT_STAT; break;

		case FC_ALTCONF: eventid = EVENT_IPV4; break;

		case FC_WIFI_RX: eventid = EVENT_PKT_WIFIRX; break;

		case FC_FPPDIAG: eventid = EVENT_IPV4; break;

		default: eventid = -1; break;
	}

	return eventid;
}

void cdx_cmd_handler(U16 fcode, U16 length, U16 *payload, U16 *rlen, U16 *rbuf)
{
	CmdProc cmdproc;
	int eventid;

	eventid = FCODE_TO_EVENT(fcode);
/////////////////////////////////////////////////////////////////////////////
	// TEMP code to satisfy CMM
	if (fcode == CMD_VOICE_BUFFER_RESET)
	{
		rbuf[0] = NO_ERR;
		*rlen = 2;
	}
	else
/////////////////////////////////////////////////////////////////////////////
	if (eventid >= 0 && (cmdproc = gCmdProcTable[eventid]) != NULL)
	{
		memcpy(rbuf, payload, length);
		*rlen = (*cmdproc)(fcode, length, rbuf);
		if (*rlen == 0)
		{
			rbuf[0] = NO_ERR;
			*rlen = 2;
		}
	}
	else
	{
		rbuf[0] = ERR_UNKNOWN_COMMAND;
		*rlen = 2;
	}
	if (rbuf[0] != NO_ERR)
		DPRINT("rbuf[0]=0x%04x, *rlen=%d\n", rbuf[0], *rlen);
}

#define CMD_DECLARE(xx)		\
static BOOL xx##_init_flag = 0;	\
int xx##_init(void);		\
void xx##_exit(void);		\

#define CMD_INIT(xx) do {	\
	rc = xx##_init();	\
	if (rc < 0)		\
		goto exit;	\
	xx##_init_flag = 1;	\
	} while (0)

#define CMD_EXIT(xx) do {	\
	if (xx##_init_flag)	\
		xx##_exit();	\
	xx##_init_flag = 0;	\
	} while (0)

CMD_DECLARE(tx)
CMD_DECLARE(rx)
CMD_DECLARE(pppoe)
CMD_DECLARE(vlan)
CMD_DECLARE(ipv4)
CMD_DECLARE(ipv6)
CMD_DECLARE(socket)
CMD_DECLARE(tunnel)
CMD_DECLARE(bridge)
CMD_DECLARE(qm)
CMD_DECLARE(statistics)
#ifdef DPA_IPSEC_OFFLOAD 
CMD_DECLARE(ipsec)
#endif
#ifdef WIFI_ENABLE
CMD_DECLARE(wifi)
#endif
CMD_DECLARE(mc4)
CMD_DECLARE(mc6)
CMD_DECLARE(rtp_relay)

int __init cdx_cmdhandler_init(void)
{
	int rc = 0;

	CMD_INIT(tx);
	CMD_INIT(rx);
	CMD_INIT(pppoe);
	CMD_INIT(vlan);
	CMD_INIT(ipv4);
	CMD_INIT(ipv6);
	CMD_INIT(socket);
	CMD_INIT(tunnel);
	CMD_INIT(bridge);
	CMD_INIT(qm);
	CMD_INIT(statistics);
#ifdef DPA_IPSEC_OFFLOAD 
	CMD_INIT(ipsec);
#endif
#ifdef WIFI_ENABLE
	CMD_INIT(wifi);
#endif
	CMD_INIT(mc4);
	CMD_INIT(mc6);
	CMD_INIT(rtp_relay);

exit:
	return rc;
}

void cdx_cmdhandler_exit(void)
{
	DPRINT("\n");

	// EXIT routines must be in reverse order from the INIT routines

	CMD_EXIT(rtp_relay);
	CMD_EXIT(mc6);
	CMD_EXIT(mc4);
#ifdef WIFI_ENABLE
	CMD_EXIT(wifi);
#endif
#ifdef DPA_IPSEC_OFFLOAD 
	CMD_EXIT(ipsec);
#endif
	CMD_EXIT(statistics);
	CMD_EXIT(qm);
	CMD_EXIT(bridge);
	CMD_EXIT(tunnel);
	CMD_EXIT(socket);
	CMD_EXIT(ipv6);
	CMD_EXIT(ipv4);
	CMD_EXIT(vlan);
	CMD_EXIT(pppoe);
	CMD_EXIT(rx);
	CMD_EXIT(tx);
}

int comcerto_fpp_send_command(u16 fcode, u16 length, u16 *payload, u16 *rlen, u16 *rbuf)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	mutex_lock(&ctrl->mutex);

	cdx_cmd_handler(fcode, length, payload, rlen, rbuf);

	mutex_unlock(&ctrl->mutex);

	return 0;
}
EXPORT_SYMBOL(comcerto_fpp_send_command);







/**
 * comcerto_fpp_register_event_cb -
 *
 */
int comcerto_fpp_register_event_cb(int (*event_cb)(u16, u16, u16*))
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	/* register FCI callback used for asynchrounous event */
	ctrl->event_cb = event_cb;

	return 0;
}
EXPORT_SYMBOL(comcerto_fpp_register_event_cb);




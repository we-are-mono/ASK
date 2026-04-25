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
#include "control_rx.h"

static U16 rx_enable_disable_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U32 portid = (U8)*(U16 *)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	if (portid >= GEM_PORTS)
		return CMD_ERR;
	return CMD_OK;
}

static U16 rx_lro_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U8 enable = (U8)*(U16 *)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	if (enable > 0)
		return CMD_ERR;
	return CMD_OK;
}

static const struct cdx_cmd_spec rx_cmd_table[] = {
	/* All three handlers read pcmd[0..1] as a U16 (portid for
	 * ENABLE/DISABLE, enable flag for LRO). Tightened from
	 * CDX_CMD_VAR(0, U16_MAX) per ISSUES.md A1b item 6. */
	CDX_CMD_VAR(CMD_RX_ENABLE,  sizeof(U16), U16_MAX, NULL, rx_enable_disable_handle),
	CDX_CMD_VAR(CMD_RX_DISABLE, sizeof(U16), U16_MAX, NULL, rx_enable_disable_handle),
	CDX_CMD_VAR(CMD_RX_LRO,     sizeof(U16), U16_MAX, NULL, rx_lro_handle),
};

static U16 M_rx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(rx_cmd_table, ARRAY_SIZE(rx_cmd_table),
				cmd_code, cmd_len, pcmd);
}


int rx_init(void)
{
	set_cmd_handler(EVENT_PKT_RX, M_rx_cmdproc);

	ff_enable = 1;

	return 0;
}

void rx_exit(void)
{
}

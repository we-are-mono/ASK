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
#include "control_rx.h"

int rx_init(void)
{
	/*
	 * The RX command surface (CMD_RX_ENABLE/DISABLE/LRO) was inherited
	 * NXP no-op stub surface: validation-only handlers that returned
	 * CMD_OK with no side effect, and no sender ever existed. Dropped.
	 * FCODE_TO_EVENT still routes non-bridge 0x00xx fcodes to
	 * EVENT_PKT_RX, which now has no registered handler — cdx_cmd_handler
	 * returns ERR_UNKNOWN_COMMAND for them. rx_init still enables the
	 * fast-forward path.
	 */
	ff_enable = 1;

	return 0;
}

void rx_exit(void)
{
}

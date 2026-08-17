/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_PPPOE_H_
#define _CONTROL_PPPOE_H_

#include "cdx_common.h"
#include "control_bridge.h"

#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */

#define PPPOE_AUTO_MODE  	0x1

typedef struct _tPPPoE_Info {
	itf_t itf;

	struct slist_entry list;

	/* store following two items in network order */
	U8 DstMAC[ETHER_ADDR_LEN];
	U16 sessionID;

	U32 ppp_flags;
} PPPoE_Info, *pPPPoE_Info;

typedef struct _tPPPoECommand {
    U16 action;
    U16 sessionID;
    U8  macAddr[6];
    U8  phy_intf[IF_NAME_SIZE];
    U8  log_intf[IF_NAME_SIZE];
    U16 mode;
} PPPoECommand, *pPPPoECommand;

int pppoe_init(void);
void pppoe_exit(void);

static __inline U32 HASH_PPPOE(U16 session_id, U8 *srcmac)
{
	return ((session_id & 0xff) ^ (session_id >> 8) ^ srcmac[5]) & (NUM_PPPOE_ENTRIES - 1);
}

#endif /* _CONTROL_PPPOE_H_ */

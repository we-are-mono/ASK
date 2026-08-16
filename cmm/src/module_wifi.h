/*
 *
 *  Copyright (C) 2007 Mindspeed Technologies, Inc.
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 *
 */

#ifndef __MODULE_WIFI__
#define __MODULE_WIFI__
#include "itf.h"

typedef struct vwd_cmd_s {
	int32_t		action;
	int32_t		ifindex;
	int16_t		vap_id;
	int16_t		direct_path_rx;
	int16_t		no_l2_itf;
	char		ifname[IFNAMSIZ];
	u_int8_t	macaddr[6];
} __attribute__((__packed__)) vwd_cmd_t;

void __cmmGetWiFi(int fd, struct interface *itf);
int cmmFeWiFiUpdate(FCI_CLIENT *fci_handle, int fd, int request, struct interface *itf);
void cmmWiFiReset(FCI_CLIENT *fci_handle);

#endif //__MODULE_WIFI__

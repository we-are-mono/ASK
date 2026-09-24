/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _GLOBALS_H_
#define _GLOBALS_H_

// The main module sets DEFINE_GLOBALS

#ifdef DEFINE_GLOBALS
#define GLOBAL_DEFINE
#else
#define GLOBAL_DEFINE extern
#endif

// Global variables

GLOBAL_DEFINE struct _cdx_info *cdx_info;

GLOBAL_DEFINE OnifDesc gOnif_DB[L2_MAX_ONIF+1] __attribute__((aligned(32)));
GLOBAL_DEFINE struct physical_port phy_port[MAX_PHY_PORTS];

#define phy_port_get(port)      (&phy_port[port])

#endif /* _GLOBALS_H_ */

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
#include "control_tx.h"

/* Every physical port slot knows its own index: the Ethernet ports first,
 * then one per Wi-Fi VAP from PORT_WIFI_IDX up. */
int tx_init(void)
{
	int i;

	for (i = 0; i < MAX_PHY_PORTS; i++)
		phy_port[i].id = i;

	return 0;
}

/* Release the logical interfaces the Ethernet ports registered. */
void tx_exit(void)
{
	int i;

	for (i = 0; i < GEM_PORTS; i++)
		remove_onif_by_index(phy_port[i].itf.index);
}

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
#include "control_ipv4.h"
#include "dpa_control_mc.h"

/**
 * add_onif()
 *
 *
 */
POnifDesc add_onif(U8 *input_itf_name, struct _itf *itf, struct _itf *phys_itf, U8 type)
{
	U32 i;

	/* find free entry (valid = 0) in the table */
	for (i = 0; i < L2_MAX_ONIF; i++)
	{
		if ((gOnif_DB[i].flags & ENTRY_VALID) == 0)
		{
			gOnif_DB[i].itf = itf;
			strncpy((char*)gOnif_DB[i].name, (char*)input_itf_name, IF_NAME_SIZE);
			gOnif_DB[i].name[IF_NAME_SIZE - 1] = '\0';

			itf->phys = phys_itf;
			itf->index = i;
			itf->type = type;
			if (type & IF_TYPE_ETHERNET) {
				if (dpa_add_eth_if(input_itf_name, itf, 
							phys_itf) != 0) {
					printk("%s::dpa_add_eth_if failed\n", 
							__func__);
					return NULL;
				}
			} 
			gOnif_DB[i].flags = ENTRY_VALID;
			return &gOnif_DB[i];
		}
	}
	return NULL;
}


/**
 * remove_onif_by_index()
 *
 *	Releases the output interface occupying if_index. The struct _itf is
 *	embedded in its owner (a physical port or a Wi-Fi VAP) and the caller
 *	frees that owner as soon as we return, so nothing may hold a pointer
 *	to it afterwards: clear the multicast group routes that name it, then
 *	release the database slot and the device manager entry.
 */
void remove_onif_by_index(U32 if_index)
{
	if (if_index >= L2_MAX_ONIF) {
		printk(KERN_ERR "%s::onif index %u out of range\n",
				__func__, if_index);
		return;
	}

	/* Stale or never-configured indexes (e.g. tx_exit's sweep over
	 * unconfigured ports, whose itf.index is still 0) must not tear
	 * down whatever live interface currently owns that index. */
	if (!(gOnif_DB[if_index].flags & ENTRY_VALID))
		return;

	cdx_mcast_clear_itf_refs(if_index);

	memset(&gOnif_DB[if_index], 0, sizeof(OnifDesc));
	dpa_release_interface(if_index);
}

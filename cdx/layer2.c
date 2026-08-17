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
 * get_onif_by_name()
 *
 *
 */
POnifDesc get_onif_by_name(U8 *itf_name)
{
	POnifDesc onif_desc = NULL;
	int i;

	if (itf_name) {
		/* return pointer on entry of the global ouput nif information database */
		for (i = 0; i < L2_MAX_ONIF; i++)
		{
			onif_desc = &gOnif_DB[i];
			if ((onif_desc->flags & ENTRY_VALID) && !strcmp((const char*)itf_name, (char*)onif_desc->name))
				return onif_desc;
		}
	}
	return NULL;
}

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
 *	embedded in its owner (VlanEntry, PPPoE_Info, TnlEntry, wifi or
 *	physical port) and the caller frees that owner as soon as we return,
 *	so nothing may hold a pointer to it afterwards. The order below is
 *	deliberate:
 *	  1. sweep the conntracks bound to the interface -- this runs first
 *	     because its match reads pRtEntry->itf->index, which step 2 may
 *	     clear,
 *	  2. remove the routes using the interface; a route that a socket, an
 *	     SA or a surviving conntrack still references cannot be freed, so
 *	     it is quarantined instead by clearing its itf pointers,
 *	  3. clear the same pointers on the multicast group routes, which are
 *	     allocated outside rt_cache and so are invisible to step 2,
 *	  4. release the database slot and the device manager entry.
 */
void remove_onif_by_index(U32 if_index)
{
	int i;

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

	IP_deleteCt_from_onif_index(if_index);

	// disable route entries bound to this interface
	for (i = 0 ; i < NUM_ROUTE_ENTRIES ; i++)
	{
		PRouteEntry pRtentry;
		struct slist_entry *entry;

		// remove the routes that still use the interface, quarantine the ones that are still referenced
		slist_for_each_safe(pRtentry, entry, &rt_cache[i], list)
		{
			/* Routes that ingress via the removed interface keep
			 * working on the egress side, but their input pointers
			 * would dangle into the owner struct our caller is
			 * about to free - clear them. */
			if (pRtentry->input_itf &&
					pRtentry->input_itf->index == if_index)
				pRtentry->input_itf = NULL;
			if (pRtentry->underlying_input_itf &&
					pRtentry->underlying_input_itf->index == if_index)
				pRtentry->underlying_input_itf = NULL;

			if (pRtentry->itf && pRtentry->itf->index == if_index) {
				/* A route pinned by a socket, an SA or a
				 * conntrack (nbref > 0) survives the remove
				 * with ERR_RT_ENTRY_LINKED. Clear its itf so
				 * nothing can follow the pointer into the freed
				 * owner struct; this is what makes the
				 * itf == NULL gate in L2_route_get() live. The
				 * holder keeps its (now interface-less)
				 * reference and gives it back through its own
				 * teardown command. */
				if (L2_route_remove(pRtentry->id) != NO_ERR)
					pRtentry->itf = NULL;
			}
		}
	}

	/* Multicast group routes live outside rt_cache, so the walk above
	 * cannot see them; quarantine them separately. */
	cdx_mcast_clear_itf_refs(if_index);

	memset(&gOnif_DB[if_index], 0, sizeof(OnifDesc));
	dpa_release_interface(if_index);
}



PRouteEntry L2_route_find(U32 id)
{
	U32 hash;
	PRouteEntry pRtEntry;
	struct slist_entry *entry;

	hash = HASH_RT(id);
	slist_for_each(pRtEntry, entry, &rt_cache[hash], list)
	{
		if (pRtEntry->id == id)
			return pRtEntry;
	}

	return NULL;
}

U16 itf_get_phys_port(struct _itf *itf)
{
	while (itf->phys)
		itf = itf->phys;

	return ((struct physical_port *)itf)->id;
}

struct _itf *itf_get_phys_itf(struct _itf *itf)
{
	while (itf->phys)
		itf = itf->phys;

	return itf;
}

/**
 * __L2_route_remove()
 *
 *          This function removes an L2 route entry
 *
 */
static int __L2_route_remove(PRouteEntry pRtEntry)
{
	U32 hash;

	hash = HASH_RT(pRtEntry->id);

	slist_remove(&rt_cache[hash], &pRtEntry->list);

	Heap_Free((PVOID)pRtEntry);

	return NO_ERR;
}

/**
 * L2_route_remove()
 *
 *          This function removes an L2 route entry
 *
 */
int L2_route_remove(U32 id)
{
	PRouteEntry pRtEntry;

	pRtEntry = L2_route_find(id);
	if (pRtEntry == NULL)
		return ERR_RT_ENTRY_NOT_FOUND;

	if (pRtEntry->nbref)
		return ERR_RT_ENTRY_LINKED;

	return __L2_route_remove(pRtEntry);
}


/**
 * L2_route_get()
 *
 *
 */
PRouteEntry L2_route_get(U32 id)
{
	PRouteEntry pRtEntry;

	pRtEntry = L2_route_find(id);
	if (pRtEntry == NULL)
	{
		return NULL;
	}

	if (pRtEntry->nbref == 0xFFFF)
	{
		return NULL;
	}

	/* Quarantined by remove_onif_by_index(): the route outlived its output
	 * interface because a holder was still referencing it. Refuse to hand
	 * out any new reference to it. */
	if (pRtEntry->itf == NULL)
	{
		return NULL;
	}

	pRtEntry->nbref++;

	return pRtEntry;
}

/**
 * L2_route_put()
 *
 *
 */
void L2_route_put(PRouteEntry pRtEntry)
{
	if (pRtEntry == NULL)
		return;

	/* nbref is a U16: an unbalanced put wraps 0 to 0xFFFF, which both
	 * pins the entry against removal forever and makes every later
	 * L2_route_get() fail its saturation check. Refuse instead. */
	if (WARN_ON_ONCE(pRtEntry->nbref == 0))
		return;

	pRtEntry->nbref--;
}

/**
 * L2_route_add()
 *
 *          This function removes an L2 route entry
 *
 */
PRouteEntry L2_route_add(U32 id)
{
	PRouteEntry pRtEntry;
	int size;
	U32 hash;

	size = ROUND_UP32(sizeof (RouteEntry));

	pRtEntry = (PRouteEntry)__Heap_Alloc(hGlobalHeap, size);
	if (!pRtEntry)
		return NULL;

	memset(pRtEntry, 0, size);

	hash = HASH_RT(id);

	pRtEntry->id = id;

	pRtEntry->nbref = 0;

	slist_add(&rt_cache[hash], &pRtEntry->list);

	return pRtEntry;
}


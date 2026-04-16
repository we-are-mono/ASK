/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include <linux/mutex.h>
#include "portdefs.h"
#include "cdx.h"
#include "cdx_cmd_validator.h"
#include "control_vlan.h"
#include "misc.h"
#include "control_stat.h"


extern spinlock_t dpa_devlist_lock;
U8 gStatVlanQueryStatus;

/*
 * Concurrency:
 *   vlan_query_mutex (file-local)
 *      - Serializes the static pagination cursors in both
 *        Vlan_Get_Next_Hash_Entry (pVlanSnapshot, vlan_*) and
 *        stat_VLAN_Get_Next_SessionEntry (pStatVLANSnapshot,
 *        stat_vlan_*).
 *   dpa_devlist_lock (owned by devman.c)
 *      - Briefly acquired in the stat path while resolving iface
 *        info; never held across vlan_cache walks.
 *
 * The vlan_cache slist itself is lock-free on both the mutator
 * (Vlan_handle_entry) and walker sides. Attackers reaching those
 * paths need CAP_NET_ADMIN via the cdx ioctl gate (G1), so the
 * race is privilege-bounded.
 *
 * Contexts: all public entry points run in process context from
 * the ioctl dispatcher (CAP_NET_ADMIN gated).
 */
static DEFINE_MUTEX(vlan_query_mutex);

static PVlanEntry vlan_alloc(void)
{
	return kzalloc(sizeof(VlanEntry), GFP_KERNEL);
}

static void vlan_free(PVlanEntry pEntry)
{
	kfree(pEntry);
}

static void vlan_add(PVlanEntry pEntry)
{
	U32 hash;

	hash = HASH_VLAN(pEntry->vlanID);

	/* Add to our local hash */
	slist_add(&vlan_cache[hash], &pEntry->list);
}

static void vlan_remove(PVlanEntry pEntry)
{
	struct slist_entry *prev;
	U32 hash;

	/*Tell the Interface Manager to remove the Vlan IF*/
	remove_onif_by_index(pEntry->itf.index);

	hash = HASH_VLAN(pEntry->vlanID);

#ifdef CDX_TODO_VLAN
	/* remove the hardware entry */
#endif

	/* Remove from our local table */
	prev = slist_prev(&vlan_cache[hash], &pEntry->list);
	slist_remove_after(prev);
}


static U16 Vlan_handle_reset(void)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	int i;

	/* free VLAN entries */
	for(i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_for_each_safe(pEntry, entry, &vlan_cache[i], list)
		{
			vlan_remove(pEntry);
			vlan_free(pEntry);
		}
	}

	return NO_ERR;
}


/*
 * Semantic validator for CMD_VLAN_ENTRY. Length has already been
 * checked against sizeof(VlanCommand) by the dispatcher, so the
 * struct cast is safe. Mirrors the original default arm of
 * Vlan_handle_entry's action switch - any other action value was
 * rejected with ERR_UNKNOWN_ACTION.
 */
static U16 vlan_entry_validate(const void *pcmd, U16 cmd_len)
{
	const VlanCommand *cmd = pcmd;

	(void)cmd_len;

	switch (cmd->action) {
	case ACTION_REGISTER:
	case ACTION_DEREGISTER:
	case ACTION_QUERY:
	case ACTION_QUERY_CONT:
		return NO_ERR;
	default:
		return ERR_UNKNOWN_ACTION;
	}
}

/*
 * Handler for CMD_VLAN_ENTRY.
 *
 * pcmd is in/out: the dispatcher stamps pcmd[0] with the return
 * value AFTER we return, and the QUERY paths rewrite pcmd with
 * the next snapshot entry. The first thing we do is memcpy the
 * incoming command into vlancmd; after that point pcmd may be
 * mutated freely.
 */
static U16 vlan_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	VlanCommand vlancmd;
	PVlanEntry pEntry;
	struct slist_entry *entry;
	POnifDesc phys_onif;
	U32 hash;
	struct net_device *device = NULL, *parent_device = NULL;
	U16 rc = NO_ERR;

	(void)cmd_len;

	memcpy(&vlancmd, pcmd, sizeof(vlancmd));
	hash = HASH_VLAN(htons(vlancmd.vlanID));

	switch (vlancmd.action) {
	case ACTION_DEREGISTER:
		device = dev_get_by_name(&init_net, vlancmd.vlanifname);

		slist_for_each(pEntry, entry, &vlan_cache[hash], list) {
			if ((pEntry->vlanID == htons(vlancmd.vlanID & 0xfff)) &&
			    (strcmp(get_onif_name(pEntry->itf.index), (char *)vlancmd.vlanifname) == 0))
				goto found;
		}

		rc = ERR_VLAN_ENTRY_NOT_FOUND;
		break;

found:
		if (device)
			device->wifi_offload_dev = NULL;
		vlan_remove(pEntry);
		vlan_free(pEntry);
		break;

	case ACTION_REGISTER:
		device = dev_get_by_name(&init_net, vlancmd.vlanifname);
		parent_device = dev_get_by_name(&init_net, vlancmd.phyifname);

		if ((!device) || (!parent_device)) {
			DPA_INFO("%s::could not find device %s or %s\n", __func__, vlancmd.vlanifname, vlancmd.phyifname);
			rc = FAILURE;
			break;
		}

		if (get_onif_by_name(vlancmd.vlanifname)) {
			rc = ERR_VLAN_ENTRY_ALREADY_REGISTERED;
			break;
		}

		slist_for_each(pEntry, entry, &vlan_cache[hash], list) {
			if ((pEntry->vlanID == htons(vlancmd.vlanID & 0xfff)) &&
			    (strcmp(get_onif_name(pEntry->itf.index), (char *)vlancmd.vlanifname) == 0)) {
				rc = ERR_VLAN_ENTRY_ALREADY_REGISTERED;
				goto end;
			}
		}

		if ((pEntry = vlan_alloc()) == NULL) {
			rc = ERR_NOT_ENOUGH_MEMORY;
			break;
		}

		pEntry->vlanID = htons(vlancmd.vlanID & 0xfff);

		/* Check if the Physical interface is known by the Interface manager */
		phys_onif = get_onif_by_name(vlancmd.phyifname);
		if (!phys_onif) {
			vlan_free(pEntry);
			rc = ERR_UNKNOWN_INTERFACE;
			break;
		}

		/* Now create a new interface in the Interface Manager and remember the index */
		if (!add_onif(vlancmd.vlanifname, &pEntry->itf, phys_onif->itf, IF_TYPE_VLAN)) {
			vlan_free(pEntry);
			rc = ERR_CREATION_FAILED;
			break;
		}
		if (dpa_add_vlan_if(vlancmd.vlanifname, &pEntry->itf, phys_onif->itf, pEntry->vlanID, vlancmd.macaddr)) {
			remove_onif_by_index(pEntry->itf.index);
			vlan_free(pEntry);
			rc = ERR_CREATION_FAILED;
			break;
		}

		if (parent_device->wifi_offload_dev)
			device->wifi_offload_dev = parent_device->wifi_offload_dev;

		vlan_add(pEntry);
		break;

	case ACTION_QUERY:
	case ACTION_QUERY_CONT: {
		PVlanCommand pVlan = (PVlanCommand)pcmd;
		int query_rc;

		query_rc = Vlan_Get_Next_Hash_Entry(pVlan, vlancmd.action == ACTION_QUERY);
		if (query_rc == NO_ERR)
			*out_reply_len = sizeof(U16) + sizeof(VlanCommand);
		return (U16)query_rc;
	}
	}

end:
	if (device)
		dev_put(device);
	if (parent_device)
		dev_put(parent_device);

	return rc;
}

/*
 * Handler for CMD_VLAN_ENTRY_RESET. No argument, status-only reply.
 */
static U16 vlan_reset_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)pcmd;
	(void)cmd_len;
	(void)out_reply_len;

	return Vlan_handle_reset();
}

/*
 * CMD_VLAN_ENTRY_RESET uses CDX_CMD_VAR(0, U16_MAX) rather than
 * CDX_CMD_NOARG to preserve the pre-migration permissive length
 * contract: the old M_vlan_cmdproc did not length-check RESET at
 * all. Canonical callers (CMM) send zero, but tightening here
 * would be a behavior change smuggled into a mechanical
 * refactor. Hardening this to strict 0-length is a separate
 * follow-up.
 */
static const struct cdx_cmd_spec vlan_cmd_table[] = {
	CDX_CMD_V  (CMD_VLAN_ENTRY,       VlanCommand, vlan_entry_validate, vlan_entry_handle),
	CDX_CMD_VAR(CMD_VLAN_ENTRY_RESET, 0, U16_MAX,  NULL,                vlan_reset_handle),
};

static U16 M_vlan_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(vlan_cmd_table, ARRAY_SIZE(vlan_cmd_table),
				cmd_code, cmd_len, pcmd);
}


int vlan_init(void)
{
	int i;

	set_cmd_handler(EVENT_VLAN, M_vlan_cmdproc);

	for(i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_head_init(&vlan_cache[i]);
	}

	return 0;
}


void vlan_exit(void)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	int i;

	for (i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_for_each_safe(pEntry, entry, &vlan_cache[i], list)
		{
			vlan_remove(pEntry);
			vlan_free(pEntry);
		}
	}

}


/* This function returns total vlan interfaces configured in FPP */
static int Vlan_Get_Hash_Entries(int vlan_hash_index)
{
	int tot_vlans=0;
	struct slist_entry *entry;

	slist_for_each_entry(entry, &vlan_cache[vlan_hash_index])
		tot_vlans++;

	return tot_vlans;
}


/* This function fills in the snapshot of all Vlan entries of a VLAN cache */

static int Vlan_Get_Hash_Snapshot(int vlan_hash_index, int vlan_entries, PVlanCommand pVlanSnapshot)
{
	int tot_vlans=0;
	PVlanEntry pVlanEntry;
	struct slist_entry *entry;

	slist_for_each(pVlanEntry, entry, &vlan_cache[vlan_hash_index], list)
	{
		pVlanSnapshot->vlanID = ntohs(pVlanEntry->vlanID);
		strscpy((char *)pVlanSnapshot->vlanifname,
				get_onif_name(pVlanEntry->itf.index),
				sizeof(pVlanSnapshot->vlanifname));
		strscpy((char *)pVlanSnapshot->phyifname,
				get_onif_name(pVlanEntry->itf.phys->index),
				sizeof(pVlanSnapshot->phyifname));

		pVlanSnapshot++;
		tot_vlans++;

		if (--vlan_entries <= 0)
			break;
	}

	return tot_vlans;

}



int Vlan_Get_Next_Hash_Entry(PVlanCommand pVlanCmd, int reset_action)
{
	int total_vlan_entries;
	PVlanCommand pVlan;
	int retval;
	static PVlanCommand pVlanSnapshot = NULL;
	static int vlan_hash_index = 0, vlan_snapshot_entries =0, vlan_snapshot_index=0, vlan_snapshot_buf_entries = 0;

	mutex_lock(&vlan_query_mutex);

	if(reset_action)
	{
		vlan_hash_index = 0;
		vlan_snapshot_entries =0;
		vlan_snapshot_index=0;
		if(pVlanSnapshot)
		{
			Heap_Free(pVlanSnapshot);
			pVlanSnapshot = NULL;
		}
		vlan_snapshot_buf_entries = 0;
	}

	if (vlan_snapshot_index == 0)
	{
		while( vlan_hash_index < NUM_VLAN_ENTRIES)
		{
			total_vlan_entries = Vlan_Get_Hash_Entries(vlan_hash_index);
			if (total_vlan_entries == 0)
			{
				vlan_hash_index++;
				continue;
			}

			if(total_vlan_entries > vlan_snapshot_buf_entries)
			{
				if(pVlanSnapshot)
					Heap_Free(pVlanSnapshot);

				pVlanSnapshot = Heap_Alloc(total_vlan_entries * sizeof(VlanCommand));

				if (!pVlanSnapshot)
				{
					vlan_hash_index = 0;
					vlan_snapshot_buf_entries = 0;
					retval = ERR_NOT_ENOUGH_MEMORY;
					goto out;
				}
				vlan_snapshot_buf_entries = total_vlan_entries;
			}


			vlan_snapshot_entries = Vlan_Get_Hash_Snapshot(vlan_hash_index,total_vlan_entries,pVlanSnapshot);
			break;

		}
		if (vlan_hash_index >= NUM_VLAN_ENTRIES)
		{
			vlan_hash_index = 0;
			if(pVlanSnapshot)
			{
				Heap_Free(pVlanSnapshot);
				pVlanSnapshot = NULL;
			}
			vlan_snapshot_buf_entries = 0;
			retval = ERR_VLAN_ENTRY_NOT_FOUND;
			goto out;
		}
	}

	pVlan = &pVlanSnapshot[vlan_snapshot_index++];

	memcpy(pVlanCmd, pVlan, sizeof(VlanCommand));
	if (vlan_snapshot_index == vlan_snapshot_entries)
	{
		vlan_snapshot_index = 0;
		vlan_hash_index++;
	}

	retval = NO_ERR;
out:
	mutex_unlock(&vlan_query_mutex);
	return retval;
}

static U16 vlan_stats_get(PVlanEntry pEntry, PStatVlanEntryResponse snapshot, U32 do_reset)
{
	struct iface_stats ifstats;
	struct dpa_iface_info *iface_info = NULL;
	struct iface_stats *last_stats;
	U16 ret = 0;

	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid((uint32_t)pEntry->itf.index)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __func__, pEntry->itf.index);
		return ERR_UNKNOWN_INTERFACE;
	}
	spin_unlock(&dpa_devlist_lock);
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __func__, ret);
		return ret;
	}

	last_stats = iface_info->last_stats;
	snapshot->total_packets_received = ifstats.rx_packets - last_stats->rx_packets;
	snapshot->total_bytes_received[0] = statistics_get_lsb(ifstats.rx_bytes - last_stats->rx_bytes);
	snapshot->total_bytes_received[1] = statistics_get_msb(ifstats.rx_bytes - last_stats->rx_bytes);

	snapshot->total_packets_transmitted = ifstats.tx_packets - last_stats->tx_packets;
	snapshot->total_bytes_transmitted[0] = statistics_get_lsb(ifstats.tx_bytes - last_stats->tx_bytes);
	snapshot->total_bytes_transmitted[1] = statistics_get_msb(ifstats.tx_bytes - last_stats->tx_bytes);

	if (do_reset)
		dpa_iface_stats_reset(iface_info, &ifstats);

	return NO_ERR;
}

static U16 stat_VLAN_Get_Session_Snapshot(int stat_vlan_hash_index, int stat_vlan_entries,
		PStatVlanEntryResponse pStatVLANSnapshot, int *stat_tot_vlans)
{
	PVlanEntry pStatVlanEntry;
	struct slist_entry *entry;
	U16 ret = 0;

	*stat_tot_vlans = 0;
	slist_for_each(pStatVlanEntry, entry, &vlan_cache[stat_vlan_hash_index], list)
	{
		pStatVLANSnapshot->eof = 0;
		pStatVLANSnapshot->vlanID = ntohs(pStatVlanEntry->vlanID);
		strscpy((char *)pStatVLANSnapshot->vlanifname,
				get_onif_name(pStatVlanEntry->itf.index),
				sizeof(pStatVLANSnapshot->vlanifname));
		strscpy((char *)pStatVLANSnapshot->phyifname,
				get_onif_name(pStatVlanEntry->itf.phys->index),
				sizeof(pStatVLANSnapshot->phyifname));

		if ((ret = vlan_stats_get(pStatVlanEntry, pStatVLANSnapshot,
						gStatVlanQueryStatus & STAT_VLAN_QUERY_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __func__, ret);
			return ret;
		}

		pStatVLANSnapshot++;
		(*stat_tot_vlans)++;

		if (--stat_vlan_entries <= 0)
			break;
	}	

	return NO_ERR;

}

U16 stat_VLAN_Get_Next_SessionEntry(PStatVlanEntryResponse pStatVlanCmd, int reset_action)
{
	int stat_total_vlan_entries;
	PStatVlanEntryResponse pStatVlan;
	static PStatVlanEntryResponse pStatVLANSnapshot = NULL;
	static int stat_vlan_hash_index = 0, stat_vlan_snapshot_entries =0, stat_vlan_snapshot_index=0, stat_vlan_snapshot_buf_entries = 0;
	U16 ret = 0;

	mutex_lock(&vlan_query_mutex);

	if(reset_action)
	{
		stat_vlan_hash_index = 0;
		stat_vlan_snapshot_entries =0;
		stat_vlan_snapshot_index=0;
		if(pStatVLANSnapshot)
		{
			Heap_Free(pStatVLANSnapshot);
			pStatVLANSnapshot = NULL;
		}
		stat_vlan_snapshot_buf_entries = 0;
		ret = NO_ERR;
		goto out;
	}

	if (stat_vlan_snapshot_index == 0)
	{
		while(stat_vlan_hash_index < NUM_VLAN_ENTRIES)
		{
			stat_total_vlan_entries = Vlan_Get_Hash_Entries(stat_vlan_hash_index);
			if (stat_total_vlan_entries == 0)
			{
				stat_vlan_hash_index++;
				continue;
			}

			if(stat_total_vlan_entries > stat_vlan_snapshot_buf_entries)
			{
				if(pStatVLANSnapshot)
					Heap_Free(pStatVLANSnapshot);

				pStatVLANSnapshot = Heap_Alloc(stat_total_vlan_entries * sizeof(StatVlanEntryResponse));

				if (!pStatVLANSnapshot)
				{
					stat_vlan_hash_index = 0;
					stat_vlan_snapshot_buf_entries = 0;
					ret = ERR_NOT_ENOUGH_MEMORY;
					goto out;
				}
				stat_vlan_snapshot_buf_entries = stat_total_vlan_entries;
			}


			if ((ret = stat_VLAN_Get_Session_Snapshot(stat_vlan_hash_index, stat_total_vlan_entries,
							pStatVLANSnapshot, &stat_vlan_snapshot_entries)) != NO_ERR)
			{
				goto out;
			}
			break;
		}

		if (stat_vlan_hash_index >= NUM_VLAN_ENTRIES)
		{
			stat_vlan_hash_index = 0;
			if(pStatVLANSnapshot)
			{
				Heap_Free(pStatVLANSnapshot);
				pStatVLANSnapshot = NULL;
			}
			stat_vlan_snapshot_buf_entries = 0;
			ret = ERR_VLAN_ENTRY_NOT_FOUND;
			goto out;
		}
	}

	pStatVlan = &pStatVLANSnapshot[stat_vlan_snapshot_index++];

	memcpy(pStatVlanCmd, pStatVlan, sizeof(StatVlanEntryResponse));
	if (stat_vlan_snapshot_index == stat_vlan_snapshot_entries)
	{
		stat_vlan_snapshot_index = 0;
		stat_vlan_hash_index++;
	}

	ret = NO_ERR;
out:
	mutex_unlock(&vlan_query_mutex);
	return ret;
}

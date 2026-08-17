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
#include "control_pppoe.h"
#include "misc.h"
#include "control_stat.h"

extern spinlock_t dpa_devlist_lock;

U8 gStatPPPoEQueryStatus;

/*
 * Concurrency:
 *   pppoe_query_mutex (file-local)
 *      - Serializes the static pagination cursors in both
 *        PPPoE_Get_Next_SessionEntry (pPPPoESnapshot, pppoe_*) and
 *        stat_PPPoE_Get_Next_SessionEntry (pStatPPPoESnapshot,
 *        stat_pppoe_*).
 *   dpa_devlist_lock (owned by devman.c)
 *      - Held in pppoe_stats_get() across the iface_info lookup AND
 *        the stats read/reset (the iface can be kfreed once the
 *        lock drops).
 *
 * The PPPoE session cache is lock-free on the mutator side. Same
 * gap as the other control_*.c files — fixing requires a subsystem
 * lock, out of scope here.
 *
 * Contexts: all public entry points run in process context from
 * the ioctl dispatcher.
 */
static DEFINE_MUTEX(pppoe_query_mutex);

int PPPoE_Get_Next_SessionEntry(pPPPoECommand pSessionCmd, int reset_action);

static pPPPoE_Info pppoe_alloc(void)
{
	return kzalloc(sizeof(PPPoE_Info), GFP_KERNEL);
}


static void pppoe_free(pPPPoE_Info pEntry)
{
	kfree(pEntry);
}


static void pppoe_add(pPPPoE_Info pEntry, U16 hash_key)
{
	/* Add to our local hash */
	slist_add(&pppoe_cache[hash_key], &pEntry->list);
}

static void pppoe_remove(pPPPoE_Info pEntry, U16 hash_key)
{
	struct slist_entry *prev;

	prev = slist_prev(&pppoe_cache[hash_key], &pEntry->list);

	/* Remove from our local hash */
	slist_remove_after(prev);

	pppoe_free(pEntry);
}

static int PPPoE_Handle_Entry(U16 *p, U16 Length)
{
	pPPPoECommand cmd;
	pPPPoE_Info pEntry;
	POnifDesc phys_onif;
	U32 hash_key;
	struct slist_entry *entry;

	cmd = (pPPPoECommand) p;
	if (Length != sizeof(PPPoECommand))
		return ERR_WRONG_COMMAND_SIZE;

	cmd->sessionID = htons(cmd->sessionID);

	hash_key = HASH_PPPOE(cmd->sessionID, cmd->macAddr);

	switch (cmd->action)
	{
		case ACTION_DEREGISTER:
			slist_for_each(pEntry, entry, &pppoe_cache[hash_key], list)
			{
				if ((pEntry->sessionID == cmd->sessionID) && TESTEQ_MACADDR(pEntry->DstMAC, cmd->macAddr) &&
						!strcmp(get_onif_name(pEntry->itf.index), (char *)cmd->log_intf) )
					goto found;
			}

			return ERR_PPPOE_ENTRY_NOT_FOUND;

found:
			/*Tell the Interface Manager to remove the pppoe IF*/
			remove_onif_by_index(pEntry->itf.index);

			pppoe_remove(pEntry, hash_key);

			gStatPPPoEQueryStatus = STAT_PPPOE_QUERY_NOT_READY;
			break;

		case ACTION_REGISTER:

			if (get_onif_by_name(cmd->log_intf))
				return ERR_PPPOE_ENTRY_ALREADY_REGISTERED;

			/*Check if the Physical interface is known by the Interface manager*/
			phys_onif = get_onif_by_name(cmd->phy_intf);
			if (!phys_onif)
				return ERR_UNKNOWN_INTERFACE;

			slist_for_each(pEntry, entry, &pppoe_cache[hash_key], list)
			{
				if ((pEntry->sessionID == cmd->sessionID) && TESTEQ_MACADDR(pEntry->DstMAC, cmd->macAddr))
					return ERR_PPPOE_ENTRY_ALREADY_REGISTERED; //trying to add exactly the same vlan entry
			}

			if ((pEntry = pppoe_alloc()) == NULL)
			{
				return ERR_NOT_ENOUGH_MEMORY;
			}

			/* populate pppoe_info entry */
			pEntry->sessionID = cmd->sessionID;
			COPY_MACADDR(pEntry->DstMAC,cmd->macAddr);

			if (cmd->mode & PPPOE_AUTO_MODE)
				pEntry->ppp_flags |= PPPOE_AUTO_MODE;

			/*Now create a new interface in the Interface Manager and remember the index*/
			if (!add_onif(cmd->log_intf, &pEntry->itf, phys_onif->itf, IF_TYPE_PPPOE))
			{
				pppoe_free(pEntry);
				return ERR_CREATION_FAILED;
			}
			//printk("%s::adding dpa pppoe iface\n", __func__);

			if (dpa_add_pppoe_if(cmd->log_intf,  &pEntry->itf, 
						phys_onif->itf, pEntry->DstMAC,
						pEntry->sessionID)) {
				remove_onif_by_index(pEntry->itf.index);
				pppoe_free(pEntry);
				return ERR_CREATION_FAILED;
			}

			pppoe_add(pEntry, hash_key);
			gStatPPPoEQueryStatus = STAT_PPPOE_QUERY_NOT_READY;
			break;

		case ACTION_QUERY:
		case ACTION_QUERY_CONT:
			{
				int rc;

				rc = PPPoE_Get_Next_SessionEntry(cmd, cmd->action == ACTION_QUERY);
				return rc;

			}

		default:
			return ERR_UNKNOWN_ACTION;
	}

	/* return success */
	return NO_ERR;
}


/*
 * CMD_PPPOE_ENTRY: snapshot action at entry because the QUERY
 * paths call PPPoE_Get_Next_SessionEntry which overwrites pcmd.
 *
 * Reply-length quirk: the pre-migration wrapper set
 * ret_len = sizeof(PPPoECommand) for query-success (NOT
 * sizeof(U16) + sizeof(PPPoECommand) as VLAN/IPv4 use).
 * The wire format is status word (2 bytes) replacing the
 * action field at offset 0, followed by the rest of
 * PPPoECommand. So the total reply is exactly sizeof(PPPoECommand)
 * bytes, and libfci parses it as a PPPoECommand struct where
 * the first U16 holds the status. Preserve that.
 */
static U16 pppoe_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U16 action = *(U16 *)pcmd;
	U16 rc = (U16)PPPoE_Handle_Entry(pcmd, cmd_len);

	if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
		*out_reply_len = sizeof(PPPoECommand);
	return rc;
}

static const struct cdx_cmd_spec pppoe_cmd_table[] = {
	CDX_CMD(CMD_PPPOE_ENTRY, PPPoECommand, pppoe_entry_handle),
};

static U16 M_pppoe_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(pppoe_cmd_table, ARRAY_SIZE(pppoe_cmd_table),
				cmd_code, cmd_len, pcmd);
}


int pppoe_init(void)
{
	int i;

	set_cmd_handler(EVENT_PPPOE, M_pppoe_cmdproc);

	for (i = 0; i < NUM_PPPOE_ENTRIES; i++)
	{
		slist_head_init(&pppoe_cache[i]);
	}

	return 0;
}

void pppoe_exit(void)
{
	int i;
	pPPPoE_Info pPPPoEEntry;
	struct slist_entry *entry;
	for (i = 0; i < NUM_PPPOE_ENTRIES; i++)
	{
		slist_for_each_safe(pPPPoEEntry, entry, &pppoe_cache[i], list)
		{
			pppoe_remove(pPPPoEEntry, i);
		}
	}
}


/* This function returns total PPPoE configured in FPP */

static int PPPoE_Get_Hash_Sessions(int pppoe_hash_index)
{
	int tot_sessions=0;
	struct slist_entry *entry;

	slist_for_each_entry(entry, &pppoe_cache[pppoe_hash_index])
		tot_sessions++;

	return tot_sessions;

}

/* This function fills in the snapshot of all PPPoE Sessions 
	 in a Session Table */

static int PPPoE_Get_Session_Snapshot(int pppoe_hash_index , int pppoe_tot_entries, pPPPoECommand pPPPoESnapshot)
{
	int tot_sessions=0;
	pPPPoE_Info pPPPoEEntry;
	struct slist_entry *entry;

	slist_for_each(pPPPoEEntry, entry, &pppoe_cache[pppoe_hash_index], list)
	{
		pPPPoESnapshot->sessionID   = ntohs(pPPPoEEntry->sessionID);
		COPY_MACADDR(pPPPoESnapshot->macAddr, pPPPoEEntry->DstMAC);

		strscpy((char *)pPPPoESnapshot->phy_intf,
				get_onif_name(pPPPoEEntry->itf.phys->index),
				sizeof(pPPPoESnapshot->phy_intf));
		strscpy((char *)pPPPoESnapshot->log_intf,
				get_onif_name(pPPPoEEntry->itf.index),
				sizeof(pPPPoESnapshot->log_intf));

		pPPPoESnapshot++;
		tot_sessions++;

		if (--pppoe_tot_entries <= 0)
			break;
	}

	return tot_sessions;
}

/* This function creates the snapshot memory and returns the 
	 next PPPoE session entry from the PPPoE Session snapshot 
	 to the caller  */
int PPPoE_Get_Next_SessionEntry(pPPPoECommand pSessionCmd, int reset_action)
{
	int pppoe_hash_entries;
	pPPPoECommand pSession;
	int retval;
	static pPPPoECommand pPPPoESnapshot = NULL;
	static int pppoe_session_hash_index =0, pppoe_snapshot_entries = 0, pppoe_snapshot_index = 0, pppoe_snapshot_buf_entries = 0;

	mutex_lock(&pppoe_query_mutex);

	if(reset_action)
	{
		pppoe_session_hash_index =0;
		pppoe_snapshot_entries = 0;
		pppoe_snapshot_index = 0;
		if(pPPPoESnapshot)
		{
			Heap_Free(pPPPoESnapshot);
			pPPPoESnapshot = NULL;
		}
		pppoe_snapshot_buf_entries = 0;
	}

	if (pppoe_snapshot_index == 0)
	{

		while( pppoe_session_hash_index <  NUM_PPPOE_ENTRIES)
		{
			pppoe_hash_entries = PPPoE_Get_Hash_Sessions(pppoe_session_hash_index);
			if (pppoe_hash_entries == 0)
			{
				pppoe_session_hash_index++;
				continue;
			}

			if(pppoe_hash_entries > pppoe_snapshot_buf_entries)
			{
				if(pPPPoESnapshot)
					Heap_Free(pPPPoESnapshot);

				pPPPoESnapshot = Heap_Alloc(pppoe_hash_entries * sizeof(PPPoECommand));
				if (!pPPPoESnapshot)
				{
					pppoe_session_hash_index =0;
					pppoe_snapshot_buf_entries = 0;
					retval = ERR_NOT_ENOUGH_MEMORY;
					goto out;
				}
				pppoe_snapshot_buf_entries = pppoe_hash_entries;
			}

			pppoe_snapshot_entries = PPPoE_Get_Session_Snapshot(pppoe_session_hash_index,pppoe_hash_entries,pPPPoESnapshot);
			break;
		}
		if (pppoe_session_hash_index >= NUM_PPPOE_ENTRIES)
		{
			pppoe_session_hash_index = 0;
			if(pPPPoESnapshot)
			{
				Heap_Free(pPPPoESnapshot);
				pPPPoESnapshot = NULL;
			}
			pppoe_snapshot_buf_entries = 0;
			retval = ERR_PPPOE_ENTRY_NOT_FOUND;
			goto out;
		}

	}

	pSession = &pPPPoESnapshot[pppoe_snapshot_index++];

	memcpy(pSessionCmd, pSession, sizeof(PPPoECommand));
	if (pppoe_snapshot_index == pppoe_snapshot_entries)
	{
		pppoe_snapshot_index = 0;
		pppoe_session_hash_index++;

	}

	retval = NO_ERR;
out:
	mutex_unlock(&pppoe_query_mutex);
	return retval;
}

static U16 pppoe_stats_get(pPPPoE_Info pEntry, PStatPPPoEEntryResponse snapshot, U8 do_reset)
{
	struct dpa_iface_info *iface_info = NULL;
	struct iface_stats ifstats;
	struct iface_stats *last_stats;
	U16 ret = 0;

	/* hold the lock across the use, not just the lookup — the iface
	 * (and its stats) can be kfreed by dpa_release_interface the
	 * moment the lock drops. Non-sleeping work only under the lock. */
	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid((uint32_t)pEntry->itf.index)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __func__, pEntry->itf.index);
		return ERR_UNKNOWN_INTERFACE;
	}
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __func__, ret);
		return ret;
	}

	last_stats = iface_info->last_stats;
	snapshot->total_packets_received = ifstats.rx_packets - last_stats->rx_packets;
	snapshot->total_packets_transmitted = ifstats.tx_packets - last_stats->tx_packets;

	if (do_reset)
		dpa_iface_stats_reset(iface_info, &ifstats);
	spin_unlock(&dpa_devlist_lock);

	return NO_ERR;
}

/* This function fills in the snapshot of all PPPoE Sessions 
	 in a Session Table */

static U16 stat_PPPoE_Get_Session_Snapshot(int stat_pppoe_hash_index, int stat_tot_entries, 
		PStatPPPoEEntryResponse pStatPPPoESnapshot, int *stat_tot_sessions)
{
	pPPPoE_Info pStatPPPoEEntry;
	struct slist_entry *entry;
	U16 ret = 0;

	*stat_tot_sessions = 0;
	slist_for_each(pStatPPPoEEntry, entry, &pppoe_cache[stat_pppoe_hash_index], list)
	{
		pStatPPPoESnapshot->eof = 0;
		pStatPPPoESnapshot->sessionID = htons(pStatPPPoEEntry->sessionID);
		pStatPPPoESnapshot->interface_no = itf_get_phys_port(&pStatPPPoEEntry->itf);

		if ((ret = pppoe_stats_get(pStatPPPoEEntry, pStatPPPoESnapshot,
						gStatPPPoEQueryStatus & STAT_PPPOE_QUERY_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __func__, ret);
			return ret;
		}

		pStatPPPoESnapshot++;
		(*stat_tot_sessions)++;

		if (--stat_tot_entries <= 0)
			break;
	}

	return NO_ERR;
}

/* This function creates the snapshot memory and returns the 
	 next PPPoE session entry from the PPPoE Session snapshot 
	 to the caller  */
U16 stat_PPPoE_Get_Next_SessionEntry(PStatPPPoEEntryResponse pStatSessionCmd, int reset_action)
{
	int stat_pppoe_hash_entries;
	PStatPPPoEEntryResponse pStatSession;
	static PStatPPPoEEntryResponse pStatPPPoESnapshot = NULL;
	static int stat_pppoe_session_hash_index=0, stat_pppoe_snapshot_entries = 0, stat_pppoe_snapshot_index = 0, stat_pppoe_snapshot_buf_entries = 0;
	U16 ret = 0;

	mutex_lock(&pppoe_query_mutex);

	if(reset_action)
	{
		stat_pppoe_session_hash_index = 0;
		stat_pppoe_snapshot_entries = 0;
		stat_pppoe_snapshot_index = 0;
		if(pStatPPPoESnapshot)
		{
			Heap_Free(pStatPPPoESnapshot);
			pStatPPPoESnapshot = NULL;
		}
		stat_pppoe_snapshot_buf_entries = 0;
		ret = NO_ERR;
		goto out;
	}

	if (stat_pppoe_snapshot_index == 0)
	{
		while( stat_pppoe_session_hash_index <  NUM_PPPOE_ENTRIES)
		{
			stat_pppoe_hash_entries = PPPoE_Get_Hash_Sessions(stat_pppoe_session_hash_index);
			if (stat_pppoe_hash_entries == 0)
			{
				stat_pppoe_session_hash_index++;
				continue;
			}

			if(stat_pppoe_hash_entries > stat_pppoe_snapshot_buf_entries)
			{
				if(pStatPPPoESnapshot)
					Heap_Free(pStatPPPoESnapshot);
				pStatPPPoESnapshot = Heap_Alloc(stat_pppoe_hash_entries * sizeof(StatPPPoEEntryResponse));
				if (!pStatPPPoESnapshot)
				{
					stat_pppoe_session_hash_index = 0;
					stat_pppoe_snapshot_buf_entries = 0;
					ret = ERR_NOT_ENOUGH_MEMORY;
					goto out;
				}
				stat_pppoe_snapshot_buf_entries = stat_pppoe_hash_entries;
			}
			if ((ret = stat_PPPoE_Get_Session_Snapshot(stat_pppoe_session_hash_index,
							stat_pppoe_hash_entries, pStatPPPoESnapshot,
							&stat_pppoe_snapshot_entries)) != NO_ERR)
			{
				goto out;
			}
			break;
		}
		if (stat_pppoe_session_hash_index >= NUM_PPPOE_ENTRIES)
		{
			stat_pppoe_session_hash_index = 0;
			if(pStatPPPoESnapshot)
			{
				Heap_Free(pStatPPPoESnapshot);
				pStatPPPoESnapshot = NULL;
			}
			stat_pppoe_snapshot_buf_entries = 0;
			ret = ERR_PPPOE_ENTRY_NOT_FOUND;
			goto out;
		}
	}

	pStatSession = &pStatPPPoESnapshot[stat_pppoe_snapshot_index++];

	memcpy(pStatSessionCmd, pStatSession, sizeof(StatPPPoEEntryResponse));
	if (stat_pppoe_snapshot_index == stat_pppoe_snapshot_entries)
	{
		stat_pppoe_snapshot_index = 0;
		stat_pppoe_session_hash_index++;
	}

	ret = NO_ERR;
out:
	mutex_unlock(&pppoe_query_mutex);
	return ret;
}


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
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_tunnel.h"
#include "misc.h"
#include "control_stat.h"

extern spinlock_t dpa_devlist_lock;

/*
 * Concurrency:
 *   tnl_query_mutex (file-local)
 *      - Serializes the static pagination cursors in both
 *        Tnl_Get_Next_Hash_Entry (pTnlSnapshot, tnl_*) and
 *        stat_tunnel_Get_Next_SessionEntry (pStatTunnelSnapshot,
 *        stat_tunnel_*, stat_tunnel_name).
 *   dpa_devlist_lock (owned by devman.c)
 *      - Acquired briefly in tunnel_stats_get() while looking up
 *        iface_info by index; not held across tunnel table walks.
 *
 * The tunnel_name_cache slist is currently lock-free on the mutator
 * side too. Same gap as the IPv4/IPv6 cases.
 *
 * Contexts: both public entry points run in process context from
 * the ioctl dispatcher.
 */
static DEFINE_MUTEX(tnl_query_mutex);

U8 gStatTunnelQueryStatus;

/**
 * M_tnl_get_by_name
 *
 *
 *
 */
static PTnlEntry M_tnl_get_by_name(U8 *tnl_name)
{
	PTnlEntry pTunnelEntry;
	struct slist_entry *entry;
	U32 hash;

	if (tnl_name)
	{
		hash = HASH_TUNNEL_NAME(tnl_name);
		slist_for_each(pTunnelEntry, entry, &tunnel_name_cache[hash], list)
		{
			if(!strcmp((const char*)tnl_name, pTunnelEntry->tnl_name))
				return pTunnelEntry;
		}
	}
	return NULL;
}


static PTnlEntry tunnel_alloc(void)
{
	return kzalloc(sizeof(TnlEntry), GFP_KERNEL);
}

static void tunnel_free(PTnlEntry pEntry)
{
	kfree(pEntry);
}


/**
 * M_tnl_add
 *
 *
 */
static int M_tnl_add(PTnlEntry pTunnelEntry)
{
	int rc = 0;
	U32 hash;

	/* Add to our local hash */
	hash = HASH_TUNNEL_NAME(pTunnelEntry->tnl_name);
	slist_add(&tunnel_name_cache[hash], &pTunnelEntry->list);

	dpa_add_tunnel_if(&pTunnelEntry->itf, (pTunnelEntry->pRtEntry) ? pTunnelEntry->pRtEntry->itf : NULL  , pTunnelEntry);
	return rc;
}




/**
 * M_tnl_delete
 *
 *
 *
 */
static BOOL M_tnl_delete(PTnlEntry pTunnelEntry)
{
	struct slist_entry *prev;
	U32 hash;

	/* Free the software entry */
	hash = HASH_TUNNEL_NAME(pTunnelEntry->tnl_name);
	prev = slist_prev(&tunnel_name_cache[hash], &pTunnelEntry->list);
	slist_remove_after(prev);
	tunnel_free(pTunnelEntry);
	return TRUE;
}


/**
 * M_tnl_build_header
 *
 *
 *
 */
static void M_tnl_build_header(PTnlEntry pTunnelEntry)
{
	ipv6_hdr_t ip6_hdr;
	ipv4_hdr_t ip4_hdr;

	switch (pTunnelEntry->mode)
	{
		/* 6o4 case : MAC|IPV4|IPV6 		*/
		/* Here IPV4 part is pre-built	*/

		case TNL_MODE_6O4:
			ip4_hdr.SourceAddress = pTunnelEntry->local[0];
			ip4_hdr.DestinationAddress = pTunnelEntry->remote[0];
			ip4_hdr.Version_IHL = 0x45;
			ip4_hdr.Protocol = IPPROTOCOL_IPV6;
			ip4_hdr.TypeOfService = pTunnelEntry->fl & 0xFF;
			ip4_hdr.TotalLength = 0; //to be computed for each packet
			ip4_hdr.TTL = pTunnelEntry->hlim;
			ip4_hdr.Identification = 0;
			ip4_hdr.HeaderChksum = 0; //to be computed
			ip4_hdr.Flags_FragmentOffset = 0;

			pTunnelEntry->header_size = sizeof(ipv4_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip4_hdr, pTunnelEntry->header_size);
			break;

			/* 4o6 case : MAC|IPV6|IPV4             */
			/* Here IPV6 part is pre-built  */


		case TNL_MODE_4O6:

			memcpy((U8*)ip6_hdr.DestinationAddress, (U8*)pTunnelEntry->remote, IPV6_ADDRESS_LENGTH);
			memcpy((U8*)ip6_hdr.SourceAddress, (U8*)pTunnelEntry->local, IPV6_ADDRESS_LENGTH);
			IPV6_SET_VER_TC_FL(&ip6_hdr, pTunnelEntry->fl);
			ip6_hdr.HopLimit = pTunnelEntry->hlim;
			ip6_hdr.TotalLength = 0; //to be computed for each packet
			ip6_hdr.NextHeader = IPPROTOCOL_IPIP;

			pTunnelEntry->header_size = sizeof(ipv6_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip6_hdr, pTunnelEntry->header_size);

			break;

		case TNL_MODE_GRE_IPV6:

			/* add IPv6 header */
			memset(&ip6_hdr, 0, sizeof(ip6_hdr));
			memcpy((U8*)ip6_hdr.DestinationAddress, (U8*)pTunnelEntry->remote, IPV6_ADDRESS_LENGTH);
			memcpy((U8*)ip6_hdr.SourceAddress, (U8*)pTunnelEntry->local, IPV6_ADDRESS_LENGTH);
			IPV6_SET_VER_TC_FL(&ip6_hdr, pTunnelEntry->fl);
			ip6_hdr.HopLimit = pTunnelEntry->hlim;
			//ip6_hdr.TotalLength = 0; //to be computed for each packet
			ip6_hdr.NextHeader = IPV6_GRE;

			pTunnelEntry->header_size = sizeof(ipv6_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip6_hdr, pTunnelEntry->header_size);

			/* add GRE header */
			*(U32*)(pTunnelEntry->header + pTunnelEntry->header_size) = htonl(TNL_GRE_HEADER);
			pTunnelEntry->header_size += TNL_GRE_HDRSIZE;
			break;

		default:
			break;
	}
}


/**
 * TNL_handle_CREATE
 *
 *
 */
static int TNL_handle_CREATE(U16 *p, U16 Length)
{
	TNLCommand_create cmd;
	PTnlEntry pTunnelEntry;
	int rc = 0;

	/* Check length */
	if (Length != sizeof(TNLCommand_create))
	{
		rc = ERR_WRONG_COMMAND_SIZE;
		goto err0;
	}


	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_create));

	if (get_onif_by_name(cmd.name))
	{
		rc = ERR_TNL_ALREADY_CREATED;
		goto err0;
	}

	/* Get the tunnel entry */
	pTunnelEntry = tunnel_alloc();
	if (!pTunnelEntry)
	{
		rc = ERR_NOT_ENOUGH_MEMORY;
		goto err0;
	}

	strncpy(pTunnelEntry->tnl_name, cmd.name, sizeof(pTunnelEntry->tnl_name) - 1);

	switch (cmd.mode)
	{
		case TNL_MODE_6O4:
			if (cmd.secure)
			{
				rc = ERR_TNL_NOT_SUPPORTED;
				goto err1;
			}

			pTunnelEntry->proto = PROTO_IPV4;
			pTunnelEntry->output_proto = PROTO_IPV6;
			pTunnelEntry->frag_off = cmd.frag_off;

			break;

		case TNL_MODE_4O6:
			if (cmd.secure)
			{
				rc = ERR_TNL_NOT_SUPPORTED;
				goto err1;
			}

			pTunnelEntry->proto = PROTO_IPV6;
			pTunnelEntry->output_proto = PROTO_IPV4;

			break;

		case TNL_MODE_GRE_IPV6:
			pTunnelEntry->proto = PROTO_IPV6;
			pTunnelEntry->output_proto = PROTO_NONE;

			break;

		default:
			rc = ERR_TNL_NOT_SUPPORTED;
			goto err1;
			//		break;
	}

	pTunnelEntry->mode = cmd.mode;

	/* For copy we don't care to copy useless data in IPv4 case */
	memcpy(pTunnelEntry->local, cmd.local, IPV6_ADDRESS_LENGTH);
	memcpy(pTunnelEntry->remote, cmd.remote, IPV6_ADDRESS_LENGTH);
	pTunnelEntry->secure = cmd.secure;
	pTunnelEntry->fl = cmd.fl;
	pTunnelEntry->hlim = cmd.hlim;
	pTunnelEntry->elim = cmd.elim;
	pTunnelEntry->route_id = cmd.route_id;
	pTunnelEntry->pRtEntry = L2_route_get(pTunnelEntry->route_id);
	pTunnelEntry->tnl_mtu  = cmd.mtu;
	pTunnelEntry->flags = cmd.flags;


	/* Now create a new interface in the Interface Manager */
	if (!add_onif(cmd.name, &pTunnelEntry->itf, NULL, IF_TYPE_TUNNEL))
	{
		rc = ERR_CREATION_FAILED;
		goto err1;
	}
	//	pTunnelEntry->output_port_id =  (pTunnelEntry->onif->flags & PHY_PORT_ID) >> PHY_PORT_ID_LOG; /* FIXME */

	M_tnl_build_header(pTunnelEntry);

	pTunnelEntry->state = TNL_STATE_CREATED;

	if(((pTunnelEntry->proto == PROTO_IPV4) && (!pTunnelEntry->remote[0])) ||
			is_ipv6_addr_any(pTunnelEntry->remote))
		pTunnelEntry->state |= TNL_STATE_REMOTE_ANY;

	if (cmd.enabled)
		pTunnelEntry->state |= TNL_STATE_ENABLED;

	if ((rc = M_tnl_add(pTunnelEntry)) != 0)
		goto err1;

	return NO_ERR;

err1:
	tunnel_free(pTunnelEntry);

err0:
	return rc;
}

/**
 * TNL_handle_UPDATE
 *
 *
 */
static int TNL_handle_UPDATE(U16 *p, U16 Length)
{
	TNLCommand_create cmd;
	PTnlEntry pTunnelEntry;

	/* Check length */
	if (Length != sizeof(TNLCommand_create))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_create));

	pTunnelEntry = M_tnl_get_by_name(cmd.name);
	if (!pTunnelEntry)
		return ERR_TNL_ENTRY_NOT_FOUND;

	if (pTunnelEntry->mode != cmd.mode)
		return ERR_TNL_NOT_SUPPORTED;

	if (pTunnelEntry->pRtEntry)
	{
		L2_route_put(pTunnelEntry->pRtEntry);

		pTunnelEntry->pRtEntry = NULL;
	}

	pTunnelEntry->state &= ~TNL_STATE_REMOTE_ANY;
	/* For copy we don't care to copy useless data in IPv4 case */
	memcpy(pTunnelEntry->local, cmd.local, IPV6_ADDRESS_LENGTH);
	memcpy(pTunnelEntry->remote, cmd.remote, IPV6_ADDRESS_LENGTH);


	if(((pTunnelEntry->proto == PROTO_IPV4) && (!pTunnelEntry->remote[0])) ||
			is_ipv6_addr_any(pTunnelEntry->remote))
		pTunnelEntry->state |= TNL_STATE_REMOTE_ANY;

	pTunnelEntry->secure = cmd.secure;
	pTunnelEntry->fl = cmd.fl;
	pTunnelEntry->hlim = cmd.hlim;
	pTunnelEntry->elim = cmd.elim;
	pTunnelEntry->route_id = cmd.route_id;
	pTunnelEntry->pRtEntry = L2_route_get(pTunnelEntry->route_id);
	pTunnelEntry->tnl_mtu  = cmd.mtu;
	pTunnelEntry->flags = cmd.flags;

	M_tnl_build_header(pTunnelEntry);

	if (cmd.enabled)
		pTunnelEntry->state |= TNL_STATE_ENABLED;
	else
		pTunnelEntry->state &= ~TNL_STATE_ENABLED;

	tnl_update(pTunnelEntry);
	return NO_ERR;
}


/**
 * TNL_handle_DELETE
 *
 *
 */
static int TNL_handle_DELETE(U16 *p, U16 Length)
{
	TNLCommand_delete cmd;
	PTnlEntry pTunnelEntry = NULL;

	/* Check length */
	if (Length != sizeof(TNLCommand_delete))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_delete));

	if((pTunnelEntry = M_tnl_get_by_name(cmd.name)) == NULL)
		return ERR_TNL_ENTRY_NOT_FOUND;

	/* Tell the Interface Manager to remove the tunnel IF */
	remove_onif_by_index(pTunnelEntry->itf.index);
	M_tnl_delete(pTunnelEntry);

	return NO_ERR;
}


/**
 * tnl_update
 *
 * Update the hardware tunnel tables
 */

void tnl_update(PTnlEntry pTunnelEntry)
{

	dpa_update_tunnel_if(&pTunnelEntry->itf, (pTunnelEntry->pRtEntry) ? pTunnelEntry->pRtEntry->itf : NULL  , pTunnelEntry);
}


/**
 * M_tnl_cmdproc
 *
 *
 *
 */
static U16 tnl_create_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)out_reply_len;
	return (U16)TNL_handle_CREATE(pcmd, cmd_len);
}

static U16 tnl_update_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)out_reply_len;
	return (U16)TNL_handle_UPDATE(pcmd, cmd_len);
}

static U16 tnl_delete_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)out_reply_len;
	return (U16)TNL_handle_DELETE(pcmd, cmd_len);
}

/*
 * CMD_TNL_QUERY / CMD_TNL_QUERY_CONT: pre-migration code handled
 * both inline under the same case with `cmd_code == CMD_TNL_QUERY`
 * picking the reset flag. Split into two handlers here so each
 * table entry points at the right one; functionally identical.
 *
 * Reply-length follows the PPPoE-style wire contract: on NO_ERR
 * the status word at pcmd[0] replaces the action field and the
 * rest of TNLCommand_query is the query payload, so total reply
 * length is exactly sizeof(TNLCommand_query) — NOT
 * sizeof(U16) + sizeof(TNLCommand_query).
 *
 * Length: the old cmdproc did not length-check the query arms,
 * so use CDX_CMD_VAR(0, U16_MAX) to preserve permissive behavior
 * per the A1b template.
 */
static U16 tnl_query_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U16 rc;

	(void)cmd_len;
	rc = (U16)Tnl_Get_Next_Hash_Entry((PTNLCommand_query)pcmd, 1);
	if (rc == NO_ERR)
		*out_reply_len = sizeof(TNLCommand_query);
	return rc;
}

static U16 tnl_query_cont_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U16 rc;

	(void)cmd_len;
	rc = (U16)Tnl_Get_Next_Hash_Entry((PTNLCommand_query)pcmd, 0);
	if (rc == NO_ERR)
		*out_reply_len = sizeof(TNLCommand_query);
	return rc;
}

static const struct cdx_cmd_spec tnl_cmd_table[] = {
	CDX_CMD(CMD_TNL_CREATE, TNLCommand_create, tnl_create_handle),
	CDX_CMD(CMD_TNL_UPDATE, TNLCommand_create, tnl_update_handle),
	CDX_CMD(CMD_TNL_DELETE, TNLCommand_delete, tnl_delete_handle),
	CDX_CMD_VAR(CMD_TNL_QUERY,      0, U16_MAX, NULL, tnl_query_handle),
	CDX_CMD_VAR(CMD_TNL_QUERY_CONT, 0, U16_MAX, NULL, tnl_query_cont_handle),
};

static U16 M_tnl_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	return cdx_dispatch_cmd(tnl_cmd_table, ARRAY_SIZE(tnl_cmd_table),
				cmd_code, cmd_len, pcmd);
}



int tunnel_init(void)
{
	int i = 0;
	set_cmd_handler(EVENT_TNL_IN, M_tnl_cmdproc);

	for(i = 0; i < NUM_TUNNEL_ENTRIES; i++)
	{
		slist_head_init(&tunnel_name_cache[i]);
	}

	return 0;
}


void tunnel_exit(void)
{
	int i;
	struct slist_entry *entry;
	PTnlEntry pTunnelEntry;

	for (i = 0; i < NUM_TUNNEL_ENTRIES; i++)
	{
		slist_for_each_safe(pTunnelEntry, entry, &tunnel_name_cache[i], list) {
			M_tnl_delete(pTunnelEntry);
		}
	}
}

static int Tnl_Get_Hash_Entries(int hash_index)
{
	int tot_tunnels = 0;
	PTnlEntry pTunnelEntry;
	struct slist_entry *entry;
	slist_for_each(pTunnelEntry, entry, &tunnel_name_cache[hash_index], list)
	{
		tot_tunnels++;
	}
	return tot_tunnels;
}


/* This function fills in the snapshot of all tunnel entries of a tunnel cache */

static void fill_snapshot(PTNLCommand_query pTnlSnapshot, PTnlEntry pTnlEntry)
{
	memset(pTnlSnapshot , 0, sizeof(TNLCommand_query));
	pTnlSnapshot->mode = pTnlEntry->mode;
	pTnlSnapshot->secure = pTnlEntry->secure;
	memcpy(pTnlSnapshot->name, pTnlEntry->tnl_name, 16);
	memcpy(pTnlSnapshot->local, pTnlEntry->local, IPV6_ADDRESS_LENGTH);
	memcpy(pTnlSnapshot->remote, pTnlEntry->remote, IPV6_ADDRESS_LENGTH);
	pTnlSnapshot->fl=pTnlEntry->fl;
	pTnlSnapshot->frag_off = pTnlEntry->frag_off;
	pTnlSnapshot->enabled = pTnlEntry->state;
	pTnlSnapshot->elim = pTnlEntry->elim;
	pTnlSnapshot->hlim = pTnlEntry->hlim;
	pTnlSnapshot->mtu = pTnlEntry->tnl_mtu;
}

static int Tnl_Get_Hash_Snapshot(int hash_index, int tnl_entries, PTNLCommand_query pTnlSnapshot)
{
	int tot_tnls = 0;
	PTnlEntry pTnlEntry;

	struct slist_entry *entry;
	slist_for_each(pTnlEntry, entry, &tunnel_name_cache[hash_index], list)
	{
		fill_snapshot(pTnlSnapshot, pTnlEntry);
		pTnlSnapshot++;
		tot_tnls++;
		tnl_entries--;
		if (tnl_entries == 0)
			break;
	}
	return tot_tnls;
}

U16 Tnl_Get_Next_Hash_Entry(PTNLCommand_query pTnlCmd, int reset_action)
{
	int total_tnl_entries;
	PTNLCommand_query pTnl;
	U16 retval;
	static PTNLCommand_query pTnlSnapshot = NULL;
	static int tnl_hash_index = 0, tnl_snapshot_entries = 0, tnl_snapshot_index = 0;

	mutex_lock(&tnl_query_mutex);

	if(reset_action)
	{
		tnl_hash_index = 0;
		tnl_snapshot_entries = 0;
		tnl_snapshot_index = 0;
		if (pTnlSnapshot)
		{
			Heap_Free(pTnlSnapshot);
			pTnlSnapshot = NULL;
		}
	}

	if (tnl_snapshot_index == 0)
	{
		while (tnl_hash_index < NUM_TUNNEL_ENTRIES)
		{
			total_tnl_entries = Tnl_Get_Hash_Entries(tnl_hash_index);
			if (total_tnl_entries == 0)
			{
				tnl_hash_index++;
				continue;
			}
			if (pTnlSnapshot)
				Heap_Free(pTnlSnapshot);
			pTnlSnapshot = Heap_Alloc(total_tnl_entries * sizeof(TNLCommand_query));
			if (!pTnlSnapshot) {
				retval = ERR_NOT_ENOUGH_MEMORY;
				goto out;
			}
			tnl_snapshot_entries = Tnl_Get_Hash_Snapshot(tnl_hash_index, total_tnl_entries, pTnlSnapshot);
			break;
		}
		if (tnl_hash_index >= NUM_TUNNEL_ENTRIES)
		{
			tnl_hash_index = 0;
			if (pTnlSnapshot)
			{
				Heap_Free(pTnlSnapshot);
				pTnlSnapshot = NULL;
			}
			retval = ERR_TNL_ENTRY_NOT_FOUND;
			goto out;
		}
	}

	pTnl = &pTnlSnapshot[tnl_snapshot_index++];
	memcpy(pTnlCmd, pTnl, sizeof(TNLCommand_query));
	if (tnl_snapshot_index == tnl_snapshot_entries)
	{
		tnl_snapshot_index = 0;
		tnl_hash_index ++;
	}

	retval = NO_ERR;
out:
	mutex_unlock(&tnl_query_mutex);
	return retval;
}

static U16 tunnel_stats_get(PTnlEntry pEntry, PStatTunnelEntryResponse snapshot, U32 do_reset)
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

/* This function fills in the snapshot of all tunnel entries of a tunnel cache along with statistics information*/

static U16 stat_tunnel_Get_Session_Snapshot(int hash_index, int stat_tunnel_entries,
		PStatTunnelEntryResponse pStatTunnelSnapshot, int *stat_tot_tunnel)
{
	PTnlEntry pStatTunnelEntry;
	struct slist_entry *entry;
	U16 ret = 0;

	*stat_tot_tunnel = 0;
	slist_for_each(pStatTunnelEntry, entry, &tunnel_name_cache[hash_index], list)
	{
		memset(pStatTunnelSnapshot, 0, sizeof(StatTunnelEntryResponse));
		strscpy((char *)pStatTunnelSnapshot->ifname,
				get_onif_name(pStatTunnelEntry->itf.index),
				sizeof(pStatTunnelSnapshot->ifname));
		if ((ret = tunnel_stats_get(pStatTunnelEntry, pStatTunnelSnapshot,
						gStatTunnelQueryStatus & STAT_TUNNEL_QUERY_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __func__, ret);
			return ret;
		}

		pStatTunnelSnapshot++;
		(*stat_tot_tunnel)++;

		if (--stat_tunnel_entries <= 0)
			break;
	}

	return NO_ERR;
}


U16 stat_tunnel_Get_Next_SessionEntry(PStatTunnelEntryResponse pResponse, int reset_action)
{
	int stat_total_tunnel_entries;
	PStatTunnelStatusCmd pCommand = (PStatTunnelStatusCmd)pResponse;
	PStatTunnelEntryResponse pStatTunnel;
	static PStatTunnelEntryResponse pStatTunnelSnapshot = NULL;
	static int stat_tunnel_hash_index = 0, stat_tunnel_snapshot_entries = 0, stat_tunnel_snapshot_index = 0;
	static char stat_tunnel_name[IF_NAME_SIZE];
	U16 ret = 0;

	mutex_lock(&tnl_query_mutex);

	if(reset_action)
	{
		stat_tunnel_hash_index = 0;
		stat_tunnel_snapshot_entries = 0;
		stat_tunnel_snapshot_index = 0;
		if (pStatTunnelSnapshot)
		{
			Heap_Free(pStatTunnelSnapshot);
			pStatTunnelSnapshot = NULL;
		}
		memcpy(stat_tunnel_name, pCommand->ifname, IF_NAME_SIZE - 1);
		ret = NO_ERR;
		goto out;
	}

top:
	if (stat_tunnel_snapshot_index == 0)
	{
		while(stat_tunnel_hash_index < NUM_TUNNEL_ENTRIES)
		{
			stat_total_tunnel_entries = Tnl_Get_Hash_Entries(stat_tunnel_hash_index);
			if (stat_total_tunnel_entries == 0)
			{
				stat_tunnel_hash_index++;
				continue;
			}

			if(pStatTunnelSnapshot)
				Heap_Free(pStatTunnelSnapshot);
			pStatTunnelSnapshot = Heap_Alloc(stat_total_tunnel_entries * sizeof(StatTunnelEntryResponse));
			if (!pStatTunnelSnapshot)
			{
				stat_tunnel_hash_index = 0;
				ret = ERR_NOT_ENOUGH_MEMORY;
				goto out;
			}

			if ((ret = stat_tunnel_Get_Session_Snapshot(stat_tunnel_hash_index,
							stat_total_tunnel_entries,pStatTunnelSnapshot,
							&stat_tunnel_snapshot_entries)) != NO_ERR)
			{
				goto out;
			}
			break;
		}

		if (stat_tunnel_hash_index >= NUM_TUNNEL_ENTRIES)
		{
			stat_tunnel_hash_index = 0;
			if(pStatTunnelSnapshot)
			{
				Heap_Free(pStatTunnelSnapshot);
				pStatTunnelSnapshot = NULL;
			}
			ret = ERR_TNL_ENTRY_NOT_FOUND;
			goto out;
		}
	}

	pStatTunnel = &pStatTunnelSnapshot[stat_tunnel_snapshot_index++];

	memcpy(pResponse, pStatTunnel, sizeof(StatTunnelEntryResponse));
	if (stat_tunnel_snapshot_index == stat_tunnel_snapshot_entries)
	{
		stat_tunnel_snapshot_index = 0;
		stat_tunnel_hash_index++;
	}

	if (stat_tunnel_name[0])
	{
		// If name is specified, and no match, keep looking
		if (strcmp(stat_tunnel_name, pResponse->ifname) != 0)
			goto top;
		// If name matches, force EOF on next call
		stat_tunnel_hash_index = NUM_TUNNEL_ENTRIES;
		stat_tunnel_snapshot_index = 0;
	}

	ret = NO_ERR;
out:
	mutex_unlock(&tnl_query_mutex);
	return ret;
}


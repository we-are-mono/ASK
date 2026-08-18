/*
 *
 *  Copyright (C) 2015 Freescale Semiconductor, Inc.
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 *
 */

#include <stdbool.h>
#include <signal.h>
#include <net/if.h>
#include <sys/time.h>

#include "cmm.h"
#include "module_ipsec.h"
#include "keytrack.h"

#define SA_STATE_INIT           0x1
#define SA_STATE_VALID          0x2
#define SA_STATE_DEAD           0x3
#define SA_STATE_EXPIRED        0x4
#define SA_STATE_DYING          0x5

struct nlkey_sa_notify {
        unsigned short sagd;
        unsigned short rsvd;
        unsigned int  action;
};

struct list_head sa_table[SA_HASH_TABLE_SIZE];
pthread_mutex_t sa_lock = PTHREAD_MUTEX_INITIALIZER;


static inline unsigned short  getSAHash(unsigned short id)
{
	return (id  & (SA_HASH_TABLE_SIZE -1));
}


int cmmSAShow(struct cli_def * cli, const char *command, char *argv[], int argc)
{
	int i, count = 0;
	struct SATable *pSAEntry;
	struct list_head *entry;
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
	__pthread_mutex_lock(&sa_lock);
	for (i = 0; i < SA_HASH_TABLE_SIZE; i++)
	{
		for(entry = list_first(&sa_table[i]); entry != &sa_table[i]; entry = list_next(entry))	
		{
			count++;
			pSAEntry = container_of(entry, struct SATable, list_by_h);
			cli_print(cli, "Sagd: %d, SPI:0x%x, sa_type: %d, protocal: %d\n", pSAEntry->SAInfo.sagd, pSAEntry->SAInfo.id.spi, pSAEntry->SAInfo.id.sa_type, pSAEntry->SAInfo.id.proto_family);
			if(pSAEntry->SAInfo.proto_family != 0)
			{
				if(pSAEntry->SAInfo.proto_family == PROTO_FAMILY_IPV4)
					cli_print(cli, "IPv4 Tunnel Header Source: %s, Destination: %s \n", inet_ntop(AF_INET, &pSAEntry->SAInfo.tunnel.ipv4h.SourceAddress, sbuf, sizeof(sbuf)), inet_ntop(AF_INET, &pSAEntry->SAInfo.tunnel.ipv4h.DestinationAddress, dbuf, sizeof(dbuf)));
				else
					cli_print(cli, "IPv6 Tunnel Header Source: %s, Destination: %s \n", inet_ntop(AF_INET6, pSAEntry->SAInfo.tunnel.ipv6h.SourceAddress, sbuf, sizeof(sbuf)), inet_ntop(AF_INET6, pSAEntry->SAInfo.tunnel.ipv6h.DestinationAddress, dbuf, sizeof(dbuf)));
			}
		}
	}
	__pthread_mutex_unlock(&sa_lock);
	cli_print(cli, "Total SA count %d\n", count);
	return CLI_OK;
}


struct SATable *__cmmSAFind(unsigned short handle)
{
	unsigned short hash = getSAHash(handle);
	struct SATable *SAEntry = NULL;
	struct list_head *entry;
	
	for(entry = list_first(&sa_table[hash]); entry != &sa_table[hash]; entry = list_next(entry))
	{
		SAEntry = container_of(entry, struct SATable, list_by_h);
		if (SAEntry->SAInfo.sagd == handle)
			return SAEntry;
	}

	return NULL;
}

static struct SATable *__cmmSAAdd(PCommandIPSecCreateSA pSA_info)
{
	struct SATable *newEntry;
	unsigned short hash;
	int i;

	newEntry = (struct SATable*) calloc(1, sizeof(struct SATable));
	if (newEntry == NULL)
	{
		cmm_print(DEBUG_ERROR, "%s: malloc failed\n", __func__);
		goto err0;
	}

	newEntry->SAInfo.sagd = pSA_info->sagd;
	hash = getSAHash(newEntry->SAInfo.sagd);
	memcpy(&newEntry->SAInfo.id, &pSA_info->said, sizeof(newEntry->SAInfo.id));

	/* Populate Sa_flow with the SA's outer endpoints so transport-mode
	 * SAs (which never go through __cmmSATunnelRegister) have valid
	 * sAddr/dAddr pointers. Without this, the conntrack-event path
	 * (____cmmCtRegister → __cmmCtTunnelRouteRegister) reaches the
	 * CMM_ENCAP_SECURE branch with a zeroed Sa_flow and crashes inside
	 * HASH_RT (NULL dAddr deref). For tunnel-mode SAs, __cmmSATunnelRegister
	 * later overwrites these with tunnel addresses — same call site,
	 * just runs later in the SET_TUNNEL handler.
	 */
	newEntry->Sa_flow.family = (newEntry->SAInfo.id.proto_family == PROTO_FAMILY_IPV4)
	                          ? AF_INET : AF_INET6;
	newEntry->Sa_flow.sAddr = newEntry->SAInfo.id.src_ip;
	newEntry->Sa_flow.dAddr = newEntry->SAInfo.id.dst_ip;
	newEntry->Sa_flow.fwmark = 0;
	newEntry->Sa_flow.iifindex = 0;
	newEntry->Sa_flow.proto = 0;
	newEntry->Sa_flow.flow_flags = FLOWFLAG_SA_ROUTE;

	/* init ctentries table */
	for(i =0; i < 2; i++)
		list_head_init(&newEntry->ctentry_list[i]);

	list_add(&sa_table[hash], &newEntry->list_by_h);

err0:
	return newEntry;
}


int __cmmSATunnelRegister(FCI_CLIENT *fci_handle, struct SATable* SAEntry)
{
	CommandIPSecSetTunnelRoute cmd_set_tnl_route;
	int rc = 0;
	SAEntry->Sa_flow.family = SAEntry->SAInfo.proto_family;
	
	if (SAEntry->SAInfo.proto_family == PROTO_FAMILY_IPV4)
	{
		SAEntry->Sa_flow.sAddr = &SAEntry->SAInfo.tunnel.ipv4h.SourceAddress;
		SAEntry->Sa_flow.dAddr = &SAEntry->SAInfo.tunnel.ipv4h.DestinationAddress;
	}
	else
	{
		SAEntry->Sa_flow.sAddr = SAEntry->SAInfo.tunnel.ipv6h.SourceAddress;
		SAEntry->Sa_flow.dAddr = SAEntry->SAInfo.tunnel.ipv6h.DestinationAddress;
	}
	
	SAEntry->Sa_flow.fwmark = 0;
	SAEntry->Sa_flow.iifindex = 0;
	SAEntry->Sa_flow.proto = 0;
	/* Eventhough SA is local connection, as the connection will not exist in kernel this is disabled */
	SAEntry->Sa_flow.flow_flags = FLOWFLAG_SA_ROUTE;

	rc = __cmmRouteRegister(&SAEntry->tnl_rt, &SAEntry->Sa_flow, "sa");
/*
   Neighbor entry in linux neighbor cache is not created during the creation of route entry
   in linux route cache. Consider a scenario where an SA is waiting for a
   neighbor 'X' and some other connection creates this neighbor entry 'X' in CMM. Now the neighbor creation
   event received by CMM will be ignored since neighbor entry is already present in CMM and no changes were
   made to neighbor entry. SA waiting for neighbor will never know the creation of neighbor entry 'X' in CMM.
   To fix this a dummy entry is created in CMM if the required neighbor entry is not present in linux neighbor cache.
*/
	if(SAEntry->tnl_rt.route && !SAEntry->tnl_rt.route->neighEntry)
	{
		struct NeighborEntry *neigh;

		neigh = __cmmNeighAdd(SAEntry->tnl_rt.route->family, SAEntry->tnl_rt.route->gwAddr, SAEntry->tnl_rt.route->oifindex);
		/* Allocation failure just means no dummy entry: the next
		 * re-registration (route or SA event) re-attaches the neighbor
		 * via __cmmNeighRegister's find-or-add. */
		if (neigh)
		{
			neigh->count++;
			SAEntry->tnl_rt.route->neighEntry = neigh;
		}
	}
	if (rc < 0)
		goto program;

	cmm_print(DEBUG_INFO, "%s:Neighor resolved \n", __func__);

	if (cmmFeRouteUpdate(fci_handle, ADD | UPDATE, SAEntry->tnl_rt.fpp_route) < 0)
	{
		/* Don't point the SA at a route id the forward engine never
		 * accepted. Record the id we tried so FPP_NEEDS_UPDATE stays
		 * armed and a later route event retries the whole sequence. */
		__cmmCheckFPPRouteIdUpdate(&SAEntry->tnl_rt, &SAEntry->flags);

		return -1;
	}

program:

	__cmmCheckFPPRouteIdUpdate(&SAEntry->tnl_rt, &SAEntry->flags);
	cmd_set_tnl_route.sagd = SAEntry->SAInfo.sagd;
	cmd_set_tnl_route.route_id = SAEntry->tnl_rt.fpp_route_id;

	/* Send the tunnel command to FPP */
	if (SAEntry->flags & FPP_NEEDS_UPDATE)
	{
		if (cmmKeyEnginetoIPSec(fci_handle, FPP_CMD_IPSEC_SA_TNL_ROUTE, sizeof(CommandIPSecSetTunnelRoute),&cmd_set_tnl_route) < 0)
		{
			cmm_print(DEBUG_ERROR, "%s:cmmKeyEnginetoIPSec failed while setting tunnel route:\n", __func__);
			return -1;
		}
	}

	SAEntry->flags &= ~FPP_NEEDS_UPDATE;

	return rc;
}


static void __cmmSARouteUpdate(FCI_CLIENT *fci_handle, struct SATable *s, struct RtEntry *route)
{
	struct ct_route rt = s->tnl_rt;
	int rollback = 0;
	int rc;

	cmm_print(DEBUG_INFO, "%s\n", __func__);

	if (route->flags & INVALID)
	{
		s->tnl_rt.route = NULL;
		s->tnl_rt.fpp_route = NULL;
	}
	else
	{
		rt.route = NULL;
		s->tnl_rt.fpp_route = NULL;
	}

	__pthread_mutex_lock(&sa_lock);

	rc = __cmmSATunnelRegister(fci_handle, s);

	if ((rc < 0) && !(route->flags & INVALID))
	{
		/* The forward engine kept the old route when it refused the swap.
		 * Put the old binding back so both sides agree, keep the update
		 * pending and let a later route event retry it. Deregistering the
		 * old route here would only be rejected, since it is still
		 * referenced. */
		if (s->tnl_rt.fpp_route != rt.fpp_route)
			__cmmFPPRouteDeregister(fci_handle, s->tnl_rt.fpp_route, "sa");
		else if (s->tnl_rt.fpp_route)
		{
			/* Re-resolution landed on the route entry already held and
			 * took a second local reference. The forward engine still has
			 * the route, so drop only the extra count. */
			__cmmFPPRoutePut(s->tnl_rt.fpp_route);
		}

		s->tnl_rt.fpp_route = rt.fpp_route;
		s->tnl_rt.fpp_route_id = rt.fpp_route_id;
		s->flags |= FPP_NEEDS_UPDATE;

		rollback = 1;
	}

	__pthread_mutex_unlock(&sa_lock);

	if (rollback)
		return;

	__cmmRouteDeregister(fci_handle, &rt, "sa");
}

void __cmmSAUpdateWithRoute(FCI_CLIENT *fci_handle, struct RtEntry *route)
{
	struct SATable *s;
	struct list_head *entry;
	int i;


	for (i = 0; i < SA_HASH_TABLE_SIZE; i++)
	{
		for (entry = list_first(&sa_table[i]); entry != &sa_table[i]; entry = list_next(entry))
		{
			s = container_of(entry, struct SATable, list_by_h);

			if (s->tnl_rt.route == route)
				 __cmmSARouteUpdate(fci_handle, s, route);
		}
	}

}

int __cmmRouteIsSA(int family, const unsigned int* daddr, struct SATable* sa, int prefix_match, int prefix_len)
{
	unsigned int* tunnel_daddr;
	int addr_len = IPADDRLEN(family);


	/* An SA that already has a route still matches while it owes the
	 * forward engine an update: its last programming attempt was refused
	 * and rolled back, so this route event is its retry. */
	if (sa->tnl_rt.route && !(sa->flags & FPP_NEEDS_UPDATE))
		goto out;

	if (sa->SAInfo.proto_family != family)
		goto out;

	if (sa->SAInfo.proto_family == PROTO_FAMILY_IPV4)
		tunnel_daddr = &sa->SAInfo.tunnel.ipv4h.DestinationAddress;
	else
		tunnel_daddr = sa->SAInfo.tunnel.ipv6h.DestinationAddress;

	if (prefix_match)
	{
		if (cmmPrefixEqual(tunnel_daddr, daddr, prefix_len))
		return 1;
	}
	else
	{
		if (memcmp(tunnel_daddr, daddr, addr_len) == 0)
		return 1;
	}
out:
	return 0;
}

static int __cmmSARemove(FCI_CLIENT *fci_handle, struct SATable *SAEntry)
{
	__cmmRouteDeregister(fci_handle, &SAEntry->tnl_rt, "sa");

        /* Remove it from the hash table */
	list_del(&SAEntry->list_by_h);
	free(SAEntry);

	return 0;
}


int cmmSACreate(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload)
{
	PCommandIPSecCreateSA pSA_cmd = (PCommandIPSecCreateSA)payload;
	struct SATable *pSAEntry;
	int rc = 0;
	if (len != sizeof(CommandIPSecCreateSA))
	{
		cmm_print(DEBUG_ERROR, "%s: command length doesn't match %zu-%d\n", __func__, sizeof(CommandIPSecCreateSA), len);
		return -1;
	}

	cmm_print(DEBUG_INFO, "%s: fcode 0x%x len %d bytes\n", __func__, fcode, len);

	__pthread_mutex_lock(&sa_lock);
	pSAEntry = __cmmSAFind(pSA_cmd->sagd);

	if (pSAEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: SA exists :%x \n", __func__, pSA_cmd->sagd);
		rc = -1;
		goto out;
	}
	
	pSAEntry = __cmmSAAdd(pSA_cmd);
	if(!pSAEntry)
	{
		rc = -1;
		goto out;
	}
	cmm_print(DEBUG_INFO, "%s: new SA added :%x, SPI %x \n", __func__, 
		pSA_cmd->sagd,pSAEntry->SAInfo.id.spi);

out:
	__pthread_mutex_unlock(&sa_lock);
	return rc;


}

int cmmSADelete(FCI_CLIENT *fci_handle, PCommandIPSecDeleteSA pSA_cmd)
{
	struct SATable *pSAEntry;
	int rc = 0;
	__pthread_mutex_lock(&sa_lock);
	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&ctMutex);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);

	pSAEntry = __cmmSAFind(pSA_cmd->sagd);
	if (!pSAEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: SA doesn't exist :%x \n", __func__, pSA_cmd->sagd);
		rc = -1;
		goto out;
	}
	cmm_print(DEBUG_INFO, "%s(%d) SA %p, XFRM handle %x, SPI %x\n",
		__func__,__LINE__,pSAEntry, pSA_cmd->sagd,pSAEntry->SAInfo.id.spi);
	
	pSAEntry->flags |= SA_DELETE;
	if(cmmUpdateFlows(pSAEntry) < 0)
	{
		rc = -1;
		goto out;
	}
	__cmmSARemove(fci_handle, pSAEntry);	

out:	
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&ctMutex);
	__pthread_mutex_unlock(&itf_table.lock);
	__pthread_mutex_unlock(&sa_lock);
	return rc;
}


int cmmSAFlush(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload)
{
	int i, rc = 0;
	struct SATable *pSAEntry;
	struct list_head *entry;

	__pthread_mutex_lock(&sa_lock);
	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&ctMutex);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	
	for (i = 0; i < SA_HASH_TABLE_SIZE; i++)
	{
		for(entry = list_first(&sa_table[i]); entry != &sa_table[i]; )	
		{
			pSAEntry = container_of(entry, struct SATable, list_by_h);
			entry = list_next(entry);
			pSAEntry->flags |= SA_DELETE;
			if(cmmUpdateFlows(pSAEntry) < 0)
			{
				cmm_print(DEBUG_INFO,"%s Failed \n", __func__);
			}
			__cmmSARemove(fci_handle, pSAEntry);
		}
	}
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&ctMutex);
	__pthread_mutex_unlock(&itf_table.lock);
	__pthread_mutex_unlock(&sa_lock);
	return rc;
}

int cmmSASetOffloadState(FCI_CLIENT *fci_handle, unsigned short sagd, bool offload_status)
{
	struct nlkey_sa_notify offload_status_change = {};
	/* Return -1 when offload is disabled so that SA never gets offloaded to CDX */
	int rc = (offload_status) ? 0:-1; 
	offload_status_change.sagd = sagd;
	offload_status_change.action = offload_status;
	if (cmmKeyEnginetoIPSec(fci_handle, FPP_CMD_IPSEC_SA_ACTION_OFFLOAD, sizeof(struct nlkey_sa_notify),
		&offload_status_change) < 0)
	{
		cmm_print(DEBUG_INFO,"%s: FPP_CMD_IPSEC_SA_ACTION_OFFLOAD failed", __func__);
		rc = -1;
	}
	return rc;
}

int cmmSASetState(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload, 
						int *state_valid, unsigned short *sgid)
{
	PCommandIPSecSetState pSA_cmd = (PCommandIPSecSetState)payload;
	struct SATable *pSAEntry;
	int rc = 0;
	if (len != sizeof(CommandIPSecSetState))
	{
		cmm_print(DEBUG_ERROR, "%s: command length doesn't match %zu-%d\n", __func__, sizeof(CommandIPSecSetState), len);
		return -1;
	}
	__pthread_mutex_lock(&sa_lock);
	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&ctMutex);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);

	pSAEntry = __cmmSAFind(pSA_cmd->sagd);

	if (!pSAEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: SA doesn't exist :%x \n", __func__, pSA_cmd->sagd);
		rc = -1;
		goto out;
	}
	cmm_print(DEBUG_INFO,"%s:  SA State change %d ",__func__,pSA_cmd->state);
#ifdef LS1043
	/* Do not offload Transport mode flows on LS104x,
	   Reset offloaded flag on the corresponding xfrm SA in Linux */
	rc = cmmSASetOffloadState(fci_handle, pSA_cmd->sagd, IS_TUNNEL_MODE_SA(pSAEntry));
#else
	rc = cmmSASetOffloadState(fci_handle, pSA_cmd->sagd, true);
#endif
	if(rc < 0)
		goto out;

	pSAEntry->SAInfo.state = pSA_cmd->state;
	if(pSA_cmd->state == SA_STATE_DYING)
	{
		pSAEntry->flags |= SA_DELETE;
		if(cmmUpdateFlows(pSAEntry) < 0)
		{
			rc = -1;
			goto out;
		}
		__cmmSARemove(fci_handle, pSAEntry);
	}

	if (pSA_cmd->state == SA_STATE_VALID)
	{
		*state_valid = 1;
		*sgid = pSAEntry->SAInfo.sagd;
		if (pSA_cmd->parent_sa_sagd)
		{
			/* Find flows having rekey_sagd value,
			update those with sagd value and new SA pointers */
			cmmUpdateFlowsWithNewSAInfo(pSAEntry, pSA_cmd->parent_sa_sagd);
		}
	}
	else
		*state_valid = 0;

out:
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&ctMutex);
	__pthread_mutex_unlock(&itf_table.lock);
	__pthread_mutex_unlock(&sa_lock);
	return rc;


}

int cmmSASetTunnel(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload)
{
	PCommandIPSecSetTunnel pSA_cmd = (PCommandIPSecSetTunnel)payload;
	int rc = 0;
	struct SATable *pSAEntry;
	if (len != sizeof(CommandIPSecSetTunnel))
	{
		cmm_print(DEBUG_ERROR, "%s: command length doesn't match %zu-%d\n", __func__, sizeof(CommandIPSecSetTunnel), len);
		return -1;
	}
	__pthread_mutex_lock(&sa_lock);
	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	pSAEntry = __cmmSAFind(pSA_cmd->sagd);

	if (!pSAEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: SA doesn't exist :%x \n", __func__, pSA_cmd->sagd);
		rc = -1;
		goto out;
	}

	pSAEntry->SAInfo.proto_family = pSA_cmd->proto_family;
	if (pSA_cmd->proto_family == PROTO_FAMILY_IPV4)
		memcpy(&pSAEntry->SAInfo.tunnel.ipv4h, &pSA_cmd->h.ipv4h, IPV4_HDR_SIZE);
	else
		memcpy(&pSAEntry->SAInfo.tunnel.ipv6h, &pSA_cmd->h.ipv6h, IPV6_HDR_SIZE);

	/* Find the route for tunnel and corresponding neighbor here */
	rc = __cmmSATunnelRegister(fci_handle, pSAEntry);
out:	
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&itf_table.lock);
	__pthread_mutex_unlock(&sa_lock);
	return rc;
}


struct SATable *cmmSAFind(unsigned short handle)
{
	return __cmmSAFind(handle);
}

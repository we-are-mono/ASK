 /*
  *  module_socket.c: Socket module
  *
  *  Copyright (C) 2007 Mindspeed Technologies, Inc.
  *  Copyright 2014-2016 Freescale Semiconductor, Inc.
  *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
  */


#include "cmm.h"
#include "module_socket.h"
#include "fpp_private.h"
#include "fpp.h"
#include "cmmd.h"

struct list_head socket_table[HASH_SOCKET_SIZE];
struct list_head socket_table_by_addr[HASH_SOCKET_SIZE];

pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;

/* One bit per allocatable private socket ID [1, NUM_INTERNAL_SOCKET_ID],
 * rounded up to whole u32 words. Sizing by ROUTE_MAX_ID (0x10000) was copied
 * from route_cache.c and wasted ~8 KB for what is really a 255-ID space. */
static u_int32_t internal_sock_ids[(NUM_INTERNAL_SOCKET_ID + 8 * sizeof(u_int32_t) - 1) / (8 * sizeof(u_int32_t))] = {0, };
static u_int32_t internal_sock_id = 0;

u_int32_t new_socket_id(void)
{
	int offset, mask;
	int i = 0;

	for ( ;i < NUM_INTERNAL_SOCKET_ID; i++, internal_sock_id++)
	{
		if (internal_sock_id >= NUM_INTERNAL_SOCKET_ID)
			internal_sock_id = 0;

		offset = internal_sock_id / (8 * sizeof(u_int32_t));
		mask = 1 << (internal_sock_id & 0x1f);
		if (!(internal_sock_ids[offset] & mask))
			goto found;

	}
	/* we're running in circles, return zero, we've exhausted all of our reserved sockets */
	return 0;

found:
	internal_sock_ids[offset] |= mask;

	return internal_sock_id + SOCK_ID_PRIVATE_START;
}

void del_socket_id(u_int32_t sock_id_ext)
{
	int sock_id = sock_id_ext - SOCK_ID_PRIVATE_START;
	int offset = sock_id / (8 * sizeof(u_int32_t));
	int mask = 1 << (sock_id & 0x1f);

	internal_sock_ids[offset] &= ~mask;
}

struct socket *socket_find(u_int16_t id)
{
	struct socket *s;
	int key;
	struct list_head *entry;

	cmm_print(DEBUG_INFO, "%s: find socket(%d)\n", __func__, id);

	key = HASH_SOCKET(id);

	entry = list_first(&socket_table[key]);

	while (entry != &socket_table[key])
	{
		s = container_of(entry, struct socket, list);
		if (s->id == id)
			//Entry found
			goto found;
		entry = list_next(entry);
	}

	s = NULL;

found:
	return s;
}

struct socket *socket_find_by_addr(int family, const u_int32_t *saddr, const u_int32_t *daddr, u_int16_t sport, u_int16_t dport, u_int8_t proto)
{
	char saddr_buf[INET6_ADDRSTRLEN], daddr_buf[INET6_ADDRSTRLEN];
	struct socket *s;
	int key;
	struct list_head *entry;
	int ip_len = IPADDRLEN(family);

	cmm_print(DEBUG_INFO, "%s(%d, %s, %s, %d, %d, %d)\n", __func__, family,
		inet_ntop(family, saddr, saddr_buf, INET6_ADDRSTRLEN),
		inet_ntop(family, daddr, daddr_buf, INET6_ADDRSTRLEN),
		ntohs(sport), ntohs(dport), proto);

	key= HASH_SOCK_ADDR(family, saddr, daddr, sport, dport, proto);

	entry = list_first(&socket_table_by_addr[key]);

	while (entry != &socket_table_by_addr[key])
	{
		s = container_of(entry, struct socket, list_by_addr);

		if ((family == s->family) && (proto == s->proto) && (sport == s->sport) && (dport == s->dport) && 
			!memcmp(saddr, s->saddr, ip_len) && !memcmp(daddr, s->daddr, ip_len))
			goto found;

		entry = list_next(entry);
	}

	return NULL;

found:
	cmm_print(DEBUG_INFO, "socket(%d, %s, %s, %d, %d, %d)\n", s->family,
			inet_ntop(s->family, s->saddr, saddr_buf, INET6_ADDRSTRLEN),
			inet_ntop(s->family, s->daddr, daddr_buf, INET6_ADDRSTRLEN),
			ntohs(s->sport), ntohs(s->dport), s->proto);

	return s;
}

void __socket_add(struct socket * s)
{
	int key;

	key = HASH_SOCKET(s->id);
	list_add(&socket_table[key], &s->list);

	key= HASH_SOCK_ADDR(s->family, s->saddr, s->daddr, s->sport, s->dport, s->proto);
	list_add(&socket_table_by_addr[key], &s->list_by_addr);

#if defined(COMCERTO_2000) || defined(LS1043)
#endif

}

static struct socket *socket_add(cmmd_socket_open_cmd_t *cmd)
{
	struct socket *s;

	s = malloc(sizeof(struct socket));
	if (!s)
	{
		cmm_print(DEBUG_ERROR, "%s: malloc() failed\n", __func__);
		goto err;
	}

	memset(s, 0, sizeof(struct socket));

	s->id = cmd->id;
	s->family = cmd->family;
	s->type = cmd->type;
	s->mode = cmd->mode;
	memcpy(s->saddr, cmd->saddr, IPADDRLEN(s->family));
	memcpy(s->daddr, cmd->daddr, IPADDRLEN(s->family));
	s->sport = cmd->sport;
	s->dport = cmd->dport;
	s->proto = cmd->proto;
	s->queue = cmd->queue;
	s->dscp = cmd->dscp;
	s->fwmark = cmd->fwmark;
#if defined(LS1043)
	s->expt_flag = cmd->expt_flag;
#endif //(LS1043)
	__socket_add(s);
err:
	return s;
}

void socket_remove(struct socket *s)
{
	list_del(&s->list);
	list_del(&s->list_by_addr);

	if((s->id >= SOCK_ID_PRIVATE_START) && (s->id <=  SOCK_ID_PRIVATE_END))
		del_socket_id(s->id);

	free(s);
}


/************************************************************
 *
 * socket4_send_cmd
 * Role: CMM to FPP commands in deamon context
 ************************************************************/
static int socket4_send_cmd(FCI_CLIENT *fci_handle, int action, struct socket *s)
{
	int ret = CMMD_ERR_OK;

	switch (action)
	{
	default:
		ret = CMMD_ERR_UNKNOWN_ACTION;
		break;

	case FPP_ACTION_REGISTER:
	{
		fpp_socket4_open_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		cmd.id = s->id;
		cmd.type = s->type;
		cmd.mode = s->mode; 
		cmd.saddr = s->saddr[0];
		cmd.daddr = s->daddr[0];
		cmd.sport = s->sport;
		cmd.dport = s->dport;
		cmd.proto = s->proto;
		cmd.queue = s->queue;
		cmd.dscp = s->dscp;
		cmd.route_id = s->rt.fpp_route_id;
#if defined(LS1043)
		cmd.expt_flag = s->expt_flag;
		cmd.iifindex = s->iifindex;
#endif //(LS1043)
#if defined(COMCERTO_2000) || defined(LS1043)
#endif

		//Send message to forward engine
		cmm_print(DEBUG_COMMAND, "Send CMD_IPV4_SOCK_OPEN\n");

		ret = fci_write(fci_handle, FPP_CMD_IPV4_SOCK_OPEN, sizeof(fpp_socket4_open_cmd_t), (u_int16_t *) &cmd);
		if (ret == FPP_ERR_OK)
		{
			s->flags |= FPP_PROGRAMMED;
			s->flags &= ~FPP_NEEDS_UPDATE;
		}
		else
		{
			if (ret > 0)
				cmm_print(DEBUG_ERROR, "%s: Error %d while sending CMD_IPV4_SOCK_OPEN\n", __func__, ret);
			else
				cmm_print(DEBUG_ERROR, "%s: Error '%s' while sending CMD_IPV4_SOCK_OPEN\n", __func__, strerror(errno));
			break;
		}
	}

		break;

	case FPP_ACTION_UPDATE:
	{
		fpp_socket4_update_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		cmd.id = s->id;
		cmd.saddr = s->saddr[0];
		cmd.sport = s->sport;
		cmd.queue = s->queue;
		cmd.dscp = s->dscp;
		cmd.route_id = s->rt.fpp_route_id;
#if defined(LS1043)
		cmd.expt_flag = s->expt_flag;
#endif
#if defined(COMCERTO_2000) || defined(LS1043)
#endif

		//Send message to forward engine
		cmm_print(DEBUG_COMMAND, "Send CMD_IPV4_SOCK_UPDATE\n");

		ret = fci_write(fci_handle, FPP_CMD_IPV4_SOCK_UPDATE, sizeof(fpp_socket4_update_cmd_t), (u_int16_t *) &cmd);
		if (ret == FPP_ERR_OK)
		{
			s->flags &= ~FPP_NEEDS_UPDATE;
		}
		else
		{
			if (ret > 0)
				cmm_print(DEBUG_ERROR, "%s: Error %d while sending CMD_IPV4_SOCK_UPDATE\n", __func__, ret);
			else
				cmm_print(DEBUG_ERROR, "%s: Error '%s' while sending CMD_IPV4_SOCK_UPDATE\n", __func__, strerror(errno));
			break;
		}
	}

		break;

	case FPP_ACTION_DEREGISTER:
	{
		fpp_socket4_close_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		//Send message to forward engine
		cmm_print(DEBUG_COMMAND, "Send CMD_IPV4_SOCK_CLOSE\n");

		cmd.id = s->id;

		ret = fci_write(fci_handle, FPP_CMD_IPV4_SOCK_CLOSE, sizeof(fpp_socket4_close_cmd_t), &cmd);
		if (ret == FPP_ERR_OK)
		{
			s->flags &= ~FPP_PROGRAMMED;
		}
		else
		{
			if (ret > 0)
				cmm_print(DEBUG_ERROR, "%s: Error %d while sending CMD_IPV4_SOCK_CLOSE\n", __func__, ret);
			else
				cmm_print(DEBUG_ERROR, "%s: Error '%s' while sending CMD_IPV4_SOCK_CLOSE\n", __func__, strerror(errno));
			break;
		}
	}
		break;
	}

	return ret;
}

/************************************************************
 *
 * socket6_send_cmd
 * Role: CMM to FPP commands in deamon context
 ************************************************************/
static int socket6_send_cmd(FCI_CLIENT *fci_handle, int action, struct socket *s)
{
	int ret = CMMD_ERR_OK;

	switch (action)
	{
	default:
		ret = CMMD_ERR_UNKNOWN_ACTION;
		break;
	case FPP_ACTION_REGISTER:
	{
		fpp_socket6_open_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		cmd.id = s->id;
		cmd.type = s->type;
		cmd.mode = s->mode; 
		memcpy(cmd.saddr, s->saddr, 16);
		memcpy(cmd.daddr, s->daddr, 16);
		cmd.sport = s->sport;
		cmd.dport = s->dport;
		cmd.proto = s->proto;
		cmd.queue = s->queue;
		cmd.dscp = s->dscp;
		cmd.route_id = s->rt.fpp_route_id;
#if defined(LS1043)
		cmd.expt_flag = s->expt_flag;
		cmd.iifindex = s->iifindex;
#endif
#if defined(COMCERTO_2000) || defined(LS1043)
#endif

		//Send message to forward engine
		cmm_print(DEBUG_COMMAND, "Send CMD_IPV6_SOCK_OPEN\n");

		ret = fci_write(fci_handle, FPP_CMD_IPV6_SOCK_OPEN, sizeof(fpp_socket6_open_cmd_t), (u_int16_t *) &cmd);
		if (ret == FPP_ERR_OK)
		{
			s->flags |= FPP_PROGRAMMED;
			s->flags &= ~FPP_NEEDS_UPDATE;
		}
		else
		{
			if (ret > 0)
				cmm_print(DEBUG_ERROR, "%s: Error %d while sending CMD_IPV6_SOCK_OPEN\n", __func__, ret);
			else
				cmm_print(DEBUG_ERROR, "%s: Error '%s' while sending CMD_IPV6_SOCK_OPEN\n", __func__, strerror(errno));
			break;
		}
	}

		break;

	case FPP_ACTION_UPDATE:
	{
		fpp_socket6_update_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		cmd.id = s->id;
		memcpy(cmd.saddr, s->saddr, 16);
		cmd.sport = s->sport;
		cmd.queue = s->queue;
		cmd.dscp = s->dscp;
		cmd.route_id = s->rt.fpp_route_id;
#if defined(LS1043)
		cmd.expt_flag = s->expt_flag;
#endif // LS1043
#if defined(COMCERTO_2000) || defined(LS1043)
#endif

		//Send message to forward engine
		cmm_print(DEBUG_COMMAND, "Send CMD_IPV6_SOCK_UPDATE\n");

		ret = fci_write(fci_handle, FPP_CMD_IPV6_SOCK_UPDATE, sizeof(fpp_socket6_update_cmd_t), (u_int16_t *) &cmd);
		if (ret == FPP_ERR_OK)
		{
			s->flags &= ~FPP_NEEDS_UPDATE;
		}
		else
		{
			if (ret > 0)
				cmm_print(DEBUG_ERROR, "%s: Error %d while sending CMD_IPV6_SOCK_UPDATE\n", __func__, ret);
			else
				cmm_print(DEBUG_ERROR, "%s: Error '%s' while sending CMD_IPV6_SOCK_UPDATE\n", __func__, strerror(errno));
			break;
		}
	}

		break;
	
	case FPP_ACTION_DEREGISTER:
	{
		fpp_socket6_close_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		//Send message to forward engine
		cmm_print(DEBUG_COMMAND, "Send CMD_IPV6_SOCK_CLOSE\n");

		cmd.id = s->id;

		ret = fci_write(fci_handle, FPP_CMD_IPV6_SOCK_CLOSE, sizeof(fpp_socket6_close_cmd_t), &cmd);
		if (ret == FPP_ERR_OK)
		{
			s->flags &= ~FPP_PROGRAMMED;
		}
		else
		{
			if (ret > 0)
				cmm_print(DEBUG_ERROR, "%s: Error %d while sending CMD_IPV6_SOCK_CLOSE\n", __func__, ret);
			else
				cmm_print(DEBUG_ERROR, "%s: Error '%s' while sending CMD_IPV6_SOCK_CLOSE\n", __func__, strerror(errno));
			break;
		}
	}
		break;
	}

	return ret;
}


/************************************************************
 *
 * socket_send_cmd
 * Role: CMM to FPP commands in deamon context
 ************************************************************/
static int socket_send_cmd(FCI_CLIENT *fci_handle, int request, struct socket *s)
{
	int action;

	switch (request)
	{
	case (ADD | UPDATE):
		if ((s->flags & (FPP_PROGRAMMED | FPP_NEEDS_UPDATE)) == FPP_PROGRAMMED)
			return CMMD_ERR_OK;

		if ((s->flags & (FPP_PROGRAMMED | FPP_NEEDS_UPDATE)) == (FPP_PROGRAMMED | FPP_NEEDS_UPDATE))
			action = FPP_ACTION_UPDATE;
		else
			action = FPP_ACTION_REGISTER;

		break;

	case UPDATE:
		if (!((s->flags & FPP_PROGRAMMED) && (s->flags & FPP_NEEDS_UPDATE)))
			return CMMD_ERR_OK;

		action = FPP_ACTION_UPDATE;
		break;
	
	case REMOVE:
		if (!(s->flags & FPP_PROGRAMMED))
			return CMMD_ERR_OK;

		action = FPP_ACTION_DEREGISTER;

		break;

	default:
		cmm_print(DEBUG_ERROR, "%s: Action not supported\n", __func__);
		return CMMD_ERR_UNKNOWN_ACTION;
	}

	if (s->family == AF_INET)
		return socket4_send_cmd(fci_handle, action, s);
	else if (s->family == AF_INET6)
		return socket6_send_cmd(fci_handle, action, s);
	else
		return CMMD_ERR_UNKNOWN;
}

int __socket_open(FCI_CLIENT *fci_handle, struct socket *s)
{
	int rc;

	cmm_print(DEBUG_INFO, "%s\n", __func__);

	if (s->type == CMMD_SOCKET_TYPE_LANWAN)
	{
		struct flow flow = {
					.family = s->family,
					.sAddr = s->daddr,
					.dAddr = s->saddr,
					.fwmark = s->fwmark,
					.iifindex = s->iifindex,
					.flow_flags = FLOWFLAG_SOCKET_ROUTE,
				};

		if (__cmmRouteRegister(&s->rt, &flow, "socket") < 0)
		{
			goto program;
		}

		if (cmmFeRouteUpdate(fci_handle, ADD | UPDATE, s->rt.fpp_route) < 0)
		{
			/* Don't describe the socket with a route id the forward
			 * engine never accepted. Record the id we tried so
			 * FPP_NEEDS_UPDATE stays armed and a later route event
			 * retries the whole sequence. */
			__cmmCheckFPPRouteIdUpdate(&s->rt, &s->flags);

			return CMMD_ERR_UNKNOWN;
		}
	}


program:
	__cmmCheckFPPRouteIdUpdate(&s->rt, &s->flags);

#if defined(COMCERTO_2000) || defined(LS1043)
			/* TODO  will be taken when supporting IPSEC for local in packets*/
#endif

	rc = socket_send_cmd(fci_handle, ADD | UPDATE, s);

	return rc;
}


#if defined(COMCERTO_2000) || defined(LS1043)
/************************************************************
 *
 * __cmmSocketFindFromFlow
 *
 ************************************************************/
struct socket *__cmmSocketFindFromFlow(int family, unsigned int *saddr, unsigned int *daddr, unsigned char proto, char *orig)
{
	struct socket *s;
	struct list_head *entry;
	int i;

	for (i = 0; i < HASH_SOCKET_SIZE; i++)
	{
		for (entry = list_first(&socket_table[i]); entry != &socket_table[i]; entry = list_next(entry))
		{
			s = container_of(entry, struct socket, list);
			if (s->family == family && s->proto == proto)
			{
				if (!memcmp(s->saddr, saddr, IPADDRLEN(family)) && !memcmp(s->daddr, daddr, IPADDRLEN(family)))
				{
					*orig = 1;
					goto found;
				}

				if (!memcmp(s->saddr, daddr, IPADDRLEN(family)) && !memcmp(s->daddr, saddr, IPADDRLEN(family)))
				{
					*orig = 0;
					goto found;
				}
			}
		}
	}

	s = NULL;

found:
	return s;
}
#endif	//  defined(COMCERTO_2000) || defined(LS1043)

/************************************************************
 *
 * __cmmSocketUpdateWithRoute
 *
 ************************************************************/
void __cmmSocketUpdateWithRoute(FCI_CLIENT *fci_handle, struct RtEntry *route)
{
	struct socket *s;
	struct list_head *entry;
	struct fpp_rt *fpp_route;
	int fpp_route_id;
	int rollback;
	int i;

	__pthread_mutex_lock(&socket_lock);

	for (i = 0; i < HASH_SOCKET_SIZE; i++)
	{
		for (entry = list_first(&socket_table[i]); entry != &socket_table[i]; entry = list_next(entry))
		{
			s = container_of(entry, struct socket, list);

			if (s->rt.route == route)
			{
				fpp_route = s->rt.fpp_route;
				fpp_route_id = s->rt.fpp_route_id;
				s->rt.fpp_route = NULL;
				rollback = 0;

				if (__socket_open(fci_handle, s) != CMMD_ERR_OK)
				{
					/* The programming attempt was refused, so the
					 * socket still owes the forward engine an update.
					 * Arm the retry whether or not the old binding has
					 * to be put back. */
					s->flags |= FPP_NEEDS_UPDATE;

					/* When the socket is not programmed the forward
					 * engine holds no old binding to stay in step with,
					 * so the old route can just be released. */
					if (s->flags & FPP_PROGRAMMED)
					{
						/* The forward engine validates before it
						 * commits, so it kept the old route. Put the
						 * old binding back so both sides agree and let
						 * a later route event retry. Deregistering the
						 * old route here would only be rejected, since
						 * it is still referenced. */
						if (s->rt.fpp_route != fpp_route)
							__cmmFPPRouteDeregister(fci_handle, s->rt.fpp_route, "socket");
						else if (s->rt.fpp_route)
						{
							/* Re-resolution landed on the route entry
							 * already held and took a second local
							 * reference. The forward engine still has
							 * the route, so drop only the extra count. */
							__cmmFPPRoutePut(s->rt.fpp_route);
						}

						s->rt.fpp_route = fpp_route;
						s->rt.fpp_route_id = fpp_route_id;

						rollback = 1;
					}
				}

				if (!rollback)
					__cmmFPPRouteDeregister(fci_handle, fpp_route, "socket");
			}
		}
	}

	__pthread_mutex_unlock(&socket_lock);
}


int __socket_close(FCI_CLIENT *fci_handle, FCI_CLIENT *fci_key_handle, struct socket *s)
{
	int rc = socket_send_cmd(fci_handle, REMOVE, s);
	if (rc != CMMD_ERR_OK)
		return rc;

	__cmmRouteDeregister(fci_handle, &s->rt, "socket");

#if defined(COMCERTO_2000) || defined(LS1043)
		/* TODO  will be taken when supporting IPSEC for local in packets*/
#endif

	/* In case of error the socket may still be programmed in fpp,
	   so don't remove it */
	if (s->flags & FPP_PROGRAMMED)
		goto err;

	socket_remove(s);

err:
	return rc;
}

static int socket_open(FCI_CLIENT *fci_handle, FCI_CLIENT *fci_key_handle, cmmd_socket_open_cmd_t *cmd)
{
	struct socket *s;
	unsigned short rc = 0; // rc=2 OK, rc=0 KO, cmm_client error code hack 

	cmm_print(DEBUG_INFO, "%s\n", __func__);

	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	__pthread_mutex_lock(&socket_lock);

	s = socket_find(cmd->id);
	if (!s)
	{
		s = socket_add(cmd);
		if (!s)
		{
			rc = -1;
			goto exit;
		}
	}
	else
		goto exit;

	rc = __socket_open(fci_handle, s);
	if(rc != CMMD_ERR_OK)
		__socket_close(fci_handle, fci_key_handle, s);

exit:
	__pthread_mutex_unlock(&socket_lock);
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&itf_table.lock);

	return rc;
}


static int socket_update(FCI_CLIENT *fci_handle, cmmd_socket_update_cmd_t *cmd)
{
	struct socket *s;
	unsigned short rc = 0; // rc=2 OK, rc=0 KO, cmm_client error code hack
	struct ct_route old_route;
	u_int32_t old_saddr[4];
	u_int16_t old_sport;
	u_int8_t old_queue;
	u_int16_t old_dscp;
#if defined(LS1043)
	u_int16_t old_expt_flag;
#endif // LS1043
	u_int8_t del_old_route=0;
	u_int32_t null_addr[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};

	cmm_print(DEBUG_INFO, "%s\n", __func__);

	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	__pthread_mutex_lock(&socket_lock);

	s = socket_find(cmd->id);
	if (!s)
	{
		cmm_print(DEBUG_ERROR, "invalid socket ID %d \n", cmd->id);
		rc = CMMD_ERR_NOT_FOUND;
		goto exit;
	}

	if (s->family != cmd->family)
	{
		cmm_print(DEBUG_ERROR, "invalid socket family %d \n", cmd->family);
		rc = CMMD_ERR_WRONG_COMMAND_PARAM;
		goto exit;
	}


	/* The forward engine validates a socket update before it commits it, so
	 * a rejected command leaves the socket running with the values it
	 * already had. Snapshot everything this command touches so it can be
	 * put back, keeping both sides on the old state when the update fails. */
	old_route = s->rt;
	memcpy(old_saddr, s->saddr, sizeof(old_saddr));
	old_sport = s->sport;
	old_queue = s->queue;
	old_dscp = s->dscp;
#if defined(LS1043)
	old_expt_flag = s->expt_flag;
#endif // LS1043

	if (memcmp(cmd->saddr, null_addr, IPADDRLEN(s->family)) && memcmp(cmd->saddr, s->saddr, IPADDRLEN(s->family))) // source has changed -> new route
	{
		memcpy(s->saddr, cmd->saddr, IPADDRLEN(s->family));
		s->rt.route = NULL;
		s->rt.fpp_route = NULL;
		del_old_route = 1;
	}

	if (cmd->sport != 0xffff)
		s->sport = cmd->sport;
	if (cmd->queue != 0xff)
		s->queue = cmd->queue;
	if (cmd->dscp != 0xffff)	
		s->dscp = cmd->dscp;
#if defined(LS1043)
	if (cmd->expt_flag != 0xffff)
		s->expt_flag = cmd->expt_flag;
#endif // LS1043

#if defined(COMCERTO_2000) || defined(LS1043)
#endif

	s->flags |= FPP_NEEDS_UPDATE;

	rc = __socket_open(fci_handle, s);

	if (rc != CMMD_ERR_OK)
	{
		/* Release whatever __socket_open() acquired, restore the snapshot
		 * and leave the old route registered. FPP_NEEDS_UPDATE stays set
		 * so a later route event retries the socket. The client gets the
		 * error, with neither side having moved. */
		if (s->rt.fpp_route != old_route.fpp_route)
			__cmmFPPRouteDeregister(fci_handle, s->rt.fpp_route, "socket");
		else if (del_old_route && s->rt.fpp_route)
		{
			/* The re-resolved route landed on the route entry already
			 * held and took a second local reference. The forward engine
			 * still has the route, so drop only the extra count. Without
			 * a new source address nothing was re-resolved, so an equal
			 * pointer there means untouched. */
			__cmmFPPRoutePut(s->rt.fpp_route);
		}

		if (s->rt.route && (s->rt.route != old_route.route))
			____cmmRouteDeregister(s->rt.route, "socket");

		s->rt = old_route;

		memcpy(s->saddr, old_saddr, sizeof(old_saddr));
		s->sport = old_sport;
		s->queue = old_queue;
		s->dscp = old_dscp;
#if defined(LS1043)
		s->expt_flag = old_expt_flag;
#endif // LS1043

		del_old_route = 0;
	}

exit:

	if (del_old_route)
	{
		cmm_print(DEBUG_INFO, "Removing old socket route entry\n");

		__cmmRouteDeregister(fci_handle, &old_route, "socket");
	}

	__pthread_mutex_unlock(&socket_lock);
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&itf_table.lock);

	return rc;
}


static int socket_close(FCI_CLIENT *fci_handle, FCI_CLIENT *fci_key_handle, cmmd_socket_close_cmd_t *cmd)
{
	struct socket *s;
	int ret = 0;

	cmm_print(DEBUG_INFO, "%s\n", __func__);

	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	__pthread_mutex_lock(&socket_lock);

	s = socket_find(cmd->id);
	if (!s)
	{
		cmm_print(DEBUG_ERROR, "%s: socket_find(%d) failed\n", __func__, cmd->id);
		ret = CMMD_ERR_NOT_FOUND;
		goto out;
	}

	ret = __socket_close(fci_handle, fci_key_handle, s);
	
out:
	__pthread_mutex_unlock(&socket_lock);
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&itf_table.lock);

	return ret;
}



/* CMM server side socket control */
int socket_daemon(FCI_CLIENT *fci_handle, FCI_CLIENT *fci_key_handle, int fc, u_int8_t *cmd_buf, u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len)
{
	int rc = 0, skipcount;
 	
	cmm_print(DEBUG_INFO, "%s\n", __func__);

	res_buf[0] = CMMD_ERR_WRONG_COMMAND_SIZE;

	switch (fc)
	{
	case CMMD_CMD_SOCKET_OPEN:
	{
		cmmd_socket_open_cmd_t *cmd = (cmmd_socket_open_cmd_t *)cmd_buf;
		*res_len = 2;

		if (cmd_len < sizeof(*cmd))
		{
			cmm_print(DEBUG_ERROR, "%s: socket open command size too small(%d, %zu)\n", __func__, cmd_len, sizeof(*cmd));
			break;
		}
		if(( cmd->id >= SOCK_ID_PRIVATE_START) && ( cmd->id <= (SOCK_ID_PRIVATE_END)) )
		{
			rc = res_buf[0] = CMMD_ERR_WRONG_SOCKID;
			break;
		}

		rc = socket_open(fci_handle, fci_key_handle, cmd);
		if (rc >= 0)
		{
			res_buf[0] = rc;
			rc = 0;
		}

		break;
	}

	case CMMD_CMD_SOCKET_UPDATE:
	{
		cmmd_socket_update_cmd_t *cmd = (cmmd_socket_update_cmd_t *)cmd_buf;
		*res_len = 2;

		if (cmd_len < sizeof(*cmd))
		{
			cmm_print(DEBUG_ERROR, "%s: socket update command size too small(%d, %zu)\n", __func__, cmd_len, sizeof(*cmd));
			break;
		}
		if(( cmd->id >= SOCK_ID_PRIVATE_START) && ( cmd->id <= (SOCK_ID_PRIVATE_END)) )
		{
			rc = res_buf[0] = CMMD_ERR_WRONG_SOCKID;
			break;
		}


		rc = socket_update(fci_handle, cmd);
		if (rc >= 0)
		{
			res_buf[0] = rc;
			rc = 0;
		}

		break;
	}

	case CMMD_CMD_SOCKET_CLOSE:
	{
		cmmd_socket_close_cmd_t *cmd = (cmmd_socket_close_cmd_t *)cmd_buf;
		*res_len = 2;

		if (cmd_len < sizeof(*cmd))
		{
			cmm_print(DEBUG_ERROR, "%s: socket close command size too small(%d, %zu)\n", __func__, cmd_len, sizeof(*cmd));
			break;
		}

		if(( cmd->id >= SOCK_ID_PRIVATE_START) && ( cmd->id <= (SOCK_ID_PRIVATE_END)) )
		{
			rc = res_buf[0] = CMMD_ERR_WRONG_SOCKID;
			break;
		}

		rc = socket_close(fci_handle, fci_key_handle, cmd);
		if (rc >= 0)
		{
			res_buf[0] = rc;
			rc = 0;
		}

		break;
	}

	case CMMD_CMD_SOCKET_SHOW:
	{
		int i;
		struct socket *s;
		cmmd_socket_show_cmd_t *cmd = (cmmd_socket_show_cmd_t *)cmd_buf;

		cmm_print(DEBUG_INFO, "reserve start and end(%d, %d)\n", SOCK_ID_PRIVATE_START, SOCK_ID_PRIVATE_END);

		__pthread_mutex_lock(&socket_lock);
		if (!cmd->dump_all)
		{
			s = socket_find(cmd->id);
			if(!s)
			{
				res_buf[0] = CMMD_ERR_NOT_FOUND;
				*res_len = 2;
			}
			else
			{
				memcpy(res_buf, s,sizeof(struct socket));
				res_buf[0] = CMMD_ERR_OK; /* XXX: overwrite first 2 bytes with return code.
							   * This is a hack. Should be fixed by defining correct response
							   * structure.
							   */
				*res_len = sizeof(struct socket);
			}
		}
		else
		{
			struct list_head *entry;
			cmmd_socket_show_res_t *res = (cmmd_socket_show_res_t*)(res_buf);
			res->rc = CMMD_ERR_OK;
			res->nb_socket = 0;
			res->eof = 1;
			skipcount = cmd->id;
			for (i = 0; i < HASH_SOCKET_SIZE; i++)
			{
				for (entry = list_first(&socket_table[i]); entry != &socket_table[i]; entry = list_next(entry))
				{
					if(skipcount)
					{
						skipcount--;
						continue;
					}
					if ((res->nb_socket + 1) * sizeof(res->sockets[0]) + sizeof(cmmd_socket_show_res_t) > CMM_BUF_SIZE) 
					{	/* no room for next entry */
						res->eof = 0;
						goto end;
					}
					s = container_of(entry, struct socket, list);
					res->sockets[res->nb_socket].sock_id = s->id;
					res->sockets[res->nb_socket].flags = s->flags;
					res->nb_socket++;
				}
			}

end:
			*res_len = res->nb_socket * sizeof(res->sockets[0]) + sizeof(cmmd_socket_show_res_t);
		}

		__pthread_mutex_unlock(&socket_lock);
		break;
	}

	default:
		res_buf[0] = CMMD_ERR_UNKNOWN_COMMAND;
		*res_len = 2;
		break;
	}

	return rc;
}


static void cmmSocketSetUsage(unsigned char family)
{
	if (family == AF_INET)
	cmm_print(DEBUG_STDOUT, 
			"Usage: set socket \n"
			"\n"
			"                                  [open]\n"
			"                                       [sock_id {socket_id}] \n"
			"                                       [type {acp | fpp}]\n"
			"                                       [saddr {IPv4 addr}] \n"
			"                                       [daddr {IPv4 addr}] \n"
			"                                       [sport {port number}] \n"
			"                                       [dport {port number}] \n"
			"                                       [proto {udp | tcp}] \n"
			"                                       [queue {0-19}] \n"
			"                                       [dscp {0-63}]  (Optional parameter, if not set ToS inherited from packet)\n"
			"                                       [fwmark {unsigned int}]  (Optional parameter)\n"
#if defined(LS1043)
			"                                       [mode {connected | unconnected | unconnected-wo-src}] (Optional parameter default connected)\n"
			"                                       [expt_pkt {0-1}]  (Optional parameter, default first packet is not sent by control plane)\n"
#else
			"                                       [mode {connected | unconnected}] (Optional parameter default unconnected)\n"
#endif // LS1043


			"                                  [update]\n"
			"                                       [sock_id {socket_id}] \n"
			"                                       [saddr {IPv4 addr}] \n"
			"                                       [sport {port number}] \n"
			"                                       [queue {0-19}] \n"
			"                                       [dscp {0-63}]  \n"
			"                                       [fwmark {unsigned int}]\n"
#if defined(LS1043)
			"                                       [expt_pkt {0-1}]  (Optional parameter, default first packet is not sent by control plane)\n"
#endif // LS1043



			"\n"
			"                                  [close]\n"
			"                                       [sock_id {socket_id}] \n"
	          );
	else
	cmm_print(DEBUG_STDOUT, 
			"Usage: set socket6 \n"
			"\n"
			"                                  [open]\n"
			"                                       [sock_id {socket_id}] \n"
			"                                       [type {acp | fpp}]\n"
			"                                       [saddr {IPv6 addr}] \n"
			"                                       [daddr {IPv6 addr}] \n"
			"                                       [sport {port number}] \n"
			"                                       [dport {port number}] \n"
			"                                       [proto {udp | tcp}] \n"
			"                                       [queue {0-19}] \n"
			"                                       [dscp {0-63}]  (Optional parameter, if not set Traffic Class inherited from packet)\n"
			"                                       [fwmark {unsigned int}]  (Optional parameter)\n"
#if defined(LS1043)
			"                                       [mode {connected | unconnected | unconnected-wo-src}] (Optional parameter default connected)\n"
			"                                       [expt_pkt {0-1}]  (Optional parameter, default first packet is not sent by control plane)\n"
#else
			"                                       [mode {connected | unconnected}] (Optional parameter default unconnected)\n"
#endif // LS1043


			"                                  [update]\n"
			"                                       [sock_id {socket_id}] \n"
			"                                       [saddr {IPv6 addr}] \n"
			"                                       [sport {port number}] \n"
			"                                       [queue {0-19}] \n"
			"                                       [dscp {0-63}]  \n"
			"                                       [fwmark {unsigned int}]\n"
#if defined(LS1043)
			"                                       [expt_pkt {0-1}]  (Optional parameter, default first packet is not sent by control plane)\n"
#endif // LS1043


			"\n"
			"                                  [close]\n"
			"                                       [sock_id {socket_id}] \n"
	          );
}

static void cmmSocketShowUsage(void)
{
	cmm_print(DEBUG_STDOUT, 
			"Usage: show socket  [sock_id {socket ID} | all]\n"
			"\n"
	          );
}

int cmmSocketSetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle, int family)
{
	int cpt = tabStart;
	unsigned int tmp;
	unsigned long ultmp;
	char * endptr;
	union u_rxbuf rxbuf;
	int rc;

	if (!keywords[cpt])
		goto print_help;

	if (strcasecmp(keywords[cpt], "open") == 0)
	{
		cmmd_socket_open_cmd_t cmd;
		memset(&cmd, 0, sizeof(cmmd_socket_open_cmd_t));
		
		if (!keywords[++cpt])
			goto print_help;

		cmd.family = family;
		cmd.dscp = 0xFFFF;

		if (strcasecmp(keywords[cpt], "sock_id") == 0)
		{
			if (!keywords[++cpt])
				goto print_help;
			
			/*Get an integer from the string*/
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) ||  (tmp > USHRT_MAX))
			{
				cmm_print(DEBUG_CRIT, "ERROR: sock_id must be a number between 0 and %d\n", USHRT_MAX);
				goto  print_help;
			}
			cmd.id = tmp;
		}
		else
			goto keyword_error;

		if(!keywords[++cpt])
			goto print_help;
	
		if(strcasecmp(keywords[cpt], "type") == 0)
		{
			if(!keywords[++cpt])
				goto print_help;
		
			if(strcasecmp(keywords[cpt], "fpp") == 0)
			{
				cmd.type = CMMD_SOCKET_TYPE_LANWAN; 
			}
			else if(strcasecmp(keywords[cpt], "acp") == 0)
			{
				cmd.type = CMMD_SOCKET_TYPE_ACP;
			}
			else
			{
				cmm_print(DEBUG_CRIT, "socket ERROR: type must be either acp or fpp \n");
				goto  print_help;
			}
		}
		else
			goto keyword_error;

		if (!keywords[++cpt])
			goto print_help;
	
		if (strcasecmp(keywords[cpt], "saddr") == 0)
		{
			if (!keywords[++cpt])
				goto print_help;
		
			if (!inet_pton(family, keywords[cpt], &cmd.saddr))
			{
				cmm_print(DEBUG_CRIT,"%s: error reading source address %s\n", __func__, keywords[cpt]);
				goto keyword_error;
			}
		}
		else
			goto keyword_error;
	
		if (!keywords[++cpt])
			goto print_help;
	
		if (strcasecmp(keywords[cpt], "daddr") == 0)
		{
			if (!keywords[++cpt])
				goto print_help;
		
			if (!inet_pton(family, keywords[cpt], cmd.daddr))
			{
				cmm_print(DEBUG_CRIT,"%s: error reading destination address %s\n", __func__,keywords[cpt]);
				goto keyword_error;
			}
		}
		else
			goto keyword_error;

		if (!keywords[++cpt])
			goto print_help;
	
		if (strcasecmp(keywords[cpt], "sport") == 0)
		{
			if(!keywords[++cpt])
				goto print_help;
				
			/*Get an integer from the string*/
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) ||  (tmp > USHRT_MAX))
			{
				cmm_print(DEBUG_CRIT, "ERROR: sport must be a number between 0 and %d\n", USHRT_MAX);
				goto  print_help;
			}
			cmd.sport= htons(tmp);
		}
		else
			goto keyword_error;

		if(!keywords[++cpt])
			goto print_help;
	
		if(strcasecmp(keywords[cpt], "dport") == 0)
		{
			if(!keywords[++cpt])
				goto print_help;
				
			/*Get an integer from the string*/
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) ||  (tmp > USHRT_MAX))
			{
				cmm_print(DEBUG_CRIT, "ERROR: dport must be a number between 0 and %d\n", USHRT_MAX);
				goto  print_help;
			}
			cmd.dport= htons(tmp);
		}
		else
			goto keyword_error;

		if(!keywords[++cpt])
			goto print_help;
	
		if(strcasecmp(keywords[cpt], "proto") == 0)
		{
			if(!keywords[++cpt])
				goto print_help;
	
			if(strcasecmp(keywords[cpt], "udp") == 0)
			{
				cmd.proto= 17; 
			}
			else if(strcasecmp(keywords[cpt], "tcp") == 0)
			{
				cmd.proto = 6;
			}
			else
			{
				cmm_print(DEBUG_CRIT, "socket ERROR: proto must be either udp or tcp\n");
				goto  print_help;
			}
		}
		else
			goto keyword_error;

		if(!keywords[++cpt])
			goto print_help;
	
		if(strcasecmp(keywords[cpt], "queue") == 0)
		{
			if(!keywords[++cpt])
				goto print_help;
			
			/*Get an integer from the string*/
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) ||  (tmp > (FPP_NUM_QUEUES - 1) ))
			{
				cmm_print(DEBUG_CRIT, "ERROR: queue number must be a number between 0 and %d\n", FPP_NUM_QUEUES - 1);
				goto  print_help;
			}
			cmd.queue= tmp;
		}
		else
			goto keyword_error;

		while (keywords[++cpt] != NULL)
		{
			if(strcasecmp(keywords[cpt], "dscp") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
			
				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (tmp > 63))
				{
					cmm_print(DEBUG_CRIT, "ERROR: dscp number must be a number between 0 and 63\n");
					goto  print_help;
				}
				cmd.dscp= tmp;
			}
			else if(strcasecmp(keywords[cpt], "fwmark") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
				
				/*Get an integer from the string*/
				endptr = NULL;
				ultmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (ultmp > UINT_MAX))
				{
					cmm_print(DEBUG_CRIT, "ERROR: fwmark number must be a number between 0 and %u\n", UINT_MAX);
					goto  print_help;
				}
				cmd.fwmark= (u_int32_t) ultmp;
			}
			else if(strcasecmp(keywords[cpt], "mode") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
			
				if(strcasecmp(keywords[cpt], "connected") == 0)
				{
					cmd.mode = SOCKET_CONNECTED; 
				}
				else if(strcasecmp(keywords[cpt], "unconnected") == 0)
				{
					cmd.mode = SOCKET_UNCONNECTED;
				}
#if defined(LS1043)
				else if(strcasecmp(keywords[cpt], "unconnected-wo-src") == 0)
				{
					cmd.mode = SOCKET_UNCONNECTED_WO_SRC;
				}
#endif // LS1043
				else
				{
#if defined(LS1043)
					cmm_print(DEBUG_CRIT, "socket ERROR: mode must be either connected or unconnected or unconnected-wo-src\n");
#else
					cmm_print(DEBUG_CRIT, "socket ERROR: mode must be either connected or unconnected \n");
#endif // LS1043
					goto  print_help;
				}
			}
#if defined(LS1043)
			else if(strcasecmp(keywords[cpt], "expt_pkt") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (tmp > 1))
				{
					cmm_print(DEBUG_CRIT, "ERROR: Value for expt_pkt needs to be 0 or 1\n");
					goto  print_help;
				}
				if(tmp)
					cmd.expt_flag |= 0x1;
			}
#endif //LS1043
			else
				goto keyword_error;
		}

		rc = cmmSendToDaemon(daemon_handle, CMMD_CMD_SOCKET_OPEN, &cmd, sizeof(cmd), rxbuf.rcvBuffer);
		if (rc == 2)
		{
#if defined(LS1043)
			if (rxbuf.result != 0)
				showErrorMsg("CMD_SOCK_OPEN", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
#else
			if (rxbuf.result  != CMMD_ERR_OK)
				cmm_print(DEBUG_CRIT,  "%s: error %d when sending CMD_SOCKET_OPEN\n", __func__, rxbuf.result);
#endif //LS1043
		}
		else if (rc > 0)
			cmm_print(DEBUG_CRIT,  "%s: wrong response size %d received\n", __func__, rc);

	}
	else if(strcasecmp(keywords[cpt], "update") == 0)
	{
		cmmd_socket_update_cmd_t cmd;

		cmd.saddr[0] = 0xffffffff;
		cmd.saddr[1] = 0xffffffff;
		cmd.saddr[2] = 0xffffffff;
		cmd.saddr[3] = 0xffffffff;
		cmd.sport = 0xffff;
		cmd.dscp = 0xffff;
		cmd.queue = 0xff;
		cmd.fwmark = 0xffffffff;
#if defined(LS1043)
		cmd.expt_flag = 0xffff;
#endif //LS1043

		if(!keywords[++cpt])
			goto print_help;

		cmd.family = family;

		if(strcasecmp(keywords[cpt], "sock_id") == 0)
		{
			if(!keywords[++cpt])
				goto print_help;
			
			/*Get an integer from the string*/
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) ||  (tmp > USHRT_MAX))
			{
				cmm_print(DEBUG_CRIT, "ERROR: sock_id must be a number between 0 and %d\n", USHRT_MAX);
				goto  print_help;
			}
			cmd.id = tmp;
		}
		else
			goto keyword_error;
		
	
		while (keywords[++cpt] != NULL)
		{
			if(strcasecmp(keywords[cpt], "saddr") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
			
				if (!inet_pton(family, keywords[cpt], cmd.saddr))
				{
					cmm_print(DEBUG_CRIT,"%s: error reading source address %s\n", __func__, keywords[cpt]);
					goto keyword_error;
				}
			}
		
			else if(strcasecmp(keywords[cpt], "sport") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
					
				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (tmp > USHRT_MAX))
				{
					cmm_print(DEBUG_CRIT, "ERROR: sport must be a number between 0 and %d\n", USHRT_MAX);
					goto  print_help;
				}
				cmd.sport= htons(tmp);
			}
			else if(strcasecmp(keywords[cpt], "queue") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
				
				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (tmp > (FPP_NUM_QUEUES - 1) ))
				{
					cmm_print(DEBUG_CRIT, "ERROR: queue number must be a number between 0 and %d\n", FPP_NUM_QUEUES - 1);
					goto  print_help;
				}
				cmd.queue= tmp;
			}
			else if(strcasecmp(keywords[cpt], "dscp") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
				
				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (tmp > 63))
				{
					cmm_print(DEBUG_CRIT, "ERROR: dscp number must be a number between 0 and 63\n");
					goto  print_help;
				}
				cmd.dscp= tmp;
			}
			else if(strcasecmp(keywords[cpt], "fwmark") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;
				
				/*Get an integer from the string*/
				endptr = NULL;
				ultmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (ultmp > UINT_MAX))
				{
					cmm_print(DEBUG_CRIT, "ERROR: fwmark number must be a number between 0 and %u\n", UINT_MAX);
					goto  print_help;
				}
				cmd.fwmark= (u_int32_t) ultmp;
			}
#if defined(LS1043)
			else if(strcasecmp(keywords[cpt], "expt_pkt") == 0)
			{
				if(!keywords[++cpt])
					goto print_help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) ||  (tmp > 1))
				{
					cmm_print(DEBUG_CRIT, "ERROR: Value for expt_pkt needs to be 0 or 1\n");
					goto  print_help;
				}
				if(tmp)
					cmd.expt_flag |= 0x1;
			}
#endif //LS1043
			else
				goto keyword_error;

		}
		rc = cmmSendToDaemon(daemon_handle, CMMD_CMD_SOCKET_UPDATE, &cmd, sizeof(cmd), rxbuf.rcvBuffer);
		if (rc == 2)
		{
#if defined (LS1043)
			if (rxbuf.result != 0)
				showErrorMsg("CMD_SOCK_UPDATE", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
#else
			if (rxbuf.result != CMMD_ERR_OK)
				cmm_print(DEBUG_CRIT,  "%s: error %d when sending CMD_SOCKET_UPDATE\n", __func__, rxbuf.result);
#endif // LS1043
		}
		else if (rc > 0)
			cmm_print(DEBUG_CRIT,  "%s: wrong response size %d received\n", __func__, rc);
	}

	
	else if(strcasecmp(keywords[cpt], "close") == 0)
	{
		cmmd_socket_close_cmd_t cmd;
		
		if(!keywords[++cpt])
			goto print_help;
		
		if(strcasecmp(keywords[cpt], "sock_id") == 0)
		{
			if(!keywords[++cpt])
				goto print_help;
			
			/*Get an integer from the string*/
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) ||  (tmp > USHRT_MAX))
			{
				cmm_print(DEBUG_CRIT, "ERROR: sock_id must be a number between 0 and %d\n", USHRT_MAX);
				goto  print_help;
			}
			cmd.id = tmp;
		}
		else
			goto keyword_error;
		
		rc = cmmSendToDaemon(daemon_handle, CMMD_CMD_SOCKET_CLOSE, &cmd, sizeof(cmd), rxbuf.rcvBuffer);
		if (rc == 2)
		{
#if defined (LS1043)
			if (rxbuf.result != 0)
				showErrorMsg("CMD_SOCK_CLOSE", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
#else
			if (rxbuf.result != CMMD_ERR_OK)
				cmm_print(DEBUG_CRIT,  "%s: error %d when sending CMD_SOCKET_CLOSE\n", __func__, rxbuf.result);
#endif //LS1043
		}
		else if (rc > 0)
			cmm_print(DEBUG_CRIT,  "%s: wrong response size %d received\n", __func__, rc);
	}
	else
		goto keyword_error;
	
	return 0;



keyword_error:
	cmm_print(DEBUG_STDOUT,"ERR: unknown keyword %s\n", keywords[cpt]);

print_help:
	cmmSocketSetUsage(family);

	return -1;
}

int cmmSocketShowProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle)
{
	union u_rxbuf rxbuf;
	
	int cpt = tabStart;
	cmmd_socket_show_cmd_t cmd;
	struct socket *s;
	int rc;
	unsigned int tmp;
	char * endptr;

	if (!keywords[cpt])
		goto print_help;

	if (strcasecmp(keywords[cpt], "sock_id") == 0)
	{
		if (!keywords[++cpt])
			goto print_help;
		
		/*Get an integer from the string*/
		endptr = NULL;
		tmp = strtoul(keywords[cpt], &endptr, 0);

		if ((keywords[cpt] == endptr) ||  (tmp > USHRT_MAX))
		{
			cmm_print(DEBUG_CRIT, "ERROR: sock_id must be a number between 0 and %d\n", USHRT_MAX);
			goto print_help;
		}

		cmd.id = tmp;
		cmd.dump_all = 0;
	}
	else if(strcasecmp(keywords[cpt], "all") == 0)
	{
		if(keywords[++cpt])
			goto print_help;
			
		cmd.id = 0;
		cmd.dump_all = 1;	
	}
	else
		goto keyword_error;

	rc = cmmSendToDaemon(daemon_handle, CMMD_CMD_SOCKET_SHOW, &cmd, sizeof(cmd), rxbuf.rcvBuffer);
	if (rc >= 2)
	{
		if (rxbuf.result != CMMD_ERR_OK)
		{
			cmm_print(DEBUG_CRIT,  "%s: error %d when sending CMD_SOCKET_SHOW\n", __func__, rxbuf.result);
			return -1;
		}
	}
	else
	{
		if (rc > 0)
			cmm_print(DEBUG_CRIT,  "%s: wrong response size %d received\n", __func__, rc);
		return -1;
	}

	if (!cmd.dump_all)
	{

		char saddr_buf[INET6_ADDRSTRLEN], daddr_buf[INET6_ADDRSTRLEN];
		s = (struct socket *)(rxbuf.rcvBuffer);

		cmm_print(DEBUG_STDOUT,	"socket id   : %d\n"
									"saddr       : %s\n"
									"daddr       : %s\n"
									"sport       : %d\n"
									"dport       : %d\n"
									"proto       : %d\n"
									"queue       : %d\n"
									"dscp        : %d\n"
									"flags       : %d\n",
						s->id,
						inet_ntop(s->family, s->saddr, saddr_buf, sizeof(saddr_buf)),
						inet_ntop(s->family, s->daddr, daddr_buf, sizeof(daddr_buf)),
						ntohs(s->sport),
						ntohs(s->dport),
						s->proto,
						s->queue,
						s->dscp,
						s->flags);
			return 0;
	}
	else
	{
		cmmd_socket_show_res_t *res = (cmmd_socket_show_res_t*)(rxbuf.rcvBuffer);
		int i, skipcount = 0;
		while(1)
		{
			skipcount += res->nb_socket;
			for(i = 0; i < res->nb_socket ; i++)
				cmm_print(DEBUG_STDOUT, "socket id : %d, flags: %d\n", res->sockets[i].sock_id, res->sockets[i].flags);	
			if(res->eof)
				break;
			cmd.id = skipcount;
			rc = cmmSendToDaemon(daemon_handle, CMMD_CMD_SOCKET_SHOW, &cmd, sizeof(cmd), rxbuf.rcvBuffer);
			if(rc < 0)
				return -1;
			res = (cmmd_socket_show_res_t*)(rxbuf.rcvBuffer);
		}
		cmm_print(DEBUG_STDOUT, "%d socket(s) programmed\n", skipcount);
		return 0;
	}
	
	keyword_error:
		cmm_print(DEBUG_STDOUT,"ERR: unknown keyword %s\n", keywords[cpt]);

	print_help:
		cmmSocketShowUsage();
		
	return 0;
}

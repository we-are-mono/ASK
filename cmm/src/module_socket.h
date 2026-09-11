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

#ifndef __MODULE_SOCKET_H
#define __MODULE_SOCKET_H

#include <sys/types.h>
#include "list.h"
#include "forward_engine.h"

#define HASH_SOCKET_SIZE	32
#define HASH_SOCKET(id)		((id) & (HASH_SOCKET_SIZE - 1))


#if defined(LS1043)
#define SOCKET_UNCONNECTED	1
#define SOCKET_CONNECTED		0
#define SOCKET_UNCONNECTED_WO_SRC  2
#endif //LS1043

#define SOCK_ID_PRIVATE_START	1
#define SOCK_ID_PRIVATE_END	255

#if (SOCK_ID_PRIVATE_START > SOCK_ID_PRIVATE_END)
         #error SOCK_ID_PRIVATE_START cannot be greater than SOCK_ID_PRIVATE_END
#endif

#if (SOCK_ID_PRIVATE_START == 0)
	#error SOCK_ID_PRIVATE_START cannot be zero
#endif

#if (SOCK_ID_PRIVATE_END > 65535)
	#error SOCK_ID_PRIVATE_END cannot be greater than 65535
#endif

struct socket {
	struct list_head list;
	u_int8_t family;
	u_int16_t id;
	u_int8_t type;
	u_int8_t mode;
	u_int32_t saddr[4];
	u_int32_t daddr[4];
	u_int16_t sport;
	u_int16_t dport;
	u_int8_t proto;
	u_int8_t queue;
	u_int16_t dscp;
	struct ct_route rt;
	int flags;
	unsigned int fwmark;
#if defined(LS1043)
	u_int16_t       expt_flag;
	u_int16_t       rsvd;
#endif //(LS1043)
};

extern struct list_head socket_table[HASH_SOCKET_SIZE];
extern pthread_mutex_t socket_lock;

int socket_daemon(FCI_CLIENT *fci_handle, int fc, u_int8_t *cmd_buf, u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len);
int cmmSocketSetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle, int family);
int cmmSocketShowProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
int __socket_open(FCI_CLIENT *fci_handle, struct socket *s);
void socket_remove(struct socket *s);
void __cmmSocketUpdateWithRoute(FCI_CLIENT *fci_handle, struct RtEntry *route);
int __socket_close(FCI_CLIENT *fci_handle, struct socket *s);
void __socket_add(struct socket * s);

#endif

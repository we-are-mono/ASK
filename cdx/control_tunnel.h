/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_TUNNEL_H_
#define _CONTROL_TUNNEL_H_

#include "cdx_common.h"
#include "control_ipv4.h"

#define TNL_MAX_HEADER		(40 + 14 + 4) /* Max header size matches that of a gre tunnel */
#define TUNNEL_HASH_MASK	(NUM_TUNNEL_ENTRIES - 1)


#define TNL_STATE_CREATED 			0x01
#define TNL_STATE_ENABLED			0x02
#define TNL_STATE_REMOTE_ANY			0x10




enum TNL_MODE {
	TNL_MODE_6O4 = 1,
	TNL_MODE_4O6,
	TNL_MODE_GRE_IPV6 = 4,
};


#define TNL_GRE_PROTOCOL	0x6558		// Transparent Ethernet Bridging
#define TNL_GRE_HDRSIZE		4
#define TNL_GRE_VERSION		0x0
#define TNL_GRE_FLAGS		(0x0000 | TNL_GRE_VERSION)	// no flags are supported
#define TNL_GRE_HEADER		((TNL_GRE_FLAGS << 16) | TNL_GRE_PROTOCOL)
/* dscp propagation */
#define INHERIT_TC 0x1
#define DSCP_COPY  0x2


/***********************************
* Tunnel API Command and Entry strutures
*
************************************/

typedef struct _tTNLCommand_create {
	U8	name[16];
	U32 	local[4];
	U32	remote[4];
	U8	output_device[16];
	U8	mode;
	/* options */
	U8 	secure;
	U8	elim;
	U8	hlim;
	U32	fl;
	U16	frag_off;
	U16	enabled;
	U32	route_id;
	U16	mtu;
	U8	flags;
	U8	pad;
}TNLCommand_create , *PTNLCommand_create;

typedef struct _tTNLCommand_delete {
	U8	name[16];
}TNLCommand_delete, *PTNLCommand_delete;



typedef struct _tTNLCommand_query{
	U16     result;
	U16     unused;
	U8      name[16];
	U32     local[4];
	U32     remote[4];
	U8      mode;
	U8      secure;
	U8			elim;
	U8			hlim;
	U32     fl;
	U16     frag_off;
	U16     enabled;
	U32			route_id;
	U16			mtu;
	U16			pad;
}TNLCommand_query , *PTNLCommand_query;




// Structure used by tunnel entries in sw

typedef struct _tTnlEntry{
	itf_t itf;
	U8       tnl_name[16];

	union {
	  U8	header[TNL_MAX_HEADER];
	  ipv4_hdr_t header_v4;
	};
	U8	header_size;
	U8	mode;
	U8	proto;
	U8	secure;
	U8	state;
	U8	hlim;
	U8	elim;
	U8	output_proto;
	U32 	local[4];
	U32	remote[4];
	U32 fl;
	U16 frag_off;
	U16 tnl_mtu;
	U8 flags;
	U8 pad;

	U32 route_id;
	PRouteEntry pRtEntry;
	struct slist_entry  list;
}TnlEntry, *PTnlEntry;

int tunnel_init(void);
void tunnel_exit(void);
void tnl_update(PTnlEntry pTunnelEntry);

U16 Tnl_Get_Next_Hash_Entry(PTNLCommand_query pTnlCmd, int reset_action);

int dpa_add_tunnel_if(itf_t *itf, itf_t *phys_itf, PTnlEntry pTunnelEntry);
int dpa_update_tunnel_if(itf_t *itf,  itf_t *phys_itf, PTnlEntry pTunnelEntry);

/* Hash a fixed-width tunnel-name field. `maxlen` is the size of the
 * underlying buffer (always 16 in current callers); the loop stops at
 * the first NUL or once `maxlen` bytes have been consumed, whichever
 * comes first. The earlier "while (*tnlname)" form trusted the input
 * to be NUL-terminated, which it isn't when the name comes straight
 * from a malformed FCI command — KASAN caught the resulting stack-OOB
 * read in tnl_delete_handle (ISSUES.md A6).
 */
static __inline U32 HASH_TUNNEL_NAME(const U8 *tnlname, size_t maxlen)
{
	U32 hash = 0;
	size_t i;
	for (i = 0; i < maxlen && tnlname[i]; i++)
	{
		hash <<= 3;
		hash ^= tnlname[i];
	}
	return (hash & TUNNEL_HASH_MASK);
}

#endif /* _CONTROL_TUNNEL_H_ */

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

enum TNL_MODE {
	TNL_MODE_6O4 = 1,
	TNL_MODE_4O6,
	TNL_MODE_GRE_IPV6 = 4,
};

/* dscp propagation */
#define INHERIT_TC 0x1
#define DSCP_COPY  0x2

/* Build the outer header the hardware inserts for a 6o4 or 4o6 tunnel into
 * `header`, which holds at least 40 bytes, leaving zero what the microcode
 * fills per packet: the IPv4 length, identification and checksum, the IPv6
 * payload length. `local` and `remote` are the endpoints in network order,
 * one word for IPv4 and four for IPv6; `fl` is the IPv4 TOS or the IPv6
 * traffic class and flow label as one network-order word; `frag_off` is the
 * IPv4 flags and fragment offset word, network order, which carries DF.
 * Returns the header size, or zero for a mode this does not build. */
U8 tnl_build_header(U8 mode, const U32 *local, const U32 *remote, U32 fl,
		    U8 hlim, U16 frag_off, U8 *header);

#endif /* _CONTROL_TUNNEL_H_ */

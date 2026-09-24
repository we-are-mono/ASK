/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#include "portdefs.h"
#include "cdx.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_tunnel.h"

U8 tnl_build_header(U8 mode, const U32 *local, const U32 *remote, U32 fl,
		    U8 hlim, U16 frag_off, U8 *header)
{
	ipv6_hdr_t ip6_hdr;
	ipv4_hdr_t ip4_hdr;

	switch (mode) {
	case TNL_MODE_6O4:
		/* MAC|IPv4|IPv6: the IPv4 part is pre-built. */
		memset(&ip4_hdr, 0, sizeof(ip4_hdr));
		ip4_hdr.SourceAddress = local[0];
		ip4_hdr.DestinationAddress = remote[0];
		ip4_hdr.Version_IHL = 0x45;
		ip4_hdr.Protocol = IPPROTOCOL_IPV6;
		ip4_hdr.TypeOfService = fl & 0xFF;
		ip4_hdr.TotalLength = 0; /* computed for each packet */
		ip4_hdr.TTL = hlim;
		ip4_hdr.Identification = 0;
		ip4_hdr.HeaderChksum = 0; /* computed for each packet */
		ip4_hdr.Flags_FragmentOffset = frag_off;
		memcpy(header, &ip4_hdr, sizeof(ip4_hdr));
		return sizeof(ip4_hdr);
	case TNL_MODE_4O6:
		/* MAC|IPv6|IPv4: the IPv6 part is pre-built. */
		memset(&ip6_hdr, 0, sizeof(ip6_hdr));
		memcpy(ip6_hdr.DestinationAddress, remote, IPV6_ADDRESS_LENGTH);
		memcpy(ip6_hdr.SourceAddress, local, IPV6_ADDRESS_LENGTH);
		IPV6_SET_VER_TC_FL(&ip6_hdr, fl);
		ip6_hdr.HopLimit = hlim;
		ip6_hdr.TotalLength = 0; /* computed for each packet */
		ip6_hdr.NextHeader = IPPROTOCOL_IPIP;
		memcpy(header, &ip6_hdr, sizeof(ip6_hdr));
		return sizeof(ip6_hdr);
	default:
		return 0;
	}
}

/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _FE_H_
#define _FE_H_

#include "list.h"
#include "cdx_hal.h"

/* The spread of HASH_CT()/HASH_CT6() */
#define ROUTE_TABLE_HASH_BITS	15
#define NUM_CT_ENTRIES		(1 << (ROUTE_TABLE_HASH_BITS))
#define	CT_TABLE_HASH_MASK	(NUM_CT_ENTRIES - 1)

/* Nb buckets in the SA cache */
#define NUM_SA_ENTRIES 	16

/* Error codes */
enum return_code {
	NO_ERR = 0,
	ERR_UNKNOWN_INTERFACE = 5,
	ERR_CREATION_FAILED = 7,

	ERR_QM_INGRESS_POLICER_HANDLE_NULL = 507,
	ERR_QM_INGRESS_SET_PROFILE_FAILED = 508,

	ERR_SA_UNKNOWN = 906,
};




/******************************
* Forward Engine Common Definitions
*
******************************/

#define IPPROTOCOL_ICMP 	1
#define IPPROTOCOL_IGMP 	2
#define IPPROTOCOL_TCP 		6
#define IPPROTOCOL_UDP		17
#define IPPROTOCOL_IPIP		4
#define IPPROTOCOL_IPV6		41
#define IPPROTOCOL_ESP 		 50            /* Encapsulation Security Payload protocol */
#define IPPROTOCOL_AH 		 51             /* Authentication Header protocol       */
#define IPPROTOCOL_ICMPV6 	58

// Ethernet definitions

#define ETHER_ADDR_LEN				6
#define ETHER_TYPE_LEN			2

#define ETH_HEADER_SIZE			14
#define ETH_VLAN_HEADER_SIZE		18	// DST MAC + SRC MAC + TPID + TCI + Packet/Length
#define ETH_MAX_HEADER_SIZE		ETH_VLAN_HEADER_SIZE

/* ethernet packet types */
#define ETHERTYPE_IPV4			0x0800	// 	IP protocol version 4
#define ETHERTYPE_ARP			0x0806	//  ARP
#define ETHERTYPE_VLAN			0x8100	// 	VLAN
#define ETHERTYPE_IPV6			0x86dd	//	IP protocol version 6
#define ETHERTYPE_PPPOE			0x8864  //  PPPoE Session packet
#define ETHERTYPE_PPPOED		0x8863  //  PPPoE Discovery packet
#define ETHERTYPE_PAE                   0x888E   /* Port Access Entity (IEEE 802.1X) */
#define ETHERTYPE_VLAN_STAG		0x88a8	// 	VLAN S-TAG
#define ETHERTYPE_UNKNOWN		0xFFFF

/* Packet type in big endianness	*/
#define ETHERTYPE_IPV4_END		htons(ETHERTYPE_IPV4)
#define ETHERTYPE_ARP_END		htons(ETHERTYPE_ARP)
#define ETHERTYPE_VLAN_END		htons(ETHERTYPE_VLAN)
#define ETHERTYPE_IPV6_END		htons(ETHERTYPE_IPV6)
#define ETHERTYPE_PPPOE_END		htons(ETHERTYPE_PPPOE)
#define ETHERTYPE_PPPOED_END		htons(ETHERTYPE_PPPOED)
#define ETHERTYPE_PAE_END               htons(ETHERTYPE_PAE)

/******************************
* Macros
*
******************************/

#define IS_IPV4(pEntry) (pEntry->fftype == FFTYPE_IPV4)
#define IS_IPV4_FLOW(pEntry) ((pEntry->fftype & FFTYPE_IPV4) != 0)
#define IS_IPV6(pEntry) (pEntry->fftype == FFTYPE_IPV6)
#define IS_IPV6_FLOW(pEntry) ((pEntry->fftype & FFTYPE_IPV6) != 0)

static __inline void COPY_MACADDR(void *ptomacaddr, void *pfrommacaddr)
{
	((U16 *)ptomacaddr)[0] = ((U16 *)pfrommacaddr)[0];
	((U16 *)ptomacaddr)[1] = ((U16 *)pfrommacaddr)[1];
	((U16 *)ptomacaddr)[2] = ((U16 *)pfrommacaddr)[2];
}

static __inline int TESTEQ_MACADDR(void *pmacaddr1, void *pmacaddr2)
{
	return ((U16 *)pmacaddr1)[0] == ((U16 *)pmacaddr2)[0] &&
					((U16 *)pmacaddr1)[1] == ((U16 *)pmacaddr2)[1] &&
					((U16 *)pmacaddr1)[2] == ((U16 *)pmacaddr2)[2];
}

#endif /* _FE_H_ */

/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_IPV6_H_
#define _CONTROL_IPV6_H_


#include"cdx_common.h"

#define IPV6_HDR_SIZE		sizeof(ipv6_hdr_t)

/* IPv6 Next Header values */
#define IPV6_GRE		47

int ipv6_cmp(void *src, void *dst);
#define IPV6_CMP(addr1, addr2) ipv6_cmp(addr1, addr2)

int ipv6_init(void);
void ipv6_exit(void);

int IPv6_delete_CTpair(PCtEntry pCtEntry);
int IPv6_Get_Next_Hash_CTEntry(PCtExCommandIPv6 pV6CtCmd, int reset_action);
PCtEntry IPv6_find_ctentry(U32 *saddr, U32 *daddr, U16 sport, U16 dport, U8 proto);

int IPv6_handle_RESET(void);


static inline u32 is_ipv6_addr_any(u32 *addr)
{
       return ((addr[0] | addr[1] | addr[2] | addr[3]) == 0);
}

#ifdef ENDIAN_LITTLE

#define IPV6_GET_VER_TC_FL(phdr) READ_UNALIGNED_INT((phdr)->Ver_TC_FL)

#define IPV6_SET_VER_TC_FL(phdr, ver_tc_fl) do { \
		u32 temp = ver_tc_fl | htonl(0x60000000); \
		WRITE_UNALIGNED_INT((phdr)->Ver_TC_FL, temp); \
		} while (0)

#endif


#endif /* _CONTROL_IPV6_H_ */

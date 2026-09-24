/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_IPV4_H_
#define _CONTROL_IPV4_H_

#include"cdx_common.h"
#include"layer2.h"


#define SA_MAX_OP		2	// maximum of stackable SA (ESP+AH)



union ctentry_qosmark {
	U32 markval;

	struct {
		U32 queue : 4;	
		U32 reserved_1: 1;
		U32 vlan_pbits : 3;
		U32 dscp_mark_flag : 1;
		U32 dscp_mark_value : 6;
		U32 vlan_pbits_valid : 1;
		U32 iqid : 4;		/* ingres Qos id, qualify with valid bit*/ 
		U32 reserved_2: 3; 
		U32 iqid_valid : 1;	/* if set, iqid is valid */
		U32 chnl_id : 4;	/* egress Qos channel id */
		U32 reserved_3: 3; 
		U32 ds_info_valid: 1; 	/* bit indicates qosconmark specified values for DS direction */
	};
};

typedef struct _tCtEntry {
	struct slist_entry list;
	U16	Sport;
	U16	Dport;
	U8	proto;
	U8	inPhyPortNum;
	U16	hash;

	union {
		struct {
			U32 Saddr_v4;
			U32 Daddr_v4;
			U32 unused1;
			U32 unused2;
			U32 twin_Saddr;
			U32 twin_Daddr;
			U16 twin_Sport;
			U16 twin_Dport;
			U32 unused3;
		};

		struct {
			U32 Saddr_v6[4];
			U32 Daddr_v6[4];
		};
	};

	/* End of fields used by hardware */

	PRouteEntry pRtEntry;
	union ctentry_qosmark qosmark;
	U16 status;

	PRouteEntry tnl_route;
	U16 hSAEntry[SA_MAX_OP];

	U8 fftype;

	struct _tCtEntry *twin;
	struct hw_ct *ct;       /** pointer to the hardware conntrack */

}CtEntry, *PCtEntry;

/* Conntrack status */
#define CONNTRACK_4O6			0x4000
#define CONNTRACK_SEC			0x1000
#define CONNTRACK_SEC_noSA     		0x800
#define CONNTRACK_TCP_FIN		0x400
#define CONNTRACK_FF_DISABLED		0x100
#define CONNTRACK_DEL_FAILED	0x40
#define CONNTRACK_NAT			0x20
#define CONNTRACK_SNAT			CONNTRACK_NAT
#define CONNTRACK_DNAT			0x10
//#define CONNTRACK_IPv6			0x08
#define CONNTRACK_ORIG			0x04
#define CONNTRACK_HWSET			0x02
#define CONNTRACK_IPv6_PORTNAT		0x01

// Fast-forward "type"

#define	FFTYPE_IPV4	0x01
#define FFTYPE_IPV6	0x02

#define CT_TWIN(pentry)		(((PCtEntry)(pentry))->twin)

/* Layer 2 encapsulation supplied by the caller instead of derived from a
 * registered VLAN interface. The Linux flowtable owner has no such interface:
 * the kernel hands it a physical redirect plus a tag stack, so the tags come
 * from the flow. Innermost first, matching dpa_l2hdr_info, which is the
 * reverse of the order the wire and Netfilter use. Ingress tags are validated
 * and stripped; egress tags are inserted. */
struct cdx_l2_encap {
	U32 num_ingress;
	U32 num_egress;
	struct vlan_header ingress[DPA_CLS_HM_MAX_VLANs];
	struct vlan_header egress[DPA_CLS_HM_MAX_VLANs];
	/* A PPPoE session on either side, the same way. It sits inside every
	 * VLAN tag on the wire, which is the order the opcodes are already
	 * emitted in and needs nothing said here. The ingress side carries no
	 * identity because the strip validates none: STRIP_PPPoE_HDR takes a
	 * statistics pointer and nothing else, so an ingress session is one
	 * bit. The egress side carries both, because the insert writes them.
	 * session_id is in host order, which is what the opcode word is built
	 * from before it is converted whole. */
	U8 ingress_pppoe;
	U8 egress_pppoe;
	U16 egress_session_id;
	U8 egress_session_mac[ETHER_ADDR_LEN];
	/* Where each side counts, as an index into the firmware's statistics
	 * area. The legacy owner looks these up from a registered interface;
	 * this one holds its own record and names it here. Zero means the
	 * session has no record -- never a record at index zero, which belongs
	 * to someone else and is exactly the aliasing this field replaces. */
	U8 ingress_stats_index;
	U8 egress_stats_index;
	/* The same for each tag, indexed like ingress[] and egress[] -- innermost
	 * first -- in the plain pool's units. A VLAN device's record counts what
	 * the strip removed into its receive half and what the insert added into
	 * its transmit half. Zero is again no record. The opcodes take all of a
	 * stack's records or none: their list form has no way to skip one tag,
	 * and naming index zero for it would count into someone else's. */
	U8 ingress_vlan_stats_index[DPA_CLS_HM_MAX_VLANs];
	U8 egress_vlan_stats_index[DPA_CLS_HM_MAX_VLANs];
	/* An IP-in-IP tunnel on either side, outside every L2 header. The
	 * egress side carries the outer header the insert writes, built as
	 * the legacy tunnel interface builds its own, with the per-packet
	 * fields left zero; the ingress side carries only what the strip
	 * needs, which is the mode and the header size. Each names its
	 * record in the plain statistics pool, or zero for none, exactly as
	 * a tag does. */
	struct cdx_tunnel_encap {
		U8 present;
		U8 mode;		/* TNL_MODE_6O4 or TNL_MODE_4O6 */
		U8 header_size;
		U8 flags;		/* INHERIT_TC, DSCP_COPY */
		U8 stats_index;
		U8 header[40];
	} ingress_tunnel, egress_tunnel;
};

/* Insert a direction's classifier entry. A NULL encap derives the L2 framing
 * from the registered interfaces alone; a flow that carries tags, a PPPoE
 * session or a tunnel names them in encap. */
int insert_entry_in_classif_table_encap(PCtEntry entry, const struct cdx_l2_encap *encap);
int delete_entry_from_classif_table(PCtEntry entry);

void display_ctentry(PCtEntry entry);
void display_route_entry(PRouteEntry entry);
int add_incoming_iface_info(PCtEntry entry);



#define CRCPOLY_BE 0x04c11db7
static inline U32 cdx_crc32_be(U8 *data)
{
	int i, j;
	U32 crc = 0xffffffff;

	for (i = 0; i < 4; i++) {
		crc ^= *data++ << 24;

		for (j = 0; j < 8; j++)
			crc = (crc << 1) ^ ((crc & 0x80000000) ? CRCPOLY_BE : 0);
	}

	return crc;
}

static __inline U32 HASH_CT(U32 Saddr, U32 Daddr, U32 Sport, U32 Dport, U16 Proto)
{
	U32 sum;

	sum = Saddr ^ htonl(ntohs(Sport));
	sum = cdx_crc32_be((u8 *)&sum);

	sum += ntohl(Daddr);
	sum += Proto;
	sum += ntohs(Dport);

	return sum & CT_TABLE_HASH_MASK;
}

static __inline U32 HASH_CT6(U32 *Saddr, U32 *Daddr, U32 Sport, U32 Dport, U16 Proto)
{
	int i;
	U32 sum;

	sum = 0;
	for (i = 0; i < 4; i++)
		sum += ntohl(READ_UNALIGNED_INT(Saddr[i]));
	sum = htonl(sum) ^ htonl(ntohs(Sport));
	sum = cdx_crc32_be((u8 *)&sum);

	for (i = 0; i < 4; i++)
		sum += ntohl(READ_UNALIGNED_INT(Daddr[i]));
	sum += Proto;
	sum += ntohs(Dport);

	return sum & CT_TABLE_HASH_MASK;
}
#endif /* _CONTROL_IPV4_H_ */

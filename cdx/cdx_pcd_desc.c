// SPDX-License-Identifier: GPL-2.0+
/*
 * The ASK FMan PCD, as data.
 *
 * Every value here was previously produced by compiling cdx_pcd.xml with fmc.
 * The table is a transcription of that compiler's output, not a reinterpretation
 * of it: docs/in-kernel-pcd.md records how to regenerate the reference model and
 * diff against it.
 *
 * Two orderings are load bearing and must not be tidied:
 *
 *   - cdx_pcd_groups[] is indexed by CC root group id. A scheme dispatches into
 *     its own index, and cdx_sp.xml reaches the PPPoE relay table by a hardcoded
 *     offset from the CC base.
 *   - cdx_pcd_units[] is indexed by the unit ids in cdx_pcd_group.units[].
 *
 * Both reproduce what fmc derived (group order is the reverse of the policy
 * dist_order; unit order is protocol name order). They are spelled out rather
 * than recomputed so the coupling is greppable.
 */
#include <linux/errno.h>
#include "cdx_pcd.h"

const e_NetHeaderType cdx_pcd_units[CDX_PCD_NUM_UNITS] = {
	[CDX_PCD_UNIT_ETH]	 = HEADER_TYPE_ETH,
	[CDX_PCD_UNIT_IPSEC_ESP] = HEADER_TYPE_IPSEC_ESP,
	[CDX_PCD_UNIT_IPV4]	 = HEADER_TYPE_IPv4,
	[CDX_PCD_UNIT_IPV6]	 = HEADER_TYPE_IPv6,
	[CDX_PCD_UNIT_PPPOE]	 = HEADER_TYPE_PPPoE,
	[CDX_PCD_UNIT_TCP]	 = HEADER_TYPE_TCP,
	[CDX_PCD_UNIT_UDP]	 = HEADER_TYPE_UDP,
};

/* An extract of a whole header field, at the outermost or innermost header. */
#define EXTRACT(_hdr, _idx, _field) {			\
	.hdr = HEADER_TYPE_##_hdr,			\
	.hdr_index = e_FM_PCD_HDR_INDEX_##_idx,		\
	.field = NET_HEADER_FIELD_##_field,		\
}

const struct cdx_pcd_group cdx_pcd_groups[CDX_PCD_NUM_GROUPS] = {
	[0] = {
		.table_name = "cdx_ethernet_cc",
		.key_size = 15, .hash_res_mask = 0x00ff,
		.table_type = ETHERNET_TABLE,
		.scheme_name = "cdx_ethernet_dist",
		/* The only group with a real FQ range: the L2 bridge spreads
		 * across 128 queues, every other group lands on one. */
		.base_fqid = 0x10000, .num_fqids = 128,
		.dist_type = ETHERNET_DIST,
		.num_units = 1, .units = { CDX_PCD_UNIT_ETH },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(ETH, NONE, ETH_DA),
			EXTRACT(ETH, NONE, ETH_SA),
			EXTRACT(ETH, NONE, ETH_TYPE),
		},
	},
	[1] = {
		.table_name = "cdx_pppoe_cc",
		.key_size = 11, .hash_res_mask = 0x000f,
		.table_type = PPPOE_RELAY_TABLE,
		.scheme_name = "cdx_pppoe_dist",
		.base_fqid = 0x1080, .num_fqids = 1,
		.dist_type = PPPOE_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_ETH, CDX_PCD_UNIT_PPPOE },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(ETH, NONE, ETH_SA),
			EXTRACT(ETH, NONE, ETH_TYPE),
			EXTRACT(PPPoE, NONE, PPPoE_SID),
		},
	},
	[2] = {
		.table_name = "cdx_tuple3udp6_cc",
		.key_size = 20, .hash_res_mask = 0x00ff,
		.table_type = IPV6_3TUPLE_UDP_TABLE,
		.scheme_name = "cdx_tup3udp6_dist",
		.base_fqid = 0x10b0, .num_fqids = 1,
		.dist_type = IPV6_3TUPLE_UDP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPV6, CDX_PCD_UNIT_UDP },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(IPv6, LAST, IPv6_DST_IP),
			EXTRACT(IPv6, LAST, IPv6_NEXT_HDR),
			EXTRACT(UDP, NONE, UDP_PORT_DST),
		},
	},
	[3] = {
		.table_name = "cdx_tuple3udp4_cc",
		.key_size = 8, .hash_res_mask = 0x00ff,
		.table_type = IPV4_3TUPLE_UDP_TABLE,
		.scheme_name = "cdx_tup3udp4_dist",
		.base_fqid = 0x1090, .num_fqids = 1,
		.dist_type = IPV4_3TUPLE_UDP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPV4, CDX_PCD_UNIT_UDP },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(IPv4, LAST, IPv4_DST_IP),
			EXTRACT(IPv4, LAST, IPv4_PROTO),
			EXTRACT(UDP, NONE, UDP_PORT_DST),
		},
	},
	[4] = {
		.table_name = "cdx_multicast6_cc",
		.key_size = 34, .hash_res_mask = 0x00ff,
		.table_type = IPV6_MULTICAST_TABLE,
		.scheme_name = "cdx_ipv6multicast_dist",
		.base_fqid = 0x1050, .num_fqids = 1,
		.dist_type = IPV6_MULTICAST_DIST,
		.num_units = 1, .units = { CDX_PCD_UNIT_IPV6 },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(IPv6, NONE, IPv6_SRC_IP),
			EXTRACT(IPv6, NONE, IPv6_DST_IP),
			EXTRACT(IPv6, NONE, IPv6_NEXT_HDR),
		},
	},
	[5] = {
		.table_name = "cdx_multicast4_cc",
		.key_size = 10, .hash_res_mask = 0x00ff,
		.table_type = IPV4_MULTICAST_TABLE,
		.scheme_name = "cdx_ipv4multicast_dist",
		.base_fqid = 0x1040, .num_fqids = 1,
		.dist_type = IPV4_MULTICAST_DIST,
		.num_units = 1, .units = { CDX_PCD_UNIT_IPV4 },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(IPv4, NONE, IPv4_SRC_IP),
			EXTRACT(IPv4, NONE, IPv4_DST_IP),
			EXTRACT(IPv4, NONE, IPv4_PROTO),
		},
	},
	[6] = {
		.table_name = "cdx_tcp6_cc",
		.key_size = 38, .hash_res_mask = 0x7fff,
		.table_type = IPV6_TCP_TABLE,
		.scheme_name = "cdx_tcp6_dist",
		.base_fqid = 0x1030, .num_fqids = 1,
		.dist_type = IPV6_TCP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPV6, CDX_PCD_UNIT_TCP },
		.num_extracts = 5,
		.extracts = {
			EXTRACT(IPv6, LAST, IPv6_SRC_IP),
			EXTRACT(IPv6, LAST, IPv6_DST_IP),
			EXTRACT(IPv6, LAST, IPv6_NEXT_HDR),
			EXTRACT(TCP, NONE, TCP_PORT_SRC),
			EXTRACT(TCP, NONE, TCP_PORT_DST),
		},
	},
	[7] = {
		.table_name = "cdx_udp6_cc",
		.key_size = 38, .hash_res_mask = 0x7fff,
		.table_type = IPV6_UDP_TABLE,
		.scheme_name = "cdx_udp6_dist",
		.base_fqid = 0x1020, .num_fqids = 1,
		.dist_type = IPV6_UDP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPV6, CDX_PCD_UNIT_UDP },
		.num_extracts = 5,
		.extracts = {
			EXTRACT(IPv6, LAST, IPv6_SRC_IP),
			EXTRACT(IPv6, LAST, IPv6_DST_IP),
			EXTRACT(IPv6, LAST, IPv6_NEXT_HDR),
			EXTRACT(UDP, NONE, UDP_PORT_SRC),
			EXTRACT(UDP, NONE, UDP_PORT_DST),
		},
	},
	[8] = {
		.table_name = "cdx_tcp4_cc",
		.key_size = 14, .hash_res_mask = 0x7fff,
		.table_type = IPV4_TCP_TABLE,
		.scheme_name = "cdx_tcp4_dist",
		.base_fqid = 0x1010, .num_fqids = 1,
		.dist_type = IPV4_TCP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPV4, CDX_PCD_UNIT_TCP },
		.num_extracts = 5,
		.extracts = {
			EXTRACT(IPv4, LAST, IPv4_SRC_IP),
			EXTRACT(IPv4, LAST, IPv4_DST_IP),
			EXTRACT(IPv4, LAST, IPv4_PROTO),
			EXTRACT(TCP, NONE, TCP_PORT_SRC),
			EXTRACT(TCP, NONE, TCP_PORT_DST),
		},
	},
	[9] = {
		.table_name = "cdx_udp4_cc",
		.key_size = 14, .hash_res_mask = 0x7fff,
		.table_type = IPV4_UDP_TABLE,
		.scheme_name = "cdx_udp4_dist",
		.base_fqid = 0x1000, .num_fqids = 1,
		.dist_type = IPV4_UDP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPV4, CDX_PCD_UNIT_UDP },
		.num_extracts = 5,
		.extracts = {
			EXTRACT(IPv4, LAST, IPv4_SRC_IP),
			EXTRACT(IPv4, LAST, IPv4_DST_IP),
			EXTRACT(IPv4, LAST, IPv4_PROTO),
			EXTRACT(UDP, NONE, UDP_PORT_SRC),
			EXTRACT(UDP, NONE, UDP_PORT_DST),
		},
	},
	[10] = {
		.table_name = "cdx_esp6_cc",
		.key_size = 22, .hash_res_mask = 0x00ff,
		.table_type = ESP_IPV6_TABLE,
		.scheme_name = "cdx_esp6_dist",
		.base_fqid = 0x1070, .num_fqids = 1,
		.dist_type = IPV6_ESP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPSEC_ESP, CDX_PCD_UNIT_IPV6 },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(IPv6, NONE, IPv6_DST_IP),
			EXTRACT(IPv6, NONE, IPv6_NEXT_HDR),
			EXTRACT(IPSEC_ESP, NONE, IPSEC_ESP_SPI),
		},
	},
	[11] = {
		.table_name = "cdx_esp4_cc",
		.key_size = 10, .hash_res_mask = 0x00ff,
		.table_type = ESP_IPV4_TABLE,
		.scheme_name = "cdx_esp4_dist",
		.base_fqid = 0x1060, .num_fqids = 1,
		.dist_type = IPV4_ESP_DIST,
		.num_units = 2,
		.units = { CDX_PCD_UNIT_IPSEC_ESP, CDX_PCD_UNIT_IPV4 },
		.num_extracts = 3,
		.extracts = {
			EXTRACT(IPv4, NONE, IPv4_DST_IP),
			EXTRACT(IPv4, NONE, IPv4_PROTO),
			EXTRACT(IPSEC_ESP, NONE, IPSEC_ESP_SPI),
		},
	},
};

int cdx_pcd_set_extract(t_FmPcdExtractEntry *entry,
			const struct cdx_pcd_extract *extract)
{
	t_FmPcdFields *field;

	memset(entry, 0, sizeof(*entry));
	entry->type = e_FM_PCD_EXTRACT_BY_HDR;
	entry->extractByHdr.hdr = extract->hdr;
	entry->extractByHdr.hdrIndex = extract->hdr_index;
	entry->extractByHdr.ignoreProtocolValidation = FALSE;
	entry->extractByHdr.type = e_FM_PCD_EXTRACT_FULL_FIELD;

	/* The union members have different widths, so assign through the one
	 * the KeyGen driver will read back for this header. */
	field = &entry->extractByHdr.extractByHdrType.fullField;
	switch (extract->hdr) {
	case HEADER_TYPE_ETH:
		field->eth = (headerFieldEth_t)extract->field;
		break;
	case HEADER_TYPE_PPPoE:
		field->pppoe = (headerFieldPppoe_t)extract->field;
		break;
	case HEADER_TYPE_IPv4:
		field->ipv4 = (headerFieldIpv4_t)extract->field;
		break;
	case HEADER_TYPE_IPv6:
		field->ipv6 = (headerFieldIpv6_t)extract->field;
		break;
	case HEADER_TYPE_TCP:
		field->tcp = (headerFieldTcp_t)extract->field;
		break;
	case HEADER_TYPE_UDP:
		field->udp = (headerFieldUdp_t)extract->field;
		break;
	case HEADER_TYPE_IPSEC_ESP:
		field->ipsecEsp = (headerFieldIpsecEsp_t)extract->field;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

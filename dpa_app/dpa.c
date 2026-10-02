/*
 *  Copyright (c) 2011, 2014 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/**
 * @file                dpa.c
 * @description         dpaa offload uspace initialization 
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "fmc.h"
#include "cdx_ioctl.h"

//uncomment to enable debug messages from this app
//#define DPA_C_DEBUG 	1
#define SP_OFFSET 	0x20

//default configuration, pcd and pdl files 
#define DEFAULT_CFG_FILE	(char *)"/etc/cdx_cfg.xml"
#define DEFAULT_PCD_FILE	(char *)"/etc/cdx_pcd.xml"
#define DEFAULT_SP_FILE		(char *)"/etc/cdx_sp.xml"
#define DEFAULT_PDL_FILE	(char *)"/etc/fmc/config/hxs_pdl_v3.xml"

enum dpa_cls_tbl_type {
	DPA_CLS_TBL_INTERNAL_HASH = 0,	/* HASH table in MURAM */
	DPA_CLS_TBL_EXTERNAL_HASH,	/* HASH table in DDR */
	DPA_CLS_TBL_INDEXED,		/* Indexed table */
	DPA_CLS_TBL_EXACT_MATCH		/* Exact match table */
};


//structure holding table config parameters for tables defined in pcd_file 
struct ccnode_table_params 
{
	char *name;		//table name as in the pcd file
	uint32_t type;		//internal table type
};

//structure holding name for distributions and types 
struct model_dist_params 
{
	char *name;		//dist name as in the pcd file
	uint32_t type;		//internal table type
};


extern void * FM_PCD_Open(t_FmPcdParams *p_FmPcdParams);     
void *FM_PCD_Get_Sch_handle(t_Handle pDev);

char *cfg_file = DEFAULT_CFG_FILE;
char *pcd_file = DEFAULT_PCD_FILE;
char *pdl_file = DEFAULT_PDL_FILE;
char *sp_file = DEFAULT_SP_FILE;

//fmc model from xml files
static struct fmc_model_t cmodel;

/* Keep the inner tuple, then append first-header fields using generic
 * extraction (known fields are reordered by KeyGen): tuple, native protocol,
 * opposite-family protocol/endpoints, then the PPPoE peer and session.
 * TCP and UDP have separate schemes and tables, so the inner protocol byte
 * is redundant. Omitting it leaves the largest key at the 56-byte limit.
 * An absent header extracts zero. Thus ordinary traffic cannot hit a tunnel
 * entry, nor can an unsupported encapsulation hit an ordinary entry. */
static void tunnel_extract(t_FmPcdKgKeyExtractAndHashParams *key,
			   e_NetHeaderType family, unsigned offset, unsigned size)
{
	t_FmPcdExtractEntry *extract = &key->extractArray[key->numOfUsedExtracts++];

	memset(extract, 0, sizeof(*extract));
	extract->type = e_FM_PCD_EXTRACT_BY_HDR;
	extract->extractByHdr.hdr = family;
	extract->extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_1;
	extract->extractByHdr.type = e_FM_PCD_EXTRACT_FROM_HDR;
	extract->extractByHdr.extractByHdrType.fromHdr.offset = offset;
	extract->extractByHdr.extractByHdrType.fromHdr.size = size;
}

static int set_tunnel_keys(struct fmc_model_t *model)
{
	unsigned i, j;

	for (i = 0; i < model->scheme_count; i++) {
		const char *name = model->scheme_name[i];
		t_FmPcdKgKeyExtractAndHashParams *key =
			&model->scheme[i].keyExtractAndHashParams;
		bool removed = false;
		bool v4 = strstr(name, "cdx_udp4_dist") || strstr(name, "cdx_tcp4_dist");
		bool v6 = strstr(name, "cdx_udp6_dist") || strstr(name, "cdx_tcp6_dist");

		if (!v4 && !v6)
			continue;
		if (key->numOfUsedExtracts + 5 >= FM_PCD_KG_MAX_NUM_OF_EXTRACTS_PER_KEY)
			return -1;
		for (j = 0; j < key->numOfUsedDflts; j++)
			if (key->dflts[j].type == e_FM_PCD_KG_GENERIC_FROM_DATA)
				break;
		if (j == key->numOfUsedDflts) {
			if (j == FM_PCD_KG_NUM_OF_DEFAULT_GROUPS)
				return -1;
			key->numOfUsedDflts++;
		}
		key->privateDflt1 = 0;
		key->dflts[j].type = e_FM_PCD_KG_GENERIC_FROM_DATA;
		key->dflts[j].dfltSelect = e_FM_PCD_KG_DFLT_PRIVATE_1;
		/* The compiled scheme still requires this IP family and TCP or
		 * UDP. Only its redundant byte in the key is removed. */
		for (j = 0; j < key->numOfUsedExtracts; j++) {
			t_FmPcdExtractEntry *extract = &key->extractArray[j];

			if (extract->type != e_FM_PCD_EXTRACT_BY_HDR ||
			    extract->extractByHdr.type != e_FM_PCD_EXTRACT_FULL_FIELD)
				continue;
			if ((v4 && extract->extractByHdr.hdr == HEADER_TYPE_IPv4 &&
			     extract->extractByHdr.extractByHdrType.fullField.ipv4 == NET_HEADER_FIELD_IPv4_PROTO) ||
			    (v6 && extract->extractByHdr.hdr == HEADER_TYPE_IPv6 &&
			     extract->extractByHdr.extractByHdrType.fullField.ipv6 == NET_HEADER_FIELD_IPv6_NEXT_HDR)) {
				removed = true;
				key->numOfUsedExtracts--;
				memmove(extract, extract + 1,
					(key->numOfUsedExtracts - j) * sizeof(*extract));
				break;
			}
		}
		if (!removed)
			return -1;
		tunnel_extract(key, v4 ? HEADER_TYPE_IPv4 : HEADER_TYPE_IPv6, v4 ? 9 : 6, 1);
		tunnel_extract(key, v4 ? HEADER_TYPE_IPv6 : HEADER_TYPE_IPv4, v4 ? 6 : 9, 1);
		tunnel_extract(key, v4 ? HEADER_TYPE_IPv6 : HEADER_TYPE_IPv4, v4 ? 8 : 12, v4 ? 16 : 8);
		if (v4) {
			tunnel_extract(key, HEADER_TYPE_IPv6, 24, 16);
			/* Next header of destination options, or the first byte of
			 * the inner IPv4 header when no extension is present. */
			tunnel_extract(key, HEADER_TYPE_IPv6, 40, 1);
		}
		/* Absent PPPoE produces eight zeroes for a native flow. A PPPoE
		 * frame starts with 0x11 here, which cannot equal a unicast MAC
		 * in a session entry, even if this scheme is reached directly. */
		tunnel_extract(key, HEADER_TYPE_PPPoE, 0, 8);
	}
	for (i = 0; i < model->htnode_count; i++) {
		const char *name = model->htnode_name[i];

		if (strstr(name, "cdx_udp4") || strstr(name, "cdx_tcp4"))
			model->htnode[i].matchKeySize = CDX_UNICAST4_KEY_SIZE;
		else if (strstr(name, "cdx_udp6") || strstr(name, "cdx_tcp6"))
			model->htnode[i].matchKeySize = CDX_UNICAST_KEY_SIZE;
	}
	return 0;
}

/* PPPoE schemes precede their native counterparts and select the same table.
 * They add the exact peer MAC and session ID in place of the native zeroes.
 * Keep the existing CC tree and soft-parser offsets unchanged. */
static int set_pppoe_keys(struct fmc_model_t *model)
{
	unsigned original = model->scheme_count, i, p, j;

	for (i = 0; i < original; i++) {
		const char *name = model->scheme_name[i];
		unsigned clone, unit = UINT_MAX;
		t_FmPcdKgSchemeParams *scheme;
		t_FmPcdKgKeyExtractAndHashParams *key;

		if (!strstr(name, "cdx_udp4_dist") && !strstr(name, "cdx_tcp4_dist") &&
		    !strstr(name, "cdx_udp6_dist") && !strstr(name, "cdx_tcp6_dist"))
			continue;
		if (model->scheme_count == FMC_SCHEMES_NUM)
			return -1;
		clone = model->scheme_count++;
		scheme = &model->scheme[clone];
		*scheme = model->scheme[i];
		if (snprintf(model->scheme_name[clone], FMC_NAME_LEN, "%s_pppoe", name) >= FMC_NAME_LEN)
			return -1;
		for (p = 0; p < model->port_count; p++) {
			fmc_port *port = &model->port[p];
			unsigned member, candidate;

			for (member = 0; member < port->schemes_count; member++)
				if (port->schemes[member] == i)
					break;
			if (member == port->schemes_count)
				continue;
			for (candidate = 0; candidate < port->distinctionUnits.numOfDistinctionUnits; candidate++)
				if (port->distinctionUnits.units[candidate].hdrs[0].hdr == HEADER_TYPE_PPPoE)
					break;
			if (candidate == port->distinctionUnits.numOfDistinctionUnits ||
			    (unit != UINT_MAX && unit != candidate) || port->schemes_count == FMC_SCHEMES_NUM)
				return -1;
			unit = candidate;
			memmove(&port->schemes[member + 1], &port->schemes[member],
				(port->schemes_count++ - member) * sizeof(port->schemes[0]));
			port->schemes[member] = clone;
		}
		if (unit == UINT_MAX || scheme->netEnvParams.numOfDistinctionUnits == FM_PCD_MAX_NUM_OF_DISTINCTION_UNITS)
			return -1;
		scheme->netEnvParams.unitIds[scheme->netEnvParams.numOfDistinctionUnits++] = unit;
		key = &scheme->keyExtractAndHashParams;
		key->numOfUsedExtracts--; /* replace the native PPPoE guard */
		tunnel_extract(key, HEADER_TYPE_ETH, 6, 6);
		tunnel_extract(key, HEADER_TYPE_PPPoE, 2, 2);
		/* FMC assigns relative scheme IDs in apply order. The lower ID
		 * wins when both the PPPoE and native protocol sets match. */
		for (j = 0; j < model->apply_order_count; j++) {
			if (model->apply_order[j].type != FMCScheme || model->apply_order[j].index != i)
				continue;
			if (model->apply_order_count == sizeof(model->apply_order) / sizeof(model->apply_order[0]))
				return -1;
			memmove(&model->apply_order[j + 1], &model->apply_order[j],
				(model->apply_order_count++ - j) * sizeof(model->apply_order[0]));
			model->apply_order[j++].index = clone;
		}
	}
	return 0;
}

//mapping CC tables names to types
static struct ccnode_table_params table_params[] = {
	{(char *)"cdx_udp4", 	IPV4_UDP_TABLE},
	{(char *)"cdx_tcp4", 	IPV4_TCP_TABLE},
	{(char *)"cdx_multicast4", IPV4_MULTICAST_TABLE},
	{(char *)"cdx_multicast6", IPV6_MULTICAST_TABLE},
	{(char *)"cdx_udp6",	IPV6_UDP_TABLE},
	{(char *)"cdx_tcp6", 	IPV6_TCP_TABLE},
	{(char *)"cdx_pppoe", PPPOE_RELAY_TABLE},  
	{(char *)"cdx_ethernet", ETHERNET_TABLE},
	{(char *)"cdx_esp4", 	ESP_IPV4_TABLE},
	{(char *)"cdx_esp6", 	ESP_IPV6_TABLE},
	{(char *)"cdx_tuple3udp4",	IPV4_3TUPLE_UDP_TABLE},
	{(char *)"cdx_tuple3udp6", IPV6_3TUPLE_UDP_TABLE},
	{(char *)"cdx_bridged_mcast4", IPV4_BRIDGED_MULTICAST_TABLE},
	{(char *)"cdx_bridged_mcast6", IPV6_BRIDGED_MULTICAST_TABLE},
	/* The IPsec offline port's own tables. cdx indexes a port's tables by
	 * type, and this port has these in place of the shared ones, so they
	 * take the types of the tables they replace there. */
	{(char *)"cdx_sec_udp4",	IPV4_UDP_TABLE},
	{(char *)"cdx_sec_tcp4",	IPV4_TCP_TABLE},
	{(char *)"cdx_sec_udp6",	IPV6_UDP_TABLE},
	{(char *)"cdx_sec_tcp6",	IPV6_TCP_TABLE},
	{(char *)"cdx_sec_esp4",	ESP_IPV4_TABLE},
	{(char *)"cdx_sec_esp6",	ESP_IPV6_TABLE},
	{(char *)"cdx_sec_ethernet",	ETHERNET_TABLE}
};
#define MAX_TABLE_PARAMS\
		(sizeof(table_params) / sizeof(struct ccnode_table_params))


static struct model_dist_params dist_name[] = {
	{(char *)"cdx_udp4_dist", 	IPV4_UDP_DIST},
	{(char *)"cdx_tcp4_dist", 	IPV4_TCP_DIST},
	{(char *)"cdx_udp6_dist", 	IPV6_UDP_DIST},
	{(char *)"cdx_tcp6_dist", 	IPV6_TCP_DIST},
	{(char *)"cdx_ipv4multicast_dist", 	IPV4_MULTICAST_DIST},
	{(char *)"cdx_ipv6multicast_dist", 	IPV6_MULTICAST_DIST},
	{(char *)"cdx_esp4_dist", 	IPV4_ESP_DIST},
	{(char *)"cdx_esp6_dist", 	IPV6_ESP_DIST},
	{(char *)"cdx_pppoe_dist",      PPPOE_DIST},
	{(char *)"cdx_ethernet_dist", 	ETHERNET_DIST},
	{(char *)"cdx_tup3udp4_dist", 	IPV4_3TUPLE_UDP_DIST},
	{(char *)"cdx_tup3udp6_dist", 	IPV6_3TUPLE_UDP_DIST},
	{(char *)"cdx_bridged_mcast4_dist", IPV4_BRIDGED_MULTICAST_DIST},
	{(char *)"cdx_bridged_mcast6_dist", IPV6_BRIDGED_MULTICAST_DIST},
	{(char *)"cdx_sec_udp4_dist",	IPV4_UDP_DIST},
	{(char *)"cdx_sec_tcp4_dist",	IPV4_TCP_DIST},
	{(char *)"cdx_sec_udp6_dist",	IPV6_UDP_DIST},
	{(char *)"cdx_sec_tcp6_dist",	IPV6_TCP_DIST},
	{(char *)"cdx_sec_esp4_dist",	IPV4_ESP_DIST},
	{(char *)"cdx_sec_esp6_dist",	IPV6_ESP_DIST},
	{(char *)"cdx_sec_ethernet_dist", ETHERNET_DIST},
};
#define MAX_DIST_PARAMS\
		(sizeof(dist_name) / sizeof(struct model_dist_params))

//rate limiter policier defaults
#define CDX_EXPT_ETH_DEFA_LIMIT         195312  //100 mbps
#define CDX_EXPT_WIFI_DEFA_LIMIT        DISABLE_EXPT_PROFILE
#define CDX_EXPT_ARPND_DEFA_LIMIT       DISABLE_EXPT_PROFILE
#define CDX_EXPT_PCAP_DEFA_LIMIT        DISABLE_EXPT_PROFILE
#define CDX_EXPT_RATELIM_MODE           EXPT_PKT_LIM_PLCR_MODE_PKT
#define CDX_EXPT_BURST_SIZE             64


//display the contents of the model as read from the xml config files
#ifdef DPA_C_DEBUG
static void display_model(struct fmc_model_t *model)
{
	uint32_t ii;
	uint32_t jj;

	printf("==================model====================\n");
	if (model->sp_enable)
		printf("sp_enabled\n");
	printf("------------------fman_info----------------\n");
	for ( ii = 0; ii < model->fman_count; ii++) {
		printf("number	\t%d\n", model->fman[ii].number);
		printf("name	\t%s\n", model->fman[ii].name);
		printf("number	\t%p\n", model->fman[ii].handle);
		printf("pcdname	\t%s\n", model->fman[ii].pcd_name);
		printf("pcd handle\t%p\n", model->fman[ii].pcd_handle);
		printf("portcount\t%d\n", model->fman[ii].port_count);
		printf("ports::	\t");
		for (jj = 0; jj < model->fman[ii].port_count; jj++)
			printf("%d ", model->fman[ii].ports[jj]);
		printf("\n");
	}
	printf("------------------schemes----------------\n");
	printf("scheme count\t%d\n", model->scheme_count);
	for (ii = 0; ii < model->scheme_count; ii++) { 
		t_FmPcdKgSchemeParams *scheme;
		printf("name	\t%s\n", &model->scheme_name[ii][0]);
		printf("handle	\t%p\n", FM_PCD_Get_Sch_handle(model->scheme_handle[ii]));
		scheme = &model->scheme[ii];
		printf("relid	\t%d\n", scheme->id.relativeSchemeId);
		printf("direct	\t%d\n", scheme->alwaysDirect);
	}
	printf("------------------ccnodes----------------\n");
	printf("ccnode count\t%d\n", model->ccnode_count);
	for (ii = 0; ii < model->ccnode_count; ii++) {
		printf("name	\t%s\n", model->ccnode_name[ii]);
		printf("handle	\t%p\n", model->ccnode_handle[ii]);
	}
	printf("------------------htnodes----------------\n");
	printf("htnode count\t%d\n", model->htnode_count);
	for (ii = 0; ii < model->htnode_count; ii++) {
		printf("name	\t%s\n", model->htnode_name[ii]);
		printf("handle	\t%p\n", model->htnode_handle[ii]);
	}
	printf("------------------ports------------------\n");
	printf("port count\t%d\n", model->port_count);
	for (ii = 0; ii < model->port_count; ii++) {
	printf("----------------port num %d---------------\n",  model->port[ii].number);
		printf("type	\t%d\n", model->port[ii].type);
		printf("name	\t%s\n", model->port[ii].name);
		printf("handle	\t%p\n", model->port[ii].handle);
		printf("cctreename\t%s\n", model->port[ii].cctree_name);
		if (model->port[ii].schemes_count) {
			printf("schemes\t%d\n", model->port[ii].schemes_count);
			printf("scheme nodes indices\n");
			for (jj = 0; jj < model->port[ii].schemes_count; jj++) {
				printf("%d ", model->port[ii].schemes[jj]);
			}
			printf("\n");
		} else
			printf("no schemes\n");
		if (model->port[ii].ccnodes_count) {
			printf("ccnodes_count\t%d\n", model->port[ii].ccnodes_count);
			printf("ccnode nodes indices\n");
			for (jj = 0; jj < model->port[ii].ccnodes_count; jj++) {
				printf("%d ", model->port[ii].ccnodes[jj]);
			}
			printf("\n");
		} else
			printf("no ccnodes\n");
		if (model->port[ii].htnodes_count) {
			printf("htnodes_count\t%d\n", model->port[ii].htnodes_count);
			printf("htnode nodes indices\n");
			for (jj = 0; jj < model->port[ii].htnodes_count; jj++) {
				printf("%d ", model->port[ii].htnodes[jj]);
			}
			printf("\n");
		} else
			printf("no htnodes\n");
	}
	printf("===========================================\n");
}
#endif

/* advance features like HMs are not enabled by default, 
   enable them before executing fmc */
static int set_fm_adv_options(uint32_t index)
{
	t_FmPcdParams params = {0};
	t_Handle fm, pcd;
	int retval = -1;

	fm = FM_Open(index);
	if (!fm) {
		fprintf(stderr, "%s: could not open fm%u\n", __func__, index);
		return -1;
	}
	params.h_Fm = fm;
	pcd = FM_PCD_Open(&params);
	if (!pcd) {
		fprintf(stderr, "%s: could not open fm%u PCD\n", __func__, index);
		goto close_fm;
	}
	if (FM_PCD_Disable(pcd) != E_OK ||
	    FM_PCD_SetAdvancedOffloadSupport(pcd) != E_OK) {
		fprintf(stderr, "%s: could not enable fm%u advanced offload\n",
			__func__, index);
		goto close_pcd;
	}
	retval = 0;
close_pcd:
	FM_PCD_Close(pcd);
close_fm:
	FM_Close(fm);
	return retval;
}

static int get_dist_type(char *name) 
{
	uint32_t ii;
	for (ii = 0; ii < MAX_DIST_PARAMS; ii++) {
		if (strstr(name, dist_name[ii].name) == 0)
			continue;
		return dist_name[ii].type; 
	}
	return -1;
}

/* scan port list in the fmc model, distributions associated with it, allocate
and fill port info structure and add it to the fman info structure */
static int get_port_info(struct cdx_fman_info *finfo)
{
	struct cdx_port_info *port_info;
	struct cdx_port_info *pinfo;
	struct cdx_dist_info *dist_info;
	char name[256];
	uint32_t size;
	uint32_t ports;
	uint32_t ii;
	uint32_t jj;

	if (!cmodel.port_count) {
		printf("%s::fm %d, no port info\n", __func__, 
				finfo->index);
		return 0;
	}
	size = 0;
	ports = 0;
	for (ii = 0; ii < cmodel.port_count ; ii++) {
#ifdef DPA_C_DEBUG
		printf("%s::port %s\n", __func__,
				cmodel.port[ii].name);
#endif
		//FM  name would be fm0, fm1 etc
		sprintf(name, "fm%d", finfo->index);
		//look for fm name in the port name
		if (strstr(cmodel.port[ii].name, name) == 0)
			continue;
		//found port on this fman instance
		size += sizeof(struct cdx_port_info);
		ports++;
		//add memory for dist for this port
		size += (cmodel.port[ii].schemes_count * sizeof(struct cdx_dist_info));
	}
	if (!ports) {
		printf("%s::no ports with fm%d\n", __func__,
			finfo->index);
		return 0;
	}
	pinfo = (struct cdx_port_info *) calloc(1, size);
	if (!pinfo) {
		printf("%s::unable to allocate mem for port info\n",
				__func__);
		goto err_ret;
	}
	port_info = pinfo;
	dist_info = (struct cdx_dist_info *)(port_info + ports);
	//scan all ports associated with this fman
	for (ii = 0; ii < cmodel.port_count; ii++) {
		sprintf(name, "fm%d", finfo->index);
		if (strstr(cmodel.port[ii].name, name) == 0)
                        continue;
		//fill all port related infor from model into cdx structures
		port_info->fm_index = finfo->index;
		port_info->index = cmodel.port[ii].number;
		port_info->portid = cmodel.port[ii].portid;
		port_info->max_dist = cmodel.port[ii].schemes_count;
		port_info->dist_info = dist_info;
		//encode the type, speed, fm index and port index in device name
		switch (cmodel.port[ii].type) {
			case 0:
				sprintf(port_info->name, "dpa-fman%d-oh@%d", 
					port_info->fm_index, (port_info->index + 1));
				port_info->type = 0;
				break;
			case 1:
				sprintf(port_info->name, "dpa-fm%d-1G-eth%d", 
					port_info->fm_index, port_info->index);
				port_info->type = 1;
				break;
			case 2:
				sprintf(port_info->name, "dpa-fm%d-10G-eth%d", 
					port_info->fm_index, port_info->index);
				port_info->type = 10;
				break;
			default:
				printf("%s::unhandled type %d\n", __func__,
					cmodel.port[ii].type);
				break;
		}
		//scan all distributions associated with this port 
		for (jj = 0; jj < port_info->max_dist; jj++) {
			uint32_t handle;

			handle = cmodel.port[ii].schemes[jj];
			dist_info->base_fqid = cmodel.scheme[handle].baseFqid;
			dist_info->type = get_dist_type(&cmodel.scheme_name[handle][0]);
			if (dist_info->type == -1) {
				printf("%s::unable to get type for dist %s\n", 
					__func__, &cmodel.scheme_name[handle][0]);
			}
			dist_info->count = 
				cmodel.scheme[handle].keyExtractAndHashParams.hashDistributionNumOfFqids;
#ifdef DPA_C_DEBUG
			printf("%s:: port %d, iter %d scheme %s handle %d basefqid %x(%d), count %d type %d\n",  __func__,
				ii, jj, &cmodel.scheme_name[handle][0], handle, dist_info->base_fqid, 
				dist_info->base_fqid, dist_info->count, dist_info->type);
#endif
			dist_info++;
		}
		port_info++;
	}
	finfo->portinfo = pinfo;
	return 0;
err_ret:
	return -1;
}

/* scan port list in the fmc model, update distribution handles associated with it */
static int update_port_dist_info(struct cdx_fman_info *finfo)
{
	struct cdx_port_info *port_info;
	struct cdx_dist_info *dist_info;
	char name[256];
	uint32_t ii;
	uint32_t jj;

	port_info = finfo->portinfo;
	//update all ports associated with this fman
	for (ii = 0; ii < cmodel.port_count; ii++) {
		sprintf(name, "fm%d", finfo->index);
		if (strstr(cmodel.port[ii].name, name) == 0)
			continue;
		dist_info = port_info->dist_info;
		for (jj = 0; jj < port_info->max_dist; jj++) {
			uint32_t handle;

			handle = cmodel.port[ii].schemes[jj];
			dist_info->handle = FM_PCD_Get_Sch_handle(cmodel.scheme_handle[handle]);
			dist_info++;
		}
		port_info++;
	}
	return 0;
}

//get cc table configuration info from user
static int get_tbl_params(struct table_info *info)
{
	uint32_t ii;
	for (ii = 0; ii < MAX_TABLE_PARAMS; ii++) {
		if (strstr(info->name, table_params[ii].name) == 0)
			continue;
		info->type = table_params[ii].type;
		return 0; 
	}
	return -1;
}


static int create_tbl_portmap(struct table_info *tbl_info, uint32_t tbl_index)
{
	uint32_t ii;
	uint32_t jj;
	fmc_port *port;
	uint32_t count;
	uint32_t *tblref;

	port = &cmodel.port[0]; 

	for (ii = 0; ii < cmodel.port_count; ii++) {
		if (tbl_info->dpa_type == DPA_CLS_TBL_EXACT_MATCH) {
			count = port->ccnodes_count;
			tblref = &port->ccnodes[0];
		} else {
			count = port->htnodes_count;
			tblref = &port->htnodes[0];
		}
		for (jj = 0; jj < count; jj++) {
			if (*tblref == tbl_index) {
				if (port->portid >= sizeof(tbl_info->port_idx) * 8) {
					printf("%s::port id %u exceeds table bitmap\n", __func__, port->portid);
					return -1;
				}
				tbl_info->port_idx |= (1U << port->portid);
				break;
			}
			tblref++;
		} 
		port++;
	}
#ifdef DPA_C_DEBUG
	printf("%s::tbl %s portmap %08x\n", __func__,
			tbl_info->name, tbl_info->port_idx);
#endif
	return 0;
}

static int get_table_info(struct cdx_fman_info *fman_info)
{
	struct table_info *info;
	uint32_t num_tables;
	uint32_t ii;
	uint32_t jj;
	uint32_t count;
	int retval;

	//get count of number of hash tables and exact match tables
	count = (cmodel.ccnode_count + cmodel.htnode_count);
	if (!count) {
		printf("%s::no tables defined\n", __func__);
		return 0;
	}
	//allocate memory for as many tables for this fman instance 
	info = (struct table_info *)
		calloc(1, (count * sizeof(struct table_info)));
	if (!info) {
		printf("%s::unable to alloc table info\n", __func__); 
		retval = -1;
		goto func_ret;
	}
	fman_info->num_tables = 0;
	fman_info->tbl_info = info;
	num_tables = 0;
	retval = 0;
	//first pass is nonhash, second for hash tables
	for (jj = 0; jj < 2; jj++) {
		if (!jj) {
			//find all non-hash tables
			count = (cmodel.ccnode_count);
		} else {
			//find all hash tables
			count = (cmodel.htnode_count);
		}
		for (ii = 0; ii < count; ii++) {
			t_Handle handle;
			char *tblname;
			uint32_t fm_idx;
			uint32_t port_id;
			uint32_t speed;
			if (!jj) 
				tblname = cmodel.ccnode_name[ii];
			else
				tblname = cmodel.htnode_name[ii];
			/* parse table name assuming it is for a physical port
			get fman instance, port speed and index & name */
			if (sscanf(tblname, "fm%d/port/%dG/%d/ccnode/%s",
                        	&fm_idx, &speed, &port_id,
                                &info->name[0]) != 4) {
				/* parse table name assuming it is for an offline port
				get fman instance, index & name */
                        	if (sscanf(tblname,
                                	"fm%d/port/OFFLINE/%d/ccnode/%s",
                                       	&fm_idx, &port_id,
                                       	&info->name[0]) != 3) {
					//neither of the two....	
                                	printf("%s::unable to parse "
                                        	"node name %s\n",
                                        	__func__, tblname);
                               		retval = -1;
                               		goto func_ret;
				}
			}
			//table for this instance?, if not skip
			if (fm_idx != fman_info->index)
				continue;
			if (!jj) {
				info->dpa_type = DPA_CLS_TBL_EXACT_MATCH;
				info->num_keys = 
					cmodel.ccnode[ii].keysParams.maxNumOfKeys;
				info->key_size = cmodel.ccnode[ii].keysParams.keySize;
				handle = cmodel.ccnode_handle[ii];
#ifdef DPA_C_DEBUG
				printf("%s::found non-hash tbl %s\n", 
					__func__, 
					info->name);
#endif
			} else {
				info->dpa_type = DPA_CLS_TBL_EXTERNAL_HASH;
				info->num_keys =
					cmodel.htnode[ii].maxNumOfKeys;
				info->num_sets = 
					(cmodel.htnode[ii].hashResMask + 1);
				info->num_ways = 
					(info->num_keys / info->num_sets);
				info->key_size = cmodel.htnode[ii].matchKeySize;
				handle = cmodel.htnode_handle[ii];
#ifdef DPA_C_DEBUG
				printf("%s::found hash tbl %s table mask %x\n", 
					__func__,
					info->name, info->num_sets);
#endif
			}
			//get and fill fd ref to table 
			info->id = (void *)((struct t_Device *)handle)->id;
			//create port map for this table
			if (create_tbl_portmap(info, ii))
				return -1;
			//fill app table type
			if (get_tbl_params(info)) {
				printf("%s::unable to get params for table %s\n", 
					__func__, info->name); 
				return -1;
			}
			info++;
			num_tables++;
		}
	}
	fman_info->num_tables = num_tables;
	if (!num_tables) {
		printf("%s::fm %d, no tables defined\n", __func__, 
			fman_info->index);	
		goto func_ret;
	}	
#ifdef DPA_C_DEBUG
	printf("%s::fm %d, num tables %d\n", __func__, 
			fman_info->index, num_tables);
#endif
func_ret:
	return retval;
}

/* Tag every external-hash node in the compiled model with the cdx
 * table type its name implies. The kernel's FM_PCD_ExternalHashTableSet()
 * switches on this field to pick the node's microcode class (L2/L3/L4)
 * and to decide whether per-bucket locks are needed, so it has to be
 * filled in before fmc_execute(). fmc itself never sets it: table_type
 * is an ASK extension to t_FmPcdHashTableParams. Unrecognised names
 * fall back to ETHERNET_TABLE (L2). */
static int set_table_types(struct fmc_model_t *model)
{
	uint32_t index;

	for (index = 0; index < model->htnode_count; index++) {
		do {
			if (strstr(model->htnode_name[index], "cdx_udp4")) {
				model->htnode[index].table_type = IPV4_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tcp4")) {
				model->htnode[index].table_type = IPV4_TCP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_esp4")) {
				model->htnode[index].table_type = ESP_IPV4_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_multicast4")) {
				model->htnode[index].table_type = IPV4_MULTICAST_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_udp6")) {
				model->htnode[index].table_type = IPV6_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tcp6")) {
				model->htnode[index].table_type = IPV6_TCP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_esp6")) {
				model->htnode[index].table_type = ESP_IPV6_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_multicast6")) {
				model->htnode[index].table_type = IPV6_MULTICAST_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_pppoe")) {
				model->htnode[index].table_type = PPPOE_RELAY_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tuple3udp4")) {
				model->htnode[index].table_type = IPV4_3TUPLE_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_tuple3udp6")) {
				model->htnode[index].table_type = IPV6_3TUPLE_UDP_TABLE;
				break;
			}
			/* The bridged multicast tables are multicast tables
			 * to the microcode, so the kernel is given the
			 * multicast types and the L3 class they select. Only
			 * cdx tells the two apart, by the type it is given
			 * in table_params[]. */
			if (strstr(model->htnode_name[index], "cdx_bridged_mcast4")) {
				model->htnode[index].table_type = IPV4_MULTICAST_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_bridged_mcast6")) {
				model->htnode[index].table_type = IPV6_MULTICAST_TABLE;
				break;
			}
			/* The IPsec offline port's tables are the classes of
			 * the ones they stand in for; their catch-all falls
			 * through to Ethernet (L2) like the shared one. */
			if (strstr(model->htnode_name[index], "cdx_sec_udp4")) {
				model->htnode[index].table_type = IPV4_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_sec_tcp4")) {
				model->htnode[index].table_type = IPV4_TCP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_sec_udp6")) {
				model->htnode[index].table_type = IPV6_UDP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_sec_tcp6")) {
				model->htnode[index].table_type = IPV6_TCP_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_sec_esp4")) {
				model->htnode[index].table_type = ESP_IPV4_TABLE;
				break;
			}
			if (strstr(model->htnode_name[index], "cdx_sec_esp6")) {
				model->htnode[index].table_type = ESP_IPV6_TABLE;
				break;
			}
			model->htnode[index].table_type = ETHERNET_TABLE;
			break;
		} while(1);
	}
	return 0;
}


void set_exptrate_policer_defaults(struct cdx_fman_info *fman_info)
{
        uint32_t ii;

        fman_info->expt_ratelim_mode = CDX_EXPT_RATELIM_MODE;
        fman_info->expt_ratelim_burst_size = CDX_EXPT_BURST_SIZE;

        for (ii = 0; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++) {
                switch (ii) {
                        case CDX_EXPT_ETH_RATELIMIT:
                                fman_info->expt_rate_limit_info[ii].limit = CDX_EXPT_ETH_DEFA_LIMIT;
                                break;
                        case CDX_EXPT_WIFI_RATELIMIT:
                                fman_info->expt_rate_limit_info[ii].limit = CDX_EXPT_WIFI_DEFA_LIMIT;
                                break;
                        case CDX_EXPT_ARPND_RATELIMIT:
                        case CDX_EXPT_PCAP_RATELIMIT:
                                fman_info->expt_rate_limit_info[ii].limit = DISABLE_EXPT_PROFILE;
                                break;
                }
                printf("%s::set limit for type %d as %d\n",  __func__,
                        ii, fman_info->expt_rate_limit_info[ii].limit);
                fman_info->expt_rate_limit_info[ii].handle = 0;
        }
}

/* dpa offload initialization.
	opens cdx device for ioctl
	compiles fmc model
	executes model (loads fman)
	for each fman in the xml configuration, gets port, table and other info
	performs ioctl call to pass this info to kernel module.
 should be called once from uspace application.
*/

int dpa_init(void)
{
	struct cdx_ctrl_set_dpa_params params = {0};
	struct cdx_fman_info *finfo;
	bool executed = false;
	uint32_t ii;
	int fd, retval = -1;

	fd = open("/dev/" CDX_CTRL_CDEVNAME, O_RDWR);
	if (fd < 0) {
		perror("dpa_init: open " CDX_CTRL_CDEVNAME);
		return -1;
	}
	/* Keep the exclusive fd until programming and any rollback finish. */
	if (ioctl(fd, CDX_CTRL_DPA_INIT_CHECK)) {
		perror("dpa_init: initialization refused");
		goto out;
	}
	if (fmc_compile(&cmodel, cfg_file, pcd_file, pdl_file, sp_file,
			SP_OFFSET, 0, NULL)) {
		fprintf(stderr, "dpa_init: unable to compile FMC input: %s\n",
			fmc_get_error());
		goto out;
	}
	if (!cmodel.fman_count || cmodel.fman_count > FMC_FMAN_NUM) {
		fprintf(stderr, "dpa_init: invalid FMAN count %u\n", cmodel.fman_count);
		goto out;
	}
	params.num_fmans = cmodel.fman_count;
	params.fman_info = calloc(params.num_fmans, sizeof(*params.fman_info));
	if (!params.fman_info)
		goto out;

	if (set_table_types(&cmodel) || set_tunnel_keys(&cmodel) || set_pppoe_keys(&cmodel))
		goto out;
	for (ii = 0; ii < params.num_fmans; ii++) {
		finfo = &params.fman_info[ii];
		finfo->index = cmodel.fman[ii].number;
		finfo->max_ports = cmodel.fman[ii].port_count;
		if (get_port_info(finfo))
			goto out;
	}
	for (ii = 0; ii < params.num_fmans; ii++) {
		if (set_fm_adv_options(params.fman_info[ii].index))
			goto out;
	}

	/* FMC may have acquired resources even when execution fails. */
	executed = true;
	if (fmc_execute(&cmodel)) {
		fprintf(stderr, "dpa_init: unable to execute FMC model\n");
		goto out;
	}
#ifdef DPA_C_DEBUG
	display_model(&cmodel);
#endif
	for (ii = 0; ii < params.num_fmans; ii++) {
		struct t_Device *pcd = cmodel.fman[ii].pcd_handle;

		finfo = &params.fman_info[ii];
		if (!pcd || update_port_dist_info(finfo) || get_table_info(finfo))
			goto out;
		finfo->pcd_handle = (void *)(uintptr_t)pcd->fd;
		set_exptrate_policer_defaults(finfo);
	}
	retval = ioctl(fd, CDX_CTRL_DPA_SET_PARAMS, &params);
	if (retval)
		perror("dpa_init: set params");
out:
	if (retval && executed && fmc_clean(&cmodel))
		fprintf(stderr, "dpa_init: FMC rollback failed; reboot before retrying\n");
	if (params.fman_info) {
		for (ii = 0; ii < params.num_fmans; ii++) {
			free(params.fman_info[ii].tbl_info);
			free(params.fman_info[ii].portinfo);
		}
		free(params.fman_info);
	}
	/* Successful FMC objects remain installed for CDX. Their userspace
	 * wrappers and descriptors are reclaimed when this one-shot app exits. */
	close(fd);
	return retval;
}

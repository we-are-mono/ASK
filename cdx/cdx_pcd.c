// SPDX-License-Identifier: GPL-2.0+
/*
 * Build the ASK FMan PCD.
 *
 * Walks the classification groups in cdx_pcd_desc.c, programming each one
 * through the FM_PCD and FM_PORT entry points. Per FMan:
 *
 *	FM_PCD_Disable, FM_PCD_SetAdvancedOffloadSupport
 *	FM_PCD_PrsLoadSw, FM_PCD_Enable
 *	FM_PCD_NetEnvCharacteristicsSet		(once per policy)
 *	per port: FM_PCD_HashTableSet x14 or x7, FM_PCD_CcRootBuild
 *	FM_PCD_KgSchemeSet x25		(bound to each policy's first tree)
 *	per port: FM_PORT_Disable, FM_PORT_SetPCD, FM_PORT_Enable
 *
 * That order is load bearing twice over: the CC root group layout is what
 * cdx_sp.xml addresses by a fixed offset, and a shared scheme can only be bound
 * once its tree exists.
 *
 * Schemes are shared by policy to fit within the KeyGen limit of 32. A scheme
 * names a group id, and the CC root tree it dispatches into comes from the
 * receiving port's FM_PORT_SetPCD, even though h_CcTree names only the first
 * port using that policy.
 *
 * Miss actions are not set here. A table's miss action points at a scheme, a
 * scheme points at a tree, and a tree points at the tables, so the miss action
 * cannot be filled in before the scheme exists. cdxdrv_set_miss_action() patches
 * them in afterwards with FM_PCD_HashTableModifyMissNextEngine().
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "lnxwrp_fm.h"
#include "cdx_pcd.h"
#include "cdx_softparse.h"

/* Resolve a described port to the FMan wrapper's port device, the same way
 * dpa_cfg's port quiesce does. The host-command port is not in this space. */
static t_LnxWrpFmPortDev *cdx_pcd_wrapper_port(t_LnxWrpFmDev *fm,
					       const struct cdx_pcd_port *port)
{
	t_LnxWrpFmPortDev *wport;

	switch (port->type) {
	case e_FM_PORT_TYPE_OH_OFFLINE_PARSING:
		if (!port->number || port->number > ARRAY_SIZE(fm->opPorts))
			return NULL;
		wport = &fm->opPorts[port->number - 1];
		break;
	case e_FM_PORT_TYPE_RX_10G:
		if (port->number >= FM_MAX_NUM_OF_10G_RX_PORTS)
			return NULL;
		wport = &fm->rxPorts[port->number + FM_MAX_NUM_OF_1G_RX_PORTS];
		break;
	case e_FM_PORT_TYPE_RX:
		if (port->number >= FM_MAX_NUM_OF_1G_RX_PORTS)
			return NULL;
		wport = &fm->rxPorts[port->number];
		break;
	default:
		return NULL;
	}
	if (!wport->active || !wport->h_Dev)
		return NULL;
	return wport;
}

static int cdx_pcd_set_net_env(struct cdx_pcd_state *state, bool sec)
{
	t_FmPcdNetEnvParams params = { 0 };
	unsigned int i;

	for (i = 0; i < CDX_PCD_NUM_UNITS; i++) {
		if (sec && i == CDX_PCD_UNIT_PPPOE)
			continue;
		params.units[params.numOfDistinctionUnits++].hdrs[0].hdr = cdx_pcd_units[i];
	}

	state->net_env[sec] = FM_PCD_NetEnvCharacteristicsSet(state->h_pcd, &params);
	if (!state->net_env[sec]) {
		pr_err("cdx: fm%u: network environment setup failed\n",
		       state->fm_index);
		return -EIO;
	}
	return 0;
}

/* One external hash table per group. Under USE_ENHANCED_EHASH every table the
 * SDK creates is external, so externalHash is left alone deliberately. The miss
 * action is a placeholder until cdxdrv_set_miss_action() replaces it. */
static int cdx_pcd_set_tables(struct cdx_pcd_state *state, unsigned int idx)
{
	struct cdx_pcd_port_state *ps = &state->port_state[idx];
	unsigned int grp;

	for (grp = 0; grp < ps->group_count; grp++) {
		const struct cdx_pcd_group *g = &cdx_pcd_groups[ps->first_group + grp];
		t_FmPcdHashTableParams params = { 0 };
		t_Handle table;

		params.maxNumOfKeys = CDX_PCD_MAX_NUM_OF_KEYS;
		params.statisticsMode = e_FM_PCD_CC_STATS_MODE_BYTE_AND_FRAME;
		params.hashResMask = g->hash_res_mask;
		params.hashShift = 0;
		params.kgHashShift = 0;
		params.matchKeySize = g->key_size;
		params.table_type = g->hw_table_type;
		params.ccNextEngineParamsForMiss.nextEngine = e_FM_PCD_DONE;
		params.ccNextEngineParamsForMiss.params.enqueueParams.action =
			e_FM_PCD_ENQ_FRAME;

		table = FM_PCD_HashTableSet(state->h_pcd, &params);
		if (!table) {
			pr_err("cdx: %s: %s setup failed\n",
			       state->ports[idx].name, g->table_name);
			return -EIO;
		}
		ps->tables[grp] = table;
		ps->num_tables = grp + 1;
	}
	return 0;
}

/* One CC group per hash table, in group order: a scheme's grpId indexes this.
 * t_FmPcdCcTreeParams is sized for the hardware maximum and runs to several
 * kilobytes, well past the kernel's stack frame limit. */
static int cdx_pcd_build_cctree(struct cdx_pcd_state *state, unsigned int idx)
{
	struct cdx_pcd_port_state *ps = &state->port_state[idx];
	t_FmPcdCcTreeParams *params;
	unsigned int grp;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return -ENOMEM;

	params->h_NetEnv = state->net_env[!!ps->first_group];
	params->numOfGrps = ps->group_count;
	for (grp = 0; grp < ps->group_count; grp++) {
		t_FmPcdCcNextEngineParams *next =
			&params->ccGrpParams[grp].nextEnginePerEntriesInGrp[0];

		params->ccGrpParams[grp].numOfDistinctionUnits = 0;
		next->nextEngine = e_FM_PCD_CC;
		next->params.ccParams.h_CcNode = ps->tables[grp];
	}

	ps->cctree = FM_PCD_CcRootBuild(state->h_pcd, params);
	kfree(params);
	if (!ps->cctree) {
		pr_err("cdx: %s: classification tree setup failed\n",
		       state->ports[idx].name);
		return -EIO;
	}
	return 0;
}

/* Generic extracts stay after the known fields. An absent header yields zero,
 * distinguishing native traffic from tunnel and PPPoE receive identities. */
static void cdx_pcd_extract_bytes(t_FmPcdKgKeyExtractAndHashParams *key,
				e_NetHeaderType hdr, u8 offset, u8 size)
{
	t_FmPcdExtractEntry *e = &key->extractArray[key->numOfUsedExtracts++];

	e->type = e_FM_PCD_EXTRACT_BY_HDR;
	e->extractByHdr.hdr = hdr;
	e->extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_1;
	e->extractByHdr.type = e_FM_PCD_EXTRACT_FROM_HDR;
	e->extractByHdr.extractByHdrType.fromHdr.offset = offset;
	e->extractByHdr.extractByHdrType.fromHdr.size = size;
}

static void cdx_pcd_tunnel_key(t_FmPcdKgKeyExtractAndHashParams *key,
			     u8 family, bool pppoe)
{
	bool v4 = family == 4;

	key->numOfUsedDflts = 1;
	key->privateDflt1 = 0;
	key->dflts[0].type = e_FM_PCD_KG_GENERIC_FROM_DATA;
	key->dflts[0].dfltSelect = e_FM_PCD_KG_DFLT_PRIVATE_1;
	cdx_pcd_extract_bytes(key, v4 ? HEADER_TYPE_IPv4 : HEADER_TYPE_IPv6,
			      v4 ? 9 : 6, 1);
	cdx_pcd_extract_bytes(key, v4 ? HEADER_TYPE_IPv6 : HEADER_TYPE_IPv4,
			      v4 ? 6 : 9, 1);
	cdx_pcd_extract_bytes(key, v4 ? HEADER_TYPE_IPv6 : HEADER_TYPE_IPv4,
			      v4 ? 8 : 12, v4 ? 16 : 8);
	if (v4) {
		cdx_pcd_extract_bytes(key, HEADER_TYPE_IPv6, 24, 16);
		cdx_pcd_extract_bytes(key, HEADER_TYPE_IPv6, 40, 1);
	}
	if (pppoe) {
		cdx_pcd_extract_bytes(key, HEADER_TYPE_ETH, 6, 6);
		cdx_pcd_extract_bytes(key, HEADER_TYPE_PPPoE, 2, 2);
	} else {
		cdx_pcd_extract_bytes(key, HEADER_TYPE_PPPoE, 0, 8);
	}
}

static int cdx_pcd_set_scheme(struct cdx_pcd_state *state, unsigned int idx,
			      unsigned int grp, bool pppoe)
{
	struct cdx_pcd_port_state *ps = &state->port_state[idx];
	unsigned int id = ps->first_group + grp, i;
	const struct cdx_pcd_group *g = &cdx_pcd_groups[id];
	t_FmPcdKgSchemeParams params = { 0 };
	t_FmPcdKgExtractedOrParams *port_or;
	t_Handle scheme;
	int rc;

	/* Creation follows match priority, including PPPoE before its native
	 * counterpart. The CC group still selects the same per-port table. */
	params.id.relativeSchemeId = state->num_schemes;
	params.shared = TRUE;
	params.netEnvParams.h_NetEnv = state->net_env[!!ps->first_group];
	params.netEnvParams.numOfDistinctionUnits = g->num_units;
	for (i = 0; i < g->num_units; i++) {
		u8 unit = g->units[i];

		/* The SEC environment has no PPPoE distinction unit. */
		if (ps->first_group && unit > CDX_PCD_UNIT_PPPOE)
			unit--;
		params.netEnvParams.unitIds[i] = unit;
	}
	if (pppoe)
		params.netEnvParams.unitIds[params.netEnvParams.numOfDistinctionUnits++] =
			CDX_PCD_UNIT_PPPOE;
	params.useHash = TRUE;
	params.keyExtractAndHashParams.numOfUsedExtracts = g->num_extracts;
	for (i = 0; i < g->num_extracts; i++) {
		rc = cdx_pcd_set_extract(&params.keyExtractAndHashParams.extractArray[i],
					&g->extracts[i]);
		if (rc)
			return rc;
	}
	if (g->tunnel_family)
		cdx_pcd_tunnel_key(&params.keyExtractAndHashParams, g->tunnel_family, pppoe);
	params.keyExtractAndHashParams.hashDistributionNumOfFqids = g->num_fqids;
	params.baseFqid = g->base_fqid;
	params.numOfUsedExtractedOrs = 1;
	port_or = &params.extractedOrs[0];
	port_or->type = e_FM_PCD_KG_EXTRACT_PORT_PRIVATE_INFO;
	port_or->dfltValue = e_FM_PCD_KG_DFLT_GBL_0;
	port_or->mask = 0x0f;
	port_or->bitOffsetInFqid = 16;
	params.nextEngine = e_FM_PCD_CC;
	params.kgNextEngineParams.cc.grpId = grp;
	params.kgNextEngineParams.cc.h_CcTree = ps->cctree;
	params.schemeCounter.update = TRUE;

	scheme = FM_PCD_KgSchemeSet(state->h_pcd, &params);
	if (!scheme) {
		pr_err("cdx: %s%s setup failed\n", g->scheme_name, pppoe ? "_pppoe" : "");
		return -EIO;
	}
	if (pppoe)
		id = CDX_PCD_NUM_GROUPS + grp - CDX_PCD_TUPLE_FIRST;
	state->schemes[id] = scheme;
	state->num_schemes++;
	return 0;
}

static int cdx_pcd_set_schemes(struct cdx_pcd_state *state, unsigned int idx)
{
	struct cdx_pcd_port_state *ps = &state->port_state[idx];
	unsigned int grp = ps->group_count;
	int rc;

	while (grp--) {
		if (cdx_pcd_groups[ps->first_group + grp].tunnel_family) {
			rc = cdx_pcd_set_scheme(state, idx, grp, true);
			if (rc)
				return rc;
		}
		rc = cdx_pcd_set_scheme(state, idx, grp, false);
		if (rc)
			return rc;
	}
	return 0;
}

static int cdx_pcd_attach_port(struct cdx_pcd_state *state, unsigned int idx)
{
	struct cdx_pcd_port_state *ps = &state->port_state[idx];
	unsigned int i;
	t_Error err;

	ps->prs.parsingOffset = 0;
	ps->prs.firstPrsHdr = HEADER_TYPE_ETH;
	/* What cdx_sp.xml reads as $logicalportid. */
	ps->prs.prsResultPrivateInfo = state->ports[idx].portid;
	/* Jump to the soft parser for exactly the headers it defines labels
	 * for -- the two lists are the same list. */
	ps->prs.numOfHdrsWithAdditionalParams = CDX_SP_NUM_LABELS;
	for (i = 0; i < CDX_SP_NUM_LABELS; i++) {
		ps->prs.additionalParams[i].hdr = cdx_sp_labels[i].hdr;
		ps->prs.additionalParams[i].swPrsEnable = TRUE;
		ps->prs.additionalParams[i].errDisable = FALSE;
		ps->prs.additionalParams[i].usePrsOpts = FALSE;
		ps->prs.additionalParams[i].indexPerHdr = 0;
	}

	for (i = 0; i < ps->group_count; i++) {
		unsigned int id = ps->first_group + i;

		if (cdx_pcd_groups[id].tunnel_family)
			ps->kg.h_Schemes[ps->kg.numOfSchemes++] =
				state->schemes[CDX_PCD_NUM_GROUPS + i - CDX_PCD_TUPLE_FIRST];
		ps->kg.h_Schemes[ps->kg.numOfSchemes++] = state->schemes[id];
	}
	ps->kg.directScheme = FALSE;

	ps->cc.h_CcTree = ps->cctree;

	ps->pcd.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC;
	ps->pcd.h_NetEnv = state->net_env[!!ps->first_group];
	ps->pcd.p_PrsParams = &ps->prs;
	ps->pcd.p_KgParams = &ps->kg;
	ps->pcd.p_CcParams = &ps->cc;

	err = FM_PORT_GetEnabled(ps->h_port, &ps->was_enabled);
	if (err != E_OK) {
		pr_err("cdx: %s: cannot read port state\n", state->ports[idx].name);
		return -EIO;
	}
	if (FM_PORT_Disable(ps->h_port) != E_OK) {
		pr_err("cdx: %s: cannot stop port\n", state->ports[idx].name);
		return -EIO;
	}
	if (FM_PORT_SetPCD(ps->h_port, &ps->pcd) != E_OK) {
		pr_err("cdx: %s: cannot attach classifier\n", state->ports[idx].name);
		/* Leave it stopped; teardown restores the original state. */
		return -EIO;
	}
	ps->pcd_set = true;
	if (ps->was_enabled && FM_PORT_Enable(ps->h_port) != E_OK) {
		pr_err("cdx: %s: cannot restart port\n", state->ports[idx].name);
		return -EIO;
	}
	return 0;
}

void cdx_pcd_teardown(struct cdx_pcd_state *state)
{
	unsigned int i, grp;
	bool detached = true;

	if (!state->h_pcd)
		return;
	for (i = 0; i < state->num_ports; i++) {
		struct cdx_pcd_port_state *ps = &state->port_state[i];

		if (!ps->pcd_set)
			continue;
		if (FM_PORT_Disable(ps->h_port) != E_OK ||
		    FM_PORT_DeletePCD(ps->h_port) != E_OK) {
			pr_err("cdx: %s: classifier detach failed; reboot required\n",
			       state->ports[i].name);
			detached = false;
		} else {
			ps->pcd_set = false;
		}
	}
	if (!detached)
		return;
	for (i = 0; i < CDX_PCD_NUM_SCHEMES; i++)
		if (state->schemes[i] && FM_PCD_KgSchemeDelete(state->schemes[i]) != E_OK)
			pr_err("cdx: scheme %u release failed\n", i);
	for (i = 0; i < state->num_ports; i++) {
		struct cdx_pcd_port_state *ps = &state->port_state[i];

		if (ps->cctree && FM_PCD_CcRootDelete(ps->cctree) != E_OK)
			pr_err("cdx: %s: classification tree release failed\n", state->ports[i].name);
		for (grp = 0; grp < ps->num_tables; grp++)
			if (FM_PCD_HashTableDelete(ps->tables[grp]) != E_OK)
				pr_err("cdx: %s: table %u release failed\n", state->ports[i].name, grp);
	}
	for (i = 0; i < ARRAY_SIZE(state->net_env); i++)
		if (state->net_env[i] && FM_PCD_NetEnvCharacteristicsDelete(state->net_env[i]) != E_OK)
			pr_err("cdx: network environment %u release failed\n", i);
	for (i = 0; i < state->num_ports; i++) {
		struct cdx_pcd_port_state *ps = &state->port_state[i];

		if (ps->h_port && ps->was_enabled && FM_PORT_Enable(ps->h_port) != E_OK)
			pr_err("cdx: %s: cannot restore port state\n", state->ports[i].name);
	}
	state->h_pcd = NULL;
}

int cdx_pcd_build(u8 fm_index, struct cdx_pcd_state *state)
{
	t_FmPcdPrsSwParams sp = { 0 };
	t_LnxWrpFmDev *fm;
	unsigned int i;
	int count, rc;

	memset(state, 0, sizeof(*state));
	state->fm_index = fm_index;

	count = cdx_pcd_enumerate_ports(fm_index, state->ports,
					CDX_PCD_MAX_PORTS, &state->fm_dev);
	if (count < 0)
		return count;
	state->num_ports = count;

	fm = state->fm_dev;
	state->h_fm = fm->h_Dev;
	state->h_pcd = fm->h_PcdDev;
	if (!state->h_fm || !state->h_pcd) {
		pr_err("cdx: fm%u is not ready (fm_dev %p, h_Dev %p, h_PcdDev %p)\n",
		       fm_index, fm, state->h_fm, state->h_pcd);
		state->h_pcd = NULL;
		return -ENODEV;
	}

	for (i = 0; i < state->num_ports; i++) {
		t_LnxWrpFmPortDev *wport =
			cdx_pcd_wrapper_port(fm, &state->ports[i]);

		if (!wport) {
			pr_err("cdx: %s is not an FMan port cdx can classify\n",
			       state->ports[i].name);
			state->h_pcd = NULL;
			return -ENODEV;
		}
		state->port_state[i].h_port = wport->h_Dev;
		/* devoh assigns OH cell 1 to SEC. The soft parser uses logical
		 * port 9 for the same policy, so refuse an inconsistent override. */
		if (state->ports[i].type == e_FM_PORT_TYPE_OH_OFFLINE_PARSING &&
		    state->ports[i].number == 1) {
			if (state->ports[i].portid != 9)
				return -EINVAL;
			state->port_state[i].first_group = CDX_PCD_SHARED_GROUPS;
			state->port_state[i].group_count = CDX_PCD_SEC_GROUPS;
		} else {
			state->port_state[i].group_count = CDX_PCD_SHARED_GROUPS;
		}
	}

	/* Header manipulation and the exception paths need advanced offload,
	 * and it can only be selected while the PCD is stopped. */
	if (FM_PCD_Disable(state->h_pcd) != E_OK ||
	    FM_PCD_SetAdvancedOffloadSupport(state->h_pcd) != E_OK) {
		pr_err("cdx: fm%u: cannot enable advanced offload\n", fm_index);
		state->h_pcd = NULL;
		return -EIO;
	}

	sp.override = TRUE;
	sp.size = CDX_SP_SIZE;
	sp.base = CDX_SP_BASE;
	sp.p_Code = cdx_sp_code;
	sp.numOfLabels = CDX_SP_NUM_LABELS;
	memcpy(sp.labelsTable, cdx_sp_labels, sizeof(cdx_sp_labels));
	if (FM_PCD_PrsLoadSw(state->h_pcd, &sp) != E_OK) {
		pr_err("cdx: fm%u: soft parser load failed\n", fm_index);
		state->h_pcd = NULL;
		return -EIO;
	}
	if (FM_PCD_Enable(state->h_pcd) != E_OK) {
		pr_err("cdx: fm%u: cannot start PCD\n", fm_index);
		state->h_pcd = NULL;
		return -EIO;
	}

	for (i = 0; i < state->num_ports; i++) {
		bool sec = !!state->port_state[i].first_group;

		if (!state->net_env[sec]) {
			rc = cdx_pcd_set_net_env(state, sec);
			if (rc)
				goto unwind;
		}
		rc = cdx_pcd_set_tables(state, i);
		if (rc)
			goto unwind;
		rc = cdx_pcd_build_cctree(state, i);
		if (rc)
			goto unwind;
	}

	for (i = 0; i < state->num_ports; i++) {
		if (state->schemes[state->port_state[i].first_group])
			continue;
		rc = cdx_pcd_set_schemes(state, i);
		if (rc)
			goto unwind;
	}

	for (i = 0; i < state->num_ports; i++) {
		rc = cdx_pcd_attach_port(state, i);
		if (rc)
			goto unwind;
	}

	pr_info("cdx: fm%u: classifier installed on %u ports, %u schemes\n",
		fm_index, state->num_ports, state->num_schemes);
	return 0;

unwind:
	cdx_pcd_teardown(state);
	return rc;
}

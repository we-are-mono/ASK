// SPDX-License-Identifier: GPL-2.0+
/*
 * Build the ASK FMan PCD.
 *
 * Walks the classification groups in cdx_pcd_desc.c, programming each one
 * through the FM_PCD and FM_PORT entry points. Per FMan:
 *
 *	FM_PCD_Disable, FM_PCD_SetAdvancedOffloadSupport
 *	FM_PCD_PrsLoadSw, FM_PCD_Enable
 *	FM_PCD_NetEnvCharacteristicsSet			(once, shared by all ports)
 *	per port: FM_PCD_HashTableSet x12, FM_PCD_CcRootBuild
 *	FM_PCD_KgSchemeSet x12				(bound to port 0's tree)
 *	per port: FM_PORT_Disable, FM_PORT_SetPCD, FM_PORT_Enable
 *
 * That order is load bearing twice over: the CC root group layout is what
 * cdx_sp.xml addresses by a fixed offset, and a shared scheme can only be bound
 * once its tree exists.
 *
 * Twelve schemes serve every port. They cannot be per-port: the KeyGen has 32
 * schemes and seven ports would need 84. A scheme names a group id, and the CC
 * root tree it dispatches into comes from the receiving port's own
 * FM_PORT_SetPCD, so one scheme serves every port even though its h_CcTree
 * names only the first.
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

static int cdx_pcd_set_net_env(struct cdx_pcd_state *state)
{
	t_FmPcdNetEnvParams params = { 0 };
	unsigned int i;

	params.numOfDistinctionUnits = CDX_PCD_NUM_UNITS;
	for (i = 0; i < CDX_PCD_NUM_UNITS; i++)
		params.units[i].hdrs[0].hdr = cdx_pcd_units[i];

	state->net_env = FM_PCD_NetEnvCharacteristicsSet(state->h_pcd, &params);
	if (!state->net_env) {
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

	for (grp = 0; grp < CDX_PCD_NUM_GROUPS; grp++) {
		const struct cdx_pcd_group *g = &cdx_pcd_groups[grp];
		t_FmPcdHashTableParams params = { 0 };
		t_Handle table;

		params.maxNumOfKeys = CDX_PCD_MAX_NUM_OF_KEYS;
		params.statisticsMode = e_FM_PCD_CC_STATS_MODE_BYTE_AND_FRAME;
		params.hashResMask = g->hash_res_mask;
		params.hashShift = 0;
		params.kgHashShift = 0;
		params.matchKeySize = g->key_size;
		params.table_type = g->table_type;
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

	params->h_NetEnv = state->net_env;
	params->numOfGrps = CDX_PCD_NUM_GROUPS;
	for (grp = 0; grp < CDX_PCD_NUM_GROUPS; grp++) {
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

static int cdx_pcd_set_schemes(struct cdx_pcd_state *state)
{
	unsigned int grp, i;

	for (grp = 0; grp < CDX_PCD_NUM_GROUPS; grp++) {
		const struct cdx_pcd_group *g = &cdx_pcd_groups[grp];
		t_FmPcdKgSchemeParams params = { 0 };
		t_FmPcdKgExtractedOrParams *port_or;
		t_Handle scheme;
		int rc;

		params.modify = FALSE;
		/*
		 * The relative scheme id is the KeyGen's match priority, not a
		 * name: when several schemes match a frame the lowest id wins.
		 * cdx_pcd_groups[] runs from the catch-all L2 group at 0 to the
		 * most specific at 11, so priority is the reverse of it -- ESP
		 * before the L4 5-tuples, those before the 3-tuples, ethernet
		 * last. Assigning the group id here instead would let the L2
		 * bridge scheme swallow every routed flow.
		 */
		params.id.relativeSchemeId = CDX_PCD_NUM_GROUPS - 1 - grp;
		params.shared = TRUE;
		params.alwaysDirect = FALSE;
		params.netEnvParams.h_NetEnv = state->net_env;
		params.netEnvParams.numOfDistinctionUnits = g->num_units;
		for (i = 0; i < g->num_units; i++)
			params.netEnvParams.unitIds[i] = g->units[i];

		params.useHash = TRUE;
		params.keyExtractAndHashParams.numOfUsedExtracts = g->num_extracts;
		for (i = 0; i < g->num_extracts; i++) {
			rc = cdx_pcd_set_extract(
				&params.keyExtractAndHashParams.extractArray[i],
				&g->extracts[i]);
			if (rc) {
				pr_err("cdx: %s: extract %u names an unclassifiable header\n",
				       g->scheme_name, i);
				return rc;
			}
		}
		params.keyExtractAndHashParams.hashDistributionNumOfFqids =
			g->num_fqids;
		params.keyExtractAndHashParams.hashShift = 0;
		params.keyExtractAndHashParams.symmetricHash = FALSE;
		params.keyExtractAndHashParams.numOfUsedMasks = 0;

		params.baseFqid = g->base_fqid;

		/* Fold the ingress port's logical id into FQID bits 16-19, so a
		 * frame's queue identifies the port it arrived on. */
		params.numOfUsedExtractedOrs = 1;
		port_or = &params.extractedOrs[0];
		port_or->type = e_FM_PCD_KG_EXTRACT_PORT_PRIVATE_INFO;
		port_or->extractionOffset = 0;
		port_or->dfltValue = e_FM_PCD_KG_DFLT_GBL_0;
		port_or->mask = 0x0f;
		port_or->bitOffsetInFqid = 16;

		params.nextEngine = e_FM_PCD_CC;
		params.kgNextEngineParams.cc.grpId = grp;
		/* Every port's tree has the same twelve groups in the same
		 * order, and the tree a frame is actually classified against
		 * comes from the receiving port's FM_PORT_SetPCD. */
		params.kgNextEngineParams.cc.h_CcTree =
			state->port_state[0].cctree;
		params.schemeCounter.update = TRUE;
		params.schemeCounter.value = 0;

		scheme = FM_PCD_KgSchemeSet(state->h_pcd, &params);
		if (!scheme) {
			pr_err("cdx: %s: scheme setup failed\n", g->scheme_name);
			return -EIO;
		}
		state->schemes[grp] = scheme;
		state->num_schemes = grp + 1;
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

	ps->kg.numOfSchemes = CDX_PCD_NUM_GROUPS;
	for (i = 0; i < CDX_PCD_NUM_GROUPS; i++)
		ps->kg.h_Schemes[i] = state->schemes[i];
	ps->kg.directScheme = FALSE;

	ps->cc.h_CcTree = ps->cctree;

	ps->pcd.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC;
	ps->pcd.h_NetEnv = state->net_env;
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
	unsigned int i, grp, leaked;

	if (!state->h_pcd)
		return;

	/* Detach before deleting anything the ports still reference. */
	for (i = 0; i < state->num_ports; i++) {
		struct cdx_pcd_port_state *ps = &state->port_state[i];

		if (!ps->pcd_set)
			continue;
		if (FM_PORT_DeletePCD(ps->h_port) != E_OK)
			pr_err("cdx: %s: classifier detach failed\n",
			       state->ports[i].name);
		ps->pcd_set = false;
	}

	for (grp = 0; grp < state->num_schemes; grp++)
		if (FM_PCD_KgSchemeDelete(state->schemes[grp]) != E_OK)
			pr_err("cdx: %s: scheme release failed\n",
			       cdx_pcd_groups[grp].scheme_name);
	state->num_schemes = 0;

	leaked = 0;
	for (i = 0; i < state->num_ports; i++) {
		struct cdx_pcd_port_state *ps = &state->port_state[i];

		if (ps->cctree && FM_PCD_CcRootDelete(ps->cctree) != E_OK)
			pr_err("cdx: %s: classification tree release failed\n",
			       state->ports[i].name);
		ps->cctree = NULL;
		/*
		 * The external hash tables cannot be released. Under
		 * USE_ENHANCED_EHASH the SDK's FM_PCD_HashTableDelete() is a
		 * stub that returns an error ("delete table code not added"),
		 * and it is not exported to modules in that build either. See
		 * ISSUES.md A138. Say so rather than pretending the teardown
		 * was complete.
		 */
		leaked += ps->num_tables;
		ps->num_tables = 0;
	}
	if (leaked)
		pr_err("cdx: %u hash tables cannot be reclaimed in this build; reboot before installing the classifier again\n",
		       leaked);

	if (state->net_env &&
	    FM_PCD_NetEnvCharacteristicsDelete(state->net_env) != E_OK)
		pr_err("cdx: fm%u: network environment release failed\n",
		       state->fm_index);
	state->net_env = NULL;

	/* Restore whatever was running before the build touched the ports. */
	for (i = 0; i < state->num_ports; i++) {
		struct cdx_pcd_port_state *ps = &state->port_state[i];

		if (ps->h_port && ps->was_enabled &&
		    FM_PORT_Enable(ps->h_port) != E_OK)
			pr_err("cdx: %s: cannot restore port state\n",
			       state->ports[i].name);
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
		pr_err("cdx: fm%u is not ready\n", fm_index);
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

	rc = cdx_pcd_set_net_env(state);
	if (rc)
		goto unwind;

	for (i = 0; i < state->num_ports; i++) {
		rc = cdx_pcd_set_tables(state, i);
		if (rc)
			goto unwind;
		rc = cdx_pcd_build_cctree(state, i);
		if (rc)
			goto unwind;
	}

	rc = cdx_pcd_set_schemes(state);
	if (rc)
		goto unwind;

	for (i = 0; i < state->num_ports; i++) {
		rc = cdx_pcd_attach_port(state, i);
		if (rc)
			goto unwind;
	}

	pr_info("cdx: fm%u: classifier installed on %u ports, %u tables\n",
		fm_index, state->num_ports,
		state->num_ports * CDX_PCD_NUM_GROUPS);
	return 0;

unwind:
	cdx_pcd_teardown(state);
	return rc;
}

/* Run the real in-kernel PCD builder on the host and dump what it programs.
 *
 * cdx_pcd.c and cdx_pcd_desc.c are compiled unmodified; only the FMan entry
 * points they call are replaced, with stubs that record their parameters. The
 * dump is compared against tools/host_tests/golden/cdx_pcd_model.json, which is
 * distilled from fmc's own compiled model -- so this asserts that the builder
 * programs the hardware the way fmc did, without needing either fmc or a board.
 *
 * Port discovery is stubbed too: it needs netdevs and the offline-port registry,
 * which do not exist here. The gateway-dk port set is supplied instead, matching
 * the golden's.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* core_ext.h reaches for <linux/smp.h>; the builder needs none of it. The other
 * SDK host fixtures suppress it the same way. */
#define __CORE_EXT_H
#include "cdx_pcd.h"
#include "lnxwrp_fm.h"

/* ---- recording stubs for the FMan entry points --------------------------- */

#define MAX_CALLS 256

static unsigned table_calls, scheme_calls, tree_calls, setpcd_calls;
static unsigned netenv_calls, prs_calls, enable_calls, adv_calls, disable_calls;
static t_FmPcdHashTableParams tables[MAX_CALLS];
static void *table_handles[MAX_CALLS];
static t_FmPcdKgSchemeParams schemes[MAX_CALLS];
static t_FmPcdNetEnvParams netenv;
static t_FmPcdPrsSwParams softparse;
static t_FmPortPcdParams setpcd[CDX_PCD_MAX_PORTS];
static t_FmPortPcdPrsParams setpcd_prs[CDX_PCD_MAX_PORTS];
static uint8_t tree_groups[CDX_PCD_MAX_PORTS];
static void *tree_nodes[CDX_PCD_MAX_PORTS][CDX_PCD_NUM_GROUPS];

/* Handles are opaque to the builder; hand back distinct non-NULL cookies. */
static char cookie_pool[MAX_CALLS * 4];
static unsigned cookies;
static void *cookie(void) { assert(cookies < sizeof(cookie_pool)); return &cookie_pool[cookies++]; }

t_Handle FM_PCD_NetEnvCharacteristicsSet(t_Handle pcd, t_FmPcdNetEnvParams *p)
{ (void)pcd; netenv = *p; netenv_calls++; return cookie(); }

t_Error FM_PCD_NetEnvCharacteristicsDelete(t_Handle h) { (void)h; return E_OK; }

t_Handle FM_PCD_HashTableSet(t_Handle pcd, t_FmPcdHashTableParams *p)
{
	(void)pcd;
	assert(table_calls < MAX_CALLS);
	tables[table_calls] = *p;
	return table_handles[table_calls++] = cookie();
}

t_Handle FM_PCD_KgSchemeSet(t_Handle pcd, t_FmPcdKgSchemeParams *p)
{ (void)pcd; assert(scheme_calls < MAX_CALLS); schemes[scheme_calls++] = *p; return cookie(); }

t_Error FM_PCD_KgSchemeDelete(t_Handle h) { (void)h; return E_OK; }

t_Handle FM_PCD_CcRootBuild(t_Handle pcd, t_FmPcdCcTreeParams *p)
{
	unsigned grp;

	(void)pcd;
	assert(tree_calls < CDX_PCD_MAX_PORTS);
	tree_groups[tree_calls] = p->numOfGrps;
	for (grp = 0; grp < p->numOfGrps && grp < CDX_PCD_NUM_GROUPS; grp++) {
		assert(p->ccGrpParams[grp].nextEnginePerEntriesInGrp[0].nextEngine ==
		       e_FM_PCD_CC);
		tree_nodes[tree_calls][grp] =
			p->ccGrpParams[grp].nextEnginePerEntriesInGrp[0].params.ccParams.h_CcNode;
	}
	tree_calls++;
	return cookie();
}

t_Error FM_PCD_CcRootDelete(t_Handle h) { (void)h; return E_OK; }
t_Error FM_PCD_PrsLoadSw(t_Handle pcd, t_FmPcdPrsSwParams *p)
{ (void)pcd; softparse = *p; prs_calls++; return E_OK; }
t_Error FM_PCD_Enable(t_Handle h) { (void)h; enable_calls++; return E_OK; }
t_Error FM_PCD_Disable(t_Handle h) { (void)h; disable_calls++; return E_OK; }
t_Error FM_PCD_SetAdvancedOffloadSupport(t_Handle h) { (void)h; adv_calls++; return E_OK; }

t_Error FM_PORT_GetEnabled(t_Handle port, bool *enabled)
{ (void)port; *enabled = TRUE; return E_OK; }
t_Error FM_PORT_Disable(t_Handle h) { (void)h; return E_OK; }
t_Error FM_PORT_Enable(t_Handle h) { (void)h; return E_OK; }
t_Error FM_PORT_DeletePCD(t_Handle h) { (void)h; return E_OK; }
t_Error FM_PORT_SetPCD(t_Handle port, t_FmPortPcdParams *p)
{
	(void)port;
	assert(setpcd_calls < CDX_PCD_MAX_PORTS);
	setpcd[setpcd_calls] = *p;
	setpcd_prs[setpcd_calls] = *p->p_PrsParams;
	setpcd_calls++;
	return E_OK;
}

/* ---- stubbed port discovery ---------------------------------------------- */

static t_LnxWrpFmDev fake_fm;

static const struct cdx_pcd_port gateway_dk[] = {
	{ e_FM_PORT_TYPE_RX,		 0, 1,  1,  1, "eth0" },
	{ e_FM_PORT_TYPE_RX,		 0, 4,  4,  1, "eth1" },
	{ e_FM_PORT_TYPE_RX,		 0, 5,  5,  1, "eth2" },
	{ e_FM_PORT_TYPE_RX_10G,	 0, 0,  6, 10, "eth3" },
	{ e_FM_PORT_TYPE_RX_10G,	 0, 1,  7, 10, "eth4" },
	{ e_FM_PORT_TYPE_OH_OFFLINE_PARSING, 0, 1,  9, 0, "dpa-fman0-oh@2" },
	{ e_FM_PORT_TYPE_OH_OFFLINE_PARSING, 0, 2, 10, 0, "dpa-fman0-oh@3" },
};

int cdx_pcd_enumerate_ports(u8 fm_index, struct cdx_pcd_port *ports,
			    unsigned int max_ports, void **fm_dev)
{
	unsigned int i;

	(void)fm_index;
	assert(ARRAY_SIZE(gateway_dk) <= max_ports);
	for (i = 0; i < ARRAY_SIZE(gateway_dk); i++)
		ports[i] = gateway_dk[i];

	/* Mark every port the fixture claims as live in the wrapper, so
	 * cdx_pcd_wrapper_port() resolves it the way it would on a board. */
	fake_fm.h_Dev = &fake_fm;
	fake_fm.h_PcdDev = &fake_fm;
	for (i = 0; i < ARRAY_SIZE(fake_fm.rxPorts); i++) {
		fake_fm.rxPorts[i].active = TRUE;
		fake_fm.rxPorts[i].h_Dev = &fake_fm.rxPorts[i];
	}
	for (i = 0; i < ARRAY_SIZE(fake_fm.opPorts); i++) {
		fake_fm.opPorts[i].active = TRUE;
		fake_fm.opPorts[i].h_Dev = &fake_fm.opPorts[i];
	}
	*fm_dev = &fake_fm;
	return ARRAY_SIZE(gateway_dk);
}

/* ---- the builder, verbatim ----------------------------------------------- */

#include "cdx_pcd_desc.c"
#include "cdx_pcd.c"

/* ---- dump ---------------------------------------------------------------- */

static const char *hdr_name(e_NetHeaderType h)
{
	switch (h) {
	case HEADER_TYPE_ETH: return "HEADER_TYPE_ETH";
	case HEADER_TYPE_IPv4: return "HEADER_TYPE_IPv4";
	case HEADER_TYPE_IPv6: return "HEADER_TYPE_IPv6";
	case HEADER_TYPE_TCP: return "HEADER_TYPE_TCP";
	case HEADER_TYPE_UDP: return "HEADER_TYPE_UDP";
	case HEADER_TYPE_PPPoE: return "HEADER_TYPE_PPPoE";
	case HEADER_TYPE_IPSEC_ESP: return "HEADER_TYPE_IPSEC_ESP";
	default: return "HEADER_TYPE_OTHER";
	}
}

static void dump_extract(const t_FmPcdExtractEntry *e)
{
	uint32_t field = 0;

	switch (e->extractByHdr.hdr) {
	case HEADER_TYPE_ETH: field = e->extractByHdr.extractByHdrType.fullField.eth; break;
	case HEADER_TYPE_IPv4: field = e->extractByHdr.extractByHdrType.fullField.ipv4; break;
	case HEADER_TYPE_IPv6: field = e->extractByHdr.extractByHdrType.fullField.ipv6; break;
	case HEADER_TYPE_TCP: field = e->extractByHdr.extractByHdrType.fullField.tcp; break;
	case HEADER_TYPE_UDP: field = e->extractByHdr.extractByHdrType.fullField.udp; break;
	case HEADER_TYPE_PPPoE: field = e->extractByHdr.extractByHdrType.fullField.pppoe; break;
	case HEADER_TYPE_IPSEC_ESP: field = e->extractByHdr.extractByHdrType.fullField.ipsecEsp; break;
	default: break;
	}
	printf("    extract %s idx=%d field=%u fulltype=%d\n",
	       hdr_name(e->extractByHdr.hdr), (int)e->extractByHdr.hdrIndex,
	       field, (int)e->extractByHdr.type);
}

int main(void)
{
	struct cdx_pcd_state *state;
	unsigned i, grp;

	state = calloc(1, sizeof(*state));
	assert(state);
	assert(cdx_pcd_build(0, state) == 0);

	printf("calls netenv=%u prs=%u adv=%u pcd_disable=%u pcd_enable=%u\n",
	       netenv_calls, prs_calls, adv_calls, disable_calls, enable_calls);
	printf("calls tables=%u schemes=%u trees=%u setpcd=%u ports=%u\n",
	       table_calls, scheme_calls, tree_calls, setpcd_calls, state->num_ports);

	printf("softparse base=%u size=%u labels=%u\n",
	       softparse.base, softparse.size, softparse.numOfLabels);

	printf("netenv units=%u\n", netenv.numOfDistinctionUnits);
	for (i = 0; i < netenv.numOfDistinctionUnits; i++)
		printf("  unit %u %s\n", i, hdr_name(netenv.units[i].hdrs[0].hdr));

	for (i = 0; i < table_calls && i < CDX_PCD_NUM_GROUPS; i++)
		printf("table %u keys=%u stats=%d keysize=%u mask=%u shift=%u type=%u\n",
		       i, tables[i].maxNumOfKeys, (int)tables[i].statisticsMode,
		       tables[i].matchKeySize, tables[i].hashResMask,
		       tables[i].hashShift, tables[i].table_type);

	for (i = 0; i < scheme_calls; i++) {
		const t_FmPcdKgSchemeParams *s = &schemes[i];

		printf("scheme %u relid=%u grp=%u fqid=%u nfq=%u shared=%d units=%u extracts=%u\n",
		       i, s->id.relativeSchemeId, s->kgNextEngineParams.cc.grpId,
		       s->baseFqid,
		       s->keyExtractAndHashParams.hashDistributionNumOfFqids,
		       (int)s->shared, s->netEnvParams.numOfDistinctionUnits,
		       s->keyExtractAndHashParams.numOfUsedExtracts);
		for (grp = 0; grp < s->netEnvParams.numOfDistinctionUnits; grp++)
			printf("    unit %u\n", s->netEnvParams.unitIds[grp]);
		for (grp = 0; grp < s->keyExtractAndHashParams.numOfUsedExtracts; grp++)
			dump_extract(&s->keyExtractAndHashParams.extractArray[grp]);
		printf("    or type=%d mask=%u bitoffset=%u n=%u\n",
		       (int)s->extractedOrs[0].type, s->extractedOrs[0].mask,
		       s->extractedOrs[0].bitOffsetInFqid, s->numOfUsedExtractedOrs);
	}

	/* Each port's tree must reference that port's own twelve tables, in
	 * group order -- this is what a scheme's grpId indexes into, and what
	 * cdx_sp.xml reaches past by a fixed offset. Tables are created twelve
	 * at a time in port order, so port i's group g is creation i*12+g. */
	for (i = 0; i < tree_calls; i++) {
		unsigned ok = 1;

		for (grp = 0; grp < CDX_PCD_NUM_GROUPS; grp++)
			if (tree_nodes[i][grp] !=
			    table_handles[i * CDX_PCD_NUM_GROUPS + grp])
				ok = 0;
		printf("tree %u groups=%u own_tables_in_group_order=%u\n",
		       i, tree_groups[i], ok);
	}

	for (i = 0; i < setpcd_calls; i++)
		printf("setpcd %u support=%d prs_private=%u first=%s addl=%u schemes=%u\n",
		       i, (int)setpcd[i].pcdSupport,
		       setpcd_prs[i].prsResultPrivateInfo,
		       hdr_name(setpcd_prs[i].firstPrsHdr),
		       setpcd_prs[i].numOfHdrsWithAdditionalParams,
		       setpcd[i].p_KgParams->numOfSchemes);

	cdx_pcd_teardown(state);
	free(state);
	return 0;
}

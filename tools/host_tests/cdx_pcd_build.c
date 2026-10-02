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
static t_FmPcdNetEnvParams netenv[2];
static void *netenv_handles[2], *scheme_handles[MAX_CALLS], *tree_handles[MAX_CALLS];
static t_FmPcdPrsSwParams softparse;
static t_FmPortPcdParams setpcd[CDX_PCD_MAX_PORTS];
static t_FmPortPcdPrsParams setpcd_prs[CDX_PCD_MAX_PORTS];
static uint8_t tree_groups[CDX_PCD_MAX_PORTS];
static void *tree_nodes[CDX_PCD_MAX_PORTS][CDX_PCD_NUM_GROUPS];

/* Handles are opaque to the builder; hand back distinct non-NULL cookies. */
static char cookie_pool[MAX_CALLS * 4];
static unsigned cookies, live_cookies, api_calls, fail_at, active_ports;
static bool cookie_live[sizeof(cookie_pool)], port_enabled[7], port_attached[7];
static void *port_handles[7];
static bool fail(void) { return ++api_calls == fail_at; }
static void *cookie(void)
{
	assert(cookies < sizeof(cookie_pool));
	cookie_live[cookies] = true;
	live_cookies++;
	return &cookie_pool[cookies++];
}
static void release(void *h)
{
	unsigned n = (char *)h - cookie_pool;

	assert(!active_ports && n < cookies && cookie_live[n]);
	cookie_live[n] = false;
	live_cookies--;
}
static unsigned port_index(void *h)
{
	unsigned n;

	for (n = 0; n < ARRAY_SIZE(port_handles); n++)
		if (port_handles[n] == h)
			return n;
	abort();
}

t_Handle FM_PCD_NetEnvCharacteristicsSet(t_Handle pcd, t_FmPcdNetEnvParams *p)
{ (void)pcd; if (fail()) return NULL; assert(netenv_calls < 2); netenv[netenv_calls] = *p;
  netenv_handles[netenv_calls] = cookie(); return netenv_handles[netenv_calls++]; }

t_Error FM_PCD_NetEnvCharacteristicsDelete(t_Handle h) { release(h); return E_OK; }

t_Handle FM_PCD_HashTableSet(t_Handle pcd, t_FmPcdHashTableParams *p)
{
	(void)pcd;
	if (fail()) return NULL;
	assert(table_calls < MAX_CALLS);
	tables[table_calls] = *p;
	return table_handles[table_calls++] = cookie();
}

t_Handle FM_PCD_KgSchemeSet(t_Handle pcd, t_FmPcdKgSchemeParams *p)
{ (void)pcd; if (fail()) return NULL; assert(scheme_calls < MAX_CALLS); schemes[scheme_calls] = *p; scheme_handles[scheme_calls] = cookie(); return scheme_handles[scheme_calls++]; }

t_Error FM_PCD_KgSchemeDelete(t_Handle h) { release(h); return E_OK; }

t_Handle FM_PCD_CcRootBuild(t_Handle pcd, t_FmPcdCcTreeParams *p)
{
	unsigned grp;

	(void)pcd;
	if (fail()) return NULL;
	assert(tree_calls < CDX_PCD_MAX_PORTS);
	tree_groups[tree_calls] = p->numOfGrps;
	for (grp = 0; grp < p->numOfGrps && grp < CDX_PCD_NUM_GROUPS; grp++) {
		assert(p->ccGrpParams[grp].nextEnginePerEntriesInGrp[0].nextEngine ==
		       e_FM_PCD_CC);
		tree_nodes[tree_calls][grp] =
			p->ccGrpParams[grp].nextEnginePerEntriesInGrp[0].params.ccParams.h_CcNode;
	}
	tree_handles[tree_calls] = cookie();
	return tree_handles[tree_calls++];
}

t_Error FM_PCD_HashTableDelete(t_Handle h) { release(h); return E_OK; }

t_Error FM_PCD_CcRootDelete(t_Handle h) { release(h); return E_OK; }
t_Error FM_PCD_PrsLoadSw(t_Handle pcd, t_FmPcdPrsSwParams *p)
{ (void)pcd; softparse = *p; prs_calls++; return E_OK; }
t_Error FM_PCD_Enable(t_Handle h) { (void)h; enable_calls++; return E_OK; }
t_Error FM_PCD_Disable(t_Handle h) { (void)h; disable_calls++; return E_OK; }
t_Error FM_PCD_SetAdvancedOffloadSupport(t_Handle h) { (void)h; adv_calls++; return E_OK; }

t_Error FM_PORT_GetEnabled(t_Handle port, bool *enabled)
{ *enabled = port_enabled[port_index(port)]; return E_OK; }
t_Error FM_PORT_Disable(t_Handle h) { port_enabled[port_index(h)] = false; return E_OK; }
t_Error FM_PORT_Enable(t_Handle h) { port_enabled[port_index(h)] = true; return E_OK; }
t_Error FM_PORT_DeletePCD(t_Handle h)
{
	unsigned n = port_index(h);

	assert(!port_enabled[n] && port_attached[n]);
	port_attached[n] = false;
	active_ports--;
	return E_OK;
}
t_Error FM_PORT_SetPCD(t_Handle port, t_FmPortPcdParams *p)
{
	unsigned n = port_index(port);

	assert(!port_enabled[n] && !port_attached[n]);
	if (fail()) return E_INVALID_STATE;
	port_attached[n] = true;
	active_ports++;
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
	for (i = 0; i < ARRAY_SIZE(gateway_dk); i++) {
		const struct cdx_pcd_port *p = &gateway_dk[i];

		port_handles[i] = p->type == e_FM_PORT_TYPE_OH_OFFLINE_PARSING ?
			fake_fm.opPorts[p->number - 1].h_Dev :
			fake_fm.rxPorts[p->number + (p->type == e_FM_PORT_TYPE_RX_10G ?
				FM_MAX_NUM_OF_1G_RX_PORTS : 0)].h_Dev;
		port_enabled[i] = !!(i % 2);
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

	if (e->extractByHdr.type == e_FM_PCD_EXTRACT_FROM_HDR) {
		assert(e->extractByHdr.hdrIndex == e_FM_PCD_HDR_INDEX_1);
		printf("    generic %s offset=%u size=%u\n", hdr_name(e->extractByHdr.hdr),
		       e->extractByHdr.extractByHdrType.fromHdr.offset,
		       e->extractByHdr.extractByHdrType.fromHdr.size);
		return;
	}

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

	for (i = 0; i < netenv_calls; i++) {
		printf("netenv %u units=%u\n", i, netenv[i].numOfDistinctionUnits);
		for (grp = 0; grp < netenv[i].numOfDistinctionUnits; grp++)
			printf("  unit %u %s\n", grp, hdr_name(netenv[i].units[grp].hdrs[0].hdr));
	}

	for (i = 0; i < table_calls; i++)
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
		printf("    defaults n=%u type=%d select=%d value=%u\n",
		       s->keyExtractAndHashParams.numOfUsedDflts,
		       s->keyExtractAndHashParams.dflts[0].type,
		       s->keyExtractAndHashParams.dflts[0].dfltSelect,
		       s->keyExtractAndHashParams.privateDflt1);
		for (grp = 0; grp < netenv_calls; grp++)
			if (netenv_handles[grp] == s->netEnvParams.h_NetEnv)
				printf("    environment %u\n", grp);
		for (grp = 0; grp < tree_calls; grp++)
			if (tree_handles[grp] == s->kgNextEngineParams.cc.h_CcTree)
				printf("    root %u\n", grp);
		printf("    or type=%d mask=%u bitoffset=%u n=%u\n",
		       (int)s->extractedOrs[0].type, s->extractedOrs[0].mask,
		       s->extractedOrs[0].bitOffsetInFqid, s->numOfUsedExtractedOrs);
	}

	unsigned table_base = 0;
	for (i = 0; i < tree_calls; i++) {
		unsigned ok = 1;

		for (grp = 0; grp < tree_groups[i]; grp++)
			if (tree_nodes[i][grp] != table_handles[table_base + grp])
				ok = 0;
		printf("tree %u groups=%u own_tables_in_group_order=%u\n", i, tree_groups[i], ok);
		table_base += tree_groups[i];
	}
	for (i = 0; i < setpcd_calls; i++) {
		printf("setpcd %u support=%d prs_private=%u first=%s addl=%u schemes=%u\n",
		       i, (int)setpcd[i].pcdSupport, setpcd_prs[i].prsResultPrivateInfo,
		       hdr_name(setpcd_prs[i].firstPrsHdr),
		       setpcd_prs[i].numOfHdrsWithAdditionalParams,
		       setpcd[i].p_KgParams->numOfSchemes);
		for (grp = 0; grp < setpcd[i].p_KgParams->numOfSchemes; grp++) {
			unsigned n;

			for (n = 0; n < scheme_calls; n++)
				if (scheme_handles[n] == setpcd[i].p_KgParams->h_Schemes[grp])
					break;
			assert(n < scheme_calls);
			printf("    bound %u\n", schemes[n].id.relativeSchemeId);
		}
	}

	unsigned failure_points = api_calls;

	cdx_pcd_teardown(state);
	assert(!live_cookies && !active_ports);
	for (i = 0; i < ARRAY_SIZE(gateway_dk); i++)
		assert(port_enabled[i] == !!(i % 2));
	/* Fail each environment, table, tree, scheme and port attachment in turn.
	 * Every previously created handle must be released exactly once. */
	for (fail_at = 1; fail_at <= failure_points; fail_at++) {
		cookies = api_calls = 0;
		table_calls = scheme_calls = tree_calls = setpcd_calls = netenv_calls = 0;
		assert(cdx_pcd_build(0, state) == -EIO);
		assert(!live_cookies && !active_ports);
		for (i = 0; i < ARRAY_SIZE(gateway_dk); i++)
			assert(port_enabled[i] == !!(i % 2));
	}
	free(state);
	return 0;
}

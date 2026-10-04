/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/**
 * @file                dpa_cfg.c
 * @description         dpa configuration routines.
 */
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/if_arp.h>
#include <linux/compat.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
//#include <linux/fsl_dpa_classifier.h>
#include "dpaa_eth.h"
#include "mac.h"

#include "cdx.h"
#include "portdefs.h"
#include "misc.h"
#include "lnxwrp_fm.h"
#include "cdx_ceetm_gdef.h"
#include "layer2.h"
#include "cdx_pcd.h"
#include "cdx_flowtable.h"
#include "cdx_devlink.h"

//#define DPA_CFG_DEBUG 	1

//number of Frame managers used
static uint32_t num_fmans;
//pointer to Frame manager info array
struct cdx_fman_info *fman_info;
//frame queue list created
static struct dpa_fq *dpa_pcd_fq;

#define CDX_MAX_FMANS		16

/* table_info.dpa_type. The two hash flavours are FM_PCD_HashTableSet objects;
 * indexed and exact-match tables are FM_PCD_MatchTableSet CC nodes. cdx only
 * builds external hash tables, but the field is part of the descriptor the
 * classifier readers see, so keep the full set. */
#define CDX_DPA_TBL_INTERNAL_HASH	0
#define CDX_DPA_TBL_EXTERNAL_HASH	1
#define CDX_DPA_TBL_INDEXED		2
#define CDX_DPA_TBL_EXACT_MATCH		3

/*
 * Concurrency:
 *   cdx_ctrl_lock_with_rtnl(), then dpa_cfg_lock
 *      - Acquires RTNL and ctrl.mutex without waiting on one while
 *        holding the other; contention restarts before any state change.
 *      - Excludes the flowtable transaction and timers while startup
 *        publishes or unwinds interfaces and classifier metadata.
 *
 *   dpa_cfg_lock (file-local mutex)
 *      - Serializes the one-shot install of the DPA configuration
 *        (fman_info, num_fmans, associated port/table/
 *        distribution sub-allocations). Held for the whole body of
 *        dpa_cfg_install(). release_cfg_info() assumes it
 *        is held by the caller.
 *      - Serializes every change to the classifier ports CDX
 *        configured (dpa_active_ports): the stop and resume of a
 *        datapath restart, the quiesce and restore of unload.
 *
 *   fman_info, num_fmans (file-scope globals)
 *      - Populated exactly once, in dpa_cfg_install() under
 *        dpa_cfg_lock, on the first successful call. A second call
 *        is rejected with -EBUSY. All later readers (dpa_get_tdinfo,
 *        cdx_ingress_*, cdx_get_policer_profile_id,
 *        etc.) observe a stable pointer and count; they run lock-
 *        free on packet paths because the install runs exactly once,
 *        synchronously inside cdx module init, before anything that
 *        reads them can be reached.
 *
 * Contexts:
 *   dpa_cfg_install()                - process, cdx module init.
 *   display_dpa_cfg(), release_cfg_info()
 *                                    - process, called under lock.
 *   dpa_get_*() readers              - any context, lock-free after init.
 */
static DEFINE_MUTEX(dpa_cfg_lock);

#ifdef CDX_DEBUG_DPA_INIT
static unsigned int dpa_init_fail_step;
static unsigned int dpa_init_step;
static char *dpa_init_fail_site;
module_param(dpa_init_fail_step, uint, 0400);
module_param(dpa_init_fail_site, charp, 0400);
MODULE_PARM_DESC(dpa_init_fail_step, "Fail the selected CDX startup acquisition (test image)");
MODULE_PARM_DESC(dpa_init_fail_site, "Restrict startup fault counting to this function (test image)");

bool cdx_dpa_init_fault_at(const char *site)
{
	if (dpa_init_fail_site && strcmp(site, dpa_init_fail_site))
		return false;
	if (++dpa_init_step != dpa_init_fail_step)
		return false;
	pr_info("cdx: injecting DPA startup failure at %s step %u\n", site, dpa_init_step);
	return true;
}
#endif

#ifdef DPA_CFG_DEBUG
//show port related info
static void display_port_info(struct cdx_port_info *pinfo)
{
	uint32_t ii;

	printk("------------------------------------\n");
	printk("port		\t%s\n", pinfo->name);
	printk("fmindex		\t%d\n", pinfo->fm_index);
	printk("pindex		\t%d\n", pinfo->index);
	printk("portid		\t%d\n", pinfo->portid);
	printk("type		\t%dG\n", pinfo->type);
	printk("max_dist	\t%d\n", pinfo->max_dist);
	if (pinfo->max_dist) {
		struct cdx_dist_info *dist_info;
		dist_info = pinfo->dist_info;
		printk("distributions\n");
		for (ii = 0; ii < pinfo->max_dist; ii++) {
			printk("handle		\t%pK\n", dist_info->handle);
			printk("type		\t%d\n", dist_info->type);
			printk("fq_base		\t%x(%d)\n", dist_info->base_fqid,
					dist_info->base_fqid);
			printk("fq_count	\t%d\n", dist_info->count);
			printk("dist_type	\t%d\n", dist_info->type);
			dist_info++;
		}
	}
}

//display classif table info
static void display_tbl_info(struct table_info *tinfo)
{
	printk("===================================\n");
	printk("table		\t%s\n", tinfo->name);
	printk("dpa_type	\t%d\n", tinfo->dpa_type);
	printk("type		\t%d\n", tinfo->type);
	printk("port idx 	\t%x\n", tinfo->port_idx);
	printk("key size	\t%d\n", tinfo->key_size);
	printk("handle		\t%pK\n", tinfo->id);
	//printk("table desc	\t%d\n", tinfo->td);
}

//display entire dpa configuration, ports, tables, dist etc
static void display_dpa_cfg(void)
{	
	uint32_t ii;
	uint32_t jj;
	struct cdx_fman_info *finfo;

	finfo = fman_info;	
	printk("num fm		\t%d\n", num_fmans);
	for (ii = 0; ii < num_fmans; ii++)  {
		struct cdx_port_info *pinfo;
		struct table_info *tinfo;

		printk(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
		printk("fm index	\t%d\n", finfo->index);
		printk("max ports	\t%d\n", finfo->max_ports);
		printk("num tables	\t%d\n", finfo->num_tables);
		printk("fm handle 	\t%pK\n", finfo->fm_handle);
		printk("pcd handle 	\t%pK\n", finfo->pcd_handle);
		pinfo = finfo->portinfo;
		for (jj = 0; jj < finfo->max_ports; jj++) {
			display_port_info(pinfo);
			pinfo++;
		}
		tinfo = finfo->tbl_info;
		for (jj = 0; jj < finfo->num_tables; jj++) {
			display_tbl_info(tinfo);
			tinfo++;
		}
		finfo++;
	}
}
#else
#define display_dpa_cfg()
#endif

int  get_tableInfo_by_portid( int fm_index, int portid,  void **td,  int * flags) 
{
	uint32_t jj;
	struct cdx_fman_info *finfo;
	struct table_info *tinfo;

	/* portid selects a bit in the 32-bit port_idx bitmap; a shift by
	 * >= 32 (or negative -- portid is signed here, unlike the uint32_t
	 * param in the sibling dpa_get_tdinfo) is undefined. Reject
	 * out-of-range ports: no tables are attached to them. */
	if (portid < 0 || portid >= 32)
		return 0;

	finfo = &fman_info[fm_index];
	tinfo = finfo->tbl_info;
	for (jj = 0; jj < finfo->num_tables; jj++) {
		/* port_idx is a bitmap (a table may serve several ports, e.g.
		 * offline/multi-port tables). Match on the bit, mirroring
		 * dpa_get_tdinfo; the old == test only matched single-port
		 * tables and silently dropped multi-port/OH ones. */
		if (tinfo->port_idx & (1U << portid))
		{
			/* type comes from the table_info populated by
			 * dpa_cfg_publish() and is used
			 * both to index td[] and as a shift count for flags.
			 * A malformed config carrying type >= MAX_MATCH_TABLES
			 * would write past td[MAX_MATCH_TABLES] and shift out
			 * of range; skip such an entry rather than corrupt
			 * memory. Valid types (0..MAX_MATCH_TABLES-1) behave
			 * exactly as before. */
			if (tinfo->type < MAX_MATCH_TABLES) {
				td[tinfo->type] = tinfo->id ;
				*flags |= (1 << tinfo->type);
			} else {
				DPA_ERROR("%s::table type %u out of range (>= %u), skipping\n",
						__func__, tinfo->type,
						(uint32_t)MAX_MATCH_TABLES);
			}
		}
		tinfo++;
	}
	return 0;
}

//release all configuration releated resources
static void release_cfg_info(void) __must_hold(&dpa_cfg_lock)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;
	uint32_t jj;

	if (!fman_info)
		return;
	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		//free port information for this fman
		if (finfo->portinfo) {
			struct cdx_port_info *port_info;
			port_info = finfo->portinfo;
			for (jj = 0; jj < finfo->max_ports; jj++) {
				if (port_info->dist_info)
					kfree(port_info->dist_info);
				port_info++;
			}
			kfree(finfo->portinfo);
		}
		//free cc table information for this fman
		if (finfo->tbl_info) {
			kfree(finfo->tbl_info);
		}
		finfo++;
	}
	kfree(fman_info);
	fman_info = NULL;
	num_fmans = 0;
}


static void *get_dist_info_by_fman_params(struct cdx_fman_info *finfo, uint32_t table_type)
{
	struct cdx_port_info *port_info;
	struct cdx_dist_info *dist;
	uint32_t ii, table_distrb_type = 0;
	uint32_t jj;

	DPA_INFO("%s(%d) table type %d \n", __func__,__LINE__, table_type);
	switch (table_type)
	{
		case ETHERNET_TABLE:
			table_distrb_type = ETHERNET_DIST;
			break;
		case IPV4_3TUPLE_UDP_TABLE:
			table_distrb_type =  IPV4_3TUPLE_UDP_DIST;
			break;
		case IPV6_3TUPLE_UDP_TABLE:
			table_distrb_type =  IPV6_3TUPLE_UDP_DIST;
			break;
		case IPV6_MULTICAST_TABLE:
			table_distrb_type =  IPV6_MULTICAST_DIST;
			break;
		case IPV4_MULTICAST_TABLE:
			table_distrb_type =  IPV4_MULTICAST_DIST;
			break;
		case IPV4_BRIDGED_MULTICAST_TABLE:
			table_distrb_type =  IPV4_BRIDGED_MULTICAST_DIST;
			break;
		case IPV6_BRIDGED_MULTICAST_TABLE:
			table_distrb_type =  IPV6_BRIDGED_MULTICAST_DIST;
			break;
	}
	port_info = finfo->portinfo;
	for (ii = 0; ii < finfo->max_ports; ii++) {
		dist = port_info->dist_info;
		for (jj = 0; jj < port_info->max_dist; jj++) {
			if (dist->type == table_distrb_type) {
				DPA_INFO("%s(%d) dist type %d , handle found \n",
						__func__,__LINE__, dist->type);
				return (dist->handle);
			}
			dist++;
		}
		port_info++; 
	}
	return NULL;
}

/* The distribution a table's miss goes to, on the table's own port.
 *
 * A scheme reached from a miss looks its table up in the CC tree of the port
 * the frame came in by, at the group the scheme was built with, so the scheme
 * has to be one that port classifies with. The Ethernet ports and the Wi-Fi
 * offline port share one set of distributions, and for them the scheme found
 * by type is theirs. The IPsec offline port has distributions of its own and
 * none of the shared ones (cdx_pcd.xml): a miss on one of its tables goes to
 * that port's Ethernet distribution instead, whose table is empty and whose
 * miss is the exception policer, where a shared table's chain ends too. So
 * does a miss whose named distribution no port has at all.
 * The builder creates each table once per port, so it serves a single port. */
static void *miss_scheme_on_port(struct cdx_fman_info *finfo,
				 const struct table_info *tbl_info, void *scheme)
{
	struct cdx_port_info *port_info = finfo->portinfo;
	void *ethernet = NULL;
	uint32_t ii, jj;

	if (!tbl_info->port_idx)
		return scheme;
	for (ii = 0; ii < finfo->max_ports; ii++, port_info++) {
		if (port_info->portid >= 32 ||
		    !(tbl_info->port_idx & (1U << port_info->portid)))
			continue;
		for (jj = 0; jj < port_info->max_dist; jj++) {
			if (scheme && port_info->dist_info[jj].handle == scheme)
				return scheme;
			if (port_info->dist_info[jj].type == ETHERNET_DIST)
				ethernet = port_info->dist_info[jj].handle;
		}
		return ethernet;
	}
	return scheme;
}


/* Whether the punt profile meters packets rather than bytes. A devlink trap
 * policer's rate is packets per second, so a caller speaking that unit has to
 * know which one the profile was configured for rather than assume it. */
bool cdx_expt_rate_is_packet_mode(uint32_t fm_index)
{
	if (fm_index >= num_fmans)
		return false;
	return (fman_info + fm_index)->expt_ratelim_mode != EXPT_PKT_LIM_PLCR_MODE_BYTE;
}

/* What the punt profile of one exception type was programmed with: a limit and
 * the burst every type shares, in whichever unit expt_ratelim_mode says. Only a
 * profile that exists answers -- a type configured DISABLE_EXPT_PROFILE was
 * never created -- so a caller reporting it never reports a meter that is not
 * there. */
int cdx_expt_rate_config(uint32_t fm_index, uint32_t type, uint32_t *limit,
			 uint32_t *burst)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= num_fmans || type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return FAILURE;
	finfo = (fman_info + fm_index);
	if (!finfo->expt_rate_limit_info[type].handle)
		return FAILURE;
	*limit = finfo->expt_rate_limit_info[type].limit;
	*burst = finfo->expt_ratelim_burst_size;
	return SUCCESS;
}

/* The colours the punt profile counted. Read without clearing, as everywhere
 * else. */
int cdx_expt_rate_counters(uint32_t fm_index, uint32_t type,
			   struct cdx_police_counters *out)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= num_fmans || type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return FAILURE;
	finfo = (fman_info + fm_index);
	if (!finfo->expt_rate_limit_info[type].handle)
		return FAILURE;
	cdx_plcr_colours(finfo->expt_rate_limit_info[type].handle, out);
	return SUCCESS;
}

int cdx_set_expt_rate(uint32_t fm_index, uint32_t type, uint32_t limit, uint32_t burst_size)
{
	struct cdx_fman_info *finfo;
	uint32_t old_limit;

	if (fm_index >= num_fmans)
		return -1;
	if (type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return -1;
	finfo = (fman_info + fm_index);
	if (!finfo->expt_rate_limit_info[type].handle)
		return -1;
	old_limit = finfo->expt_rate_limit_info[type].limit;
	finfo->expt_rate_limit_info[type].limit = limit;
	finfo->expt_ratelim_burst_size = burst_size;
	if (cdxdrv_modify_missaction_policer_profile(finfo, type)) {
		finfo->expt_rate_limit_info[type].limit = old_limit;
		return -1;
	}
	return 0;
}


static int cdxdrv_set_miss_action(uint32_t fm_index)
{
	struct cdx_fman_info *finfo;
	struct table_info *tbl_info;
	uint32_t ii;

	finfo = (fman_info + fm_index);
	tbl_info = finfo->tbl_info;
	//based on gathered table info, set miss action for all tables
#ifdef DPA_CFG_DEBUG
	DPA_INFO("%s::tables %d\n", __func__, finfo->num_tables);
#endif
	for (ii = 0; ii < finfo->num_tables; ii++) {
		t_FmPcdCcNextEngineParams miss_engine_params;

		/*
		 * FM_PCD_HashTableModifyMissNextEngine() below is a hash-table
		 * only op: it treats the handle as an FM_PCD_HashTableSet object
		 * and reads h_Ad from it. INDEXED / EXACT_MATCH tables are CC
		 * nodes (FM_PCD_MatchTableSet); passing one of their handles here
		 * would dereference at the wrong offset -- a near-NULL MMIO read
		 * that can fault at boot. Only internal/external hash tables carry
		 * this miss action, so skip everything else.
		 */
		if ((tbl_info->dpa_type != CDX_DPA_TBL_INTERNAL_HASH) &&
		    (tbl_info->dpa_type != CDX_DPA_TBL_EXTERNAL_HASH)) {
			tbl_info++;
			continue;
		}
		memset(&miss_engine_params, 0, sizeof(t_FmPcdCcNextEngineParams));
#ifdef DPA_CFG_DEBUG
		DPA_INFO("%s::tbl %s %pK changing miss action\n", __func__,
				tbl_info->name, tbl_info->id);
#endif
		// RTP relay enabled
#ifdef DPA_CFG_DEBUG
		DPA_INFO("%s::RTP relay enabled,  changing miss action\n", __func__);
#endif
		switch (tbl_info->type)
		{
			case IPV4_UDP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme = 
					get_dist_info_by_fman_params(finfo, IPV4_3TUPLE_UDP_TABLE);
				break;
			case IPV6_UDP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme = 
					get_dist_info_by_fman_params(finfo, IPV6_3TUPLE_UDP_TABLE);
				break;
			case ESP_IPV4_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo, IPV4_MULTICAST_TABLE);
				break;
			case ESP_IPV6_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo, IPV6_MULTICAST_TABLE);
				break;
			case IPV4_MULTICAST_TABLE:
			case IPV6_MULTICAST_TABLE:
				/* A frame no routed group claims is offered to
				 * the bridged groups next, whose key carries the
				 * frame's Ethernet pair and so cannot share this
				 * table. A routed group's ingress is never a
				 * bridge port and a bridged group's always is,
				 * so no frame is a candidate for both. A
				 * configuration without the bridged tables falls
				 * straight through to Ethernet, as it always did,
				 * and bridged groups then cannot be installed. */
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo,
						tbl_info->type == IPV4_MULTICAST_TABLE ?
						IPV4_BRIDGED_MULTICAST_TABLE :
						IPV6_BRIDGED_MULTICAST_TABLE);
				if (!miss_engine_params.params.kgParams.h_DirectScheme)
					miss_engine_params.params.kgParams.h_DirectScheme =
						get_dist_info_by_fman_params(finfo, ETHERNET_TABLE);
				break;
			case IPV4_BRIDGED_MULTICAST_TABLE:
			case IPV6_BRIDGED_MULTICAST_TABLE:
			case IPV4_3TUPLE_UDP_TABLE:
			case IPV6_TCP_TABLE:
			case IPV4_TCP_TABLE:
			case IPV6_3TUPLE_UDP_TABLE:
				miss_engine_params.params.kgParams.h_DirectScheme =
					get_dist_info_by_fman_params(finfo, ETHERNET_TABLE);
				break;

		}
		//adding miss action
		//get ethernet distribution scheme handle
		if((tbl_info->type != ETHERNET_TABLE) && (tbl_info->type != PPPOE_RELAY_TABLE)) {
			miss_engine_params.params.kgParams.h_DirectScheme =
				miss_scheme_on_port(finfo, tbl_info,
					miss_engine_params.params.kgParams.h_DirectScheme);
			if (miss_engine_params.params.kgParams.h_DirectScheme == NULL) {
				DPA_ERROR("%s::error finding direct dist for table %s\n",
						__func__, tbl_info->name);
				return -1;
			}
			miss_engine_params.nextEngine = e_FM_PCD_KG;
#ifdef CDX_DPA_DEBUG
			DPA_INFO("%s::changing miss action table %s as KG scheme %pK\n",
					__func__, tbl_info->name,
					miss_engine_params.params.kgParams.h_DirectScheme);
#endif
		} else {
			//adding miss action as policer
			miss_engine_params.nextEngine = e_FM_PCD_PLCR;
			//shared profile
			miss_engine_params.params.plcrParams.sharedProfile = 1;
			//get policer profile id for CP traffic
			miss_engine_params.params.plcrParams.newRelativeProfileId =
				CDX_EXPT_ETH_RATELIMIT;
#ifdef CDX_DPA_DEBUG
			DPA_INFO("%s::changing miss action table %s as policer, profile %d\n",
					__func__, tbl_info->name,
					miss_engine_params.params.plcrParams.newRelativeProfileId);
#endif
		}
		if (FM_PCD_HashTableModifyMissNextEngine(tbl_info->id,
					&miss_engine_params) != E_OK)
		{
			DPA_ERROR("%s::error changing miss action table %s\n",
					__func__, tbl_info->name);
			return -1;
		}
		tbl_info++;
	}
	return 0;
}


struct dpa_init_port {
	t_Handle handle;
	/* The port's own name (fm0-port-rx6, ...), for a report. */
	const char *name;
	bool enabled;
	/* An Rx port belongs to a netdev, whose own state also decides whether
	 * a resume enables it again; an offline port has none. */
	bool rx;
	/* The ICID the port stamps into the frames it enqueues, as the FMan
	 * held it when the port was resolved, or a negative errno. */
	int icid;
};

/* Where the classifier ports CDX configured stand. A stopped port is only
 * disabled, so it can be enabled again exactly as it was. Detaching one is not
 * undone the same way -- FM_PORT_DetachPCD() drops the actions reattaching it
 * would need -- and draining retires its queues, so a port that has been
 * through either stays stopped until unload. */
enum dpa_ports_state {
	DPA_PORTS_RUNNING,
	DPA_PORTS_STOPPED,	/* disabled and fenced, resumable */
	DPA_PORTS_DETACHING,	/* detach attempted; never resumed */
	DPA_PORTS_QUIESCED,	/* detached and drained, for good */
};

struct dpa_init_ports {
	struct dpa_init_port *entries;
	uint32_t count;
	enum dpa_ports_state state;
	/* The FMans the ports are on, whose other ports a stop has to prove
	 * reach no classifier either. */
	t_LnxWrpFmDev *fms[CDX_MAX_FMANS];
	uint32_t num_fms;
};

static struct dpa_init_ports dpa_active_ports;

/* How long a stop waits for the ports to finish the frames they have in hand
 * before it reports them busy, and how often it looks. */
#define DPA_STOP_WAIT_US	200000
#define DPA_STOP_POLL_US	1000

static bool dpa_port_listed(const struct dpa_init_ports *ports, t_Handle handle)
{
	uint32_t ii;

	for (ii = 0; ii < ports->count; ii++)
		if (ports->entries[ii].handle == handle)
			return true;
	return false;
}

/* A port in use that is not one of CDX's own and hands its frames to a PCD,
 * which would walk the classifier tables however CDX's ports stood. One that
 * cannot say is counted as one that does. */
static bool dpa_port_uncovered(const struct dpa_init_ports *ports,
		const t_LnxWrpFmPortDev *port)
{
	bool attached;

	if (!port->active || !port->h_Dev || dpa_port_listed(ports, port->h_Dev))
		return false;
	if (FM_PORT_IsPcdAttached(port->h_Dev, &attached))
		return true;
	return attached;
}

/* Whether stopping CDX's own ports stops everything that reaches a
 * classifier: no other Rx or offline port on their FMans has a PCD. The
 * host-command port is in neither array and needs no proof -- no PCD can be
 * set on it -- so it stays enabled to carry the barriers. Names the first port
 * that breaks the rule. */
static bool dpa_ports_cover(const struct dpa_init_ports *ports,
		const char **kind, uint32_t *index)
{
	uint32_t ii, jj;

	for (ii = 0; ii < ports->num_fms; ii++) {
		const t_LnxWrpFmDev *fm = ports->fms[ii];

		for (jj = 0; jj < ARRAY_SIZE(fm->opPorts); jj++)
			if (dpa_port_uncovered(ports, &fm->opPorts[jj])) {
				*kind = "offline";
				*index = jj + 1;
				return false;
			}
		for (jj = 0; jj < ARRAY_SIZE(fm->rxPorts); jj++)
			if (dpa_port_uncovered(ports, &fm->rxPorts[jj])) {
				*kind = "rx";
				*index = jj;
				return false;
			}
	}
	return true;
}

/* Resolve every port before stopping any of them. These are the same port
 * indices used by FMC's device nodes; the OH host-command port is excluded. */
static int dpa_prepare_ports(t_LnxWrpFmDev **wrappers,
		struct dpa_init_ports *ports)
{
	const char *kind;
	uint32_t ii, jj, count = 0;

	for (ii = 0; ii < num_fmans; ii++)
		count += fman_info[ii].max_ports;
	ports->entries = kcalloc(count, sizeof(*ports->entries), GFP_KERNEL);
	if (!ports->entries)
		return -ENOMEM;
	for (ii = 0; ii < num_fmans; ii++) {
		t_LnxWrpFmDev *fm = wrappers[ii];

		ports->fms[ports->num_fms++] = fm;
		for (jj = 0; jj < fman_info[ii].max_ports; jj++) {
			struct cdx_port_info *info = &fman_info[ii].portinfo[jj];
			t_LnxWrpFmPortDev *port;
			uint32_t index = info->index;

			if (info->fm_index != fm->id)
				return -EINVAL;
			switch (info->type) {
			case 0:
				if (!index || index > ARRAY_SIZE(fm->opPorts))
					return -EINVAL;
				port = &fm->opPorts[index - 1];
				break;
			case 10:
				if (index >= FM_MAX_NUM_OF_10G_RX_PORTS)
					return -EINVAL;
				port = &fm->rxPorts[index + FM_MAX_NUM_OF_1G_RX_PORTS];
				break;
			case 1:
				if (index >= FM_MAX_NUM_OF_1G_RX_PORTS)
					return -EINVAL;
				port = &fm->rxPorts[index];
				break;
			default:
				return -EINVAL;
			}
			if (!port->active || !port->h_Dev)
				return -ENODEV;
			ports->entries[ports->count].handle = port->h_Dev;
			ports->entries[ports->count].name = port->name;
			ports->entries[ports->count].rx = info->type != 0;
			ports->entries[ports->count].icid =
				fm_port_get_icid((struct fm_port *)port);
			if (FM_PORT_GetEnabled(port->h_Dev, &ports->entries[ports->count].enabled))
				return -EIO;
			ports->count++;
		}
	}
	/* Said once, here, rather than only when a stop needs it: such a port
	 * leaves every unproven deletion to a reboot. */
	if (!dpa_ports_cover(ports, &kind, &jj))
		pr_warn("cdx: %s port %u reaches a classifier CDX did not configure; a failed classifier deletion will need a reboot\n",
			kind, jj);
	return 0;
}

static int dpa_set_ports_enabled(struct dpa_init_ports *ports, bool enabled)
{
	uint32_t ii;
	int ret = 0;

	for (ii = 0; ii < ports->count; ii++) {
		bool restore_enabled = enabled && ports->entries[ii].enabled;
		t_Error err = restore_enabled ? FM_PORT_Enable(ports->entries[ii].handle) :
			FM_PORT_Disable(ports->entries[ii].handle);

		if (err) {
			DPA_ERROR("%s::cannot %s port %u\n", __func__,
					enabled ? "enable" : "disable", ii);
			ret = -EIO;
		}
	}
	return ret;
}

static void dpa_release_pcd_fqs(void)
{
	cdx_destroy_fq_list(&dpa_pcd_fq);
	cdx_reset_offline_ports();
}

/* Producer ports must be stopped and detached from PCD before this runs.
 * Keep FMAN/MURAM metadata alive until all dependent resources are gone. */
static int dpa_rollback_resources(void)
{
	uint32_t ii;
	int ret;

	/* First, while every profile it programs and counts still exists: its
	 * callbacks reach them through handles released further down. */
	cdx_devlink_detach();
	dpa_release_pcd_fqs();
	for (ii = 0; ii < MAX_PHY_PORTS; ii++) {
		if (phy_port[ii].flags) {
			remove_onif_by_index(phy_port[ii].itf.index);
			memset(&phy_port[ii], 0, sizeof(phy_port[ii]));
			phy_port[ii].id = ii;
		}
	}
	ret = cdxdrv_release_port_policer_slots();
	for (ii = 0; ii < num_fmans; ii++)
		if (cdxdrv_release_shared_policers(&fman_info[ii]))
			ret = -EIO;
	dpa_release_iflist();
	return ret;
}


/* Detach the classifier before releasing its FQs. Restored ports can then
 * use the Linux default path while the builder removes the failed configuration. */
static int dpa_detach_ports(struct dpa_init_ports *ports)
{
	uint32_t ii;
	int ret = 0;

	for (ii = 0; ii < ports->count; ii++)
		if (FM_PORT_DetachPCD(ports->entries[ii].handle))
			ret = -EIO;
	return ret;
}

/* While fenced, nothing but CDX can enable a port: not the netdev's open, a
 * resume or the FMan character device. */
static void dpa_ports_fence(struct dpa_init_ports *ports, bool fenced)
{
	uint32_t ii;

	for (ii = 0; ii < ports->count; ii++)
		if (FM_PORT_SetFenced(ports->entries[ii].handle, fenced))
			DPA_ERROR("%s::cannot %sfence port %u\n", __func__,
					fenced ? "" : "un", ii);
}

/* Wait until no port has a frame in hand. FM_PORT_Disable() waits a bounded
 * time for that and then reports success anyway, so a disabled port is not yet
 * a stopped one. */
static int dpa_ports_wait_stopped(struct dpa_init_ports *ports)
{
	unsigned int waited = 0;
	uint32_t ii;
	bool stopped;

	for (;;) {
		for (ii = 0; ii < ports->count; ii++) {
			if (FM_PORT_GetStopped(ports->entries[ii].handle, &stopped))
				return -EIO;
			if (!stopped)
				break;
		}
		if (ii == ports->count)
			return 0;
		if (waited >= DPA_STOP_WAIT_US)
			return -EBUSY;
		usleep_range(DPA_STOP_POLL_US, 2 * DPA_STOP_POLL_US);
		waited += DPA_STOP_POLL_US;
	}
}

/* Disable every port and wait until none has a frame in hand. The first stop
 * records which ports were enabled, for whoever starts them again. The ports
 * are fenced before they are disabled, and every call disables them all again,
 * which also stops one an enable racing the fence switched back on. */
static int dpa_ports_stop(struct dpa_init_ports *ports)
{
	uint32_t ii;

	if (ports->state == DPA_PORTS_RUNNING) {
		for (ii = 0; ii < ports->count; ii++)
			if (FM_PORT_GetEnabled(ports->entries[ii].handle,
					       &ports->entries[ii].enabled))
				return -EIO;
		ports->state = DPA_PORTS_STOPPED;
	}
	dpa_ports_fence(ports, true);
	if (dpa_set_ports_enabled(ports, false))
		return -EIO;
	return dpa_ports_wait_stopped(ports);
}

/* Whether the netdev an Rx port belongs to is up, in whichever namespace it
 * now lives, with its name copied out for a report. One an operator took down
 * while the port was stopped had the port disabled by its own stop, and
 * nothing starts it again under the netdev; a port no netdev owns (name left
 * empty) is left to what the stop recorded. RTNL held, which keeps every
 * netdev where it is; the namespaces are walked under RCU. */
static bool dpa_rx_port_wanted(t_Handle handle, char name[IFNAMSIZ])
{
	struct net_device *dev;
	struct net *net;
	bool wanted = true;

	ASSERT_RTNL();
	name[0] = '\0';
	rcu_read_lock();
	for_each_net_rcu(net) {
		for_each_netdev_rcu(net, dev) {
			struct dpa_priv_s *priv;

			if (dev->type != ARPHRD_ETHER || !dpa_netdev_is_dpaa(dev))
				continue;
			priv = netdev_priv(dev);
			if (priv->mac_dev && priv->mac_dev->port_dev[RX] &&
			    fm_port_get_handle(priv->mac_dev->port_dev[RX]) == handle) {
				wanted = netif_running(dev);
				strscpy(name, dev->name, IFNAMSIZ);
				goto out;
			}
		}
	}
out:
	rcu_read_unlock();
	return wanted;
}

/* Take the fence down and start the ports as a stop found them: an offline
 * port if it was enabled then, an Rx port if it was and its netdev is still
 * up. Returns how many would not start, each named in the log; the others
 * start all the same. RTNL and dpa_cfg_lock held. */
static unsigned int dpa_ports_start(struct dpa_init_ports *ports)
{
	unsigned int failed = 0;
	uint32_t ii;

	dpa_ports_fence(ports, false);
	for (ii = 0; ii < ports->count; ii++) {
		struct dpa_init_port *port = &ports->entries[ii];
		char name[IFNAMSIZ] = "";

		if (!port->enabled || (port->rx && !dpa_rx_port_wanted(port->handle, name)))
			continue;
		if (FM_PORT_Enable(port->handle)) {
			DPA_ERROR("cdx: cannot start port %s%s%s again\n", port->name,
				  name[0] ? " of " : "", name);
			failed++;
		}
	}
	return failed;
}

/* Stop the classifier ports for a repair of the tables they walk, keeping what
 * starting them again needs. Never detaches a port or drains a queue. RTNL and
 * the control mutex held; idempotent.
 *
 * 0: every port is disabled and fenced and has no frame in hand, and no port
 * CDX did not configure reaches a classifier, so nothing but host commands
 * walks the tables until dpa_cfg_resume(). -EBUSY: disabled, but a port is
 * still finishing a frame; ask again. -EXDEV: another port reaches a
 * classifier, and stopping CDX's own proves nothing about the tables.
 * -ENOTRECOVERABLE: stopped, and with no such port, but the ports have been
 * detached and can never be resumed. */
int dpa_cfg_stop(void)
{
	struct dpa_init_ports *ports = &dpa_active_ports;
	const char *kind;
	uint32_t index;
	int ret = 0;

	mutex_lock(&dpa_cfg_lock);
	if (ports->state != DPA_PORTS_QUIESCED) {
		ret = dpa_ports_stop(ports);
		if (ret)
			goto out;
	}
	if (!dpa_ports_cover(ports, &kind, &index)) {
		pr_err_ratelimited("cdx: %s port %u reaches a classifier CDX did not configure; stopping CDX's ports does not stop it\n",
				   kind, index);
		ret = -EXDEV;
	} else if (ports->state != DPA_PORTS_STOPPED) {
		ret = -ENOTRECOVERABLE;
	}
out:
	mutex_unlock(&dpa_cfg_lock);
	return ret;
}

/* Whether CDX's own ports are every port that reaches a classifier, for an
 * unload that has detached them and would settle what the tables may still
 * link. */
bool dpa_cfg_covered(void)
{
	const char *kind;
	uint32_t index;
	bool covered;

	mutex_lock(&dpa_cfg_lock);
	covered = dpa_ports_cover(&dpa_active_ports, &kind, &index);
	mutex_unlock(&dpa_cfg_lock);
	return covered;
}

/* The ICID every producer of an IPsec job shares, or a negative errno.
 *
 * SEC shares a shared descriptor -- and the ESP sequence number and the
 * counter-mode IV stored in it -- only among jobs whose frames carry one ICID
 * (SEC RM 7.3.2). An SA's jobs come from the classifier ports CDX configured
 * and from every CPU's software portal, so all of them must agree: otherwise
 * SERIAL sharing orders nothing between two producers, both encrypt from the
 * same stored number, and the peer sees replays -- for GCM, a repeated nonce
 * under one key. The boot firmware assigns these ICIDs and nothing here can
 * repair them, so a disagreement is reported once and leaves IPsec offload
 * off. The Wi-Fi storage profile copies its Rx port's value (vsp_cfg.c) and
 * feeds no SEC job. */
int dpa_cfg_shared_icid(void)
{
	const struct dpa_init_ports *ports = &dpa_active_ports;
	int icid = -ENODEV, ficid;
	unsigned int cpu;
	uint32_t ii;

	mutex_lock(&dpa_cfg_lock);
	for (ii = 0; ii < ports->count; ii++) {
		const struct dpa_init_port *port = &ports->entries[ii];

		if (port->icid < 0) {
			pr_err("cdx: cannot read %s's ICID: %d\n", port->name, port->icid);
			icid = port->icid;
			break;
		}
		if (icid >= 0 && port->icid != icid) {
			pr_err("cdx: %s enqueues with ICID %d, other classifier ports with %d\n",
			       port->name, port->icid, icid);
			icid = -EINVAL;
			break;
		}
		icid = port->icid;
	}
	mutex_unlock(&dpa_cfg_lock);
	if (icid < 0)
		return icid;
	for_each_cpu(cpu, qman_affine_cpus()) {
		ficid = qman_portal_ficid(qman_affine_channel(cpu));
		if (ficid != icid) {
			pr_err("cdx: CPU %u's QMan portal enqueues with ICID %d, the classifier ports with %d\n",
			       cpu, ficid, icid);
			return -EINVAL;
		}
	}
	return icid;
}

/* Start the ports a stop left, as they were before it: an offline port if it
 * was enabled then, an Rx port if it was and its netdev is still up. The fence
 * comes off first. RTNL and the control mutex held. -ENOTRECOVERABLE for ports
 * that have been detached, which this would start on a path nothing
 * configured; otherwise how many ports would not start, each named in the log,
 * the others started all the same. */
int dpa_cfg_resume(void)
{
	struct dpa_init_ports *ports = &dpa_active_ports;
	int ret = 0;

	ASSERT_RTNL();
	mutex_lock(&dpa_cfg_lock);
	if (ports->state == DPA_PORTS_RUNNING)
		goto out;
	if (ports->state != DPA_PORTS_STOPPED) {
		ret = -ENOTRECOVERABLE;
		goto out;
	}
	ret = dpa_ports_start(ports);
	ports->state = DPA_PORTS_RUNNING;
out:
	mutex_unlock(&dpa_cfg_lock);
	return ret;
}

/* Stop the ports for good, for unload: stopped as dpa_cfg_stop() stops them,
 * keeping what an earlier stop recorded, then detached from the classifier and
 * their queues drained. Caller holds RTNL and the control mutex; preserve
 * current stack state. */
int dpa_cfg_quiesce(void)
{
	struct dpa_init_ports *ports = &dpa_active_ports;
	int ret = 0;

	mutex_lock(&dpa_cfg_lock);
	if (ports->state == DPA_PORTS_QUIESCED)
		goto out;
	ret = dpa_ports_stop(ports);
	if (ret)
		goto out;
	ports->state = DPA_PORTS_DETACHING;
	if (dpa_detach_ports(ports)) {
		ret = -EIO;
		goto out;
	}
	/* Wi-Fi still holds these FQ pointers until its exit callback restores
	 * their drain callbacks. Reclaim frames now, retain storage until then. */
	cdx_drain_fq_list(dpa_pcd_fq);
	ports->state = DPA_PORTS_QUIESCED;
out:
	mutex_unlock(&dpa_cfg_lock);
	return ret;
}

void dpa_cfg_deinit(void)
{
	cdx_ctrl_lock_with_rtnl();
	if (dpa_cfg_quiesce()) {
		pr_err("cdx: cannot quiesce DPA resources; reboot required\n");
		goto out;
	}
	mutex_lock(&dpa_cfg_lock);
	if (fman_info) {
		if (dpa_rollback_resources())
			pr_err("cdx: DPA resource cleanup failed\n");
		/* Detached, so back to Linux's own path; nothing CDX does
		 * keeps them stopped any more. A netdev taken down while they
		 * were stopped keeps its Rx port down. */
		if (dpa_ports_start(&dpa_active_ports))
			pr_err("cdx: cannot restore port state\n");
		release_cfg_info();
	}
	kfree(dpa_active_ports.entries);
	memset(&dpa_active_ports, 0, sizeof(dpa_active_ports));
	mutex_unlock(&dpa_cfg_lock);
out:
	cdx_ctrl_unlock_with_rtnl();
}


/* Exception-path rate limits at startup; cdx_set_expt_rate() overrides them. */
#define CDX_EXPT_ETH_DEFA_LIMIT		195312	/* 100 Mbps */
#define CDX_EXPT_RATELIM_MODE		EXPT_PKT_LIM_PLCR_MODE_PKT
#define CDX_EXPT_BURST_SIZE		64

static void dpa_cfg_set_expt_defaults(struct cdx_fman_info *finfo)
{
	uint32_t ii;

	finfo->expt_ratelim_mode = CDX_EXPT_RATELIM_MODE;
	finfo->expt_ratelim_burst_size = CDX_EXPT_BURST_SIZE;
	for (ii = 0; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++) {
		finfo->expt_rate_limit_info[ii].limit =
			(ii == CDX_EXPT_ETH_RATELIMIT) ? CDX_EXPT_ETH_DEFA_LIMIT :
							 DISABLE_EXPT_PROFILE;
		finfo->expt_rate_limit_info[ii].handle = NULL;
	}
}

/*
 * Publish what the builder programmed as the classifier metadata the rest of
 * cdx reads: one record per port, the distribution handles interfaces are
 * registered with, and a table descriptor per port per group.
 */
static int dpa_cfg_publish(struct cdx_pcd_state *state)
{
	t_LnxWrpFmDev *fm = state->fm_dev;
	struct cdx_fman_info *finfo;
	struct table_info *tbl;
	uint32_t i, grp;

	fman_info = kcalloc(1, sizeof(*fman_info), GFP_KERNEL);
	if (!fman_info)
		return -ENOMEM;
	num_fmans = 1;

	finfo = &fman_info[0];
	finfo->index = state->fm_index;
	finfo->max_ports = state->num_ports;
	finfo->pcd_handle = fm->h_PcdDev;
	finfo->fm_handle = fm->h_Dev;
	finfo->muram_handle = fm->h_MuramDev;
	finfo->physicalMuramBase = fm->fmMuramPhysBaseAddr;
	finfo->fmMuramMemSize = fm->fmMuramMemSize;

	finfo->portinfo = kcalloc(state->num_ports, sizeof(*finfo->portinfo),
				  GFP_KERNEL);
	if (!finfo->portinfo)
		return -ENOMEM;
	for (i = 0; i < state->num_ports; i++)
		finfo->num_tables += state->port_state[i].num_tables;
	finfo->tbl_info = kcalloc(finfo->num_tables, sizeof(*finfo->tbl_info),
				  GFP_KERNEL);
	if (!finfo->tbl_info)
		return -ENOMEM;

	tbl = finfo->tbl_info;
	for (i = 0; i < state->num_ports; i++) {
		struct cdx_port_info *pinfo = &finfo->portinfo[i];
		struct cdx_pcd_port_state *ps = &state->port_state[i];
		struct cdx_dist_info *dist;

		pinfo->fm_index = state->fm_index;
		pinfo->index = state->ports[i].number;
		pinfo->portid = state->ports[i].portid;
		pinfo->type = state->ports[i].speed;
		pinfo->max_dist = ps->num_tables +
			(ps->first_group ? 0 : CDX_PCD_TUPLE_COUNT);
		strscpy(pinfo->name, state->ports[i].name, sizeof(pinfo->name));

		/* port_idx is a bitmap of the ports a table serves, and
		 * dpa_get_tdinfo() shifts by the logical port id. */
		if (pinfo->portid >= sizeof(tbl->port_idx) * 8) {
			DPA_ERROR("%s::port id %u exceeds the table bitmap\n",
				  __func__, pinfo->portid);
			return -EINVAL;
		}

		dist = kcalloc(pinfo->max_dist, sizeof(*dist), GFP_KERNEL);
		if (!dist)
			return -ENOMEM;
		pinfo->dist_info = dist;

		for (grp = 0; grp < ps->num_tables; grp++) {
			const struct cdx_pcd_group *g = &cdx_pcd_groups[ps->first_group + grp];

			dist->type = g->dist_type;
			dist->handle = state->schemes[ps->first_group + grp];
			dist->base_fqid = g->base_fqid;
			dist->count = g->num_fqids;
			if (g->tunnel_family) {
				dist[1] = dist[0];
				dist->handle = state->schemes[CDX_PCD_NUM_GROUPS +
					grp - CDX_PCD_TUPLE_FIRST];
				dist++;
			}
			dist++;

			tbl->id = state->port_state[i].tables[grp];
			tbl->dpa_type = CDX_DPA_TBL_EXTERNAL_HASH;
			tbl->type = g->table_type;
			tbl->port_idx = 1U << pinfo->portid;
			tbl->num_keys = CDX_PCD_MAX_NUM_OF_KEYS;
			tbl->num_sets = g->hash_res_mask + 1;
			tbl->num_ways = tbl->num_keys / tbl->num_sets;
			tbl->key_size = g->key_size;
			strscpy(tbl->name, g->table_name, sizeof(tbl->name));
			tbl++;
		}
	}
	dpa_cfg_set_expt_defaults(finfo);
	return 0;
}

/*
 * Install the classifier: build the PCD on the hardware, publish its metadata,
 * then bring up everything that hangs off it -- interface records, frame
 * queues, policer profiles and table miss actions.
 *
 * Called once from cdx module init.
 */
int dpa_cfg_install(void)
{
	struct dpa_init_ports ports = { 0 };
	bool resources_started = false, ports_stopped = false;
	struct cdx_pcd_state *state;
	t_LnxWrpFmDev *wrapper;
	uint32_t ii;
	int retval;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	cdx_ctrl_lock_with_rtnl();
	mutex_lock(&dpa_cfg_lock);
	if (fman_info) {
		DPA_ERROR("%s::classifier already installed\n", __func__);
		retval = -EBUSY;
		goto unlock;
	}

	retval = cdx_pcd_build(0, state);
	if (retval)
		goto unlock;

	retval = dpa_cfg_publish(state);
	if (retval)
		goto err_ret;

	wrapper = state->fm_dev;
	retval = dpa_prepare_ports(&wrapper, &ports);
	if (retval)
		goto err_ret;
	ports_stopped = true;
	retval = dpa_set_ports_enabled(&ports, false);
	if (retval)
		goto err_ret;
	resources_started = true;
	if (cdxdrv_init_stats(fman_info->muram_handle) || cdx_dpa_init_fault()) {
		retval = -EIO;
		goto err_ret;
	}

	/* Offline ports first, then ethernet: an ethernet interface's egress
	 * can reference an offline port, so the fixtures have to exist. */
	for (ii = 0; ii < fman_info->max_ports; ii++) {
		struct cdx_port_info *pinfo = &fman_info->portinfo[ii];

		if (pinfo->type)
			continue;
		if (cdx_add_oh_iface(pinfo->name) || cdx_dpa_init_fault()) {
			DPA_ERROR("%s::port %s add failed\n", __func__, pinfo->name);
			retval = -EIO;
			goto err_ret;
		}
	}
	for (ii = 0; ii < fman_info->max_ports; ii++) {
		struct cdx_port_info *pinfo = &fman_info->portinfo[ii];

		if (!pinfo->type)
			continue;
		if (cdx_add_eth_onif(pinfo->name) || cdx_dpa_init_fault()) {
			DPA_ERROR("%s::port %s add failed\n", __func__, pinfo->name);
			retval = -EIO;
			goto err_ret;
		}
	}

	if (cdx_create_port_fqs()) {
		retval = -EIO;
		goto err_ret;
	}
	if (cdxdrv_create_missaction_policer_profiles(fman_info)) {
		retval = -EIO;
		goto err_ret;
	}
#ifdef ENABLE_INGRESS_QOS
	if (cdxdrv_create_ingress_qos_policer_profiles(fman_info)) {
		retval = -EIO;
		goto err_ret;
	}
#endif
	/* Both device-wide meters exist from here, so devlink can be told what
	 * they run rather than a placeholder. A failure costs the operator the
	 * verb and not the port, so it is reported rather than fatal; the
	 * rollback below detaches it either way, before the profiles go. */
	if (cdx_devlink_attach(wrapper->dev))
		DPA_ERROR("%s::unable to register the devlink instance\n", __func__);
	/* Patch miss actions after their schemes and trees exist. */
	for (ii = 0; ii < num_fmans; ii++) {
		if (cdxdrv_set_miss_action(ii) || cdx_dpa_init_fault()) {
			retval = -EIO;
			goto err_ret;
		}
	}
	retval = dpa_set_ports_enabled(&ports, true);
	if (retval)
		goto err_ret;
	display_dpa_cfg();
	dpa_active_ports = ports;
	mutex_unlock(&dpa_cfg_lock);
	cdx_ctrl_unlock_with_rtnl();
	kfree(state);
	return 0;

err_ret:
	if (resources_started) {
		/* Some ports may already have resumed before an enable error. */
		if (dpa_set_ports_enabled(&ports, false) || dpa_detach_ports(&ports)) {
			pr_err("cdx: cannot detach failed DPA setup; reboot required\n");
			dpa_active_ports = ports;
			dpa_active_ports.state = DPA_PORTS_DETACHING;
			retval = -EUCLEAN;
			goto unlock;
		}
		if (dpa_rollback_resources()) {
			pr_err("cdx: DPA resource cleanup failed; reboot before retrying\n");
			retval = -EUCLEAN;
		}
	}
	if (ports_stopped && dpa_set_ports_enabled(&ports, true))
		retval = -EUCLEAN;
	kfree(ports.entries);
	release_cfg_info();
	cdx_pcd_teardown(state);
unlock:
	mutex_unlock(&dpa_cfg_lock);
	cdx_ctrl_unlock_with_rtnl();
	kfree(state);
	return retval;
}

//get pcd fq info from fqid
int find_pcd_fq_info(uint32_t fqid)
{
	struct dpa_fq *fqinfo;
	fqinfo = dpa_pcd_fq;
	while(1) {
		if (!fqinfo)
			break;
		if (fqinfo->fqid == fqid)	
			return 0;
		fqinfo = (struct dpa_fq *)fqinfo->list.next;
	}
	return -1;
}

void add_pcd_fq_info(struct dpa_fq *fq_info)
{
	//add to tail of resource list
	fq_info->list.next = (struct list_head *)dpa_pcd_fq;
	dpa_pcd_fq = fq_info;
}

//get ether iface info by name
int get_dpa_eth_iface_info(struct eth_iface_info *iface_info, char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;
		port_info = finfo->portinfo;
		//seach for port in fman structures
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				iface_info->fman_idx = port_info->fm_index;
				iface_info->port_idx = port_info->index;
				iface_info->portid = port_info->portid;
				iface_info->max_dist = port_info->max_dist;
				iface_info->dist_info = port_info->dist_info;
				return 0;
			}
			port_info++;
		}
		finfo++;
	}
	DPA_ERROR("%s::could not find info for port %s\n", 
			__func__, name);
	return -1;
}

//get oh iface info by name
int get_dpa_oh_iface_info(struct oh_iface_info *iface_info, char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;
		port_info = finfo->portinfo;
		//seach for port in fman structures
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				iface_info->max_dist = port_info->max_dist;
				iface_info->dist_info = port_info->dist_info;
				iface_info->portid = port_info->portid;
				return 0;
			}
			port_info++;
		}
		finfo++;
	}
	DPA_ERROR("%s::could not find info for port %s\n",
			__func__, name);
	return -1;
}

/* get port information by name */
struct cdx_port_info *get_dpa_port_info(char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;
		port_info = finfo->portinfo;
		//seach for port in fman structures
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				return port_info;
			}
			port_info++;
		}
		finfo++;
	}
	DPA_ERROR("%s::could not find info for port %s\n", 
			__func__, name);
	return NULL;
}

//get kernel pcd dev handle by fman index
void *dpa_get_pcdhandle(uint32_t fm_index)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;

	finfo =  fman_info;
	for (ii = 0; ii < num_fmans; ii++, finfo++) {
		if (finfo->index == fm_index) {
			return finfo->pcd_handle;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(dpa_get_pcdhandle);

/* The FMans, and so the FMan PCDs, the installed configuration spans. Every
 * write of the count holds the control mutex, so a holder reads a settled one. */
uint32_t dpa_get_num_fmans(void)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
	return num_fmans;
}

/* The first external hash table configured, which any PCD barrier can be
 * issued through: they all live on the one PCD (cdx_ft_claim() refuses more).
 * Read under the control mutex, which every change of the configuration
 * holds. */
void *dpa_get_ehash_td(void)
{
	uint32_t ii, jj;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	for (ii = 0; ii < num_fmans; ii++) {
		if (!fman_info[ii].tbl_info)
			continue;
		for (jj = 0; jj < fman_info[ii].num_tables; jj++)
			if (fman_info[ii].tbl_info[jj].dpa_type == CDX_DPA_TBL_EXTERNAL_HASH &&
			    fman_info[ii].tbl_info[jj].id)
				return fman_info[ii].tbl_info[jj].id;
	}
	return NULL;
}

//get channel and workque id infor given a fqid
int dpa_get_tx_chnl_info(uint32_t fqid, uint32_t *ch_id, uint32_t *wq_id)
{
	struct qman_fq fq;
	struct qm_fqd fqd;

	memset(&fq, 0, sizeof(struct qman_fq));
	fq.fqid = fqid;
	//query for fq info
	if (qman_query_fq(&fq, &fqd)) {
		DPA_ERROR("%s::query fq failed on fqid %d\n",
				__func__, fq.fqid);
		return FAILURE; 
	}
	//read tnd return he wq and channel info
	*wq_id = fqd.dest.wq;
	*ch_id = fqd.dest.channel;
	return SUCCESS;
}

//get table descriptor given a table type and port index
void *dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type)
{
	struct cdx_fman_info *finfo;
	struct table_info *tinfo;
	uint32_t ii;

	if (port_idx >= 32)
		return NULL;

	finfo =  fman_info;
	//loop thru al fmans
	for (ii = 0; ii < num_fmans; ii++) {
		if (finfo->index == fm_index) {
			tinfo = finfo->tbl_info;
			//scan all tables with this instance
			for (ii = 0; ii < finfo->num_tables; ii++) {
				//return if type and port index match
				if ((tinfo->type == type) &&
						(tinfo->port_idx & (1U << port_idx))) {
					return (tinfo->id);
				}
				tinfo++;
			}
			DPA_ERROR("%s::no matching type %d at index %d\n", 
					__func__, type, fm_index);
			return NULL;
		}
	}
	DPA_ERROR("%s::invalid index %d\n", __func__, fm_index);	
	return NULL;
}
void *dpa_get_fm_ctx(uint32_t fm_idx)
{
	if (fm_idx < num_fmans)
		return (fman_info + fm_idx);
	else
		return NULL;
}


void *dpa_get_fm_MURAM_handle(uint32_t fm_idx, uint64_t *phyBaseAddr,
		uint32_t *MuramSize)
{
	struct cdx_fman_info *finfo;

	if (fm_idx < num_fmans)
		finfo = fman_info + fm_idx;
	else
		return NULL;
	*phyBaseAddr = finfo->physicalMuramBase;
	*MuramSize = finfo->fmMuramMemSize;
	return finfo->muram_handle;

}
EXPORT_SYMBOL(dpa_get_fm_MURAM_handle);

#ifdef ENABLE_INGRESS_QOS
/*get policer handle given fman index and queue_no */
int cdx_get_policer_profile_id(uint32_t fm_index, uint32_t queue_no)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;

	if (queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return 0;

	finfo =  fman_info;
	for (ii = 0; ii < num_fmans; ii++) {
		if (finfo->index == fm_index) {
			if(finfo->ingress_policer_info[queue_no].policer_on == ENABLE_INGRESS_POLICER)
				return finfo->ingress_policer_info[queue_no].profile_id;
			else
				break;
		}
	}
	return 0;
}
int cdx_ingress_enable_or_disable_qos(uint32_t fm_index,uint32_t queue_no,uint32_t oper)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= num_fmans || queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return -1;

	finfo = (fman_info + fm_index);

	if (!finfo->ingress_policer_info[queue_no].handle)
		return ERR_QM_INGRESS_POLICER_HANDLE_NULL;

	return cdxdrv_enable_or_disable_ingress_policer(finfo,queue_no,oper);

}
int cdx_ingress_policer_modify_config(uint32_t fm_index,uint32_t queue_no,uint32_t cir,uint32_t pir, uint32_t cbs, uint32_t pbs)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= num_fmans || queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return -1;

	finfo = (fman_info + fm_index);

	if (!finfo->ingress_policer_info[queue_no].handle)
		return ERR_QM_INGRESS_POLICER_HANDLE_NULL;

	return cdxdrv_modify_ingress_qos_policer_profile(finfo,queue_no,cir,pir,cbs,pbs);
}

/* The peak rate and burst one ingress profile enforces, when it is metering at
 * all. A profile whose green and yellow share an action drops on the peak pair
 * alone, so this pair is what it actually holds traffic to. A disabled profile
 * does not answer: it passes everything, and it refuses a new rate until it is
 * enabled again. */
int cdx_ingress_policer_peak(uint32_t fm_index, uint32_t queue_no,
			     uint32_t *pir, uint32_t *pbs)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= num_fmans || queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return FAILURE;
	finfo = (fman_info + fm_index);
	if (!finfo->ingress_policer_info[queue_no].handle ||
	    finfo->ingress_policer_info[queue_no].policer_on != ENABLE_INGRESS_POLICER)
		return FAILURE;
	*pir = finfo->ingress_policer_info[queue_no].pir_value;
	*pbs = finfo->ingress_policer_info[queue_no].pbs;
	return SUCCESS;
}

/* The colours one ingress profile counted. Read without clearing, so every
 * other reader's baseline stays where it was; a caller wanting deltas keeps
 * its own. */
int cdx_ingress_policer_counters(uint32_t fm_index, uint32_t queue_no,
				 struct cdx_police_counters *out)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= num_fmans || queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return FAILURE;

	finfo = (fman_info + fm_index);

	if (!finfo->ingress_policer_info[queue_no].handle)
		return FAILURE;

	cdx_plcr_colours(finfo->ingress_policer_info[queue_no].handle, out);
	return SUCCESS;
}
#endif

/*
 *  Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                cdx_qos.c     
 * @description         device management routines for Qos
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <uapi/linux/in6.h> 
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/if_arp.h>
#include <linux/io.h>
#include "lnxwrp_fm.h"
#include <linux/fsl_oh_port.h>
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "fm_ehash.h"
#include "portdefs.h"
#include "layer2.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "mac.h"
#include "cdx.h"
#include "cdx_common.h"
#include "module_qm.h"
#include "fe.h"
#include "control_tunnel.h"
#include "control_ipv6.h"
#include "endian_ext.h" 
#include "dpa_control_mc.h"
#include "dpa_wifi.h"
#include "cdx_ceetm_gdef.h"
#include "cdx_defs.h"
#include "cdx_flowtable_backend.h"

/* The flowtable adapter names an ingress policer profile in its own class
 * encoding and bounds it with its own constant, because it must not include
 * the FMAN policer headers. The profile count belongs to this file, so the
 * check does too: adding profiles here fails the build until the rule's
 * encoding is widened, rather than leaving the adapter refusing a profile the
 * hardware now has. The adapter's bound is the highest profile number, so it
 * is one below the count. */
static_assert(CDX_FT_QOS_MAX_POLICER == INGRESS_FLOW_POLICER_QUEUES - 1,
	      "cdx_ft_rule.qos policer bound must track the ingress profile count");

//#define QOS_DEBUG	1

/* A port's fast-forward profile, and its record: what the profile's owner --
 * the rate the port boots with, or a tc matchall police action -- last asked
 * for, which every write of it is built from (port_plcr_params()). The bursts
 * are the ones written, a port's default already resolved from its speed.
 * Under cdx_plcr_mutex. */
struct port_ff_rate_lim_info {
	void *handle;
	t_Handle h_FmPcd;
	t_Handle port_handle;
	uint32_t rate_mode;
	uint32_t cir_value;
	uint32_t pir_value;
	uint32_t cbs;
	uint32_t pbs;
	bool tc_meter;
	struct cdx_plcr_sync sync;
};

#define MAX_PHYS_PORTS			64              /*dpaa limit*/
/* PORT PIR/CIR PBS/CBS values are for packet mode*/
#define DEFAULT_PORT_FF_CIR_VALUE_10G	2000000
#define DEFAULT_PORT_FF_PIR_VALUE_10G	12000000
#define DEFAULT_PORT_FF_CIR_VALUE_1G	4000000 /* This value is higher than the 64 byte 100% load, but with this value only it is giving 100% on 1046 RDB.*/
#define DEFAULT_PORT_FF_PIR_VALUE_1G	4000000
#define DEFAULT_10G_PORT_FF_CBS		3
#define DEFAULT_1G_PORT_FF_CBS		1
#define DEFAULT_10G_PORT_FF_PBS		3
#define DEFAULT_1G_PORT_FF_PBS		1

//enable rate limiting on exception traffic
//enable rate limiting on fast forward traffic
#define DEFAULT_INGRESS_CIR_VALUE 0xffffffff
#define DEFAULT_INGRESS_PIR_VALUE 0xffffffff
/* For packet mode expected no of packets
	 for FMAN clock speed ( 3.9ns) */
#define DEFAULT_INGRESS_PKT_MODE_CBS 3
#define DEFAULT_INGRESS_PKT_MODE_PBS 3
#define e_FM_PCD_POST_POLICER_PROCES_FRAME 0x26

/* 
 * DEFAULT_SEC_PROFILE_PKT_MODE_CIR: Secure profile packet mode default CIR value.
 * This value is packet per second. 
 * For SIB ASK limited to around 500Mbps (for 66 byte packet)
 */
#define DEFAULT_SEC_PROFILE_PKT_MODE_CIR 740000
/* 
 * DEFAULT_SEC_PROFILE_PKT_MODE_PIR: Secure profile packet mode default PIR value.
 * This value is packet per second. 
 * For SIB ASK limited to around 730Mbps (for 66 byte packet)
 */
#define DEFAULT_SEC_PROFILE_PKT_MODE_PIR 1060000

/* TO SEC max burst is allowed, as the bursts are expected from 5G/DPDK interface */
/* Bursts are confiured in pkts/usec */
#define DEFAULT_SEC_PKT_MODE_CBS 32
#define DEFAULT_SEC_PKT_MODE_PBS 64

uint32_t port_ff_lim_mode = e_FM_PCD_PLCR_PACKET_MODE;
struct port_ff_rate_lim_info port_rate_lim_mode[MAX_PHYS_PORTS];

/* ---- keeping each profile to its record ---------------------------------
 *
 * After boot the only policer writes are the runtime ones: a port's
 * fast-forward profile (tc matchall), the seven per-flow profiles (tc flower),
 * and the SEC and punt profiles (devlink). Each is one host command carrying
 * the whole profile, and it can fail: refused unsent while the host command
 * channel is shut after a timeout, or timed out itself, FMan having applied
 * it or not. So every runtime profile keeps a record of what its owner asked
 * for, the owner's request goes into the record whether or not the write
 * lands, and a write that does not land leaves the profile dirty for the
 * reconcile work to write again, about once a second, until it does.
 *
 * Writing the whole profile again is what makes that safe. The host command
 * port takes commands in order, and the channel reopens only once a timed-out
 * command's late confirmation has arrived, so a rewrite always lands after
 * whatever became of the write before it, and leaves the profile exactly as
 * its record says.
 *
 * cdx_plcr_mutex serializes every runtime write, every counter read and the
 * records. The tc callbacks (under RTNL) and the devlink ones (under the
 * instance lock) take it around each verb, a port's profile takes it coming
 * and going (under the control mutex), and the reconcile work takes it alone.
 * Nothing holding it waits for any of those, so it is always the inner lock,
 * with only cdx_police_lock inside it. The host command busy-waits, which is
 * why this is a mutex and none of it is ever done under a spinlock. */
static DEFINE_MUTEX(cdx_plcr_mutex);
static void cdx_plcr_reconcile_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(cdx_plcr_reconcile, cdx_plcr_reconcile_work);
/* Set once the profiles are about to be released, and never cleared: nothing
 * queues the reconcile work after it. Under cdx_plcr_mutex. */
static bool cdx_plcr_stopped;
/* How soon a write that did not land is tried again. */
#define CDX_PLCR_RETRY_MS	1000

void cdx_plcr_lock(void)
{
	mutex_lock(&cdx_plcr_mutex);
}

void cdx_plcr_unlock(void)
{
	mutex_unlock(&cdx_plcr_mutex);
}

/* Write one profile whole and keep its record's account of whether the
 * hardware runs it: SUCCESS when the write landed, CDX_PLCR_DEFERRED with the
 * reconcile work queued when it did not. The log hears only of a profile
 * falling behind its record and of it catching up, under the names `what'
 * and `n'. */
static int cdx_plcr_commit(t_Handle h_FmPcd, t_FmPcdPlcrProfileParams *params,
			   struct cdx_plcr_sync *sync, const char *what,
			   unsigned int n)
{
	lockdep_assert_held(&cdx_plcr_mutex);
	if (FM_PCD_PlcrProfileSet(h_FmPcd, params)) {
		if (sync->dirty)
			pr_info("cdx: %s policer %u: rewrite confirmed, the profile runs its record\n",
				what, n);
		sync->dirty = false;
		sync->writes++;
		return SUCCESS;
	}
	if (!sync->dirty)
		pr_warn("cdx: %s policer %u: write not confirmed, rewriting it until it is\n",
			what, n);
	sync->dirty = true;
	if (!cdx_plcr_stopped)
		queue_delayed_work(system_wq, &cdx_plcr_reconcile,
				   msecs_to_jiffies(CDX_PLCR_RETRY_MS));
	return CDX_PLCR_DEFERRED;
}

/* The rate a port boots with, and returns to when its tc filter goes. The
 * firmware sets the link mode (100M, 2.5G, ...), not just 1G or 10G. A default
 * above the link's rate never binds, so a slower link takes the 1G defaults
 * and a faster one the 10G defaults. */
static void port_plcr_boot(struct port_ff_rate_lim_info *info,
			   const struct dpa_iface_info *iface_info)
{
	bool slow = iface_info->eth_info.speed <= PORT_1G_SPEED;

	info->rate_mode = port_ff_lim_mode;
	info->cir_value = slow ? DEFAULT_PORT_FF_CIR_VALUE_1G : DEFAULT_PORT_FF_CIR_VALUE_10G;
	info->pir_value = slow ? DEFAULT_PORT_FF_PIR_VALUE_1G : DEFAULT_PORT_FF_PIR_VALUE_10G;
	info->cbs = slow ? DEFAULT_1G_PORT_FF_CBS : DEFAULT_10G_PORT_FF_CBS;
	info->pbs = slow ? DEFAULT_1G_PORT_FF_PBS : DEFAULT_10G_PORT_FF_PBS;
	info->tc_meter = false;
}

static void port_plcr_params(const struct port_ff_rate_lim_info *info,
			     t_FmPcdPlcrProfileParams *params);

/* api to modify shared policer parameters for exception traffic to control plane.
 * Writes one exception type's profile whole, from its record. */
int cdxdrv_modify_missaction_policer_profile(struct cdx_fman_info *finfo, uint32_t type)
{
	struct cdx_expt_ratelimit_info *info;
	t_FmPcdPlcrProfileParams Params;

	if (type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return FAILURE;
	info = &finfo->expt_rate_limit_info[type];
	if (!info->handle || info->limit == DISABLE_EXPT_PROFILE)
		return FAILURE;
	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = info->handle;
	Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	//color as red by default
	Params.color.dfltColor = e_FM_PCD_PLCR_RED;
	//override color is RED
	Params.color.override = e_FM_PCD_PLCR_RED;
	//set algorithm mode as bytes/sec
	if (finfo->expt_ratelim_mode == EXPT_PKT_LIM_PLCR_MODE_BYTE) {
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = info->limit;
		Params.nonPassthroughAlgParams.committedBurstSize = info->burst;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = info->limit;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = info->burst;
		Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
	} else {
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = info->limit;
		Params.nonPassthroughAlgParams.committedBurstSize = info->burst;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = info->limit;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = info->burst;
	}
	Params.nextEngineOnGreen = e_FM_PCD_DONE;
	Params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnYellow = e_FM_PCD_DONE;
	Params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnRed = e_FM_PCD_DONE;
	Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
	return cdx_plcr_commit(finfo->pcd_handle, &Params, &info->sync, "exception", type);
}

/* api to add shared policer profile for exception traffic to control plane */
int cdxdrv_create_missaction_policer_profiles(struct cdx_fman_info *finfo)
{
	t_Handle h_FmPcd;
	t_FmPcdPlcrProfileParams Params;
	void *handle;
	uint32_t ii;

	h_FmPcd = finfo->pcd_handle;
	for (ii = 0 ; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++) {

		/* Every type's record starts from the burst they are all
		 * created with, and keeps its own from then on. */
		finfo->expt_rate_limit_info[ii].burst = finfo->expt_ratelim_burst_size;
		if (finfo->expt_rate_limit_info[ii].limit == DISABLE_EXPT_PROFILE)  {
			finfo->expt_rate_limit_info[ii].handle = NULL;
			continue;
		}
		memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
		Params.id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
		Params.id.newParams.relativeProfileId = ii;
		Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
		Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
		//color as red by default
		Params.color.dfltColor = e_FM_PCD_PLCR_RED;
		//override color is RED
		Params.color.override = e_FM_PCD_PLCR_RED;
		//set algorithm mode as bytes/sec
		if (finfo->expt_ratelim_mode == EXPT_PKT_LIM_PLCR_MODE_BYTE) {
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
			Params.nonPassthroughAlgParams.committedInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.committedBurstSize = finfo->expt_rate_limit_info[ii].burst;
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = finfo->expt_rate_limit_info[ii].burst;
			Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
			Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
		} else {
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
			Params.nonPassthroughAlgParams.committedInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.committedBurstSize = finfo->expt_rate_limit_info[ii].burst;
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = finfo->expt_rate_limit_info[ii].burst;
		}
		Params.nextEngineOnGreen = e_FM_PCD_DONE;
		Params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
		Params.nextEngineOnYellow = e_FM_PCD_DONE;
		Params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
		Params.nextEngineOnRed = e_FM_PCD_DONE;
		Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
		handle = FM_PCD_PlcrProfileSet(h_FmPcd, &Params);
		if (!handle) {
			printk("%s::unable to set profile for type %d\n",
					__func__, ii);
			return FAILURE;
		}	
#ifdef QOS_DEBUG
		printk("%s::plcr profile modified for type %d, mode %d, handle %p\n",
				__func__, ii, finfo->expt_ratelim_mode, handle);
		printk("cir %d, pir %d, cbs %d, pbs %d\n",
				Params.nonPassthroughAlgParams.committedInfoRate,
				Params.nonPassthroughAlgParams.peakOrExcessInfoRate,
				Params.nonPassthroughAlgParams.committedBurstSize,
				Params.nonPassthroughAlgParams.peakOrExcessBurstSize);
#endif
		finfo->expt_rate_limit_info[ii].handle = handle;
		if (cdx_dpa_init_fault())
			return FAILURE;
	}
	return 0;
}

static int dpa_add_port_ff_policier_profile(struct dpa_iface_info *iface_info,
		uint8_t hardwarePortId, void *port_handle, t_Handle h_FmPcd)
{
	struct port_ff_rate_lim_info *info;
	void *handle;
	void *profhandle;
	t_FmPcdPlcrProfileParams Params;
	int rc = FAILURE;

	//init default cir and pir values for port
	if (!(iface_info->if_flags & IF_TYPE_ETHERNET)) {
		DPA_ERROR("%s::%d interface %s is not ethernet interface. Cannot configure it other than ethernet interfaces(flag 0x%x). \n",
				__func__, __LINE__, iface_info->name, iface_info->if_flags);
		return FAILURE;
	}
	if (hardwarePortId >= MAX_PHYS_PORTS)
		return FAILURE;
	info = &port_rate_lim_mode[hardwarePortId];

	profhandle = fm_port_get_handle(port_handle);
#ifdef QOS_DEBUG
	printk("%s::creating profile for port %s, hwportid %d\n", __func__,
			iface_info->name, hardwarePortId);
#endif
	if (FM_PORT_PcdPlcrAllocProfiles(profhandle, 1)) {
		DPA_ERROR("%s::unable to alloc plcr profile for dev %s\n",
				__func__, iface_info->name);
		return FAILURE;
	}
	/* The record is the reconcile work's to read as soon as the profile
	 * has a handle, so it is filled under the same lock. */
	mutex_lock(&cdx_plcr_mutex);
	info->port_handle = profhandle;
	if (cdx_dpa_init_fault())
		goto out;
	port_plcr_boot(info, iface_info);
	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.id.newParams.profileType = e_FM_PCD_PLCR_PORT_PRIVATE;
	Params.id.newParams.h_FmPort = profhandle;
	Params.id.newParams.relativeProfileId = 0;
	/* Built as every later write of it is, so a rewrite of the boot rate
	 * is the profile as it was created. */
	port_plcr_params(info, &Params);
	handle = FM_PCD_PlcrProfileSet(h_FmPcd, &Params);
	if (!handle) {
		DPA_ERROR("%s::unable to profile set for port %s\n",
				__func__, iface_info->name);
		goto out;
	}
	info->handle = handle;
	info->h_FmPcd = h_FmPcd;
	memset(&info->sync, 0, sizeof(info->sync));
	rc = SUCCESS;
#ifdef QOS_DEBUG
	printk("%s::plcr profile for dev %s handle %p\n",
			__func__, iface_info->name, handle);
#endif
	//change fmbm_rfne value to policer
	//FM_PORT_SetBmiNia(profhandle, 0x4c0000);
out:
	mutex_unlock(&cdx_plcr_mutex);
	return rc;
}

//api to add port specific policer profile on offline ports to reserve bandwidth for incoming control packets
int dpa_add_ethport_ff_policier_profile(struct dpa_iface_info *iface_info)
{
	struct eth_iface_info *eth_info;
	struct dpa_priv_s *priv;
	struct mac_device *mac_dev;
	uint8_t hardwarePortId;
	struct fm_port *port_handle;
	t_Handle h_FmPcd;

	eth_info = &iface_info->eth_info;
	priv = netdev_priv(eth_info->net_dev);
	mac_dev = priv->mac_dev;
	//hardwarePortId = fm_port_get_hwid(mac_dev->port_dev[RX]);
	hardwarePortId = eth_info->hardwarePortId;
	port_handle = mac_dev->port_dev[RX];
	h_FmPcd = dpa_get_pcdhandle(eth_info->fman_idx);
	if (h_FmPcd == NULL) {
		DPA_ERROR("%s::no pcd handle for eth dev %s\n",
				__func__, iface_info->name);
		return FAILURE;
	}
	return(dpa_add_port_ff_policier_profile(iface_info,
				hardwarePortId, port_handle, h_FmPcd));

}

/* Delete the profile before releasing its port's allocation. Under the lock
 * the reconcile work rewrites it under, so a retry never writes a profile
 * that is being deleted -- which would make it valid again -- and finds no
 * handle once it is gone. */
void dpa_remove_ethport_ff_policier_profile(struct dpa_iface_info *iface_info)
{
	int hardwarePortId = iface_info->eth_info.hardwarePortId;
	struct port_ff_rate_lim_info *info;

	if (hardwarePortId < 0 || hardwarePortId >= MAX_PHYS_PORTS)
		return;
	info = &port_rate_lim_mode[hardwarePortId];
	mutex_lock(&cdx_plcr_mutex);
	if (info->handle) {
		if (FM_PCD_PlcrProfileDelete(info->handle) != 0)
			DPA_ERROR("%s::PlcrProfileDelete failed for %s (port %d)\n",
					__func__, iface_info->name, hardwarePortId);
		info->handle = NULL;
		info->h_FmPcd = NULL;
		memset(&info->sync, 0, sizeof(info->sync));
	}
	mutex_unlock(&cdx_plcr_mutex);
}

/* Startup rollback calls this after stopping the ports and removing all
 * interfaces, including a port whose profile SET failed after allocation. */
int cdxdrv_release_port_policer_slots(void)
{
	uint32_t ii;
	int ret = 0;

	for (ii = 0; ii < MAX_PHYS_PORTS; ii++) {
		struct port_ff_rate_lim_info *info = &port_rate_lim_mode[ii];

		if (!info->port_handle)
			continue;
		if (FM_PORT_PcdPlcrFreeProfiles(info->port_handle)) {
			DPA_ERROR("%s::cannot free profiles for port %u\n", __func__, ii);
			ret = -EIO;
			continue;
		}
		memset(info, 0, sizeof(*info));
	}
	return ret;
}

int cdxdrv_release_shared_policers(struct cdx_fman_info *finfo)
{
	uint32_t ii;
	int ret = 0;

#ifdef ENABLE_INGRESS_QOS
	for (ii = 0; ii < INGRESS_ALL_POLICER_QUEUES; ii++) {
		void **handle = &finfo->ingress_policer_info[ii].handle;

		if (*handle) {
			if (FM_PCD_PlcrProfileDelete(*handle)) {
				DPA_ERROR("%s::cannot delete ingress profile %u\n", __func__, ii);
				ret = -EIO;
			}
			/* The SDK releases the profile lock even on an HC error. */
			*handle = NULL;
		}
	}
#endif
	for (ii = 0; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++) {
		void **handle = &finfo->expt_rate_limit_info[ii].handle;

		if (*handle) {
			if (FM_PCD_PlcrProfileDelete(*handle)) {
				DPA_ERROR("%s::cannot delete exception profile %u\n", __func__, ii);
				ret = -EIO;
			}
			*handle = NULL;
		}
	}
	return ret;
}

/* api to modify port specific policer profile to reserver bandwidth for incoming control packets */
/* What a byte-mode profile counts of a frame.
 *
 * A tc police action charges its rate the IP datagram (qdisc_pkt_len() at tc
 * ingress, after any VLAN tag has been moved out of the frame), which is
 * e_FM_PCD_PLCR_L3_FRM_LEN: measured on the rig with untagged frames, it counts
 * from the IP header to the end of the frame without the FCS (the parser puts
 * the IP header after any tags), where L2 counts the
 * Ethernet header too and FULL the FCS as well. A red frame's rollback was
 * measured to make no difference either way; L2, the nearer, is taken.
 * NXP's profiles meter the whole frame as the wire carried it. */
static void cdx_plcr_lengths(t_FmPcdPlcrProfileParams *params, bool tc_meter)
{
	params->nonPassthroughAlgParams.byteModeParams.frameLengthSelection =
		tc_meter ? e_FM_PCD_PLCR_L3_FRM_LEN : e_FM_PCD_PLCR_FULL_FRM_LEN;
	params->nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection =
		tc_meter ? e_FM_PCD_PLCR_ROLLBACK_L2_FRM_LEN : e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
}

/* What a profile does with each colour. A tc police action passes only a
 * frame that fits both of its buckets, which is green: yellow, above the
 * committed rate and within the peak, is excess to Linux and dropped. NXP's
 * profiles pass yellow, holding traffic to the peak pair alone. Red is
 * dropped either way. */
static void cdx_plcr_actions(t_FmPcdPlcrProfileParams *params, e_FmPcdEngine next,
			     e_FmPcdDoneAction action, bool tc_meter)
{
	params->nextEngineOnGreen = next;
	params->paramsOnGreen.action = action;
	if (tc_meter) {
		params->nextEngineOnYellow = e_FM_PCD_DONE;
		params->paramsOnYellow.action = e_FM_PCD_DROP_FRAME;
	} else {
		params->nextEngineOnYellow = next;
		params->paramsOnYellow.action = action;
	}
	params->nextEngineOnRed = e_FM_PCD_DONE;
	params->paramsOnRed.action = e_FM_PCD_DROP_FRAME;
}

/* Everything of a port's profile but which profile it is, from its record.
 *
 * `tc_meter` meters as a tc police action does (cdx_plcr_lengths(),
 * cdx_plcr_actions()). The boot-time rate meters as NXP's profiles always
 * have: whole frames, yellow passed, the port held to its peak pair.
 */
static void port_plcr_params(const struct port_ff_rate_lim_info *info,
			     t_FmPcdPlcrProfileParams *params)
{
	params->algSelection = e_FM_PCD_PLCR_RFC_2698;
	params->colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	//color as red by default
	params->color.dfltColor = e_FM_PCD_PLCR_RED;
	//override color is RED
	params->color.override = e_FM_PCD_PLCR_RED;
	params->nonPassthroughAlgParams.rateMode = info->rate_mode;
	if (info->rate_mode == e_FM_PCD_PLCR_BYTE_MODE)
		cdx_plcr_lengths(params, info->tc_meter);
	params->nonPassthroughAlgParams.committedInfoRate = info->cir_value;
	params->nonPassthroughAlgParams.committedBurstSize = info->cbs;
	params->nonPassthroughAlgParams.peakOrExcessInfoRate = info->pir_value;
	params->nonPassthroughAlgParams.peakOrExcessBurstSize = info->pbs;
	cdx_plcr_actions(params, e_FM_PCD_PRS, e_FM_PCD_ENQ_FRAME, info->tc_meter);
}

/* A port's profile, written whole from its record. */
static int port_plcr_write(struct port_ff_rate_lim_info *info, unsigned int port)
{
	t_FmPcdPlcrProfileParams Params;

	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = info->handle;
	port_plcr_params(info, &Params);
	return cdx_plcr_commit(info->h_FmPcd, &Params, &info->sync, "port", port);
}

/* Program a port's ingress rate-limiter profile. The profile is created once at
 * port init; this only pushes parameters into it.
 *
 * `cbs`/`pbs` of zero mean "use the burst this port's speed implies", which is
 * what restoring the boot-time rate does. A tc police action carries its own
 * burst and passes it through.
 *
 * A request this port can run becomes its record, whether or not the write
 * lands (cdx_plcr_commit()); one it cannot -- no such port, or no profile --
 * is refused with FAILURE and changes nothing.
 */
static int port_plcr_set(char *ifname, uint32_t rate_mode,
			 uint32_t cir, uint32_t pir, uint32_t cbs, uint32_t pbs,
			 bool tc_meter)
{
	struct port_ff_rate_lim_info *info;
	int hardwarePortId;
	struct dpa_iface_info *iface_info;

	lockdep_assert_held(&cdx_plcr_mutex);
	iface_info = dpa_get_iface_by_name(ifname);
	if (!iface_info)
	{
		printk("%s()::%d Invalid interface name <%s>\n",
				__func__, __LINE__, ifname);
		return FAILURE;
	}
	if (!(iface_info->if_flags & IF_TYPE_ETHERNET)) {
		printk("%s()::%d Interface <%s> is not ethernet(0x%x).\n",
				__func__, __LINE__, ifname, iface_info->if_flags);
		return FAILURE;
	}
	hardwarePortId = iface_info->eth_info.hardwarePortId;
	if (hardwarePortId < 0 || hardwarePortId >= MAX_PHYS_PORTS)
		return FAILURE;
	info = &port_rate_lim_mode[hardwarePortId];
	if (!info->handle)
		return FAILURE;
	/* RFC 2698 has no committed rate above its peak, and the FMD refuses
	 * one every time: recorded, it would be retried for ever. */
	if (cir > pir)
		return FAILURE;

#ifdef QOS_DEBUG
	printk("%s::modifying profile for %s::%d cir %d, pir %d\n", __func__,
			ifname, hardwarePortId, cir, pir);
#endif
	info->rate_mode = rate_mode;
	info->cir_value = cir;
	info->pir_value = pir;
	if (iface_info->eth_info.speed <= PORT_1G_SPEED) {
		info->cbs = cbs ? cbs : DEFAULT_1G_PORT_FF_CBS;
		info->pbs = pbs ? pbs : DEFAULT_1G_PORT_FF_PBS;
	} else {
		info->cbs = cbs ? cbs : DEFAULT_10G_PORT_FF_CBS;
		info->pbs = pbs ? pbs : DEFAULT_10G_PORT_FF_PBS;
	}
	info->tc_meter = tc_meter;
	return port_plcr_write(info, hardwarePortId);
}

/* A tc `matchall action police` on a port's ingress. The caller has already
 * converted the action's rates into this profile's unit; byte mode is Kbit/s,
 * packet mode is packets per second. SUCCESS, CDX_PLCR_DEFERRED or a refusal,
 * as port_plcr_set() says. */
int cdx_port_police_set(char *ifname, bool byte_mode,
			uint32_t cir, uint32_t pir, uint32_t cbs, uint32_t pbs)
{
	return port_plcr_set(ifname,
			     byte_mode ? e_FM_PCD_PLCR_BYTE_MODE : e_FM_PCD_PLCR_PACKET_MODE,
			     cir, pir, cbs, pbs, true);
}

/* Removing the filter returns the port to the rate it booted with, rather than
 * leaving the last policed value in place with nothing describing it. */
int cdx_port_police_clear(char *ifname)
{
	struct dpa_iface_info *iface_info = dpa_get_iface_by_name(ifname);
	struct port_ff_rate_lim_info boot;

	if (!iface_info || !(iface_info->if_flags & IF_TYPE_ETHERNET))
		return FAILURE;
	port_plcr_boot(&boot, iface_info);
	return port_plcr_set(ifname, boot.rate_mode, boot.cir_value, boot.pir_value,
			     boot.cbs, boot.pbs, false);
}

/* The colours a profile counted, all three from one read of it. Read without
 * clearing: the counters have more than one reader, and clearing them here
 * would move everyone else's baseline. A read that fails says so and leaves
 * *out as it was. Taken for zeroes, as the per-counter interface used to hand
 * them out, it would become a baseline the next good read reported the whole
 * counter against, or a running total gone backwards.
 *
 * The read is a host command and busy-waits, so it is not callable under a
 * spinlock; the record lookups that call it hold cdx_plcr_mutex, and say
 * which write of the profile the reading belongs to.
 */
int cdx_plcr_colours(void *handle, struct cdx_police_counters *out)
{
	t_FmPcdPlcrProfileCounterValues values;

	if (FM_PCD_PlcrProfileReadCounters(handle, &values) != E_OK)
		return FAILURE;
	out->green = values.green;
	out->yellow = values.yellow;
	out->red = values.red;
	return SUCCESS;
}

int cdx_port_police_counters(char *ifname, struct cdx_police_counters *out)
{
	int hardwarePortId = dpa_get_iface_hwid_by_name_and_type(ifname, IF_TYPE_ETHERNET);
	struct port_ff_rate_lim_info *info;

	lockdep_assert_held(&cdx_plcr_mutex);
	if (hardwarePortId < 0 || hardwarePortId >= MAX_PHYS_PORTS)
		return FAILURE;
	info = &port_rate_lim_mode[hardwarePortId];
	if (!info->handle || cdx_plcr_colours(info->handle, out) != SUCCESS)
		return FAILURE;
	out->writes = info->sync.writes;
	return SUCCESS;
}

/* One counter's share of a reading under the same write as the baseline. A
 * counter below the baseline was zeroed underneath -- by a write whose outcome
 * was unknown, landing late -- rather than having wrapped, so the value it now
 * holds is the whole of the delta. Reading it as a 32-bit wrap instead would
 * credit a reader with most of four billion frames to cover a sample nobody
 * missed, which is a far worse answer than losing one wrap's worth of
 * counting. */
static uint32_t cdx_police_delta(uint32_t last, uint32_t now)
{
	return now >= last ? now - last : now;
}

/* What a profile counted since a reader last looked, given a new reading,
 * which becomes the reader's baseline. A reading under a later write than the
 * baseline counts from that write, which zeroed the counters, so all of it is
 * new: that is how a reader's baseline follows a rewrite of the profile --
 * the owner's own, or the reconcile work's -- without anyone telling it. A
 * reader with no baseline yet starts from this reading and is credited
 * nothing. `delta->writes' is left zero. */
void cdx_police_advance(struct cdx_police_base *base,
			const struct cdx_police_counters *now,
			struct cdx_police_counters *delta)
{
	const struct cdx_police_counters *at = &base->at;

	memset(delta, 0, sizeof(*delta));
	if (base->known && at->writes != now->writes) {
		delta->green = now->green;
		delta->yellow = now->yellow;
		delta->red = now->red;
	} else if (base->known) {
		delta->green = cdx_police_delta(at->green, now->green);
		delta->yellow = cdx_police_delta(at->yellow, now->yellow);
		delta->red = cdx_police_delta(at->red, now->red);
	}
	base->at = *now;
	base->known = true;
}

void *create_ddr_and_copy_from_muram(void *muramptr, void **ddrptr, U32 size)
{
	if ((*ddrptr = kmalloc(size, GFP_KERNEL)) == NULL)
	{
		DPA_ERROR("%s(%d) Memory allocation failure:\n", __func__, __LINE__);
		return NULL;
	}
	/* Use memcpy_fromio for MURAM - it's device memory on ARM64 */
	memcpy_fromio(*ddrptr, muramptr, size);

	return *ddrptr;
}

void copy_ddr_to_muram_and_free_ddr(void *muramptr, void **ddrptr, U32 size)
{
	/* Use memcpy_toio for MURAM - it's device memory on ARM64 */
	memcpy_toio(muramptr, *ddrptr, size);
	kfree(*ddrptr);
	*ddrptr = NULL;
}

#ifdef ENABLE_INGRESS_QOS
/* api to add shared policer profiles for ingress Qos */
int cdxdrv_create_ingress_qos_policer_profiles(struct cdx_fman_info *finfo)
{
	t_Handle h_FmPcd;
	t_FmPcdPlcrProfileParams Params;
	void *handle;
	uint32_t ii,queue_no=0;

	h_FmPcd = finfo->pcd_handle;
	for (ii = CDX_INGRESS_QUEUE0_PROFILE_NO; ii <= CDX_INGRESS_ALL_PROFILES; ii++) {

		memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
		Params.id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
		Params.id.newParams.relativeProfileId = ii;
		Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
		Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
		/*color as red by default*/
		Params.color.dfltColor = e_FM_PCD_PLCR_RED;
		/*override color is RED */
		Params.color.override = e_FM_PCD_PLCR_RED;

#ifdef SEC_PROFILE_SUPPORT
		if (ii != CDX_INGRESS_SEC_QUEUE_PROFILE_NO)
#endif /* endif for SEC_PROFILE_SUPPORT */
		{
			/* init default cir and pir values */
			finfo->ingress_policer_info[queue_no].cir_value = DEFAULT_INGRESS_CIR_VALUE;
			finfo->ingress_policer_info[queue_no].pir_value = DEFAULT_INGRESS_PIR_VALUE;
			finfo->ingress_policer_info[queue_no].cbs = DEFAULT_INGRESS_BYTE_MODE_CBS;
			finfo->ingress_policer_info[queue_no].pbs = DEFAULT_INGRESS_BYTE_MODE_PBS;

			/*set algorithm mode as Bytes/sec */
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
			/*Params.nonPassthroughAlgParams.committedInfoRate = finfo->ingress_policer_info[queue_no].cir_value; */
			Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_INGRESS_CIR_VALUE;
			Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_INGRESS_BYTE_MODE_CBS;
			/*Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->ingress_policer_info[queue_no].pir_value; */
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_INGRESS_PIR_VALUE;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_INGRESS_BYTE_MODE_PBS;
			Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
			Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
		}
#ifdef SEC_PROFILE_SUPPORT
		else
		{
			/* init default sec profile cir and pir values */
			finfo->ingress_policer_info[queue_no].cir_value = DEFAULT_SEC_PROFILE_PKT_MODE_CIR;
			finfo->ingress_policer_info[queue_no].pir_value = DEFAULT_SEC_PROFILE_PKT_MODE_PIR;
			finfo->ingress_policer_info[queue_no].cbs = DEFAULT_SEC_PKT_MODE_CBS;
			finfo->ingress_policer_info[queue_no].pbs = DEFAULT_SEC_PKT_MODE_PBS;

			/*For sec profile set algorithm mode as Packets/sec */
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
			Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_SEC_PROFILE_PKT_MODE_CIR;
			Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_SEC_PKT_MODE_CBS;
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_SEC_PROFILE_PKT_MODE_PIR;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_SEC_PKT_MODE_PBS;
		}
#endif /* endif for SEC_PROFILE_SUPPORT */

		Params.nextEngineOnGreen = e_FM_PCD_CC;
		Params.paramsOnGreen.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
		Params.nextEngineOnYellow = e_FM_PCD_CC;
		Params.paramsOnYellow.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
		Params.nextEngineOnRed =e_FM_PCD_DONE;
		Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
		handle = FM_PCD_PlcrProfileSet(h_FmPcd, &Params);
		if (!handle) {
			printk("%s::unable to set profile for queue %d\n",
					__func__, queue_no);
			return FAILURE;
		}
		finfo->ingress_policer_info[queue_no].handle = handle;
		if (cdx_dpa_init_fault())
			return FAILURE;
		finfo->ingress_policer_info[queue_no].profile_id = FmPcdPlcrProfileGetAbsoluteId(finfo->ingress_policer_info[queue_no].handle);
#ifdef QOS_DEBUG
		printk("%s::Ingress plcr profile created for  queue_no %d, handle %p,profile_id %d\n",
				__func__, queue_no,handle,finfo->ingress_policer_info[queue_no].profile_id);
		printk("cir %u, pir %u, cbs %d, pbs %d\n",
				Params.nonPassthroughAlgParams.committedInfoRate,
				Params.nonPassthroughAlgParams.peakOrExcessInfoRate,
				Params.nonPassthroughAlgParams.committedBurstSize,
				Params.nonPassthroughAlgParams.peakOrExcessBurstSize);
#endif
#ifdef SEC_PROFILE_SUPPORT
		if (ii != CDX_INGRESS_SEC_QUEUE_PROFILE_NO)
#endif /* endif for SEC_PROFILE_SUPPORT */
			finfo->ingress_policer_info[queue_no].policer_on = DISABLE_INGRESS_POLICER;
#ifdef SEC_PROFILE_SUPPORT
		else
			finfo->ingress_policer_info[queue_no].policer_on = ENABLE_INGRESS_POLICER;
#endif /* endif for SEC_PROFILE_SUPPORT */

		queue_no++;
	}
	return 0;
}

/* One ingress profile, written whole from its record: the SEC profile in
 * packets, the per-flow ones in bytes, and `tc_meter` as for
 * port_plcr_params(): a tc police action's meter, or NXP's, which the SEC
 * profile keeps and a per-flow profile no filter holds returns to. */
static int cdx_ingress_plcr_write(struct cdx_fman_info *finfo, uint32_t queue_no)
{
	struct cdx_ingress_policer_info *info = &finfo->ingress_policer_info[queue_no];
	t_FmPcdPlcrProfileParams Params;

	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = info->handle;
	Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	/*color as red by default */
	Params.color.dfltColor = e_FM_PCD_PLCR_RED;
	/*override color is RED */
	Params.color.override = e_FM_PCD_PLCR_RED;
#ifdef SEC_PROFILE_SUPPORT
	if (queue_no == INGRESS_SEC_POLICER_QUEUE_NUM)
		/*set algorithm mode as Packets/sec */
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
	else
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		/*set algorithm mode as bytes/sec */
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
		cdx_plcr_lengths(&Params, info->tc_meter);
	}
	Params.nonPassthroughAlgParams.committedInfoRate = info->cir_value;
	Params.nonPassthroughAlgParams.committedBurstSize = info->cbs;
	Params.nonPassthroughAlgParams.peakOrExcessInfoRate = info->pir_value;
	Params.nonPassthroughAlgParams.peakOrExcessBurstSize = info->pbs;
	cdx_plcr_actions(&Params, e_FM_PCD_CC, e_FM_PCD_POST_POLICER_PROCES_FRAME,
			 info->tc_meter);
	return cdx_plcr_commit(finfo->pcd_handle, &Params, &info->sync, "ingress", queue_no);
}

/* api to modify ingress qos policer parameters. `tc_meter` as for
 * port_plcr_params(): a tc police action's meter, or NXP's, which the SEC
 * profile keeps. A request an enabled profile can run becomes its record,
 * whether or not the write lands (cdx_plcr_commit()); anything else is
 * refused and changes nothing. */
int cdxdrv_modify_ingress_qos_policer_profile(struct cdx_fman_info *finfo, uint32_t queue_no,uint32_t cir, uint32_t pir, uint32_t cbs, uint32_t pbs, bool tc_meter)
{
	struct cdx_ingress_policer_info *info;

	lockdep_assert_held(&cdx_plcr_mutex);
	if (queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return FAILURE;
	info = &finfo->ingress_policer_info[queue_no];

	if (info->policer_on == DISABLE_INGRESS_POLICER) {
		printk("%s::plcr profile is disabled on queue %d\n",__func__, queue_no);
		return FAILURE;
	}

#ifdef SEC_PROFILE_SUPPORT
	if (queue_no != INGRESS_SEC_POLICER_QUEUE_NUM)
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		/* Honour the caller's burst. This used to force the default of
		 * 2000 bytes whatever was asked for -- barely one frame, so a
		 * TCP flow lost enough of every window to collapse rather than
		 * settle at the rate. A caller passing zero still gets the
		 * default. */
		if (!cbs)
			cbs = DEFAULT_INGRESS_BYTE_MODE_CBS;
		if (!pbs)
			pbs = DEFAULT_INGRESS_BYTE_MODE_PBS;
	}
	/* RFC 2698 has no committed rate above its peak, and the FMD refuses
	 * one every time: recorded, it would be retried for ever. */
	if (cir > pir)
		return FAILURE;

	info->tc_meter = tc_meter;
	info->cir_value = cir;
	info->pir_value = pir;
	info->cbs = cbs;
	info->pbs = pbs;
	return cdx_ingress_plcr_write(finfo, queue_no);
}

/* A profile back to the meter it was created with, in the record and then in
 * the hardware. */
int cdxdrv_set_default_qos_policer_profile(struct cdx_fman_info *finfo, uint32_t queue_no)
{
	struct cdx_ingress_policer_info *info;

	lockdep_assert_held(&cdx_plcr_mutex);
	if (queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return FAILURE;
	info = &finfo->ingress_policer_info[queue_no];

#ifdef SEC_PROFILE_SUPPORT
	if (queue_no != INGRESS_SEC_POLICER_QUEUE_NUM)
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		/* init default cir and pir values */
		info->cir_value = DEFAULT_INGRESS_CIR_VALUE;
		info->pir_value = DEFAULT_INGRESS_PIR_VALUE;
		info->cbs = DEFAULT_INGRESS_BYTE_MODE_CBS;
		info->pbs = DEFAULT_INGRESS_BYTE_MODE_PBS;
	}
#ifdef SEC_PROFILE_SUPPORT
	else
	{
		/* init default sec profile  cir and pir values */
		info->cir_value = DEFAULT_SEC_PROFILE_PKT_MODE_CIR;
		info->pir_value = DEFAULT_SEC_PROFILE_PKT_MODE_PIR;
		info->cbs = DEFAULT_SEC_PKT_MODE_CBS;
		info->pbs = DEFAULT_SEC_PKT_MODE_PBS;
	}
#endif /* endif for SEC_PROFILE_SUPPORT */
	info->tc_meter = false;
	return cdx_ingress_plcr_write(finfo, queue_no);
}

/* `policer_on' is the record's, like the rates: set or cleared before the
 * write, and left so whether or not it lands, because it is what the owner
 * asked for and the reconcile work brings the profile to it. It is also what
 * the flowtable reads when it admits a flow (cdx_get_policer_profile_id()),
 * so a flow admitted under a filter whose write is still outstanding is told
 * to meter by the profile -- and does, once the write lands -- and no flow
 * admitted after the filter is gone is. */
int cdxdrv_enable_or_disable_ingress_policer(struct cdx_fman_info *finfo, uint32_t queue_no,uint32_t oper)
{
	struct cdx_ingress_policer_info *info = &finfo->ingress_policer_info[queue_no];

	lockdep_assert_held(&cdx_plcr_mutex);
	if (oper) {
		if (info->policer_on == ENABLE_INGRESS_POLICER) {
			printk("%s:: Policer already enabled on queue no %d\n",__func__,queue_no);
			return SUCCESS;
		}
		info->policer_on = ENABLE_INGRESS_POLICER;
		return cdx_ingress_plcr_write(finfo, queue_no);
	}
	info->policer_on = DISABLE_INGRESS_POLICER;
	return cdxdrv_set_default_qos_policer_profile(finfo, queue_no);
}

#endif

/* ---- the reconcile work --------------------------------------------------- */

/* Every profile whose last write did not land, written again from its record.
 * One that fails again queues the next try (cdx_plcr_commit()). */
static void cdx_plcr_reconcile_ports(void)
{
	unsigned int ii;

	for (ii = 0; ii < MAX_PHYS_PORTS; ii++) {
		struct port_ff_rate_lim_info *info = &port_rate_lim_mode[ii];

		if (info->handle && info->sync.dirty)
			port_plcr_write(info, ii);
	}
}

static void cdx_plcr_reconcile_shared(struct cdx_fman_info *finfo)
{
	uint32_t ii;

	for (ii = 0; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++)
		if (finfo->expt_rate_limit_info[ii].handle &&
		    finfo->expt_rate_limit_info[ii].sync.dirty)
			cdxdrv_modify_missaction_policer_profile(finfo, ii);
#ifdef ENABLE_INGRESS_QOS
	for (ii = 0; ii < INGRESS_ALL_POLICER_QUEUES; ii++)
		if (finfo->ingress_policer_info[ii].handle &&
		    finfo->ingress_policer_info[ii].sync.dirty)
			cdx_ingress_plcr_write(finfo, ii);
#endif
}

/* About once a second while any profile is behind its record. A write refused
 * while the host command channel is shut fails at once, so a try costs nothing
 * until the channel reopens, and the first try after that brings every profile
 * to its record; then nothing queues the work again. The owners' baselines
 * follow on their own (cdx_police_advance()). */
static void cdx_plcr_reconcile_work(struct work_struct *work)
{
	mutex_lock(&cdx_plcr_mutex);
	if (!cdx_plcr_stopped) {
		cdx_plcr_reconcile_ports();
		/* The one FMan cdx configures (dpa_cfg_publish()). */
		if (fman_info)
			cdx_plcr_reconcile_shared(fman_info);
	}
	mutex_unlock(&cdx_plcr_mutex);
}

void cdx_plcr_reconcile_stop(void)
{
	mutex_lock(&cdx_plcr_mutex);
	cdx_plcr_stopped = true;
	mutex_unlock(&cdx_plcr_mutex);
	/* A run already queued or under way finds the flag set and writes
	 * nothing, and nothing queues another. */
	cancel_delayed_work_sync(&cdx_plcr_reconcile);
}

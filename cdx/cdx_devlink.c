// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2026 Mono Technologies Inc.
 *
 * The two device-wide meters, as devlink trap policers.
 *
 * Everything else in the QoS plane belongs to a port or a flow and is reached
 * through `tc'. These two are neither: one meters what the device punts to the
 * CPU, the other what it hands to its crypto engine. A devlink policer is the
 * kernel's object for exactly that shape -- a rate, a burst and a drop count --
 * so both answer the same three verbs rather than one of them being a
 * configuration knob that cannot report what it dropped.
 *
 * A frame that matches no classifier entry meets a shared FMAN policer profile
 * on its way to the CPU: `cdxdrv_create_missaction_policer_profiles()' creates
 * it and `dpa_cfg.c' installs it as the miss action of the Ethernet and
 * PPPoE-relay hash tables. Until now the only way to set its rate was
 * CMD_QM_EXPT_RATE, an FCI command on a control plane that is sealed in
 * flowtable mode and whose only client does not run there.
 *
 *	devlink trap policer set platform/<fman> policer 1 rate 100000 burst 512
 *	devlink trap policer show
 *
 * is the kernel's own way of saying it. "Rate-limit what this device sends to
 * its CPU" is exactly what a trap policer is, and `trap_policer_set' and
 * `trap_policer_counter_get' are the shape of the FCI set and query, down to
 * the drop count behind them.
 *
 * Two things are deliberately not here.
 *
 * *No traps, and no groups.* The kernel's model binds policers to trap groups
 * and groups to traps, and a trap is something the driver *reports* -- it hands
 * each punted packet to `devlink_trap_report()' so drop monitor can see it.
 * This driver does not, and declaring a trap taxonomy it does not report would
 * claim more than the hardware tells us. A policer on its own is listable and
 * settable, which is the whole of the verb being ported.
 *
 * *No rate in bytes.* A devlink policer's rate is packets per second, and the
 * profile can be programmed either way -- `expt_ratelim_mode'. The FCI command
 * that fed it named its field `pkts_per_sec', so packet mode is the intent, but
 * the mode is configuration and this refuses rather than quietly reinterpreting
 * a rate it was given in one unit as the other.
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/devlink.h>
#include <dpaa_eth.h>
#include <dpaa_eth_common.h>
#include "cdx.h"
#include "misc.h"
#include "portdefs.h"
#include "cdx_devlink.h"

/* The punt policer. Numbered from one because zero is not a devlink policer
 * id, and there is exactly one: the profile is shared across every table whose
 * misses reach the CPU. */
#define CDX_DEVLINK_POLICER_PUNT	1

/* The range CMM validated before it wrote one, which is the grammar-level
 * checking the FCI control plane took with it. devlink refuses anything
 * outside min/max itself, so stating them here is how that survives. */
#define CDX_PUNT_RATE_MIN		1000
#define CDX_PUNT_RATE_MAX		5000000
#define CDX_PUNT_BURST_MIN		1
#define CDX_PUNT_BURST_MAX		2048

static struct devlink *cdx_devlink;

/* ---- the SEC meter ------------------------------------------------------
 *
 * The crypto path's meter is profile 8 of the same ingress pool the seven
 * per-flow profiles come from, and it reaches a frame the same way they do:
 * create_preemptive_checks_hm() puts a profile number in the ucode's pp_no.
 * What differs is who chooses. A flow whose egress goes to the SEC block takes
 * this profile *instead of* the one its own class names, and that substitution
 * is the hardware's, not an operator's -- no filter can ask for it, because
 * "bound for the crypto engine" is not a property of any flow's tuple.
 *
 * So it is a policer with a rate, a burst and a drop count, and no trap group,
 * exactly like the punt one above. That is the shape devlink has for this, and
 * using it means both device-wide meters answer the same three verbs instead of
 * one of them being a configuration knob that cannot report what it dropped.
 *
 * Its rate really is packets per second -- the profile is created in
 * e_FM_PCD_PLCR_PACKET_MODE with QM_SECRATE defaults -- so unlike the punt
 * policer there is no mode to check.
 *
 * The flowtable's XFRM provider now sends flows to SEC, but that frames
 * traverse this meter is not yet demonstrated: the policer reports drops, not
 * passes, and showing traversal means exceeding its rate.
 *
 * What it reports is the peak pair. The profile passes green and yellow alike
 * and drops only red, so the committed rate colours frames without deciding
 * anything; the peak rate and burst are the whole of what it enforces, and a
 * set programs both pairs with the one value devlink carries.
 */
#define CDX_DEVLINK_POLICER_SEC	2

/* The range CMM validated, as with the punt policer. */
#define CDX_SEC_RATE_MIN	1
#define CDX_SEC_RATE_MAX	14880952	/* 64-byte frames/s at 10G */
#define CDX_SEC_BURST_MIN	1
#define CDX_SEC_BURST_MAX	2048

/* ---- what devlink is told at registration ---------------------------------
 *
 * A devlink policer reports the rate and burst it was registered with until a
 * set succeeds, and a set that names only a rate keeps the registered burst. So
 * the registered values have to be the ones the hardware runs, not the ends of
 * the ranges: reporting 5000000 for a meter programmed at 195312, and then
 * "restoring" that value, would turn the meter all but off.
 *
 * Built once, at attach, from what the profiles were created with -- the
 * hardware layer keeps those beside each handle -- and kept for as long as the
 * registration, because devlink holds a pointer to each descriptor. A meter
 * that does not exist, or runs in a unit or at a value devlink cannot express,
 * is left out rather than described approximately.
 */
static struct devlink_trap_policer cdx_policers[2];
static unsigned int cdx_policer_count;

/* Whether a programmed value fits the range the policer declares. Out of range
 * is left unregistered, never clamped: a clamped value is one the hardware is
 * not running, which is the fault this whole table exists to avoid. */
static bool cdx_devlink_in_range(const char *what, u32 rate, u32 burst,
				 u32 rate_min, u32 rate_max,
				 u32 burst_min, u32 burst_max)
{
	if (rate >= rate_min && rate <= rate_max &&
	    burst >= burst_min && burst <= burst_max)
		return true;
	pr_warn("cdx: the %s policer runs at rate %u burst %u, outside the range devlink would accept; not registered\n",
		what, rate, burst);
	return false;
}

/* Fill cdx_policers[] from the programmed profiles and return how many there
 * are. Called under RTNL and the control mutex, before anything is registered,
 * so nothing else reads the table while it changes. */
static unsigned int cdx_devlink_policers_build(void)
{
	unsigned int n = 0;
	u32 rate, burst;

	/* The punt profile, if it exists and meters packets: a byte-mode
	 * profile has a rate devlink would report in the wrong unit. */
	if (cdx_expt_rate_config(FMAN_INDEX, CDX_EXPT_ETH_RATELIMIT,
				 &rate, &burst) == SUCCESS &&
	    cdx_expt_rate_is_packet_mode(FMAN_INDEX) &&
	    cdx_devlink_in_range("punt", rate, burst,
				 CDX_PUNT_RATE_MIN, CDX_PUNT_RATE_MAX,
				 CDX_PUNT_BURST_MIN, CDX_PUNT_BURST_MAX))
		cdx_policers[n++] = (struct devlink_trap_policer)
			DEVLINK_TRAP_POLICER(CDX_DEVLINK_POLICER_PUNT, rate, burst,
					     CDX_PUNT_RATE_MAX, CDX_PUNT_RATE_MIN,
					     CDX_PUNT_BURST_MAX, CDX_PUNT_BURST_MIN);
	/* The SEC profile, if it exists and is on: a disabled one refuses
	 * every set (cdxdrv_modify_ingress_qos_policer_profile()), so offering
	 * it would offer a verb that can only fail. */
	if (cdx_ingress_policer_peak(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
				     &rate, &burst) == SUCCESS &&
	    cdx_devlink_in_range("SEC", rate, burst,
				 CDX_SEC_RATE_MIN, CDX_SEC_RATE_MAX,
				 CDX_SEC_BURST_MIN, CDX_SEC_BURST_MAX))
		cdx_policers[n++] = (struct devlink_trap_policer)
			DEVLINK_TRAP_POLICER(CDX_DEVLINK_POLICER_SEC, rate, burst,
					     CDX_SEC_RATE_MAX, CDX_SEC_RATE_MIN,
					     CDX_SEC_BURST_MAX, CDX_SEC_BURST_MIN);
	return n;
}


static int cdx_devlink_policer_set(struct devlink *devlink,
				   const struct devlink_trap_policer *policer,
				   u64 rate, u64 burst,
				   struct netlink_ext_ack *extack)
{
	if (policer->id == CDX_DEVLINK_POLICER_SEC) {
		/* Packet mode by construction, so no unit to check. Rate and
		 * burst go together because the profile takes them together. */
		if (cdx_ingress_policer_modify_config(FMAN_INDEX,
						      INGRESS_SEC_POLICER_QUEUE_NUM,
						      (uint32_t)rate, (uint32_t)rate,
						      (uint32_t)burst,
						      (uint32_t)burst) != SUCCESS) {
			NL_SET_ERR_MSG_MOD(extack, "the SEC policer could not be programmed");
			return -EINVAL;
		}
		return 0;
	}
	if (policer->id != CDX_DEVLINK_POLICER_PUNT)
		return -EINVAL;
	if (!cdx_expt_rate_is_packet_mode(FMAN_INDEX)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "the punt profile is configured to meter bytes, and a policer rate is packets per second");
		return -EOPNOTSUPP;
	}
	/* Every table whose misses reach the CPU shares one profile, so the
	 * exception type is the Ethernet one and the others -- WIFI, and two
	 * the hardware layer declares but does not support -- are not separate
	 * policers to expose. */
	if (cdx_set_expt_rate(FMAN_INDEX, CDX_EXPT_ETH_RATELIMIT,
			      (uint32_t)rate, (uint32_t)burst) != SUCCESS) {
		NL_SET_ERR_MSG_MOD(extack, "the punt policer could not be programmed");
		return -EINVAL;
	}
	return 0;
}

static int cdx_devlink_policer_counter_get(struct devlink *devlink,
					   const struct devlink_trap_policer *policer,
					   u64 *p_drops)
{
	struct cdx_police_counters now;

	if (policer->id == CDX_DEVLINK_POLICER_SEC) {
		if (cdx_ingress_policer_counters(FMAN_INDEX,
						 INGRESS_SEC_POLICER_QUEUE_NUM,
						 &now) != SUCCESS)
			return -EINVAL;
		*p_drops = now.red;
		return 0;
	}
	if (policer->id != CDX_DEVLINK_POLICER_PUNT)
		return -EINVAL;
	if (cdx_expt_rate_counters(FMAN_INDEX, CDX_EXPT_ETH_RATELIMIT, &now) != SUCCESS)
		return -EINVAL;
	/* Red is what the profile dropped: it programs e_FM_PCD_DROP_FRAME on
	 * red and enqueues green and yellow. A running total, as devlink asks
	 * for -- unlike tc, it reports the counter rather than accumulating a
	 * delta, so there is no baseline to keep here. */
	*p_drops = now.red;
	return 0;
}

static const struct devlink_ops cdx_devlink_ops = {
	.trap_policer_set		= cdx_devlink_policer_set,
	.trap_policer_counter_get	= cdx_devlink_policer_counter_get,
};

/* Register once, against the FMAN the punted traffic is metered by.
 *
 * Called from the DPA configuration, once both meters' profiles exist: that is
 * the first moment there is anything true to report, and cdx already holds the
 * FMAN's own device from resolving its PCD handle. The instance belongs to the
 * FMAN rather than to a port: one profile meters every port's misses, and a
 * devlink instance per port would be four handles onto one meter.
 *
 * Neither meter is turned on here. Both profiles are created already metering
 * -- the SEC profile is the one ingress profile created enabled -- and a
 * disabled one is not registered at all.
 */
int cdx_devlink_attach(struct device *dev)
{
	struct devlink *devlink;
	unsigned int count;
	int rc;

	if (cdx_devlink || !dev)
		return 0;
	count = cdx_devlink_policers_build();
	if (!count)
		return 0;

	devlink = devlink_alloc(&cdx_devlink_ops, 0, dev);
	if (!devlink)
		return -ENOMEM;
	devl_lock(devlink);
	rc = devl_trap_policers_register(devlink, cdx_policers, count);
	devl_unlock(devlink);
	if (rc) {
		devlink_free(devlink);
		return rc;
	}
	cdx_policer_count = count;
	devlink_register(devlink);
	cdx_devlink = devlink;
	return 0;
}

/* Unregister it, before the profiles its callbacks program are released. Safe
 * to call again, and with nothing registered. */
void cdx_devlink_detach(void)
{
	struct devlink *devlink = cdx_devlink;

	if (!devlink)
		return;
	cdx_devlink = NULL;
	devlink_unregister(devlink);
	devl_lock(devlink);
	devl_trap_policers_unregister(devlink, cdx_policers, cdx_policer_count);
	devl_unlock(devlink);
	cdx_policer_count = 0;
	devlink_free(devlink);
}

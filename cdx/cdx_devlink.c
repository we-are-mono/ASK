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
 * PPPoE-relay hash tables. Its rate used to be set only by CMD_QM_EXPT_RATE, a
 * command on CMM's control plane, which is retired.
 *
 *	devlink trap policer set platform/<fman> policer 1 rate 100000 burst 512
 *	devlink trap policer show
 *
 * is the kernel's own way of saying it. "Rate-limit what this device sends to
 * its CPU" is exactly what a trap policer is, and `trap_policer_set' and
 * `trap_policer_counter_get' are the shape of the old set and query, down to
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
 * profile can be programmed either way -- `expt_ratelim_mode'. The command
 * that used to feed it named its field `pkts_per_sec', so packet mode is the
 * intent, but
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

/* The range CMM validated before it wrote one. devlink refuses anything
 * outside min/max itself, so stating them here is how that checking
 * survives. */
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

/* What each policer has dropped since it was registered: the running total
 * devlink asks for. The profile's own red counter is not one -- every set
 * zeroes it, and so does every rewrite of a set whose write did not land --
 * so the total is kept here from deltas (cdx_police_advance()) and goes on
 * across them. Indexed by policer id, under the policer lock. */
static struct {
	struct cdx_police_base	base;
	u64			total;
} cdx_policer_drops[CDX_DEVLINK_POLICER_SEC + 1];

/* Bring one policer's total up to date with what its profile holds now. A
 * read that fails leaves both the total and the baseline where they were:
 * the total is reported as it stood, never a zero that would run it
 * backwards, and the next good read adds only what was dropped since. */
static void cdx_devlink_drops_update(u32 id)
{
	struct cdx_police_counters now, delta;
	int rc;

	if (id == CDX_DEVLINK_POLICER_SEC)
		rc = cdx_ingress_policer_counters(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
						  &now);
	else
		rc = cdx_expt_rate_counters(FMAN_INDEX, CDX_EXPT_ETH_RATELIMIT, &now);
	if (rc != SUCCESS)
		return;
	cdx_police_advance(&cdx_policer_drops[id].base, &now, &delta);
	cdx_policer_drops[id].total += delta.red;
}

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
 * so nothing else reads the table while it changes; the profiles' records are
 * read under the policer lock, as everywhere. */
static unsigned int cdx_devlink_policers_build(void)
{
	unsigned int n = 0;
	u32 rate, burst;

	cdx_plcr_lock();
	/* Both profiles have counted from zero since they were created, under
	 * the write that created them. */
	memset(cdx_policer_drops, 0, sizeof(cdx_policer_drops));
	cdx_policer_drops[CDX_DEVLINK_POLICER_PUNT].base.known = true;
	cdx_policer_drops[CDX_DEVLINK_POLICER_SEC].base.known = true;
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
	cdx_plcr_unlock();
	return n;
}


/* A set whose write does not land is taken all the same: the rate and burst
 * are the profile's record, and the policer layer writes the profile from it
 * until the hardware runs them (cdx_qos.c). devlink then shows what the meter
 * is being brought to, and the operator is told it is behind, rather than
 * devlink keeping the old values over a meter the timed-out write may or may
 * not have changed. Only a set the profile cannot take is refused. */
static int cdx_devlink_policer_set(struct devlink *devlink,
				   const struct devlink_trap_policer *policer,
				   u64 rate, u64 burst,
				   struct netlink_ext_ack *extack)
{
	int rc;

	if (policer->id != CDX_DEVLINK_POLICER_SEC &&
	    policer->id != CDX_DEVLINK_POLICER_PUNT)
		return -EINVAL;
	if (policer->id == CDX_DEVLINK_POLICER_PUNT &&
	    !cdx_expt_rate_is_packet_mode(FMAN_INDEX)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "the punt profile is configured to meter bytes, and a policer rate is packets per second");
		return -EOPNOTSUPP;
	}
	cdx_plcr_lock();
	/* The write zeroes the profile's counters, so what it dropped under the
	 * old rate is counted first. */
	cdx_devlink_drops_update(policer->id);
	if (policer->id == CDX_DEVLINK_POLICER_SEC) {
		/* Packet mode by construction, so no unit to check. Rate and
		 * burst go together because the profile takes them together. */
		rc = cdx_ingress_policer_modify_config(FMAN_INDEX,
						       INGRESS_SEC_POLICER_QUEUE_NUM,
						       (uint32_t)rate, (uint32_t)rate,
						       (uint32_t)burst,
						       (uint32_t)burst, false);
	} else {
		/* Every table whose misses reach the CPU shares one profile, so
		 * the exception type is the Ethernet one and the others -- WIFI,
		 * and two the hardware layer declares but does not support --
		 * are not separate policers to expose. */
		rc = cdx_set_expt_rate(FMAN_INDEX, CDX_EXPT_ETH_RATELIMIT,
				       (uint32_t)rate, (uint32_t)burst);
	}
	cdx_plcr_unlock();
	if (rc == CDX_PLCR_DEFERRED) {
		NL_SET_ERR_MSG_MOD(extack, "the policer write was not confirmed and is retried until it is");
		return 0;
	}
	if (rc != SUCCESS) {
		if (policer->id == CDX_DEVLINK_POLICER_SEC)
			NL_SET_ERR_MSG_MOD(extack, "the SEC policer could not be programmed");
		else
			NL_SET_ERR_MSG_MOD(extack, "the punt policer could not be programmed");
		return -EINVAL;
	}
	return 0;
}

/* Red is what each profile dropped: both program e_FM_PCD_DROP_FRAME on red
 * and enqueue green and yellow. A running total, as devlink asks for
 * (cdx_policer_drops). */
static int cdx_devlink_policer_counter_get(struct devlink *devlink,
					   const struct devlink_trap_policer *policer,
					   u64 *p_drops)
{
	if (policer->id != CDX_DEVLINK_POLICER_SEC &&
	    policer->id != CDX_DEVLINK_POLICER_PUNT)
		return -EINVAL;
	cdx_plcr_lock();
	cdx_devlink_drops_update(policer->id);
	*p_drops = cdx_policer_drops[policer->id].total;
	cdx_plcr_unlock();
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

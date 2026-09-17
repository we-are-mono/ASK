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
#include "lnxwrp_fm.h"
#include "mac.h"
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

static const struct devlink_trap_policer cdx_trap_policers[] = {
	DEVLINK_TRAP_POLICER(CDX_DEVLINK_POLICER_PUNT,
			     CDX_PUNT_RATE_MAX, CDX_PUNT_BURST_MAX,
			     CDX_PUNT_RATE_MAX, CDX_PUNT_RATE_MIN,
			     CDX_PUNT_BURST_MAX, CDX_PUNT_BURST_MIN),
};

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
 * *It is idle in flowtable mode today, and that is temporary.* `CMD_INIT(ipsec)`
 * is skipped when the flowtable owns the hardware and `to_sec_fqid` is set
 * nowhere else, so no frame selects this profile there yet -- IPsec has not
 * been ported to the flowtable; it is backlog, and QoS went first. The policer
 * is registered unconditionally anyway, so that when IPsec does land the meter
 * starts working with no change here. Gating it on the ownership mode would
 * only mean a gate somebody has to remember to remove.
 */
#define CDX_DEVLINK_POLICER_SEC	2

/* The range CMM validated, as with the punt policer. */
#define CDX_SEC_RATE_MIN	1
#define CDX_SEC_RATE_MAX	14880952	/* 64-byte frames/s at 10G */
#define CDX_SEC_BURST_MIN	1
#define CDX_SEC_BURST_MAX	2048

static const struct devlink_trap_policer cdx_sec_policers[] = {
	DEVLINK_TRAP_POLICER(CDX_DEVLINK_POLICER_SEC,
			     CDX_SEC_RATE_MAX, CDX_SEC_BURST_MAX,
			     CDX_SEC_RATE_MAX, CDX_SEC_RATE_MIN,
			     CDX_SEC_BURST_MAX, CDX_SEC_BURST_MIN),
};


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
 * Called as each ethernet interface comes up, because that is the first moment
 * cdx holds anything that can name the FMAN's own platform device, and it is
 * idempotent so the second interface costs nothing. The instance belongs to the
 * FMAN rather than to a port: one profile meters every port's misses, and a
 * devlink instance per port would be four handles onto one meter.
 */
int cdx_devlink_attach(struct net_device *net_dev)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	struct devlink *devlink;
	t_LnxWrpFmDev *fm_dev;
	struct device *dev;
	int rc;

	if (cdx_devlink)
		return 0;
	if (!priv->mac_dev || !priv->mac_dev->fm_dev)
		return 0;
	/* The SDK's own accessors cast this pointer the same way -- see
	 * fm_get_handle() -- so `struct fm' is this wrapper and nothing else. */
	fm_dev = (t_LnxWrpFmDev *)priv->mac_dev->fm_dev;
	dev = fm_dev->dev;
	if (!dev)
		return 0;

	devlink = devlink_alloc(&cdx_devlink_ops, 0, dev);
	if (!devlink)
		return -ENOMEM;
	devl_lock(devlink);
	rc = devl_trap_policers_register(devlink, cdx_trap_policers,
					 ARRAY_SIZE(cdx_trap_policers));
	if (!rc) {
		/* Turned on once, here, rather than on every write: the
		 * hardware layer's enable is idempotent but announces itself in
		 * a printk, and a meter that logs a line each time it is set is
		 * one nobody sets twice. */
		cdx_ingress_enable_or_disable_qos(FMAN_INDEX,
						  INGRESS_SEC_POLICER_QUEUE_NUM,
						  ENABLE_INGRESS_POLICER);
		rc = devl_trap_policers_register(devlink, cdx_sec_policers,
						 ARRAY_SIZE(cdx_sec_policers));
		if (rc)
			devl_trap_policers_unregister(devlink, cdx_trap_policers,
						      ARRAY_SIZE(cdx_trap_policers));
	}
	devl_unlock(devlink);
	if (rc) {
		devlink_free(devlink);
		return rc;
	}
	devlink_register(devlink);
	cdx_devlink = devlink;
	return 0;
}

void cdx_devlink_detach(void)
{
	struct devlink *devlink = cdx_devlink;

	if (!devlink)
		return;
	cdx_devlink = NULL;
	devlink_unregister(devlink);
	devl_lock(devlink);
	devl_trap_policers_unregister(devlink, cdx_sec_policers,
				      ARRAY_SIZE(cdx_sec_policers));
	devl_trap_policers_unregister(devlink, cdx_trap_policers,
				      ARRAY_SIZE(cdx_trap_policers));
	devl_unlock(devlink);
	devlink_free(devlink);
}

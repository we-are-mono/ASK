// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2026 Mono
 *
 * The punt rate, as a devlink trap policer.
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

static int cdx_devlink_policer_set(struct devlink *devlink,
				   const struct devlink_trap_policer *policer,
				   u64 rate, u64 burst,
				   struct netlink_ext_ack *extack)
{
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

/* ---- the SEC rate ------------------------------------------------------
 *
 * The crypto path's meter is profile 8 of the same ingress pool the seven
 * per-flow profiles come from, and it is programmed through the same call that
 * `tc ... action police' already drives for them. What makes it different is
 * only who selects it: the hardware does, when it steers a frame to the SEC
 * block, and no 5-tuple filter can say "the crypto engine's input" because that
 * is not a property of any flow's tuple.
 *
 * So there is no verb for it. It is not a trap -- nothing is punted -- and it
 * is not a filter's own match. A driver-specific parameter is the remaining
 * generic surface, and it is an untyped knob rather than a model of the thing.
 * That is worth saying rather than inventing a shape: this is the one place in
 * the QoS port where a kernel interface is met in letter and not in spirit.
 */
enum cdx_devlink_param_id {
	/* Driver-specific ids start above the generic ones. */
	CDX_DEVLINK_PARAM_ID_SEC_RATE = DEVLINK_PARAM_GENERIC_ID_MAX + 1,
	CDX_DEVLINK_PARAM_ID_SEC_BURST,
};

/* The range CMM validated, as with the punt policer above. */
#define CDX_SEC_RATE_MIN	1
#define CDX_SEC_RATE_MAX	14880952	/* 64-byte frames/s at 10G */
#define CDX_SEC_BURST_MIN	1
#define CDX_SEC_BURST_MAX	2048

/* Both values come from and go to the hardware layer, which keeps them beside
 * the profile handle. Nothing is shadowed here: a parameter that reported a
 * value the profile did not hold would be worse than no parameter. */
static int cdx_devlink_param_get(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx)
{
	u32 cir, cbs;

	if (cdx_ingress_policer_config(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
				       &cir, &cbs) != SUCCESS)
		return -EINVAL;
	switch (id) {
	case CDX_DEVLINK_PARAM_ID_SEC_RATE:
		ctx->val.vu32 = cir;
		return 0;
	case CDX_DEVLINK_PARAM_ID_SEC_BURST:
		ctx->val.vu32 = cbs;
		return 0;
	}
	return -EINVAL;
}

static int cdx_devlink_param_set(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx,
				 struct netlink_ext_ack *extack)
{
	u32 cir, cbs;

	/* The profile takes a rate and a burst together, so the one not being
	 * set is read back rather than assumed: a rate programmed against a
	 * stale burst is a different meter from the one asked for. */
	if (cdx_ingress_policer_config(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
				       &cir, &cbs) != SUCCESS)
		return -EINVAL;
	switch (id) {
	case CDX_DEVLINK_PARAM_ID_SEC_RATE:
		cir = ctx->val.vu32;
		break;
	case CDX_DEVLINK_PARAM_ID_SEC_BURST:
		cbs = ctx->val.vu32;
		break;
	default:
		return -EINVAL;
	}
	if (cdx_ingress_policer_modify_config(FMAN_INDEX,
					      INGRESS_SEC_POLICER_QUEUE_NUM,
					      cir, cir, cbs, cbs) != SUCCESS) {
		NL_SET_ERR_MSG_MOD(extack, "the SEC policer profile could not be programmed");
		return -EINVAL;
	}
	return 0;
}

static int cdx_devlink_param_validate(struct devlink *devlink, u32 id,
				      union devlink_param_value val,
				      struct netlink_ext_ack *extack)
{
	switch (id) {
	case CDX_DEVLINK_PARAM_ID_SEC_RATE:
		if (val.vu32 < CDX_SEC_RATE_MIN || val.vu32 > CDX_SEC_RATE_MAX) {
			NL_SET_ERR_MSG_MOD(extack,
					   "the SEC rate is frames per second, up to a 10G port's 64-byte frame rate");
			return -ERANGE;
		}
		return 0;
	case CDX_DEVLINK_PARAM_ID_SEC_BURST:
		if (val.vu32 < CDX_SEC_BURST_MIN || val.vu32 > CDX_SEC_BURST_MAX) {
			NL_SET_ERR_MSG_MOD(extack, "the SEC burst is frames, at most 2048");
			return -ERANGE;
		}
		return 0;
	}
	return -EINVAL;
}

static const struct devlink_param cdx_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(CDX_DEVLINK_PARAM_ID_SEC_RATE, "sec_rate",
			     DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     cdx_devlink_param_get, cdx_devlink_param_set,
			     cdx_devlink_param_validate),
	DEVLINK_PARAM_DRIVER(CDX_DEVLINK_PARAM_ID_SEC_BURST, "sec_burst",
			     DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     cdx_devlink_param_get, cdx_devlink_param_set,
			     cdx_devlink_param_validate),
};

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
	/* The SEC profile is turned on once, here, rather than on every
	 * parameter set: the hardware layer's enable is idempotent but says so
	 * in a printk, and a knob that logs a line each time it is written is
	 * a knob nobody will use twice. */
	cdx_ingress_enable_or_disable_qos(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
					  ENABLE_INGRESS_POLICER);
	devl_lock(devlink);
	rc = devl_trap_policers_register(devlink, cdx_trap_policers,
					 ARRAY_SIZE(cdx_trap_policers));
	if (!rc) {
		rc = devl_params_register(devlink, cdx_devlink_params,
					  ARRAY_SIZE(cdx_devlink_params));
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
	devl_params_unregister(devlink, cdx_devlink_params,
			       ARRAY_SIZE(cdx_devlink_params));
	devl_trap_policers_unregister(devlink, cdx_trap_policers,
				      ARRAY_SIZE(cdx_trap_policers));
	devl_unlock(devlink);
	devlink_free(devlink);
}

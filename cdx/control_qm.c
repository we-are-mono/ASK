/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#include <linux/delay.h>
#include <linux/rtnetlink.h>
#include <dpaa_eth.h>
#include <dpaa_eth_common.h>

#include "cdx.h"
#include "cdx_ioctl.h"
#include "portdefs.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "cdx_htb.h"
#include "cdx_dscp.h"
#include "cdx_devlink.h"
#include "misc.h"

QM_context_ctl gQMCtx[MAX_PHY_PORTS];

/** QOS init function.
 * Clears every port's QoS context and builds the CEETM channels and class
 * queues the hardware qdisc and the flowtable's class word configure.
 */
int qm_init(void)
{
#ifdef ENABLE_EGRESS_QOS
	int ret;
#endif

	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
#ifdef ENABLE_EGRESS_QOS
	memset(gQMCtx, 0, sizeof(gQMCtx));
	ret = ceetm_init_channels();
	if (ret)
		return ret;
#endif
	return NO_ERR;
}
/* Module init failure/unload only: returning with registered FQs would
 * leave QMan callbacks pointing into freed module text and static storage.
 * Ordinary interface/control drains remain bounded and report failure.
 * Caller holds the control mutex and RTNL, with the timer stopped and external
 * users gone. Release both between attempts, before reacquiring either. */
void qm_quiesce(void)
{
#ifdef ENABLE_EGRESS_QOS
	ASSERT_RTNL();
	while (ceetm_exit()) {
		cdx_ctrl_unlock_with_rtnl();
		pr_warn_ratelimited("cdx: waiting for QoS shutdown; reboot if hardware cannot recover\n");
		msleep(1000);
		cdx_ctrl_lock_with_rtnl();
	}
#endif
}

/** QOS exit function.
 */
void qm_exit(void)
{
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	/* Before the hardware below it goes: an instance outliving its own
	 * device is a handle onto nothing. */
	cdx_devlink_detach();
	qm_quiesce();
	return;
}

/* CEETM class queues and netdev Tx queues are separate index spaces. This
 * used to compare the scheduler's queue count against DPAA_ETH_TX_QUEUES,
 * which held only because both happened to be sized from NR_CPUS; the Tx path
 * masks a class-queue id into conf_fqs[] regardless, so nothing was actually
 * protected. What has to hold is that the netdev reserves a queue slot for
 * every class a hardware qdisc could give away. */
#if MAX_SCHEDULER_QUEUES > DPAA_ETH_CEETM_LEAF_QUEUES
#error MAX_SCHEDULER_QUEUES exceeds the reserved leaf-class queue headroom
#endif

int cdx_enable_ceetm_on_iface(struct dpa_iface_info *iface_info)
{
#ifdef ENABLE_EGRESS_QOS
	struct cdx_port_info *port_info;
	struct tQM_context_ctl *qm_ctx;

	if (!(port_info = get_dpa_port_info(iface_info->name)))
	{
		ceetm_err("%s::unable to get port info for port %s\n",
				__func__, iface_info->name);
		return FAILURE;
	}
	qm_ctx = QM_GET_CONTEXT(port_info->portid);
	if (qm_ctx->lni || qm_ctx->sp) {
		ceetm_err("%s::qos context already exists for port %s\n",
				__func__, iface_info->name);
		return FAILURE;
	}

	RCU_INIT_POINTER(qm_ctx->dscp_fq_map, NULL);
	qm_ctx->dscp_fq_claimed = NULL;

	qm_ctx->iface_info = iface_info;
	qm_ctx->port_info = port_info;
	qm_ctx->qos_enabled = 0;
	qm_ctx->net_dev = iface_info->eth_info.net_dev;
	if (!qm_ctx->net_dev) {
		memset(qm_ctx, 0, sizeof(*qm_ctx));
		return FAILURE;
	}
	/* create lni */
	if (ceetm_create_lni(qm_ctx)) {
		memset(qm_ctx, 0, sizeof(*qm_ctx));
		return FAILURE;
	}
	/* Add qm_ctx to priv structure */
	{
		struct dpa_priv_s *priv;

		priv = netdev_priv(qm_ctx->net_dev);
		priv->qm_ctx = qm_ctx;
	}
#endif
	return SUCCESS;
}

int cdx_disable_ceetm_on_iface(struct dpa_iface_info *iface_info)
{
#ifdef ENABLE_EGRESS_QOS
	int ii, rc;

	for (ii = 0; ii < ARRAY_SIZE(gQMCtx); ii++) {
		if (gQMCtx[ii].iface_info == iface_info) {
			/* The hardware below is about to go; drop what names
			 * it first, the filters before the tree they name
			 * classes in. */
			cdx_dscp_port_gone(&gQMCtx[ii]);
			cdx_htb_port_gone(&gQMCtx[ii]);
			rc = ceetm_release_iface(&gQMCtx[ii]);
			cdx_htb_port_released();
			return rc;
		}
	}
#endif
	return SUCCESS;
}

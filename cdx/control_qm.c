/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#include <dpaa_eth.h>
#include <dpaa_eth_common.h>

#include "cdx.h"
#include "cdx_cmd_validator.h"
#include "cdx_ioctl.h"
#include "portdefs.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "misc.h"

QM_context_ctl gQMCtx[MAX_PHY_PORTS];


//uncomment to disable Egress QOS 
//#define DISABLE_EGRESS_QOS	1

/** QOS command executer.
 * This function is the QOS handler function / the entry point
 * to process the qos commands
 *
 * @param cmd_code   Command code.
 * @param cmd_len    Command length.
 * @param p          Command structure.
 *
 */

#ifdef ENABLE_EGRESS_QOS
static U16 qm_reset_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosResetCommand qcmd = (PQosResetCommand)pcmd;
	struct cdx_port_info *port_info;

	(void)cmd_len;
	(void)out_reply_len;
	port_info = get_dpa_port_info(qcmd->ifname);
	if (!port_info)
		return CMD_ERR;
	if (ceetm_reset_qos(QM_GET_CONTEXT(port_info->portid)))
		return CMD_ERR;
	return CMD_OK;
}

static U16 qm_qosenable_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosEnableCommand qcmd = (PQosEnableCommand)pcmd;
	struct cdx_port_info *port_info;

	(void)cmd_len;
	(void)out_reply_len;
	port_info = get_dpa_port_info(qcmd->ifname);
	if (!port_info)
		return QOS_ENERR_INVAL_PARAM;
	return (U16)ceetm_enable_or_disable_qos(QM_GET_CONTEXT(port_info->portid),
						qcmd->enable_flag);
}

static U16 qm_shaper_config_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)cmd_len;
	(void)out_reply_len;
	if (ceetm_configure_shaper((PQosShaperConfigCommand)pcmd))
		return CMD_ERR;
	return CMD_OK;
}

static U16 qm_wbfq_config_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)cmd_len;
	(void)out_reply_len;
	if (ceetm_configure_wbfq((PQosWbfqConfigCommand)pcmd))
		return CMD_ERR;
	return CMD_OK;
}

static U16 qm_cq_config_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)cmd_len;
	(void)out_reply_len;
	if (ceetm_configure_cq((PQosCqConfigCommand)pcmd))
		return CMD_ERR;
	return CMD_OK;
}

static U16 qm_chnl_assign_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosChnlAssignCommand qcmd = (PQosChnlAssignCommand)pcmd;
	struct cdx_port_info *port_info;

	(void)cmd_len;
	(void)out_reply_len;
	port_info = get_dpa_port_info(qcmd->ifname);
	if (!port_info)
		return CMD_ERR;
	if (ceetm_assign_chnl(QM_GET_CONTEXT(port_info->portid), qcmd->channel_num))
		return CMD_ERR;
	return CMD_OK;
}

/*
 * CMD_QM_DSCP_Q_MAP_STATUS / _CFG / _RESET all share a common
 * preamble (look up port, require qos_enabled). The old cmdproc
 * had them in a combined case body with `cmd_code == ...` inner
 * dispatch; split into three handlers with a shared helper.
 */
static U16 qm_dscp_q_map_common(PQosDscpChnlClsq_mapCmd qcmd,
				int (*op)(struct tQM_context_ctl *, PQosDscpChnlClsq_mapCmd))
{
	struct cdx_port_info *port_info;
	struct tQM_context_ctl *qm_ctx;

	port_info = get_dpa_port_info(qcmd->ifname);
	if (!port_info) {
		DPA_ERROR("%s()::%d return error %d QOS_ENERR_INVAL_PARAM\n",
			  __func__, __LINE__, QOS_ENERR_INVAL_PARAM);
		return QOS_ENERR_INVAL_PARAM;
	}
	qm_ctx = QM_GET_CONTEXT(port_info->portid);
	if (!qm_ctx->qos_enabled) {
		DPA_ERROR("%s()::%d QoS not enabled on this interface <%s>\n",
			  __func__, __LINE__, qm_ctx->iface_info->name);
		return QOS_ENERR_NOT_CONFIGURED;
	}
	if (op(qm_ctx, qcmd)) {
		DPA_ERROR("%s()::%d return error %d QOS_ENERR_INVAL_PARAM\n",
			  __func__, __LINE__, CMD_ERR);
		return CMD_ERR;
	}
	return CMD_OK;
}

static int qm_dscp_status_op(struct tQM_context_ctl *ctx, PQosDscpChnlClsq_mapCmd c)
{
	return ceetm_enable_disable_dscp_fq_map(ctx, c->status);
}

static int qm_dscp_cfg_op(struct tQM_context_ctl *ctx, PQosDscpChnlClsq_mapCmd c)
{
	return ceetm_dscp_fq_map(ctx, c->dscp, c->channel_num, c->clsqueue_num);
}

static int qm_dscp_reset_op(struct tQM_context_ctl *ctx, PQosDscpChnlClsq_mapCmd c)
{
	return ceetm_dscp_fq_unmap(ctx, c->dscp);
}

static U16 qm_dscp_q_map_status_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)cmd_len;
	(void)out_reply_len;
	return qm_dscp_q_map_common((PQosDscpChnlClsq_mapCmd)pcmd, qm_dscp_status_op);
}

static U16 qm_dscp_q_map_cfg_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)cmd_len;
	(void)out_reply_len;
	return qm_dscp_q_map_common((PQosDscpChnlClsq_mapCmd)pcmd, qm_dscp_cfg_op);
}

static U16 qm_dscp_q_map_reset_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)cmd_len;
	(void)out_reply_len;
	return qm_dscp_q_map_common((PQosDscpChnlClsq_mapCmd)pcmd, qm_dscp_reset_op);
}
#endif /* ENABLE_EGRESS_QOS */

static U16 qm_expt_rate_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosExptRateCommand pexptrate = (PQosExptRateCommand)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
#ifdef QM_DEBUG
	printk("%s::interface %d, rate pkts/s %d burst_size :%d\n", __func__,
	       pexptrate->expt_iftype, pexptrate->pkts_per_sec, pexptrate->burst_size);
#endif
	if (cdx_set_expt_rate(FMAN_INDEX, pexptrate->expt_iftype,
			      pexptrate->pkts_per_sec, pexptrate->burst_size))
		return CMD_ERR;
	return CMD_OK;
}

static U16 qm_ff_rate_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosFFRateCommand prate = (PQosFFRateCommand)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	if (cdx_set_ff_rate(prate->interface, prate->cir, prate->pir))
		return CMD_ERR;
	return CMD_OK;
}

#ifdef ENABLE_EGRESS_QOS
static U16 qm_query_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	pQosQueryCmd qcmd = (pQosQueryCmd)pcmd;
	struct cdx_port_info *port_info;

	(void)cmd_len;
	port_info = get_dpa_port_info(qcmd->interface);
	if (!port_info)
		return CMD_ERR;
	if (ceetm_get_qos_cfg(QM_GET_CONTEXT(port_info->portid), qcmd))
		return CMD_ERR;
	*out_reply_len = sizeof(QosQueryCmd);
	return CMD_OK;
}

static U16 qm_query_queue_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)cmd_len;
	if (ceetm_get_cq_query((pQosCqQueryCmd)pcmd))
		return CMD_ERR;
	*out_reply_len = sizeof(QosCqQueryCmd);
	return CMD_OK;
}
#endif

static U16 qm_query_ff_rate_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosFFRateCommand prate = (PQosFFRateCommand)pcmd;

	(void)cmd_len;
	if (cdx_get_ff_rate(prate))
		return CMD_ERR;
	*out_reply_len = sizeof(QosFFRateCommand);
#ifdef QM_DEBUG
	printk("%s::port %s cir rate pkts/s %d, pir rate %d\n", __func__,
	       prate->interface, prate->cir, prate->pir);
#endif
	return CMD_OK;
}

static U16 qm_query_expt_rate_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosExptRateCommand pexptrate = (PQosExptRateCommand)pcmd;

	(void)cmd_len;
	if (cdx_get_expt_rate(pexptrate))
		return CMD_ERR;
	*out_reply_len = sizeof(QosExptRateCommand);
	return CMD_OK;
}

#ifdef ENABLE_INGRESS_QOS
static U16 qm_query_iface_dscp_fqid_map_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosIfaceDscpFqidMapCommand pDscpFqMap = (PQosIfaceDscpFqidMapCommand)pcmd;
	struct cdx_port_info *port_info;
	struct tQM_context_ctl *qm_ctx;

	(void)cmd_len;
	port_info = get_dpa_port_info(pDscpFqMap->ifname);
	if (!port_info)
		return CMD_ERR;
	qm_ctx = QM_GET_CONTEXT(port_info->portid);
	if (!qm_ctx->qos_enabled) {
		DPA_ERROR("%s()::%d QoS not enabled on this interface <%s>\n",
			  __func__, __LINE__, qm_ctx->iface_info->name);
		return QOS_ENERR_NOT_CONFIGURED;
	}
	pDscpFqMap->enable = qm_ctx->dscp_fq_map ? 1 : 0;
	if (ceetm_get_dscp_fq_map(qm_ctx, pDscpFqMap))
		return CMD_ERR;
	*out_reply_len = sizeof(QosIfaceDscpFqidMapCommand);
	DPA_INFO("retlen %u \n", (unsigned int)sizeof(QosIfaceDscpFqidMapCommand));
	return CMD_OK;
}

static U16 qm_ingress_policer_enable_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PIngressQosEnableCommand qcmd = (PIngressQosEnableCommand)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	return (U16)cdx_ingress_enable_or_disable_qos(FMAN_INDEX, qcmd->queue_no, qcmd->enable_flag);
}

static U16 qm_ingress_policer_config_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PIngressQosCfgCommand qcmd = (PIngressQosCfgCommand)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	return (U16)cdx_ingress_policer_modify_config(FMAN_INDEX, qcmd->queue_no,
						      qcmd->cir, qcmd->pir,
						      DEFAULT_INGRESS_BYTE_MODE_CBS,
						      DEFAULT_INGRESS_BYTE_MODE_PBS);
}

static U16 qm_ingress_policer_reset_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)pcmd;
	(void)cmd_len;
	(void)out_reply_len;
	if (cdx_ingress_policer_reset(FMAN_INDEX))
		return CMD_ERR;
	return CMD_OK;
}

static U16 qm_ingress_policer_query_stats_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	pIngressQosStatCmd qcmd = (pIngressQosStatCmd)pcmd;
	uint32_t ii;

	(void)cmd_len;
	for (ii = 0; ii < INGRESS_FLOW_POLICER_QUEUES; ii++)
		cdx_ingress_policer_stats(FMAN_INDEX, ii,
					  &qcmd->policer_stats[ii], qcmd->clear);
	*out_reply_len = sizeof(IngressQosStat) * INGRESS_FLOW_POLICER_QUEUES;
	return CMD_OK;
}

#ifdef SEC_PROFILE_SUPPORT
static U16 qm_sec_policer_config_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PQosSecRateCommand qcmd = (PQosSecRateCommand)pcmd;

	(void)cmd_len;
	(void)out_reply_len;
	return (U16)cdx_ingress_policer_modify_config(FMAN_INDEX,
						      INGRESS_SEC_POLICER_QUEUE_NUM,
						      qcmd->cir, qcmd->pir,
						      qcmd->cbs, qcmd->pbs);
}

static U16 qm_sec_policer_query_stats_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	pSecQosStatCmd qcmd = (pSecQosStatCmd)pcmd;

	(void)cmd_len;
	cdx_ingress_policer_stats(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
				  &qcmd->policer_stats, qcmd->clear);
	*out_reply_len = sizeof(IngressQosStat);
	return CMD_OK;
}

static U16 qm_sec_policer_reset_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)pcmd;
	(void)cmd_len;
	(void)out_reply_len;
	if (cdx_sec_policer_reset(FMAN_INDEX))
		return CMD_ERR;
	return CMD_OK;
}
#endif /* SEC_PROFILE_SUPPORT */
#endif /* ENABLE_INGRESS_QOS */

static const struct cdx_cmd_spec qm_cmd_table[] = {
#ifdef ENABLE_EGRESS_QOS
	CDX_CMD_VAR(CMD_QM_RESET,              0, U16_MAX, NULL, qm_reset_handle),
	CDX_CMD_VAR(CMD_QM_QOSENABLE,          0, U16_MAX, NULL, qm_qosenable_handle),
	CDX_CMD_VAR(CMD_QM_SHAPER_CONFIG,      0, U16_MAX, NULL, qm_shaper_config_handle),
	CDX_CMD_VAR(CMD_QM_WBFQ_CONFIG,        0, U16_MAX, NULL, qm_wbfq_config_handle),
	CDX_CMD_VAR(CMD_QM_CQ_CONFIG,          0, U16_MAX, NULL, qm_cq_config_handle),
	CDX_CMD_VAR(CMD_QM_CHNL_ASSIGN,        0, U16_MAX, NULL, qm_chnl_assign_handle),
	CDX_CMD_VAR(CMD_QM_DSCP_Q_MAP_STATUS,  0, U16_MAX, NULL, qm_dscp_q_map_status_handle),
	CDX_CMD_VAR(CMD_QM_DSCP_Q_MAP_CFG,     0, U16_MAX, NULL, qm_dscp_q_map_cfg_handle),
	CDX_CMD_VAR(CMD_QM_DSCP_Q_MAP_RESET,   0, U16_MAX, NULL, qm_dscp_q_map_reset_handle),
#endif
	CDX_CMD_VAR(CMD_QM_EXPT_RATE,          0, U16_MAX, NULL, qm_expt_rate_handle),
	CDX_CMD_VAR(CMD_QM_FF_RATE,            0, U16_MAX, NULL, qm_ff_rate_handle),
#ifdef ENABLE_EGRESS_QOS
	CDX_CMD_VAR(CMD_QM_QUERY,              0, U16_MAX, NULL, qm_query_handle),
	CDX_CMD_VAR(CMD_QM_QUERY_QUEUE,        0, U16_MAX, NULL, qm_query_queue_handle),
#endif
	CDX_CMD_VAR(CMD_QM_QUERY_FF_RATE,      0, U16_MAX, NULL, qm_query_ff_rate_handle),
	CDX_CMD_VAR(CMD_QM_QUERY_EXPT_RATE,    0, U16_MAX, NULL, qm_query_expt_rate_handle),
#ifdef ENABLE_INGRESS_QOS
	CDX_CMD_VAR(CMD_QM_QUERY_IFACE_DSCP_FQID_MAP, 0, U16_MAX, NULL, qm_query_iface_dscp_fqid_map_handle),
	CDX_CMD_VAR(CMD_QM_INGRESS_POLICER_ENABLE,    0, U16_MAX, NULL, qm_ingress_policer_enable_handle),
	CDX_CMD_VAR(CMD_QM_INGRESS_POLICER_CONFIG,    0, U16_MAX, NULL, qm_ingress_policer_config_handle),
	CDX_CMD_VAR(CMD_QM_INGRESS_POLICER_RESET,     0, U16_MAX, NULL, qm_ingress_policer_reset_handle),
	CDX_CMD_VAR(CMD_QM_INGRESS_POLICER_QUERY_STATS, 0, U16_MAX, NULL, qm_ingress_policer_query_stats_handle),
#ifdef SEC_PROFILE_SUPPORT
	CDX_CMD_VAR(CMD_QM_SEC_POLICER_CONFIG,       0, U16_MAX, NULL, qm_sec_policer_config_handle),
	CDX_CMD_VAR(CMD_QM_SEC_POLICER_QUERY_STATS,  0, U16_MAX, NULL, qm_sec_policer_query_stats_handle),
	CDX_CMD_VAR(CMD_QM_SEC_POLICER_RESET,        0, U16_MAX, NULL, qm_sec_policer_reset_handle),
#endif
#endif
};

static U16 M_qm_cmdproc(U16 cmd_code, U16 cmd_len, U16 *p)
{
#ifdef QM_DEBUG
	printk(KERN_INFO "%s: cmd_code=0x%x\n", __func__, cmd_code);
#endif
	return cdx_dispatch_cmd(qm_cmd_table, ARRAY_SIZE(qm_cmd_table),
				cmd_code, cmd_len, p);
}

/** QOS init function.
 * This function initializes the qos control context with default configuration
 * and sends the same configuration to TMU.
 *
 */
int qm_init(void)
{
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	set_cmd_handler(EVENT_QM,M_qm_cmdproc);
#ifdef ENABLE_EGRESS_QOS	
	memset(&gQMCtx[0], 0, (sizeof(QM_context_ctl) * GEM_PORTS));
	ceetm_init_channels();
#endif
	return NO_ERR;
}
/** QOS exit function.
 */
void qm_exit(void)
{
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
#ifdef ENABLE_EGRESS_QOS	
	ceetm_exit();
#endif
	return;
}

#if MAX_SCHEDULER_QUEUES > DPAA_ETH_TX_QUEUES
#error MAX_SCHEDULER_QUEUES exceeds DPAA_ETH_TX_QUEUES
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
	if (qm_ctx->qos_enabled) {
		ceetm_err("%s::qos already enabled for port %s\n",
				__func__, iface_info->name);
		return FAILURE;
	}

	qm_ctx->dscp_fq_map = NULL;

	qm_ctx->iface_info = iface_info;
	qm_ctx->port_info = port_info;
	qm_ctx->qos_enabled = 0;
	qm_ctx->net_dev = iface_info->eth_info.net_dev;
	if (!qm_ctx->net_dev) {
		return FAILURE;
	}
	/* create lni */
	if (ceetm_create_lni(qm_ctx))
		return FAILURE;
	/* Add qm_ctx to priv structure */
	{
		struct dpa_priv_s *priv;

		priv = netdev_priv(qm_ctx->net_dev);
		priv->qm_ctx = qm_ctx;
	}
#endif
	return SUCCESS;
}

/*
 * Undo cdx_enable_ceetm_on_iface(). Releases the CEETM LNI+SP
 * claimed in ceetm_create_lni() and clears the cached qm_ctx
 * fields + netdev priv->qm_ctx pointer.
 *
 * Used on the dpa_add_eth_if err-path unwind (err_ret7). Does
 * NOT touch qm_chnl_info[] or any CEETM channel state — those
 * are set up by a separate ceetm_assign_chnl() path that
 * cdx_enable_ceetm_on_iface does not invoke.
 *
 * Best-effort: returns without bubbling up failures because we
 * are inside an err-path cascade where subsequent cleanup still
 * has to run.
 */
int cdx_disable_ceetm_on_iface(struct dpa_iface_info *iface_info)
{
#ifdef ENABLE_EGRESS_QOS
	struct cdx_port_info *port_info;
	struct tQM_context_ctl *qm_ctx;
	struct net_device *net_dev;

	port_info = get_dpa_port_info(iface_info->name);
	if (!port_info)
		return FAILURE;
	qm_ctx = QM_GET_CONTEXT(port_info->portid);

	if (!qm_ctx->lni)
		return SUCCESS;  /* nothing was allocated */

	net_dev = qm_ctx->net_dev;

	if (ceetm_release_lni(qm_ctx->lni) != CEETM_SUCCESS)
		ceetm_err("%s::ceetm_release_lni failed for %s\n",
				__func__, iface_info->name);

	qm_ctx->lni = NULL;
	qm_ctx->sp = NULL;
	qm_ctx->iface_info = NULL;
	qm_ctx->port_info = NULL;
	qm_ctx->qos_enabled = 0;
	qm_ctx->dscp_fq_map = NULL;

	if (net_dev) {
		struct dpa_priv_s *priv = netdev_priv(net_dev);

		priv->qm_ctx = NULL;
	}
	qm_ctx->net_dev = NULL;
#endif
	return SUCCESS;
}

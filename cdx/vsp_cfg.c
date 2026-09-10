/*
 *  Copyright 2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include <linux/netdevice.h>

#include "fm_vsp_ext.h"
#include "lnxwrp_fm.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "mac.h"
#include "portdefs.h"
#include "misc.h"
#include "cdx_defs.h"

int dpa_remove_virt_storage_profile(struct eth_iface_info *eth_info)
{
	if (eth_info->vsp_h) {
		FM_VSP_Free(eth_info->vsp_h);
		eth_info->vsp_h = NULL;
	}
	return 0;
}

int dpa_add_virt_storage_profile(struct net_device *net_dev,
				struct eth_iface_info *eth_info)
{
	struct dpa_priv_s *priv = netdev_priv(net_dev);
	t_LnxWrpFmPortDev *port =
		(t_LnxWrpFmPortDev *)priv->mac_dev->port_dev[RX];
	t_LnxWrpFmDev *fman = port->h_LnxWrpFmDev;
	t_FmVspParams params = { 0 };
	struct dpa_bp *bp;
	t_Handle profile;
	int err;

	if (!port->h_DfltVsp || !priv->dpa_bp)
		return -EINVAL;
	bp = dpa_bpid2pool(priv->dpa_bp->bpid);
	if (!bp)
		return -ENODEV;

	/* Wi-Fi egress selects this profile when FMan copies a frame back
	 * to the CPU. Use the Ethernet RX pool: it already contains skb-backed
	 * buffers and VWD refills it through the Ethernet per-CPU accounting.
	 * A separate unseeded pool drops every accelerated downlink packet;
	 * seeding it alone still leaves refill accounting shared across pools.
	 * The Ethernet driver owns the pool throughout this port's lifetime.
	 */
	params.h_Fm = fman->h_Dev;
	params.portParams.portType = port->settings.param.portType;
	params.portParams.portId = port->settings.param.portId;
	params.relativeProfileId = 1;
	params.extBufPools.numOfPoolsUsed = 1;
	params.extBufPools.extBufPool[0].id = bp->bpid;
	params.extBufPools.extBufPool[0].size = bp->size;

	profile = FM_VSP_Config(&params);
	if (!profile) {
		netdev_err(net_dev, "FM_VSP_Config failed\n");
		return -EINVAL;
	}
	err = FM_VSP_ConfigBufferPrefixContent(profile, &port->buffPrefixContent);
	if (err) {
		netdev_err(net_dev, "FM_VSP_ConfigBufferPrefixContent failed\n");
		goto free_profile;
	}
	err = FM_VSP_Init(profile);
	if (err) {
		netdev_err(net_dev, "FM_VSP_Init failed\n");
		goto free_profile;
	}

	eth_info->vsp_h = profile;
	return 0;

free_profile:
	FM_VSP_Free(profile);
	return -EINVAL;
}

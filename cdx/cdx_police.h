/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2026 Mono
 *
 * Ingress policing offload. The driver's single ndo_setup_tc dispatches
 * TC_SETUP_BLOCK here; see cdx_police.c for what the block accepts.
 */

#ifndef _CDX_POLICE_H_
#define _CDX_POLICE_H_

#include <linux/types.h>

struct net_device;
struct flow_block_offload;
struct cdx_ft_rule;

int cdx_police_setup_block(struct net_device *dev, struct flow_block_offload *f);

/* The ingress policer profile an admitted flow should meter against, as a
 * cdx_ft_rule.qos policer nibble, or zero for the default profile. Called once
 * per admitted flow while its hardware entry is being built. */
u8 cdx_police_lookup(const struct cdx_ft_rule *rule);

#endif /* _CDX_POLICE_H_ */

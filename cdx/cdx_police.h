/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2026 Mono
 *
 * Ingress policing offload. The driver's single ndo_setup_tc dispatches
 * TC_SETUP_BLOCK here; see cdx_police.c for what the block accepts.
 */

#ifndef _CDX_POLICE_H_
#define _CDX_POLICE_H_

struct net_device;
struct flow_block_offload;

int cdx_police_setup_block(struct net_device *dev, struct flow_block_offload *f);

#endif /* _CDX_POLICE_H_ */

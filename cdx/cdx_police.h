/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2026 Mono Technologies Inc.
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

/* A profile is named by every flow admitted under its filter, which outlive the
 * filter. The flowtable backend refs a profile when it installs a flow naming
 * it and unrefs when it removes that flow, so a profile is not reprogrammed for
 * a new filter while an old flow still meters against it. Profile 0 (the
 * default) is ignored. */
void cdx_police_profile_ref(u8 profile);
void cdx_police_profile_unref(u8 profile);

/* Which routed unicast directions arriving on a port the hardware polices by
 * the ingress filter tc knows as `cookie' there, exactly as the software
 * filter would: a TCP or UDP one (CDX_POLICE_L4), an ESP one
 * (CDX_POLICE_ESP). Zero for a filter this file does not hold. */
#define CDX_POLICE_L4	0x1u
#define CDX_POLICE_ESP	0x2u
unsigned int cdx_police_reaches(struct net_device *dev, unsigned long cookie);

#endif /* _CDX_POLICE_H_ */

/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_H
#define CDX_FLOWTABLE_H

#include <linux/types.h>

struct net_device;
enum tc_setup_type;

/* Implemented by the adapter module, for a driver whose netdev offers an
 * ndo_setup_tc. Netfilter then reaches the adapter through that ndo instead of
 * through its indirect block registration, so a driver that exports this call
 * must route TC_SETUP_FT to it or hardware acceleration stops with no error.
 * Nothing registers it yet. */
int cdx_ft_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data);

bool cdx_flowtable_enabled(void);
int cdx_flowtable_mode_check(void);
int cdx_flowtable_guard_init(void);
void cdx_flowtable_guard_exit(void);
void cdx_flowtable_quiesced(void);
/* Once claimed, adapter detach must never reopen configuration mutation. */
bool cdx_flowtable_config_sealed(void);

#endif

/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_H
#define CDX_FLOWTABLE_H

#include <linux/types.h>

struct net_device;
enum tc_setup_type;

/* Implemented by the adapter module, for a driver whose netdev offers an
 * ndo_setup_tc. Netfilter then reaches the adapter through that ndo instead of
 * through its indirect block registration, so whoever holds that ndo must route
 * TC_SETUP_FT here or hardware acceleration stops with no error.
 *
 * CDX holds it, because the driver takes one handler and CDX is the module
 * loaded in both ownership modes; the adapter registers with CDX instead, and
 * CDX dispatches. Registration is a one-shot claim: a second caller is refused
 * rather than being allowed to displace the first. */
int cdx_ft_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data);

typedef int (*cdx_ft_setup_tc_handler)(struct net_device *dev,
				       enum tc_setup_type type, void *type_data);
int cdx_register_ft_setup_tc(cdx_ft_setup_tc_handler handler);
void cdx_unregister_ft_setup_tc(void);

/* The adapter's own classifier: a conntrack mark in, an egress class out.
 *
 * Registered so the software Tx path resolves a frame's class with the very
 * function that decided the class of the hardware rule for the same flow.
 * Deriving it twice from the same mark would still be two decodes to keep in
 * step; this is one. Unregistered, the software path expresses no opinion and
 * behaves as it did before there was a qdisc. */
typedef u16 (*cdx_ft_qos_class_fn)(u32 mark);
int cdx_register_ft_qos_class(cdx_ft_qos_class_fn fn);
void cdx_unregister_ft_qos_class(void);

bool cdx_flowtable_enabled(void);
int cdx_flowtable_mode_check(void);
int cdx_flowtable_guard_init(void);
void cdx_flowtable_guard_exit(void);
void cdx_flowtable_quiesced(void);
/* Once claimed, adapter detach must never reopen configuration mutation. */
bool cdx_flowtable_config_sealed(void);

#endif

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2026 Mono
 *
 * The punt rate as a devlink trap policer; see cdx_devlink.c.
 */

#ifndef _CDX_DEVLINK_H_
#define _CDX_DEVLINK_H_

struct net_device;

/* Register the FMAN's devlink instance and its punt policer, once. Called as
 * each ethernet interface comes up and a no-op after the first. */
int cdx_devlink_attach(struct net_device *net_dev);

/* Unregister it, at module exit. */
void cdx_devlink_detach(void);

#endif /* _CDX_DEVLINK_H_ */

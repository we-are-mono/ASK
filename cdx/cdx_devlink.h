/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2026 Mono Technologies Inc.
 *
 * The punt and SEC rates as devlink trap policers; see cdx_devlink.c.
 */

#ifndef _CDX_DEVLINK_H_
#define _CDX_DEVLINK_H_

struct device;

/* Register the FMAN's devlink instance and its policers, once, against `dev',
 * the FMAN's own device. Called from the DPA configuration after both meters'
 * profiles exist, because each policer is registered with the rate and burst
 * its profile was created with. A no-op when already registered. */
int cdx_devlink_attach(struct device *dev);

/* Unregister it. Called before the profiles it programs are released, and
 * again at module exit; a no-op when nothing is registered. */
void cdx_devlink_detach(void);

#endif /* _CDX_DEVLINK_H_ */

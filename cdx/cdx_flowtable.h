/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_H
#define CDX_FLOWTABLE_H

#include <linux/types.h>

bool cdx_flowtable_enabled(void);
int cdx_flowtable_mode_check(void);
void cdx_flowtable_quiesced(void);
/* Once claimed, adapter detach must never reopen configuration mutation. */
bool cdx_flowtable_config_sealed(void);

#endif

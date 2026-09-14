/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_H
#define CDX_FLOWTABLE_H

#include <linux/types.h>

bool cdx_flowtable_enabled(void);
int cdx_flowtable_mode_check(void);
int cdx_flowtable_init(void);
void cdx_flowtable_exit(void);
void cdx_flowtable_quiesced(void);
bool cdx_flowtable_ready(void);

#endif

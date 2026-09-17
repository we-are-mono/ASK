/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _CDX_H_
#define _CDX_H_

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/elf.h>
#include <linux/dmapool.h>
#include <linux/platform_device.h>
#include <asm/byteorder.h>
#include <asm/io.h>
#include "fm_eh_types.h"


#define DPRINT(fmt, args...) do { } while(0)

#define DPRINT_ERROR(fmt, args...) printk(KERN_CRIT "%s: " fmt, __func__, ##args)

#include "types.h"
#include "list.h"
#include "fe.h"
#include "cdx_hal.h"
#include "cdx_common.h"
#include "cdx_ctrl.h"
#include "cdx_ioctl.h"
#include "cdx_timer.h"
#include "cdx_cmdhandler.h"
#include "layer2.h"
#include "globals.h"
#include "devman.h"

/* ls104x hardware has a single fman */
#define FMAN_INDEX 0 

#define MAX_CDX_INIT_FUNCTIONS  16
typedef void (*cdx_deinit_func)(void);
void register_cdx_deinit_func(cdx_deinit_func func);
/* Enter/leave a configuration or terminal teardown transaction; entry must
 * hold neither RTNL nor ctrl.mutex. Runtime callbacks use the backend API. */
void cdx_ctrl_lock_with_rtnl(void);
void cdx_ctrl_unlock_with_rtnl(void);
extern atomic_t num_active_connections;
extern struct cdx_fman_info *fman_info;

#endif /* _CDX_H_ */

/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _CDX_CTRL_H_
#define _CDX_CTRL_H_

struct _cdx_ctrl {
	struct mutex mutex;
	spinlock_t lock;
	struct device *dev;
	struct task_struct *timer_thread;
	struct hlist_head *timer_inner_wheel;
	struct hlist_head *timer_outer_wheel;

	int (*event_cb)(u16, u16, u16*);
};

struct _cdx_info {
	unsigned long ddr_phys_baseaddr;
	void *ddr_baseaddr;
	unsigned int ddr_size;
	void *cbus_baseaddr;
	void *apb_baseaddr;
	struct device dev;
	struct _cdx_ctrl ctrl;
};

extern struct _cdx_info *cdx_info;

#endif /* _CDX_CTRL_H_ */

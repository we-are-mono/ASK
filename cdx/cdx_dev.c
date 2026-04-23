/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                cdx_dev.c     
 * @description         cdx driver open,r,w,ioctl call implemnetations 
 */

#include <linux/device.h>
#include "linux/ioctl.h"
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fdtable.h>

#include "portdefs.h"
#include "misc.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "lnxwrp_fm.h"

/*
 * Concurrency:
 *   cdx_ctrl_open_count (atomic_t)
 *      - Single-opener gate. Flipped 1->0 by cdx_ctrl_open() via
 *        atomic_cmpxchg; restored to 1 by cdx_ctrl_release() via
 *        atomic_set. Guarantees at most one fd against /dev/cdx_ctrl
 *        at any time.
 *   cdx_ctrl_{cdev_major,class,dev}
 *      - Set once in cdx_driver_init() (module init), cleared once
 *        in cdx_driver_deinit() (module exit). No per-ioctl access.
 *
 * Contexts:
 *   cdx_ctrl_open/release/ioctl - process, via /dev/cdx_ctrl.
 *     All ioctls are gated by CAP_NET_ADMIN before dispatch.
 *     Dispatched handlers may take their own subsystem locks (e.g.
 *     dpa_cfg_lock for SET_PARAMS).
 */
static int cdx_ctrl_cdev_major = -1;
static struct class *cdx_ctrl_class;
static struct device *cdx_ctrl_dev;
static atomic_t cdx_ctrl_open_count;

int cdx_ctrl_open(struct inode *inode, struct file *filp);
int cdx_ctrl_release(struct inode *inode, struct file *filp);
long cdx_ctrl_ioctl(struct file *filp, unsigned int cmd,
                unsigned long args);


/* cdx device file ops */
static const struct file_operations cdx_dev_fops = {
        .owner                  = THIS_MODULE,
        .open                   = cdx_ctrl_open,
        .unlocked_ioctl         = cdx_ctrl_ioctl,
        .release                = cdx_ctrl_release
};

int cdx_ctrl_open(struct inode *inode, struct file *filp)
{
	if (atomic_cmpxchg(&cdx_ctrl_open_count, 1, 0) != 1)
		return -EBUSY;
	return 0;
}

int cdx_ctrl_release(struct inode *inode, struct file *filp)
{
	atomic_set(&cdx_ctrl_open_count, 1);
	return 0;
}

#ifdef DPAA_DEBUG_ENABLE
extern void *get_muram_data(uint32_t *size);
static long cdx_get_muram_data(unsigned long args)
{
	long retval;
	uint8_t *pdata;
	uint32_t size;
	struct muram_data data_in;

	if(copy_from_user(&data_in, (void *)args,
				sizeof(struct muram_data))) {
		DPA_ERROR("%s::unable to copy struct get_muram_data\n", __func__);
		return (-EIO);
	}
	pdata = get_muram_data(&size);
	if (!pdata) {
		DPA_ERROR("%s::get_muram_data failed\n", __func__);
		return (-EIO);
	}
	if (size > data_in.size) {
		DPA_ERROR("%s::muram data size is %d,does not fit\n", __func__, size);
		retval = -EINVAL;
		goto func_ret;
	}
	data_in.size = size;
	if(copy_to_user(data_in.buff, pdata, size)) {
		DPA_ERROR("%s::unable to copy muram data\n", __func__);
		retval = -EIO;
		goto func_ret;
	}
	if (copy_to_user((void *)args, &data_in, sizeof(struct muram_data))) {
		DPA_ERROR("%s::unable to copy result\n", __func__);
		retval = -EIO;
		goto func_ret;
	}
	retval = 0;
func_ret:
	kfree(pdata);
	return retval;
}
#endif

/*
 * Table-driven ioctl dispatch, matching the validator-table
 * idiom that FCI cmdprocs use (cdx_cmd_validator.h). The ioctl
 * ABI is different enough from FCI's (cmd, cmd_len, pcmd)
 * that we keep a file-local spec here rather than reusing
 * cdx_dispatch_cmd: ioctl commands don't carry a cmd_len and
 * the handler communicates back via copy_to_user instead of an
 * in/out buffer. What we do preserve is the single lookup
 * surface so adding, removing, or gating a new ioctl is a
 * single-line table edit.
 */
struct cdx_ioctl_spec {
	unsigned int cmd;
	long (*handle)(unsigned long args);
};

static long cdx_ioc_set_dpa_params_wrap(unsigned long args)
{
	return cdx_ioc_set_dpa_params(args);
}

static const struct cdx_ioctl_spec cdx_ioctl_table[] = {
	{ CDX_CTRL_DPA_SET_PARAMS,      cdx_ioc_set_dpa_params_wrap },
#ifdef DPAA_DEBUG_ENABLE
	{ CDX_CTRL_DPA_GET_MURAM_DATA,  cdx_get_muram_data },
#endif
};

long cdx_ctrl_ioctl(struct file *filp, unsigned int cmd,
                unsigned long args)
{
	size_t i;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	for (i = 0; i < ARRAY_SIZE(cdx_ioctl_table); i++) {
		if (cdx_ioctl_table[i].cmd == cmd)
			return cdx_ioctl_table[i].handle(args);
	}

	DPA_ERROR("%s::unsupported ioctl cmd %x\n", __func__, cmd);
	/* Linux convention: ENOTTY means "fd doesn't recognize this ioctl",
	 * which is what happened here. EINVAL is overloaded to mean "the
	 * handler got bad args", reserve it for that. */
	return -ENOTTY;
}

static void cdx_driver_deinit(void)
{
	device_destroy(cdx_ctrl_class, MKDEV(cdx_ctrl_cdev_major, 0));
	class_destroy(cdx_ctrl_class);
	unregister_chrdev(cdx_ctrl_cdev_major, CDX_CTRL_CLS_CDEVNAME);
	return;
}

int cdx_driver_init(void)
{
	/* Cannot initialize the wrapper twice */
	if (cdx_ctrl_cdev_major >= 0)
		return 0;

	//initialize driver usage count
	atomic_set(&cdx_ctrl_open_count, 1);
	cdx_ctrl_cdev_major = register_chrdev(0,CDX_CTRL_CDEVNAME,&cdx_dev_fops);
	if (cdx_ctrl_cdev_major < 0) {
		DPA_ERROR("%s::Could not register dev %s\n", 
				__func__, CDX_CTRL_CDEVNAME);
		return -1;
	}

	cdx_ctrl_class = class_create(CDX_CTRL_CLS_CDEVNAME);
	if (IS_ERR(cdx_ctrl_class)) {
		DPA_ERROR("%s::Failed to create %s class device\n",
				__func__, CDX_CTRL_CLS_CDEVNAME);
		unregister_chrdev(cdx_ctrl_cdev_major, CDX_CTRL_CLS_CDEVNAME);
		cdx_ctrl_class = NULL;
		return -1;
	}

	cdx_ctrl_dev = device_create( cdx_ctrl_class,NULL,
			MKDEV(cdx_ctrl_cdev_major, 0),NULL,CDX_CTRL_CLS_CDEVNAME);
	if (IS_ERR(cdx_ctrl_dev)) {
		DPA_ERROR("%s::Failed to create %s device\n",
				__func__, CDX_CTRL_CLS_CDEVNAME);
		class_destroy(cdx_ctrl_class);
		unregister_chrdev(cdx_ctrl_cdev_major, CDX_CTRL_CLS_CDEVNAME);
		cdx_ctrl_cdev_major = -1;
		return -1;
	}
	register_cdx_deinit_func(cdx_driver_deinit);
	return 0;
}




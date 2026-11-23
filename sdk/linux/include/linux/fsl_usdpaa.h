/* Copyright 2011-2012 Freescale Semiconductor, Inc.
 * Copyright 2020 NXP
 * This file is licensed under the terms of the GNU General Public License
 * version 2.  This program is licensed "as is" without any warranty of any
 * kind, whether express or implied.
 */

#ifndef FSL_USDPAA_H
#define FSL_USDPAA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/fsl_qman.h> /* For "enum qm_channel" */
#include <linux/compat.h>


#ifdef __KERNEL__
/* This interface is needed in a few places and though it's not specific to
 * USDPAA as such, creating a new header for it doesn't make any sense. The
 * qbman kernel driver implements this interface and uses it as the backend for
 * both the FQID and BPID allocators. The fsl_usdpaa driver also uses this
 * interface for tracking per-process allocations handed out to user-space. */
struct dpa_alloc {
	struct list_head free;
	spinlock_t lock;
	struct list_head used;
};
#define DECLARE_DPA_ALLOC(name) \
	struct dpa_alloc name = { \
		.free = { \
			.prev = &name.free, \
			.next = &name.free \
		}, \
		.lock = __SPIN_LOCK_UNLOCKED(name.lock), \
		.used = { \
			 .prev = &name.used, \
			 .next = &name.used \
		 } \
	}
static inline void dpa_alloc_init(struct dpa_alloc *alloc)
{
	INIT_LIST_HEAD(&alloc->free);
	INIT_LIST_HEAD(&alloc->used);
	spin_lock_init(&alloc->lock);
}
int dpa_alloc_new(struct dpa_alloc *alloc, u32 *result, u32 count, u32 align,
		  int partial);
void dpa_alloc_free(struct dpa_alloc *alloc, u32 base_id, u32 count);
void dpa_alloc_seed(struct dpa_alloc *alloc, u32 fqid, u32 count);

/* Like 'new' but specifies the desired range, returns -ENOMEM if the entire
 * desired range is not available, or 0 for success. */
int dpa_alloc_reserve(struct dpa_alloc *alloc, u32 base_id, u32 count);
#endif /* __KERNEL__ */


/************************************
 * Link Status support for user space
 * interface
 ************************************/
#define IF_NAME_MAX_LEN 16
#define NODE_NAME_LEN	32
#define ETH_LINK_DOWN 0
#define ETH_LINK_UP 1

struct usdpaa_ioctl_link_status {
	/* network device node name */
	char		if_name[IF_NAME_MAX_LEN];
	/* Eventfd value */
	uint32_t	efd;
};

#define USDPAA_IOCTL_ENABLE_LINK_STATUS_INTERRUPT \
	_IOW(USDPAA_IOCTL_MAGIC, 0x0E, struct usdpaa_ioctl_link_status)

#define USDPAA_IOCTL_DISABLE_LINK_STATUS_INTERRUPT \
	_IOW(USDPAA_IOCTL_MAGIC, 0x0F, char[IF_NAME_MAX_LEN])

struct usdpaa_ioctl_link_status_args {
	/* network device node name */
	char    if_name[IF_NAME_MAX_LEN];
	/* link status(UP/DOWN) */
	int     link_status;
	int	link_speed;
	int	link_duplex;
	int	link_autoneg;
};

struct usdpaa_ioctl_update_link_status {
	/* network device node name */
	char    if_name[IF_NAME_MAX_LEN];
	/* link status(ETH_LINK_UP/DOWN) */
	int     set_link_status;
};

struct usdpaa_ioctl_update_link_speed {
	/* network device node name*/
	char    if_name[IF_NAME_MAX_LEN];
	int	link_speed;
	int	link_duplex;
};

#define USDPAA_IOCTL_GET_LINK_STATUS \
	_IOWR(USDPAA_IOCTL_MAGIC, 0x10, struct usdpaa_ioctl_link_status_args)

#define USDPAA_IOCTL_UPDATE_LINK_STATUS \
	_IOW(USDPAA_IOCTL_MAGIC, 0x11, struct usdpaa_ioctl_update_link_status)

#define USDPAA_IOCTL_UPDATE_LINK_SPEED \
	_IOW(USDPAA_IOCTL_MAGIC, 0x12, struct usdpaa_ioctl_update_link_speed)

#define USDPAA_IOCTL_GET_IOCTL_VERSION \
	_IOR(USDPAA_IOCTL_MAGIC, 0x14, int)

#define USDPAA_IOCTL_RESTART_LINK_AUTONEG \
	_IOW(USDPAA_IOCTL_MAGIC, 0x13, char[IF_NAME_MAX_LEN])

#ifdef __cplusplus
}
#endif

#endif /* FSL_USDPAA_H */

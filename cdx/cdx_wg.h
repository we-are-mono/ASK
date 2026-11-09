/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_WG_H
#define CDX_WG_H

#include <linux/types.h>

struct net_device;
struct cdx_wg_dev;

/* WireGuard offload (cdx_wg.c): a WireGuard device registered as an egress
 * the classifier may finish frames for, and the receive path for its tunnels.
 *
 * Registration is three coupled things, as a Wi-Fi VAP's is, and shares none
 * of them with it:
 *
 *   - the logical interface (IF_TYPE_WG), so the encoder resolves the egress;
 *   - the devman record carrying the device's id, so the encoder's WireGuard
 *     arm turns the id into one of the device's seal queues;
 *   - the seal queues themselves, one per CPU.
 */

int cdx_wg_init(void);

/* Whether `dev` can be registered: a WireGuard device in init_net, with the
 * WireGuard offload up. Needs neither the transaction nor RTNL. */
bool cdx_wg_dev_supported(struct net_device *dev);

/* Register `dev` and return its opaque owner. Requires the flowtable
 * transaction and RTNL, in that order, and sleeps; a netdev notifier records
 * the intent and lets a worker call this (ask_flowtable_wg.c). The device is
 * borrowed, never referenced: the datapath lets go of it inside its
 * unregistration, and cdx_wg_dev_del() reads only what was copied.
 *
 * -EOPNOTSUPP: not cdx_wg_dev_supported(). -EEXIST: already registered.
 * -ENOSPC: no free slot or logical interface. -ENOMEM, -EIO: the queues or the
 * record could not be built. Nothing is left registered on any error, and
 * *result is NULL. */
int cdx_wg_dev_add(struct net_device *dev, struct cdx_wg_dev **result);

/* Always consumes *wdev: its receive steers, devman record, logical interface
 * and seal queues. Transaction and RTNL held; every flow egressing through the
 * device retired first. Well defined after the device unregistered. */
void cdx_wg_dev_del(struct cdx_wg_dev **wdev);

/* For cdx itself: the egress predicate and the encoder's WireGuard arm. */
bool cdx_wg_dev_is_open(const struct net_device *dev);
bool cdx_wg_owns(u16 id, const struct net_device *dev);
int cdx_wg_get_seal_fq(u16 id, u32 *fqid);

#endif

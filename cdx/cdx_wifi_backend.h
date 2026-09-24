/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_WIFI_BACKEND_H
#define CDX_WIFI_BACKEND_H

#include <linux/types.h>

struct net_device;
struct cdx_wifi_vap;

/* A VAP is a netdev the classifier may enqueue finished frames to.
 *
 * A VAP registering is a netdev event, and its name, index and address come
 * off the netdev: what the caller supplies is the device, and everything the
 * hardware needs is read from it.
 *
 * Registration is three coupled things, and doing fewer leaves hardware that
 * half-works:
 *
 *   - the logical interface, so the encoder can resolve an egress by itf id;
 *   - the devman record carrying the VAP id, so the encoder's WLAN arm can
 *     turn that id into a forwarding frame queue;
 *   - the VWD slot, which is what builds the frame queues that id names.
 *
 * They are one operation here because no caller has a use for a subset, and
 * because the failure handling is the interesting part: a partial registration
 * is torn back down rather than returned.
 */

/* Whether a VAP can be built on this device.
 *
 * Identity, not policy. This answers whether the hardware side can carry a
 * VAP at all -- the Wi-Fi offline port came up, the VAP table has a free slot,
 * and the device is one whose frames the classifier could address. It does not
 * ask whether the device *should* be a VAP: that it is a cfg80211 netdev in AP
 * mode is the adapter's question, decided against dev->ieee80211_ptr where the
 * rest of that module's device policy lives, exactly as the equivalent split
 * is drawn for IPsec and multicast.
 *
 * Needs neither the transaction nor RTNL, so a notifier may call it before
 * deciding whether the device is worth queueing work for.
 */
bool cdx_wifi_vap_supported(struct net_device *dev);

/* Register `dev` as a VAP and return its opaque owner.
 *
 * Requires the flowtable transaction *and* RTNL, in that order -- the order
 * cdx_ft_admission_begin() takes them, and the only order this module ever
 * takes them in. The transaction is needed because registration publishes a
 * logical interface the classifier resolves egresses against; RTNL is needed
 * because bringing the VAP up walks the netdev list to publish its aliases and
 * because the device must not unregister underneath it. A netdev notifier
 * therefore cannot call this directly: it already holds RTNL, and taking the
 * transaction under it is the inversion that cdx_ft_admission_begin() exists
 * to avoid. Record the intent and let a worker do this, as the multicast
 * learner and the IPsec next-hop watch both do.
 *
 * The VAP id is allocated here rather than supplied. A caller has no way to
 * know which ids are free -- the VWD slot table and the physical-port range
 * are both indexed by them.
 *
 * The device is **borrowed**, not pinned, and the distinction is the whole of
 * this interface's teardown contract. VWD stores the same pointer the same
 * way: vwd_vap_up() takes a reference, records the device and drops the
 * reference before returning, leaving its own netdev notifier to clear the
 * pointer when the device unregisters. A reference taken here would not make
 * that pointer safer and would make unregistration impossible, because
 * unregister_netdevice() waits for every reference and this one is not
 * dropped until the caller's worker retires the VAP -- which runs after
 * unregistration. So everything cdx_wifi_vap_del() needs is copied out at
 * registration and the device is never read back.
 *
 * Sleeps: the frame queues are built with GFP_KERNEL and qman setup.
 *
 * -EOPNOTSUPP: the device cannot carry a VAP, per cdx_wifi_vap_supported().
 * -EEXIST: this device already has one.
 * -ENOMEM: no memory for the VAP's own record.
 * -ENOSPC: no free VAP id, or the logical interface table is full.
 * -EIO: the frame queues or the logical interface could not be built. Nothing
 *  is left registered.
 * On any error *result is NULL.
 */
int cdx_wifi_vap_add(struct net_device *dev, struct cdx_wifi_vap **result);

/* Always consumes *vap. Releases the VWD slot and its frame queues, the
 * devman record and the logical interface.
 *
 * Requires the transaction and RTNL, as the add does, and sleeps for the same
 * reasons -- unpublishing waits out the lock-free consumers of the pointer the
 * add published. It reads only fields copied at registration, so it is safe
 * after the device has gone.
 *
 * A flow still naming this VAP as its egress is not this side's problem to
 * solve: the caller retires its dependent directions first, exactly as it does
 * for a neighbour, a route or an SA.
 *
 * Calling this for a device that has already unregistered is well defined and
 * expected. VWD's own netdev notifier tears the slot down when the device
 * goes, so by the time a worker gets here the hardware half may already be
 * gone; what remains -- the logical interface and the devman record, which no
 * notifier owns -- is released regardless. The two halves are idempotent
 * separately for exactly this reason.
 */
void cdx_wifi_vap_del(struct cdx_wifi_vap **vap);

#endif

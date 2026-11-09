// SPDX-License-Identifier: GPL-2.0-or-later
/* Wi-Fi VAPs.
 */
#include "ask_flowtable_internal.h"

/* Wi-Fi VAPs.
 *
 * A VAP registering is a netdev event, and that is the whole of the control
 * plane that FPP_CMD_WIFI_VAP_ENTRY, a userspace daemon and a static UCI file
 * used to be.
 *
 * It cannot be done where it is noticed. Registration needs the backend
 * transaction and RTNL, and the two have one safe order: RTNL is taken under
 * the transaction only by trying (cdx_ft_admission_begin()), because the bind
 * path already takes the transaction under RTNL and a blocking rtnl_lock()
 * inside the transaction would invert that -- lockdep reported exactly this at
 * unload, where the exit path once blocked on RTNL with the transaction held;
 * it now takes RTNL first. A netdev notifier arrives already holding RTNL, so
 * the notifier records what it saw and a worker reconciles it, as the multicast
 * learner and the IPsec next-hop watch both do, for the same reason.
 */
struct ft_wifi_watch {
	struct list_head list;
	/* NULL once the device has unregistered. Only ever compared or
	 * referenced under ft_wifi_lock, never stored beyond a worker pass. */
	struct net_device *dev;
	struct cdx_wifi_vap *vap;
	bool wanted;
	bool gone;
	/* The registration copied this device's hardware address into the
	 * port and into the encoder's record of it, and neither is re-read per
	 * frame -- so an address that changes afterwards leaves the classifier
	 * writing the old one as the source of every frame leaving this VAP.
	 * There is no way to correct it in place, for the same reason an SA's
	 * next hop cannot be: it is built into what was registered. So the VAP
	 * is retired and registered again, which this asks the worker to do. */
	bool stale;
	/* The device `vap` was registered for, kept after `dev` is cleared so
	 * the entries forwarding through it can be found when it is retired.
	 * Only compared, never followed. */
	const struct net_device *vap_dev;
};

static LIST_HEAD(ft_wifi_watches);
static DEFINE_MUTEX(ft_wifi_lock);
static bool ft_wifi_stopping;
unsigned int ft_wifi_registered;
atomic64_t ft_wifi_refusals = ATOMIC64_INIT(0);
static void ft_wifi_work_fn(struct work_struct *work);
static DECLARE_WORK(ft_wifi_work, ft_wifi_work_fn);

/* Which netdevs are VAPs, and the reason this is policy rather than mechanism.
 *
 * A cfg80211 device in AP or AP_VLAN mode. That is a property of the device
 * instead of a name in a configuration file, so a station-mode, monitor or P2P
 * interface fails it without having to be excluded by hand, and an interface
 * that changes mode stops being a VAP at the moment it does. AP_VLAN counts
 * because it is an AP's per-station egress and carries frames the same way.
 *
 * Running is part of it, and not as a policy preference -- the backend cannot
 * do anything else. vwd_vap_up() refuses a device that is not IFF_UP, so
 * offering one can only produce a failed registration; a board that registers
 * its AP interfaces at driver load and brings them up later (which is what
 * hostapd does here) would otherwise spend a refusal on every interface at
 * every boot, and count it.
 *
 * It also happens to be the only way the other half of this predicate is
 * observable. cfg80211_change_iface() changes an interface's type without
 * raising any netdev event at all -- no notifier, not even
 * netdev_state_change() -- so nothing would re-read the iftype on its own. A
 * type change goes through a down and an up, and those do raise events, so
 * gating on running is what makes "stopped being an AP" reach this at all.
 */
static bool ft_wifi_is_vap(struct net_device *dev)
{
	struct wireless_dev *wdev;

	ASSERT_RTNL();
	if (!netif_running(dev))
		return false;
	wdev = dev->ieee80211_ptr;
	return wdev && (wdev->iftype == NL80211_IFTYPE_AP ||
			wdev->iftype == NL80211_IFTYPE_AP_VLAN);
}

/* Record what this device should be and let the worker make it so. Called for
 * every event that can change the answer, including the ones that only change
 * it indirectly: hostapd sets the interface type and then brings it up, and
 * the type change alone raises no netdev event of its own. */
void ft_wifi_reconsider(struct net_device *dev)
{
	struct ft_wifi_watch *w, *found = NULL;
	bool want, changed = false;

	ASSERT_RTNL();
	want = ft_wifi_is_vap(dev) && cdx_wifi_vap_supported(dev);

	mutex_lock(&ft_wifi_lock);
	if (ft_wifi_stopping)
		goto out;
	list_for_each_entry(w, &ft_wifi_watches, list) {
		if (w->dev == dev) {
			found = w;
			break;
		}
	}
	if (!found) {
		if (!want)
			goto out;
		found = kzalloc(sizeof(*found), GFP_KERNEL);
		if (!found) {
			/* Nothing was registered, so nothing is inconsistent:
			 * the device simply is not offloaded until an event
			 * brings it past here again. */
			atomic64_inc(&ft_wifi_refusals);
			goto out;
		}
		found->dev = dev;
		list_add(&found->list, &ft_wifi_watches);
	}
	changed = found->wanted != want;
	found->wanted = want;
out:
	mutex_unlock(&ft_wifi_lock);
	if (changed)
		schedule_work(&ft_wifi_work);
}

/* This device's hardware address moved, so what was registered for it no
 * longer describes it. Marked rather than corrected: see ft_wifi_watch.stale.
 */
void ft_wifi_address_changed(struct net_device *dev)
{
	struct ft_wifi_watch *w;
	bool changed = false;

	ASSERT_RTNL();
	mutex_lock(&ft_wifi_lock);
	list_for_each_entry(w, &ft_wifi_watches, list) {
		if (w->dev != dev || !w->vap)
			continue;
		w->stale = true;
		changed = true;
	}
	mutex_unlock(&ft_wifi_lock);
	if (changed)
		schedule_work(&ft_wifi_work);
}

/* The device is going. Nothing may follow the pointer after this returns.
 *
 * VWD's own netdev notifier takes the hardware half of the VAP down as the
 * device unregisters, so what the worker still has to release is the logical
 * interface and the devman record -- neither of which needs the device, which
 * is why the backend copied what it needs at registration time. */
void ft_wifi_device_gone(struct net_device *dev)
{
	struct ft_wifi_watch *w;
	bool changed = false;

	ASSERT_RTNL();
	mutex_lock(&ft_wifi_lock);
	list_for_each_entry(w, &ft_wifi_watches, list) {
		if (w->dev != dev)
			continue;
		w->dev = NULL;
		w->gone = true;
		w->wanted = false;
		changed = true;
	}
	mutex_unlock(&ft_wifi_lock);
	if (changed)
		schedule_work(&ft_wifi_work);
}

/* Take every entry that forwards through @dev's VAP out of hardware before its
 * VWD slot is released: a slot is handed to the next VAP registered, and an
 * entry still in hardware would send the old VAP's unicast to the new one.
 * The native NETDEV_DOWN delete is not enough on its own -- it is skipped for
 * an entry still pending, or when nf_flow_table_cleanup() cannot allocate.
 * Returns false while a deletion awaits the datapath's proof, when the slot
 * must stay. Caller holds the transaction and RTNL. */
static bool ft_wifi_uses(const struct cdx_ft_entry *entry, const void *dev)
{
	return ft_entry_uses(entry, dev);
}

static bool ft_wifi_vap_drained(const struct net_device *dev)
{
	struct cdx_ft_entry *entry;

	list_for_each_entry(entry, &ft_entries, list)
		if (ft_entry_uses(entry, dev))
			ft_handle_invalidate(entry->handle, &ft_link_invalidations);
	/* A batch at a time, letting the transaction go between batches: RTNL,
	 * which the caller keeps, is the lock outside it. */
	while (ft_retire_batch(ft_wifi_uses, dev)) {
		cdx_ft_end();
		cond_resched();
		cdx_ft_begin();
	}
	return !cdx_ft_pending();
}

/* Give a claimed VAP back to its watch, marked so a later pass claims it again,
 * and last on the list so no other device waits behind it. Marked stale rather
 * than left as it was: an address change while it was claimed found no VAP to
 * mark. Only this worker frees a watch, and never one that holds a VAP. Caller
 * holds ft_wifi_lock. */
static void ft_wifi_unclaim(struct ft_wifi_watch *w, struct cdx_wifi_vap *vap)
{
	w->vap = vap;
	w->stale = true;
	ft_wifi_registered++;
	list_move_tail(&w->list, &ft_wifi_watches);
}

/* Whether a watch other than the device's own still holds a VAP for it: a
 * device that unregistered while its VAP awaits retirement, and a new one
 * allocated at the same address. The backend would refuse the new one as a
 * duplicate of the slot not yet released, so it waits for the retirement
 * instead. Caller holds ft_wifi_lock. */
static bool ft_wifi_slot_held(const struct net_device *dev)
{
	struct ft_wifi_watch *w;

	list_for_each_entry(w, &ft_wifi_watches, list)
		if (w->vap && w->vap_dev == dev)
			return true;
	return false;
}

static void ft_wifi_work_fn(struct work_struct *work)
{
	struct ft_wifi_watch *w, *tmp;

	/* One VAP per pass. The transaction is taken and dropped around each,
	 * and ft_wifi_lock is never held across it -- the same discipline the
	 * multicast worker keeps, and for the same reason: the backend sleeps.
	 */
	for (;;) {
		struct cdx_wifi_vap *vap = NULL;
		struct net_device *dev = NULL;
		const struct net_device *vap_dev = NULL;
		struct ft_wifi_watch *claimed = NULL;
		int rc;

		mutex_lock(&ft_wifi_lock);
		list_for_each_entry_safe(w, tmp, &ft_wifi_watches, list) {
			if (w->wanted && !w->vap && !ft_wifi_slot_held(w->dev)) {
				/* Referenced here, under the lock that
				 * ft_wifi_device_gone() also takes, so the
				 * device cannot be freed between choosing it
				 * and using it below. Released at the end of
				 * this pass; a reference held any longer would
				 * be one unregister_netdevice() waits on. */
				dev = w->dev;
				dev_hold(dev);
				break;
			}
			if (w->vap && (!w->wanted || w->stale)) {
				/* Claimed here rather than cleared after the
				 * delete: the watch must stop naming this VAP
				 * before the lock is dropped, or a later pass
				 * finds the same pointer again and hands it to
				 * the backend twice.
				 *
				 * A stale one is retired the same way, and
				 * leaves `wanted` set -- so the next pass sees
				 * a wanted watch with no VAP and registers it
				 * again, this time reading the address the
				 * device has now. */
				vap = w->vap;
				vap_dev = w->vap_dev;
				claimed = w;
				w->vap = NULL;
				w->stale = false;
				ft_wifi_registered--;
				break;
			}
			if (!w->wanted && !w->vap && w->gone) {
				list_del(&w->list);
				kfree(w);
			}
		}
		mutex_unlock(&ft_wifi_lock);

		if (!dev && !vap)
			return;

		cdx_ft_begin();
		if (cdx_ft_admission_begin()) {
			/* RTNL is held by something that can wait for this
			 * transaction. Come back rather than invert the two --
			 * which is the common case for a retirement, scheduled
			 * from a notifier whose caller still holds RTNL, unload's
			 * replay among them. A VAP claimed for it goes back to
			 * its watch: dropped here, its slot would stay taken for
			 * as long as CDX is loaded, and module exit would never
			 * see it. */
			cdx_ft_end();
			if (dev)
				dev_put(dev);
			if (vap) {
				mutex_lock(&ft_wifi_lock);
				ft_wifi_unclaim(claimed, vap);
				mutex_unlock(&ft_wifi_lock);
			}
			schedule_work(&ft_wifi_work);
			return;
		}

		if (dev) {
			struct cdx_wifi_vap *made = NULL;

			/* Re-read the decision under the locks that make it
			 * true rather than trusting what the notifier saw: the
			 * device may have changed mode or started
			 * unregistering since. */
			if (dev->reg_state != NETREG_REGISTERED ||
			    !ft_wifi_is_vap(dev))
				rc = -ENODEV;
			else
				rc = cdx_wifi_vap_add(dev, &made);

			mutex_lock(&ft_wifi_lock);
			list_for_each_entry(w, &ft_wifi_watches, list) {
				if (w->dev != dev)
					continue;
				if (made) {
					w->vap = made;
					w->vap_dev = dev;
					made = NULL;
					ft_wifi_registered++;
				} else {
					/* Give up on this device rather than
					 * spin: an add that failed once will
					 * fail the same way until something
					 * about the device changes, and every
					 * such change comes back through
					 * ft_wifi_reconsider(). */
					w->wanted = false;
					atomic64_inc(&ft_wifi_refusals);
				}
				break;
			}
			mutex_unlock(&ft_wifi_lock);

			/* Nothing on the list claimed it -- the watch went
			 * away while the transaction was open. Do not leak the
			 * registration it no longer owns. */
			if (made)
				cdx_wifi_vap_del(&made);
			if (rc && rc != -ENODEV)
				pr_warn_ratelimited("cdx flowtable: %s could not be offloaded as a Wi-Fi VAP (%d)\n",
						    netdev_name(dev), rc);
		} else if (!ft_wifi_vap_drained(vap_dev)) {
			bool stopping, pending;

			/* Not yet: give the VAP back to its watch. The
			 * deletion's proof is asked for with RTNL let go of --
			 * the recovery takes it itself -- and once a second,
			 * admission's own pace. */
			mutex_lock(&ft_wifi_lock);
			ft_wifi_unclaim(claimed, vap);
			stopping = ft_wifi_stopping;
			mutex_unlock(&ft_wifi_lock);
			cdx_ft_admission_end();
			cdx_ft_recover();
			pending = cdx_ft_pending();
			cdx_ft_end();
			if (stopping)
				return;
			if (pending)
				msleep(MSEC_PER_SEC);
			continue;
		} else {
			/* Already unlinked from its watch above, so this owns
			 * it outright and nothing else can reach it. */
			cdx_wifi_vap_del(&vap);
		}

		cdx_ft_admission_end();
		cdx_ft_end();
		if (dev)
			dev_put(dev);
	}
}

/* Retire every VAP this module registered. Unload cannot leave a logical
 * interface or a VWD slot owned by a module that is going away, and there is
 * no notifier replay for unregistration to do it. */
void ft_wifi_exit(void)
{
	struct ft_wifi_watch *w, *tmp;

	mutex_lock(&ft_wifi_lock);
	ft_wifi_stopping = true;
	mutex_unlock(&ft_wifi_lock);
	cancel_work_sync(&ft_wifi_work);

	list_for_each_entry_safe(w, tmp, &ft_wifi_watches, list) {
		if (w->vap) {
			/* RTNL before the transaction, never after it: the bind
			 * path takes the transaction under RTNL (via dpa_setup_tc),
			 * so the reverse order here is a lock inversion lockdep
			 * reports at unload once a table has ever been bound. */
			rtnl_lock();
			cdx_ft_begin();
			/* Its entries out of hardware first, as the worker's
			 * retirement does: the bindings that would take them
			 * are only drained later in unload. An unproven unlink
			 * left behind is proven before CDX is released. */
			ft_wifi_vap_drained(w->vap_dev);
			cdx_wifi_vap_del(&w->vap);
			cdx_ft_end();
			rtnl_unlock();
			ft_wifi_registered--;
		}
		list_del(&w->list);
		kfree(w);
	}
}

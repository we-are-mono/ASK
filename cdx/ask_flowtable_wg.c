// SPDX-License-Identifier: GPL-2.0-or-later
/* WireGuard devices.
 */
#include "ask_flowtable_internal.h"

/* WireGuard devices as egresses.
 *
 * A running WireGuard device in init_net is registered with cdx
 * (cdx_wg_dev_add()) so the flows the flowtable sends into it can be installed
 * with it as their egress; it is released when it stops running or goes.
 *
 * It cannot be done where it is noticed, for the reason the Wi-Fi watch next
 * door gives: registration needs the backend transaction and RTNL, in that
 * order, and a netdev notifier already holds RTNL. So the notifier records what
 * it saw and a worker reconciles it -- the same machinery as
 * ask_flowtable_wifi.c, kept separate so WireGuard and Wi-Fi share no state.
 * A WireGuard device's address is made up from its ifindex
 * (cdx_ft_wg_mac()), which does not change, so there is no address watch.
 */
struct ft_wg_watch {
	struct list_head list;
	/* NULL once the device has unregistered. Only ever compared or
	 * referenced under ft_wg_lock, never stored beyond a worker pass. */
	struct net_device *dev;
	struct cdx_wg_dev *wdev;
	bool wanted;
	bool gone;
	/* The device `wdev` was registered for, kept after `dev` is cleared so
	 * the entries forwarding through it can be found when it is retired.
	 * Only compared, never followed. */
	const struct net_device *wdev_dev;
};

static LIST_HEAD(ft_wg_watches);
static DEFINE_MUTEX(ft_wg_lock);
static bool ft_wg_stopping;
unsigned int ft_wg_registered;
atomic64_t ft_wg_refusals = ATOMIC64_INIT(0);
static void ft_wg_work_fn(struct work_struct *work);
static DECLARE_WORK(ft_wg_work, ft_wg_work_fn);

/* Running, as the backend's queues are only worth building for a device that
 * can take a packet, and a WireGuard device by its link kind. */
static bool ft_wg_is_dev(struct net_device *dev)
{
	ASSERT_RTNL();
	return netif_running(dev) && cdx_ft_wg_dev(dev);
}

/* Record what this device should be and let the worker make it so. */
void ft_wg_reconsider(struct net_device *dev)
{
	struct ft_wg_watch *w, *found = NULL;
	bool want, changed = false;

	ASSERT_RTNL();
	want = ft_wg_is_dev(dev) && cdx_wg_dev_supported(dev);

	mutex_lock(&ft_wg_lock);
	if (ft_wg_stopping)
		goto out;
	list_for_each_entry(w, &ft_wg_watches, list) {
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
			 * the device is not offloaded until an event brings it
			 * past here again. */
			atomic64_inc(&ft_wg_refusals);
			goto out;
		}
		found->dev = dev;
		list_add(&found->list, &ft_wg_watches);
	}
	changed = found->wanted != want;
	found->wanted = want;
out:
	mutex_unlock(&ft_wg_lock);
	if (changed)
		schedule_work(&ft_wg_work);
}

/* The device is going. Nothing may follow the pointer after this returns; the
 * backend let go of it inside the same unregistration (cdx_wg.c), and what the
 * worker still releases needs only what the registration copied. */
void ft_wg_device_gone(struct net_device *dev)
{
	struct ft_wg_watch *w;
	bool changed = false;

	ASSERT_RTNL();
	mutex_lock(&ft_wg_lock);
	list_for_each_entry(w, &ft_wg_watches, list) {
		if (w->dev != dev)
			continue;
		w->dev = NULL;
		w->gone = true;
		w->wanted = false;
		changed = true;
	}
	mutex_unlock(&ft_wg_lock);
	if (changed)
		schedule_work(&ft_wg_work);
}

/* Take every entry that forwards through @dev out of hardware before its
 * registration is released: a slot is handed to the next device registered,
 * and an entry still in hardware would enqueue to queues that are gone. The
 * native NETDEV_DOWN delete is not enough on its own -- it is skipped for an
 * entry still pending, or when nf_flow_table_cleanup() cannot allocate.
 * Returns false while a deletion awaits the datapath's proof, when the
 * registration must stay. Caller holds the transaction and RTNL. */
static bool ft_wg_uses(const struct cdx_ft_entry *entry, const void *dev)
{
	return ft_entry_uses(entry, dev);
}

static bool ft_wg_drained(const struct net_device *dev)
{
	struct cdx_ft_entry *entry;

	list_for_each_entry(entry, &ft_entries, list)
		if (ft_entry_uses(entry, dev))
			ft_handle_invalidate(entry->handle, &ft_link_invalidations);
	/* A batch at a time, letting the transaction go between batches: RTNL,
	 * which the caller keeps, is the lock outside it. */
	while (ft_retire_batch(ft_wg_uses, dev)) {
		cdx_ft_end();
		cond_resched();
		cdx_ft_begin();
	}
	return !cdx_ft_pending();
}

/* Give a claimed registration back to its watch, last on the list so no other
 * device waits behind it. Only this worker frees a watch, and never one that
 * holds a registration. Caller holds ft_wg_lock. */
static void ft_wg_unclaim(struct ft_wg_watch *w, struct cdx_wg_dev *wdev)
{
	w->wdev = wdev;
	ft_wg_registered++;
	list_move_tail(&w->list, &ft_wg_watches);
}

/* Whether a watch other than the device's own still holds a registration for
 * it: a device that unregistered while its registration awaits retirement,
 * and a new one allocated at the same address. The backend would refuse the
 * new one as a duplicate, so it waits for the retirement instead. Caller holds
 * ft_wg_lock. */
static bool ft_wg_slot_held(const struct net_device *dev)
{
	struct ft_wg_watch *w;

	list_for_each_entry(w, &ft_wg_watches, list)
		if (w->wdev && w->wdev_dev == dev)
			return true;
	return false;
}

static void ft_wg_work_fn(struct work_struct *work)
{
	struct ft_wg_watch *w, *tmp;

	/* One device per pass. The transaction is taken and dropped around
	 * each, and ft_wg_lock is never held across it: the backend sleeps. */
	for (;;) {
		struct cdx_wg_dev *wdev = NULL;
		struct net_device *dev = NULL;
		const struct net_device *wdev_dev = NULL;
		struct ft_wg_watch *claimed = NULL;
		int rc;

		mutex_lock(&ft_wg_lock);
		list_for_each_entry_safe(w, tmp, &ft_wg_watches, list) {
			if (w->wanted && !w->wdev && !ft_wg_slot_held(w->dev)) {
				/* Referenced under the lock ft_wg_device_gone()
				 * also takes, so the device cannot be freed
				 * between choosing it and using it below.
				 * Released at the end of this pass. */
				dev = w->dev;
				dev_hold(dev);
				break;
			}
			if (w->wdev && !w->wanted) {
				/* Claimed here rather than cleared after the
				 * delete: the watch must stop naming this
				 * registration before the lock is dropped, or a
				 * later pass hands it to the backend twice. */
				wdev = w->wdev;
				wdev_dev = w->wdev_dev;
				claimed = w;
				w->wdev = NULL;
				ft_wg_registered--;
				break;
			}
			if (!w->wanted && !w->wdev && w->gone) {
				list_del(&w->list);
				kfree(w);
			}
		}
		mutex_unlock(&ft_wg_lock);

		if (!dev && !wdev)
			return;

		cdx_ft_begin();
		if (cdx_ft_admission_begin()) {
			/* RTNL is held by something that can wait for this
			 * transaction. Come back rather than invert the two; a
			 * registration claimed for retirement goes back to its
			 * watch, or it would stay taken while cdx is loaded. */
			cdx_ft_end();
			if (dev)
				dev_put(dev);
			if (wdev) {
				mutex_lock(&ft_wg_lock);
				ft_wg_unclaim(claimed, wdev);
				mutex_unlock(&ft_wg_lock);
			}
			schedule_work(&ft_wg_work);
			return;
		}

		if (dev) {
			struct cdx_wg_dev *made = NULL;

			/* Re-read the decision under the locks that make it
			 * true: the device may have gone down or started
			 * unregistering since the notifier saw it. */
			if (dev->reg_state != NETREG_REGISTERED || !ft_wg_is_dev(dev))
				rc = -ENODEV;
			else
				rc = cdx_wg_dev_add(dev, &made);

			mutex_lock(&ft_wg_lock);
			list_for_each_entry(w, &ft_wg_watches, list) {
				if (w->dev != dev)
					continue;
				if (made) {
					w->wdev = made;
					w->wdev_dev = dev;
					made = NULL;
					ft_wg_registered++;
				} else {
					/* Give up on this device rather than
					 * spin: an add that failed once fails
					 * the same way until something about
					 * the device changes, and every such
					 * change comes back through
					 * ft_wg_reconsider(). */
					w->wanted = false;
					atomic64_inc(&ft_wg_refusals);
				}
				break;
			}
			mutex_unlock(&ft_wg_lock);

			/* The watch went away while the transaction was open:
			 * do not leak the registration it no longer owns. */
			if (made)
				cdx_wg_dev_del(&made);
			if (rc && rc != -ENODEV)
				pr_warn_ratelimited("cdx flowtable: %s could not be offloaded as a WireGuard egress (%d)\n",
						    netdev_name(dev), rc);
		} else if (!ft_wg_drained(wdev_dev)) {
			bool stopping, pending;

			/* Not yet: give the registration back to its watch. The
			 * deletion's proof is asked for with RTNL let go of --
			 * the recovery takes it itself -- and once a second,
			 * admission's own pace. */
			mutex_lock(&ft_wg_lock);
			ft_wg_unclaim(claimed, wdev);
			stopping = ft_wg_stopping;
			mutex_unlock(&ft_wg_lock);
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
			cdx_wg_dev_del(&wdev);
		}

		cdx_ft_admission_end();
		cdx_ft_end();
		if (dev)
			dev_put(dev);
	}
}

/* Release every device this module registered: unload cannot leave a logical
 * interface or seal queues registered by a module that is going away. */
void ft_wg_exit(void)
{
	struct ft_wg_watch *w, *tmp;

	mutex_lock(&ft_wg_lock);
	ft_wg_stopping = true;
	mutex_unlock(&ft_wg_lock);
	cancel_work_sync(&ft_wg_work);

	list_for_each_entry_safe(w, tmp, &ft_wg_watches, list) {
		if (w->wdev) {
			/* RTNL before the transaction, never after it, as the
			 * Wi-Fi exit explains. Entries out of hardware first. */
			rtnl_lock();
			cdx_ft_begin();
			ft_wg_drained(w->wdev_dev);
			cdx_wg_dev_del(&w->wdev);
			cdx_ft_end();
			rtnl_unlock();
			ft_wg_registered--;
		}
		list_del(&w->list);
		kfree(w);
	}
}

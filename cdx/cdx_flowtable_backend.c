// SPDX-License-Identifier: GPL-2.0-or-later
/* CDX ownership and hardware services for the Linux flowtable adapter. */
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/workqueue.h>
#include "portdefs.h"
#include "cdx.h"
#include "cdx_flowtable.h"
#include "cdx_flowtable_backend.h"
#include "cdx_flowtable_hw.h"
#include "cdx_htb.h"
#include "cdx_ipsec_backend.h"
#include "cdx_mcast_backend.h"
#include "devman.h"
#include "dpa_ipsec.h"
#include "dpa_wifi.h"
#include "fm_ehash.h"

static bool ft_observe;
module_param_named(flowtable_observe, ft_observe, bool, 0444);
MODULE_PARM_DESC(flowtable_observe, "Validate requests but decline hardware installation");

/* ASK-DEBUG. Lives here rather than in the adapter because both modules make
 * admission decisions and one knob should govern both; the adapter reaches it
 * through the exported symbol. Writable at runtime (0644) on purpose -- the
 * question it answers usually arrives after the interesting boot. */
unsigned int cdx_ft_debug_mask;
EXPORT_SYMBOL_NS_GPL(cdx_ft_debug_mask, ASK_CDX_FLOWTABLE);
module_param_named(ask_debug, cdx_ft_debug_mask, uint, 0644);
MODULE_PARM_DESC(ask_debug, "ASK-DEBUG admission tracing: 1=refusals 2=accepts 4=devices");

/* Detach/reclaim must not forget an unproven hardware deletion. */
static bool ft_claimed, ft_failed;
static unsigned int ft_live;

/* The restart that follows ft_failed (cdx_ft_restart()). ft_terminal: it
 * cannot be proven safe in this boot, and the ports stay stopped for a reboot.
 * ft_epoch counts restarts from one, for a hold that has to tell whether a
 * restart has happened since it was taken. The rest describe the current
 * episode: when its ports were first stopped, the keys settled so far, the next
 * retry delay, how often the hardware has not answered, and whether its stall
 * has been reported. ft_resume_failures counts the ports a restart could not
 * start again. All under the control mutex; ft_terminal is also read without
 * it. */
static bool ft_terminal, ft_restart_notify, ft_stall_reported;
static char ft_terminal_reason[128];
module_param_string(flowtable_terminal_reason, ft_terminal_reason, sizeof(ft_terminal_reason), 0444);
MODULE_PARM_DESC(flowtable_terminal_reason, "Reason the datapath requires a reboot");
static unsigned int ft_restarts, ft_window_restarts, ft_episode_resolved, ft_hw_tries;
static unsigned int ft_resume_failures;
static u32 ft_epoch = 1;
static unsigned long ft_episode_start, ft_stopped_at, ft_window_start;
static unsigned long ft_restart_backoff = HZ;

/* Restarts allowed in each FT_RESTART_WINDOW, counted from the first. A
 * datapath that keeps failing deletes has something wrong with it that a
 * restart will not mend, and stopping for good is the honest answer then. */
#define FT_RESTART_WINDOW	(10 * 60 * HZ)
static unsigned int ft_restart_limit = 3;
module_param_named(flowtable_restart_limit, ft_restart_limit, uint, 0644);
MODULE_PARM_DESC(flowtable_restart_limit, "Datapath restarts allowed per 10 minutes after unproven deletions; 0 leaves every one to a reboot");

/* Retry delays: RTNL contended, the test hold below, and the bounds of the
 * exponential backoff for what software keeps a restart waiting on -- a key
 * the table refuses, deletions still owed a barrier. The hardware's own waits
 * are retried below. A restart still waiting after FT_RESTART_STALL says so,
 * once. */
#define FT_RESTART_RTNL_RETRY	(HZ / 10)
#define FT_RESTART_HOLD_RETRY	(HZ / 4)
#define FT_RESTART_BACKOFF_MAX	(30 * HZ)
#define FT_RESTART_STALL	(30 * HZ)

/* The hardware's own answers -- a stopped port gone idle, a barrier the
 * host-command channel completed -- come within moments when the FMan is well:
 * a port drains in microseconds, a barrier completes in well under a
 * millisecond, and one the channel took but never confirmed has failed it for
 * good already. So a restart waiting on either is retried soon, at a steady
 * interval, and an episode in which the hardware has failed to answer
 * FT_RESTART_HW_TRIES times -- a few seconds, a port's own wait for idle
 * included -- is one in which it will not: the latch is left for a reboot,
 * saying what it waited for. RTNL contention and the test hold are not the
 * hardware's and never count. */
#define FT_RESTART_HW_RETRY	(HZ / 4)
#define FT_RESTART_HW_TRIES	12

#ifdef CDX_DEBUG_FLOWTABLE
/* Test-only: keep the ports stopped after a latch, with every key recorded,
 * until cleared -- the window a test inspects the stopped datapath in. */
static bool ft_restart_hold;
module_param_named(flowtable_restart_hold, ft_restart_hold, bool, 0600);
MODULE_PARM_DESC(flowtable_restart_hold, "Hold the datapath stopped after an unproven deletion until cleared (test image)");
#endif

static bool ft_restart_held(void)
{
#ifdef CDX_DEBUG_FLOWTABLE
	return READ_ONCE(ft_restart_hold);
#else
	return false;
#endif
}

bool cdx_ft_observing(void)
{
	return ft_observe;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_observing, ASK_CDX_FLOWTABLE);

/* The SDK's normal ndo_open enables FMAN ports. A failed hardware unlink
 * belongs to the provider even after adapter detach, so guard that restart
 * here until CDX has settled it and restarted the datapath -- which clears the
 * latch under the RTNL this runs under, so a port opened after it starts on a
 * running datapath -- or, when that cannot be done, until provider teardown
 * has detached PCD and released its ports. */
static int cdx_ft_netdev_event(struct notifier_block *nb, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	/* A speed change passes through the carrier, so it arrives here too.
	 * An MTU change resizes the port's egress bounds, which count frames
	 * of the largest size the MTU admits, carrier or not -- and a hardware
	 * qdisc's class queues, whose RED curves count frames of the size it
	 * admits. That one after the devlist lock is dropped: the tree's lock
	 * is a mutex. */
	if ((((event == NETDEV_UP || event == NETDEV_CHANGE) && netif_carrier_ok(dev)) ||
	     event == NETDEV_CHANGEMTU) && dpa_netdev_is_physical(dev)) {
		dpa_fwd_cgr_follow_link(dev);
		if (event == NETDEV_CHANGEMTU)
			cdx_htb_mtu_changed(dev);
		return NOTIFY_DONE;
	}
	if (event != NETDEV_PRE_UP || !READ_ONCE(ft_failed) ||
	    !dpa_netdev_is_physical(dev))
		return NOTIFY_DONE;
	if (READ_ONCE(ft_terminal))
		netdev_err(dev, "CDX hardware retirement failed; unload CDX before restarting the port\n");
	else
		netdev_err(dev, "CDX is restarting the datapath after a failed hardware retirement; start the port once it has\n");
	return notifier_from_errno(-EIO);
}

static struct notifier_block ft_guard_nb = { .notifier_call = cdx_ft_netdev_event };
static bool ft_guard_registered;

int cdx_flowtable_guard_init(void)
{
	int rc;

	rc = register_netdevice_notifier(&ft_guard_nb);
	if (!rc)
		ft_guard_registered = true;
	return rc;
}

void cdx_flowtable_guard_exit(void)
{
	if (ft_guard_registered) {
		unregister_netdevice_notifier(&ft_guard_nb);
		ft_guard_registered = false;
	}
}

void cdx_ft_begin(void)
{
	mutex_lock(&cdx_info->ctrl.mutex);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_begin, ASK_CDX_FLOWTABLE);

bool cdx_ft_trybegin(void)
{
	return mutex_trylock(&cdx_info->ctrl.mutex);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_trybegin, ASK_CDX_FLOWTABLE);

void cdx_ft_end(void)
{
	mutex_unlock(&cdx_info->ctrl.mutex);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_end, ASK_CDX_FLOWTABLE);

void cdx_ft_assert_held(void)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_assert_held, ASK_CDX_FLOWTABLE);

bool cdx_ft_failed(void)
{
	cdx_ft_assert_held();
	return ft_failed;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_failed, ASK_CDX_FLOWTABLE);

bool cdx_ft_terminal(void)
{
	cdx_ft_assert_held();
	return ft_terminal;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_terminal, ASK_CDX_FLOWTABLE);

unsigned int cdx_ft_restarts(void)
{
	cdx_ft_assert_held();
	return ft_restarts;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_restarts, ASK_CDX_FLOWTABLE);

unsigned int cdx_ft_resume_failures(void)
{
	cdx_ft_assert_held();
	return ft_resume_failures;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_resume_failures, ASK_CDX_FLOWTABLE);

u32 cdx_ft_epoch(void)
{
	cdx_ft_assert_held();
	return ft_epoch;
}

/* The latch can no longer be settled in this boot. Said once, with why; the
 * ports stay stopped, everything stays refused, and a reboot clears it. */
static void cdx_ft_set_terminal(const char *why)
{
	if (ft_terminal)
		return;
	strscpy(ft_terminal_reason, why, sizeof(ft_terminal_reason));
	WRITE_ONCE(ft_terminal, true);
	pr_err("cdx flowtable: hardware stopped after unproven deletion; reboot required (%s)\n",
	       why);
}

/* The ports were found stopped and idle after a latch. Recorded once per
 * episode, for the restart's report of how long they were. */
static void cdx_ft_ports_stopped(void)
{
	if (ft_stopped_at)
		return;
	ft_stopped_at = jiffies ?: 1;
	pr_warn("cdx flowtable: ports stopped after unproven deletion\n");
}

/* Whether a restart may follow this latch: none at all with the limit at zero,
 * and no more than the limit within a window. */
static bool cdx_ft_restart_allowed(void)
{
	if (!ft_restart_limit) {
		cdx_ft_set_terminal("datapath restarts are disabled");
		return false;
	}
	if (!ft_window_start || time_after(jiffies, ft_window_start + FT_RESTART_WINDOW)) {
		ft_window_start = jiffies ?: 1;
		ft_window_restarts = 0;
	}
	if (ft_window_restarts >= ft_restart_limit) {
		cdx_ft_set_terminal("restart budget exhausted");
		return false;
	}
	return true;
}

/* A restart still waiting once the episode has lasted long enough to matter
 * says so, once, with what it is waiting for -- whatever that is. */
static void cdx_ft_restart_stalled(const char *why)
{
	if (!ft_stall_reported && ft_episode_start &&
	    time_after(jiffies, ft_episode_start + FT_RESTART_STALL)) {
		ft_stall_reported = true;
		pr_warn("cdx flowtable: datapath restart stalled for %u s: %s; still retrying\n",
			jiffies_to_msecs(jiffies - ft_episode_start) / 1000, why);
	}
}

/* A restart that has to wait: retried after the backoff, which doubles each
 * time up to its bound. The ports stay stopped meanwhile. */
static int cdx_ft_restart_later(const char *why, unsigned long *delay)
{
	*delay = ft_restart_backoff;
	ft_restart_backoff = min_t(unsigned long, 2 * ft_restart_backoff,
				   FT_RESTART_BACKOFF_MAX);
	cdx_ft_restart_stalled(why);
	return -EAGAIN;
}

/* A restart the hardware has not answered: retried soon, until it has failed to
 * answer too often in this episode, and then the latch is for a reboot. 0 when
 * terminal; -EAGAIN with *delay set otherwise. */
static int cdx_ft_restart_hw_wait(const char *why, unsigned long *delay)
{
	if (++ft_hw_tries >= FT_RESTART_HW_TRIES) {
		cdx_ft_set_terminal(why);
		return 0;
	}
	*delay = FT_RESTART_HW_RETRY;
	cdx_ft_restart_stalled(why);
	return -EAGAIN;
}

/* One barrier through the PCD once the ports have stopped. A frame a port had
 * in hand when it stopped may still be inside the FMan's controller; the
 * barrier a delete relies on to prove no lookup begun before it still walks
 * the tables proves the same of that frame. Nothing a stop lets go of is freed
 * before it. 0, also with no table to issue it through; -EAGAIN for one that
 * failed; -ENOTRECOVERABLE when the host-command channel has failed until
 * reset and no barrier will complete again. */
static int cdx_ft_stopped_barrier(void)
{
	void *td = dpa_get_ehash_td();

	if (!td || !ExternalHashTableFmPcdHcSync(td))
		return 0;
	return ExternalHashTableHcFailed(td) ? -ENOTRECOVERABLE : -EAGAIN;
}

/* Restart the datapath after a latch, which a stopped datapath makes provable.
 *
 * The latch exists because a classifier key may still be linked: a delete
 * could not prove it unlinked, and the FMan might walk to it. Once every port
 * that walks the tables is stopped and idle (dpa_cfg_stop()) and a barrier
 * has completed behind the last frame they let go of, nothing does, and the
 * doubt can be settled: each recorded key is looked for and deleted again, or
 * found in no bucket at all (cdx_ehash_resolve_abandoned()). Then a second
 * barrier, and everything parked for one goes too. What the tables still link
 * is then exactly what the live owners believe they link, and the ports can
 * start again -- under the same RTNL hold that clears the latch, so no port
 * opens in between.
 *
 * Anything that may pass waits and is retried, with the ports stopped: RTNL
 * contended, a port still finishing a frame, a key still linked, a barrier
 * that failed -- the hardware's own waits for a few seconds at most. Anything
 * that will not -- a port outside the configuration reaching a classifier, a
 * key nothing recorded, a malformed table, a host-command channel that has
 * failed, hardware that has stopped answering, the restart budget spent --
 * leaves the latch for a reboot, as it always was.
 *
 * 0: restarted, or terminal; -EAGAIN with *delay set: try again then. Caller
 * holds the transaction. */
static int cdx_ft_restart(unsigned long *delay)
{
	unsigned int resolved, released;
	int rc, unstarted;

	cdx_ft_assert_held();
	if (!ft_episode_start)
		ft_episode_start = jiffies ?: 1;
	if (!cdx_ft_restart_allowed())
		return 0;
	if (!rtnl_trylock()) {
		/* Soon and at a steady interval: RTNL is held for moments. */
		*delay = FT_RESTART_RTNL_RETRY;
		cdx_ft_restart_stalled("RTNL is contended");
		return -EAGAIN;
	}
	rc = dpa_cfg_stop();
	if (rc == -EXDEV) {
		rc = 0;
		/* Nor does an earlier stop prove anything any more: that port
		 * walks the tables whatever CDX's own do (cdx_ft_proven()). */
		ft_stopped_at = 0;
		cdx_ft_set_terminal("a port CDX did not configure reaches the classifier");
		goto out;
	}
	if (rc == -ENOTRECOVERABLE) {
		rc = 0;
		cdx_ft_set_terminal("the classifier ports cannot be started again");
		goto out;
	}
	if (rc) {
		rc = cdx_ft_restart_hw_wait("a port would not stop and go idle", delay);
		goto out;
	}
	rc = cdx_ft_stopped_barrier();
	if (rc == -ENOTRECOVERABLE) {
		rc = 0;
		cdx_ft_set_terminal("the host-command channel has failed");
		goto out;
	}
	if (rc) {
		rc = cdx_ft_restart_hw_wait("the PCD barrier kept failing", delay);
		goto out;
	}
	cdx_ft_ports_stopped();
	cdx_ft_hw_quiesced();
	if (ft_restart_held()) {
		*delay = FT_RESTART_HOLD_RETRY;
		cdx_ft_restart_stalled("held by flowtable_restart_hold");
		rc = -EAGAIN;
		goto out;
	}
	if (cdx_ehash_abandoned_lost()) {
		cdx_ft_set_terminal("a possibly linked key could not be recorded");
		goto out;
	}
	rc = cdx_ehash_resolve_abandoned(&resolved);
	ft_episode_resolved += resolved;
	if (rc == -ENOTRECOVERABLE) {
		rc = 0;
		cdx_ft_set_terminal("a possibly linked key could not be settled");
		goto out;
	}
	if (rc) {
		rc = cdx_ft_restart_later("a possibly linked key is still linked", delay);
		goto out;
	}
	rc = cdx_ft_stopped_barrier();
	if (rc == -ENOTRECOVERABLE) {
		rc = 0;
		cdx_ft_set_terminal("the host-command channel has failed");
		goto out;
	}
	if (rc) {
		rc = cdx_ft_restart_hw_wait("the PCD barrier kept failing", delay);
		goto out;
	}
	cdx_ehash_quarantine_free_all();
	if (cdx_ft_pending()) {
		rc = cdx_ft_restart_later("deletions still wait on a barrier", delay);
		goto out;
	}
	/* Every key that could name them is settled: a release still to come
	 * sees the new epoch and gives its FQIDs back at once. */
	released = cdx_dpa_ipsec_release_held_fqids();
	ft_epoch++;
	cdx_ipsec_sa_restarted();
	WRITE_ONCE(ft_failed, false);
	/* The tables are settled whatever a port does now, so the latch stays
	 * clear: a port that would not start is named above this and counted
	 * in resume_failures. A receive port starts again with its netdev; an
	 * offline port, which has none, only with CDX's reload or a reboot. */
	unstarted = dpa_cfg_resume();
	if (unstarted > 0) {
		ft_resume_failures += unstarted;
		pr_err("cdx flowtable: %d classifier ports did not start again after the datapath restart\n",
		       unstarted);
	} else if (unstarted) {
		/* Not after a stop that succeeded under this RTNL hold. */
		ft_resume_failures++;
		pr_err("cdx flowtable: the classifier ports did not start again after the datapath restart (%d)\n",
		       unstarted);
	}
	ft_restarts++;
	ft_window_restarts++;
	pr_warn("cdx flowtable: datapath restarted after unproven deletion (%u keys resolved, %u FQID ranges released, stopped %u ms)\n",
		ft_episode_resolved, released,
		ft_stopped_at ? jiffies_to_msecs(jiffies - ft_stopped_at) : 0);
	ft_restart_notify = true;
	ft_episode_start = 0;
	ft_stopped_at = 0;
	ft_episode_resolved = 0;
	ft_hw_tries = 0;
	ft_stall_reported = false;
	ft_restart_backoff = HZ;
out:
	rtnl_unlock();
	return rc;
}

static void ft_fatal_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_fatal_work, ft_fatal_work_fn);

/* cdx_ft_fatal() latches from paths the adapter's invalidation pass never
 * visits -- a multicast root belongs to its learner, and that pass only runs
 * while a flowtable is bound -- so nothing else is guaranteed to stop the
 * ports, let alone restart them. Both happen here, in a context that holds
 * neither lock: the restart stops the ports itself, and a latch that can no
 * longer restart is left to cdx_ft_recover(), which keeps them stopped. The
 * adapter hears of a restart only after the transaction has been released,
 * since what it asks for takes the transaction itself. */
static void ft_fatal_work_fn(struct work_struct *work)
{
	unsigned long delay = HZ;
	int rc = 0;

	cdx_ft_begin();
	if (ft_failed && !ft_terminal)
		rc = cdx_ft_restart(&delay);
	if (!rc)
		rc = cdx_ft_recover();
	cdx_ft_end();
	if (xchg(&ft_restart_notify, false))
		cdx_ft_egress_restarted();
	if (rc == -EAGAIN)
		schedule_delayed_work(&ft_fatal_work, delay);
}

/* Latch the failure from outside the unicast delete path, and from it too
 * (cdx_ft_del()). A classifier root that could not be provably unlinked may
 * still resolve in hardware -- forwarding a retired flow, replicating through a
 * revoked listener chain, or enqueueing to a deleted SA's queues. The latch
 * refuses new entries and groups and blocks port restart, and the work above
 * stops the ports and then restarts them once the root is settled, so a
 * possibly-still-linked root fail-stops the datapath rather than forwarding
 * on unnoticed. Every caller holds the transaction, which the restart that
 * clears the latch holds too; the store is WRITE_ONCE for the netdev notifier,
 * which reads it under RTNL alone. */
void cdx_ft_fatal(void)
{
	WRITE_ONCE(ft_failed, true);
	schedule_delayed_work(&ft_fatal_work, 0);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_fatal, ASK_CDX_FLOWTABLE);

/* Unload stops the ports itself; the work must not outlive the module or run
 * against a freed cdx_info. Disabled rather than cancelled: the deinit chain
 * after this still destroys multicast groups, and a failure there must latch
 * without queueing the work again, as must the work's own retry while this
 * waits for it. Called without the control lock, which the work takes. */
void cdx_ft_fatal_stop(void)
{
	disable_delayed_work_sync(&ft_fatal_work);
}

unsigned int cdx_ft_pending(void)
{
	cdx_ft_assert_held();
	return cdx_ft_hw_pending() + cdx_ehash_quarantine_pending();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_pending, ASK_CDX_FLOWTABLE);

/* An unlink is out of the hardware's reach only once a barrier has completed
 * behind it: until then a walk begun before it may still be inside what it
 * unlinked -- a flow's key, a multicast group's old listener chain, an SA's
 * entry -- and send by it. So nothing is proven while anything is retired or
 * parked without one; one barrier is issued here for all of it, as one proves
 * every unlink before it. A deletion that could not be proven unlinked at all
 * latched the failure, and its key may still be linked: no barrier proves that
 * gone. Once the ports that walk the tables are found stopped and idle with a
 * barrier behind them, though, nothing reaches it, and they stay stopped until
 * the restart has settled it. 0, or -EAGAIN. */
int cdx_ft_proven(void)
{
	cdx_ft_assert_held();
	if (ft_failed && !ft_stopped_at)
		return -EAGAIN;
	if (cdx_ft_pending())
		cdx_ft_hw_retry();
	return cdx_ft_pending() ? -EAGAIN : 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_proven, ASK_CDX_FLOWTABLE);

bool cdx_ft_idle(void)
{
	bool idle;

	cdx_ft_begin();
	/* SAs and multicast groups too: an adapter that has unregistered its
	 * egress hook retires them after it, on its way out. */
	idle = !ft_live && !cdx_ft_proven() && !cdx_ipsec_sa_count() &&
	       !cdx_mc_group_count();
	cdx_ft_end();
	return idle;
}

int cdx_ft_claim(void)
{
	cdx_ft_assert_held();
	if (ft_failed)
		return -EOPNOTSUPP;
	/* Parked ehash storage is released on any completed sync, as one
	 * barrier on the single FMan PCD proves every unlink before it
	 * (ft_hw_release_synced(), cdx_ehash.c). With two PCDs it would free
	 * entries the other's walkers may still hold, so refuse to own
	 * hardware there. LS1046A has one; sealing the config below keeps a
	 * second from arriving later. The count is the loader's, so this is
	 * a configuration to refuse, not a kernel bug to trace. */
	if (dpa_get_num_fmans() > 1) {
		pr_warn_once("cdx flowtable: the DPA configuration spans %u FMans; hardware offload supports one\n",
			     dpa_get_num_fmans());
		return -EOPNOTSUPP;
	}
	if (ft_claimed || ft_live)
		return -EBUSY;
	/* A deletion still waiting on its barrier -- this backend's, or one
	 * CDX parked for a path of its own -- is retried here rather than
	 * left to refuse the load until some unrelated delete syncs. */
	if (cdx_ft_pending())
		cdx_ft_hw_retry();
	if (cdx_ft_pending())
		return -EBUSY;
	ft_claimed = true;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_claim, ASK_CDX_FLOWTABLE);

int cdx_ft_release(void)
{
	cdx_ft_assert_held();
	if (ft_live)
		return -EBUSY;
	ft_claimed = false;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_release, ASK_CDX_FLOWTABLE);

int cdx_ft_admission_begin(void)
{
	cdx_ft_assert_held();
	/* RTNL holders can wait for callbacks needing this transaction. */
	return rtnl_trylock() ? 0 : -EAGAIN;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_admission_begin, ASK_CDX_FLOWTABLE);

void cdx_ft_admission_end(void)
{
	cdx_ft_assert_held();
	rtnl_unlock();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_admission_end, ASK_CDX_FLOWTABLE);

/* The devices cdx_ft_port_supported() can admit are exactly the physical
 * Ethernet onifs, and cdx_add_eth_onif() takes a phy_port slot for each one
 * it creates. One binding per device per table therefore cannot outrun that. */
static_assert(CDX_FT_MAX_TABLE_DEVICES == MAX_PHY_PORTS);

/* A port belonging to a switch ASIC would let the bridge mark a VLAN as
 * already stripped by hardware, which describes a tag the adapter's own
 * encoder is then expected to reproduce with nothing in the rule naming it.
 * A DPAA MAC is never such a port; prove that rather than assume it. */
static bool cdx_ft_switch_port(struct net_device *dev)
{
	struct netdev_phys_item_id ppid;

	return dev_get_port_parent_id(dev, &ppid, false) != -EOPNOTSUPP;
}

/* Everything both predicates below require, which is every check that is
 * about the device rather than about what it is made of: the right namespace,
 * an Ethernet header, registered, running with carrier, not a VRF slave, not a
 * switch ASIC port, and a valid onif whose type the caller then judges.
 *
 * Returns the onif type on success and zero on any refusal. Zero is not a
 * legal type -- every onif carries at least one IF_TYPE bit -- so it is
 * unambiguous as a failure value.
 */
static U8 cdx_ft_onif_type(struct net_device *dev)
{
	POnifDesc onif;
	struct dpa_iface_info *iface;

	cdx_ft_assert_held();
	/* A bridge port is admissible: the adapter's device walk recognizes the
	 * bridge hop above it and derives the tag stack the bridge produces, so
	 * an enslaved port is described rather than excluded. An L3 slave still
	 * is not -- a VRF moves the route lookup somewhere this contract does
	 * not follow. */
	if (!dev || !net_eq(dev_net(dev), &init_net) ||
	    dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN ||
	    dev->reg_state != NETREG_REGISTERED ||
	    netif_is_l3_slave(dev) || cdx_ft_switch_port(dev) ||
	    !netif_running(dev) || !netif_carrier_ok(dev))
		return 0;
	iface = dpa_get_ifinfo_by_netdev(dev);
	if (!iface || iface->itf_id >= L2_MAX_ONIF)
		return 0;
	onif = get_onif_by_index(iface->itf_id);
	if (!(onif->flags & ENTRY_VALID) || !onif->itf ||
	    onif->itf->index != iface->itf_id)
		return 0;
	return onif->itf->type;
}

bool cdx_ft_port_supported(struct net_device *dev)
{
	return cdx_ft_onif_type(dev) == (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_port_supported, ASK_CDX_FLOWTABLE);

/* What a finished frame may be handed to, which is a strictly wider set than
 * what may originate one.
 *
 * A VAP is an egress and only an egress. The encoder already resolves one --
 * dpa_get_out_tx_info_by_itf_id() has a WLAN arm that turns the onif into the
 * VAP's forwarding frame queue -- so an entry leaving through a VAP is an
 * ordinary entry with its enqueue target pointed elsewhere, and needs nothing
 * else from this side.
 *
 * The reverse is not true and is not granted here. A VAP's own ingress is
 * never programmed: the adapter binds a non-DPAA device passively (every
 * request declined), so a flow arriving from Wi-Fi is refused here and stays
 * on the software fast path while the DPAA ports in the same table keep
 * theirs. Keeping the two predicates separate is what states that in code
 * rather than in a comment.
 *
 * Open, not merely configured: the frame queues an entry would name are built
 * during the transition to open.
 */
bool cdx_ft_egress_supported(struct net_device *dev)
{
	U8 type = cdx_ft_onif_type(dev);

	if (type == (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL))
		return true;
	ask_dbg(ASK_DBG_DEVICE, "egress %s onif_type=0x%x vap_open=%d\n",
		dev ? netdev_name(dev) : "(null)", type,
		dev ? dpaa_vwd_vap_is_open(dev) : -1);
	return type == (IF_TYPE_WLAN | IF_TYPE_PHYSICAL) &&
	       dpaa_vwd_vap_is_open(dev);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_egress_supported, ASK_CDX_FLOWTABLE);

/* A deletion waiting on its barrier refuses every new entry in cdx_ft_add(),
 * and while no invalidation is in progress nothing else retries it: least of
 * all one CDX parked for a multicast or IPsec delete, which only another delete
 * of that kind would otherwise release. So admission retries it itself, at
 * most once a second: a sync under RTNL can busy-wait on the host-command
 * channel, and a wedged channel would otherwise be asked once per offered
 * flow. */
static unsigned long ft_retry_at;

static void cdx_ft_retry_pending(void)
{
	if (ft_retry_at && time_before(jiffies, ft_retry_at))
		return;
	ft_retry_at = jiffies + HZ;
	cdx_ft_hw_retry();
}

int cdx_ft_add(const struct cdx_ft_rule *rule,
	       const struct cdx_ft_stats_binding *stats,
	       struct cdx_ft_hw **result)
{
	int rc;

	cdx_ft_assert_held();
	ASSERT_RTNL();
	*result = NULL;
	if (!ft_failed && cdx_ft_pending())
		cdx_ft_retry_pending();
	/* The adapter validates tuple/NAT eligibility, including same-port
	 * hairpin routing. The provider rechecks physical device state. */
	if (!ft_claimed || ft_failed || ft_observe || cdx_ft_pending() ||
	    !cdx_ft_port_supported(rule->in) || !cdx_ft_egress_supported(rule->out) ||
	    !ether_addr_equal(rule->src_mac, rule->out->dev_addr)) {
		/* Eight clauses and one return: without the operands a refusal
		 * here says only that CDX declined, which is the least useful
		 * true thing it could say. */
		ask_dbg(ASK_DBG_DEVICE,
			"add claimed=%d failed=%d observe=%d pending=%u in=%s(%d) out=%s(%d) srcmac=%d\n",
			ft_claimed, ft_failed, ft_observe, cdx_ft_pending(),
			rule->in ? netdev_name(rule->in) : "(null)",
			cdx_ft_port_supported(rule->in),
			rule->out ? netdev_name(rule->out) : "(null)",
			cdx_ft_egress_supported(rule->out),
			rule->out ? ether_addr_equal(rule->src_mac, rule->out->dev_addr) : -1);
		return ask_refuse(-EOPNOTSUPP);
	}
	rc = cdx_ft_hw_add(rule, stats, result);
	if (!rc)
		ft_live++;
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_add, ASK_CDX_FLOWTABLE);

/* Ownership, not encoding: a statistics slot is claimed and returned by the
 * adapter's own policy, so these are transaction-scoped like every other
 * backend operation but need no hardware state of their own. */
int cdx_ft_stats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot)
{
	cdx_ft_assert_held();
	*slot = NULL;
	if (!ft_claimed || ft_failed)
		return -EOPNOTSUPP;
	return cdx_ft_ifstats_alloc(kind, slot);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_alloc, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_free(struct cdx_ft_stats_slot **slot)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_free(slot);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_free, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_retention(unsigned int *retained, u64 *deferred)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_retention(retained, deferred);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_retention, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_read(const struct cdx_ft_stats_slot *slot,
		       struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_read(slot, rx, tx);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_read, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_publish(struct cdx_ft_stats_slot *slot, int ifindex,
			  unsigned int rx_overhead, unsigned int tx_overhead)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_publish(slot, ifindex, rx_overhead, tx_overhead);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_publish, ASK_CDX_FLOWTABLE);

/* No transaction: the caller is a netdev notifier, and the slot's owner --
 * who alone can free it -- is serialized against that notifier by its own lock. */
void cdx_ft_stats_unpublish(struct cdx_ft_stats_slot *slot)
{
	cdx_ft_ifstats_unpublish(slot);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_unpublish, ASK_CDX_FLOWTABLE);

void cdx_ft_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats)
{
	cdx_ft_assert_held();
	cdx_ft_hw_stats(hw, stats);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats, ASK_CDX_FLOWTABLE);

int cdx_ft_del(struct cdx_ft_hw **hw)
{
	int rc;

	cdx_ft_assert_held();
	if (!*hw)
		return 0;
	rc = cdx_ft_hw_del(hw);
	ft_live--;
	/* The work the latch queues stops the ports and restarts them, whether
	 * or not the adapter's own recovery gets there first. */
	if (rc == -EIO)
		cdx_ft_fatal();
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_del, ASK_CDX_FLOWTABLE);

int cdx_ft_unlink(struct cdx_ft_hw **hw)
{
	int rc;

	cdx_ft_assert_held();
	if (!*hw)
		return 0;
	rc = cdx_ft_hw_unlink(hw);
	ft_live--;
	if (rc == -EIO)
		cdx_ft_fatal();
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_unlink, ASK_CDX_FLOWTABLE);

unsigned int cdx_ft_owed(void)
{
	cdx_ft_assert_held();
	return cdx_ft_hw_owed();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_owed, ASK_CDX_FLOWTABLE);

int cdx_ft_settle(unsigned int *unproven)
{
	cdx_ft_assert_held();
	return cdx_ft_hw_settle(unproven);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_settle, ASK_CDX_FLOWTABLE);

/* When a stop that found a port still busy may be tried again. Every caller of
 * cdx_ft_recover() polls it -- the latch's work, the adapter's invalidation
 * pass, its SA retirement -- and each try holds RTNL through the whole wait
 * for idle, so a port that stays busy is not asked again before then: soon
 * while a restart may still come, then ever more rarely once the latch is
 * terminal. Under the control mutex. */
static unsigned long ft_recover_next, ft_recover_backoff;

int cdx_ft_recover(void)
{
	bool stopped;
	int rc;

	cdx_ft_assert_held();
	/* Never wait for RTNL while a callback transaction is held. CDX owns
	 * this latch even after the adapter releases its claim. Stopping the
	 * ports is all this does about it: the restart is the latch's work's,
	 * which tells the adapter when it has happened. */
	if (ft_failed) {
		if (ft_recover_next && time_before(jiffies, ft_recover_next))
			return -EAGAIN;
		if (!rtnl_trylock())
			return -EAGAIN;
		rc = dpa_cfg_stop();
		rtnl_unlock();
		ft_recover_next = 0;
		/* Another port still walks the tables: no stop of CDX's own
		 * proves anything, now or later -- nor an earlier one -- so
		 * nothing it retired is freed. */
		if (rc == -EXDEV) {
			ft_stopped_at = 0;
			cdx_ft_set_terminal("a port CDX did not configure reaches the classifier");
			cdx_ft_hw_strand();
			return cdx_ft_hw_retry();
		}
		/* Stopped, but never to be restarted: what the latch always
		 * was. */
		if (rc == -ENOTRECOVERABLE) {
			cdx_ft_set_terminal("the classifier ports cannot be started again");
		} else if (rc) {
			if (!ft_terminal)
				ft_recover_backoff = FT_RESTART_HW_RETRY;
			else if (ft_recover_backoff < HZ)
				ft_recover_backoff = HZ;
			else
				ft_recover_backoff = min_t(unsigned long, 2 * ft_recover_backoff,
							   FT_RESTART_BACKOFF_MAX);
			ft_recover_next = (jiffies + ft_recover_backoff) ?: 1;
			pr_err_ratelimited("cdx flowtable: waiting for the ports to stop after unproven deletion\n");
			return -EAGAIN;
		}
		ft_recover_backoff = 0;
		stopped = !rc;
		rc = cdx_ft_stopped_barrier();
		if (rc == -ENOTRECOVERABLE) {
			cdx_ft_set_terminal("the host-command channel has failed");
			cdx_ft_hw_strand();
			return cdx_ft_hw_retry();
		}
		if (rc)
			return -EAGAIN;
		if (stopped)
			cdx_ft_ports_stopped();
		cdx_ft_hw_quiesced();
	}
	return cdx_ft_hw_retry();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_recover, ASK_CDX_FLOWTABLE);

/* CDX's final shutdown has already stopped and detached every classifier port.
 * It can reclaim backend storage after the adapter and its work are gone. */
void cdx_flowtable_quiesced(void)
{
	cdx_ft_hw_quiesced();
}

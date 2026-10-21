// SPDX-License-Identifier: GPL-2.0-or-later
/* CDX ownership and hardware services for the Linux flowtable adapter. */
#include <linux/delay.h>
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

/* Transit ESP, GRE, IPIP and 6in4 in hardware (A386). It costs every frame
 * the TCP and UDP tables miss two more lookups on its way to the Ethernet
 * table (cdxdrv_set_miss_action()), and a bridged station pair's minimum
 * frames 13-18% of their rate (A392); off, that chain is 1.0.7's, and such flows
 * stay in the software flowtable (cdx_ft_portless()). Off by default: OpenWrt
 * offers none of them to a flowtable unless told to. Read when the classifier
 * is built, so fixed while the module is loaded. */
bool cdx_ft_transit;
EXPORT_SYMBOL_NS_GPL(cdx_ft_transit, ASK_CDX_FLOWTABLE);
module_param_named(transit, cdx_ft_transit, bool, 0444);
MODULE_PARM_DESC(transit, "Offload transit ESP, GRE, IPIP and 6in4; costs bridged minimum frames up to 18% (default off)");

/* Detach/reclaim must not forget an unproven hardware deletion. */
static bool ft_claimed, ft_failed;
static unsigned int ft_live;

/* The restart that follows ft_failed (cdx_ft_restart()), in three phases that
 * each pick up where the last left off. The classifier ports are stopped and
 * sent past the classifier, so the datapath forwards in software
 * (ft_bypassed_at), each seen idle (ft_ports_proven, and ft_ports_held counts
 * those a bypass left stopped, tried again each time); the doubt is settled
 * once nothing walks the tables and a barrier has completed behind that
 * (ft_quiet_at); and the ports take the classifier back. Nothing about it is
 * ever left for a reboot: what it waits for is retried for as long as it
 * takes.
 *
 * ft_epoch counts restarts from one, for a hold that has to tell whether a
 * restart has happened since it was taken. The rest describe the current
 * episode: when it began and when its ports were first stopped, the keys
 * settled so far, when it is next tried (ft_restart_next, for every caller)
 * and the backoff after that, how often the hardware has not answered a stop,
 * and which of its waits have been reported. ft_resume_failures counts the
 * ports a restart could not start again. All under the control mutex. */
static bool ft_restart_notify, ft_ports_proven;
static unsigned int ft_ports_held;
static unsigned int ft_restarts, ft_window_restarts, ft_episode_resolved, ft_hw_tries;
static unsigned int ft_resume_failures;
static u32 ft_epoch = 1;
static unsigned long ft_episode_start, ft_stopped_at, ft_bypassed_at, ft_quiet_at;
static unsigned long ft_window_start, ft_restart_next, ft_waits_reported;
static unsigned long ft_restart_backoff = HZ;

/* What a restart waits for, published while it waits -- empty while the
 * classifier runs -- for an operator, and for the platform's report of a
 * failure that does reset the board. Written under the parameter lock its
 * reader takes, so a read never sees two reasons at once; that lock is taken
 * under the control mutex, so no parameter of CDX's may take the control mutex
 * in its set or get. */
static char ft_degraded_reason[96];
module_param_string(flowtable_degraded_reason, ft_degraded_reason, sizeof(ft_degraded_reason), 0444);
MODULE_PARM_DESC(flowtable_degraded_reason, "What keeps the datapath forwarding in software after an unproven deletion; empty while the classifier runs");

static void ft_fatal_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_fatal_work, ft_fatal_work_fn);

/* A limit raised while a restart waits for one, read by the next attempt. */
static bool ft_restart_asked;

/* Restarts allowed in each FT_RESTART_WINDOW, counted from the first. A
 * datapath that keeps failing deletes has something wrong with it that a
 * restart will not mend, so once the budget is spent the classifier stays
 * bypassed -- the datapath forwarding in software, its tables settled -- until
 * the window allows another; at zero, until the limit is raised. A write is
 * seen at once: a restart waiting on the limit is asked again. */
#define FT_RESTART_WINDOW	(10 * 60 * HZ)
static unsigned int ft_restart_limit = 3;

static int ft_restart_limit_set(const char *val, const struct kernel_param *kp)
{
	int rc = param_set_uint(val, kp);

	if (!rc && READ_ONCE(ft_failed)) {
		WRITE_ONCE(ft_restart_asked, true);
		mod_delayed_work(system_wq, &ft_fatal_work, 0);
	}
	return rc;
}

static const struct kernel_param_ops ft_restart_limit_ops = {
	.set = ft_restart_limit_set,
	.get = param_get_uint,
};
module_param_cb(flowtable_restart_limit, &ft_restart_limit_ops, &ft_restart_limit, 0644);
MODULE_PARM_DESC(flowtable_restart_limit, "Datapath restarts allowed per 10 minutes after unproven deletions; past it, and at 0, the datapath forwards in software until it may restart");

/* Retry delays: RTNL contended, the test hold below, and the bounds of the
 * exponential backoff for everything else a restart waits on -- a port not yet
 * seen idle once the ports are bypassed, a barrier the channel refuses, a key
 * the table refuses, a port CDX did not configure. The backoff's bound is also
 * the longest the work ever sleeps while an episode lasts, so whatever ends
 * one -- a window passing, a raised limit -- is seen within it. A wait that
 * lasts past FT_RESTART_STALL into an episode is reported once for each
 * reason. */
#define FT_RESTART_RTNL_RETRY	(HZ / 10)
#define FT_RESTART_HOLD_RETRY	(HZ / 4)
#define FT_RESTART_BACKOFF_MAX	(30 * HZ)
#define FT_RESTART_STALL	(30 * HZ)

/* The hardware's own answers -- a stopped port gone idle -- come within
 * moments when the FMan is well: a port drains in microseconds. So before the
 * classifier is bypassed, while the ports are stopped and nothing they carry
 * moves, a port not yet idle is asked again soon, at a steady interval, until
 * the hardware has failed to answer FT_RESTART_HW_TRIES times -- a few
 * seconds, a port's own wait for idle included. Then the ports are bypassed
 * anyway, the datapath forwards in software, and what such a port may still
 * have in the tables keeps everything it could reach allocated until a later
 * look finds it idle. RTNL contention and the test hold are not the
 * hardware's and never count. */
#define FT_RESTART_HW_RETRY	(HZ / 4)
#define FT_RESTART_HW_TRIES	12

/* What a restart waits for, each reported at most once an episode. */
enum ft_restart_wait {
	FT_WAIT_RTNL,
	FT_WAIT_IDLE,
	FT_WAIT_FOREIGN,
	FT_WAIT_BARRIER,
	FT_WAIT_HOLD,
	FT_WAIT_LINKED,
	FT_WAIT_UNSETTLED,
	FT_WAIT_PENDING,
	FT_WAIT_DISABLED,
	FT_WAIT_BUDGET,
	FT_WAIT_ATTACH,
	FT_WAIT_DETACHED,
};

static const char *const ft_restart_why[] = {
	[FT_WAIT_RTNL] = "RTNL is contended",
	[FT_WAIT_IDLE] = "a port would not stop and go idle",
	[FT_WAIT_FOREIGN] = "a port CDX did not configure reaches the classifier",
	[FT_WAIT_BARRIER] = "the PCD barrier kept failing",
	[FT_WAIT_HOLD] = "held by flowtable_restart_hold",
	[FT_WAIT_LINKED] = "a possibly linked key is still linked",
	[FT_WAIT_UNSETTLED] = "a possibly linked key could not be settled",
	[FT_WAIT_PENDING] = "deletions still wait on a barrier",
	[FT_WAIT_DISABLED] = "datapath restarts are disabled",
	[FT_WAIT_BUDGET] = "restart budget exhausted",
	[FT_WAIT_ATTACH] = "a port would not take the classifier back",
	[FT_WAIT_DETACHED] = "the classifier ports cannot be started again",
};

#ifdef CDX_DEBUG_FLOWTABLE
/* Test-only: keep the classifier bypassed after a latch, with every key
 * recorded, until cleared -- the window a test inspects the episode in. */
static bool ft_restart_hold;
module_param_named(flowtable_restart_hold, ft_restart_hold, bool, 0600);
MODULE_PARM_DESC(flowtable_restart_hold, "Hold the classifier bypassed after an unproven deletion until cleared (test image)");
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
 * belongs to the provider even after adapter detach, so guard that open here
 * while the restart has the ports stopped -- before it has sent them past the
 * classifier, or while it gives the classifier back, which clears the latch
 * under the same RTNL hold this runs under, so a port opened after it starts
 * on a running datapath. Once the ports are bypassed, one opened walks no
 * table: it forwards in software like the rest, and opens as usual -- unless
 * its own bypass failed, which leaves it stopped and fenced: refused here as
 * well, rather than by the fence, which says nothing. */
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
	    !dpa_netdev_is_physical(dev) ||
	    (dpa_cfg_bypassed() && !dpa_cfg_port_held(dev)))
		return NOTIFY_DONE;
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

/* Callers of cdx_ft_begin() waiting to take the transaction, for
 * cdx_ft_let_waiters(). */
static atomic_t cdx_ft_waiting = ATOMIC_INIT(0);

/* When the transaction's current holder took it, in jiffies and never 0; 0
 * while it is free. Written by the holder, read by anyone. */
static unsigned long ft_held_since;

static void cdx_ft_taken(void)
{
	WRITE_ONCE(ft_held_since, jiffies ?: 1);
}

/* How long the transaction's current holder has held it, in milliseconds; 0
 * while it is free. Read without the transaction. The health probe's read of
 * /proc/cdx_flowtable waits for it behind every caller queued for it, which
 * under a route-flap storm with traffic in software took seconds while every
 * holder let it go in turn (A411): what nothing behind it gets past is a
 * holder that keeps it, which this shows. */
static int ft_hold_ms_get(char *buffer, const struct kernel_param *kp)
{
	unsigned long since = READ_ONCE(ft_held_since);

	return sysfs_emit(buffer, "%u\n", since ? jiffies_to_msecs(jiffies - since) : 0);
}

static int ft_hold_ms_set(const char *val, const struct kernel_param *kp)
{
	return -EPERM;
}

static const struct kernel_param_ops ft_hold_ms_ops = {
	.set = ft_hold_ms_set,
	.get = ft_hold_ms_get,
};
module_param_cb(flowtable_hold_ms, &ft_hold_ms_ops, NULL, 0444);
MODULE_PARM_DESC(flowtable_hold_ms, "How long the CDX transaction's current holder has held it (ms); 0 while it is free");

void cdx_ft_begin(void)
{
	atomic_inc(&cdx_ft_waiting);
	mutex_lock(&cdx_info->ctrl.mutex);
	atomic_dec(&cdx_ft_waiting);
	cdx_ft_taken();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_begin, ASK_CDX_FLOWTABLE);

/* The longest a job between two of its batches waits for others' turns. */
#define CDX_FT_LET_WAITERS_MS 100

/* For a job that goes in batches and has let the transaction go after one:
 * wait until nobody is waiting to take it, or CDX_FT_LET_WAITERS_MS, before
 * taking it again. A mutex released with waiters wakes one of them,
 * and the releasing job, still running, takes it back ahead of the rest; a
 * waiter passed over once has the next release handed to it, so each batch let
 * one waiter through and the last of several waited for as many batches
 * (A312). Bounded, so that a steady stream of others cannot keep the job from
 * finishing. Without the transaction held. */
void cdx_ft_let_waiters(void)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(CDX_FT_LET_WAITERS_MS);

	might_sleep();
	lockdep_assert_not_held(&cdx_info->ctrl.mutex);
	while (atomic_read(&cdx_ft_waiting) && time_before(jiffies, deadline))
		usleep_range(500, 1000);
	cond_resched();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_let_waiters, ASK_CDX_FLOWTABLE);

bool cdx_ft_trybegin(void)
{
	if (!mutex_trylock(&cdx_info->ctrl.mutex))
		return false;
	cdx_ft_taken();
	return true;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_trybegin, ASK_CDX_FLOWTABLE);

void cdx_ft_end(void)
{
	WRITE_ONCE(ft_held_since, 0);
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

bool cdx_ft_bypassed(void)
{
	cdx_ft_assert_held();
	return dpa_cfg_bypassed();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_bypassed, ASK_CDX_FLOWTABLE);

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

/* The ports were found stopped after a latch, or given up on after their
 * tries. Recorded once per episode, for the restart's report of how long the
 * datapath forwarded nothing. */
static void cdx_ft_ports_stopped(void)
{
	if (ft_stopped_at)
		return;
	ft_stopped_at = jiffies ?: 1;
	pr_warn("cdx flowtable: ports stopped after unproven deletion\n");
}

/* The restart has to wait, for `why`: tried again `after` jiffies on. What it
 * waits for is published while it does, and said in the log once an episode
 * for each reason, once the episode has lasted long enough to matter. */
static int cdx_ft_restart_wait(enum ft_restart_wait why, unsigned long after,
			       unsigned long *delay)
{
	const char *text = ft_restart_why[why];

	if (strcmp(ft_degraded_reason, text)) {
		kernel_param_lock(THIS_MODULE);
		strscpy(ft_degraded_reason, text, sizeof(ft_degraded_reason));
		kernel_param_unlock(THIS_MODULE);
	}
	if (!(ft_waits_reported & BIT(why)) &&
	    time_after(jiffies, ft_episode_start + FT_RESTART_STALL)) {
		ft_waits_reported |= BIT(why);
		pr_warn("cdx flowtable: datapath restart stalled for %u s: %s; %s, still retrying\n",
			jiffies_to_msecs(jiffies - ft_episode_start) / 1000, text,
			ft_bypassed_at ? "forwarding in software meanwhile" :
					 "the ports stay stopped");
	}
	*delay = after;
	return -EAGAIN;
}

/* The same after the backoff, which doubles each time up to its bound. */
static int cdx_ft_restart_later(enum ft_restart_wait why, unsigned long *delay)
{
	unsigned long after = ft_restart_backoff;

	ft_restart_backoff = min_t(unsigned long, 2 * ft_restart_backoff,
				   FT_RESTART_BACKOFF_MAX);
	return cdx_ft_restart_wait(why, after, delay);
}

/* One barrier through the PCD once nothing walks the tables any more. A frame
 * a port had in hand when it stopped may still be inside the FMan's
 * controller; the barrier a delete relies on to prove no lookup begun before
 * it still walks the tables proves the same of that frame. Nothing a stop lets
 * go of is freed before it. 0, also with no table to issue it through; -EAGAIN
 * for one that failed, which a later one completes: a host command that timed
 * out shuts the channel only until the FMan answers it. */
static int cdx_ft_stopped_barrier(void)
{
	void *td = dpa_get_ehash_td();

	if (!td || !ExternalHashTableFmPcdHcSync(td))
		return 0;
	return -EAGAIN;
}

/* The first phase: every classifier port stopped and then sent past the
 * classifier (dpa_cfg_bypass()), so that it forwards in software within
 * moments of the stop, and each seen idle since it stopped. RTNL is taken by
 * trying, for the transition alone, and never held across a wait between
 * tries.
 *
 * A port that will not go idle keeps them all stopped for its tries, a few
 * seconds, and then is bypassed with the rest anyway; until a later look finds
 * it idle it may still be walking the tables, so nothing is settled meanwhile.
 * A port CDX did not configure reaching a classifier is the next phase's to
 * wait for: CDX's own ports are stopped and idle, and go past the classifier
 * all the same. Ports detached for an unload reach no classifier at all. */
static int cdx_ft_restart_bypass(unsigned long *delay)
{
	unsigned int held;
	int rc;

	if (ft_ports_proven && !ft_ports_held)
		return 0;
	if (!rtnl_trylock()) {
		/* Only a port a bypass left stopped is still to be tried:
		 * settle meanwhile, and try it again next time. */
		if (ft_ports_proven)
			return 0;
		/* Soon and at a steady interval: RTNL is held for moments. */
		return cdx_ft_restart_wait(FT_WAIT_RTNL, FT_RESTART_RTNL_RETRY, delay);
	}
	if (!ft_bypassed_at) {
		rc = dpa_cfg_stop();
		if (rc == -ENOTRECOVERABLE) {
			rtnl_unlock();
			cdx_ft_ports_stopped();
			ft_ports_proven = true;
			return 0;
		}
		if (rc && rc != -EXDEV && ++ft_hw_tries < FT_RESTART_HW_TRIES) {
			rtnl_unlock();
			return cdx_ft_restart_wait(FT_WAIT_IDLE, FT_RESTART_HW_RETRY, delay);
		}
		cdx_ft_ports_stopped();
	}
	rc = dpa_cfg_bypass(&held);
	rtnl_unlock();
	/* Detached meanwhile, or by a stop that gave up on a port: only the
	 * stop above proves detached ports idle, so it is asked again. */
	if (rc == -ENOTRECOVERABLE)
		return cdx_ft_restart_later(FT_WAIT_DETACHED, delay);
	if (rc < 0)
		return cdx_ft_restart_later(FT_WAIT_IDLE, delay);
	if (!ft_bypassed_at) {
		ft_bypassed_at = jiffies ?: 1;
		pr_warn("cdx flowtable: classifier bypassed after unproven deletion; the datapath forwards in software until it is settled\n");
	}
	ft_ports_held = held;
	if (rc)
		return cdx_ft_restart_later(FT_WAIT_IDLE, delay);
	/* What the settle waits for backs off from the start again. */
	if (!ft_ports_proven)
		ft_restart_backoff = HZ;
	ft_ports_proven = true;
	return 0;
}

/* The second: with nothing walking the tables, the doubt settled. A barrier
 * completes behind the last frame the ports let go of; then each recorded key
 * is looked for and deleted again, or found in no bucket at all
 * (cdx_ehash_resolve_abandoned()), a second barrier follows, and everything
 * parked for one goes too. What the tables still link is then exactly what the
 * live owners believe they link. No RTNL: nothing here changes a port.
 *
 * Run again on every attempt until the restart completes, since what it frees
 * may have grown meanwhile -- a retirement finishing, a group deleted --, and
 * each run is two barriers when there is nothing to settle. Whatever fails --
 * a barrier the channel refuses, a key the table refuses, a malformed table
 * (which only a rebuild of the table would mend; until one exists the key's
 * memory stays as it is) -- is tried again, backing off, for as long as it
 * takes. */
static int cdx_ft_restart_settle(unsigned long *delay)
{
	unsigned int resolved;
	int rc;

	/* That port walks the tables whatever CDX's own do, so no earlier
	 * barrier proves anything any more, and what may still be linked is
	 * kept, out of what anything waits on; it may yet go. */
	if (!dpa_cfg_covered()) {
		ft_quiet_at = 0;
		cdx_ft_hw_strand();
		return cdx_ft_restart_later(FT_WAIT_FOREIGN, delay);
	}
	if (!ft_quiet_at) {
		if (cdx_ft_stopped_barrier())
			return cdx_ft_restart_later(FT_WAIT_BARRIER, delay);
		ft_quiet_at = jiffies ?: 1;
	}
	cdx_ft_hw_quiesced();
	if (ft_restart_held())
		return cdx_ft_restart_wait(FT_WAIT_HOLD, FT_RESTART_HOLD_RETRY, delay);
	rc = cdx_ehash_resolve_abandoned(&resolved);
	ft_episode_resolved += resolved;
	if (rc == -ENOTRECOVERABLE)
		return cdx_ft_restart_wait(FT_WAIT_UNSETTLED, FT_RESTART_BACKOFF_MAX, delay);
	if (rc)
		return cdx_ft_restart_later(FT_WAIT_LINKED, delay);
	if (cdx_ft_stopped_barrier())
		return cdx_ft_restart_later(FT_WAIT_BARRIER, delay);
	cdx_ehash_quarantine_free_all();
	if (cdx_ft_pending())
		return cdx_ft_restart_later(FT_WAIT_PENDING, delay);
	return 0;
}

/* Whether the classifier may be given back now: never with the limit at zero,
 * and no more than the limit within a window, counted from the first. Until it
 * may, the ports stay in software and this is asked again within the backoff's
 * bound, so a window that passes or a raised limit is seen. */
static int cdx_ft_restart_budget(unsigned long *delay)
{
	unsigned int limit = READ_ONCE(ft_restart_limit);
	unsigned long left;

	if (!limit)
		return cdx_ft_restart_wait(FT_WAIT_DISABLED, FT_RESTART_BACKOFF_MAX, delay);
	if (!ft_window_start || time_after(jiffies, ft_window_start + FT_RESTART_WINDOW)) {
		ft_window_start = jiffies ?: 1;
		ft_window_restarts = 0;
	}
	if (ft_window_restarts < limit)
		return 0;
	left = ft_window_start + FT_RESTART_WINDOW + 1 - jiffies;
	return cdx_ft_restart_wait(FT_WAIT_BUDGET,
				   min_t(unsigned long, left, FT_RESTART_BACKOFF_MAX), delay);
}

/* The third: the classifier given back. Under one RTNL hold, so no port opens
 * in between: the ports stop and take their PCD back (dpa_cfg_unbypass()),
 * what an SA's possibly linked key held goes back, an SA a failed delete
 * stranded gets its entry again, the latch clears, and the ports start as a
 * stop found them. A port that would not go idle for that, or would not take
 * its PCD back, leaves them all in software, asked again later. */
static int cdx_ft_restart_restore(unsigned long *delay)
{
	unsigned int released;
	int rc, unstarted;

	rc = cdx_ft_restart_budget(delay);
	if (rc)
		return rc;
	if (!rtnl_trylock())
		return cdx_ft_restart_wait(FT_WAIT_RTNL, FT_RESTART_RTNL_RETRY, delay);
	rc = dpa_cfg_unbypass();
	if (rc) {
		unsigned int held;

		/* A port the unbypass's rollback could not send past the
		 * classifier again is left stopped, and joins those the first
		 * phase tries again on every attempt. */
		if (dpa_cfg_bypass(&held) >= 0)
			ft_ports_held = held;
		rtnl_unlock();
		return cdx_ft_restart_later(rc == -EBUSY ? FT_WAIT_IDLE :
					    rc == -EIO ? FT_WAIT_ATTACH : FT_WAIT_DETACHED,
					    delay);
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
	rtnl_unlock();
	if (unstarted > 0) {
		ft_resume_failures += unstarted;
		pr_err("cdx flowtable: %d classifier ports did not start again after the datapath restart\n",
		       unstarted);
	} else if (unstarted) {
		/* Not after an unbypass that succeeded under this RTNL hold. */
		ft_resume_failures++;
		pr_err("cdx flowtable: the classifier ports did not start again after the datapath restart (%d)\n",
		       unstarted);
	}
	ft_restarts++;
	ft_window_restarts++;
	pr_warn("cdx flowtable: datapath restarted after unproven deletion (%u keys resolved, %u FQID ranges released, stopped %u ms, bypassed %u ms)\n",
		ft_episode_resolved, released,
		ft_stopped_at ? jiffies_to_msecs((ft_bypassed_at ?: jiffies) - ft_stopped_at) : 0,
		ft_bypassed_at ? jiffies_to_msecs(jiffies - ft_bypassed_at) : 0);
	ft_restart_notify = true;
	ft_episode_start = ft_stopped_at = ft_bypassed_at = ft_quiet_at = 0;
	ft_episode_resolved = ft_hw_tries = ft_ports_held = 0;
	ft_ports_proven = false;
	ft_waits_reported = 0;
	ft_restart_backoff = HZ;
	kernel_param_lock(THIS_MODULE);
	ft_degraded_reason[0] = '\0';
	kernel_param_unlock(THIS_MODULE);
	return 0;
}

/* Restart the datapath after a latch.
 *
 * The latch exists because a classifier key may still be linked: a delete
 * could not prove it unlinked, and the FMan might walk to it. Once no port
 * walks the tables, nothing does, and the doubt can be settled. Stopped ports
 * would make that so but forward nothing, not even in software; so the ports
 * are stopped only for as long as it takes to see them idle and switch them
 * past the classifier, which they keep, and run again meanwhile, every frame
 * going to Linux. Then the tables are settled, and the ports take the
 * classifier back.
 *
 * Every phase that has to wait is tried again, at the interval what it waits
 * for deserves, for as long as it takes; none of it is for a reboot, and from
 * the bypass on the datapath forwards throughout. Each attempt runs every phase
 * not yet done, at most once until the attempt due: the latch's work and the
 * adapter's own recovery drive the same restart. Caller holds the
 * transaction; RTNL is taken by trying, by each phase that changes a port,
 * for that change alone.
 *
 * 0: restarted, the adapter to be told; -EAGAIN with *delay set: try again
 * then. */
static int cdx_ft_restart(unsigned long *delay)
{
	int rc;

	cdx_ft_assert_held();
	if (xchg(&ft_restart_asked, false))
		ft_restart_next = 0;
	if (ft_restart_next && time_before(jiffies, ft_restart_next)) {
		*delay = ft_restart_next - jiffies;
		return -EAGAIN;
	}
	if (!ft_episode_start)
		ft_episode_start = jiffies ?: 1;
	rc = cdx_ft_restart_bypass(delay);
	if (!rc)
		rc = cdx_ft_restart_settle(delay);
	if (!rc)
		rc = cdx_ft_restart_restore(delay);
	ft_restart_next = rc ? ((jiffies + *delay) ?: 1) : 0;
	return rc;
}

/* cdx_ft_fatal() latches from paths the adapter's invalidation pass never
 * visits -- a multicast root belongs to its learner, and that pass only runs
 * while a flowtable is bound -- so nothing else is guaranteed to restart the
 * datapath. It happens here, in a context that holds neither lock, at
 * whatever pace the restart asks for and for as long as the latch lasts: no
 * longer than the backoff's bound between tries. The adapter hears of a
 * restart only after the transaction has been released, since what it asks
 * for takes the transaction itself. */
static void ft_fatal_work_fn(struct work_struct *work)
{
	unsigned long delay = HZ;
	int rc = 0;

	cdx_ft_begin();
	if (ft_failed)
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
 * refuses new entries and groups and blocks a port's open while the ports are
 * stopped, and the work above takes the classifier out of the datapath and
 * gives it back once the root is settled, so a possibly-still-linked root is
 * never forwarded through unnoticed and the datapath forwards in software
 * meanwhile. Every caller holds the transaction, which the restart that clears
 * the latch holds too; the store is WRITE_ONCE for the netdev notifier, which
 * reads it under RTNL alone. */
void cdx_ft_fatal(void)
{
	WRITE_ONCE(ft_failed, true);
	/* At once, even with the work queued later: a new latch stops and
	 * bypasses the ports without waiting, and one during an episode costs
	 * the attempt not yet due no more than a look at when it is. */
	mod_delayed_work(system_wq, &ft_fatal_work, 0);
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
 * gone. Once no port walks the tables -- each stopped or bypassed and seen
 * idle, with a barrier behind that -- nothing reaches it, and none does until
 * the restart has settled it. 0, or -EAGAIN. */
int cdx_ft_proven(void)
{
	cdx_ft_assert_held();
	if (ft_failed && !ft_quiet_at)
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
	/* A tag count past the rule's own arrays would be read past them. */
	if (rule->in_vlans > CDX_FT_VLAN_MAX || rule->out_vlans > CDX_FT_VLAN_MAX)
		return ask_refuse(-EOPNOTSUPP);
	if (!ft_claimed || ft_failed || ft_observe || cdx_ft_pending() ||
	    !cdx_ft_port_supported(rule->in) || !cdx_ft_egress_supported(rule->out) ||
	    !is_valid_ether_addr(rule->src_mac)) {
		/* Eight clauses and one return: without the operands a refusal
		 * here says only that CDX declined, which is the least useful
		 * true thing it could say. */
		ask_dbg(ASK_DBG_DEVICE,
			"add claimed=%d failed=%d observe=%d pending=%u in=%s(%d) out=%s(%d) srcmac=%pM\n",
			ft_claimed, ft_failed, ft_observe, cdx_ft_pending(),
			rule->in ? netdev_name(rule->in) : "(null)",
			cdx_ft_port_supported(rule->in),
			rule->out ? netdev_name(rule->out) : "(null)",
			cdx_ft_egress_supported(rule->out), rule->src_mac);
		return ask_refuse(-EOPNOTSUPP);
	}
	rc = cdx_ft_hw_add(rule, stats, result);
	if (!rc)
		ft_live++;
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_add, ASK_CDX_FLOWTABLE);

int cdx_ft_l2_add(const struct cdx_ft_l2_rule *rule, struct cdx_ft_hw **result)
{
	int rc;

	cdx_ft_assert_held();
	ASSERT_RTNL();
	*result = NULL;
	if (!ft_failed && cdx_ft_pending())
		cdx_ft_retry_pending();
	/* The gates a flow direction passes, both ends being ports: a bridged
	 * pair is never a VAP's to send. */
	if (rule->in_vlans > CDX_FT_VLAN_MAX || rule->out_vlans > CDX_FT_VLAN_MAX)
		return ask_refuse(-EOPNOTSUPP);
	if (!ft_claimed || ft_failed || ft_observe || cdx_ft_pending() ||
	    !cdx_ft_port_supported(rule->in) || !cdx_ft_port_supported(rule->out) ||
	    rule->in == rule->out || !is_valid_ether_addr(rule->src_mac) ||
	    !is_valid_ether_addr(rule->dst_mac)) {
		ask_dbg(ASK_DBG_DEVICE,
			"l2 add claimed=%d failed=%d observe=%d pending=%u in=%s(%d) out=%s(%d) %pM->%pM\n",
			ft_claimed, ft_failed, ft_observe, cdx_ft_pending(),
			rule->in ? netdev_name(rule->in) : "(null)", cdx_ft_port_supported(rule->in),
			rule->out ? netdev_name(rule->out) : "(null)", cdx_ft_port_supported(rule->out),
			rule->src_mac, rule->dst_mac);
		return ask_refuse(-EOPNOTSUPP);
	}
	rc = cdx_ft_hw_l2_add(rule, result);
	if (!rc)
		ft_live++;
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_l2_add, ASK_CDX_FLOWTABLE);

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

int cdx_ft_unlink(struct cdx_ft_hw **hw, struct cdx_ft_counters *final)
{
	int rc;

	cdx_ft_assert_held();
	if (!*hw) {
		if (final)
			memset(final, 0, sizeof(*final));
		return 0;
	}
	rc = cdx_ft_hw_unlink(hw, final);
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

int cdx_ft_recover(void)
{
	unsigned long delay;

	cdx_ft_assert_held();
	/* Never wait for RTNL while a callback transaction is held. CDX owns
	 * this latch even after the adapter releases its claim. After one this
	 * drives the latch's own restart, at the pace its next attempt is due,
	 * so every caller polling here -- the latch's work, the adapter's
	 * invalidation pass, its Wi-Fi and SA retirements -- moves it on; what
	 * was retired may go once no port walks the tables, before the
	 * classifier comes back. While a port CDX did not configure walks
	 * them, which may last, what may still be linked is kept, out of what
	 * a caller waits on (cdx_ft_hw_strand()), and the rest goes behind a
	 * barrier as it would without a latch. A restart completed here is
	 * told to the adapter by the work, which runs outside this
	 * transaction. */
	if (ft_failed) {
		if (!cdx_ft_restart(&delay)) {
			mod_delayed_work(system_wq, &ft_fatal_work, 0);
		} else if (!ft_quiet_at) {
			if (!ft_ports_proven || dpa_cfg_covered())
				return -EAGAIN;
			cdx_ft_hw_strand();
		}
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

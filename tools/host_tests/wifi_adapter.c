/* The Wi-Fi VAP side of the adapter's decision logic, compiled from the
 * adapter against stubs for cfg80211, the transaction and the VAP backend.
 *
 * The rig proves the half that a running AP can show: an interface appears,
 * a VAP is registered, and a per-VAP file turns up under /sys/class/vwd/.
 * It cannot cheaply show the other half. The driver on that board refuses
 * `ip link del` for its own interfaces and hostapd holds the module open, so
 * on hardware an AP-mode interface essentially never goes away -- which is
 * exactly the path where a mistake is expensive, because it is where a netdev
 * pointer stops being safe to follow.
 *
 * So the branches asserted here are the ones a hardware run skips: that a
 * device which unregisters is retired using only what was copied at
 * registration, that the watch for it is freed rather than leaked, that a
 * device which comes back up as something other than an AP does not keep the
 * VAP it held, that an address change registers again rather than editing in
 * place, and that a registration which loses its watch mid-transaction is
 * deleted instead of stranded.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ENODEV 19
#define ENOMEM 12
#define EOPNOTSUPP 95
#define EIO 5

/* --- list.h, enough of it -------------------------------------------- */
struct list_head { struct list_head *next, *prev; };

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static void INIT_LIST_HEAD(struct list_head *l) { l->next = l->prev = l; }

static void list_add(struct list_head *n, struct list_head *head)
{
	n->next = head->next;
	n->prev = head;
	head->next->prev = n;
	head->next = n;
}

static void list_del(struct list_head *e)
{
	e->next->prev = e->prev;
	e->prev->next = e->next;
	e->next = e->prev = NULL;
}

static void list_move_tail(struct list_head *e, struct list_head *head)
{
	list_del(e);
	e->prev = head->prev;
	e->next = head;
	head->prev->next = e;
	head->prev = e;
}

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
	     n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

/* --- kernel bits ----------------------------------------------------- */
#define ASSERT_RTNL() assert(rtnl_held)
static int rtnl_held;

struct mutex { int held; };
/* No `static` here: the kernel's macro does not carry one either, so the
 * adapter writes `static DEFINE_MUTEX(...)` and adding a second one would not
 * compile. */
#define DEFINE_MUTEX(n) struct mutex n
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held = 1; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held = 0; }

static void rtnl_lock(void) { rtnl_held++; }
static void rtnl_unlock(void) { rtnl_held--; }

typedef struct { long long v; } atomic64_t;
#define ATOMIC64_INIT(x) { (x) }
static void atomic64_inc(atomic64_t *a) { a->v++; }
static long long atomic64_read(const atomic64_t *a) { return a->v; }

struct work_struct { int dummy; };
#define DECLARE_WORK(n, fn) static struct work_struct n
static int work_pending;
static void schedule_work(struct work_struct *w) { (void)w; work_pending++; }
static void cancel_work_sync(struct work_struct *w) { (void)w; work_pending = 0; }

#define GFP_KERNEL 0
static int alloc_fail;
static void *kzalloc(size_t n, int flags)
{
	(void)flags;
	if (alloc_fail) { alloc_fail--; return NULL; }
	return calloc(1, n);
}
static void kfree(void *p) { free(p); }

#define pr_warn_ratelimited(...) do { } while (0)

/* --- devices and cfg80211 -------------------------------------------- */
enum { NL80211_IFTYPE_STATION = 2, NL80211_IFTYPE_AP = 3,
       NL80211_IFTYPE_AP_VLAN = 4, NL80211_IFTYPE_MONITOR = 6 };
enum { NETREG_REGISTERED = 0, NETREG_UNREGISTERING = 1 };

struct wireless_dev { unsigned int iftype; };

struct net_device {
	char name[16];
	struct wireless_dev *ieee80211_ptr;
	int reg_state;
	int refcount;
	bool running;
	bool freed;
};

static bool netif_running(const struct net_device *d) { return d->running; }

static void dev_hold(struct net_device *d) { assert(!d->freed); d->refcount++; }
static void dev_put(struct net_device *d) { assert(!d->freed); d->refcount--; }
/* Reached only from the warning the adapter logs on a failed registration,
 * which is a no-op here -- but it still has to compile against the real call. */
static __attribute__((unused)) const char *netdev_name(const struct net_device *d)
{
	return d->name;
}

/* --- the transaction -------------------------------------------------- */
static int txn_depth, admission_depth, admission_fail;
static void cdx_ft_begin(void) { assert(!txn_depth); txn_depth = 1; }
static void cdx_ft_end(void) { assert(txn_depth); assert(!admission_depth); txn_depth = 0; }
static int cdx_ft_admission_begin(void)
{
	assert(txn_depth);
	if (admission_fail) { admission_fail--; return -11; }
	admission_depth = 1;
	rtnl_held++;
	return 0;
}
static void cdx_ft_admission_end(void)
{
	assert(admission_depth);
	admission_depth = 0;
	rtnl_held--;
}

/* --- the VAP backend -------------------------------------------------- */
/* The real one registers three tables; what matters to the adapter is that a
 * VAP is an opaque owner it must eventually hand back exactly once. */
struct cdx_wifi_vap {
	const struct net_device *dev;
	u16 vapid;
	bool live;
};

static int vap_add_fail;
static int vaps_live;
/* ft_wifi_vap_drained()'s record, below. */
static const struct net_device *drained_dev;
static int drain_pending, drains, sleeps;
static bool drain_required;
static u16 next_vapid;
static int supported_answer = 1;

static bool cdx_wifi_vap_supported(struct net_device *dev)
{
	return dev && supported_answer;
}

static int cdx_wifi_vap_add(struct net_device *dev, struct cdx_wifi_vap **out)
{
	struct cdx_wifi_vap *v;

	/* Every requirement the header states, asserted rather than assumed:
	 * the caller owes the transaction and RTNL. Which of the two ways of
	 * taking RTNL it used -- the admission trylock from the worker, or a
	 * plain rtnl_lock() at module exit where nothing can be waiting on the
	 * transaction -- is the caller's business and not checked here. */
	assert(txn_depth);
	ASSERT_RTNL();
	*out = NULL;
	if (vap_add_fail) { vap_add_fail--; return -EIO; }
	v = calloc(1, sizeof(*v));
	v->dev = dev;
	v->vapid = next_vapid++;
	v->live = true;
	vaps_live++;
	*out = v;
	return 0;
}

static void cdx_wifi_vap_del(struct cdx_wifi_vap **vap)
{
	struct cdx_wifi_vap *v = *vap;

	assert(txn_depth);
	ASSERT_RTNL();
	if (!v)
		return;
	/* The device is borrowed, so a delete that runs after the device is
	 * gone must not have touched it. The harness frees the net_device
	 * struct at unregister, and ASan turns any read of it here into a
	 * failure -- which is the whole point of this file. */
	assert(v->live);
	assert(!drain_required || drained_dev == v->dev);
	drained_dev = NULL;
	v->live = false;
	vaps_live--;
	free(v);
	*vap = NULL;
}

/* --- the entries forwarding through a VAP ------------------------------ */
/* What ft_wifi_vap_drained() answers: the device whose entries were last taken
 * out of hardware, and how many more passes report a deletion still pending.
 * A slot released for a device not drained, or still pending, is the A311
 * race -- the next VAP would inherit an entry built for this one. The state
 * is declared with the VAP backend, which checks it. */
#define MSEC_PER_SEC 1000
static int recovers;
static void msleep(unsigned int ms) { assert(ms == MSEC_PER_SEC); sleeps++; }
/* Asked with RTNL let go of: the recovery takes it itself, and could never
 * have it while its caller held it. */
static int cdx_ft_recover(void)
{
	assert(txn_depth && !rtnl_held);
	recovers++;
	return 0;
}
/* Whether a deletion still awaits its proof after the recovery: as many more
 * drains as are still to report one. */
static bool cdx_ft_pending(void)
{
	assert(txn_depth);
	return drain_pending > 0;
}
static bool ft_wifi_vap_drained(const struct net_device *dev)
{
	assert(txn_depth);
	ASSERT_RTNL();
	drains++;
	if (drain_pending) {
		drain_pending--;
		drained_dev = NULL;
		return false;
	}
	drained_dev = dev;
	return true;
}

/* --- the adapter's own code ------------------------------------------- */
#include "wifi_production.inc"

/* --- the bench -------------------------------------------------------- */
static void drain(void)
{
	/* The kernel runs the worker when something schedules it; here the
	 * bench does, which is what makes the "did it schedule?" question
	 * observable at all. Bounded so a worker that re-arms itself forever
	 * fails loudly instead of hanging. */
	int rounds = 0;

	while (work_pending) {
		work_pending = 0;
		ft_wifi_work_fn(NULL);
		assert(++rounds < 100);
	}
}

/* Created running, because that is the state every test but the liveness one
 * wants and the state an interface is in when it is worth registering. */
static struct net_device *mkdev(const char *name, int iftype)
{
	struct net_device *d = calloc(1, sizeof(*d));
	snprintf(d->name, sizeof(d->name), "%s", name);
	d->reg_state = NETREG_REGISTERED;
	d->running = true;
	if (iftype >= 0) {
		d->ieee80211_ptr = calloc(1, sizeof(*d->ieee80211_ptr));
		d->ieee80211_ptr->iftype = iftype;
	}
	return d;
}

/* Unregister the way the kernel does: the notifier runs first, and only once
 * every reference is gone is the struct freed. Freeing it here is what makes
 * a later read of it a use-after-free that ASan catches. */
static void unregister(struct net_device *d)
{
	rtnl_held++;
	d->reg_state = NETREG_UNREGISTERING;
	ft_wifi_device_gone(d);
	rtnl_held--;
	assert(d->refcount == 0);
	free(d->ieee80211_ptr);
	d->freed = true;
	free(d);
}

static void reconsider(struct net_device *d)
{
	rtnl_held++;
	ft_wifi_reconsider(d);
	rtnl_held--;
}

static unsigned int watches(void)
{
	struct ft_wifi_watch *w;
	unsigned int n = 0;

	list_for_each_entry(w, &ft_wifi_watches, list)
		n++;
	return n;
}

static void reset(void)
{
	assert(watches() == 0);
	work_pending = 0;
	vaps_live = 0;
	next_vapid = 0;
	alloc_fail = vap_add_fail = admission_fail = 0;
	supported_answer = 1;
	ft_wifi_stopping = false;
	ft_wifi_registered = 0;
}

/* Only an AP-mode cfg80211 device is a VAP. */
static void test_identity(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);
	struct net_device *vlan = mkdev("uap0.7", NL80211_IFTYPE_AP_VLAN);
	struct net_device *sta = mkdev("mlan0", NL80211_IFTYPE_STATION);
	struct net_device *mon = mkdev("mon0", NL80211_IFTYPE_MONITOR);
	struct net_device *eth = mkdev("eth0", -1);

	rtnl_held++;
	assert(ft_wifi_is_vap(ap));
	assert(ft_wifi_is_vap(vlan));
	assert(!ft_wifi_is_vap(sta));
	assert(!ft_wifi_is_vap(mon));
	/* The one that would crash a name-based test: an ordinary ethernet
	 * port has no wireless_dev at all. */
	assert(!ft_wifi_is_vap(eth));
	rtnl_held--;

	/* None of them were offered, so none of them are watched. */
	assert(watches() == 0);
	unregister(ap); unregister(vlan); unregister(sta);
	unregister(mon); unregister(eth);
	reset();
}

/* An AP registers; the same device offered twice does not register twice. */
static void test_register_once(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	reconsider(ap);
	assert(work_pending);
	drain();
	assert(vaps_live == 1);
	assert(ft_wifi_registered == 1);
	assert(watches() == 1);

	/* A second event for an unchanged device changes nothing and does not
	 * even wake the worker -- every UP and CHANGE on every interface comes
	 * through here. */
	reconsider(ap);
	assert(!work_pending);
	drain();
	assert(vaps_live == 1);

	unregister(ap);
	drain();
	assert(vaps_live == 0);
	assert(ft_wifi_registered == 0);
	assert(watches() == 0);
	reset();
}

/* An interface registered before it is brought up -- which is what the driver
 * on the rig does, and what cost two refusals a boot before the liveness gate
 * went in -- is not offered to the backend until it is running. */
static void test_not_running(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	ap->running = false;
	reconsider(ap);
	drain();
	assert(vaps_live == 0);
	assert(watches() == 0);
	assert(atomic64_read(&ft_wifi_refusals) == 0);

	/* And registers the moment it comes up. */
	ap->running = true;
	reconsider(ap);
	drain();
	assert(vaps_live == 1);

	/* Going down retires it: the backend refuses a device that is not up,
	 * so a VAP held across a down would be one the hardware disowns. */
	ap->running = false;
	reconsider(ap);
	drain();
	assert(vaps_live == 0);

	unregister(ap);
	drain();
	reset();
}

/* Leaving AP mode retires the VAP; the device is still there afterwards.
 *
 * On real hardware the type change itself raises no netdev event, so this
 * reaches the adapter as the down and up that bracket it -- which is what the
 * liveness gate in ft_wifi_is_vap() turns into an observable transition. */
static void test_mode_change(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	reconsider(ap);
	drain();
	assert(vaps_live == 1);

	/* down, type changes silently, up */
	ap->running = false;
	reconsider(ap);
	drain();
	assert(vaps_live == 0);
	ap->ieee80211_ptr->iftype = NL80211_IFTYPE_STATION;
	ap->running = true;
	reconsider(ap);
	drain();
	assert(vaps_live == 0);
	/* The watch stays: the device still exists and could become an AP
	 * again, and only its unregistration frees the record. */
	assert(watches() == 1);

	ap->ieee80211_ptr->iftype = NL80211_IFTYPE_AP;
	reconsider(ap);
	drain();
	assert(vaps_live == 1);

	unregister(ap);
	drain();
	assert(watches() == 0);
	reset();
}

/* The case the rig cannot reach: the device unregisters while a VAP is
 * registered, and the retirement must use nothing but what was copied. */
static void test_unregister_retires(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	reconsider(ap);
	drain();
	assert(vaps_live == 1);

	/* Frees the net_device. Anything the worker still reads from it is a
	 * use-after-free, and the retirement below runs after this point. */
	unregister(ap);
	assert(vaps_live == 1);   /* not yet -- the worker has not run */
	drain();
	assert(vaps_live == 0);
	assert(watches() == 0);
	reset();
}

/* A VAP's slot is handed to the next VAP registered, so it is released only
 * once every entry forwarding through the old one has left hardware: a
 * deletion still awaiting the datapath's proof keeps the slot, and the
 * worker comes back for it. Retiring a stale VAP to register it again is the
 * same release. */
static void test_slot_released_after_its_entries(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	drain_required = true;
	drains = sleeps = 0;
	reconsider(ap);
	drain();
	assert(vaps_live == 1);

	rtnl_held++;
	ft_wifi_address_changed(ap);
	rtnl_held--;
	drain();
	assert(vaps_live == 1 && drains == 1 && sleeps == 0);

	unregister(ap);
	drain_pending = 2;
	drain();
	/* Two passes found it pending; the recovery after the second cleared
	 * it, so only the first waited. */
	assert(vaps_live == 0 && drains == 4 && sleeps == 1 && recovers == 2);
	assert(watches() == 0 && !txn_depth && !rtnl_held);

	/* A VAP whose entries are still pending does not keep the device
	 * behind it waiting: it goes to the back of the list. */
	{
		struct net_device *first = mkdev("uap0", NL80211_IFTYPE_AP);
		struct net_device *second = mkdev("uap1", NL80211_IFTYPE_AP);

		reconsider(first);
		drain();
		unregister(first);
		reconsider(second);
		drain_pending = 1;
		drains = sleeps = 0;
		drain();
		/* Retired once, sent back; the second registered on the next
		 * pass; then the first released. */
		assert(drains == 2 && sleeps == 0 && vaps_live == 1);
		unregister(second);
		drain();
		assert(vaps_live == 0 && watches() == 0);
	}

	/* And unload does not wait on a retry: one still pending when the
	 * worker is told to stop ends the pass, and exit releases the VAP. */
	{
		struct net_device *ap2 = mkdev("uap0", NL80211_IFTYPE_AP);

		reconsider(ap2);
		drain();
		unregister(ap2);
		drain_pending = 1;
		ft_wifi_stopping = true;
		drains = sleeps = 0;
		work_pending = 0;
		ft_wifi_work_fn(NULL);
		assert(drains == 1 && sleeps == 0 && vaps_live == 1 && !txn_depth);
		drain_required = false;
		ft_wifi_exit();
		assert(vaps_live == 0 && watches() == 0);
	}
	drain_required = false;
	drains = sleeps = recovers = 0;
	drain_pending = 0;
	reset();
}

/* A device that unregisters before its pending registration ever ran leaves
 * nothing behind. */
static void test_unregister_before_add(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	reconsider(ap);
	assert(work_pending);
	unregister(ap);
	drain();
	assert(vaps_live == 0);
	assert(watches() == 0);
	reset();
}

/* A failed registration is not retried forever. */
static void test_add_failure_gives_up(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	vap_add_fail = 1;
	reconsider(ap);
	drain();
	assert(vaps_live == 0);
	assert(ft_wifi_registered == 0);
	/* Watched but not wanted: the worker settles instead of spinning, and
	 * the refusal is counted so the absence is visible. */
	assert(watches() == 1);
	assert(atomic64_read(&ft_wifi_refusals) > 0);

	/* Another event re-offers it, and this time it takes. */
	reconsider(ap);
	drain();
	assert(vaps_live == 1);

	unregister(ap);
	drain();
	reset();
}

/* RTNL is held by someone waiting on this transaction: come back rather than
 * invert the order. */
static void test_admission_backoff(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	admission_fail = 1;
	reconsider(ap);
	assert(work_pending);
	work_pending = 0;
	ft_wifi_work_fn(NULL);
	/* Nothing registered, and the worker asked to be run again rather than
	 * dropping the device. */
	assert(vaps_live == 0);
	assert(work_pending);
	drain();
	assert(vaps_live == 1);

	unregister(ap);
	drain();
	reset();
}

/* A VAP whose hardware address moves is registered again, because the address
 * was built into what was registered and cannot be rewritten in place. */
static void test_address_change(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);
	struct cdx_wifi_vap *first;
	struct ft_wifi_watch *w;

	reconsider(ap);
	drain();
	assert(vaps_live == 1);
	w = list_entry(ft_wifi_watches.next, struct ft_wifi_watch, list);
	first = w->vap;

	rtnl_held++;
	ft_wifi_address_changed(ap);
	rtnl_held--;
	drain();

	/* Still exactly one, and not the one it had: a retire-then-register
	 * rather than an in-place edit that would have left the old address
	 * in the port and in the encoder's record. */
	assert(vaps_live == 1);
	assert(ft_wifi_registered == 1);
	w = list_entry(ft_wifi_watches.next, struct ft_wifi_watch, list);
	assert(w->vap != first);
	assert(!w->stale);

	unregister(ap);
	drain();
	assert(vaps_live == 0);
	reset();
}

/* Several APs, and the ids the backend hands out are distinct. */
static void test_many(void)
{
	struct net_device *d[4];
	int i;

	for (i = 0; i < 4; i++) {
		const char *n[4] = { "uap0", "uap1", "uap2", "uap3" };
		d[i] = mkdev(n[i], NL80211_IFTYPE_AP);
		reconsider(d[i]);
	}
	drain();
	assert(vaps_live == 4);
	assert(ft_wifi_registered == 4);

	for (i = 0; i < 4; i++)
		unregister(d[i]);
	drain();
	assert(vaps_live == 0);
	assert(watches() == 0);
	reset();
}

/* Module exit owes back every VAP it registered. */
static void test_exit_releases(void)
{
	struct net_device *a = mkdev("uap0", NL80211_IFTYPE_AP);
	struct net_device *b = mkdev("uap1", NL80211_IFTYPE_AP);

	reconsider(a);
	reconsider(b);
	drain();
	assert(vaps_live == 2);

	ft_wifi_exit();
	assert(vaps_live == 0);
	assert(watches() == 0);

	/* And nothing queued after it can resurrect one. */
	ft_wifi_stopping = true;
	reconsider(a);
	drain();
	assert(vaps_live == 0);
	assert(watches() == 0);

	unregister(a);
	unregister(b);
	ft_wifi_stopping = false;
	reset();
}

/* The backend refusing the device is not the same as the device not being an
 * AP, and neither leaves a watch behind. */
static void test_unsupported(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	supported_answer = 0;
	reconsider(ap);
	drain();
	assert(vaps_live == 0);
	assert(watches() == 0);

	unregister(ap);
	reset();
}

/* Out of memory for the watch: nothing is registered, so nothing is
 * inconsistent. */
static void test_watch_alloc_failure(void)
{
	struct net_device *ap = mkdev("uap0", NL80211_IFTYPE_AP);

	alloc_fail = 1;
	reconsider(ap);
	drain();
	assert(vaps_live == 0);
	assert(watches() == 0);

	unregister(ap);
	reset();
}

int main(void)
{
	INIT_LIST_HEAD(&ft_wifi_watches);
	test_identity();
	test_register_once();
	test_not_running();
	test_mode_change();
	test_unregister_retires();
	test_slot_released_after_its_entries();
	test_unregister_before_add();
	test_add_failure_gives_up();
	test_admission_backoff();
	test_address_change();
	test_many();
	test_exit_releases();
	test_unsupported();
	test_watch_alloc_failure();
	printf("wifi_adapter: ok\n");
	return 0;
}

/* A ppp unit telling the drivers that offload flows through it that its
 * channel came or went, compiled from the kernel: ppp_connect_channel() and
 * ppp_disconnect_channel(), the item that tells of a disconnect
 * (ppp_link_work()), what both raise (ppp_link_changed()), and the RTM_NEWLINK
 * rtnetlink sends for it (rtnetlink_event()), over the kernel's own
 * declarations of the unit, the channel, the per-namespace state and the
 * channel's public half. Locks, the RCU grace period, the workqueue, the
 * device's references and the notifier chain are simulated, and record what
 * happened in order.
 *
 * pppd dialling on demand keeps the unit, its addresses and routes when a
 * session ends: only the channel leaves it, and nothing else tells. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define CONFIG_CPE_FAST_PATH 1
#define __percpu
#define __rcu
#define NUM_NP 6
#define IFF_NO_QUEUE (1U << 21)
#define IFF_MASTER 0x400
#define IFF_BONDING (1U << 5)
#define RTM_NEWLINK 16
#define GFP_KERNEL 0
#define NOTIFY_DONE 0
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

/* include/linux/netdevice.h: the events rtnetlink looks at, told apart. */
enum netdev_cmd {
	NETDEV_UP = 1, NETDEV_DOWN, NETDEV_REBOOT, NETDEV_CHANGE, NETDEV_REGISTER,
	NETDEV_UNREGISTER, NETDEV_CHANGEMTU, NETDEV_CHANGEADDR, NETDEV_PRE_CHANGEADDR,
	NETDEV_GOING_DOWN, NETDEV_CHANGENAME, NETDEV_FEAT_CHANGE,
	NETDEV_BONDING_FAILOVER, NETDEV_PRE_UP, NETDEV_PRE_TYPE_CHANGE,
	NETDEV_POST_TYPE_CHANGE, NETDEV_POST_INIT, NETDEV_PRE_UNINIT, NETDEV_RELEASE,
	NETDEV_NOTIFY_PEERS, NETDEV_JOIN, NETDEV_CHANGEUPPER, NETDEV_RESEND_IGMP,
	NETDEV_PRECHANGEMTU, NETDEV_CHANGEINFODATA, NETDEV_BONDING_INFO,
	NETDEV_PRECHANGEUPPER, NETDEV_CHANGELOWERSTATE, NETDEV_UDP_TUNNEL_PUSH_INFO,
	NETDEV_UDP_TUNNEL_DROP_INFO, NETDEV_CHANGE_TX_QUEUE_LEN,
};
/* include/uapi/linux/if_link.h */
enum {
	IFLA_EVENT_NONE, IFLA_EVENT_REBOOT, IFLA_EVENT_FEATURES,
	IFLA_EVENT_BONDING_FAILOVER, IFLA_EVENT_NOTIFY_PEERS, IFLA_EVENT_IGMP_RESEND,
	IFLA_EVENT_BONDING_OPTIONS,
};
enum { NETREG_UNINITIALIZED, NETREG_REGISTERED, NETREG_UNREGISTERING,
       NETREG_UNREGISTERED };
enum NPmode { NPMODE_PASS, NPMODE_DROP, NPMODE_ERROR, NPMODE_QUEUE };

struct list_head { struct list_head *next, *prev; };
struct sk_buff_head { int unused; };
typedef struct { int unused; } wait_queue_head_t;
typedef struct { int refs; } refcount_t;
typedef struct { bool held; } spinlock_t;
typedef struct { bool held; } rwlock_t;
struct rw_semaphore { int unused; };
typedef struct { int unused; } netns_tracker;
struct rcu_head { int unused; };
struct idr { int unused; };
struct mutex { bool held; };
struct file;
struct slcompress;
struct compressor;
struct sk_buff;
struct bpf_prog;
struct ppp_channel_ops;
struct nlmsghdr;
struct notifier_block;
struct net { int id; };
struct work_struct {
	void (*func)(struct work_struct *work);
	bool pending;
};
struct workqueue_struct { int unused; };
struct net_device {
	int refs;
	int reg_state;
	unsigned int flags, priv_flags;
	unsigned short hard_header_len;
};

#include "ppp_link_types.inc"

/* What happened, in order, and how many channels the unit had then. */
enum event {
	LIST_ADD, LIST_DEL, SYNC, HOLD, PUT, QUEUED, COALESCED, RTNL_LOCK,
	RTNL_UNLOCK, NOTIFY, MUTEX_UNLOCK, DESTROY, NEWLINK, PPP_LOCK, PPP_UNLOCK,
};
static struct {
	enum event what;
	int channels;
	u32 ifla_event;
} events[128];
static unsigned int nevents;
static struct ppp *watched;

static void record(enum event what)
{
	assert(nevents < ARRAY_LEN(events));
	events[nevents].what = what;
	events[nevents].channels = watched ? watched->n_channels : -1;
	events[nevents].ifla_event = 0;
	nevents++;
}

/* The events since `from`, which must be exactly `want`. */
static void expect(unsigned int from, const enum event *want, unsigned int n)
{
	if (nevents - from != n) {
		fprintf(stderr, "%u events, %u expected:", nevents - from, n);
		for (unsigned int i = from; i < nevents; i++)
			fprintf(stderr, " %d", events[i].what);
		fprintf(stderr, "\n");
		assert(0);
	}
	for (unsigned int i = 0; i < n; i++)
		assert(events[from + i].what == want[i]);
}
#define EXPECT(from, ...) do {						\
	static const enum event want_[] = { __VA_ARGS__ };		\
	expect((from), want_, ARRAY_LEN(want_));			\
} while (0)
/* A channel taken off the unit's list, and the grace period after it. */
#define UNLISTED PPP_LOCK, LIST_DEL, PPP_UNLOCK, SYNC

/* The locks: none is taken twice, and nothing sleeps under a spinning one.
 * The unit's ppp_lock() takes its transmit lock first and ppp_unlock() lets
 * it go last, so that one lock brackets the unit's critical sections. A case
 * can have the unit start closing during a disconnect's grace period:
 * ppp_dev_uninit() sets closing under ppp_lock(), so the next section the
 * disconnect enters is the first to see it, and a read outside it does not. */
static int spinning;
static bool rtnl_held;
static bool close_in_grace, close_at_lock;
static void spin_lock_bh(spinlock_t *l)
{
	assert(!l->held);
	l->held = true;
	spinning++;
	if (watched && l == &watched->wlock) {
		if (close_at_lock) {
			watched->closing = 1;
			close_at_lock = false;
		}
		record(PPP_LOCK);
	}
}
static void spin_unlock_bh(spinlock_t *l)
{
	assert(l->held);
	l->held = false;
	spinning--;
	if (watched && l == &watched->wlock)
		record(PPP_UNLOCK);
}
static void write_lock_bh(rwlock_t *l) { assert(!l->held); l->held = true; spinning++; }
static void write_unlock_bh(rwlock_t *l) { assert(l->held); l->held = false; spinning--; }
static void mutex_lock(struct mutex *m) { assert(!m->held && !spinning); m->held = true; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held = false; record(MUTEX_UNLOCK); }
static void rtnl_lock(void) { assert(!rtnl_held && !spinning); rtnl_held = true; record(RTNL_LOCK); }
static void rtnl_unlock(void) { assert(rtnl_held); rtnl_held = false; record(RTNL_UNLOCK); }
#define ASSERT_RTNL() assert(rtnl_held)
#define rcu_dereference_protected(p, c) (p)
#define lockdep_is_held(l) 1

static void list_add_tail_rcu(struct list_head *e, struct list_head *h)
{
	e->next = h;
	e->prev = h->prev;
	h->prev->next = e;
	h->prev = e;
	record(LIST_ADD);
}
static void list_del_rcu(struct list_head *e)
{
	e->prev->next = e->next;
	e->next->prev = e->prev;
	record(LIST_DEL);
}
static void wake_up_interruptible(wait_queue_head_t *q) {}
static void synchronize_net(void)
{
	assert(!spinning);
	record(SYNC);
	close_at_lock = close_in_grace;
	close_in_grace = false;
}
static void refcount_inc(refcount_t *r) { assert(r->refs > 0); r->refs++; }
static bool refcount_dec_and_test(refcount_t *r) { assert(r->refs > 0); return !--r->refs; }
static void dev_hold(struct net_device *dev) { dev->refs++; record(HOLD); }
static void dev_put(struct net_device *dev) { assert(dev->refs > 0); dev->refs--; record(PUT); }

/* The module's own queue: an item already pending is not queued again, and
 * runs once, when the case says. */
static struct workqueue_struct link_queue;
static struct work_struct *queued;
#define INIT_WORK(w, fn) (*(w) = (struct work_struct){ .func = (fn) })
static bool queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	assert(wq == &link_queue && work->func);
	if (work->pending) {
		record(COALESCED);
		return false;
	}
	work->pending = true;
	queued = work;
	record(QUEUED);
	return true;
}
static void run_queued(void)
{
	struct work_struct *work = queued;

	assert(work && work->pending && !spinning && !rtnl_held);
	queued = NULL;
	work->pending = false;
	work->func(work);
	assert(!spinning && !rtnl_held);
}

/* The netdevice chain, which rtnetlink is on. */
static struct net_device *notified;
static int rtnetlink_event(struct notifier_block *this, unsigned long event, void *ptr);
static int call_netdevice_notifiers(unsigned long val, struct net_device *dev)
{
	assert(rtnl_held && !spinning);
	assert(val == NETDEV_CHANGEINFODATA);
	notified = dev;
	record(NOTIFY);
	return rtnetlink_event(NULL, val, dev);
}
#define netdev_notifier_info_to_dev(ptr) ((struct net_device *)(ptr))
static bool netif_is_bond_master(const struct net_device *dev)
{
	return dev->flags & IFF_MASTER && dev->priv_flags & IFF_BONDING;
}
static void rtmsg_ifinfo_event(int type, struct net_device *dev, unsigned int change,
			       u32 event, int flags, int *new_nsid, int new_ifindex,
			       u32 portid, const struct nlmsghdr *nlh)
{
	assert(type == RTM_NEWLINK && !change);
	record(NEWLINK);
	events[nevents - 1].ifla_event = event;
}

/* The per-namespace state, the one unit and the end of a unit. */
static struct net net0;
static struct ppp_net pn;
static struct ppp *unit_found;
static int unit_number;
static struct ppp_net *ppp_pernet(struct net *net) { assert(net == &net0); return &pn; }
static struct ppp *ppp_find_unit(struct ppp_net *p, int unit)
{
	assert(p == &pn && pn.all_ppp_mutex.held);
	return unit == unit_number ? unit_found : NULL;
}
static void ppp_destroy_interface(struct ppp *ppp) { record(DESTROY); }

#include "ppp_link_production.inc"

static struct net_device unit_dev, bond_dev, eth_dev;
static struct ppp unit;
static struct ppp_channel pppoe_a, pppoe_b;
static struct channel chan_a, chan_b;

/* A registered unit pppd holds open, with the reference its device holds on
 * it (ppp_dev_init()), and two PPPoE channels not yet attached. */
static void fixture(void)
{
	memset(&unit, 0, sizeof(unit));
	unit_dev = (struct net_device){ .refs = 1, .reg_state = NETREG_REGISTERED };
	unit.dev = &unit_dev;
	unit.ppp_net = &net0;
	unit.file.refcnt.refs = 2;
	unit.channels.next = unit.channels.prev = &unit.channels;
	INIT_WORK(&unit.link_work, ppp_link_work);
	unit_found = &unit;
	unit_number = 0;
	pn = (struct ppp_net){};
	pppoe_a = pppoe_b = (struct ppp_channel){ .direct_xmit = true };
	chan_a = (struct channel){ .chan = &pppoe_a, .chan_net = &net0 };
	chan_b = (struct channel){ .chan = &pppoe_b, .chan_net = &net0 };
	chan_a.file.hdrlen = chan_b.file.hdrlen = 22;
	ppp_link_wq = &link_queue;
	queued = NULL;
	notified = NULL;
	watched = &unit;
	close_in_grace = close_at_lock = false;
	nevents = 0;
	assert(!spinning && !rtnl_held);
}

static void attach(struct channel *pch)
{
	unsigned int from = nevents;

	assert(ppp_connect_channel(pch, 0) == 0);
	assert(pch->ppp == &unit);
	EXPECT(from, PPP_LOCK, LIST_ADD, PPP_UNLOCK, HOLD, MUTEX_UNLOCK, RTNL_LOCK,
	       NOTIFY, NEWLINK, RTNL_UNLOCK, PUT);
	assert(notified == &unit_dev && unit_dev.refs == 1);
	/* Told with the channel on the list, and as no bonding event. */
	assert(events[from + 6].channels == unit.n_channels);
	assert(events[from + 7].ifla_event == IFLA_EVENT_NONE);
	notified = NULL;
}

/* A channel joining is told at once, under RTNL, once all_ppp_mutex is
 * dropped, with the channel already on the unit's list, as an RTM_NEWLINK
 * that names no bonding event. */
static void test_connect(void)
{
	unsigned int from;

	fixture();
	attach(&chan_a);
	assert(events[6].channels == 1);
	assert(unit.file.refcnt.refs == 3 && unit.n_channels == 1);
	assert(unit_dev.priv_flags & IFF_NO_QUEUE);

	/* A unit whose registration has not completed, or failed, or that is
	 * being unregistered without closing yet: attached, told nothing. */
	for (int state = 0; state < 3; state++) {
		static const int states[] = { NETREG_UNINITIALIZED, NETREG_UNREGISTERING,
					      NETREG_UNREGISTERED };

		fixture();
		unit_dev.reg_state = states[state];
		from = nevents;
		assert(ppp_connect_channel(&chan_a, 0) == 0);
		EXPECT(from, PPP_LOCK, LIST_ADD, PPP_UNLOCK, HOLD, MUTEX_UNLOCK,
		       RTNL_LOCK, RTNL_UNLOCK, PUT);
		assert(!notified && unit_dev.refs == 1);
	}

	/* A closing unit takes the channel and is told nothing. */
	fixture();
	unit.closing = 1;
	from = nevents;
	assert(ppp_connect_channel(&chan_a, 0) == 0);
	EXPECT(from, PPP_LOCK, LIST_ADD, PPP_UNLOCK, MUTEX_UNLOCK);

	/* A channel whose driver has unregistered it, an attached channel and
	 * a unit that is not there join nothing and tell nothing. */
	fixture();
	chan_a.chan = NULL;
	from = nevents;
	assert(ppp_connect_channel(&chan_a, 0) == -ENOTCONN);
	EXPECT(from, PPP_LOCK, PPP_UNLOCK, MUTEX_UNLOCK);
	fixture();
	attach(&chan_a);
	from = nevents;
	assert(ppp_connect_channel(&chan_a, 0) == -EINVAL);
	EXPECT(from, MUTEX_UNLOCK);
	fixture();
	from = nevents;
	assert(ppp_connect_channel(&chan_a, 1) == -ENXIO);
	EXPECT(from, MUTEX_UNLOCK);
	assert(!notified && unit_dev.refs == 1);
}

/* A channel leaving is told from the module's queue: after the grace period
 * that lets every walk which saw it add its flow, with the channel already off
 * the list, never under the locks the disconnect runs under, and holding the
 * device until the item has run. Whether the unit is closing, and the
 * reference and the queueing that follow, are one section under ppp_lock(),
 * the lock ppp_dev_uninit() sets closing under: a unit not closing in it is
 * one whose unregistration will wait for the reference. */
static void test_disconnect(void)
{
	unsigned int from;

	fixture();
	attach(&chan_a);
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == 0);
	EXPECT(from, UNLISTED, PPP_LOCK, HOLD, QUEUED, PPP_UNLOCK);
	assert(events[from + 6].channels == 0);
	assert(!chan_a.ppp && unit.file.refcnt.refs == 2 && unit_dev.refs == 2);
	assert(!notified);
	from = nevents;
	run_queued();
	EXPECT(from, RTNL_LOCK, NOTIFY, NEWLINK, RTNL_UNLOCK, PUT);
	assert(notified == &unit_dev && unit_dev.refs == 1);
	assert(events[from + 1].channels == 0);
	assert(events[from + 2].ifla_event == IFLA_EVENT_NONE);

	/* Under RTNL and the socket lock, as pppoe_flush_dev() disconnects a
	 * session when its device goes down: the RTNL is not taken again. */
	fixture();
	attach(&chan_a);
	rtnl_held = true;
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == 0);
	EXPECT(from, UNLISTED, PPP_LOCK, HOLD, QUEUED, PPP_UNLOCK);
	rtnl_held = false;
	from = nevents;
	run_queued();
	EXPECT(from, RTNL_LOCK, NOTIFY, NEWLINK, RTNL_UNLOCK, PUT);
	assert(unit_dev.refs == 1);

	/* Disconnects pending together are told once, and the extra
	 * reference each would have held goes back at once. One that comes
	 * after the item has run queues it again. */
	fixture();
	attach(&chan_a);
	attach(&chan_b);
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == 0);
	assert(ppp_disconnect_channel(&chan_b) == 0);
	EXPECT(from, UNLISTED, PPP_LOCK, HOLD, QUEUED, PPP_UNLOCK,
	       UNLISTED, PPP_LOCK, HOLD, COALESCED, PUT, PPP_UNLOCK);
	assert(unit_dev.refs == 2);
	from = nevents;
	run_queued();
	EXPECT(from, RTNL_LOCK, NOTIFY, NEWLINK, RTNL_UNLOCK, PUT);
	assert(events[from + 1].channels == 0 && unit_dev.refs == 1);
	attach(&chan_a);
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == 0);
	EXPECT(from, UNLISTED, PPP_LOCK, HOLD, QUEUED, PPP_UNLOCK);
	run_queued();
	assert(unit_dev.refs == 1);

	/* A unit unregistered by the time the item runs is told nothing, and
	 * gets its device back. */
	fixture();
	attach(&chan_a);
	assert(ppp_disconnect_channel(&chan_a) == 0);
	unit_dev.reg_state = NETREG_UNREGISTERING;
	from = nevents;
	run_queued();
	EXPECT(from, RTNL_LOCK, RTNL_UNLOCK, PUT);
	assert(!notified && unit_dev.refs == 1);

	/* A closing unit queues nothing: its unregistration retires what went
	 * through it. Where the channel held the unit's last reference, the
	 * unit goes. */
	fixture();
	attach(&chan_a);
	unit.closing = 1;
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == 0);
	EXPECT(from, UNLISTED, PPP_LOCK, PPP_UNLOCK);
	assert(!queued && unit_dev.refs == 1);
	fixture();
	attach(&chan_a);
	unit.closing = 1;
	unit.file.refcnt.refs = 1;
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == 0);
	EXPECT(from, UNLISTED, PPP_LOCK, PPP_UNLOCK, DESTROY);
	assert(!queued);
	/* So does one that starts closing during the grace period: the
	 * section after it is the first to see that, as a read of closing
	 * taken before it, or outside ppp_lock(), would not. */
	fixture();
	attach(&chan_a);
	close_in_grace = true;
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == 0);
	EXPECT(from, UNLISTED, PPP_LOCK, PPP_UNLOCK);
	assert(unit.closing && !queued && unit_dev.refs == 1);

	/* A channel attached to nothing has nothing to tell. */
	fixture();
	from = nevents;
	assert(ppp_disconnect_channel(&chan_a) == -EINVAL);
	EXPECT(from);
	assert(!queued);
}

/* A bond still says its options changed; nobody else's change does. The
 * other events keep their mapping. */
static void test_newlink(void)
{
	unsigned int from;

	fixture();
	watched = NULL;
	bond_dev = (struct net_device){ .flags = IFF_MASTER, .priv_flags = IFF_BONDING };
	eth_dev = (struct net_device){ .flags = IFF_MASTER };
	from = nevents;
	assert(rtnetlink_event(NULL, NETDEV_CHANGEINFODATA, &bond_dev) == NOTIFY_DONE);
	assert(rtnetlink_event(NULL, NETDEV_CHANGEINFODATA, &eth_dev) == NOTIFY_DONE);
	assert(rtnetlink_event(NULL, NETDEV_CHANGEINFODATA, &unit_dev) == NOTIFY_DONE);
	assert(rtnetlink_event(NULL, NETDEV_RESEND_IGMP, &unit_dev) == NOTIFY_DONE);
	assert(rtnetlink_event(NULL, NETDEV_CHANGELOWERSTATE, &unit_dev) == NOTIFY_DONE);
	assert(rtnetlink_event(NULL, NETDEV_CHANGE, &unit_dev) == NOTIFY_DONE);
	EXPECT(from, NEWLINK, NEWLINK, NEWLINK, NEWLINK, NEWLINK);
	assert(events[from].ifla_event == IFLA_EVENT_BONDING_OPTIONS);
	assert(events[from + 1].ifla_event == IFLA_EVENT_NONE);
	assert(events[from + 2].ifla_event == IFLA_EVENT_NONE);
	assert(events[from + 3].ifla_event == IFLA_EVENT_IGMP_RESEND);
	assert(events[from + 4].ifla_event == IFLA_EVENT_NONE);
}

int main(void)
{
	test_connect();
	test_disconnect();
	test_newlink();
	printf("ppp link notification checks passed\n");
	return 0;
}

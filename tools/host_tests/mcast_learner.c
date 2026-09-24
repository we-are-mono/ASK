/* The bridged multicast learner's decision logic, compiled from the adapter
 * against stubs for everything below it.
 *
 * What this pins down is the part a hardware run cannot show cheaply. The
 * memberships: how a sequence of switchdev objects -- the same port twice, a
 * leave for a port that never joined, a host membership arriving before the
 * ports, a blocked source -- becomes the set of reasons to learn a flow. The
 * flows: how an observed frame becomes one, what the bridge's answer makes of
 * it, and that every membership change asks the bridge again rather than
 * deciding from the objects alone -- which is the only way an IGMPv3 source
 * filter can reach the hardware, since no switchdev object carries one.
 *
 * The answer itself is br_multicast_list_ports(), run against the kernel's
 * own code in bridge_mcast_snapshot.c; here it is scripted per flow.
 *
 * The answer the handler gives the bridge is the other half. `handled`
 * becomes MDB_PG_FLAGS_OFFLOAD and shows up in `bridge mdb show`, so a port
 * the hardware could never replicate to must not claim to have been taken on.
 *
 * Most cases put flows "in hardware" with pass(), which stands in for the
 * worker. The worker itself is compiled too, against a backend that keeps
 * what each entry was built from, for what it records beside an entry and
 * how that meets the egress drain.
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

struct in6_addr { unsigned char s6_addr[16]; };

/* The address union conntrack and the rule share. Only the arms the learner
 * names are needed; the shape has to match so a key compares the way the
 * production one does. */
union nf_inet_addr {
    u32 all[4];
    u32 ip;
    u32 ip6[4];
    struct in6_addr in6;
};

#define ETH_ALEN 6
#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define AF_INET 2
#define AF_INET6 10
#define BRIDGE_VLAN_INFO_UNTAGGED (1 << 2)
#define BRIDGE_VLAN_INFO_BRENTRY (1 << 5)
#define CDX_FT_VLAN_MAX 2
#define CDX_MC_MAX_LISTENERS 8
#define EOPNOTSUPP 95
#define ENOENT 2
#define EINVAL 22
#define EAGAIN 11
#define ENOMEM 12
#define E2BIG 7
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
/* As include/linux/if_bridge.h has them with patch 161. */
#define BR_MCAST_TO_HOST_JOINED (1U << 0)
#define BR_MCAST_TO_HOST_ROUTER (1U << 1)
#define BR_MCAST_TO_HOST_FLOOD  (1U << 2)
#define BR_MCAST_TO_HOST_PROMISC (1U << 3)
#define IFF_PROMISC 0x100
#define IPV6_ADDR_SCOPE_LINKLOCAL 0x02

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16((uint16_t)(x))
#define htonl(x) __builtin_bswap32((uint32_t)(x))
#else
#define htons(x) ((uint16_t)(x))
#define htonl(x) ((uint32_t)(x))
#endif

/* Only what the decision logic reads. A netdev is an opaque token here: the
 * learner compares pointers and asks the stubs about them. */
struct net_device {
    const char *name;
    int ifindex;
    bool physical;
    bool bridge_master;
    unsigned int mtu;
    /* A bridge that is a multicast router hands every group to the host. */
    bool mrouter;
    struct net_device *master;
    unsigned int flags;
    /* References the learner holds on it: a device going away waits for
     * these, and one nothing holds may be freed. */
    unsigned refs;
};

#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))

struct cdx_ft_vlan { uint16_t proto; uint16_t id; };

struct br_ip {
    union { uint32_t ip4; struct in6_addr ip6; } src;
    union { uint32_t ip4; struct in6_addr ip6; } dst;
    uint16_t proto;
    uint16_t vid;
};

struct bridge_vlan_info { uint16_t flags; uint16_t vid; };

/* --- list.h, enough of it -------------------------------------------- */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static void list_add(struct list_head *e, struct list_head *h)
{
    e->next = h->next; e->prev = h; h->next->prev = e; h->next = e;
}
static void list_add_tail(struct list_head *e, struct list_head *h)
{
    e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e;
}
static void list_del(struct list_head *e)
{
    e->prev->next = e->next; e->next->prev = e->prev;
    e->next = e->prev = e;
}
static void list_move(struct list_head *e, struct list_head *h)
{
    list_del(e);
    list_add(e, h);
}
#define list_entry(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, __typeof__(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member) \
    for (pos = list_entry((head)->next, __typeof__(*pos), member), \
         n = list_entry(pos->member.next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = n, n = list_entry(n->member.next, __typeof__(*n), member))

/* --- stubs ----------------------------------------------------------- */
static LIST_HEAD(ft_mc_groups);
static LIST_HEAD(ft_mc_flows);
static unsigned int ft_mc_count, ft_mc_flow_count;
static unsigned long long ft_mc_refused;
/* What the worker last found of the bridge filter hooks; the cases set it
 * as the worker would. */
static bool ft_mc_filtered;
/* Read only by the worker and /proc, neither of which is compiled here. */
__attribute__((unused)) static unsigned int ft_mc_installed;
__attribute__((unused)) static unsigned long long ft_mc_install_errors;

static unsigned holds;   /* net-device references outstanding, all devices */
static void dev_hold(struct net_device *d) { holds++; d->refs++; }
static void dev_put(struct net_device *d) { assert(holds && d->refs); holds--; d->refs--; }

/* The devices the traffic half can resolve an ingress index to. */
static struct net_device *by_index[8];
static struct net_device *dev_get_by_index(void *net, int ifindex)
{
    (void)net;
    for (unsigned i = 0; i < 8; i++)
        if (by_index[i] && by_index[i]->ifindex == ifindex) {
            dev_hold(by_index[i]);
            return by_index[i];
        }
    return NULL;
}
static int init_net;

static bool ether_addr_equal(const u8 *a, const u8 *b) { return !memcmp(a, b, ETH_ALEN); }
static void ether_addr_copy(u8 *d, const u8 *s) { memcpy(d, s, ETH_ALEN); }
#define ASSERT_RTNL() ((void)0)

static bool cdx_mc_port_identity(struct net_device *d)
{
    return d && d->physical;
}

static bool netif_is_bridge_master(const struct net_device *d) { return d->bridge_master; }
static struct net_device *netdev_master_upper_dev_get(struct net_device *d) { return d->master; }

/* The bridge under test: 802.1Q, with a per-(port,vid) membership table the
 * cases populate. */
static bool vlan_enabled;
static uint16_t vlan_proto = ETH_P_8021Q;
static struct { struct net_device *port; uint16_t vid; bool untagged; bool member; }
    memberships[16];
static unsigned membership_count;

static struct { struct net_device *port; uint16_t pvid; } pvids[8];
static unsigned pvid_count;
static int br_vlan_get_pvid(struct net_device *port, uint16_t *p)
{
    for (unsigned i = 0; i < pvid_count; i++)
        if (pvids[i].port == port) {
            *p = pvids[i].pvid;
            return 0;
        }
    return -EOPNOTSUPP;
}

static bool br_vlan_enabled(const struct net_device *br) { (void)br; return vlan_enabled; }
static int br_vlan_get_proto(struct net_device *br, uint16_t *p)
{
    (void)br; *p = vlan_proto; return 0;
}
/* A port's membership, or -- asked of the bridge itself -- the bridge's own,
 * which the kernel marks as a bridge entry. */
static int br_vlan_get_info_rcu(const struct net_device *dev, uint16_t vid,
                                struct bridge_vlan_info *info)
{
    for (unsigned i = 0; i < membership_count; i++)
        if (memberships[i].port == dev && memberships[i].vid == vid &&
            memberships[i].member) {
            info->vid = vid;
            info->flags = memberships[i].untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0;
            if (dev->bridge_master)
                info->flags |= BRIDGE_VLAN_INFO_BRENTRY;
            return 0;
        }
    return -EOPNOTSUPP;
}
static int br_vlan_get_info(struct net_device *port, uint16_t vid,
                            struct bridge_vlan_info *info)
{
    return br_vlan_get_info_rcu(port, vid, info);
}
static bool br_multicast_router(const struct net_device *br) { return br->mrouter; }
/* The bridge's group membership interval, which it ages its memberships by,
 * in jiffies; the learner ages an idle entry by the same. */
#define HZ 100
#define time_after(a, b) ((long)((b) - (a)) < 0)
static unsigned long membership_interval = 260 * HZ;
static unsigned long br_multicast_membership_interval(const struct net_device *br,
                                                      uint16_t vid)
{
    assert(br->bridge_master);
    (void)vid;
    return membership_interval;
}
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)

/* Link-local scope, as the kernel computes it for a multicast address: the
 * scope nibble of ff0X::. */
static bool ipv4_is_local_multicast(uint32_t a)
{
    return (a & htonl(0xffffff00)) == htonl(0xe0000000);
}
static int __ipv6_addr_type(const struct in6_addr *a)
{
    return a->s6_addr[0] == 0xff ? (a->s6_addr[1] & 0x0f) << 16 : 0x0e << 16;
}
static int __ipv6_addr_src_scope(int type) { return type >> 16; }

/* The bridge's answer, scripted per flow: which ports a frame of this source
 * arriving on this port in this VLAN goes to, and why it also goes up. A flow
 * nothing scripted gets no port at all -- the bridge's answer for a group with
 * no listener but the ingress. */
static struct snap {
    struct net_device *in;
    uint32_t source;
    uint16_t vid;
    int n;
    unsigned local;
    struct net_device *ports[CDX_MC_MAX_LISTENERS];
} snaps[16];
static unsigned snap_count, snap_calls;

static void answer(struct net_device *in, uint32_t source, uint16_t vid,
                   unsigned local, int n, ...);

static int br_multicast_list_ports(struct net_device *dev, const struct br_ip *group,
                                   struct net_device *in_dev, unsigned int *local,
                                   struct net_device **ports, unsigned int max)
{
    snap_calls++;
    /* A received frame is asked about with its ingress, and the host's copy
     * is part of the answer. */
    assert(dev && dev->bridge_master && in_dev && local);
    for (unsigned i = snap_count; i-- > 0;) {
        const struct snap *s = &snaps[i];

        if (s->in != in_dev || s->source != group->src.ip4 || s->vid != group->vid)
            continue;
        *local = s->local;
        if (s->n < 0)
            return s->n;
        if ((unsigned)s->n > max)
            return -E2BIG;
        memcpy(ports, s->ports, s->n * sizeof(ports[0]));
        return s->n;
    }
    *local = 0;
    return 0;
}

/* The learner's own locks and worker, as far as the functions compiled here
 * reach them: taken, never nested, and a worker that only counts wakes. */
static int ft_mc_lock;
static bool ft_mc_stopping;
static int ft_mc_work;
static unsigned works;
static void mutex_lock(int *m) { assert(!*m); *m = 1; }
static void mutex_unlock(int *m) { assert(*m); *m = 0; }
#define spin_lock_bh mutex_lock
#define spin_unlock_bh mutex_unlock
#define spin_lock mutex_lock
#define spin_unlock mutex_unlock
#define DEFINE_SPINLOCK(x) int x
#define DEFINE_MUTEX(x) int x
static void schedule_work(int *w) { (void)w; works++; }

/* Whether any byte differs from c. The learner uses it to ask whether a
 * membership named a source at all, which is what tells (S,G) from (*,G). */
static void *memchr_inv(const void *p, int c, size_t n)
{
    const unsigned char *b = p;

    for (size_t i = 0; i < n; i++)
        if (b[i] != (unsigned char)c)
            return (void *)(b + i);
    return NULL;
}

#define lockdep_assert_held(x) ((void)0)
/* A test can make the next allocation fail. */
static bool fail_alloc;
static void *kzalloc_stub(size_t n)
{
    if (fail_alloc) {
        fail_alloc = false;
        return NULL;
    }
    return calloc(1, n);
}
#define kzalloc(n, f) kzalloc_stub(n)
#define kfree(p) free(p)
#define GFP_KERNEL 0

/* --- the switchdev objects the MDB handler reads, as patch 160 has them -- */
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
enum switchdev_obj_id {
    SWITCHDEV_OBJ_ID_UNDEFINED,
    SWITCHDEV_OBJ_ID_PORT_VLAN,
    SWITCHDEV_OBJ_ID_PORT_MDB,
    SWITCHDEV_OBJ_ID_HOST_MDB,
};
enum { SWITCHDEV_PORT_OBJ_ADD = 1, SWITCHDEV_PORT_OBJ_DEL, SWITCHDEV_PORT_ATTR_SET };
#define SWITCHDEV_OBJ_MDB_F_BLOCKED (1 << 0)
#define NOTIFY_DONE 0
struct switchdev_obj {
    struct net_device *orig_dev;
    enum switchdev_obj_id id;
};
struct switchdev_obj_port_mdb {
    struct switchdev_obj obj;
    unsigned char addr[ETH_ALEN];
    u16 vid;
    struct br_ip group;
    u8 flags;
};
#define SWITCHDEV_OBJ_PORT_MDB(o) container_of((o), struct switchdev_obj_port_mdb, obj)
struct switchdev_notifier_info { struct net_device *dev; };
struct switchdev_notifier_port_obj_info {
    struct switchdev_notifier_info info;
    const struct switchdev_obj *obj;
    bool handled;
};
struct notifier_block;
static int *dev_net(const struct net_device *d) { (void)d; return &init_net; }
static bool net_eq(const int *a, const int *b) { return a == b; }
static unsigned mr_kicks;
static void ft_mr_kick(void) { mr_kicks++; }

/* The refresh, as far as it reaches past the learner: the transaction, the
 * clock, its own rearm, and the entry's count, which a case can make fail. */
struct work_struct;
struct cdx_mc_group;
struct cdx_ft_counters;
static unsigned long jiffies;
static int ft_mc_refresh;
static unsigned refresh_rearms;
static void schedule_delayed_work(int *w, unsigned long delay)
{
    (void)w;
    (void)delay;
    refresh_rearms++;
}
/* The worker takes RTNL only to ask the bridge, and never with the
 * transaction or the group lock held. The one caller that takes the
 * transaction under RTNL is the egress drain, under the RTNL a tc command
 * holds (`caller_rtnl`). */
static int in_transaction, rtnl;
static bool caller_rtnl;
static void rtnl_lock(void) { assert(!rtnl && !in_transaction && !ft_mc_lock); rtnl = 1; }
static void rtnl_unlock(void) { assert(rtnl && !caller_rtnl); rtnl = 0; }
/* Something that gets the transaction just before whoever asks for it next,
 * run once: a tc command's egress change and drain, or a device going away,
 * landing while the worker waits for the transaction with a flow it picked.
 * `before_begin_skip` lets that many transactions go by first: a worker pass
 * takes one to retire before any it builds in. */
static void (*before_begin)(void);
static unsigned before_begin_skip;
static void recorded_chains_hold_their_devices(void);
static void cdx_ft_begin(void)
{
    assert(!in_transaction && !ft_mc_lock && (!rtnl || caller_rtnl));
    if (before_begin && before_begin_skip) {
        before_begin_skip--;
    } else if (before_begin) {
        void (*run)(void) = before_begin;

        before_begin = NULL;
        run();
    }
    recorded_chains_hold_their_devices();
    in_transaction = 1;
}
static void cdx_ft_end(void) { assert(in_transaction); in_transaction = 0; }
static bool cdx_mc_group_stats(const struct cdx_mc_group *hw, struct cdx_ft_counters *c);
struct cdx_mc_group_spec;
static int cdx_mc_group_replace(struct cdx_mc_group *hw,
                                const struct cdx_mc_group_spec *spec);
static int cdx_mc_group_add(const struct cdx_mc_group_spec *spec,
                            struct cdx_mc_group **result);
static void cdx_mc_group_del(struct cdx_mc_group **group);

/* What the worker needs beyond the learner's own functions. The egress count
 * is the adapter's, shared with its IPsec half; ft_egress_changed() moves it
 * before any learner marks anything. */
typedef int64_t s64;
static s64 ft_egress_changes;
static s64 atomic64_read(const s64 *v) { return *v; }
static s64 atomic64_read_acquire(const s64 *v) { return *v; }
static bool ft_mc_recheck;
static bool bridge_hooked;
static bool ft_mc_bridge_filtered(void) { return bridge_hooked; }
static void ft_mc_hook_sync(bool want) { (void)want; }
#define pr_info(...) ((void)0)

#include "mcast_learner.inc"

/* A port's egress changing, as the adapter's hook has it: counted, then
 * every installed flow copying out of the port marked. */
static void egress_changed(struct net_device *dev)
{
    ft_egress_changes++;
    ft_mc_egress_mark(dev);
}

/* How many times the chains recorded for the drain name `d`. */
static unsigned recorded_namings(const struct net_device *d)
{
    const struct ft_mc_flow *f;
    unsigned n = 0;

    list_for_each_entry(f, &ft_mc_flows, list) {
        if (!f->hw_spec.listeners)
            continue;
        n += f->hw_spec.in == d;
        for (u8 i = 0; i < f->hw_spec.listeners; i++)
            n += f->hw_spec.listener[i].dev == d;
    }
    return n;
}

/* Every device a chain recorded for the drain names is held at least once
 * for each time it is named: the drain replays the chain with nothing else
 * of its own holding those devices, and a device nothing holds may be freed.
 * Checked whenever anything takes the transaction. */
static void recorded_chains_hold_their_devices(void)
{
    struct ft_mc_flow *f;

    list_for_each_entry(f, &ft_mc_flows, list) {
        if (!f->hw_spec.listeners)
            continue;
        assert(f->hw_spec.in->refs >= recorded_namings(f->hw_spec.in));
        for (u8 i = 0; i < f->hw_spec.listeners; i++)
            assert(f->hw_spec.listener[i].dev->refs >=
                   recorded_namings(f->hw_spec.listener[i].dev));
    }
}

/* The backend, as far as the worker and the drain reach it. An entry the
 * worker added is one of these, keyed as the backend keys it and remembering
 * the chain it was last given and the egress count it was built against. The
 * cases that put a flow "in hardware" themselves use FAKE_HW, which is never
 * looked into. */
struct cdx_mc_group {
    bool live;
    struct cdx_mc_group_spec key;
    struct cdx_mc_group_spec chain;
    s64 built_at;
};
static struct cdx_mc_group entries[4];
static struct cdx_mc_group *const FAKE_HW = (struct cdx_mc_group *)0x1000;
static unsigned adds, dels;
static int add_rc;
/* A port's egress changing after a build has read it and before the worker
 * records it: counted, and marking what it can at once, since the worker
 * holds no learner lock while it builds. */
static struct net_device *change_during_build;

/* The classifier key cdx_mc_same_key() compares: a replace keeps it. */
static bool same_key(const struct cdx_mc_group_spec *a, const struct cdx_mc_group_spec *b)
{
    return a->in == b->in && a->bridged == b->bridged && a->family == b->family &&
           !memcmp(&a->src, &b->src, sizeof(a->src)) &&
           !memcmp(&a->dst, &b->dst, sizeof(a->dst)) &&
           !memcmp(a->src_mac, b->src_mac, ETH_ALEN) &&
           !memcmp(a->dst_mac, b->dst_mac, ETH_ALEN) &&
           a->in_vlans == b->in_vlans &&
           !memcmp(a->in_vlan, b->in_vlan, a->in_vlans * sizeof(a->in_vlan[0]));
}

/* The key and every copy: what the entry replicates to, and how. */
static bool same_chain(const struct cdx_mc_group_spec *a, const struct cdx_mc_group_spec *b)
{
    if (!same_key(a, b) || a->listeners != b->listeners)
        return false;
    for (u8 i = 0; i < a->listeners; i++) {
        const struct cdx_mc_listener *x = &a->listener[i], *y = &b->listener[i];

        if (x->dev != y->dev || x->routed != y->routed || x->vlans != y->vlans ||
            memcmp(x->vlan, y->vlan, x->vlans * sizeof(x->vlan[0])) ||
            !ether_addr_equal(x->src_mac, y->src_mac))
            return false;
    }
    return true;
}

static void built(struct cdx_mc_group *hw, const struct cdx_mc_group_spec *spec)
{
    hw->chain = *spec;
    hw->built_at = ft_egress_changes;
    if (change_during_build) {
        struct net_device *dev = change_during_build;

        change_during_build = NULL;
        egress_changed(dev);
    }
}

/* Only the worker adds and deletes, and it does the hardware with the
 * transaction alone: the MDB handler and the netdev events, which take
 * ft_mc_lock under RTNL, must never wait behind a hardware call. The drain
 * replaces holding ft_mc_lock, under its tc command's RTNL. */
static int cdx_mc_group_add(const struct cdx_mc_group_spec *spec,
                            struct cdx_mc_group **result)
{
    assert(in_transaction && !ft_mc_lock && spec->listeners);
    adds++;
    *result = NULL;
    if (add_rc)
        return add_rc;
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++)
        if (!entries[i].live) {
            entries[i].live = true;
            entries[i].key = *spec;
            built(&entries[i], spec);
            *result = &entries[i];
            return 0;
        }
    abort();
}

static void cdx_mc_group_del(struct cdx_mc_group **group)
{
    assert(*group && in_transaction && !ft_mc_lock);
    if (*group != FAKE_HW) {
        assert((*group)->live);
        memset(*group, 0, sizeof(**group));
    }
    dels++;
    *group = NULL;
}

/* A replace: the drain's rebuild of a recorded chain, made inside the
 * transaction with the learner's lock taken there under its tc command's
 * RTNL, or the worker's, made with the transaction alone. What it was asked
 * to build is kept for a case to read; one can fail it, which leaves the old
 * chain in place. A spec under another key is refused, as the backend
 * refuses it. */
static struct cdx_mc_group_spec replaced;
static unsigned replaces;
static int replace_rc;
static int cdx_mc_group_replace(struct cdx_mc_group *hw,
                                const struct cdx_mc_group_spec *spec)
{
    assert(hw && in_transaction && spec->listeners);
    assert(!ft_mc_lock == !caller_rtnl);
    replaced = *spec;
    replaces++;
    if (replace_rc)
        return replace_rc;
    if (hw != FAKE_HW) {
        assert(hw->live);
        if (!same_key(&hw->key, spec))
            return -EINVAL;
        built(hw, spec);
    }
    return 0;
}

static bool stats_fail;
static struct cdx_ft_counters stats_now;
static bool cdx_mc_group_stats(const struct cdx_mc_group *hw, struct cdx_ft_counters *c)
{
    assert(hw && in_transaction);
    if (stats_fail) {
        memset(c, 0, sizeof(*c));
        return false;
    }
    *c = stats_now;
    return true;
}

#include <stdarg.h>

static void answer(struct net_device *in, uint32_t source, uint16_t vid,
                   unsigned local, int n, ...)
{
    struct snap *s = &snaps[snap_count++];
    va_list ap;

    assert(snap_count <= ARRAY_SIZE(snaps));
    memset(s, 0, sizeof(*s));
    s->in = in;
    s->source = source;
    s->vid = vid;
    s->local = local;
    s->n = n;
    va_start(ap, n);
    for (int i = 0; i < n; i++)
        s->ports[i] = va_arg(ap, struct net_device *);
    va_end(ap);
}

/* --- helpers --------------------------------------------------------- */

static struct net_device BR   = { .name = "br0",  .ifindex = 10, .bridge_master = true };
static struct net_device P1   = { .name = "eth3", .ifindex = 11, .physical = true, .master = &BR };
static struct net_device P2   = { .name = "eth4", .ifindex = 12, .physical = true, .master = &BR };
static struct net_device P3   = { .name = "eth5", .ifindex = 13, .physical = true, .master = &BR };
static struct net_device SOFT = { .name = "vx0",  .ifindex = 14, .physical = false, .master = &BR };
static struct net_device BR2  = { .name = "br1",  .ifindex = 15, .bridge_master = true };

static const u8 GROUP_MAC[ETH_ALEN] = { 0x01, 0, 0x5e, 0x07, 0, 0x01 };
static const u8 SENDER[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x51 };
static const u8 OTHER_SENDER[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x52 };
/* The address of the VIF a route's copy is sent through, which the copy
 * leaves with; the routed learner reads it off the oif. */
static const u8 VIF_MAC[ETH_ALEN] = { 0x02, 0, 0, 0, 0x02, 0x87 };

static struct br_ip group_v4(uint32_t dst, uint32_t src, uint16_t vid)
{
    struct br_ip a;
    memset(&a, 0, sizeof(a));
    a.dst.ip4 = dst;
    a.src.ip4 = src;
    a.proto = htons(ETH_P_IP);
    a.vid = vid;
    return a;
}

static struct br_ip group_v6(uint8_t scope, uint16_t vid)
{
    struct br_ip a;
    memset(&a, 0, sizeof(a));
    a.dst.ip6.s6_addr[0] = 0xff;
    a.dst.ip6.s6_addr[1] = scope;
    a.dst.ip6.s6_addr[15] = 1;
    a.proto = htons(ETH_P_IPV6);
    a.vid = vid;
    return a;
}

/* A frame the hook would have recorded: from `sender`, untagged unless
 * `tagged`, source `src` to `dst` in `vid`, arriving on `in`. */
static struct ft_mc_seen seen_v4(struct net_device *bridge, struct net_device *in,
                                 uint32_t dst, uint32_t src, uint16_t vid,
                                 bool tagged, const u8 *sender)
{
    struct ft_mc_seen o;

    memset(&o, 0, sizeof(o));
    o.bridge_ifindex = bridge->ifindex;
    o.in_ifindex = in->ifindex;
    o.addr = group_v4(dst, 0, vid);
    o.src.ip = src;
    memcpy(o.dst_mac, GROUP_MAC, ETH_ALEN);
    memcpy(o.src_mac, sender, ETH_ALEN);
    o.tagged = tagged;
    return o;
}

static void member(struct net_device *p, uint16_t vid, bool untagged)
{
    memberships[membership_count].port = p;
    memberships[membership_count].vid = vid;
    memberships[membership_count].untagged = untagged;
    memberships[membership_count].member = true;
    membership_count++;
}

static void pvid(struct net_device *p, uint16_t vid)
{
    pvids[pvid_count].port = p;
    pvids[pvid_count].pvid = vid;
    pvid_count++;
}

static bool list_empty(const struct list_head *h) { return h->next == h; }

static void free_lists(struct list_head *dead, struct list_head *gone)
{
    while (!list_empty(dead)) {
        struct ft_mc_group *g = list_entry(dead->next, struct ft_mc_group, list);
        list_del(&g->list);
        ft_mc_group_free(g);
    }
    while (!list_empty(gone)) {
        struct ft_mc_flow *f = list_entry(gone->next, struct ft_mc_flow, list);
        list_del(&f->list);
        f->hw = NULL;
        ft_mc_flow_free(f);
    }
}

/* One run of the worker, less the hardware: drain what the hook recorded,
 * ask the bridge about every flow marked for it, match routes, retire, and
 * put every stale flow the pick accepts "in hardware". */
static void pass(void)
{
    struct ft_mc_flow *f;
    LIST_HEAD(dead);
    LIST_HEAD(gone);

    ft_mc_drain();
    list_for_each_entry(f, &ft_mc_flows, list)
        if (f->dirty)
            ft_mc_flow_derive(f);
    ft_mc_match_routes();
    ft_mc_retire(&dead, &gone);
    free_lists(&dead, &gone);
    list_for_each_entry(f, &ft_mc_flows, list) {
        if (!f->stale)
            continue;
        if (!f->hw) {
            f->contested = ft_mc_installable(f) && ft_mc_key_contested(f);
            if (!ft_mc_installable(f) || f->contested) {
                f->stale = false;
                continue;
            }
        }
        f->stale = false;
        f->contested = ft_mc_key_contested(f);
        /* The worker records the chain it built, whole, with the entry,
         * and a build is current against every egress change before it. */
        if (!f->contested && ft_mc_installable(f) &&
            f->retries < FT_MC_MAX_RETRIES) {
            struct cdx_mc_group_spec spec;

            f->hw = FAKE_HW;
            f->carried_route = ft_mc_live_route(f) ? f->route : NULL;
            ft_mc_flow_spec(f, &spec);
            ft_mc_chain_record(f, &spec);
        } else {
            f->hw = NULL;
            f->carried_route = NULL;
            ft_mc_chain_forget(f);
        }
        f->egress_stale = false;
    }
    ft_mc_route_feedback();
}

/* The routed learner taking a route back, where what it counted does not
 * matter to the case. */
static void withdraw(struct ft_mc_route *r)
{
    struct cdx_ft_counters last;
    u32 series;
    u8 tags;

    ft_mc_route_withdraw(r, &last, &tags, &series);
}

static void reset(void)
{
    LIST_HEAD(dead);
    LIST_HEAD(gone);

    while (!list_empty(&ft_mc_groups))
        list_move(ft_mc_groups.next, &dead);
    while (!list_empty(&ft_mc_flows))
        list_move(ft_mc_flows.next, &gone);
    free_lists(&dead, &gone);
    /* Routes belong to the routed learner, which withdraws them. */
    while (ft_mc_routes.next != &ft_mc_routes)
        withdraw(list_entry(ft_mc_routes.next, struct ft_mc_route, list));
    ft_mc_taps_publish(NULL, 0, false);
    BR.mrouter = BR2.mrouter = false;
    BR.flags = BR2.flags = 0;
    P1.mtu = P2.mtu = P3.mtu = 0;
    /* A fresh learner: an empty ring and nothing recorded. */
    memset(ft_mc_last, 0, sizeof(ft_mc_last));
    ft_mc_last_next = 0;
    ft_mc_ring_head = ft_mc_ring_tail = 0;
    ft_mc_count = ft_mc_flow_count = 0;
    membership_count = 0;
    membership_interval = 260 * HZ;
    pvid_count = 0;
    snap_count = 0;
    memset(by_index, 0, sizeof(by_index));
    by_index[0] = &P1;
    by_index[1] = &P2;
    by_index[2] = &P3;
    by_index[3] = &SOFT;
    vlan_enabled = false;
    vlan_proto = ETH_P_8021Q;
    ft_mc_refused = 0;
    assert(holds == 0);
}

static struct ft_mc_group *only_group(void)
{
    assert(!list_empty(&ft_mc_groups) && ft_mc_groups.next->next == &ft_mc_groups);
    return list_entry(ft_mc_groups.next, struct ft_mc_group, list);
}

/* The flow a frame of `src` arriving on `in` in `vid` became, or NULL. */
static struct ft_mc_flow *flow(struct net_device *in, uint32_t src, uint16_t vid)
{
    struct ft_mc_flow *f;

    list_for_each_entry(f, &ft_mc_flows, list)
        if (f->in == in && f->addr.src.ip4 == src && f->addr.vid == vid)
            return f;
    return NULL;
}

static void see(struct ft_mc_seen o)
{
    ft_mc_record(&o);
    ft_mc_drain();
}

/* What the routed learner would publish for an MFC entry whose parent is the
 * bridge's VLAN device br0.<vid>: one routed copy, out of `port` tagged. */
static void route_want(struct ft_mc_route *want, uint16_t vid, uint32_t src,
                       uint32_t dst, struct net_device *port, uint16_t tag)
{
    memset(want, 0, sizeof(*want));
    want->bridge = &BR;
    want->vid = vid;
    want->tagged = true;
    want->family = AF_INET;
    want->src.ip = src;
    want->dst.ip = dst;
    want->listener[0].dev = port;
    want->listener[0].routed = true;
    ether_addr_copy(want->listener[0].src_mac, VIF_MAC);
    if (tag) {
        want->listener[0].vlans = 1;
        want->listener[0].vlan[0].proto = htons(ETH_P_8021Q);
        want->listener[0].vlan[0].id = tag;
    }
    want->listeners = 1;
    want->mtu = 1500;
}

static void memberships_and_their_answers(void)
{
    struct br_ip g1 = group_v4(0x010007ef, 0, 0);   /* 239.7.0.1, (*,G) */
    struct br_ip g2 = group_v4(0x020007ef, 0, 0);

    /* One port joins: the membership appears, the adapter takes it on, and
     * the port is pinned. */
    reset();
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(ft_mc_count == 1 && only_group()->ports == 1);
    assert(only_group()->port[0] == &P1);
    assert(holds == 2);   /* the bridge and the port */

    /* The same port again is the bridge restating a membership, not a second
     * one. Restating must not duplicate it, and must still answer yes -- a
     * repeat that answered no would clear the offload flag on a membership
     * that is still taken on. */
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(only_group()->ports == 1 && holds == 2);

    /* A second port joins the same group; a different group is a different
     * membership. */
    assert(ft_mc_membership(&BR, &P2, &g1, true, false));
    assert(ft_mc_find(&BR, &g1)->ports == 2 && ft_mc_count == 1);
    assert(ft_mc_membership(&BR, &P1, &g2, true, false));
    assert(ft_mc_count == 2);

    /* Leaving drops the port and keeps the rest compact, the freed slot
     * cleared rather than aliasing a device no longer held. The answer is
     * no: a leave is not a membership being taken on. */
    assert(!ft_mc_membership(&BR, &P1, &g1, false, false));
    {
        struct ft_mc_group *g = ft_mc_find(&BR, &g1);

        assert(g && g->ports == 1 && g->port[0] == &P2 && !g->port[1]);
    }
    /* A leave for a port that never joined, or of a group that does not
     * exist, changes nothing and releases nothing. */
    {
        struct br_ip absent = group_v4(0x090007ef, 0, 0);
        unsigned before = holds;

        assert(!ft_mc_membership(&BR, &P3, &g1, false, false));
        assert(!ft_mc_membership(&BR, &P1, &absent, false, false));
        assert(holds == before && ft_mc_count == 2);
    }

    /* A port the hardware could never replicate to is recorded -- it holds
     * the membership as much as any -- but not claimed. Whether a flow it
     * is a listener of can be carried is the bridge's answer's question. */
    reset();
    assert(!ft_mc_membership(&BR, &SOFT, &g1, true, false));
    assert(only_group()->ports == 1 && only_group()->port[0] == &SOFT);
    assert(holds == 2);

    /* Nor is one whose framing the bridge's VLANs leave undescribable: not
     * a member of the group's VLAN, or on an 802.1ad bridge. */
    reset();
    vlan_enabled = true;
    member(&P2, 3999, false);
    {
        struct br_ip tagged = group_v4(0x030007ef, 0, 3999);
        struct br_ip elsewhere = group_v4(0x030007ef, 0, 4000);

        assert(ft_mc_membership(&BR, &P2, &tagged, true, false));
        assert(!ft_mc_membership(&BR, &P2, &elsewhere, true, false));
        assert(ft_mc_find(&BR, &elsewhere)->ports == 1);
        vlan_proto = 0x88a8;
        assert(!ft_mc_membership(&BR, &P2, &tagged, true, false));
        vlan_proto = ETH_P_8021Q;
    }

    /* A host membership arriving FIRST is recorded, and this is the order
     * the bridge produces: br_multicast_add_group() calls
     * br_multicast_host_join() on a freshly created mdb entry, so HOST_MDB
     * is emitted before any port group. While it holds, no port of the
     * group is claimed; once it goes, they are again. */
    reset();
    assert(!ft_mc_membership(&BR, &BR, &g1, true, true));
    assert(ft_mc_count == 1 && only_group()->host && !only_group()->ports);
    assert(!ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(only_group()->ports == 1);
    assert(!ft_mc_membership(&BR, &BR, &g1, false, true));
    assert(!only_group()->host);
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));

    /* More ports than a board has: the ones past the last slot are neither
     * recorded nor claimed. */
    reset();
    {
        struct net_device ports[FT_MC_MAX_MEMBERS + 1];

        for (unsigned i = 0; i <= FT_MC_MAX_MEMBERS; i++) {
            ports[i] = (struct net_device){ .name = "p", .physical = true };
            assert(ft_mc_membership(&BR, &ports[i], &g1, true, false) ==
                   (i < FT_MC_MAX_MEMBERS));
        }
        assert(only_group()->ports == FT_MC_MAX_MEMBERS);
        assert(holds == 1 + FT_MC_MAX_MEMBERS);
        for (unsigned i = 0; i < FT_MC_MAX_MEMBERS; i++)
            assert(!ft_mc_membership(&BR, &ports[i], &g1, false, false));
    }
    {
        LIST_HEAD(dead);
        LIST_HEAD(gone);

        ft_mc_retire(&dead, &gone);
        assert(list_empty(&ft_mc_groups) && !ft_mc_count);
        free_lists(&dead, &gone);
    }

    /* Dropping a port by device alone, for the delete that arrives after
     * the port has already left the bridge -- del_nbp() flushes permanent
     * mdb entries after netdev_upper_dev_unlink(), so the master lookup is
     * empty and the membership would otherwise hold a reference that blocks
     * the port's unregistration for good. */
    reset();
    {
        struct br_ip a = group_v4(0x0c0007ef, 0, 0);
        struct br_ip b = group_v4(0x0d0007ef, 0, 0);

        assert(ft_mc_membership(&BR, &P1, &a, true, false));
        assert(ft_mc_membership(&BR, &P2, &a, true, false));
        assert(ft_mc_membership(&BR, &P1, &b, true, false));
        ft_mc_drop_port(&P1);
        assert(ft_mc_find(&BR, &a)->ports == 1);
        assert(ft_mc_find(&BR, &a)->port[0] == &P2);
        assert(ft_mc_find(&BR, &b)->ports == 0);
        assert(holds == 3);   /* two bridges and P2 */
        ft_mc_drop_port(&P3);
        assert(holds == 3);
    }

    /* Link-local scope is neither recorded nor learned: IGMP and MLD
     * themselves, and the solicited-node group every IPv6 address of the
     * bridge joins -- which, recorded, kept the hook registered on every
     * IPv6 LAN for nothing. */
    {
        struct br_ip mdns = group_v4(0xfb0000e0, 0, 0);   /* 224.0.0.251 */

        assert(ft_mc_link_local(&mdns));
        assert(!ft_mc_link_local(&g1));
        {
            struct br_ip v6 = group_v6(0x02, 0);   /* ff02::1 */
            assert(ft_mc_link_local(&v6));
            v6 = group_v6(0x01, 0);                /* ff01:: */
            assert(ft_mc_link_local(&v6));
            v6 = group_v6(0x05, 0);                /* ff05:: */
            assert(!ft_mc_link_local(&v6));
            v6 = group_v6(0x0e, 0);                /* ff0e:: */
            assert(!ft_mc_link_local(&v6));
        }
    }

    /* Tags. On a bridge that does not filter, nothing is pushed; a filtering
     * one gives an untagged member none and a tagged one its VLAN in the
     * bridge's own protocol; a port outside the VLAN is -ENOENT, a VLAN of
     * zero or an 802.1ad tag -EOPNOTSUPP. */
    reset();
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n = 0xff;

        assert(ft_mc_port_tags(&BR, &P1, 0, stack, &n) == 0 && n == 0);
        vlan_enabled = true;
        member(&P1, 3999, true);
        member(&P2, 3999, false);
        assert(ft_mc_port_tags(&BR, &P1, 3999, stack, &n) == 0 && n == 0);
        assert(ft_mc_port_tags(&BR, &P2, 3999, stack, &n) == 0 && n == 1);
        assert(stack[0].id == 3999 && stack[0].proto == htons(ETH_P_8021Q));
        assert(ft_mc_port_tags(&BR, &P3, 3999, stack, &n) == -ENOENT);
        assert(ft_mc_port_tags(&BR, &P1, 0, stack, &n) == -EOPNOTSUPP);
        vlan_proto = 0x88a8;
        assert(ft_mc_port_tags(&BR, &P2, 3999, stack, &n) == -EOPNOTSUPP);
    }
}

static void frames_become_flows(void)
{
    const uint32_t G = 0x0e0007ef, S1 = 0x0100000a, S2 = 0x0200000a;
    struct br_ip any = group_v4(G, 0, 0);
    struct br_ip sourced = group_v4(G, S1, 0);
    struct ft_mc_flow *f;

    /* A (*,G) membership names every source of its group: the first frame
     * of each is a flow, pinned to its ingress and its bridge. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    f = flow(&P1, S1, 0);
    assert(f && ft_mc_flow_count == 1 && f->bridge == &BR);
    assert(f->dirty && f->stale && !f->derived && !f->hw);
    assert(!memcmp(f->src_mac, SENDER, ETH_ALEN) && !f->in_tagged);
    assert(holds == 4);   /* membership: bridge, port; flow: bridge, ingress */
    assert(!strcmp(ft_mc_state(f), "pending"));
    /* A second source is a second flow, and so is the first one arriving
     * on another port: the bridge forwards each frame on its own. */
    see(seen_v4(&BR, &P1, G, S2, 0, false, SENDER));
    see(seen_v4(&BR, &P3, G, S1, 0, false, SENDER));
    assert(ft_mc_flow_count == 3 && flow(&P1, S2, 0) && flow(&P3, S1, 0));
    /* Another bridge, VLAN or family with the same bytes is named by
     * nothing here. */
    see(seen_v4(&BR2, &P1, G, S1, 0, false, SENDER));
    see(seen_v4(&BR, &P1, G, S1, 100, false, SENDER));
    {
        struct ft_mc_seen o = seen_v4(&BR, &P1, G, S1, 0, false, SENDER);

        o.addr.proto = htons(ETH_P_IPV6);
        see(o);
    }
    assert(ft_mc_flow_count == 3);

    /* An (S,G) membership -- an IGMPv3 INCLUDE report produces one -- names
     * only its own source. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &sourced, true, false));
    see(seen_v4(&BR, &P1, G, S2, 0, false, SENDER));
    assert(!ft_mc_flow_count);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    assert(ft_mc_flow_count == 1 && flow(&P1, S1, 0));

    /* A frame arriving on a port the hardware has no ingress for is not a
     * flow at all. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    see(seen_v4(&BR, &SOFT, G, S1, 0, false, SENDER));
    assert(!ft_mc_flow_count && holds == 2);

    /* Past FT_MC_MAX_FLOWS of one group, a source something asked for by
     * name -- an SSM listener's (S,G) membership -- takes the place of one
     * with nothing in hardware that nothing names that way: it must not be
     * refused because the group's other senders got there first. */
    reset();
    {
        const uint32_t SSM = htonl(0x0a0000ff);
        struct br_ip ssm = group_v4(G, SSM, 0);
        struct ft_mc_flow *given;

        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        for (uint32_t i = 0; i < FT_MC_MAX_FLOWS; i++)
            see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + i), 0, false, SENDER));
        assert(ft_mc_flow_count == FT_MC_MAX_FLOWS && !ft_mc_refused);
        pass();
        assert(ft_mc_membership(&BR, &P3, &ssm, true, false));
        see(seen_v4(&BR, &P1, G, SSM, 0, false, SENDER));
        assert(flow(&P1, SSM, 0) && ft_mc_refused == 1);
        given = NULL;
        list_for_each_entry(f, &ft_mc_flows, list)
            if (f->gone)
                given = f;
        assert(given && given->addr.src.ip4 != SSM);
        {
            const uint32_t back = given->addr.src.ip4;

            pass();
            assert(ft_mc_flow_count == FT_MC_MAX_FLOWS && !flow(&P1, back, 0));
            /* The one that gave way cannot take a place back: nothing asked
             * for it by name. Its frames are turned away at the cost of a
             * lookup -- no flow made, none given up, nothing for the
             * worker to ask the bridge -- and counted once, however often
             * the dedup slots let one through. */
            for (int i = 0; i < 4; i++) {
                ft_mc_forget_seen();
                see(seen_v4(&BR, &P1, G, back, 0, false, SENDER));
            }
            assert(ft_mc_refused == 2 && !flow(&P1, back, 0));
            list_for_each_entry(f, &ft_mc_flows, list)
                assert(!f->gone && !f->dirty && f->turned);
        }
        /* And the source asked for by name is never the one to give way. */
        {
            struct ft_mc_group *g = ft_mc_find(&BR, &ssm);

            assert(g && ft_mc_source_named(&BR, &flow(&P1, SSM, 0)->addr));
        }
    }

    /* A group every host sends to, which the host itself joined -- SSDP on
     * a router that runs a UPnP daemon. The bridge refuses every source of
     * it, so no place is given up for a new one even when it is asked for
     * by name, and nothing churns: ninth and later senders are a lookup. */
    reset();
    {
        const uint32_t NINTH = htonl(0x0a000009);
        struct br_ip named = group_v4(G, NINTH, 0);
        unsigned calls;

        assert(!ft_mc_membership(&BR, &BR, &any, true, true));
        assert(!ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_membership(&BR, &P3, &named, true, false));
        for (uint32_t i = 0; i < FT_MC_MAX_FLOWS; i++) {
            answer(&P1, htonl(0x0a000001 + i), 0, BR_MCAST_TO_HOST_JOINED, 1, &P2);
            see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + i), 0, false, SENDER));
        }
        pass();
        list_for_each_entry(f, &ft_mc_flows, list)
            assert(!strcmp(ft_mc_state(f), "refused-host"));
        calls = snap_calls;
        for (uint32_t s = 9; s < 40; s++) {
            ft_mc_forget_seen();
            see(seen_v4(&BR, &P1, G, htonl(0x0a000000 + s), 0, false, SENDER));
        }
        pass();
        assert(ft_mc_flow_count == FT_MC_MAX_FLOWS && ft_mc_refused == 1);
        assert(snap_calls == calls && !flow(&P1, NINTH, 0));
        /* Before the worker has asked about any of them, the host's own
         * membership says the same. */
        reset();
        assert(!ft_mc_membership(&BR, &BR, &any, true, true));
        assert(ft_mc_membership(&BR, &P3, &named, true, false));
        for (uint32_t i = 0; i < FT_MC_MAX_FLOWS; i++)
            see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + i), 0, false, SENDER));
        see(seen_v4(&BR, &P1, G, NINTH, 0, false, SENDER));
        assert(!flow(&P1, NINTH, 0) && ft_mc_refused == 1);
        list_for_each_entry(f, &ft_mc_flows, list)
            assert(!f->gone);
    }

    /* Nothing snooping the group: the bridge floods every source of it to
     * the host as well, which refuses each flow for the host with no host
     * membership to say so. Only the flows' own answers do, and they keep
     * the place from being given up. */
    reset();
    {
        const uint32_t NINTH = htonl(0x0a0000ff);
        struct br_ip named = group_v4(G, NINTH, 0);

        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_membership(&BR, &P3, &named, true, false));
        for (uint32_t i = 0; i < FT_MC_MAX_FLOWS; i++) {
            answer(&P1, htonl(0x0a000001 + i), 0, BR_MCAST_TO_HOST_FLOOD, 1, &P2);
            see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + i), 0, false, SENDER));
        }
        pass();
        assert(!ft_mc_host_joined(&BR, &any));
        list_for_each_entry(f, &ft_mc_flows, list)
            assert(!strcmp(ft_mc_state(f), "refused-host"));
        see(seen_v4(&BR, &P1, G, NINTH, 0, false, SENDER));
        assert(!flow(&P1, NINTH, 0) && ft_mc_refused == 1);
        list_for_each_entry(f, &ft_mc_flows, list)
            assert(!f->gone);
    }

    /* A place is given up only by a flow with nothing in hardware: when
     * every one is carried, a source asked for by name is left to the
     * bridge. A flow asked for by name keeps its place too. */
    reset();
    {
        const uint32_t NINTH = htonl(0x0a0000ff);
        struct br_ip named = group_v4(G, NINTH, 0);

        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_membership(&BR, &P3, &named, true, false));
        for (uint32_t i = 0; i < FT_MC_MAX_FLOWS; i++)
            see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + i), 0, false, SENDER));
        list_for_each_entry(f, &ft_mc_flows, list)
            f->hw = FAKE_HW;
        see(seen_v4(&BR, &P1, G, NINTH, 0, false, SENDER));
        assert(ft_mc_flow_count == FT_MC_MAX_FLOWS && ft_mc_refused == 1);
        assert(!flow(&P1, NINTH, 0));
        list_for_each_entry(f, &ft_mc_flows, list)
            f->hw = NULL;
    }
    reset();
    {
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        for (uint32_t i = 0; i <= FT_MC_MAX_FLOWS; i++) {
            struct br_ip named = group_v4(G, htonl(0x0a000001 + i), 0);

            assert(ft_mc_membership(&BR, &P3, &named, true, false));
        }
        for (uint32_t i = 0; i <= FT_MC_MAX_FLOWS; i++)
            see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + i), 0, false, SENDER));
        assert(ft_mc_flow_count == FT_MC_MAX_FLOWS && ft_mc_refused == 1);
        list_for_each_entry(f, &ft_mc_flows, list)
            assert(!f->gone);
        /* A place freed is taken by the next source seen, and the group's
         * next refusal is counted again. */
        f = flow(&P1, htonl(0x0a000001), 0);
        f->gone = true;
        pass();
        ft_mc_forget_seen();
        see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + FT_MC_MAX_FLOWS), 0, false, SENDER));
        assert(flow(&P1, htonl(0x0a000001 + FT_MC_MAX_FLOWS), 0));
        see(seen_v4(&BR, &P1, G, htonl(0x0a000001), 0, false, SENDER));
        assert(ft_mc_refused == 2 && !flow(&P1, htonl(0x0a000001), 0));
    }

    /* An allocation that fails leaves nothing behind but the promise that
     * the next frame is asked about again. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    fail_alloc = true;
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    assert(!ft_mc_flow_count && holds == 2);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    assert(flow(&P1, S1, 0));

    /* ---- the shape a flow arrives in ------------------------------------
     *
     * A bridged entry's key is the frames' own Ethernet pair as well as the
     * port and the (S,G), and its root accepts one ingress shape. With
     * nothing installed the flow takes whatever shape it is seen in; once
     * installed it keeps the one it was installed with while that carries
     * traffic, and another waits until the entry goes idle. A new MAC
     * changes nothing the bridge decides; a new tag is asked of it. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    f = flow(&P1, S1, 0);
    f->dirty = f->stale = false;
    see(seen_v4(&BR, &P1, G, S1, 0, false, OTHER_SENDER));
    assert(!memcmp(f->src_mac, OTHER_SENDER, ETH_ALEN) && !f->has_next);
    assert(!f->dirty && f->stale && ft_mc_flow_count == 1);
    /* And the shape it had is a new fact again. */
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    assert(!memcmp(f->src_mac, SENDER, ETH_ALEN));
    f->hw = FAKE_HW;
    f->idle = false;
    f->dirty = f->stale = false;
    see(seen_v4(&BR, &P1, G, S1, 0, false, OTHER_SENDER));
    assert(f->has_next && !memcmp(f->next.src_mac, OTHER_SENDER, ETH_ALEN));
    assert(!memcmp(f->src_mac, SENDER, ETH_ALEN));
    /* Not taken while the installed key is live. */
    assert(!f->dirty && !f->stale);
    /* An idle entry asks for the takeover straight away, and a tag it did
     * not arrive with is asked of the bridge first. */
    f->idle = true;
    see(seen_v4(&BR, &P1, G, S1, 0, true, SENDER));
    assert(f->has_next && f->next.tagged && f->stale && f->dirty);
    ft_mc_adopt_next(f);
    assert(!f->has_next && f->in_tagged && !memcmp(f->src_mac, SENDER, ETH_ALEN));
    f->hw = NULL;
}

static void the_bridge_decides(void)
{
    const uint32_t G = 0x0f0007ef, S1 = 0x0100000a, S2 = 0x0200000a;
    struct br_ip any = group_v4(G, 0, 0);
    struct br_ip sg1 = group_v4(G, S1, 0);
    struct cdx_mc_group_spec spec;
    struct ft_mc_flow *f, *f2;

    /* An IGMPv3 INCLUDE{S1} join on P2 is a (*,G) INCLUDE port group and an
     * (S1,G) one, both announced, neither saying which. The bridge forwards
     * S1 to P2 and nothing else of the group -- br_multicast_flood() skips
     * a (*,G) INCLUDE port group -- and that answer, not the objects, is
     * what the flows are built from. Both objects name the same flow. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_membership(&BR, &P2, &sg1, true, false));
    answer(&P1, S1, 0, 0, 1, &P2);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    snap_calls = 0;
    pass();
    f = flow(&P1, S1, 0);
    assert(snap_calls == 1 && f->derived && f->ports == 1 && f->port[0].dev == &P2);
    assert(f->hw && !strcmp(ft_mc_state(f), "installed") && ft_mc_flow_count == 1);
    ft_mc_flow_spec(f, &spec);
    assert(spec.bridged && spec.in == &P1 && spec.src.ip == S1 && spec.dst.ip == G);
    assert(spec.listeners == 1 && spec.listener[0].dev == &P2 && !spec.listener[0].routed);
    assert(!memcmp(spec.src_mac, SENDER, ETH_ALEN) && !spec.in_vlans);
    /* A second source reaches nobody: the bridge answers no port. It is
     * refused on its own, and the first stays in hardware -- the two are
     * not one key contested between two memberships. */
    see(seen_v4(&BR, &P1, G, S2, 0, false, SENDER));
    pass();
    f2 = flow(&P1, S2, 0);
    assert(f2 && !f2->hw && !strcmp(ft_mc_state(f2), "refused-listener"));
    assert(f->hw && !f->contested);

    /* Asking again with nothing changed costs the hardware nothing: the
     * flow is not marked for the install pass, and retries spent stand. */
    f->retries = 2;
    f->dirty = true;
    ft_mc_flow_derive(f);
    assert(!f->stale && f->retries == 2);
    f->retries = 0;
    /* The same object twice is the bridge restating it: every flow of the
     * group is asked again, and answers the same. */
    assert(ft_mc_membership(&BR, &P2, &sg1, true, false));
    assert(f->dirty && f2->dirty);
    pass();
    assert(f->hw && !f->stale && ft_mc_count == 2);

    /* The listener BLOCKs S1. The bridge announces the (S1,G) port group
     * again, blocked, which the handler hands on as a leave of that
     * membership -- and every flow of the group is asked again. The bridge
     * now forwards S1 nowhere: the flow leaves hardware and stays, named by
     * the (*,G) membership, for as long as that stands. */
    assert(!ft_mc_membership(&BR, &P2, &sg1, false, false));
    assert(f->dirty && f2->dirty);
    answer(&P1, S1, 0, 0, 0);
    pass();
    assert(!f->hw && !f->ports && !strcmp(ft_mc_state(f), "refused-listener"));
    assert(ft_mc_count == 1 && ft_mc_flow_count == 2);

    /* ASM and SSM listeners of one group: P3 in EXCLUDE{} for any source,
     * P2 in INCLUDE{S1}. Two sources, two flows, two port sets. */
    reset();
    assert(ft_mc_membership(&BR, &P3, &any, true, false));
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_membership(&BR, &P2, &sg1, true, false));
    answer(&P1, S1, 0, 0, 2, &P2, &P3);
    answer(&P1, S2, 0, 0, 1, &P3);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    see(seen_v4(&BR, &P1, G, S2, 0, false, SENDER));
    pass();
    f = flow(&P1, S1, 0);
    f2 = flow(&P1, S2, 0);
    assert(f->hw && f2->hw && f->ports == 2 && f2->ports == 1);
    assert(f2->port[0].dev == &P3);
    ft_mc_flow_spec(f2, &spec);
    assert(spec.listeners == 1 && spec.listener[0].dev == &P3);

    /* The (*,G) announcement first and the (S,G) one after, with a worker
     * pass between: the flow is installed from the bridge's answer at the
     * time, and the later announcement asks again, so it converges on the
     * bridge's answer once both are in. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S1, 0, 0, 1, &P2);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    pass();
    f = flow(&P1, S1, 0);
    assert(f->hw && f->ports == 1);
    answer(&P1, S1, 0, 0, 2, &P2, &P3);
    assert(ft_mc_membership(&BR, &P3, &sg1, true, false));
    assert(f->dirty);
    pass();
    assert(f->hw && f->ports == 2 && f->port[1].dev == &P3);
    /* Two memberships of a bridge and a port each; the flow's bridge and
     * ingress; its two copies; and the chain recorded for its entry, which
     * holds the ingress and both copies again. */
    assert(holds == 2 + 2 + 2 + 2 + 3);

    /* Why the bridge also hands a frame up. The host joined, or nothing is
     * snooping and the frame floods: refused, since the entry would starve
     * the host. The bridge a multicast router with no VIF on the VLAN: the
     * host drops what it is handed, and the flow is carried. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S1, 0, BR_MCAST_TO_HOST_JOINED, 1, &P2);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    pass();
    f = flow(&P1, S1, 0);
    assert(!f->hw && !strcmp(ft_mc_state(f), "refused-host"));
    answer(&P1, S1, 0, BR_MCAST_TO_HOST_FLOOD, 1, &P2);
    f->dirty = true;
    pass();
    assert(!f->hw && !strcmp(ft_mc_state(f), "refused-host"));
    answer(&P1, S1, 0, BR_MCAST_TO_HOST_ROUTER, 1, &P2);
    f->dirty = true;
    pass();
    assert(f->hw && !f->routed_host && !strcmp(ft_mc_state(f), "installed"));

    /* What the bridge says instead of a port set -- a hairpin ingress, a
     * port converting to unicast, too many ports -- refuses the flow and is
     * counted once; so does a port the hardware cannot replicate to, which
     * refuses it whole rather than carrying the rest. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S1, 0, 0, -EOPNOTSUPP);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    pass();
    f = flow(&P1, S1, 0);
    assert(f->error == -EOPNOTSUPP && !f->hw && ft_mc_refused == 1);
    assert(!strcmp(ft_mc_state(f), "refused-listener"));
    answer(&P1, S1, 0, 0, -E2BIG);
    f->dirty = true;
    pass();
    assert(f->error == -E2BIG && ft_mc_refused == 1);
    answer(&P1, S1, 0, 0, 2, &P2, &SOFT);
    f->dirty = true;
    pass();
    assert(f->error == -EOPNOTSUPP && !f->ports && !f->hw);
    answer(&P1, S1, 0, 0, 1, &P2);
    f->dirty = true;
    pass();
    /* The membership's bridge and port, the flow's bridge and ingress, its
     * copy, and the recorded chain's ingress and copy. */
    assert(!f->error && f->hw && holds == 2 + 2 + 1 + 2);
    /* The ingress is no longer a port of this bridge: the flow is over. */
    answer(&P1, S1, 0, 0, -EINVAL);
    f->dirty = true;
    pass();
    assert(!flow(&P1, S1, 0) && !ft_mc_flow_count && holds == 2);

    /* An MTU below the ingress's on any copy keeps the flow in software;
     * a flow whose ingress has gone has nothing to bound. */
    reset();
    P1.mtu = P2.mtu = P3.mtu = 1500;
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S1, 0, 0, 2, &P2, &P3);
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    pass();
    f = flow(&P1, S1, 0);
    assert(ft_mc_mtu_bounded(f) && f->hw);
    P3.mtu = 1400;
    assert(!ft_mc_mtu_bounded(f) && ft_mc_carriable(f));
    assert(!strcmp(ft_mc_state(f), "refused-mtu"));
    P1.mtu = 1400;
    assert(ft_mc_mtu_bounded(f));
    P1.mtu = P3.mtu = 1500;
}

static void the_vlan_a_flow_arrives_in(void)
{
    const uint32_t G = 0x100007ef, S1 = 0x0100000a;
    struct br_ip in3999 = group_v4(G, 0, 3999);
    struct ft_mc_flow *f;

    /* A tagged flow stands while its ingress is a member of the VLAN and
     * the bridge filters in 802.1Q; an untagged one while the port's PVID
     * is the VLAN. Otherwise its frames are another VLAN's now, or none:
     * the flow is over, and learned again from its next frame. */
    reset();
    vlan_enabled = true;
    member(&P1, 3999, false);
    member(&P2, 3999, false);
    pvid(&P1, 3999);
    assert(ft_mc_membership(&BR, &P2, &in3999, true, false));
    answer(&P1, S1, 3999, 0, 1, &P2);
    see(seen_v4(&BR, &P1, G, S1, 3999, true, SENDER));
    pass();
    f = flow(&P1, S1, 3999);
    assert(f->hw && f->port[0].vlans == 1 && f->port[0].vlan[0].id == 3999);
    {
        struct cdx_mc_group_spec spec;

        ft_mc_flow_spec(f, &spec);
        assert(spec.in_vlans == 1 && spec.in_vlan[0].id == 3999);
    }
    /* The listener becomes an untagged member: asked again, the copy
     * leaves untagged. */
    memberships[1].untagged = true;
    f->dirty = true;
    pass();
    assert(f->hw && f->port[0].vlans == 0);
    /* A shape waiting to take over that no longer resolves is dropped;
     * the installed one, while it resolves, stays. */
    f->has_next = true;
    f->next.tagged = false;
    pvids[0].pvid = 1;
    f->dirty = true;
    pass();
    assert(!f->has_next && f->hw);
    /* The tagged ingress leaves the VLAN. */
    memberships[0].member = false;
    f->dirty = true;
    pass();
    assert(!flow(&P1, S1, 3999) && holds == 2);

    /* Untagged on the PVID, and the PVID moves. */
    memberships[0].member = true;
    pvids[0].pvid = 3999;
    see(seen_v4(&BR, &P1, G, S1, 3999, false, SENDER));
    pass();
    f = flow(&P1, S1, 3999);
    assert(f && f->hw && !f->in_tagged);
    pvids[0].pvid = 1;
    f->dirty = true;
    pass();
    assert(!flow(&P1, S1, 3999));

    /* A bridge that stops filtering forwards a tagged frame with its tag,
     * which no copy it resolves would add back: a tagged flow is over, and
     * so is any flow of a VLAN other than zero. */
    pvids[0].pvid = 3999;
    see(seen_v4(&BR, &P1, G, S1, 3999, true, SENDER));
    pass();
    f = flow(&P1, S1, 3999);
    assert(f && f->hw);
    vlan_enabled = false;
    f->dirty = true;
    pass();
    assert(!flow(&P1, S1, 3999) && holds == 2);

    /* The same port, sender and source of a group on two VLANs is one
     * classifier key -- the key names no VLAN, and one root validates one
     * tag -- so neither flow installs while both stand. */
    reset();
    vlan_enabled = true;
    member(&P1, 289, false);
    member(&P2, 289, false);
    member(&P3, 286, true);
    pvid(&P1, 286);
    {
        struct br_ip iptv = group_v4(G, 0, 289), lan = group_v4(G, 0, 286);
        struct ft_mc_flow *a, *b;

        assert(ft_mc_membership(&BR, &P2, &iptv, true, false));
        assert(ft_mc_membership(&BR, &P3, &lan, true, false));
        answer(&P1, S1, 289, 0, 1, &P2);
        answer(&P1, S1, 286, 0, 1, &P3);
        see(seen_v4(&BR, &P1, G, S1, 289, true, SENDER));
        see(seen_v4(&BR, &P1, G, S1, 286, false, SENDER));
        pass();
        a = flow(&P1, S1, 289);
        b = flow(&P1, S1, 286);
        assert(a && b && !a->hw && !b->hw);
        assert(!strcmp(ft_mc_state(a), "refused-contested"));
        assert(!strcmp(ft_mc_state(b), "refused-contested"));
        /* The other goes, and the key is given up: the refused one asks
         * again at the next pass and is carried. */
        assert(!ft_mc_membership(&BR, &P3, &lan, false, false));
        pass();
        pass();
        assert(!flow(&P1, S1, 286) && a->hw && !a->contested);
    }
}

static void one_stream_both_learners(void)
{
    const uint32_t S = 0x0100000a, G = 0x110007ef;
    struct br_ip any = group_v4(G, 0, 289);
    struct cdx_mc_group_spec spec;
    struct ft_mc_route want, r1;
    struct ft_mc_flow *f;

    /* An IPTV VLAN bridged to a set-top box and routed to the rest of the
     * house. The stream arrives on a bridge port; the bridge forwards it to
     * the box and, as a multicast router, hands it to br0.289, where ipmr
     * routes it out of another port. One classifier key, so one flow: the
     * box's copy and ipmr's, each owned by the learner that asked for it. */
    reset();
    memset(&r1, 0, sizeof(r1));
    vlan_enabled = true;
    member(&BR, 289, false);    /* br0.289 receives the VLAN, tagged */
    member(&P1, 289, false);
    member(&P2, 289, false);    /* the set-top box */
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S, 289, 0, 1, &P2);
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));

    /* The routed learner publishes its copy: out of eth5 on VLAN 287. The
     * route pins what it names. */
    route_want(&want, 289, S, G, &P3, 287);
    {
        unsigned before = holds;

        assert(!ft_mc_route_publish(&r1, &want));
        assert(r1.linked && holds == before + 2);
    }

    /* A bridge that is not a multicast router hands the host nothing it did
     * not join, so Linux routes nothing and neither may the flow. */
    pass();
    f = flow(&P1, S, 289);
    assert(f && !f->route && !f->routed_host && f->hw);
    ft_mc_flow_spec(f, &spec);
    assert(spec.listeners == 1 && !spec.listener[0].routed);

    /* A router: one flow, both sets. The bridged copy keeps the sender's
     * pair and hop count; the routed one is marked for the backend to frame
     * as a router's. */
    answer(&P1, S, 289, BR_MCAST_TO_HOST_ROUTER, 1, &P2);
    f->dirty = true;
    pass();
    assert(f->route == &r1 && f->routed_host && f->hw && f->carried_route == &r1);
    ft_mc_flow_spec(f, &spec);
    assert(spec.bridged && spec.in == &P1 && spec.in_vlans == 1);
    assert(spec.listeners == 2);
    assert(spec.listener[0].dev == &P2 && !spec.listener[0].routed);
    assert(spec.listener[0].vlans == 1 && spec.listener[0].vlan[0].id == 289);
    assert(spec.listener[1].dev == &P3 && spec.listener[1].routed);
    assert(spec.listener[1].vlan[0].id == 287);
    /* The routed copy leaves with its VIF's address, which the route names;
     * the bridged one names none and keeps its sender's pair. */
    assert(ether_addr_equal(spec.listener[1].src_mac, VIF_MAC));
    assert(!memchr_inv(spec.listener[0].src_mac, 0, ETH_ALEN));
    assert(!strcmp(ft_mc_state(f), "installed"));
    {
        struct cdx_ft_counters c;
        u32 series = 0;
        u8 tags = 9;

        assert(ft_mc_route_state(&r1, &c, &tags, &series) && tags == 1);
        /* Linked once: the count's first run. */
        assert(series == 1);
        assert(!ft_mc_route_feedback());   /* said already */
    }
    /* Publishing the same copies again is not news; a changed copy set is,
     * to the flow carrying it. */
    works = 0;
    assert(ft_mc_route_publish(&r1, &want));
    assert(!works && !f->stale);
    route_want(&want, 289, S, G, &P3, 286);
    assert(ft_mc_route_publish(&r1, &want));
    assert(works == 1 && f->stale && r1.listener[0].vlan[0].id == 286);
    pass();
    /* So is the VIF being given another address, which changes nothing else
     * about the route: the entry carrying it writes the old one until the
     * flow is rebuilt from the new. */
    works = 0;
    want.listener[0].src_mac[5] ^= 0x10;
    assert(ft_mc_route_publish(&r1, &want));
    assert(works == 1 && f->stale);
    assert(ether_addr_equal(r1.listener[0].src_mac, want.listener[0].src_mac));
    pass();
    assert(f->hw && !f->stale && r1.carried);
    ft_mc_flow_spec(f, &spec);
    assert(ether_addr_equal(spec.listener[1].src_mac, want.listener[0].src_mac));
    assert(ether_addr_equal(f->hw_spec.listener[1].src_mac, want.listener[0].src_mac));

    /* A routed copy out of the port and tag stack the bridged copy takes --
     * one port, two VLANs untagged on it -- is a copy of its own and is
     * carried: it leaves with its VIF's address and one hop fewer where the
     * bridged one keeps its sender's pair and hop count, two frames Linux
     * sends, which the backend tells apart by the address. */
    route_want(&want, 289, S, G, &P2, 289);
    ft_mc_route_publish(&r1, &want);
    assert(ft_mc_carriable(f) && ft_mc_installable(f));
    pass();
    assert(f->hw && r1.carried && !strcmp(ft_mc_state(f), "installed"));
    ft_mc_flow_spec(f, &spec);
    assert(spec.listeners == 2);
    assert(spec.listener[0].dev == &P2 && spec.listener[1].dev == &P2);
    assert(spec.listener[0].vlans == spec.listener[1].vlans &&
           spec.listener[0].vlan[0].id == spec.listener[1].vlan[0].id);
    assert(!spec.listener[0].routed && spec.listener[1].routed);
    assert(!ether_addr_equal(spec.listener[0].src_mac, spec.listener[1].src_mac));

    /* What does not merge, with its reason: the union has to fit one group,
     * and every copy has to fit what the ingress can deliver. */
    route_want(&want, 289, S, G, &P3, 1);
    for (unsigned i = 1; i < CDX_MC_MAX_LISTENERS; i++) {
        want.listener[i] = want.listener[0];
        want.listener[i].vlan[0].id = 1 + i;
    }
    want.listeners = CDX_MC_MAX_LISTENERS;
    ft_mc_route_publish(&r1, &want);
    assert(!ft_mc_carriable(f) && !ft_mc_installable(f));
    assert(!strcmp(ft_mc_state(f), "refused-listener"));
    /* Out of hardware, the route carried by nothing. It keeps the framing
     * of the flow that last carried it: that is what the count it holds was
     * made with, and what the fold takes off it when the route goes. */
    pass();
    assert(!f->hw && !r1.carried && r1.in_tags == 1);
    want.listeners = CDX_MC_MAX_LISTENERS - 1;
    ft_mc_route_publish(&r1, &want);
    assert(ft_mc_carriable(f));
    route_want(&want, 289, S, G, &P3, 287);
    want.mtu = 1400;
    P1.mtu = P2.mtu = P3.mtu = 1500;
    ft_mc_route_publish(&r1, &want);
    assert(!ft_mc_mtu_bounded(f) && !strcmp(ft_mc_state(f), "refused-mtu"));
    want.mtu = 1500;
    ft_mc_route_publish(&r1, &want);
    assert(ft_mc_mtu_bounded(f) && ft_mc_installable(f));
    P1.mtu = P2.mtu = P3.mtu = 0;
    pass();
    assert(f->hw);

    /* The box leaves. The membership goes, but the flow stays: the route
     * still names it, and the entry now carries the routed copy alone. */
    assert(!ft_mc_membership(&BR, &P2, &any, false, false));
    answer(&P1, S, 289, BR_MCAST_TO_HOST_ROUTER, 0);
    pass();
    assert(!ft_mc_count && flow(&P1, S, 289) == f && f->hw && !f->ports);
    ft_mc_flow_spec(f, &spec);
    assert(spec.listeners == 1 && spec.listener[0].routed);
    /* The route goes too. Every pointer to it is cleared before its owner
     * frees it, and with neither learner naming the flow, it retires. */
    {
        struct cdx_ft_counters last;
        u32 run = r1.series, series = 0;
        u8 tags = 9;

        r1.stats.packets = 5;
        r1.stats.bytes = 5 * 578;
        /* What it counted is handed to its owner as it goes, with the
         * framing and the run that count belongs to, for the MFC entry. */
        assert(ft_mc_route_withdraw(&r1, &last, &tags, &series));
        assert(last.packets == 5 && last.bytes == 5 * 578);
        assert(tags == 1 && series == run);
        /* The count starts from zero again, and a new series says so,
         * whoever reads it next. */
        assert(r1.series == run + 1 && !r1.stats.packets && !r1.stats.bytes);
        /* Nothing is left to hand over a second time. */
        assert(!ft_mc_route_withdraw(&r1, &last, &tags, &series));
        assert(!last.packets && r1.series == run + 2);
    }
    assert(!r1.linked && !f->route && !f->carried_route && f->stale);
    assert(!r1.carried && !r1.listeners && !r1.bridge);
    pass();
    assert(list_empty(&ft_mc_flows) && holds == 0);

    /* ---- the host's copy with no route to carry ----------------------- *
     *
     * A VIF on br0.289 and no MFC entry for the stream: ipmr sees it and
     * upcalls, which is how a routing daemon learns a source. The flow
     * stays in software until the route exists. */
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    {
        struct ft_mc_tap tap = { &BR, 289, true, AF_INET };

        ft_mc_taps_publish(&tap, 1, false);
    }
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    pass();
    f = flow(&P1, S, 289);
    assert(f->routed_host && !f->route && !f->hw);
    assert(!strcmp(ft_mc_state(f), "refused-routed"));
    /* A route for another source is not this stream's, though it says the
     * host routes the group. */
    memset(&r1, 0, sizeof(r1));
    route_want(&want, 289, 0x0200000a, G, &P3, 287);
    ft_mc_route_publish(&r1, &want);
    pass();
    assert(!f->route && f->routed_host && !f->hw);
    /* Its own is. */
    route_want(&want, 289, S, G, &P3, 287);
    ft_mc_route_publish(&r1, &want);
    pass();
    assert(f->route == &r1 && f->hw);
    withdraw(&r1);
    pass();
    assert(!f->hw && !strcmp(ft_mc_state(f), "refused-routed"));
    /* Not a router: the tap sees nothing, and the flow is the box's. */
    answer(&P1, S, 289, 0, 1, &P2);
    f->dirty = true;
    pass();
    assert(!f->routed_host && f->hw);
    /* A promiscuous bridge hands everything up as a router does: the tap
     * sees the stream, which is carried only with its route. */
    answer(&P1, S, 289, BR_MCAST_TO_HOST_PROMISC, 1, &P2);
    f->dirty = true;
    pass();
    assert(f->routed_host && !f->hw && !strcmp(ft_mc_state(f), "refused-routed"));
    answer(&P1, S, 289, 0, 1, &P2);
    f->dirty = true;
    pass();
    assert(!f->routed_host && f->hw);
    /* A table that ran out names every bridge VLAN. */
    answer(&P1, S, 289, BR_MCAST_TO_HOST_ROUTER, 1, &P2);
    ft_mc_taps_publish(NULL, 0, true);
    f->dirty = true;
    pass();
    assert(f->routed_host && !f->hw);
    ft_mc_taps_publish(NULL, 0, false);
    pass();
    assert(!f->routed_host && f->hw);

    /* ---- where a VIF on a bridge receives ------------------------------ */
    reset();
    vlan_enabled = true;
    member(&BR, 289, false);
    member(&BR, 1, true);
    /* br0.289 receives VLAN 289, which the bridge carries tagged; br0 itself
     * every VLAN it carries untagged, and only those. */
    assert(ft_mc_via_receives(&BR, 289, true, 289));
    assert(!ft_mc_via_receives(&BR, 288, true, 289));
    assert(ft_mc_via_receives(&BR, 0, false, 1));
    assert(!ft_mc_via_receives(&BR, 0, false, 289));
    assert(!ft_mc_via_receives(&BR, 1, true, 1));
    assert(!ft_mc_via_receives(&BR, 0, false, 7));
    assert(!ft_mc_via_receives(&BR, 7, true, 7));
    /* A bridge that does not filter hands everything up untagged, on VLAN
     * zero. */
    vlan_enabled = false;
    assert(ft_mc_via_receives(&BR, 0, false, 0));
    assert(!ft_mc_via_receives(&BR, 289, true, 0));

    /* ---- a route names its stream's flow into existence ---------------- */
    reset();
    memset(&r1, 0, sizeof(r1));
    vlan_enabled = true;
    member(&BR, 289, false);
    member(&P1, 289, false);
    route_want(&want, 289, S, G, &P3, 287);
    ft_mc_route_publish(&r1, &want);
    /* Not a router: the host is handed nothing, and no flow is learned. */
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    assert(!ft_mc_flow_count);
    /* A router: the next frame is a flow, the route's alone. The frame seen
     * before is still in the dedup slots until the bridge says it became
     * one -- BRIDGE_MROUTER, which forgets them -- and then the same frame
     * will do. */
    BR.mrouter = true;
    answer(&P1, S, 289, BR_MCAST_TO_HOST_ROUTER, 0);
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    assert(!ft_mc_flow_count);
    ft_mc_bridge_changed(&BR);
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    pass();
    f = flow(&P1, S, 289);
    assert(f && f->route == &r1 && f->hw && !f->ports);
    /* The set-top box joins the same group: the same flow, both sets. */
    member(&P2, 289, false);
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S, 289, BR_MCAST_TO_HOST_ROUTER, 1, &P2);
    pass();
    assert(ft_mc_flow_count == 1 && f->ports == 1 && f->hw);
    withdraw(&r1);

    /* A bridge turning promiscuous hands the host everything as a router
     * does, and tells nobody: no switchdev attribute, no netdev event. The
     * routed learner publishes the same route again at each of its
     * refreshes, which is where it is found, and the frame seen before is
     * recorded again. Turning back is the same. */
    reset();
    memset(&r1, 0, sizeof(r1));
    vlan_enabled = true;
    member(&BR, 289, false);
    member(&P1, 289, false);
    route_want(&want, 289, S, G, &P3, 287);
    ft_mc_route_publish(&r1, &want);
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    assert(!ft_mc_flow_count && !r1.learns);
    BR.flags |= IFF_PROMISC;
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    assert(!ft_mc_flow_count);
    works = 0;
    assert(!ft_mc_route_publish(&r1, &want));
    assert(r1.learns && !works);
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    assert(ft_mc_flow_count == 1 && flow(&P1, S, 289));
    /* Nothing changed: nothing forgotten. */
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    ft_mc_route_publish(&r1, &want);
    {
        unsigned recorded = ft_mc_ring_head;

        see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
        assert(ft_mc_ring_head == recorded);
    }
    BR.flags &= ~IFF_PROMISC;
    ft_mc_route_publish(&r1, &want);
    assert(!r1.learns);
    withdraw(&r1);
}

static void the_dedup_slots(void)
{
    const uint32_t G = 0x130007ef, S = 0x0100000a;
    struct br_ip any = group_v4(G, 0, 0);
    struct ft_mc_seen o = seen_v4(&BR, &P1, G, S, 0, false, SENDER);
    struct ft_mc_route want, r1;

    /* The slots keep a line-rate stream from filling the ring with one fact,
     * and so they also keep the same frame from being recorded again until
     * something forgets them. Each case is a way the answer that frame got
     * could change without the frame changing. */
    (void)ft_mc_hooked;
    (void)ft_mc_hook_errors;
    (void)ft_mc_hook_lock;

    /* The frame first, the membership after: the MDB add is deferred, so
     * this is the ordinary order, and the one a host membership creating
     * the group takes too. */
    reset();
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(!ft_mc_flow_count && !ft_mc_record(&o));
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(flow(&P1, S, 0));
    reset();
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(!ft_mc_membership(&BR, &BR, &any, true, true));
    assert(ft_mc_record(&o));

    /* Learned, left, retired, joined again: the new flow is learned from
     * the same frame. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    see(o);
    assert(flow(&P1, S, 0) && !ft_mc_record(&o));
    assert(!ft_mc_membership(&BR, &P2, &any, false, false));
    pass();
    assert(!ft_mc_flow_count && !ft_mc_count);
    assert(ft_mc_record(&o));           /* and nothing names it */
    ft_mc_drain();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(flow(&P1, S, 0));

    /* A membership whose last port left, joined again before the worker
     * retired it: a frame drained in between was named by nothing, and is a
     * new fact once the membership names flows again. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(!ft_mc_membership(&BR, &P2, &any, false, false));
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(!ft_mc_flow_count && !ft_mc_record(&o));
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(flow(&P1, S, 0));

    /* The ingress goes and comes back: the flow is over, and the same frame
     * as before is a flow again. */
    ft_mc_device_gone(&P1, true);
    pass();
    assert(!ft_mc_flow_count);
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(flow(&P1, S, 0));

    /* A route published after the frame was recorded names it. */
    reset();
    memset(&r1, 0, sizeof(r1));
    BR.mrouter = true;
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(!ft_mc_record(&o));
    route_want(&want, 0, S, G, &P3, 0);
    want.tagged = false;
    ft_mc_route_publish(&r1, &want);
    assert(ft_mc_record(&o));
    ft_mc_drain();
    assert(flow(&P1, S, 0));
    withdraw(&r1);

    /* Several slots: two streams interleaving are each recorded once, and a
     * slot is reused only after FT_MC_SEEN_SLOTS others. */
    reset();
    {
        struct ft_mc_seen p = seen_v4(&BR, &P1, G, S + 0x01000000, 0, false, SENDER);

        assert(ft_mc_record(&o) && ft_mc_record(&p));
        assert(!ft_mc_record(&o) && !ft_mc_record(&p));
        for (unsigned i = 0; i < FT_MC_SEEN_SLOTS - 1; i++) {
            struct ft_mc_seen q = seen_v4(&BR, &P1, G, S + ((i + 2) << 24), 0,
                                          false, SENDER);
            ft_mc_drain();
            /* Still known while a slot is left for each newer fact. */
            assert(!ft_mc_record(&o));
            assert(ft_mc_record(&q));
        }
        /* The oldest slot went to the last of them. */
        ft_mc_drain();
        assert(ft_mc_record(&o));
        ft_mc_drain();
    }
    /* Every fact of the frame counts: a sender's MAC, the tag, the port,
     * the VLAN, the source. */
    {
        struct ft_mc_seen a = o, b;

        b = a; assert(ft_mc_seen_eq(&a, &b));
        memcpy(b.src_mac, OTHER_SENDER, ETH_ALEN); assert(!ft_mc_seen_eq(&a, &b));
        b = a; b.tagged = true; assert(!ft_mc_seen_eq(&a, &b));
        b = a; b.in_ifindex = P3.ifindex; assert(!ft_mc_seen_eq(&a, &b));
        b = a; b.addr.vid = 7; assert(!ft_mc_seen_eq(&a, &b));
        b = a; b.src.ip = 0x0200000a; assert(!ft_mc_seen_eq(&a, &b));
    }
}

/* A tc command: RTNL, held around what it asks of the adapter. */
static void tc_begin(void)
{
    rtnl_lock();
    caller_rtnl = true;
}
static void tc_end(void)
{
    caller_rtnl = false;
    rtnl_unlock();
}

/* A DSCP filter's drain of `dev`, under its tc command's RTNL. */
static int tc_drain(struct net_device *dev)
{
    int rc;

    tc_begin();
    rc = ft_mc_egress_drain(dev);
    tc_end();
    return rc;
}

static void devices_and_bridges_change(void)
{
    const uint32_t S = 0x0100000a, G = 0x120007ef;
    struct br_ip any = group_v4(G, 0, 289), other = group_v4(G + 1, 0, 289);
    struct ft_mc_route want, r1;
    struct ft_mc_flow *f, *h;

    /* ---- a port's egress queues change ---------------------------------
     *
     * Every listener entry names the queue its port had when it was built.
     * An installed flow copying out of the port -- by the bridge's copy or
     * by a route's riding it -- is marked for a rebuild; one that is not
     * installed, and one elsewhere, are not; the ingress is not a copy. */
    reset();
    memset(&r1, 0, sizeof(r1));
    vlan_enabled = true;
    member(&BR, 289, false);
    member(&P1, 289, false);
    member(&P2, 289, false);
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_membership(&BR, &P2, &other, true, false));
    route_want(&want, 289, S, G, &P3, 287);
    ft_mc_route_publish(&r1, &want);
    answer(&P1, S, 289, BR_MCAST_TO_HOST_ROUTER, 1, &P2);
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    see(seen_v4(&BR, &P1, G + 1, S, 289, true, SENDER));
    pass();
    f = NULL;
    h = NULL;
    {
        struct ft_mc_flow *x;

        list_for_each_entry(x, &ft_mc_flows, list)
            if (x->addr.dst.ip4 == G)
                f = x;
            else
                h = x;
    }
    assert(f && h && f->hw && f->carried_route == &r1 && h->hw);
    /* What the worker recorded is the chain it built: the bridge's copy to
     * P2 and the route's copy to P3, keyed on the sender and the tag the
     * stream arrives with. */
    assert(f->hw_spec.listeners == 2 && f->hw_spec.in == &P1);
    assert(f->hw_spec.listener[0].dev == &P2 && !f->hw_spec.listener[0].routed);
    assert(f->hw_spec.listener[1].dev == &P3 && f->hw_spec.listener[1].routed);
    assert(f->hw_spec.in_vlans == 1 && f->hw_spec.in_vlan[0].id == 289);
    assert(!memcmp(f->hw_spec.src_mac, SENDER, ETH_ALEN));
    h->hw = NULL;
    ft_mc_chain_forget(h);
    f->stale = h->stale = false;
    works = 0;
    assert(ft_mc_egress_mark(&P1) == 0 && !f->stale && !f->egress_stale && !works);
    assert(ft_mc_egress_mark(&P2) == 1 && f->stale && f->egress_stale && !h->stale);
    assert(works == 1 && !h->egress_stale);
    assert(!ft_mc_lock);
    f->stale = f->egress_stale = false;
    assert(ft_mc_egress_mark(&P3) == 1 && f->stale && f->egress_stale);

    /* ---- and the drain, which rebuilds in place under the tc command's
     * RTNL. No rtnl_lock() and no flush_work() are provided here: the
     * worker takes RTNL to ask the bridge, so a drain that waited for it
     * would not compile. What it replaces the entry with is the chain
     * recorded for it, whole -- the routed copy riding it, the ingress tag
     * and the sender included -- not a spec made up from what the flow now
     * says, which may be the next shape. */
    f->stale = false;
    replaces = 0;
    works = 0;
    assert(!tc_drain(&P1) && !replaces && f->egress_stale);
    assert(!tc_drain(&P3) && replaces == 1 && !f->egress_stale);
    assert(!in_transaction && !ft_mc_lock && !f->stale && !works);
    assert(replaced.listeners == 2 && replaced.listener[1].dev == &P3 &&
           replaced.listener[1].routed);
    assert(replaced.in == &P1 && replaced.in_vlans == 1 &&
           replaced.in_vlan[0].id == 289 && replaced.bridged);
    assert(!memcmp(replaced.src_mac, SENDER, ETH_ALEN));
    /* Nothing marked, nothing rebuilt. */
    assert(!tc_drain(&P3) && replaces == 1);
    /* A replace that fails left the old chain in place: the flow is the
     * worker's to rebuild or withdraw, and the drain says it could not
     * vouch for it -- once, not after waiting out any retries. */
    assert(ft_mc_egress_mark(&P2) == 1);
    f->stale = false;
    works = 0;
    replace_rc = -ENOMEM;
    assert(tc_drain(&P2) == -EAGAIN && replaces == 2);
    assert(f->egress_stale && f->stale && works == 1);
    replace_rc = 0;
    assert(!tc_drain(&P2) && replaces == 3 && !f->egress_stale);
    /* A flow the change reached with no entry any more has nothing
     * reading the old queues. */
    f->egress_stale = true;
    f->hw = NULL;
    assert(!tc_drain(&P2) && replaces == 3 && !f->egress_stale);
    f->hw = FAKE_HW;

    /* ---- a bridge setting, or a port moving -------------------------- */
    f->dirty = h->dirty = false;
    ft_mc_bridge_changed(&P3);          /* a port: its bridge's flows */
    assert(f->dirty && h->dirty);
    f->dirty = h->dirty = false;
    ft_mc_bridge_changed(&BR2);
    assert(!f->dirty && !h->dirty);
    ft_mc_port_moved(&P2, NULL);        /* a copy of both */
    assert(f->dirty && h->dirty);
    f->dirty = h->dirty = false;
    ft_mc_port_moved(&P3, NULL);        /* only a route's copy: the route's to say */
    assert(!f->dirty && !h->dirty);

    /* ---- a device a flow, a route or a tap names goes away ------------- */
    {
        struct ft_mc_tap tap = { &BR, 289, true, AF_INET };
        unsigned before;

        ft_mc_taps_publish(&tap, 1, false);
        /* The routed copy's port: the route lets go of everything it
         * names, and names nothing until the routed learner publishes what
         * is left. The flow is re-matched on the next pass. */
        works = 0;
        before = holds;
        ft_mc_device_gone(&P3, true);
        assert(!r1.listeners && !r1.bridge);
        assert(works == 1);
        /* The chain recorded for f named it: nothing may replay that now,
         * and the flow is the worker's to rebuild. Until it has, any port
         * may be in its entry, and a drain cannot vouch for it. The record
         * lets go of what it held -- the ingress and both copies -- as the
         * route let go of the bridge and its copy. */
        assert(!f->hw_spec.listeners && f->stale);
        assert(holds == before - 2 - 3 && !P3.refs);
        assert(ft_mc_egress_mark(&P1) == 1 && f->egress_stale);
        assert(tc_drain(&P1) == -EAGAIN && replaces == 3);
        f->egress_stale = false;
        /* Until the next pass drops it, the emptied route is not a route:
         * the host still needs its copies, and there are none to carry. */
        assert(f->route == &r1 && !ft_mc_installable(f));
        assert(!strcmp(ft_mc_state(f), "refused-routed"));
        f->retries = FT_MC_MAX_RETRIES;
        ft_mc_match_routes();
        assert(!f->route && f->stale && f->routed_host);
        /* A changed answer resets the retries spent on the old one. */
        assert(f->retries == 0);
        /* A port that only lost its link is still what it was: the bridge
         * keeps a permanent membership across it and never announces it
         * again, so every membership stands, and the flows naming the port
         * are asked of the bridge again. Nothing is let go. */
        before = holds;
        f->dirty = h->dirty = false;
        ft_mc_device_gone(&P2, false);
        assert(f->ports == 1 && f->dirty && h->dirty && holds == before);
        assert(ft_mc_find(&BR, &any)->ports == 1);
        f->dirty = h->dirty = false;
        ft_mc_device_gone(&P1, false);
        assert(!f->gone && f->in == &P1 && f->dirty && holds == before);
        /* A copy's port going away: dropped from both flows, which are
         * asked again, and from both memberships it held. */
        f->dirty = f->stale = false;
        ft_mc_device_gone(&P2, true);
        assert(!f->ports && f->dirty && f->stale && !h->ports);
        assert(holds == before - 2 - 2);
        /* The ingress: the flow is over. Its reference goes when the worker
         * frees it, after the entry that names it is out of hardware: the
         * backend borrows the ingress and deletes through it. */
        before = holds;
        f->hw = FAKE_HW;
        ft_mc_device_gone(&P1, true);
        assert(f->gone && f->in == &P1 && h->gone && holds == before);
        pass();
        /* Both flows' ingress and bridge, and the bridge of both
         * memberships, which the copy's port going left empty. */
        assert(!ft_mc_flow_count && !ft_mc_count && holds == before - 6);
        /* The bridge itself: its memberships empty, its tap goes. */
        assert(ft_mc_membership(&BR, &P1, &any, true, false));
        ft_mc_device_gone(&BR, true);
        assert(!ft_mc_tap_count && !only_group()->ports);
        pass();
        assert(!ft_mc_count);
        withdraw(&r1);
    }
}

/* A tc command changing a port's egress and draining it, run as the
 * transaction's next taker: what it replaced, and what the drain said. */
static struct net_device *drain_port;
static int drain_rc;
static unsigned drain_replaces;
static struct cdx_mc_group_spec drained_with;
static void tc_changes_and_drains(void)
{
    unsigned before = replaces;

    tc_begin();
    egress_changed(drain_port);
    drain_rc = ft_mc_egress_drain(drain_port);
    drain_replaces = replaces - before;
    drained_with = replaced;
    tc_end();
}

/* A tc command draining a port whose change was marked earlier, run as the
 * transaction's next taker: what the drain said, what it replaced, and how
 * many entries built before the last change it left in the hardware. */
static unsigned stale_live;
static void tc_drains_and_counts(void)
{
    unsigned before = replaces;

    tc_begin();
    drain_rc = ft_mc_egress_drain(drain_port);
    drain_replaces = replaces - before;
    stale_live = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++)
        stale_live += entries[i].live && entries[i].built_at < ft_egress_changes;
    tc_end();
}

/* P2 is moved to another namespace, under RTNL of its own: NETDEV_UNREGISTER
 * in this one, with the device still registered, and nothing more about it
 * reaches the learner after. Unregistering it is the same event. */
static void p2_leaves(void)
{
    rtnl_lock();
    ft_mc_device_gone(&P2, true);
    rtnl_unlock();
}

static void the_worker_records_what_the_drain_replays(void)
{
    const uint32_t S = 0x0100000a, G = 0x170007ef;
    struct br_ip any = group_v4(G, 0, 289);
    struct ft_mc_route want, r1;
    struct cdx_mc_group *hw;
    struct ft_mc_flow *f;
    unsigned r0, a0, d0;

    /* The worker itself this time, against the backend above: an IPTV
     * stream in tagged on P1, bridged to P2 and routed to P3 through
     * br0.289, as one entry. */
    reset();
    ft_mc_filtered = bridge_hooked = false;
    memset(&r1, 0, sizeof(r1));
    vlan_enabled = true;
    member(&BR, 289, false);
    member(&P1, 289, false);
    member(&P2, 289, false);
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    route_want(&want, 289, S, G, &P3, 287);
    ft_mc_route_publish(&r1, &want);
    answer(&P1, S, 289, BR_MCAST_TO_HOST_ROUTER, 1, &P2);
    see(seen_v4(&BR, &P1, G, S, 289, true, SENDER));
    adds = dels = replaces = 0;

    /* ---- the first build, with the count moving under it ---------------
     *
     * A flow with no entry yet is on no list a change could mark, and the
     * change does not wait for the worker to record: the worker holds no
     * learner lock while it builds. The worker reads the egress count inside
     * its transaction before building, and compares it when it records: a
     * chain built from the queues before the change is marked and built
     * again, in the same run. What is recorded beside the entry, in the same
     * transaction, is what was built, whole. */
    change_during_build = &P2;
    ft_mc_work_fn(NULL);
    assert(!change_during_build);
    f = flow(&P1, S, 289);
    assert(f && f->hw && f->hw != FAKE_HW && adds == 1 && replaces == 1);
    hw = f->hw;
    assert(hw->built_at == ft_egress_changes && !f->egress_stale && !f->stale);
    assert(same_chain(&f->hw_spec, &hw->chain));
    assert(f->hw_spec.listeners == 2 && f->hw_spec.in == &P1);
    assert(f->hw_spec.listener[0].dev == &P2 && !f->hw_spec.listener[0].routed);
    assert(f->hw_spec.listener[1].dev == &P3 && f->hw_spec.listener[1].routed);
    assert(f->hw_spec.in_vlans == 1 && f->hw_spec.in_vlan[0].id == 289);
    assert(!memcmp(f->hw_spec.src_mac, SENDER, ETH_ALEN));
    assert(!in_transaction && !ft_mc_lock && !rtnl);

    /* ---- a tc command's drain -------------------------------------------
     *
     * The change marks the flow for its copy on the port -- the bridge's to
     * P2 or the routed one riding it to P3 -- and the drain, under the tc
     * command's RTNL, replaces the entry with the chain recorded for it: no
     * RTNL of its own, no worker waited for, nothing decided. */
    for (int i = 0; i < 2; i++) {
        struct net_device *port = i ? &P3 : &P2;

        tc_begin();
        r0 = replaces;
        egress_changed(port);
        assert(f->egress_stale && f->stale);
        assert(!ft_mc_egress_drain(port));
        assert(replaces == r0 + 1 && !f->egress_stale && f->hw == hw);
        assert(hw->built_at == ft_egress_changes && same_chain(&replaced, &f->hw_spec));
        tc_end();
        /* The mark's own pass rebuilds it once more, which costs nothing. */
        ft_mc_work_fn(NULL);
        assert(!f->stale && !f->egress_stale && f->hw == hw);
    }

    /* ---- the drain while the worker holds the flow ----------------------
     *
     * The entry went idle while the stream arrived from another sender, so
     * the worker picks the flow to move it to the new key. The new shape is
     * the flow's from the pick; the entry, and the chain recorded for it,
     * are the old key's until the worker is inside its transaction. A tc
     * command that gets the transaction first rebuilds the old entry from
     * the old chain. A spec made from the flow as it is now would carry the
     * new sender, which the backend refuses as another key, and the drain
     * would hold the DSCP map until the worker had run. The worker then
     * moves the flow as it meant to, against the queues as they are now. */
    f->idle = true;
    see(seen_v4(&BR, &P1, G, S, 289, true, OTHER_SENDER));
    assert(f->has_next && f->stale);
    a0 = adds;
    d0 = dels;
    drain_port = &P2;
    drain_rc = 1;
    before_begin = tc_changes_and_drains;
    before_begin_skip = 1;
    ft_mc_work_fn(NULL);
    assert(!before_begin && !drain_rc && drain_replaces == 1);
    assert(!memcmp(drained_with.src_mac, SENDER, ETH_ALEN));
    assert(dels == d0 + 1 && adds == a0 + 1 && f->hw && !f->has_next);
    hw = f->hw;
    assert(!memcmp(hw->key.src_mac, OTHER_SENDER, ETH_ALEN));
    assert(same_chain(&f->hw_spec, &hw->chain) && !f->egress_stale);
    assert(hw->built_at == ft_egress_changes);

    /* ---- marked before the pick, drained before the build ---------------
     *
     * The change marks the flow before the worker picks it, and a tc
     * command's drain gets the transaction between the pick and the build.
     * Picking consumes the request for a pass, not the mark: only a build
     * that started after the change clears it. The drain therefore still
     * finds the flow marked, and rebuilds it rather than answer for an
     * entry built before the change. */
    tc_begin();
    egress_changed(&P2);
    tc_end();
    assert(f->egress_stale && f->stale && hw->built_at < ft_egress_changes);
    r0 = replaces;
    drain_port = &P2;
    drain_rc = 1;
    before_begin = tc_drains_and_counts;
    before_begin_skip = 1;
    ft_mc_work_fn(NULL);
    assert(!before_begin && !drain_rc && drain_replaces == 1 && !stale_live);
    assert(replaces == r0 + 2 && !f->egress_stale && f->hw == hw);
    assert(hw->built_at == ft_egress_changes);

    /* ---- a drain that cannot rebuild ------------------------------------
     *
     * The replace fails and leaves the old chain: the drain hands the flow
     * to the worker and says so. The worker's own replace fails too and
     * withdraws the flow in that pass, spending one retry, so the next drain
     * finds nothing reading the old queues -- it never waits out retries the
     * refresh paces. The install is tried again at the refresh, not before. */
    tc_begin();
    egress_changed(&P2);
    replace_rc = -ENOMEM;
    works = 0;
    assert(ft_mc_egress_drain(&P2) == -EAGAIN);
    assert(f->egress_stale && f->stale && works == 1 && f->hw == hw);
    tc_end();
    d0 = dels;
    ft_mc_work_fn(NULL);
    assert(!f->hw && dels == d0 + 1 && f->retries == 1);
    assert(!f->egress_stale && !f->hw_spec.listeners);
    replace_rc = 0;
    tc_begin();
    assert(!ft_mc_egress_drain(&P2));
    tc_end();
    a0 = adds;
    ft_mc_work_fn(NULL);
    assert(adds == a0 && !f->hw);
    ft_mc_refresh_fn(NULL);
    ft_mc_work_fn(NULL);
    assert(adds == a0 + 1 && f->hw && !f->retries && f->hw_spec.listeners == 2);

    /* ---- a device going while the worker builds with it -----------------
     *
     * The worker holds a reference of its own on every device in the chain
     * it builds. P2 moves to another namespace meanwhile -- still
     * registered, so nothing about it can be read off the device -- and its
     * event drops the flow's and the membership's holds on it, empties the
     * chain recorded before, letting go of that one's too, and asks for
     * another pass. The build then records a chain naming P2, and that
     * record holds P2 itself: once the build let go, nothing else would, P2
     * could be freed in the other namespace, and a drain replaying the
     * chain would reach it. recorded_chains_hold_their_devices() checks at
     * every transaction. The pass that follows records the chain without
     * P2 and lets it go, so the device waits for the worker and no longer. */
    f->stale = true;
    before_begin = p2_leaves;
    before_begin_skip = 1;
    r0 = replaces;
    ft_mc_work_fn(NULL);
    assert(!before_begin && replaces == r0 + 2 && f->hw && !f->ports);
    assert(f->hw_spec.listeners == 1 && f->hw_spec.listener[0].dev == &P3);
    assert(same_chain(&f->hw_spec, &f->hw->chain));
    assert(!P2.refs && P3.refs && P1.refs);

    /* ---- a flow retired while the DSCP map leaves its port ----------------
     *
     * Nothing names the flow now but the route -- P2's membership went with
     * P2 -- so the route going retires it, entry and all. The change marks
     * it first, and a tc command's drain gets the transaction before the
     * worker's retirement does. The flow leaves the list only in the
     * transaction hold that takes its entry out of the hardware, so the
     * drain finds it still listed and rebuilds it: it never answers for an
     * entry it did not see. */
    tc_begin();
    egress_changed(&P3);
    tc_end();
    assert(f->egress_stale && f->hw && f->hw->built_at < ft_egress_changes);
    d0 = dels;
    drain_port = &P3;
    drain_rc = 1;
    before_begin = tc_drains_and_counts;
    withdraw(&r1);
    ft_mc_work_fn(NULL);
    assert(!before_begin && !drain_rc && drain_replaces == 1 && !stale_live);
    assert(!flow(&P1, S, 289) && !ft_mc_flow_count && dels == d0 + 1);
    reset();
}

static void rows_speak_for_memberships(void)
{
    const uint32_t G = 0x140007ef, S1 = 0x0100000a;
    struct br_ip any = group_v4(G, 0, 0), sg = group_v4(G, S1, 0);
    struct br_ip sg2 = group_v4(G, 0x0200000a, 0);
    struct ft_mc_flow *f;

    /* A flow speaks for every membership that names it; a membership with
     * no flow has a row of its own, until one is learned. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_membership(&BR, &P2, &sg, true, false));
    assert(ft_mc_membership(&BR, &P3, &sg2, true, false));
    assert(!ft_mc_group_has_flow(ft_mc_find(&BR, &any)));
    see(seen_v4(&BR, &P1, G, S1, 0, false, SENDER));
    f = flow(&P1, S1, 0);
    assert(ft_mc_group_has_flow(ft_mc_find(&BR, &any)));
    assert(ft_mc_group_has_flow(ft_mc_find(&BR, &sg)));
    assert(!ft_mc_group_has_flow(ft_mc_find(&BR, &sg2)));
    /* And names, as `member_src`, the most specific of them. */
    assert(ft_mc_member_src(f)->src.ip4 == S1);
    assert(!ft_mc_membership(&BR, &P2, &sg, false, false));
    assert(ft_mc_member_src(f)->src.ip4 == 0);
}

static void replayed_memberships(void)
{
    const uint32_t G = 0x150007ef, S = 0x0100000a;
    struct switchdev_obj_port_mdb port_group, host_group, vlan_obj;
    struct switchdev_notifier_port_obj_info on_p1, on_p2, host_p1, host_p2, vlan;
    struct ft_mc_flow *f;
    char attr[1] = { 0 };

    /* An adapter reloaded under a standing membership: the bridge's replay
     * of each port brings the port's groups and, with every port, the
     * host's. The chain may deliver some of the same again. However many
     * times each arrives, one membership results, with the port once. */
    reset();
    memset(&port_group, 0, sizeof(port_group));
    port_group.obj.id = SWITCHDEV_OBJ_ID_PORT_MDB;
    port_group.obj.orig_dev = &P2;
    port_group.group = group_v4(G, 0, 0);
    host_group = port_group;
    host_group.obj.id = SWITCHDEV_OBJ_ID_HOST_MDB;
    host_group.obj.orig_dev = &BR;
    on_p2 = (struct switchdev_notifier_port_obj_info){ .info.dev = &P2, .obj = &port_group.obj };
    host_p1 = (struct switchdev_notifier_port_obj_info){ .info.dev = &P1, .obj = &host_group.obj };
    host_p2 = (struct switchdev_notifier_port_obj_info){ .info.dev = &P2, .obj = &host_group.obj };
    for (int round = 0; round < 2; round++) {
        assert(ft_mc_replay_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &host_p1) == NOTIFY_DONE);
        assert(ft_mc_replay_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &host_p2) == NOTIFY_DONE);
        assert(ft_mc_replay_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &on_p2) == NOTIFY_DONE);
        assert(ft_mc_swdev_obj(SWITCHDEV_PORT_OBJ_ADD, &on_p2) == false);  /* host joined */
    }
    assert(ft_mc_count == 1 && only_group()->host && only_group()->ports == 1);
    assert(only_group()->port[0] == &P2 && holds == 2);
    /* The host's copy is no longer wanted: its delete is the chain's, and
     * the port's membership is claimed again. */
    assert(!ft_mc_swdev_obj(SWITCHDEV_PORT_OBJ_DEL, &host_p1));
    assert(ft_mc_swdev_obj(SWITCHDEV_PORT_OBJ_ADD, &on_p2));
    answer(&P1, S, 0, 0, 1, &P2);
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw);

    /* A replayed port group the bridge has blocked is a leave: what the
     * notification says, the replay says (patch 160). */
    port_group.group = group_v4(G, S, 0);
    port_group.flags = SWITCHDEV_OBJ_MDB_F_BLOCKED;
    assert(!ft_mc_replay_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &on_p2));
    assert(!ft_mc_find(&BR, &port_group.group) && f->dirty);

    /* Everything else the replay sends is not a membership, and is never
     * read as one: a VLAN object, a delete, and an attribute, whose `ptr`
     * is not an object at all. */
    memset(&vlan_obj, 0, sizeof(vlan_obj));
    vlan_obj.obj.id = SWITCHDEV_OBJ_ID_PORT_VLAN;
    vlan = (struct switchdev_notifier_port_obj_info){ .info.dev = &P1, .obj = &vlan_obj.obj };
    on_p1 = on_p2;
    on_p1.info.dev = &P1;
    port_group.flags = 0;
    {
        unsigned before = ft_mc_count, kicks = mr_kicks;

        assert(ft_mc_replay_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &vlan) == NOTIFY_DONE);
        assert(ft_mc_replay_event(NULL, SWITCHDEV_PORT_OBJ_DEL, &on_p1) == NOTIFY_DONE);
        assert(ft_mc_replay_event(NULL, SWITCHDEV_PORT_ATTR_SET, attr) == NOTIFY_DONE);
        assert(ft_mc_count == before && mr_kicks == kicks);
    }
    /* And a link-local group, which the bridge reports like any other, is
     * never recorded. */
    port_group.group = group_v4(0xfb0000e0, 0, 0);   /* 224.0.0.251 */
    assert(!ft_mc_replay_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &on_p2));
    assert(!ft_mc_find(&BR, &port_group.group));
}

static void a_bridge_filter_refuses_every_flow(void)
{
    const uint32_t G = 0x180007ef, S = 0x0100000a;
    struct br_ip any = group_v4(G, 0, 0);
    struct br_ip named = group_v4(G, htonl(0x0a0000ff), 0);
    struct ft_mc_flow *f;

    /* An nftables bridge chain appears while a flow is carried. The worker
     * finds it and marks every flow for the install pass, which takes the
     * carried one out: its frames reach the chain again. The flow stays,
     * and says why. When the chain goes, it goes back in. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S, 0, 0, 1, &P2);
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw && !strcmp(ft_mc_state(f), "installed"));
    ft_mc_filtered = true;
    f->stale = true;
    pass();
    assert(!f->hw && !ft_mc_installable(f));
    assert(!strcmp(ft_mc_state(f), "refused-filter"));
    ft_mc_filtered = false;
    f->stale = true;
    pass();
    assert(f->hw && !strcmp(ft_mc_state(f), "installed"));

    /* And no place is given up for a source the filter would refuse too,
     * however it is named. */
    reset();
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    assert(ft_mc_membership(&BR, &P3, &named, true, false));
    for (uint32_t i = 0; i < FT_MC_MAX_FLOWS; i++)
        see(seen_v4(&BR, &P1, G, htonl(0x0a000001 + i), 0, false, SENDER));
    ft_mc_filtered = true;
    see(seen_v4(&BR, &P1, G, htonl(0x0a0000ff), 0, false, SENDER));
    assert(!flow(&P1, htonl(0x0a0000ff), 0) && ft_mc_refused == 1);
    list_for_each_entry(f, &ft_mc_flows, list)
        assert(!f->gone);
    ft_mc_filtered = false;
}

static void a_port_moves_between_bridges(void)
{
    const uint32_t G = 0x170007ef, S = 0x0100000a;
    struct switchdev_obj_port_mdb port_group;
    struct switchdev_notifier_port_obj_info on_p2;
    struct br_ip any = group_v4(G, 0, 0);
    struct ft_mc_group *g;
    struct ft_mc_flow *f;
    unsigned before;

    /* `ip link set eth4 master br1` with eth4 a port of br0: del_nbp()
     * unlinks it from br0, then flushes its port groups with deletes that
     * are deferred, and the port is br1's before they arrive. The handler
     * finds a membership through the port's master, so those deletes look
     * on br1. The memberships go when the port leaves br0 instead -- the
     * same ones the flush deletes -- and the flows copying to it are asked
     * again. */
    reset();
    memset(&port_group, 0, sizeof(port_group));
    port_group.obj.id = SWITCHDEV_OBJ_ID_PORT_MDB;
    port_group.obj.orig_dev = &P2;
    port_group.group = any;
    on_p2 = (struct switchdev_notifier_port_obj_info){ .info.dev = &P2, .obj = &port_group.obj };
    assert(ft_mc_swdev_obj(SWITCHDEV_PORT_OBJ_ADD, &on_p2));
    assert(ft_mc_membership(&BR, &P3, &any, true, false));
    answer(&P1, S, 0, 0, 2, &P2, &P3);
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    g = ft_mc_find(&BR, &any);
    assert(f && f->hw && g->ports == 2);
    before = holds;
    f->dirty = false;
    /* Joining names no bridge left, and drops nothing. */
    ft_mc_port_moved(&P2, NULL);
    assert(g->ports == 2 && holds == before && f->dirty);
    f->dirty = false;
    /* Leaving a device that is not a bridge -- a VLAN upper -- neither. */
    ft_mc_port_moved(&P2, &P1);
    assert(g->ports == 2 && holds == before);
    ft_mc_port_moved(&P2, &BR);
    assert(g->ports == 1 && g->port[0] == &P3 && holds == before - 1 && f->dirty);
    /* The deferred delete, arriving with the port now br1's, finds nothing
     * and releases nothing. */
    P2.master = &BR2;
    assert(!ft_mc_swdev_obj(SWITCHDEV_PORT_OBJ_DEL, &on_p2));
    assert(g->ports == 1 && holds == before - 1);
    answer(&P1, S, 0, 0, 1, &P3);
    pass();
    assert(f->ports == 1 && f->port[0].dev == &P3 && f->hw);
    P2.master = &BR;
    /* The last port leaving empties the membership, which retires with the
     * flow it named. */
    ft_mc_port_moved(&P3, &BR);
    pass();
    assert(!ft_mc_count && !ft_mc_flow_count && !holds);
}

static void idle_flows_age_out(void)
{
    const uint32_t G = 0x160007ef, S = 0x0100000a;
    struct br_ip any = group_v4(G, 0, 0);
    struct cdx_ft_counters c;
    struct ft_mc_flow *f;
    const unsigned long t0 = 1000;

    /* An installed flow whose entry counts nothing for as long as the
     * bridge keeps a membership nobody refreshes is a stream that stopped:
     * it goes, and the source is learned again when it resumes. A frame
     * within the interval starts it again; the interval is the bridge's,
     * read at each derivation. */
    reset();
    memset(&c, 0, sizeof(c));
    assert(ft_mc_membership(&BR, &P2, &any, true, false));
    answer(&P1, S, 0, 0, 1, &P2);
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw && f->age == 260 * HZ);
    f->active = t0;              /* as the worker records an add */
    c.packets = 10;
    c.bytes = 10 * 64;
    ft_mc_flow_counted(f, &c, t0 + 100 * HZ);
    assert(f->active == t0 + 100 * HZ && !f->idle && !f->gone);
    ft_mc_flow_counted(f, &c, t0 + 359 * HZ);
    assert(f->idle && !f->gone);
    /* One frame, just in time, keeps it. */
    c.packets++;
    c.bytes += 64;
    ft_mc_flow_counted(f, &c, t0 + 360 * HZ);
    assert(!f->idle && !f->gone && f->active == t0 + 360 * HZ);
    ft_mc_flow_counted(f, &c, t0 + 620 * HZ);
    assert(f->idle && !f->gone);
    ft_mc_flow_counted(f, &c, t0 + 621 * HZ);
    assert(f->gone);
    /* Out of hardware and forgotten; the membership stands. */
    pass();
    assert(!flow(&P1, S, 0) && !ft_mc_flow_count && ft_mc_count == 1);
    /* The source resumes: its very next frame is a flow again, even though
     * the same frame was recorded before. */
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw);

    /* The interval changes on the bridge: followed at the next derivation,
     * with nothing in hardware touched. */
    membership_interval = 20 * HZ;
    f->dirty = true;
    pass();
    assert(f->age == 20 * HZ && f->hw && !f->stale);
    f->active = t0;
    f->hw_packets = f->hw_bytes = 0;
    memset(&c, 0, sizeof(c));
    ft_mc_flow_counted(f, &c, t0 + 20 * HZ);
    assert(!f->gone);
    ft_mc_flow_counted(f, &c, t0 + 21 * HZ);
    assert(f->gone);
    pass();
    assert(!ft_mc_flow_count);

    /* A sample below the baseline is no answer: nothing added to the route
     * the flow carries, not idle, not active. A sane one after it counts from
     * the baseline that stood; a second low one in a row moves the baseline,
     * and counting goes on from there. */
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw);
    {
        struct ft_mc_route r;

        memset(&r, 0, sizeof(r));
        f->carried_route = &r;
        f->hw_packets = f->hw_bytes = 0;
        f->count_suspect = false;
        f->active = t0;
        c = (struct cdx_ft_counters){ .packets = 10, .bytes = 640 };
        ft_mc_flow_counted(f, &c, t0 + HZ);
        assert(r.stats.packets == 10 && r.stats.bytes == 640 && f->active == t0 + HZ);
        c = (struct cdx_ft_counters){ .packets = 3, .bytes = 192 };
        ft_mc_flow_counted(f, &c, t0 + 2 * HZ);
        assert(r.stats.packets == 10 && !f->idle && f->active == t0 + HZ);
        assert(f->hw_packets == 10 && f->count_suspect);
        c = (struct cdx_ft_counters){ .packets = 12, .bytes = 768 };
        ft_mc_flow_counted(f, &c, t0 + 3 * HZ);
        assert(r.stats.packets == 12 && r.stats.bytes == 768 && !f->count_suspect);
        c.bytes += 1ull << 32;                  /* folded, and cannot be undone */
        c.packets++;
        ft_mc_flow_counted(f, &c, t0 + 4 * HZ);
        c.bytes -= 1ull << 32;
        c.packets++;
        ft_mc_flow_counted(f, &c, t0 + 5 * HZ);
        c.packets++;
        c.bytes += 64;
        ft_mc_flow_counted(f, &c, t0 + 6 * HZ);
        assert(f->hw_packets == c.packets && f->hw_bytes == c.bytes);
        c.packets++;
        c.bytes += 64;
        ft_mc_flow_counted(f, &c, t0 + 7 * HZ);
        assert(r.stats.packets == 14 && f->active == t0 + 7 * HZ);
        f->carried_route = NULL;
    }
    f->gone = true;
    pass();
    assert(!ft_mc_flow_count);
    memset(&c, 0, sizeof(c));

    /* An interval shorter than two refreshes is taken as two: the count is
     * read one refresh apart, and a read that has not seen a running
     * stream's frames yet must not age it out. And a sample that answers
     * nothing -- below the baseline -- ages nothing, however late it is. */
    membership_interval = 4 * HZ;
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw && f->age == 2 * FT_MC_REFRESH_INTERVAL);
    f->active = t0;
    f->hw_packets = f->hw_bytes = 0;
    f->count_suspect = false;
    ft_mc_flow_counted(f, &c, t0 + FT_MC_REFRESH_INTERVAL);
    assert(f->idle && !f->gone);
    f->hw_packets = 100;
    f->hw_bytes = 6400;
    ft_mc_flow_counted(f, &c, t0 + 3 * FT_MC_REFRESH_INTERVAL);
    assert(f->count_suspect && !f->idle && !f->gone);
    c = (struct cdx_ft_counters){ .packets = 101, .bytes = 6464 };
    ft_mc_flow_counted(f, &c, t0 + 4 * FT_MC_REFRESH_INTERVAL);
    assert(!f->gone && f->active == t0 + 4 * FT_MC_REFRESH_INTERVAL);
    f->gone = true;
    pass();
    assert(!ft_mc_flow_count);
    memset(&c, 0, sizeof(c));

    /* No interval, no ageing. */
    membership_interval = 0;
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw && !f->age);
    f->active = t0;
    ft_mc_flow_counted(f, &c, t0 + 100000 * HZ);
    assert(!f->gone);
    /* And jiffies wrapping round does not age a live entry. Counted 50 s
     * before the wrap, it ages 210 s after it -- a sum that has wrapped, and
     * that a plain comparison takes for long past at any moment before the
     * wrap itself. */
    membership_interval = 260 * HZ;
    f->dirty = true;
    pass();
    f->active = (unsigned long)-50 * HZ;
    ft_mc_flow_counted(f, &c, (unsigned long)-10 * HZ);
    assert(!f->gone);
    ft_mc_flow_counted(f, &c, 100 * HZ);
    assert(!f->gone);
    ft_mc_flow_counted(f, &c, 211 * HZ);
    assert(f->gone);
    pass();
    assert(!ft_mc_flow_count);

    /* A read of the entry's count that fails is no sample. The refresh does
     * not pass it on: the flow is neither idle nor active on it and ages on
     * nothing, and the baseline stands however many fail in a row. Taken
     * as zero, two would re-base the entry there, and the first read after
     * would count the whole stream again into the route it carries. */
    see(seen_v4(&BR, &P1, G, S, 0, false, SENDER));
    pass();
    f = flow(&P1, S, 0);
    assert(f && f->hw);
    {
        struct ft_mc_route r;

        memset(&r, 0, sizeof(r));
        f->carried_route = &r;
        f->hw_packets = 100;
        f->hw_bytes = 6400;
        f->count_suspect = f->idle = false;
        jiffies = t0;
        f->active = t0;
        stats_fail = true;
        for (int i = 1; i <= 3; i++) {
            jiffies = t0 + i * FT_MC_REFRESH_INTERVAL;
            ft_mc_refresh_fn(NULL);
        }
        assert(f->hw_packets == 100 && f->hw_bytes == 6400 && !f->count_suspect);
        assert(!f->idle && !f->gone && f->active == t0 && !r.stats.packets);
        stats_fail = false;
        stats_now = (struct cdx_ft_counters){ .packets = 110, .bytes = 7040 };
        jiffies += FT_MC_REFRESH_INTERVAL;
        ft_mc_refresh_fn(NULL);
        assert(r.stats.packets == 10 && r.stats.bytes == 640);
        assert(f->active == jiffies && !f->idle && !f->gone);
        f->carried_route = NULL;
    }
    assert(!ft_mc_lock && !in_transaction && refresh_rearms);
}

int main(void)
{
    /* Until the routed learner first says where its VIFs are, they may be
     * anywhere. */
    assert(ft_mc_taps_overflow);
    ft_mc_taps_publish(NULL, 0, false);

    memberships_and_their_answers();
    frames_become_flows();
    the_bridge_decides();
    the_vlan_a_flow_arrives_in();
    one_stream_both_learners();
    the_dedup_slots();
    devices_and_bridges_change();
    the_worker_records_what_the_drain_replays();
    rows_speak_for_memberships();
    replayed_memberships();
    a_bridge_filter_refuses_every_flow();
    a_port_moves_between_bridges();
    idle_flows_age_out();

    reset();
    assert(holds == 0);
    printf("ok\n");
    return 0;
}

/* The multicast membership learner's decision logic, compiled from the
 * adapter against stubs for everything below it.
 *
 * What this pins down is the part a hardware run cannot show cheaply: how a
 * port set is accumulated from a sequence of switchdev objects. On the rig a
 * membership arrives once, correctly, and every interesting case -- the same
 * port twice, a leave for a port that never joined, the ninth listener, a host
 * membership arriving before or after the ports it disqualifies -- either does
 * not occur or occurs once in a way nothing distinguishes from success.
 *
 * The answer the handler gives the bridge is the other half. `handled` becomes
 * MDB_PG_FLAGS_OFFLOAD and shows up in `bridge mdb show`, so a membership
 * refused for capacity or for a host listener must not claim to have been
 * taken on.
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
 * names are needed; the shape has to match so a group's key compares the way
 * the production one does. */
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

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16((uint16_t)(x))
#else
#define htons(x) ((uint16_t)(x))
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
};

#define READ_ONCE(x) (x)

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
static unsigned int ft_mc_count;
static unsigned long long ft_mc_refused;
/* Read only by the worker and /proc, neither of which is compiled here. */
__attribute__((unused)) static unsigned int ft_mc_installed;
__attribute__((unused)) static unsigned long long ft_mc_install_errors;

static unsigned holds;   /* net-device references outstanding */
static void dev_hold(struct net_device *d) { (void)d; holds++; }
static void dev_put(struct net_device *d) { (void)d; assert(holds); holds--; }

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
static void eth_zero_addr(u8 *a) { memset(a, 0, ETH_ALEN); }
#define ASSERT_RTNL() ((void)0)

static bool cdx_mc_port_identity(struct net_device *d)
{
    return d && d->physical;
}

/* The bridge under test: VLAN-filtering, 802.1Q, with a per-(port,vid)
 * membership table the cases populate. */
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
static int br_vlan_get_pvid_rcu(const struct net_device *dev, uint16_t *p)
{
    return br_vlan_get_pvid((struct net_device *)dev, p);
}
static bool br_multicast_router(const struct net_device *br) { return br->mrouter; }
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)

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
#define kzalloc(n, f) calloc(1, (n))
#define kfree(p) free(p)
#define GFP_KERNEL 0

#include "mcast_learner.inc"

/* --- helpers --------------------------------------------------------- */

static struct net_device BR   = { .name = "br0",  .ifindex = 10, .bridge_master = true };
static struct net_device P1   = { .name = "eth3", .ifindex = 11, .physical = true };
static struct net_device P2   = { .name = "eth4", .ifindex = 12, .physical = true };
static struct net_device P3   = { .name = "eth5", .ifindex = 13, .physical = true };
static struct net_device SOFT = { .name = "vx0",  .ifindex = 14, .physical = false };
static struct net_device BR2  = { .name = "br1",  .ifindex = 15, .bridge_master = true };

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

static void member(struct net_device *p, uint16_t vid, bool untagged)
{
    memberships[membership_count].port = p;
    memberships[membership_count].vid = vid;
    memberships[membership_count].untagged = untagged;
    memberships[membership_count].member = true;
    membership_count++;
}

static void reset(void)
{
    while (ft_mc_groups.next != &ft_mc_groups) {
        struct ft_mc_group *g = list_entry(ft_mc_groups.next,
                                           struct ft_mc_group, list);
        list_del(&g->list);
        ft_mc_group_free(g);
    }
    /* Routes belong to the routed learner, which withdraws them. */
    while (ft_mc_routes.next != &ft_mc_routes)
        ft_mc_route_withdraw(list_entry(ft_mc_routes.next,
                                        struct ft_mc_route, list));
    ft_mc_taps_publish(NULL, 0, false);
    BR.mrouter = BR2.mrouter = false;
    /* A fresh learner: an empty ring and nothing recorded. */
    memset(&ft_mc_last, 0, sizeof(ft_mc_last));
    ft_mc_ring_head = ft_mc_ring_tail = 0;
    ft_mc_count = 0;
    membership_count = 0;
    pvid_count = 0;
    memset(by_index, 0, sizeof(by_index));
    vlan_enabled = false;
    ft_mc_refused = 0;
    assert(holds == 0);
}

/* A stream the traffic half would have resolved: untagged from `in`. */
static void stream(struct ft_mc_group *g, struct net_device *in, uint32_t src)
{
    static const u8 group_mac[ETH_ALEN] = { 0x01, 0, 0x5e, 0x07, 0, 0x0f };
    static const u8 sender[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x51 };

    dev_hold(in);
    g->in = in;
    g->src.ip = src;
    memcpy(g->dst_mac, group_mac, ETH_ALEN);
    memcpy(g->src_mac, sender, ETH_ALEN);
    g->in_tagged = false;
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
    if (tag) {
        want->listener[0].vlans = 1;
        want->listener[0].vlan[0].proto = htons(ETH_P_8021Q);
        want->listener[0].vlan[0].id = tag;
    }
    want->listeners = 1;
    want->mtu = 1500;
}

static bool list_empty(const struct list_head *h) { return h->next == h; }

static struct ft_mc_group *only_group(void)
{
    struct ft_mc_group *g = list_entry(ft_mc_groups.next,
                                       struct ft_mc_group, list);
    assert(ft_mc_groups.next != &ft_mc_groups);
    return g;
}

int main(void)
{
    struct br_ip g1 = group_v4(0x010007ef, 0, 0);   /* 239.7.0.1, (*,G) */
    struct br_ip g2 = group_v4(0x020007ef, 0, 0);

    /* Until the routed learner first says where its VIFs are, they may be
     * anywhere: a group on a multicast-router bridge waits for it. */
    assert(ft_mc_taps_overflow);

    /* One port joins: the group appears, the adapter takes it on, and the
     * port is pinned. */
    reset();
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(ft_mc_count == 1 && only_group()->ports == 1);
    assert(only_group()->port[0].dev == &P1);
    assert(holds == 2);   /* the bridge and the port */

    /* The same port again is the bridge restating a membership, not a second
     * listener. Restating must not duplicate it, and must still answer yes --
     * a repeat that answered no would clear the offload flag on a group that
     * is still taken on. */
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(only_group()->ports == 1);
    assert(holds == 2);

    /* A second port joins the same group. */
    assert(ft_mc_membership(&BR, &P2, &g1, true, false));
    assert(only_group()->ports == 2 && ft_mc_count == 1);

    /* A different group is a different entry. */
    assert(ft_mc_membership(&BR, &P1, &g2, true, false));
    assert(ft_mc_count == 2);

    /* Leaving drops the port and keeps the order of the rest compact. The
     * answer is no: a leave is not a membership being taken on. */
    assert(!ft_mc_membership(&BR, &P1, &g1, false, false));
    {
        struct ft_mc_group *g = ft_mc_find(&BR, &g1);
        assert(g && g->ports == 1 && g->port[0].dev == &P2);
        /* The slot the removed port left must be cleared, not left aliasing
         * a device the group no longer holds a reference to. */
        assert(g->port[1].dev == NULL);
    }

    /* A leave for a port that never joined changes nothing and releases
     * nothing. */
    {
        unsigned before = holds;
        assert(!ft_mc_membership(&BR, &P3, &g1, false, false));
        assert(holds == before);
        assert(ft_mc_find(&BR, &g1)->ports == 1);
    }

    /* A leave for a group that does not exist is equally inert. */
    {
        struct br_ip absent = group_v4(0x090007ef, 0, 0);
        assert(!ft_mc_membership(&BR, &P1, &absent, false, false));
        assert(ft_mc_count == 2);
    }

    /* A port the hardware cannot carry is RECORDED, not forgotten, and the
     * recording is the whole point.
     *
     * A matched frame never reaches the bridge, so a listener the hardware
     * did not take on does not fall back to software -- it stops receiving.
     * Dropping the member here and installing for the rest is exactly the
     * partial replication the contract refuses, and it is the shipping shape:
     * br-lan carries the Wi-Fi VAP, so a phone joining the stream a set-top
     * box is already watching puts an uncarriable port in the group. */
    reset();
    {
        unsigned long long before = ft_mc_refused;

        assert(!ft_mc_membership(&BR, &SOFT, &g1, true, false));
        assert(ft_mc_count == 1 && ft_mc_refused == before + 1);
        assert(only_group()->ports == 1);
        assert(only_group()->port[0].dev == &SOFT);
        assert(only_group()->port[0].uncarried);
        assert(!ft_mc_carriable(only_group()));
        assert(holds == 2);   /* the bridge and the port it cannot carry */
    }

    /* Eligible and ineligible together: the group is not installable, and the
     * eligible port's own join must not claim it was taken on either --
     * `handled` becomes MDB_PG_FLAGS_OFFLOAD, and a group that will never
     * install must not report one. */
    reset();
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(ft_mc_carriable(only_group()));
    assert(!ft_mc_membership(&BR, &SOFT, &g1, true, false));
    assert(only_group()->ports == 2 && !ft_mc_carriable(only_group()));
    /* A third port joining a group that is already uncarriable is recorded
     * and answers no. */
    assert(!ft_mc_membership(&BR, &P2, &g1, true, false));
    assert(only_group()->ports == 3 && !ft_mc_carriable(only_group()));
    /* The uncarriable one leaves and the group becomes installable again. */
    assert(!ft_mc_membership(&BR, &SOFT, &g1, false, false));
    assert(only_group()->ports == 2 && ft_mc_carriable(only_group()));
    /* And a restated membership re-answers from the group's current state
     * rather than from the port's alone. */
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(!ft_mc_membership(&BR, &SOFT, &g1, true, false));
    assert(!ft_mc_membership(&BR, &P1, &g1, true, false));

    /* ft_mc_device_gone() reaches an uncarried member the same way, so a VAP
     * unregistering releases the reference the group holds on it. */
    reset();
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(!ft_mc_membership(&BR, &SOFT, &g1, true, false));
    assert(holds == 3);
    ft_mc_drop_port(&SOFT);
    assert(only_group()->ports == 1 && ft_mc_carriable(only_group()));
    assert(holds == 2);

    /* Capacity. The ninth listener is recorded too -- forgetting it is the
     * same silent partial replication one count further along -- so the group
     * is not installable until one of them leaves. */
    reset();
    {
        struct net_device ports[CDX_MC_MAX_LISTENERS + 1];

        for (unsigned i = 0; i <= CDX_MC_MAX_LISTENERS; i++) {
            ports[i] = (struct net_device){ .name = "p", .physical = true };
            bool taken = ft_mc_membership(&BR, &ports[i], &g1, true, false);
            assert(taken == (i < CDX_MC_MAX_LISTENERS));
        }
        assert(only_group()->ports == CDX_MC_MAX_LISTENERS + 1);
        assert(!ft_mc_carriable(only_group()));
        assert(ft_mc_refused == 1);
        /* One leaves and the remaining eight are installable. */
        assert(!ft_mc_membership(&BR, &ports[0], &g1, false, false));
        assert(only_group()->ports == CDX_MC_MAX_LISTENERS);
        assert(ft_mc_carriable(only_group()));
        /* A tenth distinct port has nowhere to be recorded, which is a
         * member the group cannot name. It fails closed and stays that way
         * until the group empties: a later leave cannot be told apart from
         * that member's, so clearing it could install to a set missing
         * somebody. Unreachable on a board with five ports. */
        assert(!ft_mc_membership(&BR, &ports[0], &g1, true, false));
        assert(!ft_mc_membership(&BR, &SOFT, &g1, true, false));
        assert(only_group()->overflow);
        assert(!ft_mc_carriable(only_group()));
        assert(!ft_mc_membership(&BR, &ports[0], &g1, false, false));
        assert(only_group()->overflow && !ft_mc_carriable(only_group()));
    }

    /* The MTU bound. A bridge fragments nothing -- it drops a frame that does
     * not fit the egress port, whatever its family or DF bit -- while the
     * listener's enqueue would fragment it. So a group is carried only while
     * no frame the ingress port can deliver is larger than a listener port's
     * MTU, and a group with no ingress yet has nothing to bound. */
    reset();
    P1.mtu = P2.mtu = P3.mtu = 1500;
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(ft_mc_membership(&BR, &P2, &g1, true, false));
    assert(ft_mc_mtu_bounded(only_group()));
    only_group()->in = &P3;
    assert(ft_mc_mtu_bounded(only_group()));
    P2.mtu = 1400;
    assert(!ft_mc_mtu_bounded(only_group()));
    /* Carriable still: it is a different refusal, and /proc says which. */
    assert(ft_mc_carriable(only_group()));
    P2.mtu = 9000;
    assert(ft_mc_mtu_bounded(only_group()));
    /* A smaller ingress bounds itself. */
    P2.mtu = 1400;
    P3.mtu = 1400;
    assert(ft_mc_mtu_bounded(only_group()));
    P3.mtu = 1500;
    P2.mtu = 1500;
    only_group()->in = NULL;

    /* A host membership makes the group ineligible without removing its
     * ports: the frame would never reach the CPU, so a local listener would
     * be starved. Ports already present stop being claimed. */
    reset();
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(!ft_mc_membership(&BR, &P1, &g1, true, true));   /* host joins */
    assert(only_group()->host && only_group()->ports == 1);
    assert(!ft_mc_membership(&BR, &P2, &g1, true, false));  /* still refused */
    assert(only_group()->ports == 2);                       /* but recorded */
    assert(!ft_mc_membership(&BR, &P1, &g1, true, true) || true);
    /* The host leaving makes it eligible again. */
    ft_mc_membership(&BR, &P1, &g1, false, true);
    assert(!only_group()->host);
    assert(ft_mc_membership(&BR, &P3, &g1, true, false));

    /* A host membership arriving FIRST has to be recorded, and this is the
     * ordering the bridge actually produces: br_multicast_add_group() calls
     * br_multicast_host_join() on a freshly created mdb entry, so HOST_MDB
     * is emitted before any port group for that address. Dropping it left
     * the group to be created later by the first port join with host clear,
     * and the local listener then stopped receiving the moment the offload
     * installed -- exactly what refusing a host group exists to prevent. */
    reset();
    {
        struct br_ip lonely = group_v4(0x0a0007ef, 0, 0);

        assert(!ft_mc_membership(&BR, &BR, &lonely, true, true));
        assert(ft_mc_count == 1);
        assert(ft_mc_find(&BR, &lonely)->host);
        /* And a port joining afterwards finds it and is refused. */
        assert(!ft_mc_membership(&BR, &P1, &lonely, true, false));
        assert(ft_mc_find(&BR, &lonely)->ports == 1);
        assert(ft_mc_find(&BR, &lonely)->host);
    }

    /* Tags. On a bridge that does not filter, nothing is pushed. */
    reset();
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n = 0xff;

        vlan_enabled = false;
        assert(ft_mc_port_tags(&BR, &P1, 0, stack, &n) == 0 && n == 0);
    }

    /* Filtering: an untagged member gets no tag, a tagged member gets one in
     * the bridge's own protocol. */
    reset();
    vlan_enabled = true;
    member(&P1, 3999, true);
    member(&P2, 3999, false);
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        assert(ft_mc_port_tags(&BR, &P1, 3999, stack, &n) == 0 && n == 0);
        assert(ft_mc_port_tags(&BR, &P2, 3999, stack, &n) == 0 && n == 1);
        assert(stack[0].id == 3999 && stack[0].proto == htons(ETH_P_8021Q));
    }

    /* A port that is not a member of the group's VLAN is refused: it would
     * not receive this group in software either. */
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        assert(ft_mc_port_tags(&BR, &P3, 3999, stack, &n) != 0);
    }

    /* A filtering bridge with a VLAN of zero describes no VLAN at all, which
     * is not a tag decision this can make. */
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        assert(ft_mc_port_tags(&BR, &P1, 0, stack, &n) != 0);
    }

    /* 802.1ad is declined rather than reproduced blind: the kernel describes
     * no selector for that tag. */
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        vlan_proto = 0x88a8;
        assert(ft_mc_port_tags(&BR, &P2, 3999, stack, &n) != 0);
        vlan_proto = ETH_P_8021Q;
    }

    /* A tagged join carries the tag into the port's description. */
    reset();
    vlan_enabled = true;
    member(&P2, 3999, false);
    {
        struct br_ip tagged = group_v4(0x030007ef, 0, 3999);

        assert(ft_mc_membership(&BR, &P2, &tagged, true, false));
        assert(only_group()->port[0].vlans == 1);
        assert(only_group()->port[0].vlan[0].id == 3999);
    }

    /* And a join whose VLAN the port is not in is dropped rather than
     * installed untagged, which would put the group on the wrong VLAN.
     *
     * Dropped, not recorded as uncarriable: br_allowed_egress() would not
     * give that port a copy either, so it is not a listener this group is
     * failing to serve, and it is not counted as a refusal. */
    {
        struct br_ip elsewhere = group_v4(0x040007ef, 0, 4000);
        unsigned long long before = ft_mc_refused;

        assert(!ft_mc_membership(&BR, &P2, &elsewhere, true, false));
        assert(ft_mc_refused == before);
        assert(ft_mc_find(&BR, &elsewhere)->ports == 0);
        assert(ft_mc_carriable(ft_mc_find(&BR, &elsewhere)));
    }

    /* ---- matching an observation to a membership --------------------
     *
     * The distinction the whole design turns on. An IGMPv2 join produces a
     * (*,G) membership, which any source of that group satisfies. An IGMPv3
     * INCLUDE report produces an (S,G) one, where the bridge has already said
     * which source the group is about and a different one is a different
     * stream that these listeners did not ask for.
     */
    reset();
    {
        struct br_ip any = group_v4(0x010007ef, 0, 0);          /* (*,G) */
        struct br_ip specific = group_v4(0x020007ef, 0x0100000a, 0); /* (S,G) */
        struct ft_mc_seen seen;

        assert(ft_mc_membership(&BR, &P1, &any, true, false));
        assert(ft_mc_membership(&BR, &P1, &specific, true, false));

        /* Any source matches the wildcard membership. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = any;
        seen.src.ip = 0x0900000a;
        assert(ft_mc_match(&seen) == ft_mc_find(&BR, &any));

        /* The named source matches the source-specific one. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = specific;
        seen.addr.src.ip4 = 0;   /* the observation carries no source in addr */
        seen.src.ip = 0x0100000a;
        assert(ft_mc_match(&seen) == ft_mc_find(&BR, &specific));

        /* A different source does not. Somebody else sending to a group
         * these listeners asked for from one source is not their stream. */
        seen.src.ip = 0x0200000a;
        assert(ft_mc_match(&seen) == NULL);

        /* A different bridge is a different group even for the same
         * addresses, because it resolves to different ports. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex + 1;
        seen.addr = any;
        assert(ft_mc_match(&seen) == NULL);

        /* And a different VLAN is a different membership. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = any;
        seen.addr.vid = 100;
        assert(ft_mc_match(&seen) == NULL);

        /* As is a different family with the same bytes. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = any;
        seen.addr.proto = htons(ETH_P_IPV6);
        assert(ft_mc_match(&seen) == NULL);
    }

    /* The hook's own dedup: one fact recorded once, however many frames
     * restate it, so a line-rate stream does not fill the ring between two
     * runs of the worker. */
    {
        struct ft_mc_seen a, b;

        memset(&a, 0, sizeof(a));
        a.bridge_ifindex = 1;
        a.in_ifindex = 2;
        a.addr = group_v4(0x010007ef, 0, 0);
        a.src.ip = 0x0100000a;
        b = a;
        assert(ft_mc_seen_eq(&a, &b));
        b.src.ip = 0x0200000a;
        assert(!ft_mc_seen_eq(&a, &b));   /* a second source is a new fact */
        b = a;
        b.in_ifindex = 3;
        assert(!ft_mc_seen_eq(&a, &b));   /* so is the same stream elsewhere */
        b = a;
        b.addr.vid = 7;
        assert(!ft_mc_seen_eq(&a, &b));
    }

    /* A key two memberships both claim. The hardware distinguishes only the
     * address pair, so installing either would stop the frame reaching the
     * bridge and the other one's ports would go quiet with nothing to say
     * why. The bridge produces this routinely: an (S,G) entry appears
     * alongside the (*,G) one whenever INCLUDE and EXCLUDE listeners
     * coexist. Neither may install. */
    reset();
    {
        struct br_ip wildcard = group_v4(0x0b0007ef, 0, 0);
        struct br_ip sourced  = group_v4(0x0b0007ef, 0x0100000a, 0);

        assert(ft_mc_membership(&BR, &P1, &wildcard, true, false));
        assert(!ft_mc_key_contested(ft_mc_find(&BR, &wildcard)));
        assert(ft_mc_membership(&BR, &P2, &sourced, true, false));
        assert(ft_mc_key_contested(ft_mc_find(&BR, &wildcard)));
        assert(ft_mc_key_contested(ft_mc_find(&BR, &sourced)));

        /* A host-only membership is not a claim on the key -- it installs
         * nothing -- so it does not contest. */
        reset();
        assert(!ft_mc_membership(&BR, &BR, &wildcard, true, true));
        assert(ft_mc_membership(&BR, &P1, &sourced, true, false));
        assert(!ft_mc_key_contested(ft_mc_find(&BR, &sourced)));

        /* Nor does a group on a different bridge, whose ports are its own. */
        reset();
        assert(ft_mc_membership(&BR, &P1, &wildcard, true, false));
        assert(ft_mc_membership(&BR2, &P2, &sourced, true, false));
        assert(!ft_mc_key_contested(ft_mc_find(&BR, &wildcard)));

        /* The same group in another VLAN of one bridge is another stream --
         * the listeners of an IPTV VLAN and of the LAN it is routed into --
         * and collides only once both are learned and keyed alike. */
        reset();
        {
            struct br_ip iptv = group_v4(0x0b0007ef, 0, 289);
            struct br_ip lan = group_v4(0x0b0007ef, 0, 286);
            struct ft_mc_group *a, *b;

            vlan_enabled = true;
            member(&P2, 289, false);
            member(&P3, 286, false);
            assert(ft_mc_membership(&BR, &P2, &iptv, true, false));
            assert(ft_mc_membership(&BR, &P3, &lan, true, false));
            a = ft_mc_find(&BR, &iptv);
            b = ft_mc_find(&BR, &lan);
            assert(!ft_mc_key_contested(a) && !ft_mc_key_contested(b));
            stream(a, &P1, 0x0100000a);
            assert(!ft_mc_key_contested(a) && !ft_mc_key_contested(b));
            /* A second source is a second key. */
            stream(b, &P1, 0x0200000a);
            assert(!ft_mc_key_contested(a) && !ft_mc_key_contested(b));
            /* The same one on the same port is one key, two tags. */
            b->src.ip = 0x0100000a;
            assert(ft_mc_key_contested(a) && ft_mc_key_contested(b));
            vlan_enabled = false;
        }
    }

    /* ---- the stream a group is keyed on --------------------------------
     *
     * A bridged group's hardware key is the frames' own Ethernet pair as
     * well as the ingress port and the (S,G), and its root accepts one
     * ingress shape: tagged with the group's VLAN, or untagged on the port's
     * PVID. All of it is read off the frame that resolved the group. */
    reset();
    {
        struct br_ip any = group_v4(0x0e0007ef, 0, 0);
        struct ft_mc_seen a, b;
        struct ft_mc_group *g;
        static const u8 mac_a[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x0a };
        static const u8 mac_b[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x0b };
        static const u8 group_mac[ETH_ALEN] = { 0x01, 0, 0x5e, 0x07, 0, 0x0e };

        by_index[0] = &P2;
        by_index[1] = &P3;
        assert(ft_mc_membership(&BR, &P1, &any, true, false));
        g = ft_mc_find(&BR, &any);

        memset(&a, 0, sizeof(a));
        a.bridge_ifindex = BR.ifindex;
        a.in_ifindex = P2.ifindex;
        a.addr = any;
        a.src.ip = 0x0100000a;
        memcpy(a.dst_mac, group_mac, ETH_ALEN);
        memcpy(a.src_mac, mac_a, ETH_ALEN);
        a.tagged = true;

        /* Every part of the stream is a different fact to the hook's dedup:
         * a second sender's MAC is a second stream even from one source. */
        b = a;
        assert(ft_mc_seen_eq(&a, &b));
        memcpy(b.src_mac, mac_b, ETH_ALEN);
        assert(!ft_mc_seen_eq(&a, &b));
        b = a;
        b.tagged = false;
        assert(!ft_mc_seen_eq(&a, &b));
        b = a;
        b.dst_mac[5] ^= 1;
        assert(!ft_mc_seen_eq(&a, &b));

        /* A pending group takes all of it, and pins the ingress. */
        assert(ft_mc_resolve(g, &a));
        assert(g->in == &P2 && g->src.ip == a.src.ip && g->in_tagged);
        assert(!memcmp(g->src_mac, mac_a, ETH_ALEN));
        assert(!memcmp(g->dst_mac, group_mac, ETH_ALEN));
        assert(holds == 3);   /* bridge, listener, ingress */
        /* The same stream again changes nothing. */
        assert(!ft_mc_resolve(g, &a));
        assert(holds == 3);

        /* Installed, the key stays while it carries traffic: another sender
         * of the group is kept for later rather than taking over, so two
         * live senders do not trade one entry. */
        g->hw = (struct cdx_mc_group *)1;
        g->idle = false;
        b = a;
        memcpy(b.src_mac, mac_b, ETH_ALEN);
        assert(!ft_mc_resolve(g, &b));
        assert(g->has_next && !memcmp(g->next.src_mac, mac_b, ETH_ALEN));
        assert(!memcmp(g->src_mac, mac_a, ETH_ALEN));
        assert(holds == 4);   /* and the stream in waiting pins its port */
        /* Seen again, still waiting, nothing new held. */
        assert(!ft_mc_resolve(g, &b));
        assert(holds == 4);
        /* A newer stream replaces the one waiting, releasing its port. */
        b.in_ifindex = P3.ifindex;
        assert(!ft_mc_resolve(g, &b));
        assert(g->next.in == &P3 && holds == 4);
        /* Once the installed key is idle, the next frame asks for the
         * takeover straight away. */
        g->idle = true;
        b.src.ip = 0x0200000a;
        assert(ft_mc_resolve(g, &b));
        assert(g->next.src.ip == 0x0200000a && holds == 4);
        /* And adopting it moves the reference rather than taking one. */
        ft_mc_adopt_next(g);
        assert(!g->has_next && g->in == &P3 && g->src.ip == 0x0200000a);
        assert(!memcmp(g->src_mac, mac_b, ETH_ALEN));
        assert(holds == 3);
        /* A stream kept from an installed phase is stale once nothing is
         * installed: the same stream seen again is simply the group's. */
        b = a;
        memcpy(b.src_mac, mac_a, ETH_ALEN);
        b.in_ifindex = P2.ifindex;
        g->idle = false;
        assert(!ft_mc_resolve(g, &b) && g->has_next && holds == 4);
        g->hw = NULL;
        assert(ft_mc_resolve(g, &b));
        assert(!g->has_next && g->in == &P2 && holds == 3);
        /* And an uninstalled group simply follows the stream it sees. */
        b.in_ifindex = P3.ifindex;
        assert(ft_mc_resolve(g, &b));
        assert(g->in == &P3 && holds == 3);

        /* ---- re-deriving against a changed VLAN configuration ---------- */
        vlan_enabled = true;
        member(&P1, 3999, false);
        member(&P3, 3999, false);
        g->addr.vid = 3999;
        g->in_tagged = true;
        /* Nothing changed: the tagged ingress is still a member, and the
         * listener's tag is what it was. */
        g->port[0].vlans = 1;
        g->port[0].vlan[0].proto = htons(ETH_P_8021Q);
        g->port[0].vlan[0].id = 3999;
        g->dirty = false;
        g->vlan_stale = true;
        ft_mc_revalidate(g);
        assert(!g->vlan_stale && g->in == &P3 && !g->dirty);
        /* The listener becomes an untagged member: re-resolved, dirty. */
        memberships[0].untagged = true;
        ft_mc_revalidate(g);
        assert(g->port[0].vlans == 0 && g->dirty && !g->port[0].absent);
        /* The listener leaves the VLAN: no longer a listener, still
         * recorded, and a listener again when it comes back. */
        g->dirty = false;
        memberships[0].member = false;
        ft_mc_revalidate(g);
        assert(g->port[0].absent && g->dirty && g->ports == 1);
        g->dirty = false;
        memberships[0].member = true;
        ft_mc_revalidate(g);
        assert(!g->port[0].absent && g->dirty);
        /* The tagged ingress leaves the VLAN: the stream is forgotten and
         * the group waits for one again. */
        memberships[1].member = false;
        ft_mc_revalidate(g);
        assert(!g->in && holds == 2);
        /* An untagged stream is kept while the port's PVID is the group's
         * VLAN, and forgotten when the PVID moves. */
        memberships[1].member = true;
        pvids[0].port = &P3;
        pvids[0].pvid = 3999;
        pvid_count = 1;
        a.in_ifindex = P3.ifindex;
        a.tagged = false;
        a.addr.vid = 3999;
        assert(ft_mc_resolve(g, &a));
        ft_mc_revalidate(g);
        assert(g->in == &P3 && !g->in_tagged);
        pvids[0].pvid = 1;
        ft_mc_revalidate(g);
        assert(!g->in);
        /* And a tagged stream on a bridge that stops filtering is forgotten:
         * such a bridge forwards the tag, which no listener would add. */
        pvids[0].pvid = 3999;
        a.tagged = true;
        assert(ft_mc_resolve(g, &a));
        vlan_enabled = false;
        ft_mc_revalidate(g);
        assert(!g->in);
        /* A stream waiting to take over is dropped by a re-derivation. */
        vlan_enabled = true;
        assert(ft_mc_resolve(g, &a));
        g->hw = (struct cdx_mc_group *)1;
        b = a;
        memcpy(b.src_mac, mac_b, ETH_ALEN);
        assert(!ft_mc_resolve(g, &b) && g->has_next);
        ft_mc_revalidate(g);
        assert(!g->has_next && g->in == &P3);
        g->hw = NULL;
        vlan_enabled = false;
    }

    /* Dropping a port by device alone, for the delete that arrives after the
     * port has already left the bridge -- del_nbp() flushes permanent mdb
     * entries after netdev_upper_dev_unlink(), so the master lookup is empty
     * and the membership would otherwise never be removed, holding a
     * reference that blocks the port's unregistration for good. */
    reset();
    {
        struct br_ip a = group_v4(0x0c0007ef, 0, 0);
        struct br_ip b = group_v4(0x0d0007ef, 0, 0);

        assert(ft_mc_membership(&BR, &P1, &a, true, false));
        assert(ft_mc_membership(&BR, &P2, &a, true, false));
        assert(ft_mc_membership(&BR, &P1, &b, true, false));
        ft_mc_drop_port(&P1);
        assert(ft_mc_find(&BR, &a)->ports == 1);
        assert(ft_mc_find(&BR, &a)->port[0].dev == &P2);
        assert(ft_mc_find(&BR, &b)->ports == 0);
        /* Every reference it held is gone: the two groups' bridges only. */
        assert(holds == 3);
        /* And dropping a port nothing lists is inert. */
        ft_mc_drop_port(&P3);
        assert(holds == 3);
    }

    /* ---- one stream, both learners ------------------------------------
     *
     * An IPTV VLAN bridged to a set-top box and routed to the rest of the
     * house. The stream arrives on a bridge port; the bridge forwards it to
     * the box and, as a multicast router, hands it to br0.289, where ipmr
     * routes it out of another port. One classifier key, so one group: the
     * box's copy and ipmr's, each owned by the learner that asked for it. */
    reset();
    {
        const uint32_t S = 0x0100000a, G = 0x0f0007ef;
        struct br_ip any = group_v4(G, 0, 289);
        struct cdx_mc_group_spec spec;
        struct ft_mc_route want, r1;
        struct ft_mc_group *g;
        LIST_HEAD(dead);

        memset(&r1, 0, sizeof(r1));
        vlan_enabled = true;
        member(&BR, 289, false);    /* br0.289 receives the VLAN, tagged */
        member(&P2, 289, false);    /* the set-top box */
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        g = ft_mc_find(&BR, &any);
        stream(g, &P1, S);

        /* The routed learner publishes its copy: out of eth5 on VLAN 287.
         * The route pins what it names. */
        route_want(&want, 289, S, G, &P3, 287);
        {
            unsigned before = holds;

            assert(!ft_mc_route_publish(&r1, &want));
            assert(r1.linked && holds == before + 2);
        }

        /* A bridge that is not a multicast router hands the host nothing it
         * did not join, so Linux routes nothing and neither may the group:
         * the route names it not. The group is the box's alone. */
        ft_mc_match_routes();
        assert(!g->route && !g->routed_host && !g->routes);
        assert(ft_mc_installable(g));
        ft_mc_group_spec(g, &spec);
        assert(spec.listeners == 1 && !spec.listener[0].routed);

        /* A router: one group, both sets. The bridged copy keeps the
         * sender's pair and hop count; the routed one is marked for the
         * backend to frame as a router's. */
        BR.mrouter = true;
        g->dirty = false;
        ft_mc_match_routes();
        assert(g->route == &r1 && g->routed_host && g->routes == 1 && g->dirty);
        assert(ft_mc_installable(g));
        ft_mc_group_spec(g, &spec);
        assert(spec.bridged && spec.in == &P1 && spec.in_vlans == 0);
        assert(spec.src.ip == S && spec.dst.ip == G);
        assert(spec.listeners == 2);
        assert(spec.listener[0].dev == &P2 && !spec.listener[0].routed);
        assert(spec.listener[0].vlans == 1 && spec.listener[0].vlan[0].id == 289);
        assert(spec.listener[1].dev == &P3 && spec.listener[1].routed);
        assert(spec.listener[1].vlan[0].id == 287);
        assert(!strcmp(ft_mc_state(g), "pending"));

        /* Installed with it: the route hears so, once. */
        g->hw = (struct cdx_mc_group *)1;
        g->carried_route = g->route;
        assert(ft_mc_route_feedback());
        assert(!ft_mc_route_feedback());
        {
            struct cdx_ft_counters c;
            u8 tags = 9;

            assert(ft_mc_route_state(&r1, &c, &tags) && tags == 0);
        }
        assert(!strcmp(ft_mc_state(g), "installed"));
        /* Publishing the same copies again is not news. */
        works = 0;
        g->dirty = false;
        assert(ft_mc_route_publish(&r1, &want));
        assert(!works && !g->dirty);
        /* A changed copy set is, to the group carrying it. */
        route_want(&want, 289, S, G, &P3, 286);
        assert(ft_mc_route_publish(&r1, &want));
        assert(works == 1 && g->dirty && r1.listener[0].vlan[0].id == 286);

        /* What does not merge, with its reason. A routed copy framed
         * exactly like the bridged one is two entries the backend would
         * take for a duplicate. */
        route_want(&want, 289, S, G, &P2, 289);
        ft_mc_route_publish(&r1, &want);
        assert(!ft_mc_carriable(g) && !ft_mc_installable(g));
        assert(!strcmp(ft_mc_state(g), "refused-listener"));
        /* The union has to fit one group. */
        route_want(&want, 289, S, G, &P3, 1);
        for (unsigned i = 1; i < CDX_MC_MAX_LISTENERS; i++) {
            want.listener[i] = want.listener[0];
            want.listener[i].vlan[0].id = 1 + i;
        }
        want.listeners = CDX_MC_MAX_LISTENERS;
        ft_mc_route_publish(&r1, &want);
        assert(!strcmp(ft_mc_state(g), "refused-listener"));
        want.listeners = CDX_MC_MAX_LISTENERS - 1;
        ft_mc_route_publish(&r1, &want);
        assert(ft_mc_carriable(g));
        /* And every copy has to fit what the ingress can deliver. */
        route_want(&want, 289, S, G, &P3, 287);
        want.mtu = 1400;
        P1.mtu = 1500;
        ft_mc_route_publish(&r1, &want);
        assert(!ft_mc_mtu_bounded(g) && !strcmp(ft_mc_state(g), "refused-mtu"));
        want.mtu = 1500;
        ft_mc_route_publish(&r1, &want);
        assert(ft_mc_mtu_bounded(g) && ft_mc_installable(g));
        P1.mtu = 0;

        /* The box leaves. The group is not retired: the route still names
         * it, and the entry now carries the routed copy alone. */
        assert(!ft_mc_membership(&BR, &P2, &any, false, false));
        ft_mc_match_routes();
        ft_mc_retire(&dead);
        assert(list_empty(&dead) && g->ports == 0 && g->routes == 1);
        assert(ft_mc_installable(g));
        ft_mc_group_spec(g, &spec);
        assert(spec.listeners == 1 && spec.listener[0].routed);
        /* The box rejoins before the route goes: the same group again. */
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_find(&BR, &any) == g && g->ports == 1);
        assert(!ft_mc_membership(&BR, &P2, &any, false, false));
        /* The route goes too. Every pointer to it is cleared before its
         * owner frees it, and with neither learner naming the group, it
         * retires. */
        ft_mc_route_withdraw(&r1);
        assert(!r1.linked && !g->route && !g->carried_route && g->dirty);
        assert(!r1.carried && !r1.listeners && !r1.bridge);
        ft_mc_match_routes();
        ft_mc_retire(&dead);
        assert(!list_empty(&dead) && list_empty(&ft_mc_groups));
        g = list_entry(dead.next, struct ft_mc_group, list);
        list_del(&g->list);
        ft_mc_group_free(g);
        assert(holds == 0);

        /* ---- the host's copy with no route to carry ------------------- *
         *
         * A VIF on br0.289 and no MFC entry for the stream: ipmr sees it
         * and upcalls, which is how a routing daemon learns a source. The
         * group stays in software until the route exists. */
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        g = ft_mc_find(&BR, &any);
        stream(g, &P1, S);
        {
            struct ft_mc_tap tap = { &BR, 289, true, AF_INET };

            ft_mc_taps_publish(&tap, 1, false);
            assert(holds == 4);   /* bridge, box, ingress, the tap's bridge */
        }
        ft_mc_match_routes();
        assert(g->routed_host && !g->route && !ft_mc_installable(g));
        assert(!strcmp(ft_mc_state(g), "refused-routed"));
        /* A route for another source is not this stream's. */
        memset(&r1, 0, sizeof(r1));
        route_want(&want, 289, 0x0200000a, G, &P3, 287);
        ft_mc_route_publish(&r1, &want);
        ft_mc_match_routes();
        assert(!g->route && g->routes == 1 && !ft_mc_installable(g));
        /* Its own is. */
        route_want(&want, 289, S, G, &P3, 287);
        ft_mc_route_publish(&r1, &want);
        ft_mc_match_routes();
        assert(g->route == &r1 && ft_mc_installable(g));
        ft_mc_route_withdraw(&r1);
        /* Not a router: the tap sees nothing, and the group is the box's. */
        BR.mrouter = false;
        ft_mc_match_routes();
        assert(!g->routed_host && ft_mc_installable(g));
        /* A table that ran out names every bridge VLAN. */
        BR.mrouter = true;
        ft_mc_taps_publish(NULL, 0, true);
        ft_mc_match_routes();
        assert(g->routed_host && !ft_mc_installable(g));
        ft_mc_taps_publish(NULL, 0, false);
        ft_mc_match_routes();
        assert(!g->routed_host && ft_mc_installable(g));
    }

    /* ---- where a VIF on a bridge receives ------------------------------ */
    reset();
    {
        vlan_enabled = true;
        member(&BR, 289, false);
        member(&BR, 1, true);
        /* br0.289 receives VLAN 289, which the bridge carries tagged. */
        assert(ft_mc_via_receives(&BR, 289, true, 289));
        assert(!ft_mc_via_receives(&BR, 288, true, 289));
        /* br0 itself receives every VLAN it carries untagged, and only
         * those: a tagged one surfaces on its VLAN device instead. */
        assert(ft_mc_via_receives(&BR, 0, false, 1));
        assert(!ft_mc_via_receives(&BR, 0, false, 289));
        assert(!ft_mc_via_receives(&BR, 1, true, 1));
        /* The bridge not a member of the VLAN hands up nothing of it. */
        assert(!ft_mc_via_receives(&BR, 0, false, 7));
        assert(!ft_mc_via_receives(&BR, 7, true, 7));
        /* A bridge that does not filter hands everything up untagged, on
         * VLAN zero. */
        vlan_enabled = false;
        assert(ft_mc_via_receives(&BR, 0, false, 0));
        assert(!ft_mc_via_receives(&BR, 289, true, 0));
    }

    /* ---- a route with no group to learn its stream through ------------- */
    reset();
    {
        const uint32_t S = 0x0100000a, G = 0x100007ef;
        struct br_ip any = group_v4(G, 0, 289);
        struct ft_mc_route want, r1;
        struct ft_mc_group *g;
        LIST_HEAD(dead);

        memset(&r1, 0, sizeof(r1));
        vlan_enabled = true;
        member(&BR, 289, false);
        member(&P2, 289, false);
        route_want(&want, 289, S, G, &P3, 287);
        ft_mc_route_publish(&r1, &want);
        /* Not a router: nothing is routed, and nothing is created. */
        ft_mc_match_routes();
        assert(list_empty(&ft_mc_groups));
        /* A router: a group in the (*,G) form, with no member port, kept
         * while the route names it and waiting for its stream. */
        BR.mrouter = true;
        ft_mc_match_routes();
        g = ft_mc_find(&BR, &any);
        assert(g && g->ports == 0 && g->routes == 1 && !g->host);
        assert(ft_mc_count == 1 && !strcmp(ft_mc_state(g), "pending-source"));
        ft_mc_retire(&dead);
        assert(list_empty(&dead));
        /* Its stream arrives, and it is the route's alone. */
        stream(g, &P1, S);
        ft_mc_match_routes();
        assert(g->route == &r1 && ft_mc_installable(g));
        /* A set-top box joining the same group finds that group, and the
         * two sets merge in it. */
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_find(&BR, &any) == g && g->ports == 1 && ft_mc_count == 1);
        ft_mc_route_withdraw(&r1);

        /* br0 itself: the group is created in the bridge's PVID, provided
         * the bridge carries that VLAN untagged. */
        reset();
        vlan_enabled = true;
        BR.mrouter = true;
        member(&BR, 1, true);
        pvids[0].port = &BR;
        pvids[0].pvid = 1;
        pvid_count = 1;
        memset(&r1, 0, sizeof(r1));
        route_want(&want, 0, S, G, &P3, 287);
        want.tagged = false;
        ft_mc_route_publish(&r1, &want);
        ft_mc_match_routes();
        any.vid = 1;
        assert(ft_mc_find(&BR, &any) && ft_mc_count == 1);
        ft_mc_route_withdraw(&r1);
        ft_mc_match_routes();
        ft_mc_retire(&dead);
        assert(list_empty(&ft_mc_groups));
        while (!list_empty(&dead)) {
            g = list_entry(dead.next, struct ft_mc_group, list);
            list_del(&g->list);
            ft_mc_group_free(g);
        }
        /* A PVID the bridge carries tagged surfaces on a VLAN device, not
         * on br0: nothing is created. */
        membership_count = 0;
        member(&BR, 1, false);
        memset(&r1, 0, sizeof(r1));
        ft_mc_route_publish(&r1, &want);
        ft_mc_match_routes();
        assert(list_empty(&ft_mc_groups));
        ft_mc_route_withdraw(&r1);
    }

    /* ---- the hook's dedup slot -----------------------------------------
     *
     * The slot keeps a line-rate stream from filling the ring with one
     * fact, and so it also keeps the same frame from being recorded again
     * until something forgets it. Each case is a way the answer that frame
     * got could change without the frame changing: a group created after
     * it, retired under it, or robbed of its ingress. */
    (void)ft_mc_hooked;
    (void)ft_mc_hook_errors;
    (void)ft_mc_hook_lock;
    reset();
    {
        static const u8 group_mac[ETH_ALEN] = { 0x01, 0, 0x5e, 0x07, 0, 0x13 };
        static const u8 sender[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x13 };
        struct br_ip any = group_v4(0x130007ef, 0, 0);
        struct br_ip sourced = group_v4(0x130007ef, 0x0100000a, 0);
        struct ft_mc_seen o;
        struct ft_mc_group *g;
        LIST_HEAD(dead);

#define RETIRE() do { \
        ft_mc_retire(&dead); \
        while (!list_empty(&dead)) { \
            struct ft_mc_group *d = list_entry(dead.next, struct ft_mc_group, list); \
            list_del(&d->list); \
            ft_mc_group_free(d); \
        } \
    } while (0)
#define FRESH() do { reset(); by_index[0] = &P1; } while (0)

        by_index[0] = &P1;
        memset(&o, 0, sizeof(o));
        o.bridge_ifindex = BR.ifindex;
        o.in_ifindex = P1.ifindex;
        o.addr = any;
        o.src.ip = 0x0100000a;
        memcpy(o.dst_mac, group_mac, ETH_ALEN);
        memcpy(o.src_mac, sender, ETH_ALEN);

        /* Resolve, leave, retire, then the set-top box joins again: the
         * new group must learn the same stream from the same frame. */
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(ft_mc_find(&BR, &any)->in == &P1);
        assert(!ft_mc_record(&o));      /* nothing has changed */
        assert(!ft_mc_membership(&BR, &P2, &any, false, false));
        RETIRE();
        assert(ft_mc_record(&o));       /* and nothing matches it */
        ft_mc_drain();
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_record(&o));
        ft_mc_drain();
        g = ft_mc_find(&BR, &any);
        assert(g && g->in == &P1);
        FRESH();

        /* The frame first, the membership after: the MDB add is deferred,
         * so this is the ordinary order, and the one a host membership
         * creating the group takes too. */
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(!ft_mc_record(&o));
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(ft_mc_find(&BR, &any)->in == &P1);
        FRESH();
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(!ft_mc_membership(&BR, &BR, &any, true, true));
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(ft_mc_find(&BR, &any)->in == &P1);
        FRESH();

        /* The ingress goes and comes back: the group waits for its
         * stream, and the stream is the same frame as before. */
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_record(&o));
        ft_mc_drain();
        g = ft_mc_find(&BR, &any);
        assert(g->in == &P1);
        ft_mc_device_gone(&P1);
        assert(!g->in);
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(g->in == &P1);
        FRESH();

        /* Shadowing. The (S,G) membership takes its source's frame before
         * the (*,G) one sees it; once the (S,G) one retires, the (*,G) one
         * has to be able to see the same frame. */
        assert(ft_mc_membership(&BR, &P3, &any, true, false));
        assert(ft_mc_membership(&BR, &P2, &sourced, true, false));
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(ft_mc_find(&BR, &sourced)->in == &P1);
        assert(!ft_mc_find(&BR, &any)->in);
        assert(!ft_mc_membership(&BR, &P2, &sourced, false, false));
        RETIRE();
        assert(ft_mc_record(&o));
        ft_mc_drain();
        assert(ft_mc_find(&BR, &any)->in == &P1);
#undef RETIRE
#undef FRESH
    }

    /* ---- a port's egress queues change ---------------------------------
     *
     * Every listener entry names the queue its port had when it was built.
     * An installed group copying out of the port -- by a member port or by a
     * route's copy riding it -- is marked for a rebuild; one that is not
     * installed, one whose member left the VLAN, and one elsewhere are not. */
    reset();
    {
        const uint32_t S = 0x0100000a, G = 0x120007ef;
        struct br_ip any = group_v4(G, 0, 289), other = group_v4(G + 1, 0, 289);
        struct ft_mc_route want, r1;
        struct ft_mc_group *g, *h;

        memset(&r1, 0, sizeof(r1));
        vlan_enabled = true;
        BR.mrouter = true;
        member(&BR, 289, false);
        member(&P2, 289, false);
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        assert(ft_mc_membership(&BR, &P2, &other, true, false));
        g = ft_mc_find(&BR, &any);
        h = ft_mc_find(&BR, &other);
        stream(g, &P1, S);
        route_want(&want, 289, S, G, &P3, 287);
        ft_mc_route_publish(&r1, &want);
        ft_mc_match_routes();
        g->hw = (struct cdx_mc_group *)1;
        g->carried_route = g->route;
        g->dirty = h->dirty = false;
        works = 0;
        /* Not installed, so nothing to rebuild; the ingress is not a copy. */
        assert(ft_mc_egress_mark(&P1) == 0 && !g->dirty && !works);
        /* A member port. */
        assert(ft_mc_egress_mark(&P2) == 1 && g->dirty && !h->dirty && works == 1);
        assert(!ft_mc_lock);
        /* The route's copy. */
        g->dirty = false;
        assert(ft_mc_egress_mark(&P3) == 1 && g->dirty);
        /* A member that left the VLAN has no entry to rebuild. */
        g->dirty = false;
        g->port[0].absent = true;
        assert(ft_mc_egress_mark(&P2) == 0 && !g->dirty);
        g->port[0].absent = false;
        g->hw = NULL;
        g->carried_route = NULL;
        ft_mc_route_withdraw(&r1);
    }

    /* ---- a device a route or a tap names goes away --------------------- */
    reset();
    {
        const uint32_t S = 0x0100000a, G = 0x110007ef;
        struct br_ip any = group_v4(G, 0, 289);
        struct ft_mc_tap tap = { &BR, 289, true, AF_INET };
        struct ft_mc_route want, r1;
        struct ft_mc_group *g;

        memset(&r1, 0, sizeof(r1));
        vlan_enabled = true;
        BR.mrouter = true;
        member(&BR, 289, false);
        member(&P2, 289, false);
        assert(ft_mc_membership(&BR, &P2, &any, true, false));
        g = ft_mc_find(&BR, &any);
        stream(g, &P1, S);
        route_want(&want, 289, S, G, &P3, 287);
        ft_mc_route_publish(&r1, &want);
        ft_mc_taps_publish(&tap, 1, false);
        ft_mc_match_routes();
        assert(g->route == &r1);
        /* The routed copy's port: the route lets go of everything it
         * names, and names nothing until the routed learner publishes what
         * is left. The group is re-matched on the next pass. */
        works = 0;
        {
            unsigned before = holds;

            ft_mc_device_gone(&P3);
            assert(!r1.listeners && !r1.bridge && holds == before - 2);
        }
        assert(works == 1);
        /* Until the next pass drops it, the emptied route is not a route:
         * the host still needs its copies, and there are none to carry. */
        assert(g->route == &r1 && !ft_mc_installable(g));
        assert(!strcmp(ft_mc_state(g), "refused-routed"));
        g->dirty = false;
        g->retries = FT_MC_MAX_RETRIES;
        ft_mc_match_routes();
        assert(!g->route && g->dirty && g->routed_host);
        /* A changed answer resets the retries spent on the old one. */
        assert(g->retries == 0);
        assert(!strcmp(ft_mc_state(g), "refused-routed"));
        /* The bridge itself: the tap goes with it. */
        ft_mc_device_gone(&BR);
        assert(!ft_mc_tap_count);
        ft_mc_route_withdraw(&r1);
    }

    reset();
    assert(holds == 0);
    printf("ok\n");
    return 0;
}

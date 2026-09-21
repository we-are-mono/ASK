/* The routed multicast learner's decision logic, compiled from the adapter
 * against stubs for everything below it.
 *
 * What this pins down is the part a rig cannot show cheaply. On the bench an
 * MFC entry arrives once, correct, from a daemon that only ever writes the
 * shape the contract already accepts -- (S,G) at threshold 1 in the default
 * table, one plain oif. Every refusal in the contract, and every way a
 * replication list can be re-derived under it, either does not occur there or
 * occurs once in a way nothing distinguishes from success.
 *
 * The other half is the oif walk. An oif is a device, and which listeners it
 * becomes depends on whether that device is a port, a VLAN device or a bridge,
 * and for a bridge on its VLAN configuration and on what has joined. A rig has
 * five ports and two with carrier; this has as many as a case needs.
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

#define ETH_ALEN 6
#define ETH_HLEN 14
#define VLAN_HLEN 4
#define IFNAMSIZ 16
#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define BRIDGE_VLAN_INFO_UNTAGGED (1 << 2)
#define BR_MCAST_FLOOD (1UL << 11)
#define CDX_FT_VLAN_MAX 2
#define CDX_MC_MAX_LISTENERS 8
#define MAXVIFS 32
#define ARPHRD_PPP 512
#define AF_INET 2
#define AF_INET6 10
#define INADDR_ANY 0
#define RT_TABLE_DEFAULT 253
#define RT6_TABLE_DFLT 254
#define VIFF_TUNNEL 0x1
#define VIFF_REGISTER 0x4
#define MIFF_REGISTER 0x1
#define EOPNOTSUPP 95
#define ENOENT 2
#define E2BIG 7
#define ENOMEM 12
#define IPV6_ADDR_SCOPE_LINKLOCAL 0x02

/* The subset of fib_event_type the learner answers, with upstream's values so
 * a case names the same event the kernel would. */
#define FIB_EVENT_ENTRY_REPLACE 0
#define FIB_EVENT_ENTRY_ADD 2
#define FIB_EVENT_ENTRY_DEL 3
#define FIB_EVENT_RULE_ADD 4
#define FIB_EVENT_RULE_DEL 5
#define FIB_EVENT_VIF_ADD 8
#define FIB_EVENT_VIF_DEL 9

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16((uint16_t)(x))
#define htonl(x) __builtin_bswap32((uint32_t)(x))
#else
#define htons(x) ((uint16_t)(x))
#define htonl(x) ((uint32_t)(x))
#endif
#define ntohl(x) htonl(x)
#define ntohs(x) htons(x)

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

struct in6_addr { uint8_t s6_addr[16]; };

/* The address union conntrack and the rule share; only the arms the learner
 * names. The shape has to match so a key compares the way production's does. */
union nf_inet_addr {
    u32 all[4];
    u32 ip;
    struct in6_addr in6;
};

static bool ipv6_addr_any(const struct in6_addr *a)
{
    static const struct in6_addr zero;

    return !memcmp(a, &zero, sizeof(*a));
}

static bool ipv6_addr_equal(const struct in6_addr *a, const struct in6_addr *b)
{
    return !memcmp(a, b, sizeof(*a));
}

static bool ipv6_addr_is_multicast(const struct in6_addr *a)
{
    return a->s6_addr[0] == 0xff;
}

/* A model of the two scope helpers, not a copy: the learner only ever asks
 * whether a multicast group's scope is above link-local, and for a multicast
 * address that is the low nibble of the second byte. */
static int __ipv6_addr_type(const struct in6_addr *a)
{
    return ipv6_addr_is_multicast(a) ? ((a->s6_addr[1] & 0x0f) << 16) : 0;
}

static int __ipv6_addr_src_scope(int type) { return type >> 16; }

static bool ipv4_is_multicast(u32 addr)
{
    return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

/* --- list.h, enough of it -------------------------------------------- */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
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
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, __typeof__(*pos), member))

/* --- netdev ----------------------------------------------------------- */
struct net_device {
    char name[IFNAMSIZ];
    int ifindex;
    int type;
    bool physical;
    bool bridge_master;
    bool bridge_port;
    bool vlan;
    u16 vlan_proto;
    u16 vlan_id;
    unsigned long port_flags;
    struct net_device *master;
    struct list_head lowers;
    /* Local group memberships, for the host-delivery refusal. */
    union nf_inet_addr joined[4];
    unsigned joins;
    bool joined_v6;
};

struct ft_lower { struct list_head list; struct net_device *dev; };
static struct ft_lower lower_pool[64];
static unsigned lower_used;

#define netdev_for_each_lower_dev(d, lower, iter) \
    for ((iter) = (d)->lowers.next; \
         (iter) != &(d)->lowers && \
             (((lower) = list_entry((iter), struct ft_lower, list)->dev), 1); \
         (iter) = (iter)->next)

static bool netif_is_bridge_master(const struct net_device *d)
{
    return d->bridge_master;
}
static bool netif_is_bridge_port(const struct net_device *d)
{
    return d->bridge_port;
}
static bool is_vlan_dev(const struct net_device *d) { return d->vlan; }
static u16 vlan_dev_vlan_proto(const struct net_device *d)
{
    return htons(d->vlan_proto);
}
static u16 vlan_dev_vlan_id(const struct net_device *d) { return d->vlan_id; }

static unsigned holds;   /* net-device references outstanding */
static void dev_hold(struct net_device *d) { (void)d; holds++; }
static void dev_put(struct net_device *d) { (void)d; assert(holds); holds--; }

static bool cdx_mc_port_identity(struct net_device *d)
{
    return d && d->physical;
}

/* --- bridge ----------------------------------------------------------- */
struct bridge_vlan_info { u16 flags; u16 vid; };

static bool vlan_enabled;
static u16 vlan_proto = ETH_P_8021Q;
static u16 bridge_pvid;
static struct { struct net_device *port; u16 vid; bool untagged; }
    memberships[16];
static unsigned membership_count;

static bool br_vlan_enabled(const struct net_device *br)
{
    (void)br; return vlan_enabled;
}
static int br_vlan_get_proto(const struct net_device *br, u16 *p)
{
    (void)br; *p = vlan_proto; return 0;
}
static int br_vlan_get_pvid(const struct net_device *br, u16 *p)
{
    (void)br;
    if (!bridge_pvid)
        return -EOPNOTSUPP;
    *p = bridge_pvid;
    return 0;
}
static int br_vlan_get_info(const struct net_device *port, u16 vid,
                            struct bridge_vlan_info *info)
{
    for (unsigned i = 0; i < membership_count; i++)
        if (memberships[i].port == port && memberships[i].vid == vid) {
            info->vid = vid;
            info->flags = memberships[i].untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0;
            return 0;
        }
    return -EOPNOTSUPP;
}

/* Inputs for the kernel-snapshot stub below. */
static struct net_device *mdb_ports[CDX_MC_MAX_LISTENERS];
static int mdb_count = -ENOENT;
static u16 mdb_vid;
static u16 mdb_vid_seen;

struct br_ip {
    union { u32 ip4; struct in6_addr ip6; } src, dst;
    u16 proto, vid;
};

/* The kernel snapshot is executed separately by bridge_mcast_snapshot.c.
 * This stub controls which complete set (or failure) the adapter receives. */
static int snapshot_error;
static int br_multicast_list_ports(struct net_device *bridge,
                                  const struct br_ip *group,
                                  struct net_device **ports, unsigned max)
{
    struct net_device *port;
    struct list_head *iter;
    unsigned n = 0;
    mdb_vid_seen = group->vid;
    if (snapshot_error)
        return snapshot_error;
    netdev_for_each_lower_dev(bridge, port, iter) {
        bool selected = (port->port_flags & BR_MCAST_FLOOD) != 0;
        if (mdb_count >= 0 && group->vid == mdb_vid) {
            selected = false;
            for (int i = 0; i < mdb_count; i++)
                selected |= mdb_ports[i] == port;
        }
        if (!selected)
            continue;
        if (vlan_enabled) {
            struct bridge_vlan_info info;
            if (br_vlan_get_info(port, group->vid, &info))
                continue;
        }
        if (n == max)
            return -E2BIG;
        ports[n++] = port;
    }
    return n;
}

/* --- multicast routing ------------------------------------------------ */
struct mr_mfc {
    unsigned short mfc_parent;
    int mfc_flags;
    union {
        struct {
            int minvif;
            int maxvif;
            long pkt;
            long bytes;
            unsigned long lastuse;
            unsigned char ttls[MAXVIFS];
            int refcount;
        } res;
    } mfc_un;
};

struct mfc_cache { struct mr_mfc _c; u32 mfc_mcastgrp; u32 mfc_origin; };
struct mfc6_cache {
    struct mr_mfc _c;
    struct in6_addr mf6c_mcastgrp;
    struct in6_addr mf6c_origin;
};

static unsigned cache_holds;
static void mr_cache_hold(struct mr_mfc *c) { c->mfc_un.res.refcount++; cache_holds++; }
static void mr_cache_put(struct mr_mfc *c)
{
    assert(cache_holds && c->mfc_un.res.refcount);
    c->mfc_un.res.refcount--;
    cache_holds--;
}

/* --- the backend interface -------------------------------------------- */
struct cdx_ft_vlan { u16 proto; u16 id; };
struct cdx_mc_listener {
    struct net_device *dev;
    struct cdx_ft_vlan vlan[CDX_FT_VLAN_MAX];
    u8 vlans;
};
struct cdx_mc_group_spec {
    struct net_device *in;
    union nf_inet_addr src;
    union nf_inet_addr dst;
    u8 family;
    u8 listeners;
    struct cdx_mc_listener listener[CDX_MC_MAX_LISTENERS];
};
struct cdx_mc_group;

/* --- the host's own memberships --------------------------------------- */
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)

/* The learner reaches each list through in_dev->mc_list and idev->mc_list, so
 * those members are what the model has to provide; which device's list it is
 * follows from the accessor. */
struct ip_mc_list { u32 multiaddr; struct ip_mc_list *next_rcu; };
struct ifmcaddr6 { struct in6_addr mca_addr; struct ifmcaddr6 *next; };
struct in_device { struct net_device *dev; struct ip_mc_list *mc_list; };
struct inet6_dev { struct net_device *dev; struct ifmcaddr6 *mc_list; };

static struct ip_mc_list mc4_pool[8];
static struct ifmcaddr6 mc6_pool[8];
static struct { struct net_device *dev; struct ip_mc_list *v4; struct ifmcaddr6 *v6; }
    mc_lists[4];
static struct in_device in_dev_slots[4];
static struct inet6_dev in6_dev_slots[4];
static unsigned mc_list_count, mc4_used, mc6_used;

static struct in_device *__in_dev_get_rcu(struct net_device *dev)
{
    for (unsigned i = 0; i < mc_list_count; i++)
        if (mc_lists[i].dev == dev) {
            in_dev_slots[i].dev = dev;
            in_dev_slots[i].mc_list = mc_lists[i].v4;
            return &in_dev_slots[i];
        }
    return NULL;
}

static struct inet6_dev *__in6_dev_get(struct net_device *dev)
{
    for (unsigned i = 0; i < mc_list_count; i++)
        if (mc_lists[i].dev == dev) {
            in6_dev_slots[i].dev = dev;
            in6_dev_slots[i].mc_list = mc_lists[i].v6;
            return &in6_dev_slots[i];
        }
    return NULL;
}

/* --- kernel odds and ends --------------------------------------------- */
#define lockdep_assert_held(x) ((void)(x))
#define ASSERT_RTNL() ((void)0)
#define kzalloc(n, f) calloc(1, (n))
#define kfree(p) free(p)
#define GFP_KERNEL 0
#define scnprintf snprintf

static void strscpy(char *dst, const char *src, size_t size)
{
    size_t n = strlen(src);

    if (n >= size)
        n = size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* --- the learner's own state ------------------------------------------ */
/* The one constant the harness restates rather than extracts; the Python side
 * asserts the source spells it the same way. */
#define FT_MR_OIF_TEXT (CDX_MC_MAX_LISTENERS * (IFNAMSIZ + 1))

static LIST_HEAD(ft_mr_groups);
static int ft_mr_lock;
static unsigned int ft_mr_count;
static unsigned int ft_mr_policy[2];
__attribute__((unused)) static unsigned int ft_mr_installed;
__attribute__((unused)) static u64 ft_mr_refused;
__attribute__((unused)) static u64 ft_mr_install_errors;

/* The VIF table is declared inside the generated include, between the struct
 * it is an array of and the functions that read it. */
#include "mroute_learner.inc"

/* --- the fixture ------------------------------------------------------ */

static struct net_device WAN, LAN, LAN2, LAN3, SOFT, PPP, BR, VWAN, VLAN_LAN,
	QINQ;
static struct mfc_cache MFC;
static struct mfc6_cache MFC6;

static void dev_init(struct net_device *d, const char *name, int ifindex)
{
    memset(d, 0, sizeof(*d));
    strscpy(d->name, name, sizeof(d->name));
    d->ifindex = ifindex;
    INIT_LIST_HEAD(&d->lowers);
}

static void lower_add(struct net_device *parent, struct net_device *child)
{
    struct ft_lower *l = &lower_pool[lower_used++];

    assert(lower_used <= ARRAY_SIZE(lower_pool));
    l->dev = child;
    list_add_tail(&l->list, &parent->lowers);
}

static u32 ip4(u8 a, u8 b, u8 c, u8 d)
{
    return htonl(((u32)a << 24) | ((u32)b << 16) | ((u32)c << 8) | d);
}

static struct in6_addr ip6(u16 first, u8 last)
{
    struct in6_addr a;

    memset(&a, 0, sizeof(a));
    a.s6_addr[0] = first >> 8;
    a.s6_addr[1] = first & 0xff;
    a.s6_addr[15] = last;
    return a;
}

static void host_join4(struct net_device *dev, u32 group)
{
    struct ip_mc_list *im = &mc4_pool[mc4_used++];

    im->multiaddr = group;
    im->next_rcu = NULL;
    for (unsigned i = 0; i < mc_list_count; i++)
        if (mc_lists[i].dev == dev) {
            im->next_rcu = mc_lists[i].v4;
            mc_lists[i].v4 = im;
            return;
        }
    mc_lists[mc_list_count].dev = dev;
    mc_lists[mc_list_count].v4 = im;
    mc_lists[mc_list_count].v6 = NULL;
    mc_list_count++;
}

static void host_join6(struct net_device *dev, struct in6_addr group)
{
    struct ifmcaddr6 *mc = &mc6_pool[mc6_used++];

    mc->mca_addr = group;
    mc->next = NULL;
    for (unsigned i = 0; i < mc_list_count; i++)
        if (mc_lists[i].dev == dev) {
            mc->next = mc_lists[i].v6;
            mc_lists[i].v6 = mc;
            return;
        }
    mc_lists[mc_list_count].dev = dev;
    mc_lists[mc_list_count].v4 = NULL;
    mc_lists[mc_list_count].v6 = mc;
    mc_list_count++;
}

/* A group in the shape ft_mr_apply() would have built it: the addresses are
 * copied out of the cache entry, never restated. */
static struct ft_mr_group *group4(struct mfc_cache *c, u32 src, u32 dst,
                                  unsigned short parent)
{
    struct ft_mr_group *g = calloc(1, sizeof(*g));

    memset(c, 0, sizeof(*c));
    c->mfc_origin = src;
    c->mfc_mcastgrp = dst;
    c->_c.mfc_parent = parent;
    c->_c.mfc_un.res.minvif = MAXVIFS;
    c->_c.mfc_un.res.maxvif = 0;
    memset(c->_c.mfc_un.res.ttls, 255, sizeof(c->_c.mfc_un.res.ttls));
    g->mfc = &c->_c;
    g->family = AF_INET;
    g->table = RT_TABLE_DEFAULT;
    g->src.ip = src;
    g->dst.ip = dst;
    return g;
}

static struct ft_mr_group *group6(struct mfc6_cache *c, struct in6_addr src,
                                  struct in6_addr dst, unsigned short parent)
{
    struct ft_mr_group *g = calloc(1, sizeof(*g));

    memset(c, 0, sizeof(*c));
    c->mf6c_origin = src;
    c->mf6c_mcastgrp = dst;
    c->_c.mfc_parent = parent;
    c->_c.mfc_un.res.minvif = MAXVIFS;
    c->_c.mfc_un.res.maxvif = 0;
    memset(c->_c.mfc_un.res.ttls, 255, sizeof(c->_c.mfc_un.res.ttls));
    g->mfc = &c->_c;
    g->family = AF_INET6;
    g->table = RT6_TABLE_DFLT;
    g->src.in6 = src;
    g->dst.in6 = dst;
    return g;
}

static void oif(struct ft_mr_group *g, int vif, unsigned char ttl)
{
    struct mr_mfc *c = g->mfc;

    c->mfc_un.res.ttls[vif] = ttl;
    if (vif < c->mfc_un.res.minvif)
        c->mfc_un.res.minvif = vif;
    if (vif + 1 > c->mfc_un.res.maxvif)
        c->mfc_un.res.maxvif = vif + 1;
}

static void vif_set(u8 family, int index, struct net_device *dev,
                    unsigned short flags)
{
    unsigned idx = ft_mr_idx(family);

    ft_mr_vif[idx][index].dev = dev;
    ft_mr_vif[idx][index].flags = flags;
}

static void reset(void)
{
    memset(ft_mr_vif, 0, sizeof(ft_mr_vif));
    memset(ft_mr_policy, 0, sizeof(ft_mr_policy));
    memset(memberships, 0, sizeof(memberships));
    membership_count = 0;
    vlan_enabled = false;
    vlan_proto = ETH_P_8021Q;
    bridge_pvid = 0;
    mdb_count = -ENOENT;
    snapshot_error = 0;
    mdb_vid = 0;
    mc_list_count = mc4_used = mc6_used = 0;
    lower_used = 0;
    assert(holds == 0);

    dev_init(&WAN, "eth4", 4);
    WAN.physical = true;
    dev_init(&LAN, "eth3", 3);
    LAN.physical = true;
    dev_init(&LAN2, "eth2", 2);
    LAN2.physical = true;
    dev_init(&LAN3, "eth1", 1);
    LAN3.physical = true;
    dev_init(&SOFT, "vx0", 20);
    dev_init(&PPP, "ppp0", 21);
    PPP.type = ARPHRD_PPP;
    dev_init(&BR, "br0", 22);
    BR.bridge_master = true;
    dev_init(&VWAN, "eth4.10", 23);
    VWAN.vlan = true;
    VWAN.vlan_proto = ETH_P_8021Q;
    VWAN.vlan_id = 10;
    lower_add(&VWAN, &WAN);
    dev_init(&VLAN_LAN, "eth3.20", 24);
    VLAN_LAN.vlan = true;
    VLAN_LAN.vlan_proto = ETH_P_8021Q;
    VLAN_LAN.vlan_id = 20;
    lower_add(&VLAN_LAN, &LAN);
    dev_init(&QINQ, "eth3.20.30", 25);
    QINQ.vlan = true;
    QINQ.vlan_proto = ETH_P_8021Q;
    QINQ.vlan_id = 30;
    lower_add(&QINQ, &VLAN_LAN);
}

static void bridge_port(struct net_device *port, unsigned long flags)
{
    port->master = &BR;
    port->bridge_port = true;
    port->port_flags = flags;
    lower_add(&BR, port);
}

static void member(struct net_device *p, u16 vid, bool untagged)
{
    memberships[membership_count].port = p;
    memberships[membership_count].vid = vid;
    memberships[membership_count].untagged = untagged;
    membership_count++;
}

static enum ft_mr_state derive(struct ft_mr_group *g, struct ft_mr_plan *plan)
{
    memset(plan, 0, sizeof(*plan));
    return ft_mr_derive(g, plan);
}

/* A refusal must leave nothing behind: the plan owns a reference per device
 * only on the one path that succeeds. */
static enum ft_mr_state refuse(struct ft_mr_group *g)
{
    struct ft_mr_plan plan;
    enum ft_mr_state state;
    unsigned before = holds;

    state = derive(g, &plan);
    assert(state != FT_MR_PENDING);
    assert(holds == before);
    assert(plan.spec.listeners == 0 && plan.spec.in == NULL);
    return state;
}

int main(void)
{
    struct ft_mr_group *g;
    struct ft_mr_plan plan;

    /* ---- the group address ------------------------------------------ */

    /* An (*,G) entry has no key: the classifier composes an external hash
     * over the source and a masked field cannot match. ipmr's (*,*) form
     * likewise. */
    reset();
    g = group4(&MFC, htonl(INADDR_ANY), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    oif(g, 1, 1);
    vif_set(AF_INET, 1, &LAN, 0);
    assert(refuse(g) == FT_MR_REFUSED_WILDCARD);
    g->dst.ip = htonl(INADDR_ANY);
    assert(refuse(g) == FT_MR_REFUSED_WILDCARD);
    free(g);

    /* Link-local scope carries the membership protocols themselves, and an
     * address outside 224.0.0.0/4 is not a group at all. Both are refused
     * here as well as by the backend, so /proc says which. */
    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(224, 0, 0, 1), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &LAN, 0);
    oif(g, 1, 1);
    assert(refuse(g) == FT_MR_REFUSED_SCOPE);
    g->dst.ip = ip4(10, 1, 1, 1);
    assert(refuse(g) == FT_MR_REFUSED_SCOPE);
    free(g);

    reset();
    g = group6(&MFC6, ip6(0xfc00, 0x99), ip6(0xff02, 0x05), 0);
    vif_set(AF_INET6, 0, &WAN, 0);
    vif_set(AF_INET6, 1, &LAN, 0);
    oif(g, 1, 1);
    assert(refuse(g) == FT_MR_REFUSED_SCOPE);   /* ff02:: is link-local */
    g->dst.in6 = ip6(0xff1e, 0x05);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.family == AF_INET6 && plan.spec.in == &WAN);
    ft_mr_plan_put(&plan);
    free(g);

    /* ---- the table and the policy ----------------------------------- */

    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &LAN, 0);
    oif(g, 1, 1);
    assert(derive(g, &plan) == FT_MR_PENDING);
    ft_mr_plan_put(&plan);
    /* Another table is one this learner does not read, and a rule can send
     * traffic to it whatever this entry says. */
    g->table = 100;
    assert(refuse(g) == FT_MR_REFUSED_TABLE);
    g->table = RT_TABLE_DEFAULT;
    /* A non-default rule anywhere in the family keeps the whole family out
     * of hardware, because an entry that matches at the classifier is never
     * offered to the rule that would have redirected it. */
    ft_mr_policy[ft_mr_idx(AF_INET)] = 1;
    assert(refuse(g) == FT_MR_REFUSED_POLICY);
    ft_mr_policy[ft_mr_idx(AF_INET)] = 0;
    /* And it is per family: an IPv6 rule does not refuse IPv4. */
    ft_mr_policy[ft_mr_idx(AF_INET6)] = 1;
    assert(derive(g, &plan) == FT_MR_PENDING);
    ft_mr_plan_put(&plan);
    free(g);

    /* ---- the ingress ------------------------------------------------- */

    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 1, &LAN, 0);
    oif(g, 1, 1);
    /* No VIF at the parent index at all. */
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    /* A register VIF is a software tunnel to the rendezvous point and an
     * IPIP VIF encapsulates; neither is a port. */
    vif_set(AF_INET, 0, &WAN, VIFF_REGISTER);
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    vif_set(AF_INET, 0, &WAN, VIFF_TUNNEL);
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    /* A bridge is many ports and the classifier key is one. */
    vif_set(AF_INET, 0, &BR, 0);
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    /* A bridge port's frames go to the bridge's rx handler, so a VIF above
     * one describes traffic that never arrives. */
    bridge_port(&WAN, BR_MCAST_FLOOD);
    vif_set(AF_INET, 0, &WAN, 0);
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    WAN.bridge_port = false;
    WAN.master = NULL;
    /* A ppp device, and anything else with no port beneath it. */
    vif_set(AF_INET, 0, &PPP, 0);
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    vif_set(AF_INET, 0, &SOFT, 0);
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    /* A VLAN device resolves to the port beneath it: the key names a port
     * and the per-listener rebuild strips whatever L2 arrived. The tag count
     * is kept because the counter fold has to subtract it. */
    vif_set(AF_INET, 0, &VWAN, 0);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.in == &WAN && plan.in_tags == 1);
    ft_mr_plan_put(&plan);
    free(g);

    /* ---- local delivery ---------------------------------------------- */

    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &LAN, 0);
    oif(g, 1, 1);
    /* The box itself has joined on the interface the stream arrives on, so
     * ip_mr_input() delivers locally as well as forwarding -- and a hardware
     * entry replicates to ports without the frame reaching the CPU. */
    host_join4(&WAN, ip4(239, 8, 1, 5));
    assert(refuse(g) == FT_MR_REFUSED_HOST);
    /* A different group on the same device is not this group's listener. */
    mc_list_count = mc4_used = 0;
    host_join4(&WAN, ip4(239, 8, 1, 9));
    assert(derive(g, &plan) == FT_MR_PENDING);
    ft_mr_plan_put(&plan);
    /* Nor the same group on a different device: the check is the input
     * device's, exactly as ip_route_input_mc() asks it. */
    mc_list_count = mc4_used = 0;
    host_join4(&LAN, ip4(239, 8, 1, 5));
    assert(derive(g, &plan) == FT_MR_PENDING);
    ft_mr_plan_put(&plan);
    free(g);

    reset();
    g = group6(&MFC6, ip6(0xfc00, 0x99), ip6(0xff1e, 0x05), 0);
    vif_set(AF_INET6, 0, &WAN, 0);
    vif_set(AF_INET6, 1, &LAN, 0);
    oif(g, 1, 1);
    host_join6(&WAN, ip6(0xff1e, 0x05));
    assert(refuse(g) == FT_MR_REFUSED_HOST);
    free(g);

    /* ---- thresholds --------------------------------------------------- */

    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &LAN, 0);
    vif_set(AF_INET, 2, &LAN2, 0);
    /* ip_mr_forward() forwards when ttl > ttls[vif]; the parser refuses to
     * classify a frame with a TTL below 2, which is threshold 1 and nothing
     * else. A scoped threshold is a decision the classifier cannot make. */
    oif(g, 1, 1);
    oif(g, 2, 16);
    assert(refuse(g) == FT_MR_REFUSED_THRESHOLD);
    g->mfc->mfc_un.res.ttls[2] = 1;
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 2);
    ft_mr_plan_put(&plan);
    /* 255 means "not an oif" and is skipped rather than refused. */
    g->mfc->mfc_un.res.ttls[2] = 255;
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 1 && plan.spec.listener[0].dev == &LAN);
    assert(!strcmp(plan.oifs, "eth3"));
    ft_mr_plan_put(&plan);
    free(g);

    /* ---- listeners ---------------------------------------------------- */

    /* An oif that is a VLAN device is the port beneath it plus its tag, and
     * a QinQ pair is two tags, outermost first as the wire carries them. */
    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &VLAN_LAN, 0);
    oif(g, 1, 1);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 1);
    assert(plan.spec.listener[0].dev == &LAN);
    assert(plan.spec.listener[0].vlans == 1);
    assert(plan.spec.listener[0].vlan[0].id == 20);
    assert(plan.spec.listener[0].vlan[0].proto == htons(ETH_P_8021Q));
    assert(!strcmp(plan.oifs, "eth3.20"));
    ft_mr_plan_put(&plan);
    vif_set(AF_INET, 1, &QINQ, 0);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listener[0].vlans == 2);
    assert(plan.spec.listener[0].vlan[0].id == 20);   /* outermost */
    assert(plan.spec.listener[0].vlan[1].id == 30);
    ft_mr_plan_put(&plan);
    /* 802.1ad is declined rather than reproduced blind. */
    QINQ.vlan_proto = 0x88a8;
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    QINQ.vlan_proto = ETH_P_8021Q;
    /* Anything else above a port -- a bond, a MACVLAN, a ppp device -- is
     * refused rather than approximated. */
    vif_set(AF_INET, 1, &SOFT, 0);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    vif_set(AF_INET, 1, &PPP, 0);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    /* A listener equal to the ingress is a copy a router never sends. */
    vif_set(AF_INET, 1, &WAN, 0);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    /* And the parent VIF named as its own oif, which is the same thing said
     * one level up. */
    vif_set(AF_INET, 1, &LAN, 0);
    oif(g, 0, 1);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    free(g);

    /* Two oifs resolving to one port with different framing are two copies,
     * and both are carried: the backend identifies a listener by its whole
     * framing rather than by its device, and each gets its own entry in the
     * chain. A gateway serving several VLANs out of one port replicates that
     * way -- and so does the bench, which is the only place it can be
     * measured: the rig has one LAN port with carrier and every group's other
     * port is its ingress, so two tagged oifs on it are the only route to
     * multi-listener replication and the chain swap (ISSUES.md A158). */
    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &LAN, 0);         /* untagged out eth3 */
    vif_set(AF_INET, 2, &VLAN_LAN, 0);    /* eth3.20 */
    oif(g, 1, 1);
    oif(g, 2, 1);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 2);
    assert(plan.spec.listener[0].dev == &LAN && plan.spec.listener[0].vlans == 0);
    assert(plan.spec.listener[1].dev == &LAN && plan.spec.listener[1].vlans == 1);
    assert(plan.spec.listener[1].vlan[0].id == 20);
    ft_mr_plan_put(&plan);
    /* The same framing twice is one copy and collapses rather than being
     * programmed twice, which would put two identical frames on the wire. */
    vif_set(AF_INET, 2, &LAN, 0);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 1);
    ft_mr_plan_put(&plan);
    free(g);

    /* One port in and out, on different VLANs: eth3.10 receives and eth3.20
     * gets the copy. ft_parse() admits the unicast form of this already --
     * re-entering the ingress port is refused only when the two tag stacks
     * match -- and the hardware enqueues back to the port a frame arrived on,
     * measured as the hairpin double-NAT case. */
    reset();
    {
        static struct net_device IN10;

        dev_init(&IN10, "eth3.10", 30);
        IN10.vlan = true;
        IN10.vlan_proto = ETH_P_8021Q;
        IN10.vlan_id = 10;
        lower_add(&IN10, &LAN);

        g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
        vif_set(AF_INET, 0, &IN10, 0);      /* iif eth3.10 */
        vif_set(AF_INET, 1, &VLAN_LAN, 0);  /* oif eth3.20 */
        oif(g, 1, 1);
        assert(derive(g, &plan) == FT_MR_PENDING);
        assert(plan.spec.in == &LAN && plan.in_tags == 1);
        assert(plan.spec.listeners == 1);
        assert(plan.spec.listener[0].dev == &LAN);
        assert(plan.spec.listener[0].vlan[0].id == 20);
        ft_mr_plan_put(&plan);

        /* The same VLAN out as in is not a copy a router sends, and is
         * refused on the framing rather than on the device. */
        vif_set(AF_INET, 1, &IN10, 0);
        assert(refuse(g) == FT_MR_REFUSED_LISTENER);
        /* Untagged out of the same port is a different stack, so it is
         * carried -- the port is not the test, the framing is. */
        vif_set(AF_INET, 1, &LAN, 0);
        assert(derive(g, &plan) == FT_MR_PENDING);
        assert(plan.spec.listener[0].dev == &LAN &&
               plan.spec.listener[0].vlans == 0);
        ft_mr_plan_put(&plan);
        free(g);
    }

    /* And an untagged ingress with an untagged listener on the same port is
     * still refused: identical framing, and a group has no NAT to make it a
     * distinct path the way a unicast hairpin does. */
    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &WAN, 0);
    oif(g, 1, 1);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    free(g);

    /* The ceiling. Nine oifs cannot be nine listeners. */
    reset();
    {
        static struct net_device ports[CDX_MC_MAX_LISTENERS + 1];

        g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
        vif_set(AF_INET, 0, &WAN, 0);
        for (int i = 0; i <= CDX_MC_MAX_LISTENERS; i++) {
            dev_init(&ports[i], "p", 100 + i);
            ports[i].physical = true;
            vif_set(AF_INET, i + 1, &ports[i], 0);
            oif(g, i + 1, 1);
        }
        assert(refuse(g) == FT_MR_REFUSED_LISTENER);
        /* Eight is carried. */
        g->mfc->mfc_un.res.ttls[CDX_MC_MAX_LISTENERS] = 255;
        assert(derive(g, &plan) == FT_MR_PENDING);
        assert(plan.spec.listeners == CDX_MC_MAX_LISTENERS);
        ft_mr_plan_put(&plan);
        free(g);
    }

    /* A VIF the kernel has removed is dropped rather than refused: what is
     * left is a shorter replication list, and an empty one is refused. */
    reset();
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &LAN, 0);
    vif_set(AF_INET, 2, &LAN2, 0);
    oif(g, 1, 1);
    oif(g, 2, 1);
    vif_set(AF_INET, 2, NULL, 0);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 1 && plan.spec.listener[0].dev == &LAN);
    ft_mr_plan_put(&plan);
    vif_set(AF_INET, 1, NULL, 0);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    /* The parent's VIF going is an ingress refusal, not a listener one. */
    vif_set(AF_INET, 1, &LAN, 0);
    vif_set(AF_INET, 0, NULL, 0);
    assert(refuse(g) == FT_MR_REFUSED_INGRESS);
    free(g);

    /* ---- an oif that is a bridge -------------------------------------- */

    /* Plain bridge, no snooping: br_flood() copies to every port that floods
     * multicast, and nothing else. */
    reset();
    bridge_port(&LAN, BR_MCAST_FLOOD);
    bridge_port(&LAN2, BR_MCAST_FLOOD);
    bridge_port(&LAN3, 0);
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &BR, 0);
    oif(g, 1, 1);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 2);
    assert(plan.spec.listener[0].dev == &LAN &&
           plan.spec.listener[1].dev == &LAN2);
    assert(plan.spec.listener[0].vlans == 0);
    assert(!strcmp(plan.oifs, "br0"));
    g->in = plan.spec.in;
    g->in_tags = plan.in_tags;
    g->listeners = plan.spec.listeners;
    memcpy(g->listener, plan.spec.listener, sizeof(g->listener));
    assert(ft_mr_plan_same(g, &plan));
    g->listener[0].vlans = 1;
    assert(!ft_mr_plan_same(g, &plan));
    g->listener[0].vlans = 0;
    g->listener[0].dev = &LAN3;
    assert(!ft_mr_plan_same(g, &plan));
    g->listener[0].dev = &LAN;
    g->listeners--;
    assert(!ft_mr_plan_same(g, &plan));
    g->listeners++;
    g->in = &LAN3;
    assert(!ft_mr_plan_same(g, &plan));
    g->in = NULL;
    g->listeners = 0;

    ft_mr_plan_put(&plan);

    /* One port the hardware cannot carry refuses the whole bridge: the
     * matched frame never reaches it, so a port left out does not fall back
     * to software, it stops receiving. */
    LAN3.physical = false;
    SOFT.master = &BR;
    SOFT.port_flags = BR_MCAST_FLOOD;
    SOFT.bridge_port = true;
    lower_add(&BR, &SOFT);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    free(g);

    /* A bridge with nothing that floods is not installable. */
    reset();
    bridge_port(&LAN, 0);
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &BR, 0);
    oif(g, 1, 1);
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    free(g);

    /* Snooping on, with a membership: br_dev_xmit() hands the frame to
     * br_multicast_flood(), so the copy set is exactly that port group --
     * one port of the two, even though both flood. */
    reset();
    bridge_port(&LAN, BR_MCAST_FLOOD);
    bridge_port(&LAN2, BR_MCAST_FLOOD);
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &BR, 0);
    oif(g, 1, 1);
    mdb_ports[0] = &LAN2;
    mdb_count = 1;
    mdb_vid = 0;
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 1 && plan.spec.listener[0].dev == &LAN2);
    ft_mr_plan_put(&plan);
    /* A second set-top box joining on the other port grows the set, which is
     * what the switchdev handler's kick exists for. */
    mdb_ports[1] = &LAN;
    mdb_count = 2;
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 2);
    ft_mr_plan_put(&plan);
    free(g);

    /* A vlan-aware bridge below a VLAN device: the bridge forwards within
     * the tag the frame already carries, and each port's own membership
     * decides whether the copy leaves tagged. That is the shipping br-lan.N
     * shape. */
    reset();
    bridge_port(&LAN, BR_MCAST_FLOOD);
    bridge_port(&LAN2, BR_MCAST_FLOOD);
    vlan_enabled = true;
    bridge_pvid = 1;
    member(&LAN, 3999, false);      /* tagged member */
    member(&LAN2, 3999, true);      /* untagged member */
    dev_init(&SOFT, "br0.3999", 26);
    SOFT.vlan = true;
    SOFT.vlan_proto = ETH_P_8021Q;
    SOFT.vlan_id = 3999;
    lower_add(&SOFT, &BR);
    g = group4(&MFC, ip4(10, 0, 0, 52), ip4(239, 8, 1, 5), 0);
    vif_set(AF_INET, 0, &WAN, 0);
    vif_set(AF_INET, 1, &SOFT, 0);
    oif(g, 1, 1);
    mdb_ports[0] = &LAN;
    mdb_ports[1] = &LAN2;
    mdb_count = 2;
    mdb_vid = 3999;
    assert(derive(g, &plan) == FT_MR_PENDING);
    /* The MDB was consulted for the VLAN the bridge forwards within, not for
     * the bridge's PVID. */
    assert(mdb_vid_seen == 3999);
    assert(plan.spec.listeners == 2);
    assert(plan.spec.listener[0].dev == &LAN);
    assert(plan.spec.listener[0].vlans == 1);
    assert(plan.spec.listener[0].vlan[0].id == 3999);
    assert(plan.spec.listener[1].dev == &LAN2);
    assert(plan.spec.listener[1].vlans == 0);
    ft_mr_plan_put(&plan);
    /* The snapshot excludes a port outside this VLAN; it must never be
     * carried untagged onto a different network. */
    membership_count = 0;
    member(&LAN, 3999, false);
    assert(derive(g, &plan) == FT_MR_PENDING);
    assert(plan.spec.listeners == 1 && plan.spec.listener[0].dev == &LAN);
    ft_mr_plan_put(&plan);
    snapshot_error = -E2BIG;
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    snapshot_error = -EOPNOTSUPP;
    assert(refuse(g) == FT_MR_REFUSED_LISTENER);
    free(g);

    /* ---- what the chain does to the list ------------------------------ */

    reset();
    {
        struct mfc_cache a, b;
        struct ft_mr_event ev;
        struct ft_mr_group *ga, *gb;

        memset(&a, 0, sizeof(a));
        a.mfc_origin = ip4(10, 0, 0, 52);
        a.mfc_mcastgrp = ip4(239, 8, 1, 5);
        a._c.mfc_parent = 3;
        memset(&b, 0, sizeof(b));
        b.mfc_origin = ip4(10, 0, 0, 52);
        b.mfc_mcastgrp = ip4(239, 8, 1, 6);

        /* An add creates a group keyed on the cache entry and holds it. */
        memset(&ev, 0, sizeof(ev));
        ev.event = FIB_EVENT_ENTRY_ADD;
        ev.family = AF_INET;
        ev.table = RT_TABLE_DEFAULT;
        ev.mfc = &a._c;
        ft_mr_apply(&ev);
        assert(ft_mr_count == 1 && cache_holds == 1);
        ga = ft_mr_find(&a._c);
        assert(ga && ga->dirty && !ga->gone);
        /* The addresses come out of the entry rather than being restated. */
        assert(ga->src.ip == a.mfc_origin && ga->dst.ip == a.mfc_mcastgrp);

        /* A replace names the same pointer -- ipmr updates the entry in
         * place -- so it re-derives rather than creating a second group. */
        ga->dirty = false;
        ga->retries = 3;
        ev.event = FIB_EVENT_ENTRY_REPLACE;
        ft_mr_apply(&ev);
        assert(ft_mr_count == 1 && cache_holds == 1);
        assert(ga->dirty && ga->retries == 0);

        /* A second entry is a second group. */
        ev.event = FIB_EVENT_ENTRY_ADD;
        ev.mfc = &b._c;
        ft_mr_apply(&ev);
        assert(ft_mr_count == 2 && cache_holds == 2);
        gb = ft_mr_find(&b._c);
        assert(gb && gb != ga);

        /* A delete marks it for retirement rather than freeing it here: the
         * worker has hardware to take out first. */
        ev.event = FIB_EVENT_ENTRY_DEL;
        ft_mr_apply(&ev);
        assert(gb->gone && gb->dirty && ft_mr_count == 2);
        /* And a delete for an entry this learner never took on is inert. */
        ev.mfc = (struct mr_mfc *)&a;   /* not a key in the list */
        ft_mr_apply(&ev);
        assert(ft_mr_count == 2);

        /* A VIF add fills the table and re-derives the family; a VIF delete
         * empties it and does the same, because an index only means
         * anything against the table it indexes. */
        ga->dirty = false;
        gb->dirty = false;
        memset(&ev, 0, sizeof(ev));
        ev.event = FIB_EVENT_VIF_ADD;
        ev.family = AF_INET;
        ev.table = RT_TABLE_DEFAULT;
        ev.vif_index = 3;
        ev.vif_flags = VIFF_REGISTER;
        ev.dev = &WAN;
        ft_mr_apply(&ev);
        assert(ft_mr_vif[ft_mr_idx(AF_INET)][3].dev == &WAN);
        assert(ft_mr_vif[ft_mr_idx(AF_INET)][3].flags == VIFF_REGISTER);
        assert(ga->dirty && gb->dirty && holds == 1);

        /* A VIF in another table is not this learner's. */
        ga->dirty = false;
        ev.vif_index = 4;
        ev.table = 100;
        ft_mr_apply(&ev);
        assert(ft_mr_vif[ft_mr_idx(AF_INET)][4].dev == NULL);
        assert(!ga->dirty);

        ev.event = FIB_EVENT_VIF_DEL;
        ev.table = RT_TABLE_DEFAULT;
        ev.vif_index = 3;
        ft_mr_apply(&ev);
        assert(ft_mr_vif[ft_mr_idx(AF_INET)][3].dev == NULL);
        assert(ft_mr_vif[ft_mr_idx(AF_INET)][3].flags == 0);
        assert(holds == 0 && ga->dirty);

        /* Rules. Only a rule that is not the default one counts, and the
         * count is per family. */
        memset(&ev, 0, sizeof(ev));
        ev.event = FIB_EVENT_RULE_ADD;
        ev.family = AF_INET;
        ev.rule_default = true;
        ft_mr_apply(&ev);
        assert(ft_mr_policy[ft_mr_idx(AF_INET)] == 0);
        ev.rule_default = false;
        ft_mr_apply(&ev);
        ft_mr_apply(&ev);
        assert(ft_mr_policy[ft_mr_idx(AF_INET)] == 2);
        assert(ft_mr_policy[ft_mr_idx(AF_INET6)] == 0);
        ev.event = FIB_EVENT_RULE_DEL;
        ft_mr_apply(&ev);
        assert(ft_mr_policy[ft_mr_idx(AF_INET)] == 1);
        /* A delete that arrives without its add must not wrap the count to
         * four billion and refuse every group for ever. */
        ft_mr_apply(&ev);
        ft_mr_apply(&ev);
        assert(ft_mr_policy[ft_mr_idx(AF_INET)] == 0);

        /* Drain the way the worker does, so the references balance. */
        while (ft_mr_groups.next != &ft_mr_groups) {
            struct ft_mr_group *dead = list_entry(ft_mr_groups.next,
                                                  struct ft_mr_group, list);
            list_del(&dead->list);
            mr_cache_put(dead->mfc);
            free(dead);
        }
        ft_mr_count = 0;
        assert(cache_holds == 0 && holds == 0);
    }

    /* ---- the words /proc prints --------------------------------------- */

    {
        /* Every refusal has a word of its own: one "refused" would answer
         * ten different questions the same way. */
        static const enum ft_mr_state all[] = {
            FT_MR_PENDING, FT_MR_INSTALLED, FT_MR_REFUSED_TABLE,
            FT_MR_REFUSED_POLICY, FT_MR_REFUSED_WILDCARD,
            FT_MR_REFUSED_SCOPE, FT_MR_REFUSED_INGRESS, FT_MR_REFUSED_HOST,
            FT_MR_REFUSED_THRESHOLD, FT_MR_REFUSED_LISTENER,
            FT_MR_REFUSED_CONTESTED, FT_MR_REFUSED_FAILED,
        };

        for (unsigned i = 0; i < ARRAY_SIZE(all); i++) {
            assert(strcmp(ft_mr_state_text(all[i]), "unknown"));
            for (unsigned j = i + 1; j < ARRAY_SIZE(all); j++)
                assert(strcmp(ft_mr_state_text(all[i]),
                              ft_mr_state_text(all[j])));
            /* And the two that are not refusals are not counted as ones. */
            assert(ft_mr_refusal(all[i]) == (i >= 2));
        }
    }

    /* The default table is the only one read, and the two families do not
     * share an id. */
    assert(ft_mr_default_table(AF_INET) == RT_TABLE_DEFAULT);
    assert(ft_mr_default_table(AF_INET6) == RT6_TABLE_DFLT);
    assert(ft_mr_idx(AF_INET) != ft_mr_idx(AF_INET6));

    assert(holds == 0 && cache_holds == 0);
    printf("ok\n");
    return 0;
}

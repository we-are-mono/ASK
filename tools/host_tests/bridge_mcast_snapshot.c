/* Execute the production snapshot against bridge state, including state that
 * predates the consumer's load. No switchdev replay or event cache is modeled. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#define IS_ENABLED(x) (x)
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define BR_STATE_FORWARDING 3
#define BR_MCAST_FLOOD 1
#define BR_MULTICAST_TO_UNICAST 2
#define MDB_PG_FLAGS_BLOCKED 1
#define MCAST_INCLUDE 1
#define BROPT_VLAN_ENABLED 0
#define BROPT_MCAST_VLAN_SNOOPING_ENABLED 1
#define BROPT_MULTICAST_ENABLED 2
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
struct list_head { struct list_head *next; };
#define list_for_each_entry(p, h, m) \
    for (p = container_of((h)->next, __typeof__(*p), m); &p->m != h; \
         p = container_of(p->m.next, __typeof__(*p), m))
struct hlist_node { struct hlist_node *next; };
struct hlist_head { struct hlist_node *first; };
#define hlist_for_each(n, h) for (n = (h)->first; n; n = n->next)
#define hlist_entry(p, t, m) container_of(p, t, m)
#define mlock_dereference(p, b) (assert((b)->multicast_lock), (p))

struct br_ip {
    union { uint32_t ip4; struct in6_addr ip6; } src, dst;
    uint16_t proto, vid;
};
struct net_bridge;
struct net_bridge_vlan;
struct net_device { bool master, running; struct net_bridge *priv; int id; };
struct net_bridge_mcast {
    struct hlist_head ip4_mc_router_list, ip6_mc_router_list;
    bool disabled, querier[2], include[2];
};
struct net_bridge_vlan {
    struct net_bridge_mcast br_mcast_ctx;
    bool usable;
    int state;
    uint16_t vid;
};
struct net_bridge_port {
    struct list_head list;
    struct net_device *dev;
    struct net_bridge_vlan vlan;
    int state;
    unsigned flags;
    bool mst;
};
struct net_bridge_mcast_port {
    struct net_bridge_port *port;
    struct hlist_node ip4_rlist, ip6_rlist;
};
struct net_bridge_port_group {
    struct { struct net_bridge_port *port; } key;
    struct net_bridge_port_group *next;
    unsigned flags;
    int filter_mode;
};
struct net_bridge_mdb_entry {
    struct br_ip addr;
    struct net_bridge_port_group *ports;
};
struct net_bridge {
    struct list_head port_list;
    struct net_bridge_mcast multicast_ctx;
    struct net_bridge_vlan vlan;
    bool opts[3];
    int multicast_lock;
};
struct ethhdr { uint16_t h_proto; };
static unsigned rcu, calls, lookups;
#define ASSERT_RTNL() ((void)0)
static void rcu_read_lock(void) { rcu++; }
static void rcu_read_unlock(void) { assert(rcu); rcu--; }
static void spin_lock_bh(int *lock) { assert(!*lock); *lock = 1; }
static void spin_unlock_bh(int *lock) { assert(*lock); *lock = 0; }
static bool netif_is_bridge_master(struct net_device *d) { return d->master; }
static bool netif_running(struct net_device *d) { return d->running; }
static struct net_bridge *netdev_priv(struct net_device *d) { return d->priv; }
static bool br_opt_get(struct net_bridge *b, int opt) { return b->opts[opt]; }
static struct net_bridge_vlan *br_vlan_group_rcu(struct net_bridge *b)
{ assert(rcu); return &b->vlan; }
static struct net_bridge_vlan *nbp_vlan_group_rcu(struct net_bridge_port *p)
{ assert(rcu); return &p->vlan; }
static struct net_bridge_vlan *br_vlan_find(struct net_bridge_vlan *v, uint16_t vid)
{ return v->vid == vid ? v : NULL; }
static bool br_vlan_should_use(struct net_bridge_vlan *v) { return v->usable; }
static int br_vlan_get_state(struct net_bridge_vlan *v) { return v->state; }
static bool br_vlan_state_allowed(int state, bool learn)
{ return state == BR_STATE_FORWARDING; }
static bool br_multicast_ctx_vlan_global_disabled(struct net_bridge_mcast *c)
{ return c->disabled; }
static bool br_multicast_querier_exists(struct net_bridge_mcast *c,
                                       struct ethhdr *e, void *mdb)
{ return c->querier[e->h_proto == htons(ETH_P_IPV6)]; }
static bool br_multicast_should_handle_mode(struct net_bridge_mcast *c, uint16_t proto)
{ return c->include[proto == htons(ETH_P_IPV6)]; }
static bool br_multicast_is_star_g(const struct br_ip *g)
{
    static const char zero[16];
    return !memcmp(&g->src, zero, sizeof(g->src));
}
static bool br_mst_is_enabled(struct net_bridge_port *p) { return p->mst; }
static struct net_bridge_mdb_entry mdb[2];
static bool present[2];
static struct net_bridge_mdb_entry *br_mdb_ip_get(struct net_bridge *b, struct br_ip *key)
{
    assert(b->multicast_lock && rcu);
    lookups++;
    for (unsigned i = 0; i < 2; i++)
        if (present[i] && !memcmp(&mdb[i].addr, key, sizeof(*key)))
            return &mdb[i];
    return NULL;
}
#include "bridge_mcast_snapshot.inc"

static struct net_bridge br;
static struct net_device bridge, dev[10], *out[10];
static struct net_bridge_port port[10];
static struct net_bridge_mcast_port router[10];
static struct net_bridge_port_group pg[10];
static struct br_ip key;

static void setup(int family, bool vlan)
{
    memset(&br, 0, sizeof(br));
    memset(port, 0, sizeof(port));
    memset(router, 0, sizeof(router));
    memset(pg, 0, sizeof(pg));
    memset(mdb, 0, sizeof(mdb));
    memset(present, 0, sizeof(present));
    memset(&key, 0, sizeof(key));
    br.port_list.next = &br.port_list;
    br.opts[BROPT_MULTICAST_ENABLED] = true;
    br.opts[BROPT_VLAN_ENABLED] = vlan;
    br.opts[BROPT_MCAST_VLAN_SNOOPING_ENABLED] = vlan;
    br.vlan = (struct net_bridge_vlan){ .vid = 42, .usable = true,
                                      .state = BR_STATE_FORWARDING };
    br.multicast_ctx.querier[family] = true;
    br.vlan.br_mcast_ctx.querier[family] = true;
    key.proto = htons(family ? ETH_P_IPV6 : ETH_P_IP);
    key.vid = vlan ? 42 : 0;
    key.src.ip4 = 123;
    key.dst.ip4 = 456;
    bridge = (struct net_device){ .master = true, .running = true, .priv = &br };
    for (unsigned i = 0; i < 10; i++) {
        dev[i].id = i;
        port[i].dev = &dev[i];
        port[i].state = BR_STATE_FORWARDING;
        port[i].vlan = br.vlan;
        router[i].port = &port[i];
        pg[i].key.port = &port[i];
    }
    for (int i = 9; i >= 0; i--) {
        port[i].list.next = br.port_list.next;
        br.port_list.next = &port[i].list;
    }
    mdb[0].addr = key;
    memset(&mdb[0].addr.src, 0, sizeof(mdb[0].addr.src));
    mdb[1].addr = key;
}
static struct net_bridge_mcast *ctx(void)
{ return br.opts[BROPT_MCAST_VLAN_SNOOPING_ENABLED] ?
    &br.vlan.br_mcast_ctx : &br.multicast_ctx; }
static void add_router(unsigned i, int family)
{
    struct net_bridge_mcast *c = ctx();
    struct hlist_head *h = family ? &c->ip6_mc_router_list : &c->ip4_mc_router_list;
    struct hlist_node *n = family ? &router[i].ip6_rlist : &router[i].ip4_rlist;
    n->next = h->first; h->first = n;
}
static int snapshot(unsigned max)
{
    int n = br_multicast_list_ports(&bridge, &key, out, max);
    assert(!rcu && !br.multicast_lock);
    calls++;
    return n;
}
int main(void)
{
    for (int family = 0; family <= CONFIG_IPV6; family++) {
        for (int vlan = 0; vlan < 2; vlan++) {
            setup(family, vlan);
            assert(snapshot(8) == 0);  /* no MDB, routers or flooded data */
            add_router(1, family);     /* already present before module load */
            assert(snapshot(8) == 1 && out[0] == &dev[1]);
            add_router(2, !family);    /* unrelated address family */
            assert(snapshot(8) == 1 && out[0] == &dev[1]);
            if (vlan) {
                /* A router in the bridge-wide context is not in VLAN 42. */
                br.multicast_ctx.ip4_mc_router_list = ctx()->ip4_mc_router_list;
                br.multicast_ctx.ip6_mc_router_list = ctx()->ip6_mc_router_list;
            }
            present[0] = true;
            mdb[0].ports = &pg[0];
            assert(snapshot(8) == 2 && out[0] == &dev[0] && out[1] == &dev[1]);
            pg[0].next = &pg[1];       /* MDB + router must emit one copy */
            assert(snapshot(2) == 2);
            assert(snapshot(1) == -E2BIG);
            assert(snapshot(0) == -E2BIG);
            pg[1].flags = MDB_PG_FLAGS_BLOCKED;
            assert(snapshot(8) == 2);  /* router overrides source exclusion */
            ctx()->ip4_mc_router_list.first = NULL;
            ctx()->ip6_mc_router_list.first = NULL;
            assert(snapshot(8) == 1 && out[0] == &dev[0]);
            add_router(1, family);
            port[1].state = 0;
            assert(snapshot(8) == 1);
            port[1].state = BR_STATE_FORWARDING;
            if (vlan) {
                port[1].vlan.vid = 43;
                assert(snapshot(8) == 1);
                port[1].vlan.vid = 42;
                port[1].vlan.state = 0;
                assert(snapshot(8) == 1);
                port[1].vlan.state = BR_STATE_FORWARDING;
                port[1].vlan.usable = false;
                assert(snapshot(8) == 1);
                port[1].vlan.usable = true;
            }
            ctx()->include[family] = true;
            pg[0].filter_mode = MCAST_INCLUDE;
            assert(snapshot(8) == 1 && out[0] == &dev[1]);
            present[1] = true;
            mdb[1].ports = &pg[3];
            assert(snapshot(8) == 2 && out[0] == &dev[1] && out[1] == &dev[3]);
            pg[3].flags = MDB_PG_FLAGS_BLOCKED;
            assert(snapshot(8) == 1 && out[0] == &dev[1]);
            pg[3].flags = 0;
            port[3].flags = BR_MULTICAST_TO_UNICAST;
            assert(snapshot(8) == -EOPNOTSUPP);
            port[3].flags = 0;
            port[1].flags = BR_MULTICAST_TO_UNICAST;
            assert(snapshot(8) == 2);  /* router still receives multicast */
            port[1].flags = 0;
            port[3].mst = true;
            assert(snapshot(8) == -EOPNOTSUPP);
            port[3].mst = false;
            /* Without a querier, even an existing MDB follows flood flags. */
            ctx()->querier[family] = false;
            port[5].flags = BR_MCAST_FLOOD;
            assert(snapshot(8) == 1 && out[0] == &dev[5]);
            ctx()->querier[family] = true;
            ctx()->disabled = true;
            assert(snapshot(8) == 1 && out[0] == &dev[5]);
            ctx()->disabled = false;
            br.opts[BROPT_MULTICAST_ENABLED] = false;
            assert(snapshot(8) == 1 && out[0] == &dev[5]);
            bridge.running = false;
            assert(snapshot(8) == 0);
            bridge.running = true;
            bridge.master = false;
            assert(snapshot(8) == -EOPNOTSUPP);
            setup(family, vlan);
            for (unsigned i = 0; i < 8; i++)
                add_router(i, family);
            assert(snapshot(8) == 8);
            add_router(8, family);
            assert(snapshot(8) == -E2BIG);
            assert(snapshot(9) == 9);
        }
    }
#if !CONFIG_IPV6
    setup(1, false);
    assert(snapshot(8) == -EOPNOTSUPP);
#endif
    printf("%u multicast snapshot scenarios passed (IPv6=%d)\n", calls, CONFIG_IPV6);
    return 0;
}

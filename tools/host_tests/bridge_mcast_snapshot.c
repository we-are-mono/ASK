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

typedef uint8_t u8;
typedef uint16_t u16;

#define IS_ENABLED(x) (x)
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define BR_STATE_LEARNING 2
#define BR_STATE_FORWARDING 3
#define BR_MCAST_FLOOD 1
#define BR_MULTICAST_TO_UNICAST 2
#define BR_HAIRPIN_MODE 4
#define BR_ISOLATED 8
#define BR_PORT_LOCKED 16
#define BR_PROXYARP 32
#define IFF_PROMISC 0x100
#define MDB_RTR_TYPE_DISABLED 0
#define MDB_RTR_TYPE_TEMP_QUERY 1
#define MDB_RTR_TYPE_PERM 2
#define BR_MCAST_TO_HOST_JOINED (1U << 0)
#define BR_MCAST_TO_HOST_ROUTER (1U << 1)
#define BR_MCAST_TO_HOST_FLOOD (1U << 2)
#define BR_MCAST_TO_HOST_PROMISC (1U << 3)
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
struct net_bridge_port;
struct net_device {
    bool master, running;
    unsigned flags;
    struct net_bridge *priv;
    struct net_bridge_port *port;   /* the bridge port it is, if any */
    int id;
};
struct net_bridge_mcast {
    struct hlist_head ip4_mc_router_list, ip6_mc_router_list;
    bool disabled, querier[2], include[2];
    unsigned long multicast_membership_interval;
    /* The bridge's own router state: its mode, and per family whether the
     * query-learned router timer is running. */
    int multicast_router;
    bool router_timer[2];
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
    struct net_bridge *br;
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
    bool host_joined;
};
struct net_bridge {
    struct net_device *dev;
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
static bool netif_is_bridge_master(const struct net_device *d) { return d->master; }
static struct net_bridge_port *br_port_get_rtnl(const struct net_device *d)
{ return d->port; }
static bool br_ip4_multicast_is_router(struct net_bridge_mcast *c)
{ return c->router_timer[0]; }
static bool br_ip6_multicast_is_router(struct net_bridge_mcast *c)
{ return c->router_timer[1]; }
static bool netif_running(struct net_device *d) { return d->running; }
static struct net_bridge *netdev_priv(const struct net_device *d) { return d->priv; }
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
static unsigned long br_multicast_gmi(const struct net_bridge_mcast *c)
{ return c->multicast_membership_interval; }
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
    br.dev = &bridge;
    for (unsigned i = 0; i < 10; i++) {
        dev[i].id = i;
        dev[i].port = &port[i];
        port[i].dev = &dev[i];
        port[i].br = &br;
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
    int n = br_multicast_list_ports(&bridge, &key, NULL, NULL, out, max);
    assert(!rcu && !br.multicast_lock);
    calls++;
    return n;
}
/* Data received on port `in`, and what the bridge hands the host of it. */
static unsigned local;
static int received(unsigned in, unsigned max)
{
    int n = br_multicast_list_ports(&bridge, &key, &dev[in], &local, out, max);
    assert(!rcu && !br.multicast_lock);
    calls++;
    return n;
}
static bool listed(int n, unsigned i)
{
    for (int j = 0; j < n; j++)
        if (out[j] == &dev[i])
            return true;
    return false;
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
            /* Without a querier, even with an MDB entry, what the host
             * sends floods as br_flood() floods it: to every port but a
             * proxy-ARP one, mcast_flood or not -- that flag filters only
             * what other ports send. */
            ctx()->querier[family] = false;
            for (unsigned i = 0; i < 10; i++)
                port[i].flags = i == 5 ? 0 : BR_PROXYARP;
            assert(snapshot(8) == 1 && out[0] == &dev[5]);
            ctx()->querier[family] = true;
            ctx()->disabled = true;
            assert(snapshot(8) == 1 && out[0] == &dev[5]);
            ctx()->disabled = false;
            br.opts[BROPT_MULTICAST_ENABLED] = false;
            assert(snapshot(8) == 1 && out[0] == &dev[5]);
            port[5].flags = BR_PROXYARP;
            assert(snapshot(8) == 0);
            for (unsigned i = 0; i < 10; i++)
                port[i].flags = 0;
            assert(snapshot(8) == -E2BIG && snapshot(10) == 10);
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
    /* Data received on a bridge port: br_handle_frame_finish() and
     * br_multicast_flood(), and what goes up to the host besides. */
    for (int family = 0; family <= CONFIG_IPV6; family++) {
        for (int vlan = 0; vlan < 2; vlan++) {
            int n;

            setup(family, vlan);
            present[0] = true;              /* the (*,G) entry: ports 0, 1 */
            mdb[0].ports = &pg[0];
            pg[0].next = &pg[1];
            /* Never back out of the ingress, member or not. */
            n = received(0, 8);
            assert(n == 1 && listed(n, 1) && local == 0);
            /* Router ports too, the ingress excepted. */
            add_router(2, family);
            add_router(0, family);
            n = received(0, 8);
            assert(n == 2 && listed(n, 1) && listed(n, 2) && !listed(n, 0));
            /* No isolated port from an isolated ingress. */
            port[0].flags = port[1].flags = BR_ISOLATED;
            n = received(0, 8);
            assert(n == 1 && listed(n, 2));
            port[0].flags = 0;
            n = received(0, 8);
            assert(n == 2 && listed(n, 1));
            port[1].flags = 0;
            /* A hairpin ingress would have its own frames back, and a
             * locked one forwards only sources its FDB knows. */
            port[0].flags = BR_HAIRPIN_MODE;
            assert(received(0, 8) == -EOPNOTSUPP);
            port[0].flags = BR_PORT_LOCKED;
            assert(received(0, 8) == -EOPNOTSUPP);
            port[0].flags = 0;
            /* An ingress that is not this bridge's port. */
            port[9].br = NULL;
            assert(received(9, 8) == -EINVAL);
            port[9].br = &br;
            dev[9].port = NULL;
            assert(received(9, 8) == -EINVAL);
            dev[9].port = &port[9];
            /* An ingress that is not forwarding forwards nothing, and hands
             * the host nothing: a learning port learns the source and drops
             * the frame. */
            mdb[0].host_joined = true;
            port[0].state = BR_STATE_LEARNING;
            assert(received(0, 8) == 0 && local == 0);
            port[0].state = BR_STATE_FORWARDING;
            mdb[0].host_joined = false;
            port[0].mst = true;
            assert(received(0, 8) == -EOPNOTSUPP);
            port[0].mst = false;
            if (vlan) {
                /* Nor one whose VLAN is not forwarding, not usable, or not
                 * the port's at all. */
                port[0].vlan.state = BR_STATE_LEARNING;
                assert(received(0, 8) == 0);
                port[0].vlan.state = BR_STATE_FORWARDING;
                port[0].vlan.usable = false;
                assert(received(0, 8) == 0);
                port[0].vlan.usable = true;
                port[0].vlan.vid = 43;
                assert(received(0, 8) == 0);
                port[0].vlan.vid = 42;
                /* The bridge itself outside the VLAN: what it sends goes
                 * nowhere, but a port's data is forwarded port to port. */
                br.vlan.usable = false;
                assert(snapshot(8) == 0);
                n = received(0, 8);
                assert(n == 2 && listed(n, 1) && listed(n, 2));
                br.vlan.usable = true;
            }

            /* What goes up: the host joined it; the bridge is a router,
             * permanently or by a query heard for this family only; or
             * nobody snoops, so everything floods and goes up. */
            mdb[0].host_joined = true;
            assert(received(0, 8) == 2 && local == BR_MCAST_TO_HOST_JOINED);
            mdb[0].host_joined = false;
            ctx()->multicast_router = MDB_RTR_TYPE_PERM;
            assert(received(0, 8) == 2 && local == BR_MCAST_TO_HOST_ROUTER);
            ctx()->multicast_router = MDB_RTR_TYPE_TEMP_QUERY;
            ctx()->router_timer[!family] = true;
            assert(received(0, 8) == 2 && local == 0);
            ctx()->router_timer[family] = true;
            assert(received(0, 8) == 2 && local == BR_MCAST_TO_HOST_ROUTER);
            ctx()->multicast_router = MDB_RTR_TYPE_DISABLED;
            assert(received(0, 8) == 2 && local == 0);
            ctx()->multicast_router = MDB_RTR_TYPE_PERM;
            mdb[0].host_joined = true;
            ctx()->querier[family] = false;
            port[5].flags = BR_MCAST_FLOOD;
            n = received(0, 8);
            assert(n == 1 && listed(n, 5) && local == BR_MCAST_TO_HOST_FLOOD);
            /* A proxy-ARP port is flooded nothing, whatever its flag. */
            port[5].flags = BR_MCAST_FLOOD | BR_PROXYARP;
            assert(received(0, 8) == 0 && local == BR_MCAST_TO_HOST_FLOOD);
            port[5].flags = 0;
            ctx()->querier[family] = true;
            /* A promiscuous bridge hands everything up besides. */
            bridge.flags = IFF_PROMISC;
            assert(received(0, 8) == 2 &&
                   local == (BR_MCAST_TO_HOST_JOINED | BR_MCAST_TO_HOST_ROUTER |
                             BR_MCAST_TO_HOST_PROMISC));
            bridge.flags = 0;
            mdb[0].host_joined = false;
            ctx()->multicast_router = MDB_RTR_TYPE_TEMP_QUERY;
            ctx()->router_timer[0] = ctx()->router_timer[1] = false;
            ctx()->ip4_mc_router_list.first = NULL;
            ctx()->ip6_mc_router_list.first = NULL;

            /* IGMPv3/MLDv2. An INCLUDE port group of the (*,G) entry is
             * never forwarded for a source; a source's own entry, with its
             * EXCLUDE ports copied in, is looked up first; a port that
             * blocks the source is skipped. */
            ctx()->include[family] = true;
            pg[1].filter_mode = MCAST_INCLUDE;
            assert(received(0, 8) == 0);
            present[1] = true;
            mdb[1].ports = &pg[3];
            pg[3].next = &pg[4];
            n = received(0, 8);
            assert(n == 2 && listed(n, 3) && listed(n, 4));
            pg[3].flags = MDB_PG_FLAGS_BLOCKED;
            n = received(0, 8);
            assert(n == 1 && listed(n, 4));
            pg[4].flags = MDB_PG_FLAGS_BLOCKED;
            assert(received(0, 8) == 0);
            /* IGMPv2/MLDv1: the (*,G) entry alone, whatever its modes. */
            ctx()->include[family] = false;
            n = received(0, 8);
            assert(n == 1 && listed(n, 1));
        }
    }
    /* The membership interval of the context the snapshot uses: the VLAN's
     * own under per-VLAN snooping, the bridge's otherwise, and nothing from a
     * device that is not a bridge. */
    for (int vlan = 0; vlan < 2; vlan++) {
        setup(0, vlan);
        br.multicast_ctx.multicast_membership_interval = 260;
        br.vlan.br_mcast_ctx.multicast_membership_interval = 20;
        assert(br_multicast_membership_interval(&bridge, 42) == (vlan ? 20 : 260));
        assert(br_multicast_membership_interval(&bridge, 43) == 260);
        br.opts[BROPT_MCAST_VLAN_SNOOPING_ENABLED] = false;
        assert(br_multicast_membership_interval(&bridge, 42) == 260);
        bridge.master = false;
        assert(br_multicast_membership_interval(&bridge, 42) == 0);
        assert(!rcu);
        calls++;
    }
#if !CONFIG_IPV6
    setup(1, false);
    assert(snapshot(8) == -EOPNOTSUPP);
#endif
    printf("%u multicast snapshot scenarios passed (IPv6=%d)\n", calls, CONFIG_IPV6);
    return 0;
}

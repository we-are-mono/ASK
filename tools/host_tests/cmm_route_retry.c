#include <arpa/inet.h>
#include <assert.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "fpp_private.h"
#include "cmm_route_flags.inc"

typedef void FCI_CLIENT;
struct cli_def;
#define NEIGHBOR_HASH_TABLE_SIZE 4
#include "route_cache.h"

#define CONNTRACK_HASH_TABLE_SIZE 4
#define ITF_HASH_TABLE_SIZE 4
#define SA_HASH_TABLE_SIZE 4
#define HASH_SOCKET_SIZE 4
#define CMMD_ERR_OK 0
#define CMMD_SOCKET_TYPE_LANWAN 0
#define PROTO_FAMILY_IPV4 AF_INET
#define cmm_print(...) ((void)0)
struct NeighborEntry { unsigned char macAddr[ETH_ALEN]; };
struct interface {
    struct list_head list;
    struct ct_route rt;
    int flags, tunnel_family, phys_ifindex;
    struct { struct { unsigned int daddr; } iph; } tunnel_parm4;
    struct { struct in6_addr raddr; } tunnel_parm6;
};
struct socket { struct list_head list; struct ct_route rt; int flags, type; };
struct SATable {
    struct list_head list_by_h;
    struct ct_route tnl_rt;
    int flags;
    struct {
        int proto_family;
        union {
            struct { unsigned int DestinationAddress; } ipv4h;
            struct { unsigned int DestinationAddress[4]; } ipv6h;
        } tunnel;
    } SAInfo;
};
struct nf_conntrack { unsigned int daddr[4]; };
struct ctTable {
    struct list_head list;
    struct nf_conntrack *ct;
    struct ct_route orig, rep, orig_tunnel, rep_tunnel;
    int flags, family, dir;
};
enum { ATTR_ORIG_IPV4_DST, ATTR_REPL_IPV4_DST, ATTR_ORIG_IPV6_DST,
       ATTR_REPL_IPV6_DST, ATTR_REPL_IPV4_SRC, ATTR_REPL_IPV6_SRC,
       ATTR_ORIG_IPV4_SRC, ATTR_ORIG_IPV6_SRC };
static struct list_head ct_table[CONNTRACK_HASH_TABLE_SIZE];
static struct { struct list_head hash[ITF_HASH_TABLE_SIZE]; } itf_table;
static struct list_head sa_table[SA_HASH_TABLE_SIZE], socket_table[HASH_SOCKET_SIZE];
static unsigned sa_lock, socket_lock;
static const unsigned char null_mac[ETH_ALEN];
static unsigned failure, calls, allocations, releases, hardware_id, extra_id;
static struct RtEntry current_route;
static struct NeighborEntry neighbor;
static struct fpp_rt *pool[256];
static unsigned hardware_refs[256], next_id;

static void __pthread_mutex_lock(unsigned *lock) { assert(!*lock); *lock = 1; }
static void __pthread_mutex_unlock(unsigned *lock) { assert(*lock); *lock = 0; }
static struct interface *__itf_find(int index) { return NULL; }
static int __itf_is_bridge(int index) { return 0; }
static int __itf_is_vlan(struct interface *itf) { return 0; }
static int __itf_is_tunnel(struct interface *itf) { return 1; }
static void cmmRouteFlushCache(int family) {}
static const unsigned int *nfct_get_attr(struct nf_conntrack *ct, int attr) { return ct->daddr; }
static int ____cmmCtRegister(FCI_CLIENT *client, struct ctTable *ct) { abort(); }
static int __cmmRouteIsTnlConn(int f, const unsigned int *a, int d, struct ctTable *c, int p, int n) { abort(); }

/* Device and route-cache boundaries: the production retry/rollback code
 * below owns counted references; these mocks reject deletes of live routes. */
struct fpp_rt *__cmmFPPRouteGet(int out, int in, int underlying,
        const unsigned char *mac, int mtu, const unsigned int *addr, int len)
{
    struct fpp_rt *rt;
    if (failure == 1)
        return NULL;
    for (unsigned id = 1; id <= next_id; id++) {
        rt = pool[id];
        if (rt && rt->oifindex == out && rt->iifindex == in && rt->mtu == mtu
                && !memcmp(rt->dst_mac, mac, ETH_ALEN) && rt->dst_addr_len == len
                && (!len || !memcmp(rt->dst_addr, addr, len))) {
            rt->count++;
            return rt;
        }
    }
    assert(next_id + 1 < 256);
    rt = calloc(1, sizeof(*rt)); assert(rt);
    rt->id = ++next_id; pool[rt->id] = rt;
    rt->oifindex = out; rt->iifindex = in; rt->underlying_iifindex = underlying;
    rt->mtu = mtu; rt->count = 1;
    memcpy(rt->dst_mac, mac, ETH_ALEN);
    rt->dst_addr_len = len;
    if (len) memcpy(rt->dst_addr, addr, len);
    allocations++;
    return rt;
}
void __cmmFPPRoutePut(struct fpp_rt *rt)
{
    assert(rt && rt->count > 0 && pool[rt->id] == rt);
    if (--rt->count == 0) {
        assert(hardware_refs[rt->id] == 0);
        pool[rt->id] = NULL; free(rt); releases++;
    }
}
static int cmmFeRouteUpdate(FCI_CLIENT *client, int action, struct fpp_rt *rt)
{
    assert(rt && pool[rt->id] == rt);
    if (action == REMOVE) {
        assert(hardware_refs[rt->id] == 0);
        rt->flags &= ~FPP_PROGRAMMED;
        return 0;
    }
    if (rt->flags & FPP_PROGRAMMED)
        return 0;
    if (failure == 2)
        return -1;
    rt->flags |= FPP_PROGRAMMED;
    return 0;
}
void __cmmFPPRouteDeregister(FCI_CLIENT *, struct fpp_rt *, const char *);
static void __cmmRouteDeregister(FCI_CLIENT *client, struct ct_route *rt, const char *dir)
{
    __cmmFPPRouteDeregister(client, rt->fpp_route, dir);
    if (rt->route) {
        assert(rt->route->count > 0);
        rt->route->count--;
    }
}
static int program(struct ct_route *rt, int *flags);
static int __tunnel_add(FCI_CLIENT *c, struct interface *itf) { return program(&itf->rt, &itf->flags); }
static int __socket_open(FCI_CLIENT *c, struct socket *s) { assert(socket_lock); return program(&s->rt, &s->flags); }
static int __cmmSATunnelRegister(FCI_CLIENT *c, struct SATable *s) { assert(sa_lock); return program(&s->tnl_rt, &s->flags); }
#include "cmm_route_retry.inc"

static int program(struct ct_route *rt, int *flags)
{
    calls++;
    if (!rt->route) {
        rt->route = &current_route;
        rt->route->count++;
    }
    if (__cmmFPPRouteRegister(rt, "test") < 0)
        return -1;
    __cmmCheckFPPRouteIdUpdate(rt, flags);
    if (cmmFeRouteUpdate(NULL, ADD | UPDATE, rt->fpp_route) < 0 || failure == 3)
        return -1;
    if (hardware_id) {
        assert(hardware_refs[hardware_id]);
        hardware_refs[hardware_id]--;
    }
    hardware_id = rt->fpp_route_id;
    hardware_refs[hardware_id]++;
    *flags = (*flags | FPP_PROGRAMMED) & ~FPP_NEEDS_UPDATE;
    return 0;
}

static void exercise(int kind, int family, int change, int fault, int shared, int local)
{
    struct interface itf = { .tunnel_family = family };
    struct socket sock = { .type = CMMD_SOCKET_TYPE_LANWAN };
    struct SATable sa = { .SAInfo.proto_family = family };
    struct ct_route *rt = kind == 0 ? &itf.rt : kind == 1 ? &sock.rt : &sa.tnl_rt;
    int *flags = kind == 0 ? &itf.flags : kind == 1 ? &sock.flags : &sa.flags;
    struct nf_conntrack ct = { .daddr = { htonl(0xc6336401), 2, 3, 4 } };
    struct ctTable local_ct = { .ct = &ct, .family = family, .flags = LOCAL_CONN_ORIG };
    struct rtmsg event = { .rtm_family = family, .rtm_dst_len = IPADDRLEN(family) * 8 };
    unsigned old, baseline_calls;

    memset(&current_route, 0, sizeof(current_route));
    memset(&neighbor, 0, sizeof(neighbor));
    current_route.neighEntry = &neighbor;
    current_route.family = family;
    current_route.phys_oifindex = 7;
    current_route.iifindex = 4;
    current_route.mtu = 1500;
    current_route.flow_flags = kind == 0 ? FLOWFLAG_LOCAL : kind == 1 ? FLOWFLAG_SOCKET_ROUTE : FLOWFLAG_SA_ROUTE;
    neighbor.macAddr[0] = 2; neighbor.macAddr[5] = 1;
    memcpy(current_route.dAddr, ct.daddr, sizeof(ct.daddr));
    itf.tunnel_parm4.iph.daddr = ct.daddr[0];
    memcpy(&itf.tunnel_parm6.raddr, ct.daddr, 16);
    if (family == AF_INET) sa.SAInfo.tunnel.ipv4h.DestinationAddress = ct.daddr[0];
    else memcpy(sa.SAInfo.tunnel.ipv6h.DestinationAddress, ct.daddr, 16);
    if (kind == 0) list_add(&itf_table.hash[0], &itf.list);
    else if (kind == 1) list_add(&socket_table[0], &sock.list);
    else list_add(&sa_table[0], &sa.list_by_h);

    /* A holder with no route must still use the normal initial registration. */
    failure = 0;
    __cmmRouteNew(NULL, &event, ct.daddr, 0);
    assert(rt->route == &current_route && rt->fpp_route && hardware_id == rt->fpp_route_id);
    assert(current_route.count == 1 && !(*flags & FPP_NEEDS_UPDATE));
    old = hardware_id;
    if (shared) {
        extra_id = old; pool[old]->count++; hardware_refs[old]++;
    }
    if (change == 0) neighbor.macAddr[5]++;
    else if (change == 1) current_route.phys_oifindex++;
    else if (change == 2) current_route.mtu -= 100;

    failure = fault;
    *flags |= FPP_NEEDS_UPDATE;
    if (kind == 0) __cmmTunnelRouteUpdate(NULL, &itf, &current_route);
    else if (kind == 1) __cmmSocketRouteUpdate(NULL, &sock, &current_route);
    else __cmmSARouteUpdate(NULL, &sa, &current_route);
    /* Route-add failure cannot trigger if an unchanged route is already
     * programmed. Other failures still exercise same-pointer rollback. */
    if (!(change == 3 && fault == 2)) {
        assert(rt->fpp_route_id == old && hardware_id == old);
        assert(*flags & FPP_NEEDS_UPDATE);
    }
    for (int retry = 0; retry < 2; retry++) {
        if (local) __cmmRouteLocalNew(NULL, &local_ct);
        else __cmmRouteNew(NULL, &event, ct.daddr, 0);
        if (!(change == 3 && fault == 2)) {
            assert(rt->fpp_route_id == old && hardware_id == old);
            assert(*flags & FPP_NEEDS_UPDATE);
        }
        assert(pool[old]->count == 1 + shared && current_route.count == 1);
        assert(!sa_lock && !socket_lock);
    }
    failure = 0;
    baseline_calls = calls;
    if (local) __cmmRouteLocalNew(NULL, &local_ct);
    else __cmmRouteNew(NULL, &event, ct.daddr, 0);
    if (!(change == 3 && fault == 2)) assert(calls == baseline_calls + 1);
    assert(!(*flags & FPP_NEEDS_UPDATE));
    assert(rt->fpp_route_id == hardware_id);
    assert(!memcmp(rt->fpp_route->dst_mac, neighbor.macAddr, ETH_ALEN));
    assert(rt->fpp_route->oifindex == current_route.phys_oifindex);
    assert(rt->fpp_route->mtu == current_route.mtu);
    assert(rt->fpp_route->count == 1 + (shared && change == 3));
    baseline_calls = calls;
    __cmmRouteNew(NULL, &event, ct.daddr, 0);
    assert(calls == baseline_calls);
    hardware_refs[hardware_id]--; hardware_id = 0;
    __cmmRouteDeregister(NULL, rt, "test");
    if (shared) {
        assert(pool[extra_id]->count == 1);
        hardware_refs[extra_id]--;
        __cmmFPPRouteDeregister(NULL, pool[extra_id], "other holder");
        extra_id = 0;
    }
    assert(current_route.count == 0 && allocations == releases);
    if (kind == 0) list_del(&itf.list);
    else if (kind == 1) list_del(&sock.list);
    else list_del(&sa.list_by_h);
    next_id = 0;
}

int main(void)
{
    for (int i = 0; i < 4; i++) {
        list_head_init(&ct_table[i]); list_head_init(&itf_table.hash[i]);
        list_head_init(&sa_table[i]); list_head_init(&socket_table[i]);
    }
    unsigned scenarios = 0;
    for (int kind = 0; kind < 3; kind++)
        for (int family = 0; family < 2; family++)
            for (int change = 0; change < 4; change++)
                for (int fault = 1; fault <= 3; fault++)
                    for (int shared = 0; shared < 2; shared++)
                        for (int local = 0; local <= (kind == 0); local++) {
                            exercise(kind, family ? AF_INET6 : AF_INET, change, fault, shared, local);
                            scenarios++;
                        }
    printf("CMM route retry: %u scenarios passed; fresh bindings, repeated refusal, shared references and local events\n", scenarios);
}

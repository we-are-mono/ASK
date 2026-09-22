/* Compile real XFRM ownership paths; only kernel infrastructure is simulated. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_MODULES 1
#define CONFIG_XFRM_OFFLOAD 1
#define MODULE_STATE_LIVE 0
#define GFP_ATOMIC 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, y) ((x) = (y))
#define NL_SET_ERR_MSG(e, s) ((void)0)
#define NL_SET_ERR_MSG_WEAK(e, s) ((void)0)
#define XFRM_OFFLOAD_IPV6 1
#define XFRM_OFFLOAD_INBOUND 2
#define XFRM_OFFLOAD_PACKET 4
#define XFRM_STATE_ESN 1
#define XFRM_SA_DIR_IN 1
#define XFRM_SA_DIR_OUT 2
#define XFRM_POLICY_IN 0
#define XFRM_POLICY_OUT 1
#define XFRM_POLICY_FWD 2
#define XFRM_DEV_OFFLOAD_UNSPECIFIED 0
#define XFRM_DEV_OFFLOAD_CRYPTO 1
#define XFRM_DEV_OFFLOAD_PACKET 2
#define XFRM_DEV_OFFLOAD_IN 1
#define XFRM_DEV_OFFLOAD_OUT 2
#define XFRM_DEV_OFFLOAD_FWD 3
#define IS_ERR(p) ((intptr_t)(p) < 0)
typedef uint8_t u8;
typedef uint32_t xfrm_address_t;
struct net { int unused; };
struct netlink_ext_ack { int unused; };
struct module { int state, refs; bool refuse; };
struct xfrm_state;
struct xfrm_policy;
struct xfrmdev_ops {
    struct module *owner;
    int (*xdo_dev_state_add)(struct xfrm_state *, struct netlink_ext_ack *);
    void (*xdo_dev_state_delete)(struct xfrm_state *);
    void (*xdo_dev_state_free)(struct xfrm_state *);
    void (*xdo_dev_state_advance_esn)(struct xfrm_state *);
    void (*xdo_dev_state_update_stats)(struct xfrm_state *);
    int (*xdo_dev_policy_add)(struct xfrm_policy *, struct netlink_ext_ack *);
    void (*xdo_dev_policy_delete)(struct xfrm_policy *);
    void (*xdo_dev_policy_free)(struct xfrm_policy *);
};
struct net_device { const struct xfrmdev_ops *xfrmdev_ops; int refs; };
struct xfrm_dev_offload {
    struct net_device *dev, *real_dev;
    const struct xfrmdev_ops *ops;
    int dev_tracker, dir, type;
};
struct xfrm_state {
    struct xfrm_dev_offload xso;
    struct { xfrm_address_t saddr; int family, flags; } props;
    struct { xfrm_address_t daddr; } id;
    int type_offload, dir, tfcpad, dev_gclist;
};
struct xfrm_policy { struct xfrm_dev_offload xdo; };
struct xfrm_user_offload { int flags, ifindex; };
struct dst_entry { struct net_device *dev; };
struct xfrm_dst_lookup_params {
    struct net *net;
    xfrm_address_t *saddr, *daddr;
    int mark;
};
static struct net_device device;
static int read_depth, add_error, state_adds, policy_adds;
static int state_deletes, state_frees, policy_deletes, policy_frees, stats, esns;
static int xfrm_state_dev_gc_lock, xfrm_state_dev_gc_list, xfrm_state_cache;
static void rcu_read_lock(void) { read_depth++; }
static void rcu_read_unlock(void) { assert(read_depth == 1); read_depth--; }
static bool try_module_get(struct module *m)
{
    if (!m) return true;
    if (m->refuse) return false;
    m->refs++;
    return true;
}
static void module_put(struct module *m)
{ if (m) { assert(m->refs > 0); m->refs--; } }
static struct net_device *dev_get_by_index(struct net *n, int index)
{ if (index != 1) return NULL; device.refs++; return &device; }
static void dev_hold(struct net_device *d) { d->refs++; }
static void dev_put(struct net_device *d) { assert(d->refs > 0); d->refs--; }
static void netdev_tracker_alloc(struct net_device *d, int *t, int g) { *t = 1; }
static void netdev_put(struct net_device *d, int *t) { assert(*t); *t = 0; dev_put(d); }
static int xfrm_smark_get(int n, struct xfrm_state *x) { return 0; }
static struct dst_entry *__xfrm_dst_lookup(int f, struct xfrm_dst_lookup_params *p)
{ return (void *)(intptr_t)-ENETUNREACH; }
static void dst_release(struct dst_entry *d) { }
static void spin_lock_bh(int *l) { assert(!*l); *l = 1; }
static void spin_unlock_bh(int *l) { assert(*l); *l = 0; }
static void hlist_add_head(int *n, int *h) { assert(!*n); *n = 1; }
static bool hlist_unhashed(int *n) { return !*n; }
static void hlist_del(int *n) { assert(*n); *n = 0; }
static void kmem_cache_free(int c, void *p) { free(p); }

#include "xfrm_provider_production.inc"

static void pinned(const struct xfrmdev_ops *ops)
{ assert(ops && (!ops->owner || ops->owner->refs > 0)); }
static int state_add(struct xfrm_state *x, struct netlink_ext_ack *e)
{ pinned(x->xso.ops); state_adds++; return add_error; }
static int policy_add(struct xfrm_policy *x, struct netlink_ext_ack *e)
{ pinned(x->xdo.ops); policy_adds++; return add_error; }
static void state_delete(struct xfrm_state *x)
{ pinned(x->xso.ops); state_deletes++; }
static void state_free(struct xfrm_state *x)
{ pinned(x->xso.ops); state_frees++; }
static void policy_delete(struct xfrm_policy *x)
{ pinned(x->xdo.ops); policy_deletes++; }
static void policy_free(struct xfrm_policy *x)
{ pinned(x->xdo.ops); policy_frees++; }
static void update_stats(struct xfrm_state *x)
{ pinned(x->xso.ops); stats++; }
static void advance_esn(struct xfrm_state *x)
{ pinned(x->xso.ops); esns++; }

int main(void)
{
    struct module owner = {0};
    struct xfrmdev_ops ops = {
        .owner = &owner, .xdo_dev_state_add = state_add,
        .xdo_dev_state_delete = state_delete, .xdo_dev_state_free = state_free,
        .xdo_dev_state_update_stats = update_stats,
        .xdo_dev_state_advance_esn = advance_esn,
        .xdo_dev_policy_add = policy_add, .xdo_dev_policy_delete = policy_delete,
        .xdo_dev_policy_free = policy_free,
    };
    struct xfrm_user_offload request = {.ifindex = 1, .flags = XFRM_OFFLOAD_PACKET};
    struct net net = {0};
    device.xfrmdev_ops = &ops;
    /* A provider cannot accumulate references during failed module init,
     * once unload starts, or when the module reference operation refuses. */
    for (int unavailable = 0; unavailable < 3; unavailable++) {
        owner.state = unavailable < 2 ? unavailable + 1 : MODULE_STATE_LIVE;
        owner.refuse = unavailable == 2;
        struct xfrm_state x = {.type_offload = 1};
        struct xfrm_policy p = {0};
        assert(xfrm_dev_state_add(&net, &x, &request, NULL) == -EINVAL);
        assert(xfrm_dev_policy_add(&net, &p, &request, XFRM_POLICY_OUT, NULL) == -EINVAL);
        assert(!owner.refs && !device.refs && !state_adds && !policy_adds);
    }
    owner.state = MODULE_STATE_LIVE;
    owner.refuse = false;
    /* Callback failures, unsupported callbacks, and invalid directions
     * release both the provider and the device, permitting later unload. */
    for (int err = 0; err < 3; err++) {
        struct xfrm_state x = {.type_offload = 1};
        struct xfrm_policy p = {0};
        add_error = err == 0 ? -ENOMEM : -EOPNOTSUPP;
        if (err == 2) ops.xdo_dev_state_add = NULL;
        assert(xfrm_dev_state_add(&net, &x, &request, NULL) < 0);
        assert(xfrm_dev_policy_add(&net, &p, &request, XFRM_POLICY_OUT, NULL) < 0);
        assert(!owner.refs && !device.refs && !x.xso.ops && !p.xdo.ops);
    }
    ops.xdo_dev_state_add = state_add;
    add_error = 0;
    struct xfrm_policy invalid = {0};
    assert(xfrm_dev_policy_add(&net, &invalid, &request, 255, NULL) == -EINVAL);
    assert(!owner.refs && !device.refs);
    assert(!bond_ipsec_ops(&device) && !owner.refs);

    struct xfrm_state *x = calloc(1, sizeof(*x));
    struct xfrm_policy p = {0};
    x->type_offload = 1;
    assert(!xfrm_dev_state_add(&net, x, &request, NULL));
    assert(!xfrm_dev_policy_add(&net, &p, &request, XFRM_POLICY_OUT, NULL));
    assert(owner.refs == 2 && device.refs == 2);
    /* Device detachment must not redirect callbacks or release code while
     * a packet still references an otherwise retired state. */
    device.xfrmdev_ops = NULL;
    xfrm_dev_state_update_stats(x);
    xfrm_dev_state_advance_esn(x);
    xfrm_dev_state_delete(x);
    xfrm_dev_state_free(x);
    xfrm_dev_state_free(x);
    assert(owner.refs == 2 && device.refs == 1);
    assert(state_deletes == 1 && state_frees == 1 && stats == 1 && esns == 1);
    xfrm_dev_policy_delete(&p);
    xfrm_dev_policy_free(&p);
    xfrm_dev_policy_free(&p);
    assert(policy_deletes == 1 && policy_frees == 1);
    assert(owner.refs == 1 && !device.refs);
    xfrm_state_free(x);
    assert(!owner.refs && !read_depth);

    /* Permanent providers retain the existing device-owned contract. */
    ops.owner = NULL;
    device.xfrmdev_ops = &ops;
    assert(bond_ipsec_ops(&device) == &ops);
    assert(!xfrm_dev_policy_add(&net, &p, &request, XFRM_POLICY_IN, NULL));
    xfrm_dev_policy_delete(&p);
    xfrm_dev_policy_free(&p);
    assert(!device.refs);
    puts("XFRM provider ownership and failure paths passed");
    return 0;
}

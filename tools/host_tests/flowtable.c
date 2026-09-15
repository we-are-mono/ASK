/* Kernel shims for production adapter tests; no duplicate decoder or lifecycle. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

typedef uint8_t u8;
typedef uint16_t u16, __be16;
typedef uint32_t u32, __be32;
typedef uint64_t u64, atomic64_t;
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_ALL 3
#define BIT(n) (1UL << (n))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define GFP_KERNEL 0
#define HZ 100
#define WARN_ON_ONCE(x) (x)
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define pr_warn_ratelimited(...) ((void)0)
#define __init
#define __exit
#define CDX_DEBUG_FLOWTABLE
#define FLOW_ACTION_HW_STATS_DELAYED 1
#define IP_CT_DIR_ORIGINAL 0
#define IP_CT_DIR_REPLY 1
#define IPS_NAT_MASK 0x30
#define IPS_SRC_NAT 0x10
#define IPS_SRC_NAT_DONE 0x80
#define IS_ENABLED(x) 1
#define TCA_CSUM_UPDATE_FLAG_IPV4HDR 1
#define TCA_CSUM_UPDATE_FLAG_TCP 8
#define TCA_CSUM_UPDATE_FLAG_UDP 16
struct iphdr { u8 prefix[12]; __be32 saddr, daddr; };
#define IPS_ASSURED 4
#define TCPHDR_FIN 1
#define TCPHDR_RST 4
#define TCP_CONNTRACK_ESTABLISHED 3
#define NUD_PERMANENT 128
#define NUD_NOARP 64
#define NUD_FAILED 32
#define NUD_PROBE 16
#define NUD_DELAY 8
#define NUD_STALE 4
#define NUD_REACHABLE 2
#define NUD_INCOMPLETE 1
#define NETEVENT_NEIGH_UPDATE 1
#define NETEVENT_IPV4_ROUTE_UPDATE 7
enum { FIB_EVENT_ENTRY_REPLACE, FIB_EVENT_ENTRY_APPEND, FIB_EVENT_ENTRY_ADD,
       FIB_EVENT_ENTRY_DEL, FIB_EVENT_RULE_ADD, FIB_EVENT_RULE_DEL, FIB_EVENT_NH_ADD, FIB_EVENT_NH_DEL };
enum { NETDEV_GOING_DOWN, NETDEV_UNREGISTER, NETDEV_CHANGEMTU, NETDEV_CHANGEADDR,
       NETDEV_CHANGEUPPER, NETDEV_CHANGENAME, NETDEV_REGISTER, NETDEV_CHANGE };
enum { NEXTHOP_EVENT_DEL, NEXTHOP_EVENT_REPLACE, NEXTHOP_EVENT_RES_TABLE_PRE_REPLACE,
       NEXTHOP_EVENT_BUCKET_REPLACE, NEXTHOP_EVENT_HW_STATS_REPORT_DELTA };
struct fib_notifier_info { int family; };
struct netevent_ipv4_route { struct net *net; __be32 dst; u8 prefixlen; };
static __be32 inet_make_mask(unsigned plen) { assert(plen <= 32); return htonl(plen ? ~0U << (32 - plen) : 0); }
#define NOTIFY_DONE 0
#define cmpxchg(p, old, new) ({ typeof(*(p)) v = *(p); if (v == (old)) *(p) = (new); v; })
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define list_entry(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m); &p->m != (h); p = list_entry(p->m.next, typeof(*p), m))
#define list_for_each_entry_safe(p, n, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m), n = list_entry(p->m.next, typeof(*p), m); \
         &p->m != (h); p = n, n = list_entry(n->m.next, typeof(*n), m))
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; }
static void list_init(struct list_head *h) { h->next = h->prev = h; }
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define lockdep_assert_held(p) assert(*(p))
enum tc_setup_type { TC_SETUP_FT, TC_SETUP_CLSFLOWER };
enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
enum { FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS, FLOW_BLOCK_BIND, FLOW_BLOCK_UNBIND };
struct Qdisc { int unused; };
struct flow_block { struct list_head cb_list; };
struct flow_block_offload {
    struct flow_block *block;
    struct net *net;
    int binder_type, command;
    struct list_head *driver_block_list, cb_list;
};
struct flow_block_cb {
    struct list_head list, driver_list;
    void *ident, *priv;
    void (*release)(void *);
};
struct net { int id; };
static struct net init_net;
struct net_device { int ifindex, refs, mtu; u8 dev_addr[6]; struct net *net; bool carrier_lost, down; };
#define netif_carrier_ok(d) (!(d)->carrier_lost)
#define netif_running(d) (!(d)->down)
#define fallthrough __attribute__((fallthrough))
#define dev_net(d) ((d)->net ? (d)->net : &init_net)
struct netdev_notifier_info { struct net_device *dev; };
#define netdev_notifier_info_to_dev(p) (((struct netdev_notifier_info *)(p))->dev)
struct dst_ops { unsigned family; };
struct dst_entry {
    struct dst_ops *ops;
    struct net_device *dev;
    void *xfrm, *lwtstate;
    bool valid;
};
struct rtable { struct dst_entry dst; unsigned rt_type, rt_gw_family; __be32 rt_gw4; };
#define RTN_UNICAST 1
#define dst_xfrm(d) ((d)->xfrm)
#define dst_rtable(d) ((struct rtable *)(d))
static struct dst_entry *dst_check(struct dst_entry *d, unsigned cookie)
{ assert(!cookie); return d->valid ? d : NULL; }
static __be32 rt_nexthop(const struct rtable *r, __be32 address)
{ return r->rt_gw_family == AF_INET ? r->rt_gw4 : address; }
struct neigh_table { int unused; };
static struct neigh_table arp_tbl;
struct neighbour {
    struct neigh_table *tbl;
    struct net_device *dev;
    unsigned refs, nud_state;
    __be32 primary_key;
    bool dead, lock;
    u8 ha[6];
};
struct notifier_block { int unused; };
static struct neighbour neighbour, gateway, alternate_gateway;
static void read_lock_bh(bool *lock) { assert(!*lock); *lock = true; }
static void read_unlock_bh(bool *lock) { assert(*lock); *lock = false; }
#define spin_lock read_lock_bh
#define spin_unlock read_unlock_bh
#define spin_lock_bh read_lock_bh
#define spin_unlock_bh read_unlock_bh
struct nf_flowtable { struct { int nelems; } rhashtable; bool use_neigh, use_hw_handles, flow_block_lock; };
struct nf_conntrack_tuple {
    struct { struct { __be32 ip; } u3; union { __be16 all; } u; } src, dst;
};
struct nf_conn_nat { int masq_index; };
struct nf_conn { struct net *net; unsigned zone[2], mark, status, protonum, tcp_state;
    struct { struct nf_conntrack_tuple tuple; } tuplehash[2]; struct nf_conn_nat *nat; };
#define nfct_nat(c) ((c)->nat)
#define nf_ct_protonum(c) ((c)->protonum)
static bool nf_conntrack_tcp_established(const struct nf_conn *c)
{ return c->tcp_state == TCP_CONNTRACK_ESTABLISHED && (c->status & IPS_ASSURED); }
#define nf_ct_net(c) ((c)->net)
#define nf_ct_zone(c) ((c)->zone)
#define nf_ct_zone_id(z, dir) ((z)[dir])
#define net_eq(a, b) ((a) == (b))
static bool is_valid_ether_addr(const u8 *a)
{ return !(a[0] & 1) && memcmp(a, (u8[6]){0}, 6); }
#define ether_addr_equal(a, b) (!memcmp(a, b, 6))
#define ether_addr_copy(a, b) memcpy(a, b, 6)
#define ipv4_is_multicast(a) ((ntohl(a) & 0xf0000000) == 0xe0000000)
#define ipv4_is_zeronet(a) ((ntohl(a) & 0xff000000) == 0)
#define ipv4_is_loopback(a) ((ntohl(a) & 0xff000000) == 0x7f000000)
#define ipv4_is_lbcast(a) ((a) == htonl(0xffffffff))
enum { FLOW_DISSECTOR_KEY_META, FLOW_DISSECTOR_KEY_CONTROL, FLOW_DISSECTOR_KEY_BASIC,
       FLOW_DISSECTOR_KEY_IPV4_ADDRS, FLOW_DISSECTOR_KEY_PORTS, FLOW_DISSECTOR_KEY_TCP };
struct flow_dissector { unsigned long used_keys; };
struct meta { int ingress_ifindex; u16 ingress_iftype; u8 l2_miss; };
struct control { u16 thoff, addr_type; u32 flags; };
struct basic { __be16 n_proto; u8 ip_proto, padding; };
struct ipv4_addrs { __be32 src, dst; };
struct ports { __be16 src, dst; };
struct tcp { __be16 flags; };
#define MATCH(t) struct flow_match_##t { struct t *key, *mask; }
MATCH(meta); MATCH(control); MATCH(basic); MATCH(ipv4_addrs); MATCH(ports);
MATCH(tcp);
enum { FLOW_ACTION_MANGLE, FLOW_ACTION_REDIRECT, FLOW_ACTION_CSUM, FLOW_ACT_MANGLE_HDR_TYPE_IP4, FLOW_ACT_MANGLE_HDR_TYPE_UDP, FLOW_ACT_MANGLE_HDR_TYPE_TCP, FLOW_ACT_MANGLE_HDR_TYPE_ETH };
struct flow_action_entry {
    unsigned id, csum_flags;
    struct { unsigned htype, offset; u32 mask, val; } mangle;
    struct net_device *dev;
};
struct flow_action { unsigned num_entries; struct flow_action_entry entries[10]; };
struct flow_rule {
    struct { struct flow_dissector *dissector; } match;
    struct flow_action action;
    struct flow_match_meta meta;
    struct flow_match_control control;
    struct flow_match_basic basic;
    struct flow_match_ipv4_addrs ipv4_addrs;
    struct flow_match_ports ports;
    struct flow_match_tcp tcp;
};
#define GETMATCH(t) static void flow_rule_match_##t(struct flow_rule *r, struct flow_match_##t *m) { *m = r->t; }
GETMATCH(meta) GETMATCH(control) GETMATCH(basic) GETMATCH(ipv4_addrs) GETMATCH(ports)
GETMATCH(tcp)
struct flow_stats { u64 bytes, pkts; unsigned long lastused; };
struct nf_flow_offload_handle { unsigned refs; bool invalid; };
static struct nf_flow_offload_handle handle;
static bool nf_flow_offload_handle_valid(const struct nf_flow_offload_handle *h)
{ return h && !h->invalid; }
static bool nf_flow_offload_handle_invalidate(struct nf_flow_offload_handle *h)
{ bool old = h->invalid; h->invalid = true; return !old; }
static void nf_flow_offload_handle_get(struct nf_flow_offload_handle *h)
{ assert(h->refs); h->refs++; }
static void nf_flow_offload_handle_put(struct nf_flow_offload_handle *h)
{ assert(h->refs > 1); h->refs--; }
struct flow_cls_offload {
    const struct nf_conn *nf_ct;
    struct dst_entry *nf_dst, *nf_dst_reverse;
    struct nf_flow_offload_handle *nf_handle;
    unsigned command;
    u16 nf_mtu;
    bool nf_counter;
    struct { unsigned chain_index, protocol; } common;
    struct flow_rule *rule;
    unsigned long cookie;
    struct flow_stats stats;
};
static void flow_stats_update(struct flow_stats *s, u64 b, u64 p, u64 d, unsigned long t, int mode)
{ s->bytes += b; s->pkts += p; s->lastused = t; }
#include "flowtable_types.inc"
struct cdx_ft_hw { struct cdx_ft_counters stats; };
struct work_struct { int unused; };
static int ft_work, ft_retire_work;
static LIST_HEAD(ft_bindings);
static LIST_HEAD(ft_entries);
static LIST_HEAD(ft_neigh_entries);
static bool ft_watch_lock;
static LIST_HEAD(ft_block_list);
static unsigned ft_count, ft_bound, ft_fail_stage, ft_init_fail_stage;
static unsigned ft_neighbour_refs, ft_handle_refs;
static u64 ft_installs, ft_deletes, ft_errors, ft_validated, ft_rearms, ft_busy, ft_rejects;
static u64 ft_neigh_invalidations, ft_route_invalidations, ft_mtu_invalidations, ft_link_invalidations, ft_mac_invalidations, ft_admission_invalidations;
static void atomic64_inc(u64 *v) { (*v)++; }
static bool ft_observe, ft_stopping, ft_fatal, ft_invalid_done, ft_ready = true;
static int ft_invalid;
static unsigned long jiffies = 1000;
static unsigned allocated, live_hw, flushed, scheduled;
static bool allocation_fail, hardware_fail, invalidate_on_add, physical_ok = true, neigh_ok = true;
static bool change_neigh_on_add, change_neigh_on_lookup;
static unsigned neigh_lookups, neigh_uses;
static int neigh_send_error;
static int deletion_error;
static bool rtnl_busy, rtnl, quiesce_fail;
static bool callback_allocation_fail, invalidate_on_bind;
static unsigned private_pending, legacy_pending;
static int retry_error;
static void (*cleanup_hook)(void);
static struct { struct { bool mutex; } ctrl; } instance, *cdx_info = &instance;
static void mutex_lock(bool *m) { assert(!*m); *m = true; }
static void mutex_unlock(bool *m) { assert(*m); *m = false; }
static bool rtnl_trylock(void) { if (rtnl_busy) return false; assert(!rtnl); rtnl = true; return true; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = false; }
static int dpa_cfg_quiesce(void) { assert(rtnl && cdx_info->ctrl.mutex); return quiesce_fail ? -EIO : 0; }
static void cdx_ft_begin(void) { assert(!ft_watch_lock); mutex_lock(&cdx_info->ctrl.mutex); }
static void cdx_ft_end(void) { assert(!ft_watch_lock); mutex_unlock(&cdx_info->ctrl.mutex); }
static void cdx_ft_assert_held(void) { assert(cdx_info->ctrl.mutex); }
static bool *block_write_lock;
static void down_write(bool *lock)
{ assert(!cdx_info->ctrl.mutex && !*lock && !block_write_lock); *lock = true; block_write_lock = lock; }
static void up_write(bool *lock)
{ assert(!cdx_info->ctrl.mutex && *lock && block_write_lock == lock); *lock = false; block_write_lock = NULL; }
static int cdx_ft_admission_begin(void) { return rtnl_trylock() ? 0 : -EAGAIN; }
static void cdx_ft_admission_end(void) { rtnl_unlock(); }
static bool cdx_ft_failed(void) { return ft_fatal; }
static bool cdx_ft_observing(void) { return ft_observe; }
static unsigned cdx_ft_pending(void) { return private_pending + legacy_pending; }
static int cdx_ft_recover(void)
{
    assert(cdx_info->ctrl.mutex);
    if (ft_fatal) {
        if (!rtnl_trylock()) return -EAGAIN;
        int rc = dpa_cfg_quiesce(); rtnl_unlock();
        if (rc) return -EAGAIN;
    }
    return retry_error;
}
static void schedule_delayed_work(int *work, unsigned delay) { scheduled++; }
static unsigned neigh_scheduled;
static void schedule_work(int *work) { assert(work == &ft_retire_work); neigh_scheduled++; }
static void nf_flow_table_cleanup(struct net_device *dev)
{ assert(!cdx_info->ctrl.mutex); flushed++; if (cleanup_hook) cleanup_hook(); }
static void dev_hold(struct net_device *d) { d->refs++; }
static void dev_put(struct net_device *d) { assert(d->refs > 0); d->refs--; }
static int atomic_read(int *v) { return *v; }
static void atomic_set(int *v, int n) { *v = n; }
static void ft_invalidate(void) { ft_invalid = 1; }
static bool cdx_ft_port_supported(struct net_device *d) { return d && physical_ok; }
static struct neighbour *neigh_lookup(struct neigh_table *table, const __be32 *dst, struct net_device *dev)
{
    neigh_lookups++;
    if (!neigh_ok) return NULL;
    assert(table == &arp_tbl);
    struct neighbour *all[] = {&neighbour, &gateway, &alternate_gateway};
    for (unsigned i = 0; i < ARRAY_SIZE(all); i++) {
        struct neighbour *n = all[i];
        if (n->primary_key != *dst || n->dev != dev) continue;
        if (change_neigh_on_lookup && neigh_lookups == 2) n->ha[5]++;
        n->refs++;
        return n;
    }
    return NULL;
}
static void neigh_release(struct neighbour *n) { assert(n->refs); n->refs--; }
static int neigh_event_send(struct neighbour *n, void *skb)
{
    assert(n->refs && !n->lock && !ft_watch_lock && !skb);
    neigh_uses++;
    return neigh_send_error;
}
static void *kzalloc(size_t n, int flags) { if (allocation_fail) return NULL; allocated++; return calloc(1, n); }
static void kfree(void *p) { assert(allocated); allocated--; free(p); }
static int ft_rule_callback(enum tc_setup_type t, void *data, void *priv);
static int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr);
typedef int (*rule_callback_t)(enum tc_setup_type, void *, void *);
static struct flow_block_cb *flow_indr_block_cb_alloc(rule_callback_t fn, void *ident,
    void *priv, void (*release)(void *), struct flow_block_offload *bo,
    struct net_device *dev, struct Qdisc *sch, void *table, void *driver,
    void (*cleanup)(struct flow_block_cb *))
{
    if (callback_allocation_fail) return ERR_PTR(-ENOMEM);
    struct flow_block_cb *cb = kzalloc(sizeof(*cb), GFP_KERNEL); assert(cb);
    cb->ident = ident; cb->priv = priv; cb->release = release;
    if (invalidate_on_bind) { assert(ft_bound); ft_invalidate(); }
    return cb;
}
static void flow_block_cb_add(struct flow_block_cb *cb, struct flow_block_offload *bo)
{ list_add_tail(&cb->list, &bo->cb_list); }
static struct flow_block_cb *flow_block_cb_lookup(struct flow_block *block,
                                                 rule_callback_t fn, void *ident)
{
    struct flow_block_cb *cb;
    list_for_each_entry(cb, &block->cb_list, list) if (cb->ident == ident) return cb;
    return NULL;
}
static void flow_indr_block_cb_remove(struct flow_block_cb *cb, struct flow_block_offload *bo)
{
    /* Moving a published callback must exclude native stats walkers before
     * it reaches the temporary list; protecting only its free is too late. */
    assert(block_write_lock && *block_write_lock);
    list_del(&cb->list); list_add_tail(&cb->list, &bo->cb_list);
}
static int cdx_ft_add(const struct cdx_ft_rule *r, struct cdx_ft_hw **hw)
{
    if (hardware_fail) return -EIO;
    *hw = calloc(1, sizeof(**hw)); assert(*hw); live_hw++;
    (*hw)->stats.lastused = (u32)jiffies;
    if (invalidate_on_add) ft_invalidate();
    if (change_neigh_on_add) {
        neighbour.ha[5]++;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    }
    return 0;
}
static int cdx_ft_del(struct cdx_ft_hw **hw)
{ assert(*hw && live_hw); live_hw--; free(*hw); *hw = NULL; if (deletion_error == -EIO) ft_fatal = true; return deletion_error; }
static void cdx_ft_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats) { *stats = hw->stats; }

/* Registration infrastructure; backend claim semantics are exercised against
 * production CDX in flowtable_hw.c. Here each acquisition can fail in turn. */
struct proc_dir_entry { int unused; };
static struct proc_dir_entry proc_entry, *ft_proc;
static int ft_proc_ops;
static struct notifier_block ft_netdev_nb, ft_neigh_nb, ft_fib_nb, ft_nexthop_nb;
static unsigned registration_step, registration_failure, canceled;
static bool backend_claimed, netdev_registered, neigh_registered, fib_registered, nexthop_registered, indirect_registered;
static bool owner_enabled = true;
static bool registration_fails(void) { return ++registration_step == registration_failure; }
static struct proc_dir_entry *proc_create(const char *name, int mode, void *parent, void *ops)
{ assert(!strcmp(name,"cdx_flowtable") && mode == 0400 && !parent); return registration_fails() ? NULL : &proc_entry; }
static void proc_remove(struct proc_dir_entry *entry) { assert(entry == &proc_entry); }
static int cdx_ft_claim(void)
{
    assert(cdx_info->ctrl.mutex && !backend_claimed);
    if (!owner_enabled || ft_fatal) return -EOPNOTSUPP;
    if (registration_fails()) return -EBUSY;
    backend_claimed = true; return 0;
}
static int cdx_ft_release(void)
{
    assert(cdx_info->ctrl.mutex && backend_claimed && !live_hw);
    backend_claimed = false; return 0;
}
static int register_netdevice_notifier(struct notifier_block *nb)
{ if (registration_fails()) return -ENOMEM; netdev_registered=true; return 0; }
static int register_netevent_notifier(struct notifier_block *nb)
{ if (registration_fails()) return -ENOMEM; neigh_registered=true; return 0; }
static int register_fib_notifier(struct net *net, struct notifier_block *nb, void *cb, void *extack)
{ if (registration_fails()) return -ENOMEM; fib_registered=true; return 0; }
static int register_nexthop_notifier(struct net *net, struct notifier_block *nb, void *extack)
{ assert(net == &init_net && !cdx_info->ctrl.mutex); if (registration_fails()) return -ENOMEM; nexthop_registered=true; return 0; }
static void unregister_nexthop_notifier(struct net *net, struct notifier_block *nb)
{ assert(net == &init_net && nexthop_registered && !cdx_info->ctrl.mutex); nexthop_registered=false; }
static void unregister_netdevice_notifier(struct notifier_block *nb)
{ assert(netdev_registered); netdev_registered=false; }
static void unregister_netevent_notifier(struct notifier_block *nb)
{ assert(neigh_registered); neigh_registered=false; }
static void unregister_fib_notifier(struct net *net, struct notifier_block *nb)
{ assert(fib_registered); fib_registered=false; }
static void cancel_work_sync(int *work) { assert(work == &ft_retire_work); canceled++; }
static void cancel_delayed_work_sync(int *work) { assert(work == &ft_work); canceled++; }
static int register_indirect(void)
{ assert(ft_ready); if (registration_fails()) return -ENOMEM; indirect_registered=true; return 0; }
static void unregister_indirect(void)
{
    assert(indirect_registered && canceled == 2 && !cdx_info->ctrl.mutex);
    assert(!netdev_registered && !neigh_registered && !fib_registered && !nexthop_registered);
    while (ft_block_list.next != &ft_block_list) {
        struct flow_block_cb *cb = list_entry(ft_block_list.next, struct flow_block_cb, driver_list);
        list_del(&cb->driver_list); list_del(&cb->list);
        cb->release(cb->priv); kfree(cb);
    }
    indirect_registered=false;
}
#define flow_indr_dev_register(fn, priv) register_indirect()
#define flow_indr_dev_unregister(fn, priv, release) unregister_indirect()
static unsigned unload_sleeps, unload_failures;
static void msleep(unsigned ms)
{
    assert(ms == 1000 && backend_claimed && !cdx_info->ctrl.mutex && !rtnl);
    assert(!indirect_registered && !ft_count && !ft_bound && canceled == 2);
    assert(unload_failures);
    unload_sleeps++;
    if (!--unload_failures) { retry_error=0; quiesce_fail=false; }
}
#include "flowtable_production.inc"

static struct net_device in = { .ifindex = 5, .mtu = 1500, .dev_addr = {2, 0, 0, 0, 0, 1} };
static struct net_device out = { .ifindex = 6, .mtu = 1500, .dev_addr = {2, 0, 0, 0, 0, 2} };
static struct cdx_ft_binding binding = { .dev = &in };
static struct dst_ops ipv4_ops = { .family = AF_INET };
static struct rtable route, reverse_route;
static __be32 next_hop;
static struct nf_conn ct;
static struct flow_dissector dissector;
static struct flow_rule rule;
static struct flow_cls_offload cls;
static struct meta mk, mm;
static struct control ck, cm;
static struct basic bk, bm;
static struct ipv4_addrs ik, im;
static struct ports pk, pm;
static struct tcp tk, tm;
static void fixture(void)
{
    assert(!ft_handle_refs && handle.refs <= 1);
    handle = (struct nf_flow_offload_handle){ .refs = 1 };
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs && ft_neigh_entries.next == &ft_neigh_entries);
    neighbour = (struct neighbour){ .tbl = &arp_tbl, .nud_state = NUD_PERMANENT,
                                  .ha = {2,0x11,0x22,0x33,0x44,0x55}, .dev = &out,
                                  .primary_key = htonl(0xc6336402) };
    gateway = alternate_gateway = neighbour;
    gateway.primary_key = htonl(0xc6336401);
    alternate_gateway.primary_key = htonl(0xc6336403);
    route = (struct rtable){ .dst = { .ops = &ipv4_ops, .dev = &out, .valid = true },
                             .rt_type = RTN_UNICAST };
    reverse_route = route;
    reverse_route.dst.dev = &in;
    neigh_lookups = 0;
    ct = (struct nf_conn){ .net = &init_net, .protonum = IPPROTO_UDP };
    dissector.used_keys = 31;
    mk = (struct meta){ .ingress_ifindex = 5 }; mm = (struct meta){ .ingress_ifindex = -1 };
    ck = (struct control){ .addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS };
    cm = (struct control){ .addr_type = 0xffff };
    bk = (struct basic){ .n_proto = htons(ETH_P_IP), .ip_proto = IPPROTO_UDP };
    bm = (struct basic){ .n_proto = htons(0xffff), .ip_proto = 0xff };
    ik = (struct ipv4_addrs){ htonl(0xc0000202), htonl(0xc6336402) };
    im = (struct ipv4_addrs){ 0xffffffff, 0xffffffff };
    pk = (struct ports){ htons(10000), htons(20000) }; pm = (struct ports){ 0xffff, 0xffff };
    rule = (struct flow_rule){ .match.dissector = &dissector, .action.num_entries = 5,
        .meta = {&mk, &mm}, .control = {&ck, &cm}, .basic = {&bk, &bm},
        .ipv4_addrs = {&ik, &im}, .ports = {&pk, &pm} };
    /* Independent byte fixtures for DA 02:11:22:33:44:55 and SA 02:00:00:00:00:02. */
    u8 values[4][4] = {{0,0,2,0}, {0,0,0,2}, {2,0x11,0x22,0x33}, {0x44,0x55,0,0}};
    const unsigned offsets[] = {4,8,0,4};
    const u32 masks[] = {0xffff,0,0,0xffff0000};
    for (unsigned i = 0; i < 4; i++) {
        rule.action.entries[i].id = FLOW_ACTION_MANGLE;
        rule.action.entries[i].mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_ETH;
        rule.action.entries[i].mangle.offset = offsets[i];
        rule.action.entries[i].mangle.mask = masks[i];
        memcpy(&rule.action.entries[i].mangle.val, values[i], 4);
    }
    rule.action.entries[4].id = FLOW_ACTION_REDIRECT;
    rule.action.entries[4].dev = &out;
    cls = (struct flow_cls_offload){ .rule = &rule, .nf_ct = &ct, .nf_dst = &route.dst, .nf_mtu = 1492,
        .nf_dst_reverse = &reverse_route.dst, .nf_handle = &handle, .cookie = 123, .common.protocol = ETH_P_ALL };
    physical_ok = neigh_ok = true;
}
static void snat_fixture(bool forward, bool tcp)
{
    fixture();
    ct.status = IPS_SRC_NAT | IPS_SRC_NAT_DONE;
    if (tcp) {
        ct.protonum = bk.ip_proto = IPPROTO_TCP;
        ct.tcp_state = TCP_CONNTRACK_ESTABLISHED; ct.status |= IPS_ASSURED;
        dissector.used_keys |= BIT(FLOW_DISSECTOR_KEY_TCP);
        tk.flags = 0; tm.flags = htons(5);
        rule.tcp = (struct flow_match_tcp){ &tk, &tm };
    }
    ct.tuplehash[0].tuple = (struct nf_conntrack_tuple){
        .src = { .u3.ip = ik.src, .u.all = pk.src },
        .dst = { .u3.ip = ik.dst, .u.all = pk.dst } };
    ct.tuplehash[1].tuple = (struct nf_conntrack_tuple){
        .src = { .u3.ip = ik.dst, .u.all = pk.dst },
        .dst = { .u3.ip = htonl(0xcb007104), .u.all = htons(40000) } };
    rule.action.num_entries = 8;
    rule.action.entries[7] = rule.action.entries[4];
    rule.action.entries[4] = (struct flow_action_entry){ .id = FLOW_ACTION_MANGLE,
        .mangle = { .htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4, .offset = forward ? 12 : 16,
                    .val = forward ? htonl(0xcb007104) : htonl(0xc0000202) } };
    /* Independent wire bytes: source 40000 or destination 10000. */
    const u8 values[2][4] = {{0,0,0x27,0x10}, {0x9c,0x40,0,0}};
    const u8 masks[2][4] = {{0xff,0xff,0,0}, {0,0,0xff,0xff}};
    rule.action.entries[5] = (struct flow_action_entry){ .id = FLOW_ACTION_MANGLE,
        .mangle.htype = tcp ? FLOW_ACT_MANGLE_HDR_TYPE_TCP : FLOW_ACT_MANGLE_HDR_TYPE_UDP };
    memcpy(&rule.action.entries[5].mangle.val, values[forward], 4);
    memcpy(&rule.action.entries[5].mangle.mask, masks[forward], 4);
    rule.action.entries[6] = (struct flow_action_entry){ .id = FLOW_ACTION_CSUM, .csum_flags = tcp ? 9 : 17 };
    if (!forward) {
        ik = (struct ipv4_addrs){ htonl(0xc6336402), htonl(0xcb007104) };
        pk = (struct ports){ htons(20000), htons(40000) };
        neighbour.primary_key = htonl(0xc0000202);
    }
}
static void test_snat(void)
{
    struct cdx_ft_rule decoded;
    struct nf_conn_nat nat = { .masq_index = 7 };
    for (unsigned variant = 0; variant < 4; variant++) {
        bool forward = variant & 1, tcp = variant & 2;
        snat_fixture(forward, tcp);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(decoded.src == ik.src && decoded.dst == ik.dst);
        assert(decoded.new_src == htonl(forward ? 0xcb007104 : 0xc6336402));
        assert(decoded.new_dst == htonl(forward ? 0xc6336402 : 0xc0000202));
        assert(decoded.new_sport == htons(forward ? 40000 : 20000));
        assert(decoded.new_dport == htons(forward ? 20000 : 10000));
        assert(next_hop == decoded.new_dst);
#define NAT_REJECT(change) do { snat_fixture(forward, tcp); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
        NAT_REJECT(ct.status = IPS_NAT_MASK | IPS_SRC_NAT_DONE);
        NAT_REJECT(ct.status = IPS_SRC_NAT);
        NAT_REJECT(ct.status = 0);
        /* MASQUERADE is a Linux-owned source mapping with the same native
         * actions. Its device/address teardown uses native conntrack GC. */
        snat_fixture(forward, tcp); ct.nat = &nat;
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        NAT_REJECT(ct.protonum = bk.ip_proto = IPPROTO_ICMP);
        NAT_REJECT(rule.action.entries[5].mangle.htype = tcp ? FLOW_ACT_MANGLE_HDR_TYPE_UDP : FLOW_ACT_MANGLE_HDR_TYPE_TCP);
        NAT_REJECT(rule.action.entries[6].csum_flags = tcp ? 17 : 9);
        if (tcp) {
            NAT_REJECT(ct.status &= ~IPS_ASSURED);
            NAT_REJECT(ct.tcp_state = 0);
            NAT_REJECT(tk.flags = htons(TCPHDR_FIN));
            NAT_REJECT(tm.flags = 0);
        }
        NAT_REJECT(ik.src ^= htonl(1)); NAT_REJECT(pk.dst ^= htons(1));
        NAT_REJECT(ct.tuplehash[0].tuple.dst.u3.ip ^= htonl(1));
        NAT_REJECT(ct.tuplehash[0].tuple.dst.u.all ^= htons(1));
        NAT_REJECT(rule.action.num_entries = 5); NAT_REJECT(rule.action.num_entries = 9);
        NAT_REJECT(rule.action.entries[4].mangle.offset ^= 4);
        NAT_REJECT(rule.action.entries[4].mangle.mask = 1);
        NAT_REJECT(rule.action.entries[4].mangle.val ^= htonl(1));
        NAT_REJECT(rule.action.entries[4].mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_ETH);
        NAT_REJECT(rule.action.entries[5].mangle.offset = 2);
        NAT_REJECT(rule.action.entries[5].mangle.mask ^= htonl(1));
        NAT_REJECT(rule.action.entries[5].mangle.val ^= htonl(1));
        NAT_REJECT(rule.action.entries[5].mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4);
        NAT_REJECT(rule.action.entries[6].id = FLOW_ACTION_REDIRECT);
        NAT_REJECT(rule.action.entries[6].csum_flags = 1);
        NAT_REJECT(rule.action.entries[7].id = FLOW_ACTION_CSUM);
        NAT_REJECT(ct.tuplehash[forward ? 1 : 0].tuple.dst.u3.ip = 0);
#undef NAT_REJECT
        /* Native SNAT emits both edits even when address or port is unchanged.
         * Validate those identity edits without inventing another action shape. */
        snat_fixture(forward, tcp);
        ct.tuplehash[1].tuple.dst.u3.ip = ct.tuplehash[0].tuple.src.u3.ip;
        if (!forward) ik.dst = ct.tuplehash[1].tuple.dst.u3.ip;
        rule.action.entries[4].mangle.val = htonl(0xc0000202);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(decoded.src == decoded.new_src && decoded.dst == decoded.new_dst);
        snat_fixture(forward, tcp);
        ct.tuplehash[1].tuple.dst.u.all = ct.tuplehash[0].tuple.src.u.all;
        if (!forward) pk.dst = htons(10000);
        rule.action.entries[5].mangle.val = forward ? htonl(10000U << 16) : htonl(10000);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(decoded.sport == decoded.new_sport && decoded.dport == decoded.new_dport);
        snat_fixture(forward, tcp);
        for (unsigned stage = 1; stage <= 3; stage++) {
            ft_fail_stage = stage; assert(ft_replace(&binding, &cls) < 0);
            assert(!ft_fail_stage && !ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
        }
        assert(ft_replace(&binding, &cls) == 0);
        /* An unrelated translated-address prefix is not a routed endpoint.
         * The client route must retire even a lone reply direction. */
        struct netevent_ipv4_route event = { &init_net, htonl(0xcb007104), 32 };
        ft_route_event(&event); assert(!handle.invalid);
        event.dst = htonl(0xc0000202);
        ft_route_event(&event); assert(handle.invalid && !ft_invalid);
        ft_retire_workfn(NULL);
        assert(!ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
    }
}
static void tcp_fixture(void)
{
    fixture();
    ct.protonum = bk.ip_proto = IPPROTO_TCP;
    ct.tcp_state = TCP_CONNTRACK_ESTABLISHED; ct.status = IPS_ASSURED;
    dissector.used_keys |= BIT(FLOW_DISSECTOR_KEY_TCP);
    tk.flags = 0; tm.flags = htons(5);
    rule.tcp = (struct flow_match_tcp){ &tk, &tm };
}
#define REJECT(change) do { fixture(); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)

/* Model Netfilter's callback-list commit/free after the driver returns. In
 * particular, release must not run while ft_bind holds the control mutex. */
static struct flow_block block;
static struct nf_flowtable table;
static int bind_device(struct net_device *dev, int command)
{
    struct flow_block_offload bo = { .block = &block, .net = &init_net,
        .binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS, .command = command };
    list_init(&bo.cb_list);
    int rc = ft_bind(dev, NULL, NULL, TC_SETUP_FT, &bo, &table, NULL);
    assert(!table.flow_block_lock && !block_write_lock && !cdx_info->ctrl.mutex);
    while (bo.cb_list.next != &bo.cb_list) {
        struct flow_block_cb *cb = list_entry(bo.cb_list.next, struct flow_block_cb, list);
        list_del(&cb->list);
        if (command == FLOW_BLOCK_BIND) list_add_tail(&cb->list, &block.cb_list);
        else { cb->release(cb->priv); kfree(cb); }
    }
    return rc;
}
static bool can_rearm(void)
{
    mutex_lock(&cdx_info->ctrl.mutex);
    bool ready = ft_can_rearm();
    mutex_unlock(&cdx_info->ctrl.mutex);
    return ready;
}
static void detach_during_cleanup(void)
{
    cleanup_hook = NULL;
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_bound && !ft_count && !ft_invalid_done);
    assert(!can_rearm());
    assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
}
static void test_rearm(void)
{
    list_init(&block.cb_list);
    assert(ft_invalid && ft_fatal && ft_invalid_done);
    assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
    /* The fatal latch independently prevents admission, even if another
     * path were to clear the ordinary invalidation flag accidentally. */
    ft_invalid = 0;
    assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    ft_fatal = false; /* Simulated fresh module/boot, never a recovery action. */
    ft_invalid_done = false;
    deletion_error = 0;
    table.rhashtable.nelems = 2;
    assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP && !table.use_neigh);
    table.rhashtable.nelems = 0;
    u64 errors = ft_errors, installs = ft_installs, deletes = ft_deletes;
    for (unsigned cycle = 0; cycle < 8; cycle++) {
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
        assert(table.use_neigh && table.use_hw_handles);
        invalidate_on_bind = true;
        assert(bind_device(&out, FLOW_BLOCK_BIND) == 0);
        invalidate_on_bind = false;
        assert(ft_invalid && !ft_invalid_done && ft_rearms == cycle);
        assert(ft_bound == 2 && allocated == 4 && in.refs == 1 && out.refs == 1);
        ft_invalidate();
        /* A failed retirement barrier cannot be bypassed by detachment. */
        retry_error = -EAGAIN;
        ft_invalidate_work(NULL);
        assert(!ft_invalid_done && !can_rearm());
        if (cycle % 3 == 0) {
            assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
            assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
            assert(!ft_bound && !can_rearm());
            assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        }
        retry_error = 0;
        if (cycle % 3 == 0) {
            ft_invalidate_work(NULL);
        } else if (cycle & 1) {
            cleanup_hook = detach_during_cleanup;
            ft_invalidate_work(NULL);
        } else {
            ft_invalidate_work(NULL);
            assert(ft_invalid_done && !can_rearm());
            assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
            assert(!can_rearm());
            assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
            assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
        }
        assert(!ft_bound && !ft_count && !allocated && !in.refs && !out.refs);
        assert(can_rearm());
        table.rhashtable.nelems = 2;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        assert(ft_invalid && ft_invalid_done && !allocated && ft_rearms == cycle);
        table.rhashtable.nelems = 0;
        ft_neighbour_refs = 1;
        assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        ft_neighbour_refs = 0;
        private_pending = 1;
        assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        private_pending = 0; legacy_pending = 1;
        assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        legacy_pending = 0; ft_stopping = true;
        assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        ft_stopping = false; ft_ready = false;
        assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        ft_ready = true; allocation_fail = true;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == -ENOMEM);
        allocation_fail = false; callback_allocation_fail = true;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == -ENOMEM);
        callback_allocation_fail = false;
        assert(ft_invalid && ft_invalid_done && can_rearm() && !allocated);
        assert(ft_rearms == cycle);
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
        assert(!ft_invalid && !ft_invalid_done && !can_rearm() && ft_rearms == cycle + 1);
        assert(bind_device(&out, FLOW_BLOCK_BIND) == 0 && ft_rearms == cycle + 1);
        fixture();
        struct flow_block_cb *cb = flow_block_cb_lookup(&block, ft_rule_callback, &in);
        assert(cb && ft_replace(cb->priv, &cls) == 0);
        assert(ft_count == 1 && live_hw == 1);
        assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0); /* Real entry retirement. */
        assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
        assert(!ft_count && !ft_bound && !live_hw && !allocated && !in.refs && !out.refs);
        assert(ft_installs == installs + cycle + 1 && ft_deletes == deletes + cycle + 1);
        assert(ft_errors == errors && !ft_invalid && !ft_invalid_done && !ft_fatal);
        assert(ft_bindings.next == &ft_bindings && ft_block_list.next == &ft_block_list);
    }
}

static void test_gateways(void)
{
    struct cdx_ft_rule decoded;
    REJECT(cls.nf_dst = NULL);
    struct dst_ops ipv6_ops = {.family = AF_INET6};
    REJECT(route.dst.ops = &ipv6_ops);
    REJECT(route.dst.dev = &in);
    REJECT(route.dst.valid = false);
    REJECT(route.dst.xfrm = &route);
    REJECT(route.dst.lwtstate = &route);
    REJECT(route.rt_type = 2); /* Local route, not forwarded unicast. */
    REJECT(route.rt_gw_family = AF_INET6);
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = 0);
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = htonl(0xe0000001));
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = htonl(0x7f000001));
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = 0xffffffff);
    for (unsigned cycle = 0; cycle < 32; cycle++) {
        if (cycle & 1) tcp_fixture(); else fixture();
        route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key;
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(decoded.dst == ik.dst && next_hop != decoded.dst);
        assert(next_hop == gateway.primary_key && !gateway.refs && !neighbour.refs);
        assert(ft_replace(&binding, &cls) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        assert(e->next_hop == gateway.primary_key && e->neigh == &gateway);
        assert(gateway.refs == 1 && !neighbour.refs);
        neighbour.nud_state = NUD_FAILED; /* Remote endpoint is not the dependency. */
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid && ft_count == 1);
        u64 installs = ft_installs;
        assert(ft_replace(&binding, &cls) == 0 && ft_installs == installs);
        /* Even an identical Ethernet rewrite must move its watch when the
         * selected gateway changes. Never deduplicate by the HW rule alone. */
        route.rt_gw4 = alternate_gateway.primary_key;
        assert(ft_replace(&binding, &cls) == 0 && ft_installs == installs + 1);
        e = ft_find(&binding, cls.cookie);
        assert(e->neigh == &alternate_gateway && !gateway.refs && alternate_gateway.refs == 1);
        gateway.dead = true;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
        assert(!ft_invalid);
        alternate_gateway.ha[5]++;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &alternate_gateway);
        assert(!ft_invalid && handle.invalid && ft_remove(e) == 0);
        ft_invalid = 0;
    }
    fixture(); route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key;
    gateway.nud_state = NUD_FAILED;
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP && !ft_count);
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs);
}

static void test_neighbours(void)
{
    const unsigned valid[] = {NUD_PERMANENT, NUD_REACHABLE, NUD_STALE, NUD_DELAY, NUD_PROBE};
    const unsigned invalid[] = {0, NUD_INCOMPLETE, NUD_FAILED, NUD_NOARP,
                               NUD_NOARP | NUD_REACHABLE, NUD_FAILED | NUD_REACHABLE};
    struct cdx_ft_rule decoded;
    for (unsigned i = 0; i < ARRAY_SIZE(valid); i++) {
        fixture(); neighbour.nud_state = valid[i];
        assert(ft_replace(&binding, &cls) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        assert(e && neighbour.refs == 1 && ft_neighbour_refs == 1);
        unsigned uses = neigh_uses;
        assert(ft_stats(e, &cls) == 0 && neigh_uses == uses); /* Idle is not use. */
        e->hw->stats.packets++;
        assert(ft_stats(e, &cls) == 0 && neigh_uses == uses + 1);
        assert(ft_stats(e, &cls) == 0 && neigh_uses == uses + 1); /* No double use. */
        for (unsigned j = 0; j < ARRAY_SIZE(valid); j++) {
            neighbour.nud_state = valid[j];
            ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
            assert(!ft_invalid && ft_count == 1);
        }
        struct neighbour unrelated = neighbour;
        unrelated.nud_state = NUD_FAILED;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &unrelated);
        assert(!ft_invalid);
        neighbour.ha[5]++;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid && handle.invalid && ft_count == 1); /* Atomic callback only latches. */
        assert(ft_remove(e) == 0 && !neighbour.refs && !ft_neighbour_refs);
        ft_invalid = 0;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid); /* Removed entries cannot be dereferenced. */
    }
    for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
        fixture(); neighbour.nud_state = invalid[i];
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP && !neighbour.refs);
        neighbour.nud_state = NUD_REACHABLE;
        assert(ft_replace(&binding, &cls) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        neighbour.nud_state = invalid[i];
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid && handle.invalid);
        unsigned uses = neigh_uses;
        e->hw->stats.packets++;
        assert(ft_stats(e, &cls) == -EOPNOTSUPP && neigh_uses == uses);
        assert(ft_remove(e) == 0); ft_invalid = 0;
    }
    fixture(); neighbour.dead = true;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP && !neighbour.refs);
    fixture(); change_neigh_on_lookup = true; /* Decoder/publication race. */
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs && !live_hw && !allocated);
    change_neigh_on_lookup = false;
    fixture(); change_neigh_on_add = true; /* Watch precedes hardware insertion. */
    assert(ft_replace(&binding, &cls) == -EIO && !ft_invalid && handle.invalid);
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs && !live_hw && !allocated);
    change_neigh_on_add = false; ft_invalid = 0;
    fixture(); assert(ft_replace(&binding, &cls) == 0);
    struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
    neigh_send_error = 1; e->hw->stats.packets++;
    assert(ft_stats(e, &cls) == -EOPNOTSUPP && !ft_invalid && handle.invalid);
    assert(ft_remove(e) == 0); neigh_send_error = 0; ft_invalid = 0;
    fixture(); assert(ft_replace(&binding, &cls) == 0);
    cls.cookie++; pk.src = htons(10001);
    assert(ft_replace(&binding, &cls) == 0 && ft_neighbour_refs == 2 && neighbour.refs == 2);
    neighbour.dead = true;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(!ft_invalid && handle.invalid && ft_count == 2);
    ft_retire_workfn(NULL);
    assert(!ft_count && !live_hw && !allocated && !ft_neighbour_refs && !neighbour.refs);
    assert(ft_neigh_entries.next == &ft_neigh_entries && !out.refs);
    assert(ft_installs == ft_deletes);
}
/* Same addresses and ports across protocols must remain distinct. Keep the
 * fixture's neighbour alive while changing the borrowed rule for each request.
 */
static void connection_rule(unsigned n)
{
    cls.cookie = 1000 + n;
    cls.stats = (struct flow_stats){0};
    pk.src = htons(10000 + n / 2);
    ct.protonum = bk.ip_proto = n & 1 ? IPPROTO_TCP : IPPROTO_UDP;
    ct.tcp_state = TCP_CONNTRACK_ESTABLISHED;
    ct.status = IPS_ASSURED;
    dissector.used_keys = 31 | (n & 1 ? BIT(FLOW_DISSECTOR_KEY_TCP) : 0);
    tk.flags = 0; tm.flags = htons(TCPHDR_FIN | TCPHDR_RST);
    rule.tcp = (struct flow_match_tcp){ &tk, &tm };
}

static void test_connections(void)
{
    struct cdx_ft_entry *entries[CDX_FT_MAX_ENTRIES];
    u64 installs = ft_installs, deletes = ft_deletes, errors = ft_errors;

    fixture();
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        connection_rule(i);
        assert(ft_replace(&binding, &cls) == 0);
        entries[i] = ft_find(&binding, cls.cookie);
        assert(entries[i] && entries[i]->neigh == &neighbour);
        entries[i]->hw->stats = (struct cdx_ft_counters){
            .packets = 100 + i, .bytes = 10000 + i * 100, .lastused = 990 };
        assert(ft_stats(entries[i], &cls) == 0);
        assert(cls.stats.pkts == 100 + i && cls.stats.bytes == 10000 + i * 100);
    }
    assert(ft_count == ARRAY_SIZE(entries) && live_hw == ft_count);
    assert(allocated == ft_count && neighbour.refs == ft_count);
    assert(ft_neighbour_refs == ft_count && out.refs == (int)ft_count);

    /* Full admission must preserve idempotent updates and reject duplicate
     * keys without disturbing the existing owner or resetting its counters. */
    connection_rule(10);
    assert(ft_replace(&binding, &cls) == 0);
    cls.cookie += 10000;
    assert(ft_replace(&binding, &cls) == -EEXIST);
    connection_rule(ARRAY_SIZE(entries));
    assert(ft_replace(&binding, &cls) == -ENOSPC);
    assert(ft_installs == installs + ARRAY_SIZE(entries) && ft_deletes == deletes);

    /* Retire and reuse a middle key with a new opaque cookie. Other owners,
     * hardware handles and previously reported deltas must survive intact. */
    connection_rule(17);
    assert(ft_remove(entries[17]) == 0 && !ft_find(&binding, cls.cookie));
    cls.cookie += 10000;
    assert(ft_replace(&binding, &cls) == 0);
    entries[17] = ft_find(&binding, cls.cookie);
    assert(!entries[17]->reported.packets && !entries[17]->hw->stats.packets);
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        connection_rule(i);
        if (i == 17) cls.cookie += 10000;
        assert(ft_find(&binding, cls.cookie) == entries[i]);
        entries[i]->hw->stats.packets += i + 1;
        entries[i]->hw->stats.bytes += (i + 1) * 100;
        assert(ft_stats(entries[i], &cls) == 0);
        assert(cls.stats.pkts == i + 1 && cls.stats.bytes == (i + 1) * 100);
    }
    /* Different removal order exercises list head, middle and tail; sharing
     * a neighbour cannot tie one connection's lifetime to another's. */
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        unsigned n = i & 1 ? ARRAY_SIZE(entries) - 1 - i / 2 : i / 2;
        assert(ft_remove(entries[n]) == 0);
        assert(ft_count == ARRAY_SIZE(entries) - 1 - i && neighbour.refs == ft_count);
        assert(ft_neighbour_refs == ft_count && out.refs == (int)ft_count);
    }
    assert(!live_hw && !allocated && ft_installs == ft_deletes);
    assert(ft_installs == installs + ARRAY_SIZE(entries) + 1 && ft_errors == errors);
    assert(!ft_invalid && !ft_fatal);

    /* Every entry here shares the changed dependency; all must be drained. */
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        connection_rule(i);
        assert(ft_replace(&binding, &cls) == 0);
    }
    neighbour.dead = true;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(!ft_invalid && handle.invalid && ft_count == ARRAY_SIZE(entries));
    ft_retire_workfn(NULL);
    assert(!ft_count && !live_hw && !allocated && !ft_neighbour_refs && !neighbour.refs);
    assert(!out.refs && ft_installs == ft_deletes && ft_errors == errors);
    ft_invalid = 0; ft_invalid_done = false;
}

static void test_selective_neighbours(void)
{
    struct nf_flow_offload_handle contexts[3] = { {1, false}, {1, false}, {1, false} };
    struct cdx_ft_entry *entries[4];
    u64 invalidations = ft_neigh_invalidations, errors = ft_errors;

    fixture();
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        cls.nf_handle = &contexts[i / 2];
        cls.cookie = 5000 + i;
        pk.src = htons(11000 + i);
        route.rt_gw_family = i & 1 ? 0 : AF_INET;
        route.rt_gw4 = i < 2 ? gateway.primary_key : alternate_gateway.primary_key;
        assert(ft_replace(&binding, &cls) == 0);
        entries[i] = ft_find(&binding, cls.cookie);
        entries[i]->hw->stats.packets = 100 + i;
    }
    assert(contexts[0].refs == 3 && contexts[1].refs == 3 && ft_handle_refs == 4);
    gateway.nud_state = NUD_FAILED;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
    assert(contexts[0].invalid && !contexts[1].invalid);
    assert(ft_neigh_invalidations == invalidations + 1 && !ft_invalid && ft_count == 4);
    ft_retire_workfn(NULL);
    assert(ft_count == 2 && ft_handle_refs == 2 && ft_neighbour_refs == 2);
    assert(contexts[0].refs == 1 && contexts[1].refs == 3);
    assert(!ft_find(&binding, 5000) && !ft_find(&binding, 5001));
    assert(ft_find(&binding, 5002) == entries[2] && ft_find(&binding, 5003) == entries[3]);
    assert(entries[2]->hw->stats.packets == 102 && entries[3]->hw->stats.packets == 103);

    /* Even after resolution, a queued add for the invalid generation fails.
     * A fresh Linux generation can reuse its cookie without inheriting state. */
    gateway.nud_state = NUD_PERMANENT;
    cls.nf_handle = &contexts[0]; cls.cookie = 5000; pk.src = htons(11000);
    route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key;
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP && ft_count == 2);
    cls.nf_handle = &contexts[2];
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 3);
    struct cdx_ft_entry *fresh = ft_find(&binding, cls.cookie);
    assert(!fresh->reported.packets && !fresh->hw->stats.packets);
    cls.nf_handle = &contexts[0];
    cls.command = FLOW_CLS_DESTROY;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
    assert(ft_find(&binding, cls.cookie) == fresh);
    cls.command = FLOW_CLS_STATS;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -ENOENT);
    cls.command = FLOW_CLS_REPLACE;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -ESTALE);
    assert(ft_count == 3 && !ft_invalid && ft_errors == errors);

    /* A retirement error must escalate globally, including the unaffected
     * connection, before recovery can be announced. */
    gateway.nud_state = NUD_FAILED;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
    deletion_error = -EAGAIN;
    ft_retire_workfn(NULL);
    deletion_error = 0;
    assert(ft_invalid && !ft_fatal && ft_errors == errors + 1 && ft_count == 2);
    ft_invalidate_work(NULL);
    assert(ft_invalid_done && !ft_count && !ft_handle_refs && !ft_neighbour_refs);
    assert(!live_hw && !allocated && !out.refs && ft_installs == ft_deletes);
    for (unsigned i = 0; i < ARRAY_SIZE(contexts); i++) assert(contexts[i].refs == 1);
    ft_invalid = 0; ft_invalid_done = false;

    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    unsigned queued = neigh_scheduled;
    ft_stopping = true;
    neighbour.dead = true;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(neigh_scheduled == queued && handle.invalid);
    ft_retire_workfn(NULL);
    assert(ft_count == 1); /* Shutdown's binding release owns this retirement. */
    assert(ft_remove(ft_find(&binding, cls.cookie)) == 0);
    ft_stopping = false;
    assert(!ft_handle_refs && handle.refs == 1 && !allocated);
}

static void test_transient_admission(void)
{
    struct cdx_ft_binding other_binding = { .dev = &out };
    for (unsigned tcp = 0; tcp < 2; tcp++) {
        if (tcp) tcp_fixture(); else fixture();
        cls.command = FLOW_CLS_REPLACE;
        u64 invalidations = ft_admission_invalidations, busy = ft_busy;
        ft_fail_stage = 4;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
        assert(ft_fail_stage == 4 && ft_count == 1 && !handle.invalid);
        /* Visiting a different ingress cannot consume the fault or retire
         * the successfully installed direction, even during real contention. */
        rtnl_busy = true;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &other_binding) == -EOPNOTSUPP);
        assert(ft_fail_stage == 4 && ft_busy == busy && !handle.invalid);
        rtnl_busy = false;
        cls.cookie++; pk.src++;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EAGAIN);
        assert(!ft_fail_stage && handle.invalid && ft_count == 1);
        assert(ft_busy == busy + 1 && ft_admission_invalidations == invalidations + 1);
        ft_retire_workfn(NULL);
        assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && handle.refs == 1);
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EOPNOTSUPP);
        /* Fresh generation after native GC; the same table stays eligible. */
        handle = (struct nf_flow_offload_handle){ .refs = 1 };
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
        assert(!ft_invalid && !handle.invalid && ft_count == 1);
        rtnl_busy = true;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EAGAIN);
        assert(handle.invalid && ft_admission_invalidations == invalidations + 2);
        rtnl_busy = false;
        ft_retire_workfn(NULL);
        assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated && !live_hw);
    }
    for (unsigned excluded = 0; excluded < 4; excluded++) {
        fixture(); cls.command = FLOW_CLS_REPLACE;
        u64 invalidations = ft_admission_invalidations;
        ft_observe = excluded == 0; ft_stopping = excluded == 1;
        ft_invalid = excluded == 2; ft_fatal = excluded == 3;
        rtnl_busy = true;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EAGAIN);
        assert(!handle.invalid && ft_admission_invalidations == invalidations);
        rtnl_busy = false; ft_observe = ft_stopping = ft_fatal = false; ft_invalid = 0;
    }
}

static void test_selective_routes(void)
{
    struct nf_flow_offload_handle contexts[2] = {{1, false}, {1, false}};
    struct cdx_ft_entry *entries[4];
    struct net other_net;
    struct netevent_ipv4_route event = { .net = &init_net, .dst = htonl(0xc0000202), .prefixlen = 32 };
    struct fib_notifier_info info = { .family = AF_INET };
    u64 invalidations = ft_route_invalidations, errors = ft_errors;

    fixture();
    for (unsigned i = 0; i < 4; i++) {
        __be32 address = htonl(i < 2 ? 0xc0000202 : 0xcb007102);
        ik.src = i & 1 ? htonl(0xc6336402) : address;
        ik.dst = i & 1 ? address : htonl(0xc6336402);
        cls.nf_handle = &contexts[i / 2]; cls.cookie = 6000 + i;
        route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key;
        assert(ft_replace(&binding, &cls) == 0);
        entries[i] = ft_find(&binding, cls.cookie);
        entries[i]->hw->stats.packets = 20 + i;
    }
    for (unsigned e = FIB_EVENT_ENTRY_REPLACE; e <= FIB_EVENT_ENTRY_DEL; e++)
        assert(ft_fib_event(NULL, e, &info) == NOTIFY_DONE && !ft_invalid);
    event.net = &other_net;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    event.net = &init_net; event.dst = htonl(0xc0000203);
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(!contexts[0].invalid && !contexts[1].invalid);
    /* A more-specific addition has no old-route pointer. It still marks both
     * directions, including the opposite direction's destination. */
    event.dst = htonl(0xc0000202);
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(contexts[0].invalid && !contexts[1].invalid && !ft_invalid);
    assert(ft_route_invalidations == invalidations + 1);
    ft_retire_workfn(NULL);
    assert(ft_count == 2 && contexts[0].refs == 1 && contexts[1].refs == 3);
    for (unsigned i = 2; i < 4; i++) {
        assert(ft_find(&binding, 6000 + i) == entries[i]);
        assert(entries[i]->hw->stats.packets == 20 + i);
    }
    /* Partial hardware admission must also match its missing reverse route. */
    assert(ft_remove(entries[3]) == 0);
    event.dst = htonl(0xcb007100); event.prefixlen = 24;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(contexts[1].invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && ft_errors == errors);
    assert(ft_route_invalidations == invalidations + 2);
    assert(contexts[1].refs == 1);

    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    event.dst = 0; event.prefixlen = 0;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    ft_retire_workfn(NULL);
    assert(handle.invalid && !ft_count && !ft_invalid);
    event.prefixlen = 33;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(ft_invalid); ft_invalid = 0;
    for (unsigned e = FIB_EVENT_RULE_ADD; e <= FIB_EVENT_RULE_DEL; e++) {
        ft_fib_event(NULL, e, &info); assert(ft_invalid); ft_invalid = 0;
    }
    info.family = AF_INET6;
    ft_fib_event(NULL, FIB_EVENT_RULE_ADD, &info); assert(!ft_invalid);

    for (unsigned e = FIB_EVENT_NH_ADD; e <= FIB_EVENT_NH_DEL; e++) {
        fixture();
        struct nf_flow_offload_handle other = {1, false};
        u64 links = ft_link_invalidations;
        assert(ft_replace(&binding, &cls) == 0);
        cls.cookie++; pk.src++; cls.nf_handle = &other;
        assert(ft_replace(&binding, &cls) == 0);
        ft_fib_event(NULL, e, &info); /* Another family is ignored. */
        assert(!handle.invalid && !other.invalid);
        info.family = AF_INET;
        ft_fib_event(NULL, e, &info);
        ft_fib_event(NULL, e, &info);
        assert(handle.invalid && other.invalid && !ft_invalid);
        assert(ft_link_invalidations == links + 2);
        ft_retire_workfn(NULL);
        assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated);
        assert(handle.refs == 1 && other.refs == 1);
        info.family = AF_INET6;
    }

    /* Queued admission may carry one current and one stale route. Refuse and
     * invalidate the entire generation before any hardware allocation. */
    for (unsigned which = 0; which < 4; which++) {
        fixture();
        if (which == 0) route.dst.valid = false;
        if (which == 1) reverse_route.dst.valid = false;
        if (which == 2) cls.nf_dst = NULL;
        if (which == 3) cls.nf_dst_reverse = NULL;
        assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
        assert(handle.invalid && handle.refs == 1 && !ft_handle_refs && !allocated && !live_hw);
    }
    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    reverse_route.dst.valid = false;
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    ft_retire_workfn(NULL);
    assert(handle.invalid && !ft_count && !ft_handle_refs && !ft_neighbour_refs && !out.refs);
    assert(ft_installs == ft_deletes && ft_errors == errors);
}

static void device_event(struct net_device *dev, unsigned long event, bool invalid)
{
    struct netdev_notifier_info info = { .dev = dev };
    ft_invalid = 0; /* Isolate selection of each event without running work. */
    assert(ft_netdev_event(NULL, event, &info) == NOTIFY_DONE);
    assert(ft_invalid == invalid && !cdx_info->ctrl.mutex && !ft_watch_lock);
}

static void test_device_dependencies(void)
{
    struct net other_net;
    /* The same ifindex on another object must not match the bound port. */
    struct net_device unrelated = { .ifindex = in.ifindex };
    unsigned long events[] = { NETDEV_UNREGISTER, NETDEV_CHANGEUPPER };
    fixture();
    assert(!ft_bound && !ft_count && !ft_invalid);
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) device_event(&in, events[i], false);
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) {
        device_event(&in, events[i], true); /* Empty binding still matters. */
        device_event(&out, events[i], false);
        device_event(&unrelated, events[i], false);
    }
    in.net = &other_net;
    device_event(&in, NETDEV_CHANGEUPPER, false);
    in.net = NULL;
    device_event(&in, NETDEV_REGISTER, false);
    struct flow_block_cb *cb = flow_block_cb_lookup(&block, ft_rule_callback, &in);
    assert(cb && ft_replace(cb->priv, &cls) == 0);
    assert(ft_bound == 1 && in.refs == 1 && out.refs == 1);
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) {
        device_event(&out, events[i], true); /* Egress has no binding. */
        device_event(&in, events[i], true);
        device_event(&unrelated, events[i], false);
    }
    device_event(&out, NETDEV_CHANGEUPPER, true);
    ft_invalidate_work(NULL);
    assert(ft_invalid_done && !ft_count && !ft_handle_refs && !ft_neighbour_refs && !out.refs);
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_bound && !in.refs && !allocated && !live_hw);
    /* No stale watch can follow the released binding into its replacement. */
    assert(bind_device(&unrelated, FLOW_BLOCK_BIND) == 0);
    device_event(&in, NETDEV_CHANGEUPPER, false);
    device_event(&out, NETDEV_CHANGEUPPER, false);
    device_event(&unrelated, NETDEV_CHANGEUPPER, true);
    ft_invalid = 0;
    assert(bind_device(&unrelated, FLOW_BLOCK_UNBIND) == 0);
    assert(!unrelated.refs && !ft_bound && !allocated);
    /* Installation rollback must also remove the egress watch. */
    fixture();
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
    cb = flow_block_cb_lookup(&block, ft_rule_callback, &in);
    for (unsigned stage = 2; stage <= 3; stage++) {
        ft_fail_stage = stage;
        assert(ft_replace(cb->priv, &cls) < 0 && !ft_count && !out.refs);
        device_event(&out, NETDEV_CHANGEMTU, false);
    }
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_bound && !in.refs && !allocated && ft_installs == ft_deletes);
}

static void test_device_recovery(void)
{
    struct net other_net;
    struct net_device unrelated = { .ifindex = in.ifindex };
    struct netdev_notifier_info info = { .dev = &unrelated };
    struct fib_notifier_info policy = { .family = AF_INET };
    u64 rearms = ft_rearms;

    unsigned long events[] = {NETDEV_CHANGEMTU, NETDEV_GOING_DOWN, NETDEV_CHANGEADDR};
    for (unsigned e = 0; e < ARRAY_SIZE(events); e++) {
        unsigned long event = events[e];
        u64 *counter = event == NETDEV_CHANGEMTU ? &ft_mtu_invalidations :
                       event == NETDEV_CHANGEADDR ? &ft_mac_invalidations : &ft_link_invalidations;
        for (unsigned tcp = 0; tcp < 2; tcp++) {
            for (unsigned egress = 0; egress < 2; egress++) {
                struct nf_flow_offload_handle queued = {1, false}, fresh = {1, false};
                u64 invalidations = *counter;
                if (tcp) tcp_fixture(); else fixture();
                assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
                struct cdx_ft_binding *b = list_entry(ft_bindings.next, struct cdx_ft_binding, list);
                info.dev = &in;
                ft_netdev_event(NULL, event, &info);
                assert(!ft_invalid && *counter == invalidations); /* Empty binding. */
                assert(ft_replace(b, &cls) == 0);
                cls.cookie++; pk.src++;
                assert(ft_replace(b, &cls) == 0); /* Two entries share one flow generation. */
                info.dev = &out;
                ft_netdev_event(NULL, NETDEV_CHANGENAME, &info);
                ft_netdev_event(NULL, NETDEV_CHANGE, &info);
                assert(!handle.invalid && !ft_invalid); /* Same object, healthy carrier. */
                info.dev = &unrelated;
                ft_netdev_event(NULL, event, &info);
                info.dev = &in; in.net = &other_net;
                ft_netdev_event(NULL, event, &info);
                in.net = NULL;
                assert(!handle.invalid && *counter == invalidations);
                info.dev = egress ? &out : &in; /* Egress has no binding of its own. */
                ft_netdev_event(NULL, event, &info);
                ft_netdev_event(NULL, event, &info);
                assert(handle.invalid && *counter == invalidations + 1);
                assert(!ft_invalid && !ft_invalid_done && ft_count == 2 && handle.refs == 3);
                ft_retire_workfn(NULL);
                assert(ft_bound == 1 && !ft_count && !ft_handle_refs && !ft_neighbour_refs);
                assert(handle.refs == 1 && in.refs == 1 && !out.refs && !live_hw);

                /* IPv4 invalidates both cached dsts on MTU change. Even a queued
                 * request whose own egress is unchanged must reject the old
                 * reverse route, before allocation, and invalidate its handle. */
                cls.nf_handle = &queued; reverse_route.dst.valid = false;
                assert(ft_replace(b, &cls) == -EOPNOTSUPP && queued.invalid && queued.refs == 1);
                assert(!ft_count && !ft_invalid);
                reverse_route.dst.valid = true; cls.nf_handle = &fresh;
                physical_ok = false;
                assert(ft_replace(b, &cls) == -EOPNOTSUPP && !ft_count && !ft_invalid);
                physical_ok = true;
                out.mtu = cls.nf_mtu = 1400;
                assert(ft_replace(b, &cls) == 0);
                assert(ft_find(b, cls.cookie)->rule.mtu == 1400 && ft_bound == 1);
                assert(ft_rearms == rearms); /* No table recreation or global rearm. */

                /* MTU recovery must not reopen admission after a policy event. */
                ft_fib_event(NULL, FIB_EVENT_RULE_ADD, &policy);
                ft_netdev_event(NULL, event, &info);
                ft_retire_workfn(NULL);
                assert(ft_invalid && !ft_invalid_done && ft_count == 1 && fresh.invalid);
                ft_invalidate_work(NULL);
                assert(ft_invalid_done && ft_invalid && !ft_count);
                ft_netdev_event(NULL, event, &info);
                assert(ft_invalid_done && ft_invalid && ft_rearms == rearms);
                assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
                assert(!allocated && !in.refs && !out.refs && fresh.refs == 1);
                ft_invalid = 0; ft_invalid_done = false; out.mtu = 1500;
            }
        }
    }
    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    info.dev = &out; out.carrier_lost = true;
    ft_netdev_event(NULL, NETDEV_CHANGE, &info);
    assert(handle.invalid && !ft_invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !ft_handle_refs && !allocated);
    out.carrier_lost = false;
    fixture();
    out.dev_addr[5] ^= 1;
    u64 macs = ft_mac_invalidations;
    assert(ft_replace(&binding, &cls) == -ESTALE && handle.invalid);
    assert(!ft_count && !ft_invalid && ft_mac_invalidations == macs + 1);
    out.dev_addr[5] ^= 1;
    for (unsigned fatal = 0; fatal < 2; fatal++) {
        fixture();
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
        struct cdx_ft_binding *b = list_entry(ft_bindings.next, struct cdx_ft_binding, list);
        assert(ft_replace(b, &cls) == 0);
        info.dev = &out;
        ft_netdev_event(NULL, NETDEV_CHANGEMTU, &info);
        deletion_error = fatal ? -EIO : -EAGAIN;
        ft_retire_workfn(NULL);
        deletion_error = 0;
        assert(ft_invalid && ft_fatal == !!fatal && !ft_count);
        ft_invalidate_work(NULL);
        ft_netdev_event(NULL, NETDEV_CHANGEMTU, &info);
        assert(ft_invalid && ft_invalid_done && ft_fatal == !!fatal);
        assert(ft_rearms == rearms && handle.refs == 1);
        assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
        assert(!allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
        ft_invalid = 0; ft_invalid_done = ft_fatal = false;
    }
    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    unsigned scheduled_before = neigh_scheduled;
    ft_stopping = true; info.dev = &out;
    ft_netdev_event(NULL, NETDEV_CHANGEMTU, &info);
    assert(handle.invalid && neigh_scheduled == scheduled_before);
    ft_retire_workfn(NULL);
    assert(ft_count == 1); /* Unload owns this entry now. */
    assert(ft_remove(ft_find(&binding, cls.cookie)) == 0);
    ft_stopping = false;
    assert(ft_installs == ft_deletes && !allocated);
}

static void test_nexthop_objects(void)
{
    unsigned long events[] = {NEXTHOP_EVENT_DEL, NEXTHOP_EVENT_REPLACE,
        NEXTHOP_EVENT_RES_TABLE_PRE_REPLACE, NEXTHOP_EVENT_BUCKET_REPLACE, 999};
    ft_invalid = 0;
    assert(ft_nexthop_event(NULL, NEXTHOP_EVENT_HW_STATS_REPORT_DELTA, NULL) == NOTIFY_DONE);
    assert(!ft_invalid);
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) {
        assert(ft_nexthop_event(NULL, events[i], NULL) == NOTIFY_DONE);
        assert(ft_invalid); ft_invalid = 0;
    }
}

static void test_registration(void)
{
    for (registration_failure = 0; registration_failure <= 7; registration_failure++) {
        /* A fresh adapter instance, backed by an independently owned CDX. */
        ft_ready=ft_stopping=false; registration_step=canceled=0;
        fixture();
        int rc=ask_flowtable_init();
        if (registration_failure) {
            assert(rc < 0 && !ft_ready && !ft_proc && !backend_claimed);
        } else {
            assert(!rc && ft_ready && backend_claimed);
            assert(bind_device(&in,FLOW_BLOCK_BIND) == 0);
            assert(bind_device(&out,FLOW_BLOCK_BIND) == 0);
            struct cdx_ft_binding *b=list_entry(ft_bindings.next,struct cdx_ft_binding,list);
            assert(b->dev == &in);
            assert(ft_replace(b,&cls) == 0 && live_hw == 1);
            unload_failures=2; retry_error=-EAGAIN;
            ask_flowtable_exit();
            assert(handle.invalid && unload_sleeps == 2);
        }
        assert(!ft_proc && !ft_ready && !backend_claimed && !live_hw && !allocated);
        assert(!netdev_registered && !neigh_registered && !fib_registered && !nexthop_registered && !indirect_registered);
        assert(!ft_count && !ft_bound && !ft_neighbour_refs && !ft_handle_refs);
        assert(!in.refs && !out.refs && !cdx_info->ctrl.mutex);
    }
    registration_failure=0;
    for (ft_init_fail_stage=1; ft_init_fail_stage<=6; ft_init_fail_stage++) {
        ft_ready=ft_stopping=false; registration_step=canceled=0;
        assert(ask_flowtable_init() == -ENOMEM);
        assert(!ft_ready && !ft_proc && !backend_claimed && !cdx_info->ctrl.mutex);
        assert(!netdev_registered && !neigh_registered && !fib_registered && !nexthop_registered && !indirect_registered);
    }
    ft_init_fail_stage=0;
    /* Fatal deletion on exit still waits for quiescence. Reload is refused. */
    registration_step=canceled=0; fixture();
    assert(ask_flowtable_init() == 0);
    assert(bind_device(&in,FLOW_BLOCK_BIND) == 0);
    struct cdx_ft_binding *b=list_entry(ft_bindings.next,struct cdx_ft_binding,list);
    assert(ft_replace(b,&cls) == 0);
    deletion_error=-EIO; quiesce_fail=true; unload_failures=1;
    ask_flowtable_exit();
    assert(ft_fatal && !backend_claimed && !live_hw && !allocated && handle.invalid);
    assert(unload_sleeps == 3 && !ft_proc);
    assert(ask_flowtable_init() == -EOPNOTSUPP && !backend_claimed && !ft_proc);
    owner_enabled=false; ft_fatal=false; registration_failure=registration_step=0;
    assert(ask_flowtable_init() == -EOPNOTSUPP && !backend_claimed && !registration_step);
    assert(!ft_proc && !cdx_info->ctrl.mutex);
}

int main(void)
{
    struct cdx_ft_rule decoded;
    fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.src == ik.src && decoded.dst == ik.dst && decoded.sport == htons(10000));
    assert(decoded.mtu == 1492 && decoded.in == &in && decoded.out == &out);
    assert(!memcmp(decoded.dst_mac, (u8[]){2,0x11,0x22,0x33,0x44,0x55}, 6));
    assert(!memcmp(decoded.src_mac, out.dev_addr, 6));
    REJECT(cls.nf_ct = NULL); REJECT(ct.net = NULL); REJECT(ct.zone[0] = 1); REJECT(ct.zone[1] = 1);
    REJECT(cls.nf_counter = true); REJECT(cls.nf_handle = NULL);
    REJECT(handle.invalid = true);
    REJECT(ct.mark = 1); REJECT(ct.status = IPS_NAT_MASK); REJECT(cls.nf_mtu = 0);
    REJECT(cls.nf_mtu = 67); REJECT(cls.nf_mtu = 1501); REJECT(cls.common.chain_index = 1);
    REJECT(cls.common.protocol = 0); REJECT(dissector.used_keys |= BIT(10));
    REJECT(mm.ingress_ifindex = 0); REJECT(mk.ingress_ifindex++); REJECT(mm.ingress_iftype = 1);
    REJECT(mm.l2_miss = 1); REJECT(cm.flags = 1); REJECT(cm.thoff = 1); REJECT(cm.addr_type = 0);
    REJECT(bk.ip_proto = IPPROTO_TCP); REJECT(bm.ip_proto = 0); REJECT(im.src = 0);
    REJECT(pm.dst = 0); REJECT(pk.src = 0); REJECT(ik.dst = htonl(0xe0000001));
    REJECT(ik.src = htonl(0x7f000001)); REJECT(ik.dst = 0xffffffff);
    REJECT(rule.action.num_entries = 4); REJECT(rule.action.entries[0].mangle.offset = 0);
    REJECT(rule.action.entries[0].mangle.val |= 1); REJECT(rule.action.entries[0].mangle.mask = 0);
    REJECT(rule.action.entries[4].dev = &in); REJECT(neigh_ok = false); REJECT(physical_ok = false);
    REJECT(dissector.used_keys |= BIT(FLOW_DISSECTOR_KEY_TCP));
    REJECT(bk.ip_proto = ct.protonum = IPPROTO_ICMP);
    fixture(); assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    struct cdx_ft_rule udp = decoded;
    tcp_fixture(); assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.proto == IPPROTO_TCP);
    assert(!ft_same_key(&udp, &decoded));
#define TCP_REJECT(change) do { tcp_fixture(); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
    TCP_REJECT(ct.protonum = IPPROTO_UDP);
    TCP_REJECT(ct.tcp_state = 2); TCP_REJECT(ct.tcp_state = 4); TCP_REJECT(ct.status = 0);
    TCP_REJECT(dissector.used_keys &= ~BIT(FLOW_DISSECTOR_KEY_TCP));
    TCP_REJECT(tk.flags = htons(1)); TCP_REJECT(tm.flags = 0);
    TCP_REJECT(tm.flags = htons(1)); TCP_REJECT(tm.flags = htons(4));
    TCP_REJECT(tm.flags = htons(7)); TCP_REJECT(tm.flags = htons(0x15));
    for (unsigned cycle = 0; cycle < 128; cycle++) {
        if (cycle & 1) tcp_fixture(); else fixture();
        assert(ft_replace(&binding, &cls) == 0);
        assert(ft_count == 1 && allocated == 1 && live_hw == 1 && out.refs == 1);
        assert(ft_replace(&binding, &cls) == 0); /* exact duplicate is idempotent */
        cls.cookie++; assert(ft_replace(&binding, &cls) == -EEXIST); cls.cookie--;
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie); assert(e);
        e->hw->stats = (struct cdx_ft_counters){ .packets = 100, .bytes = 12300, .lastused = 990 };
        assert(ft_stats(e, &cls) == 0 && cls.stats.pkts == 100 && cls.stats.bytes == 12300);
        cls.stats = (struct flow_stats){0};
        assert(ft_stats(e, &cls) == 0 && cls.stats.pkts == 0 && cls.stats.bytes == 0);
        assert(cls.stats.lastused == 990);
        jiffies = (1UL << 32) + 7; e->hw->stats.lastused = 0xfffffffe;
        assert(ft_stats(e, &cls) == 0 && cls.stats.lastused == (1UL << 32) - 2); jiffies = 1000;
        assert(ft_remove(e) == 0 && !ft_count && !allocated && !live_hw && !out.refs);
    }
    fixture();
    for (unsigned stage = 1; stage <= 3; stage++) {
        ft_fail_stage = stage; assert(ft_replace(&binding, &cls) < 0);
        assert(!ft_fail_stage && !ft_count && !allocated && !live_hw && !out.refs);
    }
    allocation_fail = true; assert(ft_replace(&binding, &cls) == -ENOMEM); allocation_fail = false;
    hardware_fail = true; assert(ft_replace(&binding, &cls) == -EIO); hardware_fail = false;
    invalidate_on_add = true; assert(ft_replace(&binding, &cls) == -EIO); invalidate_on_add = false;
    assert(ft_invalid && !ft_count && !allocated && !live_hw && !out.refs);
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP); ft_invalid = 0;
    ft_observe = true; assert(ft_replace(&binding, &cls) == -EOPNOTSUPP); ft_observe = false;
    assert(ft_replace(&binding, &cls) == 0);
    struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
    cls.nf_counter = true;
    assert(ft_stats(e, &cls) == -EOPNOTSUPP && ft_invalid);
    cls.nf_counter = false; ft_invalid = 0;
    e->reported.packets = 1; assert(ft_stats(e, &cls) == -EIO && ft_invalid);
    deletion_error = -EAGAIN; assert(ft_remove(e) == -EAGAIN && !ft_fatal);
    ft_invalid = 0; deletion_error = 0; assert(ft_replace(&binding, &cls) == 0);
    deletion_error = -EIO; assert(ft_remove(ft_find(&binding, cls.cookie)) == -EIO && ft_fatal);
    assert(ft_invalid && !ft_invalid_done && !allocated && !live_hw && !out.refs);
    list_add_tail(&binding.list, &ft_bindings);
    rtnl_busy = true; ft_invalidate_work(NULL); assert(scheduled == 1 && !flushed && !ft_invalid_done);
    rtnl_busy = false; quiesce_fail = true; ft_invalidate_work(NULL);
    assert(scheduled == 2 && !flushed && !ft_invalid_done);
    quiesce_fail = false; ft_invalidate_work(NULL);
    assert(flushed == 1 && ft_invalid_done && !in.refs && !out.refs);
    list_del(&binding.list);
    assert(ft_installs == ft_deletes);
    test_rearm();
    test_gateways();
    test_connections();
    test_neighbours();
    test_selective_neighbours();
    test_selective_routes();
    test_snat();
    test_device_dependencies();
    test_device_recovery();
    test_transient_admission();
    test_nexthop_objects();
    test_registration();
    puts("Flowtable: decoder, references, deltas, wrap, rollback, connections, neighbours, invalidation, rearm and fatal retry passed");
}

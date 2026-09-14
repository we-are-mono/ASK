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
typedef uint64_t u64;
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
#define CDX_DEBUG_FLOWTABLE
#define FLOW_ACTION_HW_STATS_DELAYED 1
#define IP_CT_DIR_ORIGINAL 0
#define IP_CT_DIR_REPLY 1
#define IPS_NAT_MASK 0x30
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
enum tc_setup_type { TC_SETUP_FT };
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
struct net_device { int ifindex, refs, mtu; u8 dev_addr[6]; };
#define dev_net(d) (&init_net)
struct neigh_table { int unused; };
static struct neigh_table arp_tbl;
struct neighbour {
    struct neigh_table *tbl;
    struct net_device *dev;
    unsigned refs, nud_state;
    bool dead, lock;
    u8 ha[6];
};
struct notifier_block { int unused; };
static struct neighbour neighbour;
static void read_lock_bh(bool *lock) { assert(!*lock); *lock = true; }
static void read_unlock_bh(bool *lock) { assert(*lock); *lock = false; }
#define spin_lock read_lock_bh
#define spin_unlock read_unlock_bh
#define spin_lock_bh read_lock_bh
#define spin_unlock_bh read_unlock_bh
struct nf_flowtable { struct { int nelems; } rhashtable; bool use_neigh; };
struct nf_conn { struct net *net; unsigned zone[2], mark, status, protonum, tcp_state; };
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
enum { FLOW_ACTION_MANGLE, FLOW_ACTION_REDIRECT, FLOW_ACT_MANGLE_HDR_TYPE_ETH };
struct flow_action_entry {
    unsigned id;
    struct { unsigned htype, offset; u32 mask, val; } mangle;
    struct net_device *dev;
};
struct flow_rule {
    struct { struct flow_dissector *dissector; } match;
    struct { unsigned num_entries; struct flow_action_entry entries[6]; } action;
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
struct flow_cls_offload {
    const struct nf_conn *nf_ct;
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
static int ft_work;
static LIST_HEAD(ft_bindings);
static LIST_HEAD(ft_entries);
static LIST_HEAD(ft_neigh_entries);
static bool ft_neigh_lock;
static LIST_HEAD(ft_block_list);
static unsigned ft_count, ft_bound, ft_fail_stage;
static unsigned ft_neighbour_refs;
static u64 ft_installs, ft_deletes, ft_errors, ft_validated, ft_rearms;
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
static int cdx_ft_hw_retry(void) { return retry_error; }
static unsigned cdx_ft_hw_pending(void) { return private_pending; }
static unsigned cdx_ehash_quarantine_pending(void) { return legacy_pending; }
static void cdx_ft_hw_quiesced(void) { assert(cdx_info->ctrl.mutex && !quiesce_fail); }
static void schedule_delayed_work(int *work, unsigned delay) { scheduled++; }
static void nf_flow_table_cleanup(struct net_device *dev)
{ assert(!cdx_info->ctrl.mutex); flushed++; if (cleanup_hook) cleanup_hook(); }
static void dev_hold(struct net_device *d) { d->refs++; }
static void dev_put(struct net_device *d) { assert(d->refs > 0); d->refs--; }
static int atomic_read(int *v) { return *v; }
static void atomic_set(int *v, int n) { *v = n; }
static void ft_invalidate(void) { ft_invalid = 1; }
static bool ft_physical(struct net_device *d) { return d && physical_ok; }
static struct neighbour *neigh_lookup(struct neigh_table *table, const __be32 *dst, struct net_device *dev)
{
    neigh_lookups++;
    if (change_neigh_on_lookup && neigh_lookups == 2) neighbour.ha[5]++;
    if (!neigh_ok) return NULL;
    assert(table == &arp_tbl);
    neighbour.dev = dev; neighbour.refs++;
    return &neighbour;
}
static void neigh_release(struct neighbour *n) { assert(n->refs); n->refs--; }
static int neigh_event_send(struct neighbour *n, void *skb)
{
    assert(n->refs && !n->lock && !ft_neigh_lock && !skb);
    neigh_uses++;
    return neigh_send_error;
}
static void *kzalloc(size_t n, int flags) { if (allocation_fail) return NULL; allocated++; return calloc(1, n); }
static void kfree(void *p) { assert(allocated); allocated--; free(p); }
static int ft_rule_callback(enum tc_setup_type t, void *data, void *priv) { return 0; }
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
{ list_del(&cb->list); list_add_tail(&cb->list, &bo->cb_list); }
static int cdx_ft_hw_add(const struct cdx_ft_rule *r, struct cdx_ft_hw **hw)
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
static int cdx_ft_hw_del(struct cdx_ft_hw **hw)
{ assert(*hw && live_hw); live_hw--; free(*hw); *hw = NULL; return deletion_error; }
static void cdx_ft_hw_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats) { *stats = hw->stats; }
#include "flowtable_production.inc"

static struct net_device in = { .ifindex = 5, .mtu = 1500, .dev_addr = {2, 0, 0, 0, 0, 1} };
static struct net_device out = { .ifindex = 6, .mtu = 1500, .dev_addr = {2, 0, 0, 0, 0, 2} };
static struct cdx_ft_binding binding = { .dev = &in };
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
    assert(!neighbour.refs && !ft_neighbour_refs && ft_neigh_entries.next == &ft_neigh_entries);
    neighbour = (struct neighbour){ .tbl = &arp_tbl, .nud_state = NUD_PERMANENT,
                                  .ha = {2,0x11,0x22,0x33,0x44,0x55} };
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
    cls = (struct flow_cls_offload){ .rule = &rule, .nf_ct = &ct, .nf_mtu = 1492,
        .cookie = 123, .common.protocol = ETH_P_ALL };
    physical_ok = neigh_ok = true;
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
#define REJECT(change) do { fixture(); change; assert(ft_parse(&binding, &cls, &decoded) == -EOPNOTSUPP); } while (0)

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
        assert(table.use_neigh);
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
        assert(ft_invalid && ft_count == 1); /* Atomic callback only latches. */
        assert(ft_remove(e) == 0 && !neighbour.refs && !ft_neighbour_refs);
        ft_invalid = 0;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid); /* Removed entries cannot be dereferenced. */
    }
    for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
        fixture(); neighbour.nud_state = invalid[i];
        assert(ft_parse(&binding, &cls, &decoded) == -EOPNOTSUPP && !neighbour.refs);
        neighbour.nud_state = NUD_REACHABLE;
        assert(ft_replace(&binding, &cls) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        neighbour.nud_state = invalid[i];
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(ft_invalid);
        unsigned uses = neigh_uses;
        e->hw->stats.packets++;
        assert(ft_stats(e, &cls) == -EOPNOTSUPP && neigh_uses == uses);
        assert(ft_remove(e) == 0); ft_invalid = 0;
    }
    fixture(); neighbour.dead = true;
    assert(ft_parse(&binding, &cls, &decoded) == -EOPNOTSUPP && !neighbour.refs);
    fixture(); change_neigh_on_lookup = true; /* Decoder/publication race. */
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    assert(!neighbour.refs && !ft_neighbour_refs && !live_hw && !allocated);
    change_neigh_on_lookup = false;
    fixture(); change_neigh_on_add = true; /* Watch precedes hardware insertion. */
    assert(ft_replace(&binding, &cls) == -EIO && ft_invalid);
    assert(!neighbour.refs && !ft_neighbour_refs && !live_hw && !allocated);
    change_neigh_on_add = false; ft_invalid = 0;
    fixture(); assert(ft_replace(&binding, &cls) == 0);
    struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
    neigh_send_error = 1; e->hw->stats.packets++;
    assert(ft_stats(e, &cls) == -EOPNOTSUPP && ft_invalid);
    assert(ft_remove(e) == 0); neigh_send_error = 0; ft_invalid = 0;
    fixture(); assert(ft_replace(&binding, &cls) == 0);
    cls.cookie++; pk.src = htons(10001);
    assert(ft_replace(&binding, &cls) == 0 && ft_neighbour_refs == 2 && neighbour.refs == 2);
    neighbour.dead = true;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(ft_invalid && ft_count == 2);
    ft_invalidate_work(NULL);
    assert(!ft_count && !live_hw && !allocated && !ft_neighbour_refs && !neighbour.refs);
    assert(ft_neigh_entries.next == &ft_neigh_entries && !out.refs);
    assert(ft_installs == ft_deletes);
}
int main(void)
{
    struct cdx_ft_rule decoded;
    fixture();
    assert(ft_parse(&binding, &cls, &decoded) == 0);
    assert(decoded.src == ik.src && decoded.dst == ik.dst && decoded.sport == htons(10000));
    assert(decoded.mtu == 1492 && decoded.in == &in && decoded.out == &out);
    assert(!memcmp(decoded.dst_mac, (u8[]){2,0x11,0x22,0x33,0x44,0x55}, 6));
    assert(!memcmp(decoded.src_mac, out.dev_addr, 6));
    REJECT(cls.nf_ct = NULL); REJECT(ct.net = NULL); REJECT(ct.zone[0] = 1); REJECT(ct.zone[1] = 1);
    REJECT(cls.nf_counter = true);
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
    fixture(); assert(ft_parse(&binding, &cls, &decoded) == 0);
    struct cdx_ft_rule udp = decoded;
    tcp_fixture(); assert(ft_parse(&binding, &cls, &decoded) == 0 && decoded.proto == IPPROTO_TCP);
    assert(!ft_same_key(&udp, &decoded));
#define TCP_REJECT(change) do { tcp_fixture(); change; assert(ft_parse(&binding, &cls, &decoded) == -EOPNOTSUPP); } while (0)
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
    test_neighbours();
    puts("Flowtable: decoder, references, deltas, wrap, rollback, neighbours, invalidation, rearm and fatal retry passed");
}

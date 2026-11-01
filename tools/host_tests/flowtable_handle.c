/* Production kernel handle operations and their flow-add/lookup/GC callers. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

typedef unsigned refcount_t;
typedef int atomic_t;
typedef uint64_t u64;
typedef uint32_t u32;
typedef int32_t __s32;
struct rcu_head { int unused; };
#define GFP_ATOMIC 0
#define READ_ONCE(v) (v)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_store_release(p, v) (*(p) = (v))
#define smp_load_acquire(p) (*(p))
#define cmpxchg(p, o, n) (*(p) == (o) ? (*(p) = (n), (o)) : *(p))
#define EXPORT_SYMBOL_GPL(name)
#define unlikely(v) (v)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define refcount_set(p, v) (*(p) = (v))
#define refcount_inc(p) (assert(*(p)), ++*(p))
#define refcount_dec_and_test(p) (assert(*(p)), --*(p) == 0)
#define atomic_set(p, v) (*(p) = (v))
#define atomic_read(p) (*(p))
static int atomic_xchg(atomic_t *p, int v) { int old = *p; *p = v; return old; }
static void set_bit(unsigned bit, unsigned long *p) { *p |= 1UL << bit; }
#define __set_bit set_bit
static bool test_bit(unsigned bit, const unsigned long *p) { return (*p >> bit) & 1; }
enum { NF_FLOW_TEARDOWN, NF_FLOW_HW, NF_FLOW_HW_DYING, NF_FLOW_HW_DEAD };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY, FLOW_OFFLOAD_DIR_MAX };
#define NF_FLOW_OFFLOAD_ROUTE 1
#define NF_FLOWTABLE_COUNTER 0x2
/* The flowtable's clock, which the collector judges each flow's timeout by. */
static u32 flowtable_clock = 1000;
#define nf_flowtable_time_stamp flowtable_clock
#define HZ 10
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
struct nf_flow_offload_handle;
/* One count for every reference, the flow's and the handle's alike. */
struct nf_conntrack { int unused; };
struct nf_conn { struct nf_conntrack ct_general; unsigned refs; bool dying; unsigned long status; };
enum { IPS_OFFLOAD_BIT = 14, IPS_HW_OFFLOAD_BIT = 15 };
static void clear_bit(unsigned bit, unsigned long *p) { *p &= ~(1UL << bit); }
static void nf_conntrack_get(struct nf_conntrack *nfct)
{ struct nf_conn *ct = (struct nf_conn *)nfct; assert(ct->refs); ct->refs++; }
/* What reached the conntrack's accounting, per direction. */
static u64 acct_packets[2], acct_bytes[2];
static void nf_ct_acct_add(struct nf_conn *ct, unsigned dir, u64 packets, u64 bytes)
{ assert(ct->refs && dir < 2); acct_packets[dir] += packets; acct_bytes[dir] += bytes; }
struct net { int unused; };
static struct net conntrack_net;
static uint64_t policy_generation;
static uint64_t xfrm_flowtable_genid(struct net *net) { return policy_generation; }
#define nf_ct_net(ct) (&conntrack_net)
/* Per-cause retirement counters. Recording them is what lets a spurious
 * hardware retirement be attributed instead of merely observed. */
static struct { unsigned count_gc_hw_invalid, count_gc_expired,
                count_gc_dying, count_gc_custom; } gc_stats;
#define NF_FLOW_TABLE_STAT_INC_ATOMIC(net, counter) \
    do { (void)(net); gc_stats.counter++; } while (0)
struct rhash_head { int unused; };
struct flow_offload_tuple { unsigned dir; };
struct flow_offload_tuple_rhash { struct rhash_head node; struct flow_offload_tuple tuple; };
struct flow_offload {
    struct flow_offload_tuple_rhash tuplehash[2];
    struct nf_conn *ct;
    struct nf_flow_offload_handle *hw_handle;
    unsigned long flags;
    /* stats_time is the statistics clock patch 140 starts in
     * flow_offload_add(); a tree that predates it never names it. */
    unsigned type, timeout, stats_time;
    uint64_t xfrm_genid;
    struct rcu_head rcu_head;
};
struct rhashtable { struct flow_offload_tuple_rhash *slots[2]; };
struct list_head { struct list_head *next, *prev; };
static void list_del(struct list_head *entry)
{ entry->next->prev = entry->prev; entry->prev->next = entry->next; }
static bool list_empty(const struct list_head *head) { return head->next == head; }
/* The block's callbacks are what a table's free asks about: whether any
 * driver is still bound to be told of its flows' deletion. */
struct nf_flowtable {
    struct rhashtable rhashtable; bool use_hw_handles, hardware; unsigned flags;
    struct list_head list;
    struct { struct list_head cb_list; } flow_block;
    int flow_block_lock, gc_work;
};
/* Declared by the header in the kernel; the handle's definitions use it
 * before they define it. */
void nf_flow_offload_handle_counting(struct nf_flow_offload_handle *handle, bool counter);
static const int nf_flow_offload_rhash_params;
static bool allocation_fail;
static unsigned allocations, insertions, fail_insert, adds, deletes, stats, teardowns, route_releases;
static void *deferred[32];
static unsigned deferred_count;
static void *kzalloc(size_t size, int flags)
{
    if (allocation_fail) return NULL;
    void *p = calloc(1, size); assert(p); allocations++; return p;
}
static void defer_free(void *p) { assert(deferred_count < 32); deferred[deferred_count++] = p; }
#define kfree_rcu(p, member) defer_free(p)
static void kfree(void *p) { free(p); assert(allocations); allocations--; }
/* call_rcu() callbacks, run at the next grace period like kfree_rcu()'s frees:
 * a flow's conntrack reference is only dropped there, after every reader that
 * could still reach the conntrack through the flow is done. */
static struct { struct rcu_head *head; void (*func)(struct rcu_head *); } callbacks[32];
static unsigned callback_count;
static void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *))
{
    assert(callback_count < 32);
    callbacks[callback_count].head = head;
    callbacks[callback_count++].func = func;
}
static void grace_period(void)
{
    while (callback_count) {
        callback_count--;
        callbacks[callback_count].func(callbacks[callback_count].head);
    }
    while (deferred_count) { free(deferred[--deferred_count]); assert(allocations); allocations--; }
}
static int rhashtable_insert_fast(struct rhashtable *table, struct rhash_head *node, int params)
{
    if (++insertions == fail_insert) return -ENOMEM;
    struct flow_offload_tuple_rhash *tuple = container_of(node, struct flow_offload_tuple_rhash, node);
    assert(!table->slots[tuple->tuple.dir]); table->slots[tuple->tuple.dir] = tuple; return 0;
}
static void rhashtable_remove_fast(struct rhashtable *table, struct rhash_head *node, int params)
{
    struct flow_offload_tuple_rhash *tuple = container_of(node, struct flow_offload_tuple_rhash, node);
    assert(table->slots[tuple->tuple.dir] == tuple); table->slots[tuple->tuple.dir] = NULL;
}
static struct flow_offload_tuple_rhash *rhashtable_lookup(struct rhashtable *table,
                                                        struct flow_offload_tuple *tuple, int params)
{ return table->slots[tuple->dir]; }
static unsigned flow_offload_get_timeout(struct flow_offload *flow) { return 100; }
#define NF_CT_DAY 86400
static unsigned refreshes, extensions;
static void nf_ct_refresh(struct nf_conn *ct, const void *skb, unsigned extra)
{ assert(ct->refs && !skb && extra == NF_CT_DAY); refreshes++; }
/* The GC extends a live flow's conntrack on every pass, and never one it is
 * tearing down: that one's timeout was just handed back to conntrack. */
static void nf_flow_table_extend_ct_timeout(struct nf_conn *ct) { assert(ct->refs); extensions++; }
static bool nf_ct_is_dying(struct nf_conn *ct) { return ct->dying; }
/* What a reply the flowtable carried tells the conntrack: its replied bit,
 * and one event for its listeners. */
#define IPS_SEEN_REPLY_BIT 1
#define likely(v) (v)
static bool __attribute__((unused)) test_and_set_bit(unsigned bit, unsigned long *p)
{ bool old = (*p >> bit) & 1; *p |= 1UL << bit; return old; }
enum ip_conntrack_events { IPCT_REPLY = 3 };
static unsigned reply_events;
static int __attribute__((unused)) nf_conntrack_event(enum ip_conntrack_events event, struct nf_conn *ct)
{ assert(event == IPCT_REPLY && test_bit(IPS_SEEN_REPLY_BIT, &ct->status)); return ++reply_events; }
static void nf_ct_put(struct nf_conn *ct) { assert(ct->refs); ct->refs--; }
static bool nf_flowtable_hw_offload(struct nf_flowtable *table) { return table->hardware; }
/* The replace work nf_flow_offload_add() queues, counted as an offer. */
enum flow_cls_command { FLOW_CLS_REPLACE };
struct flow_offload_work { int unused; };
static struct flow_offload_work offer;
static struct flow_offload_work *nf_flow_offload_work_alloc(struct nf_flowtable *table,
                                                            struct flow_offload *flow,
                                                            unsigned int cmd)
{ assert(cmd == FLOW_CLS_REPLACE); return &offer; }
static void flow_offload_queue_work(struct flow_offload_work *work) { assert(work == &offer); adds++; }
void nf_flow_offload_add(struct nf_flowtable *table, struct flow_offload *flow);
static void nf_flow_offload_del(struct nf_flowtable *table, struct flow_offload *flow)
{ deletes++; set_bit(NF_FLOW_HW_DYING, &flow->flags); }
static void nf_flow_offload_stats(struct nf_flowtable *table, struct flow_offload *flow) { stats++; }
static bool nf_flow_custom_gc(struct nf_flowtable *table, struct flow_offload *flow) { return false; }
static void flow_offload_teardown(struct flow_offload *flow)
{ teardowns++; set_bit(NF_FLOW_TEARDOWN, &flow->flags); }
static void flow_offload_route_release(struct flow_offload *flow) { route_releases++; }
void flow_offload_free(struct flow_offload *flow);
static void flow_offload_del(struct nf_flowtable *table, struct flow_offload *flow)
{
    table->rhashtable.slots[0] = table->rhashtable.slots[1] = NULL;
    flow_offload_free(flow);
}
/* What a table's free runs, around the per-flow steps it is built of. The
 * table holds at most one flow, visited once, by its original direction. */
static int flowtable_lock;
static unsigned flushes, flush_cleanups;
static void mutex_lock(int *lock) { assert(!*lock); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock); *lock = 0; }
static void down_read(int *lock) { assert(!*lock); *lock = 1; }
static void up_read(int *lock) { assert(*lock); *lock = 0; }
static void cancel_delayed_work_sync(int *work) { *work = 0; }
static void nf_flow_table_offload_flush(struct nf_flowtable *table) { flushes++; }
static void rhashtable_destroy(struct rhashtable *table) { assert(!table->slots[0] && !table->slots[1]); }
static void nf_flow_table_iterate(struct nf_flowtable *table,
                                  void (*iter)(struct nf_flowtable *, struct flow_offload *, void *),
                                  void *data)
{
    struct flow_offload_tuple_rhash *tuple = table->rhashtable.slots[0];
    if (tuple) iter(table, container_of(tuple, struct flow_offload, tuplehash[0]), data);
}
static void nf_flow_table_do_cleanup(struct nf_flowtable *table, struct flow_offload *flow, void *data)
{ assert(!data); flow_offload_teardown(flow); }
void nf_flow_table_gc_run(struct nf_flowtable *table);
/* The deletion queue's flush: each deletion queued ran and marked its flow
 * dead, which the collector then frees. */
static void nf_flow_table_offload_flush_cleanup(struct nf_flowtable *table)
{
    struct flow_offload_tuple_rhash *tuple = table->rhashtable.slots[0];
    flush_cleanups++;
    if (tuple) {
        struct flow_offload *flow = container_of(tuple, struct flow_offload, tuplehash[0]);
        if (test_bit(NF_FLOW_HW_DYING, &flow->flags)) set_bit(NF_FLOW_HW_DEAD, &flow->flags);
    }
    nf_flow_table_gc_run(table);
}
#include "handle_production.inc"

static struct flow_offload *new_flow(struct nf_conn *ct)
{
    struct flow_offload *flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
    assert(flow); flow->ct = ct; ct->refs++; flow->type = NF_FLOW_OFFLOAD_ROUTE;
    flow->xfrm_genid = policy_generation;
    flow->tuplehash[1].tuple.dir = 1;
    return flow;
}

/* The first tick from @from on of a pace that starts at @base and repeats
 * every @step ticks. */
static unsigned next_at(unsigned from, unsigned base, unsigned step)
{
    return from <= base ? base : base + (from - base + step - 1) / step * step;
}

/* A flow in hardware one way only, idle since it was added at @start: its
 * one direction read every @every ticks from @first on, the collector run
 * every @stride ticks from @phase on, a read before a pass on a tick they
 * share. Returns the tick after @start that retires it. */
static unsigned one_way_idle(struct nf_flowtable *table, struct nf_conn *ct, u32 start,
                             unsigned first, unsigned every, unsigned phase, unsigned stride)
{
    struct flow_offload *flow;
    unsigned t;

    flowtable_clock = start;
    flow = new_flow(ct); assert(flow_offload_add(table, flow) == 0);
    for (t = 1; t < 1000; t++) {
        flowtable_clock = start + t;
        if (t >= first && (t - first) % every == 0)
            nf_flow_offload_handle_used(flow->hw_handle, start);
        if (t >= phase && (t - phase) % stride == 0) {
            nf_flow_offload_gc_step(table, flow, NULL);
            if (test_bit(NF_FLOW_TEARDOWN, &flow->flags))
                break;
        }
    }
    flow_offload_del(table, flow); grace_period(); assert(!allocations && !ct->refs);
    return t;
}

int main(void)
{
    struct nf_conn ct = {0};
    struct nf_flowtable table = {0};
    struct flow_offload_tuple key[2] = {{0}, {1}};
    struct flow_offload *flow = new_flow(&ct);
    /* Non-opted-in tables allocate no handle, even under allocation pressure. */
    allocation_fail = true;
    assert(flow_offload_add(&table, flow) == 0 && !flow->hw_handle && allocations == 1);
    assert(refreshes == 1);
    allocation_fail = false;
    assert(!flow_offload_hw_invalid(flow) && flow_offload_lookup(&table, &key[0]));
    /* Its timeout reached, the flow has expired. */
    flowtable_clock = flow->timeout; nf_flow_offload_gc_step(&table, flow, NULL); flowtable_clock = 1000;
    /* Unhashed at once; the conntrack is only put after the grace period,
     * since a datapath reader may still reach it through the flow. */
    assert(ct.refs == 1 && !table.rhashtable.slots[0] && !extensions);
    grace_period(); assert(!allocations && !ct.refs);

    table.use_hw_handles = table.hardware = true;
    table.flags = NF_FLOWTABLE_COUNTER;
    flow = new_flow(&ct); allocation_fail = true;
    assert(flow_offload_add(&table, flow) == -ENOMEM && !flow->hw_handle);
    allocation_fail = false; flow_offload_free(flow); grace_period(); assert(!allocations && !ct.refs);
    for (unsigned stage = 1; stage <= 2; stage++) {
        flow = new_flow(&ct); insertions = 0; fail_insert = stage;
        assert(flow_offload_add(&table, flow) == -ENOMEM);
        assert(flow->hw_handle && !table.rhashtable.slots[0] && !table.rhashtable.slots[1]);
        flow_offload_free(flow); grace_period(); assert(!allocations && !ct.refs);
    }
    fail_insert = 0;
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    struct nf_flow_offload_handle *old = flow->hw_handle;
    nf_flow_offload_handle_get(old); nf_flow_offload_handle_get(old);
    assert(old->refs == 3 && nf_flow_offload_handle_valid(old));
    for (unsigned i = 0; i < 2; i++) assert(flow_offload_lookup(&table, &key[i]) == &flow->tuplehash[i]);
    nf_flow_offload_gc_step(&table, flow, NULL); assert(stats == 1 && !deletes && extensions == 1);
    assert(nf_flow_offload_handle_invalidate(old));
    assert(!nf_flow_offload_handle_invalidate(old));
    for (unsigned i = 0; i < 2; i++) assert(!flow_offload_lookup(&table, &key[i]));
    nf_flow_offload_gc_step(&table, flow, NULL); assert(deletes == 1);
    nf_flow_offload_gc_step(&table, flow, NULL); assert(deletes == 1);
    set_bit(NF_FLOW_HW_DEAD, &flow->flags);
    nf_flow_offload_gc_step(&table, flow, NULL);
    assert(old->refs == 2 && ct.refs == 2 && extensions == 1);
    /* The flow's conntrack reference goes after the grace period; the
     * retained handle's stays, so what its driver reports after the flow
     * reaches the conntrack -- and a reply in it marks the conntrack
     * replied, as it would have marked it before the flow went. */
    grace_period(); assert(allocations == 1 && ct.refs == 1);
    assert(!test_bit(IPS_SEEN_REPLY_BIT, &ct.status));
    nf_flow_offload_handle_account(old, FLOW_OFFLOAD_DIR_REPLY, 3, 300);
    assert(acct_packets[1] == 3 && acct_bytes[1] == 300 && !acct_packets[0]);
    assert(test_bit(IPS_SEEN_REPLY_BIT, &ct.status) && reply_events == 1);

    /* A retained old handle owns no Linux flow or route, only its conntrack.
     * Reusing the tuple cannot turn a delayed invalidation into an operation
     * on the new flow. */
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    assert(flow->hw_handle != old && nf_flow_offload_handle_valid(flow->hw_handle));
    assert(!nf_flow_offload_handle_invalidate(old));
    assert(flow_offload_lookup(&table, &key[0]) == &flow->tuplehash[0]);
    assert(ct.refs == 3);
    nf_flow_offload_handle_put(old); nf_flow_offload_handle_put(old);
    assert(!nf_flow_offload_handle_valid(old)); /* Existing RCU reader is safe. */
    /* The last put drops the conntrack at once; only the memory waits. */
    assert(deferred_count == 1 && ct.refs == 2); grace_period(); assert(allocations == 2);

    old = flow->hw_handle;
    nf_flow_offload_handle_get(old);
    flow_offload_del(&table, flow); /* Table destruction may precede driver put. */
    assert(!nf_flow_offload_handle_valid(old) && old->refs == 1 && ct.refs == 2);
    grace_period(); assert(allocations == 1 && ct.refs == 1);
    nf_flow_offload_handle_put(old); grace_period(); assert(!allocations && !ct.refs);
    assert(route_releases == 6 && adds == 2);
    /* A table that does not count folds nothing, as the handle last saw it. */
    table.flags = 0;
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    nf_flow_offload_handle_account(flow->hw_handle, FLOW_OFFLOAD_DIR_ORIGINAL, 5, 500);
    assert(!acct_packets[0]);
    flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);
    table.flags = NF_FLOWTABLE_COUNTER;
    /* A policy update retires both lookup directions before asynchronous GC,
     * even while the provider handle is still valid. Fresh flows use the new
     * policy generation; a subsequent change cannot revive the old flow. */
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    old = flow->hw_handle;
    assert(flow_offload_lookup(&table, &key[0]));
    policy_generation++;
    assert(nf_flow_offload_handle_valid(old) && flow_offload_hw_invalid(flow));
    for (unsigned i = 0; i < 2; i++) assert(!flow_offload_lookup(&table, &key[i]));
    unsigned invalidations = gc_stats.count_gc_hw_invalid;
    nf_flow_offload_gc_step(&table, flow, NULL);
    assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
    assert(gc_stats.count_gc_hw_invalid == invalidations + 1);
    /* Torn down, the flow waits for its hardware retirement over passes
     * that neither judge it nor count its retirement again. */
    unsigned pending = deletes;
    nf_flow_offload_gc_step(&table, flow, NULL);
    assert(gc_stats.count_gc_hw_invalid == invalidations + 1 && deletes == pending);
    policy_generation++;
    assert(flow_offload_hw_invalid(flow));
    set_bit(NF_FLOW_HW_DEAD, &flow->flags);
    nf_flow_offload_gc_step(&table, flow, NULL);
    assert(gc_stats.count_gc_hw_invalid == invalidations + 1);
    grace_period(); assert(!allocations && !ct.refs);
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    assert(!flow_offload_hw_invalid(flow) && flow_offload_lookup(&table, &key[0]));
    flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);
    /* A handle its driver watches leaves policy to the driver: a later
     * generation no longer retires the flow here, and only the driver's own
     * invalidation does. */
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    nf_flow_offload_handle_watch(flow->hw_handle);
    policy_generation++;
    assert(!flow_offload_hw_invalid(flow) && flow_offload_lookup(&table, &key[0]));
    nf_flow_offload_gc_step(&table, flow, NULL);
    assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags));
    assert(nf_flow_offload_handle_invalidate(flow->hw_handle));
    assert(flow_offload_hw_invalid(flow) && !flow_offload_lookup(&table, &key[0]));
    nf_flow_offload_handle_watch(NULL);
    flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);
    assert(!nf_flow_offload_handle_valid(NULL) && !nf_flow_offload_handle_invalidate(NULL));
    nf_flow_offload_handle_put(NULL);
    /* A flow the table cached before a driver asked it for handles has none,
     * and that driver can admit no offer without one. Offered again once the
     * table has such a driver, it is retired instead, so that its next packet
     * adds a flow that has one; until then it is offered as always. */
    table.use_hw_handles = false;
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0 && !flow->hw_handle);
    unsigned offers = adds, retirements = teardowns;
    nf_flow_offload_add(&table, flow);
    assert(adds == offers + 1 && teardowns == retirements);
    table.use_hw_handles = true;
    nf_flow_offload_add(&table, flow);
    assert(adds == offers + 1 && teardowns == retirements + 1);
    assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
    flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0 && flow->hw_handle);
    assert(adds == offers + 2 && teardowns == retirements + 1);
    flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);
    /* A table freed with no driver bound frees its flows in place: no
     * deletion is queued for a hardware flow, which would reach no one, and
     * its conntrack is no longer marked as in the hardware. With a driver
     * still bound the deletion goes to it, as before. */
    table.list.next = table.list.prev = &table.list;
    table.flow_block.cb_list.next = table.flow_block.cb_list.prev = &table.flow_block.cb_list;
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    assert(test_bit(NF_FLOW_HW, &flow->flags));
    ct.status = 1UL << IPS_HW_OFFLOAD_BIT;
    unsigned deleted = deletes, freed_flushes = flushes;
    retirements = teardowns;
    nf_flow_table_free(&table);
    assert(deletes == deleted && teardowns == retirements + 1 && flushes == freed_flushes + 1);
    assert(!table.rhashtable.slots[0] && !test_bit(IPS_HW_OFFLOAD_BIT, &ct.status));
    grace_period(); assert(!allocations && !ct.refs);
    struct list_head bound;
    bound.next = bound.prev = &table.flow_block.cb_list;
    table.flow_block.cb_list.next = table.flow_block.cb_list.prev = &bound;
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    unsigned cleanups = flush_cleanups;
    nf_flow_table_free(&table);
    assert(deletes == deleted + 1 && flush_cleanups == cleanups + 1 && !table.rhashtable.slots[0]);
    grace_period(); assert(!allocations && !ct.refs);
    /* A driver that reports on its own says through the handle when a
     * hardware flow was last used, and the collector judges the flow against
     * the timeout that report gives it. Applied only after the judgement, a
     * report reaches the timeout a pass late, and a flow whose traffic
     * resumed in the last pass before it timed out is torn down although
     * the report in hand says it is in use. Nor is a flow retired on
     * reports made before its timeout: traffic just before the timeout
     * reaches only the next read of its direction, so the collector waits
     * until the older of the driver's last two reports, which covers both
     * directions, is from the timeout on -- as long as the last report is
     * trusted, and no longer. Either side
     * of the 32-bit clock's wrap; the stub's timeout is 100, a report is
     * trusted for 50, and every report lands on an odd stamp, which a
     * report's time is rounded to. */
    for (unsigned wrap = 0; wrap < 2; wrap++) {
        const u32 start = wrap ? UINT32_MAX - 60 : 1001;
        unsigned expirations = gc_stats.count_gc_expired, asked = stats;

        table.use_hw_handles = table.hardware = true;
        /* Reported in use just before its timeout: kept, with the timeout
         * that use gives it, and not asked for counters as well -- that
         * would only apply the same report again. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        assert(flow->timeout == start + 100 && test_bit(NF_FLOW_HW, &flow->flags));
        flowtable_clock = start + 98;
        nf_flow_offload_handle_used(flow->hw_handle, start + 98);
        flowtable_clock = start + 100;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        assert(flow->timeout == start + 198 && gc_stats.count_gc_expired == expirations);
        assert(stats == asked);
        /* Applied again on the next pass, the report changes nothing. */
        flowtable_clock = start + 101;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 198);
        assert(stats == asked);
        /* Its reports stopped, the flow is asked for counters once the last
         * is no longer trusted, and runs down from the use it reported. */
        flowtable_clock = start + 196;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && stats == asked + 1);
        flowtable_clock = start + 198;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        assert(gc_stats.count_gc_expired == expirations + 1);
        /* Waiting for its hardware retirement, it is not counted again. */
        flowtable_clock = start + 199;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(gc_stats.count_gc_expired == expirations + 1);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* Used just before its timeout, after the driver's last report: that
         * report, idle, is no reason to retire the flow once the timeout has
         * passed. The driver's next one carries the use, and moves the
         * timeout. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 98;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        flowtable_clock = start + 100;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 100);
        assert(gc_stats.count_gc_expired == expirations + 1 && stats == asked + 1);
        nf_flow_offload_handle_used(flow->hw_handle, start + 99);
        flowtable_clock = start + 101;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 199);
        assert(gc_stats.count_gc_expired == expirations + 1 && stats == asked + 1);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* In hardware both ways, its directions read one after the other,
         * one just before the timeout and one at it: the latest report does
         * not cover the first direction from the timeout on, so the flow is
         * kept, and that direction's next read carries the traffic it had
         * just before the timeout. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 98;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        flowtable_clock = start + 100;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 100);
        assert(gc_stats.count_gc_expired == expirations + 1);
        flowtable_clock = start + 102;
        nf_flow_offload_handle_used(flow->hw_handle, start + 99);
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 199);
        assert(gc_stats.count_gc_expired == expirations + 1 && stats == asked + 1);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* Idle through its timeout, and in hardware one way only: kept past
         * it until the older of the driver's last two reports is from the
         * timeout on -- a report names no direction, so one alone may be
         * the other direction's -- and then expired, once. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 98;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        flowtable_clock = start + 100;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        flowtable_clock = start + 102;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        flowtable_clock = start + 104;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 100);
        assert(gc_stats.count_gc_expired == expirations + 2);
        flowtable_clock = start + 105;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(gc_stats.count_gc_expired == expirations + 2);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* A driver that stops reporting before the timeout keeps the flow
         * only while its last report is trusted: never past the timeout and
         * that trust together. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 98;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        for (flowtable_clock = start + 100; flowtable_clock != start + 149; flowtable_clock++) {
            nf_flow_offload_gc_step(&table, flow, NULL);
            assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        }
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        assert(gc_stats.count_gc_expired == expirations + 3 && stats == asked + 1);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* Idle, with the older of the last two reports made exactly at the
         * timeout: that covers the timeout, and the flow expires. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 100;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        flowtable_clock = start + 102;
        nf_flow_offload_handle_used(flow->hw_handle, start);
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 100);
        assert(gc_stats.count_gc_expired == expirations + 4);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* A use the driver puts after its report counts as the report's
         * time: it holds the timeout out no further than a use then would,
         * and the flow, its reports stopped, expires there. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 50;
        nf_flow_offload_handle_used(flow->hw_handle, start + 90);
        flowtable_clock = start + 51;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 150);
        flowtable_clock = start + 150;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        assert(gc_stats.count_gc_expired == expirations + 5 && stats == asked + 1);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* Never reported: it expires at its timeout. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 100;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        assert(gc_stats.count_gc_expired == expirations + 6);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* Reported in use, but longer ago than a report is trusted: it is
         * forgotten, and the flow expires at its timeout. */
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        flowtable_clock = start + 40;
        nf_flow_offload_handle_used(flow->hw_handle, start + 40);
        flowtable_clock = start + 100;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags) && flow->timeout == start + 100);
        assert(gc_stats.count_gc_expired == expirations + 7);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);

        /* A flow in software alone is judged by its own timeout: a report
         * through its handle is not applied, and it expires. */
        table.hardware = false;
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        assert(flow->hw_handle && !test_bit(NF_FLOW_HW, &flow->flags));
        flowtable_clock = start + 98;
        nf_flow_offload_handle_used(flow->hw_handle, start + 98);
        flowtable_clock = start + 100;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!table.rhashtable.slots[0] && gc_stats.count_gc_expired == expirations + 8);
        grace_period(); assert(!allocations && !ct.refs);
        table.hardware = true;

        /* A hardware flow with no handle, on a table whose driver asks for
         * none: asked for its counters on each pass, as ever, and expired
         * at its timeout. */
        table.use_hw_handles = false;
        flowtable_clock = start;
        flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
        assert(!flow->hw_handle && test_bit(NF_FLOW_HW, &flow->flags));
        flowtable_clock = start + 99;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && stats == asked + 2);
        flowtable_clock = start + 100;
        nf_flow_offload_gc_step(&table, flow, NULL);
        assert(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
        assert(gc_stats.count_gc_expired == expirations + 9 && stats == asked + 2);
        flow_offload_del(&table, flow); grace_period(); assert(!allocations && !ct.refs);
        table.use_hw_handles = true;

        /* In hardware one way only and idle, its direction read as seldom
         * as a report is trusted, or nearly, and the collector out of step
         * with the reads: retired by the first pass after the second read
         * from the timeout on, however the two paces fall. */
        static const struct { unsigned first, every, phase, stride; } paces[] = {
            { 2, 50, 1, 7 }, { 10, 46, 4, 11 }, { 2, 48, 1, 1 }, { 2, 50, 2, 3 },
        };
        for (unsigned i = 0; i < sizeof(paces) / sizeof(paces[0]); i++) {
            unsigned retired = gc_stats.count_gc_expired;
            unsigned second = next_at(100, paces[i].first, paces[i].every) + paces[i].every;

            assert(one_way_idle(&table, &ct, start, paces[i].first, paces[i].every,
                                paces[i].phase, paces[i].stride)
                   == next_at(second, paces[i].phase, paces[i].stride));
            assert(gc_stats.count_gc_expired == retired + 1);
        }
    }
    flowtable_clock = 1000;
    puts("Flowtable handles: opt-in allocation, rollback, shared ownership, the conntrack held for accounting, lookup, GC judged on the driver's latest report and counted once, RCU and generation isolation passed");
}

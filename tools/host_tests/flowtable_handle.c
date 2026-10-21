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
struct rcu_head { int unused; };
#define GFP_ATOMIC 0
#define READ_ONCE(v) (v)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_store_release(p, v) (*(p) = (v))
#define smp_load_acquire(p) (*(p))
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
#define nf_flowtable_time_stamp 1000
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
static bool allocation_fail, expired;
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
static bool nf_flow_has_expired(struct flow_offload *flow) { return expired; }
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
    expired = true; nf_flow_offload_gc_step(&table, flow, NULL); expired = false;
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
    policy_generation++;
    assert(flow_offload_hw_invalid(flow));
    set_bit(NF_FLOW_HW_DEAD, &flow->flags);
    nf_flow_offload_gc_step(&table, flow, NULL);
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
    puts("Flowtable handles: opt-in allocation, rollback, shared ownership, the conntrack held for accounting, lookup, GC, RCU and generation isolation passed");
}

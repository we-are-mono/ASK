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
struct rcu_head { int unused; };
#define GFP_ATOMIC 0
#define READ_ONCE(v) (v)
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
enum { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY, FLOW_OFFLOAD_DIR_MAX };
#define NF_FLOW_OFFLOAD_ROUTE 1
#define nf_flowtable_time_stamp 1000
struct nf_flow_offload_handle;
struct nf_conn { unsigned refs; bool dying; };
struct rhash_head { int unused; };
struct flow_offload_tuple { unsigned dir; };
struct flow_offload_tuple_rhash { struct rhash_head node; struct flow_offload_tuple tuple; };
struct flow_offload {
    struct flow_offload_tuple_rhash tuplehash[2];
    struct nf_conn *ct;
    struct nf_flow_offload_handle *hw_handle;
    unsigned long flags;
    unsigned type, timeout;
    struct rcu_head rcu_head;
};
struct rhashtable { struct flow_offload_tuple_rhash *slots[2]; };
struct nf_flowtable { struct rhashtable rhashtable; bool use_hw_handles, hardware; };
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
static void grace_period(void)
{
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
static void nf_ct_offload_timeout(struct nf_conn *ct) { assert(ct->refs); }
static bool nf_ct_is_dying(struct nf_conn *ct) { return ct->dying; }
static void nf_ct_put(struct nf_conn *ct) { assert(ct->refs); ct->refs--; }
static bool nf_flowtable_hw_offload(struct nf_flowtable *table) { return table->hardware; }
static void nf_flow_offload_add(struct nf_flowtable *table, struct flow_offload *flow) { adds++; }
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
#include "handle_production.inc"

static struct flow_offload *new_flow(struct nf_conn *ct)
{
    struct flow_offload *flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
    assert(flow); flow->ct = ct; ct->refs++; flow->type = NF_FLOW_OFFLOAD_ROUTE;
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
    allocation_fail = false;
    assert(!flow_offload_hw_invalid(flow) && flow_offload_lookup(&table, &key[0]));
    expired = true; nf_flow_offload_gc_step(&table, flow, NULL); expired = false;
    assert(!ct.refs && !table.rhashtable.slots[0]); grace_period(); assert(!allocations);

    table.use_hw_handles = table.hardware = true;
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
    nf_flow_offload_gc_step(&table, flow, NULL); assert(stats == 1 && !deletes);
    assert(nf_flow_offload_handle_invalidate(old));
    assert(!nf_flow_offload_handle_invalidate(old));
    for (unsigned i = 0; i < 2; i++) assert(!flow_offload_lookup(&table, &key[i]));
    nf_flow_offload_gc_step(&table, flow, NULL); assert(deletes == 1);
    nf_flow_offload_gc_step(&table, flow, NULL); assert(deletes == 1);
    set_bit(NF_FLOW_HW_DEAD, &flow->flags);
    nf_flow_offload_gc_step(&table, flow, NULL);
    assert(old->refs == 2 && !ct.refs); grace_period(); assert(allocations == 1);

    /* A retained old handle owns no Linux flow/route/CT. Reusing the tuple
     * cannot turn a delayed invalidation into an operation on the new flow. */
    flow = new_flow(&ct); assert(flow_offload_add(&table, flow) == 0);
    assert(flow->hw_handle != old && nf_flow_offload_handle_valid(flow->hw_handle));
    assert(!nf_flow_offload_handle_invalidate(old));
    assert(flow_offload_lookup(&table, &key[0]) == &flow->tuplehash[0]);
    nf_flow_offload_handle_put(old); nf_flow_offload_handle_put(old);
    assert(!nf_flow_offload_handle_valid(old)); /* Existing RCU reader is safe. */
    assert(deferred_count == 1); grace_period(); assert(allocations == 2);

    old = flow->hw_handle;
    nf_flow_offload_handle_get(old);
    flow_offload_del(&table, flow); /* Table destruction may precede driver put. */
    assert(!nf_flow_offload_handle_valid(old) && old->refs == 1 && !ct.refs);
    grace_period(); assert(allocations == 1);
    nf_flow_offload_handle_put(old); grace_period(); assert(!allocations);
    assert(route_releases == 6 && adds == 2);
    assert(!nf_flow_offload_handle_valid(NULL) && !nf_flow_offload_handle_invalidate(NULL));
    nf_flow_offload_handle_put(NULL);
    puts("Flowtable handles: opt-in allocation, rollback, shared ownership, lookup, GC, RCU and generation isolation passed");
}

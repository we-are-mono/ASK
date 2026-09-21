/* Production native allocation paths; only their kernel boundaries are stubbed. */
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define NF_FLOW_RULE_ACTION_MAX 16
#define NF_FLOW_HW_PENDING 0
#define FLOW_OFFLOAD_XMIT_NEIGH 1
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY };
enum { FLOW_CLS_REPLACE, FLOW_CLS_STATS, FLOW_CLS_DESTROY };
struct net { int unused; };
struct dst_entry { int unused; };
struct nf_flow_offload_handle { int invalid; };
struct flow_offload_tuple { int xmit_type; struct dst_entry *dst_cache; };
struct flow_offload {
    struct nf_flow_offload_handle *hw_handle;
    unsigned long flags;
    struct { struct flow_offload_tuple tuple; } tuplehash[2];
};
struct flow_rule { struct { void *dissector, *mask, *key; } match; struct { int num_entries; } action; };
struct nf_flow_rule { struct flow_rule *rule; struct { int dissector, mask, key; } match; };
struct table_type { int (*action)(struct net *, struct flow_offload *, int, struct nf_flow_rule *); };
struct nf_flowtable { struct table_type *type; };
struct work_struct { int initialized; };
struct flow_offload_work {
    unsigned cmd;
    struct flow_offload *flow;
    struct nf_flowtable *flowtable;
    struct work_struct work;
};
static unsigned allocation, fail_at, live;
static int match_error, action_error;
static void *allocate(size_t size)
{
    if (++allocation == fail_at) return NULL;
    void *p = calloc(1, size); assert(p); live++; return p;
}
static void *kzalloc(size_t size, int flags) { return allocate(size); }
static void *kmalloc(size_t size, int flags) { return allocate(size); }
static void kfree(void *p) { if (p) { assert(live); live--; free(p); } }
static struct flow_rule *flow_rule_alloc(unsigned n) { return allocate(sizeof(struct flow_rule)); }
static int atomic_xchg(int *p, int v) { int old = *p; *p = v; return old; }
static bool test_and_set_bit(unsigned bit, unsigned long *flags)
{ bool old = *flags & (1UL << bit); *flags |= 1UL << bit; return old; }
static void clear_bit(unsigned bit, unsigned long *flags) { *flags &= ~(1UL << bit); }
static int nf_flow_rule_match(void *match, const struct flow_offload_tuple *tuple, struct dst_entry *dst)
{ return match_error; }
static int action(struct net *net, struct flow_offload *flow, int dir, struct nf_flow_rule *rule)
{ return action_error; }
static void flow_offload_work_handler(struct work_struct *work) { abort(); }
#define INIT_WORK(work, fn) do { assert((fn) == flow_offload_work_handler); (work)->initialized = 1; } while (0)
#include "allocations_production.inc"

int main(void)
{
    struct nf_flow_offload_handle handle;
    struct flow_offload flow = { .hw_handle = &handle };
    struct table_type type = { .action = action };
    struct nf_flowtable table = { .type = &type };
    struct flow_offload_work context = { .flow = &flow, .flowtable = &table };
    struct net net;
    for (unsigned opted_in = 0; opted_in < 2; opted_in++) {
        flow.hw_handle = opted_in ? &handle : NULL;
        for (unsigned dir = 0; dir < 2; dir++) {
            for (unsigned nth = 1; nth <= 2; nth++) {
                handle.invalid = allocation = 0; fail_at = nth;
                assert(!nf_flow_offload_rule_alloc(&net, &context, dir));
                assert(handle.invalid == (int)opted_in && !live);
            }
            /* Unsupported match/action construction is not memory pressure. */
            for (unsigned failure = 0; failure < 2; failure++) {
                handle.invalid = allocation = fail_at = 0;
                match_error = failure ? 0 : -EOPNOTSUPP;
                action_error = failure ? -EOPNOTSUPP : 0;
                assert(!nf_flow_offload_rule_alloc(&net, &context, dir));
                assert(!handle.invalid && !live);
            }
            match_error = action_error = 0;
            struct nf_flow_rule *rule = nf_flow_offload_rule_alloc(&net, &context, dir);
            assert(rule && !handle.invalid && live == 2);
            kfree(rule->rule); kfree(rule);
        }
        for (unsigned cmd = FLOW_CLS_REPLACE; cmd <= FLOW_CLS_DESTROY; cmd++) {
            flow.flags = handle.invalid = allocation = 0; fail_at = 1;
            assert(!nf_flow_offload_work_alloc(&table, &flow, cmd));
            assert(!flow.flags && handle.invalid == (int)(opted_in && cmd == FLOW_CLS_REPLACE));
            /* Pending work is coalescing, not a failed allocation. */
            handle.invalid = allocation = 0; flow.flags = 1;
            assert(!nf_flow_offload_work_alloc(&table, &flow, cmd));
            assert(!allocation && !handle.invalid && flow.flags == 1);
            flow.flags = allocation = fail_at = 0;
            struct flow_offload_work *work = nf_flow_offload_work_alloc(&table, &flow, cmd);
            assert(work && work->flow == &flow && work->flowtable == &table && work->cmd == cmd);
            assert(work->work.initialized && !handle.invalid);
            kfree(work);
        }
    }
    assert(!live);
}

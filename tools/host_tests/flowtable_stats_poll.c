/* Compile the flowtable's hardware-statistics gate from the kernel tree and
 * drive it through the flows it has to serve: fully offloaded, partially
 * offloaded while software keeps refreshing the timeout, and software only;
 * and one whose driver reads its counters on its own and says so through the
 * flow's handle, which is asked for none while it does. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef int32_t __s32;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) (*(p) = (v))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define cmpxchg(p, o, n) (*(p) == (o) ? (*(p) = (n), (o)) : *(p))
#define NF_FLOWTABLE_COUNTER 0x2
#define HZ 100
#define IPS_HW_OFFLOAD_BIT 15
enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };

static u32 jiffies;
#define nf_flowtable_time_stamp jiffies

struct nf_conn { unsigned long status; };
struct nf_flowtable { unsigned flags; };
/* What the handle's definition names besides what the gate reads. */
typedef struct { int refs; } refcount_t;
typedef struct { int counter; } atomic_t;
struct rcu_head { void *next; };
struct nf_flow_offload_handle;
struct flow_offload { struct nf_conn *ct; u32 timeout, stats_time;
                      struct nf_flow_offload_handle *hw_handle; };
struct flow_offload_work { int unused; };

static bool test_bit(unsigned int bit, const unsigned long *addr)
{
    return (*addr >> bit) & 1;
}

/* The protocol's offload timeout, 30 s, as nf_conntrack_proto_udp.c sets it. */
static unsigned long flow_offload_get_timeout(struct flow_offload *flow)
{
    (void)flow;
    return 30 * HZ;
}

/* One work item per flow at a time, as NF_FLOW_HW_PENDING allows. */
static bool pending, refuse;
static unsigned queued;
static struct flow_offload_work work;
static struct flow_offload_work *nf_flow_offload_work_alloc(struct nf_flowtable *table,
                                                             struct flow_offload *flow,
                                                             unsigned int cmd)
{
    (void)table; (void)flow;
    assert(cmd == FLOW_CLS_STATS);
    if (pending || refuse)
        return NULL;
    pending = true;
    return &work;
}

static void flow_offload_queue_work(struct flow_offload_work *offload)
{
    assert(offload == &work && pending);
    queued++;
}

#include "stats_poll_production.inc"

/* The driver's own pass, each second: what it reports as the flow's last use
 * -- now while the flow is active, or the time it stopped. */
static bool reporting;
static u32 last_use;

/* Run the collector once a second for @seconds. A software packet each second
 * refreshes the timeout as flow_offload_refresh() does; hardware activity
 * extends it as flow_offload_work_stats() does once the work runs. */
static struct nf_flowtable table;
static unsigned run(struct flow_offload *flow, unsigned seconds, bool software, bool hardware)
{
    unsigned before = queued;

    for (unsigned s = 0; s < seconds; s++) {
        jiffies += HZ;
        if (reporting) {
            if (hardware)
                last_use = jiffies;
            nf_flow_offload_handle_used(flow->hw_handle, last_use);
        }
        if (software)
            flow->timeout = jiffies + flow_offload_get_timeout(flow);
        nf_flow_offload_stats(&table, flow);
        if (pending) {
            u32 extended = jiffies + flow_offload_get_timeout(flow);

            pending = false;
            if (hardware && (__s32)(flow->timeout - extended) < 0)
                flow->timeout = extended;
        }
    }
    return queued - before;
}

int main(void)
{
    const unsigned long hw = 1UL << IPS_HW_OFFLOAD_BIT;

    for (unsigned wrap = 0; wrap < 2; wrap++) {
        /* Either side of the 32-bit clock's wrap. */
        u32 start = wrap ? UINT32_MAX - 10 * HZ : 1000 * HZ;

        /* Fully offloaded: the timeout runs down between reads, so the
         * counters are read once more than a tenth of it has gone -- every
         * fourth second of a one-second collector, as before this gate
         * learned the second clause, which must not add reads of its own. */
        struct nf_conn full_ct = { .status = hw };
        jiffies = start;
        struct flow_offload full = { .ct = &full_ct, .timeout = jiffies + 30 * HZ,
                                     .stats_time = jiffies };
        unsigned reads = run(&full, 100, false, true);
        assert(reads == 25);

        /* Partially offloaded: software keeps the timeout fresh every second,
         * which the timeout alone read as never due. The hardware half is
         * read at the fully offloaded flow's pace all the same. */
        struct nf_conn partial_ct = { .status = hw };
        jiffies = start;
        struct flow_offload partial = { .ct = &partial_ct, .timeout = jiffies + 30 * HZ,
                                        .stats_time = jiffies };
        assert(run(&partial, 100, true, true) == reads);

        /* Software only: nothing in hardware to ask, so nothing is asked. */
        struct nf_conn soft_ct = { .status = 0 };
        jiffies = start;
        struct flow_offload soft = { .ct = &soft_ct, .timeout = jiffies + 30 * HZ,
                                     .stats_time = jiffies };
        assert(run(&soft, 100, true, false) == 0);

        /* A read that could not be queued -- work already pending -- leaves
         * the flow due, and the next collector pass asks again. */
        jiffies = start;
        partial.timeout = jiffies + 30 * HZ;
        partial.stats_time = jiffies;
        refuse = true;
        assert(run(&partial, 5, true, true) == 0);
        refuse = false;
        assert(run(&partial, 1, true, true) == 1);
        assert(run(&partial, 3, true, true) == 0);
        assert(run(&partial, 1, true, true) == 1);

        /* A driver that reports each second on its own: never asked, and the
         * flow it says is in use is kept alive as a reply would keep it. */
        struct nf_flow_offload_handle handle = { 0 };
        struct nf_conn pushed_ct = { .status = hw };
        jiffies = start;
        struct flow_offload pushed = { .ct = &pushed_ct, .timeout = jiffies + 30 * HZ,
                                       .stats_time = jiffies, .hw_handle = &handle };
        reporting = true;
        assert(run(&pushed, 100, false, true) == 0);
        assert(nf_flow_timeout_delta(pushed.timeout) >= 29 * HZ);
        /* Sent no command, it follows the table's counter mode all the
         * same, as each command would have had it do. */
        table.flags = NF_FLOWTABLE_COUNTER;
        assert(run(&pushed, 1, false, true) == 0 && handle.counter);
        table.flags = 0;
        assert(run(&pushed, 1, false, true) == 0 && !handle.counter);
        /* Idle, still reported: asked for nothing, and left to run down from
         * its last use, so the collector retires it as it would any idle
         * flow. */
        assert(run(&pushed, 29, false, false) == 0);
        assert(nf_flow_timeout_delta(pushed.timeout) > 0);
        assert(run(&pushed, 2, false, false) == 0);
        assert(nf_flow_timeout_delta(pushed.timeout) <= 0);
        /* A driver whose passes stop: its last report covers half the
         * timeout, and then the flow, with half its timeout left, is asked
         * again at the usual pace. */
        jiffies = start;
        handle = (struct nf_flow_offload_handle){ 0 };
        pushed.timeout = jiffies + 30 * HZ;
        pushed.stats_time = jiffies;
        assert(run(&pushed, 10, false, true) == 0);
        reporting = false;
        assert(run(&pushed, 15, false, true) == 0);
        assert(nf_flow_timeout_delta(pushed.timeout) == 15 * HZ);
        assert(run(&pushed, 100, false, true) == reads);
        /* And its last report is forgotten, so the clock, once it wraps,
         * cannot make it read as recent again. */
        assert(!handle.reported);
        /* A handle never reported through asks as every flow does. */
        jiffies = start;
        handle = (struct nf_flow_offload_handle){ 0 };
        pushed.timeout = jiffies + 30 * HZ;
        pushed.stats_time = jiffies;
        assert(run(&pushed, 100, false, true) == reads);
    }
    puts("Flowtable statistics: fully, partially and software-only flows read on their period; "
         "a reporting driver's never");
    return 0;
}

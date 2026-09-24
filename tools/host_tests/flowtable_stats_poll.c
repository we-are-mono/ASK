/* Compile the flowtable's hardware-statistics gate from the kernel tree and
 * drive it through the flows it has to serve: fully offloaded, partially
 * offloaded while software keeps refreshing the timeout, and software only. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef int32_t __s32;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define HZ 100
#define IPS_HW_OFFLOAD_BIT 15
enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };

static u32 jiffies;
#define nf_flowtable_time_stamp jiffies

struct nf_conn { unsigned long status; };
struct nf_flowtable { int unused; };
struct flow_offload { struct nf_conn *ct; u32 timeout, stats_time; };
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

/* Run the collector once a second for @seconds. A software packet each second
 * refreshes the timeout as flow_offload_refresh() does; hardware activity
 * extends it as flow_offload_work_stats() does once the work runs. */
static unsigned run(struct flow_offload *flow, unsigned seconds, bool software, bool hardware)
{
    struct nf_flowtable table;
    unsigned before = queued;

    for (unsigned s = 0; s < seconds; s++) {
        jiffies += HZ;
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
    }
    puts("Flowtable statistics: fully, partially and software-only flows read on their period");
    return 0;
}

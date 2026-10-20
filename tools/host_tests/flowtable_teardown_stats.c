/* Compile the flowtable's offload work from the kernel tree and prove what a
 * flow's teardown does with the counters its driver has not reported yet.
 *
 * A driver answers FLOW_CLS_DESTROY with the delta since its last report, as
 * it answers FLOW_CLS_STATS, and the delete work folds it into the conntrack
 * under NF_FLOWTABLE_COUNTER exactly as the statistics work does -- in full,
 * since a pull every few seconds can exceed 32 bits on one flow. A device's
 * flows are torn down through its still-bound driver before the driver's
 * block is unbound, so a deleted table reports its flows' last counts too.
 * The work, the per-direction command and the accounting entry point are
 * compiled from the kernel; the drivers and the conntrack are simulated. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef uint16_t __be16;
typedef int32_t __s32;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define ETH_P_ALL 0x0003
#define HZ 100
#define ENOENT 2

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define list_entry(p, t, m) container_of(p, t, m)
#define list_first_entry(h, t, m) list_entry((h)->next, t, m)
#define list_next_entry(e, m) list_entry((e)->m.next, __typeof__(*(e)), m)
#define list_for_each_entry(e, h, m) \
    for (e = list_first_entry(h, __typeof__(*e), m); &e->m != (h); e = list_next_entry(e, m))
static void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }

static bool test_bit(unsigned nr, const unsigned long *addr) { return (*addr >> nr) & 1; }
static void set_bit(unsigned nr, unsigned long *addr) { *addr |= 1UL << nr; }
static void clear_bit(unsigned nr, unsigned long *addr) { *addr &= ~(1UL << nr); }

/* The conntrack's accounting extension, as the entry point reaches it. */
typedef struct { s64 counter; } atomic64_t;
static void atomic64_add(s64 i, atomic64_t *v) { v->counter += i; }
static s64 atomic64_read(const atomic64_t *v) { return v->counter; }
#define IP_CT_DIR_MAX 2
struct nf_conn_counter { atomic64_t packets, bytes; };
struct nf_conn_acct { struct nf_conn_counter counter[IP_CT_DIR_MAX]; };
struct nf_conn { unsigned long status; struct nf_conn_acct *acct; };
static struct nf_conn_acct *nf_conn_acct_find(const struct nf_conn *ct) { return ct->acct; }
#define IPS_HW_OFFLOAD_BIT 15

enum flow_action_hw_stats { FLOW_ACTION_HW_STATS_DELAYED = 2 };
struct flow_rule { int unused; };
struct dst_entry { int unused; };
struct nf_flow_session { int lower_ifindex; };
struct nf_flow_tunnel { int lower_ifindex; };
struct nf_flow_offload_handle { int unused; };
struct netlink_ext_ack { int unused; };
#include "teardown_stats_types.inc"

enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY,
                              FLOW_OFFLOAD_DIR_MAX };
struct flow_offload_tuple {
    int iifidx;
    enum flow_offload_xmit_type xmit_type;
    u16 mtu;
    struct nf_flow_session session;
    struct nf_flow_tunnel tunnel;
    union {
        struct { struct dst_entry *dst_cache; u32 dst_cookie; };
        struct { u32 iifidx; } tc;
    };
};
struct flow_offload_tuple_rhash { struct flow_offload_tuple tuple; };
enum { NF_FLOW_HW_BIDIRECTIONAL = 4 };
struct flow_offload {
    struct flow_offload_tuple_rhash tuplehash[FLOW_OFFLOAD_DIR_MAX];
    struct nf_conn *ct;
    struct nf_flow_offload_handle *hw_handle;
    u64 xfrm_genid;
    unsigned long flags;
    u32 timeout, stats_time;
};
static unsigned long flow_offload_get_timeout(struct flow_offload *flow) { (void)flow; return 30 * HZ; }

#define NF_FLOWTABLE_COUNTER 0x2
#define NF_FLOWTABLE_HW_OFFLOAD 0x1
enum tc_setup_type { TC_SETUP_CLSFLOWER = 1 };
struct flow_block_cb {
    struct list_head list;
    int (*cb)(enum tc_setup_type type, void *data, void *priv);
    void *cb_priv;
};
struct nf_flowtable {
    unsigned flags;
    int priority;
    struct { struct list_head cb_list; } flow_block;
    int flow_block_lock;
};
static void down_read(int *lock) { assert(!*lock); *lock = 1; }
static void up_read(int *lock) { assert(*lock); *lock = 0; }
static bool nf_flowtable_hw_offload(struct nf_flowtable *flowtable)
{ return flowtable->flags & NF_FLOWTABLE_HW_OFFLOAD; }

struct nf_flow_rule { struct flow_rule *rule; };
struct flow_offload_work {
    enum flow_cls_command cmd;
    struct nf_flowtable *flowtable;
    struct flow_offload *flow;
};
/* The replace work is compiled with the rest and never run here. */
static int nf_flow_offload_alloc(const struct flow_offload_work *offload, struct nf_flow_rule *flow_rule[])
{ (void)offload; (void)flow_rule; assert(0); return -1; }
static void nf_flow_offload_destroy(struct nf_flow_rule *flow_rule[]) { (void)flow_rule; assert(0); }

/* The block setup, as the setup entry point drives it: which step ran, in
 * what order, and whether the device's flows were swept through the driver
 * first. */
struct net_device_ops { int (*ndo_setup_tc)(void); };
struct net_device { const struct net_device_ops *netdev_ops; };
struct flow_block_offload { int unused; };
enum flow_block_command { FLOW_BLOCK_BIND, FLOW_BLOCK_UNBIND };
static unsigned steps, cleanup_step, command_step, block_step, xdp_step;
static struct net_device *cleaned_dev;
static void nf_flow_table_gc_cleanup(struct nf_flowtable *flowtable, struct net_device *dev)
{ (void)flowtable; cleanup_step = ++steps; cleaned_dev = dev; }
static int nf_flow_table_offload_cmd(struct flow_block_offload *bo, struct nf_flowtable *flowtable,
                                     struct net_device *dev, enum flow_block_command cmd,
                                     struct netlink_ext_ack *extack)
{ (void)bo; (void)flowtable; (void)dev; (void)cmd; (void)extack; command_step = ++steps; return 0; }
static int nf_flow_table_indr_offload_cmd(struct flow_block_offload *bo, struct nf_flowtable *flowtable,
                                          struct net_device *dev, enum flow_block_command cmd,
                                          struct netlink_ext_ack *extack)
{ (void)bo; (void)flowtable; (void)dev; (void)cmd; (void)extack; command_step = ++steps; return 0; }
static int nf_flow_table_block_setup(struct nf_flowtable *flowtable, struct flow_block_offload *bo,
                                     enum flow_block_command cmd)
{ (void)flowtable; (void)bo; (void)cmd; block_step = ++steps; return 0; }
static int nf_flow_offload_xdp_setup(struct nf_flowtable *flowtable, struct net_device *dev,
                                     enum flow_block_command cmd)
{ (void)flowtable; (void)dev; (void)cmd; xdp_step = ++steps; return 0; }

#include "teardown_stats_production.inc"

/* A driver bound to the table: on a counter read and on a deletion it adds
 * what the direction counted since its last report, found by the cookie
 * every command names the direction by, as a driver does with
 * flow_stats_update(). */
static struct flow_offload flow;
static struct flow_stats report[FLOW_OFFLOAD_DIR_MAX];
static unsigned destroys, reads;
static int driver(enum tc_setup_type type, void *data, void *priv)
{
    struct flow_cls_offload *cls = data;
    unsigned dir;

    assert(type == TC_SETUP_CLSFLOWER && priv == &flow);
    assert(cls->nf_ct == flow.ct && cls->nf_handle == flow.hw_handle);
    for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++)
        if (cls->cookie == (unsigned long)&flow.tuplehash[dir].tuple)
            break;
    assert(dir < FLOW_OFFLOAD_DIR_MAX);
    assert(cls->nf_ingress_ifindex == flow.tuplehash[dir].tuple.iifidx);
    if (cls->command == FLOW_CLS_DESTROY)
        destroys++;
    else if (cls->command == FLOW_CLS_STATS)
        reads++;
    else
        assert(0);
    cls->stats.pkts += report[dir].pkts;
    cls->stats.bytes += report[dir].bytes;
    return 0;
}

static u64 packets(const struct nf_conn *ct, unsigned dir) { return atomic64_read(&ct->acct->counter[dir].packets); }
static u64 bytes(const struct nf_conn *ct, unsigned dir) { return atomic64_read(&ct->acct->counter[dir].bytes); }

int main(void)
{
    struct nf_conn_acct acct = {};
    struct nf_conn ct = { .status = 1UL << IPS_HW_OFFLOAD_BIT, .acct = &acct };
    struct nf_flow_offload_handle handle;
    struct nf_flowtable table = { .flags = NF_FLOWTABLE_HW_OFFLOAD | NF_FLOWTABLE_COUNTER,
                                  .priority = 1 };
    struct flow_block_cb one = { .cb = driver, .cb_priv = &flow };
    struct flow_block_cb two = { .cb = driver, .cb_priv = &flow };
    struct flow_offload_work work = { .flowtable = &table, .flow = &flow };

    table.flow_block.cb_list = (struct list_head)LIST_HEAD_INIT(table.flow_block.cb_list);
    list_add_tail(&one.list, &table.flow_block.cb_list);
    flow.ct = &ct;
    flow.hw_handle = &handle;
    flow.flags = 1UL << NF_FLOW_HW_BIDIRECTIONAL;
    flow.tuplehash[0].tuple.iifidx = 3;
    flow.tuplehash[1].tuple.iifidx = 4;

    /* A counter read folds each direction's delta, as it always has. */
    report[0] = (struct flow_stats){ .pkts = 10, .bytes = 10 * 284 };
    report[1] = (struct flow_stats){ .pkts = 4, .bytes = 4 * 60 };
    work.cmd = FLOW_CLS_STATS;
    flow_offload_work_stats(&work);
    assert(reads == 2 && !destroys);
    assert(packets(&ct, 0) == 10 && bytes(&ct, 0) == 10 * 284);
    assert(packets(&ct, 1) == 4 && bytes(&ct, 1) == 4 * 60);

    /* The deletion folds what the driver counted since that read the same
     * way, for both directions, and clears the offload bit as before. */
    report[0] = (struct flow_stats){ .pkts = 5, .bytes = 5 * 284 };
    report[1] = (struct flow_stats){ .pkts = 2, .bytes = 2 * 60 };
    work.cmd = FLOW_CLS_DESTROY;
    flow_offload_work_del(&work);
    assert(destroys == 2 && reads == 2);
    assert(!test_bit(IPS_HW_OFFLOAD_BIT, &ct.status));
    assert(packets(&ct, 0) == 15 && bytes(&ct, 0) == 15 * 284);
    assert(packets(&ct, 1) == 6 && bytes(&ct, 1) == 6 * 60);

    /* A delta past 32 bits survives both folds whole: one flow above eight
     * gigabits per second moves that much between two reads. */
    report[0] = (struct flow_stats){ .pkts = (1ULL << 32) + 5, .bytes = 3 * (1ULL << 32) + 7 };
    report[1] = (struct flow_stats){ .pkts = 1, .bytes = (1ULL << 32) };
    work.cmd = FLOW_CLS_STATS;
    flow_offload_work_stats(&work);
    assert(packets(&ct, 0) == 15 + (1ULL << 32) + 5);
    assert(bytes(&ct, 0) == 15 * 284 + 3 * (1ULL << 32) + 7);
    assert(packets(&ct, 1) == 7 && bytes(&ct, 1) == 6 * 60 + (1ULL << 32));
    work.cmd = FLOW_CLS_DESTROY;
    flow_offload_work_del(&work);
    assert(packets(&ct, 0) == 15 + 2 * ((1ULL << 32) + 5));
    assert(bytes(&ct, 0) == 15 * 284 + 2 * (3 * (1ULL << 32) + 7));
    assert(packets(&ct, 1) == 8 && bytes(&ct, 1) == 6 * 60 + 2 * (1ULL << 32));

    /* Every driver bound to the table adds to the one reply; a direction the
     * flow does not have in hardware is not asked about. */
    list_add_tail(&two.list, &table.flow_block.cb_list);
    acct = (struct nf_conn_acct){};
    report[0] = (struct flow_stats){ .pkts = 1, .bytes = 100 };
    report[1] = (struct flow_stats){ .pkts = 1, .bytes = 100 };
    flow.flags = 0;
    destroys = 0;
    flow_offload_work_del(&work);
    assert(destroys == 2);
    assert(packets(&ct, 0) == 2 && bytes(&ct, 0) == 200 && !packets(&ct, 1) && !bytes(&ct, 1));

    /* A table that does not count folds nothing, on either command. */
    table.flags = NF_FLOWTABLE_HW_OFFLOAD;
    acct = (struct nf_conn_acct){};
    flow.flags = 1UL << NF_FLOW_HW_BIDIRECTIONAL;
    work.cmd = FLOW_CLS_STATS;
    flow_offload_work_stats(&work);
    work.cmd = FLOW_CLS_DESTROY;
    flow_offload_work_del(&work);
    assert(!packets(&ct, 0) && !bytes(&ct, 0) && !packets(&ct, 1) && !bytes(&ct, 1));

    /* Unbinding a device sweeps its flows through the driver first, so their
     * last counts are reported while something can still answer; a bind
     * sweeps nothing, and a table with no hardware offload takes the XDP
     * route as before. */
    {
        struct net_device_ops ops = { .ndo_setup_tc = NULL };
        struct net_device dev = { .netdev_ops = &ops };

        table.flags = NF_FLOWTABLE_HW_OFFLOAD;
        assert(nf_flow_table_offload_setup(&table, &dev, FLOW_BLOCK_BIND) == 0);
        assert(!cleanup_step && command_step == 1 && block_step == 2 && !xdp_step);
        steps = command_step = block_step = 0;
        assert(nf_flow_table_offload_setup(&table, &dev, FLOW_BLOCK_UNBIND) == 0);
        assert(cleanup_step == 1 && cleaned_dev == &dev && command_step == 2 && block_step == 3);
        steps = cleanup_step = command_step = block_step = 0;
        table.flags = 0;
        assert(nf_flow_table_offload_setup(&table, &dev, FLOW_BLOCK_UNBIND) == 0);
        assert(xdp_step == 1 && !cleanup_step && !command_step && !block_step);
    }
    puts("Flowtable teardown: a deletion folds the drivers' last deltas whole, and an unbind sweeps the device's flows first");
    return 0;
}

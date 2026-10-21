/* Compile the flowtable's offload work and the flow's hardware handle from
 * the kernel tree and prove where a direction's last counts go.
 *
 * A driver reports what a direction counted since its last report through
 * the flow's handle as it takes the direction out of the hardware, at
 * whatever point that is: the handle holds the conntrack, and the counter
 * mode the table had at its last command about the flow, so the count reaches
 * the conntrack after the flow, its table and the driver's binding are gone
 * -- in full, since a pull every few seconds can exceed 32 bits on one flow.
 * A reply the hardware counted, read or reported last, answered the
 * connection, and marks its conntrack replied as the stack would have. A
 * deletion's reply folds nothing, and unbinding a device tears none of its
 * flows down first. The work, the per-direction command, the handle and the
 * accounting entry point are compiled from the kernel; the drivers and the
 * conntrack are simulated. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
/* The conntrack's references, as the handle takes and drops one. */
struct nf_conntrack { unsigned use; };
struct nf_conn { struct nf_conntrack ct_general; unsigned long status; struct nf_conn_acct *acct; };
static struct nf_conn_acct *nf_conn_acct_find(const struct nf_conn *ct) { return ct->acct; }
static void nf_conntrack_get(struct nf_conntrack *nfct) { assert(nfct->use); nfct->use++; }
static void nf_ct_put(struct nf_conn *ct) { assert(ct->ct_general.use); ct->ct_general.use--; }
#define IPS_SEEN_REPLY_BIT 1
#define IPS_DYING_BIT 9
#define IPS_HW_OFFLOAD_BIT 15
#define likely(x) (x)
static bool nf_ct_is_dying(const struct nf_conn *ct) { return (ct->status >> IPS_DYING_BIT) & 1; }
static bool test_and_set_bit(unsigned nr, unsigned long *addr)
{ bool old = (*addr >> nr) & 1; *addr |= 1UL << nr; return old; }
/* What conntrack's listeners hear: a reply event only for a conntrack already
 * marked replied. */
enum ip_conntrack_events { IPCT_REPLY = 3 };
static unsigned reply_events;
static int nf_conntrack_event(enum ip_conntrack_events event, struct nf_conn *ct)
{ assert(event == IPCT_REPLY && ((ct->status >> IPS_SEEN_REPLY_BIT) & 1)); reply_events++; return 0; }

enum flow_action_hw_stats { FLOW_ACTION_HW_STATS_DELAYED = 2 };
struct flow_rule { int unused; };
struct dst_entry { int unused; };
struct nf_flow_session { int lower_ifindex; };
struct nf_flow_tunnel { int lower_ifindex; };
struct netlink_ext_ack { int unused; };

/* What the handle is built from. Its memory goes back at once here: nothing
 * in this test borrows a handle under RCU. */
typedef struct { unsigned refs; } refcount_t;
typedef struct { int counter; } atomic_t;
struct rcu_head { int unused; };
#define GFP_ATOMIC 0
#define EXPORT_SYMBOL_GPL(sym)
static void refcount_set(refcount_t *r, unsigned n) { r->refs = n; }
static void refcount_inc(refcount_t *r) { assert(r->refs); r->refs++; }
static bool refcount_dec_and_test(refcount_t *r) { assert(r->refs); return !--r->refs; }
static void atomic_set(atomic_t *v, int i) { v->counter = i; }
static int atomic_read(const atomic_t *v) { return v->counter; }
static int atomic_xchg(atomic_t *v, int i) { int old = v->counter; v->counter = i; return old; }
#define smp_store_release(p, v) (*(p) = (v))
static void *kzalloc(size_t size, int flags) { (void)flags; return calloc(1, size); }
static unsigned handles_freed;
#define kfree_rcu(p, field) (free(p), handles_freed++)
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

/* Declared by the header in the kernel; the handle's definitions use it
 * before they define it. */
struct nf_flow_offload_handle;
static void nf_flow_offload_handle_counting(struct nf_flow_offload_handle *handle, bool counter);

#include "teardown_stats_production.inc"

/* A driver bound to the table: on a counter read and on a deletion it adds
 * what the direction counted since its last report, found by the cookie
 * every command names the direction by, as a driver does with
 * flow_stats_update() -- though a deletion's reply is only there to prove it
 * is ignored. Every command names its direction outright too. */
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
    assert(dir < FLOW_OFFLOAD_DIR_MAX && cls->nf_dir == dir);
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
    /* The flow's own reference. */
    struct nf_conn ct = { .ct_general.use = 1, .status = 1UL << IPS_HW_OFFLOAD_BIT, .acct = &acct };
    struct nf_flow_offload_handle *handle;
    struct nf_flowtable table = { .flags = NF_FLOWTABLE_HW_OFFLOAD | NF_FLOWTABLE_COUNTER,
                                  .priority = 1 };
    struct flow_block_cb one = { .cb = driver, .cb_priv = &flow };
    struct flow_block_cb two = { .cb = driver, .cb_priv = &flow };
    struct flow_offload_work work = { .flowtable = &table, .flow = &flow };

    table.flow_block.cb_list = (struct list_head)LIST_HEAD_INIT(table.flow_block.cb_list);
    list_add_tail(&one.list, &table.flow_block.cb_list);
    flow.ct = &ct;
    handle = nf_flow_offload_handle_alloc(&table, &ct);
    assert(handle && ct.ct_general.use == 2);
    flow.hw_handle = handle;
    flow.flags = 1UL << NF_FLOW_HW_BIDIRECTIONAL;
    flow.tuplehash[0].tuple.iifidx = 3;
    flow.tuplehash[1].tuple.iifidx = 4;

    /* A connection answered only in hardware has been answered all the same,
     * as the stack would have seen: a read that counts a reply marks its
     * conntrack replied and tells its listeners, once; one that counts the
     * original direction alone does neither. */
    report[0] = (struct flow_stats){ .pkts = 1, .bytes = 284 };
    work.cmd = FLOW_CLS_STATS;
    flow_offload_work_stats(&work);
    assert(!test_bit(IPS_SEEN_REPLY_BIT, &ct.status) && !reply_events);
    report[1] = (struct flow_stats){ .pkts = 1, .bytes = 60 };
    flow_offload_work_stats(&work);
    assert(test_bit(IPS_SEEN_REPLY_BIT, &ct.status) && reply_events == 1);
    flow_offload_work_stats(&work);
    assert(reply_events == 1);
    acct = (struct nf_conn_acct){};
    reads = 0;

    /* A counter read folds each direction's delta, as it always has. */
    report[0] = (struct flow_stats){ .pkts = 10, .bytes = 10 * 284 };
    report[1] = (struct flow_stats){ .pkts = 4, .bytes = 4 * 60 };
    work.cmd = FLOW_CLS_STATS;
    flow_offload_work_stats(&work);
    assert(reads == 2 && !destroys);
    assert(packets(&ct, 0) == 10 && bytes(&ct, 0) == 10 * 284);
    assert(packets(&ct, 1) == 4 && bytes(&ct, 1) == 4 * 60);

    /* A deletion asks both directions and clears the offload bit as before,
     * and folds nothing from its reply: a driver reports a direction's last
     * count through the flow's handle as it takes the direction out. */
    report[0] = (struct flow_stats){ .pkts = 5, .bytes = 5 * 284 };
    report[1] = (struct flow_stats){ .pkts = 2, .bytes = 2 * 60 };
    work.cmd = FLOW_CLS_DESTROY;
    flow_offload_work_del(&work);
    assert(destroys == 2 && reads == 2);
    assert(!test_bit(IPS_HW_OFFLOAD_BIT, &ct.status));
    assert(packets(&ct, 0) == 10 && bytes(&ct, 0) == 10 * 284);
    assert(packets(&ct, 1) == 4 && bytes(&ct, 1) == 4 * 60);

    /* A delta past 32 bits survives the fold whole: one flow above eight
     * gigabits per second moves that much between two reads. */
    report[0] = (struct flow_stats){ .pkts = (1ULL << 32) + 5, .bytes = 3 * (1ULL << 32) + 7 };
    report[1] = (struct flow_stats){ .pkts = 1, .bytes = (1ULL << 32) };
    work.cmd = FLOW_CLS_STATS;
    flow_offload_work_stats(&work);
    assert(packets(&ct, 0) == 10 + (1ULL << 32) + 5);
    assert(bytes(&ct, 0) == 10 * 284 + 3 * (1ULL << 32) + 7);
    assert(packets(&ct, 1) == 5 && bytes(&ct, 1) == 4 * 60 + (1ULL << 32));

    /* Every driver bound to the table adds to the one reply; a direction the
     * flow does not have in hardware is not asked about. */
    list_add_tail(&two.list, &table.flow_block.cb_list);
    acct = (struct nf_conn_acct){};
    report[0] = (struct flow_stats){ .pkts = 1, .bytes = 100 };
    report[1] = (struct flow_stats){ .pkts = 1, .bytes = 100 };
    flow.flags = 0;
    reads = 0;
    flow_offload_work_stats(&work);
    assert(reads == 2);
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

    /* What a driver reports through the handle folds as the table counted
     * at its last command about the flow: not at all after those, and not
     * yet once the table starts counting in place, until a command says so. */
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_REPLY, 3, 3 * 60);
    assert(!packets(&ct, 1) && !bytes(&ct, 1));
    table.flags = NF_FLOWTABLE_HW_OFFLOAD | NF_FLOWTABLE_COUNTER;
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_REPLY, 3, 3 * 60);
    assert(!packets(&ct, 1) && !bytes(&ct, 1));
    report[0] = report[1] = (struct flow_stats){0};
    work.cmd = FLOW_CLS_STATS;
    flow_offload_work_stats(&work);
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_REPLY, 1, 60);
    assert(packets(&ct, 1) == 1 && bytes(&ct, 1) == 60);

    /* The flow goes while its driver still holds the handle, the conntrack
     * with it: the flow's references are dropped, and the driver's last
     * reports still reach the conntrack, into the direction named and whole,
     * an empty one changing nothing. The driver's put is the last, and the
     * conntrack's reference goes with the handle. */
    nf_flow_offload_handle_get(handle);
    flow.hw_handle = NULL;
    nf_flow_offload_handle_put(handle);
    nf_ct_put(&ct);
    assert(ct.ct_general.use == 1 && !handles_freed);
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_REPLY, 3, 3 * 60);
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_ORIGINAL, (1ULL << 32) + 1, 5 * (1ULL << 32));
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_ORIGINAL, 0, 0);
    nf_flow_offload_handle_account(NULL, FLOW_OFFLOAD_DIR_ORIGINAL, 1, 1);
    assert(packets(&ct, 1) == 4 && bytes(&ct, 1) == 4 * 60);
    assert(packets(&ct, 0) == (1ULL << 32) + 1 && bytes(&ct, 0) == 5 * (1ULL << 32));
    nf_flow_offload_handle_put(handle);
    assert(!ct.ct_general.use && handles_freed == 1);

    /* And a table that stops counting in place is followed from its next
     * command about the flow. */
    ct.ct_general.use = 1;
    acct = (struct nf_conn_acct){};
    handle = nf_flow_offload_handle_alloc(&table, &ct);
    flow.hw_handle = handle;
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_ORIGINAL, 2, 200);
    table.flags = NF_FLOWTABLE_HW_OFFLOAD;
    work.cmd = FLOW_CLS_DESTROY;
    flow_offload_work_del(&work);
    nf_flow_offload_handle_account(handle, FLOW_OFFLOAD_DIR_ORIGINAL, 2, 200);
    assert(packets(&ct, 0) == 2 && bytes(&ct, 0) == 200);
    flow.hw_handle = NULL;
    nf_flow_offload_handle_put(handle);
    assert(ct.ct_general.use == 1 && handles_freed == 2);

    /* So does a direction's last delta, counted or not, and whatever the
     * flow's state: a reply in it marks the conntrack replied and is
     * reported once; an original alone, or a reply of no packets, does
     * neither; and a conntrack already dying is left as it is. */
    {
        struct nf_conn_acct quiet = {};
        struct nf_conn answered = { .ct_general.use = 1, .acct = &quiet };
        struct nf_conn dying = { .ct_general.use = 1, .status = 1UL << IPS_DYING_BIT,
                                 .acct = &quiet };
        struct nf_flow_offload_handle *a = nf_flow_offload_handle_alloc(&table, &answered);
        struct nf_flow_offload_handle *d = nf_flow_offload_handle_alloc(&table, &dying);

        assert(!(table.flags & NF_FLOWTABLE_COUNTER));
        reply_events = 0;
        nf_flow_offload_handle_account(a, FLOW_OFFLOAD_DIR_ORIGINAL, 2, 200);
        nf_flow_offload_handle_account(a, FLOW_OFFLOAD_DIR_REPLY, 0, 0);
        assert(!test_bit(IPS_SEEN_REPLY_BIT, &answered.status) && !reply_events);
        nf_flow_offload_handle_account(a, FLOW_OFFLOAD_DIR_REPLY, 1, 60);
        assert(test_bit(IPS_SEEN_REPLY_BIT, &answered.status) && reply_events == 1);
        nf_flow_offload_handle_account(a, FLOW_OFFLOAD_DIR_REPLY, 1, 60);
        assert(reply_events == 1 && !packets(&answered, 1));
        nf_flow_offload_handle_account(d, FLOW_OFFLOAD_DIR_REPLY, 1, 60);
        assert(!test_bit(IPS_SEEN_REPLY_BIT, &dying.status) && reply_events == 1);
        nf_flow_offload_handle_put(a);
        nf_flow_offload_handle_put(d);
        assert(answered.ct_general.use == 1 && dying.ct_general.use == 1 && handles_freed == 4);
    }

    /* Unbinding a device tears none of its flows down first: a nft table's
     * deletion unbinds its devices while the chains that create flows still
     * run, so a sweep there only has them recreated, offloaded and released
     * again, inside the commit. The driver reports what it releases. A table
     * with no hardware offload takes the XDP route as before. */
    {
        struct net_device_ops ops = { .ndo_setup_tc = NULL };
        struct net_device dev = { .netdev_ops = &ops };

        table.flags = NF_FLOWTABLE_HW_OFFLOAD;
        assert(nf_flow_table_offload_setup(&table, &dev, FLOW_BLOCK_BIND) == 0);
        assert(!cleanup_step && command_step == 1 && block_step == 2 && !xdp_step);
        steps = command_step = block_step = 0;
        assert(nf_flow_table_offload_setup(&table, &dev, FLOW_BLOCK_UNBIND) == 0);
        assert(!cleanup_step && !cleaned_dev && command_step == 1 && block_step == 2);
        steps = cleanup_step = command_step = block_step = 0;
        table.flags = 0;
        assert(nf_flow_table_offload_setup(&table, &dev, FLOW_BLOCK_UNBIND) == 0);
        assert(xdp_step == 1 && !cleanup_step && !command_step && !block_step);
    }
    puts("Flowtable teardown: a driver's last deltas reach the conntrack whole through the handle, after the flow, and an unbind sweeps nothing");
    return 0;
}

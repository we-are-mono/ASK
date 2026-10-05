/* Ingress police offload: what an action has to say before hardware is
 * touched, the unit it is converted into, and which flows a filter claims.
 *
 * The conversion is the part worth pinning. tc counts bytes per second; the
 * FMD's byte mode counts Kbit/s and multiplies by 1000 on its way to bits. Get
 * that backwards and the meter is off by 8000x in a direction nobody notices
 * until a link is saturated -- which is exactly the confusion that had CMM
 * validating a packets-per-second range against a byte-mode profile.
 *
 * The other half is the binding a flower filter needs. tc matches a 5-tuple;
 * the hardware selects a profile per flowtable entry. Neither subsystem knows
 * about the other, so the lookup here is the whole of the correspondence and
 * a wrong answer silently meters the wrong traffic.
 *
 * The third is the accounting. The hardware keeps running totals with more
 * than one reader and tc accumulates deltas, so the arithmetic between them --
 * including what a counter going backwards means -- is the part that decides
 * whether a reported drop count is the truth.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint16_t __be16; typedef uint32_t __be32;
#define SUCCESS 0
#define FAILURE 1
#define U32_MAX UINT32_MAX
#define ETH_HLEN 14
#define EOPNOTSUPP 95
#define EINVAL 22
#define ENOSPC 28
#define ENOENT 2
#define ENOMEM 12
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define WARN_ON_ONCE(x) (x)
#define FMAN_INDEX 0
#define ENABLE_INGRESS_POLICER 1
#define DISABLE_INGRESS_POLICER 0
#define GFP_KERNEL 0

static u64 div_u64(u64 n, u32 d) { return n / d; }

/* --- lists, as the kernel shapes them ------------------------------------ */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e)
{ e->prev->next = e->next; e->next->prev = e->prev; }
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_entry(p, t, m) container_of(p, t, m)
#define list_for_each_entry(pos, head, m) \
    for (pos = list_entry((head)->next, typeof(*pos), m); &pos->m != (head); \
         pos = list_entry(pos->m.next, typeof(*pos), m))
#define list_for_each_entry_safe(pos, n, head, m) \
    for (pos = list_entry((head)->next, typeof(*pos), m), \
         n = list_entry(pos->m.next, typeof(*pos), m); &pos->m != (head); \
         pos = n, n = list_entry(n->m.next, typeof(*n), m))

typedef int spinlock_t;
#define DEFINE_SPINLOCK(x) spinlock_t x
static void spin_lock_irqsave_(spinlock_t *l, unsigned long *f)
{ assert(!*l); *l = 1; *f = 0; }
static void spin_unlock_irqrestore_(spinlock_t *l, unsigned long f)
{ (void)f; assert(*l); *l = 0; }
#define spin_lock_irqsave(l, f) spin_lock_irqsave_(l, &(f))
#define spin_unlock_irqrestore(l, f) spin_unlock_irqrestore_(l, f)

static unsigned allocations;
static void *kzalloc(size_t n, int flags) { (void)flags; allocations++; return calloc(1, n); }
static void kfree(void *p) { if (p) { assert(allocations); allocations--; } free(p); }

/* --- the offload vocabulary ---------------------------------------------- */
enum flow_action_id {
    FLOW_ACTION_ACCEPT, FLOW_ACTION_DROP, FLOW_ACTION_PIPE,
    FLOW_ACTION_POLICE, FLOW_ACTION_MANGLE,
};
struct flow_action_entry {
    enum flow_action_id id;
    struct {
        u32 burst; u64 rate_bytes_ps, peakrate_bytes_ps; u32 avrate; u16 overhead;
        u64 burst_pkt, rate_pkt_ps; u32 mtu;
        struct { enum flow_action_id act_id; u32 extval; } exceed, notexceed;
    } police;
};
struct flow_action { unsigned num_entries; struct flow_action_entry entries[4]; };
struct netlink_ext_ack { const char *msg; };
#define NL_SET_ERR_MSG_MOD(e, m) do { if (e) (e)->msg = (m); } while (0)
static bool flow_offload_has_one_action(const struct flow_action *a)
{ return a->num_entries == 1; }

struct in6_addr { __be32 s6_addr32[4]; };
union nf_inet_addr { __be32 all[4]; __be32 ip; struct in6_addr in6; };
struct net_device { char name[16]; };

enum {
    FLOW_DISSECTOR_KEY_CONTROL, FLOW_DISSECTOR_KEY_BASIC,
    FLOW_DISSECTOR_KEY_IPV4_ADDRS, FLOW_DISSECTOR_KEY_IPV6_ADDRS,
    FLOW_DISSECTOR_KEY_PORTS, FLOW_DISSECTOR_KEY_VLAN, FLOW_DISSECTOR_KEY_META,
};
struct flow_dissector_key_control { u16 addr_type; u32 flags; };
struct flow_dissector_key_basic { u16 n_proto; u8 ip_proto; };
struct flow_dissector_key_ipv4_addrs { __be32 src, dst; };
struct flow_dissector_key_ipv6_addrs { struct in6_addr src, dst; };
struct flow_dissector_key_ports { __be16 src, dst; };
struct flow_dissector { unsigned long long used_keys; };

struct flow_match_control { struct flow_dissector_key_control *key, *mask; };
struct flow_match_basic { struct flow_dissector_key_basic *key, *mask; };
struct flow_match_ipv4_addrs { struct flow_dissector_key_ipv4_addrs *key, *mask; };
struct flow_match_ipv6_addrs { struct flow_dissector_key_ipv6_addrs *key, *mask; };
struct flow_match_ports { struct flow_dissector_key_ports *key, *mask; };

/* Storage the match accessors hand out pointers into, so a case can set a key
 * and its mask the way flower would. */
struct flow_rule {
    struct { struct flow_dissector *dissector; } match;
    struct flow_action action;
    struct flow_dissector dis;
    struct flow_dissector_key_control control, control_mask;
    struct flow_dissector_key_basic basic, basic_mask;
    struct flow_dissector_key_ipv4_addrs ipv4, ipv4_mask;
    struct flow_dissector_key_ipv6_addrs ipv6, ipv6_mask;
    struct flow_dissector_key_ports ports, ports_mask;
};
static bool flow_rule_match_key(const struct flow_rule *r, unsigned key)
{ return r->match.dissector->used_keys & BIT_ULL(key); }
#define flow_rule_match_control(r, m) do { (m)->key = &(r)->control; (m)->mask = &(r)->control_mask; } while (0)
#define flow_rule_match_basic(r, m) do { (m)->key = &(r)->basic; (m)->mask = &(r)->basic_mask; } while (0)
#define flow_rule_match_ipv4_addrs(r, m) do { (m)->key = &(r)->ipv4; (m)->mask = &(r)->ipv4_mask; } while (0)
#define flow_rule_match_ipv6_addrs(r, m) do { (m)->key = &(r)->ipv6; (m)->mask = &(r)->ipv6_mask; } while (0)
#define flow_rule_match_ports(r, m) do { (m)->key = &(r)->ports; (m)->mask = &(r)->ports_mask; } while (0)

/* What a driver hands back on a stats command, and the accumulator tc keeps
 * it in. The real flow_stats_update() adds rather than assigns, which is why
 * the driver has to subtract a baseline before it gets here. */
#define FLOW_ACTION_HW_STATS_IMMEDIATE 2
struct flow_stats {
    u64 pkts, bytes, drops, lastused;
    unsigned used_hw_stats;
    bool used_hw_stats_valid;
};
static unsigned long jiffies = 4294000000UL;
static void flow_stats_update(struct flow_stats *s, u64 bytes, u64 pkts, u64 drops,
                              u64 lastused, unsigned used_hw_stats)
{
    s->pkts += pkts; s->bytes += bytes; s->drops += drops;
    if (lastused > s->lastused) s->lastused = lastused;
    s->used_hw_stats |= used_hw_stats;
    s->used_hw_stats_valid = true;
}

enum { TC_CLSMATCHALL_REPLACE, TC_CLSMATCHALL_DESTROY, TC_CLSMATCHALL_STATS };
enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
struct tc_cls_matchall_offload {
    struct { struct netlink_ext_ack *extack; } common;
    int command;
    unsigned long cookie;
    struct flow_rule *rule;
    struct flow_stats stats;
};
struct flow_cls_offload {
    struct { struct netlink_ext_ack *extack; u32 chain_index; u32 prio; } common;
    int command;
    unsigned long cookie;
    struct flow_rule *rule;
    struct flow_stats stats;
};
static struct flow_rule *flow_cls_offload_flow_rule(struct flow_cls_offload *f)
{ return f->rule; }

/* Only the fields the lookup reads. */
struct cdx_ft_rule {
    struct net_device *in;
    union nf_inet_addr src, dst;
    __be16 sport, dport;
    u8 family, proto;
    u16 qos;
};
#define CDX_FT_QOS_POLICER_MASK  0xf00u
#define CDX_FT_QOS_POLICER_SHIFT 8
#define CDX_FT_QOS_MAX_POLICER   7

/* --- the hardware layer, recorded rather than performed ------------------ */
static struct { bool set, cleared; bool byte_mode; u32 cir, pir, cbs, pbs; } hw;
static bool hw_fail;
static int cdx_port_police_set(const char *ifname, bool byte_mode,
                               u32 cir, u32 pir, u32 cbs, u32 pbs)
{
    (void)ifname;
    if (hw_fail) return FAILURE;
    hw.set = true; hw.byte_mode = byte_mode;
    hw.cir = cir; hw.pir = pir; hw.cbs = cbs; hw.pbs = pbs;
    return SUCCESS;
}
static int cdx_port_police_clear(const char *ifname) { (void)ifname; hw.cleared = true; return SUCCESS; }

/* The colours a profile counted. Free-running totals, as the hardware keeps
 * them, so a case can move them the way traffic would -- or reset them
 * underneath the filter. */
struct cdx_police_counters { u32 green, yellow, red; };
static struct cdx_police_counters port_hw, prof_hw[CDX_FT_QOS_MAX_POLICER + 1];
static bool counters_fail;
static int cdx_port_police_counters(const char *ifname, struct cdx_police_counters *out)
{
    (void)ifname;
    if (counters_fail) return FAILURE;
    *out = port_hw;
    return SUCCESS;
}
static int cdx_ingress_policer_counters(u32 fm, u32 queue_no, struct cdx_police_counters *out)
{
    assert(fm == FMAN_INDEX);
    assert(queue_no >= 1 && queue_no <= CDX_FT_QOS_MAX_POLICER);
    if (counters_fail) return FAILURE;
    *out = prof_hw[queue_no];
    return SUCCESS;
}

static struct {
    unsigned enabled, disabled, configured;
    u32 last_profile, cir, pir, pbs;
    bool tc_meter;
} prof;
static bool prof_fail;
static int cdx_ingress_enable_or_disable_qos(u32 fm, u32 queue_no, u32 oper)
{
    assert(fm == FMAN_INDEX);
    assert(queue_no >= 1 && queue_no <= CDX_FT_QOS_MAX_POLICER);
    if (oper == ENABLE_INGRESS_POLICER) { prof.enabled++; prof.last_profile = queue_no; }
    else prof.disabled++;
    return prof_fail ? FAILURE : SUCCESS;
}
static int cdx_ingress_policer_modify_config(u32 fm, u32 queue_no, u32 cir, u32 pir,
                                             u32 cbs, u32 pbs, bool tc_meter)
{
    (void)fm; (void)cbs;
    prof.configured++; prof.last_profile = queue_no; prof.cir = cir; prof.pir = pir;
    prof.pbs = pbs; prof.tc_meter = tc_meter;
    return prof_fail ? FAILURE : SUCCESS;
}

#include "police_production.inc"

static struct netlink_ext_ack ack;
static struct net_device dev = { .name = "eth4" };
static struct net_device other = { .name = "eth3" };

static struct flow_action_entry base(void)
{
    struct flow_action_entry a = { .id = FLOW_ACTION_POLICE };
    a.police.rate_bytes_ps = 62500000;      /* 500 Mbit/s */
    a.police.burst = 64000;
    /* What tc_police gives a byte rate offered without an mtu: 255 cells of
     * the rate table's eight bytes. */
    a.police.mtu = 2040;
    a.police.exceed.act_id = FLOW_ACTION_DROP;
    a.police.notexceed.act_id = FLOW_ACTION_ACCEPT;
    return a;
}

/* One matchall filter, and the cookie tc would name it by. */
#define MALL_COOKIE 0x5a5aUL

static int offer_on(struct net_device *d, unsigned long cookie, struct flow_action_entry act)
{
    struct flow_rule rule = { .action = { .num_entries = 1 } };
    rule.action.entries[0] = act;
    struct tc_cls_matchall_offload f = {
        .common = { .extack = &ack }, .command = TC_CLSMATCHALL_REPLACE,
        .cookie = cookie, .rule = &rule };
    memset(&hw, 0, sizeof(hw));
    ack.msg = NULL;
    return cdx_police_matchall(d, &f);
}

static int offer(struct flow_action_entry act)
{
    return offer_on(&dev, MALL_COOKIE, act);
}

static int mall_cmd(struct net_device *d, unsigned long cookie, int command,
                    struct flow_stats *out)
{
    struct tc_cls_matchall_offload f = { .common = { .extack = &ack },
        .command = command, .cookie = cookie };
    int rc;

    ack.msg = NULL;
    rc = cdx_police_matchall(d, &f);
    if (out) *out = f.stats;
    return rc;
}

/* A flower filter on a v4 5-tuple, with every field exact unless masked out. */
static struct flow_rule flower_rule(void)
{
    struct flow_rule r = { .action = { .num_entries = 1 } };
    r.action.entries[0] = base();
    /* dissector is fixed up in flower_add(): it has to point at the caller's
     * copy of this struct, not at this one, which dies on return. */
    r.dis.used_keys = BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
                      BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
                      BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
                      BIT_ULL(FLOW_DISSECTOR_KEY_PORTS);
    r.control.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
    r.basic.ip_proto = IPPROTO_UDP; r.basic_mask.ip_proto = 0xff;
    r.ipv4.src = 0x0a000001; r.ipv4_mask.src = 0xffffffff;
    r.ipv4.dst = 0x0a000002; r.ipv4_mask.dst = 0xffffffff;
    r.ports.src = 1234; r.ports_mask.src = 0xffff;
    r.ports.dst = 5678; r.ports_mask.dst = 0xffff;
    return r;
}

static int flower_add(struct net_device *d, unsigned long cookie, struct flow_rule *r)
{
    struct flow_cls_offload f = { .common = { .extack = &ack },
        .command = FLOW_CLS_REPLACE, .cookie = cookie, .rule = r };
    r->match.dissector = &r->dis;
    ack.msg = NULL;
    return cdx_police_flower(d, &f);
}

static int flower_add_prio(struct net_device *d, unsigned long cookie,
                           struct flow_rule *r, u32 prio, u32 chain)
{
    struct flow_cls_offload f = { .common = { .extack = &ack, .prio = prio,
        .chain_index = chain },
        .command = FLOW_CLS_REPLACE, .cookie = cookie, .rule = r };
    r->match.dissector = &r->dis;
    ack.msg = NULL;
    return cdx_police_flower(d, &f);
}

static int flower_cmd(struct net_device *d, unsigned long cookie, int command,
                      struct flow_stats *out)
{
    struct flow_cls_offload f = { .common = { .extack = &ack },
        .command = command, .cookie = cookie };
    int rc;

    ack.msg = NULL;
    rc = cdx_police_flower(d, &f);
    if (out) *out = f.stats;
    return rc;
}

static int flower_del(struct net_device *d, unsigned long cookie)
{
    return flower_cmd(d, cookie, FLOW_CLS_DESTROY, NULL);
}

static struct cdx_ft_rule flow_on(struct net_device *d)
{
    struct cdx_ft_rule r = { .in = d, .family = AF_INET, .proto = IPPROTO_UDP,
        .sport = 1234, .dport = 5678 };
    r.src.ip = 0x0a000001; r.dst.ip = 0x0a000002;
    return r;
}

int main(void)
{
    /* ---- matchall: the port-wide meter ---- */

    /* Bytes per second in, Kbit/s out: 62_500_000 B/s is 500 Mbit/s is
     * 500_000 Kbit/s. A factor-of-eight slip shows up here and nowhere else. */
    /* Linux passes a frame only when it fits the rate's bucket, `burst`
     * deep, and is no longer than `mtu` (tcf_police_act()). The profile's
     * green is that: the committed bucket is the rate's, and the peak bucket
     * is `mtu` deep and refilled faster than any port, so it turns away only
     * a longer frame. Yellow and red are both dropped. */
    assert(offer(base()) == 0);
    assert(hw.set && hw.byte_mode);
    assert(hw.cir == 500000 && hw.pir == CDX_POLICE_UNBOUNDED_KBITS);
    /* The profile counts from the IP header, as Linux charges the rate;
     * Linux's length check adds the Ethernet header back. */
    assert(hw.cbs == 64000 && hw.pbs == 2040 - 14);

    /* A peak rate is Linux's second bucket, `mtu` deep at that rate: its
     * long-term rate stays the committed one. */
    struct flow_action_entry a = base();
    a.police.peakrate_bytes_ps = 125000000; /* 1 Gbit/s */
    a.police.mtu = 9216;
    assert(offer(a) == 0 && hw.cir == 500000 && hw.pir == 1000000);
    assert(hw.cbs == 64000 && hw.pbs == 9216 - 14);
    a.police.mtu = U32_MAX;                 /* no length worth checking */
    assert(offer(a) == 0 && hw.pbs == U32_MAX - 14);
    /* An mtu no frame fits keeps a bucket nothing fits, never an empty
     * one, which the profile would read as "use the default". */
    a.police.mtu = 10;
    assert(offer(a) == 0 && hw.pbs == 1);

    a = base(); a.police.peakrate_bytes_ps = 1000;
    assert(offer(a) == -EOPNOTSUPP);

    a = base(); a.police.rate_bytes_ps = 0; a.police.burst = 0;
    a.police.rate_pkt_ps = 20000; a.police.burst_pkt = 100; a.police.mtu = U32_MAX;
    assert(offer(a) == 0 && !hw.byte_mode && hw.cir == 20000 && hw.cbs == 100);
    /* A packet rate's buckets count frames and cannot check a length. */
    hw.set = false;
    a.police.mtu = 1514;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);

    a = base(); a.police.rate_pkt_ps = 20000;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    a = base(); a.police.rate_bytes_ps = 0;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);

    /* A rate under 125 B/s rounds to zero Kbit/s; programming that would be a
     * meter that drops everything. */
    a = base(); a.police.rate_bytes_ps = 100;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);

    a = base(); a.police.exceed.act_id = FLOW_ACTION_PIPE;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    a = base(); a.police.notexceed.act_id = FLOW_ACTION_DROP;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    a = base(); a.police.notexceed.act_id = FLOW_ACTION_PIPE;
    assert(offer(a) == 0);
    a = base(); a.police.avrate = 1000;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    a = base(); a.id = FLOW_ACTION_MANGLE;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);

    /* A port that cannot be programmed leaves nothing behind -- the record is
     * allocated before the hardware is touched precisely so this path can
     * hand it back, and the leak checker is what says it did. */
    hw_fail = true; assert(offer(base()) == -EINVAL); hw_fail = false;

    /* ---- matchall: what the filter reports ---- */

    /* Every offer above carried the same cookie, which is what tc does when
     * it replays a filter onto a block callback that binds after it: the port
     * is reprogrammed and the record is not duplicated. */
    assert(offer(base()) == 0);

    struct flow_stats s;
    port_hw = (struct cdx_police_counters){ .green = 100, .yellow = 20, .red = 5 };
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    /* Green was enqueued, yellow and red dropped, so the meter saw 125
     * frames and discarded 25. No byte counter exists in the profile, so none
     * is claimed rather than one being invented from an assumed frame size. */
    assert(s.pkts == 125 && s.drops == 25 && s.bytes == 0);
    assert(s.lastused == jiffies && s.used_hw_stats_valid);
    assert(s.used_hw_stats == FLOW_ACTION_HW_STATS_IMMEDIATE);

    /* Totals in, deltas out: tc adds up what it is given. */
    port_hw.green += 10; port_hw.red += 2;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 12 && s.drops == 2);

    /* Nothing moved, so nothing is reported -- and no claim is made about
     * when the filter was last used. */
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 0 && s.drops == 0 && s.lastused == 0);

    /* The profile was reset underneath. What the counter now holds is the
     * whole of the delta; reading a counter that went backwards as a 32-bit
     * wrap would credit the filter with four billion frames it never saw. */
    port_hw = (struct cdx_police_counters){ .green = 3, .yellow = 0, .red = 1 };
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 4 && s.drops == 1);

    /* A cookie the driver never recorded gets no answer at all, rather than
     * the port's numbers under somebody else's name. */
    assert(mall_cmd(&dev, 999, TC_CLSMATCHALL_STATS, &s) == -ENOENT);
    counters_fail = true;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == -EINVAL);
    counters_fail = false;

    /* The port has one limiter. A second matchall is refused before the
     * hardware is touched, so the first keeps its meter and its delete is
     * still the only one that returns the port to its boot rate; another
     * port takes one of its own. */
    assert(offer_on(&dev, MALL_COOKIE + 1, base()) == -EOPNOTSUPP && !hw.set);
    assert(ack.msg && strstr(ack.msg, "already has a police filter"));
    assert(mall_cmd(&dev, MALL_COOKIE + 1, TC_CLSMATCHALL_STATS, &s) == -ENOENT);
    assert(offer_on(&other, MALL_COOKIE + 1, base()) == 0 && hw.set);
    assert(mall_cmd(&other, MALL_COOKIE + 1, TC_CLSMATCHALL_DESTROY, NULL) == 0);

    memset(&hw, 0, sizeof(hw));
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0 && hw.cleared);
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == -ENOENT);

    /* ---- flower: a meter for some of the port's flows ---- */

    /* With nothing installed every flow meters against the default. */
    struct cdx_ft_rule flow = flow_on(&dev);
    assert(cdx_police_lookup(&flow) == 0);

    struct flow_rule fr = flower_rule();
    assert(flower_add(&dev, 1, &fr) == 0);
    assert(prof.enabled == 1 && prof.configured == 1);
    assert(prof.last_profile == 1);          /* profile 0 is the default */
    assert(prof.cir == 500000 && prof.pir == CDX_POLICE_UNBOUNDED_KBITS);
    assert(prof.pbs == 2040 - 14 && prof.tc_meter);
    assert(cdx_police_lookup(&flow) == 1);

    /* The filter is on one port's ingress. The same tuple arriving elsewhere
     * is a different flow and must not pick up this meter. */
    struct cdx_ft_rule elsewhere = flow_on(&other);
    assert(cdx_police_lookup(&elsewhere) == 0);

    /* Every field narrows it. */
    struct cdx_ft_rule wrong = flow_on(&dev); wrong.dport = 9999;
    assert(cdx_police_lookup(&wrong) == 0);
    wrong = flow_on(&dev); wrong.proto = IPPROTO_TCP;
    assert(cdx_police_lookup(&wrong) == 0);
    wrong = flow_on(&dev); wrong.src.ip = 0x0a0000ff;
    assert(cdx_police_lookup(&wrong) == 0);
    wrong = flow_on(&dev); wrong.family = AF_INET6;
    assert(cdx_police_lookup(&wrong) == 0);

    assert(flower_del(&dev, 1) == 0 && prof.disabled == 1);
    assert(cdx_police_lookup(&flow) == 0);
    assert(flower_del(&dev, 1) == -ENOENT);

    /* Priority, not insertion order: an operator who adds a higher-priority
     * (lower tc prio) filter after a lower-priority one already exists must
     * have the higher-priority meter picked -- the record is insertion-ordered,
     * so first-match would pick the wrong one. */
    fr = flower_rule();
    assert(flower_add_prio(&dev, 10, &fr, 100, 0) == 0);   /* low priority, first */
    unsigned lowpri = prof.last_profile;
    fr = flower_rule();
    assert(flower_add_prio(&dev, 11, &fr, 10, 0) == 0);    /* high priority, later */
    unsigned hipri = prof.last_profile;
    assert(lowpri != hipri && cdx_police_lookup(&flow) == hipri);
    assert(flower_del(&dev, 10) == 0);                     /* drop the loser */
    assert(cdx_police_lookup(&flow) == hipri);             /* winner survives */
    assert(flower_del(&dev, 11) == 0 && cdx_police_lookup(&flow) == 0);

    /* A filter in a non-zero chain is only reached by a goto software makes;
     * the tuple-bound offload cannot see it, so it is declined. */
    fr = flower_rule();
    assert(flower_add_prio(&dev, 20, &fr, 0, 1) == -EOPNOTSUPP);

    /* A pipe conform composes with any overlapping filter, which one profile
     * cannot represent. A lone pipe is fine; a second overlapping filter --
     * either order -- is declined, but a disjoint one is not. */
    fr = flower_rule(); fr.action.entries[0].police.notexceed.act_id = FLOW_ACTION_PIPE;
    assert(flower_add(&dev, 21, &fr) == 0);                /* lone pipe: accepted */
    fr = flower_rule();
    assert(flower_add(&dev, 22, &fr) == -EOPNOTSUPP);      /* overlapping accept: declined */
    fr = flower_rule(); fr.ports.dst = 9999; fr.action.entries[0].police.notexceed.act_id = FLOW_ACTION_PIPE;
    assert(flower_add(&dev, 23, &fr) == 0);                /* disjoint pipe: accepted */
    assert(flower_del(&dev, 21) == 0 && flower_del(&dev, 23) == 0);
    fr = flower_rule();
    assert(flower_add(&dev, 24, &fr) == 0);                /* accept first */
    fr = flower_rule(); fr.action.entries[0].police.notexceed.act_id = FLOW_ACTION_PIPE;
    assert(flower_add(&dev, 25, &fr) == -EOPNOTSUPP);      /* overlapping pipe: declined */
    assert(flower_del(&dev, 24) == 0);

    /* A profile a filter installed is named by flows that outlive the filter,
     * so it must not be handed to a new filter -- and reprogrammed -- while an
     * old flow still meters against it. The backend refs on install, unrefs on
     * removal; here the refs stand in for that. */
    fr = flower_rule();
    assert(flower_add(&dev, 30, &fr) == 0);
    unsigned held = prof.last_profile;                    /* a flow names it */
    cdx_police_profile_ref(held);
    assert(flower_del(&dev, 30) == 0);                    /* filter gone, flow not */
    /* Every other profile can be filled, but the held one stays out. */
    for (unsigned i = 0; i < CDX_FT_QOS_MAX_POLICER - 1; i++) {
        fr = flower_rule(); fr.ports.dst = 7000 + i;
        assert(flower_add(&dev, 40 + i, &fr) == 0 && prof.last_profile != held);
    }
    /* Held out of the pool, so the next filter has nowhere to go -- rather than
     * reusing a profile a live flow still meters against. */
    fr = flower_rule(); fr.ports.dst = 8000;
    assert(flower_add(&dev, 50, &fr) == -EOPNOTSUPP);
    cdx_police_profile_unref(held);                       /* the flow retires */
    assert(flower_add(&dev, 50, &fr) == 0 && prof.last_profile == held);  /* now reusable */
    assert(flower_del(&dev, 50) == 0);
    for (unsigned i = 0; i < CDX_FT_QOS_MAX_POLICER - 1; i++)
        assert(flower_del(&dev, 40 + i) == 0);

    /* A prefix is what per-subscriber policing is made of: mask off the host
     * bits and every address in the subnet meets the same meter. */
    fr = flower_rule();
    fr.ipv4_mask.src = 0xffffff00;           /* /24 */
    fr.ports_mask.src = 0; fr.ports_mask.dst = 0;
    fr.basic_mask.ip_proto = 0;
    assert(flower_add(&dev, 2, &fr) == 0);
    struct cdx_ft_rule same_subnet = flow_on(&dev);
    same_subnet.src.ip = 0x0a0000fe; same_subnet.sport = 40000; same_subnet.proto = IPPROTO_TCP;
    assert(cdx_police_lookup(&same_subnet) != 0);
    struct cdx_ft_rule other_subnet = flow_on(&dev);
    other_subnet.src.ip = 0x0a000101;
    assert(cdx_police_lookup(&other_subnet) == 0);
    assert(flower_del(&dev, 2) == 0);

    /* Seven meters, because profile 0 is the default and not for hire. The
     * eighth filter is refused so tc keeps it in software, rather than being
     * quietly given somebody else's meter. */
    for (unsigned i = 1; i <= CDX_FT_QOS_MAX_POLICER; i++) {
        fr = flower_rule();
        fr.ports.dst = 5000 + i;
        assert(flower_add(&dev, 100 + i, &fr) == 0);
    }
    fr = flower_rule(); fr.ports.dst = 6000;
    assert(flower_add(&dev, 999, &fr) == -EOPNOTSUPP);
    /* Giving one back makes room for exactly one more. */
    assert(flower_del(&dev, 101) == 0);
    fr = flower_rule(); fr.ports.dst = 6000;
    assert(flower_add(&dev, 999, &fr) == 0);
    for (unsigned i = 2; i <= CDX_FT_QOS_MAX_POLICER; i++)
        assert(flower_del(&dev, 100 + i) == 0);
    assert(flower_del(&dev, 999) == 0);

    /* A packet rate would need the whole pool in packet mode, which is not a
     * per-filter decision. */
    fr = flower_rule();
    fr.action.entries[0].police.rate_bytes_ps = 0;
    fr.action.entries[0].police.burst = 0;
    fr.action.entries[0].police.rate_pkt_ps = 1000;
    assert(flower_add(&dev, 3, &fr) == -EOPNOTSUPP);

    /* A key the hardware cannot separate at this point would meter a wider set
     * than the filter described. */
    fr = flower_rule();
    fr.dis.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_VLAN);
    assert(flower_add(&dev, 4, &fr) == -EOPNOTSUPP);

    /* A profile that cannot be programmed is a failure to report, and must not
     * leave the profile marked as taken. */
    prof_fail = true;
    fr = flower_rule();
    assert(flower_add(&dev, 5, &fr) == -EINVAL);
    prof_fail = false;
    fr = flower_rule();
    assert(flower_add(&dev, 6, &fr) == 0);
    assert(flower_del(&dev, 6) == 0);

    /* ---- flower: the same accounting, on the profile the filter holds ---- */

    fr = flower_rule();
    assert(flower_add(&dev, 7, &fr) == 0);
    unsigned mine = prof.last_profile;
    fr = flower_rule(); fr.ports.dst = 7777;
    assert(flower_add(&dev, 8, &fr) == 0);
    unsigned theirs = prof.last_profile;
    assert(mine != theirs);

    prof_hw[mine] = (struct cdx_police_counters){ .green = 40, .yellow = 0, .red = 9 };
    prof_hw[theirs] = (struct cdx_police_counters){ .green = 1, .yellow = 1, .red = 1 };
    assert(flower_cmd(&dev, 7, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 49 && s.drops == 9 && s.bytes == 0);
    /* Each filter reads the profile it was given and not its neighbour's. */
    assert(flower_cmd(&dev, 8, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 3 && s.drops == 2);

    /* Baselines are per filter, so one reading its counters does not empty
     * the other's. */
    prof_hw[mine].red += 4;
    assert(flower_cmd(&dev, 7, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 4 && s.drops == 4);
    assert(flower_cmd(&dev, 8, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 0 && s.drops == 0);

    assert(flower_cmd(&dev, 4242, FLOW_CLS_STATS, &s) == -ENOENT);
    assert(flower_cmd(&other, 7, FLOW_CLS_STATS, &s) == -ENOENT);
    counters_fail = true;
    assert(flower_cmd(&dev, 7, FLOW_CLS_STATS, &s) == -EINVAL);
    counters_fail = false;

    assert(flower_del(&dev, 7) == 0);
    assert(flower_cmd(&dev, 7, FLOW_CLS_STATS, &s) == -ENOENT);
    assert(flower_del(&dev, 8) == 0);

    /* The same profile is handed to the next filter, still holding everything
     * the last one metered. A new filter reports what happened since it
     * existed, not since the profile did. */
    fr = flower_rule();
    assert(flower_add(&dev, 9, &fr) == 0);
    assert(prof.last_profile == mine);
    assert(prof_hw[mine].green + prof_hw[mine].red > 0);
    assert(flower_cmd(&dev, 9, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 0 && s.drops == 0);
    prof_hw[mine].green += 6;
    assert(flower_cmd(&dev, 9, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 6 && s.drops == 0);
    assert(flower_del(&dev, 9) == 0);

    assert(!allocations);
    puts("Police: unit conversion, action validation, flower binding, "
         "profile budget and teardown passed");
    return 0;
}

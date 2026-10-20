/* Ingress police offload: what an action has to say before hardware is
 * touched, the unit it is converted into, which flows a filter claims, and
 * what the hardware ends up running when a write of it does not land.
 *
 * The conversion is the part worth pinning. tc counts bytes per second; the
 * FMD's byte mode counts Kbit/s and multiplies by 1000 on its way to bits. Get
 * that backwards and the meter is off by 8000x in a direction nobody notices
 * until a link is saturated -- which is exactly the confusion that had CMM
 * validating a packets-per-second range against a byte-mode profile.
 *
 * The second half is the binding a flower filter needs. tc matches a 5-tuple;
 * the hardware selects a profile per flowtable entry. Neither subsystem knows
 * about the other, so the lookup here is the whole of the correspondence and
 * a wrong answer silently meters the wrong traffic.
 *
 * The third is the accounting. The hardware keeps running totals with more
 * than one reader and tc accumulates deltas, so the arithmetic between them --
 * including what a counter going backwards means, and what a failed read or a
 * rewrite of the profile does to a baseline -- is the part that decides
 * whether a reported drop count is the truth.
 *
 * The fourth is a write the host command channel does not deliver. The
 * policer layer (cdx_qos.c) is compiled whole over a stub FMan
 * (plcr_fixture.h), so what a profile runs is read off the stub rather than
 * off the layer's own records: a case that leaves the two apart fails.
 */
#include "plcr_fixture.h"

#define U32_MAX UINT32_MAX
#define ETH_HLEN 14
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define WARN_ON_ONCE(x) (x)
#define EXPORT_SYMBOL_NS_GPL(sym, ns)

static u64 div_u64(u64 n, u32 d) { return n / d; }

/* --- lists, as the kernel shapes them ------------------------------------ */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e)
{ e->prev->next = e->next; e->next->prev = e->prev; }
#define list_entry(p, t, m) container_of(p, t, m)
#define list_for_each_entry(pos, head, m) \
    for (pos = list_entry((head)->next, typeof(*pos), m); &pos->m != (head); \
         pos = list_entry(pos->m.next, typeof(*pos), m))

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
/* As the kernel's: the message must be a string literal. */
#define NL_SET_ERR_MSG_MOD(e, m) do { static const char __msg[] = m; if (e) (e)->msg = __msg; } while (0)
static bool flow_offload_has_one_action(const struct flow_action *a)
{ return a->num_entries == 1; }

struct in6_addr { __be32 s6_addr32[4]; };
union nf_inet_addr { __be32 all[4]; __be32 ip; struct in6_addr in6; };

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

/* The block plumbing cdx_police_setup_block() hands its callback to. */
enum tc_setup_type { TC_SETUP_CLSMATCHALL, TC_SETUP_CLSFLOWER };
enum { FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS = 1 };
struct flow_block_offload { int binder_type; struct list_head *driver_block_list; };
typedef int flow_setup_cb_t(enum tc_setup_type type, void *type_data, void *cb_priv);
static int flow_block_cb_setup_simple(struct flow_block_offload *f, struct list_head *list,
                                      flow_setup_cb_t *cb, void *ident, void *priv, bool ingress)
{ (void)f; (void)list; (void)cb; (void)ident; (void)priv; (void)ingress; return 0; }

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

#include "plcr_types.inc"
#include "plcr_qos.inc"
#include "plcr_cfg.inc"
#include "police_production.inc"

/* --- the board: one FMan, a 10G port and a 1G one ------------------------ */
static struct cdx_fman_info fman;
static struct fm_port rx4, rx3;
static struct mac_device mac4 = { .port_dev = { &rx4 } }, mac3 = { .port_dev = { &rx3 } };
static struct dpa_priv_s priv4 = { &mac4 }, priv3 = { &mac3 };
static struct net_device dev = { .name = "eth4", .priv = &priv4 };
static struct net_device other = { .name = "eth3", .priv = &priv3 };
/* A netdev cdx has no port for, and so no rate limiter. */
static struct net_device bare = { .name = "eth9" };
static struct dpa_iface_info eth3 = { .name = "eth3", .if_flags = IF_TYPE_ETHERNET,
    .eth_info = { .net_dev = &other, .speed = 1000, .hardwarePortId = 6 } };
static struct dpa_iface_info eth4 = { .name = "eth4", .if_flags = IF_TYPE_ETHERNET,
    .eth_info = { .net_dev = &dev, .speed = 10000, .hardwarePortId = 5 }, .next = &eth3 };

/* What the DPA configuration creates before any owner can reach a profile. */
static void boot(void)
{
    fman.pcd_handle = &plcr_pcd;
    fman_info = &fman;
    num_fmans = 1;
    dpa_cfg_set_expt_defaults(&fman);
    assert(!cdxdrv_create_missaction_policer_profiles(&fman));
    assert(!cdxdrv_create_ingress_qos_policer_profiles(&fman));
    dpa_interface_info = &eth4;
    assert(dpa_add_ethport_ff_policier_profile(&eth4) == SUCCESS);
    assert(dpa_add_ethport_ff_policier_profile(&eth3) == SUCCESS);
}

#define RATE(s) ((s)->params.nonPassthroughAlgParams)
static struct profile *port_of(struct dpa_iface_info *i)
{ return port_rate_lim_mode[i->eth_info.hardwarePortId].handle; }
static struct profile *meter(unsigned q) { return fman.ingress_policer_info[q].handle; }
/* The per-flow profile the last write that landed went to. */
static unsigned last_profile(void)
{
    for (unsigned q = 1; q <= CDX_FT_QOS_MAX_POLICER; q++)
        if (meter(q) == plcr_last)
            return q;
    assert(!"the last write was not to a per-flow profile");
    return 0;
}

/* The boot meter, as NXP's profiles always ran it: packets, whole frames,
 * yellow passed, the port held to its peak pair. */
static void assert_port_boot(struct dpa_iface_info *i)
{
    struct profile *s = port_of(i);
    bool slow = i->eth_info.speed <= PORT_1G_SPEED;

    assert(RATE(s).rateMode == e_FM_PCD_PLCR_PACKET_MODE);
    assert(RATE(s).committedInfoRate ==
           (slow ? DEFAULT_PORT_FF_CIR_VALUE_1G : DEFAULT_PORT_FF_CIR_VALUE_10G));
    assert(RATE(s).peakOrExcessInfoRate ==
           (slow ? DEFAULT_PORT_FF_PIR_VALUE_1G : DEFAULT_PORT_FF_PIR_VALUE_10G));
    assert(RATE(s).committedBurstSize == (slow ? DEFAULT_1G_PORT_FF_CBS : DEFAULT_10G_PORT_FF_CBS));
    assert(RATE(s).peakOrExcessBurstSize == (slow ? DEFAULT_1G_PORT_FF_PBS : DEFAULT_10G_PORT_FF_PBS));
    assert(s->params.nextEngineOnYellow == e_FM_PCD_PRS &&
           s->params.paramsOnYellow.action == e_FM_PCD_ENQ_FRAME);
}

/* A tc police action's meter: bytes from the IP header on, yellow dropped. */
static void assert_meter(struct profile *s, u32 cir, u32 pir, u32 cbs, u32 pbs)
{
    assert(RATE(s).rateMode == e_FM_PCD_PLCR_BYTE_MODE);
    assert(RATE(s).committedInfoRate == cir && RATE(s).peakOrExcessInfoRate == pir);
    assert(RATE(s).committedBurstSize == cbs && RATE(s).peakOrExcessBurstSize == pbs);
    assert(RATE(s).byteModeParams.frameLengthSelection == e_FM_PCD_PLCR_L3_FRM_LEN);
    assert(s->params.nextEngineOnYellow == e_FM_PCD_DONE &&
           s->params.paramsOnYellow.action == e_FM_PCD_DROP_FRAME);
    assert(s->params.nextEngineOnRed == e_FM_PCD_DONE &&
           s->params.paramsOnRed.action == e_FM_PCD_DROP_FRAME);
}

/* A per-flow profile no filter holds: NXP's meter, wide open, so a flow still
 * naming it passes. */
static void assert_flow_profile_off(struct profile *s)
{
    assert(RATE(s).rateMode == e_FM_PCD_PLCR_BYTE_MODE);
    assert(RATE(s).committedInfoRate == DEFAULT_INGRESS_CIR_VALUE);
    assert(RATE(s).peakOrExcessInfoRate == DEFAULT_INGRESS_PIR_VALUE);
    assert(RATE(s).committedBurstSize == DEFAULT_INGRESS_BYTE_MODE_CBS);
    assert(RATE(s).peakOrExcessBurstSize == DEFAULT_INGRESS_BYTE_MODE_PBS);
    assert(RATE(s).byteModeParams.frameLengthSelection == e_FM_PCD_PLCR_FULL_FRM_LEN);
    assert(s->params.nextEngineOnYellow == s->params.nextEngineOnGreen);
}

static struct netlink_ext_ack ack;

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

static int flower_add(struct net_device *d, unsigned long cookie, struct flow_rule *r)
{
    return flower_add_prio(d, cookie, r, 0, 0);
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

/* ---- every verb, with a hardware that takes every write ---------------- */
static void verbs(void)
{
    struct profile *p4 = port_of(&eth4), *p3 = port_of(&eth3);
    struct flow_action_entry a;
    struct flow_stats s;
    unsigned tried;

    /* ---- matchall: the port-wide meter ---- */

    assert_port_boot(&eth4);
    /* Bytes per second in, Kbit/s out: 62_500_000 B/s is 500 Mbit/s is
     * 500_000 Kbit/s. A factor-of-eight slip shows up here and nowhere else. */
    /* Linux passes a frame only when it fits the rate's bucket, `burst`
     * deep, and is no longer than `mtu` (tcf_police_act()). The profile's
     * green is that: the committed bucket is the rate's, and the peak bucket
     * is `mtu` deep and refilled faster than any port, so it turns away only
     * a longer frame. Yellow and red are both dropped. */
    /* The profile counts from the IP header, as Linux charges the rate;
     * Linux's length check adds the Ethernet header back. */
    assert(offer(base()) == 0 && !ack.msg);
    assert_meter(p4, 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);

    /* A peak rate is Linux's second bucket, `mtu` deep at that rate: its
     * long-term rate stays the committed one. */
    a = base();
    a.police.peakrate_bytes_ps = 125000000; /* 1 Gbit/s */
    a.police.mtu = 9216;
    assert(offer(a) == 0);
    assert_meter(p4, 500000, 1000000, 64000, 9216 - 14);
    a.police.mtu = U32_MAX;                 /* no length worth checking */
    assert(offer(a) == 0 && RATE(p4).peakOrExcessBurstSize == U32_MAX - 14);
    /* An mtu no frame fits keeps a bucket nothing fits, never an empty
     * one, which the profile would read as "use the default". */
    a.police.mtu = 10;
    assert(offer(a) == 0 && RATE(p4).peakOrExcessBurstSize == 1);

    tried = plcr_attempts;
    a = base(); a.police.peakrate_bytes_ps = 1000;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);

    a = base(); a.police.rate_bytes_ps = 0; a.police.burst = 0;
    a.police.rate_pkt_ps = 20000; a.police.burst_pkt = 100; a.police.mtu = U32_MAX;
    assert(offer(a) == 0 && RATE(p4).rateMode == e_FM_PCD_PLCR_PACKET_MODE);
    assert(RATE(p4).committedInfoRate == 20000 && RATE(p4).committedBurstSize == 100);
    /* A packet rate's buckets count frames and cannot check a length. */
    tried = plcr_attempts;
    a.police.mtu = 1514;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);

    a = base(); a.police.rate_pkt_ps = 20000;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);
    a = base(); a.police.rate_bytes_ps = 0;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);

    /* A rate under 125 B/s rounds to zero Kbit/s; programming that would be a
     * meter that drops everything. */
    a = base(); a.police.rate_bytes_ps = 100;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);

    a = base(); a.police.exceed.act_id = FLOW_ACTION_PIPE;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);
    a = base(); a.police.notexceed.act_id = FLOW_ACTION_DROP;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);
    a = base(); a.police.avrate = 1000;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);
    a = base(); a.id = FLOW_ACTION_MANGLE;
    assert(offer(a) == -EOPNOTSUPP && plcr_attempts == tried);
    a = base(); a.police.notexceed.act_id = FLOW_ACTION_PIPE;
    assert(offer(a) == 0);

    /* A netdev cdx has no port for has no rate limiter to program. Nothing is
     * written and nothing is left behind -- the record is allocated before
     * the hardware is touched precisely so this path can hand it back, and
     * the leak checker is what says it did. */
    tried = plcr_attempts;
    assert(offer_on(&bare, MALL_COOKIE, base()) == -EINVAL && plcr_attempts == tried);

    /* ---- matchall: what the filter reports ---- */

    /* Every offer above carried the same cookie, which is what tc does when
     * it replays a filter onto a block callback that binds after it: the port
     * is reprogrammed and the record is not duplicated. */
    assert(offer(base()) == 0);

    p4->green = 100; p4->yellow = 20; p4->red = 5;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    /* Green was enqueued, yellow and red dropped, so the meter saw 125
     * frames and discarded 25. No byte counter exists in the profile, so none
     * is claimed rather than one being invented from an assumed frame size. */
    assert(s.pkts == 125 && s.drops == 25 && s.bytes == 0);
    assert(s.lastused == jiffies && s.used_hw_stats_valid);
    assert(s.used_hw_stats == FLOW_ACTION_HW_STATS_IMMEDIATE);

    /* Totals in, deltas out: tc adds up what it is given. */
    p4->green += 10; p4->red += 2;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 12 && s.drops == 2);

    /* Nothing moved, so nothing is reported -- and no claim is made about
     * when the filter was last used. */
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 0 && s.drops == 0 && s.lastused == 0);

    /* The profile was reset underneath. What the counter now holds is the
     * whole of the delta; reading a counter that went backwards as a 32-bit
     * wrap would credit the filter with four billion frames it never saw. */
    p4->green = 3; p4->yellow = 0; p4->red = 1;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 4 && s.drops == 1);

    /* Reprogramming the port zeroes its counters, which is no traffic. */
    assert(offer(base()) == 0);
    p4->green += 2;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 2 && s.drops == 0);

    /* A cookie the driver never recorded gets no answer at all, rather than
     * the port's numbers under somebody else's name. */
    assert(mall_cmd(&dev, 999, TC_CLSMATCHALL_STATS, &s) == -ENOENT);

    /* The port has one limiter. A second matchall is refused before the
     * hardware is touched, so the first keeps its meter and its delete is
     * still the only one that returns the port to its boot rate; another
     * port takes one of its own. */
    tried = plcr_attempts;
    assert(offer_on(&dev, MALL_COOKIE + 1, base()) == -EOPNOTSUPP && plcr_attempts == tried);
    assert(ack.msg && strstr(ack.msg, "already has a police filter"));
    assert(mall_cmd(&dev, MALL_COOKIE + 1, TC_CLSMATCHALL_STATS, &s) == -ENOENT);
    assert(offer_on(&other, MALL_COOKIE + 1, base()) == 0);
    assert_meter(p3, 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert_meter(p4, 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(mall_cmd(&other, MALL_COOKIE + 1, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert_port_boot(&eth3);

    /* Removing the filter returns the port to the rate it booted with. */
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert_port_boot(&eth4);
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == -ENOENT);

    /* ---- flower: a meter for some of the port's flows ---- */

    /* With nothing installed every flow meters against the default. */
    struct cdx_ft_rule flow = flow_on(&dev);
    assert(cdx_police_lookup(&flow) == 0);

    struct flow_rule fr = flower_rule();
    assert(flower_add(&dev, 1, &fr) == 0 && !ack.msg);
    assert(last_profile() == 1);             /* profile 0 is the default */
    assert_meter(meter(1), 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(cdx_police_lookup(&flow) == 1);
    /* And a flow the flowtable admits naming it is told to meter by it. */
    assert(fman.ingress_policer_info[1].profile_id &&
           cdx_get_policer_profile_id(FMAN_INDEX, 1) == fman.ingress_policer_info[1].profile_id);

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

    /* Deleted, the profile meters as NXP's do again, and no flow admitted
     * from now on is told to meter by it. */
    assert(flower_del(&dev, 1) == 0);
    assert_flow_profile_off(meter(1));
    assert(cdx_get_policer_profile_id(FMAN_INDEX, 1) == 0);
    assert(cdx_police_lookup(&flow) == 0);
    assert(flower_del(&dev, 1) == -ENOENT);

    /* Priority, not insertion order: an operator who adds a higher-priority
     * (lower tc prio) filter after a lower-priority one already exists must
     * have the higher-priority meter picked -- the record is insertion-ordered,
     * so first-match would pick the wrong one. */
    fr = flower_rule();
    assert(flower_add_prio(&dev, 10, &fr, 100, 0) == 0);   /* low priority, first */
    unsigned lowpri = last_profile();
    fr = flower_rule();
    assert(flower_add_prio(&dev, 11, &fr, 10, 0) == 0);    /* high priority, later */
    unsigned hipri = last_profile();
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
    unsigned held = last_profile();                       /* a flow names it */
    cdx_police_profile_ref(held);
    assert(flower_del(&dev, 30) == 0);                    /* filter gone, flow not */
    /* Every other profile can be filled, but the held one stays out. */
    for (unsigned i = 0; i < CDX_FT_QOS_MAX_POLICER - 1; i++) {
        fr = flower_rule(); fr.ports.dst = 7000 + i;
        assert(flower_add(&dev, 40 + i, &fr) == 0 && last_profile() != held);
    }
    /* Held out of the pool, so the next filter has nowhere to go -- rather than
     * reusing a profile a live flow still meters against. */
    fr = flower_rule(); fr.ports.dst = 8000;
    assert(flower_add(&dev, 50, &fr) == -EOPNOTSUPP);
    cdx_police_profile_unref(held);                       /* the flow retires */
    assert(flower_add(&dev, 50, &fr) == 0 && last_profile() == held);  /* now reusable */
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

    /* A profile with nothing to program is a refusal to report, and must not
     * leave the profile marked as taken. */
    void *h = fman.ingress_policer_info[1].handle;
    fman.ingress_policer_info[1].handle = NULL;
    fr = flower_rule();
    assert(flower_add(&dev, 5, &fr) == -EINVAL);
    fman.ingress_policer_info[1].handle = h;
    fr = flower_rule();
    assert(flower_add(&dev, 6, &fr) == 0 && last_profile() == 1);
    assert(flower_del(&dev, 6) == 0);

    /* ---- flower: the same accounting, on the profile the filter holds ---- */

    fr = flower_rule();
    assert(flower_add(&dev, 7, &fr) == 0);
    unsigned mine = last_profile();
    fr = flower_rule(); fr.ports.dst = 7777;
    assert(flower_add(&dev, 8, &fr) == 0);
    unsigned theirs = last_profile();
    assert(mine != theirs);

    meter(mine)->green = 40; meter(mine)->yellow = 0; meter(mine)->red = 9;
    meter(theirs)->green = meter(theirs)->yellow = meter(theirs)->red = 1;
    assert(flower_cmd(&dev, 7, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 49 && s.drops == 9 && s.bytes == 0);
    /* Each filter reads the profile it was given and not its neighbour's. */
    assert(flower_cmd(&dev, 8, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 3 && s.drops == 2);

    /* Baselines are per filter, so one reading its counters does not empty
     * the other's. */
    meter(mine)->red += 4;
    assert(flower_cmd(&dev, 7, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 4 && s.drops == 4);
    assert(flower_cmd(&dev, 8, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 0 && s.drops == 0);

    assert(flower_cmd(&dev, 4242, FLOW_CLS_STATS, &s) == -ENOENT);
    assert(flower_cmd(&other, 7, FLOW_CLS_STATS, &s) == -ENOENT);

    assert(flower_del(&dev, 7) == 0);
    assert(flower_cmd(&dev, 7, FLOW_CLS_STATS, &s) == -ENOENT);
    assert(flower_del(&dev, 8) == 0);

    /* The same profile handed to the next filter holds frames that are none
     * of the new filter's. The new filter reports what happened since it
     * existed, not since the profile did. */
    meter(mine)->green = 30;
    fr = flower_rule();
    assert(flower_add(&dev, 9, &fr) == 0);
    assert(last_profile() == mine);
    assert(flower_cmd(&dev, 9, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 0 && s.drops == 0);
    meter(mine)->green += 6;
    assert(flower_cmd(&dev, 9, FLOW_CLS_STATS, &s) == 0);
    assert(s.pkts == 6 && s.drops == 0);
    assert(flower_del(&dev, 9) == 0);
}

/* ---- matchall: a write that does not land is retried until it does ----- */
static void matchall_deferred(void)
{
    struct profile *p4 = port_of(&eth4);
    struct flow_action_entry a;
    struct flow_stats s;
    unsigned landed;

    /* The write times out and FMan never applied it. The filter is the
     * operator's and is valid, so it is taken -- and the operator told the
     * hardware is behind -- rather than refused for a fault that clears on
     * its own. Until the retry lands the port keeps its boot meter. */
    p4->green = 50;
    plcr_lost = 1;
    assert(offer(base()) == 0);
    assert(ack.msg && strstr(ack.msg, "retried"));
    assert_port_boot(&eth4);
    assert(work_count == 1);

    /* The retry lands, and the port runs what tc asked for. */
    p4->green += 10;
    assert(run_queued_work() == 1);
    assert_meter(p4, 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(!work_count);

    /* The rewrite zeroed the counters, and the filter's baseline went with
     * them: what is reported is what the meter counted since, rather than a
     * jump by everything the port counted before. */
    p4->green = 7; p4->red = 2;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 9 && s.drops == 2);

    /* Timed out after FMan applied it: the caller cannot tell, so it is
     * written again. The same whole profile, so the port's meter does not
     * change; only the counters restart, and the baseline with them. */
    a = base(); a.police.rate_bytes_ps = 125000000;      /* 1 Gbit/s */
    plcr_late = 1;
    assert(offer(a) == 0 && ack.msg && work_count == 1);
    assert_meter(p4, 1000000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    p4->green = 5;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 5);
    landed = p4->landed;
    assert(run_queued_work() == 1 && p4->landed == landed + 1 && !work_count);
    assert_meter(p4, 1000000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    p4->green = 3;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 3);

    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert_port_boot(&eth4);
}

/* ---- matchall: a delete that does not land ----------------------------- */
static void matchall_destroy_deferred(void)
{
    struct profile *p4 = port_of(&eth4);
    struct flow_action_entry a;
    struct flow_stats s;

    assert(offer(base()) == 0);
    assert_meter(p4, 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);

    /* tc forgets the filter whatever the driver says, so the port has to go
     * back to its boot rate regardless: left at the filter's, it would run a
     * rate nothing shows. */
    plcr_lost = 1;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == -ENOENT);
    assert_meter(p4, 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(run_queued_work() == 1);
    assert_port_boot(&eth4);
    assert(!work_count);

    /* A new filter offered while the reset is still outstanding writes the
     * whole profile, which supersedes it: the retry that follows is the new
     * filter's, not the reset's. */
    assert(offer(base()) == 0);
    plcr_lost = 1;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    a = base(); a.police.rate_bytes_ps = 12500000;       /* 100 Mbit/s */
    assert(offer_on(&dev, MALL_COOKIE + 1, a) == 0 && !ack.msg);
    assert_meter(p4, 100000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    run_queued_work();
    assert_meter(p4, 100000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(!work_count);
    assert(mall_cmd(&dev, MALL_COOKIE + 1, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert_port_boot(&eth4);
}

/* ---- matchall: the delete of a filter the port never ran --------------- */
static void matchall_refused_destroy(void)
{
    struct profile *p4 = port_of(&eth4);
    struct flow_action_entry a = base();

    assert(offer(base()) == 0);
    a.police.rate_bytes_ps = 12500000;
    assert(offer_on(&dev, MALL_COOKIE + 1, a) == -EOPNOTSUPP);
    /* tc keeps a refused filter in software and still offers its delete to
     * the driver. That delete is no reason to take the port's limiter from
     * the filter that holds it. */
    assert(mall_cmd(&dev, MALL_COOKIE + 1, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert_meter(p4, 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert_port_boot(&eth4);
}

/* ---- flower: a disable that does not land ------------------------------ */
static void flower_destroy_deferred(void)
{
    struct cdx_ft_rule flow = flow_on(&dev);
    struct flow_rule fr = flower_rule();
    unsigned p;
    int id;

    assert(flower_add(&dev, 1, &fr) == 0);
    p = last_profile();
    id = fman.ingress_policer_info[p].profile_id;
    assert(id && cdx_get_policer_profile_id(FMAN_INDEX, p) == id);

    /* The filter is gone the moment tc says so: no flow admitted from now on
     * is told to meter by its profile, and the retry turns the meter off for
     * the flows that still name it. */
    plcr_lost = 1;
    assert(flower_del(&dev, 1) == 0);
    assert(cdx_police_lookup(&flow) == 0);
    assert(cdx_get_policer_profile_id(FMAN_INDEX, p) == 0);
    assert_meter(meter(p), 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(run_queued_work() == 1);
    assert_flow_profile_off(meter(p));
    assert(!work_count);

    /* A profile whose disable is still outstanding, handed to a new filter:
     * the new filter's writes are whole profiles and supersede it, and the
     * retry already due does not turn the new filter's meter off. */
    fr = flower_rule();
    assert(flower_add(&dev, 2, &fr) == 0 && last_profile() == p);
    plcr_lost = 1;
    assert(flower_del(&dev, 2) == 0);
    fr = flower_rule(); fr.action.entries[0].police.rate_bytes_ps = 12500000;
    assert(flower_add(&dev, 3, &fr) == 0 && !ack.msg && last_profile() == p);
    assert_meter(meter(p), 100000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    run_queued_work();
    assert_meter(meter(p), 100000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(cdx_get_policer_profile_id(FMAN_INDEX, p) == id);
    assert(!work_count);
    assert(flower_del(&dev, 3) == 0);
    assert_flow_profile_off(meter(p));

    /* A filter whose writes do not land is taken, and flows admitted under it
     * are told to meter by its profile: they meter once the retry lands,
     * rather than never because they were admitted early. */
    plcr_lost = 2;
    fr = flower_rule();
    assert(flower_add(&dev, 4, &fr) == 0);
    assert(ack.msg && strstr(ack.msg, "retried"));
    assert(cdx_police_lookup(&flow) == p);
    assert(cdx_get_policer_profile_id(FMAN_INDEX, p) == id);
    assert_flow_profile_off(meter(p));
    assert(run_queued_work() == 1 && !work_count);
    assert_meter(meter(p), 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(flower_del(&dev, 4) == 0);
    assert_flow_profile_off(meter(p));
}

/* ---- a counter read that fails ----------------------------------------- */
static void counters_unread(void)
{
    struct profile *p4 = port_of(&eth4), *p3 = port_of(&eth3);
    struct flow_rule fr = flower_rule();
    struct flow_stats s;
    unsigned p;

    assert(offer(base()) == 0);
    p4->green = 100;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0 && s.pkts == 100);

    /* A read that fails is no reading. tc is told nothing, and the baseline
     * stays where the last good read left it: taking a zero it never counted
     * for one would report the whole counter as new on the next read. */
    p4->green += 30;
    counters_fail = true;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == -EINVAL);
    assert(s.pkts == 0 && s.drops == 0);
    counters_fail = false;
    p4->green += 5;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(s.pkts == 35 && s.drops == 0);

    /* A filter whose first reading fails has nothing to start from, so its
     * first good read is the start: never the profile's whole count claimed
     * as the filter's. */
    p3->green = 1000;
    counters_fail = true;
    assert(offer_on(&other, 77, base()) == 0);
    counters_fail = false;
    p3->green = 40;
    assert(mall_cmd(&other, 77, TC_CLSMATCHALL_STATS, &s) == 0 && s.pkts <= 40);
    p3->green += 3;
    assert(mall_cmd(&other, 77, TC_CLSMATCHALL_STATS, &s) == 0 && s.pkts == 3);

    /* The same on a per-flow profile. */
    assert(flower_add(&dev, 1, &fr) == 0);
    p = last_profile();
    meter(p)->green = 20; meter(p)->red = 2;
    assert(flower_cmd(&dev, 1, FLOW_CLS_STATS, &s) == 0 && s.pkts == 22 && s.drops == 2);
    meter(p)->red += 8;
    counters_fail = true;
    assert(flower_cmd(&dev, 1, FLOW_CLS_STATS, &s) == -EINVAL && s.pkts == 0);
    counters_fail = false;
    meter(p)->red += 1;
    assert(flower_cmd(&dev, 1, FLOW_CLS_STATS, &s) == 0 && s.pkts == 9 && s.drops == 9);

    assert(flower_del(&dev, 1) == 0);
    assert(mall_cmd(&other, 77, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
}

/* ---- the channel shut: every write refused until it reopens ------------ */
static void channel_shut(void)
{
    struct cdx_ft_rule flow = flow_on(&dev);
    struct flow_rule fr = flower_rule();
    unsigned tried;

    plcr_shut = true;
    assert(offer(base()) == 0);
    assert(flower_add(&dev, 1, &fr) == 0 && cdx_police_lookup(&flow) == 1);
    assert(work_count == 1 && work_queued[0]->delay == msecs_to_jiffies(1000));

    /* About once a second while anything is behind, each try one whole write
     * of each profile behind, refused at once while the channel stays shut. */
    tried = plcr_attempts;
    for (unsigned i = 0; i < 3; i++) {
        assert(run_queued_work() == 1);
        assert(work_count == 1 && work_queued[0]->delay == msecs_to_jiffies(1000));
    }
    assert(plcr_attempts == tried + 3 * 2);
    assert_port_boot(&eth4);
    assert_flow_profile_off(meter(1));

    /* The channel reopens: one run brings both to their records, and then
     * nothing is due. */
    plcr_shut = false;
    assert(run_queued_work() == 1);
    assert_meter(port_of(&eth4), 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert_meter(meter(1), 500000, CDX_POLICE_UNBOUNDED_KBITS, 64000, 2040 - 14);
    assert(!work_count);
    tried = plcr_attempts;
    assert(run_queued_work() == 0 && plcr_attempts == tried);

    assert(flower_del(&dev, 1) == 0);
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
}

/* ---- every write and read under the policer mutex ---------------------- */
static void locking(void)
{
    struct flow_rule fr = flower_rule();
    struct flow_stats s;

    /* The verbs, with every write landing. */
    assert(offer(base()) == 0);
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_STATS, &s) == 0);
    assert(flower_add(&dev, 1, &fr) == 0);
    assert(flower_cmd(&dev, 1, FLOW_CLS_STATS, &s) == 0);
    assert(!plcr_unlocked && !lockdep_misses);
    /* And with writes that do not, and the retries that follow. */
    plcr_lost = 1;
    assert(offer(base()) == 0);
    plcr_lost = 1;
    assert(flower_del(&dev, 1) == 0);
    run_queued_work();
    plcr_lost = 1;
    assert(mall_cmd(&dev, MALL_COOKIE, TC_CLSMATCHALL_DESTROY, NULL) == 0);
    run_queued_work();
    assert(!work_count);
    /* The writes and reads the owners and the retry make, and the records
     * they are built from, are all the mutex's. */
    assert(!plcr_unlocked && !lockdep_misses);
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*run)(void); } cases[] = {
        { "verbs", verbs },
        { "matchall_deferred", matchall_deferred },
        { "matchall_destroy_deferred", matchall_destroy_deferred },
        { "matchall_refused_destroy", matchall_refused_destroy },
        { "flower_destroy_deferred", flower_destroy_deferred },
        { "counters_unread", counters_unread },
        { "channel_shut", channel_shut },
        { "locking", locking },
    };

    assert(argc == 2);
    boot();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (strcmp(argv[1], cases[i].name))
            continue;
        cases[i].run();
        /* Nothing is left behind: no record, no retry due, no lock held. */
        assert(!allocations && !work_count && !spinlocks_held && !mutexes_held);
        printf("police %s: passed\n", cases[i].name);
        return 0;
    }
    fprintf(stderr, "no case %s\n", argv[1]);
    return 2;
}

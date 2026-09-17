/* Ingress police offload: what the action has to say before hardware is
 * touched, and the unit it is converted into.
 *
 * The conversion is the part worth pinning. tc counts bytes per second; the
 * FMD's byte mode counts Kbit/s and multiplies by 1000 on its way to bits. Get
 * that backwards and the meter is off by 8000x in a direction nobody notices
 * until a link is saturated -- which is exactly the confusion that had CMM
 * validating a packets-per-second range against a byte-mode profile.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define SUCCESS 0
#define FAILURE 1
#define EOPNOTSUPP 95
#define EINVAL 22

static u64 div_u64(u64 n, u32 d) { return n / d; }

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
struct flow_rule { struct flow_action action; };
struct netlink_ext_ack { const char *msg; };
#define NL_SET_ERR_MSG_MOD(e, m) do { if (e) (e)->msg = (m); } while (0)
static bool flow_offload_has_one_action(const struct flow_action *a)
{ return a->num_entries == 1; }

struct net_device { char name[16]; };
enum { TC_CLSMATCHALL_REPLACE, TC_CLSMATCHALL_DESTROY, TC_CLSMATCHALL_STATS };
struct tc_cls_matchall_offload {
    struct { struct netlink_ext_ack *extack; } common;
    int command;
    struct flow_rule *rule;
};

/* What reached the hardware layer, so a case can require the exact numbers
 * rather than merely that something was programmed. */
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

#include "police_production.inc"

static struct netlink_ext_ack ack;
static struct net_device dev = { .name = "eth4" };

/* Offer one police action and report what the driver made of it. */
static int offer(struct flow_action_entry act)
{
    struct flow_action_entry entries[1] = { act };
    struct flow_rule rule = { .action = { .num_entries = 1 } };
    memcpy(rule.action.entries, entries, sizeof(entries));
    struct tc_cls_matchall_offload f = {
        .common = { .extack = &ack }, .command = TC_CLSMATCHALL_REPLACE, .rule = &rule };
    memset(&hw, 0, sizeof(hw));
    ack.msg = NULL;
    return cdx_police_matchall(&dev, &f);
}

static struct flow_action_entry base(void)
{
    struct flow_action_entry a = { .id = FLOW_ACTION_POLICE };
    a.police.rate_bytes_ps = 62500000;      /* 500 Mbit/s */
    a.police.burst = 64000;
    a.police.exceed.act_id = FLOW_ACTION_DROP;
    a.police.notexceed.act_id = FLOW_ACTION_ACCEPT;
    return a;
}

int main(void)
{
    /* Bytes per second in, Kbit/s out: 62_500_000 B/s is 500 Mbit/s is
     * 500_000 Kbit/s. A factor-of-eight slip shows up here and nowhere else. */
    assert(offer(base()) == 0);
    assert(hw.set && hw.byte_mode);
    assert(hw.cir == 500000 && hw.pir == 500000);
    assert(hw.cbs == 64000 && hw.pbs == 64000);

    /* A peak rate is the profile's PIR; omitting it means the two are equal,
     * which is how RFC-2698 spells "one rate". */
    struct flow_action_entry a = base();
    a.police.peakrate_bytes_ps = 125000000; /* 1 Gbit/s */
    assert(offer(a) == 0 && hw.cir == 500000 && hw.pir == 1000000);

    /* Below the committed rate it is not a peak rate at all. */
    a = base(); a.police.peakrate_bytes_ps = 1000;
    assert(offer(a) == -EOPNOTSUPP);

    /* Packet mode is the profile's other unit, passed through as counted. */
    a = base(); a.police.rate_bytes_ps = 0; a.police.burst = 0;
    a.police.rate_pkt_ps = 20000; a.police.burst_pkt = 100;
    assert(offer(a) == 0 && !hw.byte_mode && hw.cir == 20000 && hw.cbs == 100);

    /* One unit or the other, never both, and never neither. */
    a = base(); a.police.rate_pkt_ps = 20000;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    a = base(); a.police.rate_bytes_ps = 0;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);

    /* A rate under 125 B/s rounds to zero Kbit/s. Programming that would be a
     * meter that drops everything, which is not what was asked for. */
    a = base(); a.police.rate_bytes_ps = 100;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);

    /* The profile drops red and passes green and yellow. Any other pairing is
     * refused rather than approximated. */
    a = base(); a.police.exceed.act_id = FLOW_ACTION_PIPE;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    a = base(); a.police.notexceed.act_id = FLOW_ACTION_DROP;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    a = base(); a.police.notexceed.act_id = FLOW_ACTION_PIPE;
    assert(offer(a) == 0);

    /* A moving-average rate is not something this hardware keeps. */
    a = base(); a.police.avrate = 1000;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);

    /* Only police, and only one of them. */
    a = base(); a.id = FLOW_ACTION_MANGLE;
    assert(offer(a) == -EOPNOTSUPP && !hw.set);
    {
        struct flow_rule rule = { .action = { .num_entries = 2 } };
        rule.action.entries[0] = base(); rule.action.entries[1] = base();
        struct tc_cls_matchall_offload f = {
            .common = { .extack = &ack }, .command = TC_CLSMATCHALL_REPLACE, .rule = &rule };
        memset(&hw, 0, sizeof(hw));
        assert(cdx_police_matchall(&dev, &f) == -EOPNOTSUPP && !hw.set);
    }

    /* A port with no rate limiter is a failure to report, not to ignore. */
    hw_fail = true;
    assert(offer(base()) == -EINVAL);
    hw_fail = false;

    /* Removing the filter puts the port back where it booted. */
    {
        struct tc_cls_matchall_offload f = {
            .common = { .extack = &ack }, .command = TC_CLSMATCHALL_DESTROY };
        memset(&hw, 0, sizeof(hw));
        assert(cdx_police_matchall(&dev, &f) == 0 && hw.cleared);
    }
    /* Statistics are refused until the per-colour counters are wired, rather
     * than reported as a filter that passed everything. */
    {
        struct tc_cls_matchall_offload f = {
            .common = { .extack = &ack }, .command = TC_CLSMATCHALL_STATS };
        assert(cdx_police_matchall(&dev, &f) == -EOPNOTSUPP);
    }

    puts("Police: unit conversion, rate pairing, action validation and teardown passed");
    return 0;
}

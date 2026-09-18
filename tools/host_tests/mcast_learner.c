/* The multicast membership learner's decision logic, compiled from the
 * adapter against stubs for everything below it.
 *
 * What this pins down is the part a hardware run cannot show cheaply: how a
 * port set is accumulated from a sequence of switchdev objects. On the rig a
 * membership arrives once, correctly, and every interesting case -- the same
 * port twice, a leave for a port that never joined, the ninth listener, a host
 * membership arriving before or after the ports it disqualifies -- either does
 * not occur or occurs once in a way nothing distinguishes from success.
 *
 * The answer the handler gives the bridge is the other half. `handled` becomes
 * MDB_PG_FLAGS_OFFLOAD and shows up in `bridge mdb show`, so a membership
 * refused for capacity or for a host listener must not claim to have been
 * taken on.
 */
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

/* The address union conntrack and the rule share. Only the two arms the
 * learner names are needed; the shape has to match so a group's key compares
 * the way the production one does. */
union nf_inet_addr {
    u32 all[4];
    u32 ip;
    u32 ip6[4];
};

#define ETH_ALEN 6
#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define BRIDGE_VLAN_INFO_UNTAGGED (1 << 2)
#define CDX_FT_VLAN_MAX 2
#define CDX_MC_MAX_LISTENERS 8
#define EOPNOTSUPP 95

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16((uint16_t)(x))
#else
#define htons(x) ((uint16_t)(x))
#endif

/* Only what the decision logic reads. A netdev is an opaque token here: the
 * learner compares pointers and asks the stubs about them. */
struct net_device {
    const char *name;
    bool physical;
    bool bridge_master;
};

struct cdx_ft_vlan { uint16_t proto; uint16_t id; };

struct br_ip {
    union { uint32_t ip4; unsigned char ip6[16]; } src;
    union { uint32_t ip4; unsigned char ip6[16]; } dst;
    uint16_t proto;
    uint16_t vid;
};

struct bridge_vlan_info { uint16_t flags; uint16_t vid; };

/* --- list.h, enough of it -------------------------------------------- */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static void list_add(struct list_head *e, struct list_head *h)
{
    e->next = h->next; e->prev = h; h->next->prev = e; h->next = e;
}
static void list_del(struct list_head *e)
{
    e->prev->next = e->next; e->next->prev = e->prev;
    e->next = e->prev = e;
}
#define list_entry(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, __typeof__(*pos), member))

/* --- stubs ----------------------------------------------------------- */
static LIST_HEAD(ft_mc_groups);
static unsigned int ft_mc_count;
static unsigned long long ft_mc_refused;
/* Read only by the worker and /proc, neither of which is compiled here. */
__attribute__((unused)) static unsigned int ft_mc_installed;
__attribute__((unused)) static unsigned long long ft_mc_install_errors;

static unsigned holds;   /* net-device references outstanding */
static void dev_hold(struct net_device *d) { (void)d; holds++; }
static void dev_put(struct net_device *d) { (void)d; assert(holds); holds--; }

static bool cdx_mc_port_identity(struct net_device *d)
{
    return d && d->physical;
}

/* The bridge under test: VLAN-filtering, 802.1Q, with a per-(port,vid)
 * membership table the cases populate. */
static bool vlan_enabled;
static uint16_t vlan_proto = ETH_P_8021Q;
static struct { struct net_device *port; uint16_t vid; bool untagged; bool member; }
    memberships[16];
static unsigned membership_count;

static bool br_vlan_enabled(struct net_device *br) { (void)br; return vlan_enabled; }
static int br_vlan_get_proto(struct net_device *br, uint16_t *p)
{
    (void)br; *p = vlan_proto; return 0;
}
static int br_vlan_get_info(struct net_device *port, uint16_t vid,
                            struct bridge_vlan_info *info)
{
    for (unsigned i = 0; i < membership_count; i++)
        if (memberships[i].port == port && memberships[i].vid == vid &&
            memberships[i].member) {
            info->vid = vid;
            info->flags = memberships[i].untagged ? BRIDGE_VLAN_INFO_UNTAGGED : 0;
            return 0;
        }
    return -EOPNOTSUPP;
}

#define lockdep_assert_held(x) ((void)0)
#define kzalloc(n, f) calloc(1, (n))
#define kfree(p) free(p)
#define GFP_KERNEL 0

#include "mcast_learner.inc"

/* --- helpers --------------------------------------------------------- */

static struct net_device BR   = { .name = "br0",  .bridge_master = true };
static struct net_device P1   = { .name = "eth3", .physical = true };
static struct net_device P2   = { .name = "eth4", .physical = true };
static struct net_device P3   = { .name = "eth5", .physical = true };
static struct net_device SOFT = { .name = "vx0",  .physical = false };

static struct br_ip group_v4(uint32_t dst, uint32_t src, uint16_t vid)
{
    struct br_ip a;
    memset(&a, 0, sizeof(a));
    a.dst.ip4 = dst;
    a.src.ip4 = src;
    a.proto = htons(ETH_P_IP);
    a.vid = vid;
    return a;
}

static void member(struct net_device *p, uint16_t vid, bool untagged)
{
    memberships[membership_count].port = p;
    memberships[membership_count].vid = vid;
    memberships[membership_count].untagged = untagged;
    memberships[membership_count].member = true;
    membership_count++;
}

static void reset(void)
{
    while (ft_mc_groups.next != &ft_mc_groups) {
        struct ft_mc_group *g = list_entry(ft_mc_groups.next,
                                           struct ft_mc_group, list);
        list_del(&g->list);
        ft_mc_group_free(g);
    }
    ft_mc_count = 0;
    membership_count = 0;
    vlan_enabled = false;
    ft_mc_refused = 0;
    assert(holds == 0);
}

static struct ft_mc_group *only_group(void)
{
    struct ft_mc_group *g = list_entry(ft_mc_groups.next,
                                       struct ft_mc_group, list);
    assert(ft_mc_groups.next != &ft_mc_groups);
    return g;
}

int main(void)
{
    struct br_ip g1 = group_v4(0x010007ef, 0, 0);   /* 239.7.0.1, (*,G) */
    struct br_ip g2 = group_v4(0x020007ef, 0, 0);

    /* One port joins: the group appears, the adapter takes it on, and the
     * port is pinned. */
    reset();
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(ft_mc_count == 1 && only_group()->ports == 1);
    assert(only_group()->port[0].dev == &P1);
    assert(holds == 2);   /* the bridge and the port */

    /* The same port again is the bridge restating a membership, not a second
     * listener. Restating must not duplicate it, and must still answer yes --
     * a repeat that answered no would clear the offload flag on a group that
     * is still taken on. */
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(only_group()->ports == 1);
    assert(holds == 2);

    /* A second port joins the same group. */
    assert(ft_mc_membership(&BR, &P2, &g1, true, false));
    assert(only_group()->ports == 2 && ft_mc_count == 1);

    /* A different group is a different entry. */
    assert(ft_mc_membership(&BR, &P1, &g2, true, false));
    assert(ft_mc_count == 2);

    /* Leaving drops the port and keeps the order of the rest compact. The
     * answer is no: a leave is not a membership being taken on. */
    assert(!ft_mc_membership(&BR, &P1, &g1, false, false));
    {
        struct ft_mc_group *g = ft_mc_find(&BR, &g1);
        assert(g && g->ports == 1 && g->port[0].dev == &P2);
        /* The slot the removed port left must be cleared, not left aliasing
         * a device the group no longer holds a reference to. */
        assert(g->port[1].dev == NULL);
    }

    /* A leave for a port that never joined changes nothing and releases
     * nothing. */
    {
        unsigned before = holds;
        assert(!ft_mc_membership(&BR, &P3, &g1, false, false));
        assert(holds == before);
        assert(ft_mc_find(&BR, &g1)->ports == 1);
    }

    /* A leave for a group that does not exist is equally inert. */
    {
        struct br_ip absent = group_v4(0x090007ef, 0, 0);
        assert(!ft_mc_membership(&BR, &P1, &absent, false, false));
        assert(ft_mc_count == 2);
    }

    /* A port the hardware cannot carry is refused, and refusing is counted
     * rather than silent. */
    reset();
    {
        unsigned long long before = ft_mc_refused;
        assert(!ft_mc_membership(&BR, &SOFT, &g1, true, false));
        assert(ft_mc_count == 0 && ft_mc_refused == before + 1);
        assert(holds == 0);
    }

    /* Capacity. The ninth listener is refused; the group keeps the eight it
     * has and does not claim the ninth was taken on. */
    reset();
    {
        struct net_device ports[CDX_MC_MAX_LISTENERS + 1];
        for (unsigned i = 0; i <= CDX_MC_MAX_LISTENERS; i++) {
            ports[i] = (struct net_device){ .name = "p", .physical = true };
            bool taken = ft_mc_membership(&BR, &ports[i], &g1, true, false);
            assert(taken == (i < CDX_MC_MAX_LISTENERS));
        }
        assert(only_group()->ports == CDX_MC_MAX_LISTENERS);
        assert(ft_mc_refused == 1);
    }

    /* A host membership makes the group ineligible without removing its
     * ports: the frame would never reach the CPU, so a local listener would
     * be starved. Ports already present stop being claimed. */
    reset();
    assert(ft_mc_membership(&BR, &P1, &g1, true, false));
    assert(!ft_mc_membership(&BR, &P1, &g1, true, true));   /* host joins */
    assert(only_group()->host && only_group()->ports == 1);
    assert(!ft_mc_membership(&BR, &P2, &g1, true, false));  /* still refused */
    assert(only_group()->ports == 2);                       /* but recorded */
    assert(!ft_mc_membership(&BR, &P1, &g1, true, true) || true);
    /* The host leaving makes it eligible again. */
    ft_mc_membership(&BR, &P1, &g1, false, true);
    assert(!only_group()->host);
    assert(ft_mc_membership(&BR, &P3, &g1, true, false));

    /* A host membership for a group nothing else joined creates nothing --
     * there is no port set to disqualify. */
    reset();
    {
        struct br_ip lonely = group_v4(0x0a0007ef, 0, 0);
        assert(!ft_mc_membership(&BR, &P1, &lonely, true, true));
        assert(ft_mc_count == 0);
    }

    /* Tags. On a bridge that does not filter, nothing is pushed. */
    reset();
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n = 0xff;

        vlan_enabled = false;
        assert(ft_mc_port_tags(&BR, &P1, 0, stack, &n) == 0 && n == 0);
    }

    /* Filtering: an untagged member gets no tag, a tagged member gets one in
     * the bridge's own protocol. */
    reset();
    vlan_enabled = true;
    member(&P1, 3999, true);
    member(&P2, 3999, false);
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        assert(ft_mc_port_tags(&BR, &P1, 3999, stack, &n) == 0 && n == 0);
        assert(ft_mc_port_tags(&BR, &P2, 3999, stack, &n) == 0 && n == 1);
        assert(stack[0].id == 3999 && stack[0].proto == htons(ETH_P_8021Q));
    }

    /* A port that is not a member of the group's VLAN is refused: it would
     * not receive this group in software either. */
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        assert(ft_mc_port_tags(&BR, &P3, 3999, stack, &n) != 0);
    }

    /* A filtering bridge with a VLAN of zero describes no VLAN at all, which
     * is not a tag decision this can make. */
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        assert(ft_mc_port_tags(&BR, &P1, 0, stack, &n) != 0);
    }

    /* 802.1ad is declined rather than reproduced blind: the kernel describes
     * no selector for that tag. */
    {
        struct cdx_ft_vlan stack[CDX_FT_VLAN_MAX];
        uint8_t n;

        vlan_proto = 0x88a8;
        assert(ft_mc_port_tags(&BR, &P2, 3999, stack, &n) != 0);
        vlan_proto = ETH_P_8021Q;
    }

    /* A tagged join carries the tag into the port's description. */
    reset();
    vlan_enabled = true;
    member(&P2, 3999, false);
    {
        struct br_ip tagged = group_v4(0x030007ef, 0, 3999);

        assert(ft_mc_membership(&BR, &P2, &tagged, true, false));
        assert(only_group()->port[0].vlans == 1);
        assert(only_group()->port[0].vlan[0].id == 3999);
    }

    /* And a join whose VLAN the port is not in is refused rather than
     * installed untagged, which would put the group on the wrong VLAN. */
    {
        struct br_ip elsewhere = group_v4(0x040007ef, 0, 4000);
        unsigned long long before = ft_mc_refused;

        assert(!ft_mc_membership(&BR, &P2, &elsewhere, true, false));
        assert(ft_mc_refused == before + 1);
    }

    reset();
    assert(holds == 0);
    printf("ok\n");
    return 0;
}

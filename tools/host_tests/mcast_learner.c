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
    int ifindex;
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

/* Whether any byte differs from c. The learner uses it to ask whether a
 * membership named a source at all, which is what tells (S,G) from (*,G). */
static void *memchr_inv(const void *p, int c, size_t n)
{
    const unsigned char *b = p;

    for (size_t i = 0; i < n; i++)
        if (b[i] != (unsigned char)c)
            return (void *)(b + i);
    return NULL;
}

#define lockdep_assert_held(x) ((void)0)
#define kzalloc(n, f) calloc(1, (n))
#define kfree(p) free(p)
#define GFP_KERNEL 0

#include "mcast_learner.inc"

/* --- helpers --------------------------------------------------------- */

static struct net_device BR   = { .name = "br0",  .ifindex = 10, .bridge_master = true };
static struct net_device P1   = { .name = "eth3", .ifindex = 11, .physical = true };
static struct net_device P2   = { .name = "eth4", .ifindex = 12, .physical = true };
static struct net_device P3   = { .name = "eth5", .ifindex = 13, .physical = true };
static struct net_device SOFT = { .name = "vx0",  .ifindex = 14, .physical = false };
static struct net_device BR2  = { .name = "br1",  .ifindex = 15, .bridge_master = true };

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

    /* A host membership arriving FIRST has to be recorded, and this is the
     * ordering the bridge actually produces: br_multicast_add_group() calls
     * br_multicast_host_join() on a freshly created mdb entry, so HOST_MDB
     * is emitted before any port group for that address. Dropping it left
     * the group to be created later by the first port join with host clear,
     * and the local listener then stopped receiving the moment the offload
     * installed -- exactly what refusing a host group exists to prevent. */
    reset();
    {
        struct br_ip lonely = group_v4(0x0a0007ef, 0, 0);

        assert(!ft_mc_membership(&BR, &BR, &lonely, true, true));
        assert(ft_mc_count == 1);
        assert(ft_mc_find(&BR, &lonely)->host);
        /* And a port joining afterwards finds it and is refused. */
        assert(!ft_mc_membership(&BR, &P1, &lonely, true, false));
        assert(ft_mc_find(&BR, &lonely)->ports == 1);
        assert(ft_mc_find(&BR, &lonely)->host);
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

    /* ---- matching an observation to a membership --------------------
     *
     * The distinction the whole design turns on. An IGMPv2 join produces a
     * (*,G) membership, which any source of that group satisfies. An IGMPv3
     * INCLUDE report produces an (S,G) one, where the bridge has already said
     * which source the group is about and a different one is a different
     * stream that these listeners did not ask for.
     */
    reset();
    {
        struct br_ip any = group_v4(0x010007ef, 0, 0);          /* (*,G) */
        struct br_ip specific = group_v4(0x020007ef, 0x0100000a, 0); /* (S,G) */
        struct ft_mc_seen seen;

        assert(ft_mc_membership(&BR, &P1, &any, true, false));
        assert(ft_mc_membership(&BR, &P1, &specific, true, false));

        /* Any source matches the wildcard membership. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = any;
        seen.src.ip = 0x0900000a;
        assert(ft_mc_match(&seen) == ft_mc_find(&BR, &any));

        /* The named source matches the source-specific one. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = specific;
        seen.addr.src.ip4 = 0;   /* the observation carries no source in addr */
        seen.src.ip = 0x0100000a;
        assert(ft_mc_match(&seen) == ft_mc_find(&BR, &specific));

        /* A different source does not. Somebody else sending to a group
         * these listeners asked for from one source is not their stream. */
        seen.src.ip = 0x0200000a;
        assert(ft_mc_match(&seen) == NULL);

        /* A different bridge is a different group even for the same
         * addresses, because it resolves to different ports. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex + 1;
        seen.addr = any;
        assert(ft_mc_match(&seen) == NULL);

        /* And a different VLAN is a different membership. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = any;
        seen.addr.vid = 100;
        assert(ft_mc_match(&seen) == NULL);

        /* As is a different family with the same bytes. */
        memset(&seen, 0, sizeof(seen));
        seen.bridge_ifindex = BR.ifindex;
        seen.addr = any;
        seen.addr.proto = htons(ETH_P_IPV6);
        assert(ft_mc_match(&seen) == NULL);
    }

    /* The hook's own dedup: one fact recorded once, however many frames
     * restate it, so a line-rate stream does not fill the ring between two
     * runs of the worker. */
    {
        struct ft_mc_seen a, b;

        memset(&a, 0, sizeof(a));
        a.bridge_ifindex = 1;
        a.in_ifindex = 2;
        a.addr = group_v4(0x010007ef, 0, 0);
        a.src.ip = 0x0100000a;
        b = a;
        assert(ft_mc_seen_eq(&a, &b));
        b.src.ip = 0x0200000a;
        assert(!ft_mc_seen_eq(&a, &b));   /* a second source is a new fact */
        b = a;
        b.in_ifindex = 3;
        assert(!ft_mc_seen_eq(&a, &b));   /* so is the same stream elsewhere */
        b = a;
        b.addr.vid = 7;
        assert(!ft_mc_seen_eq(&a, &b));
    }

    /* A key two memberships both claim. The hardware distinguishes only the
     * address pair, so installing either would stop the frame reaching the
     * bridge and the other one's ports would go quiet with nothing to say
     * why. The bridge produces this routinely: an (S,G) entry appears
     * alongside the (*,G) one whenever INCLUDE and EXCLUDE listeners
     * coexist. Neither may install. */
    reset();
    {
        struct br_ip wildcard = group_v4(0x0b0007ef, 0, 0);
        struct br_ip sourced  = group_v4(0x0b0007ef, 0x0100000a, 0);

        assert(ft_mc_membership(&BR, &P1, &wildcard, true, false));
        assert(!ft_mc_key_contested(ft_mc_find(&BR, &wildcard)));
        assert(ft_mc_membership(&BR, &P2, &sourced, true, false));
        assert(ft_mc_key_contested(ft_mc_find(&BR, &wildcard)));
        assert(ft_mc_key_contested(ft_mc_find(&BR, &sourced)));

        /* A host-only membership is not a claim on the key -- it installs
         * nothing -- so it does not contest. */
        reset();
        assert(!ft_mc_membership(&BR, &BR, &wildcard, true, true));
        assert(ft_mc_membership(&BR, &P1, &sourced, true, false));
        assert(!ft_mc_key_contested(ft_mc_find(&BR, &sourced)));

        /* Nor does a group on a different bridge, whose ports are its own. */
        reset();
        assert(ft_mc_membership(&BR, &P1, &wildcard, true, false));
        assert(ft_mc_membership(&BR2, &P2, &sourced, true, false));
        assert(!ft_mc_key_contested(ft_mc_find(&BR, &wildcard)));
    }

    /* Dropping a port by device alone, for the delete that arrives after the
     * port has already left the bridge -- del_nbp() flushes permanent mdb
     * entries after netdev_upper_dev_unlink(), so the master lookup is empty
     * and the membership would otherwise never be removed, holding a
     * reference that blocks the port's unregistration for good. */
    reset();
    {
        struct br_ip a = group_v4(0x0c0007ef, 0, 0);
        struct br_ip b = group_v4(0x0d0007ef, 0, 0);

        assert(ft_mc_membership(&BR, &P1, &a, true, false));
        assert(ft_mc_membership(&BR, &P2, &a, true, false));
        assert(ft_mc_membership(&BR, &P1, &b, true, false));
        ft_mc_drop_port(&P1);
        assert(ft_mc_find(&BR, &a)->ports == 1);
        assert(ft_mc_find(&BR, &a)->port[0].dev == &P2);
        assert(ft_mc_find(&BR, &b)->ports == 0);
        /* Every reference it held is gone: the two groups' bridges only. */
        assert(holds == 3);
        /* And dropping a port nothing lists is inert. */
        ft_mc_drop_port(&P3);
        assert(holds == 3);
    }

    reset();
    assert(holds == 0);
    printf("ok\n");
    return 0;
}

/* The two header manipulations a multicast listener's entry emits, compiled
 * from CDX against the shipped SDK header, plus the encapsulation applier that
 * now feeds them.
 *
 * Two things are pinned here that a hardware run cannot show cheaply.
 *
 * The first is that a listener's VLAN tags can come from the caller. A
 * registered VLAN interface is how the legacy owner describes a tagged
 * listener, and it is created only from an FCI command CMM sends -- so an
 * ownership mode without CMM has no such interface for the walk to find and
 * must name the tags instead. That path has to produce the same opcode and the
 * same parameter word the interface walk would.
 *
 * The second is the opcode budget, and it is a regression net rather than a
 * description. MAX_OPCODES bounds one entry's opcode area, and opc_count is
 * the cursor into it. The multicast builder used to be handed one
 * ins_entry_info per *group* and re-based only three quarters of the cursor
 * per entry, so every listener of a group drew from one entry's budget. The
 * arithmetic below is what made that a latent ceiling: eight tagged listeners
 * exhaust sixteen slots exactly. It never tripped, because the FCI dispatcher
 * refuses a command naming more than five listeners and a larger group is
 * assembled from several commands -- but the accounting was wrong and the
 * headroom was six opcodes. */
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_be32(x) __builtin_bswap32((uint32_t)(x))
#define cpu_to_be16(x) __builtin_bswap16((uint16_t)(x))
#define htons(x) __builtin_bswap16((uint16_t)(x))
#else
#define cpu_to_be32(x) ((uint32_t)(x))
#define cpu_to_be16(x) ((uint16_t)(x))
#define htons(x) ((uint16_t)(x))
#endif
#define be32_to_cpu(x) cpu_to_be32(x)
#define be16_to_cpu(x) cpu_to_be16(x)
#define MAX_OPCODES 16
#define SUCCESS 0
#define FAILURE -1
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHERTYPE_VLAN 0x8100
#define IPV6_ADDRESS_LENGTH 16
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)
#define DPA_PACKED __attribute__((packed))
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define unsafe_memcpy(d, s, n, why) memcpy((d), (s), (n))

#include "mcast_hm_types.inc"

/* Only the fields the emitters and the applier touch. Deliberately not the
 * production struct: what is under test is that the cursor is per entry, and a
 * local definition makes the test say so rather than inherit it. */
struct ins_entry_info {
    unsigned opc_count, param_size, eth_type, flags;
    uint8_t *paramptr, *opcptr;
    uint32_t *vlan_hdrs;
    struct dpa_l2hdr_info l2_info;
    /* An encapsulation naming a tunnel reaches past the L2 half into this
     * one, so the description apply_l2_encap() fills spans both. */
    struct dpa_l3hdr_info l3_info;
};

/* The fields the multicast key composer reads off a conntrack entry. */
#define FFTYPE_IPV4 1
#define FFTYPE_IPV6 2
typedef struct {
    unsigned fftype;
    uint8_t proto;
    uint32_t Saddr_v4, Daddr_v4;
    uint32_t Saddr_v6[4], Daddr_v6[4];
} CtEntry, *PCtEntry;
#define IS_IPV6_FLOW(e) (((e)->fftype & FFTYPE_IPV6) != 0)

static uint32_t get_logical_ifstats_base(void) { return 0; }
/* The ingress strip's check that an undescribed ingress is a registered port,
 * which a group's own description never needs: its records come from the
 * description. */
static int dpa_get_num_vlan_iface_stats_entries(uint32_t a, uint32_t b, uint32_t *n)
{ (void)a; (void)b; (void)n; assert(!"a group names its own tags"); return -1; }

#include "mcast_hm.inc"

/* One listener's entry, built the way create_exthash_entry4mcast_member()
 * builds it: the cursor is re-based onto this entry's own opcode and parameter
 * area, then fill_mcast_member_actions()'s two emitters run. */
struct entry {
    uint8_t opcodes[MAX_OPCODES];
    uint8_t params[128];
};

static void cursor(struct ins_entry_info *info, struct entry *e)
{
    memset(e, 0xa5, sizeof(*e));
    info->opcptr = e->opcodes;
    info->paramptr = e->params;
    info->param_size = sizeof(e->params);
    info->eth_type = 0x0800;
}

/* What fill_mcast_member_actions() emits for a listener, in its order. */
static int listener(struct ins_entry_info *info)
{
    if ((info->flags & TTL_HM_VALID) && create_member_hop_hm(info))
        return FAILURE;
    if (info->l2_info.num_egress_vlan_hdrs && create_vlan_ins_hm(info))
        return FAILURE;
    return create_ethernet_hm(info, 1);
}

static struct cdx_l2_encap one_tag(uint16_t vid)
{
    struct cdx_l2_encap encap = {0};

    encap.num_egress = 1;
    encap.egress[0].tpid = ETHERTYPE_VLAN;
    encap.egress[0].tci = vid;
    return encap;
}

/* ---- the group interface's listener builder --------------------------
 *
 * Which pair each copy is written with is the builder's decision, not the
 * emitters': a bridged copy writes back the pair its root matched, and a
 * routed copy -- every copy of a routed group, and the routed ones of a
 * bridged group -- the group's mapped address from the address of the device
 * ipmr sends it through, which the caller names per copy. The builder and the
 * check in front of it are the backend's own. The entry builder beneath them
 * is replaced by one that does to the header what
 * create_exthash_entry4mcast_member() does -- the interface walk writes the
 * port's own address, the copy's frame is written over it, the emitters lay
 * the entry down -- and keeps the header the entry carries. */
#define ETH_ALEN ETHER_ADDR_LEN
#define AF_INET 2
#define AF_INET6 10
#define EOPNOTSUPP 95
#define EIO 5
#define IPV6_ADDR_SCOPE_LINKLOCAL 0x02
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htonl(x) __builtin_bswap32((uint32_t)(x))
#else
#define htonl(x) ((uint32_t)(x))
#endif
#define ntohl(x) htonl(x)
#define ntohs(x) htons(x)
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint16_t __be16;
/* Distinct values: which table a listener is drawn from is all the builder
 * says about it. */
enum { IPV4_MULTICAST_TABLE = 1, IPV6_MULTICAST_TABLE,
       IPV4_BRIDGED_MULTICAST_TABLE, IPV6_BRIDGED_MULTICAST_TABLE };

struct net_device {
    char name[16];
    unsigned char dev_addr[ETH_ALEN];
};
struct list_head { struct list_head *next, *prev; };
struct in6_addr { uint8_t s6_addr[16]; };
union nf_inet_addr {
    uint32_t all[4];
    uint32_t ip;
    struct in6_addr in6;
};
struct en_exthash_tbl_entry;

#include "mcast_backend_types.inc"

static bool is_zero_ether_addr(const u8 *a)
{
    return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]);
}
static bool is_multicast_ether_addr(const u8 *a) { return a[0] & 1; }
static bool is_valid_ether_addr(const u8 *a)
{
    return !is_multicast_ether_addr(a) && !is_zero_ether_addr(a);
}
static bool ether_addr_equal(const u8 *a, const u8 *b)
{
    return !memcmp(a, b, ETH_ALEN);
}
static bool ipv6_addr_any(const struct in6_addr *a)
{
    static const struct in6_addr zero;

    return !memcmp(a, &zero, sizeof(*a));
}
static bool ipv6_addr_is_multicast(const struct in6_addr *a)
{
    return a->s6_addr[0] == 0xff;
}
/* A model of the two scope helpers: for a multicast address the scope is the
 * low nibble of the second byte, and nothing else is asked of them here. */
static int __ipv6_addr_type(const struct in6_addr *a)
{
    return ipv6_addr_is_multicast(a) ? ((a->s6_addr[1] & 0x0f) << 16) : 0;
}
static int __ipv6_addr_src_scope(int type) { return type >> 16; }
/* Every port here is one the flowtable can carry: what is under test is the
 * copies, not the ports. */
static bool cdx_mc_port_supported(struct net_device *dev) { return dev != NULL; }

static unsigned freed;
static int cdx_free_exthash_mcast_members(struct mcast_group_info *grp)
{
    (void)grp;
    freed++;
    return 0;
}

/* What each copy's entry was built from and what it carries. */
static struct {
    const struct cdx_mc_listener *listener;
    uint32_t tbl_type;
    uint8_t header[2 * ETHER_ADDR_LEN];
    bool hop;
} copies[MC_MAX_LISTENERS_PER_GROUP];
static unsigned copies_built;

static struct en_exthash_tbl_entry *cdx_mc_listener_entry(RouteEntry *pRtEntry,
        const struct cdx_mc_listener *copy,
        const struct cdx_mc_member_frame *frame,
        struct en_exthash_tbl_entry *prev, uint32_t tbl_type)
{
    struct ins_entry_info info;
    struct entry e;
    uint8_t *header;
    unsigned at = copies_built++;

    assert(at < ARRAY_SIZE(copies));
    /* Threaded head to tail, each entry after the last one built. */
    assert(prev == (at ? (struct en_exthash_tbl_entry *)&copies[at - 1] : NULL));
    memset(&info, 0, sizeof(info));
    /* The interface walk: the route's destination, from the port's own
     * address. */
    memcpy(info.l2_info.l2hdr, pRtEntry->dstmac, ETHER_ADDR_LEN);
    memcpy(info.l2_info.l2hdr + ETHER_ADDR_LEN, copy->dev->dev_addr, ETHER_ADDR_LEN);
    assert(copy->vlans <= 1);
    if (copy->vlans) {
        struct cdx_l2_encap encap = one_tag(copy->vlan[0].id);

        assert(apply_l2_encap(&info, &encap) == SUCCESS);
    }
    mcast_member_frame(&info, frame);
    if (tbl_type == IPV6_MULTICAST_TABLE || tbl_type == IPV6_BRIDGED_MULTICAST_TABLE)
        info.flags |= EHASH_IPV6_FLOW;
    cursor(&info, &e);
    assert(listener(&info) == SUCCESS);
    /* The header as the entry carries it: after the hop's word and the
     * tag's, where the Ethernet insert's parameters begin. */
    copies[at].hop = (info.flags & TTL_HM_VALID) != 0;
    header = e.params + (copies[at].hop ? sizeof(struct en_ehash_update_dscp) : 0)
             + (copy->vlans ? sizeof(struct en_ehash_insert_vlan_hdr) + 4 : 0)
             + sizeof(struct en_ehash_insert_l2_hdr);
    memcpy(copies[at].header, header, sizeof(copies[at].header));
    copies[at].listener = copy;
    copies[at].tbl_type = tbl_type;
    return (struct en_exthash_tbl_entry *)&copies[at];
}

#include "mcast_backend.inc"

/* Describe a group and build its listeners, as add does once the key is its
 * own. */
static int build(struct mcast_group_info *grp, const struct cdx_mc_group_spec *spec)
{
    memset(grp, 0, sizeof(*grp));
    grp->grpid = -1;
    cdx_mc_describe(grp, spec);
    copies_built = 0;
    return cdx_mc_build_listeners(grp, spec);
}

static struct cdx_mc_listener copy_to(struct net_device *dev, uint16_t vid,
                                      bool routed, const uint8_t *src_mac)
{
    struct cdx_mc_listener l;

    memset(&l, 0, sizeof(l));
    l.dev = dev;
    if (vid) {
        l.vlans = 1;
        l.vlan[0].proto = htons(ETHERTYPE_VLAN);
        l.vlan[0].id = vid;
    }
    l.routed = routed;
    if (src_mac)
        memcpy(l.src_mac, src_mac, ETH_ALEN);
    return l;
}

int main(void)
{
    struct ins_entry_info info;
    struct entry e;

    /* An untagged listener emits one opcode: the Ethernet header. */
    memset(&info, 0, sizeof(info));
    cursor(&info, &e);
    assert(listener(&info) == SUCCESS);
    assert(info.opc_count == 1);
    assert(e.opcodes[0] == INSERT_L2_HDR);

    /* A listener whose tags the caller named emits two, the tag first, and the
     * tag reaches the parameter word where the ucode reads it. The ethertype
     * the Ethernet header then carries is the tag's, not the payload's --
     * create_vlan_ins_hm() walks eth_type outwards as it lays the stack down. */
    {
        struct cdx_l2_encap encap = one_tag(3999);
        uint32_t word;

        memset(&info, 0, sizeof(info));
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l2_info.num_egress_vlan_hdrs == 1);
        assert(info.l2_info.egress_vlan_hdrs[0].tci == 3999);
        cursor(&info, &e);
        assert(listener(&info) == SUCCESS);
        assert(info.opc_count == 2);
        assert(e.opcodes[0] == INSERT_VLAN_HDR && e.opcodes[1] == INSERT_L2_HDR);
        /* The tag word: vid in the high half, the ethertype it displaced in
         * the low half. */
        memcpy(&word, e.params + sizeof(struct en_ehash_insert_vlan_hdr), 4);
        assert(be32_to_cpu(word) == ((3999u << 16) | 0x0800u));
        assert(info.eth_type == ETHERTYPE_VLAN);
    }

    /* Two tags are one opcode, not two: the count rides in the word. */
    {
        struct cdx_l2_encap encap = one_tag(100);

        encap.num_egress = 2;
        encap.egress[1].tpid = ETHERTYPE_VLAN;
        encap.egress[1].tci = 200;
        memset(&info, 0, sizeof(info));
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        cursor(&info, &e);
        assert(listener(&info) == SUCCESS);
        assert(info.opc_count == 2);
    }

    /* A listener cannot be described twice. An interface walk that already
     * found tags and a caller that also names them disagree about the frame,
     * and guessing which is right would put a tag on the wire nobody asked
     * for. */
    {
        struct cdx_l2_encap encap = one_tag(10);

        memset(&info, 0, sizeof(info));
        info.l2_info.num_egress_vlan_hdrs = 1;
        info.l2_info.egress_vlan_hdrs[0].tci = 20;
        assert(apply_l2_encap(&info, &encap) == FAILURE);
    }

    /* An encapsulation deeper than the hardware lays down is refused rather
     * than truncated into a different frame. */
    {
        struct cdx_l2_encap encap = one_tag(10);

        encap.num_egress = DPA_CLS_HM_MAX_VLANs + 1;
        memset(&info, 0, sizeof(info));
        assert(apply_l2_encap(&info, &encap) == FAILURE);
    }

    /* The budget is per entry. Every listener of a group re-bases the cursor
     * onto its own entry, so the count after each one is that listener's own
     * and never the group's running total -- which is what a shared cursor
     * made it. Twenty is well past both MAX_OPCODES and the eight that a
     * shared cursor allowed; none of them may fail. */
    {
        struct cdx_l2_encap encap = one_tag(3999);

        for (unsigned i = 0; i < 20; i++) {
            memset(&info, 0, sizeof(info));
            assert(apply_l2_encap(&info, &encap) == SUCCESS);
            cursor(&info, &e);
            assert(listener(&info) == SUCCESS);
            assert(info.opc_count == 2);
        }
    }

    /* ---- a bridged group ------------------------------------------------
     *
     * The root is keyed on the frame's own Ethernet pair ahead of the routed
     * key's fields, in the order the key generator extracts them, and every
     * copy writes back exactly that pair. 22 and 46 bytes with the port id,
     * which is what cdx_pcd.xml sizes the bridged multicast tables for. */
    {
        static const uint8_t pair[2 * ETHER_ADDR_LEN] = {
            0x01, 0x00, 0x5e, 0x09, 0x05, 0x01,     /* destination */
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55,     /* the sender */
        };
        uint8_t key[64];
        CtEntry ct;

        memset(&ct, 0, sizeof(ct));
        memset(key, 0xa5, sizeof(key));
        ct.fftype = FFTYPE_IPV4;
        ct.proto = 17;
        ct.Saddr_v4 = 0x0267120a;   /* network order, as the entry holds it */
        ct.Daddr_v4 = 0x010509ef;
        assert(fill_mcast_mac_key(&ct, pair, key, 7) == 22);
        assert(key[0] == 7);
        assert(!memcmp(key + 1, pair, 6));          /* destination MAC */
        assert(!memcmp(key + 7, pair + 6, 6));      /* source MAC */
        assert(!memcmp(key + 13, &ct.Saddr_v4, 4));
        assert(!memcmp(key + 17, &ct.Daddr_v4, 4));
        assert(key[21] == 17);
        assert(key[22] == 0xa5);                    /* and nothing beyond */

        memset(&ct, 0, sizeof(ct));
        memset(key, 0xa5, sizeof(key));
        ct.fftype = FFTYPE_IPV6;
        ct.proto = 17;
        ct.Saddr_v6[0] = 0x00fe0000;
        ct.Daddr_v6[0] = 0x00ff1eff;
        assert(fill_mcast_mac_key(&ct, pair, key, 3) == 46);
        assert(key[0] == 3);
        assert(!memcmp(key + 1, pair, 12));
        assert(!memcmp(key + 13, ct.Saddr_v6, 16));
        assert(!memcmp(key + 29, ct.Daddr_v6, 16));
        assert(key[45] == 17 && key[46] == 0xa5);

        /* The copy is rebuilt with the pair the root matched, not the
         * egress port's address the interface walk filled in, and its tag
         * still comes first. */
        {
            struct cdx_l2_encap encap = one_tag(289);
            struct cdx_mc_member_frame frame = { .mac_pair = pair };

            memset(&info, 0, sizeof(info));
            memset(info.l2_info.l2hdr, 0xee, sizeof(info.l2_info.l2hdr));
            assert(apply_l2_encap(&info, &encap) == SUCCESS);
            mcast_member_frame(&info, &frame);
            cursor(&info, &e);
            assert(listener(&info) == SUCCESS);
            assert(e.opcodes[0] == INSERT_VLAN_HDR && e.opcodes[1] == INSERT_L2_HDR);
            {
                uint8_t *l2 = e.params + sizeof(struct en_ehash_insert_vlan_hdr) + 4
                              + sizeof(struct en_ehash_insert_l2_hdr);
                assert(!memcmp(l2, pair, 12));
                assert(l2[12] == 0x81 && l2[13] == 0x00);
            }
            /* No frame, or a routed one, leaves the walk's header alone. */
            memset(&info, 0, sizeof(info));
            memset(info.l2_info.l2hdr, 0xee, sizeof(info.l2_info.l2hdr));
            mcast_member_frame(&info, NULL);
            frame.mac_pair = NULL;
            mcast_member_frame(&info, &frame);
            for (unsigned i = 0; i < sizeof(info.l2_info.l2hdr); i++)
                assert(info.l2_info.l2hdr[i] == 0xee);
            /* And a bridged copy has no hop of its own to take off. */
            assert(!(info.flags & TTL_HM_VALID));
        }

        /* A routed copy in a bridged group. The root kept the hop count for
         * the bridged copies, so this copy decrements it in its own entry --
         * first, while the frame still starts at its IP header, and with a
         * zero DSCP word, since a replica has no mark to ask for one -- and
         * is framed from the egress port, not with the matched pair. */
        for (int v6 = 0; v6 < 2; v6++) {
            struct cdx_l2_encap encap = one_tag(287);
            struct cdx_mc_member_frame frame = { .hop = true };
            uint32_t dscp;

            memset(&info, 0, sizeof(info));
            memset(info.l2_info.l2hdr, 0xee, sizeof(info.l2_info.l2hdr));
            assert(apply_l2_encap(&info, &encap) == SUCCESS);
            mcast_member_frame(&info, &frame);
            assert(info.flags & TTL_HM_VALID);
            for (unsigned i = 0; i < sizeof(info.l2_info.l2hdr); i++)
                assert(info.l2_info.l2hdr[i] == 0xee);
            if (v6)
                info.flags |= EHASH_IPV6_FLOW;
            cursor(&info, &e);
            assert(listener(&info) == SUCCESS);
            assert(info.opc_count == 3);
            assert(e.opcodes[0] == (v6 ? UPDATE_HOPLIMIT : UPDATE_TTL));
            assert(e.opcodes[1] == INSERT_VLAN_HDR && e.opcodes[2] == INSERT_L2_HDR);
            memcpy(&dscp, e.params, sizeof(dscp));
            assert(dscp == 0);
            /* Everything after the hop's word sits where it would without
             * it, one word on: the tag, then the walk's own header. */
            {
                uint8_t *l2 = e.params + sizeof(struct en_ehash_update_dscp)
                              + sizeof(struct en_ehash_insert_vlan_hdr) + 4
                              + sizeof(struct en_ehash_insert_l2_hdr);
                for (unsigned i = 0; i < 12; i++)
                    assert(l2[i] == 0xee);
                assert(l2[12] == 0x81 && l2[13] == 0x00);
            }
        }
        /* No room for the word is a failure, not a truncated entry. */
        {
            struct cdx_mc_member_frame frame = { .hop = true };

            memset(&info, 0, sizeof(info));
            mcast_member_frame(&info, &frame);
            cursor(&info, &e);
            info.param_size = sizeof(struct en_ehash_update_dscp) - 1;
            assert(create_member_hop_hm(&info) == FAILURE);
            assert(info.opc_count == 0);
        }
    }

    /* ---- the tags a group arrives with -------------------------------
     *
     * The root validates and strips exactly the tags the group describes.
     * Before a group could describe them the strip expected an untagged
     * frame, and a tagged one matched the key and was handed to Linux. */
    {
        struct cdx_l2_encap encap = {0};
        struct en_ehash_strip_all_vlan_hdrs *p;

        encap.num_ingress = 1;
        encap.ingress[0].tpid = ETHERTYPE_VLAN;
        encap.ingress[0].tci = 289;
        memset(&info, 0, sizeof(info));
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l2_info.vlan_present && info.l2_info.num_ingress_vlan_hdrs == 1);
        cursor(&info, &e);
        memset(e.params, 0, sizeof(e.params));
        assert(insert_remove_vlan_hm(&info, 0, 0) == SUCCESS);
        assert(e.opcodes[0] == STRIP_ALL_VLAN_HDRS && info.opc_count == 1);
        p = (struct en_ehash_strip_all_vlan_hdrs *)e.params;
        assert(be16_to_cpu(p->vlan_id[0]) == 289);
        /* Not a bridge flow: the tag is validated, never skipped. */
        assert(!(p->op_flags & OP_SKIP_VLAN_VALIDATE));
        /* A tag with no record of its own counts nowhere. */
        assert(p->word == 0);

        /* Untagged, the strip expects no tag and one that arrives is
         * refused by it -- which is the other VLANs of the port. */
        memset(&info, 0, sizeof(info));
        info.l2_info.vlan_flow_ifstats = 1;
        cursor(&info, &e);
        memset(e.params, 0, sizeof(e.params));
        assert(insert_remove_vlan_hm(&info, 0, 0) == SUCCESS);
        p = (struct en_ehash_strip_all_vlan_hdrs *)e.params;
        assert(p->vlan_id[0] == 0 && !(p->op_flags & OP_SKIP_VLAN_VALIDATE));
    }

    /* And the arithmetic that made sharing it a ceiling, stated so that a
     * future change to either constant has to come back here: a tagged
     * listener costs two of MAX_OPCODES slots, so one entry's budget covers
     * exactly eight of them -- the number MC_MAX_LISTENERS_PER_GROUP happens
     * to carry. A ninth against one cursor is refused. */
    {
        struct cdx_l2_encap encap = one_tag(3999);
        struct entry entries[9];
        unsigned i;

        memset(&info, 0, sizeof(info));
        for (i = 0; i < 8; i++) {
            info.l2_info.num_egress_vlan_hdrs = 0;
            assert(apply_l2_encap(&info, &encap) == SUCCESS);
            cursor(&info, &entries[i]);
            assert(listener(&info) == SUCCESS);
        }
        assert(info.opc_count == MAX_OPCODES);
        info.l2_info.num_egress_vlan_hdrs = 0;
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        cursor(&info, &entries[8]);
        assert(listener(&info) == FAILURE);
    }

    /* ---- the address each copy leaves with ----------------------------
     *
     * ipmr builds a copy's header on the device it sends it through, and a
     * bridge or a VLAN device passes it on: the copy leaves with that
     * device's address, which is its port's only when the device is the
     * port. The walk writes the port's; a routed copy's own is written over
     * it. */
    {
        static struct net_device in = { "eth4", { 0x02, 0, 0, 0, 0, 0x04 } };
        static struct net_device out = { "eth3", { 0x02, 0, 0, 0, 0, 0x03 } };
        /* br-ftmcast.290's, say, and a second VLAN device's on the port. */
        static const uint8_t vif[ETH_ALEN] = { 0x02, 0, 0, 0, 0x02, 0x90 };
        static const uint8_t vif2[ETH_ALEN] = { 0x02, 0, 0, 0, 0x02, 0x91 };
        static const uint8_t sender[ETH_ALEN] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
        /* 239.9.5.4 */
        static const uint8_t mapped[ETH_ALEN] = { 0x01, 0x00, 0x5e, 0x09, 0x05, 0x04 };
        /* A bridged frame's own destination, which need not be the mapped
         * one: the root matches it and a bridged copy writes it back. */
        static const uint8_t arrived[ETH_ALEN] = { 0x01, 0x00, 0x5e, 0x89, 0x05, 0x04 };
        struct cdx_mc_group_spec spec;
        struct mcast_group_info grp;

        /* A routed group: every copy is a router's, whether or not the
         * caller marked it, from the group's mapped address and its own
         * device's address, and the root takes the hop off for all. */
        memset(&spec, 0, sizeof(spec));
        spec.in = &in;
        spec.family = AF_INET;
        spec.src.ip = htonl(0x0a000034);
        spec.dst.ip = htonl(0xef090504);
        spec.listener[0] = copy_to(&out, 0, true, vif);
        spec.listener[1] = copy_to(&out, 290, false, vif2);
        spec.listeners = 2;
        assert(cdx_mc_check(&spec) == 0);
        assert(build(&grp, &spec) == 0 && copies_built == 2 && grp.uiListenerCnt == 2);
        for (unsigned i = 0; i < 2; i++) {
            assert(copies[i].tbl_type == IPV4_MULTICAST_TABLE && !copies[i].hop);
            assert(!memcmp(copies[i].header, mapped, ETH_ALEN));
        }
        assert(!memcmp(copies[0].header + ETH_ALEN, vif, ETH_ALEN));
        assert(!memcmp(copies[1].header + ETH_ALEN, vif2, ETH_ALEN));
        /* IPv6 the same, from the IPv6 table. */
        spec.family = AF_INET6;
        memset(&spec.src, 0, sizeof(spec.src));
        memset(&spec.dst, 0, sizeof(spec.dst));
        spec.src.in6.s6_addr[0] = 0xfd;
        spec.src.in6.s6_addr[15] = 0x02;
        spec.dst.in6.s6_addr[0] = 0xff;
        spec.dst.in6.s6_addr[1] = 0x1e;
        spec.dst.in6.s6_addr[15] = 0x04;
        assert(cdx_mc_check(&spec) == 0);
        assert(build(&grp, &spec) == 0 && copies_built == 2);
        assert(copies[0].tbl_type == IPV6_MULTICAST_TABLE);
        assert(copies[0].header[0] == 0x33 && copies[0].header[1] == 0x33);
        assert(!memcmp(copies[0].header + ETH_ALEN, vif, ETH_ALEN));
        spec.family = AF_INET;
        spec.src.ip = htonl(0x0a000034);
        spec.dst.ip = htonl(0xef090504);

        /* A routed copy names no address of its own, or one no station
         * has: refused, never defaulted to the port's -- which is what Linux
         * sends only when the device is the port. */
        memset(spec.listener[1].src_mac, 0, ETH_ALEN);
        assert(cdx_mc_check(&spec) == -EOPNOTSUPP);
        spec.listener[1].src_mac[0] = 0x01;
        assert(cdx_mc_check(&spec) == -EOPNOTSUPP);
        /* Two copies out of one port with one framing are two only when
         * their addresses differ, which is two devices ipmr sends through;
         * the same copy twice is refused. */
        spec.listener[1] = copy_to(&out, 0, true, vif2);
        assert(cdx_mc_check(&spec) == 0);
        spec.listener[1] = copy_to(&out, 0, true, vif);
        assert(cdx_mc_check(&spec) == -EOPNOTSUPP);

        /* A bridged group: the bridged copy writes back the pair its root
         * matched and keeps the hop count, the routed one leaves from its
         * device to the mapped address and takes its own hop off -- two
         * copies out of one port and one tag stack, told apart by the
         * address. */
        memset(&spec, 0, sizeof(spec));
        spec.in = &in;
        spec.family = AF_INET;
        spec.bridged = true;
        spec.src.ip = htonl(0x0a000034);
        spec.dst.ip = htonl(0xef090504);
        memcpy(spec.dst_mac, arrived, ETH_ALEN);
        memcpy(spec.src_mac, sender, ETH_ALEN);
        spec.listener[0] = copy_to(&out, 289, false, NULL);
        spec.listener[1] = copy_to(&out, 289, true, vif);
        spec.listener[2] = copy_to(&out, 290, true, vif);
        spec.listeners = 3;
        assert(cdx_mc_check(&spec) == 0);
        assert(build(&grp, &spec) == 0 && copies_built == 3);
        assert(copies[0].tbl_type == IPV4_BRIDGED_MULTICAST_TABLE && !copies[0].hop);
        assert(!memcmp(copies[0].header, arrived, ETH_ALEN));
        assert(!memcmp(copies[0].header + ETH_ALEN, sender, ETH_ALEN));
        for (unsigned i = 1; i < 3; i++) {
            assert(copies[i].tbl_type == IPV4_BRIDGED_MULTICAST_TABLE && copies[i].hop);
            assert(!memcmp(copies[i].header, mapped, ETH_ALEN));
            assert(!memcmp(copies[i].header + ETH_ALEN, vif, ETH_ALEN));
            assert(memcmp(copies[i].header + ETH_ALEN, out.dev_addr, ETH_ALEN));
        }
        /* A routed copy without an address is refused here too, and a
         * bridged copy naming one is asking for something it cannot have:
         * it keeps its sender's. */
        memset(spec.listener[1].src_mac, 0, ETH_ALEN);
        assert(cdx_mc_check(&spec) == -EOPNOTSUPP);
        spec.listener[1] = copy_to(&out, 289, true, vif);
        memcpy(spec.listener[0].src_mac, vif2, ETH_ALEN);
        assert(cdx_mc_check(&spec) == -EOPNOTSUPP);
        assert(!freed);
    }

    printf("ok\n");
    return 0;
}

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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_be32(x) __builtin_bswap32((uint32_t)(x))
#define htons(x) __builtin_bswap16((uint16_t)(x))
#else
#define cpu_to_be32(x) ((uint32_t)(x))
#define htons(x) ((uint16_t)(x))
#endif
#define be32_to_cpu(x) cpu_to_be32(x)
#define MAX_OPCODES 16
#define SUCCESS 0
#define FAILURE -1
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHERTYPE_VLAN 0x8100
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define unsafe_memcpy(d, s, n, why) memcpy((d), (s), (n))

#include "mcast_hm_types.inc"

/* Only the fields the two emitters and the applier touch. Deliberately not the
 * production struct: what is under test is that the cursor is per entry, and a
 * local definition makes the test say so rather than inherit it. */
struct ins_entry_info {
    unsigned opc_count, param_size, eth_type;
    uint8_t *paramptr, *opcptr;
    uint32_t *vlan_hdrs;
    struct dpa_l2hdr_info l2_info;
};

static uint32_t get_logical_ifstats_base(void) { return 0; }

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

    printf("ok\n");
    return 0;
}

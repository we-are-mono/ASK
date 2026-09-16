/* The two PPPoE header manipulations and the description they read, compiled
 * from CDX against the shipped SDK header. What this pins down is the one
 * thing a hardware run cannot show cheaply: that a session described by a flow
 * emits a null statistics pointer rather than aiming the ucode's counter
 * update at the unallocated offset zero, which belongs to another interface. */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_be32(x) __builtin_bswap32((uint32_t)(x))
#else
#define cpu_to_be32(x) ((uint32_t)(x))
#endif
#define be32_to_cpu(x) cpu_to_be32(x)
#define MAX_OPCODES 16
#define SUCCESS 0
#define FAILURE -1
#define RX_IFSTATS 0
#define IF_TYPE_PPPOE 4
#define ETHERTYPE_PPPOE 0x8864
#define ETHER_ADDR_LEN 6
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

#include "pppoe_hm_types.inc"

struct ins_entry_info {
    unsigned opc_count, param_size, eth_type;
    uint8_t *paramptr, *opcptr;
    struct dpa_l2hdr_info l2_info;
};

static uint32_t stats_base;
static uint8_t stats_offset;
static int fail_stats;
static unsigned stats_lookups;
static uint32_t get_logical_ifstats_base(void) { return stats_base; }
static int dpa_get_iface_stats_entries(unsigned index, unsigned underlying,
                                       uint8_t *offset, unsigned dir, unsigned type)
{
    stats_lookups++;
    /* The interface index is the one the caller resolved; a flow-described
     * session must never get this far, because on a physical port this lookup
     * fails and takes the whole flow with it. */
    assert(index == 7 && underlying == 0 && dir == RX_IFSTATS && type == IF_TYPE_PPPOE);
    if (fail_stats) return FAILURE;
    *offset = stats_offset;
    return SUCCESS;
}

static char display_log[256];
static void printk(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t used = strlen(display_log);
    vsnprintf(display_log + used, sizeof(display_log) - used, fmt, ap);
    va_end(ap);
}

#include "pppoe_hm.inc"

/* The session id reaches the L2 description in host order and the opcode word
 * is built from it before the whole word is converted, so the id lands in the
 * low half of a big-endian word. The legacy control path arrives at the same
 * place by applying htons() twice, which is why this is worth stating. */
static void expect_insert(const uint8_t *bytes, uint32_t pointer, uint16_t sid)
{
    const uint8_t expected[] = {
        pointer >> 24, pointer >> 16, pointer >> 8, pointer,
        0x11, 0x00, sid >> 8, sid,
    };

    assert(memcmp(bytes, expected, sizeof(expected)) == 0);
}

int main(void)
{
    const uint32_t bases[] = {0, 0x10, 0x12340, 0xabcdef, 0xfffff0};
    const uint8_t offsets[] = {0, 1, 3, 127};
    const uint16_t sids[] = {1, 0x1234, 0xabcd, 0xffff};
    const uint8_t ac[ETHER_ADDR_LEN] = {2, 0xac, 0, 0, 0, 1};

    assert(sizeof(struct en_ehash_insert_pppoe_hdr) == 8);
    assert(sizeof(struct en_ehash_strip_pppoe_hdr) == 4);

    /* A session named by an interface keeps the pointer it was allocated. */
    for (unsigned b = 0; b < sizeof(bases) / sizeof(bases[0]); b++)
    for (unsigned o = 0; o < sizeof(offsets); o++)
    for (unsigned s = 0; s < sizeof(sids) / sizeof(sids[0]); s++) {
        uint8_t bytes[10], opcode[2] = {0xa5, 0xa5};
        struct ins_entry_info info = {
            .opc_count = 2, .param_size = 8,
            .paramptr = bytes + 1, .opcptr = opcode,
            .eth_type = 0x0800,
        };

        memset(bytes, 0xa5, sizeof(bytes));
        stats_base = bases[b];
        /* The timestamped slot the offset indexes is 24 bytes wide, and the
         * offset's top bit is a flag rather than part of the index. */
        stats_offset = offsets[o] | 0x80;
        info.l2_info.pppoe_sess_id = sids[s];
        info.l2_info.pppoe_stats_offset = stats_offset;
        assert(create_pppoe_ins_hm(&info) == SUCCESS);
        expect_insert(bytes + 1, stats_base + offsets[o] * 24, sids[s]);
        assert(bytes[0] == 0xa5 && bytes[9] == 0xa5 && opcode[1] == 0xa5);
        assert(opcode[0] == INSERT_PPPoE_HDR && info.opc_count == 3);
        assert(info.paramptr == bytes + 9 && info.param_size == 0);
        /* PPPoE is the outermost header once inserted, so whatever Ethernet
         * type is written afterwards has to be the session one. */
        assert(info.eth_type == ETHERTYPE_PPPOE);

        /* A flow-described session names its own record in the description,
         * and the pointer is built from that rather than from a registered
         * interface -- the same arithmetic, a different source. */
        memset(bytes, 0xa5, sizeof(bytes));
        info = (struct ins_entry_info){ .opc_count = 2, .param_size = 8,
                                        .paramptr = bytes + 1, .opcptr = opcode,
                                        .eth_type = 0x0800 };
        opcode[0] = opcode[1] = 0xa5;
        info.l2_info.pppoe_sess_id = sids[s];
        info.l2_info.pppoe_stats_offset = stats_offset;
        info.l2_info.pppoe_flow_ifstats = 1;
        assert(create_pppoe_ins_hm(&info) == SUCCESS);
        expect_insert(bytes + 1, stats_base + offsets[o] * 24, sids[s]);
        assert(opcode[0] == INSERT_PPPoE_HDR && info.eth_type == ETHERTYPE_PPPOE);

        /* And a session with no record names index zero, which is never a
         * record: every real one has STATS_WITH_TS set. The opcode then
         * carries the null pointer the statistics-disabled build writes,
         * rather than aiming at whoever owns record zero. */
        memset(bytes, 0xa5, sizeof(bytes));
        info = (struct ins_entry_info){ .opc_count = 2, .param_size = 8,
                                        .paramptr = bytes + 1, .opcptr = opcode,
                                        .eth_type = 0x0800 };
        opcode[0] = opcode[1] = 0xa5;
        info.l2_info.pppoe_sess_id = sids[s];
        info.l2_info.pppoe_stats_offset = 0;
        info.l2_info.pppoe_flow_ifstats = 1;
        assert(create_pppoe_ins_hm(&info) == SUCCESS);
        expect_insert(bytes + 1, 0, sids[s]);
        assert(opcode[0] == INSERT_PPPoE_HDR && info.eth_type == ETHERTYPE_PPPOE);

        display_log[0] = 0;
        assert(display_pppoehdr_insert_opc(bytes + 1) == bytes + 9);
    }

    /* The strip, both ways round. Its only parameter is the pointer, which is
     * exactly why a flow-described session must not be allowed to compute
     * one: there is no interface to look the offset up on, and the lookup
     * itself fails on a physical port. */
    for (unsigned o = 0; o < sizeof(offsets); o++) {
        uint8_t bytes[6], opcode[2] = {0xa5, 0xa5};
        struct ins_entry_info info = {
            .opc_count = 2, .param_size = 4,
            .paramptr = bytes + 1, .opcptr = opcode,
        };
        uint32_t pointer;

        memset(bytes, 0xa5, sizeof(bytes));
        stats_base = bases[o % (sizeof(bases) / sizeof(bases[0]))];
        stats_offset = offsets[o] | 0x80;
        pointer = stats_base + offsets[o] * 24;
        stats_lookups = 0;
        assert(insert_remove_pppoe_hm(&info, 7) == SUCCESS);
        assert(stats_lookups == 1);
        const uint8_t expected[] = { pointer >> 24, pointer >> 16,
                                     pointer >> 8, pointer };
        assert(memcmp(bytes + 1, expected, sizeof(expected)) == 0);
        assert(bytes[0] == 0xa5 && bytes[5] == 0xa5 && opcode[1] == 0xa5);
        assert(opcode[0] == STRIP_PPPoE_HDR && info.opc_count == 3);
        assert(info.paramptr == bytes + 5 && info.param_size == 0);

        /* A flow-described session names its receive record in the
         * description. The lookup is not attempted at all -- on a physical
         * port it returns a failure that would refuse the whole flow -- and
         * the pointer comes from the index that was named. */
        memset(bytes, 0xa5, sizeof(bytes));
        opcode[0] = opcode[1] = 0xa5;
        info = (struct ins_entry_info){ .opc_count = 2, .param_size = 4,
                                        .paramptr = bytes + 1, .opcptr = opcode };
        info.l2_info.pppoe_flow_ifstats = 1;
        info.l2_info.pppoe_rx_stats_offset = stats_offset;
        /* The transmit index is the insert's and must not be read here: the
         * two halves of one record are different addresses. */
        info.l2_info.pppoe_stats_offset = (uint8_t)(stats_offset + 1);
        stats_lookups = 0;
        assert(insert_remove_pppoe_hm(&info, 7) == SUCCESS);
        assert(stats_lookups == 0);
        assert(memcmp(bytes + 1, expected, sizeof(expected)) == 0);
        assert(opcode[0] == STRIP_PPPoE_HDR);

        /* No record: index zero, null pointer, still no lookup. */
        memset(bytes, 0xa5, sizeof(bytes));
        opcode[0] = opcode[1] = 0xa5;
        info = (struct ins_entry_info){ .opc_count = 2, .param_size = 4,
                                        .paramptr = bytes + 1, .opcptr = opcode };
        info.l2_info.pppoe_flow_ifstats = 1;
        stats_lookups = 0;
        assert(insert_remove_pppoe_hm(&info, 7) == SUCCESS);
        assert(stats_lookups == 0);
        assert(memcmp(bytes + 1, (uint8_t[4]){0}, 4) == 0);
        assert(opcode[0] == STRIP_PPPoE_HDR);

        display_log[0] = 0;
        assert(display_strip_pppoe_hdr_opc(bytes + 1) == bytes + 5);
    }

    /* Refusals leave every cursor and every parameter byte untouched. */
    for (unsigned failure = 0; failure < 5; failure++) {
        uint8_t bytes[8], opcode = 0xa5;
        struct ins_entry_info info = {
            .param_size = 8, .paramptr = bytes, .opcptr = &opcode,
        };
        unsigned count, size;

        memset(bytes, 0xa5, sizeof(bytes));
        fail_stats = 0;
        switch (failure) {
        case 0: info.opc_count = MAX_OPCODES; break;
        case 1: info.param_size = 7; break;
        case 2: info.param_size = 3; break;
        case 3: fail_stats = 1; break;
        case 4: fail_stats = 1; info.l2_info.pppoe_flow_ifstats = 1; break;
        }
        count = info.opc_count;
        size = info.param_size;
        if (failure < 2)
            assert(create_pppoe_ins_hm(&info) == FAILURE);
        else if (failure == 2)
            assert(insert_remove_pppoe_hm(&info, 7) == FAILURE);
        else if (failure == 3)
            assert(insert_remove_pppoe_hm(&info, 7) == FAILURE);
        else
            /* A flow-described session never consults the interface, so the
             * lookup's failure cannot reach it. */
            assert(insert_remove_pppoe_hm(&info, 7) == SUCCESS);
        if (failure == 4)
            continue;
        assert(info.opc_count == count && info.param_size == size);
        assert(info.paramptr == bytes && info.opcptr == &opcode && opcode == 0xa5);
        for (unsigned i = 0; i < sizeof(bytes); i++) assert(bytes[i] == 0xa5);
    }
    fail_stats = 0;

    /* What puts the session into that description in the first place. The
     * caller's encapsulation is the flow's, so it must also be what turns the
     * statistics pointer off on both opcodes. */
    {
        struct ins_entry_info info = { .param_size = 8 };
        struct cdx_l2_encap encap = {};

        encap.egress_pppoe = 1;
        encap.egress_session_id = 0x1234;
        memcpy(encap.egress_session_mac, ac, ETHER_ADDR_LEN);
        /* Deliberately different values on the two sides: the receive index
         * belongs to the strip and the transmit one to the insert, and a
         * description that swapped them would count each direction into the
         * other half without either opcode noticing. */
        encap.ingress_stats_index = 0x83;
        encap.egress_stats_index = 0x84;
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l2_info.add_pppoe_hdr && !info.l2_info.pppoe_present);
        assert(info.l2_info.pppoe_flow_ifstats);
        assert(info.l2_info.pppoe_sess_id == 0x1234);
        assert(!memcmp(info.l2_info.ac_mac_addr, ac, ETHER_ADDR_LEN));
        assert(info.l2_info.pppoe_rx_stats_offset == 0x83);
        assert(info.l2_info.pppoe_stats_offset == 0x84);

        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){ .ingress_pppoe = 1, .ingress_stats_index = 0x85 };
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l2_info.pppoe_present && !info.l2_info.add_pppoe_hdr);
        assert(info.l2_info.pppoe_flow_ifstats);
        assert(info.l2_info.pppoe_rx_stats_offset == 0x85);
        /* A session that inserts nothing names no transmit record either. */
        assert(!info.l2_info.pppoe_stats_offset);

        /* A description that already names a session came from a registered
         * interface, and replacing it would lose whatever it described. */
        memset(&info, 0, sizeof(info));
        info.l2_info.pppoe_present = 1;
        encap = (struct cdx_l2_encap){ .egress_pppoe = 1, .egress_session_id = 1 };
        assert(apply_l2_encap(&info, &encap) == FAILURE);
        memset(&info, 0, sizeof(info));
        info.l2_info.add_pppoe_hdr = 1;
        assert(apply_l2_encap(&info, &encap) == FAILURE);

        /* And tags with no session leave both PPPoE flags, and the
         * suppression, alone. */
        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){ .num_egress = 1 };
        encap.egress[0].tpid = 0x8100;
        encap.egress[0].tci = 100;
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(!info.l2_info.pppoe_present && !info.l2_info.add_pppoe_hdr);
        assert(!info.l2_info.pppoe_flow_ifstats);
        assert(!info.l2_info.pppoe_rx_stats_offset && !info.l2_info.pppoe_stats_offset);
        assert(info.l2_info.num_egress_vlan_hdrs == 1);
    }
    puts("PPPoE HM encoding, suppression and refusal checks passed");
}

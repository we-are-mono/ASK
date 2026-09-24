/* The two PPPoE header manipulations and the description they read, compiled
 * from CDX against the shipped SDK header. What this pins down is the one
 * thing a hardware run cannot show cheaply: that each opcode counts into the
 * record half the flow's description names for it, and that a session with no
 * record emits a null statistics pointer rather than aiming the ucode's
 * counter update at the unallocated offset zero, which belongs to another
 * interface. */
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
    /* An encapsulation that names a tunnel writes here rather than into the
     * L2 half, so the description apply_l2_encap() fills spans both. */
    struct dpa_l3hdr_info l3_info;
};

static uint32_t stats_base;
static uint8_t stats_offset;
static uint32_t get_logical_ifstats_base(void) { return stats_base; }

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

/* The debug decoder reads the same two big-endian words back. On a
 * little-endian host a bitfield read of the second puts the session id's
 * bytes the wrong way round, and a plain read of the first prints the pointer
 * byte-reversed; ids and pointers whose bytes differ catch both. */
static void expect_decode(uint8_t *bytes, uint32_t pointer, uint16_t sid)
{
    char expected[128];

    display_log[0] = 0;
    assert(display_pppoehdr_insert_opc(bytes) == bytes + 8);
    snprintf(expected, sizeof(expected), "opcode : INSERT_PPPoE_HDR\n"
             "version 1, type 1, code 0\n\nsession id %u\nstats ptr %x\n", sid, pointer);
    assert(strcmp(display_log, expected) == 0);
}

/* The encoder only ever writes version 1, type 1 and code 0, so decode a word
 * that does not: every field distinct, so a nibble read from its neighbour's
 * place cannot pass. */
static void check_decode_fields(void)
{
    uint8_t param[8] = {0x00, 0xab, 0xcd, 0xef, 0x2b, 0x5a, 0x12, 0x34};

    display_log[0] = 0;
    assert(display_pppoehdr_insert_opc(param) == param + sizeof(param));
    assert(strcmp(display_log, "opcode : INSERT_PPPoE_HDR\nversion 2, type 11, code 90\n\n"
                               "session id 4660\nstats ptr abcdef\n") == 0);
}

int main(void)
{
    const uint32_t bases[] = {0, 0x10, 0x12340, 0xabcdef, 0xfffff0};
    const uint8_t offsets[] = {0, 1, 3, 127};
    const uint16_t sids[] = {1, 0x1234, 0xabcd, 0xffff};
    const uint8_t ac[ETHER_ADDR_LEN] = {2, 0xac, 0, 0, 0, 1};

    assert(sizeof(struct en_ehash_insert_pppoe_hdr) == 8);
    assert(sizeof(struct en_ehash_strip_pppoe_hdr) == 4);
    check_decode_fields();

    /* A session keeps the record its description names. */
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
        expect_decode(bytes + 1, stats_base + offsets[o] * 24, sids[s]);
        assert(bytes[0] == 0xa5 && bytes[9] == 0xa5 && opcode[1] == 0xa5);
        assert(opcode[0] == INSERT_PPPoE_HDR && info.opc_count == 3);
        assert(info.paramptr == bytes + 9 && info.param_size == 0);
        /* PPPoE is the outermost header once inserted, so whatever Ethernet
         * type is written afterwards has to be the session one. */
        assert(info.eth_type == ETHERTYPE_PPPOE);

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
        assert(create_pppoe_ins_hm(&info) == SUCCESS);
        expect_insert(bytes + 1, 0, sids[s]);
        assert(opcode[0] == INSERT_PPPoE_HDR && info.eth_type == ETHERTYPE_PPPOE);
        expect_decode(bytes + 1, 0, sids[s]);
    }

    /* The strip. Its only parameter is the pointer, built from the receive
     * record the description names. */
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
        info.l2_info.pppoe_rx_stats_offset = stats_offset;
        /* The transmit index is the insert's and must not be read here: the
         * two halves of one record are different addresses. */
        info.l2_info.pppoe_stats_offset = (uint8_t)(stats_offset + 1);
        assert(insert_remove_pppoe_hm(&info) == SUCCESS);
        const uint8_t expected[] = { pointer >> 24, pointer >> 16,
                                     pointer >> 8, pointer };
        assert(memcmp(bytes + 1, expected, sizeof(expected)) == 0);
        assert(bytes[0] == 0xa5 && bytes[5] == 0xa5 && opcode[1] == 0xa5);
        assert(opcode[0] == STRIP_PPPoE_HDR && info.opc_count == 3);
        assert(info.paramptr == bytes + 5 && info.param_size == 0);

        /* No record: index zero, null pointer. */
        memset(bytes, 0xa5, sizeof(bytes));
        opcode[0] = opcode[1] = 0xa5;
        info = (struct ins_entry_info){ .opc_count = 2, .param_size = 4,
                                        .paramptr = bytes + 1, .opcptr = opcode };
        assert(insert_remove_pppoe_hm(&info) == SUCCESS);
        assert(memcmp(bytes + 1, (uint8_t[4]){0}, 4) == 0);
        assert(opcode[0] == STRIP_PPPoE_HDR);

        display_log[0] = 0;
        assert(display_strip_pppoe_hdr_opc(bytes + 1) == bytes + 5);
    }

    /* Refusals leave every cursor and every parameter byte untouched. */
    for (unsigned failure = 0; failure < 3; failure++) {
        uint8_t bytes[8], opcode = 0xa5;
        struct ins_entry_info info = {
            .param_size = 8, .paramptr = bytes, .opcptr = &opcode,
        };
        unsigned count, size;

        memset(bytes, 0xa5, sizeof(bytes));
        switch (failure) {
        case 0: info.opc_count = MAX_OPCODES; break;
        case 1: info.param_size = 7; break;
        case 2: info.param_size = 3; break;
        }
        count = info.opc_count;
        size = info.param_size;
        if (failure < 2)
            assert(create_pppoe_ins_hm(&info) == FAILURE);
        else
            assert(insert_remove_pppoe_hm(&info) == FAILURE);
        assert(info.opc_count == count && info.param_size == size);
        assert(info.paramptr == bytes && info.opcptr == &opcode && opcode == 0xa5);
        for (unsigned i = 0; i < sizeof(bytes); i++) assert(bytes[i] == 0xa5);
    }

    /* What puts the session into that description in the first place: the
     * caller's encapsulation, records and all. */
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
        assert(info.l2_info.pppoe_sess_id == 0x1234);
        assert(!memcmp(info.l2_info.ac_mac_addr, ac, ETHER_ADDR_LEN));
        assert(info.l2_info.pppoe_rx_stats_offset == 0x83);
        assert(info.l2_info.pppoe_stats_offset == 0x84);

        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){ .ingress_pppoe = 1, .ingress_stats_index = 0x85 };
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l2_info.pppoe_present && !info.l2_info.add_pppoe_hdr);
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

        /* And tags with no session leave both PPPoE flags, and both
         * records, alone -- even with indices in the encapsulation. */
        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){ .num_egress = 1, .ingress_stats_index = 0x86,
                                       .egress_stats_index = 0x87 };
        encap.egress[0].tpid = 0x8100;
        encap.egress[0].tci = 100;
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(!info.l2_info.pppoe_present && !info.l2_info.add_pppoe_hdr);
        assert(!info.l2_info.pppoe_rx_stats_offset && !info.l2_info.pppoe_stats_offset);
        assert(info.l2_info.num_egress_vlan_hdrs == 1);
        /* A tag says nothing about a tunnel either way. */
        assert(!info.l3_info.add_tnl_header && !info.l3_info.tnl_header_present);
        assert(!info.l3_info.header_size);
        assert(!info.l3_info.tunnel_stats_offset && !info.l3_info.tunnel_rx_stats_offset);
    }

    /* The tunnel half of the same description. A tunnel is an L3 header, so it
     * spends no encapsulation slot and lands in l3_info; what it shares with a
     * session is that the flow names its own record. */
    {
        struct ins_entry_info info;
        struct cdx_l2_encap encap;
        uint8_t outer[40];

        for (unsigned i = 0; i < sizeof(outer); i++) outer[i] = (uint8_t)(0x40 + i);

        /* Egress only: the header the insert writes, its size and the
         * transmit record. */
        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){};
        encap.egress_tunnel.present = 1;
        encap.egress_tunnel.mode = TNL_MODE_6O4;
        encap.egress_tunnel.header_size = 20;
        encap.egress_tunnel.stats_index = 0x0d;
        memcpy(encap.egress_tunnel.header, outer, 20);
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l3_info.add_tnl_header && !info.l3_info.tnl_header_present);
        assert(info.l3_info.mode == TNL_MODE_6O4 && info.l3_info.header_size == 20);
        assert(!memcmp(info.l3_info.header, outer, 20));
        /* Only what the description named: the bytes past the header stay
         * zero, so a size that grew would not carry stale ones along. */
        assert(!info.l3_info.header[20]);
        assert(info.l3_info.tunnel_stats_offset == 0x0d);
        /* A direction that strips nothing names no receive record. */
        assert(!info.l3_info.tunnel_rx_stats_offset && !info.l3_info.tunnel_flags);

        /* Ingress only: the strip validates nothing, so it takes the mode, the
         * size, the DSCP-propagation flag and the receive record and no
         * header at all. */
        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){};
        encap.ingress_tunnel.present = 1;
        encap.ingress_tunnel.mode = TNL_MODE_4O6;
        encap.ingress_tunnel.header_size = 40;
        encap.ingress_tunnel.flags = DSCP_COPY;
        encap.ingress_tunnel.stats_index = 0x0e;
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l3_info.tnl_header_present && !info.l3_info.add_tnl_header);
        assert(info.l3_info.mode == TNL_MODE_4O6 && info.l3_info.header_size == 40);
        assert(info.l3_info.tunnel_flags == DSCP_COPY);
        assert(info.l3_info.tunnel_rx_stats_offset == 0x0e);
        assert(!info.l3_info.tunnel_stats_offset);
        assert(!info.l3_info.header[0]);

        /* Both sides of a router between two tunnels of the same shape: one
         * mode, one size, two records and the flags of both. */
        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){};
        encap.ingress_tunnel = (struct cdx_tunnel_encap){
            .present = 1, .mode = TNL_MODE_4O6, .header_size = 40,
            .flags = DSCP_COPY, .stats_index = 0x10 };
        encap.egress_tunnel = (struct cdx_tunnel_encap){
            .present = 1, .mode = TNL_MODE_4O6, .header_size = 40,
            .flags = INHERIT_TC, .stats_index = 0x11 };
        memcpy(encap.egress_tunnel.header, outer, 40);
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l3_info.add_tnl_header && info.l3_info.tnl_header_present);
        assert(info.l3_info.tunnel_flags == (DSCP_COPY | INHERIT_TC));
        assert(info.l3_info.tunnel_rx_stats_offset == 0x10);
        assert(info.l3_info.tunnel_stats_offset == 0x11);
        assert(!memcmp(info.l3_info.header, outer, 40));

        /* One description carries one mode and one size, so a direction that
         * strips one shape and inserts another is refused rather than encoded
         * as whichever arm ran last. */
        memset(&info, 0, sizeof(info));
        encap.egress_tunnel.mode = TNL_MODE_6O4;
        assert(apply_l2_encap(&info, &encap) == FAILURE);
        encap.egress_tunnel.mode = TNL_MODE_4O6;
        memset(&info, 0, sizeof(info));
        encap.egress_tunnel.header_size = 20;
        assert(apply_l2_encap(&info, &encap) == FAILURE);
        encap.egress_tunnel.header_size = 40;

        /* A header larger than the one the hardware inserts would run off the
         * description; the size is a byte, so a caller can name one. */
        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){};
        encap.egress_tunnel.present = 1;
        encap.egress_tunnel.mode = TNL_MODE_4O6;
        encap.egress_tunnel.header_size = 41;
        assert(apply_l2_encap(&info, &encap) == FAILURE);

        /* A description that already names a tunnel came from a registered
         * interface, and replacing it would lose whatever it described. */
        for (unsigned side = 0; side < 2; side++) {
            memset(&info, 0, sizeof(info));
            if (side)
                info.l3_info.add_tnl_header = 1;
            else
                info.l3_info.tnl_header_present = 1;
            encap = (struct cdx_l2_encap){};
            encap.ingress_tunnel.present = 1;
            encap.ingress_tunnel.mode = TNL_MODE_6O4;
            encap.ingress_tunnel.header_size = 20;
            assert(apply_l2_encap(&info, &encap) == FAILURE);
        }
    }
    puts("PPPoE and tunnel HM encoding, suppression and refusal checks passed");
}

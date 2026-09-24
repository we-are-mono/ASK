/* The two tunnel header manipulations and the description they read, compiled
 * from CDX against the shipped SDK header. What this pins down is what a
 * hardware run cannot show cheaply: the bits of the insert's first word, the
 * bytes of the outer header it copies verbatim, and that a tunnel described by
 * a flow emits the statistics pointer its own description names -- or the null
 * pointer -- instead of resolving a registered tunnel interface it does not
 * have. */
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
/* The two directions of the interface statistics lookup, in the order the
 * production enum declares them, and the interface class a tunnel registers
 * under. */
#define RX_IFSTATS 0
#define TX_IFSTATS 1
#define IF_TYPE_TUNNEL (1 << 3)
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)

#include "tunnel_types.inc"

struct iface { unsigned index; };
/* The insert reads the egress interface and the strip the ingress one, so the
 * two legacy lookups must not be able to reach each other's. */
struct route { struct iface *itf, *input_itf; };
typedef struct ct { struct route *pRtEntry; } *PCtEntry;
/* Only the fields the two manipulations touch, but with the real L3
 * description rather than a restatement of it: a field renamed or resized on
 * that boundary has to fail here rather than compile into a silent mismatch. */
struct ins_entry_info {
    void *entry;
    uint32_t opc_count, param_size;
    uint16_t tnl_hdr_size, eth_type;
    uint8_t *paramptr, *opcptr;
    struct dpa_l3hdr_info l3_info;
};

#ifdef INCLUDE_TUNNEL_IFSTATS
static uint32_t stats_base;
static uint8_t stats_offset;
static int fail_stats;
static unsigned stats_lookups, expect_index, expect_dir;
static uint32_t get_logical_ifstats_base(void) { return stats_base; }
static int dpa_get_iface_stats_entries(unsigned index, unsigned underlying,
                                     uint8_t *offset, unsigned dir, unsigned type)
{
    stats_lookups++;
    /* The index is the one the caller resolved, and each direction resolves a
     * different interface: a flow-described tunnel must never get this far,
     * because on a physical port the lookup fails and takes the flow with it. */
    assert(index == expect_index && underlying == 0 && dir == expect_dir &&
           type == IF_TYPE_TUNNEL);
    if (fail_stats) return FAILURE;
    *offset = stats_offset;
    return SUCCESS;
}
#endif

static char display_log[512];
static void printk(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t used = strlen(display_log);
    vsnprintf(display_log + used, sizeof(display_log) - used, fmt, ap);
    va_end(ap);
}
/* The header's own dump helper writes through uint8_t buffers that a hosted
 * sprintf takes as char, which will not compile warning-free here; what the
 * decode has to get right is the pointer and the length it is handed, so those
 * are what this records. */
static void disp_buf(void *buf, uint32_t size)
{
    const uint8_t *bytes = buf;
    uint32_t i;

    for (i = 0; i < size; i++)
        printk("%02x ", bytes[i]);
    printk("\n");
}

#include "tunnel_hm.inc"

/* The outer header the description carries. Its bytes are opaque to the
 * manipulation -- cdx_ft_hw_add() builds them with tnl_build_header() -- so a
 * recognisable pattern is enough to prove they are copied whole and in order. */
static void fill_header(struct ins_entry_info *info, uint16_t size)
{
    uint16_t i;

    for (i = 0; i < size; i++)
        info->l3_info.header[i] = (uint8_t)(0x40 + i);
    info->l3_info.header_size = size;
}

static void expect_dump(char *text, size_t room, const uint8_t *bytes, uint16_t size)
{
    size_t used = 0;
    uint16_t i;

    for (i = 0; i < size; i++)
        used += (size_t)snprintf(text + used, room - used, "%02x ", bytes[i]);
    snprintf(text + used, room - used, "\n");
}

static void check_insert(unsigned mode, uint8_t tunnel_flags,
                         uint8_t index, uint32_t pointer)
{
    const uint16_t header_size = mode == TNL_MODE_6O4 ? 20 : 40;
    const uint32_t size = ALIGN(8u + header_size, 4u);
    /* Dirty, unaligned storage catches stale flags and partial stores. */
    uint8_t bytes[64], opcode[2] = {0xa5, 0xa5};
    struct ins_entry_info info = {
        .opc_count = 2, .param_size = size, .tnl_hdr_size = 3,
        .paramptr = bytes + 1, .opcptr = opcode,
    };
    /* Only 4o6 has a flag for an inherited traffic class: the IPv6 insert can
     * propagate one and the IPv4 insert cannot, so the bit must stay clear on
     * a 6o4 header however the description is marked. */
    const unsigned tos = mode == TNL_MODE_4O6 && (tunnel_flags & INHERIT_TC);
    const unsigned type = mode == TNL_MODE_6O4 ? TYPE_6o4 : TYPE_4o6;
    uint8_t expected[8];
    char head[160], dump[256];

    memset(bytes, 0xa5, sizeof(bytes));
    info.l3_info.mode = (uint8_t)mode;
    info.l3_info.tunnel_flags = tunnel_flags;
    info.l3_info.tunnel_stats_offset = index;
    /* The receive index belongs to the strip and must not be read here: the
     * two halves of one record are different addresses. */
    info.l3_info.tunnel_rx_stats_offset = (uint8_t)(index + 1);
    info.l3_info.tunnel_flow_ifstats = 1;
    fill_header(&info, header_size);

    assert(create_tunnel_insert_hm(&info) == SUCCESS);
    /* First word, big-endian: type in bits 25..24, the inherited traffic
     * class in 27, the header length in 23..16 and the initial IP
     * identification in the low half. Bit 26 -- the opcode's own
     * don't-fragment flag -- stays clear: the microcode fills the fragment
     * field itself, so nothing here sets it. */
    expected[0] = (uint8_t)(type | (tos << 3));
    expected[1] = (uint8_t)header_size;
    expected[2] = (uint8_t)(IPID_STARTVAL >> 8);
    expected[3] = (uint8_t)IPID_STARTVAL;
    /* Second word: the routing destination offset, still zero, then the
     * 24-bit MURAM address of the record this direction counts into. */
    expected[4] = (uint8_t)(pointer >> 24);
    expected[5] = (uint8_t)(pointer >> 16);
    expected[6] = (uint8_t)(pointer >> 8);
    expected[7] = (uint8_t)pointer;
    assert(memcmp(bytes + 1, expected, sizeof(expected)) == 0);
    assert(memcmp(bytes + 9, info.l3_info.header, header_size) == 0);
    assert(bytes[0] == 0xa5 && bytes[1 + size] == 0xa5 && opcode[1] == 0xa5);
    assert(opcode[0] == INSERT_L3_HDR);
    assert(info.opc_count == 3 && info.param_size == 0);
    assert(info.paramptr == bytes + 1 + size);
    assert(info.opcptr == opcode + 1);
    /* The outer header decides what the frame now is, and the inner family
     * never reaches this opcode. */
    assert(info.eth_type == (mode == TNL_MODE_6O4 ? ETHERTYPE_IPV4 : ETHERTYPE_IPV6));
    assert(info.tnl_hdr_size == 3 + header_size);

    /* The debug decode reads every field back the way the encoder wrote it:
     * the opcode, the tunnel type, the header length, the don't-fragment,
     * traffic-class and checksum bits (26, 27 and 28 of the big-endian
     * word), the 24-bit statistics pointer, and where the next opcode's
     * parameters begin. */
    display_log[0] = 0;
    assert(display_l3hdr_insert_opc(bytes + 1) == bytes + 1 + size);
    snprintf(head, sizeof(head),
             "opcode : INSERT_L3_HDR - TYPE_%s\nhdr len %u\n"
             "df 0, qos %u, cs 0\nstats ptr %x\n",
             mode == TNL_MODE_6O4 ? "6o4" : "4o6", header_size, tos, pointer);
    assert(strncmp(display_log, head, strlen(head)) == 0);
    expect_dump(dump, sizeof(dump), info.l3_info.header, header_size);
    assert(strstr(display_log, dump));
}

/* The encoder never sets the don't-fragment or checksum bits, so decode a
 * word that does: each flag on its own, with the pointer's top byte set so a
 * byte-reversed read of the second word cannot pass either. */
static void check_decode_flags(void)
{
    static const struct { uint8_t byte0; const char *flags; } cases[] = {
        {TYPE_6o4 | 1u << 2, "df 1, qos 0, cs 0\n"},
        {TYPE_6o4 | 1u << 3, "df 0, qos 1, cs 0\n"},
        {TYPE_6o4 | 1u << 4, "df 0, qos 0, cs 1\n"},
    };
    uint8_t param[8 + 4];
    unsigned i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(param, 0, sizeof(param));
        param[0] = cases[i].byte0;
        param[1] = 4;
        param[5] = 0xab; param[6] = 0xcd; param[7] = 0xef;
        display_log[0] = 0;
        assert(display_l3hdr_insert_opc(param) == param + sizeof(param));
        assert(strstr(display_log, cases[i].flags));
        assert(strstr(display_log, "stats ptr abcdef\n"));
    }
}

int main(void)
{
    struct iface ingress = {7}, egress = {9};
    struct route route = {&egress, &ingress};
    struct ct ct = {&route};
    const uint32_t bases[] = {0, 0x10, 0x12300, 0x12340, 0x12348, 0xabcdef, 0xfffff0};
    const uint8_t offsets[] = {0, 1, 127, 255};
    const unsigned modes[] = {TNL_MODE_6O4, TNL_MODE_4O6};

    assert(sizeof(struct en_ehash_remove_first_ip_hdr) == 4);
    assert(sizeof(struct en_ehash_insert_l3_hdr) == 8);
    assert(sizeof(struct en_ehash_stats) == 16);
    check_decode_flags();

    /* The strip. Its only parameter is the record pointer and the flag that
     * copies the outer DSCP over the inner one. */
    for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
    for (unsigned flags = 0; flags <= DSCP_COPY; flags += DSCP_COPY)
    for (unsigned b = 0; b < sizeof(bases) / sizeof(bases[0]); b++)
    for (unsigned o = 0; o < sizeof(offsets); o++) {
        /* Dirty, unaligned storage catches stale flags and partial stores. */
        uint8_t bytes[6], opcode[2] = {0xa5, 0xa5};
        memset(bytes, 0xa5, sizeof(bytes));
        struct ins_entry_info info = {
            .entry = &ct, .opc_count = 2, .param_size = 4,
            .paramptr = bytes + 1, .opcptr = opcode,
            .l3_info = { .mode = (uint8_t)modes[m], .tunnel_flags = (uint8_t)flags },
        };
        uint32_t pointer = 0;
#ifdef INCLUDE_TUNNEL_IFSTATS
        stats_base = bases[b];
        stats_offset = offsets[o];
        expect_index = ingress.index;
        expect_dir = RX_IFSTATS;
        pointer = (stats_base + stats_offset * sizeof(struct en_ehash_stats)) & 0xffffff;
#else
        (void)bases[b]; (void)offsets[o];
#endif
        const uint8_t expected[] = {
            !!flags, pointer >> 16, pointer >> 8, pointer,
        };
        assert(create_tunnel_remove_hm(&info) == SUCCESS);
        assert(memcmp(bytes + 1, expected, sizeof(expected)) == 0);
        assert(bytes[0] == 0xa5 && bytes[5] == 0xa5 && opcode[1] == 0xa5);
        assert(info.paramptr == bytes + 5 && info.param_size == 0);
        assert(info.opcptr == opcode + 1 && info.opc_count == 3);
        assert(opcode[0] == REMOVE_FIRST_IP_HDR);
        /* What the frame is once the outer header is off, which is the other
         * family: the strip hands the parser the inner packet. */
        assert(info.eth_type == (Get_Tnl_Ethertype(modes[m]) & 0xFFFF));

        display_log[0] = 0;
        assert(display_strip_first_iphdr(bytes + 1) == bytes + 5);
        char expected_log[256];
        snprintf(expected_log, sizeof(expected_log),
                 "opcode : REMOVE_FIRST_IP_HDR\nstats ptr %x\n"
                 "dscp propagation from outer to inner %u\n", pointer, !!flags);
        assert(strcmp(display_log, expected_log) == 0);
    }

    /* The same strip, with the record named by the flow's own description
     * rather than looked up on a registered tunnel interface. Index zero is
     * not a record -- it belongs to another owner -- so it emits the null
     * pointer the statistics-disabled build writes. */
#ifdef INCLUDE_TUNNEL_IFSTATS
    for (unsigned o = 0; o < sizeof(offsets); o++) {
        uint8_t bytes[6], opcode[2] = {0xa5, 0xa5};
        struct ins_entry_info info = {
            .entry = &ct, .opc_count = 2, .param_size = 4,
            .paramptr = bytes + 1, .opcptr = opcode,
            .l3_info = { .mode = TNL_MODE_6O4, .tunnel_flow_ifstats = 1,
                         .tunnel_rx_stats_offset = offsets[o],
                         /* The transmit index is the insert's. */
                         .tunnel_stats_offset = (uint8_t)(offsets[o] + 1) },
        };
        uint32_t pointer = offsets[o] ?
            (stats_base + offsets[o] * sizeof(struct en_ehash_stats)) & 0xffffff : 0;
        const uint8_t expected[] = {0, pointer >> 16, pointer >> 8, pointer};

        memset(bytes, 0xa5, sizeof(bytes));
        stats_lookups = 0;
        assert(create_tunnel_remove_hm(&info) == SUCCESS);
        assert(!stats_lookups);
        assert(memcmp(bytes + 1, expected, sizeof(expected)) == 0);
        assert(opcode[0] == REMOVE_FIRST_IP_HDR && info.opc_count == 3);
        assert(tunnel_stats_pointer(offsets[o]) == pointer);
    }
    assert(!tunnel_stats_pointer(0));
#endif

    /* Refused strips must leave parameter bytes and cursor state intact. */
    for (unsigned failure = 0; failure < 6; failure++) {
        uint8_t bytes[4] = {0xa5, 0xa5, 0xa5, 0xa5}, opcode = 0xa5;
        struct ins_entry_info info = {
            .entry = &ct, .param_size = 4, .paramptr = bytes, .opcptr = &opcode,
        };
        ct.pRtEntry = &route;
        route.input_itf = &ingress;
        switch (failure) {
        case 0: info.opc_count = MAX_OPCODES; break;
        case 1: info.param_size = 3; break;
        case 2: info.entry = NULL; break;
        case 3: ct.pRtEntry = NULL; break;
        case 4: route.input_itf = NULL; break;
        case 5:
#ifdef INCLUDE_TUNNEL_IFSTATS
            fail_stats = 1;
            break;
#else
            continue;
#endif
        }
        unsigned count = info.opc_count, size = info.param_size;
        assert(create_tunnel_remove_hm(&info) == FAILURE);
        assert(info.opc_count == count && info.param_size == size);
        assert(info.paramptr == bytes && info.opcptr == &opcode && opcode == 0xa5);
        for (unsigned i = 0; i < sizeof(bytes); i++) assert(bytes[i] == 0xa5);
    }
#ifdef INCLUDE_TUNNEL_IFSTATS
    fail_stats = 0;
#endif
    ct.pRtEntry = &route;
    route.input_itf = &ingress;

    /* The insert, both modes, with and without an inherited traffic class,
     * over every record index a flow can name. */
    for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
    for (unsigned tos = 0; tos <= INHERIT_TC; tos += INHERIT_TC)
    for (unsigned o = 0; o < sizeof(offsets); o++) {
        uint32_t pointer = 0;
#ifdef INCLUDE_TUNNEL_IFSTATS
        stats_base = bases[o % (sizeof(bases) / sizeof(bases[0]))];
        stats_lookups = 0;
        pointer = offsets[o] ?
            (stats_base + offsets[o] * sizeof(struct en_ehash_stats)) & 0xffffff : 0;
#endif
        check_insert(modes[m], (uint8_t)tos, offsets[o], pointer);
#ifdef INCLUDE_TUNNEL_IFSTATS
        /* A flow names its own record; the interface lookup is never reached,
         * which matters because on a physical port it fails outright. */
        assert(!stats_lookups);
#endif
    }

#ifdef INCLUDE_TUNNEL_IFSTATS
    /* The legacy arm, where the record is resolved from the egress interface
     * the route names rather than from the description. */
    {
        uint8_t bytes[64], opcode[2] = {0xa5, 0xa5};
        struct ins_entry_info info = {
            .entry = &ct, .opc_count = 2, .param_size = 28,
            .paramptr = bytes + 1, .opcptr = opcode,
            .l3_info = { .mode = TNL_MODE_6O4 },
        };
        uint32_t pointer;

        memset(bytes, 0xa5, sizeof(bytes));
        fill_header(&info, 20);
        stats_base = 0x12340;
        stats_offset = 5;
        expect_index = egress.index;
        expect_dir = TX_IFSTATS;
        stats_lookups = 0;
        pointer = (stats_base + stats_offset * sizeof(struct en_ehash_stats)) & 0xffffff;
        assert(create_tunnel_insert_hm(&info) == SUCCESS);
        assert(stats_lookups == 1);
        assert(bytes[5] == (uint8_t)(pointer >> 24) && bytes[6] == (uint8_t)(pointer >> 16));
        assert(bytes[7] == (uint8_t)(pointer >> 8) && bytes[8] == (uint8_t)pointer);
        assert(opcode[0] == INSERT_L3_HDR && info.opc_count == 3);
    }
#endif

    /* Refused inserts leave the cursor where it was, so the caller can abandon
     * the whole entry without the opcode list having grown. */
    for (unsigned failure = 0; failure < 6; failure++) {
        uint8_t bytes[64], opcode = 0xa5;
        struct ins_entry_info info = {
            .entry = &ct, .param_size = 28, .paramptr = bytes, .opcptr = &opcode,
            .l3_info = { .mode = TNL_MODE_6O4 },
        };
        unsigned count, size;

        memset(bytes, 0xa5, sizeof(bytes));
        fill_header(&info, 20);
        ct.pRtEntry = &route;
        route.itf = &egress;
        switch (failure) {
        case 0: info.opc_count = MAX_OPCODES; break;
        case 1: info.param_size = 27; break;
        /* A header the aligned parameter block cannot hold. */
        case 2: fill_header(&info, 40); break;
        /* GRE and every other mode the hardware does not build. */
        case 3: info.l3_info.mode = TNL_MODE_GRE_IPV6; break;
        case 4: ct.pRtEntry = NULL; break;
        case 5: route.itf = NULL; break;
        }
#ifndef INCLUDE_TUNNEL_IFSTATS
        /* Without the statistics build there is no interface lookup at all,
         * so neither of the last two descriptions is refused. */
        if (failure >= 4) continue;
#endif
        count = info.opc_count;
        size = info.param_size;
        assert(create_tunnel_insert_hm(&info) == FAILURE);
        assert(info.opc_count == count && info.param_size == size);
        assert(info.paramptr == bytes && info.opcptr == &opcode && opcode == 0xa5);
        /* Only a refusal taken before anything is written can promise
         * untouched bytes; the interface lookup runs after the first word and
         * the header have already been laid down, and the caller discards the
         * whole parameter block either way. */
        if (failure < 4)
            for (unsigned i = 0; i < sizeof(bytes); i++) assert(bytes[i] == 0xa5);
    }
    ct.pRtEntry = &route;
    route.itf = &egress;

    puts("Tunnel HM insert and strip encoding, display and refusal checks passed");
}

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
#define DSCP_COPY 2
#define MAX_OPCODES 16
#define SUCCESS 0
#define FAILURE -1
#define RX_IFSTATS 0
#define IF_TYPE_TUNNEL 1
#define REMOVE_FIRST_IP_HDR 0x13
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)

struct iface { unsigned index; };
struct route { struct iface *input_itf; };
typedef struct ct { struct route *pRtEntry; } *PCtEntry;
struct ins_entry_info {
    PCtEntry entry;
    unsigned opc_count, param_size, eth_type;
    uint8_t *paramptr, *opcptr;
    struct { unsigned mode, tunnel_flags; } l3_info;
};
struct en_ehash_stats { uint64_t bytes; uint32_t pkts, reserved; };

#ifdef INCLUDE_TUNNEL_IFSTATS
static uint32_t stats_base;
static uint8_t stats_offset;
static int fail_stats;
static uint32_t get_logical_ifstats_base(void) { return stats_base; }
static int dpa_get_iface_stats_entries(unsigned index, unsigned underlying,
                                     uint8_t *offset, unsigned dir, unsigned type)
{
    assert(index == 7 && underlying == 0 && dir == RX_IFSTATS && type == IF_TYPE_TUNNEL);
    if (fail_stats) return FAILURE;
    *offset = stats_offset;
    return SUCCESS;
}
#endif

static unsigned Get_Tnl_Ethertype(unsigned mode) { return mode ? 0x86dd : 0x0800; }
static char display_log[256];
static void printk(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t used = strlen(display_log);
    vsnprintf(display_log + used, sizeof(display_log) - used, fmt, ap);
    va_end(ap);
}

#include "tunnel_remove.inc"

int main(void)
{
    struct iface iface = {7};
    struct route route = {&iface};
    struct ct ct = {&route};
    const uint32_t bases[] = {0, 0x10, 0x12300, 0x12340, 0x12348, 0xabcdef, 0xfffff0};
    const uint8_t offsets[] = {0, 1, 127, 255};

    assert(sizeof(struct en_ehash_remove_first_ip_hdr) == 4);
    for (unsigned mode = 0; mode < 2; mode++)
    for (unsigned flags = 0; flags <= DSCP_COPY; flags += DSCP_COPY)
    for (unsigned b = 0; b < sizeof(bases) / sizeof(bases[0]); b++)
    for (unsigned o = 0; o < sizeof(offsets); o++) {
        /* Dirty, unaligned storage catches stale flags and partial stores. */
        uint8_t bytes[6], opcode[2] = {0xa5, 0xa5};
        memset(bytes, 0xa5, sizeof(bytes));
        struct ins_entry_info info = {
            .entry = &ct, .opc_count = 2, .param_size = 4,
            .paramptr = bytes + 1, .opcptr = opcode,
            .l3_info = {mode, flags},
        };
        uint32_t pointer = 0;
#ifdef INCLUDE_TUNNEL_IFSTATS
        stats_base = bases[b];
        stats_offset = offsets[o];
        pointer = (stats_base + stats_offset * 16) & 0xffffff;
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
        assert(info.eth_type == Get_Tnl_Ethertype(mode));

        display_log[0] = 0;
        assert(display_strip_first_iphdr(bytes + 1) == bytes + 5);
        char expected_log[256];
        snprintf(expected_log, sizeof(expected_log),
                 "opcode : REMOVE_FIRST_IP_HDR\nstats ptr %x\n"
                 "dscp propagation from outer to inner %u\n", pointer, !!flags);
        assert(strcmp(display_log, expected_log) == 0);
    }

    /* Refused commands must leave parameter bytes and cursor state intact. */
    for (unsigned failure = 0; failure < 6; failure++) {
        uint8_t bytes[4] = {0xa5, 0xa5, 0xa5, 0xa5}, opcode = 0xa5;
        struct ins_entry_info info = {
            .entry = &ct, .param_size = 4, .paramptr = bytes, .opcptr = &opcode,
        };
        ct.pRtEntry = &route;
        route.input_itf = &iface;
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
    puts("Tunnel HM encoding, display and refusal checks passed");
}

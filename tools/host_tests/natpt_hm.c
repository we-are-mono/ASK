/* A direction translated between the families, through the production action
 * selector. The selector's other emitters are traced; the NAT, NAT-PT and
 * Ethernet emitters run for real behind the trace, so their bytes are checked
 * as the microcode reads them: port update first, then the replacement
 * header, then an Ethernet header carrying the other family's EtherType. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/ipv6.h>

#define cpu_to_be32(x) htonl(x)
#define cpu_to_be16(x) htons(x)
#define SUCCESS 0
#define FAILURE -1
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define IPV6_ADDRESS_LENGTH 16
#define IPPROTOCOL_TCP 6
#define IPPROTOCOL_UDP 17
#define MAX_OPCODES 16
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)
#define DPA_PACKED __attribute__((packed))
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define unsafe_memcpy(d, s, n, why) memcpy((d), (s), (n))
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
#define ENABLE_INGRESS_QOS
#define INCLUDE_ETHER_IFSTATS 1

#include "natpt_types.inc"

struct _itf { unsigned index, type; };
typedef struct route { struct _itf *input_itf, *underlying_input_itf, *itf; } RouteEntry;
/* The fields the selector and the emitters read, the addresses laid out as
 * production overlays them: an IPv6 address occupies the words IPv4 NAT keeps
 * its twin_* mirror in, which is why a translated entry must never reach the
 * IPv4 NAT comparison. */
typedef struct ct {
    struct ct *twin;
    RouteEntry *pRtEntry;
    unsigned status, proto;
    uint16_t Sport, Dport;
    union {
        struct {
            uint32_t Saddr_v4, Daddr_v4, unused1, unused2, twin_Saddr, twin_Daddr;
            uint16_t twin_Sport, twin_Dport;
            uint32_t unused3;
        };
        struct { uint32_t Saddr_v6[4], Daddr_v6[4]; };
    };
    union ctentry_qosmark qosmark;
    uint8_t fftype, natpt_tos;
} CtEntry, *PCtEntry;
#define CT_TWIN(e) ((e)->twin)

/* Only a routed hop with no translation decrements TTL by its own opcode. */
static int create_update_dscp_hm(struct ins_entry_info *info, uint8_t opcode)
{ (void)info; (void)opcode; assert(!"a translated direction takes no TTL opcode"); return FAILURE; }

#include "natpt_emitters.inc"

enum { CHECK = 1, RX_STATS, STRIP_ETH, VLAN_CHECK, PPPOE_REMOVE, TUNNEL_REMOVE,
       NAT, TTL, HOPLIMIT, REPLICATE, TUNNEL_INSERT, PPPOE_INSERT, VLAN_INSERT,
       ETHERNET, ENQUEUE };
static unsigned trace[32], count, fail_at, rebuilt;
static int emit(unsigned op) { trace[count++] = op; return count == fail_at; }
static int traced_nat(struct ins_entry_info *info)
{ return emit(NAT) ? FAILURE : create_nat_hm(info); }
static int traced_ethernet(struct ins_entry_info *info, uint32_t rebuild)
{ rebuilt = rebuild; return emit(ETHERNET) ? FAILURE : create_ethernet_hm(info, rebuild); }
struct dpa_iface_info { int unused; };
#define dpa_get_ifinfo_by_itfid(index) ((void)(index), (struct dpa_iface_info *)0)
#define create_preemptive_checks_hm(i, q) ((void)(q), emit(CHECK))
#define create_eth_rx_stats_hm(i, a, b) ((void)(a), (void)(b), emit(RX_STATS))
#define create_strip_eth_hm(i) emit(STRIP_ETH)
#define insert_remove_vlan_hm(i, a, b) ((void)(a), (void)(b), emit(VLAN_CHECK))
#define insert_remove_pppoe_hm(i) emit(PPPOE_REMOVE)
#define create_tunnel_remove_hm(i) emit(TUNNEL_REMOVE)
#define create_nat_hm(i) traced_nat(i)
#define create_ttl_hm(i) emit(TTL)
#define create_hoplimit_hm(i) emit(HOPLIMIT)
#define create_replicate_hm(i) emit(REPLICATE)
#define create_tunnel_insert_hm(i) emit(TUNNEL_INSERT)
#define create_pppoe_ins_hm(i) emit(PPPOE_INSERT)
#define create_vlan_ins_hm(i) emit(VLAN_INSERT)
#define create_ethernet_hm(i, r) traced_ethernet(i, r)
#define create_enque_hm(i) emit(ENQUEUE)
#include "natpt_select.inc"

static const uint8_t dst_mac[6] = {2, 3, 4, 5, 6, 7}, src_mac[6] = {0xe8, 0xf6, 0xd7, 0, 1, 0x14};
/* fc00:dead::201, the IPv6 end; 64:ff9b::a00:e8, the IPv4 end's RFC 6052
 * address; 10.0.0.62, the translator's pool address; 10.0.0.232. */
static const uint32_t host6[4] = { 0x00c0adde, 0, 0, 0x01020000 };
static const uint32_t pref6[4] = { 0x9bff6400, 0, 0, 0xe800000a };
#define POOL4 htonl(0x0a00003e)
#define PEER4 htonl(0x0a0000e8)

static uint8_t ops[MAX_OPCODES], params[256];

/* Build one translated direction, as ft_hw_add_one() leaves the pair: the
 * entry keyed in its own family, the twin in the other. */
static void pair(CtEntry *entry, CtEntry *twin, RouteEntry *route, bool from6, unsigned proto, uint8_t tos)
{
    memset(entry, 0, sizeof(*entry));
    memset(twin, 0, sizeof(*twin));
    entry->twin = twin; twin->twin = entry; entry->pRtEntry = route;
    entry->status = CONNTRACK_ORIG;
    entry->proto = twin->proto = proto;
    entry->Sport = htons(1234); entry->Dport = htons(5678);
    /* The twin is the reply: from the original destination port to the new
     * source port. */
    twin->Sport = htons(5678); twin->Dport = htons(40000);
    entry->fftype = (from6 ? FFTYPE_IPV6 : FFTYPE_IPV4) | FFTYPE_NATPT;
    twin->fftype = from6 ? FFTYPE_IPV4 : FFTYPE_IPV6;
    entry->natpt_tos = tos;
    if (from6) {
        memcpy(entry->Saddr_v6, host6, 16);
        memcpy(entry->Daddr_v6, pref6, 16);
        twin->Saddr_v4 = PEER4;
        twin->Daddr_v4 = POOL4;
    } else {
        entry->Saddr_v4 = PEER4;
        entry->Daddr_v4 = POOL4;
        /* What the IPv4 NAT comparison would read and act on. */
        entry->twin_Saddr = 0xdeadbeef;
        entry->twin_Daddr = 0xfeedface;
        memcpy(twin->Saddr_v6, pref6, 16);
        memcpy(twin->Daddr_v6, host6, 16);
    }
}

/* As insert_entry_in_classif_table_encap() hands the builder its state: the
 * entry, the opcode list and the parameter area. */
static void prepare(struct ins_entry_info *info, CtEntry *entry, unsigned space)
{
    memset(info, 0, sizeof(*info));
    memset(ops, 0, sizeof(ops));
    memset(params, 0xa5, sizeof(params));
    info->entry = entry;
    info->opcptr = ops;
    info->paramptr = params;
    info->param_size = space;
    memcpy(info->l2_info.l2hdr, dst_mac, 6);
    memcpy(info->l2_info.l2hdr + 6, src_mac, 6);
}

static void translated(bool from6, unsigned proto, uint8_t tos)
{
    struct _itf port = { .index = 1 };
    RouteEntry route = { &port, &port, &port };
    CtEntry entry, twin;
    struct ins_entry_info info;
    const unsigned expected[] = { CHECK, RX_STATS, STRIP_ETH, VLAN_CHECK, NAT, ETHERNET, ENQUEUE };
    const unsigned steps = sizeof(expected) / sizeof(expected[0]);
    unsigned hdrlen = from6 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
    uint32_t word;
    uint8_t *p = params;

    pair(&entry, &twin, &route, from6, proto, tos);
    /* Every step can fail, and a failure stops the chain there. */
    for (unsigned failure = 1; failure <= steps; failure++) {
        prepare(&info, &entry, sizeof(params));
        count = 0; fail_at = failure;
        assert(fill_actions(&entry, &info, true) == FAILURE);
        assert(count == failure && !memcmp(trace, expected, count * sizeof(trace[0])));
    }
    prepare(&info, &entry, sizeof(params));
    count = 0; fail_at = 0; rebuilt = 0;
    assert(fill_actions(&entry, &info, true) == SUCCESS);
    /* The Ethernet header is stripped and rebuilt, and no TTL or hop limit
     * opcode is emitted: NAT-PT takes the hop. */
    assert(count == steps && !memcmp(trace, expected, sizeof(expected)));
    assert(rebuilt == 1);
    assert((info.flags & (NAT_HM_NATPT | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT)) ==
           (NAT_HM_NATPT | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT));
    assert(!(info.flags & (TTL_HM_VALID | NAT_HM_REPLACE_SIP | NAT_HM_REPLACE_DIP)));

    /* The opcodes the real emitters wrote, in order: ports, header, L2. */
    assert(info.opc_count == 3);
    assert(ops[0] == (UPDATE_SPORT | UPDATE_DPORT));
    assert(ops[1] == (from6 ? NATPT_6to4 : NATPT_4to6));
    assert(ops[2] == INSERT_L2_HDR);

    /* The ports, from the twin, while the checksum still covers the old
     * family. */
    struct en_ehash_update_port ports;
    memcpy(&ports, p, sizeof(ports));
    assert(ports.sport == htons(40000) && ports.dport == htons(5678));
    p += sizeof(ports);

    /* The NAT-PT word: TTL carried over always, the template's exact length,
     * a 6to4 flow counting its identification, and bit 25 only on 6to4 and
     * only for the copy sentinel. */
    memcpy(&word, p, 4);
    word = ntohl(word);
    if (from6)
        assert(word == (NATPT_TLU | (hdrlen << 16) | IPID_STARTVAL |
                        (tos == CDX_NATPT_TOS_COPY ? NATPT_TOU : 0)));
    else
        assert(word == (NATPT_HLU | (hdrlen << 16)));
    p += 4;
    if (from6) {
        /* Protocol, length, identification, TTL and checksum all zero: the
         * microcode adds each to the template's sum. DF set. */
        uint8_t want[20] = { 0x45, tos, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0 };
        memcpy(want + 12, &twin.Daddr_v4, 4);
        memcpy(want + 16, &twin.Saddr_v4, 4);
        assert(!memcmp(p, want, sizeof(want)));
    } else {
        uint32_t first = htonl(0x60000000u | (uint32_t)tos << 20);
        assert(!memcmp(p, &first, 4));
        assert(!p[4] && !p[5] && p[6] == proto && !p[7]);
        assert(!memcmp(p + 8, twin.Daddr_v6, 16) && !memcmp(p + 24, twin.Saddr_v6, 16));
    }
    p += hdrlen;

    /* The Ethernet header, whole: the two addresses and the other family's
     * EtherType, which NAT-PT does not write. */
    struct en_ehash_insert_l2_hdr *l2 = (struct en_ehash_insert_l2_hdr *)p;
    word = ntohl(l2->word);
    assert((word & 0xffff) == 14 && (word >> 29) == 2);
    assert(!memcmp(l2->l2hdr, dst_mac, 6) && !memcmp(l2->l2hdr + 6, src_mac, 6));
    uint16_t ethertype;
    memcpy(&ethertype, l2->l2hdr + 12, 2);
    assert(ethertype == htons(from6 ? ETHERTYPE_IPV4 : ETHERTYPE_IPV6));
    assert(info.eth_type == (from6 ? ETHERTYPE_IPV4 : ETHERTYPE_IPV6));
    p += ALIGN(14 + sizeof(*l2), 4);
    assert(info.paramptr == p && info.param_size == sizeof(params) - (unsigned)(p - params));

    /* No room for the replacement header: the chain fails at NAT, having
     * written the ports and nothing past them. */
    prepare(&info, &entry, sizeof(struct en_ehash_update_port) + 4 + hdrlen - 1);
    count = 0; fail_at = 0;
    assert(fill_actions(&entry, &info, true) == FAILURE);
    assert(count == 5 && trace[4] == NAT);
    assert(info.opc_count == 1 && params[sizeof(struct en_ehash_update_port)] == 0xa5);
}

int main(void)
{
    const uint8_t tos[] = { CDX_NATPT_TOS_COPY, 0x28, 0 };

    for (unsigned from6 = 0; from6 < 2; from6++)
        for (unsigned tcp = 0; tcp < 2; tcp++)
            for (unsigned t = 0; t < sizeof(tos); t++)
                translated(from6, tcp ? IPPROTOCOL_TCP : IPPROTOCOL_UDP, tos[t]);
    return 0;
}

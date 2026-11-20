/* The enqueue an entry hands a CPU egress, through the production
 * create_enque_hm(): a WireGuard seal queue, described by devman.c's own
 * WireGuard arm, or a Wi-Fi VAP's forwarding queue, as the WLAN arm describes
 * it. Both arrive with the storage profile of the Ethernet port the direction
 * came in by (dpa_check_for_logical_iface_types()), and the enqueue word's top
 * byte is that profile's relative id, which makes the microcode store the
 * frame through it.
 *
 * On a receive port that is how both have always been sent, and it stays so.
 * On an offline port the store is a copy into a fresh buffer of the profile's
 * pool, and the buffer the frame arrived in is never released: measured, one
 * buffer per frame, on the detour's port and on the IPsec offline port.
 * Without the profile the frame would wait in the CPU egress's queues in its
 * own pool -- SEC's, the fragmenter's -- outside that pool's budget. So no
 * offline port's entry leaves by a CPU egress at all. An Ethernet egress, a
 * queue into SEC and the parameters around the word are unchanged.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>

#define cpu_to_be32(x) htonl(x)
#define cpu_to_be16(x) htons(x)
#define SUCCESS 0
#define FAILURE -1
#define MAX_OPCODES 16
#define ETH_ALEN 6
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)
#define DPA_PACKED __attribute__((packed))
/* As Kbuild and cdx_common.h set them for the shipped module. */
#define ENABLE_EGRESS_QOS
#define INCLUDE_VLAN_IFSTATS 1
#define INCLUDE_PPPoE_IFSTATS 1
#define INCLUDE_ETHER_IFSTATS 1
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint16_t u16;
typedef uint32_t u32;
struct net_device;

#include "enqueue_types.inc"

typedef struct ct { uint8_t fftype; } CtEntry, *PCtEntry;

/* The fragmenter's pool and the DSCP map's MURAM, which the enqueue names. */
#define FRAG_BPID 0x23
#define DSCP_MAP 0x40
static struct { uint8_t frag_bp_id; } frag_info_g = { .frag_bp_id = FRAG_BPID };
static uint8_t muram[0x100];
static void *FmMurambaseAddr = muram;
static struct { uint8_t *muram_addr; } dscp_fq_map_ff_g = { muram + DSCP_MAP };
#define IFSTATS_BASE 0x10000
static uint32_t get_logical_ifstats_base(void) { return IFSTATS_BASE; }

/* Port ids as the DK numbers them: the Ethernet ports below 9, the offline
 * ports from 9 on -- the IPsec one (dpa_ipsec_ofport_td()) and the detour's
 * (cdx_detour_portid()). */
#define RX_PORT 3
#define IPSEC_OH 9
#define DETOUR_OH 11
static int dpaa_is_oh_port(uint32_t portid) { return portid >= 9; }

/* WireGuard's record and its seal queues, as the arm reads them. */
struct dpa_iface_info { struct wg_iface_info wg_info; };
typedef struct { uint8_t dstmac[ETH_ALEN]; } RouteEntry, *PRouteEntry;
#define SEAL_FQ 0x4000
static int cdx_wg_get_seal_fq(u16 id, u32 *fqid) { *fqid = SEAL_FQ + id; return 0; }

#include "enqueue_production.inc"

#define VAP_FQ 0x700
#define ETH_FQ 0x103
#define SEC_FQ 0x5005
#define ETH_STATS 7
/* The Ethernet ingress port's profile (vsp_cfg.c: relativeProfileId = 1). */
#define INGRESS_RSPID 1

static uint8_t ops[MAX_OPCODES], params[64];
static CtEntry entry = { .fftype = FFTYPE_IPV4 };

/* As insert_entry_in_classif_table_encap() hands the builder its state once
 * the egress lookup has filled the description: the preemptive checks
 * already emitted, the enqueue's parameters next. */
static void prepare(struct ins_entry_info *info, uint32_t port, uint8_t detour)
{
    memset(info, 0, sizeof(*info));
    memset(ops, 0, sizeof(ops));
    memset(params, 0xa5, sizeof(params));
    memset(params, 0, sizeof(struct en_ehash_preempt_op));
    info->entry = &entry;
    info->port_id = port;
    info->detour = detour;
    info->opcptr = ops;
    info->preempt_params = params;
    info->paramptr = params + sizeof(struct en_ehash_preempt_op);
    info->param_size = sizeof(params) - sizeof(struct en_ehash_preempt_op);
    info->l2_info.mtu = 1420;
    info->l2_info.rspid = INGRESS_RSPID;
    info->l2_info.ether_stats_offset = ETH_STATS;
}

/* Built through devman.c's WireGuard arm, as both egress lookups build it. */
static void wireguard(struct ins_entry_info *info)
{
    struct dpa_iface_info wg = { .wg_info = { .wg_id = 2, .mac_addr = {2, 'w', 'g', 0, 0, 9} } };
    RouteEntry route = { .dstmac = {2, 'w', 'g', 0, 0, 9} };
    unsigned char *src = NULL;

    assert(!dpa_l2_wg_egress(&wg, &route, &info->l2_info, &src));
    assert(src == wg.wg_info.mac_addr && info->l2_info.is_wlan_iface);
    assert(info->l2_info.fqid == SEAL_FQ + 2);
    /* The ingress port's profile is still in the description. */
    assert(info->l2_info.rspid == INGRESS_RSPID);
}

static void vap(struct ins_entry_info *info)
{
    info->l2_info.is_wlan_iface = 1;
    info->l2_info.fqid = VAP_FQ;
}

static struct en_ehash_enqueue_param *written(const struct ins_entry_info *info)
{
    struct en_ehash_enqueue_param *param =
        (struct en_ehash_enqueue_param *)(params + sizeof(struct en_ehash_preempt_op));

    assert(ops[0] == ENQUEUE_PKT && info->opcptr == ops + 1);
    assert(info->enqueue_params == (uint8_t *)param);
    assert(info->paramptr == (uint8_t *)(param + 1));
    assert(info->param_size == sizeof(params) - sizeof(struct en_ehash_preempt_op) - sizeof(*param));
    assert(param->mtu == htons(1420) && param->bpid == FRAG_BPID && !param->hdr_xpnd_sz);
    return param;
}

/* Refused before anything is written: no opcode, no parameter. */
static void refused(const struct ins_entry_info *info)
{
    assert(!ops[0] && info->opcptr == ops && !info->enqueue_params);
    assert(info->paramptr == params + sizeof(struct en_ehash_preempt_op));
    for (unsigned i = sizeof(struct en_ehash_preempt_op); i < sizeof(params); i++)
        assert(params[i] == 0xa5);
}

int main(void)
{
    static const struct { uint32_t port; uint8_t detour; } ports[] = {
        { RX_PORT, CDX_DETOUR_NONE },	/* a direction on its receive port */
        { DETOUR_OH, CDX_DETOUR_OFFLINE },	/* the detour's offline entry */
        { IPSEC_OH, CDX_DETOUR_NONE },	/* a decrypted direction */
    };
    struct en_ehash_preempt_op *preempt = (struct en_ehash_preempt_op *)params;
    struct en_ehash_enqueue_param *param;
    struct ins_entry_info info;

    for (unsigned i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
        bool offline = dpaa_is_oh_port(ports[i].port);

        for (unsigned seal = 0; seal < 2; seal++) {
            /* A CPU egress, a WireGuard seal queue or a VAP's: on a receive
             * port the ingress port's profile in the word, as ever, and no
             * port counters or transmit validation; on an offline port,
             * refused before anything is written. */
            prepare(&info, ports[i].port, ports[i].detour);
            info.l3_info.ipsec_inbound_flow = ports[i].port == IPSEC_OH;
            if (seal)
                wireguard(&info);
            else
                vap(&info);
            if (offline) {
                assert(create_enque_hm(&info) == FAILURE);
                refused(&info);
                assert(!preempt->OpMask);
                continue;
            }
            assert(create_enque_hm(&info) == SUCCESS);
            param = written(&info);
            assert(param->fqid == htonl(seal ? SEAL_FQ + 2 : VAP_FQ));
            assert(param->word == htonl((uint32_t)INGRESS_RSPID << 24));
            assert(param->word2 == htonl(DSCP_MAP));
            assert(!(preempt->OpMask & PREEMPT_TX_VALIDATE) &&
                   (preempt->OpMask & PREEMPT_DFBIT_HONOR));
            assert(preempt->mtu_offset == sizeof(struct en_ehash_preempt_op));
        }

        /* An Ethernet port, as before: its transmit counters in the word
         * and no profile, validated on transmit. */
        prepare(&info, ports[i].port, ports[i].detour);
        info.l2_info.fqid = ETH_FQ;
        assert(create_enque_hm(&info) == SUCCESS);
        param = written(&info);
        assert(param->fqid == htonl(ETH_FQ));
        assert(param->word == htonl(IFSTATS_BASE + ETH_STATS * sizeof(struct en_ehash_stats)));
        assert(preempt->OpMask & PREEMPT_TX_VALIDATE);
    }

    /* A direction whose enqueue is into SEC takes SEC's queue whatever the
     * description says of the egress beyond it: nothing to refuse. */
    prepare(&info, IPSEC_OH, CDX_DETOUR_NONE);
    vap(&info);
    info.to_sec_fqid = SEC_FQ;
    assert(create_enque_hm(&info) == SUCCESS);
    param = written(&info);
    assert(param->fqid == htonl(SEC_FQ) && !param->stats_ptr);

    puts("enqueue: a CPU egress keeps the ingress profile on a receive port "
         "and is refused on an offline port");
    return 0;
}

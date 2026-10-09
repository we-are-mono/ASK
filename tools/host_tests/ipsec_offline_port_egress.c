/* Which queue a decrypted flow leaves by once the IPsec offline port owns it.
 *
 * Every frame that port forwards is in a buffer of SEC's output pool, so an
 * Ethernet egress takes the port's queues for SEC's frames, which a group
 * counting frames bounds, never its forwarding queues, which a group counting
 * bytes bounds at thousands of small frames. A flow that goes back into SEC,
 * or out by a Wi-Fi VAP, keeps the queue it was given; one whose egress port
 * is gone stays in software.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint32_t u32;

#define SA_MAX_OP 2
#define CDX_DPA_IPSEC_OUTBOUND 0
#define CDX_DPA_IPSEC_INBOUND 1
#define IPV4_TCP_TABLE 1
#define IPV4_UDP_TABLE 2
#define IPV6_TCP_TABLE 3
#define IPV6_UDP_TABLE 4
#define IPV4_MULTICAST_TABLE 5
#define IF_TYPE_ETHERNET 0x1
#define IF_TYPE_WLAN 0x2
#define SUCCESS 0
#define FAILURE (-1)
#define DPA_ERROR(...) do { } while (0)

#include "qosmark.inc"

struct _itf { U32 index; };
typedef struct { struct _itf *itf; } RouteEntry, *PRouteEntry;
typedef struct {
    PRouteEntry pRtEntry;
    union ctentry_qosmark qosmark;
    U16 hash;
    U16 hSAEntry[SA_MAX_OP];
    U8 sec_expansion;
} CtEntry, *PCtEntry;
struct sec_context { u32 to_sec_fqid; };
typedef struct { int direction; U16 family; struct sec_context *pSec_sa_context; } SAEntry, *PSAEntry;
struct dpa_l2hdr_info { u32 fqid; U8 is_wlan_iface; };
struct dpa_l3hdr_info { U8 ipsec_inbound_flow; };
struct ins_entry_info {
    struct dpa_l2hdr_info l2_info;
    struct dpa_l3hdr_info l3_info;
    u32 port_id;
    void *td;
    u32 tbl_type, to_sec_fqid, sec_tag;
    uint16_t tnl_hdr_size, sa_family;
};
struct eth_iface_info { int port; };
struct dpa_iface_info { u32 if_flags; struct eth_iface_info eth_info; };

/* Two SAs, by handle: 1 inbound, 2 outbound. */
static struct sec_context out_ctx = { .to_sec_fqid = 0x5005 };
static SAEntry sas[3] = {
    [1] = { .direction = CDX_DPA_IPSEC_INBOUND, .family = 6 },
    [2] = { .direction = CDX_DPA_IPSEC_OUTBOUND, .family = 4, .pSec_sa_context = &out_ctx },
};
static PSAEntry M_ipsec_sa_cache_lookup_by_h(U16 handle)
{
    return handle && handle < 3 ? &sas[handle] : NULL;
}
static u32 cdx_ipsec_key_tag_of(PSAEntry sa) { (void)sa; return 0x7a6; }
static uint16_t cdx_ipsec_expansion_of(PSAEntry sa) { (void)sa; return 56; }
static int ofport_td, instance, *ipsec_instance = &instance;
static int dpa_ipsec_ofport_td(int *info, u32 table_type, void **td, u32 *portid)
{
    assert(info == &instance);
    (void)table_type;
    *td = &ofport_td;
    *portid = 9;
    return 0;
}

/* The ports: itf 4 Ethernet, itf 5 a VAP; anything else gone. */
static int dpa_devlist_lock, locked;
static void spin_lock(int *lock) { assert(lock == &dpa_devlist_lock && !locked); locked = 1; }
static void spin_unlock(int *lock) { assert(lock == &dpa_devlist_lock && locked); locked = 0; }
static struct dpa_iface_info eth = { .if_flags = IF_TYPE_ETHERNET, .eth_info = { 4 } };
static struct dpa_iface_info vap = { .if_flags = IF_TYPE_WLAN };
static struct dpa_iface_info *dpa_get_ifinfo_by_itfid(u32 itf)
{
    assert(locked);
    return itf == 4 ? &eth : itf == 5 ? &vap : NULL;
}
static unsigned sec_lookups;
static const void *looked_up_mark;
static uint32_t cdx_get_txfqid(struct eth_iface_info *eth_info, void *mark, uint32_t hash)
{
    (void)eth_info; (void)mark;
    return 0x100 + (hash & 15);
}
static uint32_t cdx_get_sec_txfqid(struct eth_iface_info *eth_info, void *mark, uint32_t hash)
{
    assert(eth_info == &eth.eth_info && locked);
    sec_lookups++;
    looked_up_mark = mark;
    return 0x900 + (hash & 15);
}

#include "ipsec_offline_port_egress_production.inc"

static struct _itf eth_itf = { 4 }, vap_itf = { 5 }, gone_itf = { 6 };

static int fill(U16 in, U16 out, struct _itf *egress, bool wlan, struct ins_entry_info *info,
                CtEntry *ct)
{
    static RouteEntry rt;

    rt.itf = egress;
    memset(ct, 0, sizeof(*ct));
    ct->pRtEntry = &rt;
    ct->hash = 0x1233;
    ct->hSAEntry[0] = out;
    ct->hSAEntry[1] = in;
    memset(info, 0, sizeof(*info));
    info->tbl_type = IPV6_TCP_TABLE;
    /* What dpa_get_tx_info_by_itf() gave the flow: the port's forwarding
     * queue, or the VAP's. */
    info->l2_info.fqid = wlan ? 0x700 : 0x103;
    info->l2_info.is_wlan_iface = wlan;
    return cdx_ipsec_fill_sec_info(ct, info);
}

int main(void)
{
    struct ins_entry_info info;
    CtEntry ct;

    /* Decrypted, out of an Ethernet port: the offline port's table, and the
     * port's queue for SEC's frames, by the flow's own hash and mark. */
    assert(!fill(1, 0, &eth_itf, false, &info, &ct));
    assert(info.l3_info.ipsec_inbound_flow && info.td == &ofport_td && info.port_id == 9);
    assert(info.l2_info.fqid == 0x900 + (0x1233 & 15) && sec_lookups == 1);
    assert(looked_up_mark == &ct.qosmark && !locked);

    /* Decrypted and encrypted again: it goes back to SEC, by TO_SEC. */
    assert(!fill(1, 2, &eth_itf, false, &info, &ct));
    assert(info.to_sec_fqid == 0x5005 && info.l2_info.fqid == 0x103 && sec_lookups == 1);

    /* Out by a Wi-Fi VAP: its own queues, bounded on their own. */
    assert(!fill(1, 0, &vap_itf, true, &info, &ct));
    assert(info.l2_info.fqid == 0x700 && sec_lookups == 1);

    /* The egress port gone since: refused, and the flow stays in software. */
    assert(fill(1, 0, &gone_itf, false, &info, &ct) == -1 && sec_lookups == 1 && !locked);

    /* Only encrypted: an Ethernet port's table, its forwarding queue. */
    assert(!fill(0, 2, &eth_itf, false, &info, &ct));
    assert(!info.l3_info.ipsec_inbound_flow && info.l2_info.fqid == 0x103 && sec_lookups == 1);

    /* An SA the cache does not hold is a refusal. */
    assert(fill(1, 3, &eth_itf, false, &info, &ct) == -1);

    puts("IPsec offline port egress: decrypted flows take the queues for SEC's frames; "
         "re-encrypted, Wi-Fi and vanished egress handled");
    return 0;
}

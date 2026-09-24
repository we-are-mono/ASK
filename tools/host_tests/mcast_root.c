/* Execute the production action selector; only the hardware emitters are
 * replaced with a trace. The root must retain validation and replication
 * when bridge semantics suppress the router's IP hop update. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#define SUCCESS 0
#define FAILURE 1
#define ETHERTYPE_IPV4 0x800
#define ETHERTYPE_IPV6 0x86dd
#define IPV6_ADDRESS_LENGTH 16
#define IPPROTOCOL_TCP 6
#define IPPROTOCOL_UDP 17
#define CONNTRACK_SNAT 1
#define CONNTRACK_DNAT 2
#define CONNTRACK_NAT 3
#define IF_TYPE_PPPOE 1
#define DPA_ERROR(...) do {} while (0)
struct _itf { unsigned index, type; };
struct route { struct _itf *input_itf, *underlying_input_itf, *itf; };
struct ct {
    struct route *pRtEntry;
    unsigned family, proto, status, Sport, Dport;
    uint32_t Saddr_v4, Daddr_v4, twin_Daddr, twin_Saddr;
    uint32_t Saddr_v6[4], Daddr_v6[4];
};
typedef struct ct *PCtEntry;
#define CT_TWIN(e) (e)
#define IS_IPV6_FLOW(e) ((e)->family == AF_INET6)
#define IS_IPV6(e) IS_IPV6_FLOW(e)
#define IS_IPV4(e) (!IS_IPV6(e))
struct dpa_iface_info { int unused; };
struct ins_entry_info {
    unsigned flags, nat_sport, nat_dport, vlan_ids[2], eth_type;
    unsigned num_mcast_members, to_sec_fqid;
    void *replicate_params, *paramptr;
    struct { uint32_t nat_sip, nat_dip; } v4;
    struct { uint32_t nat_sip[4], nat_dip[4]; } v6;
    struct { unsigned vlan_present, pppoe_present, num_egress_vlan_hdrs,
                      add_pppoe_hdr; struct { unsigned tci; } egress_vlan_hdrs[2]; } l2_info;
    struct { unsigned tnl_header_present, add_tnl_header, ipsec_inbound_flow; } l3_info;
};
enum { CHECK = 1, RX_STATS, STRIP_ETH, VLAN_CHECK, PPPOE_REMOVE, TUNNEL_REMOVE,
       NAT, TTL, HOPLIMIT, REPLICATE, TUNNEL_INSERT, PPPOE_INSERT, VLAN_INSERT,
       ETHERNET, ENQUEUE };
static unsigned trace[32], count, fail_at;
static int emit(unsigned op) { trace[count++] = op; return count == fail_at; }
#define dpa_get_ifinfo_by_itfid(index) ((void)(index), (struct dpa_iface_info *)0)
#define create_preemptive_checks_hm(i) emit(CHECK)
#define create_eth_rx_stats_hm(i,a,b) ((void)(a), (void)(b), emit(RX_STATS))
#define create_strip_eth_hm(i) emit(STRIP_ETH)
#define insert_remove_vlan_hm(i,a,b) ((void)(a), (void)(b), emit(VLAN_CHECK))
#define insert_remove_pppoe_hm(i,a) ((void)(a), emit(PPPOE_REMOVE))
#define create_tunnel_remove_hm(i) emit(TUNNEL_REMOVE)
#define create_nat_hm(i) emit(NAT)
#define create_ttl_hm(i) emit(TTL)
#define create_hoplimit_hm(i) emit(HOPLIMIT)
#define create_replicate_hm(i) emit(REPLICATE)
#define create_tunnel_insert_hm(i) emit(TUNNEL_INSERT)
#define create_pppoe_ins_hm(i) emit(PPPOE_INSERT)
#define create_vlan_ins_hm(i) emit(VLAN_INSERT)
#define create_ethernet_hm(i,r) ((void)(r), emit(ETHERNET))
#define create_enque_hm(i) emit(ENQUEUE)
#include "mcast_root.inc"

int main(void)
{
    struct _itf port = { .index = 1 };
    struct route route = { .input_itf = &port, .underlying_input_itf = &port,
                           .itf = &port };
    for (unsigned v6 = 0; v6 < 2; v6++) {
        struct ct entry = { .family = v6 ? AF_INET6 : AF_INET, .pRtEntry = &route };
        for (unsigned routed = 0; routed < 2; routed++) {
            unsigned expected[] = { CHECK, RX_STATS, STRIP_ETH, VLAN_CHECK,
                                    routed ? (v6 ? HOPLIMIT : TTL) : REPLICATE, REPLICATE };
            unsigned steps = routed ? 6 : 5;
            for (unsigned failure = 0; failure <= steps; failure++) {
                struct ins_entry_info info = { .num_mcast_members = 2 };
                count = 0; fail_at = failure;
                int rc = fill_actions(&entry, &info, routed);
                assert(rc == (failure ? FAILURE : SUCCESS));
                assert(count == (failure ? failure : steps));
                assert(!memcmp(trace, expected, count * sizeof(trace[0])));
                assert(!!(info.flags & TTL_HM_VALID) == routed);
            }
        }
        /* The unicast caller still requests an IP hop update. */
        struct ins_entry_info info = {0};
        count = fail_at = 0;
        assert(fill_actions(&entry, &info, true) == SUCCESS);
        unsigned expected[] = { CHECK, RX_STATS, VLAN_CHECK, v6 ? HOPLIMIT : TTL, ETHERNET, ENQUEUE };
        assert(count == 6 && !memcmp(trace, expected, sizeof(expected)));
    }
}

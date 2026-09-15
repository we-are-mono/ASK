/* Verify actual backend encoding and ownership across real failure boundaries. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint8_t u8;
typedef uint16_t u16, __be16;
typedef uint32_t u32, __be32;
typedef uint64_t u64;
#define ETH_ALEN 6
#define IF_TYPE_ETHERNET 1
#define IF_TYPE_PHYSICAL 128
#define L2_MAX_ONIF 8
#define ENTRY_VALID 1
#define NETREG_REGISTERED 1
#define FFTYPE_IPV4 1
#define CONNTRACK_ORIG 1
#define CONNTRACK_NAT 0x20
#define GFP_KERNEL 0
#define EN_EHASH_DELETE_UNSYNCED -2
#define HASH_CT(s,d,sp,dp,proto) ((proto) * 13)
#define ether_addr_copy(a,b) memcpy(a,b,6)
#define lockdep_assert_held(m) assert(*(m))
#define pr_err(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
#define ASSERT_RTNL() assert(rtnl)
#define ARPHRD_ETHER 1
#define ether_addr_equal(a,b) (!memcmp(a,b,6))
#define CDX_DEBUG_FLOWTABLE 1
#define EXPORT_SYMBOL_NS_GPL(...)
#define module_param(...)
#define module_param_named(...)
#define MODULE_PARM_DESC(...)
#define xchg(p, value) ({ __typeof__(*(p)) old = *(p); *(p) = (value); old; })
struct net { int unused; };
static struct net init_net, other_net;
struct net_device {
    char name[8];
    struct net *net;
    unsigned type, addr_len, reg_state;
    bool bridge, l3_slave, running, carrier;
    u8 dev_addr[6], perm_addr[6];
};
#define dev_net(d) ((d)->net)
#define net_eq(a,b) ((a) == (b))
#define netif_is_bridge_port(d) ((d)->bridge)
#define netif_is_l3_slave(d) ((d)->l3_slave)
#define netif_running(d) ((d)->running)
#define netif_carrier_ok(d) ((d)->carrier)
#define NETDEV_PRE_UP 1
#define NOTIFY_DONE 0
#define netdev_err(...) ((void)0)
struct notifier_block { int (*notifier_call)(struct notifier_block *, unsigned long, void *); };
struct netdev_notifier_info { struct net_device *dev; };
#define netdev_notifier_info_to_dev(i) (((struct netdev_notifier_info *)(i))->dev)
static bool notifier_registered, fail_notifier;
static int notifier_from_errno(int error) { return error; }
static int register_netdevice_notifier(struct notifier_block *nb)
{ assert(!notifier_registered); if (fail_notifier) return -ENOMEM; notifier_registered=true; return 0; }
static void unregister_netdevice_notifier(struct notifier_block *nb)
{ assert(notifier_registered); notifier_registered=false; }
struct dpa_iface_info {
    struct dpa_iface_info *next;
    unsigned if_flags, itf_id;
    struct { struct net_device *net_dev; u8 mac_addr[6]; } eth_info;
};
static struct dpa_iface_info out_iface = { .if_flags=129, .itf_id=2 };
static struct dpa_iface_info in_iface = { .next=&out_iface, .if_flags=129, .itf_id=1 };
static struct dpa_iface_info *dpa_interface_info = &in_iface;
static bool dpa_devlist_lock;
static void spin_lock(bool *l) { assert(!*l); *l=true; }
static void spin_unlock(bool *l) { assert(*l); *l=false; }
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define list_entry(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m); &p->m != (h); p = list_entry(p->m.next, typeof(*p), m))
#define list_for_each_entry_safe(p, n, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m), n = list_entry(p->m.next, typeof(*p), m); \
         &p->m != (h); p = n, n = list_entry(n->m.next, typeof(*n), m))
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; }
struct key { bool linked, safe; };
static struct key *key;
struct hw_ct { void *td; unsigned index; struct key *handle; u64 pkts, bytes; u32 timestamp; };
struct itf { unsigned type, index; };
typedef struct { struct itf *itf, *input_itf, *underlying_input_itf; unsigned mtu; u8 dstmac[6]; } RouteEntry;
typedef struct CtEntry {
    struct CtEntry *twin;
    RouteEntry *pRtEntry;
    struct hw_ct *ct;
    unsigned fftype, status, proto, hash;
    __be32 Saddr_v4, Daddr_v4, twin_Saddr, twin_Daddr;
    __be16 Sport, Dport, twin_Sport, twin_Dport;
} CtEntry, *PCtEntry;
static struct itf in_itf = {129, 1}, out_itf = {129, 2};
typedef struct { struct itf *itf; unsigned flags; } OnifDesc, *POnifDesc;
static OnifDesc in_onif = {&in_itf, ENTRY_VALID}, out_onif = {&out_itf, ENTRY_VALID};
static POnifDesc get_onif_by_index(unsigned id) { assert(id==1 || id==2); return id==1 ? &in_onif : &out_onif; }
static struct { struct { bool mutex; } ctrl; } instance = {{true}}, *cdx_info = &instance;
static bool rtnl, rtnl_busy, quiesce_fail;
static unsigned legacy_pending, quiesces;
static void mutex_lock(bool *m) { assert(!*m); *m = true; }
static void mutex_unlock(bool *m) { assert(*m); *m = false; }
static bool rtnl_trylock(void) { if (rtnl_busy) return false; assert(!rtnl); rtnl = true; return true; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = false; }
static unsigned cdx_ehash_quarantine_pending(void) { return legacy_pending; }
static unsigned allocations, deletes, syncs;
static bool fail_alloc, fail_insert, fail_sync, stopped;
static int delete_result;
static __be32 expected_src, expected_dst;
static __be16 expected_sport, expected_dport;
static unsigned expected_proto = IPPROTO_UDP;
static void *kzalloc(size_t n, int flags) { if(fail_alloc) return NULL; allocations++; return calloc(1,n); }
static void kfree(void *p) { assert(p && allocations); allocations--; free(p); }
static int insert_entry_in_classif_table(PCtEntry ct)
{
    assert(!memcmp(out_iface.eth_info.mac_addr, (u8[]){2,0,0,0,0,0}, 6));
    assert(ct->fftype == FFTYPE_IPV4 && ct->proto == expected_proto);
    assert(ct->hash == expected_proto * 13 && ct->twin->proto == expected_proto);
    assert(ct->Saddr_v4 == htonl(0xc0000201) && ct->Daddr_v4 == htonl(0xc6336401));
    assert(ct->Sport == htons(1234) && ct->Dport == htons(5678));
    assert(ct->twin_Saddr == expected_dst && ct->twin_Daddr == expected_src);
    assert(ct->twin_Sport == expected_dport && ct->twin_Dport == expected_sport);
    assert(ct->twin->Saddr_v4 == expected_dst && ct->twin->Daddr_v4 == expected_src);
    assert(ct->twin->Sport == expected_dport && ct->twin->Dport == expected_sport && ct->twin->twin == ct);
    bool nat = expected_src != ct->Saddr_v4 || expected_dst != ct->Daddr_v4 ||
               expected_sport != ct->Sport || expected_dport != ct->Dport;
    assert(ct->status == (CONNTRACK_ORIG | (nat ? CONNTRACK_NAT : 0)));
    assert(ct->pRtEntry->itf == &out_itf && ct->pRtEntry->input_itf == &in_itf);
    assert(ct->pRtEntry->underlying_input_itf == &in_itf && ct->pRtEntry->mtu == 1200);
    assert(!memcmp(ct->pRtEntry->dstmac, (u8[]){2,3,4,5,6,7},6));
    if (fail_insert) return -1;
    ct->ct = kzalloc(sizeof(*ct->ct), GFP_KERNEL); assert(ct->ct);
    assert(!key); key = calloc(1,sizeof(*key)); assert(key); key->linked = true;
    ct->ct->handle = key; ct->ct->td = &in_itf; ct->ct->index = 1;
    return 0;
}
static int ExternalHashTableDeleteKey(void *td, unsigned index, struct key *handle)
{
    assert(td == &in_itf && index == 1 && handle == key && key->linked);
    deletes++;
    if (delete_result == 0 || delete_result == EN_EHASH_DELETE_UNSYNCED) key->linked = false;
    if (!delete_result) key->safe = true;
    return delete_result;
}
static int ExternalHashTableFmPcdHcSync(void *td)
{ syncs++; if(fail_sync) return -1; assert(key && !key->linked); key->safe = true; return 0; }
static void ExternalHashTableEntryFree(struct key *handle)
{ assert(handle == key && !key->linked && (key->safe || stopped)); free(key); key = NULL; }
static void hw_ct_get_active(struct hw_ct *ct) { ct->pkts = 99; ct->bytes = 12345; ct->timestamp = 321; }
static int dpa_cfg_quiesce(void)
{
    assert(rtnl && cdx_info->ctrl.mutex);
    quiesces++;
    if (quiesce_fail) return -EIO;
    stopped = true;
    return 0;
}
#include "physical_production.inc"
#include "hardware_types.inc"
#include "hardware_production.inc"
#include "backend_production.inc"

static void test_backend(void)
{
    struct net_device in = { .name="in", .net=&init_net, .type=ARPHRD_ETHER,
        .addr_len=ETH_ALEN, .reg_state=NETREG_REGISTERED, .running=true, .carrier=true, .dev_addr={2}, .perm_addr={2} };
    struct net_device out = in;
    strcpy(out.name, "out");
    in_iface.eth_info.net_dev = &in; out_iface.eth_info.net_dev = &out;
    struct cdx_ft_rule rule = { .in=&in, .out=&out, .src=htonl(0xc0000201), .dst=htonl(0xc6336401),
        .sport=htons(1234), .dport=htons(5678), .proto=IPPROTO_UDP, .src_mac={2}, .dst_mac={2,3,4,5,6,7}, .mtu=1200 };
    rule.new_src = expected_src = rule.src; rule.new_dst = expected_dst = rule.dst;
    rule.new_sport = expected_sport = rule.sport; rule.new_dport = expected_dport = rule.dport;
    struct cdx_ft_hw *hw = NULL;
    expected_proto = IPPROTO_UDP;
    cdx_info->ctrl.mutex = false;
    assert(!cdx_flowtable_enabled() && !cdx_flowtable_config_sealed());
    assert(cdx_flowtable_mode_check() == 0);
    ft_observe=true; assert(cdx_flowtable_mode_check() == -EINVAL); ft_observe=false;
    offload_owner="wrong"; assert(cdx_flowtable_mode_check() == -EINVAL); offload_owner="cmm";
    assert(cdx_flowtable_guard_init() == 0 && !notifier_registered);
    cdx_flowtable_guard_exit();
    offload_owner="flowtable"; fail_notifier=true;
    assert(cdx_flowtable_guard_init() == -ENOMEM && !ft_guard_registered);
    cdx_flowtable_guard_exit(); fail_notifier=false;
    assert(cdx_flowtable_guard_init() == 0 && notifier_registered);
    struct netdev_notifier_info info = {&out};
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == NOTIFY_DONE);
    offload_owner="cmm";
    cdx_ft_begin();
    assert(cdx_ft_claim() == -EOPNOTSUPP && !cdx_flowtable_config_sealed());
    offload_owner="flowtable";
    assert(cdx_flowtable_mode_check() == 0 && !cdx_ft_observing());
    legacy_pending=1; assert(cdx_ft_claim() == -EBUSY); legacy_pending=0;
    assert(cdx_ft_claim() == 0 && cdx_flowtable_config_sealed());
    assert(cdx_ft_claim() == -EBUSY);
    rtnl_busy=true; assert(cdx_ft_admission_begin() == -EAGAIN && !rtnl && cdx_info->ctrl.mutex);
    rtnl_busy=false; assert(cdx_ft_admission_begin() == 0);
    assert(cdx_ft_port_supported(&in) && cdx_ft_port_supported(&out));
    assert(!cdx_ft_port_supported(NULL));
    out.net=&other_net; assert(!cdx_ft_port_supported(&out)); out.net=&init_net;
    out.bridge=true; assert(!cdx_ft_port_supported(&out)); out.bridge=false;
    out.l3_slave=true; assert(!cdx_ft_port_supported(&out)); out.l3_slave=false;
    out.carrier=false; assert(!cdx_ft_port_supported(&out)); out.carrier=true;
    out.running=false; assert(!cdx_ft_port_supported(&out)); out.running=true;
    out.dev_addr[5]=1; assert(cdx_ft_port_supported(&out));
    assert(cdx_ft_add(&rule,&hw)==-EOPNOTSUPP && !hw); out.dev_addr[5]=0;
    out.reg_state=0; assert(!cdx_ft_port_supported(&out)); out.reg_state=NETREG_REGISTERED;
    out.type=0; assert(!cdx_ft_port_supported(&out)); out.type=ARPHRD_ETHER;
    out.addr_len=0; assert(!cdx_ft_port_supported(&out)); out.addr_len=ETH_ALEN;
    strcpy(out.name,"renamed"); assert(cdx_ft_port_supported(&out)); strcpy(out.name,"out");
    out_itf.type=2; assert(!cdx_ft_port_supported(&out)); out_itf.type=129;
    in_iface.next=NULL; assert(!cdx_ft_port_supported(&out)); in_iface.next=&out_iface;
    out_onif.flags=0; assert(!cdx_ft_port_supported(&out)); out_onif.flags=ENTRY_VALID;
    out_iface.itf_id=L2_MAX_ONIF; assert(!cdx_ft_port_supported(&out)); out_iface.itf_id=2;
    out_iface.eth_info.net_dev=&in; assert(!cdx_ft_port_supported(&out)); out_iface.eth_info.net_dev=&out;
    ft_observe=true; assert(cdx_ft_add(&rule,&hw) == -EOPNOTSUPP && !hw); ft_observe=false;
    fail_insert=true; assert(cdx_ft_add(&rule,&hw) == -EIO && !ft_live); fail_insert=false;
    assert(cdx_ft_add(&rule,&hw) == 0 && ft_live == 1);
    assert(cdx_ft_release() == -EBUSY && ft_claimed);
    struct cdx_ft_counters counters;
    cdx_ft_stats(hw,&counters); assert(counters.packets == 99);
    cdx_ft_admission_end();
    delete_result=EN_EHASH_DELETE_UNSYNCED;
    assert(cdx_ft_del(&hw) == -EAGAIN && !hw && !ft_live && !cdx_ft_failed());
    assert(cdx_ft_pending() == 1);
    fail_sync=true; assert(cdx_ft_recover() == -EAGAIN && key && !key->safe);
    assert(cdx_ft_release() == 0 && cdx_flowtable_config_sealed());
    assert(cdx_ft_claim() == -EBUSY);
    fail_sync=false; assert(cdx_ft_recover() == 0 && !key && !cdx_ft_pending());
    assert(cdx_ft_claim() == 0 && cdx_flowtable_config_sealed());
    assert(cdx_ft_admission_begin() == 0);
    assert(cdx_ft_add(&rule,&hw) == 0);
    cdx_ft_admission_end();
    delete_result=-EIO;
    assert(cdx_ft_del(&hw) == -EIO && !hw && !ft_live && cdx_ft_failed());
    assert(cdx_ft_del(&hw) == 0 && cdx_ft_failed());
    rtnl_busy=true; assert(cdx_ft_recover() == -EAGAIN && !quiesces && key->linked);
    rtnl_busy=false; quiesce_fail=true;
    assert(cdx_ft_recover() == -EAGAIN && quiesces == 1 && !stopped && key->linked);
    quiesce_fail=false;
    assert(cdx_ft_recover() == 0 && stopped && quiesces == 2 && key->linked);
    assert(!allocations && !cdx_ft_pending() && cdx_ft_failed());
    assert(cdx_ft_release() == 0 && cdx_flowtable_config_sealed());
    assert(cdx_ft_claim() == -EOPNOTSUPP && cdx_ft_failed());
    assert(cdx_ft_admission_begin() == 0);
    assert(cdx_ft_add(&rule,&hw) == -EOPNOTSUPP && !hw);
    cdx_ft_admission_end();
    cdx_flowtable_quiesced();
    cdx_ft_end();
    assert(!cdx_info->ctrl.mutex && !rtnl && !allocations);
    /* A released adapter cannot bypass the provider's terminal guard.
     * The callback runs without a backend transaction and uses object identity. */
    strcpy(out.name,"renamed");
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == -EIO);
    assert(cdx_ft_netdev_event(NULL, 999, &info) == NOTIFY_DONE);
    struct net_device unrelated = out;
    info.dev=&unrelated;
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == NOTIFY_DONE);
    info.dev=&in;
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == -EIO);
    dpa_interface_info=NULL;
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == NOTIFY_DONE);
    dpa_interface_info=&in_iface;
    cdx_flowtable_guard_exit();
    assert(!notifier_registered && !ft_guard_registered);
    cdx_flowtable_guard_exit();
    free(key); key=NULL; /* Only simulated hardware reset reclaims the live key. */
}

int main(void)
{
    struct net_device in = { .name = "in" }, out = { .name = "out" };
    struct cdx_ft_rule rule = { .in=&in, .out=&out, .src=htonl(0xc0000201), .dst=htonl(0xc6336401),
        .sport=htons(1234), .dport=htons(5678), .proto=IPPROTO_UDP, .src_mac={2}, .dst_mac={2,3,4,5,6,7}, .mtu=1200 };
    rule.new_src = expected_src = rule.src; rule.new_dst = expected_dst = rule.dst;
    rule.new_sport = expected_sport = rule.sport; rule.new_dport = expected_dport = rule.dport;
    struct cdx_ft_hw *hw;
    struct cdx_ft_counters counters;
    in_iface.eth_info.net_dev=&in; out_iface.eth_info.net_dev=&out;
    fail_alloc = true; assert(cdx_ft_hw_add(&rule,&hw) == -ENOMEM && !hw); fail_alloc=false;
    fail_insert=true; assert(cdx_ft_hw_add(&rule,&hw) == -EIO && !allocations); fail_insert=false;
    out_itf.type = 2; assert(cdx_ft_hw_add(&rule,&hw) == -EOPNOTSUPP); out_itf.type=129;
    rule.proto = IPPROTO_ICMP; assert(cdx_ft_hw_add(&rule,&hw) == -EOPNOTSUPP && !hw);
    for(unsigned i=0; i<128; i++) {
        rule.proto = expected_proto = (i & 1) ? IPPROTO_TCP : IPPROTO_UDP;
        assert(cdx_ft_hw_add(&rule,&hw) == 0);
        cdx_ft_hw_stats(hw,&counters); assert(counters.packets==99 && counters.bytes==12345 && counters.lastused==321);
        /* No allocation is possible once deletion starts. */
        fail_alloc=true; assert(cdx_ft_hw_del(&hw) == 0 && !hw && !key && !allocations); fail_alloc=false;
        unsigned old=deletes; assert(cdx_ft_hw_del(&hw)==0 && deletes==old);
    }
    rule.proto = expected_proto = IPPROTO_UDP;
    for (unsigned variant = 0; variant < 6; variant++) {
        rule.new_src = expected_src = variant == 0 || variant == 4 ? htonl(0xcb007104) : rule.src;
        rule.new_dst = expected_dst = variant == 1 || variant == 5 ? htonl(0xcb007104) : rule.dst;
        rule.new_sport = expected_sport = variant == 2 || variant == 4 ? htons(40000) : rule.sport;
        rule.new_dport = expected_dport = variant == 3 || variant == 5 ? htons(40000) : rule.dport;
        assert(cdx_ft_hw_add(&rule,&hw) == 0);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
        fail_insert=true; assert(cdx_ft_hw_add(&rule,&hw) == -EIO && !allocations); fail_insert=false;
        rule.proto=IPPROTO_TCP; assert(cdx_ft_hw_add(&rule,&hw) == -EOPNOTSUPP && !hw);
        rule.proto=IPPROTO_UDP;
    }
    rule.new_src = expected_src = rule.src; rule.new_dst = expected_dst = rule.dst;
    rule.new_sport = expected_sport = rule.sport; rule.new_dport = expected_dport = rule.dport;
    assert(cdx_ft_hw_add(&rule,&hw)==0);
    delete_result=EN_EHASH_DELETE_UNSYNCED; fail_alloc=true;
    assert(cdx_ft_hw_del(&hw)==-EAGAIN && !hw && key && !key->linked && allocations==2);
    assert(cdx_ft_hw_pending()==1); unsigned old=deletes;
    fail_sync=true; assert(cdx_ft_hw_retry()==-EAGAIN && key && !key->safe && deletes==old);
    fail_sync=false; assert(cdx_ft_hw_retry()==0 && !key && !allocations && deletes==old);
    fail_alloc=false;
    assert(cdx_ft_hw_add(&rule,&hw)==0); assert(cdx_ft_hw_del(&hw)==-EAGAIN);
    stopped=true; cdx_ft_hw_quiesced(); stopped=false;
    assert(!key && !allocations && !cdx_ft_hw_pending());
    assert(cdx_ft_hw_add(&rule,&hw)==0); delete_result=-1;
    assert(cdx_ft_hw_del(&hw)==-EIO && key->linked && cdx_ft_hw_pending()==1);
    old=syncs; assert(cdx_ft_hw_retry()==-EAGAIN && syncs==old && key->linked);
    stopped=true; cdx_ft_hw_quiesced(); assert(!allocations && key->linked);
    /* Reset owns the potentially linked allocation, never the retiring owner. */
    free(key); key=NULL;
    stopped=false; delete_result=0;
    assert(cdx_ft_hw_add(&rule,&hw)==0);
    ft_fail_unlink=true; old=deletes;
    assert(cdx_ft_hw_del(&hw)==-EIO && !hw && !ft_fail_unlink);
    assert(deletes==old && key->linked && cdx_ft_hw_pending()==1);
    old=syncs; assert(cdx_ft_hw_retry()==-EAGAIN && syncs==old && key->linked);
    stopped=true; cdx_ft_hw_quiesced(); assert(!allocations && key->linked);
    free(key); key=NULL; stopped=false;
    assert(cdx_ft_hw_add(&rule,&hw)==0);
    assert(cdx_ft_hw_del(&hw)==0 && !hw && !key && !allocations);
    test_backend();
    puts("Flowtable hardware: encoding, consuming delete, allocation-free retirement, barrier retry and quiescence passed");
}

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
#define FFTYPE_IPV4 1
#define CONNTRACK_ORIG 1
#define GFP_KERNEL 0
#define EN_EHASH_DELETE_UNSYNCED -2
#define HASH_CT(s,d,sp,dp,proto) ((proto) * 13)
#define ether_addr_copy(a,b) memcpy(a,b,6)
#define lockdep_assert_held(m) assert(*(m))
#define pr_err(...) ((void)0)
#define CDX_DEBUG_FLOWTABLE 1
#define module_param_named(...)
#define MODULE_PARM_DESC(...)
#define xchg(p, value) ({ __typeof__(*(p)) old = *(p); *(p) = (value); old; })
struct net_device { char name[8]; };
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
struct itf { unsigned type; };
typedef struct { struct itf *itf, *input_itf, *underlying_input_itf; unsigned mtu; u8 dstmac[6]; } RouteEntry;
typedef struct CtEntry {
    struct CtEntry *twin;
    RouteEntry *pRtEntry;
    struct hw_ct *ct;
    unsigned fftype, status, proto, hash;
    __be32 Saddr_v4, Daddr_v4, twin_Saddr, twin_Daddr;
    __be16 Sport, Dport, twin_Sport, twin_Dport;
} CtEntry, *PCtEntry;
static struct itf in_itf = {129}, out_itf = {129};
typedef struct { struct itf *itf; } OnifDesc, *POnifDesc;
static OnifDesc in_onif = {&in_itf}, out_onif = {&out_itf};
static POnifDesc get_onif_by_name(const char *name) { return !strcmp(name,"in") ? &in_onif : &out_onif; }
static struct { struct { bool mutex; } ctrl; } instance = {{true}}, *cdx_info = &instance;
static unsigned allocations, deletes, syncs;
static bool fail_alloc, fail_insert, fail_sync, stopped;
static int delete_result;
static unsigned expected_proto = IPPROTO_UDP;
static void *kzalloc(size_t n, int flags) { if(fail_alloc) return NULL; allocations++; return calloc(1,n); }
static void kfree(void *p) { assert(p && allocations); allocations--; free(p); }
static int insert_entry_in_classif_table(PCtEntry ct)
{
    assert(ct->fftype == FFTYPE_IPV4 && ct->proto == expected_proto);
    assert(ct->hash == expected_proto * 13 && ct->twin->proto == expected_proto);
    assert(ct->Saddr_v4 == htonl(0xc0000201) && ct->Daddr_v4 == htonl(0xc6336401));
    assert(ct->Sport == htons(1234) && ct->Dport == htons(5678));
    assert(ct->twin_Saddr == ct->Daddr_v4 && ct->twin_Daddr == ct->Saddr_v4);
    assert(ct->twin_Sport == ct->Dport && ct->twin_Dport == ct->Sport);
    assert(ct->twin->Sport == ct->Dport && ct->twin->Dport == ct->Sport && ct->twin->twin == ct);
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
#include "hardware_types.inc"
#include "hardware_production.inc"

int main(void)
{
    struct net_device in = {"in"}, out = {"out"};
    struct cdx_ft_rule rule = { .in=&in, .out=&out, .src=htonl(0xc0000201), .dst=htonl(0xc6336401),
        .sport=htons(1234), .dport=htons(5678), .proto=IPPROTO_UDP, .dst_mac={2,3,4,5,6,7}, .mtu=1200 };
    struct cdx_ft_hw *hw;
    struct cdx_ft_counters counters;
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
    puts("Flowtable hardware: encoding, consuming delete, allocation-free retirement, barrier retry and quiescence passed");
}

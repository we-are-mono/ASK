/* Verify actual backend encoding and ownership across real failure boundaries. */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
typedef uint8_t u8;
typedef uint16_t u16, __be16;
typedef uint32_t u32, __be32;
typedef int32_t s32;
typedef uint64_t u64;
typedef u8 U8;
typedef u16 U16;
typedef u32 U32;
#define cpu_to_be16 htons
#define BIT(n) (1UL << (n))
#define ETH_ALEN 6
#define IF_TYPE_ETHERNET 1
#define IF_TYPE_WLAN 32
#define IF_TYPE_PHYSICAL 128
/* ASK-DEBUG tracing is a printk in production; nothing to observe here. */
#define ASK_DBG_REFUSE 1
#define ASK_DBG_ACCEPT 2
#define ASK_DBG_DEVICE 4
#define ask_refuse(err) (err)
#define ask_dbg(bit, fmt, ...) do { } while (0)
#define L2_MAX_ONIF 8
#define ENTRY_VALID 1
#define NETREG_REGISTERED 1
#define FFTYPE_IPV4 1
#define FFTYPE_IPV6 2
#define IS_IPV6_FLOW(entry) ((entry)->fftype == FFTYPE_IPV6)
#define CONNTRACK_ORIG 1
#define CONNTRACK_DNAT 0x10
#define CONNTRACK_NAT 0x20
#define CONNTRACK_SNAT CONNTRACK_NAT
#define CONNTRACK_SEC 0x1000
/* One slot per direction of travel, as the encoder reads them: an outbound SA
 * decides where a matched frame goes, an inbound one decides which port's
 * table the entry has to live in to be matched at all. */
#define SA_MAX_OP 2
#define GFP_KERNEL 0
#define EN_EHASH_DELETE_UNSYNCED -2
#define HASH_CT(s,d,sp,dp,proto) ((proto) * 13)
#define HASH_CT6(s,d,sp,dp,proto) ((proto) * 17)
#define DPA_CLS_HM_MAX_VLANs 6
#define ETH_P_8021Q 0x8100
/* Host order in this description, as the header manipulation expects: it
 * applies cpu_to_be16/32 itself when it lays the tags out. */
struct vlan_header { uint16_t tpid, tci; };
#define ETHER_ADDR_LEN 6
struct cdx_l2_encap {
    u32 num_ingress, num_egress;
    struct vlan_header ingress[DPA_CLS_HM_MAX_VLANs];
    struct vlan_header egress[DPA_CLS_HM_MAX_VLANs];
    /* At most one session per direction, with independent identities. */
    u8 ingress_pppoe;
    u8 egress_pppoe;
    u16 ingress_session_id;
    u8 ingress_session_mac[ETHER_ADDR_LEN];
    u16 egress_session_id;
    u8 egress_session_mac[ETHER_ADDR_LEN];
    /* Where each side counts. Zero means no record, never record zero. */
    u8 ingress_stats_index;
    u8 egress_stats_index;
    /* And per tag, innermost first like the tags themselves. */
    u8 ingress_vlan_stats_index[DPA_CLS_HM_MAX_VLANs];
    u8 egress_vlan_stats_index[DPA_CLS_HM_MAX_VLANs];
    /* An IP-in-IP tunnel on either side, outside every L2 header: the egress
     * side carries the outer header the insert writes and the ingress side
     * only what the strip needs, each naming its record in the plain pool. */
    struct cdx_tunnel_encap {
        u8 present;
        u8 mode;
        u8 header_size;
        u8 flags;
        u8 stats_index;
        u8 header[40];
    } ingress_tunnel, egress_tunnel;
};
/* The slot as CDX defines it. The encoder reads only the two indices, which
 * is the whole of what it needs from one; the owner adds its holds. */
struct cdx_ft_stats_slot { void *record; int kind; u8 rx_index, tx_index; unsigned holds; };
union nf_inet_addr {
    u32 all[4];
    __be32 ip;
    __be32 ip6[4];
    struct in_addr in;
    struct in6_addr in6;
};
static bool ipv6_addr_equal(const struct in6_addr *a, const struct in6_addr *b)
{ return !memcmp(a, b, sizeof(*a)); }
static bool nf_inet_addr_cmp_local(const union nf_inet_addr *a, const union nf_inet_addr *b)
{ return !memcmp(a->all, b->all, sizeof(a->all)); }
static union nf_inet_addr v4(__be32 address)
{ union nf_inet_addr a; memset(&a, 0, sizeof(a)); a.ip = address; return a; }
static union nf_inet_addr v6(u32 tail)
{
    union nf_inet_addr a;
    memset(&a, 0, sizeof(a));
    a.ip6[0] = htonl(0xfc00dead); a.ip6[3] = htonl(tail);
    return a;
}
#define ether_addr_copy(a,b) memcpy(a,b,6)
#define lockdep_assert_held(m) assert(*(m))
/* Lines the latch writes: a terminal one, the stopped ports, a restart, a
 * stall, retired entries kept for the reset and ports a restart could not
 * start each count, so a case can require one of each and no more, and the
 * last terminal, restart, stall and unstarted-port lines are kept for what
 * they say. */
static unsigned terminal_lines, stopped_lines, restart_lines, stall_lines, kept_lines, resume_lines;
static char terminal_line[256], restart_line[256], stall_line[256], resume_line[256];
__attribute__((format(printf, 1, 2)))
static void host_log(const char *format, ...)
{
    char line[256];
    va_list ap;

    va_start(ap, format);
    vsnprintf(line, sizeof(line), format, ap);
    va_end(ap);
    if (strstr(line, "reboot required")) {
        terminal_lines++;
        memcpy(terminal_line, line, sizeof(line));
    }
    stopped_lines += !!strstr(line, "ports stopped");
    if (strstr(line, "datapath restarted")) {
        restart_lines++;
        memcpy(restart_line, line, sizeof(line));
    }
    if (strstr(line, "stalled")) {
        stall_lines++;
        memcpy(stall_line, line, sizeof(line));
    }
    kept_lines += !!strstr(line, "until reset");
    if (strstr(line, "did not start again")) {
        resume_lines++;
        memcpy(resume_line, line, sizeof(line));
    }
}
#define pr_err(...) host_log(__VA_ARGS__)
#define pr_warn(...) host_log(__VA_ARGS__)
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
#define module_param_string(...)
#define MODULE_PARM_DESC(...)
#define strscpy(d, s, n) snprintf(d, n, "%s", s)
#define xchg(p, value) ({ __typeof__(*(p)) old = *(p); *(p) = (value); old; })
#define cmpxchg(p, expected, value) \
    ({ __typeof__(*(p)) old = *(p); if (old == (expected)) *(p) = (value); old; })
/* The host's own uapi headers may already carry the annotation. */
#ifndef __counted_by
#define __counted_by(member)
#endif
#define struct_size(p, member, count) (sizeof(*(p)) + sizeof(*(p)->member) * (count))
struct net { int unused; };
static struct net init_net, other_net;
struct net_device {
    char name[8];
    struct net *net;
    unsigned type, addr_len, reg_state, mtu;
    bool l3_slave, running, carrier, switch_port;
    u8 dev_addr[6], perm_addr[6];
};
/* A DPAA MAC reports no switch parent, which is what dev_get_port_parent_id()
 * signals by leaving -EOPNOTSUPP as the answer. A port that does report one
 * belongs to a switch ASIC, whose bridge VLANs the gate has to exclude. */
struct netdev_phys_item_id { unsigned char id[32]; unsigned char id_len; };
static int dev_get_port_parent_id(struct net_device *d, struct netdev_phys_item_id *ppid,
                                  bool recurse)
{
    if (!d->switch_port) return -EOPNOTSUPP;
    *ppid = (struct netdev_phys_item_id){ .id = {1}, .id_len = 1 };
    return 0;
}
#define dev_net(d) ((d)->net)
#define net_eq(a,b) ((a) == (b))
#define netif_is_l3_slave(d) ((d)->l3_slave)
#define netif_running(d) ((d)->running)
#define netif_carrier_ok(d) ((d)->carrier)
#define NETDEV_PRE_UP 1
#define NETDEV_UP 2
#define NETDEV_CHANGE 3
#define NETDEV_CHANGEMTU 4
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
    /* No mac_addr, matching production: a port's own address is its
     * netdev's, read where the header is encoded. */
    struct { struct net_device *net_dev; } eth_info;
    struct { struct net_device *net_dev; uint16_t vap_id; } wlan_info;
};
static struct dpa_iface_info out_iface = { .if_flags=129, .itf_id=2 };
static struct dpa_iface_info in_iface = { .next=&out_iface, .if_flags=129, .itf_id=1 };
static struct dpa_iface_info *dpa_interface_info = &in_iface;
/* VWD's answers about a VAP. This harness has no Wi-Fi case of its own (see
 * wifi_admission.c); both say "not a VAP" unless a case says otherwise. */
static bool vap_open;
static bool dpaa_vwd_vap_is_open(const struct net_device *d) { return d && vap_open; }
static bool dpaa_vwd_vap_owns(uint16_t vap_id, const struct net_device *d) { (void)vap_id; return d && vap_open; }
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
static bool list_empty(const struct list_head *h) { return h->next == h; }
struct key { bool linked, safe; };
/* The newest key, which most cases hold one of, and an older one a case can
 * keep underneath it: retired, or still linked after a hard failure. */
static struct key *key, *older;
struct hw_ct { void *td; unsigned index; struct key *handle; u64 pkts, bytes; u32 timestamp; };
struct itf { unsigned type, index; };
typedef struct { struct itf *itf, *input_itf, *underlying_input_itf; unsigned mtu; u8 dstmac[6]; } RouteEntry;
typedef struct CtEntry {
    struct CtEntry *twin;
    RouteEntry *pRtEntry;
    struct hw_ct *ct;
    u16 hSAEntry[SA_MAX_OP];
    u8 sec_expansion;
    unsigned fftype, status, proto, hash;
    __be16 Sport, Dport;
    /* The real hardware-visible overlay, byte for byte: an IPv6 destination
     * occupies exactly the words IPv4 uses for its twin mirror, so writing any
     * twin_* field on an IPv6 entry corrupts its own destination address.
     * Reproducing the overlap here is the point -- a harness with separate
     * fields would let that bug through. */
    union {
        struct {
            __be32 Saddr_v4, Daddr_v4, unused1, unused2, twin_Saddr, twin_Daddr;
            __be16 twin_Sport, twin_Dport;
            __be32 unused3;
        };
        struct { __be32 Saddr_v6[4], Daddr_v6[4]; };
    };
    /* Only the fields the backend writes, laid out as the production union
     * lays them out so the bit positions are the ones under test. The DSCP
     * marking bits stay out: nothing on this path sets them, and leaving them
     * absent keeps a case honest about which fields it is responsible for. */
    struct {
        /* The hardware mark's own layout, bit for bit: the remark's flag and
         * value sit between the class queue and the ingress policer, which is
         * why they are two separate fields rather than one seven-bit one. */
        unsigned queue : 4;
        unsigned pad_1 : 4;
        unsigned dscp_mark_flag : 1;
        unsigned dscp_mark_value : 6;
        unsigned pad_2 : 1;
        unsigned iqid : 4;
        unsigned pad_3 : 3;
        unsigned iqid_valid : 1;
        unsigned chnl_id : 4;
    } qosmark;
} CtEntry, *PCtEntry;
static struct itf in_itf = {129, 1}, out_itf = {129, 2};
typedef struct { struct itf *itf; unsigned flags; } OnifDesc, *POnifDesc;
static OnifDesc in_onif = {&in_itf, ENTRY_VALID}, out_onif = {&out_itf, ENTRY_VALID};
static POnifDesc get_onif_by_index(unsigned id) { assert(id==1 || id==2); return id==1 ? &in_onif : &out_onif; }
static struct { struct { bool mutex; } ctrl; } instance = {{true}}, *cdx_info = &instance;
static bool rtnl, rtnl_busy;
static unsigned legacy_pending;
static void mutex_lock(bool *m) { assert(!*m); *m = true; }
static void mutex_unlock(bool *m) { assert(*m); *m = false; }
static bool mutex_trylock(bool *m) { if (*m) return false; *m = true; return true; }
static bool rtnl_trylock(void) { if (rtnl_busy) return false; assert(!rtnl); rtnl = true; return true; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = false; }
static unsigned cdx_ehash_quarantine_pending(void) { return legacy_pending; }
/* CDX's own parked backlog, as a count. It may only be released once a
 * barrier completed after it was parked; a case parking entries clears
 * legacy_proven, and every completed sync sets it. */
static bool legacy_proven;
static unsigned legacy_freed;
/* Park entries as a failed CDX barrier does: after every sync so far. */
static void park_legacy(unsigned n) { legacy_pending += n; legacy_proven = false; }
/* The FMans the installed DPA configuration spans, read under the mutex. */
static uint32_t fmans = 1;
static unsigned warnings;
static uint32_t dpa_get_num_fmans(void) { lockdep_assert_held(&cdx_info->ctrl.mutex); return fmans; }
/* Once per call site, as the kernel's: a second refusal adds no line. */
#define pr_warn_once(...) ({ static bool warned_; if (!warned_) { warned_ = true; warnings++; } })
/* Time, for the admission retry's once-a-second bound. */
static unsigned long jiffies = 1000;
#define HZ 100
#define time_before(a, b) ((long)((a) - (b)) < 0)
/* SAs and multicast groups installed through the other two backends, which the
 * idle answer counts along with this one's directions. */
static unsigned sa_owned, mc_owned;
static unsigned int cdx_ipsec_sa_count(void) { assert(cdx_info->ctrl.mutex); return sa_owned; }
static unsigned int cdx_mc_group_count(void) { assert(cdx_info->ctrl.mutex); return mc_owned; }
static unsigned allocations, deletes, syncs;
static bool fail_alloc, fail_insert, fail_sync, stopped;
static unsigned fail_insert_after;
/* A barrier has completed since the ports were last found stopped: what a
 * stop let go of may be freed only then. fail_next_sync fails the sync that
 * counts it down to zero, the ones before it completing. */
static bool settled;
static unsigned fail_next_sync;
static int delete_result;
static union nf_inet_addr expected_src, expected_dst;
static u8 expected_family = AF_INET;
static __be16 expected_sport, expected_dport;
static unsigned expected_proto = IPPROTO_UDP;
/* The class the rule under test carries, so the encoder stub can require that
 * each nibble reached the field that reads it. */
static u16 expected_qos;
static bool expected_hairpin;
/* What the entry must carry as its own MTU. Ordinarily the flow's, but a
 * direction handed to SEC has to be given the egress port's instead: the
 * microcode adds the tunnel expansion before comparing, so a tunnel-reduced
 * bound rejects every full-size frame. */
static unsigned expected_mtu;
static u16 expected_sa, expected_in_sa;
/* Whether the SA cache still holds the outbound SA a direction names: handle
 * 7 it does, any other it does not. What the entry adds for SEC is the
 * direction's own, carried in the rule from admission. */
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
static unsigned sa_lookups;
static bool cdx_ipsec_sa_outbound(u16 handle)
{
    lockdep_assert_held(&cdx_info->ctrl.mutex);
    sa_lookups++;
    return handle == 7;
}
static u8 expected_expansion;
static struct cdx_l2_encap observed_encap;
static void *kzalloc(size_t n, int flags) { if(fail_alloc) return NULL; allocations++; return calloc(1,n); }
static void kfree(void *p) { assert(p && allocations); allocations--; free(p); }
static bool observed_encap_given;
static int insert_entry_in_classif_table_encap(PCtEntry ct, const struct cdx_l2_encap *encap)
{
    /* An untagged flow asks for no override at all, so it takes the same path
     * it took before tags existed; an override that describes nothing would
     * still subject it to the override's own refusals. */
    memset(&observed_encap, 0, sizeof(observed_encap));
    observed_encap_given = encap != NULL;
    if (encap) {
        assert(encap->num_ingress || encap->num_egress ||
               encap->ingress_pppoe || encap->egress_pppoe ||
               encap->ingress_tunnel.present || encap->egress_tunnel.present);
        observed_encap = *encap;
    }
    /* The encoding port's source address is the netdev's, and the backend no
     * longer copies it anywhere first. Admission has already refused any rule
     * whose src_mac disagrees with it, so the two match by construction. */
    assert(!memcmp((expected_hairpin ? in_iface : out_iface).eth_info.net_dev->dev_addr,
                   (u8[]){2,0,0,0,0,0}, 6));
    assert(ct->proto == expected_proto && ct->twin->proto == expected_proto);
    assert(ct->Sport == htons(1234) && ct->Dport == htons(5678));
    /* Ports always come from the twin object, in both families. */
    assert(ct->twin->Sport == expected_dport && ct->twin->Dport == expected_sport && ct->twin->twin == ct);
    if (expected_family == AF_INET6) {
        union nf_inet_addr source = v6(0x201), destination = v6(0x401);

        assert(ct->fftype == FFTYPE_IPV6 && ct->hash == expected_proto * 17);
        assert(!memcmp(ct->Saddr_v6, source.ip6, 16));
        /* The overlay trap: an intact destination proves no twin_* field was
         * written over its second half. */
        assert(!memcmp(ct->Daddr_v6, destination.ip6, 16));
        assert(!memcmp(ct->twin->Saddr_v6, expected_dst.ip6, 16));
        assert(!memcmp(ct->twin->Daddr_v6, expected_src.ip6, 16));
        unsigned expected_status = CONNTRACK_ORIG;
        if (!nf_inet_addr_cmp_local(&expected_src, &source) || expected_sport != ct->Sport)
            expected_status |= CONNTRACK_SNAT;
        if (!nf_inet_addr_cmp_local(&expected_dst, &destination) || expected_dport != ct->Dport)
            expected_status |= CONNTRACK_DNAT;
        if (expected_sa || expected_in_sa)
            expected_status |= CONNTRACK_SEC;
        assert(ct->status == expected_status);
    } else {
        assert(ct->fftype == FFTYPE_IPV4 && ct->hash == expected_proto * 13);
        assert(ct->Saddr_v4 == htonl(0xc0000201) && ct->Daddr_v4 == htonl(0xc6336401));
        assert(ct->twin_Saddr == expected_dst.ip && ct->twin_Daddr == expected_src.ip);
        assert(ct->twin_Sport == expected_dport && ct->twin_Dport == expected_sport);
        assert(ct->twin->Saddr_v4 == expected_dst.ip && ct->twin->Daddr_v4 == expected_src.ip);
        bool nat = expected_src.ip != ct->Saddr_v4 || expected_dst.ip != ct->Daddr_v4 ||
                   expected_sport != ct->Sport || expected_dport != ct->Dport;
        assert(ct->status == (CONNTRACK_ORIG | (nat ? CONNTRACK_NAT : 0) |
                              ((expected_sa || expected_in_sa) ? CONNTRACK_SEC : 0)));
    }
    /* The rule's three class nibbles reach three separate hardware fields. The
     * policer nibble is a plain profile number and is copied straight through,
     * with the valid bit always set -- profile 0 is the encoder's own default,
     * so a clear valid bit would select it anyway and a sentinel would collide
     * with the nibble that names it.
     *
     * Spelled out in nibbles rather than through the header's masks, as the
     * CtEntry bit positions above are: this stub is compiled before the
     * encoding header is included, and the caller builds its values from the
     * macros, so a shift that moved would fail there. */
    assert(ct->qosmark.queue == (expected_qos & 0xf));
    assert(ct->qosmark.chnl_id == ((expected_qos >> 4) & 0xf));
    assert(ct->qosmark.iqid == ((expected_qos >> 8) & 0xf));
    assert(ct->qosmark.iqid_valid);
    /* The remark's flag is conditional where the policer's is not, because
     * DSCP zero is a real codepoint and "remark to CS0" has to differ from
     * "do not remark". */
    assert(ct->qosmark.dscp_mark_flag == ((expected_qos >> 12) & 0x1));
    assert(ct->qosmark.dscp_mark_value == ((expected_qos >> 13) & 0x3f));
    assert(ct->pRtEntry->itf == (expected_hairpin ? &in_itf : &out_itf) && ct->pRtEntry->input_itf == &in_itf);
    assert(ct->pRtEntry->underlying_input_itf == &in_itf);
    assert(ct->pRtEntry->mtu == expected_mtu);
    assert(ct->hSAEntry[0] == expected_sa && ct->hSAEntry[1] == expected_in_sa);
    /* The expansion the entry adds before its size check is the one its MTU
     * was raised by, so the two cannot differ. */
    assert(ct->sec_expansion == expected_expansion);
    assert(!(ct->status & CONNTRACK_SEC) == !(expected_sa || expected_in_sa));
    assert(!memcmp(ct->pRtEntry->dstmac, (u8[]){2,3,4,5,6,7},6));
    if (fail_insert || (fail_insert_after && !--fail_insert_after)) return -1;
    ct->ct = kzalloc(sizeof(*ct->ct), GFP_KERNEL); assert(ct->ct);
    if (key) { assert(!older); older = key; }
    key = calloc(1,sizeof(*key)); assert(key); key->linked = true;
    ct->ct->handle = key; ct->ct->td = &in_itf; ct->ct->index = 1;
    return 0;
}
/* A completed sync proves every key unlinked before it, whichever table it
 * went through: the PCD is one. A key still linked is never proven. */
static void barrier(void)
{
    if (key && !key->linked) key->safe = true;
    if (older && !older->linked) older->safe = true;
    legacy_proven = true;
    if (stopped) settled = true;
}
static int ExternalHashTableDeleteKey(void *td, unsigned index, struct key *handle)
{
    assert(td == &in_itf && index == 1 && handle && (handle == key || handle == older) &&
           handle->linked);
    deletes++;
    if (delete_result == 0 || delete_result == EN_EHASH_DELETE_UNSYNCED) handle->linked = false;
    if (!delete_result) barrier();
    return delete_result;
}
/* The same delete without its sync, for a caller retiring many keys behind
 * one: a key it unlinks is reported unsynced, never deleted, and waits for a
 * barrier exactly as one whose own sync failed. A hard failure is the
 * delete's. */
static unsigned unlinks, delete_syncs;
static int ExternalHashTableUnlinkKey(void *td, unsigned index, struct key *handle)
{
    assert(td == &in_itf && index == 1 && handle && (handle == key || handle == older) &&
           handle->linked);
    unlinks++;
    if (delete_result != 0 && delete_result != EN_EHASH_DELETE_UNSYNCED)
        return delete_result;
    handle->linked = false;
    return EN_EHASH_DELETE_UNSYNCED;
}
static int ExternalHashTableFmPcdHcSync(void *td);
/* The sync a delete issues itself, asked for once for the unlinks above. Only
 * ever asked for while an unlinked key waits on it. */
static int ExternalHashTableDeleteSync(void *td)
{
    assert((key && !key->linked) || (older && !older->linked));
    delete_syncs++;
    return ExternalHashTableFmPcdHcSync(td);
}
static int ExternalHashTableFmPcdHcSync(void *td)
{
    assert(td == &in_itf);
    /* Only ever asked for while something unlinked waits on it, or behind
     * stopped ports, which it proves done with the tables. */
    assert((key && !key->linked) || (older && !older->linked) || legacy_pending || stopped);
    syncs++;
    if (fail_sync || (fail_next_sync && !--fail_next_sync)) return -1;
    barrier();
    return 0;
}
/* Whether the host-command channel has failed for good: a sync that fails
 * then can never complete. */
static bool hc_failed;
static bool ExternalHashTableHcFailed(void *td)
{
    assert(td == &in_itf && cdx_info->ctrl.mutex);
    return hc_failed;
}
static void ExternalHashTableEntryFree(struct key *handle)
{
    assert(handle && (handle == key || handle == older));
    assert(!handle->linked && (handle->safe || (stopped && settled)));
    if (handle == key) key = NULL; else older = NULL;
    free(handle);
}
static void cdx_ehash_quarantine_free_all(void)
{
    assert(!legacy_pending || legacy_proven || (stopped && settled));
    legacy_freed += legacy_pending;
    legacy_pending = 0;
}
/* CDX's own retry, compiled and tested in ehash_lifecycle.c: one sync through
 * a parked entry's table, releasing everything on success. */
static int cdx_ehash_quarantine_retry(void)
{
    if (!legacy_pending) return 0;
    if (ExternalHashTableFmPcdHcSync(&in_itf)) return -EAGAIN;
    cdx_ehash_quarantine_free_all();
    return 0;
}
static void hw_ct_get_active(struct hw_ct *ct) { ct->pkts = 99; ct->bytes = 12345; ct->timestamp = 321; }
/* The classifier ports. A stop answers what a case sets -- stopped and idle,
 * a port still finishing a frame, or ports no stop can vouch for -- and only
 * the first marks them stopped. A resume starts them again; it may only follow
 * a stop, under the RTNL hold that cleared the latch. */
static int stop_result;
static unsigned stops, resumes;
static bool ft_latched(void);
static int dpa_cfg_stop(void)
{
    assert(rtnl && cdx_info->ctrl.mutex);
    stops++;
    settled = false;
    if (stop_result == -EBUSY) return stop_result;
    stopped = true;
    return stop_result;
}
static int resume_result;
static int dpa_cfg_resume(void)
{
    assert(rtnl && cdx_info->ctrl.mutex && stopped && !ft_latched());
    resumes++;
    stopped = settled = false;
    return resume_result;
}
/* The table a barrier goes through when the restart has none of its own. With
 * none configured, no frame walks one, and the stop alone settles them. */
static bool no_table;
static void *dpa_get_ehash_td(void)
{
    assert(cdx_info->ctrl.mutex);
    if (no_table && stopped) settled = true;
    return no_table ? NULL : &in_itf;
}
/* CDX's record of keys a delete could not prove gone (cdx_ehash.c, exercised
 * in ehash_lifecycle.c): here a list of the keys, the one flag that a record
 * could not be made, and a resolver that answers what a case sets and
 * otherwise unlinks and frees every key -- only with the ports stopped. */
static struct key *abandoned[4];
static unsigned nabandoned, resolver_calls;
static bool record_fails, record_lost;
static int resolve_result;
static void cdx_ehash_abandon(void *td, uint16_t index, struct key *handle)
{
    /* Linked, or unlinked behind a barrier that cannot be had (stranded). */
    assert(cdx_info->ctrl.mutex && td == &in_itf && index == 1 && handle &&
           (handle->linked || !handle->safe));
    if (record_fails) { record_lost = true; return; }
    assert(nabandoned < sizeof(abandoned) / sizeof(abandoned[0]));
    abandoned[nabandoned++] = handle;
}
static bool cdx_ehash_abandoned_lost(void) { assert(cdx_info->ctrl.mutex); return record_lost; }
static int cdx_ehash_resolve_abandoned(unsigned int *resolved)
{
    assert(cdx_info->ctrl.mutex && rtnl && stopped && settled);
    resolver_calls++;
    *resolved = 0;
    if (resolve_result) return resolve_result;
    while (nabandoned) {
        struct key *gone = abandoned[--nabandoned];

        gone->linked = false;
        ExternalHashTableEntryFree(gone);
        (*resolved)++;
    }
    return 0;
}
/* IPsec's part of a restart: the FQID ranges held for a possibly linked key,
 * and the SAs a failed delete stranded. Both before the latch clears. */
static unsigned held_fqids, sa_restarts;
static unsigned cdx_dpa_ipsec_release_held_fqids(void)
{
    unsigned released = held_fqids;

    assert(cdx_info->ctrl.mutex && rtnl && stopped && ft_latched());
    held_fqids = 0;
    return released;
}
static void cdx_ipsec_sa_restarted(void)
{
    assert(cdx_info->ctrl.mutex && rtnl && stopped && ft_latched());
    sa_restarts++;
}
/* The adapter's restarted(), which takes the transaction itself. */
static unsigned notified;
static void cdx_ft_egress_restarted(void)
{
    assert(!cdx_info->ctrl.mutex && !rtnl);
    notified++;
}
#define time_after(a, b) time_before(b, a)
#define jiffies_to_msecs(j) ((unsigned)((j) * 1000 / HZ))
/* What the restart's resolver does with every recorded key once the ports are
 * stopped and a barrier has completed behind them, for the cases that
 * exercise the encoder rather than the latch: a possibly linked key is
 * recorded, never freed, until then. */
static void settle_abandoned(void)
{
    assert(stopped && settled);
    while (nabandoned) {
        struct key *gone = abandoned[--nabandoned];

        gone->linked = false;
        ExternalHashTableEntryFree(gone);
    }
}
#include "physical_production.inc"
/* The outer header the egress tunnel inserts is built by the same function
 * the legacy tunnel interface builds its own with, compiled from CDX rather
 * than restated: both owners have to put the same bytes on the wire, and a
 * copy here would agree with itself while the two diverged. */
#include "tunnel_types.inc"
#include "tunnel_production.inc"
#include "hardware_types.inc"
/* The free-list half of the statistics API lives in cdx_ifstats.c, beside the
 * lists it draws from; what the backend adds is the ownership check, so that
 * is what is exercised here and the pool itself is simulated. */
static struct cdx_ft_stats_slot ifstats_slot = { .rx_index = 0x80, .tx_index = 0x81 };
/* A tunnel device's record comes from the plain pool, whose indices carry no
 * timestamp flag; distinct from the session's so neither can stand in for it. */
static struct cdx_ft_stats_slot tunnel_slot = { .rx_index = 0x0c, .tx_index = 0x0d };
static bool ifstats_taken;
static int ifstats_alloc_error;
static unsigned ifstats_reads;
static int cdx_ft_ifstats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot)
{
    *slot = NULL;
    if (ifstats_alloc_error) return ifstats_alloc_error;
    if (ifstats_taken) return -ENOSPC;
    ifstats_taken = true;
    ifstats_slot.kind = kind;
    *slot = &ifstats_slot;
    return 0;
}
static void cdx_ft_ifstats_free(struct cdx_ft_stats_slot **slot)
{
    if (!*slot) return;
    assert(*slot == &ifstats_slot && ifstats_taken);
    ifstats_taken = false;
    *slot = NULL;
}
static void cdx_ft_ifstats_read(const struct cdx_ft_stats_slot *slot,
                                struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
    ifstats_reads++;
    if (rx) *rx = (struct cdx_ft_stats){ .bytes = slot ? 4096 : 0 };
    if (tx) *tx = (struct cdx_ft_stats){ .bytes = slot ? 8192 : 0 };
}
/* Publication is the fold's business, exercised in the ifstats harness; the
 * backend only has to pass it through under the transaction. */
static unsigned ifstats_publications;
static void cdx_ft_ifstats_publish(struct cdx_ft_stats_slot *slot, int ifindex,
                                   unsigned rx_overhead, unsigned tx_overhead)
{
    assert(slot == &ifstats_slot && ifstats_taken && ifindex);
    ifstats_publications++;
}
static void cdx_ft_ifstats_unpublish(struct cdx_ft_stats_slot *slot)
{
    assert(!slot || slot == &ifstats_slot);
}
/* An entry's hold on each record its opcodes name. What the last put does with
 * the record is the allocator's, exercised in the ifstats harness; here the
 * count is the whole of it, and a put nobody took is a double release. */
static void cdx_ft_ifstats_hold(struct cdx_ft_stats_slot *slot)
{
    assert(cdx_info->ctrl.mutex);
    slot->holds++;
}
static void cdx_ft_ifstats_put(struct cdx_ft_stats_slot *slot)
{
    /* With the ports stopped, only after a barrier behind them. */
    assert(cdx_info->ctrl.mutex && slot->holds && (!stopped || settled));
    slot->holds--;
}
static void cdx_ft_ifstats_retention(unsigned *retained, u64 *deferred)
{
    *retained = 0;
    *deferred = 0;
}
/* An entry's hold on the ingress policer profile its rule names, so the
 * profile's filter going cannot hand it to a new one while the entry still
 * meters against it. The pool behind the count is the police harness's; here
 * the count is the whole of it. Profile 0 is the default every flow meters
 * against and is not counted, as in cdx_police.c. */
static unsigned police_refs[CDX_FT_QOS_MAX_POLICER + 1];
static void cdx_police_profile_ref(u8 profile)
{
    assert(profile <= CDX_FT_QOS_MAX_POLICER);
    if (profile) police_refs[profile]++;
}
static void cdx_police_profile_unref(u8 profile)
{
    assert(profile <= CDX_FT_QOS_MAX_POLICER);
    if (!profile) return;
    assert(police_refs[profile] && (!stopped || settled));
    police_refs[profile]--;
}
/* The terminal latch's port-stop work. Queued is all the workqueue does here;
 * running it is the test's call, as the workqueue's would be, and a disabled
 * item queues nothing again. It takes the control lock, so it is never waited
 * for under it. */
struct work_struct { int unused; };
struct delayed_work {
    struct work_struct work;
    void (*func)(struct work_struct *work);
    bool queued, disabled;
    unsigned long delay;
};
#define DECLARE_DELAYED_WORK(n, f) struct delayed_work n = { .func = (f) }
static bool schedule_delayed_work(struct delayed_work *dwork, unsigned long delay)
{
    if (dwork->queued || dwork->disabled)
        return false;
    dwork->queued = true;
    dwork->delay = delay;
    return true;
}
static bool disable_delayed_work_sync(struct delayed_work *dwork)
{
    bool queued = dwork->queued;

    assert(!cdx_info->ctrl.mutex);
    dwork->queued = false;
    dwork->disabled = true;
    return queued;
}
static void run_delayed_work(struct delayed_work *dwork)
{
    assert(dwork->queued && !cdx_info->ctrl.mutex);
    dwork->queued = false;
    dwork->func(&dwork->work);
}
/* Declared by cdx_flowtable_backend.h, past the part this harness slices; the
 * work and the restart call them ahead of their definitions. */
int cdx_ft_recover(void);
unsigned int cdx_ft_pending(void);
struct cdx_ft_hw;
int cdx_ft_hw_del(struct cdx_ft_hw **hw);
void cdx_ft_fatal(void);
/* devman.c's resizer of a port's egress bound, counted. */
static unsigned follow_link_calls;
static struct net_device *followed;
static void dpa_fwd_cgr_follow_link(struct net_device *dev) { follow_link_calls++; followed = dev; }
#include "hardware_production.inc"
#include "backend_production.inc"

static bool ft_latched(void) { return ft_failed; }

/* A root outside the unicast delete path -- a multicast group's or an SA's --
 * that could not be provably unlinked: its owner records it and latches the
 * same failure, with the transaction held. */
static void latch_root(void)
{
    assert(!key && !ft_fatal_work.queued);
    key = calloc(1, sizeof(*key));
    assert(key);
    key->linked = true;
    cdx_ft_begin();
    cdx_ehash_abandon(&in_itf, 1, key);
    cdx_ft_fatal();
    assert(cdx_ft_failed());
    cdx_ft_end();
    assert(ft_fatal_work.queued && !ft_fatal_work.delay);
}

/* Run the work the way the workqueue would, until it stops queueing itself. */
static void run_until_idle(void)
{
    for (unsigned i = 0; ft_fatal_work.queued && i < 32; i++)
        run_delayed_work(&ft_fatal_work);
    assert(!ft_fatal_work.queued && !cdx_info->ctrl.mutex && !rtnl);
}

/* A latch that went terminal: the ports stay stopped, everything stays
 * refused, it says why once, and nothing queues the work again. Then a reboot,
 * as far as the latch goes: the key a failed delete may have left linked is
 * the reset's to reclaim. */
static void expect_terminal(const char *why, unsigned restarts)
{
    assert(ft_failed && ft_terminal && stopped && ft_restarts == restarts);
    assert(terminal_lines == 1 && strstr(terminal_line, why));
    cdx_ft_begin();
    assert(cdx_ft_terminal() && cdx_ft_claim() == -EOPNOTSUPP);
    cdx_ft_end();
    cdx_ft_begin(); cdx_ft_fatal(); cdx_ft_end();
    run_until_idle();
    assert(ft_terminal && stopped && ft_restarts == restarts && terminal_lines == 1);
    if (key && nabandoned) {
        assert(nabandoned == 1 && abandoned[0] == key);
        nabandoned = 0;
    }
    free(key); key = NULL;
    ft_failed = ft_terminal = record_lost = false;
    stopped = settled = false; terminal_lines = kept_lines = 0;
    ft_episode_start = ft_stopped_at = 0;
    ft_episode_resolved = ft_hw_tries = 0;
    ft_stall_reported = false;
    ft_restart_backoff = HZ;
}

/* Every way a restart is refused for the rest of the boot, the budget that
 * bounds how often one happens, its report when it stalls, the order it frees
 * in, and unload. */
static void test_restart_root(struct net_device *in, struct net_device *out,
                              struct netdev_notifier_info *info, const struct cdx_ft_rule *rule,
                              const struct cdx_ft_stats_binding *stats)
{
    unsigned restarts = ft_restarts;

    /* A root latched from outside the unicast path restarts the same way:
     * here it is the root's own record the restart settles. */
    latch_root();
    run_until_idle();
    assert(!ft_failed && !key && !nabandoned && ft_restarts == ++restarts && notified == 2);
    /* A record that could not be made leaves a key that may be linked and
     * that nothing knows of, so no restart can be proven safe: the ports stop
     * and stay stopped. The guard then keeps every port shut, with or
     * without an adapter, by object identity rather than by name. */
    unsigned resolves = resolver_calls, resumed = resumes;

    record_fails = true;
    latch_root();
    record_fails = false;
    run_until_idle();
    assert(!nabandoned && key->linked && resolver_calls == resolves && resumes == resumed);
    strcpy(out->name, "renamed");
    info->dev = out;
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, info) == -EIO);
    assert(cdx_ft_netdev_event(NULL, 999, info) == NOTIFY_DONE);
    struct net_device unrelated = *out;
    info->dev = &unrelated;
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, info) == NOTIFY_DONE);
    info->dev = in;
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, info) == -EIO);
    dpa_interface_info = NULL;
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, info) == NOTIFY_DONE);
    dpa_interface_info = &in_iface;
    /* A physical port's link coming up or changing speed resizes its egress
     * bounds, latch or not, and so does its MTU changing, carrier or not --
     * the bound on SEC's frames counts frames of the largest size it admits;
     * a link without carrier or a foreign device does not. */
    bool carrier = in->carrier;
    unsigned follows = follow_link_calls;
    in->carrier = true;
    assert(cdx_ft_netdev_event(NULL, NETDEV_UP, info) == NOTIFY_DONE);
    assert(follow_link_calls == follows + 1 && followed == in);
    assert(cdx_ft_netdev_event(NULL, NETDEV_CHANGE, info) == NOTIFY_DONE);
    assert(follow_link_calls == follows + 2);
    in->carrier = false;
    assert(cdx_ft_netdev_event(NULL, NETDEV_CHANGE, info) == NOTIFY_DONE);
    assert(follow_link_calls == follows + 2);
    assert(cdx_ft_netdev_event(NULL, NETDEV_CHANGEMTU, info) == NOTIFY_DONE);
    assert(follow_link_calls == follows + 3 && followed == in);
    info->dev = &unrelated;
    unrelated.carrier = true;
    assert(cdx_ft_netdev_event(NULL, NETDEV_UP, info) == NOTIFY_DONE);
    assert(cdx_ft_netdev_event(NULL, NETDEV_CHANGEMTU, info) == NOTIFY_DONE);
    assert(follow_link_calls == follows + 3);
    info->dev = in;
    in->carrier = carrier;
    strcpy(out->name, "out");
    expect_terminal("a possibly linked key could not be recorded", restarts);
    /* A table the resolver finds malformed. */
    latch_root();
    resolve_result = -ENOTRECOVERABLE;
    run_until_idle();
    resolve_result = 0;
    assert(resumes == resumed && key->linked);
    expect_terminal("a possibly linked key could not be settled", restarts);
    /* A host-command channel that has failed for good: no barrier will ever
     * complete, so a failed one is not worth waiting for. One that merely
     * failed is (above). */
    latch_root();
    fail_sync = true; hc_failed = true;
    run_until_idle();
    fail_sync = false; hc_failed = false;
    expect_terminal("the host-command channel has failed", restarts);
    /* Hardware that stops answering without saying so: a port that never
     * goes idle, or a barrier the channel keeps rejecting though it has not
     * failed for good. Each is retried a quarter-second apart, and the
     * dozenth unanswered try in an episode -- a few seconds in, long before
     * a stall would be reported -- leaves the latch for a reboot, saying what
     * it waited for. Recovery then keeps stopping the port until it does go
     * idle, as it always did. */
    unsigned stalls = stall_lines;

    latch_root();
    stop_result = -EBUSY;
    for (unsigned i = 1; i < FT_RESTART_HW_TRIES; i++) {
        run_delayed_work(&ft_fatal_work);
        assert(ft_fatal_work.queued && ft_fatal_work.delay == FT_RESTART_HW_RETRY);
        assert(ft_hw_tries == i && !ft_terminal && !terminal_lines);
    }
    run_delayed_work(&ft_fatal_work);
    assert(ft_terminal && terminal_lines == 1 && stall_lines == stalls && key->linked);
    /* Terminal with the port still busy: recovery keeps trying to stop it,
     * but ever more rarely -- each try holds RTNL through the whole wait for
     * idle -- and between tries asks nothing of RTNL. */
    unsigned tries = stops;
    assert(ft_recover_backoff == HZ);
    for (unsigned i = 0; i < 5; i++)
        run_delayed_work(&ft_fatal_work);
    assert(stops == tries && ft_fatal_work.queued);
    jiffies += HZ + 1;
    run_delayed_work(&ft_fatal_work);
    assert(stops == tries + 1 && ft_recover_backoff == 2 * HZ);
    jiffies += 2 * HZ + 1;
    run_delayed_work(&ft_fatal_work);
    assert(stops == tries + 2 && ft_recover_backoff == 4 * HZ);
    for (unsigned i = 0; i < 10; i++) {
        jiffies += FT_RESTART_BACKOFF_MAX + 1;
        run_delayed_work(&ft_fatal_work);
    }
    assert(ft_recover_backoff == FT_RESTART_BACKOFF_MAX && ft_terminal);
    stop_result = 0;
    jiffies += FT_RESTART_BACKOFF_MAX + 1;
    run_until_idle();
    assert(!ft_recover_next && !ft_recover_backoff);
    expect_terminal("a port would not stop and go idle", restarts);
    latch_root();
    fail_sync = true;
    for (unsigned i = 1; i < FT_RESTART_HW_TRIES; i++) {
        run_delayed_work(&ft_fatal_work);
        assert(ft_fatal_work.delay == FT_RESTART_HW_RETRY && !ft_terminal);
    }
    run_delayed_work(&ft_fatal_work);
    assert(ft_terminal && stall_lines == stalls && key->linked);
    fail_sync = false;
    run_until_idle();
    expect_terminal("the PCD barrier kept failing", restarts);
    /* Ports that were detached: stopped, but never to be started again. The
     * adapter's recovery says the same, and still settles what they let go
     * of behind a barrier. */
    latch_root();
    stop_result = -ENOTRECOVERABLE;
    run_until_idle();
    cdx_ft_begin();
    assert(cdx_ft_recover() == 0 && settled);
    cdx_ft_end();
    stop_result = 0;
    expect_terminal("cannot be started again", restarts);
    /* A port outside CDX's configuration reaching a classifier: no stop of
     * CDX's own vouches for the tables, now or later. */
    resolves = resolver_calls;
    latch_root();
    stop_result = -EXDEV;
    run_until_idle();
    assert(!settled && resolver_calls == resolves && key->linked);
    stop_result = 0;
    expect_terminal("a port CDX did not configure reaches the classifier", restarts);
    /* Without a table to barrier through, the restart has nothing parked to
     * prove either; it starts the ports all the same, and ports that will not
     * start are counted and reported without holding the others up or the
     * latch: the tables are settled. */
    unsigned unstarted = ft_resume_failures, unstarted_lines = resume_lines;
    no_table = true; resume_result = 2;
    latch_root();
    run_until_idle();
    assert(!ft_failed && resumes == resumed + 1 && ft_restarts == ++restarts);
    cdx_ft_begin();
    assert(cdx_ft_resume_failures() == unstarted + 2 && resume_lines == unstarted_lines + 1);
    cdx_ft_end();
    assert(strstr(resume_line, "2 classifier ports did not start again"));
    no_table = false; resume_result = 0;
    /* The budget: as many restarts as the limit allows within a window,
     * counted from the first -- three so far, the unicast one included --
     * and then the latch is for a reboot. A window that has passed allows
     * them again. */
    assert(ft_restart_limit == 3 && ft_window_restarts == 3 && restarts == 3);
    latch_root();
    run_until_idle();
    expect_terminal("restart budget exhausted", restarts);
    jiffies += FT_RESTART_WINDOW + 1;
    latch_root();
    run_until_idle();
    assert(!ft_failed && ft_restarts == ++restarts && ft_window_restarts == 1);
    /* A limit of zero allows none: the old behaviour, by choice. */
    ft_restart_limit = 0;
    latch_root();
    run_until_idle();
    expect_terminal("datapath restarts are disabled", restarts);
    ft_restart_limit = 3;
    jiffies += FT_RESTART_WINDOW + 1;
    /* A restart still waiting after half a minute says so, once, and keeps
     * trying; the restart that finally comes resets the report. */
    latch_root();
    resolve_result = -EAGAIN;
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_failed && !stall_lines);
    jiffies += FT_RESTART_STALL + 1;
    run_delayed_work(&ft_fatal_work);
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_failed && stall_lines == 1);
    /* However long it stalls, the retries never space out past the bound. */
    for (unsigned i = 0; i < 8; i++)
        run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.delay == FT_RESTART_BACKOFF_MAX && stall_lines == 1);
    resolve_result = 0;
    run_until_idle();
    assert(!ft_failed && ft_restarts == ++restarts && stall_lines == 1 && !ft_stall_reported);
    /* Whatever holds it up: RTNL contended for as long, or the test image's
     * hold, is reported the same way, once, naming what it waits for, at the
     * steady interval each is retried at. */
    latch_root();
    rtnl_busy = true;
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == FT_RESTART_RTNL_RETRY && stall_lines == 1);
    jiffies += FT_RESTART_STALL + 1;
    run_delayed_work(&ft_fatal_work);
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.delay == FT_RESTART_RTNL_RETRY && stall_lines == 2);
    assert(strstr(stall_line, "RTNL is contended") && ft_failed && !ft_terminal);
    rtnl_busy = false;
    run_until_idle();
    assert(!ft_failed && ft_restarts == ++restarts);
    latch_root();
    ft_restart_hold = true;
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == FT_RESTART_HOLD_RETRY && stall_lines == 2);
    jiffies += FT_RESTART_STALL + 1;
    run_delayed_work(&ft_fatal_work);
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.delay == FT_RESTART_HOLD_RETRY && stall_lines == 3);
    assert(strstr(stall_line, "flowtable_restart_hold") && ft_failed && !ft_terminal);
    ft_restart_hold = false;
    run_until_idle();
    assert(!ft_failed && ft_restarts == ++restarts && !ft_stall_reported);
    jiffies += FT_RESTART_WINDOW + 1;
    /* RTNL contended between the hardware's tries counts for nothing,
     * however long: one try short of the bound, a hundred contended passes,
     * and the port that then goes idle still restarts the datapath. The next
     * episode starts with no tries spent. */
    latch_root();
    stop_result = -EBUSY;
    for (unsigned i = 1; i < FT_RESTART_HW_TRIES; i++)
        run_delayed_work(&ft_fatal_work);
    stop_result = 0;
    rtnl_busy = true;
    for (unsigned i = 0; i < 100; i++)
        run_delayed_work(&ft_fatal_work);
    assert(ft_hw_tries == FT_RESTART_HW_TRIES - 1 && !ft_terminal && ft_failed);
    rtnl_busy = false;
    run_until_idle();
    assert(!ft_failed && !ft_terminal && ft_restarts == ++restarts && !ft_hw_tries);
    jiffies += FT_RESTART_WINDOW + 1;
    /* The restart frees nothing its stop let go of until a barrier has
     * completed behind the stopped ports: stop, then barrier, then any free.
     * Here it finds both kinds of retired entry itself, nothing having
     * recovered first -- one unlinked whose barrier failed, and one whose
     * delete may have left it linked. */
    {
        struct cdx_ft_hw *first = NULL, *second = NULL;
        unsigned before;

        cdx_ft_begin();
        assert(cdx_ft_claim() == 0 && cdx_ft_admission_begin() == 0);
        assert(cdx_ft_add(rule, stats, &first) == 0 && cdx_ft_add(rule, stats, &second) == 0);
        cdx_ft_admission_end();
        assert(older && key);
        fail_sync = true;
        delete_result = EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_del(&first) == -EAGAIN && !older->linked && !older->safe);
        delete_result = -1;
        assert(cdx_ft_del(&second) == -EIO && key->linked && cdx_ft_failed());
        assert(cdx_ft_pending() == 2 && cdx_ft_release() == 0);
        cdx_ft_end();
        fail_sync = false; delete_result = 0;
        before = syncs;
        run_until_idle();
        assert(!ft_failed && ft_restarts == ++restarts && !key && !older && !nabandoned);
        assert(syncs == before + 2 && !allocations && !stopped);
    }
    /* Unload disables the work for good, held in the middle of a restart or
     * not: neither a later latch nor the work's own retry can queue it past
     * the module, and the ports stay stopped for unload's own quiesce. */
    latch_root();
    ft_restart_hold = true;
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && stopped && ft_failed);
    cdx_ft_fatal_stop();
    assert(!ft_fatal_work.queued && ft_fatal_work.disabled);
    cdx_ft_begin(); cdx_ft_fatal(); cdx_ft_end();
    assert(!ft_fatal_work.queued && ft_failed && stopped && ft_restarts == restarts);
    ft_restart_hold = false;
    /* Unload's own quiesce then frees the retiring storage and records the
     * key; the module's exit settles or leaks it (ehash_lifecycle.c). */
    nabandoned = 0;
    free(key); key = NULL;
    cdx_flowtable_guard_exit();
    assert(!notifier_registered && !ft_guard_registered);
    cdx_flowtable_guard_exit();
    assert(!cdx_info->ctrl.mutex && !rtnl && !allocations);
}

static void test_backend(void)
{
    struct net_device in = { .name="in", .net=&init_net, .type=ARPHRD_ETHER,
        .addr_len=ETH_ALEN, .reg_state=NETREG_REGISTERED, .mtu=1500, .running=true, .carrier=true, .dev_addr={2}, .perm_addr={2} };
    struct net_device out = in;
    strcpy(out.name, "out");
    in_iface.eth_info.net_dev = &in; out_iface.eth_info.net_dev = &out;
    struct cdx_ft_rule rule = { .in=&in, .out=&out, .family=AF_INET, .src.ip=htonl(0xc0000201), .dst.ip=htonl(0xc6336401),
        .sport=htons(1234), .dport=htons(5678), .proto=IPPROTO_UDP, .src_mac={2}, .dst_mac={2,3,4,5,6,7}, .mtu=1200 };
    /* Untagged, so the logical device and the port are the same object --
     * which is what the rule's own contract says they are without a tag. */
    rule.in_logical = &in; rule.out_logical = &out;
    expected_mtu = 1200;
    rule.new_src = expected_src = rule.src; rule.new_dst = expected_dst = rule.dst;
    rule.new_sport = expected_sport = rule.sport; rule.new_dport = expected_dport = rule.dport;
    struct cdx_ft_hw *hw = NULL;
    /* No session by default, so every case that is not about statistics
     * passes a binding naming none -- which is what the encoder then has to
     * turn into an index of zero rather than an index at all. */
    struct cdx_ft_stats_binding stats = {};
    expected_proto = IPPROTO_UDP;
    cdx_info->ctrl.mutex = false;
    assert(!cdx_ft_observing());
    fail_notifier=true;
    assert(cdx_flowtable_guard_init() == -ENOMEM && !ft_guard_registered);
    cdx_flowtable_guard_exit(); fail_notifier=false;
    assert(cdx_flowtable_guard_init() == 0 && notifier_registered);
    struct netdev_notifier_info info = {&out};
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == NOTIFY_DONE);
    /* The transaction without waiting for it: taken when free, refused
     * while anything holds it, and then the caller's to end. */
    assert(cdx_ft_trybegin() && cdx_info->ctrl.mutex);
    assert(!cdx_ft_trybegin() && cdx_info->ctrl.mutex);
    cdx_ft_end();
    assert(!cdx_info->ctrl.mutex);
    cdx_ft_begin();
    /* A statistics slot is backend-owned like anything else it hands out, so
     * it is refused before the claim. Freeing nothing is always a no-op,
     * which is what every error path relies on. */
    {
        struct cdx_ft_stats_slot *slot = (void *)1;

        assert(cdx_ft_stats_alloc(CDX_FT_STATS_TIMESTAMPED, &slot) == -EOPNOTSUPP && !slot);
        cdx_ft_stats_free(&slot);
        assert(!ifstats_taken);
    }
    /* A configuration spanning two FMans is refused outright, and before
     * the claim retries a parked backlog: that barrier would release it on
     * one PCD's sync alone. The refusal neither fails the backend nor seals
     * the config, and says why once however often the load is retried. */
    park_legacy(1);
    unsigned tries = syncs;
    fmans = 2;
    assert(cdx_ft_claim() == -EOPNOTSUPP && warnings == 1);
    assert(syncs == tries && legacy_pending == 1);
    assert(!cdx_ft_failed());
    assert(cdx_ft_claim() == -EOPNOTSUPP && warnings == 1 && syncs == tries);
    fmans = 1;
    /* A backlog CDX parked for itself refuses the claim only while its
     * barrier keeps failing: the claim retries it, once per attempt. */
    fail_sync=true;
    assert(cdx_ft_claim() == -EBUSY);
    assert(syncs == tries + 1 && legacy_pending == 1);
    fail_sync=false;
    assert(cdx_ft_claim() == 0);
    assert(syncs == tries + 2 && !legacy_pending);
    assert(cdx_ft_claim() == -EBUSY && syncs == tries + 2);
    /* The pool itself, through the backend's ownership check: one record at a
     * time here, a kind that reaches the free lists unchanged, a read that
     * reports each half, and a free that returns it. */
    {
        struct cdx_ft_stats_slot *slot = NULL, *second = NULL;
        struct cdx_ft_stats rx, tx;
        unsigned reads = ifstats_reads;

        assert(cdx_ft_stats_alloc(CDX_FT_STATS_TIMESTAMPED, &slot) == 0 && slot);
        assert(slot->kind == CDX_FT_STATS_TIMESTAMPED);
        assert(cdx_ft_stats_alloc(CDX_FT_STATS_TIMESTAMPED, &second) == -ENOSPC && !second);
        cdx_ft_stats_read(slot, &rx, &tx);
        assert(ifstats_reads == reads + 1 && rx.bytes == 4096 && tx.bytes == 8192);
        cdx_ft_stats_free(&slot);
        assert(!slot && !ifstats_taken);
        assert(cdx_ft_stats_alloc(CDX_FT_STATS_PLAIN, &slot) == 0 &&
               slot->kind == CDX_FT_STATS_PLAIN);
        cdx_ft_stats_free(&slot);
        cdx_ft_stats_free(&slot);
        ifstats_alloc_error = -ENOMEM;
        assert(cdx_ft_stats_alloc(CDX_FT_STATS_TIMESTAMPED, &slot) == -ENOMEM && !slot);
        ifstats_alloc_error = 0;
    }
    rtnl_busy=true; assert(cdx_ft_admission_begin() == -EAGAIN && !rtnl && cdx_info->ctrl.mutex);
    rtnl_busy=false; assert(cdx_ft_admission_begin() == 0);
    assert(cdx_ft_port_supported(&in) && cdx_ft_port_supported(&out));
    assert(!cdx_ft_port_supported(NULL));
    out.net=&other_net; assert(!cdx_ft_port_supported(&out)); out.net=&init_net;
    /* A VRF slave moves the route lookup somewhere this contract cannot
     * follow, and a switch ASIC's port lets the bridge mark a VLAN as already
     * stripped in hardware with nothing in the rule naming it. An enslaved
     * port is no longer refused at all, so there is nothing here to assert
     * about one: the gate has stopped reading that state.
     */
    out.l3_slave=true; assert(!cdx_ft_port_supported(&out)); out.l3_slave=false;
    out.switch_port=true; assert(!cdx_ft_port_supported(&out)); out.switch_port=false;
    out.carrier=false; assert(!cdx_ft_port_supported(&out)); out.carrier=true;
    out.running=false; assert(!cdx_ft_port_supported(&out)); out.running=true;
    out.dev_addr[5]=1; assert(cdx_ft_port_supported(&out));
    assert(cdx_ft_add(&rule,&stats,&hw)==-EOPNOTSUPP && !hw); out.dev_addr[5]=0;
    out.reg_state=0; assert(!cdx_ft_port_supported(&out)); out.reg_state=NETREG_REGISTERED;
    out.type=0; assert(!cdx_ft_port_supported(&out)); out.type=ARPHRD_ETHER;
    out.addr_len=0; assert(!cdx_ft_port_supported(&out)); out.addr_len=ETH_ALEN;
    strcpy(out.name,"renamed"); assert(cdx_ft_port_supported(&out)); strcpy(out.name,"out");
    out_itf.type=2; assert(!cdx_ft_port_supported(&out)); out_itf.type=129;
    in_iface.next=NULL; assert(!cdx_ft_port_supported(&out)); in_iface.next=&out_iface;
    out_onif.flags=0; assert(!cdx_ft_port_supported(&out)); out_onif.flags=ENTRY_VALID;
    out_iface.itf_id=L2_MAX_ONIF; assert(!cdx_ft_port_supported(&out)); out_iface.itf_id=2;
    out_iface.eth_info.net_dev=&in; assert(!cdx_ft_port_supported(&out)); out_iface.eth_info.net_dev=&out;
    ft_observe=true; assert(cdx_ft_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw); ft_observe=false;
    /* The same backlog refuses admission, and admission is what retries its
     * barrier in steady state -- at most once a second, not once per flow. */
    park_legacy(1); fail_sync=true; tries=syncs;
    assert(cdx_ft_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw && syncs == tries + 1);
    jiffies += HZ - 1;
    assert(cdx_ft_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw && syncs == tries + 1);
    jiffies += 1; fail_sync=false;
    assert(cdx_ft_add(&rule,&stats,&hw) == 0 && hw && syncs == tries + 2 && !legacy_pending);
    assert(cdx_ft_del(&hw) == 0 && !hw && !ft_live && !key);
    /* With nothing pending, admission issues no barrier at all. */
    assert(cdx_ft_add(&rule,&stats,&hw) == 0 && syncs == tries + 2);
    assert(cdx_ft_del(&hw) == 0 && !hw && !ft_live && !key);
    /* A direction that names an SA. Each end lands in its own slot and marks
     * the entry secure, and the *sending* end's MTU has SEC's expansion put
     * back on: the microcode adds it before comparing, so the flow's inner
     * bound alone rejects every full-size frame and sends it to the CPU
     * instead. That failure is invisible to a functional test -- the entry
     * matches and counts either way -- so it is pinned here.
     *
     * The bound under the expansion is the bundle's, which Linux enforces:
     * the smaller of the SA's MTU and the inner route's. Netfilter hands
     * over the bundle's when the packet that created the flow was
     * transformed (1438) and the plain inner route's when it was the reply
     * (1500 on the port's own MTU), and either way the entry must answer
     * above 1438; an inner route with an MTU of its own (1400, 1200) is the
     * bound, where the egress port's MTU alone let 1401..1438 through. An
     * egress device smaller than the path caps it.
     *
     * The SA's bound and the expansion are the direction's, from the outer
     * path at admission, not the SA's from its install: a peer behind a
     * 1492-byte hop gives AES-CBC/SHA256 1422 and 70, a port lowered to
     * 1480 gives 1406 and 74, and the entry follows each -- the SA's own
     * figures, 1438 and 62 from a 1500-byte port, would let 1423..1438 and
     * 1407..1418 through. The entry adds the same expansion it was raised
     * by. */
    rule.sa_handle = expected_sa = 7;
    {
        static const struct {
            unsigned flow, sa, expansion, port, entry;
        } bounds[] = {
            { 1200, 1438, 62, 1500, 1262 }, { 1400, 1438, 62, 1500, 1462 },
            { 1438, 1438, 62, 1500, 1500 }, { 1500, 1438, 62, 1500, 1500 },
            { 1500, 1438, 62, 1480, 1480 }, { 1500, 1422, 70, 1500, 1492 },
            { 1400, 1422, 70, 1500, 1470 }, { 1480, 1406, 74, 1480, 1480 },
            { 9000, 8938, 62, 9000, 9000 },
        };
        unsigned saved = rule.mtu, i;

        for (i = 0; i < sizeof(bounds) / sizeof(bounds[0]); i++) {
            rule.mtu = bounds[i].flow;
            rule.sa_mtu = bounds[i].sa;
            rule.sa_expansion = expected_expansion = bounds[i].expansion;
            out.mtu = bounds[i].port;
            expected_mtu = bounds[i].entry;
            assert(cdx_ft_add(&rule,&stats,&hw) == 0 && hw);
            assert(cdx_ft_del(&hw) == 0 && !hw);
        }
        rule.mtu = saved;
        out.mtu = 1500;
    }
    /* A direction that names an SA without the bound admission works out
     * for it, or an SA the cache no longer holds, is refused before
     * anything is built. */
    rule.sa_expansion = 0;
    assert(cdx_ft_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw && !allocations);
    rule.sa_expansion = 62;
    rule.sa_mtu = 0;
    assert(cdx_ft_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw && !allocations);
    rule.sa_mtu = 1438;
    rule.sa_handle = expected_sa = 9;
    assert(cdx_ft_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw && !allocations);
    rule.sa_handle = expected_sa = 0;
    rule.sa_mtu = rule.sa_expansion = expected_expansion = 0;
    /* The receiving end takes no such correction: what it transmits is the
     * decrypted inner frame, so the flow's own bound is the right one. */
    rule.in_sa_handle = expected_in_sa = 8;
    expected_mtu = rule.mtu;
    assert(cdx_ft_add(&rule,&stats,&hw) == 0 && hw);
    assert(cdx_ft_del(&hw) == 0 && !hw);
    rule.in_sa_handle = expected_in_sa = 0;
    /* Exercise same-port translation through the provider's real admission
     * entry point as well as the lower encoder and adapter decoder. */
    rule.out = &in; expected_hairpin = true;
    rule.new_src = expected_src = v4(htonl(0xcb007104));
    rule.new_dst = expected_dst = v4(htonl(0xcb007105));
    rule.new_sport = expected_sport = htons(40000);
    rule.new_dport = expected_dport = htons(30000);
    assert(cdx_ft_add(&rule,&stats,&hw) == 0 && ft_live == 1);
    assert(cdx_ft_del(&hw) == 0 && !hw && !ft_live && !allocations);
    rule.out = &out; expected_hairpin = false;
    rule.new_src = expected_src = rule.src; rule.new_dst = expected_dst = rule.dst;
    rule.new_sport = expected_sport = rule.sport; rule.new_dport = expected_dport = rule.dport;
    fail_insert=true; assert(cdx_ft_add(&rule,&stats,&hw) == -EIO && !ft_live); fail_insert=false;
    assert(cdx_ft_add(&rule,&stats,&hw) == 0 && ft_live == 1);
    assert(cdx_ft_release() == -EBUSY && ft_claimed);
    struct cdx_ft_counters counters;
    cdx_ft_stats(hw,&counters); assert(counters.packets == 99);
    cdx_ft_admission_end();
    delete_result=EN_EHASH_DELETE_UNSYNCED;
    assert(cdx_ft_del(&hw) == -EAGAIN && !hw && !ft_live && !cdx_ft_failed());
    assert(cdx_ft_pending() == 1);
    fail_sync=true; assert(cdx_ft_recover() == -EAGAIN && key && !key->safe);
    assert(cdx_ft_release() == 0);
    assert(cdx_ft_claim() == -EBUSY);
    fail_sync=false; assert(cdx_ft_recover() == 0 && !key && !cdx_ft_pending());
    assert(cdx_ft_claim() == 0);
    assert(cdx_ft_admission_begin() == 0);
    assert(cdx_ft_add(&rule,&stats,&hw) == 0);
    cdx_ft_admission_end();
    /* An unlink leaves the live count at once and its barrier to the settle,
     * pending and owed until then; the settle issues the one barrier. A
     * failed settle fails nothing: what it leaves is an ordinary unproven
     * retirement, which the adapter's recovery retries. */
    {
        unsigned unproven = 99;

        tries = syncs;
        assert(cdx_ft_unlink(&hw) == 0 && !hw && !ft_live && !cdx_ft_failed());
        assert(cdx_ft_unlink(&hw) == 0 && !ft_live);
        assert(cdx_ft_owed() == 1 && cdx_ft_pending() == 1 && syncs == tries);
        assert(cdx_ft_settle(&unproven) == 0 && !unproven && syncs == tries + 1);
        assert(!cdx_ft_owed() && !cdx_ft_pending() && !key && !allocations);
        assert(cdx_ft_admission_begin() == 0);
        assert(cdx_ft_add(&rule,&stats,&hw) == 0);
        cdx_ft_admission_end();
        assert(cdx_ft_unlink(&hw) == 0 && cdx_ft_owed() == 1);
        fail_sync = true;
        assert(cdx_ft_settle(&unproven) == -EAGAIN && unproven == 1 && !cdx_ft_failed());
        assert(!cdx_ft_owed() && cdx_ft_pending() == 1 && !ft_fatal_work.queued);
        fail_sync = false;
        assert(cdx_ft_recover() == 0 && !cdx_ft_pending() && !key);
        assert(cdx_ft_admission_begin() == 0);
        assert(cdx_ft_add(&rule,&stats,&hw) == 0);
        cdx_ft_admission_end();
    }
    /* A delete that cannot be proven latches the failure, and the latch
     * queues the work that stops the datapath and then restarts it. The
     * adapter's own recovery only ever stops it: once the ports are stopped
     * and idle the retiring owner goes, and its key, which may still be
     * linked, is recorded rather than freed. A port still finishing a frame
     * frees and records nothing. */
    delete_result=-EIO;
    assert(cdx_ft_del(&hw) == -EIO && !hw && !ft_live && cdx_ft_failed());
    assert(ft_fatal_work.queued && !ft_fatal_work.delay);
    assert(cdx_ft_del(&hw) == 0 && cdx_ft_failed());
    rtnl_busy=true; assert(cdx_ft_recover() == -EAGAIN && !stops && key->linked);
    rtnl_busy=false; stop_result=-EBUSY;
    assert(cdx_ft_recover() == -EAGAIN && stops == 1 && !stopped && key->linked);
    assert(cdx_ft_pending() == 1 && !nabandoned && !stopped_lines);
    stop_result=0;
    /* A stop that found a port busy is not tried again at once: each try
     * holds RTNL through the whole wait for idle, and the adapter polls. */
    assert(cdx_ft_recover() == -EAGAIN && stops == 1 && !stopped);
    jiffies += FT_RESTART_HW_RETRY + 1;
    assert(cdx_ft_recover() == 0 && stopped && stops == 2 && key->linked);
    assert(nabandoned == 1 && abandoned[0] == key && stopped_lines == 1);
    assert(!allocations && !cdx_ft_pending() && cdx_ft_failed() && !cdx_ft_terminal());
    assert(cdx_ft_recover() == 0 && stops == 3 && nabandoned == 1 && stopped_lines == 1);
    assert(!resumes && !resolver_calls);
    /* While it is stopped nothing new is handed out, statistics included:
     * the adapter is on its way to a global recovery and a record claimed
     * now would be one nothing is going to return. */
    {
        struct cdx_ft_stats_slot *slot = (void *)1;

        assert(cdx_ft_stats_alloc(CDX_FT_STATS_TIMESTAMPED, &slot) == -EOPNOTSUPP && !slot);
        assert(!ifstats_taken);
    }
    assert(cdx_ft_release() == 0);
    assert(cdx_ft_claim() == -EOPNOTSUPP && cdx_ft_failed());
    assert(cdx_ft_admission_begin() == 0);
    assert(cdx_ft_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw);
    cdx_ft_admission_end();
    cdx_ft_end();
    /* Nor can a port be opened under it, with an adapter or without one. */
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == -EIO);
    /* The work restarts it. Contended RTNL is tried again soon, at a steady
     * interval, and changes nothing. */
    rtnl_busy = true; run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == HZ / 10 && stops == 3 && !resumes);
    rtnl_busy = false;
    /* A port still busy holds it up, retried soon at a steady interval --
     * the hardware answers in moments or not at all -- and nothing is
     * settled meanwhile. */
    stop_result = -EBUSY; run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == HZ / 4 && !resolver_calls && key->linked);
    run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == HZ / 4 && !resolver_calls && ft_hw_tries == 2);
    stop_result = 0;
    /* The test image's hold keeps the ports stopped, every key recorded, at
     * a steady poll that does not add to the backoff. */
    ft_restart_hold = true; run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == HZ / 4 && stopped);
    assert(!resolver_calls && key->linked && ft_failed);
    ft_restart_hold = false;
    /* A key the table still links -- its delete refused, for want of
     * memory most likely -- waits for the next try, backing off: memory
     * comes back on its own time, not the hardware's. */
    resolve_result = -EAGAIN; run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == HZ && resolver_calls == 1);
    assert(key->linked && !resumes && ft_failed);
    resolve_result = 0;
    /* The barrier behind the stopped ports fails: a frame they let go of may
     * still be in the controller, so nothing is settled or freed, and they
     * stay stopped. */
    unsigned before = syncs;
    fail_sync = true; run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == HZ / 4 && syncs == before + 1);
    assert(key->linked && nabandoned == 1 && resolver_calls == 1 && !resumes && ft_failed);
    fail_sync = false;
    /* Settled behind a completed one, but the barrier after it fails, so the
     * ports stay stopped. */
    before = syncs;
    fail_next_sync = 2; run_delayed_work(&ft_fatal_work);
    assert(ft_fatal_work.queued && ft_fatal_work.delay == HZ / 4 && syncs == before + 2);
    assert(ft_hw_tries == 4);
    assert(!key && !nabandoned && resolver_calls == 2 && !resumes && ft_failed);
    /* With the barrier the restart completes in one transaction and one
     * RTNL hold: what CDX parked for a barrier is released, the FQIDs held
     * for the key go back, the epoch moves on, a stranded SA is installed
     * again, and the latch clears as the ports start. The adapter is told
     * once, after both locks are gone. */
    held_fqids = 2; park_legacy(1);
    unsigned epoch = ft_epoch;
    run_delayed_work(&ft_fatal_work);
    assert(!ft_fatal_work.queued && !ft_failed && !ft_terminal && resumes == 1 && !stopped);
    assert(ft_restarts == 1 && ft_epoch == epoch + 1 && notified == 1 && sa_restarts == 1);
    assert(!held_fqids && !legacy_pending && !terminal_lines && restart_lines == 1);
    assert(strstr(restart_line, "(1 keys resolved, 2 FQID ranges released, stopped "));
    assert(!cdx_info->ctrl.mutex && !rtnl && !allocations);
    /* And everything is open again: a port, the claim, admission. */
    assert(cdx_ft_netdev_event(NULL, NETDEV_PRE_UP, &info) == NOTIFY_DONE);
    cdx_ft_begin();
    assert(cdx_ft_claim() == 0 && !cdx_ft_failed() && cdx_ft_restarts() == 1);
    assert(cdx_ft_admission_begin() == 0);
    delete_result = 0;
    assert(cdx_ft_add(&rule,&stats,&hw) == 0 && hw && key);
    cdx_ft_admission_end();
    assert(cdx_ft_del(&hw) == 0 && !key && !allocations);
    assert(cdx_ft_release() == 0);
    cdx_ft_end();
    /* With no adapter registered to ask, CDX asks this whether anything the
     * adapter installed is still in the hardware -- a direction, or an SA or
     * a multicast group, which an adapter on its way out retires only after
     * it has stopped answering. Each one alone is an answer of "not idle". */
    assert(cdx_ft_idle() && !cdx_info->ctrl.mutex);
    sa_owned = 1; assert(!cdx_ft_idle()); sa_owned = 0;
    mc_owned = 1; assert(!cdx_ft_idle()); mc_owned = 0;
    legacy_pending = 1; assert(!cdx_ft_idle()); legacy_pending = 0;
    assert(cdx_ft_idle() && !cdx_info->ctrl.mutex);
    /* A port outside CDX's configuration reaching the classifier: the latch
     * cannot restart, and the adapter's recovery keeps what was retired,
     * records and all, rather than freeing it on a stop that proves nothing.
     * The backend lets go of it, so nothing waits on it either. */
    cdx_ft_begin();
    assert(cdx_ft_claim() == 0 && cdx_ft_admission_begin() == 0);
    assert(cdx_ft_add(&rule,&stats,&hw) == 0 && key);
    cdx_ft_admission_end();
    delete_result = -1;
    assert(cdx_ft_del(&hw) == -EIO && cdx_ft_failed() && cdx_ft_pending() == 1);
    stop_result = -EXDEV;
    assert(cdx_ft_recover() == 0 && ft_terminal && !settled && kept_lines == 1);
    assert(key->linked && nabandoned == 1 && abandoned[0] == key && !cdx_ft_pending());
    assert(!allocations && cdx_ft_release() == 0);
    cdx_ft_end();
    run_until_idle();
    stop_result = 0; delete_result = 0;
    expect_terminal("a port CDX did not configure reaches the classifier", ft_restarts);
    test_restart_root(&in, &out, &info, &rule, &stats);
}

static void test_tunnel_keys(void)
{
    for (unsigned ipv6 = 0; ipv6 < 2; ipv6++) {
        CtEntry ct = { .fftype = ipv6 ? FFTYPE_IPV6 : FFTYPE_IPV4, .proto = IPPROTO_UDP };
        struct cdx_l2_encap encap = {0};
        uint8_t key[44], changed[44];
        unsigned size = ipv6 ? 18 : 43, offset = ipv6 ? 12 : 8, addresses = ipv6 ? 8 : 32;

        memset(key, 0xff, sizeof(key));
        assert(fill_tunnel_key(&ct, NULL, key) == size);
        assert(key[0] == IPPROTO_UDP && key[size] == 0xff);
        for (unsigned i = 1; i < size; i++) assert(!key[i]);
        encap.ingress_tunnel.present = 1;
        encap.ingress_tunnel.header[ipv6 ? 9 : 6] = ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP;
        for (unsigned i = 0; i < addresses; i++) encap.ingress_tunnel.header[offset + i] = i + 1;
        assert(fill_tunnel_key(&ct, &encap, key) == size);
        assert(!key[0] && key[1] == (ipv6 ? IPPROTO_IPV6 : IPPROTO_IPIP));
        for (unsigned i = 0; i < addresses; i++) {
            assert(key[i + 2] == i + 1);
            encap.ingress_tunnel.header[offset + i] ^= 0x80;
            assert(fill_tunnel_key(&ct, &encap, changed) == size);
            assert(memcmp(changed, key, size));
            encap.ingress_tunnel.header[offset + i] ^= 0x80;
        }
        if (!ipv6) {
            assert(key[34] == 0x45);
            encap.ingress_tunnel.header[6] = IPPROTO_DSTOPTS;
            assert(fill_tunnel_key(&ct, &encap, changed) == size);
            assert(changed[1] == IPPROTO_DSTOPTS && changed[34] == IPPROTO_IPIP);
            assert(!memcmp(key + 2, changed + 2, 32));
        }
        assert(key[size] == 0xff);
        encap.ingress_pppoe = 1;
        encap.ingress_session_id = 0x1234;
        memcpy(encap.ingress_session_mac, (uint8_t[]){2, 3, 4, 5, 6, 7}, 6);
        assert(fill_tunnel_key(&ct, &encap, changed) == size);
        assert(!memcmp(changed + size - 8, (uint8_t[]){2, 3, 4, 5, 6, 7, 0x12, 0x34}, 8));
        for (unsigned i = 0; i < 6; i++) {
            encap.ingress_session_mac[i] ^= 0x80;
            assert(fill_tunnel_key(&ct, &encap, key) == size);
            assert(memcmp(key, changed, size));
            encap.ingress_session_mac[i] ^= 0x80;
        }
        encap.ingress_session_id++;
        assert(fill_tunnel_key(&ct, &encap, key) == size);
        assert(memcmp(key, changed, size));
    }
}

int main(void)
{
    test_tunnel_keys();
    /* The ports carry the address the rule claims as its source. That is not
     * decoration: admission refuses any direction whose src_mac is not the
     * egress port's current address, so a fixture where they disagree
     * describes a rule the backend can never be handed. It used to be able to
     * disagree, because the backend copied the rule's value into the
     * interface record before encoding; the encoder reads the netdev now. */
    struct net_device in = { .name = "in", .mtu = 1500, .dev_addr = {2} },
                      out = { .name = "out", .mtu = 1500, .dev_addr = {2} };
    struct cdx_ft_rule rule = { .in=&in, .out=&out, .in_logical=&in, .out_logical=&out,
        .family=AF_INET, .src.ip=htonl(0xc0000201), .dst.ip=htonl(0xc6336401),
        .sport=htons(1234), .dport=htons(5678), .proto=IPPROTO_UDP, .src_mac={2}, .dst_mac={2,3,4,5,6,7}, .mtu=1200 };
    expected_mtu = 1200;
    rule.new_src = expected_src = rule.src; rule.new_dst = expected_dst = rule.dst;
    rule.new_sport = expected_sport = rule.sport; rule.new_dport = expected_dport = rule.dport;
    struct cdx_ft_hw *hw;
    struct cdx_ft_counters counters;
    struct cdx_ft_stats_binding stats = {};
    in_iface.eth_info.net_dev=&in; out_iface.eth_info.net_dev=&out;
    fail_alloc = true; assert(cdx_ft_hw_add(&rule,&stats,&hw) == -ENOMEM && !hw); fail_alloc=false;
    fail_insert=true; assert(cdx_ft_hw_add(&rule,&stats,&hw) == -EIO && !allocations); fail_insert=false;
    out_itf.type = 2; assert(cdx_ft_hw_add(&rule,&stats,&hw) == -EOPNOTSUPP); out_itf.type=129;
    rule.proto = IPPROTO_ICMP; assert(cdx_ft_hw_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw);
    for(unsigned i=0; i<128; i++) {
        rule.proto = expected_proto = (i & 1) ? IPPROTO_TCP : IPPROTO_UDP;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        cdx_ft_hw_stats(hw,&counters); assert(counters.packets==99 && counters.bytes==12345 && counters.lastused==321);
        /* No allocation is possible once deletion starts. */
        fail_alloc=true; assert(cdx_ft_hw_del(&hw) == 0 && !hw && !key && !allocations); fail_alloc=false;
        unsigned old=deletes; assert(cdx_ft_hw_del(&hw)==0 && deletes==old);
    }
    rule.proto = expected_proto = IPPROTO_UDP;
    /* Every combination the class encoding admits, so no nibble can be dropped,
     * shifted into another field or left selecting profile zero when the flow
     * asked for none. The insert callback does the checking. */
    for (unsigned queue = 0; queue <= 15; queue++)
        for (unsigned channel = 0; channel <= CDX_FT_QOS_MAX_CHANNEL; channel++)
            for (unsigned policer = 0; policer <= CDX_FT_QOS_MAX_POLICER; policer++) {
                rule.qos = expected_qos = queue |
                        (channel << CDX_FT_QOS_CHANNEL_SHIFT) |
                        (policer << CDX_FT_QOS_POLICER_SHIFT);
                assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
                assert(police_refs[policer] == !!policer);
                assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
                assert(!police_refs[policer]);
            }
    rule.qos = expected_qos = 0;
    for (unsigned i = 0; i < 16; i++) {
        unsigned variant = i % 8;
        expected_hairpin = variant == 7;
        rule.out = expected_hairpin ? &in : &out;
        rule.proto = expected_proto = i < 8 ? IPPROTO_UDP : IPPROTO_TCP;
        rule.new_src = expected_src = variant == 0 || variant == 4 || variant >= 6 ? v4(htonl(0xcb007104)) : rule.src;
        rule.new_dst = expected_dst = variant == 1 || variant == 5 || variant >= 6 ? v4(htonl(0xcb007104)) : rule.dst;
        rule.new_sport = expected_sport = variant == 2 || variant == 4 || variant >= 6 ? htons(40000) : rule.sport;
        rule.new_dport = expected_dport = variant == 3 || variant == 5 || variant >= 6 ? htons(40000) : rule.dport;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
        fail_insert=true; assert(cdx_ft_hw_add(&rule,&stats,&hw) == -EIO && !allocations); fail_insert=false;
    }
    expected_hairpin = false; rule.out = &out;
    /* The same translation matrix one family over. The encoder gates each
     * IPv6 rewrite on its own status bit instead of comparing addresses, and
     * every twin_* field it must not touch overlays the destination address,
     * so both halves are checked on each variant by the insert callback. */
    expected_family = rule.family = AF_INET6;
    rule.src = v6(0x201); rule.dst = v6(0x401);
    for (unsigned i = 0; i < 16; i++) {
        unsigned variant = i % 8;
        rule.proto = expected_proto = i < 8 ? IPPROTO_UDP : IPPROTO_TCP;
        rule.new_src = expected_src = variant == 0 || variant == 4 || variant >= 6 ? v6(0x104) : rule.src;
        rule.new_dst = expected_dst = variant == 1 || variant == 5 || variant >= 6 ? v6(0x105) : rule.dst;
        rule.new_sport = expected_sport = variant == 2 || variant == 4 || variant >= 6 ? htons(40000) : rule.sport;
        rule.new_dport = expected_dport = variant == 3 || variant == 5 || variant >= 6 ? htons(40000) : rule.dport;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
    }
    /* An unrecognised family is refused rather than silently encoded as IPv4. */
    rule.family = AF_UNSPEC; assert(cdx_ft_hw_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw);
    expected_family = rule.family = AF_INET;
    rule.src = v4(htonl(0xc0000201)); rule.dst = v4(htonl(0xc6336401));
    rule.proto = expected_proto = IPPROTO_UDP;

    /* Encapsulation. The rule orders its tags outermost first; the L2
     * description the header manipulation reads orders them innermost first,
     * because it is normally built by walking a VLAN interface up towards its
     * parent. Getting that reversal wrong swaps a QinQ pair on the wire and
     * nothing else would notice, so it is asserted tag by tag. */
    assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
    assert(!observed_encap_given);
    assert(cdx_ft_hw_del(&hw) == 0);
    rule.in_vlans = 1;
    rule.in_vlan[0] = (struct cdx_ft_vlan){ .proto = htons(ETH_P_8021Q), .id = 200 };
    rule.out_vlans = 2;
    rule.out_vlan[0] = (struct cdx_ft_vlan){ .proto = htons(ETH_P_8021Q), .id = 100 };
    rule.out_vlan[1] = (struct cdx_ft_vlan){ .proto = htons(ETH_P_8021Q), .id = 300 };
    assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
    assert(observed_encap_given);
    assert(observed_encap.num_ingress == 1 && observed_encap.num_egress == 2);
    assert(observed_encap.ingress[0].tci == 200 && observed_encap.ingress[0].tpid == 0x8100);
    /* Innermost first here: the rule's outer 100 lands last. */
    assert(observed_encap.egress[0].tci == 300 && observed_encap.egress[0].tpid == 0x8100);
    assert(observed_encap.egress[1].tci == 100 && observed_encap.egress[1].tpid == 0x8100);
    assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
    rule.in_vlans = rule.out_vlans = 0;
    memset(rule.in_vlan, 0, sizeof(rule.in_vlan));
    memset(rule.out_vlan, 0, sizeof(rule.out_vlan));

    /* A PPPoE session on its own asks for an override even though it carries
     * no tag at all, which is the one shape a tag-count test would miss. The
     * ingress and egress identities reach the encoder independently. */
    rule.out_session = (struct cdx_ft_session){ .mac = {2,0xac,0,0,0,1},
                                                .id = 0x1234, .present = true };
    rule.in_session = (struct cdx_ft_session){ .mac = {2,0xac,0,0,0,2},
                                               .id = 0x5678, .present = true };
    assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
    assert(observed_encap_given);
    assert(!observed_encap.num_ingress && !observed_encap.num_egress);
    assert(observed_encap.egress_pppoe && observed_encap.ingress_pppoe);
    assert(observed_encap.egress_session_id == 0x1234);
    assert(!memcmp(observed_encap.egress_session_mac, (u8[]){2,0xac,0,0,0,1}, 6));
    assert(observed_encap.ingress_session_id == 0x5678);
    assert(!memcmp(observed_encap.ingress_session_mac, (u8[]){2,0xac,0,0,0,2}, 6));
    /* A session with no record leaves both indices at zero, which the opcodes
     * read as no record rather than as record zero. */
    assert(!observed_encap.ingress_stats_index && !observed_encap.egress_stats_index);
    assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
    /* And with one, each direction takes the half its own encapsulation
     * counts into: a strip counts receives, an insert counts transmits. */
    stats.in_session = stats.out_session = &ifstats_slot;
    assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
    assert(observed_encap.ingress_stats_index == ifstats_slot.rx_index);
    assert(observed_encap.egress_stats_index == ifstats_slot.tx_index);
    assert(ifstats_slot.rx_index != ifstats_slot.tx_index);
    assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
    /* One direction with a record and one without keeps them apart. */
    stats.in_session = NULL;
    assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
    assert(!observed_encap.ingress_stats_index);
    assert(observed_encap.egress_stats_index == ifstats_slot.tx_index);
    assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
    stats.out_session = NULL;
    /* A session inside a tag: both descriptions travel together, and the tag
     * still reverses while the session does not. */
    rule.out_vlans = 1;
    rule.out_vlan[0] = (struct cdx_ft_vlan){ .proto = htons(ETH_P_8021Q), .id = 100 };
    assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
    assert(observed_encap.num_egress == 1 && observed_encap.egress[0].tci == 100);
    assert(observed_encap.egress_pppoe && observed_encap.egress_session_id == 0x1234);
    assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
    rule.out_vlans = 0;
    memset(rule.out_vlan, 0, sizeof(rule.out_vlan));
    rule.in_session = rule.out_session = (struct cdx_ft_session){};
    /* And with neither, the override is withheld again. */
    assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
    assert(!observed_encap_given);
    assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);

    /* An IP-in-IP tunnel, which asks for an override with no tag and no
     * session either. The egress side is the interesting half: the header is
     * built here rather than carried in the rule, so what the hardware
     * inserts and what software would insert are the same bytes only if this
     * builds them the same way -- which is why it is the production builder
     * that runs, and why every field of the result is pinned. */
    {
        const struct cdx_tunnel_encap *egress = &observed_encap.egress_tunnel;
        const struct cdx_tunnel_encap *ingress = &observed_encap.ingress_tunnel;
        const union nf_inet_addr local4 = v4(htonl(0xc0a80a01));
        const union nf_inet_addr remote4 = v4(htonl(0xcb0071c8));
        const union nf_inet_addr local6 = v6(0x901), remote6 = v6(0x902);

        /* 6o4: an IPv4 outer header around an IPv6 flow. The tunnel device is
         * doing path MTU discovery, so the hop records DF -- and the header
         * built here still leaves the fragment word clear, because the
         * INSERT_L3_HDR opcode fills that field itself and ignores the
         * template's, exactly as the legacy owner found. */
        rule.out_tunnel = (struct cdx_ft_tunnel){
            .local = local4, .remote = remote4, .nexthop = v4(htonl(0xc0a80afe)),
            .ifindex = 18, .lower_ifindex = 6, .mode = CDX_FT_TUNNEL_6O4,
            .family = AF_INET, .proto = 41, .ttl = 64, .tos = 0,
            .flags = CDX_FT_TUNNEL_DF, .header_size = 20, .present = true };
        /* The microcode compares the *outer* frame against the entry's bound,
         * and Netfilter's MTU is the tunnel device's, already reduced by the
         * header. Leaving it reduced rejects every full-size frame to the
         * CPU, which looks like offload and performs like software. */
        expected_mtu = rule.mtu + 20;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(observed_encap_given && egress->present && !ingress->present);
        assert(!observed_encap.num_ingress && !observed_encap.num_egress);
        assert(!observed_encap.ingress_pppoe && !observed_encap.egress_pppoe);
        assert(egress->mode == TNL_MODE_6O4 && egress->header_size == 20);
        assert(!egress->flags);
        assert(egress->header[0] == 0x45 && !egress->header[1]);
        /* Total length, identification, the fragment word and the checksum
         * are the microcode's, per packet, and are all left zero here -- the
         * fragment word including the DF the hop recorded. */
        assert(!egress->header[2] && !egress->header[3]);
        assert(!egress->header[4] && !egress->header[5]);
        assert(!egress->header[6] && !egress->header[7]);
        assert(egress->header[8] == 64 && egress->header[9] == 41);
        assert(!egress->header[10] && !egress->header[11]);
        assert(!memcmp(egress->header + 12, &local4.ip, 4));
        assert(!memcmp(egress->header + 16, &remote4.ip, 4));
        /* Nothing past the size it declared. */
        assert(!egress->header[20]);
        /* With no record the index is zero, which the opcode reads as no
         * record rather than as record zero. */
        assert(!egress->stats_index);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);

        /* With one, the insert counts into its transmit half. */
        stats.out_tunnel = &tunnel_slot;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(egress->stats_index == tunnel_slot.tx_index);
        assert(tunnel_slot.rx_index != tunnel_slot.tx_index);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
        stats.out_tunnel = NULL;

        /* A tunnel that never asked for DF produces the same bytes, which is
         * the point: the flag reaches the rule and stops there. */
        rule.out_tunnel.flags = 0;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(!egress->flags && !egress->header[6] && !egress->header[7]);
        assert(egress->header[0] == 0x45 && egress->header[9] == 41);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);

        /* Ingress carries the receiving endpoints for the classifier and
         * the strip's mode, size, DSCP flag and receive record. */
        rule.out_tunnel = (struct cdx_ft_tunnel){};
        rule.in_tunnel = (struct cdx_ft_tunnel){
            .local = local4, .remote = remote4, .ifindex = 19,
            .lower_ifindex = 5, .mode = CDX_FT_TUNNEL_6O4, .family = AF_INET,
            .proto = 41, .ttl = 64, .flags = CDX_FT_TUNNEL_DSCP_COPY,
            .header_size = 20, .present = true };
        stats.in_tunnel = &tunnel_slot;
        expected_mtu = rule.mtu;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(observed_encap_given && ingress->present && !egress->present);
        assert(ingress->mode == TNL_MODE_6O4 && ingress->header_size == 20);
        assert(ingress->flags == DSCP_COPY);
        assert(ingress->stats_index == tunnel_slot.rx_index);
        assert(!ingress->header[0]);
        assert(ingress->header[9] == IPPROTO_IPV6);
        assert(!memcmp(ingress->header + 12, &remote4.ip, 4));
        assert(!memcmp(ingress->header + 16, &local4.ip, 4));
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
        stats.in_tunnel = NULL;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(!ingress->stats_index);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
        rule.in_tunnel = (struct cdx_ft_tunnel){};

        /* 4o6 with an inherited traffic class: the outer IPv6 header takes
         * the flag rather than a value, and the recorded class is zero. */
        rule.out_tunnel = (struct cdx_ft_tunnel){
            .local = local6, .remote = remote6, .ifindex = 20,
            .lower_ifindex = 6, .mode = CDX_FT_TUNNEL_4O6, .family = AF_INET6,
            .proto = 4, .ttl = 63, .tos = 0, .flowlabel = htonl(0x12345),
            .flags = CDX_FT_TUNNEL_INHERIT_TOS, .header_size = 40,
            .present = true };
        expected_mtu = rule.mtu + 40;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(egress->present && egress->mode == TNL_MODE_4O6);
        assert(egress->header_size == 40 && egress->flags == INHERIT_TC);
        /* Version 6, traffic class zero, and the flow label the walk recorded. */
        assert(egress->header[0] == 0x60 && egress->header[1] == 0x01);
        assert(egress->header[2] == 0x23 && egress->header[3] == 0x45);
        assert(!egress->header[4] && !egress->header[5]);
        assert(egress->header[6] == 4 && egress->header[7] == 63);
        assert(!memcmp(egress->header + 8, local6.ip6, 16));
        assert(!memcmp(egress->header + 24, remote6.ip6, 16));
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);

        /* And a fixed traffic class, which lands in the header instead of in
         * a flag: CS1 is 0x20, so the first byte reads 0x62. */
        rule.out_tunnel.flags = 0;
        rule.out_tunnel.tos = 0x20;
        rule.out_tunnel.flowlabel = 0;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(!egress->flags && egress->header[0] == 0x62);
        assert(!egress->header[1] && !egress->header[2] && !egress->header[3]);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);

        /* Both receive forms are owned together, count together, and hold
         * the shared receive record until both hardware keys are gone. */
        struct cdx_ft_tunnel saved_tunnel = rule.out_tunnel;
        rule.in_tunnel = saved_tunnel;
        rule.out_tunnel = (struct cdx_ft_tunnel){};
        expected_mtu = rule.mtu;
        stats.in_tunnel = &tunnel_slot;
        assert(cdx_ft_hw_add(&rule, &stats, &hw) == 0 && hw->options);
        assert(key && older && tunnel_slot.holds == 2);
        assert(ingress->header[6] == IPPROTO_DSTOPTS);
        assert(!memcmp(ingress->header + 8, remote6.ip6, 16));
        assert(!memcmp(ingress->header + 24, local6.ip6, 16));
        struct cdx_ft_counters combined;
        cdx_ft_hw_stats(hw, &combined);
        assert(combined.packets == 198 && combined.bytes == 24690 && combined.lastused == 321);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !older && !allocations && !tunnel_slot.holds);
        fail_insert_after = 2;
        assert(cdx_ft_hw_add(&rule, &stats, &hw) == -EIO && !hw);
        assert(!key && !older && !allocations && !tunnel_slot.holds);
        assert(cdx_ft_hw_add(&rule, &stats, &hw) == 0);
        delete_result = EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_hw_del(&hw) == -EAGAIN && !hw && cdx_ft_hw_pending() == 2);
        assert(tunnel_slot.holds == 2);
        delete_result = 0;
        assert(cdx_ft_hw_retry() == 0 && !key && !older && !allocations && !tunnel_slot.holds);
        /* Unlinked with the barrier deferred, the options entry goes the way
         * the entry it belongs to goes: both unlinked without a sync, both
         * owed, the shared record held, and one settle proves the two. */
        {
            unsigned syncs_before = syncs, deletes_before = deletes, unlinks_before = unlinks;
            unsigned barriers = delete_syncs, unproven = 99;

            assert(cdx_ft_hw_add(&rule, &stats, &hw) == 0 && hw->options);
            assert(cdx_ft_hw_unlink(&hw) == 0 && !hw && !key->linked && !older->linked);
            assert(unlinks == unlinks_before + 2 && deletes == deletes_before);
            assert(syncs == syncs_before && cdx_ft_hw_pending() == 2 && cdx_ft_hw_owed() == 2);
            assert(tunnel_slot.holds == 2);
            assert(cdx_ft_hw_settle(&unproven) == 0 && !unproven);
            assert(syncs == syncs_before + 1 && delete_syncs == barriers + 1);
            assert(!cdx_ft_hw_pending() && !cdx_ft_hw_owed());
            assert(!key && !older && !allocations && !tunnel_slot.holds);
        }
        stats.in_tunnel = NULL;
        rule.out_tunnel = saved_tunnel;
        rule.in_tunnel = (struct cdx_ft_tunnel){};
        expected_mtu = rule.mtu + 40;

        /* A size the builder disagrees with means admission and the encoder
         * are describing different headers, which is refused rather than
         * encoded as whichever of the two the hardware happens to read. */
        rule.out_tunnel.mode = CDX_FT_TUNNEL_6O4;
        rule.out_tunnel.family = AF_INET;
        rule.out_tunnel.local = local4;
        rule.out_tunnel.remote = remote4;
        assert(rule.out_tunnel.header_size == 40);
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == -EOPNOTSUPP && !hw && !allocations);
        rule.out_tunnel = (struct cdx_ft_tunnel){};
        expected_mtu = rule.mtu;
    }
    rule.new_src = expected_src = rule.src; rule.new_dst = expected_dst = rule.dst;
    rule.new_sport = expected_sport = rule.sport; rule.new_dport = expected_dport = rule.dport;
    assert(cdx_ft_hw_add(&rule,&stats,&hw)==0);
    delete_result=EN_EHASH_DELETE_UNSYNCED; fail_alloc=true;
    assert(cdx_ft_hw_del(&hw)==-EAGAIN && !hw && key && !key->linked && allocations==2);
    assert(cdx_ft_hw_pending()==1); unsigned old=deletes;
    fail_sync=true; assert(cdx_ft_hw_retry()==-EAGAIN && key && !key->safe && deletes==old);
    fail_sync=false; assert(cdx_ft_hw_retry()==0 && !key && !allocations && deletes==old);
    fail_alloc=false;
    assert(cdx_ft_hw_add(&rule,&stats,&hw)==0); assert(cdx_ft_hw_del(&hw)==-EAGAIN);
    /* Stopped ports, and a barrier completed behind them. */
    stopped=settled=true; cdx_ft_hw_quiesced(); stopped=settled=false;
    assert(!key && !allocations && !cdx_ft_hw_pending());
    assert(cdx_ft_hw_add(&rule,&stats,&hw)==0); delete_result=-1;
    assert(cdx_ft_hw_del(&hw)==-EIO && key->linked && cdx_ft_hw_pending()==1);
    old=syncs; assert(cdx_ft_hw_retry()==-EAGAIN && syncs==old && key->linked);
    /* The stopped ports free the retiring owner and record the potentially
     * linked allocation, which only the restart's resolver frees. */
    stopped=settled=true; cdx_ft_hw_quiesced(); assert(!allocations && key->linked);
    assert(nabandoned == 1 && abandoned[0] == key);
    cdx_ft_hw_quiesced(); assert(nabandoned == 1);
    settle_abandoned(); assert(!key);
    stopped=settled=false; delete_result=0;
    assert(cdx_ft_hw_add(&rule,&stats,&hw)==0);
    ft_fail_unlink=true; old=deletes;
    assert(cdx_ft_hw_del(&hw)==-EIO && !hw && !ft_fail_unlink);
    assert(deletes==old && key->linked && cdx_ft_hw_pending()==1);
    old=syncs; assert(cdx_ft_hw_retry()==-EAGAIN && syncs==old && key->linked);
    stopped=settled=true; cdx_ft_hw_quiesced(); assert(!allocations && key->linked);
    assert(nabandoned == 1 && abandoned[0] == key);
    settle_abandoned(); stopped=settled=false;
    assert(cdx_ft_hw_add(&rule,&stats,&hw)==0);
    assert(cdx_ft_hw_del(&hw)==0 && !hw && !key && !allocations);
    /* One completed barrier proves every unlink before it -- the backend's
     * own retired entries and the backlog CDX parked for itself alike -- so
     * whichever path completes one releases them all. */
    {
        struct cdx_ft_hw *live = NULL;
        unsigned freed = legacy_freed;

        /* A delete that syncs releases a retired entry and the backlog. */
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0);
        delete_result=EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_hw_del(&hw)==-EAGAIN && cdx_ft_hw_pending()==1);
        park_legacy(2);
        delete_result=0;
        assert(cdx_ft_hw_add(&rule,&stats,&live)==0 && older && !older->linked && !older->safe);
        old=syncs;
        assert(cdx_ft_hw_del(&live)==0 && !live && syncs==old);
        assert(!key && !older && !cdx_ft_hw_pending() && !legacy_pending);
        assert(legacy_freed==freed+2 && !allocations);

        /* Two retired entries and the backlog take one sync between them;
         * a failed one keeps all three and says so. */
        delete_result=EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0 && cdx_ft_hw_del(&hw)==-EAGAIN);
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0 && cdx_ft_hw_del(&hw)==-EAGAIN);
        assert(cdx_ft_hw_pending()==2 && key && older);
        park_legacy(1); freed=legacy_freed;
        fail_sync=true; old=syncs;
        assert(cdx_ft_hw_retry()==-EAGAIN && syncs==old+1);
        assert(cdx_ft_hw_pending()==2 && legacy_pending==1 && !key->safe && !older->safe);
        fail_sync=false; old=syncs;
        assert(cdx_ft_hw_retry()==0 && syncs==old+1);
        assert(!cdx_ft_hw_pending() && !legacy_pending && legacy_freed==freed+1);
        assert(!key && !older && !allocations);

        /* With nothing retired of its own, the backlog gets exactly one sync,
         * and a failed one is the backlog's to report, not the backend's. */
        park_legacy(2); freed=legacy_freed;
        fail_sync=true; old=syncs;
        assert(cdx_ft_hw_retry()==0 && syncs==old+1 && legacy_pending==2);
        fail_sync=false; old=syncs;
        assert(cdx_ft_hw_retry()==0 && syncs==old+1 && !legacy_pending);
        assert(legacy_freed==freed+2);
        old=syncs;
        assert(cdx_ft_hw_retry()==0 && syncs==old);

        /* A key a hard failure may have left linked is never freed, by a
         * retry's barrier or by a later delete's. */
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0);
        delete_result=-1;
        assert(cdx_ft_hw_del(&hw)==-EIO && key->linked && cdx_ft_hw_pending()==1);
        park_legacy(1); old=syncs;
        assert(cdx_ft_hw_retry()==-EAGAIN && syncs==old+1 && !legacy_pending);
        assert(key->linked && cdx_ft_hw_pending()==1);
        delete_result=0;
        assert(cdx_ft_hw_add(&rule,&stats,&live)==0 && older && older->linked);
        assert(cdx_ft_hw_del(&live)==0 && !key && older->linked && cdx_ft_hw_pending()==1);
        stopped=settled=true; cdx_ft_hw_quiesced();
        assert(!allocations && !cdx_ft_hw_pending() && older->linked);
        /* Recorded for the restart, whose resolver alone frees it. */
        assert(nabandoned == 1 && abandoned[0] == older);
        settle_abandoned(); stopped=settled=false;
        assert(!older);
    }
    /* Retiring many keys behind one barrier: an unlink issues none and leaves
     * its owner retired and owed, and the settle that follows proves every
     * unsynced owner with a single one -- owed, or left by a delete whose own
     * barrier failed -- and CDX's parked backlog with them. */
    {
        struct cdx_ft_hw *first = NULL;
        unsigned barriers, freed, unproven;

        delete_result = EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_hw_add(&rule,&stats,&first)==0 && cdx_ft_hw_del(&first)==-EAGAIN);
        assert(cdx_ft_hw_pending()==1 && !cdx_ft_hw_owed());
        /* Nothing owed: no barrier, whatever else is pending. */
        old=syncs; unproven=99;
        assert(cdx_ft_hw_settle(&unproven)==0 && !unproven && syncs==old);
        assert(cdx_ft_hw_pending()==1 && key && !key->safe);
        delete_result = 0;
        old=deletes; unsigned unlinked=unlinks; barriers=syncs;
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0 && older && key->linked);
        assert(cdx_ft_hw_unlink(&hw)==0 && !hw && !key->linked && !key->safe);
        assert(unlinks==unlinked+1 && deletes==old && syncs==barriers);
        assert(cdx_ft_hw_pending()==2 && cdx_ft_hw_owed()==1 && allocations);
        park_legacy(1); freed=legacy_freed;
        old=delete_syncs;
        assert(cdx_ft_hw_settle(&unproven)==0 && !unproven);
        assert(syncs==barriers+1 && delete_syncs==old+1);
        assert(!cdx_ft_hw_pending() && !cdx_ft_hw_owed() && !key && !older && !allocations);
        assert(!legacy_pending && legacy_freed==freed+1);

        /* A barrier that fails leaves every owed owner an ordinary unproven
         * retirement, says how many, and owes nothing more: the next settle
         * asks for no barrier, and the retry that does releases them. */
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0 && cdx_ft_hw_unlink(&hw)==0);
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0 && cdx_ft_hw_unlink(&hw)==0);
        assert(cdx_ft_hw_pending()==2 && cdx_ft_hw_owed()==2);
        fail_sync=true; old=syncs; barriers=delete_syncs;
        assert(cdx_ft_hw_settle(&unproven)==-EAGAIN && unproven==2);
        assert(syncs==old+1 && delete_syncs==barriers+1);
        assert(cdx_ft_hw_pending()==2 && !cdx_ft_hw_owed() && !key->safe && !older->safe);
        fail_sync=false; old=syncs;
        assert(cdx_ft_hw_settle(&unproven)==0 && !unproven && syncs==old);
        assert(cdx_ft_hw_pending()==2);
        assert(cdx_ft_hw_retry()==0 && syncs==old+1);
        assert(!cdx_ft_hw_pending() && !key && !older && !allocations);

        /* The debug knob's withheld proof reaches the settle that asks for it,
         * never the unlink, which has no barrier of its own to withhold: the
         * settle fails without issuing one, exactly as a failed one. */
        ft_fail_sync = 1;
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0 && cdx_ft_hw_unlink(&hw)==0);
        assert(ft_fail_sync==1 && cdx_ft_hw_owed()==1);
        old=syncs;
        assert(cdx_ft_hw_settle(&unproven)==-EAGAIN && unproven==1 && syncs==old);
        assert(!ft_fail_sync && !cdx_ft_hw_owed() && cdx_ft_hw_pending()==1 && key);
        assert(cdx_ft_hw_retry()==0 && syncs==old+1 && !key && !allocations);

        /* A hard failure is the delete's: never owed, never proven by a
         * settle, kept for the stopped ports. */
        delete_result = -1;
        assert(cdx_ft_hw_add(&rule,&stats,&hw)==0 && cdx_ft_hw_unlink(&hw)==-EIO && !hw);
        assert(key->linked && cdx_ft_hw_pending()==1 && !cdx_ft_hw_owed());
        old=syncs;
        assert(cdx_ft_hw_settle(&unproven)==0 && !unproven && syncs==old && key->linked);
        stopped=settled=true; cdx_ft_hw_quiesced();
        assert(!allocations && !cdx_ft_hw_pending() && nabandoned==1 && abandoned[0]==key);
        settle_abandoned(); stopped=settled=false;
        delete_result = 0;
    }
    /* Every record an entry's opcodes can name is held by the entry itself for
     * as long as the microcode may walk it, whatever the adapter does with its
     * own hold: taken once the key is linked, one per name, and given back
     * only by what proves the entry gone -- its own synced delete, the barrier
     * that settles it once retired, or quiescence whichever way its delete
     * failed. A record back in the pool early is a free-list link the
     * microcode can still overwrite, and a record the next device is handed
     * while the old entry still counts into it. The policer profile the rule
     * names is held the same way, and for the same reason: a profile back in
     * the pool early is reprogrammed for a new filter while the entry still
     * meters against it. */
    {
        struct cdx_ft_stats_slot vlan_slot = { .rx_index = 0x10, .tx_index = 0x11 };
        struct cdx_ft_hw *live = NULL;
        unsigned before, policer = 3;

        delete_result = 0;
        stats = (struct cdx_ft_stats_binding){
            .in_session = &ifstats_slot, .out_session = &ifstats_slot,
            .out_tunnel = &tunnel_slot,
            .in_vlan = { &vlan_slot }, .out_vlan = { NULL, &vlan_slot } };
        rule.qos = expected_qos = policer << CDX_FT_QOS_POLICER_SHIFT;
        fail_insert = true;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == -EIO && !hw);
        assert(!ifstats_slot.holds && !tunnel_slot.holds && !vlan_slot.holds);
        assert(!police_refs[policer]);
        fail_insert = false;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        assert(ifstats_slot.holds == 2 && tunnel_slot.holds == 1 && vlan_slot.holds == 2);
        assert(police_refs[policer] == 1);
        assert(cdx_ft_hw_del(&hw) == 0 && !key && !allocations);
        assert(!ifstats_slot.holds && !tunnel_slot.holds && !vlan_slot.holds);
        assert(!police_refs[policer]);

        /* Retired: held through a barrier that fails, given back by the one
         * that completes. */
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        delete_result = EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_hw_del(&hw) == -EAGAIN && ifstats_slot.holds == 2 && vlan_slot.holds == 2);
        fail_sync = true;
        assert(cdx_ft_hw_retry() == -EAGAIN && ifstats_slot.holds == 2 && tunnel_slot.holds == 1);
        assert(police_refs[policer] == 1);
        fail_sync = false;
        assert(cdx_ft_hw_retry() == 0 && !cdx_ft_hw_pending() && !key);
        assert(!ifstats_slot.holds && !tunnel_slot.holds && !vlan_slot.holds);
        assert(!police_refs[policer]);

        /* And by a later delete's own sync, which proves it too. */
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0 && cdx_ft_hw_del(&hw) == -EAGAIN);
        delete_result = 0;
        assert(cdx_ft_hw_add(&rule,&stats,&live) == 0 && ifstats_slot.holds == 4);
        assert(cdx_ft_hw_del(&live) == 0 && !cdx_ft_hw_pending() && !key && !older);
        assert(!ifstats_slot.holds && !tunnel_slot.holds && !vlan_slot.holds);

        /* No barrier releases a key a hard failure may have left linked,
         * and so none releases its records; stopped ports release both
         * kinds, keeping only the key itself, recorded for the restart. */
        delete_result = EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0 && cdx_ft_hw_del(&hw) == -EAGAIN);
        delete_result = -1;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0 && cdx_ft_hw_del(&hw) == -EIO);
        assert(cdx_ft_hw_retry() == -EAGAIN && !older && key->linked);
        assert(ifstats_slot.holds == 2 && vlan_slot.holds == 2 && cdx_ft_hw_pending() == 1);
        assert(police_refs[policer] == 1);
        stopped = settled = true; cdx_ft_hw_quiesced();
        assert(!ifstats_slot.holds && !tunnel_slot.holds && !vlan_slot.holds);
        assert(!police_refs[policer]);
        assert(!allocations && !cdx_ft_hw_pending() && key->linked);
        assert(nabandoned == 1 && abandoned[0] == key);
        settle_abandoned(); stopped = settled = false;

        /* With nothing that can prove the classifier done with them -- a
         * port CDX did not configure still walking it, or a host-command
         * channel gone for good -- every retired entry stays allocated with
         * the records and profile it names, recorded as possibly linked
         * however its delete failed; only the backend lets go of it. The
         * reset alone reclaims the rest. */
        delete_result = EN_EHASH_DELETE_UNSYNCED;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0 && cdx_ft_hw_del(&hw) == -EAGAIN);
        delete_result = -1;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0 && cdx_ft_hw_del(&hw) == -EIO);
        assert(cdx_ft_hw_pending() == 2 && !older->linked && key->linked);
        cdx_ft_hw_strand();
        assert(!cdx_ft_hw_pending() && !allocations && kept_lines == 1);
        assert(nabandoned == 2 && abandoned[0] == older && abandoned[1] == key);
        assert(ifstats_slot.holds == 4 && tunnel_slot.holds == 2 && vlan_slot.holds == 4);
        assert(police_refs[policer] == 2);
        cdx_ft_hw_strand(); assert(nabandoned == 2 && kept_lines == 1);
        ifstats_slot.holds = tunnel_slot.holds = vlan_slot.holds = 0;
        police_refs[policer] = 0;
        stopped = settled = true; settle_abandoned(); stopped = settled = false;
        assert(!key && !older);
        kept_lines = 0;

        /* The debug knob's withheld proof: a delete that completed reports
         * its barrier failed, and each retry after it fails without issuing
         * one, until the count is spent. The entry and its holds are parked
         * exactly as for a real failure. A failed unlink spends nothing. */
        delete_result = -1;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        ft_fail_sync = 1;
        assert(cdx_ft_hw_del(&hw) == -EIO && ft_fail_sync == 1 && key->linked);
        stopped = settled = true; cdx_ft_hw_quiesced(); settle_abandoned();
        stopped = settled = false;
        assert(!key);
        delete_result = 0;
        ft_fail_sync = 3;
        assert(cdx_ft_hw_add(&rule,&stats,&hw) == 0);
        before = deletes;
        assert(cdx_ft_hw_del(&hw) == -EAGAIN && deletes == before + 1 && ft_fail_sync == 2);
        assert(key && !key->linked && cdx_ft_hw_pending() == 1 && ifstats_slot.holds == 2);
        before = syncs;
        assert(cdx_ft_hw_retry() == -EAGAIN && syncs == before && ft_fail_sync == 1);
        assert(cdx_ft_hw_retry() == -EAGAIN && syncs == before && !ft_fail_sync);
        assert(key && ifstats_slot.holds == 2 && vlan_slot.holds == 2);
        assert(cdx_ft_hw_retry() == 0 && syncs == before + 1 && !key && !cdx_ft_hw_pending());
        assert(!ifstats_slot.holds && !tunnel_slot.holds && !vlan_slot.holds && !allocations);
        assert(!police_refs[policer]);
        stats = (struct cdx_ft_stats_binding){};
        rule.qos = expected_qos = 0;
    }
    test_backend();
    puts("Flowtable hardware: encoding, consuming delete, allocation-free retirement, deferred settle, barrier retry and quiescence passed");
}

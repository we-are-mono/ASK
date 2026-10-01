/* Kernel shims for production adapter tests; no duplicate decoder or lifecycle. */
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
typedef uint64_t u64, atomic64_t;
#define __force
static u32 rol32(u32 v, unsigned n) { return (v << n) | (v >> (32 - n)); }
#define fallthrough __attribute__((fallthrough))
#include "flowtable_hash.inc"
static u32 get_random_u32(void) { return 0x87654321; }
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_DATA_LEN 1500
#define VLAN_HLEN 4
#define PPPOE_SES_HLEN 8
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_ALL 3
#define VLAN_VID_MASK 0x0fff
#define IPV6_MIN_MTU 1280
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
/* struct in6_addr and in_addr come from <arpa/inet.h>, with the same field
 * names the kernel uses. Same shape as the kernel's UAPI union, which is what
 * makes a conntrack tuple and a cdx_ft_rule address comparable without
 * transcription. */
union nf_inet_addr {
    u32 all[4];
    __be32 ip;
    __be32 ip6[4];
    struct in_addr in;
    struct in6_addr in6;
};
static bool nf_inet_addr_cmp(const union nf_inet_addr *a, const union nf_inet_addr *b)
{ return !memcmp(a->all, b->all, sizeof(a->all)); }
/* An IPv4 value in the union always leaves the remaining words zero, and the
 * assertions below check that rather than only the first word: a decoder that
 * left stale bytes in the unused arm would mis-key every flow. */
static union nf_inet_addr v4(__be32 address)
{ union nf_inet_addr a; memset(&a, 0, sizeof(a)); a.ip = address; return a; }
static bool is4(const union nf_inet_addr *a, __be32 address)
{ union nf_inet_addr expected = v4(address); return nf_inet_addr_cmp(a, &expected); }
#define IPV6_ADDR_ANY 0x0000U
#define IPV6_ADDR_UNICAST 0x0001U
#define IPV6_ADDR_MULTICAST 0x0002U
#define IPV6_ADDR_LOOPBACK 0x0010U
#define IPV6_ADDR_LINKLOCAL 0x0020U
#define IPV6_ADDR_COMPATv4 0x0080U
#define IPV6_ADDR_MAPPED 0x1000U
/* The subset of __ipv6_addr_type() the decoder can actually observe. */
static int ipv6_addr_type(const struct in6_addr *a)
{
    if (a->s6_addr[0] == 0xff) return IPV6_ADDR_MULTICAST;
    if ((a->s6_addr[0] == 0xfe) && ((a->s6_addr[1] & 0xc0) == 0x80))
        return IPV6_ADDR_UNICAST | IPV6_ADDR_LINKLOCAL;
    if (!a->s6_addr32[0] && !a->s6_addr32[1] && !a->s6_addr32[2]) {
        if (!a->s6_addr32[3]) return IPV6_ADDR_ANY;
        if (a->s6_addr32[3] == htonl(1))
            return IPV6_ADDR_UNICAST | IPV6_ADDR_LOOPBACK;
        return IPV6_ADDR_UNICAST | IPV6_ADDR_COMPATv4;
    }
    if (!a->s6_addr32[0] && !a->s6_addr32[1] && a->s6_addr32[2] == htonl(0xffff))
        return IPV6_ADDR_UNICAST | IPV6_ADDR_MAPPED;
    return IPV6_ADDR_UNICAST;
}
static bool ipv6_prefix_equal(const struct in6_addr *a, const struct in6_addr *b,
                              unsigned prefixlen)
{
    unsigned whole = prefixlen / 8, bits = prefixlen & 7;

    assert(prefixlen <= 128);
    if (whole && memcmp(a->s6_addr, b->s6_addr, whole)) return false;
    if (bits && ((a->s6_addr[whole] ^ b->s6_addr[whole]) >> (8 - bits))) return false;
    return true;
}
struct ipv6hdr { u8 prefix[8]; struct in6_addr saddr, daddr; };
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
#define U8_MAX 0xffU
#define __ffs(x) ((unsigned long)__builtin_ctzl(x))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_store_release(p, v) (*(p) = (v))
static void set_bit(unsigned int bit, unsigned long *p) { *p |= 1UL << bit; }
#define NETEVENT_XFRM_POLICY_UPDATE 190
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define HZ 100
/* A warn that fires is a bug the kernel would only log; here it fails the run,
 * which is what an invariant stated with WARN_ON_ONCE deserves from a test.
 * Still yields its value: production code branches on some of them. */
#define WARN_ON_ONCE(x) ({ int warned_ = !!(x); assert(!warned_); warned_; })
/* Nothing is printed, but the arguments are still consumed, exactly as the
 * kernel's own no_printk() consumes them: a message whose only use of a local
 * is the message itself must not turn that local into an unused variable
 * here, because production builds with the real printk and never sees it. No
 * format attribute, so a kernel-only specifier is not diagnosed either. */
static inline void no_print(const char *fmt, ...) { (void)fmt; }
#define pr_info(...) no_print(__VA_ARGS__)
/* The error paths keep the cheaper form: their messages name devices and bit
 * positions through kernel helpers this harness has no use for otherwise, and
 * none of them is a variable's only reader. */
#define pr_err(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define pr_warn_ratelimited(...) ((void)0)
#define __init
#define __exit
#define CDX_DEBUG_FLOWTABLE
#define FLOW_ACTION_HW_STATS_DELAYED 1
#define IP_CT_DIR_ORIGINAL 0
#define IP_CT_DIR_REPLY 1
#define IPS_NAT_MASK 0x30
#define IPS_SRC_NAT 0x10
#define IPS_SRC_NAT_DONE 0x80
#define IPS_DST_NAT 0x20
#define IPS_DST_NAT_DONE 0x100
#define IS_ENABLED(x) 1
#define TCA_CSUM_UPDATE_FLAG_IPV4HDR 1
#define TCA_CSUM_UPDATE_FLAG_TCP 8
#define TCA_CSUM_UPDATE_FLAG_UDP 16
/* Named through rather than skipped over: a sit device's configuration is an
 * iphdr and the tunnel hop is checked against its TTL and TOS, so those fields
 * have to be here -- at the offsets the NAT edits already assume, which is why
 * the leading twelve bytes are spelled out rather than replaced. */
struct iphdr { u8 vhl, tos; __be16 tot_len, id, frag_off; u8 ttl, protocol;
               __be16 check; __be32 saddr, daddr; };
#define IPS_ASSURED 4
#define TCPHDR_FIN 1
#define TCPHDR_RST 4
#define TCP_CONNTRACK_ESTABLISHED 3
#define NUD_PERMANENT 128
#define NUD_NOARP 64
#define NUD_FAILED 32
#define NUD_PROBE 16
#define NUD_DELAY 8
#define NUD_STALE 4
#define NUD_REACHABLE 2
#define NUD_INCOMPLETE 1
#define NETEVENT_NEIGH_UPDATE 1
#define NETEVENT_IPV4_ROUTE_UPDATE 7
#define NETEVENT_IPV6_ROUTE_UPDATE 8
enum { FIB_EVENT_ENTRY_REPLACE, FIB_EVENT_ENTRY_APPEND, FIB_EVENT_ENTRY_ADD,
       FIB_EVENT_ENTRY_DEL, FIB_EVENT_RULE_ADD, FIB_EVENT_RULE_DEL, FIB_EVENT_NH_ADD, FIB_EVENT_NH_DEL };
enum { NETDEV_GOING_DOWN, NETDEV_UNREGISTER, NETDEV_CHANGEMTU, NETDEV_CHANGEADDR,
       NETDEV_CHANGEUPPER, NETDEV_CHANGENAME, NETDEV_REGISTER, NETDEV_CHANGE,
       NETDEV_UP, NETDEV_DOWN };
enum { NEXTHOP_EVENT_DEL, NEXTHOP_EVENT_REPLACE, NEXTHOP_EVENT_RES_TABLE_PRE_REPLACE,
       NEXTHOP_EVENT_BUCKET_REPLACE, NEXTHOP_EVENT_HW_STATS_REPORT_DELTA };
struct fib_notifier_info { int family; };
struct netevent_ipv4_route { struct net *net; __be32 dst; u8 prefixlen; };
struct netevent_ipv6_route { struct net *net; struct in6_addr dst; u8 prefixlen; };
static __be32 inet_make_mask(unsigned plen) { assert(plen <= 32); return htonl(plen ? ~0U << (32 - plen) : 0); }
#define NOTIFY_DONE 0
#define cmpxchg(p, old, new) ({ typeof(*(p)) v = *(p); if (v == (old)) *(p) = (new); v; })
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define list_entry(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m); &p->m != (h); p = list_entry(p->m.next, typeof(*p), m))
#define list_for_each_entry_safe(p, n, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m), n = list_entry(p->m.next, typeof(*p), m); \
         &p->m != (h); p = n, n = list_entry(n->m.next, typeof(*n), m))
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; }
static void list_init(struct list_head *h) { h->next = h->prev = h; }
#define INIT_LIST_HEAD(h) list_init(h)
static bool list_empty(const struct list_head *h) { return h->next == h; }
static void list_del_init(struct list_head *e) { list_del(e); list_init(e); }
static void list_move(struct list_head *e, struct list_head *h)
{ list_del(e); e->next = h->next; e->prev = h; h->next->prev = e; h->next = e; }
static void list_splice_init(struct list_head *from, struct list_head *to)
{
    if (list_empty(from)) return;
    from->next->prev = to; from->prev->next = to->next; to->next->prev = from->prev;
    to->next = from->next; list_init(from);
}
struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
struct seq_file { int unused; };
#define HASH_SIZE(t) ARRAY_SIZE(t)
#define hlist_entry list_entry
#define hlist_for_each_entry(p, h, m) \
    for (struct hlist_node *node_ = (h)->first; \
         node_ && ((p) = list_entry(node_, typeof(*(p)), m), 1); node_ = node_->next)
#define DEFINE_HASHTABLE(n, bits) struct hlist_head n[1 << (bits)]
static unsigned long hash_ptr(const void *p, unsigned bits)
{ return ((uintptr_t)p * UINT64_C(0x61c8864680b583eb)) >> (64 - bits); }
#define hash_slot(t, k) (((uint64_t)(k) * UINT64_C(0x61c8864680b583eb)) >> (64 - __builtin_ctz(ARRAY_SIZE(t))))
static void hlist_add(struct hlist_head *h, struct hlist_node *n)
{ n->next = h->first; if (n->next) n->next->pprev = &n->next; h->first = n; n->pprev = &h->first; }
static void hash_del(struct hlist_node *n)
{ assert(n->pprev); *n->pprev = n->next; if (n->next) n->next->pprev = n->pprev; n->next = NULL; n->pprev = NULL; }
#define hash_add(t, n, k) hlist_add(&(t)[hash_slot(t, k)], n)
#define hash_for_each_possible(t, p, m, k) \
    for (struct hlist_node *node_ = (t)[hash_slot(t, k)].first; \
         node_ && ((p) = list_entry(node_, typeof(*(p)), m), 1); node_ = node_->next)
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define lockdep_assert_held(p) assert(*(p))
enum tc_setup_type { TC_SETUP_FT, TC_SETUP_CLSFLOWER };
enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
enum { FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS, FLOW_BLOCK_BIND, FLOW_BLOCK_UNBIND };
struct Qdisc { int unused; };
struct flow_block { struct list_head cb_list; };
struct flow_block_offload {
    struct flow_block *block;
    struct net *net;
    int binder_type, command;
    struct list_head *driver_block_list, cb_list;
};
struct flow_block_cb {
    struct list_head list, driver_list;
    int (*cb)(enum tc_setup_type, void *, void *);
    void *ident, *cb_priv;
    void (*release)(void *);
    /* Which route installed it. Netfilter unwinds only the indirect ones on
     * flow_indr_dev_unregister(); a direct callback stays its property until
     * somebody unbinds, which is what the adapter's own drain is for. */
    bool indirect;
    /* Netfilter's own list of every indirect callback, kept apart from the
     * table's block list: flow_indr_block_cb_alloc() links it here and only
     * flow_indr_block_cb_remove() or the unregister's cleanup unlinks it. */
    struct list_head indr_list;
};
static struct list_head flow_block_indr_list = { &flow_block_indr_list, &flow_block_indr_list };
struct net { int id; };
static struct net init_net;
/* One bridge VLAN membership, as `bridge vlan add dev D vid N [untagged]`
 * records it: on the master it carries the PVID, on a port it carries the
 * egress mode br_vlan_fill_forward_path_mode() reads. */
#define BR_MAX_VLANS 4
struct br_vlan_entry { u16 vid, flags; };
struct bridge_vlan_info { u16 vid, flags; };
#define BRIDGE_VLAN_INFO_PVID (1 << 1)
#define BRIDGE_VLAN_INFO_UNTAGGED (1 << 2)

/* real_dev is what makes a device a VLAN here, exactly as vlan_dev_priv's
 * presence does in the kernel; a physical port leaves it NULL. A bridge is
 * not a VLAN however its lower list is filled in, which is what lets the
 * bridge below carry a decoy first lower device.
 *
 * type separates a ppp device from every other one, as ARPHRD_PPP does in the
 * kernel. A ppp device has no real_dev on purpose: ppp_generic registers no
 * netdev adjacency, so there is nothing for a lower-device walk to find, which
 * is the whole reason the session hop has to be handed in from outside. */
#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
/* The two IP-in-IP tunnel devices the adapter recognises. A sit device carries
 * an IPv4 outer header around an IPv6 packet and an ip6tnl device in ipip6
 * mode an IPv6 one around an IPv4 packet. */
#define ARPHRD_TUNNEL6 769
#define ARPHRD_SIT 776
/* addr_len and priv exist for those two alone. Both are NOARP but both have
 * header ops, so arp_constructor() and ndisc_constructor() copy dev_addr --
 * the tunnel's local endpoint, four bytes or sixteen -- into every neighbour
 * they build, and that is what Netfilter then writes into the Ethernet
 * destination of a flow leaving by one. priv is what netdev_priv() hands back,
 * which is where the adapter reads the tunnel's configuration from. */
struct net_device { int ifindex, refs, mtu, ip6_mtu; u8 dev_addr[6]; struct net *net; bool carrier_lost, down;
                    unsigned short type; unsigned char addr_len; void *priv;
                    struct net_device *real_dev; u16 vlan_id; __be16 vlan_proto;
                    bool bridge, vlan_filtering, stp_blocked, mst; struct net_device *master;
                    u16 br_proto, pvid; struct br_vlan_entry br_vlans[BR_MAX_VLANS];
                    unsigned br_nvlans; u16 vid_blocked; };
#define netdev_priv(d) ((d)->priv)
/* A device's IPv6 MTU starts as the device's own, as addrconf sets it; a case
 * that needs the sysctl to differ sets ip6_mtu. */
struct inet6_dev { struct { int mtu6; } cnf; };
static struct inet6_dev inet6_view;
static struct inet6_dev *__in6_dev_get(const struct net_device *d)
{ inet6_view.cnf.mtu6 = d->ip6_mtu ? d->ip6_mtu : d->mtu; return &inet6_view; }
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
/* Devices are told apart by pointer here, never by name; the production
 * traces that print one only have to compile and consume their argument. */
static const char *netdev_name(const struct net_device *d) { (void)d; return "dev"; }
/* Only the parameters the hop is cross-checked against. Named as the kernel
 * names them, because the adapter reads them through those names. */
struct ip_tunnel_parm { struct iphdr iph; };
struct ip_tunnel { struct ip_tunnel_parm parms; };
#define IP6_TNL_F_USE_ORIG_TCLASS 0x8
struct __ip6_tnl_parm { struct in6_addr laddr, raddr; u8 hop_limit, proto; u32 flags; };
struct ip6_tnl { struct __ip6_tnl_parm parms; };
static bool ipv6_addr_equal(const struct in6_addr *a, const struct in6_addr *b)
{ return !memcmp(a, b, sizeof(*a)); }
static bool ipv6_addr_is_multicast(const struct in6_addr *a)
{ return a->s6_addr[0] == 0xff; }
static bool is_vlan_dev(const struct net_device *d) { return d->real_dev && !d->bridge; }
static bool netif_is_bridge_master(const struct net_device *d) { return d->bridge; }
static bool netif_is_bridge_port(const struct net_device *d) { return d->master && d->master->bridge; }
static struct net_device *netdev_master_upper_dev_get(struct net_device *d) { return d->master; }
/* A port forwards unless a case blocks it, and MST is off unless a case turns
 * it on: the state every other case's bridge is in. */
#define BR_STATE_DISABLED 0
#define BR_STATE_LISTENING 1
#define BR_STATE_LEARNING 2
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4
/* The bridge's own answer, which it derives from the port's STP state and,
 * with VLAN filtering, the port's and its own entry's state for that VLAN.
 * Modelled as the port's state and one VLAN a case can block on it. */
static bool br_port_forwarding(const struct net_device *d, u16 vid)
{
    assert(netif_is_bridge_port(d));
    return !d->stp_blocked && !(d->vid_blocked && d->vid_blocked == vid);
}
static bool br_mst_enabled(const struct net_device *d) { assert(d->bridge); return d->mst; }
/* The bridge queries the adapter mirrors br_vlan_fill_forward_path_pvid() and
 * br_vlan_fill_forward_path_mode() through. br_vlan_get_proto() reports host
 * order, and br_vlan_get_pvid() succeeds even with no PVID configured -- the
 * resulting zero then fails the membership lookup, exactly as in the kernel. */
static bool br_vlan_enabled(const struct net_device *d)
{ assert(d->bridge); return d->vlan_filtering; }
static int br_vlan_get_proto(const struct net_device *d, u16 *proto)
{ assert(d->bridge); *proto = d->br_proto; return 0; }
static int br_vlan_get_pvid(const struct net_device *d, u16 *pvid)
{ assert(d->bridge); *pvid = d->pvid; return 0; }
static int br_vlan_get_info(const struct net_device *d, u16 vid, struct bridge_vlan_info *info)
{
    unsigned i;

    for (i = 0; i < d->br_nvlans; i++)
        if (d->br_vlans[i].vid == vid) {
            info->vid = vid;
            info->flags = d->br_vlans[i].flags;
            return 0;
        }
    return -ENOENT;
}
/* Faithful to the kernel's own vlan_dev_real_dev(), which descends through
 * every stacked VLAN at once and returns the bottom device -- not the
 * immediate parent. Modelling it as the parent would make a QinQ stack look
 * one tag deep to the tests and exactly one tag deep on hardware. */
static struct net_device *vlan_dev_real_dev(const struct net_device *d)
{
    struct net_device *ret = d->real_dev;

    while (is_vlan_dev(ret)) ret = ret->real_dev;
    return ret;
}
static u16 vlan_dev_vlan_id(const struct net_device *d) { return d->vlan_id; }
static __be16 vlan_dev_vlan_proto(const struct net_device *d) { return d->vlan_proto; }
/* The immediate lower neighbour, which for a VLAN device is its parent and
 * nothing else. The kernel's list holds direct neighbours only, so a single
 * pointer models it exactly. */
#define netdev_for_each_lower_dev(dev, lower, iter)                       \
    for ((iter) = (struct list_head *)(dev), (lower) = (dev)->real_dev;   \
         (lower) && (iter); (iter) = NULL)
#define netif_carrier_ok(d) (!(d)->carrier_lost)
#define netif_running(d) (!(d)->down)
#define fallthrough __attribute__((fallthrough))
#define dev_net(d) ((d)->net ? (d)->net : &init_net)
struct netdev_notifier_info { struct net_device *dev; };
#define netdev_notifier_info_to_dev(p) (((struct netdev_notifier_info *)(p))->dev)
/* What NETDEV_CHANGEUPPER carries, leading with the common info as the
 * kernel's does. */
struct netdev_notifier_changeupper_info {
    struct netdev_notifier_info info;
    struct net_device *upper_dev;
    bool master;
    bool linking;
    void *upper_info;
};
/* The switchdev chains the bridge reports FDB and VLAN-membership changes on.
 * Both notifier info structs lead with the common one, which is what makes
 * switchdev_notifier_info_to_dev() work on either. */
enum switchdev_notifier_type {
    SWITCHDEV_FDB_ADD_TO_DEVICE = 1, SWITCHDEV_FDB_DEL_TO_DEVICE,
    SWITCHDEV_PORT_OBJ_ADD, SWITCHDEV_PORT_OBJ_DEL, SWITCHDEV_PORT_ATTR_SET,
};
enum switchdev_obj_id { SWITCHDEV_OBJ_ID_PORT_VLAN = 1, SWITCHDEV_OBJ_ID_PORT_MDB,
                        SWITCHDEV_OBJ_ID_HOST_MDB };
struct switchdev_notifier_info { struct net_device *dev; void *extack; const void *ctx; };
struct switchdev_notifier_fdb_info {
    struct switchdev_notifier_info info; /* must be first */
    const unsigned char *addr;
    u16 vid;
};
enum switchdev_attr_id {
    SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING = 1, SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL,
    SWITCHDEV_ATTR_ID_BRIDGE_AGEING_TIME,
    SWITCHDEV_ATTR_ID_PORT_MROUTER, SWITCHDEV_ATTR_ID_BRIDGE_MC_DISABLED,
    SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS, SWITCHDEV_ATTR_ID_PORT_STP_STATE,
    SWITCHDEV_ATTR_ID_PORT_MST_STATE, SWITCHDEV_ATTR_ID_BRIDGE_MST,
    SWITCHDEV_ATTR_ID_VLAN_MSTI, SWITCHDEV_ATTR_ID_PORT_VLAN_STATE,
    SWITCHDEV_ATTR_ID_BRIDGE_MROUTER,
};
struct switchdev_obj { enum switchdev_obj_id id; };
struct switchdev_mst_state { u16 msti; u8 state; };
struct switchdev_vlan_state { u16 vid; u8 state; };
struct switchdev_attr {
    enum switchdev_attr_id id;
    union { u8 stp_state; struct switchdev_mst_state mst_state;
            struct switchdev_vlan_state vlan_state; bool mst; } u;
};
struct switchdev_notifier_port_obj_info {
    struct switchdev_notifier_info info; /* must be first */
    const struct switchdev_obj *obj;
    bool handled;
};
struct switchdev_notifier_port_attr_info {
    struct switchdev_notifier_info info; /* must be first */
    const struct switchdev_attr *attr;
    bool handled;
};
/* The multicast learner, which this harness does not compile: it has its own
 * file, because its state and stubs have nothing to do with a flow's. What
 * matters here is only that ft_swdev_event() routes an MDB object away from
 * the VLAN dependency logic and does not fall through into it, so the stub
 * records the call and claims nothing. */
static unsigned mc_objects;
static bool ft_mc_swdev_obj(unsigned long event,
                            struct switchdev_notifier_port_obj_info *obj)
{
    (void)event; (void)obj;
    mc_objects++;
    return false;
}
static void ft_mc_exit(void) { }
static unsigned mc_devices_gone, mc_rechecks;
static void ft_mc_device_gone(struct net_device *dev, bool unregistering)
{
    (void)dev;
    (void)unregistering;
    mc_devices_gone++;
}
static void ft_mc_kick_all(void) { mc_rechecks++; }
static unsigned mc_bridge_changes, mc_ports_moved;
static struct net_device *mc_port_left;
static void ft_mc_bridge_changed(struct net_device *dev) { (void)dev; mc_bridge_changes++; }
static void ft_mc_port_moved(struct net_device *dev, struct net_device *left)
{
    (void)dev;
    mc_ports_moved++;
    mc_port_left = left;
}
/* The routed learner has its own file and its own harness
 * (mroute_learner.c); here the chains' calls into it only count. The two
 * multicast families the FIB chain carries are ipmr's and ip6mr's, and this
 * adapter hands both of them straight over. */
#define RTNL_FAMILY_IPMR 128
#define RTNL_FAMILY_IP6MR 129
static unsigned mroute_events, mroute_kicks, mroute_devices_gone;
static unsigned long ft_mr_resync_pending;
static bool ft_mr_ready;
static int ft_mr_work;
/* The count of x_tables table changes, which the learner starts from: the
 * tables as they stand at load are no change to follow. */
static unsigned int ft_mr_xt_seen, xt_changes = 7;
static unsigned int nf_xt_seq(const struct net *net)
{
    assert(net == &init_net);
    return xt_changes;
}
static int ft_mr_fib_event(unsigned long event, struct fib_notifier_info *info)
{
    (void)event; (void)info;
    mroute_events++;
    return NOTIFY_DONE;
}
static void ft_mr_kick(void) { mroute_kicks++; }
/* XFRM policy changes the routed learner was kicked for. */
static atomic64_t ft_mr_xfrm_changes;
static void ft_mr_device_gone(struct net_device *dev)
{
    (void)dev;
    mroute_devices_gone++;
}
static void ft_mr_exit(void) { ft_mr_ready = false; ft_mr_resync_pending = 0; }
/* The Wi-Fi VAP registration lives in its own file and has its own harness
 * (wifi_admission.c); here the notifier's calls into it only count. */
static unsigned wifi_reconsiders, wifi_address_changes, wifi_devices_gone;
static void ft_wifi_reconsider(struct net_device *dev) { (void)dev; wifi_reconsiders++; }
static void ft_wifi_address_changed(struct net_device *dev) { (void)dev; wifi_address_changes++; }
static void ft_wifi_device_gone(struct net_device *dev) { (void)dev; wifi_devices_gone++; }
static void ft_wifi_exit(void) { }
#define switchdev_notifier_info_to_dev(p) (((struct switchdev_notifier_info *)(p))->dev)
struct dst_ops { unsigned family; };
/* Only the field the adapter reads off a transform: what leaves the port is
 * the outer packet, addressed to the SA's remote endpoint. */
typedef union { __be32 a4; u32 a6[4]; } xfrm_address_t;
struct xfrm_state { struct { xfrm_address_t daddr; } id; struct { u16 family; } props; };
struct dst_entry {
    struct dst_ops *ops;
    struct net_device *dev;
    struct xfrm_state *xfrm;
    /* The route under a transform. A bundle with none is a broken bundle,
     * which the walk must refuse rather than read past. */
    struct dst_entry *xfrm_child;
    void *lwtstate;
    int error;
    u32 cookie;
    bool valid;
};
struct rtable { struct dst_entry dst; unsigned rt_type, rt_gw_family; __be32 rt_gw4; };
/* Only the fields the decoder reads; rt6i_dst is what an RTF_CACHE route
 * names as its own next hop. */
struct rt6_info { struct dst_entry dst; unsigned rt6i_flags;
    struct in6_addr rt6i_gateway; struct { struct in6_addr addr; } rt6i_dst; };
#define RTN_UNICAST 1
#define RTF_GATEWAY 0x0002
#define RTF_REJECT 0x0200
#define RTF_ANYCAST 0x00100000
#define RTF_CACHE 0x01000000
#define RTF_LOCAL 0x80000000
#define dst_xfrm(d) ((d)->xfrm)
#define xfrm_dst_child(d) ((d)->xfrm_child)
#define dst_rtable(d) ((struct rtable *)(d))
#define dst_rt6_info(d) ((struct rt6_info *)(d))
/* IPv4 ignores the cookie; IPv6 pins the destination to one FIB generation
 * and a mismatch must reject it, which is the whole reason the adapter has
 * to be handed the cookie its route was selected under. */
static struct dst_entry *dst_check(struct dst_entry *d, u32 cookie)
{ return d->valid && d->cookie == cookie ? d : NULL; }
static __be32 rt_nexthop(const struct rtable *r, __be32 address)
{ return r->rt_gw_family == AF_INET ? r->rt_gw4 : address; }
static const struct in6_addr *rt6_nexthop(const struct rt6_info *r,
                                          const struct in6_addr *address)
{
    if (r->rt6i_flags & RTF_GATEWAY) return &r->rt6i_gateway;
    if (r->rt6i_flags & RTF_CACHE) return &r->rt6i_dst.addr;
    return address;
}
struct neigh_table { unsigned key_len; int family; };
static struct neigh_table arp_tbl = { .key_len = 4, .family = AF_INET },
                          nd_tbl = { .key_len = 16, .family = AF_INET6 };
struct neighbour {
    struct neigh_table *tbl;
    struct net_device *dev;
    unsigned refs, nud_state;
    union nf_inet_addr primary_key;
    bool dead, lock;
    u8 ha[6];
};
struct notifier_block { int unused; };
static struct neighbour neighbour, gateway, alternate_gateway;
static void read_lock_bh(bool *lock) { assert(!*lock); *lock = true; }
static void read_unlock_bh(bool *lock) { assert(*lock); *lock = false; }
#define spin_lock read_lock_bh
#define spin_unlock read_unlock_bh
#define spin_lock_bh read_lock_bh
#define spin_unlock_bh read_unlock_bh
/* flow_block is embedded, not referenced: the direct route recovers its owner
 * with container_of on bo->block, so a harness that kept them apart would let
 * a wrong offset through. */
struct nf_flowtable { struct { int nelems; } rhashtable; struct flow_block flow_block;
    bool use_neigh, use_hw_handles, flow_block_lock; };
struct nf_conntrack_tuple {
    struct { union nf_inet_addr u3; union { __be16 all; } u; u16 l3num; } src;
    struct { union nf_inet_addr u3; union { __be16 all; } u; } dst;
};
struct nf_conn_nat { int masq_index; };
struct nf_conn { struct net *net; unsigned zone[2], mark, status, protonum, tcp_state;
    struct { struct nf_conntrack_tuple tuple; } tuplehash[2]; struct nf_conn_nat *nat; };
#define nfct_nat(c) ((c)->nat)
#define nf_ct_protonum(c) ((c)->protonum)
#define nf_ct_l3num(c) ((c)->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num)
static bool nf_conntrack_tcp_established(const struct nf_conn *c)
{ return c->tcp_state == TCP_CONNTRACK_ESTABLISHED && (c->status & IPS_ASSURED); }
#define nf_ct_net(c) ((c)->net)
#define nf_ct_zone(c) ((c)->zone)
#define nf_ct_zone_id(z, dir) ((z)[dir])
#define net_eq(a, b) ((a) == (b))
static bool is_valid_ether_addr(const u8 *a)
{ return !(a[0] & 1) && memcmp(a, (u8[6]){0}, 6); }
static bool is_zero_ether_addr(const u8 *a) { return !memcmp(a, (u8[6]){0}, 6); }
#define ether_addr_equal(a, b) (!memcmp(a, b, 6))
#define ether_addr_copy(a, b) memcpy(a, b, 6)
#define ipv4_is_multicast(a) ((ntohl(a) & 0xf0000000) == 0xe0000000)
#define ipv4_is_zeronet(a) ((ntohl(a) & 0xff000000) == 0)
#define ipv4_is_loopback(a) ((ntohl(a) & 0xff000000) == 0x7f000000)
#define ipv4_is_lbcast(a) ((a) == htonl(0xffffffff))
enum { FLOW_DISSECTOR_KEY_META, FLOW_DISSECTOR_KEY_CONTROL, FLOW_DISSECTOR_KEY_BASIC,
       FLOW_DISSECTOR_KEY_IPV4_ADDRS, FLOW_DISSECTOR_KEY_IPV6_ADDRS,
       FLOW_DISSECTOR_KEY_PORTS, FLOW_DISSECTOR_KEY_TCP,
       FLOW_DISSECTOR_KEY_VLAN, FLOW_DISSECTOR_KEY_CVLAN };
struct flow_dissector { unsigned long long used_keys; };
/* Spelled out rather than a literal: adding a dissector key shifts every bit
 * above it, and a stale literal would quietly describe a different key set. */
#define FT_KEYS(addrs) (BIT_ULL(FLOW_DISSECTOR_KEY_META) | BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | \
                        BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) | BIT_ULL(addrs) | \
                        BIT_ULL(FLOW_DISSECTOR_KEY_PORTS))
#define FT_KEYS4 FT_KEYS(FLOW_DISSECTOR_KEY_IPV4_ADDRS)
#define FT_KEYS6 FT_KEYS(FLOW_DISSECTOR_KEY_IPV6_ADDRS)
struct meta { int ingress_ifindex; u16 ingress_iftype; u8 l2_miss; };
struct control { u16 thoff, addr_type; u32 flags; };
struct basic { __be16 n_proto; u8 ip_proto, padding; };
struct ipv4_addrs { __be32 src, dst; };
struct ipv6_addrs { struct in6_addr src, dst; };
struct ports { __be16 src, dst; };
struct tcp { __be16 flags; };
/* Same field names and widths as flow_dissector_key_vlan, which is what the
 * decoder's exact-mask rules are written against. */
struct vlan { u16 vlan_id:12, vlan_dei:1, vlan_priority:3; __be16 vlan_tpid, vlan_eth_type; };
#define MATCH(t) struct flow_match_##t { struct t *key, *mask; }
MATCH(meta); MATCH(control); MATCH(basic); MATCH(ipv4_addrs); MATCH(ipv6_addrs);
MATCH(ports); MATCH(tcp); MATCH(vlan);
enum { FLOW_ACTION_MANGLE, FLOW_ACTION_REDIRECT, FLOW_ACTION_CSUM,
       FLOW_ACTION_VLAN_PUSH, FLOW_ACTION_VLAN_POP, FLOW_ACTION_PPPOE_PUSH };
enum flow_action_mangle_base { FLOW_ACT_MANGLE_HDR_TYPE_IP4, FLOW_ACT_MANGLE_HDR_TYPE_IP6,
       FLOW_ACT_MANGLE_HDR_TYPE_UDP, FLOW_ACT_MANGLE_HDR_TYPE_TCP, FLOW_ACT_MANGLE_HDR_TYPE_ETH };
struct flow_action_entry {
    unsigned id, csum_flags;
    struct { unsigned htype, offset; u32 mask, val; } mangle;
    struct { u16 vid; __be16 proto; u8 prio; } vlan;
    /* Everything FLOW_ACTION_PPPOE_PUSH carries. There is no pop counterpart
     * and no dissector key, which is why an ingress session is invisible in a
     * rule and has to be proven by the devices alone. */
    struct { u16 sid; } pppoe;
    struct net_device *dev;
};
/* NF_FLOW_RULE_ACTION_MAX, which is what Netfilter allocates and refuses to
 * exceed. The deepest list it can actually produce is four Ethernet rewrites,
 * two tags popped and two pushed, an IPv6 translation at five actions per edit
 * for both edits, and the redirect: nineteen. */
struct flow_action { unsigned num_entries; struct flow_action_entry entries[24]; };
struct flow_rule {
    struct { struct flow_dissector *dissector; } match;
    struct flow_action action;
    struct flow_match_meta meta;
    struct flow_match_control control;
    struct flow_match_basic basic;
    struct flow_match_ipv4_addrs ipv4_addrs;
    struct flow_match_ipv6_addrs ipv6_addrs;
    struct flow_match_ports ports;
    struct flow_match_tcp tcp;
    struct flow_match_vlan vlan, cvlan;
};
#define GETMATCH(t) static void flow_rule_match_##t(struct flow_rule *r, struct flow_match_##t *m) { *m = r->t; }
GETMATCH(meta) GETMATCH(control) GETMATCH(basic) GETMATCH(ipv4_addrs)
GETMATCH(ipv6_addrs) GETMATCH(ports) GETMATCH(tcp) GETMATCH(vlan)
/* The second visible tag arrives in its own key with the same value type. */
static void flow_rule_match_cvlan(struct flow_rule *r, struct flow_match_vlan *m) { *m = r->cvlan; }
struct flow_stats { u64 bytes, pkts; unsigned long lastused; };
struct nf_flow_offload_handle { unsigned refs; bool invalid; };
static struct nf_flow_offload_handle handle;
static bool nf_flow_offload_handle_valid(const struct nf_flow_offload_handle *h)
{ return h && !h->invalid; }
static bool nf_flow_offload_handle_invalidate(struct nf_flow_offload_handle *h)
{ bool old = h->invalid; h->invalid = true; return !old; }
static void nf_flow_offload_handle_get(struct nf_flow_offload_handle *h)
{ assert(h->refs); h->refs++; }
static void nf_flow_offload_handle_put(struct nf_flow_offload_handle *h)
{ assert(h->refs > 1); h->refs--; }
/* Same shape as patch 140's, and filled the same way: nf_session belongs to
 * nf_dst and nf_session_reverse to nf_dst_reverse, so a direction's egress and
 * ingress sessions are named the way its two destinations are. A path with no
 * session reports a zero lower_ifindex rather than a null record. */
struct nf_flow_session { int lower_ifindex; u16 id; u8 h_dest[6]; };
/* Same shape as patch 143's, and paired with the two destinations the same
 * way a session is: nf_tunnel belongs to nf_dst and nf_tunnel_reverse to
 * nf_dst_reverse. A path crossing no tunnel reports a zero lower_ifindex
 * rather than a null record, so the record is always there to read. */
struct nf_flow_tunnel {
    int lower_ifindex;
    u8 family, proto, ttl, tos, flags, h_dest[6];
    __be32 flowlabel;
    union nf_inet_addr saddr, daddr, nexthop;
};
struct flow_cls_offload {
    const struct nf_conn *nf_ct;
    struct dst_entry *nf_dst, *nf_dst_reverse;
    const struct nf_flow_session *nf_session, *nf_session_reverse;
    const struct nf_flow_tunnel *nf_tunnel, *nf_tunnel_reverse;
    struct nf_flow_offload_handle *nf_handle;
    u32 nf_dst_cookie, nf_dst_reverse_cookie;
    u64 nf_xfrm_genid;
    unsigned command;
    u16 nf_mtu;
    bool nf_counter;
    struct { unsigned chain_index, protocol; } common;
    struct flow_rule *rule;
    unsigned long cookie;
    struct flow_stats stats;
};
static void flow_stats_update(struct flow_stats *s, u64 b, u64 p, u64 d, unsigned long t, int mode)
{ s->bytes += b; s->pkts += p; s->lastused = t; }
#include "flowtable_types.inc"
struct cdx_ft_hw { struct cdx_ft_counters stats; };
struct work_struct { int unused; };
static int ft_work, ft_retire_work, ft_dev_stats_work, ft_rearm_work;
/* The stopped-port sweep's own declarations are compiled from the adapter;
 * these let the stubs below name its work item before they appear. */
#define DECLARE_WORK(n, fn) int n
#define DEFINE_SPINLOCK(n) bool n
typedef struct { int unused; } netdevice_tracker;
static DECLARE_WORK(ft_stopped_work, ft_stopped_workfn);
static void ft_stopped_workfn(struct work_struct *work);
static LIST_HEAD(ft_bindings);
static LIST_HEAD(ft_entries);
static DEFINE_HASHTABLE(ft_cookies, CDX_FT_HASH_BITS);
static DEFINE_HASHTABLE(ft_keys, CDX_FT_HASH_BITS);
static u32 ft_hash_seed;
static LIST_HEAD(ft_neigh_entries);
static bool ft_watch_lock;
static LIST_HEAD(ft_block_list);
static LIST_HEAD(ft_dev_stats);
static bool ft_dev_stats_lock;
static void drop_dev_records(void);
/* The production allocator asserts RTNL because the install runs under the
 * admission's rtnl_trylock(); this harness drives ft_replace() directly from
 * most cases, without one, so the assertion is a statement here rather than a
 * check. */
#define ASSERT_RTNL() do { } while (0)
static unsigned ft_count, ft_bound, ft_parked, ft_fail_stage, ft_init_fail_stage;
/* Module parameters in production; plain globals here so a case can set the
 * mask, drive ft_parse, and read the class back off the rule. */
static unsigned int ft_qos_mark_mask, ft_qos_default_class;
static unsigned ft_neighbour_refs, ft_handle_refs;
static u64 ft_installs, ft_deletes, ft_errors, ft_validated, ft_rearms, ft_busy, ft_rejects;
static u64 ft_neigh_invalidations, ft_route_invalidations, ft_mtu_invalidations, ft_link_invalidations, ft_mac_invalidations, ft_fdb_invalidations, ft_stp_invalidations, ft_qos_invalidations, ft_admission_invalidations;
static void atomic64_inc(u64 *v) { (*v)++; }
static u64 atomic64_inc_return(u64 *v) { return ++*v; }
static u64 atomic64_read_acquire(u64 *v) { return *v; }
static u64 ft_ipsec_genid, xfrm_genid, ft_ipsec_invalidations, ft_ipsec_policy_invalidations;
static u64 xfrm_flowtable_genid(struct net *net) { return xfrm_genid; }
static bool ft_observe, ft_stopping, ft_fatal, ft_invalid_done, ft_ready = true;
static int ft_invalid;
static unsigned long jiffies = 1000;
static unsigned allocated, live_hw, flushed, scheduled;
static bool allocation_fail, hardware_fail, invalidate_on_add, physical_ok = true, neigh_ok = true;
static int hardware_alloc_error;
static bool change_neigh_on_add, change_neigh_on_lookup;
static bool change_policy_on_add, change_sa_on_add;
static unsigned neigh_lookups, neigh_uses;
static int neigh_send_error;
static int deletion_error;
static bool rtnl_busy, rtnl, quiesce_fail;
static bool callback_allocation_fail, invalidate_on_bind;
static unsigned private_pending, legacy_pending;
static int retry_error;
static void (*cleanup_hook)(void);
static struct { struct { bool mutex; } ctrl; } instance, *cdx_info = &instance;
static void mutex_lock(bool *m) { assert(!*m); *m = true; }
static void mutex_unlock(bool *m) { assert(*m); *m = false; }
/* Every attempt counts, won or lost: an offer answered without RTNL is one
 * that never asked. */
static unsigned rtnl_trylocks;
static bool rtnl_trylock(void)
{
    rtnl_trylocks++;
    if (rtnl_busy) return false;
    assert(!rtnl); rtnl = true; return true;
}
/* Only the stopped-port sweep waits for RTNL, and it must never do so inside
 * the backend transaction: the rule callbacks its flush waits for take that. */
static void rtnl_lock(void) { assert(!rtnl && !cdx_info->ctrl.mutex && !ft_watch_lock); rtnl = true; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = false; }
static int dpa_cfg_quiesce(void) { assert(rtnl && cdx_info->ctrl.mutex); return quiesce_fail ? -EIO : 0; }
static void cdx_ft_begin(void) { assert(!ft_watch_lock); mutex_lock(&cdx_info->ctrl.mutex); }
static void cdx_ft_end(void) { assert(!ft_watch_lock); mutex_unlock(&cdx_info->ctrl.mutex); }
static void cdx_ft_assert_held(void) { assert(cdx_info->ctrl.mutex); }
static bool *block_write_lock;
static void down_write(bool *lock)
{ assert(!cdx_info->ctrl.mutex && !*lock && !block_write_lock); *lock = true; block_write_lock = lock; }
static void up_write(bool *lock)
{ assert(!cdx_info->ctrl.mutex && *lock && block_write_lock == lock); *lock = false; block_write_lock = NULL; }
/* The firmware's statistics pool, at its real depth: four timestamped records,
 * each a receive and a transmit half. Indices are what the header
 * manipulations carry, and index zero is never a valid one -- STATS_WITH_TS is
 * always set on a timestamped record -- which is what lets zero mean "no
 * record" everywhere one is passed on. */
#define STATS_WITH_TS 0x80
#define STATS_TIMESTAMPED_SLOTS 4
/* And a plain pool behind it, a few records deep, indexed from where the
 * timestamped records end -- in its own units, so the first plain index is
 * twelve and none of them carries the flag. */
#define STATS_PLAIN_SLOTS 8
#define STATS_PLAIN_BASE 12
struct cdx_ft_stats_slot { unsigned index; enum cdx_ft_stats_kind kind; u8 rx_index, tx_index;
                           struct cdx_ft_stats rx, tx;
                           int published_ifindex; unsigned published_rx_overhead, published_tx_overhead; };
static struct cdx_ft_stats_slot stats_pool[STATS_TIMESTAMPED_SLOTS + STATS_PLAIN_SLOTS];
static bool stats_taken[STATS_TIMESTAMPED_SLOTS + STATS_PLAIN_SLOTS];
static unsigned stats_allocations, stats_frees, stats_publications;
static int stats_alloc_fail;
static int cdx_ft_stats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot)
{
    unsigned first = kind == CDX_FT_STATS_TIMESTAMPED ? 0 : STATS_TIMESTAMPED_SLOTS;
    unsigned end = kind == CDX_FT_STATS_TIMESTAMPED ? STATS_TIMESTAMPED_SLOTS
                                                    : STATS_TIMESTAMPED_SLOTS + STATS_PLAIN_SLOTS;

    assert(cdx_info->ctrl.mutex);
    *slot = NULL;
    if (stats_alloc_fail) return stats_alloc_fail;
    for (unsigned i = first; i < end; i++) {
        unsigned n = i - first;

        if (stats_taken[i]) continue;
        stats_taken[i] = true;
        stats_pool[i] = (struct cdx_ft_stats_slot){ .index = i, .kind = kind };
        if (kind == CDX_FT_STATS_TIMESTAMPED) {
            stats_pool[i].rx_index = (u8)((n * 2) | STATS_WITH_TS);
            stats_pool[i].tx_index = (u8)((n * 2 + 1) | STATS_WITH_TS);
        } else {
            stats_pool[i].rx_index = (u8)(STATS_PLAIN_BASE + n * 2);
            stats_pool[i].tx_index = (u8)(STATS_PLAIN_BASE + n * 2 + 1);
        }
        stats_allocations++;
        *slot = &stats_pool[i];
        return 0;
    }
    return -ENOSPC;
}
static void cdx_ft_stats_free(struct cdx_ft_stats_slot **slot)
{
    assert(cdx_info->ctrl.mutex);
    if (!*slot) return;
    assert(stats_taken[(*slot)->index]);
    stats_taken[(*slot)->index] = false;
    stats_frees++;
    *slot = NULL;
}
/* Publication is the backend's; here it is recorded on the slot so a case can
 * say which device a record reaches and in what units. */
static void cdx_ft_stats_publish(struct cdx_ft_stats_slot *slot, int ifindex,
                                 unsigned rx_overhead, unsigned tx_overhead)
{
    assert(cdx_info->ctrl.mutex && slot && stats_taken[slot->index] && ifindex);
    slot->published_ifindex = ifindex;
    slot->published_rx_overhead = rx_overhead;
    slot->published_tx_overhead = tx_overhead;
    stats_publications++;
}
/* Withdrawal takes no transaction -- the notifier calls it -- and tolerates a
 * record that never had a slot. */
static void cdx_ft_stats_unpublish(struct cdx_ft_stats_slot *slot)
{
    if (!slot) return;
    assert(stats_taken[slot->index]);
    slot->published_ifindex = 0;
}
static unsigned plain_in_use(void)
{
    unsigned n = 0;
    for (unsigned i = STATS_TIMESTAMPED_SLOTS; i < STATS_TIMESTAMPED_SLOTS + STATS_PLAIN_SLOTS; i++)
        n += stats_taken[i];
    return n;
}
static void cdx_ft_stats_read(const struct cdx_ft_stats_slot *slot,
                              struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
    assert(cdx_info->ctrl.mutex);
    if (rx) *rx = (struct cdx_ft_stats){};
    if (tx) *tx = (struct cdx_ft_stats){};
    if (!slot) return;
    if (rx) *rx = slot->rx;
    if (tx) *tx = slot->tx;
}
static unsigned stats_in_use(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < STATS_TIMESTAMPED_SLOTS; i++) n += stats_taken[i];
    return n;
}
static int cdx_ft_admission_begin(void) { return rtnl_trylock() ? 0 : -EAGAIN; }
static void cdx_ft_admission_end(void) { rtnl_unlock(); }
static bool cdx_ft_failed(void) { return ft_fatal; }
/* A latch CDX will restart the datapath after, rather than one left for a
 * reboot. Cases that say nothing get the reboot. */
static bool ft_restarting;
static bool cdx_ft_terminal(void) { assert(cdx_info->ctrl.mutex); return ft_fatal && !ft_restarting; }
static bool cdx_ft_observing(void) { return ft_observe; }
static unsigned cdx_ft_pending(void) { return private_pending + legacy_pending; }
/* The barrier a retry issues, and whether it completes. A completed one proves
 * every deletion before it, the backend's own and those CDX parked for itself,
 * so both pending counts go with it. A failed one leaves both, and reports
 * failure only for the backend's own, as the backend does. */
static unsigned recoveries;
static bool barrier_fails;
static int cdx_ft_recover(void)
{
    assert(cdx_info->ctrl.mutex);
    recoveries++;
    if (ft_fatal) {
        if (!rtnl_trylock()) return -EAGAIN;
        int rc = dpa_cfg_quiesce(); rtnl_unlock();
        if (rc) return -EAGAIN;
    }
    if (!barrier_fails)
        private_pending = legacy_pending = 0;
    return barrier_fails && private_pending ? -EAGAIN : retry_error;
}
/* The parked rearm's retry is counted apart from the invalidation worker's,
 * so a case can say which of the two was asked to come back. */
static unsigned rearm_retries;
/* Which of the adapter's own work items are queued and not yet cancelled.
 * Cases mostly run a work function by hand instead of from the queue, so this
 * only means something across a stretch a case clears it for -- a load that
 * fails, which must leave nothing queued against text about to go. */
static bool work_queued_invalidate, work_queued_retire, work_queued_rearm, work_queued_dev_stats;
/* A rearm asked for at once, as CDX's restart does, rather than retried. */
static unsigned rearm_kicks;
static void schedule_delayed_work(int *work, unsigned delay)
{
    if (work == &ft_rearm_work && !delay) { rearm_kicks++; work_queued_rearm = true; return; }
    if (work == &ft_rearm_work) { assert(delay == HZ); rearm_retries++; work_queued_rearm = true; return; }
    assert(work == &ft_work);
    scheduled++;
    work_queued_invalidate = true;
}
static unsigned neigh_scheduled, dev_stats_scheduled, stopped_scheduled, follow_scheduled;
static int ft_ipsec_retire, ft_ipsec_follow, ft_ipsec_stats;
static void schedule_work(int *work)
{
    if (work == &ft_mr_work) { mroute_kicks++; return; }
    if (work == &ft_stopped_work) { stopped_scheduled++; return; }
    if (work == &ft_ipsec_follow) { follow_scheduled++; return; }
    assert(work == &ft_retire_work || work == &ft_dev_stats_work);
    if (work == &ft_dev_stats_work) { dev_stats_scheduled++; work_queued_dev_stats = true; }
    else { neigh_scheduled++; work_queued_retire = true; }
}
/* Which devices native cleanup was asked for, in order, and how many of those
 * calls ran under RTNL -- the stopped-port sweep's are all expected to. */
static struct net_device *swept[8];
static unsigned nswept, swept_under_rtnl;
static void nf_flow_table_cleanup(struct net_device *dev)
{
    assert(!cdx_info->ctrl.mutex);
    flushed++;
    if (nswept < ARRAY_SIZE(swept)) swept[nswept] = dev;
    nswept++;
    if (rtnl) swept_under_rtnl++;
    if (cleanup_hook) cleanup_hook();
}
static void dev_hold(struct net_device *d) { d->refs++; }
static void dev_put(struct net_device *d) { assert(d->refs > 0); d->refs--; }
static void netdev_hold(struct net_device *d, netdevice_tracker *t, int gfp)
{ (void)t; assert(gfp == GFP_ATOMIC); d->refs++; }
static void netdev_put(struct net_device *d, netdevice_tracker *t)
{ (void)t; assert(d->refs > 0); d->refs--; }
static unsigned grace_periods;
/* The stopped-port sweep's grace period starts under RTNL, after whichever
 * change raised its event before making it. */
static void synchronize_net(void) { assert(rtnl); grace_periods++; }
/* What for_each_netdev() walks: set by the case that needs a namespace's
 * whole device list, empty otherwise. */
static struct net_device **netdev_registry;
static unsigned netdev_registry_len;
#define for_each_netdev(n, d)                                                  \
    for (unsigned i_ = (assert((n) == &init_net), 0);                          \
         i_ < netdev_registry_len && ((d) = netdev_registry[i_], 1); i_++)
/* The IPsec side of the adapter, which the netdev notifier and the module's
 * own init and exit reach. Stubbed rather than compiled: attaching xfrmdev_ops
 * and resolving an SA pull in xfrm and the SA backend, neither of which this
 * harness simulates, and none of the behaviour under test here depends on
 * them. What must still hold is that the lifecycle calls them at all, so the
 * counters below let a case say so. */
static unsigned ipsec_attached, ipsec_detached, ipsec_detached_all;
static void ft_ipsec_attach(struct net_device *d) { ipsec_attached++; }
static void ft_ipsec_detach(struct net_device *d) { ipsec_detached++; }
static void ft_ipsec_detach_all(void) { ipsec_detached_all++; }
/* The count of what SEC refused, which the module takes at load to count
 * from and once more at unload, both inside the transaction. The fold itself
 * is compiled in ipsec_adapter.c. */
static unsigned sec_refusal_folds;
static void ft_sec_refusals_fold(void) { assert(cdx_info->ctrl.mutex); sec_refusal_folds++; }
static bool swdev_obj_registered, indirect_registered;
/* An SA rebuild an egress change asked for and that has not happened yet, on
 * this port; the follow pass clears it if `ipsec_rebuild_succeeds'. The watch
 * itself is compiled in ipsec_adapter.c. */
static struct net_device *ipsec_rebuild_pending_on;
static bool ipsec_rebuild_succeeds = true;
static bool ft_ipsec_rebuild_pending(const struct net_device *dev)
{ return dev && ipsec_rebuild_pending_on == dev; }
/* An SA deletion still on its way to the hardware, which the retire work,
 * compiled in ipsec_adapter.c, finishes inside the transaction; so it is
 * asked inside one. */
static bool ipsec_retiring;
static bool ft_ipsec_retire_pending(void)
{ assert(cdx_info->ctrl.mutex); return ipsec_retiring; }
/* Work items run where they are flushed, which is what flushing proves. */
static void ft_retire_workfn(struct work_struct *work);
static void ft_invalidate_work(struct work_struct *work);
static unsigned stopped_flushes, follow_flushes, ipsec_retire_flushes;
static void flush_work(int *work)
{
    if (work == &ft_stopped_work) {
        /* Only once nothing can queue it again; and on unload, while the
         * rule callbacks the sweep's native cleanup flushes are still
         * registered. A failed load's unwind sets ft_stopping as well, but
         * flushes only once ft_ready is clear and every bind is drained, so
         * the cleanup reaches none of them. Flushing runs whatever is still
         * queued. */
        assert(!swdev_obj_registered);
        assert(ft_ready ? indirect_registered : ft_block_list.next == &ft_block_list);
        stopped_flushes++;
        ft_stopped_workfn(NULL);
        return;
    }
    if (work == &ft_retire_work) { ft_retire_workfn(NULL); return; }
    if (work == &ft_ipsec_follow) {
        assert(!cdx_info->ctrl.mutex);
        follow_flushes++;
        if (ipsec_rebuild_succeeds) ipsec_rebuild_pending_on = NULL;
        return;
    }
    assert(work == &ft_ipsec_retire);
    ipsec_retire_flushes++;
}
/* What retired SAs left for a re-add of them, dropped only once the
 * retirements that record it are drained. The records themselves are
 * compiled in ipsec_adapter.c. */
static unsigned ipsec_forgotten;
static void ft_ipsec_forget_all(void)
{
    assert(ipsec_retire_flushes > ipsec_forgotten);
    ipsec_forgotten++;
}
/* Set by a case to model a rearm landing while the egress drain waits for
 * the invalidation pass: the latch clears, and the done flag with it. */
static bool rearm_in_flush;
static void flush_delayed_work(int *work)
{
    assert(work == &ft_work);
    ft_invalidate_work(NULL);
    if (rearm_in_flush) {
        ft_invalid = 0;
        ft_invalid_done = false;
    }
}
#define might_sleep() do { } while (0)
static void ft_ipsec_watch_flush(void) { }
/* The SA next-hop watch, which the same dependency notifiers mark. What the
 * marking then does needs an installed SA and the backend behind it, so it is
 * compiled in the IPsec harness instead; here the counters only have to show
 * that a dependency change reaches the SAs as well as the flows. */
static unsigned ipsec_marked_neigh, ipsec_marked_route, ipsec_marked_all,
		ipsec_marked_device;
static void ft_ipsec_neigh_moved(struct neighbour *n) { ipsec_marked_neigh++; }
static void ft_ipsec_route_moved(u8 family, const void *dst, __be32 mask,
				 unsigned int prefixlen) { ipsec_marked_route++; }
static void ft_ipsec_all_moved(void) { ipsec_marked_all++; }
static void ft_ipsec_device_moved(const struct net_device *d) { ipsec_marked_device++; }
/* Policy resolution for both ends of a direction, which needs xfrm. A case
 * sets what the answer should be; refusing must reject the direction rather
 * than install it, because an entry installed past a policy that says encrypt
 * forwards in the clear. */
static bool ipsec_ok = true;
static u16 ipsec_sa, ipsec_in_sa;
/* Whether any xfrm policy or blocking default is configured. With none, every
 * lookup the real resolver makes returns the plain route -- no SA, no denial --
 * so a case that wants either has to configure a policy first. That is also
 * what sends a table's packets past the software fast path, and so what stops
 * Linux offering its flows again. */
static bool xfrm_policies;
static bool xfrm_flowtable_enabled(struct net *net)
{
    assert(net == &init_net);
    return !xfrm_policies;
}
static bool ft_ipsec_handle(const struct flow_cls_offload *cls, struct cdx_ft_rule *out,
                            struct net_device *egress, struct net_device *ingress)
{
    assert(xfrm_policies || (ipsec_ok && !ipsec_sa && !ipsec_in_sa));
    out->sa_handle = ipsec_sa;
    out->in_sa_handle = ipsec_in_sa;
    return ipsec_ok;
}
/* Resolves the one device a session hop names. Defined past the device
 * declarations, which the production decoder is included ahead of. Takes no
 * reference, exactly as the kernel's does under RTNL. */
static struct net_device *__dev_get_by_index(struct net *net, int ifindex);
static int atomic_read(int *v) { return *v; }
static void atomic_set(int *v, int n) { *v = n; }
static void atomic_inc(int *v) { ++*v; }
static int ft_invalid_seq, ft_done_seq;
/* A global event, as the notifiers raise one: counted while anything is
 * parked, and latched. The pass it would queue is driven by each case. */
static unsigned events_counted;
static void ft_invalidate(void)
{
    if (ft_parked) { ft_invalid_seq++; events_counted++; }
    ft_invalid = 1;
}
/* The full barrier ft_rearm() puts between clearing the latch and reading the
 * count is where a notifier on another CPU can land; a case hooks it to raise
 * an event exactly there. */
static void (*barrier_hook)(void);
static void smp_mb(void) { if (barrier_hook) { void (*hook)(void) = barrier_hook; barrier_hook = NULL; hook(); } }
#define smp_mb__after_atomic() smp_mb()
static bool cdx_ft_port_supported(struct net_device *d) { return d && physical_ok; }
/* The egress set is wider in production (an open VAP); the asymmetry has its
 * own harness (wifi_admission.c). Here the two sets coincide. */
static bool cdx_ft_egress_supported(struct net_device *d) { return cdx_ft_port_supported(d); }
static unsigned int ft_passive;
/* ASK-DEBUG tracing is a printk in production; nothing to observe here. */
#define ask_refuse(err) (err)
#define ask_dbg(bit, fmt, ...) do { } while (0)
/* Both tables read key_len bytes from the front of the address union, so the
 * caller hands over the same pointer for either family. */
static struct neighbour *neigh_lookup(struct neigh_table *table, const void *dst, struct net_device *dev)
{
    neigh_lookups++;
    if (!neigh_ok) return NULL;
    assert(table == &arp_tbl || table == &nd_tbl);
    struct neighbour *all[] = {&neighbour, &gateway, &alternate_gateway};
    for (unsigned i = 0; i < ARRAY_SIZE(all); i++) {
        struct neighbour *n = all[i];
        if (n->tbl != table || memcmp(&n->primary_key, dst, table->key_len) ||
            n->dev != dev) continue;
        if (change_neigh_on_lookup && neigh_lookups == 2) n->ha[5]++;
        n->refs++;
        return n;
    }
    return NULL;
}
static void neigh_release(struct neighbour *n) { assert(n->refs); n->refs--; }
/* The kernel routes an SA's endpoint in the SA's own family and names the
 * neighbour on the SA's device; a case says which one that is, or none. */
static struct neighbour *peer_neigh;
static unsigned peer_neigh_lookups;
static struct neighbour *xfrm_dev_peer_neigh(struct xfrm_state *x)
{
    (void)x;
    peer_neigh_lookups++;
    if (peer_neigh)
        peer_neigh->refs++;
    return peer_neigh;
}
static int neigh_event_send(struct neighbour *n, void *skb)
{
    assert(n->refs && !n->lock && !ft_watch_lock && !skb);
    neigh_uses++;
    return neigh_send_error;
}
static void *kzalloc(size_t n, int flags) { if (allocation_fail) return NULL; allocated++; return calloc(1, n); }
static void kfree(void *p) { assert(allocated); allocated--; free(p); }
static int ft_rule_callback(enum tc_setup_type t, void *data, void *priv);
static int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr);
typedef int (*rule_callback_t)(enum tc_setup_type, void *, void *);
static struct flow_block_cb *flow_indr_block_cb_alloc(rule_callback_t fn, void *ident,
    void *priv, void (*release)(void *), struct flow_block_offload *bo,
    struct net_device *dev, struct Qdisc *sch, void *table, void *driver,
    void (*cleanup)(struct flow_block_cb *))
{
    if (callback_allocation_fail) return ERR_PTR(-ENOMEM);
    struct flow_block_cb *cb = kzalloc(sizeof(*cb), GFP_KERNEL); assert(cb);
    cb->cb = fn; cb->ident = ident; cb->cb_priv = priv; cb->release = release;
    cb->indirect = true;
    list_add_tail(&cb->indr_list, &flow_block_indr_list);
    if (invalidate_on_bind) { assert(ft_bound); ft_invalidate(); }
    return cb;
}
static void flow_block_cb_add(struct flow_block_cb *cb, struct flow_block_offload *bo)
{ list_add_tail(&cb->list, &bo->cb_list); }
static struct flow_block_cb *flow_block_cb_lookup(struct flow_block *block,
                                                 rule_callback_t fn, void *ident)
{
    struct flow_block_cb *cb;
    /* By callback as well as identity, as the kernel does: a passively bound
     * device and a programmed one carry different callbacks. */
    list_for_each_entry(cb, &block->cb_list, list)
        if (cb->ident == ident && cb->cb == fn) return cb;
    return NULL;
}
static void flow_indr_block_cb_remove(struct flow_block_cb *cb, struct flow_block_offload *bo)
{
    /* Moving a published callback must exclude native stats walkers before
     * it reaches the temporary list; protecting only its free is too late. */
    assert(block_write_lock && *block_write_lock);
    list_del(&cb->indr_list);
    list_del(&cb->list); list_add_tail(&cb->list, &bo->cb_list);
}
/* The filter layer's answer for a finished tuple. A tc police filter is the
 * more specific statement of the same intent as the mark, so a non-zero answer
 * replaces the mark's policer nibble -- and the rule carries the result, so
 * that what the hardware is told and what /proc reports are the same thing. */
static u8 police_lookup_profile;
static unsigned police_lookups;
static u8 cdx_police_lookup(const struct cdx_ft_rule *rule)
{
    /* A filter matches on the finished tuple, so this has to be asked last --
     * with the ports, the protocol and the ingress device already decided.
     * Asking earlier would match some filters against a half-built rule. */
    assert(rule && rule->in && rule->out);
    assert(rule->family == AF_INET || rule->family == AF_INET6);
    assert(rule->proto == IPPROTO_TCP || rule->proto == IPPROTO_UDP);
    assert(rule->mtu);
    police_lookups++;
    return police_lookup_profile;
}

/* The direct route's pair. Netfilter holds flow_block_lock across the whole of
 * ndo_setup_tc there, so the exclusion the indirect move asserts has to hold
 * here too -- it is just the caller who established it. This is the route
 * every bind takes once the driver has an ndo_setup_tc, which it now does. */
static struct flow_block_cb *flow_block_cb_alloc(rule_callback_t fn, void *ident,
    void *priv, void (*release)(void *))
{
    if (callback_allocation_fail) return ERR_PTR(-ENOMEM);
    struct flow_block_cb *cb = kzalloc(sizeof(*cb), GFP_KERNEL); assert(cb);
    cb->cb = fn; cb->ident = ident; cb->cb_priv = priv; cb->release = release;
    cb->indirect = false;
    if (invalidate_on_bind) { assert(ft_bound); ft_invalidate(); }
    return cb;
}
/* Netfilter's own free: runs the release and drops the callback. Mirrors a
 * kernel API, so it stays declared whether or not this build calls it. */
__attribute__((unused))
static void flow_block_cb_free(struct flow_block_cb *cb)
{
    cb->release(cb->cb_priv);
    kfree(cb);
}
static void flow_block_cb_remove(struct flow_block_cb *cb, struct flow_block_offload *bo)
{
    assert(block_write_lock && *block_write_lock);
    list_del(&cb->list); list_add_tail(&cb->list, &bo->cb_list);
}
/* The registration the direct route arrives through. CDX holds the driver's
 * single ndo_setup_tc, because it serves the hardware qdisc on the same
 * callback, so the adapter registers with CDX rather than with the driver.
 * Exactly one handler may be live at a time, and a load that fails after taking
 * it has to give it back -- otherwise the next load finds the slot occupied by
 * a module that is no longer there. */
static int registered_setup_tc;
/* What a consumer does the moment a route opens while the load is still
 * running: bind, admit, and leave work queued. Run as each registration that
 * opens one -- the indirect route, then the direct route and what follows it
 * -- returns, so a load failing at any later stage has to unwind it. */
static void (*route_open_hook)(void);
static void route_opened(void) { if (route_open_hook) route_open_hook(); }
typedef int (*cdx_ft_setup_tc_handler)(struct net_device *, enum tc_setup_type, void *);
static int cdx_register_ft_setup_tc(cdx_ft_setup_tc_handler handler)
{
    assert(handler);
    if (registered_setup_tc) return -EBUSY;
    registered_setup_tc = 1;
    route_opened();
    return 0;
}
static void cdx_unregister_ft_setup_tc(void) { registered_setup_tc = 0; }
/* The classifier CDX borrows so the software Tx path resolves a frame's class
 * with the same function that gave the flow's hardware rule one. It is claimed
 * and returned alongside the handler above, and a load that fails after taking
 * it has to give both back. */
static int registered_qos_class;
struct sk_buff;
typedef bool (*cdx_ft_qos_class_fn)(const struct sk_buff *skb, unsigned int nhoff,
                                    u8 family, bool own, u32 *class);
/* What it hands over has a harness of its own (qos_flow_class.c); here only
 * the claim and its return are exercised. */
static bool ft_qos_flow_class(const struct sk_buff *skb, unsigned int nhoff,
                              u8 family, bool own, u32 *class)
{ return false; }
static int cdx_register_ft_qos_class(cdx_ft_qos_class_fn fn, bool remarks)
{
    assert(fn);
    if (registered_qos_class) return -EBUSY;
    registered_qos_class = 1;
    route_opened();
    return 0;
}
static void cdx_unregister_ft_qos_class(void) { registered_qos_class = 0; }
/* The hooks CDX calls when a port's egress changes under its entries, claimed
 * and returned with the two above. */
static int registered_egress_changed;
struct cdx_ft_egress_ops {
    void (*changed)(struct net_device *dev);
    int (*drain)(struct net_device *dev);
    void (*restarted)(void);
};
static void ft_egress_changed(struct net_device *dev);
static int ft_egress_drain(struct net_device *dev);
static void ft_egress_restarted(void);
static struct net_device *egress_change_on_add;
/* File-scope data in the adapter, so defined here beside what it points at. */
static const struct cdx_ft_egress_ops ft_egress_ops = {
    .changed = ft_egress_changed,
    .drain = ft_egress_drain,
    .restarted = ft_egress_restarted,
};
static int cdx_register_ft_egress(const struct cdx_ft_egress_ops *ops)
{
    assert(ops == &ft_egress_ops);
    if (registered_egress_changed) return -EBUSY;
    registered_egress_changed = 1;
    return 0;
}
static void cdx_unregister_ft_egress(void) { registered_egress_changed = 0; }
/* The IPsec half of an egress change, compiled and tested in ipsec_adapter.c;
 * here only whether the flow half hands it the port. */
static struct net_device *ipsec_egress_changed;
static u64 ft_egress_changes, egress_changes_seen_by_ipsec;
static void ft_ipsec_egress_changed(const struct net_device *dev)
{ ipsec_egress_changed = (struct net_device *)dev; egress_changes_seen_by_ipsec = ft_egress_changes; }
/* The multicast halves, compiled in mcast_learner.c and mroute_refresh.c; here
 * only whether the port reaches them, after the change is counted, and whether
 * a group they cannot vouch for holds the drain. */
static struct net_device *mc_egress_changed;
static u64 egress_changes_seen_by_mc;
static int mc_drain_rc, mr_drain_rc;
static unsigned mc_drains, mr_drains;
static void ft_mc_egress_changed(const struct net_device *dev)
{ mc_egress_changed = (struct net_device *)dev; egress_changes_seen_by_mc = ft_egress_changes; }
static int ft_mc_egress_drain(const struct net_device *dev)
{ assert(!cdx_info->ctrl.mutex); mc_drains++; return mc_drain_rc; }
static int ft_mr_egress_drain(const struct net_device *dev)
{ assert(!cdx_info->ctrl.mutex); mr_drains++; return mr_drain_rc; }
/* What the encoder would write into the two PPPoE opcodes, recorded so a test
 * can require the index rather than the slot pointer: a direction that strips
 * counts into its session's receive half, one that inserts into the transmit
 * half of its own, and a session with no record leaves zero. */
static u8 observed_in_stats, observed_out_stats;
static u8 observed_in_vlan[CDX_FT_VLAN_MAX], observed_out_vlan[CDX_FT_VLAN_MAX];
static u8 observed_in_tunnel, observed_out_tunnel;
static int cdx_ft_add(const struct cdx_ft_rule *r,
                      const struct cdx_ft_stats_binding *stats, struct cdx_ft_hw **hw)
{
    assert(stats);
    assert(!stats->in_session || r->in_session.present);
    assert(!stats->out_session || r->out_session.present);
    observed_in_stats = stats->in_session ? stats->in_session->rx_index : 0;
    observed_out_stats = stats->out_session ? stats->out_session->tx_index : 0;
    /* And the tunnel device's slot, which takes its halves the same way: the
     * strip counts receives and the insert transmits. */
    assert(!stats->in_tunnel || r->in_tunnel.present);
    assert(!stats->out_tunnel || r->out_tunnel.present);
    observed_in_tunnel = stats->in_tunnel ? stats->in_tunnel->rx_index : 0;
    observed_out_tunnel = stats->out_tunnel ? stats->out_tunnel->tx_index : 0;
    /* A tag's slot is named only for a tag the rule carries, and the halves
     * are the record's: receive for what is stripped, transmit for what is
     * inserted. */
    for (unsigned i = 0; i < CDX_FT_VLAN_MAX; i++) {
        assert(!stats->in_vlan[i] || i < r->in_vlans);
        assert(!stats->out_vlan[i] || i < r->out_vlans);
        observed_in_vlan[i] = stats->in_vlan[i] ? stats->in_vlan[i]->rx_index : 0;
        observed_out_vlan[i] = stats->out_vlan[i] ? stats->out_vlan[i]->tx_index : 0;
    }
    if (hardware_fail) return -EIO;
    if (hardware_alloc_error) {
        assert(ft_handle_refs && ft_neighbour_refs);
        return hardware_alloc_error;
    }
    *hw = calloc(1, sizeof(**hw)); assert(*hw); live_hw++;
    (*hw)->stats.lastused = (u32)jiffies;
    if (invalidate_on_add) ft_invalidate();
    /* An egress change landing while the entry is being built. The change
     * holds RTNL and admission does not, so nothing orders the two but the
     * watch list. */
    if (egress_change_on_add) { assert(!rtnl); ft_egress_changed(egress_change_on_add); }
    if (change_policy_on_add) xfrm_genid++;
    if (change_sa_on_add) ft_ipsec_genid++;
    if (change_neigh_on_add) {
        neighbour.ha[5]++;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    }
    return 0;
}
static int cdx_ft_del(struct cdx_ft_hw **hw)
{ assert(*hw && live_hw); live_hw--; free(*hw); *hw = NULL; if (deletion_error == -EIO) ft_fatal = true; return deletion_error; }
static void cdx_ft_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats) { *stats = hw->stats; }

/* Registration infrastructure; backend claim semantics are exercised against
 * production CDX in flowtable_hw.c. Here each acquisition can fail in turn. */
struct proc_dir_entry { int unused; };
static struct proc_dir_entry proc_entry, *ft_proc;
static int ft_proc_ops;
static struct notifier_block ft_netdev_nb, ft_neigh_nb, ft_fib_nb, ft_nexthop_nb;
static struct notifier_block ft_fdb_nb, ft_swdev_nb;
static unsigned registration_step, registration_failure, canceled;
static bool backend_claimed, netdev_registered, neigh_registered, fib_registered, nexthop_registered, indirect_registered;
static bool fdb_registered, swdev_obj_registered;
static bool registration_fails(void) { return ++registration_step == registration_failure; }
static struct proc_dir_entry *proc_create(const char *name, int mode, void *parent, void *ops)
{ assert(!strcmp(name,"cdx_flowtable") && mode == 0400 && !parent); return registration_fails() ? NULL : &proc_entry; }
static void proc_remove(struct proc_dir_entry *entry) { assert(entry == &proc_entry); }
static int cdx_ft_claim(void)
{
    assert(cdx_info->ctrl.mutex && !backend_claimed);
    if (ft_fatal) return -EOPNOTSUPP;
    if (registration_fails()) return -EBUSY;
    backend_claimed = true; return 0;
}
static int cdx_ft_release(void)
{
    assert(cdx_info->ctrl.mutex && backend_claimed && !live_hw);
    backend_claimed = false; return 0;
}
/* The egress hook is registered before anything that can build an entry: this
 * replay attaches the ports an SA is installed through, and the binds come
 * after it. An entry built first would miss an egress change made meanwhile. */
static int register_netdevice_notifier(struct notifier_block *nb)
{ assert(registered_egress_changed); if (registration_fails()) return -ENOMEM; netdev_registered=true; return 0; }
static int register_netevent_notifier(struct notifier_block *nb)
{ if (registration_fails()) return -ENOMEM; neigh_registered=true; return 0; }
static int register_fib_notifier(struct net *net, struct notifier_block *nb, void *cb, void *extack)
{ if (registration_fails()) return -ENOMEM; fib_registered=true; return 0; }
static int register_nexthop_notifier(struct net *net, struct notifier_block *nb, void *extack)
{ assert(net == &init_net && !cdx_info->ctrl.mutex); if (registration_fails()) return -ENOMEM; nexthop_registered=true; return 0; }
static void unregister_nexthop_notifier(struct net *net, struct notifier_block *nb)
{ assert(net == &init_net && nexthop_registered && !cdx_info->ctrl.mutex); nexthop_registered=false; }
static void unregister_netdevice_notifier(struct notifier_block *nb)
{ assert(netdev_registered); netdev_registered=false; }
static void unregister_netevent_notifier(struct notifier_block *nb)
{ assert(neigh_registered); neigh_registered=false; }
static void unregister_fib_notifier(struct net *net, struct notifier_block *nb)
{ assert(fib_registered); fib_registered=false; }
static int register_switchdev_notifier(struct notifier_block *nb)
{ if (registration_fails()) return -ENOMEM; fdb_registered=true; return 0; }
static void unregister_switchdev_notifier(struct notifier_block *nb)
{ assert(fdb_registered); fdb_registered=false; }
static int register_switchdev_blocking_notifier(struct notifier_block *nb)
{ if (registration_fails()) return -ENOMEM; swdev_obj_registered=true; return 0; }
static void unregister_switchdev_blocking_notifier(struct notifier_block *nb)
{ assert(swdev_obj_registered); swdev_obj_registered=false; }
/* The bridged multicast learner asks every bridge port for the memberships
 * it already holds: only once the blocking notifier is registered, so
 * nothing falls between the two, and before the adapter says it is ready. */
static unsigned mc_replays;
static void ft_mc_replay(void) { assert(swdev_obj_registered && !ft_ready); mc_replays++; }
/* Both learners are woken for the multicast switch once the adapter is
 * ready, answering a flip that fell while they were starting. */
static unsigned mc_switches;
static void ft_mc_switched(void) { assert(ft_ready); mc_switches++; }
static void cancel_work_sync(int *work)
{
    assert(work == &ft_retire_work || work == &ft_ipsec_follow || work == &ft_dev_stats_work);
    /* CDX's egress hook queues both of these, and nothing the adapter
     * unregisters before it excludes the hook, so cancelling either while it
     * is still registered could be undone by the next call. */
    if (work != &ft_dev_stats_work)
        assert(!registered_egress_changed);
    if (work == &ft_retire_work) work_queued_retire = false;
    if (work == &ft_dev_stats_work) work_queued_dev_stats = false;
    canceled++;
}
static void cancel_delayed_work_sync(int *work)
{
    assert(work == &ft_work || work == &ft_ipsec_stats || work == &ft_rearm_work);
    if (work == &ft_work) work_queued_invalidate = false;
    else if (work == &ft_rearm_work) work_queued_rearm = false;
    canceled++;
}
static int register_indirect(void)
{
    assert(ft_ready);
    if (registration_fails()) return -ENOMEM;
    indirect_registered=true;
    route_opened();
    return 0;
}
static void unregister_indirect(void (*release)(void *))
{
    assert(indirect_registered && !cdx_info->ctrl.mutex);
    /* Both unwinds stop new binds first. Unload gives this route back last,
     * with all five works cancelled -- retirement, the delayed installer, the
     * parked rearm's retry, the SA next-hop follower and the SA accounting
     * pass -- and every notifier already gone. A load unwinding its own
     * failure gives it back first and cancels the works after, once nothing
     * bound is left to queue them, with its notifiers still registered: that
     * is what tells the two apart. */
    assert(ft_stopping);
    if (!netdev_registered) {
        assert(canceled == 5);
        assert(!neigh_registered && !fib_registered && !nexthop_registered);
        assert(!fdb_registered && !swdev_obj_registered);
    } else {
        assert(!canceled);
    }
    /* Only the indirect callbacks, and only those whose release is the one
     * given, exactly as __flow_block_indr_cleanup() selects them. Netfilter
     * tracks those itself and unwinds them here; a direct callback is the
     * flowtable's property and it has no idea the adapter is leaving.
     * Releasing those too -- as this stub used to -- models a cleanup the
     * kernel does not perform, and hid a use-after-free: the direct callback
     * survived unload, and the next offload work item called into freed
     * module text. Selecting by route rather than by release hid another: an
     * indirect callback with a release of its own stays on the indirect list
     * whatever route installed it. */
    struct flow_block_cb *cb, *next;
    list_for_each_entry_safe(cb, next, &flow_block_indr_list, indr_list) {
        assert(cb->indirect);
        if (cb->release != release)
            continue;
        list_del(&cb->indr_list);
        /* nf_flow_table_indr_cleanup(). */
        list_del(&cb->list); list_del(&cb->driver_list);
        cb->release(cb->cb_priv); kfree(cb);
    }
    indirect_registered=false;
}
#define flow_indr_dev_register(fn, priv) register_indirect()
#define flow_indr_dev_unregister(fn, priv, release) unregister_indirect(release)
static unsigned unload_sleeps, unload_failures;
static void msleep(unsigned ms)
{
    assert(ms == 1000 && backend_claimed && !cdx_info->ctrl.mutex && !rtnl);
    assert(!indirect_registered && !ft_count && !ft_bound && canceled == 5);
    assert(unload_failures);
    unload_sleeps++;
    if (!--unload_failures) { retry_error=0; quiesce_fail=false; }
}
#include "flowtable_production.inc"

static struct net_device in = { .ifindex = 5, .mtu = 1500, .type = ARPHRD_ETHER,
                                .dev_addr = {2, 0, 0, 0, 0, 1} };
static struct net_device out = { .ifindex = 6, .mtu = 1500, .type = ARPHRD_ETHER,
                                 .dev_addr = {2, 0, 0, 0, 0, 2} };
/* A bridge over each physical port, and a VLAN device on top of one of them:
 * what OpenWrt spells br-lan and br-lan.N. `decoy` is each bridge's first
 * lower device and deliberately not the port a flow leaves by -- a walk that
 * descended a bridge through its adjacency list would land there, because a
 * bridge has many lower devices and the first is whichever was enslaved
 * first, never the one the FDB chose. */
static struct net_device decoy = { .ifindex = 11, .mtu = 1500, .type = ARPHRD_ETHER,
                                   .dev_addr = {2, 0, 0, 0, 0, 9} };
static struct net_device br = { .ifindex = 12, .mtu = 1500, .type = ARPHRD_ETHER,
                                .dev_addr = {2, 0, 0, 0, 0, 2},
                                .real_dev = &decoy, .bridge = true };
static struct net_device br_tag = { .ifindex = 13, .mtu = 1500, .type = ARPHRD_ETHER,
                                    .dev_addr = {2, 0, 0, 0, 0, 2},
                                    .real_dev = &br, .vlan_id = 100 };
static struct net_device in_br = { .ifindex = 14, .mtu = 1500, .type = ARPHRD_ETHER,
                                   .dev_addr = {2, 0, 0, 0, 0, 1},
                                   .real_dev = &decoy, .bridge = true };
/* br-lan.100.300: a second tag inside the bridge's own, so the bridge resolves
 * on an outermost tag that is not the only one. */
static struct net_device br_qinq = { .ifindex = 15, .mtu = 1500, .type = ARPHRD_ETHER,
                                     .dev_addr = {2, 0, 0, 0, 0, 2},
                                     .real_dev = &br_tag, .vlan_id = 300 };
/* Two ppp devices, one per direction. No address (addr_len is zero in the
 * kernel, so dev_addr stays the zero one arp_constructor leaves behind), no
 * lower device, and the reduced MTU pppd negotiates for a session. */
static struct net_device ppp = { .ifindex = 16, .mtu = 1492, .type = ARPHRD_PPP };
static struct net_device in_ppp = { .ifindex = 17, .mtu = 1492, .type = ARPHRD_PPP };
static struct cdx_ft_binding binding = { .dev = &in };
static struct dst_ops ipv4_ops = { .family = AF_INET };
static struct dst_ops ipv6_ops6 = { .family = AF_INET6 };
static struct rtable route, reverse_route;
static struct rt6_info route6, reverse_route6;
static struct ipv6_addrs i6k, i6m;
static struct in6_addr addr6(u32 prefix, u32 tail)
{
    struct in6_addr a;

    memset(&a, 0, sizeof(a));
    a.s6_addr32[0] = htonl(prefix);
    a.s6_addr32[3] = htonl(tail);
    return a;
}
static union nf_inet_addr next_hop;
/* What patches 140 and 143 hand the callback: one record per direction, always
 * present and describing no session and no tunnel until a fixture fills one
 * in. */
static struct nf_flow_session egress_session, ingress_session;
static struct nf_flow_tunnel egress_tunnel, ingress_tunnel;
static struct nf_conn ct;
static struct flow_dissector dissector;
static struct flow_rule rule;
static struct flow_cls_offload cls;
static struct meta mk, mm;
static struct control ck, cm;
static struct basic bk, bm;
static struct ipv4_addrs ik, im;
static struct ports pk, pm;
static struct tcp tk, tm;
static void fixture(void)
{
    /* Both ends plain by default: a case that wants a transform says so. */
    ipsec_ok = true;
    ipsec_sa = ipsec_in_sa = 0;
    xfrm_policies = false;
    in.ip6_mtu = 0;
    in.mtu = 1500;
    ft_ipsec_genid = xfrm_genid = 0;
    assert(!ft_handle_refs && handle.refs <= 1);
    handle = (struct nf_flow_offload_handle){ .refs = 1 };
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs && ft_neigh_entries.next == &ft_neigh_entries);
    neighbour = (struct neighbour){ .tbl = &arp_tbl, .nud_state = NUD_PERMANENT,
                                  .ha = {2,0x11,0x22,0x33,0x44,0x55}, .dev = &out,
                                  .primary_key.ip = htonl(0xc6336402) };
    gateway = alternate_gateway = neighbour;
    gateway.primary_key.ip = htonl(0xc6336401);
    alternate_gateway.primary_key.ip = htonl(0xc6336403);
    route = (struct rtable){ .dst = { .ops = &ipv4_ops, .dev = &out, .valid = true },
                             .rt_type = RTN_UNICAST };
    reverse_route = route;
    reverse_route.dst.dev = &in;
    neigh_lookups = 0;
    /* l3num on both tuples: the decoder requires the conntrack's family to
     * agree with the one the dissector described. */
    ct = (struct nf_conn){ .net = &init_net, .protonum = IPPROTO_UDP,
        .tuplehash = { { .tuple.src.l3num = AF_INET }, { .tuple.src.l3num = AF_INET } } };
    dissector.used_keys = FT_KEYS4;
    mk = (struct meta){ .ingress_ifindex = 5 }; mm = (struct meta){ .ingress_ifindex = -1 };
    ck = (struct control){ .addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS };
    cm = (struct control){ .addr_type = 0xffff };
    bk = (struct basic){ .n_proto = htons(ETH_P_IP), .ip_proto = IPPROTO_UDP };
    bm = (struct basic){ .n_proto = htons(0xffff), .ip_proto = 0xff };
    ik = (struct ipv4_addrs){ htonl(0xc0000202), htonl(0xc6336402) };
    im = (struct ipv4_addrs){ 0xffffffff, 0xffffffff };
    pk = (struct ports){ htons(10000), htons(20000) }; pm = (struct ports){ 0xffff, 0xffff };
    rule = (struct flow_rule){ .match.dissector = &dissector, .action.num_entries = 5,
        .meta = {&mk, &mm}, .control = {&ck, &cm}, .basic = {&bk, &bm},
        .ipv4_addrs = {&ik, &im}, .ports = {&pk, &pm} };
    /* Independent byte fixtures for DA 02:11:22:33:44:55 and SA 02:00:00:00:00:02. */
    u8 values[4][4] = {{0,0,2,0}, {0,0,0,2}, {2,0x11,0x22,0x33}, {0x44,0x55,0,0}};
    const unsigned offsets[] = {4,8,0,4};
    const u32 masks[] = {0xffff,0,0,0xffff0000};
    for (unsigned i = 0; i < 4; i++) {
        rule.action.entries[i].id = FLOW_ACTION_MANGLE;
        rule.action.entries[i].mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_ETH;
        rule.action.entries[i].mangle.offset = offsets[i];
        rule.action.entries[i].mangle.mask = masks[i];
        memcpy(&rule.action.entries[i].mangle.val, values[i], 4);
    }
    rule.action.entries[4].id = FLOW_ACTION_REDIRECT;
    rule.action.entries[4].dev = &out;
    egress_session = ingress_session = (struct nf_flow_session){};
    egress_tunnel = ingress_tunnel = (struct nf_flow_tunnel){};
    /* The path as large as the port the flow arrives on, the ordinary
     * Ethernet case: a case about a smaller one narrows it. */
    cls = (struct flow_cls_offload){ .rule = &rule, .nf_ct = &ct, .nf_dst = &route.dst, .nf_mtu = 1500,
        .nf_dst_reverse = &reverse_route.dst, .nf_handle = &handle, .cookie = 123, .common.protocol = ETH_P_ALL,
        .nf_session = &egress_session, .nf_session_reverse = &ingress_session,
        .nf_tunnel = &egress_tunnel, .nf_tunnel_reverse = &ingress_tunnel };
    physical_ok = neigh_ok = true;
    /* Unbridged by default. A leftover master or VLAN membership from a
     * bridged case would change the path every later one walks. */
    in.master = out.master = decoy.master = NULL;
    in.br_nvlans = out.br_nvlans = 0;
}
/* The IPv4 fixture converted one family over: same devices, same Ethernet
 * rewrites and redirect, but IPv6 selectors, an rt6 destination carrying the
 * cookie it was selected under, and a neighbour-discovery next hop. */
#define V6_LAN 0x202
#define V6_WAN 0x401
#define V6_NAT 0x104
static void tcp_fixture(void);
static void tcp_flow(void);
static void udp_flow(void);

static void fixture6(void)
{
    fixture();
    dissector.used_keys = FT_KEYS6;
    ck.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
    bk.n_proto = htons(ETH_P_IPV6);
    i6k = (struct ipv6_addrs){ addr6(0xfc00dead, V6_LAN), addr6(0xfc00beef, V6_WAN) };
    memset(&i6m, 0xff, sizeof(i6m));
    rule.ipv6_addrs = (struct flow_match_ipv6_addrs){ &i6k, &i6m };
    ct.tuplehash[0].tuple = (struct nf_conntrack_tuple){
        .src = { .u3.in6 = i6k.src, .u.all = pk.src, .l3num = AF_INET6 },
        .dst = { .u3.in6 = i6k.dst, .u.all = pk.dst } };
    ct.tuplehash[1].tuple = (struct nf_conntrack_tuple){
        .src = { .u3.in6 = i6k.dst, .u.all = pk.dst, .l3num = AF_INET6 },
        .dst = { .u3.in6 = i6k.src, .u.all = pk.src } };
    route6 = (struct rt6_info){ .dst = { .ops = &ipv6_ops6, .dev = &out, .valid = true,
                                         .cookie = 0x5e1 } };
    reverse_route6 = route6;
    reverse_route6.dst.dev = &in;
    cls.nf_dst = &route6.dst; cls.nf_dst_reverse = &reverse_route6.dst;
    cls.nf_dst_cookie = cls.nf_dst_reverse_cookie = 0x5e1;
    /* A path smaller than the port, as a PPPoE uplink's is, and a LAN that
     * advertises it, which is what lets an IPv6 direction into hardware at
     * all when the path is smaller. */
    cls.nf_mtu = 1492;
    in.ip6_mtu = cls.nf_mtu;
    neighbour.tbl = &nd_tbl;
    neighbour.primary_key = (union nf_inet_addr){ .in6 = i6k.dst };
    gateway = alternate_gateway = neighbour;
    /* A real IPv6 gateway is link-local, which a flow endpoint may never be. */
    gateway.primary_key.in6 = addr6(0xfe800000, 1);
    alternate_gateway.primary_key.in6 = addr6(0xfe800000, 2);
}

/* Lay out one native IPv6 source translation: four address words then the
 * port, where IPv4 spends one word and appends a checksum action. */
static void nat6_fixture(void)
{
    union nf_inet_addr translated = { .in6 = addr6(0xfc00beef, V6_NAT) };

    fixture6();
    ct.status = IPS_SRC_NAT | IPS_SRC_NAT_DONE;
    ct.tuplehash[1].tuple.dst = (typeof(ct.tuplehash[1].tuple.dst)){
        .u3 = translated, .u.all = htons(40000) };
    for (unsigned i = 0; i < 4; i++) {
        rule.action.entries[4 + i] = (struct flow_action_entry){
            .id = FLOW_ACTION_MANGLE,
            .mangle = { .htype = FLOW_ACT_MANGLE_HDR_TYPE_IP6,
                        .offset = offsetof(struct ipv6hdr, saddr) + i * 4,
                        .val = translated.all[i] } };
    }
    rule.action.entries[8] = (struct flow_action_entry){
        .id = FLOW_ACTION_MANGLE,
        .mangle = { .htype = FLOW_ACT_MANGLE_HDR_TYPE_UDP,
                    .mask = ~htonl(0xffff0000), .val = htonl(40000u << 16) } };
    rule.action.entries[9] = (struct flow_action_entry){ .id = FLOW_ACTION_REDIRECT, .dev = &out };
    rule.action.num_entries = 10;
}

static void test_ipv6(void)
{
    struct cdx_ft_rule decoded;
    union nf_inet_addr expected;

    fixture6();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.family == AF_INET6 && decoded.proto == IPPROTO_UDP);
    expected = (union nf_inet_addr){ .in6 = i6k.src };
    assert(nf_inet_addr_cmp(&decoded.src, &expected));
    expected = (union nf_inet_addr){ .in6 = i6k.dst };
    assert(nf_inet_addr_cmp(&decoded.dst, &expected) &&
           nf_inet_addr_cmp(&decoded.new_dst, &expected));
    /* On-link: the destination is its own next hop. Without NAT the
     * translated tuple must equal the match in every word. */
    assert(nf_inet_addr_cmp(&next_hop, &expected));
    assert(nf_inet_addr_cmp(&decoded.src, &decoded.new_src));
    assert(decoded.new_sport == pk.src && decoded.new_dport == pk.dst);
    assert(decoded.mtu == 1492 && decoded.in == &in && decoded.out == &out);

    /* An IPv6 destination is only valid for the FIB generation it was chosen
     * in. Admission is handed that cookie; a zero one rejects every route. */
    fixture6(); cls.nf_dst_cookie = 0;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    fixture6(); route6.dst.cookie = 0x5e2;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    fixture6(); cls.nf_dst_reverse_cookie = 0;
    assert(!ft_routes_valid(&cls));

    /* A link-local gateway is a usable next hop even though it could never be
     * a flow endpoint. */
    fixture6(); route6.rt6i_flags = RTF_GATEWAY;
    route6.rt6i_gateway = gateway.primary_key.in6;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(nf_inet_addr_cmp(&next_hop, &gateway.primary_key) && !gateway.refs);
    for (unsigned flag = 0; flag < 3; flag++) {
        fixture6();
        route6.rt6i_flags = (unsigned[]){RTF_REJECT, RTF_LOCAL, RTF_ANYCAST}[flag];
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    }
    fixture6(); route6.dst.error = -ENETUNREACH;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    fixture6(); route6.dst.ops = &ipv4_ops;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);

#define V6_REJECT(...) do { fixture6(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
    /* Endpoints must be routable between the two ports. */
    V6_REJECT(i6k.src = addr6(0xfe800000, 3));
    V6_REJECT(i6k.dst = addr6(0xff020000, 1));
    V6_REJECT(memset(&i6k.src, 0, sizeof(i6k.src)));
    V6_REJECT(i6k.dst = (struct in6_addr){ .s6_addr32 = { 0, 0, htonl(0xffff), htonl(1) } });
    /* Exact masks only, in every word. */
    for (unsigned word = 0; word < 4; word++) {
        V6_REJECT(i6m.src.s6_addr32[word] = 0);
        V6_REJECT(i6m.dst.s6_addr32[word] = 0);
    }
    /* IPv6 cannot be described by the IPv4 selectors, or the other way round. */
    V6_REJECT(dissector.used_keys = FT_KEYS4);
    V6_REJECT(dissector.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS));
    V6_REJECT(ck.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS);
    V6_REJECT(bk.n_proto = htons(ETH_P_IP));
    V6_REJECT(ct.tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num = AF_INET);
    /* IPv6 never fragments in transit, so the floor is its minimum link MTU. */
    V6_REJECT(cls.nf_mtu = in.ip6_mtu = IPV6_MIN_MTU - 1);
    fixture6(); cls.nf_mtu = in.ip6_mtu = IPV6_MIN_MTU;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.mtu == IPV6_MIN_MTU);
    /* Nor may the microcode fragment one, which it does to anything over the
     * entry's MTU: a path smaller than the ingress interface's IPv6 MTU stays
     * in software, where Linux answers with Packet Too Big. Equal is enough,
     * and the device MTU only matters as the IPv6 one's default. */
    V6_REJECT(cls.nf_mtu = 1491);
    V6_REJECT(in.ip6_mtu = 1500);
    V6_REJECT(in.ip6_mtu = 0);
    fixture6(); in.mtu = 9000;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    /* IPv4 is bounded for what the microcode would fragment -- a packet
     * without DF over the entry's MTU, whose fragments it builds without
     * their payload. TCP sets DF, which the microcode hands to Linux, so a
     * TCP direction is carried into the smaller path; any other one is not.
     * A direction to or from SEC is never bounded: its fragmenting happens
     * after SEC, on the offline port. And the IPv6 MTU plays no part. */
    fixture(); cls.nf_mtu = 1492;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    fixture(); cls.nf_mtu = in.ip6_mtu = 1492;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    /* A port lowered to the path still receives full Ethernet frames from a
     * host nobody told, so its MTU never counts for less than that. */
    fixture(); cls.nf_mtu = in.mtu = 1492;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    tcp_fixture(); cls.nf_mtu = 1492;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.mtu == 1492);
    fixture(); cls.nf_mtu = 1492; xfrm_policies = true; ipsec_sa = 7;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    fixture(); cls.nf_mtu = 1492; xfrm_policies = true; ipsec_in_sa = 8;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    /* Equal is enough, and a larger ingress counts at its own size. */
    fixture(); in.ip6_mtu = 1280;
    assert(in.mtu == cls.nf_mtu && ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    fixture(); in.mtu = 9000;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    fixture(); in.mtu = out.mtu = cls.nf_mtu = 9000;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.mtu == 9000);
    out.mtu = 1500;
    /* The neighbour must be discovered in the IPv6 table. */
    V6_REJECT(neighbour.tbl = &arp_tbl);
#undef V6_REJECT
    /* The IPv6 MTU is a sysctl no device event reports, so every stats pass
     * rechecks the bound and retires a direction it no longer holds for. */
    fixture6(); assert(ft_replace(&binding, &cls) == 0);
    struct cdx_ft_entry *bounded = ft_find(&binding, cls.cookie);
    u64 mtu_invalidations = ft_mtu_invalidations;
    assert(bounded && ft_stats(bounded, &cls) == 0 && !handle.invalid);
    in.ip6_mtu = 1500;
    assert(ft_stats(bounded, &cls) == -EOPNOTSUPP && handle.invalid &&
           ft_mtu_invalidations == mtu_invalidations + 1);
    assert(ft_remove(bounded) == 0); ft_invalid = 0;

    /* Translation: five actions per edit and no checksum action. */
    nat6_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    expected = (union nf_inet_addr){ .in6 = addr6(0xfc00beef, V6_NAT) };
    assert(nf_inet_addr_cmp(&decoded.new_src, &expected));
    assert(decoded.new_sport == htons(40000) && decoded.new_dport == pk.dst);
#define NAT6_REJECT(...) do { nat6_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
    /* An IPv4-shaped translation, one word plus a checksum action, is not it. */
    NAT6_REJECT(rule.action.entries[5] = rule.action.entries[8];
                rule.action.entries[6] = (struct flow_action_entry){
                    .id = FLOW_ACTION_CSUM, .csum_flags = 17 };
                rule.action.entries[7] = rule.action.entries[9];
                rule.action.num_entries = 8);
    NAT6_REJECT(rule.action.entries[4].mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4);
    NAT6_REJECT(rule.action.entries[6].mangle.offset += 4);
    NAT6_REJECT(rule.action.entries[7].mangle.val ^= 1);
    NAT6_REJECT(rule.action.entries[4].mangle.mask = 1);
    NAT6_REJECT(rule.action.num_entries = 9);
#undef NAT6_REJECT

    /* Installed IPv6 flows answer their own route notifications. */
    fixture6();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    struct netevent_ipv6_route event = { .net = &init_net, .prefixlen = 64,
                                        .dst = addr6(0xfc00beef, 0) };
    struct net foreign_net;
    u64 invalidations = ft_route_invalidations;
    event.net = &foreign_net;
    ft_neigh_event(NULL, NETEVENT_IPV6_ROUTE_UPDATE, &event);
    event.net = &init_net;
    event.dst = addr6(0xfc00cafe, 0);
    ft_neigh_event(NULL, NETEVENT_IPV6_ROUTE_UPDATE, &event);
    /* An IPv4 notification can never match an IPv6 flow, whatever it says. */
    struct netevent_ipv4_route legacy = { .net = &init_net, .dst = 0, .prefixlen = 0 };
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &legacy);
    assert(!handle.invalid && ft_route_invalidations == invalidations);
    /* The current egress destination, matched on its prefix rather than whole. */
    event.dst = addr6(0xfc00beef, 0);
    ft_neigh_event(NULL, NETEVENT_IPV6_ROUTE_UPDATE, &event);
    assert(handle.invalid && ft_route_invalidations == invalidations + 1 && !ft_invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs);

    /* The reverse direction's egress is this flow's source, so a route change
     * there retires it too even though only one direction is installed. */
    fixture6();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    event.dst = addr6(0xfc00dead, 0);
    ft_neigh_event(NULL, NETEVENT_IPV6_ROUTE_UPDATE, &event);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count);

    /* A prefix length no address can have means the event cannot be matched
     * selectively, so everything is retired. */
    fixture6();
    assert(ft_replace(&binding, &cls) == 0);
    event.prefixlen = 129;
    ft_neigh_event(NULL, NETEVENT_IPV6_ROUTE_UPDATE, &event);
    assert(ft_invalid); ft_invalid = 0;
    ft_remove(ft_find(&binding, cls.cookie));
    assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated);

    /* Neighbour discovery retires a flow exactly as ARP does. */
    fixture6();
    assert(ft_replace(&binding, &cls) == 0);
    neighbour.ha[5]++;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated);
    neighbour.tbl = &arp_tbl;
}

/* An IPv6 flow encrypted by an SA whose endpoints are IPv4. The route under
 * the bundle is the flow's own on-link route, which has no neighbour for an
 * IPv4 endpoint, so the next hop is the one the kernel resolves for the SA in
 * the SA's family, and the entry checks and watches it in that family. */
static struct xfrm_state cross_sa;
static struct dst_entry cross_bundle;
static void cross_fixture(u16 sa_family)
{
    fixture6();
    cross_sa = (struct xfrm_state){ .props.family = sa_family };
    if (sa_family == AF_INET)
        cross_sa.id.daddr.a4 = htonl(0x0a0000e8);
    else
        memcpy(cross_sa.id.daddr.a6, &i6k.dst, sizeof(cross_sa.id.daddr.a6));
    cross_bundle = (struct dst_entry){ .ops = &ipv6_ops6, .dev = &out, .xfrm = &cross_sa,
                                       .xfrm_child = &route6.dst, .valid = true,
                                       .cookie = cls.nf_dst_cookie };
    cls.nf_dst = &cross_bundle;
    /* The endpoint's ARP neighbour on the SA's port, carrying the address
     * the Ethernet rewrite names. */
    gateway.tbl = &arp_tbl;
    gateway.primary_key = (union nf_inet_addr){ .ip = htonl(0x0a0000e8) };
    peer_neigh = &gateway;
    peer_neigh_lookups = 0;
}

static void test_cross_family_sa(void)
{
    union nf_inet_addr peer = { .ip = htonl(0x0a0000e8) };
    union nf_inet_addr own = { .in6 = i6k.dst };
    struct cdx_ft_rule decoded;

    cross_fixture(AF_INET);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.family == AF_INET6 && decoded.next_hop_family == AF_INET);
    assert(nf_inet_addr_cmp(&next_hop, &peer) && peer_neigh_lookups == 1 && !gateway.refs);
    assert(ft_replace(&binding, &cls) == 0);
    struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
    assert(e && e->neigh == &gateway && gateway.refs == 1 && !neighbour.refs);
    /* The IPv4 neighbour is the dependency: its move retires the flow. */
    gateway.ha[5]++;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !gateway.refs && !ft_neighbour_refs && !allocated);

    /* No route to the endpoint on the SA's port: nothing to address the
     * frames to, so the direction stays in software. */
    cross_fixture(AF_INET);
    peer_neigh = NULL;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    assert(!gateway.refs && !neighbour.refs);

    /* An SA of the flow's own family keeps asking the route under the
     * bundle, and never the endpoint lookup. */
    cross_fixture(AF_INET6);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.next_hop_family == AF_INET6 && !peer_neigh_lookups);
    assert(nf_inet_addr_cmp(&next_hop, &own) && !neighbour.refs);

    peer_neigh = NULL;
    neighbour.tbl = &arp_tbl;
}

/* out_tag is eth3.100 over the egress port, in_tag eth4.200 over the ingress
 * one, and out_qinq is 300 inside 100 -- what Linux spells eth3.100.300, and
 * what the wire carries as an outer 100 and an inner 300. A device that is
 * neither a VLAN, a bridge nor a physical port stands in for every other
 * upper device: a bond, a MACVLAN, a PPPoE session. */
static struct net_device out_tag = { .ifindex = 7, .mtu = 1500, .type = ARPHRD_ETHER,
                                     .dev_addr = {2, 0, 0, 0, 0, 2},
                                     .real_dev = &out, .vlan_id = 100 };
static struct net_device in_tag = { .ifindex = 8, .mtu = 1500, .type = ARPHRD_ETHER,
                                    .dev_addr = {2, 0, 0, 0, 0, 1},
                                    .real_dev = &in, .vlan_id = 200 };
static struct net_device out_qinq = { .ifindex = 9, .mtu = 1500, .type = ARPHRD_ETHER,
                                      .dev_addr = {2, 0, 0, 0, 0, 2},
                                      .real_dev = &out_tag, .vlan_id = 300 };
static struct net_device upper = { .ifindex = 10, .mtu = 1500, .type = ARPHRD_ETHER,
                                   .dev_addr = {2, 0, 0, 0, 0, 2} };
/* One tunnel device of each kind per direction: a sit device inserting an
 * IPv4 header around an IPv6 flow, and an ip6tnl device in ipip6 mode
 * inserting an IPv6 header around an IPv4 one. Their MTUs are the ones `ip
 * link add` derives, the port's less the outer header, and their addresses
 * are their local endpoints -- four bytes for sit, sixteen for ip6tnl, of
 * which only the first six ever reach an Ethernet header.
 *
 * The private areas are separate objects per device on purpose: the hop is
 * cross-checked against the device it names, so two devices sharing one
 * configuration would let a hop naming the wrong one through. */
static struct ip_tunnel sit_priv, in_sit_priv;
static struct ip6_tnl ip6tnl_priv, in_ip6tnl_priv;
static struct net_device sit = { .ifindex = 18, .mtu = 1480, .type = ARPHRD_SIT,
                                 .addr_len = 4, .priv = &sit_priv };
static struct net_device in_sit = { .ifindex = 19, .mtu = 1480, .type = ARPHRD_SIT,
                                    .addr_len = 4, .priv = &in_sit_priv };
static struct net_device ip6tnl = { .ifindex = 20, .mtu = 1452, .type = ARPHRD_TUNNEL6,
                                    .addr_len = 16, .priv = &ip6tnl_priv };
static struct net_device in_ip6tnl = { .ifindex = 21, .mtu = 1452, .type = ARPHRD_TUNNEL6,
                                       .addr_len = 16, .priv = &in_ip6tnl_priv };
/* Every device the fixtures build with, so a session or tunnel hop can name
 * any of them -- and an index naming none of them resolves to nothing, which
 * is the case a hop pointing at a device that has since gone away produces. */
static struct net_device *all_devices[] = { &in, &out, &out_tag, &in_tag, &out_qinq,
                                            &upper, &decoy, &br, &br_tag, &in_br,
                                            &br_qinq, &ppp, &in_ppp,
                                            &sit, &in_sit, &ip6tnl, &in_ip6tnl };
static struct net_device *__dev_get_by_index(struct net *net, int ifindex)
{
    assert(net == &init_net);
    for (unsigned i = 0; i < ARRAY_SIZE(all_devices); i++)
        if (all_devices[i]->ifindex == ifindex)
            return all_devices[i];
    return NULL;
}
static struct vlan vk[2], vm[2];
static void snat_fixture(bool forward, bool tcp);

/* Every mutable field is restored, because the rejection cases below work by
 * breaking one of them and the next case must not inherit the damage. */
static void vlan_fixture(void)
{
    fixture();
    /* htons() is not a constant expression, so the protocols are set here
     * rather than in the initialisers above. */
    out_tag.vlan_proto = in_tag.vlan_proto = out_qinq.vlan_proto = htons(ETH_P_8021Q);
    out_tag.mtu = in_tag.mtu = out_qinq.mtu = 1500;
    out_tag.real_dev = &out;
    in_tag.real_dev = &in;
    out_qinq.real_dev = &out_tag;
    out_tag.vlan_id = 100;
    in_tag.vlan_id = 200;
    out_qinq.vlan_id = 300;
    /* Inherited from the parent, as the kernel does by default. */
    ether_addr_copy(out_tag.dev_addr, out.dev_addr);
    ether_addr_copy(out_qinq.dev_addr, out.dev_addr);
    ether_addr_copy(in_tag.dev_addr, in.dev_addr);
    assert(!out_tag.refs && !in_tag.refs && !out_qinq.refs);
}

/* A bridge over each physical port, VLAN filtering off: the plain br-lan an
 * untagged LAN is built as. The ports are enslaved, the bridge takes its
 * lowest port's address as Linux does by default, and br_tag sits on top for
 * the vlan-aware cases. Every mutable field is restored, because the
 * rejection cases work by breaking one of them. */
static void bridge_fixture(void)
{
    vlan_fixture();
    br.real_dev = in_br.real_dev = &decoy;
    br.bridge = in_br.bridge = true;
    br.vlan_filtering = in_br.vlan_filtering = false;
    br.br_proto = in_br.br_proto = ETH_P_8021Q;
    br.pvid = in_br.pvid = 0;
    br.br_nvlans = in_br.br_nvlans = 0;
    br.mtu = in_br.mtu = 1500;
    br_tag.real_dev = &br;
    br_tag.vlan_id = 100;
    br_tag.vlan_proto = htons(ETH_P_8021Q);
    br_tag.mtu = 1500;
    br_qinq.real_dev = &br_tag;
    br_qinq.vlan_id = 300;
    br_qinq.vlan_proto = htons(ETH_P_8021Q);
    br_qinq.mtu = 1500;
    out.master = &br;
    in.master = &in_br;
    decoy.master = &br;
    out.stp_blocked = in.stp_blocked = false;
    out.vid_blocked = in.vid_blocked = 0;
    ether_addr_copy(br.dev_addr, out.dev_addr);
    ether_addr_copy(br_tag.dev_addr, out.dev_addr);
    ether_addr_copy(br_qinq.dev_addr, out.dev_addr);
    ether_addr_copy(in_br.dev_addr, in.dev_addr);
    assert(!br.refs && !br_tag.refs && !br_qinq.refs && !in_br.refs && !decoy.refs);
}

/* Make the bridge VLAN-aware and give the egress port one membership. */
static void bridge_vlan(u16 pvid, u16 vid, u16 flags)
{
    br.vlan_filtering = true;
    br.pvid = pvid;
    out.br_nvlans = 1;
    out.br_vlans[0] = (struct br_vlan_entry){ .vid = vid, .flags = flags };
}

/* Egress through a plain bridge: the route names br-lan, the redirect still
 * names the port under it, and no tag lies between. */
static void bridge_out_fixture(void)
{
    bridge_fixture();
    route.dst.dev = &br;
    neighbour.dev = &br;
}

/* Splice an encapsulation block in after the four Ethernet mangles, sliding
 * whatever the fixture already laid out from index four onward up behind it.
 * Pushes are given outermost first, the order Netfilter emits them in. */
static void encap_actions(unsigned pops, const u16 *pushes, unsigned num_pushes)
{
    unsigned encaps = pops + num_pushes, i;

    assert(rule.action.num_entries + encaps <= ARRAY_SIZE(rule.action.entries));
    for (i = rule.action.num_entries; i-- > 4; )
        rule.action.entries[i + encaps] = rule.action.entries[i];
    rule.action.num_entries += encaps;
    for (i = 0; i < pops; i++)
        rule.action.entries[4 + i] = (struct flow_action_entry){ .id = FLOW_ACTION_VLAN_POP };
    for (i = 0; i < num_pushes; i++)
        rule.action.entries[4 + pops + i] = (struct flow_action_entry){
            .id = FLOW_ACTION_VLAN_PUSH,
            .vlan = { .vid = pushes[i], .proto = htons(ETH_P_8021Q) } };
}

/* The outermost visible ingress tag is recorded in KEY_VLAN and the next one
 * in KEY_CVLAN, each with an exact VID and TPID and no priority or DEI.
 * used_keys is deliberately left alone: nf_flow_rule_match() registers these
 * two offsets and fills their values but never advertises either key, so a
 * tagged rule describes exactly the same key set as an untagged one. A
 * fixture that advertised them would be testing a kernel that does not
 * exist. */
static void encap_keys(const u16 *ingress, unsigned count)
{
    unsigned i;

    for (i = 0; i < count; i++) {
        vk[i] = (struct vlan){ .vlan_id = ingress[i], .vlan_tpid = htons(ETH_P_8021Q) };
        vm[i] = (struct vlan){ .vlan_id = VLAN_VID_MASK, .vlan_tpid = htons(0xffff) };
    }
    rule.vlan = (struct flow_match_vlan){ &vk[0], &vm[0] };
    rule.cvlan = (struct flow_match_vlan){ &vk[1], &vm[1] };
}

/* Rewrite the Ethernet source mangle words to name a different port, the way
 * flow_offload_eth_src() does. A hairpin needs it because the frame leaves by
 * the port it arrived on, whose address is not the fixture's egress one. */
static void source_mac(const struct net_device *dev)
{
    u16 leading;

    memcpy(&leading, dev->dev_addr, 2);
    rule.action.entries[0].mangle.val = (u32)leading << 16;
    memcpy(&rule.action.entries[1].mangle.val, dev->dev_addr + 2, 4);
}

/* Egress tagged with 100: the redirect still names the physical port, the
 * route still names the VLAN device, and the tag is what lies between. */
static void egress_tag_fixture(void)
{
    const u16 push[] = { 100 };

    vlan_fixture();
    route.dst.dev = &out_tag;
    /* A neighbour is discovered on the device the route names. The one the
     * plain fixture puts on the physical port is a different neighbour. */
    neighbour.dev = &out_tag;
    encap_actions(0, push, ARRAY_SIZE(push));
}

/* Ingress tagged with 200, egress untagged: the asymmetric shape of a tagged
 * LAN behind an untagged WAN, and the one a real bench is wired as. */
static void ingress_tag_fixture(void)
{
    const u16 ingress[] = { 200 };

    vlan_fixture();
    reverse_route.dst.dev = &in_tag;
    encap_actions(1, NULL, 0);
    encap_keys(ingress, ARRAY_SIZE(ingress));
}

static void test_vlan(void)
{
    struct cdx_ft_rule decoded;
    const u16 push_one[] = { 100 }, push_qinq[] = { 100, 300 }, ingress_one[] = { 200 };

    /* An untagged flow names the physical ports as its own logical devices,
     * which is what keeps every reference balanced without a special case. */
    vlan_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(!decoded.in_vlans && !decoded.out_vlans);
    assert(decoded.in_logical == &in && decoded.out_logical == &out);

    /* One egress tag. The hardware ports are unchanged; only the stack and
     * the logical device move. */
    egress_tag_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_vlans == 1 && decoded.out_vlan[0].id == 100 &&
           decoded.out_vlan[0].proto == htons(ETH_P_8021Q));
    assert(!decoded.in_vlans && decoded.out == &out && decoded.in == &in);
    assert(decoded.out_logical == &out_tag && decoded.in_logical == &in);
    /* The Ethernet source stays the physical port's: that is the address
     * Netfilter writes for a neighbour-output flow. */
    assert(!memcmp(decoded.src_mac, out.dev_addr, ETH_ALEN));

    /* One ingress tag and no egress tag. */
    ingress_tag_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in_vlans == 1 && decoded.in_vlan[0].id == 200 && !decoded.out_vlans);
    assert(decoded.in_logical == &in_tag && decoded.out_logical == &out);

    /* QinQ: the rule orders its tags outermost first, so the outer 100 the
     * lower VLAN device carries comes before the inner 300 of the upper one.
     * The trap this pins down is that vlan_dev_real_dev() reports the bottom
     * device rather than the immediate parent, so a decoder built on it sees
     * one tag where the wire carries two. */
    vlan_fixture();
    assert(vlan_dev_real_dev(&out_qinq) == &out && out_qinq.real_dev == &out_tag);
    route.dst.dev = &out_qinq;
    neighbour.dev = &out_qinq;
    encap_actions(0, push_qinq, ARRAY_SIZE(push_qinq));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_vlans == 2 &&
           decoded.out_vlan[0].id == 100 && decoded.out_vlan[1].id == 300);

#define VLAN_REJECT(...) do { egress_tag_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
    /* The PUSH actions must agree with the devices, in identity and in order. */
    VLAN_REJECT(rule.action.entries[4].vlan.vid = 101);
    VLAN_REJECT(rule.action.entries[4].vlan.proto = htons(ETH_P_8021AD));
    VLAN_REJECT(rule.action.entries[4].vlan.prio = 1);
    VLAN_REJECT(rule.action.entries[4].id = FLOW_ACTION_VLAN_POP);
    VLAN_REJECT(rule.action.entries[4].id = FLOW_ACTION_PPPOE_PUSH);
    /* A tag the device walk derived but the action list omits, and the other
     * way round, are both action-count mismatches. */
    VLAN_REJECT(rule.action.entries[4] = rule.action.entries[5];
                rule.action.num_entries = 5);
    VLAN_REJECT(route.dst.dev = &out);
    /* Only 802.1Q, and only as deep as a tuple can describe. */
    VLAN_REJECT(out_tag.vlan_proto = htons(ETH_P_8021AD));
    /* Made to agree with itself, so only the device walk can decline it: an
     * 802.1ad stack is outside the contract on its own terms, not merely
     * because some action disagreed with it. */
    VLAN_REJECT(out_tag.vlan_proto = htons(ETH_P_8021AD);
                rule.action.entries[4].vlan.proto = htons(ETH_P_8021AD));
    VLAN_REJECT(route.dst.dev = &upper);
    VLAN_REJECT(out_tag.real_dev = &upper);
    /* The payload bound belongs to the logical device, not the port. */
    VLAN_REJECT(out_tag.mtu = 1491);
    /* A VLAN device normally inherits its parent's address. One that does not
     * would have software and hardware disagree about the Ethernet source. */
    VLAN_REJECT(out_tag.dev_addr[5]++);
    /* A neighbour on the physical port is not this flow's neighbour. */
    VLAN_REJECT(neighbour.dev = &out);
#undef VLAN_REJECT

    /* A QinQ stack one tag deeper than a tuple can carry is declined rather
     * than silently truncated to its outer two tags. */
    vlan_fixture();
    struct net_device deeper = out_qinq;
    deeper.real_dev = &out_qinq;
    deeper.vlan_id = 400;
    route.dst.dev = &deeper;
    encap_actions(0, push_qinq, ARRAY_SIZE(push_qinq));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);

#define KEY_REJECT(...) do { ingress_tag_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
    /* The ingress selectors must name the tags the devices derived, under
     * Netfilter's own exact masks and imposing nothing else. */
    KEY_REJECT(vk[0].vlan_id = 201);
    KEY_REJECT(vk[0].vlan_tpid = htons(ETH_P_8021AD));
    KEY_REJECT(in_tag.vlan_proto = htons(ETH_P_8021AD);
               vk[0].vlan_tpid = htons(ETH_P_8021AD));
    KEY_REJECT(vk[0].vlan_priority = 1);
    KEY_REJECT(vk[0].vlan_dei = 1);
    KEY_REJECT(vm[0].vlan_id = 0);
    KEY_REJECT(vm[0].vlan_tpid = 0);
    KEY_REJECT(vm[0].vlan_priority = 7);
    KEY_REJECT(vm[0].vlan_eth_type = htons(0xffff));
    /* A tagged rule describes the same key set as an untagged one, so a rule
     * that advertises a VLAN selector is not one this kernel produced. */
    KEY_REJECT(dissector.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_VLAN));
    KEY_REJECT(dissector.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN));
    KEY_REJECT(rule.action.entries[4].id = FLOW_ACTION_VLAN_PUSH);
#undef KEY_REJECT

    /* Re-entering the port a frame arrived on is only a distinct path when
     * the two stacks differ; without that it still needs full NAT. */
    vlan_fixture();
    route.dst.dev = &in_tag;
    reverse_route.dst.dev = &in;
    neighbour.dev = &in_tag;
    source_mac(&in);
    encap_actions(0, (const u16[]){ 200 }, 1);
    rule.action.entries[rule.action.num_entries - 1].dev = &in;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in == decoded.out && decoded.out_vlans == 1 && !decoded.in_vlans);
    /* The same port with the same stack on both sides is the shape that still
     * needs full NAT to be a distinct path. */
    vlan_fixture();
    route.dst.dev = &in;
    reverse_route.dst.dev = &in;
    neighbour.dev = &in;
    source_mac(&in);
    rule.action.entries[4].dev = &in;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);

    /* Translation indices move with the encapsulation block: the NAT edits
     * and the checksum sit behind the pops and pushes, not at a fixed four. */
    snat_fixture(true, false);
    out_tag.vlan_proto = in_tag.vlan_proto = htons(ETH_P_8021Q);
    route.dst.dev = &out_tag;
    reverse_route.dst.dev = &in_tag;
    neighbour.dev = &out_tag;
    encap_actions(1, push_one, ARRAY_SIZE(push_one));
    encap_keys(ingress_one, ARRAY_SIZE(ingress_one));
    assert(rule.action.num_entries == 10);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in_vlans == 1 && decoded.out_vlans == 1);
    assert(decoded.new_src.ip == htonl(0xcb007104) && decoded.new_sport == htons(40000));
    /* The same list with the block removed no longer describes those indices. */
    rule.action.entries[4] = rule.action.entries[6];
    rule.action.entries[5] = rule.action.entries[7];
    rule.action.entries[6] = rule.action.entries[8];
    rule.action.entries[7] = rule.action.entries[9];
    rule.action.num_entries = 8;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);

    /* Two tags on ingress, which is the only shape that reads the second
     * selector: the first arrives in KEY_VLAN and the second in KEY_CVLAN. */
    vlan_fixture();
    reverse_route.dst.dev = &out_qinq;
    out_qinq.real_dev = &out_tag;
    out_tag.real_dev = &out;
    binding.dev = &out;
    mk.ingress_ifindex = out.ifindex;
    /* The frame leaves by `in` here, so that is whose address the Ethernet
     * source names. */
    source_mac(&in);
    rule.action.entries[4].dev = &in;
    route.dst.dev = &in;
    neighbour.dev = &in;
    encap_actions(2, NULL, 0);
    encap_keys(push_qinq, ARRAY_SIZE(push_qinq));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in_vlans == 2 && !decoded.out_vlans);
    assert(decoded.in_vlan[0].id == 100 && decoded.in_vlan[1].id == 300);
    /* The inner tag is described by the second selector, so a wrong one there
     * must be refused exactly as a wrong outer one is. */
    vk[1].vlan_id = 301;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    binding.dev = &in;
    mk.ingress_ifindex = in.ifindex;

    /* Tagged on both sides: three distinct devices are pinned, which no
     * single-sided case reaches. */
    vlan_fixture();
    route.dst.dev = &out_tag;
    reverse_route.dst.dev = &in_tag;
    neighbour.dev = &out_tag;
    encap_actions(1, push_one, ARRAY_SIZE(push_one));
    encap_keys(ingress_one, ARRAY_SIZE(ingress_one));
    /* Under the transaction, as production installs are: a tagged flow now
     * claims a VLAN device record, and that claim asserts it. */
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    assert(out.refs == 1 && out_tag.refs == 1 && in_tag.refs == 1 && !in.refs);
    ft_device_retire(&in_tag, &ft_mtu_invalidations);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !out.refs && !out_tag.refs && !in_tag.refs && !allocated);

    /* Every device the rule names is pinned for the life of the entry, and a
     * VLAN device carries its own MTU and administrative state. */
    egress_tag_fixture();
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    assert(out.refs == 1 && out_tag.refs == 1 && !in.refs);
    ft_device_retire(&out_tag, &ft_mtu_invalidations);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !out.refs && !out_tag.refs && !ft_handle_refs && !ft_neighbour_refs);

    ingress_tag_fixture();
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    assert(in_tag.refs == 1 && out.refs == 1);
    ft_device_retire(&in_tag, &ft_link_invalidations);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !in_tag.refs && !out.refs && !allocated);
}

static void test_bridge(void)
{
    struct cdx_ft_rule decoded;
    const u16 push_one[] = { 100 }, ingress_one[] = { 100 };

    /* A plain br-lan, VLAN filtering off: the route names the bridge, the
     * redirect names the port, and the wire carries no tag. This is the
     * untagged LAN OpenWrt ships by default. */
    bridge_out_fixture();
    /* The trap this pins down: the bridge's first lower device is not the
     * port the flow leaves by, so a walk that descended it by adjacency the
     * way it descends a VLAN would derive the wrong port for every case
     * below. Only the redirect and the enslavement name the right one. */
    assert(br.real_dev == &decoy && &decoy != &out && out.master == &br);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(!decoded.out_vlans && !decoded.in_vlans);
    assert(decoded.out == &out && decoded.in == &in);
    assert(decoded.out_logical == &br && decoded.out_bridge == &br &&
           decoded.out_bridge_vid == 0);
    assert(!decoded.in_bridge && decoded.in_logical == &in);
    /* The Ethernet source is still the port's, because that is the address
     * flow_offload_eth_src() writes for a neighbour-output flow. */
    assert(!memcmp(decoded.src_mac, out.dev_addr, ETH_ALEN));
    /* The bridge forwards nothing through a port STP has taken out of
     * FORWARDING, and admission runs asynchronously to the event that
     * retires such a port's flows, so it asks the bridge. MST stays in
     * software: a VID-to-MSTI remap moves per-VLAN states under one
     * bridge-wide event. */
    out.stp_blocked = true;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    out.stp_blocked = false;
    br.mst = true;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    br.mst = false;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);

    /* br-lan.100 over a bridge whose egress port is tagged for 100: the tag
     * comes from the VLAN device and the bridge keeps it. */
    bridge_fixture();
    bridge_vlan(1, 100, 0);
    route.dst.dev = &br_tag;
    neighbour.dev = &br_tag;
    encap_actions(0, push_one, ARRAY_SIZE(push_one));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_vlans == 1 && decoded.out_vlan[0].id == 100 &&
           decoded.out_vlan[0].proto == htons(ETH_P_8021Q));
    assert(decoded.out_bridge == &br && decoded.out_bridge_vid == 100);
    assert(decoded.out_logical == &br_tag && decoded.out == &out);
    /* The question is asked per VLAN, of the VLAN the bridge resolved: a
     * blocked VLAN refuses the flow while its port forwards, and another
     * VLAN blocked on the same port does not. */
    out.vid_blocked = 100;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    out.vid_blocked = 200;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    out.vid_blocked = 0;

    /* The same devices with the port untagged for 100 -- the access port a
     * vlan-aware br-lan actually ships with. The bridge strips the tag, so
     * the wire carries none and the rule pushes none, even though a device
     * walk that stopped at the netdevs would have derived one. */
    bridge_fixture();
    bridge_vlan(100, 100, BRIDGE_VLAN_INFO_UNTAGGED | BRIDGE_VLAN_INFO_PVID);
    route.dst.dev = &br_tag;
    neighbour.dev = &br_tag;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(!decoded.out_vlans && decoded.out_bridge == &br &&
           decoded.out_bridge_vid == 100);

    /* Routing through br-lan itself on a vlan-aware bridge: the frame enters
     * on the PVID and the port is tagged for it, so the bridge inserts a tag
     * that no netdev anywhere describes. */
    bridge_out_fixture();
    bridge_vlan(100, 100, BRIDGE_VLAN_INFO_PVID);
    encap_actions(0, push_one, ARRAY_SIZE(push_one));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_vlans == 1 && decoded.out_vlan[0].id == 100 &&
           decoded.out_vlan[0].proto == htons(ETH_P_8021Q));
    assert(decoded.out_bridge_vid == 100 && decoded.out_logical == &br);

    /* Untagged for the PVID is the ordinary access port, and adds nothing. */
    bridge_out_fixture();
    bridge_vlan(100, 100, BRIDGE_VLAN_INFO_UNTAGGED | BRIDGE_VLAN_INFO_PVID);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(!decoded.out_vlans && decoded.out_bridge_vid == 100);

    /* A bridge on the ingress side, which is the shipping shape: the LAN is
     * bridged and the WAN is not. */
    bridge_fixture();
    reverse_route.dst.dev = &in_br;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(!decoded.in_vlans && decoded.in_bridge == &in_br &&
           decoded.in_logical == &in_br && !decoded.out_bridge);

    /* Ingress through br-lan.100 on an access port: the frame arrives
     * untagged, so there is no POP and no ingress selector to check. */
    bridge_fixture();
    in_br.vlan_filtering = true;
    in_br.pvid = 100;
    in.br_nvlans = 1;
    in.br_vlans[0] = (struct br_vlan_entry){ .vid = 100,
        .flags = BRIDGE_VLAN_INFO_UNTAGGED | BRIDGE_VLAN_INFO_PVID };
    br_tag.real_dev = &in_br;
    reverse_route.dst.dev = &br_tag;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(!decoded.in_vlans && decoded.in_bridge == &in_br &&
           decoded.in_bridge_vid == 100);
    /* Tagged on that port instead, and the tag reappears on both the POP and
     * the ingress selector. This is also the only shape where the bridge is
     * neither logical device, so it is the one that proves a bridge is pinned
     * and watched in its own right rather than as somebody's route target. */
    bridge_fixture();
    in_br.vlan_filtering = true;
    in_br.pvid = 1;
    in.br_nvlans = 1;
    in.br_vlans[0] = (struct br_vlan_entry){ .vid = 100, .flags = 0 };
    br_tag.real_dev = &in_br;
    reverse_route.dst.dev = &br_tag;
    encap_actions(1, NULL, 0);
    encap_keys(ingress_one, ARRAY_SIZE(ingress_one));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in_vlans == 1 && decoded.in_vlan[0].id == 100 &&
           decoded.in_bridge == &in_br && decoded.in_bridge_vid == 100);
    assert(decoded.in_logical == &br_tag && !decoded.out_bridge);
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    assert(out.refs == 1 && br_tag.refs == 1 && in_br.refs == 1 && !in.refs);
    ft_device_retire(&in_br, &ft_link_invalidations);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !out.refs && !br_tag.refs && !in_br.refs && !allocated);

    /* A second tag inside the bridge's own: the bridge resolves on the
     * outermost tag, which is 100 and not the 300 above it. The egress port
     * is untagged for 100 and a member of 300, so the bridge strips its own
     * tag and the inner one survives. Resolving on the wrong end of the stack
     * would key the FDB on 300 and leave both tags on the wire. */
    bridge_fixture();
    br.vlan_filtering = true;
    br.pvid = 1;
    out.br_nvlans = 2;
    out.br_vlans[0] = (struct br_vlan_entry){ .vid = 100,
        .flags = BRIDGE_VLAN_INFO_UNTAGGED };
    out.br_vlans[1] = (struct br_vlan_entry){ .vid = 300, .flags = 0 };
    route.dst.dev = &br_qinq;
    neighbour.dev = &br_qinq;
    encap_actions(0, (const u16[]){ 300 }, 1);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_vlans == 1 && decoded.out_vlan[0].id == 300);
    assert(decoded.out_bridge == &br && decoded.out_bridge_vid == 100);

#define BRIDGE_REJECT(...) do { bridge_out_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
    /* The port a bridged flow leaves by is the one the FDB chose, and the
     * redirect names it. A bridge the port is not enslaved to describes a
     * different path entirely. */
    BRIDGE_REJECT(out.master = NULL);
    BRIDGE_REJECT(out.master = &in_br);
    /* A bridge port that is itself a stacked device hides whatever tag lies
     * between it and the physical port, so the walk declines rather than
     * deriving a stack it cannot see. */
    BRIDGE_REJECT(out.master = NULL; out_tag.master = &br);
    /* A vlan-aware bridge whose egress port is not a member of the resolved
     * VLAN would have failed the path walk outright, so Netfilter would never
     * have described this flow. The action list is made to agree with the tag
     * the PVID implies, so only the membership lookup can decline it. */
    BRIDGE_REJECT(bridge_vlan(100, 200, 0);
                  encap_actions(0, push_one, ARRAY_SIZE(push_one)));
    /* No PVID configured is the same refusal: VID zero is nobody's member. */
    BRIDGE_REJECT(bridge_vlan(0, 100, 0);
                  encap_actions(0, (const u16[]){ 0 }, 1));
    /* A bridge filtering in 802.1ad is declined for the reason a VLAN device
     * in 802.1ad is: the kernel describes no selector for such a tag and
     * emits no push action for one. Made to agree with itself, so only the
     * protocol check can refuse it. */
    BRIDGE_REJECT(bridge_vlan(100, 100, BRIDGE_VLAN_INFO_PVID);
                  br.br_proto = ETH_P_8021AD;
                  encap_actions(0, push_one, ARRAY_SIZE(push_one));
                  rule.action.entries[4].vlan.proto = htons(ETH_P_8021AD));
    /* The bridge carries its own MTU and its own address, exactly as a VLAN
     * device does, and both belong to the flow that routes through it. */
    BRIDGE_REJECT(br.mtu = 1491);
    BRIDGE_REJECT(br.dev_addr[5]++);
    /* A neighbour on the port underneath is not this flow's neighbour. */
    BRIDGE_REJECT(neighbour.dev = &out);
    /* An inserted tag the action list does not push, and a pushed tag the
     * bridge does not insert, are both refused. */
    BRIDGE_REJECT(bridge_vlan(100, 100, BRIDGE_VLAN_INFO_PVID));
    BRIDGE_REJECT(encap_actions(0, push_one, ARRAY_SIZE(push_one)));
#undef BRIDGE_REJECT

    /* Two bridges, one per direction, is three distinct devices pinned plus
     * the egress port -- and each is a dependency the flow retires on. */
    bridge_fixture();
    route.dst.dev = &br;
    neighbour.dev = &br;
    reverse_route.dst.dev = &in_br;
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    assert(out.refs == 1 && br.refs == 1 && in_br.refs == 1 && !in.refs && !br_tag.refs);
    ft_device_retire(&br, &ft_mtu_invalidations);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !out.refs && !br.refs && !in_br.refs && !allocated);

    /* The ingress bridge is watched too, and so is a VLAN device above one:
     * br-lan.100 and br-lan are separate objects and both are pinned. */
    bridge_fixture();
    bridge_vlan(1, 100, 0);
    route.dst.dev = &br_tag;
    neighbour.dev = &br_tag;
    reverse_route.dst.dev = &in_br;
    encap_actions(0, push_one, ARRAY_SIZE(push_one));
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    assert(out.refs == 1 && br.refs == 1 && br_tag.refs == 1 && in_br.refs == 1);
    ft_device_retire(&in_br, &ft_link_invalidations);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !out.refs && !br.refs && !br_tag.refs && !in_br.refs && !allocated);

    /* One bridge carrying both directions is counted once, which is what an
     * inter-VLAN route across a single vlan-aware bridge looks like. */
    bridge_fixture();
    bridge_vlan(1, 100, 0);
    in.master = &br;
    in.br_nvlans = 1;
    in.br_vlans[0] = (struct br_vlan_entry){ .vid = 1,
        .flags = BRIDGE_VLAN_INFO_UNTAGGED | BRIDGE_VLAN_INFO_PVID };
    route.dst.dev = &br_tag;
    neighbour.dev = &br_tag;
    reverse_route.dst.dev = &br;
    encap_actions(0, push_one, ARRAY_SIZE(push_one));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_bridge == &br && decoded.in_bridge == &br);
    assert(decoded.out_bridge_vid == 100 && decoded.in_bridge_vid == 1);
    assert(!decoded.in_vlans && decoded.out_vlans == 1);
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    /* The bridge is both this direction's ingress logical device and the
     * egress path's bridge, so it is pinned once for each -- what matters is
     * that the puts mirror the holds, which the teardown below proves. */
    assert(br.refs == 2 && br_tag.refs == 1 && out.refs == 1);
    ft_device_retire(&br, &ft_link_invalidations);
    assert(handle.invalid);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !br.refs && !br_tag.refs && !out.refs && !allocated);
}

/* The FDB pins a bridged flow's egress port, and nothing else here watches
 * it. Each case installs one entry, delivers one event and requires the
 * handle to move or stay exactly as the pinning did. */
static void test_bridge_fdb(void)
{
    const u8 *dst = neighbour.ha;
    struct switchdev_notifier_fdb_info info;
    u64 before;

    /* Install a bridged egress direction whose destination MAC is the one the
     * bridge would have looked up. */
#define FDB_FIXTURE() do { bridge_out_fixture(); bridge_vlan(100, 100, \
        BRIDGE_VLAN_INFO_UNTAGGED | BRIDGE_VLAN_INFO_PVID); \
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1); \
    info = (struct switchdev_notifier_fdb_info){ .info.dev = &out, .addr = dst, .vid = 100 }; \
    before = ft_fdb_invalidations; } while (0)
#define FDB_DRAIN() do { ft_handle_invalidate(&handle, &ft_mac_invalidations); \
    ft_retire_workfn(NULL); assert(!ft_count && !allocated); } while (0)

    /* A delete against the port the flow leaves by withdraws the pinning. */
    FDB_FIXTURE();
    assert(ft_fdb_event(NULL, SWITCHDEV_FDB_DEL_TO_DEVICE, &info) == NOTIFY_DONE);
    assert(handle.invalid && ft_fdb_invalidations == before + 1);
    FDB_DRAIN();

    /* An add naming the same port re-states it and changes nothing. */
    FDB_FIXTURE();
    assert(ft_fdb_event(NULL, SWITCHDEV_FDB_ADD_TO_DEVICE, &info) == NOTIFY_DONE);
    assert(!handle.invalid && ft_fdb_invalidations == before);
    /* An add naming another port is a station that roamed, and the hardware
     * entry would otherwise keep forwarding to the old one. */
    info.info.dev = &decoy;
    assert(ft_fdb_event(NULL, SWITCHDEV_FDB_ADD_TO_DEVICE, &info) == NOTIFY_DONE);
    assert(handle.invalid && ft_fdb_invalidations == before + 1);
    FDB_DRAIN();

    /* Another station's address, and another VLAN, are other flows' pinnings. */
    FDB_FIXTURE();
    info.info.dev = &decoy;
    info.vid = 101;
    assert(ft_fdb_event(NULL, SWITCHDEV_FDB_DEL_TO_DEVICE, &info) == NOTIFY_DONE);
    assert(!handle.invalid);
    info.vid = 100;
    info.addr = in.dev_addr;
    assert(ft_fdb_event(NULL, SWITCHDEV_FDB_DEL_TO_DEVICE, &info) == NOTIFY_DONE);
    assert(!handle.invalid);
    /* Neither is an unrelated event on the same chain. */
    assert(ft_fdb_event(NULL, SWITCHDEV_PORT_ATTR_SET, &info) == NOTIFY_DONE);
    assert(!handle.invalid && ft_fdb_invalidations == before);
    FDB_DRAIN();

    /* An unbridged flow has no FDB dependency, so the same event leaves it
     * alone however well its address matches. */
    fixture();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    info = (struct switchdev_notifier_fdb_info){ .info.dev = &decoy, .addr = dst, .vid = 0 };
    before = ft_fdb_invalidations;
    assert(ft_fdb_event(NULL, SWITCHDEV_FDB_DEL_TO_DEVICE, &info) == NOTIFY_DONE);
    assert(!handle.invalid && ft_fdb_invalidations == before);
    FDB_DRAIN();
#undef FDB_FIXTURE
#undef FDB_DRAIN

    /* Per-port VLAN membership decides whether a frame leaves tagged, and
     * reconfiguring it emits no netdev event, so the coarse invalidation is
     * the only thing that notices. It must never claim the object: a handled
     * port-VLAN object makes the bridge skip vlan_vid_add() and filter the
     * VLAN out of the port entirely. */
    struct switchdev_obj vlan_obj = { .id = SWITCHDEV_OBJ_ID_PORT_VLAN };
    struct switchdev_obj mdb_obj = { .id = SWITCHDEV_OBJ_ID_PORT_MDB };
    struct switchdev_notifier_port_obj_info obj = { .info.dev = &out, .obj = &vlan_obj };

    bridge_out_fixture();
    assert(ft_replace(&binding, &cls) == 0);
    assert(!atomic_read(&ft_invalid));
    unsigned vlan_changes = mc_bridge_changes;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &obj) == NOTIFY_DONE);
    assert(atomic_read(&ft_invalid) && !obj.handled);
    atomic_set(&ft_invalid, 0);
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_OBJ_DEL, &obj) == NOTIFY_DONE);
    assert(atomic_read(&ft_invalid) && !obj.handled);
    atomic_set(&ft_invalid, 0);
    /* The bridged multicast learner holds the same VLAN decisions for its
     * flows' copies and ingress, and hears both. */
    assert(mc_bridge_changes == vlan_changes + 2);
    /* A device nothing here depends on is somebody else's bridge. Every
     * bridge installs its default PVID on a port the moment it is enslaved,
     * whatever its VLAN filtering setting, so a scope test that let this
     * through would retire every flow whenever any device anywhere was
     * enslaved to anything. */
    obj.info.dev = &upper;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &obj) == NOTIFY_DONE);
    assert(!atomic_read(&ft_invalid) && !obj.handled);
    obj.info.dev = &out;
    /* An MDB object goes to the multicast learner and must not reach the VLAN
     * arm: it is a membership to install rather than a dependency that
     * changed, so retiring every flow that touches this device for one would
     * be both wrong and expensive -- a channel change would flush the
     * unicast table. */
    obj.obj = &mdb_obj;
    mc_objects = 0;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &obj) == NOTIFY_DONE);
    assert(mc_objects == 1);
    assert(!atomic_read(&ft_invalid) && !obj.handled);
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_OBJ_DEL, &obj) == NOTIFY_DONE);
    assert(mc_objects == 2);
    assert(!atomic_read(&ft_invalid) && !obj.handled);
    /* A host membership takes the same route. */
    mdb_obj.id = SWITCHDEV_OBJ_ID_HOST_MDB;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_OBJ_ADD, &obj) == NOTIFY_DONE);
    assert(mc_objects == 3);
    assert(!atomic_read(&ft_invalid) && !obj.handled);
    mdb_obj.id = SWITCHDEV_OBJ_ID_PORT_MDB;
    obj.obj = &vlan_obj;

    /* Whether the bridge filters by VLAN at all, and in which protocol, are
     * the other two inputs to the derivation, and both arrive as attributes
     * against the bridge rather than as objects against a port. Neither emits
     * a netdev event, so dropping them would leave the hardware pushing a tag
     * software had stopped pushing. */
    struct switchdev_attr filtering = { .id = SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING };
    struct switchdev_attr protocol = { .id = SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL };
    struct switchdev_attr ageing = { .id = SWITCHDEV_ATTR_ID_BRIDGE_AGEING_TIME };
    struct switchdev_notifier_port_attr_info set = { .info.dev = &br, .attr = &filtering };

    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(atomic_read(&ft_invalid) && !set.handled);
    atomic_set(&ft_invalid, 0);
    set.attr = &protocol;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(atomic_read(&ft_invalid) && !set.handled);
    atomic_set(&ft_invalid, 0);
    /* Another attribute of the same bridge changes nothing this derivation
     * reads, and neither does either attribute on an unrelated bridge. */
    set.attr = &ageing;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(!atomic_read(&ft_invalid) && !set.handled);
    set.attr = &filtering;
    set.info.dev = &upper;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(!atomic_read(&ft_invalid) && !set.handled);
    /* Multicast router, snooping and forwarding changes -- the bridge's own
     * router state among them -- refresh routed groups and ask the bridge
     * about every bridged flow again, without claiming the attribute or
     * retiring unrelated unicast entries. */
    enum switchdev_attr_id changes[] = {
        SWITCHDEV_ATTR_ID_BRIDGE_MROUTER,
        SWITCHDEV_ATTR_ID_PORT_MROUTER, SWITCHDEV_ATTR_ID_BRIDGE_MC_DISABLED,
        SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS, SWITCHDEV_ATTR_ID_PORT_STP_STATE,
        SWITCHDEV_ATTR_ID_PORT_MST_STATE, SWITCHDEV_ATTR_ID_BRIDGE_MST,
        SWITCHDEV_ATTR_ID_PORT_VLAN_STATE,
    };
    for (unsigned i = 0; i < ARRAY_SIZE(changes); i++) {
        /* A port going (or staying) FORWARDING retires nothing and queues
         * no sweep, and neither does switching MST on, which only stops
         * the ports' own STP states from applying. */
        struct switchdev_attr change = { .id = changes[i] };
        unsigned kicks = mroute_kicks, sweeps = stopped_scheduled, bridges = mc_bridge_changes;
        if (changes[i] == SWITCHDEV_ATTR_ID_PORT_STP_STATE)
            change.u.stp_state = BR_STATE_FORWARDING;
        if (changes[i] == SWITCHDEV_ATTR_ID_PORT_MST_STATE)
            change.u.mst_state.state = BR_STATE_FORWARDING;
        if (changes[i] == SWITCHDEV_ATTR_ID_PORT_VLAN_STATE)
            change.u.vlan_state = (struct switchdev_vlan_state){ 100, BR_STATE_FORWARDING };
        if (changes[i] == SWITCHDEV_ATTR_ID_BRIDGE_MST)
            change.u.mst = true;
        set.attr = &change;
        set.info.dev = changes[i] == SWITCHDEV_ATTR_ID_BRIDGE_MROUTER ? &br : &out;
        assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
        assert(mroute_kicks == kicks + 1 && stopped_scheduled == sweeps);
        assert(mc_bridge_changes == bridges + 1);
        assert(!atomic_read(&ft_invalid) && !set.handled && !handle.invalid);
        set.info.dev = NULL;
        assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
        assert(mroute_kicks == kicks + 1 && mc_bridge_changes == bridges + 1);
    }
    set.attr = NULL;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);

    /* A port STP takes out of FORWARDING retires every flow through it:
     * software stops forwarding there at once, and the hardware would carry
     * on in both directions under the shared handle. Blocking, disabled and
     * an MSTI leaving FORWARDING all count, and so does one VLAN of the port.
     * Other ports' entries are left alone. */
    const u8 stopped[] = { BR_STATE_BLOCKING, BR_STATE_DISABLED, BR_STATE_LISTENING };
    unsigned records = allocated, sweeps = stopped_scheduled;
    int decoy_refs = decoy.refs, out_refs = out.refs;
    for (unsigned i = 0; i < ARRAY_SIZE(stopped); i++) {
        struct switchdev_attr stp = { .id = SWITCHDEV_ATTR_ID_PORT_STP_STATE,
                                      .u.stp_state = stopped[i] };
        u64 before = ft_stp_invalidations;
        set.attr = &stp;
        set.info.dev = &decoy;
        assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
        assert(ft_stp_invalidations == before);
        set.info.dev = &out;
        assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
        assert(ft_stp_invalidations == before + 1);
        assert(!atomic_read(&ft_invalid) && !set.handled);
        handle.invalid = false;
    }
    struct switchdev_attr msti = { .id = SWITCHDEV_ATTR_ID_PORT_MST_STATE,
                                   .u.mst_state = { .msti = 1, .state = BR_STATE_BLOCKING } };
    u64 before_mst = ft_stp_invalidations;
    set.attr = &msti;
    set.info.dev = &out;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(ft_stp_invalidations == before_mst + 1);
    handle.invalid = false;
    struct switchdev_attr vlan_state = { .id = SWITCHDEV_ATTR_ID_PORT_VLAN_STATE,
                                         .u.vlan_state = { .vid = 100, .state = BR_STATE_BLOCKING } };
    u64 before_vlan = ft_stp_invalidations;
    set.attr = &vlan_state;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(ft_stp_invalidations == before_vlan + 1 && !set.handled);
    handle.invalid = false;

    /* Software flows through a stopped port go too, whoever owns them: one
     * this adapter refused, or another table's, names the port as its ingress,
     * and the flowtable hook runs before the bridge could drop the frame --
     * so the untouched decoy port is swept as well. The sweep is queued, one
     * record per port however many events named it, holding the device until
     * it runs: an MSTI's state arrives in an RCU section and native cleanup
     * sleeps. It takes RTNL first, so a change whose event came before it is
     * in place, then waits out a grace period, so a flow a walk described
     * just before the change is in the table to be found, and cleans outside
     * the backend transaction. */
    assert(stopped_scheduled == sweeps + 2 && allocated == records + 2);
    assert(decoy.refs == decoy_refs + 1 && out.refs == out_refs + 1);
    unsigned grace = grace_periods;
    nswept = swept_under_rtnl = 0;
    ft_stopped_workfn(NULL);
    assert(grace_periods == grace + 1 && !rtnl);
    assert(nswept == 2 && swept_under_rtnl == 2 && swept[0] == &decoy && swept[1] == &out);
    assert(allocated == records && decoy.refs == decoy_refs && out.refs == out_refs);
    /* Drained: the next event queues afresh. */
    set.info.dev = &out;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(stopped_scheduled == sweeps + 3);
    handle.invalid = false;
    nswept = swept_under_rtnl = 0;
    ft_stopped_workfn(NULL);
    assert(nswept == 1 && swept_under_rtnl == 1 && swept[0] == &out);
    assert(allocated == records && out.refs == out_refs);

    /* A VLAN of the bridge's own entry reaches every flow through the bridge
     * and every port of it; this harness gives the bridge one lower, decoy.
     * A port that is itself a VLAN device is swept at the real device too,
     * because that is where the forward-path walk ends. */
    u64 before_entry = ft_stp_invalidations;
    int br_refs = br.refs, tag_refs = out_tag.refs;
    set.info.dev = &br;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    assert(ft_stp_invalidations == before_entry + 1 && handle.invalid);
    handle.invalid = false;
    set.info.dev = &out_tag;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    nswept = swept_under_rtnl = 0;
    ft_stopped_workfn(NULL);
    assert(nswept == 3 && swept_under_rtnl == 3);
    assert(swept[0] == &decoy && swept[1] == &out_tag && swept[2] == &out);
    assert(allocated == records && br.refs == br_refs && out_tag.refs == tag_refs);

    /* The two bridge-wide MST events stop the whole bridge as well, and still
     * refresh routed groups. A VLAN moved to another MSTI takes up that
     * MSTI's state on every port, DISABLED where it has none, and no port
     * event reports it; switching MST off lets each port's own STP state
     * apply again. Neither says which port stopped, so every port is swept. */
    struct switchdev_attr remap = { .id = SWITCHDEV_ATTR_ID_VLAN_MSTI };
    struct switchdev_attr mst_off = { .id = SWITCHDEV_ATTR_ID_BRIDGE_MST, .u.mst = false };
    struct switchdev_attr *bridge_wide[] = { &remap, &mst_off };
    for (unsigned i = 0; i < ARRAY_SIZE(bridge_wide); i++) {
        u64 before_wide = ft_stp_invalidations;
        unsigned kicks = mroute_kicks, queued = stopped_scheduled;
        set.attr = bridge_wide[i];
        set.info.dev = &br;
        assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
        assert(mroute_kicks == kicks + 1 && stopped_scheduled == queued + 1);
        assert(ft_stp_invalidations == before_wide + 1 && handle.invalid);
        assert(!atomic_read(&ft_invalid) && !set.handled);
        handle.invalid = false;
        nswept = swept_under_rtnl = 0;
        ft_stopped_workfn(NULL);
        assert(nswept == 1 && swept_under_rtnl == 1 && swept[0] == &decoy);
        assert(allocated == records && br.refs == br_refs);
    }
    set.attr = &vlan_state;

    /* Losing the record to a failed allocation must not lose the sweep: the
     * work then cleans every bridge port in the namespace. */
    struct net_device *registry[] = { &in, &out, &upper, &decoy, &br };
    netdev_registry = registry;
    netdev_registry_len = ARRAY_SIZE(registry);
    allocation_fail = true;
    set.info.dev = &out;
    assert(ft_swdev_event(NULL, SWITCHDEV_PORT_ATTR_SET, &set) == NOTIFY_DONE);
    allocation_fail = false;
    assert(stopped_scheduled == sweeps + 8 && allocated == records && out.refs == out_refs);
    handle.invalid = false;
    nswept = swept_under_rtnl = 0;
    ft_stopped_workfn(NULL);
    assert(nswept == 3 && swept_under_rtnl == 3);
    assert(swept[0] == &in && swept[1] == &out && swept[2] == &decoy);
    /* Once, not on every run after. */
    nswept = 0;
    ft_stopped_workfn(NULL);
    assert(!nswept);
    netdev_registry = NULL;
    netdev_registry_len = 0;
    set.attr = NULL;

    /* A port whose egress queues changed under it -- an HTB tree coming or
     * going -- re-installs everything that transmits on it: its flows are
     * retired to be readmitted against the new queues, and its SAs and
     * multicast groups are handed on to be rebuilt, each only after the
     * change is counted, which is what something built meanwhile compares
     * against. Other ports are left alone. */
    u64 before_qos = ft_qos_invalidations, counted = ft_egress_changes;
    ipsec_egress_changed = mc_egress_changed = NULL;
    ft_egress_changed(&decoy);
    assert(ft_qos_invalidations == before_qos && ipsec_egress_changed == &decoy);
    assert(mc_egress_changed == &decoy && ft_egress_changes == counted + 1);
    ft_egress_changed(&out);
    assert(ft_qos_invalidations == before_qos + 1 && handle.invalid);
    assert(ipsec_egress_changed == &out && mc_egress_changed == &out);
    assert(ft_egress_changes == counted + 2);
    assert(egress_changes_seen_by_ipsec == counted + 2 && egress_changes_seen_by_mc == counted + 2);
    handle.invalid = false;

    ft_handle_invalidate(&handle, &ft_mac_invalidations);
    ft_retire_workfn(NULL);
    assert(!ft_count && !allocated);
}

/* The concentrator's address, which is the Ethernet destination a session
 * imposes and the one thing about the hop that no action, selector or device
 * can be cross-checked against. */
static const u8 AC_MAC[6] = { 2, 0xac, 0, 0, 0, 1 };
#define SESSION_ID 0x1234

/* Zero the two Ethernet-destination mangle words, which is what Netfilter
 * really writes for a session: flow_offload_eth_dst() resolves the NOARP
 * neighbour arp_constructor() builds on a ppp device, and that neighbour's
 * hardware address is the zero one a device with no address length leaves
 * behind. Entries 0 and 1 carry the source and are untouched. */
static void zero_ethernet_dest(void)
{
    rule.action.entries[2].mangle.val = 0;
    rule.action.entries[3].mangle.val = 0;
}

/* The same two words with an address in them, laid out the way
 * flow_offload_eth_dst() lays one out: the first four bytes in one action and
 * the last two in the next, whose remaining half belongs to the source. */
static void ethernet_dest(const u8 *mac)
{
    const u8 first[4] = { mac[0], mac[1], mac[2], mac[3] };
    const u8 second[4] = { mac[4], mac[5], 0, 0 };

    memcpy(&rule.action.entries[2].mangle.val, first, 4);
    memcpy(&rule.action.entries[3].mangle.val, second, 4);
}

/* What a NOARP device that still has header ops leaves in every neighbour
 * built on it: arp_constructor() and ndisc_constructor() copy dev_addr into
 * neigh->ha, and flow_offload_eth_dst() then writes the first six bytes of
 * that. For a tunnel device dev_addr is its local endpoint -- four bytes for
 * sit, sixteen for ip6tnl -- so the words carry the address zero-padded or
 * truncated, never zero and never a real Ethernet address. */
static void tunnel_ethernet_dest(const struct net_device *dev)
{
    u8 own[ETH_ALEN] = {};

    memcpy(own, dev->dev_addr, min_t(unsigned int, dev->addr_len, ETH_ALEN));
    ethernet_dest(own);
}

/* Append one PPPoE push after whatever encapsulation actions are already
 * there, which is where nf_flow_rule_route_common() puts it: the pushes are
 * emitted outermost first and the session is the innermost header, so it
 * comes after every tag. */
static void session_push(u16 sid)
{
    unsigned at = rule.action.num_entries - 1;

    assert(rule.action.num_entries + 1 <= ARRAY_SIZE(rule.action.entries));
    rule.action.entries[at + 1] = rule.action.entries[at];
    rule.action.entries[at] = (struct flow_action_entry){
        .id = FLOW_ACTION_PPPOE_PUSH, .pppoe = { .sid = sid } };
    rule.action.num_entries++;
}

/* A session on the egress path, running straight on the physical port. The
 * route names the ppp device, the redirect still names the port, and the
 * session is what lies between. No neighbour moves to the ppp device: there
 * is none to move, which is half the point. The path is the session's, and
 * the flow is TCP, the kind carried into a path smaller than the LAN's; see
 * the reject case for UDP. */
static void pppoe_out_fixture(void)
{
    vlan_fixture();
    tcp_flow();
    assert(!ppp.refs && !in_ppp.refs);
    route.dst.dev = &ppp;
    cls.nf_mtu = ppp.mtu;
    egress_session = (struct nf_flow_session){ .lower_ifindex = out.ifindex,
                                               .id = SESSION_ID };
    memcpy(egress_session.h_dest, AC_MAC, ETH_ALEN);
    zero_ethernet_dest();
    session_push(SESSION_ID);
}

/* A session on the ingress path. The rule is indistinguishable from an
 * unencapsulated one -- no pop action, no dissector key, the same action count
 * -- so the devices are the only thing that says the frames arrive
 * encapsulated at all. */
static void pppoe_in_fixture(void)
{
    vlan_fixture();
    assert(!ppp.refs && !in_ppp.refs);
    reverse_route.dst.dev = &in_ppp;
    ingress_session = (struct nf_flow_session){ .lower_ifindex = in.ifindex,
                                                .id = SESSION_ID + 1 };
    memcpy(ingress_session.h_dest, AC_MAC, ETH_ALEN);
}

#define PPPOE_REJECT(...) do { pppoe_out_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
#define PPPOE_IN_REJECT(...) do { pppoe_in_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)

static void test_pppoe(void)
{
    struct cdx_ft_rule decoded;
    const u16 push_one[] = { 100 };

    /* Egress session on the port itself. The destination comes from the
     * session, not from the rule, because the rule carries zeros. */
    pppoe_out_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_session.present && decoded.out_session.id == SESSION_ID);
    assert(!memcmp(decoded.out_session.mac, AC_MAC, ETH_ALEN));
    assert(!memcmp(decoded.dst_mac, AC_MAC, ETH_ALEN));
    assert(!decoded.in_session.present && !decoded.out_vlans && !decoded.in_vlans);
    assert(decoded.out_logical == &ppp && decoded.out == &out && decoded.in == &in);
    /* The Ethernet source is still the port's, exactly as for a tagged flow. */
    assert(!memcmp(decoded.src_mac, out.dev_addr, ETH_ALEN));
    /* The MTU is the ppp device's, which already accounts for the eight bytes
     * the session header costs; nothing here has to subtract them. */
    assert(decoded.mtu == 1492 && ppp.mtu == 1492);
    /* UDP from a 1500-byte LAN into the session would be fragmented by the
     * microcode, so it stays in software; the other way it fits the LAN.
     * An ingress session counts eight bytes less of the frame. */
    PPPOE_REJECT(udp_flow());
    pppoe_in_fixture(); cls.nf_mtu = 1492;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.mtu == 1492);
    pppoe_in_fixture(); cls.nf_mtu = 1491;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    /* A ppp device set smaller counts for no less: the concentrator may still
     * send what the Ethernet below carries. */
    pppoe_in_fixture(); in_ppp.mtu = cls.nf_mtu = 1480;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    in_ppp.mtu = 1492;

    /* No neighbour is consulted at all. Making every lookup fail leaves the
     * decode untouched, which an ordinary flow would not survive. */
    pppoe_out_fixture();
    neigh_ok = false;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    neigh_ok = true;

    /* Ingress session. Netfilter describes it with nothing: no pop, no key,
     * five actions -- the same rule an unencapsulated flow produces. */
    pppoe_in_fixture();
    assert(rule.action.num_entries == 5);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in_session.present && !decoded.out_session.present);
    assert(decoded.in_logical == &in_ppp && decoded.in == &in);
    /* An ingress session carries no identity into the rule, because the strip
     * validates none. What it must not do is disturb the egress destination. */
    assert(!memcmp(decoded.dst_mac, neighbour.ha, ETH_ALEN));

    /* The shape the bench runs: the session over a VLAN device over the port.
     * The tag below the session is still derived by the walk, and its push
     * comes before the session's. */
    pppoe_out_fixture();
    egress_session.lower_ifindex = out_tag.ifindex;
    encap_actions(0, push_one, ARRAY_SIZE(push_one));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_session.present && decoded.out_vlans == 1 &&
           decoded.out_vlan[0].id == 100);
    assert(rule.action.entries[4].id == FLOW_ACTION_VLAN_PUSH &&
           rule.action.entries[5].id == FLOW_ACTION_PPPOE_PUSH);

    /* And over a bridge, where the device below the session has no tag of its
     * own but does have a bridge hop the walk must still cross. */
    bridge_fixture();
    tcp_flow();
    route.dst.dev = &ppp;
    cls.nf_mtu = ppp.mtu;
    egress_session = (struct nf_flow_session){ .lower_ifindex = br.ifindex,
                                               .id = SESSION_ID };
    memcpy(egress_session.h_dest, AC_MAC, ETH_ALEN);
    zero_ethernet_dest();
    session_push(SESSION_ID);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_session.present && decoded.out_bridge == &br &&
           !decoded.out_vlans);

    /* Both directions over sessions, with different ids, which is what a
     * router between two PPPoE accesses looks like. */
    pppoe_out_fixture();
    reverse_route.dst.dev = &in_ppp;
    ingress_session = (struct nf_flow_session){ .lower_ifindex = in.ifindex,
                                                .id = SESSION_ID + 1 };
    memcpy(ingress_session.h_dest, AC_MAC, ETH_ALEN);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_session.present && decoded.in_session.present);
    assert(decoded.out_session.id == SESSION_ID &&
           decoded.in_session.id == SESSION_ID + 1);

    /* Re-entering the port a frame arrived on, with a session on one side
     * only: two distinct paths, exactly as two different tag stacks are, so
     * the hairpin rule must not collapse them into one. */
    pppoe_out_fixture();
    rule.action.entries[rule.action.num_entries - 1].dev = &in;
    source_mac(&in);
    egress_session.lower_ifindex = in.ifindex;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out == &in && decoded.in == &in && decoded.out_session.present);

    /* Every way the hop can fail to describe something the hardware could
     * reproduce. */
    PPPOE_REJECT(egress_session.lower_ifindex = 0);      /* device named none */
    PPPOE_REJECT(egress_session.lower_ifindex = 9999);   /* named one that is gone */
    PPPOE_REJECT(egress_session.lower_ifindex = ppp.ifindex); /* named itself */
    /* A second session below the first: one record for the path means the
     * hop below resolves to the device this one already named. */
    PPPOE_REJECT(egress_session.lower_ifindex = in_ppp.ifindex);
    /* A session below a tag, which is the wrong way round on the wire. */
    PPPOE_REJECT(route.dst.dev = &out_tag; out_tag.real_dev = &ppp;
                 encap_actions(0, push_one, ARRAY_SIZE(push_one)));
    out_tag.real_dev = &out;
    /* Session zero is reserved for discovery. The pushed sid is zeroed to
     * agree with it, so the id test is the only thing left that can decline
     * this -- without that, the action cross-check refuses it instead and the
     * case passes while the guard it names does nothing. */
    PPPOE_REJECT(egress_session.id = 0;
                 rule.action.entries[4].pppoe.sid = 0);
    PPPOE_REJECT(memset(egress_session.h_dest, 0, ETH_ALEN));
    PPPOE_REJECT(egress_session.h_dest[0] |= 1);         /* multicast concentrator */
    PPPOE_REJECT(cls.nf_session = NULL);
    /* The push must agree with the walk, which is the only cross-check the
     * hop has. */
    PPPOE_REJECT(rule.action.entries[4].pppoe.sid = SESSION_ID + 1);
    PPPOE_REJECT(rule.action.entries[4].id = FLOW_ACTION_VLAN_PUSH);
    PPPOE_REJECT(rule.action.entries[4].id = FLOW_ACTION_VLAN_POP);
    /* A push where the walk found no session, and a session where the rule
     * pushed nothing. */
    PPPOE_REJECT(route.dst.dev = &out);
    PPPOE_REJECT(rule.action.entries[4] = rule.action.entries[5];
                 rule.action.num_entries--);
    /* The Ethernet destination must be the zero one Netfilter writes. A
     * kernel that started resolving something there would otherwise be
     * silently overridden by the session's address. */
    PPPOE_REJECT(rule.action.entries[2].mangle.val = 0x33221102);
    /* The device below the session may not override the port's address: the
     * hardware emits the port's and software would emit the override. */
    PPPOE_REJECT(egress_session.lower_ifindex = out_tag.ifindex;
                 out_tag.dev_addr[5]++;
                 encap_actions(0, push_one, ARRAY_SIZE(push_one)));
    ether_addr_copy(out_tag.dev_addr, out.dev_addr);
    /* A session plus a full tag stack exceeds the encapsulation budget. */
    PPPOE_REJECT(egress_session.lower_ifindex = out_qinq.ifindex;
                 encap_actions(0, (const u16[]){ 100, 300 }, 2));
    /* Netfilter named a session on a path this walk never crossed one on. */
    PPPOE_IN_REJECT(reverse_route.dst.dev = &in);
    PPPOE_IN_REJECT(cls.nf_session_reverse = NULL);
    PPPOE_IN_REJECT(ingress_session.lower_ifindex = 0);
    /* An ingress session must not be given a pop the kernel never emits. */
    PPPOE_IN_REJECT(encap_actions(1, NULL, 0));

    /* IPv6 over a session, which the firmware carries: the insert opcode
     * names no PPP protocol id, so the ucode picks one, and it picks the
     * IPv6 one -- measured on hardware at line rate with the peer parsing
     * every frame. Nothing about the family reaches this decode, which is
     * the point: the session is described identically either way. */
    fixture6();
    route6.dst.dev = &ppp;
    egress_session = (struct nf_flow_session){ .lower_ifindex = out.ifindex,
                                               .id = SESSION_ID };
    memcpy(egress_session.h_dest, AC_MAC, ETH_ALEN);
    zero_ethernet_dest();
    session_push(SESSION_ID);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.family == AF_INET6 && decoded.out_session.present);
    assert(decoded.out_session.id == SESSION_ID);
    assert(!memcmp(decoded.dst_mac, AC_MAC, ETH_ALEN));
    assert(!decoded.in_session.present);
    /* And the other way round, where the rule describes the session with
     * nothing at all and only the devices say it is there. */
    fixture6();
    reverse_route6.dst.dev = &in_ppp;
    ingress_session = (struct nf_flow_session){ .lower_ifindex = in.ifindex,
                                                .id = SESSION_ID + 1 };
    memcpy(ingress_session.h_dest, AC_MAC, ETH_ALEN);
    assert(rule.action.num_entries == 5);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.family == AF_INET6 && decoded.in_session.present);
    assert(decoded.in_session.id == SESSION_ID + 1 && !decoded.out_session.present);

    /* Lifecycle. A session direction holds no neighbour, so it has to reach
     * the watch list by another route -- and a device event has to find it
     * there. The reference counts prove the ppp device is pinned like any
     * other logical device, and the teardown proves the unlink happens even
     * with nothing to release. */
    pppoe_out_fixture();
    u64 links = ft_link_invalidations;
    /* Admission and removal run inside the backend transaction the rule
     * callback holds, which is also what serializes the session statistics
     * records a session direction claims. ft_retire_workfn takes it itself,
     * so it stays outside. */
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    assert(!ft_neighbour_refs && ppp.refs == 1 && out.refs == 1);
    assert(ft_neigh_entries.next != &ft_neigh_entries);
    ft_device_retire(&ppp, &ft_link_invalidations);
    assert(handle.invalid && ft_link_invalidations == links + 1);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !ppp.refs && !out.refs && !allocated);
    assert(ft_neigh_entries.next == &ft_neigh_entries);

    /* Statistics on a session direction must not reach for a neighbour that
     * is not there, and must not report the flow as unused. */
    pppoe_out_fixture();
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    struct cdx_ft_entry *entry = ft_find(&binding, cls.cookie);
    assert(entry && !entry->neigh);
    cls.command = FLOW_CLS_STATS;
    assert(ft_stats(entry, &cls) == 0);
    cls.command = FLOW_CLS_REPLACE;
    assert(ft_remove(entry) == 0 && !ft_count);
    cdx_ft_end();
    drop_dev_records();
    assert(!ppp.refs && !out.refs && !allocated);
}

/* One more flow over a named session, on top of a fixture already laid out.
 * Mutates only what varies, because re-running a fixture while an entry is
 * live trips its own assertions. Every guard other than the one a case is
 * about is made to agree: the push carries the same id the session record
 * does, so a case that expects a refusal gets it from the guard it names
 * rather than from the action cross-check. */
static void session_rule(unsigned long cookie, u16 sport, u16 sid, int lower_ifindex)
{
    cls.cookie = cookie;
    cls.stats = (struct flow_stats){0};
    pk.src = htons(sport);
    egress_session.id = sid;
    egress_session.lower_ifindex = lower_ifindex;
    rule.action.entries[4].pppoe.sid = sid;
}

static unsigned dev_record_count(void)
{
    struct cdx_ft_dev_stats *record;
    unsigned n = 0;

    list_for_each_entry(record, &ft_dev_stats, list) n++;
    return n;
}

static struct cdx_ft_dev_stats *dev_record(int ifindex)
{
    struct cdx_ft_dev_stats *record;

    list_for_each_entry(record, &ft_dev_stats, list)
        if (record->ifindex == ifindex && !record->gone) return record;
    return NULL;
}

static void device_unregistered(struct net_device *dev)
{
    struct netdev_notifier_info info = { .dev = dev };

    assert(!cdx_info->ctrl.mutex);
    ft_netdev_event(NULL, NETDEV_UNREGISTER, &info);
    /* The invalidation a used device raises is another case's business. */
    ft_invalid = 0;
}

static unsigned session_record_count(void)
{
    struct cdx_ft_dev_stats *record;
    unsigned n = 0;

    list_for_each_entry(record, &ft_dev_stats, list)
        n += record->kind == CDX_FT_STATS_TIMESTAMPED;
    return n;
}

/* Interface-level counters for a ppp device: one timestamped record per
 * device, claimed by the first direction crossing its session and kept for the
 * device's life, published to the device with the session's framing. The
 * firmware pool is four records deep and shared with the legacy owner, so
 * running out is an expected outcome and not a failure -- the flow installs
 * and forwards, and the record says it is counting nowhere so the degradation
 * can be seen.
 *
 * Admission and removal run inside the backend transaction the rule callback
 * holds, which is what serializes the record list as well; the fixtures do not
 * touch it, so it is held across each section. Dropping the records between
 * sections stands in for the devices going away.
 */
static void test_pppoe_stats(void)
{
    struct cdx_ft_entry *first, *second;
    struct cdx_ft_dev_stats *record;
    struct cdx_ft_stats rx, tx;
    unsigned allocations, frees;

    cdx_ft_begin();
    assert(!stats_in_use() && !dev_record_count());
    allocations = stats_allocations;

    /* First admission of a session claims the ppp device's record, publishes
     * it to that device with the PPPoE framing, and hands the encoder the
     * transmit half's index -- never zero, which is somebody else's. */
    pppoe_out_fixture();
    session_rule(1, 10000, 0x1234, out.ifindex);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    assert(stats_in_use() == 1 && stats_allocations == allocations + 1);
    first = ft_find(&binding, 1);
    assert(first && first->out_stats && !first->in_stats);
    record = first->out_stats;
    assert(record == dev_record(ppp.ifindex) && record->kind == CDX_FT_STATS_TIMESTAMPED);
    assert(record->refs == 1 && record->slot && record->slot->kind == CDX_FT_STATS_TIMESTAMPED);
    assert(record->slot->published_ifindex == ppp.ifindex);
    /* The strip counts the frame less the session header alone -- the tags
     * under the session, none here, stay in -- and the insert has put the
     * session header on; the device counts the payload alone. */
    assert(record->slot->published_rx_overhead == ft_ppp_rx_overhead(0));
    assert(record->slot->published_tx_overhead == FT_PPP_TX_OVERHEAD);
    assert(ft_ppp_rx_overhead(0) == ETH_HLEN && ft_ppp_rx_overhead(1) == ETH_HLEN + VLAN_HLEN);
    assert(FT_PPP_TX_OVERHEAD == ETH_HLEN + PPPOE_SES_HLEN);
    assert(observed_out_stats == record->slot->tx_index);
    assert(observed_out_stats && !observed_in_stats);
    assert(session_record_count() == 1 && dev_record_count() == 1);
    /* The row carries the session the walk resolved, in full. */
    assert(record->session.present && record->session.id == 0x1234);
    assert(record->session.lower_ifindex == out.ifindex);
    assert(!memcmp(record->session.mac, AC_MAC, ETH_ALEN));

    /* Read-back. A fresh record has counted nothing; what the firmware puts
     * there is reported per half; and a device with no record reads as zeroes
     * rather than as an error, which is what it has to show. */
    cdx_ft_stats_read(record->slot, &rx, &tx);
    assert(!rx.packets && !rx.bytes && !tx.packets && !tx.bytes);
    record->slot->tx = (struct cdx_ft_stats){ .bytes = 4096, .packets = 32 };
    cdx_ft_stats_read(record->slot, &rx, &tx);
    assert(tx.packets == 32 && tx.bytes == 4096 && !rx.packets && !rx.bytes);
    cdx_ft_stats_read(NULL, &rx, &tx);
    assert(!rx.packets && !rx.bytes && !tx.packets && !tx.bytes);

    /* A second connection over the same device shares the record: one slot,
     * two references. */
    session_rule(2, 10001, 0x1234, out.ifindex);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 2);
    second = ft_find(&binding, 2);
    assert(second && second->out_stats == record && record->refs == 2);
    assert(stats_in_use() == 1 && session_record_count() == 1);

    /* A session renegotiated under a device that stays is that device's
     * traffic: a different id on the same ppp device finds the same record,
     * and the row follows the newest direction. */
    session_rule(3, 10002, 0x1235, out.ifindex);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 3);
    assert(ft_find(&binding, 3)->out_stats == record && record->refs == 3);
    assert(record->session.id == 0x1235 && session_record_count() == 1);

    /* The record outlives its flows: retiring them returns the references
     * and nothing else, so the device's totals survive a connection going
     * idle, and the next one finds the same record and the same slot. */
    frees = stats_frees;
    assert(ft_remove(first) == 0 && record->refs == 2);
    assert(ft_remove(second) == 0 && ft_remove(ft_find(&binding, 3)) == 0 && !ft_count);
    assert(record->refs == 0 && !record->gone && stats_frees == frees);
    assert(stats_in_use() == 1 && session_record_count() == 1);
    assert(dev_record(ppp.ifindex) == record && record->slot);
    {
        struct cdx_ft_stats_slot *slot = record->slot;

        session_rule(4, 10003, 0x1236, out.ifindex);
        assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
        assert(ft_find(&binding, 4)->out_stats == record && record->refs == 1);
        assert(record->slot == slot && record->session.id == 0x1236);
        assert(ft_remove(ft_find(&binding, 4)) == 0 && !ft_count && record->refs == 0);
    }

    /* Only the device going frees it -- here with nothing naming it, so the
     * reaper does the freeing -- and a new device under the same index then
     * starts a record of its own. */
    cdx_ft_end();
    dev_stats_scheduled = 0;
    device_unregistered(&ppp);
    assert(dev_stats_scheduled == 1);
    ft_dev_stats_reap(NULL);
    cdx_ft_begin();
    assert(!dev_record_count() && !stats_in_use() && stats_frees == frees + 1);

    /* Exhaustion. The pool has nothing: the device's record exists and says
     * so, the encoder is told there is none, and the flow installs regardless.
     * Returning a slot later does not retrofit one -- the answer a device got
     * is the answer it keeps, so a live connection's counters never begin
     * halfway through its life -- and the record, slotless, still outlives its
     * flows. */
    pppoe_out_fixture();
    stats_alloc_fail = -ENOSPC;
    session_rule(20, 12000, 0x3000, out.ifindex);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    stats_alloc_fail = 0;
    first = ft_find(&binding, 20);
    record = first->out_stats;
    assert(record && !record->slot && record->refs == 1 && !observed_out_stats);
    assert(session_record_count() == 1 && !stats_in_use());
    session_rule(21, 12001, 0x3000, out.ifindex);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 2);
    assert(ft_find(&binding, 21)->out_stats == record && !record->slot && !observed_out_stats);
    assert(ft_remove(first) == 0 && ft_remove(ft_find(&binding, 21)) == 0 && !ft_count);
    assert(dev_record(ppp.ifindex) == record && !record->slot && !record->refs);
    /* Gone and unreferenced, it is reaped like any other; the device that
     * comes back under the index gets a slot if the pool has one. This one
     * runs its session over a VLAN device, the shape the bench has: the tag
     * under the session stays in what the strip counts, so the device's
     * receive framing grows by it, and the tag's own record sits alongside. */
    cdx_ft_end();
    device_unregistered(&ppp);
    ft_dev_stats_reap(NULL);
    cdx_ft_begin();
    assert(!dev_record_count());
    pppoe_out_fixture();
    /* The session's push is named before the tag's is inserted ahead of it. */
    session_rule(22, 12002, 0x3001, out_tag.ifindex);
    encap_actions(0, (const u16[]){ 100 }, 1);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 22);
    record = first->out_stats;
    assert(stats_in_use() == 1 && record && record->slot);
    assert(record->slot->published_rx_overhead == ETH_HLEN + VLAN_HLEN);
    assert(record->slot->published_tx_overhead == FT_PPP_TX_OVERHEAD);
    assert(observed_out_stats == record->slot->tx_index);
    assert(first->out_vlan_stats[0] && first->out_vlan_stats[0]->ifindex == out_tag.ifindex);
    assert(plain_in_use() == 1 && dev_record_count() == 2);
    assert(ft_remove(first) == 0 && !ft_count);

    /* An allocation failing for any other reason lands in the same place: the
     * flow installs, counts nowhere, and holds a record saying so. */
    cdx_ft_end();
    drop_dev_records();
    pppoe_out_fixture();
    cdx_ft_begin();
    stats_alloc_fail = -ENOMEM;
    session_rule(31, 13001, 0x4001, out.ifindex);
    assert(ft_replace(&binding, &cls) == 0 && !observed_out_stats);
    assert(session_record_count() == 1 && !dev_record(ppp.ifindex)->slot);
    stats_alloc_fail = 0;
    assert(ft_remove(ft_find(&binding, 31)) == 0 && !ft_count);

    /* A flow whose hardware installation fails releases its reference with
     * everything else. */
    session_rule(32, 13002, 0x4002, out.ifindex);
    hardware_fail = true;
    assert(ft_replace(&binding, &cls) == -EIO && !ft_count);
    hardware_fail = false;
    assert(dev_record(ppp.ifindex) && !dev_record(ppp.ifindex)->refs);

    /* A record has two halves and the direction decides which one is counted
     * into: a direction that strips counts received frames, one that inserts
     * counts transmitted ones. The two halves of a connection therefore
     * describe the device between them. The ingress fixture's session runs on
     * another ppp device, which gets a record of its own. */
    cdx_ft_end();
    drop_dev_records();
    pppoe_in_fixture();
    cdx_ft_begin();
    /* Not session_rule(): that one names an egress session, and naming one
     * here would be a session the walk never crosses. The ingress fixture has
     * already described this direction's. */
    cls.cookie = 40;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 40);
    assert(first && first->in_stats && !first->out_stats);
    record = first->in_stats;
    assert(record == dev_record(in_ppp.ifindex) && record->slot && record->refs == 1);
    assert(record->slot->published_ifindex == in_ppp.ifindex);
    assert(observed_in_stats == record->slot->rx_index && !observed_out_stats);
    assert(record->slot->rx_index != record->slot->tx_index);
    assert(record->session.present && record->session.id == SESSION_ID + 1);
    assert(ft_remove(first) == 0 && !ft_count);
    assert(stats_in_use() == 1 && session_record_count() == 1 && !record->refs);

    /* A flow with no session claims nothing at all. */
    cdx_ft_end();
    drop_dev_records();
    fixture();
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0);
    assert(!stats_in_use() && !dev_record_count());
    assert(!observed_in_stats && !observed_out_stats);
    assert(ft_remove(ft_find(&binding, cls.cookie)) == 0 && !ft_count);
    cdx_ft_end();
}

/* The outer endpoints and the outer next hop, all distinct from every address
 * the flow fixtures use, so nothing can pass by matching the wrong one. */
#define TNL4_LOCAL   htonl(0xc0a80a01)	/* 192.168.10.1 */
#define TNL4_REMOTE  htonl(0xcb0071c8)	/* 203.0.113.200 */
#define TNL4_NEXTHOP htonl(0xc0a80afe)	/* 192.168.10.254 */
#define TNL6_PREFIX  0xfc00cafe
/* The outer next hop's Ethernet address, which is what a tunnel egress uses
 * as its destination -- the tunnel device resolves none of its own. */
static const u8 OUTER_MAC[6] = { 2, 0x0e, 0, 0, 0, 7 };
static struct in6_addr tnl6_local(void) { return addr6(TNL6_PREFIX, 1); }
static struct in6_addr tnl6_remote(void) { return addr6(TNL6_PREFIX, 2); }
static struct in6_addr tnl6_nexthop(void) { return addr6(0xfe800000, 9); }

static void sit_parms(struct ip_tunnel *priv)
{
    memset(priv, 0, sizeof(*priv));
    priv->parms.iph.saddr = TNL4_LOCAL;
    priv->parms.iph.daddr = TNL4_REMOTE;
    priv->parms.iph.ttl = 64;
    priv->parms.iph.tos = 0;
}

static void tnl6_parms(struct ip6_tnl *priv)
{
    memset(priv, 0, sizeof(*priv));
    priv->parms.laddr = tnl6_local();
    priv->parms.raddr = tnl6_remote();
    priv->parms.hop_limit = 63;
    priv->parms.proto = IPPROTO_IPIP;
}

/* Every tunnel device restored to the configuration the hops below agree
 * with, because the rejection cases work by pulling one of the two out of
 * step with the other. A device's address is its local endpoint, which is
 * what its neighbours -- and so Netfilter's Ethernet destination -- carry. */
static void tunnel_devices(void)
{
    __be32 local4 = TNL4_LOCAL;
    struct in6_addr local6 = tnl6_local();

    assert(!sit.refs && !in_sit.refs && !ip6tnl.refs && !in_ip6tnl.refs);
    sit.type = in_sit.type = ARPHRD_SIT;
    sit.addr_len = in_sit.addr_len = sizeof(local4);
    /* The MTUs `ip link add` derives: the port's less the outer header. */
    sit.mtu = in_sit.mtu = 1480;
    memset(sit.dev_addr, 0, ETH_ALEN);
    memcpy(sit.dev_addr, &local4, sizeof(local4));
    memcpy(in_sit.dev_addr, sit.dev_addr, ETH_ALEN);
    sit_parms(&sit_priv);
    sit_parms(&in_sit_priv);

    ip6tnl.type = in_ip6tnl.type = ARPHRD_TUNNEL6;
    ip6tnl.addr_len = in_ip6tnl.addr_len = sizeof(local6);
    ip6tnl.mtu = in_ip6tnl.mtu = 1452;
    memcpy(ip6tnl.dev_addr, &local6, ETH_ALEN);
    memcpy(in_ip6tnl.dev_addr, ip6tnl.dev_addr, ETH_ALEN);
    tnl6_parms(&ip6tnl_priv);
    tnl6_parms(&in_ip6tnl_priv);
}

/* One hop per mode, as the kernel's forwarding-path walk records it. */
static void tnl4_hop(struct nf_flow_tunnel *hop, int lower)
{
    memset(hop, 0, sizeof(*hop));
    hop->lower_ifindex = lower;
    hop->family = AF_INET;
    hop->proto = IPPROTO_IPV6;
    hop->ttl = 64;
    hop->tos = 0;
    hop->flags = CDX_FT_TUNNEL_DF;
    hop->saddr = v4(TNL4_LOCAL);
    hop->daddr = v4(TNL4_REMOTE);
    hop->nexthop = v4(TNL4_NEXTHOP);
    memcpy(hop->h_dest, OUTER_MAC, ETH_ALEN);
}

static void tnl6_hop(struct nf_flow_tunnel *hop, int lower)
{
    memset(hop, 0, sizeof(*hop));
    hop->lower_ifindex = lower;
    hop->family = AF_INET6;
    hop->proto = IPPROTO_IPIP;
    hop->ttl = 63;
    hop->flowlabel = htonl(0x12345);
    hop->saddr.in6 = tnl6_local();
    hop->daddr.in6 = tnl6_remote();
    hop->nexthop.in6 = tnl6_nexthop();
    memcpy(hop->h_dest, OUTER_MAC, ETH_ALEN);
}

/* The outer next hop's neighbour, which lives on the device below the tunnel
 * and in the outer header's family -- never on the tunnel device, which has
 * none, and not necessarily in the flow's family either. */
static void outer_neighbour(struct net_device *lower, u8 family)
{
    gateway = (struct neighbour){ .tbl = family == AF_INET6 ? &nd_tbl : &arp_tbl,
                                  .nud_state = NUD_PERMANENT, .dev = lower };
    memcpy(gateway.ha, OUTER_MAC, ETH_ALEN);
    if (family == AF_INET6)
        gateway.primary_key.in6 = tnl6_nexthop();
    else
        gateway.primary_key.ip = TNL4_NEXTHOP;
}

/* 6o4 egress: an IPv6 flow leaving by a sit device that runs straight on the
 * egress port. The route names the tunnel device, the redirect still names
 * the port, and the outer IPv4 header is what lies between. */
static void sit_out_fixture(void)
{
    fixture6();
    tunnel_devices();
    route6.dst.dev = &sit;
    /* The LAN advertises the tunnel's MTU; see the reject case below. */
    cls.nf_mtu = in.ip6_mtu = sit.mtu;
    tnl4_hop(&egress_tunnel, out.ifindex);
    tunnel_ethernet_dest(&sit);
    outer_neighbour(&out, AF_INET);
}

/* 6o4 ingress. Netfilter describes it with nothing at all -- no pop, no key,
 * the same five actions an unencapsulated flow produces -- so the devices are
 * the only thing saying the frames arrive encapsulated. The egress side stays
 * an ordinary routed one, destination and all. */
static void sit_in_fixture(void)
{
    fixture6();
    tunnel_devices();
    reverse_route6.dst.dev = &in_sit;
    tnl4_hop(&ingress_tunnel, in.ifindex);
}

/* 4o6 egress: an IPv4 flow leaving by an ip6tnl device in ipip6 mode. Built on
 * the VLAN fixture so the cases that put a tag or a bridge under the tunnel
 * have the devices they need. TCP, the kind carried into the tunnel's path
 * from a larger LAN; see the reject case for UDP. */
static void ip6tnl_out_fixture(void)
{
    vlan_fixture();
    tcp_flow();
    tunnel_devices();
    route.dst.dev = &ip6tnl;
    cls.nf_mtu = ip6tnl.mtu;
    tnl6_hop(&egress_tunnel, out.ifindex);
    tunnel_ethernet_dest(&ip6tnl);
    outer_neighbour(&out, AF_INET6);
}

static void ip6tnl_in_fixture(void)
{
    vlan_fixture();
    tunnel_devices();
    reverse_route.dst.dev = &in_ip6tnl;
    tnl6_hop(&ingress_tunnel, in.ifindex);
}

#define TUNNEL_REJECT(...) do { sit_out_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
#define TUNNEL_IN_REJECT(...) do { sit_in_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
#define TUNNEL6_REJECT(...) do { ip6tnl_out_fixture(); __VA_ARGS__; \
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)

/* Declared with the device dependencies it belongs to; used here because a
 * tunnel device's events are the whole of its lifecycle. */
static void device_event(struct net_device *dev, unsigned long event, bool invalid);

static void test_tunnel(void)
{
    struct cdx_ft_rule decoded;
    const u16 push_one[] = { 100 };
    union nf_inet_addr expected;

    /* 6o4 egress. Everything about the hop reaches the rule, because nothing
     * else records it: no action describes the header and no selector
     * describes the one the reverse direction strips. */
    sit_out_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.present && !decoded.in_tunnel.present);
    assert(decoded.out_tunnel.mode == CDX_FT_TUNNEL_6O4);
    /* A LAN that still lets its hosts send 1500 bytes into a 1480-byte
     * tunnel keeps this direction in software, where the inner packet gets
     * its Packet Too Big instead of an outer fragmentation. */
    TUNNEL_REJECT(in.ip6_mtu = 1500);
    sit_out_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.family == AF_INET);
    assert(decoded.out_tunnel.proto == IPPROTO_IPV6);
    assert(decoded.out_tunnel.ttl == 64 && !decoded.out_tunnel.tos);
    assert(decoded.out_tunnel.flags == CDX_FT_TUNNEL_DF);
    assert(decoded.out_tunnel.header_size == 20);
    expected = v4(TNL4_LOCAL);
    assert(nf_inet_addr_cmp(&decoded.out_tunnel.local, &expected));
    expected = v4(TNL4_REMOTE);
    assert(nf_inet_addr_cmp(&decoded.out_tunnel.remote, &expected));
    expected = v4(TNL4_NEXTHOP);
    assert(nf_inet_addr_cmp(&decoded.out_tunnel.nexthop, &expected));
    assert(!memcmp(decoded.out_tunnel.mac, OUTER_MAC, ETH_ALEN));
    assert(decoded.out_tunnel.ifindex == sit.ifindex);
    assert(decoded.out_tunnel.lower_ifindex == out.ifindex);
    /* The destination is the outer next hop, not anything the tunnel device
     * resolved and not what the mangle words carry. */
    assert(!memcmp(decoded.dst_mac, OUTER_MAC, ETH_ALEN));
    assert(!memcmp(decoded.src_mac, out.dev_addr, ETH_ALEN));
    /* The hardware ports are unchanged; only the logical device moves, the
     * way a tag moves it. No encapsulation slot is spent. */
    assert(decoded.out_logical == &sit && decoded.out == &out && decoded.in == &in);
    assert(!decoded.out_vlans && !decoded.in_vlans);
    assert(!decoded.out_session.present && !decoded.in_session.present);
    /* The MTU is the tunnel device's, already reduced by the outer header;
     * putting the header back on is the backend's business, not this one's. */
    assert(decoded.mtu == 1480 && sit.mtu == 1480);

    /* 6o4 ingress. The rule is indistinguishable from an unencapsulated one,
     * so the devices are the whole of the evidence, and the egress side is
     * unaffected -- its destination still comes from its own neighbour. */
    sit_in_fixture();
    assert(rule.action.num_entries == 5);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in_tunnel.present && !decoded.out_tunnel.present);
    assert(decoded.in_tunnel.mode == CDX_FT_TUNNEL_6O4);
    assert(decoded.in_tunnel.header_size == 20);
    assert(decoded.in_tunnel.ifindex == in_sit.ifindex);
    assert(decoded.in_tunnel.lower_ifindex == in.ifindex);
    assert(decoded.in_logical == &in_sit && decoded.in == &in);
    assert(decoded.out_logical == &out && decoded.mtu == 1492);
    assert(!memcmp(decoded.dst_mac, neighbour.ha, ETH_ALEN));

    /* 4o6 egress: the other mode, the other family, and a flow label and hop
     * limit the IPv4 header has nowhere to put. */
    ip6tnl_out_fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.present && decoded.out_tunnel.mode == CDX_FT_TUNNEL_4O6);
    assert(decoded.out_tunnel.family == AF_INET6);
    assert(decoded.out_tunnel.proto == IPPROTO_IPIP);
    assert(decoded.out_tunnel.ttl == 63);
    assert(decoded.out_tunnel.flowlabel == htonl(0x12345));
    assert(decoded.out_tunnel.header_size == 40);
    expected = (union nf_inet_addr){ .in6 = tnl6_local() };
    assert(nf_inet_addr_cmp(&decoded.out_tunnel.local, &expected));
    expected = (union nf_inet_addr){ .in6 = tnl6_remote() };
    assert(nf_inet_addr_cmp(&decoded.out_tunnel.remote, &expected));
    expected = (union nf_inet_addr){ .in6 = tnl6_nexthop() };
    assert(nf_inet_addr_cmp(&decoded.out_tunnel.nexthop, &expected));
    assert(decoded.family == AF_INET && decoded.out_logical == &ip6tnl);
    assert(!memcmp(decoded.dst_mac, OUTER_MAC, ETH_ALEN));
    assert(decoded.mtu == 1452);
    /* A 1500-byte LAN into the 1452-byte tunnel: the microcode would
     * fragment a UDP packet without DF, so that direction stays in software,
     * while a TCP one is carried -- DF set, its segments clamped. */
    TUNNEL6_REJECT(udp_flow());

    /* 4o6 ingress, and the one per-tunnel property only this mode may carry:
     * the ip6tnl strip can copy the outer DSCP over the inner one. */
    ip6tnl_in_fixture();
    ingress_tunnel.flags = CDX_FT_TUNNEL_DSCP_COPY;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.in_tunnel.present && decoded.in_tunnel.mode == CDX_FT_TUNNEL_4O6);
    assert(decoded.in_tunnel.flags == CDX_FT_TUNNEL_DSCP_COPY);
    assert(decoded.in_tunnel.header_size == 40 && !decoded.out_tunnel.present);
    assert(decoded.in_logical == &in_ip6tnl);
    /* What arrives through it is what a full outer packet carries past its
     * 40-byte header -- a peer need not add the encapsulation limit the
     * device's own MTU allows for -- so UDP needs that much path. */
    ip6tnl_in_fixture(); cls.nf_mtu = 1460;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    ip6tnl_in_fixture(); cls.nf_mtu = 1459;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);

    /* The tunnel over a VLAN device. A tunnel is above every tag, so the
     * device the outer packet leaves by is walked exactly as it would be
     * without one: the tag is derived, the port is still the port, and the
     * outer neighbour belongs to the VLAN device. */
    ip6tnl_out_fixture();
    egress_tunnel.lower_ifindex = out_tag.ifindex;
    outer_neighbour(&out_tag, AF_INET6);
    encap_actions(0, push_one, ARRAY_SIZE(push_one));
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.present && decoded.out_vlans == 1);
    assert(decoded.out_vlan[0].id == 100 && decoded.out_vlan[0].ifindex == out_tag.ifindex);
    assert(decoded.out_tunnel.lower_ifindex == out_tag.ifindex);
    assert(decoded.out == &out && decoded.out_logical == &ip6tnl);
    assert(!memcmp(decoded.dst_mac, OUTER_MAC, ETH_ALEN));

    /* And over a bridge, where the device below the tunnel has no tag of its
     * own but does have a bridge hop the walk must still cross. */
    bridge_fixture();
    tcp_flow();
    tunnel_devices();
    route.dst.dev = &ip6tnl;
    cls.nf_mtu = ip6tnl.mtu;
    tnl6_hop(&egress_tunnel, br.ifindex);
    tunnel_ethernet_dest(&ip6tnl);
    outer_neighbour(&br, AF_INET6);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.present && decoded.out_bridge == &br);
    assert(!decoded.out_vlans && decoded.out == &out);

    /* And over a PPPoE session -- DS-Lite or 6rd on a PPPoE WAN -- which is
     * the one shape where the tunnel does not decide the destination: the
     * outer packet is still addressed to the concentrator, so the session's
     * address wins and the hop's own may be the zero one a ppp device's
     * neighbours carry. The Ethernet words are what a real kernel writes:
     * the route names the tunnel, so they carry the tunnel device's address,
     * exactly as for a tunnel over a port. Zero words, which the ppp device's
     * own neighbour would have given, describe a route that never named the
     * tunnel and are refused. */
    ip6tnl_out_fixture();
    egress_tunnel.lower_ifindex = ppp.ifindex;
    memset(egress_tunnel.h_dest, 0, ETH_ALEN);
    egress_session = (struct nf_flow_session){ .lower_ifindex = out.ifindex,
                                               .id = SESSION_ID };
    memcpy(egress_session.h_dest, AC_MAC, ETH_ALEN);
    tunnel_ethernet_dest(&ip6tnl);
    session_push(SESSION_ID);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.present && decoded.out_session.present);
    assert(decoded.out_tunnel.lower_ifindex == ppp.ifindex);
    assert(decoded.out_session.lower_ifindex == out.ifindex);
    assert(!memcmp(decoded.dst_mac, AC_MAC, ETH_ALEN));
    assert(decoded.out == &out && decoded.out_logical == &ip6tnl);
    zero_ethernet_dest();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);

    /* Every way the hop can fail to describe something the hardware could
     * reproduce. */
    TUNNEL_REJECT(egress_tunnel.lower_ifindex = 0);        /* device named none */
    TUNNEL_REJECT(egress_tunnel.lower_ifindex = 9999);     /* named one that is gone */
    TUNNEL_REJECT(egress_tunnel.lower_ifindex = sit.ifindex); /* named itself */
    /* A TTL of zero means the inner packet's, and the insert writes the
     * header it is given. Both sides are zeroed so the guard that names it is
     * the one that declines, not the cross-check against the device. */
    TUNNEL_REJECT(egress_tunnel.ttl = 0; sit_priv.parms.iph.ttl = 0);
    /* An inherited TOS has a flag in the ip6tnl insert and none in the sit
     * one, and DSCP propagation on receive likewise. */
    TUNNEL_REJECT(egress_tunnel.flags |= CDX_FT_TUNNEL_INHERIT_TOS);
    TUNNEL_REJECT(egress_tunnel.flags |= CDX_FT_TUNNEL_DSCP_COPY);
    /* The hop must describe the header the device would build. */
    TUNNEL_REJECT(egress_tunnel.family = AF_INET6);
    TUNNEL_REJECT(egress_tunnel.proto = IPPROTO_IPIP);
    TUNNEL_REJECT(egress_tunnel.ttl = 63);
    TUNNEL_REJECT(sit_priv.parms.iph.ttl = 63);
    TUNNEL_REJECT(sit_priv.parms.iph.tos = 4);
    TUNNEL_REJECT(egress_tunnel.tos = 4);
    /* Endpoints, each way round, and the two "not configured at all" cases a
     * tunnel with no fixed remote or no chosen local produces. */
    TUNNEL_REJECT(egress_tunnel.daddr = v4(htonl(0xcb0071c9)));
    TUNNEL_REJECT(sit_priv.parms.iph.daddr = htonl(0xcb0071c9));
    TUNNEL_REJECT(sit_priv.parms.iph.daddr = 0);
    TUNNEL_REJECT(egress_tunnel.saddr = v4(htonl(0xc0a80a02)));
    TUNNEL_REJECT(egress_tunnel.saddr = v4(0));
    /* A remote that is not a single host is not a tunnel endpoint. */
    TUNNEL_REJECT(egress_tunnel.daddr = v4(htonl(0xe0000001));
                  sit_priv.parms.iph.daddr = htonl(0xe0000001));
    TUNNEL_REJECT(egress_tunnel.daddr = v4(htonl(0xffffffff));
                  sit_priv.parms.iph.daddr = htonl(0xffffffff));
    /* A device that is neither kind, which is every other upper device. */
    TUNNEL_REJECT(sit.type = ARPHRD_ETHER);
    /* The flow's family has to be the one the mode carries inside: an IPv4
     * flow through a sit device is IPv4 in IPv4 and an IPv6 one through an
     * ip6tnl device is IPv6 in IPv6, neither of which the hardware builds. */
    vlan_fixture();
    /* Each flow fits its path otherwise -- TCP, and a LAN advertising the
     * tunnel's IPv6 MTU -- so the family is the only thing wrong with either. */
    tcp_flow();
    tunnel_devices();
    route.dst.dev = &sit;
    cls.nf_mtu = sit.mtu;
    tnl4_hop(&egress_tunnel, out.ifindex);
    tunnel_ethernet_dest(&sit);
    outer_neighbour(&out, AF_INET);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    fixture6();
    tunnel_devices();
    route6.dst.dev = &ip6tnl;
    cls.nf_mtu = in.ip6_mtu = ip6tnl.mtu;
    tnl6_hop(&egress_tunnel, out.ifindex);
    tunnel_ethernet_dest(&ip6tnl);
    outer_neighbour(&out, AF_INET6);
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    /* The Ethernet destination must be exactly what the tunnel device's own
     * neighbours carry. Zero is what a ppp device leaves and would mean this
     * tunnel has no local address; anything else means a kernel resolved
     * something here, which must not be silently overridden. */
    TUNNEL_REJECT(zero_ethernet_dest());
    TUNNEL_REJECT(ethernet_dest(neighbour.ha));
    TUNNEL_REJECT(ethernet_dest(OUTER_MAC));
    /* Truncation counts: a sixteen-byte address padded to six is not the same
     * six bytes as a four-byte one. */
    TUNNEL_REJECT(tunnel_ethernet_dest(&ip6tnl));
    /* The device below the tunnel may not override the port's address: the
     * hardware emits the port's and software would emit the override. */
    TUNNEL6_REJECT(egress_tunnel.lower_ifindex = out_tag.ifindex;
                   outer_neighbour(&out_tag, AF_INET6);
                   out_tag.dev_addr[5]++;
                   encap_actions(0, push_one, ARRAY_SIZE(push_one)));
    ether_addr_copy(out_tag.dev_addr, out.dev_addr);
    /* A tunnel the kernel's walk crossed but this one did not reach: the
     * hardware would be asked to forward with no outer header at all. */
    TUNNEL_REJECT(route6.dst.dev = &out; ethernet_dest(neighbour.ha));
    TUNNEL_IN_REJECT(reverse_route6.dst.dev = &in);
    TUNNEL_REJECT(cls.nf_tunnel = NULL);
    TUNNEL_IN_REJECT(cls.nf_tunnel_reverse = NULL);
    /* A tunnel inside a transform, or a transform inside a tunnel, is a
     * header order nothing in this contract proves. */
    TUNNEL_REJECT(xfrm_policies = true; ipsec_sa = 7);
    TUNNEL_REJECT(xfrm_policies = true; ipsec_in_sa = 8);
    TUNNEL_IN_REJECT(xfrm_policies = true; ipsec_sa = 7);
    /* The outer neighbour is checked exactly as a routed flow's own is. */
    TUNNEL_REJECT(gateway.nud_state = NUD_FAILED);
    TUNNEL_REJECT(gateway.dev = &in);
    TUNNEL_REJECT(neigh_ok = false);
    /* Except that its address is the one the walk recorded when the flow was
     * created, which no later offer of the generation refreshes: a usable
     * neighbour that has moved is stale, like a changed source address. */
    sit_out_fixture(); gateway.ha[5]++;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -ESTALE);
    sit_out_fixture(); gateway.ha[5]++; gateway.nud_state = NUD_FAILED;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    /* An ip6tnl device carries its own set of cross-checks. */
    TUNNEL6_REJECT(ip6tnl_priv.parms.laddr = addr6(TNL6_PREFIX, 3));
    TUNNEL6_REJECT(ip6tnl_priv.parms.raddr = addr6(TNL6_PREFIX, 4));
    TUNNEL6_REJECT(egress_tunnel.saddr.in6 = addr6(TNL6_PREFIX, 5));
    TUNNEL6_REJECT(egress_tunnel.daddr.in6 = addr6(TNL6_PREFIX, 6));
    TUNNEL6_REJECT(ip6tnl_priv.parms.hop_limit = 64);
    TUNNEL6_REJECT(egress_tunnel.ttl = 64);
    /* A device carrying anything but IPv4 is not in ipip6 mode. */
    TUNNEL6_REJECT(ip6tnl_priv.parms.proto = IPPROTO_IPV6);
    TUNNEL6_REJECT(egress_tunnel.proto = IPPROTO_IPV6);
    /* The inherited traffic class has to agree with the device, both ways. */
    TUNNEL6_REJECT(ip6tnl_priv.parms.flags = IP6_TNL_F_USE_ORIG_TCLASS);
    TUNNEL6_REJECT(egress_tunnel.flags |= CDX_FT_TUNNEL_INHERIT_TOS);
    /* A multicast outer destination is not a tunnel endpoint here either. */
    TUNNEL6_REJECT(ip6tnl_priv.parms.raddr = addr6(0xff020000, 1);
                   egress_tunnel.daddr.in6 = addr6(0xff020000, 1));
    /* And the pair the device does accept: "any" as the payload protocol is
     * ipip6 as far as an IPv4 flow is concerned. */
    ip6tnl_out_fixture();
    ip6tnl_priv.parms.proto = 0;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.mode == CDX_FT_TUNNEL_4O6);
    /* As is an inherited class named on both sides at once. */
    ip6tnl_out_fixture();
    ip6tnl_priv.parms.flags = IP6_TNL_F_USE_ORIG_TCLASS;
    egress_tunnel.flags |= CDX_FT_TUNNEL_INHERIT_TOS;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(decoded.out_tunnel.flags & CDX_FT_TUNNEL_INHERIT_TOS);

    /* Lifecycle. A tunnel egress holds a neighbour, but not one of its own:
     * the outer next hop's, on the device below. */
    sit_out_fixture();
    u64 links = ft_link_invalidations;
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    struct cdx_ft_entry *entry = ft_find(&binding, cls.cookie);
    assert(entry && entry->neigh == &gateway && ft_neighbour_refs == 1);
    assert(gateway.refs == 1 && !neighbour.refs);
    /* The tunnel device is pinned like any other logical device; the ingress
     * port is its own logical device here and so is never held twice. */
    assert(sit.refs == 1 && out.refs == 1 && !in.refs);
    /* `ip tunnel change` rewrites the endpoints in place and raises only
     * NETDEV_CHANGE, on a device that is running with carrier: every flow
     * through it was admitted against the old parameters and has to go. */
    device_event(&sit, NETDEV_CHANGE, false);
    assert(handle.invalid && ft_link_invalidations == links + 1);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !sit.refs && !out.refs && !allocated && !ft_neighbour_refs);

    /* Unregistration retires the flows through the tunnel and nothing else:
     * a tunnel device is never a port and never bound, so the bindings stay
     * up. The binding list is populated for this, because an empty one would
     * make the answer trivially the same either way -- and the same event on
     * the egress port, which the entry uses just as much, shows the
     * difference. */
    sit_out_fixture();
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    list_add_tail(&binding.list, &ft_bindings);
    links = ft_link_invalidations;
    device_event(&sit, NETDEV_UNREGISTER, false);
    assert(handle.invalid && ft_link_invalidations == links + 1);
    device_event(&out, NETDEV_UNREGISTER, true);
    list_del(&binding.list);
    ft_invalid = 0;
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !sit.refs && !out.refs && !allocated && !ft_neighbour_refs);

    /* The outer route is a dependency of its own, in the outer header's
     * family rather than the flow's: nothing borrowed from an IPv6 flow
     * watches an IPv4 route, and the inner destination stays on the tunnel
     * device whatever the outer route does. */
    sit_out_fixture();
    struct netevent_ipv4_route v4route = { .net = &init_net, .prefixlen = 32 };
    u64 routes = ft_route_invalidations;
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    v4route.dst = htonl(0xcb0071c9);
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &v4route);
    assert(!handle.invalid && ft_route_invalidations == routes);
    v4route.dst = TNL4_REMOTE;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &v4route);
    assert(handle.invalid && ft_route_invalidations == routes + 1);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !allocated && !ft_neighbour_refs);

    /* And the mirror: a 4o6 tunnel's outer route is IPv6 while the flow is
     * IPv4, so the v6 watch has to reach an entry it would otherwise skip. */
    ip6tnl_out_fixture();
    struct netevent_ipv6_route v6route = { .net = &init_net, .prefixlen = 128 };
    routes = ft_route_invalidations;
    cdx_ft_begin();
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    cdx_ft_end();
    v6route.dst = addr6(TNL6_PREFIX, 9);
    ft_neigh_event(NULL, NETEVENT_IPV6_ROUTE_UPDATE, &v6route);
    assert(!handle.invalid && ft_route_invalidations == routes);
    v6route.dst = tnl6_remote();
    ft_neigh_event(NULL, NETEVENT_IPV6_ROUTE_UPDATE, &v6route);
    assert(handle.invalid && ft_route_invalidations == routes + 1);
    ft_retire_workfn(NULL);
    drop_dev_records();
    assert(!ft_count && !allocated && !ft_neighbour_refs && !ip6tnl.refs);
}

/* The tunnel device records: one plain record per tunnel device, held for the
 * device's life rather than the flow's, with the strip counting into its
 * receive half and the insert into its transmit half -- the two halves
 * describing the tunnel between them, as a session's do. */
static unsigned tunnel_record_count(void)
{
    struct cdx_ft_dev_stats *record;
    unsigned n = 0;

    list_for_each_entry(record, &ft_dev_stats, list)
        n += record->tunnel.present;
    return n;
}

static void test_tunnel_stats(void)
{
    struct cdx_ft_entry *first, *second;
    struct cdx_ft_dev_stats *record;
    struct cdx_ft_stats_slot *slot;

    cdx_ft_begin();
    assert(!plain_in_use() && !dev_record_count());

    /* First admission claims the tunnel device's record from the plain pool,
     * publishes it to that device, and hands the encoder the transmit half's
     * index -- never zero, which is somebody else's. */
    sit_out_fixture();
    cls.cookie = 70;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 70);
    assert(first && first->out_tunnel_stats && !first->in_tunnel_stats);
    record = first->out_tunnel_stats;
    assert(record == dev_record(sit.ifindex) && record->kind == CDX_FT_STATS_PLAIN);
    assert(record->refs == 1 && record->slot && record->slot->kind == CDX_FT_STATS_PLAIN);
    assert(record->slot->published_ifindex == sit.ifindex);
    /* The identity the flow rows carry, so a record and a flow can be joined,
     * and what tells a tunnel device's record from a VLAN device's. */
    assert(record->tunnel.present && record->tunnel.ifindex == sit.ifindex);
    assert(record->tunnel.mode == CDX_FT_TUNNEL_6O4);
    assert(record->tunnel.lower_ifindex == out.ifindex);
    assert(tunnel_record_count() == 1 && dev_record_count() == 1);
    /* The strip counts the frame as it arrived less the outer header it
     * removed, so the framing to take off is the Ethernet header and whatever
     * tag or session sits under the tunnel -- none here; the insert counts
     * the outer packet with the Ethernet header still in it, so the framing
     * is that header plus the outer one. The device itself counts the inner
     * packet alone on both sides. */
    assert(record->slot->published_rx_overhead == ETH_HLEN);
    assert(record->slot->published_tx_overhead == ETH_HLEN + 20);
    assert(ft_tunnel_under(0, false) == 0 &&
           ft_tunnel_under(1, false) == VLAN_HLEN &&
           ft_tunnel_under(0, true) == PPPOE_SES_HLEN);
    assert(observed_out_tunnel == record->slot->tx_index && !observed_in_tunnel);
    assert(!(record->slot->tx_index & STATS_WITH_TS));
    assert(plain_in_use() == 1 && !stats_in_use());

    /* The other direction of the same connection strips what this one
     * inserts, so it finds the same record and counts into its other half.
     * The harness binds one port, so the reverse direction is offered against
     * that same binding with the tunnel on its ingress side; what is under
     * test is that one device's record serves a strip and an insert. */
    cls.cookie = 71;
    pk.src = htons(10001);
    route6.dst.dev = &out;
    reverse_route6.dst.dev = &sit;
    ethernet_dest(neighbour.ha);
    egress_tunnel = (struct nf_flow_tunnel){};
    tnl4_hop(&ingress_tunnel, in.ifindex);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 2);
    second = ft_find(&binding, 71);
    assert(second && second->in_tunnel_stats == record && !second->out_tunnel_stats);
    assert(record->refs == 2 && plain_in_use() == 1 && tunnel_record_count() == 1);
    assert(observed_in_tunnel == record->slot->rx_index && !observed_out_tunnel);
    assert(record->slot->rx_index != record->slot->tx_index);
    /* The row follows the newest direction admitted, as a session's does. */
    assert(record->tunnel.lower_ifindex == in.ifindex);

    /* The record outlives its flows: retiring them returns the references and
     * nothing else, so the device's totals survive the connections going
     * idle. */
    slot = record->slot;
    assert(ft_remove(first) == 0 && ft_remove(second) == 0 && !ft_count);
    assert(!record->refs && !record->gone && record->slot == slot);
    assert(dev_record(sit.ifindex) == record && plain_in_use() == 1);

    /* Only the device going frees it. */
    cdx_ft_end();
    dev_stats_scheduled = 0;
    device_unregistered(&sit);
    assert(dev_stats_scheduled == 1);
    ft_dev_stats_reap(NULL);
    cdx_ft_begin();
    assert(!dev_record_count() && !plain_in_use());
    cdx_ft_end();

    /* A tag under the tunnel stays in what the strip counts, so the device's
     * receive framing grows by it -- and the tag's own record sits alongside,
     * one plain record each. */
    ip6tnl_in_fixture();
    ingress_tunnel.lower_ifindex = in_tag.ifindex;
    encap_actions(1, NULL, 0);
    encap_keys((const u16[]){ 200 }, 1);
    cdx_ft_begin();
    cls.cookie = 72;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 72);
    record = first->in_tunnel_stats;
    assert(record && record->ifindex == in_ip6tnl.ifindex && record->tunnel.present);
    assert(record->slot->published_rx_overhead == ETH_HLEN + VLAN_HLEN);
    /* The transmit framing this record is published with is deliberately not
     * pinned here: a direction that only strips derives it from a half it
     * does not feed, and the two directions of one connection disagree about
     * it. See the note in the report. */
    assert(observed_in_tunnel == record->slot->rx_index);
    assert(first->in_vlan_stats[0] && first->in_vlan_stats[0]->ifindex == in_tag.ifindex);
    assert(!first->in_vlan_stats[0]->tunnel.present);
    assert(tunnel_record_count() == 1 && dev_record_count() == 2 && plain_in_use() == 2);
    /* And the frame the classifier counted, restated in Netfilter's units:
     * the outer header comes off before the inner packet exists, so it is
     * framing here exactly as the Ethernet header and the tag are. */
    assert(ft_l2_overhead(&first->rule) == ETH_HLEN + VLAN_HLEN + 40);
    first->hw->stats = (struct cdx_ft_counters){ .packets = 10, .bytes = 6000 };
    cls.command = FLOW_CLS_STATS;
    assert(ft_stats(first, &cls) == 0);
    assert(cls.stats.pkts == 10 &&
           cls.stats.bytes == 6000 - 10 * (ETH_HLEN + VLAN_HLEN + 40));
    cls.command = FLOW_CLS_REPLACE;
    assert(ft_remove(first) == 0 && !ft_count);
    cdx_ft_end();
    drop_dev_records();

    /* A session under the tunnel counts the same way, one layer further in:
     * its header is still on the frame the strip counted. */
    ip6tnl_in_fixture();
    ingress_tunnel.lower_ifindex = in_ppp.ifindex;
    memset(ingress_tunnel.h_dest, 0, ETH_ALEN);
    ingress_session = (struct nf_flow_session){ .lower_ifindex = in.ifindex,
                                                .id = SESSION_ID + 1 };
    memcpy(ingress_session.h_dest, AC_MAC, ETH_ALEN);
    cdx_ft_begin();
    cls.cookie = 73;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 73);
    record = first->in_tunnel_stats;
    assert(record && record->ifindex == in_ip6tnl.ifindex);
    assert(record->slot->published_rx_overhead == ETH_HLEN + PPPOE_SES_HLEN);
    /* The session's own record is the timestamped one, on the ppp device the
     * tunnel named as its lower rather than on the tunnel device. */
    assert(first->in_stats && first->in_stats->ifindex == in_ppp.ifindex);
    assert(first->in_stats->kind == CDX_FT_STATS_TIMESTAMPED);
    assert(!first->in_stats->tunnel.present);
    assert(ft_l2_overhead(&first->rule) == ETH_HLEN + PPPOE_SES_HLEN + 40);
    assert(ft_remove(first) == 0 && !ft_count);
    cdx_ft_end();
    drop_dev_records();

    /* The pool empty: the record exists and says so, the encoder is told
     * there is none, and the flow installs and forwards regardless. */
    sit_out_fixture();
    cdx_ft_begin();
    stats_alloc_fail = -ENOSPC;
    cls.cookie = 74;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    stats_alloc_fail = 0;
    first = ft_find(&binding, 74);
    record = first->out_tunnel_stats;
    assert(record && !record->slot && record->refs == 1 && !observed_out_tunnel);
    assert(tunnel_record_count() == 1 && !plain_in_use());
    assert(ft_remove(first) == 0 && !ft_count);
    cdx_ft_end();
    drop_dev_records();

    /* And a flow with no tunnel claims none of this. */
    fixture();
    cdx_ft_begin();
    cls.cookie = 75;
    assert(ft_replace(&binding, &cls) == 0);
    assert(!tunnel_record_count() && !dev_record_count());
    assert(!observed_in_tunnel && !observed_out_tunnel);
    assert(ft_remove(ft_find(&binding, 75)) == 0 && !ft_count);
    cdx_ft_end();
}

/* The VLAN device records: one per device the tags of a flow belong to, held
 * for the device's life rather than the flow's, published to the device in
 * the units its own counters use. */
static void test_vlan_stats(void)
{
    struct cdx_ft_entry *first, *second;
    struct cdx_ft_dev_stats *record, *outer, *inner;
    struct cdx_ft_stats_slot *slot;

    /* One egress tag, on eth3.100 over the egress port. The direction inserts,
     * so it names the record's transmit half; nothing is stripped, so the
     * ingress side names nothing. The record is published to the VLAN device
     * with the framing a first-position tag implies. */
    egress_tag_fixture();
    cdx_ft_begin();
    cls.cookie = 50;
    cls.stats = (struct flow_stats){0};
    assert(!plain_in_use() && !dev_record_count());
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 50);
    assert(first && first->out_vlan_stats[0] && !first->out_vlan_stats[1]);
    assert(!first->in_vlan_stats[0] && !first->in_stats && !first->out_stats);
    record = first->out_vlan_stats[0];
    assert(record == dev_record(out_tag.ifindex) && record->refs == 1 && !record->gone);
    assert(record->slot && record->slot->kind == CDX_FT_STATS_PLAIN);
    assert(record->slot->published_ifindex == out_tag.ifindex);
    /* The firmware counts a device's record with the device's own tag already
     * handled; the device counts both ways without its own tag, so the
     * framing to take off is the Ethernet header on receive and the tag on
     * transmit -- the adapter's own constants, read off the source. */
    assert(record->slot->published_rx_overhead == FT_VLAN_RX_OVERHEAD);
    assert(record->slot->published_tx_overhead == FT_VLAN_TX_OVERHEAD);
    assert(FT_VLAN_RX_OVERHEAD == ETH_HLEN && FT_VLAN_TX_OVERHEAD == VLAN_HLEN);
    assert(observed_out_vlan[0] == record->slot->tx_index && !observed_out_vlan[1]);
    assert(!observed_in_vlan[0] && !observed_in_stats && !observed_out_stats);
    assert(plain_in_use() == 1 && dev_record_count() == 1 && !stats_in_use());

    /* A second connection through the same device shares the record. */
    cls.cookie = 51;
    pk.src = htons(10001);
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 2);
    second = ft_find(&binding, 51);
    assert(second && second->out_vlan_stats[0] == record && record->refs == 2);
    assert(plain_in_use() == 1 && dev_record_count() == 1);
    assert(observed_out_vlan[0] == record->slot->tx_index);

    /* Both retire; the device is still here, so its record and its slot stay,
     * totals intact. The next flow through it finds the same record. */
    slot = record->slot;
    assert(ft_remove(first) == 0 && ft_remove(second) == 0 && !ft_count);
    assert(record->refs == 0 && !record->gone);
    assert(dev_record(out_tag.ifindex) == record && record->slot == slot);
    assert(plain_in_use() == 1 && dev_record_count() == 1);
    cls.cookie = 52;
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 52);
    assert(first->out_vlan_stats[0] == record && record->refs == 1 && record->slot == slot);

    /* The device unregisters while a direction still names the record: it is
     * marked gone, kept until that direction retires, and freed by the
     * retirement. Nothing is queued for the reaper, which has nothing to do. */
    cdx_ft_end();
    dev_stats_scheduled = 0;
    device_unregistered(&out_tag);
    assert(!dev_stats_scheduled);
    cdx_ft_begin();
    assert(record->gone && record->refs == 1 && !dev_record(out_tag.ifindex));
    assert(dev_record_count() == 1 && plain_in_use() == 1);
    /* Its publication went with the device, not with the slot: the index may
     * be handed to a new device while this record waits on its direction. */
    assert(record->slot && !record->slot->published_ifindex);
    /* And a claim for the same index now starts a record of its own rather
     * than finding the gone one -- the index may belong to a new device. The
     * unregistration retired the flow's handle, so this claims directly, as
     * the install of a flow on the new device would. */
    {
        struct cdx_ft_dev_stats *fresh = ft_dev_stats_get(out_tag.ifindex,
                                                          CDX_FT_STATS_PLAIN, NULL, NULL,
                                                          FT_VLAN_RX_OVERHEAD,
                                                          FT_VLAN_TX_OVERHEAD);

        assert(fresh && fresh != record && !fresh->gone && fresh->refs == 1);
        assert(fresh->slot && fresh->slot != record->slot);
        assert(dev_record_count() == 2 && plain_in_use() == 2);
        ft_dev_stats_put(&fresh);
        assert(!fresh && dev_record(out_tag.ifindex) && dev_record_count() == 2);
    }
    /* The gone record goes with its last direction; the fresh one stays with
     * what it takes to be a live device. */
    assert(ft_remove(first) == 0 && !ft_count);
    assert(dev_record_count() == 1 && plain_in_use() == 1 && dev_record(out_tag.ifindex));

    /* The device unregisters with nothing naming its record: the reaper is
     * queued and frees it. */
    cdx_ft_end();
    device_unregistered(&out_tag);
    assert(dev_stats_scheduled == 1);
    ft_dev_stats_reap(NULL);
    cdx_ft_begin();
    assert(!dev_record_count() && !plain_in_use());
    /* An event for a device without a record queues nothing. */
    cdx_ft_end();
    device_unregistered(&out_tag);
    assert(dev_stats_scheduled == 1);

    /* One ingress tag: the direction strips, so it names the receive half,
     * and the record belongs to the ingress VLAN device. */
    ingress_tag_fixture();
    cdx_ft_begin();
    cls.cookie = 54;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 54);
    assert(first->in_vlan_stats[0] && !first->out_vlan_stats[0]);
    record = first->in_vlan_stats[0];
    assert(record == dev_record(in_tag.ifindex) && record->slot);
    assert(record->slot->published_ifindex == in_tag.ifindex);
    assert(record->slot->published_rx_overhead == FT_VLAN_RX_OVERHEAD);
    assert(observed_in_vlan[0] == record->slot->rx_index && !observed_out_vlan[0]);
    assert(record->slot->rx_index != record->slot->tx_index);
    assert(!(record->slot->rx_index & STATS_WITH_TS));
    assert(ft_remove(first) == 0 && !ft_count);
    assert(record->refs == 0 && dev_record_count() == 1);

    /* QinQ egress: two devices, two records, ordered like the rule's tags.
     * The outer tag is eth3.100's and comes first; the inner is
     * eth3.100.300's. Both are published with the same framing, because the
     * firmware hands each record the frame with that record's own tag
     * handled, whatever its depth. */
    cdx_ft_end();
    vlan_fixture();
    route.dst.dev = &out_qinq;
    neighbour.dev = &out_qinq;
    encap_actions(0, (const u16[]){ 100, 300 }, 2);
    cdx_ft_begin();
    cls.cookie = 55;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    first = ft_find(&binding, 55);
    outer = first->out_vlan_stats[0];
    inner = first->out_vlan_stats[1];
    assert(outer && inner && outer != inner);
    assert(outer->ifindex == out_tag.ifindex && inner->ifindex == out_qinq.ifindex);
    assert(outer->slot->published_rx_overhead == FT_VLAN_RX_OVERHEAD);
    assert(outer->slot->published_tx_overhead == FT_VLAN_TX_OVERHEAD);
    assert(inner->slot->published_rx_overhead == FT_VLAN_RX_OVERHEAD);
    assert(inner->slot->published_tx_overhead == FT_VLAN_TX_OVERHEAD);
    assert(observed_out_vlan[0] == outer->slot->tx_index);
    assert(observed_out_vlan[1] == inner->slot->tx_index);
    assert(plain_in_use() == 3 && dev_record_count() == 3);
    assert(ft_remove(first) == 0 && !ft_count);

    /* The pool empty: the record exists and says it has no slot, the encoder
     * is told there is none, and the flow installs regardless. Returning a
     * slot later does not retrofit one. The records the devices above still
     * hold are dropped first, or eth3.100's would simply be found again. */
    cdx_ft_end();
    drop_dev_records();
    egress_tag_fixture();
    cdx_ft_begin();
    stats_alloc_fail = -ENOSPC;
    cls.cookie = 56;
    cls.stats = (struct flow_stats){0};
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    stats_alloc_fail = 0;
    first = ft_find(&binding, 56);
    record = first->out_vlan_stats[0];
    assert(record && !record->slot && record->refs == 1 && !observed_out_vlan[0]);
    assert(!plain_in_use() && dev_record_count() == 1);
    assert(ft_remove(first) == 0);
    cls.cookie = 57;
    assert(ft_replace(&binding, &cls) == 0);
    assert(ft_find(&binding, 57)->out_vlan_stats[0] == record && !record->slot);
    assert(ft_remove(ft_find(&binding, 57)) == 0 && !ft_count);

    /* A hardware installation that fails releases the reference with
     * everything else. */
    cls.cookie = 58;
    hardware_fail = true;
    assert(ft_replace(&binding, &cls) == -EIO && !ft_count);
    hardware_fail = false;
    assert(record->refs == 0);

    /* Unload frees what the devices were holding, referenced by nothing. */
    cdx_ft_end();
    ft_dev_stats_drop_all();
    assert(!dev_record_count() && !plain_in_use());
    /* And a flow with no tags claims none of this. */
    fixture();
    cdx_ft_begin();
    cls.cookie = 59;
    assert(ft_replace(&binding, &cls) == 0);
    assert(!dev_record_count() && !plain_in_use());
    assert(!observed_in_vlan[0] && !observed_out_vlan[0]);
    assert(ft_remove(ft_find(&binding, 59)) == 0 && !ft_count);
    cdx_ft_end();
}

static void snat_fixture(bool forward, bool tcp)
{
    fixture();
    ct.status = IPS_SRC_NAT | IPS_SRC_NAT_DONE;
    if (tcp) {
        ct.protonum = bk.ip_proto = IPPROTO_TCP;
        ct.tcp_state = TCP_CONNTRACK_ESTABLISHED; ct.status |= IPS_ASSURED;
        dissector.used_keys |= BIT(FLOW_DISSECTOR_KEY_TCP);
        tk.flags = 0; tm.flags = htons(5);
        rule.tcp = (struct flow_match_tcp){ &tk, &tm };
    }
    ct.tuplehash[0].tuple = (struct nf_conntrack_tuple){
        .src = { .u3.ip = ik.src, .u.all = pk.src, .l3num = AF_INET },
        .dst = { .u3.ip = ik.dst, .u.all = pk.dst } };
    ct.tuplehash[1].tuple = (struct nf_conntrack_tuple){
        .src = { .u3.ip = ik.dst, .u.all = pk.dst, .l3num = AF_INET },
        .dst = { .u3.ip = htonl(0xcb007104), .u.all = htons(40000) } };
    rule.action.num_entries = 8;
    rule.action.entries[7] = rule.action.entries[4];
    rule.action.entries[4] = (struct flow_action_entry){ .id = FLOW_ACTION_MANGLE,
        .mangle = { .htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4, .offset = forward ? 12 : 16,
                    .val = forward ? htonl(0xcb007104) : htonl(0xc0000202) } };
    /* Independent wire bytes: source 40000 or destination 10000. */
    const u8 values[2][4] = {{0,0,0x27,0x10}, {0x9c,0x40,0,0}};
    const u8 masks[2][4] = {{0xff,0xff,0,0}, {0,0,0xff,0xff}};
    rule.action.entries[5] = (struct flow_action_entry){ .id = FLOW_ACTION_MANGLE,
        .mangle.htype = tcp ? FLOW_ACT_MANGLE_HDR_TYPE_TCP : FLOW_ACT_MANGLE_HDR_TYPE_UDP };
    memcpy(&rule.action.entries[5].mangle.val, values[forward], 4);
    memcpy(&rule.action.entries[5].mangle.mask, masks[forward], 4);
    rule.action.entries[6] = (struct flow_action_entry){ .id = FLOW_ACTION_CSUM, .csum_flags = tcp ? 9 : 17 };
    if (!forward) {
        ik = (struct ipv4_addrs){ htonl(0xc6336402), htonl(0xcb007104) };
        pk = (struct ports){ htons(20000), htons(40000) };
        neighbour.primary_key.ip = htonl(0xc0000202);
    }
}
static void test_snat(void)
{
    struct cdx_ft_rule decoded;
    struct nf_conn_nat nat = { .masq_index = 7 };
    for (unsigned variant = 0; variant < 4; variant++) {
        bool forward = variant & 1, tcp = variant & 2;
        snat_fixture(forward, tcp);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(is4(&decoded.src, ik.src) && is4(&decoded.dst, ik.dst));
        assert(is4(&decoded.new_src, htonl(forward ? 0xcb007104 : 0xc6336402)));
        assert(is4(&decoded.new_dst, htonl(forward ? 0xc6336402 : 0xc0000202)));
        assert(decoded.new_sport == htons(forward ? 40000 : 20000));
        assert(decoded.new_dport == htons(forward ? 20000 : 10000));
        assert(nf_inet_addr_cmp(&next_hop, &decoded.new_dst));
#define NAT_REJECT(change) do { snat_fixture(forward, tcp); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
        NAT_REJECT(ct.status = IPS_NAT_MASK | IPS_SRC_NAT_DONE);
        NAT_REJECT(ct.status = IPS_SRC_NAT);
        NAT_REJECT(ct.status = 0);
        /* MASQUERADE is a Linux-owned source mapping with the same native
         * actions. Its device/address teardown uses native conntrack GC. */
        snat_fixture(forward, tcp); ct.nat = &nat;
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        NAT_REJECT(ct.protonum = bk.ip_proto = IPPROTO_ICMP);
        NAT_REJECT(rule.action.entries[5].mangle.htype = tcp ? FLOW_ACT_MANGLE_HDR_TYPE_UDP : FLOW_ACT_MANGLE_HDR_TYPE_TCP);
        NAT_REJECT(rule.action.entries[6].csum_flags = tcp ? 17 : 9);
        if (tcp) {
            NAT_REJECT(ct.status &= ~IPS_ASSURED);
            NAT_REJECT(ct.tcp_state = 0);
            NAT_REJECT(tk.flags = htons(TCPHDR_FIN));
            NAT_REJECT(tm.flags = 0);
        }
        NAT_REJECT(ik.src ^= htonl(1)); NAT_REJECT(pk.dst ^= htons(1));
        NAT_REJECT(ct.tuplehash[0].tuple.dst.u3.ip ^= htonl(1));
        NAT_REJECT(ct.tuplehash[0].tuple.dst.u.all ^= htons(1));
        NAT_REJECT(rule.action.num_entries = 5); NAT_REJECT(rule.action.num_entries = 9);
        NAT_REJECT(rule.action.entries[4].mangle.offset ^= 4);
        NAT_REJECT(rule.action.entries[4].mangle.mask = 1);
        NAT_REJECT(rule.action.entries[4].mangle.val ^= htonl(1));
        NAT_REJECT(rule.action.entries[4].mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_ETH);
        NAT_REJECT(rule.action.entries[5].mangle.offset = 2);
        NAT_REJECT(rule.action.entries[5].mangle.mask ^= htonl(1));
        NAT_REJECT(rule.action.entries[5].mangle.val ^= htonl(1));
        NAT_REJECT(rule.action.entries[5].mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4);
        NAT_REJECT(rule.action.entries[6].id = FLOW_ACTION_REDIRECT);
        NAT_REJECT(rule.action.entries[6].csum_flags = 1);
        NAT_REJECT(rule.action.entries[7].id = FLOW_ACTION_CSUM);
        NAT_REJECT(ct.tuplehash[forward ? 1 : 0].tuple.dst.u3.ip = 0);
#undef NAT_REJECT
        /* Native SNAT emits both edits even when address or port is unchanged.
         * Validate those identity edits without inventing another action shape. */
        snat_fixture(forward, tcp);
        ct.tuplehash[1].tuple.dst.u3.ip = ct.tuplehash[0].tuple.src.u3.ip;
        if (!forward) ik.dst = ct.tuplehash[1].tuple.dst.u3.ip;
        rule.action.entries[4].mangle.val = htonl(0xc0000202);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(nf_inet_addr_cmp(&decoded.src, &decoded.new_src) && nf_inet_addr_cmp(&decoded.dst, &decoded.new_dst));
        snat_fixture(forward, tcp);
        ct.tuplehash[1].tuple.dst.u.all = ct.tuplehash[0].tuple.src.u.all;
        if (!forward) pk.dst = htons(10000);
        rule.action.entries[5].mangle.val = forward ? htonl(10000U << 16) : htonl(10000);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(decoded.sport == decoded.new_sport && decoded.dport == decoded.new_dport);
        snat_fixture(forward, tcp);
        for (unsigned stage = 1; stage <= 3; stage++) {
            ft_fail_stage = stage; assert(ft_replace(&binding, &cls) < 0);
            assert(!ft_fail_stage && !ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
        }
        assert(ft_replace(&binding, &cls) == 0);
        /* An unrelated translated-address prefix is not a routed endpoint.
         * The client route must retire even a lone reply direction. */
        struct netevent_ipv4_route event = { &init_net, htonl(0xcb007104), 32 };
        ft_route_event(&event); assert(!handle.invalid);
        event.dst = htonl(0xc0000202);
        ft_route_event(&event); assert(handle.invalid && !ft_invalid);
        ft_retire_workfn(NULL);
        assert(!ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
    }
}
static void dnat_fixture(bool forward, bool tcp)
{
    snat_fixture(forward, tcp);
    ct.status = (ct.status & ~(IPS_SRC_NAT | IPS_SRC_NAT_DONE)) | IPS_DST_NAT | IPS_DST_NAT_DONE;
    for (unsigned i = 0; i < 2; i++) {
        struct nf_conntrack_tuple *t = &ct.tuplehash[i].tuple;
        __be32 address = t->src.u3.ip; t->src.u3.ip = t->dst.u3.ip; t->dst.u3.ip = address;
        __be16 port = t->src.u.all; t->src.u.all = t->dst.u.all; t->dst.u.all = port;
    }
    __be32 address = ik.src; ik.src = ik.dst; ik.dst = address;
    __be16 port = pk.src; pk.src = pk.dst; pk.dst = port;
    rule.action.entries[4].mangle.offset = forward ? 16 : 12;
    const u8 values[2][4] = {{0x27,0x10,0,0}, {0,0,0x9c,0x40}};
    const u8 masks[2][4] = {{0,0,0xff,0xff}, {0xff,0xff,0,0}};
    memcpy(&rule.action.entries[5].mangle.val, values[forward], 4);
    memcpy(&rule.action.entries[5].mangle.mask, masks[forward], 4);
    neighbour.primary_key.ip = htonl(forward ? 0xcb007104 : 0xc6336402);
}
static void test_dnat(void)
{
    struct cdx_ft_rule decoded;
    for (unsigned variant = 0; variant < 4; variant++) {
        bool forward = variant & 1, tcp = variant & 2;
        dnat_fixture(forward, tcp);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(is4(&decoded.src, ik.src) && is4(&decoded.dst, ik.dst));
        assert(is4(&decoded.new_src, htonl(forward ? 0xc6336402 : 0xc0000202)));
        assert(is4(&decoded.new_dst, htonl(forward ? 0xcb007104 : 0xc6336402)));
        assert(decoded.new_sport == htons(forward ? 20000 : 10000));
        assert(decoded.new_dport == htons(forward ? 40000 : 20000));
        assert(nf_inet_addr_cmp(&next_hop, &decoded.new_dst));
#define DNAT_REJECT(change) do { dnat_fixture(forward, tcp); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
        DNAT_REJECT(ct.status &= ~IPS_DST_NAT_DONE);
        DNAT_REJECT(ct.status |= IPS_SRC_NAT | IPS_SRC_NAT_DONE);
        DNAT_REJECT(ct.tuplehash[0].tuple.src.u3.ip ^= htonl(1));
        DNAT_REJECT(ct.tuplehash[0].tuple.src.u.all ^= htons(1));
        DNAT_REJECT(rule.action.entries[4].mangle.offset ^= 4);
        DNAT_REJECT(rule.action.entries[4].mangle.val ^= htonl(1));
        DNAT_REJECT(rule.action.entries[5].mangle.mask ^= htonl(1));
        DNAT_REJECT(rule.action.entries[5].mangle.val ^= htonl(1));
        DNAT_REJECT(rule.action.entries[6].csum_flags = tcp ? 17 : 9);
#undef DNAT_REJECT
        dnat_fixture(forward, tcp);
        for (unsigned stage = 1; stage <= 3; stage++) {
            ft_fail_stage = stage; assert(ft_replace(&binding, &cls) < 0);
            assert(!ft_fail_stage && !ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
        }
        assert(ft_replace(&binding, &cls) == 0);
        struct netevent_ipv4_route event = { &init_net, htonl(0xcb007104), 32 };
        ft_route_event(&event); assert(handle.invalid);
        ft_retire_workfn(NULL);
        assert(!ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
    }
}
static void double_nat_fixture(bool forward, bool tcp, bool hairpin)
{
    snat_fixture(forward, tcp);
    ct.status |= IPS_DST_NAT | IPS_DST_NAT_DONE;
    /* Original 192.0.2.2:10000 -> 198.51.100.2:20000 becomes
     * 203.0.113.4:40000 -> 203.0.113.5:30000. */
    ct.tuplehash[1].tuple.src.u3.ip = htonl(0xcb007105);
    ct.tuplehash[1].tuple.src.u.all = htons(30000);
    if (!forward) { ik.src = htonl(0xcb007105); pk.src = htons(30000); }
    rule.action.num_entries = 10;
    rule.action.entries[9] = rule.action.entries[7];
    rule.action.entries[8] = rule.action.entries[6];
    rule.action.entries[6] = (struct flow_action_entry){ .id = FLOW_ACTION_MANGLE,
        .mangle = { .htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4, .offset = forward ? 16 : 12,
                    .val = forward ? htonl(0xcb007105) : htonl(0xc6336402) } };
    const u8 values[2][4] = {{0x4e,0x20,0,0}, {0,0,0x75,0x30}};
    const u8 masks[2][4] = {{0,0,0xff,0xff}, {0xff,0xff,0,0}};
    rule.action.entries[7] = (struct flow_action_entry){ .id = FLOW_ACTION_MANGLE,
        .mangle.htype = tcp ? FLOW_ACT_MANGLE_HDR_TYPE_TCP : FLOW_ACT_MANGLE_HDR_TYPE_UDP };
    memcpy(&rule.action.entries[7].mangle.val, values[forward], 4);
    memcpy(&rule.action.entries[7].mangle.mask, masks[forward], 4);
    neighbour.primary_key.ip = htonl(forward ? 0xcb007105 : 0xc0000202);
    if (hairpin) {
        rule.action.entries[9].dev = &in;
        route.dst.dev = neighbour.dev = &in;
        memcpy(&rule.action.entries[1].mangle.val, (u8[]){0,0,0,1}, 4);
    }
}
static void test_double_nat(void)
{
    struct cdx_ft_rule decoded;
    for (unsigned variant = 0; variant < 8; variant++) {
        bool forward = variant & 1, tcp = variant & 2, hairpin = variant & 4;
        double_nat_fixture(forward, tcp, hairpin);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(is4(&decoded.src, ik.src) && is4(&decoded.dst, ik.dst));
        assert(is4(&decoded.new_src, htonl(forward ? 0xcb007104 : 0xc6336402)));
        assert(is4(&decoded.new_dst, htonl(forward ? 0xcb007105 : 0xc0000202)));
        assert(decoded.new_sport == htons(forward ? 40000 : 20000));
        assert(decoded.new_dport == htons(forward ? 30000 : 10000));
        assert(nf_inet_addr_cmp(&next_hop, &decoded.new_dst) && decoded.in == &in);
        assert(decoded.out == (hairpin ? &in : &out));
#define DOUBLE_REJECT(change) do { double_nat_fixture(forward, tcp, hairpin); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
        DOUBLE_REJECT(ct.status &= ~IPS_SRC_NAT_DONE);
        DOUBLE_REJECT(ct.status &= ~IPS_DST_NAT_DONE);
        DOUBLE_REJECT(ct.status &= ~IPS_SRC_NAT);
        DOUBLE_REJECT(ct.status &= ~IPS_DST_NAT);
        DOUBLE_REJECT(rule.action.num_entries = 8);
        DOUBLE_REJECT(rule.action.entries[6].mangle.offset ^= 4);
        DOUBLE_REJECT(rule.action.entries[6].mangle.val ^= htonl(1));
        DOUBLE_REJECT(rule.action.entries[7].mangle.mask ^= htonl(1));
        DOUBLE_REJECT(rule.action.entries[7].mangle.val ^= htonl(1));
        DOUBLE_REJECT(rule.action.entries[8].csum_flags = tcp ? 17 : 9);
        DOUBLE_REJECT(rule.action.entries[6] = rule.action.entries[4]);
        DOUBLE_REJECT(ct.tuplehash[1].tuple.src.u3.ip = htonl(0xe0000001));
        DOUBLE_REJECT(ct.tuplehash[1].tuple.src.u.all = 0);
#undef DOUBLE_REJECT
        double_nat_fixture(forward, tcp, hairpin);
        for (unsigned stage = 1; stage <= 3; stage++) {
            ft_fail_stage = stage; assert(ft_replace(&binding, &cls) < 0);
            assert(!ft_fail_stage && !ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
        }
        assert(ft_replace(&binding, &cls) == 0);
        /* Even one installed direction retains both routed dependencies. */
        struct netevent_ipv4_route event = { &init_net, htonl(0xcb007105), 32 };
        ft_route_event(&event); assert(handle.invalid);
        ft_retire_workfn(NULL);
        assert(!ft_count && !allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
    }
    /* Same-port source-only/destination-only NAT is still outside the
     * supported boundary, even with otherwise valid route and MAC context. */
    for (unsigned kind = 0; kind < 2; kind++) {
        if (kind) dnat_fixture(true, true); else snat_fixture(true, true);
        rule.action.entries[7].dev = &in;
        route.dst.dev = neighbour.dev = &in;
        memcpy(&rule.action.entries[1].mangle.val, (u8[]){0,0,0,1}, 4);
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    }
}

/* Make whatever flow the fixture built an established TCP one. */
static void tcp_flow(void)
{
    ct.protonum = bk.ip_proto = IPPROTO_TCP;
    ct.tcp_state = TCP_CONNTRACK_ESTABLISHED; ct.status = IPS_ASSURED;
    dissector.used_keys |= BIT(FLOW_DISSECTOR_KEY_TCP);
    tk.flags = 0; tm.flags = htons(5);
    rule.tcp = (struct flow_match_tcp){ &tk, &tm };
}

/* And back to the plain fixture's UDP, for a TCP fixture's UDP case. */
static void udp_flow(void)
{
    ct.protonum = bk.ip_proto = IPPROTO_UDP;
    ct.tcp_state = 0; ct.status = 0;
    dissector.used_keys &= ~BIT(FLOW_DISSECTOR_KEY_TCP);
    rule.tcp = (struct flow_match_tcp){ 0 };
}

static void tcp_fixture(void)
{
    fixture();
    tcp_flow();
}
#define REJECT(change) do { fixture(); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)

/* Model Netfilter's callback-list commit/free after the driver returns. In
 * particular, release must not run while ft_bind holds the control mutex. */
static struct flow_block block;
static struct nf_flowtable table;
static int bind_to(struct net_device *dev, int command, struct nf_flowtable *t,
                   struct flow_block *b)
{
    struct flow_block_offload bo = { .block = b, .net = &init_net,
        .binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS, .command = command };
    list_init(&bo.cb_list);
    int rc = ft_bind(dev, NULL, NULL, TC_SETUP_FT, &bo, t, NULL);
    assert(!t->flow_block_lock && !block_write_lock && !cdx_info->ctrl.mutex);
    while (bo.cb_list.next != &bo.cb_list) {
        struct flow_block_cb *cb = list_entry(bo.cb_list.next, struct flow_block_cb, list);
        list_del(&cb->list);
        if (command == FLOW_BLOCK_BIND) list_add_tail(&cb->list, &b->cb_list);
        else { cb->release(cb->cb_priv); kfree(cb); }
    }
    return rc;
}
static int bind_device(struct net_device *dev, int command)
{
    return bind_to(dev, command, &table, &block);
}
/* The direct route, as a netdev that has an ndo_setup_tc takes it: Netfilter
 * passes the flowtable's own embedded block and no table argument, recovers
 * the owner by container_of, and holds flow_block_lock across the call. */
static int bind_device_direct(struct net_device *dev, int command)
{
    struct flow_block_offload bo = { .block = &table.flow_block, .net = &init_net,
        .binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS, .command = command };
    list_init(&bo.cb_list);
    down_write(&table.flow_block_lock);
    int rc = cdx_ft_setup_tc(dev, TC_SETUP_FT, &bo);
    up_write(&table.flow_block_lock);
    assert(!block_write_lock && !cdx_info->ctrl.mutex);
    while (bo.cb_list.next != &bo.cb_list) {
        struct flow_block_cb *cb = list_entry(bo.cb_list.next, struct flow_block_cb, list);
        list_del(&cb->list);
        if (command == FLOW_BLOCK_BIND) list_add_tail(&cb->list, &table.flow_block.cb_list);
        else { cb->release(cb->cb_priv); kfree(cb); }
    }
    return rc;
}

static bool can_rearm(void)
{
    mutex_lock(&cdx_info->ctrl.mutex);
    bool ready = ft_can_rearm();
    mutex_unlock(&cdx_info->ctrl.mutex);
    return ready;
}
/* The binding a device holds in a table, or NULL; parked or live alike. */
static struct cdx_ft_binding *bound_to(const struct flow_block *b, struct net_device *dev)
{
    struct flow_block_cb *cb = flow_block_cb_lookup((struct flow_block *)b, ft_rule_callback, dev);
    return cb ? cb->cb_priv : NULL;
}
static void detach_during_cleanup(void)
{
    cleanup_hook = NULL;
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_bound && !ft_parked && !ft_count && !ft_invalid_done);
    assert(!can_rearm());
    /* The worker has not finished, so a bind now is parked behind it rather
     * than refused. Leaving again gives everything back. */
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
    assert(ft_bound == 1 && ft_parked == 1 && bound_to(&block, &in)->parked && ft_invalid);
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0 && !ft_bound && !ft_parked);
}
/* A bind made while something still holds a rearm back: parked, not refused,
 * and left again without having reopened anything. */
static void park_and_leave(struct net_device *dev, u64 rearms)
{
    unsigned held = allocated;

    assert(bind_device(dev, FLOW_BLOCK_BIND) == 0);
    assert(ft_bound == 1 && ft_parked == 1 && bound_to(&block, dev)->parked);
    assert(ft_invalid && ft_invalid_done && ft_rearms == rearms && dev->refs == 1);
    assert(bind_device(dev, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_bound && !ft_parked && !dev->refs && allocated == held);
}
static void test_rearm(void)
{
    list_init(&block.cb_list);
    assert(ft_invalid && ft_fatal && ft_invalid_done);
    u64 rearms = ft_rearms;
    /* A failed deletion stops admission until a fresh boot. The bind still
     * succeeds -- refusing it would fail the consumer's whole transaction --
     * but passively: not counted as a binding, holding no device, never
     * rearmed, and declining everything it is offered. */
    assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == 0);
    assert(ft_passive == 1 && !ft_bound && !ft_parked && !in.refs && !table.use_neigh);
    assert(!bound_to(&block, &in) && flow_block_cb_lookup(&block, ft_passive_callback, &in));
    /* The fatal latch independently prevents admission, even if another
     * path were to clear the ordinary invalidation flag accidentally. */
    ft_invalid = 0;
    assert(bind_device(&out, FLOW_BLOCK_BIND) == 0 && ft_passive == 2 && !ft_bound);
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0 && bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_passive && !allocated && !ft_invalid && ft_rearms == rearms);
    assert(block.cb_list.next == &block.cb_list && ft_block_list.next == &ft_block_list);
    /* A latch CDX is restarting the datapath after is not that. A bind
     * under it is an ordinary one -- parked behind the invalidation the
     * failed delete raised -- and declines every flow while the latch
     * holds; a repeat invalidation pass is not skipped either, since the
     * parked table's flows go live after the restart and must have been
     * flushed first. The restart asks for everything the stop refused:
     * both learners reconsider their groups, every SA its peer, and the
     * parked binding is rearmed at once rather than at the next retry. */
    ft_restarting = true; ft_invalid = 1;
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
    assert(!ft_passive && ft_bound == 1 && ft_parked == 1 && bound_to(&block, &in)->parked);
    assert(ft_replace(bound_to(&block, &in), &cls) == -EOPNOTSUPP && !live_hw);
    unsigned flushes = flushed, recovered = recoveries;
    ft_invalidate_work(NULL);
    assert(flushed == flushes + 1 && recoveries == recovered + 1 && ft_invalid_done);
    ft_rearm_workfn(NULL);
    assert(ft_parked == 1 && ft_rearms == rearms);
    unsigned rechecks = mc_rechecks, kicks = mroute_kicks, marked = ipsec_marked_all;
    unsigned follows = follow_scheduled, rearming = rearm_kicks;
    ft_fatal = false; /* The restart CDX did, which clears its latch. */
    ft_egress_restarted();
    assert(mc_rechecks == rechecks + 1 && mroute_kicks == kicks + 1);
    assert(ipsec_marked_all == marked + 1 && follow_scheduled == follows + 1);
    assert(rearm_kicks == rearming + 1);
    ft_rearm_workfn(NULL);
    assert(!ft_parked && !ft_invalid && ft_rearms == rearms + 1 && !bound_to(&block, &in)->parked);
    rearms = ft_rearms;
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0 && !ft_bound && !allocated && !in.refs);
    ft_restarting = false;
    /* A table of a fresh load, which has never been bound. */
    table.use_neigh = table.use_hw_handles = false;
    ft_fatal = false; /* Simulated fresh module/boot, never a recovery action. */
    ft_invalid_done = false;
    deletion_error = 0;
    table.rhashtable.nelems = 2;
    assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP && !table.use_neigh);
    table.rhashtable.nelems = 0;
    u64 errors = ft_errors, installs = ft_installs, deletes = ft_deletes;
    for (unsigned cycle = 0; cycle < 8; cycle++) {
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
        assert(table.use_neigh && table.use_hw_handles);
        invalidate_on_bind = true;
        assert(bind_device(&out, FLOW_BLOCK_BIND) == 0);
        invalidate_on_bind = false;
        /* Raised while the second binding was being allocated, so that one
         * is parked behind it rather than clearing it. */
        assert(ft_invalid && !ft_invalid_done && ft_rearms == rearms + cycle);
        assert(ft_bound == 2 && ft_parked == 1 && allocated == 4 && in.refs == 1 && out.refs == 1);
        assert(!bound_to(&block, &in)->parked && bound_to(&block, &out)->parked);
        ft_invalidate();
        /* A failed retirement barrier cannot be bypassed by detachment. */
        retry_error = -EAGAIN;
        ft_invalidate_work(NULL);
        assert(!ft_invalid_done && !can_rearm());
        if (cycle % 3 == 0) {
            /* The live binding going does not unpark anything while the
             * worker is still retrying. */
            assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
            assert(ft_invalid && ft_bound == 1 && ft_parked == 1);
            assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
            assert(!ft_bound && !ft_parked && !can_rearm());
            assert(bind_device(&in, FLOW_BLOCK_BIND) == 0 && ft_parked == 1);
            assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0 && !ft_parked);
        }
        retry_error = 0;
        if (cycle % 3 == 0) {
            ft_invalidate_work(NULL);
        } else if (cycle & 1) {
            cleanup_hook = detach_during_cleanup;
            ft_invalidate_work(NULL);
        } else {
            ft_invalidate_work(NULL);
            assert(ft_invalid_done && !can_rearm());
            /* The parked binding leaving first changes nothing: the live
             * one is still in the way. */
            assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
            assert(!ft_parked && ft_bound == 1 && !can_rearm());
            /* A second binding of the same table on the same device is
             * refused as ever, parked or not. */
            assert(bind_device(&in, FLOW_BLOCK_BIND) == -EBUSY && in.refs == 1);
            /* With nothing parked, the live one going rearms nothing; the
             * next bind does. */
            assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
            assert(ft_invalid && ft_rearms == rearms + cycle);
        }
        assert(!ft_bound && !ft_parked && !ft_count && !allocated && !in.refs && !out.refs);
        assert(can_rearm());
        table.rhashtable.nelems = 2;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        assert(ft_invalid && ft_invalid_done && !allocated && ft_rearms == rearms + cycle);
        table.rhashtable.nelems = 0;
        ft_neighbour_refs = 1;
        assert(!can_rearm());
        park_and_leave(&in, rearms + cycle);
        ft_neighbour_refs = 0;
        /* A deletion the barrier cannot prove yet holds a rearm back, and
         * the parked binding retries that barrier every second. */
        private_pending = 1; barrier_fails = true;
        unsigned tries = recoveries, retries = rearm_retries;
        assert(!can_rearm());
        park_and_leave(&in, rearms + cycle);
        assert(recoveries == tries + 1 && rearm_retries == retries + 1);
        /* CDX's own parked backlog, the same way. */
        private_pending = 0; legacy_pending = 1;
        park_and_leave(&in, rearms + cycle);
        assert(recoveries == tries + 2 && rearm_retries == retries + 2);
        legacy_pending = 0; barrier_fails = false; ft_stopping = true;
        assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        ft_stopping = false; ft_ready = false;
        assert(!can_rearm() && bind_device(&in, FLOW_BLOCK_BIND) == -EOPNOTSUPP);
        ft_ready = true; allocation_fail = true;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == -ENOMEM);
        allocation_fail = false; callback_allocation_fail = true;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == -ENOMEM);
        callback_allocation_fail = false;
        assert(ft_invalid && ft_invalid_done && can_rearm() && !allocated);
        assert(ft_rearms == rearms + cycle && !ft_bound && !ft_parked);
        /* Nothing left to wait for: the first bind parks and is made live
         * in the same call, as the rearming bind always was. */
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
        assert(!ft_invalid && !ft_invalid_done && !can_rearm() && ft_rearms == rearms + cycle + 1);
        assert(!ft_parked && !bound_to(&block, &in)->parked);
        assert(bind_device(&out, FLOW_BLOCK_BIND) == 0 && ft_rearms == rearms + cycle + 1);
        assert(!ft_parked && !bound_to(&block, &out)->parked);
        fixture();
        struct flow_block_cb *cb = flow_block_cb_lookup(&block, ft_rule_callback, &in);
        assert(cb && ft_replace(cb->cb_priv, &cls) == 0);
        assert(ft_count == 1 && live_hw == 1);
        assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0); /* Real entry retirement. */
        assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
        assert(!ft_count && !ft_bound && !live_hw && !allocated && !in.refs && !out.refs);
        assert(ft_installs == installs + cycle + 1 && ft_deletes == deletes + cycle + 1);
        assert(ft_errors == errors && !ft_invalid && !ft_invalid_done && !ft_fatal);
        assert(ft_bindings.next == &ft_bindings && ft_block_list.next == &ft_block_list);
    }
}

static void test_gateways(void)
{
    struct cdx_ft_rule decoded;
    REJECT(cls.nf_dst = NULL);
    struct dst_ops ipv6_ops = {.family = AF_INET6};
    REJECT(route.dst.ops = &ipv6_ops);
    REJECT(route.dst.dev = &in);
    REJECT(route.dst.valid = false);
    static struct xfrm_state sa;
    REJECT(route.dst.xfrm = &sa);            /* a bundle with no route under it */
    REJECT(xfrm_policies = true; ipsec_ok = false); /* a policy claims it, hardware cannot */
    REJECT(route.dst.lwtstate = &route);
    REJECT(route.rt_type = 2); /* Local route, not forwarded unicast. */
    REJECT(route.rt_gw_family = AF_INET6);
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = 0);
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = htonl(0xe0000001));
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = htonl(0x7f000001));
    REJECT(route.rt_gw_family = AF_INET; route.rt_gw4 = 0xffffffff);
    for (unsigned cycle = 0; cycle < 32; cycle++) {
        if (cycle & 1) tcp_fixture(); else fixture();
        route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key.ip;
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
        assert(is4(&decoded.dst, ik.dst) && !nf_inet_addr_cmp(&next_hop, &decoded.dst));
        assert(nf_inet_addr_cmp(&next_hop, &gateway.primary_key) && !gateway.refs && !neighbour.refs);
        assert(ft_replace(&binding, &cls) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        assert(nf_inet_addr_cmp(&e->next_hop, &gateway.primary_key) && e->neigh == &gateway);
        assert(gateway.refs == 1 && !neighbour.refs);
        neighbour.nud_state = NUD_FAILED; /* Remote endpoint is not the dependency. */
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid && ft_count == 1);
        u64 installs = ft_installs;
        assert(ft_replace(&binding, &cls) == 0 && ft_installs == installs);
        /* Even an identical Ethernet rewrite must move its watch when the
         * selected gateway changes. Never deduplicate by the HW rule alone. */
        route.rt_gw4 = alternate_gateway.primary_key.ip;
        assert(ft_replace(&binding, &cls) == 0 && ft_installs == installs + 1);
        e = ft_find(&binding, cls.cookie);
        assert(e->neigh == &alternate_gateway && !gateway.refs && alternate_gateway.refs == 1);
        gateway.dead = true;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
        assert(!ft_invalid);
        alternate_gateway.ha[5]++;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &alternate_gateway);
        assert(!ft_invalid && handle.invalid && ft_remove(e) == 0);
        ft_invalid = 0;
    }
    fixture(); route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key.ip;
    gateway.nud_state = NUD_FAILED;
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP && !ft_count);
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs);
}

static void test_neighbours(void)
{
    const unsigned valid[] = {NUD_PERMANENT, NUD_REACHABLE, NUD_STALE, NUD_DELAY, NUD_PROBE};
    const unsigned invalid[] = {0, NUD_INCOMPLETE, NUD_FAILED, NUD_NOARP,
                               NUD_NOARP | NUD_REACHABLE, NUD_FAILED | NUD_REACHABLE};
    struct cdx_ft_rule decoded;
    for (unsigned i = 0; i < ARRAY_SIZE(valid); i++) {
        fixture(); neighbour.nud_state = valid[i];
        assert(ft_replace(&binding, &cls) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        assert(e && neighbour.refs == 1 && ft_neighbour_refs == 1);
        unsigned uses = neigh_uses;
        assert(ft_stats(e, &cls) == 0 && neigh_uses == uses); /* Idle is not use. */
        e->hw->stats.packets++;
        assert(ft_stats(e, &cls) == 0 && neigh_uses == uses + 1);
        assert(ft_stats(e, &cls) == 0 && neigh_uses == uses + 1); /* No double use. */
        for (unsigned j = 0; j < ARRAY_SIZE(valid); j++) {
            neighbour.nud_state = valid[j];
            ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
            assert(!ft_invalid && ft_count == 1);
        }
        struct neighbour unrelated = neighbour;
        unrelated.nud_state = NUD_FAILED;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &unrelated);
        assert(!ft_invalid);
        neighbour.ha[5]++;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid && handle.invalid && ft_count == 1); /* Atomic callback only latches. */
        assert(ft_remove(e) == 0 && !neighbour.refs && !ft_neighbour_refs);
        ft_invalid = 0;
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid); /* Removed entries cannot be dereferenced. */
    }
    for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
        fixture(); neighbour.nud_state = invalid[i];
        assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP && !neighbour.refs);
        neighbour.nud_state = NUD_REACHABLE;
        assert(ft_replace(&binding, &cls) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        neighbour.nud_state = invalid[i];
        ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
        assert(!ft_invalid && handle.invalid);
        unsigned uses = neigh_uses;
        e->hw->stats.packets++;
        assert(ft_stats(e, &cls) == -EOPNOTSUPP && neigh_uses == uses);
        assert(ft_remove(e) == 0); ft_invalid = 0;
    }
    fixture(); neighbour.dead = true;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP && !neighbour.refs);
    fixture(); change_neigh_on_lookup = true; /* Decoder/publication race. */
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs && !live_hw && !allocated);
    change_neigh_on_lookup = false;
    fixture(); change_neigh_on_add = true; /* Watch precedes hardware insertion. */
    assert(ft_replace(&binding, &cls) == -EIO && !ft_invalid && handle.invalid);
    assert(!gateway.refs && !alternate_gateway.refs && !neighbour.refs && !ft_neighbour_refs && !live_hw && !allocated);
    change_neigh_on_add = false; ft_invalid = 0;
    fixture(); assert(ft_replace(&binding, &cls) == 0);
    struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
    neigh_send_error = 1; e->hw->stats.packets++;
    assert(ft_stats(e, &cls) == -EOPNOTSUPP && !ft_invalid && handle.invalid);
    assert(ft_remove(e) == 0); neigh_send_error = 0; ft_invalid = 0;
    fixture(); assert(ft_replace(&binding, &cls) == 0);
    cls.cookie++; pk.src = htons(10001);
    assert(ft_replace(&binding, &cls) == 0 && ft_neighbour_refs == 2 && neighbour.refs == 2);
    neighbour.dead = true;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(!ft_invalid && handle.invalid && ft_count == 2);
    ft_retire_workfn(NULL);
    assert(!ft_count && !live_hw && !allocated && !ft_neighbour_refs && !neighbour.refs);
    assert(ft_neigh_entries.next == &ft_neigh_entries && !out.refs);
    assert(ft_installs == ft_deletes);
}
/* Same addresses and ports across protocols must remain distinct. Keep the
 * fixture's neighbour alive while changing the borrowed rule for each request.
 */
static void connection_rule(unsigned n)
{
    cls.cookie = 1000 + n;
    cls.stats = (struct flow_stats){0};
    pk.src = htons(10000 + n / 2);
    ct.protonum = bk.ip_proto = n & 1 ? IPPROTO_TCP : IPPROTO_UDP;
    ct.tcp_state = TCP_CONNTRACK_ESTABLISHED;
    ct.status = IPS_ASSURED;
    dissector.used_keys = FT_KEYS4 | (n & 1 ? BIT_ULL(FLOW_DISSECTOR_KEY_TCP) : 0);
    tk.flags = 0; tm.flags = htons(TCPHDR_FIN | TCPHDR_RST);
    rule.tcp = (struct flow_match_tcp){ &tk, &tm };
}

/* Complete and fragmented proc iteration must enumerate every live owner once,
 * including collisions, empty buckets and a resumed read at the current row. */
static void test_iterator(unsigned expected)
{
    bool seen[CDX_FT_MAX_ENTRIES] = {0};
    loff_t pos = 0;
    void *row = ft_start(NULL, &pos);
    unsigned count = 0;

    assert(row == &ft_entries);
    while ((row = ft_next(NULL, row, &pos))) {
        struct cdx_ft_entry *entry = list_entry(row, struct cdx_ft_entry, list);
        unsigned index = (entry->cookie - 1000) % 100000;
        assert(index < CDX_FT_MAX_ENTRIES && !seen[index]);
        seen[index] = true;
        count++;
        if (!(count % 17)) {
            ft_stop(NULL, row);
            assert(ft_start(NULL, &pos) == row);
        }
    }
    ft_stop(NULL, row);
    assert(count == expected);
}

static void test_connections(void)
{
    struct cdx_ft_entry *entries[CDX_FT_MAX_ENTRIES];
    u64 installs = ft_installs, deletes = ft_deletes, errors = ft_errors;

    fixture();
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        connection_rule(i);
        assert(ft_replace(&binding, &cls) == 0);
        entries[i] = ft_find(&binding, cls.cookie);
        assert(entries[i] && entries[i]->neigh == &neighbour);
        entries[i]->hw->stats = (struct cdx_ft_counters){
            .packets = 100 + i, .bytes = 10000 + i * 100, .lastused = 990 };
        assert(ft_stats(entries[i], &cls) == 0);
        assert(cls.stats.pkts == 100 + i &&
               cls.stats.bytes == 10000 + i * 100 - (100 + i) * ETH_HLEN);
    }
    test_iterator(ARRAY_SIZE(entries));
    assert(ft_count == ARRAY_SIZE(entries) && live_hw == ft_count);
    assert(allocated == ft_count && neighbour.refs == ft_count);
    assert(ft_neighbour_refs == ft_count && out.refs == (int)ft_count);

    /* Full admission must preserve idempotent updates and reject duplicate
     * keys without disturbing the existing owner or resetting its counters. */
    connection_rule(10);
    assert(ft_replace(&binding, &cls) == 0);
    cls.cookie += 100000;
    assert(ft_replace(&binding, &cls) == -EEXIST);
    connection_rule(ARRAY_SIZE(entries));
    assert(ft_replace(&binding, &cls) == -ENOSPC);
    assert(ft_installs == installs + ARRAY_SIZE(entries) && ft_deletes == deletes);

    /* Retire and reuse a middle key with a new opaque cookie. Other owners,
     * hardware handles and previously reported deltas must survive intact. */
    connection_rule(17);
    assert(ft_remove(entries[17]) == 0 && !ft_find(&binding, cls.cookie));
    cls.cookie += 100000;
    assert(ft_replace(&binding, &cls) == 0);
    entries[17] = ft_find(&binding, cls.cookie);
    assert(!entries[17]->reported.packets && !entries[17]->hw->stats.packets);
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        connection_rule(i);
        if (i == 17) cls.cookie += 100000;
        assert(ft_find(&binding, cls.cookie) == entries[i]);
        entries[i]->hw->stats.packets += i + 1;
        entries[i]->hw->stats.bytes += (i + 1) * 100;
        assert(ft_stats(entries[i], &cls) == 0);
        assert(cls.stats.pkts == i + 1 &&
               cls.stats.bytes == (i + 1) * (100 - ETH_HLEN));
    }
    test_iterator(ARRAY_SIZE(entries));
    /* Different removal order exercises list head, middle and tail; sharing
     * a neighbour cannot tie one connection's lifetime to another's. */
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        unsigned n = i & 1 ? ARRAY_SIZE(entries) - 1 - i / 2 : i / 2;
        assert(ft_remove(entries[n]) == 0);
        assert(ft_count == ARRAY_SIZE(entries) - 1 - i && neighbour.refs == ft_count);
        assert(ft_neighbour_refs == ft_count && out.refs == (int)ft_count);
    }
    assert(!live_hw && !allocated && ft_installs == ft_deletes);
    assert(ft_installs == installs + ARRAY_SIZE(entries) + 1 && ft_errors == errors);
    assert(!ft_invalid && !ft_fatal);

    test_iterator(0);
    /* Every entry here shares the changed dependency; all must be drained. */
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        connection_rule(i);
        assert(ft_replace(&binding, &cls) == 0);
    }
    neighbour.dead = true;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(!ft_invalid && handle.invalid && ft_count == ARRAY_SIZE(entries));
    ft_retire_workfn(NULL);
    assert(!ft_count && !live_hw && !allocated && !ft_neighbour_refs && !neighbour.refs);
    assert(!out.refs && ft_installs == ft_deletes && ft_errors == errors);
    ft_invalid = 0; ft_invalid_done = false;
}

static void test_selective_neighbours(void)
{
    struct nf_flow_offload_handle contexts[3] = { {1, false}, {1, false}, {1, false} };
    struct cdx_ft_entry *entries[4];
    u64 invalidations = ft_neigh_invalidations, errors = ft_errors;

    fixture();
    for (unsigned i = 0; i < ARRAY_SIZE(entries); i++) {
        cls.nf_handle = &contexts[i / 2];
        cls.cookie = 5000 + i;
        pk.src = htons(11000 + i);
        route.rt_gw_family = i & 1 ? 0 : AF_INET;
        route.rt_gw4 = i < 2 ? gateway.primary_key.ip : alternate_gateway.primary_key.ip;
        assert(ft_replace(&binding, &cls) == 0);
        entries[i] = ft_find(&binding, cls.cookie);
        entries[i]->hw->stats.packets = 100 + i;
    }
    assert(contexts[0].refs == 3 && contexts[1].refs == 3 && ft_handle_refs == 4);
    gateway.nud_state = NUD_FAILED;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
    assert(contexts[0].invalid && !contexts[1].invalid);
    assert(ft_neigh_invalidations == invalidations + 1 && !ft_invalid && ft_count == 4);
    ft_retire_workfn(NULL);
    assert(ft_count == 2 && ft_handle_refs == 2 && ft_neighbour_refs == 2);
    assert(contexts[0].refs == 1 && contexts[1].refs == 3);
    assert(!ft_find(&binding, 5000) && !ft_find(&binding, 5001));
    assert(ft_find(&binding, 5002) == entries[2] && ft_find(&binding, 5003) == entries[3]);
    assert(entries[2]->hw->stats.packets == 102 && entries[3]->hw->stats.packets == 103);

    /* Even after resolution, a queued add for the invalid generation fails.
     * A fresh Linux generation can reuse its cookie without inheriting state. */
    gateway.nud_state = NUD_PERMANENT;
    cls.nf_handle = &contexts[0]; cls.cookie = 5000; pk.src = htons(11000);
    route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key.ip;
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP && ft_count == 2);
    cls.nf_handle = &contexts[2];
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 3);
    struct cdx_ft_entry *fresh = ft_find(&binding, cls.cookie);
    assert(!fresh->reported.packets && !fresh->hw->stats.packets);
    cls.nf_handle = &contexts[0];
    cls.command = FLOW_CLS_DESTROY;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
    assert(ft_find(&binding, cls.cookie) == fresh);
    cls.command = FLOW_CLS_STATS;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -ENOENT);
    cls.command = FLOW_CLS_REPLACE;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -ESTALE);
    assert(ft_count == 3 && !ft_invalid && ft_errors == errors);

    /* A retirement error must escalate globally, including the unaffected
     * connection, before recovery can be announced. */
    gateway.nud_state = NUD_FAILED;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &gateway);
    deletion_error = -EAGAIN;
    ft_retire_workfn(NULL);
    deletion_error = 0;
    assert(ft_invalid && !ft_fatal && ft_errors == errors + 1 && ft_count == 2);
    ft_invalidate_work(NULL);
    assert(ft_invalid_done && !ft_count && !ft_handle_refs && !ft_neighbour_refs);
    assert(!live_hw && !allocated && !out.refs && ft_installs == ft_deletes);
    for (unsigned i = 0; i < ARRAY_SIZE(contexts); i++) assert(contexts[i].refs == 1);
    ft_invalid = 0; ft_invalid_done = false;

    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    unsigned queued = neigh_scheduled;
    ft_stopping = true;
    neighbour.dead = true;
    ft_neigh_event(NULL, NETEVENT_NEIGH_UPDATE, &neighbour);
    assert(neigh_scheduled == queued && handle.invalid);
    ft_retire_workfn(NULL);
    assert(ft_count == 1); /* Shutdown's binding release owns this retirement. */
    assert(ft_remove(ft_find(&binding, cls.cookie)) == 0);
    ft_stopping = false;
    assert(!ft_handle_refs && handle.refs == 1 && !allocated);
}

/* Take every installed direction out, and the device records a session left
 * behind, which outlive the entries that counted into them. In the cases below
 * both directions of the fixture's flow share one generation: the second is
 * the same connection offered under the next cookie, with a source port of its
 * own so the two never share a hardware key. */
static void remove_all(void)
{
    struct cdx_ft_entry *entry, *next;

    cdx_ft_begin();
    list_for_each_entry_safe(entry, next, &ft_entries, list)
        assert(ft_remove(entry) == 0);
    cdx_ft_end();
    drop_dev_records();
    assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated && !live_hw);
}

static void test_transient_admission(void)
{
    struct cdx_ft_binding other_binding = { .dev = &out };
    for (unsigned tcp = 0; tcp < 2; tcp++)
        for (unsigned policies = 0; policies < 2; policies++) {
            if (tcp) tcp_fixture(); else fixture();
            /* A policy anywhere closes the software fast path, and with it
             * the only thing that would ever offer this flow again. None
             * of them claims this flow. */
            xfrm_policies = policies;
            cls.command = FLOW_CLS_REPLACE;
            u64 invalidations = ft_admission_invalidations, busy = ft_busy;
            unsigned long first = cls.cookie;
            ft_fail_stage = 4;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            assert(ft_fail_stage == 4 && ft_count == 1 && !handle.invalid);
            /* Visiting a different ingress cannot consume the fault or retire
             * the successfully installed direction, even during real contention. */
            /* Nor is the visit a refusal: a rejects count that moved on
             * visits alone would pass an oracle for a refusal that never
             * happened. */
            rtnl_busy = true;
            u64 rejects = ft_rejects;
            unsigned visits = rtnl_trylocks;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &other_binding) == -EOPNOTSUPP);
            assert(ft_fail_stage == 4 && ft_busy == busy && !handle.invalid);
            assert(ft_rejects == rejects && rtnl_trylocks == visits);
            rtnl_busy = false;
            /* Nor can the installed direction offered again, which is what
             * Linux does alongside its other one: it never asks for RTNL. */
            unsigned trylocks = rtnl_trylocks;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            assert(ft_fail_stage == 4 && rtnl_trylocks == trylocks && ft_count == 1);
            /* The second direction loses RTNL. */
            cls.cookie++; pk.src++;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EAGAIN);
            assert(!ft_fail_stage && ft_count == 1 && ft_busy == busy + 1);
            if (!policies) {
                /* Software forwards it and offers the flow again within a
                 * second, so the installed direction keeps its hardware and
                 * the next offer admits this one next to it. */
                assert(!handle.invalid && ft_admission_invalidations == invalidations);
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
                assert(ft_count == 2 && !handle.invalid && handle.refs == 3);
            } else {
                /* Nothing would offer it again, and the installed direction
                 * keeps the generation alive from hardware alone: retire it,
                 * so fresh traffic retries both after native GC. */
                assert(handle.invalid && ft_admission_invalidations == invalidations + 1);
                ft_retire_workfn(NULL);
                assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && handle.refs == 1);
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EOPNOTSUPP);
                /* Fresh generation after native GC; the same table stays eligible. */
                handle = (struct nf_flow_offload_handle){ .refs = 1 };
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
                cls.cookie = first; pk.src--;
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
                assert(ft_count == 2 && !handle.invalid && handle.refs == 3);
            }
            /* Both installed: however busy RTNL is, offering either again
             * takes nothing out of hardware, and asks for nothing. */
            rtnl_busy = true;
            trylocks = rtnl_trylocks;
            busy = ft_busy;
            invalidations = ft_admission_invalidations;
            for (unsigned direction = 0; direction < 2; direction++) {
                cls.cookie = first + direction; pk.src = htons(10000) + direction;
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            }
            rtnl_busy = false;
            assert(!handle.invalid && ft_count == 2 && handle.refs == 3 && live_hw == 2);
            assert(rtnl_trylocks == trylocks && ft_busy == busy &&
                   ft_admission_invalidations == invalidations);
            remove_all();
        }
    /* RTNL really held elsewhere, on the first offer of a flow and on the
     * second direction of one whose first is installed. With software
     * forwarding the flow nothing is retired and the next offer admits the
     * direction; with a policy closing that path, retiring the generation is
     * what lets fresh traffic retry. */
    for (unsigned installed = 0; installed < 2; installed++)
        for (unsigned policies = 0; policies < 2; policies++) {
            fixture(); cls.command = FLOW_CLS_REPLACE;
            xfrm_policies = policies;
            if (installed) {
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
                cls.cookie++; pk.src++;
            }
            u64 invalidations = ft_admission_invalidations, busy = ft_busy;
            rtnl_busy = true;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EAGAIN);
            rtnl_busy = false;
            assert(ft_busy == busy + 1 && ft_count == installed);
            assert(handle.invalid == !!policies &&
                   ft_admission_invalidations == invalidations + policies);
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) ==
                   (policies ? -EOPNOTSUPP : 0));
            assert(ft_count == installed + !policies);
            if (policies) ft_retire_workfn(NULL);
            remove_all();
        }
    /* A latch pending owns the recovery, even where a lost RTNL would
     * otherwise retire the generation. */
    for (unsigned excluded = 0; excluded < 4; excluded++) {
        fixture(); cls.command = FLOW_CLS_REPLACE;
        xfrm_policies = true;
        u64 invalidations = ft_admission_invalidations;
        ft_observe = excluded == 0; ft_stopping = excluded == 1;
        ft_invalid = excluded == 2; ft_fatal = excluded == 3;
        rtnl_busy = true;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EAGAIN);
        assert(!handle.invalid && ft_admission_invalidations == invalidations);
        rtnl_busy = false; ft_observe = ft_stopping = ft_fatal = false; ft_invalid = 0;
    }
}

static void test_allocation_admission_recovery(void)
{
    for (unsigned tcp = 0; tcp < 2; tcp++)
        for (unsigned peer_installed = 0; peer_installed < 2; peer_installed++)
            for (unsigned hardware = 0; hardware < 2; hardware++) {
                if (tcp) tcp_fixture(); else fixture();
                cls.command = FLOW_CLS_REPLACE;
                u64 invalidations = ft_admission_invalidations;
                if (peer_installed) {
                    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
                    cls.cookie++; pk.src++;
                }
                allocation_fail = !hardware;
                hardware_alloc_error = hardware ? -ENOMEM : 0;
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -ENOMEM);
                allocation_fail = false;
                hardware_alloc_error = 0;
                /* Hardware-only activity in the installed direction can
                 * keep a partial generation alive without software refresh
                 * retrying admission. Retire it on allocation failure. */
                assert(handle.invalid && ft_admission_invalidations == invalidations + 1);
                assert(ft_count == peer_installed && ft_handle_refs == peer_installed &&
                       ft_neighbour_refs == peer_installed);
                ft_retire_workfn(NULL);
                assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs &&
                       !allocated && !live_hw && handle.refs == 1);
                /* Native GC permits the same connection's next generation. */
                handle = (struct nf_flow_offload_handle){ .refs = 1 };
                assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
                assert(ft_count == 1 && !handle.invalid && !ft_invalid);
                cdx_ft_begin();
                assert(ft_remove(ft_find(&binding, cls.cookie)) == 0);
                cdx_ft_end();
            }
}

/* A direction already in hardware offered again, which Linux does about once
 * a second while software forwards the flow's other direction. */
static void test_installed_reoffer(void)
{
    for (unsigned stale = 0; stale < 3; stale++)
        for (unsigned policies = 0; policies < 2; policies++) {
            fixture(); cls.command = FLOW_CLS_REPLACE;
            xfrm_policies = policies;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            struct cdx_ft_entry *installed = ft_find(&binding, cls.cookie);
            u64 busy = ft_busy, rejects = ft_rejects, validated = ft_validated;
            u64 admission = ft_admission_invalidations, policy = ft_ipsec_policy_invalidations;
            u64 routes = ft_route_invalidations;
            unsigned trylocks = rtnl_trylocks, lookups = police_lookups;
            /* What no lock orders against an offer still counts: a policy
             * generation or a borrowed route that has moved on. */
            if (stale == 1) xfrm_genid++;
            if (stale == 2) route.dst.valid = false;
            rtnl_busy = true;
            int rc = ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding);
            rtnl_busy = false;
            /* Answered without RTNL and without a walk, whatever the answer. */
            assert(rtnl_trylocks == trylocks && ft_busy == busy && ft_validated == validated &&
                   police_lookups == lookups && ft_admission_invalidations == admission);
            assert(ft_find(&binding, cls.cookie) == installed && ft_count == 1 && live_hw == 1);
            if (!stale) {
                assert(rc == 0 && !handle.invalid && handle.refs == 2 && ft_rejects == rejects);
                assert(installed->handle == &handle && ft_handle_refs == 1);
                remove_all();
                continue;
            }
            assert(rc == -EOPNOTSUPP && handle.invalid && ft_rejects == rejects + 1);
            assert(ft_ipsec_policy_invalidations == policy + (stale == 1));
            assert(ft_route_invalidations == routes + (stale == 2));
            ft_retire_workfn(NULL);
            assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated && !live_hw);
        }
    /* The IPv6 ingress MTU is a sysctl no event reports. A partially offloaded
     * flow is offered again every second, which is when a raised LAN IPv6 MTU
     * has to take its installed direction out -- also without RTNL. */
    for (unsigned raised = 0; raised < 2; raised++) {
        fixture6(); cls.command = FLOW_CLS_REPLACE;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0 && ft_count == 1);
        u64 mtu = ft_mtu_invalidations, rejects = ft_rejects;
        unsigned trylocks = rtnl_trylocks;
        if (raised) in.ip6_mtu = 1500;
        rtnl_busy = true;
        int rc = ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding);
        rtnl_busy = false;
        assert(rtnl_trylocks == trylocks && ft_count == 1);
        assert(rc == (raised ? -EOPNOTSUPP : 0) && handle.invalid == !!raised);
        assert(ft_mtu_invalidations == mtu + raised && ft_rejects == rejects + raised);
        if (raised) ft_retire_workfn(NULL); else remove_all();
        assert(!ft_count && !ft_handle_refs);
    }
    /* A generation already retired -- by an event, a latch or Linux itself --
     * is not an installed direction to answer for. The offer goes through
     * admission: with RTNL it is refused and the entry taken out at once, and
     * with RTNL busy it is declined and the retirement already queued takes it
     * out, retiring nothing more. */
    for (unsigned busy = 0; busy < 2; busy++) {
        fixture(); cls.command = FLOW_CLS_REPLACE;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
        nf_flow_offload_handle_invalidate(&handle);
        u64 busy_before = ft_busy, admission = ft_admission_invalidations;
        unsigned trylocks = rtnl_trylocks;
        rtnl_busy = busy;
        int rc = ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding);
        rtnl_busy = false;
        assert(rtnl_trylocks == trylocks + 1 && ft_admission_invalidations == admission);
        assert(rc == (busy ? -EAGAIN : -EOPNOTSUPP) && ft_busy == busy_before + busy);
        assert(ft_count == busy);
        ft_retire_workfn(NULL);
        assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated && !live_hw);
    }
    /* A latch pending sends the offer the way it always went, through
     * admission, which takes the entry out. */
    unsigned trylocks;
    for (unsigned latch = 0; latch < 4; latch++) {
        fixture(); cls.command = FLOW_CLS_REPLACE;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
        trylocks = rtnl_trylocks;
        ft_observe = latch == 0; ft_stopping = latch == 1;
        ft_invalid = latch == 2; ft_fatal = latch == 3;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EOPNOTSUPP);
        ft_observe = ft_stopping = ft_fatal = false; ft_invalid = 0;
        assert(rtnl_trylocks == trylocks + 1 && !ft_count && !live_hw && !allocated);
    }
    /* An offer from another generation under the same cookie is not the
     * installed direction, and admission refuses it as before. */
    fixture(); cls.command = FLOW_CLS_REPLACE;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
    struct nf_flow_offload_handle other = { .refs = 1 };
    struct cdx_ft_entry *current = ft_find(&binding, cls.cookie);
    assert(ft_offer_installed(current, &cls));
    cls.nf_handle = &other;
    assert(!ft_offer_installed(current, &cls));
    trylocks = rtnl_trylocks;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -ESTALE);
    assert(rtnl_trylocks == trylocks + 1 && ft_count == 1 && other.refs == 1 && !other.invalid);
    cls.nf_handle = &handle;
    remove_all();
}

/* Either kind of direction from the same connection: one that arrives through
 * a tunnel -- 4in6, or 6in4 when the flow is IPv6 -- or the same flow arriving
 * on the port directly. */
static void arrival_fixture(bool ipv6, bool tunnel)
{
    if (tunnel) {
        if (ipv6) sit_in_fixture(); else ip6tnl_in_fixture();
    } else {
        if (ipv6) fixture6(); else fixture();
    }
    cls.command = FLOW_CLS_REPLACE;
}

/* A direction that arrives through a tunnel is never offered again by its own
 * traffic: its tuple names the port below the tunnel, where software sees only
 * the outer packet. With its sibling in hardware, a refusal that clears by
 * itself therefore retires the generation, where a direction the fast path
 * forwards simply waits for its next offer. */
static void test_tunnel_arrival_retry(void)
{
    for (unsigned ipv6 = 0; ipv6 < 2; ipv6++)
        for (unsigned tunnel = 0; tunnel < 2; tunnel++) {
            /* RTNL lost on the second direction. */
            arrival_fixture(ipv6, tunnel);
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            cls.cookie++; pk.src++;
            u64 invalidations = ft_admission_invalidations, busy = ft_busy;
            rtnl_busy = true;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EAGAIN);
            rtnl_busy = false;
            assert(ft_busy == busy + 1 && ft_count == 1);
            assert(handle.invalid == !!tunnel &&
                   ft_admission_invalidations == invalidations + tunnel);
            ft_retire_workfn(NULL);
            remove_all();

            /* A hardware key another generation still holds: the one Linux
             * tore down, whose removal has not run yet. */
            struct nf_flow_offload_handle old = { .refs = 1 };
            arrival_fixture(ipv6, tunnel);
            cls.nf_handle = &old; cls.cookie = 900;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            cls.nf_handle = &handle; cls.cookie = 901; pk.src++;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            cls.cookie = 902; pk.src--;
            invalidations = ft_admission_invalidations;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EEXIST);
            assert(handle.invalid == !!tunnel && !old.invalid &&
                   ft_admission_invalidations == invalidations + tunnel);
            ft_retire_workfn(NULL);
            assert(ft_count == 2 - tunnel);
            remove_all();
            assert(old.refs == 1);

            /* A full table keeps the direction that holds a slot. */
            arrival_fixture(ipv6, tunnel);
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            cls.cookie++; pk.src++;
            unsigned count = ft_count, attempts = rtnl_trylocks;
            u64 rejects = ft_rejects;
            busy = ft_busy;
            ft_count = CDX_FT_MAX_ENTRIES;
            rtnl_busy = !tunnel;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -ENOSPC);
            rtnl_busy = false;
            ft_count = count;
            assert(!handle.invalid && ft_count == 1);
            /* Refused before RTNL where software keeps offering it, since
             * it would be refused again every second until a slot frees;
             * where nothing offers it again, admission decides. */
            assert(rtnl_trylocks == attempts + tunnel && ft_busy == busy);
            assert(ft_rejects == rejects + 1);
            remove_all();

            /* And so does a neighbour this adapter cannot use, which Linux
             * never offers unresolved: what reaches here raced the offer, or
             * is a state that would be refused again after readmission. */
            arrival_fixture(ipv6, tunnel);
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
            cls.cookie++; pk.src++;
            neighbour.ha[5]++;
            assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EOPNOTSUPP);
            neighbour.ha[5]--;
            assert(!handle.invalid && ft_count == 1);
            remove_all();
        }
    /* A tunnel's egress whose outer next hop has moved since the walk
     * recorded it would be refused on every later offer of the generation,
     * so the first retires it and the next generation walks the path afresh.
     * One still resolving waits for the next offer instead. */
    for (unsigned moved = 0; moved < 2; moved++) {
        sit_out_fixture(); cls.command = FLOW_CLS_REPLACE;
        if (moved)
            gateway.ha[5]++;
        else
            gateway.nud_state = NUD_INCOMPLETE;
        u64 macs = ft_mac_invalidations;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) ==
               (moved ? -ESTALE : -EOPNOTSUPP));
        assert(handle.invalid == !!moved && ft_mac_invalidations == macs + moved);
        assert(!ft_count);
    }
}

/* Devices a direction crosses without the rule naming them: held while it is
 * installed, and retiring it on a change exactly as a named device does. */
static void test_crossed_devices(void)
{
    /* QinQ egress: eth3.100 lies between the logical eth3.100.300 and the
     * port. */
    const unsigned long events[] = { NETDEV_CHANGEMTU, NETDEV_CHANGEADDR,
                                     NETDEV_UNREGISTER, NETDEV_CHANGEUPPER };
    for (unsigned event = 0; event < ARRAY_SIZE(events); event++) {
        vlan_fixture(); cls.command = FLOW_CLS_REPLACE;
        route.dst.dev = &out_qinq;
        neighbour.dev = &out_qinq;
        encap_actions(0, (const u16[]){ 100, 300 }, 2);
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        assert(e->ncrossed == 1 && e->crossed[0] == &out_tag);
        assert(out_tag.refs == 1 && out_qinq.refs == 1 && !in_tag.refs);
        assert(ft_device_role(&out_tag) == FT_DEV_CROSSED);
        assert(ft_device_role(&out_qinq) == FT_DEV_NAMED);
        assert(ft_device_role(&out) == FT_DEV_PORT && ft_device_role(&in) == FT_DEV_PORT);
        assert(ft_device_role(&in_tag) == FT_DEV_UNUSED);
        u64 *counter = event == 0 ? &ft_mtu_invalidations :
                       event == 1 ? &ft_mac_invalidations : &ft_link_invalidations;
        u64 before = *counter;
        /* Its unregistration, and an upper it gains or loses, retire the
         * flows through it and leave every binding and every other flow
         * up. */
        device_event(&out_tag, events[event], false);
        assert(handle.invalid && *counter == before + 1);
        ft_retire_workfn(NULL);
        assert(!ft_count && !out_tag.refs && !out_qinq.refs);
        drop_dev_records();
    }
    /* The ingress side, crossed the same way: 4in6 arriving over a PPPoE
     * session, where the ppp device under the tunnel is crossed, and over a
     * VLAN device, where the tag's device is. */
    for (unsigned under = 0; under < 2; under++) {
        struct net_device *crossed = under ? &in_tag : &in_ppp;

        ip6tnl_in_fixture(); cls.command = FLOW_CLS_REPLACE;
        ingress_tunnel.lower_ifindex = crossed->ifindex;
        if (under) {
            encap_actions(1, NULL, 0);
            encap_keys((const u16[]){ 200 }, 1);
        } else {
            memset(ingress_tunnel.h_dest, 0, ETH_ALEN);
            ingress_session = (struct nf_flow_session){ .lower_ifindex = in.ifindex,
                                                        .id = SESSION_ID + 1 };
            memcpy(ingress_session.h_dest, AC_MAC, ETH_ALEN);
        }
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
        assert(e->ncrossed == 1 && e->crossed[0] == crossed);
        assert(crossed->refs == 1 && in_ip6tnl.refs == 1);
        assert(ft_device_role(crossed) == FT_DEV_CROSSED);
        assert(ft_device_role(&in_ip6tnl) == FT_DEV_NAMED);
        u64 links = ft_link_invalidations;
        device_event(crossed, NETDEV_UNREGISTER, false);
        assert(handle.invalid && ft_link_invalidations == links + 1);
        ft_retire_workfn(NULL);
        assert(!ft_count && !crossed->refs && !in_ip6tnl.refs);
        drop_dev_records();
    }
    /* And two tags on ingress with nothing above them, where the device of
     * the outer tag is crossed by the tag walk alone: the frame arrives on
     * `out` as eth3.100.300 and leaves by `in`. */
    struct cdx_ft_binding qinq_binding = { .dev = &out };
    vlan_fixture(); cls.command = FLOW_CLS_REPLACE;
    reverse_route.dst.dev = &out_qinq;
    mk.ingress_ifindex = out.ifindex;
    source_mac(&in);
    rule.action.entries[4].dev = &in;
    route.dst.dev = &in;
    neighbour.dev = &in;
    encap_actions(2, NULL, 0);
    encap_keys((const u16[]){ 100, 300 }, 2);
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &qinq_binding) == 0);
    struct cdx_ft_entry *qinq = ft_find(&qinq_binding, cls.cookie);
    assert(qinq && qinq->ncrossed == 1 && qinq->crossed[0] == &out_tag);
    assert(out_tag.refs == 1 && out_qinq.refs == 1);
    assert(ft_device_role(&out_tag) == FT_DEV_CROSSED);
    u64 crossings = ft_link_invalidations;
    device_event(&out_tag, NETDEV_UNREGISTER, false);
    assert(handle.invalid && ft_link_invalidations == crossings + 1);
    ft_retire_workfn(NULL);
    assert(!ft_count && !out_tag.refs && !out_qinq.refs && !in.refs);
    drop_dev_records();
    /* A session over a VLAN device: the device the session runs over is the
     * tag's, and a carrier loss there reaches the flow. */
    pppoe_out_fixture(); cls.command = FLOW_CLS_REPLACE;
    egress_session.lower_ifindex = out_tag.ifindex;
    encap_actions(0, (const u16[]){ 100 }, 1);
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
    struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
    assert(e->ncrossed == 1 && e->crossed[0] == &out_tag && out_tag.refs == 1 && ppp.refs == 1);
    u64 links = ft_link_invalidations;
    out_tag.carrier_lost = true;
    device_event(&out_tag, NETDEV_CHANGE, false);
    out_tag.carrier_lost = false;
    assert(handle.invalid && ft_link_invalidations == links + 1);
    ft_retire_workfn(NULL);
    assert(!ft_count && !out_tag.refs && !ppp.refs);
    drop_dev_records();
    /* A tunnel over a session: the ppp device is what the tunnel runs over,
     * and a session dropping under it retires the flow selectively. */
    ip6tnl_out_fixture(); cls.command = FLOW_CLS_REPLACE;
    egress_tunnel.lower_ifindex = ppp.ifindex;
    memset(egress_tunnel.h_dest, 0, ETH_ALEN);
    egress_session = (struct nf_flow_session){ .lower_ifindex = out.ifindex,
                                               .id = SESSION_ID };
    memcpy(egress_session.h_dest, AC_MAC, ETH_ALEN);
    tunnel_ethernet_dest(&ip6tnl);
    session_push(SESSION_ID);
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
    e = ft_find(&binding, cls.cookie);
    assert(e->ncrossed == 1 && e->crossed[0] == &ppp && ppp.refs == 1 && ip6tnl.refs == 1);
    links = ft_link_invalidations;
    device_event(&ppp, NETDEV_UNREGISTER, false);
    assert(handle.invalid && ft_link_invalidations == links + 1);
    ft_retire_workfn(NULL);
    assert(!ft_count && !ppp.refs && !ip6tnl.refs);
    drop_dev_records();
    /* A device one flow crosses and another names is named: eth3.100 under
     * one flow's eth3.100.300 and another's own logical device. An upper
     * change on it may change what that flow carries, and stops admission;
     * its unregistration only retires the two flows. */
    vlan_fixture(); cls.command = FLOW_CLS_REPLACE;
    route.dst.dev = &out_qinq;
    neighbour.dev = &out_qinq;
    encap_actions(0, (const u16[]){ 100, 300 }, 2);
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
    cls.cookie++; pk.src++;
    route.dst.dev = &out_tag;
    neighbour.dev = &out_tag;
    rule.action.entries[5] = rule.action.entries[6];
    rule.action.num_entries = 6;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0 && ft_count == 2);
    assert(out_tag.refs == 2 && ft_device_role(&out_tag) == FT_DEV_NAMED);
    device_event(&out_tag, NETDEV_CHANGEUPPER, true);
    assert(!handle.invalid);
    links = ft_link_invalidations;
    device_event(&out_tag, NETDEV_UNREGISTER, false);
    assert(handle.invalid && ft_link_invalidations == links + 1);
    ft_retire_workfn(NULL);
    assert(!ft_count && !out_tag.refs && !out_qinq.refs);
    drop_dev_records();
    /* Every device a flow names without it being a port leaves the same way:
     * a VLAN device, a bridge, a ppp device and a tunnel device, each its
     * flow's own logical device. The port's unregistration still stops
     * everything. */
    for (unsigned kind = 0; kind < 5; kind++) {
        struct net_device *named;

        switch (kind) {
        case 0: egress_tag_fixture(); named = &out_tag; break;
        case 1: bridge_fixture(); reverse_route.dst.dev = &in_br; named = &in_br; break;
        case 2: pppoe_out_fixture(); named = &ppp; break;
        case 3: ip6tnl_out_fixture(); named = &ip6tnl; break;
        default: vlan_fixture(); named = &out; break;
        }
        cls.command = FLOW_CLS_REPLACE;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0 && ft_count == 1);
        bool port = kind == 4;
        assert(ft_device_role(named) == (port ? FT_DEV_PORT : FT_DEV_NAMED));
        links = ft_link_invalidations;
        device_event(named, NETDEV_UNREGISTER, port);
        assert(handle.invalid == !port && ft_link_invalidations == links + !port);
        if (port) {
            ft_invalid = 0;
            remove_all();
        } else {
            ft_retire_workfn(NULL);
            assert(!ft_count && !named->refs);
            drop_dev_records();
        }
    }
    /* An installation that fails gives back what it took. */
    for (unsigned stage = 1; stage <= 3; stage++) {
        vlan_fixture();
        route.dst.dev = &out_qinq;
        neighbour.dev = &out_qinq;
        encap_actions(0, (const u16[]){ 100, 300 }, 2);
        ft_fail_stage = stage;
        cdx_ft_begin();
        assert(ft_replace(&binding, &cls) < 0);
        cdx_ft_end();
        assert(!ft_fail_stage && !ft_count && !out_tag.refs && !out_qinq.refs);
        drop_dev_records();
    }
}

/* A direction the MTU bound keeps out, offered again for as long as software
 * forwards it: refused before RTNL, never counted busy, retiring nothing. */
static void test_mtu_before_admission(void)
{
    static struct xfrm_state sa;
    struct cdx_ft_rule decoded;

    /* The PPPoE uplink: the download admitted through its session, the
     * upload from a 1500-byte LAN port refused -- offered in the order
     * Linux offers them, three rounds, RTNL held elsewhere every other one. */
    pppoe_in_fixture(); cls.command = FLOW_CLS_REPLACE;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0 && ft_count == 1);
    unsigned long download = cls.cookie;
    cls.cookie++; pk.src++;
    reverse_route.dst.dev = &in;
    ingress_session = (struct nf_flow_session){};
    route.dst.dev = &ppp;
    cls.nf_mtu = ppp.mtu;
    egress_session = (struct nf_flow_session){ .lower_ifindex = out.ifindex, .id = SESSION_ID };
    memcpy(egress_session.h_dest, AC_MAC, ETH_ALEN);
    zero_ethernet_dest();
    session_push(SESSION_ID);
    u64 busy = ft_busy, rejects = ft_rejects, validated = ft_validated;
    u64 admission = ft_admission_invalidations;
    unsigned trylocks = rtnl_trylocks, lookups = police_lookups;
    assert(ft_mtu_refused(&cls));
    for (unsigned offer = 0; offer < 3; offer++) {
        rtnl_busy = offer & 1;
        cls.cookie = download;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0);
        cls.cookie = download + 1;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EOPNOTSUPP);
    }
    rtnl_busy = false;
    assert(rtnl_trylocks == trylocks && ft_busy == busy && ft_rejects == rejects + 3);
    assert(ft_validated == validated && police_lookups == lookups);
    assert(!handle.invalid && ft_admission_invalidations == admission);
    assert(ft_count == 1 && ft_find(&binding, download) && !ft_find(&binding, download + 1));
    /* The refusal is the one ft_parse() makes. */
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP);
    remove_all();

    /* What is not certain goes to admission, which decides as before. TCP
     * is carried into the smaller path. */
    tcp_fixture(); cls.command = FLOW_CLS_REPLACE; cls.nf_mtu = 1492;
    trylocks = rtnl_trylocks;
    assert(!ft_mtu_refused(&cls));
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0 && ft_count == 1);
    assert(rtnl_trylocks == trylocks + 1);
    remove_all();
    /* With a policy configured an SA may exempt the direction, or a policy
     * deny it and retire the generation; the walk finds out which. */
    for (unsigned exempt = 0; exempt < 2; exempt++) {
        fixture(); cls.command = FLOW_CLS_REPLACE; cls.nf_mtu = 1492;
        xfrm_policies = true;
        ipsec_sa = exempt ? 7 : 0;
        trylocks = rtnl_trylocks;
        assert(!ft_mtu_refused(&cls));
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == (exempt ? 0 : -EOPNOTSUPP));
        assert(rtnl_trylocks == trylocks + 1 && ft_count == exempt);
        remove_all();
    }
    /* Nor is a transform on either destination left to this. */
    fixture(); cls.nf_mtu = 1492;
    route.dst.xfrm = &sa;
    assert(!ft_mtu_refused(&cls));
    fixture(); cls.nf_mtu = 1492;
    reverse_route.dst.xfrm = &sa;
    assert(!ft_mtu_refused(&cls));
    /* A request this cannot read is not one it refuses. */
    fixture(); cls.nf_mtu = 1492; bm.ip_proto = 0;
    assert(!ft_mtu_refused(&cls));
    fixture(); cls.nf_mtu = 1492; bm.n_proto = 0;
    assert(!ft_mtu_refused(&cls));
    fixture(); cls.nf_mtu = 1492; dissector.used_keys &= ~BIT_ULL(FLOW_DISSECTOR_KEY_BASIC);
    assert(!ft_mtu_refused(&cls));
    fixture(); cls.nf_mtu = 1492; cls.nf_dst_reverse = NULL;
    assert(!ft_mtu_refused(&cls));
    fixture(); cls.nf_mtu = 1492; cls.nf_dst = NULL;
    assert(!ft_mtu_refused(&cls));
    fixture(); cls.nf_mtu = 1492; cls.rule = NULL;
    assert(!ft_mtu_refused(&cls));
    /* Nor a path the bound admits, the ordinary Ethernet WAN. */
    fixture();
    assert(!ft_mtu_refused(&cls));

    /* IPv6 is refused on its own bound, the ingress IPv6 MTU, for every
     * protocol -- and admitted through RTNL once the LAN advertises the path. */
    for (unsigned tcp = 0; tcp < 2; tcp++) {
        fixture6(); cls.command = FLOW_CLS_REPLACE;
        if (tcp) tcp_flow();
        in.ip6_mtu = 1500;
        trylocks = rtnl_trylocks; busy = ft_busy;
        assert(ft_mtu_refused(&cls));
        rtnl_busy = true;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == -EOPNOTSUPP);
        rtnl_busy = false;
        assert(rtnl_trylocks == trylocks && ft_busy == busy && !handle.invalid && !ft_count);
        in.ip6_mtu = cls.nf_mtu;
        assert(!ft_mtu_refused(&cls));
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, &binding) == 0 && ft_count == 1);
        assert(rtnl_trylocks == trylocks + 1);
        remove_all();
    }
}

/* The early refusal never refuses what admission would admit: every ingress
 * shape the walk can find, both families, both protocols, with and without a
 * policy or an SA, across ingress MTUs and paths either side of each bound. And
 * where only the MTU can decide, it refuses exactly what admission refuses. */
static void test_mtu_refusal_sound(void)
{
    enum { PLAIN, SESSION, TUNNEL, SESSION_TUNNEL, TAG, BRIDGE,
           PLAIN6, SESSION6, TUNNEL6, SHAPES };
    static const int ingress[] = { 1280, 1400, 1440, 1452, 1460, 1480, 1491, 1492,
                                   1493, 1500, 1508, 9000 };
    static const u16 paths[] = { 68, 1279, 1280, 1400, 1440, 1451, 1452, 1453, 1459,
                                 1460, 1480, 1491, 1492, 1493, 1499, 1500, 1508, 9000 };
    unsigned refused = 0, exact = 0;

    for (unsigned shape = 0; shape < SHAPES; shape++)
    for (unsigned tcp = 0; tcp < 2; tcp++)
    for (unsigned sec = 0; sec < 4; sec++)
    for (unsigned i = 0; i < ARRAY_SIZE(ingress); i++)
    for (unsigned p = 0; p < ARRAY_SIZE(paths); p++) {
        struct net_device *logical;
        struct cdx_ft_rule decoded;

        switch (shape) {
        case PLAIN: fixture(); logical = &in; break;
        case SESSION: pppoe_in_fixture(); logical = &in_ppp; break;
        case TUNNEL: ip6tnl_in_fixture(); logical = &in_ip6tnl; break;
        case SESSION_TUNNEL:
            ip6tnl_in_fixture();
            ingress_tunnel.lower_ifindex = in_ppp.ifindex;
            memset(ingress_tunnel.h_dest, 0, ETH_ALEN);
            ingress_session = (struct nf_flow_session){ .lower_ifindex = in.ifindex,
                                                        .id = SESSION_ID + 1 };
            memcpy(ingress_session.h_dest, AC_MAC, ETH_ALEN);
            logical = &in_ip6tnl;
            break;
        case TAG: ingress_tag_fixture(); logical = &in_tag; break;
        case BRIDGE: bridge_fixture(); reverse_route.dst.dev = &in_br; logical = &in_br; break;
        case PLAIN6: fixture6(); logical = &in; break;
        case SESSION6:
            fixture6();
            reverse_route6.dst.dev = &in_ppp;
            ingress_session = (struct nf_flow_session){ .lower_ifindex = in.ifindex,
                                                        .id = SESSION_ID + 1 };
            memcpy(ingress_session.h_dest, AC_MAC, ETH_ALEN);
            logical = &in_ppp;
            break;
        default: sit_in_fixture(); logical = &in_sit; break;
        }
        if (tcp) tcp_flow(); else udp_flow();
        /* None, a policy claiming nothing, an SA sending, an SA receiving. */
        xfrm_policies = sec > 0;
        ipsec_sa = sec == 2 ? 7 : 0;
        ipsec_in_sa = sec == 3 ? 8 : 0;
        /* The IPv6 MTU follows the device's, so one number moves both. */
        logical->mtu = ingress[i];
        logical->ip6_mtu = 0;
        out.mtu = 9000;
        cls.nf_mtu = paths[p];
        bool early = ft_mtu_refused(&cls);
        int rc = ft_parse(&binding, &cls, &decoded, &next_hop);
        assert(!early || rc == -EOPNOTSUPP);
        refused += early;
        /* Behind a session under 4in6 the IPv4 bound is at its lowest, which
         * is the one the early refusal assumes; IPv6 reads nothing else. */
        if (!sec && ((shape == SESSION_TUNNEL && !tcp) || shape >= PLAIN6)) {
            assert(early == (rc != 0));
            exact++;
        }
        logical->mtu = logical == &in ? 1500 : logical == &in_ppp ? 1492 :
                       logical == &in_ip6tnl ? 1452 : logical == &in_sit ? 1480 : 1500;
        logical->ip6_mtu = 0;
        out.mtu = 1500;
    }
    assert(refused && exact);
    xfrm_policies = false;
    ipsec_sa = ipsec_in_sa = 0;
}

static void test_ipsec_generation_retirement(void)
{
    fixture();
    xfrm_genid++;
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    assert(handle.invalid && !ft_count && !live_hw && !allocated);
    for (unsigned sa = 0; sa < 2; sa++) {
        fixture();
        u64 before = sa ? ft_ipsec_invalidations : ft_ipsec_policy_invalidations;
        change_sa_on_add = sa;
        change_policy_on_add = !sa;
        assert(ft_replace(&binding, &cls) == -EIO);
        change_sa_on_add = change_policy_on_add = false;
        assert(handle.invalid && !ft_invalid && !ft_count && !live_hw && !allocated);
        assert(!ft_handle_refs && !ft_neighbour_refs && handle.refs == 1);
        assert((sa ? ft_ipsec_invalidations : ft_ipsec_policy_invalidations) == before + 1);
        /* A fresh generation can be admitted without rearming the backend. */
        handle = (struct nf_flow_offload_handle){ .refs = 1 };
        cls.nf_xfrm_genid = xfrm_genid;
        assert(ft_replace(&binding, &cls) == 0);
        struct net foreign = {0};
        unsigned kicks = mroute_kicks;
        u64 changes = ft_mr_xfrm_changes;
        ft_neigh_event(NULL, NETEVENT_XFRM_POLICY_UPDATE, &foreign);
        assert(!handle.invalid && mroute_kicks == kicks && ft_mr_xfrm_changes == changes);
        ft_neigh_event(NULL, NETEVENT_XFRM_POLICY_UPDATE, &init_net);
        assert(handle.invalid && ft_count == 1);
        /* And every routed group is asked again: an output policy can
         * govern a multicast copy, which nothing else would report. */
        assert(mroute_kicks == kicks + 1 && ft_mr_xfrm_changes == changes + 1);
        ft_retire_workfn(NULL);
        assert(!ft_count && !live_hw && !allocated && !ft_handle_refs && !ft_neighbour_refs);
    }
}

static void test_selective_routes(void)
{
    struct nf_flow_offload_handle contexts[2] = {{1, false}, {1, false}};
    struct cdx_ft_entry *entries[4];
    struct net other_net;
    struct netevent_ipv4_route event = { .net = &init_net, .dst = htonl(0xc0000202), .prefixlen = 32 };
    struct fib_notifier_info info = { .family = AF_INET };
    u64 invalidations = ft_route_invalidations, errors = ft_errors;

    fixture();
    for (unsigned i = 0; i < 4; i++) {
        __be32 address = htonl(i < 2 ? 0xc0000202 : 0xcb007102);
        ik.src = i & 1 ? htonl(0xc6336402) : address;
        ik.dst = i & 1 ? address : htonl(0xc6336402);
        cls.nf_handle = &contexts[i / 2]; cls.cookie = 6000 + i;
        route.rt_gw_family = AF_INET; route.rt_gw4 = gateway.primary_key.ip;
        assert(ft_replace(&binding, &cls) == 0);
        entries[i] = ft_find(&binding, cls.cookie);
        entries[i]->hw->stats.packets = 20 + i;
    }
    for (unsigned e = FIB_EVENT_ENTRY_REPLACE; e <= FIB_EVENT_ENTRY_DEL; e++)
        assert(ft_fib_event(NULL, e, &info) == NOTIFY_DONE && !ft_invalid);
    event.net = &other_net;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    event.net = &init_net; event.dst = htonl(0xc0000203);
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(!contexts[0].invalid && !contexts[1].invalid);
    /* A more-specific addition has no old-route pointer. It still marks both
     * directions, including the opposite direction's destination. */
    event.dst = htonl(0xc0000202);
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(contexts[0].invalid && !contexts[1].invalid && !ft_invalid);
    assert(ft_route_invalidations == invalidations + 1);
    ft_retire_workfn(NULL);
    assert(ft_count == 2 && contexts[0].refs == 1 && contexts[1].refs == 3);
    for (unsigned i = 2; i < 4; i++) {
        assert(ft_find(&binding, 6000 + i) == entries[i]);
        assert(entries[i]->hw->stats.packets == 20 + i);
    }
    /* Partial hardware admission must also match its missing reverse route. */
    assert(ft_remove(entries[3]) == 0);
    event.dst = htonl(0xcb007100); event.prefixlen = 24;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(contexts[1].invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && ft_errors == errors);
    assert(ft_route_invalidations == invalidations + 2);
    assert(contexts[1].refs == 1);

    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    event.dst = 0; event.prefixlen = 0;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    ft_retire_workfn(NULL);
    assert(handle.invalid && !ft_count && !ft_invalid);
    event.prefixlen = 33;
    ft_neigh_event(NULL, NETEVENT_IPV4_ROUTE_UPDATE, &event);
    assert(ft_invalid); ft_invalid = 0;
    for (unsigned e = FIB_EVENT_RULE_ADD; e <= FIB_EVENT_RULE_DEL; e++) {
        ft_fib_event(NULL, e, &info); assert(ft_invalid); ft_invalid = 0;
    }
    /* Policy changes need explicit recovery in either family, not just IPv4. */
    info.family = AF_INET6;
    ft_fib_event(NULL, FIB_EVENT_RULE_ADD, &info); assert(ft_invalid); ft_invalid = 0;
    /* A family this adapter forwards for neither of is still ignored outright. */
    info.family = AF_BRIDGE;
    ft_fib_event(NULL, FIB_EVENT_RULE_ADD, &info); assert(!ft_invalid);

    for (unsigned e = FIB_EVENT_NH_ADD; e <= FIB_EVENT_NH_DEL; e++) {
        fixture();
        struct nf_flow_offload_handle other = {1, false};
        u64 links = ft_link_invalidations;
        assert(ft_replace(&binding, &cls) == 0);
        cls.cookie++; pk.src++; cls.nf_handle = &other;
        assert(ft_replace(&binding, &cls) == 0);
        ft_fib_event(NULL, e, &info); /* Another family is ignored. */
        assert(!handle.invalid && !other.invalid);
        info.family = AF_INET;
        ft_fib_event(NULL, e, &info);
        ft_fib_event(NULL, e, &info);
        assert(handle.invalid && other.invalid && !ft_invalid);
        assert(ft_link_invalidations == links + 2);
        ft_retire_workfn(NULL);
        assert(!ft_count && !ft_handle_refs && !ft_neighbour_refs && !allocated);
        assert(handle.refs == 1 && other.refs == 1);
        info.family = AF_BRIDGE;
    }

    /* Queued admission may carry one current and one stale route. Refuse and
     * invalidate the entire generation before any hardware allocation. */
    for (unsigned which = 0; which < 4; which++) {
        fixture();
        if (which == 0) route.dst.valid = false;
        if (which == 1) reverse_route.dst.valid = false;
        if (which == 2) cls.nf_dst = NULL;
        if (which == 3) cls.nf_dst_reverse = NULL;
        assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
        assert(handle.invalid && handle.refs == 1 && !ft_handle_refs && !allocated && !live_hw);
    }
    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    reverse_route.dst.valid = false;
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP);
    ft_retire_workfn(NULL);
    assert(handle.invalid && !ft_count && !ft_handle_refs && !ft_neighbour_refs && !out.refs);
    assert(ft_installs == ft_deletes && ft_errors == errors);
}

/* A VLAN device's counter record outlives its flows by design, so a scenario
 * that ends with every flow retired still holds one per VLAN device the flows
 * crossed. Before a case asserts that nothing is left allocated, drop them the
 * way unload does -- after checking that no retired flow still references
 * one, which is the leak this would otherwise hide. */
static void drop_dev_records(void)
{
    struct cdx_ft_dev_stats *record;

    assert(!cdx_info->ctrl.mutex);
    list_for_each_entry(record, &ft_dev_stats, list)
        assert(!record->refs);
    ft_dev_stats_drop_all();
}

static void device_event(struct net_device *dev, unsigned long event, bool invalid)
{
    /* The largest info any event here carries; the common one leads it. */
    struct netdev_notifier_changeupper_info info = { .info.dev = dev };
    ft_invalid = 0; /* Isolate selection of each event without running work. */
    assert(ft_netdev_event(NULL, event, &info) == NOTIFY_DONE);
    assert(ft_invalid == invalid && !cdx_info->ctrl.mutex && !ft_watch_lock);
}

static void test_device_dependencies(void)
{
    struct net other_net;
    /* The same ifindex on another object must not match the bound port. */
    struct net_device unrelated = { .ifindex = in.ifindex };
    unsigned long events[] = { NETDEV_UNREGISTER, NETDEV_CHANGEUPPER };
    fixture();
    assert(!ft_bound && !ft_count && !ft_invalid);
    unsigned moved = mc_ports_moved;
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) device_event(&in, events[i], false);
    /* A device changing its master is the bridged multicast learner's news
     * as well: a flow's ingress may have left its bridge, which nothing else
     * reports. Unregistration reaches it by its own way. */
    assert(mc_ports_moved == moved + 1);
    /* Leaving names the bridge left, whose memberships of the port go with
     * it; joining names none. */
    {
        struct net_device bridge = { .ifindex = 90 };
        struct netdev_notifier_changeupper_info up = {
            .info.dev = &in, .upper_dev = &bridge, .master = true,
        };

        assert(ft_netdev_event(NULL, NETDEV_CHANGEUPPER, &up) == NOTIFY_DONE);
        assert(mc_ports_moved == moved + 2 && mc_port_left == &bridge);
        up.linking = true;
        assert(ft_netdev_event(NULL, NETDEV_CHANGEUPPER, &up) == NOTIFY_DONE);
        assert(mc_ports_moved == moved + 3 && !mc_port_left);
        assert(!ft_invalid);
    }
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) {
        device_event(&in, events[i], true); /* Empty binding still matters. */
        device_event(&out, events[i], false);
        device_event(&unrelated, events[i], false);
    }
    in.net = &other_net;
    device_event(&in, NETDEV_CHANGEUPPER, false);
    in.net = NULL;
    device_event(&in, NETDEV_REGISTER, false);
    struct flow_block_cb *cb = flow_block_cb_lookup(&block, ft_rule_callback, &in);
    assert(cb && ft_replace(cb->cb_priv, &cls) == 0);
    assert(ft_bound == 1 && in.refs == 1 && out.refs == 1);
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) {
        device_event(&out, events[i], true); /* Egress has no binding. */
        device_event(&in, events[i], true);
        device_event(&unrelated, events[i], false);
    }
    device_event(&out, NETDEV_CHANGEUPPER, true);
    ft_invalidate_work(NULL);
    assert(ft_invalid_done && !ft_count && !ft_handle_refs && !ft_neighbour_refs && !out.refs);
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_bound && !in.refs && !allocated && !live_hw);
    /* No stale watch can follow the released binding into its replacement. */
    assert(bind_device(&unrelated, FLOW_BLOCK_BIND) == 0);
    device_event(&in, NETDEV_CHANGEUPPER, false);
    device_event(&out, NETDEV_CHANGEUPPER, false);
    device_event(&unrelated, NETDEV_CHANGEUPPER, true);
    ft_invalid = 0;
    assert(bind_device(&unrelated, FLOW_BLOCK_UNBIND) == 0);
    assert(!unrelated.refs && !ft_bound && !allocated);
    /* Installation rollback must also remove the egress watch. */
    fixture();
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
    cb = flow_block_cb_lookup(&block, ft_rule_callback, &in);
    for (unsigned stage = 2; stage <= 3; stage++) {
        ft_fail_stage = stage;
        assert(ft_replace(cb->cb_priv, &cls) < 0 && !ft_count && !out.refs);
        device_event(&out, NETDEV_CHANGEMTU, false);
    }
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_bound && !in.refs && !allocated && ft_installs == ft_deletes);
}

/* A real gateway binds one flowtable to every port that forwards: a WAN and
 * three bridged LANs is four, and nothing pairs two bindings -- a direction's
 * egress needs no binding of its own. Fill the table to its stated bound and
 * check the paths that walk bindings rather than count them: admission is
 * still one per device, and invalidation still flushes Netfilter's cache for
 * every bound device, not for the first two it snapshots. */
static void test_binding_capacity(void)
{
    struct net_device ports[CDX_FT_MAX_TABLE_DEVICES + 1];
    unsigned i, before;

    fixture();
    assert(!ft_bound && !ft_count && !ft_invalid && !allocated);
    for (i = 0; i < ARRAY_SIZE(ports); i++)
        ports[i] = (struct net_device){ .ifindex = 1000 + (int)i, .mtu = 1500,
            .type = ARPHRD_ETHER, .dev_addr = {2, 0, 0, 0, 1, (u8)i} };
    for (i = 0; i < CDX_FT_MAX_TABLE_DEVICES; i++) {
        assert(bind_device(&ports[i], FLOW_BLOCK_BIND) == 0);
        assert(ft_bound == i + 1 && ports[i].refs == 1);
        /* One binding per device, whatever the count is -- while there is
         * room, since a full table refuses everything before it looks at
         * which device is asking. */
        if (ft_bound < CDX_FT_MAX_TABLE_DEVICES)
            assert(bind_device(&ports[i], FLOW_BLOCK_BIND) == -EBUSY);
        assert(ft_bound == i + 1 && ports[i].refs == 1);
    }
    /* Past the last port the backend could ever describe. */
    assert(bind_device(&ports[i], FLOW_BLOCK_BIND) == -EOPNOTSUPP && !ports[i].refs);
    assert(bind_device(&ports[0], FLOW_BLOCK_BIND) == -EOPNOTSUPP && ports[0].refs == 1);
    before = flushed;
    ft_invalidate();
    ft_invalidate_work(NULL);
    assert(flushed - before == CDX_FT_MAX_TABLE_DEVICES && ft_invalid_done);
    for (i = 0; i < CDX_FT_MAX_TABLE_DEVICES; i++) {
        assert(bind_device(&ports[i], FLOW_BLOCK_UNBIND) == 0);
        assert(!ports[i].refs);
    }
    assert(!ft_bound && !allocated && ft_installs == ft_deletes);
    ft_invalid = 0;
    ft_invalid_done = false;
}

/* A consumer replaces its table in one transaction: Netfilter binds the new
 * flowtable while preparing it and unbinds the old one only at commit. OpenWrt's
 * firewall also probes offload with a second table while its own is bound. Both
 * have to bind beside the live table without disturbing it; a refusal aborts
 * the whole firewall transaction, or turns the probe into a silent fallback to
 * software. The same table twice on one device, or a third table at once, is
 * still refused. */
static void test_table_handover(void)
{
    static struct nf_flowtable next_table, probe_table;
    static struct flow_block next_block, probe_block;
    struct net_device wan = { .ifindex = 71, .mtu = 1500, .type = ARPHRD_ETHER,
                              .dev_addr = {2, 0, 0, 0, 2, 1} };
    struct net_device lan = { .ifindex = 72, .mtu = 1500, .type = ARPHRD_ETHER,
                              .dev_addr = {2, 0, 0, 0, 2, 2} };
    struct cdx_ft_binding *binding;

    fixture();
    list_init(&next_block.cb_list);
    list_init(&probe_block.cb_list);
    assert(bind_device(&wan, FLOW_BLOCK_BIND) == 0);
    assert(bind_device(&lan, FLOW_BLOCK_BIND) == 0);
    assert(bind_device(&wan, FLOW_BLOCK_BIND) == -EBUSY && wan.refs == 1);

    /* The replacement binds the same devices beside the live table. */
    assert(bind_to(&wan, FLOW_BLOCK_BIND, &next_table, &next_block) == 0);
    assert(bind_to(&lan, FLOW_BLOCK_BIND, &next_table, &next_block) == 0);
    assert(ft_bound == 4 && wan.refs == 2 && lan.refs == 2);
    /* A third table at once is not a handover. */
    assert(bind_to(&wan, FLOW_BLOCK_BIND, &probe_table, &probe_block) == -EBUSY);
    assert(ft_bound == 4 && wan.refs == 2);

    /* Commit unbinds the old table and leaves the new one bound. */
    assert(bind_device(&wan, FLOW_BLOCK_UNBIND) == 0);
    assert(bind_device(&lan, FLOW_BLOCK_UNBIND) == 0);
    assert(ft_bound == 2 && wan.refs == 1 && lan.refs == 1);
    list_for_each_entry(binding, &ft_bindings, list)
        assert(binding->table == &next_table);

    /* A probe binds and unbinds a second table while the live one stays. */
    assert(bind_to(&wan, FLOW_BLOCK_BIND, &probe_table, &probe_block) == 0);
    assert(bind_to(&wan, FLOW_BLOCK_UNBIND, &probe_table, &probe_block) == 0);
    assert(ft_bound == 2 && wan.refs == 1);
    list_for_each_entry(binding, &ft_bindings, list)
        assert(binding->table == &next_table);

    assert(bind_to(&wan, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
    assert(bind_to(&lan, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
    assert(!ft_bound && !wan.refs && !lan.refs && !allocated);
}

/* The same handover after an invalidation. Netfilter binds the replacement
 * while the invalidated table is still bound, so the bind that used to rearm
 * admission always finds a live binding in the way, and refusing it failed the
 * consumer's whole reload. The replacement is parked instead -- bound, counted,
 * declining every flow -- and made live, with the invalidation cleared and one
 * rearm counted, as soon as the old bindings are gone and the hardware has
 * drained. Three events can complete that: the release of the last old
 * binding, the worker's completion, and the retry of a barrier still owed. */
static void test_parked_rearm(void)
{
    static struct nf_flowtable next_table;
    static struct flow_block next_block;
    struct cdx_ft_binding *parked_in, *parked_out;
    u64 rearms = ft_rearms, errors = ft_errors, rejects, admissions;
    unsigned tries, retries;

    fixture();
    list_init(&block.cb_list);
    list_init(&next_block.cb_list);
    assert(!ft_bound && !ft_parked && !ft_passive && !ft_invalid && !allocated);

    /* The live table, with a direction in hardware. */
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
    assert(bind_device(&out, FLOW_BLOCK_BIND) == 0);
    cls.command = FLOW_CLS_REPLACE;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, bound_to(&block, &in)) == 0);
    assert(ft_count == 1 && live_hw == 1 && handle.refs == 2);
    /* Invalidated and drained: the entry is retired, the table stays bound. */
    ft_invalidate();
    ft_invalidate_work(NULL);
    assert(ft_invalid && ft_invalid_done && !ft_count && !live_hw && ft_bound == 2);
    assert(handle.refs == 1 && !ft_handle_refs && !ft_neighbour_refs && !can_rearm());

    /* Prepare binds the replacement beside it: accepted, and parked. */
    assert(bind_to(&in, FLOW_BLOCK_BIND, &next_table, &next_block) == 0);
    assert(bind_to(&out, FLOW_BLOCK_BIND, &next_table, &next_block) == 0);
    parked_in = bound_to(&next_block, &in);
    parked_out = bound_to(&next_block, &out);
    assert(parked_in && parked_in->parked && parked_out && parked_out->parked);
    assert(ft_bound == 4 && ft_parked == 2 && in.refs == 2 && out.refs == 2);
    assert(next_table.use_neigh && next_table.use_hw_handles);
    assert(ft_invalid && ft_rearms == rearms && !can_rearm());
    /* A third table is still one too many, parked or not. */
    {
        static struct nf_flowtable third_table;
        static struct flow_block third_block;

        list_init(&third_block.cb_list);
        assert(bind_to(&in, FLOW_BLOCK_BIND, &third_table, &third_block) == -EBUSY);
        assert(ft_bound == 4 && ft_parked == 2 && in.refs == 2);
    }

    /* A flow offered to the parked table stays in software without taking
     * RTNL, and nothing about it changes: its handle is still valid, so the
     * next refresh can offer it again. */
    fixture();
    cls.command = FLOW_CLS_REPLACE;
    rejects = ft_rejects;
    admissions = ft_admission_invalidations;
    rtnl_busy = true;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, parked_in) == -EOPNOTSUPP);
    rtnl_busy = false;
    assert(!ft_count && !live_hw && !handle.invalid && handle.refs == 1);
    assert(ft_rejects == rejects + 1 && ft_admission_invalidations == admissions);
    cls.command = FLOW_CLS_STATS;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, parked_in) == -ENOENT);
    cls.command = FLOW_CLS_DESTROY;
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, parked_in) == 0);
    cls.command = FLOW_CLS_REPLACE;

    /* Commit releases the old table. The first release leaves a live one. */
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(ft_invalid && ft_parked == 2 && ft_rearms == rearms);
    /* The last is what the parked table waited for. */
    assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
    assert(!ft_invalid && !ft_invalid_done && !ft_parked && ft_rearms == rearms + 1);
    assert(!parked_in->parked && !parked_out->parked && ft_bound == 2);
    assert(in.refs == 1 && out.refs == 1 && block.cb_list.next == &block.cb_list);
    /* The same flow's next refresh is admitted, with no reload. */
    assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, parked_in) == 0);
    assert(ft_count == 1 && live_hw == 1 && handle.refs == 2);

    /* The worker's completion finishes the drain when the old bindings left
     * first, here while it was still retrying a barrier. */
    ft_invalidate();
    retry_error = -EAGAIN;
    ft_invalidate_work(NULL);
    assert(ft_invalid && !ft_invalid_done && !ft_count && !live_hw);
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0 && bind_device(&out, FLOW_BLOCK_BIND) == 0);
    assert(ft_parked == 2 && bound_to(&block, &in)->parked && bound_to(&block, &out)->parked);
    assert(bind_to(&in, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
    assert(bind_to(&out, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
    assert(ft_invalid && ft_parked == 2 && ft_bound == 2 && ft_rearms == rearms + 1);
    retry_error = 0;
    ft_invalidate_work(NULL);
    assert(!ft_invalid && !ft_invalid_done && !ft_parked && ft_rearms == rearms + 2);
    assert(!bound_to(&block, &in)->parked && !bound_to(&block, &out)->parked);

    /* A deletion CDX parked for a path of its own. Nothing the adapter does
     * completes it, so the parked binding retries the barrier every second,
     * and the retry that completes one releases the backlog and rearms. */
    ft_invalidate();
    ft_invalidate_work(NULL);
    assert(ft_invalid && ft_invalid_done);
    legacy_pending = 1; barrier_fails = true;
    tries = recoveries; retries = rearm_retries;
    assert(bind_to(&in, FLOW_BLOCK_BIND, &next_table, &next_block) == 0);
    /* Not while a live binding is still in the way. */
    assert(ft_parked == 1 && recoveries == tries && rearm_retries == retries);
    assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
    assert(ft_parked == 1 && recoveries == tries && rearm_retries == retries);
    assert(bind_device(&out, FLOW_BLOCK_UNBIND) == 0);
    assert(ft_parked == 1 && ft_invalid && recoveries == tries + 1 && rearm_retries == retries + 1);
    ft_rearm_workfn(NULL);
    assert(ft_parked == 1 && ft_invalid && recoveries == tries + 2 && rearm_retries == retries + 2);
    assert(legacy_pending == 1);
    barrier_fails = false;
    ft_rearm_workfn(NULL);
    assert(!ft_parked && !ft_invalid && ft_rearms == rearms + 3 && !legacy_pending);
    assert(recoveries == tries + 3 && rearm_retries == retries + 2);
    /* A retry that was already queued finds nothing left to do. */
    ft_rearm_workfn(NULL);
    assert(ft_rearms == rearms + 3 && rearm_retries == retries + 2);
    /* And a deletion of the backend's own that the retry proves at once. */
    ft_invalidate();
    ft_invalidate_work(NULL);
    private_pending = 1;
    tries = recoveries;
    assert(bind_to(&out, FLOW_BLOCK_BIND, &next_table, &next_block) == 0);
    assert(ft_parked == 1 && bound_to(&next_block, &out)->parked);
    assert(bind_to(&in, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
    assert(!private_pending && !ft_parked && !ft_invalid && ft_rearms == rearms + 4);
    assert(recoveries == tries + 1 && rearm_retries == retries + 2);

    /* Past the binding bound a bind is passive: ft_invalidate_work()'s device
     * snapshot is sized by it. */
    {
        unsigned bound = ft_bound;

        ft_bound = CDX_FT_MAX_BINDINGS;
        assert(bind_to(&in, FLOW_BLOCK_BIND, &next_table, &next_block) == 0);
        assert(ft_passive == 1 && ft_bound == CDX_FT_MAX_BINDINGS && !ft_parked);
        assert(!bound_to(&next_block, &in) && !in.refs);
        /* A bind the table checks refuse is still refused there. */
        assert(bind_to(&out, FLOW_BLOCK_BIND, &next_table, &next_block) == -EBUSY);
        assert(ft_passive == 1 && out.refs == 1);
        ft_bound = bound;
        assert(bind_to(&in, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0 && !ft_passive);
    }

    /* An event raised while a table is parked. That table keeps making
     * software flows the event may have made stale, so the event is counted
     * and the rearm waits for a pass that flushes them; folded into the latch,
     * it would let those flows into hardware afterwards. */
    {
        unsigned flushes;
        int seq;

        list_init(&block.cb_list);
        ft_invalidate();
        ft_invalidate_work(NULL);
        assert(ft_invalid && ft_invalid_done && ft_bound == 1 && can_rearm() == false);
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0 && ft_parked == 1);
        seq = ft_invalid_seq;
        ft_invalidate();
        assert(ft_invalid_seq == seq + 1);
        assert(bind_to(&out, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
        assert(ft_invalid && ft_parked == 1 && ft_rearms == rearms + 4 && !can_rearm());
        flushes = flushed;
        ft_invalidate_work(NULL);
        assert(flushed == flushes + 1 && ft_done_seq == ft_invalid_seq);
        assert(!ft_invalid && !ft_parked && ft_rearms == rearms + 5);
        /* A pass left queued behind that rearm finds the latch clear and does
         * nothing at all. */
        flushes = flushed;
        ft_invalidate_work(NULL);
        assert(flushed == flushes && !ft_invalid && !ft_invalid_done);

        /* The same event counted by a notifier on another CPU between the
         * rearm clearing the latch and reading the count: the latch is put
         * back and the table stays parked for the event's own pass. */
        ft_invalidate();
        ft_invalidate_work(NULL);
        assert(bind_to(&out, FLOW_BLOCK_BIND, &next_table, &next_block) == 0 && ft_parked == 1);
        barrier_hook = ft_invalidate;
        assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
        assert(!barrier_hook && ft_invalid && ft_parked == 1 && ft_rearms == rearms + 5);
        assert(bound_to(&next_block, &out)->parked);
        ft_invalidate_work(NULL);
        assert(!ft_invalid && !ft_parked && ft_rearms == rearms + 6);

        /* A table that already holds flows gaining a device: those flows may
         * predate the latch and ride a device no pass flushed, so the bind
         * itself asks for a pass before the table can go live. */
        ft_invalidate();
        ft_invalidate_work(NULL);
        table.rhashtable.nelems = 3;
        unsigned queued = scheduled;
        seq = ft_invalid_seq;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0 && ft_parked == 1);
        assert(scheduled == queued + 1 && ft_invalid_seq == seq + 1);
        assert(bind_to(&out, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
        assert(ft_invalid && ft_parked == 1 && ft_rearms == rearms + 6);
        flushes = flushed;
        ft_invalidate_work(NULL);
        assert(flushed == flushes + 1 && !ft_invalid && !ft_parked && ft_rearms == rearms + 7);
        table.rhashtable.nelems = 0;
        assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
        assert(bind_to(&out, FLOW_BLOCK_BIND, &next_table, &next_block) == 0 && !ft_parked);
    }

    assert(bind_to(&out, FLOW_BLOCK_UNBIND, &next_table, &next_block) == 0);
    assert(!ft_bound && !ft_parked && !ft_passive && !ft_count && !live_hw && !allocated);
    assert(!in.refs && !out.refs && handle.refs == 1 && !ft_handle_refs && !ft_neighbour_refs);
    assert(!ft_invalid && !ft_invalid_done && ft_errors == errors && !rtnl);
    assert(ft_bindings.next == &ft_bindings && ft_block_list.next == &ft_block_list);
}

/* OpenWrt's firewall declares `counter` on every flowtable it renders, with no
 * option to turn it off, so refusing a counter-enabled table refuses the only
 * configuration the consumer actually ships. The two counters disagree about
 * framing rather than about packets: hardware counts the frame as it arrived,
 * Netfilter counts what it forwards, after the encapsulation has been popped. */
static void test_counter_accounting(void)
{
    struct cdx_ft_rule framing = {};
    struct cdx_ft_entry *e;

    /* Every ingress shape the subtraction has to describe. */
    assert(ft_l2_overhead(&framing) == ETH_HLEN);
    framing.in_vlans = 1;
    assert(ft_l2_overhead(&framing) == ETH_HLEN + VLAN_HLEN);
    framing.in_vlans = 2;
    assert(ft_l2_overhead(&framing) == ETH_HLEN + 2 * VLAN_HLEN);
    framing.in_session.present = true;
    assert(ft_l2_overhead(&framing) == ETH_HLEN + 2 * VLAN_HLEN + PPPOE_SES_HLEN);
    framing.in_vlans = 0;
    assert(ft_l2_overhead(&framing) == ETH_HLEN + PPPOE_SES_HLEN);
    /* SEC removed the ingress stack and inserted one private identity tag. */
    framing.in_vlans = 2;
    framing.in_sa_handle = 1;
    assert(ft_l2_overhead(&framing) == ETH_HLEN + VLAN_HLEN);
    /* An egress tag is pushed after the hit was counted and changes nothing. */
    framing = (struct cdx_ft_rule){ .out_vlans = 2, .out_session = { .present = true } };
    assert(ft_l2_overhead(&framing) == ETH_HLEN);

    fixture();
    cls.nf_counter = true;
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1);
    e = ft_find(&binding, cls.cookie);
    assert(e && !e->rule.in_vlans && !e->rule.in_session.present);
    /* Ten 256-byte UDP payloads: 14 + 20 + 8 + 256 on the wire, and the 284
     * Netfilter would have counted for each after popping the Ethernet header. */
    e->hw->stats.packets = 10;
    e->hw->stats.bytes = 10 * 298;
    cls.stats = (struct flow_stats){0};
    assert(ft_stats(e, &cls) == 0 && !ft_invalid);
    assert(cls.stats.pkts == 10 && cls.stats.bytes == 10 * 284);
    /* A later sample reports its own delta, corrected the same way. */
    e->hw->stats.packets = 15;
    e->hw->stats.bytes = 15 * 298;
    cls.stats = (struct flow_stats){0};
    assert(ft_stats(e, &cls) == 0 && cls.stats.pkts == 5 && cls.stats.bytes == 5 * 284);
    /* A delta too small to carry its own framing reports nothing, rather than
     * underflowing into an enormous unsigned byte count. */
    e->hw->stats.packets = 16;
    e->hw->stats.bytes += 4;
    cls.stats = (struct flow_stats){0};
    assert(ft_stats(e, &cls) == 0 && cls.stats.pkts == 1 && cls.stats.bytes == 0);
    /* The hardware counts the internal shim; conntrack counts only IP. */
    e->rule.in_sa_handle = 1;
    e->hw->stats.packets += 32;
    e->hw->stats.bytes += 32 * (256 + ETH_HLEN + VLAN_HLEN);
    cls.stats = (struct flow_stats){0};
    assert(ft_stats(e, &cls) == 0 && cls.stats.pkts == 32 && cls.stats.bytes == 32 * 256);
    e->rule.in_sa_handle = 0;
    assert(ft_remove(e) == 0 && !ft_count && !allocated && !live_hw);
    cls.nf_counter = false;
}

static void test_device_recovery(void)
{
    struct net other_net;
    struct net_device unrelated = { .ifindex = in.ifindex };
    struct netdev_notifier_info info = { .dev = &unrelated };
    struct fib_notifier_info policy = { .family = AF_INET };
    u64 rearms = ft_rearms;

    unsigned long events[] = {NETDEV_CHANGEMTU, NETDEV_GOING_DOWN, NETDEV_CHANGEADDR};
    for (unsigned e = 0; e < ARRAY_SIZE(events); e++) {
        unsigned long event = events[e];
        u64 *counter = event == NETDEV_CHANGEMTU ? &ft_mtu_invalidations :
                       event == NETDEV_CHANGEADDR ? &ft_mac_invalidations : &ft_link_invalidations;
        for (unsigned tcp = 0; tcp < 2; tcp++) {
            for (unsigned egress = 0; egress < 2; egress++) {
                struct nf_flow_offload_handle queued = {1, false}, fresh = {1, false};
                u64 invalidations = *counter;
                if (tcp) tcp_fixture(); else fixture();
                assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
                struct cdx_ft_binding *b = list_entry(ft_bindings.next, struct cdx_ft_binding, list);
                info.dev = &in;
                ft_netdev_event(NULL, event, &info);
                assert(!ft_invalid && *counter == invalidations); /* Empty binding. */
                assert(ft_replace(b, &cls) == 0);
                cls.cookie++; pk.src++;
                assert(ft_replace(b, &cls) == 0); /* Two entries share one flow generation. */
                info.dev = &out;
                ft_netdev_event(NULL, NETDEV_CHANGENAME, &info);
                ft_netdev_event(NULL, NETDEV_CHANGE, &info);
                assert(!handle.invalid && !ft_invalid); /* Same object, healthy carrier. */
                info.dev = &unrelated;
                ft_netdev_event(NULL, event, &info);
                info.dev = &in; in.net = &other_net;
                ft_netdev_event(NULL, event, &info);
                in.net = NULL;
                assert(!handle.invalid && *counter == invalidations);
                info.dev = egress ? &out : &in; /* Egress has no binding of its own. */
                unsigned marked = ipsec_marked_device;
                ft_netdev_event(NULL, event, &info);
                ft_netdev_event(NULL, event, &info);
                assert(handle.invalid && *counter == invalidations + 1);
                /* An SA riding the port carries both its address and, in the
                 * MTU it fragments SEC's output to, its MTU: each asks the
                 * SA to follow. Going down retires flows and leaves SAs. */
                assert(ipsec_marked_device == marked + (event == NETDEV_GOING_DOWN ? 0 : 2));
                assert(!ft_invalid && !ft_invalid_done && ft_count == 2 && handle.refs == 3);
                ft_retire_workfn(NULL);
                assert(ft_bound == 1 && !ft_count && !ft_handle_refs && !ft_neighbour_refs);
                assert(handle.refs == 1 && in.refs == 1 && !out.refs && !live_hw);

                /* IPv4 invalidates both cached dsts on MTU change. Even a queued
                 * request whose own egress is unchanged must reject the old
                 * reverse route, before allocation, and invalidate its handle. */
                cls.nf_handle = &queued; reverse_route.dst.valid = false;
                assert(ft_replace(b, &cls) == -EOPNOTSUPP && queued.invalid && queued.refs == 1);
                assert(!ft_count && !ft_invalid);
                reverse_route.dst.valid = true; cls.nf_handle = &fresh;
                physical_ok = false;
                assert(ft_replace(b, &cls) == -EOPNOTSUPP && !ft_count && !ft_invalid);
                physical_ok = true;
                out.mtu = cls.nf_mtu = 1400;
                /* Now smaller than what the ingress receives, which only a
                 * TCP direction is carried into: a UDP one stays in software. */
                if (!tcp) {
                    assert(ft_replace(b, &cls) == -EOPNOTSUPP && !ft_count && !ft_invalid);
                    tcp_flow();
                }
                assert(ft_replace(b, &cls) == 0);
                assert(ft_find(b, cls.cookie)->rule.mtu == 1400 && ft_bound == 1);
                assert(ft_rearms == rearms); /* No table recreation or global rearm. */

                /* MTU recovery must not reopen admission after a policy event. */
                ft_fib_event(NULL, FIB_EVENT_RULE_ADD, &policy);
                ft_netdev_event(NULL, event, &info);
                ft_retire_workfn(NULL);
                assert(ft_invalid && !ft_invalid_done && ft_count == 1 && fresh.invalid);
                ft_invalidate_work(NULL);
                assert(ft_invalid_done && ft_invalid && !ft_count);
                ft_netdev_event(NULL, event, &info);
                assert(ft_invalid_done && ft_invalid && ft_rearms == rearms);
                assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
                assert(!allocated && !in.refs && !out.refs && fresh.refs == 1);
                ft_invalid = 0; ft_invalid_done = false; out.mtu = 1500;
            }
        }
    }
    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    info.dev = &out; out.carrier_lost = true;
    ft_netdev_event(NULL, NETDEV_CHANGE, &info);
    assert(handle.invalid && !ft_invalid);
    ft_retire_workfn(NULL);
    assert(!ft_count && !ft_handle_refs && !allocated);
    out.carrier_lost = false;
    fixture();
    out.dev_addr[5] ^= 1;
    u64 macs = ft_mac_invalidations;
    assert(ft_replace(&binding, &cls) == -ESTALE && handle.invalid);
    assert(!ft_count && !ft_invalid && ft_mac_invalidations == macs + 1);
    out.dev_addr[5] ^= 1;
    for (unsigned fatal = 0; fatal < 2; fatal++) {
        fixture();
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0);
        struct cdx_ft_binding *b = list_entry(ft_bindings.next, struct cdx_ft_binding, list);
        assert(ft_replace(b, &cls) == 0);
        info.dev = &out;
        unsigned rechecks = mc_rechecks, kicks = mroute_kicks;
        ft_netdev_event(NULL, NETDEV_CHANGEMTU, &info);
        /* Both multicast learners hear it too: a group is carried only while
         * no copy can outgrow a listener, installed groups included. */
        assert(mc_rechecks == rechecks + 1 && mroute_kicks == kicks + 1);
        deletion_error = fatal ? -EIO : -EAGAIN;
        ft_retire_workfn(NULL);
        deletion_error = 0;
        assert(ft_invalid && ft_fatal == !!fatal && !ft_count);
        ft_invalidate_work(NULL);
        ft_netdev_event(NULL, NETDEV_CHANGEMTU, &info);
        assert(ft_invalid && ft_invalid_done && ft_fatal == !!fatal);
        assert(ft_rearms == rearms && handle.refs == 1);
        assert(bind_device(&in, FLOW_BLOCK_UNBIND) == 0);
        assert(!allocated && !live_hw && !ft_handle_refs && !ft_neighbour_refs);
        ft_invalid = 0; ft_invalid_done = ft_fatal = false;
    }
    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    unsigned scheduled_before = neigh_scheduled;
    ft_stopping = true; info.dev = &out;
    ft_netdev_event(NULL, NETDEV_CHANGEMTU, &info);
    assert(handle.invalid && neigh_scheduled == scheduled_before);
    ft_retire_workfn(NULL);
    assert(ft_count == 1); /* Unload owns this entry now. */
    assert(ft_remove(ft_find(&binding, cls.cookie)) == 0);
    ft_stopping = false;
    assert(ft_installs == ft_deletes && !allocated);
}

static void test_nexthop_objects(void)
{
    unsigned long events[] = {NEXTHOP_EVENT_DEL, NEXTHOP_EVENT_REPLACE,
        NEXTHOP_EVENT_RES_TABLE_PRE_REPLACE, NEXTHOP_EVENT_BUCKET_REPLACE, 999};
    ft_invalid = 0;
    assert(ft_nexthop_event(NULL, NEXTHOP_EVENT_HW_STATS_REPORT_DELTA, NULL) == NOTIFY_DONE);
    assert(!ft_invalid);
    for (unsigned i = 0; i < ARRAY_SIZE(events); i++) {
        assert(ft_nexthop_event(NULL, events[i], NULL) == NOTIFY_DONE);
        assert(ft_invalid); ft_invalid = 0;
    }
}

/* The conntrack mark is the only classification key, and one decode serves both
 * the hardware rule and the software Tx path, so what it produces is a contract
 * rather than an implementation detail. Three nibbles, each with a sentinel
 * meaning "unspecified": class queue, channel, ingress policer profile. */
/* A DSCP filter turning a port's map on or off marks what is installed there
 * and then waits for it to leave the hardware before the map may go to another
 * port: the map is one table with no port in it. Neither op relies on the
 * caller's RTNL, so both are driven here without it. */
static void test_egress_drain(void)
{
    u64 before;

    /* Nothing marked, nothing to wait for. */
    fixture();
    assert(!rtnl);
    assert(!ft_egress_drain(&out));

    /* An entry on the port is marked, and the drain is what takes it out of
     * the hardware. */
    assert(ft_replace(&binding, &cls) == 0 && ft_count == 1 && live_hw == 1);
    before = ft_qos_invalidations;
    ft_egress_changed(&out);
    assert(!rtnl && ft_qos_invalidations == before + 1 && handle.invalid && ft_count == 1);
    assert(!ft_egress_drain(&out));
    assert(!ft_count && !live_hw && !allocated && !out.refs);

    /* An admission the change races. The entry is on the watch list before
     * its hardware entry is built, so the change marks it mid-install and
     * the admission takes back what it built rather than leaving an entry
     * decided from the state before the change. */
    fixture();
    egress_change_on_add = &out;
    before = ft_qos_invalidations;
    assert(ft_replace(&binding, &cls) == -EIO);
    egress_change_on_add = NULL;
    assert(ft_qos_invalidations == before + 1 && !ft_count && !live_hw && !allocated);

    /* A global invalidation retires everything itself, and while its
     * recovery cannot prove the hardware stopped, nothing can be promised. */
    fixture();
    assert(ft_replace(&binding, &cls) == 0);
    list_add_tail(&binding.list, &ft_bindings);
    ft_invalid = 1; ft_invalid_done = false; ft_fatal = true; rtnl_busy = true;
    assert(ft_egress_drain(&out) == -EAGAIN);
    assert(!ft_count && !live_hw && !ft_invalid_done);
    rtnl_busy = false;
    assert(!ft_egress_drain(&out) && ft_invalid_done);
    list_del(&binding.list);
    ft_invalid = 0; ft_invalid_done = false; ft_fatal = false;

    /* A rearm landing while the drain waits clears the latch and resets the
     * done flag with it; it only rearms a finished invalidation, so the
     * drain is done too rather than asked to come back. */
    ft_invalid = 1; ft_invalid_done = false; rearm_in_flush = true;
    assert(!ft_egress_drain(&out));
    rearm_in_flush = false;
    assert(!ft_invalid && !ft_invalid_done);

    /* An unload in progress retires everything on its own schedule. */
    ft_stopping = true;
    assert(ft_egress_drain(&out) == -EAGAIN);
    ft_stopping = false;

    /* An SA on the port whose rebuild is outstanding -- being rebuilt by a
     * pass now, or failed and waiting: a pass is asked for and waited on,
     * outside the control transaction every pass takes, and only a rebuild
     * that happened lets the drain say so. */
    ipsec_rebuild_pending_on = &out;
    ipsec_rebuild_succeeds = false;
    follow_scheduled = follow_flushes = 0;
    assert(ft_egress_drain(&out) == -EAGAIN);
    assert(follow_scheduled == 1 && follow_flushes == 1);
    assert(!ft_egress_drain(&decoy));
    ipsec_rebuild_succeeds = true;
    assert(!ft_egress_drain(&out) && !ipsec_rebuild_pending_on);
    assert(follow_scheduled == 2 && follow_flushes == 2);

    /* A multicast group either learner cannot vouch for holds the drain
     * too, each learner is asked outside the control transaction, and one
     * that fails does not keep the other from rebuilding what it can. */
    mc_drains = mr_drains = 0;
    mc_drain_rc = -EAGAIN;
    assert(ft_egress_drain(&out) == -EAGAIN && mc_drains == 1 && mr_drains == 1);
    mc_drain_rc = 0;
    mr_drain_rc = -EAGAIN;
    assert(ft_egress_drain(&out) == -EAGAIN && mc_drains == 2 && mr_drains == 2);
    mr_drain_rc = 0;
    assert(!ft_egress_drain(&out) && mc_drains == 3 && mr_drains == 3);

    /* An SA being deleted has left the watch list, and its entries -- an
     * outbound one reads the port's DSCP map -- leave the hardware only when
     * its retire work runs. The drain says so rather than wait for that
     * work, which can itself be waiting on RTNL. */
    ipsec_retiring = true;
    assert(ft_egress_drain(&out) == -EAGAIN && !cdx_info->ctrl.mutex);
    ipsec_retiring = false;
    assert(!ft_egress_drain(&out));
}

static void test_qos_decode(void)
{
    unsigned int saved_mask = ft_qos_mark_mask, saved_default = ft_qos_default_class;

    /* No mask configured is not "class zero" — it is classification switched
     * off, and admission refuses marked flows outright elsewhere. */
    ft_qos_mark_mask = 0; ft_qos_default_class = 0x123;
    assert(ft_qos_class(0xabc) == 0);

    /* The field is shifted down to its own base, so an operator may place it
     * anywhere in the word and keep the rest for policy routing or a VPN. */
    ft_qos_mark_mask = 0xfff00; ft_qos_default_class = 0;
    assert(ft_qos_class(0x12300) == 0x123);
    assert(ft_qos_class(0x12345) == 0x123);   /* bits outside the mask ignored */
    assert(ft_qos_class(0xfff12300) == 0x123);

    /* A masked mark of zero takes the named default rather than landing on
     * whatever zero happens to mean. */
    ft_qos_default_class = 0x207;
    assert(ft_qos_class(0x00000) == 0x207);
    assert(ft_qos_class(0x00045) == 0x207);

    /* A mask narrower than the encoding is not an error: the nibbles it does
     * not reach read zero, which every position spells "unspecified". */
    ft_qos_mark_mask = 0xf; ft_qos_default_class = 0;
    assert(ft_qos_class(0x7) == 0x007);

    /* Whether any class can carry a remark, which is what a port with no
     * tree asks the classifier about frames for at all: never with no mask,
     * not with a mask whose bits stop short of the remark flag unless the
     * default class carries one, and always with one that reaches it. */
    ft_qos_mark_mask = 0; ft_qos_default_class = CDX_FT_QOS_REMARK_MASK;
    assert(!ft_qos_remarks());
    ft_qos_mark_mask = 0xf0; ft_qos_default_class = 0;
    assert(!ft_qos_remarks());
    ft_qos_default_class = CDX_FT_QOS_REMARK_MASK | 46u << CDX_FT_QOS_DSCP_SHIFT;
    assert(ft_qos_remarks());
    ft_qos_mark_mask = 0x7ffff0; ft_qos_default_class = 0;
    assert(ft_qos_remarks());
    ft_qos_mark_mask = 0xfff0;
    assert(!ft_qos_remarks());

    ft_qos_mark_mask = saved_mask; ft_qos_default_class = saved_default;

    /* Validity. Each nibble is bounded at its own maximum, inclusive. The
     * channel nibble admits 8 because value n names channel n-1 and zero is a
     * sentinel; the policer nibble admits 7 because it is a plain profile
     * number with no sentinel to make room for. */
    assert(ft_qos_class_valid(0x000));
    assert(ft_qos_class_valid(0x00f));                       /* class queue 15 */
    assert(ft_qos_class_valid(CDX_FT_QOS_MAX_CHANNEL << CDX_FT_QOS_CHANNEL_SHIFT));
    assert(ft_qos_class_valid(CDX_FT_QOS_MAX_POLICER << CDX_FT_QOS_POLICER_SHIFT));
    assert(ft_qos_class_valid(0x78f));                       /* all three, full */
    /* One past either bound names an object the hardware does not have. A flow
     * asking for it is declined to software, never truncated onto a queue or a
     * meter nobody asked for. */
    assert(!ft_qos_class_valid((CDX_FT_QOS_MAX_CHANNEL + 1) << CDX_FT_QOS_CHANNEL_SHIFT));
    assert(!ft_qos_class_valid((CDX_FT_QOS_MAX_POLICER + 1) << CDX_FT_QOS_POLICER_SHIFT));

    /* The remark: a flag and six bits of codepoint. Every codepoint is valid --
     * six bits is exactly the field -- so the only thing out of range above the
     * policer nibble is a bit the encoding does not define at all. */
    assert(ft_qos_class_valid(CDX_FT_QOS_REMARK_MASK));            /* remark to CS0 */
    assert(ft_qos_class_valid(CDX_FT_QOS_REMARK_MASK |
                              (CDX_FT_QOS_MAX_DSCP << CDX_FT_QOS_DSCP_SHIFT)));
    /* Every field at its own maximum. Not CDX_FT_QOS_MASK itself: that has all
     * four channel bits set, and channel 15 is three past the eight CEETM has. */
    assert(ft_qos_class_valid(CDX_FT_QOS_QUEUE_MASK |
                              (CDX_FT_QOS_MAX_CHANNEL << CDX_FT_QOS_CHANNEL_SHIFT) |
                              (CDX_FT_QOS_MAX_POLICER << CDX_FT_QOS_POLICER_SHIFT) |
                              CDX_FT_QOS_REMARK_MASK |
                              (CDX_FT_QOS_MAX_DSCP << CDX_FT_QOS_DSCP_SHIFT)));
    assert(!ft_qos_class_valid(CDX_FT_QOS_MASK + 1));
    assert(!ft_qos_class_valid(~CDX_FT_QOS_MASK & 0xffffffu));

    /* The flag is why the codepoint needs one. Every other field spells
     * "unspecified" as zero, but DSCP zero is CS0 -- a real codepoint, and the
     * one an operator remarks *to* for best effort -- so "remark to zero" and
     * "do not remark" have to be different values, and they are. */
    assert(CDX_FT_QOS_REMARK_MASK != 0);
    assert((0u & CDX_FT_QOS_REMARK_MASK) == 0);                    /* says nothing */
    assert((CDX_FT_QOS_REMARK_MASK & CDX_FT_QOS_REMARK_MASK) != 0);/* says CS0 */

    /* The six bits sit above the flag and below nothing else. */
    assert(CDX_FT_QOS_DSCP_MASK >> CDX_FT_QOS_DSCP_SHIFT == CDX_FT_QOS_MAX_DSCP);
    assert(!(CDX_FT_QOS_DSCP_MASK & CDX_FT_QOS_REMARK_MASK));

    /* Nineteen bits spoken for, thirteen left to the operator. */
    assert(CDX_FT_QOS_MASK == 0x07ffffu);        /* 19 contiguous bits from zero */
    assert((CDX_FT_QOS_MASK & (CDX_FT_QOS_MASK + 1)) == 0);

    /* The egress mask is what the Tx path may index its class table with, so it
     * has to exclude the policer nibble and the remark -- neither says anything
     * about where a frame leaves -- and stay inside a 256-entry table. Widening
     * the class made this load-bearing: unmasked, a remark of CS7 indexes 508
     * entries past the table. */
    assert(CDX_FT_QOS_EGRESS_MASK == 0xff);
    assert(!(CDX_FT_QOS_EGRESS_MASK & CDX_FT_QOS_POLICER_MASK));
    assert(!(CDX_FT_QOS_EGRESS_MASK & CDX_FT_QOS_REMARK_MASK));
    assert(!(CDX_FT_QOS_EGRESS_MASK & CDX_FT_QOS_DSCP_MASK));
    assert((CDX_FT_QOS_MASK & CDX_FT_QOS_EGRESS_MASK) == CDX_FT_QOS_EGRESS_MASK);

    /* Init refuses a mask wider than a class rather than narrowing it silently,
     * and that bound has to track the encoding. It did not when the policer
     * nibble was added: the check still said eight bits, so a mask covering all
     * three nibbles was refused and the adapter never came up. Both edges are
     * pinned here because only the rig caught it the first time. */
    ft_ready=ft_stopping=false; registration_step=canceled=0;
    fixture();
    ft_qos_mark_mask = CDX_FT_QOS_MASK; ft_qos_default_class = 0;
    sec_refusal_folds = 0;
    ft_mr_xt_seen = 0;
    assert(ask_flowtable_init() == 0);
    /* Counting what SEC refused starts at load and ends at unload. */
    assert(sec_refusal_folds == 1);
    assert(ft_mr_xt_seen == xt_changes);
    ask_flowtable_exit();
    assert(sec_refusal_folds == 2);
    ft_ready=ft_stopping=false; registration_step=canceled=0;
    fixture();
    ft_qos_mark_mask = (CDX_FT_QOS_MASK << 1) | 1;   /* one bit too wide */
    assert(ask_flowtable_init() == -EINVAL);
    /* The same width placed anywhere in the word is still a class: the field is
     * shifted down to its own base before it is measured. */
    ft_ready=ft_stopping=false; registration_step=canceled=0;
    fixture();
    ft_qos_mark_mask = CDX_FT_QOS_MASK << 16;
    assert(ask_flowtable_init() == 0);
    ask_flowtable_exit();
    ft_qos_mark_mask = saved_mask; ft_qos_default_class = saved_default;
    ft_ready=ft_stopping=false; registration_step=canceled=0;
}

/* Unload after a direct bind.
 *
 * Netfilter unwinds the binds it brokered indirectly when the adapter
 * unregisters, and it has no idea about a direct one -- that callback is the
 * flowtable's, and the flowtable is still alive. If the adapter does not hand
 * it back itself, it survives the unload still pointing at this module's text,
 * and the next queued offload calls it. On hardware that is
 * flow_offload_work_handler faulting on freed text with the table perfectly
 * healthy, which is exactly what the rig showed.
 *
 * Every bind takes this route now that the driver has an ndo_setup_tc, so
 * this is the ordinary case rather than a corner of one.
 */
static void test_direct_bind_unload(void)
{
    list_init(&table.flow_block.cb_list);
    ft_ready=ft_stopping=false; registration_step=canceled=0;
    fixture();
    assert(ask_flowtable_init() == 0);
    assert(bind_device_direct(&in, FLOW_BLOCK_BIND) == 0);
    assert(ft_bound == 1 && in.refs == 1);
    /* The callback is live in the table, which is where it has to be for the
     * fault to be reachable at all. */
    assert(table.flow_block.cb_list.next != &table.flow_block.cb_list);
    /* A port that stopped forwarding just before unload still has its
     * software flows swept, while the module whose text the work runs is
     * here to run it. */
    unsigned flushes = stopped_flushes;
    ft_port_stopped(&out);
    assert(out.refs == 1);
    nswept = swept_under_rtnl = 0;

    ask_flowtable_exit();
    assert(stopped_flushes == flushes + 1 && !out.refs);
    assert(nswept == 1 && swept_under_rtnl == 1 && swept[0] == &out);

    /* Nothing may still name this module: not in the table Netfilter walks,
     * not on the adapter's own list. */
    assert(table.flow_block.cb_list.next == &table.flow_block.cb_list);
    assert(ft_block_list.next == &ft_block_list);
    /* And the release really ran, rather than the callback being dropped on
     * the floor: the binding is gone and its device reference with it. */
    assert(!ft_bound && !in.refs && !allocated && !ft_count);
}

/* Unload after a passive bind through the indirect route -- the route a Wi-Fi
 * VAP takes, having no ndo_setup_tc.
 *
 * Netfilter unwinds the indirect callbacks it brokered by their release
 * function alone. A passive binding that carried a release of its own was left
 * on Netfilter's indirect list, and the adapter's drain then freed it there:
 * the next driver to walk or extend that list touched freed memory. */
static void test_passive_indirect_unload(void)
{
    struct flow_block_cb *cb;
    unsigned linked = 0;

    list_init(&block.cb_list);
    ft_ready=ft_stopping=false; registration_step=canceled=0;
    fixture();
    assert(ask_flowtable_init() == 0);
    physical_ok = false;
    assert(bind_device(&in, FLOW_BLOCK_BIND) == 0 && ft_passive == 1 && !ft_bound && !in.refs);
    physical_ok = true;
    assert(bind_device(&out, FLOW_BLOCK_BIND) == 0 && ft_passive == 1 && ft_bound == 1);
    list_for_each_entry(cb, &flow_block_indr_list, indr_list)
        linked++;
    assert(linked == 2);

    ask_flowtable_exit();

    /* What the next driver on that list would do: walk it. A callback freed
     * while still linked is a use-after-free here, under ASan. */
    linked = 0;
    list_for_each_entry(cb, &flow_block_indr_list, indr_list)
        linked++;
    assert(!linked);
    assert(block.cb_list.next == &block.cb_list && ft_block_list.next == &ft_block_list);
    assert(!ft_passive && !ft_bound && !allocated && !in.refs && !out.refs);
}

/* A consumer binding the moment a route opens, while the load goes on: through
 * the indirect route a passive and a real bind, a flow admitted and all three
 * of the adapter's own work items queued; through the direct route a real
 * bind. A load failing after that owes every one of them back. */
static void bind_while_loading(void)
{
    if (!registered_setup_tc) {
        physical_ok = false;
        assert(bind_device(&decoy, FLOW_BLOCK_BIND) == 0 && ft_passive == 1);
        physical_ok = true;
        assert(bind_device(&in, FLOW_BLOCK_BIND) == 0 && ft_bound == 1);
        cls.command = FLOW_CLS_REPLACE;
        assert(ft_rule_callback(TC_SETUP_CLSFLOWER, &cls, bound_to(&block, &in)) == 0);
        assert(ft_count == 1 && live_hw == 1);
        schedule_work(&ft_retire_work);
        schedule_delayed_work(&ft_work, 0);
        schedule_delayed_work(&ft_rearm_work, HZ);
    } else if (!registered_qos_class) {
        assert(bind_device_direct(&out, FLOW_BLOCK_BIND) == 0 && ft_bound == 2);
    }
}
static void unwound(void)
{
    assert(!work_queued_invalidate && !work_queued_retire && !work_queued_rearm);
    assert(!work_queued_dev_stats);
    assert(!ft_bound && !ft_parked && !ft_passive && !ft_count && !live_hw && !allocated);
    assert(ft_bindings.next == &ft_bindings && ft_block_list.next == &ft_block_list);
    assert(block.cb_list.next == &block.cb_list);
    assert(table.flow_block.cb_list.next == &table.flow_block.cb_list);
    assert(flow_block_indr_list.next == &flow_block_indr_list);
    assert(!in.refs && !out.refs && !decoy.refs && handle.refs == 1);
    assert(!registered_setup_tc && !registered_qos_class && !registered_egress_changed);
}
static void test_registration(void)
{
    list_init(&block.cb_list);
    list_init(&table.flow_block.cb_list);
    for (registration_failure = 0; registration_failure <= 9; registration_failure++) {
        /* A fresh adapter instance, backed by an independently owned CDX. */
        ft_ready=ft_stopping=false; registration_step=canceled=0;
        work_queued_invalidate = work_queued_retire = work_queued_rearm = false;
        route_open_hook = registration_failure ? bind_while_loading : NULL;
        fixture();
        unsigned replays = mc_replays, switches = mc_switches;
        int rc=ask_flowtable_init();
        if (registration_failure) {
            assert(rc < 0 && !ft_ready && !ft_proc && !backend_claimed);
            unwound();
        } else {
            assert(!rc && ft_ready && backend_claimed);
            assert(mc_replays == replays + 1 && mc_switches == switches + 1);
            assert(bind_device(&in,FLOW_BLOCK_BIND) == 0);
            assert(bind_device(&out,FLOW_BLOCK_BIND) == 0);
            struct cdx_ft_binding *b=list_entry(ft_bindings.next,struct cdx_ft_binding,list);
            assert(b->dev == &in);
            assert(ft_replace(b,&cls) == 0 && live_hw == 1);
            unload_failures=2; retry_error=-EAGAIN;
            ask_flowtable_exit();
            assert(handle.invalid && unload_sleeps == 2);
        }
        assert(!ft_proc && !ft_ready && !backend_claimed && !live_hw && !allocated);
        assert(!registered_egress_changed);
        assert(!netdev_registered && !neigh_registered && !fib_registered && !nexthop_registered && !indirect_registered);
        assert(!fdb_registered && !swdev_obj_registered);
        assert(!ft_count && !ft_bound && !ft_neighbour_refs && !ft_handle_refs);
        assert(!in.refs && !out.refs && !cdx_info->ctrl.mutex);
    }
    registration_failure=0;
    route_open_hook = bind_while_loading;
    for (ft_init_fail_stage=1; ft_init_fail_stage<=8; ft_init_fail_stage++) {
        ft_ready=ft_stopping=false; registration_step=canceled=0;
        work_queued_invalidate = work_queued_retire = work_queued_rearm = false;
        fixture();
        assert(ask_flowtable_init() == -ENOMEM);
        assert(!ft_ready && !ft_proc && !backend_claimed && !cdx_info->ctrl.mutex);
        assert(!registered_egress_changed);
        assert(!netdev_registered && !neigh_registered && !fib_registered && !nexthop_registered && !indirect_registered);
        assert(!fdb_registered && !swdev_obj_registered);
        unwound();
    }
    /* The three registrations CDX holds fail with -EBUSY rather than -ENOMEM,
     * and a later one failing has to give the earlier ones back: a module
     * that left the driver's ndo or the egress hook pointing into it would be
     * unloadable text on a path CDX still calls. The egress hook is claimed
     * first, before anything could bind; each of the other two fails with a
     * route already open and bound through, and the direct binds of the last
     * one are Netfilter's to keep unless the unwind drains them. */
    for (ft_init_fail_stage=9; ft_init_fail_stage<=11; ft_init_fail_stage++) {
        ft_ready=ft_stopping=false; registration_step=canceled=0;
        work_queued_invalidate = work_queued_retire = work_queued_rearm = false;
        fixture();
        unsigned deletes = ft_deletes;
        assert(ask_flowtable_init() == -EBUSY);
        assert(!ft_ready && !ft_proc && !backend_claimed && !indirect_registered);
        /* The admitted flow's generation is retired for Linux too, as at
         * unload, and its hardware entry went with its binding. The egress
         * hook's failure comes before any route opened, with nothing bound. */
        if (ft_init_fail_stage != 11)
            assert(handle.invalid && ft_deletes == deletes + 1);
        else
            assert(!handle.invalid && ft_deletes == deletes);
        unwound();
    }
    route_open_hook = NULL;
    ft_init_fail_stage=0;
    /* Fatal deletion on exit still waits for quiescence. Reload is refused. */
    ft_ready=ft_stopping=false; registration_step=canceled=0; fixture();
    assert(ask_flowtable_init() == 0);
    assert(bind_device(&in,FLOW_BLOCK_BIND) == 0);
    struct cdx_ft_binding *b=list_entry(ft_bindings.next,struct cdx_ft_binding,list);
    assert(ft_replace(b,&cls) == 0);
    deletion_error=-EIO; quiesce_fail=true; unload_failures=1;
    ask_flowtable_exit();
    assert(ft_fatal && !backend_claimed && !live_hw && !allocated && handle.invalid);
    assert(unload_sleeps == 3 && !ft_proc);
    assert(ask_flowtable_init() == -EOPNOTSUPP && !backend_claimed && !ft_proc);
    /* The refused claim comes before anything registers. */
    registration_failure=registration_step=0;
    assert(ask_flowtable_init() == -EOPNOTSUPP && !backend_claimed && !registration_step);
    assert(!ft_proc && !cdx_info->ctrl.mutex);
    ft_fatal=false;
    /* A load unwinding its own failure owes the same: a drain whose delete
     * fails fatally is proven by stopping the datapath, and the unwind waits
     * for that before it lets the claim go. With the adapter stopping, the
     * production ft_invalidate() queues no worker, so nothing else would;
     * this harness's latches regardless, and is cleared on either side. */
    {
        unsigned sleeps = unload_sleeps, tries = recoveries;

        route_open_hook = bind_while_loading;
        ft_init_fail_stage=9; ft_invalid=0;
        ft_ready=ft_stopping=false; registration_step=canceled=0;
        work_queued_invalidate = work_queued_retire = work_queued_rearm = false;
        fixture();
        deletion_error=-EIO; quiesce_fail=true; unload_failures=1;
        assert(ask_flowtable_init() == -EBUSY);
        assert(ft_fatal && !quiesce_fail && unload_sleeps == sleeps + 1);
        assert(recoveries == tries + 2);
        assert(!ft_ready && !ft_proc && !backend_claimed && !indirect_registered);
        unwound();
        route_open_hook = NULL;
        ft_init_fail_stage=0; deletion_error=0; ft_fatal=false; ft_invalid=0;
    }
}

int main(void)
{
    struct cdx_ft_rule decoded;
    fixture();
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    assert(is4(&decoded.src, ik.src) && is4(&decoded.dst, ik.dst) && decoded.sport == htons(10000));
    assert(decoded.mtu == 1500 && decoded.in == &in && decoded.out == &out);
    assert(!memcmp(decoded.dst_mac, (u8[]){2,0x11,0x22,0x33,0x44,0x55}, 6));
    assert(!memcmp(decoded.src_mac, out.dev_addr, 6));
    /* The MTU is the path's, not the egress device's. */
    tcp_fixture(); cls.nf_mtu = 1400;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.mtu == 1400 && out.mtu == 1500);
    REJECT(cls.nf_ct = NULL); REJECT(ct.net = NULL); REJECT(ct.zone[0] = 1); REJECT(ct.zone[1] = 1);
    REJECT(cls.nf_handle = NULL);
    REJECT(handle.invalid = true);
    REJECT(ct.mark = 1); REJECT(ct.status = IPS_NAT_MASK); REJECT(cls.nf_mtu = 0);
    /* The floor on a TCP flow, which no ingress bound refuses first. */
    REJECT(tcp_flow(); cls.nf_mtu = 67);
    tcp_fixture(); cls.nf_mtu = 68;
    assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.mtu == 68);
    REJECT(cls.nf_mtu = 1501); REJECT(cls.common.chain_index = 1);
    REJECT(cls.common.protocol = 0); REJECT(dissector.used_keys |= BIT(10));
    REJECT(mm.ingress_ifindex = 0); REJECT(mk.ingress_ifindex++); REJECT(mm.ingress_iftype = 1);
    REJECT(mm.l2_miss = 1); REJECT(cm.flags = 1); REJECT(cm.thoff = 1); REJECT(cm.addr_type = 0);
    REJECT(bk.ip_proto = IPPROTO_TCP); REJECT(bm.ip_proto = 0); REJECT(im.src = 0);
    REJECT(pm.dst = 0); REJECT(pk.src = 0); REJECT(ik.dst = htonl(0xe0000001));
    REJECT(ik.src = htonl(0x7f000001)); REJECT(ik.dst = 0xffffffff);
    REJECT(rule.action.num_entries = 4); REJECT(rule.action.entries[0].mangle.offset = 0);
    REJECT(rule.action.entries[0].mangle.val |= 1); REJECT(rule.action.entries[0].mangle.mask = 0);
    REJECT(rule.action.entries[4].dev = &in); REJECT(neigh_ok = false); REJECT(physical_ok = false);
    REJECT(dissector.used_keys |= BIT(FLOW_DISSECTOR_KEY_TCP));
    REJECT(bk.ip_proto = ct.protonum = IPPROTO_ICMP);
    fixture(); assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0);
    struct cdx_ft_rule udp = decoded;
    tcp_fixture(); assert(ft_parse(&binding, &cls, &decoded, &next_hop) == 0 && decoded.proto == IPPROTO_TCP);
    assert(!ft_same_key(&udp, &decoded));
#define TCP_REJECT(change) do { tcp_fixture(); change; assert(ft_parse(&binding, &cls, &decoded, &next_hop) == -EOPNOTSUPP); } while (0)
    TCP_REJECT(ct.protonum = IPPROTO_UDP);
    TCP_REJECT(ct.tcp_state = 2); TCP_REJECT(ct.tcp_state = 4); TCP_REJECT(ct.status = 0);
    TCP_REJECT(dissector.used_keys &= ~BIT(FLOW_DISSECTOR_KEY_TCP));
    TCP_REJECT(tk.flags = htons(1)); TCP_REJECT(tm.flags = 0);
    TCP_REJECT(tm.flags = htons(1)); TCP_REJECT(tm.flags = htons(4));
    TCP_REJECT(tm.flags = htons(7)); TCP_REJECT(tm.flags = htons(0x15));
    for (unsigned cycle = 0; cycle < 128; cycle++) {
        if (cycle & 1) tcp_fixture(); else fixture();
        assert(ft_replace(&binding, &cls) == 0);
        assert(ft_count == 1 && allocated == 1 && live_hw == 1 && out.refs == 1);
        assert(ft_replace(&binding, &cls) == 0); /* exact duplicate is idempotent */
        cls.cookie++; assert(ft_replace(&binding, &cls) == -EEXIST); cls.cookie--;
        struct cdx_ft_entry *e = ft_find(&binding, cls.cookie); assert(e);
        e->hw->stats = (struct cdx_ft_counters){ .packets = 100, .bytes = 12300, .lastused = 990 };
        /* Reported in Netfilter's units whether or not this table counts:
         * the number means one thing, and which reader wants it is not the
         * adapter's business. */
        assert(ft_stats(e, &cls) == 0 && cls.stats.pkts == 100 &&
               cls.stats.bytes == 12300 - 100 * ETH_HLEN);
        cls.stats = (struct flow_stats){0};
        assert(ft_stats(e, &cls) == 0 && cls.stats.pkts == 0 && cls.stats.bytes == 0);
        assert(cls.stats.lastused == 990);
        jiffies = (1UL << 32) + 7; e->hw->stats.lastused = 0xfffffffe;
        assert(ft_stats(e, &cls) == 0 && cls.stats.lastused == (1UL << 32) - 2); jiffies = 1000;
        assert(ft_remove(e) == 0 && !ft_count && !allocated && !live_hw && !out.refs);
    }
    fixture();
    for (unsigned stage = 1; stage <= 3; stage++) {
        ft_fail_stage = stage; assert(ft_replace(&binding, &cls) < 0);
        assert(!ft_fail_stage && !ft_count && !allocated && !live_hw && !out.refs);
    }
    allocation_fail = true; assert(ft_replace(&binding, &cls) == -ENOMEM); allocation_fail = false;
    hardware_fail = true; assert(ft_replace(&binding, &cls) == -EIO); hardware_fail = false;
    invalidate_on_add = true; assert(ft_replace(&binding, &cls) == -EIO); invalidate_on_add = false;
    assert(ft_invalid && !ft_count && !allocated && !live_hw && !out.refs);
    assert(ft_replace(&binding, &cls) == -EOPNOTSUPP); ft_invalid = 0;
    ft_observe = true; assert(ft_replace(&binding, &cls) == -EOPNOTSUPP); ft_observe = false;
    assert(ft_replace(&binding, &cls) == 0);
    struct cdx_ft_entry *e = ft_find(&binding, cls.cookie);
    e->reported.packets = 1; assert(ft_stats(e, &cls) == -EIO && ft_invalid);
    deletion_error = -EAGAIN; assert(ft_remove(e) == -EAGAIN && !ft_fatal);
    ft_invalid = 0; deletion_error = 0; assert(ft_replace(&binding, &cls) == 0);
    deletion_error = -EIO; assert(ft_remove(ft_find(&binding, cls.cookie)) == -EIO && ft_fatal);
    assert(ft_invalid && !ft_invalid_done && !allocated && !live_hw && !out.refs);
    list_add_tail(&binding.list, &ft_bindings);
    rtnl_busy = true; ft_invalidate_work(NULL); assert(scheduled == 1 && !flushed && !ft_invalid_done);
    rtnl_busy = false; quiesce_fail = true; ft_invalidate_work(NULL);
    assert(scheduled == 2 && !flushed && !ft_invalid_done);
    quiesce_fail = false; ft_invalidate_work(NULL);
    assert(flushed == 1 && ft_invalid_done && !in.refs && !out.refs);
    list_del(&binding.list);
    assert(ft_installs == ft_deletes);
    test_rearm();
    test_gateways();
    test_connections();
    test_neighbours();
    test_selective_neighbours();
    test_selective_routes();
    test_ipv6();
    test_cross_family_sa();
    test_vlan();
    test_bridge();
    test_bridge_fdb();
    test_pppoe();
    test_pppoe_stats();
    test_tunnel();
    test_tunnel_stats();
    test_snat();
    test_dnat();
    test_double_nat();
    test_device_dependencies();
    test_binding_capacity();
    test_table_handover();
    test_parked_rearm();
    test_counter_accounting();
    test_device_recovery();
    test_transient_admission();
    test_allocation_admission_recovery();
    test_installed_reoffer();
    test_tunnel_arrival_retry();
    test_crossed_devices();
    test_mtu_before_admission();
    test_mtu_refusal_sound();
    test_ipsec_generation_retirement();
    test_nexthop_objects();
    test_qos_decode();
    test_egress_drain();
    test_vlan_stats();
    test_direct_bind_unload();
    test_passive_indirect_unload();
    test_registration();
    puts("Flowtable: decoder, references, deltas, wrap, rollback, connections, neighbours, invalidation, rearm, class decode, VLAN records and fatal retry passed");
}

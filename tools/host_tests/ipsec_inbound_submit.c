/* The driver's inbound hand-off to SEC is production code: the test for a
 * DPAA port, the test for the state's own port and the submit around them.
 * xfrm_input() calls it for a packet-offloaded state whatever device the frame
 * reached the stack on, so it is given each kind here, and the state bound to
 * one port or another. Every device that is not a port keeps its private area
 * on a page nothing may read or write: the submit borrowing it as a struct
 * dpa_priv_s faults, and the fault fails the test by name. */
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define raw_cpu_ptr(p) (p)
#define pr_err_ratelimited(...) ((void)0)
#define net_err_ratelimited(...) ((void)0)

#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
#define ARPHRD_IPGRE 778
#define ARPHRD_NONE 0xFFFE
#define ETH_HLEN 14
#define PPPOE_SES_HLEN 8
#define DPAA_IP_VERSION_4 4
#define IPVERSION 4
#define IPPROTO_UDP 17
#define IPPROTO_ESP 50
#define NEXTHDR_HOP 0
#define NEXTHDR_DEST 60
#define XFRM_MODE_TRANSPORT 0
#define XFRM_MODE_TUNNEL 1

struct iphdr { u8 ihl:4, version:4; u8 tos, tot_len[2], id[2], frag_off[2], ttl, protocol; u16 check; u8 addrs[8]; };
struct ipv6hdr { u8 version_class[4]; u8 payload_len[2]; u8 nexthdr; u8 hop_limit; u8 addrs[32]; };
struct udphdr { u16 source, dest, len, check; };
/* Where the stack found the header it hands on: the byte naming it. */
struct inet6_skb_parm { u16 nhoff; };

struct net { int unused; };
struct net_device;
struct net_device_ops { int (*ndo_init)(struct net_device *dev); };
struct net_device {
	const char *name;
	unsigned short type;
	int ifindex;
	const struct net_device_ops *netdev_ops;
	struct net_device *wifi_offload_dev;
	/* What netdev_priv() answers: a struct dpa_priv_s behind a port, the
	 * guard page behind anything else. */
	void *priv;
	/* A VLAN device's lower device. The kernel keeps it in the VLAN
	 * driver's own private area, which vlan_dev_real_dev() may read. */
	struct net_device *vlan_real_dev;
};
struct device { int unused; };
struct dpa_bp { struct device *dev; };
struct dpa_percpu_priv_s { unsigned long tx_caam_dec; };
struct dpa_priv_s {
	struct dpa_percpu_priv_s *percpu_priv;
	struct dpa_bp *dpa_bp;
	struct net_device *net_dev;
};
struct qman_fq { int unused; };
struct qm_fd { u32 cmd; };
struct sk_buff {
	struct net_device *dev;
	unsigned char *head, *data;
	unsigned int len;
	u16 mac_header, network_header, mac_len;
	int iif_index;
	struct inet6_skb_parm cb6;
};
#define IP6CB(skb) (&(skb)->cb6)
/* What the submit reads of the state: its handle, its mode, whether it is
 * received in UDP and the device it is bound to. */
struct xfrm_encap_tmpl { u16 encap_type; };
struct xfrm_state {
	u16 handle;
	struct { u8 mode; } props;
	struct xfrm_encap_tmpl *encap;
	struct { struct net_device *dev; } xso;
};

typedef struct qman_fq *(*cdx_get_ipsec_fq_hook_t)(u32 handle);
static cdx_get_ipsec_fq_hook_t cdx_get_ipsec_fq_hookfn;

static struct net init_net;

/* The one member of the driver's ops the driver exports. */
static int dpa_ndo_init(struct net_device *dev) { (void)dev; return 0; }
static int other_ndo_init(struct net_device *dev) { (void)dev; return 0; }
static const struct net_device_ops dpa_ops = { .ndo_init = dpa_ndo_init };
static const struct net_device_ops bridge_ops = { .ndo_init = other_ndo_init };
static const struct net_device_ops vlan_ops = { .ndo_init = other_ndo_init };
static const struct net_device_ops veth_ops = { .ndo_init = NULL };
static const struct net_device_ops wifi_ops = { .ndo_init = other_ndo_init };
static const struct net_device_ops ppp_ops = { .ndo_init = NULL };
static const struct net_device_ops usbnet_ops = { .ndo_init = other_ndo_init };
static const struct net_device_ops tunnel_ops = { .ndo_init = other_ndo_init };
static const struct net_device_ops wwan_ops = { .ndo_init = NULL };

/* What happened to the frame. */
static struct {
	int sg_result, enqueue_result, cow_result;
	unsigned cows, sg_calls, enqueues, releases;
	struct device *sg_dev;
	struct net_device *sg_netdev;
	u32 sg_cmd;
} bench;

static struct qman_fq sec_fq;
static struct qman_fq *fq_answer;
static u32 fq_asked;
static int rcu_depth;

static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth > 0); rcu_depth--; }

static bool is_vlan_dev(const struct net_device *dev) { return dev->vlan_real_dev; }
static struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	return dev->vlan_real_dev;
}
static void *netdev_priv(const struct net_device *dev) { return dev->priv; }
static unsigned char *skb_mac_header(const struct sk_buff *skb)
{
	return skb->head + skb->mac_header;
}
static unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}
static struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

/* The one's-complement sum of a header `ihl` words long, folded and
 * inverted: zero for a header whose checksum is right. */
static u16 ip_fast_csum(const void *header, unsigned ihl)
{
	const u8 *p = header;
	uint32_t sum = 0;

	for (unsigned i = 0; i < ihl * 4; i += 2)
		sum += p[i] << 8 | p[i + 1];
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (u16)~sum;
}

static unsigned checksum_writes;

static void ip_send_check(struct iphdr *iph)
{
	u16 sum;

	checksum_writes++;
	iph->check = 0;
	sum = ip_fast_csum(iph, iph->ihl);
	/* Stored in network order, as the sum was taken. */
	((u8 *)&iph->check)[0] = sum >> 8;
	((u8 *)&iph->check)[1] = sum & 0xff;
}
static struct net *dev_net(const struct net_device *dev) { (void)dev; return &init_net; }

static int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	(void)skb; (void)headroom;
	bench.cows++;
	return bench.cow_result;
}

static int skb_fraglist_to_sg_fd(struct device *dev, struct net_device *net_dev,
				 struct sk_buff *skb, struct qm_fd *fd, u32 fd_cmd)
{
	(void)skb;
	bench.sg_calls++;
	bench.sg_dev = dev;
	bench.sg_netdev = net_dev;
	bench.sg_cmd = fd_cmd;
	fd->cmd = fd_cmd;
	return bench.sg_result;
}

static int qman_enqueue(struct qman_fq *fq, const struct qm_fd *fd, u32 flags)
{
	(void)fd; (void)flags;
	assert(fq == &sec_fq && rcu_depth == 1);
	bench.enqueues++;
	return bench.enqueue_result;
}

static void dpaa_sec_sg_release(const struct qm_fd *fd, bool free_skb)
{
	(void)fd;
	assert(!free_skb);
	bench.releases++;
}

static struct qman_fq *get_fq(u32 handle)
{
	assert(rcu_depth == 1);
	fq_asked = handle;
	return fq_answer;
}

/* A device the submit found by index: the one a PPP session's frames entered
 * the stack by. */
static struct net_device *devices[16];
static unsigned n_devices;

static struct net_device *dev_get_by_index_rcu(struct net *net, int ifindex)
{
	assert(net == &init_net && rcu_depth == 1);
	for (unsigned i = 0; i < n_devices; i++)
		if (devices[i]->ifindex == ifindex)
			return devices[i];
	return NULL;
}

#include "ipsec_inbound_submit.inc"

/* The page behind every device that is not a port. */
static void *guard;
static size_t page;

static void fault(int sig, siginfo_t *info, void *context)
{
	static const char touched[] =
		"FAIL: the submit touched the private area of a device that is not a DPAA port\n";
	static const char other[] = "FAIL: segmentation fault outside the guard page\n";
	uintptr_t at = (uintptr_t)info->si_addr, base = (uintptr_t)guard;

	(void)sig; (void)context;
	if (at >= base && at < base + page)
		(void)!write(2, touched, sizeof(touched) - 1);
	else
		(void)!write(2, other, sizeof(other) - 1);
	_exit(3);
}

static struct device eth3_dma, eth4_dma;
static struct dpa_bp eth3_bp = { .dev = &eth3_dma }, eth4_bp = { .dev = &eth4_dma };
static struct dpa_percpu_priv_s eth3_cpu, eth4_cpu;
static struct net_device eth3, eth4;
static struct dpa_priv_s eth3_priv = { &eth3_cpu, &eth3_bp, &eth3 };
static struct dpa_priv_s eth4_priv = { &eth4_cpu, &eth4_bp, &eth4 };
static struct net_device eth3_vlan, bridge, bridge_vlan, veth, vap, vap_vlan, ppp, usb, gre,
	wwan;
/* Stands in for VWD's descriptor, which is all wifi_offload_dev points at. */
static struct net_device vap_desc;

static void setup(void)
{
	page = (size_t)sysconf(_SC_PAGESIZE);
	guard = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(guard != MAP_FAILED);

	struct sigaction sa = { .sa_sigaction = fault, .sa_flags = SA_SIGINFO };
	sigemptyset(&sa.sa_mask);
	assert(!sigaction(SIGSEGV, &sa, NULL) && !sigaction(SIGBUS, &sa, NULL));

	eth3 = (struct net_device){ "eth3", ARPHRD_ETHER, 3, &dpa_ops, NULL, &eth3_priv, NULL };
	eth4 = (struct net_device){ "eth4", ARPHRD_ETHER, 4, &dpa_ops, NULL, &eth4_priv, NULL };
	eth3_vlan = (struct net_device){ "eth3.100", ARPHRD_ETHER, 5, &vlan_ops, NULL, guard, &eth3 };
	bridge = (struct net_device){ "br-lan", ARPHRD_ETHER, 6, &bridge_ops, NULL, guard, NULL };
	bridge_vlan = (struct net_device){ "br-lan.10", ARPHRD_ETHER, 7, &vlan_ops, NULL, guard, &bridge };
	veth = (struct net_device){ "veth0", ARPHRD_ETHER, 8, &veth_ops, NULL, guard, NULL };
	vap = (struct net_device){ "wlan0", ARPHRD_ETHER, 9, &wifi_ops, &vap_desc, guard, NULL };
	vap_vlan = (struct net_device){ "wlan0.20", ARPHRD_ETHER, 10, &vlan_ops, &vap_desc, guard, &vap };
	ppp = (struct net_device){ "ppp0", ARPHRD_PPP, 11, &ppp_ops, NULL, guard, NULL };
	usb = (struct net_device){ "usb0", ARPHRD_ETHER, 12, &usbnet_ops, NULL, guard, NULL };
	gre = (struct net_device){ "gre1", ARPHRD_IPGRE, 13, &tunnel_ops, NULL, guard, NULL };
	/* A device VWD serves that is not Ethernet at all. */
	wwan = (struct net_device){ "wwan0", ARPHRD_NONE, 14, &wwan_ops, &vap_desc, guard, NULL };

	struct net_device *all[] = { &eth3, &eth4, &eth3_vlan, &bridge, &bridge_vlan, &veth,
				     &vap, &vap_vlan, &ppp, &usb, &gre, &wwan };
	n_devices = sizeof(all) / sizeof(all[0]);
	memcpy(devices, all, sizeof(all));
}

/* Room for a tunnel's longest outer header, and a little past it. */
static _Alignas(8) u8 buffer[4352], original[4352];
static struct sk_buff skb;
/* Where the frame's ESP starts, and the DPOVRD value SEC is to be given. */
static unsigned char *start;
static u32 want;

/* A transport SA's value: the header's length, and its byte that names ESP
 * as SEC counts it. */
static u32 word(unsigned len, unsigned nh_offset)
{
	return DPOVRD_ENABLE | len << 16 | nh_offset << 8;
}

static void reset(void)
{
	memset(&bench, 0, sizeof(bench));
	checksum_writes = 0;
	eth3_cpu.tx_caam_dec = eth4_cpu.tx_caam_dec = 0;
	cdx_get_ipsec_fq_hookfn = get_fq;
	fq_answer = &sec_fq;
	fq_asked = 0;
}

/* An ESP datagram as the stack hands it to xfrm_input(): data at the ESP
 * header, the MAC header `l2` bytes ahead of the IP header, which sits at
 * offset `l3`. */
static void frame(struct net_device *dev, unsigned l3, unsigned l2)
{
	memset(buffer, 0, sizeof(buffer));
	memset(buffer, 0xaa, 6);
	memset(buffer + 6, 0xbb, 6);
	buffer[12] = 0x08;
	buffer[l3] = 0x45;
	buffer[l3 + 9] = 50;
	skb = (struct sk_buff){
		.dev = dev, .head = buffer, .data = buffer + l3 + 20,
		.len = 100, .mac_header = (u16)(l3 - l2), .network_header = (u16)l3,
		.mac_len = (u16)l2,
	};
	start = skb.data;
	want = word(20, 1);
	memcpy(original, buffer, sizeof(buffer));
	reset();
}

/* As frame() on a port, but IPv6, with `n` extension headers of the given
 * types and eight-byte lengths ahead of ESP, and the stack's note of the byte
 * naming ESP. */
static void frame6(struct net_device *dev, const u8 *types, const u16 *units, int n)
{
	unsigned l3 = 14, at = l3 + 6, off = l3 + 40;

	frame(dev, l3, 14);
	buffer[13] = 0xdd;
	buffer[12] = 0x86;
	memset(buffer + l3, 0, 40);
	buffer[l3] = 0x60;
	buffer[l3 + 7] = 64;
	for (int i = 0; i < n; i++) {
		buffer[at] = types[i];
		buffer[off + 1] = units[i] - 1;
		at = off;
		off += units[i] * 8;
	}
	buffer[at] = IPPROTO_ESP;
	skb.data = start = buffer + off;
	skb.cb6.nhoff = (u16)(at - l3);
	want = word(off - l3, n ? (at - l3) / 8 : 1);
	memcpy(original, buffer, sizeof(buffer));
}

/* A frame from a PPPoE session: Ethernet, the session header and the PPP
 * protocol, with the MAC header left at the IP header as PPP leaves it. The
 * session arrived by `lower`. */
static void session(struct net_device *lower)
{
	frame(&ppp, 22, 0);
	buffer[12] = 0x88;
	buffer[13] = 0x64;
	buffer[14] = 0x11;
	buffer[21] = 0x21;
	memcpy(original, buffer, sizeof(buffer));
	skb.iif_index = lower ? lower->ifindex : 99;
}

/* The state the frame is for, bound to one port or another. */
static struct xfrm_state sa = { .handle = 7 };

static int submit(void) { return dpaa_submit_inb_pkt_to_SEC(&skb, &sa); }

/* Given back to Linux exactly as it came: nothing moved, nothing written,
 * nothing given to SEC. */
static void handed_back(int rc)
{
	assert(rc == -1);
	assert(skb.data == start && skb.len == 100);
	assert(!memcmp(buffer, original, sizeof(buffer)));
	assert(!bench.cows && !bench.sg_calls && !bench.enqueues && !bench.releases);
	assert(!eth3_cpu.tx_caam_dec && !eth4_cpu.tx_caam_dec);
	assert(rcu_depth == 0);
}

/* Given to SEC from the MAC header on, with the DPOVRD value its header asks
 * for, mapped for `dma` and counted as the port's. */
static void taken(int rc, struct dpa_priv_s *priv, struct device *dma)
{
	assert(rc == 0 && fq_asked == 7);
	assert(bench.sg_calls == 1 && bench.enqueues == 1 && !bench.releases);
	assert(bench.sg_cmd == want);
	assert(bench.sg_dev == dma && bench.sg_netdev == priv->net_dev);
	assert(priv->percpu_priv->tx_caam_dec == 1);
	assert(rcu_depth == 0);
}

static void test_ports(void)
{
	/* The state's own port: SEC gets the frame from its MAC header. */
	sa.xso.dev = &eth3;
	frame(&eth3, 14, 14);
	taken(submit(), &eth3_priv, &eth3_dma);
	assert(skb.data == buffer && skb.len == 100 + 34);

	/* A VLAN over it lends the port's. */
	frame(&eth3_vlan, 18, 14);
	taken(submit(), &eth3_priv, &eth3_dma);
	assert(skb.data == buffer + 4 && skb.len == 100 + 34);

	/* The other port, for a state bound to it: its own pool. */
	sa.xso.dev = &eth4;
	frame(&eth4, 14, 14);
	taken(submit(), &eth4_priv, &eth4_dma);

	/* A PPPoE session on it: the Ethernet header rebuilt in front. */
	session(&eth4);
	taken(submit(), &eth4_priv, &eth4_dma);
	assert(bench.cows == 1 && skb.data == buffer + 8 && skb.len == 100 + 34);
	assert(skb.data[12] == 0x08 && skb.data[13] == 0x00);

	/* Another port -- directly, under a VLAN, under a PPPoE session -- is
	 * not the state's, however much a port it is. */
	frame(&eth3, 14, 14);
	handed_back(submit());
	frame(&eth3_vlan, 18, 14);
	handed_back(submit());
	session(&eth3);
	handed_back(submit());
	/* Nor is any port once the state is bound to none. */
	sa.xso.dev = NULL;
	frame(&eth4, 14, 14);
	handed_back(submit());

	/* What SEC refuses to queue goes back to Linux, the shift undone. */
	sa.xso.dev = &eth3;
	frame(&eth3, 14, 14);
	bench.enqueue_result = -5;
	assert(submit() == -1);
	assert(bench.releases == 1 && !eth3_cpu.tx_caam_dec);
	assert(skb.data == buffer + 34 && skb.len == 100);

	/* With no hook, or no queue for the handle, nothing is given to SEC,
	 * so neither is the frame taken: claimed, it would have no owner. */
	frame(&eth3, 14, 14);
	cdx_get_ipsec_fq_hookfn = NULL;
	handed_back(submit());
	frame(&eth3, 14, 14);
	fq_answer = NULL;
	handed_back(submit());
}

static void test_other_devices(void)
{
	struct net_device *others[] = { &bridge, &bridge_vlan, &veth, &vap, &vap_vlan, &usb };

	/* Even a state bound to the very device a frame arrived on is not
	 * submitted from it unless it is a port. */
	for (unsigned i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
		sa.xso.dev = &eth4;
		frame(others[i], 18, 14);
		handed_back(submit());
		sa.xso.dev = others[i];
		frame(others[i], 18, 14);
		handed_back(submit());
	}
	sa.xso.dev = &eth4;

	/* A tunnel device: no Ethernet header, and no port under it. */
	frame(&gre, 14, 0);
	handed_back(submit());

	/* A non-Ethernet device VWD serves has no port under it either, and
	 * is not the state's: nothing goes to SEC from it. */
	frame(&wwan, 14, 14);
	handed_back(submit());

	/* A session over another driver's device, or over one that is gone. */
	session(&usb);
	handed_back(submit());
	session(NULL);
	handed_back(submit());
}

/* What SEC is told of a transport frame's IP header. Its SA's PDB states a
 * plain one naming ESP in the fixed part, so anything else is described per
 * frame: the length up to ESP and the byte naming it, which SEC overwrites
 * with the protocol from the trailer. */
static void test_headers(void)
{
	sa.xso.dev = &eth3;

	/* IPv4 options: the header's own length. The stack checked the
	 * header's checksum and then wrote into a Record Route option, so the
	 * checksum SEC is handed is put right; SEC only updates it. */
	frame(&eth3, 14, 14);
	buffer[14] = 0x46;
	skb.data = start = buffer + 14 + 24;
	want = word(24, 1);
	memcpy(original, buffer, sizeof(buffer));
	assert(ip_fast_csum(buffer + 14, 6));
	taken(submit(), &eth3_priv, &eth3_dma);
	/* Unshared first: a raw socket's clone may share the header. */
	assert(bench.cows == 1);
	assert(checksum_writes == 1 && !ip_fast_csum(buffer + 14, 6));
	/* A header that cannot be unshared goes back unwritten, the frame
	 * moved back to where it was. */
	frame(&eth3, 14, 14);
	buffer[14] = 0x46;
	skb.data = start = buffer + 14 + 24;
	memcpy(original, buffer, sizeof(buffer));
	bench.cow_result = -12;
	assert(submit() == -1 && skb.data == start && skb.len == 100);
	assert(!checksum_writes && !bench.sg_calls && !memcmp(buffer, original, sizeof(buffer)));
	/* One that is right is left alone... */
	frame(&eth3, 14, 14);
	buffer[14] = 0x46;
	skb.data = start = buffer + 14 + 24;
	ip_send_check((struct iphdr *)(buffer + 14));
	want = word(24, 1);
	reset();
	taken(submit(), &eth3_priv, &eth3_dma);
	assert(!checksum_writes && !bench.cows);
	/* ...as is a header without options, which the stack never writes:
	 * its checksum here is nonsense, and stays so. */
	frame(&eth3, 14, 14);
	assert(ip_fast_csum(buffer + 14, 5));
	taken(submit(), &eth3_priv, &eth3_dma);
	assert(!checksum_writes);

	/* ESP the stack found behind a UDP header is not where this SA's is. */
	frame(&eth3, 14, 14);
	buffer[14 + 9] = IPPROTO_UDP;
	skb.data = start = buffer + 14 + 28;
	memcpy(original, buffer, sizeof(buffer));
	handed_back(submit());

	/* IPv6: the fixed header's byte, offset one... */
	frame6(&eth3, NULL, NULL, 0);
	assert(want == word(40, 1));
	taken(submit(), &eth3_priv, &eth3_dma);
	/* ...or the last extension header's, in eight-byte units. */
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){1}, 1);
	assert(want == word(48, 5));
	taken(submit(), &eth3_priv, &eth3_dma);
	frame6(&eth3, (u8[]){NEXTHDR_HOP, NEXTHDR_DEST}, (u16[]){1, 2}, 2);
	assert(want == word(64, 6));
	taken(submit(), &eth3_priv, &eth3_dma);

	/* The byte the stack found ESP by has to name it. */
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){1}, 1);
	skb.cb6.nhoff = 6;
	handed_back(submit());

	/* Up to the longest header the offline port reliably parses past in
	 * SEC's output, and no further. */
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){11}, 1);
	assert(want == word(128, 5));
	taken(submit(), &eth3_priv, &eth3_dma);
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){12}, 1);
	handed_back(submit());
}

/* A tunnel SA's value: the length of the outer header material SEC strips. */
static u32 strip(unsigned len)
{
	return DPOVRD_ENABLE | len;
}

/* As frame() on a port, with an IPv4 header `ihl` words long and, for
 * ESP-in-UDP, a UDP header between it and ESP. */
static void frame4(unsigned ihl, bool udp)
{
	unsigned len = ihl * 4 + (udp ? 8 : 0);

	frame(&eth3, 14, 14);
	buffer[14] = (u8)(0x40 | ihl);
	buffer[14 + 9] = udp ? IPPROTO_UDP : IPPROTO_ESP;
	skb.data = start = buffer + 14 + len;
	want = strip(len);
	memcpy(original, buffer, sizeof(buffer));
}

/* frame6()'s frame in UDP: the byte the stack found the next header by names
 * UDP, and ESP follows a UDP header. */
static void udp6(void)
{
	buffer[14 + skb.cb6.nhoff] = IPPROTO_UDP;
	skb.data = start = skb.data + 8;
	memcpy(original, buffer, sizeof(buffer));
}

/* What SEC is told of a tunnel frame's outer header. Its SA's PDB states a
 * plain one, so each frame gives everything ahead of ESP, which SEC strips,
 * IPv4 options and IPv6 extension headers included -- provided it came the
 * way the state receives: in UDP for a state with an encapsulation, bare
 * otherwise. */
static void test_tunnel_headers(void)
{
	static struct xfrm_encap_tmpl espinudp = { 2 };

	sa.xso.dev = &eth3;
	sa.props.mode = XFRM_MODE_TUNNEL;

	/* IPv4, plain and with options. The outer header goes, checksum and
	 * all, so a stale one is left as it is. */
	frame4(5, false);
	taken(submit(), &eth3_priv, &eth3_dma);
	frame4(6, false);
	assert(ip_fast_csum(buffer + 14, 6));
	taken(submit(), &eth3_priv, &eth3_dma);
	assert(!checksum_writes && !bench.cows);
	frame4(15, false);
	assert(want == strip(60));
	taken(submit(), &eth3_priv, &eth3_dma);
	/* A header length that is not where the stack found ESP. */
	frame4(6, false);
	buffer[14] = 0x45;
	memcpy(original, buffer, sizeof(buffer));
	handed_back(submit());

	/* IPv6, plain and with extension headers, past a transport word's
	 * eight bits... */
	frame6(&eth3, NULL, NULL, 0);
	want = strip(40);
	taken(submit(), &eth3_priv, &eth3_dma);
	frame6(&eth3, (u8[]){NEXTHDR_HOP, NEXTHDR_DEST}, (u16[]){1, 2}, 2);
	want = strip(64);
	taken(submit(), &eth3_priv, &eth3_dma);
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){32}, 1);
	want = strip(296);
	taken(submit(), &eth3_priv, &eth3_dma);
	/* ...up to its twelve, the whole way back to the MAC header counted:
	 * that is how much SEC is given. */
	frame6(&eth3, (u8[]){NEXTHDR_HOP, NEXTHDR_DEST}, (u16[]){256, 250}, 2);
	want = strip(4088);
	taken(submit(), &eth3_priv, &eth3_dma);
	assert(skb.data == buffer && skb.len == 100 + 14 + 4088);
	frame6(&eth3, (u8[]){NEXTHDR_HOP, NEXTHDR_DEST}, (u16[]){256, 251}, 2);
	handed_back(submit());
	/* What SEC refuses to queue goes back moved by as much. */
	frame6(&eth3, (u8[]){NEXTHDR_HOP, NEXTHDR_DEST}, (u16[]){256, 250}, 2);
	bench.enqueue_result = -5;
	assert(submit() == -1 && bench.releases == 1);
	assert(skb.data == start && skb.len == 100);
	/* The byte the stack found ESP by has to name it. */
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){1}, 1);
	skb.cb6.nhoff = 6;
	handed_back(submit());

	/* ESP-in-UDP: the UDP header goes too... */
	sa.encap = &espinudp;
	frame4(5, true);
	assert(want == strip(28));
	taken(submit(), &eth3_priv, &eth3_dma);
	frame4(6, true);
	taken(submit(), &eth3_priv, &eth3_dma);
	assert(!checksum_writes && !bench.cows);
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){1}, 1);
	udp6();
	want = strip(56);
	taken(submit(), &eth3_priv, &eth3_dma);
	/* ...but bare ESP is not how such a state receives... */
	frame4(5, false);
	handed_back(submit());
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){1}, 1);
	handed_back(submit());
	/* ...nor is ESP without a whole IP and UDP header ahead of it. */
	frame(&eth3, 14, 14);
	buffer[14 + 9] = IPPROTO_UDP;
	skb.data = start = buffer + 14 + 8;
	memcpy(original, buffer, sizeof(buffer));
	handed_back(submit());
	frame4(6, true);
	buffer[14] = 0x45;
	memcpy(original, buffer, sizeof(buffer));
	handed_back(submit());

	/* A state without one takes nothing the stack found in UDP. */
	sa.encap = NULL;
	frame4(5, true);
	handed_back(submit());
	frame6(&eth3, (u8[]){NEXTHDR_HOP}, (u16[]){1}, 1);
	udp6();
	handed_back(submit());

	/* Nor is a transport state received in UDP, which is never
	 * offloaded. */
	sa.props.mode = XFRM_MODE_TRANSPORT;
	sa.encap = &espinudp;
	frame4(5, true);
	handed_back(submit());
	sa.encap = NULL;
}

int main(void)
{
	setup();
	test_ports();
	test_other_devices();
	test_headers();
	test_tunnel_headers();
	return 0;
}

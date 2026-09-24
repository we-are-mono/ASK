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
};
/* What the submit reads of the state: its handle and the device it is bound
 * to. */
struct xfrm_state {
	u16 handle;
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
	int sg_result, enqueue_result;
	unsigned cows, sg_calls, enqueues, releases;
	struct device *sg_dev;
	struct net_device *sg_netdev;
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
static struct net *dev_net(const struct net_device *dev) { (void)dev; return &init_net; }

static int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	(void)skb; (void)headroom;
	bench.cows++;
	return 0;
}

static int skb_fraglist_to_sg_fd(struct device *dev, struct net_device *net_dev,
				 struct sk_buff *skb, struct qm_fd *fd, u32 fd_cmd)
{
	(void)skb;
	bench.sg_calls++;
	bench.sg_dev = dev;
	bench.sg_netdev = net_dev;
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

static _Alignas(8) u8 buffer[256], original[256];
static struct sk_buff skb;

static void reset(void)
{
	memset(&bench, 0, sizeof(bench));
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
	memcpy(original, buffer, sizeof(buffer));
	reset();
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
	assert(skb.data == buffer + skb.network_header + 20 && skb.len == 100);
	assert(!memcmp(buffer, original, sizeof(buffer)));
	assert(!bench.cows && !bench.sg_calls && !bench.enqueues && !bench.releases);
	assert(!eth3_cpu.tx_caam_dec && !eth4_cpu.tx_caam_dec);
	assert(rcu_depth == 0);
}

/* Given to SEC from the MAC header on, mapped for `dma` and counted as the
 * port's. */
static void taken(int rc, struct dpa_priv_s *priv, struct device *dma)
{
	assert(rc == 0 && fq_asked == 7);
	assert(bench.sg_calls == 1 && bench.enqueues == 1 && !bench.releases);
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

int main(void)
{
	setup();
	test_ports();
	test_other_devices();
	return 0;
}

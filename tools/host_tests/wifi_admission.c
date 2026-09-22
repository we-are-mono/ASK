/* The admission contract for a Wi-Fi VAP, compiled from the backend.
 *
 * Step 5 of docs/flowtable/wifi.md rests on one asymmetry: a VAP may be a
 * flow's egress and may never be its ingress. That is not a preference. A
 * VAP's ingress cannot be hooked at all -- an offloaded flowtable refuses to
 * bind a device whose driver supports no offload, and `moal` supports none --
 * so a flow arriving from Wi-Fi never reaches this contract and stays on the
 * software path. Two predicates state it, and a test that only exercised the
 * wider one would not notice the narrow one quietly widening too.
 *
 * Three gates had to open before a VAP egress reached hardware, and each was
 * found on the rig at the cost of a build and a reboot:
 *
 *   - the predicate itself matched IF_TYPE_ETHERNET|PHYSICAL exactly;
 *   - dpa_get_ifinfo_by_netdev() looked only at ethernet ifaces, so a VAP was
 *     unresolvable from its netdev and widening the predicate changed nothing;
 *   - cdx_ft_hw_add() carried its own copy of the same type test.
 *
 * The first and third are compiled here. The second is a lookup this harness
 * stubs, so it is covered by the case where the lookup finds nothing -- which
 * is exactly what that bug looked like from the predicate's side, and the
 * shape a reader should recognise if it ever returns.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8, U8;
typedef uint16_t u16;
typedef uint32_t u32;

#define ETH_ALEN 6
#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
#define L2_MAX_ONIF 64
#define ENTRY_VALID 1

/* The real interface-type bits, from cdx/layer2.h. Stated rather than included
 * because the header drags in the whole control plane; a mismatch here would
 * make every assertion below vacuous, so they are checked against the values
 * the adapter uses, not merely against each other. */
#define IF_TYPE_ETHERNET (1 << 0)
#define IF_TYPE_WLAN     (1 << 5)
#define IF_TYPE_PHYSICAL (1 << 7)

enum { NETREG_REGISTERED = 0, NETREG_UNREGISTERING = 1 };

struct net_device {
	char name[16];
	unsigned short type;
	unsigned char addr_len;
	int reg_state;
	bool running;
	bool carrier;
	bool l3_slave;
	bool switch_port;
	bool in_init_net;
};

struct _itf { u32 index; U8 type; };
typedef struct { u32 flags; struct _itf *itf; } OnifDesc, *POnifDesc;
struct dpa_iface_info { u32 itf_id; };

/* --- the world the predicates read ------------------------------------- */
static OnifDesc onif_table[L2_MAX_ONIF];
static struct dpa_iface_info iface_table[L2_MAX_ONIF];
static struct _itf itf_table[L2_MAX_ONIF];
/* Which netdev each onif index belongs to; NULL means the lookup fails, which
 * is how an unresolvable device presents. */
static struct net_device *owner[L2_MAX_ONIF];
static bool vap_open_answer;

static bool net_eq_init(const struct net_device *d) { return d->in_init_net; }
static bool netif_is_l3_slave(const struct net_device *d) { return d->l3_slave; }
static bool netif_running(const struct net_device *d) { return d->running; }
static bool netif_carrier_ok(const struct net_device *d) { return d->carrier; }
static void cdx_ft_assert_held(void) { }

static struct dpa_iface_info *dpa_get_ifinfo_by_netdev(const struct net_device *dev)
{
	int i;

	for (i = 0; i < L2_MAX_ONIF; i++)
		if (owner[i] == dev)
			return &iface_table[i];
	return NULL;
}

static POnifDesc get_onif_by_index(u32 i) { return &onif_table[i]; }
static bool dpaa_vwd_vap_is_open(const struct net_device *dev)
{
	(void)dev;
	return vap_open_answer;
}

/* The production predicates read this through dev_get_port_parent_id(); the
 * harness answers the same question from the device. */
static bool cdx_ft_switch_port(struct net_device *dev) { return dev->switch_port; }

#define net_eq(a, b) net_eq_init(dev)
#define dev_net(d) (d)
#define init_net (0)
#define netdev_name(d) ((d)->name)
#define unlikely(x) (x)
#define pr_info(...) do { } while (0)

static __attribute__((unused)) unsigned int cdx_ft_debug_mask;
#define ASK_DBG_DEVICE 0x4
#define ask_dbg(bit, fmt, ...) do { (void)(bit); } while (0)

#include "wifi_admission_production.inc"

/* --- the bench --------------------------------------------------------- */
static struct net_device devs[8];
static int ndevs;

/* A device wired to an onif of the given type, in the state a working port is
 * in. Each test then breaks exactly one thing. */
static struct net_device *mkdev(const char *name, U8 onif_type)
{
	struct net_device *d = &devs[ndevs];
	int i = ndevs++;

	memset(d, 0, sizeof(*d));
	snprintf(d->name, sizeof(d->name), "%s", name);
	d->type = ARPHRD_ETHER;
	d->addr_len = ETH_ALEN;
	d->reg_state = NETREG_REGISTERED;
	d->running = d->carrier = d->in_init_net = true;
	itf_table[i].index = i;
	itf_table[i].type = onif_type;
	onif_table[i].flags = ENTRY_VALID;
	onif_table[i].itf = &itf_table[i];
	iface_table[i].itf_id = i;
	owner[i] = d;
	return d;
}

static void reset(void)
{
	memset(owner, 0, sizeof(owner));
	ndevs = 0;
	vap_open_answer = true;
}

/* The contract itself: ethernet is both, a VAP is egress only. */
static void test_asymmetry(void)
{
	struct net_device *eth = mkdev("eth4", IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
	struct net_device *vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);

	assert(cdx_ft_port_supported(eth));
	assert(cdx_ft_egress_supported(eth));

	/* The whole of step 5, and the whole of what it must not become. */
	assert(cdx_ft_egress_supported(vap));
	assert(!cdx_ft_port_supported(vap));
	reset();
}

/* A VAP that is not open has no frame queues for an entry to name. */
static void test_vap_must_be_open(void)
{
	struct net_device *vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);

	vap_open_answer = false;
	assert(!cdx_ft_egress_supported(vap));
	vap_open_answer = true;
	assert(cdx_ft_egress_supported(vap));
	reset();
}

/* The shape of the bug that made widening the predicate useless: the device
 * resolves to no interface at all, so the onif type is never even reached. */
static void test_unresolvable_device(void)
{
	struct net_device *vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);

	owner[0] = NULL;
	assert(!cdx_ft_egress_supported(vap));
	assert(!cdx_ft_port_supported(vap));
	reset();
}

/* Everything the two predicates share, checked through the wider one so a
 * regression cannot hide behind the VAP arm. */
static void test_common_requirements(void)
{
	struct net_device *vap;

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	vap->running = false;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	vap->carrier = false;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	vap->reg_state = NETREG_UNREGISTERING;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	vap->l3_slave = true;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	vap->switch_port = true;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	vap->type = ARPHRD_PPP;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	vap->in_init_net = false;
	assert(!cdx_ft_egress_supported(vap));
	reset();
}

/* A type neither predicate names. IF_TYPE_WLAN without PHYSICAL is what a
 * VLAN riding a VAP would carry, and it is not an egress this contract
 * admits: the encoder resolves a frame queue from the physical VAP, not from
 * a tag on top of one. */
static void test_unnamed_types(void)
{
	struct net_device *d;

	d = mkdev("x", IF_TYPE_WLAN);
	assert(!cdx_ft_egress_supported(d) && !cdx_ft_port_supported(d));
	reset();

	d = mkdev("x", IF_TYPE_ETHERNET);
	assert(!cdx_ft_egress_supported(d) && !cdx_ft_port_supported(d));
	reset();

	d = mkdev("x", IF_TYPE_ETHERNET | IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	assert(!cdx_ft_egress_supported(d) && !cdx_ft_port_supported(d));
	reset();
}

/* An onif whose entry is stale, or whose index disagrees with the interface
 * record pointing at it. */
static void test_onif_consistency(void)
{
	struct net_device *vap;

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	onif_table[0].flags = 0;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	itf_table[0].index = 7;
	assert(!cdx_ft_egress_supported(vap));
	reset();

	vap = mkdev("uap0", IF_TYPE_WLAN | IF_TYPE_PHYSICAL);
	onif_table[0].itf = NULL;
	assert(!cdx_ft_egress_supported(vap));
	reset();
}

int main(void)
{
	reset();
	test_asymmetry();
	test_vap_must_be_open();
	test_unresolvable_device();
	test_common_requirements();
	test_unnamed_types();
	test_onif_consistency();
	printf("wifi_admission: ok\n");
	return 0;
}

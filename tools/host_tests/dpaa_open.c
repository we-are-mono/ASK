/* A DPAA netdev's open, compiled from the kernel source: the SDK's port
 * enable through dpa_start() to the ndo_open.
 *
 * An open can fail: a port its owner holds fenced (FM_PORT_SetFenced())
 * refuses to enable, a MAC may not start, a PHY may be taken. Such an open has
 * to leave the netdev as it found it -- NAPI off, the PHY let go, every port
 * disabled -- and say so with an errno, so that the next open, once the port
 * may start, works. Here enabling a NAPI already enabled fails an assertion,
 * as the kernel's BUG_ON in napi_enable() does, and connecting a PHY already
 * attached fails with -EBUSY, as phy_attach_direct() does.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define __cold
#define EXPORT_SYMBOL(sym)	extern int __unused_##sym
#define netif_msg_ifup(priv)	0
#define netdev_err(...)		((void)0)

/* The SDK's error codes: a module in the upper half, the type -- an errno's
 * value, E_BUSY being EBUSY -- in the lower. Any module will do. */
typedef uint32_t t_Error;
#define __ERR_MODULE__		0x00110000u

/* A port as the SDK keeps it: enabled, fenced against enables, and
 * verifying L4 checksums -- or refusing to change that. */
struct port { bool enabled, fenced, l4csum, fixed_l4csum; };
struct fm_port;
typedef struct { void *h_Dev; } t_LnxWrpFmPortDev;

struct net_device { bool tx_started; };
struct phy_device { struct net_device *attached; };
struct mac_device {
	struct fm_port *port_dev[2];
	struct phy_device *phy_dev;
	int (*init_phy)(struct net_device *net_dev, struct mac_device *mac_dev);
	int (*start)(struct mac_device *mac_dev);
};
struct dpa_priv_s { struct mac_device *mac_dev; bool napi; };

static struct dpa_priv_s priv;
static void *netdev_priv(const struct net_device *dev) { (void)dev; return &priv; }
/* Every NAPI context of the netdev, as one: the kernel's BUG_ON. */
static void dpaa_eth_napi_enable(struct dpa_priv_s *p) { assert(!p->napi); p->napi = true; }
static void dpaa_eth_napi_disable(struct dpa_priv_s *p) { assert(p->napi); p->napi = false; }
static void netif_tx_start_all_queues(struct net_device *dev) { dev->tx_started = true; }
static void dpa_update_eth_if(struct dpa_priv_s *p) { (void)p; }

static struct phy_device phy;
/* memac_init_phy(): of_phy_connect() turns phy_attach_direct()'s -EBUSY
 * ("PHY already attached") into NULL, answered as -ENODEV. */
static int init_phy(struct net_device *dev, struct mac_device *mac)
{
	if (phy.attached)
		return -ENODEV;
	phy.attached = dev;
	mac->phy_dev = &phy;
	return 0;
}
static void phy_disconnect(struct phy_device *p) { assert(p->attached); p->attached = NULL; }
static int mac_start_result;
static int mac_start(struct mac_device *mac) { (void)mac; return mac_start_result; }

/* Defined after the error macros below are lifted. */
static t_Error FM_PORT_Enable(void *h);
static t_Error FM_PORT_Disable(void *h);
static t_Error FM_PORT_SetRxL4ChecksumVerify(void *h, bool enable);

#include "dpaa_open_production.inc"

static t_Error FM_PORT_Enable(void *h)
{
	struct port *p = h;

	if (p->fenced)
		return ERROR_CODE(EBUSY);
	p->enabled = true;
	return 0;
}
static t_Error FM_PORT_Disable(void *h) { ((struct port *)h)->enabled = false; return 0; }
static t_Error FM_PORT_SetRxL4ChecksumVerify(void *h, bool enable)
{
	struct port *p = h;

	if (p->fixed_l4csum)
		return ERROR_CODE(EIO);
	p->l4csum = enable;
	return 0;
}

/* Rx first, then Tx, as the SDK lists a MAC's ports. */
static struct port ports[2];
static t_LnxWrpFmPortDev wrappers[2] = { { &ports[0] }, { &ports[1] } };
static struct mac_device mac = {
	.port_dev = { (struct fm_port *)&wrappers[0], (struct fm_port *)&wrappers[1] },
	.init_phy = init_phy,
	.start = mac_start,
};
static struct net_device netdev, other;

static bool closed(void)
{
	return !priv.napi && !phy.attached && !mac.phy_dev &&
	       !ports[0].enabled && !ports[1].enabled && !netdev.tx_started;
}
static bool opened(void)
{
	return priv.napi && phy.attached == &netdev && mac.phy_dev == &phy &&
	       ports[0].enabled && ports[1].enabled && netdev.tx_started;
}
/* What the stop undoes (dpa_eth_priv_stop(), dpa_stop()). */
static void stop(void)
{
	if (priv.napi)
		dpaa_eth_napi_disable(&priv);
	phy_disconnect(mac.phy_dev);
	mac.phy_dev = NULL;
	ports[0].enabled = ports[1].enabled = false;
	netdev.tx_started = false;
}

int main(void)
{
	priv.mac_dev = &mac;
	/* The port API answers in errnos, not in the SDK's own codes. */
	assert(fm_port_enable(mac.port_dev[0]) == 0 && ports[0].enabled);
	assert(fm_port_disable(mac.port_dev[0]) == 0 && !ports[0].enabled);
	ports[1].fenced = true;
	assert(fm_port_enable(mac.port_dev[1]) == -EBUSY && !ports[1].enabled);
	/* And so do the PM callbacks' and ndo_set_features' calls, whose
	 * callers read only a negative value as a failure. */
	assert(fm_port_resume(mac.port_dev[1]) == -EBUSY && !ports[1].enabled);
	ports[1].fenced = false;
	assert(fm_port_resume(mac.port_dev[1]) == 0 && ports[1].enabled);
	assert(fm_port_suspend(mac.port_dev[1]) == 0 && !ports[1].enabled);
	assert(fm_port_enable_rx_l4csum(mac.port_dev[0], true) == 0 && ports[0].l4csum);
	ports[0].fixed_l4csum = true;
	assert(fm_port_enable_rx_l4csum(mac.port_dev[0], false) == -EIO && ports[0].l4csum);
	ports[0].fixed_l4csum = false;

	/* A fenced Rx port: the open fails with -EBUSY and leaves nothing
	 * behind; asked again while fenced, the same; once the fence is down,
	 * the next open works. */
	ports[0].fenced = true;
	assert(dpa_eth_priv_start(&netdev) == -EBUSY && closed());
	assert(dpa_eth_priv_start(&netdev) == -EBUSY && closed());
	ports[0].fenced = false;
	assert(dpa_eth_priv_start(&netdev) == 0 && opened());
	stop();
	/* A fenced Tx port: the Rx port it had started is disabled again. */
	ports[1].fenced = true;
	assert(dpa_eth_priv_start(&netdev) == -EBUSY && closed());
	ports[1].fenced = false;
	assert(dpa_eth_priv_start(&netdev) == 0 && opened());
	stop();
	/* A MAC that will not start: the same. */
	mac_start_result = -EIO;
	assert(dpa_eth_priv_start(&netdev) == -EIO && closed());
	mac_start_result = 0;
	assert(dpa_eth_priv_start(&netdev) == 0 && opened());
	stop();
	/* A PHY another device holds: nothing else is touched. */
	phy.attached = &other;
	assert(dpa_eth_priv_start(&netdev) == -ENODEV && !priv.napi && !mac.phy_dev &&
	       !ports[0].enabled && !ports[1].enabled);
	phy.attached = NULL;
	assert(dpa_eth_priv_start(&netdev) == 0 && opened());
	stop();
	puts("DPAA failed opens unwind: passed");
	return 0;
}

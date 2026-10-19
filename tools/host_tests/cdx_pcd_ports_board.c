/* Run the real cdx_pcd_ports.c on the host against a modelled gateway-dk.
 *
 * The model is what the SDK leaves behind after probing the board: one netdev
 * per MAC, each MAC bound to the FMan wrapper's RX port that its device-tree
 * port node names, and the offline ports the OH driver registered. Only the
 * MACs' link speeds differ between the boards:
 *
 *   dut     every MAC at its native speed
 *   router  MAC10 at 1000base-x, as U-Boot leaves it when the SerDes RCW
 *           (0x1333) runs SFP1's lane at 1G; its RX port is still the FMan's
 *           10G port 1
 *
 * For every port the harness prints what cdx classifies, and whether the
 * wrapper port that classification resolves to is the one the MAC is bound to.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cdx_pcd.h"
#include "lnxwrp_fm.h"
#include "dpaa_eth.h"
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/fsl_oh_port.h>

struct net init_net;
struct net_device *harness_netdevs[8];
unsigned int harness_num_netdevs;
struct device_node *harness_nodes[8];
unsigned int harness_num_nodes;

static t_LnxWrpFmDev fm;

static const char *const oh_bound[] = {
	"dpa-fman0-oh@2", "dpa-fman0-oh@3", "dpa-fman0-oh@4",
};

int oh_port_driver_get_port_info(struct fman_offline_port_info *info)
{
	for (size_t i = 0; i < sizeof(oh_bound) / sizeof(oh_bound[0]); i++)
		if (!strcmp(info->port_name, oh_bound[i]))
			return 0;
	return -ENODEV;
}

struct mac {
	const char *name;
	unsigned int mac_cell;	/* the MAC node's cell-index */
	unsigned int rx_cell;	/* its RX port node's cell-index */
	int max_speed;
};

static struct device_node eth_compat = { .compatible = "fsl,dpa-ethernet" };

static void add_mac(const struct mac *m, int max_speed)
{
	struct net_device *dev = calloc(1, sizeof(*dev));
	struct device *parent = calloc(1, sizeof(*parent));
	struct device *mac_of = calloc(1, sizeof(*mac_of));
	struct device_node *mac_node = calloc(1, sizeof(*mac_node));
	struct mac_device *mac_dev = calloc(1, sizeof(*mac_dev));
	struct dpa_priv_s *priv = calloc(1, sizeof(*priv));
	t_LnxWrpFmPortDev *rx;

	/* sdk_fman's port probe: 1G RX ports are cell-index 0x08 + n and land
	 * at rxPorts[n]; 10G RX ports are 0x10 + n and land after the 1G ones. */
	if (m->rx_cell >= 0x10) {
		rx = &fm.rxPorts[m->rx_cell - 0x10 + FM_MAX_NUM_OF_1G_RX_PORTS];
		rx->id = m->rx_cell - 0x10;
		rx->settings.param.portType = e_FM_PORT_TYPE_RX_10G;
	} else {
		rx = &fm.rxPorts[m->rx_cell - 0x08];
		rx->id = m->rx_cell - 0x08;
		rx->settings.param.portType = e_FM_PORT_TYPE_RX;
	}
	rx->settings.param.portId = rx->id;
	rx->active = true;
	rx->h_Dev = rx;

	/* sdk_dpaa's mac probe: cell-index folded below 8, speed from the
	 * interface mode. */
	mac_node->full_name = m->name;
	mac_of->of_node = mac_node;
	mac_dev->dev = mac_of;
	mac_dev->fm_dev = &fm;
	mac_dev->cell_index = m->mac_cell >= 8 ? m->mac_cell - 8 : m->mac_cell;
	mac_dev->max_speed = max_speed;
	mac_dev->port_dev[RX] = rx;

	priv->mac_dev = mac_dev;
	parent->of_node = &eth_compat;
	snprintf(dev->name, sizeof(dev->name), "%s", m->name);
	dev->dev.parent = parent;
	dev->priv = priv;
	harness_netdevs[harness_num_netdevs++] = dev;
}

static void add_oh_node(const char *path)
{
	struct device_node *node = calloc(1, sizeof(*node));

	node->full_name = path;
	node->compatible = "fsl,dpa-oh";
	harness_nodes[harness_num_nodes++] = node;
}

/* What cdx_pcd.c's cdx_pcd_wrapper_port() resolves a classified port to. */
static t_LnxWrpFmPortDev *resolve(const struct cdx_pcd_port *port)
{
	switch (port->type) {
	case e_FM_PORT_TYPE_RX_10G:
		return &fm.rxPorts[port->number + FM_MAX_NUM_OF_1G_RX_PORTS];
	case e_FM_PORT_TYPE_RX:
		return &fm.rxPorts[port->number];
	default:
		return NULL;
	}
}

static const char *type_name(e_FmPortType type)
{
	switch (type) {
	case e_FM_PORT_TYPE_RX: return "1G";
	case e_FM_PORT_TYPE_RX_10G: return "10G";
	case e_FM_PORT_TYPE_OH_OFFLINE_PARSING: return "OH";
	default: return "?";
	}
}

int main(int argc, char **argv)
{
	/* eth0..eth4 in the order the router registers them. */
	static const struct mac macs[] = {
		{ "eth0", 1, 0x09, 1000 },	/* MAC2 */
		{ "eth1", 4, 0x0c, 1000 },	/* MAC5 */
		{ "eth2", 5, 0x0d, 1000 },	/* MAC6 */
		{ "eth3", 8, 0x10, 10000 },	/* MAC9, SFP0 */
		{ "eth4", 9, 0x11, 10000 },	/* MAC10, SFP1 */
	};
	struct cdx_pcd_port ports[CDX_PCD_MAX_PORTS];
	bool router = argc > 1 && !strcmp(argv[1], "router");
	void *fm_dev;
	int count;

	for (size_t i = 0; i < sizeof(macs) / sizeof(macs[0]); i++)
		add_mac(&macs[i], router && i == 4 ? 1000 : macs[i].max_speed);
	add_oh_node("/soc/fsl,dpaa/dpa-fman0-oh@2");
	add_oh_node("/soc/fsl,dpaa/dpa-fman0-oh@3");
	add_oh_node("/soc/fsl,dpaa/dpa-fman0-oh@4");

	count = cdx_pcd_enumerate_ports(0, ports, CDX_PCD_MAX_PORTS, &fm_dev);
	printf("count %d\n", count);
	for (int i = 0; i < count; i++) {
		const struct cdx_pcd_port *p = &ports[i];
		const char *bound = "-";

		for (unsigned int n = 0; n < harness_num_netdevs; n++) {
			struct dpa_priv_s *priv = harness_netdevs[n]->priv;

			if (!strcmp(harness_netdevs[n]->name, p->name))
				bound = (void *)resolve(p) == priv->mac_dev->port_dev[RX] ?
					"own" : "other";
		}
		printf("%s %s %u %u %u %s\n", p->name, type_name(p->type),
		       p->number, p->portid, p->speed, bound);
	}
	return 0;
}

// SPDX-License-Identifier: GPL-2.0+
/*
 * Which FMan ports take part in classification, and what logical port id each
 * one carries.
 *
 * This replaces cdx_cfg.xml. Nothing in that file was board data the kernel did
 * not already have: the port set is whatever the device tree enabled, `number`
 * is the DT cell-index, `policy` was identical for every port, and `portid` is
 * a formula over the SoC's port counts. See docs/in-kernel-pcd.md.
 *
 * The logical port id ends up in prsResultPrivateInfo, which cdx_sp.xml reads as
 * $logicalportid and tests against 9 to tell ethernet ports from offline ports.
 * Get it wrong and the soft parser misroutes rather than failing loudly.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/rtnetlink.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/fsl_oh_port.h>
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "mac.h"
#include "lnxwrp_fm.h"
#include "portdefs.h"
#include "cdx_pcd.h"

/*
 * A flat index over the FMan's whole port space: 1G MACs first, then 10G, then
 * the offline ports. Offline port 0 is the host-command port, which lands on
 * the first offline slot and never takes part in classification.
 */
#define CDX_PCD_PORTID_10G_BASE		FM_MAX_NUM_OF_1G_RX_PORTS
#define CDX_PCD_PORTID_OH_BASE		(FM_MAX_NUM_OF_1G_RX_PORTS + \
					 FM_MAX_NUM_OF_10G_RX_PORTS)

/* Boards that follow the convention need no device-tree property at all. */
#define CDX_PCD_PORTID_PROP		"mono,cdx-logical-portid"

static int cdx_pcd_portid(const struct device_node *node, e_FmPortType type,
			  u8 cell_index)
{
	u32 override;
	unsigned int base;

	switch (type) {
	case e_FM_PORT_TYPE_RX:
		base = 0;
		break;
	case e_FM_PORT_TYPE_RX_10G:
		base = CDX_PCD_PORTID_10G_BASE;
		break;
	case e_FM_PORT_TYPE_OH_OFFLINE_PARSING:
		base = CDX_PCD_PORTID_OH_BASE;
		break;
	default:
		return -EINVAL;
	}

	if (node && !of_property_read_u32(node, CDX_PCD_PORTID_PROP, &override)) {
		/* The id is OR'd into FQID bits 16-19 through a 4-bit mask and
		 * compared against 9 by the soft parser; anything that does not
		 * fit those is a board bug worth refusing. */
		if (override > 15) {
			pr_err("cdx: %pOF: " CDX_PCD_PORTID_PROP " %u out of range\n",
			       node, override);
			return -ERANGE;
		}
		return override;
	}
	return base + cell_index;
}

/*
 * netdev_priv() is only a struct dpa_priv_s on a netdev the SDK's private
 * ethernet driver created. Every bridge, VLAN and veth interface is also
 * ARPHRD_ETHER, so type alone does not establish that -- match the parent
 * platform device's binding instead, which is what dpa_probe() set.
 */
static bool cdx_pcd_is_dpa_netdev(const struct net_device *dev)
{
	return dev->dev.parent && dev->dev.parent->of_node &&
	       of_device_is_compatible(dev->dev.parent->of_node,
				       "fsl,dpa-ethernet");
}

/* Mirrors find_osdev_by_fman_params() in the opposite direction: instead of
 * asking "which netdev is this FMan port", ask every DPAA netdev which FMan
 * port it is. Caller holds RTNL. */
static int cdx_pcd_add_eth_ports(u8 fm_index, struct cdx_pcd_port *ports,
				 unsigned int max_ports, unsigned int count,
				 void **fm_dev_out)
{
	struct net_device *dev;

	ASSERT_RTNL();

	for_each_netdev(&init_net, dev) {
		t_LnxWrpFmDev *fm_dev;
		struct mac_device *mac_dev;
		struct cdx_pcd_port *port;
		struct dpa_priv_s *priv;
		int portid;

		if (!cdx_pcd_is_dpa_netdev(dev))
			continue;
		priv = netdev_priv(dev);
		mac_dev = priv->mac_dev;
		if (!mac_dev)
			continue;
		fm_dev = (t_LnxWrpFmDev *)mac_dev->fm;
		if (!fm_dev || fm_dev->id != fm_index)
			continue;

		if (count >= max_ports) {
			pr_err("cdx: more than %u classification ports\n", max_ports);
			return -ENOSPC;
		}
		port = &ports[count];
		port->type = mac_dev->max_speed == SPEED_10000 ?
			e_FM_PORT_TYPE_RX_10G : e_FM_PORT_TYPE_RX;
		port->speed = mac_dev->max_speed == SPEED_10000 ? 10 : 1;
		port->fm_index = fm_index;
		port->number = mac_dev->cell_index;

		portid = cdx_pcd_portid(mac_dev->dev ? mac_dev->dev->of_node : NULL,
					port->type, port->number);
		if (portid < 0)
			return portid;
		port->portid = portid;
		strscpy(port->name, dev->name, sizeof(port->name));
		*fm_dev_out = fm_dev;
		count++;
	}
	return count;
}

/*
 * The offline-port driver records every fsl,dpa-oh node it bound, keyed by the
 * node name. Probing the names is how cdx learns which offline ports exist:
 * ports the device tree left unbound -- including the host-command port -- never
 * registered, so they drop out without needing to be excluded by name.
 */
static struct device_node *cdx_pcd_find_oh_node(const char *name)
{
	struct device_node *node = NULL;

	for_each_compatible_node(node, NULL, "fsl,dpa-oh")
		if (!strcmp(kbasename(node->full_name), name))
			return node;
	return NULL;
}

static int cdx_pcd_add_oh_ports(u8 fm_index, struct cdx_pcd_port *ports,
				unsigned int max_ports, unsigned int count)
{
	unsigned int slot;

	for (slot = 1; slot <= MAX_OFFLINE_PORTS; slot++) {
		struct fman_offline_port_info info = { 0 };
		struct cdx_pcd_port *port;
		struct device_node *node;
		int portid;

		snprintf(info.port_name, sizeof(info.port_name),
			 "dpa-fman%u-oh@%u", fm_index, slot);
		if (oh_port_driver_get_port_info(&info))
			continue;

		if (count >= max_ports) {
			pr_err("cdx: more than %u classification ports\n", max_ports);
			return -ENOSPC;
		}
		port = &ports[count];
		port->type = e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
		port->speed = 0;
		port->fm_index = fm_index;
		/* The node name counts from one, the SDK cell-index from zero. */
		port->number = slot - 1;

		node = cdx_pcd_find_oh_node(info.port_name);
		portid = cdx_pcd_portid(node, port->type, port->number);
		of_node_put(node);
		if (portid < 0)
			return portid;
		port->portid = portid;
		strscpy(port->name, info.port_name, sizeof(port->name));
		count++;
	}
	return count;
}

/* Rank by port class, then by cell-index. */
static int cdx_pcd_port_cmp(const void *a, const void *b)
{
	static const int rank[] = {
		[e_FM_PORT_TYPE_RX] = 0,
		[e_FM_PORT_TYPE_RX_10G] = 1,
		[e_FM_PORT_TYPE_OH_OFFLINE_PARSING] = 2,
	};
	const struct cdx_pcd_port *pa = a, *pb = b;

	if (rank[pa->type] != rank[pb->type])
		return rank[pa->type] - rank[pb->type];
	return (int)pa->number - (int)pb->number;
}

int cdx_pcd_enumerate_ports(u8 fm_index, struct cdx_pcd_port *ports,
			    unsigned int max_ports, void **fm_dev)
{
	unsigned int i, j;
	int count;

	*fm_dev = NULL;
	count = cdx_pcd_add_eth_ports(fm_index, ports, max_ports, 0, fm_dev);
	if (count < 0)
		return count;
	count = cdx_pcd_add_oh_ports(fm_index, ports, max_ports, count);
	if (count < 0)
		return count;
	if (!count) {
		pr_err("cdx: fm%u has no classification ports\n", fm_index);
		return -ENODEV;
	}
	/* The FMan wrapper comes from a MAC's back-pointer, so an FMan with
	 * only offline ports would leave it unset. No such configuration
	 * exists, and the classifier would have nothing to receive from. */
	if (!*fm_dev) {
		pr_err("cdx: fm%u has no ethernet ports\n", fm_index);
		return -ENODEV;
	}

	/* Netdev registration order is not cell-index order, and the port this
	 * sort puts first is the one whose CC root tree every shared scheme
	 * binds to. Sorting keeps that choice, and the whole build, independent
	 * of the order interfaces happened to come up in. */
	sort(ports, count, sizeof(*ports), cdx_pcd_port_cmp, NULL);

	/* A duplicate id would make two ports share FQID bits 16-19 and give
	 * the soft parser an ambiguous $logicalportid. Cheap to check once. */
	for (i = 0; i < (unsigned int)count; i++)
		for (j = i + 1; j < (unsigned int)count; j++)
			if (ports[i].portid == ports[j].portid) {
				pr_err("cdx: %s and %s share logical port id %u\n",
				       ports[i].name, ports[j].name, ports[i].portid);
				return -EINVAL;
			}
	return count;
}

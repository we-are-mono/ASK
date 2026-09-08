// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Mono SFP port LED controller for the DPAA SDK fixed-link configuration.
 *
 * Module presence comes from the mandatory SFP EEPROM. Link state comes
 * from the MAC's XFI PCS, for both optical modules and DACs. The monitor
 * does not configure the PCS or interact with the SFP state machine.
 *
 * No module: both LEDs off. Module without link: solid orange. Link up:
 * green on, orange blinking on changes to the netdev packet counters.
 * User-selected LED triggers take precedence over this monitor.
 *
 * Each mono,sfp-led child references an SFP with "sfp" and its link and
 * activity LEDs with "leds". The associated fsl,fman-memac node references
 * the same SFP and identifies the XFI PCS through "pcs-handle" and
 * "pcs-handle-names". No module diagnostic support is required.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Author: Tomaz Zaman <tomaz@mono.si>
 */

#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/leds.h>
#include <linux/mdio.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/rtnetlink.h>
#include <linux/sfp.h>
#include <linux/workqueue.h>

#define SFP_LED_POLL_INTERVAL_MS	100
#define SFP_LED_EEPROM_ADDR	0x50

struct sfp_led_port {
	struct device_node *mac_np;
	struct i2c_adapter *i2c;
	struct mii_bus *pcs_bus;
	int pcs_addr;
	struct led_classdev *link_led;
	struct led_classdev *activity_led;
	struct delayed_work poll_work;
	bool last_link;
	bool activity_on;
	int last_ifindex;
	u64 last_tx_packets;
	u64 last_rx_packets;
};

struct sfp_led_priv {
	unsigned int num_ports;
	struct sfp_led_port *ports;
};

static void sfp_led_set(struct led_classdev *led, bool on)
{
	if (!led)
		return;

	down_read(&led->trigger_lock);
	if (!led->trigger)
		led_set_brightness(led, on ? led->max_brightness : LED_OFF);
	up_read(&led->trigger_lock);
}

/* The caller holds RTNL throughout lookup and use; no reference is cached. */
static struct net_device *sfp_led_find_netdev(struct device_node *mac_np)
{
	struct net_device *netdev;

	ASSERT_RTNL();
	for_each_netdev(&init_net, netdev) {
		struct device *parent = netdev->dev.parent;
		struct device_node *node;
		bool match;

		if (!parent || !parent->of_node)
			continue;

		node = of_parse_phandle(parent->of_node, "fsl,fman-mac", 0);
		match = node == mac_np;
		of_node_put(node);
		if (match)
			return netdev;
	}

	return NULL;
}

static bool sfp_led_module_present(struct sfp_led_port *port)
{
	union i2c_smbus_data data;
	int ret;

	ret = i2c_smbus_xfer(port->i2c, SFP_LED_EEPROM_ADDR, 0,
			     I2C_SMBUS_READ, SFP_PHYS_ID,
			     I2C_SMBUS_BYTE_DATA, &data);
	return ret >= 0;
}

static int sfp_led_pcs_link(struct sfp_led_port *port)
{
	int status;

	/*
	 * Read twice to clear the latched-low link indication. Keep both reads
	 * under the bus lock so another MDIO user cannot consume the latch.
	 */
	mutex_lock(&port->pcs_bus->mdio_lock);
	status = __mdiobus_c45_read(port->pcs_bus, port->pcs_addr,
				    MDIO_MMD_PCS, MDIO_STAT1);
	if (status >= 0 && status != 0xffff)
		status = __mdiobus_c45_read(port->pcs_bus, port->pcs_addr,
					    MDIO_MMD_PCS, MDIO_STAT1);
	mutex_unlock(&port->pcs_bus->mdio_lock);

	if (status < 0)
		return status;
	/* The FMan MDIO driver returns all ones for an unanswered read. */
	if (status == 0xffff)
		return -ENODEV;

	return !!(status & MDIO_STAT1_LSTATUS);
}

static void sfp_led_update(struct sfp_led_port *port, bool present, bool link,
			   int ifindex, const struct rtnl_link_stats64 *stats)
{
	if (!link) {
		port->activity_on = present;
	} else if (!port->last_link || port->last_ifindex != ifindex) {
		/* Establish a baseline; old traffic is not new activity. */
		port->activity_on = false;
	} else if (stats->tx_packets != port->last_tx_packets ||
		   stats->rx_packets != port->last_rx_packets) {
		port->activity_on = !port->activity_on;
	} else {
		port->activity_on = false;
	}

	if (link) {
		port->last_tx_packets = stats->tx_packets;
		port->last_rx_packets = stats->rx_packets;
	}
	port->last_link = link;
	port->last_ifindex = ifindex;
	sfp_led_set(port->link_led, link);
	sfp_led_set(port->activity_led, port->activity_on);
}

static void sfp_led_poll(struct work_struct *work)
{
	struct sfp_led_port *port = container_of(to_delayed_work(work),
						struct sfp_led_port, poll_work);
	struct rtnl_link_stats64 stats;
	struct net_device *netdev;
	bool link = false;
	int ifindex = 0;

	if (!sfp_led_module_present(port)) {
		sfp_led_update(port, false, false, 0, NULL);
		goto reschedule;
	}

	/*
	 * Network teardown can flush work while holding RTNL. Retry instead
	 * of waiting, and never carry a netdev pointer across rtnl_unlock().
	 */
	if (!rtnl_trylock())
		goto reschedule;

	netdev = sfp_led_find_netdev(port->mac_np);
	if (netdev && netif_running(netdev) && netif_device_present(netdev)) {
		ifindex = netdev->ifindex;
		link = sfp_led_pcs_link(port) > 0;
		if (link)
			dev_get_stats(netdev, &stats);
	}
	rtnl_unlock();

	sfp_led_update(port, true, link, ifindex, &stats);

reschedule:
	schedule_delayed_work(&port->poll_work,
			      msecs_to_jiffies(SFP_LED_POLL_INTERVAL_MS));
}

static struct device_node *sfp_led_find_mac(struct device_node *sfp_np)
{
	struct device_node *mac_np;

	for_each_compatible_node(mac_np, NULL, "fsl,fman-memac") {
		struct device_node *node;
		bool match;

		if (!of_device_is_available(mac_np))
			continue;
		node = of_parse_phandle(mac_np, "sfp", 0);
		match = node == sfp_np;
		of_node_put(node);
		if (match)
			return mac_np;
	}

	return NULL;
}

static int sfp_led_get_pcs(struct device *dev, struct sfp_led_port *port)
{
	struct device_node *pcs_np, *bus_np;
	phy_interface_t interface;
	int index, ret;

	ret = of_get_phy_mode(port->mac_np, &interface);
	if (ret)
		return ret;
	if (interface != PHY_INTERFACE_MODE_XGMII &&
	    interface != PHY_INTERFACE_MODE_10GBASER)
		return -EOPNOTSUPP;

	index = of_property_match_string(port->mac_np, "pcs-handle-names", "xfi");
	if (index < 0)
		return index;
	pcs_np = of_parse_phandle(port->mac_np, "pcs-handle", index);
	if (!pcs_np)
		return -EINVAL;
	if (!of_device_is_available(pcs_np)) {
		ret = -ENODEV;
		goto put_pcs;
	}
	ret = of_mdio_parse_addr(dev, pcs_np);
	if (ret < 0)
		goto put_pcs;
	port->pcs_addr = ret;

	/*
	 * The SDK DT may describe the PCS as a PHY even though it has no
	 * clause 22 PHY ID. Resolve its bus and address without requiring a
	 * PHY driver to bind, and use only clause 45 status reads.
	 */
	bus_np = of_get_parent(pcs_np);
	if (!of_device_is_available(bus_np)) {
		ret = -ENODEV;
	} else {
		port->pcs_bus = of_mdio_find_bus(bus_np);
		ret = port->pcs_bus ? 0 : -EPROBE_DEFER;
	}
	of_node_put(bus_np);
	if (ret)
		goto put_pcs;

	/* Stop the monitor before the MDIO controller releases its registers. */
	if (!device_link_add(dev, port->pcs_bus->parent,
			     DL_FLAG_AUTOREMOVE_CONSUMER))
		ret = -EINVAL;

put_pcs:
	of_node_put(pcs_np);
	return ret;
}

static int sfp_led_get_port(struct device *dev, struct device_node *node,
			    struct sfp_led_port *port)
{
	struct device_node *sfp_np, *i2c_np;
	int ret;

	sfp_np = of_parse_phandle(node, "sfp", 0);
	if (!sfp_np)
		return -EINVAL;
	if (!of_device_is_available(sfp_np)) {
		ret = -ENODEV;
		goto put_sfp;
	}

	port->mac_np = sfp_led_find_mac(sfp_np);
	if (!port->mac_np) {
		ret = -ENODEV;
		goto put_sfp;
	}

	i2c_np = of_parse_phandle(sfp_np, "i2c-bus", 0);
	if (!i2c_np) {
		ret = -EINVAL;
		goto put_sfp;
	}
	if (!of_device_is_available(i2c_np)) {
		ret = -ENODEV;
	} else {
		port->i2c = of_get_i2c_adapter_by_node(i2c_np);
		ret = port->i2c ? 0 : -EPROBE_DEFER;
	}
	of_node_put(i2c_np);
	if (ret)
		goto put_sfp;
	if (!i2c_check_functionality(port->i2c, I2C_FUNC_SMBUS_READ_BYTE_DATA)) {
		ret = -EOPNOTSUPP;
		goto put_sfp;
	}

	ret = sfp_led_get_pcs(dev, port);
	if (ret)
		goto put_sfp;

	port->link_led = of_led_get(node, 0);
	if (IS_ERR(port->link_led)) {
		ret = PTR_ERR(port->link_led);
		port->link_led = NULL;
		goto put_sfp;
	}
	port->activity_led = of_led_get(node, 1);
	if (IS_ERR(port->activity_led)) {
		ret = PTR_ERR(port->activity_led);
		port->activity_led = NULL;
	}

put_sfp:
	of_node_put(sfp_np);
	return ret;
}

static void sfp_led_put_port(struct sfp_led_port *port)
{
	if (port->activity_led)
		led_put(port->activity_led);
	if (port->link_led)
		led_put(port->link_led);
	if (port->pcs_bus)
		put_device(&port->pcs_bus->dev);
	if (port->i2c)
		i2c_put_adapter(port->i2c);
	of_node_put(port->mac_np);
}

static int sfp_led_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sfp_led_priv *priv;
	struct device_node *child;
	unsigned int i = 0;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->num_ports = of_get_available_child_count(dev->of_node);
	if (!priv->num_ports)
		return -ENODEV;
	priv->ports = devm_kcalloc(dev, priv->num_ports, sizeof(*priv->ports),
				   GFP_KERNEL);
	if (!priv->ports)
		return -ENOMEM;

	/*
	 * Acquire every port before starting work: a deferred probe must not
	 * leave a partially running monitor behind.
	 */
	for_each_available_child_of_node(dev->of_node, child) {
		ret = sfp_led_get_port(dev, child, &priv->ports[i++]);
		if (ret) {
			dev_err_probe(dev, ret, "cannot acquire resources for %pOFn\n",
				      child);
			of_node_put(child);
			goto put_ports;
		}
	}

	platform_set_drvdata(pdev, priv);
	for (i = 0; i < priv->num_ports; i++) {
		INIT_DELAYED_WORK(&priv->ports[i].poll_work, sfp_led_poll);
		schedule_delayed_work(&priv->ports[i].poll_work, 0);
	}
	return 0;

put_ports:
	while (i)
		sfp_led_put_port(&priv->ports[--i]);
	return ret;
}

static void sfp_led_remove(struct platform_device *pdev)
{
	struct sfp_led_priv *priv = platform_get_drvdata(pdev);
	unsigned int i;

	for (i = 0; i < priv->num_ports; i++) {
		struct sfp_led_port *port = &priv->ports[i];

		cancel_delayed_work_sync(&port->poll_work);
		sfp_led_set(port->link_led, false);
		sfp_led_set(port->activity_led, false);
		sfp_led_put_port(port);
	}
}

static const struct of_device_id sfp_led_of_match[] = {
	{ .compatible = "mono,sfp-led" },
	{ }
};
MODULE_DEVICE_TABLE(of, sfp_led_of_match);

static struct platform_driver sfp_led_driver = {
	.probe = sfp_led_probe,
	.remove = sfp_led_remove,
	.driver = {
		.name = "sfp-led",
		.of_match_table = sfp_led_of_match,
	},
};
module_platform_driver(sfp_led_driver);

MODULE_AUTHOR("Tomaz Zaman <tomaz@mono.si>");
MODULE_DESCRIPTION("Mono SFP port LED controller");
MODULE_LICENSE("GPL");

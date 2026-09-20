// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Mono SFP port LED controller for the DPAA SDK fixed-link configuration.
 *
 * Module presence comes from the cage's MOD_DEF0 line and link state from
 * the MAC's XFI PCS, for both optical modules and DACs. Nothing here goes
 * near i2c, deliberately: a module caught mid-transfer by a reset holds SDA
 * low until it loses power, and a port whose module has done that must
 * still light its LEDs -- as must its neighbour, which shares the bus.
 * The monitor does not configure the PCS or interact with the SFP state
 * machine.
 *
 * No module: both LEDs off. Module without link: solid orange. Link up:
 * green on, orange blinking on changes to the netdev packet counters.
 * User-selected LED triggers take precedence over this monitor.
 *
 * Each mono,sfp-led child references an SFP with "sfp" and its link and
 * activity LEDs with "leds". MOD_DEF0 comes from that SFP's own
 * "mod-def0-gpios", borrowed non-exclusively from the sfp driver that owns
 * the line and never released by the borrower (see sfp_led_get_port()).
 * The associated fsl,fman-memac node references the same SFP and
 * identifies the XFI PCS through "pcs-handle" and "pcs-handle-names". No
 * module diagnostic support is required.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Author: Tomaz Zaman <tomaz@mono.si>
 */

#include <linux/err.h>
#include <linux/gpio/consumer.h>
#include <linux/leds.h>
#include <linux/mdio.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/workqueue.h>

#define SFP_LED_POLL_INTERVAL_MS	100

struct sfp_led_port {
	struct device_node *mac_np;
	struct gpio_desc *present;
	/* False when `present` is the sfp driver's descriptor, only borrowed. */
	bool present_owned;
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

static void sfp_led_set(struct led_classdev *led, bool on)
{
	if (!led)
		return;

	down_read(&led->trigger_lock);
	if (!led->trigger)
		led_set_brightness(led, on ? led->max_brightness : LED_OFF);
	up_read(&led->trigger_lock);
}

/*
 * The running netdev of the port's MAC, with a reference the caller drops,
 * or NULL. Resolved under RCU rather than RTNL: this runs ten times a second
 * per port, and the offload backend only ever tries RTNL under its own
 * transaction, declining and retiring an admission when the try fails. A
 * poll holding RTNL would turn a share of every box's flow admissions into
 * such retirements. The reference is what keeps the device, its driver
 * private data and its statistics valid until the poll is done with them.
 */
static struct net_device *sfp_led_get_netdev(struct device_node *mac_np)
{
	struct net_device *netdev, *found = NULL;

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, netdev) {
		struct device *parent = netdev->dev.parent;
		struct device_node *node;
		bool match;

		if (!parent || !parent->of_node)
			continue;

		node = of_parse_phandle(parent->of_node, "fsl,fman-mac", 0);
		match = node == mac_np;
		of_node_put(node);
		if (!match)
			continue;
		if (netif_running(netdev) && netif_device_present(netdev)) {
			dev_hold(netdev);
			found = netdev;
		}
		break;
	}
	rcu_read_unlock();

	return found;
}

static bool sfp_led_module_present(struct sfp_led_port *port)
{
	/* MOD_DEF0 is asserted by the module itself, pulled up when the cage
	 * is empty. The dts carries the polarity, so this reads logically.
	 */
	return gpiod_get_value_cansleep(port->present) > 0;
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
	 * The PCS read sleeps on the MDIO bus lock, so it runs outside RCU;
	 * the held reference keeps the netdev and its counters valid across it.
	 */
	netdev = sfp_led_get_netdev(port->mac_np);
	if (netdev) {
		ifindex = netdev->ifindex;
		link = sfp_led_pcs_link(port) > 0;
		if (link)
			dev_get_stats(netdev, &stats);
		dev_put(netdev);
	}

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

static int sfp_led_get_port(struct device *dev, struct sfp_led_port *port)
{
	struct platform_device *sfp_pdev;
	struct device_node *sfp_np;
	bool bound;
	int ret;

	sfp_np = of_parse_phandle(dev->of_node, "sfp", 0);
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

	/*
	 * The sfp driver requests MOD_DEF0 only once it has its I2C adapter,
	 * and requests it exclusively; a port that took the line before that
	 * would leave the cage without an sfp driver for good. Wait for it to
	 * be bound, so that the line is always already taken and only borrowed.
	 */
	sfp_pdev = of_find_device_by_node(sfp_np);
	if (!sfp_pdev) {
		ret = -EPROBE_DEFER;
		goto put_sfp;
	}
	bound = device_is_bound(&sfp_pdev->dev);
	put_device(&sfp_pdev->dev);
	if (!bound) {
		ret = -EPROBE_DEFER;
		goto put_sfp;
	}

	/*
	 * The sfp driver owns this line for its own state machine, so the
	 * exclusive request fails with -EBUSY and the non-exclusive retry
	 * returns the owner's descriptor. gpiolib takes no reference for that
	 * second consumer and configures nothing, so a borrowed descriptor must
	 * never be put: putting it would release the owner's line under it,
	 * clear its active-low flag -- the sfp driver would then read presence
	 * inverted -- and drop a device reference the port never took. Hence no
	 * devm here, and sfp_led_put_port() releases only what the port owns,
	 * which is the line only on a board whose sfp driver left it untaken.
	 */
	port->present = fwnode_gpiod_get_index(of_fwnode_handle(sfp_np), "mod-def0",
					       0, GPIOD_IN, "sfp-led-present");
	port->present_owned = !IS_ERR(port->present);
	if (PTR_ERR(port->present) == -EBUSY)
		port->present = fwnode_gpiod_get_index(of_fwnode_handle(sfp_np),
						       "mod-def0", 0,
						       GPIOD_IN | GPIOD_FLAGS_BIT_NONEXCLUSIVE,
						       "sfp-led-present");
	if (IS_ERR(port->present)) {
		ret = PTR_ERR(port->present);
		port->present = NULL;
		goto put_sfp;
	}

	ret = sfp_led_get_pcs(dev, port);
	if (ret)
		goto put_sfp;

	port->link_led = devm_of_led_get(dev, 0);
	if (IS_ERR(port->link_led)) {
		ret = PTR_ERR(port->link_led);
		port->link_led = NULL;
		goto put_sfp;
	}
	port->activity_led = devm_of_led_get_optional(dev, 1);
	if (IS_ERR(port->activity_led)) {
		ret = PTR_ERR(port->activity_led);
		port->activity_led = NULL;
	} else {
		ret = 0;
	}

put_sfp:
	of_node_put(sfp_np);
	return ret;
}

static void sfp_led_put_port(struct sfp_led_port *port)
{
	if (port->present && port->present_owned)
		gpiod_put(port->present);
	if (port->pcs_bus)
		put_device(&port->pcs_bus->dev);
	of_node_put(port->mac_np);
}

static int sfp_led_port_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sfp_led_port *port;
	int ret;

	port = devm_kzalloc(dev, sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	ret = sfp_led_get_port(dev, port);
	if (ret) {
		sfp_led_put_port(port);
		return dev_err_probe(dev, ret, "cannot acquire port resources\n");
	}

	platform_set_drvdata(pdev, port);
	INIT_DELAYED_WORK(&port->poll_work, sfp_led_poll);
	schedule_delayed_work(&port->poll_work, 0);
	return 0;
}

static void sfp_led_port_remove(struct platform_device *pdev)
{
	struct sfp_led_port *port = platform_get_drvdata(pdev);

	cancel_delayed_work_sync(&port->poll_work);
	sfp_led_set(port->link_led, false);
	sfp_led_set(port->activity_led, false);
	sfp_led_put_port(port);
}

static const struct of_device_id sfp_led_port_of_match[] = {
	{ .compatible = "mono,sfp-led-port" },
	{ }
};
MODULE_DEVICE_TABLE(of, sfp_led_port_of_match);

static struct platform_driver sfp_led_port_driver = {
	.probe = sfp_led_port_probe,
	.remove = sfp_led_port_remove,
	.driver = {
		.name = "sfp-led-port",
		.of_match_table = sfp_led_port_of_match,
	},
};

/*
 * The controller exists only to bring its port children up as devices of their
 * own. Every exported LED getter resolves against dev->of_node, so a port has
 * to be a device to reach the "leds" phandles in its own node.
 */
static int sfp_led_probe(struct platform_device *pdev)
{
	return devm_of_platform_populate(&pdev->dev);
}

static const struct of_device_id sfp_led_of_match[] = {
	{ .compatible = "mono,sfp-led" },
	{ }
};
MODULE_DEVICE_TABLE(of, sfp_led_of_match);

static struct platform_driver sfp_led_driver = {
	.probe = sfp_led_probe,
	.driver = {
		.name = "sfp-led",
		.of_match_table = sfp_led_of_match,
	},
};

static struct platform_driver * const sfp_led_drivers[] = {
	&sfp_led_driver,
	&sfp_led_port_driver,
};

static int __init sfp_led_init(void)
{
	return platform_register_drivers(sfp_led_drivers,
					 ARRAY_SIZE(sfp_led_drivers));
}
module_init(sfp_led_init);

static void __exit sfp_led_exit(void)
{
	platform_unregister_drivers(sfp_led_drivers,
				    ARRAY_SIZE(sfp_led_drivers));
}
module_exit(sfp_led_exit);

MODULE_AUTHOR("Tomaz Zaman <tomaz@mono.si>");
MODULE_DESCRIPTION("Mono SFP port LED controller");
MODULE_LICENSE("GPL");

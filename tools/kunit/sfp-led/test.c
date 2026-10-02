// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Included after the production driver in an isolated UML kernel.
 * The fixture uses real GPIO, MDIO, LED, OF and netdev APIs with fake hardware.
 */
#include <kunit/test.h>
#include <kunit/test-bug.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/gpio/driver.h>
#include <linux/rtnetlink.h>

/* MOD_DEF0 of /sfp on line 0, of /sfp-1g on line 1. */
#define SFP_LED_TEST_LINES	2U

/* A 1000BASE-X PCS's BMSR without link: extended status and AN ability. */
#define SFP_LED_TEST_BMSR	(BMSR_ESTATEN | BMSR_ANEGCAPABLE | BMSR_ERCAP)

struct sfp_led_test {
	struct kunit *test;
	struct sfp_led_port port;
	struct gpio_chip gc;
	struct device_node *gpio_np;
	struct mii_bus *bus;
	struct led_classdev link, activity, late;
	struct platform_device *provider, *consumer, *dpaa, *dpaa_1g;
	/* Bound stand-ins for the sfp driver on /sfp and /sfp-nogpio. */
	struct platform_device *sfp0, *sfp1;
	/*
	 * Suppliers of the 1000BASE-X cage, bound with their nodes: the sfp
	 * stand-in on /sfp-1g owns its MOD_DEF0 line and the provider on /leds
	 * its LEDs, and each lets go of them when it unbinds.
	 */
	struct platform_device *sfp_1g, *leds;
	/* Port devices with the controller's child nodes, never auto-bound:
	 * their of_node is set after registration so the driver core does not
	 * match them, and a test drives the probe itself. */
	struct platform_device *port0, *port1, *port2;
	/* A port the driver core binds, which is what device links act on. */
	struct platform_device *bound;
	/* What the last supplier stand-in to unbind saw of the watched port. */
	struct device *watched, *unbound;
	bool watched_bound, watched_lit;
	struct net_device *netdev, *netdev_1g;
	int pcs_status[2];
	unsigned int pcs_reads;
	/* The same PCS's clause 22 BMSR, which a 1000BASE-X port reads. */
	int bmsr[2];
	unsigned int bmsr_reads;
	unsigned int line_reads[SFP_LED_TEST_LINES];
	bool present;
	bool gc_added, bus_added, late_added, probed;
};

/* The LEDs of /leds, allocated per binding of their provider. */
struct sfp_led_test_leds {
	struct led_classdev link, activity;
};

/*
 * A supplier stand-in unbinding: note whether the port under watch was still
 * bound, and so still able to use what this supplier is about to release.
 */
static void sfp_led_test_supplier_unbind(struct device *dev, bool lit)
{
	struct kunit *test = kunit_get_current_test();
	struct sfp_led_test *ctx = test ? test->priv : NULL;

	if (!ctx || !ctx->watched)
		return;
	ctx->unbound = dev;
	ctx->watched_bound = device_is_bound(ctx->watched);
	ctx->watched_lit = lit;
}

static int sfp_led_test_provider_probe(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver sfp_led_test_provider_driver = {
	.probe = sfp_led_test_provider_probe,
	.driver.name = "sfp-led-kunit-provider",
};

/*
 * The sfp driver requests its cage's MOD_DEF0 exclusively when it binds and
 * releases it when it unbinds. A stand-in bound before its node is attached
 * requests nothing: the fixture holds that line in its place.
 */
static int sfp_led_test_sfp_probe(struct platform_device *pdev)
{
	struct gpio_desc *desc;

	if (!pdev->dev.of_node)
		return 0;
	desc = devm_gpiod_get(&pdev->dev, "mod-def0", GPIOD_IN);
	if (IS_ERR(desc))
		return PTR_ERR(desc);
	platform_set_drvdata(pdev, desc);
	return 0;
}

static void sfp_led_test_sfp_remove(struct platform_device *pdev)
{
	sfp_led_test_supplier_unbind(&pdev->dev, false);
}

static struct platform_driver sfp_led_test_sfp_driver = {
	.probe = sfp_led_test_sfp_probe,
	.remove = sfp_led_test_sfp_remove,
	.driver.name = "sfp-led-kunit-sfp",
};

static int sfp_led_test_mdio_read(struct mii_bus *bus, int addr, int devad,
				  int regnum)
{
	struct sfp_led_test *ctx = bus->priv;

	KUNIT_EXPECT_EQ(ctx->test, addr, 0);
	KUNIT_EXPECT_EQ(ctx->test, devad, MDIO_MMD_PCS);
	KUNIT_EXPECT_EQ(ctx->test, regnum, MDIO_STAT1);
	return ctx->pcs_status[min(ctx->pcs_reads++, 1U)];
}

static int sfp_led_test_mdio_c22(struct mii_bus *bus, int addr, int reg)
{
	struct sfp_led_test *ctx = bus->priv;

	/*
	 * Match the SDK's PCS: it answers its status register, but has no
	 * clause 22 PHY ID, so no PHY can bind.
	 */
	if (reg != MII_BMSR)
		return 0xffff;
	KUNIT_EXPECT_EQ(ctx->test, addr, 0);
	return ctx->bmsr[min(ctx->bmsr_reads++, 1U)];
}

static int sfp_led_test_mdio_write(struct mii_bus *bus, int addr, int devad,
				   int reg, u16 value)
{
	struct sfp_led_test *ctx = bus->priv;

	KUNIT_FAIL(ctx->test, "the LED monitor must not write PCS registers");
	return -EOPNOTSUPP;
}

static int sfp_led_test_mdio_write_c22(struct mii_bus *bus, int addr, int reg,
				       u16 value)
{
	return sfp_led_test_mdio_write(bus, addr, 0, reg, value);
}

/*
 * MOD_DEF0 as the cage drives it: pulled up when empty, grounded by a module,
 * active-low in the DT as on the board. The test's `present` is the logical
 * value; the borrowed descriptor inherits the owner's polarity.
 */
static int sfp_led_test_gpio_get(struct gpio_chip *gc, unsigned int offset)
{
	struct sfp_led_test *ctx = gpiochip_get_data(gc);

	KUNIT_EXPECT_LT(ctx->test, offset, SFP_LED_TEST_LINES);
	if (offset < SFP_LED_TEST_LINES)
		ctx->line_reads[offset]++;
	return !ctx->present;
}

static int sfp_led_test_gpio_direction_input(struct gpio_chip *gc,
					     unsigned int offset)
{
	return 0;
}

static int sfp_led_test_gpio_get_direction(struct gpio_chip *gc,
					   unsigned int offset)
{
	return GPIO_LINE_DIRECTION_IN;
}

static void sfp_led_test_brightness(struct led_classdev *led,
				    enum led_brightness value)
{
}

static int sfp_led_test_register_led(struct sfp_led_test *ctx,
				     struct led_classdev *led,
				     const char *path)
{
	struct device_node *node = of_find_node_by_path(path);
	struct led_init_data data = {
		.fwnode = of_fwnode_handle(node),
	};
	int ret;

	led->name = path + 1;
	led->max_brightness = 1;
	led->brightness_set = sfp_led_test_brightness;
	ret = led_classdev_register_ext(&ctx->provider->dev, led, &data);
	of_node_put(node);
	return ret;
}

static int sfp_led_test_leds_add(struct device *dev, struct led_classdev *led,
				 const char *name)
{
	struct fwnode_handle *node = device_get_named_child_node(dev, name);
	struct led_init_data data = {
		.fwnode = node,
	};
	int ret;

	led->name = name;
	led->max_brightness = 1;
	led->brightness_set = sfp_led_test_brightness;
	ret = devm_led_classdev_register_ext(dev, led, &data);
	fwnode_handle_put(node);
	return ret;
}

/*
 * As gpio-leds does, the provider allocates its led_classdevs when it binds
 * and frees them when it unbinds; a gotten LED does not keep them.
 */
static int sfp_led_test_leds_probe(struct platform_device *pdev)
{
	struct sfp_led_test_leds *leds;
	int ret;

	leds = devm_kzalloc(&pdev->dev, sizeof(*leds), GFP_KERNEL);
	if (!leds)
		return -ENOMEM;
	ret = sfp_led_test_leds_add(&pdev->dev, &leds->link, "link");
	if (ret)
		return ret;
	ret = sfp_led_test_leds_add(&pdev->dev, &leds->activity, "activity");
	if (ret)
		return ret;
	platform_set_drvdata(pdev, leds);
	return 0;
}

static void sfp_led_test_leds_remove(struct platform_device *pdev)
{
	struct sfp_led_test_leds *leds = platform_get_drvdata(pdev);

	sfp_led_test_supplier_unbind(&pdev->dev, leds->link.brightness ||
				     leds->activity.brightness);
}

static struct platform_driver sfp_led_test_leds_driver = {
	.probe = sfp_led_test_leds_probe,
	.remove = sfp_led_test_leds_remove,
	.driver.name = "sfp-led-kunit-leds",
};

static struct platform_driver * const sfp_led_test_drivers[] = {
	&sfp_led_test_provider_driver,
	&sfp_led_test_sfp_driver,
	&sfp_led_test_leds_driver,
};

static int sfp_led_test_open(struct net_device *netdev)
{
	return 0;
}

static const struct net_device_ops sfp_led_test_netdev_ops = {
	.ndo_open = sfp_led_test_open,
	.ndo_stop = sfp_led_test_open,
};

static int sfp_led_test_add_netdev(struct platform_device *parent,
				   struct net_device **netdev)
{
	struct net_device *ndev;
	int ret;

	ndev = alloc_etherdev(0);
	if (!ndev)
		return -ENOMEM;
	ndev->netdev_ops = &sfp_led_test_netdev_ops;
	SET_NETDEV_DEV(ndev, &parent->dev);
	eth_hw_addr_random(ndev);
	ret = register_netdev(ndev);
	if (ret) {
		free_netdev(ndev);
		return ret;
	}
	*netdev = ndev;
	rtnl_lock();
	ret = dev_open(ndev, NULL);
	rtnl_unlock();
	return ret;
}

static void sfp_led_test_put_netdev(struct net_device **netdev)
{
	if (!*netdev)
		return;
	unregister_netdev(*netdev);
	free_netdev(*netdev);
	*netdev = NULL;
}

static struct platform_device *sfp_led_test_port_device(int id,
							const char *path)
{
	struct platform_device *pdev;

	pdev = platform_device_register_simple("sfp-led-kunit-port", id, NULL, 0);
	if (!IS_ERR(pdev))
		pdev->dev.of_node = of_find_node_by_path(path);
	return pdev;
}

/*
 * A device registered with its node already attached, which it probes with:
 * a stand-in finds its resources there, and a port is matched and bound by
 * the driver core.
 */
static struct platform_device *sfp_led_test_node_device(const char *name,
							int id,
							const char *path)
{
	struct device_node *node = of_find_node_by_path(path);
	struct platform_device_info info = {
		.name = name,
		.id = id,
		.fwnode = of_fwnode_handle(node),
	};
	struct platform_device *pdev;

	pdev = platform_device_register_full(&info);
	of_node_put(node);
	return pdev;
}

/* platform_device_release() puts the node the registration looked up. */
static void sfp_led_test_put_port_device(struct platform_device **pdev)
{
	if (IS_ERR_OR_NULL(*pdev))
		return;
	platform_device_unregister(*pdev);
	*pdev = NULL;
}

static void sfp_led_test_cleanup(void *data)
{
	struct sfp_led_test *ctx = data;

	/* No supplier unbinding from here on may look at the port. */
	ctx->watched = NULL;
	sfp_led_test_put_port_device(&ctx->bound);
	cancel_delayed_work_sync(&ctx->port.poll_work);
	if (ctx->probed)
		sfp_led_port_remove(ctx->port1);
	sfp_led_test_put_netdev(&ctx->netdev);
	sfp_led_test_put_netdev(&ctx->netdev_1g);
	/* Port devices first: their devres holds LEDs and the MDIO bus. */
	sfp_led_test_put_port_device(&ctx->port0);
	sfp_led_test_put_port_device(&ctx->port1);
	sfp_led_test_put_port_device(&ctx->port2);
	if (!IS_ERR_OR_NULL(ctx->sfp0))
		platform_device_unregister(ctx->sfp0);
	if (!IS_ERR_OR_NULL(ctx->sfp1))
		platform_device_unregister(ctx->sfp1);
	if (!IS_ERR_OR_NULL(ctx->sfp_1g))
		platform_device_unregister(ctx->sfp_1g);
	if (!IS_ERR_OR_NULL(ctx->leds))
		platform_device_unregister(ctx->leds);
	if (!IS_ERR_OR_NULL(ctx->consumer))
		platform_device_unregister(ctx->consumer);
	if (!IS_ERR_OR_NULL(ctx->dpaa))
		platform_device_unregister(ctx->dpaa);
	if (!IS_ERR_OR_NULL(ctx->dpaa_1g))
		platform_device_unregister(ctx->dpaa_1g);
	if (ctx->late_added)
		led_classdev_unregister(&ctx->late);
	if (ctx->activity.dev)
		led_classdev_unregister(&ctx->activity);
	if (ctx->link.dev)
		led_classdev_unregister(&ctx->link);
	if (ctx->bus_added)
		mdiobus_unregister(ctx->bus);
	if (ctx->bus)
		mdiobus_free(ctx->bus);
	of_node_put(ctx->port.mac_np);
	/* The owner's descriptor goes last, after every borrower is gone. */
	if (ctx->port.present)
		gpiod_put(ctx->port.present);
	if (ctx->gc_added)
		gpiochip_remove(&ctx->gc);
	of_node_put(ctx->gpio_np);
	if (!IS_ERR_OR_NULL(ctx->provider))
		platform_device_unregister(ctx->provider);
	platform_unregister_drivers(sfp_led_test_drivers,
				    ARRAY_SIZE(sfp_led_test_drivers));
}

static int sfp_led_test_init(struct kunit *test)
{
	struct device_node *node;
	struct sfp_led_test *ctx;
	int ret;

	/* The runner supplies test.dtb as UML's firmware tree. */
	if (!of_find_property(of_root, "sfp-led-kunit", NULL))
		return -EINVAL;

	ret = platform_register_drivers(sfp_led_test_drivers,
					ARRAY_SIZE(sfp_led_test_drivers));
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}
	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		platform_unregister_drivers(sfp_led_test_drivers,
					    ARRAY_SIZE(sfp_led_test_drivers));
		return -ENOMEM;
	}
	ctx->test = test;
	test->priv = ctx;
	INIT_DELAYED_WORK(&ctx->port.poll_work, sfp_led_poll);
	ret = kunit_add_action_or_reset(test, sfp_led_test_cleanup, ctx);
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}

	ctx->provider = platform_device_register_simple("sfp-led-kunit-provider",
							-1, NULL, 0);
	if (IS_ERR(ctx->provider))
		return PTR_ERR(ctx->provider);
	ctx->consumer = platform_device_register_simple("sfp-led-kunit-consumer",
							-1, NULL, 0);
	if (IS_ERR(ctx->consumer))
		return PTR_ERR(ctx->consumer);
	ctx->consumer->dev.of_node = of_find_node_by_path("/controller");
	ctx->dpaa = platform_device_register_simple("sfp-led-kunit-dpaa",
						    -1, NULL, 0);
	if (IS_ERR(ctx->dpaa))
		return PTR_ERR(ctx->dpaa);
	ctx->dpaa->dev.of_node = of_find_node_by_path("/dpaa");
	/* Bound before their node is attached, as the sfp driver is on the
	 * board by the time the ports probe; a port waits for exactly that. */
	ctx->sfp0 = platform_device_register_simple("sfp-led-kunit-sfp", 0, NULL, 0);
	if (IS_ERR(ctx->sfp0))
		return PTR_ERR(ctx->sfp0);
	ctx->sfp0->dev.of_node = of_find_node_by_path("/sfp");
	ctx->sfp1 = platform_device_register_simple("sfp-led-kunit-sfp", 1, NULL, 0);
	if (IS_ERR(ctx->sfp1))
		return PTR_ERR(ctx->sfp1);
	ctx->sfp1->dev.of_node = of_find_node_by_path("/sfp-nogpio");
	ctx->port.mac_np = of_find_node_by_path("/mac");
	ctx->port0 = sfp_led_test_port_device(0, "/controller/port0");
	if (IS_ERR(ctx->port0))
		return PTR_ERR(ctx->port0);
	ctx->port1 = sfp_led_test_port_device(1, "/controller/port1");
	if (IS_ERR(ctx->port1))
		return PTR_ERR(ctx->port1);
	ctx->port2 = sfp_led_test_port_device(2, "/controller/port2");
	if (IS_ERR(ctx->port2))
		return PTR_ERR(ctx->port2);

	ctx->gpio_np = of_find_node_by_path("/gpio");
	ctx->gc.label = "sfp-led-kunit";
	ctx->gc.parent = &ctx->provider->dev;
	ctx->gc.fwnode = of_fwnode_handle(ctx->gpio_np);
	ctx->gc.owner = THIS_MODULE;
	ctx->gc.base = -1;
	ctx->gc.ngpio = SFP_LED_TEST_LINES;
	ctx->gc.can_sleep = true;
	ctx->gc.get = sfp_led_test_gpio_get;
	ctx->gc.direction_input = sfp_led_test_gpio_direction_input;
	ctx->gc.get_direction = sfp_led_test_gpio_get_direction;
	ret = gpiochip_add_data(&ctx->gc, ctx);
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}
	ctx->gc_added = true;
	ctx->present = true;
	/*
	 * On the board the sfp driver owns MOD_DEF0 and a port only borrows
	 * it. The fixture stands in for that owner: it requests the line first,
	 * exclusively, so every port probe below meets a line already taken.
	 */
	node = of_find_node_by_path("/sfp");
	ctx->port.present = fwnode_gpiod_get_index(of_fwnode_handle(node), "mod-def0",
						   0, GPIOD_IN, "sfp-kunit-owner");
	of_node_put(node);
	if (IS_ERR(ctx->port.present)) {
		ret = PTR_ERR(ctx->port.present);
		ctx->port.present = NULL;
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}

	ctx->bus = mdiobus_alloc();
	if (!ctx->bus)
		return -ENOMEM;
	ctx->bus->name = "sfp-led-kunit";
	strscpy(ctx->bus->id, "sfp-led-kunit", MII_BUS_ID_SIZE);
	ctx->bus->parent = &ctx->provider->dev;
	ctx->bus->priv = ctx;
	ctx->bus->read = sfp_led_test_mdio_c22;
	ctx->bus->write = sfp_led_test_mdio_write_c22;
	ctx->bus->read_c45 = sfp_led_test_mdio_read;
	ctx->bus->write_c45 = sfp_led_test_mdio_write;
	ctx->bus->phy_mask = ~0U;
	node = of_find_node_by_path("/mdio");
	ret = of_mdiobus_register(ctx->bus, node);
	of_node_put(node);
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}
	ctx->bus_added = true;
	ctx->port.pcs_bus = ctx->bus;
	/* /mac is XGMII, so its PCS reports link in clause 45 MDIO_STAT1. */
	ctx->port.pcs_c45 = true;

	ret = sfp_led_test_register_led(ctx, &ctx->link, "/link-led");
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}
	ret = sfp_led_test_register_led(ctx, &ctx->activity, "/activity-led");
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}
	ctx->port.link_led = &ctx->link;
	ctx->port.activity_led = &ctx->activity;

	ctx->sfp_1g = sfp_led_test_node_device("sfp-led-kunit-sfp", 2, "/sfp-1g");
	if (IS_ERR(ctx->sfp_1g))
		return PTR_ERR(ctx->sfp_1g);
	ctx->leds = sfp_led_test_node_device("sfp-led-kunit-leds",
					     PLATFORM_DEVID_NONE, "/leds");
	if (IS_ERR(ctx->leds))
		return PTR_ERR(ctx->leds);
	if (!device_is_bound(&ctx->sfp_1g->dev) ||
	    !device_is_bound(&ctx->leds->dev)) {
		kunit_err(test, "fixture initialization at line %d\n", __LINE__);
		return -ENODEV;
	}
	ctx->dpaa_1g = sfp_led_test_node_device("sfp-led-kunit-dpaa", 1,
						"/dpaa-1g");
	if (IS_ERR(ctx->dpaa_1g))
		return PTR_ERR(ctx->dpaa_1g);

	ret = sfp_led_test_add_netdev(ctx->dpaa, &ctx->netdev);
	if (ret)
		return ret;
	return sfp_led_test_add_netdev(ctx->dpaa_1g, &ctx->netdev_1g);
}

/* A bound port also polls on its own; cancel that and take a sample by hand. */
static void sfp_led_test_poll_port(struct sfp_led_test *ctx,
				   struct sfp_led_port *port)
{
	cancel_delayed_work_sync(&port->poll_work);
	ctx->pcs_reads = 0;
	ctx->bmsr_reads = 0;
	sfp_led_poll(&port->poll_work.work);
	cancel_delayed_work_sync(&port->poll_work);
}

static void sfp_led_test_poll_once(struct sfp_led_test *ctx)
{
	sfp_led_test_poll_port(ctx, &ctx->port);
}

/*
 * Bind /controller/<port> through the driver core, as the controller's
 * populate does. Device links act only on a consumer bound that way: a
 * supplier that unbinds releases the port's driver, which it cannot do for a
 * port probed by hand.
 */
static struct sfp_led_port *sfp_led_test_bind_port(struct kunit *test,
						   const char *path)
{
	struct sfp_led_test *ctx = test->priv;

	ctx->bound = sfp_led_test_node_device("sfp-led-kunit-port",
					      PLATFORM_DEVID_AUTO, path);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->bound);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->bound->dev));
	return platform_get_drvdata(ctx->bound);
}

static unsigned int sfp_led_test_gpio_refs(struct sfp_led_test *ctx)
{
	struct gpio_device *gdev = gpiod_to_gpio_device(ctx->port.present);

	return kref_read(&gpio_device_to_device(gdev)->kobj.kref);
}

static void sfp_led_test_link_and_activity(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	/* Carrier is asserted, as with the board's fixed PHY, but PCS is down. */
	netif_carrier_on(ctx->netdev);
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, ctx->link.brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, ctx->activity.brightness, (enum led_brightness)1);

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	ctx->netdev->stats.rx_packets = 100;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, ctx->link.brightness, (enum led_brightness)1);
	KUNIT_EXPECT_EQ(test, ctx->activity.brightness, LED_OFF);

	ctx->netdev->stats.rx_packets++;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, ctx->activity.brightness, (enum led_brightness)1);
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, ctx->activity.brightness, LED_OFF);

	/* Removing only the far end must extinguish green despite carrier. */
	ctx->pcs_status[0] = 0;
	ctx->pcs_status[1] = 0;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_TRUE(test, netif_carrier_ok(ctx->netdev));
	KUNIT_EXPECT_EQ(test, ctx->link.brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, ctx->activity.brightness, (enum led_brightness)1);
}

static void sfp_led_test_pcs_errors(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	static const int statuses[][3] = {
		{ 0, MDIO_STAT1_LSTATUS, 1 },
		{ MDIO_STAT1_LSTATUS, 0, 0 },
		{ -EIO, MDIO_STAT1_LSTATUS, -EIO },
		{ MDIO_STAT1_LSTATUS, -ETIMEDOUT, -ETIMEDOUT },
		{ 0xffff, MDIO_STAT1_LSTATUS, -ENODEV },
		{ MDIO_STAT1_LSTATUS, 0xffff, -ENODEV },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(statuses); i++) {
		ctx->pcs_reads = 0;
		ctx->pcs_status[0] = statuses[i][0];
		ctx->pcs_status[1] = statuses[i][1];
		KUNIT_EXPECT_EQ(test, sfp_led_pcs_link(&ctx->port), statuses[i][2]);
	}
	/* A failed read is retried next poll without a module replug. */
	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_TRUE(test, ctx->port.last_link);
}

/*
 * U-Boot switches a 10G MAC to 1000base-x when the RCW runs its lane at 1G.
 * Such a port used to fail its probe with -EOPNOTSUPP; it now reads link from
 * the same PCS's clause 22 BMSR, and never from clause 45. Any PCS write, in
 * either clause, fails the test in the MDIO stand-in.
 */
static void sfp_led_test_1000basex_link(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	struct sfp_led_port *port;

	port = sfp_led_test_bind_port(test, "/controller/port3");
	KUNIT_ASSERT_NOT_NULL(test, port);
	KUNIT_EXPECT_FALSE(test, port->pcs_c45);
	KUNIT_EXPECT_PTR_EQ(test, port->pcs_bus, ctx->bus);
	KUNIT_EXPECT_EQ(test, port->pcs_addr, 0);

	/* Module seated, PCS down: solid orange, whatever the other bits say. */
	ctx->bmsr[0] = SFP_LED_TEST_BMSR;
	ctx->bmsr[1] = SFP_LED_TEST_BMSR;
	sfp_led_test_poll_port(ctx, port);
	KUNIT_EXPECT_EQ(test, port->link_led->brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, port->activity_led->brightness, (enum led_brightness)1);

	/* Up again after a drop: the first read returns the latched low. */
	ctx->bmsr[1] = SFP_LED_TEST_BMSR | BMSR_LSTATUS;
	sfp_led_test_poll_port(ctx, port);
	KUNIT_EXPECT_EQ(test, ctx->bmsr_reads, 2U);
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 0U);
	KUNIT_EXPECT_EQ(test, port->link_led->brightness, (enum led_brightness)1);
	KUNIT_EXPECT_EQ(test, port->activity_led->brightness, LED_OFF);

	/* Dropped between the two reads: the second, live one decides. */
	ctx->bmsr[0] = SFP_LED_TEST_BMSR | BMSR_LSTATUS;
	ctx->bmsr[1] = SFP_LED_TEST_BMSR;
	sfp_led_test_poll_port(ctx, port);
	KUNIT_EXPECT_EQ(test, port->link_led->brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, port->activity_led->brightness, (enum led_brightness)1);

	/* An XGMII port on the same PCS still reads clause 45 only. */
	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_TRUE(test, ctx->port.last_link);
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 2U);
	KUNIT_EXPECT_EQ(test, ctx->bmsr_reads, 0U);
}

static void sfp_led_test_1000basex_pcs_errors(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	static const struct {
		int first, second, link;
		unsigned int reads;
	} cases[] = {
		{ SFP_LED_TEST_BMSR, SFP_LED_TEST_BMSR | BMSR_LSTATUS, 1, 2 },
		{ SFP_LED_TEST_BMSR | BMSR_LSTATUS, SFP_LED_TEST_BMSR, 0, 2 },
		{ -EIO, BMSR_LSTATUS, -EIO, 1 },
		{ BMSR_LSTATUS, -ETIMEDOUT, -ETIMEDOUT, 2 },
		{ 0xffff, BMSR_LSTATUS, -ENODEV, 1 },
		{ BMSR_LSTATUS, 0xffff, -ENODEV, 2 },
	};
	struct sfp_led_port *port;
	unsigned int i;

	port = sfp_led_test_bind_port(test, "/controller/port3");
	KUNIT_ASSERT_NOT_NULL(test, port);
	cancel_delayed_work_sync(&port->poll_work);
	ctx->pcs_reads = 0;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		ctx->bmsr_reads = 0;
		ctx->bmsr[0] = cases[i].first;
		ctx->bmsr[1] = cases[i].second;
		KUNIT_EXPECT_EQ(test, sfp_led_pcs_link(port), cases[i].link);
		KUNIT_EXPECT_EQ(test, ctx->bmsr_reads, cases[i].reads);
	}
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 0U);
}

static void sfp_led_test_presence_recovery(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_TRUE(test, ctx->port.last_link);

	/* MOD_DEF0 released: both LEDs off, and nothing else is touched. */
	ctx->present = false;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, ctx->link.brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, ctx->activity.brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 0U);

	ctx->present = true;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_TRUE(test, ctx->port.last_link);
}

static void sfp_led_test_admin_down(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	sfp_led_test_poll_once(ctx);
	rtnl_lock();
	dev_close(ctx->netdev);
	rtnl_unlock();
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_FALSE(test, ctx->port.last_link);
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 0U);
}

/*
 * The poll neither waits for nor yields to RTNL: a holder elsewhere -- an
 * offload admission trying the lock, a link change under it -- must find the
 * sample already taken, and the sample must not depend on the lock being free.
 */
static void sfp_led_test_rtnl_held(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	rtnl_lock();
	sfp_led_test_poll_once(ctx);
	rtnl_unlock();
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 2U);
	KUNIT_EXPECT_TRUE(test, ctx->port.last_link);
	KUNIT_EXPECT_EQ(test, ctx->port.last_ifindex, ctx->netdev->ifindex);
}

static void sfp_led_test_unregister(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	unsigned int refs = netdev_refcnt_read(ctx->netdev);

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, netdev_refcnt_read(ctx->netdev), refs);
	sfp_led_test_put_netdev(&ctx->netdev);
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_FALSE(test, ctx->port.last_link);
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 0U);
}

static void sfp_led_test_user_trigger(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	struct led_trigger trigger = {};

	/* Simulate a selected trigger under the same lock as LED core. */
	down_write(&ctx->link.trigger_lock);
	ctx->link.trigger = &trigger;
	up_write(&ctx->link.trigger_lock);
	sfp_led_set(&ctx->link, true);
	KUNIT_EXPECT_EQ(test, ctx->link.brightness, LED_OFF);
	down_write(&ctx->link.trigger_lock);
	ctx->link.trigger = NULL;
	up_write(&ctx->link.trigger_lock);
	sfp_led_set(&ctx->link, true);
	KUNIT_EXPECT_EQ(test, ctx->link.brightness, (enum led_brightness)1);
}

/*
 * A port borrows MOD_DEF0 from the sfp driver. gpiolib hands a second,
 * non-exclusive consumer the owner's descriptor without a reference of its
 * own, so the port must never put it: the line stays requested by its owner
 * and the chip's device keeps its count after the port has gone away.
 */
static void sfp_led_test_shared_gpio(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	unsigned int refs = sfp_led_test_gpio_refs(ctx);
	struct sfp_led_port *port;
	char *label;

	KUNIT_ASSERT_EQ(test, sfp_led_port_probe(ctx->port0), 0);
	port = platform_get_drvdata(ctx->port0);
	KUNIT_ASSERT_NOT_NULL(test, port);
	KUNIT_EXPECT_PTR_EQ(test, port->present, ctx->port.present);
	sfp_led_port_remove(ctx->port0);
	sfp_led_test_put_port_device(&ctx->port0);

	label = gpiochip_dup_line_label(&ctx->gc, 0);
	KUNIT_EXPECT_FALSE(test, IS_ERR_OR_NULL(label));
	if (!IS_ERR(label))
		kfree(label);
	KUNIT_EXPECT_EQ(test, sfp_led_test_gpio_refs(ctx), refs);
	KUNIT_EXPECT_EQ(test, gpiod_get_value_cansleep(ctx->port.present), 1);
}

/*
 * A port must not take MOD_DEF0 while the sfp driver is not bound. sfp.c
 * requests the line only once its I2C adapter is there, and requests it
 * exclusively, so a port that had won the line first would leave the cage
 * without an sfp driver for good. The port defers, and the free line stays
 * free.
 */
static void sfp_led_test_sfp_unbound(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	char *label;
	int ret;

	gpiod_put(ctx->port.present);
	ctx->port.present = NULL;
	platform_device_unregister(ctx->sfp0);
	ctx->sfp0 = NULL;

	ret = sfp_led_port_probe(ctx->port0);
	KUNIT_EXPECT_EQ(test, ret, -EPROBE_DEFER);
	if (!ret)
		sfp_led_port_remove(ctx->port0);
	label = gpiochip_dup_line_label(&ctx->gc, 0);
	KUNIT_EXPECT_NULL(test, label);
	if (!IS_ERR(label))
		kfree(label);
}

/* Unbound, the port no longer samples its cage at all. */
static void sfp_led_test_expect_idle(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	unsigned int reads = READ_ONCE(ctx->line_reads[1]);

	msleep(3 * SFP_LED_POLL_INTERVAL_MS);
	KUNIT_EXPECT_EQ(test, READ_ONCE(ctx->line_reads[1]), reads);
}

/*
 * Unbinding the sfp driver releases MOD_DEF0, which clears its active-low
 * flag and frees it for anyone, so a port still polling it would show
 * presence inverted. The port is linked to the sfp device: the unbind takes
 * the port down first, and binding the sfp driver again probes it again.
 */
static void sfp_led_test_sfp_rebind(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	struct sfp_led_port *port;
	struct device *dev;
	char *label;

	port = sfp_led_test_bind_port(test, "/controller/port3");
	KUNIT_ASSERT_NOT_NULL(test, port);
	dev = &ctx->bound->dev;
	KUNIT_EXPECT_PTR_EQ(test, port->present, platform_get_drvdata(ctx->sfp_1g));
	KUNIT_EXPECT_FALSE(test, port->present_owned);

	ctx->watched = dev;
	device_release_driver(&ctx->sfp_1g->dev);
	KUNIT_EXPECT_PTR_EQ(test, ctx->unbound, &ctx->sfp_1g->dev);
	KUNIT_EXPECT_FALSE(test, ctx->watched_bound);
	KUNIT_EXPECT_FALSE(test, device_is_bound(dev));
	/* The port kept no hold on the line its owner has now released. */
	label = gpiochip_dup_line_label(&ctx->gc, 1);
	KUNIT_EXPECT_NULL(test, label);
	if (!IS_ERR(label))
		kfree(label);
	sfp_led_test_expect_idle(test);

	KUNIT_ASSERT_EQ(test, device_attach(&ctx->sfp_1g->dev), 1);
	wait_for_device_probe();
	KUNIT_ASSERT_TRUE(test, device_is_bound(dev));
	port = dev_get_drvdata(dev);
	KUNIT_EXPECT_PTR_EQ(test, port->present, platform_get_drvdata(ctx->sfp_1g));
	KUNIT_EXPECT_FALSE(test, port->present_owned);
	/* Borrowed from the new owner, the line reads the seated module. */
	KUNIT_EXPECT_EQ(test, gpiod_get_value_cansleep(port->present), 1);
}

/*
 * Unbinding the LED provider frees the led_classdevs, which a gotten LED does
 * not pin. The port is linked to the provider: the unbind takes the port down
 * first, whose removal puts its LEDs out while they still exist, and binding
 * the provider again probes the port again with the new LEDs.
 */
static void sfp_led_test_led_provider_rebind(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	struct sfp_led_test_leds *leds;
	struct sfp_led_port *port;
	struct device *dev;

	port = sfp_led_test_bind_port(test, "/controller/port3");
	KUNIT_ASSERT_NOT_NULL(test, port);
	dev = &ctx->bound->dev;
	leds = platform_get_drvdata(ctx->leds);
	KUNIT_EXPECT_PTR_EQ(test, port->link_led, &leds->link);
	KUNIT_EXPECT_PTR_EQ(test, port->activity_led, &leds->activity);
	/* Module seated without link: solid orange, and the port keeps polling. */
	flush_delayed_work(&port->poll_work);
	KUNIT_EXPECT_EQ(test, leds->activity.brightness, (enum led_brightness)1);

	ctx->watched = dev;
	device_release_driver(&ctx->leds->dev);
	KUNIT_EXPECT_PTR_EQ(test, ctx->unbound, &ctx->leds->dev);
	KUNIT_EXPECT_FALSE(test, ctx->watched_bound);
	KUNIT_EXPECT_FALSE(test, ctx->watched_lit);
	KUNIT_EXPECT_FALSE(test, device_is_bound(dev));
	sfp_led_test_expect_idle(test);

	KUNIT_ASSERT_EQ(test, device_attach(&ctx->leds->dev), 1);
	wait_for_device_probe();
	KUNIT_ASSERT_TRUE(test, device_is_bound(dev));
	port = dev_get_drvdata(dev);
	leds = platform_get_drvdata(ctx->leds);
	KUNIT_EXPECT_PTR_EQ(test, port->link_led, &leds->link);
	KUNIT_EXPECT_PTR_EQ(test, port->activity_led, &leds->activity);
}

static void sfp_led_test_deferred_led(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	unsigned int refs = kref_read(&ctx->bus->dev.kobj.kref);
	int ret;

	/* Port 1's activity LED has not registered yet. */
	ret = sfp_led_port_probe(ctx->port1);
	KUNIT_EXPECT_EQ(test, ret, -EPROBE_DEFER);
	KUNIT_EXPECT_PTR_EQ(test, platform_get_drvdata(ctx->port1), NULL);
	KUNIT_EXPECT_EQ(test, kref_read(&ctx->bus->dev.kobj.kref), refs);

	ret = sfp_led_test_register_led(ctx, &ctx->late, "/late-led");
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx->late_added = true;
	ret = sfp_led_port_probe(ctx->port1);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx->probed = true;
}

static void sfp_led_test_deferred_gpio(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	/* Port 2's cage line belongs to a controller that never registered. */
	KUNIT_EXPECT_EQ(test, sfp_led_port_probe(ctx->port2), -EPROBE_DEFER);
	KUNIT_EXPECT_PTR_EQ(test, platform_get_drvdata(ctx->port2), NULL);
}

static void sfp_led_test_deferred_mdio(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	mdiobus_unregister(ctx->bus);
	ctx->bus_added = false;
	KUNIT_EXPECT_EQ(test, sfp_led_port_probe(ctx->port0), -EPROBE_DEFER);
	KUNIT_EXPECT_PTR_EQ(test, platform_get_drvdata(ctx->port0), NULL);
}

static int sfp_led_test_match_node(struct device *dev, void *data)
{
	return dev->of_node == data;
}

/*
 * The controller only brings its children up as devices; the port driver,
 * registered at init, binds them. Port 0 has everything; port 1 waits for a
 * LED and port 2 for a GPIO controller, and neither holds the others back.
 */
static void sfp_led_test_populate(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	struct device_node *node;
	struct device *dev;

	/* The fixture's own port devices would compete for the same nodes. */
	sfp_led_test_put_port_device(&ctx->port0);
	sfp_led_test_put_port_device(&ctx->port1);
	sfp_led_test_put_port_device(&ctx->port2);

	KUNIT_ASSERT_EQ(test, sfp_led_probe(ctx->consumer), 0);

	node = of_find_node_by_path("/controller/port0");
	dev = device_find_child(&ctx->consumer->dev, node, sfp_led_test_match_node);
	of_node_put(node);
	KUNIT_ASSERT_NOT_NULL(test, dev);
	KUNIT_EXPECT_NOT_NULL(test, dev->driver);
	KUNIT_EXPECT_NOT_NULL(test, dev_get_drvdata(dev));
	put_device(dev);

	node = of_find_node_by_path("/controller/port1");
	dev = device_find_child(&ctx->consumer->dev, node, sfp_led_test_match_node);
	of_node_put(node);
	KUNIT_ASSERT_NOT_NULL(test, dev);
	KUNIT_EXPECT_NULL(test, dev->driver);
	put_device(dev);

	of_platform_depopulate(&ctx->consumer->dev);
}

static struct kunit_case sfp_led_test_cases[] = {
	KUNIT_CASE(sfp_led_test_link_and_activity),
	KUNIT_CASE(sfp_led_test_pcs_errors),
	KUNIT_CASE(sfp_led_test_1000basex_link),
	KUNIT_CASE(sfp_led_test_1000basex_pcs_errors),
	KUNIT_CASE(sfp_led_test_presence_recovery),
	KUNIT_CASE(sfp_led_test_admin_down),
	KUNIT_CASE(sfp_led_test_rtnl_held),
	KUNIT_CASE(sfp_led_test_unregister),
	KUNIT_CASE(sfp_led_test_user_trigger),
	KUNIT_CASE(sfp_led_test_shared_gpio),
	KUNIT_CASE(sfp_led_test_sfp_unbound),
	KUNIT_CASE(sfp_led_test_sfp_rebind),
	KUNIT_CASE(sfp_led_test_led_provider_rebind),
	KUNIT_CASE(sfp_led_test_deferred_led),
	KUNIT_CASE(sfp_led_test_deferred_gpio),
	KUNIT_CASE(sfp_led_test_deferred_mdio),
	KUNIT_CASE(sfp_led_test_populate),
	{}
};

static struct kunit_suite sfp_led_test_suite = {
	.name = "sfp-led",
	.init = sfp_led_test_init,
	.test_cases = sfp_led_test_cases,
};
kunit_test_suite(sfp_led_test_suite);

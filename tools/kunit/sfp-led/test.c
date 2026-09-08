// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Included after the production driver in an isolated UML kernel.
 * The fixture uses real I2C, MDIO, LED, OF and netdev APIs with fake hardware.
 */
#include <kunit/test.h>
#include <linux/etherdevice.h>

struct sfp_led_test {
	struct kunit *test;
	struct sfp_led_port port;
	struct i2c_adapter i2c;
	struct device_node *i2c_np;
	struct mii_bus *bus;
	struct led_classdev link, activity, late;
	struct platform_device *provider, *consumer, *dpaa;
	struct net_device *netdev;
	int pcs_status[2];
	unsigned int pcs_reads;
	int i2c_error;
	bool i2c_added, bus_added, late_added, probed;
};

static int sfp_led_test_provider_probe(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver sfp_led_test_provider_driver = {
	.probe = sfp_led_test_provider_probe,
	.driver.name = "sfp-led-kunit-provider",
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
	/* Match the SDK's XFI PCS: no clause 22 PHY can bind. */
	return 0xffff;
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

static int sfp_led_test_i2c_xfer(struct i2c_adapter *adapter, u16 addr,
				 unsigned short flags, char rw, u8 command,
				 int size, union i2c_smbus_data *data)
{
	struct sfp_led_test *ctx = i2c_get_adapdata(adapter);

	KUNIT_EXPECT_EQ(ctx->test, addr, (u16)0x50);
	KUNIT_EXPECT_EQ(ctx->test, rw, (char)I2C_SMBUS_READ);
	KUNIT_EXPECT_EQ(ctx->test, command, (u8)SFP_PHYS_ID);
	KUNIT_EXPECT_EQ(ctx->test, size, I2C_SMBUS_BYTE_DATA);
	data->byte = SFF8024_ID_SFP;
	return ctx->i2c_error;
}

static u32 sfp_led_test_i2c_functions(struct i2c_adapter *adapter)
{
	return I2C_FUNC_SMBUS_READ_BYTE_DATA;
}

static const struct i2c_algorithm sfp_led_test_i2c_algo = {
	.smbus_xfer = sfp_led_test_i2c_xfer,
	.functionality = sfp_led_test_i2c_functions,
};

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

static int sfp_led_test_open(struct net_device *netdev)
{
	return 0;
}

static const struct net_device_ops sfp_led_test_netdev_ops = {
	.ndo_open = sfp_led_test_open,
	.ndo_stop = sfp_led_test_open,
};

static void sfp_led_test_cleanup(void *data)
{
	struct sfp_led_test *ctx = data;

	cancel_delayed_work_sync(&ctx->port.poll_work);
	if (ctx->probed)
		sfp_led_remove(ctx->consumer);
	if (ctx->netdev) {
		unregister_netdev(ctx->netdev);
		free_netdev(ctx->netdev);
	}
	if (!IS_ERR_OR_NULL(ctx->consumer))
		platform_device_unregister(ctx->consumer);
	if (!IS_ERR_OR_NULL(ctx->dpaa))
		platform_device_unregister(ctx->dpaa);
	if (ctx->late_added)
		led_classdev_unregister(&ctx->late);
	if (ctx->activity.dev)
		led_classdev_unregister(&ctx->activity);
	if (ctx->link.dev)
		led_classdev_unregister(&ctx->link);
	if (ctx->i2c_added)
		i2c_del_adapter(&ctx->i2c);
	of_node_put(ctx->i2c_np);
	if (ctx->bus_added)
		mdiobus_unregister(ctx->bus);
	if (ctx->bus)
		mdiobus_free(ctx->bus);
	of_node_put(ctx->port.mac_np);
	if (!IS_ERR_OR_NULL(ctx->provider))
		platform_device_unregister(ctx->provider);
	platform_driver_unregister(&sfp_led_test_provider_driver);
}

static int sfp_led_test_init(struct kunit *test)
{
	struct device_node *node;
	struct sfp_led_test *ctx;
	int ret;

	/* The runner supplies test.dtb as UML's firmware tree. */
	if (!of_find_property(of_root, "sfp-led-kunit", NULL))
		return -EINVAL;

	ret = platform_driver_register(&sfp_led_test_provider_driver);
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}
	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		platform_driver_unregister(&sfp_led_test_provider_driver);
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
	ctx->port.mac_np = of_find_node_by_path("/mac");

	ctx->i2c.owner = THIS_MODULE;
	ctx->i2c.algo = &sfp_led_test_i2c_algo;
	ctx->i2c.dev.parent = &ctx->provider->dev;
	ctx->i2c_np = of_find_node_by_path("/i2c");
	ctx->i2c.dev.of_node = ctx->i2c_np;
	strscpy(ctx->i2c.name, "sfp-led-kunit", sizeof(ctx->i2c.name));
	i2c_set_adapdata(&ctx->i2c, ctx);
	ret = i2c_add_adapter(&ctx->i2c);
	if (ret) {
		kunit_err(test, "fixture initialization at line %d: %d\n", __LINE__, ret);
		return ret;
	}
	ctx->i2c_added = true;
	ctx->port.i2c = &ctx->i2c;

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

	ctx->netdev = alloc_etherdev(0);
	if (!ctx->netdev)
		return -ENOMEM;
	ctx->netdev->netdev_ops = &sfp_led_test_netdev_ops;
	SET_NETDEV_DEV(ctx->netdev, &ctx->dpaa->dev);
	eth_hw_addr_random(ctx->netdev);
	ret = register_netdev(ctx->netdev);
	if (ret) {
		free_netdev(ctx->netdev);
		ctx->netdev = NULL;
		return ret;
	}
	rtnl_lock();
	ret = dev_open(ctx->netdev, NULL);
	rtnl_unlock();
	return ret;
}

static void sfp_led_test_poll_once(struct sfp_led_test *ctx)
{
	ctx->pcs_reads = 0;
	sfp_led_poll(&ctx->port.poll_work.work);
	cancel_delayed_work_sync(&ctx->port.poll_work);
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

static void sfp_led_test_presence_recovery(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	sfp_led_test_poll_once(ctx);
	ctx->i2c_error = -ENXIO;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, ctx->link.brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, ctx->activity.brightness, LED_OFF);
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 0U);
	ctx->i2c_error = 0;
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

static void sfp_led_test_rtnl_busy(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	rtnl_lock();
	sfp_led_test_poll_once(ctx);
	rtnl_unlock();
	KUNIT_EXPECT_EQ(test, ctx->pcs_reads, 0U);
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_TRUE(test, ctx->port.last_link);
}

static void sfp_led_test_unregister(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	unsigned int refs = netdev_refcnt_read(ctx->netdev);

	ctx->pcs_status[0] = MDIO_STAT1_LSTATUS;
	ctx->pcs_status[1] = MDIO_STAT1_LSTATUS;
	sfp_led_test_poll_once(ctx);
	KUNIT_EXPECT_EQ(test, netdev_refcnt_read(ctx->netdev), refs);
	unregister_netdev(ctx->netdev);
	free_netdev(ctx->netdev);
	ctx->netdev = NULL;
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

static void sfp_led_test_deferred_led(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;
	unsigned int refs = kref_read(&ctx->i2c.dev.kobj.kref);
	int ret;

	/* Port 0 is ready; port 1's activity LED has not registered yet. */
	ret = sfp_led_probe(ctx->consumer);
	KUNIT_EXPECT_EQ(test, ret, -EPROBE_DEFER);
	KUNIT_EXPECT_EQ(test, kref_read(&ctx->i2c.dev.kobj.kref), refs);
	KUNIT_EXPECT_PTR_EQ(test, platform_get_drvdata(ctx->consumer), NULL);

	ret = sfp_led_test_register_led(ctx, &ctx->late, "/late-led");
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx->late_added = true;
	ret = sfp_led_probe(ctx->consumer);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx->probed = true;
}

static void sfp_led_test_deferred_i2c(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	i2c_del_adapter(&ctx->i2c);
	ctx->i2c_added = false;
	KUNIT_EXPECT_EQ(test, sfp_led_probe(ctx->consumer), -EPROBE_DEFER);
	KUNIT_EXPECT_PTR_EQ(test, platform_get_drvdata(ctx->consumer), NULL);
}

static void sfp_led_test_deferred_mdio(struct kunit *test)
{
	struct sfp_led_test *ctx = test->priv;

	mdiobus_unregister(ctx->bus);
	ctx->bus_added = false;
	KUNIT_EXPECT_EQ(test, sfp_led_probe(ctx->consumer), -EPROBE_DEFER);
	KUNIT_EXPECT_PTR_EQ(test, platform_get_drvdata(ctx->consumer), NULL);
}

static struct kunit_case sfp_led_test_cases[] = {
	KUNIT_CASE(sfp_led_test_link_and_activity),
	KUNIT_CASE(sfp_led_test_pcs_errors),
	KUNIT_CASE(sfp_led_test_presence_recovery),
	KUNIT_CASE(sfp_led_test_admin_down),
	KUNIT_CASE(sfp_led_test_rtnl_busy),
	KUNIT_CASE(sfp_led_test_unregister),
	KUNIT_CASE(sfp_led_test_user_trigger),
	KUNIT_CASE(sfp_led_test_deferred_led),
	KUNIT_CASE(sfp_led_test_deferred_i2c),
	KUNIT_CASE(sfp_led_test_deferred_mdio),
	{}
};

static struct kunit_suite sfp_led_test_suite = {
	.name = "sfp-led",
	.init = sfp_led_test_init,
	.test_cases = sfp_led_test_cases,
};

kunit_test_suite(sfp_led_test_suite);

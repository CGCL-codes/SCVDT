int __mdiobus_register(struct mii_bus *bus, struct module *owner)
{
	struct mdio_device *mdiodev;
	int i, err;
	struct gpio_desc *gpiod;

	if (NULL == bus || NULL == bus->name ||
	    NULL == bus->read || NULL == bus->write)
		return -EINVAL;

	BUG_ON(bus->state != MDIOBUS_ALLOCATED &&
	       bus->state != MDIOBUS_UNREGISTERED);

	bus->owner = owner;
	bus->dev.parent = bus->parent;
	bus->dev.class = &mdio_bus_class;
	bus->dev.groups = NULL;
	dev_set_name(&bus->dev, "%s", bus->id);

	err = device_register(&bus->dev);
	if (err) {
		pr_err("mii_bus %s failed to register\n", bus->id);
		put_device(&bus->dev);
		return -EINVAL;
	}

	mutex_init(&bus->mdio_lock);

	/* de-assert bus level PHY GPIO reset */
	gpiod = devm_gpiod_get_optional(&bus->dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(gpiod)) {
		dev_err(&bus->dev, "mii_bus %s couldn't get reset GPIO\n",
			bus->id);
		device_del(&bus->dev);
		return PTR_ERR(gpiod);
	} else	if (gpiod) {
		bus->reset_gpiod = gpiod;

		gpiod_set_value_cansleep(gpiod, 1);
		udelay(bus->reset_delay_us);
		gpiod_set_value_cansleep(gpiod, 0);
	}

	if (bus->reset)
		bus->reset(bus);

	for (i = 0; i < PHY_MAX_ADDR; i++) {
		if ((bus->phy_mask & (1 << i)) == 0) {
			struct phy_device *phydev;

			phydev = mdiobus_scan(bus, i);
			if (IS_ERR(phydev) && (PTR_ERR(phydev) != -ENODEV)) {
				err = PTR_ERR(phydev);
				goto error;
			}
		}
	}

	mdiobus_setup_mdiodev_from_board_info(bus, mdiobus_create_device);

	bus->state = MDIOBUS_REGISTERED;
	pr_info("%s: probed\n", bus->name);
	return 0;

error:
	while (--i >= 0) {
		mdiodev = bus->mdio_map[i];
		if (!mdiodev)
			continue;

		mdiodev->device_remove(mdiodev);
		mdiodev->device_free(mdiodev);
	}

	/* Put PHYs in RESET to save power */
	if (bus->reset_gpiod)
		gpiod_set_value_cansleep(bus->reset_gpiod, 1);

	device_del(&bus->dev);
	return err;
}

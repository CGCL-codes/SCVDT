static int cp2112_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	struct cp2112_device *dev;
	u8 buf[3];
	struct cp2112_smbus_config_report config;
	int ret;

	dev = devm_kzalloc(&hdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->in_out_buffer = devm_kzalloc(&hdev->dev, CP2112_REPORT_MAX_LENGTH,
					  GFP_KERNEL);
	if (!dev->in_out_buffer)
		return -ENOMEM;

	mutex_init(&dev->lock);

	ret = hid_parse(hdev);
	if (ret) {
		hid_err(hdev, "parse failed\n");
		return ret;
	}

	ret = hid_hw_start(hdev, HID_CONNECT_HIDRAW);
	if (ret) {
		hid_err(hdev, "hw start failed\n");
		return ret;
	}

	ret = hid_hw_open(hdev);
	if (ret) {
		hid_err(hdev, "hw open failed\n");
		goto err_hid_stop;
	}

	ret = hid_hw_power(hdev, PM_HINT_FULLON);
	if (ret < 0) {
		hid_err(hdev, "power management error: %d\n", ret);
		goto err_hid_close;
	}

	ret = cp2112_hid_get(hdev, CP2112_GET_VERSION_INFO, buf, sizeof(buf),
			     HID_FEATURE_REPORT);
	if (ret != sizeof(buf)) {
		hid_err(hdev, "error requesting version\n");
		if (ret >= 0)
			ret = -EIO;
		goto err_power_normal;
	}

	hid_info(hdev, "Part Number: 0x%02X Device Version: 0x%02X\n",
		 buf[1], buf[2]);

	ret = cp2112_hid_get(hdev, CP2112_SMBUS_CONFIG, (u8 *)&config,
			     sizeof(config), HID_FEATURE_REPORT);
	if (ret != sizeof(config)) {
		hid_err(hdev, "error requesting SMBus config\n");
		if (ret >= 0)
			ret = -EIO;
		goto err_power_normal;
	}

	config.retry_time = cpu_to_be16(1);

	ret = cp2112_hid_output(hdev, (u8 *)&config, sizeof(config),
				HID_FEATURE_REPORT);
	if (ret != sizeof(config)) {
		hid_err(hdev, "error setting SMBus config\n");
		if (ret >= 0)
			ret = -EIO;
		goto err_power_normal;
	}

	hid_set_drvdata(hdev, (void *)dev);
	dev->hdev		= hdev;
	dev->adap.owner		= THIS_MODULE;
	dev->adap.class		= I2C_CLASS_HWMON;
	dev->adap.algo		= &smbus_algorithm;
	dev->adap.algo_data	= dev;
	dev->adap.dev.parent	= &hdev->dev;
	snprintf(dev->adap.name, sizeof(dev->adap.name),
		 "CP2112 SMBus Bridge on hiddev%d", hdev->minor);
	dev->hwversion = buf[2];
	init_waitqueue_head(&dev->wait);

	hid_device_io_start(hdev);
	ret = i2c_add_adapter(&dev->adap);
	hid_device_io_stop(hdev);

	if (ret) {
		hid_err(hdev, "error registering i2c adapter\n");
		goto err_power_normal;
	}

	hid_dbg(hdev, "adapter registered\n");

	dev->gc.label			= "cp2112_gpio";
	dev->gc.direction_input		= cp2112_gpio_direction_input;
	dev->gc.direction_output	= cp2112_gpio_direction_output;
	dev->gc.set			= cp2112_gpio_set;
	dev->gc.get			= cp2112_gpio_get;
	dev->gc.base			= -1;
	dev->gc.ngpio			= 8;
	dev->gc.can_sleep		= 1;
	dev->gc.parent			= &hdev->dev;

	ret = gpiochip_add_data(&dev->gc, dev);
	if (ret < 0) {
		hid_err(hdev, "error registering gpio chip\n");
		goto err_free_i2c;
	}

	ret = sysfs_create_group(&hdev->dev.kobj, &cp2112_attr_group);
	if (ret < 0) {
		hid_err(hdev, "error creating sysfs attrs\n");
		goto err_gpiochip_remove;
	}

	chmod_sysfs_attrs(hdev);
	hid_hw_power(hdev, PM_HINT_NORMAL);

	ret = gpiochip_irqchip_add(&dev->gc, &cp2112_gpio_irqchip, 0,
				   handle_simple_irq, IRQ_TYPE_NONE);
	if (ret) {
		dev_err(dev->gc.parent, "failed to add IRQ chip\n");
		goto err_sysfs_remove;
	}

	return ret;

err_sysfs_remove:
	sysfs_remove_group(&hdev->dev.kobj, &cp2112_attr_group);
err_gpiochip_remove:
	gpiochip_remove(&dev->gc);
err_free_i2c:
	i2c_del_adapter(&dev->adap);
err_power_normal:
	hid_hw_power(hdev, PM_HINT_NORMAL);
err_hid_close:
	hid_hw_close(hdev);
err_hid_stop:
	hid_hw_stop(hdev);
	return ret;
}

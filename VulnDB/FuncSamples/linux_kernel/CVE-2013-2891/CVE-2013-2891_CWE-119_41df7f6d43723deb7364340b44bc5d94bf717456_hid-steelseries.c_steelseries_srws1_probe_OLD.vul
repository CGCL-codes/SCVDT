static int steelseries_srws1_probe(struct hid_device *hdev,
		const struct hid_device_id *id)
{
	int ret, i;
	struct led_classdev *led;
	size_t name_sz;
	char *name;

	struct steelseries_srws1_data *drv_data = kzalloc(sizeof(*drv_data), GFP_KERNEL);

	if (drv_data == NULL) {
		hid_err(hdev, "can't alloc SRW-S1 memory\n");
		return -ENOMEM;
	}

	hid_set_drvdata(hdev, drv_data);

	ret = hid_parse(hdev);
	if (ret) {
		hid_err(hdev, "parse failed\n");
		goto err_free;
	}

	ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
	if (ret) {
		hid_err(hdev, "hw start failed\n");
		goto err_free;
	}

	/* register led subsystem */
	drv_data->led_state = 0;
	for (i = 0; i < SRWS1_NUMBER_LEDS + 1; i++)
		drv_data->led[i] = NULL;

	steelseries_srws1_set_leds(hdev, 0);

	name_sz = strlen(hdev->uniq) + 16;

	/* 'ALL', for setting all LEDs simultaneously */
	led = kzalloc(sizeof(struct led_classdev)+name_sz, GFP_KERNEL);
	if (!led) {
		hid_err(hdev, "can't allocate memory for LED ALL\n");
		goto err_led;
	}

	name = (void *)(&led[1]);
	snprintf(name, name_sz, "SRWS1::%s::RPMALL", hdev->uniq);
	led->name = name;
	led->brightness = 0;
	led->max_brightness = 1;
	led->brightness_get = steelseries_srws1_led_all_get_brightness;
	led->brightness_set = steelseries_srws1_led_all_set_brightness;

	drv_data->led[SRWS1_NUMBER_LEDS] = led;
	ret = led_classdev_register(&hdev->dev, led);
	if (ret)
		goto err_led;

	/* Each individual LED */
	for (i = 0; i < SRWS1_NUMBER_LEDS; i++) {
		led = kzalloc(sizeof(struct led_classdev)+name_sz, GFP_KERNEL);
		if (!led) {
			hid_err(hdev, "can't allocate memory for LED %d\n", i);
			goto err_led;
		}

		name = (void *)(&led[1]);
		snprintf(name, name_sz, "SRWS1::%s::RPM%d", hdev->uniq, i+1);
		led->name = name;
		led->brightness = 0;
		led->max_brightness = 1;
		led->brightness_get = steelseries_srws1_led_get_brightness;
		led->brightness_set = steelseries_srws1_led_set_brightness;

		drv_data->led[i] = led;
		ret = led_classdev_register(&hdev->dev, led);

		if (ret) {
			hid_err(hdev, "failed to register LED %d. Aborting.\n", i);
err_led:
			/* Deregister all LEDs (if any) */
			for (i = 0; i < SRWS1_NUMBER_LEDS + 1; i++) {
				led = drv_data->led[i];
				drv_data->led[i] = NULL;
				if (!led)
					continue;
				led_classdev_unregister(led);
				kfree(led);
			}
			goto out;	/* but let the driver continue without LEDs */
		}
	}
out:
	return 0;
err_free:
	kfree(drv_data);
	return ret;
}

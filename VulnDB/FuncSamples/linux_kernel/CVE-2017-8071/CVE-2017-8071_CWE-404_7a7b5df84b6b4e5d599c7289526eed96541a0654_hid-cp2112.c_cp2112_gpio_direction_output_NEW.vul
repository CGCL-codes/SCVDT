static int cp2112_gpio_direction_output(struct gpio_chip *chip,
					unsigned offset, int value)
{
	struct cp2112_device *dev = gpiochip_get_data(chip);
	struct hid_device *hdev = dev->hdev;
	u8 *buf = dev->in_out_buffer;
	int ret;

	mutex_lock(&dev->lock);

	ret = hid_hw_raw_request(hdev, CP2112_GPIO_CONFIG, buf,
				 CP2112_GPIO_CONFIG_LENGTH, HID_FEATURE_REPORT,
				 HID_REQ_GET_REPORT);
	if (ret != CP2112_GPIO_CONFIG_LENGTH) {
		hid_err(hdev, "error requesting GPIO config: %d\n", ret);
		goto fail;
	}

	buf[1] |= 1 << offset;
	buf[2] = gpio_push_pull;

	ret = hid_hw_raw_request(hdev, CP2112_GPIO_CONFIG, buf,
				 CP2112_GPIO_CONFIG_LENGTH, HID_FEATURE_REPORT,
				 HID_REQ_SET_REPORT);
	if (ret < 0) {
		hid_err(hdev, "error setting GPIO config: %d\n", ret);
		goto fail;
	}

	mutex_unlock(&dev->lock);

	/*
	 * Set gpio value when output direction is already set,
	 * as specified in AN495, Rev. 0.2, cpt. 4.4
	 */
	cp2112_gpio_set(chip, offset, value);

	return 0;

fail:
	mutex_unlock(&dev->lock);
	return ret < 0 ? ret : -EIO;
}

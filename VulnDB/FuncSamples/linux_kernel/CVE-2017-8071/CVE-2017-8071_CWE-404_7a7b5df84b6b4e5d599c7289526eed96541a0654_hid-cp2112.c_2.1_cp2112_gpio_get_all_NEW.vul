static int cp2112_gpio_get_all(struct gpio_chip *chip)
{
	struct cp2112_device *dev = gpiochip_get_data(chip);
	struct hid_device *hdev = dev->hdev;
	u8 *buf = dev->in_out_buffer;
	int ret;

	mutex_lock(&dev->lock);

	ret = hid_hw_raw_request(hdev, CP2112_GPIO_GET, buf,
				 CP2112_GPIO_GET_LENGTH, HID_FEATURE_REPORT,
				 HID_REQ_GET_REPORT);
	if (ret != CP2112_GPIO_GET_LENGTH) {
		hid_err(hdev, "error requesting GPIO values: %d\n", ret);
		ret = ret < 0 ? ret : -EIO;
		goto exit;
	}

	ret = buf[1];

exit:
	mutex_unlock(&dev->lock);

	return ret;
}

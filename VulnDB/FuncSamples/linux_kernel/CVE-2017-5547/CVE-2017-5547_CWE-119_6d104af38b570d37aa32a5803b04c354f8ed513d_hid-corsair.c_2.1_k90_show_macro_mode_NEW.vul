static ssize_t k90_show_macro_mode(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int ret;
	struct usb_interface *usbif = to_usb_interface(dev->parent);
	struct usb_device *usbdev = interface_to_usbdev(usbif);
	const char *macro_mode;
	char *data;

	data = kmalloc(2, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = usb_control_msg(usbdev, usb_rcvctrlpipe(usbdev, 0),
			      K90_REQUEST_GET_MODE,
			      USB_DIR_IN | USB_TYPE_VENDOR |
			      USB_RECIP_DEVICE, 0, 0, data, 2,
			      USB_CTRL_SET_TIMEOUT);
	if (ret < 0) {
		dev_warn(dev, "Failed to get K90 initial mode (error %d).\n",
			 ret);
		ret = -EIO;
		goto out;
	}

	switch (data[0]) {
	case K90_MACRO_MODE_HW:
		macro_mode = "HW";
		break;

	case K90_MACRO_MODE_SW:
		macro_mode = "SW";
		break;
	default:
		dev_warn(dev, "K90 in unknown mode: %02hhx.\n",
			 data[0]);
		ret = -EIO;
		goto out;
	}

	ret = snprintf(buf, PAGE_SIZE, "%s\n", macro_mode);
out:
	kfree(data);

	return ret;
}

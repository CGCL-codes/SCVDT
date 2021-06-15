int usb_get_bos_descriptor(struct usb_device *dev)
{
	struct device *ddev = &dev->dev;
	struct usb_bos_descriptor *bos;
	struct usb_dev_cap_header *cap;
	unsigned char *buffer;
	int length, total_len, num, i;
	int ret;

	bos = kzalloc(sizeof(struct usb_bos_descriptor), GFP_KERNEL);
	if (!bos)
		return -ENOMEM;

	/* Get BOS descriptor */
	ret = usb_get_descriptor(dev, USB_DT_BOS, 0, bos, USB_DT_BOS_SIZE);
	if (ret < USB_DT_BOS_SIZE) {
		dev_err(ddev, "unable to get BOS descriptor\n");
		if (ret >= 0)
			ret = -ENOMSG;
		kfree(bos);
		return ret;
	}

	length = bos->bLength;
	total_len = le16_to_cpu(bos->wTotalLength);
	num = bos->bNumDeviceCaps;
	kfree(bos);
	if (total_len < length)
		return -EINVAL;

	dev->bos = kzalloc(sizeof(struct usb_host_bos), GFP_KERNEL);
	if (!dev->bos)
		return -ENOMEM;

	/* Now let's get the whole BOS descriptor set */
	buffer = kzalloc(total_len, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto err;
	}
	dev->bos->desc = (struct usb_bos_descriptor *)buffer;

	ret = usb_get_descriptor(dev, USB_DT_BOS, 0, buffer, total_len);
	if (ret < total_len) {
		dev_err(ddev, "unable to get BOS descriptor set\n");
		if (ret >= 0)
			ret = -ENOMSG;
		goto err;
	}
	total_len -= length;

	for (i = 0; i < num; i++) {
		buffer += length;
		cap = (struct usb_dev_cap_header *)buffer;
		length = cap->bLength;

		if (total_len < length)
			break;
		total_len -= length;

		if (cap->bDescriptorType != USB_DT_DEVICE_CAPABILITY) {
			dev_warn(ddev, "descriptor type invalid, skip\n");
			continue;
		}

		switch (cap->bDevCapabilityType) {
		case USB_CAP_TYPE_WIRELESS_USB:
			/* Wireless USB cap descriptor is handled by wusb */
			break;
		case USB_CAP_TYPE_EXT:
			dev->bos->ext_cap =
				(struct usb_ext_cap_descriptor *)buffer;
			break;
		case USB_SS_CAP_TYPE:
			dev->bos->ss_cap =
				(struct usb_ss_cap_descriptor *)buffer;
			break;
		case USB_SSP_CAP_TYPE:
			dev->bos->ssp_cap =
				(struct usb_ssp_cap_descriptor *)buffer;
			break;
		case CONTAINER_ID_TYPE:
			dev->bos->ss_id =
				(struct usb_ss_container_id_descriptor *)buffer;
			break;
		case USB_PTM_CAP_TYPE:
			dev->bos->ptm_cap =
				(struct usb_ptm_cap_descriptor *)buffer;
		default:
			break;
		}
	}

	return 0;

err:
	usb_release_bos_descriptor(dev);
	return ret;
}

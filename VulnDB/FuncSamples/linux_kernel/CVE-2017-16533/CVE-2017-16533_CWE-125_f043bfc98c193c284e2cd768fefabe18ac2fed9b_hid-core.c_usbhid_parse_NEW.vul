static int usbhid_parse(struct hid_device *hid)
{
	struct usb_interface *intf = to_usb_interface(hid->dev.parent);
	struct usb_host_interface *interface = intf->cur_altsetting;
	struct usb_device *dev = interface_to_usbdev (intf);
	struct hid_descriptor *hdesc;
	u32 quirks = 0;
	unsigned int rsize = 0;
	char *rdesc;
	int ret, n;
	int num_descriptors;
	size_t offset = offsetof(struct hid_descriptor, desc);

	quirks = usbhid_lookup_quirk(le16_to_cpu(dev->descriptor.idVendor),
			le16_to_cpu(dev->descriptor.idProduct));

	if (quirks & HID_QUIRK_IGNORE)
		return -ENODEV;

	/* Many keyboards and mice don't like to be polled for reports,
	 * so we will always set the HID_QUIRK_NOGET flag for them. */
	if (interface->desc.bInterfaceSubClass == USB_INTERFACE_SUBCLASS_BOOT) {
		if (interface->desc.bInterfaceProtocol == USB_INTERFACE_PROTOCOL_KEYBOARD ||
			interface->desc.bInterfaceProtocol == USB_INTERFACE_PROTOCOL_MOUSE)
				quirks |= HID_QUIRK_NOGET;
	}

	if (usb_get_extra_descriptor(interface, HID_DT_HID, &hdesc) &&
	    (!interface->desc.bNumEndpoints ||
	     usb_get_extra_descriptor(&interface->endpoint[0], HID_DT_HID, &hdesc))) {
		dbg_hid("class descriptor not present\n");
		return -ENODEV;
	}

	if (hdesc->bLength < sizeof(struct hid_descriptor)) {
		dbg_hid("hid descriptor is too short\n");
		return -EINVAL;
	}

	hid->version = le16_to_cpu(hdesc->bcdHID);
	hid->country = hdesc->bCountryCode;

	num_descriptors = min_t(int, hdesc->bNumDescriptors,
	       (hdesc->bLength - offset) / sizeof(struct hid_class_descriptor));

	for (n = 0; n < num_descriptors; n++)
		if (hdesc->desc[n].bDescriptorType == HID_DT_REPORT)
			rsize = le16_to_cpu(hdesc->desc[n].wDescriptorLength);

	if (!rsize || rsize > HID_MAX_DESCRIPTOR_SIZE) {
		dbg_hid("weird size of report descriptor (%u)\n", rsize);
		return -EINVAL;
	}

	rdesc = kmalloc(rsize, GFP_KERNEL);
	if (!rdesc)
		return -ENOMEM;

	hid_set_idle(dev, interface->desc.bInterfaceNumber, 0, 0);

	ret = hid_get_class_descriptor(dev, interface->desc.bInterfaceNumber,
			HID_DT_REPORT, rdesc, rsize);
	if (ret < 0) {
		dbg_hid("reading report descriptor failed\n");
		kfree(rdesc);
		goto err;
	}

	ret = hid_parse_report(hid, rdesc, rsize);
	kfree(rdesc);
	if (ret) {
		dbg_hid("parsing report descriptor failed\n");
		goto err;
	}

	hid->quirks |= quirks;

	return 0;
err:
	return ret;
}

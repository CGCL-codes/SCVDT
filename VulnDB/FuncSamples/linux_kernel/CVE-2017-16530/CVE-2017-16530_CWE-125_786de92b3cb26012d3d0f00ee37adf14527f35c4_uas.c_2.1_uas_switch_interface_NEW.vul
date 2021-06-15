static int uas_switch_interface(struct usb_device *udev,
				struct usb_interface *intf)
{
	struct usb_host_interface *alt;

	alt = uas_find_uas_alt_setting(intf);
	if (!alt)
		return -ENODEV;

	return usb_set_interface(udev, alt->desc.bInterfaceNumber,
			alt->desc.bAlternateSetting);
}

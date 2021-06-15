static int uas_switch_interface(struct usb_device *udev,
				struct usb_interface *intf)
{
	int alt;

	alt = uas_find_uas_alt_setting(intf);
	if (alt < 0)
		return alt;

	return usb_set_interface(udev,
			intf->altsetting[0].desc.bInterfaceNumber, alt);
}

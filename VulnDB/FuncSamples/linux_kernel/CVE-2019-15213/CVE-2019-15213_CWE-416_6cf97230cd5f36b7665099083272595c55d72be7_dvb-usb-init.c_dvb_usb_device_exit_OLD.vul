void dvb_usb_device_exit(struct usb_interface *intf)
{
	struct dvb_usb_device *d = usb_get_intfdata(intf);
	const char *name = "generic DVB-USB module";

	usb_set_intfdata(intf, NULL);
	if (d != NULL && d->desc != NULL) {
		name = d->desc->name;
		dvb_usb_exit(d);
	}
	info("%s successfully deinitialized and disconnected.", name);

}

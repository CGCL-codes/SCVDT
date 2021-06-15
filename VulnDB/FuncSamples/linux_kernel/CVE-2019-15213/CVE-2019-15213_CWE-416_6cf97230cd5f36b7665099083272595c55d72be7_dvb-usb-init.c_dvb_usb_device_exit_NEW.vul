void dvb_usb_device_exit(struct usb_interface *intf)
{
	struct dvb_usb_device *d = usb_get_intfdata(intf);
	const char *default_name = "generic DVB-USB module";
	char name[40];

	usb_set_intfdata(intf, NULL);
	if (d != NULL && d->desc != NULL) {
		strscpy(name, d->desc->name, sizeof(name));
		dvb_usb_exit(d);
	} else {
		strscpy(name, default_name, sizeof(name));
	}
	info("%s successfully deinitialized and disconnected.", name);

}

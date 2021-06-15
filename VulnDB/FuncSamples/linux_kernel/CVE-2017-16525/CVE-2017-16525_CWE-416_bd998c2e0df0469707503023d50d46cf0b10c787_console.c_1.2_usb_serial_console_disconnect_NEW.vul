void usb_serial_console_disconnect(struct usb_serial *serial)
{
	if (serial->port[0] && serial->port[0] == usbcons_info.port) {
		usb_serial_console_exit();
		usb_serial_put(serial);
	}
}

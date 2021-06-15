static int get_pipe(struct stub_device *sdev, int epnum, int dir)
{
	struct usb_device *udev = sdev->udev;
	struct usb_host_endpoint *ep;
	struct usb_endpoint_descriptor *epd = NULL;

	if (dir == USBIP_DIR_IN)
		ep = udev->ep_in[epnum & 0x7f];
	else
		ep = udev->ep_out[epnum & 0x7f];
	if (!ep) {
		dev_err(&sdev->udev->dev, "no such endpoint?, %d\n",
			epnum);
		BUG();
	}

	epd = &ep->desc;
	if (usb_endpoint_xfer_control(epd)) {
		if (dir == USBIP_DIR_OUT)
			return usb_sndctrlpipe(udev, epnum);
		else
			return usb_rcvctrlpipe(udev, epnum);
	}

	if (usb_endpoint_xfer_bulk(epd)) {
		if (dir == USBIP_DIR_OUT)
			return usb_sndbulkpipe(udev, epnum);
		else
			return usb_rcvbulkpipe(udev, epnum);
	}

	if (usb_endpoint_xfer_int(epd)) {
		if (dir == USBIP_DIR_OUT)
			return usb_sndintpipe(udev, epnum);
		else
			return usb_rcvintpipe(udev, epnum);
	}

	if (usb_endpoint_xfer_isoc(epd)) {
		if (dir == USBIP_DIR_OUT)
			return usb_sndisocpipe(udev, epnum);
		else
			return usb_rcvisocpipe(udev, epnum);
	}

	/* NOT REACHED */
	dev_err(&sdev->udev->dev, "get pipe, epnum %d\n", epnum);
	return 0;
}

static int pn533_usb_probe(struct usb_interface *interface,
			const struct usb_device_id *id)
{
	struct pn533 *priv;
	struct pn533_usb_phy *phy;
	struct usb_host_interface *iface_desc;
	struct usb_endpoint_descriptor *endpoint;
	int in_endpoint = 0;
	int out_endpoint = 0;
	int rc = -ENOMEM;
	int i;
	u32 protocols;
	enum pn533_protocol_type protocol_type = PN533_PROTO_REQ_ACK_RESP;
	struct pn533_frame_ops *fops = NULL;
	unsigned char *in_buf;
	int in_buf_len = PN533_EXT_FRAME_HEADER_LEN +
			 PN533_STD_FRAME_MAX_PAYLOAD_LEN +
			 PN533_STD_FRAME_TAIL_LEN;

	phy = devm_kzalloc(&interface->dev, sizeof(*phy), GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	in_buf = kzalloc(in_buf_len, GFP_KERNEL);
	if (!in_buf)
		return -ENOMEM;

	phy->udev = usb_get_dev(interface_to_usbdev(interface));
	phy->interface = interface;

	iface_desc = interface->cur_altsetting;
	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (!in_endpoint && usb_endpoint_is_bulk_in(endpoint))
			in_endpoint = endpoint->bEndpointAddress;

		if (!out_endpoint && usb_endpoint_is_bulk_out(endpoint))
			out_endpoint = endpoint->bEndpointAddress;
	}

	if (!in_endpoint || !out_endpoint) {
		nfc_err(&interface->dev,
			"Could not find bulk-in or bulk-out endpoint\n");
		rc = -ENODEV;
		goto error;
	}

	phy->in_urb = usb_alloc_urb(0, GFP_KERNEL);
	phy->out_urb = usb_alloc_urb(0, GFP_KERNEL);
	phy->ack_urb = usb_alloc_urb(0, GFP_KERNEL);

	if (!phy->in_urb || !phy->out_urb || !phy->ack_urb)
		goto error;

	usb_fill_bulk_urb(phy->in_urb, phy->udev,
			  usb_rcvbulkpipe(phy->udev, in_endpoint),
			  in_buf, in_buf_len, NULL, phy);

	usb_fill_bulk_urb(phy->out_urb, phy->udev,
			  usb_sndbulkpipe(phy->udev, out_endpoint),
			  NULL, 0, pn533_send_complete, phy);
	usb_fill_bulk_urb(phy->ack_urb, phy->udev,
			  usb_sndbulkpipe(phy->udev, out_endpoint),
			  NULL, 0, pn533_send_complete, phy);

	switch (id->driver_info) {
	case PN533_DEVICE_STD:
		protocols = PN533_ALL_PROTOCOLS;
		break;

	case PN533_DEVICE_PASORI:
		protocols = PN533_NO_TYPE_B_PROTOCOLS;
		break;

	case PN533_DEVICE_ACR122U:
		protocols = PN533_NO_TYPE_B_PROTOCOLS;
		fops = &pn533_acr122_frame_ops;
		protocol_type = PN533_PROTO_REQ_RESP,

		rc = pn533_acr122_poweron_rdr(phy);
		if (rc < 0) {
			nfc_err(&interface->dev,
				"Couldn't poweron the reader (error %d)\n", rc);
			goto error;
		}
		break;

	default:
		nfc_err(&interface->dev, "Unknown device type %lu\n",
			id->driver_info);
		rc = -EINVAL;
		goto error;
	}

	priv = pn533_register_device(id->driver_info, protocols, protocol_type,
					phy, &usb_phy_ops, fops,
					&phy->udev->dev, &interface->dev);

	if (IS_ERR(priv)) {
		rc = PTR_ERR(priv);
		goto error;
	}

	phy->priv = priv;

	rc = pn533_finalize_setup(priv);
	if (rc)
		goto err_deregister;

	usb_set_intfdata(interface, phy);

	return 0;

err_deregister:
	pn533_unregister_device(phy->priv);
error:
	usb_kill_urb(phy->in_urb);
	usb_kill_urb(phy->out_urb);
	usb_kill_urb(phy->ack_urb);

	usb_free_urb(phy->in_urb);
	usb_free_urb(phy->out_urb);
	usb_free_urb(phy->ack_urb);
	usb_put_dev(phy->udev);
	kfree(in_buf);
	kfree(phy->ack_buffer);

	return rc;
}

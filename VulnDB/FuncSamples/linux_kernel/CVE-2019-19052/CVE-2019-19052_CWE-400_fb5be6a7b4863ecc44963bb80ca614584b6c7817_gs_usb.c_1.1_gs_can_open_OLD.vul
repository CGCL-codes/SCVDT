static int gs_can_open(struct net_device *netdev)
{
	struct gs_can *dev = netdev_priv(netdev);
	struct gs_usb *parent = dev->parent;
	int rc, i;
	struct gs_device_mode *dm;
	u32 ctrlmode;

	rc = open_candev(netdev);
	if (rc)
		return rc;

	if (atomic_add_return(1, &parent->active_channels) == 1) {
		for (i = 0; i < GS_MAX_RX_URBS; i++) {
			struct urb *urb;
			u8 *buf;

			/* alloc rx urb */
			urb = usb_alloc_urb(0, GFP_KERNEL);
			if (!urb)
				return -ENOMEM;

			/* alloc rx buffer */
			buf = usb_alloc_coherent(dev->udev,
						 sizeof(struct gs_host_frame),
						 GFP_KERNEL,
						 &urb->transfer_dma);
			if (!buf) {
				netdev_err(netdev,
					   "No memory left for USB buffer\n");
				usb_free_urb(urb);
				return -ENOMEM;
			}

			/* fill, anchor, and submit rx urb */
			usb_fill_bulk_urb(urb,
					  dev->udev,
					  usb_rcvbulkpipe(dev->udev,
							  GSUSB_ENDPOINT_IN),
					  buf,
					  sizeof(struct gs_host_frame),
					  gs_usb_receive_bulk_callback,
					  parent);
			urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

			usb_anchor_urb(urb, &parent->rx_submitted);

			rc = usb_submit_urb(urb, GFP_KERNEL);
			if (rc) {
				if (rc == -ENODEV)
					netif_device_detach(dev->netdev);

				netdev_err(netdev,
					   "usb_submit failed (err=%d)\n",
					   rc);

				usb_unanchor_urb(urb);
				break;
			}

			/* Drop reference,
			 * USB core will take care of freeing it
			 */
			usb_free_urb(urb);
		}
	}

	dm = kmalloc(sizeof(*dm), GFP_KERNEL);
	if (!dm)
		return -ENOMEM;

	/* flags */
	ctrlmode = dev->can.ctrlmode;
	dm->flags = 0;

	if (ctrlmode & CAN_CTRLMODE_LOOPBACK)
		dm->flags |= GS_CAN_MODE_LOOP_BACK;
	else if (ctrlmode & CAN_CTRLMODE_LISTENONLY)
		dm->flags |= GS_CAN_MODE_LISTEN_ONLY;

	/* Controller is not allowed to retry TX
	 * this mode is unavailable on atmels uc3c hardware
	 */
	if (ctrlmode & CAN_CTRLMODE_ONE_SHOT)
		dm->flags |= GS_CAN_MODE_ONE_SHOT;

	if (ctrlmode & CAN_CTRLMODE_3_SAMPLES)
		dm->flags |= GS_CAN_MODE_TRIPLE_SAMPLE;

	/* finally start device */
	dm->mode = GS_CAN_MODE_START;
	rc = usb_control_msg(interface_to_usbdev(dev->iface),
			     usb_sndctrlpipe(interface_to_usbdev(dev->iface), 0),
			     GS_USB_BREQ_MODE,
			     USB_DIR_OUT | USB_TYPE_VENDOR |
			     USB_RECIP_INTERFACE,
			     dev->channel,
			     0,
			     dm,
			     sizeof(*dm),
			     1000);

	if (rc < 0) {
		netdev_err(netdev, "Couldn't start device (err=%d)\n", rc);
		kfree(dm);
		return rc;
	}

	kfree(dm);

	dev->can.state = CAN_STATE_ERROR_ACTIVE;

	if (!(dev->can.ctrlmode & CAN_CTRLMODE_LISTENONLY))
		netif_start_queue(netdev);

	return 0;
}

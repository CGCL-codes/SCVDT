static void atusb_disconnect(struct usb_interface *interface)
{
	struct atusb *atusb = usb_get_intfdata(interface);

	dev_dbg(&atusb->usb_dev->dev, "%s\n", __func__);

	atusb->shutdown = 1;
	cancel_delayed_work_sync(&atusb->work);

	usb_kill_anchored_urbs(&atusb->rx_urbs);
	atusb_free_urbs(atusb);
	usb_kill_urb(atusb->tx_urb);
	usb_free_urb(atusb->tx_urb);

	ieee802154_unregister_hw(atusb->hw);

	usb_put_dev(atusb->usb_dev);

	ieee802154_free_hw(atusb->hw);

	usb_set_intfdata(interface, NULL);

	pr_debug("%s done\n", __func__);
}

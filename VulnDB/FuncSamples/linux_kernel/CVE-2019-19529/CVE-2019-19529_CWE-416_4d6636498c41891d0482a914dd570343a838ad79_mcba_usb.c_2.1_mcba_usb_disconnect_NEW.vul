static void mcba_usb_disconnect(struct usb_interface *intf)
{
	struct mcba_priv *priv = usb_get_intfdata(intf);

	usb_set_intfdata(intf, NULL);

	netdev_info(priv->netdev, "device disconnected\n");

	unregister_candev(priv->netdev);
	mcba_urb_unlink(priv);
	free_candev(priv->netdev);
}

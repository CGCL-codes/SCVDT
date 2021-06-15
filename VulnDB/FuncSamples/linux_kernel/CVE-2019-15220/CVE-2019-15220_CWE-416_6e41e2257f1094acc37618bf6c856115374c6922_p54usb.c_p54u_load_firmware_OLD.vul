static int p54u_load_firmware(struct ieee80211_hw *dev,
			      struct usb_interface *intf)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct p54u_priv *priv = dev->priv;
	struct device *device = &udev->dev;
	int err, i;

	BUILD_BUG_ON(ARRAY_SIZE(p54u_fwlist) != __NUM_P54U_HWTYPES);

	init_completion(&priv->fw_wait_load);
	i = p54_find_type(priv);
	if (i < 0)
		return i;

	dev_info(&priv->udev->dev, "Loading firmware file %s\n",
	       p54u_fwlist[i].fw);

	usb_get_dev(udev);
	err = request_firmware_nowait(THIS_MODULE, 1, p54u_fwlist[i].fw,
				      device, GFP_KERNEL, priv,
				      p54u_load_firmware_cb);
	if (err) {
		dev_err(&priv->udev->dev, "(p54usb) cannot load firmware %s "
					  "(%d)!\n", p54u_fwlist[i].fw, err);
		usb_put_dev(udev);
	}

	return err;
}

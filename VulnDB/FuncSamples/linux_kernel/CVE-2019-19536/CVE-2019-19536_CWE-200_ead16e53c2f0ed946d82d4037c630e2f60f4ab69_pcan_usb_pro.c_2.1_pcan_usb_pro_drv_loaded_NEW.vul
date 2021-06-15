static int pcan_usb_pro_drv_loaded(struct peak_usb_device *dev, int loaded)
{
	u8 *buffer;
	int err;

	buffer = kzalloc(PCAN_USBPRO_FCT_DRVLD_REQ_LEN, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	buffer[0] = 0;
	buffer[1] = !!loaded;

	err = pcan_usb_pro_send_req(dev, PCAN_USBPRO_REQ_FCT,
				    PCAN_USBPRO_FCT_DRVLD, buffer,
				    PCAN_USBPRO_FCT_DRVLD_REQ_LEN);
	kfree(buffer);

	return err;
}

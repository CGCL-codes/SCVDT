static int logi_dj_probe(struct hid_device *hdev,
			 const struct hid_device_id *id)
{
	struct usb_interface *intf = to_usb_interface(hdev->dev.parent);
	struct dj_receiver_dev *djrcv_dev;
	int retval;

	if (is_dj_device((struct dj_device *)hdev->driver_data))
		return -ENODEV;

	dbg_hid("%s called for ifnum %d\n", __func__,
		intf->cur_altsetting->desc.bInterfaceNumber);

	/* Ignore interfaces 0 and 1, they will not carry any data, dont create
	 * any hid_device for them */
	if (intf->cur_altsetting->desc.bInterfaceNumber !=
	    LOGITECH_DJ_INTERFACE_NUMBER) {
		dbg_hid("%s: ignoring ifnum %d\n", __func__,
			intf->cur_altsetting->desc.bInterfaceNumber);
		return -ENODEV;
	}

	/* Treat interface 2 */

	djrcv_dev = kzalloc(sizeof(struct dj_receiver_dev), GFP_KERNEL);
	if (!djrcv_dev) {
		dev_err(&hdev->dev,
			"%s:failed allocating dj_receiver_dev\n", __func__);
		return -ENOMEM;
	}
	djrcv_dev->hdev = hdev;
	INIT_WORK(&djrcv_dev->work, delayedwork_callback);
	spin_lock_init(&djrcv_dev->lock);
	if (kfifo_alloc(&djrcv_dev->notif_fifo,
			DJ_MAX_NUMBER_NOTIFICATIONS * sizeof(struct dj_report),
			GFP_KERNEL)) {
		dev_err(&hdev->dev,
			"%s:failed allocating notif_fifo\n", __func__);
		kfree(djrcv_dev);
		return -ENOMEM;
	}
	hid_set_drvdata(hdev, djrcv_dev);

	/* Call  to usbhid to fetch the HID descriptors of interface 2 and
	 * subsequently call to the hid/hid-core to parse the fetched
	 * descriptors, this will in turn create the hidraw and hiddev nodes
	 * for interface 2 of the receiver */
	retval = hid_parse(hdev);
	if (retval) {
		dev_err(&hdev->dev,
			"%s:parse of interface 2 failed\n", __func__);
		goto hid_parse_fail;
	}

	if (!hid_validate_values(hdev, HID_OUTPUT_REPORT, REPORT_ID_DJ_SHORT,
				 0, DJREPORT_SHORT_LENGTH - 1)) {
		retval = -ENODEV;
		goto hid_parse_fail;
	}

	/* Starts the usb device and connects to upper interfaces hiddev and
	 * hidraw */
	retval = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
	if (retval) {
		dev_err(&hdev->dev,
			"%s:hid_hw_start returned error\n", __func__);
		goto hid_hw_start_fail;
	}

	retval = logi_dj_recv_switch_to_dj_mode(djrcv_dev, 0);
	if (retval < 0) {
		dev_err(&hdev->dev,
			"%s:logi_dj_recv_switch_to_dj_mode returned error:%d\n",
			__func__, retval);
		goto switch_to_dj_mode_fail;
	}

	/* This is enabling the polling urb on the IN endpoint */
	retval = hid_hw_open(hdev);
	if (retval < 0) {
		dev_err(&hdev->dev, "%s:hid_hw_open returned error:%d\n",
			__func__, retval);
		goto llopen_failed;
	}

	/* Allow incoming packets to arrive: */
	hid_device_io_start(hdev);

	retval = logi_dj_recv_query_paired_devices(djrcv_dev);
	if (retval < 0) {
		dev_err(&hdev->dev, "%s:logi_dj_recv_query_paired_devices "
			"error:%d\n", __func__, retval);
		goto logi_dj_recv_query_paired_devices_failed;
	}

	return retval;

logi_dj_recv_query_paired_devices_failed:
	hid_hw_close(hdev);

llopen_failed:
switch_to_dj_mode_fail:
	hid_hw_stop(hdev);

hid_hw_start_fail:
hid_parse_fail:
	kfifo_free(&djrcv_dev->notif_fifo);
	kfree(djrcv_dev);
	hid_set_drvdata(hdev, NULL);
	return retval;

}

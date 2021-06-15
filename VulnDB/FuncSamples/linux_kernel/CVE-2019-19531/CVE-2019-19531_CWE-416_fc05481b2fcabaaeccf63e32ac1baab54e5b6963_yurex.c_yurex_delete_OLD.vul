static void yurex_delete(struct kref *kref)
{
	struct usb_yurex *dev = to_yurex_dev(kref);

	dev_dbg(&dev->interface->dev, "%s\n", __func__);

	usb_put_dev(dev->udev);
	if (dev->cntl_urb) {
		usb_kill_urb(dev->cntl_urb);
		kfree(dev->cntl_req);
		if (dev->cntl_buffer)
			usb_free_coherent(dev->udev, YUREX_BUF_SIZE,
				dev->cntl_buffer, dev->cntl_urb->transfer_dma);
		usb_free_urb(dev->cntl_urb);
	}
	if (dev->urb) {
		usb_kill_urb(dev->urb);
		if (dev->int_buffer)
			usb_free_coherent(dev->udev, YUREX_BUF_SIZE,
				dev->int_buffer, dev->urb->transfer_dma);
		usb_free_urb(dev->urb);
	}
	kfree(dev);
}

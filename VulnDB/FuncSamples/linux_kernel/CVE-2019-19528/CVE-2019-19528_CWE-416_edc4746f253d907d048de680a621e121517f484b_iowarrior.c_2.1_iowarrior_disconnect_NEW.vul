static void iowarrior_disconnect(struct usb_interface *interface)
{
	struct iowarrior *dev;
	int minor;

	dev = usb_get_intfdata(interface);
	mutex_lock(&iowarrior_open_disc_lock);
	usb_set_intfdata(interface, NULL);

	minor = dev->minor;
	mutex_unlock(&iowarrior_open_disc_lock);
	/* give back our minor - this will call close() locks need to be dropped at this point*/

	usb_deregister_dev(interface, &iowarrior_class);

	mutex_lock(&dev->mutex);

	/* prevent device read, write and ioctl */
	dev->present = 0;

	if (dev->opened) {
		/* There is a process that holds a filedescriptor to the device ,
		   so we only shutdown read-/write-ops going on.
		   Deleting the device is postponed until close() was called.
		 */
		usb_kill_urb(dev->int_in_urb);
		wake_up_interruptible(&dev->read_wait);
		wake_up_interruptible(&dev->write_wait);
		mutex_unlock(&dev->mutex);
	} else {
		/* no process is using the device, cleanup now */
		mutex_unlock(&dev->mutex);
		iowarrior_delete(dev);
	}

	dev_info(&interface->dev, "I/O-Warror #%d now disconnected\n",
		 minor - IOWARRIOR_MINOR_BASE);
}

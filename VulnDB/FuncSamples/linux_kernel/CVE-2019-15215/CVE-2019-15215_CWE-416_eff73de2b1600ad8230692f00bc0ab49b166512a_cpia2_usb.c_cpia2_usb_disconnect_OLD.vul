static void cpia2_usb_disconnect(struct usb_interface *intf)
{
	struct camera_data *cam = usb_get_intfdata(intf);
	usb_set_intfdata(intf, NULL);

	DBG("Stopping stream\n");
	cpia2_usb_stream_stop(cam);

	mutex_lock(&cam->v4l2_lock);
	DBG("Unregistering camera\n");
	cpia2_unregister_camera(cam);
	v4l2_device_disconnect(&cam->v4l2_dev);
	mutex_unlock(&cam->v4l2_lock);
	v4l2_device_put(&cam->v4l2_dev);

	if(cam->buffers) {
		DBG("Wakeup waiting processes\n");
		cam->curbuff->status = FRAME_READY;
		cam->curbuff->length = 0;
		wake_up_interruptible(&cam->wq_stream);
	}

	LOG("CPiA2 camera disconnected.\n");
}

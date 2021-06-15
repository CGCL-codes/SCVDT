static int zr364xx_vidioc_querycap(struct file *file, void *priv,
				   struct v4l2_capability *cap)
{
	struct zr364xx_camera *cam = video_drvdata(file);

	strscpy(cap->driver, DRIVER_DESC, sizeof(cap->driver));
	strscpy(cap->card, cam->udev->product, sizeof(cap->card));
	strscpy(cap->bus_info, dev_name(&cam->udev->dev),
		sizeof(cap->bus_info));
	cap->device_caps = V4L2_CAP_VIDEO_CAPTURE |
			    V4L2_CAP_READWRITE |
			    V4L2_CAP_STREAMING;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;

	return 0;
}

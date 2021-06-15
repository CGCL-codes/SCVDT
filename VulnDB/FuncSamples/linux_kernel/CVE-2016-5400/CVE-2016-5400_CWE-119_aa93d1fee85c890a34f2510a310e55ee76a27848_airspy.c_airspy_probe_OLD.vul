static int airspy_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	struct airspy *s;
	int ret;
	u8 u8tmp, buf[BUF_SIZE];

	s = kzalloc(sizeof(struct airspy), GFP_KERNEL);
	if (s == NULL) {
		dev_err(&intf->dev, "Could not allocate memory for state\n");
		return -ENOMEM;
	}

	mutex_init(&s->v4l2_lock);
	mutex_init(&s->vb_queue_lock);
	spin_lock_init(&s->queued_bufs_lock);
	INIT_LIST_HEAD(&s->queued_bufs);
	s->dev = &intf->dev;
	s->udev = interface_to_usbdev(intf);
	s->f_adc = bands[0].rangelow;
	s->f_rf = bands_rf[0].rangelow;
	s->pixelformat = formats[0].pixelformat;
	s->buffersize = formats[0].buffersize;

	/* Detect device */
	ret = airspy_ctrl_msg(s, CMD_BOARD_ID_READ, 0, 0, &u8tmp, 1);
	if (ret == 0)
		ret = airspy_ctrl_msg(s, CMD_VERSION_STRING_READ, 0, 0,
				buf, BUF_SIZE);
	if (ret) {
		dev_err(s->dev, "Could not detect board\n");
		goto err_free_mem;
	}

	buf[BUF_SIZE - 1] = '\0';

	dev_info(s->dev, "Board ID: %02x\n", u8tmp);
	dev_info(s->dev, "Firmware version: %s\n", buf);

	/* Init videobuf2 queue structure */
	s->vb_queue.type = V4L2_BUF_TYPE_SDR_CAPTURE;
	s->vb_queue.io_modes = VB2_MMAP | VB2_USERPTR | VB2_READ;
	s->vb_queue.drv_priv = s;
	s->vb_queue.buf_struct_size = sizeof(struct airspy_frame_buf);
	s->vb_queue.ops = &airspy_vb2_ops;
	s->vb_queue.mem_ops = &vb2_vmalloc_memops;
	s->vb_queue.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	ret = vb2_queue_init(&s->vb_queue);
	if (ret) {
		dev_err(s->dev, "Could not initialize vb2 queue\n");
		goto err_free_mem;
	}

	/* Init video_device structure */
	s->vdev = airspy_template;
	s->vdev.queue = &s->vb_queue;
	s->vdev.queue->lock = &s->vb_queue_lock;
	video_set_drvdata(&s->vdev, s);

	/* Register the v4l2_device structure */
	s->v4l2_dev.release = airspy_video_release;
	ret = v4l2_device_register(&intf->dev, &s->v4l2_dev);
	if (ret) {
		dev_err(s->dev, "Failed to register v4l2-device (%d)\n", ret);
		goto err_free_mem;
	}

	/* Register controls */
	v4l2_ctrl_handler_init(&s->hdl, 5);
	s->lna_gain_auto = v4l2_ctrl_new_std(&s->hdl, &airspy_ctrl_ops,
			V4L2_CID_RF_TUNER_LNA_GAIN_AUTO, 0, 1, 1, 0);
	s->lna_gain = v4l2_ctrl_new_std(&s->hdl, &airspy_ctrl_ops,
			V4L2_CID_RF_TUNER_LNA_GAIN, 0, 14, 1, 8);
	v4l2_ctrl_auto_cluster(2, &s->lna_gain_auto, 0, false);
	s->mixer_gain_auto = v4l2_ctrl_new_std(&s->hdl, &airspy_ctrl_ops,
			V4L2_CID_RF_TUNER_MIXER_GAIN_AUTO, 0, 1, 1, 0);
	s->mixer_gain = v4l2_ctrl_new_std(&s->hdl, &airspy_ctrl_ops,
			V4L2_CID_RF_TUNER_MIXER_GAIN, 0, 15, 1, 8);
	v4l2_ctrl_auto_cluster(2, &s->mixer_gain_auto, 0, false);
	s->if_gain = v4l2_ctrl_new_std(&s->hdl, &airspy_ctrl_ops,
			V4L2_CID_RF_TUNER_IF_GAIN, 0, 15, 1, 0);
	if (s->hdl.error) {
		ret = s->hdl.error;
		dev_err(s->dev, "Could not initialize controls\n");
		goto err_free_controls;
	}

	v4l2_ctrl_handler_setup(&s->hdl);

	s->v4l2_dev.ctrl_handler = &s->hdl;
	s->vdev.v4l2_dev = &s->v4l2_dev;
	s->vdev.lock = &s->v4l2_lock;

	ret = video_register_device(&s->vdev, VFL_TYPE_SDR, -1);
	if (ret) {
		dev_err(s->dev, "Failed to register as video device (%d)\n",
				ret);
		goto err_unregister_v4l2_dev;
	}
	dev_info(s->dev, "Registered as %s\n",
			video_device_node_name(&s->vdev));
	dev_notice(s->dev, "SDR API is still slightly experimental and functionality changes may follow\n");
	return 0;

err_free_controls:
	v4l2_ctrl_handler_free(&s->hdl);
err_unregister_v4l2_dev:
	v4l2_device_unregister(&s->v4l2_dev);
err_free_mem:
	kfree(s);
	return ret;
}

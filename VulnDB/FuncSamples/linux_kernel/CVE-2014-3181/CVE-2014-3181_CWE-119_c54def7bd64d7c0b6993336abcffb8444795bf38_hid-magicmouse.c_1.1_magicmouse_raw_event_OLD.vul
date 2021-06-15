static int magicmouse_raw_event(struct hid_device *hdev,
		struct hid_report *report, u8 *data, int size)
{
	struct magicmouse_sc *msc = hid_get_drvdata(hdev);
	struct input_dev *input = msc->input;
	int x = 0, y = 0, ii, clicks = 0, npoints;

	switch (data[0]) {
	case TRACKPAD_REPORT_ID:
		/* Expect four bytes of prefix, and N*9 bytes of touch data. */
		if (size < 4 || ((size - 4) % 9) != 0)
			return 0;
		npoints = (size - 4) / 9;
		msc->ntouches = 0;
		for (ii = 0; ii < npoints; ii++)
			magicmouse_emit_touch(msc, ii, data + ii * 9 + 4);

		clicks = data[1];

		/* The following bits provide a device specific timestamp. They
		 * are unused here.
		 *
		 * ts = data[1] >> 6 | data[2] << 2 | data[3] << 10;
		 */
		break;
	case MOUSE_REPORT_ID:
		/* Expect six bytes of prefix, and N*8 bytes of touch data. */
		if (size < 6 || ((size - 6) % 8) != 0)
			return 0;
		npoints = (size - 6) / 8;
		msc->ntouches = 0;
		for (ii = 0; ii < npoints; ii++)
			magicmouse_emit_touch(msc, ii, data + ii * 8 + 6);

		/* When emulating three-button mode, it is important
		 * to have the current touch information before
		 * generating a click event.
		 */
		x = (int)(((data[3] & 0x0c) << 28) | (data[1] << 22)) >> 22;
		y = (int)(((data[3] & 0x30) << 26) | (data[2] << 22)) >> 22;
		clicks = data[3];

		/* The following bits provide a device specific timestamp. They
		 * are unused here.
		 *
		 * ts = data[3] >> 6 | data[4] << 2 | data[5] << 10;
		 */
		break;
	case DOUBLE_REPORT_ID:
		/* Sometimes the trackpad sends two touch reports in one
		 * packet.
		 */
		magicmouse_raw_event(hdev, report, data + 2, data[1]);
		magicmouse_raw_event(hdev, report, data + 2 + data[1],
			size - 2 - data[1]);
		break;
	default:
		return 0;
	}

	if (input->id.product == USB_DEVICE_ID_APPLE_MAGICMOUSE) {
		magicmouse_emit_buttons(msc, clicks & 3);
		input_report_rel(input, REL_X, x);
		input_report_rel(input, REL_Y, y);
	} else { /* USB_DEVICE_ID_APPLE_MAGICTRACKPAD */
		input_report_key(input, BTN_MOUSE, clicks & 1);
		input_mt_report_pointer_emulation(input, true);
	}

	input_sync(input);
	return 1;
}

static int drff_init(struct hid_device *hid)
{
	struct drff_device *drff;
	struct hid_report *report;
	struct hid_input *hidinput = list_first_entry(&hid->inputs,
						struct hid_input, list);
	struct list_head *report_list =
			&hid->report_enum[HID_OUTPUT_REPORT].report_list;
	struct input_dev *dev = hidinput->input;
	int error;

	if (list_empty(report_list)) {
		hid_err(hid, "no output reports found\n");
		return -ENODEV;
	}

	report = list_first_entry(report_list, struct hid_report, list);
	if (report->maxfield < 1) {
		hid_err(hid, "no fields in the report\n");
		return -ENODEV;
	}

	if (report->field[0]->report_count < 7) {
		hid_err(hid, "not enough values in the field\n");
		return -ENODEV;
	}

	drff = kzalloc(sizeof(struct drff_device), GFP_KERNEL);
	if (!drff)
		return -ENOMEM;

	set_bit(FF_RUMBLE, dev->ffbit);

	error = input_ff_create_memless(dev, drff, drff_play);
	if (error) {
		kfree(drff);
		return error;
	}

	drff->report = report;
	drff->report->field[0]->value[0] = 0xf3;
	drff->report->field[0]->value[1] = 0x00;
	drff->report->field[0]->value[2] = 0x00;
	drff->report->field[0]->value[3] = 0x00;
	drff->report->field[0]->value[4] = 0x00;
	drff->report->field[0]->value[5] = 0x00;
	drff->report->field[0]->value[6] = 0x00;
	hid_hw_request(hid, drff->report, HID_REQ_SET_REPORT);

	hid_info(hid, "Force Feedback for DragonRise Inc. "
		 "game controllers by Richard Walmsley <richwalm@gmail.com>\n");

	return 0;
}

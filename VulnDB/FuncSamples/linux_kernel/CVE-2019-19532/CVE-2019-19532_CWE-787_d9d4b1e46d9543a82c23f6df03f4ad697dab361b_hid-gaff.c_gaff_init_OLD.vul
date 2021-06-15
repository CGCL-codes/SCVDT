static int gaff_init(struct hid_device *hid)
{
	struct gaff_device *gaff;
	struct hid_report *report;
	struct hid_input *hidinput = list_entry(hid->inputs.next,
						struct hid_input, list);
	struct list_head *report_list =
			&hid->report_enum[HID_OUTPUT_REPORT].report_list;
	struct list_head *report_ptr = report_list;
	struct input_dev *dev = hidinput->input;
	int error;

	if (list_empty(report_list)) {
		hid_err(hid, "no output reports found\n");
		return -ENODEV;
	}

	report_ptr = report_ptr->next;

	report = list_entry(report_ptr, struct hid_report, list);
	if (report->maxfield < 1) {
		hid_err(hid, "no fields in the report\n");
		return -ENODEV;
	}

	if (report->field[0]->report_count < 6) {
		hid_err(hid, "not enough values in the field\n");
		return -ENODEV;
	}

	gaff = kzalloc(sizeof(struct gaff_device), GFP_KERNEL);
	if (!gaff)
		return -ENOMEM;

	set_bit(FF_RUMBLE, dev->ffbit);

	error = input_ff_create_memless(dev, gaff, hid_gaff_play);
	if (error) {
		kfree(gaff);
		return error;
	}

	gaff->report = report;
	gaff->report->field[0]->value[0] = 0x51;
	gaff->report->field[0]->value[1] = 0x00;
	gaff->report->field[0]->value[2] = 0x00;
	gaff->report->field[0]->value[3] = 0x00;
	hid_hw_request(hid, gaff->report, HID_REQ_SET_REPORT);

	gaff->report->field[0]->value[0] = 0xfa;
	gaff->report->field[0]->value[1] = 0xfe;

	hid_hw_request(hid, gaff->report, HID_REQ_SET_REPORT);

	hid_info(hid, "Force Feedback for GreenAsia 0x12 devices by Lukasz Lubojanski <lukasz@lubojanski.info>\n");

	return 0;
}

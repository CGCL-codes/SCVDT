static int emsff_init(struct hid_device *hid)
{
	struct emsff_device *emsff;
	struct hid_report *report;
	struct hid_input *hidinput;
	struct list_head *report_list =
			&hid->report_enum[HID_OUTPUT_REPORT].report_list;
	struct input_dev *dev;
	int error;

	if (list_empty(&hid->inputs)) {
		hid_err(hid, "no inputs found\n");
		return -ENODEV;
	}
	hidinput = list_first_entry(&hid->inputs, struct hid_input, list);
	dev = hidinput->input;

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

	emsff = kzalloc(sizeof(struct emsff_device), GFP_KERNEL);
	if (!emsff)
		return -ENOMEM;

	set_bit(FF_RUMBLE, dev->ffbit);

	error = input_ff_create_memless(dev, emsff, emsff_play);
	if (error) {
		kfree(emsff);
		return error;
	}

	emsff->report = report;
	emsff->report->field[0]->value[0] = 0x01;
	emsff->report->field[0]->value[1] = 0x00;
	emsff->report->field[0]->value[2] = 0x00;
	emsff->report->field[0]->value[3] = 0x00;
	emsff->report->field[0]->value[4] = 0x00;
	emsff->report->field[0]->value[5] = 0x00;
	emsff->report->field[0]->value[6] = 0x00;
	hid_hw_request(hid, emsff->report, HID_REQ_SET_REPORT);

	hid_info(hid, "force feedback for EMS based devices by Ignaz Forster <ignaz.forster@gmx.de>\n");

	return 0;
}

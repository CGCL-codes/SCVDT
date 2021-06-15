static int axff_init(struct hid_device *hid)
{
	struct axff_device *axff;
	struct hid_report *report;
	struct hid_input *hidinput = list_first_entry(&hid->inputs, struct hid_input, list);
	struct list_head *report_list =&hid->report_enum[HID_OUTPUT_REPORT].report_list;
	struct input_dev *dev = hidinput->input;
	int field_count = 0;
	int i, j;
	int error;

	if (list_empty(report_list)) {
		hid_err(hid, "no output reports found\n");
		return -ENODEV;
	}

	report = list_first_entry(report_list, struct hid_report, list);
	for (i = 0; i < report->maxfield; i++) {
		for (j = 0; j < report->field[i]->report_count; j++) {
			report->field[i]->value[j] = 0x00;
			field_count++;
		}
	}

	if (field_count < 4 && hid->product != 0xf705) {
		hid_err(hid, "not enough fields in the report: %d\n",
			field_count);
		return -ENODEV;
	}

	axff = kzalloc(sizeof(struct axff_device), GFP_KERNEL);
	if (!axff)
		return -ENOMEM;

	set_bit(FF_RUMBLE, dev->ffbit);

	error = input_ff_create_memless(dev, axff, axff_play);
	if (error)
		goto err_free_mem;

	axff->report = report;
	hid_hw_request(hid, axff->report, HID_REQ_SET_REPORT);

	hid_info(hid, "Force Feedback for ACRUX game controllers by Sergei Kolzun <x0r@dv-life.ru>\n");

	return 0;

err_free_mem:
	kfree(axff);
	return error;
}

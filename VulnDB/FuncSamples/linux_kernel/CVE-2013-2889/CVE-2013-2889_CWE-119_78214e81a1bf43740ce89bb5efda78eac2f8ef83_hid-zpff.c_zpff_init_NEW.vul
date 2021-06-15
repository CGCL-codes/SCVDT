static int zpff_init(struct hid_device *hid)
{
	struct zpff_device *zpff;
	struct hid_report *report;
	struct hid_input *hidinput = list_entry(hid->inputs.next,
						struct hid_input, list);
	struct input_dev *dev = hidinput->input;
	int i, error;

	for (i = 0; i < 4; i++) {
		report = hid_validate_values(hid, HID_OUTPUT_REPORT, 0, i, 1);
		if (!report)
			return -ENODEV;
	}

	zpff = kzalloc(sizeof(struct zpff_device), GFP_KERNEL);
	if (!zpff)
		return -ENOMEM;

	set_bit(FF_RUMBLE, dev->ffbit);

	error = input_ff_create_memless(dev, zpff, zpff_play);
	if (error) {
		kfree(zpff);
		return error;
	}

	zpff->report = report;
	zpff->report->field[0]->value[0] = 0x00;
	zpff->report->field[1]->value[0] = 0x02;
	zpff->report->field[2]->value[0] = 0x00;
	zpff->report->field[3]->value[0] = 0x00;
	hid_hw_request(hid, zpff->report, HID_REQ_SET_REPORT);

	hid_info(hid, "force feedback for Zeroplus based devices by Anssi Hannula <anssi.hannula@gmail.com>\n");

	return 0;
}

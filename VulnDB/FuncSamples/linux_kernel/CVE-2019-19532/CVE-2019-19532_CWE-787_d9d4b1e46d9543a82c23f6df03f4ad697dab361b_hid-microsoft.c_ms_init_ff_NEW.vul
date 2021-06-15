static int ms_init_ff(struct hid_device *hdev)
{
	struct hid_input *hidinput;
	struct input_dev *input_dev;
	struct ms_data *ms = hid_get_drvdata(hdev);

	if (list_empty(&hdev->inputs)) {
		hid_err(hdev, "no inputs found\n");
		return -ENODEV;
	}
	hidinput = list_entry(hdev->inputs.next, struct hid_input, list);
	input_dev = hidinput->input;

	if (!(ms->quirks & MS_QUIRK_FF))
		return 0;

	ms->hdev = hdev;
	INIT_WORK(&ms->ff_worker, ms_ff_worker);

	ms->output_report_dmabuf = devm_kzalloc(&hdev->dev,
						sizeof(struct xb1s_ff_report),
						GFP_KERNEL);
	if (ms->output_report_dmabuf == NULL)
		return -ENOMEM;

	input_set_capability(input_dev, EV_FF, FF_RUMBLE);
	return input_ff_create_memless(input_dev, NULL, ms_play_effect);
}

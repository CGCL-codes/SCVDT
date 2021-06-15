static int picolcd_raw_event(struct hid_device *hdev,
		struct hid_report *report, u8 *raw_data, int size)
{
	struct picolcd_data *data = hid_get_drvdata(hdev);
	unsigned long flags;
	int ret = 0;

	if (!data)
		return 1;

	if (report->id == REPORT_KEY_STATE) {
		if (data->input_keys)
			ret = picolcd_raw_keypad(data, report, raw_data+1, size-1);
	} else if (report->id == REPORT_IR_DATA) {
		ret = picolcd_raw_cir(data, report, raw_data+1, size-1);
	} else {
		spin_lock_irqsave(&data->lock, flags);
		/*
		 * We let the caller of picolcd_send_and_wait() check if the
		 * report we got is one of the expected ones or not.
		 */
		if (data->pending) {
			memcpy(data->pending->raw_data, raw_data+1, size-1);
			data->pending->raw_size  = size-1;
			data->pending->in_report = report;
			complete(&data->pending->ready);
		}
		spin_unlock_irqrestore(&data->lock, flags);
	}

	picolcd_debug_raw_event(data, hdev, report, raw_data, size);
	return 1;
}

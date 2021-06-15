static ssize_t picolcd_operation_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct picolcd_data *data = dev_get_drvdata(dev);
	struct hid_report *report = NULL;
	size_t cnt = count;
	int timeout = data->opmode_delay;
	unsigned long flags;

	if (cnt >= 3 && strncmp("lcd", buf, 3) == 0) {
		if (data->status & PICOLCD_BOOTLOADER)
			report = picolcd_out_report(REPORT_EXIT_FLASHER, data->hdev);
		buf += 3;
		cnt -= 3;
	} else if (cnt >= 10 && strncmp("bootloader", buf, 10) == 0) {
		if (!(data->status & PICOLCD_BOOTLOADER))
			report = picolcd_out_report(REPORT_EXIT_KEYBOARD, data->hdev);
		buf += 10;
		cnt -= 10;
	}
	if (!report || report->maxfield != 1)
		return -EINVAL;

	while (cnt > 0 && (buf[cnt-1] == '\n' || buf[cnt-1] == '\r'))
		cnt--;
	if (cnt != 0)
		return -EINVAL;

	spin_lock_irqsave(&data->lock, flags);
	hid_set_field(report->field[0], 0, timeout & 0xff);
	hid_set_field(report->field[0], 1, (timeout >> 8) & 0xff);
	hid_hw_request(data->hdev, report, HID_REQ_SET_REPORT);
	spin_unlock_irqrestore(&data->lock, flags);
	return count;
}

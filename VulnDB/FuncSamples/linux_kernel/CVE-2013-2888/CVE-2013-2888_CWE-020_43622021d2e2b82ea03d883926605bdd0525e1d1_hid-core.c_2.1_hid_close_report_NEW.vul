static void hid_close_report(struct hid_device *device)
{
	unsigned i, j;

	for (i = 0; i < HID_REPORT_TYPES; i++) {
		struct hid_report_enum *report_enum = device->report_enum + i;

		for (j = 0; j < HID_MAX_IDS; j++) {
			struct hid_report *report = report_enum->report_id_hash[j];
			if (report)
				hid_free_report(report);
		}
		memset(report_enum, 0, sizeof(*report_enum));
		INIT_LIST_HEAD(&report_enum->report_list);
	}

	kfree(device->rdesc);
	device->rdesc = NULL;
	device->rsize = 0;

	kfree(device->collection);
	device->collection = NULL;
	device->collection_size = 0;
	device->maxcollection = 0;
	device->maxapplication = 0;

	device->status &= ~HID_STAT_PARSED;
}

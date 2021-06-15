static int hid_parser_global(struct hid_parser *parser, struct hid_item *item)
{
	__u32 raw_value;
	switch (item->tag) {
	case HID_GLOBAL_ITEM_TAG_PUSH:

		if (parser->global_stack_ptr == HID_GLOBAL_STACK_SIZE) {
			hid_err(parser->device, "global environment stack overflow\n");
			return -1;
		}

		memcpy(parser->global_stack + parser->global_stack_ptr++,
			&parser->global, sizeof(struct hid_global));
		return 0;

	case HID_GLOBAL_ITEM_TAG_POP:

		if (!parser->global_stack_ptr) {
			hid_err(parser->device, "global environment stack underflow\n");
			return -1;
		}

		memcpy(&parser->global, parser->global_stack +
			--parser->global_stack_ptr, sizeof(struct hid_global));
		return 0;

	case HID_GLOBAL_ITEM_TAG_USAGE_PAGE:
		parser->global.usage_page = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_LOGICAL_MINIMUM:
		parser->global.logical_minimum = item_sdata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_LOGICAL_MAXIMUM:
		if (parser->global.logical_minimum < 0)
			parser->global.logical_maximum = item_sdata(item);
		else
			parser->global.logical_maximum = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_PHYSICAL_MINIMUM:
		parser->global.physical_minimum = item_sdata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_PHYSICAL_MAXIMUM:
		if (parser->global.physical_minimum < 0)
			parser->global.physical_maximum = item_sdata(item);
		else
			parser->global.physical_maximum = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_UNIT_EXPONENT:
		/* Units exponent negative numbers are given through a
		 * two's complement.
		 * See "6.2.2.7 Global Items" for more information. */
		raw_value = item_udata(item);
		if (!(raw_value & 0xfffffff0))
			parser->global.unit_exponent = hid_snto32(raw_value, 4);
		else
			parser->global.unit_exponent = raw_value;
		return 0;

	case HID_GLOBAL_ITEM_TAG_UNIT:
		parser->global.unit = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_REPORT_SIZE:
		parser->global.report_size = item_udata(item);
		if (parser->global.report_size > 128) {
			hid_err(parser->device, "invalid report_size %d\n",
					parser->global.report_size);
			return -1;
		}
		return 0;

	case HID_GLOBAL_ITEM_TAG_REPORT_COUNT:
		parser->global.report_count = item_udata(item);
		if (parser->global.report_count > HID_MAX_USAGES) {
			hid_err(parser->device, "invalid report_count %d\n",
					parser->global.report_count);
			return -1;
		}
		return 0;

	case HID_GLOBAL_ITEM_TAG_REPORT_ID:
		parser->global.report_id = item_udata(item);
		if (parser->global.report_id == 0 ||
		    parser->global.report_id >= HID_MAX_IDS) {
			hid_err(parser->device, "report_id %u is invalid\n",
				parser->global.report_id);
			return -1;
		}
		return 0;

	default:
		hid_err(parser->device, "unknown global tag 0x%x\n", item->tag);
		return -1;
	}
}

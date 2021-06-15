static void* exif_ifd_make_value(image_info_data *info_data, int motorola_intel TSRMLS_DC) {
	size_t  byte_count;
	char    *value_ptr, *data_ptr;
	size_t  i;

	image_info_value  *info_value;

	byte_count = php_tiff_bytes_per_format[info_data->format] * info_data->length;
	value_ptr = safe_emalloc(max(byte_count, 4), 1, 0);
	memset(value_ptr, 0, 4);
	if (!info_data->length) {
		return value_ptr;
	}
	if (info_data->format == TAG_FMT_UNDEFINED || info_data->format == TAG_FMT_STRING
	  || (byte_count>1 && (info_data->format == TAG_FMT_BYTE || info_data->format == TAG_FMT_SBYTE))
	) {
		memmove(value_ptr, info_data->value.s, byte_count);
		return value_ptr;
	} else if (info_data->format == TAG_FMT_BYTE) {
		*value_ptr = info_data->value.u;
		return value_ptr;
	} else if (info_data->format == TAG_FMT_SBYTE) {
		*value_ptr = info_data->value.i;
		return value_ptr;
	} else {
		data_ptr = value_ptr;
		for(i=0; i<info_data->length; i++) {
			if (info_data->length==1) {
				info_value = &info_data->value;
			} else {
				info_value = &info_data->value.list[i];
			}
			switch(info_data->format) {
				case TAG_FMT_USHORT:
					php_ifd_set16u(data_ptr, info_value->u, motorola_intel);
					data_ptr += 2;
					break;
				case TAG_FMT_ULONG:
					php_ifd_set32u(data_ptr, info_value->u, motorola_intel);
					data_ptr += 4;
					break;
				case TAG_FMT_SSHORT:
					php_ifd_set16u(data_ptr, info_value->i, motorola_intel);
					data_ptr += 2;
					break;
				case TAG_FMT_SLONG:
					php_ifd_set32u(data_ptr, info_value->i, motorola_intel);
					data_ptr += 4;
					break;
				case TAG_FMT_URATIONAL:
					php_ifd_set32u(data_ptr,   info_value->sr.num, motorola_intel);
					php_ifd_set32u(data_ptr+4, info_value->sr.den, motorola_intel);
					data_ptr += 8;
					break;
				case TAG_FMT_SRATIONAL:
					php_ifd_set32u(data_ptr,   info_value->ur.num, motorola_intel);
					php_ifd_set32u(data_ptr+4, info_value->ur.den, motorola_intel);
					data_ptr += 8;
					break;
				case TAG_FMT_SINGLE:
					memmove(data_ptr, &info_value->f, 4);
					data_ptr += 4;
					break;
				case TAG_FMT_DOUBLE:
					memmove(data_ptr, &info_value->d, 8);
					data_ptr += 8;
					break;
			}
		}
	}
	return value_ptr;
}

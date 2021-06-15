int jp2_box_put(jp2_box_t *box, jas_stream_t *out)
{
	jas_stream_t *tmpstream;
	bool extlen;
	bool dataflag;

	tmpstream = 0;

	dataflag = !(box->info->flags & (JP2_BOX_SUPER | JP2_BOX_NODATA));

	if (dataflag) {
		if (!(tmpstream = jas_stream_memopen(0, 0))) {
			goto error;
		}
		if (box->ops->putdata) {
			if ((*box->ops->putdata)(box, tmpstream)) {
				goto error;
			}
		}
		box->len = jas_stream_tell(tmpstream) + JP2_BOX_HDRLEN(false);
		jas_stream_rewind(tmpstream);
	}
	extlen = (box->len >= (((uint_fast64_t)1) << 32)) != 0;
	if (jp2_putuint32(out, extlen ? 1 : box->len)) {
		goto error;
	}
	if (jp2_putuint32(out, box->type)) {
		goto error;
	}
	if (extlen) {
		if (jp2_putuint64(out, box->len)) {
			goto error;
		}
	}

	if (dataflag) {
		if (jas_stream_copy(out, tmpstream, box->len - JP2_BOX_HDRLEN(false))) {
			goto error;
		}
		jas_stream_close(tmpstream);
	}

	return 0;

error:

	if (tmpstream) {
		jas_stream_close(tmpstream);
	}
	return -1;
}

int jas_image_readcmpt(jas_image_t *image, int cmptno, jas_image_coord_t x,
  jas_image_coord_t y, jas_image_coord_t width, jas_image_coord_t height,
  jas_matrix_t *data)
{
	jas_image_cmpt_t *cmpt;
	jas_image_coord_t i;
	jas_image_coord_t j;
	int k;
	jas_seqent_t v;
	int c;
	jas_seqent_t *dr;
	jas_seqent_t *d;
	int drs;

	JAS_DBGLOG(100, ("jas_image_readcmpt(%p, %d, %ld, %ld, %ld, %ld, %p)\n",
	  image, cmptno, JAS_CAST(long, x), JAS_CAST(long, y),
	  JAS_CAST(long, width), JAS_CAST(long, height), data));

	if (cmptno < 0 || cmptno >= image->numcmpts_) {
		return -1;
	}

	cmpt = image->cmpts_[cmptno];
	if (x >= cmpt->width_ || y >= cmpt->height_ ||
	  x + width > cmpt->width_ ||
	  y + height > cmpt->height_) {
		return -1;
	}

	if (!jas_matrix_numrows(data) || !jas_matrix_numcols(data)) {
		return -1;
	}

	if (jas_matrix_numrows(data) != height || jas_matrix_numcols(data) != width) {
		if (jas_matrix_resize(data, height, width)) {
			return -1;
		}
	}

	dr = jas_matrix_getref(data, 0, 0);
	drs = jas_matrix_rowstep(data);
	for (i = 0; i < height; ++i, dr += drs) {
		d = dr;
		if (jas_stream_seek(cmpt->stream_, (cmpt->width_ * (y + i) + x)
		  * cmpt->cps_, SEEK_SET) < 0) {
			return -1;
		}
		for (j = width; j > 0; --j, ++d) {
			v = 0;
			for (k = cmpt->cps_; k > 0; --k) {
				if ((c = jas_stream_getc(cmpt->stream_)) == EOF) {
					return -1;
				}
				v = (v << 8) | (c & 0xff);
			}
			*d = bitstoint(v, cmpt->prec_, cmpt->sgnd_);
		}
	}

	return 0;
}

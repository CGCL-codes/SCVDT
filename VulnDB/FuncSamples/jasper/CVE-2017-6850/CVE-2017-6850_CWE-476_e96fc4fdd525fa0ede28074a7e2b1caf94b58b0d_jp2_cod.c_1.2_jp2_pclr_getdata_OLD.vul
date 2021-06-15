static int jp2_pclr_getdata(jp2_box_t *box, jas_stream_t *in)
{
	jp2_pclr_t *pclr = &box->data.pclr;
	int lutsize;
	unsigned int i;
	unsigned int j;
	int_fast32_t x;

	pclr->lutdata = 0;

	if (jp2_getuint16(in, &pclr->numlutents) ||
	  jp2_getuint8(in, &pclr->numchans)) {
		return -1;
	}
	lutsize = pclr->numlutents * pclr->numchans;
	if (!(pclr->lutdata = jas_alloc2(lutsize, sizeof(int_fast32_t)))) {
		return -1;
	}
	if (!(pclr->bpc = jas_alloc2(pclr->numchans, sizeof(uint_fast8_t)))) {
		return -1;
	}
	for (i = 0; i < pclr->numchans; ++i) {
		if (jp2_getuint8(in, &pclr->bpc[i])) {
			return -1;
		}
	}
	for (i = 0; i < pclr->numlutents; ++i) {
		for (j = 0; j < pclr->numchans; ++j) {
			if (jp2_getint(in, (pclr->bpc[j] & 0x80) != 0,
			  (pclr->bpc[j] & 0x7f) + 1, &x)) {
				return -1;
			}
			pclr->lutdata[i * pclr->numchans + j] = x;
		}
	}
	return 0;
}

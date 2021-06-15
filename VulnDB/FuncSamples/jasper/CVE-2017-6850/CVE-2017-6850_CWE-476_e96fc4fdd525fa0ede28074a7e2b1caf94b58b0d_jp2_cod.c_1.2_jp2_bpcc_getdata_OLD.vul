static int jp2_bpcc_getdata(jp2_box_t *box, jas_stream_t *in)
{
	jp2_bpcc_t *bpcc = &box->data.bpcc;
	unsigned int i;
	bpcc->numcmpts = box->datalen;
	if (!(bpcc->bpcs = jas_alloc2(bpcc->numcmpts, sizeof(uint_fast8_t)))) {
		return -1;
	}
	for (i = 0; i < bpcc->numcmpts; ++i) {
		if (jp2_getuint8(in, &bpcc->bpcs[i])) {
			return -1;
		}
	}
	return 0;
}

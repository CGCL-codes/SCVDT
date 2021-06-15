static int jp2_cdef_getdata(jp2_box_t *box, jas_stream_t *in)
{
	jp2_cdef_t *cdef = &box->data.cdef;
	jp2_cdefchan_t *chan;
	unsigned int channo;
	if (jp2_getuint16(in, &cdef->numchans)) {
		return -1;
	}
	if (!(cdef->ents = jas_alloc2(cdef->numchans, sizeof(jp2_cdefchan_t)))) {
		return -1;
	}
	for (channo = 0; channo < cdef->numchans; ++channo) {
		chan = &cdef->ents[channo];
		if (jp2_getuint16(in, &chan->channo) || jp2_getuint16(in, &chan->type) ||
		  jp2_getuint16(in, &chan->assoc)) {
			return -1;
		}
	}
	return 0;
}

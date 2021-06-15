static int jp2_cmap_getdata(jp2_box_t *box, jas_stream_t *in)
{
	jp2_cmap_t *cmap = &box->data.cmap;
	jp2_cmapent_t *ent;
	unsigned int i;

	cmap->numchans = (box->datalen) / 4;
	if (!(cmap->ents = jas_alloc2(cmap->numchans, sizeof(jp2_cmapent_t)))) {
		return -1;
	}
	for (i = 0; i < cmap->numchans; ++i) {
		ent = &cmap->ents[i];
		if (jp2_getuint16(in, &ent->cmptno) ||
		  jp2_getuint8(in, &ent->map) ||
		  jp2_getuint8(in, &ent->pcol)) {
			return -1;
		}
	}
	
	return 0;
}

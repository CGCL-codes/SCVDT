static int jpc_siz_getparms(jpc_ms_t *ms, jpc_cstate_t *cstate,
  jas_stream_t *in)
{
	jpc_siz_t *siz = &ms->parms.siz;
	unsigned int i;
	uint_fast8_t tmp;

	siz->comps = 0;

	/* Eliminate compiler warning about unused variables. */
	cstate = 0;

	if (jpc_getuint16(in, &siz->caps) ||
	  jpc_getuint32(in, &siz->width) ||
	  jpc_getuint32(in, &siz->height) ||
	  jpc_getuint32(in, &siz->xoff) ||
	  jpc_getuint32(in, &siz->yoff) ||
	  jpc_getuint32(in, &siz->tilewidth) ||
	  jpc_getuint32(in, &siz->tileheight) ||
	  jpc_getuint32(in, &siz->tilexoff) ||
	  jpc_getuint32(in, &siz->tileyoff) ||
	  jpc_getuint16(in, &siz->numcomps)) {
		goto error;
	}
	if (!siz->width || !siz->height) {
		jas_eprintf("reference grid cannot have zero area\n");
		goto error;
	}
	if (!siz->tilewidth || !siz->tileheight) {
		jas_eprintf("tile cannot have zero area\n");
		goto error;
	}
	if (!siz->numcomps || siz->numcomps > 16384) {
		jas_eprintf("number of components not in permissible range\n");
		goto error;
	}
	if (siz->xoff >= siz->width) {
		jas_eprintf("XOsiz not in permissible range\n");
		goto error;
	}
	if (siz->yoff >= siz->height) {
		jas_eprintf("YOsiz not in permissible range\n");
		goto error;
	}
	if (siz->tilexoff > siz->xoff || siz->tilexoff + siz->tilewidth <= siz->xoff) {
		jas_eprintf("XTOsiz not in permissible range\n");
		goto error;
	}
	if (siz->tileyoff > siz->yoff || siz->tileyoff + siz->tileheight <= siz->yoff) {
		jas_eprintf("YTOsiz not in permissible range\n");
		goto error;
	}

	if (!(siz->comps = jas_alloc2(siz->numcomps, sizeof(jpc_sizcomp_t)))) {
		goto error;
	}
	for (i = 0; i < siz->numcomps; ++i) {
		if (jpc_getuint8(in, &tmp) ||
		  jpc_getuint8(in, &siz->comps[i].hsamp) ||
		  jpc_getuint8(in, &siz->comps[i].vsamp)) {
			goto error;
		}
		if (siz->comps[i].hsamp == 0 || siz->comps[i].hsamp > 255) {
			jas_eprintf("invalid XRsiz value %d\n", siz->comps[i].hsamp);
			goto error;
		}
		if (siz->comps[i].vsamp == 0 || siz->comps[i].vsamp > 255) {
			jas_eprintf("invalid YRsiz value %d\n", siz->comps[i].vsamp);
			goto error;
		}
		siz->comps[i].sgnd = (tmp >> 7) & 1;
		siz->comps[i].prec = (tmp & 0x7f) + 1;
	}
	if (jas_stream_eof(in)) {
		goto error;
	}
	return 0;

error:
	if (siz->comps) {
		jas_free(siz->comps);
	}
	return -1;
}

static int jas_icctxtdesc_input(jas_iccattrval_t *attrval, jas_stream_t *in,
  int cnt)
{
	int n;
	int c;
	jas_icctxtdesc_t *txtdesc = &attrval->data.txtdesc;
	txtdesc->ascdata = 0;
	txtdesc->ucdata = 0;
	if (jas_iccgetuint32(in, &txtdesc->asclen))
		goto error;
	if (!(txtdesc->ascdata = jas_malloc(txtdesc->asclen)))
		goto error;
	if (jas_stream_read(in, txtdesc->ascdata, txtdesc->asclen) !=
	  JAS_CAST(int, txtdesc->asclen))
		goto error;
	txtdesc->ascdata[txtdesc->asclen - 1] = '\0';
	if (jas_iccgetuint32(in, &txtdesc->uclangcode) ||
	  jas_iccgetuint32(in, &txtdesc->uclen))
		goto error;
	if (!(txtdesc->ucdata = jas_alloc2(txtdesc->uclen, 2)))
		goto error;
	if (jas_stream_read(in, txtdesc->ucdata, txtdesc->uclen * 2) !=
	  JAS_CAST(int, txtdesc->uclen * 2))
		goto error;
	if (jas_iccgetuint16(in, &txtdesc->sccode))
		goto error;
	if ((c = jas_stream_getc(in)) == EOF)
		goto error;
	txtdesc->maclen = c;
	if (jas_stream_read(in, txtdesc->macdata, 67) != 67)
		goto error;
	txtdesc->asclen = JAS_CAST(jas_iccuint32_t, strlen(txtdesc->ascdata) + 1);
#define WORKAROUND_BAD_PROFILES
#ifdef WORKAROUND_BAD_PROFILES
	n = txtdesc->asclen + txtdesc->uclen * 2 + 15 + 67;
	if (n > cnt) {
		return -1;
	}
	if (n < cnt) {
		if (jas_stream_gobble(in, cnt - n) != cnt - n)
			goto error;
	}
#else
	if (txtdesc->asclen + txtdesc->uclen * 2 + 15 + 67 != cnt)
		return -1;
#endif
	return 0;
error:
	jas_icctxtdesc_destroy(attrval);
	return -1;
}

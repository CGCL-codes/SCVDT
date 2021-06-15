static int jas_icctxt_input(jas_iccattrval_t *attrval, jas_stream_t *in,
  int cnt)
{
	jas_icctxt_t *txt = &attrval->data.txt;
	txt->string = 0;
	if (!(txt->string = jas_malloc(cnt)))
		goto error;
	if (jas_stream_read(in, txt->string, cnt) != cnt)
		goto error;
	txt->string[cnt - 1] = '\0';
	if (JAS_CAST(int, strlen(txt->string)) + 1 != cnt)
		goto error;
	return 0;
error:
	jas_icctxt_destroy(attrval);
	return -1;
}

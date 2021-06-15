static void jas_icctxt_destroy(jas_iccattrval_t *attrval)
{
	jas_icctxt_t *txt = &attrval->data.txt;
	if (txt->string) {
		jas_free(txt->string);
		txt->string = 0;
	}
}

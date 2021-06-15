static void jas_icctxtdesc_destroy(jas_iccattrval_t *attrval)
{
	jas_icctxtdesc_t *txtdesc = &attrval->data.txtdesc;
	if (txtdesc->ascdata) {
		jas_free(txtdesc->ascdata);
		txtdesc->ascdata = 0;
	}
	if (txtdesc->ucdata) {
		jas_free(txtdesc->ucdata);
		txtdesc->ucdata = 0;
	}
}

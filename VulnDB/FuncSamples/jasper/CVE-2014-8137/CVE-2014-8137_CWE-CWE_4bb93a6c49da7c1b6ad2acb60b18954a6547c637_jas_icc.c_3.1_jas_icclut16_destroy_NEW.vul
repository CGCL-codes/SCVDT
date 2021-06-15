static void jas_icclut16_destroy(jas_iccattrval_t *attrval)
{
	jas_icclut16_t *lut16 = &attrval->data.lut16;
	if (lut16->clut) {
		jas_free(lut16->clut);
		lut16->clut = 0;
	}
	if (lut16->intabs) {
		jas_free(lut16->intabs);
		lut16->intabs = 0;
	}
	if (lut16->intabsbuf) {
		jas_free(lut16->intabsbuf);
		lut16->intabsbuf = 0;
	}
	if (lut16->outtabs) {
		jas_free(lut16->outtabs);
		lut16->outtabs = 0;
	}
	if (lut16->outtabsbuf) {
		jas_free(lut16->outtabsbuf);
		lut16->outtabsbuf = 0;
	}
}

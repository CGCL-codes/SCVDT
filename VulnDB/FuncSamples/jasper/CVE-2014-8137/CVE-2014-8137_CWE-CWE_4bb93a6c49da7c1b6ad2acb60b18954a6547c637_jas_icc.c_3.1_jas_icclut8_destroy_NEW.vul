static void jas_icclut8_destroy(jas_iccattrval_t *attrval)
{
	jas_icclut8_t *lut8 = &attrval->data.lut8;
	if (lut8->clut) {
		jas_free(lut8->clut);
		lut8->clut = 0;
	}
	if (lut8->intabs) {
		jas_free(lut8->intabs);
		lut8->intabs = 0;
	}
	if (lut8->intabsbuf) {
		jas_free(lut8->intabsbuf);
		lut8->intabsbuf = 0;
	}
	if (lut8->outtabs) {
		jas_free(lut8->outtabs);
		lut8->outtabs = 0;
	}
	if (lut8->outtabsbuf) {
		jas_free(lut8->outtabsbuf);
		lut8->outtabsbuf = 0;
	}
}

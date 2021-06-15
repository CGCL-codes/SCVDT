static void jas_icccurv_destroy(jas_iccattrval_t *attrval)
{
	jas_icccurv_t *curv = &attrval->data.curv;
	if (curv->ents) {
		jas_free(curv->ents);
		curv->ents = 0;
	}
}

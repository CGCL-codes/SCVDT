static void jpc_dec_destroy(jpc_dec_t *dec)
{
	if (dec->cstate) {
		jpc_cstate_destroy(dec->cstate);
	}
	if (dec->pkthdrstreams) {
		jpc_streamlist_destroy(dec->pkthdrstreams);
	}
	if (dec->image) {
		jas_image_destroy(dec->image);
	}

	if (dec->cp) {
		jpc_dec_cp_destroy(dec->cp);
	}

	if (dec->cmpts) {
		jas_free(dec->cmpts);
	}

	if (dec->tiles) {
		jas_free(dec->tiles);
	}

	jas_free(dec);
}

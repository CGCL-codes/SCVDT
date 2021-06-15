static int jpc_dec_process_rgn(jpc_dec_t *dec, jpc_ms_t *ms)
{
	jpc_rgn_t *rgn = &ms->parms.rgn;
	jpc_dec_tile_t *tile;

	if (JAS_CAST(int, rgn->compno) >= dec->numcomps) {
		jas_eprintf("invalid component number in RGN marker segment\n");
		return -1;
	}
	switch (dec->state) {
	case JPC_MH:
		jpc_dec_cp_setfromrgn(dec->cp, rgn);
		break;
	case JPC_TPH:
		if (!(tile = dec->curtile)) {
			return -1;
		}
		if (tile->partno > 0) {
			return -1;
		}
		jpc_dec_cp_setfromrgn(tile->cp, rgn);
		break;
	}

	return 0;
}

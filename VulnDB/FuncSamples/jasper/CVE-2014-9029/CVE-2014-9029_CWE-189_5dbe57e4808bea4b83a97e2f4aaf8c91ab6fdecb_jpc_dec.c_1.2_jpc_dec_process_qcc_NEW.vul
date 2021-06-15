static int jpc_dec_process_qcc(jpc_dec_t *dec, jpc_ms_t *ms)
{
	jpc_qcc_t *qcc = &ms->parms.qcc;
	jpc_dec_tile_t *tile;

	if (JAS_CAST(int, qcc->compno) >= dec->numcomps) {
		jas_eprintf("invalid component number in QCC marker segment\n");
		return -1;
	}
	switch (dec->state) {
	case JPC_MH:
		jpc_dec_cp_setfromqcc(dec->cp, qcc);
		break;
	case JPC_TPH:
		if (!(tile = dec->curtile)) {
			return -1;
		}
		if (tile->partno > 0) {
			return -1;
		}
		jpc_dec_cp_setfromqcc(tile->cp, qcc);
		break;
	}
	return 0;
}

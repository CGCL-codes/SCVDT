static int jpc_dec_tiledecode(jpc_dec_t *dec, jpc_dec_tile_t *tile)
{
	int i;
	int j;
	jpc_dec_tcomp_t *tcomp;
	jpc_dec_rlvl_t *rlvl;
	jpc_dec_band_t *band;
	int compno;
	int rlvlno;
	int bandno;
	int adjust;
	int v;
	jpc_dec_ccp_t *ccp;
	jpc_dec_cmpt_t *cmpt;

	if (jpc_dec_decodecblks(dec, tile)) {
		jas_eprintf("jpc_dec_decodecblks failed\n");
		return -1;
	}

	/* Perform dequantization. */
	for (compno = 0, tcomp = tile->tcomps; compno < dec->numcomps;
	  ++compno, ++tcomp) {
		ccp = &tile->cp->ccps[compno];
		for (rlvlno = 0, rlvl = tcomp->rlvls; rlvlno < tcomp->numrlvls;
		  ++rlvlno, ++rlvl) {
			if (!rlvl->bands) {
				continue;
			}
			for (bandno = 0, band = rlvl->bands;
			  bandno < rlvl->numbands; ++bandno, ++band) {
				if (!band->data) {
					continue;
				}
				jpc_undo_roi(band->data, band->roishift, ccp->roishift -
				  band->roishift, band->numbps);
				if (tile->realmode) {
					jas_matrix_asl(band->data, JPC_FIX_FRACBITS);
					jpc_dequantize(band->data, band->absstepsize);
				}

			}
		}
	}

	/* Apply an inverse wavelet transform if necessary. */
	for (compno = 0, tcomp = tile->tcomps; compno < dec->numcomps;
	  ++compno, ++tcomp) {
		ccp = &tile->cp->ccps[compno];
		jpc_tsfb_synthesize(tcomp->tsfb, tcomp->data);
	}


	/* Apply an inverse intercomponent transform if necessary. */
	switch (tile->cp->mctid) {
	case JPC_MCT_RCT:
		if (dec->numcomps < 3) {
			jas_eprintf("RCT requires at least three components\n");
			return -1;
		}
		if (!jas_image_cmpt_domains_same(dec->image)) {
			jas_eprintf("RCT requires all components have the same domain\n");
			return -1;
		}
		jpc_irct(tile->tcomps[0].data, tile->tcomps[1].data,
		  tile->tcomps[2].data);
		break;
	case JPC_MCT_ICT:
		if (dec->numcomps < 3) {
			jas_eprintf("ICT requires at least three components\n");
			return -1;
		}
		if (!jas_image_cmpt_domains_same(dec->image)) {
			jas_eprintf("RCT requires all components have the same domain\n");
			return -1;
		}
		jpc_iict(tile->tcomps[0].data, tile->tcomps[1].data,
		  tile->tcomps[2].data);
		break;
	}

	/* Perform rounding and convert to integer values. */
	if (tile->realmode) {
		for (compno = 0, tcomp = tile->tcomps; compno < dec->numcomps;
		  ++compno, ++tcomp) {
			for (i = 0; i < jas_matrix_numrows(tcomp->data); ++i) {
				for (j = 0; j < jas_matrix_numcols(tcomp->data); ++j) {
					v = jas_matrix_get(tcomp->data, i, j);
					v = jpc_fix_round(v);
					jas_matrix_set(tcomp->data, i, j, jpc_fixtoint(v));
				}
			}
		}
	}

	/* Perform level shift. */
	for (compno = 0, tcomp = tile->tcomps, cmpt = dec->cmpts; compno <
	  dec->numcomps; ++compno, ++tcomp, ++cmpt) {
		adjust = cmpt->sgnd ? 0 : (1 << (cmpt->prec - 1));
		for (i = 0; i < jas_matrix_numrows(tcomp->data); ++i) {
			for (j = 0; j < jas_matrix_numcols(tcomp->data); ++j) {
				*jas_matrix_getref(tcomp->data, i, j) += adjust;
			}
		}
	}

	/* Perform clipping. */
	for (compno = 0, tcomp = tile->tcomps, cmpt = dec->cmpts; compno <
	  dec->numcomps; ++compno, ++tcomp, ++cmpt) {
		jpc_fix_t mn;
		jpc_fix_t mx;
		mn = cmpt->sgnd ? (-(1 << (cmpt->prec - 1))) : (0);
		mx = cmpt->sgnd ? ((1 << (cmpt->prec - 1)) - 1) : ((1 <<
		  cmpt->prec) - 1);
		jas_matrix_clip(tcomp->data, mn, mx);
	}

	/* XXX need to free tsfb struct */

	/* Write the data for each component of the image. */
	for (compno = 0, tcomp = tile->tcomps, cmpt = dec->cmpts; compno <
	  dec->numcomps; ++compno, ++tcomp, ++cmpt) {
		if (jas_image_writecmpt(dec->image, compno, tcomp->xstart -
		  JPC_CEILDIV(dec->xstart, cmpt->hstep), tcomp->ystart -
		  JPC_CEILDIV(dec->ystart, cmpt->vstep), jas_matrix_numcols(
		  tcomp->data), jas_matrix_numrows(tcomp->data), tcomp->data)) {
			jas_eprintf("write component failed\n");
			return -1;
		}
	}

	return 0;
}

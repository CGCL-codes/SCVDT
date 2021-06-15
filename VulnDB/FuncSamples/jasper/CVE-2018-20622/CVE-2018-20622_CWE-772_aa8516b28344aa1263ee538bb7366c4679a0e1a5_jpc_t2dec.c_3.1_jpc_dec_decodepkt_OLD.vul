static int jpc_dec_decodepkt(jpc_dec_t *dec, jas_stream_t *pkthdrstream, jas_stream_t *in, int compno, int rlvlno,
  int prcno, int lyrno)
{
	jpc_bitstream_t *inb;
	jpc_dec_tcomp_t *tcomp;
	jpc_dec_rlvl_t *rlvl;
	jpc_dec_band_t *band;
	jpc_dec_cblk_t *cblk;
	int n;
	int m;
	int i;
	jpc_tagtreenode_t *leaf;
	int included;
	int ret;
	int numnewpasses;
	jpc_dec_seg_t *seg;
	int len;
	int present;
	int savenumnewpasses;
	int mycounter;
	jpc_ms_t *ms;
	jpc_dec_tile_t *tile;
	jpc_dec_ccp_t *ccp;
	jpc_dec_cp_t *cp;
	int bandno;
	jpc_dec_prc_t *prc;
	int usedcblkcnt;
	int cblkno;
	uint_fast32_t bodylen;
	bool discard;
	int passno;
	int maxpasses;
	int hdrlen;
	int hdroffstart;
	int hdroffend;

	/* Avoid compiler warning about possible use of uninitialized
	  variable. */
	bodylen = 0;

	discard = (lyrno >= dec->maxlyrs);

	tile = dec->curtile;
	cp = tile->cp;
	ccp = &cp->ccps[compno];

	/*
	 * Decode the packet header.
	 */

	/* Decode the SOP marker segment if present. */
	if (cp->csty & JPC_COD_SOP) {
		if (jpc_dec_lookahead(in) == JPC_MS_SOP) {
			if (!(ms = jpc_getms(in, dec->cstate))) {
				return -1;
			}
			if (jpc_ms_gettype(ms) != JPC_MS_SOP) {
				jpc_ms_destroy(ms);
				jas_eprintf("missing SOP marker segment\n");
				return -1;
			}
			jpc_ms_destroy(ms);
		}
	}

hdroffstart = jas_stream_getrwcount(pkthdrstream);

	if (!(inb = jpc_bitstream_sopen(pkthdrstream, "r"))) {
		return -1;
	}

	if ((present = jpc_bitstream_getbit(inb)) < 0) {
		return 1;
	}
	JAS_DBGLOG(10, ("\n", present));
	JAS_DBGLOG(10, ("present=%d ", present));

	/* Is the packet non-empty? */
	if (present) {
		/* The packet is non-empty. */
		tcomp = &tile->tcomps[compno];
		rlvl = &tcomp->rlvls[rlvlno];
		bodylen = 0;
		for (bandno = 0, band = rlvl->bands; bandno < rlvl->numbands;
		  ++bandno, ++band) {
			if (!band->data) {
				continue;
			}
			prc = &band->prcs[prcno];
			if (!prc->cblks) {
				continue;
			}
			usedcblkcnt = 0;
			for (cblkno = 0, cblk = prc->cblks; cblkno < prc->numcblks;
			  ++cblkno, ++cblk) {
				++usedcblkcnt;
				if (!cblk->numpasses) {
					leaf = jpc_tagtree_getleaf(prc->incltagtree, usedcblkcnt - 1);
					if ((included = jpc_tagtree_decode(prc->incltagtree, leaf, lyrno + 1, inb)) < 0) {
						return -1;
					}
				} else {
					if ((included = jpc_bitstream_getbit(inb)) < 0) {
						return -1;
					}
				}
				JAS_DBGLOG(10, ("\n"));
				JAS_DBGLOG(10, ("included=%d ", included));
				if (!included) {
					continue;
				}
				if (!cblk->numpasses) {
					i = 1;
					leaf = jpc_tagtree_getleaf(prc->numimsbstagtree, usedcblkcnt - 1);
					for (;;) {
						if ((ret = jpc_tagtree_decode(prc->numimsbstagtree, leaf, i, inb)) < 0) {
							return -1;
						}
						if (ret) {
							break;
						}
						++i;
					}
					cblk->numimsbs = i - 1;
					cblk->firstpassno = cblk->numimsbs * 3;
				}
				if ((numnewpasses = jpc_getnumnewpasses(inb)) < 0) {
					return -1;
				}
				JAS_DBGLOG(10, ("numnewpasses=%d ", numnewpasses));
				seg = cblk->curseg;
				savenumnewpasses = numnewpasses;
				mycounter = 0;
				if (numnewpasses > 0) {
					if ((m = jpc_getcommacode(inb)) < 0) {
						return -1;
					}
					cblk->numlenbits += m;
					JAS_DBGLOG(10, ("increment=%d ", m));
					while (numnewpasses > 0) {
						passno = cblk->firstpassno + cblk->numpasses + mycounter;
	/* XXX - the maxpasses is not set precisely but this doesn't matter... */
						maxpasses = JPC_SEGPASSCNT(passno, cblk->firstpassno, 10000, (ccp->cblkctx & JPC_COX_LAZY) != 0, (ccp->cblkctx & JPC_COX_TERMALL) != 0);
						if (!discard && !seg) {
							if (!(seg = jpc_seg_alloc())) {
								return -1;
							}
							jpc_seglist_insert(&cblk->segs, cblk->segs.tail, seg);
							if (!cblk->curseg) {
								cblk->curseg = seg;
							}
							seg->passno = passno;
							seg->type = JPC_SEGTYPE(seg->passno, cblk->firstpassno, (ccp->cblkctx & JPC_COX_LAZY) != 0);
							seg->maxpasses = maxpasses;
						}
						n = JAS_MIN(numnewpasses, maxpasses);
						mycounter += n;
						numnewpasses -= n;
						if ((len = jpc_bitstream_getbits(inb, cblk->numlenbits + jpc_floorlog2(n))) < 0) {
							return -1;
						}
						JAS_DBGLOG(10, ("len=%d ", len));
						if (!discard) {
							seg->lyrno = lyrno;
							seg->numpasses += n;
							seg->cnt = len;
							seg = seg->next;
						}
						bodylen += len;
					}
				}
				cblk->numpasses += savenumnewpasses;
			}
		}

		jpc_bitstream_inalign(inb, 0, 0);

	} else {
		if (jpc_bitstream_inalign(inb, 0x7f, 0)) {
			jas_eprintf("alignment failed\n");
			return -1;
		}
	}
	jpc_bitstream_close(inb);

	hdroffend = jas_stream_getrwcount(pkthdrstream);
	hdrlen = hdroffend - hdroffstart;
	if (jas_getdbglevel() >= 5) {
		jas_eprintf("hdrlen=%lu bodylen=%lu \n", (unsigned long) hdrlen,
		  (unsigned long) bodylen);
	}

	if (cp->csty & JPC_COD_EPH) {
		if (jpc_dec_lookahead(pkthdrstream) == JPC_MS_EPH) {
			if (!(ms = jpc_getms(pkthdrstream, dec->cstate))) {
				jas_eprintf("cannot get (EPH) marker segment\n");
				return -1;
			}
			if (jpc_ms_gettype(ms) != JPC_MS_EPH) {
				jpc_ms_destroy(ms);
				jas_eprintf("missing EPH marker segment\n");
				return -1;
			}
			jpc_ms_destroy(ms);
		}
	}

	/* decode the packet body. */

	if (jas_getdbglevel() >= 1) {
		jas_eprintf("packet body offset=%06ld\n", (long) jas_stream_getrwcount(in));
	}

	if (!discard) {
		tcomp = &tile->tcomps[compno];
		rlvl = &tcomp->rlvls[rlvlno];
		for (bandno = 0, band = rlvl->bands; bandno < rlvl->numbands;
		  ++bandno, ++band) {
			if (!band->data) {
				continue;
			}
			prc = &band->prcs[prcno];
			if (!prc->cblks) {
				continue;
			}
			for (cblkno = 0, cblk = prc->cblks; cblkno < prc->numcblks;
			  ++cblkno, ++cblk) {
				seg = cblk->curseg;
				while (seg) {
					if (!seg->stream) {
						if (!(seg->stream = jas_stream_memopen(0, 0))) {
							return -1;
						}
					}
#if 0
jas_eprintf("lyrno=%02d, compno=%02d, lvlno=%02d, prcno=%02d, bandno=%02d, cblkno=%02d, passno=%02d numpasses=%02d cnt=%d numbps=%d, numimsbs=%d\n", lyrno, compno, rlvlno, prcno, band - rlvl->bands, cblk - prc->cblks, seg->passno, seg->numpasses, seg->cnt, band->numbps, cblk->numimsbs);
#endif
					if (seg->cnt > 0) {
						if (jpc_getdata(in, seg->stream, seg->cnt) < 0) {
							return -1;
						}
						seg->cnt = 0;
					}
					if (seg->numpasses >= seg->maxpasses) {
						cblk->curseg = seg->next;
					}
					seg = seg->next;
				}
			}
		}
	} else {
		if (jas_stream_gobble(in, bodylen) != JAS_CAST(int, bodylen)) {
			return -1;
		}
	}
	return 0;
}

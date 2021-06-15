static int jpc_pi_nextrpcl(register jpc_pi_t *pi)
{
	int rlvlno;
	jpc_pirlvl_t *pirlvl;
	jpc_pchg_t *pchg;
	int prchind;
	int prcvind;
	int *prclyrno;
	int compno;
	jpc_picomp_t *picomp;
	int xstep;
	int ystep;
	uint_fast32_t r;
	uint_fast32_t rpx;
	uint_fast32_t rpy;
	uint_fast32_t trx0;
	uint_fast32_t try0;

	pchg = pi->pchg;
	if (!pi->prgvolfirst) {
		goto skip;
	} else {
		pi->xstep = 0;
		pi->ystep = 0;
		for (compno = 0, picomp = pi->picomps; compno < pi->numcomps;
		  ++compno, ++picomp) {
			for (rlvlno = 0, pirlvl = picomp->pirlvls; rlvlno <
			  picomp->numrlvls; ++rlvlno, ++pirlvl) {
				xstep = picomp->hsamp * (1 << (pirlvl->prcwidthexpn +
				  picomp->numrlvls - rlvlno - 1));
				ystep = picomp->vsamp * (1 << (pirlvl->prcheightexpn +
				  picomp->numrlvls - rlvlno - 1));
				pi->xstep = (!pi->xstep) ? xstep : JAS_MIN(pi->xstep, xstep);
				pi->ystep = (!pi->ystep) ? ystep : JAS_MIN(pi->ystep, ystep);
			}
		}
		pi->prgvolfirst = 0;
	}

	for (pi->rlvlno = pchg->rlvlnostart; pi->rlvlno < pchg->rlvlnoend &&
	  pi->rlvlno < pi->maxrlvls; ++pi->rlvlno) {
		for (pi->y = pi->ystart; pi->y < pi->yend; pi->y +=
		  pi->ystep - (pi->y % pi->ystep)) {
			for (pi->x = pi->xstart; pi->x < pi->xend; pi->x +=
			  pi->xstep - (pi->x % pi->xstep)) {
				for (pi->compno = pchg->compnostart,
				  pi->picomp = &pi->picomps[pi->compno];
				  pi->compno < JAS_CAST(int, pchg->compnoend) && pi->compno <
				  pi->numcomps; ++pi->compno, ++pi->picomp) {
					if (pi->rlvlno >= pi->picomp->numrlvls) {
						continue;
					}
					pi->pirlvl = &pi->picomp->pirlvls[pi->rlvlno];
					if (pi->pirlvl->numprcs == 0) {
						continue;
					}
					r = pi->picomp->numrlvls - 1 - pi->rlvlno;
					rpx = r + pi->pirlvl->prcwidthexpn;
					rpy = r + pi->pirlvl->prcheightexpn;
					trx0 = JPC_CEILDIV(pi->xstart, pi->picomp->hsamp << r);
					try0 = JPC_CEILDIV(pi->ystart, pi->picomp->vsamp << r);
					if (((pi->x == pi->xstart && ((trx0 << r) % (1 << rpx)))
					  || !(pi->x % (1 << rpx))) &&
					  ((pi->y == pi->ystart && ((try0 << r) % (1 << rpy)))
					  || !(pi->y % (1 << rpy)))) {
						prchind = JPC_FLOORDIVPOW2(JPC_CEILDIV(pi->x, pi->picomp->hsamp
						  << r), pi->pirlvl->prcwidthexpn) - JPC_FLOORDIVPOW2(trx0,
						  pi->pirlvl->prcwidthexpn);
						prcvind = JPC_FLOORDIVPOW2(JPC_CEILDIV(pi->y, pi->picomp->vsamp
						  << r), pi->pirlvl->prcheightexpn) - JPC_FLOORDIVPOW2(try0,
						  pi->pirlvl->prcheightexpn);
						pi->prcno = prcvind * pi->pirlvl->numhprcs + prchind;

						assert(pi->prcno < pi->pirlvl->numprcs);
						for (pi->lyrno = 0; pi->lyrno <
						  pi->numlyrs && pi->lyrno < JAS_CAST(int, pchg->lyrnoend); ++pi->lyrno) {
							prclyrno = &pi->pirlvl->prclyrnos[pi->prcno];
							if (pi->lyrno >= *prclyrno) {
								++(*prclyrno);
								return 0;
							}
skip:
							;
						}
					}
				}
			}
		}
	}
	return 1;
}

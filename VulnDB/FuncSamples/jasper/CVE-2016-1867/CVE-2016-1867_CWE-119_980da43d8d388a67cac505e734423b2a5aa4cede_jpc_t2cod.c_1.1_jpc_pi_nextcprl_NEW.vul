static int jpc_pi_nextcprl(register jpc_pi_t *pi)
{
	int rlvlno;
	jpc_pirlvl_t *pirlvl;
	jpc_pchg_t *pchg;
	int prchind;
	int prcvind;
	int *prclyrno;
	uint_fast32_t trx0;
	uint_fast32_t try0;
	uint_fast32_t r;
	uint_fast32_t rpx;
	uint_fast32_t rpy;

	pchg = pi->pchg;
	if (!pi->prgvolfirst) {
		goto skip;
	} else {
		pi->prgvolfirst = 0;
	}

	for (pi->compno = pchg->compnostart, pi->picomp =
	  &pi->picomps[pi->compno]; pi->compno < JAS_CAST(int, pchg->compnoend) && pi->compno < pi->numcomps; ++pi->compno,
	  ++pi->picomp) {
		pirlvl = pi->picomp->pirlvls;
		pi->xstep = pi->picomp->hsamp * (1 << (pirlvl->prcwidthexpn +
		  pi->picomp->numrlvls - 1));
		pi->ystep = pi->picomp->vsamp * (1 << (pirlvl->prcheightexpn +
		  pi->picomp->numrlvls - 1));
		for (rlvlno = 1, pirlvl = &pi->picomp->pirlvls[1];
		  rlvlno < pi->picomp->numrlvls; ++rlvlno, ++pirlvl) {
			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp * (1 <<
			  (pirlvl->prcwidthexpn + pi->picomp->numrlvls -
			  rlvlno - 1)));
			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp * (1 <<
			  (pirlvl->prcheightexpn + pi->picomp->numrlvls -
			  rlvlno - 1)));
		}
		for (pi->y = pi->ystart; pi->y < pi->yend;
		  pi->y += pi->ystep - (pi->y % pi->ystep)) {
			for (pi->x = pi->xstart; pi->x < pi->xend;
			  pi->x += pi->xstep - (pi->x % pi->xstep)) {
				for (pi->rlvlno = pchg->rlvlnostart,
				  pi->pirlvl = &pi->picomp->pirlvls[pi->rlvlno];
				  pi->rlvlno < pi->picomp->numrlvls && pi->rlvlno <
				  pchg->rlvlnoend; ++pi->rlvlno, ++pi->pirlvl) {
					if (pi->pirlvl->numprcs == 0) {
						continue;
					}
					r = pi->picomp->numrlvls - 1 - pi->rlvlno;
					trx0 = JPC_CEILDIV(pi->xstart, pi->picomp->hsamp << r);
					try0 = JPC_CEILDIV(pi->ystart, pi->picomp->vsamp << r);
					rpx = r + pi->pirlvl->prcwidthexpn;
					rpy = r + pi->pirlvl->prcheightexpn;
					if (((pi->x == pi->xstart && ((trx0 << r) % (1 << rpx))) ||
					  !(pi->x % (pi->picomp->hsamp << rpx))) &&
					  ((pi->y == pi->ystart && ((try0 << r) % (1 << rpy))) ||
					  !(pi->y % (pi->picomp->vsamp << rpy)))) {
						prchind = JPC_FLOORDIVPOW2(JPC_CEILDIV(pi->x, pi->picomp->hsamp
						  << r), pi->pirlvl->prcwidthexpn) - JPC_FLOORDIVPOW2(trx0,
						  pi->pirlvl->prcwidthexpn);
						prcvind = JPC_FLOORDIVPOW2(JPC_CEILDIV(pi->y, pi->picomp->vsamp
						  << r), pi->pirlvl->prcheightexpn) - JPC_FLOORDIVPOW2(try0,
						  pi->pirlvl->prcheightexpn);
						pi->prcno = prcvind *
						  pi->pirlvl->numhprcs +
						  prchind;
						assert(pi->prcno <
						  pi->pirlvl->numprcs);
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

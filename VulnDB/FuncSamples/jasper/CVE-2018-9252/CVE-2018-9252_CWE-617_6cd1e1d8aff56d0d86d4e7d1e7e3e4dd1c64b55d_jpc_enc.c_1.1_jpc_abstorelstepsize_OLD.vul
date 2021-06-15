static uint_fast32_t jpc_abstorelstepsize(jpc_fix_t absdelta, int scaleexpn)
{
	int p;
	uint_fast32_t mant;
	uint_fast32_t expn;
	int n;

	if (absdelta < 0) {
		abort();
	}

	p = jpc_fix_firstone(absdelta) - JPC_FIX_FRACBITS;
	n = 11 - jpc_fix_firstone(absdelta);
	mant = ((n < 0) ? (absdelta >> (-n)) : (absdelta << n)) & 0x7ff;
	expn = scaleexpn - p;
	if (scaleexpn < p) {
		abort();
	}
	return JPC_QCX_EXPN(expn) | JPC_QCX_MANT(mant);
}

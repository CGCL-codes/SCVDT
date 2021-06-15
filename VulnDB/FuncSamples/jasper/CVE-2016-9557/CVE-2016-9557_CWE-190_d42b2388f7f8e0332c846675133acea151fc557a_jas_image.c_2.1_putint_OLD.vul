static int putint(jas_stream_t *out, int sgnd, int prec, long val)
{
	int n;
	int c;
	bool s;
	ulong tmp;
	assert((!sgnd && prec >= 1) || (sgnd && prec >= 2));
	if (sgnd) {
		val = encode_twos_comp(val, prec);
	}
	assert(val >= 0);
	val &= (1 << prec) - 1;
	n = (prec + 7) / 8;
	while (--n >= 0) {
		c = (val >> (n * 8)) & 0xff;
		if (jas_stream_putc(out, c) != c)
			return -1;
	}
	return 0;
}

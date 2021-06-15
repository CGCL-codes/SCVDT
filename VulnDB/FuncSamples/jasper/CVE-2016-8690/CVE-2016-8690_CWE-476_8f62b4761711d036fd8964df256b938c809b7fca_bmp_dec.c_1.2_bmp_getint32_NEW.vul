static int bmp_getint32(jas_stream_t *in, int_fast32_t *val)
{
	int n;
	uint_fast32_t v;
	int c;
	for (n = 4, v = 0;;) {
		if ((c = jas_stream_getc(in)) == EOF) {
			return -1;
		}
		v |= (JAS_CAST(uint_fast32_t, c) << 24);
		if (--n <= 0) {
			break;
		}
		v >>= 8;
	}
	if (val) {
		*val = v;
	}
	return 0;
}

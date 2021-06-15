int jas_stream_gobble(jas_stream_t *stream, int n)
{
	int m;
	m = n;
	for (m = n; m > 0; --m) {
		if (jas_stream_getc(stream) == EOF) {
			return n - m;
		}
	}
	return n;
}

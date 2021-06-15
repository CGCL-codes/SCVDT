int jas_stream_write(jas_stream_t *stream, const void *buf, int cnt)
{
	int n;
	const char *bufptr;

	bufptr = buf;

	n = 0;
	while (n < cnt) {
		if (jas_stream_putc(stream, *bufptr) == EOF) {
			return n;
		}
		++bufptr;
		++n;
	}

	return n;
}

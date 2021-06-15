int jas_stream_printf(jas_stream_t *stream, const char *fmt, ...)
{
	va_list ap;
	char buf[4096];
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(buf, sizeof buf, fmt, ap);
	jas_stream_puts(stream, buf);
	va_end(ap);
	return ret;
}

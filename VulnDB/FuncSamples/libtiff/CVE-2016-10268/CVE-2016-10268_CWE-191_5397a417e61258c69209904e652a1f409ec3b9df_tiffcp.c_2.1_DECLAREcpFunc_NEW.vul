DECLAREcpFunc(cpContig2ContigByRow)
{
	tsize_t scanlinesize = TIFFScanlineSize(in);
	tdata_t buf;
	uint32 row;

	buf = _TIFFmalloc(scanlinesize);
	if (!buf)
		return 0;
	_TIFFmemset(buf, 0, scanlinesize);
	(void) imagewidth; (void) spp;
	for (row = 0; row < imagelength; row++) {
		if (TIFFReadScanline(in, buf, row, 0) < 0 && !ignore) {
			TIFFError(TIFFFileName(in),
				  "Error, can't read scanline %lu",
				  (unsigned long) row);
			goto bad;
		}
		if (TIFFWriteScanline(out, buf, row, 0) < 0) {
			TIFFError(TIFFFileName(out),
				  "Error, can't write scanline %lu",
				  (unsigned long) row);
			goto bad;
		}
	}
	_TIFFfree(buf);
	return 1;
bad:
	_TIFFfree(buf);
	return 0;
}

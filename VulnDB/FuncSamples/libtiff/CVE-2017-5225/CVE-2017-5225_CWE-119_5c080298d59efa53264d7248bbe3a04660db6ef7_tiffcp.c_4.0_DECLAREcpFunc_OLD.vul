DECLAREcpFunc(cpSeparate2ContigByRow)
{
	tsize_t scanlinesizein = TIFFScanlineSize(in);
	tsize_t scanlinesizeout = TIFFScanlineSize(out);
	tdata_t inbuf;
	tdata_t outbuf;
	register uint8 *inp, *outp;
	register uint32 n;
	uint32 row;
	tsample_t s;

	inbuf = _TIFFmalloc(scanlinesizein);
	outbuf = _TIFFmalloc(scanlinesizeout);
	if (!inbuf || !outbuf)
                goto bad;
	_TIFFmemset(inbuf, 0, scanlinesizein);
	_TIFFmemset(outbuf, 0, scanlinesizeout);
	for (row = 0; row < imagelength; row++) {
		/* merge channels */
		for (s = 0; s < spp; s++) {
			if (TIFFReadScanline(in, inbuf, row, s) < 0
			    && !ignore) {
				TIFFError(TIFFFileName(in),
				    "Error, can't read scanline %lu",
				    (unsigned long) row);
				goto bad;
			}
			inp = (uint8*)inbuf;
			outp = ((uint8*)outbuf) + s;
			for (n = imagewidth; n-- > 0;) {
				*outp = *inp++;
				outp += spp;
			}
		}
		if (TIFFWriteScanline(out, outbuf, row, 0) < 0) {
			TIFFError(TIFFFileName(out),
			    "Error, can't write scanline %lu",
			    (unsigned long) row);
			goto bad;
		}
	}
	if (inbuf) _TIFFfree(inbuf);
	if (outbuf) _TIFFfree(outbuf);
	return 1;
bad:
	if (inbuf) _TIFFfree(inbuf);
	if (outbuf) _TIFFfree(outbuf);
	return 0;
}

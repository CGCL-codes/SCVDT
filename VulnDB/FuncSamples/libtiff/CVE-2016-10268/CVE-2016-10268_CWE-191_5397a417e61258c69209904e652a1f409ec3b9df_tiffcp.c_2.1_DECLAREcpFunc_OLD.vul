DECLAREcpFunc(cpDecodedStrips)
{
	tsize_t stripsize  = TIFFStripSize(in);
	tdata_t buf = _TIFFmalloc(stripsize);

	(void) imagewidth; (void) spp;
	if (buf) {
		tstrip_t s, ns = TIFFNumberOfStrips(in);
		uint32 row = 0;
		_TIFFmemset(buf, 0, stripsize);
		for (s = 0; s < ns; s++) {
			tsize_t cc = (row + rowsperstrip > imagelength) ?
			    TIFFVStripSize(in, imagelength - row) : stripsize;
			if (TIFFReadEncodedStrip(in, s, buf, cc) < 0
			    && !ignore) {
				TIFFError(TIFFFileName(in),
				    "Error, can't read strip %lu",
				    (unsigned long) s);
				goto bad;
			}
			if (TIFFWriteEncodedStrip(out, s, buf, cc) < 0) {
				TIFFError(TIFFFileName(out),
				    "Error, can't write strip %lu",
				    (unsigned long) s);
				goto bad;
			}
			row += rowsperstrip;
		}
		_TIFFfree(buf);
		return 1;
	} else {
		TIFFError(TIFFFileName(in),
		    "Error, can't allocate memory buffer of size %lu "
		    "to read strips", (unsigned long) stripsize);
		return 0;
	}

bad:
	_TIFFfree(buf);
	return 0;
}

DECLAREwriteFunc(writeBufferToContigStrips)
{
	uint32 row, rowsperstrip;
	tstrip_t strip = 0;

	(void) imagewidth; (void) spp;
	(void) TIFFGetFieldDefaulted(out, TIFFTAG_ROWSPERSTRIP, &rowsperstrip);
	for (row = 0; row < imagelength; row += rowsperstrip) {
		uint32 nrows = (row+rowsperstrip > imagelength) ?
		    imagelength-row : rowsperstrip;
		tsize_t stripsize = TIFFVStripSize(out, nrows);
		if (TIFFWriteEncodedStrip(out, strip++, buf, stripsize) < 0) {
			TIFFError(TIFFFileName(out),
			    "Error, can't write strip %u", strip - 1);
			return 0;
		}
		buf += stripsize;
	}
	return 1;
}

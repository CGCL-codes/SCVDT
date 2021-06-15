DECLAREreadFunc(readContigTilesIntoBuffer)
{
	int status = 1;
	tsize_t tilesize = TIFFTileSize(in);
	tdata_t tilebuf;
	uint32 imagew = TIFFScanlineSize(in);
	uint32 tilew  = TIFFTileRowSize(in);
	int iskew = imagew - tilew;
	uint8* bufp = (uint8*) buf;
	uint32 tw, tl;
	uint32 row;

	(void) spp;
	tilebuf = _TIFFmalloc(tilesize);
	if (tilebuf == 0)
		return 0;
	_TIFFmemset(tilebuf, 0, tilesize);
	(void) TIFFGetField(in, TIFFTAG_TILEWIDTH, &tw);
	(void) TIFFGetField(in, TIFFTAG_TILELENGTH, &tl);
        
	for (row = 0; row < imagelength; row += tl) {
		uint32 nrow = (row+tl > imagelength) ? imagelength-row : tl;
		uint32 colb = 0;
		uint32 col;

		for (col = 0; col < imagewidth && colb < imagew; col += tw) {
			if (TIFFReadTile(in, tilebuf, col, row, 0, 0) < 0
			    && !ignore) {
				TIFFError(TIFFFileName(in),
				    "Error, can't read tile at %lu %lu",
				    (unsigned long) col,
				    (unsigned long) row);
				status = 0;
				goto done;
			}
			if (colb + tilew > imagew) {
				uint32 width = imagew - colb;
				uint32 oskew = tilew - width;
				cpStripToTile(bufp + colb,
				    tilebuf, nrow, width,
				    oskew + iskew, oskew );
			} else
				cpStripToTile(bufp + colb,
				    tilebuf, nrow, tilew,
				    iskew, 0);
			colb += tilew;
		}
		bufp += imagew * nrow;
	}
done:
	_TIFFfree(tilebuf);
	return status;
}

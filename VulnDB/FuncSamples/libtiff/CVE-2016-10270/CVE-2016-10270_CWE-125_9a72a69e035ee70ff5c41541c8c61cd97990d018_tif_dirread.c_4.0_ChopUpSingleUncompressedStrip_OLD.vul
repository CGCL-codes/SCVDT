static void
ChopUpSingleUncompressedStrip(TIFF* tif)
{
	register TIFFDirectory *td = &tif->tif_dir;
	uint64 bytecount;
	uint64 offset;
	uint32 rowblock;
	uint64 rowblockbytes;
	uint64 stripbytes;
	uint32 strip;
	uint64 nstrips64;
	uint32 nstrips32;
	uint32 rowsperstrip;
	uint64* newcounts;
	uint64* newoffsets;

	bytecount = td->td_stripbytecount[0];
	offset = td->td_stripoffset[0];
	assert(td->td_planarconfig == PLANARCONFIG_CONTIG);
	if ((td->td_photometric == PHOTOMETRIC_YCBCR)&&
	    (!isUpSampled(tif)))
		rowblock = td->td_ycbcrsubsampling[1];
	else
		rowblock = 1;
	rowblockbytes = TIFFVTileSize64(tif, rowblock);
	/*
	 * Make the rows hold at least one scanline, but fill specified amount
	 * of data if possible.
	 */
	if (rowblockbytes > STRIP_SIZE_DEFAULT) {
		stripbytes = rowblockbytes;
		rowsperstrip = rowblock;
	} else if (rowblockbytes > 0 ) {
		uint32 rowblocksperstrip;
		rowblocksperstrip = (uint32) (STRIP_SIZE_DEFAULT / rowblockbytes);
		rowsperstrip = rowblocksperstrip * rowblock;
		stripbytes = rowblocksperstrip * rowblockbytes;
	}
	else
	    return;

	/*
	 * never increase the number of strips in an image
	 */
	if (rowsperstrip >= td->td_rowsperstrip)
		return;
	nstrips64 = TIFFhowmany_64(bytecount, stripbytes);
	if ((nstrips64==0)||(nstrips64>0xFFFFFFFF)) /* something is wonky, do nothing. */
	    return;
	nstrips32 = (uint32)nstrips64;

	newcounts = (uint64*) _TIFFCheckMalloc(tif, nstrips32, sizeof (uint64),
				"for chopped \"StripByteCounts\" array");
	newoffsets = (uint64*) _TIFFCheckMalloc(tif, nstrips32, sizeof (uint64),
				"for chopped \"StripOffsets\" array");
	if (newcounts == NULL || newoffsets == NULL) {
		/*
		 * Unable to allocate new strip information, give up and use
		 * the original one strip information.
		 */
		if (newcounts != NULL)
			_TIFFfree(newcounts);
		if (newoffsets != NULL)
			_TIFFfree(newoffsets);
		return;
	}
	/*
	 * Fill the strip information arrays with new bytecounts and offsets
	 * that reflect the broken-up format.
	 */
	for (strip = 0; strip < nstrips32; strip++) {
		if (stripbytes > bytecount)
			stripbytes = bytecount;
		newcounts[strip] = stripbytes;
		newoffsets[strip] = offset;
		offset += stripbytes;
		bytecount -= stripbytes;
	}
	/*
	 * Replace old single strip info with multi-strip info.
	 */
	td->td_stripsperimage = td->td_nstrips = nstrips32;
	TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rowsperstrip);

	_TIFFfree(td->td_stripbytecount);
	_TIFFfree(td->td_stripoffset);
	td->td_stripbytecount = newcounts;
	td->td_stripoffset = newoffsets;
	td->td_stripbytecountsorted = 1;
}

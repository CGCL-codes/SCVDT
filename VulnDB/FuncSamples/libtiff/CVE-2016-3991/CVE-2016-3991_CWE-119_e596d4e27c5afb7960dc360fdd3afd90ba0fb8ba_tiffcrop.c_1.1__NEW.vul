static int writeBufferToContigTiles (TIFF* out, uint8* buf, uint32 imagelength,
				       uint32 imagewidth, tsample_t spp, 
                                       struct dump_opts* dump)
  {
  uint16 bps;
  uint32 tl, tw;
  uint32 row, col, nrow, ncol;
  uint32 src_rowsize, col_offset;
  uint32 tile_rowsize  = TIFFTileRowSize(out);
  uint8* bufp = (uint8*) buf;
  tsize_t tile_buffsize = 0;
  tsize_t tilesize = TIFFTileSize(out);
  unsigned char *tilebuf = NULL;

  if( !TIFFGetField(out, TIFFTAG_TILELENGTH, &tl) ||
      !TIFFGetField(out, TIFFTAG_TILEWIDTH, &tw) ||
      !TIFFGetField(out, TIFFTAG_BITSPERSAMPLE, &bps) )
      return 1;

  if (tilesize == 0 || tile_rowsize == 0 || tl == 0 || tw == 0)
  {
    TIFFError("writeBufferToContigTiles", "Tile size, tile row size, tile width, or tile length is zero");
    exit(-1);
  }
  
  tile_buffsize = tilesize;
  if (tilesize < (tsize_t)(tl * tile_rowsize))
    {
#ifdef DEBUG2
    TIFFError("writeBufferToContigTiles",
	      "Tilesize %lu is too small, using alternate calculation %u",
              tilesize, tl * tile_rowsize);
#endif
    tile_buffsize = tl * tile_rowsize;
    if (tl != tile_buffsize / tile_rowsize)
    {
	TIFFError("writeBufferToContigTiles", "Integer overflow when calculating buffer size");
	exit(-1);
    }
    }

  tilebuf = _TIFFmalloc(tile_buffsize);
  if (tilebuf == 0)
    return 1;

  src_rowsize = ((imagewidth * spp * bps) + 7) / 8;
  for (row = 0; row < imagelength; row += tl)
    {
    nrow = (row + tl > imagelength) ? imagelength - row : tl;
    for (col = 0; col < imagewidth; col += tw)
      {
      /* Calculate visible portion of tile. */
      if (col + tw > imagewidth)
	ncol = imagewidth - col;
      else
        ncol = tw;

      col_offset = (((col * bps * spp) + 7) / 8);
      bufp = buf + (row * src_rowsize) + col_offset;
      if (extractContigSamplesToTileBuffer(tilebuf, bufp, nrow, ncol, imagewidth,
					   tw, 0, spp, spp, bps, dump) > 0)
        {
	TIFFError("writeBufferToContigTiles", 
                  "Unable to extract data to tile for row %lu, col %lu",
                  (unsigned long) row, (unsigned long)col);
	_TIFFfree(tilebuf);
	return 1;
        }

      if (TIFFWriteTile(out, tilebuf, col, row, 0, 0) < 0)
        {
	TIFFError("writeBufferToContigTiles",
	          "Cannot write tile at %lu %lu",
	          (unsigned long) col, (unsigned long) row);
	 _TIFFfree(tilebuf);
	return 1;
	}
      }
    }
  _TIFFfree(tilebuf);

  return 0;
  } /* end writeBufferToContigTiles */

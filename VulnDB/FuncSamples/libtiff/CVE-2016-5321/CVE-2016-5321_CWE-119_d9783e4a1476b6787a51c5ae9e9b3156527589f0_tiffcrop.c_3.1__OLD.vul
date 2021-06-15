static int  readSeparateTilesIntoBuffer (TIFF* in, uint8 *obuf, 
					 uint32 imagelength, uint32 imagewidth, 
                                         uint32 tw, uint32 tl,
                                         uint16 spp, uint16 bps)
  {
  int     i, status = 1, sample;
  int     shift_width, bytes_per_pixel;
  uint16  bytes_per_sample;
  uint32  row, col;     /* Current row and col of image */
  uint32  nrow, ncol;   /* Number of rows and cols in current tile */
  uint32  row_offset, col_offset; /* Output buffer offsets */
  tsize_t tbytes = 0, tilesize = TIFFTileSize(in);
  tsample_t s;
  uint8*  bufp = (uint8*)obuf;
  unsigned char *srcbuffs[MAX_SAMPLES];
  unsigned char *tbuff = NULL;

  bytes_per_sample = (bps + 7) / 8;

  for (sample = 0; (sample < spp) && (sample < MAX_SAMPLES); sample++)
    {
    srcbuffs[sample] = NULL;
    tbuff = (unsigned char *)_TIFFmalloc(tilesize + 8);
    if (!tbuff)
      {
      TIFFError ("readSeparateTilesIntoBuffer", 
                 "Unable to allocate tile read buffer for sample %d", sample);
      for (i = 0; i < sample; i++)
        _TIFFfree (srcbuffs[i]);
      return 0;
      }
    srcbuffs[sample] = tbuff;
    } 
  /* Each tile contains only the data for a single plane
   * arranged in scanlines of tw * bytes_per_sample bytes.
   */
  for (row = 0; row < imagelength; row += tl)
    {
    nrow = (row + tl > imagelength) ? imagelength - row : tl;
    for (col = 0; col < imagewidth; col += tw)
      {
      for (s = 0; s < spp; s++)
        {  /* Read each plane of a tile set into srcbuffs[s] */
	tbytes = TIFFReadTile(in, srcbuffs[s], col, row, 0, s);
        if (tbytes < 0  && !ignore)
          {
	  TIFFError(TIFFFileName(in),
                 "Error, can't read tile for row %lu col %lu, "
		 "sample %lu",
		 (unsigned long) col, (unsigned long) row,
		 (unsigned long) s);
		 status = 0;
          for (sample = 0; (sample < spp) && (sample < MAX_SAMPLES); sample++)
            {
            tbuff = srcbuffs[sample];
            if (tbuff != NULL)
              _TIFFfree(tbuff);
            }
          return status;
	  }
	}
     /* Tiles on the right edge may be padded out to tw 
      * which must be a multiple of 16.
      * Ncol represents the visible (non padding) portion.  
      */
      if (col + tw > imagewidth)
        ncol = imagewidth - col;
      else
        ncol = tw;

      row_offset = row * (((imagewidth * spp * bps) + 7) / 8);
      col_offset = ((col * spp * bps) + 7) / 8;
      bufp = obuf + row_offset + col_offset;

      if ((bps % 8) == 0)
        {
        if (combineSeparateTileSamplesBytes(srcbuffs, bufp, ncol, nrow, imagewidth,
					    tw, spp, bps, NULL, 0, 0))
	  {
          status = 0;
          break;
      	  }
	}
      else
        {
        bytes_per_pixel  = ((bps * spp) + 7) / 8;
        if (bytes_per_pixel < (bytes_per_sample + 1))
          shift_width = bytes_per_pixel;
        else
          shift_width = bytes_per_sample + 1;

        switch (shift_width)
          {
          case 1: if (combineSeparateTileSamples8bits (srcbuffs, bufp, ncol, nrow,
                                                       imagewidth, tw, spp, bps, 
						       NULL, 0, 0))
	            {
                    status = 0;
                    break;
      	            }
	          break;
          case 2: if (combineSeparateTileSamples16bits (srcbuffs, bufp, ncol, nrow,
                                                       imagewidth, tw, spp, bps, 
						       NULL, 0, 0))
	            {
                    status = 0;
                    break;
		    }
	          break;
          case 3: if (combineSeparateTileSamples24bits (srcbuffs, bufp, ncol, nrow,
                                                       imagewidth, tw, spp, bps, 
						       NULL, 0, 0))
	            {
                    status = 0;
                    break;
       	            }
                  break;
          case 4: 
          case 5:
          case 6:
          case 7:
          case 8: if (combineSeparateTileSamples32bits (srcbuffs, bufp, ncol, nrow,
                                                       imagewidth, tw, spp, bps, 
						       NULL, 0, 0))
	            {
                    status = 0;
                    break;
		    }
	          break;
          default: TIFFError ("readSeparateTilesIntoBuffer", "Unsupported bit depth: %d", bps);
                  status = 0;
                  break;
          }
        }
      }
    }

  for (sample = 0; (sample < spp) && (sample < MAX_SAMPLES); sample++)
    {
    tbuff = srcbuffs[sample];
    if (tbuff != NULL)
      _TIFFfree(tbuff);
    }
 
  return status;
  }

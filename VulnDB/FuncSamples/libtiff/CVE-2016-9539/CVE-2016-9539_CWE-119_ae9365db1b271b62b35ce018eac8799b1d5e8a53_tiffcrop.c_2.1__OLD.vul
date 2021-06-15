static int readContigTilesIntoBuffer (TIFF* in, uint8* buf, 
                                      uint32 imagelength, 
                                      uint32 imagewidth, 
                                      uint32 tw, uint32 tl,
                                      tsample_t spp, uint16 bps)
  {
  int status = 1;
  tsample_t sample = 0;
  tsample_t count = spp; 
  uint32 row, col, trow;
  uint32 nrow, ncol;
  uint32 dst_rowsize, shift_width;
  uint32 bytes_per_sample, bytes_per_pixel;
  uint32 trailing_bits, prev_trailing_bits;
  uint32 tile_rowsize  = TIFFTileRowSize(in);
  uint32 src_offset, dst_offset;
  uint32 row_offset, col_offset;
  uint8 *bufp = (uint8*) buf;
  unsigned char *src = NULL;
  unsigned char *dst = NULL;
  tsize_t tbytes = 0, tile_buffsize = 0;
  tsize_t tilesize = TIFFTileSize(in);
  unsigned char *tilebuf = NULL;

  bytes_per_sample = (bps + 7) / 8; 
  bytes_per_pixel  = ((bps * spp) + 7) / 8;

  if ((bps % 8) == 0)
    shift_width = 0;
  else
    {
    if (bytes_per_pixel < (bytes_per_sample + 1))
      shift_width = bytes_per_pixel;
    else
      shift_width = bytes_per_sample + 1;
    }

  tile_buffsize = tilesize;
  if (tilesize == 0 || tile_rowsize == 0)
  {
     TIFFError("readContigTilesIntoBuffer", "Tile size or tile rowsize is zero");
     exit(-1);
  }

  if (tilesize < (tsize_t)(tl * tile_rowsize))
    {
#ifdef DEBUG2
    TIFFError("readContigTilesIntoBuffer",
	      "Tilesize %lu is too small, using alternate calculation %u",
              tilesize, tl * tile_rowsize);
#endif
    tile_buffsize = tl * tile_rowsize;
    if (tl != (tile_buffsize / tile_rowsize))
    {
    	TIFFError("readContigTilesIntoBuffer", "Integer overflow when calculating buffer size.");
        exit(-1);
    }
    }

  tilebuf = _TIFFmalloc(tile_buffsize);
  if (tilebuf == 0)
    return 0;

  dst_rowsize = ((imagewidth * bps * spp) + 7) / 8;  
  for (row = 0; row < imagelength; row += tl)
    {
    nrow = (row + tl > imagelength) ? imagelength - row : tl;
    for (col = 0; col < imagewidth; col += tw)
      {
      tbytes = TIFFReadTile(in, tilebuf, col, row, 0, 0);
      if (tbytes < tilesize  && !ignore)
        {
	TIFFError(TIFFFileName(in),
		  "Error, can't read tile at row %lu col %lu, Read %lu bytes of %lu",
		  (unsigned long) col, (unsigned long) row, (unsigned long)tbytes,
                  (unsigned long)tilesize);
		  status = 0;
                  _TIFFfree(tilebuf);
		  return status;
	}
      
      row_offset = row * dst_rowsize;
      col_offset = ((col * bps * spp) + 7)/ 8;
      bufp = buf + row_offset + col_offset;

      if (col + tw > imagewidth)
	ncol = imagewidth - col;
      else
        ncol = tw;

      /* Each tile scanline will start on a byte boundary but it
       * has to be merged into the scanline for the entire
       * image buffer and the previous segment may not have
       * ended on a byte boundary
       */
      /* Optimization for common bit depths, all samples */
      if (((bps % 8) == 0) && (count == spp))
        {
	for (trow = 0; trow < nrow; trow++)
          {
	  src_offset = trow * tile_rowsize;
	  _TIFFmemcpy (bufp, tilebuf + src_offset, (ncol * spp * bps) / 8);
          bufp += (imagewidth * bps * spp) / 8;
	  }
        }
      else
        {
	/* Bit depths not a multiple of 8 and/or extract fewer than spp samples */
        prev_trailing_bits = trailing_bits = 0;
        trailing_bits = (ncol * bps * spp) % 8;

	/*	for (trow = 0; tl < nrow; trow++) */
	for (trow = 0; trow < nrow; trow++)
          {
	  src_offset = trow * tile_rowsize;
          src = tilebuf + src_offset;
	  dst_offset = (row + trow) * dst_rowsize;
          dst = buf + dst_offset + col_offset;
          switch (shift_width)
            {
            case 0: if (extractContigSamplesBytes (src, dst, ncol, sample,
                                                   spp, bps, count, 0, ncol))
                      {
		      TIFFError("readContigTilesIntoBuffer",
                                "Unable to extract row %d from tile %lu", 
				row, (unsigned long)TIFFCurrentTile(in));
		      return 1;
		      }
		    break;
            case 1: if (bps == 1)
                      { 
                      if (extractContigSamplesShifted8bits (src, dst, ncol,
                                                            sample, spp,
                                                            bps, count,
                                                            0, ncol,
                                                            prev_trailing_bits))
                        {
		        TIFFError("readContigTilesIntoBuffer",
                                  "Unable to extract row %d from tile %lu", 
				  row, (unsigned long)TIFFCurrentTile(in));
		        return 1;
		        }
		      break;
		      }
                    else
                      if (extractContigSamplesShifted16bits (src, dst, ncol,
                                                             sample, spp,
                                                             bps, count,
                                                             0, ncol,
                                                             prev_trailing_bits))
                        {
		        TIFFError("readContigTilesIntoBuffer",
                                  "Unable to extract row %d from tile %lu", 
			  	  row, (unsigned long)TIFFCurrentTile(in));
		        return 1;
		        }
	            break;
            case 2: if (extractContigSamplesShifted24bits (src, dst, ncol,
                                                           sample, spp,
                                                           bps, count,
                                                           0, ncol,
                                                           prev_trailing_bits))
                      {
		      TIFFError("readContigTilesIntoBuffer",
                                "Unable to extract row %d from tile %lu", 
		  	        row, (unsigned long)TIFFCurrentTile(in));
		      return 1;
		      }
		    break;
            case 3:
            case 4:
            case 5: if (extractContigSamplesShifted32bits (src, dst, ncol,
                                                           sample, spp,
                                                           bps, count,
                                                           0, ncol,
                                                           prev_trailing_bits))
                      {
		      TIFFError("readContigTilesIntoBuffer",
                                "Unable to extract row %d from tile %lu", 
			        row, (unsigned long)TIFFCurrentTile(in));
		      return 1;
		      }
		    break;
            default: TIFFError("readContigTilesIntoBuffer", "Unsupported bit depth %d", bps);
		     return 1;
	    }
          }
        prev_trailing_bits += trailing_bits;
        /* if (prev_trailing_bits > 7) */
	/*   prev_trailing_bits-= 8; */
	}
      }
    }

  _TIFFfree(tilebuf);
  return status;
  }

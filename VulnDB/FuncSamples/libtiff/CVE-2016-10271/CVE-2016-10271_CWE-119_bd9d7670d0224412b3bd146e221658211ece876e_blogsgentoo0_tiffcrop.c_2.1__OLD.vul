static int readSeparateStripsIntoBuffer (TIFF *in, uint8 *obuf, uint32 length, 
                                         uint32 width, uint16 spp,
                                         struct dump_opts *dump)
  {
  int i, bytes_per_sample, bytes_per_pixel, shift_width, result = 1;
  uint32 j;
  int32  bytes_read = 0;
  uint16 bps, planar;
  uint32 nstrips;
  uint32 strips_per_sample;
  uint32 src_rowsize, dst_rowsize, rows_processed, rps;
  uint32 rows_this_strip = 0;
  tsample_t s;
  tstrip_t  strip;
  tsize_t scanlinesize = TIFFScanlineSize(in);
  tsize_t stripsize    = TIFFStripSize(in);
  unsigned char *srcbuffs[MAX_SAMPLES];
  unsigned char *buff = NULL;
  unsigned char *dst = NULL;

  if (obuf == NULL)
    {
    TIFFError("readSeparateStripsIntoBuffer","Invalid buffer argument");
    return (0);
    }

  memset (srcbuffs, '\0', sizeof(srcbuffs));
  TIFFGetField(in, TIFFTAG_BITSPERSAMPLE, &bps);
  TIFFGetFieldDefaulted(in, TIFFTAG_PLANARCONFIG, &planar);
  TIFFGetFieldDefaulted(in, TIFFTAG_ROWSPERSTRIP, &rps);
  if (rps > length)
    rps = length;

  bytes_per_sample = (bps + 7) / 8; 
  bytes_per_pixel  = ((bps * spp) + 7) / 8;
  if (bytes_per_pixel < (bytes_per_sample + 1))
    shift_width = bytes_per_pixel;
  else
    shift_width = bytes_per_sample + 1;

  src_rowsize = ((bps * width) + 7) / 8;
  dst_rowsize = ((bps * width * spp) + 7) / 8;
  dst = obuf;

  if ((dump->infile != NULL) && (dump->level == 3))
    {
    dump_info  (dump->infile, dump->format, "", 
                "Image width %d, length %d, Scanline size, %4d bytes",
                width, length,  scanlinesize);
    dump_info  (dump->infile, dump->format, "", 
                "Bits per sample %d, Samples per pixel %d, Shift width %d",
		bps, spp, shift_width);
    }

  /* Libtiff seems to assume/require that data for separate planes are 
   * written one complete plane after another and not interleaved in any way.
   * Multiple scanlines and possibly strips of the same plane must be 
   * written before data for any other plane.
   */
  nstrips = TIFFNumberOfStrips(in);
  strips_per_sample = nstrips /spp;

  for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)
    {
    srcbuffs[s] = NULL;
    buff = _TIFFmalloc(stripsize);
    if (!buff)
      {
      TIFFError ("readSeparateStripsIntoBuffer", 
                 "Unable to allocate strip read buffer for sample %d", s);
      for (i = 0; i < s; i++)
        _TIFFfree (srcbuffs[i]);
      return 0;
      }
    srcbuffs[s] = buff;
    }

  rows_processed = 0;
  for (j = 0; (j < strips_per_sample) && (result == 1); j++)
    {
    for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)
      {
      buff = srcbuffs[s];
      strip = (s * strips_per_sample) + j; 
      bytes_read = TIFFReadEncodedStrip (in, strip, buff, stripsize);
      rows_this_strip = bytes_read / src_rowsize;
      if (bytes_read < 0 && !ignore)
        {
        TIFFError(TIFFFileName(in),
	          "Error, can't read strip %lu for sample %d",
         	   (unsigned long) strip, s + 1);
        result = 0;
        break;
        }
#ifdef DEVELMODE
      TIFFError("", "Strip %2d, read %5d bytes for %4d scanlines, shift width %d", 
		strip, bytes_read, rows_this_strip, shift_width);
#endif
      }

    if (rps > rows_this_strip)
      rps = rows_this_strip;
    dst = obuf + (dst_rowsize * rows_processed);
    if ((bps % 8) == 0)
      {
      if (combineSeparateSamplesBytes (srcbuffs, dst, width, rps,
                                       spp, bps, dump->infile, 
                                       dump->format, dump->level))
        {
        result = 0;
        break;
	}
      }
    else
      {
      switch (shift_width)
        {
        case 1: if (combineSeparateSamples8bits (srcbuffs, dst, width, rps,
                                                 spp, bps, dump->infile,
                                                 dump->format, dump->level))
	          {
                  result = 0;
                  break;
      	          }
	        break;
        case 2: if (combineSeparateSamples16bits (srcbuffs, dst, width, rps,
                                                  spp, bps, dump->infile,
                                                  dump->format, dump->level))
	          {
                  result = 0;
                  break;
		  }
	        break;
        case 3: if (combineSeparateSamples24bits (srcbuffs, dst, width, rps,
                                                  spp, bps, dump->infile,
                                                  dump->format, dump->level))
	          {
                  result = 0;
                  break;
       	          }
                break;
        case 4: 
        case 5:
        case 6:
        case 7:
        case 8: if (combineSeparateSamples32bits (srcbuffs, dst, width, rps,
                                                  spp, bps, dump->infile,
                                                  dump->format, dump->level))
	          {
                  result = 0;
                  break;
		  }
	        break;
        default: TIFFError ("readSeparateStripsIntoBuffer", "Unsupported bit depth: %d", bps);
                  result = 0;
                  break;
        }
      }
 
    if ((rows_processed + rps) > length)
      {
      rows_processed = length;
      rps = length - rows_processed;
      }
    else
      rows_processed += rps;
    }

  /* free any buffers allocated for each plane or scanline and 
   * any temporary buffers 
   */
  for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)
    {
    buff = srcbuffs[s];
    if (buff != NULL)
      _TIFFfree(buff);
    }

  return (result);
  } /* end readSeparateStripsIntoBuffer */

static int
JPEGSetupEncode(TIFF* tif)
{
	JPEGState* sp = JState(tif);
	TIFFDirectory *td = &tif->tif_dir;
	static const char module[] = "JPEGSetupEncode";

#if defined(JPEG_DUAL_MODE_8_12) && !defined(TIFFInitJPEG)
        if( tif->tif_dir.td_bitspersample == 12 )
            return TIFFReInitJPEG_12( tif, COMPRESSION_JPEG, 1 );
#endif

        JPEGInitializeLibJPEG( tif, FALSE );

	assert(sp != NULL);
	assert(!sp->cinfo.comm.is_decompressor);

	sp->photometric = td->td_photometric;

	/*
	 * Initialize all JPEG parameters to default values.
	 * Note that jpeg_set_defaults needs legal values for
	 * in_color_space and input_components.
	 */
	if (td->td_planarconfig == PLANARCONFIG_CONTIG) {
		sp->cinfo.c.input_components = td->td_samplesperpixel;
		if (sp->photometric == PHOTOMETRIC_YCBCR) {
			if (sp->jpegcolormode == JPEGCOLORMODE_RGB) {
				sp->cinfo.c.in_color_space = JCS_RGB;
			} else {
				sp->cinfo.c.in_color_space = JCS_YCbCr;
			}
		} else {
			if ((td->td_photometric == PHOTOMETRIC_MINISWHITE || td->td_photometric == PHOTOMETRIC_MINISBLACK) && td->td_samplesperpixel == 1)
				sp->cinfo.c.in_color_space = JCS_GRAYSCALE;
			else if (td->td_photometric == PHOTOMETRIC_RGB && td->td_samplesperpixel == 3)
				sp->cinfo.c.in_color_space = JCS_RGB;
			else if (td->td_photometric == PHOTOMETRIC_SEPARATED && td->td_samplesperpixel == 4)
				sp->cinfo.c.in_color_space = JCS_CMYK;
			else
				sp->cinfo.c.in_color_space = JCS_UNKNOWN;
		}
	} else {
		sp->cinfo.c.input_components = 1;
		sp->cinfo.c.in_color_space = JCS_UNKNOWN;
	}
	if (!TIFFjpeg_set_defaults(sp))
		return (0);
	/* Set per-file parameters */
	switch (sp->photometric) {
	case PHOTOMETRIC_YCBCR:
		sp->h_sampling = td->td_ycbcrsubsampling[0];
		sp->v_sampling = td->td_ycbcrsubsampling[1];
                if( sp->h_sampling == 0 || sp->v_sampling == 0 )
                {
                    TIFFErrorExt(tif->tif_clientdata, module,
                            "Invalig horizontal/vertical sampling value");
                    return (0);
                }

		/*
		 * A ReferenceBlackWhite field *must* be present since the
		 * default value is inappropriate for YCbCr.  Fill in the
		 * proper value if application didn't set it.
		 */
		{
			float *ref;
			if (!TIFFGetField(tif, TIFFTAG_REFERENCEBLACKWHITE,
					  &ref)) {
				float refbw[6];
				long top = 1L << td->td_bitspersample;
				refbw[0] = 0;
				refbw[1] = (float)(top-1L);
				refbw[2] = (float)(top>>1);
				refbw[3] = refbw[1];
				refbw[4] = refbw[2];
				refbw[5] = refbw[1];
				TIFFSetField(tif, TIFFTAG_REFERENCEBLACKWHITE,
					     refbw);
			}
		}
		break;
	case PHOTOMETRIC_PALETTE:		/* disallowed by Tech Note */
	case PHOTOMETRIC_MASK:
		TIFFErrorExt(tif->tif_clientdata, module,
			  "PhotometricInterpretation %d not allowed for JPEG",
			  (int) sp->photometric);
		return (0);
	default:
		/* TIFF 6.0 forbids subsampling of all other color spaces */
		sp->h_sampling = 1;
		sp->v_sampling = 1;
		break;
	}

	/* Verify miscellaneous parameters */

	/*
	 * This would need work if libtiff ever supports different
	 * depths for different components, or if libjpeg ever supports
	 * run-time selection of depth.  Neither is imminent.
	 */
#ifdef JPEG_LIB_MK1
        /* BITS_IN_JSAMPLE now permits 8 and 12 --- dgilbert */
	if (td->td_bitspersample != 8 && td->td_bitspersample != 12) 
#else
	if (td->td_bitspersample != BITS_IN_JSAMPLE )
#endif
	{
		TIFFErrorExt(tif->tif_clientdata, module, "BitsPerSample %d not allowed for JPEG",
			  (int) td->td_bitspersample);
		return (0);
	}
	sp->cinfo.c.data_precision = td->td_bitspersample;
#ifdef JPEG_LIB_MK1
        sp->cinfo.c.bits_in_jsample = td->td_bitspersample;
#endif
	if (isTiled(tif)) {
		if ((td->td_tilelength % (sp->v_sampling * DCTSIZE)) != 0) {
			TIFFErrorExt(tif->tif_clientdata, module,
				  "JPEG tile height must be multiple of %d",
				  sp->v_sampling * DCTSIZE);
			return (0);
		}
		if ((td->td_tilewidth % (sp->h_sampling * DCTSIZE)) != 0) {
			TIFFErrorExt(tif->tif_clientdata, module,
				  "JPEG tile width must be multiple of %d",
				  sp->h_sampling * DCTSIZE);
			return (0);
		}
	} else {
		if (td->td_rowsperstrip < td->td_imagelength &&
		    (td->td_rowsperstrip % (sp->v_sampling * DCTSIZE)) != 0) {
			TIFFErrorExt(tif->tif_clientdata, module,
				  "RowsPerStrip must be multiple of %d for JPEG",
				  sp->v_sampling * DCTSIZE);
			return (0);
		}
	}

	/* Create a JPEGTables field if appropriate */
	if (sp->jpegtablesmode & (JPEGTABLESMODE_QUANT|JPEGTABLESMODE_HUFF)) {
                if( sp->jpegtables == NULL
                    || memcmp(sp->jpegtables,"\0\0\0\0\0\0\0\0\0",8) == 0 )
                {
                        if (!prepare_JPEGTables(tif))
                                return (0);
                        /* Mark the field present */
                        /* Can't use TIFFSetField since BEENWRITING is already set! */
                        tif->tif_flags |= TIFF_DIRTYDIRECT;
                        TIFFSetFieldBit(tif, FIELD_JPEGTABLES);
                }
	} else {
		/* We do not support application-supplied JPEGTables, */
		/* so mark the field not present */
		TIFFClrFieldBit(tif, FIELD_JPEGTABLES);
	}

	/* Direct libjpeg output to libtiff's output buffer */
	TIFFjpeg_data_dest(sp, tif);

	return (1);
}

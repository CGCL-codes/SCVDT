static int
cmptags(TIFF* tif1, TIFF* tif2)
{
	CmpLongField(TIFFTAG_SUBFILETYPE,	"SubFileType");
	CmpLongField(TIFFTAG_IMAGEWIDTH,	"ImageWidth");
	CmpLongField(TIFFTAG_IMAGELENGTH,	"ImageLength");
	CmpShortField(TIFFTAG_BITSPERSAMPLE,	"BitsPerSample");
	CmpShortField(TIFFTAG_COMPRESSION,	"Compression");
	CmpShortField(TIFFTAG_PREDICTOR,	"Predictor");
	CmpShortField(TIFFTAG_PHOTOMETRIC,	"PhotometricInterpretation");
	CmpShortField(TIFFTAG_THRESHHOLDING,	"Thresholding");
	CmpShortField(TIFFTAG_FILLORDER,	"FillOrder");
	CmpShortField(TIFFTAG_ORIENTATION,	"Orientation");
	CmpShortField(TIFFTAG_SAMPLESPERPIXEL,	"SamplesPerPixel");
	CmpShortField(TIFFTAG_MINSAMPLEVALUE,	"MinSampleValue");
	CmpShortField(TIFFTAG_MAXSAMPLEVALUE,	"MaxSampleValue");
	CmpShortField(TIFFTAG_SAMPLEFORMAT,	"SampleFormat");
	CmpFloatField(TIFFTAG_XRESOLUTION,	"XResolution");
	CmpFloatField(TIFFTAG_YRESOLUTION,	"YResolution");
	CmpLongField(TIFFTAG_GROUP3OPTIONS,	"Group3Options");
	CmpLongField(TIFFTAG_GROUP4OPTIONS,	"Group4Options");
	CmpShortField(TIFFTAG_RESOLUTIONUNIT,	"ResolutionUnit");
	CmpShortField(TIFFTAG_PLANARCONFIG,	"PlanarConfiguration");
	CmpLongField(TIFFTAG_ROWSPERSTRIP,	"RowsPerStrip");
	CmpFloatField(TIFFTAG_XPOSITION,	"XPosition");
	CmpFloatField(TIFFTAG_YPOSITION,	"YPosition");
	CmpShortField(TIFFTAG_GRAYRESPONSEUNIT, "GrayResponseUnit");
	CmpShortField(TIFFTAG_COLORRESPONSEUNIT, "ColorResponseUnit");
#ifdef notdef
	{ uint16 *graycurve;
	  CmpField(TIFFTAG_GRAYRESPONSECURVE, graycurve);
	}
	{ uint16 *red, *green, *blue;
	  CmpField3(TIFFTAG_COLORRESPONSECURVE, red, green, blue);
	}
	{ uint16 *red, *green, *blue;
	  CmpField3(TIFFTAG_COLORMAP, red, green, blue);
	}
#endif
	CmpShortField2(TIFFTAG_PAGENUMBER,	"PageNumber");
	CmpStringField(TIFFTAG_ARTIST,		"Artist");
	CmpStringField(TIFFTAG_IMAGEDESCRIPTION,"ImageDescription");
	CmpStringField(TIFFTAG_MAKE,		"Make");
	CmpStringField(TIFFTAG_MODEL,		"Model");
	CmpStringField(TIFFTAG_SOFTWARE,	"Software");
	CmpStringField(TIFFTAG_DATETIME,	"DateTime");
	CmpStringField(TIFFTAG_HOSTCOMPUTER,	"HostComputer");
	CmpStringField(TIFFTAG_PAGENAME,	"PageName");
	CmpStringField(TIFFTAG_DOCUMENTNAME,	"DocumentName");
	CmpShortField(TIFFTAG_MATTEING,		"Matteing");
	CmpShortArrayField(TIFFTAG_EXTRASAMPLES,"ExtraSamples");
	return (1);
}

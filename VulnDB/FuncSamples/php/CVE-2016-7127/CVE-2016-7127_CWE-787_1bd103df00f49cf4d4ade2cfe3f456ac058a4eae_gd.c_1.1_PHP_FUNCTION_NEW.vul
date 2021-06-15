PHP_FUNCTION(gd_info)
{
	if (zend_parse_parameters_none() == FAILURE) {
		RETURN_FALSE;
	}

	array_init(return_value);

	add_assoc_string(return_value, "GD Version", PHP_GD_VERSION_STRING, 1);

#ifdef ENABLE_GD_TTF
	add_assoc_bool(return_value, "FreeType Support", 1);
#if HAVE_LIBFREETYPE
	add_assoc_string(return_value, "FreeType Linkage", "with freetype", 1);
#else
	add_assoc_string(return_value, "FreeType Linkage", "with unknown library", 1);
#endif
#else
	add_assoc_bool(return_value, "FreeType Support", 0);
#endif

#ifdef HAVE_LIBT1
	add_assoc_bool(return_value, "T1Lib Support", 1);
#else
	add_assoc_bool(return_value, "T1Lib Support", 0);
#endif
	add_assoc_bool(return_value, "GIF Read Support", 1);
	add_assoc_bool(return_value, "GIF Create Support", 1);
#ifdef HAVE_GD_JPG
	add_assoc_bool(return_value, "JPEG Support", 1);
#else
	add_assoc_bool(return_value, "JPEG Support", 0);
#endif
#ifdef HAVE_GD_PNG
	add_assoc_bool(return_value, "PNG Support", 1);
#else
	add_assoc_bool(return_value, "PNG Support", 0);
#endif
	add_assoc_bool(return_value, "WBMP Support", 1);
#if defined(HAVE_GD_XPM)
	add_assoc_bool(return_value, "XPM Support", 1);
#else
	add_assoc_bool(return_value, "XPM Support", 0);
#endif
	add_assoc_bool(return_value, "XBM Support", 1);
#ifdef HAVE_GD_WEBP
	add_assoc_bool(return_value, "WebP Support", 1);
#else
	add_assoc_bool(return_value, "WebP Support", 0);
#endif
#if defined(USE_GD_JISX0208)
	add_assoc_bool(return_value, "JIS-mapped Japanese Font Support", 1);
#else
	add_assoc_bool(return_value, "JIS-mapped Japanese Font Support", 0);
#endif
}

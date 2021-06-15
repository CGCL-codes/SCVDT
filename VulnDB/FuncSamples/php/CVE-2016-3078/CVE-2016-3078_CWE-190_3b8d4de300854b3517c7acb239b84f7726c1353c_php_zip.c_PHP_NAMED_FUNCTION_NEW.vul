static PHP_NAMED_FUNCTION(zif_zip_open)
{
	char resolved_path[MAXPATHLEN + 1];
	zip_rsrc *rsrc_int;
	int err = 0;
	zend_string *filename;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "P", &filename) == FAILURE) {
		return;
	}

	if (ZSTR_LEN(filename) == 0) {
		php_error_docref(NULL, E_WARNING, "Empty string as source");
		RETURN_FALSE;
	}

	if (ZIP_OPENBASEDIR_CHECKPATH(ZSTR_VAL(filename))) {
		RETURN_FALSE;
	}

	if(!expand_filepath(ZSTR_VAL(filename), resolved_path)) {
		RETURN_FALSE;
	}

	rsrc_int = (zip_rsrc *)emalloc(sizeof(zip_rsrc));

	rsrc_int->za = zip_open(resolved_path, 0, &err);
	if (rsrc_int->za == NULL) {
		efree(rsrc_int);
		RETURN_LONG((zend_long)err);
	}

	rsrc_int->index_current = 0;
	rsrc_int->num_files = zip_get_num_files(rsrc_int->za);

	RETURN_RES(zend_register_resource(rsrc_int, le_zip_dir));
}

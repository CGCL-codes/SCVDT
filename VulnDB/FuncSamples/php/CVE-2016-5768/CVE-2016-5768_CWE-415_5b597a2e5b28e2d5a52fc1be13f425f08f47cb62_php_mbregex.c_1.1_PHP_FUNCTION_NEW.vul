PHP_FUNCTION(mb_regex_encoding)
{
	size_t argc = ZEND_NUM_ARGS();
	char *encoding;
	int encoding_len;
	OnigEncoding mbctype;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &encoding, &encoding_len) == FAILURE) {
		return;
	}

	if (argc == 0) {
		const char *retval = _php_mb_regex_mbctype2name(MBREX(current_mbctype));

		if (retval == NULL) {
			RETURN_FALSE;
		}

		RETURN_STRING((char *)retval, 1);
	} else if (argc == 1) {
		mbctype = _php_mb_regex_name2mbctype(encoding);

		if (mbctype == ONIG_ENCODING_UNDEF) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown encoding \"%s\"", encoding);
			RETURN_FALSE;
		}

		MBREX(current_mbctype) = mbctype;
		RETURN_TRUE;
	}
}

PHP_FUNCTION(grapheme_strlen)
{
	unsigned char* string;
	int string_len;
	UChar* ustring = NULL;
	int ustring_len = 0;
	int ret_len;
	UErrorCode status;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", (char **)&string, &string_len) == FAILURE) {

		intl_error_set( NULL, U_ILLEGAL_ARGUMENT_ERROR,
			 "grapheme_strlen: unable to parse input param", 0 TSRMLS_CC );

		RETURN_FALSE;
	}

	ret_len = grapheme_ascii_check(string, string_len);

	if ( ret_len >= 0 )
		RETURN_LONG(ret_len);

	/* convert the string to UTF-16. */
	status = U_ZERO_ERROR;
	intl_convert_utf8_to_utf16(&ustring, &ustring_len, (char*) string, string_len, &status );

	if ( U_FAILURE( status ) ) {
		/* Set global error code. */
		intl_error_set_code( NULL, status TSRMLS_CC );

		/* Set error messages. */
		intl_error_set_custom_msg( NULL, "Error converting input string to UTF-16", 0 TSRMLS_CC );
		if (ustring) {
			efree( ustring );
		}
		RETURN_NULL();
	}

	ret_len = grapheme_split_string(ustring, ustring_len, NULL, 0 TSRMLS_CC );

	if (ustring) {
		efree( ustring );
	}

	if (ret_len >= 0) {
		RETVAL_LONG(ret_len);
	} else {
		RETVAL_FALSE;
	}
}

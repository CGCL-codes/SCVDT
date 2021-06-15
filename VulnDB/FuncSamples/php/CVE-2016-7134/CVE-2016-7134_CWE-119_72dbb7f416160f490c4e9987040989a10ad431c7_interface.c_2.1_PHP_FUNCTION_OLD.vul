PHP_FUNCTION(curl_unescape)
{
	char       *str = NULL, *out = NULL;
	size_t     str_len = 0;
	int        out_len;
	zval       *zid;
	php_curl   *ch;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &zid, &str, &str_len) == FAILURE) {
		return;
	}

	if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
		RETURN_FALSE;
	}

	if (str_len > INT_MAX) {
		RETURN_FALSE;
	}

	if ((out = curl_easy_unescape(ch->cp, str, str_len, &out_len))) {
		RETVAL_STRINGL(out, out_len);
		curl_free(out);
	} else {
		RETURN_FALSE;
	}
}

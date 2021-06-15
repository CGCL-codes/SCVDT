PHP_FUNCTION(constant)
{
	char *const_name;
	int const_name_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &const_name, &const_name_len) == FAILURE) {
		return;
	}

	if (!zend_get_constant_ex(const_name, const_name_len, return_value, NULL, ZEND_FETCH_CLASS_SILENT TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Couldn't find constant %s", const_name);
		RETURN_NULL();
	}
}

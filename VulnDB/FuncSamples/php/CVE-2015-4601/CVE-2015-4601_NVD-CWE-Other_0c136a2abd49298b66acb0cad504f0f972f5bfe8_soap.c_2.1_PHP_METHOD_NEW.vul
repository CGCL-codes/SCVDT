PHP_METHOD(SoapParam, SoapParam)
{
	zval *data;
	char *name;
	int name_length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &data, &name, &name_length) == FAILURE) {
		return;
	}
	if (name_length == 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid parameter name");
		return;
	}

	add_property_stringl(this_ptr, "param_name", name, name_length, 1);
	add_property_zval(this_ptr, "param_data", data);
}

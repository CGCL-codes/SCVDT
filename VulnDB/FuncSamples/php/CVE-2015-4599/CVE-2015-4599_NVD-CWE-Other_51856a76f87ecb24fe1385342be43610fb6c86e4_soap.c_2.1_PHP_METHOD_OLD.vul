PHP_METHOD(SoapFault, __toString)
{
	zval *faultcode, *faultstring, *file, *line, *trace;
	char *str;
	int len;
	zend_fcall_info fci;
	zval fname;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	faultcode   = zend_read_property(soap_fault_class_entry, this_ptr, "faultcode", sizeof("faultcode")-1, 1 TSRMLS_CC);
	faultstring = zend_read_property(soap_fault_class_entry, this_ptr, "faultstring", sizeof("faultstring")-1, 1 TSRMLS_CC);
	file = zend_read_property(soap_fault_class_entry, this_ptr, "file", sizeof("file")-1, 1 TSRMLS_CC);
	line = zend_read_property(soap_fault_class_entry, this_ptr, "line", sizeof("line")-1, 1 TSRMLS_CC);

	ZVAL_STRINGL(&fname, "gettraceasstring", sizeof("gettraceasstring")-1, 0);

	fci.size = sizeof(fci);
	fci.function_table = &Z_OBJCE_P(getThis())->function_table;
	fci.function_name = &fname;
	fci.symbol_table = NULL;
	fci.object_ptr = getThis();
	fci.retval_ptr_ptr = &trace;
	fci.param_count = 0;
	fci.params = NULL;
	fci.no_separation = 1;

	zend_call_function(&fci, NULL TSRMLS_CC);

	len = spprintf(&str, 0, "SoapFault exception: [%s] %s in %s:%ld\nStack trace:\n%s",
	               Z_STRVAL_P(faultcode), Z_STRVAL_P(faultstring), Z_STRVAL_P(file), Z_LVAL_P(line),
	               Z_STRLEN_P(trace) ? Z_STRVAL_P(trace) : "#0 {main}\n");

	zval_ptr_dtor(&trace);

	RETURN_STRINGL(str, len, 0);
}

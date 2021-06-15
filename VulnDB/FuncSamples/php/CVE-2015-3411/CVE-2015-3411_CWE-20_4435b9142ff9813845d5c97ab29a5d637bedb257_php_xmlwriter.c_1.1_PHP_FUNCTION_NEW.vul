static PHP_FUNCTION(xmlwriter_set_indent)
{
	zval *pind;
	xmlwriter_object *intern;
	xmlTextWriterPtr ptr;
	int retval;
	zend_bool indent;

#ifdef ZEND_ENGINE_2
	zval *this = getThis();
	
	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &indent) == FAILURE) {
			return;
		}
		XMLWRITER_FROM_OBJECT(intern, this);
	} else
#endif
	{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rb", &pind, &indent) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(intern,xmlwriter_object *, &pind, -1, "XMLWriter", le_xmlwriter);
	}


	ptr = intern->ptr;
	if (ptr) {
		retval = xmlTextWriterSetIndent(ptr, indent);
		if (retval == 0) {
			RETURN_TRUE;
		}
	}
	
	RETURN_FALSE;
}

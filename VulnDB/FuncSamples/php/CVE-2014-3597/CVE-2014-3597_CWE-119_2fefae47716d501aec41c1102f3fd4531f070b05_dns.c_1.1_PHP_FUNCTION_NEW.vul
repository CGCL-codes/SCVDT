PHP_FUNCTION(gethostname)
{
	char buf[HOST_NAME_MAX];

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	if (gethostname(buf, sizeof(buf) - 1)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "unable to fetch host [%d]: %s", errno, strerror(errno));
		RETURN_FALSE;
	}

	RETURN_STRING(buf, 1);
}

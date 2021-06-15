PHP_FUNCTION(readlink)
{
	char *link;
	size_t link_len;
	char target[MAXPATHLEN];

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "p", &link, &link_len) == FAILURE) {
		return;
	}

	if (OPENBASEDIR_CHECKPATH(link)) {
		RETURN_FALSE;
	}

	if (php_sys_readlink(link, target, MAXPATHLEN) == -1) {
		php_error_docref(NULL, E_WARNING, "readlink failed to read the symbolic link (%s), error %d)", link, GetLastError());
		RETURN_FALSE;
	}
	RETURN_STRING(target);
}

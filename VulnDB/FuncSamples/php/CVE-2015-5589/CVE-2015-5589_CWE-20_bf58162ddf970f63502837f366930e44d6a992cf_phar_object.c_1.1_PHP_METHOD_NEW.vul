PHP_METHOD(Phar, running)
{
	char *fname, *arch, *entry;
	int fname_len, arch_len, entry_len;
	zend_bool retphar = 1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &retphar) == FAILURE) {
		return;
	}

	fname = (char*)zend_get_executed_filename(TSRMLS_C);
	fname_len = strlen(fname);

	if (fname_len > 7 && !memcmp(fname, "phar://", 7) && SUCCESS == phar_split_fname(fname, fname_len, &arch, &arch_len, &entry, &entry_len, 2, 0 TSRMLS_CC)) {
		efree(entry);
		if (retphar) {
			RETVAL_STRINGL(fname, arch_len + 7, 1);
			efree(arch);
			return;
		} else {
			RETURN_STRINGL(arch, arch_len, 0);
		}
	}

	RETURN_STRINGL("", 0, 1);
}

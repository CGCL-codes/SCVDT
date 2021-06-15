static void php_html_entities(INTERNAL_FUNCTION_PARAMETERS, int all)
{
	char *str, *hint_charset = NULL;
	int str_len, hint_charset_len = 0;
	size_t new_len;
	long flags = ENT_COMPAT;
	char *replaced;
	zend_bool double_encode = 1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ls!b", &str, &str_len, &flags, &hint_charset, &hint_charset_len, &double_encode) == FAILURE) {
		return;
	}

	replaced = php_escape_html_entities_ex(str, str_len, &new_len, all, (int) flags, hint_charset, double_encode TSRMLS_CC);
	if (new_len > INT_MAX) {
		efree(replaced);
		RETURN_FALSE;
	}
	RETVAL_STRINGL(replaced, (int)new_len, 0);
}

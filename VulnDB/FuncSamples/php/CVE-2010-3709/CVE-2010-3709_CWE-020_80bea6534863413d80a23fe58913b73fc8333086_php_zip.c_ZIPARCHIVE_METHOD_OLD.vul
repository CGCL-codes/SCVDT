static ZIPARCHIVE_METHOD(getCommentIndex)
{
	struct zip *intern;
	zval *this = getThis();
	long index, flags = 0;
	const char * comment;
	int comment_len = 0;
	struct zip_stat sb;

	if (!this) {
		RETURN_FALSE;
	}

	ZIP_FROM_OBJECT(intern, this);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l",
				&index, &flags) == FAILURE) {
		return;
	}

	PHP_ZIP_STAT_INDEX(intern, index, 0, sb);
	comment = zip_get_file_comment(intern, index, &comment_len, (int)flags);
	RETURN_STRINGL((char *)comment, (long)comment_len, 1);
}

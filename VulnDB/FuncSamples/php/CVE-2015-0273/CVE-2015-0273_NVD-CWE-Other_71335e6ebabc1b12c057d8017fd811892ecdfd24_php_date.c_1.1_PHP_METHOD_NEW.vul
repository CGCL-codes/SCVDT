PHP_METHOD(DateTime, __construct)
{
	zval *timezone_object = NULL;
	char *time_str = NULL;
	int time_str_len = 0;
	zend_error_handling error_handling;

	zend_replace_error_handling(EH_THROW, NULL, &error_handling TSRMLS_CC);
	if (SUCCESS == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sO!", &time_str, &time_str_len, &timezone_object, date_ce_timezone)) {
		php_date_initialize(zend_object_store_get_object(getThis() TSRMLS_CC), time_str, time_str_len, NULL, timezone_object, 1 TSRMLS_CC);
	}
	zend_restore_error_handling(&error_handling TSRMLS_CC);
}

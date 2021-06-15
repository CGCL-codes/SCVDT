PHP_FUNCTION(curl_version)
{
	curl_version_info_data *d;
	zend_long uversion = CURLVERSION_NOW;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &uversion) == FAILURE) {
		return;
	}

	d = curl_version_info(uversion);
	if (d == NULL) {
		RETURN_FALSE;
	}

	array_init(return_value);

	CAAL("version_number", d->version_num);
	CAAL("age", d->age);
	CAAL("features", d->features);
	CAAL("ssl_version_number", d->ssl_version_num);
	CAAS("version", d->version);
	CAAS("host", d->host);
	CAAS("ssl_version", d->ssl_version);
	CAAS("libz_version", d->libz_version);
	/* Add an array of protocols */
	{
		char **p = (char **) d->protocols;
		zval protocol_list;

		array_init(&protocol_list);

		while (*p != NULL) {
			add_next_index_string(&protocol_list, *p);
			p++;
		}
		CAAZ("protocols", &protocol_list);
	}
}

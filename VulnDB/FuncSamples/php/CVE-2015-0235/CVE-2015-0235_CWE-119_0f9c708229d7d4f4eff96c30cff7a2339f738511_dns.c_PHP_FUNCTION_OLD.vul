PHP_FUNCTION(gethostbynamel)
{
	char *hostname;
	int hostname_len;
	struct hostent *hp;
	struct in_addr in;
	int i;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &hostname, &hostname_len) == FAILURE) {
		return;
	}

	hp = gethostbyname(hostname);
	if (hp == NULL || hp->h_addr_list == NULL) {
		RETURN_FALSE;
	}

	array_init(return_value);

	for (i = 0 ; hp->h_addr_list[i] != 0 ; i++) {
		in = *(struct in_addr *) hp->h_addr_list[i];
		add_next_index_string(return_value, inet_ntoa(in), 1);
	}
}

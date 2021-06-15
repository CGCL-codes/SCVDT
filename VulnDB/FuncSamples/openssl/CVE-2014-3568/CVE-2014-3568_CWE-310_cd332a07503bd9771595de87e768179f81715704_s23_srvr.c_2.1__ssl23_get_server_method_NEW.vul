static SSL_METHOD *ssl23_get_server_method(int ver)
	{
#ifndef OPENSSL_NO_SSL2
	if (ver == SSL2_VERSION)
		return(SSLv2_server_method());
#endif
#ifndef OPENSSL_NO_SSL3
	if (ver == SSL3_VERSION)
		return(SSLv3_server_method());
#endif
	if (ver == TLS1_VERSION)
		return(TLSv1_server_method());
	else
		return(NULL);
	}

PHP_FUNCTION(openssl_get_cert_locations)
{
	array_init(return_value);

	add_assoc_string(return_value, "default_cert_file", (char *) X509_get_default_cert_file(), 1);
	add_assoc_string(return_value, "default_cert_file_env", (char *) X509_get_default_cert_file_env(), 1);
	add_assoc_string(return_value, "default_cert_dir", (char *) X509_get_default_cert_dir(), 1);
	add_assoc_string(return_value, "default_cert_dir_env", (char *) X509_get_default_cert_dir_env(), 1);
	add_assoc_string(return_value, "default_private_dir", (char *) X509_get_default_private_dir(), 1);
	add_assoc_string(return_value, "default_default_cert_area", (char *) X509_get_default_cert_area(), 1);
	add_assoc_string(return_value, "ini_cafile",
		zend_ini_string("openssl.cafile", sizeof("openssl.cafile"), 0), 1);
	add_assoc_string(return_value, "ini_capath",
		zend_ini_string("openssl.capath", sizeof("openssl.capath"), 0), 1);
}

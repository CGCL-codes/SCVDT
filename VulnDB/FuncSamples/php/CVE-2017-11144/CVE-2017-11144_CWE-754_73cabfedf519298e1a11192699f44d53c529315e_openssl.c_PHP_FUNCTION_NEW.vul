PHP_FUNCTION(openssl_get_cert_locations)
{
	array_init(return_value);

	add_assoc_string(return_value, "default_cert_file", (char *) X509_get_default_cert_file());
	add_assoc_string(return_value, "default_cert_file_env", (char *) X509_get_default_cert_file_env());
	add_assoc_string(return_value, "default_cert_dir", (char *) X509_get_default_cert_dir());
	add_assoc_string(return_value, "default_cert_dir_env", (char *) X509_get_default_cert_dir_env());
	add_assoc_string(return_value, "default_private_dir", (char *) X509_get_default_private_dir());
	add_assoc_string(return_value, "default_default_cert_area", (char *) X509_get_default_cert_area());
	add_assoc_string(return_value, "ini_cafile",
		zend_ini_string("openssl.cafile", sizeof("openssl.cafile")-1, 0));
	add_assoc_string(return_value, "ini_capath",
		zend_ini_string("openssl.capath", sizeof("openssl.capath")-1, 0));
}

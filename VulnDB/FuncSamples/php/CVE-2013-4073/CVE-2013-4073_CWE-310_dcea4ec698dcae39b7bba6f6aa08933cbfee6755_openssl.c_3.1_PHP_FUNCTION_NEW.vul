PHP_FUNCTION(openssl_x509_export_to_file)
{
	X509 * cert;
	zval ** zcert;
	zend_bool notext = 1;
	BIO * bio_out;
	long certresource;
	char * filename;
	int filename_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Zs|b", &zcert, &filename, &filename_len, &notext) == FAILURE) {
		return;
	}
	RETVAL_FALSE;

	cert = php_openssl_x509_from_zval(zcert, 0, &certresource TSRMLS_CC);
	if (cert == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot get cert from parameter 1");
		return;
	}

	if (php_openssl_safe_mode_chk(filename TSRMLS_CC)) {
		return;
	}

	bio_out = BIO_new_file(filename, "w");
	if (bio_out) {
		if (!notext) {
			X509_print(bio_out, cert);
		}
		PEM_write_bio_X509(bio_out, cert);

		RETVAL_TRUE;
	} else {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "error opening file %s", filename);
	}
	if (certresource == -1 && cert) {
		X509_free(cert);
	}
	BIO_free(bio_out);
}

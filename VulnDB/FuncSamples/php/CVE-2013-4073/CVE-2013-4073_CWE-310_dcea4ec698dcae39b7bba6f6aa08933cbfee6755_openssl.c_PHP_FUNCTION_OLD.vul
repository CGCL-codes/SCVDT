PHP_FUNCTION(openssl_x509_parse)
{
	zval ** zcert;
	X509 * cert = NULL;
	long certresource = -1;
	int i;
	zend_bool useshortnames = 1;
	char * tmpstr;
	zval * subitem;
	X509_EXTENSION *extension;
	char *extname;
	BIO  *bio_out;
	BUF_MEM *bio_buf;
	char buf[256];

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Z|b", &zcert, &useshortnames) == FAILURE) {
		return;
	}
	cert = php_openssl_x509_from_zval(zcert, 0, &certresource TSRMLS_CC);
	if (cert == NULL) {
		RETURN_FALSE;
	}
	array_init(return_value);

	if (cert->name) {
		add_assoc_string(return_value, "name", cert->name, 1);
	}
/*	add_assoc_bool(return_value, "valid", cert->valid); */

	add_assoc_name_entry(return_value, "subject", 		X509_get_subject_name(cert), useshortnames TSRMLS_CC);
	/* hash as used in CA directories to lookup cert by subject name */
	{
		char buf[32];
		snprintf(buf, sizeof(buf), "%08lx", X509_subject_name_hash(cert));
		add_assoc_string(return_value, "hash", buf, 1);
	}
	
	add_assoc_name_entry(return_value, "issuer", 		X509_get_issuer_name(cert), useshortnames TSRMLS_CC);
	add_assoc_long(return_value, "version", 			X509_get_version(cert));

	add_assoc_string(return_value, "serialNumber", i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(cert)), 1); 

	add_assoc_asn1_string(return_value, "validFrom", 	X509_get_notBefore(cert));
	add_assoc_asn1_string(return_value, "validTo", 		X509_get_notAfter(cert));

	add_assoc_long(return_value, "validFrom_time_t", 	asn1_time_to_time_t(X509_get_notBefore(cert) TSRMLS_CC));
	add_assoc_long(return_value, "validTo_time_t", 		asn1_time_to_time_t(X509_get_notAfter(cert) TSRMLS_CC));

	tmpstr = (char *)X509_alias_get0(cert, NULL);
	if (tmpstr) {
		add_assoc_string(return_value, "alias", tmpstr, 1);
	}
/*
	add_assoc_long(return_value, "signaturetypeLONG", X509_get_signature_type(cert));
	add_assoc_string(return_value, "signaturetype", OBJ_nid2sn(X509_get_signature_type(cert)), 1);
	add_assoc_string(return_value, "signaturetypeLN", OBJ_nid2ln(X509_get_signature_type(cert)), 1);
*/
	MAKE_STD_ZVAL(subitem);
	array_init(subitem);

	/* NOTE: the purposes are added as integer keys - the keys match up to the X509_PURPOSE_SSL_XXX defines
	   in x509v3.h */
	for (i = 0; i < X509_PURPOSE_get_count(); i++) {
		int id, purpset;
		char * pname;
		X509_PURPOSE * purp;
		zval * subsub;

		MAKE_STD_ZVAL(subsub);
		array_init(subsub);

		purp = X509_PURPOSE_get0(i);
		id = X509_PURPOSE_get_id(purp);

		purpset = X509_check_purpose(cert, id, 0);
		add_index_bool(subsub, 0, purpset);

		purpset = X509_check_purpose(cert, id, 1);
		add_index_bool(subsub, 1, purpset);

		pname = useshortnames ? X509_PURPOSE_get0_sname(purp) : X509_PURPOSE_get0_name(purp);
		add_index_string(subsub, 2, pname, 1);

		/* NOTE: if purpset > 1 then it's a warning - we should mention it ? */

		add_index_zval(subitem, id, subsub);
	}
	add_assoc_zval(return_value, "purposes", subitem);

	MAKE_STD_ZVAL(subitem);
	array_init(subitem);


	for (i = 0; i < X509_get_ext_count(cert); i++) {
		extension = X509_get_ext(cert, i);
		if (OBJ_obj2nid(X509_EXTENSION_get_object(extension)) != NID_undef) {
			extname = (char *)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(extension)));
		} else {
			OBJ_obj2txt(buf, sizeof(buf)-1, X509_EXTENSION_get_object(extension), 1);
			extname = buf;
		}
		bio_out = BIO_new(BIO_s_mem());
		if (X509V3_EXT_print(bio_out, extension, 0, 0)) {
			BIO_get_mem_ptr(bio_out, &bio_buf);
			add_assoc_stringl(subitem, extname, bio_buf->data, bio_buf->length, 1);
		} else {
			add_assoc_asn1_string(subitem, extname, X509_EXTENSION_get_data(extension));
		}
		BIO_free(bio_out);
	}
	add_assoc_zval(return_value, "extensions", subitem);

	if (certresource == -1 && cert) {
		X509_free(cert);
	}
}

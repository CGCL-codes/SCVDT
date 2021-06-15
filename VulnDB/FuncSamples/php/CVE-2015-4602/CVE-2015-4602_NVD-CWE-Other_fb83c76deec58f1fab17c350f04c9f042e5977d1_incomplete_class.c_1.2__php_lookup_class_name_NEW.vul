PHPAPI char *php_lookup_class_name(zval *object, zend_uint *nlen)
{
	zval **val;
	char *retval = NULL;
	HashTable *object_properties;
	TSRMLS_FETCH();

	object_properties = Z_OBJPROP_P(object);

	if (zend_hash_find(object_properties, MAGIC_MEMBER, sizeof(MAGIC_MEMBER), (void **) &val) == SUCCESS && Z_TYPE_PP(val) == IS_STRING) {
		retval = estrndup(Z_STRVAL_PP(val), Z_STRLEN_PP(val));

		if (nlen) {
			*nlen = Z_STRLEN_PP(val);
		}
	}

	return retval;
}

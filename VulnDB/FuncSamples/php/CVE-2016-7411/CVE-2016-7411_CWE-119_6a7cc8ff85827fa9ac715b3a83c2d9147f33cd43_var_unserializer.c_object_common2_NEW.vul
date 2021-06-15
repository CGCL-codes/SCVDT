static inline int object_common2(UNSERIALIZE_PARAMETER, long elements)
{
	zval *retval_ptr = NULL;
	zval fname;

	if (Z_TYPE_PP(rval) != IS_OBJECT) {
		return 0;
	}

	if (!process_nested_data(UNSERIALIZE_PASSTHRU, Z_OBJPROP_PP(rval), elements, 1)) {
	    /* We've got partially constructed object on our hands here. Wipe it. */
	    if(Z_TYPE_PP(rval) == IS_OBJECT) {
	       zend_hash_clean(Z_OBJPROP_PP(rval));
	       zend_object_store_ctor_failed(*rval TSRMLS_CC);
	    }
	    ZVAL_NULL(*rval);
		return 0;
	}

    if (Z_TYPE_PP(rval) != IS_OBJECT) {
        return 0;
    }

	if (Z_OBJCE_PP(rval) != PHP_IC_ENTRY &&
		zend_hash_exists(&Z_OBJCE_PP(rval)->function_table, "__wakeup", sizeof("__wakeup"))) {
		INIT_PZVAL(&fname);
		ZVAL_STRINGL(&fname, "__wakeup", sizeof("__wakeup") - 1, 0);
		BG(serialize_lock)++;
		call_user_function_ex(CG(function_table), rval, &fname, &retval_ptr, 0, 0, 1, NULL TSRMLS_CC);
		BG(serialize_lock)--;
	}

	if (retval_ptr) {
		zval_ptr_dtor(&retval_ptr);
	}

	if (EG(exception)) {
		return 0;
	}

	return finish_nested_data(UNSERIALIZE_PASSTHRU);

}

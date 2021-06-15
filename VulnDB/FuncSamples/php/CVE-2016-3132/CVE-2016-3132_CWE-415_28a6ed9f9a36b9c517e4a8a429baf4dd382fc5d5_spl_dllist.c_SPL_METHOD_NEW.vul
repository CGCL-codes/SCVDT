SPL_METHOD(SplDoublyLinkedList, push)
{
	zval *value;
	spl_dllist_object *intern;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &value) == FAILURE) {
		return;
	}

	intern = Z_SPLDLLIST_P(getThis());
	spl_ptr_llist_push(intern->llist, value);

	RETURN_TRUE;
}

static inline long object_common1(UNSERIALIZE_PARAMETER, zend_class_entry *ce)
{
	long elements;

	elements = parse_iv2((*p) + 2, p);

	(*p) += 2;

	if (ce->serialize == NULL) {
		object_init_ex(*rval, ce);
	} else {
		/* If this class implements Serializable, it should not land here but in object_custom(). The passed string
		obviously doesn't descend from the regular serializer. */
		zend_error(E_WARNING, "Erroneous data format for unserializing '%s'", ce->name);
		return 0;
	}

	return elements;
}

PHP_METHOD(PharFileInfo, getCompressedSize)
{
	PHAR_ENTRY_OBJECT();
	
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	RETURN_LONG(entry_obj->ent.entry->compressed_filesize);
}

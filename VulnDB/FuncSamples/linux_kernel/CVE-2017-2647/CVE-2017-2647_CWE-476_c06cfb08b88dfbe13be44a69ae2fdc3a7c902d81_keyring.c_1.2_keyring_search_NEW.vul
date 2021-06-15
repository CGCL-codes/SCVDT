key_ref_t keyring_search(key_ref_t keyring,
			 struct key_type *type,
			 const char *description)
{
	struct keyring_search_context ctx = {
		.index_key.type		= type,
		.index_key.description	= description,
		.cred			= current_cred(),
		.match_data.cmp		= key_default_cmp,
		.match_data.raw_data	= description,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
		.flags			= KEYRING_SEARCH_DO_STATE_CHECK,
	};
	key_ref_t key;
	int ret;

	if (type->match_preparse) {
		ret = type->match_preparse(&ctx.match_data);
		if (ret < 0)
			return ERR_PTR(ret);
	}

	key = keyring_search_aux(keyring, &ctx);

	if (type->match_free)
		type->match_free(&ctx.match_data);
	return key;
}

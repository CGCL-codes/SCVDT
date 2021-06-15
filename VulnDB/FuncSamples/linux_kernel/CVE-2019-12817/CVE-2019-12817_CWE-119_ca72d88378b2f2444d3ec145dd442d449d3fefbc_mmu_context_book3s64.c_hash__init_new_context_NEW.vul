static int hash__init_new_context(struct mm_struct *mm)
{
	int index;

	/*
	 * The old code would re-promote on fork, we don't do that when using
	 * slices as it could cause problem promoting slices that have been
	 * forced down to 4K.
	 *
	 * For book3s we have MMU_NO_CONTEXT set to be ~0. Hence check
	 * explicitly against context.id == 0. This ensures that we properly
	 * initialize context slice details for newly allocated mm's (which will
	 * have id == 0) and don't alter context slice inherited via fork (which
	 * will have id != 0).
	 *
	 * We should not be calling init_new_context() on init_mm. Hence a
	 * check against 0 is OK.
	 */
	if (mm->context.id == 0)
		slice_init_new_context_exec(mm);

	index = realloc_context_ids(&mm->context);
	if (index < 0)
		return index;

	subpage_prot_init_new_context(mm);

	pkey_mm_init(mm);
	return index;
}

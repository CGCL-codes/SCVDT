static int f2fs_set_data_page_dirty(struct page *page)
{
	struct inode *inode = page_file_mapping(page)->host;

	trace_f2fs_set_page_dirty(page, DATA);

	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (PageSwapCache(page))
		return __set_page_dirty_nobuffers(page);

	if (f2fs_is_atomic_file(inode) && !f2fs_is_commit_atomic_write(inode)) {
		if (!IS_ATOMIC_WRITTEN_PAGE(page)) {
			f2fs_register_inmem_page(inode, page);
			return 1;
		}
		/*
		 * Previously, this page has been registered, we just
		 * return here.
		 */
		return 0;
	}

	if (!PageDirty(page)) {
		__set_page_dirty_nobuffers(page);
		f2fs_update_dirty_page(inode, page);
		return 1;
	}
	return 0;
}

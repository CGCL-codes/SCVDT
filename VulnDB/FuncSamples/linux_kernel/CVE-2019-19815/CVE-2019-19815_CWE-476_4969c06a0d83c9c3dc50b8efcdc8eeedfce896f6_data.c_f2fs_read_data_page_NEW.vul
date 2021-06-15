static int f2fs_read_data_page(struct file *file, struct page *page)
{
	struct inode *inode = page_file_mapping(page)->host;
	int ret = -EAGAIN;

	trace_f2fs_readpage(page, DATA);

	/* If the file has inline data, try to read it directly */
	if (f2fs_has_inline_data(inode))
		ret = f2fs_read_inline_data(inode, page);
	if (ret == -EAGAIN)
		ret = f2fs_mpage_readpages(page_file_mapping(page),
						NULL, page, 1, false);
	return ret;
}

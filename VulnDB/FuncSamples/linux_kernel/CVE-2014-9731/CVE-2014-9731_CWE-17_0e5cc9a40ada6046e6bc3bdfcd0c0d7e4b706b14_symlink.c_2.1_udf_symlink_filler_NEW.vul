static int udf_symlink_filler(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *bh = NULL;
	unsigned char *symlink;
	int err;
	unsigned char *p = kmap(page);
	struct udf_inode_info *iinfo;
	uint32_t pos;

	/* We don't support symlinks longer than one block */
	if (inode->i_size > inode->i_sb->s_blocksize) {
		err = -ENAMETOOLONG;
		goto out_unmap;
	}

	iinfo = UDF_I(inode);
	pos = udf_block_map(inode, 0);

	down_read(&iinfo->i_data_sem);
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
		symlink = iinfo->i_ext.i_data + iinfo->i_lenEAttr;
	} else {
		bh = sb_bread(inode->i_sb, pos);

		if (!bh) {
			err = -EIO;
			goto out_unlock_inode;
		}

		symlink = bh->b_data;
	}

	err = udf_pc_to_char(inode->i_sb, symlink, inode->i_size, p, PAGE_SIZE);
	brelse(bh);
	if (err)
		goto out_unlock_inode;

	up_read(&iinfo->i_data_sem);
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;

out_unlock_inode:
	up_read(&iinfo->i_data_sem);
	SetPageError(page);
out_unmap:
	kunmap(page);
	unlock_page(page);
	return err;
}

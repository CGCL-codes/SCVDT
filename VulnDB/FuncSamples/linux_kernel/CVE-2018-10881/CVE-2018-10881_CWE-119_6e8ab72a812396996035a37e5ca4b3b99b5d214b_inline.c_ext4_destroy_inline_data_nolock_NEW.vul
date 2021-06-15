static int ext4_destroy_inline_data_nolock(handle_t *handle,
					   struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_xattr_ibody_find is = {
		.s = { .not_found = 0, },
	};
	struct ext4_xattr_info i = {
		.name_index = EXT4_XATTR_INDEX_SYSTEM,
		.name = EXT4_XATTR_SYSTEM_DATA,
		.value = NULL,
		.value_len = 0,
	};
	int error;

	if (!ei->i_inline_off)
		return 0;

	error = ext4_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ext4_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	BUFFER_TRACE(is.iloc.bh, "get_write_access");
	error = ext4_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto out;

	error = ext4_xattr_ibody_inline_set(handle, inode, &i, &is);
	if (error)
		goto out;

	memset((void *)ext4_raw_inode(&is.iloc)->i_block,
		0, EXT4_MIN_INLINE_DATA_SIZE);
	memset(ei->i_data, 0, EXT4_MIN_INLINE_DATA_SIZE);

	if (ext4_has_feature_extents(inode->i_sb)) {
		if (S_ISDIR(inode->i_mode) ||
		    S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
			ext4_set_inode_flag(inode, EXT4_INODE_EXTENTS);
			ext4_ext_tree_init(handle, inode);
		}
	}
	ext4_clear_inode_flag(inode, EXT4_INODE_INLINE_DATA);

	get_bh(is.iloc.bh);
	error = ext4_mark_iloc_dirty(handle, inode, &is.iloc);

	EXT4_I(inode)->i_inline_off = 0;
	EXT4_I(inode)->i_inline_size = 0;
	ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
out:
	brelse(is.iloc.bh);
	if (error == -ENODATA)
		error = 0;
	return error;
}

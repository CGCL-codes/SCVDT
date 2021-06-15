int ext4_find_inline_data_nolock(struct inode *inode)
{
	struct ext4_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ext4_xattr_info i = {
		.name_index = EXT4_XATTR_INDEX_SYSTEM,
		.name = EXT4_XATTR_SYSTEM_DATA,
	};
	int error;

	if (EXT4_I(inode)->i_extra_isize == 0)
		return 0;

	error = ext4_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ext4_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	if (!is.s.not_found) {
		EXT4_I(inode)->i_inline_off = (u16)((void *)is.s.here -
					(void *)ext4_raw_inode(&is.iloc));
		EXT4_I(inode)->i_inline_size = EXT4_MIN_INLINE_DATA_SIZE +
				le32_to_cpu(is.s.here->e_value_size);
		ext4_set_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
	}
out:
	brelse(is.iloc.bh);
	return error;
}

static int
ext4_xattr_check_entries(struct ext4_xattr_entry *entry, void *end,
			 void *value_start)
{
	struct ext4_xattr_entry *e = entry;

	/* Find the end of the names list */
	while (!IS_LAST_ENTRY(e)) {
		struct ext4_xattr_entry *next = EXT4_XATTR_NEXT(e);
		if ((void *)next >= end)
			return -EFSCORRUPTED;
		e = next;
	}

	/* Check the values */
	while (!IS_LAST_ENTRY(entry)) {
		if (entry->e_value_size != 0 &&
		    entry->e_value_inum == 0) {
			u16 offs = le16_to_cpu(entry->e_value_offs);
			u32 size = le32_to_cpu(entry->e_value_size);
			void *value;

			/*
			 * The value cannot overlap the names, and the value
			 * with padding cannot extend beyond 'end'.  Check both
			 * the padded and unpadded sizes, since the size may
			 * overflow to 0 when adding padding.
			 */
			if (offs > end - value_start)
				return -EFSCORRUPTED;
			value = value_start + offs;
			if (value < (void *)e + sizeof(u32) ||
			    size > end - value ||
			    EXT4_XATTR_SIZE(size) > end - value)
				return -EFSCORRUPTED;
		}
		entry = EXT4_XATTR_NEXT(entry);
	}

	return 0;
}

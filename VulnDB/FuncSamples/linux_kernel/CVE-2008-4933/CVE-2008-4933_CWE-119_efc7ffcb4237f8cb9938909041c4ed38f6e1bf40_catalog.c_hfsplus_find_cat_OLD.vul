int hfsplus_find_cat(struct super_block *sb, u32 cnid,
		     struct hfs_find_data *fd)
{
	hfsplus_cat_entry tmp;
	int err;
	u16 type;

	hfsplus_cat_build_key(sb, fd->search_key, cnid, NULL);
	err = hfs_brec_read(fd, &tmp, sizeof(hfsplus_cat_entry));
	if (err)
		return err;

	type = be16_to_cpu(tmp.type);
	if (type != HFSPLUS_FOLDER_THREAD && type != HFSPLUS_FILE_THREAD) {
		printk(KERN_ERR "hfs: found bad thread record in catalog\n");
		return -EIO;
	}

	hfsplus_cat_build_key_uni(fd->search_key, be32_to_cpu(tmp.thread.parentID),
				 &tmp.thread.nodeName);
	return hfs_brec_find(fd);
}

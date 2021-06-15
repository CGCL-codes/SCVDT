static int rock_continue(struct rock_state *rs)
{
	int ret = 1;
	int blocksize = 1 << rs->inode->i_blkbits;
	const int min_de_size = offsetof(struct rock_ridge, u);

	kfree(rs->buffer);
	rs->buffer = NULL;

	if ((unsigned)rs->cont_offset > blocksize - min_de_size ||
	    (unsigned)rs->cont_size > blocksize ||
	    (unsigned)(rs->cont_offset + rs->cont_size) > blocksize) {
		printk(KERN_NOTICE "rock: corrupted directory entry. "
			"extent=%d, offset=%d, size=%d\n",
			rs->cont_extent, rs->cont_offset, rs->cont_size);
		ret = -EIO;
		goto out;
	}

	if (rs->cont_extent) {
		struct buffer_head *bh;

		rs->buffer = kmalloc(rs->cont_size, GFP_KERNEL);
		if (!rs->buffer) {
			ret = -ENOMEM;
			goto out;
		}
		ret = -EIO;
		bh = sb_bread(rs->inode->i_sb, rs->cont_extent);
		if (bh) {
			memcpy(rs->buffer, bh->b_data + rs->cont_offset,
					rs->cont_size);
			put_bh(bh);
			rs->chr = rs->buffer;
			rs->len = rs->cont_size;
			rs->cont_extent = 0;
			rs->cont_size = 0;
			rs->cont_offset = 0;
			return 0;
		}
		printk("Unable to read rock-ridge attributes\n");
	}
out:
	kfree(rs->buffer);
	rs->buffer = NULL;
	return ret;
}

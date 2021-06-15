static int fuse_notify_inval_entry(struct fuse_conn *fc, unsigned int size,
				   struct fuse_copy_state *cs)
{
	struct fuse_notify_inval_entry_out outarg;
	int err = -ENOMEM;
	char *buf;
	struct qstr name;

	buf = kzalloc(FUSE_NAME_MAX + 1, GFP_KERNEL);
	if (!buf)
		goto err;

	err = -EINVAL;
	if (size < sizeof(outarg))
		goto err;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		goto err;

	err = -ENAMETOOLONG;
	if (outarg.namelen > FUSE_NAME_MAX)
		goto err;

	name.name = buf;
	name.len = outarg.namelen;
	err = fuse_copy_one(cs, buf, outarg.namelen + 1);
	if (err)
		goto err;
	fuse_copy_finish(cs);
	buf[outarg.namelen] = 0;
	name.hash = full_name_hash(name.name, name.len);

	down_read(&fc->killsb);
	err = -ENOENT;
	if (fc->sb)
		err = fuse_reverse_inval_entry(fc->sb, outarg.parent, &name);
	up_read(&fc->killsb);
	kfree(buf);
	return err;

err:
	kfree(buf);
	fuse_copy_finish(cs);
	return err;
}

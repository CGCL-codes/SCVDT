int ovl_permission(struct inode *inode, int mask)
{
	struct ovl_entry *oe;
	struct dentry *alias = NULL;
	struct inode *realinode;
	struct dentry *realdentry;
	bool is_upper;
	int err;

	if (S_ISDIR(inode->i_mode)) {
		oe = inode->i_private;
	} else if (mask & MAY_NOT_BLOCK) {
		return -ECHILD;
	} else {
		/*
		 * For non-directories find an alias and get the info
		 * from there.
		 */
		alias = d_find_any_alias(inode);
		if (WARN_ON(!alias))
			return -ENOENT;

		oe = alias->d_fsdata;
	}

	realdentry = ovl_entry_real(oe, &is_upper);

	/* Careful in RCU walk mode */
	realinode = ACCESS_ONCE(realdentry->d_inode);
	if (!realinode) {
		WARN_ON(!(mask & MAY_NOT_BLOCK));
		err = -ENOENT;
		goto out_dput;
	}

	if (mask & MAY_WRITE) {
		umode_t mode = realinode->i_mode;

		/*
		 * Writes will always be redirected to upper layer, so
		 * ignore lower layer being read-only.
		 *
		 * If the overlay itself is read-only then proceed
		 * with the permission check, don't return EROFS.
		 * This will only happen if this is the lower layer of
		 * another overlayfs.
		 *
		 * If upper fs becomes read-only after the overlay was
		 * constructed return EROFS to prevent modification of
		 * upper layer.
		 */
		err = -EROFS;
		if (is_upper && !IS_RDONLY(inode) && IS_RDONLY(realinode) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			goto out_dput;
	}

	err = __inode_permission(realinode, mask);
out_dput:
	dput(alias);
	return err;
}

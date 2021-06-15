static struct mnt_namespace *create_mnt_ns(struct vfsmount *m)
{
	struct mnt_namespace *new_ns = alloc_mnt_ns(&init_user_ns);
	if (!IS_ERR(new_ns)) {
		struct mount *mnt = real_mount(m);
		mnt->mnt_ns = new_ns;
		new_ns->root = mnt;
		list_add(&mnt->mnt_list, &new_ns->list);
	} else {
		mntput(m);
	}
	return new_ns;
}

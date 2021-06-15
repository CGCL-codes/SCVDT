struct vfsmount *collect_mounts(struct path *path)
{
	struct mount *tree;
	namespace_lock();
	tree = copy_tree(real_mount(path->mnt), path->dentry,
			 CL_COPY_ALL | CL_PRIVATE);
	namespace_unlock();
	if (IS_ERR(tree))
		return ERR_CAST(tree);
	return &tree->mnt;
}

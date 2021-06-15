static int do_change_type(struct nameidata *nd, int flag)
{
	struct vfsmount *m, *mnt = nd->mnt;
	int recurse = flag & MS_REC;
	int type = flag & ~MS_REC;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (nd->dentry != nd->mnt->mnt_root)
		return -EINVAL;

	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);
	for (m = mnt; m; m = (recurse ? next_mnt(m, mnt) : NULL))
		change_mnt_propagation(m, type);
	spin_unlock(&vfsmount_lock);
	up_write(&namespace_sem);
	return 0;
}

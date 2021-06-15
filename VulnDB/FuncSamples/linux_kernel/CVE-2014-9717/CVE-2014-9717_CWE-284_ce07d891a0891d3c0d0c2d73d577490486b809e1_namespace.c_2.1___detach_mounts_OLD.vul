void __detach_mounts(struct dentry *dentry)
{
	struct mountpoint *mp;
	struct mount *mnt;

	namespace_lock();
	mp = lookup_mountpoint(dentry);
	if (!mp)
		goto out_unlock;

	lock_mount_hash();
	while (!hlist_empty(&mp->m_list)) {
		mnt = hlist_entry(mp->m_list.first, struct mount, mnt_mp_list);
		umount_tree(mnt, 0);
	}
	unlock_mount_hash();
	put_mountpoint(mp);
out_unlock:
	namespace_unlock();
}

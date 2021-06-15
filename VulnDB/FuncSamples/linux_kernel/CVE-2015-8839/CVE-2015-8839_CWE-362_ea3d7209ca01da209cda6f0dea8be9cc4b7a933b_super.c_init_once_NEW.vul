static void init_once(void *foo)
{
	struct ext4_inode_info *ei = (struct ext4_inode_info *) foo;

	INIT_LIST_HEAD(&ei->i_orphan);
	init_rwsem(&ei->xattr_sem);
	init_rwsem(&ei->i_data_sem);
	init_rwsem(&ei->i_mmap_sem);
	inode_init_once(&ei->vfs_inode);
}

static int proc_pid_permission(struct inode *inode, int mask)
{
	struct pid_namespace *pid = inode->i_sb->s_fs_info;
	struct task_struct *task;
	bool has_perms;

	task = get_proc_task(inode);
	if (!task)
		return -ESRCH;
	has_perms = has_pid_permissions(pid, task, 1);
	put_task_struct(task);

	if (!has_perms) {
		if (pid->hide_pid == 2) {
			/*
			 * Let's make getdents(), stat(), and open()
			 * consistent with each other.  If a process
			 * may not stat() a file, it shouldn't be seen
			 * in procfs at all.
			 */
			return -ENOENT;
		}

		return -EPERM;
	}
	return generic_permission(inode, mask);
}

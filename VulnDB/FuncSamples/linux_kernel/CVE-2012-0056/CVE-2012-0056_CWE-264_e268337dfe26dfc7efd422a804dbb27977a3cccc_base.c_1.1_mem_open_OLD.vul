static int mem_open(struct inode* inode, struct file* file)
{
	file->private_data = (void*)((long)current->self_exec_id);
	/* OK to pass negative loff_t, we can catch out-of-range */
	file->f_mode |= FMODE_UNSIGNED_OFFSET;
	return 0;
}

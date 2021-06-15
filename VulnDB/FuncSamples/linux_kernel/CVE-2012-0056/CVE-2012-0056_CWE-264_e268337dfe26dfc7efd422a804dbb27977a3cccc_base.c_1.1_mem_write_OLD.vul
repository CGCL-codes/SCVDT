static ssize_t mem_write(struct file * file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	int copied;
	char *page;
	struct task_struct *task = get_proc_task(file->f_path.dentry->d_inode);
	unsigned long dst = *ppos;
	struct mm_struct *mm;

	copied = -ESRCH;
	if (!task)
		goto out_no_task;

	copied = -ENOMEM;
	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page)
		goto out_task;

	mm = check_mem_permission(task);
	copied = PTR_ERR(mm);
	if (IS_ERR(mm))
		goto out_free;

	copied = -EIO;
	if (file->private_data != (void *)((long)current->self_exec_id))
		goto out_mm;

	copied = 0;
	while (count > 0) {
		int this_len, retval;

		this_len = (count > PAGE_SIZE) ? PAGE_SIZE : count;
		if (copy_from_user(page, buf, this_len)) {
			copied = -EFAULT;
			break;
		}
		retval = access_remote_vm(mm, dst, page, this_len, 1);
		if (!retval) {
			if (!copied)
				copied = -EIO;
			break;
		}
		copied += retval;
		buf += retval;
		dst += retval;
		count -= retval;			
	}
	*ppos = dst;

out_mm:
	mmput(mm);
out_free:
	free_page((unsigned long) page);
out_task:
	put_task_struct(task);
out_no_task:
	return copied;
}

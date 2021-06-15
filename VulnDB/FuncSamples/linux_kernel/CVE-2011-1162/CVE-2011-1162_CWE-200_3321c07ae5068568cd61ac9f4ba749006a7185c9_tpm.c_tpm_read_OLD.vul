ssize_t tpm_read(struct file *file, char __user *buf,
		 size_t size, loff_t *off)
{
	struct tpm_chip *chip = file->private_data;
	ssize_t ret_size;

	del_singleshot_timer_sync(&chip->user_read_timer);
	flush_work_sync(&chip->work);
	ret_size = atomic_read(&chip->data_pending);
	atomic_set(&chip->data_pending, 0);
	if (ret_size > 0) {	/* relay data */
		if (size < ret_size)
			ret_size = size;

		mutex_lock(&chip->buffer_mutex);
		if (copy_to_user(buf, chip->data_buffer, ret_size))
			ret_size = -EFAULT;
		mutex_unlock(&chip->buffer_mutex);
	}

	return ret_size;
}

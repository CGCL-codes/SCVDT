static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct snd_timer_user *tu = file->private_data;
	long ret;

	mutex_lock(&tu->ioctl_lock);
	ret = __snd_timer_user_ioctl(file, cmd, arg);
	mutex_unlock(&tu->ioctl_lock);
	return ret;
}

static int snd_timer_user_release(struct inode *inode, struct file *file)
{
	struct snd_timer_user *tu;

	if (file->private_data) {
		tu = file->private_data;
		file->private_data = NULL;
		if (tu->timeri)
			snd_timer_close(tu->timeri);
		kfree(tu->queue);
		kfree(tu->tqueue);
		kfree(tu);
	}
	return 0;
}

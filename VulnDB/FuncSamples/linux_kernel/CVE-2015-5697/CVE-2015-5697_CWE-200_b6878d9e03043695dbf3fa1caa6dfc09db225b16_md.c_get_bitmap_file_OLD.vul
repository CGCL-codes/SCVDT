static int get_bitmap_file(struct mddev *mddev, void __user * arg)
{
	mdu_bitmap_file_t *file = NULL; /* too big for stack allocation */
	char *ptr;
	int err;

	file = kmalloc(sizeof(*file), GFP_NOIO);
	if (!file)
		return -ENOMEM;

	err = 0;
	spin_lock(&mddev->lock);
	/* bitmap disabled, zero the first byte and copy out */
	if (!mddev->bitmap_info.file)
		file->pathname[0] = '\0';
	else if ((ptr = file_path(mddev->bitmap_info.file,
			       file->pathname, sizeof(file->pathname))),
		 IS_ERR(ptr))
		err = PTR_ERR(ptr);
	else
		memmove(file->pathname, ptr,
			sizeof(file->pathname)-(ptr-file->pathname));
	spin_unlock(&mddev->lock);

	if (err == 0 &&
	    copy_to_user(arg, file, sizeof(*file)))
		err = -EFAULT;

	kfree(file);
	return err;
}

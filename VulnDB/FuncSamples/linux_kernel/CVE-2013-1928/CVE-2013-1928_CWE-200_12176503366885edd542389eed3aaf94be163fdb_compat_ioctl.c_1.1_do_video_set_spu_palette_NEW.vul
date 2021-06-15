static int do_video_set_spu_palette(unsigned int fd, unsigned int cmd,
		struct compat_video_spu_palette __user *up)
{
	struct video_spu_palette __user *up_native;
	compat_uptr_t palp;
	int length, err;

	err  = get_user(palp, &up->palette);
	err |= get_user(length, &up->length);
	if (err)
		return -EFAULT;

	up_native = compat_alloc_user_space(sizeof(struct video_spu_palette));
	err  = put_user(compat_ptr(palp), &up_native->palette);
	err |= put_user(length, &up_native->length);
	if (err)
		return -EFAULT;

	err = sys_ioctl(fd, cmd, (unsigned long) up_native);

	return err;
}

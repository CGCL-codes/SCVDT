asmlinkage long sys_oabi_epoll_wait(int epfd,
				    struct oabi_epoll_event __user *events,
				    int maxevents, int timeout)
{
	struct epoll_event *kbuf;
	mm_segment_t fs;
	long ret, err, i;

	if (maxevents <= 0 || maxevents > (INT_MAX/sizeof(struct epoll_event)))
		return -EINVAL;
	kbuf = kmalloc(sizeof(*kbuf) * maxevents, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	fs = get_fs();
	set_fs(KERNEL_DS);
	ret = sys_epoll_wait(epfd, kbuf, maxevents, timeout);
	set_fs(fs);
	err = 0;
	for (i = 0; i < ret; i++) {
		__put_user_error(kbuf[i].events, &events->events, err);
		__put_user_error(kbuf[i].data,   &events->data,   err);
		events++;
	}
	kfree(kbuf);
	return err ? -EFAULT : ret;
}

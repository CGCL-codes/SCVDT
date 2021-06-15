static int do_siocgstampns(struct net *net, struct socket *sock,
			   unsigned int cmd, void __user *up)
{
	mm_segment_t old_fs = get_fs();
	struct timespec kts;
	int err;

	set_fs(KERNEL_DS);
	err = sock_do_ioctl(net, sock, cmd, (unsigned long)&kts);
	set_fs(old_fs);
	if (!err)
		err = compat_put_timespec(&kts, up);

	return err;
}

static int do_siocgstamp(struct net *net, struct socket *sock,
			 unsigned int cmd, void __user *up)
{
	mm_segment_t old_fs = get_fs();
	struct timeval ktv;
	int err;

	set_fs(KERNEL_DS);
	err = sock_do_ioctl(net, sock, cmd, (unsigned long)&ktv);
	set_fs(old_fs);
	if (!err)
		err = compat_put_timeval(up, &ktv);

	return err;
}

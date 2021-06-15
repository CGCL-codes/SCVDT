static inline int iov_from_user_compat_to_kern(struct iovec *kiov,
					  struct compat_iovec __user *uiov32,
					  int niov)
{
	int tot_len = 0;

	while (niov > 0) {
		compat_uptr_t buf;
		compat_size_t len;

		if (get_user(len, &uiov32->iov_len) ||
		    get_user(buf, &uiov32->iov_base))
			return -EFAULT;

		if (len > INT_MAX - tot_len)
			len = INT_MAX - tot_len;

		tot_len += len;
		kiov->iov_base = compat_ptr(buf);
		kiov->iov_len = (__kernel_size_t) len;
		uiov32++;
		kiov++;
		niov--;
	}
	return tot_len;
}

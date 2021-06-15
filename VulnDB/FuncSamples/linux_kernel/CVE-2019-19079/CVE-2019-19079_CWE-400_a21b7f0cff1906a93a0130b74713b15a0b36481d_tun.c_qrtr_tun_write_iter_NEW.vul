static ssize_t qrtr_tun_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *filp = iocb->ki_filp;
	struct qrtr_tun *tun = filp->private_data;
	size_t len = iov_iter_count(from);
	ssize_t ret;
	void *kbuf;

	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (!copy_from_iter_full(kbuf, len, from)) {
		kfree(kbuf);
		return -EFAULT;
	}

	ret = qrtr_endpoint_post(&tun->ep, kbuf, len);

	kfree(kbuf);
	return ret < 0 ? ret : len;
}

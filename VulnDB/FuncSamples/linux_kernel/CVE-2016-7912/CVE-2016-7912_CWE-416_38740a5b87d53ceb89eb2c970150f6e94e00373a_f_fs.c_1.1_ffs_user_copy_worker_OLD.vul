static void ffs_user_copy_worker(struct work_struct *work)
{
	struct ffs_io_data *io_data = container_of(work, struct ffs_io_data,
						   work);
	int ret = io_data->req->status ? io_data->req->status :
					 io_data->req->actual;

	if (io_data->read && ret > 0) {
		use_mm(io_data->mm);
		ret = copy_to_iter(io_data->buf, ret, &io_data->data);
		if (iov_iter_count(&io_data->data))
			ret = -EFAULT;
		unuse_mm(io_data->mm);
	}

	io_data->kiocb->ki_complete(io_data->kiocb, ret, ret);

	if (io_data->ffs->ffs_eventfd &&
	    !(io_data->kiocb->ki_flags & IOCB_EVENTFD))
		eventfd_signal(io_data->ffs->ffs_eventfd, 1);

	usb_ep_free_request(io_data->ep, io_data->req);

	io_data->kiocb->private = NULL;
	if (io_data->read)
		kfree(io_data->to_free);
	kfree(io_data->buf);
	kfree(io_data);
}

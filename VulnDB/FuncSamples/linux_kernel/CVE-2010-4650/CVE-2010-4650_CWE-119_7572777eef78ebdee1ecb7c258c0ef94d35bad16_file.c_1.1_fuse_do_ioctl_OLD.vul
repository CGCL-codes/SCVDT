long fuse_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_ioctl_in inarg = {
		.fh = ff->fh,
		.cmd = cmd,
		.arg = arg,
		.flags = flags
	};
	struct fuse_ioctl_out outarg;
	struct fuse_req *req = NULL;
	struct page **pages = NULL;
	struct page *iov_page = NULL;
	struct iovec *in_iov = NULL, *out_iov = NULL;
	unsigned int in_iovs = 0, out_iovs = 0, num_pages = 0, max_pages;
	size_t in_size, out_size, transferred;
	int err;

	/* assume all the iovs returned by client always fits in a page */
	BUILD_BUG_ON(sizeof(struct iovec) * FUSE_IOCTL_MAX_IOV > PAGE_SIZE);

	err = -ENOMEM;
	pages = kzalloc(sizeof(pages[0]) * FUSE_MAX_PAGES_PER_REQ, GFP_KERNEL);
	iov_page = alloc_page(GFP_KERNEL);
	if (!pages || !iov_page)
		goto out;

	/*
	 * If restricted, initialize IO parameters as encoded in @cmd.
	 * RETRY from server is not allowed.
	 */
	if (!(flags & FUSE_IOCTL_UNRESTRICTED)) {
		struct iovec *iov = page_address(iov_page);

		iov->iov_base = (void __user *)arg;
		iov->iov_len = _IOC_SIZE(cmd);

		if (_IOC_DIR(cmd) & _IOC_WRITE) {
			in_iov = iov;
			in_iovs = 1;
		}

		if (_IOC_DIR(cmd) & _IOC_READ) {
			out_iov = iov;
			out_iovs = 1;
		}
	}

 retry:
	inarg.in_size = in_size = iov_length(in_iov, in_iovs);
	inarg.out_size = out_size = iov_length(out_iov, out_iovs);

	/*
	 * Out data can be used either for actual out data or iovs,
	 * make sure there always is at least one page.
	 */
	out_size = max_t(size_t, out_size, PAGE_SIZE);
	max_pages = DIV_ROUND_UP(max(in_size, out_size), PAGE_SIZE);

	/* make sure there are enough buffer pages and init request with them */
	err = -ENOMEM;
	if (max_pages > FUSE_MAX_PAGES_PER_REQ)
		goto out;
	while (num_pages < max_pages) {
		pages[num_pages] = alloc_page(GFP_KERNEL | __GFP_HIGHMEM);
		if (!pages[num_pages])
			goto out;
		num_pages++;
	}

	req = fuse_get_req(fc);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		req = NULL;
		goto out;
	}
	memcpy(req->pages, pages, sizeof(req->pages[0]) * num_pages);
	req->num_pages = num_pages;

	/* okay, let's send it to the client */
	req->in.h.opcode = FUSE_IOCTL;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	if (in_size) {
		req->in.numargs++;
		req->in.args[1].size = in_size;
		req->in.argpages = 1;

		err = fuse_ioctl_copy_user(pages, in_iov, in_iovs, in_size,
					   false);
		if (err)
			goto out;
	}

	req->out.numargs = 2;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	req->out.args[1].size = out_size;
	req->out.argpages = 1;
	req->out.argvar = 1;

	fuse_request_send(fc, req);
	err = req->out.h.error;
	transferred = req->out.args[1].size;
	fuse_put_request(fc, req);
	req = NULL;
	if (err)
		goto out;

	/* did it ask for retry? */
	if (outarg.flags & FUSE_IOCTL_RETRY) {
		char *vaddr;

		/* no retry if in restricted mode */
		err = -EIO;
		if (!(flags & FUSE_IOCTL_UNRESTRICTED))
			goto out;

		in_iovs = outarg.in_iovs;
		out_iovs = outarg.out_iovs;

		/*
		 * Make sure things are in boundary, separate checks
		 * are to protect against overflow.
		 */
		err = -ENOMEM;
		if (in_iovs > FUSE_IOCTL_MAX_IOV ||
		    out_iovs > FUSE_IOCTL_MAX_IOV ||
		    in_iovs + out_iovs > FUSE_IOCTL_MAX_IOV)
			goto out;

		vaddr = kmap_atomic(pages[0], KM_USER0);
		err = fuse_copy_ioctl_iovec(page_address(iov_page), vaddr,
					    transferred, in_iovs + out_iovs,
					    (flags & FUSE_IOCTL_COMPAT) != 0);
		kunmap_atomic(vaddr, KM_USER0);
		if (err)
			goto out;

		in_iov = page_address(iov_page);
		out_iov = in_iov + in_iovs;

		goto retry;
	}

	err = -EIO;
	if (transferred > inarg.out_size)
		goto out;

	err = fuse_ioctl_copy_user(pages, out_iov, out_iovs, transferred, true);
 out:
	if (req)
		fuse_put_request(fc, req);
	if (iov_page)
		__free_page(iov_page);
	while (num_pages)
		__free_page(pages[--num_pages]);
	kfree(pages);

	return err ? err : outarg.result;
}

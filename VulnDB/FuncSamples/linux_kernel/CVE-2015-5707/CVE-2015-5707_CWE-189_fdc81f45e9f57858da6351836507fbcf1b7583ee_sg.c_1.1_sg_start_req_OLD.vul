static int
sg_start_req(Sg_request *srp, unsigned char *cmd)
{
	int res;
	struct request *rq;
	Sg_fd *sfp = srp->parentfp;
	sg_io_hdr_t *hp = &srp->header;
	int dxfer_len = (int) hp->dxfer_len;
	int dxfer_dir = hp->dxfer_direction;
	unsigned int iov_count = hp->iovec_count;
	Sg_scatter_hold *req_schp = &srp->data;
	Sg_scatter_hold *rsv_schp = &sfp->reserve;
	struct request_queue *q = sfp->parentdp->device->request_queue;
	struct rq_map_data *md, map_data;
	int rw = hp->dxfer_direction == SG_DXFER_TO_DEV ? WRITE : READ;
	unsigned char *long_cmdp = NULL;

	SCSI_LOG_TIMEOUT(4, sg_printk(KERN_INFO, sfp->parentdp,
				      "sg_start_req: dxfer_len=%d\n",
				      dxfer_len));

	if (hp->cmd_len > BLK_MAX_CDB) {
		long_cmdp = kzalloc(hp->cmd_len, GFP_KERNEL);
		if (!long_cmdp)
			return -ENOMEM;
	}

	/*
	 * NOTE
	 *
	 * With scsi-mq enabled, there are a fixed number of preallocated
	 * requests equal in number to shost->can_queue.  If all of the
	 * preallocated requests are already in use, then using GFP_ATOMIC with
	 * blk_get_request() will return -EWOULDBLOCK, whereas using GFP_KERNEL
	 * will cause blk_get_request() to sleep until an active command
	 * completes, freeing up a request.  Neither option is ideal, but
	 * GFP_KERNEL is the better choice to prevent userspace from getting an
	 * unexpected EWOULDBLOCK.
	 *
	 * With scsi-mq disabled, blk_get_request() with GFP_KERNEL usually
	 * does not sleep except under memory pressure.
	 */
	rq = blk_get_request(q, rw, GFP_KERNEL);
	if (IS_ERR(rq)) {
		kfree(long_cmdp);
		return PTR_ERR(rq);
	}

	blk_rq_set_block_pc(rq);

	if (hp->cmd_len > BLK_MAX_CDB)
		rq->cmd = long_cmdp;
	memcpy(rq->cmd, cmd, hp->cmd_len);
	rq->cmd_len = hp->cmd_len;

	srp->rq = rq;
	rq->end_io_data = srp;
	rq->sense = srp->sense_b;
	rq->retries = SG_DEFAULT_RETRIES;

	if ((dxfer_len <= 0) || (dxfer_dir == SG_DXFER_NONE))
		return 0;

	if (sg_allow_dio && hp->flags & SG_FLAG_DIRECT_IO &&
	    dxfer_dir != SG_DXFER_UNKNOWN && !iov_count &&
	    !sfp->parentdp->device->host->unchecked_isa_dma &&
	    blk_rq_aligned(q, (unsigned long)hp->dxferp, dxfer_len))
		md = NULL;
	else
		md = &map_data;

	if (md) {
		if (!sg_res_in_use(sfp) && dxfer_len <= rsv_schp->bufflen)
			sg_link_reserve(sfp, srp, dxfer_len);
		else {
			res = sg_build_indirect(req_schp, sfp, dxfer_len);
			if (res)
				return res;
		}

		md->pages = req_schp->pages;
		md->page_order = req_schp->page_order;
		md->nr_entries = req_schp->k_use_sg;
		md->offset = 0;
		md->null_mapped = hp->dxferp ? 0 : 1;
		if (dxfer_dir == SG_DXFER_TO_FROM_DEV)
			md->from_user = 1;
		else
			md->from_user = 0;
	}

	if (unlikely(iov_count > MAX_UIOVEC))
		return -EINVAL;

	if (iov_count) {
		int size = sizeof(struct iovec) * iov_count;
		struct iovec *iov;
		struct iov_iter i;

		iov = memdup_user(hp->dxferp, size);
		if (IS_ERR(iov))
			return PTR_ERR(iov);

		iov_iter_init(&i, rw, iov, iov_count,
			      min_t(size_t, hp->dxfer_len,
				    iov_length(iov, iov_count)));

		res = blk_rq_map_user_iov(q, rq, md, &i, GFP_ATOMIC);
		kfree(iov);
	} else
		res = blk_rq_map_user(q, rq, md, hp->dxferp,
				      hp->dxfer_len, GFP_ATOMIC);

	if (!res) {
		srp->bio = rq->bio;

		if (!md) {
			req_schp->dio_in_use = 1;
			hp->info |= SG_INFO_DIRECT_IO;
		}
	}
	return res;
}

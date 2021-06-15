static ssize_t aio_setup_single_vector(struct kiocb *kiocb)
{
	kiocb->ki_iovec = &kiocb->ki_inline_vec;
	kiocb->ki_iovec->iov_base = kiocb->ki_buf;
	kiocb->ki_iovec->iov_len = kiocb->ki_left;
	kiocb->ki_nr_segs = 1;
	kiocb->ki_cur_seg = 0;
	return 0;
}

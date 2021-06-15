static int mem_read(jas_stream_obj_t *obj, char *buf, int cnt)
{
	ssize_t n;
	assert(cnt >= 0);
	assert(buf);

	JAS_DBGLOG(100, ("mem_read(%p, %p, %d)\n", obj, buf, cnt));
	jas_stream_memobj_t *m = (jas_stream_memobj_t *)obj;
	n = m->len_ - m->pos_;
	cnt = JAS_MIN(n, cnt);
	memcpy(buf, &m->buf_[m->pos_], cnt);
	m->pos_ += cnt;
	return cnt;
}

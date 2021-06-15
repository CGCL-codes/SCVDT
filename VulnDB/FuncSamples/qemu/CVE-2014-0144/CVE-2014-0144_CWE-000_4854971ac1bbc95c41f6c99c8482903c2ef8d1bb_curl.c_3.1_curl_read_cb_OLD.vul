static size_t curl_read_cb(void *ptr, size_t size, size_t nmemb, void *opaque)
{
    CURLState *s = ((CURLState*)opaque);
    size_t realsize = size * nmemb;
    int i;

    DPRINTF("CURL: Just reading %zd bytes\n", realsize);

    if (!s || !s->orig_buf)
        goto read_end;

    memcpy(s->orig_buf + s->buf_off, ptr, realsize);
    s->buf_off += realsize;

    for(i=0; i<CURL_NUM_ACB; i++) {
        CURLAIOCB *acb = s->acb[i];

        if (!acb)
            continue;

        if ((s->buf_off >= acb->end)) {
            qemu_iovec_from_buf(acb->qiov, 0, s->orig_buf + acb->start,
                                acb->end - acb->start);
            acb->common.cb(acb->common.opaque, 0);
            qemu_aio_release(acb);
            s->acb[i] = NULL;
        }
    }

read_end:
    return realsize;
}

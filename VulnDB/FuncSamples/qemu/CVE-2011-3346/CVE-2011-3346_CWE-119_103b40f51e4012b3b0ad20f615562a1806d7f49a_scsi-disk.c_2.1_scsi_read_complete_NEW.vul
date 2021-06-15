static void scsi_read_complete(void * opaque, int ret)
{
    SCSIDiskReq *r = (SCSIDiskReq *)opaque;
    SCSIDiskState *s = DO_UPCAST(SCSIDiskState, qdev, r->req.dev);
    int n;

    if (r->req.aiocb != NULL) {
        r->req.aiocb = NULL;
        bdrv_acct_done(s->bs, &r->acct);
    }

    if (ret) {
        if (scsi_handle_rw_error(r, -ret, SCSI_REQ_STATUS_RETRY_READ)) {
            return;
        }
    }

    DPRINTF("Data ready tag=0x%x len=%zd\n", r->req.tag, r->qiov.size);

    n = r->qiov.size / 512;
    r->sector += n;
    r->sector_count -= n;
    scsi_req_data(&r->req, r->qiov.size);
}

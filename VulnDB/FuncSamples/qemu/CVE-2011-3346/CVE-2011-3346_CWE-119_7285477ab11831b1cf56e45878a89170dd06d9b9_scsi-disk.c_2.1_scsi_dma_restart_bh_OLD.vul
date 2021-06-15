static void scsi_dma_restart_bh(void *opaque)
{
    SCSIDiskState *s = opaque;
    SCSIRequest *req;
    SCSIDiskReq *r;

    qemu_bh_delete(s->bh);
    s->bh = NULL;

    QTAILQ_FOREACH(req, &s->qdev.requests, next) {
        r = DO_UPCAST(SCSIDiskReq, req, req);
        if (r->status & SCSI_REQ_STATUS_RETRY) {
            int status = r->status;
            int ret;

            r->status &=
                ~(SCSI_REQ_STATUS_RETRY | SCSI_REQ_STATUS_RETRY_TYPE_MASK);

            switch (status & SCSI_REQ_STATUS_RETRY_TYPE_MASK) {
            case SCSI_REQ_STATUS_RETRY_READ:
                scsi_read_data(&r->req);
                break;
            case SCSI_REQ_STATUS_RETRY_WRITE:
                scsi_write_data(&r->req);
                break;
            case SCSI_REQ_STATUS_RETRY_FLUSH:
                ret = scsi_disk_emulate_command(r, r->iov.iov_base);
                if (ret == 0) {
                    scsi_req_complete(&r->req, GOOD);
                }
            }
        }
    }
}
